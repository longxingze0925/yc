use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use url::Url;

const CONFIG_FILE_VERSION: u16 = 1;
const CONTROLLED_ACCESS_FILE_VERSION: u16 = 1;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub api_base_url: String,
    pub signal_url: String,
    pub relay_url: String,
    server_key_fingerprint: String,
    #[serde(default)]
    official: bool,
}

impl ServiceConfig {
    pub fn new(
        api_base_url: impl Into<String>,
        signal_url: impl Into<String>,
        relay_url: impl Into<String>,
        server_key_fingerprint: impl Into<String>,
    ) -> Result<Self, ConfigError> {
        let config = Self {
            api_base_url: api_base_url.into().trim().trim_end_matches('/').to_owned(),
            signal_url: signal_url.into().trim().to_owned(),
            relay_url: relay_url.into().trim().to_owned(),
            server_key_fingerprint: server_key_fingerprint.into().trim().to_owned(),
            official: false,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn server_key_fingerprint(&self) -> &str {
        &self.server_key_fingerprint
    }

    pub fn environment_label(&self) -> &'static str {
        if self.official {
            return "官方服务";
        }
        match Url::parse(&self.api_base_url)
            .ok()
            .and_then(|url| url.host_str().map(ToOwned::to_owned))
            .as_deref()
        {
            Some("localhost" | "127.0.0.1" | "::1") => "本地开发服务",
            _ => "自定义服务",
        }
    }

    pub fn official() -> Result<Self, ConfigError> {
        let (api, signal, relay) = if cfg!(debug_assertions) {
            (
                option_env!("RCTL_OFFICIAL_API_URL").unwrap_or("http://127.0.0.1:18080"),
                option_env!("RCTL_OFFICIAL_SIGNAL_URL").unwrap_or("ws://127.0.0.1:18081/ws"),
                option_env!("RCTL_OFFICIAL_RELAY_URL").unwrap_or("127.0.0.1:18443"),
            )
        } else {
            (
                option_env!("RCTL_OFFICIAL_API_URL").ok_or_else(|| {
                    ConfigError::Invalid("Release 构建缺少 RCTL_OFFICIAL_API_URL".into())
                })?,
                option_env!("RCTL_OFFICIAL_SIGNAL_URL").ok_or_else(|| {
                    ConfigError::Invalid("Release 构建缺少 RCTL_OFFICIAL_SIGNAL_URL".into())
                })?,
                option_env!("RCTL_OFFICIAL_RELAY_URL").ok_or_else(|| {
                    ConfigError::Invalid("Release 构建缺少 RCTL_OFFICIAL_RELAY_URL".into())
                })?,
            )
        };
        let mut config = Self::new(api, signal, relay, "official-managed")?;
        config.official = true;
        Ok(config)
    }

    pub fn from_environment() -> Result<Option<Self>, ConfigError> {
        let names = [
            "RCTL_API_URL",
            "RCTL_SIGNAL_URL",
            "RCTL_RELAY_URL",
            "RCTL_SERVER_KEY_FINGERPRINT",
        ];
        let values = names.iter().map(std::env::var).collect::<Vec<_>>();
        let present = values.iter().filter(|value| value.is_ok()).count();
        if present == 0 {
            return Ok(None);
        }
        if present != names.len() {
            return Err(ConfigError::Invalid(
                "RCTL_API_URL、RCTL_SIGNAL_URL、RCTL_RELAY_URL 和 RCTL_SERVER_KEY_FINGERPRINT 必须同时配置".into(),
            ));
        }
        let values = values
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ConfigError::Invalid("服务配置环境变量必须是 UTF-8".into()))?;
        Self::new(&values[0], &values[1], &values[2], &values[3]).map(Some)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        validate_url(&self.api_base_url, &["http", "https"], "API")?;
        validate_url(&self.signal_url, &["ws", "wss"], "Signal")?;
        validate_relay_url(&self.relay_url)?;
        if self.server_key_fingerprint.is_empty() || self.server_key_fingerprint.len() > 512 {
            return Err(ConfigError::Invalid(
                "服务器公钥指纹长度必须在 1..=512 之间".into(),
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for ServiceConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceConfig")
            .field("api_base_url", &self.api_base_url)
            .field("signal_url", &self.signal_url)
            .field("relay_url", &self.relay_url)
            .field("server_key_fingerprint", &"<redacted>")
            .finish()
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Invalid(String),
    Io(std::io::Error),
    Serialization(serde_json::Error),
    UnsupportedLocation,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::Io(error) => write!(formatter, "服务配置存储失败: {error}"),
            Self::Serialization(_) => formatter.write_str("服务配置文件格式无效"),
            Self::UnsupportedLocation => formatter.write_str("无法确定当前用户的配置目录"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<std::io::Error> for ConfigError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for ConfigError {
    fn from(error: serde_json::Error) -> Self {
        Self::Serialization(error)
    }
}

pub trait ServiceConfigStore {
    fn load(&self) -> Result<Option<ServiceConfig>, ConfigError>;
    fn save(&self, config: &ServiceConfig) -> Result<(), ConfigError>;
}

#[derive(Debug, Clone)]
pub struct JsonFileServiceConfigStore {
    path: PathBuf,
}

impl JsonFileServiceConfigStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn for_current_user() -> Result<Self, ConfigError> {
        Ok(Self::new(default_config_path()?))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[derive(Serialize, Deserialize)]
struct ConfigFile {
    version: u16,
    services: ServiceConfig,
}

impl ServiceConfigStore for JsonFileServiceConfigStore {
    fn load(&self) -> Result<Option<ServiceConfig>, ConfigError> {
        let mut file = match OpenOptions::new().read(true).open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let persisted: ConfigFile = serde_json::from_slice(&bytes)?;
        if persisted.version != CONFIG_FILE_VERSION {
            return Err(ConfigError::Invalid(format!(
                "不支持服务配置版本 {}",
                persisted.version
            )));
        }
        persisted.services.validate()?;
        Ok(Some(persisted.services))
    }

    fn save(&self, config: &ServiceConfig) -> Result<(), ConfigError> {
        config.validate()?;
        let parent = self.path.parent().ok_or(ConfigError::UnsupportedLocation)?;
        fs::create_dir_all(parent)?;
        tighten_directory_permissions(parent)?;

        let temporary = self.path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(&ConfigFile {
            version: CONFIG_FILE_VERSION,
            services: config.clone(),
        })?;
        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        configure_private_file(&mut options);
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(temporary, &self.path)?;
        tighten_file_permissions(&self.path)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ControlledAccessPreferences {
    pub allow_account_devices: bool,
}

#[derive(Debug, Clone)]
pub struct JsonFileControlledAccessStore {
    path: PathBuf,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlledAccessFile {
    version: u16,
    allow_account_devices: bool,
}

impl JsonFileControlledAccessStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn for_current_user() -> Result<Self, ConfigError> {
        let mut path = default_config_path()?;
        path.set_file_name("controlled-access.json");
        Ok(Self::new(path))
    }

    pub fn load(&self) -> Result<ControlledAccessPreferences, ConfigError> {
        let mut file = match OpenOptions::new().read(true).open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ControlledAccessPreferences::default())
            }
            Err(error) => return Err(error.into()),
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let persisted: ControlledAccessFile = serde_json::from_slice(&bytes)?;
        if persisted.version != CONTROLLED_ACCESS_FILE_VERSION {
            return Err(ConfigError::Invalid(format!(
                "不支持被控访问配置版本 {}",
                persisted.version
            )));
        }
        Ok(ControlledAccessPreferences {
            allow_account_devices: persisted.allow_account_devices,
        })
    }

    pub fn save(&self, preferences: ControlledAccessPreferences) -> Result<(), ConfigError> {
        let parent = self.path.parent().ok_or(ConfigError::UnsupportedLocation)?;
        fs::create_dir_all(parent)?;
        tighten_directory_permissions(parent)?;
        let temporary = self.path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(&ControlledAccessFile {
            version: CONTROLLED_ACCESS_FILE_VERSION,
            allow_account_devices: preferences.allow_account_devices,
        })?;
        let mut options = OpenOptions::new();
        options.create(true).truncate(true).write(true);
        configure_private_file(&mut options);
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(temporary, &self.path)?;
        tighten_file_permissions(&self.path)?;
        Ok(())
    }
}

fn validate_url(value: &str, schemes: &[&str], label: &str) -> Result<(), ConfigError> {
    let url =
        Url::parse(value).map_err(|_| ConfigError::Invalid(format!("{label} 地址格式无效")))?;
    if !schemes.contains(&url.scheme()) || url.host_str().is_none() {
        return Err(ConfigError::Invalid(format!(
            "{label} 地址必须使用 {}",
            schemes.join("/")
        )));
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(ConfigError::Invalid(format!(
            "{label} 地址不得包含用户信息或 fragment"
        )));
    }
    Ok(())
}

fn validate_relay_url(value: &str) -> Result<(), ConfigError> {
    if value.is_empty() {
        return Err(ConfigError::Invalid("Relay 地址不得为空".into()));
    }
    if value.contains("://") {
        return validate_url(value, &["quic", "tls", "https"], "Relay");
    }
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| ConfigError::Invalid("Relay 地址必须包含端口".into()))?;
    if host.trim().is_empty() || port.parse::<u16>().is_err() {
        return Err(ConfigError::Invalid("Relay 地址格式无效".into()));
    }
    Ok(())
}

fn default_config_path() -> Result<PathBuf, ConfigError> {
    if let Some(path) = std::env::var_os("RCTL_DESKTOP_CONFIG") {
        return Ok(PathBuf::from(path));
    }
    #[cfg(target_os = "windows")]
    if let Some(path) = std::env::var_os("APPDATA") {
        return Ok(PathBuf::from(path).join("RctlRemote").join("services.json"));
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Some(path) = std::env::var_os("XDG_CONFIG_HOME") {
            return Ok(PathBuf::from(path)
                .join("rctl-remote")
                .join("services.json"));
        }
        if let Some(path) = std::env::var_os("HOME") {
            return Ok(PathBuf::from(path)
                .join(".config")
                .join("rctl-remote")
                .join("services.json"));
        }
    }
    Err(ConfigError::UnsupportedLocation)
}

#[cfg(unix)]
fn configure_private_file(options: &mut OpenOptions) {
    use std::os::unix::fs::OpenOptionsExt;
    options.mode(0o600);
}

#[cfg(not(unix))]
fn configure_private_file(_options: &mut OpenOptions) {}

#[cfg(unix)]
fn tighten_directory_permissions(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn tighten_directory_permissions(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(unix)]
fn tighten_file_permissions(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn tighten_file_permissions(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ServiceConfig {
        ServiceConfig::new(
            "https://api.example.com/",
            "wss://signal.example.com/ws",
            "relay.example.com:443",
            "sha256:private-fingerprint",
        )
        .expect("valid config")
    }

    #[test]
    fn config_round_trip_is_persistent_and_redacts_fingerprint_in_debug() {
        let root = std::env::temp_dir().join(format!("rctl-config-{}", uuid::Uuid::new_v4()));
        let store = JsonFileServiceConfigStore::new(root.join("services.json"));
        let config = config();
        store.save(&config).expect("save");

        assert_eq!(store.load().expect("load"), Some(config.clone()));
        let debug = format!("{config:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("private-fingerprint"));
        fs::remove_dir_all(root).expect("remove test config");
    }

    #[test]
    fn config_rejects_credentials_inside_service_urls() {
        let error = ServiceConfig::new(
            "https://user:secret@api.example.com",
            "wss://signal.example.com/ws",
            "relay.example.com:443",
            "fingerprint",
        )
        .expect_err("credentials must be rejected");
        assert!(matches!(error, ConfigError::Invalid(_)));
    }

    #[test]
    fn debug_official_configuration_needs_no_user_input() {
        let config = ServiceConfig::official().expect("debug official config");
        assert_eq!(config.environment_label(), "官方服务");
        assert!(!config.api_base_url.is_empty());
        assert!(!config.signal_url.is_empty());
        assert!(!config.relay_url.is_empty());
    }

    #[test]
    fn controlled_access_defaults_off_and_persists_explicit_enable() {
        let root = std::env::temp_dir().join(format!("rctl-access-{}", uuid::Uuid::new_v4()));
        let store = JsonFileControlledAccessStore::new(root.join("controlled-access.json"));
        assert_eq!(
            store.load().expect("default"),
            ControlledAccessPreferences::default()
        );
        let enabled = ControlledAccessPreferences {
            allow_account_devices: true,
        };
        store.save(enabled).expect("save");
        assert_eq!(store.load().expect("load"), enabled);
        fs::remove_dir_all(root).expect("remove test config");
    }
}
