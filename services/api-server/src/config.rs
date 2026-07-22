use std::env;
use std::net::SocketAddr;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use thiserror::Error;

const MAX_ACCESS_TTL_SECONDS: u64 = 15 * 60;
const MAX_REFRESH_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;
const MAX_CHALLENGE_TTL_SECONDS: u64 = 5 * 60;
const MAX_CHALLENGE_ATTEMPTS: u8 = 5;

#[derive(Clone)]
pub struct AppConfig {
    pub bind: SocketAddr,
    pub public_url: String,
    pub token_secret: Vec<u8>,
    pub service_token: String,
    pub access_ttl_seconds: u64,
    pub refresh_ttl_seconds: u64,
    pub challenge_ttl_seconds: u64,
    pub challenge_attempts: u8,
    pub database_url: Option<String>,
    pub redis_url: Option<String>,
    pub signal_push_url: Option<String>,
    pub mfa_secret_key: Option<[u8; 32]>,
    pub storage_backend: StorageBackend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageBackend {
    Memory,
    Postgres,
}

impl StorageBackend {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Postgres => "postgres",
        }
    }
}

impl AppConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let bind = env_string("REMOTE_API_BIND", "127.0.0.1:18080")?
            .parse()
            .map_err(|_| ConfigError::Invalid("REMOTE_API_BIND must be a socket address"))?;
        let public_url = env_string("REMOTE_API_PUBLIC_URL", "http://127.0.0.1:18080")?;
        validate_url(
            "REMOTE_API_PUBLIC_URL",
            &public_url,
            &["http://", "https://"],
        )?;

        let token_secret = required_secret("REMOTE_TOKEN_SECRET", 32)?;
        let service_token = env::var("REMOTE_SERVICE_TOKEN")
            .map_err(|_| ConfigError::Missing("REMOTE_SERVICE_TOKEN"))?;
        if service_token.len() < 32 {
            return Err(ConfigError::Invalid(
                "REMOTE_SERVICE_TOKEN must contain at least 32 bytes",
            ));
        }

        let access_ttl_seconds = bounded_u64(
            "REMOTE_ACCESS_TTL_SECONDS",
            MAX_ACCESS_TTL_SECONDS,
            MAX_ACCESS_TTL_SECONDS,
        )?;
        let refresh_ttl_seconds = bounded_u64(
            "REMOTE_REFRESH_TTL_SECONDS",
            MAX_REFRESH_TTL_SECONDS,
            MAX_REFRESH_TTL_SECONDS,
        )?;
        let challenge_ttl_seconds = bounded_u64(
            "REMOTE_CHALLENGE_TTL_SECONDS",
            MAX_CHALLENGE_TTL_SECONDS,
            MAX_CHALLENGE_TTL_SECONDS,
        )?;
        let challenge_attempts = bounded_u8(
            "REMOTE_CHALLENGE_ATTEMPTS",
            MAX_CHALLENGE_ATTEMPTS,
            MAX_CHALLENGE_ATTEMPTS,
        )?;

        let database_url = optional_url("DATABASE_URL", &["postgres://", "postgresql://"])?;
        let redis_url = optional_url("REDIS_URL", &["redis://", "rediss://"])?;
        let signal_push_url = optional_url("REMOTE_SIGNAL_PUSH_URL", &["http://", "https://"])?;
        let mfa_secret_key = optional_key("REMOTE_MFA_SECRET_KEY")?;
        let storage_backend = match env::var("REMOTE_STORAGE_BACKEND")
            .map_err(|_| ConfigError::Missing("REMOTE_STORAGE_BACKEND"))?
            .as_str()
        {
            "memory" => StorageBackend::Memory,
            "postgres" => StorageBackend::Postgres,
            value => {
                return Err(ConfigError::InvalidValue {
                    name: "REMOTE_STORAGE_BACKEND",
                    value: value.to_owned(),
                });
            }
        };
        validate_runtime_storage(
            storage_backend,
            database_url.as_deref(),
            redis_url.as_deref(),
            mfa_secret_key.as_ref(),
        )?;

        Ok(Self {
            bind,
            public_url,
            token_secret,
            service_token,
            access_ttl_seconds,
            refresh_ttl_seconds,
            challenge_ttl_seconds,
            challenge_attempts,
            database_url,
            redis_url,
            signal_push_url,
            mfa_secret_key,
            storage_backend,
        })
    }

    pub fn for_test() -> Self {
        Self {
            bind: "127.0.0.1:0".parse().expect("test bind"),
            public_url: "http://127.0.0.1".to_owned(),
            token_secret: vec![0x42; 32],
            service_token: "test-service-token-that-is-at-least-32-bytes".to_owned(),
            access_ttl_seconds: MAX_ACCESS_TTL_SECONDS,
            refresh_ttl_seconds: MAX_REFRESH_TTL_SECONDS,
            challenge_ttl_seconds: MAX_CHALLENGE_TTL_SECONDS,
            challenge_attempts: MAX_CHALLENGE_ATTEMPTS,
            database_url: None,
            redis_url: None,
            signal_push_url: None,
            mfa_secret_key: None,
            storage_backend: StorageBackend::Memory,
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required environment variable {0}")]
    Missing(&'static str),
    #[error("invalid configuration: {0}")]
    Invalid(&'static str),
    #[error("invalid value for {name}: {value}")]
    InvalidValue { name: &'static str, value: String },
}

fn env_string(name: &'static str, default: &str) -> Result<String, ConfigError> {
    let value = env::var(name).unwrap_or_else(|_| default.to_owned());
    if value.trim().is_empty() {
        return Err(ConfigError::InvalidValue { name, value });
    }
    Ok(value)
}

fn required_secret(name: &'static str, min_len: usize) -> Result<Vec<u8>, ConfigError> {
    let value = env::var(name).map_err(|_| ConfigError::Missing(name))?;
    if value.len() < min_len {
        return Err(ConfigError::InvalidValue {
            name,
            value: "<redacted: too short>".to_owned(),
        });
    }
    Ok(value.into_bytes())
}

fn bounded_u64(name: &'static str, default: u64, maximum: u64) -> Result<u64, ConfigError> {
    let raw = env::var(name).unwrap_or_else(|_| default.to_string());
    let value = raw
        .parse::<u64>()
        .map_err(|_| ConfigError::InvalidValue { name, value: raw })?;
    if value == 0 || value > maximum {
        return Err(ConfigError::InvalidValue {
            name,
            value: value.to_string(),
        });
    }
    Ok(value)
}

fn bounded_u8(name: &'static str, default: u8, maximum: u8) -> Result<u8, ConfigError> {
    let raw = env::var(name).unwrap_or_else(|_| default.to_string());
    let value = raw
        .parse::<u8>()
        .map_err(|_| ConfigError::InvalidValue { name, value: raw })?;
    if value == 0 || value > maximum {
        return Err(ConfigError::InvalidValue {
            name,
            value: value.to_string(),
        });
    }
    Ok(value)
}

fn optional_url(name: &'static str, schemes: &[&str]) -> Result<Option<String>, ConfigError> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => {
            validate_url(name, &value, schemes)?;
            Ok(Some(value))
        }
        _ => Ok(None),
    }
}

fn optional_key(name: &'static str) -> Result<Option<[u8; 32]>, ConfigError> {
    let Ok(value) = env::var(name) else {
        return Ok(None);
    };
    let decoded = URL_SAFE_NO_PAD
        .decode(value.trim())
        .map_err(|_| ConfigError::InvalidValue {
            name,
            value: "<redacted: invalid base64url>".to_owned(),
        })?;
    let key = decoded.try_into().map_err(|_| ConfigError::InvalidValue {
        name,
        value: "<redacted: expected 32 bytes>".to_owned(),
    })?;
    Ok(Some(key))
}

fn validate_url(name: &'static str, value: &str, schemes: &[&str]) -> Result<(), ConfigError> {
    if schemes.iter().any(|scheme| value.starts_with(scheme)) {
        Ok(())
    } else {
        Err(ConfigError::InvalidValue {
            name,
            value: value.to_owned(),
        })
    }
}

fn validate_runtime_storage(
    storage_backend: StorageBackend,
    database_url: Option<&str>,
    redis_url: Option<&str>,
    mfa_secret_key: Option<&[u8; 32]>,
) -> Result<(), ConfigError> {
    if storage_backend == StorageBackend::Memory {
        return Err(ConfigError::Invalid(
            "REMOTE_STORAGE_BACKEND=memory is only available through test configuration",
        ));
    }
    if database_url.is_none() {
        return Err(ConfigError::Missing("DATABASE_URL"));
    }
    if redis_url.is_none() {
        return Err(ConfigError::Missing("REDIS_URL"));
    }
    if mfa_secret_key.is_none() {
        return Err(ConfigError::Missing("REMOTE_MFA_SECRET_KEY"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_configuration_uses_frozen_maxima() {
        let config = AppConfig::for_test();
        assert_eq!(config.access_ttl_seconds, 900);
        assert_eq!(config.refresh_ttl_seconds, 2_592_000);
        assert_eq!(config.challenge_ttl_seconds, 300);
        assert_eq!(config.challenge_attempts, 5);
        assert_eq!(config.storage_backend, StorageBackend::Memory);
        assert_eq!(StorageBackend::Postgres.as_str(), "postgres");
    }

    #[test]
    fn production_postgres_requires_redis() {
        let result = validate_runtime_storage(
            StorageBackend::Postgres,
            Some("postgres://database"),
            None,
            Some(&[0; 32]),
        );
        assert!(matches!(result, Err(ConfigError::Missing("REDIS_URL"))));
    }

    #[test]
    fn production_memory_backend_is_rejected() {
        let result = validate_runtime_storage(StorageBackend::Memory, None, None, None);
        assert!(matches!(result, Err(ConfigError::Invalid(_))));
    }
}
