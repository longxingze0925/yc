use crate::api::{DeviceStatus, DeviceView, MfaChallenge, MfaFactor, Platform};
use crate::config::ServiceConfig;
use crate::platform::PlatformSnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Page {
    Devices = 0,
    Assist = 1,
    Server = 2,
    Controlled = 3,
    Session = 4,
}

impl Page {
    pub fn from_index(index: i32) -> Option<Self> {
        match index {
            0 => Some(Self::Devices),
            1 => Some(Self::Assist),
            2 => Some(Self::Server),
            3 => Some(Self::Controlled),
            4 => Some(Self::Session),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginError {
    MissingAccount,
    MissingPassword,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaFlowError {
    MissingChallenge,
    EmptyCode,
    FactorNotAllowed,
    Expired,
    AttemptsExhausted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MfaAttemptContext {
    pub account: String,
    pub challenge_id: String,
    pub factor: MfaFactor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingMfa {
    account: String,
    challenge_id: String,
    allowed_factors: Vec<MfaFactor>,
    expires_at_epoch_millis: u64,
    attempts_remaining: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalDeviceRegistration {
    pub display_name: String,
    pub device_id: String,
    pub controller: bool,
    pub controlled: bool,
    pub server_backed: bool,
    pub public_key_id: Option<String>,
    pub public_key_version: Option<u32>,
    pub identity_durably_persisted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppDevice {
    pub device_id: String,
    pub display_name: String,
    pub glyph: String,
    pub detail: String,
    pub state: String,
    pub online: bool,
    pub local: bool,
    pub controlled: bool,
}

impl AppDevice {
    pub fn from_api(device: &DeviceView, local_device_id: &str) -> Self {
        let platform = match device.platform {
            Platform::Windows => "Windows",
            Platform::Ubuntu => "Ubuntu",
            Platform::Ios => "iOS",
        };
        let glyph = match device.platform {
            Platform::Windows => "W",
            Platform::Ubuntu => "U",
            Platform::Ios => "iOS",
        };
        let capabilities = if device.role_capabilities.controlled {
            "controller + controlled"
        } else {
            "controller only"
        };
        let online = matches!(device.status, DeviceStatus::Online | DeviceStatus::Busy);
        Self {
            device_id: device.device_id.clone(),
            display_name: device.display_name.clone(),
            glyph: glyph.into(),
            detail: format!("{platform} {} · {capabilities}", device.os_version),
            state: match device.status {
                DeviceStatus::Online => "在线",
                DeviceStatus::Offline => "离线",
                DeviceStatus::Busy => "使用中",
                DeviceStatus::Unknown => "状态未知",
            }
            .into(),
            online,
            local: device.device_id == local_device_id,
            controlled: device.role_capabilities.controlled,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppModel {
    page: Page,
    account: Option<String>,
    account_id: Option<String>,
    local_device: Option<LocalDeviceRegistration>,
    devices: Vec<AppDevice>,
    service_config: Option<ServiceConfig>,
    platform: PlatformSnapshot,
    pending_mfa: Option<PendingMfa>,
    login_status: String,
    assist_status: String,
    server_status: String,
    signal_status: String,
    session_status: String,
}

impl AppModel {
    pub fn new(platform: PlatformSnapshot) -> Self {
        Self {
            page: Page::Devices,
            account: None,
            account_id: None,
            local_device: None,
            devices: Vec::new(),
            service_config: None,
            platform,
            pending_mfa: None,
            login_status: String::new(),
            assist_status: "等待输入对方设备 ID".into(),
            server_status: "未配置服务地址".into(),
            signal_status: "Signal 未连接".into(),
            session_status: "会话尚未建立".into(),
        }
    }

    pub fn page(&self) -> Page {
        self.page
    }

    pub fn account(&self) -> Option<&str> {
        self.account.as_deref()
    }

    pub fn account_id(&self) -> Option<&str> {
        self.account_id.as_deref()
    }

    pub fn local_device(&self) -> Option<&LocalDeviceRegistration> {
        self.local_device.as_ref()
    }

    pub fn devices(&self) -> &[AppDevice] {
        &self.devices
    }

    pub fn service_config(&self) -> Option<&ServiceConfig> {
        self.service_config.as_ref()
    }

    pub fn platform(&self) -> &PlatformSnapshot {
        &self.platform
    }

    pub fn login_status(&self) -> &str {
        &self.login_status
    }

    pub fn mfa_required(&self) -> bool {
        self.pending_mfa.is_some()
    }

    pub fn mfa_account(&self) -> &str {
        self.pending_mfa
            .as_ref()
            .map(|pending| pending.account.as_str())
            .unwrap_or_default()
    }

    pub fn mfa_attempts_remaining(&self) -> u8 {
        self.pending_mfa
            .as_ref()
            .map(|pending| pending.attempts_remaining)
            .unwrap_or_default()
    }

    pub fn mfa_allows_factor(&self, factor: MfaFactor) -> bool {
        self.pending_mfa
            .as_ref()
            .is_some_and(|pending| pending.allowed_factors.contains(&factor))
    }

    pub fn mfa_expired(&self, now_epoch_millis: u64) -> bool {
        self.pending_mfa.as_ref().is_some_and(|pending| {
            pending.expires_at_epoch_millis <= now_epoch_millis || pending.attempts_remaining == 0
        })
    }

    pub fn assist_status(&self) -> &str {
        &self.assist_status
    }

    pub fn server_status(&self) -> &str {
        &self.server_status
    }

    pub fn signal_status(&self) -> &str {
        &self.signal_status
    }

    pub fn session_status(&self) -> &str {
        &self.session_status
    }

    pub fn validate_login(account: &str, password: &str) -> Result<(), LoginError> {
        if account.trim().is_empty() {
            return Err(LoginError::MissingAccount);
        }
        if password.is_empty() {
            return Err(LoginError::MissingPassword);
        }
        Ok(())
    }

    pub fn set_login_status(&mut self, status: impl Into<String>) {
        self.login_status = status.into();
    }

    pub fn begin_mfa(
        &mut self,
        account: impl Into<String>,
        challenge: MfaChallenge,
        now_epoch_millis: u64,
    ) {
        let pending = PendingMfa {
            account: account.into(),
            challenge_id: challenge.mfa_challenge_id,
            allowed_factors: challenge.allowed_factors,
            expires_at_epoch_millis: challenge.expires_at_epoch_millis,
            attempts_remaining: challenge.attempts_remaining,
        };
        self.login_status = if pending.expires_at_epoch_millis <= now_epoch_millis {
            "验证已过期，请取消并重新登录".into()
        } else if pending.allowed_factors.is_empty() {
            "服务端未提供此客户端支持的 MFA 验证方式".into()
        } else {
            format!(
                "请输入身份验证器代码或一次性恢复码，还可尝试 {} 次",
                pending.attempts_remaining
            )
        };
        self.pending_mfa = Some(pending);
    }

    pub fn prepare_mfa_attempt(
        &self,
        factor: MfaFactor,
        code: &str,
        now_epoch_millis: u64,
    ) -> Result<MfaAttemptContext, MfaFlowError> {
        let pending = self
            .pending_mfa
            .as_ref()
            .ok_or(MfaFlowError::MissingChallenge)?;
        if pending.expires_at_epoch_millis <= now_epoch_millis {
            return Err(MfaFlowError::Expired);
        }
        if pending.attempts_remaining == 0 {
            return Err(MfaFlowError::AttemptsExhausted);
        }
        if !pending.allowed_factors.contains(&factor) {
            return Err(MfaFlowError::FactorNotAllowed);
        }
        if code.trim().is_empty() {
            return Err(MfaFlowError::EmptyCode);
        }
        Ok(MfaAttemptContext {
            account: pending.account.clone(),
            challenge_id: pending.challenge_id.clone(),
            factor,
        })
    }

    pub fn record_mfa_rejection(&mut self, now_epoch_millis: u64) {
        let Some(pending) = self.pending_mfa.as_mut() else {
            return;
        };
        if pending.expires_at_epoch_millis <= now_epoch_millis {
            self.login_status = "验证已过期，请取消并重新登录".into();
            return;
        }
        pending.attempts_remaining = pending.attempts_remaining.saturating_sub(1);
        self.login_status = if pending.attempts_remaining == 0 {
            "验证失败，当前挑战已失效，请取消并重新登录".into()
        } else {
            format!(
                "验证失败：代码无效、已过期或已使用，还可尝试 {} 次",
                pending.attempts_remaining
            )
        };
    }

    pub fn complete_mfa(&mut self) {
        self.pending_mfa = None;
        self.login_status = "MFA 验证成功，正在注册本机设备".into();
    }

    pub fn cancel_mfa(&mut self) {
        self.pending_mfa = None;
        self.login_status.clear();
    }

    pub fn set_authenticated(
        &mut self,
        account: impl Into<String>,
        account_id: impl Into<String>,
        local_device: LocalDeviceRegistration,
        devices: Vec<DeviceView>,
    ) {
        let local_device_id = local_device.device_id.clone();
        self.account = Some(account.into());
        self.account_id = Some(account_id.into());
        self.local_device = Some(local_device);
        self.devices = devices
            .iter()
            .map(|device| AppDevice::from_api(device, &local_device_id))
            .collect();
        self.pending_mfa = None;
        self.page = Page::Devices;
        self.login_status.clear();
    }

    pub fn set_service_config(&mut self, config: ServiceConfig, status: impl Into<String>) {
        self.service_config = Some(config);
        self.server_status = status.into();
    }

    pub fn set_server_status(&mut self, status: impl Into<String>) {
        self.server_status = status.into();
    }

    pub fn set_signal_status(&mut self, status: impl Into<String>) {
        self.signal_status = status.into();
    }

    pub fn navigate(&mut self, page: Page) {
        if self.account.is_some() {
            self.page = page;
        }
    }

    pub fn request_assistance(
        &mut self,
        device_id: &str,
        temporary_code: &str,
        risk_confirmed: bool,
    ) {
        self.assist_status = if device_id.trim().is_empty() {
            "未发起：请输入对方设备 ID".into()
        } else if temporary_code.trim().is_empty() {
            "未发起：请输入临时验证码".into()
        } else if !risk_confirmed {
            "未发起：请先确认对方身份与远控风险".into()
        } else {
            "未发起：OPAQUE 临时验证码客户端尚未接入，不会上传验证码明文".into()
        };
    }

    pub fn set_session_status(&mut self, status: impl Into<String>) {
        self.session_status = status.into();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{Architecture, DeviceCapabilities};

    fn platform() -> PlatformSnapshot {
        PlatformSnapshot {
            platform_label: "Ubuntu 26.04 LTS".into(),
            local_device_name: "Test Ubuntu".into(),
            session_kind: "Wayland".into(),
            capture_status: "unsupported".into(),
            render_status: "unsupported".into(),
            input_status: "unsupported".into(),
            privacy_status: "unsupported".into(),
        }
    }

    fn device(device_id: &str) -> DeviceView {
        DeviceView {
            device_id: device_id.into(),
            display_name: "Test Ubuntu".into(),
            platform: Platform::Ubuntu,
            os_version: "26.04".into(),
            arch: Architecture::X86_64,
            role_capabilities: DeviceCapabilities {
                controller: true,
                controlled: true,
                file_transfer: false,
                unattended: false,
            },
            status: DeviceStatus::Offline,
            public_key_id: "key-1".into(),
            public_key_version: 1,
        }
    }

    #[test]
    fn authentication_uses_only_server_backed_registration() {
        let mut app = AppModel::new(platform());
        let registration = LocalDeviceRegistration {
            display_name: "Test Ubuntu".into(),
            device_id: "device-1".into(),
            controller: true,
            controlled: true,
            server_backed: true,
            public_key_id: Some("key-1".into()),
            public_key_version: Some(1),
            identity_durably_persisted: false,
        };
        app.set_authenticated(
            "owner@example.com",
            "account-1",
            registration,
            vec![device("device-1")],
        );

        assert!(app.local_device().expect("device").server_backed);
        assert_eq!(app.account(), Some("owner@example.com"));
        assert_eq!(app.account_id(), Some("account-1"));
        assert_eq!(app.devices().len(), 1);
    }

    #[test]
    fn busy_devices_remain_in_the_online_group() {
        let mut api_device = device("device-busy");
        api_device.status = DeviceStatus::Busy;

        let view = AppDevice::from_api(&api_device, "other-device");

        assert!(view.online);
        assert_eq!(view.state, "使用中");
    }

    #[test]
    fn pages_are_only_reachable_after_server_authentication() {
        let mut app = AppModel::new(platform());
        app.navigate(Page::Assist);
        assert_eq!(app.page(), Page::Devices);

        app.set_authenticated(
            "owner@example.com",
            "account-1",
            LocalDeviceRegistration {
                display_name: "Test Ubuntu".into(),
                device_id: "device-1".into(),
                controller: true,
                controlled: true,
                server_backed: true,
                public_key_id: Some("key-1".into()),
                public_key_version: Some(1),
                identity_durably_persisted: true,
            },
            vec![],
        );
        app.navigate(Page::Assist);
        assert_eq!(app.page(), Page::Assist);
    }

    #[test]
    fn assistance_never_sends_a_plaintext_temporary_code() {
        let mut app = AppModel::new(platform());
        app.request_assistance("307 455 218", "123456", true);
        assert!(app.assist_status().contains("OPAQUE"));
        assert!(!app.assist_status().contains("123456"));
    }

    fn mfa_challenge(expires_at_epoch_millis: u64) -> MfaChallenge {
        MfaChallenge {
            code: "mfa_required".into(),
            mfa_required: true,
            mfa_challenge_id: "challenge-1".into(),
            allowed_factors: vec![MfaFactor::Totp, MfaFactor::RecoveryCode],
            expires_at_epoch_millis,
            attempts_remaining: 5,
        }
    }

    #[test]
    fn mfa_required_verify_authenticated_clears_challenge() {
        let mut app = AppModel::new(platform());
        app.begin_mfa("owner@example.com", mfa_challenge(10_000), 1_000);

        let attempt = app
            .prepare_mfa_attempt(MfaFactor::Totp, "123456", 2_000)
            .expect("active challenge");
        assert_eq!(attempt.account, "owner@example.com");
        assert_eq!(attempt.challenge_id, "challenge-1");

        app.complete_mfa();
        app.set_authenticated(
            attempt.account,
            "account-1",
            LocalDeviceRegistration {
                display_name: "Test Ubuntu".into(),
                device_id: "device-1".into(),
                controller: true,
                controlled: true,
                server_backed: true,
                public_key_id: Some("key-1".into()),
                public_key_version: Some(1),
                identity_durably_persisted: true,
            },
            vec![device("device-1")],
        );

        assert_eq!(app.account(), Some("owner@example.com"));
        assert!(!app.mfa_required());
    }

    #[test]
    fn failed_mfa_stays_on_challenge_without_retaining_code() {
        let mut app = AppModel::new(platform());
        app.begin_mfa("owner@example.com", mfa_challenge(10_000), 1_000);
        app.prepare_mfa_attempt(MfaFactor::RecoveryCode, "recovery-private", 2_000)
            .expect("active challenge");

        app.record_mfa_rejection(2_000);

        assert!(app.mfa_required());
        assert_eq!(app.mfa_attempts_remaining(), 4);
        assert!(!app.login_status().contains("recovery-private"));
    }

    #[test]
    fn cancel_mfa_clears_challenge_and_returns_to_login() {
        let mut app = AppModel::new(platform());
        app.begin_mfa("owner@example.com", mfa_challenge(10_000), 1_000);

        app.cancel_mfa();

        assert!(!app.mfa_required());
        assert!(matches!(
            app.prepare_mfa_attempt(MfaFactor::Totp, "123456", 2_000),
            Err(MfaFlowError::MissingChallenge)
        ));
        assert!(app.login_status().is_empty());
    }

    #[test]
    fn expired_mfa_is_reported_without_submitting() {
        let mut app = AppModel::new(platform());
        app.begin_mfa("owner@example.com", mfa_challenge(2_000), 1_000);

        assert!(app.mfa_expired(2_000));
        assert!(matches!(
            app.prepare_mfa_attempt(MfaFactor::Totp, "123456", 2_000),
            Err(MfaFlowError::Expired)
        ));
    }
}
