use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub account_id: String,
    pub email: String,
    pub display_name: String,
    pub password_hash: String,
    pub status: AccountStatus,
    pub created_at_epoch_millis: u64,
    pub updated_at_epoch_millis: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountStatus {
    Active,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountSession {
    pub account_session_id: String,
    pub account_id: String,
    pub refresh_token_hash: [u8; 32],
    pub mfa_verified: bool,
    pub expires_at_epoch_millis: u64,
    pub revoked_at_epoch_millis: Option<u64>,
    pub revoked_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MfaFactor {
    pub factor_id: String,
    pub account_id: String,
    pub secret_base32: String,
    pub active: bool,
    pub last_used_counter: Option<u64>,
    pub created_at_epoch_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCode {
    pub recovery_code_id: String,
    pub account_id: String,
    pub code_hash: [u8; 32],
    pub used_at_epoch_millis: Option<u64>,
    pub expires_at_epoch_millis: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthChallenge {
    pub challenge_id: String,
    pub account_id: String,
    pub device_id: Option<String>,
    pub purpose: ChallengePurpose,
    pub operation_binding_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub login: Option<LoginChallengeContext>,
    pub attempts_remaining: u8,
    pub expires_at_epoch_millis: u64,
    pub verified_at_epoch_millis: Option<u64>,
    pub consumed_at_epoch_millis: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LoginDeviceState {
    Registered,
    PendingEnrollment,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoginChallengeContext {
    pub device_state: LoginDeviceState,
    pub device_id: String,
    pub account_updated_at_epoch_millis: u64,
    pub device_public_key: [u8; 32],
    pub device_public_key_fingerprint: [u8; 32],
    pub public_key_id: Option<String>,
    pub public_key_version: u32,
    pub client_nonce: [u8; 32],
    pub server_nonce: [u8; 32],
    pub login_request_binding_hash: [u8; 32],
    pub login_challenge_binding_hash: [u8; 32],
    pub ip_address_hash: [u8; 32],
    pub user_agent_hash: [u8; 32],
    pub required_factors: Vec<String>,
    pub trusted_device_id: Option<String>,
    pub protocol_version: u16,
    pub issued_at_epoch_millis: u64,
    pub attempts_limit: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ChallengePurpose {
    LoginMfa,
    StepUp(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskChallengeStatus {
    Issued,
    Verified,
    Failed,
    Consumed,
    Expired,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskChallenge {
    pub risk_challenge_id: String,
    pub account_id: String,
    pub device_id: Option<String>,
    pub purpose: String,
    pub operation_binding_hash: [u8; 32],
    pub risk_level: String,
    pub required_methods: Vec<String>,
    pub status: RiskChallengeStatus,
    pub attempts_remaining: u8,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at_epoch_millis: u64,
    pub created_at_epoch_millis: u64,
    pub verified_at_epoch_millis: Option<u64>,
    pub consumed_at_epoch_millis: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedDeviceStatus {
    Active,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedControllerDevice {
    pub trusted_device_id: String,
    pub account_id: String,
    pub controller_device_id: String,
    pub device_fingerprint_hash: [u8; 32],
    pub trust_level: String,
    pub status: TrustedDeviceStatus,
    pub trust_proof_type: String,
    pub created_at_epoch_millis: u64,
    pub last_used_at_epoch_millis: Option<u64>,
    pub expires_at_epoch_millis: u64,
    pub revoked_at_epoch_millis: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceEnrollmentGrant {
    pub grant_id: String,
    pub grant_secret_hash: [u8; 32],
    pub account_id: String,
    pub device_id: String,
    pub device_public_key_fingerprint: [u8; 32],
    pub login_challenge_id: String,
    pub login_challenge_binding_hash: [u8; 32],
    pub trust_proof_type: Option<String>,
    pub trust_level: Option<String>,
    pub establish_trust: bool,
    pub protocol_version: u16,
    pub issued_account_session_id: String,
    pub issued_at_epoch_millis: u64,
    pub expires_at_epoch_millis: u64,
    pub consumed_at_epoch_millis: Option<u64>,
    pub registration_request_binding_hash: Option<[u8; 32]>,
    pub registered_public_key_id: Option<String>,
    pub registered_trusted_device_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCodeDelivery {
    pub delivery_id: String,
    pub account_id: String,
    pub account_session_id: String,
    pub factor_id: String,
    pub idempotency_key_hash: [u8; 32],
    pub finish_request_binding_hash: [u8; 32],
    pub client_ephemeral_public_key: [u8; 32],
    pub server_ephemeral_public_key: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub recovery_code_count: u16,
    pub created_at_epoch_millis: u64,
    pub expires_at_epoch_millis: u64,
    pub acknowledged_at_epoch_millis: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Windows,
    Ubuntu,
    Ios,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Aarch64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceCapabilities {
    pub controller: bool,
    pub controlled: bool,
    pub file_transfer: bool,
    pub unattended: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    Online,
    Offline,
    Busy,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceLifecycleStatus {
    Online,
    Offline,
    Busy,
    Suspended,
    Disabled,
    Unbound,
}

impl DeviceLifecycleStatus {
    pub const fn is_authorizable(self) -> bool {
        matches!(self, Self::Online | Self::Offline | Self::Busy)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    pub device_id: String,
    pub account_id: String,
    pub display_name: String,
    pub platform: Platform,
    pub os_version: String,
    pub arch: Architecture,
    pub capabilities: DeviceCapabilities,
    pub public_key_id: String,
    pub public_key: [u8; 32],
    pub public_key_version: u32,
    pub public_key_revoked_at_epoch_millis: Option<u64>,
    pub status: DeviceLifecycleStatus,
    pub last_seen_epoch_millis: Option<u64>,
    pub created_at_epoch_millis: u64,
    pub updated_at_epoch_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePublicKeyRecord {
    pub public_key_id: String,
    pub device_id: String,
    pub public_key: [u8; 32],
    pub version: u32,
    pub created_at_epoch_millis: u64,
    pub revoked_at_epoch_millis: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceView {
    pub device_id: String,
    pub display_name: String,
    pub platform: Platform,
    pub os_version: String,
    pub arch: Architecture,
    pub role_capabilities: DeviceCapabilities,
    pub status: DeviceStatus,
    pub public_key_id: String,
    pub public_key_version: u32,
}

impl From<&Device> for DeviceView {
    fn from(device: &Device) -> Self {
        Self {
            device_id: device.device_id.clone(),
            display_name: device.display_name.clone(),
            platform: device.platform.clone(),
            os_version: device.os_version.clone(),
            arch: device.arch.clone(),
            role_capabilities: device.capabilities.clone(),
            status: match device.status {
                DeviceLifecycleStatus::Online => DeviceStatus::Online,
                DeviceLifecycleStatus::Busy => DeviceStatus::Busy,
                DeviceLifecycleStatus::Offline
                | DeviceLifecycleStatus::Suspended
                | DeviceLifecycleStatus::Disabled
                | DeviceLifecycleStatus::Unbound => DeviceStatus::Offline,
            },
            public_key_id: device.public_key_id.clone(),
            public_key_version: device.public_key_version,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    AccountPrompt,
    TemporaryCode,
    Unattended,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    PendingCodeVerification,
    PendingUnattendedVerification,
    CodeVerified,
    UnattendedVerified,
    WaitingApproval,
    Accepted,
    Connected,
    Degraded,
    Reconnecting,
    Cancelled,
    Closed,
    Rejected,
    Failed,
}

impl SessionStatus {
    pub fn can_signal(self) -> bool {
        matches!(
            self,
            Self::Accepted
                | Self::UnattendedVerified
                | Self::Connected
                | Self::Degraded
                | Self::Reconnecting
        )
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Cancelled | Self::Closed | Self::Rejected | Self::Failed
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionPermissions {
    pub remote_desktop: bool,
    pub input_control: bool,
    pub clipboard: bool,
    pub file_transfer: bool,
    pub unattended: bool,
    pub privacy_screen: bool,
    pub block_local_input: bool,
    pub require_prompt: bool,
    pub allow_relay: bool,
}

impl Default for SessionPermissions {
    fn default() -> Self {
        Self {
            remote_desktop: false,
            input_control: false,
            clipboard: false,
            file_transfer: false,
            unattended: false,
            privacy_screen: false,
            block_local_input: false,
            require_prompt: true,
            allow_relay: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Session {
    pub session_id: String,
    pub controller_account_id: String,
    pub controller_device_id: String,
    pub controlled_device_id: String,
    pub auth_method: AuthMethod,
    pub status: SessionStatus,
    pub permissions: SessionPermissions,
    pub permissions_digest: String,
    pub policy_evaluation_id: String,
    pub relay_token_epoch: u64,
    pub session_expires_at_epoch_millis: u64,
    pub created_at_epoch_millis: u64,
    pub updated_at_epoch_millis: u64,
    pub ended_at_epoch_millis: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionView {
    pub session_id: String,
    pub controller_account_id: String,
    pub controller_device_id: String,
    pub controlled_device_id: String,
    pub auth_method: AuthMethod,
    pub status: SessionStatus,
    pub permissions: SessionPermissions,
    pub permissions_digest: String,
    pub policy_evaluation_id: String,
    pub relay_token_epoch: u64,
    pub session_expires_at_epoch_millis: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SessionEvent {
    pub event_id: String,
    pub session_id: String,
    pub event_type: String,
    pub from_status: Option<SessionStatus>,
    pub to_status: SessionStatus,
    pub actor_type: String,
    pub actor_account_id: Option<String>,
    pub actor_device_id: Option<String>,
    pub actor_role: Option<String>,
    pub reason: Option<String>,
    pub idempotency_key_hash: String,
    pub request_id: String,
    pub created_at_epoch_millis: u64,
    pub result_session: Option<Session>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluation {
    pub policy_evaluation_id: String,
    pub session_id: String,
    pub account_id: String,
    pub controller_device_id: String,
    pub controlled_device_id: String,
    pub access_decision: String,
    pub anti_abuse_decision: String,
    pub session_access_decision: String,
    pub effective_permissions: SessionPermissions,
    pub permissions_digest: String,
    pub evaluated_at_epoch_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyRecord {
    pub account_id: String,
    pub device_id: String,
    pub method: String,
    pub path: String,
    pub operation: String,
    pub idempotency_key: String,
    pub body_hash: String,
    pub request_id: String,
    pub session_id: String,
    pub request_binding_hash: String,
    pub created_at_epoch_millis: u64,
    pub expires_at_epoch_millis: u64,
}

impl From<&Session> for SessionView {
    fn from(session: &Session) -> Self {
        Self {
            session_id: session.session_id.clone(),
            controller_account_id: session.controller_account_id.clone(),
            controller_device_id: session.controller_device_id.clone(),
            controlled_device_id: session.controlled_device_id.clone(),
            auth_method: session.auth_method,
            status: session.status,
            permissions: session.permissions,
            permissions_digest: session.permissions_digest.clone(),
            policy_evaluation_id: session.policy_evaluation_id.clone(),
            relay_token_epoch: session.relay_token_epoch,
            session_expires_at_epoch_millis: session.session_expires_at_epoch_millis,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AuditEntry {
    pub audit_id: String,
    pub actor_type: String,
    pub actor_account_id: Option<String>,
    pub actor_device_id: Option<String>,
    pub actor_role: Option<String>,
    pub actor_service: Option<String>,
    pub target_device_id: Option<String>,
    pub session_id: Option<String>,
    pub action: String,
    pub result: String,
    pub reason: Option<String>,
    pub metadata: BTreeMap<String, Value>,
    pub request_id: String,
    pub created_at_epoch_millis: u64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Database {
    pub accounts: BTreeMap<String, Account>,
    pub account_by_email: BTreeMap<String, String>,
    pub account_sessions: BTreeMap<String, AccountSession>,
    pub mfa_factors: BTreeMap<String, MfaFactor>,
    pub recovery_codes: BTreeMap<String, RecoveryCode>,
    pub risk_challenges: BTreeMap<String, RiskChallenge>,
    pub login_challenge_contexts: BTreeMap<String, LoginChallengeContext>,
    pub trusted_controller_devices: BTreeMap<String, TrustedControllerDevice>,
    pub device_enrollment_grants: BTreeMap<String, DeviceEnrollmentGrant>,
    pub recovery_code_deliveries: BTreeMap<String, RecoveryCodeDelivery>,
    pub devices: BTreeMap<String, Device>,
    pub device_public_keys: BTreeMap<String, DevicePublicKeyRecord>,
    pub sessions: BTreeMap<String, Session>,
    pub session_events: Vec<SessionEvent>,
    pub session_idempotency: BTreeMap<String, IdempotencyRecord>,
    pub policy_evaluations: BTreeMap<String, PolicyEvaluation>,
    pub audit_logs: Vec<AuditEntry>,
}
