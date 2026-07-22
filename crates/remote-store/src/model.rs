use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::collections::BTreeMap;

pub type EpochMillis = i64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PasswordHash(pub String);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Sha256Digest(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncryptedValue(pub Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OpaqueRecord(pub Vec<u8>);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PublicKey(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChaCha20Poly1305Nonce(pub [u8; 12]);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignatureBytes(pub Vec<u8>);

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JsonObject(pub BTreeMap<String, JsonValue>);

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JsonArray(pub Vec<JsonValue>);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountStatus {
    Active,
    Disabled,
    Locked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Windows,
    Ubuntu,
    Ios,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Aarch64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    Online,
    Offline,
    Busy,
    Suspended,
    Disabled,
    Unbound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyValue {
    Inherit,
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptPolicy {
    Inherit,
    Require,
    NoPrompt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportPath {
    LanDirect,
    UdpP2p,
    QuicRelay,
    #[serde(rename = "tls_443_relay")]
    Tls443Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    TemporaryCode,
    Unattended,
    AccountPrompt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateRole {
    Controller,
    Controlled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    LanDirect,
    UdpP2p,
    QuicRelay,
    #[serde(rename = "tls_443_relay")]
    Tls443Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateSource {
    UdpObserved,
    LocalInterface,
    RelayAllocated,
    StaticConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidatePairStatus {
    Probing,
    Selected,
    Degraded,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayNodeStatus {
    Active,
    Draining,
    Disabled,
    Quarantined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChallengeStatus {
    Active,
    Consumed,
    Expired,
    Replaced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseChannel {
    Stable,
    Beta,
    Internal,
    Private,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseArtifactStatus {
    Draft,
    Published,
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateEventType {
    Checked,
    Downloaded,
    Verified,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileTransferDirection {
    ControllerToControlled,
    ControlledToController,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileTransferStatus {
    Requested,
    Accepted,
    Rejected,
    Transferring,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EffectivePermissions {
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

impl Default for EffectivePermissions {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayeredPermissions {
    pub allow_remote_desktop: PolicyValue,
    pub allow_input_control: PolicyValue,
    pub allow_clipboard: PolicyValue,
    pub allow_file_transfer: PolicyValue,
    pub allow_unattended: PolicyValue,
    pub allow_privacy_screen: PolicyValue,
    pub allow_block_local_input: PolicyValue,
    pub allow_relay: PolicyValue,
    pub require_prompt: PromptPolicy,
    pub allow_remote_reboot: PolicyValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRecord {
    pub account_id: String,
    pub email: String,
    pub display_name: String,
    pub password_hash: PasswordHash,
    pub status: AccountStatus,
    pub created_at_epoch_millis: EpochMillis,
    pub updated_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountSessionRecord {
    pub account_session_id: String,
    pub account_id: String,
    pub refresh_token_hash: Sha256Digest,
    pub device_label: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at_epoch_millis: EpochMillis,
    pub revoked_at_epoch_millis: Option<EpochMillis>,
    pub revoked_reason: Option<String>,
    pub created_at_epoch_millis: EpochMillis,
    pub updated_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountMfaFactorRecord {
    pub factor_id: String,
    pub account_id: String,
    pub factor_type: String,
    pub encrypted_secret: EncryptedValue,
    pub status: String,
    pub last_used_at_epoch_millis: Option<EpochMillis>,
    pub created_at_epoch_millis: EpochMillis,
    pub disabled_at_epoch_millis: Option<EpochMillis>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MfaRecoveryCodeDeliveryRecord {
    pub delivery_id: String,
    pub account_id: String,
    pub account_session_id: String,
    pub factor_id: String,
    pub idempotency_key_hash: Sha256Digest,
    pub finish_request_binding_hash: Sha256Digest,
    pub client_ephemeral_public_key: PublicKey,
    pub server_ephemeral_public_key: PublicKey,
    pub nonce: ChaCha20Poly1305Nonce,
    pub ciphertext: EncryptedValue,
    pub recovery_code_count: u16,
    pub created_at_epoch_millis: EpochMillis,
    pub expires_at_epoch_millis: EpochMillis,
    pub acknowledged_at_epoch_millis: Option<EpochMillis>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRecoveryCodeRecord {
    pub recovery_code_id: String,
    pub account_id: String,
    pub code_hash: Sha256Digest,
    pub status: String,
    pub used_at_epoch_millis: Option<EpochMillis>,
    pub created_at_epoch_millis: EpochMillis,
    pub expires_at_epoch_millis: Option<EpochMillis>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRiskChallengeRecord {
    pub risk_challenge_id: String,
    pub account_id: String,
    pub device_id: Option<String>,
    pub purpose: String,
    pub operation_binding_hash: Sha256Digest,
    pub risk_level: String,
    pub required_methods: JsonArray,
    pub status: String,
    pub attempts_remaining: u8,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at_epoch_millis: EpochMillis,
    pub created_at_epoch_millis: EpochMillis,
    pub verified_at_epoch_millis: Option<EpochMillis>,
    pub consumed_at_epoch_millis: Option<EpochMillis>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceEnrollmentGrantRecord {
    pub grant_id: String,
    pub grant_secret_hash: Sha256Digest,
    pub account_id: String,
    pub device_id: String,
    pub device_public_key_fingerprint: Sha256Digest,
    pub login_challenge_id: String,
    pub login_challenge_binding_hash: Sha256Digest,
    pub trust_proof_type: Option<String>,
    pub trust_level: Option<String>,
    pub establish_trust: bool,
    pub protocol_version: u16,
    pub issued_account_session_id: String,
    pub issued_at_epoch_millis: EpochMillis,
    pub expires_at_epoch_millis: EpochMillis,
    pub consumed_at_epoch_millis: Option<EpochMillis>,
    pub created_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedControllerDeviceRecord {
    pub trusted_device_id: String,
    pub account_id: String,
    pub controller_device_id: String,
    pub device_fingerprint_hash: Sha256Digest,
    pub trust_level: String,
    pub status: String,
    pub trust_proof_type: String,
    pub created_at_epoch_millis: EpochMillis,
    pub last_used_at_epoch_millis: Option<EpochMillis>,
    pub expires_at_epoch_millis: EpochMillis,
    pub revoked_at_epoch_millis: Option<EpochMillis>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub device_id: String,
    pub account_id: String,
    pub primary_organization_id: Option<String>,
    pub display_name: String,
    pub platform: Platform,
    pub os_version: String,
    pub arch: Architecture,
    pub public_key_id: String,
    pub public_key: PublicKey,
    pub public_key_version: u32,
    pub public_key_revoked_at_epoch_millis: Option<EpochMillis>,
    pub status: DeviceStatus,
    pub unattended_enabled: bool,
    pub last_seen_epoch_millis: Option<EpochMillis>,
    pub created_at_epoch_millis: EpochMillis,
    pub updated_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePolicyRecord {
    pub device_id: String,
    pub permissions: EffectivePermissions,
    pub allow_remote_reboot: bool,
    pub last_high_risk_allow_step_up_challenge_id: Option<String>,
    pub last_high_risk_allow_step_up_verified_at_epoch_millis: Option<EpochMillis>,
    pub created_at_epoch_millis: EpochMillis,
    pub updated_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceAccessRuleRecord {
    pub device_access_rule_id: String,
    pub controlled_device_id: String,
    pub controller_account_id: Option<String>,
    pub controller_device_id: Option<String>,
    pub rule_type: String,
    pub reason: Option<String>,
    pub created_by_account_id: String,
    pub created_at_epoch_millis: EpochMillis,
    pub expires_at_epoch_millis: Option<EpochMillis>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceLocalSecuritySettingRecord {
    pub device_id: String,
    pub allow_privacy_screen: bool,
    pub allow_block_local_input: bool,
    pub local_escape_hint_enabled: bool,
    pub privacy_screen_supported: bool,
    pub block_local_input_supported: bool,
    pub last_capability_probe_at_epoch_millis: Option<EpochMillis>,
    pub last_allow_step_up_challenge_id: Option<String>,
    pub last_allow_step_up_verified_at_epoch_millis: Option<EpochMillis>,
    pub created_at_epoch_millis: EpochMillis,
    pub updated_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiIdempotencyKeyRecord {
    pub idempotency_key: String,
    pub account_id: String,
    pub device_id: String,
    pub method: String,
    pub path: String,
    pub body_hash: Sha256Digest,
    pub request_id: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub response_status: Option<u16>,
    pub response_body_hash: Option<Sha256Digest>,
    pub expires_at_epoch_millis: EpochMillis,
    pub created_at_epoch_millis: EpochMillis,
}

impl ApiIdempotencyKeyRecord {
    fn storage_key(&self) -> String {
        [
            self.account_id.as_str(),
            self.device_id.as_str(),
            self.method.as_str(),
            self.path.as_str(),
            self.idempotency_key.as_str(),
        ]
        .join("\u{0}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationCodeRecord {
    pub code_id: String,
    pub device_id: String,
    pub code_verifier_record: OpaqueRecord,
    pub code_verifier_salt: Vec<u8>,
    pub proof_scheme: String,
    pub active_challenge_id: Option<String>,
    pub active_session_id: Option<String>,
    pub server_nonce: Option<Vec<u8>>,
    pub challenge_status: ChallengeStatus,
    pub challenge_issued_at_epoch_millis: Option<EpochMillis>,
    pub challenge_expires_at_epoch_millis: Option<EpochMillis>,
    pub expires_at_epoch_millis: EpochMillis,
    pub attempts_remaining: u8,
    pub consumed_at_epoch_millis: Option<EpochMillis>,
    pub created_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnattendedSecretRecord {
    pub unattended_secret_id: String,
    pub device_id: String,
    pub credential_record: OpaqueRecord,
    pub credential_salt: Vec<u8>,
    pub proof_scheme: String,
    pub version: u32,
    pub enabled: bool,
    pub created_at_epoch_millis: EpochMillis,
    pub rotated_at_epoch_millis: Option<EpochMillis>,
    pub disabled_at_epoch_millis: Option<EpochMillis>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessPolicyRecord {
    pub access_policy_id: String,
    pub scope_type: String,
    pub scope_id: String,
    pub name: String,
    pub priority: i32,
    pub status: String,
    pub conditions: JsonObject,
    pub effects: JsonObject,
    pub created_by_account_id: String,
    pub updated_by_account_id: String,
    pub created_at_epoch_millis: EpochMillis,
    pub updated_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessPolicyAssignmentRecord {
    pub assignment_id: String,
    pub access_policy_id: String,
    pub target_type: String,
    pub target_id: String,
    pub status: String,
    pub created_by_account_id: String,
    pub disabled_at_epoch_millis: Option<EpochMillis>,
    pub deleted_at_epoch_millis: Option<EpochMillis>,
    pub created_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyEvaluationRecord {
    pub policy_evaluation_id: String,
    pub account_id: String,
    pub controller_device_id: String,
    pub controlled_device_id: String,
    pub session_id: Option<String>,
    pub request_type: String,
    pub access_decision: String,
    pub anti_abuse_decision: String,
    pub session_access_decision: String,
    pub effective_permissions: EffectivePermissions,
    pub permissions_digest: Sha256Digest,
    pub matched_policy_ids: JsonArray,
    pub abuse_actions: JsonArray,
    pub risk_challenge_id: Option<String>,
    pub cooldown_until_epoch_millis: Option<EpochMillis>,
    pub user_warnings: JsonArray,
    pub deny_reason: Option<String>,
    pub metadata: JsonObject,
    pub created_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id: String,
    pub controller_account_id: String,
    pub controller_device_id: String,
    pub controlled_device_id: String,
    pub auth_method: AuthMethod,
    pub status: SessionStatus,
    pub permissions: EffectivePermissions,
    pub permissions_digest: Sha256Digest,
    pub permissions_digest_last_changed_at_epoch_millis: EpochMillis,
    pub policy_evaluation_id: String,
    pub relay_token_epoch: u64,
    pub session_expires_at_epoch_millis: EpochMillis,
    pub transport_path: Option<TransportPath>,
    pub selected_candidate_pair_id: Option<String>,
    pub relay_node_id: Option<String>,
    pub started_at_epoch_millis: Option<EpochMillis>,
    pub ended_at_epoch_millis: Option<EpochMillis>,
    pub created_at_epoch_millis: EpochMillis,
    pub updated_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteRebootRequestRecord {
    pub reboot_request_id: String,
    pub session_id: String,
    pub controller_account_id: String,
    pub controller_device_id: String,
    pub controlled_device_id: String,
    pub status: String,
    pub api_request_hash: Sha256Digest,
    pub api_request_hash_status: String,
    pub mode: String,
    pub reason_hash: Sha256Digest,
    pub countdown_seconds: u32,
    pub reconnect_after_reboot: bool,
    pub allow_remote_reboot: bool,
    pub allow_remote_reboot_last_changed_at_epoch_millis: EpochMillis,
    pub step_up_challenge_id: String,
    pub step_up_verified_at_epoch_millis: EpochMillis,
    pub step_up_expires_at_epoch_millis: EpochMillis,
    pub idempotency_key_hash: Sha256Digest,
    pub policy_evaluation_id: String,
    pub policy_evaluated_at_epoch_millis: EpochMillis,
    pub permissions_digest: Sha256Digest,
    pub permissions_digest_last_changed_at_epoch_millis: EpochMillis,
    pub auto_resume_consent: String,
    pub consent_at_epoch_millis: Option<EpochMillis>,
    pub consent_controlled_device_id: Option<String>,
    pub consent_local_user_principal_hash: Option<Sha256Digest>,
    pub consent_revoked_at_epoch_millis: Option<EpochMillis>,
    pub consent_revoked_by_actor_type: Option<String>,
    pub consent_revoked_reason: Option<String>,
    pub local_consent_token_hash: Option<Sha256Digest>,
    pub auto_resume_consumed_at_epoch_millis: Option<EpochMillis>,
    pub reboot_resume_token_id: Option<String>,
    pub reboot_resume_token_secret_hash: Option<Sha256Digest>,
    pub reboot_resume_token_consumed_at_epoch_millis: Option<EpochMillis>,
    pub reboot_resume_token_invalidated_at_epoch_millis: Option<EpochMillis>,
    pub reboot_resume_token_invalidation_reason: Option<String>,
    pub resume_expires_at_epoch_millis: Option<EpochMillis>,
    pub created_at_epoch_millis: EpochMillis,
    pub expires_at_epoch_millis: EpochMillis,
    pub requested_at_epoch_millis: EpochMillis,
    pub accepted_at_epoch_millis: Option<EpochMillis>,
    pub executed_at_epoch_millis: Option<EpochMillis>,
    pub cancelled_at_epoch_millis: Option<EpochMillis>,
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionCandidateRecord {
    pub candidate_id: String,
    pub session_id: String,
    pub device_id: String,
    pub role: CandidateRole,
    pub kind: CandidateKind,
    pub endpoint: String,
    pub source: CandidateSource,
    pub observe_result_id: Option<String>,
    pub priority: i32,
    pub rtt_ms: Option<u32>,
    pub loss_ppm: Option<u32>,
    pub jitter_ms: Option<u32>,
    pub relay_node_id: Option<String>,
    pub created_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionCandidatePairRecord {
    pub candidate_pair_id: String,
    pub session_id: String,
    pub controller_candidate_id: String,
    pub controlled_candidate_id: String,
    pub selected_transport_path: TransportPath,
    pub relay_node_id: Option<String>,
    pub selected_at_epoch_millis: Option<EpochMillis>,
    pub rtt_ms: Option<u32>,
    pub loss_ppm: Option<u32>,
    pub jitter_ms: Option<u32>,
    pub status: CandidatePairStatus,
    pub created_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEventRecord {
    pub event_id: String,
    pub session_id: String,
    pub event_type: String,
    pub actor_type: String,
    pub actor_account_id: Option<String>,
    pub actor_device_id: Option<String>,
    pub actor_role: String,
    pub actor_service: Option<String>,
    pub reason: Option<String>,
    pub metadata: JsonObject,
    pub created_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayNodeRecord {
    pub relay_node_id: String,
    pub region: String,
    pub country: String,
    pub provider: String,
    pub public_endpoint: String,
    pub status: RelayNodeStatus,
    pub max_sessions: u32,
    pub active_sessions: u32,
    pub supports_quic: bool,
    pub supports_tls_443: bool,
    pub data_residency_class: Option<String>,
    pub created_at_epoch_millis: EpochMillis,
    pub updated_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelaySessionStatRecord {
    pub relay_session_stat_id: String,
    pub session_id: String,
    pub relay_node_id: String,
    pub region: String,
    pub region_policy_id: Option<String>,
    pub region_policy_version: Option<u64>,
    pub transport: TransportPath,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub rtt_ms: Option<u32>,
    pub loss_ppm: Option<u32>,
    pub started_at_epoch_millis: EpochMillis,
    pub ended_at_epoch_millis: Option<EpochMillis>,
    pub disconnect_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileTransferRecord {
    pub file_transfer_id: String,
    pub session_id: String,
    pub sender_device_id: String,
    pub receiver_device_id: String,
    pub direction: FileTransferDirection,
    pub file_name: String,
    pub safe_file_name: Option<String>,
    pub file_size_bytes: u64,
    pub sha256: Sha256Digest,
    pub status: FileTransferStatus,
    pub confirmed_by_controlled: bool,
    pub confirmed_by_device_id: Option<String>,
    pub confirmed_at_epoch_millis: Option<EpochMillis>,
    pub receiver_save_policy: String,
    pub temporary_path_hash: Option<Sha256Digest>,
    pub final_path_hash: Option<Sha256Digest>,
    pub bytes_transferred: u64,
    pub cancelled_by_device_id: Option<String>,
    pub cancelled_at_epoch_millis: Option<EpochMillis>,
    pub started_at_epoch_millis: Option<EpochMillis>,
    pub ended_at_epoch_millis: Option<EpochMillis>,
    pub failure_reason: Option<String>,
    pub created_at_epoch_millis: EpochMillis,
    pub updated_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbuseReportRecord {
    pub abuse_report_id: String,
    pub reporter_account_id: String,
    pub reporter_device_id: String,
    pub reported_account_id: Option<String>,
    pub reported_device_id: Option<String>,
    pub session_id: Option<String>,
    pub category: String,
    pub reason: Option<String>,
    pub status: String,
    pub created_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbuseCaseRecord {
    pub abuse_case_id: String,
    pub primary_report_id: String,
    pub subject_account_id: Option<String>,
    pub subject_device_id: Option<String>,
    pub risk_level: String,
    pub status: String,
    pub assigned_to_account_id: Option<String>,
    pub created_at_epoch_millis: EpochMillis,
    pub updated_at_epoch_millis: EpochMillis,
    pub closed_at_epoch_millis: Option<EpochMillis>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbuseEnforcementActionRecord {
    pub enforcement_action_id: String,
    pub abuse_case_id: String,
    pub subject_type: String,
    pub subject_id: String,
    pub action: String,
    pub reason: String,
    pub starts_at_epoch_millis: EpochMillis,
    pub expires_at_epoch_millis: Option<EpochMillis>,
    pub created_by_actor_type: String,
    pub created_by_account_id: Option<String>,
    pub revoked_at_epoch_millis: Option<EpochMillis>,
    pub created_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbuseRiskEventRecord {
    pub risk_event_id: String,
    pub account_id: Option<String>,
    pub device_id: Option<String>,
    pub session_id: Option<String>,
    pub event_type: String,
    pub risk_level: String,
    pub signals: JsonObject,
    pub decision: String,
    pub created_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationRecord {
    pub organization_id: String,
    pub name: String,
    pub organization_type: String,
    pub status: String,
    pub created_by_account_id: Option<String>,
    pub created_at_epoch_millis: EpochMillis,
    pub updated_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationDeviceRecord {
    pub organization_device_id: String,
    pub organization_id: String,
    pub device_id: String,
    pub membership_type: String,
    pub status: String,
    pub created_at_epoch_millis: EpochMillis,
    pub updated_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationMemberRecord {
    pub organization_member_id: String,
    pub organization_id: String,
    pub account_id: String,
    pub role_id: String,
    pub status: String,
    pub created_at_epoch_millis: EpochMillis,
    pub updated_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleRecord {
    pub role_id: String,
    pub organization_id: Option<String>,
    pub scope: String,
    pub role_key: String,
    pub display_name: String,
    pub status: String,
    pub created_at_epoch_millis: EpochMillis,
    pub updated_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolePermissionRecord {
    pub role_id: String,
    pub allow_remote_desktop: bool,
    pub allow_input_control: bool,
    pub allow_clipboard: bool,
    pub allow_file_transfer: bool,
    pub allow_unattended: bool,
    pub allow_privacy_screen: bool,
    pub allow_block_local_input: bool,
    pub allow_relay: bool,
    pub can_bypass_prompt: bool,
    pub allow_remote_reboot: bool,
    pub can_manage_organization: bool,
    pub can_manage_devices: bool,
    pub can_manage_policies: bool,
    pub can_view_audit_logs: bool,
    pub can_manage_releases: bool,
    pub can_manage_abuse_cases: bool,
    pub created_at_epoch_millis: EpochMillis,
    pub updated_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrganizationPolicyRecord {
    pub organization_policy_id: String,
    pub organization_id: String,
    pub priority: i32,
    pub permissions: LayeredPermissions,
    pub status: String,
    pub updated_by_account_id: String,
    pub created_at_epoch_millis: EpochMillis,
    pub updated_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceGroupRecord {
    pub device_group_id: String,
    pub organization_id: String,
    pub name: String,
    pub status: String,
    pub created_at_epoch_millis: EpochMillis,
    pub updated_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceGroupMemberRecord {
    pub device_group_member_id: String,
    pub device_group_id: String,
    pub organization_id: String,
    pub device_id: String,
    pub status: String,
    pub created_at_epoch_millis: EpochMillis,
    pub updated_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceGroupPolicyRecord {
    pub device_group_policy_id: String,
    pub device_group_id: String,
    pub priority: i32,
    pub permissions: LayeredPermissions,
    pub status: String,
    pub updated_by_account_id: String,
    pub created_at_epoch_millis: EpochMillis,
    pub updated_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientReleaseChannelRecord {
    pub release_channel_id: String,
    pub channel: ReleaseChannel,
    pub scope_type: String,
    pub scope_id: Option<String>,
    pub status: String,
    pub release_public_key_id: String,
    pub created_at_epoch_millis: EpochMillis,
    pub updated_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientReleaseArtifactRecord {
    pub artifact_id: String,
    pub release_channel_id: String,
    pub version: String,
    pub build_number: u64,
    pub platform: Platform,
    pub arch: Architecture,
    pub artifact_url: String,
    pub storage_location_id: Option<String>,
    pub artifact_sha256: Sha256Digest,
    pub artifact_size_bytes: u64,
    pub manifest_version: u32,
    pub min_supported_version: String,
    pub rollout_percent: u8,
    pub mandatory: bool,
    pub release_notes_url: Option<String>,
    pub manifest_expires_at_epoch_millis: EpochMillis,
    pub manifest_signature: SignatureBytes,
    pub sbom_url: String,
    pub status: ReleaseArtifactStatus,
    pub published_by_actor_type: Option<String>,
    pub published_by_account_id: Option<String>,
    pub published_by_service: Option<String>,
    pub published_at_epoch_millis: Option<EpochMillis>,
    pub revoked_at_epoch_millis: Option<EpochMillis>,
    pub created_at_epoch_millis: EpochMillis,
    pub updated_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientUpdateCheckRecord {
    pub update_check_id: String,
    pub account_id: String,
    pub device_id: String,
    pub platform: Platform,
    pub arch: Architecture,
    pub current_version: String,
    pub channel: ReleaseChannel,
    pub event_type: UpdateEventType,
    pub result: String,
    pub artifact_id: Option<String>,
    pub manifest_signature_valid: Option<bool>,
    pub artifact_hash_valid: Option<bool>,
    pub platform_signature_valid: Option<bool>,
    pub failure_reason: Option<String>,
    pub checked_at_epoch_millis: EpochMillis,
    pub downloaded_at_epoch_millis: Option<EpochMillis>,
    pub verified_at_epoch_millis: Option<EpochMillis>,
    pub failed_at_epoch_millis: Option<EpochMillis>,
    pub created_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditLogRecord {
    pub audit_id: String,
    pub actor_type: String,
    pub actor_account_id: Option<String>,
    pub actor_device_id: Option<String>,
    pub actor_role: String,
    pub actor_service: Option<String>,
    pub target_device_id: Option<String>,
    pub session_id: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub action: String,
    pub result: String,
    pub reason: Option<String>,
    pub metadata: JsonObject,
    pub actor_account_snapshot: Option<JsonObject>,
    pub actor_device_snapshot: Option<JsonObject>,
    pub target_device_snapshot: Option<JsonObject>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    pub created_at_epoch_millis: EpochMillis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    Account,
    AccountSession,
    AccountMfaFactor,
    MfaRecoveryCodeDelivery,
    AccountRecoveryCode,
    AccountRiskChallenge,
    DeviceEnrollmentGrant,
    TrustedControllerDevice,
    AbuseReport,
    AbuseCase,
    AbuseEnforcementAction,
    AbuseRiskEvent,
    ApiIdempotencyKey,
    Device,
    DevicePolicy,
    DeviceAccessRule,
    DeviceLocalSecuritySetting,
    AccessPolicy,
    AccessPolicyAssignment,
    PolicyEvaluation,
    VerificationCode,
    UnattendedSecret,
    RelayNode,
    Session,
    RemoteRebootRequest,
    ConnectionCandidate,
    ConnectionCandidatePair,
    SessionEvent,
    AuditLog,
    RelaySessionStat,
    FileTransfer,
    Organization,
    OrganizationDevice,
    OrganizationMember,
    Role,
    RolePermission,
    OrganizationPolicy,
    DeviceGroup,
    DeviceGroupMember,
    DeviceGroupPolicy,
    ClientReleaseChannel,
    ClientReleaseArtifact,
    ClientUpdateCheck,
}

impl RecordKind {
    pub fn table_name(self) -> &'static str {
        match self {
            Self::Account => "accounts",
            Self::AccountSession => "account_sessions",
            Self::AccountMfaFactor => "account_mfa_factors",
            Self::MfaRecoveryCodeDelivery => "mfa_recovery_code_deliveries",
            Self::AccountRecoveryCode => "account_recovery_codes",
            Self::AccountRiskChallenge => "account_risk_challenges",
            Self::DeviceEnrollmentGrant => "device_enrollment_grants",
            Self::TrustedControllerDevice => "trusted_controller_devices",
            Self::AbuseReport => "abuse_reports",
            Self::AbuseCase => "abuse_cases",
            Self::AbuseEnforcementAction => "abuse_enforcement_actions",
            Self::AbuseRiskEvent => "abuse_risk_events",
            Self::ApiIdempotencyKey => "api_idempotency_keys",
            Self::Device => "devices",
            Self::DevicePolicy => "device_policies",
            Self::DeviceAccessRule => "device_access_rules",
            Self::DeviceLocalSecuritySetting => "device_local_security_settings",
            Self::AccessPolicy => "access_policies",
            Self::AccessPolicyAssignment => "access_policy_assignments",
            Self::PolicyEvaluation => "policy_evaluations",
            Self::VerificationCode => "verification_codes",
            Self::UnattendedSecret => "unattended_secrets",
            Self::RelayNode => "relay_nodes",
            Self::Session => "sessions",
            Self::RemoteRebootRequest => "remote_reboot_requests",
            Self::ConnectionCandidate => "connection_candidates",
            Self::ConnectionCandidatePair => "connection_candidate_pairs",
            Self::SessionEvent => "session_events",
            Self::AuditLog => "audit_logs",
            Self::RelaySessionStat => "relay_session_stats",
            Self::FileTransfer => "file_transfers",
            Self::Organization => "organizations",
            Self::OrganizationDevice => "organization_devices",
            Self::OrganizationMember => "organization_members",
            Self::Role => "roles",
            Self::RolePermission => "role_permissions",
            Self::OrganizationPolicy => "organization_policies",
            Self::DeviceGroup => "device_groups",
            Self::DeviceGroupMember => "device_group_members",
            Self::DeviceGroupPolicy => "device_group_policies",
            Self::ClientReleaseChannel => "client_release_channels",
            Self::ClientReleaseArtifact => "client_release_artifacts",
            Self::ClientUpdateCheck => "client_update_checks",
        }
    }

    pub fn is_append_only(self) -> bool {
        matches!(
            self,
            Self::PolicyEvaluation
                | Self::AbuseRiskEvent
                | Self::SessionEvent
                | Self::AuditLog
                | Self::RelaySessionStat
                | Self::ClientUpdateCheck
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RecordKey {
    kind: RecordKind,
    id: String,
}

impl RecordKey {
    pub fn new(kind: RecordKind, id: impl Into<String>) -> Self {
        Self {
            kind,
            id: id.into(),
        }
    }

    pub fn kind(&self) -> RecordKind {
        self.kind
    }

    pub fn id(&self) -> &str {
        &self.id
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "record_type", content = "record", rename_all = "snake_case")]
pub enum StoredRecord {
    Account(AccountRecord),
    AccountSession(AccountSessionRecord),
    AccountMfaFactor(AccountMfaFactorRecord),
    MfaRecoveryCodeDelivery(MfaRecoveryCodeDeliveryRecord),
    AccountRecoveryCode(AccountRecoveryCodeRecord),
    AccountRiskChallenge(AccountRiskChallengeRecord),
    DeviceEnrollmentGrant(DeviceEnrollmentGrantRecord),
    TrustedControllerDevice(TrustedControllerDeviceRecord),
    AbuseReport(AbuseReportRecord),
    AbuseCase(AbuseCaseRecord),
    AbuseEnforcementAction(AbuseEnforcementActionRecord),
    AbuseRiskEvent(AbuseRiskEventRecord),
    ApiIdempotencyKey(ApiIdempotencyKeyRecord),
    Device(DeviceRecord),
    DevicePolicy(DevicePolicyRecord),
    DeviceAccessRule(DeviceAccessRuleRecord),
    DeviceLocalSecuritySetting(DeviceLocalSecuritySettingRecord),
    AccessPolicy(AccessPolicyRecord),
    AccessPolicyAssignment(AccessPolicyAssignmentRecord),
    PolicyEvaluation(PolicyEvaluationRecord),
    VerificationCode(VerificationCodeRecord),
    UnattendedSecret(UnattendedSecretRecord),
    RelayNode(RelayNodeRecord),
    Session(SessionRecord),
    RemoteRebootRequest(Box<RemoteRebootRequestRecord>),
    ConnectionCandidate(ConnectionCandidateRecord),
    ConnectionCandidatePair(ConnectionCandidatePairRecord),
    SessionEvent(SessionEventRecord),
    AuditLog(AuditLogRecord),
    RelaySessionStat(RelaySessionStatRecord),
    FileTransfer(FileTransferRecord),
    Organization(OrganizationRecord),
    OrganizationDevice(OrganizationDeviceRecord),
    OrganizationMember(OrganizationMemberRecord),
    Role(RoleRecord),
    RolePermission(RolePermissionRecord),
    OrganizationPolicy(OrganizationPolicyRecord),
    DeviceGroup(DeviceGroupRecord),
    DeviceGroupMember(DeviceGroupMemberRecord),
    DeviceGroupPolicy(DeviceGroupPolicyRecord),
    ClientReleaseChannel(ClientReleaseChannelRecord),
    ClientReleaseArtifact(ClientReleaseArtifactRecord),
    ClientUpdateCheck(ClientUpdateCheckRecord),
}

impl StoredRecord {
    pub fn kind(&self) -> RecordKind {
        match self {
            Self::Account(_) => RecordKind::Account,
            Self::AccountSession(_) => RecordKind::AccountSession,
            Self::AccountMfaFactor(_) => RecordKind::AccountMfaFactor,
            Self::MfaRecoveryCodeDelivery(_) => RecordKind::MfaRecoveryCodeDelivery,
            Self::AccountRecoveryCode(_) => RecordKind::AccountRecoveryCode,
            Self::AccountRiskChallenge(_) => RecordKind::AccountRiskChallenge,
            Self::DeviceEnrollmentGrant(_) => RecordKind::DeviceEnrollmentGrant,
            Self::TrustedControllerDevice(_) => RecordKind::TrustedControllerDevice,
            Self::AbuseReport(_) => RecordKind::AbuseReport,
            Self::AbuseCase(_) => RecordKind::AbuseCase,
            Self::AbuseEnforcementAction(_) => RecordKind::AbuseEnforcementAction,
            Self::AbuseRiskEvent(_) => RecordKind::AbuseRiskEvent,
            Self::ApiIdempotencyKey(_) => RecordKind::ApiIdempotencyKey,
            Self::Device(_) => RecordKind::Device,
            Self::DevicePolicy(_) => RecordKind::DevicePolicy,
            Self::DeviceAccessRule(_) => RecordKind::DeviceAccessRule,
            Self::DeviceLocalSecuritySetting(_) => RecordKind::DeviceLocalSecuritySetting,
            Self::AccessPolicy(_) => RecordKind::AccessPolicy,
            Self::AccessPolicyAssignment(_) => RecordKind::AccessPolicyAssignment,
            Self::PolicyEvaluation(_) => RecordKind::PolicyEvaluation,
            Self::VerificationCode(_) => RecordKind::VerificationCode,
            Self::UnattendedSecret(_) => RecordKind::UnattendedSecret,
            Self::RelayNode(_) => RecordKind::RelayNode,
            Self::Session(_) => RecordKind::Session,
            Self::RemoteRebootRequest(_) => RecordKind::RemoteRebootRequest,
            Self::ConnectionCandidate(_) => RecordKind::ConnectionCandidate,
            Self::ConnectionCandidatePair(_) => RecordKind::ConnectionCandidatePair,
            Self::SessionEvent(_) => RecordKind::SessionEvent,
            Self::AuditLog(_) => RecordKind::AuditLog,
            Self::RelaySessionStat(_) => RecordKind::RelaySessionStat,
            Self::FileTransfer(_) => RecordKind::FileTransfer,
            Self::Organization(_) => RecordKind::Organization,
            Self::OrganizationDevice(_) => RecordKind::OrganizationDevice,
            Self::OrganizationMember(_) => RecordKind::OrganizationMember,
            Self::Role(_) => RecordKind::Role,
            Self::RolePermission(_) => RecordKind::RolePermission,
            Self::OrganizationPolicy(_) => RecordKind::OrganizationPolicy,
            Self::DeviceGroup(_) => RecordKind::DeviceGroup,
            Self::DeviceGroupMember(_) => RecordKind::DeviceGroupMember,
            Self::DeviceGroupPolicy(_) => RecordKind::DeviceGroupPolicy,
            Self::ClientReleaseChannel(_) => RecordKind::ClientReleaseChannel,
            Self::ClientReleaseArtifact(_) => RecordKind::ClientReleaseArtifact,
            Self::ClientUpdateCheck(_) => RecordKind::ClientUpdateCheck,
        }
    }

    pub fn key(&self) -> RecordKey {
        let (kind, id) = match self {
            Self::Account(record) => (RecordKind::Account, record.account_id.clone()),
            Self::AccountSession(record) => (
                RecordKind::AccountSession,
                record.account_session_id.clone(),
            ),
            Self::AccountMfaFactor(record) => {
                (RecordKind::AccountMfaFactor, record.factor_id.clone())
            }
            Self::MfaRecoveryCodeDelivery(record) => (
                RecordKind::MfaRecoveryCodeDelivery,
                record.delivery_id.clone(),
            ),
            Self::AccountRecoveryCode(record) => (
                RecordKind::AccountRecoveryCode,
                record.recovery_code_id.clone(),
            ),
            Self::AccountRiskChallenge(record) => (
                RecordKind::AccountRiskChallenge,
                record.risk_challenge_id.clone(),
            ),
            Self::DeviceEnrollmentGrant(record) => {
                (RecordKind::DeviceEnrollmentGrant, record.grant_id.clone())
            }
            Self::TrustedControllerDevice(record) => (
                RecordKind::TrustedControllerDevice,
                record.trusted_device_id.clone(),
            ),
            Self::AbuseReport(record) => (RecordKind::AbuseReport, record.abuse_report_id.clone()),
            Self::AbuseCase(record) => (RecordKind::AbuseCase, record.abuse_case_id.clone()),
            Self::AbuseEnforcementAction(record) => (
                RecordKind::AbuseEnforcementAction,
                record.enforcement_action_id.clone(),
            ),
            Self::AbuseRiskEvent(record) => {
                (RecordKind::AbuseRiskEvent, record.risk_event_id.clone())
            }
            Self::ApiIdempotencyKey(record) => {
                (RecordKind::ApiIdempotencyKey, record.storage_key())
            }
            Self::Device(record) => (RecordKind::Device, record.device_id.clone()),
            Self::DevicePolicy(record) => (RecordKind::DevicePolicy, record.device_id.clone()),
            Self::DeviceAccessRule(record) => (
                RecordKind::DeviceAccessRule,
                record.device_access_rule_id.clone(),
            ),
            Self::DeviceLocalSecuritySetting(record) => (
                RecordKind::DeviceLocalSecuritySetting,
                record.device_id.clone(),
            ),
            Self::AccessPolicy(record) => {
                (RecordKind::AccessPolicy, record.access_policy_id.clone())
            }
            Self::AccessPolicyAssignment(record) => (
                RecordKind::AccessPolicyAssignment,
                record.assignment_id.clone(),
            ),
            Self::PolicyEvaluation(record) => (
                RecordKind::PolicyEvaluation,
                record.policy_evaluation_id.clone(),
            ),
            Self::VerificationCode(record) => {
                (RecordKind::VerificationCode, record.code_id.clone())
            }
            Self::UnattendedSecret(record) => (
                RecordKind::UnattendedSecret,
                record.unattended_secret_id.clone(),
            ),
            Self::RelayNode(record) => (RecordKind::RelayNode, record.relay_node_id.clone()),
            Self::Session(record) => (RecordKind::Session, record.session_id.clone()),
            Self::RemoteRebootRequest(record) => (
                RecordKind::RemoteRebootRequest,
                record.reboot_request_id.clone(),
            ),
            Self::ConnectionCandidate(record) => {
                (RecordKind::ConnectionCandidate, record.candidate_id.clone())
            }
            Self::ConnectionCandidatePair(record) => (
                RecordKind::ConnectionCandidatePair,
                record.candidate_pair_id.clone(),
            ),
            Self::SessionEvent(record) => (RecordKind::SessionEvent, record.event_id.clone()),
            Self::AuditLog(record) => (RecordKind::AuditLog, record.audit_id.clone()),
            Self::RelaySessionStat(record) => (
                RecordKind::RelaySessionStat,
                record.relay_session_stat_id.clone(),
            ),
            Self::FileTransfer(record) => {
                (RecordKind::FileTransfer, record.file_transfer_id.clone())
            }
            Self::Organization(record) => {
                (RecordKind::Organization, record.organization_id.clone())
            }
            Self::OrganizationDevice(record) => (
                RecordKind::OrganizationDevice,
                record.organization_device_id.clone(),
            ),
            Self::OrganizationMember(record) => (
                RecordKind::OrganizationMember,
                record.organization_member_id.clone(),
            ),
            Self::Role(record) => (RecordKind::Role, record.role_id.clone()),
            Self::RolePermission(record) => (RecordKind::RolePermission, record.role_id.clone()),
            Self::OrganizationPolicy(record) => (
                RecordKind::OrganizationPolicy,
                record.organization_policy_id.clone(),
            ),
            Self::DeviceGroup(record) => (RecordKind::DeviceGroup, record.device_group_id.clone()),
            Self::DeviceGroupMember(record) => (
                RecordKind::DeviceGroupMember,
                record.device_group_member_id.clone(),
            ),
            Self::DeviceGroupPolicy(record) => (
                RecordKind::DeviceGroupPolicy,
                record.device_group_policy_id.clone(),
            ),
            Self::ClientReleaseChannel(record) => (
                RecordKind::ClientReleaseChannel,
                record.release_channel_id.clone(),
            ),
            Self::ClientReleaseArtifact(record) => (
                RecordKind::ClientReleaseArtifact,
                record.artifact_id.clone(),
            ),
            Self::ClientUpdateCheck(record) => (
                RecordKind::ClientUpdateCheck,
                record.update_check_id.clone(),
            ),
        };

        RecordKey::new(kind, id)
    }
}
