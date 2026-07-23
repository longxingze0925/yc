use std::collections::{BTreeMap, HashSet};
use std::future::Future;
use std::pin::Pin;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

pub use crate::model::Database;
use crate::model::{
    Account, AccountSession, AccountStatus, Architecture, AuditEntry, Device, DeviceCapabilities,
    DeviceEnrollmentGrant, DeviceLifecycleStatus, DevicePublicKeyRecord, IdempotencyRecord,
    LoginChallengeContext, LoginDeviceState, MfaFactor, Platform, PolicyEvaluation, RecoveryCode,
    RecoveryCodeDelivery, RiskChallenge, RiskChallengeStatus, Session, SessionEvent, SessionStatus,
    TrustedControllerDevice, TrustedDeviceStatus,
};
use crate::security::{
    canonical_fields, constant_time_sha256_eq, device_registration_binding_hash, hex_encode,
    sha256, sha256_hex, verify_device_signature, verify_password, verify_totp,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreError {
    Conflict,
    Unavailable,
}

pub type RepositoryFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;
pub type SessionDeviceAuthority = (Option<Session>, Option<Device>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepUpExpectation {
    pub challenge_id: String,
    pub account_id: String,
    pub device_id: String,
    pub purpose: String,
    pub operation_binding_hash: [u8; 32],
    pub now_epoch_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceKeyRotation {
    pub step_up: StepUpExpectation,
    pub current_public_key_id: String,
    pub current_public_key_version: u32,
    pub new_public_key_id: String,
    pub new_public_key: [u8; 32],
    pub new_public_key_version: u32,
    pub audit_entry: AuditEntry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAuthorityChange {
    pub device: Box<Device>,
    pub closed_session_events: Vec<SessionEvent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceManagementAction {
    Disable,
    Restore,
    Unbind,
    RevokePublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceManagementCommand {
    pub account_id: String,
    pub actor_device_id: String,
    pub actor_public_key_id: String,
    pub actor_public_key_version: u32,
    pub target_device_id: String,
    pub expected_target_public_key_id: String,
    pub expected_target_public_key_version: u32,
    pub display_name: Option<String>,
    pub action: Option<DeviceManagementAction>,
    pub audit_entry: AuditEntry,
    pub now_epoch_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceManagementOutcome {
    Updated(DeviceAuthorityChange),
    NotFound,
    InvalidTransition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpEnrollmentCompletion {
    pub factor: MfaFactor,
    pub recovery_codes: Vec<RecoveryCode>,
    pub delivery: RecoveryCodeDelivery,
    pub audit_entry: AuditEntry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpEnrollmentReplayLookup {
    pub account_id: String,
    pub account_session_id: String,
    pub factor_id: String,
    pub idempotency_key_hash: [u8; 32],
    pub finish_request_binding_hash: Option<[u8; 32]>,
    pub client_ephemeral_public_key: Option<[u8; 32]>,
    pub access_token_expires_at_epoch_millis: u64,
    pub now_epoch_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TotpEnrollmentReplayOutcome {
    Replayed(Box<RecoveryCodeDelivery>),
    NotFound,
    BindingMismatch,
    NotAuthorized,
}

#[derive(Clone, PartialEq, Eq)]
pub struct LoginFinishCommand {
    pub challenge_id: String,
    pub account_id: String,
    pub account_updated_at_epoch_millis: u64,
    pub persistent_device_id: Option<String>,
    pub device_id: String,
    pub public_key_id: Option<String>,
    pub public_key_version: u32,
    pub device_public_key_fingerprint: [u8; 32],
    pub challenge_binding_hash: [u8; 32],
    pub required_factors: Vec<String>,
    pub factor_kind: Option<String>,
    pub factor_code: Option<String>,
    pub trusted_device_id_to_use: Option<String>,
    pub account_session: AccountSession,
    pub enrollment_grant: Option<DeviceEnrollmentGrant>,
    pub trusted_device_to_create: Option<TrustedControllerDevice>,
    pub audit_entries: Vec<AuditEntry>,
    pub failure_audit_entry: AuditEntry,
    pub now_epoch_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginChallengeAuthority {
    pub challenge: RiskChallenge,
    pub context: LoginChallengeContext,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginFinishOutcome {
    Completed,
    Rejected,
    InvalidChallenge,
    InvalidFactor,
    InvalidTrust,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskChallengeVerification {
    pub challenge_id: String,
    pub account_id: String,
    pub factor_kind: String,
    pub factor_code: String,
    pub success_audit_entry: AuditEntry,
    pub failure_audit_entry: AuditEntry,
    pub recovery_code_audit_entry: Option<AuditEntry>,
    pub now_epoch_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskChallengeVerificationOutcome {
    Verified(RiskChallenge),
    AlreadyVerified(RiskChallenge),
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RiskChallengeCreationOutcome {
    Created(Box<RiskChallenge>),
    MfaEnrollmentRequired,
    NotAuthorized,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRegistrationCommand {
    pub grant_id: String,
    pub grant_secret_hash: [u8; 32],
    pub account_id: String,
    pub account_session_id: String,
    pub protocol_version: u16,
    pub registration_request_binding_hash: [u8; 32],
    pub device: Device,
    pub trusted_device_id: Option<String>,
    pub registration_audit_entry: AuditEntry,
    pub grant_audit_entry: AuditEntry,
    pub trusted_device_audit_entry: Option<AuditEntry>,
    pub signature_proof: InitialDeviceSignatureProof,
    pub now_epoch_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitialDeviceSignatureProof {
    pub target: String,
    pub content_type: Option<String>,
    pub request_id: String,
    pub timestamp_epoch_millis: u64,
    pub nonce: String,
    pub signature: String,
    pub canonical_body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceRegistrationOutcome {
    Created(Device),
    Replayed(Device),
    InvalidGrant,
}

pub(crate) const DEVICE_REGISTRATION_RESULT_METADATA_KEY: &str = "device_registration_result_v1";

#[derive(Debug, Serialize, Deserialize)]
struct DeviceRegistrationResultSnapshot {
    grant_id: String,
    registration_request_binding_hash: String,
    device_id: String,
    account_id: String,
    display_name: String,
    platform: Platform,
    os_version: String,
    arch: Architecture,
    capabilities: DeviceCapabilities,
    public_key_id: String,
    public_key_fingerprint: String,
    public_key_version: u32,
    public_key_revoked_at_epoch_millis: Option<u64>,
    status: String,
    last_seen_epoch_millis: Option<u64>,
    created_at_epoch_millis: u64,
    updated_at_epoch_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MfaFactorSummary {
    pub factor_id: String,
    pub created_at_epoch_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MfaStatusSnapshot {
    pub factors: Vec<MfaFactorSummary>,
    pub recovery_codes_remaining: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateSessionCommand {
    pub storage_key: String,
    pub idempotency: IdempotencyRecord,
    pub session: Session,
    pub event: SessionEvent,
    pub policy_evaluation: PolicyEvaluation,
    pub audit_entry: AuditEntry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CreateSessionOutcome {
    Created(Session),
    Replayed(Session),
    BindingMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionSessionCommand {
    pub storage_key: String,
    pub expected_status: SessionStatus,
    pub apply_allowed: bool,
    pub idempotency: IdempotencyRecord,
    pub session: Session,
    pub event: SessionEvent,
    pub audit_entry: AuditEntry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionSessionOutcome {
    Applied { session: Session, event_id: String },
    Replayed { session: Session, event_id: String },
    BindingMismatch,
    InvalidTransition,
    StateConflict,
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepUpAction {
    RotateRecoveryCodes {
        records: Vec<RecoveryCode>,
        audit_entry: AuditEntry,
    },
    DisableMfaFactor {
        factor_id: String,
        audit_entry: AuditEntry,
    },
    ChangePassword {
        expected_password_hash: String,
        new_password_hash: String,
        audit_entry: AuditEntry,
    },
    RevokeTrustedDevice {
        trusted_device_id: String,
        audit_entry: AuditEntry,
    },
}

impl StepUpAction {
    pub fn audit_entry(&self) -> &AuditEntry {
        match self {
            Self::RotateRecoveryCodes { audit_entry, .. }
            | Self::DisableMfaFactor { audit_entry, .. }
            | Self::ChangePassword { audit_entry, .. }
            | Self::RevokeTrustedDevice { audit_entry, .. } => audit_entry,
        }
    }
}

pub trait Repository: Send + Sync {
    fn backend_name(&self) -> &'static str;

    fn read<'a>(
        &'a self,
        operation: &'a mut (dyn FnMut(&Database) + Send),
    ) -> RepositoryFuture<'a, ()>;

    fn transact<'a>(
        &'a self,
        operation: &'a mut (dyn FnMut(&mut Database) -> Result<(), StoreError> + Send),
    ) -> RepositoryFuture<'a, Result<(), StoreError>>;

    fn account_session_active<'a>(
        &'a self,
        account_session_id: &'a str,
        account_id: &'a str,
        now_epoch_millis: u64,
    ) -> RepositoryFuture<'a, Result<bool, StoreError>>;

    fn load_account_by_email<'a>(
        &'a self,
        email: &'a str,
    ) -> RepositoryFuture<'a, Result<Option<Account>, StoreError>>;

    fn load_account_by_id<'a>(
        &'a self,
        account_id: &'a str,
    ) -> RepositoryFuture<'a, Result<Option<Account>, StoreError>>;

    fn account_mfa_enabled<'a>(
        &'a self,
        account_id: &'a str,
    ) -> RepositoryFuture<'a, Result<bool, StoreError>>;

    fn load_mfa_status<'a>(
        &'a self,
        account_id: &'a str,
        now_epoch_millis: u64,
    ) -> RepositoryFuture<'a, Result<MfaStatusSnapshot, StoreError>>;

    fn load_risk_challenge_authority<'a>(
        &'a self,
        challenge_id: &'a str,
    ) -> RepositoryFuture<'a, Result<Option<RiskChallenge>, StoreError>>;

    fn load_login_challenge_authority<'a>(
        &'a self,
        challenge_id: &'a str,
    ) -> RepositoryFuture<'a, Result<Option<LoginChallengeAuthority>, StoreError>>;

    fn create_risk_challenge<'a>(
        &'a self,
        challenge: &'a RiskChallenge,
        audit_entry: &'a AuditEntry,
    ) -> RepositoryFuture<'a, Result<RiskChallengeCreationOutcome, StoreError>>;

    fn create_login_challenge<'a>(
        &'a self,
        authority: &'a LoginChallengeAuthority,
        audit_entry: &'a AuditEntry,
    ) -> RepositoryFuture<'a, Result<(), StoreError>>;

    fn cancel_risk_challenge<'a>(
        &'a self,
        challenge_id: &'a str,
        audit_entry: &'a AuditEntry,
    ) -> RepositoryFuture<'a, Result<bool, StoreError>>;

    fn load_refresh_session_authority<'a>(
        &'a self,
        refresh_token_hash: &'a [u8; 32],
        now_epoch_millis: u64,
    ) -> RepositoryFuture<'a, Result<Option<AccountSession>, StoreError>>;

    fn rotate_refresh_session<'a>(
        &'a self,
        refresh_token_hash: &'a [u8; 32],
        replacement: &'a AccountSession,
        audit_entry: &'a AuditEntry,
        now_epoch_millis: u64,
    ) -> RepositoryFuture<'a, Result<bool, StoreError>>;

    fn revoke_account_session<'a>(
        &'a self,
        account_session_id: &'a str,
        account_id: &'a str,
        now_epoch_millis: u64,
        audit_entry: &'a AuditEntry,
    ) -> RepositoryFuture<'a, Result<bool, StoreError>>;

    fn load_device_authority<'a>(
        &'a self,
        device_id: &'a str,
    ) -> RepositoryFuture<'a, Result<Option<Device>, StoreError>>;

    fn load_session_authority<'a>(
        &'a self,
        session_id: &'a str,
    ) -> RepositoryFuture<'a, Result<Option<Session>, StoreError>>;

    fn list_devices_for_account<'a>(
        &'a self,
        account_id: &'a str,
    ) -> RepositoryFuture<'a, Result<Vec<Device>, StoreError>>;

    fn list_trusted_devices_for_account<'a>(
        &'a self,
        account_id: &'a str,
    ) -> RepositoryFuture<'a, Result<Vec<TrustedControllerDevice>, StoreError>>;

    fn load_signal_device_authority<'a>(
        &'a self,
        account_session_id: &'a str,
        account_id: &'a str,
        device_id: &'a str,
        now_epoch_millis: u64,
    ) -> RepositoryFuture<'a, Result<Option<(bool, Device)>, StoreError>>;

    fn load_session_device_authority<'a>(
        &'a self,
        session_id: &'a str,
        device_id: &'a str,
    ) -> RepositoryFuture<'a, Result<SessionDeviceAuthority, StoreError>>;

    fn verify_factor<'a>(
        &'a self,
        challenge_id: Option<&'a str>,
        account_id: &'a str,
        factor_kind: &'a str,
        code: &'a str,
        now_epoch_millis: u64,
    ) -> RepositoryFuture<'a, Result<bool, StoreError>>;

    fn verify_risk_challenge<'a>(
        &'a self,
        verification: &'a RiskChallengeVerification,
    ) -> RepositoryFuture<'a, Result<RiskChallengeVerificationOutcome, StoreError>>;

    fn consume_step_up<'a>(
        &'a self,
        expectation: &'a StepUpExpectation,
    ) -> RepositoryFuture<'a, Result<(), StoreError>>;

    fn apply_step_up_action<'a>(
        &'a self,
        expectation: &'a StepUpExpectation,
        action: &'a StepUpAction,
    ) -> RepositoryFuture<'a, Result<(), StoreError>>;

    fn finish_totp_enrollment<'a>(
        &'a self,
        completion: &'a TotpEnrollmentCompletion,
    ) -> RepositoryFuture<'a, Result<(), StoreError>>;

    fn replay_totp_enrollment<'a>(
        &'a self,
        _lookup: &'a TotpEnrollmentReplayLookup,
    ) -> RepositoryFuture<'a, Result<TotpEnrollmentReplayOutcome, StoreError>> {
        Box::pin(async { Err(StoreError::Unavailable) })
    }

    fn finish_login<'a>(
        &'a self,
        command: &'a LoginFinishCommand,
    ) -> RepositoryFuture<'a, Result<LoginFinishOutcome, StoreError>>;

    fn reject_login_challenge<'a>(
        &'a self,
        challenge_id: &'a str,
        challenge_binding_hash: &'a [u8; 32],
        now_epoch_millis: u64,
        audit_entry: &'a AuditEntry,
    ) -> RepositoryFuture<'a, Result<bool, StoreError>>;

    fn create_session<'a>(
        &'a self,
        command: &'a CreateSessionCommand,
    ) -> RepositoryFuture<'a, Result<CreateSessionOutcome, StoreError>>;

    fn transition_session<'a>(
        &'a self,
        command: &'a TransitionSessionCommand,
    ) -> RepositoryFuture<'a, Result<TransitionSessionOutcome, StoreError>>;

    fn register_device<'a>(
        &'a self,
        command: &'a DeviceRegistrationCommand,
    ) -> RepositoryFuture<'a, Result<DeviceRegistrationOutcome, StoreError>>;

    fn rotate_device_key<'a>(
        &'a self,
        rotation: &'a DeviceKeyRotation,
    ) -> RepositoryFuture<'a, Result<DeviceAuthorityChange, StoreError>>;

    fn manage_device<'a>(
        &'a self,
        command: &'a DeviceManagementCommand,
    ) -> RepositoryFuture<'a, Result<DeviceManagementOutcome, StoreError>>;
}

#[derive(Debug, Default)]
pub struct MemoryRepository {
    database: RwLock<Database>,
}

impl Repository for MemoryRepository {
    fn backend_name(&self) -> &'static str {
        "memory"
    }

    fn read<'a>(
        &'a self,
        operation: &'a mut (dyn FnMut(&Database) + Send),
    ) -> RepositoryFuture<'a, ()> {
        Box::pin(async move {
            let database = self.database.read().await;
            operation(&database);
        })
    }

    fn verify_risk_challenge<'a>(
        &'a self,
        verification: &'a RiskChallengeVerification,
    ) -> RepositoryFuture<'a, Result<RiskChallengeVerificationOutcome, StoreError>> {
        Box::pin(async move {
            let mut database = self.database.write().await;
            let mut candidate = database.clone();
            let Some(account) = candidate.accounts.get(&verification.account_id) else {
                return Ok(RiskChallengeVerificationOutcome::Rejected);
            };
            if account.status != crate::model::AccountStatus::Active {
                return Ok(RiskChallengeVerificationOutcome::Rejected);
            }
            let password_hash = account.password_hash.clone();
            let Some(authority) = candidate
                .risk_challenges
                .get(&verification.challenge_id)
                .cloned()
            else {
                return Ok(RiskChallengeVerificationOutcome::Rejected);
            };
            if authority.account_id != verification.account_id || authority.purpose == "login_mfa" {
                return Ok(RiskChallengeVerificationOutcome::Rejected);
            }
            let device_authorized = authority.device_id.as_ref().is_some_and(|device_id| {
                candidate.devices.get(device_id).is_some_and(|device| {
                    device.account_id == verification.account_id && device.status.is_authorizable()
                })
            });
            if !device_authorized {
                return Ok(RiskChallengeVerificationOutcome::Rejected);
            }
            if authority.status == RiskChallengeStatus::Verified
                && authority.verified_at_epoch_millis.is_some()
                && authority.consumed_at_epoch_millis.is_none()
                && authority.expires_at_epoch_millis > verification.now_epoch_millis
            {
                return Ok(RiskChallengeVerificationOutcome::AlreadyVerified(authority));
            }
            if authority.status != RiskChallengeStatus::Issued
                || authority.attempts_remaining == 0
                || authority.consumed_at_epoch_millis.is_some()
            {
                return Ok(RiskChallengeVerificationOutcome::Rejected);
            }
            if candidate.audit_logs.iter().any(|entry| {
                entry.audit_id == verification.success_audit_entry.audit_id
                    || entry.audit_id == verification.failure_audit_entry.audit_id
                    || verification
                        .recovery_code_audit_entry
                        .as_ref()
                        .is_some_and(|audit| entry.audit_id == audit.audit_id)
            }) {
                return Err(StoreError::Conflict);
            }
            if authority.expires_at_epoch_millis <= verification.now_epoch_millis {
                let challenge = candidate
                    .risk_challenges
                    .get_mut(&verification.challenge_id)
                    .ok_or(StoreError::Unavailable)?;
                challenge.status = RiskChallengeStatus::Expired;
                let mut audit = verification.failure_audit_entry.clone();
                audit.reason = Some("expired".to_owned());
                candidate.audit_logs.push(audit);
                *database = candidate;
                return Ok(RiskChallengeVerificationOutcome::Rejected);
            }
            let method_allowed = authority
                .required_methods
                .iter()
                .any(|method| method == &verification.factor_kind);
            let accepted = if !method_allowed {
                false
            } else if verification.factor_kind == "password" {
                authority.purpose == "password_change"
                    && verify_password(&password_hash, &verification.factor_code)
            } else {
                verify_factor_in_database(
                    &mut candidate,
                    Some(&verification.challenge_id),
                    &verification.account_id,
                    &verification.factor_kind,
                    &verification.factor_code,
                    verification.now_epoch_millis,
                )?
            };
            if !method_allowed || verification.factor_kind == "password" {
                let challenge = candidate
                    .risk_challenges
                    .get_mut(&verification.challenge_id)
                    .ok_or(StoreError::Unavailable)?;
                if accepted {
                    challenge.status = RiskChallengeStatus::Verified;
                    challenge.verified_at_epoch_millis = Some(verification.now_epoch_millis);
                } else {
                    challenge.attempts_remaining = challenge.attempts_remaining.saturating_sub(1);
                    if challenge.attempts_remaining == 0 {
                        challenge.status = RiskChallengeStatus::Failed;
                    }
                }
            }
            let challenge = candidate
                .risk_challenges
                .get(&verification.challenge_id)
                .cloned()
                .ok_or(StoreError::Unavailable)?;
            if accepted {
                candidate
                    .audit_logs
                    .push(verification.success_audit_entry.clone());
                if verification.factor_kind == "recovery_code" {
                    let recovery_audit = verification
                        .recovery_code_audit_entry
                        .clone()
                        .ok_or(StoreError::Conflict)?;
                    candidate.audit_logs.push(recovery_audit);
                }
                *database = candidate;
                Ok(RiskChallengeVerificationOutcome::Verified(challenge))
            } else {
                candidate
                    .audit_logs
                    .push(verification.failure_audit_entry.clone());
                *database = candidate;
                Ok(RiskChallengeVerificationOutcome::Rejected)
            }
        })
    }

    fn load_account_by_id<'a>(
        &'a self,
        account_id: &'a str,
    ) -> RepositoryFuture<'a, Result<Option<Account>, StoreError>> {
        Box::pin(async move {
            let database = self.database.read().await;
            Ok(database.accounts.get(account_id).cloned())
        })
    }

    fn transact<'a>(
        &'a self,
        operation: &'a mut (dyn FnMut(&mut Database) -> Result<(), StoreError> + Send),
    ) -> RepositoryFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let mut database = self.database.write().await;
            let mut candidate = database.clone();
            operation(&mut candidate)?;
            *database = candidate;
            Ok(())
        })
    }

    fn finish_login<'a>(
        &'a self,
        command: &'a LoginFinishCommand,
    ) -> RepositoryFuture<'a, Result<LoginFinishOutcome, StoreError>> {
        Box::pin(async move {
            validate_login_finish_command_shape(command)?;
            let mut database = self.database.write().await;
            let mut candidate = database.clone();
            let Some(challenge) = candidate
                .risk_challenges
                .get(&command.challenge_id)
                .cloned()
            else {
                return Ok(LoginFinishOutcome::InvalidChallenge);
            };
            let Some(context) = candidate
                .login_challenge_contexts
                .get(&command.challenge_id)
                .cloned()
            else {
                return Ok(LoginFinishOutcome::InvalidChallenge);
            };
            if challenge.account_id != command.account_id
                || challenge.device_id != command.persistent_device_id
                || challenge.purpose != "login_mfa"
                || !constant_time_sha256_eq(
                    &challenge.operation_binding_hash,
                    &command.challenge_binding_hash,
                )
                || challenge.required_methods != command.required_factors
            {
                return Ok(LoginFinishOutcome::InvalidChallenge);
            }
            if validate_login_finish_authority_binding(command, &challenge, &context).is_err() {
                return Ok(LoginFinishOutcome::InvalidChallenge);
            }
            if candidate
                .audit_logs
                .iter()
                .any(|entry| entry.audit_id == command.failure_audit_entry.audit_id)
            {
                return Err(StoreError::Conflict);
            }
            if challenge.status == RiskChallengeStatus::Issued
                && challenge.expires_at_epoch_millis <= command.now_epoch_millis
            {
                let current = candidate
                    .risk_challenges
                    .get_mut(&command.challenge_id)
                    .ok_or(StoreError::Unavailable)?;
                current.status = RiskChallengeStatus::Expired;
                let mut audit = command.failure_audit_entry.clone();
                audit.reason = Some("expired".to_owned());
                candidate.audit_logs.push(audit);
                *database = candidate;
                return Ok(LoginFinishOutcome::InvalidChallenge);
            }
            if challenge.status != RiskChallengeStatus::Issued || challenge.attempts_remaining == 0
            {
                return Ok(LoginFinishOutcome::InvalidChallenge);
            }
            validate_login_finish_artifacts(command, &challenge)?;
            if command.audit_entries.iter().any(|audit| {
                candidate
                    .audit_logs
                    .iter()
                    .any(|existing| existing.audit_id == audit.audit_id)
            }) {
                return Err(StoreError::Conflict);
            }

            let account_security_changed =
                candidate
                    .accounts
                    .get(&command.account_id)
                    .is_none_or(|account| {
                        account.status != crate::model::AccountStatus::Active
                            || account.updated_at_epoch_millis
                                != command.account_updated_at_epoch_millis
                    });
            if account_security_changed {
                let current = candidate
                    .risk_challenges
                    .get_mut(&command.challenge_id)
                    .ok_or(StoreError::Unavailable)?;
                current.attempts_remaining = current.attempts_remaining.saturating_sub(1);
                if current.attempts_remaining == 0 {
                    current.status = RiskChallengeStatus::Failed;
                }
                let mut audit = command.failure_audit_entry.clone();
                audit.reason = Some("account_security_changed".to_owned());
                candidate.audit_logs.push(audit);
                *database = candidate;
                return Ok(LoginFinishOutcome::Rejected);
            }
            let registered_device_valid = command.persistent_device_id.as_ref().is_some_and(|_| {
                candidate
                    .devices
                    .get(&command.device_id)
                    .is_some_and(|device| {
                        device.account_id == command.account_id
                            && device.status.is_authorizable()
                            && device.public_key_revoked_at_epoch_millis.is_none()
                            && command.public_key_id.as_deref()
                                == Some(device.public_key_id.as_str())
                            && command.public_key_version == device.public_key_version
                            && constant_time_sha256_eq(
                                &sha256(&device.public_key),
                                &command.device_public_key_fingerprint,
                            )
                    })
            });
            let pending_device_valid = command.persistent_device_id.is_none()
                && command.public_key_id.is_none()
                && command.public_key_version == 0
                && !candidate.devices.contains_key(&command.device_id);
            if !registered_device_valid && !pending_device_valid {
                let current = candidate
                    .risk_challenges
                    .get_mut(&command.challenge_id)
                    .ok_or(StoreError::Unavailable)?;
                current.attempts_remaining = current.attempts_remaining.saturating_sub(1);
                if current.attempts_remaining == 0 {
                    current.status = RiskChallengeStatus::Failed;
                }
                let mut audit = command.failure_audit_entry.clone();
                audit.reason = Some("device_authority_changed".to_owned());
                candidate.audit_logs.push(audit);
                *database = candidate;
                return Ok(LoginFinishOutcome::Rejected);
            }

            let mfa_enabled = candidate
                .mfa_factors
                .values()
                .any(|factor| factor.account_id == command.account_id && factor.active);
            if command.required_factors.is_empty() {
                if command.factor_kind.is_some() || command.factor_code.is_some() {
                    return Ok(LoginFinishOutcome::InvalidFactor);
                }
                if mfa_enabled {
                    let Some(trusted_device_id) = command.trusted_device_id_to_use.as_deref()
                    else {
                        return Ok(LoginFinishOutcome::InvalidTrust);
                    };
                    let Some(trusted) = candidate
                        .trusted_controller_devices
                        .get_mut(trusted_device_id)
                    else {
                        return Ok(LoginFinishOutcome::InvalidTrust);
                    };
                    if trusted.account_id != command.account_id
                        || trusted.controller_device_id != command.device_id
                        || trusted.status != TrustedDeviceStatus::Active
                        || trusted.expires_at_epoch_millis <= command.now_epoch_millis
                        || !constant_time_sha256_eq(
                            &trusted.device_fingerprint_hash,
                            &command.device_public_key_fingerprint,
                        )
                    {
                        if trusted.status == TrustedDeviceStatus::Active
                            && trusted.expires_at_epoch_millis <= command.now_epoch_millis
                        {
                            trusted.status = TrustedDeviceStatus::Expired;
                        }
                        *database = candidate;
                        return Ok(LoginFinishOutcome::InvalidTrust);
                    }
                    trusted.last_used_at_epoch_millis = Some(command.now_epoch_millis);
                } else if command.trusted_device_id_to_use.is_some() {
                    return Ok(LoginFinishOutcome::InvalidTrust);
                }
                let challenge = candidate
                    .risk_challenges
                    .get_mut(&command.challenge_id)
                    .ok_or(StoreError::Unavailable)?;
                challenge.verified_at_epoch_millis = Some(command.now_epoch_millis);
            } else {
                if command.trusted_device_id_to_use.is_some() || !mfa_enabled {
                    return Ok(LoginFinishOutcome::InvalidFactor);
                }
                let Some(factor_kind) = command.factor_kind.as_deref() else {
                    return Ok(LoginFinishOutcome::InvalidFactor);
                };
                let Some(factor_code) = command.factor_code.as_deref() else {
                    return Ok(LoginFinishOutcome::InvalidFactor);
                };
                if !command
                    .required_factors
                    .iter()
                    .any(|allowed| allowed == factor_kind)
                {
                    return Ok(LoginFinishOutcome::InvalidFactor);
                }
                let accepted = verify_factor_in_database(
                    &mut candidate,
                    Some(&command.challenge_id),
                    &command.account_id,
                    factor_kind,
                    factor_code,
                    command.now_epoch_millis,
                )?;
                if !accepted {
                    candidate
                        .audit_logs
                        .push(command.failure_audit_entry.clone());
                    *database = candidate;
                    return Ok(LoginFinishOutcome::InvalidFactor);
                }
            }

            if candidate
                .account_sessions
                .contains_key(&command.account_session.account_session_id)
                || command.account_session.account_id != command.account_id
                || command.account_session.revoked_at_epoch_millis.is_some()
                || command.account_session.revoked_reason.is_some()
            {
                return Err(StoreError::Conflict);
            }
            if let Some(grant) = &command.enrollment_grant {
                if candidate
                    .device_enrollment_grants
                    .contains_key(&grant.grant_id)
                    || grant.account_id != command.account_id
                    || grant.device_id != command.device_id
                    || grant.issued_account_session_id != command.account_session.account_session_id
                    || !constant_time_sha256_eq(
                        &grant.device_public_key_fingerprint,
                        &command.device_public_key_fingerprint,
                    )
                    || !constant_time_sha256_eq(
                        &grant.login_challenge_binding_hash,
                        &command.challenge_binding_hash,
                    )
                {
                    return Err(StoreError::Conflict);
                }
                candidate
                    .device_enrollment_grants
                    .insert(grant.grant_id.clone(), grant.clone());
            }
            if let Some(trusted) = &command.trusted_device_to_create {
                if command.enrollment_grant.is_some()
                    || command.factor_kind.is_none()
                    || candidate
                        .trusted_controller_devices
                        .contains_key(&trusted.trusted_device_id)
                    || trusted.account_id != command.account_id
                    || trusted.controller_device_id != command.device_id
                    || !constant_time_sha256_eq(
                        &trusted.device_fingerprint_hash,
                        &command.device_public_key_fingerprint,
                    )
                {
                    return Err(StoreError::Conflict);
                }
                let trust_added_audit = command
                    .audit_entries
                    .iter()
                    .find(|audit| audit.action == "trusted_device_added")
                    .ok_or(StoreError::Conflict)?;
                let revocation_audits = candidate
                    .trusted_controller_devices
                    .values()
                    .filter(|current| {
                        current.account_id == command.account_id
                            && current.controller_device_id == command.device_id
                            && current.status == TrustedDeviceStatus::Active
                    })
                    .map(|current| {
                        trusted_device_revocation_audit(
                            trust_added_audit,
                            &current.trusted_device_id,
                            &current.controller_device_id,
                            "refreshed",
                        )
                    })
                    .collect::<Vec<_>>();
                if revocation_audits.iter().any(|audit| {
                    candidate
                        .audit_logs
                        .iter()
                        .chain(command.audit_entries.iter())
                        .any(|existing| existing.audit_id == audit.audit_id)
                }) {
                    return Err(StoreError::Conflict);
                }
                for current in candidate.trusted_controller_devices.values_mut() {
                    if current.account_id == command.account_id
                        && current.controller_device_id == command.device_id
                        && current.status == TrustedDeviceStatus::Active
                    {
                        current.status = TrustedDeviceStatus::Revoked;
                        current.revoked_at_epoch_millis = Some(command.now_epoch_millis);
                    }
                }
                candidate.audit_logs.extend(revocation_audits);
                candidate
                    .trusted_controller_devices
                    .insert(trusted.trusted_device_id.clone(), trusted.clone());
            }

            let challenge = candidate
                .risk_challenges
                .get_mut(&command.challenge_id)
                .ok_or(StoreError::Unavailable)?;
            challenge.status = RiskChallengeStatus::Consumed;
            challenge.verified_at_epoch_millis = Some(command.now_epoch_millis);
            challenge.consumed_at_epoch_millis = Some(command.now_epoch_millis);
            candidate.account_sessions.insert(
                command.account_session.account_session_id.clone(),
                command.account_session.clone(),
            );
            candidate.audit_logs.extend(command.audit_entries.clone());
            *database = candidate;
            Ok(LoginFinishOutcome::Completed)
        })
    }

    fn reject_login_challenge<'a>(
        &'a self,
        challenge_id: &'a str,
        challenge_binding_hash: &'a [u8; 32],
        now_epoch_millis: u64,
        audit_entry: &'a AuditEntry,
    ) -> RepositoryFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move {
            let mut database = self.database.write().await;
            if database
                .audit_logs
                .iter()
                .any(|entry| entry.audit_id == audit_entry.audit_id)
            {
                return Err(StoreError::Conflict);
            }
            let Some(challenge) = database.risk_challenges.get_mut(challenge_id) else {
                return Ok(false);
            };
            if challenge.purpose != "login_mfa"
                || challenge.status != RiskChallengeStatus::Issued
                || challenge.expires_at_epoch_millis <= now_epoch_millis
                || !constant_time_sha256_eq(
                    &challenge.operation_binding_hash,
                    challenge_binding_hash,
                )
            {
                return Ok(false);
            }
            challenge.attempts_remaining = challenge.attempts_remaining.saturating_sub(1);
            if challenge.attempts_remaining == 0 {
                challenge.status = RiskChallengeStatus::Failed;
            }
            database.audit_logs.push(audit_entry.clone());
            Ok(true)
        })
    }

    fn account_session_active<'a>(
        &'a self,
        account_session_id: &'a str,
        account_id: &'a str,
        now_epoch_millis: u64,
    ) -> RepositoryFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move {
            let database = self.database.read().await;
            Ok(active_account_session(
                database.account_sessions.get(account_session_id),
                account_id,
                now_epoch_millis,
            ))
        })
    }

    fn load_account_by_email<'a>(
        &'a self,
        email: &'a str,
    ) -> RepositoryFuture<'a, Result<Option<Account>, StoreError>> {
        Box::pin(async move {
            let database = self.database.read().await;
            Ok(database
                .account_by_email
                .get(email)
                .and_then(|account_id| database.accounts.get(account_id))
                .cloned())
        })
    }

    fn account_mfa_enabled<'a>(
        &'a self,
        account_id: &'a str,
    ) -> RepositoryFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move {
            let database = self.database.read().await;
            Ok(database
                .mfa_factors
                .values()
                .any(|factor| factor.account_id == account_id && factor.active))
        })
    }

    fn load_mfa_status<'a>(
        &'a self,
        account_id: &'a str,
        now_epoch_millis: u64,
    ) -> RepositoryFuture<'a, Result<MfaStatusSnapshot, StoreError>> {
        Box::pin(async move {
            let database = self.database.read().await;
            let factors = database
                .mfa_factors
                .values()
                .filter(|factor| factor.account_id == account_id && factor.active)
                .map(|factor| MfaFactorSummary {
                    factor_id: factor.factor_id.clone(),
                    created_at_epoch_millis: factor.created_at_epoch_millis,
                })
                .collect();
            let recovery_codes_remaining = database
                .recovery_codes
                .values()
                .filter(|code| {
                    code.account_id == account_id
                        && code.used_at_epoch_millis.is_none()
                        && code
                            .expires_at_epoch_millis
                            .is_none_or(|expires| expires > now_epoch_millis)
                })
                .count();
            Ok(MfaStatusSnapshot {
                factors,
                recovery_codes_remaining,
            })
        })
    }

    fn load_risk_challenge_authority<'a>(
        &'a self,
        challenge_id: &'a str,
    ) -> RepositoryFuture<'a, Result<Option<RiskChallenge>, StoreError>> {
        Box::pin(async move {
            let database = self.database.read().await;
            Ok(database.risk_challenges.get(challenge_id).cloned())
        })
    }

    fn load_login_challenge_authority<'a>(
        &'a self,
        challenge_id: &'a str,
    ) -> RepositoryFuture<'a, Result<Option<LoginChallengeAuthority>, StoreError>> {
        Box::pin(async move {
            let database = self.database.read().await;
            Ok(database
                .risk_challenges
                .get(challenge_id)
                .zip(database.login_challenge_contexts.get(challenge_id))
                .map(|(challenge, context)| LoginChallengeAuthority {
                    challenge: challenge.clone(),
                    context: context.clone(),
                }))
        })
    }

    fn create_risk_challenge<'a>(
        &'a self,
        challenge: &'a RiskChallenge,
        audit_entry: &'a AuditEntry,
    ) -> RepositoryFuture<'a, Result<RiskChallengeCreationOutcome, StoreError>> {
        Box::pin(async move {
            if matches!(
                challenge.purpose.as_str(),
                "login_mfa" | "new_controller_device"
            ) || !challenge.required_methods.is_empty()
            {
                return Err(StoreError::Conflict);
            }
            let mut database = self.database.write().await;
            let account_active = database
                .accounts
                .get(&challenge.account_id)
                .is_some_and(|account| account.status == AccountStatus::Active);
            let device_authorized = challenge.device_id.as_ref().is_some_and(|device_id| {
                database.devices.get(device_id).is_some_and(|device| {
                    device.account_id == challenge.account_id && device.status.is_authorizable()
                })
            });
            if !account_active || !device_authorized {
                return Ok(RiskChallengeCreationOutcome::NotAuthorized);
            }
            let mfa_enabled = database
                .mfa_factors
                .values()
                .any(|factor| factor.account_id == challenge.account_id && factor.active);
            let required_methods = if mfa_enabled {
                vec!["totp".to_owned(), "recovery_code".to_owned()]
            } else if challenge.purpose == "password_change" {
                vec!["password".to_owned()]
            } else {
                return Ok(RiskChallengeCreationOutcome::MfaEnrollmentRequired);
            };
            let mut challenge = challenge.clone();
            challenge.required_methods = required_methods;
            if database
                .risk_challenges
                .contains_key(&challenge.risk_challenge_id)
                || database
                    .audit_logs
                    .iter()
                    .any(|entry| entry.audit_id == audit_entry.audit_id)
                || audit_entry.actor_account_id.as_deref() != Some(challenge.account_id.as_str())
            {
                return Err(StoreError::Conflict);
            }
            database
                .risk_challenges
                .insert(challenge.risk_challenge_id.clone(), challenge.clone());
            database.audit_logs.push(audit_entry.clone());
            Ok(RiskChallengeCreationOutcome::Created(Box::new(challenge)))
        })
    }

    fn create_login_challenge<'a>(
        &'a self,
        authority: &'a LoginChallengeAuthority,
        audit_entry: &'a AuditEntry,
    ) -> RepositoryFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            validate_login_challenge_authority(authority)?;
            let mut database = self.database.write().await;
            let account_unchanged = database
                .accounts
                .get(&authority.challenge.account_id)
                .is_some_and(|account| {
                    account.status == AccountStatus::Active
                        && account.updated_at_epoch_millis
                            == authority.context.account_updated_at_epoch_millis
                });
            if database
                .risk_challenges
                .contains_key(&authority.challenge.risk_challenge_id)
                || database
                    .login_challenge_contexts
                    .contains_key(&authority.challenge.risk_challenge_id)
                || database
                    .audit_logs
                    .iter()
                    .any(|entry| entry.audit_id == audit_entry.audit_id)
                || audit_entry.actor_account_id.as_deref()
                    != Some(authority.challenge.account_id.as_str())
                || !account_unchanged
            {
                return Err(StoreError::Conflict);
            }
            database.risk_challenges.insert(
                authority.challenge.risk_challenge_id.clone(),
                authority.challenge.clone(),
            );
            database.login_challenge_contexts.insert(
                authority.challenge.risk_challenge_id.clone(),
                authority.context.clone(),
            );
            database.audit_logs.push(audit_entry.clone());
            Ok(())
        })
    }

    fn cancel_risk_challenge<'a>(
        &'a self,
        challenge_id: &'a str,
        audit_entry: &'a AuditEntry,
    ) -> RepositoryFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move {
            let mut database = self.database.write().await;
            let Some(challenge) = database.risk_challenges.get(challenge_id) else {
                return Ok(false);
            };
            if challenge.status != RiskChallengeStatus::Issued {
                return Ok(false);
            }
            if audit_entry.actor_account_id.as_deref() != Some(challenge.account_id.as_str())
                || audit_entry.action != "risk_challenge_failed"
                || audit_entry.result != "failure"
                || audit_entry.reason.as_deref() != Some("cancelled")
                || database
                    .audit_logs
                    .iter()
                    .any(|entry| entry.audit_id == audit_entry.audit_id)
            {
                return Err(StoreError::Conflict);
            }
            let challenge = database
                .risk_challenges
                .get_mut(challenge_id)
                .expect("challenge existence checked while holding write lock");
            challenge.status = RiskChallengeStatus::Cancelled;
            database.audit_logs.push(audit_entry.clone());
            Ok(true)
        })
    }

    fn load_refresh_session_authority<'a>(
        &'a self,
        refresh_token_hash: &'a [u8; 32],
        now_epoch_millis: u64,
    ) -> RepositoryFuture<'a, Result<Option<AccountSession>, StoreError>> {
        Box::pin(async move {
            let database = self.database.read().await;
            Ok(database
                .account_sessions
                .values()
                .find(|session| {
                    constant_time_sha256_eq(&session.refresh_token_hash, refresh_token_hash)
                        && session.revoked_at_epoch_millis.is_none()
                        && session.revoked_reason.is_none()
                        && session.expires_at_epoch_millis > now_epoch_millis
                        && database
                            .accounts
                            .get(&session.account_id)
                            .is_some_and(|account| {
                                account.status == crate::model::AccountStatus::Active
                            })
                })
                .cloned())
        })
    }

    fn rotate_refresh_session<'a>(
        &'a self,
        refresh_token_hash: &'a [u8; 32],
        replacement: &'a AccountSession,
        audit_entry: &'a AuditEntry,
        now_epoch_millis: u64,
    ) -> RepositoryFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move {
            let mut database = self.database.write().await;
            let mut candidate = database.clone();
            if replacement.revoked_at_epoch_millis.is_some()
                || replacement.revoked_reason.is_some()
                || replacement.expires_at_epoch_millis <= now_epoch_millis
                || candidate
                    .account_sessions
                    .contains_key(&replacement.account_session_id)
                || candidate
                    .audit_logs
                    .iter()
                    .any(|entry| entry.audit_id == audit_entry.audit_id)
                || audit_entry.actor_account_id.as_deref() != Some(replacement.account_id.as_str())
                || !candidate
                    .accounts
                    .get(&replacement.account_id)
                    .is_some_and(|account| account.status == crate::model::AccountStatus::Active)
            {
                return Err(StoreError::Conflict);
            }
            let old_session_id = candidate
                .account_sessions
                .iter()
                .find(|(_, session)| {
                    session.account_id == replacement.account_id
                        && session.mfa_verified == replacement.mfa_verified
                        && constant_time_sha256_eq(&session.refresh_token_hash, refresh_token_hash)
                        && session.revoked_at_epoch_millis.is_none()
                        && session.revoked_reason.is_none()
                        && session.expires_at_epoch_millis > now_epoch_millis
                })
                .map(|(id, _)| id.clone());
            let Some(old_session_id) = old_session_id else {
                return Ok(false);
            };
            let revocation_audit =
                account_session_revocation_audit(audit_entry, &old_session_id, "refresh_replay");
            if candidate
                .audit_logs
                .iter()
                .any(|entry| entry.audit_id == revocation_audit.audit_id)
                || revocation_audit.audit_id == audit_entry.audit_id
            {
                return Err(StoreError::Conflict);
            }
            let old_session = candidate
                .account_sessions
                .get_mut(&old_session_id)
                .ok_or(StoreError::Unavailable)?;
            old_session.revoked_at_epoch_millis = Some(now_epoch_millis);
            old_session.revoked_reason = Some("refresh_replay".to_owned());
            candidate
                .account_sessions
                .insert(replacement.account_session_id.clone(), replacement.clone());
            candidate.audit_logs.push(revocation_audit);
            candidate.audit_logs.push(audit_entry.clone());
            *database = candidate;
            Ok(true)
        })
    }

    fn revoke_account_session<'a>(
        &'a self,
        account_session_id: &'a str,
        account_id: &'a str,
        now_epoch_millis: u64,
        audit_entry: &'a AuditEntry,
    ) -> RepositoryFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move {
            let mut database = self.database.write().await;
            let Some(session) = database.account_sessions.get(account_session_id) else {
                return Ok(false);
            };
            if session.account_id != account_id || session.revoked_at_epoch_millis.is_some() {
                return Ok(false);
            }
            if audit_entry.actor_account_id.as_deref() != Some(account_id)
                || audit_entry.action != "logout"
                || audit_entry.result != "success"
                || database
                    .audit_logs
                    .iter()
                    .any(|entry| entry.audit_id == audit_entry.audit_id)
            {
                return Err(StoreError::Conflict);
            }
            let revocation_audit =
                account_session_revocation_audit(audit_entry, account_session_id, "logout");
            if database
                .audit_logs
                .iter()
                .any(|entry| entry.audit_id == revocation_audit.audit_id)
            {
                return Err(StoreError::Conflict);
            }
            let session = database
                .account_sessions
                .get_mut(account_session_id)
                .ok_or(StoreError::Unavailable)?;
            session.revoked_at_epoch_millis = Some(now_epoch_millis);
            session.revoked_reason = Some("logout".to_owned());
            database.audit_logs.push(revocation_audit);
            database.audit_logs.push(audit_entry.clone());
            Ok(true)
        })
    }

    fn load_device_authority<'a>(
        &'a self,
        device_id: &'a str,
    ) -> RepositoryFuture<'a, Result<Option<Device>, StoreError>> {
        Box::pin(async move {
            let database = self.database.read().await;
            Ok(database.devices.get(device_id).cloned())
        })
    }

    fn load_session_authority<'a>(
        &'a self,
        session_id: &'a str,
    ) -> RepositoryFuture<'a, Result<Option<Session>, StoreError>> {
        Box::pin(async move {
            let database = self.database.read().await;
            Ok(database.sessions.get(session_id).cloned())
        })
    }

    fn list_devices_for_account<'a>(
        &'a self,
        account_id: &'a str,
    ) -> RepositoryFuture<'a, Result<Vec<Device>, StoreError>> {
        Box::pin(async move {
            let database = self.database.read().await;
            Ok(database
                .devices
                .values()
                .filter(|device| device.account_id == account_id)
                .cloned()
                .collect())
        })
    }

    fn list_trusted_devices_for_account<'a>(
        &'a self,
        account_id: &'a str,
    ) -> RepositoryFuture<'a, Result<Vec<TrustedControllerDevice>, StoreError>> {
        Box::pin(async move {
            let database = self.database.read().await;
            Ok(database
                .trusted_controller_devices
                .values()
                .filter(|device| device.account_id == account_id)
                .cloned()
                .collect())
        })
    }

    fn load_signal_device_authority<'a>(
        &'a self,
        account_session_id: &'a str,
        account_id: &'a str,
        device_id: &'a str,
        now_epoch_millis: u64,
    ) -> RepositoryFuture<'a, Result<Option<(bool, Device)>, StoreError>> {
        Box::pin(async move {
            let database = self.database.read().await;
            let Some(device) = database.devices.get(device_id).cloned() else {
                return Ok(None);
            };
            let session_active = active_account_session(
                database.account_sessions.get(account_session_id),
                account_id,
                now_epoch_millis,
            );
            Ok(Some((session_active, device)))
        })
    }

    fn load_session_device_authority<'a>(
        &'a self,
        session_id: &'a str,
        device_id: &'a str,
    ) -> RepositoryFuture<'a, Result<SessionDeviceAuthority, StoreError>> {
        Box::pin(async move {
            let database = self.database.read().await;
            Ok((
                database.sessions.get(session_id).cloned(),
                database.devices.get(device_id).cloned(),
            ))
        })
    }

    fn verify_factor<'a>(
        &'a self,
        challenge_id: Option<&'a str>,
        account_id: &'a str,
        factor_kind: &'a str,
        code: &'a str,
        now_epoch_millis: u64,
    ) -> RepositoryFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move {
            let mut database = self.database.write().await;
            verify_factor_in_database(
                &mut database,
                challenge_id,
                account_id,
                factor_kind,
                code,
                now_epoch_millis,
            )
        })
    }

    fn consume_step_up<'a>(
        &'a self,
        expectation: &'a StepUpExpectation,
    ) -> RepositoryFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let mut database = self.database.write().await;
            consume_step_up_in_database(&mut database, expectation)
        })
    }

    fn apply_step_up_action<'a>(
        &'a self,
        expectation: &'a StepUpExpectation,
        action: &'a StepUpAction,
    ) -> RepositoryFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let mut database = self.database.write().await;
            let mut candidate = database.clone();
            apply_step_up_action_in_database(&mut candidate, expectation, action)?;
            *database = candidate;
            Ok(())
        })
    }

    fn finish_totp_enrollment<'a>(
        &'a self,
        completion: &'a TotpEnrollmentCompletion,
    ) -> RepositoryFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let mut database = self.database.write().await;
            let mut candidate = database.clone();
            let factor = &completion.factor;
            if !factor.active
                || factor.last_used_counter.is_none()
                || completion.recovery_codes.is_empty()
                || candidate.mfa_factors.contains_key(&factor.factor_id)
                || candidate
                    .mfa_factors
                    .values()
                    .any(|current| current.account_id == factor.account_id && current.active)
            {
                return Err(StoreError::Conflict);
            }
            let mut recovery_ids = HashSet::new();
            let mut recovery_hashes = HashSet::new();
            for record in &completion.recovery_codes {
                if record.account_id != factor.account_id
                    || record.used_at_epoch_millis.is_some()
                    || record.expires_at_epoch_millis.is_some_and(|expires| {
                        expires <= completion.audit_entry.created_at_epoch_millis
                    })
                    || !recovery_ids.insert(&record.recovery_code_id)
                    || !recovery_hashes.insert(record.code_hash)
                    || candidate
                        .recovery_codes
                        .contains_key(&record.recovery_code_id)
                    || candidate
                        .recovery_codes
                        .values()
                        .any(|current| current.code_hash == record.code_hash)
                {
                    return Err(StoreError::Conflict);
                }
            }
            let delivery = &completion.delivery;
            if delivery.account_id != factor.account_id
                || delivery.factor_id != factor.factor_id
                || usize::from(delivery.recovery_code_count) != completion.recovery_codes.len()
                || delivery.ciphertext.len() < 16
                || delivery.expires_at_epoch_millis <= delivery.created_at_epoch_millis
                || delivery.expires_at_epoch_millis
                    > delivery
                        .created_at_epoch_millis
                        .saturating_add(24 * 60 * 60 * 1_000)
                || delivery.acknowledged_at_epoch_millis.is_some()
                || !recovery_delivery_binding_is_valid(delivery)
                || !active_account_session(
                    candidate.account_sessions.get(&delivery.account_session_id),
                    &factor.account_id,
                    completion.audit_entry.created_at_epoch_millis,
                )
                || candidate
                    .recovery_code_deliveries
                    .contains_key(&delivery.delivery_id)
                || candidate.recovery_code_deliveries.values().any(|current| {
                    current.account_id == delivery.account_id
                        && constant_time_sha256_eq(
                            &current.idempotency_key_hash,
                            &delivery.idempotency_key_hash,
                        )
                })
            {
                return Err(StoreError::Conflict);
            }

            candidate
                .mfa_factors
                .insert(factor.factor_id.clone(), factor.clone());
            candidate.recovery_codes.retain(|_, record| {
                record.account_id != factor.account_id || record.used_at_epoch_millis.is_some()
            });
            for record in &completion.recovery_codes {
                candidate
                    .recovery_codes
                    .insert(record.recovery_code_id.clone(), record.clone());
            }
            candidate
                .recovery_code_deliveries
                .insert(delivery.delivery_id.clone(), delivery.clone());
            advance_account_security_epoch(
                &mut candidate,
                &factor.account_id,
                completion.audit_entry.created_at_epoch_millis,
            )?;
            let revocation_audits = authority_revocation_audits(
                &candidate,
                &factor.account_id,
                "mfa_enabled",
                &completion.audit_entry,
            );
            if revocation_audits.iter().any(|audit| {
                candidate
                    .audit_logs
                    .iter()
                    .any(|existing| existing.audit_id == audit.audit_id)
            }) {
                return Err(StoreError::Conflict);
            }
            for session in candidate.account_sessions.values_mut() {
                if session.account_id == factor.account_id
                    && session.revoked_at_epoch_millis.is_none()
                {
                    session.revoked_at_epoch_millis =
                        Some(completion.audit_entry.created_at_epoch_millis);
                    session.revoked_reason = Some("mfa_enabled".to_owned());
                }
            }
            for trusted in candidate.trusted_controller_devices.values_mut() {
                if trusted.account_id == factor.account_id
                    && trusted.status == TrustedDeviceStatus::Active
                {
                    trusted.status = TrustedDeviceStatus::Revoked;
                    trusted.revoked_at_epoch_millis =
                        Some(completion.audit_entry.created_at_epoch_millis);
                }
            }
            candidate.audit_logs.extend(revocation_audits);
            candidate.audit_logs.push(completion.audit_entry.clone());
            *database = candidate;
            Ok(())
        })
    }

    fn replay_totp_enrollment<'a>(
        &'a self,
        lookup: &'a TotpEnrollmentReplayLookup,
    ) -> RepositoryFuture<'a, Result<TotpEnrollmentReplayOutcome, StoreError>> {
        Box::pin(async move {
            let database = self.database.read().await;
            let delivery = database.recovery_code_deliveries.values().find(|delivery| {
                delivery.account_id == lookup.account_id
                    && constant_time_sha256_eq(
                        &delivery.idempotency_key_hash,
                        &lookup.idempotency_key_hash,
                    )
            });
            let Some(delivery) = delivery else {
                return Ok(TotpEnrollmentReplayOutcome::NotFound);
            };
            if delivery.account_session_id != lookup.account_session_id
                || delivery.factor_id != lookup.factor_id
                || lookup
                    .finish_request_binding_hash
                    .as_ref()
                    .is_some_and(|binding| {
                        !constant_time_sha256_eq(&delivery.finish_request_binding_hash, binding)
                    })
                || lookup
                    .client_ephemeral_public_key
                    .as_ref()
                    .is_some_and(|public_key| {
                        !constant_time_sha256_eq(&delivery.client_ephemeral_public_key, public_key)
                    })
            {
                return Ok(TotpEnrollmentReplayOutcome::BindingMismatch);
            }
            if !recovery_delivery_binding_is_valid(delivery) {
                return Err(StoreError::Unavailable);
            }
            let Some(session) = database.account_sessions.get(&delivery.account_session_id) else {
                return Ok(TotpEnrollmentReplayOutcome::NotAuthorized);
            };
            if session.account_id != lookup.account_id
                || session.revoked_reason.as_deref() != Some("mfa_enabled")
                || session.revoked_at_epoch_millis.is_none()
                || lookup.now_epoch_millis >= lookup.access_token_expires_at_epoch_millis
            {
                return Ok(TotpEnrollmentReplayOutcome::NotAuthorized);
            }
            if delivery.acknowledged_at_epoch_millis.is_some()
                || delivery.expires_at_epoch_millis <= lookup.now_epoch_millis
            {
                return Ok(TotpEnrollmentReplayOutcome::NotAuthorized);
            }
            Ok(TotpEnrollmentReplayOutcome::Replayed(Box::new(
                delivery.clone(),
            )))
        })
    }

    fn create_session<'a>(
        &'a self,
        command: &'a CreateSessionCommand,
    ) -> RepositoryFuture<'a, Result<CreateSessionOutcome, StoreError>> {
        Box::pin(async move {
            let mut database = self.database.write().await;
            if let Some(existing) = database.session_idempotency.get(&command.storage_key) {
                if existing.request_binding_hash != command.idempotency.request_binding_hash {
                    return Ok(CreateSessionOutcome::BindingMismatch);
                }
                let session = database
                    .session_events
                    .iter()
                    .find(|event| {
                        event.session_id == existing.session_id
                            && event.event_type == command.event.event_type
                            && event.actor_device_id == command.event.actor_device_id
                            && event.idempotency_key_hash == command.event.idempotency_key_hash
                    })
                    .and_then(|event| event.result_session.clone())
                    .ok_or(StoreError::Unavailable)?;
                return Ok(CreateSessionOutcome::Replayed(session));
            }
            if database.sessions.contains_key(&command.session.session_id)
                || database
                    .policy_evaluations
                    .contains_key(&command.policy_evaluation.policy_evaluation_id)
                || database
                    .session_events
                    .iter()
                    .any(|event| event.event_id == command.event.event_id)
                || database
                    .audit_logs
                    .iter()
                    .any(|entry| entry.audit_id == command.audit_entry.audit_id)
            {
                return Err(StoreError::Conflict);
            }
            let mut event = command.event.clone();
            event.result_session = Some(command.session.clone());
            database
                .session_idempotency
                .insert(command.storage_key.clone(), command.idempotency.clone());
            database
                .sessions
                .insert(command.session.session_id.clone(), command.session.clone());
            database.policy_evaluations.insert(
                command.policy_evaluation.policy_evaluation_id.clone(),
                command.policy_evaluation.clone(),
            );
            database.session_events.push(event);
            database.audit_logs.push(command.audit_entry.clone());
            Ok(CreateSessionOutcome::Created(command.session.clone()))
        })
    }

    fn transition_session<'a>(
        &'a self,
        command: &'a TransitionSessionCommand,
    ) -> RepositoryFuture<'a, Result<TransitionSessionOutcome, StoreError>> {
        Box::pin(async move {
            let mut database = self.database.write().await;
            if let Some(existing) = database.session_idempotency.get(&command.storage_key) {
                if existing.request_binding_hash != command.idempotency.request_binding_hash {
                    return Ok(TransitionSessionOutcome::BindingMismatch);
                }
                let event = database
                    .session_events
                    .iter()
                    .rev()
                    .find(|event| {
                        event.session_id == existing.session_id
                            && event.event_type == command.event.event_type
                            && event.actor_device_id == command.event.actor_device_id
                            && event.idempotency_key_hash == command.event.idempotency_key_hash
                    })
                    .ok_or(StoreError::Unavailable)?;
                let session = event
                    .result_session
                    .clone()
                    .ok_or(StoreError::Unavailable)?;
                return Ok(TransitionSessionOutcome::Replayed {
                    session,
                    event_id: event.event_id.clone(),
                });
            }
            if !command.apply_allowed {
                return Ok(TransitionSessionOutcome::InvalidTransition);
            }
            let Some(current) = database.sessions.get(&command.session.session_id) else {
                return Ok(TransitionSessionOutcome::NotFound);
            };
            if current.status != command.expected_status {
                return Ok(TransitionSessionOutcome::StateConflict);
            }
            if command.event.from_status != Some(command.expected_status)
                || command.event.session_id != command.session.session_id
                || command.event.to_status != command.session.status
                || command.idempotency.session_id != command.session.session_id
                || database
                    .session_events
                    .iter()
                    .any(|event| event.event_id == command.event.event_id)
                || database
                    .audit_logs
                    .iter()
                    .any(|entry| entry.audit_id == command.audit_entry.audit_id)
            {
                return Err(StoreError::Conflict);
            }
            let mut session = current.clone();
            session.status = command.session.status;
            session.updated_at_epoch_millis = current
                .updated_at_epoch_millis
                .max(command.session.updated_at_epoch_millis);
            if session.status.is_terminal() {
                if current.relay_token_epoch >= i64::MAX as u64 {
                    return Err(StoreError::Conflict);
                }
                session.relay_token_epoch = current.relay_token_epoch + 1;
                session.ended_at_epoch_millis = Some(
                    command
                        .session
                        .ended_at_epoch_millis
                        .unwrap_or(command.event.created_at_epoch_millis),
                );
            } else {
                session.relay_token_epoch = current.relay_token_epoch;
                session.ended_at_epoch_millis = current.ended_at_epoch_millis;
            }
            let mut event = command.event.clone();
            event.result_session = Some(session.clone());
            database
                .session_idempotency
                .insert(command.storage_key.clone(), command.idempotency.clone());
            database
                .sessions
                .insert(session.session_id.clone(), session.clone());
            database.session_events.push(event);
            database.audit_logs.push(command.audit_entry.clone());
            Ok(TransitionSessionOutcome::Applied {
                session,
                event_id: command.event.event_id.clone(),
            })
        })
    }

    fn register_device<'a>(
        &'a self,
        command: &'a DeviceRegistrationCommand,
    ) -> RepositoryFuture<'a, Result<DeviceRegistrationOutcome, StoreError>> {
        Box::pin(async move {
            let mut database = self.database.write().await;
            let mut candidate = database.clone();
            let Some(grant) = candidate
                .device_enrollment_grants
                .get(&command.grant_id)
                .cloned()
            else {
                return Ok(DeviceRegistrationOutcome::InvalidGrant);
            };
            validate_device_registration_authority(&candidate, command, &grant)?;
            let challenge_matches = candidate
                .risk_challenges
                .get(&grant.login_challenge_id)
                .is_some_and(|challenge| {
                    challenge.account_id == grant.account_id
                        && challenge.purpose == "login_mfa"
                        && challenge.status == RiskChallengeStatus::Consumed
                        && challenge.consumed_at_epoch_millis.is_some()
                        && constant_time_sha256_eq(
                            &challenge.operation_binding_hash,
                            &grant.login_challenge_binding_hash,
                        )
                });
            if !constant_time_sha256_eq(&grant.grant_secret_hash, &command.grant_secret_hash)
                || grant.account_id != command.account_id
                || grant.device_id != command.device.device_id
                || grant.protocol_version != command.protocol_version
                || grant.issued_account_session_id != command.account_session_id
                || !challenge_matches
                || !constant_time_sha256_eq(
                    &grant.device_public_key_fingerprint,
                    &sha256(&command.device.public_key),
                )
                || command
                    .now_epoch_millis
                    .abs_diff(command.signature_proof.timestamp_epoch_millis)
                    > 30_000
                || verify_registration_signature(command).is_err()
            {
                return Ok(DeviceRegistrationOutcome::InvalidGrant);
            }
            if grant.consumed_at_epoch_millis.is_some() {
                if grant.registration_request_binding_hash.as_ref()
                    != Some(&command.registration_request_binding_hash)
                {
                    return Err(StoreError::Conflict);
                }
                let Some(registered_public_key_id) = grant.registered_public_key_id.as_deref()
                else {
                    return Err(StoreError::Unavailable);
                };
                if grant.establish_trust != grant.registered_trusted_device_id.is_some() {
                    return Err(StoreError::Unavailable);
                }
                if !replayed_trust_matches(&candidate, &grant) {
                    return Err(StoreError::Unavailable);
                }
                let mut registration_audits = candidate.audit_logs.iter().filter(|audit| {
                    audit.action == "device_registered"
                        && audit.result == "success"
                        && audit.actor_account_id.as_deref() == Some(command.account_id.as_str())
                        && audit.target_device_id.as_deref()
                            == Some(command.device.device_id.as_str())
                        && registration_result_grant_id(&audit.metadata)
                            == Some(command.grant_id.as_str())
                });
                let registration_audit = registration_audits
                    .next()
                    .filter(|_| registration_audits.next().is_none())
                    .ok_or(StoreError::Unavailable)?;
                let historical_public_key =
                    candidate.device_public_keys.get(registered_public_key_id);
                let replayed = replayed_device_registration_result(
                    &registration_audit.metadata,
                    command,
                    &grant,
                    historical_public_key,
                )?;
                return Ok(DeviceRegistrationOutcome::Replayed(replayed));
            }
            if grant.expires_at_epoch_millis <= command.now_epoch_millis
                || !active_account_session(
                    candidate.account_sessions.get(&command.account_session_id),
                    &command.account_id,
                    command.now_epoch_millis,
                )
                || (grant.establish_trust
                    && !candidate
                        .account_sessions
                        .get(&command.account_session_id)
                        .is_some_and(|session| session.mfa_verified))
            {
                return Ok(DeviceRegistrationOutcome::InvalidGrant);
            }
            if candidate.devices.contains_key(&command.device.device_id)
                || candidate
                    .devices
                    .values()
                    .any(|current| current.public_key_id == command.device.public_key_id)
            {
                return Err(StoreError::Conflict);
            }
            if grant.registration_request_binding_hash.is_some()
                || grant.registered_public_key_id.is_some()
                || grant.registered_trusted_device_id.is_some()
            {
                return Err(StoreError::Unavailable);
            }
            let registered_trusted_device_id = if grant.establish_trust {
                Some(
                    command
                        .trusted_device_id
                        .clone()
                        .ok_or(StoreError::Conflict)?,
                )
            } else {
                None
            };
            if registered_trusted_device_id
                .as_ref()
                .is_some_and(|id| candidate.trusted_controller_devices.contains_key(id))
            {
                return Err(StoreError::Conflict);
            }
            let grant_record = candidate
                .device_enrollment_grants
                .get_mut(&command.grant_id)
                .ok_or(StoreError::Unavailable)?;
            grant_record.consumed_at_epoch_millis = Some(command.now_epoch_millis);
            grant_record.registration_request_binding_hash =
                Some(command.registration_request_binding_hash);
            grant_record.registered_public_key_id = Some(command.device.public_key_id.clone());
            grant_record.registered_trusted_device_id = registered_trusted_device_id.clone();
            candidate
                .devices
                .insert(command.device.device_id.clone(), command.device.clone());
            candidate.device_public_keys.insert(
                command.device.public_key_id.clone(),
                DevicePublicKeyRecord {
                    public_key_id: command.device.public_key_id.clone(),
                    device_id: command.device.device_id.clone(),
                    public_key: command.device.public_key,
                    version: command.device.public_key_version,
                    created_at_epoch_millis: command.device.created_at_epoch_millis,
                    revoked_at_epoch_millis: command.device.public_key_revoked_at_epoch_millis,
                },
            );
            if grant.establish_trust {
                let trusted_device_id = registered_trusted_device_id
                    .as_ref()
                    .ok_or(StoreError::Unavailable)?;
                let trust_proof_type =
                    grant.trust_proof_type.clone().ok_or(StoreError::Conflict)?;
                let trust_level = grant.trust_level.clone().ok_or(StoreError::Conflict)?;
                let ttl = if trust_proof_type == "device_signature_and_recovery_code" {
                    24 * 60 * 60 * 1_000
                } else {
                    30 * 24 * 60 * 60 * 1_000
                };
                candidate.trusted_controller_devices.insert(
                    trusted_device_id.clone(),
                    TrustedControllerDevice {
                        trusted_device_id: trusted_device_id.clone(),
                        account_id: command.account_id.clone(),
                        controller_device_id: command.device.device_id.clone(),
                        device_fingerprint_hash: grant.device_public_key_fingerprint,
                        trust_level,
                        status: TrustedDeviceStatus::Active,
                        trust_proof_type,
                        created_at_epoch_millis: command.now_epoch_millis,
                        last_used_at_epoch_millis: None,
                        expires_at_epoch_millis: command.now_epoch_millis.saturating_add(ttl),
                        revoked_at_epoch_millis: None,
                    },
                );
                candidate.audit_logs.push(
                    command
                        .trusted_device_audit_entry
                        .clone()
                        .ok_or(StoreError::Conflict)?,
                );
            }
            candidate
                .audit_logs
                .push(device_registration_result_audit(command)?);
            candidate.audit_logs.push(command.grant_audit_entry.clone());
            *database = candidate;
            Ok(DeviceRegistrationOutcome::Created(command.device.clone()))
        })
    }

    fn rotate_device_key<'a>(
        &'a self,
        rotation: &'a DeviceKeyRotation,
    ) -> RepositoryFuture<'a, Result<DeviceAuthorityChange, StoreError>> {
        Box::pin(async move {
            let mut database = self.database.write().await;
            let mut candidate = database.clone();
            let change = apply_device_key_rotation(&mut candidate, rotation)?;
            *database = candidate;
            Ok(change)
        })
    }

    fn manage_device<'a>(
        &'a self,
        command: &'a DeviceManagementCommand,
    ) -> RepositoryFuture<'a, Result<DeviceManagementOutcome, StoreError>> {
        Box::pin(async move {
            let mut database = self.database.write().await;
            let mut candidate = database.clone();
            let actor_valid =
                candidate
                    .devices
                    .get(&command.actor_device_id)
                    .is_some_and(|actor| {
                        actor.account_id == command.account_id
                            && actor.public_key_id == command.actor_public_key_id
                            && actor.public_key_version == command.actor_public_key_version
                            && actor.public_key_revoked_at_epoch_millis.is_none()
                            && actor.status.is_authorizable()
                    });
            if !actor_valid {
                return Err(StoreError::Conflict);
            }
            let Some(target) = candidate.devices.get(&command.target_device_id) else {
                return Ok(DeviceManagementOutcome::NotFound);
            };
            if target.account_id != command.account_id
                || target.public_key_id != command.expected_target_public_key_id
                || target.public_key_version != command.expected_target_public_key_version
            {
                return Err(StoreError::Conflict);
            }
            if !device_management_transition_allowed(target, command) {
                return Ok(DeviceManagementOutcome::InvalidTransition);
            }

            let tightening = matches!(
                command.action,
                Some(
                    DeviceManagementAction::Disable
                        | DeviceManagementAction::Unbind
                        | DeviceManagementAction::RevokePublicKey
                )
            );
            let mut affected_session_ids = candidate
                .sessions
                .values()
                .filter(|session| {
                    tightening
                        && !session.status.is_terminal()
                        && (session.controller_device_id == command.target_device_id
                            || session.controlled_device_id == command.target_device_id)
                })
                .map(|session| session.session_id.clone())
                .collect::<Vec<_>>();
            affected_session_ids.sort();
            let close_reason = command
                .action
                .and_then(device_management_session_close_reason);
            let mut session_events = Vec::with_capacity(affected_session_ids.len());
            let mut session_audits = Vec::with_capacity(affected_session_ids.len());
            let target_snapshot = target.clone();
            let authority_audits = device_management_authority_audits(
                command,
                &target_snapshot,
                &affected_session_ids,
            )?;
            let authority_audit = authority_audits.first().ok_or(StoreError::Unavailable)?;
            let trust_revocation_reason = command.action.and_then(|action| match action {
                DeviceManagementAction::Disable => Some("device_disabled"),
                DeviceManagementAction::Unbind => Some("device_unbound"),
                DeviceManagementAction::RevokePublicKey => Some("device_public_key_revoked"),
                DeviceManagementAction::Restore => None,
            });
            let trust_revocation_audits = trust_revocation_reason
                .map(|reason| {
                    candidate
                        .trusted_controller_devices
                        .values()
                        .filter(|trusted| {
                            trusted.account_id == command.account_id
                                && trusted.controller_device_id == command.target_device_id
                                && trusted.status == TrustedDeviceStatus::Active
                        })
                        .map(|trusted| {
                            trusted_device_revocation_audit(
                                authority_audit,
                                &trusted.trusted_device_id,
                                &trusted.controller_device_id,
                                reason,
                            )
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let account_session_revocation_audits = command
                .action
                .filter(|action| device_management_revokes_account_sessions(*action))
                .map(|_| {
                    candidate
                        .account_sessions
                        .values()
                        .filter(|session| {
                            session.account_id == command.account_id
                                && session.revoked_at_epoch_millis.is_none()
                        })
                        .map(|session| {
                            account_session_revocation_audit(
                                authority_audit,
                                &session.account_session_id,
                                "device_unbound",
                            )
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            for session_id in &affected_session_ids {
                let session = candidate
                    .sessions
                    .get_mut(session_id)
                    .ok_or(StoreError::Unavailable)?;
                let from_status = session.status;
                session.relay_token_epoch = session
                    .relay_token_epoch
                    .checked_add(1)
                    .ok_or(StoreError::Conflict)?;
                session.status = SessionStatus::Closed;
                session.ended_at_epoch_millis = Some(command.now_epoch_millis);
                session.updated_at_epoch_millis = session
                    .updated_at_epoch_millis
                    .max(command.now_epoch_millis);
                let (event, audit) = forced_session_close_records(
                    session,
                    from_status,
                    &command.audit_entry,
                    close_reason.ok_or(StoreError::Unavailable)?,
                );
                session_events.push(event);
                session_audits.push(audit);
            }
            if tightening {
                for trusted in candidate
                    .trusted_controller_devices
                    .values_mut()
                    .filter(|trusted| {
                        trusted.account_id == command.account_id
                            && trusted.controller_device_id == command.target_device_id
                            && trusted.status == TrustedDeviceStatus::Active
                    })
                {
                    trusted.status = TrustedDeviceStatus::Revoked;
                    trusted.revoked_at_epoch_millis = Some(command.now_epoch_millis);
                }
            }
            if command
                .action
                .is_some_and(device_management_revokes_account_sessions)
            {
                for session in candidate.account_sessions.values_mut().filter(|session| {
                    session.account_id == command.account_id
                        && session.revoked_at_epoch_millis.is_none()
                }) {
                    session.revoked_at_epoch_millis = Some(command.now_epoch_millis);
                    session.revoked_reason = Some("device_unbound".to_owned());
                }
            }

            let target = candidate
                .devices
                .get_mut(&command.target_device_id)
                .ok_or(StoreError::Unavailable)?;
            apply_device_management(target, command);
            let revoked_key_id = target
                .public_key_revoked_at_epoch_millis
                .map(|revoked_at| (target.public_key_id.clone(), revoked_at));
            let updated = target.clone();
            if let Some((public_key_id, revoked_at)) = revoked_key_id {
                if let Some(key) = candidate.device_public_keys.get_mut(&public_key_id) {
                    key.revoked_at_epoch_millis = Some(revoked_at);
                }
            }
            candidate
                .session_events
                .extend(session_events.iter().cloned());
            let new_audits = session_audits
                .into_iter()
                .chain(trust_revocation_audits)
                .chain(account_session_revocation_audits)
                .chain(authority_audits)
                .collect::<Vec<_>>();
            let mut new_audit_ids = HashSet::new();
            if new_audits.iter().any(|audit| {
                !new_audit_ids.insert(audit.audit_id.as_str())
                    || database
                        .audit_logs
                        .iter()
                        .any(|current| current.audit_id == audit.audit_id)
            }) {
                return Err(StoreError::Conflict);
            }
            candidate.audit_logs.extend(new_audits);
            *database = candidate;
            Ok(DeviceManagementOutcome::Updated(DeviceAuthorityChange {
                device: Box::new(updated),
                closed_session_events: session_events,
            }))
        })
    }
}

fn active_account_session(
    session: Option<&AccountSession>,
    account_id: &str,
    now_epoch_millis: u64,
) -> bool {
    session.is_some_and(|session| {
        session.account_id == account_id
            && session.revoked_at_epoch_millis.is_none()
            && session.expires_at_epoch_millis > now_epoch_millis
    })
}

pub(crate) fn verify_registration_signature(command: &DeviceRegistrationCommand) -> Result<(), ()> {
    let proof = &command.signature_proof;
    verify_device_signature(
        &command.device.public_key,
        "POST",
        &proof.target,
        &proof.canonical_body,
        proof.content_type.as_deref(),
        &proof.request_id,
        &command.device.device_id,
        &command.account_id,
        proof.timestamp_epoch_millis,
        &proof.nonce,
        &proof.signature,
    )
}

pub(crate) fn device_registration_result_audit(
    command: &DeviceRegistrationCommand,
) -> Result<AuditEntry, StoreError> {
    let device = &command.device;
    let snapshot = DeviceRegistrationResultSnapshot {
        grant_id: command.grant_id.clone(),
        registration_request_binding_hash: hex_encode(&command.registration_request_binding_hash),
        device_id: device.device_id.clone(),
        account_id: device.account_id.clone(),
        display_name: device.display_name.clone(),
        platform: device.platform.clone(),
        os_version: device.os_version.clone(),
        arch: device.arch.clone(),
        capabilities: device.capabilities.clone(),
        public_key_id: device.public_key_id.clone(),
        public_key_fingerprint: hex_encode(&sha256(&device.public_key)),
        public_key_version: device.public_key_version,
        public_key_revoked_at_epoch_millis: device.public_key_revoked_at_epoch_millis,
        status: device_lifecycle_status_snapshot_name(device.status).to_owned(),
        last_seen_epoch_millis: device.last_seen_epoch_millis,
        created_at_epoch_millis: device.created_at_epoch_millis,
        updated_at_epoch_millis: device.updated_at_epoch_millis,
    };
    let mut audit = command.registration_audit_entry.clone();
    audit.metadata.insert(
        DEVICE_REGISTRATION_RESULT_METADATA_KEY.to_owned(),
        serde_json::to_value(snapshot).map_err(|_| StoreError::Unavailable)?,
    );
    Ok(audit)
}

pub(crate) fn replayed_device_registration_result(
    metadata: &BTreeMap<String, serde_json::Value>,
    command: &DeviceRegistrationCommand,
    grant: &DeviceEnrollmentGrant,
    historical_public_key: Option<&DevicePublicKeyRecord>,
) -> Result<Device, StoreError> {
    let snapshot = metadata
        .get(DEVICE_REGISTRATION_RESULT_METADATA_KEY)
        .cloned()
        .ok_or(StoreError::Unavailable)
        .and_then(|value| {
            serde_json::from_value::<DeviceRegistrationResultSnapshot>(value)
                .map_err(|_| StoreError::Unavailable)
        })?;
    let device = &command.device;
    if snapshot.grant_id != command.grant_id
        || snapshot.grant_id != grant.grant_id
        || snapshot.registration_request_binding_hash
            != hex_encode(&command.registration_request_binding_hash)
        || snapshot.device_id != device.device_id
        || snapshot.device_id != grant.device_id
        || snapshot.account_id != command.account_id
        || snapshot.account_id != device.account_id
        || snapshot.account_id != grant.account_id
        || snapshot.display_name != device.display_name
        || snapshot.platform != device.platform
        || snapshot.os_version != device.os_version
        || snapshot.arch != device.arch
        || snapshot.capabilities != device.capabilities
        || snapshot.public_key_id.as_str()
            != grant.registered_public_key_id.as_deref().unwrap_or("")
        || snapshot.public_key_fingerprint != hex_encode(&grant.device_public_key_fingerprint)
        || snapshot.public_key_version != 1
        || snapshot.public_key_revoked_at_epoch_millis.is_some()
        || snapshot.status != "offline"
        || snapshot.last_seen_epoch_millis.is_some()
        || snapshot.updated_at_epoch_millis < snapshot.created_at_epoch_millis
    {
        return Err(StoreError::Unavailable);
    }

    let public_key = match historical_public_key {
        Some(record)
            if record.public_key_id == snapshot.public_key_id
                && record.device_id == snapshot.device_id
                && record.version == snapshot.public_key_version
                && constant_time_sha256_eq(
                    &sha256(&record.public_key),
                    &grant.device_public_key_fingerprint,
                ) =>
        {
            record.public_key
        }
        Some(_) => return Err(StoreError::Unavailable),
        None => device.public_key,
    };
    if !constant_time_sha256_eq(&sha256(&public_key), &grant.device_public_key_fingerprint) {
        return Err(StoreError::Unavailable);
    }

    Ok(Device {
        device_id: snapshot.device_id,
        account_id: snapshot.account_id,
        display_name: snapshot.display_name,
        platform: snapshot.platform,
        os_version: snapshot.os_version,
        arch: snapshot.arch,
        capabilities: snapshot.capabilities,
        public_key_id: snapshot.public_key_id,
        public_key,
        public_key_version: snapshot.public_key_version,
        public_key_revoked_at_epoch_millis: snapshot.public_key_revoked_at_epoch_millis,
        status: DeviceLifecycleStatus::Offline,
        last_seen_epoch_millis: snapshot.last_seen_epoch_millis,
        created_at_epoch_millis: snapshot.created_at_epoch_millis,
        updated_at_epoch_millis: snapshot.updated_at_epoch_millis,
    })
}

pub(crate) fn registration_result_grant_id(
    metadata: &BTreeMap<String, serde_json::Value>,
) -> Option<&str> {
    metadata
        .get(DEVICE_REGISTRATION_RESULT_METADATA_KEY)?
        .get("grant_id")?
        .as_str()
}

const fn device_lifecycle_status_snapshot_name(status: DeviceLifecycleStatus) -> &'static str {
    match status {
        DeviceLifecycleStatus::Online => "online",
        DeviceLifecycleStatus::Offline => "offline",
        DeviceLifecycleStatus::Busy => "busy",
        DeviceLifecycleStatus::Suspended => "suspended",
        DeviceLifecycleStatus::Disabled => "disabled",
        DeviceLifecycleStatus::Unbound => "unbound",
    }
}

pub(crate) fn device_management_transition_allowed(
    target: &Device,
    command: &DeviceManagementCommand,
) -> bool {
    if command.display_name.is_some() && command.action.is_some() {
        return false;
    }
    match command.action {
        None => command.display_name.is_some() && target.status != DeviceLifecycleStatus::Unbound,
        Some(DeviceManagementAction::Disable) => target.status.is_authorizable(),
        Some(DeviceManagementAction::Restore) => {
            target.status == DeviceLifecycleStatus::Disabled
                && target.public_key_revoked_at_epoch_millis.is_none()
        }
        Some(DeviceManagementAction::Unbind) => target.status != DeviceLifecycleStatus::Unbound,
        Some(DeviceManagementAction::RevokePublicKey) => {
            target.status != DeviceLifecycleStatus::Unbound
                && target.public_key_revoked_at_epoch_millis.is_none()
        }
    }
}

pub(crate) fn apply_device_management(target: &mut Device, command: &DeviceManagementCommand) {
    if let Some(display_name) = &command.display_name {
        target.display_name = display_name.clone();
    }
    match command.action {
        None => {}
        Some(DeviceManagementAction::Disable) => {
            target.status = DeviceLifecycleStatus::Disabled;
            target.capabilities.controlled = false;
            target.capabilities.unattended = false;
        }
        Some(DeviceManagementAction::Restore) => {
            target.status = DeviceLifecycleStatus::Offline;
            target.capabilities.controlled = false;
            target.capabilities.unattended = false;
        }
        Some(DeviceManagementAction::Unbind) => {
            target.status = DeviceLifecycleStatus::Unbound;
            target.capabilities.controlled = false;
            target.capabilities.unattended = false;
            target.public_key_revoked_at_epoch_millis = Some(command.now_epoch_millis);
        }
        Some(DeviceManagementAction::RevokePublicKey) => {
            target.status = DeviceLifecycleStatus::Disabled;
            target.capabilities.controlled = false;
            target.capabilities.unattended = false;
            target.public_key_revoked_at_epoch_millis = Some(command.now_epoch_millis);
        }
    }
    target.updated_at_epoch_millis = target.updated_at_epoch_millis.max(command.now_epoch_millis);
}

pub(crate) fn device_management_audit(
    command: &DeviceManagementCommand,
    affected_session_ids: &[String],
) -> Result<AuditEntry, StoreError> {
    let mut audit = command.audit_entry.clone();
    if command.action == Some(DeviceManagementAction::RevokePublicKey) {
        let serialized =
            serde_json::to_vec(affected_session_ids).map_err(|_| StoreError::Unavailable)?;
        audit.metadata.insert(
            "affected_session_ids_hash".to_owned(),
            serde_json::Value::String(sha256_hex(&serialized)),
        );
    }
    Ok(audit)
}

pub(crate) fn device_management_authority_audits(
    command: &DeviceManagementCommand,
    target: &Device,
    affected_session_ids: &[String],
) -> Result<Vec<AuditEntry>, StoreError> {
    let expected_action = match command.action {
        None | Some(DeviceManagementAction::Disable | DeviceManagementAction::Restore) => {
            "device_status_changed"
        }
        Some(DeviceManagementAction::Unbind) => "device_unregistered",
        Some(DeviceManagementAction::RevokePublicKey) => "device_public_key_revoked",
    };
    let audit_shape_valid = !command.audit_entry.audit_id.trim().is_empty()
        && command.audit_entry.actor_type == "device"
        && command.audit_entry.actor_account_id.as_deref() == Some(command.account_id.as_str())
        && command.audit_entry.actor_device_id.as_deref() == Some(command.actor_device_id.as_str())
        && command.audit_entry.target_device_id.as_deref()
            == Some(command.target_device_id.as_str())
        && command.audit_entry.action == expected_action
        && command.audit_entry.result == "success"
        && command.audit_entry.created_at_epoch_millis == command.now_epoch_millis;
    if !audit_shape_valid
        || target.account_id != command.account_id
        || target.device_id != command.target_device_id
        || target.public_key_id != command.expected_target_public_key_id
        || target.public_key_version != command.expected_target_public_key_version
    {
        return Err(StoreError::Conflict);
    }

    let mut primary = device_management_audit(command, affected_session_ids)?;
    match command.action {
        Some(DeviceManagementAction::RevokePublicKey) => {
            primary
                .metadata
                .extend(device_public_key_revocation_snapshot(
                    target,
                    affected_session_ids,
                    command.now_epoch_millis,
                    "user_requested",
                )?);
            Ok(vec![primary])
        }
        Some(DeviceManagementAction::Unbind) => {
            let mut key_audit = primary.clone();
            key_audit.audit_id = format!("{}:public-key", primary.audit_id);
            key_audit.action = "device_public_key_revoked".to_owned();
            key_audit.reason = Some("device_unbound".to_owned());
            key_audit.metadata = device_public_key_revocation_snapshot(
                target,
                affected_session_ids,
                command.now_epoch_millis,
                "device_unbound",
            )?;
            Ok(vec![primary, key_audit])
        }
        _ => Ok(vec![primary]),
    }
}

fn device_public_key_revocation_snapshot(
    target: &Device,
    affected_session_ids: &[String],
    revoked_at_epoch_millis: u64,
    revocation_reason: &str,
) -> Result<BTreeMap<String, serde_json::Value>, StoreError> {
    let mut session_ids = affected_session_ids.to_vec();
    session_ids.sort();
    let serialized = serde_json::to_vec(&session_ids).map_err(|_| StoreError::Unavailable)?;
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "old_public_key_id".to_owned(),
        serde_json::Value::String(target.public_key_id.clone()),
    );
    metadata.insert(
        "old_public_key_version".to_owned(),
        serde_json::Value::from(target.public_key_version),
    );
    metadata.insert(
        "old_public_key_fingerprint".to_owned(),
        serde_json::Value::String(sha256_hex(&target.public_key)),
    );
    metadata.insert(
        "revoked_at_epoch_millis".to_owned(),
        serde_json::Value::from(revoked_at_epoch_millis),
    );
    metadata.insert(
        "revocation_reason".to_owned(),
        serde_json::Value::String(revocation_reason.to_owned()),
    );
    metadata.insert(
        "affected_session_ids_hash".to_owned(),
        serde_json::Value::String(sha256_hex(&serialized)),
    );
    Ok(metadata)
}

pub(crate) fn validate_device_registration_authority(
    database: &Database,
    command: &DeviceRegistrationCommand,
    grant: &DeviceEnrollmentGrant,
) -> Result<(), StoreError> {
    let device = &command.device;
    let capability_shape_valid = device.capabilities.controller
        && !device.capabilities.file_transfer
        && !device.capabilities.unattended
        && (!matches!(device.platform, Platform::Ios) || !device.capabilities.controlled);
    let platform_architecture_valid =
        device.platform != Platform::Ubuntu || device.arch == Architecture::X86_64;
    let expected_binding = device_registration_binding_hash(
        &command.account_id,
        &command.account_session_id,
        &command.grant_id,
        &device.device_id,
        &device.display_name,
        registration_platform_name(&device.platform),
        &device.os_version,
        registration_architecture_name(&device.arch),
        device.capabilities.controller,
        device.capabilities.controlled,
        device.capabilities.file_transfer,
        device.capabilities.unattended,
        &sha256(&device.public_key),
        command.protocol_version,
    );
    if command.grant_id.trim().is_empty()
        || command.account_id.trim().is_empty()
        || command.account_session_id.trim().is_empty()
        || command.protocol_version == 0
        || device.account_id != command.account_id
        || device.device_id.trim().is_empty()
        || device.display_name.trim().is_empty()
        || device.os_version.trim().is_empty()
        || device.public_key_id.trim().is_empty()
        || device.public_key_version != 1
        || device.public_key_revoked_at_epoch_millis.is_some()
        || device.status != DeviceLifecycleStatus::Offline
        || device.last_seen_epoch_millis.is_some()
        || device.created_at_epoch_millis > command.now_epoch_millis
        || device.updated_at_epoch_millis < device.created_at_epoch_millis
        || !capability_shape_valid
        || !platform_architecture_valid
        || !constant_time_sha256_eq(
            &expected_binding,
            &command.registration_request_binding_hash,
        )
    {
        return Err(StoreError::Conflict);
    }

    let grant_ttl_valid = grant
        .expires_at_epoch_millis
        .checked_sub(grant.issued_at_epoch_millis)
        .is_some_and(|ttl| ttl > 0 && ttl <= 300_000);
    let grant_result_shape_valid = match grant.consumed_at_epoch_millis {
        None => {
            grant.registration_request_binding_hash.is_none()
                && grant.registered_public_key_id.is_none()
                && grant.registered_trusted_device_id.is_none()
        }
        Some(consumed_at) => {
            consumed_at >= grant.issued_at_epoch_millis
                && consumed_at <= grant.expires_at_epoch_millis
                && grant.registration_request_binding_hash.is_some()
                && grant
                    .registered_public_key_id
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty())
                && grant.establish_trust == grant.registered_trusted_device_id.is_some()
        }
    };
    let trust_shape_valid = matches!(
        (
            grant.establish_trust,
            grant.trust_proof_type.as_deref(),
            grant.trust_level.as_deref(),
        ),
        (false, None, None)
            | (true, Some("device_signature_and_mfa"), Some("standard"))
            | (
                true,
                Some("device_signature_and_recovery_code"),
                Some("high_risk_step_up_required")
            )
    );
    if grant.grant_id != command.grant_id
        || grant.account_id.trim().is_empty()
        || grant.device_id.trim().is_empty()
        || grant.login_challenge_id.trim().is_empty()
        || grant.issued_account_session_id.trim().is_empty()
        || grant.protocol_version == 0
        || !grant_ttl_valid
        || !grant_result_shape_valid
        || !trust_shape_valid
    {
        return Err(StoreError::Unavailable);
    }

    let registration_audit = &command.registration_audit_entry;
    let grant_audit = &command.grant_audit_entry;
    let mut audits = vec![registration_audit, grant_audit];
    if grant.establish_trust {
        audits.push(
            command
                .trusted_device_audit_entry
                .as_ref()
                .ok_or(StoreError::Conflict)?,
        );
        if command
            .trusted_device_id
            .as_deref()
            .is_none_or(|id| id.trim().is_empty())
        {
            return Err(StoreError::Conflict);
        }
    }
    if registration_audit.action != "device_registered"
        || grant_audit.action != "device_enrollment_grant_consumed"
        || (grant.establish_trust
            && command
                .trusted_device_audit_entry
                .as_ref()
                .is_none_or(|audit| audit.action != "trusted_device_added"))
    {
        return Err(StoreError::Conflict);
    }
    let mut audit_ids = HashSet::new();
    if audits.iter().any(|audit| {
        !audit_ids.insert(audit.audit_id.as_str())
            || database
                .audit_logs
                .iter()
                .any(|current| current.audit_id == audit.audit_id)
            || audit.actor_type != "device"
            || audit.actor_account_id.as_deref() != Some(command.account_id.as_str())
            || audit.actor_device_id.as_deref() != Some(device.device_id.as_str())
            || audit.actor_role.as_deref() != Some("none")
            || audit.actor_service.is_some()
            || audit.target_device_id.as_deref() != Some(device.device_id.as_str())
            || audit.session_id.is_some()
            || audit.result != "success"
            || audit.reason.is_some()
            || audit.request_id != command.signature_proof.request_id
            || audit.created_at_epoch_millis != command.now_epoch_millis
    }) {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

const fn registration_platform_name(platform: &Platform) -> &'static str {
    match platform {
        Platform::Windows => "windows",
        Platform::Ubuntu => "ubuntu",
        Platform::Ios => "ios",
    }
}

const fn registration_architecture_name(architecture: &Architecture) -> &'static str {
    match architecture {
        Architecture::X86_64 => "x86_64",
        Architecture::Aarch64 => "aarch64",
    }
}

fn replayed_trust_matches(database: &Database, grant: &DeviceEnrollmentGrant) -> bool {
    match grant.registered_trusted_device_id.as_deref() {
        None => !grant.establish_trust,
        Some(trusted_device_id) => {
            grant.establish_trust
                && database
                    .trusted_controller_devices
                    .get(trusted_device_id)
                    .is_some_and(|trusted| {
                        trusted.account_id == grant.account_id
                            && trusted.controller_device_id == grant.device_id
                            && trusted.trust_proof_type.as_str()
                                == grant.trust_proof_type.as_deref().unwrap_or("")
                            && trusted.trust_level.as_str()
                                == grant.trust_level.as_deref().unwrap_or("")
                            && constant_time_sha256_eq(
                                &trusted.device_fingerprint_hash,
                                &grant.device_public_key_fingerprint,
                            )
                    })
        }
    }
}

fn step_up_matches(database: &Database, expectation: &StepUpExpectation) -> bool {
    database
        .risk_challenges
        .get(&expectation.challenge_id)
        .is_some_and(|challenge| {
            challenge.status == RiskChallengeStatus::Verified
                && challenge.expires_at_epoch_millis > expectation.now_epoch_millis
                && challenge.account_id == expectation.account_id
                && challenge.device_id.as_deref() == Some(expectation.device_id.as_str())
                && challenge.purpose == expectation.purpose
                && challenge.verified_at_epoch_millis.is_some()
                && challenge.consumed_at_epoch_millis.is_none()
                && constant_time_sha256_eq(
                    &challenge.operation_binding_hash,
                    &expectation.operation_binding_hash,
                )
        })
}

fn verify_factor_in_database(
    database: &mut Database,
    challenge_id: Option<&str>,
    account_id: &str,
    factor_kind: &str,
    code: &str,
    now_epoch_millis: u64,
) -> Result<bool, StoreError> {
    if let Some(challenge_id) = challenge_id {
        let challenge = database
            .risk_challenges
            .get(challenge_id)
            .ok_or(StoreError::Conflict)?;
        if challenge.account_id != account_id
            || challenge.status != RiskChallengeStatus::Issued
            || challenge.attempts_remaining == 0
            || challenge.expires_at_epoch_millis <= now_epoch_millis
        {
            return Err(StoreError::Conflict);
        }
    }

    let accepted = match factor_kind {
        "totp" => {
            let factor = database
                .mfa_factors
                .values_mut()
                .find(|factor| factor.account_id == account_id && factor.active);
            factor.is_some_and(|factor| {
                verify_totp(
                    &factor.secret_base32,
                    code,
                    now_epoch_millis,
                    factor.last_used_counter,
                )
                .is_some_and(|counter| {
                    factor.last_used_counter = Some(counter);
                    true
                })
            })
        }
        "recovery_code" => {
            let code_hash = sha256(code.as_bytes());
            let recovery = database.recovery_codes.values_mut().find(|value| {
                value.account_id == account_id
                    && value.used_at_epoch_millis.is_none()
                    && value
                        .expires_at_epoch_millis
                        .is_none_or(|expires| expires > now_epoch_millis)
                    && constant_time_sha256_eq(&value.code_hash, &code_hash)
            });
            recovery.is_some_and(|recovery| {
                recovery.used_at_epoch_millis = Some(now_epoch_millis);
                true
            })
        }
        _ => false,
    };

    if let Some(challenge_id) = challenge_id {
        let challenge = database
            .risk_challenges
            .get_mut(challenge_id)
            .ok_or(StoreError::Conflict)?;
        if accepted {
            challenge.status = RiskChallengeStatus::Verified;
            challenge.verified_at_epoch_millis = Some(now_epoch_millis);
        } else {
            challenge.attempts_remaining = challenge.attempts_remaining.saturating_sub(1);
            if challenge.attempts_remaining == 0 {
                challenge.status = RiskChallengeStatus::Failed;
            }
        }
    }
    Ok(accepted)
}

fn consume_step_up_in_database(
    database: &mut Database,
    expectation: &StepUpExpectation,
) -> Result<(), StoreError> {
    if !step_up_matches(database, expectation) {
        return Err(StoreError::Conflict);
    }
    let challenge = database
        .risk_challenges
        .get_mut(&expectation.challenge_id)
        .ok_or(StoreError::Conflict)?;
    challenge.status = RiskChallengeStatus::Consumed;
    challenge.consumed_at_epoch_millis = Some(expectation.now_epoch_millis);
    Ok(())
}

fn apply_step_up_action_in_database(
    database: &mut Database,
    expectation: &StepUpExpectation,
    action: &StepUpAction,
) -> Result<(), StoreError> {
    if !step_up_matches(database, expectation) {
        return Err(StoreError::Conflict);
    }
    if !database
        .devices
        .get(&expectation.device_id)
        .is_some_and(|device| {
            device.account_id == expectation.account_id && device.status.is_authorizable()
        })
    {
        return Err(StoreError::Conflict);
    }
    if database
        .audit_logs
        .iter()
        .any(|entry| entry.audit_id == action.audit_entry().audit_id)
        || action.audit_entry().actor_account_id.as_deref() != Some(expectation.account_id.as_str())
    {
        return Err(StoreError::Conflict);
    }
    match action {
        StepUpAction::RotateRecoveryCodes { records, .. } => {
            if expectation.purpose != "recovery_code_rotate"
                || records.is_empty()
                || records
                    .iter()
                    .any(|record| record.account_id != expectation.account_id)
            {
                return Err(StoreError::Conflict);
            }
        }
        StepUpAction::DisableMfaFactor { factor_id, .. } => {
            if expectation.purpose != "mfa_factor_change"
                || !database.mfa_factors.get(factor_id).is_some_and(|factor| {
                    factor.account_id == expectation.account_id && factor.active
                })
            {
                return Err(StoreError::Conflict);
            }
        }
        StepUpAction::ChangePassword {
            expected_password_hash,
            new_password_hash,
            ..
        } => {
            if expectation.purpose != "password_change"
                || new_password_hash.is_empty()
                || new_password_hash == expected_password_hash
                || !database
                    .accounts
                    .get(&expectation.account_id)
                    .is_some_and(|account| {
                        account.status == crate::model::AccountStatus::Active
                            && account.password_hash == *expected_password_hash
                    })
            {
                return Err(StoreError::Conflict);
            }
        }
        StepUpAction::RevokeTrustedDevice {
            trusted_device_id, ..
        } => {
            if expectation.purpose != "trusted_device_change"
                || !database
                    .trusted_controller_devices
                    .get(trusted_device_id)
                    .is_some_and(|trusted| {
                        trusted.account_id == expectation.account_id
                            && trusted.status == TrustedDeviceStatus::Active
                    })
            {
                return Err(StoreError::Conflict);
            }
        }
    }

    consume_step_up_in_database(database, expectation)?;
    match action {
        StepUpAction::RotateRecoveryCodes { records, .. } => {
            database
                .recovery_codes
                .retain(|_, record| record.account_id != expectation.account_id);
            for record in records {
                database
                    .recovery_codes
                    .insert(record.recovery_code_id.clone(), record.clone());
            }
        }
        StepUpAction::DisableMfaFactor { factor_id, .. } => {
            database.mfa_factors.remove(factor_id);
            if !database
                .mfa_factors
                .values()
                .any(|factor| factor.account_id == expectation.account_id && factor.active)
            {
                database
                    .recovery_codes
                    .retain(|_, code| code.account_id != expectation.account_id);
            }
            advance_account_security_epoch(
                database,
                &expectation.account_id,
                expectation.now_epoch_millis,
            )?;
        }
        StepUpAction::ChangePassword {
            new_password_hash, ..
        } => {
            let account = database
                .accounts
                .get_mut(&expectation.account_id)
                .ok_or(StoreError::Conflict)?;
            account.password_hash = new_password_hash.clone();
            account.updated_at_epoch_millis = account
                .updated_at_epoch_millis
                .saturating_add(1)
                .max(expectation.now_epoch_millis);
        }
        StepUpAction::RevokeTrustedDevice {
            trusted_device_id, ..
        } => {
            let trusted = database
                .trusted_controller_devices
                .get_mut(trusted_device_id)
                .ok_or(StoreError::Conflict)?;
            trusted.status = TrustedDeviceStatus::Revoked;
            trusted.revoked_at_epoch_millis = Some(expectation.now_epoch_millis);
        }
    }
    let revoked_reason = match action {
        StepUpAction::DisableMfaFactor { .. } => Some("mfa_disabled"),
        StepUpAction::ChangePassword { .. } => Some("password_changed"),
        _ => None,
    };
    if let Some(revoked_reason) = revoked_reason {
        let revocation_audits = authority_revocation_audits(
            database,
            &expectation.account_id,
            revoked_reason,
            action.audit_entry(),
        );
        if revocation_audits.iter().any(|audit| {
            database
                .audit_logs
                .iter()
                .any(|existing| existing.audit_id == audit.audit_id)
        }) {
            return Err(StoreError::Conflict);
        }
        for session in database.account_sessions.values_mut() {
            if session.account_id == expectation.account_id
                && session.revoked_at_epoch_millis.is_none()
            {
                session.revoked_at_epoch_millis = Some(expectation.now_epoch_millis);
                session.revoked_reason = Some(revoked_reason.to_owned());
            }
        }
        for trusted in database.trusted_controller_devices.values_mut() {
            if trusted.account_id == expectation.account_id
                && trusted.status == TrustedDeviceStatus::Active
            {
                trusted.status = TrustedDeviceStatus::Revoked;
                trusted.revoked_at_epoch_millis = Some(expectation.now_epoch_millis);
            }
        }
        database.audit_logs.extend(revocation_audits);
    }
    database.audit_logs.push(action.audit_entry().clone());
    Ok(())
}

fn advance_account_security_epoch(
    database: &mut Database,
    account_id: &str,
    now_epoch_millis: u64,
) -> Result<(), StoreError> {
    let account = database
        .accounts
        .get_mut(account_id)
        .ok_or(StoreError::Conflict)?;
    account.updated_at_epoch_millis = account
        .updated_at_epoch_millis
        .saturating_add(1)
        .max(now_epoch_millis);
    Ok(())
}

pub(crate) fn authority_revocation_audits(
    database: &Database,
    account_id: &str,
    revoked_reason: &str,
    source: &AuditEntry,
) -> Vec<AuditEntry> {
    let mut audits = Vec::new();
    for session in database.account_sessions.values().filter(|session| {
        session.account_id == account_id && session.revoked_at_epoch_millis.is_none()
    }) {
        audits.push(account_session_revocation_audit(
            source,
            &session.account_session_id,
            revoked_reason,
        ));
    }
    for trusted in database
        .trusted_controller_devices
        .values()
        .filter(|trusted| {
            trusted.account_id == account_id && trusted.status == TrustedDeviceStatus::Active
        })
    {
        audits.push(trusted_device_revocation_audit(
            source,
            &trusted.trusted_device_id,
            &trusted.controller_device_id,
            revoked_reason,
        ));
    }
    audits
}

pub(crate) fn account_session_revocation_audit(
    source: &AuditEntry,
    account_session_id: &str,
    revoked_reason: &str,
) -> AuditEntry {
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "account_session_id".to_owned(),
        serde_json::Value::String(account_session_id.to_owned()),
    );
    metadata.insert(
        "revoked_reason".to_owned(),
        serde_json::Value::String(revoked_reason.to_owned()),
    );
    AuditEntry {
        audit_id: format!("{}:account-session:{account_session_id}", source.audit_id),
        actor_type: source.actor_type.clone(),
        actor_account_id: source.actor_account_id.clone(),
        actor_device_id: source.actor_device_id.clone(),
        actor_role: source.actor_role.clone(),
        actor_service: source.actor_service.clone(),
        target_device_id: None,
        session_id: None,
        action: "account_session_revoked".to_owned(),
        result: "success".to_owned(),
        reason: Some(revoked_reason.to_owned()),
        metadata,
        request_id: source.request_id.clone(),
        created_at_epoch_millis: source.created_at_epoch_millis,
    }
}

pub(crate) fn trusted_device_revocation_audit(
    source: &AuditEntry,
    trusted_device_id: &str,
    controller_device_id: &str,
    revoked_reason: &str,
) -> AuditEntry {
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "trusted_device_id".to_owned(),
        serde_json::Value::String(trusted_device_id.to_owned()),
    );
    metadata.insert(
        "revoked_reason".to_owned(),
        serde_json::Value::String(revoked_reason.to_owned()),
    );
    AuditEntry {
        audit_id: format!("{}:trusted-device:{trusted_device_id}", source.audit_id),
        actor_type: source.actor_type.clone(),
        actor_account_id: source.actor_account_id.clone(),
        actor_device_id: source.actor_device_id.clone(),
        actor_role: source.actor_role.clone(),
        actor_service: source.actor_service.clone(),
        target_device_id: Some(controller_device_id.to_owned()),
        session_id: None,
        action: "trusted_device_revoked".to_owned(),
        result: "success".to_owned(),
        reason: Some(revoked_reason.to_owned()),
        metadata,
        request_id: source.request_id.clone(),
        created_at_epoch_millis: source.created_at_epoch_millis,
    }
}

fn apply_device_key_rotation(
    database: &mut Database,
    rotation: &DeviceKeyRotation,
) -> Result<DeviceAuthorityChange, StoreError> {
    if !step_up_matches(database, &rotation.step_up)
        || rotation.step_up.purpose != "device_key_rotation"
    {
        return Err(StoreError::Conflict);
    }
    let current = database
        .devices
        .get(&rotation.step_up.device_id)
        .ok_or(StoreError::Conflict)?;
    if current.account_id != rotation.step_up.account_id
        || current.public_key_id != rotation.current_public_key_id
        || current.public_key_version != rotation.current_public_key_version
        || current.public_key_revoked_at_epoch_millis.is_some()
        || current.public_key == rotation.new_public_key
        || current.public_key_version.checked_add(1) != Some(rotation.new_public_key_version)
        || rotation.new_public_key_id == rotation.current_public_key_id
        || database.devices.values().any(|device| {
            device.public_key_id == rotation.new_public_key_id
                && device.device_id != rotation.step_up.device_id
        })
    {
        return Err(StoreError::Conflict);
    }
    let current = current.clone();
    let old_fingerprint = sha256(&current.public_key);
    let mut affected_epochs = database
        .sessions
        .values()
        .filter(|session| {
            !session.status.is_terminal()
                && (session.controller_device_id == rotation.step_up.device_id
                    || session.controlled_device_id == rotation.step_up.device_id)
        })
        .map(|session| {
            session
                .relay_token_epoch
                .checked_add(1)
                .map(|epoch| (session.session_id.clone(), epoch))
                .ok_or(StoreError::Conflict)
        })
        .collect::<Result<Vec<_>, _>>()?;
    affected_epochs.sort_by(|left, right| left.0.cmp(&right.0));
    let rotation_audit = device_key_rotation_authority_audit(rotation, &current)?;
    let trust_revocation_audits = database
        .trusted_controller_devices
        .values()
        .filter(|trusted| {
            trusted.account_id == rotation.step_up.account_id
                && trusted.controller_device_id == rotation.step_up.device_id
                && trusted.status == TrustedDeviceStatus::Active
                && constant_time_sha256_eq(&trusted.device_fingerprint_hash, &old_fingerprint)
        })
        .map(|trusted| {
            trusted_device_revocation_audit(
                &rotation_audit,
                &trusted.trusted_device_id,
                &trusted.controller_device_id,
                "device_key_rotated",
            )
        })
        .collect::<Vec<_>>();

    consume_step_up_in_database(database, &rotation.step_up)?;
    if let Some(old_key) = database
        .device_public_keys
        .get_mut(&rotation.current_public_key_id)
    {
        old_key.revoked_at_epoch_millis = Some(rotation.step_up.now_epoch_millis);
    }
    for trusted in database
        .trusted_controller_devices
        .values_mut()
        .filter(|trusted| {
            trusted.account_id == rotation.step_up.account_id
                && trusted.controller_device_id == rotation.step_up.device_id
                && trusted.status == TrustedDeviceStatus::Active
                && constant_time_sha256_eq(&trusted.device_fingerprint_hash, &old_fingerprint)
        })
    {
        trusted.status = TrustedDeviceStatus::Revoked;
        trusted.revoked_at_epoch_millis = Some(rotation.step_up.now_epoch_millis);
    }
    database.device_public_keys.insert(
        rotation.new_public_key_id.clone(),
        DevicePublicKeyRecord {
            public_key_id: rotation.new_public_key_id.clone(),
            device_id: rotation.step_up.device_id.clone(),
            public_key: rotation.new_public_key,
            version: rotation.new_public_key_version,
            created_at_epoch_millis: rotation.step_up.now_epoch_millis,
            revoked_at_epoch_millis: None,
        },
    );
    let device = database
        .devices
        .get_mut(&rotation.step_up.device_id)
        .ok_or(StoreError::Conflict)?;
    device.public_key_id = rotation.new_public_key_id.clone();
    device.public_key = rotation.new_public_key;
    device.public_key_version = rotation.new_public_key_version;
    device.public_key_revoked_at_epoch_millis = None;
    device.updated_at_epoch_millis = rotation.step_up.now_epoch_millis;
    let updated = device.clone();
    let mut session_events = Vec::with_capacity(affected_epochs.len());
    let mut session_audits = Vec::with_capacity(affected_epochs.len());
    for (session_id, epoch) in affected_epochs {
        if let Some(session) = database.sessions.get_mut(&session_id) {
            let from_status = session.status;
            session.relay_token_epoch = epoch;
            session.status = SessionStatus::Closed;
            session.ended_at_epoch_millis = Some(rotation.step_up.now_epoch_millis);
            session.updated_at_epoch_millis = session
                .updated_at_epoch_millis
                .max(rotation.step_up.now_epoch_millis);
            let (event, audit) = forced_session_close_records(
                session,
                from_status,
                &rotation_audit,
                "device_key_rotated",
            );
            session_events.push(event);
            session_audits.push(audit);
        }
    }
    database
        .session_events
        .extend(session_events.iter().cloned());
    let new_audits = session_audits
        .into_iter()
        .chain(trust_revocation_audits)
        .chain([rotation_audit])
        .collect::<Vec<_>>();
    let mut new_audit_ids = HashSet::new();
    if new_audits.iter().any(|audit| {
        !new_audit_ids.insert(audit.audit_id.as_str())
            || database
                .audit_logs
                .iter()
                .any(|current| current.audit_id == audit.audit_id)
    }) {
        return Err(StoreError::Conflict);
    }
    database.audit_logs.extend(new_audits);
    Ok(DeviceAuthorityChange {
        device: Box::new(updated),
        closed_session_events: session_events,
    })
}

pub(crate) fn device_key_rotation_authority_audit(
    rotation: &DeviceKeyRotation,
    current: &Device,
) -> Result<AuditEntry, StoreError> {
    let source = &rotation.audit_entry;
    if source.audit_id.trim().is_empty()
        || source.actor_type != "device"
        || source.actor_account_id.as_deref() != Some(rotation.step_up.account_id.as_str())
        || source.actor_device_id.as_deref() != Some(rotation.step_up.device_id.as_str())
        || source.target_device_id.as_deref() != Some(rotation.step_up.device_id.as_str())
        || source.action != "device_public_key_rotated"
        || source.result != "success"
        || source.created_at_epoch_millis != rotation.step_up.now_epoch_millis
        || current.account_id != rotation.step_up.account_id
        || current.device_id != rotation.step_up.device_id
        || current.public_key_id != rotation.current_public_key_id
        || current.public_key_version != rotation.current_public_key_version
    {
        return Err(StoreError::Conflict);
    }
    let mut audit = source.clone();
    audit.metadata.insert(
        "old_public_key_id".to_owned(),
        serde_json::Value::String(current.public_key_id.clone()),
    );
    audit.metadata.insert(
        "old_public_key_version".to_owned(),
        serde_json::Value::from(current.public_key_version),
    );
    audit.metadata.insert(
        "old_public_key_fingerprint".to_owned(),
        serde_json::Value::String(sha256_hex(&current.public_key)),
    );
    audit.metadata.insert(
        "new_public_key_id".to_owned(),
        serde_json::Value::String(rotation.new_public_key_id.clone()),
    );
    audit.metadata.insert(
        "new_public_key_version".to_owned(),
        serde_json::Value::from(rotation.new_public_key_version),
    );
    audit.metadata.insert(
        "new_public_key_fingerprint".to_owned(),
        serde_json::Value::String(sha256_hex(&rotation.new_public_key)),
    );
    audit.metadata.insert(
        "revoked_at_epoch_millis".to_owned(),
        serde_json::Value::from(rotation.step_up.now_epoch_millis),
    );
    audit.metadata.insert(
        "rotation_reason".to_owned(),
        serde_json::Value::String("user_requested".to_owned()),
    );
    audit.metadata.insert(
        "step_up_challenge_id".to_owned(),
        serde_json::Value::String(rotation.step_up.challenge_id.clone()),
    );
    Ok(audit)
}

pub(crate) fn device_management_session_close_reason(
    action: DeviceManagementAction,
) -> Option<&'static str> {
    match action {
        DeviceManagementAction::Disable => Some("device_disabled"),
        DeviceManagementAction::Unbind => Some("device_unbound"),
        DeviceManagementAction::RevokePublicKey => Some("device_public_key_revoked"),
        DeviceManagementAction::Restore => None,
    }
}

pub(crate) const fn device_management_revokes_account_sessions(
    action: DeviceManagementAction,
) -> bool {
    matches!(
        action,
        DeviceManagementAction::Unbind | DeviceManagementAction::RevokePublicKey
    )
}

pub(crate) fn forced_session_close_records(
    session: &Session,
    from_status: SessionStatus,
    source_audit: &AuditEntry,
    reason: &str,
) -> (SessionEvent, AuditEntry) {
    let binding = format!(
        "rctl-forced-session-close-v1\0{}\0{}",
        source_audit.audit_id, session.session_id
    );
    let event_id = sha256_hex(format!("event\0{binding}").as_bytes());
    let audit_id = sha256_hex(format!("audit\0{binding}").as_bytes());
    let idempotency_key_hash = sha256_hex(format!("idempotency\0{binding}").as_bytes());
    let event = SessionEvent {
        event_id,
        session_id: session.session_id.clone(),
        event_type: "closed".to_owned(),
        from_status: Some(from_status),
        to_status: SessionStatus::Closed,
        actor_type: "system".to_owned(),
        actor_account_id: None,
        actor_device_id: None,
        actor_role: None,
        reason: Some(reason.to_owned()),
        idempotency_key_hash,
        request_id: source_audit.request_id.clone(),
        created_at_epoch_millis: source_audit.created_at_epoch_millis,
        result_session: Some(session.clone()),
    };
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "trigger_action".to_owned(),
        serde_json::Value::String(source_audit.action.clone()),
    );
    let audit = AuditEntry {
        audit_id,
        actor_type: "system".to_owned(),
        actor_account_id: None,
        actor_device_id: None,
        actor_role: None,
        actor_service: None,
        target_device_id: source_audit.target_device_id.clone(),
        session_id: Some(session.session_id.clone()),
        action: "session_ended".to_owned(),
        result: "success".to_owned(),
        reason: Some(reason.to_owned()),
        metadata,
        request_id: source_audit.request_id.clone(),
        created_at_epoch_millis: source_audit.created_at_epoch_millis,
    };
    (event, audit)
}

pub(crate) fn validate_login_challenge_authority(
    authority: &LoginChallengeAuthority,
) -> Result<(), StoreError> {
    let challenge = &authority.challenge;
    let context = &authority.context;
    let expected_persistent_device_id =
        (context.device_state == LoginDeviceState::Registered).then(|| context.device_id.clone());
    let identity_shape_valid = match context.device_state {
        LoginDeviceState::Registered => {
            context
                .public_key_id
                .as_ref()
                .is_some_and(|id| !id.is_empty())
                && context.public_key_version > 0
        }
        LoginDeviceState::PendingEnrollment => {
            context.public_key_id.is_none() && context.public_key_version == 0
        }
    };
    let ttl_valid = challenge
        .expires_at_epoch_millis
        .checked_sub(challenge.created_at_epoch_millis)
        .is_some_and(|ttl| ttl > 0 && ttl <= 300_000);
    if challenge.purpose != "login_mfa"
        || !risk_challenge_required_methods_are_valid(
            &challenge.purpose,
            &challenge.required_methods,
        )
        || challenge.status != RiskChallengeStatus::Issued
        || challenge.device_id != expected_persistent_device_id
        || challenge.account_id.is_empty()
        || context.device_id.is_empty()
        || !identity_shape_valid
        || context.protocol_version == 0
        || context.attempts_limit == 0
        || context.attempts_limit > 5
        || challenge.attempts_remaining != context.attempts_limit
        || challenge.required_methods != context.required_factors
        || challenge.created_at_epoch_millis != context.issued_at_epoch_millis
        || !ttl_valid
        || !constant_time_sha256_eq(
            &sha256(&context.device_public_key),
            &context.device_public_key_fingerprint,
        )
        || !constant_time_sha256_eq(
            &challenge.operation_binding_hash,
            &context.login_challenge_binding_hash,
        )
    {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

pub(crate) fn validate_login_finish_command_shape(
    command: &LoginFinishCommand,
) -> Result<(), StoreError> {
    let has_factor = command.factor_kind.is_some();
    let uses_trusted_device = command.trusted_device_id_to_use.is_some();
    let expected_mfa_verified = has_factor || uses_trusted_device;
    let registered = command.persistent_device_id.is_some();
    let enrollment_shape_valid = matches!(
        (
            registered,
            command.enrollment_grant.is_some(),
            command.trusted_device_to_create.is_some(),
            has_factor,
        ),
        (true, false, true, true) | (true, false, false, false) | (false, true, false, _)
    );
    if command.challenge_id.is_empty()
        || command.account_id.is_empty()
        || command.device_id.is_empty()
        || command.account_session.account_session_id.is_empty()
        || command.account_session.account_id != command.account_id
        || command.account_session.mfa_verified != expected_mfa_verified
        || command.account_session.expires_at_epoch_millis <= command.now_epoch_millis
        || command.account_session.revoked_at_epoch_millis.is_some()
        || command.account_session.revoked_reason.is_some()
        || has_factor != command.factor_code.is_some()
        || has_factor == command.required_factors.is_empty()
        || (has_factor && uses_trusted_device)
        || (!registered && uses_trusted_device)
        || command
            .persistent_device_id
            .as_deref()
            .is_some_and(|device_id| device_id != command.device_id)
        || !enrollment_shape_valid
    {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

pub(crate) fn validate_login_finish_artifacts(
    command: &LoginFinishCommand,
    challenge: &RiskChallenge,
) -> Result<(), StoreError> {
    let mut audit_ids = HashSet::new();
    let mut expected_actions = HashSet::from(["mfa_challenge_succeeded", "login_succeeded"]);
    if command.trusted_device_to_create.is_some() {
        expected_actions.insert("trusted_device_added");
    }
    if command.factor_kind.as_deref() == Some("recovery_code") {
        expected_actions.insert("mfa_recovery_code_used");
    }
    let actual_actions = command
        .audit_entries
        .iter()
        .map(|audit| audit.action.as_str())
        .collect::<HashSet<_>>();
    if actual_actions != expected_actions
        || command.audit_entries.len() != expected_actions.len()
        || command.audit_entries.iter().any(|audit| {
            audit.audit_id.trim().is_empty()
                || audit.actor_type != "account"
                || audit.result != "success"
                || audit.actor_account_id.as_deref() != Some(command.account_id.as_str())
                || audit.actor_device_id.is_some()
                || audit.actor_role.is_some()
                || audit.actor_service.is_some()
                || audit.created_at_epoch_millis != command.now_epoch_millis
                || !audit_ids.insert(audit.audit_id.as_str())
        })
        || command.failure_audit_entry.audit_id.trim().is_empty()
        || command.failure_audit_entry.actor_type != "account"
        || command.failure_audit_entry.actor_account_id.as_deref()
            != Some(command.account_id.as_str())
        || command.failure_audit_entry.actor_device_id.is_some()
        || command.failure_audit_entry.actor_role.is_some()
        || command.failure_audit_entry.actor_service.is_some()
        || command.failure_audit_entry.action != "mfa_challenge_failed"
        || command.failure_audit_entry.result != "failure"
        || command.failure_audit_entry.created_at_epoch_millis != command.now_epoch_millis
        || !audit_ids.insert(command.failure_audit_entry.audit_id.as_str())
    {
        return Err(StoreError::Conflict);
    }

    if let Some(grant) = &command.enrollment_grant {
        let ttl = grant
            .expires_at_epoch_millis
            .checked_sub(grant.issued_at_epoch_millis);
        let unconsumed_shape = grant.consumed_at_epoch_millis.is_none()
            && grant.registration_request_binding_hash.is_none()
            && grant.registered_public_key_id.is_none()
            && grant.registered_trusted_device_id.is_none();
        let trust_matches_factor = match command.factor_kind.as_deref() {
            None => {
                !grant.establish_trust
                    && grant.trust_proof_type.is_none()
                    && grant.trust_level.is_none()
            }
            Some("totp") => {
                grant.establish_trust
                    && grant.trust_proof_type.as_deref() == Some("device_signature_and_mfa")
                    && grant.trust_level.as_deref() == Some("standard")
            }
            Some("recovery_code") => {
                grant.establish_trust
                    && grant.trust_proof_type.as_deref()
                        == Some("device_signature_and_recovery_code")
                    && grant.trust_level.as_deref() == Some("high_risk_step_up_required")
            }
            Some(_) => false,
        };
        if grant.grant_id.trim().is_empty()
            || grant.account_id != command.account_id
            || grant.device_id != command.device_id
            || grant.login_challenge_id != command.challenge_id
            || grant.issued_account_session_id != command.account_session.account_session_id
            || grant.protocol_version == 0
            || grant.issued_at_epoch_millis != command.now_epoch_millis
            || grant.expires_at_epoch_millis > challenge.expires_at_epoch_millis
            || !ttl.is_some_and(|ttl| ttl > 0 && ttl <= 300_000)
            || !unconsumed_shape
            || !trust_matches_factor
            || !constant_time_sha256_eq(
                &grant.device_public_key_fingerprint,
                &command.device_public_key_fingerprint,
            )
            || !constant_time_sha256_eq(
                &grant.login_challenge_binding_hash,
                &command.challenge_binding_hash,
            )
        {
            return Err(StoreError::Conflict);
        }
    }

    if let Some(trusted) = &command.trusted_device_to_create {
        let ttl = trusted
            .expires_at_epoch_millis
            .checked_sub(trusted.created_at_epoch_millis);
        let trust_shape_valid = matches!(
            (
                command.factor_kind.as_deref(),
                trusted.trust_proof_type.as_str(),
                trusted.trust_level.as_str(),
                ttl,
            ),
            (
                Some("totp"),
                "device_signature_and_mfa",
                "standard",
                Some(2_592_000_000)
            ) | (
                Some("recovery_code"),
                "device_signature_and_recovery_code",
                "high_risk_step_up_required",
                Some(86_400_000),
            )
        );
        if trusted.trusted_device_id.trim().is_empty()
            || trusted.account_id != command.account_id
            || trusted.controller_device_id != command.device_id
            || trusted.status != TrustedDeviceStatus::Active
            || trusted.created_at_epoch_millis != command.now_epoch_millis
            || trusted.last_used_at_epoch_millis.is_some()
            || trusted.revoked_at_epoch_millis.is_some()
            || !trust_shape_valid
            || !constant_time_sha256_eq(
                &trusted.device_fingerprint_hash,
                &command.device_public_key_fingerprint,
            )
        {
            return Err(StoreError::Conflict);
        }
    } else if command.factor_kind.is_some() && command.persistent_device_id.is_some() {
        return Err(StoreError::Conflict);
    }

    Ok(())
}

pub(crate) fn validate_login_finish_authority_binding(
    command: &LoginFinishCommand,
    challenge: &RiskChallenge,
    context: &LoginChallengeContext,
) -> Result<(), StoreError> {
    let expected_persistent_device_id =
        (context.device_state == LoginDeviceState::Registered).then(|| context.device_id.clone());
    if command.challenge_id != challenge.risk_challenge_id
        || command.account_id != challenge.account_id
        || command.persistent_device_id != challenge.device_id
        || command.persistent_device_id != expected_persistent_device_id
        || command.account_updated_at_epoch_millis != context.account_updated_at_epoch_millis
        || command.device_id != context.device_id
        || command.public_key_id != context.public_key_id
        || command.public_key_version != context.public_key_version
        || !constant_time_sha256_eq(
            &command.device_public_key_fingerprint,
            &context.device_public_key_fingerprint,
        )
        || !constant_time_sha256_eq(
            &command.challenge_binding_hash,
            &context.login_challenge_binding_hash,
        )
        || command.required_factors != context.required_factors
        || command.trusted_device_id_to_use != context.trusted_device_id
        || command
            .enrollment_grant
            .as_ref()
            .is_some_and(|grant| grant.protocol_version != context.protocol_version)
    {
        return Err(StoreError::Conflict);
    }
    Ok(())
}

pub(crate) fn risk_challenge_required_methods_are_valid(
    purpose: &str,
    required_methods: &[String],
) -> bool {
    let mfa_methods = ["totp", "recovery_code"];
    match purpose {
        "login_mfa" => required_methods.is_empty() || required_methods == mfa_methods,
        "password_change" => required_methods == ["password"] || required_methods == mfa_methods,
        _ => required_methods == mfa_methods,
    }
}

pub(crate) fn totp_enrollment_finish_binding_hash(
    account_id: &str,
    account_session_id: &str,
    factor_id: &str,
    idempotency_key_hash: &[u8; 32],
    client_ephemeral_public_key: &[u8; 32],
) -> [u8; 32] {
    sha256(&canonical_fields(
        "rctl-totp-enrollment-finish-v1",
        &[
            ("account_id", account_id.as_bytes()),
            ("account_session_id", account_session_id.as_bytes()),
            ("factor_id", factor_id.as_bytes()),
            ("idempotency_key_hash", idempotency_key_hash),
            ("client_ephemeral_public_key", client_ephemeral_public_key),
        ],
    ))
}

pub(crate) fn recovery_delivery_binding_is_valid(delivery: &RecoveryCodeDelivery) -> bool {
    constant_time_sha256_eq(
        &delivery.finish_request_binding_hash,
        &totp_enrollment_finish_binding_hash(
            &delivery.account_id,
            &delivery.account_session_id,
            &delivery.factor_id,
            &delivery.idempotency_key_hash,
            &delivery.client_ephemeral_public_key,
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashSet};
    use std::sync::Arc;

    use crate::model::*;
    use crate::security::{
        generate_totp_secret, hash_password, sha256, sign_device_request_for_test, totp_code,
    };

    fn issued_risk_challenge(id: &str) -> RiskChallenge {
        RiskChallenge {
            risk_challenge_id: id.to_owned(),
            account_id: "account-1".into(),
            device_id: Some("device-1".into()),
            purpose: "mfa_factor_change".into(),
            operation_binding_hash: [7; 32],
            risk_level: "high".into(),
            required_methods: vec!["totp".into(), "recovery_code".into()],
            status: RiskChallengeStatus::Issued,
            attempts_remaining: 5,
            ip_address: None,
            user_agent: Some("test-client".into()),
            expires_at_epoch_millis: 1_700_000_300_000,
            created_at_epoch_millis: 1_700_000_000_000,
            verified_at_epoch_millis: None,
            consumed_at_epoch_millis: None,
        }
    }

    fn risk_challenge_audit(id: &str) -> AuditEntry {
        AuditEntry {
            audit_id: format!("audit-{id}"),
            actor_type: "account".into(),
            actor_account_id: Some("account-1".into()),
            actor_device_id: Some("device-1".into()),
            actor_role: None,
            actor_service: None,
            target_device_id: Some("device-1".into()),
            session_id: None,
            action: "risk_challenge_issued".into(),
            result: "success".into(),
            reason: None,
            metadata: BTreeMap::new(),
            request_id: format!("request-{id}"),
            created_at_epoch_millis: 1_700_000_000_000,
        }
    }

    fn risk_challenge_cancelled_audit(id: &str) -> AuditEntry {
        let mut audit = risk_challenge_audit(id);
        audit.audit_id = format!("audit-cancelled-{id}");
        audit.action = "risk_challenge_failed".into();
        audit.result = "failure".into();
        audit.reason = Some("cancelled".into());
        audit
    }

    fn account_security_audit(id: &str, action: &str, result: &str, now: u64) -> AuditEntry {
        AuditEntry {
            audit_id: id.to_owned(),
            actor_type: "account".into(),
            actor_account_id: Some("account-1".into()),
            actor_device_id: None,
            actor_role: None,
            actor_service: None,
            target_device_id: Some("device-1".into()),
            session_id: None,
            action: action.into(),
            result: result.into(),
            reason: None,
            metadata: BTreeMap::new(),
            request_id: format!("request-{id}"),
            created_at_epoch_millis: now,
        }
    }

    fn active_account_session(id: &str, now: u64) -> AccountSession {
        AccountSession {
            account_session_id: id.to_owned(),
            account_id: "account-1".into(),
            refresh_token_hash: sha256(id.as_bytes()),
            mfa_verified: false,
            expires_at_epoch_millis: now + 300_000,
            revoked_at_epoch_millis: None,
            revoked_reason: None,
        }
    }

    fn active_account(now: u64) -> Account {
        Account {
            account_id: "account-1".into(),
            email: "account-1@example.com".into(),
            display_name: "Account One".into(),
            password_hash: "password-hash".into(),
            status: AccountStatus::Active,
            created_at_epoch_millis: now.saturating_sub(1),
            updated_at_epoch_millis: now.saturating_sub(1),
        }
    }

    fn pending_login_finish_command(now: u64) -> LoginFinishCommand {
        let challenge_id = "login-challenge-1".to_owned();
        let session = active_account_session("login-session-1", now);
        let device_public_key_fingerprint = sha256(&[1; 32]);
        LoginFinishCommand {
            challenge_id: challenge_id.clone(),
            account_id: "account-1".into(),
            account_updated_at_epoch_millis: now.saturating_sub(1),
            persistent_device_id: None,
            device_id: "pending-device-1".into(),
            public_key_id: None,
            public_key_version: 0,
            device_public_key_fingerprint,
            challenge_binding_hash: [7; 32],
            required_factors: Vec::new(),
            factor_kind: None,
            factor_code: None,
            trusted_device_id_to_use: None,
            account_session: session.clone(),
            enrollment_grant: Some(DeviceEnrollmentGrant {
                grant_id: "grant-1".into(),
                grant_secret_hash: [4; 32],
                account_id: "account-1".into(),
                device_id: "pending-device-1".into(),
                device_public_key_fingerprint,
                login_challenge_id: challenge_id,
                login_challenge_binding_hash: [7; 32],
                trust_proof_type: None,
                trust_level: None,
                establish_trust: false,
                protocol_version: 1,
                issued_account_session_id: session.account_session_id.clone(),
                issued_at_epoch_millis: now,
                expires_at_epoch_millis: now + 300_000,
                consumed_at_epoch_millis: None,
                registration_request_binding_hash: None,
                registered_public_key_id: None,
                registered_trusted_device_id: None,
            }),
            trusted_device_to_create: None,
            audit_entries: vec![
                account_security_audit(
                    "login-mfa-success",
                    "mfa_challenge_succeeded",
                    "success",
                    now,
                ),
                account_security_audit("login-success", "login_succeeded", "success", now),
            ],
            failure_audit_entry: account_security_audit(
                "login-failure",
                "mfa_challenge_failed",
                "failure",
                now,
            ),
            now_epoch_millis: now,
        }
    }

    fn pending_login_context(
        command: &LoginFinishCommand,
        challenge: &RiskChallenge,
    ) -> LoginChallengeContext {
        LoginChallengeContext {
            device_state: LoginDeviceState::PendingEnrollment,
            device_id: command.device_id.clone(),
            account_updated_at_epoch_millis: command.account_updated_at_epoch_millis,
            device_public_key: [1; 32],
            device_public_key_fingerprint: command.device_public_key_fingerprint,
            public_key_id: None,
            public_key_version: 0,
            client_nonce: [2; 32],
            server_nonce: [3; 32],
            login_request_binding_hash: [4; 32],
            login_challenge_binding_hash: command.challenge_binding_hash,
            ip_address_hash: [5; 32],
            user_agent_hash: [6; 32],
            required_factors: command.required_factors.clone(),
            trusted_device_id: None,
            protocol_version: 1,
            issued_at_epoch_millis: challenge.created_at_epoch_millis,
            attempts_limit: 5,
        }
    }

    #[test]
    fn login_finish_command_shape_is_shared_and_fail_closed() {
        let now = 1_700_000_000_000;
        let command = pending_login_finish_command(now);
        assert_eq!(validate_login_finish_command_shape(&command), Ok(()));

        let mut invalid_mfa_snapshot = command.clone();
        invalid_mfa_snapshot.account_session.mfa_verified = true;
        assert_eq!(
            validate_login_finish_command_shape(&invalid_mfa_snapshot),
            Err(StoreError::Conflict)
        );

        let mut missing_factor_code = command.clone();
        missing_factor_code.factor_kind = Some("totp".into());
        missing_factor_code.required_factors = vec!["totp".into(), "recovery_code".into()];
        missing_factor_code.account_session.mfa_verified = true;
        assert_eq!(
            validate_login_finish_command_shape(&missing_factor_code),
            Err(StoreError::Conflict)
        );

        let mut pending_trust_reuse = command.clone();
        pending_trust_reuse.trusted_device_id_to_use = Some("trust-1".into());
        pending_trust_reuse.account_session.mfa_verified = true;
        assert_eq!(
            validate_login_finish_command_shape(&pending_trust_reuse),
            Err(StoreError::Conflict)
        );

        let mut registered_with_grant = command.clone();
        registered_with_grant.persistent_device_id = Some(command.device_id.clone());
        assert_eq!(
            validate_login_finish_command_shape(&registered_with_grant),
            Err(StoreError::Conflict)
        );

        let mut revoked_session = command;
        revoked_session.account_session.revoked_at_epoch_millis = Some(now);
        revoked_session.account_session.revoked_reason = Some("password_changed".into());
        assert_eq!(
            validate_login_finish_command_shape(&revoked_session),
            Err(StoreError::Conflict)
        );
    }

    #[test]
    fn login_finish_artifacts_reject_cross_challenge_and_trust_escalation() {
        let now = 1_700_000_000_000;
        let command = pending_login_finish_command(now);
        let challenge = RiskChallenge {
            risk_challenge_id: command.challenge_id.clone(),
            account_id: command.account_id.clone(),
            device_id: None,
            purpose: "login_mfa".into(),
            operation_binding_hash: command.challenge_binding_hash,
            risk_level: "low".into(),
            required_methods: Vec::new(),
            status: RiskChallengeStatus::Issued,
            attempts_remaining: 5,
            ip_address: None,
            user_agent: None,
            expires_at_epoch_millis: now + 300_000,
            created_at_epoch_millis: now,
            verified_at_epoch_millis: None,
            consumed_at_epoch_millis: None,
        };
        assert_eq!(
            validate_login_finish_artifacts(&command, &challenge),
            Ok(())
        );

        let mut cross_challenge = command.clone();
        cross_challenge
            .enrollment_grant
            .as_mut()
            .expect("pending grant")
            .login_challenge_id = "another-challenge".into();
        assert_eq!(
            validate_login_finish_artifacts(&cross_challenge, &challenge),
            Err(StoreError::Conflict)
        );

        let mut trust_escalation = command.clone();
        let grant = trust_escalation
            .enrollment_grant
            .as_mut()
            .expect("pending grant");
        grant.establish_trust = true;
        grant.trust_proof_type = Some("device_signature_and_mfa".into());
        grant.trust_level = Some("standard".into());
        assert_eq!(
            validate_login_finish_artifacts(&trust_escalation, &challenge),
            Err(StoreError::Conflict)
        );

        let context = pending_login_context(&command, &challenge);
        assert_eq!(
            validate_login_finish_authority_binding(&command, &challenge, &context),
            Ok(())
        );
        let mut stale_snapshot = command.clone();
        stale_snapshot.account_updated_at_epoch_millis = stale_snapshot
            .account_updated_at_epoch_millis
            .saturating_add(1);
        assert_eq!(
            validate_login_finish_authority_binding(&stale_snapshot, &challenge, &context),
            Err(StoreError::Conflict)
        );
        let mut missing_success_audit = command;
        missing_success_audit
            .audit_entries
            .retain(|audit| audit.action != "mfa_challenge_succeeded");
        assert_eq!(
            validate_login_finish_artifacts(&missing_success_audit, &challenge),
            Err(StoreError::Conflict)
        );
    }

    fn authorizable_device(id: &str, account_id: &str, now: u64) -> Device {
        Device {
            device_id: id.to_owned(),
            account_id: account_id.to_owned(),
            display_name: "Test Device".into(),
            platform: Platform::Windows,
            os_version: "11".into(),
            arch: Architecture::X86_64,
            capabilities: DeviceCapabilities {
                controller: true,
                controlled: true,
                file_transfer: false,
                unattended: false,
            },
            public_key_id: format!("key-{id}"),
            public_key: [1; 32],
            public_key_version: 1,
            public_key_revoked_at_epoch_millis: None,
            status: DeviceLifecycleStatus::Offline,
            last_seen_epoch_millis: None,
            created_at_epoch_millis: now.saturating_sub(1),
            updated_at_epoch_millis: now.saturating_sub(1),
        }
    }

    fn consumed_login_challenge(id: &str, now: u64) -> RiskChallenge {
        RiskChallenge {
            risk_challenge_id: id.to_owned(),
            account_id: "account-1".into(),
            device_id: None,
            purpose: "login_mfa".into(),
            operation_binding_hash: [7; 32],
            risk_level: "low".into(),
            required_methods: Vec::new(),
            status: RiskChallengeStatus::Consumed,
            attempts_remaining: 5,
            ip_address: None,
            user_agent: None,
            expires_at_epoch_millis: now + 300_000,
            created_at_epoch_millis: now,
            verified_at_epoch_millis: Some(now),
            consumed_at_epoch_millis: Some(now),
        }
    }

    fn recovery_delivery(
        delivery_id: &str,
        factor_id: &str,
        session_id: &str,
        recovery_code_count: u16,
        now: u64,
    ) -> RecoveryCodeDelivery {
        let account_id = "account-1".to_owned();
        let account_session_id = session_id.to_owned();
        let factor_id = factor_id.to_owned();
        let idempotency_key_hash = sha256(delivery_id.as_bytes());
        let client_ephemeral_public_key = [3; 32];
        RecoveryCodeDelivery {
            delivery_id: delivery_id.to_owned(),
            finish_request_binding_hash: totp_enrollment_finish_binding_hash(
                &account_id,
                &account_session_id,
                &factor_id,
                &idempotency_key_hash,
                &client_ephemeral_public_key,
            ),
            account_id,
            account_session_id,
            factor_id,
            idempotency_key_hash,
            client_ephemeral_public_key,
            server_ephemeral_public_key: [4; 32],
            nonce: [5; 12],
            ciphertext: vec![6; 32],
            recovery_code_count,
            created_at_epoch_millis: now,
            expires_at_epoch_millis: now + 60_000,
            acknowledged_at_epoch_millis: None,
        }
    }

    fn create_session_command(tag: &str, storage_key: &str, binding: &str) -> CreateSessionCommand {
        let now = 1_700_000_000_000;
        let session = Session {
            session_id: format!("session-{tag}"),
            controller_account_id: "account-1".into(),
            controller_device_id: "controller-1".into(),
            controlled_device_id: "controlled-1".into(),
            auth_method: AuthMethod::AccountPrompt,
            status: SessionStatus::WaitingApproval,
            permissions: SessionPermissions {
                remote_desktop: true,
                require_prompt: true,
                ..SessionPermissions::default()
            },
            permissions_digest: "11".repeat(32),
            policy_evaluation_id: format!("policy-{tag}"),
            relay_token_epoch: 1,
            session_expires_at_epoch_millis: now + 300_000,
            created_at_epoch_millis: now,
            updated_at_epoch_millis: now,
            ended_at_epoch_millis: None,
        };
        CreateSessionCommand {
            storage_key: storage_key.into(),
            idempotency: IdempotencyRecord {
                account_id: "account-1".into(),
                device_id: "controller-1".into(),
                method: "POST".into(),
                path: "/v1/sessions".into(),
                operation: "create".into(),
                idempotency_key: "create-key".into(),
                body_hash: "22".repeat(32),
                request_id: format!("request-{tag}"),
                session_id: session.session_id.clone(),
                request_binding_hash: binding.into(),
                created_at_epoch_millis: now,
                expires_at_epoch_millis: now + 300_000,
            },
            event: SessionEvent {
                event_id: format!("event-{tag}"),
                session_id: session.session_id.clone(),
                event_type: "invite_created".into(),
                from_status: None,
                to_status: SessionStatus::WaitingApproval,
                actor_type: "device".into(),
                actor_account_id: Some("account-1".into()),
                actor_device_id: Some("controller-1".into()),
                actor_role: Some("controller".into()),
                reason: None,
                idempotency_key_hash: "33".repeat(32),
                request_id: format!("request-{tag}"),
                created_at_epoch_millis: now,
                result_session: Some(session.clone()),
            },
            policy_evaluation: PolicyEvaluation {
                policy_evaluation_id: session.policy_evaluation_id.clone(),
                session_id: session.session_id.clone(),
                account_id: "account-1".into(),
                controller_device_id: "controller-1".into(),
                controlled_device_id: "controlled-1".into(),
                access_decision: "allow".into(),
                anti_abuse_decision: "allow".into(),
                session_access_decision: "require_prompt".into(),
                effective_permissions: session.permissions,
                permissions_digest: session.permissions_digest.clone(),
                evaluated_at_epoch_millis: now,
            },
            audit_entry: AuditEntry {
                audit_id: format!("audit-{tag}"),
                actor_type: "device".into(),
                actor_account_id: Some("account-1".into()),
                actor_device_id: Some("controller-1".into()),
                actor_role: Some("controller".into()),
                actor_service: None,
                target_device_id: Some("controlled-1".into()),
                session_id: Some(session.session_id.clone()),
                action: "session_invited".into(),
                result: "success".into(),
                reason: None,
                metadata: BTreeMap::new(),
                request_id: format!("request-{tag}"),
                created_at_epoch_millis: now,
            },
            session,
        }
    }

    fn transition_session_command(
        tag: &str,
        storage_key: &str,
        binding: &str,
        current: &Session,
        target: SessionStatus,
        terminal: bool,
    ) -> TransitionSessionCommand {
        let now = current.updated_at_epoch_millis + 1;
        let mut session = current.clone();
        session.status = target;
        session.updated_at_epoch_millis = now;
        if terminal {
            session.ended_at_epoch_millis = Some(now);
            session.relay_token_epoch += 1;
        }
        TransitionSessionCommand {
            storage_key: storage_key.into(),
            expected_status: current.status,
            apply_allowed: true,
            idempotency: IdempotencyRecord {
                account_id: "account-1".into(),
                device_id: "controlled-1".into(),
                method: "POST".into(),
                path: format!("/v1/sessions/{}/accept", current.session_id),
                operation: format!("transition-{tag}"),
                idempotency_key: format!("key-{tag}"),
                body_hash: "44".repeat(32),
                request_id: format!("transition-request-{tag}"),
                session_id: current.session_id.clone(),
                request_binding_hash: binding.into(),
                created_at_epoch_millis: now,
                expires_at_epoch_millis: current.session_expires_at_epoch_millis,
            },
            event: SessionEvent {
                event_id: format!("transition-event-{tag}"),
                session_id: current.session_id.clone(),
                event_type: format!("transition-{tag}"),
                from_status: Some(current.status),
                to_status: target,
                actor_type: "device".into(),
                actor_account_id: Some("account-1".into()),
                actor_device_id: Some("controlled-1".into()),
                actor_role: Some("controlled".into()),
                reason: terminal.then(|| "done".into()),
                idempotency_key_hash: format!("hash-{tag}"),
                request_id: format!("transition-request-{tag}"),
                created_at_epoch_millis: now,
                result_session: Some(session.clone()),
            },
            audit_entry: AuditEntry {
                audit_id: format!("transition-audit-{tag}"),
                actor_type: "device".into(),
                actor_account_id: Some("account-1".into()),
                actor_device_id: Some("controlled-1".into()),
                actor_role: Some("controlled".into()),
                actor_service: None,
                target_device_id: Some("controlled-1".into()),
                session_id: Some(current.session_id.clone()),
                action: format!("session_{tag}"),
                result: "success".into(),
                reason: terminal.then(|| "done".into()),
                metadata: BTreeMap::new(),
                request_id: format!("transition-request-{tag}"),
                created_at_epoch_millis: now,
            },
            session,
        }
    }

    #[tokio::test]
    async fn memory_parallel_session_create_commits_one_graph_and_replays_original() {
        let repository = Arc::new(MemoryRepository::default());
        let first = create_session_command("first", "same-storage", "same-binding");
        let second = create_session_command("second", "same-storage", "same-binding");
        let (left, right) = tokio::join!(
            repository.create_session(&first),
            repository.create_session(&second)
        );
        let outcomes = [left.expect("first create"), right.expect("second create")];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, CreateSessionOutcome::Created(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, CreateSessionOutcome::Replayed(_)))
                .count(),
            1
        );
        let session_ids = outcomes
            .iter()
            .map(|outcome| match outcome {
                CreateSessionOutcome::Created(session)
                | CreateSessionOutcome::Replayed(session) => session.session_id.as_str(),
                CreateSessionOutcome::BindingMismatch => "",
            })
            .collect::<HashSet<_>>();
        assert_eq!(session_ids.len(), 1);
        repository
            .read(&mut |database| {
                assert_eq!(database.sessions.len(), 1);
                assert_eq!(database.session_idempotency.len(), 1);
                assert_eq!(database.policy_evaluations.len(), 1);
                assert_eq!(database.session_events.len(), 1);
                assert_eq!(database.audit_logs.len(), 1);
            })
            .await;

        let mismatch = create_session_command("mismatch", "same-storage", "other-binding");
        assert_eq!(
            repository.create_session(&mismatch).await,
            Ok(CreateSessionOutcome::BindingMismatch)
        );
    }

    #[tokio::test]
    async fn memory_parallel_session_transition_has_one_cas_winner_and_replays_event() {
        let repository = Arc::new(MemoryRepository::default());
        let create = create_session_command("base", "create-storage", "create-binding");
        let base = match repository.create_session(&create).await.expect("create") {
            CreateSessionOutcome::Created(session) => session,
            outcome => panic!("unexpected create outcome: {outcome:?}"),
        };
        let accepted = transition_session_command(
            "accepted",
            "accept-storage",
            "accept-binding",
            &base,
            SessionStatus::Accepted,
            false,
        );
        let rejected = transition_session_command(
            "rejected",
            "reject-storage",
            "reject-binding",
            &base,
            SessionStatus::Rejected,
            true,
        );
        let (left, right) = tokio::join!(
            repository.transition_session(&accepted),
            repository.transition_session(&rejected)
        );
        let outcomes = [left.expect("accept"), right.expect("reject")];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, TransitionSessionOutcome::Applied { .. }))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, TransitionSessionOutcome::StateConflict))
                .count(),
            1
        );
        let applied = if matches!(outcomes[0], TransitionSessionOutcome::Applied { .. }) {
            &accepted
        } else {
            &rejected
        };
        let original_event_id = match repository
            .transition_session(applied)
            .await
            .expect("replay transition")
        {
            TransitionSessionOutcome::Replayed { event_id, .. } => event_id,
            outcome => panic!("unexpected replay outcome: {outcome:?}"),
        };
        assert_eq!(original_event_id, applied.event.event_id);
        repository
            .read(&mut |database| {
                assert_eq!(database.sessions.len(), 1);
                assert_eq!(database.session_idempotency.len(), 2);
                assert_eq!(database.session_events.len(), 2);
                assert_eq!(database.audit_logs.len(), 2);
            })
            .await;
    }

    #[tokio::test]
    async fn memory_stale_transition_cannot_reopen_terminal_or_reduce_epoch() {
        let repository = MemoryRepository::default();
        let create = create_session_command("terminal", "create-terminal", "create-binding");
        let base = match repository.create_session(&create).await.expect("create") {
            CreateSessionOutcome::Created(session) => session,
            outcome => panic!("unexpected create outcome: {outcome:?}"),
        };
        let close = transition_session_command(
            "closed",
            "close-storage",
            "close-binding",
            &base,
            SessionStatus::Closed,
            true,
        );
        assert!(matches!(
            repository.transition_session(&close).await,
            Ok(TransitionSessionOutcome::Applied { .. })
        ));
        let stale = transition_session_command(
            "stale",
            "stale-storage",
            "stale-binding",
            &base,
            SessionStatus::Accepted,
            false,
        );
        assert_eq!(
            repository.transition_session(&stale).await,
            Ok(TransitionSessionOutcome::StateConflict)
        );
        assert_eq!(
            repository.load_session_authority(&base.session_id).await,
            Ok(Some(close.session))
        );
    }

    #[tokio::test]
    async fn memory_terminal_transition_increments_the_current_authority_epoch() {
        let repository = MemoryRepository::default();
        let create = create_session_command("epoch", "create-epoch", "create-binding");
        let base = match repository.create_session(&create).await.expect("create") {
            CreateSessionOutcome::Created(session) => session,
            outcome => panic!("unexpected create outcome: {outcome:?}"),
        };
        let close = transition_session_command(
            "close-after-rotation",
            "close-after-rotation",
            "close-binding",
            &base,
            SessionStatus::Closed,
            true,
        );
        repository
            .transact(&mut |database| {
                let session = database.sessions.get_mut(&base.session_id).unwrap();
                session.relay_token_epoch = 5;
                session.updated_at_epoch_millis += 10;
                Ok(())
            })
            .await
            .expect("simulate concurrent key rotation");

        let result = repository
            .transition_session(&close)
            .await
            .expect("close transition");
        let session = match result {
            TransitionSessionOutcome::Applied { session, .. } => session,
            outcome => panic!("unexpected close outcome: {outcome:?}"),
        };
        assert_eq!(session.status, SessionStatus::Closed);
        assert_eq!(session.relay_token_epoch, 6);
        assert!(session.updated_at_epoch_millis >= base.updated_at_epoch_millis + 10);
    }

    #[tokio::test]
    async fn memory_transition_replay_returns_the_original_result_snapshot() {
        let repository = MemoryRepository::default();
        let create = create_session_command("snapshot", "create-snapshot", "create-binding");
        let waiting = match repository.create_session(&create).await.expect("create") {
            CreateSessionOutcome::Created(session) => session,
            outcome => panic!("unexpected create outcome: {outcome:?}"),
        };
        let accept = transition_session_command(
            "snapshot-accept",
            "snapshot-accept",
            "accept-binding",
            &waiting,
            SessionStatus::Accepted,
            false,
        );
        let accepted = match repository
            .transition_session(&accept)
            .await
            .expect("accept")
        {
            TransitionSessionOutcome::Applied { session, .. } => session,
            outcome => panic!("unexpected accept outcome: {outcome:?}"),
        };
        let connected = transition_session_command(
            "snapshot-connected",
            "snapshot-connected",
            "connected-binding",
            &accepted,
            SessionStatus::Connected,
            false,
        );
        assert!(matches!(
            repository.transition_session(&connected).await,
            Ok(TransitionSessionOutcome::Applied { .. })
        ));

        let replay = repository
            .transition_session(&accept)
            .await
            .expect("replay accept");
        match replay {
            TransitionSessionOutcome::Replayed { session, event_id } => {
                assert_eq!(session.status, SessionStatus::Accepted);
                assert_eq!(event_id, accept.event.event_id);
            }
            outcome => panic!("unexpected replay outcome: {outcome:?}"),
        }
    }

    #[tokio::test]
    async fn memory_repository_commits_transaction() {
        let repository = MemoryRepository::default();
        repository
            .transact(&mut |database| {
                database
                    .account_by_email
                    .insert("a@example.com".into(), "id".into());
                Ok(())
            })
            .await
            .expect("transaction");

        let mut found = false;
        repository
            .read(&mut |database| found = database.account_by_email.contains_key("a@example.com"))
            .await;
        assert!(found);
    }

    #[tokio::test]
    async fn memory_repository_rolls_back_failed_transaction() {
        let repository = MemoryRepository::default();
        let result = repository
            .transact(&mut |database| {
                database
                    .account_by_email
                    .insert("rollback@example.com".into(), "rollback-account".into());
                Err(StoreError::Conflict)
            })
            .await;
        assert_eq!(result, Err(StoreError::Conflict));

        let mut found = false;
        repository
            .read(&mut |database| {
                found = database
                    .account_by_email
                    .contains_key("rollback@example.com")
            })
            .await;
        assert!(!found);
    }

    #[tokio::test]
    async fn memory_risk_challenge_create_and_cancel_are_atomic_and_terminal() {
        let repository = MemoryRepository::default();
        let mut challenge = issued_risk_challenge("risk-1");
        challenge.required_methods.clear();
        let audit_entry = risk_challenge_audit("risk-1");
        let cancelled_audit = risk_challenge_cancelled_audit("risk-1");
        let mut invalid_cancelled_audit = cancelled_audit.clone();
        invalid_cancelled_audit.audit_id = "audit-invalid-cancelled-risk-1".into();
        invalid_cancelled_audit.reason = None;
        let mut unsupported_new_device_challenge = issued_risk_challenge("risk-new-device");
        unsupported_new_device_challenge.device_id = None;
        unsupported_new_device_challenge.purpose = "new_controller_device".into();
        unsupported_new_device_challenge.required_methods.clear();

        repository
            .transact(&mut |database| {
                database.accounts.insert(
                    "account-1".into(),
                    Account {
                        account_id: "account-1".into(),
                        email: "account-1@example.com".into(),
                        display_name: "Account One".into(),
                        password_hash: "password-hash".into(),
                        status: AccountStatus::Active,
                        created_at_epoch_millis: 1_699_999_999_999,
                        updated_at_epoch_millis: 1_699_999_999_999,
                    },
                );
                database.devices.insert(
                    "device-1".into(),
                    authorizable_device("device-1", "account-1", 1_700_000_000_000),
                );
                database.mfa_factors.insert(
                    "factor-1".into(),
                    MfaFactor {
                        factor_id: "factor-1".into(),
                        account_id: "account-1".into(),
                        secret_base32: "JBSWY3DPEHPK3PXP".into(),
                        active: true,
                        last_used_counter: None,
                        created_at_epoch_millis: 1_699_999_999_999,
                    },
                );
                Ok(())
            })
            .await
            .expect("seed risk challenge authority");

        let created = repository
            .create_risk_challenge(&challenge, &audit_entry)
            .await
            .expect("create risk challenge");
        match created {
            RiskChallengeCreationOutcome::Created(challenge) => assert_eq!(
                challenge.required_methods,
                vec!["totp".to_owned(), "recovery_code".to_owned()]
            ),
            outcome => panic!("unexpected risk challenge outcome: {outcome:?}"),
        }
        assert_eq!(
            repository
                .create_risk_challenge(
                    &unsupported_new_device_challenge,
                    &risk_challenge_audit("risk-new-device"),
                )
                .await,
            Err(StoreError::Conflict)
        );
        assert_eq!(
            repository
                .create_risk_challenge(&challenge, &audit_entry)
                .await,
            Err(StoreError::Conflict)
        );
        assert_eq!(
            repository
                .cancel_risk_challenge(&challenge.risk_challenge_id, &invalid_cancelled_audit)
                .await,
            Err(StoreError::Conflict)
        );
        assert_eq!(
            repository
                .load_risk_challenge_authority(&challenge.risk_challenge_id)
                .await
                .expect("load issued risk challenge")
                .expect("risk challenge")
                .status,
            RiskChallengeStatus::Issued
        );
        assert_eq!(
            repository
                .cancel_risk_challenge(&challenge.risk_challenge_id, &cancelled_audit)
                .await,
            Ok(true)
        );
        assert_eq!(
            repository
                .cancel_risk_challenge(&challenge.risk_challenge_id, &cancelled_audit)
                .await,
            Ok(false)
        );
        assert_eq!(
            repository
                .load_risk_challenge_authority(&challenge.risk_challenge_id)
                .await
                .expect("load cancelled risk challenge")
                .expect("risk challenge")
                .status,
            RiskChallengeStatus::Cancelled
        );
        repository
            .transact(&mut |database| {
                database.mfa_factors.clear();
                Ok(())
            })
            .await
            .expect("disable seeded MFA factor");
        let mut password_challenge = issued_risk_challenge("risk-password");
        password_challenge.purpose = "password_change".into();
        password_challenge.required_methods.clear();
        let password_outcome = repository
            .create_risk_challenge(&password_challenge, &risk_challenge_audit("risk-password"))
            .await
            .expect("create password reauthentication challenge");
        match password_outcome {
            RiskChallengeCreationOutcome::Created(challenge) => {
                assert_eq!(challenge.required_methods, vec!["password".to_owned()]);
            }
            outcome => panic!("unexpected password challenge outcome: {outcome:?}"),
        }
        let mut mfa_required_challenge = issued_risk_challenge("risk-mfa-required");
        mfa_required_challenge.purpose = "mfa_factor_change".into();
        mfa_required_challenge.required_methods.clear();
        assert_eq!(
            repository
                .create_risk_challenge(
                    &mfa_required_challenge,
                    &risk_challenge_audit("risk-mfa-required"),
                )
                .await,
            Ok(RiskChallengeCreationOutcome::MfaEnrollmentRequired)
        );
        assert!(repository
            .load_risk_challenge_authority("risk-mfa-required")
            .await
            .expect("load missing MFA challenge")
            .is_none());
        repository
            .read(&mut |database| {
                assert!(database
                    .audit_logs
                    .iter()
                    .any(|entry| entry.audit_id == cancelled_audit.audit_id));
            })
            .await;
    }

    #[tokio::test]
    async fn memory_login_finish_rejects_challenge_after_account_security_change() {
        let repository = MemoryRepository::default();
        let now = 1_700_000_000_000;
        let command = pending_login_finish_command(now);
        let mut account = active_account(now.saturating_sub(100));
        account.updated_at_epoch_millis = now.saturating_sub(50);
        let challenge = RiskChallenge {
            risk_challenge_id: command.challenge_id.clone(),
            account_id: command.account_id.clone(),
            device_id: None,
            purpose: "login_mfa".into(),
            operation_binding_hash: command.challenge_binding_hash,
            risk_level: "low".into(),
            required_methods: Vec::new(),
            status: RiskChallengeStatus::Issued,
            attempts_remaining: 5,
            ip_address: None,
            user_agent: None,
            expires_at_epoch_millis: now + 300_000,
            created_at_epoch_millis: now.saturating_sub(100),
            verified_at_epoch_millis: None,
            consumed_at_epoch_millis: None,
        };
        let context = pending_login_context(&command, &challenge);
        repository
            .transact(&mut |database| {
                database
                    .accounts
                    .insert(account.account_id.clone(), account.clone());
                database
                    .risk_challenges
                    .insert(challenge.risk_challenge_id.clone(), challenge.clone());
                database
                    .login_challenge_contexts
                    .insert(challenge.risk_challenge_id.clone(), context.clone());
                Ok(())
            })
            .await
            .expect("seed stale login challenge");

        assert_eq!(
            repository.finish_login(&command).await,
            Ok(LoginFinishOutcome::Rejected)
        );
        repository
            .read(&mut |database| {
                let challenge = &database.risk_challenges[&command.challenge_id];
                assert_eq!(challenge.status, RiskChallengeStatus::Issued);
                assert_eq!(challenge.attempts_remaining, 4);
                assert!(database.account_sessions.is_empty());
                assert!(database.device_enrollment_grants.is_empty());
                assert_eq!(database.audit_logs.len(), 1);
                assert_eq!(
                    database.audit_logs[0].reason.as_deref(),
                    Some("account_security_changed")
                );
            })
            .await;
    }

    #[tokio::test]
    async fn memory_login_finish_rejects_changed_device_authority_inside_repository() {
        let repository = MemoryRepository::default();
        let now = 1_700_000_000_000;
        let command = pending_login_finish_command(now);
        let challenge = RiskChallenge {
            risk_challenge_id: command.challenge_id.clone(),
            account_id: command.account_id.clone(),
            device_id: None,
            purpose: "login_mfa".into(),
            operation_binding_hash: command.challenge_binding_hash,
            risk_level: "low".into(),
            required_methods: Vec::new(),
            status: RiskChallengeStatus::Issued,
            attempts_remaining: 5,
            ip_address: None,
            user_agent: None,
            expires_at_epoch_millis: now + 300_000,
            created_at_epoch_millis: now.saturating_sub(100),
            verified_at_epoch_millis: None,
            consumed_at_epoch_millis: None,
        };
        let context = pending_login_context(&command, &challenge);
        repository
            .transact(&mut |database| {
                database
                    .accounts
                    .insert(command.account_id.clone(), active_account(now));
                database.devices.insert(
                    command.device_id.clone(),
                    authorizable_device(&command.device_id, &command.account_id, now),
                );
                database
                    .risk_challenges
                    .insert(challenge.risk_challenge_id.clone(), challenge.clone());
                database
                    .login_challenge_contexts
                    .insert(challenge.risk_challenge_id.clone(), context.clone());
                Ok(())
            })
            .await
            .expect("seed changed pending device authority");

        assert_eq!(
            repository.finish_login(&command).await,
            Ok(LoginFinishOutcome::Rejected)
        );
        repository
            .read(&mut |database| {
                let challenge = &database.risk_challenges[&command.challenge_id];
                assert_eq!(challenge.status, RiskChallengeStatus::Issued);
                assert_eq!(challenge.attempts_remaining, 4);
                assert!(database.account_sessions.is_empty());
                assert_eq!(database.audit_logs.len(), 1);
                assert_eq!(
                    database.audit_logs[0].reason.as_deref(),
                    Some("device_authority_changed")
                );
            })
            .await;
    }

    #[tokio::test]
    async fn memory_login_finish_audits_replaced_trust_and_rolls_back_audit_conflict() {
        fn fixture(
            now: u64,
        ) -> (
            LoginFinishCommand,
            RiskChallenge,
            LoginChallengeContext,
            Device,
            MfaFactor,
            TrustedControllerDevice,
        ) {
            let secret = generate_totp_secret();
            let (code, _) = totp_code(&secret, now).expect("TOTP code");
            let device = authorizable_device("device-1", "account-1", now);
            let mut command = pending_login_finish_command(now);
            command.persistent_device_id = Some(device.device_id.clone());
            command.device_id = device.device_id.clone();
            command.public_key_id = Some(device.public_key_id.clone());
            command.public_key_version = device.public_key_version;
            command.device_public_key_fingerprint = sha256(&device.public_key);
            command.required_factors = vec!["totp".into(), "recovery_code".into()];
            command.factor_kind = Some("totp".into());
            command.factor_code = Some(code);
            command.account_session.mfa_verified = true;
            command.enrollment_grant = None;
            command.trusted_device_to_create = Some(TrustedControllerDevice {
                trusted_device_id: "new-trust".into(),
                account_id: command.account_id.clone(),
                controller_device_id: device.device_id.clone(),
                device_fingerprint_hash: command.device_public_key_fingerprint,
                trust_level: "standard".into(),
                status: TrustedDeviceStatus::Active,
                trust_proof_type: "device_signature_and_mfa".into(),
                created_at_epoch_millis: now,
                last_used_at_epoch_millis: None,
                expires_at_epoch_millis: now + 2_592_000_000,
                revoked_at_epoch_millis: None,
            });
            command.audit_entries.push(account_security_audit(
                "trusted-device-added",
                "trusted_device_added",
                "success",
                now,
            ));
            let challenge = RiskChallenge {
                risk_challenge_id: command.challenge_id.clone(),
                account_id: command.account_id.clone(),
                device_id: Some(device.device_id.clone()),
                purpose: "login_mfa".into(),
                operation_binding_hash: command.challenge_binding_hash,
                risk_level: "low".into(),
                required_methods: command.required_factors.clone(),
                status: RiskChallengeStatus::Issued,
                attempts_remaining: 5,
                ip_address: None,
                user_agent: None,
                expires_at_epoch_millis: now + 300_000,
                created_at_epoch_millis: now,
                verified_at_epoch_millis: None,
                consumed_at_epoch_millis: None,
            };
            let context = LoginChallengeContext {
                device_state: LoginDeviceState::Registered,
                device_id: device.device_id.clone(),
                account_updated_at_epoch_millis: command.account_updated_at_epoch_millis,
                device_public_key: device.public_key,
                device_public_key_fingerprint: command.device_public_key_fingerprint,
                public_key_id: Some(device.public_key_id.clone()),
                public_key_version: device.public_key_version,
                client_nonce: [2; 32],
                server_nonce: [3; 32],
                login_request_binding_hash: [4; 32],
                login_challenge_binding_hash: command.challenge_binding_hash,
                ip_address_hash: [5; 32],
                user_agent_hash: [6; 32],
                required_factors: command.required_factors.clone(),
                trusted_device_id: None,
                protocol_version: 1,
                issued_at_epoch_millis: now,
                attempts_limit: 5,
            };
            let factor = MfaFactor {
                factor_id: "factor-1".into(),
                account_id: command.account_id.clone(),
                secret_base32: secret,
                active: true,
                last_used_counter: None,
                created_at_epoch_millis: now.saturating_sub(1),
            };
            let old_trust = TrustedControllerDevice {
                trusted_device_id: "old-trust".into(),
                account_id: command.account_id.clone(),
                controller_device_id: device.device_id.clone(),
                device_fingerprint_hash: command.device_public_key_fingerprint,
                trust_level: "standard".into(),
                status: TrustedDeviceStatus::Active,
                trust_proof_type: "device_signature_and_mfa".into(),
                created_at_epoch_millis: now.saturating_sub(1),
                last_used_at_epoch_millis: None,
                expires_at_epoch_millis: now + 60_000,
                revoked_at_epoch_millis: None,
            };
            (command, challenge, context, device, factor, old_trust)
        }

        let now = 1_700_000_000_000;
        let (command, challenge, context, device, factor, old_trust) = fixture(now);
        let repository = MemoryRepository::default();
        repository
            .transact(&mut |database| {
                database
                    .accounts
                    .insert(command.account_id.clone(), active_account(now));
                database
                    .devices
                    .insert(device.device_id.clone(), device.clone());
                database
                    .mfa_factors
                    .insert(factor.factor_id.clone(), factor.clone());
                database
                    .risk_challenges
                    .insert(challenge.risk_challenge_id.clone(), challenge.clone());
                database
                    .login_challenge_contexts
                    .insert(challenge.risk_challenge_id.clone(), context.clone());
                database
                    .trusted_controller_devices
                    .insert(old_trust.trusted_device_id.clone(), old_trust.clone());
                Ok(())
            })
            .await
            .expect("seed login trust refresh");

        assert_eq!(
            repository.finish_login(&command).await,
            Ok(LoginFinishOutcome::Completed)
        );
        repository
            .read(&mut |database| {
                let old = &database.trusted_controller_devices["old-trust"];
                assert_eq!(old.status, TrustedDeviceStatus::Revoked);
                assert_eq!(old.revoked_at_epoch_millis, Some(now));
                assert_eq!(
                    database.trusted_controller_devices["new-trust"].status,
                    TrustedDeviceStatus::Active
                );
                let audit = database
                    .audit_logs
                    .iter()
                    .find(|entry| {
                        entry.action == "trusted_device_revoked"
                            && entry.metadata["trusted_device_id"] == "old-trust"
                    })
                    .expect("old trust revocation audit");
                assert_eq!(audit.reason.as_deref(), Some("refreshed"));
            })
            .await;

        let (command, challenge, context, device, factor, old_trust) = fixture(now);
        let repository = MemoryRepository::default();
        let trust_added_audit = command
            .audit_entries
            .iter()
            .find(|entry| entry.action == "trusted_device_added")
            .expect("trusted-device added audit");
        let conflicting_audit = trusted_device_revocation_audit(
            trust_added_audit,
            &old_trust.trusted_device_id,
            &old_trust.controller_device_id,
            "refreshed",
        );
        repository
            .transact(&mut |database| {
                database
                    .accounts
                    .insert(command.account_id.clone(), active_account(now));
                database
                    .devices
                    .insert(device.device_id.clone(), device.clone());
                database
                    .mfa_factors
                    .insert(factor.factor_id.clone(), factor.clone());
                database
                    .risk_challenges
                    .insert(challenge.risk_challenge_id.clone(), challenge.clone());
                database
                    .login_challenge_contexts
                    .insert(challenge.risk_challenge_id.clone(), context.clone());
                database
                    .trusted_controller_devices
                    .insert(old_trust.trusted_device_id.clone(), old_trust.clone());
                database.audit_logs.push(conflicting_audit.clone());
                Ok(())
            })
            .await
            .expect("seed trust audit conflict");
        assert_eq!(
            repository.finish_login(&command).await,
            Err(StoreError::Conflict)
        );
        repository
            .read(&mut |database| {
                assert_eq!(
                    database.trusted_controller_devices["old-trust"].status,
                    TrustedDeviceStatus::Active
                );
                assert!(!database
                    .trusted_controller_devices
                    .contains_key("new-trust"));
                assert!(!database
                    .account_sessions
                    .contains_key(&command.account_session.account_session_id));
                assert_eq!(
                    database.risk_challenges[&command.challenge_id].status,
                    RiskChallengeStatus::Issued
                );
                assert!(database.mfa_factors["factor-1"].last_used_counter.is_none());
            })
            .await;
    }

    #[tokio::test]
    async fn memory_login_finish_trusted_device_use_does_not_extend_fixed_ttl() {
        let repository = MemoryRepository::default();
        let now = 1_700_000_000_000;
        let device = authorizable_device("device-1", "account-1", now);
        let mut command = pending_login_finish_command(now);
        command.persistent_device_id = Some(device.device_id.clone());
        command.device_id = device.device_id.clone();
        command.public_key_id = Some(device.public_key_id.clone());
        command.public_key_version = device.public_key_version;
        command.device_public_key_fingerprint = sha256(&device.public_key);
        command.trusted_device_id_to_use = Some("fixed-trust".into());
        command.account_session.mfa_verified = true;
        command.enrollment_grant = None;
        let fixed_expiry = now + 60_000;
        let trusted = TrustedControllerDevice {
            trusted_device_id: "fixed-trust".into(),
            account_id: command.account_id.clone(),
            controller_device_id: device.device_id.clone(),
            device_fingerprint_hash: command.device_public_key_fingerprint,
            trust_level: "standard".into(),
            status: TrustedDeviceStatus::Active,
            trust_proof_type: "device_signature_and_mfa".into(),
            created_at_epoch_millis: now.saturating_sub(1),
            last_used_at_epoch_millis: None,
            expires_at_epoch_millis: fixed_expiry,
            revoked_at_epoch_millis: None,
        };
        let challenge = RiskChallenge {
            risk_challenge_id: command.challenge_id.clone(),
            account_id: command.account_id.clone(),
            device_id: Some(device.device_id.clone()),
            purpose: "login_mfa".into(),
            operation_binding_hash: command.challenge_binding_hash,
            risk_level: "low".into(),
            required_methods: Vec::new(),
            status: RiskChallengeStatus::Issued,
            attempts_remaining: 5,
            ip_address: None,
            user_agent: None,
            expires_at_epoch_millis: now + 300_000,
            created_at_epoch_millis: now,
            verified_at_epoch_millis: None,
            consumed_at_epoch_millis: None,
        };
        let context = LoginChallengeContext {
            device_state: LoginDeviceState::Registered,
            device_id: device.device_id.clone(),
            account_updated_at_epoch_millis: command.account_updated_at_epoch_millis,
            device_public_key: device.public_key,
            device_public_key_fingerprint: command.device_public_key_fingerprint,
            public_key_id: Some(device.public_key_id.clone()),
            public_key_version: device.public_key_version,
            client_nonce: [2; 32],
            server_nonce: [3; 32],
            login_request_binding_hash: [4; 32],
            login_challenge_binding_hash: command.challenge_binding_hash,
            ip_address_hash: [5; 32],
            user_agent_hash: [6; 32],
            required_factors: Vec::new(),
            trusted_device_id: Some(trusted.trusted_device_id.clone()),
            protocol_version: 1,
            issued_at_epoch_millis: now,
            attempts_limit: 5,
        };
        repository
            .transact(&mut |database| {
                database
                    .accounts
                    .insert(command.account_id.clone(), active_account(now));
                database
                    .devices
                    .insert(device.device_id.clone(), device.clone());
                database.mfa_factors.insert(
                    "factor-1".into(),
                    MfaFactor {
                        factor_id: "factor-1".into(),
                        account_id: command.account_id.clone(),
                        secret_base32: generate_totp_secret(),
                        active: true,
                        last_used_counter: None,
                        created_at_epoch_millis: now.saturating_sub(1),
                    },
                );
                database
                    .risk_challenges
                    .insert(challenge.risk_challenge_id.clone(), challenge.clone());
                database
                    .login_challenge_contexts
                    .insert(challenge.risk_challenge_id.clone(), context.clone());
                database
                    .trusted_controller_devices
                    .insert(trusted.trusted_device_id.clone(), trusted.clone());
                Ok(())
            })
            .await
            .expect("seed fixed trust login");

        assert_eq!(
            repository.finish_login(&command).await,
            Ok(LoginFinishOutcome::Completed)
        );
        repository
            .read(&mut |database| {
                let trusted = &database.trusted_controller_devices["fixed-trust"];
                assert_eq!(trusted.last_used_at_epoch_millis, Some(now));
                assert_eq!(trusted.expires_at_epoch_millis, fixed_expiry);
                assert_eq!(trusted.status, TrustedDeviceStatus::Active);
                assert!(
                    database.account_sessions[&command.account_session.account_session_id]
                        .mfa_verified
                );
            })
            .await;
    }

    #[tokio::test]
    async fn memory_device_registration_is_atomic_and_rejects_duplicate_identity() {
        let repository = MemoryRepository::default();
        let now = 1_700_000_000_000;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let public_key = signing_key.verifying_key().to_bytes();
        let device = Device {
            device_id: "device-1".into(),
            account_id: "account-1".into(),
            display_name: "Device".into(),
            platform: Platform::Windows,
            os_version: "11".into(),
            arch: Architecture::X86_64,
            capabilities: DeviceCapabilities {
                controller: true,
                controlled: true,
                file_transfer: false,
                unattended: false,
            },
            public_key_id: "key-1".into(),
            public_key,
            public_key_version: 1,
            public_key_revoked_at_epoch_millis: None,
            status: DeviceLifecycleStatus::Offline,
            last_seen_epoch_millis: None,
            created_at_epoch_millis: now,
            updated_at_epoch_millis: now,
        };
        let registration_audit_entry = AuditEntry {
            audit_id: "audit-1".into(),
            actor_type: "device".into(),
            actor_account_id: Some("account-1".into()),
            actor_device_id: Some("device-1".into()),
            actor_role: Some("none".into()),
            actor_service: None,
            target_device_id: Some("device-1".into()),
            session_id: None,
            action: "device_registered".into(),
            result: "success".into(),
            reason: None,
            metadata: BTreeMap::new(),
            request_id: "request-1".into(),
            created_at_epoch_millis: now,
        };
        let grant_audit_entry = AuditEntry {
            audit_id: "audit-grant-1".into(),
            action: "device_enrollment_grant_consumed".into(),
            ..registration_audit_entry.clone()
        };
        let trust_audit_entry = AuditEntry {
            audit_id: "audit-trust-candidate".into(),
            action: "trusted_device_added".into(),
            ..registration_audit_entry.clone()
        };
        let session = active_account_session("account-session-1", now);
        let grant = DeviceEnrollmentGrant {
            grant_id: "grant-1".into(),
            grant_secret_hash: sha256(b"grant-secret-1"),
            account_id: "account-1".into(),
            device_id: device.device_id.clone(),
            device_public_key_fingerprint: sha256(&device.public_key),
            login_challenge_id: "login-challenge-1".into(),
            login_challenge_binding_hash: [7; 32],
            trust_proof_type: None,
            trust_level: None,
            establish_trust: false,
            protocol_version: 1,
            issued_account_session_id: session.account_session_id.clone(),
            issued_at_epoch_millis: now,
            expires_at_epoch_millis: now + 300_000,
            consumed_at_epoch_millis: None,
            registration_request_binding_hash: None,
            registered_public_key_id: None,
            registered_trusted_device_id: None,
        };
        repository
            .transact(&mut |database| {
                database
                    .account_sessions
                    .insert(session.account_session_id.clone(), session.clone());
                let challenge = consumed_login_challenge(&grant.login_challenge_id, now);
                database
                    .risk_challenges
                    .insert(challenge.risk_challenge_id.clone(), challenge);
                database
                    .device_enrollment_grants
                    .insert(grant.grant_id.clone(), grant.clone());
                Ok(())
            })
            .await
            .expect("seed registration authority");
        let registration_binding_for = |device: &Device| {
            device_registration_binding_hash(
                "account-1",
                &session.account_session_id,
                &grant.grant_id,
                &device.device_id,
                &device.display_name,
                registration_platform_name(&device.platform),
                &device.os_version,
                registration_architecture_name(&device.arch),
                device.capabilities.controller,
                device.capabilities.controlled,
                device.capabilities.file_transfer,
                device.capabilities.unattended,
                &sha256(&device.public_key),
                1,
            )
        };
        let registration_request_binding_hash = registration_binding_for(&device);
        let command = DeviceRegistrationCommand {
            grant_id: grant.grant_id.clone(),
            grant_secret_hash: grant.grant_secret_hash,
            account_id: "account-1".into(),
            account_session_id: session.account_session_id.clone(),
            protocol_version: 1,
            registration_request_binding_hash,
            device: device.clone(),
            trusted_device_id: Some("ignored-trust-candidate".into()),
            registration_audit_entry: registration_audit_entry.clone(),
            grant_audit_entry: grant_audit_entry.clone(),
            trusted_device_audit_entry: Some(trust_audit_entry),
            signature_proof: InitialDeviceSignatureProof {
                target: "/v1/devices".into(),
                content_type: Some("application/json".into()),
                request_id: "request-1".into(),
                timestamp_epoch_millis: now,
                nonce: "nonce-1".into(),
                signature: sign_device_request_for_test(
                    &signing_key,
                    "POST",
                    "/v1/devices",
                    b"{}",
                    "request-1",
                    "device-1",
                    "account-1",
                    now,
                    "nonce-1",
                ),
                canonical_body: b"{}".to_vec(),
            },
            now_epoch_millis: now,
        };

        let mut desktop_without_controlled = command.clone();
        desktop_without_controlled.device.capabilities.controlled = false;
        desktop_without_controlled.registration_request_binding_hash =
            registration_binding_for(&desktop_without_controlled.device);
        assert_eq!(
            validate_device_registration_authority(
                &Database::default(),
                &desktop_without_controlled,
                &grant,
            ),
            Ok(())
        );
        let mut ubuntu_aarch64 = desktop_without_controlled.clone();
        ubuntu_aarch64.device.platform = Platform::Ubuntu;
        ubuntu_aarch64.device.arch = Architecture::Aarch64;
        ubuntu_aarch64.registration_request_binding_hash =
            registration_binding_for(&ubuntu_aarch64.device);
        assert_eq!(
            validate_device_registration_authority(&Database::default(), &ubuntu_aarch64, &grant),
            Err(StoreError::Conflict)
        );

        let mut cross_account_device = command.clone();
        cross_account_device.device.account_id = "account-2".into();
        assert_eq!(
            repository.register_device(&cross_account_device).await,
            Err(StoreError::Conflict)
        );

        repository
            .transact(&mut |database| {
                let grant = database
                    .device_enrollment_grants
                    .get_mut("grant-1")
                    .ok_or(StoreError::Unavailable)?;
                grant.establish_trust = true;
                grant.trust_proof_type = Some("device_signature_and_mfa".into());
                grant.trust_level = Some("standard".into());
                Ok(())
            })
            .await
            .expect("enable trust on non-MFA grant");
        assert_eq!(
            repository.register_device(&command).await,
            Ok(DeviceRegistrationOutcome::InvalidGrant)
        );
        repository
            .transact(&mut |database| {
                let grant = database
                    .device_enrollment_grants
                    .get_mut("grant-1")
                    .ok_or(StoreError::Unavailable)?;
                grant.establish_trust = false;
                grant.trust_proof_type = None;
                grant.trust_level = None;
                database.audit_logs.push(registration_audit_entry.clone());
                Ok(())
            })
            .await
            .expect("seed registration audit conflict");
        assert_eq!(
            repository.register_device(&command).await,
            Err(StoreError::Conflict)
        );
        repository
            .transact(&mut |database| {
                database
                    .audit_logs
                    .retain(|audit| audit.audit_id != registration_audit_entry.audit_id);
                Ok(())
            })
            .await
            .expect("remove registration audit conflict");
        repository
            .read(&mut |database| {
                assert!(database.devices.is_empty());
                assert!(database.device_public_keys.is_empty());
                assert!(database.trusted_controller_devices.is_empty());
                assert!(database.audit_logs.is_empty());
                assert!(database.device_enrollment_grants["grant-1"]
                    .consumed_at_epoch_millis
                    .is_none());
            })
            .await;

        assert_eq!(
            repository.register_device(&command).await,
            Ok(DeviceRegistrationOutcome::Created(device.clone()))
        );
        let mut replay_device = device.clone();
        replay_device.public_key_id = "retry-generated-key-id".into();
        replay_device.created_at_epoch_millis = now + 1;
        replay_device.updated_at_epoch_millis = now + 1;
        let replay_command = DeviceRegistrationCommand {
            device: replay_device,
            trusted_device_id: Some("retry-generated-trust-id".into()),
            registration_audit_entry: AuditEntry {
                audit_id: "audit-retry".into(),
                request_id: "request-retry".into(),
                created_at_epoch_millis: now + 1,
                ..command.registration_audit_entry.clone()
            },
            grant_audit_entry: AuditEntry {
                audit_id: "audit-grant-retry".into(),
                request_id: "request-retry".into(),
                created_at_epoch_millis: now + 1,
                ..command.grant_audit_entry.clone()
            },
            trusted_device_audit_entry: command.trusted_device_audit_entry.as_ref().map(|audit| {
                AuditEntry {
                    audit_id: "audit-trust-retry".into(),
                    request_id: "request-retry".into(),
                    created_at_epoch_millis: now + 1,
                    ..audit.clone()
                }
            }),
            signature_proof: InitialDeviceSignatureProof {
                target: "/v1/devices".into(),
                content_type: Some("application/json".into()),
                request_id: "request-retry".into(),
                timestamp_epoch_millis: now + 1,
                nonce: "nonce-retry".into(),
                signature: sign_device_request_for_test(
                    &signing_key,
                    "POST",
                    "/v1/devices",
                    b"{}",
                    "request-retry",
                    "device-1",
                    "account-1",
                    now + 1,
                    "nonce-retry",
                ),
                canonical_body: b"{}".to_vec(),
            },
            now_epoch_millis: now + 1,
            ..command.clone()
        };
        assert_eq!(
            repository.register_device(&replay_command).await,
            Ok(DeviceRegistrationOutcome::Replayed(device.clone()))
        );
        repository
            .transact(&mut |database| {
                let old_key = database
                    .device_public_keys
                    .get_mut("key-1")
                    .ok_or(StoreError::Unavailable)?;
                old_key.revoked_at_epoch_millis = Some(now + 2);
                let current = database
                    .devices
                    .get_mut("device-1")
                    .ok_or(StoreError::Unavailable)?;
                current.display_name = "Renamed after registration".into();
                current.capabilities.controlled = false;
                current.public_key_id = "key-rotated".into();
                current.public_key = [2; 32];
                current.public_key_version = 2;
                current.public_key_revoked_at_epoch_millis = Some(now + 3);
                current.status = DeviceLifecycleStatus::Unbound;
                current.updated_at_epoch_millis = now + 3;
                database.device_public_keys.insert(
                    "key-rotated".into(),
                    DevicePublicKeyRecord {
                        public_key_id: "key-rotated".into(),
                        device_id: "device-1".into(),
                        public_key: [2; 32],
                        version: 2,
                        created_at_epoch_millis: now + 2,
                        revoked_at_epoch_millis: Some(now + 3),
                    },
                );
                Ok(())
            })
            .await
            .expect("mutate registered device authority");
        let immutable_replay = DeviceRegistrationCommand {
            registration_audit_entry: AuditEntry {
                audit_id: "audit-immutable-retry".into(),
                request_id: "request-immutable-retry".into(),
                created_at_epoch_millis: now + 4,
                ..replay_command.registration_audit_entry.clone()
            },
            grant_audit_entry: AuditEntry {
                audit_id: "audit-grant-immutable-retry".into(),
                request_id: "request-immutable-retry".into(),
                created_at_epoch_millis: now + 4,
                ..replay_command.grant_audit_entry.clone()
            },
            trusted_device_audit_entry: replay_command.trusted_device_audit_entry.as_ref().map(
                |audit| AuditEntry {
                    audit_id: "audit-trust-immutable-retry".into(),
                    request_id: "request-immutable-retry".into(),
                    created_at_epoch_millis: now + 4,
                    ..audit.clone()
                },
            ),
            signature_proof: InitialDeviceSignatureProof {
                target: "/v1/devices".into(),
                content_type: Some("application/json".into()),
                request_id: "request-immutable-retry".into(),
                timestamp_epoch_millis: now + 4,
                nonce: "nonce-immutable-retry".into(),
                signature: sign_device_request_for_test(
                    &signing_key,
                    "POST",
                    "/v1/devices",
                    b"{}",
                    "request-immutable-retry",
                    "device-1",
                    "account-1",
                    now + 4,
                    "nonce-immutable-retry",
                ),
                canonical_body: b"{}".to_vec(),
            },
            now_epoch_millis: now + 4,
            ..replay_command.clone()
        };
        assert_eq!(
            repository.register_device(&immutable_replay).await,
            Ok(DeviceRegistrationOutcome::Replayed(device.clone()))
        );
        repository
            .read(&mut |database| {
                let current = &database.devices["device-1"];
                assert_eq!(current.display_name, "Renamed after registration");
                assert_eq!(current.status, DeviceLifecycleStatus::Unbound);
                assert_eq!(current.public_key_id, "key-rotated");
                assert_eq!(database.audit_logs.len(), 2);
                let result = database.audit_logs[0]
                    .metadata
                    .get(DEVICE_REGISTRATION_RESULT_METADATA_KEY)
                    .and_then(serde_json::Value::as_object)
                    .expect("registration result snapshot");
                assert!(!result.contains_key("public_key"));
                assert!(!result.contains_key("grant_secret"));
                assert!(!result.contains_key("signature"));
                assert!(!result.contains_key("nonce"));
            })
            .await;
        let mut changed_business_fields = immutable_replay.clone();
        changed_business_fields.device.display_name = "Different registration".into();
        changed_business_fields.registration_request_binding_hash =
            registration_binding_for(&changed_business_fields.device);
        assert_eq!(
            repository.register_device(&changed_business_fields).await,
            Err(StoreError::Conflict)
        );
        assert_eq!(
            repository
                .register_device(&DeviceRegistrationCommand {
                    registration_request_binding_hash: [9; 32],
                    ..replay_command.clone()
                })
                .await,
            Err(StoreError::Conflict)
        );
        repository
            .transact(&mut |database| {
                database
                    .devices
                    .insert(device.device_id.clone(), device.clone());
                database.device_public_keys.remove("key-rotated");
                database
                    .device_public_keys
                    .get_mut("key-1")
                    .ok_or(StoreError::Unavailable)?
                    .revoked_at_epoch_millis = None;
                Ok(())
            })
            .await
            .expect("restore duplicate identity test authority");
        repository
            .read(&mut |database| {
                assert!(database.trusted_controller_devices.is_empty());
                let consumed = &database.device_enrollment_grants["grant-1"];
                assert_eq!(consumed.registered_public_key_id.as_deref(), Some("key-1"));
                assert!(consumed.registered_trusted_device_id.is_none());
                assert_eq!(
                    consumed.registration_request_binding_hash,
                    Some(registration_request_binding_hash)
                );
            })
            .await;

        let mut duplicate_key = device.clone();
        duplicate_key.device_id = "device-2".into();
        let duplicate_grant = DeviceEnrollmentGrant {
            grant_id: "grant-2".into(),
            grant_secret_hash: sha256(b"grant-secret-2"),
            device_id: duplicate_key.device_id.clone(),
            login_challenge_id: "login-challenge-2".into(),
            ..grant
        };
        repository
            .transact(&mut |database| {
                let challenge = consumed_login_challenge(&duplicate_grant.login_challenge_id, now);
                database
                    .risk_challenges
                    .insert(challenge.risk_challenge_id.clone(), challenge);
                database
                    .device_enrollment_grants
                    .insert(duplicate_grant.grant_id.clone(), duplicate_grant.clone());
                Ok(())
            })
            .await
            .expect("seed duplicate identity grant");
        let duplicate_command = DeviceRegistrationCommand {
            grant_id: duplicate_grant.grant_id.clone(),
            grant_secret_hash: duplicate_grant.grant_secret_hash,
            device: duplicate_key,
            registration_audit_entry: AuditEntry {
                audit_id: "audit-2".into(),
                ..registration_audit_entry
            },
            grant_audit_entry: AuditEntry {
                audit_id: "audit-grant-2".into(),
                ..grant_audit_entry
            },
            signature_proof: InitialDeviceSignatureProof {
                target: "/v1/devices".into(),
                content_type: Some("application/json".into()),
                request_id: "request-2".into(),
                timestamp_epoch_millis: now,
                nonce: "nonce-2".into(),
                signature: sign_device_request_for_test(
                    &signing_key,
                    "POST",
                    "/v1/devices",
                    b"{}",
                    "request-2",
                    "device-2",
                    "account-1",
                    now,
                    "nonce-2",
                ),
                canonical_body: b"{}".to_vec(),
            },
            ..command
        };
        assert_eq!(
            repository.register_device(&duplicate_command).await,
            Err(StoreError::Conflict)
        );
        repository
            .read(&mut |database| {
                assert_eq!(database.devices.len(), 1);
                assert_eq!(database.device_public_keys.len(), 1);
                assert_eq!(database.audit_logs.len(), 2);
                assert!(!database.devices.contains_key("device-2"));
            })
            .await;
    }

    #[tokio::test]
    async fn memory_risk_challenge_verification_is_authoritative_and_device_bound() {
        let repository = MemoryRepository::default();
        let now = 1_700_000_000_000;
        let password_hash = hash_password("correct horse battery staple").expect("password hash");
        repository
            .transact(&mut |database| {
                database.accounts.insert(
                    "account-1".into(),
                    Account {
                        account_id: "account-1".into(),
                        email: "account-1@example.com".into(),
                        display_name: "Account One".into(),
                        password_hash: password_hash.clone(),
                        status: AccountStatus::Active,
                        created_at_epoch_millis: now - 1,
                        updated_at_epoch_millis: now - 1,
                    },
                );
                database.devices.insert(
                    "device-1".into(),
                    authorizable_device("device-1", "account-1", now),
                );
                database.risk_challenges.insert(
                    "password-challenge".into(),
                    RiskChallenge {
                        risk_challenge_id: "password-challenge".into(),
                        account_id: "account-1".into(),
                        device_id: Some("device-1".into()),
                        purpose: "password_change".into(),
                        operation_binding_hash: [9; 32],
                        risk_level: "high".into(),
                        required_methods: vec!["password".into()],
                        status: RiskChallengeStatus::Issued,
                        attempts_remaining: 5,
                        ip_address: None,
                        user_agent: None,
                        expires_at_epoch_millis: now + 60_000,
                        created_at_epoch_millis: now - 1,
                        verified_at_epoch_millis: None,
                        consumed_at_epoch_millis: None,
                    },
                );
                Ok(())
            })
            .await
            .expect("seed password challenge");

        let downgrade = RiskChallengeVerification {
            challenge_id: "password-challenge".into(),
            account_id: "account-1".into(),
            factor_kind: "totp".into(),
            factor_code: "123456".into(),
            success_audit_entry: account_security_audit(
                "downgrade-success",
                "risk_challenge_succeeded",
                "success",
                now,
            ),
            failure_audit_entry: account_security_audit(
                "downgrade-failure",
                "risk_challenge_failed",
                "failure",
                now,
            ),
            recovery_code_audit_entry: None,
            now_epoch_millis: now,
        };
        assert_eq!(
            repository.verify_risk_challenge(&downgrade).await,
            Ok(RiskChallengeVerificationOutcome::Rejected)
        );
        repository
            .read(&mut |database| {
                assert_eq!(
                    database.risk_challenges["password-challenge"].attempts_remaining,
                    4
                );
                assert!(database
                    .audit_logs
                    .iter()
                    .any(|entry| entry.audit_id == "downgrade-failure"));
            })
            .await;

        let verified = RiskChallengeVerification {
            challenge_id: "password-challenge".into(),
            account_id: "account-1".into(),
            factor_kind: "password".into(),
            factor_code: "correct horse battery staple".into(),
            success_audit_entry: account_security_audit(
                "password-success",
                "risk_challenge_succeeded",
                "success",
                now,
            ),
            failure_audit_entry: account_security_audit(
                "password-failure",
                "risk_challenge_failed",
                "failure",
                now,
            ),
            recovery_code_audit_entry: None,
            now_epoch_millis: now,
        };
        assert!(matches!(
            repository.verify_risk_challenge(&verified).await,
            Ok(RiskChallengeVerificationOutcome::Verified(_))
        ));
        let retry = RiskChallengeVerification {
            success_audit_entry: account_security_audit(
                "retry-success",
                "risk_challenge_succeeded",
                "success",
                now,
            ),
            failure_audit_entry: account_security_audit(
                "retry-failure",
                "risk_challenge_failed",
                "failure",
                now,
            ),
            ..verified.clone()
        };
        assert!(matches!(
            repository.verify_risk_challenge(&retry).await,
            Ok(RiskChallengeVerificationOutcome::AlreadyVerified(_))
        ));
        repository
            .transact(&mut |database| {
                database
                    .devices
                    .get_mut("device-1")
                    .ok_or(StoreError::Unavailable)?
                    .status = DeviceLifecycleStatus::Disabled;
                Ok(())
            })
            .await
            .expect("disable step-up device");
        assert_eq!(
            repository.verify_risk_challenge(&retry).await,
            Ok(RiskChallengeVerificationOutcome::Rejected)
        );
        assert_eq!(
            repository
                .apply_step_up_action(
                    &StepUpExpectation {
                        challenge_id: "password-challenge".into(),
                        account_id: "account-1".into(),
                        device_id: "device-1".into(),
                        purpose: "password_change".into(),
                        operation_binding_hash: [9; 32],
                        now_epoch_millis: now,
                    },
                    &StepUpAction::ChangePassword {
                        expected_password_hash: password_hash,
                        new_password_hash: "new-password-hash".into(),
                        audit_entry: account_security_audit(
                            "password-changed",
                            "password_changed",
                            "success",
                            now,
                        ),
                    },
                )
                .await,
            Err(StoreError::Conflict)
        );
    }

    #[tokio::test]
    async fn memory_refresh_rotation_writes_object_audit_and_preserves_mfa_snapshot() {
        let repository = MemoryRepository::default();
        let now = 1_700_000_000_000;
        let old_hash = sha256(b"old-refresh");
        let mut old_session = active_account_session("old-session", now);
        old_session.refresh_token_hash = old_hash;
        old_session.mfa_verified = true;
        repository
            .transact(&mut |database| {
                database
                    .accounts
                    .insert("account-1".into(), active_account(now));
                database
                    .account_sessions
                    .insert(old_session.account_session_id.clone(), old_session.clone());
                Ok(())
            })
            .await
            .expect("seed refresh authority");
        let mut replacement = active_account_session("replacement-session", now);
        replacement.refresh_token_hash = sha256(b"replacement-refresh");
        replacement.mfa_verified = true;
        let refresh_audit =
            account_security_audit("refresh-audit", "token_refreshed", "success", now);

        assert!(repository
            .rotate_refresh_session(&old_hash, &replacement, &refresh_audit, now)
            .await
            .expect("rotate refresh session"));
        repository
            .read(&mut |database| {
                let old = &database.account_sessions["old-session"];
                assert_eq!(old.revoked_at_epoch_millis, Some(now));
                assert_eq!(old.revoked_reason.as_deref(), Some("refresh_replay"));
                assert!(database.account_sessions["replacement-session"].mfa_verified);
                let object_audits = database
                    .audit_logs
                    .iter()
                    .filter(|entry| entry.action == "account_session_revoked")
                    .collect::<Vec<_>>();
                assert_eq!(object_audits.len(), 1);
                assert_eq!(object_audits[0].reason.as_deref(), Some("refresh_replay"));
                assert_eq!(
                    object_audits[0].metadata["account_session_id"],
                    serde_json::Value::String("old-session".into())
                );
                assert_eq!(
                    database
                        .audit_logs
                        .iter()
                        .filter(|entry| entry.action == "token_refreshed")
                        .count(),
                    1
                );
            })
            .await;
    }

    #[tokio::test]
    async fn memory_refresh_rotation_rolls_back_when_object_audit_conflicts() {
        let repository = MemoryRepository::default();
        let now = 1_700_000_000_000;
        let old_hash = sha256(b"old-refresh");
        let mut old_session = active_account_session("old-session", now);
        old_session.refresh_token_hash = old_hash;
        let replacement = active_account_session("replacement-session", now);
        let refresh_audit =
            account_security_audit("refresh-audit", "token_refreshed", "success", now);
        let conflicting_audit = account_session_revocation_audit(
            &refresh_audit,
            &old_session.account_session_id,
            "refresh_replay",
        );
        repository
            .transact(&mut |database| {
                database
                    .accounts
                    .insert("account-1".into(), active_account(now));
                database
                    .account_sessions
                    .insert(old_session.account_session_id.clone(), old_session.clone());
                database.audit_logs.push(conflicting_audit.clone());
                Ok(())
            })
            .await
            .expect("seed conflicting refresh audit");

        assert_eq!(
            repository
                .rotate_refresh_session(&old_hash, &replacement, &refresh_audit, now)
                .await,
            Err(StoreError::Conflict)
        );
        repository
            .read(&mut |database| {
                let old = &database.account_sessions["old-session"];
                assert!(old.revoked_at_epoch_millis.is_none());
                assert!(old.revoked_reason.is_none());
                assert!(!database
                    .account_sessions
                    .contains_key("replacement-session"));
                assert!(!database
                    .audit_logs
                    .iter()
                    .any(|entry| entry.action == "token_refreshed"));
            })
            .await;
    }

    #[tokio::test]
    async fn memory_refresh_rotation_cannot_resurrect_a_revoked_account_session() {
        let repository = MemoryRepository::default();
        let now = 1_700_000_000_000;
        let old_hash = sha256(b"old-refresh");
        repository
            .transact(&mut |database| {
                database.accounts.insert(
                    "account-1".into(),
                    Account {
                        account_id: "account-1".into(),
                        email: "account-1@example.com".into(),
                        display_name: "Account One".into(),
                        password_hash: "password-hash".into(),
                        status: AccountStatus::Active,
                        created_at_epoch_millis: now - 1,
                        updated_at_epoch_millis: now - 1,
                    },
                );
                database.account_sessions.insert(
                    "old-session".into(),
                    AccountSession {
                        account_session_id: "old-session".into(),
                        account_id: "account-1".into(),
                        refresh_token_hash: old_hash,
                        mfa_verified: false,
                        expires_at_epoch_millis: now + 60_000,
                        revoked_at_epoch_millis: None,
                        revoked_reason: None,
                    },
                );
                Ok(())
            })
            .await
            .expect("seed refresh session");
        assert!(repository
            .load_refresh_session_authority(&old_hash, now)
            .await
            .expect("load refresh authority")
            .is_some());
        repository
            .transact(&mut |database| {
                let session = database
                    .account_sessions
                    .get_mut("old-session")
                    .ok_or(StoreError::Unavailable)?;
                session.revoked_at_epoch_millis = Some(now);
                session.revoked_reason = Some("password_changed".into());
                Ok(())
            })
            .await
            .expect("revoke account sessions");
        let replacement = AccountSession {
            account_session_id: "replacement-session".into(),
            account_id: "account-1".into(),
            refresh_token_hash: sha256(b"replacement-refresh"),
            mfa_verified: false,
            expires_at_epoch_millis: now + 60_000,
            revoked_at_epoch_millis: None,
            revoked_reason: None,
        };
        assert!(!repository
            .rotate_refresh_session(
                &old_hash,
                &replacement,
                &account_security_audit("refresh-audit", "token_refreshed", "success", now,),
                now,
            )
            .await
            .expect("stale refresh rotation"));
        repository
            .read(&mut |database| {
                assert!(!database
                    .account_sessions
                    .contains_key("replacement-session"));
                assert_eq!(
                    database.account_sessions["old-session"]
                        .revoked_reason
                        .as_deref(),
                    Some("password_changed")
                );
            })
            .await;
    }

    #[tokio::test]
    async fn memory_logout_rolls_back_session_when_object_audit_conflicts() {
        let repository = MemoryRepository::default();
        let now = 1_700_000_000_000;
        let session = active_account_session("logout-session", now);
        let logout_audit = account_security_audit("logout-audit", "logout", "success", now);
        let conflicting_audit =
            account_session_revocation_audit(&logout_audit, &session.account_session_id, "logout");
        repository
            .transact(&mut |database| {
                database
                    .account_sessions
                    .insert(session.account_session_id.clone(), session.clone());
                database.audit_logs.push(conflicting_audit.clone());
                Ok(())
            })
            .await
            .expect("seed logout authority");

        assert_eq!(
            repository
                .revoke_account_session(
                    &session.account_session_id,
                    &session.account_id,
                    now,
                    &logout_audit,
                )
                .await,
            Err(StoreError::Conflict)
        );
        repository
            .read(&mut |database| {
                assert!(database.account_sessions[&session.account_session_id]
                    .revoked_at_epoch_millis
                    .is_none());
                assert_eq!(database.audit_logs, vec![conflicting_audit.clone()]);
            })
            .await;

        repository
            .transact(&mut |database| {
                database
                    .audit_logs
                    .retain(|entry| entry.audit_id != conflicting_audit.audit_id);
                Ok(())
            })
            .await
            .expect("remove injected logout conflict");
        assert_eq!(
            repository
                .revoke_account_session(
                    &session.account_session_id,
                    &session.account_id,
                    now,
                    &logout_audit,
                )
                .await,
            Ok(true)
        );
        repository
            .read(&mut |database| {
                assert_eq!(
                    database.account_sessions[&session.account_session_id]
                        .revoked_reason
                        .as_deref(),
                    Some("logout")
                );
                assert_eq!(database.audit_logs.len(), 2);
            })
            .await;
    }

    #[tokio::test]
    async fn memory_totp_enrollment_commits_factor_recovery_codes_and_audit_once() {
        let repository = MemoryRepository::default();
        let now = 1_700_000_000_000;
        let session = active_account_session("account-session-1", now);
        let trusted = TrustedControllerDevice {
            trusted_device_id: "trusted-1".into(),
            account_id: "account-1".into(),
            controller_device_id: "device-1".into(),
            device_fingerprint_hash: [9; 32],
            trust_level: "standard".into(),
            status: TrustedDeviceStatus::Active,
            trust_proof_type: "device_signature_and_mfa".into(),
            created_at_epoch_millis: now - 1,
            last_used_at_epoch_millis: None,
            expires_at_epoch_millis: now + 300_000,
            revoked_at_epoch_millis: None,
        };
        repository
            .transact(&mut |database| {
                database
                    .accounts
                    .insert("account-1".into(), active_account(now));
                database
                    .account_sessions
                    .insert(session.account_session_id.clone(), session.clone());
                database
                    .trusted_controller_devices
                    .insert(trusted.trusted_device_id.clone(), trusted.clone());
                Ok(())
            })
            .await
            .expect("seed MFA revocation authority");
        let completion = TotpEnrollmentCompletion {
            factor: MfaFactor {
                factor_id: "factor-1".into(),
                account_id: "account-1".into(),
                secret_base32: "JBSWY3DPEHPK3PXP".into(),
                active: true,
                last_used_counter: Some(42),
                created_at_epoch_millis: now,
            },
            recovery_codes: vec![
                RecoveryCode {
                    recovery_code_id: "recovery-1".into(),
                    account_id: "account-1".into(),
                    code_hash: [1; 32],
                    used_at_epoch_millis: None,
                    expires_at_epoch_millis: None,
                },
                RecoveryCode {
                    recovery_code_id: "recovery-2".into(),
                    account_id: "account-1".into(),
                    code_hash: [2; 32],
                    used_at_epoch_millis: None,
                    expires_at_epoch_millis: None,
                },
            ],
            delivery: recovery_delivery(
                "delivery-1",
                "factor-1",
                &session.account_session_id,
                2,
                now,
            ),
            audit_entry: AuditEntry {
                audit_id: "audit-1".into(),
                actor_type: "account".into(),
                actor_account_id: Some("account-1".into()),
                actor_device_id: None,
                actor_role: None,
                actor_service: None,
                target_device_id: None,
                session_id: None,
                action: "mfa_factor_enrolled".into(),
                result: "success".into(),
                reason: None,
                metadata: BTreeMap::new(),
                request_id: "request-1".into(),
                created_at_epoch_millis: now,
            },
        };

        repository
            .finish_totp_enrollment(&completion)
            .await
            .expect("finish enrollment");
        assert_eq!(
            repository.finish_totp_enrollment(&completion).await,
            Err(StoreError::Conflict)
        );
        let replay_lookup = TotpEnrollmentReplayLookup {
            account_id: completion.delivery.account_id.clone(),
            account_session_id: completion.delivery.account_session_id.clone(),
            factor_id: completion.delivery.factor_id.clone(),
            idempotency_key_hash: completion.delivery.idempotency_key_hash,
            finish_request_binding_hash: Some(completion.delivery.finish_request_binding_hash),
            client_ephemeral_public_key: Some(completion.delivery.client_ephemeral_public_key),
            access_token_expires_at_epoch_millis: now + 300_000,
            now_epoch_millis: now + 1,
        };
        assert_eq!(
            repository
                .replay_totp_enrollment(&replay_lookup)
                .await
                .expect("replay exact enrollment delivery"),
            TotpEnrollmentReplayOutcome::Replayed(Box::new(completion.delivery.clone()))
        );

        let mut mismatched_lookups = Vec::new();
        let mut different_session = replay_lookup.clone();
        different_session.account_session_id = "different-session".into();
        mismatched_lookups.push(different_session);
        let mut different_factor = replay_lookup.clone();
        different_factor.factor_id = "different-factor".into();
        mismatched_lookups.push(different_factor);
        let mut different_binding = replay_lookup.clone();
        different_binding.finish_request_binding_hash = Some([7; 32]);
        mismatched_lookups.push(different_binding);
        let mut different_client_key = replay_lookup;
        different_client_key.client_ephemeral_public_key = Some([8; 32]);
        mismatched_lookups.push(different_client_key);
        for lookup in mismatched_lookups {
            assert_eq!(
                repository
                    .replay_totp_enrollment(&lookup)
                    .await
                    .expect("reject changed enrollment replay binding"),
                TotpEnrollmentReplayOutcome::BindingMismatch
            );
        }
        repository
            .read(&mut |database| {
                assert_eq!(database.mfa_factors.len(), 1);
                assert_eq!(database.recovery_codes.len(), 2);
                assert_eq!(database.recovery_code_deliveries.len(), 1);
                assert_eq!(database.audit_logs.len(), 3);
                assert_eq!(
                    database
                        .audit_logs
                        .iter()
                        .filter(|entry| entry.action == "account_session_revoked")
                        .count(),
                    1
                );
                assert_eq!(
                    database
                        .audit_logs
                        .iter()
                        .filter(|entry| entry.action == "trusted_device_revoked")
                        .count(),
                    1
                );
                assert!(database.mfa_factors["factor-1"].active);
                assert_eq!(database.mfa_factors["factor-1"].last_used_counter, Some(42));
                assert_eq!(
                    database.account_sessions[&session.account_session_id]
                        .revoked_reason
                        .as_deref(),
                    Some("mfa_enabled")
                );
                assert_eq!(
                    database.trusted_controller_devices["trusted-1"].status,
                    TrustedDeviceStatus::Revoked
                );
            })
            .await;
    }

    #[tokio::test]
    async fn memory_totp_enrollment_rejects_invalid_recovery_batch_without_partial_state() {
        let repository = MemoryRepository::default();
        let now = 1_700_000_000_000;
        let session = active_account_session("account-session-1", now);
        repository
            .transact(&mut |database| {
                database
                    .account_sessions
                    .insert(session.account_session_id.clone(), session.clone());
                Ok(())
            })
            .await
            .expect("seed MFA session");
        let completion = TotpEnrollmentCompletion {
            factor: MfaFactor {
                factor_id: "factor-1".into(),
                account_id: "account-1".into(),
                secret_base32: "JBSWY3DPEHPK3PXP".into(),
                active: true,
                last_used_counter: Some(42),
                created_at_epoch_millis: now,
            },
            recovery_codes: vec![
                RecoveryCode {
                    recovery_code_id: "duplicate".into(),
                    account_id: "account-1".into(),
                    code_hash: [1; 32],
                    used_at_epoch_millis: None,
                    expires_at_epoch_millis: None,
                },
                RecoveryCode {
                    recovery_code_id: "duplicate".into(),
                    account_id: "account-1".into(),
                    code_hash: [2; 32],
                    used_at_epoch_millis: None,
                    expires_at_epoch_millis: None,
                },
            ],
            delivery: recovery_delivery(
                "delivery-1",
                "factor-1",
                &session.account_session_id,
                2,
                now,
            ),
            audit_entry: AuditEntry {
                audit_id: "audit-1".into(),
                actor_type: "account".into(),
                actor_account_id: Some("account-1".into()),
                actor_device_id: None,
                actor_role: None,
                actor_service: None,
                target_device_id: None,
                session_id: None,
                action: "mfa_factor_enrolled".into(),
                result: "success".into(),
                reason: None,
                metadata: BTreeMap::new(),
                request_id: "request-1".into(),
                created_at_epoch_millis: now,
            },
        };

        assert_eq!(
            repository.finish_totp_enrollment(&completion).await,
            Err(StoreError::Conflict)
        );
        repository
            .read(&mut |database| {
                assert!(database.mfa_factors.is_empty());
                assert!(database.recovery_codes.is_empty());
                assert!(database.audit_logs.is_empty());
            })
            .await;
    }

    #[tokio::test]
    async fn memory_repository_consumes_totp_and_recovery_codes_once() {
        let repository = MemoryRepository::default();
        let now = 1_700_000_000_000;
        let secret = generate_totp_secret();
        let (code, _) = totp_code(&secret, now).expect("TOTP code");
        let recovery_plaintext = "recovery-code";
        let expired_recovery_plaintext = "expired-recovery-code";
        repository
            .transact(&mut |database| {
                database.mfa_factors.insert(
                    "factor-1".into(),
                    MfaFactor {
                        factor_id: "factor-1".into(),
                        account_id: "account-1".into(),
                        secret_base32: secret.clone(),
                        active: true,
                        last_used_counter: None,
                        created_at_epoch_millis: now - 1,
                    },
                );
                database.recovery_codes.insert(
                    "recovery-1".into(),
                    RecoveryCode {
                        recovery_code_id: "recovery-1".into(),
                        account_id: "account-1".into(),
                        code_hash: sha256(recovery_plaintext.as_bytes()),
                        used_at_epoch_millis: None,
                        expires_at_epoch_millis: None,
                    },
                );
                database.recovery_codes.insert(
                    "recovery-expired".into(),
                    RecoveryCode {
                        recovery_code_id: "recovery-expired".into(),
                        account_id: "account-1".into(),
                        code_hash: sha256(expired_recovery_plaintext.as_bytes()),
                        used_at_epoch_millis: None,
                        expires_at_epoch_millis: Some(now),
                    },
                );
                database.risk_challenges.insert(
                    "challenge-1".into(),
                    RiskChallenge {
                        risk_challenge_id: "challenge-1".into(),
                        account_id: "account-1".into(),
                        device_id: Some("device-1".into()),
                        purpose: "device_key_rotation".into(),
                        operation_binding_hash: [7; 32],
                        risk_level: "high".into(),
                        required_methods: vec!["totp".into(), "recovery_code".into()],
                        status: RiskChallengeStatus::Issued,
                        attempts_remaining: 5,
                        ip_address: None,
                        user_agent: None,
                        expires_at_epoch_millis: now + 60_000,
                        created_at_epoch_millis: now - 1,
                        verified_at_epoch_millis: None,
                        consumed_at_epoch_millis: None,
                    },
                );
                Ok(())
            })
            .await
            .expect("seed MFA state");

        assert!(repository
            .verify_factor(Some("challenge-1"), "account-1", "totp", &code, now,)
            .await
            .expect("verify TOTP"));
        assert!(!repository
            .verify_factor(None, "account-1", "totp", &code, now)
            .await
            .expect("reject reused TOTP"));
        assert!(repository
            .verify_factor(None, "account-1", "recovery_code", recovery_plaintext, now,)
            .await
            .expect("consume recovery code"));
        assert!(!repository
            .verify_factor(None, "account-1", "recovery_code", recovery_plaintext, now,)
            .await
            .expect("reject reused recovery code"));
        assert!(!repository
            .verify_factor(
                None,
                "account-1",
                "recovery_code",
                expired_recovery_plaintext,
                now,
            )
            .await
            .expect("reject expired recovery code"));
    }

    #[tokio::test]
    async fn memory_step_up_action_commits_target_and_audit_once() {
        let repository = MemoryRepository::default();
        let now = 1_700_000_000_000;
        repository
            .transact(&mut |database| {
                database.devices.insert(
                    "device-1".into(),
                    authorizable_device("device-1", "account-1", now),
                );
                database.risk_challenges.insert(
                    "challenge-1".into(),
                    RiskChallenge {
                        risk_challenge_id: "challenge-1".into(),
                        account_id: "account-1".into(),
                        device_id: Some("device-1".into()),
                        purpose: "recovery_code_rotate".into(),
                        operation_binding_hash: [6; 32],
                        risk_level: "high".into(),
                        required_methods: vec!["totp".into(), "recovery_code".into()],
                        status: RiskChallengeStatus::Verified,
                        attempts_remaining: 5,
                        ip_address: None,
                        user_agent: None,
                        expires_at_epoch_millis: now + 60_000,
                        created_at_epoch_millis: now - 1,
                        verified_at_epoch_millis: Some(now - 1),
                        consumed_at_epoch_millis: None,
                    },
                );
                database.recovery_codes.insert(
                    "old-code".into(),
                    RecoveryCode {
                        recovery_code_id: "old-code".into(),
                        account_id: "account-1".into(),
                        code_hash: [1; 32],
                        used_at_epoch_millis: None,
                        expires_at_epoch_millis: None,
                    },
                );
                Ok(())
            })
            .await
            .expect("seed step-up action");
        let expectation = StepUpExpectation {
            challenge_id: "challenge-1".into(),
            account_id: "account-1".into(),
            device_id: "device-1".into(),
            purpose: "recovery_code_rotate".into(),
            operation_binding_hash: [6; 32],
            now_epoch_millis: now,
        };
        let action = StepUpAction::RotateRecoveryCodes {
            records: vec![RecoveryCode {
                recovery_code_id: "new-code".into(),
                account_id: "account-1".into(),
                code_hash: [2; 32],
                used_at_epoch_millis: None,
                expires_at_epoch_millis: None,
            }],
            audit_entry: AuditEntry {
                audit_id: "audit-1".into(),
                actor_type: "account".into(),
                actor_account_id: Some("account-1".into()),
                actor_device_id: None,
                actor_role: None,
                actor_service: None,
                target_device_id: Some("device-1".into()),
                session_id: None,
                action: "mfa_recovery_codes_rotated".into(),
                result: "success".into(),
                reason: None,
                metadata: BTreeMap::new(),
                request_id: "request-1".into(),
                created_at_epoch_millis: now,
            },
        };

        repository
            .apply_step_up_action(&expectation, &action)
            .await
            .expect("apply step-up action");
        assert_eq!(
            repository.apply_step_up_action(&expectation, &action).await,
            Err(StoreError::Conflict)
        );
        repository
            .read(&mut |database| {
                assert!(!database.recovery_codes.contains_key("old-code"));
                assert!(database.recovery_codes.contains_key("new-code"));
                assert_eq!(database.audit_logs.len(), 1);
                assert_eq!(
                    database.risk_challenges["challenge-1"].status,
                    RiskChallengeStatus::Consumed
                );
            })
            .await;
    }

    #[tokio::test]
    async fn memory_disabling_mfa_revokes_all_sessions_trust_and_recovery_codes() {
        let repository = MemoryRepository::default();
        let now = 1_700_000_000_000;
        let expectation = StepUpExpectation {
            challenge_id: "disable-mfa-challenge".into(),
            account_id: "account-1".into(),
            device_id: "device-1".into(),
            purpose: "mfa_factor_change".into(),
            operation_binding_hash: [4; 32],
            now_epoch_millis: now,
        };
        let action = StepUpAction::DisableMfaFactor {
            factor_id: "factor-1".into(),
            audit_entry: account_security_audit(
                "disable-mfa-audit",
                "mfa_factor_disabled",
                "success",
                now,
            ),
        };
        let conflicting_audit =
            account_session_revocation_audit(action.audit_entry(), "session-1", "mfa_disabled");
        repository
            .transact(&mut |database| {
                database
                    .accounts
                    .insert("account-1".into(), active_account(now));
                database.devices.insert(
                    "device-1".into(),
                    authorizable_device("device-1", "account-1", now),
                );
                database.mfa_factors.insert(
                    "factor-1".into(),
                    MfaFactor {
                        factor_id: "factor-1".into(),
                        account_id: "account-1".into(),
                        secret_base32: generate_totp_secret(),
                        active: true,
                        last_used_counter: None,
                        created_at_epoch_millis: now - 1,
                    },
                );
                database.recovery_codes.insert(
                    "recovery-1".into(),
                    RecoveryCode {
                        recovery_code_id: "recovery-1".into(),
                        account_id: "account-1".into(),
                        code_hash: [3; 32],
                        used_at_epoch_millis: None,
                        expires_at_epoch_millis: None,
                    },
                );
                for id in ["session-1", "session-2"] {
                    database
                        .account_sessions
                        .insert(id.into(), active_account_session(id, now));
                }
                database.trusted_controller_devices.insert(
                    "trust-1".into(),
                    TrustedControllerDevice {
                        trusted_device_id: "trust-1".into(),
                        account_id: "account-1".into(),
                        controller_device_id: "device-1".into(),
                        device_fingerprint_hash: sha256(&[1; 32]),
                        trust_level: "standard".into(),
                        status: TrustedDeviceStatus::Active,
                        trust_proof_type: "device_signature_and_mfa".into(),
                        created_at_epoch_millis: now - 1,
                        last_used_at_epoch_millis: None,
                        expires_at_epoch_millis: now + 60_000,
                        revoked_at_epoch_millis: None,
                    },
                );
                database.risk_challenges.insert(
                    "disable-mfa-challenge".into(),
                    RiskChallenge {
                        risk_challenge_id: "disable-mfa-challenge".into(),
                        account_id: "account-1".into(),
                        device_id: Some("device-1".into()),
                        purpose: "mfa_factor_change".into(),
                        operation_binding_hash: [4; 32],
                        risk_level: "high".into(),
                        required_methods: vec!["totp".into(), "recovery_code".into()],
                        status: RiskChallengeStatus::Verified,
                        attempts_remaining: 5,
                        ip_address: None,
                        user_agent: None,
                        expires_at_epoch_millis: now + 60_000,
                        created_at_epoch_millis: now - 1,
                        verified_at_epoch_millis: Some(now - 1),
                        consumed_at_epoch_millis: None,
                    },
                );
                database.audit_logs.push(conflicting_audit.clone());
                Ok(())
            })
            .await
            .expect("seed MFA disable authority");
        assert_eq!(
            repository.apply_step_up_action(&expectation, &action).await,
            Err(StoreError::Conflict)
        );
        repository
            .read(&mut |database| {
                assert!(database.mfa_factors.contains_key("factor-1"));
                assert!(database.recovery_codes.contains_key("recovery-1"));
                assert!(database
                    .account_sessions
                    .values()
                    .all(|session| session.revoked_at_epoch_millis.is_none()));
                assert_eq!(
                    database.trusted_controller_devices["trust-1"].status,
                    TrustedDeviceStatus::Active
                );
                assert_eq!(
                    database.risk_challenges["disable-mfa-challenge"].status,
                    RiskChallengeStatus::Verified
                );
                assert_eq!(
                    database.accounts["account-1"].updated_at_epoch_millis,
                    now - 1
                );
                assert_eq!(database.audit_logs, vec![conflicting_audit.clone()]);
            })
            .await;
        repository
            .transact(&mut |database| {
                database
                    .audit_logs
                    .retain(|entry| entry.audit_id != conflicting_audit.audit_id);
                Ok(())
            })
            .await
            .expect("remove injected audit conflict");
        repository
            .apply_step_up_action(&expectation, &action)
            .await
            .expect("disable MFA factor");
        repository
            .read(&mut |database| {
                assert!(!database.mfa_factors.contains_key("factor-1"));
                assert!(database.recovery_codes.is_empty());
                assert!(database.account_sessions.values().all(|session| {
                    session.revoked_at_epoch_millis == Some(now)
                        && session.revoked_reason.as_deref() == Some("mfa_disabled")
                }));
                assert_eq!(
                    database.trusted_controller_devices["trust-1"].status,
                    TrustedDeviceStatus::Revoked
                );
                assert_eq!(
                    database.risk_challenges["disable-mfa-challenge"].status,
                    RiskChallengeStatus::Consumed
                );
                assert_eq!(
                    database
                        .audit_logs
                        .iter()
                        .filter(|entry| entry.audit_id == "disable-mfa-audit")
                        .count(),
                    1
                );
                assert_eq!(
                    database
                        .audit_logs
                        .iter()
                        .filter(|entry| entry.action == "account_session_revoked")
                        .count(),
                    2
                );
                assert_eq!(
                    database
                        .audit_logs
                        .iter()
                        .filter(|entry| entry.action == "trusted_device_revoked")
                        .count(),
                    1
                );
            })
            .await;
    }

    #[tokio::test]
    async fn memory_device_rotation_is_atomic_and_single_use() {
        let repository = MemoryRepository::default();
        let now = 1_700_000_000_000;
        let device = Device {
            device_id: "device-1".into(),
            account_id: "account-1".into(),
            display_name: "Device".into(),
            platform: Platform::Windows,
            os_version: "11".into(),
            arch: Architecture::X86_64,
            capabilities: DeviceCapabilities {
                controller: true,
                controlled: true,
                file_transfer: false,
                unattended: false,
            },
            public_key_id: "key-1".into(),
            public_key: [1; 32],
            public_key_version: 1,
            public_key_revoked_at_epoch_millis: None,
            status: DeviceLifecycleStatus::Online,
            last_seen_epoch_millis: Some(now),
            created_at_epoch_millis: now - 1,
            updated_at_epoch_millis: now - 1,
        };
        repository
            .transact(&mut |database| {
                database
                    .devices
                    .insert(device.device_id.clone(), device.clone());
                database.account_sessions.insert(
                    "account-session-1".into(),
                    active_account_session("account-session-1", now),
                );
                database.device_public_keys.insert(
                    "key-1".into(),
                    DevicePublicKeyRecord {
                        public_key_id: "key-1".into(),
                        device_id: "device-1".into(),
                        public_key: [1; 32],
                        version: 1,
                        created_at_epoch_millis: now - 1,
                        revoked_at_epoch_millis: None,
                    },
                );
                database.trusted_controller_devices.insert(
                    "trusted-1".into(),
                    TrustedControllerDevice {
                        trusted_device_id: "trusted-1".into(),
                        account_id: "account-1".into(),
                        controller_device_id: "device-1".into(),
                        device_fingerprint_hash: sha256(&[1; 32]),
                        trust_level: "standard".into(),
                        status: TrustedDeviceStatus::Active,
                        trust_proof_type: "device_signature_and_mfa".into(),
                        created_at_epoch_millis: now - 1,
                        last_used_at_epoch_millis: None,
                        expires_at_epoch_millis: now + 60_000,
                        revoked_at_epoch_millis: None,
                    },
                );
                database.risk_challenges.insert(
                    "challenge-1".into(),
                    RiskChallenge {
                        risk_challenge_id: "challenge-1".into(),
                        account_id: "account-1".into(),
                        device_id: Some("device-1".into()),
                        purpose: "device_key_rotation".into(),
                        operation_binding_hash: [8; 32],
                        risk_level: "high".into(),
                        required_methods: vec!["totp".into()],
                        status: RiskChallengeStatus::Verified,
                        attempts_remaining: 5,
                        ip_address: None,
                        user_agent: None,
                        expires_at_epoch_millis: now + 60_000,
                        created_at_epoch_millis: now - 1,
                        verified_at_epoch_millis: Some(now - 1),
                        consumed_at_epoch_millis: None,
                    },
                );
                database.sessions.insert(
                    "session-1".into(),
                    Session {
                        session_id: "session-1".into(),
                        controller_account_id: "account-1".into(),
                        controller_device_id: "device-1".into(),
                        controlled_device_id: "device-2".into(),
                        auth_method: AuthMethod::AccountPrompt,
                        status: SessionStatus::Connected,
                        permissions: SessionPermissions::default(),
                        permissions_digest: "digest".into(),
                        policy_evaluation_id: "policy-1".into(),
                        relay_token_epoch: 4,
                        session_expires_at_epoch_millis: now + 60_000,
                        created_at_epoch_millis: now - 1,
                        updated_at_epoch_millis: now - 1,
                        ended_at_epoch_millis: None,
                    },
                );
                Ok(())
            })
            .await
            .expect("seed rotation state");

        let rotation = DeviceKeyRotation {
            step_up: StepUpExpectation {
                challenge_id: "challenge-1".into(),
                account_id: "account-1".into(),
                device_id: "device-1".into(),
                purpose: "device_key_rotation".into(),
                operation_binding_hash: [8; 32],
                now_epoch_millis: now,
            },
            current_public_key_id: "key-1".into(),
            current_public_key_version: 1,
            new_public_key_id: "key-2".into(),
            new_public_key: [2; 32],
            new_public_key_version: 2,
            audit_entry: AuditEntry {
                audit_id: "audit-1".into(),
                actor_type: "device".into(),
                actor_account_id: Some("account-1".into()),
                actor_device_id: Some("device-1".into()),
                actor_role: Some("none".into()),
                actor_service: None,
                target_device_id: Some("device-1".into()),
                session_id: None,
                action: "device_public_key_rotated".into(),
                result: "success".into(),
                reason: None,
                metadata: BTreeMap::new(),
                request_id: "request-1".into(),
                created_at_epoch_millis: now,
            },
        };
        let updated = repository
            .rotate_device_key(&rotation)
            .await
            .expect("rotate device key");
        assert_eq!(updated.device.public_key_id, "key-2");
        assert_eq!(updated.device.public_key_version, 2);
        assert_eq!(
            repository.rotate_device_key(&rotation).await,
            Err(StoreError::Conflict)
        );

        repository
            .read(&mut |database| {
                assert_eq!(database.sessions["session-1"].relay_token_epoch, 5);
                assert_eq!(database.sessions["session-1"].status, SessionStatus::Closed);
                assert_eq!(
                    database.sessions["session-1"].ended_at_epoch_millis,
                    Some(now)
                );
                assert_eq!(
                    database.trusted_controller_devices["trusted-1"].status,
                    TrustedDeviceStatus::Revoked
                );
                assert_eq!(
                    database.risk_challenges["challenge-1"].status,
                    RiskChallengeStatus::Consumed
                );
                assert_eq!(database.session_events.len(), 1);
                assert_eq!(database.session_events[0].event_type, "closed");
                assert_eq!(database.session_events[0].actor_type, "system");
                assert_eq!(database.audit_logs.len(), 3);
                assert!(database
                    .audit_logs
                    .iter()
                    .any(|audit| audit.action == "session_ended"));
                let trust_audit = database
                    .audit_logs
                    .iter()
                    .find(|audit| audit.action == "trusted_device_revoked")
                    .expect("rotation trust revocation audit");
                assert_eq!(trust_audit.reason.as_deref(), Some("device_key_rotated"));
                let rotation_audit = database
                    .audit_logs
                    .iter()
                    .find(|audit| audit.action == "device_public_key_rotated")
                    .expect("device key rotation audit");
                for field in [
                    "old_public_key_id",
                    "old_public_key_version",
                    "old_public_key_fingerprint",
                    "new_public_key_id",
                    "new_public_key_version",
                    "new_public_key_fingerprint",
                    "revoked_at_epoch_millis",
                    "rotation_reason",
                    "step_up_challenge_id",
                ] {
                    assert!(
                        rotation_audit.metadata.contains_key(field),
                        "missing {field}"
                    );
                }
                assert!(database.account_sessions["account-session-1"]
                    .revoked_at_epoch_millis
                    .is_none());
            })
            .await;
    }

    #[tokio::test]
    async fn memory_device_management_closes_authority_and_restore_stays_fail_closed() {
        let repository = MemoryRepository::default();
        let now = 1_700_000_000_000;
        let make_device = |device_id: &str, key_id: &str, key: [u8; 32]| Device {
            device_id: device_id.into(),
            account_id: "account-1".into(),
            display_name: device_id.into(),
            platform: Platform::Windows,
            os_version: "11".into(),
            arch: Architecture::X86_64,
            capabilities: DeviceCapabilities {
                controller: true,
                controlled: true,
                file_transfer: false,
                unattended: true,
            },
            public_key_id: key_id.into(),
            public_key: key,
            public_key_version: 1,
            public_key_revoked_at_epoch_millis: None,
            status: DeviceLifecycleStatus::Offline,
            last_seen_epoch_millis: None,
            created_at_epoch_millis: now - 1,
            updated_at_epoch_millis: now - 1,
        };
        let actor = make_device("actor-1", "actor-key-1", [1; 32]);
        let target = make_device("target-1", "target-key-1", [2; 32]);
        repository
            .transact(&mut |database| {
                database
                    .devices
                    .insert(actor.device_id.clone(), actor.clone());
                database
                    .devices
                    .insert(target.device_id.clone(), target.clone());
                let account_session = active_account_session("account-session-1", now);
                database
                    .account_sessions
                    .insert(account_session.account_session_id.clone(), account_session);
                database.trusted_controller_devices.insert(
                    "trusted-target".into(),
                    TrustedControllerDevice {
                        trusted_device_id: "trusted-target".into(),
                        account_id: "account-1".into(),
                        controller_device_id: "target-1".into(),
                        device_fingerprint_hash: sha256(&target.public_key),
                        trust_level: "standard".into(),
                        status: TrustedDeviceStatus::Active,
                        trust_proof_type: "device_signature_and_mfa".into(),
                        created_at_epoch_millis: now - 1,
                        last_used_at_epoch_millis: None,
                        expires_at_epoch_millis: now + 60_000,
                        revoked_at_epoch_millis: None,
                    },
                );
                database.sessions.insert(
                    "session-target".into(),
                    Session {
                        session_id: "session-target".into(),
                        controller_account_id: "account-1".into(),
                        controller_device_id: "actor-1".into(),
                        controlled_device_id: "target-1".into(),
                        auth_method: AuthMethod::AccountPrompt,
                        status: SessionStatus::Connected,
                        permissions: SessionPermissions::default(),
                        permissions_digest: "digest".into(),
                        policy_evaluation_id: "policy-1".into(),
                        relay_token_epoch: 3,
                        session_expires_at_epoch_millis: now + 60_000,
                        created_at_epoch_millis: now - 1,
                        updated_at_epoch_millis: now - 1,
                        ended_at_epoch_millis: None,
                    },
                );
                Ok(())
            })
            .await
            .expect("seed device management state");
        let audit = AuditEntry {
            audit_id: "audit-disable".into(),
            actor_type: "device".into(),
            actor_account_id: Some("account-1".into()),
            actor_device_id: Some("actor-1".into()),
            actor_role: Some("controller".into()),
            actor_service: None,
            target_device_id: Some("target-1".into()),
            session_id: None,
            action: "device_status_changed".into(),
            result: "success".into(),
            reason: None,
            metadata: BTreeMap::new(),
            request_id: "request-disable".into(),
            created_at_epoch_millis: now,
        };
        let command = DeviceManagementCommand {
            account_id: "account-1".into(),
            actor_device_id: "actor-1".into(),
            actor_public_key_id: "actor-key-1".into(),
            actor_public_key_version: 1,
            target_device_id: "target-1".into(),
            expected_target_public_key_id: "target-key-1".into(),
            expected_target_public_key_version: 1,
            display_name: None,
            action: Some(DeviceManagementAction::Disable),
            audit_entry: audit.clone(),
            now_epoch_millis: now,
        };
        let DeviceManagementOutcome::Updated(disabled) = repository
            .manage_device(&command)
            .await
            .expect("disable target")
        else {
            panic!("expected updated device");
        };
        assert_eq!(disabled.device.status, DeviceLifecycleStatus::Disabled);
        assert!(!disabled.device.capabilities.controlled);
        assert_eq!(disabled.closed_session_events.len(), 1);
        repository
            .read(&mut |database| {
                assert_eq!(
                    database.sessions["session-target"].status,
                    SessionStatus::Closed
                );
                assert_eq!(database.sessions["session-target"].relay_token_epoch, 4);
                assert_eq!(
                    database.trusted_controller_devices["trusted-target"].status,
                    TrustedDeviceStatus::Revoked
                );
                assert_eq!(database.session_events.len(), 1);
                assert_eq!(database.session_events[0].event_type, "closed");
                assert_eq!(
                    database.session_events[0].reason.as_deref(),
                    Some("device_disabled")
                );
                assert!(database.account_sessions["account-session-1"]
                    .revoked_at_epoch_millis
                    .is_none());
                assert!(database.audit_logs.iter().any(|audit| {
                    audit.action == "trusted_device_revoked"
                        && audit.reason.as_deref() == Some("device_disabled")
                        && audit.metadata["trusted_device_id"] == "trusted-target"
                }));
            })
            .await;

        let restore = DeviceManagementCommand {
            action: Some(DeviceManagementAction::Restore),
            audit_entry: AuditEntry {
                audit_id: "audit-restore".into(),
                request_id: "request-restore".into(),
                created_at_epoch_millis: now + 1,
                ..audit.clone()
            },
            now_epoch_millis: now + 1,
            ..command.clone()
        };
        let DeviceManagementOutcome::Updated(restored) = repository
            .manage_device(&restore)
            .await
            .expect("restore target")
        else {
            panic!("expected restored device");
        };
        assert_eq!(restored.device.status, DeviceLifecycleStatus::Offline);
        assert!(!restored.device.capabilities.controlled);
        assert!(restored.closed_session_events.is_empty());

        let revoke = DeviceManagementCommand {
            action: Some(DeviceManagementAction::RevokePublicKey),
            audit_entry: AuditEntry {
                audit_id: "audit-revoke".into(),
                action: "device_public_key_revoked".into(),
                request_id: "request-revoke".into(),
                created_at_epoch_millis: now + 2,
                ..audit
            },
            now_epoch_millis: now + 2,
            ..command
        };
        let DeviceManagementOutcome::Updated(revoked) = repository
            .manage_device(&revoke)
            .await
            .expect("revoke target key")
        else {
            panic!("expected revoked device");
        };
        assert_eq!(revoked.device.status, DeviceLifecycleStatus::Disabled);
        assert_eq!(
            revoked.device.public_key_revoked_at_epoch_millis,
            Some(now + 2)
        );
        assert_eq!(
            repository
                .manage_device(&DeviceManagementCommand {
                    action: Some(DeviceManagementAction::Restore),
                    now_epoch_millis: now + 3,
                    ..restore
                })
                .await,
            Ok(DeviceManagementOutcome::InvalidTransition)
        );
        repository
            .read(&mut |database| {
                assert!(database.audit_logs.iter().any(|audit| {
                    audit.action == "device_public_key_revoked"
                        && [
                            "old_public_key_id",
                            "old_public_key_version",
                            "old_public_key_fingerprint",
                            "revoked_at_epoch_millis",
                            "revocation_reason",
                            "affected_session_ids_hash",
                        ]
                        .iter()
                        .all(|field| audit.metadata.contains_key(*field))
                }));
                assert_eq!(
                    database.account_sessions["account-session-1"].revoked_at_epoch_millis,
                    Some(now + 2)
                );
                assert_eq!(
                    database.account_sessions["account-session-1"]
                        .revoked_reason
                        .as_deref(),
                    Some("device_unbound")
                );
                assert!(database.audit_logs.iter().any(|audit| {
                    audit.action == "account_session_revoked"
                        && audit.reason.as_deref() == Some("device_unbound")
                        && audit.metadata["account_session_id"] == "account-session-1"
                }));
            })
            .await;
    }

    #[tokio::test]
    async fn memory_device_unbind_audits_every_revocation_and_rolls_back_conflicts() {
        fn seed_unbind_state(database: &mut Database, now: u64) {
            let actor = authorizable_device("actor-1", "account-1", now);
            let target = authorizable_device("target-1", "account-1", now);
            database.devices.insert(actor.device_id.clone(), actor);
            database
                .devices
                .insert(target.device_id.clone(), target.clone());
            database.device_public_keys.insert(
                target.public_key_id.clone(),
                DevicePublicKeyRecord {
                    public_key_id: target.public_key_id.clone(),
                    device_id: target.device_id.clone(),
                    public_key: target.public_key,
                    version: target.public_key_version,
                    created_at_epoch_millis: now.saturating_sub(1),
                    revoked_at_epoch_millis: None,
                },
            );
            for id in ["account-session-1", "account-session-2"] {
                database
                    .account_sessions
                    .insert(id.into(), active_account_session(id, now));
            }
            for id in ["trust-1", "trust-2"] {
                database.trusted_controller_devices.insert(
                    id.into(),
                    TrustedControllerDevice {
                        trusted_device_id: id.into(),
                        account_id: "account-1".into(),
                        controller_device_id: "target-1".into(),
                        device_fingerprint_hash: sha256(&target.public_key),
                        trust_level: "standard".into(),
                        status: TrustedDeviceStatus::Active,
                        trust_proof_type: "device_signature_and_mfa".into(),
                        created_at_epoch_millis: now.saturating_sub(1),
                        last_used_at_epoch_millis: None,
                        expires_at_epoch_millis: now + 60_000,
                        revoked_at_epoch_millis: None,
                    },
                );
            }
            database.sessions.insert(
                "remote-session-1".into(),
                Session {
                    session_id: "remote-session-1".into(),
                    controller_account_id: "account-1".into(),
                    controller_device_id: "actor-1".into(),
                    controlled_device_id: "target-1".into(),
                    auth_method: AuthMethod::AccountPrompt,
                    status: SessionStatus::Connected,
                    permissions: SessionPermissions::default(),
                    permissions_digest: "digest".into(),
                    policy_evaluation_id: "policy-1".into(),
                    relay_token_epoch: 2,
                    session_expires_at_epoch_millis: now + 60_000,
                    created_at_epoch_millis: now.saturating_sub(1),
                    updated_at_epoch_millis: now.saturating_sub(1),
                    ended_at_epoch_millis: None,
                },
            );
        }

        let now = 1_700_000_000_000;
        let command = DeviceManagementCommand {
            account_id: "account-1".into(),
            actor_device_id: "actor-1".into(),
            actor_public_key_id: "key-actor-1".into(),
            actor_public_key_version: 1,
            target_device_id: "target-1".into(),
            expected_target_public_key_id: "key-target-1".into(),
            expected_target_public_key_version: 1,
            display_name: None,
            action: Some(DeviceManagementAction::Unbind),
            audit_entry: AuditEntry {
                audit_id: "audit-unbind".into(),
                actor_type: "device".into(),
                actor_account_id: Some("account-1".into()),
                actor_device_id: Some("actor-1".into()),
                actor_role: Some("none".into()),
                actor_service: None,
                target_device_id: Some("target-1".into()),
                session_id: None,
                action: "device_unregistered".into(),
                result: "success".into(),
                reason: None,
                metadata: BTreeMap::new(),
                request_id: "request-unbind".into(),
                created_at_epoch_millis: now,
            },
            now_epoch_millis: now,
        };

        let repository = MemoryRepository::default();
        repository
            .transact(&mut |database| {
                seed_unbind_state(database, now);
                Ok(())
            })
            .await
            .expect("seed unbind state");
        let DeviceManagementOutcome::Updated(change) = repository
            .manage_device(&command)
            .await
            .expect("unbind target")
        else {
            panic!("expected unbound device");
        };
        assert_eq!(change.device.status, DeviceLifecycleStatus::Unbound);
        repository
            .read(&mut |database| {
                assert_eq!(
                    database.devices["target-1"].public_key_revoked_at_epoch_millis,
                    Some(now)
                );
                assert!(database.account_sessions.values().all(|session| {
                    session.revoked_at_epoch_millis == Some(now)
                        && session.revoked_reason.as_deref() == Some("device_unbound")
                }));
                assert!(database
                    .trusted_controller_devices
                    .values()
                    .all(|trusted| trusted.status == TrustedDeviceStatus::Revoked));
                assert_eq!(
                    database.sessions["remote-session-1"].status,
                    SessionStatus::Closed
                );
                assert_eq!(
                    database
                        .audit_logs
                        .iter()
                        .filter(|audit| audit.action == "account_session_revoked")
                        .count(),
                    2
                );
                assert_eq!(
                    database
                        .audit_logs
                        .iter()
                        .filter(|audit| audit.action == "trusted_device_revoked")
                        .count(),
                    2
                );
                let key_audit = database
                    .audit_logs
                    .iter()
                    .find(|audit| {
                        audit.action == "device_public_key_revoked"
                            && audit.reason.as_deref() == Some("device_unbound")
                    })
                    .expect("unbind key revocation audit");
                assert_eq!(
                    key_audit.metadata["revocation_reason"],
                    serde_json::Value::String("device_unbound".into())
                );
                for field in [
                    "old_public_key_id",
                    "old_public_key_version",
                    "old_public_key_fingerprint",
                    "revoked_at_epoch_millis",
                    "affected_session_ids_hash",
                ] {
                    assert!(key_audit.metadata.contains_key(field), "missing {field}");
                }
            })
            .await;

        let repository = MemoryRepository::default();
        let conflicting_audit = account_session_revocation_audit(
            &command.audit_entry,
            "account-session-1",
            "device_unbound",
        );
        repository
            .transact(&mut |database| {
                seed_unbind_state(database, now);
                database.audit_logs.push(conflicting_audit.clone());
                Ok(())
            })
            .await
            .expect("seed unbind audit conflict");
        assert_eq!(
            repository.manage_device(&command).await,
            Err(StoreError::Conflict)
        );
        repository
            .read(&mut |database| {
                assert_eq!(
                    database.devices["target-1"].status,
                    DeviceLifecycleStatus::Offline
                );
                assert!(database.devices["target-1"]
                    .public_key_revoked_at_epoch_millis
                    .is_none());
                assert!(database
                    .account_sessions
                    .values()
                    .all(|session| session.revoked_at_epoch_millis.is_none()));
                assert!(database
                    .trusted_controller_devices
                    .values()
                    .all(|trusted| trusted.status == TrustedDeviceStatus::Active));
                assert_eq!(
                    database.sessions["remote-session-1"].status,
                    SessionStatus::Connected
                );
                assert!(database.session_events.is_empty());
                assert_eq!(database.audit_logs, vec![conflicting_audit.clone()]);
            })
            .await;
    }
}
