use std::collections::{BTreeMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
use remote_protocol::canonical_idempotency_binding_bytes;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{Mutex, RwLock};
use tokio_postgres::error::SqlState;
use tokio_postgres::{Client, IsolationLevel, NoTls, Row, Transaction};
use tracing::error;

use crate::model::*;
use crate::security::{
    canonical_fields, constant_time_sha256_eq, sha256, sha256_hex, verify_password, verify_totp,
};
use crate::store::{
    account_session_revocation_audit, apply_device_management, device_management_audit,
    device_management_revokes_account_sessions, device_management_session_close_reason,
    device_management_transition_allowed, forced_session_close_records,
    risk_challenge_required_methods_are_valid, trusted_device_revocation_audit,
    validate_login_challenge_authority, validate_login_finish_artifacts,
    validate_login_finish_command_shape, verify_registration_signature, CreateSessionCommand,
    CreateSessionOutcome, DeviceAuthorityChange, DeviceKeyRotation, DeviceManagementAction,
    DeviceManagementCommand, DeviceManagementOutcome, DeviceRegistrationCommand,
    DeviceRegistrationOutcome, LoginChallengeAuthority, LoginFinishCommand, LoginFinishOutcome,
    MfaFactorSummary, MfaStatusSnapshot, Repository, RepositoryFuture,
    RiskChallengeCreationOutcome, RiskChallengeVerification, RiskChallengeVerificationOutcome,
    SessionDeviceAuthority, StepUpAction, StepUpExpectation, StoreError, TotpEnrollmentCompletion,
    TotpEnrollmentReplayLookup, TotpEnrollmentReplayOutcome, TransitionSessionCommand,
    TransitionSessionOutcome,
};

const MFA_ENVELOPE_VERSION: u8 = 1;
const MFA_NONCE_BYTES: usize = 12;
const RISK_CHALLENGE_PURPOSES: &[&str] = &[
    "login_mfa",
    "new_controller_device",
    "trusted_device_change",
    "password_change",
    "mfa_factor_change",
    "recovery_code_rotate",
    "device_key_rotation",
    "unattended_secret_change",
    "require_prompt_relax",
    "allow_privacy_screen",
    "allow_block_local_input",
    "allow_remote_reboot",
    "remote_reboot",
    "access_policy_change",
    "client_release_change",
    "region_policy_change",
];
const RISK_LEVELS: &[&str] = &["low", "medium", "high"];
const TRUST_LEVELS: &[&str] = &["standard", "high_risk_step_up_required"];
const TRUST_PROOF_TYPES: &[&str] = &[
    "device_signature_and_mfa",
    "device_signature_and_recovery_code",
];
const ACCOUNT_SESSION_REVOKED_REASONS: &[&str] = &[
    "logout",
    "password_changed",
    "mfa_enabled",
    "mfa_disabled",
    "account_locked",
    "device_unbound",
    "refresh_replay",
];

const INSERT_ACCOUNT_SESSION_SQL: &str =
    "INSERT INTO account_sessions (account_session_id, account_id,
        refresh_token_hash, mfa_verified, device_label, expires_at_epoch_millis,
        revoked_at_epoch_millis, revoked_reason, created_at_epoch_millis,
        updated_at_epoch_millis)
     VALUES ($1,$2,$3,$4,'unified-client',$5,NULL,NULL,$6,$6)";

const LOAD_REFRESH_ACCOUNT_SESSION_SQL: &str =
    "SELECT s.account_session_id, s.account_id, s.refresh_token_hash,
            s.mfa_verified, s.expires_at_epoch_millis, s.revoked_at_epoch_millis,
            s.revoked_reason
     FROM account_sessions s
     JOIN accounts a ON a.account_id=s.account_id
     WHERE s.refresh_token_hash=$1 AND s.revoked_at_epoch_millis IS NULL
       AND s.revoked_reason IS NULL AND s.expires_at_epoch_millis > $2
       AND a.status='active'";

const ROTATE_REFRESH_ACCOUNT_SESSION_SQL: &str = "UPDATE account_sessions
     SET revoked_at_epoch_millis=$3, revoked_reason='refresh_replay',
         updated_at_epoch_millis=$3
     WHERE refresh_token_hash=$1 AND account_id=$2 AND mfa_verified=$4
       AND revoked_at_epoch_millis IS NULL AND revoked_reason IS NULL
       AND expires_at_epoch_millis > $3
     RETURNING account_session_id, account_id, refresh_token_hash, mfa_verified,
               expires_at_epoch_millis, revoked_at_epoch_millis, revoked_reason";

const LOAD_ACCOUNT_SESSIONS_SQL: &str =
    "SELECT account_session_id, account_id, refresh_token_hash, mfa_verified,
            expires_at_epoch_millis, revoked_at_epoch_millis, revoked_reason
     FROM account_sessions";

const UPSERT_ACCOUNT_SESSION_SQL: &str =
    "INSERT INTO account_sessions (account_session_id, account_id, refresh_token_hash,
        mfa_verified, device_label, expires_at_epoch_millis, revoked_at_epoch_millis,
        revoked_reason, created_at_epoch_millis, updated_at_epoch_millis)
     VALUES ($1,$2,$3,$4,'unified-client',$5,$6,$7,$8,$8)
     ON CONFLICT (account_session_id) DO UPDATE SET
        refresh_token_hash=EXCLUDED.refresh_token_hash,
        mfa_verified=EXCLUDED.mfa_verified,
        expires_at_epoch_millis=EXCLUDED.expires_at_epoch_millis,
        revoked_at_epoch_millis=COALESCE(
            account_sessions.revoked_at_epoch_millis,
            EXCLUDED.revoked_at_epoch_millis),
        revoked_reason=COALESCE(
            account_sessions.revoked_reason, EXCLUDED.revoked_reason),
        updated_at_epoch_millis=EXCLUDED.updated_at_epoch_millis";

const DEVICE_AUTHORITY_SELECT: &str =
    "SELECT d.device_id, d.account_id, d.display_name, d.platform, d.os_version, \
            d.arch, d.public_key_id, d.public_key, d.public_key_version, \
            d.public_key_revoked_at_epoch_millis, d.unattended_enabled, \
            d.status, d.last_seen_epoch_millis, d.created_at_epoch_millis, \
            d.updated_at_epoch_millis, \
            COALESCE(p.allow_remote_desktop, FALSE) AS allow_remote_desktop, \
            COALESCE(p.allow_file_transfer, FALSE) AS allow_file_transfer, \
            COALESCE(p.allow_unattended, FALSE) AS allow_unattended \
     FROM devices d LEFT JOIN device_policies p ON p.device_id = d.device_id";

const SESSION_AUTHORITY_SELECT: &str =
    "SELECT session_id, controller_account_id, controller_device_id, \
            controlled_device_id, auth_method, status, permissions, permissions_digest, \
            policy_evaluation_id, relay_token_epoch, session_expires_at_epoch_millis, \
            created_at_epoch_millis, updated_at_epoch_millis, ended_at_epoch_millis \
     FROM sessions";

pub struct PostgresRepository {
    database: RwLock<Database>,
    client: Mutex<Client>,
    mfa_secret_key: [u8; 32],
}

impl PostgresRepository {
    pub async fn connect(database_url: &str, mfa_secret_key: [u8; 32]) -> Result<Self, String> {
        let (client, connection) = tokio_postgres::connect(database_url, NoTls)
            .await
            .map_err(|error| format!("connect PostgreSQL: {error}"))?;
        tokio::spawn(async move {
            if let Err(connection_error) = connection.await {
                error!(error = %connection_error, "PostgreSQL connection terminated");
            }
        });

        verify_schema(&client).await?;
        let database = load_database(&client, &mfa_secret_key).await?;
        Ok(Self {
            database: RwLock::new(database),
            client: Mutex::new(client),
            mfa_secret_key,
        })
    }
}

impl Repository for PostgresRepository {
    fn backend_name(&self) -> &'static str {
        "postgres"
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

    fn transact<'a>(
        &'a self,
        operation: &'a mut (dyn FnMut(&mut Database) -> Result<(), StoreError> + Send),
    ) -> RepositoryFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let mut published = self.database.write().await;
            let before = published.clone();
            let mut candidate = before.clone();
            operation(&mut candidate)?;

            let mut client = self.client.lock().await;
            let transaction = client.transaction().await.map_err(log_store_error)?;
            transaction
                .batch_execute("SET CONSTRAINTS ALL DEFERRED")
                .await
                .map_err(log_store_error)?;
            persist_changes(&transaction, &before, &candidate, &self.mfa_secret_key)
                .await
                .map_err(log_persistence_error)?;
            transaction.commit().await.map_err(log_store_error)?;
            *published = candidate;
            Ok(())
        })
    }

    fn finish_login<'a>(
        &'a self,
        command: &'a LoginFinishCommand,
    ) -> RepositoryFuture<'a, Result<LoginFinishOutcome, StoreError>> {
        Box::pin(async move {
            validate_login_finish_command_shape(command)?;
            let mut published = self.database.write().await;
            let mut client = self.client.lock().await;
            let transaction = client.transaction().await.map_err(log_store_error)?;
            let now = to_i64_lossless(command.now_epoch_millis);
            let account_row = transaction
                .query_opt(
                    "SELECT status, updated_at_epoch_millis FROM accounts
                     WHERE account_id=$1 FOR UPDATE",
                    &[&command.account_id],
                )
                .await
                .map_err(log_store_error)?;
            let Some(account_row) = account_row else {
                return Ok(LoginFinishOutcome::Rejected);
            };
            let account_active = account_row.get::<_, String>("status") == "active";
            let account_updated_at =
                from_i64(account_row.get("updated_at_epoch_millis")).map_err(|reason| {
                    error!(%reason, "PostgreSQL locked login account timestamp is invalid");
                    StoreError::Unavailable
                })?;
            let challenge_row = transaction
                .query_opt(
                    "SELECT risk_challenge_id, account_id, device_id, purpose,
                            operation_binding_hash, risk_level, required_methods, status,
                            attempts_remaining, ip_address::text AS ip_address, user_agent,
                            expires_at_epoch_millis, created_at_epoch_millis,
                            verified_at_epoch_millis, consumed_at_epoch_millis
                     FROM account_risk_challenges
                     WHERE risk_challenge_id=$1
                     FOR UPDATE",
                    &[&command.challenge_id],
                )
                .await
                .map_err(log_store_error)?;
            let Some(challenge_row) = challenge_row else {
                return Ok(LoginFinishOutcome::Rejected);
            };
            let mut challenge = risk_challenge_from_row(&challenge_row).map_err(|reason| {
                error!(%reason, "PostgreSQL locked login challenge row is invalid");
                StoreError::Unavailable
            })?;
            if challenge.account_id != command.account_id
                || challenge.device_id != command.persistent_device_id
                || challenge.purpose != "login_mfa"
                || challenge.status != RiskChallengeStatus::Issued
                || challenge.attempts_remaining == 0
                || !constant_time_sha256_eq(
                    &challenge.operation_binding_hash,
                    &command.challenge_binding_hash,
                )
                || challenge.required_methods != command.required_factors
            {
                return Ok(LoginFinishOutcome::InvalidChallenge);
            }
            if challenge.expires_at_epoch_millis <= command.now_epoch_millis {
                transaction
                    .execute(
                        "UPDATE account_risk_challenges SET status='expired'
                         WHERE risk_challenge_id=$1 AND status='issued'",
                        &[&command.challenge_id],
                    )
                    .await
                    .map_err(log_store_error)?;
                let mut audit = command.failure_audit_entry.clone();
                audit.reason = Some("expired".to_owned());
                insert_audit_entry_strict(&transaction, &audit)
                    .await
                    .map_err(log_conflict_or_store_error)?;
                transaction.commit().await.map_err(log_store_error)?;
                challenge.status = RiskChallengeStatus::Expired;
                published
                    .risk_challenges
                    .insert(challenge.risk_challenge_id.clone(), challenge);
                published.audit_logs.push(audit);
                return Ok(LoginFinishOutcome::InvalidChallenge);
            }
            validate_login_finish_artifacts(command, &challenge)?;

            if !account_active || account_updated_at != command.account_updated_at_epoch_millis {
                let (attempts_remaining, status) = reject_locked_login_challenge(
                    &transaction,
                    &command.challenge_id,
                    challenge.attempts_remaining,
                )
                .await
                .map_err(log_store_error)?;
                let mut audit = command.failure_audit_entry.clone();
                audit.reason = Some("account_security_changed".to_owned());
                insert_audit_entry_strict(&transaction, &audit)
                    .await
                    .map_err(log_conflict_or_store_error)?;
                transaction.commit().await.map_err(log_store_error)?;
                challenge.attempts_remaining = attempts_remaining;
                challenge.status = status;
                published
                    .risk_challenges
                    .insert(challenge.risk_challenge_id.clone(), challenge);
                published.audit_logs.push(audit);
                return Ok(LoginFinishOutcome::Rejected);
            }

            let device_row = transaction
                .query_opt(
                    "SELECT account_id, public_key_id, public_key, public_key_version,
                            public_key_revoked_at_epoch_millis, status
                     FROM devices WHERE device_id=$1 FOR UPDATE",
                    &[&command.device_id],
                )
                .await
                .map_err(log_store_error)?;
            let registered_device_valid = command.persistent_device_id.is_some()
                && device_row.as_ref().is_some_and(|row| {
                    let version = u32::try_from(row.get::<_, i32>("public_key_version")).ok();
                    let public_key =
                        fixed_32(row.get::<_, Vec<u8>>("public_key"), "devices.public_key").ok();
                    row.get::<_, String>("account_id") == command.account_id
                        && matches!(
                            row.get::<_, String>("status").as_str(),
                            "online" | "offline" | "busy"
                        )
                        && row
                            .get::<_, Option<i64>>("public_key_revoked_at_epoch_millis")
                            .is_none()
                        && command.public_key_id.as_deref()
                            == Some(row.get::<_, String>("public_key_id").as_str())
                        && version == Some(command.public_key_version)
                        && public_key.is_some_and(|public_key| {
                            constant_time_sha256_eq(
                                &sha256(&public_key),
                                &command.device_public_key_fingerprint,
                            )
                        })
                });
            let pending_device_valid = command.persistent_device_id.is_none()
                && command.public_key_id.is_none()
                && command.public_key_version == 0
                && device_row.is_none();
            if !registered_device_valid && !pending_device_valid {
                let (attempts_remaining, status) = reject_locked_login_challenge(
                    &transaction,
                    &command.challenge_id,
                    challenge.attempts_remaining,
                )
                .await
                .map_err(log_store_error)?;
                let mut audit = command.failure_audit_entry.clone();
                audit.reason = Some("device_authority_changed".to_owned());
                insert_audit_entry_strict(&transaction, &audit)
                    .await
                    .map_err(log_conflict_or_store_error)?;
                transaction.commit().await.map_err(log_store_error)?;
                challenge.attempts_remaining = attempts_remaining;
                challenge.status = status;
                published
                    .risk_challenges
                    .insert(challenge.risk_challenge_id.clone(), challenge);
                published.audit_logs.push(audit);
                return Ok(LoginFinishOutcome::Rejected);
            }

            let mfa_enabled: bool = transaction
                .query_one(
                    "SELECT EXISTS (
                         SELECT 1 FROM account_mfa_factors
                         WHERE account_id=$1 AND factor_type='totp' AND status='active')",
                    &[&command.account_id],
                )
                .await
                .map_err(log_store_error)?
                .get(0);
            let mut accepted_totp = None;
            let mut accepted_recovery_code = None;
            let mut used_trusted_device = None;

            if command.required_factors.is_empty() {
                if command.factor_kind.is_some() || command.factor_code.is_some() {
                    return Ok(LoginFinishOutcome::InvalidFactor);
                }
                if mfa_enabled {
                    let Some(trusted_device_id) = command.trusted_device_id_to_use.as_deref()
                    else {
                        return Ok(LoginFinishOutcome::InvalidTrust);
                    };
                    let trusted_row = transaction
                        .query_opt(
                            "SELECT trusted_device_id, account_id, controller_device_id,
                                    device_fingerprint_hash, trust_level, status, trust_proof_type,
                                    created_at_epoch_millis, last_used_at_epoch_millis,
                                    expires_at_epoch_millis, revoked_at_epoch_millis
                             FROM trusted_controller_devices
                             WHERE trusted_device_id=$1
                             FOR UPDATE",
                            &[&trusted_device_id],
                        )
                        .await
                        .map_err(log_store_error)?;
                    let Some(trusted_row) = trusted_row else {
                        return Ok(LoginFinishOutcome::InvalidTrust);
                    };
                    let mut trusted = trusted_device_from_row(&trusted_row).map_err(|reason| {
                        error!(%reason, "PostgreSQL locked trusted device row is invalid");
                        StoreError::Unavailable
                    })?;
                    if trusted.account_id != command.account_id
                        || trusted.controller_device_id != command.device_id
                        || trusted.status != TrustedDeviceStatus::Active
                        || !constant_time_sha256_eq(
                            &trusted.device_fingerprint_hash,
                            &command.device_public_key_fingerprint,
                        )
                    {
                        return Ok(LoginFinishOutcome::InvalidTrust);
                    }
                    if trusted.expires_at_epoch_millis <= command.now_epoch_millis {
                        transaction
                            .execute(
                                "UPDATE trusted_controller_devices SET status='expired'
                                 WHERE trusted_device_id=$1 AND status='active'",
                                &[&trusted_device_id],
                            )
                            .await
                            .map_err(log_store_error)?;
                        transaction.commit().await.map_err(log_store_error)?;
                        trusted.status = TrustedDeviceStatus::Expired;
                        published
                            .trusted_controller_devices
                            .insert(trusted.trusted_device_id.clone(), trusted);
                        return Ok(LoginFinishOutcome::InvalidTrust);
                    }
                    let affected = transaction
                        .execute(
                            "UPDATE trusted_controller_devices
                             SET last_used_at_epoch_millis=$2
                             WHERE trusted_device_id=$1 AND status='active'
                               AND expires_at_epoch_millis > $2",
                            &[&trusted_device_id, &now],
                        )
                        .await
                        .map_err(log_store_error)?;
                    if affected != 1 {
                        return Err(StoreError::Conflict);
                    }
                    trusted.last_used_at_epoch_millis = Some(command.now_epoch_millis);
                    used_trusted_device = Some(trusted);
                } else if command.trusted_device_id_to_use.is_some() {
                    return Ok(LoginFinishOutcome::InvalidTrust);
                }
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

                let accepted = match factor_kind {
                    "totp" => {
                        let factor_row = transaction
                            .query_opt(
                                "SELECT factor_id, encrypted_secret, created_at_epoch_millis
                                 FROM account_mfa_factors
                                 WHERE account_id=$1 AND factor_type='totp' AND status='active'
                                 FOR UPDATE",
                                &[&command.account_id],
                            )
                            .await
                            .map_err(log_store_error)?;
                        if let Some(factor_row) = factor_row {
                            let factor_id: String = factor_row.get("factor_id");
                            let payload = decrypt_mfa(
                                &self.mfa_secret_key,
                                &command.account_id,
                                &factor_id,
                                &factor_row.get::<_, Vec<u8>>("encrypted_secret"),
                            )
                            .map_err(|reason| {
                                error!(%reason, "PostgreSQL login MFA factor cannot be decrypted");
                                StoreError::Unavailable
                            })?;
                            let mut factor = MfaFactor {
                                factor_id: factor_id.clone(),
                                account_id: command.account_id.clone(),
                                secret_base32: payload.secret_base32,
                                active: true,
                                last_used_counter: payload.last_used_counter,
                                created_at_epoch_millis: from_i64(
                                    factor_row.get("created_at_epoch_millis"),
                                )
                                .map_err(|reason| {
                                    error!(%reason, "PostgreSQL login MFA timestamp is invalid");
                                    StoreError::Unavailable
                                })?,
                            };
                            if let Some(counter) = verify_totp(
                                &factor.secret_base32,
                                factor_code,
                                command.now_epoch_millis,
                                factor.last_used_counter,
                            ) {
                                factor.last_used_counter = Some(counter);
                                let encrypted = encrypt_mfa(&self.mfa_secret_key, &factor)
                                    .map_err(|reason| {
                                        error!(%reason, "PostgreSQL login MFA factor cannot be encrypted");
                                        StoreError::Unavailable
                                    })?;
                                let affected = transaction
                                    .execute(
                                        "UPDATE account_mfa_factors
                                         SET encrypted_secret=$2, last_used_at_epoch_millis=$3
                                         WHERE factor_id=$1 AND account_id=$4 AND status='active'",
                                        &[&factor_id, &encrypted, &now, &command.account_id],
                                    )
                                    .await
                                    .map_err(log_store_error)?;
                                if affected != 1 {
                                    return Err(StoreError::Conflict);
                                }
                                accepted_totp = Some((factor_id, counter));
                                true
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    }
                    "recovery_code" => {
                        let code_hash = sha256(factor_code.as_bytes());
                        let row = transaction
                            .query_opt(
                                "UPDATE account_recovery_codes
                                 SET status='used', used_at_epoch_millis=$3
                                 WHERE account_id=$1 AND code_hash=$2 AND status='active'
                                   AND (expires_at_epoch_millis IS NULL
                                        OR expires_at_epoch_millis > $3)
                                 RETURNING recovery_code_id",
                                &[&command.account_id, &&code_hash[..], &now],
                            )
                            .await
                            .map_err(log_store_error)?;
                        accepted_recovery_code =
                            row.map(|row| row.get::<_, String>("recovery_code_id"));
                        accepted_recovery_code.is_some()
                    }
                    _ => false,
                };
                if !accepted {
                    let (attempts_remaining, status) = reject_locked_login_challenge(
                        &transaction,
                        &command.challenge_id,
                        challenge.attempts_remaining,
                    )
                    .await
                    .map_err(log_store_error)?;
                    insert_audit_entry_strict(&transaction, &command.failure_audit_entry)
                        .await
                        .map_err(log_conflict_or_store_error)?;
                    transaction.commit().await.map_err(log_store_error)?;
                    challenge.attempts_remaining = attempts_remaining;
                    challenge.status = status;
                    published
                        .risk_challenges
                        .insert(challenge.risk_challenge_id.clone(), challenge);
                    published
                        .audit_logs
                        .push(command.failure_audit_entry.clone());
                    return Ok(LoginFinishOutcome::InvalidFactor);
                }
            }

            let session_expires = to_i64_lossless(command.account_session.expires_at_epoch_millis);
            transaction
                .execute(
                    INSERT_ACCOUNT_SESSION_SQL,
                    &[
                        &command.account_session.account_session_id,
                        &command.account_session.account_id,
                        &&command.account_session.refresh_token_hash[..],
                        &command.account_session.mfa_verified,
                        &session_expires,
                        &now,
                    ],
                )
                .await
                .map_err(log_conflict_or_store_error)?;

            if let Some(grant) = &command.enrollment_grant {
                validate_device_enrollment_grant(grant).map_err(|reason| {
                    error!(%reason, "PostgreSQL login finish rejected invalid enrollment grant");
                    StoreError::Conflict
                })?;
                if grant.account_id != command.account_id
                    || grant.device_id != command.device_id
                    || grant.login_challenge_id != command.challenge_id
                    || grant.issued_account_session_id != command.account_session.account_session_id
                    || grant.protocol_version == 0
                    || grant.consumed_at_epoch_millis.is_some()
                    || grant.issued_at_epoch_millis != command.now_epoch_millis
                    || grant.expires_at_epoch_millis > challenge.expires_at_epoch_millis
                    || !constant_time_sha256_eq(
                        &grant.device_public_key_fingerprint,
                        &command.device_public_key_fingerprint,
                    )
                    || !constant_time_sha256_eq(
                        &grant.login_challenge_binding_hash,
                        &command.challenge_binding_hash,
                    )
                    || !grant_trust_matches_factor(grant, command.factor_kind.as_deref())
                {
                    return Err(StoreError::Conflict);
                }
                let protocol_version = i32::from(grant.protocol_version);
                let issued = to_i64_lossless(grant.issued_at_epoch_millis);
                let expires = to_i64_lossless(grant.expires_at_epoch_millis);
                transaction
                    .execute(
                        "INSERT INTO device_enrollment_grants (grant_id, grant_secret_hash,
                            account_id, device_id, device_public_key_fingerprint,
                            login_challenge_id, login_challenge_binding_hash, trust_proof_type,
                            trust_level, establish_trust, protocol_version,
                            issued_account_session_id, issued_at_epoch_millis,
                            expires_at_epoch_millis, consumed_at_epoch_millis,
                            created_at_epoch_millis)
                         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NULL,$13)",
                        &[
                            &grant.grant_id,
                            &&grant.grant_secret_hash[..],
                            &grant.account_id,
                            &grant.device_id,
                            &&grant.device_public_key_fingerprint[..],
                            &grant.login_challenge_id,
                            &&grant.login_challenge_binding_hash[..],
                            &grant.trust_proof_type,
                            &grant.trust_level,
                            &grant.establish_trust,
                            &protocol_version,
                            &grant.issued_account_session_id,
                            &issued,
                            &expires,
                        ],
                    )
                    .await
                    .map_err(log_conflict_or_store_error)?;
            }

            if let Some(trusted) = &command.trusted_device_to_create {
                validate_trusted_device(trusted).map_err(|reason| {
                    error!(%reason, "PostgreSQL login finish rejected invalid trusted device");
                    StoreError::Conflict
                })?;
                if command.enrollment_grant.is_some()
                    || command.factor_kind.is_none()
                    || trusted.account_id != command.account_id
                    || trusted.controller_device_id != command.device_id
                    || trusted.created_at_epoch_millis != command.now_epoch_millis
                    || !constant_time_sha256_eq(
                        &trusted.device_fingerprint_hash,
                        &command.device_public_key_fingerprint,
                    )
                {
                    return Err(StoreError::Conflict);
                }
                transaction
                    .execute(
                        "UPDATE trusted_controller_devices
                         SET status='revoked', revoked_at_epoch_millis=$3
                         WHERE account_id=$1 AND controller_device_id=$2 AND status='active'",
                        &[&command.account_id, &command.device_id, &now],
                    )
                    .await
                    .map_err(log_store_error)?;
                insert_trusted_device_strict(&transaction, trusted)
                    .await
                    .map_err(log_conflict_or_persistence_error)?;
            } else if command.factor_kind.is_some() && command.persistent_device_id.is_some() {
                return Err(StoreError::Conflict);
            }

            let consumed = transaction
                .execute(
                    "UPDATE account_risk_challenges
                     SET status='consumed', verified_at_epoch_millis=$2,
                         consumed_at_epoch_millis=$2
                     WHERE risk_challenge_id=$1 AND status='issued'
                       AND operation_binding_hash=$3 AND expires_at_epoch_millis > $2",
                    &[
                        &command.challenge_id,
                        &now,
                        &&command.challenge_binding_hash[..],
                    ],
                )
                .await
                .map_err(log_store_error)?;
            if consumed != 1 {
                return Err(StoreError::Conflict);
            }
            for audit_entry in command
                .audit_entries
                .iter()
                .filter(|entry| entry.action != "device_enrollment_grant_issued")
            {
                insert_audit_entry_strict(&transaction, audit_entry)
                    .await
                    .map_err(log_conflict_or_store_error)?;
            }
            transaction.commit().await.map_err(log_store_error)?;

            challenge.status = RiskChallengeStatus::Consumed;
            challenge.verified_at_epoch_millis = Some(command.now_epoch_millis);
            challenge.consumed_at_epoch_millis = Some(command.now_epoch_millis);
            published
                .risk_challenges
                .insert(challenge.risk_challenge_id.clone(), challenge);
            if let Some((factor_id, counter)) = accepted_totp {
                if let Some(factor) = published.mfa_factors.get_mut(&factor_id) {
                    factor.last_used_counter = Some(counter);
                }
            }
            if let Some(recovery_code_id) = accepted_recovery_code {
                if let Some(recovery_code) = published.recovery_codes.get_mut(&recovery_code_id) {
                    recovery_code.used_at_epoch_millis = Some(command.now_epoch_millis);
                }
            }
            if let Some(trusted) = used_trusted_device {
                published
                    .trusted_controller_devices
                    .insert(trusted.trusted_device_id.clone(), trusted);
            }
            if let Some(trusted) = &command.trusted_device_to_create {
                for current in published.trusted_controller_devices.values_mut() {
                    if current.account_id == command.account_id
                        && current.controller_device_id == command.device_id
                        && current.status == TrustedDeviceStatus::Active
                    {
                        current.status = TrustedDeviceStatus::Revoked;
                        current.revoked_at_epoch_millis = Some(command.now_epoch_millis);
                    }
                }
                published
                    .trusted_controller_devices
                    .insert(trusted.trusted_device_id.clone(), trusted.clone());
            }
            if let Some(grant) = &command.enrollment_grant {
                published
                    .device_enrollment_grants
                    .insert(grant.grant_id.clone(), grant.clone());
            }
            published.account_sessions.insert(
                command.account_session.account_session_id.clone(),
                command.account_session.clone(),
            );
            published.audit_logs.extend(
                command
                    .audit_entries
                    .iter()
                    .filter(|entry| entry.action != "device_enrollment_grant_issued")
                    .cloned(),
            );
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
            let mut published = self.database.write().await;
            let mut client = self.client.lock().await;
            let transaction = client.transaction().await.map_err(log_store_error)?;
            let now = to_i64_lossless(now_epoch_millis);
            let row = transaction
                .query_opt(
                    "UPDATE account_risk_challenges
                     SET attempts_remaining=attempts_remaining-1,
                         status=CASE WHEN attempts_remaining=1 THEN 'failed' ELSE 'issued' END
                     WHERE risk_challenge_id=$1 AND purpose='login_mfa' AND status='issued'
                       AND attempts_remaining > 0 AND expires_at_epoch_millis > $3
                       AND operation_binding_hash=$2
                     RETURNING risk_challenge_id, account_id, device_id, purpose,
                               operation_binding_hash, risk_level, required_methods, status,
                               attempts_remaining, ip_address::text AS ip_address, user_agent,
                               expires_at_epoch_millis, created_at_epoch_millis,
                               verified_at_epoch_millis, consumed_at_epoch_millis",
                    &[&challenge_id, &&challenge_binding_hash[..], &now],
                )
                .await
                .map_err(log_store_error)?;
            let Some(row) = row else {
                transaction.commit().await.map_err(log_store_error)?;
                return Ok(false);
            };
            let challenge = risk_challenge_from_row(&row).map_err(|reason| {
                error!(%reason, "PostgreSQL rejected login challenge row is invalid");
                StoreError::Unavailable
            })?;
            insert_audit_entry_strict(&transaction, audit_entry)
                .await
                .map_err(log_conflict_or_store_error)?;
            transaction.commit().await.map_err(log_store_error)?;
            published
                .risk_challenges
                .insert(challenge.risk_challenge_id.clone(), challenge);
            published.audit_logs.push(audit_entry.clone());
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
            let client = self.client.lock().await;
            let now = to_i64_lossless(now_epoch_millis);
            client
                .query_one(
                    "SELECT EXISTS (
                         SELECT 1 FROM account_sessions
                         WHERE account_session_id=$1 AND account_id=$2
                           AND revoked_at_epoch_millis IS NULL
                           AND revoked_reason IS NULL
                           AND expires_at_epoch_millis > $3
                     )",
                    &[&account_session_id, &account_id, &now],
                )
                .await
                .map(|row| row.get(0))
                .map_err(log_store_error)
        })
    }

    fn load_account_by_email<'a>(
        &'a self,
        email: &'a str,
    ) -> RepositoryFuture<'a, Result<Option<Account>, StoreError>> {
        Box::pin(async move {
            let client = self.client.lock().await;
            let row = client
                .query_opt(
                    "SELECT account_id, email, display_name, password_hash, status,
                            created_at_epoch_millis, updated_at_epoch_millis
                     FROM accounts WHERE email=$1",
                    &[&email],
                )
                .await
                .map_err(log_store_error)?;
            row.map(|row| account_from_row(&row))
                .transpose()
                .map_err(|reason| {
                    error!(%reason, "PostgreSQL authority account row is invalid");
                    StoreError::Unavailable
                })
        })
    }

    fn load_account_by_id<'a>(
        &'a self,
        account_id: &'a str,
    ) -> RepositoryFuture<'a, Result<Option<Account>, StoreError>> {
        Box::pin(async move {
            let client = self.client.lock().await;
            let row = client
                .query_opt(
                    "SELECT account_id, email, display_name, password_hash, status,
                            created_at_epoch_millis, updated_at_epoch_millis
                     FROM accounts WHERE account_id=$1",
                    &[&account_id],
                )
                .await
                .map_err(log_store_error)?;
            row.map(|row| account_from_row(&row))
                .transpose()
                .map_err(|reason| {
                    error!(%reason, "PostgreSQL authority account row is invalid");
                    StoreError::Unavailable
                })
        })
    }

    fn account_mfa_enabled<'a>(
        &'a self,
        account_id: &'a str,
    ) -> RepositoryFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move {
            let client = self.client.lock().await;
            client
                .query_one(
                    "SELECT EXISTS (
                         SELECT 1 FROM account_mfa_factors
                         WHERE account_id=$1 AND factor_type='totp' AND status='active'
                     )",
                    &[&account_id],
                )
                .await
                .map(|row| row.get(0))
                .map_err(log_store_error)
        })
    }

    fn load_mfa_status<'a>(
        &'a self,
        account_id: &'a str,
        now_epoch_millis: u64,
    ) -> RepositoryFuture<'a, Result<MfaStatusSnapshot, StoreError>> {
        Box::pin(async move {
            let mut client = self.client.lock().await;
            let transaction = client
                .build_transaction()
                .isolation_level(IsolationLevel::RepeatableRead)
                .read_only(true)
                .start()
                .await
                .map_err(log_store_error)?;
            let rows = transaction
                .query(
                    "SELECT factor_id, created_at_epoch_millis
                     FROM account_mfa_factors
                     WHERE account_id=$1 AND factor_type='totp' AND status='active'
                     ORDER BY created_at_epoch_millis, factor_id",
                    &[&account_id],
                )
                .await
                .map_err(log_store_error)?;
            let factors = rows
                .iter()
                .map(|row| {
                    Ok(MfaFactorSummary {
                        factor_id: row.get("factor_id"),
                        created_at_epoch_millis: from_i64(row.get("created_at_epoch_millis"))?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()
                .map_err(|reason| {
                    error!(%reason, "PostgreSQL MFA status timestamp is invalid");
                    StoreError::Unavailable
                })?;
            let now = to_i64_lossless(now_epoch_millis);
            let recovery_count: i64 = transaction
                .query_one(
                    "SELECT COUNT(*) FROM account_recovery_codes
                     WHERE account_id=$1 AND status='active'
                       AND (expires_at_epoch_millis IS NULL OR expires_at_epoch_millis > $2)",
                    &[&account_id, &now],
                )
                .await
                .map_err(log_store_error)?
                .get(0);
            transaction.commit().await.map_err(log_store_error)?;
            let recovery_codes_remaining = usize::try_from(recovery_count).map_err(|_| {
                error!(recovery_count, "PostgreSQL MFA recovery count is invalid");
                StoreError::Unavailable
            })?;
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
            let mut published = self.database.write().await;
            let client = self.client.lock().await;
            let row = client
                .query_opt(
                    "SELECT risk_challenge_id, account_id, device_id, purpose,
                            operation_binding_hash, risk_level, required_methods, status,
                            attempts_remaining, ip_address::text AS ip_address, user_agent,
                            expires_at_epoch_millis, created_at_epoch_millis,
                            verified_at_epoch_millis, consumed_at_epoch_millis
                     FROM account_risk_challenges WHERE risk_challenge_id=$1",
                    &[&challenge_id],
                )
                .await
                .map_err(log_store_error)?;
            let challenge = row
                .map(|row| risk_challenge_from_row(&row))
                .transpose()
                .map_err(|reason| {
                    error!(%reason, "PostgreSQL authority risk challenge row is invalid");
                    StoreError::Unavailable
                })?;
            if let Some(challenge) = &challenge {
                published
                    .risk_challenges
                    .insert(challenge.risk_challenge_id.clone(), challenge.clone());
            } else {
                published.risk_challenges.remove(challenge_id);
            }
            Ok(challenge)
        })
    }

    fn load_login_challenge_authority<'a>(
        &'a self,
        challenge_id: &'a str,
    ) -> RepositoryFuture<'a, Result<Option<LoginChallengeAuthority>, StoreError>> {
        Box::pin(async move {
            let mut published = self.database.write().await;
            let client = self.client.lock().await;
            let row = client
                .query_opt(
                    "SELECT risk_challenge_id, account_id, device_id, purpose,
                            operation_binding_hash, risk_level, required_methods, status,
                            attempts_remaining, ip_address::text AS ip_address, user_agent,
                            expires_at_epoch_millis, created_at_epoch_millis,
                            verified_at_epoch_millis, consumed_at_epoch_millis,
                            login_device_state, login_device_id,
                            login_account_updated_at_epoch_millis, login_device_public_key,
                            login_device_public_key_fingerprint, login_public_key_id,
                            login_public_key_version, login_client_nonce, login_server_nonce,
                            login_request_binding_hash, login_ip_address_hash,
                            login_user_agent_hash, login_trusted_device_id,
                            login_protocol_version, login_attempts_limit
                     FROM account_risk_challenges
                     WHERE risk_challenge_id=$1 AND purpose='login_mfa'",
                    &[&challenge_id],
                )
                .await
                .map_err(log_store_error)?;
            let authority = row
                .map(|row| login_challenge_authority_from_row(&row))
                .transpose()
                .map_err(|reason| {
                    error!(%reason, "PostgreSQL login challenge context row is invalid");
                    StoreError::Unavailable
                })?;
            if let Some(authority) = &authority {
                published.risk_challenges.insert(
                    authority.challenge.risk_challenge_id.clone(),
                    authority.challenge.clone(),
                );
                published.login_challenge_contexts.insert(
                    authority.challenge.risk_challenge_id.clone(),
                    authority.context.clone(),
                );
            } else {
                published.login_challenge_contexts.remove(challenge_id);
            }
            Ok(authority)
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
            let mut published = self.database.write().await;
            let mut client = self.client.lock().await;
            let transaction = client.transaction().await.map_err(log_store_error)?;
            let account_active = transaction
                .query_opt(
                    "SELECT account_id FROM accounts
                     WHERE account_id=$1 AND status='active' FOR UPDATE",
                    &[&challenge.account_id],
                )
                .await
                .map_err(log_store_error)?
                .is_some();
            let device_authorized = if let Some(device_id) = challenge.device_id.as_deref() {
                transaction
                    .query_opt(
                        "SELECT account_id, status FROM devices WHERE device_id=$1 FOR SHARE",
                        &[&device_id],
                    )
                    .await
                    .map_err(log_store_error)?
                    .is_some_and(|row| {
                        row.get::<_, String>("account_id") == challenge.account_id
                            && matches!(
                                row.get::<_, String>("status").as_str(),
                                "online" | "offline" | "busy"
                            )
                    })
            } else {
                false
            };
            if !account_active || !device_authorized {
                return Ok(RiskChallengeCreationOutcome::NotAuthorized);
            }
            let mfa_enabled: bool = transaction
                .query_one(
                    "SELECT EXISTS (
                         SELECT 1 FROM account_mfa_factors
                         WHERE account_id=$1 AND factor_type='totp' AND status='active')",
                    &[&challenge.account_id],
                )
                .await
                .map_err(log_store_error)?
                .get(0);
            let required_methods = if mfa_enabled {
                vec!["totp".to_owned(), "recovery_code".to_owned()]
            } else if challenge.purpose == "password_change" {
                vec!["password".to_owned()]
            } else {
                return Ok(RiskChallengeCreationOutcome::MfaEnrollmentRequired);
            };
            let mut challenge = challenge.clone();
            challenge.required_methods = required_methods;
            validate_new_risk_challenge(&challenge).map_err(|reason| {
                error!(%reason, "PostgreSQL repository rejected invalid risk challenge creation");
                StoreError::Unavailable
            })?;
            let required_methods = Value::Array(
                challenge
                    .required_methods
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            );
            let attempts_remaining = i16::from(challenge.attempts_remaining);
            let expires = to_i64_lossless(challenge.expires_at_epoch_millis);
            let created = to_i64_lossless(challenge.created_at_epoch_millis);

            transaction
                .execute(
                    "INSERT INTO account_risk_challenges (risk_challenge_id, account_id, device_id,
                        purpose, operation_binding_hash, risk_level, required_methods, status,
                        attempts_remaining, ip_address, user_agent, expires_at_epoch_millis,
                        created_at_epoch_millis, verified_at_epoch_millis,
                        consumed_at_epoch_millis)
                     VALUES ($1,$2,$3,$4,$5,$6,$7,'issued',$8,$9::text::inet,$10,$11,$12,NULL,NULL)",
                    &[
                        &challenge.risk_challenge_id,
                        &challenge.account_id,
                        &challenge.device_id,
                        &challenge.purpose,
                        &&challenge.operation_binding_hash[..],
                        &challenge.risk_level,
                        &required_methods,
                        &attempts_remaining,
                        &challenge.ip_address,
                        &challenge.user_agent,
                        &expires,
                        &created,
                    ],
                )
                .await
                .map_err(log_conflict_or_store_error)?;
            insert_audit_entry_strict(&transaction, audit_entry)
                .await
                .map_err(log_conflict_or_store_error)?;
            transaction.commit().await.map_err(log_store_error)?;
            published
                .risk_challenges
                .insert(challenge.risk_challenge_id.clone(), challenge.clone());
            published.audit_logs.push(audit_entry.clone());
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
            validate_new_risk_challenge(&authority.challenge).map_err(|reason| {
                error!(%reason, "PostgreSQL repository rejected invalid login challenge creation");
                StoreError::Unavailable
            })?;
            let challenge = &authority.challenge;
            let context = &authority.context;
            let required_methods = Value::Array(
                challenge
                    .required_methods
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            );
            let attempts_remaining = i16::from(challenge.attempts_remaining);
            let expires = to_i64_lossless(challenge.expires_at_epoch_millis);
            let created = to_i64_lossless(challenge.created_at_epoch_millis);
            let public_key_version =
                i32::try_from(context.public_key_version).map_err(|_| StoreError::Conflict)?;
            let protocol_version = i32::from(context.protocol_version);
            let attempts_limit = i16::from(context.attempts_limit);
            let device_state = login_device_state_name(context.device_state);
            let account_updated = to_i64_lossless(context.account_updated_at_epoch_millis);

            let mut published = self.database.write().await;
            let mut client = self.client.lock().await;
            let transaction = client.transaction().await.map_err(log_store_error)?;
            let account_unchanged = transaction
                .query_opt(
                    "SELECT account_id FROM accounts
                     WHERE account_id=$1 AND status='active'
                       AND updated_at_epoch_millis=$2
                     FOR UPDATE",
                    &[&challenge.account_id, &account_updated],
                )
                .await
                .map_err(log_store_error)?
                .is_some();
            if !account_unchanged {
                return Err(StoreError::Conflict);
            }
            transaction
                .execute(
                    "INSERT INTO account_risk_challenges (risk_challenge_id, account_id,
                        device_id, purpose, operation_binding_hash, risk_level, required_methods,
                        status, attempts_remaining, ip_address, user_agent,
                        expires_at_epoch_millis, created_at_epoch_millis,
                        verified_at_epoch_millis, consumed_at_epoch_millis,
                        login_device_state, login_device_id, login_device_public_key,
                        login_device_public_key_fingerprint, login_public_key_id,
                        login_public_key_version, login_client_nonce, login_server_nonce,
                        login_request_binding_hash, login_ip_address_hash,
                        login_user_agent_hash, login_trusted_device_id,
                        login_protocol_version, login_attempts_limit,
                        login_account_updated_at_epoch_millis)
                     VALUES ($1,$2,$3,$4,$5,$6,$7,'issued',$8,$9::text::inet,$10,$11,$12,
                        NULL,NULL,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27)",
                    &[
                        &challenge.risk_challenge_id,
                        &challenge.account_id,
                        &challenge.device_id,
                        &challenge.purpose,
                        &&challenge.operation_binding_hash[..],
                        &challenge.risk_level,
                        &required_methods,
                        &attempts_remaining,
                        &challenge.ip_address,
                        &challenge.user_agent,
                        &expires,
                        &created,
                        &device_state,
                        &context.device_id,
                        &&context.device_public_key[..],
                        &&context.device_public_key_fingerprint[..],
                        &context.public_key_id,
                        &public_key_version,
                        &&context.client_nonce[..],
                        &&context.server_nonce[..],
                        &&context.login_request_binding_hash[..],
                        &&context.ip_address_hash[..],
                        &&context.user_agent_hash[..],
                        &context.trusted_device_id,
                        &protocol_version,
                        &attempts_limit,
                        &account_updated,
                    ],
                )
                .await
                .map_err(log_conflict_or_store_error)?;
            insert_audit_entry_strict(&transaction, audit_entry)
                .await
                .map_err(log_conflict_or_store_error)?;
            transaction.commit().await.map_err(log_store_error)?;
            published
                .risk_challenges
                .insert(challenge.risk_challenge_id.clone(), challenge.clone());
            published
                .login_challenge_contexts
                .insert(challenge.risk_challenge_id.clone(), context.clone());
            published.audit_logs.push(audit_entry.clone());
            Ok(())
        })
    }

    fn cancel_risk_challenge<'a>(
        &'a self,
        challenge_id: &'a str,
        audit_entry: &'a AuditEntry,
    ) -> RepositoryFuture<'a, Result<bool, StoreError>> {
        Box::pin(async move {
            let mut published = self.database.write().await;
            let mut client = self.client.lock().await;
            let transaction = client.transaction().await.map_err(log_store_error)?;
            let updated = transaction
                .query_opt(
                    "UPDATE account_risk_challenges SET status='cancelled'
                     WHERE risk_challenge_id=$1 AND status='issued'
                     RETURNING risk_challenge_id, account_id, device_id, purpose,
                               operation_binding_hash, risk_level, required_methods, status,
                               attempts_remaining, ip_address::text AS ip_address, user_agent,
                               expires_at_epoch_millis, created_at_epoch_millis,
                               verified_at_epoch_millis, consumed_at_epoch_millis",
                    &[&challenge_id],
                )
                .await
                .map_err(log_store_error)?;
            let transitioned = updated.is_some();
            let row = match updated {
                Some(row) => Some(row),
                None => transaction
                    .query_opt(
                        "SELECT risk_challenge_id, account_id, device_id, purpose,
                                operation_binding_hash, risk_level, required_methods, status,
                                attempts_remaining, ip_address::text AS ip_address, user_agent,
                                expires_at_epoch_millis, created_at_epoch_millis,
                                verified_at_epoch_millis, consumed_at_epoch_millis
                         FROM account_risk_challenges WHERE risk_challenge_id=$1",
                        &[&challenge_id],
                    )
                    .await
                    .map_err(log_store_error)?,
            };
            let authoritative = row
                .map(|row| risk_challenge_from_row(&row))
                .transpose()
                .map_err(|reason| {
                    error!(%reason, "PostgreSQL cancelled risk challenge row is invalid");
                    StoreError::Unavailable
                })?;
            if transitioned {
                let challenge = authoritative.as_ref().ok_or(StoreError::Unavailable)?;
                if !risk_challenge_cancel_audit_is_valid(challenge, audit_entry) {
                    return Err(StoreError::Conflict);
                }
                insert_audit_entry_strict(&transaction, audit_entry)
                    .await
                    .map_err(log_conflict_or_store_error)?;
            }
            transaction.commit().await.map_err(log_store_error)?;

            if let Some(challenge) = authoritative {
                published
                    .risk_challenges
                    .insert(challenge.risk_challenge_id.clone(), challenge);
            } else {
                published.risk_challenges.remove(challenge_id);
            }
            if transitioned {
                published.audit_logs.push(audit_entry.clone());
            }
            Ok(transitioned)
        })
    }

    fn load_refresh_session_authority<'a>(
        &'a self,
        refresh_token_hash: &'a [u8; 32],
        now_epoch_millis: u64,
    ) -> RepositoryFuture<'a, Result<Option<AccountSession>, StoreError>> {
        Box::pin(async move {
            let client = self.client.lock().await;
            let now = to_i64_lossless(now_epoch_millis);
            let row = client
                .query_opt(
                    LOAD_REFRESH_ACCOUNT_SESSION_SQL,
                    &[&&refresh_token_hash[..], &now],
                )
                .await
                .map_err(log_store_error)?;
            row.map(|row| account_session_from_row(&row))
                .transpose()
                .map_err(|reason| {
                    error!(%reason, "PostgreSQL refresh session authority row is invalid");
                    StoreError::Unavailable
                })
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
            if replacement.revoked_at_epoch_millis.is_some()
                || replacement.revoked_reason.is_some()
                || replacement.expires_at_epoch_millis <= now_epoch_millis
                || audit_entry.actor_account_id.as_deref() != Some(replacement.account_id.as_str())
            {
                return Err(StoreError::Conflict);
            }
            let mut published = self.database.write().await;
            let mut client = self.client.lock().await;
            let transaction = client.transaction().await.map_err(log_store_error)?;
            let account_active = transaction
                .query_opt(
                    "SELECT account_id FROM accounts
                     WHERE account_id=$1 AND status='active' FOR UPDATE",
                    &[&replacement.account_id],
                )
                .await
                .map_err(log_store_error)?
                .is_some();
            if !account_active {
                return Ok(false);
            }
            let now = to_i64_lossless(now_epoch_millis);
            let old_row = transaction
                .query_opt(
                    ROTATE_REFRESH_ACCOUNT_SESSION_SQL,
                    &[
                        &&refresh_token_hash[..],
                        &replacement.account_id,
                        &now,
                        &replacement.mfa_verified,
                    ],
                )
                .await
                .map_err(log_store_error)?;
            let Some(old_row) = old_row else {
                return Ok(false);
            };
            let old_session = account_session_from_row(&old_row).map_err(|reason| {
                error!(%reason, "PostgreSQL rotated refresh session row is invalid");
                StoreError::Unavailable
            })?;
            let expires = to_i64_lossless(replacement.expires_at_epoch_millis);
            transaction
                .execute(
                    INSERT_ACCOUNT_SESSION_SQL,
                    &[
                        &replacement.account_session_id,
                        &replacement.account_id,
                        &&replacement.refresh_token_hash[..],
                        &replacement.mfa_verified,
                        &expires,
                        &now,
                    ],
                )
                .await
                .map_err(log_conflict_or_store_error)?;
            insert_audit_entry_strict(&transaction, audit_entry)
                .await
                .map_err(log_conflict_or_store_error)?;
            transaction.commit().await.map_err(log_store_error)?;
            published
                .account_sessions
                .insert(old_session.account_session_id.clone(), old_session);
            published
                .account_sessions
                .insert(replacement.account_session_id.clone(), replacement.clone());
            published.audit_logs.push(audit_entry.clone());
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
            let mut published = self.database.write().await;
            if audit_entry.actor_account_id.as_deref() != Some(account_id)
                || audit_entry.action != "logout"
                || audit_entry.result != "success"
            {
                return Err(StoreError::Conflict);
            }
            let mut client = self.client.lock().await;
            let transaction = client.transaction().await.map_err(log_store_error)?;
            let now = to_i64_lossless(now_epoch_millis);
            let row = transaction
                .query_opt(
                    "UPDATE account_sessions
                     SET revoked_at_epoch_millis=$3, revoked_reason='logout',
                         updated_at_epoch_millis=$3
                     WHERE account_session_id=$1 AND account_id=$2
                       AND revoked_at_epoch_millis IS NULL AND revoked_reason IS NULL
                     RETURNING account_session_id",
                    &[&account_session_id, &account_id, &now],
                )
                .await
                .map_err(log_store_error)?;
            let Some(_) = row else {
                transaction.commit().await.map_err(log_store_error)?;
                return Ok(false);
            };
            let revocation_audit =
                account_session_revocation_audit(audit_entry, account_session_id, "logout");
            insert_audit_entry_strict(&transaction, &revocation_audit)
                .await
                .map_err(log_conflict_or_store_error)?;
            insert_audit_entry_strict(&transaction, audit_entry)
                .await
                .map_err(log_conflict_or_store_error)?;
            transaction.commit().await.map_err(log_store_error)?;
            if let Some(session) = published.account_sessions.get_mut(account_session_id) {
                session.revoked_at_epoch_millis = Some(now_epoch_millis);
                session.revoked_reason = Some("logout".to_owned());
            }
            published.audit_logs.push(revocation_audit);
            published.audit_logs.push(audit_entry.clone());
            Ok(true)
        })
    }

    fn load_device_authority<'a>(
        &'a self,
        device_id: &'a str,
    ) -> RepositoryFuture<'a, Result<Option<Device>, StoreError>> {
        Box::pin(async move {
            let client = self.client.lock().await;
            let sql = format!("{DEVICE_AUTHORITY_SELECT} WHERE d.device_id=$1");
            let row = client
                .query_opt(&sql, &[&device_id])
                .await
                .map_err(log_store_error)?;
            row.map(|row| device_from_row(&row).map(|(device, _)| device))
                .transpose()
                .map_err(|reason| {
                    error!(%reason, "PostgreSQL authority device row is invalid");
                    StoreError::Unavailable
                })
        })
    }

    fn load_session_authority<'a>(
        &'a self,
        session_id: &'a str,
    ) -> RepositoryFuture<'a, Result<Option<Session>, StoreError>> {
        Box::pin(async move {
            let client = self.client.lock().await;
            let sql = format!("{SESSION_AUTHORITY_SELECT} WHERE session_id=$1");
            let row = client
                .query_opt(&sql, &[&session_id])
                .await
                .map_err(log_store_error)?;
            row.map(|row| session_from_row(&row))
                .transpose()
                .map_err(|reason| {
                    error!(%reason, "PostgreSQL authority session row is invalid");
                    StoreError::Unavailable
                })
        })
    }

    fn list_devices_for_account<'a>(
        &'a self,
        account_id: &'a str,
    ) -> RepositoryFuture<'a, Result<Vec<Device>, StoreError>> {
        Box::pin(async move {
            let client = self.client.lock().await;
            let sql = format!(
                "{DEVICE_AUTHORITY_SELECT} WHERE d.account_id=$1 ORDER BY d.created_at_epoch_millis, d.device_id"
            );
            let rows = client
                .query(&sql, &[&account_id])
                .await
                .map_err(log_store_error)?;
            rows.iter()
                .map(|row| device_from_row(row).map(|(device, _)| device))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|reason| {
                    error!(%reason, "PostgreSQL authority device list is invalid");
                    StoreError::Unavailable
                })
        })
    }

    fn list_trusted_devices_for_account<'a>(
        &'a self,
        account_id: &'a str,
    ) -> RepositoryFuture<'a, Result<Vec<TrustedControllerDevice>, StoreError>> {
        Box::pin(async move {
            let client = self.client.lock().await;
            let rows = client
                .query(
                    "SELECT trusted_device_id, account_id, controller_device_id,
                            device_fingerprint_hash, trust_level, status, trust_proof_type,
                            created_at_epoch_millis, last_used_at_epoch_millis,
                            expires_at_epoch_millis, revoked_at_epoch_millis
                     FROM trusted_controller_devices
                     WHERE account_id=$1 ORDER BY created_at_epoch_millis, trusted_device_id",
                    &[&account_id],
                )
                .await
                .map_err(log_store_error)?;
            rows.iter()
                .map(trusted_device_from_row)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|reason| {
                    error!(%reason, "PostgreSQL trusted device list is invalid");
                    StoreError::Unavailable
                })
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
            let client = self.client.lock().await;
            let sql = format!(
                "SELECT authority.*, EXISTS (\
                     SELECT 1 FROM account_sessions \
                     WHERE account_session_id=$1 AND account_id=$2 \
                       AND revoked_at_epoch_millis IS NULL \
                       AND revoked_reason IS NULL \
                       AND expires_at_epoch_millis > $3) AS account_session_active \
                 FROM ({DEVICE_AUTHORITY_SELECT}) AS authority \
                 WHERE authority.device_id=$4"
            );
            let now = to_i64_lossless(now_epoch_millis);
            let row = client
                .query_opt(&sql, &[&account_session_id, &account_id, &now, &device_id])
                .await
                .map_err(log_store_error)?;
            row.map(|row| {
                let device = device_from_row(&row)
                    .map(|(device, _)| device)
                    .map_err(|reason| {
                        error!(%reason, "PostgreSQL signal authority device row is invalid");
                        StoreError::Unavailable
                    })?;
                Ok((row.get("account_session_active"), device))
            })
            .transpose()
        })
    }

    fn load_session_device_authority<'a>(
        &'a self,
        session_id: &'a str,
        device_id: &'a str,
    ) -> RepositoryFuture<'a, Result<SessionDeviceAuthority, StoreError>> {
        Box::pin(async move {
            let mut client = self.client.lock().await;
            let transaction = client
                .build_transaction()
                .isolation_level(IsolationLevel::RepeatableRead)
                .read_only(true)
                .start()
                .await
                .map_err(log_store_error)?;
            let session_sql = format!("{SESSION_AUTHORITY_SELECT} WHERE session_id=$1");
            let device_sql = format!("{DEVICE_AUTHORITY_SELECT} WHERE d.device_id=$1");
            let session_row = transaction
                .query_opt(&session_sql, &[&session_id])
                .await
                .map_err(log_store_error)?;
            let device_row = transaction
                .query_opt(&device_sql, &[&device_id])
                .await
                .map_err(log_store_error)?;
            let session = session_row
                .map(|row| session_from_row(&row))
                .transpose()
                .map_err(|reason| {
                    error!(%reason, "PostgreSQL authority session row is invalid");
                    StoreError::Unavailable
                })?;
            let device = device_row
                .map(|row| device_from_row(&row).map(|(device, _)| device))
                .transpose()
                .map_err(|reason| {
                    error!(%reason, "PostgreSQL authority device row is invalid");
                    StoreError::Unavailable
                })?;
            transaction.commit().await.map_err(log_store_error)?;
            Ok((session, device))
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
            let mut published = self.database.write().await;
            let mut client = self.client.lock().await;
            let transaction = client.transaction().await.map_err(log_store_error)?;
            let now = to_i64_lossless(now_epoch_millis);

            let challenge_attempts = if let Some(challenge_id) = challenge_id {
                let row = transaction
                    .query_opt(
                        "SELECT attempts_remaining FROM account_risk_challenges
                         WHERE risk_challenge_id=$1 AND account_id=$2
                           AND status='issued' AND attempts_remaining > 0
                           AND expires_at_epoch_millis > $3
                         FOR UPDATE",
                        &[&challenge_id, &account_id, &now],
                    )
                    .await
                    .map_err(log_store_error)?
                    .ok_or(StoreError::Conflict)?;
                Some(row.get::<_, i16>("attempts_remaining"))
            } else {
                None
            };

            let mut accepted_totp = None;
            let mut accepted_recovery_code = None;
            let accepted = match factor_kind {
                "totp" => {
                    let row = transaction
                        .query_opt(
                            "SELECT factor_id, encrypted_secret, created_at_epoch_millis
                             FROM account_mfa_factors
                             WHERE account_id=$1 AND factor_type='totp' AND status='active'
                             FOR UPDATE",
                            &[&account_id],
                        )
                        .await
                        .map_err(log_store_error)?;
                    if let Some(row) = row {
                        let factor_id: String = row.get("factor_id");
                        let payload = decrypt_mfa(
                            &self.mfa_secret_key,
                            account_id,
                            &factor_id,
                            &row.get::<_, Vec<u8>>("encrypted_secret"),
                        )
                        .map_err(|reason| {
                            error!(%reason, "PostgreSQL MFA factor cannot be decrypted");
                            StoreError::Unavailable
                        })?;
                        let mut factor = MfaFactor {
                            factor_id: factor_id.clone(),
                            account_id: account_id.to_owned(),
                            secret_base32: payload.secret_base32,
                            active: true,
                            last_used_counter: payload.last_used_counter,
                            created_at_epoch_millis: from_i64(row.get("created_at_epoch_millis"))
                                .map_err(|reason| {
                                error!(%reason, "PostgreSQL MFA factor timestamp is invalid");
                                StoreError::Unavailable
                            })?,
                        };
                        if let Some(counter) = verify_totp(
                            &factor.secret_base32,
                            code,
                            now_epoch_millis,
                            factor.last_used_counter,
                        ) {
                            factor.last_used_counter = Some(counter);
                            let encrypted =
                                encrypt_mfa(&self.mfa_secret_key, &factor).map_err(|reason| {
                                    error!(%reason, "PostgreSQL MFA factor cannot be encrypted");
                                    StoreError::Unavailable
                                })?;
                            let updated = transaction
                                .execute(
                                    "UPDATE account_mfa_factors
                                     SET encrypted_secret=$2, last_used_at_epoch_millis=$3
                                     WHERE factor_id=$1 AND account_id=$4 AND status='active'",
                                    &[&factor_id, &encrypted, &now, &account_id],
                                )
                                .await
                                .map_err(log_store_error)?;
                            if updated != 1 {
                                return Err(StoreError::Conflict);
                            }
                            accepted_totp = Some((factor_id, counter));
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
                "recovery_code" => {
                    let code_hash = sha256(code.as_bytes());
                    let row = transaction
                        .query_opt(
                            "UPDATE account_recovery_codes
                             SET status='used', used_at_epoch_millis=$3
                             WHERE account_id=$1 AND code_hash=$2 AND status='active'
                               AND (expires_at_epoch_millis IS NULL OR expires_at_epoch_millis > $3)
                             RETURNING recovery_code_id",
                            &[&account_id, &&code_hash[..], &now],
                        )
                        .await
                        .map_err(log_store_error)?;
                    accepted_recovery_code =
                        row.map(|row| row.get::<_, String>("recovery_code_id"));
                    accepted_recovery_code.is_some()
                }
                _ => false,
            };

            let challenge_outcome =
                if let (Some(challenge_id), Some(attempts)) = (challenge_id, challenge_attempts) {
                    let remaining = if accepted {
                        attempts
                    } else {
                        attempts.checked_sub(1).ok_or(StoreError::Conflict)?
                    };
                    let status = if accepted {
                        "verified"
                    } else if remaining == 0 {
                        "failed"
                    } else {
                        "issued"
                    };
                    let verified_at = accepted.then_some(now);
                    let updated = transaction
                        .execute(
                            "UPDATE account_risk_challenges
                         SET attempts_remaining=$2, status=$3, verified_at_epoch_millis=$4
                         WHERE risk_challenge_id=$1 AND status='issued'",
                            &[&challenge_id, &remaining, &status, &verified_at],
                        )
                        .await
                        .map_err(log_store_error)?;
                    if updated != 1 {
                        return Err(StoreError::Conflict);
                    }
                    Some((
                        u8::try_from(remaining).map_err(|_| StoreError::Unavailable)?,
                        if accepted {
                            RiskChallengeStatus::Verified
                        } else if remaining == 0 {
                            RiskChallengeStatus::Failed
                        } else {
                            RiskChallengeStatus::Issued
                        },
                    ))
                } else {
                    None
                };
            transaction.commit().await.map_err(log_store_error)?;

            if let Some((factor_id, counter)) = accepted_totp {
                if let Some(factor) = published.mfa_factors.get_mut(&factor_id) {
                    factor.last_used_counter = Some(counter);
                }
            }
            if let Some(recovery_code_id) = accepted_recovery_code {
                if let Some(recovery) = published.recovery_codes.get_mut(&recovery_code_id) {
                    recovery.used_at_epoch_millis = Some(now_epoch_millis);
                }
            }
            if let (Some(challenge_id), Some((remaining, status))) =
                (challenge_id, challenge_outcome)
            {
                if let Some(challenge) = published.risk_challenges.get_mut(challenge_id) {
                    challenge.attempts_remaining = remaining;
                    challenge.status = status;
                    if accepted {
                        challenge.verified_at_epoch_millis = Some(now_epoch_millis);
                    }
                }
            }
            Ok(accepted)
        })
    }

    fn verify_risk_challenge<'a>(
        &'a self,
        verification: &'a RiskChallengeVerification,
    ) -> RepositoryFuture<'a, Result<RiskChallengeVerificationOutcome, StoreError>> {
        Box::pin(async move {
            if verification.success_audit_entry.actor_account_id.as_deref()
                != Some(verification.account_id.as_str())
                || verification.failure_audit_entry.actor_account_id.as_deref()
                    != Some(verification.account_id.as_str())
                || verification
                    .recovery_code_audit_entry
                    .as_ref()
                    .is_some_and(|entry| {
                        entry.actor_account_id.as_deref() != Some(verification.account_id.as_str())
                    })
            {
                return Err(StoreError::Conflict);
            }

            let mut published = self.database.write().await;
            let mut client = self.client.lock().await;
            let transaction = client.transaction().await.map_err(log_store_error)?;
            let now = to_i64_lossless(verification.now_epoch_millis);
            let account_row = transaction
                .query_opt(
                    "SELECT password_hash, status FROM accounts
                     WHERE account_id=$1 FOR UPDATE",
                    &[&verification.account_id],
                )
                .await
                .map_err(log_store_error)?;
            let Some(account_row) = account_row else {
                return Ok(RiskChallengeVerificationOutcome::Rejected);
            };
            if account_row.get::<_, String>("status") != "active" {
                return Ok(RiskChallengeVerificationOutcome::Rejected);
            }
            let password_hash: String = account_row.get("password_hash");
            let challenge_row = transaction
                .query_opt(
                    "SELECT risk_challenge_id, account_id, device_id, purpose,
                            operation_binding_hash, risk_level, required_methods, status,
                            attempts_remaining, ip_address::text AS ip_address, user_agent,
                            expires_at_epoch_millis, created_at_epoch_millis,
                            verified_at_epoch_millis, consumed_at_epoch_millis
                     FROM account_risk_challenges
                     WHERE risk_challenge_id=$1 FOR UPDATE",
                    &[&verification.challenge_id],
                )
                .await
                .map_err(log_store_error)?;
            let Some(challenge_row) = challenge_row else {
                return Ok(RiskChallengeVerificationOutcome::Rejected);
            };
            let mut challenge = risk_challenge_from_row(&challenge_row).map_err(|reason| {
                error!(%reason, "PostgreSQL locked step-up challenge row is invalid");
                StoreError::Unavailable
            })?;
            if challenge.account_id != verification.account_id || challenge.purpose == "login_mfa" {
                return Ok(RiskChallengeVerificationOutcome::Rejected);
            }
            let device_row = if let Some(device_id) = challenge.device_id.as_deref() {
                transaction
                    .query_opt(
                        "SELECT account_id, status FROM devices WHERE device_id=$1 FOR UPDATE",
                        &[&device_id],
                    )
                    .await
                    .map_err(log_store_error)?
            } else {
                None
            };
            let device_authorized = device_row.is_some_and(|row| {
                row.get::<_, String>("account_id") == verification.account_id
                    && matches!(
                        row.get::<_, String>("status").as_str(),
                        "online" | "offline" | "busy"
                    )
            });
            if !device_authorized {
                return Ok(RiskChallengeVerificationOutcome::Rejected);
            }
            if challenge.status == RiskChallengeStatus::Verified
                && challenge.verified_at_epoch_millis.is_some()
                && challenge.consumed_at_epoch_millis.is_none()
                && challenge.expires_at_epoch_millis > verification.now_epoch_millis
            {
                transaction.commit().await.map_err(log_store_error)?;
                published
                    .risk_challenges
                    .insert(challenge.risk_challenge_id.clone(), challenge.clone());
                return Ok(RiskChallengeVerificationOutcome::AlreadyVerified(challenge));
            }
            if challenge.status != RiskChallengeStatus::Issued
                || challenge.attempts_remaining == 0
                || challenge.consumed_at_epoch_millis.is_some()
            {
                return Ok(RiskChallengeVerificationOutcome::Rejected);
            }
            if challenge.expires_at_epoch_millis <= verification.now_epoch_millis {
                let affected = transaction
                    .execute(
                        "UPDATE account_risk_challenges SET status='expired'
                         WHERE risk_challenge_id=$1 AND status='issued'",
                        &[&verification.challenge_id],
                    )
                    .await
                    .map_err(log_store_error)?;
                if affected != 1 {
                    return Err(StoreError::Conflict);
                }
                let mut audit = verification.failure_audit_entry.clone();
                audit.reason = Some("expired".to_owned());
                insert_audit_entry_strict(&transaction, &audit)
                    .await
                    .map_err(log_conflict_or_store_error)?;
                transaction.commit().await.map_err(log_store_error)?;
                challenge.status = RiskChallengeStatus::Expired;
                published
                    .risk_challenges
                    .insert(challenge.risk_challenge_id.clone(), challenge);
                published.audit_logs.push(audit);
                return Ok(RiskChallengeVerificationOutcome::Rejected);
            }

            let method_allowed = challenge
                .required_methods
                .iter()
                .any(|method| method == &verification.factor_kind);
            let mut accepted_totp = None;
            let mut accepted_recovery_code = None;
            let accepted = if !method_allowed {
                false
            } else {
                match verification.factor_kind.as_str() {
                    "password" => {
                        challenge.purpose == "password_change"
                            && verify_password(&password_hash, &verification.factor_code)
                    }
                    "totp" => {
                        let row = transaction
                            .query_opt(
                                "SELECT factor_id, encrypted_secret, created_at_epoch_millis
                                 FROM account_mfa_factors
                                 WHERE account_id=$1 AND factor_type='totp' AND status='active'
                                 FOR UPDATE",
                                &[&verification.account_id],
                            )
                            .await
                            .map_err(log_store_error)?;
                        if let Some(row) = row {
                            let factor_id: String = row.get("factor_id");
                            let payload = decrypt_mfa(
                                &self.mfa_secret_key,
                                &verification.account_id,
                                &factor_id,
                                &row.get::<_, Vec<u8>>("encrypted_secret"),
                            )
                            .map_err(|reason| {
                                error!(%reason, "PostgreSQL step-up MFA factor cannot be decrypted");
                                StoreError::Unavailable
                            })?;
                            let mut factor = MfaFactor {
                                factor_id: factor_id.clone(),
                                account_id: verification.account_id.clone(),
                                secret_base32: payload.secret_base32,
                                active: true,
                                last_used_counter: payload.last_used_counter,
                                created_at_epoch_millis: from_i64(
                                    row.get("created_at_epoch_millis"),
                                )
                                .map_err(|reason| {
                                    error!(%reason, "PostgreSQL step-up MFA timestamp is invalid");
                                    StoreError::Unavailable
                                })?,
                            };
                            if let Some(counter) = verify_totp(
                                &factor.secret_base32,
                                &verification.factor_code,
                                verification.now_epoch_millis,
                                factor.last_used_counter,
                            ) {
                                factor.last_used_counter = Some(counter);
                                let encrypted = encrypt_mfa(&self.mfa_secret_key, &factor)
                                    .map_err(|reason| {
                                        error!(%reason, "PostgreSQL step-up MFA factor cannot be encrypted");
                                        StoreError::Unavailable
                                    })?;
                                let updated = transaction
                                    .execute(
                                        "UPDATE account_mfa_factors
                                         SET encrypted_secret=$2, last_used_at_epoch_millis=$3
                                         WHERE factor_id=$1 AND account_id=$4 AND status='active'",
                                        &[&factor_id, &encrypted, &now, &verification.account_id],
                                    )
                                    .await
                                    .map_err(log_store_error)?;
                                if updated != 1 {
                                    return Err(StoreError::Conflict);
                                }
                                accepted_totp = Some((factor_id, counter));
                                true
                            } else {
                                false
                            }
                        } else {
                            false
                        }
                    }
                    "recovery_code" => {
                        let code_hash = sha256(verification.factor_code.as_bytes());
                        let row = transaction
                            .query_opt(
                                "UPDATE account_recovery_codes
                                 SET status='used', used_at_epoch_millis=$3
                                 WHERE account_id=$1 AND code_hash=$2 AND status='active'
                                   AND (expires_at_epoch_millis IS NULL OR expires_at_epoch_millis > $3)
                                 RETURNING recovery_code_id",
                                &[&verification.account_id, &&code_hash[..], &now],
                            )
                            .await
                            .map_err(log_store_error)?;
                        accepted_recovery_code =
                            row.map(|row| row.get::<_, String>("recovery_code_id"));
                        accepted_recovery_code.is_some()
                    }
                    _ => false,
                }
            };

            let remaining = if accepted {
                challenge.attempts_remaining
            } else {
                challenge
                    .attempts_remaining
                    .checked_sub(1)
                    .ok_or(StoreError::Conflict)?
            };
            let status = if accepted {
                "verified"
            } else if remaining == 0 {
                "failed"
            } else {
                "issued"
            };
            let verified_at = accepted.then_some(now);
            let updated = transaction
                .execute(
                    "UPDATE account_risk_challenges
                     SET attempts_remaining=$2, status=$3, verified_at_epoch_millis=$4
                     WHERE risk_challenge_id=$1 AND status='issued'",
                    &[
                        &verification.challenge_id,
                        &i16::from(remaining),
                        &status,
                        &verified_at,
                    ],
                )
                .await
                .map_err(log_store_error)?;
            if updated != 1 {
                return Err(StoreError::Conflict);
            }
            if accepted {
                insert_audit_entry_strict(&transaction, &verification.success_audit_entry)
                    .await
                    .map_err(log_conflict_or_store_error)?;
                if verification.factor_kind == "recovery_code" {
                    let recovery_audit = verification
                        .recovery_code_audit_entry
                        .as_ref()
                        .ok_or(StoreError::Conflict)?;
                    insert_audit_entry_strict(&transaction, recovery_audit)
                        .await
                        .map_err(log_conflict_or_store_error)?;
                }
            } else {
                insert_audit_entry_strict(&transaction, &verification.failure_audit_entry)
                    .await
                    .map_err(log_conflict_or_store_error)?;
            }
            transaction.commit().await.map_err(log_store_error)?;

            challenge.attempts_remaining = remaining;
            challenge.status = if accepted {
                RiskChallengeStatus::Verified
            } else if remaining == 0 {
                RiskChallengeStatus::Failed
            } else {
                RiskChallengeStatus::Issued
            };
            if accepted {
                challenge.verified_at_epoch_millis = Some(verification.now_epoch_millis);
            }
            if let Some((factor_id, counter)) = accepted_totp {
                if let Some(factor) = published.mfa_factors.get_mut(&factor_id) {
                    factor.last_used_counter = Some(counter);
                }
            }
            if let Some(recovery_code_id) = accepted_recovery_code {
                if let Some(recovery) = published.recovery_codes.get_mut(&recovery_code_id) {
                    recovery.used_at_epoch_millis = Some(verification.now_epoch_millis);
                }
            }
            published
                .risk_challenges
                .insert(challenge.risk_challenge_id.clone(), challenge.clone());
            if accepted {
                published
                    .audit_logs
                    .push(verification.success_audit_entry.clone());
                if verification.factor_kind == "recovery_code" {
                    published.audit_logs.push(
                        verification
                            .recovery_code_audit_entry
                            .clone()
                            .ok_or(StoreError::Conflict)?,
                    );
                }
                Ok(RiskChallengeVerificationOutcome::Verified(challenge))
            } else {
                published
                    .audit_logs
                    .push(verification.failure_audit_entry.clone());
                Ok(RiskChallengeVerificationOutcome::Rejected)
            }
        })
    }

    fn consume_step_up<'a>(
        &'a self,
        expectation: &'a StepUpExpectation,
    ) -> RepositoryFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let mut published = self.database.write().await;
            let mut client = self.client.lock().await;
            let transaction = client.transaction().await.map_err(log_store_error)?;
            let now = to_i64_lossless(expectation.now_epoch_millis);
            let affected = transaction
                .execute(
                    "UPDATE account_risk_challenges
                     SET status='consumed', consumed_at_epoch_millis=$6
                     WHERE risk_challenge_id=$1 AND account_id=$2 AND device_id=$3
                       AND purpose=$4 AND operation_binding_hash=$5
                       AND status='verified' AND verified_at_epoch_millis IS NOT NULL
                       AND consumed_at_epoch_millis IS NULL
                       AND expires_at_epoch_millis > $6",
                    &[
                        &expectation.challenge_id,
                        &expectation.account_id,
                        &expectation.device_id,
                        &expectation.purpose,
                        &&expectation.operation_binding_hash[..],
                        &now,
                    ],
                )
                .await
                .map_err(log_store_error)?;
            if affected != 1 {
                return Err(StoreError::Conflict);
            }
            transaction.commit().await.map_err(log_store_error)?;
            if let Some(challenge) = published.risk_challenges.get_mut(&expectation.challenge_id) {
                if challenge.account_id == expectation.account_id
                    && challenge.device_id.as_deref() == Some(expectation.device_id.as_str())
                {
                    challenge.status = RiskChallengeStatus::Consumed;
                    challenge.consumed_at_epoch_millis = Some(expectation.now_epoch_millis);
                }
            }
            Ok(())
        })
    }

    fn apply_step_up_action<'a>(
        &'a self,
        expectation: &'a StepUpExpectation,
        action: &'a StepUpAction,
    ) -> RepositoryFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let mut authority_revocation_audits = Vec::new();
            match action {
                StepUpAction::RotateRecoveryCodes { records, .. }
                    if expectation.purpose != "recovery_code_rotate"
                        || records.is_empty()
                        || records
                            .iter()
                            .any(|record| record.account_id != expectation.account_id) =>
                {
                    return Err(StoreError::Conflict);
                }
                StepUpAction::DisableMfaFactor { .. }
                    if expectation.purpose != "mfa_factor_change" =>
                {
                    return Err(StoreError::Conflict);
                }
                StepUpAction::ChangePassword {
                    expected_password_hash,
                    new_password_hash,
                    ..
                } if expectation.purpose != "password_change"
                    || expected_password_hash.is_empty()
                    || new_password_hash.is_empty()
                    || expected_password_hash == new_password_hash =>
                {
                    return Err(StoreError::Conflict);
                }
                StepUpAction::RevokeTrustedDevice { .. }
                    if expectation.purpose != "trusted_device_change" =>
                {
                    return Err(StoreError::Conflict);
                }
                _ => {}
            }

            let mut published = self.database.write().await;
            let mut client = self.client.lock().await;
            let transaction = client.transaction().await.map_err(log_store_error)?;
            let now = to_i64_lossless(expectation.now_epoch_millis);
            let account_active = transaction
                .query_opt(
                    "SELECT account_id FROM accounts
                     WHERE account_id=$1 AND status='active' FOR UPDATE",
                    &[&expectation.account_id],
                )
                .await
                .map_err(log_store_error)?
                .is_some();
            if !account_active {
                return Err(StoreError::Conflict);
            }
            let device_authorized = transaction
                .query_opt(
                    "SELECT account_id, status FROM devices WHERE device_id=$1 FOR UPDATE",
                    &[&expectation.device_id],
                )
                .await
                .map_err(log_store_error)?
                .is_some_and(|row| {
                    row.get::<_, String>("account_id") == expectation.account_id
                        && matches!(
                            row.get::<_, String>("status").as_str(),
                            "online" | "offline" | "busy"
                        )
                });
            if !device_authorized {
                return Err(StoreError::Conflict);
            }
            let consumed = transaction
                .execute(
                    "UPDATE account_risk_challenges
                     SET status='consumed', consumed_at_epoch_millis=$6
                     WHERE risk_challenge_id=$1 AND account_id=$2 AND device_id=$3
                       AND purpose=$4 AND operation_binding_hash=$5
                       AND status='verified' AND verified_at_epoch_millis IS NOT NULL
                       AND consumed_at_epoch_millis IS NULL
                       AND expires_at_epoch_millis > $6",
                    &[
                        &expectation.challenge_id,
                        &expectation.account_id,
                        &expectation.device_id,
                        &expectation.purpose,
                        &&expectation.operation_binding_hash[..],
                        &now,
                    ],
                )
                .await
                .map_err(log_store_error)?;
            if consumed != 1 {
                return Err(StoreError::Conflict);
            }

            match action {
                StepUpAction::RotateRecoveryCodes { records, .. } => {
                    transaction
                        .execute(
                            "UPDATE account_recovery_codes SET status='revoked'
                             WHERE account_id=$1 AND status='active'",
                            &[&expectation.account_id],
                        )
                        .await
                        .map_err(log_store_error)?;
                    for record in records {
                        transaction
                            .execute(
                                "INSERT INTO account_recovery_codes
                                    (recovery_code_id, account_id, code_hash, status,
                                     used_at_epoch_millis, created_at_epoch_millis,
                                     expires_at_epoch_millis)
                                 VALUES ($1,$2,$3,'active',NULL,$4,$5)",
                                &[
                                    &record.recovery_code_id,
                                    &record.account_id,
                                    &&record.code_hash[..],
                                    &now,
                                    &record.expires_at_epoch_millis.map(to_i64_lossless),
                                ],
                            )
                            .await
                            .map_err(log_store_error)?;
                    }
                }
                StepUpAction::DisableMfaFactor { factor_id, .. } => {
                    let affected = transaction
                        .execute(
                            "UPDATE account_mfa_factors
                             SET status='disabled', disabled_at_epoch_millis=$3
                             WHERE factor_id=$1 AND account_id=$2 AND status='active'",
                            &[&factor_id, &expectation.account_id, &now],
                        )
                        .await
                        .map_err(log_store_error)?;
                    if affected != 1 {
                        return Err(StoreError::Conflict);
                    }
                    let any_active: bool = transaction
                        .query_one(
                            "SELECT EXISTS (
                                 SELECT 1 FROM account_mfa_factors
                                 WHERE account_id=$1 AND status='active')",
                            &[&expectation.account_id],
                        )
                        .await
                        .map_err(log_store_error)?
                        .get(0);
                    if !any_active {
                        transaction
                            .execute(
                                "UPDATE account_recovery_codes SET status='revoked'
                                 WHERE account_id=$1 AND status='active'",
                                &[&expectation.account_id],
                            )
                            .await
                            .map_err(log_store_error)?;
                    }
                    transaction
                        .execute(
                            "UPDATE accounts
                             SET updated_at_epoch_millis=GREATEST(updated_at_epoch_millis + 1,$2)
                             WHERE account_id=$1",
                            &[&expectation.account_id, &now],
                        )
                        .await
                        .map_err(log_store_error)?;
                    authority_revocation_audits = revoke_account_sessions_and_trust(
                        &transaction,
                        &expectation.account_id,
                        "mfa_disabled",
                        now,
                        action.audit_entry(),
                    )
                    .await?;
                }
                StepUpAction::ChangePassword {
                    expected_password_hash,
                    new_password_hash,
                    ..
                } => {
                    let affected = transaction
                        .execute(
                            "UPDATE accounts
                             SET password_hash=$3,
                                 updated_at_epoch_millis=GREATEST(updated_at_epoch_millis + 1,$4)
                             WHERE account_id=$1 AND status='active' AND password_hash=$2",
                            &[
                                &expectation.account_id,
                                &expected_password_hash,
                                &new_password_hash,
                                &now,
                            ],
                        )
                        .await
                        .map_err(log_store_error)?;
                    if affected != 1 {
                        return Err(StoreError::Conflict);
                    }
                    authority_revocation_audits = revoke_account_sessions_and_trust(
                        &transaction,
                        &expectation.account_id,
                        "password_changed",
                        now,
                        action.audit_entry(),
                    )
                    .await?;
                }
                StepUpAction::RevokeTrustedDevice {
                    trusted_device_id, ..
                } => {
                    let affected = transaction
                        .execute(
                            "UPDATE trusted_controller_devices
                             SET status='revoked', revoked_at_epoch_millis=$3
                             WHERE trusted_device_id=$1 AND account_id=$2 AND status='active'",
                            &[&trusted_device_id, &expectation.account_id, &now],
                        )
                        .await
                        .map_err(log_store_error)?;
                    if affected != 1 {
                        return Err(StoreError::Conflict);
                    }
                }
            }
            insert_audit_entry_strict(&transaction, action.audit_entry())
                .await
                .map_err(log_conflict_or_store_error)?;
            transaction.commit().await.map_err(log_store_error)?;

            if let Some(challenge) = published.risk_challenges.get_mut(&expectation.challenge_id) {
                challenge.status = RiskChallengeStatus::Consumed;
                challenge.consumed_at_epoch_millis = Some(expectation.now_epoch_millis);
            }
            match action {
                StepUpAction::RotateRecoveryCodes { records, .. } => {
                    published
                        .recovery_codes
                        .retain(|_, record| record.account_id != expectation.account_id);
                    for record in records {
                        published
                            .recovery_codes
                            .insert(record.recovery_code_id.clone(), record.clone());
                    }
                }
                StepUpAction::DisableMfaFactor { factor_id, .. } => {
                    published.mfa_factors.remove(factor_id);
                    if !published
                        .mfa_factors
                        .values()
                        .any(|factor| factor.account_id == expectation.account_id && factor.active)
                    {
                        published
                            .recovery_codes
                            .retain(|_, code| code.account_id != expectation.account_id);
                    }
                }
                StepUpAction::ChangePassword {
                    new_password_hash, ..
                } => {
                    if let Some(account) = published.accounts.get_mut(&expectation.account_id) {
                        account.password_hash = new_password_hash.clone();
                    }
                }
                StepUpAction::RevokeTrustedDevice {
                    trusted_device_id, ..
                } => {
                    if let Some(trusted) = published
                        .trusted_controller_devices
                        .get_mut(trusted_device_id)
                    {
                        trusted.status = TrustedDeviceStatus::Revoked;
                        trusted.revoked_at_epoch_millis = Some(expectation.now_epoch_millis);
                    }
                }
            }
            let revoked_reason = match action {
                StepUpAction::DisableMfaFactor { .. } => Some("mfa_disabled"),
                StepUpAction::ChangePassword { .. } => Some("password_changed"),
                _ => None,
            };
            if let Some(revoked_reason) = revoked_reason {
                if let Some(account) = published.accounts.get_mut(&expectation.account_id) {
                    account.updated_at_epoch_millis = account
                        .updated_at_epoch_millis
                        .saturating_add(1)
                        .max(expectation.now_epoch_millis);
                }
                for session in published.account_sessions.values_mut() {
                    if session.account_id == expectation.account_id
                        && session.revoked_at_epoch_millis.is_none()
                    {
                        session.revoked_at_epoch_millis = Some(expectation.now_epoch_millis);
                        session.revoked_reason = Some(revoked_reason.to_owned());
                    }
                }
                for trusted in published.trusted_controller_devices.values_mut() {
                    if trusted.account_id == expectation.account_id
                        && trusted.status == TrustedDeviceStatus::Active
                    {
                        trusted.status = TrustedDeviceStatus::Revoked;
                        trusted.revoked_at_epoch_millis = Some(expectation.now_epoch_millis);
                    }
                }
            }
            published.audit_logs.extend(authority_revocation_audits);
            published.audit_logs.push(action.audit_entry().clone());
            Ok(())
        })
    }

    fn finish_totp_enrollment<'a>(
        &'a self,
        completion: &'a TotpEnrollmentCompletion,
    ) -> RepositoryFuture<'a, Result<(), StoreError>> {
        Box::pin(async move {
            let factor = &completion.factor;
            let delivery = &completion.delivery;
            if !factor.active
                || factor.last_used_counter.is_none()
                || completion.recovery_codes.is_empty()
                || completion.audit_entry.created_at_epoch_millis < factor.created_at_epoch_millis
                || delivery.account_id != factor.account_id
                || delivery.factor_id != factor.factor_id
                || usize::from(delivery.recovery_code_count) != completion.recovery_codes.len()
            {
                return Err(StoreError::Conflict);
            }
            validate_recovery_code_delivery(delivery).map_err(|reason| {
                error!(%reason, "PostgreSQL MFA enrollment delivery is invalid");
                StoreError::Conflict
            })?;
            let mut recovery_ids = HashSet::new();
            let mut recovery_hashes = HashSet::new();
            for record in &completion.recovery_codes {
                if record.account_id != factor.account_id
                    || record.used_at_epoch_millis.is_some()
                    || !recovery_ids.insert(&record.recovery_code_id)
                    || !recovery_hashes.insert(record.code_hash)
                {
                    return Err(StoreError::Conflict);
                }
            }

            let encrypted = encrypt_mfa(&self.mfa_secret_key, factor).map_err(|reason| {
                error!(%reason, "PostgreSQL MFA enrollment cannot be encrypted");
                StoreError::Unavailable
            })?;
            let mut published = self.database.write().await;
            let mut client = self.client.lock().await;
            let transaction = client.transaction().await.map_err(log_store_error)?;
            let account_exists = transaction
                .query_opt(
                    "SELECT account_id FROM accounts
                     WHERE account_id=$1 AND status='active' FOR UPDATE",
                    &[&factor.account_id],
                )
                .await
                .map_err(log_store_error)?
                .is_some();
            if !account_exists {
                return Err(StoreError::Conflict);
            }
            let session_active: bool = transaction
                .query_opt(
                    "SELECT revoked_at_epoch_millis IS NULL
                            AND revoked_reason IS NULL
                            AND expires_at_epoch_millis > $3 AS active
                     FROM account_sessions
                     WHERE account_session_id=$1 AND account_id=$2
                     FOR UPDATE",
                    &[
                        &delivery.account_session_id,
                        &delivery.account_id,
                        &to_i64_lossless(completion.audit_entry.created_at_epoch_millis),
                    ],
                )
                .await
                .map_err(log_store_error)?
                .is_some_and(|row| row.get("active"));
            if !session_active {
                return Err(StoreError::Conflict);
            }
            let active_exists: bool = transaction
                .query_one(
                    "SELECT EXISTS (
                         SELECT 1 FROM account_mfa_factors
                         WHERE account_id=$1 AND factor_type='totp' AND status='active')",
                    &[&factor.account_id],
                )
                .await
                .map_err(log_store_error)?
                .get(0);
            if active_exists {
                return Err(StoreError::Conflict);
            }

            let created = to_i64_lossless(factor.created_at_epoch_millis);
            let completed = to_i64_lossless(completion.audit_entry.created_at_epoch_millis);
            transaction
                .execute(
                    "INSERT INTO account_mfa_factors
                        (factor_id, account_id, factor_type, encrypted_secret, status,
                         last_used_at_epoch_millis, created_at_epoch_millis,
                         disabled_at_epoch_millis)
                     VALUES ($1,$2,'totp',$3,'active',$4,$5,NULL)",
                    &[
                        &factor.factor_id,
                        &factor.account_id,
                        &encrypted,
                        &completed,
                        &created,
                    ],
                )
                .await
                .map_err(log_conflict_or_store_error)?;
            transaction
                .execute(
                    "UPDATE account_recovery_codes SET status='revoked'
                     WHERE account_id=$1 AND status='active'",
                    &[&factor.account_id],
                )
                .await
                .map_err(log_store_error)?;
            for record in &completion.recovery_codes {
                transaction
                    .execute(
                        "INSERT INTO account_recovery_codes
                            (recovery_code_id, account_id, code_hash, status,
                             used_at_epoch_millis, created_at_epoch_millis,
                             expires_at_epoch_millis)
                         VALUES ($1,$2,$3,'active',NULL,$4,$5)",
                        &[
                            &record.recovery_code_id,
                            &record.account_id,
                            &&record.code_hash[..],
                            &completed,
                            &record.expires_at_epoch_millis.map(to_i64_lossless),
                        ],
                    )
                    .await
                    .map_err(log_conflict_or_store_error)?;
            }
            let recovery_code_count =
                i16::try_from(delivery.recovery_code_count).map_err(|_| StoreError::Conflict)?;
            transaction
                .execute(
                    "INSERT INTO mfa_recovery_code_deliveries
                        (delivery_id, account_id, account_session_id, factor_id,
                         idempotency_key_hash, finish_request_binding_hash,
                         client_ephemeral_public_key, server_ephemeral_public_key,
                         nonce, ciphertext, recovery_code_count, created_at_epoch_millis,
                         expires_at_epoch_millis, acknowledged_at_epoch_millis)
                     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NULL)",
                    &[
                        &delivery.delivery_id,
                        &delivery.account_id,
                        &delivery.account_session_id,
                        &delivery.factor_id,
                        &&delivery.idempotency_key_hash[..],
                        &&delivery.finish_request_binding_hash[..],
                        &&delivery.client_ephemeral_public_key[..],
                        &&delivery.server_ephemeral_public_key[..],
                        &&delivery.nonce[..],
                        &delivery.ciphertext,
                        &recovery_code_count,
                        &to_i64_lossless(delivery.created_at_epoch_millis),
                        &to_i64_lossless(delivery.expires_at_epoch_millis),
                    ],
                )
                .await
                .map_err(log_conflict_or_store_error)?;
            transaction
                .execute(
                    "UPDATE accounts
                     SET updated_at_epoch_millis=GREATEST(updated_at_epoch_millis + 1,$2)
                     WHERE account_id=$1",
                    &[&factor.account_id, &completed],
                )
                .await
                .map_err(log_store_error)?;
            let authority_revocation_audits = revoke_account_sessions_and_trust(
                &transaction,
                &factor.account_id,
                "mfa_enabled",
                completed,
                &completion.audit_entry,
            )
            .await?;
            insert_audit_entry_strict(&transaction, &completion.audit_entry)
                .await
                .map_err(log_conflict_or_store_error)?;
            transaction.commit().await.map_err(log_store_error)?;

            published
                .mfa_factors
                .insert(factor.factor_id.clone(), factor.clone());
            published.recovery_codes.retain(|_, record| {
                record.account_id != factor.account_id || record.used_at_epoch_millis.is_some()
            });
            for record in &completion.recovery_codes {
                published
                    .recovery_codes
                    .insert(record.recovery_code_id.clone(), record.clone());
            }
            published
                .recovery_code_deliveries
                .insert(delivery.delivery_id.clone(), delivery.clone());
            if let Some(account) = published.accounts.get_mut(&factor.account_id) {
                account.updated_at_epoch_millis = account
                    .updated_at_epoch_millis
                    .saturating_add(1)
                    .max(completion.audit_entry.created_at_epoch_millis);
            }
            for session in published.account_sessions.values_mut() {
                if session.account_id == factor.account_id
                    && session.revoked_at_epoch_millis.is_none()
                {
                    session.revoked_at_epoch_millis =
                        Some(completion.audit_entry.created_at_epoch_millis);
                    session.revoked_reason = Some("mfa_enabled".to_owned());
                }
            }
            for trusted in published.trusted_controller_devices.values_mut() {
                if trusted.account_id == factor.account_id
                    && trusted.status == TrustedDeviceStatus::Active
                {
                    trusted.status = TrustedDeviceStatus::Revoked;
                    trusted.revoked_at_epoch_millis =
                        Some(completion.audit_entry.created_at_epoch_millis);
                }
            }
            published.audit_logs.extend(authority_revocation_audits);
            published.audit_logs.push(completion.audit_entry.clone());
            Ok(())
        })
    }

    fn replay_totp_enrollment<'a>(
        &'a self,
        lookup: &'a TotpEnrollmentReplayLookup,
    ) -> RepositoryFuture<'a, Result<TotpEnrollmentReplayOutcome, StoreError>> {
        Box::pin(async move {
            if lookup.now_epoch_millis >= lookup.access_token_expires_at_epoch_millis {
                return Ok(TotpEnrollmentReplayOutcome::NotAuthorized);
            }
            let client = self.client.lock().await;
            let row = client
                .query_opt(
                    "SELECT d.delivery_id, d.account_id, d.account_session_id, d.factor_id,
                            d.idempotency_key_hash, d.finish_request_binding_hash,
                            d.client_ephemeral_public_key, d.server_ephemeral_public_key,
                            d.nonce, d.ciphertext, d.recovery_code_count,
                            d.created_at_epoch_millis, d.expires_at_epoch_millis,
                            d.acknowledged_at_epoch_millis, s.revoked_reason,
                            s.revoked_at_epoch_millis
                     FROM mfa_recovery_code_deliveries d
                     JOIN account_sessions s
                       ON s.account_session_id=d.account_session_id
                      AND s.account_id=d.account_id
                     WHERE d.account_id=$1 AND d.account_session_id=$2
                       AND d.factor_id=$3 AND d.idempotency_key_hash=$4",
                    &[
                        &lookup.account_id,
                        &lookup.account_session_id,
                        &lookup.factor_id,
                        &&lookup.idempotency_key_hash[..],
                    ],
                )
                .await
                .map_err(log_store_error)?;
            let Some(row) = row else {
                return Ok(TotpEnrollmentReplayOutcome::NotFound);
            };
            let revoked_reason: Option<String> = row.get("revoked_reason");
            let revoked_at: Option<i64> = row.get("revoked_at_epoch_millis");
            if revoked_reason.as_deref() != Some("mfa_enabled") || revoked_at.is_none() {
                return Ok(TotpEnrollmentReplayOutcome::NotAuthorized);
            }
            let delivery = recovery_code_delivery_from_row(&row).map_err(|reason| {
                error!(%reason, "PostgreSQL MFA delivery replay row is invalid");
                StoreError::Unavailable
            })?;
            if !constant_time_sha256_eq(
                &delivery.finish_request_binding_hash,
                &lookup.finish_request_binding_hash,
            ) {
                return Ok(TotpEnrollmentReplayOutcome::BindingMismatch);
            }
            if delivery.acknowledged_at_epoch_millis.is_some()
                || delivery.expires_at_epoch_millis <= lookup.now_epoch_millis
            {
                return Ok(TotpEnrollmentReplayOutcome::NotAuthorized);
            }
            Ok(TotpEnrollmentReplayOutcome::Replayed(Box::new(delivery)))
        })
    }

    fn create_session<'a>(
        &'a self,
        command: &'a CreateSessionCommand,
    ) -> RepositoryFuture<'a, Result<CreateSessionOutcome, StoreError>> {
        Box::pin(async move {
            let body_hash = decode_hex_32(&command.idempotency.body_hash).map_err(|reason| {
                error!(%reason, "PostgreSQL session idempotency body hash is invalid");
                StoreError::Unavailable
            })?;
            let mut published = self.database.write().await;
            let mut client = self.client.lock().await;
            let transaction = client.transaction().await.map_err(log_store_error)?;
            transaction
                .batch_execute("SET CONSTRAINTS ALL DEFERRED")
                .await
                .map_err(log_store_error)?;

            match claim_session_idempotency(&transaction, &command.idempotency, &body_hash)
                .await
                .map_err(log_conflict_or_persistence_error)?
            {
                SessionIdempotencyClaim::Existing(existing) => {
                    if existing.body_hash != body_hash {
                        transaction.commit().await.map_err(log_store_error)?;
                        return Ok(CreateSessionOutcome::BindingMismatch);
                    }
                    let (_, session_snapshot) =
                        load_replay_event(&transaction, &existing.resource_id, &command.event)
                            .await
                            .map_err(log_persistence_error)?;
                    let session = match session_snapshot {
                        Some(session) => session,
                        None => load_transaction_session(&transaction, &existing.resource_id)
                            .await
                            .map_err(log_persistence_error)?,
                    };
                    transaction.commit().await.map_err(log_store_error)?;

                    published
                        .sessions
                        .insert(session.session_id.clone(), session.clone());
                    return Ok(CreateSessionOutcome::Replayed(session));
                }
                SessionIdempotencyClaim::Claimed => {}
            }

            if command.idempotency.session_id != command.session.session_id
                || command.event.session_id != command.session.session_id
                || command.policy_evaluation.session_id != command.session.session_id
                || command.session.policy_evaluation_id
                    != command.policy_evaluation.policy_evaluation_id
            {
                return Err(StoreError::Conflict);
            }
            if !session_devices_are_authorizable(&transaction, &command.session)
                .await
                .map_err(log_persistence_error)?
            {
                return Err(StoreError::Conflict);
            }

            insert_policy_evaluation_strict(&transaction, &command.policy_evaluation)
                .await
                .map_err(log_conflict_or_persistence_error)?;
            insert_session_strict(&transaction, &command.session)
                .await
                .map_err(log_conflict_or_persistence_error)?;
            let mut event = command.event.clone();
            event.result_session = Some(command.session.clone());
            insert_session_event_strict(&transaction, &event)
                .await
                .map_err(log_conflict_or_persistence_error)?;
            insert_audit_entry_strict(&transaction, &command.audit_entry)
                .await
                .map_err(log_conflict_or_store_error)?;
            transaction.commit().await.map_err(log_store_error)?;

            published
                .session_idempotency
                .insert(command.storage_key.clone(), command.idempotency.clone());
            published.policy_evaluations.insert(
                command.policy_evaluation.policy_evaluation_id.clone(),
                command.policy_evaluation.clone(),
            );
            published
                .sessions
                .insert(command.session.session_id.clone(), command.session.clone());
            published.session_events.push(event);
            published.audit_logs.push(command.audit_entry.clone());
            Ok(CreateSessionOutcome::Created(command.session.clone()))
        })
    }

    fn transition_session<'a>(
        &'a self,
        command: &'a TransitionSessionCommand,
    ) -> RepositoryFuture<'a, Result<TransitionSessionOutcome, StoreError>> {
        Box::pin(async move {
            let mut published = self.database.write().await;
            let mut client = self.client.lock().await;
            let transaction = client.transaction().await.map_err(log_store_error)?;

            let existing = find_session_idempotency(&transaction, &command.idempotency)
                .await
                .map_err(log_persistence_error)?;
            if existing.is_none() && !command.apply_allowed {
                transaction.commit().await.map_err(log_store_error)?;
                return Ok(TransitionSessionOutcome::InvalidTransition);
            }

            let body_hash = decode_hex_32(&command.idempotency.body_hash).map_err(|reason| {
                error!(%reason, "PostgreSQL session idempotency body hash is invalid");
                StoreError::Unavailable
            })?;
            let claim = if let Some(existing) = existing {
                SessionIdempotencyClaim::Existing(existing)
            } else {
                claim_session_idempotency(&transaction, &command.idempotency, &body_hash)
                    .await
                    .map_err(log_conflict_or_persistence_error)?
            };

            if let SessionIdempotencyClaim::Existing(existing) = claim {
                if existing.body_hash != body_hash {
                    transaction.commit().await.map_err(log_store_error)?;
                    return Ok(TransitionSessionOutcome::BindingMismatch);
                }
                let (event_id, session_snapshot) =
                    load_replay_event(&transaction, &existing.resource_id, &command.event)
                        .await
                        .map_err(log_persistence_error)?;
                let session = match session_snapshot {
                    Some(session) => session,
                    None => load_transaction_session(&transaction, &existing.resource_id)
                        .await
                        .map_err(log_persistence_error)?,
                };
                transaction.commit().await.map_err(log_store_error)?;

                published
                    .sessions
                    .insert(session.session_id.clone(), session.clone());
                return Ok(TransitionSessionOutcome::Replayed { session, event_id });
            }

            if command.event.from_status != Some(command.expected_status)
                || command.event.session_id != command.session.session_id
                || command.event.to_status != command.session.status
                || command.idempotency.session_id != command.session.session_id
                || command.event.actor_account_id.as_deref()
                    != Some(command.idempotency.account_id.as_str())
                || command.event.actor_device_id.as_deref()
                    != Some(command.idempotency.device_id.as_str())
            {
                return Err(StoreError::Conflict);
            }

            let terminal = command.session.status.is_terminal();
            let ended = terminal.then(|| {
                to_i64_lossless(
                    command
                        .session
                        .ended_at_epoch_millis
                        .unwrap_or(command.event.created_at_epoch_millis),
                )
            });
            let updated = to_i64_lossless(command.session.updated_at_epoch_millis);
            let target_status = session_status_name(command.session.status);
            let expected_status = session_status_name(command.expected_status);
            let actor_role = command.event.actor_role.as_deref().unwrap_or("none");
            let affected = transaction
                .execute(
                    "UPDATE sessions
                     SET status=$2,
                         relay_token_epoch=CASE WHEN $3 THEN relay_token_epoch+1
                                                ELSE relay_token_epoch END,
                         ended_at_epoch_millis=CASE WHEN $3 THEN $4
                                                    ELSE ended_at_epoch_millis END,
                         updated_at_epoch_millis=GREATEST(updated_at_epoch_millis,$5)
                     WHERE session_id=$1 AND status=$6
                       AND (NOT $3 OR relay_token_epoch < 9223372036854775807)
                       AND (
                           ($7='controller' AND controller_account_id=$8
                                             AND controller_device_id=$9)
                           OR
                           ($7='controlled' AND controlled_device_id=$9
                            AND EXISTS (
                                SELECT 1 FROM devices
                                WHERE device_id=$9 AND account_id=$8
                            ))
                       )",
                    &[
                        &command.session.session_id,
                        &target_status,
                        &terminal,
                        &ended,
                        &updated,
                        &expected_status,
                        &actor_role,
                        &command.idempotency.account_id,
                        &command.idempotency.device_id,
                    ],
                )
                .await
                .map_err(log_store_error)?;
            if affected == 0 {
                let exists = transaction
                    .query_opt(
                        "SELECT 1 FROM sessions WHERE session_id=$1",
                        &[&command.session.session_id],
                    )
                    .await
                    .map_err(log_store_error)?
                    .is_some();
                transaction.rollback().await.map_err(log_store_error)?;
                return Ok(if exists {
                    TransitionSessionOutcome::StateConflict
                } else {
                    TransitionSessionOutcome::NotFound
                });
            }
            if affected != 1 {
                error!(
                    affected,
                    "PostgreSQL session CAS affected an invalid row count"
                );
                return Err(StoreError::Unavailable);
            }

            let session = load_transaction_session(&transaction, &command.session.session_id)
                .await
                .map_err(log_persistence_error)?;
            let mut event = command.event.clone();
            event.result_session = Some(session.clone());
            insert_session_event_strict(&transaction, &event)
                .await
                .map_err(log_conflict_or_persistence_error)?;
            insert_audit_entry_strict(&transaction, &command.audit_entry)
                .await
                .map_err(log_conflict_or_store_error)?;
            transaction.commit().await.map_err(log_store_error)?;

            published
                .session_idempotency
                .insert(command.storage_key.clone(), command.idempotency.clone());
            published
                .sessions
                .insert(session.session_id.clone(), session.clone());
            published.session_events.push(event);
            published.audit_logs.push(command.audit_entry.clone());
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
            if command.device.account_id != command.account_id
                || command.device.device_id.is_empty()
                || command.device.public_key_version != 1
                || command.device.public_key_revoked_at_epoch_millis.is_some()
                || command.device.created_at_epoch_millis > command.now_epoch_millis
                || command.device.updated_at_epoch_millis < command.device.created_at_epoch_millis
            {
                return Err(StoreError::Conflict);
            }
            let mut published = self.database.write().await;
            let mut client = self.client.lock().await;
            let transaction = client.transaction().await.map_err(log_store_error)?;
            let grant_row = transaction
                .query_opt(
                    "SELECT grant_id, grant_secret_hash, account_id, device_id,
                            device_public_key_fingerprint, login_challenge_id,
                            login_challenge_binding_hash, trust_proof_type, trust_level,
                            establish_trust, protocol_version, issued_account_session_id,
                            issued_at_epoch_millis, expires_at_epoch_millis,
                            consumed_at_epoch_millis, registration_request_binding_hash,
                            registered_public_key_id, registered_trusted_device_id
                     FROM device_enrollment_grants
                     WHERE grant_id=$1
                     FOR UPDATE",
                    &[&command.grant_id],
                )
                .await
                .map_err(log_store_error)?;
            let Some(grant_row) = grant_row else {
                return Ok(DeviceRegistrationOutcome::InvalidGrant);
            };
            let mut grant = device_enrollment_grant_from_row(&grant_row).map_err(|reason| {
                error!(%reason, "PostgreSQL locked enrollment grant row is invalid");
                StoreError::Unavailable
            })?;
            if !constant_time_sha256_eq(&grant.grant_secret_hash, &command.grant_secret_hash)
                || grant.account_id != command.account_id
                || grant.device_id != command.device.device_id
                || grant.protocol_version != command.protocol_version
                || grant.issued_account_session_id != command.account_session_id
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

            let challenge_row = transaction
                .query_opt(
                    "SELECT account_id, operation_binding_hash, status
                     FROM account_risk_challenges
                     WHERE risk_challenge_id=$1
                     FOR SHARE",
                    &[&grant.login_challenge_id],
                )
                .await
                .map_err(log_store_error)?
                .ok_or(StoreError::Unavailable)?;
            let challenge_account_id: String = challenge_row.get("account_id");
            let challenge_binding_hash = fixed_32(
                challenge_row.get::<_, Vec<u8>>("operation_binding_hash"),
                "account_risk_challenges.operation_binding_hash",
            )
            .map_err(|reason| {
                error!(%reason, "PostgreSQL enrollment challenge binding is invalid");
                StoreError::Unavailable
            })?;
            if challenge_account_id != grant.account_id
                || challenge_row.get::<_, String>("status") != "consumed"
                || !constant_time_sha256_eq(
                    &challenge_binding_hash,
                    &grant.login_challenge_binding_hash,
                )
            {
                return Ok(DeviceRegistrationOutcome::InvalidGrant);
            }

            if grant.consumed_at_epoch_millis.is_some() {
                if grant.registration_request_binding_hash.as_ref()
                    != Some(&command.registration_request_binding_hash)
                {
                    return Err(StoreError::Conflict);
                }
                let registered_public_key_id = grant
                    .registered_public_key_id
                    .as_deref()
                    .ok_or(StoreError::Unavailable)?;
                if grant.establish_trust != grant.registered_trusted_device_id.is_some() {
                    return Err(StoreError::Unavailable);
                }
                let existing = load_transaction_device(&transaction, &command.device.device_id)
                    .await
                    .map_err(log_persistence_error)?
                    .ok_or(StoreError::Unavailable)?;
                if existing.account_id != command.account_id
                    || existing.public_key_id != registered_public_key_id
                    || !constant_time_sha256_eq(
                        &sha256(&existing.public_key),
                        &grant.device_public_key_fingerprint,
                    )
                {
                    return Err(StoreError::Conflict);
                }
                verify_replayed_device_trust(&transaction, &grant).await?;
                transaction.commit().await.map_err(log_store_error)?;
                published
                    .devices
                    .insert(existing.device_id.clone(), existing.clone());
                published
                    .device_enrollment_grants
                    .insert(grant.grant_id.clone(), grant);
                return Ok(DeviceRegistrationOutcome::Replayed(existing));
            }

            if grant.expires_at_epoch_millis <= command.now_epoch_millis {
                return Ok(DeviceRegistrationOutcome::InvalidGrant);
            }
            if grant.registration_request_binding_hash.is_some()
                || grant.registered_public_key_id.is_some()
                || grant.registered_trusted_device_id.is_some()
            {
                return Err(StoreError::Unavailable);
            }
            let now = to_i64_lossless(command.now_epoch_millis);
            let account_session_active: bool = transaction
                .query_one(
                    "SELECT EXISTS (
                         SELECT 1 FROM account_sessions
                         WHERE account_session_id=$1 AND account_id=$2
                           AND revoked_at_epoch_millis IS NULL
                           AND revoked_reason IS NULL
                           AND expires_at_epoch_millis > $3
                         FOR SHARE)",
                    &[&command.account_session_id, &command.account_id, &now],
                )
                .await
                .map_err(log_store_error)?
                .get(0);
            if !account_session_active {
                return Ok(DeviceRegistrationOutcome::InvalidGrant);
            }
            if transaction
                .query_opt(
                    "SELECT 1 FROM devices WHERE device_id=$1 OR public_key_id=$2 LIMIT 1",
                    &[&command.device.device_id, &command.device.public_key_id],
                )
                .await
                .map_err(log_store_error)?
                .is_some()
            {
                return Err(StoreError::Conflict);
            }

            insert_device_registration_strict(&transaction, &command.device)
                .await
                .map_err(log_conflict_or_persistence_error)?;
            let trusted_device = if grant.establish_trust {
                let trusted_device_id = command
                    .trusted_device_id
                    .as_ref()
                    .ok_or(StoreError::Conflict)?;
                let trust_proof_type = grant
                    .trust_proof_type
                    .clone()
                    .ok_or(StoreError::Unavailable)?;
                let trust_level = grant.trust_level.clone().ok_or(StoreError::Unavailable)?;
                let ttl = if trust_proof_type == "device_signature_and_recovery_code" {
                    24 * 60 * 60 * 1_000
                } else {
                    30 * 24 * 60 * 60 * 1_000
                };
                let trusted = TrustedControllerDevice {
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
                };
                validate_trusted_device(&trusted).map_err(|reason| {
                    error!(%reason, "PostgreSQL registration trust decision is invalid");
                    StoreError::Unavailable
                })?;
                insert_trusted_device_strict(&transaction, &trusted)
                    .await
                    .map_err(log_conflict_or_persistence_error)?;
                insert_audit_entry_strict(
                    &transaction,
                    command
                        .trusted_device_audit_entry
                        .as_ref()
                        .ok_or(StoreError::Conflict)?,
                )
                .await
                .map_err(log_conflict_or_store_error)?;
                Some(trusted)
            } else {
                None
            };
            let registered_trusted_device_id = trusted_device
                .as_ref()
                .map(|trusted| trusted.trusted_device_id.as_str());
            let consumed = transaction
                .execute(
                    "UPDATE device_enrollment_grants
                     SET consumed_at_epoch_millis=$2,
                         registration_request_binding_hash=$3,
                         registered_public_key_id=$4,
                         registered_trusted_device_id=$5
                     WHERE grant_id=$1 AND consumed_at_epoch_millis IS NULL
                       AND registration_request_binding_hash IS NULL
                       AND registered_public_key_id IS NULL
                       AND registered_trusted_device_id IS NULL
                       AND expires_at_epoch_millis > $2",
                    &[
                        &grant.grant_id,
                        &now,
                        &&command.registration_request_binding_hash[..],
                        &command.device.public_key_id,
                        &registered_trusted_device_id,
                    ],
                )
                .await
                .map_err(log_store_error)?;
            if consumed != 1 {
                return Err(StoreError::Conflict);
            }
            grant.consumed_at_epoch_millis = Some(command.now_epoch_millis);
            grant.registration_request_binding_hash =
                Some(command.registration_request_binding_hash);
            grant.registered_public_key_id = Some(command.device.public_key_id.clone());
            grant.registered_trusted_device_id =
                registered_trusted_device_id.map(ToOwned::to_owned);
            insert_audit_entry_strict(&transaction, &command.registration_audit_entry)
                .await
                .map_err(log_conflict_or_store_error)?;
            insert_audit_entry_strict(&transaction, &command.grant_audit_entry)
                .await
                .map_err(log_conflict_or_store_error)?;
            transaction.commit().await.map_err(log_store_error)?;

            published
                .devices
                .insert(command.device.device_id.clone(), command.device.clone());
            published.device_public_keys.insert(
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
            published
                .device_enrollment_grants
                .insert(grant.grant_id.clone(), grant);
            if let Some(trusted) = trusted_device {
                published
                    .trusted_controller_devices
                    .insert(trusted.trusted_device_id.clone(), trusted);
                published.audit_logs.push(
                    command
                        .trusted_device_audit_entry
                        .clone()
                        .ok_or(StoreError::Unavailable)?,
                );
            }
            published
                .audit_logs
                .push(command.registration_audit_entry.clone());
            published.audit_logs.push(command.grant_audit_entry.clone());
            Ok(DeviceRegistrationOutcome::Created(command.device.clone()))
        })
    }

    fn rotate_device_key<'a>(
        &'a self,
        rotation: &'a DeviceKeyRotation,
    ) -> RepositoryFuture<'a, Result<DeviceAuthorityChange, StoreError>> {
        Box::pin(async move {
            // Keep the cache write lock before the client lock, matching transact(), so
            // cache publication cannot race a legacy snapshot transaction in this process.
            let mut published = self.database.write().await;
            let mut client = self.client.lock().await;
            let transaction = client.transaction().await.map_err(log_store_error)?;
            let now = to_i64_lossless(rotation.step_up.now_epoch_millis);
            let consumed = transaction
                .execute(
                    "UPDATE account_risk_challenges
                     SET status='consumed', consumed_at_epoch_millis=$6
                     WHERE risk_challenge_id=$1 AND account_id=$2 AND device_id=$3
                       AND purpose=$4 AND operation_binding_hash=$5
                       AND status='verified' AND verified_at_epoch_millis IS NOT NULL
                       AND consumed_at_epoch_millis IS NULL
                       AND expires_at_epoch_millis > $6",
                    &[
                        &rotation.step_up.challenge_id,
                        &rotation.step_up.account_id,
                        &rotation.step_up.device_id,
                        &rotation.step_up.purpose,
                        &&rotation.step_up.operation_binding_hash[..],
                        &now,
                    ],
                )
                .await
                .map_err(log_store_error)?;
            if consumed != 1 {
                return Err(StoreError::Conflict);
            }

            let device_sql =
                format!("{DEVICE_AUTHORITY_SELECT} WHERE d.device_id=$1 FOR UPDATE OF d");
            let row = transaction
                .query_opt(&device_sql, &[&rotation.step_up.device_id])
                .await
                .map_err(log_store_error)?
                .ok_or(StoreError::Conflict)?;
            let (mut current, _) = device_from_row(&row).map_err(|reason| {
                error!(%reason, "PostgreSQL rotation device row is invalid");
                StoreError::Unavailable
            })?;
            if current.account_id != rotation.step_up.account_id
                || current.public_key_id != rotation.current_public_key_id
                || current.public_key_version != rotation.current_public_key_version
                || current.public_key_revoked_at_epoch_millis.is_some()
                || current.public_key == rotation.new_public_key
                || current.public_key_version.checked_add(1)
                    != Some(rotation.new_public_key_version)
            {
                return Err(StoreError::Conflict);
            }
            let duplicate = transaction
                .query_opt(
                    "SELECT 1 FROM devices WHERE public_key_id=$1 AND device_id<>$2 LIMIT 1",
                    &[&rotation.new_public_key_id, &rotation.step_up.device_id],
                )
                .await
                .map_err(log_store_error)?
                .is_some();
            if duplicate || rotation.new_public_key_id == rotation.current_public_key_id {
                return Err(StoreError::Conflict);
            }

            let affected_rows = transaction
                .query(
                    "SELECT session_id, status, relay_token_epoch FROM sessions
                     WHERE (controller_device_id=$1 OR controlled_device_id=$1)
                       AND status NOT IN ('cancelled','closed','rejected','failed')
                     ORDER BY session_id
                     FOR UPDATE",
                    &[&rotation.step_up.device_id],
                )
                .await
                .map_err(log_store_error)?;
            if affected_rows
                .iter()
                .any(|row| row.get::<_, i64>("relay_token_epoch") == i64::MAX)
            {
                return Err(StoreError::Conflict);
            }
            let old_public_key_fingerprint = sha256(&current.public_key);
            current.public_key_id = rotation.new_public_key_id.clone();
            current.public_key = rotation.new_public_key;
            current.public_key_version = rotation.new_public_key_version;
            current.public_key_revoked_at_epoch_millis = None;
            current.updated_at_epoch_millis = current
                .updated_at_epoch_millis
                .max(rotation.step_up.now_epoch_millis);
            transaction
                .execute(
                    "UPDATE trusted_controller_devices
                     SET status='revoked', revoked_at_epoch_millis=$4
                     WHERE account_id=$1 AND controller_device_id=$2
                       AND device_fingerprint_hash=$3 AND status='active'",
                    &[
                        &rotation.step_up.account_id,
                        &rotation.step_up.device_id,
                        &&old_public_key_fingerprint[..],
                        &now,
                    ],
                )
                .await
                .map_err(log_store_error)?;
            let version =
                i32::try_from(rotation.new_public_key_version).map_err(|_| StoreError::Conflict)?;
            let current_version = i32::try_from(rotation.current_public_key_version)
                .map_err(|_| StoreError::Conflict)?;
            let updated = transaction
                .execute(
                    "UPDATE devices SET public_key_id=$1, public_key=$2,
                            public_key_version=$3, public_key_revoked_at_epoch_millis=NULL,
                            updated_at_epoch_millis=GREATEST(updated_at_epoch_millis,$4)
                     WHERE device_id=$5 AND account_id=$6
                       AND public_key_id=$7 AND public_key_version=$8
                       AND public_key_revoked_at_epoch_millis IS NULL",
                    &[
                        &rotation.new_public_key_id,
                        &&rotation.new_public_key[..],
                        &version,
                        &now,
                        &rotation.step_up.device_id,
                        &rotation.step_up.account_id,
                        &rotation.current_public_key_id,
                        &current_version,
                    ],
                )
                .await
                .map_err(log_store_error)?;
            if updated != 1 {
                return Err(StoreError::Conflict);
            }
            transaction
                .execute(
                    "UPDATE sessions SET relay_token_epoch=relay_token_epoch+1,
                            status='closed', ended_at_epoch_millis=$2,
                            updated_at_epoch_millis=GREATEST(updated_at_epoch_millis,$2)
                     WHERE (controller_device_id=$1 OR controlled_device_id=$1)
                       AND status NOT IN ('cancelled','closed','rejected','failed')",
                    &[&rotation.step_up.device_id, &now],
                )
                .await
                .map_err(log_store_error)?;
            let mut forced_session_events = Vec::with_capacity(affected_rows.len());
            let mut forced_session_audits = Vec::with_capacity(affected_rows.len());
            for row in &affected_rows {
                let session_id = row.get::<_, String>("session_id");
                let from_status = parse_session_status(&row.get::<_, String>("status"))
                    .map_err(|_| StoreError::Unavailable)?;
                let session = load_transaction_session(&transaction, &session_id)
                    .await
                    .map_err(log_persistence_error)?;
                let (event, audit) = forced_session_close_records(
                    &session,
                    from_status,
                    &rotation.audit_entry,
                    "device_key_rotated",
                );
                insert_session_event_strict(&transaction, &event)
                    .await
                    .map_err(log_conflict_or_persistence_error)?;
                insert_audit_entry_strict(&transaction, &audit)
                    .await
                    .map_err(log_conflict_or_store_error)?;
                forced_session_events.push(event);
                forced_session_audits.push(audit);
            }
            insert_audit_entry_strict(&transaction, &rotation.audit_entry)
                .await
                .map_err(log_conflict_or_store_error)?;
            transaction.commit().await.map_err(log_store_error)?;

            if let Some(challenge) = published
                .risk_challenges
                .get_mut(&rotation.step_up.challenge_id)
            {
                challenge.status = RiskChallengeStatus::Consumed;
                challenge.consumed_at_epoch_millis = Some(rotation.step_up.now_epoch_millis);
            }
            if let Some(old_key) = published
                .device_public_keys
                .get_mut(&rotation.current_public_key_id)
            {
                old_key.revoked_at_epoch_millis = Some(rotation.step_up.now_epoch_millis);
            }
            for trusted in published
                .trusted_controller_devices
                .values_mut()
                .filter(|trusted| {
                    trusted.account_id == rotation.step_up.account_id
                        && trusted.controller_device_id == rotation.step_up.device_id
                        && trusted.status == TrustedDeviceStatus::Active
                        && constant_time_sha256_eq(
                            &trusted.device_fingerprint_hash,
                            &old_public_key_fingerprint,
                        )
                })
            {
                trusted.status = TrustedDeviceStatus::Revoked;
                trusted.revoked_at_epoch_millis = Some(rotation.step_up.now_epoch_millis);
            }
            published.device_public_keys.insert(
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
            published
                .devices
                .insert(current.device_id.clone(), current.clone());
            for event in &forced_session_events {
                if let Some(session) = &event.result_session {
                    published
                        .sessions
                        .insert(session.session_id.clone(), session.clone());
                }
            }
            published
                .session_events
                .extend(forced_session_events.iter().cloned());
            published.audit_logs.extend(forced_session_audits);
            published.audit_logs.push(rotation.audit_entry.clone());
            Ok(DeviceAuthorityChange {
                device: Box::new(current),
                closed_session_events: forced_session_events,
            })
        })
    }

    fn manage_device<'a>(
        &'a self,
        command: &'a DeviceManagementCommand,
    ) -> RepositoryFuture<'a, Result<DeviceManagementOutcome, StoreError>> {
        Box::pin(async move {
            let mut published = self.database.write().await;
            let mut client = self.client.lock().await;
            let transaction = client.transaction().await.map_err(log_store_error)?;
            let mut lock_ids = vec![
                command.actor_device_id.clone(),
                command.target_device_id.clone(),
            ];
            lock_ids.sort();
            lock_ids.dedup();
            transaction
                .query(
                    "SELECT device_id FROM devices
                     WHERE device_id=ANY($1)
                     ORDER BY device_id
                     FOR UPDATE",
                    &[&lock_ids],
                )
                .await
                .map_err(log_store_error)?;
            let actor = load_transaction_device(&transaction, &command.actor_device_id)
                .await
                .map_err(log_persistence_error)?
                .ok_or(StoreError::Conflict)?;
            if actor.account_id != command.account_id
                || actor.public_key_id != command.actor_public_key_id
                || actor.public_key_version != command.actor_public_key_version
                || actor.public_key_revoked_at_epoch_millis.is_some()
                || !actor.status.is_authorizable()
            {
                return Err(StoreError::Conflict);
            }
            let Some(mut target) = load_transaction_device(&transaction, &command.target_device_id)
                .await
                .map_err(log_persistence_error)?
            else {
                return Ok(DeviceManagementOutcome::NotFound);
            };
            if target.account_id != command.account_id
                || target.public_key_id != command.expected_target_public_key_id
                || target.public_key_version != command.expected_target_public_key_version
            {
                return Err(StoreError::Conflict);
            }
            if !device_management_transition_allowed(&target, command) {
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
            let affected_rows = if tightening {
                transaction
                    .query(
                        "SELECT session_id, status, relay_token_epoch FROM sessions
                         WHERE (controller_device_id=$1 OR controlled_device_id=$1)
                           AND status NOT IN ('cancelled','closed','rejected','failed')
                         ORDER BY session_id
                         FOR UPDATE",
                        &[&command.target_device_id],
                    )
                    .await
                    .map_err(log_store_error)?
            } else {
                Vec::new()
            };
            if affected_rows
                .iter()
                .any(|row| row.get::<_, i64>("relay_token_epoch") == i64::MAX)
            {
                return Err(StoreError::Conflict);
            }
            let affected_session_ids = affected_rows
                .iter()
                .map(|row| row.get::<_, String>("session_id"))
                .collect::<Vec<_>>();

            apply_device_management(&mut target, command);
            let now = to_i64_lossless(command.now_epoch_millis);
            let revoked = target
                .public_key_revoked_at_epoch_millis
                .map(to_i64_lossless);
            let updated = transaction
                .execute(
                    "UPDATE devices SET display_name=$1, status=$2,
                            public_key_revoked_at_epoch_millis=$3,
                            unattended_enabled=$4,
                            updated_at_epoch_millis=GREATEST(updated_at_epoch_millis,$5)
                     WHERE device_id=$6 AND account_id=$7
                       AND public_key_id=$8 AND public_key_version=$9",
                    &[
                        &target.display_name,
                        &device_lifecycle_status_name(target.status),
                        &revoked,
                        &target.capabilities.unattended,
                        &now,
                        &target.device_id,
                        &target.account_id,
                        &command.expected_target_public_key_id,
                        &i32::try_from(command.expected_target_public_key_version)
                            .map_err(|_| StoreError::Conflict)?,
                    ],
                )
                .await
                .map_err(log_store_error)?;
            if updated != 1 {
                return Err(StoreError::Conflict);
            }
            transaction
                .execute(
                    "UPDATE device_policies SET allow_remote_desktop=$2,
                            allow_input_control=$2, allow_unattended=$3,
                            updated_at_epoch_millis=GREATEST(updated_at_epoch_millis,$4)
                     WHERE device_id=$1",
                    &[
                        &target.device_id,
                        &target.capabilities.controlled,
                        &target.capabilities.unattended,
                        &now,
                    ],
                )
                .await
                .map_err(log_store_error)?;
            if tightening {
                transaction
                    .execute(
                        "UPDATE trusted_controller_devices
                         SET status='revoked', revoked_at_epoch_millis=$3
                         WHERE account_id=$1 AND controller_device_id=$2 AND status='active'",
                        &[&command.account_id, &command.target_device_id, &now],
                    )
                    .await
                    .map_err(log_store_error)?;
                if command
                    .action
                    .is_some_and(device_management_revokes_account_sessions)
                {
                    transaction
                        .execute(
                            "UPDATE account_sessions
                             SET revoked_at_epoch_millis=$2, revoked_reason='device_unbound',
                                 updated_at_epoch_millis=GREATEST(updated_at_epoch_millis,$2)
                             WHERE account_id=$1 AND revoked_at_epoch_millis IS NULL",
                            &[&command.account_id, &now],
                        )
                        .await
                        .map_err(log_store_error)?;
                }
                transaction
                    .execute(
                        "UPDATE sessions SET relay_token_epoch=relay_token_epoch+1,
                                status='closed', ended_at_epoch_millis=$2,
                                updated_at_epoch_millis=GREATEST(updated_at_epoch_millis,$2)
                         WHERE (controller_device_id=$1 OR controlled_device_id=$1)
                           AND status NOT IN ('cancelled','closed','rejected','failed')",
                        &[&command.target_device_id, &now],
                    )
                    .await
                    .map_err(log_store_error)?;
            }
            let close_reason = command
                .action
                .and_then(device_management_session_close_reason);
            let mut forced_session_events = Vec::with_capacity(affected_rows.len());
            let mut forced_session_audits = Vec::with_capacity(affected_rows.len());
            for row in &affected_rows {
                let session_id = row.get::<_, String>("session_id");
                let from_status = parse_session_status(&row.get::<_, String>("status"))
                    .map_err(|_| StoreError::Unavailable)?;
                let session = load_transaction_session(&transaction, &session_id)
                    .await
                    .map_err(log_persistence_error)?;
                let (event, audit) = forced_session_close_records(
                    &session,
                    from_status,
                    &command.audit_entry,
                    close_reason.ok_or(StoreError::Unavailable)?,
                );
                insert_session_event_strict(&transaction, &event)
                    .await
                    .map_err(log_conflict_or_persistence_error)?;
                insert_audit_entry_strict(&transaction, &audit)
                    .await
                    .map_err(log_conflict_or_store_error)?;
                forced_session_events.push(event);
                forced_session_audits.push(audit);
            }
            let audit = device_management_audit(command, &affected_session_ids)?;
            insert_audit_entry_strict(&transaction, &audit)
                .await
                .map_err(log_conflict_or_store_error)?;
            transaction.commit().await.map_err(log_store_error)?;

            published
                .devices
                .insert(target.device_id.clone(), target.clone());
            if let Some(revoked_at) = target.public_key_revoked_at_epoch_millis {
                if let Some(key) = published.device_public_keys.get_mut(&target.public_key_id) {
                    key.revoked_at_epoch_millis = Some(revoked_at);
                }
            }
            if tightening {
                for trusted in published
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
                if command
                    .action
                    .is_some_and(device_management_revokes_account_sessions)
                {
                    for account_session in
                        published.account_sessions.values_mut().filter(|session| {
                            session.account_id == command.account_id
                                && session.revoked_at_epoch_millis.is_none()
                        })
                    {
                        account_session.revoked_at_epoch_millis = Some(command.now_epoch_millis);
                        account_session.revoked_reason = Some("device_unbound".to_owned());
                    }
                }
                for event in &forced_session_events {
                    if let Some(session) = &event.result_session {
                        published
                            .sessions
                            .insert(session.session_id.clone(), session.clone());
                    }
                }
            }
            published
                .session_events
                .extend(forced_session_events.iter().cloned());
            published.audit_logs.extend(forced_session_audits);
            published.audit_logs.push(audit);
            Ok(DeviceManagementOutcome::Updated(DeviceAuthorityChange {
                device: Box::new(target),
                closed_session_events: forced_session_events,
            }))
        })
    }
}

fn log_store_error(error: tokio_postgres::Error) -> StoreError {
    error!(error = %error, "PostgreSQL repository operation failed");
    StoreError::Unavailable
}

fn log_conflict_or_store_error(error: tokio_postgres::Error) -> StoreError {
    if error.code() == Some(&SqlState::UNIQUE_VIOLATION) {
        StoreError::Conflict
    } else {
        log_store_error(error)
    }
}

enum PersistenceError {
    Database(tokio_postgres::Error),
    Data(String),
}

impl From<tokio_postgres::Error> for PersistenceError {
    fn from(error: tokio_postgres::Error) -> Self {
        Self::Database(error)
    }
}

fn log_persistence_error(error: PersistenceError) -> StoreError {
    match error {
        PersistenceError::Database(error) => log_store_error(error),
        PersistenceError::Data(reason) => {
            error!(%reason, "PostgreSQL repository rejected invalid application data");
            StoreError::Unavailable
        }
    }
}

fn log_conflict_or_persistence_error(error: PersistenceError) -> StoreError {
    match error {
        PersistenceError::Database(error) => log_conflict_or_store_error(error),
        PersistenceError::Data(reason) => {
            error!(%reason, "PostgreSQL repository rejected invalid application data");
            StoreError::Unavailable
        }
    }
}

struct ExistingSessionIdempotency {
    body_hash: [u8; 32],
    resource_id: String,
}

enum SessionIdempotencyClaim {
    Claimed,
    Existing(ExistingSessionIdempotency),
}

async fn verify_schema(client: &Client) -> Result<(), String> {
    let row = client
        .query_one(
            "SELECT to_regclass('public.accounts') IS NOT NULL, \
                    to_regclass('public.sessions') IS NOT NULL, \
                    to_regclass('public.audit_logs') IS NOT NULL, \
                    to_regclass('public.device_enrollment_grants') IS NOT NULL, \
                    to_regclass('public.mfa_recovery_code_deliveries') IS NOT NULL",
            &[],
        )
        .await
        .map_err(|error| format!("verify PostgreSQL schema: {error}"))?;
    if !(0..5).all(|index| row.get::<_, bool>(index)) {
        return Err(
            "PostgreSQL V1 schema is missing; apply the frozen 0001 migration first".into(),
        );
    }
    Ok(())
}

async fn load_database(client: &Client, mfa_key: &[u8; 32]) -> Result<Database, String> {
    let mut database = Database::default();
    load_accounts(client, &mut database).await?;
    load_devices(client, &mut database).await?;
    load_mfa(client, &mut database, mfa_key).await?;
    load_account_sessions(client, &mut database).await?;
    load_recovery_codes(client, &mut database).await?;
    load_recovery_code_deliveries(client, &mut database).await?;
    load_risk_challenges(client, &mut database).await?;
    load_login_challenge_contexts(client, &mut database).await?;
    load_device_enrollment_grants(client, &mut database).await?;
    load_trusted_controller_devices(client, &mut database).await?;
    load_policy_evaluations(client, &mut database).await?;
    load_sessions(client, &mut database).await?;
    load_idempotency(client, &mut database).await?;
    load_session_events(client, &mut database).await?;
    load_audit_logs(client, &mut database).await?;
    Ok(database)
}

async fn load_accounts(client: &Client, database: &mut Database) -> Result<(), String> {
    let rows = client
        .query(
            "SELECT account_id, email, display_name, password_hash, status, \
                    created_at_epoch_millis, updated_at_epoch_millis FROM accounts",
            &[],
        )
        .await
        .map_err(load_error("accounts"))?;
    for row in rows {
        let account = account_from_row(&row)?;
        database
            .account_by_email
            .insert(account.email.clone(), account.account_id.clone());
        database
            .accounts
            .insert(account.account_id.clone(), account);
    }
    Ok(())
}

async fn load_account_sessions(client: &Client, database: &mut Database) -> Result<(), String> {
    let rows = client
        .query(LOAD_ACCOUNT_SESSIONS_SQL, &[])
        .await
        .map_err(load_error("account_sessions"))?;
    for row in rows {
        let session = account_session_from_row(&row)?;
        database
            .account_sessions
            .insert(session.account_session_id.clone(), session);
    }
    Ok(())
}

async fn load_recovery_code_deliveries(
    client: &Client,
    database: &mut Database,
) -> Result<(), String> {
    let rows = client
        .query(
            "SELECT delivery_id, account_id, account_session_id, factor_id,
                    idempotency_key_hash, finish_request_binding_hash,
                    client_ephemeral_public_key, server_ephemeral_public_key, nonce,
                    ciphertext, recovery_code_count, created_at_epoch_millis,
                    expires_at_epoch_millis, acknowledged_at_epoch_millis
             FROM mfa_recovery_code_deliveries",
            &[],
        )
        .await
        .map_err(load_error("mfa_recovery_code_deliveries"))?;
    for row in rows {
        let delivery = recovery_code_delivery_from_row(&row)?;
        database
            .recovery_code_deliveries
            .insert(delivery.delivery_id.clone(), delivery);
    }
    Ok(())
}

async fn load_mfa(
    client: &Client,
    database: &mut Database,
    mfa_key: &[u8; 32],
) -> Result<(), String> {
    let rows = client
        .query(
            "SELECT factor_id, account_id, encrypted_secret, created_at_epoch_millis \
             FROM account_mfa_factors WHERE status = 'active'",
            &[],
        )
        .await
        .map_err(load_error("account_mfa_factors"))?;
    for row in rows {
        let factor_id: String = row.get("factor_id");
        let account_id: String = row.get("account_id");
        let payload = decrypt_mfa(
            mfa_key,
            &account_id,
            &factor_id,
            &row.get::<_, Vec<u8>>("encrypted_secret"),
        )?;
        database.mfa_factors.insert(
            factor_id.clone(),
            MfaFactor {
                factor_id,
                account_id,
                secret_base32: payload.secret_base32,
                active: true,
                last_used_counter: payload.last_used_counter,
                created_at_epoch_millis: from_i64(row.get("created_at_epoch_millis"))?,
            },
        );
    }
    Ok(())
}

async fn load_recovery_codes(client: &Client, database: &mut Database) -> Result<(), String> {
    let rows = client
        .query(
            "SELECT recovery_code_id, account_id, code_hash, used_at_epoch_millis, \
                    expires_at_epoch_millis \
             FROM account_recovery_codes WHERE status IN ('active', 'used')",
            &[],
        )
        .await
        .map_err(load_error("account_recovery_codes"))?;
    for row in rows {
        let recovery_code_id: String = row.get("recovery_code_id");
        database.recovery_codes.insert(
            recovery_code_id.clone(),
            RecoveryCode {
                recovery_code_id,
                account_id: row.get("account_id"),
                code_hash: fixed_32(row.get::<_, Vec<u8>>("code_hash"), "code_hash")?,
                used_at_epoch_millis: optional_u64(row.get("used_at_epoch_millis"))?,
                expires_at_epoch_millis: optional_u64(row.get("expires_at_epoch_millis"))?,
            },
        );
    }
    Ok(())
}

async fn load_risk_challenges(client: &Client, database: &mut Database) -> Result<(), String> {
    let rows = client
        .query(
            "SELECT risk_challenge_id, account_id, device_id, purpose, \
                    operation_binding_hash, risk_level, required_methods, status, \
                    attempts_remaining, ip_address::text AS ip_address, user_agent, \
                    expires_at_epoch_millis, created_at_epoch_millis, \
                    verified_at_epoch_millis, consumed_at_epoch_millis \
             FROM account_risk_challenges",
            &[],
        )
        .await
        .map_err(load_error("account_risk_challenges"))?;
    for row in rows {
        let challenge = risk_challenge_from_row(&row)?;
        database
            .risk_challenges
            .insert(challenge.risk_challenge_id.clone(), challenge);
    }
    Ok(())
}

async fn load_login_challenge_contexts(
    client: &Client,
    database: &mut Database,
) -> Result<(), String> {
    let rows = client
        .query(
            "SELECT risk_challenge_id, account_id, device_id, purpose,
                    operation_binding_hash, risk_level, required_methods, status,
                    attempts_remaining, ip_address::text AS ip_address, user_agent,
                    expires_at_epoch_millis, created_at_epoch_millis,
                    verified_at_epoch_millis, consumed_at_epoch_millis,
                    login_device_state, login_device_id,
                    login_account_updated_at_epoch_millis, login_device_public_key,
                    login_device_public_key_fingerprint, login_public_key_id,
                    login_public_key_version, login_client_nonce, login_server_nonce,
                    login_request_binding_hash, login_ip_address_hash,
                    login_user_agent_hash, login_trusted_device_id,
                    login_protocol_version, login_attempts_limit
             FROM account_risk_challenges
             WHERE purpose='login_mfa'",
            &[],
        )
        .await
        .map_err(load_error("account_risk_challenges login contexts"))?;
    for row in rows {
        let authority = login_challenge_authority_from_row(&row)?;
        database
            .login_challenge_contexts
            .insert(authority.challenge.risk_challenge_id, authority.context);
    }
    Ok(())
}

async fn load_device_enrollment_grants(
    client: &Client,
    database: &mut Database,
) -> Result<(), String> {
    let rows = client
        .query(
            "SELECT grant_id, grant_secret_hash, account_id, device_id,
                    device_public_key_fingerprint, login_challenge_id,
                    login_challenge_binding_hash, trust_proof_type, trust_level,
                    establish_trust, protocol_version, issued_account_session_id,
                    issued_at_epoch_millis, expires_at_epoch_millis,
                    consumed_at_epoch_millis, registration_request_binding_hash,
                    registered_public_key_id, registered_trusted_device_id
             FROM device_enrollment_grants",
            &[],
        )
        .await
        .map_err(load_error("device_enrollment_grants"))?;
    for row in rows {
        let grant = device_enrollment_grant_from_row(&row)?;
        database
            .device_enrollment_grants
            .insert(grant.grant_id.clone(), grant);
    }
    Ok(())
}

fn validate_new_risk_challenge(challenge: &RiskChallenge) -> Result<(), String> {
    validate_fixed_enum(
        &challenge.purpose,
        "account_risk_challenges.purpose",
        RISK_CHALLENGE_PURPOSES,
    )?;
    if !risk_challenge_required_methods_are_valid(&challenge.purpose, &challenge.required_methods) {
        return Err(
            "account_risk_challenges.required_methods violates the frozen purpose matrix"
                .to_owned(),
        );
    }
    validate_fixed_enum(
        &challenge.risk_level,
        "account_risk_challenges.risk_level",
        RISK_LEVELS,
    )?;
    if challenge.status != RiskChallengeStatus::Issued
        || challenge.attempts_remaining == 0
        || challenge.attempts_remaining > 5
        || challenge.verified_at_epoch_millis.is_some()
        || challenge.consumed_at_epoch_millis.is_some()
    {
        return Err("new account_risk_challenges row is not in issued state".to_owned());
    }
    let ttl = challenge
        .expires_at_epoch_millis
        .checked_sub(challenge.created_at_epoch_millis)
        .ok_or_else(|| "account_risk_challenges expiry precedes creation".to_owned())?;
    if ttl == 0 || ttl > 300_000 {
        return Err("account_risk_challenges expiry exceeds 5 minutes".to_owned());
    }
    Ok(())
}

fn risk_challenge_cancel_audit_is_valid(
    challenge: &RiskChallenge,
    audit_entry: &AuditEntry,
) -> bool {
    audit_entry.actor_account_id.as_deref() == Some(challenge.account_id.as_str())
        && audit_entry.action == "risk_challenge_failed"
        && audit_entry.result == "failure"
        && audit_entry.reason.as_deref() == Some("cancelled")
}

fn risk_challenge_from_row(row: &Row) -> Result<RiskChallenge, String> {
    let purpose: String = row.get("purpose");
    validate_fixed_enum(
        &purpose,
        "account_risk_challenges.purpose",
        RISK_CHALLENGE_PURPOSES,
    )?;
    let risk_level: String = row.get("risk_level");
    validate_fixed_enum(
        &risk_level,
        "account_risk_challenges.risk_level",
        RISK_LEVELS,
    )?;
    let attempts_remaining = u8::try_from(row.get::<_, i16>("attempts_remaining"))
        .map_err(|_| "account_risk_challenges.attempts_remaining is invalid".to_owned())?;
    if attempts_remaining > 5 {
        return Err("account_risk_challenges.attempts_remaining exceeds 5".to_owned());
    }
    let required_methods = parse_required_methods(row.get("required_methods"))?;
    if !risk_challenge_required_methods_are_valid(&purpose, &required_methods) {
        return Err(
            "account_risk_challenges.required_methods violates the frozen purpose matrix"
                .to_owned(),
        );
    }
    Ok(RiskChallenge {
        risk_challenge_id: row.get("risk_challenge_id"),
        account_id: row.get("account_id"),
        device_id: row.get("device_id"),
        purpose,
        operation_binding_hash: fixed_32(
            row.get::<_, Vec<u8>>("operation_binding_hash"),
            "account_risk_challenges.operation_binding_hash",
        )?,
        risk_level,
        required_methods,
        status: parse_risk_challenge_status(&row.get::<_, String>("status"))?,
        attempts_remaining,
        ip_address: row.get("ip_address"),
        user_agent: row.get("user_agent"),
        expires_at_epoch_millis: from_i64(row.get("expires_at_epoch_millis"))?,
        created_at_epoch_millis: from_i64(row.get("created_at_epoch_millis"))?,
        verified_at_epoch_millis: optional_u64(row.get("verified_at_epoch_millis"))?,
        consumed_at_epoch_millis: optional_u64(row.get("consumed_at_epoch_millis"))?,
    })
}

fn login_challenge_authority_from_row(row: &Row) -> Result<LoginChallengeAuthority, String> {
    let challenge = risk_challenge_from_row(row)?;
    if challenge.purpose != "login_mfa" {
        return Err("account_risk_challenges row is not a login challenge".to_owned());
    }
    let device_state = match row.get::<_, String>("login_device_state").as_str() {
        "registered" => LoginDeviceState::Registered,
        "pending_enrollment" => LoginDeviceState::PendingEnrollment,
        value => {
            return Err(format!(
                "account_risk_challenges.login_device_state contains unsupported value {value}"
            ));
        }
    };
    let public_key_version = u32::try_from(row.get::<_, i32>("login_public_key_version"))
        .map_err(|_| "account_risk_challenges.login_public_key_version is invalid".to_owned())?;
    let protocol_version = u16::try_from(row.get::<_, i32>("login_protocol_version"))
        .map_err(|_| "account_risk_challenges.login_protocol_version is invalid".to_owned())?;
    let attempts_limit = u8::try_from(row.get::<_, i16>("login_attempts_limit"))
        .map_err(|_| "account_risk_challenges.login_attempts_limit is invalid".to_owned())?;
    let context = LoginChallengeContext {
        device_state,
        device_id: row.get("login_device_id"),
        account_updated_at_epoch_millis: from_i64(
            row.get("login_account_updated_at_epoch_millis"),
        )?,
        device_public_key: fixed_32(
            row.get::<_, Vec<u8>>("login_device_public_key"),
            "account_risk_challenges.login_device_public_key",
        )?,
        device_public_key_fingerprint: fixed_32(
            row.get::<_, Vec<u8>>("login_device_public_key_fingerprint"),
            "account_risk_challenges.login_device_public_key_fingerprint",
        )?,
        public_key_id: row.get("login_public_key_id"),
        public_key_version,
        client_nonce: fixed_32(
            row.get::<_, Vec<u8>>("login_client_nonce"),
            "account_risk_challenges.login_client_nonce",
        )?,
        server_nonce: fixed_32(
            row.get::<_, Vec<u8>>("login_server_nonce"),
            "account_risk_challenges.login_server_nonce",
        )?,
        login_request_binding_hash: fixed_32(
            row.get::<_, Vec<u8>>("login_request_binding_hash"),
            "account_risk_challenges.login_request_binding_hash",
        )?,
        login_challenge_binding_hash: challenge.operation_binding_hash,
        ip_address_hash: fixed_32(
            row.get::<_, Vec<u8>>("login_ip_address_hash"),
            "account_risk_challenges.login_ip_address_hash",
        )?,
        user_agent_hash: fixed_32(
            row.get::<_, Vec<u8>>("login_user_agent_hash"),
            "account_risk_challenges.login_user_agent_hash",
        )?,
        required_factors: challenge.required_methods.clone(),
        trusted_device_id: row.get("login_trusted_device_id"),
        protocol_version,
        issued_at_epoch_millis: challenge.created_at_epoch_millis,
        attempts_limit,
    };
    let authority = LoginChallengeAuthority { challenge, context };
    validate_login_challenge_authority(&authority)
        .map_err(|_| "account_risk_challenges login context binding is invalid".to_owned())?;
    Ok(authority)
}

const fn login_device_state_name(state: LoginDeviceState) -> &'static str {
    match state {
        LoginDeviceState::Registered => "registered",
        LoginDeviceState::PendingEnrollment => "pending_enrollment",
    }
}

async fn load_trusted_controller_devices(
    client: &Client,
    database: &mut Database,
) -> Result<(), String> {
    let rows = client
        .query(
            "SELECT trusted_device_id, account_id, controller_device_id, \
                    device_fingerprint_hash, trust_level, status, trust_proof_type, \
                    created_at_epoch_millis, last_used_at_epoch_millis, \
                    expires_at_epoch_millis, revoked_at_epoch_millis \
             FROM trusted_controller_devices",
            &[],
        )
        .await
        .map_err(load_error("trusted_controller_devices"))?;
    for row in rows {
        let trusted = trusted_device_from_row(&row)?;
        database
            .trusted_controller_devices
            .insert(trusted.trusted_device_id.clone(), trusted);
    }
    Ok(())
}

async fn load_devices(client: &Client, database: &mut Database) -> Result<(), String> {
    let rows = client
        .query(DEVICE_AUTHORITY_SELECT, &[])
        .await
        .map_err(load_error("devices"))?;
    for row in rows {
        let (device, key_record) = device_from_row(&row)?;
        database
            .device_public_keys
            .insert(key_record.public_key_id.clone(), key_record);
        database.devices.insert(device.device_id.clone(), device);
    }
    Ok(())
}

async fn load_policy_evaluations(client: &Client, database: &mut Database) -> Result<(), String> {
    let rows = client
        .query(
            "SELECT policy_evaluation_id, account_id, controller_device_id, \
                    controlled_device_id, session_id, access_decision, anti_abuse_decision, \
                    session_access_decision, effective_permissions, permissions_digest, \
                    created_at_epoch_millis FROM policy_evaluations WHERE session_id IS NOT NULL",
            &[],
        )
        .await
        .map_err(load_error("policy_evaluations"))?;
    for row in rows {
        let policy_evaluation_id: String = row.get("policy_evaluation_id");
        database.policy_evaluations.insert(
            policy_evaluation_id.clone(),
            PolicyEvaluation {
                policy_evaluation_id,
                session_id: row.get("session_id"),
                account_id: row.get("account_id"),
                controller_device_id: row.get("controller_device_id"),
                controlled_device_id: row.get("controlled_device_id"),
                access_decision: row.get("access_decision"),
                anti_abuse_decision: row.get("anti_abuse_decision"),
                session_access_decision: row.get("session_access_decision"),
                effective_permissions: serde_json::from_value(row.get("effective_permissions"))
                    .map_err(|error| format!("decode effective_permissions: {error}"))?,
                permissions_digest: encode_hex(&row.get::<_, Vec<u8>>("permissions_digest")),
                evaluated_at_epoch_millis: from_i64(row.get("created_at_epoch_millis"))?,
            },
        );
    }
    Ok(())
}

async fn load_sessions(client: &Client, database: &mut Database) -> Result<(), String> {
    let rows = client
        .query(SESSION_AUTHORITY_SELECT, &[])
        .await
        .map_err(load_error("sessions"))?;
    for row in rows {
        let session = session_from_row(&row)?;
        database
            .sessions
            .insert(session.session_id.clone(), session);
    }
    Ok(())
}

fn device_from_row(row: &Row) -> Result<(Device, DevicePublicKeyRecord), String> {
    let device_id: String = row.get("device_id");
    let public_key = fixed_32(row.get::<_, Vec<u8>>("public_key"), "public_key")?;
    let public_key_id: String = row.get("public_key_id");
    let public_key_version = u32::try_from(row.get::<_, i32>("public_key_version"))
        .map_err(|_| "device public_key_version is negative".to_owned())?;
    let created_at_epoch_millis = from_i64(row.get("created_at_epoch_millis"))?;
    let revoked_at = optional_u64(row.get("public_key_revoked_at_epoch_millis"))?;
    let device = Device {
        device_id: device_id.clone(),
        account_id: row.get("account_id"),
        display_name: row.get("display_name"),
        platform: parse_platform(&row.get::<_, String>("platform"))?,
        os_version: row.get("os_version"),
        arch: parse_architecture(&row.get::<_, String>("arch"))?,
        capabilities: DeviceCapabilities {
            controller: true,
            controlled: row.get("allow_remote_desktop"),
            file_transfer: row.get("allow_file_transfer"),
            unattended: row.get::<_, bool>("allow_unattended")
                && row.get::<_, bool>("unattended_enabled"),
        },
        public_key_id: public_key_id.clone(),
        public_key,
        public_key_version,
        public_key_revoked_at_epoch_millis: revoked_at,
        status: parse_device_lifecycle_status(&row.get::<_, String>("status"))?,
        last_seen_epoch_millis: optional_u64(row.get("last_seen_epoch_millis"))?,
        created_at_epoch_millis,
        updated_at_epoch_millis: from_i64(row.get("updated_at_epoch_millis"))?,
    };
    let key_record = DevicePublicKeyRecord {
        public_key_id,
        device_id,
        public_key,
        version: public_key_version,
        created_at_epoch_millis,
        revoked_at_epoch_millis: revoked_at,
    };
    Ok((device, key_record))
}

fn account_from_row(row: &Row) -> Result<Account, String> {
    let status = match row.get::<_, String>("status").as_str() {
        "active" => AccountStatus::Active,
        "disabled" | "locked" => AccountStatus::Disabled,
        value => return Err(format!("accounts contains unsupported status {value}")),
    };
    Ok(Account {
        account_id: row.get("account_id"),
        email: row.get("email"),
        display_name: row.get("display_name"),
        password_hash: row.get("password_hash"),
        status,
        created_at_epoch_millis: from_i64(row.get("created_at_epoch_millis"))?,
        updated_at_epoch_millis: from_i64(row.get("updated_at_epoch_millis"))?,
    })
}

fn account_session_from_row(row: &Row) -> Result<AccountSession, String> {
    let revoked_reason: Option<String> = row.get("revoked_reason");
    if let Some(reason) = revoked_reason.as_deref() {
        validate_fixed_enum(
            reason,
            "account_sessions.revoked_reason",
            ACCOUNT_SESSION_REVOKED_REASONS,
        )?;
    }
    Ok(AccountSession {
        account_session_id: row.get("account_session_id"),
        account_id: row.get("account_id"),
        refresh_token_hash: fixed_32(
            row.get::<_, Vec<u8>>("refresh_token_hash"),
            "refresh_token_hash",
        )?,
        mfa_verified: row.get("mfa_verified"),
        expires_at_epoch_millis: from_i64(row.get("expires_at_epoch_millis"))?,
        revoked_at_epoch_millis: optional_u64(row.get("revoked_at_epoch_millis"))?,
        revoked_reason,
    })
}

fn device_enrollment_grant_from_row(row: &Row) -> Result<DeviceEnrollmentGrant, String> {
    let grant = DeviceEnrollmentGrant {
        grant_id: row.get("grant_id"),
        grant_secret_hash: fixed_32(
            row.get::<_, Vec<u8>>("grant_secret_hash"),
            "device_enrollment_grants.grant_secret_hash",
        )?,
        account_id: row.get("account_id"),
        device_id: row.get("device_id"),
        device_public_key_fingerprint: fixed_32(
            row.get::<_, Vec<u8>>("device_public_key_fingerprint"),
            "device_enrollment_grants.device_public_key_fingerprint",
        )?,
        login_challenge_id: row.get("login_challenge_id"),
        login_challenge_binding_hash: fixed_32(
            row.get::<_, Vec<u8>>("login_challenge_binding_hash"),
            "device_enrollment_grants.login_challenge_binding_hash",
        )?,
        trust_proof_type: row.get("trust_proof_type"),
        trust_level: row.get("trust_level"),
        establish_trust: row.get("establish_trust"),
        protocol_version: u16::try_from(row.get::<_, i32>("protocol_version"))
            .map_err(|_| "device_enrollment_grants.protocol_version is invalid".to_owned())?,
        issued_account_session_id: row.get("issued_account_session_id"),
        issued_at_epoch_millis: from_i64(row.get("issued_at_epoch_millis"))?,
        expires_at_epoch_millis: from_i64(row.get("expires_at_epoch_millis"))?,
        consumed_at_epoch_millis: optional_u64(row.get("consumed_at_epoch_millis"))?,
        registration_request_binding_hash: row
            .get::<_, Option<Vec<u8>>>("registration_request_binding_hash")
            .map(|value| {
                fixed_32(
                    value,
                    "device_enrollment_grants.registration_request_binding_hash",
                )
            })
            .transpose()?,
        registered_public_key_id: row.get("registered_public_key_id"),
        registered_trusted_device_id: row.get("registered_trusted_device_id"),
    };
    validate_device_enrollment_grant(&grant)?;
    Ok(grant)
}

fn recovery_code_delivery_from_row(row: &Row) -> Result<RecoveryCodeDelivery, String> {
    let nonce: [u8; 12] = row
        .get::<_, Vec<u8>>("nonce")
        .try_into()
        .map_err(|_| "mfa_recovery_code_deliveries.nonce is not 12 bytes".to_owned())?;
    let recovery_code_count = u16::try_from(row.get::<_, i16>("recovery_code_count"))
        .map_err(|_| "mfa_recovery_code_deliveries.recovery_code_count is invalid".to_owned())?;
    let delivery = RecoveryCodeDelivery {
        delivery_id: row.get("delivery_id"),
        account_id: row.get("account_id"),
        account_session_id: row.get("account_session_id"),
        factor_id: row.get("factor_id"),
        idempotency_key_hash: fixed_32(
            row.get::<_, Vec<u8>>("idempotency_key_hash"),
            "mfa_recovery_code_deliveries.idempotency_key_hash",
        )?,
        finish_request_binding_hash: fixed_32(
            row.get::<_, Vec<u8>>("finish_request_binding_hash"),
            "mfa_recovery_code_deliveries.finish_request_binding_hash",
        )?,
        client_ephemeral_public_key: fixed_32(
            row.get::<_, Vec<u8>>("client_ephemeral_public_key"),
            "mfa_recovery_code_deliveries.client_ephemeral_public_key",
        )?,
        server_ephemeral_public_key: fixed_32(
            row.get::<_, Vec<u8>>("server_ephemeral_public_key"),
            "mfa_recovery_code_deliveries.server_ephemeral_public_key",
        )?,
        nonce,
        ciphertext: row.get("ciphertext"),
        recovery_code_count,
        created_at_epoch_millis: from_i64(row.get("created_at_epoch_millis"))?,
        expires_at_epoch_millis: from_i64(row.get("expires_at_epoch_millis"))?,
        acknowledged_at_epoch_millis: optional_u64(row.get("acknowledged_at_epoch_millis"))?,
    };
    validate_recovery_code_delivery(&delivery)?;
    Ok(delivery)
}

fn trusted_device_from_row(row: &Row) -> Result<TrustedControllerDevice, String> {
    let trust_level: String = row.get("trust_level");
    validate_fixed_enum(
        &trust_level,
        "trusted_controller_devices.trust_level",
        TRUST_LEVELS,
    )?;
    let trust_proof_type: String = row.get("trust_proof_type");
    validate_fixed_enum(
        &trust_proof_type,
        "trusted_controller_devices.trust_proof_type",
        TRUST_PROOF_TYPES,
    )?;
    Ok(TrustedControllerDevice {
        trusted_device_id: row.get("trusted_device_id"),
        account_id: row.get("account_id"),
        controller_device_id: row.get("controller_device_id"),
        device_fingerprint_hash: fixed_32(
            row.get::<_, Vec<u8>>("device_fingerprint_hash"),
            "trusted_controller_devices.device_fingerprint_hash",
        )?,
        trust_level,
        status: parse_trusted_device_status(&row.get::<_, String>("status"))?,
        trust_proof_type,
        created_at_epoch_millis: from_i64(row.get("created_at_epoch_millis"))?,
        last_used_at_epoch_millis: optional_u64(row.get("last_used_at_epoch_millis"))?,
        expires_at_epoch_millis: from_i64(row.get("expires_at_epoch_millis"))?,
        revoked_at_epoch_millis: optional_u64(row.get("revoked_at_epoch_millis"))?,
    })
}

fn session_from_row(row: &Row) -> Result<Session, String> {
    let session_id: String = row.get("session_id");
    Ok(Session {
        session_id,
        controller_account_id: row.get("controller_account_id"),
        controller_device_id: row.get("controller_device_id"),
        controlled_device_id: row.get("controlled_device_id"),
        auth_method: parse_auth_method(&row.get::<_, String>("auth_method"))?,
        status: parse_session_status(&row.get::<_, String>("status"))?,
        permissions: serde_json::from_value(row.get("permissions"))
            .map_err(|error| format!("decode session permissions: {error}"))?,
        permissions_digest: encode_hex(&row.get::<_, Vec<u8>>("permissions_digest")),
        policy_evaluation_id: row.get("policy_evaluation_id"),
        relay_token_epoch: from_i64(row.get("relay_token_epoch"))?,
        session_expires_at_epoch_millis: from_i64(row.get("session_expires_at_epoch_millis"))?,
        created_at_epoch_millis: from_i64(row.get("created_at_epoch_millis"))?,
        updated_at_epoch_millis: from_i64(row.get("updated_at_epoch_millis"))?,
        ended_at_epoch_millis: optional_u64(row.get("ended_at_epoch_millis"))?,
    })
}

async fn load_idempotency(client: &Client, database: &mut Database) -> Result<(), String> {
    let rows = client
        .query(
            "SELECT idempotency_key, account_id, device_id, method, path, body_hash, \
                    request_id, resource_type, resource_id, created_at_epoch_millis, \
                    expires_at_epoch_millis FROM api_idempotency_keys \
             WHERE resource_type IS NOT NULL AND resource_id IS NOT NULL",
            &[],
        )
        .await
        .map_err(load_error("api_idempotency_keys"))?;
    for row in rows {
        let account_id: String = row.get("account_id");
        let device_id: String = row.get("device_id");
        let method: String = row.get("method");
        let path: String = row.get("path");
        let idempotency_key: String = row.get("idempotency_key");
        let operation: String = row.get("resource_type");
        let body_hash = encode_hex(&row.get::<_, Vec<u8>>("body_hash"));
        let storage_key =
            idempotency_storage_key(&account_id, &device_id, &method, &path, &idempotency_key);
        let body_hash_bytes = decode_hex_32(&body_hash)?;
        let canonical = canonical_idempotency_binding_bytes(
            &account_id,
            &device_id,
            &method,
            &path,
            &body_hash_bytes,
        )
        .map_err(|_| "api_idempotency_keys request target is invalid".to_owned())?;
        let request_binding_hash = sha256_hex(&canonical);
        database.session_idempotency.insert(
            storage_key,
            IdempotencyRecord {
                account_id,
                device_id,
                method,
                path,
                operation,
                idempotency_key,
                body_hash,
                request_id: row.get("request_id"),
                session_id: row.get("resource_id"),
                request_binding_hash,
                created_at_epoch_millis: from_i64(row.get("created_at_epoch_millis"))?,
                expires_at_epoch_millis: from_i64(row.get("expires_at_epoch_millis"))?,
            },
        );
    }
    Ok(())
}

async fn load_session_events(client: &Client, database: &mut Database) -> Result<(), String> {
    let rows = client
        .query(
            "SELECT event_id, session_id, event_type, actor_type, actor_account_id, \
                    actor_device_id, actor_role, reason, metadata, created_at_epoch_millis \
             FROM session_events ORDER BY created_at_epoch_millis, event_id",
            &[],
        )
        .await
        .map_err(load_error("session_events"))?;
    for row in rows {
        let metadata: Value = row.get("metadata");
        let from_status = metadata
            .get("from_status")
            .and_then(Value::as_str)
            .map(parse_session_status)
            .transpose()?;
        let to_status = metadata
            .get("to_status")
            .and_then(Value::as_str)
            .map(parse_session_status)
            .transpose()?
            .ok_or_else(|| "session event metadata is missing to_status".to_owned())?;
        let result_session = metadata
            .get("result_session")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| format!("session event result_session is invalid: {error}"))?;
        database.session_events.push(SessionEvent {
            event_id: row.get("event_id"),
            session_id: row.get("session_id"),
            event_type: row.get("event_type"),
            from_status,
            to_status,
            actor_type: row.get("actor_type"),
            actor_account_id: row.get("actor_account_id"),
            actor_device_id: row.get("actor_device_id"),
            actor_role: optional_role(row.get::<_, String>("actor_role")),
            reason: row.get("reason"),
            idempotency_key_hash: metadata
                .get("idempotency_key_hash")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            request_id: metadata
                .get("request_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            created_at_epoch_millis: from_i64(row.get("created_at_epoch_millis"))?,
            result_session,
        });
    }
    Ok(())
}

async fn load_audit_logs(client: &Client, database: &mut Database) -> Result<(), String> {
    let rows = client
        .query(
            "SELECT audit_id, actor_type, actor_account_id, actor_device_id, actor_role, \
                    actor_service, target_device_id, session_id, action, result, reason, \
                    metadata, request_id, created_at_epoch_millis \
             FROM audit_logs ORDER BY created_at_epoch_millis, audit_id",
            &[],
        )
        .await
        .map_err(load_error("audit_logs"))?;
    for row in rows {
        let metadata: Value = row.get("metadata");
        let metadata = metadata
            .as_object()
            .ok_or_else(|| "audit metadata is not an object".to_owned())?
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<BTreeMap<_, _>>();
        database.audit_logs.push(AuditEntry {
            audit_id: row.get("audit_id"),
            actor_type: row.get("actor_type"),
            actor_account_id: row.get("actor_account_id"),
            actor_device_id: row.get("actor_device_id"),
            actor_role: optional_role(row.get::<_, String>("actor_role")),
            actor_service: row.get("actor_service"),
            target_device_id: row.get("target_device_id"),
            session_id: row.get("session_id"),
            action: row.get("action"),
            result: row.get("result"),
            reason: row.get("reason"),
            metadata,
            request_id: row
                .get::<_, Option<String>>("request_id")
                .unwrap_or_default(),
            created_at_epoch_millis: from_i64(row.get("created_at_epoch_millis"))?,
        });
    }
    Ok(())
}

async fn persist_changes(
    transaction: &Transaction<'_>,
    before: &Database,
    after: &Database,
    mfa_key: &[u8; 32],
) -> Result<(), PersistenceError> {
    if before.login_challenge_contexts != after.login_challenge_contexts {
        return Err(PersistenceError::Data(
            "login challenge contexts require the specialized repository API".to_owned(),
        ));
    }
    persist_accounts(transaction, before, after).await?;
    persist_account_sessions(transaction, before, after).await?;
    persist_devices(transaction, before, after).await?;
    persist_mfa(transaction, before, after, mfa_key).await?;
    persist_recovery_codes(transaction, before, after).await?;
    persist_recovery_code_deliveries(transaction, before, after).await?;
    persist_risk_challenges(transaction, before, after).await?;
    persist_device_enrollment_grants(transaction, before, after).await?;
    persist_trusted_controller_devices(transaction, before, after).await?;
    persist_policy_evaluations(transaction, before, after).await?;
    persist_sessions(transaction, before, after).await?;
    persist_idempotency(transaction, before, after).await?;
    persist_session_events(transaction, before, after).await?;
    persist_audit_logs(transaction, before, after).await?;
    Ok(())
}

async fn persist_accounts(
    transaction: &Transaction<'_>,
    before: &Database,
    after: &Database,
) -> Result<(), PersistenceError> {
    for (id, account) in changed_values(&before.accounts, &after.accounts) {
        let created = to_i64_lossless(account.created_at_epoch_millis);
        let updated = to_i64_lossless(account.updated_at_epoch_millis);
        transaction
            .execute(
                "INSERT INTO accounts (account_id, email, display_name, password_hash, status, \
                    created_at_epoch_millis, updated_at_epoch_millis) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7) \
                 ON CONFLICT (account_id) DO UPDATE SET email=EXCLUDED.email, \
                    display_name=EXCLUDED.display_name, password_hash=EXCLUDED.password_hash, \
                    status=EXCLUDED.status, updated_at_epoch_millis=EXCLUDED.updated_at_epoch_millis",
                &[&id, &account.email, &account.display_name, &account.password_hash,
                    &account_status(account.status), &created, &updated],
            )
            .await?;
    }
    Ok(())
}

async fn persist_account_sessions(
    transaction: &Transaction<'_>,
    before: &Database,
    after: &Database,
) -> Result<(), PersistenceError> {
    for (id, session) in changed_values(&before.account_sessions, &after.account_sessions) {
        if session.revoked_at_epoch_millis.is_some() != session.revoked_reason.is_some() {
            return Err(PersistenceError::Data(format!(
                "account_sessions revoked timestamp and reason differ for {id}"
            )));
        }
        if let Some(reason) = session.revoked_reason.as_deref() {
            validate_fixed_enum(
                reason,
                "account_sessions.revoked_reason",
                ACCOUNT_SESSION_REVOKED_REASONS,
            )
            .map_err(PersistenceError::Data)?;
        }
        let now = to_i64_lossless(now_epoch_millis());
        let expires = to_i64_lossless(session.expires_at_epoch_millis);
        let revoked = session.revoked_at_epoch_millis.map(to_i64_lossless);
        transaction
            .execute(
                UPSERT_ACCOUNT_SESSION_SQL,
                &[
                    &id,
                    &session.account_id,
                    &&session.refresh_token_hash[..],
                    &session.mfa_verified,
                    &expires,
                    &revoked,
                    &session.revoked_reason,
                    &now,
                ],
            )
            .await?;
    }
    Ok(())
}

async fn persist_devices(
    transaction: &Transaction<'_>,
    before: &Database,
    after: &Database,
) -> Result<(), PersistenceError> {
    for (id, device) in changed_values(&before.devices, &after.devices) {
        if before.devices.get(id).is_some_and(|previous| {
            previous.public_key_id != device.public_key_id
                || previous.public_key != device.public_key
                || previous.public_key_version != device.public_key_version
                || previous.public_key_revoked_at_epoch_millis
                    != device.public_key_revoked_at_epoch_millis
        }) {
            return Err(PersistenceError::Data(format!(
                "devices refused public key mutation outside the rotation transaction for {id}"
            )));
        }
        if before.devices.get(id).is_some_and(|previous| {
            is_terminal_device_lifecycle_status(previous.status)
                && !is_terminal_device_lifecycle_status(device.status)
        }) {
            return Err(PersistenceError::Data(format!(
                "devices refused terminal status reactivation for {id}"
            )));
        }
        let created = to_i64_lossless(device.created_at_epoch_millis);
        let updated = to_i64_lossless(device.updated_at_epoch_millis);
        let version = i32::try_from(device.public_key_version).map_err(|_| {
            PersistenceError::Data("device public_key_version exceeds PostgreSQL INTEGER".into())
        })?;
        let revoked = device
            .public_key_revoked_at_epoch_millis
            .map(to_i64_lossless);
        let last_seen = device.last_seen_epoch_millis.map(to_i64_lossless);
        let affected = transaction
            .execute(
                "INSERT INTO devices (device_id, account_id, display_name, platform, os_version, \
                    arch, public_key_id, public_key, public_key_version, \
                    public_key_revoked_at_epoch_millis, status, unattended_enabled, \
                    last_seen_epoch_millis, created_at_epoch_millis, updated_at_epoch_millis) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) \
                 ON CONFLICT (device_id) DO UPDATE SET display_name=EXCLUDED.display_name, \
                    platform=EXCLUDED.platform, os_version=EXCLUDED.os_version, arch=EXCLUDED.arch, \
                    status=EXCLUDED.status, \
                    unattended_enabled=EXCLUDED.unattended_enabled, \
                    last_seen_epoch_millis=CASE \
                        WHEN devices.last_seen_epoch_millis IS NULL \
                            THEN EXCLUDED.last_seen_epoch_millis \
                        WHEN EXCLUDED.last_seen_epoch_millis IS NULL \
                            THEN devices.last_seen_epoch_millis \
                        ELSE GREATEST(devices.last_seen_epoch_millis, \
                            EXCLUDED.last_seen_epoch_millis) END, \
                    updated_at_epoch_millis=GREATEST(devices.updated_at_epoch_millis, \
                        EXCLUDED.updated_at_epoch_millis) \
                 WHERE devices.account_id=EXCLUDED.account_id \
                    AND (devices.status NOT IN ('suspended','disabled','unbound') \
                        OR EXCLUDED.status IN ('suspended','disabled','unbound'))",
                &[&id, &device.account_id, &device.display_name, &platform_name(&device.platform),
                    &device.os_version, &architecture_name(&device.arch), &device.public_key_id,
                    &&device.public_key[..], &version, &revoked,
                    &device_lifecycle_status_name(device.status), &device.capabilities.unattended,
                    &last_seen, &created, &updated],
            )
            .await?;
        if affected != 1 {
            return Err(PersistenceError::Data(format!(
                "devices refused terminal status reactivation for {id}"
            )));
        }
        transaction
            .execute(
                "INSERT INTO device_policies (device_id, allow_remote_desktop, allow_input_control, \
                    allow_file_transfer, allow_unattended, created_at_epoch_millis, updated_at_epoch_millis) \
                 VALUES ($1,$2,$2,$3,$4,$5,$6) ON CONFLICT (device_id) DO UPDATE SET \
                    allow_remote_desktop=EXCLUDED.allow_remote_desktop, \
                    allow_input_control=EXCLUDED.allow_input_control, \
                    allow_file_transfer=EXCLUDED.allow_file_transfer, \
                    allow_unattended=EXCLUDED.allow_unattended, \
                    updated_at_epoch_millis=EXCLUDED.updated_at_epoch_millis",
                &[&id, &device.capabilities.controlled, &device.capabilities.file_transfer,
                    &device.capabilities.unattended, &created, &updated],
            )
            .await?;
    }
    Ok(())
}

async fn persist_mfa(
    transaction: &Transaction<'_>,
    before: &Database,
    after: &Database,
    mfa_key: &[u8; 32],
) -> Result<(), PersistenceError> {
    let now = to_i64_lossless(now_epoch_millis());
    for (id, previous) in &before.mfa_factors {
        if previous.active
            && !after
                .mfa_factors
                .get(id)
                .is_some_and(|factor| factor.active)
        {
            transaction
                .execute(
                    "UPDATE account_mfa_factors SET status='disabled', disabled_at_epoch_millis=$2 \
                     WHERE factor_id=$1 AND status='active'",
                    &[id, &now],
                )
                .await?;
        }
    }
    for (id, factor) in changed_values(&before.mfa_factors, &after.mfa_factors) {
        if !factor.active {
            continue;
        }
        let encrypted = encrypt_mfa(mfa_key, factor).map_err(PersistenceError::Data)?;
        let created = to_i64_lossless(factor.created_at_epoch_millis);
        let last_used = factor.last_used_counter.map(|_| now);
        transaction
            .execute(
                "INSERT INTO account_mfa_factors (factor_id, account_id, factor_type, \
                    encrypted_secret, status, last_used_at_epoch_millis, created_at_epoch_millis) \
                 VALUES ($1,$2,'totp',$3,'active',$4,$5) ON CONFLICT (factor_id) DO UPDATE SET \
                    encrypted_secret=EXCLUDED.encrypted_secret, status='active', \
                    last_used_at_epoch_millis=EXCLUDED.last_used_at_epoch_millis, \
                    disabled_at_epoch_millis=NULL",
                &[&id, &factor.account_id, &encrypted, &last_used, &created],
            )
            .await?;
    }
    Ok(())
}

async fn persist_recovery_codes(
    transaction: &Transaction<'_>,
    before: &Database,
    after: &Database,
) -> Result<(), PersistenceError> {
    let now = to_i64_lossless(now_epoch_millis());
    for id in before.recovery_codes.keys() {
        if !after.recovery_codes.contains_key(id) {
            transaction
                .execute(
                    "UPDATE account_recovery_codes SET status='revoked' \
                     WHERE recovery_code_id=$1 AND status='active'",
                    &[id],
                )
                .await?;
        }
    }
    for (id, code) in changed_values(&before.recovery_codes, &after.recovery_codes) {
        let status = if code.used_at_epoch_millis.is_some() {
            "used"
        } else {
            "active"
        };
        let used = code.used_at_epoch_millis.map(to_i64_lossless);
        let expires = code.expires_at_epoch_millis.map(to_i64_lossless);
        transaction
            .execute(
                "INSERT INTO account_recovery_codes (recovery_code_id, account_id, code_hash, \
                    status, used_at_epoch_millis, created_at_epoch_millis, \
                    expires_at_epoch_millis) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (recovery_code_id) DO UPDATE SET \
                    status=EXCLUDED.status, used_at_epoch_millis=EXCLUDED.used_at_epoch_millis, \
                    expires_at_epoch_millis=EXCLUDED.expires_at_epoch_millis",
                &[
                    &id,
                    &code.account_id,
                    &&code.code_hash[..],
                    &status,
                    &used,
                    &now,
                    &expires,
                ],
            )
            .await?;
    }
    Ok(())
}

async fn persist_recovery_code_deliveries(
    transaction: &Transaction<'_>,
    before: &Database,
    after: &Database,
) -> Result<(), PersistenceError> {
    for (id, delivery) in changed_values(
        &before.recovery_code_deliveries,
        &after.recovery_code_deliveries,
    ) {
        validate_recovery_code_delivery(delivery).map_err(PersistenceError::Data)?;
        let recovery_code_count = i16::try_from(delivery.recovery_code_count).map_err(|_| {
            PersistenceError::Data(
                "mfa_recovery_code_deliveries.recovery_code_count exceeds SMALLINT".into(),
            )
        })?;
        let created = to_i64_lossless(delivery.created_at_epoch_millis);
        let expires = to_i64_lossless(delivery.expires_at_epoch_millis);
        let acknowledged = delivery.acknowledged_at_epoch_millis.map(to_i64_lossless);
        let affected = transaction
            .execute(
                "INSERT INTO mfa_recovery_code_deliveries (delivery_id, account_id,
                    account_session_id, factor_id, idempotency_key_hash,
                    finish_request_binding_hash, client_ephemeral_public_key,
                    server_ephemeral_public_key, nonce, ciphertext, recovery_code_count,
                    created_at_epoch_millis, expires_at_epoch_millis,
                    acknowledged_at_epoch_millis)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
                 ON CONFLICT (delivery_id) DO UPDATE SET
                    acknowledged_at_epoch_millis=COALESCE(
                        mfa_recovery_code_deliveries.acknowledged_at_epoch_millis,
                        EXCLUDED.acknowledged_at_epoch_millis)
                 WHERE mfa_recovery_code_deliveries.account_id=EXCLUDED.account_id
                   AND mfa_recovery_code_deliveries.account_session_id=EXCLUDED.account_session_id
                   AND mfa_recovery_code_deliveries.factor_id=EXCLUDED.factor_id
                   AND mfa_recovery_code_deliveries.idempotency_key_hash=EXCLUDED.idempotency_key_hash
                   AND mfa_recovery_code_deliveries.finish_request_binding_hash=EXCLUDED.finish_request_binding_hash
                   AND mfa_recovery_code_deliveries.client_ephemeral_public_key=EXCLUDED.client_ephemeral_public_key
                   AND mfa_recovery_code_deliveries.server_ephemeral_public_key=EXCLUDED.server_ephemeral_public_key
                   AND mfa_recovery_code_deliveries.nonce=EXCLUDED.nonce
                   AND mfa_recovery_code_deliveries.ciphertext=EXCLUDED.ciphertext
                   AND mfa_recovery_code_deliveries.recovery_code_count=EXCLUDED.recovery_code_count
                   AND mfa_recovery_code_deliveries.created_at_epoch_millis=EXCLUDED.created_at_epoch_millis
                   AND mfa_recovery_code_deliveries.expires_at_epoch_millis=EXCLUDED.expires_at_epoch_millis",
                &[
                    &id,
                    &delivery.account_id,
                    &delivery.account_session_id,
                    &delivery.factor_id,
                    &&delivery.idempotency_key_hash[..],
                    &&delivery.finish_request_binding_hash[..],
                    &&delivery.client_ephemeral_public_key[..],
                    &&delivery.server_ephemeral_public_key[..],
                    &&delivery.nonce[..],
                    &delivery.ciphertext,
                    &recovery_code_count,
                    &created,
                    &expires,
                    &acknowledged,
                ],
            )
            .await?;
        if affected != 1 {
            return Err(PersistenceError::Data(format!(
                "mfa_recovery_code_deliveries refused binding change for {id}"
            )));
        }
    }
    Ok(())
}

async fn persist_risk_challenges(
    transaction: &Transaction<'_>,
    before: &Database,
    after: &Database,
) -> Result<(), PersistenceError> {
    for (id, challenge) in changed_values(&before.risk_challenges, &after.risk_challenges) {
        validate_fixed_enum(
            &challenge.purpose,
            "account_risk_challenges.purpose",
            RISK_CHALLENGE_PURPOSES,
        )
        .map_err(PersistenceError::Data)?;
        validate_fixed_enum(
            &challenge.risk_level,
            "account_risk_challenges.risk_level",
            RISK_LEVELS,
        )
        .map_err(PersistenceError::Data)?;
        if challenge.attempts_remaining > 5 {
            return Err(PersistenceError::Data(
                "account_risk_challenges.attempts_remaining exceeds 5".into(),
            ));
        }
        let required_methods = Value::Array(
            challenge
                .required_methods
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        );
        let attempts_remaining = i16::from(challenge.attempts_remaining);
        let expires = to_i64_lossless(challenge.expires_at_epoch_millis);
        let created = to_i64_lossless(challenge.created_at_epoch_millis);
        let verified = challenge.verified_at_epoch_millis.map(to_i64_lossless);
        let consumed = challenge.consumed_at_epoch_millis.map(to_i64_lossless);
        let affected = transaction
            .execute(
                "INSERT INTO account_risk_challenges (risk_challenge_id, account_id, device_id, \
                    purpose, operation_binding_hash, risk_level, required_methods, status, \
                    attempts_remaining, ip_address, user_agent, expires_at_epoch_millis, \
                    created_at_epoch_millis, verified_at_epoch_millis, consumed_at_epoch_millis) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::text::inet,$11,$12,$13,$14,$15) \
                 ON CONFLICT (risk_challenge_id) DO UPDATE SET \
                    status=EXCLUDED.status, \
                    attempts_remaining=LEAST(account_risk_challenges.attempts_remaining, \
                        EXCLUDED.attempts_remaining), \
                    verified_at_epoch_millis=COALESCE( \
                        account_risk_challenges.verified_at_epoch_millis, \
                        EXCLUDED.verified_at_epoch_millis), \
                    consumed_at_epoch_millis=COALESCE( \
                        account_risk_challenges.consumed_at_epoch_millis, \
                        EXCLUDED.consumed_at_epoch_millis) \
                 WHERE account_risk_challenges.account_id=EXCLUDED.account_id \
                    AND account_risk_challenges.device_id IS NOT DISTINCT FROM EXCLUDED.device_id \
                    AND account_risk_challenges.purpose=EXCLUDED.purpose \
                    AND account_risk_challenges.operation_binding_hash=EXCLUDED.operation_binding_hash \
                    AND account_risk_challenges.risk_level=EXCLUDED.risk_level \
                    AND account_risk_challenges.required_methods=EXCLUDED.required_methods \
                    AND account_risk_challenges.ip_address IS NOT DISTINCT FROM EXCLUDED.ip_address \
                    AND account_risk_challenges.user_agent IS NOT DISTINCT FROM EXCLUDED.user_agent \
                    AND account_risk_challenges.expires_at_epoch_millis=EXCLUDED.expires_at_epoch_millis \
                    AND account_risk_challenges.created_at_epoch_millis=EXCLUDED.created_at_epoch_millis \
                    AND ((account_risk_challenges.status='issued' \
                            AND EXCLUDED.status IN ('issued','verified','failed','consumed','expired','cancelled')) \
                        OR (account_risk_challenges.status='verified' \
                            AND EXCLUDED.status IN ('verified','consumed','expired','cancelled')))",
                &[
                    &id,
                    &challenge.account_id,
                    &challenge.device_id,
                    &challenge.purpose,
                    &&challenge.operation_binding_hash[..],
                    &challenge.risk_level,
                    &required_methods,
                    &risk_challenge_status_name(challenge.status),
                    &attempts_remaining,
                    &challenge.ip_address,
                    &challenge.user_agent,
                    &expires,
                    &created,
                    &verified,
                    &consumed,
                ],
            )
            .await?;
        if affected != 1 {
            return Err(PersistenceError::Data(format!(
                "account_risk_challenges refused stale or terminal update for {id}"
            )));
        }
    }
    Ok(())
}

async fn persist_device_enrollment_grants(
    transaction: &Transaction<'_>,
    before: &Database,
    after: &Database,
) -> Result<(), PersistenceError> {
    for (id, grant) in changed_values(
        &before.device_enrollment_grants,
        &after.device_enrollment_grants,
    ) {
        validate_device_enrollment_grant(grant).map_err(PersistenceError::Data)?;
        let protocol_version = i32::from(grant.protocol_version);
        let issued = to_i64_lossless(grant.issued_at_epoch_millis);
        let expires = to_i64_lossless(grant.expires_at_epoch_millis);
        let consumed = grant.consumed_at_epoch_millis.map(to_i64_lossless);
        let registration_binding = grant
            .registration_request_binding_hash
            .as_ref()
            .map(|value| &value[..]);
        let affected = transaction
            .execute(
                "INSERT INTO device_enrollment_grants (grant_id, grant_secret_hash, account_id,
                    device_id, device_public_key_fingerprint, login_challenge_id,
                    login_challenge_binding_hash, trust_proof_type, trust_level,
                    establish_trust, protocol_version, issued_account_session_id,
                    issued_at_epoch_millis, expires_at_epoch_millis,
                    consumed_at_epoch_millis, registration_request_binding_hash,
                    registered_public_key_id, registered_trusted_device_id,
                    created_at_epoch_millis)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$13)
                 ON CONFLICT (grant_id) DO UPDATE SET
                    consumed_at_epoch_millis=COALESCE(
                        device_enrollment_grants.consumed_at_epoch_millis,
                        EXCLUDED.consumed_at_epoch_millis),
                    registration_request_binding_hash=COALESCE(
                        device_enrollment_grants.registration_request_binding_hash,
                        EXCLUDED.registration_request_binding_hash),
                    registered_public_key_id=COALESCE(
                        device_enrollment_grants.registered_public_key_id,
                        EXCLUDED.registered_public_key_id),
                    registered_trusted_device_id=COALESCE(
                        device_enrollment_grants.registered_trusted_device_id,
                        EXCLUDED.registered_trusted_device_id)
                 WHERE device_enrollment_grants.grant_secret_hash=EXCLUDED.grant_secret_hash
                   AND device_enrollment_grants.account_id=EXCLUDED.account_id
                   AND device_enrollment_grants.device_id=EXCLUDED.device_id
                   AND device_enrollment_grants.device_public_key_fingerprint=EXCLUDED.device_public_key_fingerprint
                   AND device_enrollment_grants.login_challenge_id=EXCLUDED.login_challenge_id
                   AND device_enrollment_grants.login_challenge_binding_hash=EXCLUDED.login_challenge_binding_hash
                   AND device_enrollment_grants.trust_proof_type IS NOT DISTINCT FROM EXCLUDED.trust_proof_type
                   AND device_enrollment_grants.trust_level IS NOT DISTINCT FROM EXCLUDED.trust_level
                   AND device_enrollment_grants.establish_trust=EXCLUDED.establish_trust
                   AND device_enrollment_grants.protocol_version=EXCLUDED.protocol_version
                   AND device_enrollment_grants.issued_account_session_id=EXCLUDED.issued_account_session_id
                   AND device_enrollment_grants.issued_at_epoch_millis=EXCLUDED.issued_at_epoch_millis
                   AND device_enrollment_grants.expires_at_epoch_millis=EXCLUDED.expires_at_epoch_millis
                   AND (device_enrollment_grants.registration_request_binding_hash IS NULL
                        OR device_enrollment_grants.registration_request_binding_hash=EXCLUDED.registration_request_binding_hash)
                   AND (device_enrollment_grants.registered_public_key_id IS NULL
                        OR device_enrollment_grants.registered_public_key_id=EXCLUDED.registered_public_key_id)
                   AND (device_enrollment_grants.registered_trusted_device_id IS NULL
                        OR device_enrollment_grants.registered_trusted_device_id=EXCLUDED.registered_trusted_device_id)",
                &[
                    &id,
                    &&grant.grant_secret_hash[..],
                    &grant.account_id,
                    &grant.device_id,
                    &&grant.device_public_key_fingerprint[..],
                    &grant.login_challenge_id,
                    &&grant.login_challenge_binding_hash[..],
                    &grant.trust_proof_type,
                    &grant.trust_level,
                    &grant.establish_trust,
                    &protocol_version,
                    &grant.issued_account_session_id,
                    &issued,
                    &expires,
                    &consumed,
                    &registration_binding,
                    &grant.registered_public_key_id,
                    &grant.registered_trusted_device_id,
                ],
            )
            .await?;
        if affected != 1 {
            return Err(PersistenceError::Data(format!(
                "device_enrollment_grants refused binding change for {id}"
            )));
        }
    }
    Ok(())
}

async fn persist_trusted_controller_devices(
    transaction: &Transaction<'_>,
    before: &Database,
    after: &Database,
) -> Result<(), PersistenceError> {
    for (id, trusted) in changed_values(
        &before.trusted_controller_devices,
        &after.trusted_controller_devices,
    ) {
        validate_fixed_enum(
            &trusted.trust_level,
            "trusted_controller_devices.trust_level",
            TRUST_LEVELS,
        )
        .map_err(PersistenceError::Data)?;
        validate_fixed_enum(
            &trusted.trust_proof_type,
            "trusted_controller_devices.trust_proof_type",
            TRUST_PROOF_TYPES,
        )
        .map_err(PersistenceError::Data)?;
        let created = to_i64_lossless(trusted.created_at_epoch_millis);
        let last_used = trusted.last_used_at_epoch_millis.map(to_i64_lossless);
        let expires = to_i64_lossless(trusted.expires_at_epoch_millis);
        let revoked = trusted.revoked_at_epoch_millis.map(to_i64_lossless);
        let affected = transaction
            .execute(
                "INSERT INTO trusted_controller_devices (trusted_device_id, account_id, \
                    controller_device_id, device_fingerprint_hash, trust_level, status, \
                    trust_proof_type, created_at_epoch_millis, last_used_at_epoch_millis, \
                    expires_at_epoch_millis, revoked_at_epoch_millis) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) \
                 ON CONFLICT (trusted_device_id) DO UPDATE SET \
                    trust_level=EXCLUDED.trust_level, status=EXCLUDED.status, \
                    last_used_at_epoch_millis=CASE \
                        WHEN trusted_controller_devices.last_used_at_epoch_millis IS NULL \
                            THEN EXCLUDED.last_used_at_epoch_millis \
                        WHEN EXCLUDED.last_used_at_epoch_millis IS NULL \
                            THEN trusted_controller_devices.last_used_at_epoch_millis \
                        ELSE GREATEST(trusted_controller_devices.last_used_at_epoch_millis, \
                            EXCLUDED.last_used_at_epoch_millis) END, \
                    expires_at_epoch_millis=EXCLUDED.expires_at_epoch_millis, \
                    revoked_at_epoch_millis=COALESCE( \
                        trusted_controller_devices.revoked_at_epoch_millis, \
                        EXCLUDED.revoked_at_epoch_millis) \
                 WHERE trusted_controller_devices.account_id=EXCLUDED.account_id \
                    AND trusted_controller_devices.controller_device_id=EXCLUDED.controller_device_id \
                    AND trusted_controller_devices.device_fingerprint_hash=EXCLUDED.device_fingerprint_hash \
                    AND trusted_controller_devices.trust_proof_type=EXCLUDED.trust_proof_type \
                    AND trusted_controller_devices.created_at_epoch_millis=EXCLUDED.created_at_epoch_millis \
                    AND trusted_controller_devices.status='active' \
                    AND EXCLUDED.status IN ('active','expired','revoked')",
                &[
                    &id,
                    &trusted.account_id,
                    &trusted.controller_device_id,
                    &&trusted.device_fingerprint_hash[..],
                    &trusted.trust_level,
                    &trusted_device_status_name(trusted.status),
                    &trusted.trust_proof_type,
                    &created,
                    &last_used,
                    &expires,
                    &revoked,
                ],
            )
            .await?;
        if affected != 1 {
            return Err(PersistenceError::Data(format!(
                "trusted_controller_devices refused stale or terminal update for {id}"
            )));
        }
    }
    Ok(())
}

async fn find_session_idempotency(
    transaction: &Transaction<'_>,
    record: &IdempotencyRecord,
) -> Result<Option<ExistingSessionIdempotency>, PersistenceError> {
    let row = transaction
        .query_opt(
            "SELECT body_hash, resource_id FROM api_idempotency_keys
             WHERE account_id=$1 AND device_id=$2 AND method=$3 AND path=$4
               AND idempotency_key=$5
             FOR UPDATE",
            &[
                &record.account_id,
                &record.device_id,
                &record.method,
                &record.path,
                &record.idempotency_key,
            ],
        )
        .await?;
    row.map(session_idempotency_from_row).transpose()
}

async fn claim_session_idempotency(
    transaction: &Transaction<'_>,
    record: &IdempotencyRecord,
    body_hash: &[u8; 32],
) -> Result<SessionIdempotencyClaim, PersistenceError> {
    let created = to_i64_lossless(record.created_at_epoch_millis);
    let expires = to_i64_lossless(record.expires_at_epoch_millis);
    let response_status: i16 = if record.operation == "create" {
        201
    } else {
        200
    };
    let affected = transaction
        .execute(
            "INSERT INTO api_idempotency_keys (idempotency_key, account_id, device_id,
                    method, path, body_hash, request_id, resource_type, resource_id,
                    response_status, expires_at_epoch_millis, created_at_epoch_millis)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
             ON CONFLICT (account_id, device_id, method, path, idempotency_key) DO NOTHING",
            &[
                &record.idempotency_key,
                &record.account_id,
                &record.device_id,
                &record.method,
                &record.path,
                &&body_hash[..],
                &record.request_id,
                &record.operation,
                &record.session_id,
                &response_status,
                &expires,
                &created,
            ],
        )
        .await?;
    match affected {
        1 => Ok(SessionIdempotencyClaim::Claimed),
        0 => find_session_idempotency(transaction, record)
            .await?
            .map(SessionIdempotencyClaim::Existing)
            .ok_or_else(|| {
                PersistenceError::Data(
                    "api_idempotency_keys conflict row disappeared during claim".to_owned(),
                )
            }),
        _ => Err(PersistenceError::Data(format!(
            "api_idempotency_keys claim affected {affected} rows"
        ))),
    }
}

fn session_idempotency_from_row(row: Row) -> Result<ExistingSessionIdempotency, PersistenceError> {
    let body_hash = fixed_32(
        row.try_get::<_, Vec<u8>>("body_hash")?,
        "api_idempotency_keys.body_hash",
    )
    .map_err(PersistenceError::Data)?;
    let resource_id = row
        .try_get::<_, Option<String>>("resource_id")?
        .ok_or_else(|| {
            PersistenceError::Data(
                "api_idempotency_keys.resource_id is missing for a session request".to_owned(),
            )
        })?;
    Ok(ExistingSessionIdempotency {
        body_hash,
        resource_id,
    })
}

async fn load_transaction_session(
    transaction: &Transaction<'_>,
    session_id: &str,
) -> Result<Session, PersistenceError> {
    let sql = format!("{SESSION_AUTHORITY_SELECT} WHERE session_id=$1");
    let row = transaction.query_opt(&sql, &[&session_id]).await?;
    let row = row.ok_or_else(|| {
        PersistenceError::Data(format!(
            "api_idempotency_keys references missing session {session_id}"
        ))
    })?;
    session_from_row(&row).map_err(PersistenceError::Data)
}

async fn session_devices_are_authorizable(
    transaction: &Transaction<'_>,
    session: &Session,
) -> Result<bool, PersistenceError> {
    if session.controller_device_id == session.controlled_device_id {
        return Ok(false);
    }
    let mut device_ids = [
        session.controller_device_id.as_str(),
        session.controlled_device_id.as_str(),
    ];
    device_ids.sort_unstable();
    let mut devices = BTreeMap::new();
    for device_id in device_ids {
        let row = transaction
            .query_opt(
                "SELECT account_id, status FROM devices WHERE device_id=$1 FOR UPDATE",
                &[&device_id],
            )
            .await?;
        let Some(row) = row else {
            return Ok(false);
        };
        devices.insert(
            device_id,
            (
                row.try_get::<_, String>("account_id")?,
                row.try_get::<_, String>("status")?,
            ),
        );
    }
    let Some((controller_account_id, controller_status)) =
        devices.get(session.controller_device_id.as_str())
    else {
        return Ok(false);
    };
    let Some((_, controlled_status)) = devices.get(session.controlled_device_id.as_str()) else {
        return Ok(false);
    };
    let controlled_policy = transaction
        .query_opt(
            "SELECT allow_remote_desktop FROM device_policies
             WHERE device_id=$1 FOR SHARE",
            &[&session.controlled_device_id],
        )
        .await?;
    Ok(controller_account_id == &session.controller_account_id
        && matches!(controller_status.as_str(), "online" | "offline" | "busy")
        && matches!(controlled_status.as_str(), "online" | "offline" | "busy")
        && controlled_policy.is_some_and(|row| row.get::<_, bool>("allow_remote_desktop")))
}

async fn load_replay_event(
    transaction: &Transaction<'_>,
    session_id: &str,
    event: &SessionEvent,
) -> Result<(String, Option<Session>), PersistenceError> {
    let row = transaction
        .query_opt(
            "SELECT event_id, metadata FROM session_events
             WHERE session_id=$1 AND event_type=$2
               AND actor_device_id IS NOT DISTINCT FROM $3
               AND metadata->>'idempotency_key_hash'=$4
             ORDER BY created_at_epoch_millis DESC, event_id DESC
             LIMIT 1",
            &[
                &session_id,
                &event.event_type,
                &event.actor_device_id,
                &event.idempotency_key_hash,
            ],
        )
        .await?;
    let row = row.ok_or_else(|| {
        PersistenceError::Data(format!(
            "session idempotency replay cannot find event for session {session_id}"
        ))
    })?;
    let event_id = row.try_get("event_id")?;
    let metadata: Value = row.try_get("metadata")?;
    let result_session = metadata
        .get("result_session")
        .cloned()
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| {
            PersistenceError::Data(format!(
                "session idempotency replay snapshot is invalid: {error}"
            ))
        })?;
    if result_session
        .as_ref()
        .is_some_and(|session: &Session| session.session_id != session_id)
    {
        return Err(PersistenceError::Data(
            "session idempotency replay snapshot references another session".to_owned(),
        ));
    }
    Ok((event_id, result_session))
}

async fn insert_policy_evaluation_strict(
    transaction: &Transaction<'_>,
    evaluation: &PolicyEvaluation,
) -> Result<(), PersistenceError> {
    let permissions = serde_json::to_value(evaluation.effective_permissions).map_err(|error| {
        PersistenceError::Data(format!("encode policy effective_permissions: {error}"))
    })?;
    let digest = decode_hex_32(&evaluation.permissions_digest).map_err(PersistenceError::Data)?;
    let created = to_i64_lossless(evaluation.evaluated_at_epoch_millis);
    transaction
        .execute(
            "INSERT INTO policy_evaluations (policy_evaluation_id, account_id,
                    controller_device_id, controlled_device_id, session_id, request_type,
                    access_decision, anti_abuse_decision, session_access_decision,
                    effective_permissions, permissions_digest, created_at_epoch_millis)
             VALUES ($1,$2,$3,$4,$5,'remote_session',$6,$7,$8,$9,$10,$11)",
            &[
                &evaluation.policy_evaluation_id,
                &evaluation.account_id,
                &evaluation.controller_device_id,
                &evaluation.controlled_device_id,
                &evaluation.session_id,
                &evaluation.access_decision,
                &evaluation.anti_abuse_decision,
                &evaluation.session_access_decision,
                &permissions,
                &&digest[..],
                &created,
            ],
        )
        .await?;
    Ok(())
}

async fn insert_session_strict(
    transaction: &Transaction<'_>,
    session: &Session,
) -> Result<(), PersistenceError> {
    let permissions = serde_json::to_value(session.permissions)
        .map_err(|error| PersistenceError::Data(format!("encode session permissions: {error}")))?;
    let digest = decode_hex_32(&session.permissions_digest).map_err(PersistenceError::Data)?;
    let relay_epoch = to_i64_lossless(session.relay_token_epoch);
    let expires = to_i64_lossless(session.session_expires_at_epoch_millis);
    let created = to_i64_lossless(session.created_at_epoch_millis);
    let updated = to_i64_lossless(session.updated_at_epoch_millis);
    let ended = session.ended_at_epoch_millis.map(to_i64_lossless);
    transaction
        .execute(
            "INSERT INTO sessions (session_id, controller_account_id, controller_device_id,
                    controlled_device_id, auth_method, status, permissions, permissions_digest,
                    permissions_digest_last_changed_at_epoch_millis, policy_evaluation_id,
                    relay_token_epoch, session_expires_at_epoch_millis, ended_at_epoch_millis,
                    created_at_epoch_millis, updated_at_epoch_millis)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$9,$14)",
            &[
                &session.session_id,
                &session.controller_account_id,
                &session.controller_device_id,
                &session.controlled_device_id,
                &auth_method_name(session.auth_method),
                &session_status_name(session.status),
                &permissions,
                &&digest[..],
                &created,
                &session.policy_evaluation_id,
                &relay_epoch,
                &expires,
                &ended,
                &updated,
            ],
        )
        .await?;
    Ok(())
}

async fn insert_session_event_strict(
    transaction: &Transaction<'_>,
    event: &SessionEvent,
) -> Result<(), PersistenceError> {
    let metadata = json!({
        "from_status": event.from_status.map(session_status_name),
        "to_status": session_status_name(event.to_status),
        "idempotency_key_hash": event.idempotency_key_hash,
        "request_id": event.request_id,
        "result_session": event.result_session,
    });
    let created = to_i64_lossless(event.created_at_epoch_millis);
    let actor_role = event.actor_role.as_deref().unwrap_or("none");
    transaction
        .execute(
            "INSERT INTO session_events (event_id, session_id, event_type, actor_type,
                    actor_account_id, actor_device_id, actor_role, reason, metadata,
                    created_at_epoch_millis) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            &[
                &event.event_id,
                &event.session_id,
                &event.event_type,
                &event.actor_type,
                &event.actor_account_id,
                &event.actor_device_id,
                &actor_role,
                &event.reason,
                &metadata,
                &created,
            ],
        )
        .await?;
    Ok(())
}

async fn persist_policy_evaluations(
    transaction: &Transaction<'_>,
    before: &Database,
    after: &Database,
) -> Result<(), PersistenceError> {
    for (id, evaluation) in changed_values(&before.policy_evaluations, &after.policy_evaluations) {
        let permissions =
            serde_json::to_value(evaluation.effective_permissions).map_err(|error| {
                PersistenceError::Data(format!("encode policy effective_permissions: {error}"))
            })?;
        let digest =
            decode_hex_32(&evaluation.permissions_digest).map_err(PersistenceError::Data)?;
        let created = to_i64_lossless(evaluation.evaluated_at_epoch_millis);
        transaction
            .execute(
                "INSERT INTO policy_evaluations (policy_evaluation_id, account_id, \
                    controller_device_id, controlled_device_id, session_id, request_type, \
                    access_decision, anti_abuse_decision, session_access_decision, \
                    effective_permissions, permissions_digest, created_at_epoch_millis) \
                 VALUES ($1,$2,$3,$4,$5,'remote_session',$6,$7,$8,$9,$10,$11) \
                 ON CONFLICT (policy_evaluation_id) DO NOTHING",
                &[
                    &id,
                    &evaluation.account_id,
                    &evaluation.controller_device_id,
                    &evaluation.controlled_device_id,
                    &evaluation.session_id,
                    &evaluation.access_decision,
                    &evaluation.anti_abuse_decision,
                    &evaluation.session_access_decision,
                    &permissions,
                    &&digest[..],
                    &created,
                ],
            )
            .await?;
    }
    Ok(())
}

async fn persist_sessions(
    transaction: &Transaction<'_>,
    before: &Database,
    after: &Database,
) -> Result<(), PersistenceError> {
    for (id, session) in changed_values(&before.sessions, &after.sessions) {
        let permissions = serde_json::to_value(session.permissions).map_err(|error| {
            PersistenceError::Data(format!("encode session permissions: {error}"))
        })?;
        let digest = decode_hex_32(&session.permissions_digest).map_err(PersistenceError::Data)?;
        let relay_epoch = to_i64_lossless(session.relay_token_epoch);
        let expires = to_i64_lossless(session.session_expires_at_epoch_millis);
        let created = to_i64_lossless(session.created_at_epoch_millis);
        let updated = to_i64_lossless(session.updated_at_epoch_millis);
        let ended = session.ended_at_epoch_millis.map(to_i64_lossless);
        transaction
            .execute(
                "INSERT INTO sessions (session_id, controller_account_id, controller_device_id, \
                    controlled_device_id, auth_method, status, permissions, permissions_digest, \
                    permissions_digest_last_changed_at_epoch_millis, policy_evaluation_id, \
                    relay_token_epoch, session_expires_at_epoch_millis, ended_at_epoch_millis, \
                    created_at_epoch_millis, updated_at_epoch_millis) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$9,$14) \
                 ON CONFLICT (session_id) DO UPDATE SET status=EXCLUDED.status, \
                    permissions=EXCLUDED.permissions, permissions_digest=EXCLUDED.permissions_digest, \
                    permissions_digest_last_changed_at_epoch_millis=EXCLUDED.permissions_digest_last_changed_at_epoch_millis, \
                    relay_token_epoch=GREATEST(sessions.relay_token_epoch, \
                        EXCLUDED.relay_token_epoch), \
                    session_expires_at_epoch_millis=EXCLUDED.session_expires_at_epoch_millis, \
                    ended_at_epoch_millis=EXCLUDED.ended_at_epoch_millis, \
                    updated_at_epoch_millis=EXCLUDED.updated_at_epoch_millis",
                &[&id, &session.controller_account_id, &session.controller_device_id,
                    &session.controlled_device_id, &auth_method_name(session.auth_method),
                    &session_status_name(session.status), &permissions, &&digest[..], &created,
                    &session.policy_evaluation_id, &relay_epoch, &expires, &ended, &updated],
            )
            .await?;
    }
    Ok(())
}

async fn persist_idempotency(
    transaction: &Transaction<'_>,
    before: &Database,
    after: &Database,
) -> Result<(), PersistenceError> {
    for (_, record) in changed_values(&before.session_idempotency, &after.session_idempotency) {
        let body_hash = decode_hex_32(&record.body_hash).map_err(PersistenceError::Data)?;
        let created = to_i64_lossless(record.created_at_epoch_millis);
        let expires = to_i64_lossless(record.expires_at_epoch_millis);
        let response_status: i16 = if record.operation == "create" {
            201
        } else {
            200
        };
        transaction
            .execute(
                "INSERT INTO api_idempotency_keys (idempotency_key, account_id, device_id, \
                    method, path, body_hash, request_id, resource_type, resource_id, \
                    response_status, expires_at_epoch_millis, created_at_epoch_millis) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) \
                 ON CONFLICT (account_id, device_id, method, path, idempotency_key) DO NOTHING",
                &[
                    &record.idempotency_key,
                    &record.account_id,
                    &record.device_id,
                    &record.method,
                    &record.path,
                    &&body_hash[..],
                    &record.request_id,
                    &record.operation,
                    &record.session_id,
                    &response_status,
                    &expires,
                    &created,
                ],
            )
            .await?;
    }
    Ok(())
}

async fn persist_session_events(
    transaction: &Transaction<'_>,
    before: &Database,
    after: &Database,
) -> Result<(), PersistenceError> {
    let existing = before
        .session_events
        .iter()
        .map(|event| event.event_id.as_str())
        .collect::<HashSet<_>>();
    for event in after
        .session_events
        .iter()
        .filter(|event| !existing.contains(event.event_id.as_str()))
    {
        let metadata = json!({
            "from_status": event.from_status.map(session_status_name),
            "to_status": session_status_name(event.to_status),
            "idempotency_key_hash": event.idempotency_key_hash,
            "request_id": event.request_id,
            "result_session": event.result_session,
        });
        let created = to_i64_lossless(event.created_at_epoch_millis);
        let actor_role = event.actor_role.as_deref().unwrap_or("none");
        transaction
            .execute(
                "INSERT INTO session_events (event_id, session_id, event_type, actor_type, \
                    actor_account_id, actor_device_id, actor_role, reason, metadata, \
                    created_at_epoch_millis) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) \
                 ON CONFLICT (event_id) DO NOTHING",
                &[
                    &event.event_id,
                    &event.session_id,
                    &event.event_type,
                    &event.actor_type,
                    &event.actor_account_id,
                    &event.actor_device_id,
                    &actor_role,
                    &event.reason,
                    &metadata,
                    &created,
                ],
            )
            .await?;
    }
    Ok(())
}

async fn persist_audit_logs(
    transaction: &Transaction<'_>,
    before: &Database,
    after: &Database,
) -> Result<(), PersistenceError> {
    let existing = before
        .audit_logs
        .iter()
        .map(|entry| entry.audit_id.as_str())
        .collect::<HashSet<_>>();
    for entry in after
        .audit_logs
        .iter()
        .filter(|entry| !existing.contains(entry.audit_id.as_str()))
    {
        let metadata = Value::Object(entry.metadata.clone().into_iter().collect());
        let created = to_i64_lossless(entry.created_at_epoch_millis);
        let actor_role = entry.actor_role.as_deref().unwrap_or("none");
        transaction
            .execute(
                "INSERT INTO audit_logs (audit_id, actor_type, actor_account_id, actor_device_id, \
                    actor_role, actor_service, target_device_id, session_id, action, result, \
                    reason, metadata, request_id, created_at_epoch_millis) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) \
                 ON CONFLICT (audit_id) DO NOTHING",
                &[
                    &entry.audit_id,
                    &entry.actor_type,
                    &entry.actor_account_id,
                    &entry.actor_device_id,
                    &actor_role,
                    &entry.actor_service,
                    &entry.target_device_id,
                    &entry.session_id,
                    &entry.action,
                    &entry.result,
                    &entry.reason,
                    &metadata,
                    &entry.request_id,
                    &created,
                ],
            )
            .await?;
    }
    Ok(())
}

async fn revoke_account_sessions_and_trust(
    transaction: &Transaction<'_>,
    account_id: &str,
    revoked_reason: &str,
    now_epoch_millis: i64,
    source_audit: &AuditEntry,
) -> Result<Vec<AuditEntry>, StoreError> {
    if !ACCOUNT_SESSION_REVOKED_REASONS.contains(&revoked_reason)
        || source_audit.actor_account_id.as_deref() != Some(account_id)
    {
        return Err(StoreError::Conflict);
    }
    let session_rows = transaction
        .query(
            "UPDATE account_sessions
             SET revoked_at_epoch_millis=$3, revoked_reason=$2,
                 updated_at_epoch_millis=GREATEST(updated_at_epoch_millis,$3)
             WHERE account_id=$1 AND revoked_at_epoch_millis IS NULL
               AND revoked_reason IS NULL
             RETURNING account_session_id",
            &[&account_id, &revoked_reason, &now_epoch_millis],
        )
        .await
        .map_err(log_store_error)?;
    let trust_rows = transaction
        .query(
            "UPDATE trusted_controller_devices
             SET status='revoked', revoked_at_epoch_millis=$2
             WHERE account_id=$1 AND status='active'
             RETURNING trusted_device_id, controller_device_id",
            &[&account_id, &now_epoch_millis],
        )
        .await
        .map_err(log_store_error)?;
    let mut audits = Vec::with_capacity(session_rows.len() + trust_rows.len());
    for row in session_rows {
        audits.push(account_session_revocation_audit(
            source_audit,
            &row.get::<_, String>("account_session_id"),
            revoked_reason,
        ));
    }
    for row in trust_rows {
        audits.push(trusted_device_revocation_audit(
            source_audit,
            &row.get::<_, String>("trusted_device_id"),
            &row.get::<_, String>("controller_device_id"),
            revoked_reason,
        ));
    }
    for audit in &audits {
        insert_audit_entry_strict(transaction, audit)
            .await
            .map_err(log_conflict_or_store_error)?;
    }
    Ok(audits)
}

async fn insert_audit_entry_strict(
    transaction: &Transaction<'_>,
    entry: &AuditEntry,
) -> Result<(), tokio_postgres::Error> {
    let metadata = Value::Object(entry.metadata.clone().into_iter().collect());
    let created = to_i64_lossless(entry.created_at_epoch_millis);
    let actor_role = entry.actor_role.as_deref().unwrap_or("none");
    transaction
        .execute(
            "INSERT INTO audit_logs (audit_id, actor_type, actor_account_id, actor_device_id, \
                    actor_role, actor_service, target_device_id, session_id, action, result, \
                    reason, metadata, request_id, created_at_epoch_millis) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
            &[
                &entry.audit_id,
                &entry.actor_type,
                &entry.actor_account_id,
                &entry.actor_device_id,
                &actor_role,
                &entry.actor_service,
                &entry.target_device_id,
                &entry.session_id,
                &entry.action,
                &entry.result,
                &entry.reason,
                &metadata,
                &entry.request_id,
                &created,
            ],
        )
        .await
        .map(|_| ())
}

async fn reject_locked_login_challenge(
    transaction: &Transaction<'_>,
    challenge_id: &str,
    attempts_remaining: u8,
) -> Result<(u8, RiskChallengeStatus), tokio_postgres::Error> {
    let remaining = attempts_remaining.saturating_sub(1);
    let status = if remaining == 0 { "failed" } else { "issued" };
    transaction
        .execute(
            "UPDATE account_risk_challenges
             SET attempts_remaining=$2, status=$3
             WHERE risk_challenge_id=$1 AND status='issued'",
            &[&challenge_id, &i16::from(remaining), &status],
        )
        .await?;
    Ok((
        remaining,
        if remaining == 0 {
            RiskChallengeStatus::Failed
        } else {
            RiskChallengeStatus::Issued
        },
    ))
}

fn validate_device_enrollment_grant(grant: &DeviceEnrollmentGrant) -> Result<(), String> {
    if grant.grant_id.trim().is_empty()
        || grant.account_id.trim().is_empty()
        || grant.device_id.trim().is_empty()
        || grant.login_challenge_id.trim().is_empty()
        || grant.issued_account_session_id.trim().is_empty()
        || grant.protocol_version == 0
    {
        return Err("device_enrollment_grants contains an empty required field".to_owned());
    }
    let ttl = grant
        .expires_at_epoch_millis
        .checked_sub(grant.issued_at_epoch_millis)
        .ok_or_else(|| "device_enrollment_grants expiry precedes issue time".to_owned())?;
    if ttl == 0 || ttl > 300_000 {
        return Err("device_enrollment_grants expiry exceeds 5 minutes".to_owned());
    }
    if grant.consumed_at_epoch_millis.is_some_and(|consumed| {
        consumed < grant.issued_at_epoch_millis || consumed > grant.expires_at_epoch_millis
    }) {
        return Err("device_enrollment_grants consumed time is outside its TTL".to_owned());
    }
    let registration_result_valid = match grant.consumed_at_epoch_millis {
        None => {
            grant.registration_request_binding_hash.is_none()
                && grant.registered_public_key_id.is_none()
                && grant.registered_trusted_device_id.is_none()
        }
        Some(_) => {
            grant.registration_request_binding_hash.is_some()
                && grant
                    .registered_public_key_id
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty())
                && (grant.establish_trust == grant.registered_trusted_device_id.is_some())
                && grant
                    .registered_trusted_device_id
                    .as_deref()
                    .is_none_or(|value| !value.trim().is_empty())
        }
    };
    if !registration_result_valid {
        return Err("device_enrollment_grants registration result is inconsistent".to_owned());
    }
    match (
        grant.establish_trust,
        grant.trust_proof_type.as_deref(),
        grant.trust_level.as_deref(),
    ) {
        (false, None, None) => Ok(()),
        (true, Some(proof), Some(level)) => {
            validate_fixed_enum(
                proof,
                "device_enrollment_grants.trust_proof_type",
                TRUST_PROOF_TYPES,
            )?;
            validate_fixed_enum(level, "device_enrollment_grants.trust_level", TRUST_LEVELS)
        }
        _ => Err("device_enrollment_grants trust decision is inconsistent".to_owned()),
    }
}

fn grant_trust_matches_factor(grant: &DeviceEnrollmentGrant, factor: Option<&str>) -> bool {
    match factor {
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
                && grant.trust_proof_type.as_deref() == Some("device_signature_and_recovery_code")
                && grant.trust_level.as_deref() == Some("high_risk_step_up_required")
        }
        Some(_) => false,
    }
}

fn validate_trusted_device(trusted: &TrustedControllerDevice) -> Result<(), String> {
    validate_fixed_enum(
        &trusted.trust_level,
        "trusted_controller_devices.trust_level",
        TRUST_LEVELS,
    )?;
    validate_fixed_enum(
        &trusted.trust_proof_type,
        "trusted_controller_devices.trust_proof_type",
        TRUST_PROOF_TYPES,
    )?;
    let ttl = trusted
        .expires_at_epoch_millis
        .checked_sub(trusted.created_at_epoch_millis)
        .ok_or_else(|| "trusted_controller_devices expiry precedes creation".to_owned())?;
    if ttl == 0 || ttl > 30 * 24 * 60 * 60 * 1_000 {
        return Err("trusted_controller_devices expiry exceeds 30 days".to_owned());
    }
    if trusted.status != TrustedDeviceStatus::Active
        || trusted.last_used_at_epoch_millis.is_some()
        || trusted.revoked_at_epoch_millis.is_some()
    {
        return Err("new trusted_controller_devices row is not active".to_owned());
    }
    match trusted.trust_proof_type.as_str() {
        "device_signature_and_mfa"
            if trusted.trust_level == "standard" && ttl == 30 * 24 * 60 * 60 * 1_000 =>
        {
            Ok(())
        }
        "device_signature_and_recovery_code"
            if trusted.trust_level == "high_risk_step_up_required"
                && ttl == 24 * 60 * 60 * 1_000 =>
        {
            Ok(())
        }
        _ => Err("trusted_controller_devices proof, level, or TTL is inconsistent".to_owned()),
    }
}

fn validate_recovery_code_delivery(delivery: &RecoveryCodeDelivery) -> Result<(), String> {
    if delivery.delivery_id.trim().is_empty()
        || delivery.account_id.trim().is_empty()
        || delivery.account_session_id.trim().is_empty()
        || delivery.factor_id.trim().is_empty()
        || delivery.recovery_code_count == 0
        || delivery.ciphertext.len() < 16
    {
        return Err("mfa_recovery_code_deliveries contains invalid required data".to_owned());
    }
    let ttl = delivery
        .expires_at_epoch_millis
        .checked_sub(delivery.created_at_epoch_millis)
        .ok_or_else(|| "mfa_recovery_code_deliveries expiry precedes creation".to_owned())?;
    if ttl == 0 || ttl > 24 * 60 * 60 * 1_000 {
        return Err("mfa_recovery_code_deliveries expiry exceeds 24 hours".to_owned());
    }
    if delivery
        .acknowledged_at_epoch_millis
        .is_some_and(|acknowledged| {
            acknowledged < delivery.created_at_epoch_millis
                || acknowledged > delivery.expires_at_epoch_millis
        })
    {
        return Err("mfa_recovery_code_deliveries acknowledgement is outside its TTL".to_owned());
    }
    Ok(())
}

async fn insert_trusted_device_strict(
    transaction: &Transaction<'_>,
    trusted: &TrustedControllerDevice,
) -> Result<(), PersistenceError> {
    validate_trusted_device(trusted).map_err(PersistenceError::Data)?;
    let created = to_i64_lossless(trusted.created_at_epoch_millis);
    let expires = to_i64_lossless(trusted.expires_at_epoch_millis);
    transaction
        .execute(
            "INSERT INTO trusted_controller_devices (trusted_device_id, account_id,
                controller_device_id, device_fingerprint_hash, trust_level, status,
                trust_proof_type, created_at_epoch_millis, last_used_at_epoch_millis,
                expires_at_epoch_millis, revoked_at_epoch_millis)
             VALUES ($1,$2,$3,$4,$5,'active',$6,$7,NULL,$8,NULL)",
            &[
                &trusted.trusted_device_id,
                &trusted.account_id,
                &trusted.controller_device_id,
                &&trusted.device_fingerprint_hash[..],
                &trusted.trust_level,
                &trusted.trust_proof_type,
                &created,
                &expires,
            ],
        )
        .await?;
    Ok(())
}

async fn insert_device_registration_strict(
    transaction: &Transaction<'_>,
    device: &Device,
) -> Result<(), PersistenceError> {
    let version = i32::try_from(device.public_key_version).map_err(|_| {
        PersistenceError::Data("devices.public_key_version exceeds INTEGER".to_owned())
    })?;
    let created = to_i64_lossless(device.created_at_epoch_millis);
    let updated = to_i64_lossless(device.updated_at_epoch_millis);
    let revoked = device
        .public_key_revoked_at_epoch_millis
        .map(to_i64_lossless);
    let last_seen = device.last_seen_epoch_millis.map(to_i64_lossless);
    transaction
        .execute(
            "INSERT INTO devices (device_id, account_id, display_name, platform, os_version,
                arch, public_key_id, public_key, public_key_version,
                public_key_revoked_at_epoch_millis, status, unattended_enabled,
                last_seen_epoch_millis, created_at_epoch_millis, updated_at_epoch_millis)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
            &[
                &device.device_id,
                &device.account_id,
                &device.display_name,
                &platform_name(&device.platform),
                &device.os_version,
                &architecture_name(&device.arch),
                &device.public_key_id,
                &&device.public_key[..],
                &version,
                &revoked,
                &device_lifecycle_status_name(device.status),
                &device.capabilities.unattended,
                &last_seen,
                &created,
                &updated,
            ],
        )
        .await?;
    transaction
        .execute(
            "INSERT INTO device_policies (device_id, allow_remote_desktop,
                allow_input_control, allow_file_transfer, allow_unattended,
                created_at_epoch_millis, updated_at_epoch_millis)
             VALUES ($1,$2,$2,$3,$4,$5,$6)",
            &[
                &device.device_id,
                &device.capabilities.controlled,
                &device.capabilities.file_transfer,
                &device.capabilities.unattended,
                &created,
                &updated,
            ],
        )
        .await?;
    Ok(())
}

async fn load_transaction_device(
    transaction: &Transaction<'_>,
    device_id: &str,
) -> Result<Option<Device>, PersistenceError> {
    let sql = format!("{DEVICE_AUTHORITY_SELECT} WHERE d.device_id=$1 FOR UPDATE OF d");
    transaction
        .query_opt(&sql, &[&device_id])
        .await?
        .map(|row| {
            device_from_row(&row)
                .map(|(device, _)| device)
                .map_err(PersistenceError::Data)
        })
        .transpose()
}

async fn verify_replayed_device_trust(
    transaction: &Transaction<'_>,
    grant: &DeviceEnrollmentGrant,
) -> Result<(), StoreError> {
    if !grant.establish_trust {
        return if grant.registered_trusted_device_id.is_none() {
            Ok(())
        } else {
            Err(StoreError::Unavailable)
        };
    }
    let trusted_device_id = grant
        .registered_trusted_device_id
        .as_deref()
        .ok_or(StoreError::Unavailable)?;
    let row = transaction
        .query_opt(
            "SELECT trusted_device_id, account_id, controller_device_id,
                    device_fingerprint_hash, trust_level, status, trust_proof_type,
                    created_at_epoch_millis, last_used_at_epoch_millis,
                    expires_at_epoch_millis, revoked_at_epoch_millis
             FROM trusted_controller_devices
             WHERE trusted_device_id=$1
             FOR SHARE",
            &[&trusted_device_id],
        )
        .await
        .map_err(log_store_error)?
        .ok_or(StoreError::Unavailable)?;
    let trusted = trusted_device_from_row(&row).map_err(|reason| {
        error!(%reason, "PostgreSQL replayed registration trust row is invalid");
        StoreError::Unavailable
    })?;
    if trusted.account_id != grant.account_id
        || trusted.controller_device_id != grant.device_id
        || trusted.trust_proof_type.as_str() != grant.trust_proof_type.as_deref().unwrap_or("")
        || trusted.trust_level.as_str() != grant.trust_level.as_deref().unwrap_or("")
        || !constant_time_sha256_eq(
            &trusted.device_fingerprint_hash,
            &grant.device_public_key_fingerprint,
        )
    {
        return Err(StoreError::Unavailable);
    }
    Ok(())
}

fn changed_values<'a, V: PartialEq>(
    before: &'a BTreeMap<String, V>,
    after: &'a BTreeMap<String, V>,
) -> impl Iterator<Item = (&'a String, &'a V)> {
    after
        .iter()
        .filter(|(key, value)| before.get(*key) != Some(*value))
}

#[derive(Serialize, Deserialize)]
struct MfaSecretPayload {
    secret_base32: String,
    last_used_counter: Option<u64>,
}

fn encrypt_mfa(key: &[u8; 32], factor: &MfaFactor) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0_u8; MFA_NONCE_BYTES];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let plaintext = serde_json::to_vec(&MfaSecretPayload {
        secret_base32: factor.secret_base32.clone(),
        last_used_counter: factor.last_used_counter,
    })
    .map_err(|error| format!("encode MFA secret: {error}"))?;
    let aad = mfa_aad(&factor.account_id, &factor.factor_id);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| "encrypt MFA secret".to_owned())?;
    let mut envelope = Vec::with_capacity(1 + MFA_NONCE_BYTES + ciphertext.len());
    envelope.push(MFA_ENVELOPE_VERSION);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

fn decrypt_mfa(
    key: &[u8; 32],
    account_id: &str,
    factor_id: &str,
    envelope: &[u8],
) -> Result<MfaSecretPayload, String> {
    if envelope.len() <= 1 + MFA_NONCE_BYTES || envelope[0] != MFA_ENVELOPE_VERSION {
        return Err("MFA secret envelope is invalid".to_owned());
    }
    let cipher = ChaCha20Poly1305::new(key.into());
    let aad = mfa_aad(account_id, factor_id);
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&envelope[1..1 + MFA_NONCE_BYTES]),
            Payload {
                msg: &envelope[1 + MFA_NONCE_BYTES..],
                aad: &aad,
            },
        )
        .map_err(|_| "MFA secret authentication failed".to_owned())?;
    serde_json::from_slice(&plaintext).map_err(|error| format!("decode MFA secret: {error}"))
}

fn mfa_aad(account_id: &str, factor_id: &str) -> Vec<u8> {
    canonical_fields(
        "rctl-mfa-secret-v1",
        &[
            ("account_id", account_id.as_bytes()),
            ("factor_id", factor_id.as_bytes()),
        ],
    )
}

fn load_error(table: &'static str) -> impl Fn(tokio_postgres::Error) -> String {
    move |error| format!("load {table}: {error}")
}

fn fixed_32(value: Vec<u8>, field: &str) -> Result<[u8; 32], String> {
    value
        .try_into()
        .map_err(|_| format!("{field} is not 32 bytes"))
}

fn parse_required_methods(value: Value) -> Result<Vec<String>, String> {
    let Value::Array(methods) = value else {
        return Err("account_risk_challenges.required_methods is not an array".to_owned());
    };
    methods
        .into_iter()
        .enumerate()
        .map(|(index, method)| match method {
            Value::String(method) => Ok(method),
            _ => Err(format!(
                "account_risk_challenges.required_methods[{index}] is not a string"
            )),
        })
        .collect()
}

fn validate_fixed_enum(value: &str, field: &str, allowed: &[&str]) -> Result<(), String> {
    if allowed.contains(&value) {
        Ok(())
    } else {
        Err(format!("{field} contains unsupported value {value}"))
    }
}

fn from_i64(value: i64) -> Result<u64, String> {
    u64::try_from(value).map_err(|_| "database timestamp is negative".to_owned())
}

fn optional_u64(value: Option<i64>) -> Result<Option<u64>, String> {
    value.map(from_i64).transpose()
}

fn to_i64_lossless(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn now_epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("digest is not 64 hexadecimal characters".to_owned());
    }
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "digest contains invalid hexadecimal".to_owned())?;
    }
    Ok(output)
}

fn account_status(status: AccountStatus) -> &'static str {
    match status {
        AccountStatus::Active => "active",
        AccountStatus::Disabled => "disabled",
    }
}

fn platform_name(platform: &Platform) -> &'static str {
    match platform {
        Platform::Windows => "windows",
        Platform::Ubuntu => "ubuntu",
        Platform::Ios => "ios",
    }
}

fn parse_platform(value: &str) -> Result<Platform, String> {
    match value {
        "windows" => Ok(Platform::Windows),
        "ubuntu" => Ok(Platform::Ubuntu),
        "ios" => Ok(Platform::Ios),
        _ => Err(format!("unsupported platform {value}")),
    }
}

fn architecture_name(architecture: &Architecture) -> &'static str {
    match architecture {
        Architecture::X86_64 => "x86_64",
        Architecture::Aarch64 => "aarch64",
    }
}

fn parse_architecture(value: &str) -> Result<Architecture, String> {
    match value {
        "x86_64" => Ok(Architecture::X86_64),
        "aarch64" => Ok(Architecture::Aarch64),
        _ => Err(format!("unsupported architecture {value}")),
    }
}

fn device_lifecycle_status_name(status: DeviceLifecycleStatus) -> &'static str {
    match status {
        DeviceLifecycleStatus::Online => "online",
        DeviceLifecycleStatus::Offline => "offline",
        DeviceLifecycleStatus::Busy => "busy",
        DeviceLifecycleStatus::Suspended => "suspended",
        DeviceLifecycleStatus::Disabled => "disabled",
        DeviceLifecycleStatus::Unbound => "unbound",
    }
}

fn parse_device_lifecycle_status(value: &str) -> Result<DeviceLifecycleStatus, String> {
    match value {
        "online" => Ok(DeviceLifecycleStatus::Online),
        "offline" => Ok(DeviceLifecycleStatus::Offline),
        "busy" => Ok(DeviceLifecycleStatus::Busy),
        "suspended" => Ok(DeviceLifecycleStatus::Suspended),
        "disabled" => Ok(DeviceLifecycleStatus::Disabled),
        "unbound" => Ok(DeviceLifecycleStatus::Unbound),
        _ => Err(format!("devices.status contains unsupported value {value}")),
    }
}

const fn is_terminal_device_lifecycle_status(status: DeviceLifecycleStatus) -> bool {
    matches!(
        status,
        DeviceLifecycleStatus::Suspended
            | DeviceLifecycleStatus::Disabled
            | DeviceLifecycleStatus::Unbound
    )
}

fn auth_method_name(method: AuthMethod) -> &'static str {
    match method {
        AuthMethod::AccountPrompt => "account_prompt",
        AuthMethod::TemporaryCode => "temporary_code",
        AuthMethod::Unattended => "unattended",
    }
}

fn parse_auth_method(value: &str) -> Result<AuthMethod, String> {
    match value {
        "account_prompt" => Ok(AuthMethod::AccountPrompt),
        "temporary_code" => Ok(AuthMethod::TemporaryCode),
        "unattended" => Ok(AuthMethod::Unattended),
        _ => Err(format!("unsupported auth_method {value}")),
    }
}

fn session_status_name(status: SessionStatus) -> &'static str {
    match status {
        SessionStatus::PendingCodeVerification => "pending_code_verification",
        SessionStatus::PendingUnattendedVerification => "pending_unattended_verification",
        SessionStatus::CodeVerified => "code_verified",
        SessionStatus::UnattendedVerified => "unattended_verified",
        SessionStatus::WaitingApproval => "waiting_approval",
        SessionStatus::Accepted => "accepted",
        SessionStatus::Connected => "connected",
        SessionStatus::Degraded => "degraded",
        SessionStatus::Reconnecting => "reconnecting",
        SessionStatus::Cancelled => "cancelled",
        SessionStatus::Closed => "closed",
        SessionStatus::Rejected => "rejected",
        SessionStatus::Failed => "failed",
    }
}

fn parse_session_status(value: &str) -> Result<SessionStatus, String> {
    match value {
        "pending_code_verification" => Ok(SessionStatus::PendingCodeVerification),
        "pending_unattended_verification" => Ok(SessionStatus::PendingUnattendedVerification),
        "code_verified" => Ok(SessionStatus::CodeVerified),
        "unattended_verified" => Ok(SessionStatus::UnattendedVerified),
        "waiting_approval" => Ok(SessionStatus::WaitingApproval),
        "accepted" => Ok(SessionStatus::Accepted),
        "connected" => Ok(SessionStatus::Connected),
        "degraded" => Ok(SessionStatus::Degraded),
        "reconnecting" => Ok(SessionStatus::Reconnecting),
        "cancelled" => Ok(SessionStatus::Cancelled),
        "closed" => Ok(SessionStatus::Closed),
        "rejected" => Ok(SessionStatus::Rejected),
        "failed" => Ok(SessionStatus::Failed),
        _ => Err(format!("unsupported session status {value}")),
    }
}

fn risk_challenge_status_name(status: RiskChallengeStatus) -> &'static str {
    match status {
        RiskChallengeStatus::Issued => "issued",
        RiskChallengeStatus::Verified => "verified",
        RiskChallengeStatus::Failed => "failed",
        RiskChallengeStatus::Consumed => "consumed",
        RiskChallengeStatus::Expired => "expired",
        RiskChallengeStatus::Cancelled => "cancelled",
    }
}

fn parse_risk_challenge_status(value: &str) -> Result<RiskChallengeStatus, String> {
    match value {
        "issued" => Ok(RiskChallengeStatus::Issued),
        "verified" => Ok(RiskChallengeStatus::Verified),
        "failed" => Ok(RiskChallengeStatus::Failed),
        "consumed" => Ok(RiskChallengeStatus::Consumed),
        "expired" => Ok(RiskChallengeStatus::Expired),
        "cancelled" => Ok(RiskChallengeStatus::Cancelled),
        _ => Err(format!(
            "account_risk_challenges.status contains unsupported value {value}"
        )),
    }
}

fn trusted_device_status_name(status: TrustedDeviceStatus) -> &'static str {
    match status {
        TrustedDeviceStatus::Active => "active",
        TrustedDeviceStatus::Expired => "expired",
        TrustedDeviceStatus::Revoked => "revoked",
    }
}

fn parse_trusted_device_status(value: &str) -> Result<TrustedDeviceStatus, String> {
    match value {
        "active" => Ok(TrustedDeviceStatus::Active),
        "expired" => Ok(TrustedDeviceStatus::Expired),
        "revoked" => Ok(TrustedDeviceStatus::Revoked),
        _ => Err(format!(
            "trusted_controller_devices.status contains unsupported value {value}"
        )),
    }
}

fn optional_role(value: String) -> Option<String> {
    (value != "none").then_some(value)
}

fn idempotency_storage_key(
    account_id: &str,
    device_id: &str,
    method: &str,
    path: &str,
    idempotency_key: &str,
) -> String {
    sha256_hex(
        format!(
            "{account_id}\0{device_id}\0{}\0{path}\0{idempotency_key}",
            method.to_ascii_uppercase()
        )
        .as_bytes(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issued_risk_challenge(
        risk_challenge_id: String,
        account_id: String,
        device_id: String,
        created_at_epoch_millis: u64,
    ) -> RiskChallenge {
        RiskChallenge {
            risk_challenge_id,
            account_id,
            device_id: Some(device_id),
            purpose: "password_change".into(),
            operation_binding_hash: [9; 32],
            risk_level: "high".into(),
            required_methods: Vec::new(),
            status: RiskChallengeStatus::Issued,
            attempts_remaining: 5,
            ip_address: Some("127.0.0.1".into()),
            user_agent: Some("postgres-multi-instance-test".into()),
            expires_at_epoch_millis: created_at_epoch_millis + 300_000,
            created_at_epoch_millis,
            verified_at_epoch_millis: None,
            consumed_at_epoch_millis: None,
        }
    }

    fn risk_challenge_audit(challenge: &RiskChallenge) -> AuditEntry {
        AuditEntry {
            audit_id: format!("audit-{}", challenge.risk_challenge_id),
            actor_type: "account".into(),
            actor_account_id: Some(challenge.account_id.clone()),
            actor_device_id: challenge.device_id.clone(),
            actor_role: None,
            actor_service: None,
            target_device_id: challenge.device_id.clone(),
            session_id: None,
            action: "risk_challenge_issued".into(),
            result: "success".into(),
            reason: None,
            metadata: BTreeMap::new(),
            request_id: format!("request-{}", challenge.risk_challenge_id),
            created_at_epoch_millis: challenge.created_at_epoch_millis,
        }
    }

    fn risk_challenge_cancelled_audit(challenge: &RiskChallenge) -> AuditEntry {
        let mut audit = risk_challenge_audit(challenge);
        audit.audit_id = format!("audit-cancelled-{}", challenge.risk_challenge_id);
        audit.action = "risk_challenge_failed".into();
        audit.result = "failure".into();
        audit.reason = Some("cancelled".into());
        audit
    }

    fn normalized_sql(sql: &str) -> String {
        sql.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    #[test]
    fn account_session_sql_persists_and_restores_mfa_verified() {
        let insert = normalized_sql(INSERT_ACCOUNT_SESSION_SQL);
        assert!(insert
            .contains("refresh_token_hash, mfa_verified, device_label, expires_at_epoch_millis"));
        assert!(insert.contains("VALUES ($1,$2,$3,$4,'unified-client',$5,NULL,NULL,$6,$6)"));

        for read_sql in [
            LOAD_REFRESH_ACCOUNT_SESSION_SQL,
            LOAD_ACCOUNT_SESSIONS_SQL,
            ROTATE_REFRESH_ACCOUNT_SESSION_SQL,
        ] {
            assert!(
                normalized_sql(read_sql).contains("mfa_verified"),
                "account session materialization must select mfa_verified"
            );
        }

        let rotate = normalized_sql(ROTATE_REFRESH_ACCOUNT_SESSION_SQL);
        assert!(rotate.contains("account_id=$2 AND mfa_verified=$4"));
        assert!(rotate.contains(
            "RETURNING account_session_id, account_id, refresh_token_hash, mfa_verified"
        ));

        let upsert = normalized_sql(UPSERT_ACCOUNT_SESSION_SQL);
        assert!(upsert
            .contains("refresh_token_hash, mfa_verified, device_label, expires_at_epoch_millis"));
        assert!(upsert.contains("mfa_verified=EXCLUDED.mfa_verified"));
    }

    #[test]
    fn account_session_schema_requires_mfa_verified() {
        let schema = include_str!("../../../infra/migrations/0001_initial_schema.sql");
        let account_sessions = schema
            .split_once("CREATE TABLE account_sessions (")
            .and_then(|(_, remainder)| remainder.split_once("\n);"))
            .map(|(table, _)| table)
            .expect("0001 must define account_sessions");

        assert!(account_sessions.contains("mfa_verified BOOLEAN NOT NULL"));
    }

    #[test]
    fn login_challenge_schema_requires_account_security_snapshot() {
        let schema = include_str!("../../../infra/migrations/0001_initial_schema.sql");
        let challenges = schema
            .split_once("CREATE TABLE account_risk_challenges (")
            .and_then(|(_, remainder)| remainder.split_once("\n);"))
            .map(|(table, _)| table)
            .expect("0001 must define account_risk_challenges");
        assert!(challenges.contains(
            "login_account_updated_at_epoch_millis BIGINT CHECK (login_account_updated_at_epoch_millis >= 0)"
        ));
        assert!(challenges.contains("login_account_updated_at_epoch_millis IS NOT NULL"));
        assert!(challenges.contains("login_account_updated_at_epoch_millis IS NULL"));
    }

    #[test]
    fn risk_challenge_cancel_audit_requires_frozen_fields() {
        let challenge = issued_risk_challenge(
            "risk-cancel".into(),
            "account-1".into(),
            "device-1".into(),
            1,
        );
        let audit = risk_challenge_cancelled_audit(&challenge);
        assert!(risk_challenge_cancel_audit_is_valid(&challenge, &audit));

        for invalid in [
            AuditEntry {
                actor_account_id: Some("other-account".into()),
                ..audit.clone()
            },
            AuditEntry {
                action: "risk_challenge_succeeded".into(),
                ..audit.clone()
            },
            AuditEntry {
                result: "success".into(),
                ..audit.clone()
            },
            AuditEntry {
                reason: Some("expired".into()),
                ..audit.clone()
            },
        ] {
            assert!(!risk_challenge_cancel_audit_is_valid(&challenge, &invalid));
        }
    }

    #[tokio::test]
    #[ignore = "requires a migrated PostgreSQL database in API_TEST_DATABASE_URL"]
    async fn risk_challenge_create_and_cancel_use_authority_across_instances() {
        let database_url = std::env::var("API_TEST_DATABASE_URL")
            .expect("API_TEST_DATABASE_URL must point to an isolated migrated database");
        let left = PostgresRepository::connect(&database_url, [0; 32])
            .await
            .expect("connect left PostgreSQL repository");
        let right = PostgresRepository::connect(&database_url, [0; 32])
            .await
            .expect("connect right PostgreSQL repository");
        let suffix = crate::security::random_uuid_v4();
        let account_id = format!("risk-account-{suffix}");
        let device_id = format!("risk-device-{suffix}");
        let public_key_id = format!("risk-key-{suffix}");
        let email = format!("risk-{suffix}@example.com");
        let created_at = now_epoch_millis();
        {
            let client = left.client.lock().await;
            client
                .execute(
                    "INSERT INTO accounts (account_id, email, display_name, password_hash,
                        status, created_at_epoch_millis, updated_at_epoch_millis)
                     VALUES ($1,$2,'Risk Test','test-password-hash','active',$3,$3)",
                    &[&account_id, &email, &to_i64_lossless(created_at)],
                )
                .await
                .expect("insert risk challenge test account");
            client
                .execute(
                    "INSERT INTO devices (device_id, account_id, display_name, platform,
                        os_version, arch, public_key_id, public_key, public_key_version,
                        public_key_revoked_at_epoch_millis, status, unattended_enabled,
                        last_seen_epoch_millis, created_at_epoch_millis,
                        updated_at_epoch_millis)
                     VALUES ($1,$2,'Risk Device','ubuntu','26.04','x86_64',$3,$4,1,
                        NULL,'online',FALSE,$5,$5,$5)",
                    &[
                        &device_id,
                        &account_id,
                        &public_key_id,
                        &vec![7_u8; 32],
                        &to_i64_lossless(created_at),
                    ],
                )
                .await
                .expect("insert risk challenge test device");
        }

        let duplicate = issued_risk_challenge(
            format!("risk-duplicate-{suffix}"),
            account_id.clone(),
            device_id.clone(),
            created_at,
        );
        let duplicate_audit = risk_challenge_audit(&duplicate);
        let (left_create, right_create) = tokio::join!(
            left.create_risk_challenge(&duplicate, &duplicate_audit),
            right.create_risk_challenge(&duplicate, &duplicate_audit)
        );
        assert!(matches!(
            (left_create, right_create),
            (
                Ok(RiskChallengeCreationOutcome::Created(_)),
                Err(StoreError::Conflict)
            ) | (
                Err(StoreError::Conflict),
                Ok(RiskChallengeCreationOutcome::Created(_))
            )
        ));

        let challenge = issued_risk_challenge(
            format!("risk-cancel-{suffix}"),
            account_id.clone(),
            device_id,
            created_at,
        );
        let challenge_audit = risk_challenge_audit(&challenge);
        left.create_risk_challenge(&challenge, &challenge_audit)
            .await
            .expect("create cancellable risk challenge");
        let cancelled_audit = risk_challenge_cancelled_audit(&challenge);
        assert_eq!(
            right
                .cancel_risk_challenge(&challenge.risk_challenge_id, &cancelled_audit)
                .await,
            Ok(true),
            "an instance with a stale startup snapshot must cancel the authority row"
        );
        assert_eq!(
            left.cancel_risk_challenge(&challenge.risk_challenge_id, &cancelled_audit)
                .await,
            Ok(false),
            "cancelled is terminal for the cancellation operation"
        );
        assert_eq!(
            left.load_risk_challenge_authority(&challenge.risk_challenge_id)
                .await
                .expect("load authoritative challenge")
                .expect("challenge exists")
                .status,
            RiskChallengeStatus::Cancelled
        );
        left.read(&mut |database| {
            assert_eq!(
                database.risk_challenges[&challenge.risk_challenge_id].status,
                RiskChallengeStatus::Cancelled
            );
        })
        .await;

        let client = left.client.lock().await;
        let cancellation_audit = client
            .query_one(
                "SELECT COUNT(*) OVER () AS audit_count, actor_account_id, action, result, reason
                 FROM audit_logs WHERE audit_id=$1",
                &[&cancelled_audit.audit_id],
            )
            .await
            .expect("load cancellation audit");
        assert_eq!(cancellation_audit.get::<_, i64>("audit_count"), 1);
        assert_eq!(
            cancellation_audit.get::<_, Option<String>>("actor_account_id"),
            Some(account_id.clone())
        );
        assert_eq!(
            cancellation_audit.get::<_, String>("action"),
            "risk_challenge_failed"
        );
        assert_eq!(cancellation_audit.get::<_, String>("result"), "failure");
        assert_eq!(
            cancellation_audit
                .get::<_, Option<String>>("reason")
                .as_deref(),
            Some("cancelled")
        );
        client
            .execute(
                "DELETE FROM account_risk_challenges WHERE account_id=$1",
                &[&account_id],
            )
            .await
            .expect("delete risk challenge test rows");
        client
            .execute(
                "DELETE FROM audit_logs WHERE actor_account_id=$1",
                &[&account_id],
            )
            .await
            .expect("delete risk challenge test audits");
        client
            .execute("DELETE FROM accounts WHERE account_id=$1", &[&account_id])
            .await
            .expect("delete risk challenge test account");
    }

    #[test]
    fn mfa_envelope_round_trips_and_binds_factor() {
        let key = [7_u8; 32];
        let factor = MfaFactor {
            factor_id: "factor-1".into(),
            account_id: "account-1".into(),
            secret_base32: "JBSWY3DPEHPK3PXP".into(),
            active: true,
            last_used_counter: Some(42),
            created_at_epoch_millis: 1,
        };
        let envelope = encrypt_mfa(&key, &factor).expect("encrypt");
        assert!(!envelope
            .windows(factor.secret_base32.len())
            .any(|window| { window == factor.secret_base32.as_bytes() }));
        let payload =
            decrypt_mfa(&key, &factor.account_id, &factor.factor_id, &envelope).expect("decrypt");
        assert_eq!(payload.secret_base32, factor.secret_base32);
        assert_eq!(payload.last_used_counter, Some(42));
        assert!(decrypt_mfa(&key, "other-account", &factor.factor_id, &envelope).is_err());
    }

    #[test]
    fn required_methods_must_be_a_string_array() {
        assert_eq!(
            parse_required_methods(json!(["totp", "recovery_code"])).expect("string array"),
            vec!["totp", "recovery_code"]
        );
        assert!(parse_required_methods(json!({"method": "totp"})).is_err());
        assert!(parse_required_methods(json!(["totp", 1])).is_err());
    }

    #[test]
    fn account_security_enums_fail_closed() {
        assert_eq!(
            parse_risk_challenge_status("consumed").expect("known risk status"),
            RiskChallengeStatus::Consumed
        );
        assert!(parse_risk_challenge_status("reopened").is_err());
        assert_eq!(
            parse_trusted_device_status("revoked").expect("known trusted status"),
            TrustedDeviceStatus::Revoked
        );
        assert!(parse_trusted_device_status("restored").is_err());
        assert!(validate_fixed_enum(
            "unknown",
            "account_risk_challenges.purpose",
            RISK_CHALLENGE_PURPOSES
        )
        .is_err());
        assert!(validate_fixed_enum(
            "unknown",
            "trusted_controller_devices.trust_proof_type",
            TRUST_PROOF_TYPES
        )
        .is_err());
    }

    #[test]
    fn account_security_hashes_require_exactly_32_bytes() {
        assert!(fixed_32(vec![0; 31], "hash").is_err());
        assert_eq!(
            fixed_32(vec![7; 32], "hash").expect("32-byte hash"),
            [7; 32]
        );
        assert!(fixed_32(vec![0; 33], "hash").is_err());
    }

    #[test]
    fn device_lifecycle_status_round_trips_and_unknown_fails_closed() {
        let statuses = [
            DeviceLifecycleStatus::Online,
            DeviceLifecycleStatus::Offline,
            DeviceLifecycleStatus::Busy,
            DeviceLifecycleStatus::Suspended,
            DeviceLifecycleStatus::Disabled,
            DeviceLifecycleStatus::Unbound,
        ];

        for status in statuses {
            let persisted = device_lifecycle_status_name(status);
            assert_eq!(parse_device_lifecycle_status(persisted), Ok(status));
        }
        assert!(parse_device_lifecycle_status("active").is_err());
    }

    #[test]
    fn device_lifecycle_terminal_statuses_are_fail_closed() {
        assert!(!is_terminal_device_lifecycle_status(
            DeviceLifecycleStatus::Online
        ));
        assert!(!is_terminal_device_lifecycle_status(
            DeviceLifecycleStatus::Offline
        ));
        assert!(!is_terminal_device_lifecycle_status(
            DeviceLifecycleStatus::Busy
        ));
        assert!(is_terminal_device_lifecycle_status(
            DeviceLifecycleStatus::Suspended
        ));
        assert!(is_terminal_device_lifecycle_status(
            DeviceLifecycleStatus::Disabled
        ));
        assert!(is_terminal_device_lifecycle_status(
            DeviceLifecycleStatus::Unbound
        ));
    }
}
