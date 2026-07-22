use std::collections::BTreeMap;

use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error::{ApiError, ApiResult};
use crate::model::{
    Account, AccountSession, AccountStatus, AuditEntry, AuthChallenge, ChallengePurpose,
    DeviceEnrollmentGrant, LoginChallengeContext, LoginDeviceState, RiskChallenge,
    RiskChallengeStatus, TrustedControllerDevice, TrustedDeviceStatus,
};
use crate::security::{
    constant_time_sha256_eq, decode_base64url_32, decode_public_key, decode_sha256_hex,
    encode_base64url, hash_password, hex_encode, login_challenge_binding_hash,
    login_ip_address_hash, login_request_binding_hash, login_user_agent_hash, now_epoch_millis,
    random_bytes_32, random_token, random_uuid_v4, sha256, sha256_hex, sign_access_token,
    verify_device_signature, verify_password, verify_password_or_dummy, AccessClaims,
};
use crate::store::{
    LoginChallengeAuthority, LoginFinishCommand, LoginFinishOutcome, StepUpAction, StoreError,
};
use crate::{AppState, ObservedPeerIp, RequestId};

use super::{audit, authenticate, parse_json};

const MAX_LOGIN_FAILURES: u8 = 5;
const LOCK_MILLIS: u64 = 60_000;
const LOGIN_FAILURE_STATE_TTL_MILLIS: u64 = 15 * 60_000;
const TOTP_TRUST_TTL_MILLIS: u64 = 30 * 24 * 60 * 60 * 1_000;
const RECOVERY_TRUST_TTL_MILLIS: u64 = 24 * 60 * 60 * 1_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterRequest {
    email: String,
    password: String,
    display_name: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginRequest {
    email: String,
    password: String,
    device_id: String,
    device_public_key: String,
    public_key_id: Option<String>,
    public_key_version: u32,
    client_nonce: String,
    protocol_version: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginFinishRequest {
    login_challenge_id: String,
    login_request_binding_hash: String,
    login_challenge_binding_hash: String,
    client_nonce: String,
    server_nonce: String,
    factor: Option<String>,
    code: Option<String>,
    protocol_version: u16,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshRequest {
    refresh_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenResponse {
    pub account_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub access_token_expires_at_epoch_millis: u64,
    pub refresh_token_expires_at_epoch_millis: u64,
}

pub async fn register(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<TokenResponse>)> {
    let request: RegisterRequest = parse_json(&body, &request_id.0)?;
    let email = normalize_email(&request.email, &request_id.0)?;
    validate_password(&request.password, &request_id.0)?;
    if request.display_name.trim().is_empty() || request.display_name.len() > 100 {
        return Err(ApiError::bad_request(
            "invalid_display_name",
            "display_name must contain 1 to 100 characters",
            &request_id.0,
        ));
    }
    let password_hash =
        hash_password(&request.password).map_err(|_| ApiError::internal(&request_id.0))?;
    let account_id = random_uuid_v4();
    let now = now_epoch_millis();
    let account = Account {
        account_id: account_id.clone(),
        email: email.clone(),
        display_name: request.display_name.trim().to_owned(),
        password_hash,
        status: AccountStatus::Active,
        created_at_epoch_millis: now,
        updated_at_epoch_millis: now,
    };
    state
        .repository
        .transact(&mut |database| {
            if database.account_by_email.contains_key(&email) {
                return Err(StoreError::Conflict);
            }
            database
                .account_by_email
                .insert(email.clone(), account_id.clone());
            database
                .accounts
                .insert(account_id.clone(), account.clone());
            Ok(())
        })
        .await
        .map_err(|error| match error {
            StoreError::Conflict => ApiError::conflict(
                "account_exists",
                "an account already exists for this email",
                &request_id.0,
            ),
            StoreError::Unavailable => ApiError::internal(&request_id.0),
        })?;

    let tokens = issue_tokens(&state, &account_id, false, &request_id.0).await?;
    audit(
        &state,
        &request_id.0,
        "account",
        Some(&account_id),
        None,
        None,
        None,
        None,
        "login_succeeded",
        "success",
        None,
        BTreeMap::new(),
    )
    .await?;
    Ok((StatusCode::CREATED, Json(tokens)))
}

pub async fn login(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(ObservedPeerIp(observed_peer_ip)): Extension<ObservedPeerIp>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let request: LoginRequest = parse_json(&body, &request_id.0)?;
    validate_protocol_version(request.protocol_version, &request_id.0)?;
    validate_device_id(&request.device_id, &request_id.0)?;
    let requested_public_key = decode_public_key(&request.device_public_key).map_err(|_| {
        ApiError::bad_request(
            "invalid_device_public_key",
            "device_public_key must encode exactly 32 Ed25519 bytes",
            &request_id.0,
        )
    })?;
    let client_nonce = decode_base64url_32(&request.client_nonce).map_err(|_| {
        ApiError::bad_request(
            "invalid_client_nonce",
            "client_nonce must be 32 base64url bytes without padding",
            &request_id.0,
        )
    })?;
    let email = normalize_email(&request.email, &request_id.0)?;
    let now = now_epoch_millis();
    let account = state
        .repository
        .load_account_by_email(&email)
        .await
        .map_err(|_| ApiError::internal(&request_id.0))?;

    let login_failure_key = login_failure_key(account.as_ref(), &email);
    let locked = state
        .ephemeral
        .login_failure_state(&login_failure_key, now)
        .await
        .map_err(|_| ApiError::internal(&request_id.0))?
        .is_locked_at(now);
    let password_valid = verify_password_or_dummy(
        account
            .as_ref()
            .map(|account| account.password_hash.as_str()),
        &request.password,
    );
    let valid = account
        .as_ref()
        .is_some_and(|account| account.status == AccountStatus::Active && !locked)
        && password_valid;
    if !valid {
        record_login_failure(&state, &login_failure_key, account.as_ref(), &request_id.0).await?;
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "invalid_credentials",
            "email or password is invalid",
            &request_id.0,
        ));
    }
    let account = account.expect("valid login has account");
    state
        .ephemeral
        .clear_login_failures(&login_failure_key)
        .await
        .map_err(|_| ApiError::internal(&request_id.0))?;

    let authority = state
        .repository
        .load_device_authority(&request.device_id)
        .await
        .map_err(|_| ApiError::internal(&request_id.0))?;
    let (device_state, public_key_id, public_key_version, device_public_key) = match authority {
        Some(device)
            if device.account_id == account.account_id
                && device.status.is_authorizable()
                && device.public_key_revoked_at_epoch_millis.is_none()
                && request.public_key_id.as_deref() == Some(device.public_key_id.as_str())
                && request.public_key_version == device.public_key_version
                && requested_public_key == device.public_key =>
        {
            (
                LoginDeviceState::Registered,
                Some(device.public_key_id),
                device.public_key_version,
                device.public_key,
            )
        }
        None if request.public_key_id.is_none() && request.public_key_version == 0 => (
            LoginDeviceState::PendingEnrollment,
            None,
            0,
            requested_public_key,
        ),
        _ => {
            return Err(ApiError::forbidden(
                "device_identity_invalid",
                "device identity does not match the account authority record",
                &request_id.0,
            ));
        }
    };
    let device_public_key_fingerprint = sha256(&device_public_key);
    let mfa_enabled = state
        .repository
        .account_mfa_enabled(&account.account_id)
        .await
        .map_err(|_| ApiError::internal(&request_id.0))?;
    let trusted_device_id = if mfa_enabled && device_state == LoginDeviceState::Registered {
        state
            .repository
            .list_trusted_devices_for_account(&account.account_id)
            .await
            .map_err(|_| ApiError::internal(&request_id.0))?
            .into_iter()
            .find(|trusted| {
                trusted.controller_device_id == request.device_id
                    && trusted.status == TrustedDeviceStatus::Active
                    && trusted.expires_at_epoch_millis > now
                    && constant_time_sha256_eq(
                        &trusted.device_fingerprint_hash,
                        &device_public_key_fingerprint,
                    )
            })
            .map(|trusted| trusted.trusted_device_id)
    } else {
        None
    };
    let required_factors = if mfa_enabled && trusted_device_id.is_none() {
        vec!["totp".to_owned(), "recovery_code".to_owned()]
    } else {
        Vec::new()
    };
    let device_state_name = login_device_state_name(device_state);
    let issued_at = now;
    let expires_at = now.saturating_add(state.config.challenge_ttl_seconds * 1_000);
    let challenge_id = random_uuid_v4();
    let server_nonce = random_bytes_32();
    let ip_address = observed_peer_ip;
    let user_agent = sanitized_user_agent(&headers);
    let ip_address_hash = login_ip_address_hash(ip_address);
    let user_agent_hash = login_user_agent_hash(&user_agent);
    let request_binding_hash = login_request_binding_hash(
        &account.account_id,
        &request_id.0,
        &request.device_id,
        device_state_name,
        public_key_id.as_deref(),
        public_key_version,
        &device_public_key_fingerprint,
        &client_nonce,
        request.protocol_version,
    );
    let risk_decision = if required_factors.is_empty() {
        "allow"
    } else {
        "require_mfa"
    };
    let challenge_binding_hash = login_challenge_binding_hash(
        &challenge_id,
        &account.account_id,
        account.updated_at_epoch_millis,
        &request_binding_hash,
        &request.device_id,
        device_state_name,
        &device_public_key_fingerprint,
        &client_nonce,
        &server_nonce,
        &ip_address_hash,
        &user_agent_hash,
        risk_decision,
        &required_factors,
        issued_at,
        expires_at,
        state.config.challenge_attempts,
    );
    let challenge = AuthChallenge {
        challenge_id: challenge_id.clone(),
        account_id: account.account_id.clone(),
        device_id: (device_state == LoginDeviceState::Registered)
            .then(|| request.device_id.clone()),
        purpose: ChallengePurpose::LoginMfa,
        operation_binding_hash: Some(hex_encode(&challenge_binding_hash)),
        login: Some(LoginChallengeContext {
            device_state,
            device_id: request.device_id.clone(),
            account_updated_at_epoch_millis: account.updated_at_epoch_millis,
            device_public_key,
            device_public_key_fingerprint,
            public_key_id,
            public_key_version,
            client_nonce,
            server_nonce,
            login_request_binding_hash: request_binding_hash,
            login_challenge_binding_hash: challenge_binding_hash,
            ip_address_hash,
            user_agent_hash,
            required_factors: required_factors.clone(),
            trusted_device_id,
            protocol_version: request.protocol_version,
            issued_at_epoch_millis: issued_at,
            attempts_limit: state.config.challenge_attempts,
        }),
        attempts_remaining: state.config.challenge_attempts,
        expires_at_epoch_millis: expires_at,
        verified_at_epoch_millis: None,
        consumed_at_epoch_millis: None,
    };
    let persistent = RiskChallenge {
        risk_challenge_id: challenge_id.clone(),
        account_id: account.account_id.clone(),
        device_id: challenge.device_id.clone(),
        purpose: "login_mfa".to_owned(),
        operation_binding_hash: challenge_binding_hash,
        risk_level: if required_factors.is_empty() {
            "low".to_owned()
        } else {
            "medium".to_owned()
        },
        required_methods: required_factors.clone(),
        status: RiskChallengeStatus::Issued,
        attempts_remaining: state.config.challenge_attempts,
        ip_address: ip_address.map(|ip| ip.to_string()),
        user_agent: (!user_agent.is_empty()).then_some(user_agent),
        expires_at_epoch_millis: expires_at,
        created_at_epoch_millis: issued_at,
        verified_at_epoch_millis: None,
        consumed_at_epoch_millis: None,
    };
    let challenge_audit_entry = auth_audit_entry(
        &request_id.0,
        &account.account_id,
        (device_state == LoginDeviceState::Registered).then_some(request.device_id.as_str()),
        "mfa_challenge_issued",
        None,
        now,
    );
    state
        .repository
        .create_login_challenge(
            &LoginChallengeAuthority {
                challenge: persistent,
                context: challenge
                    .login
                    .clone()
                    .expect("new login challenge contains persistent context"),
            },
            &challenge_audit_entry,
        )
        .await
        .map_err(|_| ApiError::internal(&request_id.0))?;
    let _ = state.ephemeral.put_challenge(&challenge).await;
    Ok((
        StatusCode::ACCEPTED,
        Json(json!({
            "code": "login_challenge_required",
            "account_id": account.account_id,
            "login_challenge_id": challenge_id,
            "login_request_binding_hash": hex_encode(&request_binding_hash),
            "login_challenge_binding_hash": hex_encode(&challenge_binding_hash),
            "server_nonce": encode_base64url(&server_nonce),
            "device_state": device_state_name,
            "required_factors": required_factors,
            "expires_at_epoch_millis": expires_at,
            "attempts_remaining": state.config.challenge_attempts,
        })),
    ))
}

pub async fn login_finish(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Extension(ObservedPeerIp(observed_peer_ip)): Extension<ObservedPeerIp>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let request: LoginFinishRequest = parse_json(&body, &request_id.0)?;
    validate_protocol_version(request.protocol_version, &request_id.0)?;
    let now = now_epoch_millis();
    let request_binding_hash =
        decode_sha256_hex(&request.login_request_binding_hash).map_err(|_| {
            ApiError::bad_request(
                "invalid_login_binding",
                "login_request_binding_hash must be a hexadecimal SHA-256 digest",
                &request_id.0,
            )
        })?;
    let challenge_binding_hash =
        decode_sha256_hex(&request.login_challenge_binding_hash).map_err(|_| {
            ApiError::bad_request(
                "invalid_login_binding",
                "login_challenge_binding_hash must be a hexadecimal SHA-256 digest",
                &request_id.0,
            )
        })?;
    let client_nonce = decode_base64url_32(&request.client_nonce).map_err(|_| {
        ApiError::bad_request(
            "invalid_client_nonce",
            "client_nonce must be 32 base64url bytes without padding",
            &request_id.0,
        )
    })?;
    let server_nonce = decode_base64url_32(&request.server_nonce).map_err(|_| {
        ApiError::bad_request(
            "invalid_server_nonce",
            "server_nonce must be 32 base64url bytes without padding",
            &request_id.0,
        )
    })?;

    let authority = state
        .repository
        .load_login_challenge_authority(&request.login_challenge_id)
        .await
        .map_err(|_| ApiError::internal(&request_id.0))?
        .ok_or_else(|| login_verification_error(&request_id.0))?;
    let authoritative = &authority.challenge;
    if authoritative.purpose != "login_mfa"
        || !constant_time_sha256_eq(
            &authoritative.operation_binding_hash,
            &challenge_binding_hash,
        )
    {
        return Err(login_verification_error(&request_id.0));
    }
    let challenge = auth_challenge_from_authority(&authority);
    let context = authority.context.clone();
    let current_ip_hash = login_ip_address_hash(observed_peer_ip);
    let current_user_agent_hash = login_user_agent_hash(&sanitized_user_agent(&headers));
    let current_device = state
        .repository
        .load_device_authority(&context.device_id)
        .await
        .map_err(|_| ApiError::internal(&request_id.0))?;
    let device_authority_valid = match (context.device_state, current_device) {
        (LoginDeviceState::PendingEnrollment, None) => true,
        (LoginDeviceState::Registered, Some(device)) => {
            device.account_id == authoritative.account_id
                && device.status.is_authorizable()
                && device.public_key_id.as_str() == context.public_key_id.as_deref().unwrap_or("")
                && device.public_key_version == context.public_key_version
                && device.public_key_revoked_at_epoch_millis.is_none()
                && constant_time_sha256_eq(&device.public_key, &context.device_public_key)
        }
        _ => false,
    };
    let factor_shape_valid = if context.required_factors.is_empty() {
        request.factor.is_none() && request.code.is_none()
    } else {
        request.factor.as_ref().is_some_and(|factor| {
            context
                .required_factors
                .iter()
                .any(|allowed| allowed == factor)
        }) && request.code.as_ref().is_some_and(|code| !code.is_empty())
    };
    let recomputed_challenge_binding_hash = login_challenge_binding_hash(
        &challenge.challenge_id,
        &challenge.account_id,
        context.account_updated_at_epoch_millis,
        &context.login_request_binding_hash,
        &context.device_id,
        login_device_state_name(context.device_state),
        &context.device_public_key_fingerprint,
        &context.client_nonce,
        &context.server_nonce,
        &context.ip_address_hash,
        &context.user_agent_hash,
        if context.required_factors.is_empty() {
            "allow"
        } else {
            "require_mfa"
        },
        &context.required_factors,
        context.issued_at_epoch_millis,
        challenge.expires_at_epoch_millis,
        context.attempts_limit,
    );
    let context_valid = challenge.challenge_id == request.login_challenge_id
        && challenge.account_id == authoritative.account_id
        && context == authority.context
        && device_authority_valid
        && challenge.device_id
            == (context.device_state == LoginDeviceState::Registered)
                .then(|| context.device_id.clone())
        && constant_time_sha256_eq(
            &sha256(&context.device_public_key),
            &context.device_public_key_fingerprint,
        )
        && constant_time_sha256_eq(&context.login_request_binding_hash, &request_binding_hash)
        && constant_time_sha256_eq(
            &context.login_challenge_binding_hash,
            &challenge_binding_hash,
        )
        && constant_time_sha256_eq(&recomputed_challenge_binding_hash, &challenge_binding_hash)
        && constant_time_sha256_eq(&context.client_nonce, &client_nonce)
        && constant_time_sha256_eq(&context.server_nonce, &server_nonce)
        && constant_time_sha256_eq(&context.ip_address_hash, &current_ip_hash)
        && constant_time_sha256_eq(&context.user_agent_hash, &current_user_agent_hash)
        && context.protocol_version == request.protocol_version
        && factor_shape_valid;
    if !context_valid {
        reject_login_attempt(
            &state,
            &challenge,
            &challenge_binding_hash,
            now,
            &request_id.0,
        )
        .await?;
        return Err(login_verification_error(&request_id.0));
    }
    if let Err(error) = verify_login_device_signature(
        &state,
        &challenge.account_id,
        &context,
        &uri,
        &headers,
        &body,
        &request_id.0,
    )
    .await
    {
        reject_login_attempt(
            &state,
            &challenge,
            &challenge_binding_hash,
            now,
            &request_id.0,
        )
        .await?;
        return Err(error);
    }

    let mfa_verified = request.factor.is_some() || context.trusted_device_id.is_some();
    let (tokens, account_session) = build_token_bundle(
        &state,
        &challenge.account_id,
        mfa_verified,
        now,
        &request_id.0,
    )?;
    let mut enrollment_grant_secret = None;
    let enrollment_grant = if context.device_state == LoginDeviceState::PendingEnrollment {
        let grant_id = random_token(18);
        let grant_secret = random_token(32);
        let factor = request.factor.as_deref();
        let establish_trust = factor.is_some();
        let (trust_proof_type, trust_level) = trust_decision(factor);
        enrollment_grant_secret = Some(format!("{grant_id}.{grant_secret}"));
        Some(DeviceEnrollmentGrant {
            grant_id,
            grant_secret_hash: sha256(grant_secret.as_bytes()),
            account_id: challenge.account_id.clone(),
            device_id: signed_device_id(&headers, &request_id.0)?.to_owned(),
            device_public_key_fingerprint: context.device_public_key_fingerprint,
            login_challenge_id: request.login_challenge_id.clone(),
            login_challenge_binding_hash: context.login_challenge_binding_hash,
            trust_proof_type: trust_proof_type.map(ToOwned::to_owned),
            trust_level: trust_level.map(ToOwned::to_owned),
            establish_trust,
            protocol_version: request.protocol_version,
            issued_account_session_id: account_session.account_session_id.clone(),
            issued_at_epoch_millis: now,
            expires_at_epoch_millis: challenge.expires_at_epoch_millis,
            consumed_at_epoch_millis: None,
            registration_request_binding_hash: None,
            registered_public_key_id: None,
            registered_trusted_device_id: None,
        })
    } else {
        None
    };
    let trusted_device_to_create = if context.device_state == LoginDeviceState::Registered {
        request.factor.as_deref().map(|factor| {
            let (proof, level) = trust_decision(Some(factor));
            let ttl = if factor == "recovery_code" {
                RECOVERY_TRUST_TTL_MILLIS
            } else {
                TOTP_TRUST_TTL_MILLIS
            };
            TrustedControllerDevice {
                trusted_device_id: random_uuid_v4(),
                account_id: challenge.account_id.clone(),
                controller_device_id: signed_device_id(&headers, &request_id.0)
                    .expect("device id was verified")
                    .to_owned(),
                device_fingerprint_hash: context.device_public_key_fingerprint,
                trust_level: level.expect("MFA trust level").to_owned(),
                status: TrustedDeviceStatus::Active,
                trust_proof_type: proof.expect("MFA trust proof").to_owned(),
                created_at_epoch_millis: now,
                last_used_at_epoch_millis: None,
                expires_at_epoch_millis: now.saturating_add(ttl),
                revoked_at_epoch_millis: None,
            }
        })
    } else {
        None
    };
    let device_id = signed_device_id(&headers, &request_id.0)?.to_owned();
    let audit_device_id =
        (context.device_state == LoginDeviceState::Registered).then_some(device_id.as_str());
    let mut audit_entries = vec![
        auth_audit_entry(
            &request_id.0,
            &challenge.account_id,
            audit_device_id,
            "mfa_challenge_succeeded",
            None,
            now,
        ),
        auth_audit_entry(
            &request_id.0,
            &challenge.account_id,
            audit_device_id,
            "login_succeeded",
            None,
            now,
        ),
    ];
    if trusted_device_to_create.is_some() {
        audit_entries.push(auth_audit_entry(
            &request_id.0,
            &challenge.account_id,
            Some(&device_id),
            "trusted_device_added",
            None,
            now,
        ));
    }
    if request.factor.as_deref() == Some("recovery_code") {
        audit_entries.push(auth_audit_entry(
            &request_id.0,
            &challenge.account_id,
            (context.device_state == LoginDeviceState::Registered).then_some(device_id.as_str()),
            "mfa_recovery_code_used",
            None,
            now,
        ));
    }
    let outcome = state
        .repository
        .finish_login(&LoginFinishCommand {
            challenge_id: request.login_challenge_id.clone(),
            account_id: challenge.account_id.clone(),
            account_updated_at_epoch_millis: context.account_updated_at_epoch_millis,
            persistent_device_id: challenge.device_id.clone(),
            device_id,
            public_key_id: context.public_key_id.clone(),
            public_key_version: context.public_key_version,
            device_public_key_fingerprint: context.device_public_key_fingerprint,
            challenge_binding_hash,
            required_factors: context.required_factors.clone(),
            factor_kind: request.factor.clone(),
            factor_code: request.code.clone(),
            trusted_device_id_to_use: context.trusted_device_id.clone(),
            account_session,
            enrollment_grant: enrollment_grant.clone(),
            trusted_device_to_create,
            audit_entries,
            failure_audit_entry: auth_failure_audit_entry(
                &request_id.0,
                &challenge.account_id,
                (context.device_state == LoginDeviceState::Registered)
                    .then_some(context.device_id.as_str()),
                "mfa_challenge_failed",
                Some("verification_failed"),
                now,
            ),
            now_epoch_millis: now,
        })
        .await
        .map_err(|error| match error {
            StoreError::Conflict => login_verification_error(&request_id.0),
            StoreError::Unavailable => ApiError::internal(&request_id.0),
        })?;
    if outcome != LoginFinishOutcome::Completed {
        let already_decremented = matches!(
            outcome,
            LoginFinishOutcome::InvalidFactor | LoginFinishOutcome::Rejected
        );
        if !already_decremented {
            reject_login_attempt(
                &state,
                &challenge,
                &challenge_binding_hash,
                now,
                &request_id.0,
            )
            .await?;
        }
        return Err(login_verification_error(&request_id.0));
    }
    let mut response =
        serde_json::to_value(tokens).map_err(|_| ApiError::internal(&request_id.0))?;
    if let (Some(grant), Some(grant_token)) = (enrollment_grant, enrollment_grant_secret) {
        let object = response
            .as_object_mut()
            .ok_or_else(|| ApiError::internal(&request_id.0))?;
        object.insert(
            "device_enrollment_grant".to_owned(),
            Value::String(grant_token),
        );
        object.insert(
            "device_enrollment_grant_expires_at_epoch_millis".to_owned(),
            Value::from(grant.expires_at_epoch_millis),
        );
    }
    Ok(Json(response))
}

pub async fn refresh(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    body: Bytes,
) -> ApiResult<Json<TokenResponse>> {
    let request: RefreshRequest = parse_json(&body, &request_id.0)?;
    let token_hash = sha256(request.refresh_token.as_bytes());
    let now = now_epoch_millis();
    let matched = state
        .repository
        .load_refresh_session_authority(&token_hash, now)
        .await
        .map_err(|_| ApiError::internal(&request_id.0))?
        .ok_or_else(|| ApiError::unauthorized(&request_id.0))?;
    let (response, replacement) = build_token_bundle(
        &state,
        &matched.account_id,
        matched.mfa_verified,
        now,
        &request_id.0,
    )?;
    let refreshed = state
        .repository
        .rotate_refresh_session(
            &token_hash,
            &replacement,
            &auth_audit_entry(
                &request_id.0,
                &matched.account_id,
                None,
                "token_refreshed",
                None,
                now,
            ),
            now,
        )
        .await
        .map_err(|_| ApiError::internal(&request_id.0))?;
    if !refreshed {
        return Err(ApiError::unauthorized(&request_id.0));
    }
    Ok(Json(response))
}

pub async fn logout(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    let claims = authenticate(&state, &headers, &request_id.0).await?;
    let now = now_epoch_millis();
    let logout_audit =
        auth_audit_entry(&request_id.0, &claims.account_id, None, "logout", None, now);
    state
        .repository
        .revoke_account_session(
            &claims.account_session_id,
            &claims.account_id,
            now,
            &logout_audit,
        )
        .await
        .map_err(|_| ApiError::internal(&request_id.0))?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn change_password(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<StatusCode> {
    let claims = authenticate(&state, &headers, &request_id.0).await?;
    let request: ChangePasswordRequest = parse_json(&body, &request_id.0)?;
    validate_password(&request.new_password, &request_id.0)?;
    if request.current_password == request.new_password {
        return Err(ApiError::bad_request(
            "password_unchanged",
            "new_password must differ from current_password",
            &request_id.0,
        ));
    }
    let account = state
        .repository
        .load_account_by_id(&claims.account_id)
        .await
        .map_err(|_| ApiError::internal(&request_id.0))?
        .filter(|account| account.status == AccountStatus::Active)
        .ok_or_else(|| ApiError::unauthorized(&request_id.0))?;
    if !verify_password(&account.password_hash, &request.current_password) {
        return Err(ApiError::forbidden(
            "invalid_current_password",
            "current_password is invalid",
            &request_id.0,
        ));
    }
    let step_up = super::mfa::validate_step_up_for_request(
        &state,
        &claims,
        &headers,
        &method,
        &uri,
        &body,
        None,
        "password_change",
        &request_id.0,
    )
    .await?;
    let new_password_hash =
        hash_password(&request.new_password).map_err(|_| ApiError::internal(&request_id.0))?;
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "risk_challenge_id".to_owned(),
        Value::String(step_up.challenge_id.clone()),
    );
    state
        .repository
        .apply_step_up_action(
            &step_up,
            &StepUpAction::ChangePassword {
                expected_password_hash: account.password_hash,
                new_password_hash,
                audit_entry: AuditEntry {
                    audit_id: random_uuid_v4(),
                    actor_type: "account".to_owned(),
                    actor_account_id: Some(claims.account_id),
                    actor_device_id: None,
                    actor_role: None,
                    actor_service: None,
                    target_device_id: Some(step_up.device_id.clone()),
                    session_id: None,
                    action: "password_changed".to_owned(),
                    result: "success".to_owned(),
                    reason: None,
                    metadata,
                    request_id: request_id.0.clone(),
                    created_at_epoch_millis: step_up.now_epoch_millis,
                },
            },
        )
        .await
        .map_err(|error| match error {
            StoreError::Conflict => ApiError::conflict(
                "password_change_conflict",
                "password authority changed or the step-up token was already consumed",
                &request_id.0,
            ),
            StoreError::Unavailable => ApiError::internal(&request_id.0),
        })?;
    super::mfa::consume_ephemeral_step_up(&state, &step_up).await;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn issue_tokens(
    state: &AppState,
    account_id: &str,
    mfa_verified: bool,
    request_id: &str,
) -> ApiResult<TokenResponse> {
    let now = now_epoch_millis();
    let (response, account_session) =
        build_token_bundle(state, account_id, mfa_verified, now, request_id)?;
    let account_session_id = account_session.account_session_id.clone();
    state
        .repository
        .transact(&mut |database| {
            if database.account_sessions.contains_key(&account_session_id) {
                return Err(StoreError::Conflict);
            }
            database
                .account_sessions
                .insert(account_session_id.clone(), account_session.clone());
            Ok(())
        })
        .await
        .map_err(|_| ApiError::internal(request_id))?;
    Ok(response)
}

fn build_token_bundle(
    state: &AppState,
    account_id: &str,
    mfa_verified: bool,
    now: u64,
    request_id: &str,
) -> ApiResult<(TokenResponse, AccountSession)> {
    let account_session_id = random_uuid_v4();
    let refresh_token = random_token(48);
    let access_token_expires_at_epoch_millis = now + state.config.access_ttl_seconds * 1_000;
    let refresh_token_expires_at_epoch_millis = now + state.config.refresh_ttl_seconds * 1_000;
    let claims = AccessClaims {
        account_id: account_id.to_owned(),
        account_session_id: account_session_id.clone(),
        issued_at_epoch_millis: now,
        expires_at_epoch_millis: access_token_expires_at_epoch_millis,
        mfa_verified,
        token_type: "access".to_owned(),
    };
    let access_token = sign_access_token(&claims, &state.config.token_secret)
        .map_err(|_| ApiError::internal(request_id))?;
    let account_session = AccountSession {
        account_session_id: account_session_id.clone(),
        account_id: account_id.to_owned(),
        refresh_token_hash: sha256(refresh_token.as_bytes()),
        mfa_verified,
        expires_at_epoch_millis: refresh_token_expires_at_epoch_millis,
        revoked_at_epoch_millis: None,
        revoked_reason: None,
    };
    Ok((
        TokenResponse {
            account_id: account_id.to_owned(),
            access_token,
            refresh_token,
            access_token_expires_at_epoch_millis,
            refresh_token_expires_at_epoch_millis,
        },
        account_session,
    ))
}

fn normalize_email(value: &str, request_id: &str) -> ApiResult<String> {
    let email = value.trim().to_ascii_lowercase();
    if email.len() > 254 || !email.contains('@') || email.starts_with('@') || email.ends_with('@') {
        return Err(ApiError::bad_request(
            "invalid_email",
            "email is invalid",
            request_id,
        ));
    }
    Ok(email)
}

fn validate_password(value: &str, request_id: &str) -> ApiResult<()> {
    if value.len() < 12 || value.len() > 256 {
        return Err(ApiError::bad_request(
            "weak_password",
            "password must contain 12 to 256 bytes",
            request_id,
        ));
    }
    Ok(())
}

fn validate_protocol_version(value: u16, request_id: &str) -> ApiResult<()> {
    if value != remote_protocol::PROTOCOL_VERSION {
        return Err(ApiError::new(
            StatusCode::UPGRADE_REQUIRED,
            "unsupported_version",
            "protocol_version is unsupported",
            request_id,
        ));
    }
    Ok(())
}

fn validate_device_id(value: &str, request_id: &str) -> ApiResult<()> {
    if value.is_empty() || value.len() > 128 || !value.is_ascii() {
        return Err(ApiError::bad_request(
            "invalid_device_id",
            "device_id must contain 1 to 128 ASCII characters",
            request_id,
        ));
    }
    Ok(())
}

const fn login_device_state_name(state: LoginDeviceState) -> &'static str {
    match state {
        LoginDeviceState::Registered => "registered",
        LoginDeviceState::PendingEnrollment => "pending_enrollment",
    }
}

fn auth_challenge_from_authority(authority: &LoginChallengeAuthority) -> AuthChallenge {
    AuthChallenge {
        challenge_id: authority.challenge.risk_challenge_id.clone(),
        account_id: authority.challenge.account_id.clone(),
        device_id: authority.challenge.device_id.clone(),
        purpose: ChallengePurpose::LoginMfa,
        operation_binding_hash: Some(hex_encode(&authority.challenge.operation_binding_hash)),
        login: Some(authority.context.clone()),
        attempts_remaining: authority.challenge.attempts_remaining,
        expires_at_epoch_millis: authority.challenge.expires_at_epoch_millis,
        verified_at_epoch_millis: authority.challenge.verified_at_epoch_millis,
        consumed_at_epoch_millis: authority.challenge.consumed_at_epoch_millis,
    }
}

fn sanitized_user_agent(headers: &HeaderMap) -> String {
    headers
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .chars()
        .take(512)
        .collect()
}

fn signed_device_id<'a>(headers: &'a HeaderMap, request_id: &str) -> ApiResult<&'a str> {
    required_signature_header(headers, "x-rctl-device-id", request_id)
}

fn required_signature_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
    request_id: &str,
) -> ApiResult<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ApiError::bad_request(
                "missing_device_signature_header",
                format!("missing required header {name}"),
                request_id,
            )
        })
}

async fn verify_login_device_signature(
    state: &AppState,
    account_id: &str,
    context: &LoginChallengeContext,
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    request_id: &str,
) -> ApiResult<()> {
    let device_id = signed_device_id(headers, request_id)?;
    if device_id != context.device_id {
        return Err(ApiError::forbidden(
            "device_signature_mismatch",
            "signed device_id does not match the login challenge",
            request_id,
        ));
    }
    let timestamp = required_signature_header(headers, "x-rctl-timestamp", request_id)?
        .parse::<u64>()
        .map_err(|_| {
            ApiError::bad_request(
                "invalid_device_signature",
                "invalid signature timestamp",
                request_id,
            )
        })?;
    let now = now_epoch_millis();
    if now.abs_diff(timestamp) > 30_000 {
        return Err(ApiError::forbidden(
            "device_signature_expired",
            "device signature timestamp is outside the 30 second window",
            request_id,
        ));
    }
    let nonce = required_signature_header(headers, "x-rctl-api-nonce", request_id)?;
    let signature = required_signature_header(headers, "x-rctl-device-signature", request_id)?;
    let target = uri
        .path_and_query()
        .map_or(uri.path(), |value| value.as_str());
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    verify_device_signature(
        &context.device_public_key,
        "POST",
        target,
        body,
        content_type,
        request_id,
        device_id,
        account_id,
        timestamp,
        nonce,
        signature,
    )
    .map_err(|_| {
        ApiError::forbidden(
            "invalid_device_signature",
            "proof of device private key failed",
            request_id,
        )
    })?;
    let nonce_key = format!("login-finish:{account_id}:{device_id}:{nonce}");
    if !state
        .ephemeral
        .record_nonce(&nonce_key, now, 60_000)
        .await
        .map_err(|_| ApiError::internal(request_id))?
    {
        return Err(ApiError::conflict(
            "device_nonce_replayed",
            "device request nonce has already been used",
            request_id,
        ));
    }
    Ok(())
}

async fn reject_login_attempt(
    state: &AppState,
    challenge: &AuthChallenge,
    challenge_binding_hash: &[u8; 32],
    now: u64,
    request_id: &str,
) -> ApiResult<()> {
    let audit_entry = auth_failure_audit_entry(
        request_id,
        &challenge.account_id,
        challenge.device_id.as_deref(),
        "mfa_challenge_failed",
        Some("verification_failed"),
        now,
    );
    state
        .repository
        .reject_login_challenge(
            &challenge.challenge_id,
            challenge_binding_hash,
            now,
            &audit_entry,
        )
        .await
        .map_err(|_| ApiError::internal(request_id))?;
    Ok(())
}

fn login_verification_error(request_id: &str) -> ApiError {
    ApiError::forbidden(
        "login_verification_failed",
        "login challenge is invalid, expired, consumed, or the proof is incorrect",
        request_id,
    )
}

fn trust_decision(factor: Option<&str>) -> (Option<&'static str>, Option<&'static str>) {
    match factor {
        Some("totp") => (Some("device_signature_and_mfa"), Some("standard")),
        Some("recovery_code") => (
            Some("device_signature_and_recovery_code"),
            Some("high_risk_step_up_required"),
        ),
        _ => (None, None),
    }
}

fn auth_audit_entry(
    request_id: &str,
    account_id: &str,
    device_id: Option<&str>,
    action: &str,
    reason: Option<&str>,
    now: u64,
) -> AuditEntry {
    AuditEntry {
        audit_id: random_uuid_v4(),
        actor_type: "account".to_owned(),
        actor_account_id: Some(account_id.to_owned()),
        actor_device_id: device_id.map(ToOwned::to_owned),
        actor_role: None,
        actor_service: None,
        target_device_id: device_id.map(ToOwned::to_owned),
        session_id: None,
        action: action.to_owned(),
        result: "success".to_owned(),
        reason: reason.map(ToOwned::to_owned),
        metadata: BTreeMap::new(),
        request_id: request_id.to_owned(),
        created_at_epoch_millis: now,
    }
}

fn auth_failure_audit_entry(
    request_id: &str,
    account_id: &str,
    device_id: Option<&str>,
    action: &str,
    reason: Option<&str>,
    now: u64,
) -> AuditEntry {
    let mut entry = auth_audit_entry(request_id, account_id, device_id, action, reason, now);
    entry.result = "failure".to_owned();
    entry
}

fn login_failure_key(account: Option<&Account>, normalized_email: &str) -> String {
    let principal = account.map_or(normalized_email, |account| account.account_id.as_str());
    let principal_kind = if account.is_some() {
        "account"
    } else {
        "email"
    };
    sha256_hex(format!("rctl-login-limit-v1\0{principal_kind}\0{principal}").as_bytes())
}

async fn record_login_failure(
    state: &AppState,
    login_failure_key: &str,
    account: Option<&Account>,
    request_id: &str,
) -> ApiResult<()> {
    let now = now_epoch_millis();
    let failure = state
        .ephemeral
        .record_login_failure(
            login_failure_key,
            now,
            MAX_LOGIN_FAILURES,
            LOCK_MILLIS,
            LOGIN_FAILURE_STATE_TTL_MILLIS,
        )
        .await
        .map_err(|_| ApiError::internal(request_id))?;
    if failure.newly_locked && account.is_some() {
        audit(
            state,
            request_id,
            "anonymous",
            None,
            None,
            None,
            None,
            None,
            "account_locked",
            "success",
            Some("too_many_login_failures"),
            BTreeMap::new(),
        )
        .await?;
    }
    audit(
        state,
        request_id,
        "anonymous",
        None,
        None,
        None,
        None,
        None,
        "login_failed",
        "failure",
        Some("invalid_credentials"),
        BTreeMap::new(),
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Method, Request};
    use ed25519_dalek::SigningKey;
    use http_body_util::BodyExt;
    use serde_json::{json, Value};
    use tower::ServiceExt;

    use super::*;
    use crate::security::{
        canonical_request_body_hash, encode_public_key, sign_device_request_for_test,
    };
    use crate::{
        build_router, AppConfig, AppState, Architecture, Device, DeviceCapabilities,
        DeviceLifecycleStatus, MemoryRepository, Platform, SignalNotifier,
    };

    #[tokio::test]
    async fn registration_uses_the_frozen_token_lifetimes() {
        let (_, body) = register_account(build_router(AppState::for_test())).await;

        let access_expiry = body["access_token_expires_at_epoch_millis"]
            .as_u64()
            .expect("access expiry");
        let refresh_expiry = body["refresh_token_expires_at_epoch_millis"]
            .as_u64()
            .expect("refresh expiry");
        assert_eq!(
            refresh_expiry - access_expiry,
            (30 * 24 * 60 * 60 - 15 * 60) * 1_000
        );
        assert!(body["access_token"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
        assert!(body["refresh_token"]
            .as_str()
            .is_some_and(|value| !value.is_empty()));
    }

    #[tokio::test]
    async fn refresh_token_is_consumed_once_even_when_requests_race() {
        let router = build_router(AppState::for_test());
        let (_, registered) = register_account(router.clone()).await;
        let refresh_token = registered["refresh_token"]
            .as_str()
            .expect("refresh token")
            .to_owned();
        let payload = json!({ "refresh_token": refresh_token });

        let first = send_json(
            router.clone(),
            Method::POST,
            "/v1/auth/refresh",
            payload.clone(),
            None,
        );
        let second = send_json(router, Method::POST, "/v1/auth/refresh", payload, None);
        let (first, second) = tokio::join!(first, second);
        let statuses = [first.0, second.0];

        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status == StatusCode::OK)
                .count(),
            1
        );
        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status == StatusCode::UNAUTHORIZED)
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn expired_refresh_token_is_rejected() {
        let state = AppState::for_test();
        let router = build_router(state.clone());
        let (_, registered) = register_account(router.clone()).await;
        let refresh_token = registered["refresh_token"]
            .as_str()
            .expect("refresh token")
            .to_owned();
        state
            .repository
            .transact(&mut |database| {
                for session in database.account_sessions.values_mut() {
                    session.expires_at_epoch_millis = now_epoch_millis().saturating_sub(1);
                }
                Ok(())
            })
            .await
            .expect("expire refresh session");

        let (status, body) = send_json(
            router,
            Method::POST,
            "/v1/auth/refresh",
            json!({ "refresh_token": refresh_token }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["code"], "unauthorized");
    }

    #[tokio::test]
    async fn logout_revokes_the_access_and_refresh_token_session() {
        let router = build_router(AppState::for_test());
        let (_, registered) = register_account(router.clone()).await;
        let access_token = registered["access_token"]
            .as_str()
            .expect("access token")
            .to_owned();
        let refresh_token = registered["refresh_token"]
            .as_str()
            .expect("refresh token")
            .to_owned();

        let (logout_status, _) = send_json(
            router.clone(),
            Method::POST,
            "/v1/auth/logout",
            Value::Null,
            Some(&access_token),
        )
        .await;
        assert_eq!(logout_status, StatusCode::NO_CONTENT);

        let (access_status, _) = send_json(
            router.clone(),
            Method::GET,
            "/v1/devices",
            Value::Null,
            Some(&access_token),
        )
        .await;
        assert_eq!(access_status, StatusCode::UNAUTHORIZED);

        let (refresh_status, _) = send_json(
            router,
            Method::POST,
            "/v1/auth/refresh",
            json!({ "refresh_token": refresh_token }),
            None,
        )
        .await;
        assert_eq!(refresh_status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn password_change_without_mfa_uses_password_step_up_and_revokes_account_authority() {
        let state = AppState::for_test();
        let router = build_router(state.clone());
        let (_, registered) = register_account(router.clone()).await;
        let account_id = registered["account_id"]
            .as_str()
            .expect("account id")
            .to_owned();
        let access_token = registered["access_token"]
            .as_str()
            .expect("access token")
            .to_owned();
        let refresh_token = registered["refresh_token"]
            .as_str()
            .expect("refresh token")
            .to_owned();
        let device_id = "password-change-device";
        let now = now_epoch_millis();
        state
            .repository
            .transact(&mut |database| {
                database.devices.insert(
                    device_id.to_owned(),
                    Device {
                        device_id: device_id.to_owned(),
                        account_id: account_id.clone(),
                        display_name: "Password Change Device".into(),
                        platform: Platform::Windows,
                        os_version: "11".into(),
                        arch: Architecture::X86_64,
                        capabilities: DeviceCapabilities {
                            controller: true,
                            controlled: true,
                            file_transfer: false,
                            unattended: false,
                        },
                        public_key_id: "password-change-key".into(),
                        public_key: [31; 32],
                        public_key_version: 1,
                        public_key_revoked_at_epoch_millis: None,
                        status: DeviceLifecycleStatus::Offline,
                        last_seen_epoch_millis: None,
                        created_at_epoch_millis: now,
                        updated_at_epoch_millis: now,
                    },
                );
                database.account_sessions.insert(
                    "other-session".into(),
                    AccountSession {
                        account_session_id: "other-session".into(),
                        account_id: account_id.clone(),
                        refresh_token_hash: sha256(b"other-refresh"),
                        mfa_verified: false,
                        expires_at_epoch_millis: now + 300_000,
                        revoked_at_epoch_millis: None,
                        revoked_reason: None,
                    },
                );
                database.trusted_controller_devices.insert(
                    "password-change-trust".into(),
                    TrustedControllerDevice {
                        trusted_device_id: "password-change-trust".into(),
                        account_id: account_id.clone(),
                        controller_device_id: device_id.into(),
                        device_fingerprint_hash: sha256(&[31; 32]),
                        trust_level: "standard".into(),
                        status: TrustedDeviceStatus::Active,
                        trust_proof_type: "device_signature_and_mfa".into(),
                        created_at_epoch_millis: now,
                        last_used_at_epoch_millis: None,
                        expires_at_epoch_millis: now + 300_000,
                        revoked_at_epoch_millis: None,
                    },
                );
                Ok(())
            })
            .await
            .expect("seed password change authority");

        let request_id = "password-change-final-request";
        let password_body = serde_json::to_vec(&json!({
            "current_password": "correct horse battery staple",
            "new_password": "new correct horse battery staple"
        }))
        .expect("password body");
        let body_hash = canonical_request_body_hash(&password_body, Some("application/json"))
            .expect("canonical password body hash");
        let (challenge_status, challenge) = send_json(
            router.clone(),
            Method::POST,
            "/v1/auth/risk-challenge",
            json!({
                "purpose": "password_change",
                "device_id": device_id,
                "method": "PATCH",
                "path": "/v1/me/password",
                "body_hash": hex_encode(&body_hash),
                "request_id": request_id
            }),
            Some(&access_token),
        )
        .await;
        assert_eq!(challenge_status, StatusCode::CREATED);
        assert_eq!(challenge["required_methods"], json!(["password"]));
        let challenge_id = challenge["risk_challenge_id"]
            .as_str()
            .expect("challenge id")
            .to_owned();
        let router = build_router(AppState::new(
            state.repository.clone(),
            AppConfig::for_test(),
            SignalNotifier::disabled(),
        ));
        let verify_path = format!("/v1/auth/risk-challenge/{challenge_id}/verify");
        let (verify_status, verified) = send_json(
            router.clone(),
            Method::POST,
            &verify_path,
            json!({
                "factor": "password",
                "code": "correct horse battery staple"
            }),
            Some(&access_token),
        )
        .await;
        assert_eq!(verify_status, StatusCode::OK);
        let step_up_token = verified["step_up_token"].as_str().expect("step-up token");

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PATCH)
                    .uri("/v1/me/password")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {access_token}"))
                    .header("x-rctl-protocol-version", remote_protocol::PROTOCOL_VERSION)
                    .header("x-request-id", request_id)
                    .header("x-rctl-risk-challenge-id", &challenge_id)
                    .header("x-rctl-step-up-token", step_up_token)
                    .body(Body::from(password_body))
                    .expect("password change request"),
            )
            .await
            .expect("password change response");
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(response
            .into_body()
            .collect()
            .await
            .expect("empty password response")
            .to_bytes()
            .is_empty());

        let account = state
            .repository
            .load_account_by_id(&account_id)
            .await
            .expect("load changed account")
            .expect("changed account");
        assert!(!verify_password(
            &account.password_hash,
            "correct horse battery staple"
        ));
        assert!(verify_password(
            &account.password_hash,
            "new correct horse battery staple"
        ));
        state
            .repository
            .read(&mut |database| {
                assert!(database
                    .account_sessions
                    .values()
                    .filter(|session| session.account_id == account_id)
                    .all(|session| {
                        session.revoked_at_epoch_millis.is_some()
                            && session.revoked_reason.as_deref() == Some("password_changed")
                    }));
                let trusted = &database.trusted_controller_devices["password-change-trust"];
                assert_eq!(trusted.status, TrustedDeviceStatus::Revoked);
                assert!(trusted.revoked_at_epoch_millis.is_some());
                assert_eq!(
                    database.risk_challenges[&challenge_id].status,
                    RiskChallengeStatus::Consumed
                );
                assert_eq!(
                    database
                        .audit_logs
                        .iter()
                        .filter(|entry| entry.action == "password_changed")
                        .count(),
                    1
                );
            })
            .await;

        let (access_status, _) = send_json(
            router.clone(),
            Method::GET,
            "/v1/devices",
            Value::Null,
            Some(&access_token),
        )
        .await;
        assert_eq!(access_status, StatusCode::UNAUTHORIZED);
        let (refresh_status, _) = send_json(
            router,
            Method::POST,
            "/v1/auth/refresh",
            json!({ "refresh_token": refresh_token }),
            None,
        )
        .await;
        assert_eq!(refresh_status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn password_change_rejects_invalid_password_inputs_before_mutation() {
        let state = AppState::for_test();
        let router = build_router(state.clone());
        let (_, registered) = register_account(router.clone()).await;
        let account_id = registered["account_id"].as_str().expect("account id");
        let access_token = registered["access_token"].as_str().expect("access token");

        let (weak_status, weak_body) = send_json(
            router.clone(),
            Method::PATCH,
            "/v1/me/password",
            json!({
                "current_password": "correct horse battery staple",
                "new_password": "short"
            }),
            Some(access_token),
        )
        .await;
        assert_eq!(weak_status, StatusCode::BAD_REQUEST);
        assert_eq!(weak_body["code"], "weak_password");

        let (same_status, same_body) = send_json(
            router.clone(),
            Method::PATCH,
            "/v1/me/password",
            json!({
                "current_password": "correct horse battery staple",
                "new_password": "correct horse battery staple"
            }),
            Some(access_token),
        )
        .await;
        assert_eq!(same_status, StatusCode::BAD_REQUEST);
        assert_eq!(same_body["code"], "password_unchanged");

        let (wrong_status, wrong_body) = send_json(
            router,
            Method::PATCH,
            "/v1/me/password",
            json!({
                "current_password": "wrong current password",
                "new_password": "another correct horse battery staple"
            }),
            Some(access_token),
        )
        .await;
        assert_eq!(wrong_status, StatusCode::FORBIDDEN);
        assert_eq!(wrong_body["code"], "invalid_current_password");

        let account = state
            .repository
            .load_account_by_id(account_id)
            .await
            .expect("load account")
            .expect("account");
        assert!(verify_password(
            &account.password_hash,
            "correct horse battery staple"
        ));
    }

    #[tokio::test]
    async fn login_succeeds_and_repeated_failures_lock_the_account() {
        let router = build_router(AppState::for_test());
        let email = format!("{}@example.com", random_uuid_v4());
        let password = "correct horse battery staple";
        let device_id = "login-device";
        let key = SigningKey::from_bytes(&[41_u8; 32]);
        let (register_status, _) = send_json(
            router.clone(),
            Method::POST,
            "/v1/auth/register",
            json!({
                "email": email,
                "password": password,
                "display_name": "Login Test"
            }),
            None,
        )
        .await;
        assert_eq!(register_status, StatusCode::CREATED);

        let (login_status, login_body) = send_json(
            router.clone(),
            Method::POST,
            "/v1/auth/login",
            login_request_json(&email, password, device_id, &key, 7),
            None,
        )
        .await;
        assert_eq!(login_status, StatusCode::ACCEPTED);
        assert_eq!(login_body["code"], "login_challenge_required");
        assert!(login_body.get("access_token").is_none());
        let finish_body = serde_json::to_vec(&json!({
            "login_challenge_id": login_body["login_challenge_id"],
            "login_request_binding_hash": login_body["login_request_binding_hash"],
            "login_challenge_binding_hash": login_body["login_challenge_binding_hash"],
            "client_nonce": encode_base64url(&[7_u8; 32]),
            "server_nonce": login_body["server_nonce"],
            "protocol_version": remote_protocol::PROTOCOL_VERSION
        }))
        .expect("finish body");
        let finish_request_id = "login-finish-request";
        let finish_timestamp = now_epoch_millis();
        let finish_signature = sign_device_request_for_test(
            &key,
            "POST",
            "/v1/auth/login/finish",
            &finish_body,
            finish_request_id,
            device_id,
            login_body["account_id"].as_str().expect("account id"),
            finish_timestamp,
            "login-finish-nonce",
        );
        let finish_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/login/finish")
                    .header("content-type", "application/json")
                    .header("x-rctl-protocol-version", remote_protocol::PROTOCOL_VERSION)
                    .header("x-request-id", finish_request_id)
                    .header("x-rctl-device-id", device_id)
                    .header("x-rctl-timestamp", finish_timestamp)
                    .header("x-rctl-api-nonce", "login-finish-nonce")
                    .header("x-rctl-device-signature", finish_signature)
                    .body(Body::from(finish_body))
                    .expect("finish request"),
            )
            .await
            .expect("finish response");
        assert_eq!(finish_response.status(), StatusCode::OK);
        let finish_body: Value = serde_json::from_slice(
            &finish_response
                .into_body()
                .collect()
                .await
                .expect("finish response body")
                .to_bytes(),
        )
        .expect("finish response JSON");
        assert!(finish_body["access_token"].is_string());
        assert!(finish_body["device_enrollment_grant"].is_string());

        for _ in 0..MAX_LOGIN_FAILURES {
            let (status, body) = send_json(
                router.clone(),
                Method::POST,
                "/v1/auth/login",
                login_request_json(&email, "definitely the wrong password", device_id, &key, 8),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(body["code"], "invalid_credentials");
        }

        let (locked_status, locked_body) = send_json(
            router,
            Method::POST,
            "/v1/auth/login",
            login_request_json(&email, password, device_id, &key, 9),
            None,
        )
        .await;
        assert_eq!(locked_status, StatusCode::UNAUTHORIZED);
        assert_eq!(locked_body["code"], "invalid_credentials");
    }

    #[tokio::test]
    async fn login_finish_recovers_pending_device_context_after_ephemeral_state_loss() {
        let repository = Arc::new(MemoryRepository::default());
        let initial_state = AppState::new(
            repository.clone(),
            AppConfig::for_test(),
            SignalNotifier::disabled(),
        );
        let initial_router = build_router(initial_state);
        let email = format!("{}@example.com", random_uuid_v4());
        let password = "correct horse battery staple";
        let device_id = "recovered-login-device";
        let key = SigningKey::from_bytes(&[45_u8; 32]);
        let (register_status, _) = send_json(
            initial_router.clone(),
            Method::POST,
            "/v1/auth/register",
            json!({
                "email": email,
                "password": password,
                "display_name": "Recovered Login Test"
            }),
            None,
        )
        .await;
        assert_eq!(register_status, StatusCode::CREATED);
        let (login_status, login_body) = send_json(
            initial_router,
            Method::POST,
            "/v1/auth/login",
            login_request_json(&email, password, device_id, &key, 12),
            None,
        )
        .await;
        assert_eq!(login_status, StatusCode::ACCEPTED);

        let recovered_router = build_router(AppState::new(
            repository,
            AppConfig::for_test(),
            SignalNotifier::disabled(),
        ));
        let finish_body = serde_json::to_vec(&json!({
            "login_challenge_id": login_body["login_challenge_id"],
            "login_request_binding_hash": login_body["login_request_binding_hash"],
            "login_challenge_binding_hash": login_body["login_challenge_binding_hash"],
            "client_nonce": encode_base64url(&[12_u8; 32]),
            "server_nonce": login_body["server_nonce"],
            "protocol_version": remote_protocol::PROTOCOL_VERSION
        }))
        .expect("finish body");
        let request_id = "recovered-login-finish";
        let timestamp = now_epoch_millis();
        let signature = sign_device_request_for_test(
            &key,
            "POST",
            "/v1/auth/login/finish",
            &finish_body,
            request_id,
            device_id,
            login_body["account_id"].as_str().expect("account id"),
            timestamp,
            "recovered-login-nonce",
        );
        let response = recovered_router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/login/finish")
                    .header("content-type", "application/json")
                    .header("x-rctl-protocol-version", remote_protocol::PROTOCOL_VERSION)
                    .header("x-request-id", request_id)
                    .header("x-rctl-device-id", device_id)
                    .header("x-rctl-timestamp", timestamp)
                    .header("x-rctl-api-nonce", "recovered-login-nonce")
                    .header("x-rctl-device-signature", signature)
                    .body(Body::from(finish_body))
                    .expect("finish request"),
            )
            .await
            .expect("finish response");
        assert_eq!(response.status(), StatusCode::OK);
        let body: Value = serde_json::from_slice(
            &response
                .into_body()
                .collect()
                .await
                .expect("finish body")
                .to_bytes(),
        )
        .expect("finish JSON");
        assert!(body["access_token"].is_string());
        assert!(body["device_enrollment_grant"].is_string());
    }

    #[tokio::test]
    async fn login_finish_rejects_a_registered_key_revoked_after_challenge_issue() {
        let state = AppState::for_test();
        let router = build_router(state.clone());
        let email = format!("{}@example.com", random_uuid_v4());
        let password = "correct horse battery staple";
        let device_id = "registered-login-device";
        let public_key_id = "registered-login-key";
        let key = SigningKey::from_bytes(&[47_u8; 32]);
        let (register_status, registered) = send_json(
            router.clone(),
            Method::POST,
            "/v1/auth/register",
            json!({
                "email": email,
                "password": password,
                "display_name": "Registered Login Test"
            }),
            None,
        )
        .await;
        assert_eq!(register_status, StatusCode::CREATED);
        let account_id = registered["account_id"].as_str().expect("account id");
        let now = now_epoch_millis();
        state
            .repository
            .transact(&mut |database| {
                database.devices.insert(
                    device_id.to_owned(),
                    Device {
                        device_id: device_id.to_owned(),
                        account_id: account_id.to_owned(),
                        display_name: "Registered Device".into(),
                        platform: Platform::Windows,
                        os_version: "11".into(),
                        arch: Architecture::X86_64,
                        capabilities: DeviceCapabilities {
                            controller: true,
                            controlled: true,
                            file_transfer: false,
                            unattended: false,
                        },
                        public_key_id: public_key_id.to_owned(),
                        public_key: key.verifying_key().to_bytes(),
                        public_key_version: 1,
                        public_key_revoked_at_epoch_millis: None,
                        status: DeviceLifecycleStatus::Offline,
                        last_seen_epoch_millis: None,
                        created_at_epoch_millis: now,
                        updated_at_epoch_millis: now,
                    },
                );
                Ok(())
            })
            .await
            .expect("seed registered device");
        let mut login_request = login_request_json(&email, password, device_id, &key, 14);
        login_request["public_key_id"] = Value::String(public_key_id.to_owned());
        login_request["public_key_version"] = Value::from(1);
        let (login_status, login_body) = send_json(
            router.clone(),
            Method::POST,
            "/v1/auth/login",
            login_request,
            None,
        )
        .await;
        assert_eq!(login_status, StatusCode::ACCEPTED);
        state
            .repository
            .transact(&mut |database| {
                let device = database
                    .devices
                    .get_mut(device_id)
                    .ok_or(StoreError::Unavailable)?;
                device.public_key_revoked_at_epoch_millis = Some(now_epoch_millis());
                Ok(())
            })
            .await
            .expect("revoke challenged key");

        let finish_body = serde_json::to_vec(&json!({
            "login_challenge_id": login_body["login_challenge_id"],
            "login_request_binding_hash": login_body["login_request_binding_hash"],
            "login_challenge_binding_hash": login_body["login_challenge_binding_hash"],
            "client_nonce": encode_base64url(&[14_u8; 32]),
            "server_nonce": login_body["server_nonce"],
            "protocol_version": remote_protocol::PROTOCOL_VERSION
        }))
        .expect("finish body");
        let request_id = "revoked-key-login-finish";
        let timestamp = now_epoch_millis();
        let signature = sign_device_request_for_test(
            &key,
            "POST",
            "/v1/auth/login/finish",
            &finish_body,
            request_id,
            device_id,
            account_id,
            timestamp,
            "revoked-key-login-nonce",
        );
        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/login/finish")
                    .header("content-type", "application/json")
                    .header("x-rctl-protocol-version", remote_protocol::PROTOCOL_VERSION)
                    .header("x-request-id", request_id)
                    .header("x-rctl-device-id", device_id)
                    .header("x-rctl-timestamp", timestamp)
                    .header("x-rctl-api-nonce", "revoked-key-login-nonce")
                    .header("x-rctl-device-signature", signature)
                    .body(Body::from(finish_body))
                    .expect("finish request"),
            )
            .await
            .expect("finish response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body: Value = serde_json::from_slice(
            &response
                .into_body()
                .collect()
                .await
                .expect("finish body")
                .to_bytes(),
        )
        .expect("finish JSON");
        assert_eq!(body["code"], "login_verification_failed");
        assert!(body.get("access_token").is_none());
    }

    #[tokio::test]
    async fn unknown_account_failures_use_an_opaque_rate_limit_bucket() {
        let state = AppState::for_test();
        let router = build_router(state.clone());
        let email = format!("missing-{}@example.com", random_uuid_v4());
        let key = SigningKey::from_bytes(&[43_u8; 32]);

        for _ in 0..MAX_LOGIN_FAILURES {
            let (status, body) = send_json(
                router.clone(),
                Method::POST,
                "/v1/auth/login",
                login_request_json(
                    &email,
                    "definitely the wrong password",
                    "missing-device",
                    &key,
                    11,
                ),
                None,
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
            assert_eq!(body["code"], "invalid_credentials");
        }

        let key = login_failure_key(None, &email);
        assert!(!key.contains(&email));
        assert_eq!(key.len(), 64);
        assert!(state
            .ephemeral
            .login_failure_state(&key, now_epoch_millis())
            .await
            .expect("login failure state")
            .is_locked_at(now_epoch_millis()));
    }

    async fn register_account(router: axum::Router) -> (StatusCode, Value) {
        send_json(
            router,
            Method::POST,
            "/v1/auth/register",
            json!({
                "email": format!("{}@example.com", random_uuid_v4()),
                "password": "correct horse battery staple",
                "display_name": "Test Account"
            }),
            None,
        )
        .await
    }

    fn login_request_json(
        email: &str,
        password: &str,
        device_id: &str,
        key: &SigningKey,
        nonce_byte: u8,
    ) -> Value {
        json!({
            "email": email,
            "password": password,
            "device_id": device_id,
            "device_public_key": encode_public_key(&key.verifying_key().to_bytes()),
            "public_key_id": Value::Null,
            "public_key_version": 0,
            "client_nonce": encode_base64url(&[nonce_byte; 32]),
            "protocol_version": remote_protocol::PROTOCOL_VERSION
        })
    }

    async fn send_json(
        router: axum::Router,
        method: Method,
        uri: &str,
        body: Value,
        bearer: Option<&str>,
    ) -> (StatusCode, Value) {
        let body = if body.is_null() {
            Body::empty()
        } else {
            Body::from(serde_json::to_vec(&body).expect("serialize request"))
        };
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .header("x-rctl-protocol-version", remote_protocol::PROTOCOL_VERSION)
            .header("content-type", "application/json");
        if let Some(token) = bearer {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let response = router
            .oneshot(request.body(body).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("JSON response")
        };
        (status, value)
    }
}
