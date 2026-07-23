use std::collections::BTreeMap;

use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::Json;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use remote_protocol::canonical_request_target;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::Zeroize;

#[cfg(test)]
use crate::ephemeral::{ChallengeAttemptStart, ExpectedChallengeKind};
use crate::ephemeral::{PendingTotpEnrollment, StepUpConsumption};
use crate::error::{ApiError, ApiResult};
use crate::model::{
    AuditEntry, AuthChallenge, ChallengePurpose, MfaFactor, RecoveryCode, RecoveryCodeDelivery,
    RiskChallenge, RiskChallengeStatus, TrustedDeviceStatus,
};
use crate::security::{
    bearer, canonical_fields, canonical_request_body_hash, decode_base64url_32, decode_sha256_hex,
    encode_base64url, generate_totp_secret, hex_encode, now_epoch_millis, operation_binding_hash,
    random_bytes_32, random_token, random_uuid_v4, sha256, sign_step_up_token, verify_access_token,
    verify_step_up_token, verify_totp, AccessClaims, StepUpClaims,
};
use crate::store::{
    totp_enrollment_finish_binding_hash, RiskChallengeCreationOutcome, RiskChallengeVerification,
    RiskChallengeVerificationOutcome, StepUpAction, StepUpExpectation, StoreError,
    TotpEnrollmentCompletion, TotpEnrollmentReplayLookup, TotpEnrollmentReplayOutcome,
};
use crate::{AppState, RequestId};

use super::{authenticate, parse_json};

const ALLOWED_STEP_UP_PURPOSES: &[&str] = &[
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
const RECOVERY_DELIVERY_TTL_MILLIS: u64 = 24 * 60 * 60 * 1_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotpStartRequest {
    recovery_delivery_public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotpFinishRequest {
    factor_id: String,
    code: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskChallengeRequest {
    device_id: String,
    purpose: String,
    method: String,
    path: String,
    body_hash: String,
    request_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyRiskRequest {
    factor: String,
    code: String,
}

#[derive(Debug, Serialize)]
struct TrustedDeviceView {
    trusted_device_id: String,
    controller_device_id: String,
    trust_level: String,
    status: &'static str,
    created_at_epoch_millis: u64,
    last_used_at_epoch_millis: Option<u64>,
    expires_at_epoch_millis: u64,
}

pub async fn mfa_status(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let claims = authenticate(&state, &headers, &request_id.0).await?;
    let status = state
        .repository
        .load_mfa_status(&claims.account_id, now_epoch_millis())
        .await
        .map_err(|_| ApiError::internal(&request_id.0))?;
    let factors = status
        .factors
        .iter()
        .map(|factor| {
            json!({
                "factor_id": factor.factor_id,
                "factor_type": "totp",
                "status": "active",
                "created_at_epoch_millis": factor.created_at_epoch_millis,
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "enabled": !factors.is_empty(),
        "factors": factors,
        "recovery_codes_remaining": status.recovery_codes_remaining,
    })))
}

pub async fn totp_start(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let claims = authenticate(&state, &headers, &request_id.0).await?;
    let request: TotpStartRequest = parse_json(&body, &request_id.0)?;
    let recovery_delivery_public_key = decode_base64url_32(&request.recovery_delivery_public_key)
        .map_err(|_| {
        ApiError::bad_request(
            "invalid_recovery_delivery_key",
            "recovery_delivery_public_key must be 32 base64url X25519 bytes",
            &request_id.0,
        )
    })?;
    validate_x25519_public_key(&recovery_delivery_public_key, &request_id.0)?;
    if state
        .repository
        .account_mfa_enabled(&claims.account_id)
        .await
        .map_err(|_| ApiError::internal(&request_id.0))?
    {
        return Err(ApiError::conflict(
            "mfa_already_enabled",
            "disable the active TOTP factor before enrolling a replacement",
            &request_id.0,
        ));
    }
    let created_at_epoch_millis = now_epoch_millis();
    let enrollment = PendingTotpEnrollment {
        factor_id: random_uuid_v4(),
        account_id: claims.account_id.clone(),
        secret_base32: generate_totp_secret(),
        recovery_delivery_public_key,
        created_at_epoch_millis,
        expires_at_epoch_millis: created_at_epoch_millis
            .saturating_add(state.config.challenge_ttl_seconds.saturating_mul(1_000)),
        attempts_remaining: state.config.challenge_attempts,
    };
    let created = state
        .ephemeral
        .put_pending_totp_enrollment(&enrollment, created_at_epoch_millis)
        .await
        .map_err(|_| ApiError::internal(&request_id.0))?;
    if !created {
        return Err(ApiError::conflict(
            "mfa_enrollment_in_progress",
            "a TOTP enrollment is already in progress",
            &request_id.0,
        ));
    }
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "factor_id": enrollment.factor_id,
            "secret_base32": enrollment.secret_base32,
            "otpauth_uri": format!("otpauth://totp/Rctl:{}?secret={}&issuer=Rctl", claims.account_id, enrollment.secret_base32),
            "expires_in_seconds": state.config.challenge_ttl_seconds,
        })),
    ))
}

pub async fn totp_finish(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let request: TotpFinishRequest = parse_json(&body, &request_id.0)?;
    let now = now_epoch_millis();
    let access_token = bearer(&headers, &request_id.0)?;
    let claims = verify_access_token(&access_token, &state.config.token_secret, now)
        .map_err(|_| ApiError::unauthorized(&request_id.0))?;
    let idempotency_key = required_idempotency_key(&headers, &request_id.0)?;
    let idempotency_key_hash = sha256(idempotency_key.as_bytes());
    let replay_lookup = TotpEnrollmentReplayLookup {
        account_id: claims.account_id.clone(),
        account_session_id: claims.account_session_id.clone(),
        factor_id: request.factor_id.clone(),
        idempotency_key_hash,
        finish_request_binding_hash: None,
        client_ephemeral_public_key: None,
        access_token_expires_at_epoch_millis: claims.expires_at_epoch_millis,
        now_epoch_millis: now,
    };
    let account_session_active = state
        .repository
        .account_session_active(&claims.account_session_id, &claims.account_id, now)
        .await
        .map_err(|_| ApiError::internal(&request_id.0))?;
    if !account_session_active {
        return replay_totp_delivery(&state, &replay_lookup, &request_id.0).await;
    }
    let Some(attempt) = state
        .ephemeral
        .begin_pending_totp_enrollment_attempt(&claims.account_id, &request.factor_id, now)
        .await
        .map_err(|_| ApiError::internal(&request_id.0))?
    else {
        let still_active = state
            .repository
            .account_session_active(
                &claims.account_session_id,
                &claims.account_id,
                now_epoch_millis(),
            )
            .await
            .map_err(|_| ApiError::internal(&request_id.0))?;
        if !still_active {
            return replay_totp_delivery(&state, &replay_lookup, &request_id.0).await;
        }
        return Err(ApiError::forbidden(
            "invalid_mfa_code",
            "the TOTP code is invalid or already used",
            &request_id.0,
        ));
    };
    let Some(counter) = verify_totp(&attempt.enrollment.secret_base32, &request.code, now, None)
    else {
        state
            .ephemeral
            .finish_pending_totp_enrollment_attempt(&attempt, false, now)
            .await
            .map_err(|_| ApiError::internal(&request_id.0))?;
        return Err(ApiError::forbidden(
            "invalid_mfa_code",
            "the TOTP code is invalid or already used",
            &request_id.0,
        ));
    };

    let (mut recovery_codes, records) = generate_recovery_codes(&claims.account_id);
    let finish_request_binding_hash = totp_enrollment_finish_binding_hash(
        &claims.account_id,
        &claims.account_session_id,
        &request.factor_id,
        &idempotency_key_hash,
        &attempt.enrollment.recovery_delivery_public_key,
    );
    let bound_replay_lookup = TotpEnrollmentReplayLookup {
        finish_request_binding_hash: Some(finish_request_binding_hash),
        client_ephemeral_public_key: Some(attempt.enrollment.recovery_delivery_public_key),
        ..replay_lookup.clone()
    };
    let delivery = build_recovery_delivery(
        &claims,
        &attempt.enrollment,
        &recovery_codes,
        idempotency_key_hash,
        finish_request_binding_hash,
        now,
        &request_id.0,
    )?;
    for code in &mut recovery_codes {
        code.zeroize();
    }
    let completion = TotpEnrollmentCompletion {
        factor: MfaFactor {
            factor_id: attempt.enrollment.factor_id.clone(),
            account_id: claims.account_id.clone(),
            secret_base32: attempt.enrollment.secret_base32.clone(),
            active: true,
            last_used_counter: Some(counter),
            created_at_epoch_millis: attempt.enrollment.created_at_epoch_millis,
        },
        recovery_codes: records,
        delivery: delivery.clone(),
        audit_entry: AuditEntry {
            audit_id: random_uuid_v4(),
            actor_type: "account".to_owned(),
            actor_account_id: Some(claims.account_id.clone()),
            actor_device_id: None,
            actor_role: None,
            actor_service: None,
            target_device_id: None,
            session_id: None,
            action: "mfa_factor_enrolled".to_owned(),
            result: "success".to_owned(),
            reason: None,
            metadata: BTreeMap::new(),
            request_id: request_id.0.clone(),
            created_at_epoch_millis: now,
        },
    };
    if let Err(error) = state.repository.finish_totp_enrollment(&completion).await {
        let _ = state
            .ephemeral
            .abort_pending_totp_enrollment_attempt(&attempt)
            .await;
        return match error {
            StoreError::Conflict => {
                replay_totp_delivery(&state, &bound_replay_lookup, &request_id.0).await
            }
            StoreError::Unavailable => Err(ApiError::internal(&request_id.0)),
        };
    }
    if state
        .ephemeral
        .finish_pending_totp_enrollment_attempt(&attempt, true, now)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        let _ = state
            .ephemeral
            .remove_pending_totp_enrollment(&claims.account_id, &request.factor_id)
            .await;
    }
    Ok(Json(recovery_delivery_response(&delivery)))
}

pub async fn rotate_recovery_codes(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let claims = authenticate(&state, &headers, &request_id.0).await?;
    let step_up = validate_step_up_for_request(
        &state,
        &claims,
        &headers,
        &method,
        &uri,
        &[],
        None,
        "recovery_code_rotate",
        &request_id.0,
    )
    .await?;
    let (recovery_codes, records) = generate_recovery_codes(&claims.account_id);
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "risk_challenge_id".to_owned(),
        Value::String(step_up.challenge_id.clone()),
    );
    state
        .repository
        .apply_step_up_action(
            &step_up,
            &StepUpAction::RotateRecoveryCodes {
                records,
                audit_entry: AuditEntry {
                    audit_id: random_uuid_v4(),
                    actor_type: "account".to_owned(),
                    actor_account_id: Some(claims.account_id.clone()),
                    actor_device_id: None,
                    actor_role: None,
                    actor_service: None,
                    target_device_id: Some(step_up.device_id.clone()),
                    session_id: None,
                    action: "mfa_recovery_codes_rotated".to_owned(),
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
                "step_up_already_consumed",
                "the step-up challenge is invalid, expired, or already consumed",
                &request_id.0,
            ),
            StoreError::Unavailable => ApiError::internal(&request_id.0),
        })?;
    consume_ephemeral_step_up(&state, &step_up).await;
    Ok(Json(json!({ "recovery_codes": recovery_codes })))
}

pub async fn delete_mfa_factor(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(factor_id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    let claims = authenticate(&state, &headers, &request_id.0).await?;
    let step_up = validate_step_up_for_request(
        &state,
        &claims,
        &headers,
        &method,
        &uri,
        &[],
        None,
        "mfa_factor_change",
        &request_id.0,
    )
    .await?;
    let mut metadata = BTreeMap::new();
    metadata.insert("factor_id".to_owned(), Value::String(factor_id.clone()));
    metadata.insert(
        "risk_challenge_id".to_owned(),
        Value::String(step_up.challenge_id.clone()),
    );
    state
        .repository
        .apply_step_up_action(
            &step_up,
            &StepUpAction::DisableMfaFactor {
                factor_id,
                audit_entry: AuditEntry {
                    audit_id: random_uuid_v4(),
                    actor_type: "account".to_owned(),
                    actor_account_id: Some(claims.account_id.clone()),
                    actor_device_id: None,
                    actor_role: None,
                    actor_service: None,
                    target_device_id: Some(step_up.device_id.clone()),
                    session_id: None,
                    action: "mfa_factor_disabled".to_owned(),
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
                "mfa_factor_changed",
                "the MFA factor changed or the step-up token was already consumed",
                &request_id.0,
            ),
            StoreError::Unavailable => ApiError::internal(&request_id.0),
        })?;
    consume_ephemeral_step_up(&state, &step_up).await;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_trusted_devices(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let claims = authenticate(&state, &headers, &request_id.0).await?;
    let now = now_epoch_millis();
    let devices = state
        .repository
        .list_trusted_devices_for_account(&claims.account_id)
        .await
        .map_err(|_| ApiError::internal(&request_id.0))?
        .iter()
        .map(|trusted| {
            let status = if trusted.status == TrustedDeviceStatus::Active
                && trusted.expires_at_epoch_millis <= now
            {
                "expired"
            } else {
                trusted_device_status(trusted.status)
            };
            TrustedDeviceView {
                trusted_device_id: trusted.trusted_device_id.clone(),
                controller_device_id: trusted.controller_device_id.clone(),
                trust_level: trusted.trust_level.clone(),
                status,
                created_at_epoch_millis: trusted.created_at_epoch_millis,
                last_used_at_epoch_millis: trusted.last_used_at_epoch_millis,
                expires_at_epoch_millis: trusted.expires_at_epoch_millis,
            }
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({ "trusted_devices": devices })))
}

pub async fn revoke_trusted_device(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(trusted_device_id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    let claims = authenticate(&state, &headers, &request_id.0).await?;
    let step_up = validate_step_up_for_request(
        &state,
        &claims,
        &headers,
        &method,
        &uri,
        &[],
        None,
        "trusted_device_change",
        &request_id.0,
    )
    .await?;
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "trusted_device_id".to_owned(),
        Value::String(trusted_device_id.clone()),
    );
    metadata.insert(
        "risk_challenge_id".to_owned(),
        Value::String(step_up.challenge_id.clone()),
    );
    state
        .repository
        .apply_step_up_action(
            &step_up,
            &StepUpAction::RevokeTrustedDevice {
                trusted_device_id,
                audit_entry: AuditEntry {
                    audit_id: random_uuid_v4(),
                    actor_type: "account".to_owned(),
                    actor_account_id: Some(claims.account_id.clone()),
                    actor_device_id: None,
                    actor_role: None,
                    actor_service: None,
                    target_device_id: Some(step_up.device_id.clone()),
                    session_id: None,
                    action: "trusted_device_revoked".to_owned(),
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
                "trusted_device_changed",
                "the trusted device changed or the step-up token was already consumed",
                &request_id.0,
            ),
            StoreError::Unavailable => ApiError::internal(&request_id.0),
        })?;
    consume_ephemeral_step_up(&state, &step_up).await;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn verify_mfa(Extension(request_id): Extension<RequestId>) -> ApiError {
    ApiError::new(
        StatusCode::UPGRADE_REQUIRED,
        "login_finish_required",
        "use POST /v1/auth/login/finish with device proof",
        &request_id.0,
    )
}

pub async fn create_risk_challenge(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let claims = authenticate(&state, &headers, &request_id.0).await?;
    let request: RiskChallengeRequest = parse_json(&body, &request_id.0)?;
    if !ALLOWED_STEP_UP_PURPOSES.contains(&request.purpose.as_str()) {
        return Err(ApiError::bad_request(
            "invalid_risk_purpose",
            "purpose is not a frozen step-up purpose",
            &request_id.0,
        ));
    }
    let binding_method = Method::from_bytes(request.method.as_bytes()).map_err(|_| {
        ApiError::bad_request(
            "invalid_operation_binding",
            "method is not a valid HTTP method",
            &request_id.0,
        )
    })?;
    if !matches!(
        binding_method,
        Method::GET | Method::POST | Method::PATCH | Method::DELETE
    ) {
        return Err(ApiError::bad_request(
            "invalid_operation_binding",
            "method is not allowed for a step-up operation",
            &request_id.0,
        ));
    }
    let binding_path = canonical_operation_path(&request.path, &request_id.0)?;
    let body_hash_bytes = decode_sha256_hex(&request.body_hash).map_err(|_| {
        ApiError::bad_request(
            "invalid_operation_binding",
            "body_hash must be a 32-byte hexadecimal SHA-256 digest",
            &request_id.0,
        )
    })?;
    if request.request_id.is_empty()
        || request.request_id.len() > 128
        || !request.request_id.is_ascii()
    {
        return Err(ApiError::bad_request(
            "invalid_operation_binding",
            "request_id must be 1 to 128 ASCII characters",
            &request_id.0,
        ));
    }
    let now = now_epoch_millis();
    let expires = now + state.config.challenge_ttl_seconds * 1_000;
    let binding = operation_binding_hash(
        &claims.account_id,
        &request.device_id,
        &request.purpose,
        binding_method.as_str(),
        &binding_path,
        &body_hash_bytes,
        &request.request_id,
        expires,
    )
    .map_err(|_| ApiError::internal(&request_id.0))?;
    let challenge_id = random_uuid_v4();
    let persistent = RiskChallenge {
        risk_challenge_id: challenge_id.clone(),
        account_id: claims.account_id.clone(),
        device_id: Some(request.device_id.clone()),
        purpose: request.purpose.clone(),
        operation_binding_hash: decode_sha256_hex(&binding)
            .map_err(|_| ApiError::internal(&request_id.0))?,
        risk_level: "high".to_owned(),
        required_methods: Vec::new(),
        status: RiskChallengeStatus::Issued,
        attempts_remaining: state.config.challenge_attempts,
        ip_address: None,
        user_agent: sanitized_user_agent(&headers),
        expires_at_epoch_millis: expires,
        created_at_epoch_millis: now,
        verified_at_epoch_millis: None,
        consumed_at_epoch_millis: None,
    };
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "risk_challenge_id".to_owned(),
        Value::String(challenge_id.clone()),
    );
    metadata.insert("purpose".to_owned(), Value::String(request.purpose));
    let audit_entry = AuditEntry {
        audit_id: random_uuid_v4(),
        actor_type: "account".to_owned(),
        actor_account_id: Some(claims.account_id.clone()),
        actor_device_id: None,
        actor_role: None,
        actor_service: None,
        target_device_id: Some(request.device_id.clone()),
        session_id: None,
        action: "risk_challenge_issued".to_owned(),
        result: "success".to_owned(),
        reason: None,
        metadata,
        request_id: request_id.0.clone(),
        created_at_epoch_millis: now,
    };
    let persistent = match state
        .repository
        .create_risk_challenge(&persistent, &audit_entry)
        .await
        .map_err(|_| ApiError::internal(&request_id.0))?
    {
        RiskChallengeCreationOutcome::Created(challenge) => *challenge,
        RiskChallengeCreationOutcome::MfaEnrollmentRequired => {
            return Err(ApiError::forbidden(
                "mfa_enrollment_required",
                "this high-risk operation requires an enrolled MFA factor",
                &request_id.0,
            ));
        }
        RiskChallengeCreationOutcome::NotAuthorized => {
            return Err(ApiError::forbidden(
                "device_not_authorized",
                "step-up device does not belong to the account",
                &request_id.0,
            ));
        }
    };
    let required_methods = persistent.required_methods.clone();
    let challenge = AuthChallenge {
        challenge_id: persistent.risk_challenge_id,
        account_id: persistent.account_id,
        device_id: persistent.device_id,
        purpose: ChallengePurpose::StepUp(persistent.purpose),
        operation_binding_hash: Some(binding.clone()),
        login: None,
        attempts_remaining: persistent.attempts_remaining,
        expires_at_epoch_millis: persistent.expires_at_epoch_millis,
        verified_at_epoch_millis: None,
        consumed_at_epoch_millis: None,
    };
    let _ = state.ephemeral.put_challenge(&challenge).await;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "risk_challenge_id": challenge.challenge_id,
            "required_methods": required_methods,
            "operation_binding_hash": binding,
            "expires_at_epoch_millis": expires,
            "attempts_remaining": challenge.attempts_remaining,
        })),
    ))
}

pub async fn verify_risk_challenge(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(challenge_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    let claims = authenticate(&state, &headers, &request_id.0).await?;
    let request: VerifyRiskRequest = parse_json(&body, &request_id.0)?;
    let challenge = verify_challenge_factor(
        &state,
        &challenge_id,
        &request.factor,
        &request.code,
        ChallengeKind::StepUp,
        Some(&claims.account_id),
        &request_id.0,
    )
    .await?;
    let purpose = challenge.purpose.clone();
    let operation_binding_hash = hex_encode(&challenge.operation_binding_hash);
    let step_up_device_id = challenge
        .device_id
        .clone()
        .ok_or_else(|| ApiError::internal(&request_id.0))?;
    let token = sign_step_up_token(
        &StepUpClaims {
            account_id: challenge.account_id.clone(),
            device_id: step_up_device_id.clone(),
            challenge_id: challenge_id.clone(),
            purpose,
            operation_binding_hash,
            expires_at_epoch_millis: challenge.expires_at_epoch_millis,
            token_type: "step_up".to_owned(),
        },
        &state.config.token_secret,
    )
    .map_err(|_| ApiError::internal(&request_id.0))?;
    Ok(Json(json!({
        "risk_challenge_id": challenge_id,
        "step_up_token": token,
        "expires_at_epoch_millis": challenge.expires_at_epoch_millis,
    })))
}

#[derive(Clone, Copy)]
enum ChallengeKind {
    StepUp,
}

impl ChallengeKind {
    const fn success_action(self) -> &'static str {
        match self {
            Self::StepUp => "risk_challenge_succeeded",
        }
    }

    const fn failure_action(self) -> &'static str {
        match self {
            Self::StepUp => "risk_challenge_failed",
        }
    }
}

async fn verify_challenge_factor(
    state: &AppState,
    challenge_id: &str,
    factor_kind: &str,
    code: &str,
    kind: ChallengeKind,
    expected_account_id: Option<&str>,
    request_id: &str,
) -> ApiResult<RiskChallenge> {
    let now = now_epoch_millis();
    let account_id = expected_account_id.ok_or_else(|| challenge_verification_error(request_id))?;
    let authority = state
        .repository
        .load_risk_challenge_authority(challenge_id)
        .await
        .map_err(|_| ApiError::internal(request_id))?
        .filter(|challenge| challenge.account_id == account_id)
        .ok_or_else(|| challenge_verification_error(request_id))?;
    let success_audit_entry = challenge_audit_entry(
        request_id,
        &authority,
        kind.success_action(),
        "success",
        None,
        now,
    );
    let failure_audit_entry = challenge_audit_entry(
        request_id,
        &authority,
        kind.failure_action(),
        "failure",
        Some("invalid_expired_consumed_or_incorrect"),
        now,
    );
    let recovery_code_audit_entry = (factor_kind == "recovery_code").then(|| {
        challenge_audit_entry(
            request_id,
            &authority,
            "mfa_recovery_code_used",
            "success",
            None,
            now,
        )
    });
    match state
        .repository
        .verify_risk_challenge(&RiskChallengeVerification {
            challenge_id: challenge_id.to_owned(),
            account_id: account_id.to_owned(),
            factor_kind: factor_kind.to_owned(),
            factor_code: code.to_owned(),
            success_audit_entry,
            failure_audit_entry,
            recovery_code_audit_entry,
            now_epoch_millis: now,
        })
        .await
        .map_err(|error| match error {
            StoreError::Conflict => challenge_verification_error(request_id),
            StoreError::Unavailable => ApiError::internal(request_id),
        })? {
        RiskChallengeVerificationOutcome::Verified(challenge)
        | RiskChallengeVerificationOutcome::AlreadyVerified(challenge) => Ok(challenge),
        RiskChallengeVerificationOutcome::Rejected => Err(challenge_verification_error(request_id)),
    }
}

fn challenge_verification_error(request_id: &str) -> ApiError {
    ApiError::forbidden(
        "mfa_verification_failed",
        "challenge is invalid, expired, consumed, or the code is incorrect",
        request_id,
    )
}

fn challenge_audit_entry(
    request_id: &str,
    challenge: &RiskChallenge,
    action: &str,
    result: &str,
    reason: Option<&str>,
    now_epoch_millis: u64,
) -> AuditEntry {
    AuditEntry {
        audit_id: random_uuid_v4(),
        actor_type: "account".to_owned(),
        actor_account_id: Some(challenge.account_id.clone()),
        actor_device_id: None,
        actor_role: None,
        actor_service: None,
        target_device_id: challenge.device_id.clone(),
        session_id: None,
        action: action.to_owned(),
        result: result.to_owned(),
        reason: reason.map(ToOwned::to_owned),
        metadata: BTreeMap::new(),
        request_id: request_id.to_owned(),
        created_at_epoch_millis: now_epoch_millis,
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
pub(super) async fn consume_step_up_for_request(
    state: &AppState,
    access_claims: &AccessClaims,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    body: &[u8],
    expected_device_id: Option<&str>,
    expected_purpose: &str,
    request_id: &str,
) -> ApiResult<()> {
    let expectation = validate_step_up_for_request(
        state,
        access_claims,
        headers,
        method,
        uri,
        body,
        expected_device_id,
        expected_purpose,
        request_id,
    )
    .await?;
    state
        .repository
        .consume_step_up(&expectation)
        .await
        .map_err(|error| match error {
            StoreError::Conflict => ApiError::conflict(
                "step_up_already_consumed",
                "the step-up challenge is invalid, expired, or already consumed",
                request_id,
            ),
            StoreError::Unavailable => ApiError::internal(request_id),
        })?;

    consume_ephemeral_step_up(state, &expectation).await;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn validate_step_up_for_request(
    state: &AppState,
    access_claims: &AccessClaims,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    body: &[u8],
    expected_device_id: Option<&str>,
    expected_purpose: &str,
    request_id: &str,
) -> ApiResult<StepUpExpectation> {
    let challenge_id = required_step_up_header(headers, "x-rctl-risk-challenge-id", request_id)?;
    let token = required_step_up_header(headers, "x-rctl-step-up-token", request_id)?;
    let now = now_epoch_millis();
    let step_up = verify_step_up_token(token, &state.config.token_secret, now).map_err(|_| {
        ApiError::forbidden(
            "invalid_step_up_token",
            "step-up token is invalid or expired",
            request_id,
        )
    })?;
    let target = uri
        .path_and_query()
        .map_or(uri.path(), |value| value.as_str());
    let target = canonical_operation_path(target, request_id)?;
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    let body_hash = canonical_request_body_hash(body, content_type).map_err(|_| {
        ApiError::bad_request(
            "invalid_payload",
            "request body cannot be canonicalized",
            request_id,
        )
    })?;
    let expected_binding = operation_binding_hash(
        &access_claims.account_id,
        &step_up.device_id,
        expected_purpose,
        method.as_str(),
        &target,
        &body_hash,
        request_id,
        step_up.expires_at_epoch_millis,
    )
    .map_err(|_| {
        ApiError::bad_request(
            "invalid_operation_binding",
            "request target cannot be canonicalized",
            request_id,
        )
    })?;
    let expected_binding_bytes =
        decode_sha256_hex(&expected_binding).map_err(|_| ApiError::internal(request_id))?;
    if step_up.account_id != access_claims.account_id
        || step_up.challenge_id != challenge_id
        || step_up.purpose != expected_purpose
        || expected_device_id.is_some_and(|device_id| step_up.device_id != device_id)
        || step_up.operation_binding_hash != expected_binding
    {
        return Err(ApiError::forbidden(
            "step_up_binding_mismatch",
            "step-up token is not bound to this operation",
            request_id,
        ));
    }

    Ok(StepUpExpectation {
        challenge_id: challenge_id.to_owned(),
        account_id: access_claims.account_id.clone(),
        device_id: step_up.device_id,
        purpose: expected_purpose.to_owned(),
        operation_binding_hash: expected_binding_bytes,
        now_epoch_millis: now,
    })
}

pub(super) async fn consume_ephemeral_step_up(state: &AppState, expectation: &StepUpExpectation) {
    let operation_binding_hash = hex_encode(&expectation.operation_binding_hash);
    let ephemeral = state.ephemeral.clone();
    let challenge_id = expectation.challenge_id.clone();
    let account_id = expectation.account_id.clone();
    let device_id = expectation.device_id.clone();
    let purpose = expectation.purpose.clone();
    let now_epoch_millis = expectation.now_epoch_millis;
    tokio::spawn(async move {
        let _ = ephemeral
            .consume_step_up(
                &StepUpConsumption {
                    challenge_id: &challenge_id,
                    account_id: &account_id,
                    device_id: &device_id,
                    purpose: &purpose,
                    operation_binding_hash: &operation_binding_hash,
                },
                now_epoch_millis,
            )
            .await;
    });
}

fn canonical_operation_path(value: &str, request_id: &str) -> ApiResult<String> {
    if value.is_empty()
        || value.len() > 2_048
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'\\')
    {
        return Err(ApiError::bad_request(
            "invalid_operation_binding",
            "path must be a canonical origin-form /v1 path",
            request_id,
        ));
    }
    let target = canonical_request_target(value).map_err(|_| {
        ApiError::bad_request(
            "invalid_operation_binding",
            "path is not a valid canonical HTTP request target",
            request_id,
        )
    })?;
    if !target.starts_with("/v1/") {
        return Err(ApiError::bad_request(
            "invalid_operation_binding",
            "path must target a versioned API endpoint",
            request_id,
        ));
    }
    Ok(target)
}

fn required_step_up_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
    request_id: &str,
) -> ApiResult<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ApiError::forbidden(
                "step_up_required",
                format!("missing required step-up header {name}"),
                request_id,
            )
        })
}

fn sanitized_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .map(|value| value.chars().take(512).collect())
}

const fn trusted_device_status(status: TrustedDeviceStatus) -> &'static str {
    match status {
        TrustedDeviceStatus::Active => "active",
        TrustedDeviceStatus::Expired => "expired",
        TrustedDeviceStatus::Revoked => "revoked",
    }
}

fn required_idempotency_key<'a>(headers: &'a HeaderMap, request_id: &str) -> ApiResult<&'a str> {
    headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            !value.is_empty() && value.len() <= 128 && value.bytes().all(|byte| byte.is_ascii())
        })
        .ok_or_else(|| {
            ApiError::bad_request(
                "idempotency_key_required",
                "Idempotency-Key must contain 1 to 128 ASCII characters",
                request_id,
            )
        })
}

fn validate_x25519_public_key(public_key: &[u8; 32], request_id: &str) -> ApiResult<()> {
    let probe_secret = StaticSecret::from([0x42_u8; 32]);
    let shared = probe_secret.diffie_hellman(&X25519PublicKey::from(*public_key));
    if shared.as_bytes().iter().all(|byte| *byte == 0) {
        return Err(ApiError::bad_request(
            "invalid_recovery_delivery_key",
            "recovery_delivery_public_key is a low-order X25519 point",
            request_id,
        ));
    }
    Ok(())
}

fn build_recovery_delivery(
    claims: &AccessClaims,
    enrollment: &PendingTotpEnrollment,
    recovery_codes: &[String],
    idempotency_key_hash: [u8; 32],
    finish_request_binding_hash: [u8; 32],
    now: u64,
    request_id: &str,
) -> ApiResult<RecoveryCodeDelivery> {
    let delivery_id = random_uuid_v4();
    let expires_at = now.saturating_add(RECOVERY_DELIVERY_TTL_MILLIS);
    let mut server_secret_bytes = random_bytes_32();
    let server_secret = StaticSecret::from(server_secret_bytes);
    server_secret_bytes.zeroize();
    let server_public_key = X25519PublicKey::from(&server_secret).to_bytes();
    let client_public_key = X25519PublicKey::from(enrollment.recovery_delivery_public_key);
    let mut shared_secret = *server_secret.diffie_hellman(&client_public_key).as_bytes();
    if shared_secret.iter().all(|byte| *byte == 0) {
        shared_secret.zeroize();
        return Err(ApiError::bad_request(
            "invalid_recovery_delivery_key",
            "recovery delivery X25519 agreement failed",
            request_id,
        ));
    }
    let salt = sha256(&canonical_fields(
        "rctl-recovery-delivery-salt-v1",
        &[
            ("account_id", claims.account_id.as_bytes()),
            ("account_session_id", claims.account_session_id.as_bytes()),
            ("factor_id", enrollment.factor_id.as_bytes()),
            ("delivery_id", delivery_id.as_bytes()),
            ("idempotency_key_hash", &idempotency_key_hash),
        ],
    ));
    let created = now.to_be_bytes();
    let expires = expires_at.to_be_bytes();
    let info = canonical_fields(
        "rctl-recovery-delivery-v1",
        &[
            ("account_id", claims.account_id.as_bytes()),
            ("account_session_id", claims.account_session_id.as_bytes()),
            ("factor_id", enrollment.factor_id.as_bytes()),
            ("delivery_id", delivery_id.as_bytes()),
            (
                "client_ephemeral_public_key",
                &enrollment.recovery_delivery_public_key,
            ),
            ("server_ephemeral_public_key", &server_public_key),
            ("created_at_epoch_millis", &created),
            ("expires_at_epoch_millis", &expires),
        ],
    );
    let mut delivery_key = [0_u8; 32];
    Hkdf::<Sha256>::new(Some(&salt), &shared_secret)
        .expand(&info, &mut delivery_key)
        .map_err(|_| ApiError::internal(request_id))?;
    shared_secret.zeroize();
    let raw_plaintext = serde_json::to_vec(&json!({ "recovery_codes": recovery_codes }))
        .map_err(|_| ApiError::internal(request_id))?;
    let mut plaintext = remote_protocol::canonical_json_bytes_from_slice(&raw_plaintext)
        .map_err(|_| ApiError::internal(request_id))?;
    let mut nonce_source = random_bytes_32();
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(&nonce_source[..12]);
    nonce_source.zeroize();
    let ciphertext = ChaCha20Poly1305::new((&delivery_key).into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &info,
            },
        )
        .map_err(|_| ApiError::internal(request_id))?;
    plaintext.zeroize();
    delivery_key.zeroize();
    let recovery_code_count =
        u16::try_from(recovery_codes.len()).map_err(|_| ApiError::internal(request_id))?;
    Ok(RecoveryCodeDelivery {
        delivery_id,
        account_id: claims.account_id.clone(),
        account_session_id: claims.account_session_id.clone(),
        factor_id: enrollment.factor_id.clone(),
        idempotency_key_hash,
        finish_request_binding_hash,
        client_ephemeral_public_key: enrollment.recovery_delivery_public_key,
        server_ephemeral_public_key: server_public_key,
        nonce,
        ciphertext,
        recovery_code_count,
        created_at_epoch_millis: now,
        expires_at_epoch_millis: expires_at,
        acknowledged_at_epoch_millis: None,
    })
}

async fn replay_totp_delivery(
    state: &AppState,
    lookup: &TotpEnrollmentReplayLookup,
    request_id: &str,
) -> ApiResult<Json<Value>> {
    match state
        .repository
        .replay_totp_enrollment(lookup)
        .await
        .map_err(|_| ApiError::internal(request_id))?
    {
        TotpEnrollmentReplayOutcome::Replayed(delivery) => {
            Ok(Json(recovery_delivery_response(&delivery)))
        }
        TotpEnrollmentReplayOutcome::BindingMismatch => Err(ApiError::conflict(
            "idempotency_binding_mismatch",
            "Idempotency-Key was already used with a different TOTP enrollment binding",
            request_id,
        )),
        TotpEnrollmentReplayOutcome::NotFound | TotpEnrollmentReplayOutcome::NotAuthorized => {
            Err(ApiError::unauthorized(request_id))
        }
    }
}

fn recovery_delivery_response(delivery: &RecoveryCodeDelivery) -> Value {
    json!({
        "delivery_id": delivery.delivery_id,
        "server_ephemeral_public_key": encode_base64url(&delivery.server_ephemeral_public_key),
        "nonce": encode_base64url(&delivery.nonce),
        "ciphertext": encode_base64url(&delivery.ciphertext),
        "created_at_epoch_millis": delivery.created_at_epoch_millis,
        "expires_at_epoch_millis": delivery.expires_at_epoch_millis,
        "recovery_code_count": delivery.recovery_code_count,
    })
}

fn generate_recovery_codes(account_id: &str) -> (Vec<String>, Vec<RecoveryCode>) {
    let codes = (0..8)
        .map(|_| {
            let raw = random_token(12).to_ascii_uppercase();
            format!("{}-{}", &raw[..8], &raw[8..16])
        })
        .collect::<Vec<_>>();
    let records = codes
        .iter()
        .map(|code| RecoveryCode {
            recovery_code_id: random_uuid_v4(),
            account_id: account_id.to_owned(),
            code_hash: sha256(code.as_bytes()),
            used_at_epoch_millis: None,
            expires_at_epoch_millis: None,
        })
        .collect::<Vec<_>>();
    (codes, records)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::ephemeral::FailingEphemeralState;
    use crate::model::{
        Account, AccountSession, AccountStatus, Architecture, Device, DeviceCapabilities,
        DeviceLifecycleStatus, Platform,
    };
    use crate::security::{sha256, sign_access_token, sign_step_up_token};
    use crate::{AppConfig, MemoryRepository, SignalNotifier};

    #[derive(Debug)]
    struct StepUpFixture {
        account_id: String,
        account_session_id: String,
        device_id: String,
        factor_id: String,
        recovery_code_id: String,
        recovery_code: String,
        email: String,
        operation_path: String,
        operation_request_id: String,
    }

    impl StepUpFixture {
        fn new(suffix: &str) -> Self {
            let account_id = format!("step-up-account-{suffix}");
            let device_id = format!("step-up-device-{suffix}");
            let factor_id = format!("step-up-factor-{suffix}");
            Self {
                account_session_id: format!("step-up-session-{suffix}"),
                recovery_code_id: format!("step-up-recovery-{suffix}"),
                recovery_code: format!("RECOVERY-{suffix}"),
                email: format!("step-up-{suffix}@example.com"),
                operation_path: format!("/v1/me/mfa/factors/{factor_id}"),
                operation_request_id: format!("step-up-operation-{suffix}"),
                account_id,
                device_id,
                factor_id,
            }
        }

        fn access_headers(&self, state: &AppState, now_epoch_millis: u64) -> HeaderMap {
            let token = sign_access_token(
                &AccessClaims {
                    account_id: self.account_id.clone(),
                    account_session_id: self.account_session_id.clone(),
                    issued_at_epoch_millis: now_epoch_millis,
                    expires_at_epoch_millis: now_epoch_millis + 300_000,
                    mfa_verified: true,
                    token_type: "access".to_owned(),
                },
                &state.config.token_secret,
            )
            .expect("sign access token");
            let mut headers = HeaderMap::new();
            headers.insert(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {token}")
                    .parse()
                    .expect("authorization header"),
            );
            headers
        }
    }

    async fn seed_step_up_fixture(
        state: &AppState,
        fixture: &StepUpFixture,
        now_epoch_millis: u64,
    ) {
        state
            .repository
            .transact(&mut |database| {
                database.accounts.insert(
                    fixture.account_id.clone(),
                    Account {
                        account_id: fixture.account_id.clone(),
                        email: fixture.email.clone(),
                        display_name: "Step-up Test".to_owned(),
                        password_hash: "unused-password-hash".to_owned(),
                        status: AccountStatus::Active,
                        created_at_epoch_millis: now_epoch_millis.saturating_sub(1),
                        updated_at_epoch_millis: now_epoch_millis.saturating_sub(1),
                    },
                );
                database
                    .account_by_email
                    .insert(fixture.email.clone(), fixture.account_id.clone());
                database.account_sessions.insert(
                    fixture.account_session_id.clone(),
                    AccountSession {
                        account_session_id: fixture.account_session_id.clone(),
                        account_id: fixture.account_id.clone(),
                        refresh_token_hash: sha256(fixture.account_session_id.as_bytes()),
                        mfa_verified: true,
                        expires_at_epoch_millis: now_epoch_millis + 300_000,
                        revoked_at_epoch_millis: None,
                        revoked_reason: None,
                    },
                );
                database.devices.insert(
                    fixture.device_id.clone(),
                    Device {
                        device_id: fixture.device_id.clone(),
                        account_id: fixture.account_id.clone(),
                        display_name: "Step-up Device".to_owned(),
                        platform: Platform::Windows,
                        os_version: "11".to_owned(),
                        arch: Architecture::X86_64,
                        capabilities: DeviceCapabilities {
                            controller: true,
                            controlled: true,
                            file_transfer: false,
                            unattended: false,
                        },
                        public_key_id: format!("key-{}", fixture.device_id),
                        public_key: [7; 32],
                        public_key_version: 1,
                        public_key_revoked_at_epoch_millis: None,
                        status: DeviceLifecycleStatus::Offline,
                        last_seen_epoch_millis: None,
                        created_at_epoch_millis: now_epoch_millis.saturating_sub(1),
                        updated_at_epoch_millis: now_epoch_millis.saturating_sub(1),
                    },
                );
                database.mfa_factors.insert(
                    fixture.factor_id.clone(),
                    MfaFactor {
                        factor_id: fixture.factor_id.clone(),
                        account_id: fixture.account_id.clone(),
                        secret_base32: "JBSWY3DPEHPK3PXP".to_owned(),
                        active: true,
                        last_used_counter: None,
                        created_at_epoch_millis: now_epoch_millis.saturating_sub(1),
                    },
                );
                database.recovery_codes.insert(
                    fixture.recovery_code_id.clone(),
                    RecoveryCode {
                        recovery_code_id: fixture.recovery_code_id.clone(),
                        account_id: fixture.account_id.clone(),
                        code_hash: sha256(fixture.recovery_code.as_bytes()),
                        used_at_epoch_millis: None,
                        expires_at_epoch_millis: None,
                    },
                );
                Ok(())
            })
            .await
            .expect("seed step-up authority");
    }

    async fn assert_authoritative_step_up_retry_gate(
        state: &AppState,
        failing_ephemeral: &FailingEphemeralState,
        fixture: &StepUpFixture,
    ) -> String {
        let now = now_epoch_millis();
        let headers = fixture.access_headers(state, now);
        let create_body = Bytes::from(
            serde_json::to_vec(&json!({
                "device_id": fixture.device_id,
                "purpose": "mfa_factor_change",
                "method": "DELETE",
                "path": fixture.operation_path,
                "body_hash": hex_encode(&sha256(&[])),
                "request_id": fixture.operation_request_id,
            }))
            .expect("serialize create challenge request"),
        );
        let (status, Json(created)) = create_risk_challenge(
            State(state.clone()),
            Extension(RequestId("create-step-up".to_owned())),
            headers.clone(),
            create_body,
        )
        .await
        .expect("PostgreSQL creation must survive ephemeral put failure");
        assert_eq!(status, StatusCode::CREATED);
        let challenge_id = created["risk_challenge_id"]
            .as_str()
            .expect("challenge id")
            .to_owned();
        assert_eq!(failing_ephemeral.calls().put_challenge, 1);

        let verify_body = Bytes::from(
            serde_json::to_vec(&json!({
                "factor": "recovery_code",
                "code": fixture.recovery_code,
            }))
            .expect("serialize challenge verification"),
        );
        let Json(first) = verify_risk_challenge(
            State(state.clone()),
            Extension(RequestId("verify-step-up-first".to_owned())),
            Path(challenge_id.clone()),
            headers.clone(),
            verify_body.clone(),
        )
        .await
        .expect("authoritative verification");
        let first_token = first["step_up_token"]
            .as_str()
            .expect("first step-up token")
            .to_owned();

        let Json(retry) = verify_risk_challenge(
            State(state.clone()),
            Extension(RequestId("verify-step-up-retry".to_owned())),
            Path(challenge_id.clone()),
            headers.clone(),
            verify_body.clone(),
        )
        .await
        .expect("verified challenge retry");
        assert_eq!(
            retry["step_up_token"].as_str(),
            Some(first_token.as_str()),
            "the same PostgreSQL authority must deterministically sign the same semantic token"
        );

        let mut verified_snapshot = None;
        state
            .repository
            .read(&mut |database| {
                let challenge = &database.risk_challenges[&challenge_id];
                verified_snapshot = Some((
                    challenge.status,
                    challenge.consumed_at_epoch_millis,
                    database.recovery_codes[&fixture.recovery_code_id].used_at_epoch_millis,
                    database
                        .audit_logs
                        .iter()
                        .filter(|entry| {
                            entry.actor_account_id.as_deref() == Some(&fixture.account_id)
                                && entry.action == "risk_challenge_succeeded"
                        })
                        .count(),
                    database
                        .audit_logs
                        .iter()
                        .filter(|entry| {
                            entry.actor_account_id.as_deref() == Some(&fixture.account_id)
                                && entry.action == "mfa_recovery_code_used"
                        })
                        .count(),
                ));
            })
            .await;
        let (status, consumed_at, recovery_used_at, success_audits, recovery_audits) =
            verified_snapshot.expect("verified authority snapshot");
        assert_eq!(status, RiskChallengeStatus::Verified);
        assert_eq!(consumed_at, None);
        assert!(recovery_used_at.is_some());
        assert_eq!(success_audits, 1);
        assert_eq!(recovery_audits, 1);

        let calls = failing_ephemeral.calls();
        assert_eq!(calls.begin_challenge_attempt, 0);
        assert_eq!(calls.finish_challenge_attempt, 0);
        assert_eq!(calls.consume_step_up, 0);

        let mut step_up_headers = HeaderMap::new();
        step_up_headers.insert("x-rctl-risk-challenge-id", challenge_id.parse().unwrap());
        step_up_headers.insert("x-rctl-step-up-token", first_token.parse().unwrap());
        let operation_uri: Uri = fixture.operation_path.parse().expect("operation URI");
        let mismatched = consume_step_up_for_request(
            state,
            &AccessClaims {
                account_id: fixture.account_id.clone(),
                account_session_id: fixture.account_session_id.clone(),
                issued_at_epoch_millis: now,
                expires_at_epoch_millis: now + 300_000,
                mfa_verified: true,
                token_type: "access".to_owned(),
            },
            &step_up_headers,
            &Method::DELETE,
            &operation_uri,
            b"different binding",
            Some(&fixture.device_id),
            "mfa_factor_change",
            &fixture.operation_request_id,
        )
        .await
        .expect_err("a different operation binding must be rejected");
        assert_eq!(mismatched.code, "step_up_binding_mismatch");
        assert_eq!(
            state
                .repository
                .load_risk_challenge_authority(&challenge_id)
                .await
                .expect("load challenge after binding mismatch")
                .expect("challenge after binding mismatch")
                .status,
            RiskChallengeStatus::Verified
        );

        consume_step_up_for_request(
            state,
            &AccessClaims {
                account_id: fixture.account_id.clone(),
                account_session_id: fixture.account_session_id.clone(),
                issued_at_epoch_millis: now,
                expires_at_epoch_millis: now + 300_000,
                mfa_verified: true,
                token_type: "access".to_owned(),
            },
            &step_up_headers,
            &Method::DELETE,
            &operation_uri,
            &[],
            Some(&fixture.device_id),
            "mfa_factor_change",
            &fixture.operation_request_id,
        )
        .await
        .expect("PostgreSQL consumption must not depend on ephemeral finalize");
        tokio::time::timeout(Duration::from_secs(1), async {
            while failing_ephemeral.calls().consume_step_up == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("ephemeral finalize attempt");
        assert_eq!(failing_ephemeral.calls().consume_step_up, 1);

        let consumed = state
            .repository
            .load_risk_challenge_authority(&challenge_id)
            .await
            .expect("load consumed challenge")
            .expect("consumed challenge");
        assert_eq!(consumed.status, RiskChallengeStatus::Consumed);
        assert!(consumed.consumed_at_epoch_millis.is_some());
        let reopened = verify_risk_challenge(
            State(state.clone()),
            Extension(RequestId("verify-step-up-consumed".to_owned())),
            Path(challenge_id.clone()),
            headers,
            verify_body,
        )
        .await
        .expect_err("ephemeral failure must not reopen a consumed PostgreSQL challenge");
        assert_eq!(reopened.code, "mfa_verification_failed");

        let mut final_counts = None;
        state
            .repository
            .read(&mut |database| {
                final_counts = Some((
                    database
                        .audit_logs
                        .iter()
                        .filter(|entry| {
                            entry.actor_account_id.as_deref() == Some(&fixture.account_id)
                                && entry.action == "risk_challenge_succeeded"
                        })
                        .count(),
                    database
                        .audit_logs
                        .iter()
                        .filter(|entry| {
                            entry.actor_account_id.as_deref() == Some(&fixture.account_id)
                                && entry.action == "mfa_recovery_code_used"
                        })
                        .count(),
                ));
            })
            .await;
        assert_eq!(final_counts, Some((1, 1)));
        challenge_id
    }

    async fn cleanup_postgres_step_up_fixture(database_url: &str, fixture: &StepUpFixture) {
        let (mut client, connection) = tokio_postgres::connect(database_url, tokio_postgres::NoTls)
            .await
            .expect("connect PostgreSQL cleanup client");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let transaction = client
            .transaction()
            .await
            .expect("start cleanup transaction");
        transaction
            .batch_execute("SET CONSTRAINTS ALL DEFERRED")
            .await
            .expect("defer cleanup constraints");
        for statement in [
            "DELETE FROM audit_logs WHERE actor_account_id=$1",
            "DELETE FROM account_risk_challenges WHERE account_id=$1",
            "DELETE FROM account_recovery_codes WHERE account_id=$1",
            "DELETE FROM account_mfa_factors WHERE account_id=$1",
            "DELETE FROM account_sessions WHERE account_id=$1",
            "DELETE FROM device_policies WHERE device_id IN (SELECT device_id FROM devices WHERE account_id=$1)",
            "DELETE FROM devices WHERE account_id=$1",
            "DELETE FROM accounts WHERE account_id=$1",
        ] {
            transaction
                .execute(statement, &[&fixture.account_id])
                .await
                .unwrap_or_else(|error| panic!("cleanup statement failed ({statement}): {error}"));
        }
        transaction.commit().await.expect("commit fixture cleanup");
    }

    #[test]
    fn operation_paths_are_canonicalized_and_absolute_targets_are_rejected() {
        assert_eq!(
            canonical_operation_path(
                "/v1/me/./mfa/../mfa/factors/factor-1?z=2&mode=disable&z=1",
                "request-1"
            )
            .expect("canonical path"),
            "/v1/me/mfa/factors/factor-1?mode=disable&z=1&z=2"
        );
        for invalid in [
            "https://api.example/v1/me/mfa",
            "/v1/me\\devices",
            "/v1/me?name=a+b",
            "/health",
        ] {
            assert!(canonical_operation_path(invalid, "request-1").is_err());
        }
    }

    #[tokio::test]
    async fn postgres_authoritative_step_up_is_operation_bound_and_single_use() {
        let state = AppState::for_test();
        let now = now_epoch_millis();
        let expires = now + 60_000;
        let request_id = "factor-delete-request";
        let path = "/v1/me/mfa/factors/factor-1";
        let body_hash = sha256(&[]);
        let binding = operation_binding_hash(
            "account-1",
            "device-1",
            "mfa_factor_change",
            "DELETE",
            path,
            &body_hash,
            request_id,
            expires,
        )
        .expect("operation binding");
        let ephemeral = AuthChallenge {
            challenge_id: "risk-1".to_owned(),
            account_id: "account-1".to_owned(),
            device_id: Some("device-1".to_owned()),
            purpose: ChallengePurpose::StepUp("mfa_factor_change".to_owned()),
            operation_binding_hash: Some(binding.clone()),
            login: None,
            attempts_remaining: 5,
            expires_at_epoch_millis: expires,
            verified_at_epoch_millis: None,
            consumed_at_epoch_millis: None,
        };
        assert!(state.ephemeral.put_challenge(&ephemeral).await.unwrap());
        let attempt = match state
            .ephemeral
            .begin_challenge_attempt("risk-1", ExpectedChallengeKind::StepUp, now)
            .await
            .unwrap()
        {
            ChallengeAttemptStart::Started(attempt) => attempt,
            ChallengeAttemptStart::Rejected { .. } => panic!("challenge attempt rejected"),
        };
        state
            .ephemeral
            .finish_challenge_attempt(&attempt, true, false, now)
            .await
            .unwrap()
            .expect("verified challenge");
        let binding_bytes = decode_sha256_hex(&binding).unwrap();
        state
            .repository
            .transact(&mut |database| {
                database.risk_challenges.insert(
                    "risk-1".to_owned(),
                    RiskChallenge {
                        risk_challenge_id: "risk-1".to_owned(),
                        account_id: "account-1".to_owned(),
                        device_id: Some("device-1".to_owned()),
                        purpose: "mfa_factor_change".to_owned(),
                        operation_binding_hash: binding_bytes,
                        risk_level: "high".to_owned(),
                        required_methods: vec!["totp".to_owned()],
                        status: RiskChallengeStatus::Verified,
                        attempts_remaining: 5,
                        ip_address: None,
                        user_agent: None,
                        expires_at_epoch_millis: expires,
                        created_at_epoch_millis: now,
                        verified_at_epoch_millis: Some(now),
                        consumed_at_epoch_millis: None,
                    },
                );
                Ok(())
            })
            .await
            .unwrap();
        let token = sign_step_up_token(
            &StepUpClaims {
                account_id: "account-1".to_owned(),
                device_id: "device-1".to_owned(),
                challenge_id: "risk-1".to_owned(),
                purpose: "mfa_factor_change".to_owned(),
                operation_binding_hash: binding,
                expires_at_epoch_millis: expires,
                token_type: "step_up".to_owned(),
            },
            &state.config.token_secret,
        )
        .unwrap();
        let headers = HeaderMap::from_iter([
            (
                "x-rctl-risk-challenge-id".parse().unwrap(),
                "risk-1".parse().unwrap(),
            ),
            (
                "x-rctl-step-up-token".parse().unwrap(),
                token.parse().unwrap(),
            ),
        ]);
        let claims = AccessClaims {
            account_id: "account-1".to_owned(),
            account_session_id: "session-1".to_owned(),
            issued_at_epoch_millis: now,
            expires_at_epoch_millis: expires,
            mfa_verified: true,
            token_type: "access".to_owned(),
        };
        let uri: Uri = path.parse().unwrap();

        consume_step_up_for_request(
            &state,
            &claims,
            &headers,
            &Method::DELETE,
            &uri,
            &[],
            Some("device-1"),
            "mfa_factor_change",
            request_id,
        )
        .await
        .expect("first consume");
        let replay = consume_step_up_for_request(
            &state,
            &claims,
            &headers,
            &Method::DELETE,
            &uri,
            &[],
            Some("device-1"),
            "mfa_factor_change",
            request_id,
        )
        .await
        .expect_err("replay must fail");
        assert_eq!(replay.code, "step_up_already_consumed");

        let mut consumed = false;
        state
            .repository
            .read(&mut |database| {
                consumed = database.risk_challenges.get("risk-1").is_some_and(|value| {
                    value.status == RiskChallengeStatus::Consumed
                        && value.consumed_at_epoch_millis.is_some()
                });
            })
            .await;
        assert!(consumed);
    }

    #[tokio::test]
    async fn verified_step_up_retry_and_terminal_state_ignore_ephemeral_failures() {
        let repository = Arc::new(MemoryRepository::default());
        let failing_ephemeral = Arc::new(FailingEphemeralState::default());
        let state = AppState::with_ephemeral(
            repository,
            failing_ephemeral.clone(),
            AppConfig::for_test(),
            SignalNotifier::disabled(),
        );
        let fixture = StepUpFixture::new("memory-redis-failure");
        seed_step_up_fixture(&state, &fixture, now_epoch_millis()).await;

        assert_authoritative_step_up_retry_gate(&state, &failing_ephemeral, &fixture).await;
    }

    #[tokio::test]
    #[ignore = "requires a migrated PostgreSQL database in API_TEST_DATABASE_URL"]
    async fn postgres_verified_step_up_retry_survives_ephemeral_failures() {
        let database_url = std::env::var("API_TEST_DATABASE_URL")
            .expect("API_TEST_DATABASE_URL must point to an isolated migrated database");
        let repository = Arc::new(
            crate::PostgresRepository::connect(&database_url, [0; 32])
                .await
                .expect("connect PostgreSQL repository"),
        );
        let failing_ephemeral = Arc::new(FailingEphemeralState::default());
        let state = AppState::with_ephemeral(
            repository,
            failing_ephemeral.clone(),
            AppConfig::for_test(),
            SignalNotifier::disabled(),
        );
        let fixture = StepUpFixture::new(&format!("postgres-{}", random_uuid_v4()));
        seed_step_up_fixture(&state, &fixture, now_epoch_millis()).await;

        assert_authoritative_step_up_retry_gate(&state, &failing_ephemeral, &fixture).await;
        cleanup_postgres_step_up_fixture(&database_url, &fixture).await;
    }

    #[tokio::test]
    async fn cancelled_step_up_keeps_only_the_frozen_failure_audit() {
        let repository = Arc::new(MemoryRepository::default());
        let failing_ephemeral = Arc::new(FailingEphemeralState::default());
        let state = AppState::with_ephemeral(
            repository,
            failing_ephemeral.clone(),
            AppConfig::for_test(),
            SignalNotifier::disabled(),
        );
        let fixture = StepUpFixture::new("cancelled");
        let now = now_epoch_millis();
        seed_step_up_fixture(&state, &fixture, now).await;
        let challenge = RiskChallenge {
            risk_challenge_id: "cancelled-risk-challenge".to_owned(),
            account_id: fixture.account_id.clone(),
            device_id: Some(fixture.device_id.clone()),
            purpose: "mfa_factor_change".to_owned(),
            operation_binding_hash: [11; 32],
            risk_level: "high".to_owned(),
            required_methods: vec!["totp".to_owned(), "recovery_code".to_owned()],
            status: RiskChallengeStatus::Issued,
            attempts_remaining: 5,
            ip_address: None,
            user_agent: None,
            expires_at_epoch_millis: now + 60_000,
            created_at_epoch_millis: now,
            verified_at_epoch_millis: None,
            consumed_at_epoch_millis: None,
        };
        state
            .repository
            .transact(&mut |database| {
                database
                    .risk_challenges
                    .insert(challenge.risk_challenge_id.clone(), challenge.clone());
                Ok(())
            })
            .await
            .expect("seed cancellable challenge");
        let cancelled_audit = challenge_audit_entry(
            "cancel-step-up",
            &challenge,
            "risk_challenge_failed",
            "failure",
            Some("cancelled"),
            now,
        );
        assert!(state
            .repository
            .cancel_risk_challenge(&challenge.risk_challenge_id, &cancelled_audit)
            .await
            .expect("cancel issued challenge"));
        assert!(!state
            .repository
            .cancel_risk_challenge(&challenge.risk_challenge_id, &cancelled_audit)
            .await
            .expect("cancelled challenge is terminal"));

        let rejected = verify_challenge_factor(
            &state,
            &challenge.risk_challenge_id,
            "recovery_code",
            &fixture.recovery_code,
            ChallengeKind::StepUp,
            Some(&fixture.account_id),
            "verify-cancelled-step-up",
        )
        .await
        .expect_err("cancelled challenge cannot issue a new action token");
        assert_eq!(rejected.code, "mfa_verification_failed");

        let mut snapshot = None;
        state
            .repository
            .read(&mut |database| {
                snapshot = Some((
                    database.risk_challenges[&challenge.risk_challenge_id].status,
                    database.recovery_codes[&fixture.recovery_code_id].used_at_epoch_millis,
                    database
                        .audit_logs
                        .iter()
                        .filter(|entry| {
                            entry.actor_account_id.as_deref() == Some(&fixture.account_id)
                        })
                        .map(|entry| {
                            (
                                entry.action.clone(),
                                entry.result.clone(),
                                entry.reason.clone(),
                            )
                        })
                        .collect::<Vec<_>>(),
                ));
            })
            .await;
        assert_eq!(
            snapshot,
            Some((
                RiskChallengeStatus::Cancelled,
                None,
                vec![(
                    "risk_challenge_failed".to_owned(),
                    "failure".to_owned(),
                    Some("cancelled".to_owned()),
                )],
            ))
        );
        assert_eq!(failing_ephemeral.calls(), Default::default());
    }
}
