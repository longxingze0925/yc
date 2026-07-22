mod audit;
mod auth;
mod devices;
mod internal;
mod mfa;
mod sessions;

use std::collections::BTreeMap;

use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use remote_protocol::canonical_json_bytes_from_slice;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};

use crate::error::{ApiError, ApiResult};
use crate::model::{AuditEntry, Device};
use crate::security::{
    bearer, now_epoch_millis, random_uuid_v4, verify_access_token, verify_device_signature,
    AccessClaims,
};
use crate::{AppState, RequestId};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/auth/register", post(auth::register))
        .route("/v1/auth/login", post(auth::login))
        .route("/v1/auth/login/finish", post(auth::login_finish))
        .route("/v1/auth/refresh", post(auth::refresh))
        .route("/v1/auth/logout", post(auth::logout))
        .route("/v1/me/password", patch(auth::change_password))
        .route("/v1/auth/mfa/verify", post(mfa::verify_mfa))
        .route("/v1/auth/risk-challenge", post(mfa::create_risk_challenge))
        .route(
            "/v1/auth/risk-challenge/{challenge_id}/verify",
            post(mfa::verify_risk_challenge),
        )
        .route("/v1/me/mfa", get(mfa::mfa_status))
        .route("/v1/me/mfa/totp/start", post(mfa::totp_start))
        .route("/v1/me/mfa/totp/finish", post(mfa::totp_finish))
        .route(
            "/v1/me/mfa/factors/{factor_id}",
            delete(mfa::delete_mfa_factor),
        )
        .route(
            "/v1/me/mfa/recovery-codes/rotate",
            post(mfa::rotate_recovery_codes),
        )
        .route("/v1/me/trusted-devices", get(mfa::list_trusted_devices))
        .route(
            "/v1/me/trusted-devices/{trusted_device_id}",
            delete(mfa::revoke_trusted_device),
        )
        .route(
            "/v1/devices",
            post(devices::register_device).get(devices::list_devices),
        )
        .route(
            "/v1/devices/{device_id}",
            get(devices::get_device).patch(devices::update_device),
        )
        .route(
            "/v1/devices/{device_id}/keys/rotate",
            post(devices::rotate_device_key),
        )
        .route("/v1/sessions", post(sessions::create_session))
        .route("/v1/sessions/{session_id}", get(sessions::get_session))
        .route(
            "/v1/sessions/{session_id}/effective-permissions",
            get(sessions::effective_permissions),
        )
        .route(
            "/v1/sessions/{session_id}/accept",
            post(sessions::accept_session),
        )
        .route(
            "/v1/sessions/{session_id}/reject",
            post(sessions::reject_session),
        )
        .route(
            "/v1/sessions/{session_id}/cancel",
            post(sessions::cancel_session),
        )
        .route(
            "/v1/sessions/{session_id}/close",
            post(sessions::close_session),
        )
        .route(
            "/v1/sessions/{session_id}/connection-state",
            post(sessions::connection_state),
        )
        .route("/v1/audit-logs", get(audit::list_audit_logs))
        .route(
            "/internal/v1/signal/device-auth",
            post(internal::signal_device_auth),
        )
        .route(
            "/internal/v1/signal/session-authorize",
            post(internal::signal_session_authorize),
        )
        .route(
            "/internal/v1/relay/authorize",
            post(internal::relay_authorize),
        )
        .fallback(fallback)
        .with_state(state)
}

async fn health(State(state): State<AppState>) -> (StatusCode, Json<Value>) {
    let ephemeral_healthy = state.ephemeral.health().await.is_ok();
    let status = if ephemeral_healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "service": "api-server",
            "status": if ephemeral_healthy { "ok" } else { "degraded" },
            "storage": state.repository.backend_name(),
            "ephemeral_storage": state.ephemeral.backend_name(),
            "postgres_configured": state.config.database_url.is_some(),
            "redis_configured": state.config.redis_url.is_some(),
        })),
    )
}

async fn fallback(Extension(request_id): Extension<RequestId>) -> ApiError {
    ApiError::not_found(
        "route_not_found",
        "the requested route does not exist",
        &request_id.0,
    )
}

pub fn parse_json<T: DeserializeOwned>(body: &Bytes, request_id: &str) -> ApiResult<T> {
    let canonical = canonical_json_bytes_from_slice(body).map_err(|_| {
        ApiError::bad_request(
            "invalid_payload",
            "request body must be valid JSON without duplicate object keys",
            request_id,
        )
    })?;
    serde_json::from_slice(&canonical).map_err(|_| {
        ApiError::bad_request(
            "invalid_payload",
            "request body must match the documented JSON schema",
            request_id,
        )
    })
}

pub async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    request_id: &str,
) -> ApiResult<AccessClaims> {
    let token = bearer(headers, request_id)?;
    let now = now_epoch_millis();
    let claims = verify_access_token(&token, &state.config.token_secret, now)
        .map_err(|_| ApiError::unauthorized(request_id))?;

    let valid = state
        .repository
        .account_session_active(&claims.account_session_id, &claims.account_id, now)
        .await
        .map_err(|_| ApiError::internal(request_id))?;
    if !valid {
        return Err(ApiError::unauthorized(request_id));
    }
    Ok(claims)
}

pub fn authenticate_service(
    state: &AppState,
    headers: &HeaderMap,
    request_id: &str,
) -> ApiResult<()> {
    let token = bearer(headers, request_id)?;
    if token.as_bytes() != state.config.service_token.as_bytes() {
        return Err(ApiError::unauthorized(request_id));
    }
    Ok(())
}

pub async fn verify_signed_device_request(
    state: &AppState,
    claims: &AccessClaims,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    body: &[u8],
    request_id: &str,
) -> ApiResult<Device> {
    let device_id = required_header(headers, "x-rctl-device-id", request_id)?;
    let timestamp = required_header(headers, "x-rctl-timestamp", request_id)?
        .parse::<u64>()
        .map_err(|_| {
            ApiError::bad_request(
                "invalid_device_signature",
                "invalid signature timestamp",
                request_id,
            )
        })?;
    let nonce = required_header(headers, "x-rctl-api-nonce", request_id)?;
    let signature = required_header(headers, "x-rctl-device-signature", request_id)?;
    let now = now_epoch_millis();
    if now.abs_diff(timestamp) > 30_000 {
        return Err(ApiError::forbidden(
            "device_signature_expired",
            "device signature timestamp is outside the 30 second window",
            request_id,
        ));
    }

    let device = state
        .repository
        .load_device_authority(device_id)
        .await
        .map_err(|_| ApiError::internal(request_id))?
        .ok_or_else(|| {
            ApiError::forbidden("unknown_device", "device is not registered", request_id)
        })?;
    if device.account_id != claims.account_id
        || device.public_key_revoked_at_epoch_millis.is_some()
        || !device.status.is_authorizable()
    {
        return Err(ApiError::forbidden(
            "device_not_authorized",
            "device does not belong to this account, is inactive, or its key is revoked",
            request_id,
        ));
    }
    let target = uri
        .path_and_query()
        .map_or(uri.path(), |value| value.as_str());
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok());
    verify_device_signature(
        &device.public_key,
        method.as_str(),
        target,
        body,
        content_type,
        request_id,
        device_id,
        &claims.account_id,
        timestamp,
        nonce,
        signature,
    )
    .map_err(|_| {
        ApiError::forbidden(
            "invalid_device_signature",
            "device signature verification failed",
            request_id,
        )
    })?;

    let nonce_key = format!("{}:{}:{}", claims.account_id, device_id, nonce);
    let recorded = state
        .ephemeral
        .record_nonce(&nonce_key, now, 60_000)
        .await
        .map_err(|_| ApiError::internal(request_id))?;
    if !recorded {
        return Err(ApiError::conflict(
            "device_nonce_replayed",
            "device request nonce has already been used",
            request_id,
        ));
    }
    Ok(device)
}

#[allow(clippy::too_many_arguments)]
pub async fn audit(
    state: &AppState,
    request_id: &str,
    actor_type: &str,
    actor_account_id: Option<&str>,
    actor_device_id: Option<&str>,
    actor_role: Option<&str>,
    target_device_id: Option<&str>,
    session_id: Option<&str>,
    action: &str,
    result: &str,
    reason: Option<&str>,
    metadata: BTreeMap<String, Value>,
) -> ApiResult<()> {
    let entry = AuditEntry {
        audit_id: random_uuid_v4(),
        actor_type: actor_type.to_owned(),
        actor_account_id: actor_account_id.map(ToOwned::to_owned),
        actor_device_id: actor_device_id.map(ToOwned::to_owned),
        actor_role: actor_role.map(ToOwned::to_owned),
        actor_service: None,
        target_device_id: target_device_id.map(ToOwned::to_owned),
        session_id: session_id.map(ToOwned::to_owned),
        action: action.to_owned(),
        result: result.to_owned(),
        reason: reason.map(ToOwned::to_owned),
        metadata,
        request_id: request_id.to_owned(),
        created_at_epoch_millis: now_epoch_millis(),
    };
    state
        .repository
        .transact(&mut |database| {
            database.audit_logs.push(entry.clone());
            Ok(())
        })
        .await
        .map_err(|_| ApiError::internal(request_id))
}

fn required_header<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
    request_id: &str,
) -> ApiResult<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::BAD_REQUEST,
                "missing_device_signature_header",
                format!("missing required header {name}"),
                request_id,
            )
        })
}
