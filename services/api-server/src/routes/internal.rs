use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::{ApiError, ApiResult};
use crate::security::{encode_public_key, now_epoch_millis, verify_access_token};
use crate::{AppState, RequestId};

use super::{authenticate_service, parse_json};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignalDeviceAuthRequest {
    access_token: String,
    account_id: String,
    device_id: String,
    public_key_id: String,
    public_key_version: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionAuthorizeRequest {
    account_id: String,
    device_id: String,
    session_id: String,
    role: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayAuthorizeRequest {
    session_id: String,
    device_id: String,
    role: String,
    permissions_digest: String,
    relay_token_epoch: u64,
}

pub async fn signal_device_auth(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    authenticate_service(&state, &headers, &request_id.0)?;
    let request: SignalDeviceAuthRequest = parse_json(&body, &request_id.0)?;
    let now = now_epoch_millis();
    let claims = verify_access_token(&request.access_token, &state.config.token_secret, now)
        .map_err(|_| ApiError::unauthorized(&request_id.0))?;
    if claims.account_id != request.account_id {
        return Err(ApiError::forbidden(
            "account_mismatch",
            "access token account does not match the handshake account",
            &request_id.0,
        ));
    }
    let authority = state
        .repository
        .load_signal_device_authority(
            &claims.account_session_id,
            &claims.account_id,
            &request.device_id,
            now,
        )
        .await
        .map_err(|_| ApiError::internal(&request_id.0))?;
    let Some((session_valid, device)) = authority else {
        return Err(ApiError::forbidden(
            "unknown_device",
            "device is not registered",
            &request_id.0,
        ));
    };
    if !session_valid {
        return Err(ApiError::unauthorized(&request_id.0));
    }
    if device.account_id != claims.account_id
        || device.public_key_id != request.public_key_id
        || device.public_key_version != request.public_key_version
        || device.public_key_revoked_at_epoch_millis.is_some()
        || !device.status.is_authorizable()
    {
        return Err(ApiError::forbidden(
            "device_key_mismatch",
            "device ownership or public key version does not match",
            &request_id.0,
        ));
    }
    Ok(Json(json!({
        "authorized": true,
        "account_id": claims.account_id,
        "device_id": device.device_id,
        "public_key": encode_public_key(&device.public_key),
        "public_key_id": device.public_key_id,
        "public_key_version": device.public_key_version,
        "access_token_expires_at_epoch_millis": claims.expires_at_epoch_millis,
    })))
}

pub async fn signal_session_authorize(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    authenticate_service(&state, &headers, &request_id.0)?;
    let request: SessionAuthorizeRequest = parse_json(&body, &request_id.0)?;
    let (session, device) = authorized_participant(
        &state,
        &request.session_id,
        &request.account_id,
        &request.device_id,
        &request.role,
        &request_id.0,
    )
    .await?;
    if !session.status.can_signal() || session.session_expires_at_epoch_millis <= now_epoch_millis()
    {
        return Err(ApiError::forbidden(
            "session_not_connectable",
            "session has not reached an API-authorized connection state",
            &request_id.0,
        ));
    }
    Ok(Json(json!({
        "authorized": true,
        "session_id": session.session_id,
        "status": session.status,
        "controller_device_id": session.controller_device_id,
        "controlled_device_id": session.controlled_device_id,
        "permissions_digest": session.permissions_digest,
        "relay_token_epoch": session.relay_token_epoch,
        "public_key": encode_public_key(&device.public_key),
        "public_key_id": device.public_key_id,
        "public_key_version": device.public_key_version,
    })))
}

pub async fn relay_authorize(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    authenticate_service(&state, &headers, &request_id.0)?;
    let request: RelayAuthorizeRequest = parse_json(&body, &request_id.0)?;
    let (session, device) = state
        .repository
        .load_session_device_authority(&request.session_id, &request.device_id)
        .await
        .map_err(|_| ApiError::internal(&request_id.0))?;
    let session = session.ok_or_else(|| {
        ApiError::not_found("session_not_found", "session was not found", &request_id.0)
    })?;
    let device = device.ok_or_else(|| {
        ApiError::forbidden("unknown_device", "device is not registered", &request_id.0)
    })?;
    let now = now_epoch_millis();
    let role_matches = match request.role.as_str() {
        "controller" => session.controller_device_id == device.device_id,
        "controlled" => session.controlled_device_id == device.device_id,
        _ => false,
    };
    if !role_matches
        || !session.status.can_signal()
        || session.session_expires_at_epoch_millis <= now
        || !session.permissions.allow_relay
        || session.permissions_digest != request.permissions_digest
        || session.relay_token_epoch != request.relay_token_epoch
        || device.public_key_revoked_at_epoch_millis.is_some()
        || !device.status.is_authorizable()
    {
        return Err(ApiError::forbidden(
            "relay_not_authorized",
            "relay binding, session state, permission, epoch, or device key is invalid",
            &request_id.0,
        ));
    }
    Ok(Json(json!({
        "authorized": true,
        "session_id": session.session_id,
        "role": request.role,
        "controller_device_id": session.controller_device_id,
        "controlled_device_id": session.controlled_device_id,
        "permissions_digest": session.permissions_digest,
        "relay_token_epoch": session.relay_token_epoch,
        "authorization_expires_at_epoch_millis": session
            .session_expires_at_epoch_millis
            .min(now.saturating_add(60_000)),
        "device_public_key": encode_public_key(&device.public_key),
        "device_public_key_id": device.public_key_id,
        "device_public_key_version": device.public_key_version,
    })))
}

async fn authorized_participant(
    state: &AppState,
    session_id: &str,
    account_id: &str,
    device_id: &str,
    role: &str,
    request_id: &str,
) -> ApiResult<(crate::Session, crate::Device)> {
    let (session, device) = state
        .repository
        .load_session_device_authority(session_id, device_id)
        .await
        .map_err(|_| ApiError::internal(request_id))?;
    let session = session.ok_or_else(|| {
        ApiError::not_found("session_not_found", "session was not found", request_id)
    })?;
    let device = device.ok_or_else(|| {
        ApiError::forbidden("unknown_device", "device is not registered", request_id)
    })?;
    let matches = device.account_id == account_id
        && match role {
            "controller" => {
                session.controller_account_id == account_id
                    && session.controller_device_id == device_id
            }
            "controlled" => session.controlled_device_id == device_id,
            _ => false,
        };
    if !matches
        || device.public_key_revoked_at_epoch_millis.is_some()
        || !device.status.is_authorizable()
    {
        return Err(ApiError::forbidden(
            "session_participant_mismatch",
            "account, device, role, or public key does not match the session",
            request_id,
        ));
    }
    Ok((session, device))
}
