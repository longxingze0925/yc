use std::collections::BTreeMap;

use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::ephemeral::{DevicePresence, DevicePresenceStatus, StepUpConsumption};
use crate::error::{ApiError, ApiResult};
use crate::model::{
    Architecture, AuditEntry, Device, DeviceCapabilities, DeviceLifecycleStatus, DeviceStatus,
    DeviceView, Platform, SessionEvent, SessionView,
};
use crate::security::{
    decode_public_key, device_registration_binding_hash, hex_encode, now_epoch_millis,
    random_uuid_v4, sha256, verify_device_signature, verify_new_device_key_proof,
};
use crate::store::{
    DeviceKeyRotation, DeviceManagementAction, DeviceManagementCommand, DeviceManagementOutcome,
    DeviceRegistrationCommand, DeviceRegistrationOutcome, InitialDeviceSignatureProof, StoreError,
};
use crate::{AppState, RequestId};

use super::{authenticate, parse_json};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterDeviceRequest {
    device_enrollment_grant: Option<String>,
    device_id: String,
    display_name: String,
    platform: Platform,
    os_version: String,
    arch: Architecture,
    role_capabilities: DeviceCapabilities,
    public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateDeviceKeyRequest {
    current_public_key_id: String,
    current_public_key_version: u32,
    new_public_key: String,
    new_public_key_proof: String,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DeviceActionRequest {
    Disable,
    Restore,
    Unbind,
    RevokePublicKey,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateDeviceRequest {
    display_name: Option<String>,
    action: Option<DeviceActionRequest>,
}

pub async fn register_device(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<DeviceView>)> {
    let claims = authenticate(&state, &headers, &request_id.0).await?;
    let request: RegisterDeviceRequest = parse_json(&body, &request_id.0)?;
    validate_device_request(&request, &request_id.0)?;
    let enrollment_grant = request.device_enrollment_grant.as_deref().ok_or_else(|| {
        ApiError::bad_request(
            "device_enrollment_grant_required",
            "device_enrollment_grant is required",
            &request_id.0,
        )
    })?;
    let (grant_id, grant_secret) = parse_enrollment_grant(enrollment_grant, &request_id.0)?;
    let public_key = decode_public_key(&request.public_key).map_err(|_| {
        ApiError::bad_request(
            "invalid_public_key",
            "public_key must encode exactly 32 Ed25519 bytes",
            &request_id.0,
        )
    })?;
    let signature_proof = verify_initial_device_signature(
        &state,
        &claims.account_id,
        &request.device_id,
        &public_key,
        &uri,
        &headers,
        &body,
        &request_id.0,
    )
    .await?;

    let capabilities = match request.platform {
        Platform::Ios => DeviceCapabilities {
            controller: true,
            controlled: false,
            file_transfer: false,
            unattended: false,
        },
        _ => DeviceCapabilities {
            controller: true,
            controlled: request.role_capabilities.controlled,
            file_transfer: false,
            unattended: false,
        },
    };
    let created_at_epoch_millis = now_epoch_millis();
    let device = Device {
        device_id: request.device_id.clone(),
        account_id: claims.account_id.clone(),
        display_name: request.display_name.trim().to_owned(),
        platform: request.platform,
        os_version: request.os_version.trim().to_owned(),
        arch: request.arch,
        capabilities,
        public_key_id: random_uuid_v4(),
        public_key,
        public_key_version: 1,
        public_key_revoked_at_epoch_millis: None,
        status: DeviceLifecycleStatus::Offline,
        last_seen_epoch_millis: None,
        created_at_epoch_millis,
        updated_at_epoch_millis: created_at_epoch_millis,
    };
    let registration_request_binding_hash = device_registration_binding_hash(
        &claims.account_id,
        &claims.account_session_id,
        grant_id,
        &device.device_id,
        &device.display_name,
        platform_name(&device.platform),
        &device.os_version,
        architecture_name(&device.arch),
        device.capabilities.controller,
        device.capabilities.controlled,
        device.capabilities.file_transfer,
        device.capabilities.unattended,
        &sha256(&device.public_key),
        remote_protocol::PROTOCOL_VERSION,
    );
    let registration_audit_entry = AuditEntry {
        audit_id: random_uuid_v4(),
        actor_type: "device".to_owned(),
        actor_account_id: Some(claims.account_id.clone()),
        actor_device_id: Some(device.device_id.clone()),
        actor_role: Some("none".to_owned()),
        actor_service: None,
        target_device_id: Some(device.device_id.clone()),
        session_id: None,
        action: "device_registered".to_owned(),
        result: "success".to_owned(),
        reason: None,
        metadata: BTreeMap::new(),
        request_id: request_id.0.clone(),
        created_at_epoch_millis,
    };
    let grant_audit_entry = AuditEntry {
        audit_id: random_uuid_v4(),
        actor_type: "device".to_owned(),
        actor_account_id: Some(claims.account_id.clone()),
        actor_device_id: Some(device.device_id.clone()),
        actor_role: Some("none".to_owned()),
        actor_service: None,
        target_device_id: Some(device.device_id.clone()),
        session_id: None,
        action: "device_enrollment_grant_consumed".to_owned(),
        result: "success".to_owned(),
        reason: None,
        metadata: BTreeMap::new(),
        request_id: request_id.0.clone(),
        created_at_epoch_millis,
    };
    let trusted_device_audit_entry = AuditEntry {
        audit_id: random_uuid_v4(),
        actor_type: "device".to_owned(),
        actor_account_id: Some(claims.account_id.clone()),
        actor_device_id: Some(device.device_id.clone()),
        actor_role: Some("none".to_owned()),
        actor_service: None,
        target_device_id: Some(device.device_id.clone()),
        session_id: None,
        action: "trusted_device_added".to_owned(),
        result: "success".to_owned(),
        reason: None,
        metadata: BTreeMap::new(),
        request_id: request_id.0.clone(),
        created_at_epoch_millis,
    };
    let outcome = state
        .repository
        .register_device(&DeviceRegistrationCommand {
            grant_id: grant_id.to_owned(),
            grant_secret_hash: sha256(grant_secret.as_bytes()),
            account_id: claims.account_id.clone(),
            account_session_id: claims.account_session_id,
            protocol_version: remote_protocol::PROTOCOL_VERSION,
            registration_request_binding_hash,
            device: device.clone(),
            trusted_device_id: Some(random_uuid_v4()),
            registration_audit_entry,
            grant_audit_entry,
            trusted_device_audit_entry: Some(trusted_device_audit_entry),
            signature_proof,
            now_epoch_millis: created_at_epoch_millis,
        })
        .await
        .map_err(|error| match error {
            StoreError::Conflict => ApiError::conflict(
                "device_registration_conflict",
                "device registration conflicts with existing authority state",
                &request_id.0,
            ),
            StoreError::Unavailable => ApiError::internal(&request_id.0),
        })?;
    match outcome {
        DeviceRegistrationOutcome::Created(device) => {
            Ok((StatusCode::CREATED, Json(DeviceView::from(&device))))
        }
        DeviceRegistrationOutcome::Replayed(device) => {
            Ok((StatusCode::OK, Json(DeviceView::from(&device))))
        }
        DeviceRegistrationOutcome::InvalidGrant => Err(ApiError::forbidden(
            "device_enrollment_grant_invalid",
            "device enrollment grant is invalid, expired, consumed, or does not match",
            &request_id.0,
        )),
    }
}

pub async fn list_devices(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let claims = authenticate(&state, &headers, &request_id.0).await?;
    let presences = state
        .ephemeral
        .list_device_presence(&claims.account_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|presence| (presence.device_id.clone(), presence))
        .collect::<BTreeMap<_, _>>();
    let devices = state
        .repository
        .list_devices_for_account(&claims.account_id)
        .await
        .map_err(|_| ApiError::internal(&request_id.0))?
        .iter()
        .map(|device| {
            let presence = presences.get(&device.device_id);
            device_view_with_presence(device, presence)
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({ "devices": devices })))
}

pub async fn get_device(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(device_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<DeviceView>> {
    let claims = authenticate(&state, &headers, &request_id.0).await?;
    let presences = state
        .ephemeral
        .list_device_presence(&claims.account_id)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|presence| (presence.device_id.clone(), presence))
        .collect::<BTreeMap<_, _>>();
    let device = state
        .repository
        .load_device_authority(&device_id)
        .await
        .map_err(|_| ApiError::internal(&request_id.0))?
        .filter(|device| device.account_id == claims.account_id)
        .ok_or_else(|| {
            ApiError::not_found("device_not_found", "device was not found", &request_id.0)
        })?;
    let presence = presences.get(&device.device_id);
    Ok(Json(device_view_with_presence(&device, presence)))
}

pub async fn update_device(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(device_id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<DeviceView>> {
    let claims = authenticate(&state, &headers, &request_id.0).await?;
    let request: UpdateDeviceRequest = parse_json(&body, &request_id.0)?;
    let display_name = request.display_name.map(|value| value.trim().to_owned());
    if display_name.is_some() == request.action.is_some()
        || display_name
            .as_deref()
            .is_some_and(|value| value.is_empty() || value.len() > 100)
    {
        return Err(ApiError::bad_request(
            "invalid_device_update",
            "provide exactly one valid display_name or action",
            &request_id.0,
        ));
    }
    let actor = super::verify_signed_device_request(
        &state,
        &claims,
        &headers,
        &method,
        &uri,
        &body,
        &request_id.0,
    )
    .await?;
    let target = state
        .repository
        .load_device_authority(&device_id)
        .await
        .map_err(|_| ApiError::internal(&request_id.0))?
        .filter(|device| device.account_id == claims.account_id)
        .ok_or_else(|| {
            ApiError::not_found("device_not_found", "device was not found", &request_id.0)
        })?;
    let action = request.action.map(|action| match action {
        DeviceActionRequest::Disable => DeviceManagementAction::Disable,
        DeviceActionRequest::Restore => DeviceManagementAction::Restore,
        DeviceActionRequest::Unbind => DeviceManagementAction::Unbind,
        DeviceActionRequest::RevokePublicKey => DeviceManagementAction::RevokePublicKey,
    });
    let now = now_epoch_millis();
    let mut metadata = BTreeMap::new();
    if let Some(name) = &display_name {
        metadata.insert(
            "change".to_owned(),
            Value::String("display_name".to_owned()),
        );
        metadata.insert(
            "display_name_changed".to_owned(),
            Value::Bool(!name.is_empty()),
        );
    }
    if let Some(action) = action {
        metadata.insert(
            "lifecycle_action".to_owned(),
            Value::String(device_management_action_name(action).to_owned()),
        );
    }
    let audit_action = match action {
        Some(DeviceManagementAction::Unbind) => "device_unregistered",
        Some(DeviceManagementAction::RevokePublicKey) => {
            metadata.insert(
                "old_public_key_id".to_owned(),
                Value::String(target.public_key_id.clone()),
            );
            metadata.insert(
                "old_public_key_version".to_owned(),
                Value::from(target.public_key_version),
            );
            metadata.insert(
                "old_public_key_fingerprint".to_owned(),
                Value::String(hex_encode(&sha256(&target.public_key))),
            );
            metadata.insert("revoked_at_epoch_millis".to_owned(), Value::from(now));
            metadata.insert(
                "revocation_reason".to_owned(),
                Value::String("user_requested".to_owned()),
            );
            "device_public_key_revoked"
        }
        _ => "device_status_changed",
    };
    let outcome = state
        .repository
        .manage_device(&DeviceManagementCommand {
            account_id: claims.account_id.clone(),
            actor_device_id: actor.device_id.clone(),
            actor_public_key_id: actor.public_key_id.clone(),
            actor_public_key_version: actor.public_key_version,
            target_device_id: device_id.clone(),
            expected_target_public_key_id: target.public_key_id.clone(),
            expected_target_public_key_version: target.public_key_version,
            display_name,
            action,
            audit_entry: AuditEntry {
                audit_id: random_uuid_v4(),
                actor_type: "device".to_owned(),
                actor_account_id: Some(claims.account_id),
                actor_device_id: Some(actor.device_id),
                actor_role: Some("none".to_owned()),
                actor_service: None,
                target_device_id: Some(device_id),
                session_id: None,
                action: audit_action.to_owned(),
                result: "success".to_owned(),
                reason: None,
                metadata,
                request_id: request_id.0.clone(),
                created_at_epoch_millis: now,
            },
            now_epoch_millis: now,
        })
        .await
        .map_err(|error| match error {
            StoreError::Conflict => ApiError::conflict(
                "device_update_conflict",
                "device authority changed while applying the update",
                &request_id.0,
            ),
            StoreError::Unavailable => ApiError::internal(&request_id.0),
        })?;
    match outcome {
        DeviceManagementOutcome::Updated(change) => {
            notify_forced_session_closures(&state, &change.closed_session_events).await;
            Ok(Json(DeviceView::from(change.device.as_ref())))
        }
        DeviceManagementOutcome::NotFound => Err(ApiError::not_found(
            "device_not_found",
            "device was not found",
            &request_id.0,
        )),
        DeviceManagementOutcome::InvalidTransition => Err(ApiError::conflict(
            "invalid_device_transition",
            "the requested device lifecycle transition is not allowed",
            &request_id.0,
        )),
    }
}

pub async fn rotate_device_key(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(device_id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<DeviceView>> {
    let claims = authenticate(&state, &headers, &request_id.0).await?;
    let request: RotateDeviceKeyRequest = parse_json(&body, &request_id.0)?;
    let signed_device = super::verify_signed_device_request(
        &state,
        &claims,
        &headers,
        &method,
        &uri,
        &body,
        &request_id.0,
    )
    .await?;
    if signed_device.device_id != device_id
        || signed_device.public_key_id != request.current_public_key_id
        || signed_device.public_key_version != request.current_public_key_version
    {
        return Err(ApiError::forbidden(
            "current_device_key_mismatch",
            "the signed device and current public key fields must match",
            &request_id.0,
        ));
    }
    let now = now_epoch_millis();
    let new_public_key = decode_public_key(&request.new_public_key).map_err(|_| {
        ApiError::bad_request(
            "invalid_public_key",
            "new_public_key must encode exactly 32 Ed25519 bytes",
            &request_id.0,
        )
    })?;
    if new_public_key == signed_device.public_key {
        return Err(ApiError::bad_request(
            "unchanged_public_key",
            "new_public_key must differ from the current key",
            &request_id.0,
        ));
    }
    verify_new_device_key_proof(
        &new_public_key,
        &claims.account_id,
        &device_id,
        &request.current_public_key_id,
        request.current_public_key_version,
        &request.new_public_key_proof,
    )
    .map_err(|_| {
        ApiError::forbidden(
            "new_device_key_proof_failed",
            "proof of possession for the new device key failed",
            &request_id.0,
        )
    })?;

    let step_up = super::mfa::validate_step_up_for_request(
        &state,
        &claims,
        &headers,
        &method,
        &uri,
        &body,
        Some(&device_id),
        "device_key_rotation",
        &request_id.0,
    )
    .await?;
    let new_public_key_id = random_uuid_v4();
    let new_public_key_version =
        signed_device
            .public_key_version
            .checked_add(1)
            .ok_or_else(|| {
                ApiError::conflict(
                    "device_key_version_exhausted",
                    "the device public key version cannot be incremented",
                    &request_id.0,
                )
            })?;
    let old_fingerprint = hex_encode(&sha256(&signed_device.public_key));
    let new_fingerprint = hex_encode(&sha256(&new_public_key));
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "old_public_key_id".to_owned(),
        Value::String(request.current_public_key_id.clone()),
    );
    metadata.insert(
        "old_public_key_version".to_owned(),
        Value::from(request.current_public_key_version),
    );
    metadata.insert(
        "old_public_key_fingerprint".to_owned(),
        Value::String(old_fingerprint.clone()),
    );
    metadata.insert(
        "new_public_key_id".to_owned(),
        Value::String(new_public_key_id.clone()),
    );
    metadata.insert(
        "new_public_key_version".to_owned(),
        Value::from(new_public_key_version),
    );
    metadata.insert(
        "new_public_key_fingerprint".to_owned(),
        Value::String(new_fingerprint.clone()),
    );
    metadata.insert("revoked_at_epoch_millis".to_owned(), Value::from(now));
    metadata.insert(
        "rotation_reason".to_owned(),
        Value::String("user_requested".to_owned()),
    );
    metadata.insert(
        "step_up_challenge_id".to_owned(),
        Value::String(step_up.challenge_id.clone()),
    );
    let change = state
        .repository
        .rotate_device_key(&DeviceKeyRotation {
            step_up: step_up.clone(),
            current_public_key_id: request.current_public_key_id.clone(),
            current_public_key_version: request.current_public_key_version,
            new_public_key_id: new_public_key_id.clone(),
            new_public_key,
            new_public_key_version,
            audit_entry: AuditEntry {
                audit_id: random_uuid_v4(),
                actor_type: "device".to_owned(),
                actor_account_id: Some(claims.account_id.clone()),
                actor_device_id: Some(device_id.clone()),
                actor_role: Some("none".to_owned()),
                actor_service: None,
                target_device_id: Some(device_id.clone()),
                session_id: None,
                action: "device_public_key_rotated".to_owned(),
                result: "success".to_owned(),
                reason: None,
                metadata,
                request_id: request_id.0.clone(),
                created_at_epoch_millis: now,
            },
        })
        .await
        .map_err(|error| match error {
            StoreError::Conflict => ApiError::conflict(
                "device_key_rotation_conflict",
                "current key changed or the step-up token was already consumed",
                &request_id.0,
            ),
            StoreError::Unavailable => ApiError::internal(&request_id.0),
        })?;
    let operation_binding_hash = hex_encode(&step_up.operation_binding_hash);
    let _ = state
        .ephemeral
        .consume_step_up(
            &StepUpConsumption {
                challenge_id: &step_up.challenge_id,
                account_id: &step_up.account_id,
                device_id: &step_up.device_id,
                purpose: &step_up.purpose,
                operation_binding_hash: &operation_binding_hash,
            },
            step_up.now_epoch_millis,
        )
        .await;
    notify_forced_session_closures(&state, &change.closed_session_events).await;
    Ok(Json(DeviceView::from(change.device.as_ref())))
}

async fn notify_forced_session_closures(state: &AppState, events: &[SessionEvent]) {
    for event in events {
        let Some(session) = event.result_session.as_ref() else {
            continue;
        };
        let notification = json!({
            "type": "session_close_ack",
            "session_id": session.session_id,
            "status": session.status,
            "actor_type": "system",
            "actor_device_id": null,
            "actor_role": null,
            "actor_service": null,
            "reason": event.reason,
            "event_id": event.event_id,
            "session": SessionView::from(session),
        });
        state
            .notifier
            .push(&session.controller_device_id, notification.clone())
            .await;
        state
            .notifier
            .push(&session.controlled_device_id, notification)
            .await;
    }
}

fn validate_device_request(request: &RegisterDeviceRequest, request_id: &str) -> ApiResult<()> {
    if request.device_id.is_empty()
        || request.device_id.len() > 128
        || !request
            .device_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ApiError::bad_request(
            "invalid_device_id",
            "device_id must contain 1 to 128 ASCII letters, digits, '-' or '_'",
            request_id,
        ));
    }
    if request.display_name.trim().is_empty()
        || request.display_name.len() > 100
        || request.os_version.trim().is_empty()
        || request.os_version.len() > 100
    {
        return Err(ApiError::bad_request(
            "invalid_device_metadata",
            "display_name and os_version must contain 1 to 100 characters",
            request_id,
        ));
    }
    if !request.role_capabilities.controller
        || request.role_capabilities.file_transfer
        || request.role_capabilities.unattended
        || (request.platform == Platform::Ios && request.role_capabilities.controlled)
    {
        return Err(ApiError::bad_request(
            "invalid_platform_capability",
            "registration capabilities do not match the platform enrollment policy",
            request_id,
        ));
    }
    Ok(())
}

fn device_view_with_presence(device: &Device, presence: Option<&DevicePresence>) -> DeviceView {
    let mut view = DeviceView::from(device);
    if device.status.is_authorizable() {
        if let Some(presence) = presence {
            view.status = match presence.status {
                DevicePresenceStatus::Online => DeviceStatus::Online,
                DevicePresenceStatus::Busy => DeviceStatus::Busy,
            };
        }
    }
    view
}

#[allow(clippy::too_many_arguments)]
async fn verify_initial_device_signature(
    state: &AppState,
    account_id: &str,
    device_id: &str,
    public_key: &[u8; 32],
    uri: &Uri,
    headers: &HeaderMap,
    body: &[u8],
    request_id: &str,
) -> ApiResult<InitialDeviceSignatureProof> {
    let signed_device_id = header(headers, "x-rctl-device-id", request_id)?;
    if signed_device_id != device_id {
        return Err(ApiError::forbidden(
            "device_signature_mismatch",
            "signed device_id does not match request body",
            request_id,
        ));
    }
    let timestamp = header(headers, "x-rctl-timestamp", request_id)?
        .parse::<u64>()
        .map_err(|_| {
            ApiError::bad_request("invalid_device_signature", "invalid timestamp", request_id)
        })?;
    let now = now_epoch_millis();
    if now.abs_diff(timestamp) > 30_000 {
        return Err(ApiError::forbidden(
            "device_signature_expired",
            "device signature timestamp is outside the 30 second window",
            request_id,
        ));
    }
    let nonce = header(headers, "x-rctl-api-nonce", request_id)?;
    let signature = header(headers, "x-rctl-device-signature", request_id)?;
    let target = uri
        .path_and_query()
        .map_or(uri.path(), |value| value.as_str())
        .to_owned();
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    verify_device_signature(
        public_key,
        "POST",
        &target,
        body,
        content_type.as_deref(),
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

    let nonce_key = format!("{account_id}:{device_id}:{nonce}");
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
    Ok(InitialDeviceSignatureProof {
        target,
        content_type,
        request_id: request_id.to_owned(),
        timestamp_epoch_millis: timestamp,
        nonce: nonce.to_owned(),
        signature: signature.to_owned(),
        canonical_body: body.to_vec(),
    })
}

fn platform_name(platform: &Platform) -> &'static str {
    match platform {
        Platform::Windows => "windows",
        Platform::Ubuntu => "ubuntu",
        Platform::Ios => "ios",
    }
}

fn architecture_name(architecture: &Architecture) -> &'static str {
    match architecture {
        Architecture::X86_64 => "x86_64",
        Architecture::Aarch64 => "aarch64",
    }
}

fn device_management_action_name(action: DeviceManagementAction) -> &'static str {
    match action {
        DeviceManagementAction::Disable => "disable",
        DeviceManagementAction::Restore => "restore",
        DeviceManagementAction::Unbind => "unbind",
        DeviceManagementAction::RevokePublicKey => "revoke_public_key",
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &'static str, request_id: &str) -> ApiResult<&'a str> {
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

fn parse_enrollment_grant<'a>(value: &'a str, request_id: &str) -> ApiResult<(&'a str, &'a str)> {
    let (grant_id, grant_secret) = value.split_once('.').ok_or_else(|| {
        ApiError::bad_request(
            "device_enrollment_grant_required",
            "device_enrollment_grant must contain a grant id and secret",
            request_id,
        )
    })?;
    if grant_id.is_empty()
        || grant_secret.is_empty()
        || grant_id.len() > 128
        || grant_secret.len() > 128
        || !grant_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        || !grant_secret
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(ApiError::bad_request(
            "device_enrollment_grant_required",
            "device_enrollment_grant is malformed",
            request_id,
        ));
    }
    Ok((grant_id, grant_secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(status: DeviceLifecycleStatus) -> Device {
        Device {
            device_id: "device-1".to_owned(),
            account_id: "account-1".to_owned(),
            display_name: "Ubuntu".to_owned(),
            platform: Platform::Ubuntu,
            os_version: "26.04".to_owned(),
            arch: Architecture::X86_64,
            capabilities: DeviceCapabilities {
                controller: true,
                controlled: true,
                file_transfer: false,
                unattended: false,
            },
            public_key_id: "key-1".to_owned(),
            public_key: [7; 32],
            public_key_version: 1,
            public_key_revoked_at_epoch_millis: None,
            status,
            last_seen_epoch_millis: None,
            created_at_epoch_millis: 1,
            updated_at_epoch_millis: 1,
        }
    }

    #[test]
    fn presence_overlays_active_devices_but_not_management_blocks() {
        let presence = DevicePresence {
            device_id: "device-1".to_owned(),
            status: DevicePresenceStatus::Busy,
            last_seen_epoch_millis: 10,
        };

        assert_eq!(
            device_view_with_presence(&device(DeviceLifecycleStatus::Offline), Some(&presence))
                .status,
            DeviceStatus::Busy
        );
        for status in [
            DeviceLifecycleStatus::Suspended,
            DeviceLifecycleStatus::Disabled,
            DeviceLifecycleStatus::Unbound,
        ] {
            assert_eq!(
                device_view_with_presence(&device(status), Some(&presence)).status,
                DeviceStatus::Offline
            );
        }
    }

    #[test]
    fn registration_capabilities_must_match_enrollment_policy() {
        let request =
            |platform, controller, controlled, file_transfer, unattended| RegisterDeviceRequest {
                device_enrollment_grant: Some("grant.secret".to_owned()),
                device_id: "device-1".to_owned(),
                display_name: "Device".to_owned(),
                platform,
                os_version: "26.04".to_owned(),
                arch: Architecture::X86_64,
                role_capabilities: DeviceCapabilities {
                    controller,
                    controlled,
                    file_transfer,
                    unattended,
                },
                public_key: "unused".to_owned(),
            };

        assert!(validate_device_request(
            &request(Platform::Ubuntu, true, true, false, false),
            "request"
        )
        .is_ok());
        for invalid in [
            request(Platform::Ubuntu, false, true, false, false),
            request(Platform::Ubuntu, true, true, true, false),
            request(Platform::Ubuntu, true, true, false, true),
            request(Platform::Ios, true, true, false, false),
        ] {
            let error = validate_device_request(&invalid, "request").unwrap_err();
            assert_eq!(error.code, "invalid_platform_capability");
        }
    }
}
