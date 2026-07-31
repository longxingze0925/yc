use std::collections::BTreeMap;

use axum::body::Bytes;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::Json;
use remote_protocol::{canonical_idempotency_binding_bytes, canonical_request_target};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::error::{ApiError, ApiResult};
use crate::model::{
    AuditEntry, AuthMethod, Device, IdempotencyRecord, PolicyEvaluation, Session, SessionEvent,
    SessionPermissions, SessionStatus, SessionView,
};
use crate::security::{
    canonical_request_body_hash, hex_encode, now_epoch_millis, permissions_digest, random_uuid_v4,
    sha256_hex,
};
use crate::store::{
    CreateSessionCommand, CreateSessionOutcome, StoreError, TransitionSessionCommand,
    TransitionSessionOutcome,
};
use crate::{AppState, RequestId};

use super::{authenticate, parse_json, verify_signed_device_request};

const SESSION_AUTH_TTL_MILLIS: u64 = 5 * 60 * 1_000;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSessionRequest {
    controller_device_id: String,
    controlled_device_id: String,
    auth_method: AuthMethod,
    requested_permissions: SessionPermissions,
    idempotency_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionActionRequest {
    actor_type: String,
    actor_device_id: String,
    actor_role: String,
    idempotency_key: String,
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionStateRequest {
    actor_type: String,
    actor_device_id: String,
    actor_role: String,
    idempotency_key: String,
    state: SessionStatus,
    reason: Option<String>,
}

pub async fn create_session(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let claims = authenticate(&state, &headers, &request_id.0).await?;
    let request: CreateSessionRequest = parse_json(&body, &request_id.0)?;
    validate_idempotency_key(&request.idempotency_key, &request_id.0)?;
    let controller = verify_signed_device_request(
        &state,
        &claims,
        &headers,
        &method,
        &uri,
        &body,
        &request_id.0,
    )
    .await?;
    if controller.device_id != request.controller_device_id || !controller.capabilities.controller {
        return Err(ApiError::forbidden(
            "controller_not_authorized",
            "the signed device must match controller_device_id and support controller mode",
            &request_id.0,
        ));
    }
    if request.controller_device_id == request.controlled_device_id {
        return Err(ApiError::bad_request(
            "invalid_session_pair",
            "controller and controlled devices must be different",
            &request_id.0,
        ));
    }

    let controlled = state
        .repository
        .load_device_authority(&request.controlled_device_id)
        .await
        .map_err(|_| ApiError::internal(&request_id.0))?
        .ok_or_else(|| {
            ApiError::not_found(
                "controlled_device_not_found",
                "the controlled device does not exist",
                &request_id.0,
            )
        })?;
    if !controlled.status.is_authorizable() {
        return Err(ApiError::forbidden(
            "controlled_device_inactive",
            "the target device is suspended, disabled, or unbound",
            &request_id.0,
        ));
    }
    if request.auth_method == AuthMethod::AccountPrompt
        && controlled.account_id != claims.account_id
    {
        return Err(ApiError::not_found(
            "controlled_device_not_found",
            "the controlled device does not exist",
            &request_id.0,
        ));
    }
    if !controlled.capabilities.controlled {
        return Err(ApiError::forbidden(
            "controlled_capability_disabled",
            "the target device does not allow remote control",
            &request_id.0,
        ));
    }
    if !request.requested_permissions.remote_desktop {
        return Err(ApiError::bad_request(
            "remote_desktop_required",
            "remote_desktop permission is required for a control session",
            &request_id.0,
        ));
    }

    let request_binding = canonical_request_binding(
        &claims.account_id,
        &controller.device_id,
        &method,
        &uri,
        &body,
        &headers,
        &request_id.0,
    )?;
    let idempotency_key = idempotency_storage_key(
        &claims.account_id,
        &controller.device_id,
        method.as_str(),
        &request_binding.target,
        &request.idempotency_key,
    );
    let now = now_epoch_millis();
    let mut permissions = request.requested_permissions;
    permissions.unattended &= request.auth_method == AuthMethod::Unattended;
    // V1 policy storage is not wired yet. Privileged local-protection capabilities fail closed.
    permissions.privacy_screen = false;
    permissions.block_local_input = false;
    permissions.require_prompt = request.auth_method != AuthMethod::Unattended
        || request.requested_permissions.require_prompt;
    let status = match request.auth_method {
        AuthMethod::AccountPrompt => SessionStatus::WaitingApproval,
        AuthMethod::TemporaryCode => SessionStatus::PendingCodeVerification,
        AuthMethod::Unattended => SessionStatus::PendingUnattendedVerification,
    };
    let session = Session {
        session_id: random_uuid_v4(),
        controller_account_id: claims.account_id.clone(),
        controller_device_id: controller.device_id.clone(),
        controlled_device_id: controlled.device_id.clone(),
        auth_method: request.auth_method,
        status,
        permissions,
        permissions_digest: permissions_digest(&permissions),
        policy_evaluation_id: random_uuid_v4(),
        relay_token_epoch: 1,
        session_expires_at_epoch_millis: now + SESSION_AUTH_TTL_MILLIS,
        created_at_epoch_millis: now,
        updated_at_epoch_millis: now,
        ended_at_epoch_millis: None,
    };
    let event = new_event(
        &session,
        "invite_created",
        None,
        status,
        &claims.account_id,
        &controller.device_id,
        "controller",
        None,
        &request.idempotency_key,
        &request_id.0,
    );
    let policy_evaluation = PolicyEvaluation {
        policy_evaluation_id: session.policy_evaluation_id.clone(),
        session_id: session.session_id.clone(),
        account_id: claims.account_id.clone(),
        controller_device_id: controller.device_id.clone(),
        controlled_device_id: controlled.device_id.clone(),
        access_decision: "allow".to_owned(),
        anti_abuse_decision: "allow".to_owned(),
        session_access_decision: if permissions.require_prompt {
            "require_prompt".to_owned()
        } else {
            "allow".to_owned()
        },
        effective_permissions: permissions,
        permissions_digest: session.permissions_digest.clone(),
        evaluated_at_epoch_millis: now,
    };
    let audit_entry = new_session_audit(
        &request_id.0,
        &claims.account_id,
        &controller.device_id,
        "controller",
        &session,
        "session_invited",
        None,
    );
    let outcome = state
        .repository
        .create_session(&CreateSessionCommand {
            storage_key: idempotency_key,
            idempotency: IdempotencyRecord {
                account_id: claims.account_id.clone(),
                device_id: controller.device_id.clone(),
                method: method.as_str().to_ascii_uppercase(),
                path: request_binding.target,
                operation: "create".to_owned(),
                idempotency_key: request.idempotency_key,
                body_hash: request_binding.body_hash,
                request_id: request_id.0.clone(),
                session_id: session.session_id.clone(),
                request_binding_hash: request_binding.digest,
                created_at_epoch_millis: now,
                expires_at_epoch_millis: session.session_expires_at_epoch_millis,
            },
            session: session.clone(),
            event,
            policy_evaluation,
            audit_entry,
        })
        .await
        .map_err(|error| match error {
            StoreError::Conflict => ApiError::conflict(
                "idempotency_conflict",
                "idempotency key was used by another request",
                &request_id.0,
            ),
            StoreError::Unavailable => ApiError::internal(&request_id.0),
        })?;
    match outcome {
        CreateSessionOutcome::Created(created) => {
            state
                .notifier
                .push(
                    &controlled.device_id,
                    json!({ "type": "session_invite", "session": SessionView::from(&created) }),
                )
                .await;
            Ok((
                StatusCode::CREATED,
                Json(session_response(&created, &controlled)),
            ))
        }
        CreateSessionOutcome::Replayed(existing) => Ok((
            StatusCode::OK,
            Json(session_response(&existing, &controlled)),
        )),
        CreateSessionOutcome::BindingMismatch => Err(ApiError::conflict(
            "idempotency_binding_mismatch",
            "idempotency key was already used with a different signed request",
            &request_id.0,
        )),
    }
}

pub async fn get_session(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<SessionView>> {
    let claims = authenticate(&state, &headers, &request_id.0).await?;
    let session =
        authorized_session(&state, &claims.account_id, &session_id, &request_id.0).await?;
    Ok(Json(SessionView::from(&session)))
}

pub async fn effective_permissions(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let claims = authenticate(&state, &headers, &request_id.0).await?;
    let session =
        authorized_session(&state, &claims.account_id, &session_id, &request_id.0).await?;
    Ok(Json(json!({
        "session_id": session.session_id,
        "effective_permissions": session.permissions,
        "permissions_digest": session.permissions_digest,
        "policy_evaluation_id": session.policy_evaluation_id,
    })))
}

pub async fn accept_session(
    state: State<AppState>,
    request_id: Extension<RequestId>,
    path: Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<SessionView>> {
    transition_session(
        state,
        request_id,
        path,
        method,
        uri,
        headers,
        body,
        SessionAction::Accept,
    )
    .await
}

pub async fn reject_session(
    state: State<AppState>,
    request_id: Extension<RequestId>,
    path: Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<SessionView>> {
    transition_session(
        state,
        request_id,
        path,
        method,
        uri,
        headers,
        body,
        SessionAction::Reject,
    )
    .await
}

pub async fn cancel_session(
    state: State<AppState>,
    request_id: Extension<RequestId>,
    path: Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<SessionView>> {
    transition_session(
        state,
        request_id,
        path,
        method,
        uri,
        headers,
        body,
        SessionAction::Cancel,
    )
    .await
}

pub async fn close_session(
    state: State<AppState>,
    request_id: Extension<RequestId>,
    path: Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<SessionView>> {
    transition_session(
        state,
        request_id,
        path,
        method,
        uri,
        headers,
        body,
        SessionAction::Close,
    )
    .await
}

pub async fn connection_state(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(session_id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<SessionView>> {
    let claims = authenticate(&state, &headers, &request_id.0).await?;
    let actor = verify_signed_device_request(
        &state,
        &claims,
        &headers,
        &method,
        &uri,
        &body,
        &request_id.0,
    )
    .await?;
    let request: ConnectionStateRequest = parse_json(&body, &request_id.0)?;
    validate_actor(
        &request.actor_type,
        &request.actor_device_id,
        &actor,
        &request_id.0,
    )?;
    validate_idempotency_key(&request.idempotency_key, &request_id.0)?;
    if !matches!(
        request.state,
        SessionStatus::Connected
            | SessionStatus::Degraded
            | SessionStatus::Reconnecting
            | SessionStatus::Failed
    ) {
        return Err(ApiError::bad_request(
            "invalid_connection_state",
            "connection state must be connected, degraded, reconnecting, or failed",
            &request_id.0,
        ));
    }
    let (event_type, audit_action) = match request.state {
        SessionStatus::Connected => ("connected", "session_connected"),
        SessionStatus::Degraded => ("degraded", "session_degraded"),
        SessionStatus::Reconnecting => ("reconnecting", "session_reconnecting"),
        SessionStatus::Failed => ("failed", "session_failed"),
        _ => unreachable!("connection state was validated above"),
    };
    let request_binding = canonical_request_binding(
        &claims.account_id,
        &actor.device_id,
        &method,
        &uri,
        &body,
        &headers,
        &request_id.0,
    )?;
    let transition = transition_to(
        &state,
        &claims.account_id,
        &actor,
        &request.actor_role,
        &session_id,
        request.state,
        event_type,
        audit_action,
        request.reason.as_deref(),
        &request.idempotency_key,
        &request_binding.digest,
        &request_binding.body_hash,
        method.as_str(),
        &request_binding.target,
        &request_id.0,
    )
    .await?;
    let view = SessionView::from(&transition.session);
    let notification = json!({
        "type": "connection_state",
        "session_id": transition.session.session_id,
        "status": view.status,
        "actor_type": request.actor_type,
        "actor_device_id": actor.device_id,
        "actor_role": request.actor_role,
        "actor_service": null,
        "reason": request.reason,
        "event_id": transition.event_id,
        "session": view,
    });
    notify_session_participants(&state, &transition.session, notification).await;
    Ok(Json(view))
}

#[derive(Debug, Clone, Copy)]
enum SessionAction {
    Accept,
    Reject,
    Cancel,
    Close,
}

impl SessionAction {
    const fn contract(self) -> (SessionStatus, &'static str, &'static str, &'static str) {
        match self {
            Self::Accept => (
                SessionStatus::Accepted,
                "invite_accepted",
                "session_accepted",
                "session_accept_ack",
            ),
            Self::Reject => (
                SessionStatus::Rejected,
                "invite_rejected",
                "session_rejected",
                "session_reject_ack",
            ),
            Self::Cancel => (
                SessionStatus::Cancelled,
                "cancelled",
                "session_cancelled",
                "session_cancel_ack",
            ),
            Self::Close => (
                SessionStatus::Closed,
                "closed",
                "session_ended",
                "session_close_ack",
            ),
        }
    }
}

struct TransitionResult {
    session: Session,
    event_id: String,
}

#[allow(clippy::too_many_arguments)]
async fn transition_session(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(session_id): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    action: SessionAction,
) -> ApiResult<Json<SessionView>> {
    let claims = authenticate(&state, &headers, &request_id.0).await?;
    let actor = verify_signed_device_request(
        &state,
        &claims,
        &headers,
        &method,
        &uri,
        &body,
        &request_id.0,
    )
    .await?;
    let request: SessionActionRequest = parse_json(&body, &request_id.0)?;
    validate_actor(
        &request.actor_type,
        &request.actor_device_id,
        &actor,
        &request_id.0,
    )?;
    validate_idempotency_key(&request.idempotency_key, &request_id.0)?;
    if matches!(
        action,
        SessionAction::Reject | SessionAction::Cancel | SessionAction::Close
    ) && request.reason.as_deref().is_none_or(str::is_empty)
    {
        return Err(ApiError::bad_request(
            "reason_required",
            "reject, cancel, and close require a reason",
            &request_id.0,
        ));
    }
    let (status, event_type, audit_action, notification_type) = action.contract();
    let request_binding = canonical_request_binding(
        &claims.account_id,
        &actor.device_id,
        &method,
        &uri,
        &body,
        &headers,
        &request_id.0,
    )?;
    let transition = transition_to(
        &state,
        &claims.account_id,
        &actor,
        &request.actor_role,
        &session_id,
        status,
        event_type,
        audit_action,
        request.reason.as_deref(),
        &request.idempotency_key,
        &request_binding.digest,
        &request_binding.body_hash,
        method.as_str(),
        &request_binding.target,
        &request_id.0,
    )
    .await?;
    let view = SessionView::from(&transition.session);
    let notification = json!({
        "type": notification_type,
        "session_id": transition.session.session_id,
        "status": view.status,
        "actor_type": request.actor_type,
        "actor_device_id": actor.device_id,
        "actor_role": request.actor_role,
        "actor_service": null,
        "reason": request.reason,
        "event_id": transition.event_id,
        "session": view,
    });
    notify_session_participants(&state, &transition.session, notification).await;
    Ok(Json(view))
}

#[allow(clippy::too_many_arguments)]
async fn transition_to(
    state: &AppState,
    account_id: &str,
    actor: &Device,
    actor_role: &str,
    session_id: &str,
    target: SessionStatus,
    event_type: &str,
    audit_action: &str,
    reason: Option<&str>,
    idempotency_key: &str,
    request_binding_hash: &str,
    request_body_hash: &str,
    request_method: &str,
    request_path: &str,
    request_id: &str,
) -> ApiResult<TransitionResult> {
    let mut session = state
        .repository
        .load_session_authority(session_id)
        .await
        .map_err(|_| ApiError::internal(request_id))?
        .ok_or_else(|| {
            ApiError::not_found("session_not_found", "session was not found", request_id)
        })?;
    let expected_role = participant_role(state, &session, account_id, &actor.device_id)
        .await
        .map_err(|_| ApiError::internal(request_id))?
        .ok_or_else(|| {
            ApiError::forbidden(
                "session_not_authorized",
                "device is not a session participant",
                request_id,
            )
        })?;
    if expected_role != actor_role {
        return Err(ApiError::forbidden(
            "actor_role_mismatch",
            "actor_role does not match the signed session participant",
            request_id,
        ));
    }
    let storage_key = idempotency_storage_key(
        account_id,
        &actor.device_id,
        request_method,
        request_path,
        idempotency_key,
    );
    let validation = validate_transition(
        session.status,
        target,
        expected_role,
        session.permissions.require_prompt,
        request_id,
    );

    let from = session.status;
    let now = now_epoch_millis();
    session.status = target;
    session.updated_at_epoch_millis = now;
    if target.is_terminal() {
        session.ended_at_epoch_millis = Some(now);
        session.relay_token_epoch = session.relay_token_epoch.saturating_add(1);
    }
    let event = new_event(
        &session,
        event_type,
        Some(from),
        target,
        account_id,
        &actor.device_id,
        expected_role,
        reason,
        idempotency_key,
        request_id,
    );
    let audit_entry = new_session_audit(
        request_id,
        account_id,
        &actor.device_id,
        expected_role,
        &session,
        audit_action,
        reason,
    );
    let outcome = state
        .repository
        .transition_session(&TransitionSessionCommand {
            storage_key,
            expected_status: from,
            apply_allowed: validation.is_ok(),
            idempotency: IdempotencyRecord {
                account_id: account_id.to_owned(),
                device_id: actor.device_id.clone(),
                method: request_method.to_ascii_uppercase(),
                path: request_path.to_owned(),
                operation: event_type.to_owned(),
                idempotency_key: idempotency_key.to_owned(),
                body_hash: request_body_hash.to_owned(),
                request_id: request_id.to_owned(),
                session_id: session_id.to_owned(),
                request_binding_hash: request_binding_hash.to_owned(),
                created_at_epoch_millis: now,
                expires_at_epoch_millis: session.session_expires_at_epoch_millis,
            },
            session,
            event,
            audit_entry,
        })
        .await
        .map_err(|error| match error {
            StoreError::Conflict => ApiError::conflict(
                "session_state_conflict",
                "session state changed concurrently",
                request_id,
            ),
            StoreError::Unavailable => ApiError::internal(request_id),
        })?;
    match outcome {
        TransitionSessionOutcome::Applied { session, event_id }
        | TransitionSessionOutcome::Replayed { session, event_id } => {
            Ok(TransitionResult { session, event_id })
        }
        TransitionSessionOutcome::BindingMismatch => Err(ApiError::conflict(
            "idempotency_binding_mismatch",
            "idempotency key was already used with a different signed request",
            request_id,
        )),
        TransitionSessionOutcome::InvalidTransition => {
            Err(validation.expect_err("invalid transition outcome has validation error"))
        }
        TransitionSessionOutcome::StateConflict => Err(ApiError::conflict(
            "session_state_conflict",
            "session state changed concurrently",
            request_id,
        )),
        TransitionSessionOutcome::NotFound => Err(ApiError::not_found(
            "session_not_found",
            "session was not found",
            request_id,
        )),
    }
}

fn validate_transition(
    from: SessionStatus,
    to: SessionStatus,
    actor_role: &str,
    require_prompt: bool,
    request_id: &str,
) -> ApiResult<()> {
    let allowed = match to {
        SessionStatus::Accepted => {
            actor_role == "controlled"
                && matches!(
                    from,
                    SessionStatus::WaitingApproval
                        | SessionStatus::CodeVerified
                        | SessionStatus::UnattendedVerified
                )
        }
        SessionStatus::Rejected => {
            actor_role == "controlled"
                && matches!(
                    from,
                    SessionStatus::WaitingApproval
                        | SessionStatus::CodeVerified
                        | SessionStatus::UnattendedVerified
                )
        }
        SessionStatus::Cancelled => {
            actor_role == "controller"
                && matches!(
                    from,
                    SessionStatus::PendingCodeVerification
                        | SessionStatus::PendingUnattendedVerification
                        | SessionStatus::CodeVerified
                        | SessionStatus::UnattendedVerified
                        | SessionStatus::WaitingApproval
                )
        }
        SessionStatus::Closed => {
            matches!(
                from,
                SessionStatus::Accepted
                    | SessionStatus::Connected
                    | SessionStatus::Degraded
                    | SessionStatus::Reconnecting
            )
        }
        SessionStatus::Connected => {
            matches!(
                from,
                SessionStatus::Accepted | SessionStatus::Degraded | SessionStatus::Reconnecting
            ) || (from == SessionStatus::UnattendedVerified && !require_prompt)
        }
        SessionStatus::Degraded => from == SessionStatus::Connected,
        SessionStatus::Reconnecting => {
            matches!(from, SessionStatus::Connected | SessionStatus::Degraded)
        }
        SessionStatus::Failed => !matches!(
            from,
            SessionStatus::Rejected
                | SessionStatus::Cancelled
                | SessionStatus::Closed
                | SessionStatus::Failed
        ),
        _ => false,
    };
    if !allowed {
        return Err(ApiError::conflict(
            "invalid_session_transition",
            "the requested session transition is not allowed",
            request_id,
        ));
    }
    Ok(())
}

async fn participant_role<'a>(
    state: &AppState,
    session: &Session,
    account_id: &str,
    device_id: &str,
) -> Result<Option<&'a str>, StoreError> {
    if session.controller_account_id == account_id && session.controller_device_id == device_id {
        return Ok(Some("controller"));
    }
    let Some(target) = state
        .repository
        .load_device_authority(&session.controlled_device_id)
        .await?
    else {
        return Ok(None);
    };
    Ok((target.account_id == account_id && target.device_id == device_id).then_some("controlled"))
}

async fn authorized_session(
    state: &AppState,
    account_id: &str,
    session_id: &str,
    request_id: &str,
) -> ApiResult<Session> {
    let session = state
        .repository
        .load_session_authority(session_id)
        .await
        .map_err(|_| ApiError::internal(request_id))?
        .ok_or_else(|| {
            ApiError::not_found("session_not_found", "session was not found", request_id)
        })?;
    let target_account = state
        .repository
        .load_device_authority(&session.controlled_device_id)
        .await
        .map_err(|_| ApiError::internal(request_id))?
        .map(|device| device.account_id)
        .ok_or_else(|| ApiError::internal(request_id))?;
    if session.controller_account_id != account_id && target_account != account_id {
        return Err(ApiError::not_found(
            "session_not_found",
            "session was not found",
            request_id,
        ));
    }
    Ok(session)
}

async fn notify_session_participants(state: &AppState, session: &Session, message: Value) {
    state
        .notifier
        .push(&session.controller_device_id, message.clone())
        .await;
    state
        .notifier
        .push(&session.controlled_device_id, message)
        .await;
}

struct CanonicalRequestBinding {
    digest: String,
    body_hash: String,
    target: String,
}

fn canonical_request_binding(
    account_id: &str,
    device_id: &str,
    method: &Method,
    uri: &Uri,
    body: &[u8],
    headers: &HeaderMap,
    request_id: &str,
) -> ApiResult<CanonicalRequestBinding> {
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
    let raw_target = uri
        .path_and_query()
        .map_or(uri.path(), |value| value.as_str());
    let target = canonical_request_target(raw_target).map_err(|_| {
        ApiError::bad_request(
            "invalid_request_target",
            "request target cannot be canonicalized",
            request_id,
        )
    })?;
    let canonical = canonical_idempotency_binding_bytes(
        account_id,
        device_id,
        method.as_str(),
        &target,
        &body_hash,
    )
    .map_err(|_| ApiError::internal(request_id))?;
    Ok(CanonicalRequestBinding {
        digest: sha256_hex(&canonical),
        body_hash: hex_encode(&body_hash),
        target,
    })
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

fn validate_idempotency_key(value: &str, request_id: &str) -> ApiResult<()> {
    if value.is_empty() || value.len() > 128 || !value.is_ascii() {
        return Err(ApiError::bad_request(
            "invalid_idempotency_key",
            "idempotency_key must contain 1 to 128 ASCII characters",
            request_id,
        ));
    }
    Ok(())
}

fn validate_actor(
    actor_type: &str,
    actor_device_id: &str,
    signed_device: &Device,
    request_id: &str,
) -> ApiResult<()> {
    if actor_type != "device" || actor_device_id != signed_device.device_id {
        return Err(ApiError::forbidden(
            "actor_mismatch",
            "actor fields must identify the signed device",
            request_id,
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn new_event(
    session: &Session,
    event_type: &str,
    from_status: Option<SessionStatus>,
    to_status: SessionStatus,
    actor_account_id: &str,
    actor_device_id: &str,
    actor_role: &str,
    reason: Option<&str>,
    idempotency_key: &str,
    request_id: &str,
) -> SessionEvent {
    SessionEvent {
        event_id: random_uuid_v4(),
        session_id: session.session_id.clone(),
        event_type: event_type.to_owned(),
        from_status,
        to_status,
        actor_type: "device".to_owned(),
        actor_account_id: Some(actor_account_id.to_owned()),
        actor_device_id: Some(actor_device_id.to_owned()),
        actor_role: Some(actor_role.to_owned()),
        reason: reason.map(ToOwned::to_owned),
        idempotency_key_hash: sha256_hex(idempotency_key.as_bytes()),
        request_id: request_id.to_owned(),
        created_at_epoch_millis: now_epoch_millis(),
        result_session: Some(session.clone()),
    }
}

#[allow(clippy::too_many_arguments)]
fn new_session_audit(
    request_id: &str,
    account_id: &str,
    actor_device_id: &str,
    actor_role: &str,
    session: &Session,
    action: &str,
    reason: Option<&str>,
) -> AuditEntry {
    AuditEntry {
        audit_id: random_uuid_v4(),
        actor_type: "device".to_owned(),
        actor_account_id: Some(account_id.to_owned()),
        actor_device_id: Some(actor_device_id.to_owned()),
        actor_role: Some(actor_role.to_owned()),
        actor_service: None,
        target_device_id: Some(session.controlled_device_id.clone()),
        session_id: Some(session.session_id.clone()),
        action: action.to_owned(),
        result: "success".to_owned(),
        reason: reason.map(ToOwned::to_owned),
        metadata: BTreeMap::new(),
        request_id: request_id.to_owned(),
        created_at_epoch_millis: now_epoch_millis(),
    }
}

fn session_response(session: &Session, controlled: &Device) -> Value {
    json!({
        "session_id": session.session_id,
        "status": session.status,
        "controlled_device_id": controlled.device_id,
        "controlled_device_name": controlled.display_name,
        "permissions": session.permissions,
        "permissions_digest": session.permissions_digest,
        "policy_evaluation_id": session.policy_evaluation_id,
        "session_expires_at_epoch_millis": session.session_expires_at_epoch_millis,
        "session_access_decision": if session.permissions.require_prompt { "require_prompt" } else { "allow" },
        "matched_policy_ids": [],
        "abuse_actions": [],
        "user_warnings": [],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_actions_keep_audit_and_signal_contracts_separate() {
        assert_eq!(
            SessionAction::Reject.contract(),
            (
                SessionStatus::Rejected,
                "invite_rejected",
                "session_rejected",
                "session_reject_ack",
            )
        );
        assert_eq!(
            SessionAction::Cancel.contract(),
            (
                SessionStatus::Cancelled,
                "cancelled",
                "session_cancelled",
                "session_cancel_ack",
            )
        );
    }

    #[test]
    fn idempotency_storage_key_is_scoped_to_method_and_canonical_path() {
        let first = idempotency_storage_key(
            "account-1",
            "device-1",
            "post",
            "/v1/sessions/session-1/accept",
            "shared-key",
        );
        let same = idempotency_storage_key(
            "account-1",
            "device-1",
            "POST",
            "/v1/sessions/session-1/accept",
            "shared-key",
        );
        let other_session = idempotency_storage_key(
            "account-1",
            "device-1",
            "POST",
            "/v1/sessions/session-2/accept",
            "shared-key",
        );

        assert_eq!(first, same);
        assert_ne!(first, other_session);
    }

    #[test]
    fn connection_state_can_recover_but_accepted_session_cannot_be_cancelled() {
        assert!(validate_transition(
            SessionStatus::Reconnecting,
            SessionStatus::Connected,
            "controller",
            true,
            "request-1",
        )
        .is_ok());
        assert!(validate_transition(
            SessionStatus::Degraded,
            SessionStatus::Connected,
            "controlled",
            true,
            "request-2",
        )
        .is_ok());
        assert!(validate_transition(
            SessionStatus::Accepted,
            SessionStatus::Cancelled,
            "controller",
            true,
            "request-3",
        )
        .is_err());
    }
}
