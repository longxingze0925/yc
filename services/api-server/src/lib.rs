mod config;
mod ephemeral;
mod error;
mod model;
mod notifier;
mod postgres_store;
mod routes;
mod security;
mod store;

pub use config::{AppConfig, StorageBackend};
pub use ephemeral::{EphemeralState, MemoryEphemeralState, RedisEphemeralState, StepUpConsumption};
pub use error::{ApiError, ApiResult};
pub use model::*;
pub use notifier::SignalNotifier;
pub use postgres_store::PostgresRepository;
pub use security::{
    device_enrollment_grant_binding_hash, sign_device_request_for_test, AccessClaims,
};
pub use store::{Database, MemoryRepository, Repository};

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderValue};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::Router;
use tracing::{field, info, Instrument};

#[derive(Clone)]
pub struct AppState {
    pub repository: Arc<dyn Repository>,
    pub ephemeral: Arc<dyn EphemeralState>,
    pub config: AppConfig,
    pub notifier: SignalNotifier,
}

impl AppState {
    pub fn new(
        repository: Arc<dyn Repository>,
        config: AppConfig,
        notifier: SignalNotifier,
    ) -> Self {
        Self::with_ephemeral(
            repository,
            Arc::new(MemoryEphemeralState::default()),
            config,
            notifier,
        )
    }

    pub fn with_ephemeral(
        repository: Arc<dyn Repository>,
        ephemeral: Arc<dyn EphemeralState>,
        config: AppConfig,
        notifier: SignalNotifier,
    ) -> Self {
        Self {
            repository,
            ephemeral,
            config,
            notifier,
        }
    }

    pub fn for_test() -> Self {
        Self::new(
            Arc::new(MemoryRepository::default()),
            AppConfig::for_test(),
            SignalNotifier::disabled(),
        )
    }
}

#[derive(Debug, Clone)]
pub struct RequestId(pub String);

#[derive(Debug, Clone, Copy)]
pub struct ObservedPeerIp(pub Option<IpAddr>);

pub fn build_router(state: AppState) -> Router {
    routes::router(state.clone()).layer(middleware::from_fn_with_state(state, request_middleware))
}

async fn request_middleware(
    State(_state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let started_at = Instant::now();
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= 128 && value.is_ascii())
        .map(ToOwned::to_owned)
        .unwrap_or_else(security::random_uuid_v4);
    let span = tracing::info_span!(
        "http.request",
        request_id = %request_id,
        method = %method,
        path = %path,
        status = field::Empty,
    );

    request
        .extensions_mut()
        .insert(RequestId(request_id.clone()));
    let observed_peer_ip = request
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|ConnectInfo(peer)| peer.ip());
    request
        .extensions_mut()
        .insert(ObservedPeerIp(observed_peer_ip));
    let response = if request.uri().path().starts_with("/v1/") {
        let protocol_version = request
            .headers()
            .get("x-rctl-protocol-version")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u16>().ok());
        if protocol_version != Some(remote_protocol::PROTOCOL_VERSION) {
            ApiError::new(
                axum::http::StatusCode::UPGRADE_REQUIRED,
                "unsupported_version",
                "X-Rctl-Protocol-Version is missing or unsupported",
                &request_id,
            )
            .into_response()
        } else {
            next.run(request).instrument(span.clone()).await
        }
    } else {
        next.run(request).instrument(span.clone()).await
    };
    let response = finalize_response(response, &request_id);
    span.record("status", response.status().as_u16());
    info!(
        parent: &span,
        latency_ms = started_at.elapsed().as_millis(),
        "request completed"
    );
    response
}

fn finalize_response(mut response: Response, request_id: &str) -> Response {
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(request_id) {
        headers.insert("x-request-id", value);
    }
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    use ed25519_dalek::SigningKey;
    use hkdf::Hkdf;
    use http_body_util::BodyExt;
    use serde_json::{json, Value};
    use sha2::Sha256;
    use tower::ServiceExt;
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    use super::*;
    use crate::security::{
        canonical_fields, encode_public_key, now_epoch_millis, random_token, sha256, totp_code,
        verify_access_token,
    };

    const VERSION: &str = "1";

    #[tokio::test]
    async fn version_header_is_required_on_v1_routes() {
        let response = build_router(AppState::for_test())
            .oneshot(
                Request::builder()
                    .uri("/v1/devices")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::UPGRADE_REQUIRED);
        assert!(response.headers().contains_key("x-request-id"));
        assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
        assert_eq!(
            response.headers().get("x-content-type-options").unwrap(),
            "nosniff"
        );
    }

    #[tokio::test]
    async fn health_reports_the_storage_and_ephemeral_backends() {
        let response = build_router(AppState::for_test())
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .header("x-request-id", "health-test-request")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("x-request-id").unwrap(),
            "health-test-request"
        );
        let body: Value = serde_json::from_slice(
            &response
                .into_body()
                .collect()
                .await
                .expect("health body")
                .to_bytes(),
        )
        .expect("health JSON");
        assert_eq!(body["status"], "ok");
        assert_eq!(body["storage"], "memory");
        assert_eq!(body["ephemeral_storage"], "memory");
    }

    #[tokio::test]
    async fn unregistered_devices_cannot_use_the_generic_step_up_endpoint() {
        let state = AppState::for_test();
        let router = build_router(state);
        let tokens = register_account(router.clone(), "generic-new-device@example.com").await;
        let access_token = tokens["access_token"].as_str().expect("access token");
        let body = serde_json::to_vec(&json!({
            "device_id": "pending-device",
            "purpose": "new_controller_device",
            "method": "POST",
            "path": "/v1/devices",
            "body_hash": "0000000000000000000000000000000000000000000000000000000000000000",
            "request_id": "generic-new-device-step-up"
        }))
        .expect("risk challenge body");

        let (status, response) = authenticated_json_request(
            router,
            "POST",
            "/v1/auth/risk-challenge",
            access_token,
            "generic-new-device-step-up",
            body,
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(response["code"], "invalid_risk_purpose");
    }

    #[tokio::test]
    async fn totp_enrollment_retries_invalid_code_and_commits_complete_state_once() {
        let state = AppState::for_test();
        let router = build_router(state.clone());
        let tokens = register_account(router.clone(), "totp-enrollment@example.com").await;
        let access_token = tokens["access_token"].as_str().expect("access token");
        let claims =
            verify_access_token(access_token, &state.config.token_secret, now_epoch_millis())
                .expect("access claims");
        let recovery_secret = StaticSecret::from([11_u8; 32]);
        let recovery_public = X25519PublicKey::from(&recovery_secret).to_bytes();

        let start = authenticated_json_request(
            router.clone(),
            "POST",
            "/v1/me/mfa/totp/start",
            access_token,
            "totp-start",
            serde_json::to_vec(&json!({
                "recovery_delivery_public_key": URL_SAFE_NO_PAD.encode(recovery_public),
            }))
            .expect("start body"),
        )
        .await;
        assert_eq!(start.0, StatusCode::CREATED, "{}", start.1);
        let factor_id = start.1["factor_id"].as_str().expect("factor id").to_owned();
        let secret = start.1["secret_base32"]
            .as_str()
            .expect("TOTP secret")
            .to_owned();
        state
            .repository
            .read(&mut |database| assert!(database.mfa_factors.is_empty()))
            .await;

        let code_now = now_epoch_millis();
        let (valid_code, _) = totp_code(&secret, code_now).expect("valid TOTP code");
        let neighboring_codes = [
            code_now.saturating_sub(30_000),
            code_now,
            code_now.saturating_add(30_000),
        ]
        .into_iter()
        .map(|timestamp| totp_code(&secret, timestamp).expect("neighbor TOTP").0)
        .collect::<Vec<_>>();
        let invalid_code = (0..1_000_000)
            .map(|value| format!("{value:06}"))
            .find(|candidate| !neighboring_codes.contains(candidate))
            .expect("invalid TOTP candidate");
        let invalid = authenticated_json_request_with_idempotency(
            router.clone(),
            "POST",
            "/v1/me/mfa/totp/finish",
            access_token,
            "totp-invalid",
            serde_json::to_vec(&json!({
                "factor_id": factor_id,
                "code": invalid_code,
            }))
            .expect("invalid finish body"),
            "totp-invalid-key",
        )
        .await;
        assert_eq!(invalid.0, StatusCode::FORBIDDEN, "{}", invalid.1);
        assert_eq!(invalid.1["code"], "invalid_mfa_code");

        let finish = authenticated_json_request_with_idempotency(
            router.clone(),
            "POST",
            "/v1/me/mfa/totp/finish",
            access_token,
            "totp-finish",
            serde_json::to_vec(&json!({
                "factor_id": factor_id,
                "code": valid_code,
            }))
            .expect("finish body"),
            "totp-finish-key",
        )
        .await;
        assert_eq!(finish.0, StatusCode::OK, "{}", finish.1);
        assert!(finish.1.get("recovery_codes").is_none());
        let recovery_codes = decrypt_recovery_delivery(
            &finish.1,
            &claims,
            &factor_id,
            "totp-finish-key",
            &recovery_secret,
            &recovery_public,
        );
        assert_eq!(recovery_codes.len(), 8);
        let unique_codes = recovery_codes
            .iter()
            .map(String::as_str)
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(unique_codes.len(), 8);
        let expected_hashes = unique_codes
            .iter()
            .map(|code| sha256(code.as_bytes()))
            .collect::<std::collections::HashSet<_>>();

        let status = authenticated_json_request(
            router.clone(),
            "GET",
            "/v1/me/mfa",
            access_token,
            "totp-status",
            Vec::new(),
        )
        .await;
        assert_eq!(status.0, StatusCode::UNAUTHORIZED, "{}", status.1);

        let replay = authenticated_json_request_with_idempotency(
            router.clone(),
            "POST",
            "/v1/me/mfa/totp/finish",
            access_token,
            "totp-replay",
            serde_json::to_vec(&json!({
                "factor_id": factor_id,
                "code": valid_code,
            }))
            .expect("replay body"),
            "totp-finish-key",
        )
        .await;
        assert_eq!(replay.0, StatusCode::OK, "{}", replay.1);
        assert_eq!(replay.1, finish.1);
        let unrelated_replay = authenticated_json_request_with_idempotency(
            router,
            "POST",
            "/v1/me/mfa/totp/finish",
            access_token,
            "totp-unrelated-replay",
            serde_json::to_vec(&json!({
                "factor_id": factor_id,
                "code": valid_code,
            }))
            .expect("unrelated replay body"),
            "different-finish-key",
        )
        .await;
        assert_eq!(unrelated_replay.0, StatusCode::UNAUTHORIZED);
        state
            .repository
            .read(&mut |database| {
                assert_eq!(database.mfa_factors.len(), 1);
                assert_eq!(database.recovery_codes.len(), 8);
                assert_eq!(database.recovery_code_deliveries.len(), 1);
                assert!(database.account_sessions.values().all(|session| {
                    session.account_id != claims.account_id
                        || session.revoked_reason.as_deref() == Some("mfa_enabled")
                }));
                assert_eq!(
                    database
                        .audit_logs
                        .iter()
                        .filter(|entry| entry.action == "mfa_factor_enrolled")
                        .count(),
                    1
                );
                assert_eq!(
                    database
                        .recovery_codes
                        .values()
                        .map(|record| record.code_hash)
                        .collect::<std::collections::HashSet<_>>(),
                    expected_hashes
                );
                assert!(database.audit_logs.iter().all(|entry| {
                    let serialized = serde_json::to_string(&entry.metadata).unwrap();
                    !serialized.contains(&secret)
                        && unique_codes.iter().all(|code| !serialized.contains(code))
                }));
            })
            .await;
    }

    #[tokio::test]
    async fn parallel_totp_start_has_exactly_one_winner() {
        let state = AppState::for_test();
        let router = build_router(state.clone());
        let tokens = register_account(router.clone(), "totp-parallel@example.com").await;
        let access_token = tokens["access_token"]
            .as_str()
            .expect("access token")
            .to_owned();
        let recovery_public = X25519PublicKey::from(&StaticSecret::from([13_u8; 32])).to_bytes();
        let start_body = serde_json::to_vec(&json!({
            "recovery_delivery_public_key": URL_SAFE_NO_PAD.encode(recovery_public),
        }))
        .expect("parallel start body");

        let first = authenticated_json_request(
            router.clone(),
            "POST",
            "/v1/me/mfa/totp/start",
            &access_token,
            "totp-parallel-1",
            start_body.clone(),
        );
        let second = authenticated_json_request(
            router,
            "POST",
            "/v1/me/mfa/totp/start",
            &access_token,
            "totp-parallel-2",
            start_body,
        );
        let (first, second) = tokio::join!(first, second);
        let statuses = [first.0, second.0];
        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status == StatusCode::CREATED)
                .count(),
            1
        );
        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status == StatusCode::CONFLICT)
                .count(),
            1
        );
        let conflict = if first.0 == StatusCode::CONFLICT {
            first.1
        } else {
            second.1
        };
        assert_eq!(conflict["code"], "mfa_enrollment_in_progress");
        state
            .repository
            .read(&mut |database| assert!(database.mfa_factors.is_empty()))
            .await;
    }

    #[tokio::test]
    async fn account_devices_and_prompt_session_complete_a_signed_lifecycle() {
        run_prompt_session_lifecycle(
            AppState::for_test(),
            "owner@example.com",
            "controller-1",
            "controlled-1",
            "memory",
        )
        .await;
    }

    #[tokio::test]
    async fn signed_device_patch_enforces_lifecycle_and_key_revocation() {
        let state = AppState::for_test();
        let router = build_router(state.clone());
        let tokens = register_account(router.clone(), "device-patch@example.com").await;
        let access_token = tokens["access_token"].as_str().unwrap().to_owned();
        let account_id = tokens["account_id"].as_str().unwrap().to_owned();
        let actor_key = SigningKey::from_bytes(&[61_u8; 32]);
        let target_key = SigningKey::from_bytes(&[63_u8; 32]);
        register_device(
            &state,
            router.clone(),
            &access_token,
            &account_id,
            "patch-actor",
            &actor_key,
        )
        .await;
        register_device(
            &state,
            router.clone(),
            &access_token,
            &account_id,
            "patch-target",
            &target_key,
        )
        .await;

        let renamed = signed_request(
            router.clone(),
            "PATCH",
            "/v1/devices/patch-target",
            &access_token,
            &account_id,
            "patch-actor",
            &actor_key,
            "patch-rename",
            serde_json::to_vec(&json!({ "display_name": "Office Ubuntu" })).unwrap(),
        )
        .await;
        assert_eq!(renamed.0, StatusCode::OK, "{}", renamed.1);
        assert_eq!(renamed.1["display_name"], "Office Ubuntu");

        let disabled = signed_request(
            router.clone(),
            "PATCH",
            "/v1/devices/patch-target",
            &access_token,
            &account_id,
            "patch-actor",
            &actor_key,
            "patch-disable",
            serde_json::to_vec(&json!({ "action": "disable" })).unwrap(),
        )
        .await;
        assert_eq!(disabled.0, StatusCode::OK, "{}", disabled.1);
        state
            .repository
            .read(&mut |database| {
                let target = &database.devices["patch-target"];
                assert_eq!(target.status, DeviceLifecycleStatus::Disabled);
                assert!(!target.capabilities.controlled);
            })
            .await;

        let restored = signed_request(
            router.clone(),
            "PATCH",
            "/v1/devices/patch-target",
            &access_token,
            &account_id,
            "patch-actor",
            &actor_key,
            "patch-restore",
            serde_json::to_vec(&json!({ "action": "restore" })).unwrap(),
        )
        .await;
        assert_eq!(restored.0, StatusCode::OK, "{}", restored.1);
        assert_eq!(restored.1["role_capabilities"]["controlled"], false);

        let revoked = signed_request(
            router.clone(),
            "PATCH",
            "/v1/devices/patch-target",
            &access_token,
            &account_id,
            "patch-actor",
            &actor_key,
            "patch-revoke-key",
            serde_json::to_vec(&json!({ "action": "revoke_public_key" })).unwrap(),
        )
        .await;
        assert_eq!(revoked.0, StatusCode::OK, "{}", revoked.1);
        state
            .repository
            .read(&mut |database| {
                let target = &database.devices["patch-target"];
                assert_eq!(target.status, DeviceLifecycleStatus::Disabled);
                assert!(target.public_key_revoked_at_epoch_millis.is_some());
                let audit = database
                    .audit_logs
                    .iter()
                    .find(|entry| entry.action == "device_public_key_revoked")
                    .expect("key revocation audit");
                assert!(audit.metadata.contains_key("affected_session_ids_hash"));
                assert!(database
                    .account_sessions
                    .values()
                    .filter(|session| session.account_id == account_id)
                    .all(|session| {
                        session.revoked_at_epoch_millis.is_some()
                            && session.revoked_reason.as_deref() == Some("device_unbound")
                    }));
            })
            .await;
        let rejected = authenticated_json_request(
            router,
            "GET",
            "/v1/devices",
            &access_token,
            "revoked-account-session",
            Vec::new(),
        )
        .await;
        assert_eq!(rejected.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn device_registration_without_enrollment_grant_uses_the_frozen_error_code() {
        let state = AppState::for_test();
        let router = build_router(state);
        let tokens = register_account(router.clone(), "missing-grant@example.com").await;
        let response = authenticated_json_request(
            router,
            "POST",
            "/v1/devices",
            tokens["access_token"].as_str().unwrap(),
            "missing-grant",
            serde_json::to_vec(&json!({
                "device_id": "missing-grant-device",
                "display_name": "Missing Grant",
                "platform": "ubuntu",
                "os_version": "26.04",
                "arch": "x86_64",
                "role_capabilities": {
                    "controller": true,
                    "controlled": true,
                    "file_transfer": false,
                    "unattended": false
                },
                "public_key": encode_public_key(&[7; 32])
            }))
            .unwrap(),
        )
        .await;
        assert_eq!(response.0, StatusCode::BAD_REQUEST);
        assert_eq!(response.1["code"], "device_enrollment_grant_required");
    }

    #[tokio::test]
    async fn concurrent_session_requests_commit_once_and_replay_original_results() {
        let state = AppState::for_test();
        let router = build_router(state.clone());
        let tokens = register_account(router.clone(), "session-race@example.com").await;
        let access_token = tokens["access_token"].as_str().unwrap().to_owned();
        let account_id = tokens["account_id"].as_str().unwrap().to_owned();
        let controller_id = "race-controller";
        let controlled_id = "race-controlled";
        let controller_key = SigningKey::from_bytes(&[31_u8; 32]);
        let controlled_key = SigningKey::from_bytes(&[33_u8; 32]);
        register_device(
            &state,
            router.clone(),
            &access_token,
            &account_id,
            controller_id,
            &controller_key,
        )
        .await;
        register_device(
            &state,
            router.clone(),
            &access_token,
            &account_id,
            controlled_id,
            &controlled_key,
        )
        .await;

        let create_body = prompt_session_body(controller_id, controlled_id, "parallel-create");
        let first_create = signed_request(
            router.clone(),
            "POST",
            "/v1/sessions",
            &access_token,
            &account_id,
            controller_id,
            &controller_key,
            "parallel-create-a",
            create_body.clone(),
        );
        let second_create = signed_request(
            router.clone(),
            "POST",
            "/v1/sessions",
            &access_token,
            &account_id,
            controller_id,
            &controller_key,
            "parallel-create-b",
            create_body.clone(),
        );
        let (first_create, second_create) = tokio::join!(first_create, second_create);
        let create_statuses = [first_create.0, second_create.0];
        assert_eq!(
            create_statuses
                .iter()
                .filter(|status| **status == StatusCode::CREATED)
                .count(),
            1
        );
        assert_eq!(
            create_statuses
                .iter()
                .filter(|status| **status == StatusCode::OK)
                .count(),
            1
        );
        let session_id = first_create.1["session_id"].as_str().unwrap().to_owned();
        assert_eq!(second_create.1["session_id"], session_id);

        let accept_body = serde_json::to_vec(&json!({
            "actor_type": "device",
            "actor_device_id": controlled_id,
            "actor_role": "controlled",
            "idempotency_key": "parallel-accept"
        }))
        .unwrap();
        let reject_body = serde_json::to_vec(&json!({
            "actor_type": "device",
            "actor_device_id": controlled_id,
            "actor_role": "controlled",
            "idempotency_key": "parallel-reject",
            "reason": "declined"
        }))
        .unwrap();
        let accept_path = format!("/v1/sessions/{session_id}/accept");
        let reject_path = format!("/v1/sessions/{session_id}/reject");
        let accept = signed_request(
            router.clone(),
            "POST",
            &accept_path,
            &access_token,
            &account_id,
            controlled_id,
            &controlled_key,
            "parallel-accept",
            accept_body,
        );
        let reject = signed_request(
            router.clone(),
            "POST",
            &reject_path,
            &access_token,
            &account_id,
            controlled_id,
            &controlled_key,
            "parallel-reject",
            reject_body,
        );
        let (accept, reject) = tokio::join!(accept, reject);
        let transition_statuses = [accept.0, reject.0];
        assert_eq!(
            transition_statuses
                .iter()
                .filter(|status| **status == StatusCode::OK)
                .count(),
            1
        );
        assert_eq!(
            transition_statuses
                .iter()
                .filter(|status| **status == StatusCode::CONFLICT)
                .count(),
            1
        );
        let conflict = if accept.0 == StatusCode::CONFLICT {
            &accept.1
        } else {
            &reject.1
        };
        assert!(matches!(
            conflict["code"].as_str(),
            Some("session_state_conflict" | "invalid_session_transition")
        ));

        let create_replay = signed_request(
            router.clone(),
            "POST",
            "/v1/sessions",
            &access_token,
            &account_id,
            controller_id,
            &controller_key,
            "parallel-create-replay",
            create_body,
        )
        .await;
        assert_eq!(create_replay.0, StatusCode::OK);
        assert_eq!(create_replay.1["session_id"], session_id);
        assert_eq!(create_replay.1["status"], "waiting_approval");

        state
            .repository
            .read(&mut |database| {
                assert_eq!(
                    database
                        .sessions
                        .values()
                        .filter(|session| session.session_id == session_id)
                        .count(),
                    1
                );
                assert_eq!(
                    database
                        .policy_evaluations
                        .values()
                        .filter(|evaluation| evaluation.session_id == session_id)
                        .count(),
                    1
                );
                assert_eq!(
                    database
                        .session_events
                        .iter()
                        .filter(|event| event.session_id == session_id)
                        .count(),
                    2
                );
                assert_eq!(
                    database
                        .audit_logs
                        .iter()
                        .filter(|entry| entry.session_id.as_deref() == Some(session_id.as_str()))
                        .count(),
                    2
                );
                assert_eq!(
                    database
                        .session_idempotency
                        .values()
                        .filter(|record| record.session_id == session_id)
                        .count(),
                    2
                );
            })
            .await;

        let snapshot_create = prompt_session_body(controller_id, controlled_id, "snapshot-create");
        let snapshot = signed_request(
            router.clone(),
            "POST",
            "/v1/sessions",
            &access_token,
            &account_id,
            controller_id,
            &controller_key,
            "snapshot-create",
            snapshot_create,
        )
        .await;
        assert_eq!(snapshot.0, StatusCode::CREATED);
        let snapshot_id = snapshot.1["session_id"].as_str().unwrap().to_owned();
        let snapshot_accept_path = format!("/v1/sessions/{snapshot_id}/accept");
        let snapshot_accept_body = serde_json::to_vec(&json!({
            "actor_type": "device",
            "actor_device_id": controlled_id,
            "actor_role": "controlled",
            "idempotency_key": "snapshot-accept"
        }))
        .unwrap();
        let accepted = signed_request(
            router.clone(),
            "POST",
            &snapshot_accept_path,
            &access_token,
            &account_id,
            controlled_id,
            &controlled_key,
            "snapshot-accept",
            snapshot_accept_body.clone(),
        )
        .await;
        assert_eq!(accepted.0, StatusCode::OK);
        assert_eq!(accepted.1["status"], "accepted");

        let connected_body = serde_json::to_vec(&json!({
            "actor_type": "device",
            "actor_device_id": controller_id,
            "actor_role": "controller",
            "idempotency_key": "snapshot-connected",
            "state": "connected"
        }))
        .unwrap();
        let connected = signed_request(
            router.clone(),
            "POST",
            &format!("/v1/sessions/{snapshot_id}/connection-state"),
            &access_token,
            &account_id,
            controller_id,
            &controller_key,
            "snapshot-connected",
            connected_body,
        )
        .await;
        assert_eq!(connected.0, StatusCode::OK);
        assert_eq!(connected.1["status"], "connected");

        let accept_replay = signed_request(
            router,
            "POST",
            &snapshot_accept_path,
            &access_token,
            &account_id,
            controlled_id,
            &controlled_key,
            "snapshot-accept-replay",
            snapshot_accept_body,
        )
        .await;
        assert_eq!(accept_replay.0, StatusCode::OK);
        assert_eq!(accept_replay.1["status"], "accepted");
    }

    #[tokio::test]
    async fn inactive_devices_cannot_create_remote_sessions() {
        let state = AppState::for_test();
        let router = build_router(state.clone());
        let tokens = register_account(router.clone(), "inactive-device@example.com").await;
        let access_token = tokens["access_token"].as_str().unwrap().to_owned();
        let account_id = tokens["account_id"].as_str().unwrap().to_owned();
        let controller_key = SigningKey::from_bytes(&[17_u8; 32]);
        let controlled_key = SigningKey::from_bytes(&[19_u8; 32]);
        register_device(
            &state,
            router.clone(),
            &access_token,
            &account_id,
            "inactive-controller",
            &controller_key,
        )
        .await;
        register_device(
            &state,
            router.clone(),
            &access_token,
            &account_id,
            "inactive-controlled",
            &controlled_key,
        )
        .await;
        let create_body = serde_json::to_vec(&json!({
            "controller_device_id": "inactive-controller",
            "controlled_device_id": "inactive-controlled",
            "auth_method": "account_prompt",
            "requested_permissions": {
                "remote_desktop": true,
                "input_control": true,
                "clipboard": false,
                "file_transfer": false,
                "unattended": false,
                "privacy_screen": false,
                "block_local_input": false,
                "require_prompt": true,
                "allow_relay": false
            },
            "idempotency_key": "inactive-device-create"
        }))
        .unwrap();

        state
            .repository
            .transact(&mut |database| {
                database
                    .devices
                    .get_mut("inactive-controller")
                    .unwrap()
                    .status = DeviceLifecycleStatus::Unbound;
                Ok(())
            })
            .await
            .unwrap();
        let unbound = signed_request(
            router.clone(),
            "POST",
            "/v1/sessions",
            &access_token,
            &account_id,
            "inactive-controller",
            &controller_key,
            "inactive-controller-unbound",
            create_body.clone(),
        )
        .await;
        assert_eq!(unbound.0, StatusCode::FORBIDDEN);
        assert_eq!(unbound.1["code"], "device_not_authorized");

        state
            .repository
            .transact(&mut |database| {
                database
                    .devices
                    .get_mut("inactive-controller")
                    .unwrap()
                    .status = DeviceLifecycleStatus::Offline;
                database
                    .devices
                    .get_mut("inactive-controlled")
                    .unwrap()
                    .status = DeviceLifecycleStatus::Disabled;
                Ok(())
            })
            .await
            .unwrap();
        let disabled = signed_request(
            router,
            "POST",
            "/v1/sessions",
            &access_token,
            &account_id,
            "inactive-controller",
            &controller_key,
            "inactive-controlled-disabled",
            create_body,
        )
        .await;
        assert_eq!(disabled.0, StatusCode::FORBIDDEN);
        assert_eq!(disabled.1["code"], "controlled_device_inactive");
    }

    #[tokio::test]
    #[ignore = "requires a migrated PostgreSQL database in API_TEST_DATABASE_URL"]
    async fn postgres_two_instances_commit_one_session_graph_and_one_transition() {
        let database_url = std::env::var("API_TEST_DATABASE_URL")
            .expect("API_TEST_DATABASE_URL must point to an isolated migrated database");
        let mfa_key = [0_u8; 32];
        let setup_repository = Arc::new(
            PostgresRepository::connect(&database_url, mfa_key)
                .await
                .expect("connect setup PostgreSQL repository"),
        );
        let suffix = crate::security::random_uuid_v4();
        let email = format!("postgres-race-{suffix}@example.com");
        let controller_id = format!("controller-race-{suffix}");
        let controlled_id = format!("controlled-race-{suffix}");
        let setup_state = AppState::new(
            setup_repository,
            AppConfig::for_test(),
            SignalNotifier::disabled(),
        );
        let setup = build_router(setup_state.clone());
        let tokens = register_account(setup.clone(), &email).await;
        let access_token = tokens["access_token"].as_str().unwrap().to_owned();
        let account_id = tokens["account_id"].as_str().unwrap().to_owned();
        let controller_key =
            SigningKey::from_bytes(&sha256(format!("postgres-controller-{suffix}").as_bytes()));
        let controlled_key =
            SigningKey::from_bytes(&sha256(format!("postgres-controlled-{suffix}").as_bytes()));
        register_device(
            &setup_state,
            setup.clone(),
            &access_token,
            &account_id,
            &controller_id,
            &controller_key,
        )
        .await;
        register_device(
            &setup_state,
            setup,
            &access_token,
            &account_id,
            &controlled_id,
            &controlled_key,
        )
        .await;

        let left = Arc::new(
            PostgresRepository::connect(&database_url, mfa_key)
                .await
                .expect("connect left PostgreSQL repository"),
        );
        let right = Arc::new(
            PostgresRepository::connect(&database_url, mfa_key)
                .await
                .expect("connect right PostgreSQL repository"),
        );
        let left_router = build_router(AppState::new(
            left,
            AppConfig::for_test(),
            SignalNotifier::disabled(),
        ));
        let right_router = build_router(AppState::new(
            right,
            AppConfig::for_test(),
            SignalNotifier::disabled(),
        ));
        let create_body = prompt_session_body(&controller_id, &controlled_id, "postgres-race");
        let left_create_nonce = format!("postgres-create-left-{suffix}");
        let right_create_nonce = format!("postgres-create-right-{suffix}");
        let left_create = signed_request(
            left_router.clone(),
            "POST",
            "/v1/sessions",
            &access_token,
            &account_id,
            &controller_id,
            &controller_key,
            &left_create_nonce,
            create_body.clone(),
        );
        let right_create = signed_request(
            right_router.clone(),
            "POST",
            "/v1/sessions",
            &access_token,
            &account_id,
            &controller_id,
            &controller_key,
            &right_create_nonce,
            create_body,
        );
        let (left_create, right_create) = tokio::join!(left_create, right_create);
        let statuses = [left_create.0, right_create.0];
        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status == StatusCode::CREATED)
                .count(),
            1
        );
        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status == StatusCode::OK)
                .count(),
            1
        );
        let session_id = left_create.1["session_id"].as_str().unwrap().to_owned();
        assert_eq!(right_create.1["session_id"], session_id);

        let accept_body = serde_json::to_vec(&json!({
            "actor_type": "device",
            "actor_device_id": controlled_id,
            "actor_role": "controlled",
            "idempotency_key": "postgres-accept"
        }))
        .unwrap();
        let reject_body = serde_json::to_vec(&json!({
            "actor_type": "device",
            "actor_device_id": controlled_id,
            "actor_role": "controlled",
            "idempotency_key": "postgres-reject",
            "reason": "declined"
        }))
        .unwrap();
        let accept_path = format!("/v1/sessions/{session_id}/accept");
        let reject_path = format!("/v1/sessions/{session_id}/reject");
        let accept_nonce = format!("postgres-accept-{suffix}");
        let reject_nonce = format!("postgres-reject-{suffix}");
        let left_transition = signed_request(
            left_router,
            "POST",
            &accept_path,
            &access_token,
            &account_id,
            &controlled_id,
            &controlled_key,
            &accept_nonce,
            accept_body,
        );
        let right_transition = signed_request(
            right_router,
            "POST",
            &reject_path,
            &access_token,
            &account_id,
            &controlled_id,
            &controlled_key,
            &reject_nonce,
            reject_body,
        );
        let (left_transition, right_transition) = tokio::join!(left_transition, right_transition);
        let transition_statuses = [left_transition.0, right_transition.0];
        assert_eq!(
            transition_statuses
                .iter()
                .filter(|status| **status == StatusCode::OK)
                .count(),
            1
        );
        assert_eq!(
            transition_statuses
                .iter()
                .filter(|status| **status == StatusCode::CONFLICT)
                .count(),
            1
        );

        let (client, connection) = tokio_postgres::connect(&database_url, tokio_postgres::NoTls)
            .await
            .expect("connect PostgreSQL assertion client");
        tokio::spawn(async move {
            connection.await.expect("PostgreSQL assertion connection");
        });
        let row = client
            .query_one(
                "SELECT
                    (SELECT count(*) FROM sessions WHERE session_id=$1) AS sessions,
                    (SELECT count(*) FROM policy_evaluations WHERE session_id=$1) AS policies,
                    (SELECT count(*) FROM session_events WHERE session_id=$1) AS events,
                    (SELECT count(*) FROM audit_logs WHERE session_id=$1) AS audits,
                    (SELECT count(*) FROM api_idempotency_keys WHERE resource_id=$1) AS idempotency",
                &[&session_id],
            )
            .await
            .expect("query PostgreSQL session graph counts");
        assert_eq!(row.get::<_, i64>("sessions"), 1);
        assert_eq!(row.get::<_, i64>("policies"), 1);
        assert_eq!(row.get::<_, i64>("events"), 2);
        assert_eq!(row.get::<_, i64>("audits"), 2);
        assert_eq!(row.get::<_, i64>("idempotency"), 2);
    }

    #[tokio::test]
    #[ignore = "requires a migrated PostgreSQL database in API_TEST_DATABASE_URL"]
    async fn postgres_concurrent_device_registration_creates_one_stable_result() {
        let database_url = std::env::var("API_TEST_DATABASE_URL")
            .expect("API_TEST_DATABASE_URL must point to an isolated migrated database");
        let setup_repository = Arc::new(
            PostgresRepository::connect(&database_url, [0; 32])
                .await
                .expect("connect setup PostgreSQL repository"),
        );
        let setup_state = AppState::new(
            setup_repository,
            AppConfig::for_test(),
            SignalNotifier::disabled(),
        );
        let setup_router = build_router(setup_state.clone());
        let suffix = crate::security::random_uuid_v4();
        let tokens = register_account(
            setup_router,
            &format!("postgres-registration-race-{suffix}@example.com"),
        )
        .await;
        let access_token = tokens["access_token"].as_str().unwrap().to_owned();
        let account_id = tokens["account_id"].as_str().unwrap().to_owned();
        let device_id = format!("registration-race-{suffix}");
        let key = SigningKey::from_bytes(&sha256(format!("race-key-{suffix}").as_bytes()));
        let body =
            seed_device_registration(&setup_state, &access_token, &account_id, &device_id, &key)
                .await;

        let left = Arc::new(
            PostgresRepository::connect(&database_url, [0; 32])
                .await
                .expect("connect left PostgreSQL repository"),
        );
        let right = Arc::new(
            PostgresRepository::connect(&database_url, [0; 32])
                .await
                .expect("connect right PostgreSQL repository"),
        );
        let left_router = build_router(AppState::new(
            left,
            AppConfig::for_test(),
            SignalNotifier::disabled(),
        ));
        let right_router = build_router(AppState::new(
            right,
            AppConfig::for_test(),
            SignalNotifier::disabled(),
        ));
        let left_nonce = format!("registration-left-{suffix}");
        let right_nonce = format!("registration-right-{suffix}");
        let left_request = signed_request(
            left_router,
            "POST",
            "/v1/devices",
            &access_token,
            &account_id,
            &device_id,
            &key,
            &left_nonce,
            body.clone(),
        );
        let right_request = signed_request(
            right_router,
            "POST",
            "/v1/devices",
            &access_token,
            &account_id,
            &device_id,
            &key,
            &right_nonce,
            body,
        );
        let (left_response, right_response) = tokio::join!(left_request, right_request);
        let statuses = [left_response.0, right_response.0];
        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status == StatusCode::CREATED)
                .count(),
            1
        );
        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status == StatusCode::OK)
                .count(),
            1
        );
        assert_eq!(
            left_response.1["public_key_id"],
            right_response.1["public_key_id"]
        );

        let (client, connection) = tokio_postgres::connect(&database_url, tokio_postgres::NoTls)
            .await
            .expect("connect PostgreSQL assertion client");
        tokio::spawn(async move {
            connection.await.expect("PostgreSQL assertion connection");
        });
        let counts = client
            .query_one(
                "SELECT
                    (SELECT count(*) FROM devices WHERE device_id=$1) AS devices,
                    (SELECT count(*) FROM device_enrollment_grants
                     WHERE device_id=$1 AND consumed_at_epoch_millis IS NOT NULL
                       AND registered_public_key_id IS NOT NULL) AS grants,
                    (SELECT count(*) FROM trusted_controller_devices
                     WHERE controller_device_id=$1) AS trusts,
                    (SELECT count(*) FROM audit_logs
                     WHERE target_device_id=$1 AND action='device_registered') AS registrations",
                &[&device_id],
            )
            .await
            .expect("query registration race counts");
        assert_eq!(counts.get::<_, i64>("devices"), 1);
        assert_eq!(counts.get::<_, i64>("grants"), 1);
        assert_eq!(counts.get::<_, i64>("trusts"), 0);
        assert_eq!(counts.get::<_, i64>("registrations"), 1);
    }

    #[tokio::test]
    #[ignore = "requires a migrated PostgreSQL database in API_TEST_DATABASE_URL"]
    async fn postgres_device_rotation_and_revocation_close_identity_authority() {
        let database_url = std::env::var("API_TEST_DATABASE_URL")
            .expect("API_TEST_DATABASE_URL must point to an isolated migrated database");
        let repository = Arc::new(
            PostgresRepository::connect(&database_url, [0; 32])
                .await
                .expect("connect PostgreSQL repository"),
        );
        let state = AppState::new(
            repository.clone(),
            AppConfig::for_test(),
            SignalNotifier::disabled(),
        );
        let router = build_router(state.clone());
        let suffix = crate::security::random_uuid_v4();
        let tokens = register_account(
            router.clone(),
            &format!("postgres-device-{suffix}@example.com"),
        )
        .await;
        let access_token = tokens["access_token"].as_str().unwrap().to_owned();
        let account_id = tokens["account_id"].as_str().unwrap().to_owned();
        let claims = verify_access_token(
            &access_token,
            &state.config.token_secret,
            now_epoch_millis(),
        )
        .expect("access claims");
        let actor_id = format!("rotation-actor-{suffix}");
        let target_id = format!("rotation-target-{suffix}");
        let old_key = SigningKey::from_bytes(&sha256(format!("old-key-{suffix}").as_bytes()));
        let new_key = SigningKey::from_bytes(&sha256(format!("new-key-{suffix}").as_bytes()));
        let target_key = SigningKey::from_bytes(&sha256(format!("target-key-{suffix}").as_bytes()));
        register_device(
            &state,
            router.clone(),
            &access_token,
            &account_id,
            &actor_id,
            &old_key,
        )
        .await;

        let mut actor = None;
        repository
            .read(&mut |database| actor = database.devices.get(&actor_id).cloned())
            .await;
        let actor = actor.expect("registered actor");
        let now = now_epoch_millis();
        let challenge_id = format!("rotation-challenge-{suffix}");
        let operation_binding_hash = sha256(format!("rotation-binding-{suffix}").as_bytes());
        repository
            .transact(&mut |database| {
                database.risk_challenges.insert(
                    challenge_id.clone(),
                    RiskChallenge {
                        risk_challenge_id: challenge_id.clone(),
                        account_id: account_id.clone(),
                        device_id: Some(actor_id.clone()),
                        purpose: "device_key_rotation".to_owned(),
                        operation_binding_hash,
                        risk_level: "high".to_owned(),
                        required_methods: vec!["totp".to_owned()],
                        status: RiskChallengeStatus::Verified,
                        attempts_remaining: 5,
                        ip_address: None,
                        user_agent: None,
                        expires_at_epoch_millis: now.saturating_add(300_000),
                        created_at_epoch_millis: now,
                        verified_at_epoch_millis: Some(now),
                        consumed_at_epoch_millis: None,
                    },
                );
                Ok(())
            })
            .await
            .expect("seed rotation step-up");
        let rotated = repository
            .rotate_device_key(&crate::store::DeviceKeyRotation {
                step_up: crate::store::StepUpExpectation {
                    challenge_id,
                    account_id: account_id.clone(),
                    device_id: actor_id.clone(),
                    purpose: "device_key_rotation".to_owned(),
                    operation_binding_hash,
                    now_epoch_millis: now,
                },
                current_public_key_id: actor.public_key_id,
                current_public_key_version: actor.public_key_version,
                new_public_key_id: crate::security::random_uuid_v4(),
                new_public_key: new_key.verifying_key().to_bytes(),
                new_public_key_version: 2,
                audit_entry: AuditEntry {
                    audit_id: crate::security::random_uuid_v4(),
                    actor_type: "device".to_owned(),
                    actor_account_id: Some(account_id.clone()),
                    actor_device_id: Some(actor_id.clone()),
                    actor_role: Some("none".to_owned()),
                    actor_service: None,
                    target_device_id: Some(actor_id.clone()),
                    session_id: None,
                    action: "device_public_key_rotated".to_owned(),
                    result: "success".to_owned(),
                    reason: None,
                    metadata: std::collections::BTreeMap::new(),
                    request_id: format!("rotation-request-{suffix}"),
                    created_at_epoch_millis: now,
                },
            })
            .await
            .expect("rotate PostgreSQL device key");
        assert_eq!(rotated.device.public_key_version, 2);

        register_device(
            &state,
            router.clone(),
            &access_token,
            &account_id,
            &target_id,
            &target_key,
        )
        .await;
        let revoked = signed_request(
            router,
            "PATCH",
            &format!("/v1/devices/{target_id}"),
            &access_token,
            &account_id,
            &actor_id,
            &new_key,
            &format!("postgres-revoke-{suffix}"),
            serde_json::to_vec(&json!({ "action": "revoke_public_key" })).unwrap(),
        )
        .await;
        assert_eq!(revoked.0, StatusCode::OK, "{}", revoked.1);
        assert!(!repository
            .account_session_active(&claims.account_session_id, &account_id, now_epoch_millis())
            .await
            .expect("query account session authority"));
    }

    #[tokio::test]
    #[ignore = "requires a migrated PostgreSQL database in API_TEST_DATABASE_URL"]
    async fn postgres_repository_persists_a_complete_session_and_encrypted_mfa() {
        let database_url = std::env::var("API_TEST_DATABASE_URL")
            .expect("API_TEST_DATABASE_URL must point to an isolated migrated database");
        let mfa_key = [0_u8; 32];
        let repository = Arc::new(
            PostgresRepository::connect(&database_url, mfa_key)
                .await
                .expect("connect PostgreSQL repository"),
        );
        let suffix = crate::security::random_uuid_v4();
        let email = format!("postgres-{suffix}@example.com");
        let controller_id = format!("controller-{suffix}");
        let controlled_id = format!("controlled-{suffix}");
        let state = AppState::new(
            repository.clone(),
            AppConfig::for_test(),
            SignalNotifier::disabled(),
        );
        let (account_id, session_id) =
            run_prompt_session_lifecycle(state, &email, &controller_id, &controlled_id, &suffix)
                .await;

        let factor_id = format!("factor-{suffix}");
        let mfa_secret = format!("JBSWY3DPEHPK3PXP{suffix}");
        let enrolled_at = now_epoch_millis();
        let mut account_session_id = None;
        repository
            .read(&mut |database| {
                account_session_id = database
                    .account_sessions
                    .values()
                    .find(|session| {
                        session.account_id == account_id
                            && session.revoked_at_epoch_millis.is_none()
                    })
                    .map(|session| session.account_session_id.clone());
            })
            .await;
        let account_session_id = account_session_id.expect("active account session");
        let recovery_codes = (0..8)
            .map(|index| RecoveryCode {
                recovery_code_id: format!("recovery-{index}-{suffix}"),
                account_id: account_id.clone(),
                code_hash: sha256(format!("recovery-code-{index}-{suffix}").as_bytes()),
                used_at_epoch_millis: None,
                expires_at_epoch_millis: None,
            })
            .collect::<Vec<_>>();
        repository
            .finish_totp_enrollment(&crate::store::TotpEnrollmentCompletion {
                factor: MfaFactor {
                    factor_id: factor_id.clone(),
                    account_id: account_id.clone(),
                    secret_base32: mfa_secret.clone(),
                    active: true,
                    last_used_counter: Some(42),
                    created_at_epoch_millis: enrolled_at,
                },
                recovery_codes,
                delivery: RecoveryCodeDelivery {
                    delivery_id: format!("delivery-{suffix}"),
                    account_id: account_id.clone(),
                    account_session_id,
                    factor_id: factor_id.clone(),
                    idempotency_key_hash: sha256(format!("delivery-key-{suffix}").as_bytes()),
                    finish_request_binding_hash: sha256(
                        format!("delivery-binding-{suffix}").as_bytes(),
                    ),
                    client_ephemeral_public_key: [3; 32],
                    server_ephemeral_public_key: [4; 32],
                    nonce: [5; 12],
                    ciphertext: vec![6; 32],
                    recovery_code_count: 8,
                    created_at_epoch_millis: enrolled_at,
                    expires_at_epoch_millis: enrolled_at.saturating_add(60_000),
                    acknowledged_at_epoch_millis: None,
                },
                audit_entry: AuditEntry {
                    audit_id: format!("mfa-enrollment-{suffix}"),
                    actor_type: "account".to_owned(),
                    actor_account_id: Some(account_id.clone()),
                    actor_device_id: None,
                    actor_role: None,
                    actor_service: None,
                    target_device_id: None,
                    session_id: None,
                    action: "mfa_factor_enrolled".to_owned(),
                    result: "success".to_owned(),
                    reason: None,
                    metadata: std::collections::BTreeMap::new(),
                    request_id: format!("mfa-enrollment-request-{suffix}"),
                    created_at_epoch_millis: enrolled_at,
                },
            })
            .await
            .expect("persist complete MFA enrollment");

        let (client, connection) = tokio_postgres::connect(&database_url, tokio_postgres::NoTls)
            .await
            .expect("connect PostgreSQL for ciphertext assertion");
        tokio::spawn(async move { connection.await.expect("PostgreSQL test connection") });
        let encrypted: Vec<u8> = client
            .query_one(
                "SELECT encrypted_secret FROM account_mfa_factors WHERE factor_id = $1",
                &[&factor_id],
            )
            .await
            .expect("load encrypted MFA secret")
            .get(0);
        assert!(!encrypted
            .windows(mfa_secret.len())
            .any(|window| window == mfa_secret.as_bytes()));
        let active_recovery_codes: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM account_recovery_codes
                 WHERE account_id=$1 AND status='active'",
                &[&account_id],
            )
            .await
            .expect("count active recovery codes")
            .get(0);
        assert_eq!(active_recovery_codes, 8);
        let enrollment_audits: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM audit_logs
                 WHERE actor_account_id=$1 AND action='mfa_factor_enrolled'",
                &[&account_id],
            )
            .await
            .expect("count enrollment audits")
            .get(0);
        assert_eq!(enrollment_audits, 1);

        let restored = PostgresRepository::connect(&database_url, mfa_key)
            .await
            .expect("restore PostgreSQL repository");
        let mut restored_all = false;
        restored
            .read(&mut |database| {
                restored_all = database.accounts.contains_key(&account_id)
                    && database.devices.contains_key(&controller_id)
                    && database.devices.contains_key(&controlled_id)
                    && database.sessions.contains_key(&session_id)
                    && database
                        .mfa_factors
                        .get(&factor_id)
                        .is_some_and(|factor| factor.secret_base32 == mfa_secret)
                    && !database.session_events.is_empty()
                    && !database.audit_logs.is_empty();
            })
            .await;
        assert!(restored_all);
    }

    fn prompt_session_body(
        controller_id: &str,
        controlled_id: &str,
        idempotency_key: &str,
    ) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "controller_device_id": controller_id,
            "controlled_device_id": controlled_id,
            "auth_method": "account_prompt",
            "requested_permissions": {
                "remote_desktop": true,
                "input_control": true,
                "clipboard": false,
                "file_transfer": false,
                "unattended": false,
                "privacy_screen": false,
                "block_local_input": false,
                "require_prompt": true,
                "allow_relay": true
            },
            "idempotency_key": idempotency_key
        }))
        .expect("prompt session body")
    }

    async fn run_prompt_session_lifecycle(
        state: AppState,
        email: &str,
        controller_id: &str,
        controlled_id: &str,
        test_tag: &str,
    ) -> (String, String) {
        let router = build_router(state.clone());
        let tokens = register_account(router.clone(), email).await;
        let access_token = tokens["access_token"].as_str().expect("access token");
        let account_id = tokens["account_id"]
            .as_str()
            .expect("account id")
            .to_owned();

        let controller_key = SigningKey::from_bytes(&[7_u8; 32]);
        let controlled_key = SigningKey::from_bytes(&[9_u8; 32]);
        register_device(
            &state,
            router.clone(),
            access_token,
            &account_id,
            controller_id,
            &controller_key,
        )
        .await;
        register_device(
            &state,
            router.clone(),
            access_token,
            &account_id,
            controlled_id,
            &controlled_key,
        )
        .await;

        let create_body = serde_json::to_vec(&json!({
            "controller_device_id": controller_id,
            "controlled_device_id": controlled_id,
            "auth_method": "account_prompt",
            "requested_permissions": {
                "remote_desktop": true,
                "input_control": true,
                "clipboard": false,
                "file_transfer": false,
                "unattended": false,
                "privacy_screen": true,
                "block_local_input": true,
                "require_prompt": true,
                "allow_relay": true
            },
            "idempotency_key": "create-1"
        }))
        .expect("create body");
        let create_response = signed_request(
            router.clone(),
            "POST",
            "/v1/sessions",
            access_token,
            &account_id,
            controller_id,
            &controller_key,
            &format!("create-nonce-{test_tag}"),
            create_body.clone(),
        )
        .await;
        assert_eq!(create_response.0, StatusCode::CREATED);
        assert_eq!(create_response.1["status"], "waiting_approval");
        assert_eq!(create_response.1["permissions"]["privacy_screen"], false);
        let session_id = create_response.1["session_id"]
            .as_str()
            .expect("session id")
            .to_owned();

        let retry = signed_request(
            router.clone(),
            "POST",
            "/v1/sessions",
            access_token,
            &account_id,
            controller_id,
            &controller_key,
            &format!("create-retry-nonce-{test_tag}"),
            create_body,
        )
        .await;
        assert_eq!(retry.0, StatusCode::OK);
        assert_eq!(retry.1["session_id"], session_id);

        let changed_body = serde_json::to_vec(&json!({
            "controller_device_id": controller_id,
            "controlled_device_id": controlled_id,
            "auth_method": "account_prompt",
            "requested_permissions": {
                "remote_desktop": true,
                "input_control": false,
                "clipboard": false,
                "file_transfer": false,
                "unattended": false,
                "privacy_screen": false,
                "block_local_input": false,
                "require_prompt": true,
                "allow_relay": true
            },
            "idempotency_key": "create-1"
        }))
        .expect("changed body");
        let mismatch = signed_request(
            router.clone(),
            "POST",
            "/v1/sessions",
            access_token,
            &account_id,
            controller_id,
            &controller_key,
            &format!("create-mismatch-nonce-{test_tag}"),
            changed_body,
        )
        .await;
        assert_eq!(mismatch.0, StatusCode::CONFLICT);
        assert_eq!(mismatch.1["code"], "idempotency_binding_mismatch");

        let accept_body = serde_json::to_vec(&json!({
            "actor_type": "device",
            "actor_device_id": controlled_id,
            "actor_role": "controlled",
            "idempotency_key": "accept-1"
        }))
        .expect("accept body");
        let accept = signed_request(
            router,
            "POST",
            &format!("/v1/sessions/{session_id}/accept"),
            access_token,
            &account_id,
            controlled_id,
            &controlled_key,
            &format!("accept-nonce-{test_tag}"),
            accept_body,
        )
        .await;
        assert_eq!(accept.0, StatusCode::OK);
        assert_eq!(accept.1["status"], "accepted");
        (account_id, session_id)
    }

    async fn register_account(router: Router, email: &str) -> Value {
        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/register")
                    .header("content-type", "application/json")
                    .header("x-rctl-protocol-version", VERSION)
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "email": email,
                            "password": "correct horse battery staple",
                            "display_name": "Owner"
                        }))
                        .expect("register body"),
                    ))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::CREATED);
        response_json(response).await
    }

    async fn authenticated_json_request(
        router: Router,
        method: &str,
        path: &str,
        access_token: &str,
        request_id: &str,
        body: Vec<u8>,
    ) -> (StatusCode, Value) {
        authenticated_json_request_with_optional_idempotency(
            router,
            method,
            path,
            access_token,
            request_id,
            body,
            None,
        )
        .await
    }

    async fn authenticated_json_request_with_idempotency(
        router: Router,
        method: &str,
        path: &str,
        access_token: &str,
        request_id: &str,
        body: Vec<u8>,
        idempotency_key: &str,
    ) -> (StatusCode, Value) {
        authenticated_json_request_with_optional_idempotency(
            router,
            method,
            path,
            access_token,
            request_id,
            body,
            Some(idempotency_key),
        )
        .await
    }

    async fn authenticated_json_request_with_optional_idempotency(
        router: Router,
        method: &str,
        path: &str,
        access_token: &str,
        request_id: &str,
        body: Vec<u8>,
        idempotency_key: Option<&str>,
    ) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {access_token}"))
            .header("x-rctl-protocol-version", VERSION)
            .header("x-request-id", request_id);
        if let Some(idempotency_key) = idempotency_key {
            request = request.header("idempotency-key", idempotency_key);
        }
        let response = router
            .oneshot(
                request
                    .body(Body::from(body))
                    .expect("authenticated request"),
            )
            .await
            .expect("authenticated response");
        let status = response.status();
        (status, response_json(response).await)
    }

    fn decrypt_recovery_delivery(
        delivery: &Value,
        claims: &AccessClaims,
        factor_id: &str,
        idempotency_key: &str,
        client_secret: &StaticSecret,
        client_public_key: &[u8; 32],
    ) -> Vec<String> {
        let delivery_id = delivery["delivery_id"].as_str().expect("delivery id");
        let server_public_key: [u8; 32] = URL_SAFE_NO_PAD
            .decode(
                delivery["server_ephemeral_public_key"]
                    .as_str()
                    .expect("server public key"),
            )
            .expect("decode server public key")
            .try_into()
            .expect("server public key length");
        let nonce = URL_SAFE_NO_PAD
            .decode(delivery["nonce"].as_str().expect("delivery nonce"))
            .expect("decode nonce");
        let ciphertext = URL_SAFE_NO_PAD
            .decode(
                delivery["ciphertext"]
                    .as_str()
                    .expect("delivery ciphertext"),
            )
            .expect("decode ciphertext");
        let created_at = delivery["created_at_epoch_millis"]
            .as_u64()
            .expect("delivery creation time");
        let expires_at = delivery["expires_at_epoch_millis"]
            .as_u64()
            .expect("delivery expiry");
        let idempotency_key_hash = sha256(idempotency_key.as_bytes());
        let salt = sha256(&canonical_fields(
            "rctl-recovery-delivery-salt-v1",
            &[
                ("account_id", claims.account_id.as_bytes()),
                ("account_session_id", claims.account_session_id.as_bytes()),
                ("factor_id", factor_id.as_bytes()),
                ("delivery_id", delivery_id.as_bytes()),
                ("idempotency_key_hash", &idempotency_key_hash),
            ],
        ));
        let created = created_at.to_be_bytes();
        let expires = expires_at.to_be_bytes();
        let info = canonical_fields(
            "rctl-recovery-delivery-v1",
            &[
                ("account_id", claims.account_id.as_bytes()),
                ("account_session_id", claims.account_session_id.as_bytes()),
                ("factor_id", factor_id.as_bytes()),
                ("delivery_id", delivery_id.as_bytes()),
                ("client_ephemeral_public_key", client_public_key),
                ("server_ephemeral_public_key", &server_public_key),
                ("created_at_epoch_millis", &created),
                ("expires_at_epoch_millis", &expires),
            ],
        );
        let shared_secret = client_secret.diffie_hellman(&X25519PublicKey::from(server_public_key));
        let mut key = [0_u8; 32];
        Hkdf::<Sha256>::new(Some(&salt), shared_secret.as_bytes())
            .expand(&info, &mut key)
            .expect("derive delivery key");
        let plaintext = ChaCha20Poly1305::new((&key).into())
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &info,
                },
            )
            .expect("decrypt recovery delivery");
        serde_json::from_slice::<Value>(&plaintext).expect("delivery JSON")["recovery_codes"]
            .as_array()
            .expect("recovery code array")
            .iter()
            .map(|value| value.as_str().expect("recovery code").to_owned())
            .collect()
    }

    async fn seed_device_registration(
        state: &AppState,
        access_token: &str,
        account_id: &str,
        device_id: &str,
        key: &SigningKey,
    ) -> Vec<u8> {
        let now = now_epoch_millis();
        let claims = verify_access_token(access_token, &state.config.token_secret, now)
            .expect("test access token");
        let account_updated_at_epoch_millis = state
            .repository
            .load_account_by_id(account_id)
            .await
            .expect("load seeded account")
            .expect("seeded account")
            .updated_at_epoch_millis;
        let challenge_id = format!("test-login-{}", random_token(12));
        let grant_id = random_token(18);
        let grant_secret = random_token(32);
        let binding_hash = sha256(format!("test-binding:{account_id}:{device_id}").as_bytes());
        let public_key = key.verifying_key().to_bytes();
        let grant = format!("{grant_id}.{grant_secret}");
        let issued_challenge = RiskChallenge {
            risk_challenge_id: challenge_id.clone(),
            account_id: account_id.to_owned(),
            device_id: None,
            purpose: "login_mfa".to_owned(),
            operation_binding_hash: binding_hash,
            risk_level: "low".to_owned(),
            required_methods: Vec::new(),
            status: RiskChallengeStatus::Issued,
            attempts_remaining: 5,
            ip_address: None,
            user_agent: None,
            expires_at_epoch_millis: now.saturating_add(300_000),
            created_at_epoch_millis: now,
            verified_at_epoch_millis: None,
            consumed_at_epoch_millis: None,
        };
        let issued_audit = AuditEntry {
            audit_id: format!("audit-{challenge_id}"),
            actor_type: "account".to_owned(),
            actor_account_id: Some(account_id.to_owned()),
            actor_device_id: None,
            actor_role: None,
            actor_service: None,
            target_device_id: None,
            session_id: None,
            action: "mfa_challenge_issued".to_owned(),
            result: "success".to_owned(),
            reason: None,
            metadata: std::collections::BTreeMap::new(),
            request_id: format!("request-{challenge_id}"),
            created_at_epoch_millis: now,
        };
        state
            .repository
            .create_login_challenge(
                &crate::store::LoginChallengeAuthority {
                    challenge: issued_challenge,
                    context: LoginChallengeContext {
                        device_state: LoginDeviceState::PendingEnrollment,
                        device_id: device_id.to_owned(),
                        account_updated_at_epoch_millis,
                        device_public_key: public_key,
                        device_public_key_fingerprint: sha256(&public_key),
                        public_key_id: None,
                        public_key_version: 0,
                        client_nonce: [1; 32],
                        server_nonce: [2; 32],
                        login_request_binding_hash: [3; 32],
                        login_challenge_binding_hash: binding_hash,
                        ip_address_hash: [4; 32],
                        user_agent_hash: [5; 32],
                        required_factors: Vec::new(),
                        trusted_device_id: None,
                        protocol_version: remote_protocol::PROTOCOL_VERSION,
                        issued_at_epoch_millis: now,
                        attempts_limit: 5,
                    },
                },
                &issued_audit,
            )
            .await
            .expect("seed persistent login challenge");
        state
            .repository
            .transact(&mut |database| {
                let challenge = database
                    .risk_challenges
                    .get_mut(&challenge_id)
                    .ok_or(crate::store::StoreError::Unavailable)?;
                challenge.status = RiskChallengeStatus::Consumed;
                challenge.verified_at_epoch_millis = Some(now);
                challenge.consumed_at_epoch_millis = Some(now);
                database.device_enrollment_grants.insert(
                    grant_id.clone(),
                    DeviceEnrollmentGrant {
                        grant_id: grant_id.clone(),
                        grant_secret_hash: sha256(grant_secret.as_bytes()),
                        account_id: account_id.to_owned(),
                        device_id: device_id.to_owned(),
                        device_public_key_fingerprint: sha256(&public_key),
                        login_challenge_id: challenge_id.clone(),
                        login_challenge_binding_hash: binding_hash,
                        trust_proof_type: None,
                        trust_level: None,
                        establish_trust: false,
                        protocol_version: remote_protocol::PROTOCOL_VERSION,
                        issued_account_session_id: claims.account_session_id.clone(),
                        issued_at_epoch_millis: now,
                        expires_at_epoch_millis: now.saturating_add(300_000),
                        consumed_at_epoch_millis: None,
                        registration_request_binding_hash: None,
                        registered_public_key_id: None,
                        registered_trusted_device_id: None,
                    },
                );
                Ok(())
            })
            .await
            .expect("seed device enrollment grant");
        serde_json::to_vec(&json!({
            "device_enrollment_grant": grant,
            "device_id": device_id,
            "display_name": device_id,
            "platform": "ubuntu",
            "os_version": "26.04",
            "arch": "x86_64",
            "role_capabilities": {
                "controller": true,
                "controlled": true,
                "file_transfer": false,
                "unattended": false
            },
            "public_key": encode_public_key(&public_key)
        }))
        .expect("device body")
    }

    async fn register_device(
        state: &AppState,
        router: Router,
        access_token: &str,
        account_id: &str,
        device_id: &str,
        key: &SigningKey,
    ) {
        let body = seed_device_registration(state, access_token, account_id, device_id, key).await;
        let response = signed_request(
            router.clone(),
            "POST",
            "/v1/devices",
            access_token,
            account_id,
            device_id,
            key,
            &format!("register-{device_id}"),
            body.clone(),
        )
        .await;
        assert_eq!(response.0, StatusCode::CREATED, "{}", response.1);
        assert_eq!(response.1["platform"], "ubuntu");
        assert_eq!(response.1["os_version"], "26.04");
        assert_eq!(response.1["role_capabilities"]["controlled"], true);
        assert_eq!(response.1["role_capabilities"]["file_transfer"], false);
        assert_eq!(response.1["role_capabilities"]["unattended"], false);
        let replay = signed_request(
            router,
            "POST",
            "/v1/devices",
            access_token,
            account_id,
            device_id,
            key,
            &format!("register-replay-{device_id}"),
            body,
        )
        .await;
        assert_eq!(replay.0, StatusCode::OK, "{}", replay.1);
        assert_eq!(replay.1["public_key_id"], response.1["public_key_id"]);
    }

    #[allow(clippy::too_many_arguments)]
    async fn signed_request(
        router: Router,
        method: &str,
        path: &str,
        access_token: &str,
        account_id: &str,
        device_id: &str,
        key: &SigningKey,
        nonce: &str,
        body: Vec<u8>,
    ) -> (StatusCode, Value) {
        let request_id = format!("request-{nonce}");
        let timestamp = now_epoch_millis();
        let signature = sign_device_request_for_test(
            key,
            method,
            path,
            &body,
            &request_id,
            device_id,
            account_id,
            timestamp,
            nonce,
        );
        let response = router
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {access_token}"))
                    .header("x-rctl-protocol-version", VERSION)
                    .header("x-request-id", &request_id)
                    .header("x-rctl-device-id", device_id)
                    .header("x-rctl-timestamp", timestamp.to_string())
                    .header("x-rctl-api-nonce", nonce)
                    .header("x-rctl-device-signature", signature)
                    .body(Body::from(body))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status();
        (status, response_json(response).await)
    }

    async fn response_json(response: Response) -> Value {
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("response body")
            .to_bytes();
        serde_json::from_slice::<Value>(&bytes)
            .unwrap_or_else(|_| json!({ "raw": URL_SAFE_NO_PAD.encode(bytes) }))
    }
}
