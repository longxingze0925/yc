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
    use ed25519_dalek::{Signer, SigningKey};
    use hkdf::Hkdf;
    use http_body_util::BodyExt;
    use serde_json::{json, Value};
    use sha2::Sha256;
    use tower::ServiceExt;
    use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

    use super::*;
    use crate::security::{
        canonical_fields, canonical_request_body_hash, encode_base64url, encode_public_key,
        now_epoch_millis, random_token, sha256, totp_code, verify_access_token, verify_password,
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
    async fn device_registration_rejects_each_grant_authority_mismatch_without_partial_state() {
        for (index, case) in [
            "wrong_secret",
            "cross_account",
            "cross_device",
            "cross_fingerprint",
            "cross_challenge",
            "cross_session",
            "expired",
        ]
        .into_iter()
        .enumerate()
        {
            let state = AppState::for_test();
            let router = build_router(state.clone());
            let tokens = register_account(
                router.clone(),
                &format!("grant-mismatch-{index}@example.com"),
            )
            .await;
            let access_token = tokens["access_token"].as_str().expect("access token");
            let account_id = tokens["account_id"].as_str().expect("account id");
            let device_id = format!("grant-mismatch-{index}");
            let key = SigningKey::from_bytes(&[71_u8.saturating_add(index as u8); 32]);
            let mut body =
                seed_device_registration(&state, access_token, account_id, &device_id, &key).await;
            let mut body_json: Value = serde_json::from_slice(&body).expect("registration body");
            let grant_value = body_json["device_enrollment_grant"]
                .as_str()
                .expect("enrollment grant")
                .to_owned();
            let grant_id = grant_value
                .split_once('.')
                .expect("grant id and secret")
                .0
                .to_owned();
            if case == "wrong_secret" {
                body_json["device_enrollment_grant"] =
                    Value::String(format!("{grant_id}.wrong-secret"));
                body = serde_json::to_vec(&body_json).expect("wrong-secret body");
            } else {
                state
                    .repository
                    .transact(&mut |database| {
                        let grant = database
                            .device_enrollment_grants
                            .get_mut(&grant_id)
                            .ok_or(crate::store::StoreError::Unavailable)?;
                        match case {
                            "cross_account" => grant.account_id = "other-account".to_owned(),
                            "cross_device" => grant.device_id = "other-device".to_owned(),
                            "cross_fingerprint" => grant.device_public_key_fingerprint = [9; 32],
                            "cross_challenge" => {
                                grant.login_challenge_id = "other-challenge".to_owned()
                            }
                            "cross_session" => {
                                grant.issued_account_session_id = "other-session".to_owned()
                            }
                            "expired" => {
                                grant.issued_at_epoch_millis =
                                    grant.issued_at_epoch_millis.saturating_sub(300_000);
                                grant.expires_at_epoch_millis =
                                    grant.issued_at_epoch_millis.saturating_add(1);
                            }
                            _ => unreachable!("covered mismatch case"),
                        }
                        Ok(())
                    })
                    .await
                    .expect("mutate enrollment grant authority");
            }
            let audit_count_before = {
                let mut count = 0;
                state
                    .repository
                    .read(&mut |database| count = database.audit_logs.len())
                    .await;
                count
            };

            let response = signed_request(
                router,
                "POST",
                "/v1/devices",
                access_token,
                account_id,
                &device_id,
                &key,
                &format!("grant-mismatch-{case}"),
                body,
            )
            .await;
            assert_eq!(response.0, StatusCode::FORBIDDEN, "{case}: {}", response.1);
            assert_eq!(
                response.1["code"], "device_enrollment_grant_invalid",
                "{case}"
            );
            state
                .repository
                .read(&mut |database| {
                    assert!(!database.devices.contains_key(&device_id), "{case}");
                    assert!(database.trusted_controller_devices.is_empty(), "{case}");
                    assert_eq!(database.audit_logs.len(), audit_count_before, "{case}");
                    assert!(database.device_enrollment_grants[&grant_id]
                        .consumed_at_epoch_millis
                        .is_none());
                })
                .await;
        }
    }

    #[tokio::test]
    async fn trusted_device_registration_uses_factor_specific_fixed_ttl_and_replays_once() {
        for (index, factor) in ["totp", "recovery_code"].into_iter().enumerate() {
            let state = AppState::for_test();
            let router = build_router(state.clone());
            let tokens = register_account(
                router.clone(),
                &format!("trusted-registration-{factor}@example.com"),
            )
            .await;
            let access_token = tokens["access_token"].as_str().expect("access token");
            let account_id = tokens["account_id"].as_str().expect("account id");
            let device_id = format!("trusted-registration-{factor}");
            let key = SigningKey::from_bytes(&[101_u8.saturating_add(index as u8); 32]);
            let body = seed_trusted_device_registration(
                &state,
                access_token,
                account_id,
                &device_id,
                &key,
                factor,
            )
            .await;

            let created = signed_request(
                router.clone(),
                "POST",
                "/v1/devices",
                access_token,
                account_id,
                &device_id,
                &key,
                &format!("trusted-registration-{factor}"),
                body.clone(),
            )
            .await;
            assert_eq!(created.0, StatusCode::CREATED, "{}", created.1);
            let mut first_counts = (0, 0);
            state
                .repository
                .read(&mut |database| {
                    let trust = database
                        .trusted_controller_devices
                        .values()
                        .find(|trust| trust.controller_device_id == device_id)
                        .expect("registered trusted controller");
                    let expected_ttl = if factor == "totp" {
                        30 * 24 * 60 * 60 * 1_000
                    } else {
                        24 * 60 * 60 * 1_000
                    };
                    assert_eq!(
                        trust.expires_at_epoch_millis - trust.created_at_epoch_millis,
                        expected_ttl
                    );
                    assert_eq!(
                        trust.trust_proof_type,
                        if factor == "totp" {
                            "device_signature_and_mfa"
                        } else {
                            "device_signature_and_recovery_code"
                        }
                    );
                    first_counts = (
                        database.trusted_controller_devices.len(),
                        database.audit_logs.len(),
                    );
                    assert_eq!(
                        database
                            .audit_logs
                            .iter()
                            .filter(|audit| audit.action == "trusted_device_added")
                            .count(),
                        1
                    );
                })
                .await;

            let replay = signed_request(
                router,
                "POST",
                "/v1/devices",
                access_token,
                account_id,
                &device_id,
                &key,
                &format!("trusted-registration-replay-{factor}"),
                body,
            )
            .await;
            assert_eq!(replay.0, StatusCode::OK, "{}", replay.1);
            assert_eq!(replay.1["public_key_id"], created.1["public_key_id"]);
            state
                .repository
                .read(&mut |database| {
                    assert_eq!(
                        (
                            database.trusted_controller_devices.len(),
                            database.audit_logs.len(),
                        ),
                        first_counts
                    );
                })
                .await;
        }
    }

    #[tokio::test]
    async fn device_queries_and_patch_enforce_account_signature_and_unbind_boundaries() {
        let state = AppState::for_test();
        let router = build_router(state.clone());
        let owner = register_account(router.clone(), "device-owner@example.com").await;
        let owner_token = owner["access_token"].as_str().expect("owner access token");
        let owner_account = owner["account_id"].as_str().expect("owner account id");
        let owner_key = SigningKey::from_bytes(&[81; 32]);
        let target_key = SigningKey::from_bytes(&[82; 32]);
        register_device(
            &state,
            router.clone(),
            owner_token,
            owner_account,
            "owner-controller",
            &owner_key,
        )
        .await;
        register_device(
            &state,
            router.clone(),
            owner_token,
            owner_account,
            "owner-target",
            &target_key,
        )
        .await;

        let foreign = register_account(router.clone(), "device-foreign@example.com").await;
        let foreign_token = foreign["access_token"]
            .as_str()
            .expect("foreign access token");
        let foreign_account = foreign["account_id"].as_str().expect("foreign account id");
        let foreign_key = SigningKey::from_bytes(&[83; 32]);
        register_device(
            &state,
            router.clone(),
            foreign_token,
            foreign_account,
            "foreign-target",
            &foreign_key,
        )
        .await;

        let listed = authenticated_json_request(
            router.clone(),
            "GET",
            "/v1/devices",
            owner_token,
            "owner-device-list",
            Vec::new(),
        )
        .await;
        assert_eq!(listed.0, StatusCode::OK, "{}", listed.1);
        let listed_ids = listed.1["devices"]
            .as_array()
            .expect("device list")
            .iter()
            .map(|device| device["device_id"].as_str().expect("device id"))
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            listed_ids,
            std::collections::BTreeSet::from(["owner-controller", "owner-target"])
        );

        let hidden = authenticated_json_request(
            router.clone(),
            "GET",
            "/v1/devices/foreign-target",
            owner_token,
            "owner-foreign-device",
            Vec::new(),
        )
        .await;
        assert_eq!(hidden.0, StatusCode::NOT_FOUND, "{}", hidden.1);

        let unsigned = authenticated_json_request(
            router.clone(),
            "PATCH",
            "/v1/devices/owner-target",
            owner_token,
            "unsigned-device-patch",
            serde_json::to_vec(&json!({ "display_name": "Unsigned" })).unwrap(),
        )
        .await;
        assert_eq!(unsigned.0, StatusCode::BAD_REQUEST, "{}", unsigned.1);
        assert_eq!(unsigned.1["code"], "missing_device_signature_header");

        let cross_account = signed_request(
            router.clone(),
            "PATCH",
            "/v1/devices/foreign-target",
            owner_token,
            owner_account,
            "owner-controller",
            &owner_key,
            "cross-account-device-patch",
            serde_json::to_vec(&json!({ "action": "disable" })).unwrap(),
        )
        .await;
        assert_eq!(
            cross_account.0,
            StatusCode::NOT_FOUND,
            "{}",
            cross_account.1
        );

        let unbound = signed_request(
            router,
            "PATCH",
            "/v1/devices/owner-target",
            owner_token,
            owner_account,
            "owner-controller",
            &owner_key,
            "owner-target-unbind",
            serde_json::to_vec(&json!({ "action": "unbind" })).unwrap(),
        )
        .await;
        assert_eq!(unbound.0, StatusCode::OK, "{}", unbound.1);
        state
            .repository
            .read(&mut |database| {
                let target = &database.devices["owner-target"];
                assert_eq!(target.status, DeviceLifecycleStatus::Unbound);
                assert!(target.public_key_revoked_at_epoch_millis.is_some());
                assert!(database.audit_logs.iter().any(|audit| {
                    audit.action == "device_unregistered"
                        && audit.target_device_id.as_deref() == Some("owner-target")
                }));
                assert!(database.audit_logs.iter().any(|audit| {
                    audit.action == "device_public_key_revoked"
                        && audit.reason.as_deref() == Some("device_unbound")
                }));
                assert!(database
                    .account_sessions
                    .values()
                    .filter(|session| session.account_id == owner_account)
                    .all(|session| session.revoked_at_epoch_millis.is_some()));
                assert_eq!(
                    database.devices["foreign-target"].status,
                    DeviceLifecycleStatus::Offline
                );
            })
            .await;
    }

    #[tokio::test]
    async fn device_key_rotation_requires_new_key_proof_and_operation_bound_step_up() {
        let state = AppState::for_test();
        let router = build_router(state.clone());
        let tokens = register_account(router.clone(), "rotation-gates@example.com").await;
        let access_token = tokens["access_token"].as_str().expect("access token");
        let account_id = tokens["account_id"].as_str().expect("account id");
        let current_key = SigningKey::from_bytes(&[91; 32]);
        let new_key = SigningKey::from_bytes(&[92; 32]);
        register_device(
            &state,
            router.clone(),
            access_token,
            account_id,
            "rotation-gated-device",
            &current_key,
        )
        .await;
        let mut current = None;
        state
            .repository
            .read(&mut |database| current = database.devices.get("rotation-gated-device").cloned())
            .await;
        let current = current.expect("registered rotation device");
        let path = "/v1/devices/rotation-gated-device/keys/rotate";
        let new_public_key = new_key.verifying_key().to_bytes();

        let invalid_proof = signed_request(
            router.clone(),
            "POST",
            path,
            access_token,
            account_id,
            "rotation-gated-device",
            &current_key,
            "rotation-invalid-new-key-proof",
            serde_json::to_vec(&json!({
                "current_public_key_id": current.public_key_id.clone(),
                "current_public_key_version": current.public_key_version,
                "new_public_key": encode_public_key(&new_public_key),
                "new_public_key_proof": "invalid"
            }))
            .unwrap(),
        )
        .await;
        assert_eq!(
            invalid_proof.0,
            StatusCode::FORBIDDEN,
            "{}",
            invalid_proof.1
        );
        assert_eq!(invalid_proof.1["code"], "new_device_key_proof_failed");

        let version = current.public_key_version.to_be_bytes();
        let proof_payload = canonical_fields(
            "rctl-device-key-rotation-v1",
            &[
                ("account_id", account_id.as_bytes()),
                ("device_id", b"rotation-gated-device"),
                ("current_public_key_id", current.public_key_id.as_bytes()),
                ("current_public_key_version", &version),
                ("new_public_key", &new_public_key),
            ],
        );
        let proof = URL_SAFE_NO_PAD.encode(new_key.sign(&sha256(&proof_payload)).to_bytes());
        let missing_step_up = signed_request(
            router,
            "POST",
            path,
            access_token,
            account_id,
            "rotation-gated-device",
            &current_key,
            "rotation-missing-step-up",
            serde_json::to_vec(&json!({
                "current_public_key_id": current.public_key_id.clone(),
                "current_public_key_version": current.public_key_version,
                "new_public_key": encode_public_key(&new_public_key),
                "new_public_key_proof": proof
            }))
            .unwrap(),
        )
        .await;
        assert_eq!(
            missing_step_up.0,
            StatusCode::FORBIDDEN,
            "{}",
            missing_step_up.1
        );
        assert_eq!(missing_step_up.1["code"], "step_up_required");
        state
            .repository
            .read(&mut |database| {
                let unchanged = &database.devices["rotation-gated-device"];
                assert_eq!(unchanged.public_key_id, current.public_key_id);
                assert_eq!(unchanged.public_key_version, 1);
                assert_eq!(unchanged.public_key, current_key.verifying_key().to_bytes());
                assert!(!database
                    .audit_logs
                    .iter()
                    .any(|audit| audit.action == "device_public_key_rotated"));
            })
            .await;
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
    async fn account_prompt_session_cannot_target_another_accounts_device() {
        let state = AppState::for_test();
        let router = build_router(state.clone());
        let controller_tokens =
            register_account(router.clone(), "controller-owner@example.com").await;
        let controlled_tokens =
            register_account(router.clone(), "controlled-owner@example.com").await;
        let controller_access = controller_tokens["access_token"].as_str().unwrap();
        let controller_account = controller_tokens["account_id"].as_str().unwrap();
        let controlled_access = controlled_tokens["access_token"].as_str().unwrap();
        let controlled_account = controlled_tokens["account_id"].as_str().unwrap();
        let controller_key = SigningKey::from_bytes(&[41_u8; 32]);
        let controlled_key = SigningKey::from_bytes(&[43_u8; 32]);
        register_device(
            &state,
            router.clone(),
            controller_access,
            controller_account,
            "account-controller",
            &controller_key,
        )
        .await;
        register_device(
            &state,
            router.clone(),
            controlled_access,
            controlled_account,
            "other-account-controlled",
            &controlled_key,
        )
        .await;

        let response = signed_request(
            router,
            "POST",
            "/v1/sessions",
            controller_access,
            controller_account,
            "account-controller",
            &controller_key,
            "cross-account-prompt",
            prompt_session_body(
                "account-controller",
                "other-account-controlled",
                "cross-account-prompt",
            ),
        )
        .await;

        assert_eq!(response.0, StatusCode::NOT_FOUND);
        assert_eq!(response.1["code"], "controlled_device_not_found");
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
    async fn postgres_trusted_registration_persists_fixed_ttl_and_replays_once() {
        let database_url = std::env::var("API_TEST_DATABASE_URL")
            .expect("API_TEST_DATABASE_URL must point to an isolated migrated database");
        for (index, factor) in ["totp", "recovery_code"].into_iter().enumerate() {
            let repository = Arc::new(
                PostgresRepository::connect(&database_url, [0; 32])
                    .await
                    .expect("connect trusted-registration PostgreSQL repository"),
            );
            let state = AppState::new(
                repository,
                AppConfig::for_test(),
                SignalNotifier::disabled(),
            );
            let router = build_router(state.clone());
            let suffix = crate::security::random_uuid_v4();
            let tokens = register_account(
                router.clone(),
                &format!("postgres-trusted-registration-{factor}-{suffix}@example.com"),
            )
            .await;
            let access_token = tokens["access_token"].as_str().expect("access token");
            let account_id = tokens["account_id"].as_str().expect("account id");
            let device_id = format!("postgres-trusted-registration-{factor}-{suffix}");
            let key = SigningKey::from_bytes(&sha256(
                format!("postgres-trusted-key-{index}-{suffix}").as_bytes(),
            ));
            let body = seed_trusted_device_registration(
                &state,
                access_token,
                account_id,
                &device_id,
                &key,
                factor,
            )
            .await;
            let created = signed_request(
                router.clone(),
                "POST",
                "/v1/devices",
                access_token,
                account_id,
                &device_id,
                &key,
                &format!("postgres-trusted-create-{factor}-{suffix}"),
                body.clone(),
            )
            .await;
            assert_eq!(created.0, StatusCode::CREATED, "{}", created.1);
            let replay = signed_request(
                router,
                "POST",
                "/v1/devices",
                access_token,
                account_id,
                &device_id,
                &key,
                &format!("postgres-trusted-replay-{factor}-{suffix}"),
                body,
            )
            .await;
            assert_eq!(replay.0, StatusCode::OK, "{}", replay.1);
            assert_eq!(replay.1["public_key_id"], created.1["public_key_id"]);

            let restarted = PostgresRepository::connect(&database_url, [0; 32])
                .await
                .expect("restart trusted-registration PostgreSQL repository");
            let trusts = restarted
                .list_trusted_devices_for_account(account_id)
                .await
                .expect("load persisted trusted registration");
            assert_eq!(trusts.len(), 1);
            let expected_ttl = if factor == "totp" {
                30 * 24 * 60 * 60 * 1_000
            } else {
                24 * 60 * 60 * 1_000
            };
            assert_eq!(
                trusts[0].expires_at_epoch_millis - trusts[0].created_at_epoch_millis,
                expected_ttl
            );
            let (client, connection) =
                tokio_postgres::connect(&database_url, tokio_postgres::NoTls)
                    .await
                    .expect("connect trusted-registration assertion client");
            tokio::spawn(async move {
                connection
                    .await
                    .expect("trusted-registration assertion connection");
            });
            let counts = client
                .query_one(
                    "SELECT
                        (SELECT count(*) FROM trusted_controller_devices
                         WHERE account_id=$1 AND controller_device_id=$2) AS trusts,
                        (SELECT count(*) FROM audit_logs
                         WHERE actor_account_id=$1 AND target_device_id=$2
                           AND action='trusted_device_added') AS trust_audits",
                    &[&account_id, &device_id],
                )
                .await
                .expect("query trusted-registration counts");
            assert_eq!(counts.get::<_, i64>("trusts"), 1);
            assert_eq!(counts.get::<_, i64>("trust_audits"), 1);
            cleanup_postgres_account(&database_url, account_id).await;
        }
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
                        required_methods: vec!["totp".to_owned(), "recovery_code".to_owned()],
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
        let old_key_rejected = signed_request(
            router.clone(),
            "PATCH",
            &format!("/v1/devices/{target_id}"),
            &access_token,
            &account_id,
            &actor_id,
            &old_key,
            &format!("postgres-old-key-rejected-{suffix}"),
            serde_json::to_vec(&json!({ "display_name": "Must Not Apply" })).unwrap(),
        )
        .await;
        assert_eq!(
            old_key_rejected.0,
            StatusCode::FORBIDDEN,
            "{}",
            old_key_rejected.1
        );
        assert_eq!(old_key_rejected.1["code"], "invalid_device_signature");
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
    async fn postgres_refresh_preserves_mfa_snapshot_across_instances_and_audits_each_rotation() {
        let database_url = std::env::var("API_TEST_DATABASE_URL")
            .expect("API_TEST_DATABASE_URL must point to an isolated migrated database");
        let mfa_key = [0_u8; 32];
        let setup_repository = Arc::new(
            PostgresRepository::connect(&database_url, mfa_key)
                .await
                .expect("connect setup PostgreSQL repository"),
        );
        let setup_state = AppState::new(
            setup_repository.clone(),
            AppConfig::for_test(),
            SignalNotifier::disabled(),
        );
        let setup_router = build_router(setup_state.clone());
        let suffix = crate::security::random_uuid_v4();
        let email = format!("postgres-refresh-snapshot-{suffix}@example.com");
        let registered = register_account(setup_router.clone(), &email).await;
        let account_id = registered["account_id"]
            .as_str()
            .expect("registered account id")
            .to_owned();
        let false_refresh_token = registered["refresh_token"]
            .as_str()
            .expect("registered refresh token")
            .to_owned();
        let false_original_claims = verify_access_token(
            registered["access_token"]
                .as_str()
                .expect("registered access token"),
            &setup_state.config.token_secret,
            now_epoch_millis(),
        )
        .expect("registered access claims");
        assert!(!false_original_claims.mfa_verified);

        let mfa_secret = "JBSWY3DPEHPK3PXP";
        let factor_id = format!("refresh-factor-{suffix}");
        setup_repository
            .transact(&mut |database| {
                database.mfa_factors.insert(
                    factor_id.clone(),
                    MfaFactor {
                        factor_id: factor_id.clone(),
                        account_id: account_id.clone(),
                        secret_base32: mfa_secret.to_owned(),
                        active: true,
                        last_used_counter: None,
                        created_at_epoch_millis: now_epoch_millis(),
                    },
                );
                Ok(())
            })
            .await
            .expect("seed active PostgreSQL MFA factor");

        let login_key = SigningKey::from_bytes(&sha256(
            format!("postgres-refresh-login-key-{suffix}").as_bytes(),
        ));
        let (totp, _) = totp_code(mfa_secret, now_epoch_millis()).expect("generate login TOTP");
        let (login_challenge, mfa_login) = login_account_via_challenge(
            setup_router,
            &email,
            &format!("refresh-login-device-{suffix}"),
            &login_key,
            51,
            Some(("totp", &totp)),
        )
        .await;
        assert_eq!(
            login_challenge["required_factors"],
            json!(["totp", "recovery_code"])
        );
        let true_refresh_token = mfa_login["refresh_token"]
            .as_str()
            .expect("MFA refresh token")
            .to_owned();
        let true_original_claims = verify_access_token(
            mfa_login["access_token"]
                .as_str()
                .expect("MFA access token"),
            &setup_state.config.token_secret,
            now_epoch_millis(),
        )
        .expect("MFA access claims");
        assert!(true_original_claims.mfa_verified);

        let second_repository = Arc::new(
            PostgresRepository::connect(&database_url, mfa_key)
                .await
                .expect("connect second PostgreSQL repository"),
        );
        let second_router = build_router(AppState::new(
            second_repository,
            AppConfig::for_test(),
            SignalNotifier::disabled(),
        ));
        let (false_first_status, false_first) = post_json_request(
            second_router.clone(),
            "/v1/auth/refresh",
            &format!("false-first-refresh-{suffix}"),
            json!({ "refresh_token": false_refresh_token }),
        )
        .await;
        assert_eq!(false_first_status, StatusCode::OK, "{false_first}");
        let (true_first_status, true_first) = post_json_request(
            second_router,
            "/v1/auth/refresh",
            &format!("true-first-refresh-{suffix}"),
            json!({ "refresh_token": true_refresh_token }),
        )
        .await;
        assert_eq!(true_first_status, StatusCode::OK, "{true_first}");
        let false_first_claims = verify_access_token(
            false_first["access_token"]
                .as_str()
                .expect("first false access token"),
            &setup_state.config.token_secret,
            now_epoch_millis(),
        )
        .expect("first false access claims");
        let true_first_claims = verify_access_token(
            true_first["access_token"]
                .as_str()
                .expect("first true access token"),
            &setup_state.config.token_secret,
            now_epoch_millis(),
        )
        .expect("first true access claims");
        assert!(!false_first_claims.mfa_verified);
        assert!(true_first_claims.mfa_verified);

        let third_repository = Arc::new(
            PostgresRepository::connect(&database_url, mfa_key)
                .await
                .expect("connect restarted PostgreSQL repository"),
        );
        let third_router = build_router(AppState::new(
            third_repository,
            AppConfig::for_test(),
            SignalNotifier::disabled(),
        ));
        let (false_second_status, false_second) = post_json_request(
            third_router.clone(),
            "/v1/auth/refresh",
            &format!("false-second-refresh-{suffix}"),
            json!({
                "refresh_token": false_first["refresh_token"]
                    .as_str()
                    .expect("first false refresh token")
            }),
        )
        .await;
        assert_eq!(false_second_status, StatusCode::OK, "{false_second}");
        let (true_second_status, true_second) = post_json_request(
            third_router,
            "/v1/auth/refresh",
            &format!("true-second-refresh-{suffix}"),
            json!({
                "refresh_token": true_first["refresh_token"]
                    .as_str()
                    .expect("first true refresh token")
            }),
        )
        .await;
        assert_eq!(true_second_status, StatusCode::OK, "{true_second}");
        let false_second_claims = verify_access_token(
            false_second["access_token"]
                .as_str()
                .expect("second false access token"),
            &setup_state.config.token_secret,
            now_epoch_millis(),
        )
        .expect("second false access claims");
        let true_second_claims = verify_access_token(
            true_second["access_token"]
                .as_str()
                .expect("second true access token"),
            &setup_state.config.token_secret,
            now_epoch_millis(),
        )
        .expect("second true access claims");
        assert!(!false_second_claims.mfa_verified);
        assert!(true_second_claims.mfa_verified);

        let (client, connection) = tokio_postgres::connect(&database_url, tokio_postgres::NoTls)
            .await
            .expect("connect PostgreSQL refresh assertion client");
        tokio::spawn(async move {
            connection
                .await
                .expect("PostgreSQL refresh assertion connection");
        });
        let session_rows = client
            .query(
                "SELECT account_session_id, mfa_verified, revoked_reason
                 FROM account_sessions WHERE account_id=$1",
                &[&account_id],
            )
            .await
            .expect("query PostgreSQL refresh sessions");
        assert_eq!(session_rows.len(), 6);
        for (claims, expected_mfa, expected_revoked_reason) in [
            (&false_original_claims, false, Some("refresh_replay")),
            (&true_original_claims, true, Some("refresh_replay")),
            (&false_first_claims, false, Some("refresh_replay")),
            (&true_first_claims, true, Some("refresh_replay")),
            (&false_second_claims, false, None),
            (&true_second_claims, true, None),
        ] {
            let row = session_rows
                .iter()
                .find(|row| row.get::<_, String>("account_session_id") == claims.account_session_id)
                .expect("expected PostgreSQL account session");
            assert_eq!(row.get::<_, bool>("mfa_verified"), expected_mfa);
            assert_eq!(
                row.get::<_, Option<String>>("revoked_reason").as_deref(),
                expected_revoked_reason
            );
        }

        let revocation_rows = client
            .query(
                "SELECT reason, metadata->>'account_session_id' AS account_session_id,
                        metadata->>'revoked_reason' AS metadata_reason
                 FROM audit_logs
                 WHERE actor_account_id=$1 AND action='account_session_revoked'
                   AND reason='refresh_replay'",
                &[&account_id],
            )
            .await
            .expect("query per-session refresh revocation audits");
        assert_eq!(revocation_rows.len(), 4);
        let mut audited_session_ids = revocation_rows
            .iter()
            .map(|row| {
                assert_eq!(row.get::<_, String>("reason"), "refresh_replay");
                assert_eq!(row.get::<_, String>("metadata_reason"), "refresh_replay");
                row.get::<_, String>("account_session_id")
            })
            .collect::<Vec<_>>();
        audited_session_ids.sort();
        let mut expected_audited_session_ids = vec![
            false_original_claims.account_session_id,
            true_original_claims.account_session_id,
            false_first_claims.account_session_id,
            true_first_claims.account_session_id,
        ];
        expected_audited_session_ids.sort();
        assert_eq!(audited_session_ids, expected_audited_session_ids);
        let refresh_audits: i64 = client
            .query_one(
                "SELECT count(*) FROM audit_logs
                 WHERE actor_account_id=$1 AND action='token_refreshed'",
                &[&account_id],
            )
            .await
            .expect("count top-level refresh audits")
            .get(0);
        assert_eq!(refresh_audits, 4);
    }

    #[tokio::test]
    #[ignore = "requires a migrated PostgreSQL database in API_TEST_DATABASE_URL"]
    async fn postgres_account_revocation_prevents_refresh_resurrection_across_instances() {
        let database_url = std::env::var("API_TEST_DATABASE_URL")
            .expect("API_TEST_DATABASE_URL must point to an isolated migrated database");
        let mfa_key = [0_u8; 32];
        let setup_repository = Arc::new(
            PostgresRepository::connect(&database_url, mfa_key)
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
        let email = format!("postgres-refresh-revocation-{suffix}@example.com");
        let registered = register_account(setup_router, &email).await;
        let account_id = registered["account_id"]
            .as_str()
            .expect("registered account id")
            .to_owned();
        let original_claims = verify_access_token(
            registered["access_token"]
                .as_str()
                .expect("registered access token"),
            &setup_state.config.token_secret,
            now_epoch_millis(),
        )
        .expect("registered access claims");

        let security_repository = Arc::new(
            PostgresRepository::connect(&database_url, mfa_key)
                .await
                .expect("connect security PostgreSQL repository"),
        );
        let security_state = AppState::new(
            security_repository,
            AppConfig::for_test(),
            SignalNotifier::disabled(),
        );
        let security_router = build_router(security_state.clone());
        let (rotated_status, rotated) = post_json_request(
            security_router.clone(),
            "/v1/auth/refresh",
            &format!("pre-revocation-refresh-{suffix}"),
            json!({
                "refresh_token": registered["refresh_token"]
                    .as_str()
                    .expect("registered refresh token")
            }),
        )
        .await;
        assert_eq!(rotated_status, StatusCode::OK, "{rotated}");
        let rotated_access_token = rotated["access_token"]
            .as_str()
            .expect("rotated access token")
            .to_owned();
        let rotated_refresh_token = rotated["refresh_token"]
            .as_str()
            .expect("rotated refresh token")
            .to_owned();
        let rotated_claims = verify_access_token(
            &rotated_access_token,
            &security_state.config.token_secret,
            now_epoch_millis(),
        )
        .expect("rotated access claims");

        let login_key = SigningKey::from_bytes(&sha256(
            format!("postgres-revocation-login-key-{suffix}").as_bytes(),
        ));
        let (_, second_login) = login_account_via_challenge(
            security_router.clone(),
            &email,
            &format!("revocation-login-device-{suffix}"),
            &login_key,
            61,
            None,
        )
        .await;
        let second_refresh_token = second_login["refresh_token"]
            .as_str()
            .expect("second login refresh token")
            .to_owned();
        let second_login_claims = verify_access_token(
            second_login["access_token"]
                .as_str()
                .expect("second login access token"),
            &security_state.config.token_secret,
            now_epoch_millis(),
        )
        .expect("second login access claims");
        assert!(!second_login_claims.mfa_verified);

        let device_id = format!("password-change-device-{suffix}");
        let device_key = SigningKey::from_bytes(&sha256(
            format!("postgres-password-device-key-{suffix}").as_bytes(),
        ));
        register_device(
            &security_state,
            security_router.clone(),
            &rotated_access_token,
            &account_id,
            &device_id,
            &device_key,
        )
        .await;

        let password_request_id = format!("password-change-{suffix}");
        let password_body = serde_json::to_vec(&json!({
            "current_password": "correct horse battery staple",
            "new_password": "new correct horse battery staple"
        }))
        .expect("password change body");
        let password_body_hash =
            canonical_request_body_hash(&password_body, Some("application/json"))
                .expect("canonical password change body hash");
        let (challenge_status, challenge) = authenticated_json_request(
            security_router.clone(),
            "POST",
            "/v1/auth/risk-challenge",
            &rotated_access_token,
            &format!("issue-password-challenge-{suffix}"),
            serde_json::to_vec(&json!({
                "purpose": "password_change",
                "device_id": device_id,
                "method": "PATCH",
                "path": "/v1/me/password",
                "body_hash": crate::security::hex_encode(&password_body_hash),
                "request_id": password_request_id
            }))
            .expect("password challenge body"),
        )
        .await;
        assert_eq!(challenge_status, StatusCode::CREATED, "{challenge}");
        assert_eq!(challenge["required_methods"], json!(["password"]));
        let challenge_id = challenge["risk_challenge_id"]
            .as_str()
            .expect("password challenge id")
            .to_owned();
        let (verify_status, verified) = authenticated_json_request(
            security_router.clone(),
            "POST",
            &format!("/v1/auth/risk-challenge/{challenge_id}/verify"),
            &rotated_access_token,
            &format!("verify-password-challenge-{suffix}"),
            serde_json::to_vec(&json!({
                "factor": "password",
                "code": "correct horse battery staple"
            }))
            .expect("password verification body"),
        )
        .await;
        assert_eq!(verify_status, StatusCode::OK, "{verified}");
        let step_up_token = verified["step_up_token"]
            .as_str()
            .expect("password step-up token");
        let password_response = security_router
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/v1/me/password")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {rotated_access_token}"))
                    .header("x-rctl-protocol-version", VERSION)
                    .header("x-request-id", &password_request_id)
                    .header("x-rctl-risk-challenge-id", &challenge_id)
                    .header("x-rctl-step-up-token", step_up_token)
                    .body(Body::from(password_body))
                    .expect("password change request"),
            )
            .await
            .expect("password change response");
        assert_eq!(password_response.status(), StatusCode::NO_CONTENT);
        assert!(password_response
            .into_body()
            .collect()
            .await
            .expect("password change response body")
            .to_bytes()
            .is_empty());

        let restarted_repository = Arc::new(
            PostgresRepository::connect(&database_url, mfa_key)
                .await
                .expect("connect post-revocation PostgreSQL repository"),
        );
        let restarted_router = build_router(AppState::new(
            restarted_repository,
            AppConfig::for_test(),
            SignalNotifier::disabled(),
        ));
        for (tag, refresh_token) in [
            ("rotated", rotated_refresh_token),
            ("second-login", second_refresh_token),
        ] {
            let (status, body) = post_json_request(
                restarted_router.clone(),
                "/v1/auth/refresh",
                &format!("post-revocation-{tag}-{suffix}"),
                json!({ "refresh_token": refresh_token }),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        }

        let (client, connection) = tokio_postgres::connect(&database_url, tokio_postgres::NoTls)
            .await
            .expect("connect PostgreSQL revocation assertion client");
        tokio::spawn(async move {
            connection
                .await
                .expect("PostgreSQL revocation assertion connection");
        });
        let session_rows = client
            .query(
                "SELECT account_session_id, revoked_reason
                 FROM account_sessions WHERE account_id=$1",
                &[&account_id],
            )
            .await
            .expect("query revoked PostgreSQL sessions");
        assert_eq!(session_rows.len(), 3);
        for (claims, expected_reason) in [
            (&original_claims, "refresh_replay"),
            (&rotated_claims, "password_changed"),
            (&second_login_claims, "password_changed"),
        ] {
            let row = session_rows
                .iter()
                .find(|row| row.get::<_, String>("account_session_id") == claims.account_session_id)
                .expect("expected revoked PostgreSQL account session");
            assert_eq!(
                row.get::<_, Option<String>>("revoked_reason").as_deref(),
                Some(expected_reason)
            );
        }
        assert_eq!(
            session_rows
                .iter()
                .filter(|row| row.get::<_, Option<String>>("revoked_reason").is_none())
                .count(),
            0
        );

        let revocation_rows = client
            .query(
                "SELECT reason, metadata->>'account_session_id' AS account_session_id,
                        metadata->>'revoked_reason' AS metadata_reason
                 FROM audit_logs
                 WHERE actor_account_id=$1 AND action='account_session_revoked'",
                &[&account_id],
            )
            .await
            .expect("query account revocation audits");
        assert_eq!(revocation_rows.len(), 3);
        for (claims, expected_reason) in [
            (&original_claims, "refresh_replay"),
            (&rotated_claims, "password_changed"),
            (&second_login_claims, "password_changed"),
        ] {
            let row = revocation_rows
                .iter()
                .find(|row| row.get::<_, String>("account_session_id") == claims.account_session_id)
                .expect("per-session revocation audit");
            assert_eq!(row.get::<_, String>("reason"), expected_reason);
            assert_eq!(row.get::<_, String>("metadata_reason"), expected_reason);
        }
        let active_sessions: i64 = client
            .query_one(
                "SELECT count(*) FROM account_sessions
                 WHERE account_id=$1 AND revoked_at_epoch_millis IS NULL
                   AND revoked_reason IS NULL",
                &[&account_id],
            )
            .await
            .expect("count active sessions after account revocation")
            .get(0);
        assert_eq!(active_sessions, 0);
    }

    #[tokio::test]
    #[ignore = "requires a migrated PostgreSQL database in API_TEST_DATABASE_URL"]
    async fn postgres_totp_password_change_revokes_all_authority_and_survives_restart() {
        run_postgres_mfa_password_change("totp").await;
    }

    #[tokio::test]
    #[ignore = "requires a migrated PostgreSQL database in API_TEST_DATABASE_URL"]
    async fn postgres_recovery_password_change_revokes_all_authority_and_survives_restart() {
        run_postgres_mfa_password_change("recovery_code").await;
    }

    #[tokio::test]
    #[ignore = "requires a migrated PostgreSQL database in API_TEST_DATABASE_URL"]
    async fn postgres_mfa_security_audit_conflict_rolls_back_every_security_object() {
        let database_url = std::env::var("API_TEST_DATABASE_URL")
            .expect("API_TEST_DATABASE_URL must point to an isolated migrated database");
        let fixture = postgres_mfa_password_change_fixture(&database_url, "audit-conflict").await;
        let now = now_epoch_millis();
        let challenge_id = format!("mfa-disable-conflict-challenge-{}", fixture.suffix);
        let binding_hash = sha256(challenge_id.as_bytes());
        let source_audit = AuditEntry {
            audit_id: format!("mfa-disable-conflict-audit-{}", fixture.suffix),
            actor_type: "account".to_owned(),
            actor_account_id: Some(fixture.account_id.clone()),
            actor_device_id: None,
            actor_role: None,
            actor_service: None,
            target_device_id: Some(fixture.device_id.clone()),
            session_id: None,
            action: "mfa_factor_disabled".to_owned(),
            result: "success".to_owned(),
            reason: None,
            metadata: std::collections::BTreeMap::from([(
                "risk_challenge_id".to_owned(),
                Value::String(challenge_id.clone()),
            )]),
            request_id: format!("mfa-disable-conflict-request-{}", fixture.suffix),
            created_at_epoch_millis: now,
        };
        let conflicting_audit = crate::store::account_session_revocation_audit(
            &source_audit,
            &fixture.active_session_ids[0],
            "mfa_disabled",
        );
        let (mut client, connection) =
            tokio_postgres::connect(&database_url, tokio_postgres::NoTls)
                .await
                .expect("connect PostgreSQL rollback assertion client");
        tokio::spawn(async move {
            connection
                .await
                .expect("PostgreSQL rollback assertion connection");
        });
        let seed = client
            .transaction()
            .await
            .expect("begin PostgreSQL strict audit conflict seed");
        let now_i64 = i64::try_from(now).expect("fixture timestamp fits BIGINT");
        let created_i64 =
            i64::try_from(now.saturating_sub(1)).expect("fixture timestamp fits BIGINT");
        let expires_i64 = i64::try_from(now.saturating_sub(1).saturating_add(300_000))
            .expect("fixture timestamp fits BIGINT");
        let required_methods = json!(["totp", "recovery_code"]);
        seed.execute(
            "INSERT INTO account_risk_challenges
                (risk_challenge_id, account_id, device_id, purpose,
                 operation_binding_hash, risk_level, required_methods, status,
                 attempts_remaining, expires_at_epoch_millis, created_at_epoch_millis,
                 verified_at_epoch_millis, consumed_at_epoch_millis)
             VALUES ($1,$2,$3,'mfa_factor_change',$4,'high',$5,'verified',5,$6,$7,$7,NULL)",
            &[
                &challenge_id,
                &fixture.account_id,
                &fixture.device_id,
                &&binding_hash[..],
                &required_methods,
                &expires_i64,
                &created_i64,
            ],
        )
        .await
        .expect("seed verified PostgreSQL MFA challenge");
        let conflict_metadata =
            Value::Object(conflicting_audit.metadata.clone().into_iter().collect());
        seed.execute(
            "INSERT INTO audit_logs
                (audit_id, actor_type, actor_account_id, actor_role,
                 target_device_id, action, result, reason, metadata, request_id,
                 created_at_epoch_millis)
             VALUES ($1,$2,$3,'none',$4,$5,$6,$7,$8,$9,$10)",
            &[
                &conflicting_audit.audit_id,
                &conflicting_audit.actor_type,
                &conflicting_audit.actor_account_id,
                &conflicting_audit.target_device_id,
                &conflicting_audit.action,
                &conflicting_audit.result,
                &conflicting_audit.reason,
                &conflict_metadata,
                &conflicting_audit.request_id,
                &now_i64,
            ],
        )
        .await
        .expect("seed conflicting PostgreSQL object audit");
        seed.commit()
            .await
            .expect("commit PostgreSQL strict audit conflict seed");
        let before = client
            .query_one(
                "SELECT a.password_hash, a.updated_at_epoch_millis, f.encrypted_secret
                 FROM accounts a JOIN account_mfa_factors f ON f.account_id=a.account_id
                 WHERE a.account_id=$1 AND f.factor_id=$2 AND f.status='active'",
                &[&fixture.account_id, &fixture.factor_id],
            )
            .await
            .expect("snapshot PostgreSQL security state");
        let password_hash_before = before.get::<_, String>("password_hash");
        let account_updated_before = before.get::<_, i64>("updated_at_epoch_millis");
        let encrypted_factor_before = before.get::<_, Vec<u8>>("encrypted_secret");

        let expectation = crate::store::StepUpExpectation {
            challenge_id: challenge_id.clone(),
            account_id: fixture.account_id.clone(),
            device_id: fixture.device_id.clone(),
            purpose: "mfa_factor_change".to_owned(),
            operation_binding_hash: binding_hash,
            now_epoch_millis: now,
        };
        let action = crate::store::StepUpAction::DisableMfaFactor {
            factor_id: fixture.factor_id.clone(),
            audit_entry: source_audit.clone(),
        };
        assert_eq!(
            fixture
                .repository
                .apply_step_up_action(&expectation, &action)
                .await,
            Err(crate::store::StoreError::Conflict)
        );

        let account_after = client
            .query_one(
                "SELECT password_hash, updated_at_epoch_millis FROM accounts WHERE account_id=$1",
                &[&fixture.account_id],
            )
            .await
            .expect("query rolled-back account state");
        assert_eq!(
            account_after.get::<_, String>("password_hash"),
            password_hash_before
        );
        assert_eq!(
            account_after.get::<_, i64>("updated_at_epoch_millis"),
            account_updated_before
        );
        let factor_after = client
            .query_one(
                "SELECT status, encrypted_secret FROM account_mfa_factors WHERE factor_id=$1",
                &[&fixture.factor_id],
            )
            .await
            .expect("query rolled-back MFA factor");
        assert_eq!(factor_after.get::<_, String>("status"), "active");
        assert_eq!(
            factor_after.get::<_, Vec<u8>>("encrypted_secret"),
            encrypted_factor_before
        );
        let challenge_after = client
            .query_one(
                "SELECT status, consumed_at_epoch_millis FROM account_risk_challenges
                 WHERE risk_challenge_id=$1",
                &[&challenge_id],
            )
            .await
            .expect("query rolled-back MFA challenge");
        assert_eq!(challenge_after.get::<_, String>("status"), "verified");
        assert_eq!(
            challenge_after.get::<_, Option<i64>>("consumed_at_epoch_millis"),
            None
        );
        let active_recovery_codes: i64 = client
            .query_one(
                "SELECT count(*) FROM account_recovery_codes
                 WHERE account_id=$1 AND status='active' AND used_at_epoch_millis IS NULL",
                &[&fixture.account_id],
            )
            .await
            .expect("count rolled-back recovery codes")
            .get(0);
        assert_eq!(active_recovery_codes, 1);
        assert_postgres_authority_is_active(
            &client,
            &fixture.account_id,
            fixture.active_session_ids.len() as i64,
            fixture.active_trust_ids.len() as i64,
        )
        .await;
        let action_audits: i64 = client
            .query_one(
                "SELECT count(*) FROM audit_logs WHERE audit_id=$1",
                &[&source_audit.audit_id],
            )
            .await
            .expect("count rolled-back top-level audit")
            .get(0);
        assert_eq!(action_audits, 0);
        let conflict_audits: i64 = client
            .query_one(
                "SELECT count(*) FROM audit_logs WHERE audit_id=$1",
                &[&conflicting_audit.audit_id],
            )
            .await
            .expect("count injected conflict audit")
            .get(0);
        assert_eq!(conflict_audits, 1);

        cleanup_postgres_account(&database_url, &fixture.account_id).await;
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
        let idempotency_key_hash = sha256(format!("delivery-key-{suffix}").as_bytes());
        let client_ephemeral_public_key = [3; 32];
        let finish_request_binding_hash = crate::store::totp_enrollment_finish_binding_hash(
            &account_id,
            &account_session_id,
            &factor_id,
            &idempotency_key_hash,
            &client_ephemeral_public_key,
        );
        let delivery = RecoveryCodeDelivery {
            delivery_id: format!("delivery-{suffix}"),
            account_id: account_id.clone(),
            account_session_id: account_session_id.clone(),
            factor_id: factor_id.clone(),
            idempotency_key_hash,
            finish_request_binding_hash,
            client_ephemeral_public_key,
            server_ephemeral_public_key: [4; 32],
            nonce: [5; 12],
            ciphertext: vec![6; 32],
            recovery_code_count: 8,
            created_at_epoch_millis: enrolled_at,
            expires_at_epoch_millis: enrolled_at.saturating_add(60_000),
            acknowledged_at_epoch_millis: None,
        };
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
                delivery: delivery.clone(),
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
        let idempotency_constraint_columns: Vec<String> = client
            .query_one(
                "SELECT array_agg(attribute.attname::TEXT ORDER BY key_column.position)
                 FROM pg_constraint AS constraint_record
                 CROSS JOIN LATERAL unnest(constraint_record.conkey)
                     WITH ORDINALITY AS key_column(attnum, position)
                 JOIN pg_attribute AS attribute
                   ON attribute.attrelid=constraint_record.conrelid
                  AND attribute.attnum=key_column.attnum
                 WHERE constraint_record.conname=
                     'uq_mfa_recovery_code_deliveries_idempotency'
                   AND constraint_record.conrelid=
                     'public.mfa_recovery_code_deliveries'::regclass
                   AND constraint_record.contype='u'",
                &[],
            )
            .await
            .expect("load recovery delivery idempotency constraint")
            .get(0);
        assert_eq!(
            idempotency_constraint_columns,
            vec!["account_id", "idempotency_key_hash"]
        );

        let restored = PostgresRepository::connect(&database_url, mfa_key)
            .await
            .expect("restore PostgreSQL repository");
        let replay_lookup = crate::store::TotpEnrollmentReplayLookup {
            account_id: account_id.clone(),
            account_session_id: account_session_id.clone(),
            factor_id: factor_id.clone(),
            idempotency_key_hash,
            finish_request_binding_hash: Some(finish_request_binding_hash),
            client_ephemeral_public_key: Some(client_ephemeral_public_key),
            access_token_expires_at_epoch_millis: enrolled_at.saturating_add(300_000),
            now_epoch_millis: enrolled_at.saturating_add(1),
        };
        assert_eq!(
            restored
                .replay_totp_enrollment(&replay_lookup)
                .await
                .expect("replay PostgreSQL recovery delivery after restart"),
            crate::store::TotpEnrollmentReplayOutcome::Replayed(Box::new(delivery.clone()))
        );

        let conflicting_factor_id = format!("factor-conflict-{suffix}");
        let conflicting_client_key = [8; 32];
        let conflicting_binding = crate::store::totp_enrollment_finish_binding_hash(
            &account_id,
            &account_session_id,
            &conflicting_factor_id,
            &idempotency_key_hash,
            &conflicting_client_key,
        );
        let conflicting_completion = crate::store::TotpEnrollmentCompletion {
            factor: MfaFactor {
                factor_id: conflicting_factor_id.clone(),
                account_id: account_id.clone(),
                secret_base32: format!("JBSWY3DPEHPK3PXP-CONFLICT-{suffix}"),
                active: true,
                last_used_counter: Some(43),
                created_at_epoch_millis: enrolled_at,
            },
            recovery_codes: vec![RecoveryCode {
                recovery_code_id: format!("recovery-conflict-{suffix}"),
                account_id: account_id.clone(),
                code_hash: sha256(format!("recovery-code-conflict-{suffix}").as_bytes()),
                used_at_epoch_millis: None,
                expires_at_epoch_millis: None,
            }],
            delivery: RecoveryCodeDelivery {
                delivery_id: format!("delivery-conflict-{suffix}"),
                account_id: account_id.clone(),
                account_session_id: account_session_id.clone(),
                factor_id: conflicting_factor_id,
                idempotency_key_hash,
                finish_request_binding_hash: conflicting_binding,
                client_ephemeral_public_key: conflicting_client_key,
                server_ephemeral_public_key: [9; 32],
                nonce: [10; 12],
                ciphertext: vec![11; 32],
                recovery_code_count: 1,
                created_at_epoch_millis: enrolled_at,
                expires_at_epoch_millis: enrolled_at.saturating_add(60_000),
                acknowledged_at_epoch_millis: None,
            },
            audit_entry: AuditEntry {
                audit_id: format!("mfa-enrollment-conflict-{suffix}"),
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
                request_id: format!("mfa-enrollment-conflict-request-{suffix}"),
                created_at_epoch_millis: enrolled_at,
            },
        };
        assert_eq!(
            restored
                .finish_totp_enrollment(&conflicting_completion)
                .await,
            Err(crate::store::StoreError::Conflict)
        );
        let delivery_count: i64 = client
            .query_one(
                "SELECT COUNT(*) FROM mfa_recovery_code_deliveries
                 WHERE account_id=$1 AND idempotency_key_hash=$2",
                &[&account_id, &&idempotency_key_hash[..]],
            )
            .await
            .expect("count account-level recovery delivery claims")
            .get(0);
        assert_eq!(delivery_count, 1);
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

    struct PostgresMfaPasswordChangeFixture {
        suffix: String,
        repository: Arc<PostgresRepository>,
        router: Router,
        account_id: String,
        access_token: String,
        refresh_tokens: Vec<String>,
        device_id: String,
        factor_id: String,
        totp_secret: String,
        recovery_code: String,
        active_session_ids: Vec<String>,
        active_trust_ids: Vec<String>,
    }

    async fn postgres_mfa_password_change_fixture(
        database_url: &str,
        tag: &str,
    ) -> PostgresMfaPasswordChangeFixture {
        let repository = Arc::new(
            PostgresRepository::connect(database_url, [0_u8; 32])
                .await
                .expect("connect PostgreSQL MFA password fixture repository"),
        );
        let state = AppState::new(
            repository.clone(),
            AppConfig::for_test(),
            SignalNotifier::disabled(),
        );
        let router = build_router(state);
        let suffix = crate::security::random_uuid_v4();
        let registered = register_account(
            router.clone(),
            &format!("postgres-{tag}-{suffix}@example.com"),
        )
        .await;
        let account_id = registered["account_id"]
            .as_str()
            .expect("PostgreSQL fixture account id")
            .to_owned();
        let access_token = registered["access_token"]
            .as_str()
            .expect("PostgreSQL fixture access token")
            .to_owned();
        let original_refresh_token = registered["refresh_token"]
            .as_str()
            .expect("PostgreSQL fixture refresh token")
            .to_owned();
        let original_claims = verify_access_token(
            &access_token,
            &AppConfig::for_test().token_secret,
            now_epoch_millis(),
        )
        .expect("PostgreSQL fixture access claims");
        let now = now_epoch_millis();
        let device_id = format!("postgres-{tag}-device-a-{suffix}");
        let other_device_id = format!("postgres-{tag}-device-b-{suffix}");
        let device_public_key = sha256(device_id.as_bytes());
        let other_device_public_key = sha256(other_device_id.as_bytes());
        let factor_id = format!("postgres-{tag}-factor-{suffix}");
        let recovery_code_id = format!("postgres-{tag}-recovery-{suffix}");
        let totp_secret = "JBSWY3DPEHPK3PXP".to_owned();
        let recovery_code = format!("RECOVERY-{suffix}");
        let extra_refresh_tokens = [
            format!("postgres-{tag}-refresh-a-{suffix}"),
            format!("postgres-{tag}-refresh-b-{suffix}"),
        ];
        let extra_session_ids = [
            format!("postgres-{tag}-session-a-{suffix}"),
            format!("postgres-{tag}-session-b-{suffix}"),
        ];
        let active_trust_ids = vec![
            format!("postgres-{tag}-trust-a-{suffix}"),
            format!("postgres-{tag}-trust-b-{suffix}"),
        ];
        repository
            .transact(&mut |database| {
                let account = database
                    .accounts
                    .get_mut(&account_id)
                    .ok_or(crate::store::StoreError::Unavailable)?;
                account.updated_at_epoch_millis =
                    account.updated_at_epoch_millis.saturating_add(1).max(now);
                for (id, public_key) in [
                    (&device_id, device_public_key),
                    (&other_device_id, other_device_public_key),
                ] {
                    database.devices.insert(
                        id.clone(),
                        Device {
                            device_id: id.clone(),
                            account_id: account_id.clone(),
                            display_name: id.clone(),
                            platform: Platform::Ubuntu,
                            os_version: "26.04".to_owned(),
                            arch: Architecture::X86_64,
                            capabilities: DeviceCapabilities {
                                controller: true,
                                controlled: true,
                                file_transfer: false,
                                unattended: false,
                            },
                            public_key_id: format!("{id}-key"),
                            public_key,
                            public_key_version: 1,
                            public_key_revoked_at_epoch_millis: None,
                            status: DeviceLifecycleStatus::Offline,
                            last_seen_epoch_millis: None,
                            created_at_epoch_millis: now,
                            updated_at_epoch_millis: now,
                        },
                    );
                }
                database.mfa_factors.insert(
                    factor_id.clone(),
                    MfaFactor {
                        factor_id: factor_id.clone(),
                        account_id: account_id.clone(),
                        secret_base32: totp_secret.clone(),
                        active: true,
                        last_used_counter: None,
                        created_at_epoch_millis: now,
                    },
                );
                database.recovery_codes.insert(
                    recovery_code_id.clone(),
                    RecoveryCode {
                        recovery_code_id: recovery_code_id.clone(),
                        account_id: account_id.clone(),
                        code_hash: sha256(recovery_code.as_bytes()),
                        used_at_epoch_millis: None,
                        expires_at_epoch_millis: None,
                    },
                );
                for (session_id, refresh_token) in
                    extra_session_ids.iter().zip(extra_refresh_tokens.iter())
                {
                    database.account_sessions.insert(
                        session_id.clone(),
                        AccountSession {
                            account_session_id: session_id.clone(),
                            account_id: account_id.clone(),
                            refresh_token_hash: sha256(refresh_token.as_bytes()),
                            mfa_verified: true,
                            expires_at_epoch_millis: now.saturating_add(600_000),
                            revoked_at_epoch_millis: None,
                            revoked_reason: None,
                        },
                    );
                }
                for (trusted_device_id, controller_device_id, public_key) in [
                    (&active_trust_ids[0], &device_id, device_public_key),
                    (
                        &active_trust_ids[1],
                        &other_device_id,
                        other_device_public_key,
                    ),
                ] {
                    database.trusted_controller_devices.insert(
                        trusted_device_id.clone(),
                        TrustedControllerDevice {
                            trusted_device_id: trusted_device_id.clone(),
                            account_id: account_id.clone(),
                            controller_device_id: controller_device_id.clone(),
                            device_fingerprint_hash: sha256(&public_key),
                            trust_level: "standard".to_owned(),
                            status: TrustedDeviceStatus::Active,
                            trust_proof_type: "device_signature_and_mfa".to_owned(),
                            created_at_epoch_millis: now,
                            last_used_at_epoch_millis: None,
                            expires_at_epoch_millis: now.saturating_add(600_000),
                            revoked_at_epoch_millis: None,
                        },
                    );
                }
                Ok(())
            })
            .await
            .expect("seed PostgreSQL MFA password fixture");

        let mut active_session_ids = vec![original_claims.account_session_id];
        active_session_ids.extend(extra_session_ids);
        let mut refresh_tokens = vec![original_refresh_token];
        refresh_tokens.extend(extra_refresh_tokens);
        PostgresMfaPasswordChangeFixture {
            suffix,
            repository,
            router,
            account_id,
            access_token,
            refresh_tokens,
            device_id,
            factor_id,
            totp_secret,
            recovery_code,
            active_session_ids,
            active_trust_ids,
        }
    }

    async fn run_postgres_mfa_password_change(factor: &str) {
        let database_url = std::env::var("API_TEST_DATABASE_URL")
            .expect("API_TEST_DATABASE_URL must point to an isolated migrated database");
        let fixture = postgres_mfa_password_change_fixture(&database_url, factor).await;
        let (client, connection) = tokio_postgres::connect(&database_url, tokio_postgres::NoTls)
            .await
            .expect("connect PostgreSQL password assertion client");
        tokio::spawn(async move {
            connection
                .await
                .expect("PostgreSQL password assertion connection");
        });
        assert_postgres_authority_is_active(
            &client,
            &fixture.account_id,
            fixture.active_session_ids.len() as i64,
            fixture.active_trust_ids.len() as i64,
        )
        .await;

        let wrong_request_id = format!("postgres-{factor}-wrong-password-{}", fixture.suffix);
        let wrong_body = serde_json::to_vec(&json!({
            "current_password": "wrong current password",
            "new_password": format!("unused new password {}", fixture.suffix)
        }))
        .expect("wrong current password body");
        let (wrong_factor, wrong_code) = if factor == "totp" {
            ("recovery_code", fixture.recovery_code.clone())
        } else {
            let (code, _) = totp_code(&fixture.totp_secret, now_epoch_millis())
                .expect("generate PostgreSQL wrong-password TOTP");
            ("totp", code)
        };
        let (wrong_challenge_id, wrong_step_up_token) = complete_postgres_password_step_up(
            &fixture,
            &wrong_request_id,
            &wrong_body,
            wrong_factor,
            &wrong_code,
        )
        .await;
        let wrong_response = send_postgres_password_change(
            &fixture,
            &wrong_request_id,
            &wrong_challenge_id,
            &wrong_step_up_token,
            wrong_body,
        )
        .await;
        assert_eq!(wrong_response.status(), StatusCode::FORBIDDEN);
        let wrong_response_body = response_json(wrong_response).await;
        assert_eq!(wrong_response_body["code"], "invalid_current_password");
        let wrong_challenge = client
            .query_one(
                "SELECT status, consumed_at_epoch_millis FROM account_risk_challenges
                 WHERE risk_challenge_id=$1",
                &[&wrong_challenge_id],
            )
            .await
            .expect("query wrong-password PostgreSQL challenge");
        assert_eq!(wrong_challenge.get::<_, String>("status"), "verified");
        assert_eq!(
            wrong_challenge.get::<_, Option<i64>>("consumed_at_epoch_millis"),
            None
        );
        let unchanged_password_hash: String = client
            .query_one(
                "SELECT password_hash FROM accounts WHERE account_id=$1",
                &[&fixture.account_id],
            )
            .await
            .expect("query unchanged PostgreSQL password")
            .get(0);
        assert!(verify_password(
            &unchanged_password_hash,
            "correct horse battery staple"
        ));
        assert_postgres_authority_is_active(
            &client,
            &fixture.account_id,
            fixture.active_session_ids.len() as i64,
            fixture.active_trust_ids.len() as i64,
        )
        .await;

        let request_id = format!("postgres-{factor}-password-change-{}", fixture.suffix);
        let new_password = format!("new correct password {}", fixture.suffix);
        let password_body = serde_json::to_vec(&json!({
            "current_password": "correct horse battery staple",
            "new_password": new_password
        }))
        .expect("PostgreSQL password change body");
        let factor_code = if factor == "totp" {
            totp_code(&fixture.totp_secret, now_epoch_millis())
                .expect("generate PostgreSQL password-change TOTP")
                .0
        } else {
            fixture.recovery_code.clone()
        };
        let (challenge_id, step_up_token) = complete_postgres_password_step_up(
            &fixture,
            &request_id,
            &password_body,
            factor,
            &factor_code,
        )
        .await;
        let response = send_postgres_password_change(
            &fixture,
            &request_id,
            &challenge_id,
            &step_up_token,
            password_body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        for token_header in [
            "authorization",
            "x-rctl-access-token",
            "x-rctl-refresh-token",
            "x-rctl-step-up-token",
        ] {
            assert!(!response.headers().contains_key(token_header));
        }
        assert!(response
            .into_body()
            .collect()
            .await
            .expect("empty PostgreSQL password response")
            .to_bytes()
            .is_empty());

        let restarted_repository = Arc::new(
            PostgresRepository::connect(&database_url, [0_u8; 32])
                .await
                .expect("connect restarted PostgreSQL password repository"),
        );
        let restarted_router = build_router(AppState::new(
            restarted_repository,
            AppConfig::for_test(),
            SignalNotifier::disabled(),
        ));
        for (index, refresh_token) in fixture.refresh_tokens.iter().enumerate() {
            let (status, body) = post_json_request(
                restarted_router.clone(),
                "/v1/auth/refresh",
                &format!("postgres-{factor}-old-refresh-{index}-{}", fixture.suffix),
                json!({ "refresh_token": refresh_token }),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        }

        let account = client
            .query_one(
                "SELECT password_hash FROM accounts WHERE account_id=$1",
                &[&fixture.account_id],
            )
            .await
            .expect("query changed PostgreSQL password");
        let changed_password_hash = account.get::<_, String>("password_hash");
        assert!(!verify_password(
            &changed_password_hash,
            "correct horse battery staple"
        ));
        assert!(verify_password(&changed_password_hash, &new_password));
        let final_challenge = client
            .query_one(
                "SELECT status, consumed_at_epoch_millis FROM account_risk_challenges
                 WHERE risk_challenge_id=$1",
                &[&challenge_id],
            )
            .await
            .expect("query consumed PostgreSQL password challenge");
        assert_eq!(final_challenge.get::<_, String>("status"), "consumed");
        assert!(final_challenge
            .get::<_, Option<i64>>("consumed_at_epoch_millis")
            .is_some());
        let mfa_state = client
            .query_one(
                "SELECT f.status AS factor_status, f.last_used_at_epoch_millis,
                        r.status AS recovery_status, r.used_at_epoch_millis
                 FROM account_mfa_factors f JOIN account_recovery_codes r
                   ON r.account_id=f.account_id
                 WHERE f.factor_id=$1 AND f.account_id=$2",
                &[&fixture.factor_id, &fixture.account_id],
            )
            .await
            .expect("query consumed PostgreSQL MFA proofs");
        assert_eq!(mfa_state.get::<_, String>("factor_status"), "active");
        assert!(mfa_state
            .get::<_, Option<i64>>("last_used_at_epoch_millis")
            .is_some());
        assert_eq!(mfa_state.get::<_, String>("recovery_status"), "used");
        assert!(mfa_state
            .get::<_, Option<i64>>("used_at_epoch_millis")
            .is_some());

        let session_rows = client
            .query(
                "SELECT account_session_id, revoked_reason FROM account_sessions
                 WHERE account_id=$1",
                &[&fixture.account_id],
            )
            .await
            .expect("query PostgreSQL password-revoked sessions");
        assert_eq!(session_rows.len(), fixture.active_session_ids.len());
        for session_id in &fixture.active_session_ids {
            let row = session_rows
                .iter()
                .find(|row| row.get::<_, String>("account_session_id") == *session_id)
                .expect("expected password-revoked PostgreSQL session");
            assert_eq!(
                row.get::<_, Option<String>>("revoked_reason").as_deref(),
                Some("password_changed")
            );
        }
        let trust_rows = client
            .query(
                "SELECT trusted_device_id, status, revoked_at_epoch_millis
                 FROM trusted_controller_devices WHERE account_id=$1",
                &[&fixture.account_id],
            )
            .await
            .expect("query PostgreSQL password-revoked trust");
        assert_eq!(trust_rows.len(), fixture.active_trust_ids.len());
        for trusted_device_id in &fixture.active_trust_ids {
            let row = trust_rows
                .iter()
                .find(|row| row.get::<_, String>("trusted_device_id") == *trusted_device_id)
                .expect("expected password-revoked PostgreSQL trust");
            assert_eq!(row.get::<_, String>("status"), "revoked");
            assert!(row
                .get::<_, Option<i64>>("revoked_at_epoch_millis")
                .is_some());
        }

        let session_audits = client
            .query(
                "SELECT reason, metadata->>'account_session_id' AS object_id,
                        metadata->>'revoked_reason' AS metadata_reason
                 FROM audit_logs WHERE actor_account_id=$1 AND request_id=$2
                   AND action='account_session_revoked'",
                &[&fixture.account_id, &request_id],
            )
            .await
            .expect("query PostgreSQL per-session password audits");
        let audited_session_ids = session_audits
            .iter()
            .map(|row| {
                assert_eq!(row.get::<_, String>("reason"), "password_changed");
                assert_eq!(row.get::<_, String>("metadata_reason"), "password_changed");
                row.get::<_, String>("object_id")
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            audited_session_ids,
            fixture
                .active_session_ids
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>()
        );
        let trust_audits = client
            .query(
                "SELECT reason, metadata->>'trusted_device_id' AS object_id,
                        metadata->>'revoked_reason' AS metadata_reason
                 FROM audit_logs WHERE actor_account_id=$1 AND request_id=$2
                   AND action='trusted_device_revoked'",
                &[&fixture.account_id, &request_id],
            )
            .await
            .expect("query PostgreSQL per-trust password audits");
        let audited_trust_ids = trust_audits
            .iter()
            .map(|row| {
                assert_eq!(row.get::<_, String>("reason"), "password_changed");
                assert_eq!(row.get::<_, String>("metadata_reason"), "password_changed");
                row.get::<_, String>("object_id")
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            audited_trust_ids,
            fixture
                .active_trust_ids
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<_>>()
        );
        let password_audits: i64 = client
            .query_one(
                "SELECT count(*) FROM audit_logs WHERE actor_account_id=$1 AND request_id=$2
                   AND action='password_changed' AND result='success'",
                &[&fixture.account_id, &request_id],
            )
            .await
            .expect("count PostgreSQL top-level password audits")
            .get(0);
        assert_eq!(password_audits, 1);

        cleanup_postgres_account(&database_url, &fixture.account_id).await;
    }

    async fn complete_postgres_password_step_up(
        fixture: &PostgresMfaPasswordChangeFixture,
        request_id: &str,
        password_body: &[u8],
        factor: &str,
        code: &str,
    ) -> (String, String) {
        let body_hash = canonical_request_body_hash(password_body, Some("application/json"))
            .expect("canonical PostgreSQL password body hash");
        let (challenge_status, challenge) = authenticated_json_request(
            fixture.router.clone(),
            "POST",
            "/v1/auth/risk-challenge",
            &fixture.access_token,
            &format!("issue-{request_id}"),
            serde_json::to_vec(&json!({
                "purpose": "password_change",
                "device_id": fixture.device_id,
                "method": "PATCH",
                "path": "/v1/me/password",
                "body_hash": crate::security::hex_encode(&body_hash),
                "request_id": request_id
            }))
            .expect("PostgreSQL password challenge body"),
        )
        .await;
        assert_eq!(challenge_status, StatusCode::CREATED, "{challenge}");
        assert_eq!(
            challenge["required_methods"],
            json!(["totp", "recovery_code"])
        );
        let challenge_id = challenge["risk_challenge_id"]
            .as_str()
            .expect("PostgreSQL password challenge id")
            .to_owned();
        let (verify_status, verified) = authenticated_json_request(
            fixture.router.clone(),
            "POST",
            &format!("/v1/auth/risk-challenge/{challenge_id}/verify"),
            &fixture.access_token,
            &format!("verify-{request_id}"),
            serde_json::to_vec(&json!({ "factor": factor, "code": code }))
                .expect("PostgreSQL password verification body"),
        )
        .await;
        assert_eq!(verify_status, StatusCode::OK, "{verified}");
        let step_up_token = verified["step_up_token"]
            .as_str()
            .expect("PostgreSQL password step-up token")
            .to_owned();
        (challenge_id, step_up_token)
    }

    async fn send_postgres_password_change(
        fixture: &PostgresMfaPasswordChangeFixture,
        request_id: &str,
        challenge_id: &str,
        step_up_token: &str,
        password_body: Vec<u8>,
    ) -> Response {
        fixture
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("PATCH")
                    .uri("/v1/me/password")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {}", fixture.access_token))
                    .header("x-rctl-protocol-version", VERSION)
                    .header("x-request-id", request_id)
                    .header("x-rctl-risk-challenge-id", challenge_id)
                    .header("x-rctl-step-up-token", step_up_token)
                    .body(Body::from(password_body))
                    .expect("PostgreSQL password change request"),
            )
            .await
            .expect("PostgreSQL password change response")
    }

    async fn assert_postgres_authority_is_active(
        client: &tokio_postgres::Client,
        account_id: &str,
        expected_sessions: i64,
        expected_trust: i64,
    ) {
        let row = client
            .query_one(
                "SELECT
                    (SELECT count(*) FROM account_sessions
                     WHERE account_id=$1 AND revoked_at_epoch_millis IS NULL
                       AND revoked_reason IS NULL) AS active_sessions,
                    (SELECT count(*) FROM trusted_controller_devices
                     WHERE account_id=$1 AND status='active'
                       AND revoked_at_epoch_millis IS NULL) AS active_trust",
                &[&account_id],
            )
            .await
            .expect("query active PostgreSQL account authority");
        assert_eq!(row.get::<_, i64>("active_sessions"), expected_sessions);
        assert_eq!(row.get::<_, i64>("active_trust"), expected_trust);
    }

    async fn cleanup_postgres_account(database_url: &str, account_id: &str) {
        let (mut client, connection) = tokio_postgres::connect(database_url, tokio_postgres::NoTls)
            .await
            .expect("connect PostgreSQL fixture cleanup client");
        tokio::spawn(async move {
            connection
                .await
                .expect("PostgreSQL fixture cleanup connection");
        });
        let transaction = client
            .transaction()
            .await
            .expect("begin PostgreSQL fixture cleanup");
        transaction
            .batch_execute("SET CONSTRAINTS ALL DEFERRED")
            .await
            .expect("defer PostgreSQL fixture cleanup constraints");
        for statement in [
            "DELETE FROM audit_logs WHERE actor_account_id=$1",
            "DELETE FROM api_idempotency_keys WHERE account_id=$1",
            "DELETE FROM device_enrollment_grants WHERE account_id=$1",
            "DELETE FROM mfa_recovery_code_deliveries WHERE account_id=$1",
            "DELETE FROM trusted_controller_devices WHERE account_id=$1",
            "DELETE FROM account_recovery_codes WHERE account_id=$1",
            "DELETE FROM account_mfa_factors WHERE account_id=$1",
            "DELETE FROM account_risk_challenges WHERE account_id=$1",
            "DELETE FROM account_sessions WHERE account_id=$1",
            "DELETE FROM device_policies WHERE device_id IN
                (SELECT device_id FROM devices WHERE account_id=$1)",
            "DELETE FROM devices WHERE account_id=$1",
            "DELETE FROM accounts WHERE account_id=$1",
        ] {
            transaction
                .execute(statement, &[&account_id])
                .await
                .unwrap_or_else(|error| {
                    panic!("clean PostgreSQL fixture with {statement}: {error}")
                });
        }
        transaction
            .commit()
            .await
            .expect("commit PostgreSQL fixture cleanup");
        let remaining: i64 = client
            .query_one(
                "SELECT count(*) FROM accounts WHERE account_id=$1",
                &[&account_id],
            )
            .await
            .expect("verify PostgreSQL fixture cleanup")
            .get(0);
        assert_eq!(remaining, 0);
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

    async fn post_json_request(
        router: Router,
        path: &str,
        request_id: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        let response = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/json")
                    .header("x-rctl-protocol-version", VERSION)
                    .header("x-request-id", request_id)
                    .body(Body::from(
                        serde_json::to_vec(&body).expect("serialize JSON request body"),
                    ))
                    .expect("JSON request"),
            )
            .await
            .expect("JSON response");
        let status = response.status();
        (status, response_json(response).await)
    }

    async fn login_account_via_challenge(
        router: Router,
        email: &str,
        device_id: &str,
        key: &SigningKey,
        client_nonce_byte: u8,
        factor: Option<(&str, &str)>,
    ) -> (Value, Value) {
        let client_nonce = [client_nonce_byte; 32];
        let (login_status, challenge) = post_json_request(
            router.clone(),
            "/v1/auth/login",
            &format!("login-start-{device_id}"),
            json!({
                "email": email,
                "password": "correct horse battery staple",
                "device_id": device_id,
                "device_public_key": encode_public_key(&key.verifying_key().to_bytes()),
                "public_key_id": Value::Null,
                "public_key_version": 0,
                "client_nonce": encode_base64url(&client_nonce),
                "protocol_version": remote_protocol::PROTOCOL_VERSION
            }),
        )
        .await;
        assert_eq!(login_status, StatusCode::ACCEPTED, "{challenge}");
        let account_id = challenge["account_id"]
            .as_str()
            .expect("login challenge account id");
        let mut finish = json!({
            "login_challenge_id": challenge["login_challenge_id"],
            "login_request_binding_hash": challenge["login_request_binding_hash"],
            "login_challenge_binding_hash": challenge["login_challenge_binding_hash"],
            "client_nonce": encode_base64url(&client_nonce),
            "server_nonce": challenge["server_nonce"],
            "protocol_version": remote_protocol::PROTOCOL_VERSION
        });
        if let Some((factor, code)) = factor {
            finish["factor"] = Value::String(factor.to_owned());
            finish["code"] = Value::String(code.to_owned());
        }
        let finish_response = signed_request(
            router,
            "POST",
            "/v1/auth/login/finish",
            "login-finish-does-not-use-bearer-authority",
            account_id,
            device_id,
            key,
            &format!("login-finish-{device_id}"),
            serde_json::to_vec(&finish).expect("serialize login finish body"),
        )
        .await;
        assert_eq!(finish_response.0, StatusCode::OK, "{}", finish_response.1);
        (challenge, finish_response.1)
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
        seed_device_registration_authority(state, access_token, account_id, device_id, key, None)
            .await
    }

    async fn seed_trusted_device_registration(
        state: &AppState,
        access_token: &str,
        account_id: &str,
        device_id: &str,
        key: &SigningKey,
        factor: &str,
    ) -> Vec<u8> {
        seed_device_registration_authority(
            state,
            access_token,
            account_id,
            device_id,
            key,
            Some(factor),
        )
        .await
    }

    async fn seed_device_registration_authority(
        state: &AppState,
        access_token: &str,
        account_id: &str,
        device_id: &str,
        key: &SigningKey,
        trust_factor: Option<&str>,
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
        let (establish_trust, trust_proof_type, trust_level) = match trust_factor {
            None => (false, None, None),
            Some("totp") => (
                true,
                Some("device_signature_and_mfa".to_owned()),
                Some("standard".to_owned()),
            ),
            Some("recovery_code") => (
                true,
                Some("device_signature_and_recovery_code".to_owned()),
                Some("high_risk_step_up_required".to_owned()),
            ),
            Some(_) => panic!("unsupported registration trust factor"),
        };
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
                if establish_trust {
                    let session = database
                        .account_sessions
                        .get_mut(&claims.account_session_id)
                        .ok_or(crate::store::StoreError::Unavailable)?;
                    session.mfa_verified = true;
                }
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
                        trust_proof_type: trust_proof_type.clone(),
                        trust_level: trust_level.clone(),
                        establish_trust,
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
