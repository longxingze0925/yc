mod backend;
mod notify;
mod security;

use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use backend::{PresenceMutation, ReplayRecord, StateBackend, PRESENCE_TTL_MILLIS};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use notify::{ConnectionRegistry, EnqueueError};
use rand::random;
use remote_protocol::{
    CandidateAuthorization, CandidateTokenRequest, ConnectionCandidateDto, DeviceStatus, ErrorCode,
    KeyConfirm, SessionRole, SignedKeyExchange, PROTOCOL_VERSION,
};
use remote_transport::{candidate_token_binding_hash, LanCandidateGuard};
use security::{
    client_capabilities_hash, decode_array, decode_hex_array, encode, encode_hex,
    ensure_timestamp_in_window, hello_signature_input, parse_protocol_headers,
    service_token_matches, verify_access_token, verify_hello_signature, AccessClaims,
    ProtocolNegotiation, SecurityError, SUPPORTED_PROTOCOL_VERSIONS,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::time::{interval, timeout, Duration, MissedTickBehavior};
use tracing::{info, warn};

pub const DEFAULT_BIND: &str = "127.0.0.1:18081";
const HELLO_TTL_MILLIS: u64 = 30_000;
const PRESENCE_REFRESH_MILLIS: u64 = PRESENCE_TTL_MILLIS / 3;
const MAX_INTERNAL_PUSH_BODY_BYTES: usize = 64 * 1024;
const MAX_SESSION_CERTIFICATE_DER_BYTES: usize = 16 * 1024;
const NOTIFICATION_SEND_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub bind: SocketAddr,
    pub token_secret: Vec<u8>,
    pub internal_api_url: String,
    pub service_token: String,
    pub redis_url: String,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, String> {
        let bind = env::var("REMOTE_SIGNAL_BIND")
            .unwrap_or_else(|_| DEFAULT_BIND.to_owned())
            .parse()
            .map_err(|_| "REMOTE_SIGNAL_BIND must be a socket address".to_owned())?;
        let token_secret = env::var("REMOTE_TOKEN_SECRET")
            .map_err(|_| "REMOTE_TOKEN_SECRET is required".to_owned())?
            .into_bytes();
        if token_secret.len() < 32 {
            return Err("REMOTE_TOKEN_SECRET must contain at least 32 bytes".to_owned());
        }
        let internal_api_url = env::var("REMOTE_API_INTERNAL_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:18080".to_owned());
        if !internal_api_url.starts_with("http://") && !internal_api_url.starts_with("https://") {
            return Err("REMOTE_API_INTERNAL_URL must use http or https".to_owned());
        }
        let service_token = env::var("REMOTE_SERVICE_TOKEN")
            .map_err(|_| "REMOTE_SERVICE_TOKEN is required".to_owned())?;
        if service_token.len() < 32 {
            return Err("REMOTE_SERVICE_TOKEN must contain at least 32 bytes".to_owned());
        }
        let redis_url = env::var("REDIS_URL").map_err(|_| "REDIS_URL is required".to_owned())?;
        if !redis_url.starts_with("redis://") && !redis_url.starts_with("rediss://") {
            return Err("REDIS_URL must use redis or rediss".to_owned());
        }
        Ok(Self {
            bind,
            token_secret,
            internal_api_url,
            service_token,
            redis_url,
        })
    }

    pub fn for_test() -> Self {
        Self {
            bind: "127.0.0.1:0".parse().expect("test bind"),
            token_secret: b"test-token-secret-that-is-at-least-32-bytes".to_vec(),
            internal_api_url: "http://127.0.0.1:1".to_owned(),
            service_token: "test-service-token-that-is-at-least-32-bytes".to_owned(),
            redis_url: "redis://127.0.0.1:1/0".to_owned(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TrustedDevice {
    pub account_id: String,
    pub device_id: String,
    pub public_key_id: String,
    pub public_key_version: u32,
    pub public_key: [u8; 32],
    pub public_key_revoked: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedDeviceSeed {
    account_id: String,
    device_id: String,
    public_key_id: String,
    public_key_version: u32,
    public_key: String,
    #[serde(default)]
    public_key_revoked: bool,
}

#[derive(Debug, Default)]
pub struct DeviceDirectory {
    devices: HashMap<(String, String), TrustedDevice>,
}

impl DeviceDirectory {
    pub fn from_json(json: &str) -> Result<Self, String> {
        let seeds: Vec<TrustedDeviceSeed> = serde_json::from_str(json)
            .map_err(|error| format!("invalid device seed JSON: {error}"))?;
        let mut directory = Self::default();
        for seed in seeds {
            let public_key = decode_array::<32>(&seed.public_key)
                .map_err(|_| format!("invalid public key for device {}", seed.device_id))?;
            directory.insert(TrustedDevice {
                account_id: seed.account_id,
                device_id: seed.device_id,
                public_key_id: seed.public_key_id,
                public_key_version: seed.public_key_version,
                public_key,
                public_key_revoked: seed.public_key_revoked,
            })?;
        }
        Ok(directory)
    }

    pub fn insert(&mut self, device: TrustedDevice) -> Result<(), String> {
        if device.account_id.is_empty()
            || device.device_id.is_empty()
            || device.public_key_id.is_empty()
            || device.public_key_version == 0
        {
            return Err("trusted device identity is incomplete".to_owned());
        }
        let key = (device.account_id.clone(), device.device_id.clone());
        if self.devices.insert(key, device).is_some() {
            return Err("duplicate trusted device".to_owned());
        }
        Ok(())
    }

    fn find(&self, account_id: &str, device_id: &str) -> Option<&TrustedDevice> {
        self.devices
            .get(&(account_id.to_owned(), device_id.to_owned()))
    }
}

#[derive(Clone)]
enum DeviceAuthenticator {
    Api(ApiDeviceAuthenticator),
    Memory(Arc<DeviceDirectory>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionAuthorization {
    session_id: String,
    controller_device_id: String,
    controlled_device_id: String,
    permissions_digest: String,
    relay_token_epoch: u64,
}

impl SessionAuthorization {
    fn peer_for(&self, device_id: &str, role: SessionRole) -> Option<&str> {
        match role {
            SessionRole::Controller if self.controller_device_id == device_id => {
                Some(&self.controlled_device_id)
            }
            SessionRole::Controlled if self.controlled_device_id == device_id => {
                Some(&self.controller_device_id)
            }
            _ => None,
        }
    }
}

#[derive(Clone)]
enum SessionAuthorizer {
    Api(ApiSessionAuthorizer),
    Memory(Arc<StdRwLock<HashMap<String, SessionAuthorization>>>),
}

impl SessionAuthorizer {
    async fn authorize(
        &self,
        account_id: &str,
        device_id: &str,
        session_id: &str,
        role: SessionRole,
    ) -> Result<SessionAuthorization, String> {
        match self {
            Self::Api(api) => api.authorize(account_id, device_id, session_id, role).await,
            Self::Memory(sessions) => {
                let authorization = sessions
                    .read()
                    .map_err(|_| "session authorization lock poisoned".to_owned())?
                    .get(session_id)
                    .cloned()
                    .ok_or_else(|| "session was not authorized".to_owned())?;
                authorization
                    .peer_for(device_id, role)
                    .ok_or_else(|| "session role binding mismatch".to_owned())?;
                Ok(authorization)
            }
        }
    }
}

#[derive(Clone)]
struct ApiSessionAuthorizer {
    client: reqwest::Client,
    endpoint: String,
    service_token: String,
}

#[derive(Debug, Serialize)]
struct SessionAuthRequest<'a> {
    account_id: &'a str,
    device_id: &'a str,
    session_id: &'a str,
    role: &'static str,
}

#[derive(Debug, Deserialize)]
struct SessionAuthResponse {
    authorized: bool,
    session_id: String,
    controller_device_id: String,
    controlled_device_id: String,
    permissions_digest: String,
    relay_token_epoch: u64,
}

impl ApiSessionAuthorizer {
    async fn authorize(
        &self,
        account_id: &str,
        device_id: &str,
        session_id: &str,
        role: SessionRole,
    ) -> Result<SessionAuthorization, String> {
        let response = self
            .client
            .post(&self.endpoint)
            .bearer_auth(&self.service_token)
            .json(&SessionAuthRequest {
                account_id,
                device_id,
                session_id,
                role: role.as_str(),
            })
            .send()
            .await
            .map_err(|_| "session authorization service unavailable".to_owned())?;
        if !response.status().is_success() {
            return Err("session authorization rejected".to_owned());
        }
        let response: SessionAuthResponse = response
            .json()
            .await
            .map_err(|_| "invalid session authorization response".to_owned())?;
        if !response.authorized || response.session_id != session_id {
            return Err("session authorization binding mismatch".to_owned());
        }
        let authorization = SessionAuthorization {
            session_id: response.session_id,
            controller_device_id: response.controller_device_id,
            controlled_device_id: response.controlled_device_id,
            permissions_digest: response.permissions_digest,
            relay_token_epoch: response.relay_token_epoch,
        };
        authorization
            .peer_for(device_id, role)
            .ok_or_else(|| "session authorization role mismatch".to_owned())?;
        Ok(authorization)
    }
}

impl DeviceAuthenticator {
    async fn authorize(&self, request: DeviceAuthRequest) -> Result<TrustedDevice, String> {
        match self {
            Self::Api(api) => api.authorize(request).await,
            Self::Memory(directory) => directory
                .find(&request.account_id, &request.device_id)
                .filter(|device| {
                    device.public_key_id == request.public_key_id
                        && device.public_key_version == request.public_key_version
                        && !device.public_key_revoked
                })
                .cloned()
                .ok_or_else(|| "device identity was not authorized".to_owned()),
        }
    }
}

#[derive(Clone)]
struct ApiDeviceAuthenticator {
    client: reqwest::Client,
    endpoint: String,
    service_token: String,
}

#[derive(Debug, Clone, Serialize)]
struct DeviceAuthRequest {
    access_token: String,
    account_id: String,
    device_id: String,
    public_key_id: String,
    public_key_version: u32,
}

#[derive(Debug, Deserialize)]
struct DeviceAuthResponse {
    authorized: bool,
    account_id: String,
    device_id: String,
    public_key: String,
    public_key_id: String,
    public_key_version: u32,
    access_token_expires_at_epoch_millis: u64,
}

impl ApiDeviceAuthenticator {
    async fn authorize(&self, request: DeviceAuthRequest) -> Result<TrustedDevice, String> {
        let response = self
            .client
            .post(&self.endpoint)
            .bearer_auth(&self.service_token)
            .json(&request)
            .send()
            .await
            .map_err(|_| "device authorization service unavailable".to_owned())?;
        if !response.status().is_success() {
            return Err("device authorization rejected".to_owned());
        }
        let response: DeviceAuthResponse = response
            .json()
            .await
            .map_err(|_| "invalid device authorization response".to_owned())?;
        trusted_device_from_response(&request, response, now_epoch_millis())
    }
}

fn trusted_device_from_response(
    request: &DeviceAuthRequest,
    response: DeviceAuthResponse,
    now_epoch_millis: u64,
) -> Result<TrustedDevice, String> {
    if !response.authorized
        || response.account_id != request.account_id
        || response.device_id != request.device_id
        || response.public_key_id != request.public_key_id
        || response.public_key_version != request.public_key_version
        || response.access_token_expires_at_epoch_millis <= now_epoch_millis
    {
        return Err("device authorization binding mismatch".to_owned());
    }
    let public_key = decode_array::<32>(&response.public_key)
        .map_err(|_| "invalid device public key from authorization service".to_owned())?;
    Ok(TrustedDevice {
        account_id: response.account_id,
        device_id: response.device_id,
        public_key_id: response.public_key_id,
        public_key_version: response.public_key_version,
        public_key,
        public_key_revoked: false,
    })
}

#[derive(Debug, Clone, Serialize)]
pub struct OnlineDevice {
    pub account_id: String,
    pub device_id: String,
    pub public_key_id: String,
    pub public_key_version: u32,
    pub public_key: String,
    pub client_capabilities_hash: String,
    pub status: DeviceStatus,
    pub last_seen_epoch_millis: u64,
    pub connection_id: String,
}

#[derive(Clone)]
pub struct AppState {
    config: AppConfig,
    device_authenticator: DeviceAuthenticator,
    session_authorizer: SessionAuthorizer,
    backend: StateBackend,
    connections: ConnectionRegistry,
    lan_candidate_guard: Arc<StdMutex<LanCandidateGuard>>,
}

type UpgradeValidation = Result<(AccessClaims, String, ProtocolNegotiation), Box<Response>>;

impl AppState {
    pub async fn new(config: AppConfig) -> Result<Self, String> {
        let backend = StateBackend::connect_redis(&config.redis_url)
            .await
            .map_err(|error| format!("cannot initialize signal state backend: {error}"))?;
        Ok(Self::with_backend(config, backend))
    }

    fn with_backend(config: AppConfig, backend: StateBackend) -> Self {
        let device_endpoint = format!(
            "{}/internal/v1/signal/device-auth",
            config.internal_api_url.trim_end_matches('/')
        );
        let session_endpoint = format!(
            "{}/internal/v1/signal/session-authorize",
            config.internal_api_url.trim_end_matches('/')
        );
        let client = reqwest::Client::new();
        Self {
            device_authenticator: DeviceAuthenticator::Api(ApiDeviceAuthenticator {
                client: client.clone(),
                endpoint: device_endpoint,
                service_token: config.service_token.clone(),
            }),
            session_authorizer: SessionAuthorizer::Api(ApiSessionAuthorizer {
                client,
                endpoint: session_endpoint,
                service_token: config.service_token.clone(),
            }),
            config,
            backend,
            connections: ConnectionRegistry::default(),
            lan_candidate_guard: Arc::new(StdMutex::new(LanCandidateGuard::default())),
        }
    }

    pub fn for_test(devices: DeviceDirectory) -> Self {
        Self {
            config: AppConfig::for_test(),
            device_authenticator: DeviceAuthenticator::Memory(Arc::new(devices)),
            session_authorizer: SessionAuthorizer::Memory(Arc::new(StdRwLock::new(HashMap::new()))),
            backend: StateBackend::memory(),
            connections: ConnectionRegistry::default(),
            lan_candidate_guard: Arc::new(StdMutex::new(LanCandidateGuard::default())),
        }
    }

    pub fn backend_name(&self) -> &'static str {
        self.backend.name()
    }

    #[cfg(test)]
    async fn online_count(&self) -> Result<usize, backend::BackendError> {
        self.backend.online_count().await
    }

    #[cfg(test)]
    fn add_test_session(&self, authorization: SessionAuthorization) {
        let SessionAuthorizer::Memory(sessions) = &self.session_authorizer else {
            panic!("test state must use memory session authorization");
        };
        sessions
            .write()
            .expect("session authorizations")
            .insert(authorization.session_id.clone(), authorization);
    }
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ws", get(websocket))
        .route(
            "/internal/v1/push",
            post(internal_push).layer(DefaultBodyLimit::max(MAX_INTERNAL_PUSH_BODY_BYTES)),
        )
        .with_state(state)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InternalPushRequest {
    device_id: String,
    message: PersistedServerNotification,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum PersistedNotificationType {
    SessionInvite,
    SessionInviteQueued,
    SessionAcceptAck,
    SessionRejectAck,
    SessionCancelAck,
    SessionCloseAck,
    ConnectionState,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedServerNotification {
    #[serde(rename = "type")]
    kind: PersistedNotificationType,
    session: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    actor_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    actor_device_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    actor_role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    actor_service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    event_id: Option<String>,
}

impl PersistedServerNotification {
    fn is_valid_for_device(&self, device_id: &str) -> bool {
        let Some(session) = self.session.as_object() else {
            return false;
        };
        let Some(snapshot_session_id) = session.get("session_id").and_then(Value::as_str) else {
            return false;
        };
        let Some(snapshot_status) = session.get("status").and_then(Value::as_str) else {
            return false;
        };
        let controller = session.get("controller_device_id").and_then(Value::as_str);
        let controlled = session.get("controlled_device_id").and_then(Value::as_str);
        if snapshot_session_id.is_empty()
            || snapshot_status.is_empty()
            || (Some(device_id) != controller && Some(device_id) != controlled)
        {
            return false;
        }
        if matches!(
            self.kind,
            PersistedNotificationType::SessionInvite
                | PersistedNotificationType::SessionInviteQueued
        ) {
            return true;
        }
        if self.session_id.as_deref() != Some(snapshot_session_id)
            || self.status.as_deref() != Some(snapshot_status)
            || self.event_id.as_deref().is_none_or(str::is_empty)
            || !self.valid_actor()
        {
            return false;
        }
        if matches!(
            self.kind,
            PersistedNotificationType::SessionRejectAck
                | PersistedNotificationType::SessionCancelAck
                | PersistedNotificationType::SessionCloseAck
        ) && self.reason.as_deref().is_none_or(str::is_empty)
        {
            return false;
        }
        true
    }

    fn valid_actor(&self) -> bool {
        match self.actor_type.as_deref() {
            Some("device") => {
                self.actor_device_id
                    .as_deref()
                    .is_some_and(|value| !value.is_empty())
                    && matches!(
                        self.actor_role.as_deref(),
                        Some("controller" | "controlled")
                    )
                    && self.actor_service.is_none()
            }
            Some("service") => {
                self.actor_device_id.is_none()
                    && self.actor_role.is_none()
                    && self
                        .actor_service
                        .as_deref()
                        .is_some_and(|value| !value.is_empty())
            }
            Some("system") => {
                self.actor_device_id.is_none()
                    && self.actor_role.is_none()
                    && self.actor_service.is_none()
            }
            _ => false,
        }
    }
}

async fn internal_push(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let authorized = bearer(&headers)
        .is_some_and(|token| service_token_matches(token, &state.config.service_token));
    if !authorized {
        return http_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "invalid service bearer token",
        );
    }
    if body.len() > MAX_INTERNAL_PUSH_BODY_BYTES {
        return http_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "payload_too_large",
            "notification payload exceeds the size limit",
        );
    }
    let request: InternalPushRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return http_error(
                StatusCode::BAD_REQUEST,
                "invalid_payload",
                "invalid notification payload",
            );
        }
    };
    if !valid_device_id(&request.device_id)
        || !request.message.is_valid_for_device(&request.device_id)
    {
        return http_error(
            StatusCode::BAD_REQUEST,
            "invalid_payload",
            "notification device or session payload is invalid",
        );
    }
    let notification = match serde_json::to_string(&request.message) {
        Ok(notification) => notification,
        Err(_) => {
            return http_error(
                StatusCode::BAD_REQUEST,
                "invalid_payload",
                "invalid notification",
            )
        }
    };
    match state
        .connections
        .enqueue(&request.device_id, notification)
        .await
    {
        Ok(()) => (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({
                "code": "notification_queued",
                "device_id": request.device_id,
            })),
        )
            .into_response(),
        Err(EnqueueError::Offline) => http_error(
            StatusCode::NOT_FOUND,
            "device_offline",
            "target device has no active Signal connection",
        ),
        Err(EnqueueError::Overloaded) => http_error(
            StatusCode::TOO_MANY_REQUESTS,
            "notification_queue_full",
            "target device notification queue is full",
        ),
    }
}

fn valid_device_id(device_id: &str) -> bool {
    !device_id.is_empty()
        && device_id.len() <= 128
        && device_id.trim() == device_id
        && !device_id.chars().any(char::is_control)
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    protocol_version: u16,
    online_backend: &'static str,
    hello_replay_backend: &'static str,
    redis_migration_pending: bool,
}

async fn health(State(state): State<AppState>) -> Response {
    let (status_code, response) = health_snapshot(&state).await;
    (status_code, Json(response)).into_response()
}

async fn health_snapshot(state: &AppState) -> (StatusCode, HealthResponse) {
    let backend_healthy = state.backend.health().await.is_ok();
    let status_code = if backend_healthy {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let status = if backend_healthy { "ok" } else { "unavailable" };
    (
        status_code,
        HealthResponse {
            status,
            protocol_version: PROTOCOL_VERSION,
            online_backend: state.backend.name(),
            hello_replay_backend: state.backend.name(),
            redis_migration_pending: false,
        },
    )
}

async fn websocket(
    State(state): State<AppState>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Response {
    let (claims, access_token, negotiation) =
        match validate_upgrade(&state, &headers, now_epoch_millis()) {
            Ok(validated) => validated,
            Err(response) => return *response,
        };
    upgrade
        .on_upgrade(move |socket| handle_socket(socket, state, claims, access_token, negotiation))
        .into_response()
}

fn validate_upgrade(
    state: &AppState,
    headers: &HeaderMap,
    now_epoch_millis: u64,
) -> UpgradeValidation {
    let token = bearer(headers).ok_or_else(|| {
        Box::new(http_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing bearer token",
        ))
    })?;
    let claims =
        verify_access_token(token, &state.config.token_secret, now_epoch_millis).map_err(|_| {
            Box::new(http_error(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "invalid access token",
            ))
        })?;
    let negotiation = match parse_protocol_headers(
        header(headers, "x-rctl-protocol-versions"),
        header(headers, "x-rctl-min-protocol-version"),
    ) {
        Ok(negotiation) => negotiation,
        Err(SecurityError::UnsupportedVersion) => {
            return Err(Box::new(
                (
                    StatusCode::UPGRADE_REQUIRED,
                    Json(serde_json::json!({
                        "code": "unsupported_version",
                        "message": "no supported protocol version intersection",
                        "server_supported_protocol_versions": SUPPORTED_PROTOCOL_VERSIONS,
                    })),
                )
                    .into_response(),
            ));
        }
        Err(_) => {
            return Err(Box::new(http_error(
                StatusCode::BAD_REQUEST,
                "invalid_protocol_version_header",
                "invalid or missing protocol version headers",
            )));
        }
    };
    Ok((claims, token.to_owned(), negotiation))
}

async fn handle_socket(
    mut socket: WebSocket,
    state: AppState,
    claims: AccessClaims,
    access_token: String,
    negotiation: ProtocolNegotiation,
) {
    let server_nonce = random::<[u8; 32]>();
    let challenge_expires_at = now_epoch_millis().saturating_add(HELLO_TTL_MILLIS);
    let challenge = ServerMessage::HelloChallenge {
        account_id: claims.account_id.clone(),
        protocol_version: negotiation.selected_version,
        server_nonce: encode(&server_nonce),
        expires_at_epoch_millis: challenge_expires_at,
        server_supported_protocol_versions: SUPPORTED_PROTOCOL_VERSIONS.to_vec(),
    };
    if send_server_message(&mut socket, &challenge).await.is_err() {
        return;
    }

    let response = match socket.recv().await {
        Some(Ok(Message::Text(text))) => serde_json::from_str::<HelloResponse>(&text).ok(),
        _ => None,
    };
    let Some(response) = response else {
        reject_socket(&mut socket, "hello_response required").await;
        return;
    };
    let authenticated = match authenticate_hello(
        &state,
        &claims,
        &access_token,
        &negotiation,
        &server_nonce,
        challenge_expires_at,
        response,
        now_epoch_millis(),
    )
    .await
    {
        Ok(authenticated) => authenticated,
        Err(reason) => {
            reject_socket(&mut socket, reason).await;
            return;
        }
    };

    let device_id = authenticated.device.device_id.clone();
    let connection_id = authenticated.connection_id.clone();
    if let Err(error) = state
        .backend
        .put_presence(online_device(
            &authenticated.device,
            &connection_id,
            &authenticated.capabilities_hash,
            DeviceStatus::Online,
        ))
        .await
    {
        warn!(%error, %device_id, %connection_id, "cannot write device presence");
        reject_socket(&mut socket, "presence backend unavailable").await;
        return;
    }
    let registration = state.connections.register(&device_id, &connection_id).await;
    let mut notifications = registration.notifications;
    let mut superseded = registration.superseded;
    let hello_ok = ServerMessage::HelloOk {
        account_id: claims.account_id.clone(),
        device_id: device_id.clone(),
        protocol_version: negotiation.selected_version,
        connection_id: connection_id.clone(),
        client_supported_protocol_versions_hash: encode_hex(&negotiation.versions_hash),
        client_capabilities_hash: encode_hex(&authenticated.capabilities_hash),
        server_supported_protocol_versions: SUPPORTED_PROTOCOL_VERSIONS.to_vec(),
        server_time_epoch_millis: now_epoch_millis(),
    };
    if send_server_message(&mut socket, &hello_ok).await.is_err() {
        remove_connection(&state, &claims.account_id, &device_id, &connection_id).await;
        return;
    }
    info!(%device_id, %connection_id, "device authenticated and online");

    let mut presence_refresh = interval(Duration::from_millis(PRESENCE_REFRESH_MILLIS));
    presence_refresh.set_missed_tick_behavior(MissedTickBehavior::Skip);
    presence_refresh.tick().await;
    loop {
        tokio::select! {
            biased;
            _ = &mut superseded => {
                info!(%device_id, %connection_id, "connection superseded by a reconnect");
                break;
            }
            notification = notifications.recv() => {
                let Some(notification) = notification else {
                    break;
                };
                let Some(ownership_guard) = state
                    .connections
                    .acquire_ownership(&device_id, &connection_id)
                    .await
                else {
                    break;
                };
                let send_result = timeout(
                    NOTIFICATION_SEND_TIMEOUT,
                    socket.send(Message::Text(notification.into())),
                )
                .await;
                drop(ownership_guard);
                if !matches!(send_result, Ok(Ok(()))) {
                    break;
                }
            }
            _ = presence_refresh.tick() => {
                match state
                    .backend
                    .refresh_presence(&claims.account_id, &device_id, &connection_id)
                    .await
                {
                    Ok(PresenceMutation::Updated) => {}
                    Ok(PresenceMutation::Missing | PresenceMutation::Superseded) => {
                        warn!(%device_id, %connection_id, "authenticated connection lost presence ownership");
                        break;
                    }
                    Err(error) => {
                        warn!(%error, %device_id, %connection_id, "cannot refresh device presence");
                        break;
                    }
                }
            }
            message = socket.recv() => {
                let Some(message) = message else {
                    break;
                };
                match message {
                    Ok(Message::Text(text)) => {
                        let response = handle_authenticated_text(
                            &state,
                            &claims.account_id,
                            &device_id,
                            &authenticated.device.public_key,
                            &connection_id,
                            &text,
                        )
                        .await;
                        if send_server_message(&mut socket, &response).await.is_err() {
                            break;
                        }
                    }
                    Ok(Message::Ping(payload)) => {
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            break;
                        }
                    }
                    Ok(Message::Pong(_)) => {}
                    Ok(Message::Close(_)) | Err(_) => break,
                    Ok(Message::Binary(_)) => {
                        let response = ServerMessage::Error {
                            code: ErrorCode::InvalidPayload,
                            message: "binary signaling messages are not supported".to_owned(),
                        };
                        if send_server_message(&mut socket, &response).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    }
    remove_connection(&state, &claims.account_id, &device_id, &connection_id).await;
    info!(%device_id, %connection_id, "device offline");
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
struct HelloResponse {
    account_id: String,
    device_id: String,
    client_nonce: String,
    timestamp: u64,
    client_supported_protocol_versions: Vec<u16>,
    client_min_protocol_version: u16,
    public_key_id: String,
    public_key_version: u32,
    client_supported_protocol_versions_hash: String,
    client_capabilities: Value,
    client_capabilities_hash: String,
    device_signature: String,
}

#[derive(Debug)]
struct AuthenticatedHello {
    device: TrustedDevice,
    capabilities_hash: [u8; 32],
    connection_id: String,
}

#[allow(clippy::too_many_arguments)]
async fn authenticate_hello(
    state: &AppState,
    claims: &AccessClaims,
    access_token: &str,
    negotiation: &ProtocolNegotiation,
    server_nonce: &[u8; 32],
    challenge_expires_at: u64,
    response: HelloResponse,
    now_epoch_millis: u64,
) -> Result<AuthenticatedHello, &'static str> {
    if now_epoch_millis >= challenge_expires_at {
        return Err("hello challenge expired");
    }
    if response.account_id != claims.account_id {
        return Err("account_id does not match access token");
    }
    if response.client_supported_protocol_versions != negotiation.client_versions
        || response.client_min_protocol_version != negotiation.client_min_version
    {
        return Err("protocol negotiation does not match upgrade headers");
    }
    let submitted_versions_hash =
        decode_hex_array::<32>(&response.client_supported_protocol_versions_hash)
            .map_err(|_| "invalid protocol versions hash")?;
    if submitted_versions_hash != negotiation.versions_hash {
        return Err("protocol versions hash mismatch");
    }
    let capabilities_hash = client_capabilities_hash(&response.client_capabilities)
        .map_err(|_| "invalid capabilities")?;
    let submitted_capabilities_hash = decode_hex_array::<32>(&response.client_capabilities_hash)
        .map_err(|_| "invalid capabilities hash")?;
    if submitted_capabilities_hash != capabilities_hash {
        return Err("client capabilities hash mismatch");
    }
    ensure_timestamp_in_window(response.timestamp, now_epoch_millis)
        .map_err(|_| "hello timestamp outside allowed window")?;
    let client_nonce =
        decode_array::<32>(&response.client_nonce).map_err(|_| "invalid client nonce")?;
    let device = state
        .device_authenticator
        .authorize(DeviceAuthRequest {
            access_token: access_token.to_owned(),
            account_id: claims.account_id.clone(),
            device_id: response.device_id.clone(),
            public_key_id: response.public_key_id.clone(),
            public_key_version: response.public_key_version,
        })
        .await
        .map_err(|_| "device authorization rejected")?;
    if device.public_key_revoked || device.public_key_version == 0 {
        return Err("device key is revoked");
    }
    let canonical = hello_signature_input(
        server_nonce,
        &client_nonce,
        &response.account_id,
        &response.device_id,
        negotiation.selected_version,
        response.timestamp,
        &negotiation.versions_hash,
        &capabilities_hash,
    )
    .map_err(|_| "cannot build hello signature input")?;
    verify_hello_signature(&device.public_key, &canonical, &response.device_signature)
        .map_err(|_| "invalid device signature")?;
    record_nonce_once(
        state,
        &claims.account_id,
        &response.device_id,
        client_nonce,
        challenge_expires_at,
        now_epoch_millis,
    )
    .await?;

    Ok(AuthenticatedHello {
        device,
        capabilities_hash,
        connection_id: encode(&random::<[u8; 16]>()),
    })
}

async fn record_nonce_once(
    state: &AppState,
    account_id: &str,
    device_id: &str,
    client_nonce: [u8; 32],
    expires_at_epoch_millis: u64,
    now_epoch_millis: u64,
) -> Result<(), &'static str> {
    match state
        .backend
        .record_hello_nonce_once(
            account_id,
            device_id,
            &client_nonce,
            expires_at_epoch_millis,
            now_epoch_millis,
        )
        .await
    {
        Ok(ReplayRecord::Recorded) => Ok(()),
        Ok(ReplayRecord::Duplicate) => Err("hello nonce replay detected"),
        Ok(ReplayRecord::Full) => Err("hello replay cache is full"),
        Err(error) => {
            warn!(%error, %device_id, "hello replay backend unavailable");
            Err("hello replay backend unavailable")
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum AuthenticatedClientMessage {
    Ping,
    ListOnlineDevices,
    SetDeviceStatus {
        device_id: String,
        status: DeviceStatus,
        seen_at_epoch_millis: u64,
    },
    ConnectionCandidate {
        session_id: String,
        role: SessionRole,
        payload: Value,
    },
    RequestCandidateToken {
        payload: Box<CandidateTokenRequest>,
    },
    KeyExchangeMessage {
        session_id: String,
        role: SessionRole,
        payload: Value,
    },
    KeyConfirm {
        session_id: String,
        role: SessionRole,
        payload: Value,
    },
}

async fn handle_authenticated_text(
    state: &AppState,
    account_id: &str,
    authenticated_device_id: &str,
    authenticated_public_key: &[u8; 32],
    connection_id: &str,
    text: &str,
) -> ServerMessage {
    let value: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(error) => {
            return ServerMessage::Error {
                code: ErrorCode::InvalidPayload,
                message: format!("invalid signaling json: {error}"),
            };
        }
    };
    let message_type = value
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if is_forbidden_ws_write(message_type) {
        return ServerMessage::Error {
            code: ErrorCode::PermissionDenied,
            message: format!("{message_type} is API-only and cannot be written over WebSocket"),
        };
    }
    let request: AuthenticatedClientMessage = match serde_json::from_str(text) {
        Ok(request) => request,
        Err(error) => {
            return ServerMessage::Error {
                code: ErrorCode::UnsupportedMessageKind,
                message: format!("unsupported authenticated signaling message: {error}"),
            };
        }
    };

    match request {
        AuthenticatedClientMessage::Ping => ServerMessage::Pong,
        AuthenticatedClientMessage::ListOnlineDevices => {
            match state.backend.list_presence(account_id).await {
                Ok(devices) => ServerMessage::OnlineDevices { devices },
                Err(error) => {
                    warn!(%error, %account_id, "cannot list device presence");
                    ServerMessage::Error {
                        code: ErrorCode::Internal,
                        message: "presence backend unavailable".to_owned(),
                    }
                }
            }
        }
        AuthenticatedClientMessage::SetDeviceStatus {
            device_id,
            status,
            seen_at_epoch_millis: _client_seen_at_epoch_millis,
        } => {
            if device_id != authenticated_device_id {
                return ServerMessage::Error {
                    code: ErrorCode::PermissionDenied,
                    message: "cannot update another device status".to_owned(),
                };
            }
            match state
                .backend
                .update_presence(
                    account_id,
                    &device_id,
                    connection_id,
                    status,
                    now_epoch_millis(),
                )
                .await
            {
                Ok(PresenceMutation::Updated) => {
                    ServerMessage::DeviceStatusUpdated { device_id, status }
                }
                Ok(PresenceMutation::Missing) => ServerMessage::Error {
                    code: ErrorCode::DeviceOffline,
                    message: "authenticated connection is no longer online".to_owned(),
                },
                Ok(PresenceMutation::Superseded) => ServerMessage::Error {
                    code: ErrorCode::AuthenticationFailed,
                    message: "connection was superseded by a reconnect".to_owned(),
                },
                Err(error) => {
                    warn!(%error, %device_id, %connection_id, "cannot update device presence");
                    ServerMessage::Error {
                        code: ErrorCode::Internal,
                        message: "presence backend unavailable".to_owned(),
                    }
                }
            }
        }
        AuthenticatedClientMessage::ConnectionCandidate {
            session_id,
            role,
            payload,
        } => {
            forward_session_message(
                state,
                account_id,
                authenticated_device_id,
                "connection_candidate",
                session_id,
                role,
                payload,
            )
            .await
        }
        AuthenticatedClientMessage::RequestCandidateToken { payload } => {
            issue_lan_candidate_token(
                state,
                account_id,
                authenticated_device_id,
                authenticated_public_key,
                *payload,
            )
            .await
        }
        AuthenticatedClientMessage::KeyExchangeMessage {
            session_id,
            role,
            payload,
        } => {
            forward_session_message(
                state,
                account_id,
                authenticated_device_id,
                "key_exchange_message",
                session_id,
                role,
                payload,
            )
            .await
        }
        AuthenticatedClientMessage::KeyConfirm {
            session_id,
            role,
            payload,
        } => {
            forward_session_message(
                state,
                account_id,
                authenticated_device_id,
                "key_confirm",
                session_id,
                role,
                payload,
            )
            .await
        }
    }
}

async fn issue_lan_candidate_token(
    state: &AppState,
    account_id: &str,
    authenticated_device_id: &str,
    authenticated_public_key: &[u8; 32],
    request: CandidateTokenRequest,
) -> ServerMessage {
    let session_id = uuid::Uuid::from_u128(request.session_id)
        .hyphenated()
        .to_string();
    if state
        .session_authorizer
        .authorize(
            account_id,
            authenticated_device_id,
            &session_id,
            request.role,
        )
        .await
        .is_err()
    {
        return ServerMessage::Error {
            code: ErrorCode::PermissionDenied,
            message: "candidate token request was not authorized".to_owned(),
        };
    }
    let now = now_epoch_millis();
    let candidate = match state
        .lan_candidate_guard
        .lock()
        .map_err(|_| ())
        .and_then(|mut guard| {
            guard
                .validate_request(
                    &request,
                    request.session_id,
                    authenticated_device_id,
                    request.role,
                    authenticated_public_key,
                    now,
                )
                .map_err(|_| ())
        }) {
        Ok(candidate) => candidate,
        Err(()) => {
            return ServerMessage::Error {
                code: ErrorCode::InvalidPayload,
                message: "LAN candidate token request binding is invalid".to_owned(),
            };
        }
    };
    let expires_at_epoch_millis = now.saturating_add(u64::from(request.requested_ttl_millis));
    let candidate_token_binding_hash =
        match candidate_token_binding_hash(&candidate, expires_at_epoch_millis) {
            Ok(binding) => binding,
            Err(_) => {
                return ServerMessage::Error {
                    code: ErrorCode::InvalidPayload,
                    message: "LAN candidate token binding is invalid".to_owned(),
                };
            }
        };
    ServerMessage::CandidateTokenIssued {
        session_id: request.session_id,
        device_id: request.device_id,
        role: request.role,
        candidate_id: request.candidate_id,
        candidate_token: random::<[u8; 32]>().to_vec(),
        candidate_token_binding_hash,
        expires_at_epoch_millis,
    }
}

async fn forward_session_message(
    state: &AppState,
    account_id: &str,
    authenticated_device_id: &str,
    message_type: &'static str,
    session_id: String,
    role: SessionRole,
    payload: Value,
) -> ServerMessage {
    let Some(binary_session_id) = uuid::Uuid::parse_str(&session_id)
        .ok()
        .map(|value| value.as_u128())
    else {
        return ServerMessage::Error {
            code: ErrorCode::InvalidPayload,
            message: "session_id must be a UUID".to_owned(),
        };
    };
    if !validate_forward_payload(
        message_type,
        &payload,
        binary_session_id,
        authenticated_device_id,
        role,
    ) {
        return ServerMessage::Error {
            code: ErrorCode::InvalidPayload,
            message: "session message payload binding is invalid".to_owned(),
        };
    }
    let authorization = match state
        .session_authorizer
        .authorize(account_id, authenticated_device_id, &session_id, role)
        .await
    {
        Ok(authorization) => authorization,
        Err(_) => {
            return ServerMessage::Error {
                code: ErrorCode::PermissionDenied,
                message: "session message was not authorized".to_owned(),
            }
        }
    };
    let Some(peer_device_id) = authorization.peer_for(authenticated_device_id, role) else {
        return ServerMessage::Error {
            code: ErrorCode::PermissionDenied,
            message: "session role binding mismatch".to_owned(),
        };
    };
    let notification = serde_json::json!({
        "type": message_type,
        "session_id": session_id,
        "role": role,
        "from_device_id": authenticated_device_id,
        "payload": payload,
    });
    let notification = match serde_json::to_string(&notification) {
        Ok(notification) => notification,
        Err(_) => {
            return ServerMessage::Error {
                code: ErrorCode::InvalidPayload,
                message: "session message serialization failed".to_owned(),
            }
        }
    };
    match state
        .connections
        .enqueue(peer_device_id, notification)
        .await
    {
        Ok(()) => ServerMessage::SessionMessageForwarded {
            session_id,
            message_type,
            target_device_id: peer_device_id.to_owned(),
        },
        Err(EnqueueError::Offline) => ServerMessage::Error {
            code: ErrorCode::DeviceOffline,
            message: "session peer is offline".to_owned(),
        },
        Err(EnqueueError::Overloaded) => ServerMessage::Error {
            code: ErrorCode::Internal,
            message: "session peer queue is full".to_owned(),
        },
    }
}

fn validate_forward_payload(
    message_type: &str,
    payload: &Value,
    session_id: u128,
    device_id: &str,
    role: SessionRole,
) -> bool {
    match message_type {
        "connection_candidate" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct CandidatePayload {
                candidate: ConnectionCandidateDto,
                authorization: CandidateAuthorization,
                transport_certificate_der: Option<String>,
                server_name: Option<String>,
            }
            serde_json::from_value::<CandidatePayload>(payload.clone())
                .ok()
                .is_some_and(|value| {
                    let transport_identity_valid = match role {
                        SessionRole::Controller => {
                            value.transport_certificate_der.is_none() && value.server_name.is_none()
                        }
                        SessionRole::Controlled => {
                            value
                                .transport_certificate_der
                                .as_deref()
                                .and_then(|encoded| URL_SAFE_NO_PAD.decode(encoded).ok())
                                .is_some_and(|certificate| {
                                    !certificate.is_empty()
                                        && certificate.len() <= MAX_SESSION_CERTIFICATE_DER_BYTES
                                })
                                && value
                                    .server_name
                                    .as_deref()
                                    .is_some_and(valid_session_server_name)
                        }
                    };
                    transport_identity_valid
                        && value.candidate.session_id == session_id
                        && value.candidate.device_id == device_id
                        && value.candidate.role == role
                        && !value.authorization.candidate_token.is_empty()
                        && value.authorization.expires_at_epoch_millis > now_epoch_millis()
                })
        }
        "key_exchange_message" => serde_json::from_value::<SignedKeyExchange>(payload.clone())
            .ok()
            .is_some_and(|value| {
                value.payload.session_id == session_id
                    && value.payload.device_id == device_id
                    && value.payload.role == role
                    && value.payload.validate_path_binding()
                    && value.signature.len() == 64
            }),
        "key_confirm" => serde_json::from_value::<KeyConfirm>(payload.clone())
            .ok()
            .is_some_and(|value| {
                value.session_id == session_id && value.device_id == device_id && value.role == role
            }),
        _ => false,
    }
}

fn valid_session_server_name(value: &str) -> bool {
    value.len() <= 253
        && value.starts_with("rctl-")
        && value.ends_with(".invalid")
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
}

fn is_forbidden_ws_write(message_type: &str) -> bool {
    matches!(
        message_type,
        "register_device"
            | "invite_session"
            | "create_session"
            | "accept_session"
            | "reject_session"
            | "cancel_session"
            | "close_session"
            | "connection_state"
    )
}

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMessage {
    Pong,
    HelloChallenge {
        account_id: String,
        protocol_version: u16,
        server_nonce: String,
        expires_at_epoch_millis: u64,
        server_supported_protocol_versions: Vec<u16>,
    },
    HelloOk {
        account_id: String,
        device_id: String,
        protocol_version: u16,
        connection_id: String,
        client_supported_protocol_versions_hash: String,
        client_capabilities_hash: String,
        server_supported_protocol_versions: Vec<u16>,
        server_time_epoch_millis: u64,
    },
    DeviceStatusUpdated {
        device_id: String,
        status: DeviceStatus,
    },
    OnlineDevices {
        devices: Vec<OnlineDevice>,
    },
    CandidateTokenIssued {
        #[serde(with = "remote_protocol::serde_uuid_u128")]
        session_id: u128,
        device_id: String,
        role: SessionRole,
        #[serde(with = "remote_protocol::serde_hex_u128")]
        candidate_id: u128,
        candidate_token: Vec<u8>,
        candidate_token_binding_hash: [u8; 32],
        expires_at_epoch_millis: u64,
    },
    SessionMessageForwarded {
        session_id: String,
        message_type: &'static str,
        target_device_id: String,
    },
    AuthFailed {
        code: ErrorCode,
        message: String,
    },
    Error {
        code: ErrorCode,
        message: String,
    },
}

async fn send_server_message(socket: &mut WebSocket, message: &ServerMessage) -> Result<(), ()> {
    let text = serde_json::to_string(message).map_err(|_| ())?;
    socket
        .send(Message::Text(text.into()))
        .await
        .map_err(|_| ())
}

async fn reject_socket(socket: &mut WebSocket, reason: &str) {
    let _ = send_server_message(
        socket,
        &ServerMessage::AuthFailed {
            code: ErrorCode::AuthenticationFailed,
            message: reason.to_owned(),
        },
    )
    .await;
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code: 1008,
            reason: "authentication failed".into(),
        })))
        .await;
    warn!(reason, "websocket authentication rejected");
}

fn online_device(
    device: &TrustedDevice,
    connection_id: &str,
    capabilities_hash: &[u8; 32],
    status: DeviceStatus,
) -> OnlineDevice {
    OnlineDevice {
        account_id: device.account_id.clone(),
        device_id: device.device_id.clone(),
        public_key_id: device.public_key_id.clone(),
        public_key_version: device.public_key_version,
        public_key: encode(&device.public_key),
        client_capabilities_hash: encode_hex(capabilities_hash),
        status,
        last_seen_epoch_millis: now_epoch_millis(),
        connection_id: connection_id.to_owned(),
    }
}

async fn remove_presence(state: &AppState, account_id: &str, device_id: &str, connection_id: &str) {
    if let Err(error) = state
        .backend
        .remove_presence(account_id, device_id, connection_id)
        .await
    {
        warn!(%error, %device_id, %connection_id, "cannot remove device presence");
    }
}

async fn remove_connection(
    state: &AppState,
    account_id: &str,
    device_id: &str,
    connection_id: &str,
) {
    state.connections.unregister(device_id, connection_id).await;
    remove_presence(state, account_id, device_id, connection_id).await;
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .filter(|value| !value.is_empty())
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

fn http_error(status: StatusCode, code: &'static str, message: &'static str) -> Response {
    (
        status,
        Json(serde_json::json!({"code": code, "message": message})),
    )
        .into_response()
}

fn now_epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use ed25519_dalek::{Signer, SigningKey};
    use remote_protocol::{CandidateSource, TransportPath};
    use remote_transport::{
        candidate_id, local_interface_claim_hash, validate_candidate_authorization,
    };
    use security::{hello_signature_input, sha256, sign_access_token_for_test, AccessClaims};

    fn fixture() -> (AppState, SigningKey, TrustedDevice) {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let device = TrustedDevice {
            account_id: "account-1".to_owned(),
            device_id: "ubuntu-1".to_owned(),
            public_key_id: "key-1".to_owned(),
            public_key_version: 1,
            public_key: signing_key.verifying_key().to_bytes(),
            public_key_revoked: false,
        };
        let mut directory = DeviceDirectory::default();
        directory.insert(device.clone()).expect("device seed");
        (AppState::for_test(directory), signing_key, device)
    }

    #[tokio::test]
    async fn authorized_lan_candidate_token_is_bound_and_replay_is_rejected() {
        let (state, signing_key, device) = fixture();
        let session_id = uuid::Uuid::from_u128(0x00000000000040008000000000000001);
        state.add_test_session(SessionAuthorization {
            session_id: session_id.hyphenated().to_string(),
            controller_device_id: "ios-1".to_owned(),
            controlled_device_id: device.device_id.clone(),
            permissions_digest: "11".repeat(32),
            relay_token_epoch: 1,
        });
        let mut candidate = ConnectionCandidateDto {
            candidate_id: 0,
            session_id: session_id.as_u128(),
            device_id: device.device_id.clone(),
            role: SessionRole::Controlled,
            kind: TransportPath::LanDirect,
            endpoint: "192.168.1.10:50000".to_owned(),
            source: CandidateSource::LocalInterface,
            observe_result_id: None,
            priority: 0,
            rtt_ms: None,
            loss_ppm: None,
            jitter_ms: None,
            relay_node_id: None,
        };
        candidate.candidate_id = candidate_id(&candidate).expect("candidate ID");
        let now = now_epoch_millis();
        let mut request = CandidateTokenRequest {
            session_id: candidate.session_id,
            device_id: candidate.device_id.clone(),
            role: candidate.role,
            candidate_id: candidate.candidate_id,
            kind: candidate.kind,
            endpoint: candidate.endpoint.clone(),
            source: candidate.source,
            relay_node_id: None,
            observe_result_id: None,
            observe_result_binding_hash: None,
            local_interface_claim_hash: None,
            local_interface_signature: None,
            interface_name_hash: Some([1; 32]),
            interface_index_hash: Some([2; 32]),
            local_socket_nonce: Some([3; 32]),
            timestamp_epoch_millis: Some(now),
            requested_ttl_millis: 30_000,
        };
        let claim = local_interface_claim_hash(&request).expect("interface claim");
        request.local_interface_claim_hash = Some(claim);
        request.local_interface_signature = Some(signing_key.sign(&claim).to_bytes().to_vec());
        let message = serde_json::json!({
            "type": "request_candidate_token",
            "payload": request,
        })
        .to_string();

        let response = handle_authenticated_text(
            &state,
            &device.account_id,
            &device.device_id,
            &device.public_key,
            "controlled-connection",
            &message,
        )
        .await;
        let ServerMessage::CandidateTokenIssued {
            session_id: issued_session_id,
            device_id,
            role,
            candidate_id,
            candidate_token,
            candidate_token_binding_hash,
            expires_at_epoch_millis,
        } = response
        else {
            panic!("candidate token response expected");
        };
        assert_eq!(issued_session_id, candidate.session_id);
        assert_eq!(device_id, candidate.device_id);
        assert_eq!(role, candidate.role);
        assert_eq!(candidate_id, candidate.candidate_id);
        assert_eq!(candidate_token.len(), 32);
        validate_candidate_authorization(
            &candidate,
            &CandidateAuthorization {
                candidate_token,
                candidate_token_binding_hash,
                expires_at_epoch_millis,
            },
            now,
        )
        .expect("issued candidate authorization");

        let replay = handle_authenticated_text(
            &state,
            &device.account_id,
            &device.device_id,
            &device.public_key,
            "controlled-connection",
            &message,
        )
        .await;
        assert!(matches!(
            replay,
            ServerMessage::Error {
                code: ErrorCode::InvalidPayload,
                ..
            }
        ));
    }

    fn claims(now: u64) -> AccessClaims {
        AccessClaims {
            account_id: "account-1".to_owned(),
            account_session_id: "account-session-1".to_owned(),
            issued_at_epoch_millis: now.saturating_sub(1_000),
            expires_at_epoch_millis: now + 60_000,
            mfa_verified: false,
            token_type: "access".to_owned(),
        }
    }

    fn valid_hello(
        signing_key: &SigningKey,
        server_nonce: &[u8; 32],
        negotiation: &ProtocolNegotiation,
        now: u64,
    ) -> HelloResponse {
        let client_nonce = [8_u8; 32];
        let capabilities = serde_json::json!({
            "platform": "ubuntu",
            "os_version": "26.04",
            "arch": "x86_64",
            "transport": ["quic", "relay"]
        });
        let capabilities_hash = client_capabilities_hash(&capabilities).expect("capabilities hash");
        let canonical = hello_signature_input(
            server_nonce,
            &client_nonce,
            "account-1",
            "ubuntu-1",
            negotiation.selected_version,
            now,
            &negotiation.versions_hash,
            &capabilities_hash,
        )
        .expect("canonical");
        let signature = signing_key.sign(&sha256(&canonical));
        HelloResponse {
            account_id: "account-1".to_owned(),
            device_id: "ubuntu-1".to_owned(),
            client_nonce: encode(&client_nonce),
            timestamp: now,
            client_supported_protocol_versions: negotiation.client_versions.clone(),
            client_min_protocol_version: negotiation.client_min_version,
            public_key_id: "key-1".to_owned(),
            public_key_version: 1,
            client_supported_protocol_versions_hash: encode_hex(&negotiation.versions_hash),
            client_capabilities: capabilities,
            client_capabilities_hash: encode_hex(&capabilities_hash),
            device_signature: encode(&signature.to_bytes()),
        }
    }

    fn notification_body(message: Value) -> Value {
        serde_json::json!({
            "device_id": "ubuntu-1",
            "message": message,
        })
    }

    async fn push_json(state: &AppState, token: Option<&str>, body: Value) -> Response {
        push_bytes(
            state,
            token,
            Bytes::from(serde_json::to_vec(&body).expect("push JSON")),
        )
        .await
    }

    async fn push_bytes(state: &AppState, token: Option<&str>, body: Bytes) -> Response {
        let mut headers = HeaderMap::new();
        if let Some(token) = token {
            headers.insert(
                axum::http::header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {token}")).expect("service token header"),
            );
        }
        internal_push(State(state.clone()), headers, body).await
    }

    #[tokio::test]
    async fn account_token_and_device_signature_authenticate_device() {
        let (state, signing_key, _) = fixture();
        let now = 1_000_000;
        let negotiation = parse_protocol_headers(Some("1"), Some("1")).expect("negotiation");
        let response = valid_hello(&signing_key, &[3; 32], &negotiation, now);

        let result = authenticate_hello(
            &state,
            &claims(now),
            "access-token",
            &negotiation,
            &[3; 32],
            now + HELLO_TTL_MILLIS,
            response,
            now,
        )
        .await
        .expect("authenticated");

        assert_eq!(result.device.device_id, "ubuntu-1");
        assert_ne!(result.capabilities_hash, [0; 32]);
    }

    #[test]
    fn runtime_device_auth_binds_internal_api_response_and_service_bearer() {
        let config = AppConfig::for_test();
        let state = AppState::with_backend(config.clone(), StateBackend::memory());
        let DeviceAuthenticator::Api(authenticator) = state.device_authenticator else {
            panic!("runtime must use API device authorization");
        };
        assert_eq!(authenticator.service_token, config.service_token);
        assert!(authenticator
            .endpoint
            .ends_with("/internal/v1/signal/device-auth"));
        let request = DeviceAuthRequest {
            access_token: "account-access-token".to_owned(),
            account_id: "account-1".to_owned(),
            device_id: "ubuntu-1".to_owned(),
            public_key_id: "key-1".to_owned(),
            public_key_version: 1,
        };
        let device = trusted_device_from_response(
            &request,
            DeviceAuthResponse {
                authorized: true,
                account_id: "account-1".to_owned(),
                device_id: "ubuntu-1".to_owned(),
                public_key: encode(&SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes()),
                public_key_id: "key-1".to_owned(),
                public_key_version: 1,
                access_token_expires_at_epoch_millis: 2_000_000,
            },
            1_000_000,
        )
        .expect("authorized device");
        assert_eq!(device.public_key_id, "key-1");
        assert_eq!(device.public_key_version, 1);
    }

    #[tokio::test]
    async fn runtime_state_rejects_invalid_redis_without_memory_fallback() {
        let mut config = AppConfig::for_test();
        config.redis_url = "http://not-redis".to_owned();
        assert!(AppState::new(config).await.is_err());
    }

    #[tokio::test]
    async fn memory_health_reports_explicit_backends() {
        let (state, _, _) = fixture();
        let (status, response) = health_snapshot(&state).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(response.online_backend, "memory");
        assert_eq!(response.hello_replay_backend, "memory");
        assert!(!response.redis_migration_pending);
    }

    #[tokio::test]
    async fn rejects_account_mismatch_signature_tampering_and_nonce_replay() {
        let (state, signing_key, _) = fixture();
        let now = 1_000_000;
        let negotiation = parse_protocol_headers(Some("1"), Some("1")).expect("negotiation");

        let mut account_mismatch = valid_hello(&signing_key, &[3; 32], &negotiation, now);
        account_mismatch.account_id = "account-2".to_owned();
        assert!(matches!(
            authenticate_hello(
                &state,
                &claims(now),
                "access-token",
                &negotiation,
                &[3; 32],
                now + HELLO_TTL_MILLIS,
                account_mismatch,
                now,
            )
            .await,
            Err("account_id does not match access token")
        ));

        let mut tampered = valid_hello(&signing_key, &[3; 32], &negotiation, now);
        tampered.client_capabilities["arch"] = Value::String("aarch64".to_owned());
        assert!(matches!(
            authenticate_hello(
                &state,
                &claims(now),
                "access-token",
                &negotiation,
                &[3; 32],
                now + HELLO_TTL_MILLIS,
                tampered,
                now,
            )
            .await,
            Err("client capabilities hash mismatch")
        ));

        let first = valid_hello(&signing_key, &[3; 32], &negotiation, now);
        authenticate_hello(
            &state,
            &claims(now),
            "access-token",
            &negotiation,
            &[3; 32],
            now + HELLO_TTL_MILLIS,
            first,
            now,
        )
        .await
        .expect("first hello");
        let replay = valid_hello(&signing_key, &[3; 32], &negotiation, now);
        assert!(matches!(
            authenticate_hello(
                &state,
                &claims(now),
                "access-token",
                &negotiation,
                &[3; 32],
                now + HELLO_TTL_MILLIS,
                replay,
                now,
            )
            .await,
            Err("hello nonce replay detected")
        ));
    }

    #[tokio::test]
    async fn websocket_rejects_missing_token_and_protocol_headers_before_upgrade() {
        let (state, _, _) = fixture();
        let response = validate_upgrade(&state, &HeaderMap::new(), now_epoch_millis())
            .expect_err("missing token");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn websocket_rejects_invalid_protocol_header_before_upgrade() {
        let (state, _, _) = fixture();
        let now = now_epoch_millis();
        let token = sign_access_token_for_test(&claims(now), &state.config.token_secret);
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).expect("token header"),
        );
        headers.insert("x-rctl-protocol-versions", HeaderValue::from_static("1, 2"));
        headers.insert("x-rctl-min-protocol-version", HeaderValue::from_static("1"));
        let response = validate_upgrade(&state, &headers, now).expect_err("invalid header");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn websocket_registration_and_session_state_writes_are_rejected() {
        let (state, _, device) = fixture();
        let connection_id = "connection-1";
        state
            .backend
            .put_presence(online_device(
                &device,
                connection_id,
                &[1; 32],
                DeviceStatus::Online,
            ))
            .await
            .expect("presence");
        for message_type in ["register_device", "invite_session", "connection_state"] {
            let response = handle_authenticated_text(
                &state,
                &device.account_id,
                &device.device_id,
                &device.public_key,
                connection_id,
                &format!(r#"{{"type":"{message_type}"}}"#),
            )
            .await;
            assert!(matches!(
                response,
                ServerMessage::Error {
                    code: ErrorCode::PermissionDenied,
                    ..
                }
            ));
        }
    }

    #[tokio::test]
    async fn authorized_key_confirm_is_forwarded_only_to_the_session_peer() {
        let (state, _, device) = fixture();
        let session_id = "00000000-0000-4000-8000-000000000001";
        state.add_test_session(SessionAuthorization {
            session_id: session_id.to_owned(),
            controller_device_id: "ios-1".to_owned(),
            controlled_device_id: device.device_id.clone(),
            permissions_digest: "11".repeat(32),
            relay_token_epoch: 1,
        });
        let mut peer = state.connections.register("ios-1", "ios-connection").await;
        let payload = serde_json::to_value(KeyConfirm {
            session_id: uuid::Uuid::parse_str(session_id).unwrap().as_u128(),
            device_id: device.device_id.clone(),
            role: SessionRole::Controlled,
            key_exchange_transcript_hash: [3; 32],
            confirm_mac: [5; 32],
            timestamp_epoch_millis: now_epoch_millis(),
        })
        .expect("key confirm");
        let response = handle_authenticated_text(
            &state,
            &device.account_id,
            &device.device_id,
            &device.public_key,
            "ubuntu-connection",
            &serde_json::json!({
                "type": "key_confirm",
                "session_id": session_id,
                "role": "controlled",
                "payload": payload,
            })
            .to_string(),
        )
        .await;

        assert!(matches!(
            response,
            ServerMessage::SessionMessageForwarded {
                session_id: forwarded_session,
                message_type: "key_confirm",
                target_device_id,
            } if forwarded_session == session_id && target_device_id == "ios-1"
        ));
        let forwarded = peer.notifications.recv().await.expect("forwarded message");
        let forwarded: Value = serde_json::from_str(&forwarded).expect("forwarded json");
        assert_eq!(forwarded["type"], "key_confirm");
        assert_eq!(forwarded["from_device_id"], "ubuntu-1");
        assert_eq!(forwarded["session_id"], session_id);
        assert_eq!(forwarded["payload"]["device_id"], "ubuntu-1");
    }

    #[tokio::test]
    async fn controlled_candidate_transport_identity_is_forwarded_unchanged_to_controller() {
        let (state, _, device) = fixture();
        let session_id = "00000000-0000-4000-8000-000000000001";
        let binary_session_id = uuid::Uuid::parse_str(session_id).unwrap().as_u128();
        state.add_test_session(SessionAuthorization {
            session_id: session_id.to_owned(),
            controller_device_id: "ios-1".to_owned(),
            controlled_device_id: device.device_id.clone(),
            permissions_digest: "11".repeat(32),
            relay_token_epoch: 1,
        });
        let mut peer = state.connections.register("ios-1", "ios-connection").await;
        let certificate = URL_SAFE_NO_PAD.encode([0x30, 0x01, 0x00]);
        let server_name = format!("rctl-{session_id}.invalid");
        let payload = serde_json::json!({
            "candidate": ConnectionCandidateDto {
                candidate_id: 1,
                session_id: binary_session_id,
                device_id: device.device_id.clone(),
                role: SessionRole::Controlled,
                kind: TransportPath::LanDirect,
                endpoint: "192.168.1.10:50000".to_owned(),
                source: CandidateSource::LocalInterface,
                observe_result_id: None,
                priority: 0,
                rtt_ms: None,
                loss_ppm: None,
                jitter_ms: None,
                relay_node_id: None,
            },
            "authorization": CandidateAuthorization {
                candidate_token: vec![1; 32],
                candidate_token_binding_hash: [2; 32],
                expires_at_epoch_millis: now_epoch_millis() + 30_000,
            },
            "transport_certificate_der": certificate,
            "server_name": server_name,
        });
        let response = handle_authenticated_text(
            &state,
            &device.account_id,
            &device.device_id,
            &device.public_key,
            "ubuntu-connection",
            &serde_json::json!({
                "type": "connection_candidate",
                "session_id": session_id,
                "role": "controlled",
                "payload": payload,
            })
            .to_string(),
        )
        .await;

        assert!(matches!(
            response,
            ServerMessage::SessionMessageForwarded {
                session_id: forwarded_session,
                message_type: "connection_candidate",
                target_device_id,
            } if forwarded_session == session_id && target_device_id == "ios-1"
        ));
        let forwarded = peer.notifications.recv().await.expect("forwarded message");
        let forwarded: Value = serde_json::from_str(&forwarded).expect("forwarded json");
        assert_eq!(forwarded["type"], "connection_candidate");
        assert_eq!(forwarded["from_device_id"], "ubuntu-1");
        assert_eq!(
            forwarded["payload"]["transport_certificate_der"],
            certificate
        );
        assert_eq!(forwarded["payload"]["server_name"], server_name);
        assert_eq!(forwarded["payload"]["candidate"]["session_id"], session_id);
    }

    #[tokio::test]
    async fn session_forward_rejects_payload_device_or_role_substitution() {
        let (state, _, device) = fixture();
        let session_id = "00000000-0000-4000-8000-000000000001";
        state.add_test_session(SessionAuthorization {
            session_id: session_id.to_owned(),
            controller_device_id: "ios-1".to_owned(),
            controlled_device_id: device.device_id.clone(),
            permissions_digest: "11".repeat(32),
            relay_token_epoch: 1,
        });
        let payload = serde_json::to_value(KeyConfirm {
            session_id: uuid::Uuid::parse_str(session_id).unwrap().as_u128(),
            device_id: "substituted-device".to_owned(),
            role: SessionRole::Controlled,
            key_exchange_transcript_hash: [3; 32],
            confirm_mac: [5; 32],
            timestamp_epoch_millis: now_epoch_millis(),
        })
        .expect("key confirm");
        let response = handle_authenticated_text(
            &state,
            &device.account_id,
            &device.device_id,
            &device.public_key,
            "ubuntu-connection",
            &serde_json::json!({
                "type": "key_confirm",
                "session_id": session_id,
                "role": "controlled",
                "payload": payload,
            })
            .to_string(),
        )
        .await;

        assert!(
            matches!(
                &response,
                ServerMessage::Error {
                    code: ErrorCode::InvalidPayload,
                    ..
                }
            ),
            "unexpected response: {response:?}"
        );
    }

    #[test]
    fn controlled_candidate_requires_a_bounded_session_transport_identity() {
        let session_id = uuid::Uuid::from_u128(0x00000000000040008000000000000001);
        let candidate = ConnectionCandidateDto {
            candidate_id: 1,
            session_id: session_id.as_u128(),
            device_id: "ubuntu-1".to_owned(),
            role: SessionRole::Controlled,
            kind: TransportPath::LanDirect,
            endpoint: "192.168.1.10:50000".to_owned(),
            source: CandidateSource::LocalInterface,
            observe_result_id: None,
            priority: 0,
            rtt_ms: None,
            loss_ppm: None,
            jitter_ms: None,
            relay_node_id: None,
        };
        let authorization = CandidateAuthorization {
            candidate_token: vec![1; 32],
            candidate_token_binding_hash: [2; 32],
            expires_at_epoch_millis: now_epoch_millis() + 30_000,
        };
        let base = serde_json::json!({
            "candidate": candidate,
            "authorization": authorization,
        });
        assert!(!validate_forward_payload(
            "connection_candidate",
            &base,
            session_id.as_u128(),
            "ubuntu-1",
            SessionRole::Controlled,
        ));

        let valid = serde_json::json!({
            "candidate": candidate,
            "authorization": authorization,
            "transport_certificate_der": URL_SAFE_NO_PAD.encode([0x30, 0x01, 0x00]),
            "server_name": format!("rctl-{session_id}.invalid"),
        });
        assert!(validate_forward_payload(
            "connection_candidate",
            &valid,
            session_id.as_u128(),
            "ubuntu-1",
            SessionRole::Controlled,
        ));

        for (certificate, server_name) in [
            ("not-base64!", "rctl-session.invalid"),
            ("MAEA", "localhost"),
        ] {
            let invalid = serde_json::json!({
                "candidate": candidate,
                "authorization": authorization,
                "transport_certificate_der": certificate,
                "server_name": server_name,
            });
            assert!(!validate_forward_payload(
                "connection_candidate",
                &invalid,
                session_id.as_u128(),
                "ubuntu-1",
                SessionRole::Controlled,
            ));
        }
    }

    #[tokio::test]
    async fn internal_push_requires_the_service_bearer() {
        let (state, _, _) = fixture();
        let body = notification_body(serde_json::json!({
            "type": "session_invite",
            "session": {
                "session_id": "session-1",
                "status": "waiting_approval",
                "controller_device_id": "windows-1",
                "controlled_device_id": "ubuntu-1"
            },
        }));

        assert_eq!(
            push_json(&state, None, body.clone()).await.status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            push_json(&state, Some("wrong-service-token"), body.clone())
                .await
                .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            push_json(&state, Some(&state.config.service_token), body)
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn internal_push_delivers_to_an_online_connection_and_cleanup_makes_it_offline() {
        let (state, _, device) = fixture();
        let connection_id = "notification-connection";
        state
            .backend
            .put_presence(online_device(
                &device,
                connection_id,
                &[1; 32],
                DeviceStatus::Online,
            ))
            .await
            .expect("presence");
        let mut registration = state
            .connections
            .register(&device.device_id, connection_id)
            .await;
        let message = serde_json::json!({
            "type": "session_invite",
            "session": {
                "session_id": "session-1",
                "status": "waiting_approval",
                "controller_device_id": "windows-1",
                "controlled_device_id": "ubuntu-1"
            },
        });

        let response = push_json(
            &state,
            Some(&state.config.service_token),
            notification_body(message.clone()),
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let delivered = timeout(Duration::from_secs(1), registration.notifications.recv())
            .await
            .expect("notification timeout")
            .expect("notification channel");
        assert_eq!(
            serde_json::from_str::<Value>(&delivered).expect("delivered JSON"),
            message
        );

        remove_connection(&state, &device.account_id, &device.device_id, connection_id).await;
        assert_eq!(state.online_count().await.expect("online count"), 0);
        assert_eq!(
            push_json(
                &state,
                Some(&state.config.service_token),
                notification_body(serde_json::json!({
                    "type": "session_invite",
                    "session": {
                        "session_id": "session-2",
                        "status": "waiting_approval",
                        "controller_device_id": "windows-1",
                        "controlled_device_id": "ubuntu-1"
                    },
                })),
            )
            .await
            .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn reconnect_replaces_notification_ownership_without_old_connection_delivery() {
        let (state, _, device) = fixture();
        let old_registration = state
            .connections
            .register(&device.device_id, "old-connection")
            .await;
        let mut old_notifications = old_registration.notifications;
        let old_superseded = old_registration.superseded;
        let mut new_registration = state
            .connections
            .register(&device.device_id, "new-connection")
            .await;
        timeout(Duration::from_secs(1), old_superseded)
            .await
            .expect("old connection supersede timeout")
            .expect("old connection superseded");

        let message = serde_json::json!({
            "type": "connection_state",
            "session_id": "session-1",
            "status": "connected",
            "actor_type": "device",
            "actor_device_id": "windows-1",
            "actor_role": "controller",
            "event_id": "event-1",
            "session": {
                "session_id": "session-1",
                "status": "connected",
                "controller_device_id": "windows-1",
                "controlled_device_id": "ubuntu-1"
            },
        });
        assert_eq!(
            push_json(
                &state,
                Some(&state.config.service_token),
                notification_body(message.clone()),
            )
            .await
            .status(),
            StatusCode::ACCEPTED
        );
        let delivered = new_registration
            .notifications
            .recv()
            .await
            .expect("new owner notification");
        assert_eq!(
            serde_json::from_str::<Value>(&delivered).expect("delivered JSON"),
            message
        );
        assert!(old_notifications.try_recv().is_err());
        assert!(
            !state
                .connections
                .unregister(&device.device_id, "old-connection")
                .await
        );
        assert!(
            state
                .connections
                .is_owner(&device.device_id, "new-connection")
                .await
        );
    }

    #[tokio::test]
    async fn internal_push_returns_overload_when_the_bounded_queue_is_full() {
        let (mut state, _, device) = fixture();
        state.connections = ConnectionRegistry::new(1);
        let _registration = state
            .connections
            .register(&device.device_id, "overloaded-connection")
            .await;
        let body = notification_body(serde_json::json!({
            "type": "session_invite",
            "session": {
                "session_id": "session-1",
                "status": "waiting_approval",
                "controller_device_id": "windows-1",
                "controlled_device_id": "ubuntu-1"
            },
        }));

        assert_eq!(
            push_json(&state, Some(&state.config.service_token), body.clone(),)
                .await
                .status(),
            StatusCode::ACCEPTED
        );
        assert_eq!(
            push_json(&state, Some(&state.config.service_token), body)
                .await
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn internal_push_rejects_unknown_oversized_and_non_notification_payloads() {
        let (state, _, _) = fixture();
        let token = state.config.service_token.as_str();
        let invalid_payloads = [
            serde_json::json!({
                "device_id": "ubuntu-1",
                "message": {"type": "session_invite", "session": {}},
                "unexpected": true,
            }),
            notification_body(serde_json::json!({
                "type": "create_session",
                "session": {},
            })),
            notification_body(serde_json::json!({
                "type": "session_invite",
                "session": {},
                "unexpected": true,
            })),
            notification_body(serde_json::json!({
                "type": "connection_state",
                "session": null,
            })),
        ];
        for payload in invalid_payloads {
            assert_eq!(
                push_json(&state, Some(token), payload).await.status(),
                StatusCode::BAD_REQUEST
            );
        }

        assert_eq!(
            push_bytes(
                &state,
                Some(token),
                Bytes::from(vec![b'x'; MAX_INTERNAL_PUSH_BODY_BYTES + 1]),
            )
            .await
            .status(),
            StatusCode::PAYLOAD_TOO_LARGE
        );
    }

    #[tokio::test]
    async fn online_list_is_account_scoped_and_disconnect_is_connection_safe() {
        let (state, _, device) = fixture();
        let foreign_device = TrustedDevice {
            account_id: "account-2".to_owned(),
            device_id: "windows-2".to_owned(),
            public_key_id: "key-2".to_owned(),
            public_key_version: 1,
            public_key: [2; 32],
            public_key_revoked: false,
        };
        for presence in [
            online_device(&device, "new-connection", &[1; 32], DeviceStatus::Online),
            online_device(
                &foreign_device,
                "foreign-connection",
                &[2; 32],
                DeviceStatus::Online,
            ),
        ] {
            state
                .backend
                .put_presence(presence)
                .await
                .expect("presence");
        }

        let response = handle_authenticated_text(
            &state,
            &device.account_id,
            &device.device_id,
            &device.public_key,
            "new-connection",
            r#"{"type":"list_online_devices"}"#,
        )
        .await;
        let ServerMessage::OnlineDevices { devices } = response else {
            panic!("online devices response expected");
        };
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, device.device_id);

        remove_presence(
            &state,
            &device.account_id,
            &device.device_id,
            "old-connection",
        )
        .await;
        assert_eq!(state.online_count().await.expect("online count"), 2);
        remove_presence(
            &state,
            &device.account_id,
            &device.device_id,
            "new-connection",
        )
        .await;
        assert_eq!(state.online_count().await.expect("online count"), 1);
    }

    #[tokio::test]
    async fn device_status_uses_server_time_in_memory_backend() {
        let (state, _, device) = fixture();
        let connection_id = "connection-server-time";
        state
            .backend
            .put_presence(online_device(
                &device,
                connection_id,
                &[1; 32],
                DeviceStatus::Online,
            ))
            .await
            .expect("presence");

        let before_update = now_epoch_millis();
        let response = handle_authenticated_text(
            &state,
            &device.account_id,
            &device.device_id,
            &device.public_key,
            connection_id,
            &format!(
                r#"{{"type":"set_device_status","device_id":"{}","status":"busy","seen_at_epoch_millis":{}}}"#,
                device.device_id,
                u64::MAX
            ),
        )
        .await;
        let after_update = now_epoch_millis();
        assert!(matches!(
            response,
            ServerMessage::DeviceStatusUpdated {
                status: DeviceStatus::Busy,
                ..
            }
        ));

        let devices = state
            .backend
            .list_presence(&device.account_id)
            .await
            .expect("presence list");
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].status, DeviceStatus::Busy);
        assert_ne!(devices[0].last_seen_epoch_millis, u64::MAX);
        assert!(devices[0].last_seen_epoch_millis >= before_update);
        assert!(devices[0].last_seen_epoch_millis <= after_update);
    }

    #[tokio::test]
    #[ignore = "requires Redis on SIGNAL_TEST_REDIS_URL or 127.0.0.1:16379"]
    async fn redis_backend_persists_presence_and_replay_state() {
        let redis_url = env::var("SIGNAL_TEST_REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:16379/0".to_owned());
        let backend = StateBackend::connect_redis(&redis_url)
            .await
            .expect("Redis integration backend");
        let suffix = encode(&random::<[u8; 8]>());
        let account_id = format!("signal-test-account-{suffix}");
        let device_id = format!("signal-test-device-{suffix}");
        let device = TrustedDevice {
            account_id: account_id.clone(),
            device_id: device_id.clone(),
            public_key_id: "signal-test-key".to_owned(),
            public_key_version: 1,
            public_key: [3; 32],
            public_key_revoked: false,
        };
        backend
            .put_presence(online_device(
                &device,
                "redis-connection",
                &[4; 32],
                DeviceStatus::Online,
            ))
            .await
            .expect("put Redis presence");

        let devices = backend
            .list_presence(&account_id)
            .await
            .expect("list Redis presence");
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].connection_id, "redis-connection");
        assert_eq!(
            backend
                .update_presence(
                    &account_id,
                    &device_id,
                    "old-connection",
                    DeviceStatus::Busy,
                    now_epoch_millis(),
                )
                .await
                .expect("connection-safe update"),
            PresenceMutation::Superseded
        );

        let state = AppState::with_backend(AppConfig::for_test(), backend.clone());
        let before_update = now_epoch_millis();
        let response = handle_authenticated_text(
            &state,
            &account_id,
            &device_id,
            &[0; 32],
            "redis-connection",
            &format!(
                r#"{{"type":"set_device_status","device_id":"{device_id}","status":"busy","seen_at_epoch_millis":{}}}"#,
                u64::MAX
            ),
        )
        .await;
        let after_update = now_epoch_millis();
        assert!(matches!(
            response,
            ServerMessage::DeviceStatusUpdated {
                status: DeviceStatus::Busy,
                ..
            }
        ));
        let devices = backend
            .list_presence(&account_id)
            .await
            .expect("updated Redis presence");
        assert_eq!(devices[0].status, DeviceStatus::Busy);
        assert_ne!(devices[0].last_seen_epoch_millis, u64::MAX);
        assert!(devices[0].last_seen_epoch_millis >= before_update);
        assert!(devices[0].last_seen_epoch_millis <= after_update);

        let now = now_epoch_millis();
        assert_eq!(
            backend
                .record_hello_nonce_once(
                    &account_id,
                    &device_id,
                    &[5; 32],
                    now + HELLO_TTL_MILLIS,
                    now,
                )
                .await
                .expect("record nonce"),
            ReplayRecord::Recorded
        );
        assert_eq!(
            backend
                .record_hello_nonce_once(
                    &account_id,
                    &device_id,
                    &[5; 32],
                    now + HELLO_TTL_MILLIS,
                    now,
                )
                .await
                .expect("detect replay"),
            ReplayRecord::Duplicate
        );

        let (status, response) = health_snapshot(&state).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(response.online_backend, "redis");
        assert_eq!(response.hello_replay_backend, "redis");

        assert!(!backend
            .remove_presence(&account_id, &device_id, "old-connection")
            .await
            .expect("connection-safe remove"));
        assert!(backend
            .remove_presence(&account_id, &device_id, "redis-connection")
            .await
            .expect("remove Redis presence"));
        assert!(backend
            .list_presence(&account_id)
            .await
            .expect("empty Redis presence")
            .is_empty());
    }
}
