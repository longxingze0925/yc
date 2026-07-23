use crate::config::ServiceConfig;
use crate::identity::{DeviceIdentity, IdentityError};
use crate::secret_store::AccountTokens;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use remote_protocol::{canonical_json_bytes, PROTOCOL_VERSION};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::Zeroize;

const CONTENT_TYPE_JSON: &str = "application/json";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
}

impl HttpMethod {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

pub struct HttpRequest {
    pub method: HttpMethod,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header_names = self.headers.keys().collect::<Vec<_>>();
        formatter
            .debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field("header_names", &header_names)
            .field("body", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportError {
    message: String,
}

impl TransportError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for TransportError {}

pub trait HttpTransport: Send + Sync {
    fn execute(&self, request: HttpRequest) -> Result<HttpResponse, TransportError>;
}

#[derive(Debug, Clone)]
pub struct ReqwestHttpTransport {
    client: reqwest::blocking::Client,
}

impl ReqwestHttpTransport {
    pub fn new() -> Result<Self, TransportError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| TransportError::new(format!("HTTP 客户端初始化失败: {error}")))?;
        Ok(Self { client })
    }
}

impl HttpTransport for ReqwestHttpTransport {
    fn execute(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
        let method = reqwest::Method::from_bytes(request.method.as_str().as_bytes())
            .map_err(|_| TransportError::new("不支持的 HTTP 方法"))?;
        let mut builder = self.client.request(method, &request.url);
        for (name, value) in request.headers {
            builder = builder.header(name, value);
        }
        if !request.body.is_empty() {
            builder = builder.body(request.body);
        }
        let response = builder
            .send()
            .map_err(|error| TransportError::new(format!("HTTP 请求失败: {error}")))?;
        let status = response.status().as_u16();
        let body = response
            .bytes()
            .map_err(|error| TransportError::new(format!("HTTP 响应读取失败: {error}")))?
            .to_vec();
        Ok(HttpResponse { status, body })
    }
}

#[derive(Debug)]
pub enum ApiClientError {
    Transport(TransportError),
    Identity(IdentityError),
    Serialization,
    InvalidResponse(&'static str),
    Http {
        status: u16,
        code: String,
        message: String,
        request_id: Option<String>,
    },
}

impl ApiClientError {
    pub fn code(&self) -> Option<&str> {
        match self {
            Self::Http { code, .. } => Some(code),
            _ => None,
        }
    }
}

impl fmt::Display for ApiClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "{error}"),
            Self::Identity(error) => write!(formatter, "{error}"),
            Self::Serialization => formatter.write_str("请求或响应 JSON 处理失败"),
            Self::InvalidResponse(reason) => write!(formatter, "API 响应无效: {reason}"),
            Self::Http {
                status,
                code,
                message,
                request_id,
            } => {
                write!(formatter, "API {status} {code}: {message}")?;
                if let Some(request_id) = request_id {
                    write!(formatter, " (request_id={request_id})")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ApiClientError {}

impl From<TransportError> for ApiClientError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

impl From<IdentityError> for ApiClientError {
    fn from(error: IdentityError) -> Self {
        Self::Identity(error)
    }
}

pub struct ApiClient {
    config: ServiceConfig,
    transport: Arc<dyn HttpTransport>,
}

impl ApiClient {
    pub fn new(config: ServiceConfig, transport: Arc<dyn HttpTransport>) -> Self {
        Self { config, transport }
    }

    pub fn health(&self) -> Result<(), ApiClientError> {
        let response = self.transport.execute(HttpRequest {
            method: HttpMethod::Get,
            url: self.endpoint("/health"),
            headers: BTreeMap::new(),
            body: Vec::new(),
        })?;
        ensure_success(response).map(|_| ())
    }

    pub fn login(&self, request: &LoginRequest) -> Result<LoginChallenge, ApiClientError> {
        let response = self.send_json(HttpMethod::Post, "/v1/auth/login", request, None)?;
        serde_json::from_value(ensure_success(response)?)
            .map(|challenge: LoginChallenge| challenge.with_client_nonce(request.client_nonce.clone()))
            .map_err(|_| ApiClientError::Serialization)
    }

    pub fn finish_login(
        &self,
        challenge: &LoginChallenge,
        identity: &DeviceIdentity,
        factor: Option<MfaFactor>,
        code: Option<&str>,
    ) -> Result<LoginFinishOutcome, ApiClientError> {
        let request = LoginFinishRequest::new(challenge, factor, code);
        self.send_login_finish_json(&request, challenge, identity)
    }

    pub fn register_device(
        &self,
        access_token: &str,
        account_id: &str,
        identity: &DeviceIdentity,
        metadata: DeviceRegistrationMetadata,
        enrollment_grant: &str,
    ) -> Result<DeviceView, ApiClientError> {
        let request = RegisterDeviceRequest {
            device_id: identity.device_id().to_owned(),
            display_name: metadata.display_name,
            platform: metadata.platform,
            os_version: metadata.os_version,
            arch: metadata.arch,
            role_capabilities: metadata.role_capabilities,
            public_key: identity.encoded_public_key(),
            device_enrollment_grant: enrollment_grant.to_owned(),
        };
        self.send_signed_json(
            HttpMethod::Post,
            "/v1/devices",
            &request,
            access_token,
            account_id,
            identity,
        )
    }

    pub fn list_devices(&self, access_token: &str) -> Result<Vec<DeviceView>, ApiClientError> {
        let response =
            self.send_json::<()>(HttpMethod::Get, "/v1/devices", &(), Some(access_token))?;
        let list: DeviceListResponse = serde_json::from_value(ensure_success(response)?)
            .map_err(|_| ApiClientError::Serialization)?;
        Ok(list.devices)
    }

    pub fn create_session(
        &self,
        access_token: &str,
        account_id: &str,
        identity: &DeviceIdentity,
        request: &CreateSessionRequest,
    ) -> Result<CreateSessionResponse, ApiClientError> {
        self.send_signed_json(
            HttpMethod::Post,
            "/v1/sessions",
            request,
            access_token,
            account_id,
            identity,
        )
    }

    fn send_json<T: Serialize>(
        &self,
        method: HttpMethod,
        path: &str,
        body: &T,
        access_token: Option<&str>,
    ) -> Result<HttpResponse, ApiClientError> {
        let request_id = new_request_id();
        let body = if method == HttpMethod::Get {
            Vec::new()
        } else {
            canonical_json_bytes(body).map_err(|_| ApiClientError::Serialization)?
        };
        let mut headers = common_headers(&request_id);
        if !body.is_empty() {
            headers.insert("content-type".into(), CONTENT_TYPE_JSON.into());
        }
        if let Some(access_token) = access_token {
            headers.insert("authorization".into(), format!("Bearer {access_token}"));
        }
        self.transport
            .execute(HttpRequest {
                method,
                url: self.endpoint(path),
                headers,
                body,
            })
            .map_err(Into::into)
    }

    #[allow(clippy::too_many_arguments)]
    fn send_signed_json<T: Serialize, R: DeserializeOwned>(
        &self,
        method: HttpMethod,
        path: &str,
        body: &T,
        access_token: &str,
        account_id: &str,
        identity: &DeviceIdentity,
    ) -> Result<R, ApiClientError> {
        let request_id = new_request_id();
        let api_nonce = Uuid::new_v4().to_string();
        let timestamp = now_epoch_millis();
        let encoded = canonical_json_bytes(body).map_err(|_| ApiClientError::Serialization)?;
        let signature = identity.sign_api_request(
            method.as_str(),
            path,
            body,
            &request_id,
            account_id,
            timestamp,
            &api_nonce,
        )?;
        let mut headers = common_headers(&request_id);
        headers.insert("content-type".into(), CONTENT_TYPE_JSON.into());
        headers.insert("authorization".into(), format!("Bearer {access_token}"));
        headers.insert("x-rctl-device-id".into(), identity.device_id().into());
        headers.insert("x-rctl-timestamp".into(), timestamp.to_string());
        headers.insert("x-rctl-api-nonce".into(), api_nonce);
        headers.insert("x-rctl-device-signature".into(), signature);
        let response = self.transport.execute(HttpRequest {
            method,
            url: self.endpoint(path),
            headers,
            body: encoded,
        })?;
        serde_json::from_value(ensure_success(response)?).map_err(|_| ApiClientError::Serialization)
    }

    fn send_login_finish_json(
        &self,
        body: &LoginFinishRequest,
        challenge: &LoginChallenge,
        identity: &DeviceIdentity,
    ) -> Result<LoginFinishOutcome, ApiClientError> {
        let request_id = new_request_id();
        let api_nonce = Uuid::new_v4().to_string();
        let timestamp = now_epoch_millis();
        let encoded = canonical_json_bytes(body).map_err(|_| ApiClientError::Serialization)?;
        let signature = identity.sign_api_request(
            HttpMethod::Post.as_str(),
            "/v1/auth/login/finish",
            body,
            &request_id,
            &challenge.account_id,
            timestamp,
            &api_nonce,
        )?;
        let mut headers = common_headers(&request_id);
        headers.insert("content-type".into(), CONTENT_TYPE_JSON.into());
        headers.insert("x-rctl-device-id".into(), identity.device_id().into());
        headers.insert("x-rctl-timestamp".into(), timestamp.to_string());
        headers.insert("x-rctl-api-nonce".into(), api_nonce);
        headers.insert("x-rctl-device-signature".into(), signature);
        let response = self.transport.execute(HttpRequest {
            method: HttpMethod::Post,
            url: self.endpoint("/v1/auth/login/finish"),
            headers,
            body: encoded,
        })?;
        let response: LoginFinishResponse = serde_json::from_value(ensure_success(response)?)
            .map_err(|_| ApiClientError::Serialization)?;
        Ok(LoginFinishOutcome::from_response(
            response,
            challenge.device_state.clone(),
        ))
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.config.api_base_url)
    }
}

fn common_headers(request_id: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("x-request-id".into(), request_id.into()),
        (
            "x-rctl-protocol-version".into(),
            PROTOCOL_VERSION.to_string(),
        ),
    ])
}

fn ensure_success(response: HttpResponse) -> Result<serde_json::Value, ApiClientError> {
    if (200..300).contains(&response.status) {
        if response.body.is_empty() {
            return Ok(serde_json::Value::Null);
        }
        return serde_json::from_slice(&response.body).map_err(|_| ApiClientError::Serialization);
    }
    let body: ErrorResponse = serde_json::from_slice(&response.body).unwrap_or(ErrorResponse {
        code: "http_error".into(),
        message: "服务端返回了非成功状态".into(),
        request_id: None,
    });
    Err(ApiClientError::Http {
        status: response.status,
        code: body.code,
        message: body.message,
        request_id: body.request_id,
    })
}

fn new_request_id() -> String {
    Uuid::new_v4().to_string()
}

pub fn now_epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[derive(Serialize)]
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

impl LoginRequest {
    pub fn new(
        email: impl Into<String>,
        password: impl Into<String>,
        identity: &DeviceIdentity,
    ) -> Self {
        let mut nonce = [0_u8; 32];
        rand::rng().fill_bytes(&mut nonce);
        Self {
            email: email.into(),
            password: password.into(),
            device_id: identity.device_id().to_owned(),
            device_public_key: identity.encoded_public_key(),
            public_key_id: identity.public_key_id().map(ToOwned::to_owned),
            public_key_version: identity.public_key_version(),
            client_nonce: URL_SAFE_NO_PAD.encode(nonce),
            protocol_version: PROTOCOL_VERSION,
        }
    }
}

impl fmt::Debug for LoginRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoginRequest")
            .field("email", &self.email)
            .field("password", &"<redacted>")
            .field("device_id", &self.device_id)
            .field("public_key_id", &self.public_key_id)
            .field("public_key_version", &self.public_key_version)
            .field("client_nonce", &"<redacted>")
            .field("protocol_version", &self.protocol_version)
            .finish()
    }
}

impl Drop for LoginRequest {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct LoginChallenge {
    pub account_id: String,
    pub login_challenge_id: String,
    pub login_request_binding_hash: String,
    pub login_challenge_binding_hash: String,
    pub server_nonce: String,
    pub device_state: String,
    pub required_factors: Vec<String>,
    pub expires_at_epoch_millis: u64,
    pub attempts_remaining: u8,
    #[serde(skip)]
    pub client_nonce: String,
}

impl LoginChallenge {
    pub fn with_client_nonce(mut self, client_nonce: String) -> Self {
        self.client_nonce = client_nonce;
        self
    }

    pub fn mfa_challenge(&self) -> MfaChallenge {
        MfaChallenge {
            code: "login_challenge_required".into(),
            mfa_required: !self.required_factors.is_empty(),
            mfa_challenge_id: self.login_challenge_id.clone(),
            allowed_factors: self
                .required_factors
                .iter()
                .filter_map(|value| match value.as_str() {
                    "totp" => Some(MfaFactor::Totp),
                    "recovery_code" => Some(MfaFactor::RecoveryCode),
                    _ => None,
                })
                .collect(),
            expires_at_epoch_millis: self.expires_at_epoch_millis,
            attempts_remaining: self.attempts_remaining,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct MfaChallenge {
    pub code: String,
    pub mfa_required: bool,
    pub mfa_challenge_id: String,
    pub allowed_factors: Vec<MfaFactor>,
    pub expires_at_epoch_millis: u64,
    pub attempts_remaining: u8,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MfaFactor {
    Totp,
    RecoveryCode,
}

#[derive(Serialize)]
struct LoginFinishRequest {
    login_challenge_id: String,
    login_request_binding_hash: String,
    login_challenge_binding_hash: String,
    client_nonce: String,
    server_nonce: String,
    factor: Option<MfaFactor>,
    code: Option<String>,
    protocol_version: u16,
}

impl LoginFinishRequest {
    fn new(challenge: &LoginChallenge, factor: Option<MfaFactor>, code: Option<&str>) -> Self {
        Self {
            login_challenge_id: challenge.login_challenge_id.clone(),
            login_request_binding_hash: challenge.login_request_binding_hash.clone(),
            login_challenge_binding_hash: challenge.login_challenge_binding_hash.clone(),
            client_nonce: challenge.client_nonce.clone(),
            server_nonce: challenge.server_nonce.clone(),
            factor,
            code: code.map(ToOwned::to_owned),
            protocol_version: PROTOCOL_VERSION,
        }
    }
}

impl fmt::Debug for LoginFinishRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoginFinishRequest")
            .field("login_challenge_id", &self.login_challenge_id)
            .field("factor", &self.factor)
            .field("code", &"<redacted>")
            .finish()
    }
}

impl Drop for LoginFinishRequest {
    fn drop(&mut self) {
        if let Some(code) = &mut self.code {
            code.zeroize();
        }
    }
}

pub struct LoginFinishOutcome {
    pub tokens: AccountTokens,
    pub device_enrollment_grant: Option<String>,
    pub device_state: String,
}

impl LoginFinishOutcome {
    fn from_response(response: LoginFinishResponse, device_state: String) -> Self {
        Self {
            tokens: AccountTokens::new(
                response.account_id,
                response.access_token,
                response.refresh_token,
                response.access_token_expires_at_epoch_millis,
                response.refresh_token_expires_at_epoch_millis,
            ),
            device_enrollment_grant: response.device_enrollment_grant,
            device_state,
        }
    }
}

impl fmt::Debug for LoginFinishOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoginFinishOutcome")
            .field("tokens", &self.tokens)
            .field("device_enrollment_grant", &"<redacted>")
            .field("device_state", &self.device_state)
            .finish()
    }
}

#[derive(Deserialize)]
struct LoginFinishResponse {
    account_id: String,
    access_token: String,
    refresh_token: String,
    access_token_expires_at_epoch_millis: u64,
    refresh_token_expires_at_epoch_millis: u64,
    device_enrollment_grant: Option<String>,
}

#[derive(Deserialize)]
struct ErrorResponse {
    code: String,
    message: String,
    request_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Windows,
    Ubuntu,
    Ios,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Aarch64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceCapabilities {
    pub controller: bool,
    pub controlled: bool,
    pub file_transfer: bool,
    pub unattended: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    Online,
    Offline,
    Busy,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceView {
    pub device_id: String,
    pub display_name: String,
    pub platform: Platform,
    pub os_version: String,
    pub arch: Architecture,
    pub role_capabilities: DeviceCapabilities,
    pub status: DeviceStatus,
    pub public_key_id: String,
    pub public_key_version: u32,
}

#[derive(Debug, Clone)]
pub struct DeviceRegistrationMetadata {
    pub display_name: String,
    pub platform: Platform,
    pub os_version: String,
    pub arch: Architecture,
    pub role_capabilities: DeviceCapabilities,
}

#[derive(Serialize)]
struct RegisterDeviceRequest {
    device_id: String,
    display_name: String,
    platform: Platform,
    os_version: String,
    arch: Architecture,
    role_capabilities: DeviceCapabilities,
    public_key: String,
    device_enrollment_grant: String,
}

#[derive(Deserialize)]
struct DeviceListResponse {
    devices: Vec<DeviceView>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    AccountPrompt,
    TemporaryCode,
    Unattended,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionPermissions {
    pub remote_desktop: bool,
    pub input_control: bool,
    pub clipboard: bool,
    pub file_transfer: bool,
    pub unattended: bool,
    pub privacy_screen: bool,
    pub block_local_input: bool,
    pub require_prompt: bool,
    pub allow_relay: bool,
}

impl SessionPermissions {
    pub const fn account_prompt_default() -> Self {
        Self {
            remote_desktop: true,
            input_control: true,
            clipboard: false,
            file_transfer: false,
            unattended: false,
            privacy_screen: false,
            block_local_input: false,
            require_prompt: true,
            allow_relay: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CreateSessionRequest {
    pub controller_device_id: String,
    pub controlled_device_id: String,
    pub auth_method: AuthMethod,
    pub requested_permissions: SessionPermissions,
    pub idempotency_key: String,
}

impl CreateSessionRequest {
    pub fn account_prompt(
        controller_device_id: impl Into<String>,
        controlled_device_id: impl Into<String>,
    ) -> Self {
        Self {
            controller_device_id: controller_device_id.into(),
            controlled_device_id: controlled_device_id.into(),
            auth_method: AuthMethod::AccountPrompt,
            requested_permissions: SessionPermissions::account_prompt_default(),
            idempotency_key: Uuid::new_v4().to_string(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct CreateSessionResponse {
    pub session_id: String,
    pub status: String,
    pub controlled_device_id: String,
    pub controlled_device_name: String,
    pub permissions: SessionPermissions,
    pub permissions_digest: String,
    pub policy_evaluation_id: String,
    pub session_expires_at_epoch_millis: u64,
    pub session_access_decision: String,
    #[serde(default)]
    pub matched_policy_ids: Vec<String>,
    #[serde(default)]
    pub abuse_actions: Vec<String>,
    #[serde(default)]
    pub user_warnings: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentityManager;
    use crate::secret_store::ProcessSecretStore;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingTransport {
        requests: Mutex<Vec<HttpRequest>>,
        responses: Mutex<VecDeque<HttpResponse>>,
    }

    impl RecordingTransport {
        fn respond(&self, status: u16, body: serde_json::Value) {
            self.responses
                .lock()
                .expect("responses")
                .push_back(HttpResponse {
                    status,
                    body: serde_json::to_vec(&body).expect("json"),
                });
        }

        fn take_request(&self) -> HttpRequest {
            self.requests.lock().expect("requests").remove(0)
        }
    }

    impl HttpTransport for RecordingTransport {
        fn execute(&self, request: HttpRequest) -> Result<HttpResponse, TransportError> {
            self.requests.lock().expect("requests").push(request);
            self.responses
                .lock()
                .expect("responses")
                .pop_front()
                .ok_or_else(|| TransportError::new("missing mock response"))
        }
    }

    fn config() -> ServiceConfig {
        ServiceConfig::new(
            "https://api.example.com",
            "wss://signal.example.com/ws",
            "relay.example.com:443",
            "private-fingerprint",
        )
        .expect("config")
    }

    fn token_json() -> serde_json::Value {
        serde_json::json!({
            "account_id": "account-1",
            "access_token": "access-private",
            "refresh_token": "refresh-private",
            "access_token_expires_at_epoch_millis": u64::MAX,
            "refresh_token_expires_at_epoch_millis": u64::MAX,
        })
    }

    #[test]
    fn login_starts_with_a_device_bound_challenge_without_tokens() {
        let transport = Arc::new(RecordingTransport::default());
        transport.respond(
            202,
            serde_json::json!({
                "code": "login_challenge_required",
                "account_id": "account-1",
                "login_challenge_id": "challenge-1",
                "login_request_binding_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "login_challenge_binding_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "server_nonce": "c2VydmVyLW5vbmNl",
                "device_state": "pending_enrollment",
                "required_factors": ["totp", "recovery_code"],
                "expires_at_epoch_millis": u64::MAX,
                "attempts_remaining": 5,
            }),
        );
        let client = ApiClient::new(config(), transport.clone());
        let store = Arc::new(ProcessSecretStore::default());
        let mut manager = DeviceIdentityManager::new(store);
        manager.load_or_create().expect("identity");
        let identity = manager.current().expect("identity");
        let request = LoginRequest::new("owner@example.com", "password-private", identity);
        let challenge = client.login(&request).expect("challenge");

        assert_eq!(challenge.device_state, "pending_enrollment");
        assert_eq!(challenge.mfa_challenge().attempts_remaining, 5);
        assert!(!format!("{request:?}").contains("password-private"));
        let login = transport.take_request();
        assert!(!login.headers.contains_key("authorization"));
        let body: serde_json::Value = serde_json::from_slice(&login.body).expect("login body");
        assert_eq!(body["device_id"], identity.device_id());
        assert_eq!(body["public_key_version"], 0);
        assert!(body["client_nonce"].as_str().is_some_and(|value| !value.is_empty()));
        assert!(body.get("access_token").is_none());
    }

    #[test]
    fn login_finish_uses_device_signature_and_never_bearer_auth() {
        let transport = Arc::new(RecordingTransport::default());
        transport.respond(
            202,
            serde_json::json!({
                "code": "login_challenge_required",
                "account_id": "account-1",
                "login_challenge_id": "challenge-1",
                "login_request_binding_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "login_challenge_binding_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "server_nonce": "c2VydmVyLW5vbmNl",
                "device_state": "pending_enrollment",
                "required_factors": ["totp", "recovery_code"],
                "expires_at_epoch_millis": u64::MAX,
                "attempts_remaining": 5,
            }),
        );
        let mut finish_response = token_json();
        finish_response.as_object_mut().expect("object").insert(
            "device_enrollment_grant".into(),
            serde_json::Value::String("grant-id.grant-private".into()),
        );
        transport.respond(200, finish_response);
        let client = ApiClient::new(config(), transport.clone());
        let store = Arc::new(ProcessSecretStore::default());
        let mut manager = DeviceIdentityManager::new(store);
        manager.load_or_create().expect("identity");
        let identity = manager.current().expect("identity");
        let login_request = LoginRequest::new("owner@example.com", "password-private", identity);
        let challenge = client.login(&login_request).expect("challenge");
        let outcome = client
            .finish_login(
                &challenge,
                identity,
                Some(MfaFactor::Totp),
                Some("123456-private"),
            )
            .expect("finish");

        assert_eq!(outcome.tokens.account_id, "account-1");
        assert_eq!(outcome.device_state, "pending_enrollment");
        assert_eq!(
            outcome.device_enrollment_grant.as_deref(),
            Some("grant-id.grant-private")
        );
        assert!(!format!("{outcome:?}").contains("grant-private"));
        let _login = transport.take_request();
        let finish = transport.take_request();
        assert!(finish.url.ends_with("/v1/auth/login/finish"));
        assert!(!finish.headers.contains_key("authorization"));
        assert!(finish.headers.contains_key("x-rctl-device-signature"));
        let body: serde_json::Value = serde_json::from_slice(&finish.body).expect("finish body");
        assert_eq!(body["factor"], "totp");
        assert_eq!(body["login_challenge_id"], "challenge-1");
        assert!(!format!("{finish:?}").contains("123456-private"));
    }

    #[test]
    fn login_finish_rejection_uses_generic_error_without_exposing_code() {
        let transport = Arc::new(RecordingTransport::default());
        transport.respond(
            202,
            serde_json::json!({
                "code": "login_challenge_required",
                "account_id": "account-1",
                "login_challenge_id": "challenge-1",
                "login_request_binding_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "login_challenge_binding_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "server_nonce": "c2VydmVyLW5vbmNl",
                "device_state": "registered",
                "required_factors": ["recovery_code"],
                "expires_at_epoch_millis": u64::MAX,
                "attempts_remaining": 5
            }),
        );
        transport.respond(
            403,
            serde_json::json!({
                "code": "login_verification_failed",
                "message": "challenge is invalid, expired, consumed, or the code is incorrect",
                "request_id": "request-1",
            }),
        );
        let client = ApiClient::new(config(), transport.clone());
        let store = Arc::new(ProcessSecretStore::default());
        let mut manager = DeviceIdentityManager::new(store);
        manager.load_or_create().expect("identity");
        let identity = manager.current().expect("identity");
        let challenge = client
            .login(&LoginRequest::new(
                "owner@example.com",
                "password-private",
                identity,
            ))
            .expect("challenge");
        let error = client
            .finish_login(
                &challenge,
                identity,
                Some(MfaFactor::RecoveryCode),
                Some("recovery-private"),
            )
            .expect_err("finish must fail");

        assert_eq!(error.code(), Some("login_verification_failed"));
        assert!(!error.to_string().contains("recovery-private"));
        let _login = transport.take_request();
        let finish = transport.take_request();
        assert!(!format!("{finish:?}").contains("recovery-private"));
    }

    #[test]
    fn signed_registration_and_session_creation_include_frozen_fields() {
        let transport = Arc::new(RecordingTransport::default());
        transport.respond(
            201,
            serde_json::json!({
                "device_id": "desktop-test",
                "display_name": "Test Desktop",
                "platform": "ubuntu",
                "os_version": "26.04",
                "arch": "x86_64",
                "role_capabilities": {"controller": true, "controlled": true, "file_transfer": false, "unattended": false},
                "status": "offline",
                "public_key_id": "key-1",
                "public_key_version": 1
            }),
        );
        transport.respond(
            201,
            serde_json::json!({
                "session_id": "session-1",
                "status": "waiting_approval",
                "controlled_device_id": "controlled-1",
                "controlled_device_name": "Target",
                "permissions": {
                    "remote_desktop": true, "input_control": true, "clipboard": false,
                    "file_transfer": false, "unattended": false, "privacy_screen": false,
                    "block_local_input": false, "require_prompt": true, "allow_relay": true
                },
                "permissions_digest": "digest",
                "policy_evaluation_id": "policy-1",
                "session_expires_at_epoch_millis": 99,
                "session_access_decision": "require_prompt"
            }),
        );
        let client = ApiClient::new(config(), transport.clone());
        let store = Arc::new(ProcessSecretStore::default());
        let mut manager = DeviceIdentityManager::new(store);
        manager.load_or_create().expect("identity");
        let identity = manager.current().expect("identity");
        let metadata = DeviceRegistrationMetadata {
            display_name: "Test Desktop".into(),
            platform: Platform::Ubuntu,
            os_version: "26.04".into(),
            arch: Architecture::X86_64,
            role_capabilities: DeviceCapabilities {
                controller: true,
                controlled: true,
                file_transfer: false,
                unattended: false,
            },
        };
        client
            .register_device(
                "access-private",
                "account-1",
                identity,
                metadata,
                "grant-id.grant-private",
            )
            .expect("register");
        let registration = transport.take_request();
        assert_eq!(registration.method, HttpMethod::Post);
        assert!(registration.headers.contains_key("x-rctl-device-signature"));
        assert_eq!(
            registration.headers.get("x-rctl-device-id"),
            Some(&identity.device_id().to_owned())
        );
        let registration_body: serde_json::Value =
            serde_json::from_slice(&registration.body).expect("registration body");
        assert_eq!(
            registration_body["device_enrollment_grant"],
            "grant-id.grant-private"
        );
        assert!(!format!("{registration:?}").contains("grant-private"));

        let request = CreateSessionRequest::account_prompt(identity.device_id(), "controlled-1");
        client
            .create_session("access-private", "account-1", identity, &request)
            .expect("session");
        let session = transport.take_request();
        let body: serde_json::Value = serde_json::from_slice(&session.body).expect("body");
        assert_eq!(body["controller_device_id"], identity.device_id());
        assert_eq!(body["controlled_device_id"], "controlled-1");
        assert!(!body["idempotency_key"].as_str().expect("key").is_empty());
        assert!(session.headers.contains_key("x-rctl-device-signature"));
        assert!(!format!("{session:?}").contains("access-private"));
    }

    #[test]
    fn device_list_uses_server_data_without_synthetic_entries() {
        let transport = Arc::new(RecordingTransport::default());
        transport.respond(
            200,
            serde_json::json!({"devices": [{
                "device_id": "device-1",
                "display_name": "Office",
                "platform": "windows",
                "os_version": "11",
                "arch": "x86_64",
                "role_capabilities": {"controller": true, "controlled": true, "file_transfer": false, "unattended": false},
                "status": "offline",
                "public_key_id": "key-1",
                "public_key_version": 1
            }]}),
        );
        let client = ApiClient::new(config(), transport);
        let devices = client.list_devices("access-private").expect("devices");
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].display_name, "Office");
    }
}
