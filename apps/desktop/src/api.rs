use crate::config::ServiceConfig;
use crate::identity::{DeviceIdentity, IdentityError};
use crate::secret_store::AccountTokens;
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

    pub fn login(&self, request: &LoginRequest) -> Result<LoginOutcome, ApiClientError> {
        let response = self.send_json(HttpMethod::Post, "/v1/auth/login", request, None)?;
        let value = ensure_success(response)?;
        if value
            .get("mfa_required")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            let challenge: MfaChallenge =
                serde_json::from_value(value).map_err(|_| ApiClientError::Serialization)?;
            return Ok(LoginOutcome::MfaRequired(challenge));
        }
        parse_tokens(value).map(LoginOutcome::Authenticated)
    }

    pub fn verify_mfa(&self, request: &MfaVerifyRequest) -> Result<AccountTokens, ApiClientError> {
        let response = self.send_json(HttpMethod::Post, "/v1/auth/mfa/verify", request, None)?;
        parse_tokens(ensure_success(response)?)
    }

    pub fn register_device(
        &self,
        access_token: &str,
        account_id: &str,
        identity: &DeviceIdentity,
        metadata: DeviceRegistrationMetadata,
    ) -> Result<DeviceView, ApiClientError> {
        let request = RegisterDeviceRequest {
            device_id: identity.device_id().to_owned(),
            display_name: metadata.display_name,
            platform: metadata.platform,
            os_version: metadata.os_version,
            arch: metadata.arch,
            role_capabilities: metadata.role_capabilities,
            public_key: identity.encoded_public_key(),
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

fn parse_tokens(value: serde_json::Value) -> Result<AccountTokens, ApiClientError> {
    let response: TokenResponse =
        serde_json::from_value(value).map_err(|_| ApiClientError::Serialization)?;
    Ok(AccountTokens::new(
        response.account_id,
        response.access_token,
        response.refresh_token,
        response.access_token_expires_at_epoch_millis,
        response.refresh_token_expires_at_epoch_millis,
    ))
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
    protocol_version: u16,
}

impl LoginRequest {
    pub fn new(email: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            email: email.into(),
            password: password.into(),
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
            .field("protocol_version", &self.protocol_version)
            .finish()
    }
}

impl Drop for LoginRequest {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

#[derive(Debug)]
pub enum LoginOutcome {
    Authenticated(AccountTokens),
    MfaRequired(MfaChallenge),
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
pub struct MfaVerifyRequest {
    mfa_challenge_id: String,
    factor: MfaFactor,
    code: String,
    protocol_version: u16,
}

impl MfaVerifyRequest {
    pub fn new(
        mfa_challenge_id: impl Into<String>,
        factor: MfaFactor,
        code: impl Into<String>,
    ) -> Self {
        Self {
            mfa_challenge_id: mfa_challenge_id.into(),
            factor,
            code: code.into(),
            protocol_version: PROTOCOL_VERSION,
        }
    }
}

impl fmt::Debug for MfaVerifyRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MfaVerifyRequest")
            .field("mfa_challenge_id", &self.mfa_challenge_id)
            .field("factor", &self.factor)
            .field("code", &"<redacted>")
            .field("protocol_version", &self.protocol_version)
            .finish()
    }
}

impl Drop for MfaVerifyRequest {
    fn drop(&mut self) {
        self.code.zeroize();
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    account_id: String,
    access_token: String,
    refresh_token: String,
    access_token_expires_at_epoch_millis: u64,
    refresh_token_expires_at_epoch_millis: u64,
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
    fn login_models_authenticated_and_mfa_responses_without_debug_leaks() {
        let transport = Arc::new(RecordingTransport::default());
        transport.respond(200, token_json());
        transport.respond(
            202,
            serde_json::json!({
                "code": "mfa_required",
                "mfa_required": true,
                "mfa_challenge_id": "challenge-1",
                "allowed_factors": ["totp", "recovery_code"],
                "expires_at_epoch_millis": 5_000,
                "attempts_remaining": 5,
            }),
        );
        let client = ApiClient::new(config(), transport);
        let request = LoginRequest::new("owner@example.com", "password-private");
        assert!(matches!(
            client.login(&request).expect("login"),
            LoginOutcome::Authenticated(_)
        ));
        assert!(matches!(
            client.login(&request).expect("mfa"),
            LoginOutcome::MfaRequired(MfaChallenge {
                attempts_remaining: 5,
                ..
            })
        ));
        assert!(!format!("{request:?}").contains("password-private"));
    }

    #[test]
    fn mfa_mock_flow_verifies_challenge_and_returns_authenticated_tokens() {
        let transport = Arc::new(RecordingTransport::default());
        transport.respond(
            202,
            serde_json::json!({
                "code": "mfa_required",
                "mfa_required": true,
                "mfa_challenge_id": "challenge-1",
                "allowed_factors": ["totp", "recovery_code"],
                "expires_at_epoch_millis": u64::MAX,
                "attempts_remaining": 5,
            }),
        );
        transport.respond(200, token_json());
        let client = ApiClient::new(config(), transport.clone());

        let challenge = match client
            .login(&LoginRequest::new("owner@example.com", "password-private"))
            .expect("mfa challenge")
        {
            LoginOutcome::MfaRequired(challenge) => challenge,
            LoginOutcome::Authenticated(_) => panic!("expected MFA challenge"),
        };
        let request = MfaVerifyRequest::new(
            challenge.mfa_challenge_id,
            MfaFactor::Totp,
            "123456-private",
        );
        let tokens = client.verify_mfa(&request).expect("MFA authenticated");

        assert_eq!(tokens.account_id, "account-1");
        let _login = transport.take_request();
        let verify = transport.take_request();
        assert!(verify.url.ends_with("/v1/auth/mfa/verify"));
        let body: serde_json::Value = serde_json::from_slice(&verify.body).expect("verify body");
        assert_eq!(body["factor"], "totp");
        assert_eq!(body["mfa_challenge_id"], "challenge-1");
        assert!(!format!("{request:?}").contains("123456-private"));
        assert!(!format!("{verify:?}").contains("123456-private"));
    }

    #[test]
    fn mfa_mock_rejection_uses_generic_error_without_exposing_code() {
        let transport = Arc::new(RecordingTransport::default());
        transport.respond(
            403,
            serde_json::json!({
                "code": "mfa_verification_failed",
                "message": "challenge is invalid, expired, consumed, or the code is incorrect",
                "request_id": "request-1",
            }),
        );
        let client = ApiClient::new(config(), transport);
        let request =
            MfaVerifyRequest::new("challenge-1", MfaFactor::RecoveryCode, "recovery-private");

        let error = client.verify_mfa(&request).expect_err("MFA must fail");

        assert_eq!(error.code(), Some("mfa_verification_failed"));
        assert!(!format!("{request:?}").contains("recovery-private"));
        assert!(!error.to_string().contains("recovery-private"));
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
            .register_device("access-private", "account-1", identity, metadata)
            .expect("register");
        let registration = transport.take_request();
        assert_eq!(registration.method, HttpMethod::Post);
        assert!(registration.headers.contains_key("x-rctl-device-signature"));
        assert_eq!(
            registration.headers.get("x-rctl-device-id"),
            Some(&identity.device_id().to_owned())
        );

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
