use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use quinn::{Endpoint, VarInt};
use remote_protocol::{CanonicalWriter, RelayOpen, SessionRole, TransportPath};
use reqwest::{Request, StatusCode};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

#[cfg(test)]
mod test_tls;

type HmacSha256 = Hmac<Sha256>;

pub const DEFAULT_RELAY_BIND: &str = "127.0.0.1:18082";
pub const DEFAULT_HEALTH_BIND: &str = "127.0.0.1:18083";
pub const MAX_OPEN_BYTES: usize = 64 * 1024;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
const MAX_RELAY_TOKEN_TTL_MILLIS: u64 = 60_000;
const REPLAY_RETENTION_MILLIS: u64 = 60_000;
const MAX_REPLAY_ENTRIES: usize = 100_000;
const FRAME_QUEUE_CAPACITY: usize = 32;
const OPEN_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const QUIC_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);
const RELAY_ALPN: &[u8] = b"rctl-relay-v1";
const QUIC_CLOSE_NORMAL: u32 = 0;
const QUIC_CLOSE_PROTOCOL: u32 = 1;

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub quic_bind: SocketAddr,
    pub tls_bind: SocketAddr,
    pub health_bind: SocketAddr,
    pub tls_certificate_path: PathBuf,
    pub tls_private_key_path: PathBuf,
    pub relay_node_id: String,
    pub relay_token_secret: Vec<u8>,
    pub internal_api_url: String,
    pub service_token: String,
    pub allowed_transports: Vec<TransportPath>,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, String> {
        let default_bind =
            env::var("REMOTE_RELAY_BIND").unwrap_or_else(|_| DEFAULT_RELAY_BIND.to_owned());
        let quic_bind = env::var("REMOTE_RELAY_QUIC_BIND")
            .unwrap_or_else(|_| default_bind.clone())
            .parse()
            .map_err(|_| "REMOTE_RELAY_QUIC_BIND must be a socket address".to_owned())?;
        let tls_bind = env::var("REMOTE_RELAY_TLS_BIND")
            .unwrap_or(default_bind)
            .parse()
            .map_err(|_| "REMOTE_RELAY_TLS_BIND must be a socket address".to_owned())?;
        let health_bind = env::var("REMOTE_RELAY_HEALTH_BIND")
            .unwrap_or_else(|_| DEFAULT_HEALTH_BIND.to_owned())
            .parse()
            .map_err(|_| "REMOTE_RELAY_HEALTH_BIND must be a socket address".to_owned())?;
        let tls_certificate_path = required_path("REMOTE_RELAY_TLS_CERT_PATH")?;
        let tls_private_key_path = required_path("REMOTE_RELAY_TLS_KEY_PATH")?;
        let relay_node_id =
            env::var("REMOTE_RELAY_NODE_ID").unwrap_or_else(|_| "relay-local-1".to_owned());
        if relay_node_id.trim().is_empty() {
            return Err("REMOTE_RELAY_NODE_ID must not be empty".to_owned());
        }
        let relay_token_secret = env::var("REMOTE_RELAY_TOKEN_SECRET")
            .map_err(|_| "REMOTE_RELAY_TOKEN_SECRET is required".to_owned())?
            .into_bytes();
        if relay_token_secret.len() < 32 {
            return Err("REMOTE_RELAY_TOKEN_SECRET must contain at least 32 bytes".to_owned());
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
        let allowed_transports = env::var("REMOTE_RELAY_ALLOWED_TRANSPORTS")
            .unwrap_or_else(|_| "quic_relay,tls_443_relay".to_owned())
            .split(',')
            .map(parse_transport)
            .collect::<Result<Vec<_>, _>>()?;
        if allowed_transports.is_empty() {
            return Err("REMOTE_RELAY_ALLOWED_TRANSPORTS must not be empty".to_owned());
        }

        Ok(Self {
            quic_bind,
            tls_bind,
            health_bind,
            tls_certificate_path,
            tls_private_key_path,
            relay_node_id,
            relay_token_secret,
            internal_api_url,
            service_token,
            allowed_transports,
        })
    }

    pub fn for_test() -> Self {
        Self {
            quic_bind: "127.0.0.1:0".parse().expect("test QUIC bind"),
            tls_bind: "127.0.0.1:0".parse().expect("test TLS bind"),
            health_bind: "127.0.0.1:0".parse().expect("test health bind"),
            tls_certificate_path: PathBuf::from("test-relay-cert.pem"),
            tls_private_key_path: PathBuf::from("test-relay-key.pem"),
            relay_node_id: "relay-local-1".to_owned(),
            relay_token_secret: b"test-relay-token-secret-at-least-32-bytes".to_vec(),
            internal_api_url: "http://127.0.0.1:1".to_owned(),
            service_token: "test-service-token-that-is-at-least-32-bytes".to_owned(),
            allowed_transports: vec![TransportPath::QuicRelay, TransportPath::Tls443Relay],
        }
    }
}

fn required_path(name: &str) -> Result<PathBuf, String> {
    let value = env::var(name).map_err(|_| format!("{name} is required"))?;
    if value.trim().is_empty() {
        return Err(format!("{name} must not be empty"));
    }
    Ok(PathBuf::from(value))
}

fn parse_transport(value: &str) -> Result<TransportPath, String> {
    match value {
        "quic_relay" => Ok(TransportPath::QuicRelay),
        "tls_443_relay" => Ok(TransportPath::Tls443Relay),
        _ => Err(format!("unsupported relay transport: {value}")),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RelayTokenClaims {
    session_id: u128,
    device_id: String,
    role: SessionRole,
    controller_device_id: String,
    controlled_device_id: String,
    relay_node_id: String,
    transport: TransportPath,
    permissions_digest: [u8; 32],
    relay_token_epoch: u64,
    issued_at_epoch_millis: u64,
    expires_at_epoch_millis: u64,
    relay_token_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RelayAuthorizeRequest {
    session_id: String,
    device_id: String,
    role: String,
    permissions_digest: String,
    relay_token_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayAuthorization {
    authorized: bool,
    session_id: String,
    role: String,
    controller_device_id: String,
    controlled_device_id: String,
    permissions_digest: String,
    relay_token_epoch: u64,
    authorization_expires_at_epoch_millis: u64,
    device_public_key: String,
    device_public_key_id: String,
    device_public_key_version: u32,
}

#[derive(Clone)]
enum RelayAuthorizer {
    Api(ApiRelayAuthorizer),
    #[cfg(test)]
    Memory(Arc<MemoryRelayAuthorizer>),
}

impl RelayAuthorizer {
    async fn authorize(
        &self,
        request: &RelayAuthorizeRequest,
    ) -> Result<RelayAuthorization, AuthError> {
        match self {
            Self::Api(api) => api.authorize(request).await,
            #[cfg(test)]
            Self::Memory(memory) => memory.authorize(request),
        }
    }
}

#[derive(Clone)]
struct ApiRelayAuthorizer {
    client: reqwest::Client,
    endpoint: String,
    service_token: String,
}

impl ApiRelayAuthorizer {
    fn from_config(config: &AppConfig) -> Self {
        Self {
            client: reqwest::Client::new(),
            endpoint: format!(
                "{}/internal/v1/relay/authorize",
                config.internal_api_url.trim_end_matches('/')
            ),
            service_token: config.service_token.clone(),
        }
    }

    fn build_request(&self, request: &RelayAuthorizeRequest) -> Result<Request, AuthError> {
        self.client
            .post(&self.endpoint)
            .bearer_auth(&self.service_token)
            .json(request)
            .build()
            .map_err(|_| AuthError::AuthorizationUnavailable)
    }

    async fn authorize(
        &self,
        request: &RelayAuthorizeRequest,
    ) -> Result<RelayAuthorization, AuthError> {
        let response = self
            .client
            .execute(self.build_request(request)?)
            .await
            .map_err(|_| AuthError::AuthorizationUnavailable)?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|_| AuthError::AuthorizationUnavailable)?;
        decode_authorization_response(status, &body)
    }
}

fn decode_authorization_response(
    status: StatusCode,
    body: &[u8],
) -> Result<RelayAuthorization, AuthError> {
    if matches!(
        status,
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND
    ) {
        return Err(AuthError::AuthorizationRejected);
    }
    if !status.is_success() {
        return Err(AuthError::AuthorizationUnavailable);
    }
    serde_json::from_slice(body).map_err(|_| AuthError::AuthorizationUnavailable)
}

#[cfg(test)]
#[derive(Debug, Default)]
struct MemoryRelayAuthorizer {
    authorizations: HashMap<(String, String, String), RelayAuthorization>,
}

#[cfg(test)]
impl MemoryRelayAuthorizer {
    fn insert(&mut self, authorization: RelayAuthorization, device_id: &str) {
        self.authorizations.insert(
            (
                authorization.session_id.clone(),
                device_id.to_owned(),
                authorization.role.clone(),
            ),
            authorization,
        );
    }

    fn authorize(&self, request: &RelayAuthorizeRequest) -> Result<RelayAuthorization, AuthError> {
        self.authorizations
            .get(&(
                request.session_id.clone(),
                request.device_id.clone(),
                request.role.clone(),
            ))
            .filter(|authorization| {
                authorization.permissions_digest == request.permissions_digest
                    && authorization.relay_token_epoch == request.relay_token_epoch
            })
            .cloned()
            .ok_or(AuthError::AuthorizationRejected)
    }
}

#[derive(Clone)]
pub struct AppState {
    config: AppConfig,
    authorizer: RelayAuthorizer,
    node_enabled: Arc<AtomicBool>,
    replays: Arc<Mutex<HashMap<ReplayKey, u64>>>,
    peers: Arc<SessionPeers>,
    next_connection_id: Arc<AtomicU64>,
}

impl AppState {
    pub fn new(config: AppConfig) -> Self {
        Self {
            authorizer: RelayAuthorizer::Api(ApiRelayAuthorizer::from_config(&config)),
            config,
            node_enabled: Arc::new(AtomicBool::new(true)),
            replays: Arc::new(Mutex::new(HashMap::new())),
            peers: Arc::new(SessionPeers::default()),
            next_connection_id: Arc::new(AtomicU64::new(1)),
        }
    }

    #[cfg(test)]
    fn for_test(config: AppConfig, authorizer: MemoryRelayAuthorizer) -> Self {
        Self {
            config,
            authorizer: RelayAuthorizer::Memory(Arc::new(authorizer)),
            node_enabled: Arc::new(AtomicBool::new(true)),
            replays: Arc::new(Mutex::new(HashMap::new())),
            peers: Arc::new(SessionPeers::default()),
            next_connection_id: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn set_node_enabled(&self, enabled: bool) {
        self.node_enabled.store(enabled, Ordering::Release);
    }
}

pub async fn run(state: AppState) -> io::Result<()> {
    let tls_config = load_tls_server_config(&state.config)?;
    let tls_listener = TcpListener::bind(state.config.tls_bind).await?;
    let quic_endpoint = Endpoint::server(
        make_quic_server_config(Arc::clone(&tls_config))?,
        state.config.quic_bind,
    )?;
    let health_listener = TcpListener::bind(state.config.health_bind).await?;

    info!(
        quic_address = %quic_endpoint.local_addr()?,
        tls_address = %tls_listener.local_addr()?,
        health_address = %health_listener.local_addr()?,
        relay_node_id = %state.config.relay_node_id,
        replay_backend = "memory_single_instance",
        "encrypted relay listeners ready"
    );

    tokio::try_join!(
        serve_quic(quic_endpoint, state.clone()),
        serve_tls(tls_listener, tls_config, state.clone()),
        serve_health(health_listener, state),
    )?;
    Ok(())
}

fn load_tls_server_config(config: &AppConfig) -> io::Result<Arc<rustls::ServerConfig>> {
    let mut certificate_reader = BufReader::new(File::open(&config.tls_certificate_path)?);
    let certificates: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut certificate_reader).collect::<Result<_, _>>()?;
    if certificates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "relay TLS certificate file contains no certificates",
        ));
    }

    let mut private_key_reader = BufReader::new(File::open(&config.tls_private_key_path)?);
    let private_key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut private_key_reader)?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "relay TLS private key file contains no supported key",
            )
        })?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls_config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    tls_config.alpn_protocols = vec![RELAY_ALPN.to_vec()];
    Ok(Arc::new(tls_config))
}

fn make_quic_server_config(
    tls_config: Arc<rustls::ServerConfig>,
) -> io::Result<quinn::ServerConfig> {
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from((*tls_config).clone())
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut transport = quinn::TransportConfig::default();
    let idle_timeout = QUIC_IDLE_TIMEOUT
        .try_into()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    transport
        .max_idle_timeout(Some(idle_timeout))
        .keep_alive_interval(Some(QUIC_KEEP_ALIVE_INTERVAL))
        .max_concurrent_bidi_streams(VarInt::from_u32(1))
        .max_concurrent_uni_streams(VarInt::from_u32(0));
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server_config.transport = Arc::new(transport);
    Ok(server_config)
}

async fn serve_quic(endpoint: Endpoint, state: AppState) -> io::Result<()> {
    while let Some(incoming) = endpoint.accept().await {
        let state = state.clone();
        tokio::spawn(async move {
            let peer = incoming.remote_address();
            if let Err(error) = handle_quic_connection(incoming, state).await {
                warn!(%peer, %error, "QUIC relay connection closed with error");
            }
        });
    }
    Err(io::Error::new(
        io::ErrorKind::NotConnected,
        "QUIC relay endpoint stopped",
    ))
}

async fn handle_quic_connection(incoming: quinn::Incoming, state: AppState) -> io::Result<()> {
    let connection = timeout(TLS_HANDSHAKE_TIMEOUT, incoming)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "QUIC handshake timed out"))?
        .map_err(quinn_connection_error)?;
    let (writer, reader) = timeout(OPEN_TIMEOUT, connection.accept_bi())
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "QUIC relay stream timed out"))?
        .map_err(quinn_connection_error)?;
    let result = handle_relay_stream(
        reader,
        writer,
        state,
        TransportPath::QuicRelay,
        "quic_relay",
    )
    .await;
    let (code, reason) = if result.is_ok() {
        (QUIC_CLOSE_NORMAL, b"relay connection closed".as_slice())
    } else {
        (QUIC_CLOSE_PROTOCOL, b"relay protocol error".as_slice())
    };
    connection.close(VarInt::from_u32(code), reason);
    result
}

fn quinn_connection_error(error: quinn::ConnectionError) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, error)
}

async fn serve_tls(
    listener: TcpListener,
    tls_config: Arc<rustls::ServerConfig>,
    state: AppState,
) -> io::Result<()> {
    let acceptor = TlsAcceptor::from(tls_config);
    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_tls_connection(stream, acceptor, state).await {
                warn!(%peer, %error, "TLS relay connection closed with error");
            }
        });
    }
}

async fn handle_tls_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    state: AppState,
) -> io::Result<()> {
    let stream = timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))??;
    let (reader, writer) = tokio::io::split(stream);
    handle_relay_stream(
        reader,
        writer,
        state,
        TransportPath::Tls443Relay,
        "tls_443_relay",
    )
    .await
}

async fn handle_relay_stream<R, W>(
    mut reader: R,
    mut writer: W,
    state: AppState,
    expected_transport: TransportPath,
    transport_mode: &'static str,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let open_bytes = timeout(OPEN_TIMEOUT, read_frame(&mut reader, MAX_OPEN_BYTES))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "relay_open timed out"))??
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "relay_open missing"))?;
    let open: RelayOpen = serde_json::from_slice(&open_bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid relay_open"))?;
    let authenticated = authenticate_open(&state, &open, expected_transport, now_epoch_millis())
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error.as_str()))?;

    let connection_id = state.next_connection_id.fetch_add(1, Ordering::Relaxed);
    let (sender, mut receiver) = mpsc::channel(FRAME_QUEUE_CAPACITY);
    state
        .peers
        .register(
            open.session_id,
            open.transport,
            open.role,
            connection_id,
            sender,
        )
        .await
        .map_err(|error| io::Error::new(io::ErrorKind::AlreadyExists, error))?;
    let result = async {
        write_json_frame(
            &mut writer,
            &OpenResponse {
                status: "ok",
                session_id: open.session_id,
                role: open.role,
                transport_mode,
            },
        )
        .await?;
        info!(
            session_id = %uuid_string(open.session_id),
            device_id = %authenticated.device_id,
            role = open.role.as_str(),
            transport = open.transport.as_str(),
            connection_id,
            "relay_open accepted"
        );

        let read_loop = async {
            while let Some(frame) = read_frame(&mut reader, MAX_FRAME_BYTES).await? {
                state
                    .peers
                    .forward(open.session_id, open.transport, open.role, frame)
                    .await
                    .map_err(|error| io::Error::new(io::ErrorKind::NotConnected, error))?;
            }
            Ok::<(), io::Error>(())
        };
        let write_loop = async {
            while let Some(frame) = receiver.recv().await {
                write_frame(&mut writer, &frame).await?;
            }
            Ok::<(), io::Error>(())
        };
        tokio::select! {
            result = read_loop => result,
            result = write_loop => result,
        }
    }
    .await;
    state
        .peers
        .remove(open.session_id, open.transport, open.role, connection_id)
        .await;
    result
}

async fn serve_health(listener: TcpListener, state: AppState) -> io::Result<()> {
    loop {
        let (mut stream, peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_health_connection(&mut stream, &state).await {
                warn!(%peer, %error, "relay health connection failed");
            }
        });
    }
}

async fn handle_health_connection(stream: &mut TcpStream, state: &AppState) -> io::Result<()> {
    let mut request = [0_u8; 1024];
    let read = timeout(Duration::from_secs(2), stream.read(&mut request))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "health request timed out"))??;
    let is_health = request[..read].starts_with(b"GET /health ");
    let (status, body) = if is_health {
        let body = serde_json::json!({
            "status": "ok",
            "relay_node_id": state.config.relay_node_id,
            "transports": ["quic_relay", "tls_443_relay"],
            "payload_visibility": "opaque_e2ee",
            "replay_backend": "memory_single_instance",
            "multi_instance_ready": false,
        });
        ("200 OK", serde_json::to_vec(&body).expect("health JSON"))
    } else {
        ("404 Not Found", b"{\"status\":\"not_found\"}".to_vec())
    };
    let headers = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.shutdown().await
}

#[derive(Debug, Serialize)]
struct OpenResponse {
    status: &'static str,
    session_id: u128,
    role: SessionRole,
    transport_mode: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthenticatedOpen {
    device_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthError {
    InvalidToken,
    TokenBindingMismatch,
    TokenExpired,
    TokenTtlExceeded,
    RoleMismatch,
    NodeMismatch,
    TransportMismatch,
    AuthorizationUnavailable,
    AuthorizationRejected,
    AuthorizationBindingMismatch,
    AuthorizationExpired,
    InvalidDeviceKey,
    InvalidDeviceSignature,
    ReplayDetected,
    ReplayCacheFull,
}

impl AuthError {
    const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidToken => "invalid relay token",
            Self::TokenBindingMismatch => "relay token binding mismatch",
            Self::TokenExpired => "relay token expired",
            Self::TokenTtlExceeded => "relay token TTL exceeds maximum",
            Self::RoleMismatch => "relay role does not match device",
            Self::NodeMismatch => "relay node mismatch or disabled",
            Self::TransportMismatch => "relay transport mismatch",
            Self::AuthorizationUnavailable => "relay authorization service unavailable",
            Self::AuthorizationRejected => "relay authorization rejected",
            Self::AuthorizationBindingMismatch => "relay authorization binding mismatch",
            Self::AuthorizationExpired => "relay authorization expired",
            Self::InvalidDeviceKey => "invalid authorized device key",
            Self::InvalidDeviceSignature => "invalid relay_open device signature",
            Self::ReplayDetected => "relay_open nonce replay detected",
            Self::ReplayCacheFull => "relay replay cache is full",
        }
    }
}

async fn authenticate_open(
    state: &AppState,
    open: &RelayOpen,
    expected_transport: TransportPath,
    now_epoch_millis: u64,
) -> Result<AuthenticatedOpen, AuthError> {
    if !state.node_enabled.load(Ordering::Acquire)
        || open.relay_node_id != state.config.relay_node_id
    {
        return Err(AuthError::NodeMismatch);
    }
    if open.transport != expected_transport
        || !open.transport.is_relay()
        || !state.config.allowed_transports.contains(&open.transport)
    {
        return Err(AuthError::TransportMismatch);
    }
    if open.expires_at_epoch_millis <= now_epoch_millis {
        return Err(AuthError::TokenExpired);
    }
    if open.issued_at_epoch_millis > now_epoch_millis.saturating_add(5_000)
        || open
            .expires_at_epoch_millis
            .saturating_sub(open.issued_at_epoch_millis)
            > MAX_RELAY_TOKEN_TTL_MILLIS
    {
        return Err(AuthError::TokenTtlExceeded);
    }
    let role_device = match open.role {
        SessionRole::Controller => &open.controller_device_id,
        SessionRole::Controlled => &open.controlled_device_id,
    };
    if &open.device_id != role_device {
        return Err(AuthError::RoleMismatch);
    }

    let claims = verify_relay_token(&open.session_relay_token, &state.config.relay_token_secret)?;
    if claims != claims_from_open(open) {
        return Err(AuthError::TokenBindingMismatch);
    }
    let binding_hash = relay_token_binding_hash(&claims)?;
    if binding_hash != open.token_binding_hash {
        return Err(AuthError::TokenBindingMismatch);
    }

    let request = RelayAuthorizeRequest {
        session_id: uuid_string(open.session_id),
        device_id: open.device_id.clone(),
        role: open.role.as_str().to_owned(),
        permissions_digest: hex(&open.permissions_digest),
        relay_token_epoch: open.relay_token_epoch,
    };
    let authorization = state.authorizer.authorize(&request).await?;
    validate_authorization(open, &request, &authorization, now_epoch_millis)?;
    let public_key = decode_array::<32>(&authorization.device_public_key)
        .map_err(|_| AuthError::InvalidDeviceKey)?;
    let signature: [u8; 64] = open
        .device_signature
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::InvalidDeviceSignature)?;
    let canonical = relay_open_canonical_bytes(open)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| AuthError::InvalidDeviceKey)?;
    verifying_key
        .verify(&sha256(&canonical), &Signature::from_bytes(&signature))
        .map_err(|_| AuthError::InvalidDeviceSignature)?;
    record_replay(state, open, now_epoch_millis).await?;

    Ok(AuthenticatedOpen {
        device_id: open.device_id.clone(),
    })
}

fn validate_authorization(
    open: &RelayOpen,
    request: &RelayAuthorizeRequest,
    authorization: &RelayAuthorization,
    now_epoch_millis: u64,
) -> Result<(), AuthError> {
    if !authorization.authorized
        || authorization.session_id != request.session_id
        || authorization.role != request.role
        || authorization.permissions_digest != request.permissions_digest
        || authorization.relay_token_epoch != request.relay_token_epoch
        || authorization.controller_device_id != open.controller_device_id
        || authorization.controlled_device_id != open.controlled_device_id
        || authorization.device_public_key_id.is_empty()
        || authorization.device_public_key_version == 0
    {
        return Err(AuthError::AuthorizationBindingMismatch);
    }
    if authorization.authorization_expires_at_epoch_millis <= now_epoch_millis {
        return Err(AuthError::AuthorizationExpired);
    }
    Ok(())
}

fn claims_from_open(open: &RelayOpen) -> RelayTokenClaims {
    RelayTokenClaims {
        session_id: open.session_id,
        device_id: open.device_id.clone(),
        role: open.role,
        controller_device_id: open.controller_device_id.clone(),
        controlled_device_id: open.controlled_device_id.clone(),
        relay_node_id: open.relay_node_id.clone(),
        transport: open.transport,
        permissions_digest: open.permissions_digest,
        relay_token_epoch: open.relay_token_epoch,
        issued_at_epoch_millis: open.issued_at_epoch_millis,
        expires_at_epoch_millis: open.expires_at_epoch_millis,
        relay_token_id: open.relay_token_id.clone(),
    }
}

fn verify_relay_token(token: &[u8], secret: &[u8]) -> Result<RelayTokenClaims, AuthError> {
    let token = str::from_utf8(token).map_err(|_| AuthError::InvalidToken)?;
    let (payload, encoded_signature) = token.split_once('.').ok_or(AuthError::InvalidToken)?;
    let signature = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| AuthError::InvalidToken)?;
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| AuthError::InvalidToken)?;
    mac.update(payload.as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| AuthError::InvalidToken)?;
    let payload = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| AuthError::InvalidToken)?;
    serde_json::from_slice(&payload).map_err(|_| AuthError::InvalidToken)
}

fn relay_token_binding_hash(claims: &RelayTokenClaims) -> Result<[u8; 32], AuthError> {
    let mut writer = CanonicalWriter::new("rctl-relay-token-binding-v1")
        .map_err(|_| AuthError::TokenBindingMismatch)?;
    append_claim_fields(&mut writer, claims)?;
    Ok(sha256(&writer.finish()))
}

fn relay_open_canonical_bytes(open: &RelayOpen) -> Result<Vec<u8>, AuthError> {
    let claims = claims_from_open(open);
    let mut writer = CanonicalWriter::new("rctl-relay-open-v1")
        .map_err(|_| AuthError::InvalidDeviceSignature)?;
    append_claim_fields(&mut writer, &claims)?;
    writer
        .push_field("relay_open_nonce", &open.relay_open_nonce)
        .map_err(|_| AuthError::InvalidDeviceSignature)?
        .push_field("session_relay_token", &open.session_relay_token)
        .map_err(|_| AuthError::InvalidDeviceSignature)?
        .push_field("token_binding_hash", &open.token_binding_hash)
        .map_err(|_| AuthError::InvalidDeviceSignature)?;
    Ok(writer.finish())
}

fn append_claim_fields(
    writer: &mut CanonicalWriter,
    claims: &RelayTokenClaims,
) -> Result<(), AuthError> {
    writer
        .push_u128("session_id", claims.session_id)
        .map_err(|_| AuthError::TokenBindingMismatch)?
        .push_str("device_id", &claims.device_id)
        .map_err(|_| AuthError::TokenBindingMismatch)?
        .push_str("role", claims.role.as_str())
        .map_err(|_| AuthError::TokenBindingMismatch)?
        .push_str("controller_device_id", &claims.controller_device_id)
        .map_err(|_| AuthError::TokenBindingMismatch)?
        .push_str("controlled_device_id", &claims.controlled_device_id)
        .map_err(|_| AuthError::TokenBindingMismatch)?
        .push_str("relay_node_id", &claims.relay_node_id)
        .map_err(|_| AuthError::TokenBindingMismatch)?
        .push_str("transport", claims.transport.as_str())
        .map_err(|_| AuthError::TokenBindingMismatch)?
        .push_field("permissions_digest", &claims.permissions_digest)
        .map_err(|_| AuthError::TokenBindingMismatch)?
        .push_u64("relay_token_epoch", claims.relay_token_epoch)
        .map_err(|_| AuthError::TokenBindingMismatch)?
        .push_u64("issued_at_epoch_millis", claims.issued_at_epoch_millis)
        .map_err(|_| AuthError::TokenBindingMismatch)?
        .push_u64("expires_at_epoch_millis", claims.expires_at_epoch_millis)
        .map_err(|_| AuthError::TokenBindingMismatch)?
        .push_str("relay_token_id", &claims.relay_token_id)
        .map_err(|_| AuthError::TokenBindingMismatch)?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReplayKey {
    relay_token_id: String,
    role: SessionRole,
    relay_open_nonce: [u8; 32],
}

async fn record_replay(
    state: &AppState,
    open: &RelayOpen,
    now_epoch_millis: u64,
) -> Result<(), AuthError> {
    let mut replays = state.replays.lock().await;
    replays.retain(|_, retain_until| *retain_until > now_epoch_millis);
    if replays.len() >= MAX_REPLAY_ENTRIES {
        return Err(AuthError::ReplayCacheFull);
    }
    let key = ReplayKey {
        relay_token_id: open.relay_token_id.clone(),
        role: open.role,
        relay_open_nonce: open.relay_open_nonce,
    };
    if replays
        .insert(
            key,
            open.expires_at_epoch_millis
                .saturating_add(REPLAY_RETENTION_MILLIS),
        )
        .is_some()
    {
        return Err(AuthError::ReplayDetected);
    }
    Ok(())
}

#[derive(Debug)]
struct Peer {
    connection_id: u64,
    sender: mpsc::Sender<Vec<u8>>,
}

#[derive(Debug, Default)]
struct PeerSet {
    controller: Option<Peer>,
    controlled: Option<Peer>,
}

#[derive(Debug, Default)]
struct SessionPeers {
    sessions: Mutex<HashMap<(u128, TransportPath), PeerSet>>,
}

impl SessionPeers {
    async fn register(
        &self,
        session_id: u128,
        transport: TransportPath,
        role: SessionRole,
        connection_id: u64,
        sender: mpsc::Sender<Vec<u8>>,
    ) -> Result<(), &'static str> {
        let mut sessions = self.sessions.lock().await;
        let peers = sessions.entry((session_id, transport)).or_default();
        let slot = match role {
            SessionRole::Controller => &mut peers.controller,
            SessionRole::Controlled => &mut peers.controlled,
        };
        if slot.is_some() {
            return Err("relay role already connected");
        }
        *slot = Some(Peer {
            connection_id,
            sender,
        });
        Ok(())
    }

    async fn forward(
        &self,
        session_id: u128,
        transport: TransportPath,
        sender_role: SessionRole,
        frame: Vec<u8>,
    ) -> Result<(), &'static str> {
        let sender = {
            let sessions = self.sessions.lock().await;
            let peers = sessions
                .get(&(session_id, transport))
                .ok_or("relay session not paired")?;
            match sender_role {
                SessionRole::Controller => peers.controlled.as_ref(),
                SessionRole::Controlled => peers.controller.as_ref(),
            }
            .ok_or("relay peer not connected")?
            .sender
            .clone()
        };
        sender
            .send(frame)
            .await
            .map_err(|_| "relay peer queue is closed")
    }

    async fn remove(
        &self,
        session_id: u128,
        transport: TransportPath,
        role: SessionRole,
        connection_id: u64,
    ) {
        let mut sessions = self.sessions.lock().await;
        let key = (session_id, transport);
        let Some(peers) = sessions.get_mut(&key) else {
            return;
        };
        let slot = match role {
            SessionRole::Controller => &mut peers.controller,
            SessionRole::Controlled => &mut peers.controlled,
        };
        if slot
            .as_ref()
            .is_some_and(|peer| peer.connection_id == connection_id)
        {
            *slot = None;
        }
        if peers.controller.is_none() && peers.controlled.is_none() {
            sessions.remove(&key);
        }
    }
}

async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    maximum: usize,
) -> io::Result<Option<Vec<u8>>> {
    let mut prefix = [0_u8; 4];
    match reader.read_exact(&mut prefix).await {
        Ok(_) => read_frame_after_prefix(reader, prefix, maximum)
            .await
            .map(Some),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Err(error) => Err(error),
    }
}

async fn read_frame_after_prefix<R: AsyncRead + Unpin>(
    reader: &mut R,
    prefix: [u8; 4],
    maximum: usize,
) -> io::Result<Vec<u8>> {
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > maximum {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "relay frame length is outside configured bounds",
        ));
    }
    let mut frame = vec![0_u8; length];
    reader.read_exact(&mut frame).await?;
    Ok(frame)
}

async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: &[u8]) -> io::Result<()> {
    let length = u32::try_from(frame.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "relay frame too large"))?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(frame).await?;
    writer.flush().await
}

async fn write_json_frame<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> io::Result<()> {
    let frame = serde_json::to_vec(value)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response JSON failed"))?;
    write_frame(writer, &frame).await
}

fn decode_array<const N: usize>(value: &str) -> Result<[u8; N], ()> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ())?
        .try_into()
        .map_err(|_| ())
}

fn sha256(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

fn hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn uuid_string(value: u128) -> String {
    let value = format!("{value:032x}");
    format!(
        "{}-{}-{}-{}-{}",
        &value[0..8],
        &value[8..12],
        &value[12..16],
        &value[16..20],
        &value[20..32]
    )
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
    use ed25519_dalek::{Signer, SigningKey};
    use reqwest::header::AUTHORIZATION;
    use rustls::pki_types::ServerName;
    use tokio::io::AsyncWriteExt;
    use tokio::task::JoinHandle;
    use tokio_rustls::{client::TlsStream, TlsConnector};

    const SESSION_ID: u128 = 0x00112233445566778899aabbccddeeff;

    fn sign_token(claims: &RelayTokenClaims, secret: &[u8]) -> Vec<u8> {
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("token json"));
        let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key");
        mac.update(payload.as_bytes());
        format!(
            "{payload}.{}",
            URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
        )
        .into_bytes()
    }

    fn authorization(open: &RelayOpen, signing_key: &SigningKey, now: u64) -> RelayAuthorization {
        RelayAuthorization {
            authorized: true,
            session_id: uuid_string(open.session_id),
            role: open.role.as_str().to_owned(),
            controller_device_id: open.controller_device_id.clone(),
            controlled_device_id: open.controlled_device_id.clone(),
            permissions_digest: hex(&open.permissions_digest),
            relay_token_epoch: open.relay_token_epoch,
            authorization_expires_at_epoch_millis: now + 60_000,
            device_public_key: URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes()),
            device_public_key_id: "key-1".to_owned(),
            device_public_key_version: 1,
        }
    }

    fn signed_open_for(
        config: &AppConfig,
        signing_key: &SigningKey,
        now: u64,
        role: SessionRole,
        transport: TransportPath,
        nonce_byte: u8,
    ) -> RelayOpen {
        let device_id = match role {
            SessionRole::Controller => "controller-1",
            SessionRole::Controlled => "controlled-1",
        };
        let claims = RelayTokenClaims {
            session_id: SESSION_ID,
            device_id: device_id.to_owned(),
            role,
            controller_device_id: "controller-1".to_owned(),
            controlled_device_id: "controlled-1".to_owned(),
            relay_node_id: config.relay_node_id.clone(),
            transport,
            permissions_digest: [9; 32],
            relay_token_epoch: 7,
            issued_at_epoch_millis: now - 1_000,
            expires_at_epoch_millis: now + 30_000,
            relay_token_id: format!("relay-token-{device_id}-{}", transport.as_str()),
        };
        let token = sign_token(&claims, &config.relay_token_secret);
        let mut open = RelayOpen {
            session_id: claims.session_id,
            device_id: claims.device_id.clone(),
            role: claims.role,
            controller_device_id: claims.controller_device_id.clone(),
            controlled_device_id: claims.controlled_device_id.clone(),
            relay_node_id: claims.relay_node_id.clone(),
            transport: claims.transport,
            permissions_digest: claims.permissions_digest,
            relay_token_epoch: claims.relay_token_epoch,
            issued_at_epoch_millis: claims.issued_at_epoch_millis,
            expires_at_epoch_millis: claims.expires_at_epoch_millis,
            relay_token_id: claims.relay_token_id.clone(),
            relay_open_nonce: [nonce_byte; 32],
            session_relay_token: token,
            token_binding_hash: relay_token_binding_hash(&claims).expect("binding hash"),
            device_signature: Vec::new(),
        };
        open.device_signature = signing_key
            .sign(&sha256(
                &relay_open_canonical_bytes(&open).expect("open canonical"),
            ))
            .to_bytes()
            .to_vec();
        open
    }

    fn signed_open(config: &AppConfig, signing_key: &SigningKey, now: u64) -> RelayOpen {
        signed_open_for(
            config,
            signing_key,
            now,
            SessionRole::Controller,
            TransportPath::QuicRelay,
            5,
        )
    }

    fn state_for_open(
        config: AppConfig,
        open: &RelayOpen,
        signing_key: &SigningKey,
        now: u64,
    ) -> AppState {
        let mut authorizer = MemoryRelayAuthorizer::default();
        authorizer.insert(authorization(open, signing_key, now), &open.device_id);
        AppState::for_test(config, authorizer)
    }

    fn state_for_pair(
        config: AppConfig,
        controller_open: &RelayOpen,
        controller_key: &SigningKey,
        controlled_open: &RelayOpen,
        controlled_key: &SigningKey,
        now: u64,
    ) -> AppState {
        let mut authorizer = MemoryRelayAuthorizer::default();
        authorizer.insert(
            authorization(controller_open, controller_key, now),
            &controller_open.device_id,
        );
        authorizer.insert(
            authorization(controlled_open, controlled_key, now),
            &controlled_open.device_id,
        );
        AppState::for_test(config, authorizer)
    }

    async fn assert_open_accepted<R: AsyncRead + Unpin>(reader: &mut R, open: &RelayOpen) {
        #[derive(Deserialize)]
        struct TestOpenResponse {
            status: String,
            session_id: u128,
            role: SessionRole,
            transport_mode: String,
        }

        let response = timeout(Duration::from_secs(2), read_frame(reader, MAX_OPEN_BYTES))
            .await
            .expect("relay_open response timeout")
            .expect("relay_open response read")
            .expect("relay_open response frame");
        let response: TestOpenResponse =
            serde_json::from_slice(&response).expect("relay_open response JSON");
        assert_eq!(response.status, "ok");
        assert_eq!(response.session_id, open.session_id);
        assert_eq!(response.role, open.role);
        assert_eq!(response.transport_mode, open.transport.as_str());
    }

    async fn assert_connection_rejected<R: AsyncRead + Unpin>(reader: &mut R) {
        match timeout(Duration::from_secs(2), read_frame(reader, MAX_OPEN_BYTES)).await {
            Ok(Ok(None) | Err(_)) => {}
            Ok(Ok(Some(frame))) => panic!("rejected connection returned frame: {frame:?}"),
            Err(_) => panic!("relay did not close rejected connection"),
        }
    }

    async fn peer_count(state: &AppState) -> usize {
        state
            .peers
            .sessions
            .lock()
            .await
            .values()
            .map(|peers| {
                usize::from(peers.controller.is_some()) + usize::from(peers.controlled.is_some())
            })
            .sum()
    }

    async fn wait_for_peer_count(state: &AppState, expected: usize) {
        timeout(Duration::from_secs(2), async {
            loop {
                if peer_count(state).await == expected {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("relay peer count did not reach {expected}"));
    }

    struct QuicTestClient {
        endpoint: Endpoint,
        connection: quinn::Connection,
        writer: quinn::SendStream,
        reader: quinn::RecvStream,
    }

    impl QuicTestClient {
        async fn connect(address: SocketAddr) -> Self {
            let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(
                (*test_tls::client_config()).clone(),
            )
            .expect("test QUIC client TLS config");
            let mut endpoint = Endpoint::client("127.0.0.1:0".parse().expect("client bind"))
                .expect("QUIC client endpoint");
            endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
            let connection = endpoint
                .connect(address, "localhost")
                .expect("QUIC connect start")
                .await
                .expect("QUIC connect");
            let (writer, reader) = connection.open_bi().await.expect("QUIC relay stream");
            Self {
                endpoint,
                connection,
                writer,
                reader,
            }
        }

        fn close(&self) {
            self.connection
                .close(VarInt::from_u32(QUIC_CLOSE_NORMAL), b"test complete");
            self.endpoint.close(
                VarInt::from_u32(QUIC_CLOSE_NORMAL),
                b"test endpoint complete",
            );
        }
    }

    async fn start_quic_server(
        state: AppState,
    ) -> (Endpoint, SocketAddr, JoinHandle<io::Result<()>>) {
        let endpoint = Endpoint::server(
            make_quic_server_config(test_tls::server_config()).expect("QUIC server config"),
            "127.0.0.1:0".parse().expect("server bind"),
        )
        .expect("QUIC server endpoint");
        let address = endpoint.local_addr().expect("QUIC server address");
        let server = tokio::spawn(serve_quic(endpoint.clone(), state));
        (endpoint, address, server)
    }

    async fn connect_tls(address: SocketAddr) -> TlsStream<TcpStream> {
        let tcp = TcpStream::connect(address).await.expect("TLS TCP connect");
        let server_name = ServerName::try_from("localhost".to_owned()).expect("TLS server name");
        TlsConnector::from(test_tls::client_config())
            .connect(server_name, tcp)
            .await
            .expect("TLS connect")
    }

    async fn start_tls_server(state: AppState) -> (SocketAddr, JoinHandle<io::Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("TLS server bind");
        let address = listener.local_addr().expect("TLS server address");
        let server = tokio::spawn(serve_tls(listener, test_tls::server_config(), state));
        (address, server)
    }

    #[test]
    fn runtime_authorizer_uses_internal_contract_and_binds_response() {
        let mut config = AppConfig::for_test();
        config.internal_api_url = "http://api-server:18080/".to_owned();
        config.service_token = "compose-service-token-that-is-at-least-32-bytes".to_owned();
        let signing_key = SigningKey::from_bytes(&[3; 32]);
        let now = 1_000_000;
        let open = signed_open(&config, &signing_key, now);
        let request = RelayAuthorizeRequest {
            session_id: uuid_string(open.session_id),
            device_id: open.device_id.clone(),
            role: open.role.as_str().to_owned(),
            permissions_digest: hex(&open.permissions_digest),
            relay_token_epoch: open.relay_token_epoch,
        };
        let authorizer = ApiRelayAuthorizer::from_config(&config);

        let http_request = authorizer.build_request(&request).expect("HTTP request");
        assert_eq!(
            http_request.url().as_str(),
            "http://api-server:18080/internal/v1/relay/authorize"
        );
        assert_eq!(http_request.method(), reqwest::Method::POST);
        assert_eq!(
            http_request.headers().get(AUTHORIZATION).expect("bearer"),
            "Bearer compose-service-token-that-is-at-least-32-bytes"
        );
        let encoded_request: RelayAuthorizeRequest = serde_json::from_slice(
            http_request
                .body()
                .and_then(reqwest::Body::as_bytes)
                .expect("JSON body"),
        )
        .expect("request contract");
        assert_eq!(encoded_request, request);

        let authorization = authorization(&open, &signing_key, now);
        let decoded = decode_authorization_response(
            StatusCode::OK,
            &serde_json::to_vec(&authorization).expect("response JSON"),
        )
        .expect("authorized response");
        validate_authorization(&open, &request, &decoded, now).expect("response binding");

        let mut mismatched = authorization.clone();
        mismatched.relay_token_epoch += 1;
        assert_eq!(
            validate_authorization(&open, &request, &mismatched, now),
            Err(AuthError::AuthorizationBindingMismatch)
        );
        assert!(matches!(
            decode_authorization_response(StatusCode::FORBIDDEN, b"{}"),
            Err(AuthError::AuthorizationRejected)
        ));
        assert!(matches!(
            decode_authorization_response(StatusCode::SERVICE_UNAVAILABLE, b"{}"),
            Err(AuthError::AuthorizationUnavailable)
        ));
    }

    #[tokio::test]
    async fn valid_open_checks_token_binding_authorization_and_device_signature() {
        let config = AppConfig::for_test();
        let signing_key = SigningKey::from_bytes(&[3; 32]);
        let now = 1_000_000;
        let open = signed_open(&config, &signing_key, now);
        let state = state_for_open(config, &open, &signing_key, now);

        let authenticated = authenticate_open(&state, &open, open.transport, now)
            .await
            .expect("valid relay_open");
        assert_eq!(authenticated.device_id, "controller-1");
    }

    #[tokio::test]
    async fn rejects_expired_ttl_role_node_transport_epoch_and_permissions() {
        let signing_key = SigningKey::from_bytes(&[3; 32]);
        let now = 1_000_000;

        let config = AppConfig::for_test();
        let mut expired = signed_open(&config, &signing_key, now);
        expired.expires_at_epoch_millis = now;
        let state = state_for_open(config, &expired, &signing_key, now);
        assert_eq!(
            authenticate_open(&state, &expired, expired.transport, now).await,
            Err(AuthError::TokenExpired)
        );

        let config = AppConfig::for_test();
        let mut role = signed_open(&config, &signing_key, now);
        role.device_id = "controlled-1".to_owned();
        let state = state_for_open(config, &role, &signing_key, now);
        assert_eq!(
            authenticate_open(&state, &role, role.transport, now).await,
            Err(AuthError::RoleMismatch)
        );

        let config = AppConfig::for_test();
        let mut node = signed_open(&config, &signing_key, now);
        node.relay_node_id = "other-node".to_owned();
        let state = state_for_open(config, &node, &signing_key, now);
        assert_eq!(
            authenticate_open(&state, &node, node.transport, now).await,
            Err(AuthError::NodeMismatch)
        );

        let mut config = AppConfig::for_test();
        config.allowed_transports = vec![TransportPath::Tls443Relay];
        let transport = signed_open(&config, &signing_key, now);
        let state = state_for_open(config, &transport, &signing_key, now);
        assert_eq!(
            authenticate_open(&state, &transport, transport.transport, now).await,
            Err(AuthError::TransportMismatch)
        );

        let config = AppConfig::for_test();
        let open = signed_open(&config, &signing_key, now);
        let mut authorizer = MemoryRelayAuthorizer::default();
        let mut stale = authorization(&open, &signing_key, now);
        stale.relay_token_epoch += 1;
        stale.permissions_digest = hex(&[8; 32]);
        authorizer.insert(stale, &open.device_id);
        let state = AppState::for_test(config, authorizer);
        assert_eq!(
            authenticate_open(&state, &open, open.transport, now).await,
            Err(AuthError::AuthorizationRejected)
        );
    }

    #[tokio::test]
    async fn rejects_tampered_token_signature_direct_canonical_signature_and_replay() {
        let config = AppConfig::for_test();
        let signing_key = SigningKey::from_bytes(&[3; 32]);
        let now = 1_000_000;

        let mut token = signed_open(&config, &signing_key, now);
        token.session_relay_token[0] ^= 1;
        let state = state_for_open(config.clone(), &token, &signing_key, now);
        assert_eq!(
            authenticate_open(&state, &token, token.transport, now).await,
            Err(AuthError::InvalidToken)
        );

        let mut direct = signed_open(&config, &signing_key, now);
        direct.device_signature = signing_key
            .sign(&relay_open_canonical_bytes(&direct).expect("canonical"))
            .to_bytes()
            .to_vec();
        let state = state_for_open(config.clone(), &direct, &signing_key, now);
        assert_eq!(
            authenticate_open(&state, &direct, direct.transport, now).await,
            Err(AuthError::InvalidDeviceSignature)
        );

        let open = signed_open(&config, &signing_key, now);
        let state = state_for_open(config, &open, &signing_key, now);
        authenticate_open(&state, &open, open.transport, now)
            .await
            .expect("first open");
        assert_eq!(
            authenticate_open(&state, &open, open.transport, now).await,
            Err(AuthError::ReplayDetected)
        );
    }

    #[tokio::test]
    async fn disabled_node_rejects_new_open_immediately() {
        let config = AppConfig::for_test();
        let signing_key = SigningKey::from_bytes(&[3; 32]);
        let now = 1_000_000;
        let open = signed_open(&config, &signing_key, now);
        let state = state_for_open(config, &open, &signing_key, now);
        state.set_node_enabled(false);
        assert_eq!(
            authenticate_open(&state, &open, open.transport, now).await,
            Err(AuthError::NodeMismatch)
        );
    }

    #[tokio::test]
    async fn bounded_frames_reject_zero_and_oversized_lengths() {
        for length in [0_u32, (MAX_FRAME_BYTES as u32) + 1] {
            let (mut writer, mut reader) = tokio::io::duplex(16);
            writer
                .write_all(&length.to_be_bytes())
                .await
                .expect("length");
            drop(writer);
            let error = read_frame(&mut reader, MAX_FRAME_BYTES)
                .await
                .expect_err("invalid bound");
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    }

    #[tokio::test]
    async fn paired_forwarding_preserves_opaque_payload_without_parsing() {
        let peers = SessionPeers::default();
        let (controller_tx, _controller_rx) = mpsc::channel(1);
        let (controlled_tx, mut controlled_rx) = mpsc::channel(1);
        peers
            .register(
                SESSION_ID,
                TransportPath::QuicRelay,
                SessionRole::Controller,
                1,
                controller_tx,
            )
            .await
            .expect("controller");
        peers
            .register(
                SESSION_ID,
                TransportPath::QuicRelay,
                SessionRole::Controlled,
                2,
                controlled_tx,
            )
            .await
            .expect("controlled");
        let opaque = vec![0xff, 0x00, 0x81, b'{', b'}'];

        peers
            .forward(
                SESSION_ID,
                TransportPath::QuicRelay,
                SessionRole::Controller,
                opaque.clone(),
            )
            .await
            .expect("forward");

        assert_eq!(controlled_rx.recv().await, Some(opaque));
    }

    #[tokio::test]
    async fn localhost_quic_relay_forwards_opaque_payloads_and_cleans_connections() {
        let config = AppConfig::for_test();
        let controller_key = SigningKey::from_bytes(&[3; 32]);
        let controlled_key = SigningKey::from_bytes(&[4; 32]);
        let now = now_epoch_millis();
        let controller_open = signed_open_for(
            &config,
            &controller_key,
            now,
            SessionRole::Controller,
            TransportPath::QuicRelay,
            11,
        );
        let controlled_open = signed_open_for(
            &config,
            &controlled_key,
            now,
            SessionRole::Controlled,
            TransportPath::QuicRelay,
            12,
        );
        let state = state_for_pair(
            config,
            &controller_open,
            &controller_key,
            &controlled_open,
            &controlled_key,
            now,
        );
        let (server_endpoint, address, server) = start_quic_server(state.clone()).await;

        let mut controller = QuicTestClient::connect(address).await;
        write_json_frame(&mut controller.writer, &controller_open)
            .await
            .expect("controller relay_open");
        assert_open_accepted(&mut controller.reader, &controller_open).await;
        let mut controlled = QuicTestClient::connect(address).await;
        write_json_frame(&mut controlled.writer, &controlled_open)
            .await
            .expect("controlled relay_open");
        assert_open_accepted(&mut controlled.reader, &controlled_open).await;
        wait_for_peer_count(&state, 2).await;

        let controller_payload = vec![0xff, 0x00, 0x81, b'{', 0x13, 0x37];
        write_frame(&mut controller.writer, &controller_payload)
            .await
            .expect("controller opaque payload");
        let forwarded = timeout(
            Duration::from_secs(2),
            read_frame(&mut controlled.reader, MAX_FRAME_BYTES),
        )
        .await
        .expect("controller payload timeout")
        .expect("controller payload read")
        .expect("controller payload frame");
        assert_eq!(forwarded, controller_payload);

        let controlled_payload = vec![0x00, 0xfe, b'}', 0x80, 0x01, 0x02];
        write_frame(&mut controlled.writer, &controlled_payload)
            .await
            .expect("controlled opaque payload");
        let forwarded = timeout(
            Duration::from_secs(2),
            read_frame(&mut controller.reader, MAX_FRAME_BYTES),
        )
        .await
        .expect("controlled payload timeout")
        .expect("controlled payload read")
        .expect("controlled payload frame");
        assert_eq!(forwarded, controlled_payload);

        controller.close();
        wait_for_peer_count(&state, 1).await;
        controlled.close();
        wait_for_peer_count(&state, 0).await;
        server_endpoint.close(VarInt::from_u32(QUIC_CLOSE_NORMAL), b"test complete");
        server.abort();
    }

    #[tokio::test]
    async fn localhost_quic_relay_rejects_wrong_transport_and_invalid_open() {
        let config = AppConfig::for_test();
        let signing_key = SigningKey::from_bytes(&[3; 32]);
        let now = now_epoch_millis();
        let wrong_transport = signed_open_for(
            &config,
            &signing_key,
            now,
            SessionRole::Controller,
            TransportPath::Tls443Relay,
            21,
        );
        let state = state_for_open(config, &wrong_transport, &signing_key, now);
        let (server_endpoint, address, server) = start_quic_server(state.clone()).await;

        let mut wrong_transport_client = QuicTestClient::connect(address).await;
        write_json_frame(&mut wrong_transport_client.writer, &wrong_transport)
            .await
            .expect("wrong transport relay_open");
        assert_connection_rejected(&mut wrong_transport_client.reader).await;
        wait_for_peer_count(&state, 0).await;

        let mut invalid_open_client = QuicTestClient::connect(address).await;
        write_frame(&mut invalid_open_client.writer, b"not-a-relay-open")
            .await
            .expect("invalid relay_open");
        assert_connection_rejected(&mut invalid_open_client.reader).await;
        wait_for_peer_count(&state, 0).await;

        wrong_transport_client.close();
        invalid_open_client.close();
        server_endpoint.close(VarInt::from_u32(QUIC_CLOSE_NORMAL), b"test complete");
        server.abort();
    }

    #[tokio::test]
    async fn localhost_tls_relay_forwards_opaque_payloads_and_cleans_connections() {
        let config = AppConfig::for_test();
        let controller_key = SigningKey::from_bytes(&[3; 32]);
        let controlled_key = SigningKey::from_bytes(&[4; 32]);
        let now = now_epoch_millis();
        let controller_open = signed_open_for(
            &config,
            &controller_key,
            now,
            SessionRole::Controller,
            TransportPath::Tls443Relay,
            31,
        );
        let controlled_open = signed_open_for(
            &config,
            &controlled_key,
            now,
            SessionRole::Controlled,
            TransportPath::Tls443Relay,
            32,
        );
        let state = state_for_pair(
            config,
            &controller_open,
            &controller_key,
            &controlled_open,
            &controlled_key,
            now,
        );
        let (address, server) = start_tls_server(state.clone()).await;

        let mut controller = connect_tls(address).await;
        write_json_frame(&mut controller, &controller_open)
            .await
            .expect("controller relay_open");
        assert_open_accepted(&mut controller, &controller_open).await;
        let mut controlled = connect_tls(address).await;
        write_json_frame(&mut controlled, &controlled_open)
            .await
            .expect("controlled relay_open");
        assert_open_accepted(&mut controlled, &controlled_open).await;
        wait_for_peer_count(&state, 2).await;

        let controller_payload = vec![0xff, 0x00, 0x81, b'{', 0x13, 0x37];
        write_frame(&mut controller, &controller_payload)
            .await
            .expect("controller opaque payload");
        let forwarded = timeout(
            Duration::from_secs(2),
            read_frame(&mut controlled, MAX_FRAME_BYTES),
        )
        .await
        .expect("controller payload timeout")
        .expect("controller payload read")
        .expect("controller payload frame");
        assert_eq!(forwarded, controller_payload);

        let controlled_payload = vec![0x00, 0xfe, b'}', 0x80, 0x01, 0x02];
        write_frame(&mut controlled, &controlled_payload)
            .await
            .expect("controlled opaque payload");
        let forwarded = timeout(
            Duration::from_secs(2),
            read_frame(&mut controller, MAX_FRAME_BYTES),
        )
        .await
        .expect("controlled payload timeout")
        .expect("controlled payload read")
        .expect("controlled payload frame");
        assert_eq!(forwarded, controlled_payload);

        controller.shutdown().await.expect("controller shutdown");
        wait_for_peer_count(&state, 1).await;
        controlled.shutdown().await.expect("controlled shutdown");
        wait_for_peer_count(&state, 0).await;
        server.abort();
    }

    #[tokio::test]
    async fn localhost_tls_relay_rejects_wrong_transport_and_invalid_open() {
        let config = AppConfig::for_test();
        let signing_key = SigningKey::from_bytes(&[3; 32]);
        let now = now_epoch_millis();
        let wrong_transport = signed_open_for(
            &config,
            &signing_key,
            now,
            SessionRole::Controller,
            TransportPath::QuicRelay,
            41,
        );
        let state = state_for_open(config, &wrong_transport, &signing_key, now);
        let (address, server) = start_tls_server(state.clone()).await;

        let mut wrong_transport_client = connect_tls(address).await;
        write_json_frame(&mut wrong_transport_client, &wrong_transport)
            .await
            .expect("wrong transport relay_open");
        assert_connection_rejected(&mut wrong_transport_client).await;
        wait_for_peer_count(&state, 0).await;

        let mut invalid_open_client = connect_tls(address).await;
        write_frame(&mut invalid_open_client, b"not-a-relay-open")
            .await
            .expect("invalid relay_open");
        assert_connection_rejected(&mut invalid_open_client).await;
        wait_for_peer_count(&state, 0).await;

        let _ = wrong_transport_client.shutdown().await;
        let _ = invalid_open_client.shutdown().await;
        server.abort();
    }
}
