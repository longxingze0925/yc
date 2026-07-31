use crate::identity::DeviceIdentity;
use crate::secret_store::SecretText;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use remote_crypto::sha256;
use remote_protocol::{
    canonical_json_bytes, CandidateAuthorization, CandidateTokenIssued, CandidateTokenRequest,
    CanonicalWriter, ConnectionCandidateDto, KeyConfirm, SessionRole, SignedKeyExchange,
    PROTOCOL_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{header::AUTHORIZATION, HeaderName, HeaderValue};
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::CloseFrame;
use tokio_tungstenite::tungstenite::{Error as WebSocketError, Message};
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

const PROTOCOL_VERSIONS_HEADER: HeaderName = HeaderName::from_static("x-rctl-protocol-versions");
const MIN_PROTOCOL_VERSION_HEADER: HeaderName =
    HeaderName::from_static("x-rctl-min-protocol-version");
const NOTIFICATION_QUEUE_CAPACITY: usize = 64;
const OUTBOUND_QUEUE_CAPACITY: usize = 64;
const MAX_SESSION_CERTIFICATE_DER_BYTES: usize = 16 * 1024;

type SignalSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;
type SharedMachine = Arc<Mutex<SignalStateMachine>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalConnectionState {
    Disconnected,
    Connecting,
    AwaitingChallenge,
    Authenticating,
    Online,
    Reconnecting,
    Failed,
}

impl SignalConnectionState {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Disconnected => "Signal 未连接",
            Self::Connecting => "Signal 连接中",
            Self::AwaitingChallenge => "Signal 等待设备挑战",
            Self::Authenticating => "Signal 设备签名验证中",
            Self::Online => "Signal 已通过鉴权",
            Self::Reconnecting => "Signal 重连中",
            Self::Failed => "Signal 未上线",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignalError {
    InvalidTransition,
    InvalidChallenge,
    HelloMismatch,
    Canonical,
    InvalidUrl,
    InvalidHeader,
    UpgradeRejected(u16),
    Transport,
    TimedOut,
    ConnectionClosed,
    InvalidServerMessage,
    AuthenticationRejected,
    Cancelled,
    WorkerUnavailable,
    NotificationQueueFull,
    NotificationReceiverUnavailable,
    OutboundQueueFull,
    InvalidSessionMessage,
}

impl SignalError {
    fn is_retriable(&self) -> bool {
        matches!(
            self,
            Self::Transport | Self::TimedOut | Self::ConnectionClosed
        )
    }
}

impl fmt::Display for SignalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition => formatter.write_str("Signal 状态转移非法"),
            Self::InvalidChallenge => formatter.write_str("Signal hello_challenge 无效"),
            Self::HelloMismatch => formatter.write_str("Signal hello_ok 与已签名握手不匹配"),
            Self::Canonical => formatter.write_str("Signal 握手 canonical 编码失败"),
            Self::InvalidUrl => formatter.write_str("Signal WebSocket 地址无效"),
            Self::InvalidHeader => formatter.write_str("Signal Upgrade Header 无效"),
            Self::UpgradeRejected(status) => {
                write!(formatter, "Signal Upgrade 被拒绝（HTTP {status}）")
            }
            Self::Transport => formatter.write_str("Signal WebSocket 传输失败"),
            Self::TimedOut => formatter.write_str("Signal WebSocket 连接或握手超时"),
            Self::ConnectionClosed => formatter.write_str("Signal WebSocket 已断开"),
            Self::InvalidServerMessage => formatter.write_str("Signal 服务端消息无效"),
            Self::AuthenticationRejected => formatter.write_str("Signal 鉴权被拒绝"),
            Self::Cancelled => formatter.write_str("Signal 连接已取消"),
            Self::WorkerUnavailable => formatter.write_str("Signal 工作线程不可用"),
            Self::NotificationQueueFull => formatter.write_str("Signal 通知队列已满"),
            Self::NotificationReceiverUnavailable => formatter.write_str("Signal 通知接收器不可用"),
            Self::OutboundQueueFull => formatter.write_str("Signal 发送队列已满"),
            Self::InvalidSessionMessage => formatter.write_str("Signal 会话消息绑定无效"),
        }
    }
}

impl std::error::Error for SignalError {}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionSnapshot {
    pub session_id: String,
    pub status: String,
    pub controller_device_id: String,
    pub controlled_device_id: String,
    pub payload: Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionActorRole {
    Controller,
    Controlled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionActor {
    Device {
        device_id: String,
        role: SessionActorRole,
    },
    Service {
        service: String,
    },
    System,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionInviteNotification {
    pub session: SessionSnapshot,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionStateNotification {
    pub session_id: String,
    pub status: String,
    pub actor: SessionActor,
    pub reason: Option<String>,
    pub event_id: String,
    pub session: SessionSnapshot,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SignalNotification {
    OnlineDevices(Vec<SignalOnlineDevice>),
    SessionInvite(SessionInviteNotification),
    SessionAcceptAck(SessionStateNotification),
    SessionRejectAck(SessionStateNotification),
    SessionCancelAck(SessionStateNotification),
    SessionCloseAck(SessionStateNotification),
    ConnectionState(SessionStateNotification),
    CandidateTokenIssued(CandidateTokenIssued),
    SessionMessage(SessionPeerMessage),
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SignalOnlineDevice {
    pub account_id: String,
    pub device_id: String,
    pub public_key_id: String,
    pub public_key_version: u32,
    pub public_key: String,
    pub client_capabilities_hash: String,
    pub status: remote_protocol::DeviceStatus,
    pub last_seen_epoch_millis: u64,
    pub connection_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionSignalMessageKind {
    ConnectionCandidate,
    KeyExchangeMessage,
    KeyConfirm,
}

impl SessionSignalMessageKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ConnectionCandidate => "connection_candidate",
            Self::KeyExchangeMessage => "key_exchange_message",
            Self::KeyConfirm => "key_confirm",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "connection_candidate" => Some(Self::ConnectionCandidate),
            "key_exchange_message" => Some(Self::KeyExchangeMessage),
            "key_confirm" => Some(Self::KeyConfirm),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SessionPeerMessage {
    pub kind: SessionSignalMessageKind,
    pub session_id: String,
    pub role: SessionRole,
    pub from_device_id: String,
    pub payload: Value,
}

pub struct SignalConnectContext {
    pub signal_url: String,
    access_token: SecretText,
    pub account_id: String,
    pub device_id: String,
    pub public_key_id: String,
    pub public_key_version: u32,
    pub client_capabilities: Value,
    identity: Arc<DeviceIdentity>,
}

impl SignalConnectContext {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        signal_url: impl Into<String>,
        access_token: impl Into<String>,
        account_id: impl Into<String>,
        device_id: impl Into<String>,
        public_key_id: impl Into<String>,
        public_key_version: u32,
        client_capabilities: Value,
        identity: Arc<DeviceIdentity>,
    ) -> Self {
        Self {
            signal_url: signal_url.into(),
            access_token: SecretText::new(access_token),
            account_id: account_id.into(),
            device_id: device_id.into(),
            public_key_id: public_key_id.into(),
            public_key_version,
            client_capabilities,
            identity,
        }
    }

    pub fn access_token(&self) -> &str {
        self.access_token.expose()
    }
}

impl fmt::Debug for SignalConnectContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignalConnectContext")
            .field("signal_url", &self.signal_url)
            .field("access_token", &"<redacted>")
            .field("account_id", &self.account_id)
            .field("device_id", &self.device_id)
            .field("public_key_id", &self.public_key_id)
            .field("public_key_version", &self.public_key_version)
            .field("client_capabilities", &self.client_capabilities)
            .field("identity", &"<loaded>")
            .finish()
    }
}

pub trait SignalClient {
    fn state(&self) -> SignalConnectionState;
    fn connect(&mut self, context: SignalConnectContext) -> Result<(), SignalError>;
    fn disconnect(&mut self);
}

#[derive(Debug, Clone)]
pub struct SignalClientOptions {
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
    pub heartbeat_interval: Duration,
    pub heartbeat_timeout: Duration,
    pub max_reconnect_attempts: usize,
    pub initial_reconnect_delay: Duration,
    pub max_reconnect_delay: Duration,
}

impl Default for SignalClientOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            handshake_timeout: Duration::from_secs(10),
            heartbeat_interval: Duration::from_secs(15),
            heartbeat_timeout: Duration::from_secs(45),
            max_reconnect_attempts: 3,
            initial_reconnect_delay: Duration::from_millis(500),
            max_reconnect_delay: Duration::from_secs(4),
        }
    }
}

impl SignalClientOptions {
    fn reconnect_delay(&self, attempt: usize) -> Duration {
        let exponent = attempt.saturating_sub(1).min(31) as u32;
        self.initial_reconnect_delay
            .saturating_mul(1_u32 << exponent)
            .min(self.max_reconnect_delay)
    }
}

struct SignalWorker {
    cancel: watch::Sender<bool>,
    outbound: tokio::sync::mpsc::Sender<String>,
    thread: JoinHandle<()>,
}

pub struct SignalWebSocketClient {
    machine: SharedMachine,
    worker: Option<SignalWorker>,
    notifications: Option<Receiver<SignalNotification>>,
    options: SignalClientOptions,
    local_device_id: Option<String>,
}

impl Default for SignalWebSocketClient {
    fn default() -> Self {
        Self::with_options(SignalClientOptions::default())
    }
}

impl fmt::Debug for SignalWebSocketClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignalWebSocketClient")
            .field("state", &self.state())
            .field("worker_active", &self.worker.is_some())
            .finish()
    }
}

impl SignalWebSocketClient {
    pub fn with_options(options: SignalClientOptions) -> Self {
        Self {
            machine: Arc::new(Mutex::new(SignalStateMachine::default())),
            worker: None,
            notifications: None,
            options,
            local_device_id: None,
        }
    }

    pub fn try_recv_notification(&self) -> Result<Option<SignalNotification>, SignalError> {
        let receiver = self
            .notifications
            .as_ref()
            .ok_or(SignalError::NotificationReceiverUnavailable)?;
        match receiver.try_recv() {
            Ok(notification) => Ok(Some(notification)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(SignalError::NotificationReceiverUnavailable),
        }
    }

    pub fn send_session_message(
        &self,
        kind: SessionSignalMessageKind,
        session_id: &str,
        role: SessionRole,
        payload: Value,
    ) -> Result<(), SignalError> {
        let worker = self.worker.as_ref().ok_or(SignalError::WorkerUnavailable)?;
        let local_device_id = self
            .local_device_id
            .as_deref()
            .ok_or(SignalError::WorkerUnavailable)?;
        let message =
            encode_outbound_session_message(kind, session_id, role, local_device_id, payload)?;
        worker
            .outbound
            .try_send(message)
            .map_err(|error| match error {
                tokio::sync::mpsc::error::TrySendError::Full(_) => SignalError::OutboundQueueFull,
                tokio::sync::mpsc::error::TrySendError::Closed(_) => SignalError::WorkerUnavailable,
            })
    }

    pub fn request_candidate_token(
        &self,
        request: &CandidateTokenRequest,
    ) -> Result<(), SignalError> {
        let worker = self.worker.as_ref().ok_or(SignalError::WorkerUnavailable)?;
        let local_device_id = self
            .local_device_id
            .as_deref()
            .ok_or(SignalError::WorkerUnavailable)?;
        let message = encode_candidate_token_request(local_device_id, request)?;
        worker
            .outbound
            .try_send(message)
            .map_err(|error| match error {
                tokio::sync::mpsc::error::TrySendError::Full(_) => SignalError::OutboundQueueFull,
                tokio::sync::mpsc::error::TrySendError::Closed(_) => SignalError::WorkerUnavailable,
            })
    }

    fn stop_worker(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.cancel.send(true);
            let _ = worker.thread.join();
        }
        self.local_device_id = None;
    }

    #[cfg(test)]
    fn has_active_worker(&self) -> bool {
        self.worker.is_some()
    }
}

impl SignalClient for SignalWebSocketClient {
    fn state(&self) -> SignalConnectionState {
        lock_machine(&self.machine).state()
    }

    fn connect(&mut self, context: SignalConnectContext) -> Result<(), SignalError> {
        self.stop_worker();
        self.notifications = None;
        {
            let mut machine = lock_machine(&self.machine);
            machine.disconnect();
            machine.begin_connect()?;
        }

        let (cancel_tx, cancel_rx) = watch::channel(false);
        let (notification_tx, notification_rx) = mpsc::sync_channel(NOTIFICATION_QUEUE_CAPACITY);
        let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(OUTBOUND_QUEUE_CAPACITY);
        self.local_device_id = Some(context.device_id.clone());
        let machine = Arc::clone(&self.machine);
        let options = self.options.clone();
        let thread = thread::Builder::new()
            .name("desktop-signal-ws".to_owned())
            .spawn(move || {
                run_signal_worker(
                    machine,
                    context,
                    options,
                    cancel_rx,
                    notification_tx,
                    outbound_rx,
                )
            })
            .map_err(|_| {
                lock_machine(&self.machine).fail();
                SignalError::WorkerUnavailable
            })?;
        self.worker = Some(SignalWorker {
            cancel: cancel_tx,
            outbound: outbound_tx,
            thread,
        });
        self.notifications = Some(notification_rx);
        Ok(())
    }

    fn disconnect(&mut self) {
        self.stop_worker();
        self.notifications = None;
        lock_machine(&self.machine).disconnect();
    }
}

impl Drop for SignalWebSocketClient {
    fn drop(&mut self) {
        self.disconnect();
    }
}

fn lock_machine(machine: &SharedMachine) -> MutexGuard<'_, SignalStateMachine> {
    machine
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn run_signal_worker(
    machine: SharedMachine,
    context: SignalConnectContext,
    options: SignalClientOptions,
    mut cancel: watch::Receiver<bool>,
    notifications: SyncSender<SignalNotification>,
    mut outbound: tokio::sync::mpsc::Receiver<String>,
) {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(_) => {
            lock_machine(&machine).fail();
            return;
        }
    };

    runtime.block_on(async move {
        let mut socket = match establish_connection(&machine, &context, &options, &mut cancel).await
        {
            Ok(socket) => socket,
            Err(error) => {
                if error == SignalError::Cancelled {
                    lock_machine(&machine).disconnect();
                } else {
                    lock_machine(&machine).fail();
                }
                return;
            }
        };

        loop {
            let mut error = match run_online(
                &mut socket,
                &options,
                &mut cancel,
                &notifications,
                &context.device_id,
                &mut outbound,
            )
            .await
            {
                Ok(()) => SignalError::ConnectionClosed,
                Err(SignalError::Cancelled) => {
                    lock_machine(&machine).disconnect();
                    return;
                }
                Err(error) => error,
            };
            let mut attempt = 0;
            loop {
                if !error.is_retriable() || attempt >= options.max_reconnect_attempts {
                    lock_machine(&machine).fail();
                    return;
                }
                attempt += 1;
                lock_machine(&machine).mark_reconnecting();
                if wait_for_reconnect(options.reconnect_delay(attempt), &mut cancel).await {
                    lock_machine(&machine).disconnect();
                    return;
                }
                if lock_machine(&machine).begin_connect().is_err() {
                    lock_machine(&machine).fail();
                    return;
                }
                match establish_connection(&machine, &context, &options, &mut cancel).await {
                    Ok(reconnected) => {
                        socket = reconnected;
                        break;
                    }
                    Err(SignalError::Cancelled) => {
                        lock_machine(&machine).disconnect();
                        return;
                    }
                    Err(reconnect_error) => error = reconnect_error,
                }
            }
        }
    });
}

async fn wait_for_reconnect(delay: Duration, cancel: &mut watch::Receiver<bool>) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(delay) => false,
        _ = wait_for_cancel(cancel) => true,
    }
}

async fn establish_connection(
    machine: &SharedMachine,
    context: &SignalConnectContext,
    options: &SignalClientOptions,
    cancel: &mut watch::Receiver<bool>,
) -> Result<SignalSocket, SignalError> {
    let mut socket = connect_socket(context, options.connect_timeout, cancel).await?;

    let challenge_text =
        receive_handshake_text(&mut socket, options.handshake_timeout, cancel).await?;
    let challenge = decode_typed_message::<HelloChallenge>(&challenge_text, "hello_challenge")
        .inspect_err(|_| {
            lock_machine(machine).fail();
        })?;
    let response = {
        let mut machine = lock_machine(machine);
        machine.build_hello_response(
            &challenge,
            context,
            context.identity.as_ref(),
            now_epoch_millis(),
        )?
    };
    let response = serde_json::to_string(&response).map_err(|_| SignalError::Canonical)?;
    send_with_timeout(
        &mut socket,
        Message::Text(response.into()),
        options.handshake_timeout,
        cancel,
    )
    .await?;

    let hello_text = receive_handshake_text(&mut socket, options.handshake_timeout, cancel).await?;
    let message_type = server_message_type(&hello_text)?;
    if matches!(message_type.as_str(), "auth_failed" | "error") {
        close_socket(&mut socket, CloseCode::Policy, "authentication rejected").await;
        lock_machine(machine).fail();
        return Err(SignalError::AuthenticationRejected);
    }
    if message_type != "hello_ok" {
        close_socket(&mut socket, CloseCode::Policy, "hello_ok required").await;
        lock_machine(machine).fail();
        return Err(SignalError::InvalidServerMessage);
    }
    let hello = serde_json::from_str::<HelloOk>(&hello_text).map_err(|_| {
        lock_machine(machine).fail();
        SignalError::InvalidServerMessage
    })?;
    let hello_result = {
        let mut machine = lock_machine(machine);
        machine.accept_hello_ok(&hello)
    };
    if let Err(error) = hello_result {
        close_socket(&mut socket, CloseCode::Policy, "hello_ok rejected").await;
        return Err(error);
    }
    Ok(socket)
}

async fn connect_socket(
    context: &SignalConnectContext,
    connect_timeout: Duration,
    cancel: &mut watch::Receiver<bool>,
) -> Result<SignalSocket, SignalError> {
    let parsed = Url::parse(&context.signal_url).map_err(|_| SignalError::InvalidUrl)?;
    if !matches!(parsed.scheme(), "ws" | "wss")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(SignalError::InvalidUrl);
    }
    let mut request = context
        .signal_url
        .as_str()
        .into_client_request()
        .map_err(|_| SignalError::InvalidUrl)?;
    let bearer = Zeroizing::new(format!("Bearer {}", context.access_token()));
    let mut authorization =
        HeaderValue::from_str(&bearer).map_err(|_| SignalError::InvalidHeader)?;
    let protocol_version = PROTOCOL_VERSION.to_string();
    let protocol_version =
        HeaderValue::from_str(&protocol_version).map_err(|_| SignalError::InvalidHeader)?;
    authorization.set_sensitive(true);
    request.headers_mut().insert(AUTHORIZATION, authorization);
    request
        .headers_mut()
        .insert(PROTOCOL_VERSIONS_HEADER, protocol_version.clone());
    request
        .headers_mut()
        .insert(MIN_PROTOCOL_VERSION_HEADER, protocol_version);

    tokio::select! {
        _ = wait_for_cancel(cancel) => Err(SignalError::Cancelled),
        result = tokio::time::timeout(connect_timeout, connect_async(request)) => {
            match result {
                Err(_) => Err(SignalError::TimedOut),
                Ok(Ok((socket, _))) => Ok(socket),
                Ok(Err(WebSocketError::Http(response))) => {
                    Err(SignalError::UpgradeRejected(response.status().as_u16()))
                }
                Ok(Err(_)) => Err(SignalError::Transport),
            }
        }
    }
}

async fn receive_handshake_text(
    socket: &mut SignalSocket,
    handshake_timeout: Duration,
    cancel: &mut watch::Receiver<bool>,
) -> Result<String, SignalError> {
    let receive = async {
        loop {
            tokio::select! {
                _ = wait_for_cancel(cancel) => {
                    close_socket(socket, CloseCode::Normal, "cancelled").await;
                    return Err(SignalError::Cancelled);
                }
                message = socket.next() => match message {
                    Some(Ok(Message::Text(text))) => return Ok(text.to_string()),
                    Some(Ok(Message::Ping(payload))) => {
                        socket.send(Message::Pong(payload)).await.map_err(|_| SignalError::Transport)?;
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | None => return Err(SignalError::ConnectionClosed),
                    Some(Ok(_)) => return Err(SignalError::InvalidServerMessage),
                    Some(Err(_)) => return Err(SignalError::Transport),
                }
            }
        }
    };
    tokio::time::timeout(handshake_timeout, receive)
        .await
        .map_err(|_| SignalError::TimedOut)?
}

async fn send_with_timeout(
    socket: &mut SignalSocket,
    message: Message,
    handshake_timeout: Duration,
    cancel: &mut watch::Receiver<bool>,
) -> Result<(), SignalError> {
    tokio::select! {
        _ = wait_for_cancel(cancel) => {
            close_socket(socket, CloseCode::Normal, "cancelled").await;
            Err(SignalError::Cancelled)
        }
        result = tokio::time::timeout(handshake_timeout, socket.send(message)) => match result {
            Err(_) => Err(SignalError::TimedOut),
            Ok(Err(_)) => Err(SignalError::Transport),
            Ok(Ok(())) => Ok(()),
        }
    }
}

async fn run_online(
    socket: &mut SignalSocket,
    options: &SignalClientOptions,
    cancel: &mut watch::Receiver<bool>,
    notifications: &SyncSender<SignalNotification>,
    device_id: &str,
    outbound: &mut tokio::sync::mpsc::Receiver<String>,
) -> Result<(), SignalError> {
    let mut heartbeat = tokio::time::interval(options.heartbeat_interval);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await;
    let mut last_received = Instant::now();

    loop {
        tokio::select! {
            _ = wait_for_cancel(cancel) => {
                close_socket(socket, CloseCode::Normal, "client disconnect").await;
                return Err(SignalError::Cancelled);
            }
            _ = heartbeat.tick() => {
                if last_received.elapsed() >= options.heartbeat_timeout {
                    return Err(SignalError::TimedOut);
                }
                socket
                    .send(Message::Ping(Vec::new().into()))
                    .await
                    .map_err(|_| SignalError::Transport)?;
            }
            outbound_message = outbound.recv() => {
                let Some(outbound_message) = outbound_message else {
                    return Err(SignalError::WorkerUnavailable);
                };
                socket
                    .send(Message::Text(outbound_message.into()))
                    .await
                    .map_err(|_| SignalError::Transport)?;
            }
            message = socket.next() => match message {
                Some(Ok(Message::Text(text))) => {
                    last_received = Instant::now();
                    let message_type = server_message_type(&text)?;
                    if matches!(message_type.as_str(), "auth_failed" | "error") {
                        return Err(SignalError::AuthenticationRejected);
                    }
                    if let Some(notification) =
                        decode_server_notification(&text, &message_type, device_id)?
                    {
                        deliver_notification(notifications, notification)?;
                    }
                }
                Some(Ok(Message::Ping(payload))) => {
                    last_received = Instant::now();
                    socket
                        .send(Message::Pong(payload))
                        .await
                        .map_err(|_| SignalError::Transport)?;
                }
                Some(Ok(Message::Pong(_))) => last_received = Instant::now(),
                Some(Ok(Message::Close(_))) | None => return Err(SignalError::ConnectionClosed),
                Some(Ok(_)) => return Err(SignalError::InvalidServerMessage),
                Some(Err(_)) => return Err(SignalError::Transport),
            }
        }
    }
}

fn deliver_notification(
    notifications: &SyncSender<SignalNotification>,
    notification: SignalNotification,
) -> Result<(), SignalError> {
    match notifications.try_send(notification) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(_)) => Err(SignalError::NotificationQueueFull),
        Err(TrySendError::Disconnected(_)) => Err(SignalError::NotificationReceiverUnavailable),
    }
}

async fn wait_for_cancel(cancel: &mut watch::Receiver<bool>) {
    if *cancel.borrow() {
        return;
    }
    let _ = cancel.wait_for(|cancelled| *cancelled).await;
}

async fn close_socket(socket: &mut SignalSocket, code: CloseCode, reason: &'static str) {
    let _ = socket
        .send(Message::Close(Some(CloseFrame {
            code,
            reason: reason.into(),
        })))
        .await;
}

fn server_message_type(text: &str) -> Result<String, SignalError> {
    let value: Value = serde_json::from_str(text).map_err(|_| SignalError::InvalidServerMessage)?;
    value
        .get("type")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or(SignalError::InvalidServerMessage)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionInviteWire {
    #[serde(rename = "type")]
    kind: String,
    session: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionStateWire {
    #[serde(rename = "type")]
    kind: String,
    session_id: String,
    status: String,
    actor_type: String,
    #[serde(default)]
    actor_device_id: Option<String>,
    #[serde(default)]
    actor_role: Option<String>,
    #[serde(default)]
    actor_service: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    event_id: String,
    session: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionMessageWire {
    #[serde(rename = "type")]
    kind: String,
    session_id: String,
    role: SessionRole,
    from_device_id: String,
    payload: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OnlineDevicesWire {
    #[serde(rename = "type")]
    kind: String,
    devices: Vec<SignalOnlineDevice>,
}

fn decode_server_notification(
    text: &str,
    message_type: &str,
    device_id: &str,
) -> Result<Option<SignalNotification>, SignalError> {
    let notification = match message_type {
        "online_devices" => {
            let wire: OnlineDevicesWire =
                serde_json::from_str(text).map_err(|_| SignalError::InvalidServerMessage)?;
            if wire.kind != message_type
                || wire.devices.iter().any(|online| {
                    online.device_id.is_empty()
                        || online.public_key_id.is_empty()
                        || online.public_key_version == 0
                        || URL_SAFE_NO_PAD
                            .decode(&online.public_key)
                            .ok()
                            .is_none_or(|public_key| public_key.len() != 32)
                })
            {
                return Err(SignalError::InvalidServerMessage);
            }
            SignalNotification::OnlineDevices(wire.devices)
        }
        "session_invite" => {
            let wire: SessionInviteWire = decode_notification_wire(text, message_type)?;
            SignalNotification::SessionInvite(SessionInviteNotification {
                session: decode_session_snapshot(wire.session, device_id)?,
            })
        }
        "session_accept_ack" => SignalNotification::SessionAcceptAck(decode_session_state(
            text,
            message_type,
            device_id,
            false,
        )?),
        "session_reject_ack" => SignalNotification::SessionRejectAck(decode_session_state(
            text,
            message_type,
            device_id,
            true,
        )?),
        "session_cancel_ack" => SignalNotification::SessionCancelAck(decode_session_state(
            text,
            message_type,
            device_id,
            true,
        )?),
        "session_close_ack" => SignalNotification::SessionCloseAck(decode_session_state(
            text,
            message_type,
            device_id,
            true,
        )?),
        "connection_state" => SignalNotification::ConnectionState(decode_session_state(
            text,
            message_type,
            device_id,
            false,
        )?),
        "candidate_token_issued" => {
            let issued: CandidateTokenIssued =
                serde_json::from_str(text).map_err(|_| SignalError::InvalidServerMessage)?;
            if issued.device_id != device_id
                || issued.candidate_token.is_empty()
                || issued.expires_at_epoch_millis <= now_epoch_millis()
            {
                return Err(SignalError::InvalidServerMessage);
            }
            SignalNotification::CandidateTokenIssued(issued)
        }
        "connection_candidate" | "key_exchange_message" | "key_confirm" => {
            SignalNotification::SessionMessage(decode_session_message(text, message_type)?)
        }
        _ => return Ok(None),
    };
    Ok(Some(notification))
}

fn encode_candidate_token_request(
    local_device_id: &str,
    request: &CandidateTokenRequest,
) -> Result<String, SignalError> {
    if local_device_id.is_empty()
        || request.device_id != local_device_id
        || request.requested_ttl_millis == 0
    {
        return Err(SignalError::InvalidSessionMessage);
    }
    serde_json::to_string(&serde_json::json!({
        "type": "request_candidate_token",
        "payload": request,
    }))
    .map_err(|_| SignalError::InvalidSessionMessage)
}

fn decode_session_message(
    text: &str,
    expected_type: &str,
) -> Result<SessionPeerMessage, SignalError> {
    let wire: SessionMessageWire =
        serde_json::from_str(text).map_err(|_| SignalError::InvalidServerMessage)?;
    let kind =
        SessionSignalMessageKind::parse(expected_type).ok_or(SignalError::InvalidServerMessage)?;
    if wire.kind != expected_type
        || wire.session_id.is_empty()
        || wire.from_device_id.is_empty()
        || !validate_session_message_payload(
            kind,
            &wire.session_id,
            &wire.from_device_id,
            wire.role,
            &wire.payload,
        )
    {
        return Err(SignalError::InvalidServerMessage);
    }
    Ok(SessionPeerMessage {
        kind,
        session_id: wire.session_id,
        role: wire.role,
        from_device_id: wire.from_device_id,
        payload: wire.payload,
    })
}

fn encode_outbound_session_message(
    kind: SessionSignalMessageKind,
    session_id: &str,
    role: SessionRole,
    local_device_id: &str,
    payload: Value,
) -> Result<String, SignalError> {
    if !validate_session_message_payload(kind, session_id, local_device_id, role, &payload) {
        return Err(SignalError::InvalidSessionMessage);
    }
    serde_json::to_string(&serde_json::json!({
        "type": kind.as_str(),
        "session_id": session_id,
        "role": role,
        "payload": payload,
    }))
    .map_err(|_| SignalError::InvalidSessionMessage)
}

fn validate_session_message_payload(
    kind: SessionSignalMessageKind,
    session_id: &str,
    device_id: &str,
    role: SessionRole,
    payload: &Value,
) -> bool {
    let Some(session_id) = Uuid::parse_str(session_id)
        .ok()
        .map(|value| value.as_u128())
    else {
        return false;
    };
    match kind {
        SessionSignalMessageKind::ConnectionCandidate => {
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
        SessionSignalMessageKind::KeyExchangeMessage => {
            serde_json::from_value::<SignedKeyExchange>(payload.clone())
                .ok()
                .is_some_and(|value| {
                    value.payload.session_id == session_id
                        && value.payload.device_id == device_id
                        && value.payload.role == role
                        && value.payload.validate_path_binding()
                        && value.signature_bytes().is_some()
                })
        }
        SessionSignalMessageKind::KeyConfirm => {
            serde_json::from_value::<KeyConfirm>(payload.clone())
                .ok()
                .is_some_and(|value| {
                    value.session_id == session_id
                        && value.device_id == device_id
                        && value.role == role
                })
        }
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

fn decode_notification_wire<T>(text: &str, expected_type: &str) -> Result<T, SignalError>
where
    T: for<'de> Deserialize<'de> + NotificationWire,
{
    let wire: T = serde_json::from_str(text).map_err(|_| SignalError::InvalidServerMessage)?;
    if wire.kind() != expected_type {
        return Err(SignalError::InvalidServerMessage);
    }
    Ok(wire)
}

trait NotificationWire {
    fn kind(&self) -> &str;
}

impl NotificationWire for SessionInviteWire {
    fn kind(&self) -> &str {
        &self.kind
    }
}

impl NotificationWire for SessionStateWire {
    fn kind(&self) -> &str {
        &self.kind
    }
}

fn decode_session_state(
    text: &str,
    message_type: &str,
    device_id: &str,
    reason_required: bool,
) -> Result<SessionStateNotification, SignalError> {
    let wire: SessionStateWire = decode_notification_wire(text, message_type)?;
    let session = decode_session_snapshot(wire.session, device_id)?;
    if wire.session_id.is_empty()
        || wire.status.is_empty()
        || wire.event_id.is_empty()
        || wire.session_id != session.session_id
        || wire.status != session.status
        || (reason_required && wire.reason.as_deref().is_none_or(str::is_empty))
    {
        return Err(SignalError::InvalidServerMessage);
    }
    let actor = decode_session_actor(
        &wire.actor_type,
        wire.actor_device_id,
        wire.actor_role,
        wire.actor_service,
    )?;
    Ok(SessionStateNotification {
        session_id: wire.session_id,
        status: wire.status,
        actor,
        reason: wire.reason,
        event_id: wire.event_id,
        session,
    })
}

fn decode_session_snapshot(
    payload: Value,
    current_device_id: &str,
) -> Result<SessionSnapshot, SignalError> {
    let object = payload
        .as_object()
        .ok_or(SignalError::InvalidServerMessage)?;
    let string_field = |field: &str| {
        object
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .ok_or(SignalError::InvalidServerMessage)
    };
    let session_id = string_field("session_id")?;
    let status = string_field("status")?;
    let controller_device_id = string_field("controller_device_id")?;
    let controlled_device_id = string_field("controlled_device_id")?;
    if current_device_id != controller_device_id && current_device_id != controlled_device_id {
        return Err(SignalError::InvalidServerMessage);
    }
    Ok(SessionSnapshot {
        session_id,
        status,
        controller_device_id,
        controlled_device_id,
        payload,
    })
}

fn decode_session_actor(
    actor_type: &str,
    actor_device_id: Option<String>,
    actor_role: Option<String>,
    actor_service: Option<String>,
) -> Result<SessionActor, SignalError> {
    match actor_type {
        "device" => {
            let device_id = actor_device_id
                .filter(|value| !value.is_empty())
                .ok_or(SignalError::InvalidServerMessage)?;
            let role = match actor_role.as_deref() {
                Some("controller") => SessionActorRole::Controller,
                Some("controlled") => SessionActorRole::Controlled,
                _ => return Err(SignalError::InvalidServerMessage),
            };
            if actor_service.is_some() {
                return Err(SignalError::InvalidServerMessage);
            }
            Ok(SessionActor::Device { device_id, role })
        }
        "service" => {
            if actor_device_id.is_some() || actor_role.is_some() {
                return Err(SignalError::InvalidServerMessage);
            }
            let service = actor_service
                .filter(|value| !value.is_empty())
                .ok_or(SignalError::InvalidServerMessage)?;
            Ok(SessionActor::Service { service })
        }
        "system" => {
            if actor_device_id.is_some() || actor_role.is_some() || actor_service.is_some() {
                return Err(SignalError::InvalidServerMessage);
            }
            Ok(SessionActor::System)
        }
        _ => Err(SignalError::InvalidServerMessage),
    }
}

fn decode_typed_message<T>(text: &str, expected_type: &str) -> Result<T, SignalError>
where
    T: for<'de> Deserialize<'de>,
{
    if server_message_type(text)? != expected_type {
        return Err(SignalError::InvalidServerMessage);
    }
    serde_json::from_str(text).map_err(|_| SignalError::InvalidServerMessage)
}

fn now_epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[derive(Debug)]
pub struct SignalStateMachine {
    state: SignalConnectionState,
    expected: Option<ExpectedHello>,
}

impl Default for SignalStateMachine {
    fn default() -> Self {
        Self {
            state: SignalConnectionState::Disconnected,
            expected: None,
        }
    }
}

impl SignalStateMachine {
    pub fn state(&self) -> SignalConnectionState {
        self.state
    }

    pub fn begin_connect(&mut self) -> Result<(), SignalError> {
        if !matches!(
            self.state,
            SignalConnectionState::Disconnected
                | SignalConnectionState::Failed
                | SignalConnectionState::Reconnecting
        ) {
            return Err(SignalError::InvalidTransition);
        }
        self.expected = None;
        self.state = SignalConnectionState::Connecting;
        self.state = SignalConnectionState::AwaitingChallenge;
        Ok(())
    }

    pub fn build_hello_response(
        &mut self,
        challenge: &HelloChallenge,
        context: &SignalConnectContext,
        identity: &DeviceIdentity,
        timestamp_epoch_millis: u64,
    ) -> Result<HelloResponse, SignalError> {
        if self.state != SignalConnectionState::AwaitingChallenge {
            return Err(SignalError::InvalidTransition);
        }
        if challenge.account_id != context.account_id
            || challenge.protocol_version != PROTOCOL_VERSION
            || challenge.server_supported_protocol_versions.is_empty()
            || challenge.server_supported_protocol_versions.len() > 16
            || !challenge
                .server_supported_protocol_versions
                .contains(&PROTOCOL_VERSION)
            || challenge.expires_at_epoch_millis <= timestamp_epoch_millis
            || identity.device_id() != context.device_id
        {
            self.fail();
            return Err(SignalError::InvalidChallenge);
        }
        let server_nonce: [u8; 32] = match URL_SAFE_NO_PAD
            .decode(&challenge.server_nonce)
            .ok()
            .and_then(|nonce| nonce.try_into().ok())
        {
            Some(nonce) => nonce,
            None => {
                self.fail();
                return Err(SignalError::InvalidChallenge);
            }
        };
        let first_nonce = Uuid::new_v4();
        let second_nonce = Uuid::new_v4();
        let mut client_nonce = [0_u8; 32];
        client_nonce[..16].copy_from_slice(first_nonce.as_bytes());
        client_nonce[16..].copy_from_slice(second_nonce.as_bytes());
        let versions = vec![PROTOCOL_VERSION];
        let versions_hash = protocol_versions_hash(&versions, PROTOCOL_VERSION)?;
        let capabilities_hash = client_capabilities_hash(&context.client_capabilities)?;
        let canonical = hello_signature_input(
            &server_nonce,
            &client_nonce,
            &context.account_id,
            &context.device_id,
            challenge.protocol_version,
            timestamp_epoch_millis,
            &versions_hash,
            &capabilities_hash,
        )?;
        let response = HelloResponse {
            account_id: context.account_id.clone(),
            device_id: context.device_id.clone(),
            client_nonce: URL_SAFE_NO_PAD.encode(client_nonce),
            timestamp: timestamp_epoch_millis,
            client_supported_protocol_versions: versions,
            client_min_protocol_version: PROTOCOL_VERSION,
            public_key_id: context.public_key_id.clone(),
            public_key_version: context.public_key_version,
            client_supported_protocol_versions_hash: hex(&versions_hash),
            client_capabilities: context.client_capabilities.clone(),
            client_capabilities_hash: hex(&capabilities_hash),
            device_signature: URL_SAFE_NO_PAD.encode(identity.sign_canonical(&canonical)),
        };
        self.expected = Some(ExpectedHello {
            account_id: context.account_id.clone(),
            device_id: context.device_id.clone(),
            protocol_version: challenge.protocol_version,
            versions_hash: response.client_supported_protocol_versions_hash.clone(),
            capabilities_hash: response.client_capabilities_hash.clone(),
            server_supported_protocol_versions: challenge
                .server_supported_protocol_versions
                .clone(),
        });
        self.state = SignalConnectionState::Authenticating;
        Ok(response)
    }

    pub fn accept_hello_ok(&mut self, hello: &HelloOk) -> Result<(), SignalError> {
        if self.state != SignalConnectionState::Authenticating {
            return Err(SignalError::InvalidTransition);
        }
        let matches = self.expected.take().is_some_and(|expected| {
            expected.account_id == hello.account_id
                && expected.device_id == hello.device_id
                && expected.protocol_version == hello.protocol_version
                && expected.versions_hash == hello.client_supported_protocol_versions_hash
                && expected.capabilities_hash == hello.client_capabilities_hash
                && expected.server_supported_protocol_versions
                    == hello.server_supported_protocol_versions
                && !hello.connection_id.is_empty()
        });
        if !matches {
            self.fail();
            return Err(SignalError::HelloMismatch);
        }
        self.state = SignalConnectionState::Online;
        Ok(())
    }

    pub fn reconnect(&mut self) -> Result<(), SignalError> {
        if self.state != SignalConnectionState::Online {
            return Err(SignalError::InvalidTransition);
        }
        self.mark_reconnecting();
        Ok(())
    }

    fn mark_reconnecting(&mut self) {
        self.expected = None;
        self.state = SignalConnectionState::Reconnecting;
    }

    pub fn fail(&mut self) {
        self.expected = None;
        self.state = SignalConnectionState::Failed;
    }

    pub fn disconnect(&mut self) {
        self.expected = None;
        self.state = SignalConnectionState::Disconnected;
    }
}

#[derive(Debug)]
struct ExpectedHello {
    account_id: String,
    device_id: String,
    protocol_version: u16,
    versions_hash: String,
    capabilities_hash: String,
    server_supported_protocol_versions: Vec<u16>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct HelloChallenge {
    pub account_id: String,
    pub protocol_version: u16,
    pub server_nonce: String,
    pub expires_at_epoch_millis: u64,
    pub server_supported_protocol_versions: Vec<u16>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(tag = "type", rename = "hello_response")]
pub struct HelloResponse {
    pub account_id: String,
    pub device_id: String,
    pub client_nonce: String,
    pub timestamp: u64,
    pub client_supported_protocol_versions: Vec<u16>,
    pub client_min_protocol_version: u16,
    pub public_key_id: String,
    pub public_key_version: u32,
    pub client_supported_protocol_versions_hash: String,
    pub client_capabilities: Value,
    pub client_capabilities_hash: String,
    pub device_signature: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct HelloOk {
    pub account_id: String,
    pub device_id: String,
    pub protocol_version: u16,
    pub connection_id: String,
    pub client_supported_protocol_versions_hash: String,
    pub client_capabilities_hash: String,
    pub server_supported_protocol_versions: Vec<u16>,
    pub server_time_epoch_millis: u64,
}

fn protocol_versions_hash(versions: &[u16], minimum: u16) -> Result<[u8; 32], SignalError> {
    let mut encoded = Vec::with_capacity(versions.len() * 2);
    for version in versions {
        encoded.extend_from_slice(&version.to_be_bytes());
    }
    let mut writer =
        CanonicalWriter::new("rctl-protocol-versions-v1").map_err(|_| SignalError::Canonical)?;
    writer
        .push_field("client_supported_protocol_versions", &encoded)
        .map_err(|_| SignalError::Canonical)?
        .push_u16("client_min_protocol_version", minimum)
        .map_err(|_| SignalError::Canonical)?;
    Ok(sha256(&writer.finish()))
}

fn client_capabilities_hash(capabilities: &Value) -> Result<[u8; 32], SignalError> {
    let capabilities = canonical_json_bytes(capabilities).map_err(|_| SignalError::Canonical)?;
    let mut writer =
        CanonicalWriter::new("rctl-client-capabilities-v1").map_err(|_| SignalError::Canonical)?;
    writer
        .push_field("client_capabilities", &capabilities)
        .map_err(|_| SignalError::Canonical)?;
    Ok(sha256(&writer.finish()))
}

#[allow(clippy::too_many_arguments)]
fn hello_signature_input(
    server_nonce: &[u8; 32],
    client_nonce: &[u8; 32],
    account_id: &str,
    device_id: &str,
    protocol_version: u16,
    timestamp_epoch_millis: u64,
    versions_hash: &[u8; 32],
    capabilities_hash: &[u8; 32],
) -> Result<Vec<u8>, SignalError> {
    let mut writer =
        CanonicalWriter::new("rctl-ws-hello-v1").map_err(|_| SignalError::Canonical)?;
    writer
        .push_field("server_nonce", server_nonce)
        .map_err(|_| SignalError::Canonical)?
        .push_field("client_nonce", client_nonce)
        .map_err(|_| SignalError::Canonical)?
        .push_str("account_id", account_id)
        .map_err(|_| SignalError::Canonical)?
        .push_str("device_id", device_id)
        .map_err(|_| SignalError::Canonical)?
        .push_u16("protocol_version", protocol_version)
        .map_err(|_| SignalError::Canonical)?
        .push_u64("timestamp", timestamp_epoch_millis)
        .map_err(|_| SignalError::Canonical)?
        .push_field("client_supported_protocol_versions_hash", versions_hash)
        .map_err(|_| SignalError::Canonical)?
        .push_field("client_capabilities_hash", capabilities_hash)
        .map_err(|_| SignalError::Canonical)?;
    Ok(writer.finish())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceIdentityManager;
    use crate::secret_store::ProcessSecretStore;
    use remote_crypto::verify_canonical_signature;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use tokio_tungstenite::accept_hdr_async;
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

    #[derive(Clone, Copy)]
    enum TestServerMode {
        StayOnline,
        SendConnectionState(&'static str),
        TamperHelloOk,
        CloseAfterHello,
        StallBeforeChallenge,
    }

    struct TestServer {
        url: String,
        accepted: mpsc::Receiver<()>,
        closed: mpsc::Receiver<()>,
        thread: JoinHandle<()>,
    }

    impl TestServer {
        fn wait_for_accept(&self) {
            self.accepted
                .recv_timeout(Duration::from_secs(3))
                .expect("server accepted websocket");
        }

        fn wait_for_close(self) {
            self.closed
                .recv_timeout(Duration::from_secs(3))
                .expect("server observed close");
            self.thread.join().expect("test server");
        }
    }

    fn context(
        identity: Arc<DeviceIdentity>,
        signal_url: impl Into<String>,
    ) -> SignalConnectContext {
        let device_id = identity.device_id().to_owned();
        SignalConnectContext::new(
            signal_url,
            "access-private",
            "account-1",
            device_id,
            "key-1",
            1,
            serde_json::json!({
                "platform": "ubuntu",
                "arch": "x86_64",
                "transport": ["quic", "relay"]
            }),
            identity,
        )
    }

    fn identity_manager() -> DeviceIdentityManager {
        let mut manager = DeviceIdentityManager::new(Arc::new(ProcessSecretStore::default()));
        manager.load_or_create().expect("identity");
        manager
    }

    fn test_options(max_reconnect_attempts: usize) -> SignalClientOptions {
        SignalClientOptions {
            connect_timeout: Duration::from_secs(2),
            handshake_timeout: Duration::from_secs(2),
            heartbeat_interval: Duration::from_millis(50),
            heartbeat_timeout: Duration::from_secs(1),
            max_reconnect_attempts,
            initial_reconnect_delay: Duration::from_millis(10),
            max_reconnect_delay: Duration::from_millis(20),
        }
    }

    fn key_confirm_payload(session_id: &str, device_id: &str, role: SessionRole) -> Value {
        serde_json::to_value(KeyConfirm {
            session_id: Uuid::parse_str(session_id).unwrap().as_u128(),
            device_id: device_id.to_owned(),
            role,
            key_exchange_transcript_hash: [3; 32],
            confirm_mac: [5; 32],
            timestamp_epoch_millis: now_epoch_millis(),
        })
        .expect("key confirm payload")
    }

    fn candidate_token_request(device_id: &str) -> CandidateTokenRequest {
        use remote_protocol::{CandidateSource, TransportPath};

        CandidateTokenRequest {
            session_id: Uuid::parse_str("00000000-0000-4000-8000-000000000001")
                .expect("session UUID")
                .as_u128(),
            device_id: device_id.to_owned(),
            role: SessionRole::Controlled,
            candidate_id: 2,
            kind: TransportPath::LanDirect,
            endpoint: "192.168.1.10:50000".to_owned(),
            source: CandidateSource::LocalInterface,
            relay_node_id: None,
            observe_result_id: None,
            observe_result_binding_hash: None,
            local_interface_claim_hash: Some([1; 32]),
            local_interface_signature: Some(vec![2; 64]),
            interface_name_hash: Some([3; 32]),
            interface_index_hash: Some([4; 32]),
            local_socket_nonce: Some([5; 32]),
            timestamp_epoch_millis: Some(now_epoch_millis()),
            requested_ttl_millis: 30_000,
        }
    }

    #[test]
    fn candidate_token_request_and_response_are_bound_to_the_local_device() {
        let request = candidate_token_request("ubuntu-1");
        let encoded =
            encode_candidate_token_request("ubuntu-1", &request).expect("encode token request");
        let value: Value = serde_json::from_str(&encoded).expect("request JSON");
        assert_eq!(value["type"], "request_candidate_token");
        assert_eq!(value["payload"]["device_id"], "ubuntu-1");
        assert_eq!(
            encode_candidate_token_request("substituted", &request),
            Err(SignalError::InvalidSessionMessage)
        );

        let response = serde_json::json!({
            "type": "candidate_token_issued",
            "session_id": "00000000-0000-4000-8000-000000000001",
            "device_id": "ubuntu-1",
            "role": "controlled",
            "candidate_id": "00000000000000000000000000000002",
            "candidate_token": [7, 8, 9],
            "candidate_token_binding_hash": vec![6; 32],
            "expires_at_epoch_millis": now_epoch_millis() + 30_000,
        })
        .to_string();
        let decoded = decode_server_notification(&response, "candidate_token_issued", "ubuntu-1")
            .expect("decode token response")
            .expect("token notification");
        let SignalNotification::CandidateTokenIssued(issued) = decoded else {
            panic!("candidate token notification expected");
        };
        assert_eq!(issued.device_id, "ubuntu-1");
        assert_eq!(issued.candidate_id, 2);
        assert_eq!(issued.candidate_token, [7, 8, 9]);

        assert_eq!(
            decode_server_notification(&response, "candidate_token_issued", "substituted",),
            Err(SignalError::InvalidServerMessage)
        );
    }

    #[test]
    fn controlled_candidate_requires_and_preserves_single_session_transport_identity() {
        use remote_protocol::{CandidateSource, TransportPath};

        let session_id = "00000000-0000-4000-8000-000000000001";
        let candidate = ConnectionCandidateDto {
            candidate_id: 2,
            session_id: Uuid::parse_str(session_id).unwrap().as_u128(),
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
            candidate_token: vec![7; 32],
            candidate_token_binding_hash: [8; 32],
            expires_at_epoch_millis: now_epoch_millis() + 30_000,
        };
        let certificate = URL_SAFE_NO_PAD.encode([0x30, 0x01, 0x00]);
        let server_name = format!("rctl-{session_id}.invalid");
        let payload = serde_json::json!({
            "candidate": candidate,
            "authorization": authorization,
            "transport_certificate_der": certificate,
            "server_name": server_name,
        });
        let encoded = encode_outbound_session_message(
            SessionSignalMessageKind::ConnectionCandidate,
            session_id,
            SessionRole::Controlled,
            "ubuntu-1",
            payload,
        )
        .expect("encode controlled candidate");
        let value: Value = serde_json::from_str(&encoded).expect("candidate JSON");
        assert_eq!(value["payload"]["transport_certificate_der"], certificate);
        assert_eq!(value["payload"]["server_name"], server_name);

        let missing_identity = serde_json::json!({
            "candidate": candidate,
            "authorization": authorization,
        });
        assert_eq!(
            encode_outbound_session_message(
                SessionSignalMessageKind::ConnectionCandidate,
                session_id,
                SessionRole::Controlled,
                "ubuntu-1",
                missing_identity,
            ),
            Err(SignalError::InvalidSessionMessage)
        );
    }

    #[test]
    fn online_device_public_key_is_available_for_peer_key_exchange_verification() {
        let message = serde_json::json!({
            "type": "online_devices",
            "devices": [{
                "account_id": "account-1",
                "device_id": "ios-1",
                "public_key_id": "key-1",
                "public_key_version": 1,
                "public_key": URL_SAFE_NO_PAD.encode([7; 32]),
                "client_capabilities_hash": "aa".repeat(32),
                "status": "online",
                "last_seen_epoch_millis": 1_000,
                "connection_id": "connection-1"
            }]
        })
        .to_string();
        let notification = decode_server_notification(&message, "online_devices", "ubuntu-1")
            .expect("decode online devices")
            .expect("online devices notification");
        let SignalNotification::OnlineDevices(devices) = notification else {
            panic!("online device notification expected");
        };
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, "ios-1");
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(&devices[0].public_key)
                .expect("peer public key"),
            [7; 32]
        );
    }

    #[test]
    fn outbound_key_confirm_is_strictly_bound_and_omits_sender_field() {
        let session_id = "00000000-0000-4000-8000-000000000001";
        let encoded = encode_outbound_session_message(
            SessionSignalMessageKind::KeyConfirm,
            session_id,
            SessionRole::Controlled,
            "ubuntu-1",
            key_confirm_payload(session_id, "ubuntu-1", SessionRole::Controlled),
        )
        .expect("encode outbound key confirm");
        let value: Value = serde_json::from_str(&encoded).expect("outbound JSON");
        assert_eq!(value["type"], "key_confirm");
        assert_eq!(value["session_id"], session_id);
        assert_eq!(value["role"], "controlled");
        assert!(value.get("from_device_id").is_none());

        assert_eq!(
            encode_outbound_session_message(
                SessionSignalMessageKind::KeyConfirm,
                session_id,
                SessionRole::Controlled,
                "ubuntu-1",
                key_confirm_payload(session_id, "substituted", SessionRole::Controlled),
            ),
            Err(SignalError::InvalidSessionMessage)
        );
    }

    #[test]
    fn inbound_key_confirm_preserves_sender_and_rejects_role_substitution() {
        let session_id = "00000000-0000-4000-8000-000000000001";
        let message = serde_json::json!({
            "type": "key_confirm",
            "session_id": session_id,
            "role": "controller",
            "from_device_id": "ios-1",
            "payload": key_confirm_payload(session_id, "ios-1", SessionRole::Controller),
        })
        .to_string();
        let decoded = decode_server_notification(&message, "key_confirm", "ubuntu-1")
            .expect("decode notification")
            .expect("session notification");
        let SignalNotification::SessionMessage(decoded) = decoded else {
            panic!("expected session message");
        };
        assert_eq!(decoded.kind, SessionSignalMessageKind::KeyConfirm);
        assert_eq!(decoded.from_device_id, "ios-1");
        assert_eq!(decoded.role, SessionRole::Controller);

        let substituted = serde_json::json!({
            "type": "key_confirm",
            "session_id": session_id,
            "role": "controlled",
            "from_device_id": "ios-1",
            "payload": key_confirm_payload(session_id, "ios-1", SessionRole::Controller),
        })
        .to_string();
        assert_eq!(
            decode_server_notification(&substituted, "key_confirm", "ubuntu-1"),
            Err(SignalError::InvalidServerMessage)
        );
    }

    fn spawn_test_server(public_key: [u8; 32], mode: TestServerMode) -> TestServer {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test signal");
        let address = listener.local_addr().expect("test address");
        listener.set_nonblocking(true).expect("nonblocking");
        let (accepted_tx, accepted_rx) = mpsc::sync_channel(1);
        let (closed_tx, closed_rx) = mpsc::sync_channel(1);
        let thread = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
                let (stream, _) = listener.accept().await.expect("accept client");
                let mut socket =
                    accept_hdr_async(stream, |request: &Request, response: Response| {
                    assert_eq!(
                        request
                            .headers()
                            .get(AUTHORIZATION)
                            .and_then(|value| value.to_str().ok()),
                        Some("Bearer access-private")
                    );
                    assert_eq!(
                        request
                            .headers()
                            .get(&PROTOCOL_VERSIONS_HEADER)
                            .and_then(|value| value.to_str().ok()),
                        Some("1")
                    );
                    assert_eq!(
                        request
                            .headers()
                            .get(&MIN_PROTOCOL_VERSION_HEADER)
                            .and_then(|value| value.to_str().ok()),
                        Some("1")
                    );
                        Ok(response)
                    })
                    .await
                    .expect("websocket upgrade");
                accepted_tx.send(()).expect("accept event");

                if matches!(mode, TestServerMode::StallBeforeChallenge) {
                    loop {
                        match socket.next().await {
                            Some(Ok(Message::Ping(payload))) => {
                                socket
                                    .send(Message::Pong(payload))
                                    .await
                                    .expect("server pong");
                            }
                            Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                            Some(Ok(_)) => {}
                        }
                    }
                    closed_tx.send(()).expect("close event");
                    return;
                }

                let server_nonce = [3_u8; 32];
                let challenge = serde_json::json!({
                    "type": "hello_challenge",
                    "account_id": "account-1",
                    "protocol_version": PROTOCOL_VERSION,
                    "server_nonce": URL_SAFE_NO_PAD.encode(server_nonce),
                    "expires_at_epoch_millis": now_epoch_millis() + 30_000,
                    "server_supported_protocol_versions": [PROTOCOL_VERSION]
                });
                socket
                    .send(Message::Text(challenge.to_string().into()))
                    .await
                    .expect("challenge");
                let response = match socket.next().await {
                    Some(Ok(Message::Text(text))) => {
                        serde_json::from_str::<HelloResponse>(&text).expect("hello response")
                    }
                    other => panic!("unexpected hello response: {other:?}"),
                };
                verify_response_signature(&public_key, &server_nonce, &response);

                let capabilities_hash = if matches!(mode, TestServerMode::TamperHelloOk) {
                    "tampered".to_owned()
                } else {
                    response.client_capabilities_hash.clone()
                };
                let authenticated_device_id = response.device_id.clone();
                let hello_ok = serde_json::json!({
                    "type": "hello_ok",
                    "account_id": response.account_id,
                    "device_id": response.device_id,
                    "protocol_version": PROTOCOL_VERSION,
                    "connection_id": "connection-1",
                    "client_supported_protocol_versions_hash": response.client_supported_protocol_versions_hash,
                    "client_capabilities_hash": capabilities_hash,
                    "server_supported_protocol_versions": [PROTOCOL_VERSION],
                    "server_time_epoch_millis": now_epoch_millis()
                });
                socket
                    .send(Message::Text(hello_ok.to_string().into()))
                    .await
                    .expect("hello ok");

                if let TestServerMode::SendConnectionState(event_id) = mode {
                    let notification = session_state_json(
                        "connection_state",
                        &authenticated_device_id,
                        "connected",
                        event_id,
                        None,
                    );
                    socket
                        .send(Message::Text(notification.to_string().into()))
                        .await
                        .expect("connection state notification");
                }

                if matches!(mode, TestServerMode::CloseAfterHello) {
                    socket.close(None).await.expect("server close");
                    closed_tx.send(()).expect("close event");
                    return;
                }
                loop {
                    match socket.next().await {
                        Some(Ok(Message::Ping(payload))) => {
                            socket
                                .send(Message::Pong(payload))
                                .await
                                .expect("server pong");
                        }
                        Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                        Some(Ok(_)) => {}
                    }
                }
                closed_tx.send(()).expect("close event");
            });
        });
        TestServer {
            url: format!("ws://{address}/ws"),
            accepted: accepted_rx,
            closed: closed_rx,
            thread,
        }
    }

    fn session_snapshot_json(device_id: &str, status: &str) -> Value {
        serde_json::json!({
            "session_id": "session-1",
            "status": status,
            "controller_device_id": "windows-1",
            "controlled_device_id": device_id,
            "permissions": { "remote_desktop": true }
        })
    }

    fn session_state_json(
        message_type: &str,
        device_id: &str,
        status: &str,
        event_id: &str,
        reason: Option<&str>,
    ) -> Value {
        serde_json::json!({
            "type": message_type,
            "session_id": "session-1",
            "status": status,
            "actor_type": "device",
            "actor_device_id": "windows-1",
            "actor_role": "controller",
            "reason": reason,
            "event_id": event_id,
            "session": session_snapshot_json(device_id, status)
        })
    }

    fn wait_for_notification(client: &SignalWebSocketClient) -> SignalNotification {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            match client.try_recv_notification() {
                Ok(Some(notification)) => return notification,
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(error) => panic!("notification receiver failed: {error}"),
            }
        }
        panic!("notification delivery timed out");
    }

    fn verify_response_signature(
        public_key: &[u8; 32],
        server_nonce: &[u8; 32],
        response: &HelloResponse,
    ) {
        let client_nonce: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&response.client_nonce)
            .expect("client nonce")
            .try_into()
            .expect("nonce length");
        let versions_hash = protocol_versions_hash(
            &response.client_supported_protocol_versions,
            response.client_min_protocol_version,
        )
        .expect("versions hash");
        let capabilities_hash =
            client_capabilities_hash(&response.client_capabilities).expect("capabilities hash");
        let canonical = hello_signature_input(
            server_nonce,
            &client_nonce,
            &response.account_id,
            &response.device_id,
            PROTOCOL_VERSION,
            response.timestamp,
            &versions_hash,
            &capabilities_hash,
        )
        .expect("canonical");
        let signature: [u8; 64] = URL_SAFE_NO_PAD
            .decode(&response.device_signature)
            .expect("signature")
            .try_into()
            .expect("signature length");
        verify_canonical_signature(public_key, &canonical, &signature).expect("valid signature");
    }

    fn wait_for_state(client: &SignalWebSocketClient, expected: SignalConnectionState) {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if client.state() == expected {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(client.state(), expected);
    }

    #[test]
    fn reconnect_backoff_is_exponential_and_capped() {
        let options = SignalClientOptions {
            initial_reconnect_delay: Duration::from_millis(100),
            max_reconnect_delay: Duration::from_millis(350),
            ..test_options(4)
        };

        assert_eq!(options.reconnect_delay(1), Duration::from_millis(100));
        assert_eq!(options.reconnect_delay(2), Duration::from_millis(200));
        assert_eq!(options.reconnect_delay(3), Duration::from_millis(350));
        assert_eq!(options.reconnect_delay(4), Duration::from_millis(350));
    }

    #[test]
    fn all_supported_business_notifications_are_typed_and_preserve_snapshots() {
        let invite = serde_json::json!({
            "type": "session_invite",
            "session": session_snapshot_json("ubuntu-1", "waiting_approval")
        });
        let invite_type = server_message_type(&invite.to_string()).expect("invite type");
        let invite = decode_server_notification(&invite.to_string(), &invite_type, "ubuntu-1")
            .expect("valid invite")
            .expect("known invite");
        let SignalNotification::SessionInvite(invite) = invite else {
            panic!("expected session invite");
        };
        assert_eq!(invite.session.session_id, "session-1");
        assert_eq!(invite.session.status, "waiting_approval");
        assert_eq!(
            invite.session.payload["permissions"]["remote_desktop"],
            true
        );

        for (message_type, reason) in [
            ("session_accept_ack", None),
            ("session_reject_ack", Some("declined")),
            ("session_cancel_ack", Some("cancelled_by_user")),
            ("session_close_ack", Some("completed")),
            ("connection_state", None),
        ] {
            let payload = session_state_json(
                message_type,
                "ubuntu-1",
                "connected",
                &format!("event-{message_type}"),
                reason,
            );
            let parsed_type = server_message_type(&payload.to_string()).expect("message type");
            let notification =
                decode_server_notification(&payload.to_string(), &parsed_type, "ubuntu-1")
                    .expect("valid state notification")
                    .expect("known state notification");
            let state = match (message_type, notification) {
                ("session_accept_ack", SignalNotification::SessionAcceptAck(state))
                | ("session_reject_ack", SignalNotification::SessionRejectAck(state))
                | ("session_cancel_ack", SignalNotification::SessionCancelAck(state))
                | ("session_close_ack", SignalNotification::SessionCloseAck(state))
                | ("connection_state", SignalNotification::ConnectionState(state)) => state,
                _ => panic!("notification variant did not match {message_type}"),
            };
            assert_eq!(state.session_id, "session-1");
            assert_eq!(state.status, "connected");
            assert_eq!(state.event_id, format!("event-{message_type}"));
            assert_eq!(state.reason.as_deref(), reason);
            assert_eq!(state.session.payload, payload["session"]);
            assert_eq!(
                state.actor,
                SessionActor::Device {
                    device_id: "windows-1".into(),
                    role: SessionActorRole::Controller,
                }
            );
        }
    }

    #[test]
    fn unknown_notifications_are_ignored_for_forward_compatibility() {
        let payload = serde_json::json!({
            "type": "future_session_update",
            "opaque": { "access_token": "must-not-be-rendered" }
        });
        let message_type = server_message_type(&payload.to_string()).expect("future type");

        assert_eq!(
            decode_server_notification(&payload.to_string(), &message_type, "ubuntu-1")
                .expect("unknown types are valid"),
            None
        );
    }

    #[test]
    fn malformed_known_notifications_fail_closed_without_payload_in_error() {
        let mut missing_event =
            session_state_json("connection_state", "ubuntu-1", "connected", "event-1", None);
        missing_event
            .as_object_mut()
            .expect("notification object")
            .remove("event_id");

        let mut mismatched_snapshot =
            session_state_json("connection_state", "ubuntu-1", "connected", "event-1", None);
        mismatched_snapshot["session"]["status"] = Value::String("degraded".into());

        let mut invalid_actor =
            session_state_json("connection_state", "ubuntu-1", "connected", "event-1", None);
        invalid_actor["actor_service"] = Value::String("signal-server".into());

        let reject_without_reason = session_state_json(
            "session_reject_ack",
            "ubuntu-1",
            "rejected",
            "event-2",
            None,
        );
        let wrong_device = session_state_json(
            "connection_state",
            "other-device",
            "connected",
            "event-3",
            None,
        );
        let mut unknown_field =
            session_state_json("connection_state", "ubuntu-1", "connected", "event-4", None);
        unknown_field["private_business_body"] = Value::String("must-not-leak".into());
        let invalid_invite = serde_json::json!({
            "type": "session_invite",
            "session": "not-an-object"
        });

        for payload in [
            missing_event,
            mismatched_snapshot,
            invalid_actor,
            reject_without_reason,
            wrong_device,
            unknown_field,
            invalid_invite,
        ] {
            let encoded = payload.to_string();
            let message_type = server_message_type(&encoded).expect("known type");
            let error = decode_server_notification(&encoded, &message_type, "ubuntu-1")
                .expect_err("known malformed notification must fail closed");
            assert_eq!(error, SignalError::InvalidServerMessage);
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains("must-not-leak"));
            assert!(!rendered.contains("private_business_body"));
        }
    }

    #[test]
    fn notification_delivery_is_bounded_and_fails_when_full() {
        let (sender, receiver) = mpsc::sync_channel(1);
        let notification = SignalNotification::SessionInvite(SessionInviteNotification {
            session: decode_session_snapshot(
                session_snapshot_json("ubuntu-1", "waiting_approval"),
                "ubuntu-1",
            )
            .expect("snapshot"),
        });

        deliver_notification(&sender, notification.clone()).expect("first queued notification");
        assert_eq!(
            deliver_notification(&sender, notification),
            Err(SignalError::NotificationQueueFull)
        );
        assert!(receiver.try_recv().is_ok());
    }

    #[test]
    fn online_requires_a_matching_hello_ok() {
        let manager = identity_manager();
        let identity = manager.shared_current().expect("identity");
        let context = context(identity.clone(), "wss://signal.example.com/ws");
        let now = 1_000;
        let challenge = HelloChallenge {
            account_id: "account-1".into(),
            protocol_version: PROTOCOL_VERSION,
            server_nonce: URL_SAFE_NO_PAD.encode([3_u8; 32]),
            expires_at_epoch_millis: now + 30_000,
            server_supported_protocol_versions: vec![PROTOCOL_VERSION],
        };
        let mut machine = SignalStateMachine::default();
        machine.begin_connect().expect("connect");
        let response = machine
            .build_hello_response(&challenge, &context, identity.as_ref(), now)
            .expect("hello response");
        assert_eq!(
            serde_json::to_value(&response).expect("json")["type"],
            "hello_response"
        );
        assert_eq!(machine.state(), SignalConnectionState::Authenticating);
        assert_ne!(machine.state(), SignalConnectionState::Online);

        machine
            .accept_hello_ok(&HelloOk {
                account_id: response.account_id,
                device_id: response.device_id,
                protocol_version: PROTOCOL_VERSION,
                connection_id: "connection-1".into(),
                client_supported_protocol_versions_hash: response
                    .client_supported_protocol_versions_hash,
                client_capabilities_hash: response.client_capabilities_hash,
                server_supported_protocol_versions: vec![PROTOCOL_VERSION],
                server_time_epoch_millis: now,
            })
            .expect("hello ok");
        assert_eq!(machine.state(), SignalConnectionState::Online);
    }

    #[test]
    fn real_websocket_upgrade_and_signed_handshake_reach_online() {
        let manager = identity_manager();
        let identity = manager.shared_current().expect("identity");
        let server = spawn_test_server(identity.public_key(), TestServerMode::StayOnline);
        let mut client = SignalWebSocketClient::with_options(test_options(0));

        client
            .connect(context(identity, &server.url))
            .expect("start authenticated websocket");
        wait_for_state(&client, SignalConnectionState::Online);
        assert!(!format!("{client:?}").contains("access-private"));

        client.disconnect();
        assert_eq!(client.state(), SignalConnectionState::Disconnected);
        assert!(!client.has_active_worker());
        server.wait_for_close();
    }

    #[test]
    fn real_websocket_delivers_typed_business_notification() {
        let manager = identity_manager();
        let identity = manager.shared_current().expect("identity");
        let server = spawn_test_server(
            identity.public_key(),
            TestServerMode::SendConnectionState("event-live"),
        );
        let mut client = SignalWebSocketClient::with_options(test_options(0));

        client
            .connect(context(identity, &server.url))
            .expect("start authenticated websocket");
        wait_for_state(&client, SignalConnectionState::Online);
        let notification = wait_for_notification(&client);
        let SignalNotification::ConnectionState(state) = notification else {
            panic!("expected connection state");
        };
        assert_eq!(state.event_id, "event-live");
        assert_eq!(state.session.session_id, "session-1");

        client.disconnect();
        server.wait_for_close();
    }

    #[test]
    fn reconnect_replaces_old_websocket_notification_ownership() {
        let manager = identity_manager();
        let identity = manager.shared_current().expect("identity");
        let old_server = spawn_test_server(
            identity.public_key(),
            TestServerMode::SendConnectionState("event-old"),
        );
        let new_server = spawn_test_server(
            identity.public_key(),
            TestServerMode::SendConnectionState("event-new"),
        );
        let mut client = SignalWebSocketClient::with_options(test_options(0));

        client
            .connect(context(identity.clone(), &old_server.url))
            .expect("connect old websocket");
        wait_for_state(&client, SignalConnectionState::Online);
        thread::sleep(Duration::from_millis(100));

        client
            .connect(context(identity, &new_server.url))
            .expect("replace websocket");
        old_server.wait_for_close();
        wait_for_state(&client, SignalConnectionState::Online);
        let notification = wait_for_notification(&client);
        let SignalNotification::ConnectionState(state) = notification else {
            panic!("expected new connection state");
        };
        assert_eq!(state.event_id, "event-new");
        assert_eq!(client.try_recv_notification(), Ok(None));

        client.disconnect();
        new_server.wait_for_close();
    }

    #[test]
    fn tampered_hello_ok_is_rejected_and_socket_is_released() {
        let manager = identity_manager();
        let identity = manager.shared_current().expect("identity");
        let server = spawn_test_server(identity.public_key(), TestServerMode::TamperHelloOk);
        let mut client = SignalWebSocketClient::with_options(test_options(0));

        client
            .connect(context(identity, &server.url))
            .expect("start websocket");
        wait_for_state(&client, SignalConnectionState::Failed);
        client.disconnect();
        assert!(!client.has_active_worker());
        server.wait_for_close();
    }

    #[test]
    fn server_disconnect_clears_online_after_bounded_reconnects() {
        let manager = identity_manager();
        let identity = manager.shared_current().expect("identity");
        let server = spawn_test_server(identity.public_key(), TestServerMode::CloseAfterHello);
        let mut client = SignalWebSocketClient::with_options(test_options(0));

        client
            .connect(context(identity, &server.url))
            .expect("start initial hello");
        wait_for_state(&client, SignalConnectionState::Failed);
        assert!(
            !client.has_active_worker()
                || client
                    .worker
                    .as_ref()
                    .is_some_and(|worker| worker.thread.is_finished())
        );
        client.disconnect();
        assert!(!client.has_active_worker());
        server.wait_for_close();
    }

    #[test]
    fn in_flight_handshake_can_be_cancelled_and_joined() {
        let manager = identity_manager();
        let identity = manager.shared_current().expect("identity");
        let server = spawn_test_server(identity.public_key(), TestServerMode::StallBeforeChallenge);
        let mut client = SignalWebSocketClient::with_options(test_options(0));

        client
            .connect(context(identity, &server.url))
            .expect("start websocket");
        server.wait_for_accept();
        client.disconnect();

        assert_eq!(client.state(), SignalConnectionState::Disconnected);
        assert!(!client.has_active_worker());
        server.wait_for_close();
    }

    #[test]
    fn mismatched_hello_ok_fails_closed() {
        let manager = identity_manager();
        let identity = manager.shared_current().expect("identity");
        let context = context(identity.clone(), "wss://signal.example.com/ws");
        let challenge = HelloChallenge {
            account_id: "account-1".into(),
            protocol_version: PROTOCOL_VERSION,
            server_nonce: URL_SAFE_NO_PAD.encode([3_u8; 32]),
            expires_at_epoch_millis: 31_000,
            server_supported_protocol_versions: vec![PROTOCOL_VERSION],
        };
        let mut machine = SignalStateMachine::default();
        machine.begin_connect().expect("connect");
        let response = machine
            .build_hello_response(&challenge, &context, identity.as_ref(), 1_000)
            .expect("response");
        let error = machine
            .accept_hello_ok(&HelloOk {
                account_id: response.account_id,
                device_id: response.device_id,
                protocol_version: PROTOCOL_VERSION,
                connection_id: "connection-1".into(),
                client_supported_protocol_versions_hash: "tampered".into(),
                client_capabilities_hash: response.client_capabilities_hash,
                server_supported_protocol_versions: vec![PROTOCOL_VERSION],
                server_time_epoch_millis: 1_000,
            })
            .expect_err("must reject mismatch");
        assert_eq!(error, SignalError::HelloMismatch);
        assert_eq!(machine.state(), SignalConnectionState::Failed);
    }

    #[test]
    fn signal_context_debug_redacts_access_token() {
        let manager = identity_manager();
        let context = context(
            manager.shared_current().expect("identity"),
            "wss://signal.example.com/ws",
        );
        let debug = format!("{context:?}");
        assert!(!debug.contains("access-private"));
        assert!(debug.contains("<redacted>"));
    }
}
