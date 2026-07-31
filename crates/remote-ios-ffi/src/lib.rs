use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use remote_core::{
    ControllerSession, ControllerSessionError, ControllerSessionEvent, ControllerSessionState,
    ControllerTransport, ControllerTransportError, ControllerTransportEvent, H264AccessUnit,
    InputDelivery, SecureSession,
};
use remote_protocol::{
    decode_header, encode_header, ChannelId, InputEvent, KeyConfirm, KeyframeRequest, MessageKind,
    SessionKdfContext, SessionPermissions, SessionRole, SignedKeyExchange, TransportPath,
    VideoFrameInfo, HEADER_LEN, PROTOCOL_VERSION,
};
use remote_runtime::{SessionHandshake, SessionHandshakeConfig, SessionHandshakeError};
use serde::{Deserialize, Serialize};

mod quic_transport;

pub use quic_transport::*;

const RESULT_OK: i32 = 0;
const RESULT_INVALID_ARGUMENT: i32 = 1;
const RESULT_INVALID_HANDLE: i32 = 2;
const RESULT_INVALID_STATE: i32 = 3;
const RESULT_INVALID_INPUT: i32 = 4;
const RESULT_TRANSPORT_ERROR: i32 = 5;
const RESULT_SECURITY_ERROR: i32 = 6;
const RESULT_PANIC: i32 = 255;

const COMMAND_START: i32 = 1;
const COMMAND_CLOSE: i32 = 3;
const COMMAND_SIGN_KEY_EXCHANGE: i32 = 4;
const COMMAND_SEND_KEY_EXCHANGE: i32 = 5;
const COMMAND_SEND_KEY_CONFIRM: i32 = 6;
const COMMAND_SEND_SECURE_PACKET: i32 = 7;

const EVENT_STATE: i32 = 1;
const EVENT_H264: i32 = 2;
const EVENT_RECOVERABLE_ERROR: i32 = 3;
const EVENT_FATAL_ERROR: i32 = 4;
const EVENT_VIDEO_FORMAT: i32 = 5;

const DELIVERY_REALTIME: i32 = 1;
const DELIVERY_RELIABLE: i32 = 2;

pub type RemoteControllerCommandCallback = extern "C" fn(
    context: u64,
    command_kind: i32,
    connection_epoch: u64,
    delivery: i32,
    payload: *const u8,
    payload_len: usize,
);

pub type RemoteControllerEventCallback = extern "C" fn(
    context: u64,
    event_kind: i32,
    state_or_error: i32,
    payload: *const u8,
    payload_len: usize,
    presentation_time_millis: i64,
    is_keyframe: bool,
    frame_id: u64,
);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RemoteControllerCallbacks {
    pub context: u64,
    pub on_command: Option<RemoteControllerCommandCallback>,
    pub on_event: Option<RemoteControllerEventCallback>,
}

#[derive(Default)]
struct CallbackGate {
    state: Mutex<CallbackGateState>,
    idle: Condvar,
}

#[derive(Default)]
struct CallbackGateState {
    closing: bool,
    active: usize,
}

impl CallbackGate {
    fn enter(self: &Arc<Self>) -> Option<CallbackLease> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.closing {
            return None;
        }
        state.active += 1;
        Some(CallbackLease {
            gate: Arc::clone(self),
        })
    }

    fn close_and_wait(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.closing = true;
        while state.active != 0 {
            state = self
                .idle
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }
}

struct CallbackLease {
    gate: Arc<CallbackGate>,
}

impl Drop for CallbackLease {
    fn drop(&mut self) {
        let mut state = self
            .gate
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.active = state.active.saturating_sub(1);
        if state.active == 0 {
            self.gate.idle.notify_all();
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HandshakeConfigWire {
    session_id: uuid::Uuid,
    account_id: String,
    controller_device_id: String,
    controlled_device_id: String,
    permissions: SessionPermissions,
    permissions_digest: Vec<u8>,
    protocol_version: u16,
    session_expires_at_epoch_millis: u64,
    selected_transport_path: TransportPath,
    selected_candidate_pair_id: String,
    relay_node_id: Option<String>,
    local_device_public_key: Vec<u8>,
    key_exchange_nonce: Vec<u8>,
    timestamp_epoch_millis: u64,
}

impl HandshakeConfigWire {
    fn into_runtime(self) -> Result<SessionHandshakeConfig, i32> {
        let local_device_public_key = fixed_bytes::<32>(&self.local_device_public_key)?;
        let key_exchange_nonce = fixed_bytes::<32>(&self.key_exchange_nonce)?;
        if self.controller_device_id.is_empty()
            || self.session_id.as_u128() == 0
            || self.protocol_version != PROTOCOL_VERSION
            || self.selected_candidate_pair_id.len() != 32
            || !self
                .selected_candidate_pair_id
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(RESULT_INVALID_ARGUMENT);
        }
        let selected_candidate_pair_id = u128::from_str_radix(&self.selected_candidate_pair_id, 16)
            .map_err(|_| RESULT_INVALID_ARGUMENT)?;
        Ok(SessionHandshakeConfig {
            context: SessionKdfContext {
                account_id: self.account_id,
                session_id: self.session_id.as_u128(),
                controller_device_id: self.controller_device_id.clone(),
                controlled_device_id: self.controlled_device_id,
                permissions_digest: fixed_bytes::<32>(&self.permissions_digest)?,
                protocol_version: self.protocol_version,
                session_expires_at_epoch_millis: self.session_expires_at_epoch_millis,
                selected_transport_path: self.selected_transport_path,
                selected_candidate_pair_id,
                relay_node_id: self.relay_node_id,
                key_exchange_transcript_hash: [0; 32],
            },
            permissions: self.permissions,
            local_role: SessionRole::Controller,
            local_device_id: self.controller_device_id,
            local_device_public_key,
            key_exchange_nonce,
            timestamp_epoch_millis: self.timestamp_epoch_millis,
        })
    }
}

#[derive(Default)]
struct SessionSecurity {
    handshake: Option<SessionHandshake>,
    secure_session: Option<SecureSession>,
    peer_device_id: Option<String>,
    expires_at_epoch_millis: Option<u64>,
    selected_transport_path: Option<TransportPath>,
}

struct CallbackTransport {
    callbacks: RemoteControllerCallbacks,
    callback_gate: Arc<CallbackGate>,
    security: Arc<Mutex<SessionSecurity>>,
}

impl ControllerTransport for CallbackTransport {
    fn start(&mut self, connection_epoch: u64) -> Result<(), ControllerTransportError> {
        *self.security.lock().map_err(|_| {
            ControllerTransportError::Unavailable("security state lock failed".to_owned())
        })? = SessionSecurity::default();
        emit_command(
            &self.callback_gate,
            self.callbacks,
            COMMAND_START,
            connection_epoch,
            0,
            &[],
        )
        .map_err(|_| ControllerTransportError::Unavailable("command callback closed".to_owned()))
    }

    fn send_input(
        &mut self,
        payload: &[u8],
        delivery: InputDelivery,
    ) -> Result<(), ControllerTransportError> {
        let (delivery_code, channel) = match delivery {
            InputDelivery::Realtime => (DELIVERY_REALTIME, ChannelId::InputRealtime),
            InputDelivery::Reliable => (DELIVERY_RELIABLE, ChannelId::InputReliable),
        };
        let packet = seal_packet(&self.security, MessageKind::InputEvent, channel, payload)
            .map_err(|_| {
                ControllerTransportError::Unavailable("secure session is not ready".to_owned())
            })?;
        emit_command(
            &self.callback_gate,
            self.callbacks,
            COMMAND_SEND_SECURE_PACKET,
            0,
            delivery_code,
            &packet,
        )
        .map_err(|_| ControllerTransportError::Unavailable("command callback closed".to_owned()))
    }

    fn close(&mut self) -> Result<(), ControllerTransportError> {
        emit_command(
            &self.callback_gate,
            self.callbacks,
            COMMAND_CLOSE,
            0,
            0,
            &[],
        )
        .map_err(|_| ControllerTransportError::Unavailable("command callback closed".to_owned()))
    }
}

struct FfiSession {
    controller: ControllerSession<CallbackTransport>,
    callbacks: RemoteControllerCallbacks,
    callback_gate: Arc<CallbackGate>,
    security: Arc<Mutex<SessionSecurity>>,
}

type SharedSession = Arc<Mutex<FfiSession>>;

fn sessions() -> &'static Mutex<HashMap<u64, SharedSession>> {
    static SESSIONS: OnceLock<Mutex<HashMap<u64, SharedSession>>> = OnceLock::new();
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_handle() -> u64 {
    static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
    NEXT_HANDLE.fetch_add(1, Ordering::Relaxed).max(1)
}

fn lookup(handle: u64) -> Result<SharedSession, i32> {
    if handle == 0 {
        return Err(RESULT_INVALID_HANDLE);
    }
    sessions()
        .lock()
        .map_err(|_| RESULT_PANIC)?
        .get(&handle)
        .cloned()
        .ok_or(RESULT_INVALID_HANDLE)
}

fn run_session(
    handle: u64,
    operation: impl FnOnce(
        &mut ControllerSession<CallbackTransport>,
    ) -> Result<(), ControllerSessionError>,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let shared = lookup(handle)?;
        let mut session = shared.lock().map_err(|_| RESULT_PANIC)?;
        let result = operation(&mut session.controller).map_err(map_session_error);
        let events = drain_events(&mut session.controller);
        let callbacks = session.callbacks;
        let callback_gate = Arc::clone(&session.callback_gate);
        drop(session);
        emit_events(&callback_gate, callbacks, events);
        result
    }));
    match result {
        Ok(Ok(())) => RESULT_OK,
        Ok(Err(code)) => code,
        Err(_) => RESULT_PANIC,
    }
}

fn drain_events(
    controller: &mut ControllerSession<CallbackTransport>,
) -> Vec<ControllerSessionEvent> {
    let mut events = Vec::new();
    while let Some(event) = controller.poll_event() {
        events.push(event);
    }
    events
}

fn emit_events(
    callback_gate: &Arc<CallbackGate>,
    callbacks: RemoteControllerCallbacks,
    events: Vec<ControllerSessionEvent>,
) {
    let Some(_lease) = callback_gate.enter() else {
        return;
    };
    emit_events_with_lease(callbacks, events);
}

fn emit_events_with_lease(
    callbacks: RemoteControllerCallbacks,
    events: Vec<ControllerSessionEvent>,
) {
    let Some(callback) = callbacks.on_event else {
        return;
    };
    for event in events {
        match event {
            ControllerSessionEvent::StateChanged(state) => callback(
                callbacks.context,
                EVENT_STATE,
                state_code(state),
                std::ptr::null(),
                0,
                0,
                false,
                0,
            ),
            ControllerSessionEvent::H264(access_unit) => callback(
                callbacks.context,
                EVENT_H264,
                0,
                access_unit.data.as_ptr(),
                access_unit.data.len(),
                access_unit.presentation_time_millis,
                access_unit.is_keyframe,
                access_unit.frame_id,
            ),
            ControllerSessionEvent::RecoverableTransportError(message) => callback(
                callbacks.context,
                EVENT_RECOVERABLE_ERROR,
                0,
                message.as_ptr(),
                message.len(),
                0,
                false,
                0,
            ),
            ControllerSessionEvent::FatalTransportError(message) => callback(
                callbacks.context,
                EVENT_FATAL_ERROR,
                0,
                message.as_ptr(),
                message.len(),
                0,
                false,
                0,
            ),
        }
    }
}

fn flatten_ffi_result(result: Result<Result<(), i32>, Box<dyn std::any::Any + Send>>) -> i32 {
    match result {
        Ok(Ok(())) => RESULT_OK,
        Ok(Err(code)) => code,
        Err(_) => RESULT_PANIC,
    }
}

const fn state_code(state: ControllerSessionState) -> i32 {
    match state {
        ControllerSessionState::Idle => 0,
        ControllerSessionState::Connecting => 1,
        ControllerSessionState::Streaming => 2,
        ControllerSessionState::Reconnecting => 3,
        ControllerSessionState::Closed => 4,
    }
}

fn map_session_error(error: ControllerSessionError) -> i32 {
    match error {
        ControllerSessionError::InvalidState => RESULT_INVALID_STATE,
        ControllerSessionError::InvalidInput
        | ControllerSessionError::InputSessionMismatch
        | ControllerSessionError::InvalidAccessUnit
        | ControllerSessionError::Serialization => RESULT_INVALID_INPUT,
        ControllerSessionError::Transport(_) => RESULT_TRANSPORT_ERROR,
    }
}

fn map_handshake_error(_error: SessionHandshakeError) -> i32 {
    RESULT_SECURITY_ERROR
}

fn fixed_bytes<const N: usize>(bytes: &[u8]) -> Result<[u8; N], i32> {
    bytes.try_into().map_err(|_| RESULT_INVALID_ARGUMENT)
}

fn now_epoch_millis() -> Result<u64, i32> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RESULT_SECURITY_ERROR)?
        .as_millis();
    u64::try_from(millis).map_err(|_| RESULT_SECURITY_ERROR)
}

fn ensure_session_active(security: &mut SessionSecurity, now_epoch_millis: u64) -> Result<(), i32> {
    let expires_at = security
        .expires_at_epoch_millis
        .ok_or(RESULT_INVALID_STATE)?;
    if now_epoch_millis >= expires_at {
        security.handshake = None;
        if let Some(secure) = security.secure_session.as_mut() {
            secure.invalidate_for_reboot();
        }
        return Err(RESULT_SECURITY_ERROR);
    }
    Ok(())
}

fn emit_command(
    callback_gate: &Arc<CallbackGate>,
    callbacks: RemoteControllerCallbacks,
    command_kind: i32,
    connection_epoch: u64,
    delivery: i32,
    payload: &[u8],
) -> Result<(), i32> {
    let callback = callbacks.on_command.ok_or(RESULT_TRANSPORT_ERROR)?;
    let _lease = callback_gate.enter().ok_or(RESULT_INVALID_HANDLE)?;
    callback(
        callbacks.context,
        command_kind,
        connection_epoch,
        delivery,
        payload.as_ptr(),
        payload.len(),
    );
    Ok(())
}

fn seal_packet(
    security: &Arc<Mutex<SessionSecurity>>,
    kind: MessageKind,
    channel: ChannelId,
    plaintext: &[u8],
) -> Result<Vec<u8>, i32> {
    let mut security = security.lock().map_err(|_| RESULT_PANIC)?;
    ensure_session_active(&mut security, now_epoch_millis()?)?;
    let secure = security
        .secure_session
        .as_mut()
        .ok_or(RESULT_INVALID_STATE)?;
    let (header, ciphertext) = secure
        .seal(kind, channel, 0, plaintext)
        .map_err(|_| RESULT_SECURITY_ERROR)?;
    let mut packet = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    packet.extend_from_slice(&encode_header(header));
    packet.extend_from_slice(&ciphertext);
    Ok(packet)
}

fn open_packet(
    secure: &mut SecureSession,
    packet: &[u8],
    expected_kind: MessageKind,
) -> Result<Vec<u8>, i32> {
    if packet.len() < HEADER_LEN {
        return Err(RESULT_INVALID_INPUT);
    }
    let header = decode_header(&packet[..HEADER_LEN]).map_err(|_| RESULT_INVALID_INPUT)?;
    let ciphertext = &packet[HEADER_LEN..];
    if header.kind != expected_kind
        || usize::try_from(header.payload_len).ok() != Some(ciphertext.len())
    {
        return Err(RESULT_INVALID_INPUT);
    }
    secure
        .open(header, ciphertext)
        .map_err(|_| RESULT_SECURITY_ERROR)
}

fn read_bytes<'a>(pointer: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if len == 0 {
        return Ok(&[]);
    }
    if pointer.is_null() {
        return Err(RESULT_INVALID_ARGUMENT);
    }
    // SAFETY: callers guarantee that `pointer` references `len` readable bytes for this call.
    Ok(unsafe { slice::from_raw_parts(pointer, len) })
}

#[no_mangle]
pub extern "C" fn remote_controller_session_create(
    session_id_high: u64,
    session_id_low: u64,
    callbacks: RemoteControllerCallbacks,
) -> u64 {
    catch_unwind(AssertUnwindSafe(|| {
        if callbacks.on_command.is_none() || callbacks.on_event.is_none() {
            return 0;
        }
        let session_id = uuid::Uuid::from_u64_pair(session_id_high, session_id_low);
        let security = Arc::new(Mutex::new(SessionSecurity::default()));
        let callback_gate = Arc::new(CallbackGate::default());
        let transport = CallbackTransport {
            callbacks,
            callback_gate: Arc::clone(&callback_gate),
            security: security.clone(),
        };
        let ffi_session = FfiSession {
            controller: ControllerSession::new(session_id, transport),
            callbacks,
            callback_gate,
            security,
        };
        let handle = next_handle();
        match sessions().lock() {
            Ok(mut sessions) => {
                sessions.insert(handle, Arc::new(Mutex::new(ffi_session)));
                handle
            }
            Err(_) => 0,
        }
    }))
    .unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn remote_controller_session_connect(handle: u64) -> i32 {
    run_session(handle, |controller| controller.connect().map(|_| ()))
}

#[no_mangle]
pub extern "C" fn remote_controller_session_configure_handshake_json(
    handle: u64,
    payload: *const u8,
    payload_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let config = read_bytes(payload, payload_len)
            .and_then(|bytes| {
                serde_json::from_slice::<HandshakeConfigWire>(bytes)
                    .map_err(|_| RESULT_INVALID_ARGUMENT)
            })?
            .into_runtime()?;
        let shared = lookup(handle)?;
        let session = shared.lock().map_err(|_| RESULT_PANIC)?;
        if session.controller.session_id().as_u128() != config.context.session_id
            || !matches!(
                session.controller.state(),
                ControllerSessionState::Connecting | ControllerSessionState::Reconnecting
            )
        {
            return Err(RESULT_INVALID_STATE);
        }
        let mut security = session.security.lock().map_err(|_| RESULT_PANIC)?;
        if security.handshake.is_some() || security.secure_session.is_some() {
            return Err(RESULT_INVALID_STATE);
        }
        let expires_at_epoch_millis = config.context.session_expires_at_epoch_millis;
        let selected_transport_path = config.context.selected_transport_path;
        let handshake = SessionHandshake::new(config).map_err(map_handshake_error)?;
        let digest = handshake
            .local_signature_digest()
            .map_err(map_handshake_error)?;
        security.handshake = Some(handshake);
        security.expires_at_epoch_millis = Some(expires_at_epoch_millis);
        security.selected_transport_path = Some(selected_transport_path);
        let callbacks = session.callbacks;
        let callback_gate = Arc::clone(&session.callback_gate);
        drop(security);
        drop(session);
        emit_command(
            &callback_gate,
            callbacks,
            COMMAND_SIGN_KEY_EXCHANGE,
            0,
            0,
            &digest,
        )
    }));
    flatten_ffi_result(result)
}

#[no_mangle]
pub extern "C" fn remote_controller_session_submit_key_exchange_signature(
    handle: u64,
    signature: *const u8,
    signature_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let signature = read_bytes(signature, signature_len)?;
        let shared = lookup(handle)?;
        let session = shared.lock().map_err(|_| RESULT_PANIC)?;
        let mut security = session.security.lock().map_err(|_| RESULT_PANIC)?;
        let message = security
            .handshake
            .as_mut()
            .ok_or(RESULT_INVALID_STATE)?
            .set_local_signature(signature.to_vec())
            .map_err(map_handshake_error)?;
        let payload = serde_json::to_vec(message).map_err(|_| RESULT_PANIC)?;
        let callbacks = session.callbacks;
        let callback_gate = Arc::clone(&session.callback_gate);
        drop(security);
        drop(session);
        emit_command(
            &callback_gate,
            callbacks,
            COMMAND_SEND_KEY_EXCHANGE,
            0,
            DELIVERY_RELIABLE,
            &payload,
        )
    }));
    flatten_ffi_result(result)
}

#[no_mangle]
pub extern "C" fn remote_controller_session_receive_peer_key_exchange_json(
    handle: u64,
    payload: *const u8,
    payload_len: usize,
    peer_device_public_key: *const u8,
    peer_device_public_key_len: usize,
    now_epoch_millis: u64,
    key_confirm_timestamp_epoch_millis: u64,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let message = read_bytes(payload, payload_len).and_then(|bytes| {
            serde_json::from_slice::<SignedKeyExchange>(bytes).map_err(|_| RESULT_INVALID_INPUT)
        })?;
        let peer_public_key = fixed_bytes::<32>(read_bytes(
            peer_device_public_key,
            peer_device_public_key_len,
        )?)?;
        let shared = lookup(handle)?;
        let session = shared.lock().map_err(|_| RESULT_PANIC)?;
        let mut security = session.security.lock().map_err(|_| RESULT_PANIC)?;
        ensure_session_active(&mut security, now_epoch_millis)?;
        ensure_session_active(&mut security, key_confirm_timestamp_epoch_millis)?;
        let mut handshake = security.handshake.take().ok_or(RESULT_INVALID_STATE)?;
        if let Err(error) =
            handshake.verify_peer_message(message.clone(), &peer_public_key, now_epoch_millis)
        {
            security.handshake = Some(handshake);
            return Err(map_handshake_error(error));
        }
        let peer_device_id = message.payload.device_id;
        let ready = handshake
            .finish(key_confirm_timestamp_epoch_millis)
            .map_err(map_handshake_error)?;
        let confirm = serde_json::to_vec(&ready.local_key_confirm).map_err(|_| RESULT_PANIC)?;
        security.secure_session = Some(ready.secure_session);
        security.peer_device_id = Some(peer_device_id);
        let callbacks = session.callbacks;
        let callback_gate = Arc::clone(&session.callback_gate);
        drop(security);
        drop(session);
        emit_command(
            &callback_gate,
            callbacks,
            COMMAND_SEND_KEY_CONFIRM,
            0,
            DELIVERY_RELIABLE,
            &confirm,
        )
    }));
    flatten_ffi_result(result)
}

#[no_mangle]
pub extern "C" fn remote_controller_session_receive_peer_key_confirm_json(
    handle: u64,
    payload: *const u8,
    payload_len: usize,
    now_epoch_millis: u64,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let confirm = read_bytes(payload, payload_len).and_then(|bytes| {
            serde_json::from_slice::<KeyConfirm>(bytes).map_err(|_| RESULT_INVALID_INPUT)
        })?;
        let shared = lookup(handle)?;
        let mut session = shared.lock().map_err(|_| RESULT_PANIC)?;
        {
            let mut security = session.security.lock().map_err(|_| RESULT_PANIC)?;
            ensure_session_active(&mut security, now_epoch_millis)?;
            let expected_peer_device_id = security
                .peer_device_id
                .clone()
                .ok_or(RESULT_INVALID_STATE)?;
            security
                .secure_session
                .as_mut()
                .ok_or(RESULT_INVALID_STATE)?
                .verify_peer_key_confirm(&confirm, &expected_peer_device_id, now_epoch_millis)
                .map_err(|_| RESULT_SECURITY_ERROR)?;
        }
        let epoch = session.controller.connection_epoch();
        session
            .controller
            .handle_transport_event(epoch, ControllerTransportEvent::Connected)
            .map_err(map_session_error)?;
        let events = drain_events(&mut session.controller);
        let callbacks = session.callbacks;
        let callback_gate = Arc::clone(&session.callback_gate);
        drop(session);
        emit_events(&callback_gate, callbacks, events);
        Ok(())
    }));
    flatten_ffi_result(result)
}

#[no_mangle]
pub extern "C" fn remote_controller_session_send_input_json(
    handle: u64,
    payload: *const u8,
    payload_len: usize,
) -> i32 {
    let input = match read_bytes(payload, payload_len).and_then(|bytes| {
        serde_json::from_slice::<InputEvent>(bytes).map_err(|_| RESULT_INVALID_INPUT)
    }) {
        Ok(input) => input,
        Err(code) => return code,
    };
    run_session(handle, |controller| controller.send_input(&input))
}

#[no_mangle]
pub extern "C" fn remote_controller_session_send_keyframe_request_json(
    handle: u64,
    payload: *const u8,
    payload_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let payload = read_bytes(payload, payload_len)?;
        let request: KeyframeRequest =
            serde_json::from_slice(payload).map_err(|_| RESULT_INVALID_INPUT)?;
        let shared = lookup(handle)?;
        let session = shared.lock().map_err(|_| RESULT_PANIC)?;
        if session.controller.state() != ControllerSessionState::Streaming
            || request.session_id != session.controller.session_id().as_u128()
        {
            return Err(RESULT_INVALID_STATE);
        }
        let packet = seal_packet(
            &session.security,
            MessageKind::KeyframeRequest,
            ChannelId::MediaControl,
            payload,
        )?;
        let callbacks = session.callbacks;
        let callback_gate = Arc::clone(&session.callback_gate);
        drop(session);
        emit_command(
            &callback_gate,
            callbacks,
            COMMAND_SEND_SECURE_PACKET,
            0,
            DELIVERY_RELIABLE,
            &packet,
        )
    }));
    flatten_ffi_result(result)
}

#[no_mangle]
pub extern "C" fn remote_controller_session_transport_event(
    handle: u64,
    connection_epoch: u64,
    event_kind: i32,
    reason: *const u8,
    reason_len: usize,
) -> i32 {
    let reason = match read_bytes(reason, reason_len).and_then(|bytes| {
        std::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| RESULT_INVALID_ARGUMENT)
    }) {
        Ok(reason) => reason,
        Err(code) => return code,
    };
    let event = match event_kind {
        1 => return RESULT_SECURITY_ERROR,
        2 => ControllerTransportEvent::Disconnected {
            recoverable: true,
            reason,
        },
        3 => ControllerTransportEvent::Disconnected {
            recoverable: false,
            reason,
        },
        4 => ControllerTransportEvent::Closed,
        _ => return RESULT_INVALID_ARGUMENT,
    };
    run_session(handle, |controller| {
        controller.handle_transport_event(connection_epoch, event)
    })
}

#[derive(Serialize)]
struct VideoFormatEvent<'a> {
    display_id: &'a str,
    width: u32,
    height: u32,
}

#[no_mangle]
pub extern "C" fn remote_controller_session_receive_secure_video_frame(
    handle: u64,
    info_packet: *const u8,
    info_packet_len: usize,
    data_packet: *const u8,
    data_packet_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let info_packet = read_bytes(info_packet, info_packet_len)?;
        let data_packet = read_bytes(data_packet, data_packet_len)?;
        let shared = lookup(handle)?;
        let mut session = shared.lock().map_err(|_| RESULT_PANIC)?;
        let (info, annex_b) = {
            let mut security = session.security.lock().map_err(|_| RESULT_PANIC)?;
            ensure_session_active(&mut security, now_epoch_millis()?)?;
            let secure = security
                .secure_session
                .as_mut()
                .ok_or(RESULT_INVALID_STATE)?;
            let info_json = open_packet(secure, info_packet, MessageKind::VideoFrameInfo)?;
            let annex_b = open_packet(secure, data_packet, MessageKind::VideoFrameData)?;
            let info: VideoFrameInfo =
                serde_json::from_slice(&info_json).map_err(|_| RESULT_INVALID_INPUT)?;
            if info.session_id != session.controller.session_id().as_u128()
                || usize::try_from(info.frame_bytes_len).ok() != Some(annex_b.len())
                || annex_b.is_empty()
            {
                return Err(RESULT_INVALID_INPUT);
            }
            (info, annex_b)
        };
        let epoch = session.controller.connection_epoch();
        session
            .controller
            .handle_transport_event(
                epoch,
                ControllerTransportEvent::H264(H264AccessUnit {
                    data: annex_b,
                    presentation_time_millis: i64::try_from(info.pts_millis)
                        .map_err(|_| RESULT_INVALID_INPUT)?,
                    is_keyframe: info.is_keyframe,
                    frame_id: info.frame_id,
                }),
            )
            .map_err(map_session_error)?;
        let format = serde_json::to_vec(&VideoFormatEvent {
            display_id: &info.display_id,
            width: info.width,
            height: info.height,
        })
        .map_err(|_| RESULT_PANIC)?;
        let callbacks = session.callbacks;
        let callback_gate = Arc::clone(&session.callback_gate);
        let events = drain_events(&mut session.controller);
        drop(session);
        let _lease = callback_gate.enter().ok_or(RESULT_INVALID_HANDLE)?;
        let callback = callbacks.on_event.ok_or(RESULT_TRANSPORT_ERROR)?;
        callback(
            callbacks.context,
            EVENT_VIDEO_FORMAT,
            0,
            format.as_ptr(),
            format.len(),
            0,
            false,
            0,
        );
        emit_events_with_lease(callbacks, events);
        Ok(())
    }));
    flatten_ffi_result(result)
}

#[no_mangle]
pub extern "C" fn remote_controller_session_close(handle: u64) -> i32 {
    run_session(handle, ControllerSession::close)
}

#[no_mangle]
pub extern "C" fn remote_controller_session_destroy(handle: u64) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let shared = sessions()
            .lock()
            .map_err(|_| RESULT_PANIC)?
            .remove(&handle)
            .ok_or(RESULT_INVALID_HANDLE)?;
        let callback_gate = {
            let session = shared.lock().map_err(|_| RESULT_PANIC)?;
            Arc::clone(&session.callback_gate)
        };
        callback_gate.close_and_wait();
        let mut session = shared.lock().map_err(|_| RESULT_PANIC)?;
        let result = session.controller.close().map_err(map_session_error);
        let _ = drain_events(&mut session.controller);
        result
    }));
    match result {
        Ok(Ok(())) => RESULT_OK,
        Ok(Err(code)) => code,
        Err(_) => RESULT_PANIC,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, OnceLock};

    use remote_crypto::{permissions_digest, DeviceKeyPair};
    use remote_protocol::{MediaQualityReason, VideoCodec, PROTOCOL_VERSION};

    use super::*;

    type CallbackLogEntry = (i32, i32, Vec<u8>);
    type CallbackLog = Mutex<Vec<CallbackLogEntry>>;

    fn callback_log() -> &'static CallbackLog {
        static LOG: OnceLock<CallbackLog> = OnceLock::new();
        LOG.get_or_init(|| Mutex::new(Vec::new()))
    }

    extern "C" fn command_callback(
        _context: u64,
        command_kind: i32,
        _connection_epoch: u64,
        delivery: i32,
        payload: *const u8,
        payload_len: usize,
    ) {
        let payload = read_bytes(payload, payload_len)
            .expect("callback payload")
            .to_vec();
        callback_log()
            .lock()
            .expect("log")
            .push((100 + command_kind, delivery, payload));
    }

    extern "C" fn event_callback(
        _context: u64,
        event_kind: i32,
        state_or_error: i32,
        payload: *const u8,
        payload_len: usize,
        _presentation_time_millis: i64,
        _is_keyframe: bool,
        _frame_id: u64,
    ) {
        let payload = read_bytes(payload, payload_len)
            .expect("callback payload")
            .to_vec();
        callback_log()
            .lock()
            .expect("log")
            .push((event_kind, state_or_error, payload));
    }

    extern "C" fn quic_state_callback(
        _context: u64,
        _transport_handle: u64,
        _state: i32,
        _detail: *const u8,
        _detail_len: usize,
    ) {
    }

    extern "C" fn quic_packet_callback(
        _context: u64,
        _transport_handle: u64,
        _delivery: i32,
        _channel_id: u16,
        _packet_group_id: u64,
        _packet_index: u32,
        _packet_count: u32,
        _packet: *const u8,
        _packet_len: usize,
    ) {
    }

    extern "C" fn quic_disconnect_callback(
        _context: u64,
        _transport_handle: u64,
        _result: i32,
        _reason: *const u8,
        _reason_len: usize,
    ) {
    }

    extern "C" fn quic_closed_callback(_context: u64, _transport_handle: u64) {}

    fn quic_callbacks() -> RemoteQuicCallbacks {
        RemoteQuicCallbacks {
            context: 0,
            on_state: Some(quic_state_callback),
            on_packet: Some(quic_packet_callback),
            on_disconnect: Some(quic_disconnect_callback),
            on_closed: Some(quic_closed_callback),
        }
    }

    fn command_payload(command_kind: i32) -> Vec<u8> {
        callback_log()
            .lock()
            .expect("log")
            .iter()
            .rev()
            .find(|entry| entry.0 == 100 + command_kind)
            .expect("command")
            .2
            .clone()
    }

    fn packet(header: remote_protocol::MessageHeader, ciphertext: Vec<u8>) -> Vec<u8> {
        let mut packet = encode_header(header).to_vec();
        packet.extend_from_slice(&ciphertext);
        packet
    }

    #[test]
    fn ffi_handshake_seals_input_and_opens_secure_video() {
        callback_log().lock().expect("log").clear();
        let controller_key = DeviceKeyPair::from_private_key([7; 32]);
        let controlled_key = DeviceKeyPair::from_private_key([8; 32]);
        let permissions = SessionPermissions {
            remote_desktop: true,
            input_control: true,
            require_prompt: false,
            ..SessionPermissions::default()
        };
        let digest = permissions_digest(permissions).expect("permissions digest");
        let base_now = now_epoch_millis().expect("current time");
        let handle = remote_controller_session_create(
            0,
            1,
            RemoteControllerCallbacks {
                context: 9,
                on_command: Some(command_callback),
                on_event: Some(event_callback),
            },
        );
        assert_ne!(handle, 0);
        assert_eq!(remote_controller_session_connect(handle), RESULT_OK);
        assert_eq!(
            remote_controller_quic_transport_create(handle, quic_callbacks()),
            0,
            "QUIC must remain unavailable before peer key_confirm"
        );
        assert_eq!(
            remote_controller_session_transport_event(handle, 1, 1, std::ptr::null(), 0),
            RESULT_SECURITY_ERROR
        );

        let config = serde_json::json!({
            "session_id": "00000000-0000-0000-0000-000000000001",
            "account_id": "account",
            "controller_device_id": "ios-1",
            "controlled_device_id": "ubuntu-1",
            "permissions": permissions,
            "permissions_digest": digest,
            "protocol_version": PROTOCOL_VERSION,
            "session_expires_at_epoch_millis": base_now + 60_000,
            "selected_transport_path": "lan_direct",
            "selected_candidate_pair_id": "00000000000000000000000000000002",
            "relay_node_id": null,
            "local_device_public_key": controller_key.public_key,
            "key_exchange_nonce": vec![3; 32],
            "timestamp_epoch_millis": base_now
        })
        .to_string();
        assert_eq!(
            remote_controller_session_configure_handshake_json(
                handle,
                config.as_ptr(),
                config.len()
            ),
            RESULT_OK
        );
        let signature_digest = command_payload(COMMAND_SIGN_KEY_EXCHANGE);
        assert_eq!(signature_digest.len(), 32);
        let signature = controller_key.sign_digest(
            &signature_digest
                .as_slice()
                .try_into()
                .expect("signature digest"),
        );
        assert_eq!(
            remote_controller_session_submit_key_exchange_signature(
                handle,
                signature.as_ptr(),
                signature.len()
            ),
            RESULT_OK
        );
        let controller_message: SignedKeyExchange =
            serde_json::from_slice(&command_payload(COMMAND_SEND_KEY_EXCHANGE))
                .expect("controller key exchange");

        let controlled_config = SessionHandshakeConfig {
            context: SessionKdfContext {
                account_id: "account".to_owned(),
                session_id: 1,
                controller_device_id: "ios-1".to_owned(),
                controlled_device_id: "ubuntu-1".to_owned(),
                permissions_digest: digest,
                protocol_version: PROTOCOL_VERSION,
                session_expires_at_epoch_millis: base_now + 60_000,
                selected_transport_path: TransportPath::LanDirect,
                selected_candidate_pair_id: 2,
                relay_node_id: None,
                key_exchange_transcript_hash: [0; 32],
            },
            permissions,
            local_role: SessionRole::Controlled,
            local_device_id: "ubuntu-1".to_owned(),
            local_device_public_key: controlled_key.public_key,
            key_exchange_nonce: [4; 32],
            timestamp_epoch_millis: base_now,
        };
        let mut controlled =
            SessionHandshake::new(controlled_config).expect("controlled handshake");
        let controlled_digest = controlled
            .local_signature_digest()
            .expect("controlled signature digest");
        let controlled_message = controlled
            .set_local_signature(controlled_key.sign_digest(&controlled_digest).to_vec())
            .expect("controlled signature")
            .clone();
        controlled
            .verify_peer_message(controller_message, &controller_key.public_key, base_now + 1)
            .expect("verify controller");
        let controlled_message_json =
            serde_json::to_vec(&controlled_message).expect("controlled message json");
        assert_eq!(
            remote_controller_session_receive_peer_key_exchange_json(
                handle,
                controlled_message_json.as_ptr(),
                controlled_message_json.len(),
                controlled_key.public_key.as_ptr(),
                controlled_key.public_key.len(),
                base_now + 1,
                base_now + 2,
            ),
            RESULT_OK
        );
        let controller_confirm: KeyConfirm =
            serde_json::from_slice(&command_payload(COMMAND_SEND_KEY_CONFIRM))
                .expect("controller confirm");
        let mut controlled = controlled.finish(base_now + 2).expect("controlled ready");
        controlled
            .secure_session
            .verify_peer_key_confirm(&controller_confirm, "ios-1", base_now + 3)
            .expect("verify controller confirm");
        let controlled_confirm_json =
            serde_json::to_vec(&controlled.local_key_confirm).expect("controlled confirm json");
        assert_eq!(
            remote_controller_session_receive_peer_key_confirm_json(
                handle,
                controlled_confirm_json.as_ptr(),
                controlled_confirm_json.len(),
                base_now + 3,
            ),
            RESULT_OK
        );
        let quic_handle = remote_controller_quic_transport_create(handle, quic_callbacks());
        assert_ne!(
            quic_handle, 0,
            "QUIC becomes available after peer key_confirm"
        );
        assert_eq!(
            remote_controller_quic_transport_destroy(quic_handle),
            RESULT_OK
        );

        let input = serde_json::json!({
            "session_id": "00000000-0000-0000-0000-000000000001",
            "event_id": "00000000-0000-0000-0000-000000000002",
            "display_id": "primary",
            "input_kind": "mouse_move",
            "x_norm": 0.5,
            "y_norm": 0.25,
            "timestamp_epoch_millis": 1
        })
        .to_string();
        assert_eq!(
            remote_controller_session_send_input_json(handle, input.as_ptr(), input.len()),
            RESULT_OK
        );
        let encrypted_input = command_payload(COMMAND_SEND_SECURE_PACKET);
        let header = decode_header(&encrypted_input[..HEADER_LEN]).expect("input header");
        assert_eq!(header.kind, MessageKind::InputEvent);
        let decrypted_input = controlled
            .secure_session
            .open(header, &encrypted_input[HEADER_LEN..])
            .expect("decrypt input");
        assert_eq!(
            serde_json::from_slice::<InputEvent>(&decrypted_input).expect("decrypted input json"),
            serde_json::from_str::<InputEvent>(&input).expect("original input json")
        );

        let frame = vec![0, 0, 0, 1, 0x65, 1];
        let info = VideoFrameInfo {
            session_id: 1,
            display_id: "primary".to_owned(),
            frame_id: 7,
            codec: VideoCodec::H264,
            width: 1_920,
            height: 1_080,
            stride: 0,
            pixel_format: "annex_b".to_owned(),
            color_space: "bt709".to_owned(),
            rotation: 0,
            is_keyframe: true,
            pts_millis: 5,
            frame_bytes_len: frame.len() as u32,
        };
        let info_json = serde_json::to_vec(&info).expect("video info");
        let (info_header, info_ciphertext) = controlled
            .secure_session
            .seal(MessageKind::VideoFrameInfo, ChannelId::Video, 0, &info_json)
            .expect("seal info");
        let (data_header, data_ciphertext) = controlled
            .secure_session
            .seal(MessageKind::VideoFrameData, ChannelId::Video, 0, &frame)
            .expect("seal data");
        let info_packet = packet(info_header, info_ciphertext);
        let data_packet = packet(data_header, data_ciphertext);
        assert_eq!(
            remote_controller_session_receive_secure_video_frame(
                handle,
                info_packet.as_ptr(),
                info_packet.len(),
                data_packet.as_ptr(),
                data_packet.len(),
            ),
            RESULT_OK
        );

        let keyframe = KeyframeRequest {
            session_id: 1,
            display_id: "primary".to_owned(),
            reason: MediaQualityReason::KeyframeLoss,
            last_received_frame_id: 7,
            timestamp_epoch_millis: 6,
        };
        let keyframe_json = serde_json::to_vec(&keyframe).expect("keyframe json");
        assert_eq!(
            remote_controller_session_send_keyframe_request_json(
                handle,
                keyframe_json.as_ptr(),
                keyframe_json.len(),
            ),
            RESULT_OK
        );
        let encrypted_keyframe = command_payload(COMMAND_SEND_SECURE_PACKET);
        let header = decode_header(&encrypted_keyframe[..HEADER_LEN]).expect("keyframe header");
        assert_eq!(header.kind, MessageKind::KeyframeRequest);
        assert_eq!(
            controlled
                .secure_session
                .open(header, &encrypted_keyframe[HEADER_LEN..])
                .expect("decrypt keyframe"),
            keyframe_json
        );

        assert_eq!(remote_controller_session_close(handle), RESULT_OK);
        assert_eq!(remote_controller_session_close(handle), RESULT_OK);
        assert_eq!(remote_controller_session_destroy(handle), RESULT_OK);
        assert_eq!(
            remote_controller_session_connect(handle),
            RESULT_INVALID_HANDLE
        );

        let log = callback_log().lock().expect("log");
        assert!(log.iter().any(|entry| entry.0 == 101));
        assert!(log
            .iter()
            .any(|entry| entry.0 == EVENT_H264 && entry.2 == frame));
        assert!(log.iter().any(|entry| {
            entry.0 == EVENT_VIDEO_FORMAT
                && serde_json::from_slice::<serde_json::Value>(&entry.2)
                    .ok()
                    .is_some_and(|value| value["width"] == 1_920 && value["height"] == 1_080)
        }));
        assert_eq!(log.iter().filter(|entry| entry.0 == 103).count(), 1);
        assert_eq!(
            log.iter()
                .filter(|entry| entry.0 == EVENT_STATE && entry.1 == 4)
                .count(),
            1
        );
    }

    #[test]
    fn c_header_declares_all_secure_session_entry_points() {
        let header = include_str!("../include/remote_ios_ffi.h");
        let native_bridge_header =
            include_str!("../../../apps/ios/NativeBridge/include/remote_ios_ffi.h");
        assert_eq!(header, native_bridge_header, "iOS bridge header drifted");
        for symbol in [
            "REMOTE_CONTROLLER_COMMAND_SIGN_KEY_EXCHANGE",
            "REMOTE_CONTROLLER_COMMAND_SEND_KEY_EXCHANGE",
            "REMOTE_CONTROLLER_COMMAND_SEND_KEY_CONFIRM",
            "REMOTE_CONTROLLER_COMMAND_SEND_SECURE_PACKET",
            "remote_controller_session_configure_handshake_json",
            "remote_controller_session_submit_key_exchange_signature",
            "remote_controller_session_receive_peer_key_exchange_json",
            "remote_controller_session_receive_peer_key_confirm_json",
            "remote_controller_session_send_keyframe_request_json",
            "remote_controller_session_receive_secure_video_frame",
            "RemoteQuicCallbacks",
            "remote_controller_quic_transport_create",
            "remote_controller_quic_transport_bind",
            "remote_controller_quic_transport_bind_socket",
            "remote_controller_quic_transport_connect",
            "remote_controller_quic_transport_send_reliable",
            "remote_controller_quic_transport_send_realtime",
            "remote_controller_quic_transport_close",
            "remote_controller_quic_transport_destroy",
        ] {
            assert!(header.contains(symbol), "missing C declaration: {symbol}");
        }
    }

    #[test]
    fn callback_gate_waits_for_in_flight_callback_before_destroy() {
        let gate = Arc::new(CallbackGate::default());
        let lease = gate.enter().expect("callback lease");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let closing_gate = Arc::clone(&gate);
        let closer = std::thread::spawn(move || {
            closing_gate.close_and_wait();
            done_tx.send(()).expect("notify close");
        });

        assert!(done_rx
            .recv_timeout(std::time::Duration::from_millis(20))
            .is_err());
        drop(lease);
        done_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("close waits only for active callback");
        closer.join().expect("closer");
        assert!(gate.enter().is_none());
    }
}
