use std::collections::HashMap;
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::fd::{BorrowedFd, RawFd};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use remote_core::SecureSessionState;
use remote_protocol::{decode_header, ChannelId, SessionRole, TransportPath, HEADER_LEN};
use remote_transport::{
    quic_route, DataChannelError, DataChannelFailure, DataChannelLimits, OpaqueFrame,
    QuicClientEndpoint, QuicDataChannel, QuicFrameRoute, RoleHandshake, TransportCancellation,
    TransportKind, RELIABLE_CHANNELS,
};
use rustls::pki_types::CertificateDer;
use rustls::{ClientConfig, RootCertStore};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::{
    ensure_session_active, lookup, now_epoch_millis, read_bytes, CallbackGate,
    ControllerSessionState, RESULT_INVALID_ARGUMENT, RESULT_INVALID_HANDLE, RESULT_INVALID_INPUT,
    RESULT_INVALID_STATE, RESULT_PANIC, RESULT_SECURITY_ERROR, RESULT_TRANSPORT_ERROR,
};

const STATE_BOUND: i32 = 1;
const STATE_CONNECTING: i32 = 2;
const STATE_CONNECTED: i32 = 3;

const DELIVERY_REALTIME: i32 = 1;
const DELIVERY_RELIABLE: i32 = 2;
const DELIVERY_VIDEO: i32 = 3;

const MAX_CERTIFICATE_DER_BYTES: usize = 64 * 1024;
const MAX_SERVER_NAME_BYTES: usize = 253;
const OUTBOUND_QUEUE_CAPACITY: usize = 256;

pub type RemoteQuicStateCallback = extern "C" fn(
    context: u64,
    transport_handle: u64,
    state: i32,
    detail: *const u8,
    detail_len: usize,
);

pub type RemoteQuicPacketCallback = extern "C" fn(
    context: u64,
    transport_handle: u64,
    delivery: i32,
    channel_id: u16,
    packet_group_id: u64,
    packet_index: u32,
    packet_count: u32,
    packet: *const u8,
    packet_len: usize,
);

pub type RemoteQuicDisconnectCallback = extern "C" fn(
    context: u64,
    transport_handle: u64,
    result: i32,
    reason: *const u8,
    reason_len: usize,
);

pub type RemoteQuicClosedCallback = extern "C" fn(context: u64, transport_handle: u64);

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RemoteQuicCallbacks {
    pub context: u64,
    pub on_state: Option<RemoteQuicStateCallback>,
    pub on_packet: Option<RemoteQuicPacketCallback>,
    pub on_disconnect: Option<RemoteQuicDisconnectCallback>,
    pub on_closed: Option<RemoteQuicClosedCallback>,
}

#[derive(Debug, Clone, Copy)]
struct QuicAuthorization {
    session_id: u128,
    path: TransportKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuicLifecycle {
    Created,
    Bound,
    Connecting,
    Connected,
    Failed,
    Closed,
}

struct QuicState {
    lifecycle: QuicLifecycle,
    endpoint: Option<Arc<QuicClientEndpoint>>,
    channel: Option<Arc<QuicDataChannel>>,
    outbound: Option<mpsc::Sender<OpaqueFrame>>,
}

struct FfiQuicTransport {
    handle: u64,
    authorization: QuicAuthorization,
    callbacks: RemoteQuicCallbacks,
    callback_gate: Arc<CallbackGate>,
    callback_serial: Mutex<()>,
    state: Mutex<QuicState>,
    cancellation: TransportCancellation,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    next_packet_group_id: AtomicU64,
}

type SharedQuicTransport = Arc<FfiQuicTransport>;

fn transports() -> &'static Mutex<HashMap<u64, SharedQuicTransport>> {
    static TRANSPORTS: OnceLock<Mutex<HashMap<u64, SharedQuicTransport>>> = OnceLock::new();
    TRANSPORTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("remote-ios-quic")
            .build()
            .expect("create iOS QUIC runtime")
    })
}

fn lookup_transport(handle: u64) -> Result<SharedQuicTransport, i32> {
    if handle == 0 {
        return Err(RESULT_INVALID_HANDLE);
    }
    transports()
        .lock()
        .map_err(|_| RESULT_PANIC)?
        .get(&handle)
        .cloned()
        .ok_or(RESULT_INVALID_HANDLE)
}

fn authorize_controller_session(session_handle: u64) -> Result<QuicAuthorization, i32> {
    let shared = lookup(session_handle)?;
    let session = shared.lock().map_err(|_| RESULT_PANIC)?;
    if session.controller.state() != ControllerSessionState::Streaming {
        return Err(RESULT_INVALID_STATE);
    }
    let mut security = session.security.lock().map_err(|_| RESULT_PANIC)?;
    ensure_session_active(&mut security, now_epoch_millis()?)?;
    let secure = security
        .secure_session
        .as_ref()
        .ok_or(RESULT_INVALID_STATE)?;
    if secure.state() != SecureSessionState::Ready || secure.local_role() != SessionRole::Controller
    {
        return Err(RESULT_SECURITY_ERROR);
    }
    let path = match security
        .selected_transport_path
        .ok_or(RESULT_INVALID_STATE)?
    {
        TransportPath::LanDirect => TransportKind::LanDirect,
        TransportPath::UdpP2p => TransportKind::UdpP2p,
        TransportPath::QuicRelay | TransportPath::Tls443Relay => {
            return Err(RESULT_INVALID_ARGUMENT)
        }
    };
    Ok(QuicAuthorization {
        session_id: secure.session_id(),
        path,
    })
}

fn create_transport(
    authorization: QuicAuthorization,
    callbacks: RemoteQuicCallbacks,
) -> Result<u64, i32> {
    if callbacks.on_state.is_none()
        || callbacks.on_packet.is_none()
        || callbacks.on_disconnect.is_none()
        || callbacks.on_closed.is_none()
    {
        return Err(RESULT_INVALID_ARGUMENT);
    }
    let handle = super::next_handle();
    let transport = Arc::new(FfiQuicTransport {
        handle,
        authorization,
        callbacks,
        callback_gate: Arc::new(CallbackGate::default()),
        callback_serial: Mutex::new(()),
        state: Mutex::new(QuicState {
            lifecycle: QuicLifecycle::Created,
            endpoint: None,
            channel: None,
            outbound: None,
        }),
        cancellation: TransportCancellation::default(),
        tasks: Mutex::new(Vec::new()),
        next_packet_group_id: AtomicU64::new(1),
    });
    transports()
        .lock()
        .map_err(|_| RESULT_PANIC)?
        .insert(handle, transport);
    Ok(handle)
}

fn pinned_tls_config(certificate_der: &[u8]) -> Result<Arc<ClientConfig>, i32> {
    if certificate_der.is_empty() || certificate_der.len() > MAX_CERTIFICATE_DER_BYTES {
        return Err(RESULT_INVALID_ARGUMENT);
    }
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(certificate_der.to_vec()))
        .map_err(|_| RESULT_SECURITY_ERROR)?;
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|_| RESULT_SECURITY_ERROR)?
            .with_root_certificates(roots)
            .with_no_client_auth();
    Ok(Arc::new(config))
}

fn bind_transport_socket(
    transport: &SharedQuicTransport,
    socket: std::net::UdpSocket,
    certificate_der: &[u8],
) -> Result<(), i32> {
    let tls_config = pinned_tls_config(certificate_der)?;
    let limits = DataChannelLimits {
        io_timeout: Duration::from_secs(24 * 60 * 60),
        ..DataChannelLimits::default()
    };
    socket
        .set_nonblocking(true)
        .map_err(|_| RESULT_TRANSPORT_ERROR)?;
    let endpoint = {
        let _runtime_guard = runtime().enter();
        Arc::new(
            QuicClientEndpoint::from_std_socket(socket, tls_config, limits)
                .map_err(|error| map_transport_error(&error))?,
        )
    };
    let bound_addr = endpoint
        .local_addr()
        .map_err(|error| map_transport_error(&error))?;
    {
        let mut state = transport.state.lock().map_err(|_| RESULT_PANIC)?;
        if state.lifecycle != QuicLifecycle::Created {
            return Err(RESULT_INVALID_STATE);
        }
        state.endpoint = Some(endpoint);
        state.lifecycle = QuicLifecycle::Bound;
    }
    emit_state(transport, STATE_BOUND, bound_addr.to_string().as_bytes());
    Ok(())
}

fn parse_utf8(pointer: *const u8, len: usize, max_len: usize) -> Result<String, i32> {
    if len == 0 || len > max_len {
        return Err(RESULT_INVALID_ARGUMENT);
    }
    std::str::from_utf8(read_bytes(pointer, len)?)
        .map(str::to_owned)
        .map_err(|_| RESULT_INVALID_ARGUMENT)
}

fn parse_wire_packet(packet: &[u8], session_id: u128) -> Result<OpaqueFrame, i32> {
    if packet.len() < HEADER_LEN {
        return Err(RESULT_INVALID_INPUT);
    }
    let header = decode_header(&packet[..HEADER_LEN]).map_err(|_| RESULT_INVALID_INPUT)?;
    if header.session_id != session_id
        || usize::try_from(header.payload_len).ok() != Some(packet.len() - HEADER_LEN)
    {
        return Err(RESULT_INVALID_INPUT);
    }
    OpaqueFrame::new(header, packet[HEADER_LEN..].to_vec()).map_err(|_| RESULT_INVALID_INPUT)
}

fn map_transport_error(error: &DataChannelError) -> i32 {
    match error.kind() {
        DataChannelFailure::Authentication => RESULT_SECURITY_ERROR,
        DataChannelFailure::InvalidAddress
        | DataChannelFailure::InvalidConfiguration
        | DataChannelFailure::Protocol
        | DataChannelFailure::FrameTooLarge => RESULT_INVALID_INPUT,
        DataChannelFailure::Cancelled | DataChannelFailure::Closed => RESULT_INVALID_STATE,
        _ => RESULT_TRANSPORT_ERROR,
    }
}

fn emit_state(transport: &FfiQuicTransport, state: i32, detail: &[u8]) {
    let Some(_lease) = transport.callback_gate.enter() else {
        return;
    };
    let Ok(_serial) = transport.callback_serial.lock() else {
        return;
    };
    if let Some(callback) = transport.callbacks.on_state {
        callback(
            transport.callbacks.context,
            transport.handle,
            state,
            detail.as_ptr(),
            detail.len(),
        );
    }
}

fn emit_packet_group(transport: &FfiQuicTransport, delivery: i32, frames: &[OpaqueFrame]) {
    if frames.is_empty() {
        return;
    }
    let Some(_lease) = transport.callback_gate.enter() else {
        return;
    };
    let Ok(_serial) = transport.callback_serial.lock() else {
        return;
    };
    let Some(callback) = transport.callbacks.on_packet else {
        return;
    };
    let group_id = transport
        .next_packet_group_id
        .fetch_add(1, Ordering::Relaxed)
        .max(1);
    let packet_count = u32::try_from(frames.len()).unwrap_or(u32::MAX);
    for (index, frame) in frames.iter().enumerate() {
        let packet = frame.to_wire_bytes();
        callback(
            transport.callbacks.context,
            transport.handle,
            delivery,
            frame.header().channel_id as u16,
            group_id,
            u32::try_from(index).unwrap_or(u32::MAX),
            packet_count,
            packet.as_ptr(),
            packet.len(),
        );
    }
}

fn emit_disconnect(transport: &FfiQuicTransport, result: i32, reason: &[u8]) {
    let Some(_lease) = transport.callback_gate.enter() else {
        return;
    };
    let Ok(_serial) = transport.callback_serial.lock() else {
        return;
    };
    if let Some(callback) = transport.callbacks.on_disconnect {
        callback(
            transport.callbacks.context,
            transport.handle,
            result,
            reason.as_ptr(),
            reason.len(),
        );
    }
}

fn emit_closed(transport: &FfiQuicTransport) {
    let Some(_lease) = transport.callback_gate.enter() else {
        return;
    };
    let Ok(_serial) = transport.callback_serial.lock() else {
        return;
    };
    if let Some(callback) = transport.callbacks.on_closed {
        callback(transport.callbacks.context, transport.handle);
    }
}

fn fail_transport(transport: &SharedQuicTransport, error: &DataChannelError) {
    if transport.cancellation.is_cancelled() {
        return;
    }
    let channel = {
        let Ok(mut state) = transport.state.lock() else {
            return;
        };
        if matches!(
            state.lifecycle,
            QuicLifecycle::Failed | QuicLifecycle::Closed
        ) {
            return;
        }
        state.lifecycle = QuicLifecycle::Failed;
        state.outbound = None;
        state.channel.take()
    };
    transport.cancellation.cancel();
    if let Some(channel) = channel {
        channel.close();
    }
    emit_disconnect(
        transport,
        map_transport_error(error),
        error.to_string().as_bytes(),
    );
}

fn spawn_background_tasks(
    transport: &SharedQuicTransport,
    channel: Arc<QuicDataChannel>,
    outbound_rx: mpsc::Receiver<OpaqueFrame>,
) -> Result<(), i32> {
    let mut tasks = transport.tasks.lock().map_err(|_| RESULT_PANIC)?;

    let outbound_transport = Arc::clone(transport);
    let outbound_channel = Arc::clone(&channel);
    tasks.push(runtime().spawn(async move {
        run_outbound(outbound_transport, outbound_channel, outbound_rx).await;
    }));

    for channel_id in RELIABLE_CHANNELS {
        let receiver_transport = Arc::clone(transport);
        let receiver_channel = Arc::clone(&channel);
        tasks.push(runtime().spawn(async move {
            run_reliable_receiver(receiver_transport, receiver_channel, channel_id).await;
        }));
    }

    let datagram_transport = Arc::clone(transport);
    let datagram_channel = Arc::clone(&channel);
    tasks.push(runtime().spawn(async move {
        run_datagram_receiver(datagram_transport, datagram_channel).await;
    }));

    let video_transport = Arc::clone(transport);
    tasks.push(runtime().spawn(async move {
        run_video_receiver(video_transport, channel).await;
    }));
    Ok(())
}

async fn run_outbound(
    transport: SharedQuicTransport,
    channel: Arc<QuicDataChannel>,
    mut outbound: mpsc::Receiver<OpaqueFrame>,
) {
    while let Some(frame) = outbound.recv().await {
        let result = match quic_route(frame.header().channel_id) {
            QuicFrameRoute::ReliableStream(_) => channel.send_reliable(&frame).await,
            QuicFrameRoute::Datagram => channel.send_datagram(&frame),
            QuicFrameRoute::VideoFrameStream => Err(DataChannelError::new(
                DataChannelFailure::InvalidConfiguration,
                "send_controller_video",
            )),
        };
        if let Err(error) = result {
            fail_transport(&transport, &error);
            return;
        }
    }
}

async fn run_reliable_receiver(
    transport: SharedQuicTransport,
    channel: Arc<QuicDataChannel>,
    channel_id: ChannelId,
) {
    loop {
        match channel.receive_reliable(channel_id).await {
            Ok(frame) => emit_packet_group(&transport, DELIVERY_RELIABLE, &[frame]),
            Err(error) => {
                fail_transport(&transport, &error);
                return;
            }
        }
    }
}

async fn run_datagram_receiver(transport: SharedQuicTransport, channel: Arc<QuicDataChannel>) {
    loop {
        match channel.receive_datagram().await {
            Ok(frame) => emit_packet_group(&transport, DELIVERY_REALTIME, &[frame]),
            Err(error) => {
                fail_transport(&transport, &error);
                return;
            }
        }
    }
}

async fn run_video_receiver(transport: SharedQuicTransport, channel: Arc<QuicDataChannel>) {
    loop {
        match channel.receive_video_frame().await {
            Ok(frames)
                if frames.len() == 2
                    && frames[0].header().kind == remote_protocol::MessageKind::VideoFrameInfo
                    && frames[1].header().kind == remote_protocol::MessageKind::VideoFrameData =>
            {
                emit_packet_group(&transport, DELIVERY_VIDEO, &frames);
            }
            Ok(_) => {
                fail_transport(
                    &transport,
                    &DataChannelError::new(
                        DataChannelFailure::Protocol,
                        "receive_ios_video_packet_group",
                    ),
                );
                return;
            }
            Err(error) => {
                fail_transport(&transport, &error);
                return;
            }
        }
    }
}

async fn connect_transport(
    transport: SharedQuicTransport,
    endpoint: Arc<QuicClientEndpoint>,
    remote_addr: SocketAddr,
    server_name: String,
) {
    let handshake = RoleHandshake::new(transport.authorization.session_id, SessionRole::Controller);
    let result = endpoint
        .connect(
            remote_addr,
            &server_name,
            transport.authorization.path,
            handshake,
            &transport.cancellation,
        )
        .await;
    let channel = match result {
        Ok(channel) => Arc::new(channel),
        Err(error) => {
            fail_transport(&transport, &error);
            return;
        }
    };
    let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_QUEUE_CAPACITY);
    {
        let Ok(mut state) = transport.state.lock() else {
            channel.close();
            return;
        };
        if state.lifecycle != QuicLifecycle::Connecting || transport.cancellation.is_cancelled() {
            channel.close();
            return;
        }
        state.channel = Some(Arc::clone(&channel));
        state.outbound = Some(outbound_tx);
        if spawn_background_tasks(&transport, channel, outbound_rx).is_err() {
            if let Some(channel) = state.channel.take() {
                channel.close();
            }
            state.outbound = None;
            state.lifecycle = QuicLifecycle::Failed;
            drop(state);
            emit_disconnect(&transport, RESULT_PANIC, b"start QUIC background tasks");
            return;
        }
        state.lifecycle = QuicLifecycle::Connected;
    }
    emit_state(
        &transport,
        STATE_CONNECTED,
        remote_addr.to_string().as_bytes(),
    );
}

fn enqueue_packet(handle: u64, packet: *const u8, packet_len: usize, realtime: bool) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let packet = read_bytes(packet, packet_len)?;
        let transport = lookup_transport(handle)?;
        let frame = parse_wire_packet(packet, transport.authorization.session_id)?;
        let valid_route = matches!(
            (realtime, quic_route(frame.header().channel_id)),
            (true, QuicFrameRoute::Datagram) | (false, QuicFrameRoute::ReliableStream(_))
        );
        if !valid_route {
            return Err(RESULT_INVALID_INPUT);
        }
        let outbound = {
            let state = transport.state.lock().map_err(|_| RESULT_PANIC)?;
            if state.lifecycle != QuicLifecycle::Connected {
                return Err(RESULT_INVALID_STATE);
            }
            state.outbound.clone().ok_or(RESULT_INVALID_STATE)?
        };
        outbound.try_send(frame).map_err(|error| match error {
            mpsc::error::TrySendError::Full(_) => RESULT_TRANSPORT_ERROR,
            mpsc::error::TrySendError::Closed(_) => RESULT_INVALID_STATE,
        })
    }));
    super::flatten_ffi_result(result)
}

fn close_transport(transport: &SharedQuicTransport, emit_callback: bool) -> Result<(), i32> {
    let (channel, should_emit) = {
        let mut state = transport.state.lock().map_err(|_| RESULT_PANIC)?;
        if state.lifecycle == QuicLifecycle::Closed {
            return Ok(());
        }
        state.lifecycle = QuicLifecycle::Closed;
        state.endpoint = None;
        state.outbound = None;
        (state.channel.take(), true)
    };
    transport.cancellation.cancel();
    if let Some(channel) = channel {
        channel.close();
    }
    if emit_callback && should_emit {
        emit_closed(transport);
    }
    Ok(())
}

#[no_mangle]
pub extern "C" fn remote_controller_quic_transport_create(
    session_handle: u64,
    callbacks: RemoteQuicCallbacks,
) -> u64 {
    catch_unwind(AssertUnwindSafe(|| {
        authorize_controller_session(session_handle)
            .and_then(|authorization| create_transport(authorization, callbacks))
            .unwrap_or(0)
    }))
    .unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn remote_controller_quic_transport_bind(
    handle: u64,
    local_addr: *const u8,
    local_addr_len: usize,
    peer_certificate_der: *const u8,
    peer_certificate_der_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let local_addr = parse_utf8(local_addr, local_addr_len, 128)?
            .parse::<SocketAddr>()
            .map_err(|_| RESULT_INVALID_ARGUMENT)?;
        let certificate = read_bytes(peer_certificate_der, peer_certificate_der_len)?;
        let transport = lookup_transport(handle)?;
        let socket = std::net::UdpSocket::bind(local_addr).map_err(|_| RESULT_TRANSPORT_ERROR)?;
        bind_transport_socket(&transport, socket, certificate)
    }));
    super::flatten_ffi_result(result)
}

/// Duplicates an already-bound UDP socket so the candidate probe and QUIC
/// handshake use the same local endpoint. The caller keeps ownership of
/// `socket_fd` and may close it after this function returns successfully.
#[no_mangle]
pub extern "C" fn remote_controller_quic_transport_bind_socket(
    handle: u64,
    socket_fd: i32,
    peer_certificate_der: *const u8,
    peer_certificate_der_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if socket_fd < 0 {
            return Err(RESULT_INVALID_ARGUMENT);
        }
        let certificate = read_bytes(peer_certificate_der, peer_certificate_der_len)?;
        let transport = lookup_transport(handle)?;
        #[cfg(unix)]
        let socket = {
            // SAFETY: the descriptor is borrowed only long enough to duplicate it;
            // the caller retains ownership of the original descriptor.
            let borrowed = unsafe { BorrowedFd::borrow_raw(socket_fd as RawFd) };
            let owned = borrowed
                .try_clone_to_owned()
                .map_err(|_| RESULT_INVALID_ARGUMENT)?;
            std::net::UdpSocket::from(owned)
        };
        #[cfg(not(unix))]
        return Err(RESULT_INVALID_ARGUMENT);
        #[cfg(unix)]
        bind_transport_socket(&transport, socket, certificate)
    }));
    super::flatten_ffi_result(result)
}

#[no_mangle]
pub extern "C" fn remote_controller_quic_transport_connect(
    handle: u64,
    remote_addr: *const u8,
    remote_addr_len: usize,
    server_name: *const u8,
    server_name_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let remote_addr = parse_utf8(remote_addr, remote_addr_len, 128)?
            .parse::<SocketAddr>()
            .map_err(|_| RESULT_INVALID_ARGUMENT)?;
        let server_name = parse_utf8(server_name, server_name_len, MAX_SERVER_NAME_BYTES)?;
        let transport = lookup_transport(handle)?;
        let mut state = transport.state.lock().map_err(|_| RESULT_PANIC)?;
        if state.lifecycle != QuicLifecycle::Bound {
            return Err(RESULT_INVALID_STATE);
        }
        let endpoint = state.endpoint.clone().ok_or(RESULT_INVALID_STATE)?;
        state.lifecycle = QuicLifecycle::Connecting;
        drop(state);
        emit_state(
            &transport,
            STATE_CONNECTING,
            remote_addr.to_string().as_bytes(),
        );
        let state = transport.state.lock().map_err(|_| RESULT_PANIC)?;
        if state.lifecycle != QuicLifecycle::Connecting {
            return Err(RESULT_INVALID_STATE);
        }
        let task_transport = Arc::clone(&transport);
        let task = runtime().spawn(async move {
            connect_transport(task_transport, endpoint, remote_addr, server_name).await;
        });
        transport.tasks.lock().map_err(|_| RESULT_PANIC)?.push(task);
        drop(state);
        Ok(())
    }));
    super::flatten_ffi_result(result)
}

#[no_mangle]
pub extern "C" fn remote_controller_quic_transport_send_reliable(
    handle: u64,
    packet: *const u8,
    packet_len: usize,
) -> i32 {
    enqueue_packet(handle, packet, packet_len, false)
}

#[no_mangle]
pub extern "C" fn remote_controller_quic_transport_send_realtime(
    handle: u64,
    packet: *const u8,
    packet_len: usize,
) -> i32 {
    enqueue_packet(handle, packet, packet_len, true)
}

#[no_mangle]
pub extern "C" fn remote_controller_quic_transport_close(handle: u64) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let transport = lookup_transport(handle)?;
        close_transport(&transport, true)
    }));
    super::flatten_ffi_result(result)
}

#[no_mangle]
pub extern "C" fn remote_controller_quic_transport_destroy(handle: u64) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let transport = transports()
            .lock()
            .map_err(|_| RESULT_PANIC)?
            .remove(&handle)
            .ok_or(RESULT_INVALID_HANDLE)?;
        transport.callback_gate.close_and_wait();
        close_transport(&transport, false)?;
        let tasks = std::mem::take(&mut *transport.tasks.lock().map_err(|_| RESULT_PANIC)?);
        for task in &tasks {
            task.abort();
        }
        if tokio::runtime::Handle::try_current().is_err() {
            runtime().block_on(async {
                for task in tasks {
                    let _ = task.await;
                }
            });
        }
        Ok(())
    }));
    super::flatten_ffi_result(result)
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::fd::AsRawFd;
    use std::sync::Mutex;
    use std::time::Instant;

    use remote_protocol::{encode_header, MessageHeader, MessageKind};
    use remote_transport::{test_tls, QuicServerEndpoint};
    use rustls::pki_types::pem::PemObject;

    use super::*;
    use crate::RESULT_OK;

    const SESSION_ID: u128 = 0x00000000000040008000000000000033;
    const CERTIFICATE_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDSTCCAjGgAwIBAgIUHO+49BfK06g0AP7o93L8jN4BKa0wDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDcyMTA1MzE1MloXDTM2MDcx
ODA1MzE1MlowFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAoVDwYHk5BNUuvB6j/aly9zqdEBDI+U8fd2kxA6pZIaC7
K1eVGtdpp32bhgBzMoo8AptUKtIk/QaugEWr9F3vrzWrZufkGlBj8Z1pUZliLPLz
0Yh+BvX1mqH69b7gXIqxbhAhhYwvDIEz+X9aim51GPyg60dDJsBMyGVG26b3TgyR
uCf2/YD2QZ6eJTPMaKxW36OQNy8D0q75WDloTxihNmpNRqZkZBPihU0OpCZjyWsY
g+VqqfrGzlAEMJN5W4N6xI1ofC/G9tgalUusDj+FSYkueSz4vX/KBuH+5RXuhMYn
toxK+2uFYdscNd4R0Vap4jdVS9wbhF0t9B7Yo6EMDQIDAQABo4GSMIGPMB0GA1Ud
DgQWBBQHSC9T7B09au+bun1Y2gIbpaKqGTAfBgNVHSMEGDAWgBQHSC9T7B09au+b
un1Y2gIbpaKqGTAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUE
DDAKBggrBgEFBQcDATAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwDQYJKoZI
hvcNAQELBQADggEBAHxGmvEj5NyrToBpaq75mK2uIKOPwNhZWX5BwiAiXPmwv6It
GydKvocIVgOntiBIivKVSXIcViRiwKQ8wH0YIlfBPLxJE08Z1mHHn693lV9tRVXa
YeeaEo0UaXkg7T8onpuHvhtvJatb/BhXqDs6Xw8fmPdT3QW5iF1fh+abphf8hatA
9lvJ85ID0MkVui1NwZ27F2YEiVVLb6ktvvDkg1BVKMsqVUQy49qjmIBkrAsDHQqm
pfa1oFh3bgg8OGl0BHDp5Qd/Rgk+sIJcM9KEBYn6yTypJx78zH02QblLYHsKFEqs
6MR5LGICNiqe6UzJmZNPXcBGZgZVEFnh/lAVW4A=
-----END CERTIFICATE-----"#;
    const WRONG_CERTIFICATE_PEM: &str = r#"-----BEGIN CERTIFICATE-----
MIIDBDCCAeygAwIBAgIUGwR12XwDGsSwTFDa035ubBLuwnAwDQYJKoZIhvcNAQEL
BQAwGDEWMBQGA1UEAwwNbG9uZ3hpbmd6ZS1QQzAeFw0yNjA3MTcxNjMwMzJaFw0z
NjA3MTQxNjMwMzJaMBgxFjAUBgNVBAMMDWxvbmd4aW5nemUtUEMwggEiMA0GCSqG
SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCrwKWXZRCI/8MVBF2ddsfDAZEtbGLH0Qd4
5yGccCjmgn88iCEOAgxfyuZKj3aHOzeM36nbE3SbQwx7pj/jiyXussAx07YJzWKK
PkCrcfrNWWig664ku2avZcpKoVtqo4iCwekIwIDeR4k3147VxLX/YHNp8dMjl8WG
qBZalgXhsmiDGRq2c+JnVUDPr+xuq9ynhbSO+6/aj6RfJ+BHyptfflbFuZl6RPLS
cWmhrKEy4CDa5RbAys49EppVIAkHzifi/6KGuk/X5qvKMVMONcWucC3ytEx57WMF
hiKQBjCDzRqA9FIdiPIQYEqgkcFCWW3u6uUOqEsw2FP4T+DRf9SlAgMBAAGjRjBE
MAkGA1UdEwQCMAAwGAYDVR0RBBEwD4INbG9uZ3hpbmd6ZS1QQzAdBgNVHQ4EFgQU
5QmUZeWY77EOO5x9uSzmQEIDR3YwDQYJKoZIhvcNAQELBQADggEBAFwuHVj8A6SN
6hLEP+cFW4y1THpZwYFwPf06xcE1KIUWD2DadHRbcHrqFkfDbW8315mwv9Mcwlx2
BtXG1YocQ+NykkOE6AC5AJEUTXpOhotcKh8A5DfT2KODegtZbbMWz20RpRitRjH8
Vbczx16nX0+J5CiIGHp7R4LoaOA/q3dfkGAi1hvTNAPGYJwQ/BP3wLQYWFaJnMzq
wAZapbE2MgesLrvT3ay3K9g7QBnpwGyboay74SMfQUDX9G41hSCafw779Xg0d8O2
EGyNV0Q4zsxug7Ui936pxl5BFQibgCgUk8Ww/wUskjOlx+30Bts8jeiBgO2mf76Y
/zVD5ra5X5w=
-----END CERTIFICATE-----"#;

    #[derive(Clone, Debug)]
    enum TestEvent {
        State(i32),
        Packet(Vec<u8>),
        Disconnected(i32),
        Closed,
    }

    fn events() -> &'static Mutex<Vec<TestEvent>> {
        static EVENTS: OnceLock<Mutex<Vec<TestEvent>>> = OnceLock::new();
        EVENTS.get_or_init(|| Mutex::new(Vec::new()))
    }

    fn test_serial() -> &'static Mutex<()> {
        static SERIAL: OnceLock<Mutex<()>> = OnceLock::new();
        SERIAL.get_or_init(|| Mutex::new(()))
    }

    extern "C" fn state_callback(
        _context: u64,
        _handle: u64,
        state: i32,
        _detail: *const u8,
        _detail_len: usize,
    ) {
        events()
            .lock()
            .expect("events")
            .push(TestEvent::State(state));
    }

    extern "C" fn packet_callback(
        _context: u64,
        _handle: u64,
        _delivery: i32,
        _channel_id: u16,
        _packet_group_id: u64,
        _packet_index: u32,
        _packet_count: u32,
        packet: *const u8,
        packet_len: usize,
    ) {
        let packet = read_bytes(packet, packet_len).expect("packet").to_vec();
        events()
            .lock()
            .expect("events")
            .push(TestEvent::Packet(packet));
    }

    extern "C" fn disconnect_callback(
        _context: u64,
        _handle: u64,
        result: i32,
        _reason: *const u8,
        _reason_len: usize,
    ) {
        events()
            .lock()
            .expect("events")
            .push(TestEvent::Disconnected(result));
    }

    extern "C" fn closed_callback(_context: u64, _handle: u64) {
        events().lock().expect("events").push(TestEvent::Closed);
    }

    fn callbacks() -> RemoteQuicCallbacks {
        RemoteQuicCallbacks {
            context: 0,
            on_state: Some(state_callback),
            on_packet: Some(packet_callback),
            on_disconnect: Some(disconnect_callback),
            on_closed: Some(closed_callback),
        }
    }

    fn certificate_der() -> Vec<u8> {
        CertificateDer::from_pem_slice(CERTIFICATE_PEM.as_bytes())
            .expect("certificate")
            .to_vec()
    }

    fn wrong_certificate_der() -> Vec<u8> {
        CertificateDer::from_pem_slice(WRONG_CERTIFICATE_PEM.as_bytes())
            .expect("wrong certificate")
            .to_vec()
    }

    fn bind_test_server(limits: DataChannelLimits) -> QuicServerEndpoint {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("server socket");
        socket.set_nonblocking(true).expect("nonblocking server");
        let _runtime_guard = runtime().enter();
        QuicServerEndpoint::from_std_socket(socket, test_tls::server_config(), limits)
            .expect("server")
    }

    fn create_test_transport() -> u64 {
        create_transport(
            QuicAuthorization {
                session_id: SESSION_ID,
                path: TransportKind::LanDirect,
            },
            callbacks(),
        )
        .expect("transport")
    }

    fn wait_for_event(predicate: impl Fn(&TestEvent) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if events().lock().expect("events").iter().any(&predicate) {
                return;
            }
            assert!(Instant::now() < deadline, "timed out waiting for event");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn wire_packet(kind: MessageKind, channel: ChannelId, sequence: u64, body: &[u8]) -> Vec<u8> {
        let header = MessageHeader::new_on_channel(
            kind,
            channel,
            SESSION_ID,
            sequence,
            u32::try_from(body.len()).expect("body length"),
        )
        .expect("header");
        let mut packet = encode_header(header).to_vec();
        packet.extend_from_slice(body);
        packet
    }

    #[test]
    fn localhost_quic_routes_bidirectional_opaque_packets_and_destroy_releases_tasks() {
        let _serial = test_serial().lock().expect("test serial");
        events().lock().expect("events").clear();
        let limits = DataChannelLimits {
            io_timeout: Duration::from_secs(24 * 60 * 60),
            ..DataChannelLimits::default()
        };
        let server = bind_test_server(limits);
        let server_addr = server.local_addr().expect("server address");
        let server_task = runtime().spawn(async move {
            server
                .accept(
                    TransportKind::LanDirect,
                    RoleHandshake::new(SESSION_ID, SessionRole::Controlled),
                    &TransportCancellation::default(),
                )
                .await
                .expect("server channel")
        });

        let handle = create_test_transport();
        let candidate_socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("candidate socket");
        let candidate_addr = candidate_socket.local_addr().expect("candidate address");
        let certificate = certificate_der();
        #[cfg(unix)]
        assert_eq!(
            remote_controller_quic_transport_bind_socket(
                handle,
                candidate_socket.as_raw_fd(),
                certificate.as_ptr(),
                certificate.len(),
            ),
            RESULT_OK
        );
        drop(candidate_socket);
        let remote_addr = server_addr.to_string();
        let server_name = b"localhost";
        assert_eq!(
            remote_controller_quic_transport_connect(
                handle,
                remote_addr.as_ptr(),
                remote_addr.len(),
                server_name.as_ptr(),
                server_name.len(),
            ),
            RESULT_OK
        );
        wait_for_event(|event| matches!(event, TestEvent::State(STATE_CONNECTED)));
        let server_channel = runtime().block_on(server_task).expect("server task");
        assert_eq!(server_channel.remote_address(), candidate_addr);

        let outbound = wire_packet(
            MessageKind::KeyframeRequest,
            ChannelId::MediaControl,
            0,
            b"opaque-controller-ciphertext",
        );
        assert_eq!(
            remote_controller_quic_transport_send_reliable(
                handle,
                outbound.as_ptr(),
                outbound.len()
            ),
            RESULT_OK
        );
        let received = runtime()
            .block_on(server_channel.receive_reliable(ChannelId::MediaControl))
            .expect("server receives packet");
        assert_eq!(received.to_wire_bytes().as_ref(), outbound);

        let outbound_realtime = wire_packet(
            MessageKind::InputEvent,
            ChannelId::InputRealtime,
            0,
            b"opaque-realtime-controller-ciphertext",
        );
        assert_eq!(
            remote_controller_quic_transport_send_realtime(
                handle,
                outbound_realtime.as_ptr(),
                outbound_realtime.len(),
            ),
            RESULT_OK
        );
        let received_realtime = runtime()
            .block_on(server_channel.receive_datagram())
            .expect("server receives realtime packet");
        assert_eq!(
            received_realtime.to_wire_bytes().as_ref(),
            outbound_realtime
        );

        let inbound = wire_packet(
            MessageKind::ErrorReport,
            ChannelId::SecureControl,
            0,
            b"opaque-controlled-ciphertext",
        );
        let inbound_frame = parse_wire_packet(&inbound, SESSION_ID).expect("inbound frame");
        runtime()
            .block_on(server_channel.send_reliable(&inbound_frame))
            .expect("server sends packet");
        wait_for_event(|event| matches!(event, TestEvent::Packet(packet) if packet == &inbound));

        let inbound_realtime = wire_packet(
            MessageKind::Stats,
            ChannelId::Telemetry,
            0,
            b"opaque-realtime-controlled-ciphertext",
        );
        let inbound_realtime_frame =
            parse_wire_packet(&inbound_realtime, SESSION_ID).expect("realtime frame");
        server_channel
            .send_datagram(&inbound_realtime_frame)
            .expect("server sends realtime packet");
        wait_for_event(
            |event| matches!(event, TestEvent::Packet(packet) if packet == &inbound_realtime),
        );

        assert_eq!(remote_controller_quic_transport_close(handle), RESULT_OK);
        wait_for_event(|event| matches!(event, TestEvent::Closed));
        let started = Instant::now();
        assert_eq!(remote_controller_quic_transport_destroy(handle), RESULT_OK);
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(
            remote_controller_quic_transport_send_reliable(
                handle,
                outbound.as_ptr(),
                outbound.len()
            ),
            RESULT_INVALID_HANDLE
        );
        server_channel.close();
    }

    #[test]
    fn wrong_session_certificate_fails_tls_connection() {
        let _serial = test_serial().lock().expect("test serial");
        events().lock().expect("events").clear();
        let server = bind_test_server(DataChannelLimits::default());
        let server_addr = server.local_addr().expect("server address");
        let server_task = runtime().spawn(async move {
            let _ = server
                .accept(
                    TransportKind::LanDirect,
                    RoleHandshake::new(SESSION_ID, SessionRole::Controlled),
                    &TransportCancellation::default(),
                )
                .await;
        });

        let handle = create_test_transport();
        let local_addr = b"127.0.0.1:0";
        let wrong_certificate = wrong_certificate_der();
        assert_eq!(
            remote_controller_quic_transport_bind(
                handle,
                local_addr.as_ptr(),
                local_addr.len(),
                wrong_certificate.as_ptr(),
                wrong_certificate.len(),
            ),
            RESULT_OK
        );
        let remote_addr = server_addr.to_string();
        let server_name = b"localhost";
        assert_eq!(
            remote_controller_quic_transport_connect(
                handle,
                remote_addr.as_ptr(),
                remote_addr.len(),
                server_name.as_ptr(),
                server_name.len(),
            ),
            RESULT_OK
        );
        wait_for_event(|event| matches!(event, TestEvent::Disconnected(RESULT_SECURITY_ERROR)));
        assert_eq!(remote_controller_quic_transport_destroy(handle), RESULT_OK);
        server_task.abort();
    }
}
