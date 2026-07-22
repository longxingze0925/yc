use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use bytes::Bytes;
use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use remote_protocol::{
    decode_header, encode_header, ChannelId, MessageKind, SessionRole, HEADER_LEN,
};
use rustls::{ClientConfig as RustlsClientConfig, ServerConfig as RustlsServerConfig};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Mutex,
};

use crate::{
    quic_route, run_with_deadline, supports_quic_data_path, DataChannelError, DataChannelFailure,
    DataChannelLimits, DataChannelResult, OpaqueFrame, QuicFrameRoute, RoleHandshake,
    TransportCancellation, TransportKind, RELIABLE_CHANNELS,
};

const QUIC_ALPN: &[u8] = b"rctl-data-v1";
const ROLE_HANDSHAKE_MAGIC: [u8; 4] = *b"RTH1";
const ROLE_HANDSHAKE_LEN: usize = 24;
const STREAM_PREFACE_MAGIC: [u8; 4] = *b"RCS1";
const STREAM_PREFACE_LEN: usize = 8;
const CLOSE_NORMAL: u32 = 0;
const CLOSE_PROTOCOL: u32 = 1;

#[derive(Debug)]
struct DuplexStream {
    send: Mutex<SendStream>,
    recv: Mutex<RecvStream>,
}

#[derive(Debug)]
pub struct QuicClientEndpoint {
    endpoint: Endpoint,
    limits: DataChannelLimits,
}

impl QuicClientEndpoint {
    pub fn bind(
        local_addr: SocketAddr,
        tls_config: Arc<RustlsClientConfig>,
        limits: DataChannelLimits,
    ) -> DataChannelResult<Self> {
        let limits = limits.validate()?;
        let client_config = make_quinn_client_config(tls_config, limits)?;
        let mut endpoint = Endpoint::client(local_addr).map_err(|_| {
            DataChannelError::new(DataChannelFailure::InvalidAddress, "bind_quic_client")
        })?;
        endpoint.set_default_client_config(client_config);
        Ok(Self { endpoint, limits })
    }

    /// Takes ownership of a UDP socket already used for observe/probing so the
    /// NAT mapping and local port are retained for the QUIC handshake.
    pub fn from_std_socket(
        socket: std::net::UdpSocket,
        tls_config: Arc<RustlsClientConfig>,
        limits: DataChannelLimits,
    ) -> DataChannelResult<Self> {
        let limits = limits.validate()?;
        let client_config = make_quinn_client_config(tls_config, limits)?;
        let mut endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|_| {
            DataChannelError::new(
                DataChannelFailure::InvalidAddress,
                "adopt_quic_client_socket",
            )
        })?;
        endpoint.set_default_client_config(client_config);
        Ok(Self { endpoint, limits })
    }

    pub fn local_addr(&self) -> DataChannelResult<SocketAddr> {
        self.endpoint
            .local_addr()
            .map_err(|_| DataChannelError::new(DataChannelFailure::Io, "quic_client_local_addr"))
    }

    pub async fn connect(
        &self,
        remote_addr: SocketAddr,
        server_name: &str,
        path: TransportKind,
        handshake: RoleHandshake,
        cancellation: &TransportCancellation,
    ) -> DataChannelResult<QuicDataChannel> {
        if !supports_quic_data_path(path) {
            return Err(DataChannelError::new(
                DataChannelFailure::InvalidConfiguration,
                "select_quic_path",
            ));
        }
        let connecting = self
            .endpoint
            .connect(remote_addr, server_name)
            .map_err(classify_connect_error)?;
        let connection = await_connection(connecting, self.limits, cancellation).await?;
        QuicDataChannel::establish(
            self.endpoint.clone(),
            connection,
            path,
            handshake,
            self.limits,
            cancellation,
        )
        .await
    }
}

#[derive(Debug)]
pub struct QuicServerEndpoint {
    endpoint: Endpoint,
    limits: DataChannelLimits,
}

impl QuicServerEndpoint {
    pub fn bind(
        local_addr: SocketAddr,
        tls_config: Arc<RustlsServerConfig>,
        limits: DataChannelLimits,
    ) -> DataChannelResult<Self> {
        let limits = limits.validate()?;
        let server_config = make_quinn_server_config(tls_config, limits)?;
        let endpoint = Endpoint::server(server_config, local_addr).map_err(|_| {
            DataChannelError::new(DataChannelFailure::InvalidAddress, "bind_quic_server")
        })?;
        Ok(Self { endpoint, limits })
    }

    /// Takes ownership of a UDP socket after an authorized P2P probe. No raw
    /// UDP business traffic is exposed by this endpoint.
    pub fn from_std_socket(
        socket: std::net::UdpSocket,
        tls_config: Arc<RustlsServerConfig>,
        limits: DataChannelLimits,
    ) -> DataChannelResult<Self> {
        let limits = limits.validate()?;
        let server_config = make_quinn_server_config(tls_config, limits)?;
        let endpoint = Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|_| {
            DataChannelError::new(
                DataChannelFailure::InvalidAddress,
                "adopt_quic_server_socket",
            )
        })?;
        Ok(Self { endpoint, limits })
    }

    pub fn local_addr(&self) -> DataChannelResult<SocketAddr> {
        self.endpoint
            .local_addr()
            .map_err(|_| DataChannelError::new(DataChannelFailure::Io, "quic_server_local_addr"))
    }

    pub async fn accept(
        &self,
        path: TransportKind,
        handshake: RoleHandshake,
        cancellation: &TransportCancellation,
    ) -> DataChannelResult<QuicDataChannel> {
        if !supports_quic_data_path(path) {
            return Err(DataChannelError::new(
                DataChannelFailure::InvalidConfiguration,
                "select_quic_path",
            ));
        }
        let incoming = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                return Err(DataChannelError::new(
                    DataChannelFailure::Cancelled,
                    "accept_quic",
                ));
            }
            result = tokio::time::timeout(self.limits.connect_timeout, self.endpoint.accept()) => {
                result.map_err(|_| DataChannelError::new(
                    DataChannelFailure::Timeout,
                    "accept_quic",
                ))?
            }
        }
        .ok_or_else(|| DataChannelError::new(DataChannelFailure::Closed, "accept_quic"))?;
        let connection = await_connection(
            incoming
                .accept()
                .map_err(|error| classify_connection_error(error, "accept_quic_connection"))?,
            self.limits,
            cancellation,
        )
        .await?;
        QuicDataChannel::establish(
            self.endpoint.clone(),
            connection,
            path,
            handshake,
            self.limits,
            cancellation,
        )
        .await
    }

    pub fn close(&self) {
        self.endpoint
            .close(VarInt::from_u32(CLOSE_NORMAL), b"shutdown");
    }
}

#[derive(Debug)]
pub struct QuicDataChannel {
    _endpoint: Endpoint,
    connection: Connection,
    path: TransportKind,
    handshake: RoleHandshake,
    limits: DataChannelLimits,
    streams: HashMap<ChannelId, DuplexStream>,
    cancellation: TransportCancellation,
    video_accept: Mutex<()>,
    datagram_receive: Mutex<()>,
}

impl QuicDataChannel {
    async fn establish(
        endpoint: Endpoint,
        connection: Connection,
        path: TransportKind,
        handshake: RoleHandshake,
        limits: DataChannelLimits,
        cancellation: &TransportCancellation,
    ) -> DataChannelResult<Self> {
        let streams = match handshake.role {
            SessionRole::Controller => {
                open_controller_streams(&connection, handshake, limits, cancellation).await
            }
            SessionRole::Controlled => {
                accept_controlled_streams(&connection, handshake, limits, cancellation).await
            }
        };
        let streams = match streams {
            Ok(streams) => streams,
            Err(error) => {
                connection.close(VarInt::from_u32(CLOSE_PROTOCOL), b"role handshake failed");
                return Err(error);
            }
        };
        Ok(Self {
            _endpoint: endpoint,
            connection,
            path,
            handshake,
            limits,
            streams,
            cancellation: TransportCancellation::default(),
            video_accept: Mutex::new(()),
            datagram_receive: Mutex::new(()),
        })
    }

    pub const fn path(&self) -> TransportKind {
        self.path
    }

    pub const fn local_handshake(&self) -> RoleHandshake {
        self.handshake
    }

    pub fn remote_address(&self) -> SocketAddr {
        self.connection.remote_address()
    }

    pub fn datagrams_supported(&self) -> bool {
        self.connection.max_datagram_size().is_some()
    }

    pub async fn send_reliable(&self, frame: &OpaqueFrame) -> DataChannelResult<()> {
        frame.validate_for(self.handshake.session_id, self.limits)?;
        let channel = frame.header().channel_id;
        if !matches!(quic_route(channel), QuicFrameRoute::ReliableStream(_)) {
            return Err(DataChannelError::new(
                DataChannelFailure::Protocol,
                "route_reliable_frame",
            ));
        }
        let stream = self.streams.get(&channel).ok_or_else(|| {
            DataChannelError::new(DataChannelFailure::Protocol, "select_reliable_stream")
        })?;
        let mut send = stream.send.lock().await;
        let result = write_frame(
            &mut *send,
            frame,
            self.limits,
            &self.cancellation,
            "send_quic_reliable",
        )
        .await;
        self.close_on_stream_error(&result);
        result
    }

    pub async fn receive_reliable(&self, channel: ChannelId) -> DataChannelResult<OpaqueFrame> {
        if !matches!(quic_route(channel), QuicFrameRoute::ReliableStream(_)) {
            return Err(DataChannelError::new(
                DataChannelFailure::Protocol,
                "route_reliable_frame",
            ));
        }
        let stream = self.streams.get(&channel).ok_or_else(|| {
            DataChannelError::new(DataChannelFailure::Protocol, "select_reliable_stream")
        })?;
        let mut recv = stream.recv.lock().await;
        let result = read_frame(
            &mut *recv,
            self.handshake.session_id,
            self.limits,
            &self.cancellation,
            "receive_quic_reliable",
        )
        .await
        .and_then(|frame| {
            if frame.header().channel_id == channel {
                Ok(frame)
            } else {
                Err(DataChannelError::new(
                    DataChannelFailure::Protocol,
                    "verify_reliable_channel",
                ))
            }
        });
        self.close_on_stream_error(&result);
        result
    }

    pub fn send_datagram(&self, frame: &OpaqueFrame) -> DataChannelResult<()> {
        frame.validate_for(self.handshake.session_id, self.limits)?;
        if !matches!(
            quic_route(frame.header().channel_id),
            QuicFrameRoute::Datagram
        ) {
            return Err(DataChannelError::new(
                DataChannelFailure::Protocol,
                "route_quic_datagram",
            ));
        }
        let bytes = frame.to_wire_bytes();
        if bytes.len() > self.limits.max_datagram_bytes {
            return Err(DataChannelError::new(
                DataChannelFailure::FrameTooLarge,
                "send_quic_datagram",
            ));
        }
        self.connection.send_datagram(bytes).map_err(|error| {
            let kind = match error {
                quinn::SendDatagramError::UnsupportedByPeer
                | quinn::SendDatagramError::Disabled => DataChannelFailure::DatagramUnavailable,
                quinn::SendDatagramError::TooLarge => DataChannelFailure::FrameTooLarge,
                quinn::SendDatagramError::ConnectionLost(_) => DataChannelFailure::Closed,
            };
            DataChannelError::new(kind, "send_quic_datagram")
        })
    }

    pub async fn receive_datagram(&self) -> DataChannelResult<OpaqueFrame> {
        let _guard = self.datagram_receive.lock().await;
        let bytes = tokio::select! {
            biased;
            () = self.cancellation.cancelled() => {
                return Err(DataChannelError::new(
                    DataChannelFailure::Cancelled,
                    "receive_quic_datagram",
                ));
            }
            result = tokio::time::timeout(
                self.limits.io_timeout,
                self.connection.read_datagram(),
            ) => match result {
                Ok(Ok(bytes)) => bytes,
                Ok(Err(error)) => {
                    return Err(classify_connection_error(error, "receive_quic_datagram"));
                }
                Err(_) => {
                    return Err(DataChannelError::new(
                        DataChannelFailure::Timeout,
                        "receive_quic_datagram",
                    ));
                }
            }
        };
        if bytes.len() > self.limits.max_datagram_bytes {
            return Err(DataChannelError::new(
                DataChannelFailure::FrameTooLarge,
                "receive_quic_datagram",
            ));
        }
        let frame = OpaqueFrame::from_wire_bytes(bytes, self.handshake.session_id, self.limits)?;
        if !matches!(
            quic_route(frame.header().channel_id),
            QuicFrameRoute::Datagram
        ) {
            return Err(DataChannelError::new(
                DataChannelFailure::Protocol,
                "route_quic_datagram",
            ));
        }
        Ok(frame)
    }

    pub async fn send_video_frame(&self, frames: &[OpaqueFrame]) -> DataChannelResult<()> {
        validate_video_frames(frames, self.handshake.session_id, self.limits)?;
        let total_bytes = frames
            .iter()
            .try_fold(0_usize, |total, frame| total.checked_add(frame.wire_len()))
            .ok_or_else(|| {
                DataChannelError::new(DataChannelFailure::ResourceLimit, "size_video_stream")
            })?;
        if total_bytes > self.limits.max_video_stream_bytes {
            return Err(DataChannelError::new(
                DataChannelFailure::FrameTooLarge,
                "size_video_stream",
            ));
        }
        let mut send = run_with_deadline(
            self.limits.io_timeout,
            &self.cancellation,
            "open_video_stream",
            self.connection.open_uni(),
        )
        .await?;
        send.set_priority(stream_priority(ChannelId::Video))
            .map_err(|_| {
                DataChannelError::new(DataChannelFailure::Closed, "prioritize_video_stream")
            })?;
        for frame in frames {
            write_frame(
                &mut send,
                frame,
                self.limits,
                &self.cancellation,
                "send_video_stream",
            )
            .await?;
        }
        send.finish()
            .map_err(|_| DataChannelError::new(DataChannelFailure::Closed, "finish_video_stream"))
    }

    pub async fn receive_video_frame(&self) -> DataChannelResult<Vec<OpaqueFrame>> {
        let _guard = self.video_accept.lock().await;
        let mut recv = run_with_deadline(
            self.limits.io_timeout,
            &self.cancellation,
            "accept_video_stream",
            self.connection.accept_uni(),
        )
        .await?;
        let bytes = tokio::select! {
            biased;
            () = self.cancellation.cancelled() => {
                return Err(DataChannelError::new(
                    DataChannelFailure::Cancelled,
                    "receive_video_stream",
                ));
            }
            result = tokio::time::timeout(
                self.limits.io_timeout,
                recv.read_to_end(self.limits.max_video_stream_bytes),
            ) => match result {
                Ok(Ok(bytes)) => Bytes::from(bytes),
                Ok(Err(_)) => {
                    return Err(DataChannelError::new(
                        DataChannelFailure::ResourceLimit,
                        "receive_video_stream",
                    ));
                }
                Err(_) => {
                    return Err(DataChannelError::new(
                        DataChannelFailure::Timeout,
                        "receive_video_stream",
                    ));
                }
            }
        };
        let frames = parse_video_stream(bytes, self.handshake.session_id, self.limits)?;
        validate_video_frames(&frames, self.handshake.session_id, self.limits)?;
        Ok(frames)
    }

    pub fn close(&self) {
        self.cancellation.cancel();
        self.connection
            .close(VarInt::from_u32(CLOSE_NORMAL), b"closed");
    }

    pub async fn closed(&self) -> DataChannelFailure {
        classify_quinn_connection_failure(&self.connection.closed().await)
    }

    fn close_on_stream_error<T>(&self, result: &DataChannelResult<T>) {
        if result.is_err() {
            self.cancellation.cancel();
            self.connection
                .close(VarInt::from_u32(CLOSE_PROTOCOL), b"stream framing failed");
        }
    }
}

impl Drop for QuicDataChannel {
    fn drop(&mut self) {
        self.cancellation.cancel();
        self.connection
            .close(VarInt::from_u32(CLOSE_NORMAL), b"released");
    }
}

pub fn default_untrusted_client_tls_config() -> DataChannelResult<Arc<RustlsClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = RustlsClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|_| {
            DataChannelError::new(
                DataChannelFailure::InvalidConfiguration,
                "build_untrusted_tls_config",
            )
        })?;
    Ok(Arc::new(
        builder
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth(),
    ))
}

fn make_quinn_client_config(
    tls_config: Arc<RustlsClientConfig>,
    limits: DataChannelLimits,
) -> DataChannelResult<quinn::ClientConfig> {
    let mut tls_config = (*tls_config).clone();
    tls_config.alpn_protocols = vec![QUIC_ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config).map_err(|_| {
        DataChannelError::new(
            DataChannelFailure::InvalidConfiguration,
            "configure_quic_client_tls",
        )
    })?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(make_transport_config(limits)?));
    Ok(config)
}

fn make_quinn_server_config(
    tls_config: Arc<RustlsServerConfig>,
    limits: DataChannelLimits,
) -> DataChannelResult<quinn::ServerConfig> {
    let mut tls_config = (*tls_config).clone();
    tls_config.alpn_protocols = vec![QUIC_ALPN.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).map_err(|_| {
        DataChannelError::new(
            DataChannelFailure::InvalidConfiguration,
            "configure_quic_server_tls",
        )
    })?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport = Arc::new(make_transport_config(limits)?);
    Ok(config)
}

fn make_transport_config(limits: DataChannelLimits) -> DataChannelResult<quinn::TransportConfig> {
    let idle_timeout = limits.idle_timeout.try_into().map_err(|_| {
        DataChannelError::new(
            DataChannelFailure::InvalidConfiguration,
            "configure_quic_idle_timeout",
        )
    })?;
    let mut config = quinn::TransportConfig::default();
    config
        .max_idle_timeout(Some(idle_timeout))
        .keep_alive_interval(Some(limits.keep_alive_interval))
        .max_concurrent_bidi_streams(VarInt::from_u32(limits.max_bidirectional_streams))
        .max_concurrent_uni_streams(VarInt::from_u32(limits.max_unidirectional_streams))
        .stream_receive_window(VarInt::from_u32(limits.stream_receive_window_bytes))
        .receive_window(VarInt::from_u32(limits.connection_receive_window_bytes))
        .send_window(u64::from(limits.connection_receive_window_bytes))
        .datagram_receive_buffer_size(Some(limits.datagram_buffer_bytes))
        .datagram_send_buffer_size(limits.datagram_buffer_bytes);
    Ok(config)
}

async fn await_connection(
    connecting: quinn::Connecting,
    limits: DataChannelLimits,
    cancellation: &TransportCancellation,
) -> DataChannelResult<Connection> {
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(DataChannelError::new(
            DataChannelFailure::Cancelled,
            "establish_quic_connection",
        )),
        result = tokio::time::timeout(limits.connect_timeout, connecting) => match result {
            Ok(Ok(connection)) => Ok(connection),
            Ok(Err(error)) => Err(classify_connection_error(
                error,
                "establish_quic_connection",
            )),
            Err(_) => Err(DataChannelError::new(
                DataChannelFailure::Timeout,
                "establish_quic_connection",
            )),
        }
    }
}

async fn open_controller_streams(
    connection: &Connection,
    handshake: RoleHandshake,
    limits: DataChannelLimits,
    cancellation: &TransportCancellation,
) -> DataChannelResult<HashMap<ChannelId, DuplexStream>> {
    let mut streams = HashMap::with_capacity(RELIABLE_CHANNELS.len());
    for channel in RELIABLE_CHANNELS {
        let (mut send, mut recv) = run_with_deadline(
            limits.handshake_timeout,
            cancellation,
            "open_reliable_stream",
            connection.open_bi(),
        )
        .await?;
        send.set_priority(stream_priority(channel)).map_err(|_| {
            DataChannelError::new(DataChannelFailure::Closed, "prioritize_reliable_stream")
        })?;
        write_stream_preface(&mut send, channel, limits, cancellation).await?;
        if channel == ChannelId::SecureControl {
            write_role_handshake(&mut send, handshake, limits, cancellation).await?;
            let peer = read_role_handshake(&mut recv, limits, cancellation).await?;
            validate_peer_handshake(handshake, peer)?;
        }
        streams.insert(
            channel,
            DuplexStream {
                send: Mutex::new(send),
                recv: Mutex::new(recv),
            },
        );
    }
    Ok(streams)
}

async fn accept_controlled_streams(
    connection: &Connection,
    handshake: RoleHandshake,
    limits: DataChannelLimits,
    cancellation: &TransportCancellation,
) -> DataChannelResult<HashMap<ChannelId, DuplexStream>> {
    let mut streams = HashMap::with_capacity(RELIABLE_CHANNELS.len());
    while streams.len() < RELIABLE_CHANNELS.len() {
        let (mut send, mut recv) = run_with_deadline(
            limits.handshake_timeout,
            cancellation,
            "accept_reliable_stream",
            connection.accept_bi(),
        )
        .await?;
        let channel = read_stream_preface(&mut recv, limits, cancellation).await?;
        if !RELIABLE_CHANNELS.contains(&channel) || streams.contains_key(&channel) {
            return Err(DataChannelError::new(
                DataChannelFailure::Protocol,
                "validate_stream_preface",
            ));
        }
        send.set_priority(stream_priority(channel)).map_err(|_| {
            DataChannelError::new(DataChannelFailure::Closed, "prioritize_reliable_stream")
        })?;
        if channel == ChannelId::SecureControl {
            let peer = read_role_handshake(&mut recv, limits, cancellation).await?;
            validate_peer_handshake(handshake, peer)?;
            write_role_handshake(&mut send, handshake, limits, cancellation).await?;
        } else if !streams.contains_key(&ChannelId::SecureControl) {
            return Err(DataChannelError::new(
                DataChannelFailure::Protocol,
                "order_role_handshake",
            ));
        }
        streams.insert(
            channel,
            DuplexStream {
                send: Mutex::new(send),
                recv: Mutex::new(recv),
            },
        );
    }
    Ok(streams)
}

async fn write_stream_preface(
    send: &mut SendStream,
    channel: ChannelId,
    limits: DataChannelLimits,
    cancellation: &TransportCancellation,
) -> DataChannelResult<()> {
    let mut bytes = [0_u8; STREAM_PREFACE_LEN];
    bytes[..4].copy_from_slice(&STREAM_PREFACE_MAGIC);
    bytes[4..6].copy_from_slice(&(channel as u16).to_be_bytes());
    run_with_deadline(
        limits.handshake_timeout,
        cancellation,
        "write_stream_preface",
        send.write_all(&bytes),
    )
    .await
}

async fn read_stream_preface(
    recv: &mut RecvStream,
    limits: DataChannelLimits,
    cancellation: &TransportCancellation,
) -> DataChannelResult<ChannelId> {
    let mut bytes = [0_u8; STREAM_PREFACE_LEN];
    run_with_deadline(
        limits.handshake_timeout,
        cancellation,
        "read_stream_preface",
        recv.read_exact(&mut bytes),
    )
    .await?;
    if bytes[..4] != STREAM_PREFACE_MAGIC || bytes[6..] != [0, 0] {
        return Err(DataChannelError::new(
            DataChannelFailure::Protocol,
            "decode_stream_preface",
        ));
    }
    ChannelId::try_from(u16::from_be_bytes([bytes[4], bytes[5]]))
        .map_err(|_| DataChannelError::new(DataChannelFailure::Protocol, "decode_stream_preface"))
}

async fn write_role_handshake(
    send: &mut SendStream,
    handshake: RoleHandshake,
    limits: DataChannelLimits,
    cancellation: &TransportCancellation,
) -> DataChannelResult<()> {
    let bytes = encode_role_handshake(handshake);
    run_with_deadline(
        limits.handshake_timeout,
        cancellation,
        "write_role_handshake",
        send.write_all(&bytes),
    )
    .await
}

async fn read_role_handshake(
    recv: &mut RecvStream,
    limits: DataChannelLimits,
    cancellation: &TransportCancellation,
) -> DataChannelResult<RoleHandshake> {
    let mut bytes = [0_u8; ROLE_HANDSHAKE_LEN];
    run_with_deadline(
        limits.handshake_timeout,
        cancellation,
        "read_role_handshake",
        recv.read_exact(&mut bytes),
    )
    .await?;
    decode_role_handshake(bytes)
}

pub(crate) fn encode_role_handshake(handshake: RoleHandshake) -> [u8; ROLE_HANDSHAKE_LEN] {
    let mut bytes = [0_u8; ROLE_HANDSHAKE_LEN];
    bytes[..4].copy_from_slice(&ROLE_HANDSHAKE_MAGIC);
    bytes[4..6].copy_from_slice(&1_u16.to_be_bytes());
    bytes[6] = match handshake.role {
        SessionRole::Controller => 1,
        SessionRole::Controlled => 2,
    };
    bytes[8..].copy_from_slice(&handshake.session_id.to_be_bytes());
    bytes
}

pub(crate) fn decode_role_handshake(
    bytes: [u8; ROLE_HANDSHAKE_LEN],
) -> DataChannelResult<RoleHandshake> {
    if bytes[..4] != ROLE_HANDSHAKE_MAGIC || bytes[4..6] != 1_u16.to_be_bytes() || bytes[7] != 0 {
        return Err(DataChannelError::new(
            DataChannelFailure::Protocol,
            "decode_role_handshake",
        ));
    }
    let role = match bytes[6] {
        1 => SessionRole::Controller,
        2 => SessionRole::Controlled,
        _ => {
            return Err(DataChannelError::new(
                DataChannelFailure::Protocol,
                "decode_role_handshake",
            ));
        }
    };
    Ok(RoleHandshake {
        session_id: u128::from_be_bytes(
            bytes[8..]
                .try_into()
                .expect("role handshake session slice is fixed"),
        ),
        role,
    })
}

pub(crate) fn validate_peer_handshake(
    local: RoleHandshake,
    peer: RoleHandshake,
) -> DataChannelResult<()> {
    if peer.session_id != local.session_id || peer.role != local.expected_peer_role() {
        return Err(DataChannelError::new(
            DataChannelFailure::Authentication,
            "validate_peer_role",
        ));
    }
    Ok(())
}

async fn write_frame<W>(
    writer: &mut W,
    frame: &OpaqueFrame,
    limits: DataChannelLimits,
    cancellation: &TransportCancellation,
    operation: &'static str,
) -> DataChannelResult<()>
where
    W: AsyncWrite + Unpin,
{
    frame.validate_for(frame.header().session_id, limits)?;
    let header = encode_header(frame.header());
    run_with_deadline(limits.io_timeout, cancellation, operation, async {
        writer.write_all(&header).await?;
        writer.write_all(frame.opaque_payload()).await?;
        writer.flush().await
    })
    .await
}

async fn read_frame<R>(
    reader: &mut R,
    session_id: u128,
    limits: DataChannelLimits,
    cancellation: &TransportCancellation,
    operation: &'static str,
) -> DataChannelResult<OpaqueFrame>
where
    R: AsyncRead + Unpin,
{
    let mut header_bytes = [0_u8; HEADER_LEN];
    run_with_deadline(limits.io_timeout, cancellation, operation, async {
        reader.read_exact(&mut header_bytes).await
    })
    .await?;
    let header = decode_header(&header_bytes)
        .map_err(|_| DataChannelError::new(DataChannelFailure::Protocol, operation))?;
    let payload_len = usize::try_from(header.payload_len)
        .map_err(|_| DataChannelError::new(DataChannelFailure::FrameTooLarge, operation))?;
    if payload_len > limits.max_frame_payload_bytes {
        return Err(DataChannelError::new(
            DataChannelFailure::FrameTooLarge,
            operation,
        ));
    }
    let mut payload = vec![0_u8; payload_len];
    run_with_deadline(limits.io_timeout, cancellation, operation, async {
        reader.read_exact(&mut payload).await
    })
    .await?;
    let frame = OpaqueFrame::new(header, payload)?;
    frame.validate_for(session_id, limits)?;
    Ok(frame)
}

fn validate_video_frames(
    frames: &[OpaqueFrame],
    session_id: u128,
    limits: DataChannelLimits,
) -> DataChannelResult<()> {
    if frames.len() < 2 || frames.len() > limits.max_video_stream_messages {
        return Err(DataChannelError::new(
            DataChannelFailure::ResourceLimit,
            "validate_video_stream",
        ));
    }
    for (index, frame) in frames.iter().enumerate() {
        frame.validate_for(session_id, limits)?;
        let expected_kind = if index == 0 {
            MessageKind::VideoFrameInfo
        } else {
            MessageKind::VideoFrameData
        };
        if frame.header().channel_id != ChannelId::Video || frame.header().kind != expected_kind {
            return Err(DataChannelError::new(
                DataChannelFailure::Protocol,
                "validate_video_stream",
            ));
        }
    }
    Ok(())
}

fn parse_video_stream(
    bytes: Bytes,
    session_id: u128,
    limits: DataChannelLimits,
) -> DataChannelResult<Vec<OpaqueFrame>> {
    let mut offset = 0_usize;
    let mut frames = Vec::new();
    while offset < bytes.len() {
        if frames.len() >= limits.max_video_stream_messages
            || bytes.len().saturating_sub(offset) < HEADER_LEN
        {
            return Err(DataChannelError::new(
                DataChannelFailure::ResourceLimit,
                "parse_video_stream",
            ));
        }
        let header = decode_header(&bytes[offset..offset + HEADER_LEN]).map_err(|_| {
            DataChannelError::new(DataChannelFailure::Protocol, "parse_video_stream")
        })?;
        let payload_len = usize::try_from(header.payload_len).map_err(|_| {
            DataChannelError::new(DataChannelFailure::FrameTooLarge, "parse_video_stream")
        })?;
        let end = offset
            .checked_add(HEADER_LEN)
            .and_then(|value| value.checked_add(payload_len))
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| {
                DataChannelError::new(DataChannelFailure::Protocol, "parse_video_stream")
            })?;
        frames.push(OpaqueFrame::from_wire_bytes(
            bytes.slice(offset..end),
            session_id,
            limits,
        )?);
        offset = end;
    }
    Ok(frames)
}

const fn stream_priority(channel: ChannelId) -> i32 {
    match channel {
        ChannelId::SecureControl | ChannelId::InputReliable | ChannelId::DeviceControl => 100,
        ChannelId::MediaControl => 80,
        ChannelId::Video => 60,
        ChannelId::Clipboard => 40,
        ChannelId::FileTransfer => 20,
        ChannelId::Telemetry => 0,
        ChannelId::InputRealtime => 100,
    }
}

fn classify_connect_error(error: quinn::ConnectError) -> DataChannelError {
    let kind = match error {
        quinn::ConnectError::InvalidServerName(_)
        | quinn::ConnectError::InvalidRemoteAddress(_) => DataChannelFailure::InvalidAddress,
        quinn::ConnectError::EndpointStopping => DataChannelFailure::Closed,
        quinn::ConnectError::CidsExhausted => DataChannelFailure::ResourceLimit,
        quinn::ConnectError::NoDefaultClientConfig | quinn::ConnectError::UnsupportedVersion => {
            DataChannelFailure::InvalidConfiguration
        }
    };
    DataChannelError::new(kind, "start_quic_connection")
}

fn classify_connection_error(
    error: quinn::ConnectionError,
    operation: &'static str,
) -> DataChannelError {
    DataChannelError::new(classify_quinn_connection_failure(&error), operation)
}

fn classify_quinn_connection_failure(error: &quinn::ConnectionError) -> DataChannelFailure {
    match error {
        quinn::ConnectionError::TransportError(error)
            if (0x100..0x200).contains(&u64::from(error.code)) =>
        {
            DataChannelFailure::Authentication
        }
        quinn::ConnectionError::TimedOut => DataChannelFailure::Timeout,
        quinn::ConnectionError::LocallyClosed | quinn::ConnectionError::ApplicationClosed(_) => {
            DataChannelFailure::Closed
        }
        quinn::ConnectionError::TransportError(_)
        | quinn::ConnectionError::VersionMismatch
        | quinn::ConnectionError::ConnectionClosed(_)
        | quinn::ConnectionError::Reset => DataChannelFailure::Connection,
        quinn::ConnectionError::CidsExhausted => DataChannelFailure::ResourceLimit,
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use remote_protocol::{MessageHeader, MessageKind};

    use super::*;
    use crate::test_tls::{client_config, server_config};

    const SESSION_ID: u128 = 0x1234;

    fn frame(
        kind: MessageKind,
        channel: ChannelId,
        sequence: u64,
        payload: &'static [u8],
    ) -> OpaqueFrame {
        OpaqueFrame::new(
            MessageHeader::new_on_channel(
                kind,
                channel,
                SESSION_ID,
                sequence,
                u32::try_from(payload.len()).expect("test payload length"),
            )
            .expect("header"),
            Bytes::from_static(payload),
        )
        .expect("frame")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn localhost_quic_carries_streams_datagrams_and_video() {
        let limits = DataChannelLimits::default();
        let server = QuicServerEndpoint::bind(
            "127.0.0.1:0".parse().expect("server address"),
            server_config(),
            limits,
        )
        .expect("server");
        let server_addr = server.local_addr().expect("server local address");
        let server_cancel = TransportCancellation::default();
        let server_task = tokio::spawn(async move {
            server
                .accept(
                    TransportKind::LanDirect,
                    RoleHandshake::new(SESSION_ID, SessionRole::Controlled),
                    &server_cancel,
                )
                .await
                .expect("server channel")
        });

        let client = QuicClientEndpoint::bind(
            "127.0.0.1:0".parse().expect("client address"),
            client_config(),
            limits,
        )
        .expect("client");
        let cancel = TransportCancellation::default();
        let client_channel = client
            .connect(
                server_addr,
                "localhost",
                TransportKind::LanDirect,
                RoleHandshake::new(SESSION_ID, SessionRole::Controller),
                &cancel,
            )
            .await
            .expect("client channel");
        let server_channel = server_task.await.expect("server task");

        let control = frame(
            MessageKind::KeyConfirm,
            ChannelId::SecureControl,
            1,
            b"opaque-control",
        );
        client_channel
            .send_reliable(&control)
            .await
            .expect("send control");
        assert_eq!(
            server_channel
                .receive_reliable(ChannelId::SecureControl)
                .await
                .expect("receive control"),
            control
        );

        let datagram = frame(
            MessageKind::InputEvent,
            ChannelId::InputRealtime,
            2,
            b"opaque-move",
        );
        client_channel
            .send_datagram(&datagram)
            .expect("send datagram");
        assert_eq!(
            server_channel
                .receive_datagram()
                .await
                .expect("receive datagram"),
            datagram
        );

        let video = vec![
            frame(
                MessageKind::VideoFrameInfo,
                ChannelId::Video,
                3,
                b"opaque-info",
            ),
            frame(
                MessageKind::VideoFrameData,
                ChannelId::Video,
                4,
                b"opaque-video-data",
            ),
        ];
        server_channel
            .send_video_frame(&video)
            .await
            .expect("send video");
        assert_eq!(
            client_channel
                .receive_video_frame()
                .await
                .expect("receive video"),
            video
        );

        client_channel.close();
        assert_eq!(server_channel.closed().await, DataChannelFailure::Closed);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn default_config_rejects_untrusted_quic_certificate() {
        let limits = DataChannelLimits {
            connect_timeout: std::time::Duration::from_secs(1),
            ..DataChannelLimits::default()
        };
        let server = QuicServerEndpoint::bind(
            "127.0.0.1:0".parse().expect("server address"),
            server_config(),
            limits,
        )
        .expect("server");
        let server_addr = server.local_addr().expect("server local address");
        let server_cancel = TransportCancellation::default();
        let server_task = tokio::spawn(async move {
            server
                .accept(
                    TransportKind::UdpP2p,
                    RoleHandshake::new(SESSION_ID, SessionRole::Controlled),
                    &server_cancel,
                )
                .await
        });
        let client = QuicClientEndpoint::bind(
            "127.0.0.1:0".parse().expect("client address"),
            default_untrusted_client_tls_config().expect("default config"),
            limits,
        )
        .expect("client");
        let result = client
            .connect(
                server_addr,
                "localhost",
                TransportKind::UdpP2p,
                RoleHandshake::new(SESSION_ID, SessionRole::Controller),
                &TransportCancellation::default(),
            )
            .await;
        assert!(matches!(
            result,
            Err(ref error) if error.kind() == DataChannelFailure::Authentication
        ));
        let _ = server_task.await.expect("server task finishes");
    }

    #[test]
    fn maps_only_udp_quic_paths_and_fixed_channels() {
        assert!(supports_quic_data_path(TransportKind::LanDirect));
        assert!(supports_quic_data_path(TransportKind::UdpP2p));
        assert!(supports_quic_data_path(TransportKind::QuicRelay));
        assert!(!supports_quic_data_path(TransportKind::Tls443Relay));
        assert_eq!(
            quic_route(ChannelId::InputReliable),
            QuicFrameRoute::ReliableStream(ChannelId::InputReliable)
        );
        assert_eq!(
            quic_route(ChannelId::Video),
            QuicFrameRoute::VideoFrameStream
        );
        assert_eq!(quic_route(ChannelId::Telemetry), QuicFrameRoute::Datagram);
    }
}
