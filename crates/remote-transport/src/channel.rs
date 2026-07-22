use std::{
    fmt,
    future::Future,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use bytes::{Bytes, BytesMut};
use remote_protocol::{
    decode_header, encode_header, ChannelId, MessageHeader, SessionRole, HEADER_LEN,
    MAX_SECURE_SEQUENCE,
};
use tokio::sync::Notify;

use crate::TransportKind;

pub const RELIABLE_CHANNELS: [ChannelId; 6] = [
    ChannelId::SecureControl,
    ChannelId::InputReliable,
    ChannelId::MediaControl,
    ChannelId::Clipboard,
    ChannelId::FileTransfer,
    ChannelId::DeviceControl,
];

pub const DEFAULT_MAX_FRAME_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_MAX_VIDEO_STREAM_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_VIDEO_STREAM_MESSAGES: usize = 1_024;
pub const DEFAULT_MAX_DATAGRAM_BYTES: usize = 1_200;
pub const DEFAULT_STREAM_RECEIVE_WINDOW_BYTES: u32 = 2 * 1024 * 1024;
pub const DEFAULT_CONNECTION_RECEIVE_WINDOW_BYTES: u32 = 16 * 1024 * 1024;
pub const DEFAULT_DATAGRAM_BUFFER_BYTES: usize = 256 * 1024;
pub const DEFAULT_MAX_BIDIRECTIONAL_STREAMS: u32 = 8;
pub const DEFAULT_MAX_UNIDIRECTIONAL_STREAMS: u32 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataChannelLimits {
    pub connect_timeout: Duration,
    pub handshake_timeout: Duration,
    pub io_timeout: Duration,
    pub idle_timeout: Duration,
    pub keep_alive_interval: Duration,
    pub max_frame_payload_bytes: usize,
    pub max_video_stream_bytes: usize,
    pub max_video_stream_messages: usize,
    pub max_datagram_bytes: usize,
    pub stream_receive_window_bytes: u32,
    pub connection_receive_window_bytes: u32,
    pub datagram_buffer_bytes: usize,
    pub max_bidirectional_streams: u32,
    pub max_unidirectional_streams: u32,
}

impl Default for DataChannelLimits {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(3),
            handshake_timeout: Duration::from_secs(3),
            io_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(30),
            keep_alive_interval: Duration::from_secs(10),
            max_frame_payload_bytes: DEFAULT_MAX_FRAME_PAYLOAD_BYTES,
            max_video_stream_bytes: DEFAULT_MAX_VIDEO_STREAM_BYTES,
            max_video_stream_messages: DEFAULT_MAX_VIDEO_STREAM_MESSAGES,
            max_datagram_bytes: DEFAULT_MAX_DATAGRAM_BYTES,
            stream_receive_window_bytes: DEFAULT_STREAM_RECEIVE_WINDOW_BYTES,
            connection_receive_window_bytes: DEFAULT_CONNECTION_RECEIVE_WINDOW_BYTES,
            datagram_buffer_bytes: DEFAULT_DATAGRAM_BUFFER_BYTES,
            max_bidirectional_streams: DEFAULT_MAX_BIDIRECTIONAL_STREAMS,
            max_unidirectional_streams: DEFAULT_MAX_UNIDIRECTIONAL_STREAMS,
        }
    }
}

impl DataChannelLimits {
    pub fn validate(self) -> DataChannelResult<Self> {
        if self.connect_timeout.is_zero()
            || self.handshake_timeout.is_zero()
            || self.io_timeout.is_zero()
            || self.idle_timeout.is_zero()
            || self.keep_alive_interval.is_zero()
            || self.keep_alive_interval >= self.idle_timeout
            || self.max_frame_payload_bytes == 0
            || self.max_video_stream_bytes < HEADER_LEN
            || self.max_video_stream_messages < 2
            || self.max_datagram_bytes < HEADER_LEN
            || self.stream_receive_window_bytes == 0
            || self.connection_receive_window_bytes < self.stream_receive_window_bytes
            || self.datagram_buffer_bytes < self.max_datagram_bytes
            || self.max_bidirectional_streams < RELIABLE_CHANNELS.len() as u32
            || self.max_unidirectional_streams == 0
        {
            return Err(DataChannelError::new(
                DataChannelFailure::InvalidConfiguration,
                "validate_limits",
            ));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataChannelFailure {
    Cancelled,
    Timeout,
    InvalidAddress,
    Authentication,
    Connection,
    Closed,
    Protocol,
    FrameTooLarge,
    ResourceLimit,
    DatagramUnavailable,
    Backpressure,
    InvalidConfiguration,
    Io,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{kind:?} during {operation}")]
pub struct DataChannelError {
    kind: DataChannelFailure,
    operation: &'static str,
}

impl DataChannelError {
    pub const fn new(kind: DataChannelFailure, operation: &'static str) -> Self {
        Self { kind, operation }
    }

    pub const fn kind(&self) -> DataChannelFailure {
        self.kind
    }

    pub const fn operation(&self) -> &'static str {
        self.operation
    }
}

pub type DataChannelResult<T> = Result<T, DataChannelError>;

#[derive(Debug, Clone, Default)]
pub struct TransportCancellation {
    inner: Arc<CancellationInner>,
}

#[derive(Debug, Default)]
struct CancellationInner {
    cancelled: AtomicBool,
    notify: Notify,
}

impl TransportCancellation {
    pub fn cancel(&self) {
        if !self.inner.cancelled.swap(true, Ordering::AcqRel) {
            self.inner.notify.notify_waiters();
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    pub async fn cancelled(&self) {
        loop {
            let notified = self.inner.notify.notified();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct OpaqueFrame {
    header: MessageHeader,
    payload: Bytes,
}

impl fmt::Debug for OpaqueFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueFrame")
            .field("header", &self.header)
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl OpaqueFrame {
    pub fn new(header: MessageHeader, payload: impl Into<Bytes>) -> DataChannelResult<Self> {
        let payload = payload.into();
        header
            .validate_kind_channel()
            .map_err(|_| DataChannelError::new(DataChannelFailure::Protocol, "validate_frame"))?;
        if usize::try_from(header.payload_len).ok() != Some(payload.len())
            || header.sequence > MAX_SECURE_SEQUENCE
        {
            return Err(DataChannelError::new(
                DataChannelFailure::Protocol,
                "validate_frame",
            ));
        }
        Ok(Self { header, payload })
    }

    pub const fn header(&self) -> MessageHeader {
        self.header
    }

    pub fn opaque_payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn wire_len(&self) -> usize {
        HEADER_LEN.saturating_add(self.payload.len())
    }

    pub fn to_wire_bytes(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(self.wire_len());
        bytes.extend_from_slice(&encode_header(self.header));
        bytes.extend_from_slice(&self.payload);
        bytes.freeze()
    }

    pub(crate) fn validate_for(
        &self,
        session_id: u128,
        limits: DataChannelLimits,
    ) -> DataChannelResult<()> {
        if self.header.session_id != session_id {
            return Err(DataChannelError::new(
                DataChannelFailure::Protocol,
                "validate_session",
            ));
        }
        if self.payload.len() > limits.max_frame_payload_bytes {
            return Err(DataChannelError::new(
                DataChannelFailure::FrameTooLarge,
                "validate_frame",
            ));
        }
        Ok(())
    }

    pub(crate) fn from_wire_bytes(
        bytes: Bytes,
        session_id: u128,
        limits: DataChannelLimits,
    ) -> DataChannelResult<Self> {
        if bytes.len() < HEADER_LEN {
            return Err(DataChannelError::new(
                DataChannelFailure::Protocol,
                "decode_frame",
            ));
        }
        let header = decode_header(&bytes[..HEADER_LEN]).map_err(|_| {
            DataChannelError::new(DataChannelFailure::Protocol, "decode_frame_header")
        })?;
        let payload_len = usize::try_from(header.payload_len).map_err(|_| {
            DataChannelError::new(DataChannelFailure::FrameTooLarge, "decode_frame_length")
        })?;
        if payload_len > limits.max_frame_payload_bytes {
            return Err(DataChannelError::new(
                DataChannelFailure::FrameTooLarge,
                "decode_frame_length",
            ));
        }
        if bytes.len() != HEADER_LEN.saturating_add(payload_len) {
            return Err(DataChannelError::new(
                DataChannelFailure::Protocol,
                "decode_frame_length",
            ));
        }
        let frame = Self::new(header, bytes.slice(HEADER_LEN..))?;
        frame.validate_for(session_id, limits)?;
        Ok(frame)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleHandshake {
    pub session_id: u128,
    pub role: SessionRole,
}

impl RoleHandshake {
    pub const fn new(session_id: u128, role: SessionRole) -> Self {
        Self { session_id, role }
    }

    pub const fn expected_peer_role(self) -> SessionRole {
        match self.role {
            SessionRole::Controller => SessionRole::Controlled,
            SessionRole::Controlled => SessionRole::Controller,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicFrameRoute {
    ReliableStream(ChannelId),
    VideoFrameStream,
    Datagram,
}

pub fn quic_route(channel: ChannelId) -> QuicFrameRoute {
    match channel {
        ChannelId::Video => QuicFrameRoute::VideoFrameStream,
        ChannelId::InputRealtime | ChannelId::Telemetry => QuicFrameRoute::Datagram,
        channel => QuicFrameRoute::ReliableStream(channel),
    }
}

pub fn supports_quic_data_path(kind: TransportKind) -> bool {
    matches!(
        kind,
        TransportKind::LanDirect | TransportKind::UdpP2p | TransportKind::QuicRelay
    )
}

pub(crate) async fn run_with_deadline<T, E, F>(
    timeout: Duration,
    cancellation: &TransportCancellation,
    operation: &'static str,
    future: F,
) -> DataChannelResult<T>
where
    F: Future<Output = Result<T, E>>,
{
    tokio::select! {
        biased;
        () = cancellation.cancelled() => Err(DataChannelError::new(
            DataChannelFailure::Cancelled,
            operation,
        )),
        result = tokio::time::timeout(timeout, future) => match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(_)) => Err(DataChannelError::new(DataChannelFailure::Io, operation)),
            Err(_) => Err(DataChannelError::new(DataChannelFailure::Timeout, operation)),
        },
    }
}

impl From<DataChannelError> for crate::TransportError {
    fn from(value: DataChannelError) -> Self {
        match value.kind() {
            DataChannelFailure::Cancelled | DataChannelFailure::Closed => Self::Closed,
            DataChannelFailure::Backpressure => Self::Backpressure,
            DataChannelFailure::InvalidConfiguration | DataChannelFailure::Protocol => {
                Self::InvalidState
            }
            _ => Self::Io(value.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use remote_protocol::{MessageKind, PROTOCOL_VERSION};

    use super::*;

    #[test]
    fn opaque_frame_debug_never_prints_payload() {
        let frame = OpaqueFrame::new(
            MessageHeader::new(MessageKind::KeyConfirm, 7, 1, 13),
            Bytes::from_static(b"secret-marker"),
        )
        .expect("frame");
        let debug = format!("{frame:?}");
        assert!(!debug.contains("secret-marker"));
        assert!(debug.contains("payload_len"));
    }

    #[test]
    fn rejects_oversized_and_exhausted_sequence() {
        let limits = DataChannelLimits {
            max_frame_payload_bytes: 1,
            ..DataChannelLimits::default()
        };
        let frame = OpaqueFrame::new(
            MessageHeader::new(MessageKind::KeyConfirm, 7, 1, 2),
            Bytes::from_static(b"xx"),
        )
        .expect("shape-valid frame");
        assert_eq!(
            frame.validate_for(7, limits).map_err(|error| error.kind()),
            Err(DataChannelFailure::FrameTooLarge)
        );

        let exhausted = MessageHeader {
            version: PROTOCOL_VERSION,
            kind: MessageKind::KeyConfirm,
            flags: 0,
            channel_id: ChannelId::SecureControl,
            session_id: 7,
            sequence: MAX_SECURE_SEQUENCE + 1,
            payload_len: 0,
        };
        assert_eq!(
            OpaqueFrame::new(exhausted, Bytes::new()).map_err(|error| error.kind()),
            Err(DataChannelFailure::Protocol)
        );
    }

    #[tokio::test]
    async fn cancellation_wakes_waiters() {
        let cancellation = TransportCancellation::default();
        let waiter = cancellation.clone();
        let task = tokio::spawn(async move { waiter.cancelled().await });
        cancellation.cancel();
        task.await.expect("waiter");
        assert!(cancellation.is_cancelled());
    }
}
