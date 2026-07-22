use std::{net::SocketAddr, sync::Arc};

use bytes::Bytes;
use remote_protocol::{decode_header, encode_header, HEADER_LEN};
use rustls::{
    pki_types::ServerName, ClientConfig as RustlsClientConfig, ServerConfig as RustlsServerConfig,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};

use crate::{
    quic::{decode_role_handshake, encode_role_handshake, validate_peer_handshake},
    run_with_deadline, DataChannelError, DataChannelFailure, DataChannelLimits, DataChannelResult,
    OpaqueFrame, RoleHandshake, TransportCancellation,
};

const TLS_FALLBACK_ALPN: &[u8] = b"rctl-tls-fallback-v1";
const ROLE_HANDSHAKE_LEN: usize = 24;

type TlsReadHalf = ReadHalf<TlsStream<TcpStream>>;
type TlsWriteHalf = WriteHalf<TlsStream<TcpStream>>;

pub struct TlsFallbackListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
    limits: DataChannelLimits,
}

impl TlsFallbackListener {
    pub async fn bind(
        local_addr: SocketAddr,
        tls_config: Arc<RustlsServerConfig>,
        limits: DataChannelLimits,
    ) -> DataChannelResult<Self> {
        let limits = limits.validate()?;
        let mut tls_config = (*tls_config).clone();
        tls_config.alpn_protocols = vec![TLS_FALLBACK_ALPN.to_vec()];
        let listener = TcpListener::bind(local_addr).await.map_err(|_| {
            DataChannelError::new(DataChannelFailure::InvalidAddress, "bind_tls_fallback")
        })?;
        Ok(Self {
            listener,
            acceptor: TlsAcceptor::from(Arc::new(tls_config)),
            limits,
        })
    }

    pub fn local_addr(&self) -> DataChannelResult<SocketAddr> {
        self.listener
            .local_addr()
            .map_err(|_| DataChannelError::new(DataChannelFailure::Io, "tls_fallback_local_addr"))
    }

    pub async fn accept(
        &self,
        handshake: RoleHandshake,
        cancellation: &TransportCancellation,
    ) -> DataChannelResult<TlsFallbackChannel> {
        let (stream, _) = run_with_deadline(
            self.limits.connect_timeout,
            cancellation,
            "accept_tls_fallback_tcp",
            self.listener.accept(),
        )
        .await?;
        configure_tcp(&stream)?;
        let stream = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                return Err(DataChannelError::new(
                    DataChannelFailure::Cancelled,
                    "accept_tls_fallback",
                ));
            }
            result = tokio::time::timeout(
                self.limits.handshake_timeout,
                self.acceptor.accept(stream),
            ) => match result {
                Ok(Ok(stream)) => TlsStream::Server(stream),
                Ok(Err(_)) => {
                    return Err(DataChannelError::new(
                        DataChannelFailure::Authentication,
                        "accept_tls_fallback",
                    ));
                }
                Err(_) => {
                    return Err(DataChannelError::new(
                        DataChannelFailure::Timeout,
                        "accept_tls_fallback",
                    ));
                }
            }
        };
        TlsFallbackChannel::establish(stream, handshake, self.limits, cancellation).await
    }
}

#[derive(Debug)]
pub struct TlsFallbackChannel {
    reader: Mutex<TlsReadHalf>,
    writer: Mutex<TlsWriteHalf>,
    handshake: RoleHandshake,
    limits: DataChannelLimits,
    cancellation: TransportCancellation,
}

impl TlsFallbackChannel {
    pub async fn connect(
        local_addr: Option<SocketAddr>,
        remote_addr: SocketAddr,
        server_name: &str,
        tls_config: Arc<RustlsClientConfig>,
        handshake: RoleHandshake,
        limits: DataChannelLimits,
        cancellation: &TransportCancellation,
    ) -> DataChannelResult<Self> {
        let limits = limits.validate()?;
        let stream = if let Some(local_addr) = local_addr {
            let socket = match local_addr {
                SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4(),
                SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6(),
            }
            .map_err(|_| {
                DataChannelError::new(
                    DataChannelFailure::InvalidAddress,
                    "create_tls_fallback_socket",
                )
            })?;
            socket.bind(local_addr).map_err(|_| {
                DataChannelError::new(
                    DataChannelFailure::InvalidAddress,
                    "bind_tls_fallback_client",
                )
            })?;
            run_with_deadline(
                limits.connect_timeout,
                cancellation,
                "connect_tls_fallback_tcp",
                socket.connect(remote_addr),
            )
            .await?
        } else {
            run_with_deadline(
                limits.connect_timeout,
                cancellation,
                "connect_tls_fallback_tcp",
                TcpStream::connect(remote_addr),
            )
            .await?
        };
        configure_tcp(&stream)?;

        let mut tls_config = (*tls_config).clone();
        tls_config.alpn_protocols = vec![TLS_FALLBACK_ALPN.to_vec()];
        let server_name = ServerName::try_from(server_name.to_owned()).map_err(|_| {
            DataChannelError::new(
                DataChannelFailure::InvalidAddress,
                "validate_tls_fallback_server_name",
            )
        })?;
        let connector = TlsConnector::from(Arc::new(tls_config));
        let stream = tokio::select! {
            biased;
            () = cancellation.cancelled() => {
                return Err(DataChannelError::new(
                    DataChannelFailure::Cancelled,
                    "connect_tls_fallback",
                ));
            }
            result = tokio::time::timeout(
                limits.handshake_timeout,
                connector.connect(server_name, stream),
            ) => match result {
                Ok(Ok(stream)) => TlsStream::Client(stream),
                Ok(Err(_)) => {
                    return Err(DataChannelError::new(
                        DataChannelFailure::Authentication,
                        "connect_tls_fallback",
                    ));
                }
                Err(_) => {
                    return Err(DataChannelError::new(
                        DataChannelFailure::Timeout,
                        "connect_tls_fallback",
                    ));
                }
            }
        };
        Self::establish(stream, handshake, limits, cancellation).await
    }

    async fn establish(
        mut stream: TlsStream<TcpStream>,
        handshake: RoleHandshake,
        limits: DataChannelLimits,
        cancellation: &TransportCancellation,
    ) -> DataChannelResult<Self> {
        match handshake.role {
            remote_protocol::SessionRole::Controller => {
                write_role(&mut stream, handshake, limits, cancellation).await?;
                let peer = read_role(&mut stream, limits, cancellation).await?;
                validate_peer_handshake(handshake, peer)?;
            }
            remote_protocol::SessionRole::Controlled => {
                let peer = read_role(&mut stream, limits, cancellation).await?;
                validate_peer_handshake(handshake, peer)?;
                write_role(&mut stream, handshake, limits, cancellation).await?;
            }
        }
        let (reader, writer) = tokio::io::split(stream);
        Ok(Self {
            reader: Mutex::new(reader),
            writer: Mutex::new(writer),
            handshake,
            limits,
            cancellation: TransportCancellation::default(),
        })
    }

    pub const fn local_handshake(&self) -> RoleHandshake {
        self.handshake
    }

    pub async fn send_frame(&self, frame: &OpaqueFrame) -> DataChannelResult<()> {
        frame.validate_for(self.handshake.session_id, self.limits)?;
        let header = encode_header(frame.header());
        let mut writer = self.writer.lock().await;
        let result = run_with_deadline(
            self.limits.io_timeout,
            &self.cancellation,
            "send_tls_fallback_frame",
            async {
                writer.write_all(&header).await?;
                writer.write_all(frame.opaque_payload()).await?;
                writer.flush().await
            },
        )
        .await;
        if result.is_err() {
            self.cancellation.cancel();
        }
        result
    }

    pub async fn receive_frame(&self) -> DataChannelResult<OpaqueFrame> {
        let mut reader = self.reader.lock().await;
        let mut header_bytes = [0_u8; HEADER_LEN];
        run_with_deadline(
            self.limits.io_timeout,
            &self.cancellation,
            "receive_tls_fallback_header",
            reader.read_exact(&mut header_bytes),
        )
        .await?;
        let header = decode_header(&header_bytes).map_err(|_| {
            DataChannelError::new(DataChannelFailure::Protocol, "decode_tls_fallback_header")
        })?;
        let payload_len = usize::try_from(header.payload_len).map_err(|_| {
            DataChannelError::new(
                DataChannelFailure::FrameTooLarge,
                "receive_tls_fallback_frame",
            )
        })?;
        if payload_len > self.limits.max_frame_payload_bytes {
            self.cancellation.cancel();
            return Err(DataChannelError::new(
                DataChannelFailure::FrameTooLarge,
                "receive_tls_fallback_frame",
            ));
        }
        let mut payload = vec![0_u8; payload_len];
        run_with_deadline(
            self.limits.io_timeout,
            &self.cancellation,
            "receive_tls_fallback_payload",
            reader.read_exact(&mut payload),
        )
        .await?;
        let frame = OpaqueFrame::new(header, Bytes::from(payload))?;
        frame.validate_for(self.handshake.session_id, self.limits)?;
        Ok(frame)
    }

    pub async fn close(&self) -> DataChannelResult<()> {
        self.cancellation.cancel();
        let mut writer = self.writer.lock().await;
        tokio::time::timeout(self.limits.io_timeout, writer.shutdown())
            .await
            .map_err(|_| DataChannelError::new(DataChannelFailure::Timeout, "close_tls_fallback"))?
            .map_err(|_| DataChannelError::new(DataChannelFailure::Io, "close_tls_fallback"))
    }
}

impl Drop for TlsFallbackChannel {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

async fn write_role(
    stream: &mut TlsStream<TcpStream>,
    handshake: RoleHandshake,
    limits: DataChannelLimits,
    cancellation: &TransportCancellation,
) -> DataChannelResult<()> {
    let bytes = encode_role_handshake(handshake);
    run_with_deadline(
        limits.handshake_timeout,
        cancellation,
        "write_tls_fallback_role",
        async {
            stream.write_all(&bytes).await?;
            stream.flush().await
        },
    )
    .await
}

async fn read_role(
    stream: &mut TlsStream<TcpStream>,
    limits: DataChannelLimits,
    cancellation: &TransportCancellation,
) -> DataChannelResult<RoleHandshake> {
    let mut bytes = [0_u8; ROLE_HANDSHAKE_LEN];
    run_with_deadline(
        limits.handshake_timeout,
        cancellation,
        "read_tls_fallback_role",
        stream.read_exact(&mut bytes),
    )
    .await?;
    decode_role_handshake(bytes)
}

fn configure_tcp(stream: &TcpStream) -> DataChannelResult<()> {
    stream
        .set_nodelay(true)
        .map_err(|_| DataChannelError::new(DataChannelFailure::Io, "configure_tls_fallback_tcp"))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use remote_protocol::{ChannelId, MessageHeader, MessageKind, SessionRole};

    use super::*;
    use crate::{
        default_untrusted_client_tls_config,
        test_tls::{client_config, server_config},
    };

    const SESSION_ID: u128 = 0x5678;

    fn opaque_control() -> OpaqueFrame {
        let payload = Bytes::from_static(b"already-e2ee-ciphertext");
        OpaqueFrame::new(
            MessageHeader::new(
                MessageKind::KeyConfirm,
                SESSION_ID,
                1,
                u32::try_from(payload.len()).expect("payload length"),
            ),
            payload,
        )
        .expect("frame")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn localhost_tls_fallback_frames_opaque_data_both_directions() {
        let limits = DataChannelLimits::default();
        let listener = TlsFallbackListener::bind(
            "127.0.0.1:0".parse().expect("listen address"),
            server_config(),
            limits,
        )
        .await
        .expect("listener");
        let address = listener.local_addr().expect("local address");
        let server_task = tokio::spawn(async move {
            listener
                .accept(
                    RoleHandshake::new(SESSION_ID, SessionRole::Controlled),
                    &TransportCancellation::default(),
                )
                .await
                .expect("server channel")
        });
        let client = TlsFallbackChannel::connect(
            None,
            address,
            "localhost",
            client_config(),
            RoleHandshake::new(SESSION_ID, SessionRole::Controller),
            limits,
            &TransportCancellation::default(),
        )
        .await
        .expect("client channel");
        let server = server_task.await.expect("server task");

        let outbound = opaque_control();
        client.send_frame(&outbound).await.expect("client send");
        assert_eq!(
            server.receive_frame().await.expect("server receive"),
            outbound
        );

        let response_payload = Bytes::from_static(b"opaque-stats");
        let response = OpaqueFrame::new(
            MessageHeader::new(
                MessageKind::Stats,
                SESSION_ID,
                2,
                u32::try_from(response_payload.len()).expect("payload length"),
            ),
            response_payload,
        )
        .expect("response frame");
        assert_eq!(response.header().channel_id, ChannelId::Telemetry);
        server.send_frame(&response).await.expect("server send");
        assert_eq!(
            client.receive_frame().await.expect("client receive"),
            response
        );
        client.close().await.expect("client close");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn default_config_rejects_untrusted_tls_certificate() {
        let limits = DataChannelLimits {
            connect_timeout: std::time::Duration::from_secs(1),
            ..DataChannelLimits::default()
        };
        let listener = TlsFallbackListener::bind(
            "127.0.0.1:0".parse().expect("listen address"),
            server_config(),
            limits,
        )
        .await
        .expect("listener");
        let address = listener.local_addr().expect("local address");
        let server_task = tokio::spawn(async move {
            listener
                .accept(
                    RoleHandshake::new(SESSION_ID, SessionRole::Controlled),
                    &TransportCancellation::default(),
                )
                .await
        });
        let result = TlsFallbackChannel::connect(
            None,
            address,
            "localhost",
            default_untrusted_client_tls_config().expect("default config"),
            RoleHandshake::new(SESSION_ID, SessionRole::Controller),
            limits,
            &TransportCancellation::default(),
        )
        .await;
        assert!(matches!(
            result,
            Err(ref error) if error.kind() == DataChannelFailure::Authentication
        ));
        assert!(server_task.await.expect("server task").is_err());
    }
}
