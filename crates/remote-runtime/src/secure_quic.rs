use bytes::Bytes;
use remote_core::{SecureSession, SecureSessionError};
use remote_protocol::{
    ChannelId, InputEvent, KeyframeRequest, MessageKind, SessionRole, VideoFrameInfo,
};
use remote_transport::{
    quic_route, DataChannelError, OpaqueFrame, QuicDataChannel, QuicFrameRoute,
};
use serde::{de::DeserializeOwned, Serialize};
use tokio::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum SecureQuicError {
    #[error("secure session binding does not match the QUIC channel")]
    BindingMismatch,
    #[error("message is not valid for the selected data channel")]
    InvalidMessage,
    #[error("secure session failed: {0:?}")]
    Secure(SecureSessionError),
    #[error("QUIC data channel failed: {0}")]
    Transport(#[from] DataChannelError),
    #[error("business payload serialization failed")]
    Serialization,
}

pub type SecureQuicResult<T> = Result<T, SecureQuicError>;

impl From<SecureSessionError> for SecureQuicError {
    fn from(value: SecureSessionError) -> Self {
        Self::Secure(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedVideoFrame {
    pub info: VideoFrameInfo,
    pub annex_b: Vec<u8>,
}

#[derive(Debug)]
pub struct SecureQuicChannel {
    session_id: u128,
    local_role: SessionRole,
    channel: QuicDataChannel,
    secure_session: Mutex<SecureSession>,
}

impl SecureQuicChannel {
    pub fn new(channel: QuicDataChannel, secure_session: SecureSession) -> SecureQuicResult<Self> {
        let handshake = channel.local_handshake();
        if handshake.session_id != secure_session.session_id()
            || handshake.role != secure_session.local_role()
        {
            return Err(SecureQuicError::BindingMismatch);
        }
        Ok(Self {
            session_id: handshake.session_id,
            local_role: handshake.role,
            channel,
            secure_session: Mutex::new(secure_session),
        })
    }

    pub const fn session_id(&self) -> u128 {
        self.session_id
    }

    pub const fn local_role(&self) -> SessionRole {
        self.local_role
    }

    pub async fn send_input(&self, event: &InputEvent, realtime: bool) -> SecureQuicResult<()> {
        if self.local_role != SessionRole::Controller
            || event.session_id.as_u128() != self.session_id
        {
            return Err(SecureQuicError::BindingMismatch);
        }
        event
            .validate()
            .map_err(|_| SecureQuicError::InvalidMessage)?;
        let channel = if realtime {
            ChannelId::InputRealtime
        } else {
            ChannelId::InputReliable
        };
        if !event.accepts_channel(channel) {
            return Err(SecureQuicError::InvalidMessage);
        }
        let frame = self
            .seal_json(MessageKind::InputEvent, channel, event)
            .await?;
        self.send_frame(&frame).await
    }

    pub async fn receive_reliable_input(&self) -> SecureQuicResult<InputEvent> {
        self.receive_input(ChannelId::InputReliable).await
    }

    pub async fn receive_realtime_input(&self) -> SecureQuicResult<InputEvent> {
        self.receive_input(ChannelId::InputRealtime).await
    }

    pub async fn send_keyframe_request(&self, request: &KeyframeRequest) -> SecureQuicResult<()> {
        if self.local_role != SessionRole::Controller || request.session_id != self.session_id {
            return Err(SecureQuicError::BindingMismatch);
        }
        let frame = self
            .seal_json(
                MessageKind::KeyframeRequest,
                ChannelId::MediaControl,
                request,
            )
            .await?;
        self.channel.send_reliable(&frame).await?;
        Ok(())
    }

    pub async fn receive_keyframe_request(&self) -> SecureQuicResult<KeyframeRequest> {
        if self.local_role != SessionRole::Controlled {
            return Err(SecureQuicError::InvalidMessage);
        }
        let frame = self
            .channel
            .receive_reliable(ChannelId::MediaControl)
            .await?;
        let request: KeyframeRequest = self.open_json(frame, MessageKind::KeyframeRequest).await?;
        if request.session_id != self.session_id {
            return Err(SecureQuicError::BindingMismatch);
        }
        Ok(request)
    }

    pub async fn send_video_frame(
        &self,
        info: &VideoFrameInfo,
        annex_b: &[u8],
    ) -> SecureQuicResult<()> {
        if self.local_role != SessionRole::Controlled
            || info.session_id != self.session_id
            || usize::try_from(info.frame_bytes_len).ok() != Some(annex_b.len())
            || annex_b.is_empty()
        {
            return Err(SecureQuicError::BindingMismatch);
        }
        let info_bytes = serde_json::to_vec(info).map_err(|_| SecureQuicError::Serialization)?;
        let mut secure = self.secure_session.lock().await;
        let (info_header, info_ciphertext) = secure.seal(
            MessageKind::VideoFrameInfo,
            ChannelId::Video,
            0,
            &info_bytes,
        )?;
        let (data_header, data_ciphertext) =
            secure.seal(MessageKind::VideoFrameData, ChannelId::Video, 0, annex_b)?;
        drop(secure);
        let frames = [
            OpaqueFrame::new(info_header, Bytes::from(info_ciphertext))?,
            OpaqueFrame::new(data_header, Bytes::from(data_ciphertext))?,
        ];
        self.channel.send_video_frame(&frames).await?;
        Ok(())
    }

    pub async fn receive_video_frame(&self) -> SecureQuicResult<ReceivedVideoFrame> {
        if self.local_role != SessionRole::Controller {
            return Err(SecureQuicError::InvalidMessage);
        }
        let frames = self.channel.receive_video_frame().await?;
        if frames.len() != 2
            || frames[0].header().kind != MessageKind::VideoFrameInfo
            || frames[1].header().kind != MessageKind::VideoFrameData
        {
            return Err(SecureQuicError::InvalidMessage);
        }
        let mut secure = self.secure_session.lock().await;
        let info_plaintext = secure.open(frames[0].header(), frames[0].opaque_payload())?;
        let annex_b = secure.open(frames[1].header(), frames[1].opaque_payload())?;
        drop(secure);
        let info: VideoFrameInfo =
            serde_json::from_slice(&info_plaintext).map_err(|_| SecureQuicError::Serialization)?;
        if info.session_id != self.session_id
            || usize::try_from(info.frame_bytes_len).ok() != Some(annex_b.len())
            || annex_b.is_empty()
        {
            return Err(SecureQuicError::BindingMismatch);
        }
        Ok(ReceivedVideoFrame { info, annex_b })
    }

    pub fn close(&self) {
        self.channel.close();
    }

    async fn receive_input(&self, channel: ChannelId) -> SecureQuicResult<InputEvent> {
        if self.local_role != SessionRole::Controlled {
            return Err(SecureQuicError::InvalidMessage);
        }
        let frame = match quic_route(channel) {
            QuicFrameRoute::ReliableStream(_) => self.channel.receive_reliable(channel).await?,
            QuicFrameRoute::Datagram => self.channel.receive_datagram().await?,
            QuicFrameRoute::VideoFrameStream => return Err(SecureQuicError::InvalidMessage),
        };
        let event: InputEvent = self.open_json(frame, MessageKind::InputEvent).await?;
        if event.session_id.as_u128() != self.session_id || !event.accepts_channel(channel) {
            return Err(SecureQuicError::BindingMismatch);
        }
        event
            .validate()
            .map_err(|_| SecureQuicError::InvalidMessage)?;
        Ok(event)
    }

    async fn seal_json<T: Serialize + ?Sized>(
        &self,
        kind: MessageKind,
        channel: ChannelId,
        value: &T,
    ) -> SecureQuicResult<OpaqueFrame> {
        let plaintext = serde_json::to_vec(value).map_err(|_| SecureQuicError::Serialization)?;
        let (header, ciphertext) = self
            .secure_session
            .lock()
            .await
            .seal(kind, channel, 0, &plaintext)?;
        Ok(OpaqueFrame::new(header, Bytes::from(ciphertext))?)
    }

    async fn open_json<T: DeserializeOwned>(
        &self,
        frame: OpaqueFrame,
        expected_kind: MessageKind,
    ) -> SecureQuicResult<T> {
        if frame.header().kind != expected_kind {
            return Err(SecureQuicError::InvalidMessage);
        }
        let plaintext = self
            .secure_session
            .lock()
            .await
            .open(frame.header(), frame.opaque_payload())?;
        serde_json::from_slice(&plaintext).map_err(|_| SecureQuicError::Serialization)
    }

    async fn send_frame(&self, frame: &OpaqueFrame) -> SecureQuicResult<()> {
        match quic_route(frame.header().channel_id) {
            QuicFrameRoute::ReliableStream(_) => self.channel.send_reliable(frame).await?,
            QuicFrameRoute::Datagram => self.channel.send_datagram(frame)?,
            QuicFrameRoute::VideoFrameStream => return Err(SecureQuicError::InvalidMessage),
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use remote_core::SecureSession;
    use remote_crypto::{derive_session_keys, permissions_digest};
    use remote_protocol::{
        InputKind, MediaQualityReason, SessionKdfContext, SessionPermissions, TransportPath,
        VideoCodec, PROTOCOL_VERSION,
    };
    use remote_transport::{
        test_tls, DataChannelLimits, QuicClientEndpoint, QuicServerEndpoint, RoleHandshake,
        TransportCancellation, TransportKind,
    };
    use uuid::Uuid;

    use super::*;

    const SESSION_ID: u128 = 0x00000000000040008000000000000001;
    const CANDIDATE_PAIR_ID: u128 = 2;
    const TRANSCRIPT_HASH: [u8; 32] = [4; 32];

    fn secure_pair() -> (SecureSession, SecureSession) {
        let permissions = SessionPermissions {
            remote_desktop: true,
            input_control: true,
            require_prompt: false,
            ..SessionPermissions::default()
        };
        let digest = permissions_digest(permissions).expect("permissions digest");
        let context = SessionKdfContext {
            account_id: "account".to_owned(),
            session_id: SESSION_ID,
            controller_device_id: "ios-controller".to_owned(),
            controlled_device_id: "ubuntu-controlled".to_owned(),
            permissions_digest: digest,
            protocol_version: PROTOCOL_VERSION,
            session_expires_at_epoch_millis: 10_000,
            selected_transport_path: TransportPath::LanDirect,
            selected_candidate_pair_id: CANDIDATE_PAIR_ID,
            relay_node_id: None,
            key_exchange_transcript_hash: TRANSCRIPT_HASH,
        };
        let controller_keys = derive_session_keys(&[9; 32], &context).expect("controller keys");
        let controlled_keys = derive_session_keys(&[9; 32], &context).expect("controlled keys");
        let mut controller = SecureSession::new(
            SESSION_ID,
            SessionRole::Controller,
            permissions,
            digest,
            TransportPath::LanDirect,
            CANDIDATE_PAIR_ID,
            None,
            TRANSCRIPT_HASH,
            controller_keys,
        )
        .expect("controller secure session");
        let mut controlled = SecureSession::new(
            SESSION_ID,
            SessionRole::Controlled,
            permissions,
            digest,
            TransportPath::LanDirect,
            CANDIDATE_PAIR_ID,
            None,
            TRANSCRIPT_HASH,
            controlled_keys,
        )
        .expect("controlled secure session");
        let controller_confirm = controller
            .create_local_key_confirm("ios-controller".to_owned(), 1_000)
            .expect("controller confirm");
        let controlled_confirm = controlled
            .create_local_key_confirm("ubuntu-controlled".to_owned(), 1_000)
            .expect("controlled confirm");
        controller
            .verify_peer_key_confirm(&controlled_confirm, "ubuntu-controlled", 1_001)
            .expect("controller verifies controlled");
        controlled
            .verify_peer_key_confirm(&controller_confirm, "ios-controller", 1_001)
            .expect("controlled verifies controller");
        (controller, controlled)
    }

    async fn channel_pair() -> (SecureQuicChannel, SecureQuicChannel) {
        let limits = DataChannelLimits::default();
        let server = QuicServerEndpoint::bind(
            "127.0.0.1:0".parse().expect("server address"),
            test_tls::server_config(),
            limits,
        )
        .expect("server endpoint");
        let server_address = server.local_addr().expect("server local address");
        let server_task = tokio::spawn(async move {
            server
                .accept(
                    TransportKind::LanDirect,
                    RoleHandshake::new(SESSION_ID, SessionRole::Controlled),
                    &TransportCancellation::default(),
                )
                .await
                .expect("controlled QUIC channel")
        });
        let client = QuicClientEndpoint::bind(
            "127.0.0.1:0".parse().expect("client address"),
            test_tls::client_config(),
            limits,
        )
        .expect("client endpoint");
        let controller_quic = client
            .connect(
                server_address,
                "localhost",
                TransportKind::LanDirect,
                RoleHandshake::new(SESSION_ID, SessionRole::Controller),
                &TransportCancellation::default(),
            )
            .await
            .expect("controller QUIC channel");
        let controlled_quic = server_task.await.expect("controlled endpoint task");
        let (controller_secure, controlled_secure) = secure_pair();
        (
            SecureQuicChannel::new(controller_quic, controller_secure).expect("controller runtime"),
            SecureQuicChannel::new(controlled_quic, controlled_secure).expect("controlled runtime"),
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn localhost_quic_and_e2ee_carry_input_and_h264_in_opposite_directions() {
        let (controller, controlled) = channel_pair().await;
        let input = InputEvent {
            session_id: Uuid::from_u128(SESSION_ID),
            event_id: Uuid::from_u128(7),
            display_id: "primary".to_owned(),
            input_kind: InputKind::MouseMove,
            key_event_kind: None,
            physical_code: None,
            scan_code: None,
            virtual_key: None,
            logical_key: None,
            x_norm: Some(0.25),
            y_norm: Some(0.75),
            button: None,
            key_code: 0,
            modifiers: Vec::new(),
            wheel_delta_x: 0.0,
            wheel_delta_y: 0.0,
            text: None,
            composition_text: None,
            composition_state: None,
            keyboard_layout: None,
            is_auto_repeat: false,
            timestamp_epoch_millis: 2_000,
        };
        controller
            .send_input(&input, false)
            .await
            .expect("send encrypted input");
        assert_eq!(
            controlled
                .receive_reliable_input()
                .await
                .expect("receive decrypted input"),
            input
        );

        let annex_b = vec![0, 0, 0, 1, 0x67, 0x64, 0, 0x1f, 0, 0, 0, 1, 0x65, 0x88];
        let info = VideoFrameInfo {
            session_id: SESSION_ID,
            display_id: "primary".to_owned(),
            frame_id: 11,
            codec: VideoCodec::H264,
            width: 1_920,
            height: 1_080,
            stride: 0,
            pixel_format: "annex_b".to_owned(),
            color_space: "bt709".to_owned(),
            rotation: 0,
            is_keyframe: true,
            pts_millis: 2_001,
            frame_bytes_len: annex_b.len() as u32,
        };
        controlled
            .send_video_frame(&info, &annex_b)
            .await
            .expect("send encrypted H.264");
        let received = controller
            .receive_video_frame()
            .await
            .expect("receive decrypted H.264");
        assert_eq!(received.info, info);
        assert_eq!(received.annex_b, annex_b);

        let request = KeyframeRequest {
            session_id: SESSION_ID,
            display_id: "primary".to_owned(),
            reason: MediaQualityReason::KeyframeLoss,
            last_received_frame_id: 11,
            timestamp_epoch_millis: 2_002,
        };
        controller
            .send_keyframe_request(&request)
            .await
            .expect("send encrypted keyframe request");
        assert_eq!(
            controlled
                .receive_keyframe_request()
                .await
                .expect("receive keyframe request"),
            request
        );

        controller.close();
        controlled.close();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mismatched_secure_and_transport_roles_are_rejected() {
        let limits = DataChannelLimits::default();
        let server = QuicServerEndpoint::bind(
            "127.0.0.1:0".parse().expect("server address"),
            test_tls::server_config(),
            limits,
        )
        .expect("server endpoint");
        let address = server.local_addr().expect("server address");
        let server_task = tokio::spawn(async move {
            server
                .accept(
                    TransportKind::LanDirect,
                    RoleHandshake::new(SESSION_ID, SessionRole::Controlled),
                    &TransportCancellation::default(),
                )
                .await
                .expect("server channel")
        });
        let client = QuicClientEndpoint::bind(
            "127.0.0.1:0".parse().expect("client address"),
            test_tls::client_config(),
            limits,
        )
        .expect("client endpoint");
        let controller_quic = client
            .connect(
                address,
                "localhost",
                TransportKind::LanDirect,
                RoleHandshake::new(SESSION_ID, SessionRole::Controller),
                &TransportCancellation::default(),
            )
            .await
            .expect("client channel");
        let server_channel = server_task.await.expect("server task");
        let (_, controlled_secure) = secure_pair();
        let result = SecureQuicChannel::new(controller_quic, controlled_secure);
        assert!(matches!(result, Err(SecureQuicError::BindingMismatch)));
        server_channel.close();
    }
}
