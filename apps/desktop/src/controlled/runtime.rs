use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use remote_capture::{MonitorInfo, ScreenCapturer};
use remote_codec::EncodedAccessUnit;
use remote_protocol::{VideoCodec, VideoFrameInfo};
use remote_runtime::{SecureQuicChannel, SecureQuicError};
use tokio::sync::{oneshot, watch, Mutex};
use tokio::task::{JoinHandle, JoinSet};

use crate::input::{InputBackend, InputError, InputManager};

use super::{ControlledMediaSession, EncodedVideoSink, MediaPumpError};

#[derive(Debug)]
pub enum ControlledRuntimeError {
    InvalidFrameRate,
    Media(MediaPumpError),
    SecureChannel(SecureQuicError),
    Input(InputError),
    TaskStopped,
}

impl fmt::Display for ControlledRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFrameRate => formatter.write_str("controlled frame rate is invalid"),
            Self::Media(error) => write!(formatter, "controlled media failed: {error}"),
            Self::SecureChannel(error) => write!(formatter, "secure QUIC channel failed: {error}"),
            Self::Input(error) => write!(formatter, "controlled input failed: {error}"),
            Self::TaskStopped => {
                formatter.write_str("controlled session task stopped unexpectedly")
            }
        }
    }
}

impl std::error::Error for ControlledRuntimeError {}

impl From<SecureQuicError> for ControlledRuntimeError {
    fn from(value: SecureQuicError) -> Self {
        Self::SecureChannel(value)
    }
}

#[derive(Clone)]
struct LatestVideoSink {
    sender: watch::Sender<Option<EncodedAccessUnit>>,
}

impl EncodedVideoSink for LatestVideoSink {
    fn send_access_unit(&mut self, access_unit: &EncodedAccessUnit) -> Result<(), String> {
        self.sender.send_replace(Some(access_unit.clone()));
        Ok(())
    }
}

pub async fn run_controlled_quic_session<B>(
    channel: Arc<SecureQuicChannel>,
    capturer: Box<dyn ScreenCapturer>,
    input: InputManager<B>,
    display_id: String,
    frame_rate: u32,
) -> Result<(), ControlledRuntimeError>
where
    B: InputBackend + 'static,
{
    if !(1..=60).contains(&frame_rate) || display_id.is_empty() {
        return Err(ControlledRuntimeError::InvalidFrameRate);
    }
    let cancellation = Arc::new(AtomicBool::new(false));
    let keyframe_requested = Arc::new(AtomicBool::new(false));
    let input = Arc::new(Mutex::new(input));
    let (video_tx, video_rx) = watch::channel(None);
    let (monitor_tx, monitor_rx) = oneshot::channel();
    let (media_result_tx, media_result_rx) = oneshot::channel();
    let media_thread = start_media_thread(
        capturer,
        LatestVideoSink { sender: video_tx },
        frame_rate,
        Arc::clone(&cancellation),
        Arc::clone(&keyframe_requested),
        monitor_tx,
        media_result_tx,
    );

    let mut tasks = JoinSet::new();
    tasks.spawn(send_video_loop(
        Arc::clone(&channel),
        display_id,
        video_rx,
        monitor_rx,
    ));
    tasks.spawn(receive_reliable_input_loop(
        Arc::clone(&channel),
        Arc::clone(&input),
    ));
    tasks.spawn(receive_realtime_input_loop(
        Arc::clone(&channel),
        Arc::clone(&input),
    ));
    tasks.spawn(receive_keyframe_loop(
        Arc::clone(&channel),
        Arc::clone(&keyframe_requested),
    ));
    tokio::pin!(media_result_rx);

    let result = tokio::select! {
        result = tasks.join_next() => match result {
            Some(result) => join_runtime_task(result),
            None => Err(ControlledRuntimeError::TaskStopped),
        },
        result = &mut media_result_rx => match result {
            Ok(result) => result.map_err(ControlledRuntimeError::Media),
            Err(_) => Err(ControlledRuntimeError::TaskStopped),
        },
    };

    cancellation.store(true, Ordering::Release);
    channel.close();
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    let _ = media_thread.await;
    let _ = input.lock().await.release_all();
    result
}

fn start_media_thread(
    capturer: Box<dyn ScreenCapturer>,
    sink: LatestVideoSink,
    frame_rate: u32,
    cancellation: Arc<AtomicBool>,
    keyframe_requested: Arc<AtomicBool>,
    monitor_tx: oneshot::Sender<MonitorInfo>,
    result_tx: oneshot::Sender<Result<(), MediaPumpError>>,
) -> JoinHandle<()> {
    tokio::task::spawn_blocking(move || {
        let mut session = match ControlledMediaSession::start(capturer, sink, frame_rate) {
            Ok(session) => session,
            Err(error) => {
                let _ = result_tx.send(Err(error));
                return;
            }
        };
        let _ = monitor_tx.send(session.snapshot().monitor.clone());
        let frame_interval = Duration::from_secs_f64(1.0 / f64::from(frame_rate));
        let result = loop {
            if cancellation.load(Ordering::Acquire) {
                break Ok(());
            }
            if keyframe_requested.swap(false, Ordering::AcqRel) {
                session.request_keyframe();
            }
            let started = std::time::Instant::now();
            if let Err(error) = session.pump_once() {
                break Err(error);
            }
            if let Some(remaining) = frame_interval.checked_sub(started.elapsed()) {
                std::thread::sleep(remaining);
            }
        };
        session.stop();
        let _ = result_tx.send(result);
    })
}

async fn send_video_loop(
    channel: Arc<SecureQuicChannel>,
    display_id: String,
    mut video: watch::Receiver<Option<EncodedAccessUnit>>,
    monitor: oneshot::Receiver<MonitorInfo>,
) -> Result<(), ControlledRuntimeError> {
    let monitor = monitor
        .await
        .map_err(|_| ControlledRuntimeError::TaskStopped)?;
    loop {
        video
            .changed()
            .await
            .map_err(|_| ControlledRuntimeError::TaskStopped)?;
        let Some(access_unit) = video.borrow_and_update().clone() else {
            continue;
        };
        let frame_bytes_len = u32::try_from(access_unit.data.len())
            .map_err(|_| ControlledRuntimeError::TaskStopped)?;
        let info = VideoFrameInfo {
            session_id: channel.session_id(),
            display_id: display_id.clone(),
            frame_id: access_unit.frame_id,
            codec: VideoCodec::H264,
            width: monitor.width,
            height: monitor.height,
            stride: 0,
            pixel_format: "annex_b".to_owned(),
            color_space: "bt709".to_owned(),
            rotation: 0,
            is_keyframe: access_unit.is_keyframe,
            pts_millis: access_unit.pts / 1_000,
            frame_bytes_len,
        };
        channel.send_video_frame(&info, &access_unit.data).await?;
    }
}

async fn receive_reliable_input_loop<B: InputBackend>(
    channel: Arc<SecureQuicChannel>,
    input: Arc<Mutex<InputManager<B>>>,
) -> Result<(), ControlledRuntimeError> {
    loop {
        let event = channel.receive_reliable_input().await?;
        input
            .lock()
            .await
            .apply_protocol_event(&event)
            .map_err(ControlledRuntimeError::Input)?;
    }
}

async fn receive_realtime_input_loop<B: InputBackend>(
    channel: Arc<SecureQuicChannel>,
    input: Arc<Mutex<InputManager<B>>>,
) -> Result<(), ControlledRuntimeError> {
    loop {
        let event = channel.receive_realtime_input().await?;
        input
            .lock()
            .await
            .apply_protocol_event(&event)
            .map_err(ControlledRuntimeError::Input)?;
    }
}

async fn receive_keyframe_loop(
    channel: Arc<SecureQuicChannel>,
    keyframe_requested: Arc<AtomicBool>,
) -> Result<(), ControlledRuntimeError> {
    loop {
        channel.receive_keyframe_request().await?;
        keyframe_requested.store(true, Ordering::Release);
    }
}

fn join_runtime_task(
    result: Result<Result<(), ControlledRuntimeError>, tokio::task::JoinError>,
) -> Result<(), ControlledRuntimeError> {
    result.unwrap_or(Err(ControlledRuntimeError::TaskStopped))
}

#[cfg(test)]
mod tests {
    use remote_capture::{MonitorInfo, SafeMockCapturer};
    use remote_core::SecureSession;
    use remote_crypto::{derive_session_keys, permissions_digest};
    use remote_protocol::{
        InputEvent as ProtocolInputEvent, InputKind, KeyframeRequest, MediaQualityReason,
        SessionKdfContext, SessionPermissions, SessionRole, TransportPath, PROTOCOL_VERSION,
    };
    use remote_transport::{
        test_tls, DataChannelLimits, QuicClientEndpoint, QuicServerEndpoint, RoleHandshake,
        TransportCancellation, TransportKind,
    };
    use uuid::Uuid;

    use crate::input::{InputEvent, SafeMockInputBackend};

    use super::*;

    const SESSION_ID: u128 = 0x00000000000040008000000000000001;

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
            controller_device_id: "ios-1".to_owned(),
            controlled_device_id: "ubuntu-1".to_owned(),
            permissions_digest: digest,
            protocol_version: PROTOCOL_VERSION,
            session_expires_at_epoch_millis: 10_000,
            selected_transport_path: TransportPath::LanDirect,
            selected_candidate_pair_id: 2,
            relay_node_id: None,
            key_exchange_transcript_hash: [4; 32],
        };
        let mut controller = SecureSession::new(
            SESSION_ID,
            SessionRole::Controller,
            permissions,
            digest,
            TransportPath::LanDirect,
            2,
            None,
            [4; 32],
            derive_session_keys(&[9; 32], &context).expect("controller keys"),
        )
        .expect("controller secure session");
        let mut controlled = SecureSession::new(
            SESSION_ID,
            SessionRole::Controlled,
            permissions,
            digest,
            TransportPath::LanDirect,
            2,
            None,
            [4; 32],
            derive_session_keys(&[9; 32], &context).expect("controlled keys"),
        )
        .expect("controlled secure session");
        let controller_confirm = controller
            .create_local_key_confirm("ios-1".to_owned(), 1_000)
            .expect("controller confirm");
        let controlled_confirm = controlled
            .create_local_key_confirm("ubuntu-1".to_owned(), 1_000)
            .expect("controlled confirm");
        controller
            .verify_peer_key_confirm(&controlled_confirm, "ubuntu-1", 1_001)
            .expect("verify controlled");
        controlled
            .verify_peer_key_confirm(&controller_confirm, "ios-1", 1_001)
            .expect("verify controller");
        (controller, controlled)
    }

    async fn channel_pair() -> (Arc<SecureQuicChannel>, Arc<SecureQuicChannel>) {
        let limits = DataChannelLimits::default();
        let server = QuicServerEndpoint::bind(
            "127.0.0.1:0".parse().expect("server address"),
            test_tls::server_config(),
            limits,
        )
        .expect("server endpoint");
        let address = server.local_addr().expect("server local address");
        let server_task = tokio::spawn(async move {
            server
                .accept(
                    TransportKind::LanDirect,
                    RoleHandshake::new(SESSION_ID, SessionRole::Controlled),
                    &TransportCancellation::default(),
                )
                .await
                .expect("controlled channel")
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
            .expect("controller channel");
        let controlled_quic = server_task.await.expect("controlled task");
        let (controller_secure, controlled_secure) = secure_pair();
        (
            Arc::new(
                SecureQuicChannel::new(controller_quic, controller_secure)
                    .expect("controller runtime"),
            ),
            Arc::new(
                SecureQuicChannel::new(controlled_quic, controlled_secure)
                    .expect("controlled runtime"),
            ),
        )
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ubuntu_controlled_runtime_streams_h264_applies_input_and_releases_on_close() {
        if std::process::Command::new("gst-launch-1.0")
            .arg("--version")
            .output()
            .is_err()
        {
            return;
        }
        let (controller, controlled) = channel_pair().await;
        let capturer = SafeMockCapturer::new(vec![MonitorInfo {
            monitor_id: 7,
            name: "primary".to_owned(),
            x: 0,
            y: 0,
            width: 4,
            height: 4,
            scale_factor_milli: 1_000,
            is_primary: true,
        }]);
        let backend = SafeMockInputBackend::default();
        let observer = backend.clone();
        let runtime = tokio::spawn(run_controlled_quic_session(
            controlled,
            Box::new(capturer),
            InputManager::new(backend),
            "primary".to_owned(),
            30,
        ));

        let first_frame =
            tokio::time::timeout(Duration::from_secs(5), controller.receive_video_frame())
                .await
                .expect("first frame timeout")
                .expect("first encrypted frame");
        assert_eq!(first_frame.info.width, 4);
        assert_eq!(first_frame.info.height, 4);
        assert!(first_frame.info.is_keyframe);
        assert!(first_frame.annex_b.starts_with(&[0, 0, 0, 1]));

        controller
            .send_input(
                &ProtocolInputEvent {
                    session_id: Uuid::from_u128(SESSION_ID),
                    event_id: Uuid::from_u128(8),
                    display_id: "primary".to_owned(),
                    input_kind: InputKind::MouseMove,
                    key_event_kind: None,
                    physical_code: None,
                    scan_code: None,
                    virtual_key: None,
                    logical_key: None,
                    x_norm: Some(0.2),
                    y_norm: Some(0.8),
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
                },
                false,
            )
            .await
            .expect("send input");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(observer.events().contains(&InputEvent::PointerMove {
            x_norm: 0.2,
            y_norm: 0.8,
        }));

        controller
            .send_keyframe_request(&KeyframeRequest {
                session_id: SESSION_ID,
                display_id: "primary".to_owned(),
                reason: MediaQualityReason::KeyframeLoss,
                last_received_frame_id: first_frame.info.frame_id,
                timestamp_epoch_millis: 2_001,
            })
            .await
            .expect("request keyframe");
        let mut received_keyframe = false;
        for _ in 0..10 {
            let frame =
                tokio::time::timeout(Duration::from_secs(2), controller.receive_video_frame())
                    .await
                    .expect("next frame timeout")
                    .expect("next encrypted frame");
            if frame.info.frame_id > first_frame.info.frame_id && frame.info.is_keyframe {
                received_keyframe = true;
                break;
            }
        }
        assert!(received_keyframe);

        controller.close();
        let _ = tokio::time::timeout(Duration::from_secs(5), runtime)
            .await
            .expect("controlled runtime stops");
        assert_eq!(observer.events().last(), Some(&InputEvent::ReleaseAll));
    }
}
