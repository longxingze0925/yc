use std::collections::VecDeque;

use remote_protocol::{InputEvent, InputKind};

const MAX_H264_ACCESS_UNIT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControllerSessionState {
    Idle,
    Connecting,
    Streaming,
    Reconnecting,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct H264AccessUnit {
    pub data: Vec<u8>,
    pub presentation_time_millis: i64,
    pub is_keyframe: bool,
    pub frame_id: u64,
}

impl H264AccessUnit {
    fn validate(&self) -> Result<(), ControllerSessionError> {
        if self.data.is_empty() || self.data.len() > MAX_H264_ACCESS_UNIT_BYTES {
            return Err(ControllerSessionError::InvalidAccessUnit);
        }
        if !self.data.starts_with(&[0, 0, 1]) && !self.data.starts_with(&[0, 0, 0, 1]) {
            return Err(ControllerSessionError::InvalidAccessUnit);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerSessionEvent {
    StateChanged(ControllerSessionState),
    H264(H264AccessUnit),
    RecoverableTransportError(String),
    FatalTransportError(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerTransportEvent {
    Connected,
    H264(H264AccessUnit),
    Disconnected { recoverable: bool, reason: String },
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputDelivery {
    Realtime,
    Reliable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerTransportError {
    Unavailable(String),
    Closed,
}

pub trait ControllerTransport: Send {
    fn start(&mut self, connection_epoch: u64) -> Result<(), ControllerTransportError>;

    fn send_input(
        &mut self,
        payload: &[u8],
        delivery: InputDelivery,
    ) -> Result<(), ControllerTransportError>;

    fn close(&mut self) -> Result<(), ControllerTransportError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControllerSessionError {
    InvalidState,
    InvalidInput,
    InputSessionMismatch,
    InvalidAccessUnit,
    Serialization,
    Transport(ControllerTransportError),
}

impl From<ControllerTransportError> for ControllerSessionError {
    fn from(value: ControllerTransportError) -> Self {
        Self::Transport(value)
    }
}

pub struct ControllerSession<T: ControllerTransport> {
    session_id: uuid::Uuid,
    transport: T,
    state: ControllerSessionState,
    connection_epoch: u64,
    events: VecDeque<ControllerSessionEvent>,
    close_started: bool,
}

impl<T: ControllerTransport> ControllerSession<T> {
    pub fn new(session_id: uuid::Uuid, transport: T) -> Self {
        Self {
            session_id,
            transport,
            state: ControllerSessionState::Idle,
            connection_epoch: 0,
            events: VecDeque::new(),
            close_started: false,
        }
    }

    pub fn session_id(&self) -> uuid::Uuid {
        self.session_id
    }

    pub fn state(&self) -> ControllerSessionState {
        self.state
    }

    pub fn connection_epoch(&self) -> u64 {
        self.connection_epoch
    }

    pub fn connect(&mut self) -> Result<u64, ControllerSessionError> {
        if self.state != ControllerSessionState::Idle || self.close_started {
            return Err(ControllerSessionError::InvalidState);
        }
        self.connection_epoch = self.connection_epoch.saturating_add(1);
        self.transition_to(ControllerSessionState::Connecting);
        if let Err(error) = self.transport.start(self.connection_epoch) {
            self.fail_transport(error.clone());
            return Err(error.into());
        }
        Ok(self.connection_epoch)
    }

    pub fn handle_transport_event(
        &mut self,
        connection_epoch: u64,
        event: ControllerTransportEvent,
    ) -> Result<(), ControllerSessionError> {
        if self.close_started || connection_epoch != self.connection_epoch {
            return Ok(());
        }
        match event {
            ControllerTransportEvent::Connected => {
                if !matches!(
                    self.state,
                    ControllerSessionState::Connecting | ControllerSessionState::Reconnecting
                ) {
                    return Err(ControllerSessionError::InvalidState);
                }
                self.transition_to(ControllerSessionState::Streaming);
            }
            ControllerTransportEvent::H264(access_unit) => {
                if self.state != ControllerSessionState::Streaming {
                    return Ok(());
                }
                access_unit.validate()?;
                self.events
                    .push_back(ControllerSessionEvent::H264(access_unit));
            }
            ControllerTransportEvent::Disconnected {
                recoverable,
                reason,
            } => {
                if recoverable {
                    self.events
                        .push_back(ControllerSessionEvent::RecoverableTransportError(reason));
                    self.restart_transport()?;
                } else {
                    self.events
                        .push_back(ControllerSessionEvent::FatalTransportError(reason));
                    self.close()?;
                }
            }
            ControllerTransportEvent::Closed => self.close()?,
        }
        Ok(())
    }

    pub fn send_input(&mut self, event: &InputEvent) -> Result<(), ControllerSessionError> {
        if self.state != ControllerSessionState::Streaming || self.close_started {
            return Err(ControllerSessionError::InvalidState);
        }
        if event.session_id != self.session_id {
            return Err(ControllerSessionError::InputSessionMismatch);
        }
        event
            .validate()
            .map_err(|_| ControllerSessionError::InvalidInput)?;
        let delivery = if event.input_kind == InputKind::MouseMove {
            InputDelivery::Realtime
        } else {
            InputDelivery::Reliable
        };
        let payload =
            serde_json::to_vec(event).map_err(|_| ControllerSessionError::Serialization)?;
        self.transport.send_input(&payload, delivery)?;
        Ok(())
    }

    pub fn poll_event(&mut self) -> Option<ControllerSessionEvent> {
        self.events.pop_front()
    }

    pub fn close(&mut self) -> Result<(), ControllerSessionError> {
        if self.close_started {
            return Ok(());
        }
        self.close_started = true;
        self.connection_epoch = self.connection_epoch.saturating_add(1);
        let close_result = self.transport.close();
        self.transition_to(ControllerSessionState::Closed);
        close_result.map_err(ControllerSessionError::Transport)
    }

    fn restart_transport(&mut self) -> Result<(), ControllerSessionError> {
        if !matches!(
            self.state,
            ControllerSessionState::Connecting
                | ControllerSessionState::Streaming
                | ControllerSessionState::Reconnecting
        ) {
            return Err(ControllerSessionError::InvalidState);
        }
        self.connection_epoch = self.connection_epoch.saturating_add(1);
        self.transition_to(ControllerSessionState::Reconnecting);
        if let Err(error) = self.transport.start(self.connection_epoch) {
            self.fail_transport(error.clone());
            return Err(error.into());
        }
        Ok(())
    }

    fn fail_transport(&mut self, error: ControllerTransportError) {
        let message = match error {
            ControllerTransportError::Unavailable(message) => message,
            ControllerTransportError::Closed => "transport closed".to_owned(),
        };
        self.events
            .push_back(ControllerSessionEvent::FatalTransportError(message));
        let _ = self.close();
    }

    fn transition_to(&mut self, state: ControllerSessionState) {
        if self.state == state {
            return;
        }
        self.state = state;
        self.events
            .push_back(ControllerSessionEvent::StateChanged(state));
    }
}

impl<T: ControllerTransport> Drop for ControllerSession<T> {
    fn drop(&mut self) {
        if !self.close_started {
            self.close_started = true;
            let _ = self.transport.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use remote_protocol::{CompositionState, InputModifier, KeyEventKind, MouseButton};

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum TransportCall {
        Start(u64),
        Input(InputDelivery, Vec<u8>),
        Close,
    }

    #[derive(Clone, Default)]
    struct FakeTransport {
        calls: Arc<Mutex<Vec<TransportCall>>>,
    }

    impl ControllerTransport for FakeTransport {
        fn start(&mut self, connection_epoch: u64) -> Result<(), ControllerTransportError> {
            self.calls
                .lock()
                .expect("calls")
                .push(TransportCall::Start(connection_epoch));
            Ok(())
        }

        fn send_input(
            &mut self,
            payload: &[u8],
            delivery: InputDelivery,
        ) -> Result<(), ControllerTransportError> {
            self.calls
                .lock()
                .expect("calls")
                .push(TransportCall::Input(delivery, payload.to_vec()));
            Ok(())
        }

        fn close(&mut self) -> Result<(), ControllerTransportError> {
            self.calls.lock().expect("calls").push(TransportCall::Close);
            Ok(())
        }
    }

    fn input(session_id: uuid::Uuid, kind: InputKind) -> InputEvent {
        InputEvent {
            session_id,
            event_id: uuid::Uuid::from_u128(2),
            display_id: "primary".to_owned(),
            input_kind: kind,
            key_event_kind: (kind == InputKind::PhysicalKey).then_some(KeyEventKind::Down),
            physical_code: (kind == InputKind::PhysicalKey).then_some(4),
            scan_code: None,
            virtual_key: None,
            logical_key: None,
            x_norm: (kind == InputKind::MouseMove).then_some(0.5),
            y_norm: (kind == InputKind::MouseMove).then_some(0.25),
            button: (kind == InputKind::MouseButton).then_some(MouseButton::Left),
            key_code: u32::from(kind == InputKind::PhysicalKey) * 4,
            modifiers: vec![InputModifier::Ctrl],
            wheel_delta_x: 0.0,
            wheel_delta_y: if kind == InputKind::MouseWheel {
                -8.0
            } else {
                0.0
            },
            text: (kind == InputKind::TextCommit).then(|| "hello".to_owned()),
            composition_text: None,
            composition_state: None::<CompositionState>,
            keyboard_layout: None,
            is_auto_repeat: false,
            timestamp_epoch_millis: 3,
        }
    }

    fn streaming_session() -> (
        ControllerSession<FakeTransport>,
        Arc<Mutex<Vec<TransportCall>>>,
    ) {
        let session_id = uuid::Uuid::from_u128(1);
        let transport = FakeTransport::default();
        let calls = Arc::clone(&transport.calls);
        let mut session = ControllerSession::new(session_id, transport);
        let epoch = session.connect().expect("connect");
        session
            .handle_transport_event(epoch, ControllerTransportEvent::Connected)
            .expect("connected");
        while session.poll_event().is_some() {}
        (session, calls)
    }

    #[test]
    fn connect_frame_input_and_close_form_a_complete_slice() {
        let (mut session, calls) = streaming_session();
        let frame = H264AccessUnit {
            data: vec![0, 0, 0, 1, 0x65, 1],
            presentation_time_millis: 5,
            is_keyframe: true,
            frame_id: 9,
        };
        session
            .handle_transport_event(
                session.connection_epoch(),
                ControllerTransportEvent::H264(frame.clone()),
            )
            .expect("frame");
        assert_eq!(
            session.poll_event(),
            Some(ControllerSessionEvent::H264(frame))
        );

        for kind in [
            InputKind::MouseMove,
            InputKind::MouseButton,
            InputKind::MouseWheel,
            InputKind::TextCommit,
            InputKind::PhysicalKey,
            InputKind::ReleaseAllKeys,
        ] {
            session
                .send_input(&input(session.session_id(), kind))
                .expect("send input");
        }
        session.close().expect("close");
        session.close().expect("idempotent close");

        let calls = calls.lock().expect("calls");
        assert_eq!(calls[0], TransportCall::Start(1));
        assert!(matches!(
            calls[1],
            TransportCall::Input(InputDelivery::Realtime, _)
        ));
        assert!(calls[2..7]
            .iter()
            .all(|call| matches!(call, TransportCall::Input(InputDelivery::Reliable, _))));
        assert_eq!(
            calls
                .iter()
                .filter(|call| **call == TransportCall::Close)
                .count(),
            1
        );
        let TransportCall::Input(_, payload) = &calls[6] else {
            panic!("release-all payload");
        };
        let decoded: InputEvent = serde_json::from_slice(payload).expect("decode payload");
        assert_eq!(decoded.input_kind, InputKind::ReleaseAllKeys);
    }

    #[test]
    fn reconnect_drops_callbacks_from_the_previous_epoch() {
        let (mut session, calls) = streaming_session();
        let old_epoch = session.connection_epoch();
        session
            .handle_transport_event(
                old_epoch,
                ControllerTransportEvent::Disconnected {
                    recoverable: true,
                    reason: "network changed".to_owned(),
                },
            )
            .expect("reconnect");
        let reconnect_epoch = session.connection_epoch();
        assert!(reconnect_epoch > old_epoch);
        assert_eq!(session.state(), ControllerSessionState::Reconnecting);

        session
            .handle_transport_event(old_epoch, ControllerTransportEvent::Connected)
            .expect("late callback is ignored");
        assert_eq!(session.state(), ControllerSessionState::Reconnecting);
        session
            .handle_transport_event(reconnect_epoch, ControllerTransportEvent::Connected)
            .expect("new connection");
        assert_eq!(session.state(), ControllerSessionState::Streaming);
        assert_eq!(
            calls.lock().expect("calls").as_slice(),
            &[TransportCall::Start(1), TransportCall::Start(2)]
        );
    }

    #[test]
    fn drop_releases_transport_once() {
        let calls = {
            let (session, calls) = streaming_session();
            drop(session);
            calls
        };
        assert_eq!(
            calls
                .lock()
                .expect("calls")
                .iter()
                .filter(|call| **call == TransportCall::Close)
                .count(),
            1
        );
    }

    #[test]
    fn mismatched_session_and_invalid_frames_are_rejected() {
        let (mut session, _) = streaming_session();
        assert_eq!(
            session.send_input(&input(uuid::Uuid::from_u128(99), InputKind::MouseMove)),
            Err(ControllerSessionError::InputSessionMismatch)
        );
        assert_eq!(
            session.handle_transport_event(
                session.connection_epoch(),
                ControllerTransportEvent::H264(H264AccessUnit {
                    data: vec![1, 2, 3],
                    presentation_time_millis: 0,
                    is_keyframe: false,
                    frame_id: 1,
                }),
            ),
            Err(ControllerSessionError::InvalidAccessUnit)
        );
    }
}
