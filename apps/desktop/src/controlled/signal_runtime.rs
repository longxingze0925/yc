use std::collections::HashSet;
use std::fmt;

use remote_core::SecureSession;
use remote_protocol::{
    CandidateAuthorization, ConnectionCandidateDto, KeyConfirm, SessionRole, SignedKeyExchange,
};
use remote_runtime::{SessionHandshake, SessionHandshakeConfig, SessionHandshakeError};
use remote_transport::{validate_candidate_authorization, ValidatedCandidatePath};
use serde::Deserialize;
use serde_json::Value;
use uuid::Uuid;

use crate::identity::DeviceIdentity;
use crate::signal::{SessionPeerMessage, SessionSignalMessageKind, SessionSnapshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlledSignalState {
    Idle,
    AwaitingCandidates,
    AwaitingTransportSelection,
    AwaitingPeerKeyExchange,
    AwaitingPeerKeyConfirm,
    Ready,
    Closed,
    Failed,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ControlledSignalAction {
    Send {
        kind: SessionSignalMessageKind,
        session_id: String,
        role: SessionRole,
        payload: Value,
    },
    Ready,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlledSignalRuntimeError {
    InvalidAcceptedSession,
    SessionMismatch,
    PeerMismatch,
    PeerKeyUnavailable,
    TransportSelectionRequired,
    InvalidCandidate,
    InvalidKeyExchange,
    InvalidKeyConfirm,
    SessionExpired,
    InvalidState,
    Serialization,
    Handshake(SessionHandshakeError),
}

impl fmt::Display for ControlledSignalRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAcceptedSession => {
                formatter.write_str("controlled accepted session is invalid")
            }
            Self::SessionMismatch => {
                formatter.write_str("Signal message belongs to another session")
            }
            Self::PeerMismatch => formatter.write_str("Signal message is not from the controller"),
            Self::PeerKeyUnavailable => {
                formatter.write_str("controller device public key is unavailable")
            }
            Self::TransportSelectionRequired => {
                formatter.write_str("authorized candidate exchange has not selected a transport")
            }
            Self::InvalidCandidate => formatter.write_str("candidate authorization is invalid"),
            Self::InvalidKeyExchange => formatter.write_str("key exchange payload is invalid"),
            Self::InvalidKeyConfirm => formatter.write_str("key confirmation payload is invalid"),
            Self::SessionExpired => formatter.write_str("controlled session has expired"),
            Self::InvalidState => formatter.write_str("controlled Signal runtime state is invalid"),
            Self::Serialization => {
                formatter.write_str("Signal session payload serialization failed")
            }
            Self::Handshake(error) => write!(formatter, "session handshake failed: {error:?}"),
        }
    }
}

impl std::error::Error for ControlledSignalRuntimeError {}

impl From<SessionHandshakeError> for ControlledSignalRuntimeError {
    fn from(value: SessionHandshakeError) -> Self {
        Self::Handshake(value)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidatePayload {
    candidate: ConnectionCandidateDto,
    authorization: CandidateAuthorization,
}

/// Signal-side state for one controlled session. UDP observe, candidate gathering,
/// path racing, and QUIC ownership stay outside this type so they cannot be implied
/// by a Signal acknowledgement alone.
pub struct ControlledSignalRuntime {
    session_id: String,
    session_id_u128: u128,
    controller_device_id: String,
    controlled_device_id: String,
    session_expires_at_epoch_millis: u64,
    state: ControlledSignalState,
    controller_public_key: Option<[u8; 32]>,
    received_candidate_ids: HashSet<u128>,
    handshake: Option<SessionHandshake>,
    secure_session: Option<SecureSession>,
}

impl ControlledSignalRuntime {
    pub fn from_accepted(session: &SessionSnapshot) -> Result<Self, ControlledSignalRuntimeError> {
        let session_id_u128 = Uuid::parse_str(&session.session_id)
            .map_err(|_| ControlledSignalRuntimeError::InvalidAcceptedSession)?
            .as_u128();
        if session.status != "accepted"
            || session.controller_device_id.is_empty()
            || session.controlled_device_id.is_empty()
        {
            return Err(ControlledSignalRuntimeError::InvalidAcceptedSession);
        }
        let session_expires_at_epoch_millis = session
            .payload
            .get("session_expires_at_epoch_millis")
            .and_then(Value::as_u64)
            .filter(|value| *value > 0)
            .ok_or(ControlledSignalRuntimeError::InvalidAcceptedSession)?;
        Ok(Self {
            session_id: session.session_id.clone(),
            session_id_u128,
            controller_device_id: session.controller_device_id.clone(),
            controlled_device_id: session.controlled_device_id.clone(),
            session_expires_at_epoch_millis,
            state: ControlledSignalState::AwaitingCandidates,
            controller_public_key: None,
            received_candidate_ids: HashSet::new(),
            handshake: None,
            secure_session: None,
        })
    }

    pub const fn state(&self) -> ControlledSignalState {
        self.state
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn controller_device_id(&self) -> &str {
        &self.controller_device_id
    }

    pub fn set_controller_public_key(
        &mut self,
        device_id: &str,
        public_key: [u8; 32],
    ) -> Result<(), ControlledSignalRuntimeError> {
        if device_id != self.controller_device_id || public_key == [0; 32] {
            return Err(ControlledSignalRuntimeError::PeerMismatch);
        }
        self.controller_public_key = Some(public_key);
        Ok(())
    }

    /// Starts the signed exchange only after the caller has completed authorized
    /// candidate gathering/racing and supplied the selected binding in `config`.
    pub fn begin_key_exchange(
        &mut self,
        mut config: SessionHandshakeConfig,
        selected_path: &ValidatedCandidatePath,
        identity: &DeviceIdentity,
    ) -> Result<ControlledSignalAction, ControlledSignalRuntimeError> {
        if self.state != ControlledSignalState::AwaitingTransportSelection
            || self.handshake.is_some()
            || self.secure_session.is_some()
            || self.controller_public_key.is_none()
            || config.local_role != SessionRole::Controlled
            || config.local_device_id != self.controlled_device_id
            || config.context.session_id != self.session_id_u128
            || config.context.controller_device_id != self.controller_device_id
            || config.context.controlled_device_id != self.controlled_device_id
            || config.context.session_expires_at_epoch_millis
                != self.session_expires_at_epoch_millis
            || selected_path.remote_candidate.session_id != self.session_id_u128
            || selected_path.remote_candidate.device_id != self.controller_device_id
            || selected_path.remote_candidate.role != SessionRole::Controller
            || selected_path.controller_candidate_id != selected_path.remote_candidate.candidate_id
            || !self
                .received_candidate_ids
                .contains(&selected_path.controller_candidate_id)
            || config.context.selected_transport_path != selected_path.binding.transport_path
            || config.context.selected_candidate_pair_id != selected_path.binding.candidate_pair_id
            || config.context.relay_node_id != selected_path.binding.relay_node_id
            || config.context.permissions_digest != selected_path.binding.permissions_digest
        {
            return Err(ControlledSignalRuntimeError::TransportSelectionRequired);
        }
        config.local_device_public_key = identity.public_key();
        let mut handshake = SessionHandshake::new(config)?;
        let digest = handshake.local_signature_digest()?;
        let message = handshake
            .set_local_signature(identity.sign_digest(&digest).to_vec())?
            .clone();
        let payload = serde_json::to_value(message)
            .map_err(|_| ControlledSignalRuntimeError::Serialization)?;
        self.handshake = Some(handshake);
        self.state = ControlledSignalState::AwaitingPeerKeyExchange;
        Ok(ControlledSignalAction::Send {
            kind: SessionSignalMessageKind::KeyExchangeMessage,
            session_id: self.session_id.clone(),
            role: SessionRole::Controlled,
            payload,
        })
    }

    pub fn handle_peer_message(
        &mut self,
        message: &SessionPeerMessage,
        now_epoch_millis: u64,
    ) -> Result<Vec<ControlledSignalAction>, ControlledSignalRuntimeError> {
        if now_epoch_millis >= self.session_expires_at_epoch_millis {
            self.fail();
            return Err(ControlledSignalRuntimeError::SessionExpired);
        }
        self.validate_peer_message(message)?;
        match message.kind {
            SessionSignalMessageKind::ConnectionCandidate => {
                let payload: CandidatePayload =
                    match serde_json::from_value(message.payload.clone()) {
                        Ok(payload) => payload,
                        Err(_) => {
                            self.fail();
                            return Err(ControlledSignalRuntimeError::InvalidCandidate);
                        }
                    };
                if payload.candidate.session_id != self.session_id_u128
                    || payload.candidate.device_id != self.controller_device_id
                    || payload.candidate.role != SessionRole::Controller
                    || validate_candidate_authorization(
                        &payload.candidate,
                        &payload.authorization,
                        now_epoch_millis,
                    )
                    .is_err()
                {
                    self.fail();
                    return Err(ControlledSignalRuntimeError::InvalidCandidate);
                }
                self.received_candidate_ids
                    .insert(payload.candidate.candidate_id);
                self.state = ControlledSignalState::AwaitingTransportSelection;
                Ok(Vec::new())
            }
            SessionSignalMessageKind::KeyExchangeMessage => {
                self.handle_key_exchange(message, now_epoch_millis)
            }
            SessionSignalMessageKind::KeyConfirm => {
                self.handle_key_confirm(message, now_epoch_millis)
            }
        }
    }

    pub fn take_secure_session(&mut self) -> Option<SecureSession> {
        (self.state == ControlledSignalState::Ready)
            .then(|| self.secure_session.take())
            .flatten()
    }

    pub fn close(&mut self) {
        self.handshake = None;
        self.secure_session = None;
        self.received_candidate_ids.clear();
        self.state = ControlledSignalState::Closed;
    }

    fn fail(&mut self) {
        self.handshake = None;
        self.secure_session = None;
        self.received_candidate_ids.clear();
        self.state = ControlledSignalState::Failed;
    }

    fn validate_peer_message(
        &self,
        message: &SessionPeerMessage,
    ) -> Result<(), ControlledSignalRuntimeError> {
        if message.session_id != self.session_id {
            return Err(ControlledSignalRuntimeError::SessionMismatch);
        }
        if message.from_device_id != self.controller_device_id
            || message.role != SessionRole::Controller
        {
            return Err(ControlledSignalRuntimeError::PeerMismatch);
        }
        Ok(())
    }

    fn handle_key_exchange(
        &mut self,
        message: &SessionPeerMessage,
        now_epoch_millis: u64,
    ) -> Result<Vec<ControlledSignalAction>, ControlledSignalRuntimeError> {
        if self.state != ControlledSignalState::AwaitingPeerKeyExchange {
            return Err(ControlledSignalRuntimeError::TransportSelectionRequired);
        }
        let peer_key = self
            .controller_public_key
            .ok_or(ControlledSignalRuntimeError::PeerKeyUnavailable)?;
        let peer_message: SignedKeyExchange = serde_json::from_value(message.payload.clone())
            .map_err(|_| {
                self.fail();
                ControlledSignalRuntimeError::InvalidKeyExchange
            })?;
        let mut handshake = self
            .handshake
            .take()
            .ok_or(ControlledSignalRuntimeError::InvalidState)?;
        if let Err(error) = handshake.verify_peer_message(peer_message, &peer_key, now_epoch_millis)
        {
            self.fail();
            return Err(error.into());
        }
        let ready = match handshake.finish(now_epoch_millis) {
            Ok(ready) => ready,
            Err(error) => {
                self.fail();
                return Err(error.into());
            }
        };
        let payload = match serde_json::to_value(ready.local_key_confirm) {
            Ok(payload) => payload,
            Err(_) => {
                self.fail();
                return Err(ControlledSignalRuntimeError::Serialization);
            }
        };
        self.secure_session = Some(ready.secure_session);
        self.state = ControlledSignalState::AwaitingPeerKeyConfirm;
        Ok(vec![ControlledSignalAction::Send {
            kind: SessionSignalMessageKind::KeyConfirm,
            session_id: self.session_id.clone(),
            role: SessionRole::Controlled,
            payload,
        }])
    }

    fn handle_key_confirm(
        &mut self,
        message: &SessionPeerMessage,
        now_epoch_millis: u64,
    ) -> Result<Vec<ControlledSignalAction>, ControlledSignalRuntimeError> {
        if self.state != ControlledSignalState::AwaitingPeerKeyConfirm {
            return Err(ControlledSignalRuntimeError::InvalidState);
        }
        let confirm: KeyConfirm = match serde_json::from_value(message.payload.clone()) {
            Ok(confirm) => confirm,
            Err(_) => {
                self.fail();
                return Err(ControlledSignalRuntimeError::InvalidKeyConfirm);
            }
        };
        let secure_session = self
            .secure_session
            .as_mut()
            .ok_or(ControlledSignalRuntimeError::InvalidState)?;
        if secure_session
            .verify_peer_key_confirm(&confirm, &self.controller_device_id, now_epoch_millis)
            .is_err()
        {
            self.fail();
            return Err(ControlledSignalRuntimeError::InvalidKeyConfirm);
        }
        self.state = ControlledSignalState::Ready;
        Ok(vec![ControlledSignalAction::Ready])
    }
}

#[cfg(test)]
mod tests {
    use remote_crypto::DeviceKeyPair;
    use remote_protocol::{
        CandidateSource, SessionKdfContext, SessionPermissions, TransportPath, PROTOCOL_VERSION,
    };
    use remote_transport::SecurePathBinding;

    use super::*;

    const SESSION_ID: &str = "00000000-0000-4000-8000-000000000001";

    fn snapshot(controlled_device_id: &str) -> SessionSnapshot {
        SessionSnapshot {
            session_id: SESSION_ID.to_owned(),
            status: "accepted".to_owned(),
            controller_device_id: "ios-1".to_owned(),
            controlled_device_id: controlled_device_id.to_owned(),
            payload: serde_json::json!({
                "session_expires_at_epoch_millis": 60_000,
            }),
        }
    }

    fn context(controlled_device_id: &str) -> SessionKdfContext {
        let permissions = SessionPermissions {
            remote_desktop: true,
            input_control: true,
            require_prompt: false,
            ..SessionPermissions::default()
        };
        SessionKdfContext {
            account_id: "account-1".to_owned(),
            session_id: Uuid::parse_str(SESSION_ID).expect("UUID").as_u128(),
            controller_device_id: "ios-1".to_owned(),
            controlled_device_id: controlled_device_id.to_owned(),
            permissions_digest: remote_crypto::permissions_digest(permissions).expect("digest"),
            protocol_version: PROTOCOL_VERSION,
            session_expires_at_epoch_millis: 60_000,
            selected_transport_path: TransportPath::LanDirect,
            selected_candidate_pair_id: 7,
            relay_node_id: None,
            key_exchange_transcript_hash: [0; 32],
        }
    }

    fn config(
        controlled_device_id: &str,
        role: SessionRole,
        public_key: [u8; 32],
    ) -> SessionHandshakeConfig {
        SessionHandshakeConfig {
            context: context(controlled_device_id),
            permissions: SessionPermissions {
                remote_desktop: true,
                input_control: true,
                require_prompt: false,
                ..SessionPermissions::default()
            },
            local_role: role,
            local_device_id: if role == SessionRole::Controlled {
                controlled_device_id.to_owned()
            } else {
                "ios-1".to_owned()
            },
            local_device_public_key: public_key,
            key_exchange_nonce: if role == SessionRole::Controlled {
                [4; 32]
            } else {
                [3; 32]
            },
            timestamp_epoch_millis: 1_000,
        }
    }

    fn peer_message(kind: SessionSignalMessageKind, payload: Value) -> SessionPeerMessage {
        SessionPeerMessage {
            kind,
            session_id: SESSION_ID.to_owned(),
            role: SessionRole::Controller,
            from_device_id: "ios-1".to_owned(),
            payload,
        }
    }

    fn selected_path(controlled_device_id: &str) -> ValidatedCandidatePath {
        let remote_candidate = ConnectionCandidateDto {
            candidate_id: 11,
            session_id: Uuid::parse_str(SESSION_ID).expect("UUID").as_u128(),
            device_id: "ios-1".to_owned(),
            role: SessionRole::Controller,
            kind: TransportPath::LanDirect,
            endpoint: "192.168.1.20:50000".to_owned(),
            source: CandidateSource::LocalInterface,
            observe_result_id: None,
            priority: 1,
            rtt_ms: None,
            loss_ppm: None,
            jitter_ms: None,
            relay_node_id: None,
        };
        ValidatedCandidatePath {
            controller_candidate_id: remote_candidate.candidate_id,
            controlled_candidate_id: 12,
            remote_candidate,
            binding: SecurePathBinding {
                transport_path: TransportPath::LanDirect,
                candidate_pair_id: 7,
                relay_node_id: None,
                permissions_digest: context(controlled_device_id).permissions_digest,
            },
        }
    }

    #[test]
    fn candidate_is_validated_before_transport_selection_is_unblocked() {
        let identity = DeviceIdentity::generate();
        let mut runtime = ControlledSignalRuntime::from_accepted(&snapshot(identity.device_id()))
            .expect("accepted runtime");
        let mut candidate = ConnectionCandidateDto {
            candidate_id: 0,
            session_id: Uuid::parse_str(SESSION_ID).expect("UUID").as_u128(),
            device_id: "ios-1".to_owned(),
            role: SessionRole::Controller,
            kind: TransportPath::UdpP2p,
            endpoint: "198.51.100.10:50000".to_owned(),
            source: CandidateSource::UdpObserved,
            observe_result_id: Some("observe-1".to_owned()),
            priority: 1,
            rtt_ms: None,
            loss_ppm: None,
            jitter_ms: None,
            relay_node_id: None,
        };
        candidate.candidate_id = remote_transport::candidate_id(&candidate).expect("candidate ID");
        let authorization = CandidateAuthorization {
            candidate_token: vec![1, 2, 3],
            candidate_token_binding_hash: remote_transport::candidate_token_binding_hash(
                &candidate, 30_000,
            )
            .expect("binding"),
            expires_at_epoch_millis: 30_000,
        };
        let candidate_message = peer_message(
            SessionSignalMessageKind::ConnectionCandidate,
            serde_json::json!({ "candidate": candidate, "authorization": authorization }),
        );
        runtime
            .handle_peer_message(&candidate_message, 1_000)
            .expect("authorized candidate");
        assert_eq!(
            runtime.state(),
            ControlledSignalState::AwaitingTransportSelection
        );
        assert_eq!(
            runtime.handle_peer_message(&candidate_message, 60_000),
            Err(ControlledSignalRuntimeError::SessionExpired)
        );
        assert_eq!(runtime.state(), ControlledSignalState::Failed);
        assert!(runtime.received_candidate_ids.is_empty());
    }

    #[test]
    fn signed_exchange_and_key_confirm_reach_ready_only_after_peer_confirm() {
        let identity = DeviceIdentity::generate();
        let controller_key = DeviceKeyPair::from_private_key([7; 32]);
        let mut runtime = ControlledSignalRuntime::from_accepted(&snapshot(identity.device_id()))
            .expect("accepted runtime");
        runtime.state = ControlledSignalState::AwaitingTransportSelection;
        runtime
            .set_controller_public_key("ios-1", controller_key.public_key)
            .expect("peer key");
        let selected_path = selected_path(identity.device_id());
        runtime
            .received_candidate_ids
            .insert(selected_path.controller_candidate_id);
        let handshake_config = config(
            identity.device_id(),
            SessionRole::Controlled,
            identity.public_key(),
        );
        let mut mismatched_path = selected_path.clone();
        mismatched_path.binding.candidate_pair_id = 8;
        assert_eq!(
            runtime.begin_key_exchange(handshake_config.clone(), &mismatched_path, &identity),
            Err(ControlledSignalRuntimeError::TransportSelectionRequired)
        );
        let local_exchange = runtime
            .begin_key_exchange(handshake_config, &selected_path, &identity)
            .expect("local exchange");
        let ControlledSignalAction::Send { payload, .. } = local_exchange else {
            panic!("local exchange signal action");
        };
        let controlled_exchange: SignedKeyExchange =
            serde_json::from_value(payload).expect("controlled exchange");

        let mut controller = SessionHandshake::new(config(
            identity.device_id(),
            SessionRole::Controller,
            controller_key.public_key,
        ))
        .expect("controller handshake");
        let digest = controller
            .local_signature_digest()
            .expect("controller digest");
        let controller_exchange = controller
            .set_local_signature(controller_key.sign_digest(&digest).to_vec())
            .expect("controller signature")
            .clone();
        let actions = runtime
            .handle_peer_message(
                &peer_message(
                    SessionSignalMessageKind::KeyExchangeMessage,
                    serde_json::to_value(controller_exchange.clone()).expect("exchange JSON"),
                ),
                1_001,
            )
            .expect("controller exchange");
        assert_eq!(
            runtime.state(),
            ControlledSignalState::AwaitingPeerKeyConfirm
        );
        let ControlledSignalAction::Send { payload, .. } = &actions[0] else {
            panic!("controlled confirmation action");
        };
        let controlled_confirm: KeyConfirm =
            serde_json::from_value(payload.clone()).expect("controlled confirm");
        controller
            .verify_peer_message(controlled_exchange, &identity.public_key(), 1_001)
            .expect("verify controlled exchange");
        let ready = controller.finish(1_001).expect("controller ready");
        runtime
            .handle_peer_message(
                &peer_message(
                    SessionSignalMessageKind::KeyConfirm,
                    serde_json::to_value(ready.local_key_confirm).expect("confirm JSON"),
                ),
                1_002,
            )
            .expect("controller confirmation");
        assert_eq!(runtime.state(), ControlledSignalState::Ready);
        assert!(runtime.take_secure_session().is_some());
        assert!(controlled_confirm.confirm_mac.iter().any(|byte| *byte != 0));
    }
}
