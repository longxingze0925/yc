use std::{fmt, net::SocketAddr, sync::Arc, time::Duration};

use remote_capture::ScreenCapturer;
use remote_core::{SecureSession, SecureSessionError, SecureSessionState};
use remote_protocol::{
    CandidateAuthorization, CandidateTokenIssued, ConnectionCandidateDto, SessionRole,
    TransportPath,
};
use remote_runtime::{SecureQuicChannel, SecureQuicError};
use remote_transport::{
    accept_authorized_probe, CandidatePairInput, CandidateRaceOrchestrator, DataChannelError,
    DataChannelLimits, EphemeralCandidateAuthorization, LinkMetrics, LocalNetwork,
    P2pProbeReplayGuard, ProbedP2pSocket, RaceConfig, RoleHandshake, TransportCancellation,
    ValidatedCandidatePath,
};
use rustls::ServerConfig;
use tokio::net::UdpSocket;

use crate::input::{InputBackend, InputManager};

use super::{run_controlled_quic_session, ControlledRuntimeError};

const P2P_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug)]
pub enum ControlledP2pTransportError {
    InvalidRole,
    SocketCandidateMismatch,
    Candidate(remote_transport::BindingError),
    Transport(DataChannelError),
    SecureSession(SecureSessionError),
    SecureChannel(SecureQuicError),
    Runtime(ControlledRuntimeError),
    InvalidState,
}

impl fmt::Display for ControlledP2pTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRole => {
                formatter.write_str("controlled P2P transport requires controlled candidates")
            }
            Self::SocketCandidateMismatch => {
                formatter.write_str("candidate endpoint does not match the retained UDP socket")
            }
            Self::Candidate(error) => write!(formatter, "candidate binding failed: {error:?}"),
            Self::Transport(error) => write!(formatter, "QUIC transport failed: {error}"),
            Self::SecureSession(error) => {
                write!(formatter, "secure session binding failed: {error:?}")
            }
            Self::SecureChannel(error) => write!(formatter, "secure QUIC channel failed: {error}"),
            Self::Runtime(error) => write!(formatter, "controlled runtime failed: {error}"),
            Self::InvalidState => formatter.write_str("controlled P2P transport state is invalid"),
        }
    }
}

impl std::error::Error for ControlledP2pTransportError {}

impl From<remote_transport::BindingError> for ControlledP2pTransportError {
    fn from(value: remote_transport::BindingError) -> Self {
        Self::Candidate(value)
    }
}

impl From<DataChannelError> for ControlledP2pTransportError {
    fn from(value: DataChannelError) -> Self {
        Self::Transport(value)
    }
}

impl From<SecureSessionError> for ControlledP2pTransportError {
    fn from(value: SecureSessionError) -> Self {
        Self::SecureSession(value)
    }
}

impl From<SecureQuicError> for ControlledP2pTransportError {
    fn from(value: SecureQuicError) -> Self {
        Self::SecureChannel(value)
    }
}

impl From<ControlledRuntimeError> for ControlledP2pTransportError {
    fn from(value: ControlledRuntimeError) -> Self {
        Self::Runtime(value)
    }
}

/// Owns the one UDP socket selected for a controlled P2P path. The socket is
/// retained from probe through QUIC acceptance so NAT state and the validated
/// peer address cannot be replaced between phases.
pub struct ControlledP2pTransport {
    local_candidate: ConnectionCandidateDto,
    local_authorization: EphemeralCandidateAuthorization,
    remote_candidate: ConnectionCandidateDto,
    selected_path: ValidatedCandidatePath,
    socket: Option<UdpSocket>,
    probed_socket: Option<ProbedP2pSocket>,
    local_networks: Vec<LocalNetwork>,
    replay_guard: P2pProbeReplayGuard,
    race: CandidateRaceOrchestrator,
}

impl fmt::Debug for ControlledP2pTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlledP2pTransport")
            .field("local_candidate_id", &self.local_candidate.candidate_id)
            .field("remote_candidate_id", &self.remote_candidate.candidate_id)
            .field("selected_path", &self.selected_path.binding.transport_path)
            .field("probe_complete", &self.probed_socket.is_some())
            .finish()
    }
}

impl ControlledP2pTransport {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        socket: UdpSocket,
        local_candidate: ConnectionCandidateDto,
        local_authorization: CandidateAuthorization,
        remote_candidate: ConnectionCandidateDto,
        remote_authorization: CandidateAuthorization,
        local_networks: Vec<LocalNetwork>,
        permissions_digest: [u8; 32],
        now_epoch_millis: u64,
    ) -> Result<Self, ControlledP2pTransportError> {
        if local_candidate.role != SessionRole::Controlled
            || remote_candidate.role != SessionRole::Controller
            || local_candidate.session_id != remote_candidate.session_id
            || local_candidate.kind != remote_candidate.kind
            || !matches!(
                local_candidate.kind,
                TransportPath::LanDirect | TransportPath::UdpP2p
            )
        {
            return Err(ControlledP2pTransportError::InvalidRole);
        }
        let socket_endpoint = socket
            .local_addr()
            .map_err(|_| ControlledP2pTransportError::SocketCandidateMismatch)?;
        if local_candidate.endpoint != socket_endpoint.to_string() {
            return Err(ControlledP2pTransportError::SocketCandidateMismatch);
        }
        let local_authorization =
            authorization_from_candidate(&local_candidate, local_authorization, now_epoch_millis)?;
        let remote_authorization = authorization_from_candidate(
            &remote_candidate,
            remote_authorization,
            now_epoch_millis,
        )?;
        let mut race = CandidateRaceOrchestrator::new(
            SessionRole::Controlled,
            [CandidatePairInput {
                controller: remote_candidate.clone(),
                controlled: local_candidate.clone(),
                remote_authorization: Some(remote_authorization),
            }],
            &local_networks,
            permissions_digest,
            now_epoch_millis,
            RaceConfig::default(),
        )?;
        let selected_path = race
            .path(0)
            .cloned()
            .ok_or(ControlledP2pTransportError::InvalidState)?;
        if race.take_due_attempts(now_epoch_millis).len() != 1 {
            return Err(ControlledP2pTransportError::InvalidState);
        }
        Ok(Self {
            local_candidate,
            local_authorization,
            remote_candidate,
            selected_path,
            socket: Some(socket),
            probed_socket: None,
            local_networks,
            replay_guard: P2pProbeReplayGuard::default(),
            race,
        })
    }

    pub fn selected_path(&self) -> Option<&ValidatedCandidatePath> {
        self.probed_socket.as_ref().map(|_| &self.selected_path)
    }

    pub fn local_candidate(&self) -> &ConnectionCandidateDto {
        &self.local_candidate
    }

    /// Waits for the controller's token-bound probe and only records a path as
    /// selected after the exact candidate endpoint has echoed that probe.
    pub async fn accept_probe(
        &mut self,
        now_epoch_millis: u64,
    ) -> Result<&ValidatedCandidatePath, ControlledP2pTransportError> {
        if self.probed_socket.is_some() {
            return self
                .selected_path()
                .ok_or(ControlledP2pTransportError::InvalidState);
        }
        let expected_peer = self
            .remote_candidate
            .endpoint
            .parse::<SocketAddr>()
            .map_err(|_| ControlledP2pTransportError::InvalidState)?;
        let socket = self
            .socket
            .take()
            .ok_or(ControlledP2pTransportError::InvalidState)?;
        let started = std::time::Instant::now();
        let probed = match accept_authorized_probe(
            socket,
            expected_peer,
            &self.local_candidate,
            &self.local_authorization,
            &self.local_networks,
            &mut self.replay_guard,
            now_epoch_millis,
            P2P_PROBE_TIMEOUT,
        )
        .await
        {
            Ok(probed) => probed,
            Err(error) => {
                let _ = self.race.record_failure(0);
                return Err(error.into());
            }
        };
        let elapsed = started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;
        self.race.record_success(
            0,
            LinkMetrics {
                rtt_ms: elapsed,
                ..LinkMetrics::default()
            },
        )?;
        if self.race.winner_binding() != Some(&self.selected_path.binding) {
            return Err(ControlledP2pTransportError::InvalidState);
        }
        self.probed_socket = Some(probed);
        self.selected_path()
            .ok_or(ControlledP2pTransportError::InvalidState)
    }

    /// Adopts the probed socket into Quinn after Signal key confirmation. It
    /// rejects a session whose permission digest or candidate binding differs
    /// from the path that was actually probed.
    pub async fn accept_secure_channel(
        &mut self,
        mut secure_session: SecureSession,
        tls_config: Arc<ServerConfig>,
        limits: DataChannelLimits,
        cancellation: &TransportCancellation,
    ) -> Result<Arc<SecureQuicChannel>, ControlledP2pTransportError> {
        if secure_session.state() != SecureSessionState::Ready {
            return Err(ControlledP2pTransportError::InvalidState);
        }
        let path = self
            .selected_path()
            .ok_or(ControlledP2pTransportError::InvalidState)?;
        secure_session.invalidate_if_binding_changed(
            path.binding.permissions_digest,
            path.binding.transport_path,
            path.binding.candidate_pair_id,
            path.binding.relay_node_id.as_deref(),
        )?;
        let probed_socket = self
            .probed_socket
            .take()
            .ok_or(ControlledP2pTransportError::InvalidState)?;
        let channel = probed_socket
            .accept_quic(
                tls_config,
                limits,
                RoleHandshake::new(secure_session.session_id(), SessionRole::Controlled),
                cancellation,
            )
            .await?;
        Ok(Arc::new(SecureQuicChannel::new(channel, secure_session)?))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn accept_and_run<B>(
        &mut self,
        secure_session: SecureSession,
        tls_config: Arc<ServerConfig>,
        limits: DataChannelLimits,
        cancellation: &TransportCancellation,
        capturer: Box<dyn ScreenCapturer>,
        input: InputManager<B>,
        display_id: String,
        frame_rate: u32,
    ) -> Result<(), ControlledP2pTransportError>
    where
        B: InputBackend + 'static,
    {
        let channel = self
            .accept_secure_channel(secure_session, tls_config, limits, cancellation)
            .await?;
        run_controlled_quic_session(channel, capturer, input, display_id, frame_rate)
            .await
            .map_err(Into::into)
    }

    pub fn close(&mut self) {
        self.socket.take();
        self.probed_socket.take();
    }
}

fn authorization_from_candidate(
    candidate: &ConnectionCandidateDto,
    authorization: CandidateAuthorization,
    now_epoch_millis: u64,
) -> Result<EphemeralCandidateAuthorization, ControlledP2pTransportError> {
    EphemeralCandidateAuthorization::from_issued(
        candidate,
        CandidateTokenIssued {
            session_id: candidate.session_id,
            device_id: candidate.device_id.clone(),
            role: candidate.role,
            candidate_id: candidate.candidate_id,
            candidate_token: authorization.candidate_token,
            candidate_token_binding_hash: authorization.candidate_token_binding_hash,
            expires_at_epoch_millis: authorization.expires_at_epoch_millis,
        },
        now_epoch_millis,
    )
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use remote_crypto::{derive_session_keys, permissions_digest};
    use remote_protocol::{
        CandidateSource, SessionKdfContext, SessionPermissions, TransportPath, PROTOCOL_VERSION,
    };
    use remote_transport::{
        candidate_id, candidate_token_binding_hash, probe_authorized_candidate, test_tls,
        DataChannelLimits, RoleHandshake, TransportCancellation,
    };

    use super::*;

    const SESSION_ID: u128 = 0x00000000_00004000_8000000000000001;

    fn candidate(
        device_id: &str,
        role: SessionRole,
        endpoint: SocketAddr,
    ) -> ConnectionCandidateDto {
        let mut candidate = ConnectionCandidateDto {
            candidate_id: 0,
            session_id: SESSION_ID,
            device_id: device_id.to_owned(),
            role,
            kind: TransportPath::UdpP2p,
            endpoint: endpoint.to_string(),
            source: CandidateSource::UdpObserved,
            observe_result_id: Some(format!("observe-{device_id}")),
            priority: 0,
            rtt_ms: None,
            loss_ppm: None,
            jitter_ms: None,
            relay_node_id: None,
        };
        candidate.candidate_id = candidate_id(&candidate).expect("candidate ID");
        candidate
    }

    fn authorization(candidate: &ConnectionCandidateDto) -> CandidateAuthorization {
        CandidateAuthorization {
            candidate_token: vec![7, 8, 9],
            candidate_token_binding_hash: candidate_token_binding_hash(candidate, 30_000)
                .expect("candidate binding"),
            expires_at_epoch_millis: 30_000,
        }
    }

    fn secure_pair(path: &ValidatedCandidatePath) -> (SecureSession, SecureSession) {
        let permissions = SessionPermissions {
            remote_desktop: true,
            input_control: true,
            require_prompt: false,
            ..SessionPermissions::default()
        };
        let digest = permissions_digest(permissions).expect("permissions digest");
        assert_eq!(digest, path.binding.permissions_digest);
        let context = SessionKdfContext {
            account_id: "account".to_owned(),
            session_id: SESSION_ID,
            controller_device_id: "ios-1".to_owned(),
            controlled_device_id: "ubuntu-1".to_owned(),
            permissions_digest: digest,
            protocol_version: PROTOCOL_VERSION,
            session_expires_at_epoch_millis: 60_000,
            selected_transport_path: path.binding.transport_path,
            selected_candidate_pair_id: path.binding.candidate_pair_id,
            relay_node_id: path.binding.relay_node_id.clone(),
            key_exchange_transcript_hash: [3; 32],
        };
        let controller_keys = derive_session_keys(&[4; 32], &context).expect("controller keys");
        let controlled_keys = derive_session_keys(&[4; 32], &context).expect("controlled keys");
        let mut controller = SecureSession::new(
            SESSION_ID,
            SessionRole::Controller,
            permissions,
            digest,
            path.binding.transport_path,
            path.binding.candidate_pair_id,
            path.binding.relay_node_id.clone(),
            [3; 32],
            controller_keys,
        )
        .expect("controller session");
        let mut controlled = SecureSession::new(
            SESSION_ID,
            SessionRole::Controlled,
            permissions,
            digest,
            path.binding.transport_path,
            path.binding.candidate_pair_id,
            path.binding.relay_node_id.clone(),
            [3; 32],
            controlled_keys,
        )
        .expect("controlled session");
        let controller_confirm = controller
            .create_local_key_confirm("ios-1".to_owned(), 1_000)
            .expect("controller confirm");
        let controlled_confirm = controlled
            .create_local_key_confirm("ubuntu-1".to_owned(), 1_000)
            .expect("controlled confirm");
        controller
            .verify_peer_key_confirm(&controlled_confirm, "ubuntu-1", 1_001)
            .expect("controller verification");
        controlled
            .verify_peer_key_confirm(&controller_confirm, "ios-1", 1_001)
            .expect("controlled verification");
        (controller, controlled)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn authorized_probe_is_retained_for_bound_quic_accept() {
        let controlled_socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("controlled socket");
        let controller_socket = UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("controller socket");
        let controlled_candidate = candidate(
            "ubuntu-1",
            SessionRole::Controlled,
            controlled_socket.local_addr().expect("controlled endpoint"),
        );
        let controller_candidate = candidate(
            "ios-1",
            SessionRole::Controller,
            controller_socket.local_addr().expect("controller endpoint"),
        );
        let permissions = SessionPermissions {
            remote_desktop: true,
            input_control: true,
            require_prompt: false,
            ..SessionPermissions::default()
        };
        let mut controlled = ControlledP2pTransport::new(
            controlled_socket,
            controlled_candidate.clone(),
            authorization(&controlled_candidate),
            controller_candidate.clone(),
            authorization(&controller_candidate),
            Vec::new(),
            permissions_digest(permissions).expect("permissions digest"),
            1_000,
        )
        .expect("controlled P2P transport");

        let controller_authorization = authorization(&controlled_candidate);
        let controller_task = tokio::spawn(async move {
            probe_authorized_candidate(
                controller_socket,
                &controlled_candidate,
                &authorization_from_candidate(
                    &controlled_candidate,
                    controller_authorization,
                    1_000,
                )
                .expect("controller authorization"),
                SessionRole::Controller,
                [9; 32],
                &[],
                &mut remote_transport::P2pProbeRateLimiter::default(),
                1_000,
                Duration::from_secs(3),
            )
            .await
            .expect("controller probe")
        });
        let selected = controlled
            .accept_probe(1_000)
            .await
            .expect("controlled probe")
            .clone();
        let controller_socket = controller_task.await.expect("controller task");
        let (controller_session, controlled_session) = secure_pair(&selected);
        let cancellation = TransportCancellation::default();
        let mut controlled_task = controlled;
        let server_task = tokio::spawn(async move {
            controlled_task
                .accept_secure_channel(
                    controlled_session,
                    test_tls::server_config(),
                    DataChannelLimits::default(),
                    &cancellation,
                )
                .await
                .expect("controlled QUIC channel")
        });
        let controller_channel = controller_socket
            .connect_quic(
                test_tls::client_config(),
                DataChannelLimits::default(),
                "localhost",
                RoleHandshake::new(SESSION_ID, SessionRole::Controller),
                &TransportCancellation::default(),
            )
            .await
            .expect("controller QUIC channel");
        let controlled_channel = server_task.await.expect("server task");
        let controller_channel = SecureQuicChannel::new(controller_channel, controller_session)
            .expect("controller secure QUIC channel");
        assert_eq!(controlled_channel.session_id(), SESSION_ID);
        assert_eq!(controller_channel.local_role(), SessionRole::Controller);
        controlled_channel.close();
        controller_channel.close();
    }
}
