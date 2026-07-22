use std::{
    collections::{HashMap, VecDeque},
    fmt,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use remote_protocol::{ConnectionCandidateDto, SessionRole, TransportPath};
use rustls::{ClientConfig as RustlsClientConfig, ServerConfig as RustlsServerConfig};
use subtle::ConstantTimeEq;
use tokio::net::UdpSocket;
use zeroize::Zeroize;

use crate::{
    candidate_id, candidate_pair_id, validate_ephemeral_candidate_authorization,
    validate_lan_probe_scope, BindingError, ConnectionCandidate, DataChannelError,
    DataChannelFailure, DataChannelLimits, DataChannelResult, EphemeralCandidateAuthorization,
    EphemeralToken, KeyReuseDecision, LinkMetrics, LocalNetwork, PathRace, QuicClientEndpoint,
    QuicDataChannel, QuicServerEndpoint, RaceAttempt, RaceConfig, RoleHandshake, SecurePathBinding,
    TransportCancellation, TransportKind,
};

const PROBE_MAGIC: [u8; 4] = *b"RCP1";
const MAX_PROBE_PACKET_BYTES: usize = 2_304;
const MAX_PROBE_TOKEN_BYTES: usize = 2_048;
pub const DEFAULT_PROBE_RATE_LIMIT: usize = 4;
pub const DEFAULT_PROBE_RATE_WINDOW_MILLIS: u64 = 1_000;

#[derive(Clone, PartialEq, Eq)]
pub struct P2pProbePacket {
    pub session_id: u128,
    pub candidate_id: u128,
    pub role: SessionRole,
    token: EphemeralToken,
    binding_hash: [u8; 32],
    pub probe_nonce: [u8; 32],
}

impl P2pProbePacket {
    pub fn new(
        authorization: &EphemeralCandidateAuthorization,
        role: SessionRole,
        probe_nonce: [u8; 32],
    ) -> Result<Self, BindingError> {
        if role == authorization.role || probe_nonce == [0; 32] {
            return Err(BindingError::ProbeRoleMismatch);
        }
        Ok(Self {
            session_id: authorization.session_id,
            candidate_id: authorization.candidate_id,
            role,
            token: authorization.token().clone(),
            binding_hash: *authorization.binding_hash(),
            probe_nonce,
        })
    }

    pub fn token(&self) -> &EphemeralToken {
        &self.token
    }

    pub const fn binding_hash(&self) -> &[u8; 32] {
        &self.binding_hash
    }
}

impl fmt::Debug for P2pProbePacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("P2pProbePacket")
            .field("session_id", &self.session_id)
            .field("candidate_id", &self.candidate_id)
            .field("role", &self.role)
            .field("authorization", &"<redacted>")
            .field("probe_nonce", &self.probe_nonce)
            .finish()
    }
}

#[derive(Debug, Default)]
pub struct P2pProbeReplayGuard {
    seen: HashMap<(u128, u128, SessionRole, [u8; 32]), u64>,
}

impl P2pProbeReplayGuard {
    pub fn validate(
        &mut self,
        candidate: &ConnectionCandidateDto,
        authorization: &EphemeralCandidateAuthorization,
        packet: &P2pProbePacket,
        now_epoch_millis: u64,
    ) -> Result<(), BindingError> {
        validate_ephemeral_candidate_authorization(candidate, authorization, now_epoch_millis)?;
        if packet.session_id != candidate.session_id
            || packet.candidate_id != candidate.candidate_id
            || packet.role == candidate.role
        {
            return Err(BindingError::ProbeRoleMismatch);
        }
        if !packet
            .token
            .constant_time_eq(authorization.token().expose_for_transport())
        {
            return Err(BindingError::TokenMismatch);
        }
        if !bool::from(packet.binding_hash.ct_eq(authorization.binding_hash())) {
            return Err(BindingError::TokenBindingMismatch);
        }
        self.seen
            .retain(|_, expires_at| *expires_at >= now_epoch_millis);
        let key = (
            packet.session_id,
            packet.candidate_id,
            packet.role,
            packet.probe_nonce,
        );
        if self
            .seen
            .insert(key, authorization.expires_at_epoch_millis())
            .is_some()
        {
            return Err(BindingError::ProbeReplay);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct P2pProbeRateLimiter {
    max_attempts: usize,
    window_millis: u64,
    attempts: HashMap<(u128, u128), VecDeque<u64>>,
}

impl Default for P2pProbeRateLimiter {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_PROBE_RATE_LIMIT,
            window_millis: DEFAULT_PROBE_RATE_WINDOW_MILLIS,
            attempts: HashMap::new(),
        }
    }
}

impl P2pProbeRateLimiter {
    pub fn new(max_attempts: usize, window_millis: u64) -> Result<Self, BindingError> {
        if max_attempts == 0 || window_millis == 0 {
            return Err(BindingError::InvalidState);
        }
        Ok(Self {
            max_attempts,
            window_millis,
            attempts: HashMap::new(),
        })
    }

    pub fn check(
        &mut self,
        session_id: u128,
        candidate_id: u128,
        now_epoch_millis: u64,
    ) -> Result<(), BindingError> {
        let oldest_allowed = now_epoch_millis.saturating_sub(self.window_millis);
        let attempts = self.attempts.entry((session_id, candidate_id)).or_default();
        while attempts
            .front()
            .is_some_and(|value| *value <= oldest_allowed)
        {
            attempts.pop_front();
        }
        if attempts.len() >= self.max_attempts {
            return Err(BindingError::ProbeRateLimited);
        }
        attempts.push_back(now_epoch_millis);
        Ok(())
    }
}

pub struct ProbedP2pSocket {
    socket: UdpSocket,
    remote: SocketAddr,
    path: TransportKind,
}

impl fmt::Debug for ProbedP2pSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProbedP2pSocket")
            .field("local", &self.socket.local_addr().ok())
            .field("remote", &self.remote)
            .field("path", &self.path)
            .finish()
    }
}

impl ProbedP2pSocket {
    pub async fn connect_quic(
        self,
        tls_config: Arc<RustlsClientConfig>,
        limits: DataChannelLimits,
        server_name: &str,
        handshake: RoleHandshake,
        cancellation: &TransportCancellation,
    ) -> DataChannelResult<QuicDataChannel> {
        if handshake.role != SessionRole::Controller {
            return Err(DataChannelError::new(
                DataChannelFailure::Protocol,
                "verify_p2p_client_role",
            ));
        }
        let remote = self.remote;
        let path = self.path;
        let socket = self.socket.into_std().map_err(|_| {
            DataChannelError::new(DataChannelFailure::Io, "adopt_p2p_client_socket")
        })?;
        QuicClientEndpoint::from_std_socket(socket, tls_config, limits)?
            .connect(remote, server_name, path, handshake, cancellation)
            .await
    }

    pub async fn accept_quic(
        self,
        tls_config: Arc<RustlsServerConfig>,
        limits: DataChannelLimits,
        handshake: RoleHandshake,
        cancellation: &TransportCancellation,
    ) -> DataChannelResult<QuicDataChannel> {
        if handshake.role != SessionRole::Controlled {
            return Err(DataChannelError::new(
                DataChannelFailure::Protocol,
                "verify_p2p_server_role",
            ));
        }
        let remote = self.remote;
        let path = self.path;
        let socket = self.socket.into_std().map_err(|_| {
            DataChannelError::new(DataChannelFailure::Io, "adopt_p2p_server_socket")
        })?;
        let channel = QuicServerEndpoint::from_std_socket(socket, tls_config, limits)?
            .accept(path, handshake, cancellation)
            .await?;
        if channel.remote_address() != remote {
            channel.close();
            return Err(DataChannelError::new(
                DataChannelFailure::Authentication,
                "verify_probed_quic_peer",
            ));
        }
        Ok(channel)
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn probe_authorized_candidate(
    socket: UdpSocket,
    remote_candidate: &ConnectionCandidateDto,
    authorization: &EphemeralCandidateAuthorization,
    local_role: SessionRole,
    probe_nonce: [u8; 32],
    local_networks: &[LocalNetwork],
    rate_limiter: &mut P2pProbeRateLimiter,
    now_epoch_millis: u64,
    timeout: Duration,
) -> Result<ProbedP2pSocket, BindingError> {
    validate_ephemeral_candidate_authorization(remote_candidate, authorization, now_epoch_millis)?;
    let remote = p2p_remote_endpoint(remote_candidate, local_networks)?;
    rate_limiter.check(
        remote_candidate.session_id,
        remote_candidate.candidate_id,
        now_epoch_millis,
    )?;
    let packet = P2pProbePacket::new(authorization, local_role, probe_nonce)?;
    let mut encoded = encode_probe_packet(&packet)?;
    socket
        .send_to(&encoded, remote)
        .await
        .map_err(|_| BindingError::InvalidEndpoint)?;
    let mut echoed = vec![0_u8; MAX_PROBE_PACKET_BYTES + 1];
    let (echoed_len, peer) = tokio::time::timeout(timeout, socket.recv_from(&mut echoed))
        .await
        .map_err(|_| BindingError::InvalidState)?
        .map_err(|_| BindingError::InvalidEndpoint)?;
    if peer != remote
        || echoed_len != encoded.len()
        || !bool::from(echoed[..echoed_len].ct_eq(&encoded))
    {
        encoded.zeroize();
        echoed.zeroize();
        return Err(BindingError::ProbeMalformed);
    }
    encoded.zeroize();
    echoed.zeroize();
    Ok(ProbedP2pSocket {
        socket,
        remote,
        path: transport_kind(remote_candidate.kind)?,
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn accept_authorized_probe(
    socket: UdpSocket,
    expected_peer: SocketAddr,
    local_candidate: &ConnectionCandidateDto,
    authorization: &EphemeralCandidateAuthorization,
    local_networks: &[LocalNetwork],
    replay_guard: &mut P2pProbeReplayGuard,
    now_epoch_millis: u64,
    timeout: Duration,
) -> Result<ProbedP2pSocket, BindingError> {
    validate_ephemeral_candidate_authorization(local_candidate, authorization, now_epoch_millis)?;
    if local_candidate.kind == TransportPath::LanDirect {
        validate_lan_probe_scope(&expected_peer.to_string(), local_networks)?;
    }
    let mut encoded = vec![0_u8; MAX_PROBE_PACKET_BYTES + 1];
    let (encoded_len, peer) = tokio::time::timeout(timeout, socket.recv_from(&mut encoded))
        .await
        .map_err(|_| BindingError::InvalidState)?
        .map_err(|_| BindingError::InvalidEndpoint)?;
    if peer != expected_peer || encoded_len > MAX_PROBE_PACKET_BYTES {
        encoded.zeroize();
        return Err(BindingError::ProbeMalformed);
    }
    let packet = decode_probe_packet(&encoded[..encoded_len])?;
    replay_guard.validate(local_candidate, authorization, &packet, now_epoch_millis)?;
    socket
        .send_to(&encoded[..encoded_len], peer)
        .await
        .map_err(|_| BindingError::InvalidEndpoint)?;
    encoded.zeroize();
    Ok(ProbedP2pSocket {
        socket,
        remote: peer,
        path: transport_kind(local_candidate.kind)?,
    })
}

fn p2p_remote_endpoint(
    candidate: &ConnectionCandidateDto,
    local_networks: &[LocalNetwork],
) -> Result<SocketAddr, BindingError> {
    match candidate.kind {
        TransportPath::LanDirect => validate_lan_probe_scope(&candidate.endpoint, local_networks),
        TransportPath::UdpP2p => candidate
            .endpoint
            .parse()
            .map_err(|_| BindingError::InvalidEndpoint),
        _ => Err(BindingError::InvalidCandidateKindSource),
    }
}

fn encode_probe_packet(packet: &P2pProbePacket) -> Result<Vec<u8>, BindingError> {
    let token = packet.token.expose_for_transport();
    if token.is_empty() || token.len() > MAX_PROBE_TOKEN_BYTES {
        return Err(BindingError::ProbeMalformed);
    }
    let token_len = u16::try_from(token.len()).map_err(|_| BindingError::ProbeMalformed)?;
    let mut bytes = Vec::with_capacity(128 + token.len());
    bytes.extend_from_slice(&PROBE_MAGIC);
    bytes.extend_from_slice(&packet.session_id.to_be_bytes());
    bytes.extend_from_slice(&packet.candidate_id.to_be_bytes());
    bytes.push(match packet.role {
        SessionRole::Controller => 1,
        SessionRole::Controlled => 2,
    });
    bytes.extend_from_slice(&token_len.to_be_bytes());
    bytes.extend_from_slice(token);
    bytes.extend_from_slice(&packet.binding_hash);
    bytes.extend_from_slice(&packet.probe_nonce);
    Ok(bytes)
}

fn decode_probe_packet(bytes: &[u8]) -> Result<P2pProbePacket, BindingError> {
    if bytes.len() > MAX_PROBE_PACKET_BYTES || bytes.get(..4) != Some(&PROBE_MAGIC) {
        return Err(BindingError::ProbeMalformed);
    }
    let mut offset = 4;
    let session_id = take_array::<16>(bytes, &mut offset).map(u128::from_be_bytes)?;
    let candidate_id = take_array::<16>(bytes, &mut offset).map(u128::from_be_bytes)?;
    let role = match take_array::<1>(bytes, &mut offset)?[0] {
        1 => SessionRole::Controller,
        2 => SessionRole::Controlled,
        _ => return Err(BindingError::ProbeMalformed),
    };
    let token_len = usize::from(u16::from_be_bytes(take_array::<2>(bytes, &mut offset)?));
    if token_len == 0 || token_len > MAX_PROBE_TOKEN_BYTES {
        return Err(BindingError::ProbeMalformed);
    }
    let token_end = offset
        .checked_add(token_len)
        .ok_or(BindingError::ProbeMalformed)?;
    let token = bytes
        .get(offset..token_end)
        .ok_or(BindingError::ProbeMalformed)?
        .to_vec();
    offset = token_end;
    let binding_hash = take_array(bytes, &mut offset)?;
    let probe_nonce = take_array(bytes, &mut offset)?;
    if offset != bytes.len() || probe_nonce == [0; 32] {
        return Err(BindingError::ProbeMalformed);
    }
    Ok(P2pProbePacket {
        session_id,
        candidate_id,
        role,
        token: EphemeralToken::new(token),
        binding_hash,
        probe_nonce,
    })
}

fn take_array<const N: usize>(bytes: &[u8], offset: &mut usize) -> Result<[u8; N], BindingError> {
    let end = offset.checked_add(N).ok_or(BindingError::ProbeMalformed)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(BindingError::ProbeMalformed)?
        .try_into()
        .map_err(|_| BindingError::ProbeMalformed)?;
    *offset = end;
    Ok(value)
}

pub struct CandidatePairInput {
    pub controller: ConnectionCandidateDto,
    pub controlled: ConnectionCandidateDto,
    pub remote_authorization: Option<EphemeralCandidateAuthorization>,
}

impl fmt::Debug for CandidatePairInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CandidatePairInput")
            .field("controller_candidate_id", &self.controller.candidate_id)
            .field("controlled_candidate_id", &self.controlled.candidate_id)
            .field("kind", &self.controller.kind)
            .field("remote_authorization", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedCandidatePath {
    pub controller_candidate_id: u128,
    pub controlled_candidate_id: u128,
    pub remote_candidate: ConnectionCandidateDto,
    pub binding: SecurePathBinding,
}

pub struct CandidateRaceOrchestrator {
    race: PathRace,
    paths: Vec<ValidatedCandidatePath>,
    authorizations: Vec<Option<EphemeralCandidateAuthorization>>,
}

impl CandidateRaceOrchestrator {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        local_role: SessionRole,
        inputs: impl IntoIterator<Item = CandidatePairInput>,
        local_networks: &[LocalNetwork],
        permissions_digest: [u8; 32],
        now_epoch_millis: u64,
        race_config: RaceConfig,
    ) -> Result<Self, BindingError> {
        let mut race_candidates = Vec::new();
        let mut paths = Vec::new();
        let mut authorizations = Vec::new();
        for input in inputs {
            let controller_id = candidate_id(&input.controller)?;
            let controlled_id = candidate_id(&input.controlled)?;
            if controller_id != input.controller.candidate_id
                || controlled_id != input.controlled.candidate_id
            {
                return Err(BindingError::CandidateIdMismatch);
            }
            if input.controller.session_id != input.controlled.session_id
                || input.controller.role != SessionRole::Controller
                || input.controlled.role != SessionRole::Controlled
                || input.controller.kind != input.controlled.kind
                || input.controller.relay_node_id != input.controlled.relay_node_id
            {
                return Err(BindingError::InvalidCandidateKindSource);
            }
            let remote_candidate = match local_role {
                SessionRole::Controller => input.controlled.clone(),
                SessionRole::Controlled => input.controller.clone(),
            };
            let path_kind = transport_kind(remote_candidate.kind)?;
            let relay_node_id = remote_candidate.relay_node_id.as_deref();
            let pair_id = candidate_pair_id(
                remote_candidate.session_id,
                controller_id,
                controlled_id,
                remote_candidate.kind,
                relay_node_id,
            )?;
            match path_kind {
                TransportKind::LanDirect | TransportKind::UdpP2p => {
                    let authorization = input
                        .remote_authorization
                        .as_ref()
                        .ok_or(BindingError::TokenMismatch)?;
                    validate_ephemeral_candidate_authorization(
                        &remote_candidate,
                        authorization,
                        now_epoch_millis,
                    )?;
                    p2p_remote_endpoint(&remote_candidate, local_networks)?;
                }
                TransportKind::QuicRelay | TransportKind::Tls443Relay => {
                    if input.remote_authorization.is_some() {
                        return Err(BindingError::InvalidCandidateKindSource);
                    }
                }
            }
            race_candidates.push(ConnectionCandidate {
                kind: path_kind,
                endpoint: remote_candidate.endpoint.clone(),
                rtt_ms: remote_candidate.rtt_ms,
            });
            paths.push(ValidatedCandidatePath {
                controller_candidate_id: controller_id,
                controlled_candidate_id: controlled_id,
                remote_candidate,
                binding: SecurePathBinding {
                    transport_path: input.controller.kind,
                    candidate_pair_id: pair_id,
                    relay_node_id: input.controller.relay_node_id.clone(),
                    permissions_digest,
                },
            });
            authorizations.push(input.remote_authorization);
        }
        Ok(Self {
            race: PathRace::new(race_candidates, now_epoch_millis, race_config),
            paths,
            authorizations,
        })
    }

    pub fn take_due_attempts(&mut self, now_epoch_millis: u64) -> Vec<RaceAttempt> {
        self.race.take_due_attempts(now_epoch_millis)
    }

    pub fn path(&self, attempt_id: usize) -> Option<&ValidatedCandidatePath> {
        self.paths.get(attempt_id)
    }

    pub fn authorization(&self, attempt_id: usize) -> Option<&EphemeralCandidateAuthorization> {
        self.authorizations.get(attempt_id).and_then(Option::as_ref)
    }

    pub fn record_failure(&mut self, attempt_id: usize) -> Result<(), BindingError> {
        self.race
            .record_failure(attempt_id)
            .map_err(|_| BindingError::InvalidState)
    }

    pub fn record_success(
        &mut self,
        attempt_id: usize,
        metrics: LinkMetrics,
    ) -> Result<(), BindingError> {
        self.race
            .record_success(attempt_id, metrics)
            .map_err(|_| BindingError::InvalidState)
    }

    pub fn winner_binding(&self) -> Option<&SecurePathBinding> {
        self.race
            .best_success()
            .and_then(|winner| self.paths.get(winner.attempt_id))
            .map(|path| &path.binding)
    }

    pub fn reconnect_decision_for(
        active: &SecurePathBinding,
        selected: &SecurePathBinding,
    ) -> KeyReuseDecision {
        if active == selected {
            KeyReuseDecision::ResumeExistingKeys
        } else {
            KeyReuseDecision::RekeyRequired
        }
    }
}

fn transport_kind(path: TransportPath) -> Result<TransportKind, BindingError> {
    match path {
        TransportPath::LanDirect => Ok(TransportKind::LanDirect),
        TransportPath::UdpP2p => Ok(TransportKind::UdpP2p),
        TransportPath::QuicRelay => Ok(TransportKind::QuicRelay),
        TransportPath::Tls443Relay => Ok(TransportKind::Tls443Relay),
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use remote_crypto::{decrypt_payload, encrypt_payload, ReplayGuard};
    use remote_protocol::{
        CandidateSource, CandidateTokenIssued, ChannelId, MessageHeader, MessageKind,
        TrafficDirection,
    };

    use super::*;
    use crate::{
        candidate_token_binding_hash,
        test_tls::{client_config, server_config},
        OpaqueFrame,
    };

    const SESSION_ID: u128 = 0x9911;
    const NOW: u64 = 10_000;

    fn candidate(
        role: SessionRole,
        kind: TransportPath,
        endpoint: SocketAddr,
    ) -> ConnectionCandidateDto {
        let mut candidate = ConnectionCandidateDto {
            candidate_id: 0,
            session_id: SESSION_ID,
            device_id: match role {
                SessionRole::Controller => "controller",
                SessionRole::Controlled => "controlled",
            }
            .to_owned(),
            role,
            kind,
            endpoint: endpoint.to_string(),
            source: match kind {
                TransportPath::LanDirect => CandidateSource::LocalInterface,
                TransportPath::UdpP2p => CandidateSource::UdpObserved,
                TransportPath::QuicRelay | TransportPath::Tls443Relay => {
                    CandidateSource::RelayAllocated
                }
            },
            observe_result_id: (kind == TransportPath::UdpP2p).then(|| "observe-1".to_owned()),
            priority: 1,
            rtt_ms: Some(10),
            loss_ppm: Some(0),
            jitter_ms: Some(0),
            relay_node_id: kind.is_relay().then(|| "relay-a".to_owned()),
        };
        candidate.candidate_id = candidate_id(&candidate).expect("candidate id");
        candidate
    }

    fn authorization(candidate: &ConnectionCandidateDto) -> EphemeralCandidateAuthorization {
        let expires_at = NOW + 50_000;
        let issued = CandidateTokenIssued {
            session_id: candidate.session_id,
            device_id: candidate.device_id.clone(),
            role: candidate.role,
            candidate_id: candidate.candidate_id,
            candidate_token: b"candidate-token".to_vec(),
            candidate_token_binding_hash: candidate_token_binding_hash(candidate, expires_at)
                .expect("binding"),
            expires_at_epoch_millis: expires_at,
        };
        EphemeralCandidateAuthorization::from_issued(candidate, issued, NOW).expect("authorization")
    }

    #[test]
    fn probe_rejects_tampering_trailing_payload_and_nonce_replay() {
        let candidate = candidate(
            SessionRole::Controlled,
            TransportPath::UdpP2p,
            "198.51.100.1:50000".parse().expect("address"),
        );
        let authorization = authorization(&candidate);
        let packet =
            P2pProbePacket::new(&authorization, SessionRole::Controller, [8; 32]).expect("probe");
        let mut encoded = encode_probe_packet(&packet).expect("encode");
        let decoded = decode_probe_packet(&encoded).expect("decode");
        let mut guard = P2pProbeReplayGuard::default();
        assert!(guard
            .validate(&candidate, &authorization, &decoded, NOW)
            .is_ok());
        assert_eq!(
            guard.validate(&candidate, &authorization, &decoded, NOW),
            Err(BindingError::ProbeReplay)
        );
        encoded.push(1);
        assert_eq!(
            decode_probe_packet(&encoded),
            Err(BindingError::ProbeMalformed)
        );

        let mut tampered = packet;
        tampered.binding_hash[0] ^= 1;
        assert_eq!(
            P2pProbeReplayGuard::default().validate(&candidate, &authorization, &tampered, NOW,),
            Err(BindingError::TokenBindingMismatch)
        );
    }

    #[test]
    fn probe_rate_limit_is_bounded_per_session_candidate() {
        let mut limiter = P2pProbeRateLimiter::new(2, 1_000).expect("limiter");
        assert!(limiter.check(1, 2, 1_000).is_ok());
        assert!(limiter.check(1, 2, 1_100).is_ok());
        assert_eq!(
            limiter.check(1, 2, 1_200),
            Err(BindingError::ProbeRateLimited)
        );
        assert!(limiter.check(1, 2, 2_001).is_ok());
    }

    #[test]
    fn validated_race_falls_back_and_changed_pair_requires_rekey() {
        let controller_addr = "198.51.100.10:50000".parse().expect("controller");
        let controlled_addr = "198.51.100.11:50000".parse().expect("controlled");
        let controller = candidate(
            SessionRole::Controller,
            TransportPath::UdpP2p,
            controller_addr,
        );
        let controlled = candidate(
            SessionRole::Controlled,
            TransportPath::UdpP2p,
            controlled_addr,
        );
        let auth = authorization(&controlled);
        let relay_controller = candidate(
            SessionRole::Controller,
            TransportPath::QuicRelay,
            "203.0.113.10:443".parse().expect("relay"),
        );
        let relay_controlled = candidate(
            SessionRole::Controlled,
            TransportPath::QuicRelay,
            "203.0.113.10:443".parse().expect("relay"),
        );
        let mut orchestrator = CandidateRaceOrchestrator::new(
            SessionRole::Controller,
            [
                CandidatePairInput {
                    controller,
                    controlled,
                    remote_authorization: Some(auth),
                },
                CandidatePairInput {
                    controller: relay_controller,
                    controlled: relay_controlled,
                    remote_authorization: None,
                },
            ],
            &[],
            [4; 32],
            NOW,
            RaceConfig::default(),
        )
        .expect("orchestrator");
        assert_eq!(orchestrator.take_due_attempts(NOW).len(), 2);
        orchestrator.record_failure(0).expect("p2p failed");
        orchestrator
            .record_success(
                1,
                LinkMetrics {
                    rtt_ms: 20,
                    loss_ppm: 0,
                    jitter_ms: 1,
                },
            )
            .expect("relay succeeds");
        let relay_binding = orchestrator.winner_binding().expect("winner");
        assert_eq!(relay_binding.transport_path, TransportPath::QuicRelay);
        let old = SecurePathBinding {
            transport_path: TransportPath::UdpP2p,
            candidate_pair_id: 1,
            relay_node_id: None,
            permissions_digest: [4; 32],
        };
        assert_eq!(
            CandidateRaceOrchestrator::reconnect_decision_for(&old, relay_binding),
            KeyReuseDecision::RekeyRequired
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn udp_p2p_probe_then_quic_carries_only_encrypted_frames() {
        encrypted_p2p_round_trip(TransportPath::UdpP2p, "127.0.0.1").await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires REMOTE_TEST_LAN_IP bound to a routable private interface"]
    async fn lan_direct_probe_then_quic_carries_only_encrypted_frames() {
        let ip = std::env::var("REMOTE_TEST_LAN_IP").expect("REMOTE_TEST_LAN_IP");
        encrypted_p2p_round_trip(TransportPath::LanDirect, &ip).await;
    }

    async fn encrypted_p2p_round_trip(path: TransportPath, bind_ip: &str) {
        let server_socket = UdpSocket::bind(format!("{bind_ip}:0"))
            .await
            .expect("server socket");
        let server_addr = server_socket.local_addr().expect("server address");
        let client_socket = UdpSocket::bind(format!("{bind_ip}:0"))
            .await
            .expect("client socket");
        let client_addr = client_socket.local_addr().expect("client address");
        let server_candidate = candidate(SessionRole::Controlled, path, server_addr);
        let authorization = authorization(&server_candidate);
        let server_candidate_for_task = server_candidate.clone();
        let server_authorization = authorization.clone();
        let networks = if path == TransportPath::LanDirect {
            vec![LocalNetwork::new(server_addr.ip(), 24).expect("LAN network")]
        } else {
            Vec::new()
        };
        let server_networks = networks.clone();
        let limits = DataChannelLimits::default();
        let server_task = tokio::spawn(async move {
            let mut guard = P2pProbeReplayGuard::default();
            let probed = accept_authorized_probe(
                server_socket,
                client_addr,
                &server_candidate_for_task,
                &server_authorization,
                &server_networks,
                &mut guard,
                NOW,
                Duration::from_secs(2),
            )
            .await
            .expect("accept probe");
            probed
                .accept_quic(
                    server_config(),
                    limits,
                    RoleHandshake::new(SESSION_ID, SessionRole::Controlled),
                    &TransportCancellation::default(),
                )
                .await
                .expect("accept QUIC")
        });

        let mut limiter = P2pProbeRateLimiter::default();
        let probed = probe_authorized_candidate(
            client_socket,
            &server_candidate,
            &authorization,
            SessionRole::Controller,
            [9; 32],
            &networks,
            &mut limiter,
            NOW,
            Duration::from_secs(2),
        )
        .await
        .expect("probe candidate");
        let client_channel = probed
            .connect_quic(
                client_config(),
                limits,
                "localhost",
                RoleHandshake::new(SESSION_ID, SessionRole::Controller),
                &TransportCancellation::default(),
            )
            .await
            .expect("connect QUIC");
        let server_channel = server_task.await.expect("server task");

        let key = [1; 32];
        let prefix = [2; 4];
        let permissions = [3; 32];
        let header = MessageHeader::new_on_channel(
            MessageKind::InputEvent,
            ChannelId::InputReliable,
            SESSION_ID,
            1,
            0,
        )
        .expect("header");
        let (header, ciphertext) = encrypt_payload(
            &key,
            &prefix,
            &permissions,
            TrafficDirection::ControllerToControlled,
            header,
            b"private-input",
        )
        .expect("encrypt");
        assert!(!ciphertext
            .windows(13)
            .any(|window| window == b"private-input"));
        let encrypted = OpaqueFrame::new(header, Bytes::from(ciphertext)).expect("frame");
        client_channel
            .send_reliable(&encrypted)
            .await
            .expect("send ciphertext");
        let received = server_channel
            .receive_reliable(ChannelId::InputReliable)
            .await
            .expect("receive ciphertext");
        let plaintext = decrypt_payload(
            &key,
            &prefix,
            &permissions,
            TrafficDirection::ControllerToControlled,
            received.header(),
            received.opaque_payload(),
            &mut ReplayGuard::default(),
        )
        .expect("decrypt");
        assert_eq!(plaintext, b"private-input");
        client_channel.close();
    }
}
