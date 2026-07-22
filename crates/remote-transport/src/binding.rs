use std::collections::{HashMap, HashSet};

use remote_crypto::{sha256, verify_canonical_signature};
use remote_protocol::{
    CandidateAuthorization, CandidateSource, CanonicalWriter, ConnectionCandidateDto,
    RelayAllocation, RelayOpen, SessionRole, TransportPath,
};
use subtle::ConstantTimeEq;

pub const OBSERVE_TOKEN_MAX_TTL_MILLIS: u64 = 30_000;
pub const CANDIDATE_TOKEN_MAX_TTL_MILLIS: u64 = 60_000;
pub const RELAY_TOKEN_MAX_TTL_MILLIS: u64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingError {
    CanonicalEncoding,
    CandidateIdMismatch,
    InvalidCandidateKindSource,
    InvalidRelayNodeBinding,
    TokenMismatch,
    TokenBindingMismatch,
    TokenExpired,
    TokenTtlExceeded,
    TokenSignatureInvalid,
    AuthorizationUnavailable,
    AuthorizationExpired,
    SessionClosed,
    RelayNotAllowed,
    RelayNodeNotAllowed,
    RelayEpochMismatch,
    PermissionsMismatch,
    DeviceMismatch,
    DeviceKeyVersionMismatch,
    DeviceKeyRevoked,
    DeviceSignatureInvalid,
    NonceReplay,
    ProbeReplay,
    InvalidEndpoint,
    LanAddressForbidden,
    LanPortForbidden,
    LanCandidateLimitExceeded,
    LanClaimMissing,
    LanClaimHashMismatch,
    TimestampOutsideWindow,
    InvalidInterfaceHash,
    ObserveContextMismatch,
    ObserveResultMismatch,
    InvalidRequestedTtl,
    ProbeRoleMismatch,
    ProbeMalformed,
    ProbeRateLimited,
    LanNotRoutable,
    InvalidState,
}

pub fn candidate_id(candidate: &ConnectionCandidateDto) -> Result<u128, BindingError> {
    validate_candidate_shape(candidate)?;
    let mut writer = CanonicalWriter::new("rctl-candidate-id-v1")
        .map_err(|_| BindingError::CanonicalEncoding)?;
    writer
        .push_u128("session_id", candidate.session_id)
        .and_then(|writer| writer.push_str("device_id", &candidate.device_id))
        .and_then(|writer| writer.push_str("role", candidate.role.as_str()))
        .and_then(|writer| writer.push_str("kind", candidate.kind.as_str()))
        .and_then(|writer| writer.push_str("endpoint", &candidate.endpoint))
        .and_then(|writer| writer.push_str("source", candidate.source.as_str()))
        .and_then(|writer| {
            writer.push_optional_str("relay_node_id", candidate.relay_node_id.as_deref())
        })
        .map_err(|_| BindingError::CanonicalEncoding)?;
    let digest = sha256(&writer.finish());
    Ok(u128::from_be_bytes(
        digest[0..16].try_into().expect("fixed hash prefix"),
    ))
}

pub fn candidate_pair_id(
    session_id: u128,
    controller_candidate_id: u128,
    controlled_candidate_id: u128,
    selected_transport_path: TransportPath,
    relay_node_id: Option<&str>,
) -> Result<u128, BindingError> {
    if selected_transport_path.is_relay() != relay_node_id.is_some() {
        return Err(BindingError::InvalidRelayNodeBinding);
    }
    let mut writer = CanonicalWriter::new("rctl-candidate-pair-id-v1")
        .map_err(|_| BindingError::CanonicalEncoding)?;
    writer
        .push_u128("session_id", session_id)
        .and_then(|writer| writer.push_u128("controller_candidate_id", controller_candidate_id))
        .and_then(|writer| writer.push_u128("controlled_candidate_id", controlled_candidate_id))
        .and_then(|writer| {
            writer.push_str("selected_transport_path", selected_transport_path.as_str())
        })
        .and_then(|writer| writer.push_optional_str("relay_node_id", relay_node_id))
        .map_err(|_| BindingError::CanonicalEncoding)?;
    let digest = sha256(&writer.finish());
    Ok(u128::from_be_bytes(
        digest[0..16].try_into().expect("fixed hash prefix"),
    ))
}

pub fn candidate_token_binding_hash(
    candidate: &ConnectionCandidateDto,
    expires_at_epoch_millis: u64,
) -> Result<[u8; 32], BindingError> {
    let recomputed_id = candidate_id(candidate)?;
    if recomputed_id != candidate.candidate_id {
        return Err(BindingError::CandidateIdMismatch);
    }
    let mut writer = CanonicalWriter::new("rctl-candidate-token-binding-v1")
        .map_err(|_| BindingError::CanonicalEncoding)?;
    writer
        .push_u128("session_id", candidate.session_id)
        .and_then(|writer| writer.push_str("device_id", &candidate.device_id))
        .and_then(|writer| writer.push_str("role", candidate.role.as_str()))
        .and_then(|writer| writer.push_u128("candidate_id", candidate.candidate_id))
        .and_then(|writer| writer.push_str("kind", candidate.kind.as_str()))
        .and_then(|writer| writer.push_str("endpoint", &candidate.endpoint))
        .and_then(|writer| writer.push_str("source", candidate.source.as_str()))
        .and_then(|writer| {
            writer.push_optional_str("observe_result_id", candidate.observe_result_id.as_deref())
        })
        .and_then(|writer| writer.push_u64("expires_at_epoch_millis", expires_at_epoch_millis))
        .map_err(|_| BindingError::CanonicalEncoding)?;
    Ok(sha256(&writer.finish()))
}

pub fn validate_candidate_authorization(
    candidate: &ConnectionCandidateDto,
    authorization: &CandidateAuthorization,
    now_epoch_millis: u64,
) -> Result<(), BindingError> {
    if now_epoch_millis > authorization.expires_at_epoch_millis {
        return Err(BindingError::TokenExpired);
    }
    if authorization
        .expires_at_epoch_millis
        .saturating_sub(now_epoch_millis)
        > CANDIDATE_TOKEN_MAX_TTL_MILLIS
    {
        return Err(BindingError::TokenTtlExceeded);
    }
    let expected = candidate_token_binding_hash(candidate, authorization.expires_at_epoch_millis)?;
    if !bool::from(expected.ct_eq(&authorization.candidate_token_binding_hash)) {
        return Err(BindingError::TokenBindingMismatch);
    }
    if authorization.candidate_token.is_empty() {
        return Err(BindingError::TokenMismatch);
    }
    Ok(())
}

fn validate_candidate_shape(candidate: &ConnectionCandidateDto) -> Result<(), BindingError> {
    let valid_source = matches!(
        (candidate.kind, candidate.source),
        (TransportPath::LanDirect, CandidateSource::LocalInterface)
            | (TransportPath::UdpP2p, CandidateSource::UdpObserved)
            | (TransportPath::QuicRelay, CandidateSource::RelayAllocated)
            | (TransportPath::Tls443Relay, CandidateSource::RelayAllocated)
    );
    if !valid_source {
        return Err(BindingError::InvalidCandidateKindSource);
    }
    if candidate.kind.is_relay() != candidate.relay_node_id.is_some() {
        return Err(BindingError::InvalidRelayNodeBinding);
    }
    if (candidate.source == CandidateSource::UdpObserved) != candidate.observe_result_id.is_some() {
        return Err(BindingError::InvalidCandidateKindSource);
    }
    Ok(())
}

pub fn relay_token_binding_hash(allocation: &RelayAllocation) -> Result<[u8; 32], BindingError> {
    if !allocation.transport.is_relay() {
        return Err(BindingError::InvalidRelayNodeBinding);
    }
    let mut writer = CanonicalWriter::new("rctl-relay-token-binding-v1")
        .map_err(|_| BindingError::CanonicalEncoding)?;
    push_relay_binding_fields(
        &mut writer,
        allocation.session_id,
        &allocation.device_id,
        allocation.role,
        &allocation.controller_device_id,
        &allocation.controlled_device_id,
        &allocation.relay_node_id,
        allocation.transport,
        &allocation.permissions_digest,
        allocation.relay_token_epoch,
        allocation.issued_at_epoch_millis,
        allocation.expires_at_epoch_millis,
        &allocation.relay_token_id,
    )?;
    Ok(sha256(&writer.finish()))
}

pub fn relay_open_canonical_bytes(open: &RelayOpen) -> Result<Vec<u8>, BindingError> {
    let mut writer =
        CanonicalWriter::new("rctl-relay-open-v1").map_err(|_| BindingError::CanonicalEncoding)?;
    push_relay_binding_fields(
        &mut writer,
        open.session_id,
        &open.device_id,
        open.role,
        &open.controller_device_id,
        &open.controlled_device_id,
        &open.relay_node_id,
        open.transport,
        &open.permissions_digest,
        open.relay_token_epoch,
        open.issued_at_epoch_millis,
        open.expires_at_epoch_millis,
        &open.relay_token_id,
    )?;
    writer
        .push_field("relay_open_nonce", &open.relay_open_nonce)
        .and_then(|writer| writer.push_field("session_relay_token", &open.session_relay_token))
        .and_then(|writer| writer.push_field("token_binding_hash", &open.token_binding_hash))
        .map_err(|_| BindingError::CanonicalEncoding)?;
    Ok(writer.finish())
}

#[allow(clippy::too_many_arguments)]
fn push_relay_binding_fields(
    writer: &mut CanonicalWriter,
    session_id: u128,
    device_id: &str,
    role: SessionRole,
    controller_device_id: &str,
    controlled_device_id: &str,
    relay_node_id: &str,
    transport: TransportPath,
    permissions_digest: &[u8; 32],
    relay_token_epoch: u64,
    issued_at_epoch_millis: u64,
    expires_at_epoch_millis: u64,
    relay_token_id: &str,
) -> Result<(), BindingError> {
    writer
        .push_u128("session_id", session_id)
        .and_then(|writer| writer.push_str("device_id", device_id))
        .and_then(|writer| writer.push_str("role", role.as_str()))
        .and_then(|writer| writer.push_str("controller_device_id", controller_device_id))
        .and_then(|writer| writer.push_str("controlled_device_id", controlled_device_id))
        .and_then(|writer| writer.push_str("relay_node_id", relay_node_id))
        .and_then(|writer| writer.push_str("transport", transport.as_str()))
        .and_then(|writer| writer.push_field("permissions_digest", permissions_digest))
        .and_then(|writer| writer.push_u64("relay_token_epoch", relay_token_epoch))
        .and_then(|writer| writer.push_u64("issued_at_epoch_millis", issued_at_epoch_millis))
        .and_then(|writer| writer.push_u64("expires_at_epoch_millis", expires_at_epoch_millis))
        .and_then(|writer| writer.push_str("relay_token_id", relay_token_id))
        .map_err(|_| BindingError::CanonicalEncoding)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelaySessionStatus {
    CanConnect,
    Connected,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAuthorizationSnapshot {
    pub session_id: u128,
    pub device_id: String,
    pub role: SessionRole,
    pub status: RelaySessionStatus,
    pub allow_relay: bool,
    pub permissions_digest: [u8; 32],
    pub relay_token_epoch: u64,
    pub allowed_relay_node_ids: Vec<String>,
    pub device_public_key: [u8; 32],
    pub device_public_key_version: u64,
    pub expected_device_public_key_version: u64,
    pub device_key_revoked: bool,
    pub expires_at_epoch_millis: u64,
}

#[derive(Debug, Default)]
pub struct RelayOpenReplayGuard {
    seen: HashSet<(String, SessionRole, [u8; 32])>,
}

impl RelayOpenReplayGuard {
    #[allow(clippy::too_many_arguments)]
    pub fn validate(
        &mut self,
        open: &RelayOpen,
        allocation: &RelayAllocation,
        authorization: &RelayAuthorizationSnapshot,
        token_signature_valid: bool,
        now_epoch_millis: u64,
    ) -> Result<(), BindingError> {
        if !token_signature_valid {
            return Err(BindingError::TokenSignatureInvalid);
        }
        if authorization.expires_at_epoch_millis < now_epoch_millis {
            return Err(BindingError::AuthorizationExpired);
        }
        if authorization.status == RelaySessionStatus::Closed {
            return Err(BindingError::SessionClosed);
        }
        if !authorization.allow_relay {
            return Err(BindingError::RelayNotAllowed);
        }
        if authorization.device_key_revoked {
            return Err(BindingError::DeviceKeyRevoked);
        }
        if authorization.device_public_key_version
            != authorization.expected_device_public_key_version
        {
            return Err(BindingError::DeviceKeyVersionMismatch);
        }
        if now_epoch_millis > open.expires_at_epoch_millis {
            return Err(BindingError::TokenExpired);
        }
        if open
            .expires_at_epoch_millis
            .saturating_sub(open.issued_at_epoch_millis)
            > RELAY_TOKEN_MAX_TTL_MILLIS
        {
            return Err(BindingError::TokenTtlExceeded);
        }
        if !authorization
            .allowed_relay_node_ids
            .contains(&open.relay_node_id)
        {
            return Err(BindingError::RelayNodeNotAllowed);
        }
        if open.session_id != authorization.session_id
            || open.device_id != authorization.device_id
            || open.role != authorization.role
        {
            return Err(BindingError::DeviceMismatch);
        }
        if open.permissions_digest != authorization.permissions_digest {
            return Err(BindingError::PermissionsMismatch);
        }
        if open.relay_token_epoch != authorization.relay_token_epoch {
            return Err(BindingError::RelayEpochMismatch);
        }
        if !relay_open_matches_allocation(open, allocation) {
            return Err(BindingError::TokenMismatch);
        }
        let expected_binding = relay_token_binding_hash(allocation)?;
        if !bool::from(expected_binding.ct_eq(&open.token_binding_hash))
            || !bool::from(expected_binding.ct_eq(&allocation.token_binding_hash))
        {
            return Err(BindingError::TokenBindingMismatch);
        }
        let signature: [u8; 64] = open
            .device_signature
            .as_slice()
            .try_into()
            .map_err(|_| BindingError::DeviceSignatureInvalid)?;
        let canonical = relay_open_canonical_bytes(open)?;
        verify_canonical_signature(&authorization.device_public_key, &canonical, &signature)
            .map_err(|_| BindingError::DeviceSignatureInvalid)?;
        if !self.seen.insert((
            open.relay_token_id.clone(),
            open.role,
            open.relay_open_nonce,
        )) {
            return Err(BindingError::NonceReplay);
        }
        Ok(())
    }
}

fn relay_open_matches_allocation(open: &RelayOpen, allocation: &RelayAllocation) -> bool {
    open.session_id == allocation.session_id
        && open.device_id == allocation.device_id
        && open.role == allocation.role
        && open.controller_device_id == allocation.controller_device_id
        && open.controlled_device_id == allocation.controlled_device_id
        && open.relay_node_id == allocation.relay_node_id
        && open.transport == allocation.transport
        && open.permissions_digest == allocation.permissions_digest
        && open.relay_token_epoch == allocation.relay_token_epoch
        && open.issued_at_epoch_millis == allocation.issued_at_epoch_millis
        && open.expires_at_epoch_millis == allocation.expires_at_epoch_millis
        && open.relay_token_id == allocation.relay_token_id
        && bool::from(
            open.session_relay_token
                .ct_eq(&allocation.session_relay_token),
        )
}

#[derive(Debug, Default)]
pub struct ProbeReplayGuard {
    seen: HashMap<(u128, u128, SessionRole, [u8; 32]), u64>,
}

impl ProbeReplayGuard {
    pub fn validate(
        &mut self,
        candidate: &ConnectionCandidateDto,
        authorization: &CandidateAuthorization,
        returned_token: &[u8],
        probe_role: SessionRole,
        probe_nonce: [u8; 32],
        now_epoch_millis: u64,
    ) -> Result<(), BindingError> {
        validate_candidate_authorization(candidate, authorization, now_epoch_millis)?;
        if probe_role == candidate.role {
            return Err(BindingError::ProbeRoleMismatch);
        }
        if !bool::from(returned_token.ct_eq(&authorization.candidate_token)) {
            return Err(BindingError::TokenMismatch);
        }
        self.seen
            .retain(|_, expires_at| *expires_at >= now_epoch_millis);
        if self
            .seen
            .insert(
                (
                    candidate.session_id,
                    candidate.candidate_id,
                    probe_role,
                    probe_nonce,
                ),
                authorization.expires_at_epoch_millis,
            )
            .is_some()
        {
            return Err(BindingError::ProbeReplay);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use remote_crypto::DeviceKeyPair;

    use super::*;

    fn candidate() -> ConnectionCandidateDto {
        let mut candidate = ConnectionCandidateDto {
            candidate_id: 0,
            session_id: 1,
            device_id: "controlled".to_owned(),
            role: SessionRole::Controlled,
            kind: TransportPath::UdpP2p,
            endpoint: "198.51.100.2:45000".to_owned(),
            source: CandidateSource::UdpObserved,
            observe_result_id: Some("observe-1".to_owned()),
            priority: 10,
            rtt_ms: None,
            loss_ppm: None,
            jitter_ms: None,
            relay_node_id: None,
        };
        candidate.candidate_id = candidate_id(&candidate).expect("id");
        candidate
    }

    #[test]
    fn candidate_id_and_binding_reject_field_tampering() {
        let candidate = candidate();
        let binding = candidate_token_binding_hash(&candidate, 5_000).expect("binding");
        let authorization = CandidateAuthorization {
            candidate_token: b"opaque-token".to_vec(),
            candidate_token_binding_hash: binding,
            expires_at_epoch_millis: 5_000,
        };
        assert!(validate_candidate_authorization(&candidate, &authorization, 1_000).is_ok());

        let mut tampered = candidate;
        tampered.endpoint = "198.51.100.9:45000".to_owned();
        assert_eq!(
            validate_candidate_authorization(&tampered, &authorization, 1_000),
            Err(BindingError::CandidateIdMismatch)
        );
    }

    #[test]
    fn probe_nonce_replay_is_rejected() {
        let candidate = candidate();
        let authorization = CandidateAuthorization {
            candidate_token: b"opaque-token".to_vec(),
            candidate_token_binding_hash: candidate_token_binding_hash(&candidate, 5_000)
                .expect("binding"),
            expires_at_epoch_millis: 5_000,
        };
        let mut guard = ProbeReplayGuard::default();
        assert!(guard
            .validate(
                &candidate,
                &authorization,
                b"opaque-token",
                SessionRole::Controller,
                [7_u8; 32],
                1_000
            )
            .is_ok());
        assert_eq!(
            guard.validate(
                &candidate,
                &authorization,
                b"opaque-token",
                SessionRole::Controller,
                [7_u8; 32],
                1_000
            ),
            Err(BindingError::ProbeReplay)
        );
    }

    #[test]
    fn relay_open_signature_and_replay_are_checked() {
        let key = DeviceKeyPair::from_private_key([9_u8; 32]);
        let mut allocation = RelayAllocation {
            session_id: 1,
            device_id: "controller".to_owned(),
            role: SessionRole::Controller,
            controller_device_id: "controller".to_owned(),
            controlled_device_id: "controlled".to_owned(),
            relay_node_id: "relay-a".to_owned(),
            transport: TransportPath::QuicRelay,
            public_endpoint: "relay.example:443".to_owned(),
            permissions_digest: [3_u8; 32],
            relay_token_epoch: 4,
            issued_at_epoch_millis: 1_000,
            expires_at_epoch_millis: 50_000,
            relay_token_id: "token-a".to_owned(),
            session_relay_token: b"signed-token".to_vec(),
            token_binding_hash: [0_u8; 32],
        };
        allocation.token_binding_hash = relay_token_binding_hash(&allocation).expect("binding");
        let mut open = RelayOpen {
            session_id: allocation.session_id,
            device_id: allocation.device_id.clone(),
            role: allocation.role,
            controller_device_id: allocation.controller_device_id.clone(),
            controlled_device_id: allocation.controlled_device_id.clone(),
            relay_node_id: allocation.relay_node_id.clone(),
            transport: allocation.transport,
            permissions_digest: allocation.permissions_digest,
            relay_token_epoch: allocation.relay_token_epoch,
            issued_at_epoch_millis: allocation.issued_at_epoch_millis,
            expires_at_epoch_millis: allocation.expires_at_epoch_millis,
            relay_token_id: allocation.relay_token_id.clone(),
            relay_open_nonce: [8_u8; 32],
            session_relay_token: allocation.session_relay_token.clone(),
            token_binding_hash: allocation.token_binding_hash,
            device_signature: Vec::new(),
        };
        open.device_signature = key
            .sign_canonical(&relay_open_canonical_bytes(&open).expect("canonical"))
            .to_vec();
        let authorization = RelayAuthorizationSnapshot {
            session_id: 1,
            device_id: "controller".to_owned(),
            role: SessionRole::Controller,
            status: RelaySessionStatus::CanConnect,
            allow_relay: true,
            permissions_digest: [3_u8; 32],
            relay_token_epoch: 4,
            allowed_relay_node_ids: vec!["relay-a".to_owned()],
            device_public_key: key.public_key,
            device_public_key_version: 2,
            expected_device_public_key_version: 2,
            device_key_revoked: false,
            expires_at_epoch_millis: 60_000,
        };
        let mut guard = RelayOpenReplayGuard::default();
        assert!(guard
            .validate(&open, &allocation, &authorization, true, 2_000)
            .is_ok());
        assert_eq!(
            guard.validate(&open, &allocation, &authorization, true, 2_000),
            Err(BindingError::NonceReplay)
        );
    }
}
