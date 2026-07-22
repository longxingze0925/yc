use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::{IpAddr, SocketAddr},
};

use remote_crypto::{sha256, verify_digest_signature};
use remote_protocol::{
    CandidateSource, CandidateTokenIssued, CandidateTokenRequest, CanonicalWriter,
    ConnectionCandidateDto, ObserveTokenIssued, SessionRole, TransportPath,
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

use crate::{
    candidate_id, candidate_token_binding_hash, BindingError, CANDIDATE_TOKEN_MAX_TTL_MILLIS,
    OBSERVE_TOKEN_MAX_TTL_MILLIS,
};

pub const LAN_CANDIDATE_MAX_PER_DEVICE_SESSION: usize = 8;
pub const LAN_INTERFACE_CLAIM_WINDOW_MILLIS: u64 = 30_000;
pub const LAN_EPHEMERAL_PORT_MIN: u16 = 49_152;

#[derive(Clone, PartialEq, Eq)]
pub struct EphemeralToken(Vec<u8>);

impl EphemeralToken {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn expose_for_transport(&self) -> &[u8] {
        &self.0
    }

    pub fn constant_time_eq(&self, other: &[u8]) -> bool {
        bool::from(self.0.ct_eq(other))
    }
}

impl Drop for EphemeralToken {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for EphemeralToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EphemeralToken(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ObserveAuthorization {
    pub session_id: u128,
    pub device_id: String,
    pub role: SessionRole,
    pub local_socket_nonce: [u8; 32],
    pub(crate) token: EphemeralToken,
    pub(crate) binding_hash: [u8; 32],
    pub(crate) expires_at_epoch_millis: u64,
}

impl ObserveAuthorization {
    pub fn from_issued(
        issued: ObserveTokenIssued,
        now_epoch_millis: u64,
    ) -> Result<Self, BindingError> {
        let authorization = Self {
            session_id: issued.session_id,
            device_id: issued.device_id,
            role: issued.role,
            local_socket_nonce: issued.local_socket_nonce,
            token: EphemeralToken::new(issued.observe_token),
            binding_hash: issued.observe_token_binding_hash,
            expires_at_epoch_millis: issued.expires_at_epoch_millis,
        };
        validate_observe_authorization(&authorization, now_epoch_millis)?;
        Ok(authorization)
    }

    pub fn token(&self) -> &EphemeralToken {
        &self.token
    }

    pub const fn binding_hash(&self) -> &[u8; 32] {
        &self.binding_hash
    }

    pub const fn expires_at_epoch_millis(&self) -> u64 {
        self.expires_at_epoch_millis
    }
}

impl fmt::Debug for ObserveAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObserveAuthorization")
            .field("session_id", &self.session_id)
            .field("device_id", &self.device_id)
            .field("role", &self.role)
            .field("authorization", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct EphemeralCandidateAuthorization {
    pub session_id: u128,
    pub device_id: String,
    pub role: SessionRole,
    pub candidate_id: u128,
    pub(crate) token: EphemeralToken,
    pub(crate) binding_hash: [u8; 32],
    pub(crate) expires_at_epoch_millis: u64,
}

impl EphemeralCandidateAuthorization {
    pub fn from_issued(
        candidate: &ConnectionCandidateDto,
        issued: CandidateTokenIssued,
        now_epoch_millis: u64,
    ) -> Result<Self, BindingError> {
        if issued.session_id != candidate.session_id
            || issued.device_id != candidate.device_id
            || issued.role != candidate.role
            || issued.candidate_id != candidate.candidate_id
        {
            return Err(BindingError::DeviceMismatch);
        }
        let authorization = Self {
            session_id: issued.session_id,
            device_id: issued.device_id,
            role: issued.role,
            candidate_id: issued.candidate_id,
            token: EphemeralToken::new(issued.candidate_token),
            binding_hash: issued.candidate_token_binding_hash,
            expires_at_epoch_millis: issued.expires_at_epoch_millis,
        };
        validate_ephemeral_candidate_authorization(candidate, &authorization, now_epoch_millis)?;
        Ok(authorization)
    }

    pub fn token(&self) -> &EphemeralToken {
        &self.token
    }

    pub const fn binding_hash(&self) -> &[u8; 32] {
        &self.binding_hash
    }

    pub const fn expires_at_epoch_millis(&self) -> u64 {
        self.expires_at_epoch_millis
    }
}

impl fmt::Debug for EphemeralCandidateAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EphemeralCandidateAuthorization")
            .field("session_id", &self.session_id)
            .field("device_id", &self.device_id)
            .field("role", &self.role)
            .field("candidate_id", &self.candidate_id)
            .field("authorization", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedObserveResult {
    pub session_id: u128,
    pub device_id: String,
    pub role: SessionRole,
    pub local_socket_nonce: [u8; 32],
    pub observed_endpoint: String,
    pub observe_result_id: String,
    pub(crate) binding_hash: [u8; 32],
    pub(crate) expires_at_epoch_millis: u64,
}

impl ValidatedObserveResult {
    pub const fn binding_hash(&self) -> &[u8; 32] {
        &self.binding_hash
    }

    pub const fn expires_at_epoch_millis(&self) -> u64 {
        self.expires_at_epoch_millis
    }
}

impl fmt::Debug for ValidatedObserveResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedObserveResult")
            .field("session_id", &self.session_id)
            .field("device_id", &self.device_id)
            .field("role", &self.role)
            .field("observed_endpoint", &self.observed_endpoint)
            .field("observe_result_id", &self.observe_result_id)
            .field("binding_hash_prefix", &&self.binding_hash[..8])
            .finish()
    }
}

pub fn observe_token_binding_hash(
    session_id: u128,
    device_id: &str,
    role: SessionRole,
    local_socket_nonce: &[u8; 32],
    expires_at_epoch_millis: u64,
) -> Result<[u8; 32], BindingError> {
    let mut writer = CanonicalWriter::new("rctl-observe-token-binding-v1")
        .map_err(|_| BindingError::CanonicalEncoding)?;
    writer
        .push_u128("session_id", session_id)
        .and_then(|writer| writer.push_str("device_id", device_id))
        .and_then(|writer| writer.push_str("role", role.as_str()))
        .and_then(|writer| writer.push_field("local_socket_nonce", local_socket_nonce))
        .and_then(|writer| writer.push_u64("expires_at_epoch_millis", expires_at_epoch_millis))
        .map_err(|_| BindingError::CanonicalEncoding)?;
    Ok(sha256(&writer.finish()))
}

pub fn validate_observe_authorization(
    authorization: &ObserveAuthorization,
    now_epoch_millis: u64,
) -> Result<(), BindingError> {
    if authorization.expires_at_epoch_millis < now_epoch_millis {
        return Err(BindingError::TokenExpired);
    }
    if authorization
        .expires_at_epoch_millis
        .saturating_sub(now_epoch_millis)
        > OBSERVE_TOKEN_MAX_TTL_MILLIS
    {
        return Err(BindingError::TokenTtlExceeded);
    }
    if authorization.token.is_empty() {
        return Err(BindingError::TokenMismatch);
    }
    let expected = observe_token_binding_hash(
        authorization.session_id,
        &authorization.device_id,
        authorization.role,
        &authorization.local_socket_nonce,
        authorization.expires_at_epoch_millis,
    )?;
    if !bool::from(expected.ct_eq(&authorization.binding_hash)) {
        return Err(BindingError::TokenBindingMismatch);
    }
    Ok(())
}

pub fn observe_result_binding_hash(
    result: &ValidatedObserveResult,
) -> Result<[u8; 32], BindingError> {
    let mut writer = CanonicalWriter::new("rctl-observe-result-binding-v1")
        .map_err(|_| BindingError::CanonicalEncoding)?;
    writer
        .push_u128("session_id", result.session_id)
        .and_then(|writer| writer.push_str("device_id", &result.device_id))
        .and_then(|writer| writer.push_str("role", result.role.as_str()))
        .and_then(|writer| writer.push_field("local_socket_nonce", &result.local_socket_nonce))
        .and_then(|writer| writer.push_str("observed_endpoint", &result.observed_endpoint))
        .and_then(|writer| writer.push_str("source", CandidateSource::UdpObserved.as_str()))
        .and_then(|writer| {
            writer.push_u64("expires_at_epoch_millis", result.expires_at_epoch_millis)
        })
        .and_then(|writer| writer.push_str("observe_result_id", &result.observe_result_id))
        .map_err(|_| BindingError::CanonicalEncoding)?;
    Ok(sha256(&writer.finish()))
}

pub fn validate_observe_result(
    result: &ValidatedObserveResult,
    authorization: &ObserveAuthorization,
    now_epoch_millis: u64,
) -> Result<(), BindingError> {
    validate_observe_authorization(authorization, now_epoch_millis)?;
    if result.session_id != authorization.session_id
        || result.device_id != authorization.device_id
        || result.role != authorization.role
        || result.local_socket_nonce != authorization.local_socket_nonce
    {
        return Err(BindingError::ObserveContextMismatch);
    }
    if result.expires_at_epoch_millis < now_epoch_millis
        || result.expires_at_epoch_millis > authorization.expires_at_epoch_millis
    {
        return Err(BindingError::TokenExpired);
    }
    result
        .observed_endpoint
        .parse::<SocketAddr>()
        .map_err(|_| BindingError::InvalidEndpoint)?;
    if result.observe_result_id.is_empty() {
        return Err(BindingError::ObserveResultMismatch);
    }
    let expected = observe_result_binding_hash(result)?;
    if !bool::from(expected.ct_eq(&result.binding_hash)) {
        return Err(BindingError::ObserveResultMismatch);
    }
    Ok(())
}

pub fn validate_ephemeral_candidate_authorization(
    candidate: &ConnectionCandidateDto,
    authorization: &EphemeralCandidateAuthorization,
    now_epoch_millis: u64,
) -> Result<(), BindingError> {
    if authorization.session_id != candidate.session_id
        || authorization.device_id != candidate.device_id
        || authorization.role != candidate.role
        || authorization.candidate_id != candidate.candidate_id
    {
        return Err(BindingError::DeviceMismatch);
    }
    if authorization.expires_at_epoch_millis < now_epoch_millis {
        return Err(BindingError::TokenExpired);
    }
    if authorization
        .expires_at_epoch_millis
        .saturating_sub(now_epoch_millis)
        > CANDIDATE_TOKEN_MAX_TTL_MILLIS
    {
        return Err(BindingError::TokenTtlExceeded);
    }
    if authorization.token.is_empty() {
        return Err(BindingError::TokenMismatch);
    }
    let expected = candidate_token_binding_hash(candidate, authorization.expires_at_epoch_millis)?;
    if !bool::from(expected.ct_eq(&authorization.binding_hash)) {
        return Err(BindingError::TokenBindingMismatch);
    }
    Ok(())
}

pub fn candidate_from_token_request(
    request: &CandidateTokenRequest,
) -> Result<ConnectionCandidateDto, BindingError> {
    let candidate = ConnectionCandidateDto {
        candidate_id: request.candidate_id,
        session_id: request.session_id,
        device_id: request.device_id.clone(),
        role: request.role,
        kind: request.kind,
        endpoint: request.endpoint.clone(),
        source: request.source,
        observe_result_id: request.observe_result_id.clone(),
        priority: 0,
        rtt_ms: None,
        loss_ppm: None,
        jitter_ms: None,
        relay_node_id: request.relay_node_id.clone(),
    };
    if candidate_id(&candidate)? != request.candidate_id {
        return Err(BindingError::CandidateIdMismatch);
    }
    Ok(candidate)
}

pub fn local_interface_claim_hash(
    request: &CandidateTokenRequest,
) -> Result<[u8; 32], BindingError> {
    let interface_name_hash = request
        .interface_name_hash
        .ok_or(BindingError::LanClaimMissing)?;
    let interface_index_hash = request
        .interface_index_hash
        .ok_or(BindingError::LanClaimMissing)?;
    let local_socket_nonce = request
        .local_socket_nonce
        .ok_or(BindingError::LanClaimMissing)?;
    let timestamp = request
        .timestamp_epoch_millis
        .ok_or(BindingError::LanClaimMissing)?;
    let mut writer = CanonicalWriter::new("rctl-local-interface-claim-v1")
        .map_err(|_| BindingError::CanonicalEncoding)?;
    writer
        .push_u128("session_id", request.session_id)
        .and_then(|writer| writer.push_str("device_id", &request.device_id))
        .and_then(|writer| writer.push_str("role", request.role.as_str()))
        .and_then(|writer| writer.push_u128("candidate_id", request.candidate_id))
        .and_then(|writer| writer.push_str("endpoint", &request.endpoint))
        .and_then(|writer| writer.push_field("interface_name_hash", &interface_name_hash))
        .and_then(|writer| writer.push_field("interface_index_hash", &interface_index_hash))
        .and_then(|writer| writer.push_field("local_socket_nonce", &local_socket_nonce))
        .and_then(|writer| writer.push_u64("timestamp_epoch_millis", timestamp))
        .map_err(|_| BindingError::CanonicalEncoding)?;
    Ok(sha256(&writer.finish()))
}

#[derive(Debug, Default)]
pub struct LanCandidateGuard {
    accepted_candidates: HashMap<(u128, String), HashSet<u128>>,
    accepted_claims: HashSet<(String, u128, [u8; 32], u128)>,
}

impl LanCandidateGuard {
    #[allow(clippy::too_many_arguments)]
    pub fn validate_request(
        &mut self,
        request: &CandidateTokenRequest,
        expected_session_id: u128,
        expected_device_id: &str,
        expected_role: SessionRole,
        device_public_key: &[u8; 32],
        now_epoch_millis: u64,
    ) -> Result<ConnectionCandidateDto, BindingError> {
        validate_token_request_ttl(request.requested_ttl_millis)?;
        if request.session_id != expected_session_id
            || request.device_id != expected_device_id
            || request.role != expected_role
        {
            return Err(BindingError::DeviceMismatch);
        }
        if request.kind != TransportPath::LanDirect
            || request.source != CandidateSource::LocalInterface
            || request.relay_node_id.is_some()
            || request.observe_result_id.is_some()
            || request.observe_result_binding_hash.is_some()
        {
            return Err(BindingError::InvalidCandidateKindSource);
        }
        let endpoint = validate_lan_endpoint(&request.endpoint)?;
        let interface_name_hash = request
            .interface_name_hash
            .ok_or(BindingError::LanClaimMissing)?;
        let interface_index_hash = request
            .interface_index_hash
            .ok_or(BindingError::LanClaimMissing)?;
        let local_socket_nonce = request
            .local_socket_nonce
            .ok_or(BindingError::LanClaimMissing)?;
        let timestamp = request
            .timestamp_epoch_millis
            .ok_or(BindingError::LanClaimMissing)?;
        if interface_name_hash == [0; 32]
            || interface_index_hash == [0; 32]
            || local_socket_nonce == [0; 32]
        {
            return Err(BindingError::InvalidInterfaceHash);
        }
        if timestamp.abs_diff(now_epoch_millis) > LAN_INTERFACE_CLAIM_WINDOW_MILLIS {
            return Err(BindingError::TimestampOutsideWindow);
        }
        let candidate = candidate_from_token_request(request)?;
        if endpoint.to_string() != request.endpoint {
            return Err(BindingError::InvalidEndpoint);
        }
        let expected_claim = local_interface_claim_hash(request)?;
        let supplied_claim = request
            .local_interface_claim_hash
            .ok_or(BindingError::LanClaimMissing)?;
        if !bool::from(expected_claim.ct_eq(&supplied_claim)) {
            return Err(BindingError::LanClaimHashMismatch);
        }
        let signature: [u8; 64] = request
            .local_interface_signature
            .as_deref()
            .ok_or(BindingError::LanClaimMissing)?
            .try_into()
            .map_err(|_| BindingError::DeviceSignatureInvalid)?;
        verify_digest_signature(device_public_key, &expected_claim, &signature)
            .map_err(|_| BindingError::DeviceSignatureInvalid)?;

        let replay_key = (
            request.device_id.clone(),
            request.session_id,
            local_socket_nonce,
            request.candidate_id,
        );
        if self.accepted_claims.contains(&replay_key) {
            return Err(BindingError::NonceReplay);
        }
        let candidates = self
            .accepted_candidates
            .entry((request.session_id, request.device_id.clone()))
            .or_default();
        if !candidates.contains(&request.candidate_id)
            && candidates.len() >= LAN_CANDIDATE_MAX_PER_DEVICE_SESSION
        {
            return Err(BindingError::LanCandidateLimitExceeded);
        }
        candidates.insert(request.candidate_id);
        self.accepted_claims.insert(replay_key);
        Ok(candidate)
    }
}

#[allow(clippy::too_many_arguments)]
pub fn validate_udp_candidate_request(
    request: &CandidateTokenRequest,
    observe_result: &ValidatedObserveResult,
    expected_session_id: u128,
    expected_device_id: &str,
    expected_role: SessionRole,
    now_epoch_millis: u64,
) -> Result<ConnectionCandidateDto, BindingError> {
    validate_token_request_ttl(request.requested_ttl_millis)?;
    if request.session_id != expected_session_id
        || request.device_id != expected_device_id
        || request.role != expected_role
    {
        return Err(BindingError::DeviceMismatch);
    }
    if request.kind != TransportPath::UdpP2p
        || request.source != CandidateSource::UdpObserved
        || request.relay_node_id.is_some()
        || request.local_interface_claim_hash.is_some()
        || request.local_interface_signature.is_some()
        || request.interface_name_hash.is_some()
        || request.interface_index_hash.is_some()
        || request.local_socket_nonce.is_some()
        || request.timestamp_epoch_millis.is_some()
    {
        return Err(BindingError::InvalidCandidateKindSource);
    }
    if observe_result.expires_at_epoch_millis < now_epoch_millis
        || observe_result.session_id != request.session_id
        || observe_result.device_id != request.device_id
        || observe_result.role != request.role
        || observe_result.observed_endpoint != request.endpoint
        || request.observe_result_id.as_deref() != Some(&observe_result.observe_result_id)
    {
        return Err(BindingError::ObserveResultMismatch);
    }
    let expected_result_binding = observe_result_binding_hash(observe_result)?;
    if !bool::from(expected_result_binding.ct_eq(&observe_result.binding_hash))
        || request
            .observe_result_binding_hash
            .as_ref()
            .is_none_or(|binding| !bool::from(binding.ct_eq(&expected_result_binding)))
    {
        return Err(BindingError::ObserveResultMismatch);
    }
    candidate_from_token_request(request)
}

fn validate_token_request_ttl(requested_ttl_millis: u32) -> Result<(), BindingError> {
    if requested_ttl_millis == 0 || u64::from(requested_ttl_millis) > CANDIDATE_TOKEN_MAX_TTL_MILLIS
    {
        return Err(BindingError::InvalidRequestedTtl);
    }
    Ok(())
}

pub fn validate_lan_endpoint(endpoint: &str) -> Result<SocketAddr, BindingError> {
    let endpoint = endpoint
        .parse::<SocketAddr>()
        .map_err(|_| BindingError::InvalidEndpoint)?;
    if endpoint.port() < LAN_EPHEMERAL_PORT_MIN {
        return Err(BindingError::LanPortForbidden);
    }
    if !is_private_lan_unicast(endpoint.ip()) {
        return Err(BindingError::LanAddressForbidden);
    }
    Ok(endpoint)
}

fn is_private_lan_unicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            address.is_private()
                && !address.is_loopback()
                && !address.is_link_local()
                && !address.is_broadcast()
                && !address.is_documentation()
                && octets[3] != 0
                && octets[3] != 255
        }
        IpAddr::V6(address) => address.is_unique_local() && !address.is_multicast(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalNetwork {
    address: IpAddr,
    prefix_len: u8,
}

impl LocalNetwork {
    pub fn new(address: IpAddr, prefix_len: u8) -> Result<Self, BindingError> {
        let max = if address.is_ipv4() { 32 } else { 128 };
        if prefix_len > max || !is_private_lan_unicast(address) {
            return Err(BindingError::LanAddressForbidden);
        }
        Ok(Self {
            address,
            prefix_len,
        })
    }

    pub fn contains(self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(local), IpAddr::V4(remote)) => {
                let mask = prefix_mask_v4(self.prefix_len);
                u32::from(local) & mask == u32::from(remote) & mask
            }
            (IpAddr::V6(local), IpAddr::V6(remote)) => {
                let mask = prefix_mask_v6(self.prefix_len);
                u128::from(local) & mask == u128::from(remote) & mask
            }
            _ => false,
        }
    }
}

pub fn validate_lan_probe_scope(
    endpoint: &str,
    local_networks: &[LocalNetwork],
) -> Result<SocketAddr, BindingError> {
    let endpoint = validate_lan_endpoint(endpoint)?;
    if !local_networks
        .iter()
        .any(|network| network.contains(endpoint.ip()))
    {
        return Err(BindingError::LanNotRoutable);
    }
    Ok(endpoint)
}

const fn prefix_mask_v4(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

const fn prefix_mask_v6(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use remote_crypto::DeviceKeyPair;

    use super::*;

    fn issued_observe(expires_at: u64) -> ObserveTokenIssued {
        let mut issued = ObserveTokenIssued {
            session_id: 11,
            device_id: "controlled".to_owned(),
            role: SessionRole::Controlled,
            local_socket_nonce: [7; 32],
            observe_token: b"observe-secret".to_vec(),
            observe_token_binding_hash: [0; 32],
            expires_at_epoch_millis: expires_at,
        };
        issued.observe_token_binding_hash = observe_token_binding_hash(
            issued.session_id,
            &issued.device_id,
            issued.role,
            &issued.local_socket_nonce,
            expires_at,
        )
        .expect("binding");
        issued
    }

    fn lan_request(index: u8, key: &DeviceKeyPair, now: u64) -> CandidateTokenRequest {
        let endpoint = format!("10.0.0.{}:{}", index + 1, 50_000 + u16::from(index));
        let mut candidate = ConnectionCandidateDto {
            candidate_id: 0,
            session_id: 9,
            device_id: "controlled".to_owned(),
            role: SessionRole::Controlled,
            kind: TransportPath::LanDirect,
            endpoint: endpoint.clone(),
            source: CandidateSource::LocalInterface,
            observe_result_id: None,
            priority: 0,
            rtt_ms: None,
            loss_ppm: None,
            jitter_ms: None,
            relay_node_id: None,
        };
        candidate.candidate_id = candidate_id(&candidate).expect("candidate id");
        let mut request = CandidateTokenRequest {
            session_id: candidate.session_id,
            device_id: candidate.device_id,
            role: candidate.role,
            candidate_id: candidate.candidate_id,
            kind: candidate.kind,
            endpoint,
            source: candidate.source,
            relay_node_id: None,
            observe_result_id: None,
            observe_result_binding_hash: None,
            local_interface_claim_hash: None,
            local_interface_signature: None,
            interface_name_hash: Some([1; 32]),
            interface_index_hash: Some([2; 32]),
            local_socket_nonce: Some([index.saturating_add(1); 32]),
            timestamp_epoch_millis: Some(now),
            requested_ttl_millis: 60_000,
        };
        let claim = local_interface_claim_hash(&request).expect("claim");
        request.local_interface_claim_hash = Some(claim);
        request.local_interface_signature = Some(key.sign_digest(&claim).to_vec());
        request
    }

    #[test]
    fn authorization_debug_redacts_tokens_and_full_bindings() {
        let auth = ObserveAuthorization::from_issued(issued_observe(20_000), 1_000)
            .expect("authorization");
        let debug = format!("{auth:?}");
        assert!(!debug.contains("observe-secret"));
        assert!(!debug.contains(&format!("{:?}", auth.binding_hash())));
    }

    #[test]
    fn observe_token_rejects_expiry_tampering_and_overlong_ttl() {
        assert_eq!(
            ObserveAuthorization::from_issued(issued_observe(900), 1_000),
            Err(BindingError::TokenExpired)
        );
        assert_eq!(
            ObserveAuthorization::from_issued(issued_observe(31_001), 1_000),
            Err(BindingError::TokenTtlExceeded)
        );
        let mut tampered = issued_observe(20_000);
        tampered.device_id = "attacker".to_owned();
        assert_eq!(
            ObserveAuthorization::from_issued(tampered, 1_000),
            Err(BindingError::TokenBindingMismatch)
        );
    }

    #[test]
    fn binding_domains_do_not_overlap() {
        let authorization =
            ObserveAuthorization::from_issued(issued_observe(20_000), 1_000).expect("auth");
        let mut result = ValidatedObserveResult {
            session_id: authorization.session_id,
            device_id: authorization.device_id.clone(),
            role: authorization.role,
            local_socket_nonce: authorization.local_socket_nonce,
            observed_endpoint: "198.51.100.10:50000".to_owned(),
            observe_result_id: "result-1".to_owned(),
            binding_hash: [0; 32],
            expires_at_epoch_millis: 20_000,
        };
        result.binding_hash = observe_result_binding_hash(&result).expect("result binding");
        assert_ne!(authorization.binding_hash(), result.binding_hash());
    }

    #[test]
    fn lan_claim_checks_signature_window_replay_and_limit() {
        let key = DeviceKeyPair::from_private_key([5; 32]);
        let now = 50_000;
        let mut guard = LanCandidateGuard::default();
        let first = lan_request(0, &key, now);
        assert!(guard
            .validate_request(
                &first,
                first.session_id,
                &first.device_id,
                first.role,
                &key.public_key,
                now,
            )
            .is_ok());
        assert_eq!(
            guard.validate_request(
                &first,
                first.session_id,
                &first.device_id,
                first.role,
                &key.public_key,
                now,
            ),
            Err(BindingError::NonceReplay)
        );

        let mut stale = lan_request(1, &key, now - 30_001);
        stale.timestamp_epoch_millis = Some(now - 30_001);
        assert_eq!(
            guard.validate_request(
                &stale,
                stale.session_id,
                &stale.device_id,
                stale.role,
                &key.public_key,
                now,
            ),
            Err(BindingError::TimestampOutsideWindow)
        );

        let mut forged = lan_request(2, &key, now);
        forged.local_interface_signature = Some([9; 64].to_vec());
        assert_eq!(
            guard.validate_request(
                &forged,
                forged.session_id,
                &forged.device_id,
                forged.role,
                &key.public_key,
                now,
            ),
            Err(BindingError::DeviceSignatureInvalid)
        );

        for index in 1..8 {
            let request = lan_request(index, &key, now);
            guard
                .validate_request(
                    &request,
                    request.session_id,
                    &request.device_id,
                    request.role,
                    &key.public_key,
                    now,
                )
                .expect("within limit");
        }
        let ninth = lan_request(8, &key, now);
        assert_eq!(
            guard.validate_request(
                &ninth,
                ninth.session_id,
                &ninth.device_id,
                ninth.role,
                &key.public_key,
                now,
            ),
            Err(BindingError::LanCandidateLimitExceeded)
        );
    }

    #[test]
    fn lan_address_port_and_route_scope_are_restricted() {
        for endpoint in [
            "127.0.0.1:50000",
            "169.254.1.2:50000",
            "224.0.0.1:50000",
            "192.0.2.2:50000",
            "8.8.8.8:50000",
            "192.168.1.255:50000",
        ] {
            assert_eq!(
                validate_lan_endpoint(endpoint),
                Err(BindingError::LanAddressForbidden),
                "{endpoint}"
            );
        }
        assert_eq!(
            validate_lan_endpoint("192.168.1.2:1024"),
            Err(BindingError::LanPortForbidden)
        );
        let local =
            LocalNetwork::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 24).expect("network");
        assert!(validate_lan_probe_scope("192.168.1.20:50000", &[local]).is_ok());
        assert_eq!(
            validate_lan_probe_scope("10.10.10.20:50000", &[local]),
            Err(BindingError::LanNotRoutable)
        );
    }
}
