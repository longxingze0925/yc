use serde::{Deserialize, Serialize};

use crate::{SessionRole, TransportPath};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateSource {
    LocalInterface,
    UdpObserved,
    RelayAllocated,
}

impl CandidateSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalInterface => "local_interface",
            Self::UdpObserved => "udp_observed",
            Self::RelayAllocated => "relay_allocated",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionCandidateDto {
    #[serde(with = "crate::serde_hex_u128")]
    pub candidate_id: u128,
    #[serde(with = "crate::serde_uuid_u128")]
    pub session_id: u128,
    pub device_id: String,
    pub role: SessionRole,
    pub kind: TransportPath,
    pub endpoint: String,
    pub source: CandidateSource,
    pub observe_result_id: Option<String>,
    pub priority: u32,
    pub rtt_ms: Option<u32>,
    pub loss_ppm: Option<u32>,
    pub jitter_ms: Option<u32>,
    pub relay_node_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateAuthorization {
    pub candidate_token: Vec<u8>,
    pub candidate_token_binding_hash: [u8; 32],
    pub expires_at_epoch_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserveTokenRequest {
    #[serde(with = "crate::serde_uuid_u128")]
    pub session_id: u128,
    pub device_id: String,
    pub role: SessionRole,
    pub local_socket_nonce: [u8; 32],
    pub requested_ttl_millis: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserveTokenIssued {
    #[serde(with = "crate::serde_uuid_u128")]
    pub session_id: u128,
    pub device_id: String,
    pub role: SessionRole,
    pub local_socket_nonce: [u8; 32],
    pub observe_token: Vec<u8>,
    pub observe_token_binding_hash: [u8; 32],
    pub expires_at_epoch_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserveResult {
    #[serde(with = "crate::serde_uuid_u128")]
    pub session_id: u128,
    pub device_id: String,
    pub role: SessionRole,
    pub local_socket_nonce: [u8; 32],
    pub observed_endpoint: String,
    pub observe_result_id: String,
    pub observe_result_binding_hash: [u8; 32],
    pub expires_at_epoch_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateTokenRequest {
    #[serde(with = "crate::serde_uuid_u128")]
    pub session_id: u128,
    pub device_id: String,
    pub role: SessionRole,
    #[serde(with = "crate::serde_hex_u128")]
    pub candidate_id: u128,
    pub kind: TransportPath,
    pub endpoint: String,
    pub source: CandidateSource,
    pub relay_node_id: Option<String>,
    pub observe_result_id: Option<String>,
    pub observe_result_binding_hash: Option<[u8; 32]>,
    pub local_interface_claim_hash: Option<[u8; 32]>,
    pub local_interface_signature: Option<Vec<u8>>,
    pub interface_name_hash: Option<[u8; 32]>,
    pub interface_index_hash: Option<[u8; 32]>,
    pub local_socket_nonce: Option<[u8; 32]>,
    pub timestamp_epoch_millis: Option<u64>,
    pub requested_ttl_millis: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateTokenIssued {
    #[serde(with = "crate::serde_uuid_u128")]
    pub session_id: u128,
    pub device_id: String,
    pub role: SessionRole,
    #[serde(with = "crate::serde_hex_u128")]
    pub candidate_id: u128,
    pub candidate_token: Vec<u8>,
    pub candidate_token_binding_hash: [u8; 32],
    pub expires_at_epoch_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayAllocation {
    #[serde(with = "crate::serde_uuid_u128")]
    pub session_id: u128,
    pub device_id: String,
    pub role: SessionRole,
    pub controller_device_id: String,
    pub controlled_device_id: String,
    pub relay_node_id: String,
    pub transport: TransportPath,
    pub public_endpoint: String,
    pub permissions_digest: [u8; 32],
    pub relay_token_epoch: u64,
    pub issued_at_epoch_millis: u64,
    pub expires_at_epoch_millis: u64,
    pub relay_token_id: String,
    pub session_relay_token: Vec<u8>,
    pub token_binding_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayOpen {
    #[serde(with = "crate::serde_uuid_u128")]
    pub session_id: u128,
    pub device_id: String,
    pub role: SessionRole,
    pub controller_device_id: String,
    pub controlled_device_id: String,
    pub relay_node_id: String,
    pub transport: TransportPath,
    pub permissions_digest: [u8; 32],
    pub relay_token_epoch: u64,
    pub issued_at_epoch_millis: u64,
    pub expires_at_epoch_millis: u64,
    pub relay_token_id: String,
    pub relay_open_nonce: [u8; 32],
    pub session_relay_token: Vec<u8>,
    pub token_binding_hash: [u8; 32],
    pub device_signature: Vec<u8>,
}
