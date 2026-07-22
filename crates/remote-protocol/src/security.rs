use serde::{Deserialize, Serialize};

use crate::{CanonicalError, CanonicalWriter};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionRole {
    Controller,
    Controlled,
}

impl SessionRole {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Controller => "controller",
            Self::Controlled => "controlled",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportPath {
    LanDirect,
    UdpP2p,
    QuicRelay,
    Tls443Relay,
}

impl TransportPath {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LanDirect => "lan_direct",
            Self::UdpP2p => "udp_p2p",
            Self::QuicRelay => "quic_relay",
            Self::Tls443Relay => "tls_443_relay",
        }
    }

    pub const fn is_relay(self) -> bool {
        matches!(self, Self::QuicRelay | Self::Tls443Relay)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficDirection {
    ControllerToControlled,
    ControlledToController,
}

impl TrafficDirection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ControllerToControlled => "controller_to_controlled",
            Self::ControlledToController => "controlled_to_controller",
        }
    }

    pub const fn from_sender_role(role: SessionRole) -> Self {
        match role {
            SessionRole::Controller => Self::ControllerToControlled,
            SessionRole::Controlled => Self::ControlledToController,
        }
    }

    pub const fn reverse(self) -> Self {
        match self {
            Self::ControllerToControlled => Self::ControlledToController,
            Self::ControlledToController => Self::ControllerToControlled,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionContext {
    pub account_id: String,
    pub session_id: u128,
    pub controller_device_id: String,
    pub controlled_device_id: String,
    pub permissions_digest: [u8; 32],
    pub protocol_version: u16,
    pub session_expires_at_epoch_millis: u64,
}

impl SessionContext {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        let mut writer = CanonicalWriter::new("rctl-session-context-v1")?;
        writer
            .push_str("account_id", &self.account_id)?
            .push_u128("session_id", self.session_id)?
            .push_str("controller_device_id", &self.controller_device_id)?
            .push_str("controlled_device_id", &self.controlled_device_id)?
            .push_field("permissions_digest", &self.permissions_digest)?
            .push_u16("protocol_version", self.protocol_version)?
            .push_u64(
                "session_expires_at_epoch_millis",
                self.session_expires_at_epoch_millis,
            )?;
        Ok(writer.finish())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedKeyExchangePayload {
    pub session_id: u128,
    pub device_id: String,
    pub role: SessionRole,
    pub session_context_hash: [u8; 32],
    pub permissions_digest: [u8; 32],
    pub session_expires_at_epoch_millis: u64,
    pub ephemeral_public_key: [u8; 32],
    pub key_exchange_nonce: [u8; 32],
    pub selected_transport_path: TransportPath,
    pub selected_candidate_pair_id: u128,
    pub relay_node_id: Option<String>,
    pub timestamp_epoch_millis: u64,
}

impl SignedKeyExchangePayload {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        let mut writer = CanonicalWriter::new("rctl-signed-key-exchange-v1")?;
        writer
            .push_u128("session_id", self.session_id)?
            .push_str("device_id", &self.device_id)?
            .push_str("role", self.role.as_str())?
            .push_field("session_context_hash", &self.session_context_hash)?
            .push_field("permissions_digest", &self.permissions_digest)?
            .push_u64(
                "session_expires_at_epoch_millis",
                self.session_expires_at_epoch_millis,
            )?
            .push_field("ephemeral_public_key", &self.ephemeral_public_key)?
            .push_field("key_exchange_nonce", &self.key_exchange_nonce)?
            .push_str(
                "selected_transport_path",
                self.selected_transport_path.as_str(),
            )?
            .push_u128(
                "selected_candidate_pair_id",
                self.selected_candidate_pair_id,
            )?
            .push_optional_str("relay_node_id", self.relay_node_id.as_deref())?
            .push_u64("timestamp", self.timestamp_epoch_millis)?;
        Ok(writer.finish())
    }

    pub fn validate_path_binding(&self) -> bool {
        self.selected_transport_path.is_relay() == self.relay_node_id.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedKeyExchange {
    pub payload: SignedKeyExchangePayload,
    pub signature: Vec<u8>,
}

impl SignedKeyExchange {
    pub fn signature_bytes(&self) -> Option<[u8; 64]> {
        self.signature.as_slice().try_into().ok()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyConfirm {
    pub session_id: u128,
    pub device_id: String,
    pub role: SessionRole,
    pub key_exchange_transcript_hash: [u8; 32],
    pub confirm_mac: [u8; 32],
    pub timestamp_epoch_millis: u64,
}

impl KeyConfirm {
    pub fn canonical_mac_input(&self) -> Result<Vec<u8>, CanonicalError> {
        let mut writer = CanonicalWriter::new("rctl-key-confirm-v1")?;
        writer
            .push_u128("session_id", self.session_id)?
            .push_str("device_id", &self.device_id)?
            .push_str("role", self.role.as_str())?
            .push_field(
                "key_exchange_transcript_hash",
                &self.key_exchange_transcript_hash,
            )?
            .push_u64("timestamp", self.timestamp_epoch_millis)?;
        Ok(writer.finish())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKdfContext {
    pub account_id: String,
    pub session_id: u128,
    pub controller_device_id: String,
    pub controlled_device_id: String,
    pub permissions_digest: [u8; 32],
    pub protocol_version: u16,
    pub session_expires_at_epoch_millis: u64,
    pub selected_transport_path: TransportPath,
    pub selected_candidate_pair_id: u128,
    pub relay_node_id: Option<String>,
    pub key_exchange_transcript_hash: [u8; 32],
}

impl SessionKdfContext {
    pub fn salt_canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        let mut writer = CanonicalWriter::new("rctl-hkdf-salt-v1")?;
        writer
            .push_u128("session_id", self.session_id)?
            .push_str("controller_device_id", &self.controller_device_id)?
            .push_str("controlled_device_id", &self.controlled_device_id)?
            .push_field("permissions_digest", &self.permissions_digest)?
            .push_u64(
                "session_expires_at_epoch_millis",
                self.session_expires_at_epoch_millis,
            )?;
        Ok(writer.finish())
    }

    pub fn info_base(&self) -> Result<Vec<u8>, CanonicalError> {
        let mut writer = CanonicalWriter::new("rctl-session-v1")?;
        writer
            .push_str("account_id", &self.account_id)?
            .push_u128("session_id", self.session_id)?
            .push_str("controller_device_id", &self.controller_device_id)?
            .push_str("controlled_device_id", &self.controlled_device_id)?
            .push_field("permissions_digest", &self.permissions_digest)?
            .push_u16("protocol_version", self.protocol_version)?
            .push_u64(
                "session_expires_at_epoch_millis",
                self.session_expires_at_epoch_millis,
            )?
            .push_str(
                "selected_transport_path",
                self.selected_transport_path.as_str(),
            )?
            .push_u128(
                "selected_candidate_pair_id",
                self.selected_candidate_pair_id,
            )?
            .push_optional_str("relay_node_id", self.relay_node_id.as_deref())?
            .push_field(
                "key_exchange_transcript_hash",
                &self.key_exchange_transcript_hash,
            )?;
        Ok(writer.finish())
    }
}
