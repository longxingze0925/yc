use remote_crypto::{
    create_key_confirm, decrypt_payload, encrypt_payload, CryptoError, DerivedSessionKeys,
    KeyConfirmReplayGuard, ReplayGuard,
};
use remote_protocol::{
    ChannelId, KeyConfirm, MessageHeader, MessageKind, SessionPermissions, SessionRole,
    TrafficDirection, TransportPath, MAX_SECURE_SEQUENCE,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureSessionState {
    AwaitingKeyConfirm,
    Ready,
    Invalidated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureSessionError {
    KeyConfirmationRequired,
    Invalidated,
    PermissionDenied,
    SessionMismatch,
    PathChanged,
    PermissionsChanged,
    Crypto(CryptoError),
}

impl From<CryptoError> for SecureSessionError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

#[derive(Debug)]
pub struct SecureSession {
    session_id: u128,
    local_role: SessionRole,
    permissions: SessionPermissions,
    permissions_digest: [u8; 32],
    path: TransportPath,
    candidate_pair_id: u128,
    relay_node_id: Option<String>,
    key_exchange_transcript_hash: [u8; 32],
    keys: DerivedSessionKeys,
    send_sequences: [u64; 9],
    receive_replay_guard: ReplayGuard,
    key_confirm_replay_guard: KeyConfirmReplayGuard,
    local_confirm_sent: bool,
    peer_confirmed: bool,
    invalidated: bool,
}

impl SecureSession {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: u128,
        local_role: SessionRole,
        permissions: SessionPermissions,
        permissions_digest: [u8; 32],
        path: TransportPath,
        candidate_pair_id: u128,
        relay_node_id: Option<String>,
        key_exchange_transcript_hash: [u8; 32],
        keys: DerivedSessionKeys,
    ) -> Result<Self, SecureSessionError> {
        if path.is_relay() != relay_node_id.is_some() {
            return Err(SecureSessionError::PathChanged);
        }
        Ok(Self {
            session_id,
            local_role,
            permissions,
            permissions_digest,
            path,
            candidate_pair_id,
            relay_node_id,
            key_exchange_transcript_hash,
            keys,
            send_sequences: [0; 9],
            receive_replay_guard: ReplayGuard::default(),
            key_confirm_replay_guard: KeyConfirmReplayGuard::default(),
            local_confirm_sent: false,
            peer_confirmed: false,
            invalidated: false,
        })
    }

    pub fn state(&self) -> SecureSessionState {
        if self.invalidated {
            SecureSessionState::Invalidated
        } else if self.local_confirm_sent && self.peer_confirmed {
            SecureSessionState::Ready
        } else {
            SecureSessionState::AwaitingKeyConfirm
        }
    }

    pub fn create_local_key_confirm(
        &mut self,
        device_id: String,
        timestamp_epoch_millis: u64,
    ) -> Result<KeyConfirm, SecureSessionError> {
        self.ensure_not_invalidated()?;
        if self.local_confirm_sent {
            return Err(CryptoError::ReplayDetected.into());
        }
        let confirm = create_key_confirm(
            self.session_id,
            device_id,
            self.local_role,
            self.key_exchange_transcript_hash,
            timestamp_epoch_millis,
            &self.keys,
        )?;
        self.local_confirm_sent = true;
        Ok(confirm)
    }

    pub fn verify_peer_key_confirm(
        &mut self,
        confirm: &KeyConfirm,
        expected_peer_device_id: &str,
        now_epoch_millis: u64,
    ) -> Result<(), SecureSessionError> {
        self.ensure_not_invalidated()?;
        if self.peer_confirmed {
            self.invalidated = true;
            return Err(CryptoError::ReplayDetected.into());
        }
        if confirm.session_id != self.session_id || confirm.role == self.local_role {
            self.invalidated = true;
            return Err(SecureSessionError::SessionMismatch);
        }
        let verification = self.key_confirm_replay_guard.verify(
            confirm,
            expected_peer_device_id,
            match self.local_role {
                SessionRole::Controller => SessionRole::Controlled,
                SessionRole::Controlled => SessionRole::Controller,
            },
            &self.key_exchange_transcript_hash,
            now_epoch_millis,
            &self.keys,
        );
        if let Err(error) = verification {
            self.invalidated = true;
            return Err(error.into());
        }
        self.peer_confirmed = true;
        Ok(())
    }

    pub fn seal(
        &mut self,
        kind: MessageKind,
        channel: ChannelId,
        flags: u16,
        plaintext: &[u8],
    ) -> Result<(MessageHeader, Vec<u8>), SecureSessionError> {
        self.ensure_ready()?;
        self.authorize(kind)?;
        let sequence = self.send_sequences[channel as usize];
        if sequence > MAX_SECURE_SEQUENCE {
            return Err(CryptoError::SequenceExhausted.into());
        }
        let mut header = MessageHeader::new_on_channel(kind, channel, self.session_id, sequence, 0)
            .map_err(|_| SecureSessionError::Crypto(CryptoError::InvalidChannel))?;
        header.flags = flags;
        let direction = TrafficDirection::from_sender_role(self.local_role);
        let encrypted = encrypt_payload(
            self.keys.traffic_key(direction),
            self.keys.nonce_prefix(direction),
            &self.permissions_digest,
            direction,
            header,
            plaintext,
        )?;
        self.send_sequences[channel as usize] = sequence.saturating_add(1);
        Ok(encrypted)
    }

    pub fn open(
        &mut self,
        header: MessageHeader,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SecureSessionError> {
        self.ensure_ready()?;
        if header.session_id != self.session_id {
            return Err(SecureSessionError::SessionMismatch);
        }
        let direction = TrafficDirection::from_sender_role(self.local_role).reverse();
        let plaintext = decrypt_payload(
            self.keys.traffic_key(direction),
            self.keys.nonce_prefix(direction),
            &self.permissions_digest,
            direction,
            header,
            ciphertext,
            &mut self.receive_replay_guard,
        )?;
        self.authorize(header.kind)?;
        Ok(plaintext)
    }

    pub fn invalidate_if_binding_changed(
        &mut self,
        permissions_digest: [u8; 32],
        path: TransportPath,
        candidate_pair_id: u128,
        relay_node_id: Option<&str>,
    ) -> Result<(), SecureSessionError> {
        if permissions_digest != self.permissions_digest {
            self.invalidated = true;
            return Err(SecureSessionError::PermissionsChanged);
        }
        if path != self.path
            || candidate_pair_id != self.candidate_pair_id
            || relay_node_id != self.relay_node_id.as_deref()
        {
            self.invalidated = true;
            return Err(SecureSessionError::PathChanged);
        }
        Ok(())
    }

    pub fn invalidate_for_reboot(&mut self) {
        self.invalidated = true;
    }

    pub fn restore_send_sequence(
        &mut self,
        channel: ChannelId,
        next_sequence: u64,
    ) -> Result<(), SecureSessionError> {
        self.ensure_not_invalidated()?;
        if next_sequence < self.send_sequences[channel as usize]
            || next_sequence > MAX_SECURE_SEQUENCE
        {
            return Err(CryptoError::ReplayDetected.into());
        }
        self.send_sequences[channel as usize] = next_sequence;
        Ok(())
    }

    fn ensure_not_invalidated(&self) -> Result<(), SecureSessionError> {
        if self.invalidated {
            Err(SecureSessionError::Invalidated)
        } else {
            Ok(())
        }
    }

    fn ensure_ready(&self) -> Result<(), SecureSessionError> {
        self.ensure_not_invalidated()?;
        if self.local_confirm_sent && self.peer_confirmed {
            Ok(())
        } else {
            Err(SecureSessionError::KeyConfirmationRequired)
        }
    }

    fn authorize(&self, kind: MessageKind) -> Result<(), SecureSessionError> {
        let allowed = match kind {
            MessageKind::KeyExchangeMessage
            | MessageKind::KeyConfirm
            | MessageKind::ErrorReport => true,
            MessageKind::InputEvent => self.permissions.input_control,
            MessageKind::MediaCapabilities
            | MessageKind::MediaConfigRequest
            | MessageKind::MediaConfigState
            | MessageKind::MediaQualityRequest
            | MessageKind::MediaQualityState
            | MessageKind::KeyframeRequest
            | MessageKind::VideoFrameInfo
            | MessageKind::VideoFrameData
            | MessageKind::DisplayList
            | MessageKind::DisplaySelect
            | MessageKind::DisplayChanged => self.permissions.remote_desktop,
            MessageKind::ClipboardPermissionRequest
            | MessageKind::ClipboardPermissionState
            | MessageKind::ClipboardText => self.permissions.clipboard,
            MessageKind::FileTransferRequest
            | MessageKind::FileTransferAck
            | MessageKind::FileChunk
            | MessageKind::FileTransferCancel => self.permissions.file_transfer,
            MessageKind::PrivacyModeRequest
            | MessageKind::PrivacyModeState
            | MessageKind::PrivacyModeRestore => {
                self.permissions.privacy_screen || self.permissions.block_local_input
            }
            MessageKind::RebootRequest
            | MessageKind::RebootState
            | MessageKind::RebootCancel
            | MessageKind::RebootResumeHint
            | MessageKind::Stats => true,
        };
        if allowed {
            Ok(())
        } else {
            Err(SecureSessionError::PermissionDenied)
        }
    }
}

#[cfg(test)]
mod tests {
    use remote_crypto::{derive_session_keys, permissions_digest};
    use remote_protocol::{SessionKdfContext, PROTOCOL_VERSION};

    use super::*;

    fn keys() -> DerivedSessionKeys {
        derive_session_keys(
            &[9_u8; 32],
            &SessionKdfContext {
                account_id: "account".to_owned(),
                session_id: 1,
                controller_device_id: "controller".to_owned(),
                controlled_device_id: "controlled".to_owned(),
                permissions_digest: [3_u8; 32],
                protocol_version: PROTOCOL_VERSION,
                session_expires_at_epoch_millis: 10_000,
                selected_transport_path: TransportPath::UdpP2p,
                selected_candidate_pair_id: 2,
                relay_node_id: None,
                key_exchange_transcript_hash: [4_u8; 32],
            },
        )
        .expect("keys")
    }

    fn session(role: SessionRole) -> SecureSession {
        let permissions = SessionPermissions {
            input_control: true,
            ..SessionPermissions::default()
        };
        SecureSession::new(
            1,
            role,
            permissions,
            permissions_digest(permissions).expect("digest"),
            TransportPath::UdpP2p,
            2,
            None,
            [4_u8; 32],
            keys(),
        )
        .expect("session")
    }

    fn confirm_both(controller: &mut SecureSession, controlled: &mut SecureSession) {
        let controller_confirm = controller
            .create_local_key_confirm("controller".to_owned(), 1_000)
            .expect("confirm");
        let controlled_confirm = controlled
            .create_local_key_confirm("controlled".to_owned(), 1_000)
            .expect("confirm");
        controller
            .verify_peer_key_confirm(&controlled_confirm, "controlled", 1_001)
            .expect("verify");
        controlled
            .verify_peer_key_confirm(&controller_confirm, "controller", 1_001)
            .expect("verify");
    }

    #[test]
    fn business_data_is_blocked_until_both_confirms() {
        let mut controller = session(SessionRole::Controller);
        assert_eq!(
            controller.seal(
                MessageKind::InputEvent,
                ChannelId::InputReliable,
                0,
                b"input"
            ),
            Err(SecureSessionError::KeyConfirmationRequired)
        );
    }

    #[test]
    fn opposite_roles_exchange_encrypted_business_data() {
        let mut controller = session(SessionRole::Controller);
        let mut controlled = session(SessionRole::Controlled);
        confirm_both(&mut controller, &mut controlled);
        let (header, ciphertext) = controller
            .seal(
                MessageKind::InputEvent,
                ChannelId::InputReliable,
                0,
                b"input",
            )
            .expect("seal");

        assert_eq!(controlled.open(header, &ciphertext), Ok(b"input".to_vec()));
        assert_eq!(
            controlled.open(header, &ciphertext),
            Err(SecureSessionError::Crypto(CryptoError::ReplayDetected))
        );
    }

    #[test]
    fn tampered_header_is_authenticated_before_authorization() {
        let mut controller = session(SessionRole::Controller);
        let mut controlled = session(SessionRole::Controlled);
        confirm_both(&mut controller, &mut controlled);
        let (mut header, ciphertext) = controller
            .seal(
                MessageKind::InputEvent,
                ChannelId::InputReliable,
                0,
                b"input",
            )
            .expect("seal");
        header.kind = MessageKind::ClipboardText;
        header.channel_id = ChannelId::Clipboard;

        assert_eq!(
            controlled.open(header, &ciphertext),
            Err(SecureSessionError::Crypto(
                CryptoError::AuthenticationFailed
            ))
        );
    }

    #[test]
    fn permissions_or_path_change_invalidates_old_keys() {
        let mut controller = session(SessionRole::Controller);
        assert_eq!(
            controller.invalidate_if_binding_changed([0_u8; 32], TransportPath::UdpP2p, 2, None),
            Err(SecureSessionError::PermissionsChanged)
        );
        assert_eq!(controller.state(), SecureSessionState::Invalidated);
    }

    #[test]
    fn failed_peer_key_confirm_invalidates_session() {
        let mut controller = session(SessionRole::Controller);
        let controlled = session(SessionRole::Controlled);
        let mut confirm = create_key_confirm(
            1,
            "controlled".to_owned(),
            SessionRole::Controlled,
            controlled.key_exchange_transcript_hash,
            1_000,
            &controlled.keys,
        )
        .expect("confirm");
        confirm.key_exchange_transcript_hash = [8_u8; 32];

        assert_eq!(
            controller.verify_peer_key_confirm(&confirm, "controlled", 1_001),
            Err(SecureSessionError::Crypto(
                CryptoError::InvalidKeyExchangeContext
            ))
        );
        assert_eq!(controller.state(), SecureSessionState::Invalidated);
        assert_eq!(
            controller.verify_peer_key_confirm(&confirm, "controlled", 1_001),
            Err(SecureSessionError::Invalidated)
        );
    }
}
