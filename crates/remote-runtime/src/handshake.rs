use remote_core::{SecureSession, SecureSessionError};
use remote_crypto::{
    derive_session_keys, key_exchange_transcript_hash, permissions_digest, session_context_hash,
    sha256, verify_canonical_signature, CryptoError, EphemeralKeyPair,
};
use remote_protocol::{
    KeyConfirm, SessionContext, SessionKdfContext, SessionPermissions, SessionRole,
    SignedKeyExchange, SignedKeyExchangePayload, PROTOCOL_VERSION,
};

const KEY_EXCHANGE_WINDOW_MILLIS: u64 = 30_000;

#[derive(Debug, Clone)]
pub struct SessionHandshakeConfig {
    pub context: SessionKdfContext,
    pub permissions: SessionPermissions,
    pub local_role: SessionRole,
    pub local_device_id: String,
    pub local_device_public_key: [u8; 32],
    pub key_exchange_nonce: [u8; 32],
    pub timestamp_epoch_millis: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionHandshakeError {
    InvalidConfiguration,
    InvalidState,
    InvalidLocalSignature,
    PeerBindingMismatch,
    PeerMessageTooOld,
    SessionExpired,
    Crypto(CryptoError),
    SecureSession(SecureSessionError),
}

impl From<CryptoError> for SessionHandshakeError {
    fn from(value: CryptoError) -> Self {
        Self::Crypto(value)
    }
}

impl From<SecureSessionError> for SessionHandshakeError {
    fn from(value: SecureSessionError) -> Self {
        Self::SecureSession(value)
    }
}

pub struct SessionHandshakeReady {
    pub secure_session: SecureSession,
    pub local_key_confirm: KeyConfirm,
    pub key_exchange_transcript_hash: [u8; 32],
}

pub struct SessionHandshake {
    config: SessionHandshakeConfig,
    ephemeral_key: EphemeralKeyPair,
    local_payload: SignedKeyExchangePayload,
    local_message: Option<SignedKeyExchange>,
    peer_message: Option<SignedKeyExchange>,
}

impl std::fmt::Debug for SessionHandshake {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionHandshake")
            .field("session_id", &self.config.context.session_id)
            .field("local_role", &self.config.local_role)
            .field("local_device_id", &self.config.local_device_id)
            .field("local_signed", &self.local_message.is_some())
            .field("peer_verified", &self.peer_message.is_some())
            .field("ephemeral_key", &"<redacted>")
            .finish()
    }
}

impl SessionHandshake {
    pub fn new(config: SessionHandshakeConfig) -> Result<Self, SessionHandshakeError> {
        Self::with_ephemeral_key(config, EphemeralKeyPair::generate())
    }

    #[cfg(test)]
    fn from_ephemeral_secret(
        config: SessionHandshakeConfig,
        ephemeral_secret: [u8; 32],
    ) -> Result<Self, SessionHandshakeError> {
        Self::with_ephemeral_key(
            config,
            EphemeralKeyPair::from_secret_bytes(ephemeral_secret),
        )
    }

    fn with_ephemeral_key(
        config: SessionHandshakeConfig,
        ephemeral_key: EphemeralKeyPair,
    ) -> Result<Self, SessionHandshakeError> {
        validate_config(&config)?;
        let context_hash = session_context_hash(&SessionContext {
            account_id: config.context.account_id.clone(),
            session_id: config.context.session_id,
            controller_device_id: config.context.controller_device_id.clone(),
            controlled_device_id: config.context.controlled_device_id.clone(),
            permissions_digest: config.context.permissions_digest,
            protocol_version: config.context.protocol_version,
            session_expires_at_epoch_millis: config.context.session_expires_at_epoch_millis,
        })?;
        let local_payload = SignedKeyExchangePayload {
            session_id: config.context.session_id,
            device_id: config.local_device_id.clone(),
            role: config.local_role,
            session_context_hash: context_hash,
            permissions_digest: config.context.permissions_digest,
            session_expires_at_epoch_millis: config.context.session_expires_at_epoch_millis,
            ephemeral_public_key: ephemeral_key.public_key,
            key_exchange_nonce: config.key_exchange_nonce,
            selected_transport_path: config.context.selected_transport_path,
            selected_candidate_pair_id: config.context.selected_candidate_pair_id,
            relay_node_id: config.context.relay_node_id.clone(),
            timestamp_epoch_millis: config.timestamp_epoch_millis,
        };
        Ok(Self {
            config,
            ephemeral_key,
            local_payload,
            local_message: None,
            peer_message: None,
        })
    }

    pub fn local_payload(&self) -> &SignedKeyExchangePayload {
        &self.local_payload
    }

    pub fn local_signature_digest(&self) -> Result<[u8; 32], SessionHandshakeError> {
        self.local_payload
            .canonical_bytes()
            .map(|canonical| sha256(&canonical))
            .map_err(|_| CryptoError::CanonicalEncoding.into())
    }

    pub fn set_local_signature(
        &mut self,
        signature: Vec<u8>,
    ) -> Result<&SignedKeyExchange, SessionHandshakeError> {
        if self.local_message.is_some() || signature.len() != 64 {
            return Err(SessionHandshakeError::InvalidState);
        }
        let signature_bytes: [u8; 64] = signature
            .as_slice()
            .try_into()
            .map_err(|_| SessionHandshakeError::InvalidLocalSignature)?;
        let canonical = self
            .local_payload
            .canonical_bytes()
            .map_err(|_| CryptoError::CanonicalEncoding)?;
        verify_canonical_signature(
            &self.config.local_device_public_key,
            &canonical,
            &signature_bytes,
        )
        .map_err(|_| SessionHandshakeError::InvalidLocalSignature)?;
        self.local_message = Some(SignedKeyExchange {
            payload: self.local_payload.clone(),
            signature,
        });
        self.local_message
            .as_ref()
            .ok_or(SessionHandshakeError::InvalidState)
    }

    pub fn verify_peer_message(
        &mut self,
        message: SignedKeyExchange,
        peer_device_public_key: &[u8; 32],
        now_epoch_millis: u64,
    ) -> Result<(), SessionHandshakeError> {
        if self.peer_message.is_some() {
            return Err(SessionHandshakeError::InvalidState);
        }
        if now_epoch_millis >= self.config.context.session_expires_at_epoch_millis
            || message.payload.timestamp_epoch_millis
                >= self.config.context.session_expires_at_epoch_millis
        {
            return Err(SessionHandshakeError::SessionExpired);
        }
        let expected_peer_role = opposite_role(self.config.local_role);
        let expected_peer_device = device_for_role(&self.config.context, expected_peer_role);
        if message.payload.session_id != self.config.context.session_id
            || message.payload.device_id != expected_peer_device
            || message.payload.role != expected_peer_role
            || message.payload.session_context_hash != self.local_payload.session_context_hash
            || message.payload.permissions_digest != self.config.context.permissions_digest
            || message.payload.session_expires_at_epoch_millis
                != self.config.context.session_expires_at_epoch_millis
            || message.payload.selected_transport_path
                != self.config.context.selected_transport_path
            || message.payload.selected_candidate_pair_id
                != self.config.context.selected_candidate_pair_id
            || message.payload.relay_node_id != self.config.context.relay_node_id
            || message.payload.ephemeral_public_key == [0; 32]
            || message.payload.key_exchange_nonce == [0; 32]
            || !message.payload.validate_path_binding()
        {
            return Err(SessionHandshakeError::PeerBindingMismatch);
        }
        if message
            .payload
            .timestamp_epoch_millis
            .abs_diff(now_epoch_millis)
            > KEY_EXCHANGE_WINDOW_MILLIS
        {
            return Err(SessionHandshakeError::PeerMessageTooOld);
        }
        let signature = message
            .signature_bytes()
            .ok_or(SessionHandshakeError::PeerBindingMismatch)?;
        let canonical = message
            .payload
            .canonical_bytes()
            .map_err(|_| CryptoError::CanonicalEncoding)?;
        verify_canonical_signature(peer_device_public_key, &canonical, &signature)?;
        self.peer_message = Some(message);
        Ok(())
    }

    pub fn finish(
        self,
        key_confirm_timestamp_epoch_millis: u64,
    ) -> Result<SessionHandshakeReady, SessionHandshakeError> {
        if key_confirm_timestamp_epoch_millis >= self.config.context.session_expires_at_epoch_millis
        {
            return Err(SessionHandshakeError::SessionExpired);
        }
        let local = self
            .local_message
            .ok_or(SessionHandshakeError::InvalidState)?;
        let peer = self
            .peer_message
            .ok_or(SessionHandshakeError::InvalidState)?;
        let (controller, controlled) = match self.config.local_role {
            SessionRole::Controller => (&local, &peer),
            SessionRole::Controlled => (&peer, &local),
        };
        let transcript_hash = key_exchange_transcript_hash(controller, controlled)?;
        let shared_secret = self
            .ephemeral_key
            .diffie_hellman(peer.payload.ephemeral_public_key)?;
        let mut kdf_context = self.config.context.clone();
        kdf_context.key_exchange_transcript_hash = transcript_hash;
        let keys = derive_session_keys(&shared_secret, &kdf_context)?;
        let mut secure_session = SecureSession::new(
            kdf_context.session_id,
            self.config.local_role,
            self.config.permissions,
            kdf_context.permissions_digest,
            kdf_context.selected_transport_path,
            kdf_context.selected_candidate_pair_id,
            kdf_context.relay_node_id,
            transcript_hash,
            keys,
        )?;
        let local_key_confirm = secure_session.create_local_key_confirm(
            self.config.local_device_id,
            key_confirm_timestamp_epoch_millis,
        )?;
        Ok(SessionHandshakeReady {
            secure_session,
            local_key_confirm,
            key_exchange_transcript_hash: transcript_hash,
        })
    }
}

fn validate_config(config: &SessionHandshakeConfig) -> Result<(), SessionHandshakeError> {
    if config.context.account_id.is_empty()
        || config.context.session_id == 0
        || config.local_device_id.is_empty()
        || config.context.controller_device_id.is_empty()
        || config.context.controlled_device_id.is_empty()
        || config.context.controller_device_id == config.context.controlled_device_id
        || config.context.protocol_version != PROTOCOL_VERSION
        || config.context.session_expires_at_epoch_millis <= config.timestamp_epoch_millis
        || config.context.selected_candidate_pair_id == 0
        || config.key_exchange_nonce == [0; 32]
        || config.context.selected_transport_path.is_relay()
            != config.context.relay_node_id.is_some()
        || device_for_role(&config.context, config.local_role) != config.local_device_id
        || permissions_digest(config.permissions).ok() != Some(config.context.permissions_digest)
    {
        return Err(SessionHandshakeError::InvalidConfiguration);
    }
    Ok(())
}

fn device_for_role(context: &SessionKdfContext, role: SessionRole) -> &str {
    match role {
        SessionRole::Controller => &context.controller_device_id,
        SessionRole::Controlled => &context.controlled_device_id,
    }
}

const fn opposite_role(role: SessionRole) -> SessionRole {
    match role {
        SessionRole::Controller => SessionRole::Controlled,
        SessionRole::Controlled => SessionRole::Controller,
    }
}

#[cfg(test)]
mod tests {
    use remote_crypto::DeviceKeyPair;
    use remote_protocol::{ChannelId, MessageKind, TransportPath, PROTOCOL_VERSION};

    use super::*;

    fn config(
        role: SessionRole,
        public_key: [u8; 32],
        permissions: SessionPermissions,
    ) -> SessionHandshakeConfig {
        SessionHandshakeConfig {
            context: SessionKdfContext {
                account_id: "account".to_owned(),
                session_id: 1,
                controller_device_id: "ios-1".to_owned(),
                controlled_device_id: "ubuntu-1".to_owned(),
                permissions_digest: permissions_digest(permissions).expect("permissions digest"),
                protocol_version: PROTOCOL_VERSION,
                session_expires_at_epoch_millis: 60_000,
                selected_transport_path: TransportPath::LanDirect,
                selected_candidate_pair_id: 2,
                relay_node_id: None,
                key_exchange_transcript_hash: [0; 32],
            },
            permissions,
            local_role: role,
            local_device_id: match role {
                SessionRole::Controller => "ios-1",
                SessionRole::Controlled => "ubuntu-1",
            }
            .to_owned(),
            local_device_public_key: public_key,
            key_exchange_nonce: match role {
                SessionRole::Controller => [3; 32],
                SessionRole::Controlled => [4; 32],
            },
            timestamp_epoch_millis: 1_000,
        }
    }

    fn sign(handshake: &mut SessionHandshake, key: &DeviceKeyPair) -> SignedKeyExchange {
        let digest = handshake
            .local_signature_digest()
            .expect("signature digest");
        handshake
            .set_local_signature(key.sign_digest(&digest).to_vec())
            .expect("set signature")
            .clone()
    }

    #[test]
    fn platform_signed_exchange_derives_matching_sessions_and_key_confirms() {
        let controller_key = DeviceKeyPair::from_private_key([7; 32]);
        let controlled_key = DeviceKeyPair::from_private_key([8; 32]);
        let permissions = SessionPermissions {
            remote_desktop: true,
            input_control: true,
            require_prompt: false,
            ..SessionPermissions::default()
        };
        let mut controller = SessionHandshake::from_ephemeral_secret(
            config(
                SessionRole::Controller,
                controller_key.public_key,
                permissions,
            ),
            [11; 32],
        )
        .expect("controller handshake");
        let mut controlled = SessionHandshake::from_ephemeral_secret(
            config(
                SessionRole::Controlled,
                controlled_key.public_key,
                permissions,
            ),
            [12; 32],
        )
        .expect("controlled handshake");
        let controller_message = sign(&mut controller, &controller_key);
        let controlled_message = sign(&mut controlled, &controlled_key);
        controller
            .verify_peer_message(
                controlled_message.clone(),
                &controlled_key.public_key,
                1_001,
            )
            .expect("controller verifies peer");
        controlled
            .verify_peer_message(
                controller_message.clone(),
                &controller_key.public_key,
                1_001,
            )
            .expect("controlled verifies peer");
        let mut controller = controller.finish(1_002).expect("controller ready");
        let mut controlled = controlled.finish(1_002).expect("controlled ready");
        assert_eq!(
            controller.key_exchange_transcript_hash,
            controlled.key_exchange_transcript_hash
        );
        controller
            .secure_session
            .verify_peer_key_confirm(&controlled.local_key_confirm, "ubuntu-1", 1_003)
            .expect("controller key confirm");
        controlled
            .secure_session
            .verify_peer_key_confirm(&controller.local_key_confirm, "ios-1", 1_003)
            .expect("controlled key confirm");
        let (header, ciphertext) = controller
            .secure_session
            .seal(
                MessageKind::InputEvent,
                ChannelId::InputReliable,
                0,
                b"encrypted-input",
            )
            .expect("seal input");
        assert_eq!(
            controlled
                .secure_session
                .open(header, &ciphertext)
                .expect("open input"),
            b"encrypted-input"
        );
    }

    #[test]
    fn peer_role_path_and_context_substitution_are_rejected() {
        let controller_key = DeviceKeyPair::from_private_key([7; 32]);
        let controlled_key = DeviceKeyPair::from_private_key([8; 32]);
        let permissions = SessionPermissions {
            remote_desktop: true,
            ..SessionPermissions::default()
        };
        let mut controller = SessionHandshake::from_ephemeral_secret(
            config(
                SessionRole::Controller,
                controller_key.public_key,
                permissions,
            ),
            [11; 32],
        )
        .expect("controller handshake");
        let mut controlled = SessionHandshake::from_ephemeral_secret(
            config(
                SessionRole::Controlled,
                controlled_key.public_key,
                permissions,
            ),
            [12; 32],
        )
        .expect("controlled handshake");
        let mut controlled_message = sign(&mut controlled, &controlled_key);
        controlled_message.payload.selected_candidate_pair_id = 9;
        assert_eq!(
            controller.verify_peer_message(controlled_message, &controlled_key.public_key, 1_001),
            Err(SessionHandshakeError::PeerBindingMismatch)
        );
    }

    #[test]
    fn unsupported_protocol_version_and_expired_session_are_rejected() {
        let controller_key = DeviceKeyPair::from_private_key([7; 32]);
        let controlled_key = DeviceKeyPair::from_private_key([8; 32]);
        let permissions = SessionPermissions {
            remote_desktop: true,
            ..SessionPermissions::default()
        };

        let mut unsupported = config(
            SessionRole::Controller,
            controller_key.public_key,
            permissions,
        );
        unsupported.context.protocol_version = PROTOCOL_VERSION + 1;
        assert_eq!(
            SessionHandshake::new(unsupported).expect_err("unsupported protocol version"),
            SessionHandshakeError::InvalidConfiguration
        );

        let mut controller = SessionHandshake::from_ephemeral_secret(
            config(
                SessionRole::Controller,
                controller_key.public_key,
                permissions,
            ),
            [11; 32],
        )
        .expect("controller handshake");
        let mut controlled = SessionHandshake::from_ephemeral_secret(
            config(
                SessionRole::Controlled,
                controlled_key.public_key,
                permissions,
            ),
            [12; 32],
        )
        .expect("controlled handshake");
        let controller_message = sign(&mut controller, &controller_key);
        let controlled_message = sign(&mut controlled, &controlled_key);
        assert_eq!(
            controller.verify_peer_message(
                controlled_message.clone(),
                &controlled_key.public_key,
                60_000,
            ),
            Err(SessionHandshakeError::SessionExpired)
        );

        let mut controller = SessionHandshake::from_ephemeral_secret(
            config(
                SessionRole::Controller,
                controller_key.public_key,
                permissions,
            ),
            [11; 32],
        )
        .expect("controller handshake");
        let _ = sign(&mut controller, &controller_key);
        controller
            .verify_peer_message(controlled_message, &controlled_key.public_key, 1_001)
            .expect("peer exchange before expiry");
        assert!(matches!(
            controller.finish(60_000),
            Err(SessionHandshakeError::SessionExpired)
        ));

        // Keep both signed roles used in this fixture, preventing accidental
        // role-order regressions while exercising the expiration branch.
        assert_eq!(controller_message.payload.role, SessionRole::Controller);
    }
}
