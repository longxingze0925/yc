use std::collections::HashSet;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use remote_protocol::{
    KeyConfirm, SessionKdfContext, SessionPermissions, SessionRole, SignedKeyExchange,
    SignedKeyExchangePayload, TrafficDirection,
};
use sha2::Sha256;

use crate::{sha256, verify_canonical_signature, CryptoError, DeviceKeyPair, SecretBytes};

const KEY_LEN: usize = 32;
const NONCE_PREFIX_LEN: usize = 4;
pub const KEY_CONFIRM_WINDOW_MILLIS: u64 = 30_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedSessionKeys {
    controller_to_controlled_key: SecretBytes<KEY_LEN>,
    controller_to_controlled_nonce_prefix: SecretBytes<NONCE_PREFIX_LEN>,
    controlled_to_controller_key: SecretBytes<KEY_LEN>,
    controlled_to_controller_nonce_prefix: SecretBytes<NONCE_PREFIX_LEN>,
    key_confirmation_controller_to_controlled: SecretBytes<KEY_LEN>,
    key_confirmation_controlled_to_controller: SecretBytes<KEY_LEN>,
}

impl DerivedSessionKeys {
    pub fn traffic_key(&self, direction: TrafficDirection) -> &[u8; KEY_LEN] {
        match direction {
            TrafficDirection::ControllerToControlled => {
                self.controller_to_controlled_key.expose_for_crypto()
            }
            TrafficDirection::ControlledToController => {
                self.controlled_to_controller_key.expose_for_crypto()
            }
        }
    }

    pub fn nonce_prefix(&self, direction: TrafficDirection) -> &[u8; NONCE_PREFIX_LEN] {
        match direction {
            TrafficDirection::ControllerToControlled => self
                .controller_to_controlled_nonce_prefix
                .expose_for_crypto(),
            TrafficDirection::ControlledToController => self
                .controlled_to_controller_nonce_prefix
                .expose_for_crypto(),
        }
    }

    pub fn confirmation_key(&self, direction: TrafficDirection) -> &[u8; KEY_LEN] {
        match direction {
            TrafficDirection::ControllerToControlled => self
                .key_confirmation_controller_to_controlled
                .expose_for_crypto(),
            TrafficDirection::ControlledToController => self
                .key_confirmation_controlled_to_controller
                .expose_for_crypto(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionKeys {
    send_key: SecretBytes<32>,
    receive_key: SecretBytes<32>,
}

impl SessionKeys {
    pub fn from_key_exchange(send_key: [u8; 32], receive_key: [u8; 32]) -> Self {
        Self {
            send_key: SecretBytes::new(send_key),
            receive_key: SecretBytes::new(receive_key),
        }
    }

    pub fn send_key_for_platform_crypto(&self) -> &[u8; 32] {
        self.send_key.expose_for_crypto()
    }

    pub fn receive_key_for_platform_crypto(&self) -> &[u8; 32] {
        self.receive_key.expose_for_crypto()
    }
}

pub fn permissions_digest(permissions: SessionPermissions) -> Result<[u8; 32], CryptoError> {
    permissions
        .canonical_bytes()
        .map(|bytes| sha256(&bytes))
        .map_err(|_| CryptoError::CanonicalEncoding)
}

pub fn session_context_hash(
    context: &remote_protocol::SessionContext,
) -> Result<[u8; 32], CryptoError> {
    context
        .canonical_bytes()
        .map(|bytes| sha256(&bytes))
        .map_err(|_| CryptoError::CanonicalEncoding)
}

pub fn sign_key_exchange(
    payload: SignedKeyExchangePayload,
    device_key: &DeviceKeyPair,
) -> Result<SignedKeyExchange, CryptoError> {
    if !payload.validate_path_binding() {
        return Err(CryptoError::InvalidKeyExchangeContext);
    }
    let canonical = payload
        .canonical_bytes()
        .map_err(|_| CryptoError::CanonicalEncoding)?;
    Ok(SignedKeyExchange {
        payload,
        signature: device_key.sign_canonical(&canonical).to_vec(),
    })
}

pub fn verify_key_exchange(
    message: &SignedKeyExchange,
    expected_payload: &SignedKeyExchangePayload,
    device_public_key: &[u8; 32],
) -> Result<(), CryptoError> {
    if &message.payload != expected_payload || !message.payload.validate_path_binding() {
        return Err(CryptoError::InvalidKeyExchangeContext);
    }
    let canonical = message
        .payload
        .canonical_bytes()
        .map_err(|_| CryptoError::CanonicalEncoding)?;
    let signature = message
        .signature_bytes()
        .ok_or(CryptoError::InvalidSignature)?;
    verify_canonical_signature(device_public_key, &canonical, &signature)
}

pub fn key_exchange_transcript_hash(
    controller: &SignedKeyExchange,
    controlled: &SignedKeyExchange,
) -> Result<[u8; 32], CryptoError> {
    if controller.payload.role != SessionRole::Controller
        || controlled.payload.role != SessionRole::Controlled
    {
        return Err(CryptoError::DeviceRoleMismatch);
    }
    let controller_canonical = controller
        .payload
        .canonical_bytes()
        .map_err(|_| CryptoError::CanonicalEncoding)?;
    let controlled_canonical = controlled
        .payload
        .canonical_bytes()
        .map_err(|_| CryptoError::CanonicalEncoding)?;
    let controller_signature = controller
        .signature_bytes()
        .ok_or(CryptoError::InvalidSignature)?;
    let controlled_signature = controlled
        .signature_bytes()
        .ok_or(CryptoError::InvalidSignature)?;

    let mut transcript =
        Vec::with_capacity(controller_canonical.len() + controlled_canonical.len() + 2 * 64);
    transcript.extend_from_slice(&controller_canonical);
    transcript.extend_from_slice(&controller_signature);
    transcript.extend_from_slice(&controlled_canonical);
    transcript.extend_from_slice(&controlled_signature);
    Ok(sha256(&transcript))
}

pub fn derive_session_keys(
    shared_secret: &[u8; 32],
    context: &SessionKdfContext,
) -> Result<DerivedSessionKeys, CryptoError> {
    if context.selected_transport_path.is_relay() != context.relay_node_id.is_some() {
        return Err(CryptoError::InvalidKeyExchangeContext);
    }
    let salt = context
        .salt_canonical_bytes()
        .map(|bytes| sha256(&bytes))
        .map_err(|_| CryptoError::CanonicalEncoding)?;
    let info_base = context
        .info_base()
        .map_err(|_| CryptoError::CanonicalEncoding)?;
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret);

    Ok(DerivedSessionKeys {
        controller_to_controlled_key: SecretBytes::new(expand::<32>(
            &hkdf,
            &info_base,
            b"controller_to_controlled_key",
        )?),
        controller_to_controlled_nonce_prefix: SecretBytes::new(expand::<4>(
            &hkdf,
            &info_base,
            b"controller_to_controlled_nonce_prefix",
        )?),
        controlled_to_controller_key: SecretBytes::new(expand::<32>(
            &hkdf,
            &info_base,
            b"controlled_to_controller_key",
        )?),
        controlled_to_controller_nonce_prefix: SecretBytes::new(expand::<4>(
            &hkdf,
            &info_base,
            b"controlled_to_controller_nonce_prefix",
        )?),
        key_confirmation_controller_to_controlled: SecretBytes::new(expand::<32>(
            &hkdf,
            &info_base,
            b"key_confirmation_controller_to_controlled",
        )?),
        key_confirmation_controlled_to_controller: SecretBytes::new(expand::<32>(
            &hkdf,
            &info_base,
            b"key_confirmation_controlled_to_controller",
        )?),
    })
}

fn expand<const N: usize>(
    hkdf: &Hkdf<Sha256>,
    info_base: &[u8],
    label: &[u8],
) -> Result<[u8; N], CryptoError> {
    let mut info = Vec::with_capacity(info_base.len() + label.len());
    info.extend_from_slice(info_base);
    info.extend_from_slice(label);
    let mut output = [0_u8; N];
    hkdf.expand(&info, &mut output)
        .map_err(|_| CryptoError::KeyDerivation)?;
    Ok(output)
}

pub fn create_key_confirm(
    session_id: u128,
    device_id: String,
    role: SessionRole,
    transcript_hash: [u8; 32],
    timestamp_epoch_millis: u64,
    keys: &DerivedSessionKeys,
) -> Result<KeyConfirm, CryptoError> {
    let mut confirm = KeyConfirm {
        session_id,
        device_id,
        role,
        key_exchange_transcript_hash: transcript_hash,
        confirm_mac: [0_u8; 32],
        timestamp_epoch_millis,
    };
    let canonical = confirm
        .canonical_mac_input()
        .map_err(|_| CryptoError::CanonicalEncoding)?;
    let direction = TrafficDirection::from_sender_role(role);
    let mut mac = Hmac::<Sha256>::new_from_slice(keys.confirmation_key(direction))
        .map_err(|_| CryptoError::KeyDerivation)?;
    mac.update(&canonical);
    confirm.confirm_mac = mac.finalize().into_bytes().into();
    Ok(confirm)
}

#[derive(Debug, Default)]
pub struct KeyConfirmReplayGuard {
    accepted: HashSet<[u8; 32]>,
}

impl KeyConfirmReplayGuard {
    pub fn verify(
        &mut self,
        confirm: &KeyConfirm,
        expected_device_id: &str,
        expected_role: SessionRole,
        expected_transcript_hash: &[u8; 32],
        now_epoch_millis: u64,
        keys: &DerivedSessionKeys,
    ) -> Result<(), CryptoError> {
        if confirm.device_id != expected_device_id || confirm.role != expected_role {
            return Err(CryptoError::DeviceRoleMismatch);
        }
        if &confirm.key_exchange_transcript_hash != expected_transcript_hash {
            return Err(CryptoError::InvalidKeyExchangeContext);
        }
        if now_epoch_millis.abs_diff(confirm.timestamp_epoch_millis) > KEY_CONFIRM_WINDOW_MILLIS {
            return Err(CryptoError::TimestampOutsideWindow);
        }
        let canonical = confirm
            .canonical_mac_input()
            .map_err(|_| CryptoError::CanonicalEncoding)?;
        let direction = TrafficDirection::from_sender_role(confirm.role);
        let mut mac = Hmac::<Sha256>::new_from_slice(keys.confirmation_key(direction))
            .map_err(|_| CryptoError::KeyDerivation)?;
        mac.update(&canonical);
        mac.verify_slice(&confirm.confirm_mac)
            .map_err(|_| CryptoError::AuthenticationFailed)?;

        let mut fingerprint_input = canonical;
        fingerprint_input.extend_from_slice(&confirm.confirm_mac);
        let fingerprint = sha256(&fingerprint_input);
        if !self.accepted.insert(fingerprint) {
            return Err(CryptoError::ReplayDetected);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use remote_protocol::{SessionContext, TransportPath, PROTOCOL_VERSION};

    use super::*;

    fn kdf_context() -> SessionKdfContext {
        SessionKdfContext {
            account_id: "account-a".to_owned(),
            session_id: 1,
            controller_device_id: "controller-a".to_owned(),
            controlled_device_id: "controlled-a".to_owned(),
            permissions_digest: [3_u8; 32],
            protocol_version: PROTOCOL_VERSION,
            session_expires_at_epoch_millis: 10_000,
            selected_transport_path: TransportPath::UdpP2p,
            selected_candidate_pair_id: 2,
            relay_node_id: None,
            key_exchange_transcript_hash: [4_u8; 32],
        }
    }

    #[test]
    fn nine_permissions_feed_digest() {
        let baseline = permissions_digest(SessionPermissions::default()).expect("digest");
        let changed = permissions_digest(SessionPermissions {
            block_local_input: true,
            ..SessionPermissions::default()
        })
        .expect("digest");

        assert_ne!(baseline, changed);
    }

    #[test]
    fn account_is_covered_by_context_hash_and_hkdf() {
        let permissions_digest = [3_u8; 32];
        let mut session = SessionContext {
            account_id: "account-a".to_owned(),
            session_id: 1,
            controller_device_id: "controller-a".to_owned(),
            controlled_device_id: "controlled-a".to_owned(),
            permissions_digest,
            protocol_version: PROTOCOL_VERSION,
            session_expires_at_epoch_millis: 10_000,
        };
        let first_context_hash = session_context_hash(&session).expect("hash");
        session.account_id = "account-b".to_owned();
        assert_ne!(
            first_context_hash,
            session_context_hash(&session).expect("hash")
        );

        let first = derive_session_keys(&[9_u8; 32], &kdf_context()).expect("keys");
        let mut changed = kdf_context();
        changed.account_id = "account-b".to_owned();
        let second = derive_session_keys(&[9_u8; 32], &changed).expect("keys");
        assert_ne!(
            first.traffic_key(TrafficDirection::ControllerToControlled),
            second.traffic_key(TrafficDirection::ControllerToControlled)
        );
    }

    #[test]
    fn direction_labels_derive_distinct_material() {
        let keys = derive_session_keys(&[9_u8; 32], &kdf_context()).expect("keys");

        assert_ne!(
            keys.traffic_key(TrafficDirection::ControllerToControlled),
            keys.traffic_key(TrafficDirection::ControlledToController)
        );
        assert_ne!(
            keys.nonce_prefix(TrafficDirection::ControllerToControlled),
            keys.nonce_prefix(TrafficDirection::ControlledToController)
        );
    }

    #[test]
    fn key_confirm_rejects_replay_and_wrong_direction() {
        let keys = derive_session_keys(&[9_u8; 32], &kdf_context()).expect("keys");
        let confirm = create_key_confirm(
            1,
            "controller-a".to_owned(),
            SessionRole::Controller,
            [5_u8; 32],
            1_000,
            &keys,
        )
        .expect("confirm");
        let mut replay = KeyConfirmReplayGuard::default();
        assert!(replay
            .verify(
                &confirm,
                "controller-a",
                SessionRole::Controller,
                &[5_u8; 32],
                1_001,
                &keys,
            )
            .is_ok());
        assert_eq!(
            replay.verify(
                &confirm,
                "controller-a",
                SessionRole::Controller,
                &[5_u8; 32],
                1_001,
                &keys,
            ),
            Err(CryptoError::ReplayDetected)
        );

        let mut wrong_role = confirm.clone();
        wrong_role.role = SessionRole::Controlled;
        assert_eq!(
            KeyConfirmReplayGuard::default().verify(
                &wrong_role,
                "controller-a",
                SessionRole::Controller,
                &[5_u8; 32],
                1_001,
                &keys,
            ),
            Err(CryptoError::DeviceRoleMismatch)
        );

        assert_eq!(
            KeyConfirmReplayGuard::default().verify(
                &confirm,
                "controller-a",
                SessionRole::Controller,
                &[6_u8; 32],
                1_001,
                &keys,
            ),
            Err(CryptoError::InvalidKeyExchangeContext)
        );
    }
}
