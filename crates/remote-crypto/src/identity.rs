use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::{sha256, CryptoError, SecretBytes};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceKeyPair {
    pub public_key: [u8; 32],
    private_key: SecretBytes<32>,
}

impl DeviceKeyPair {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self::from_private_key(signing_key.to_bytes())
    }

    pub fn from_private_key(private_key: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&private_key);
        Self {
            public_key: signing_key.verifying_key().to_bytes(),
            private_key: SecretBytes::new(private_key),
        }
    }

    pub fn try_from_platform_keys(
        public_key: [u8; 32],
        private_key: [u8; 32],
    ) -> Result<Self, CryptoError> {
        let key_pair = Self::from_private_key(private_key);
        if key_pair.public_key.ct_eq(&public_key).into() {
            Ok(key_pair)
        } else {
            Err(CryptoError::InvalidPublicKey)
        }
    }

    pub fn private_key_for_platform_crypto(&self) -> &[u8; 32] {
        self.private_key.expose_for_crypto()
    }

    pub fn sign_digest(&self, digest: &[u8; 32]) -> [u8; 64] {
        SigningKey::from_bytes(self.private_key.expose_for_crypto())
            .sign(digest)
            .to_bytes()
    }

    pub fn sign_canonical(&self, canonical_bytes: &[u8]) -> [u8; 64] {
        self.sign_digest(&sha256(canonical_bytes))
    }
}

pub fn verify_digest_signature(
    public_key: &[u8; 32],
    digest: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| CryptoError::InvalidPublicKey)?;
    let signature = Signature::from_bytes(signature);
    verifying_key
        .verify(digest, &signature)
        .map_err(|_| CryptoError::SignatureMismatch)
}

pub fn verify_canonical_signature(
    public_key: &[u8; 32],
    canonical_bytes: &[u8],
    signature: &[u8; 64],
) -> Result<(), CryptoError> {
    verify_digest_signature(public_key, &sha256(canonical_bytes), signature)
}

pub struct EphemeralKeyPair {
    secret: StaticSecret,
    pub public_key: [u8; 32],
}

impl std::fmt::Debug for EphemeralKeyPair {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EphemeralKeyPair")
            .field("secret", &"<redacted>")
            .field("public_key", &self.public_key)
            .finish()
    }
}

impl EphemeralKeyPair {
    pub fn generate() -> Self {
        Self::from_secret_bytes(StaticSecret::random_from_rng(OsRng).to_bytes())
    }

    pub fn from_secret_bytes(secret: [u8; 32]) -> Self {
        let secret = StaticSecret::from(secret);
        let public_key = X25519PublicKey::from(&secret).to_bytes();
        Self { secret, public_key }
    }

    pub fn diffie_hellman(&self, peer_public_key: [u8; 32]) -> Result<[u8; 32], CryptoError> {
        let peer = X25519PublicKey::from(peer_public_key);
        let shared_secret = self.secret.diffie_hellman(&peer).to_bytes();
        if shared_secret.ct_eq(&[0_u8; 32]).into() {
            Err(CryptoError::NonContributoryKeyExchange)
        } else {
            Ok(shared_secret)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_detects_canonical_tampering() {
        let key = DeviceKeyPair::from_private_key([7_u8; 32]);
        let signature = key.sign_canonical(b"signed bytes");

        assert!(verify_canonical_signature(&key.public_key, b"signed bytes", &signature).is_ok());
        assert_eq!(
            verify_canonical_signature(&key.public_key, b"tampered", &signature),
            Err(CryptoError::SignatureMismatch)
        );
    }

    #[test]
    fn x25519_agrees_on_shared_secret() {
        let controller = EphemeralKeyPair::from_secret_bytes([1_u8; 32]);
        let controlled = EphemeralKeyPair::from_secret_bytes([2_u8; 32]);

        assert_eq!(
            controller
                .diffie_hellman(controlled.public_key)
                .expect("shared"),
            controlled
                .diffie_hellman(controller.public_key)
                .expect("shared")
        );
    }
}
