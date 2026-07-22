mod e2ee;
mod identity;
mod session;

pub use e2ee::*;
pub use identity::*;
pub use session::*;

use std::fmt;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

#[derive(PartialEq, Eq)]
pub struct SecretBytes<const N: usize>([u8; N]);

impl<const N: usize> SecretBytes<N> {
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    pub fn expose_for_crypto(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> Clone for SecretBytes<N> {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl<const N: usize> Drop for SecretBytes<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes(<redacted>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    InvalidPublicKey,
    InvalidSignature,
    SignatureMismatch,
    CanonicalEncoding,
    InvalidKeyExchangeContext,
    NonContributoryKeyExchange,
    KeyDerivation,
    AuthenticationFailed,
    InvalidChannel,
    InvalidPayloadLength,
    SequenceExhausted,
    ReplayDetected,
    MessageTooOld,
    TimestampOutsideWindow,
    DeviceRoleMismatch,
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_redacts_secret_material() {
        let secret = SecretBytes::new([7_u8; 32]);
        let debug = format!("{secret:?}");

        assert_eq!(debug, "SecretBytes(<redacted>)");
        assert!(!debug.contains("7, 7, 7"));
    }
}
