use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use remote_protocol::{
    encode_header, ChannelId, MessageHeader, TrafficDirection, MAX_SECURE_SEQUENCE,
};

use crate::CryptoError;

const AUTH_TAG_LEN: usize = 16;
const REPLAY_WINDOW_BITS: u64 = 64;

pub fn build_nonce(
    direction_nonce_prefix: &[u8; 4],
    channel_id: ChannelId,
    sequence: u64,
) -> Result<[u8; 12], CryptoError> {
    if sequence > MAX_SECURE_SEQUENCE {
        return Err(CryptoError::SequenceExhausted);
    }
    let mut nonce = [0_u8; 12];
    nonce[0..4].copy_from_slice(direction_nonce_prefix);
    nonce[4..6].copy_from_slice(&(channel_id as u16).to_be_bytes());
    nonce[6..12].copy_from_slice(&sequence.to_be_bytes()[2..8]);
    Ok(nonce)
}

pub fn build_aad(
    header: MessageHeader,
    permissions_digest: &[u8; 32],
    direction: TrafficDirection,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(40 + 32 + direction.as_str().len());
    aad.extend_from_slice(&encode_header(header));
    aad.extend_from_slice(permissions_digest);
    aad.extend_from_slice(direction.as_str().as_bytes());
    aad
}

pub fn encrypt_payload(
    key: &[u8; 32],
    direction_nonce_prefix: &[u8; 4],
    permissions_digest: &[u8; 32],
    direction: TrafficDirection,
    mut header: MessageHeader,
    plaintext: &[u8],
) -> Result<(MessageHeader, Vec<u8>), CryptoError> {
    header
        .validate_kind_channel()
        .map_err(|_| CryptoError::InvalidChannel)?;
    let encrypted_len = plaintext
        .len()
        .checked_add(AUTH_TAG_LEN)
        .and_then(|len| u32::try_from(len).ok())
        .ok_or(CryptoError::InvalidPayloadLength)?;
    header.payload_len = encrypted_len;
    let nonce = build_nonce(direction_nonce_prefix, header.channel_id, header.sequence)?;
    let aad = build_aad(header, permissions_digest, direction);
    let cipher = ChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    Ok((header, ciphertext))
}

pub fn decrypt_payload(
    key: &[u8; 32],
    direction_nonce_prefix: &[u8; 4],
    permissions_digest: &[u8; 32],
    direction: TrafficDirection,
    header: MessageHeader,
    ciphertext: &[u8],
    replay_guard: &mut ReplayGuard,
) -> Result<Vec<u8>, CryptoError> {
    header
        .validate_kind_channel()
        .map_err(|_| CryptoError::InvalidChannel)?;
    if usize::try_from(header.payload_len).ok() != Some(ciphertext.len()) {
        return Err(CryptoError::InvalidPayloadLength);
    }
    replay_guard.check(header.channel_id, header.sequence)?;
    let nonce = build_nonce(direction_nonce_prefix, header.channel_id, header.sequence)?;
    let aad = build_aad(header, permissions_digest, direction);
    let cipher = ChaCha20Poly1305::new(key.into());
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::AuthenticationFailed)?;
    replay_guard.record(header.channel_id, header.sequence);
    Ok(plaintext)
}

#[derive(Debug, Clone, Copy, Default)]
struct ReplayWindow {
    highest: Option<u64>,
    bitmap: u64,
}

impl ReplayWindow {
    fn check(self, sequence: u64) -> Result<(), CryptoError> {
        let Some(highest) = self.highest else {
            return Ok(());
        };
        if sequence > highest {
            return Ok(());
        }
        let distance = highest - sequence;
        if distance >= REPLAY_WINDOW_BITS {
            return Err(CryptoError::MessageTooOld);
        }
        if self.bitmap & (1_u64 << distance) != 0 {
            return Err(CryptoError::ReplayDetected);
        }
        Ok(())
    }

    fn record(&mut self, sequence: u64) {
        match self.highest {
            None => {
                self.highest = Some(sequence);
                self.bitmap = 1;
            }
            Some(highest) if sequence > highest => {
                let shift = sequence - highest;
                self.bitmap = if shift >= REPLAY_WINDOW_BITS {
                    1
                } else {
                    (self.bitmap << shift) | 1
                };
                self.highest = Some(sequence);
            }
            Some(highest) => {
                self.bitmap |= 1_u64 << (highest - sequence);
            }
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ReplayGuard {
    channels: [ReplayWindow; 9],
}

impl ReplayGuard {
    pub fn check(&self, channel: ChannelId, sequence: u64) -> Result<(), CryptoError> {
        if sequence > MAX_SECURE_SEQUENCE {
            return Err(CryptoError::SequenceExhausted);
        }
        self.channels[channel as usize].check(sequence)
    }

    pub fn record(&mut self, channel: ChannelId, sequence: u64) {
        self.channels[channel as usize].record(sequence);
    }
}

#[cfg(test)]
mod tests {
    use remote_protocol::{ChannelId, MessageKind};

    use super::*;

    fn frame(sequence: u64) -> MessageHeader {
        MessageHeader::new_on_channel(
            MessageKind::InputEvent,
            ChannelId::InputReliable,
            7,
            sequence,
            0,
        )
        .expect("header")
    }

    #[test]
    fn nonce_is_exact_4_plus_2_plus_6_vector() {
        assert_eq!(
            build_nonce(
                &[0xaa, 0xbb, 0xcc, 0xdd],
                ChannelId::InputRealtime,
                0x010203040506
            ),
            Ok([0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
        );
    }

    #[test]
    fn encrypted_payload_round_trips_and_replay_is_rejected() {
        let key = [1_u8; 32];
        let prefix = [2_u8; 4];
        let digest = [3_u8; 32];
        let (header, ciphertext) = encrypt_payload(
            &key,
            &prefix,
            &digest,
            TrafficDirection::ControllerToControlled,
            frame(1),
            b"secret input",
        )
        .expect("encrypt");
        assert!(!ciphertext.windows(6).any(|part| part == b"secret"));

        let mut replay = ReplayGuard::default();
        assert_eq!(
            decrypt_payload(
                &key,
                &prefix,
                &digest,
                TrafficDirection::ControllerToControlled,
                header,
                &ciphertext,
                &mut replay
            ),
            Ok(b"secret input".to_vec())
        );
        assert_eq!(
            decrypt_payload(
                &key,
                &prefix,
                &digest,
                TrafficDirection::ControllerToControlled,
                header,
                &ciphertext,
                &mut replay
            ),
            Err(CryptoError::ReplayDetected)
        );
    }

    #[test]
    fn direction_and_header_tampering_fail_authentication() {
        let key = [1_u8; 32];
        let prefix = [2_u8; 4];
        let digest = [3_u8; 32];
        let (header, ciphertext) = encrypt_payload(
            &key,
            &prefix,
            &digest,
            TrafficDirection::ControllerToControlled,
            frame(2),
            b"payload",
        )
        .expect("encrypt");

        assert_eq!(
            decrypt_payload(
                &key,
                &prefix,
                &digest,
                TrafficDirection::ControlledToController,
                header,
                &ciphertext,
                &mut ReplayGuard::default()
            ),
            Err(CryptoError::AuthenticationFailed)
        );

        let mut tampered = header;
        tampered.flags = 1;
        assert_eq!(
            decrypt_payload(
                &key,
                &prefix,
                &digest,
                TrafficDirection::ControllerToControlled,
                tampered,
                &ciphertext,
                &mut ReplayGuard::default()
            ),
            Err(CryptoError::AuthenticationFailed)
        );
    }
}
