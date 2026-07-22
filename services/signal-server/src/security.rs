use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use remote_protocol::{canonical_json_bytes, CanonicalWriter, PROTOCOL_VERSION};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

pub const SUPPORTED_PROTOCOL_VERSIONS: [u16; 1] = [PROTOCOL_VERSION];
pub const HELLO_WINDOW_MILLIS: u64 = 30_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolNegotiation {
    pub client_versions: Vec<u16>,
    pub client_min_version: u16,
    pub selected_version: u16,
    pub versions_hash: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessClaims {
    pub account_id: String,
    pub account_session_id: String,
    pub issued_at_epoch_millis: u64,
    pub expires_at_epoch_millis: u64,
    pub mfa_verified: bool,
    pub token_type: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityError {
    InvalidToken,
    ExpiredToken,
    InvalidProtocolHeader,
    UnsupportedVersion,
    InvalidEncoding,
    InvalidHash,
    InvalidSignature,
    TimestampOutsideWindow,
}

pub fn verify_access_token(
    token: &str,
    secret: &[u8],
    now_epoch_millis: u64,
) -> Result<AccessClaims, SecurityError> {
    let (payload, encoded_signature) = token.split_once('.').ok_or(SecurityError::InvalidToken)?;
    let signature = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| SecurityError::InvalidToken)?;
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| SecurityError::InvalidToken)?;
    mac.update(payload.as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| SecurityError::InvalidToken)?;

    let claims_bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| SecurityError::InvalidToken)?;
    let claims: AccessClaims =
        serde_json::from_slice(&claims_bytes).map_err(|_| SecurityError::InvalidToken)?;
    if claims.token_type != "access" || claims.account_id.is_empty() {
        return Err(SecurityError::InvalidToken);
    }
    if claims.expires_at_epoch_millis <= now_epoch_millis {
        return Err(SecurityError::ExpiredToken);
    }
    Ok(claims)
}

pub fn service_token_matches(provided: &str, expected: &str) -> bool {
    const COMPARISON_KEY: &[u8] = b"rctl-service-token-comparison-v1";
    let Ok(mut expected_mac) = HmacSha256::new_from_slice(COMPARISON_KEY) else {
        return false;
    };
    expected_mac.update(expected.as_bytes());
    let expected_tag = expected_mac.finalize().into_bytes();

    let Ok(mut provided_mac) = HmacSha256::new_from_slice(COMPARISON_KEY) else {
        return false;
    };
    provided_mac.update(provided.as_bytes());
    provided_mac.verify_slice(&expected_tag).is_ok()
}

pub fn parse_protocol_headers(
    versions: Option<&str>,
    minimum: Option<&str>,
) -> Result<ProtocolNegotiation, SecurityError> {
    let versions = versions.ok_or(SecurityError::InvalidProtocolHeader)?;
    let minimum = minimum.ok_or(SecurityError::InvalidProtocolHeader)?;
    let client_min_version = minimum
        .parse::<u16>()
        .map_err(|_| SecurityError::InvalidProtocolHeader)?;

    let mut client_versions = versions
        .split(',')
        .map(|value| {
            if value.is_empty() || value.trim() != value {
                return Err(SecurityError::InvalidProtocolHeader);
            }
            value
                .parse::<u16>()
                .map_err(|_| SecurityError::InvalidProtocolHeader)
        })
        .collect::<Result<Vec<_>, _>>()?;
    client_versions.sort_unstable();
    client_versions.dedup();
    if client_versions.is_empty()
        || client_versions.len() > 16
        || !client_versions.contains(&client_min_version)
    {
        return Err(SecurityError::InvalidProtocolHeader);
    }

    let selected_version = SUPPORTED_PROTOCOL_VERSIONS
        .iter()
        .copied()
        .filter(|version| {
            *version >= client_min_version && client_versions.binary_search(version).is_ok()
        })
        .max()
        .ok_or(SecurityError::UnsupportedVersion)?;
    let versions_hash = protocol_versions_hash(&client_versions, client_min_version)?;

    Ok(ProtocolNegotiation {
        client_versions,
        client_min_version,
        selected_version,
        versions_hash,
    })
}

pub fn protocol_versions_hash(versions: &[u16], minimum: u16) -> Result<[u8; 32], SecurityError> {
    let mut encoded_versions = Vec::with_capacity(versions.len() * 2);
    for version in versions {
        encoded_versions.extend_from_slice(&version.to_be_bytes());
    }
    let mut writer = CanonicalWriter::new("rctl-protocol-versions-v1")
        .map_err(|_| SecurityError::InvalidHash)?;
    writer
        .push_field("client_supported_protocol_versions", &encoded_versions)
        .map_err(|_| SecurityError::InvalidHash)?
        .push_u16("client_min_protocol_version", minimum)
        .map_err(|_| SecurityError::InvalidHash)?;
    Ok(sha256(&writer.finish()))
}

pub fn client_capabilities_hash(capabilities: &Value) -> Result<[u8; 32], SecurityError> {
    let capabilities =
        canonical_json_bytes(capabilities).map_err(|_| SecurityError::InvalidHash)?;
    let mut writer = CanonicalWriter::new("rctl-client-capabilities-v1")
        .map_err(|_| SecurityError::InvalidHash)?;
    writer
        .push_field("client_capabilities", &capabilities)
        .map_err(|_| SecurityError::InvalidHash)?;
    Ok(sha256(&writer.finish()))
}

#[allow(clippy::too_many_arguments)]
pub fn hello_signature_input(
    server_nonce: &[u8; 32],
    client_nonce: &[u8; 32],
    account_id: &str,
    device_id: &str,
    protocol_version: u16,
    timestamp_epoch_millis: u64,
    versions_hash: &[u8; 32],
    capabilities_hash: &[u8; 32],
) -> Result<Vec<u8>, SecurityError> {
    let mut writer =
        CanonicalWriter::new("rctl-ws-hello-v1").map_err(|_| SecurityError::InvalidHash)?;
    writer
        .push_field("server_nonce", server_nonce)
        .map_err(|_| SecurityError::InvalidHash)?
        .push_field("client_nonce", client_nonce)
        .map_err(|_| SecurityError::InvalidHash)?
        .push_str("account_id", account_id)
        .map_err(|_| SecurityError::InvalidHash)?
        .push_str("device_id", device_id)
        .map_err(|_| SecurityError::InvalidHash)?
        .push_u16("protocol_version", protocol_version)
        .map_err(|_| SecurityError::InvalidHash)?
        .push_u64("timestamp", timestamp_epoch_millis)
        .map_err(|_| SecurityError::InvalidHash)?
        .push_field("client_supported_protocol_versions_hash", versions_hash)
        .map_err(|_| SecurityError::InvalidHash)?
        .push_field("client_capabilities_hash", capabilities_hash)
        .map_err(|_| SecurityError::InvalidHash)?;
    Ok(writer.finish())
}

pub fn verify_hello_signature(
    public_key: &[u8; 32],
    canonical_input: &[u8],
    encoded_signature: &str,
) -> Result<(), SecurityError> {
    let signature = decode_array::<64>(encoded_signature)?;
    let signature = Signature::from_bytes(&signature);
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| SecurityError::InvalidSignature)?;
    verifying_key
        .verify(&sha256(canonical_input), &signature)
        .map_err(|_| SecurityError::InvalidSignature)
}

pub fn ensure_timestamp_in_window(
    timestamp_epoch_millis: u64,
    now_epoch_millis: u64,
) -> Result<(), SecurityError> {
    if timestamp_epoch_millis.abs_diff(now_epoch_millis) > HELLO_WINDOW_MILLIS {
        Err(SecurityError::TimestampOutsideWindow)
    } else {
        Ok(())
    }
}

pub fn decode_array<const N: usize>(value: &str) -> Result<[u8; N], SecurityError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| SecurityError::InvalidEncoding)?
        .try_into()
        .map_err(|_| SecurityError::InvalidEncoding)
}

pub fn encode(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

pub fn encode_hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

pub fn decode_hex_array<const N: usize>(value: &str) -> Result<[u8; N], SecurityError> {
    if value.len() != N * 2 {
        return Err(SecurityError::InvalidEncoding);
    }
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_hex_nibble(pair[0]).ok_or(SecurityError::InvalidEncoding)?;
        let low = decode_hex_nibble(pair[1]).ok_or(SecurityError::InvalidEncoding)?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn decode_hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

pub fn sha256(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

#[cfg(test)]
pub fn sign_access_token_for_test(claims: &AccessClaims, secret: &[u8]) -> String {
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).expect("claims json"));
    let mut mac = HmacSha256::new_from_slice(secret).expect("test HMAC key");
    mac.update(payload.as_bytes());
    format!(
        "{payload}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_headers_are_sorted_deduplicated_and_bound() {
        let negotiated = parse_protocol_headers(Some("1,1"), Some("1")).expect("negotiation");
        assert_eq!(negotiated.client_versions, vec![1]);
        assert_eq!(negotiated.selected_version, 1);
        assert_ne!(negotiated.versions_hash, [0; 32]);
    }

    #[test]
    fn protocol_headers_reject_missing_invalid_and_unsupported_values() {
        assert_eq!(
            parse_protocol_headers(None, Some("1")),
            Err(SecurityError::InvalidProtocolHeader)
        );
        assert_eq!(
            parse_protocol_headers(Some("1, 2"), Some("1")),
            Err(SecurityError::InvalidProtocolHeader)
        );
        assert_eq!(
            parse_protocol_headers(Some("2"), Some("2")),
            Err(SecurityError::UnsupportedVersion)
        );
    }

    #[test]
    fn access_token_rejects_tampering_and_expiry() {
        let claims = AccessClaims {
            account_id: "account-1".to_owned(),
            account_session_id: "session-1".to_owned(),
            issued_at_epoch_millis: 10,
            expires_at_epoch_millis: 100,
            mfa_verified: false,
            token_type: "access".to_owned(),
        };
        let token = sign_access_token_for_test(&claims, b"01234567890123456789012345678901");
        assert!(verify_access_token(&token, b"01234567890123456789012345678901", 99).is_ok());
        assert_eq!(
            verify_access_token(&token, b"11234567890123456789012345678901", 99),
            Err(SecurityError::InvalidToken)
        );
        assert_eq!(
            verify_access_token(&token, b"01234567890123456789012345678901", 100),
            Err(SecurityError::ExpiredToken)
        );
    }

    #[test]
    fn service_token_comparison_rejects_wrong_values() {
        assert!(service_token_matches("service-token-1", "service-token-1"));
        assert!(!service_token_matches("service-token-2", "service-token-1"));
        assert!(!service_token_matches("", "service-token-1"));
    }

    #[test]
    fn capabilities_hash_uses_domain_separation() {
        let capabilities = serde_json::json!({"platform": "ubuntu", "arch": "x86_64"});
        let hash = client_capabilities_hash(&capabilities).expect("hash");
        assert_ne!(
            hash,
            sha256(&canonical_json_bytes(&capabilities).expect("jcs"))
        );
    }
}
