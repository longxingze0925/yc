use std::net::IpAddr;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use rand::random;
use remote_protocol::{
    canonical_api_request_bytes, canonical_json_bytes_from_slice, canonical_operation_binding_bytes,
};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::error::ApiError;

type HmacSha256 = Hmac<Sha256>;
type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessClaims {
    pub account_id: String,
    pub account_session_id: String,
    pub issued_at_epoch_millis: u64,
    pub expires_at_epoch_millis: u64,
    pub mfa_verified: bool,
    pub token_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepUpClaims {
    pub account_id: String,
    pub device_id: String,
    pub challenge_id: String,
    pub purpose: String,
    pub operation_binding_hash: String,
    pub expires_at_epoch_millis: u64,
    pub token_type: String,
}

pub fn now_epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

pub fn random_uuid_v4() -> String {
    let mut bytes = random::<[u8; 16]>();
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

pub fn random_token(bytes: usize) -> String {
    let mut value = vec![0_u8; bytes];
    for chunk in value.chunks_mut(16) {
        let random = random::<[u8; 16]>();
        chunk.copy_from_slice(&random[..chunk.len()]);
    }
    URL_SAFE_NO_PAD.encode(value)
}

pub fn random_bytes_32() -> [u8; 32] {
    random::<[u8; 32]>()
}

pub fn decode_base64url_32(value: &str) -> Result<[u8; 32], ()> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| ())?
        .try_into()
        .map_err(|_| ())
}

pub fn encode_base64url(value: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

pub fn hash_password(password: &str) -> Result<String, ()> {
    let salt = SaltString::encode_b64(&random::<[u8; 16]>()).map_err(|_| ())?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| ())
}

pub fn verify_password(password_hash: &str, candidate: &str) -> bool {
    PasswordHash::new(password_hash)
        .ok()
        .and_then(|hash| {
            Argon2::default()
                .verify_password(candidate.as_bytes(), &hash)
                .ok()
        })
        .is_some()
}

pub fn verify_password_or_dummy(password_hash: Option<&str>, candidate: &str) -> bool {
    static DUMMY_PASSWORD_HASH: OnceLock<String> = OnceLock::new();
    let dummy_hash = DUMMY_PASSWORD_HASH.get_or_init(|| {
        hash_password("rctl-login-dummy-password-not-used")
            .expect("static dummy password hashing must succeed")
    });
    let verified = verify_password(password_hash.unwrap_or(dummy_hash), candidate);
    verified && password_hash.is_some()
}

pub fn sha256(value: &[u8]) -> [u8; 32] {
    Sha256::digest(value).into()
}

pub fn sha256_hex(value: &[u8]) -> String {
    hex(&sha256(value))
}

pub fn decode_sha256_hex(value: &str) -> Result<[u8; 32], ()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(());
    }
    let mut decoded = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(chunk[0]).ok_or(())?;
        let low = hex_nibble(chunk[1]).ok_or(())?;
        decoded[index] = (high << 4) | low;
    }
    Ok(decoded)
}

pub fn constant_time_sha256_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    constant_time_eq(left, right)
}

pub fn sign_access_token(claims: &AccessClaims, secret: &[u8]) -> Result<String, ()> {
    let payload = serde_json::to_vec(claims).map_err(|_| ())?;
    let encoded = URL_SAFE_NO_PAD.encode(payload);
    let signature = hmac_sha256(secret, encoded.as_bytes())?;
    Ok(format!("{encoded}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

pub fn sign_step_up_token(claims: &StepUpClaims, secret: &[u8]) -> Result<String, ()> {
    let payload = serde_json::to_vec(claims).map_err(|_| ())?;
    let encoded = URL_SAFE_NO_PAD.encode(payload);
    let signature = hmac_sha256(secret, encoded.as_bytes())?;
    Ok(format!("{encoded}.{}", URL_SAFE_NO_PAD.encode(signature)))
}

#[allow(clippy::too_many_arguments)]
pub fn operation_binding_hash(
    account_id: &str,
    device_id: &str,
    purpose: &str,
    method: &str,
    path: &str,
    body_hash: &[u8; 32],
    request_id: &str,
    expires_at_epoch_millis: u64,
) -> Result<String, ()> {
    canonical_operation_binding_bytes(
        account_id,
        device_id,
        purpose,
        method,
        path,
        body_hash,
        request_id,
        expires_at_epoch_millis,
    )
    .map(|canonical| sha256_hex(&canonical))
    .map_err(|_| ())
}

#[allow(clippy::too_many_arguments)]
pub fn login_request_binding_hash(
    account_id: &str,
    request_id: &str,
    device_id: &str,
    device_state: &str,
    public_key_id: Option<&str>,
    public_key_version: u32,
    device_public_key_fingerprint: &[u8; 32],
    client_nonce: &[u8; 32],
    protocol_version: u16,
) -> [u8; 32] {
    let public_key_version = public_key_version.to_be_bytes();
    let protocol_version = protocol_version.to_be_bytes();
    sha256(&canonical_fields(
        "rctl-login-request-binding-v1",
        &[
            ("account_id", account_id.as_bytes()),
            ("method", b"POST"),
            ("path", b"/v1/auth/login"),
            ("request_id", request_id.as_bytes()),
            ("device_id", device_id.as_bytes()),
            ("device_state", device_state.as_bytes()),
            (
                "public_key_id",
                public_key_id.unwrap_or_default().as_bytes(),
            ),
            ("public_key_version", &public_key_version),
            (
                "device_public_key_fingerprint",
                device_public_key_fingerprint,
            ),
            ("client_nonce", client_nonce),
            ("protocol_version", &protocol_version),
        ],
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn login_challenge_binding_hash(
    challenge_id: &str,
    account_id: &str,
    account_updated_at_epoch_millis: u64,
    login_request_binding_hash: &[u8; 32],
    device_id: &str,
    device_state: &str,
    device_public_key_fingerprint: &[u8; 32],
    client_nonce: &[u8; 32],
    server_nonce: &[u8; 32],
    ip_address_hash: &[u8; 32],
    user_agent_hash: &[u8; 32],
    risk_decision: &str,
    required_factors: &[String],
    issued_at_epoch_millis: u64,
    expires_at_epoch_millis: u64,
    attempts_limit: u8,
) -> [u8; 32] {
    let mut factors = required_factors.to_vec();
    factors.sort();
    factors.dedup();
    let required_factors_hash =
        sha256(&serde_json::to_vec(&factors).expect("string-array serialization must succeed"));
    let issued = issued_at_epoch_millis.to_be_bytes();
    let expires = expires_at_epoch_millis.to_be_bytes();
    let account_updated = account_updated_at_epoch_millis.to_be_bytes();
    let attempts = [attempts_limit];
    sha256(&canonical_fields(
        "rctl-login-challenge-v1",
        &[
            ("login_challenge_id", challenge_id.as_bytes()),
            ("account_id", account_id.as_bytes()),
            ("account_updated_at_epoch_millis", &account_updated),
            ("login_request_binding_hash", login_request_binding_hash),
            ("device_id", device_id.as_bytes()),
            ("device_state", device_state.as_bytes()),
            (
                "device_public_key_fingerprint",
                device_public_key_fingerprint,
            ),
            ("client_nonce", client_nonce),
            ("server_nonce", server_nonce),
            ("ip_address_hash", ip_address_hash),
            ("user_agent_hash", user_agent_hash),
            ("risk_decision", risk_decision.as_bytes()),
            ("required_factors_hash", &required_factors_hash),
            ("issued_at_epoch_millis", &issued),
            ("expires_at_epoch_millis", &expires),
            ("attempts_limit", &attempts),
        ],
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn device_enrollment_grant_binding_hash(
    grant_id: &str,
    account_id: &str,
    device_id: &str,
    device_public_key_fingerprint: &[u8; 32],
    login_challenge_id: &str,
    login_challenge_binding_hash: &[u8; 32],
    establish_trust: bool,
    trust_proof_type: Option<&str>,
    trust_level: Option<&str>,
    protocol_version: u16,
    issued_at_epoch_millis: u64,
    expires_at_epoch_millis: u64,
) -> [u8; 32] {
    let establish_trust = [u8::from(establish_trust)];
    let protocol_version = protocol_version.to_be_bytes();
    let issued = issued_at_epoch_millis.to_be_bytes();
    let expires = expires_at_epoch_millis.to_be_bytes();
    sha256(&canonical_fields(
        "rctl-device-enrollment-grant-v1",
        &[
            ("grant_id", grant_id.as_bytes()),
            ("account_id", account_id.as_bytes()),
            ("device_id", device_id.as_bytes()),
            (
                "device_public_key_fingerprint",
                device_public_key_fingerprint,
            ),
            ("login_challenge_id", login_challenge_id.as_bytes()),
            ("login_challenge_binding_hash", login_challenge_binding_hash),
            ("establish_trust", &establish_trust),
            (
                "trust_proof_type",
                trust_proof_type.unwrap_or_default().as_bytes(),
            ),
            ("trust_level", trust_level.unwrap_or_default().as_bytes()),
            ("protocol_version", &protocol_version),
            ("issued_at_epoch_millis", &issued),
            ("expires_at_epoch_millis", &expires),
        ],
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn device_registration_binding_hash(
    account_id: &str,
    account_session_id: &str,
    grant_id: &str,
    device_id: &str,
    display_name: &str,
    platform: &str,
    os_version: &str,
    architecture: &str,
    controller: bool,
    controlled: bool,
    file_transfer: bool,
    unattended: bool,
    device_public_key_fingerprint: &[u8; 32],
    protocol_version: u16,
) -> [u8; 32] {
    let controller = [u8::from(controller)];
    let controlled = [u8::from(controlled)];
    let file_transfer = [u8::from(file_transfer)];
    let unattended = [u8::from(unattended)];
    let protocol_version = protocol_version.to_be_bytes();
    sha256(&canonical_fields(
        "rctl-device-registration-v1",
        &[
            ("account_id", account_id.as_bytes()),
            ("account_session_id", account_session_id.as_bytes()),
            ("grant_id", grant_id.as_bytes()),
            ("device_id", device_id.as_bytes()),
            ("display_name", display_name.as_bytes()),
            ("platform", platform.as_bytes()),
            ("os_version", os_version.as_bytes()),
            ("architecture", architecture.as_bytes()),
            ("controller", &controller),
            ("controlled", &controlled),
            ("file_transfer", &file_transfer),
            ("unattended", &unattended),
            (
                "device_public_key_fingerprint",
                device_public_key_fingerprint,
            ),
            ("protocol_version", &protocol_version),
        ],
    ))
}

pub fn login_ip_address_hash(ip_address: Option<IpAddr>) -> [u8; 32] {
    match ip_address {
        Some(IpAddr::V4(address)) => sha256(&canonical_fields(
            "rctl-login-ip-v1",
            &[("address_family", b"ipv4"), ("address", &address.octets())],
        )),
        Some(IpAddr::V6(address)) => sha256(&canonical_fields(
            "rctl-login-ip-v1",
            &[("address_family", b"ipv6"), ("address", &address.octets())],
        )),
        None => sha256(&canonical_fields(
            "rctl-login-ip-v1",
            &[("address_family", b"unknown"), ("address", b"")],
        )),
    }
}

pub fn login_user_agent_hash(user_agent: &str) -> [u8; 32] {
    sha256(&canonical_fields(
        "rctl-login-user-agent-v1",
        &[("user_agent", user_agent.as_bytes())],
    ))
}

pub fn verify_access_token(token: &str, secret: &[u8], now: u64) -> Result<AccessClaims, ()> {
    let (payload, signature) = token.split_once('.').ok_or(())?;
    let received = URL_SAFE_NO_PAD.decode(signature).map_err(|_| ())?;
    let expected = hmac_sha256(secret, payload.as_bytes())?;
    if received.len() != expected.len() || !constant_time_eq(&received, &expected) {
        return Err(());
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|_| ())?;
    let claims: AccessClaims = serde_json::from_slice(&bytes).map_err(|_| ())?;
    if claims.token_type != "access" || claims.expires_at_epoch_millis <= now {
        return Err(());
    }
    Ok(claims)
}

pub fn verify_step_up_token(token: &str, secret: &[u8], now: u64) -> Result<StepUpClaims, ()> {
    let (payload, signature) = token.split_once('.').ok_or(())?;
    let received = URL_SAFE_NO_PAD.decode(signature).map_err(|_| ())?;
    let expected = hmac_sha256(secret, payload.as_bytes())?;
    if received.len() != expected.len() || !constant_time_eq(&received, &expected) {
        return Err(());
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|_| ())?;
    let claims: StepUpClaims = serde_json::from_slice(&bytes).map_err(|_| ())?;
    if claims.token_type != "step_up" || claims.expires_at_epoch_millis <= now {
        return Err(());
    }
    Ok(claims)
}

pub fn generate_totp_secret() -> String {
    BASE32_NOPAD.encode(&random::<[u8; 20]>())
}

pub fn totp_code(secret_base32: &str, timestamp_millis: u64) -> Result<(String, u64), ()> {
    let secret = BASE32_NOPAD
        .decode(secret_base32.as_bytes())
        .map_err(|_| ())?;
    let counter = timestamp_millis / 30_000;
    let mut mac = HmacSha1::new_from_slice(&secret).map_err(|_| ())?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[19] & 0x0f);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    Ok((format!("{:06}", binary % 1_000_000), counter))
}

pub fn verify_totp(secret_base32: &str, code: &str, now: u64, last: Option<u64>) -> Option<u64> {
    for offset in [-1_i64, 0, 1] {
        let adjusted = now.checked_add_signed(offset * 30_000)?;
        let (expected, counter) = totp_code(secret_base32, adjusted).ok()?;
        if expected == code && last.is_none_or(|last_counter| counter > last_counter) {
            return Some(counter);
        }
    }
    None
}

pub fn decode_public_key(value: &str) -> Result<[u8; 32], ()> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| STANDARD.decode(value))
        .map_err(|_| ())?;
    decoded.try_into().map_err(|_| ())
}

pub fn encode_public_key(value: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(value)
}

pub fn verify_new_device_key_proof(
    new_public_key: &[u8; 32],
    account_id: &str,
    device_id: &str,
    current_public_key_id: &str,
    current_public_key_version: u32,
    proof: &str,
) -> Result<(), ()> {
    let version = current_public_key_version.to_be_bytes();
    let canonical = canonical_fields(
        "rctl-device-key-rotation-v1",
        &[
            ("account_id", account_id.as_bytes()),
            ("device_id", device_id.as_bytes()),
            ("current_public_key_id", current_public_key_id.as_bytes()),
            ("current_public_key_version", &version),
            ("new_public_key", new_public_key),
        ],
    );
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(proof)
        .or_else(|_| STANDARD.decode(proof))
        .map_err(|_| ())?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| ())?;
    let verifying_key = VerifyingKey::from_bytes(new_public_key).map_err(|_| ())?;
    verifying_key
        .verify(&sha256(&canonical), &signature)
        .map_err(|_| ())
}

pub fn hex_encode(bytes: &[u8]) -> String {
    hex(bytes)
}

pub fn canonical_json_hash(bytes: &[u8]) -> Result<[u8; 32], ()> {
    if bytes.is_empty() {
        return Ok(sha256(&[]));
    }
    let canonical = canonical_json_bytes_from_slice(bytes).map_err(|_| ())?;
    Ok(sha256(&canonical))
}

pub fn canonical_request_body_hash(
    bytes: &[u8],
    content_type: Option<&str>,
) -> Result<[u8; 32], ()> {
    if bytes.is_empty() {
        return Ok(sha256(&[]));
    }
    let media_type = content_type
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if media_type.is_some_and(|value| value.eq_ignore_ascii_case("application/json")) {
        canonical_json_hash(bytes)
    } else {
        Ok(sha256(bytes))
    }
}

#[allow(clippy::too_many_arguments)]
pub fn verify_device_signature(
    public_key: &[u8; 32],
    method: &str,
    path: &str,
    body: &[u8],
    content_type: Option<&str>,
    request_id: &str,
    device_id: &str,
    account_id: &str,
    timestamp: u64,
    nonce: &str,
    signature: &str,
) -> Result<(), ()> {
    let body_hash = canonical_request_body_hash(body, content_type)?;
    let canonical = canonical_api_request_bytes(
        method, path, &body_hash, request_id, device_id, account_id, timestamp, nonce,
    )
    .map_err(|_| ())?;
    let digest = sha256(&canonical);
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature)
        .or_else(|_| STANDARD.decode(signature))
        .map_err(|_| ())?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| ())?;
    let verifying_key = VerifyingKey::from_bytes(public_key).map_err(|_| ())?;
    verifying_key.verify(&digest, &signature).map_err(|_| ())
}

#[allow(clippy::too_many_arguments)]
pub fn sign_device_request_for_test(
    signing_key: &ed25519_dalek::SigningKey,
    method: &str,
    path: &str,
    body: &[u8],
    request_id: &str,
    device_id: &str,
    account_id: &str,
    timestamp: u64,
    nonce: &str,
) -> String {
    use ed25519_dalek::Signer;
    let body_hash = canonical_json_hash(body).expect("canonical test body");
    let canonical = canonical_api_request_bytes(
        method, path, &body_hash, request_id, device_id, account_id, timestamp, nonce,
    )
    .expect("canonical test request");
    URL_SAFE_NO_PAD.encode(signing_key.sign(&sha256(&canonical)).to_bytes())
}

pub fn permissions_digest(permissions: &crate::SessionPermissions) -> String {
    let fields = [
        ("remote_desktop", permissions.remote_desktop),
        ("input_control", permissions.input_control),
        ("clipboard", permissions.clipboard),
        ("file_transfer", permissions.file_transfer),
        ("unattended", permissions.unattended),
        ("privacy_screen", permissions.privacy_screen),
        ("block_local_input", permissions.block_local_input),
        ("require_prompt", permissions.require_prompt),
        ("allow_relay", permissions.allow_relay),
    ];
    let values = fields
        .iter()
        .map(|(name, value)| (*name, [u8::from(*value)]))
        .collect::<Vec<_>>();
    let refs = values
        .iter()
        .map(|(name, value)| (*name, value.as_slice()))
        .collect::<Vec<_>>();
    sha256_hex(&canonical_fields("rctl-permissions-v1", &refs))
}

pub fn canonical_fields(domain: &str, fields: &[(&str, &[u8])]) -> Vec<u8> {
    let mut output = Vec::new();
    append_field(&mut output, "domain", domain.as_bytes());
    for (name, value) in fields {
        append_field(&mut output, name, value);
    }
    output
}

fn append_field(output: &mut Vec<u8>, name: &str, value: &[u8]) {
    output.extend_from_slice(&(name.len() as u32).to_be_bytes());
    output.extend_from_slice(name.as_bytes());
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

pub fn bearer(headers: &axum::http::HeaderMap, request_id: &str) -> Result<String, ApiError> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ApiError::unauthorized(request_id))?;
    Ok(value.to_owned())
}

fn hmac_sha256(secret: &[u8], value: &[u8]) -> Result<Vec<u8>, ()> {
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| ())?;
    mac.update(value);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use remote_protocol::canonical_idempotency_binding_bytes;

    #[derive(Deserialize)]
    struct HttpCanonicalVector {
        body: String,
        canonical_body: String,
        body_hash: String,
        method: String,
        request_target: String,
        canonical_request_target: String,
        request_id: String,
        device_id: String,
        account_id: String,
        timestamp_epoch_millis: u64,
        api_nonce: String,
        api_input_hash: String,
        purpose: String,
        expires_at_epoch_millis: u64,
        operation_binding_hash: String,
        idempotency_binding_hash: String,
    }

    #[test]
    fn password_hash_is_argon2_and_verifies() {
        let hash = hash_password("correct horse battery staple").expect("hash");
        assert!(hash.starts_with("$argon2"));
        assert!(verify_password(&hash, "correct horse battery staple"));
        assert!(!verify_password(&hash, "wrong"));
    }

    #[test]
    fn dummy_password_verification_never_authenticates_unknown_account() {
        let hash = hash_password("correct horse battery staple").expect("hash");
        assert!(verify_password_or_dummy(
            Some(&hash),
            "correct horse battery staple"
        ));
        assert!(!verify_password_or_dummy(
            None,
            "correct horse battery staple"
        ));
    }

    #[test]
    fn access_token_rejects_tampering_and_expiry() {
        let claims = AccessClaims {
            account_id: "account".into(),
            account_session_id: "session".into(),
            issued_at_epoch_millis: 100,
            expires_at_epoch_millis: 200,
            mfa_verified: true,
            token_type: "access".into(),
        };
        let token = sign_access_token(&claims, b"01234567890123456789012345678901").unwrap();
        assert!(verify_access_token(&token, b"01234567890123456789012345678901", 150).is_ok());
        assert!(verify_access_token(&token, b"11234567890123456789012345678901", 150).is_err());
        assert!(verify_access_token(&token, b"01234567890123456789012345678901", 200).is_err());
    }

    #[test]
    fn step_up_token_is_purpose_bound_and_expires() {
        let claims = StepUpClaims {
            account_id: "account".into(),
            device_id: "device".into(),
            challenge_id: "challenge".into(),
            purpose: "device_key_rotation".into(),
            operation_binding_hash: "binding".into(),
            expires_at_epoch_millis: 200,
            token_type: "step_up".into(),
        };
        let secret = b"01234567890123456789012345678901";
        let token = sign_step_up_token(&claims, secret).expect("step-up token");
        let verified = verify_step_up_token(&token, secret, 150).expect("valid step-up");
        assert_eq!(verified.purpose, "device_key_rotation");
        assert!(verify_step_up_token(&token, secret, 200).is_err());
    }

    #[test]
    fn permissions_digest_changes_for_every_permission() {
        let baseline = crate::SessionPermissions::default();
        let expected = permissions_digest(&baseline);
        let variants = [
            crate::SessionPermissions {
                remote_desktop: true,
                ..baseline
            },
            crate::SessionPermissions {
                input_control: true,
                ..baseline
            },
            crate::SessionPermissions {
                clipboard: true,
                ..baseline
            },
            crate::SessionPermissions {
                file_transfer: true,
                ..baseline
            },
            crate::SessionPermissions {
                unattended: true,
                ..baseline
            },
            crate::SessionPermissions {
                privacy_screen: true,
                ..baseline
            },
            crate::SessionPermissions {
                block_local_input: true,
                ..baseline
            },
            crate::SessionPermissions {
                require_prompt: false,
                ..baseline
            },
            crate::SessionPermissions {
                allow_relay: true,
                ..baseline
            },
        ];
        assert!(variants
            .iter()
            .all(|value| permissions_digest(value) != expected));
    }

    #[test]
    fn shared_http_canonical_vector_matches_all_server_bindings() {
        let vector: HttpCanonicalVector = serde_json::from_str(include_str!(
            "../../../test-vectors/http-canonical/rctl-api-input-v1.json"
        ))
        .expect("shared HTTP canonical vector");
        let canonical_body = canonical_json_bytes_from_slice(vector.body.as_bytes()).expect("JCS");
        assert_eq!(
            std::str::from_utf8(&canonical_body).expect("UTF-8"),
            vector.canonical_body
        );
        let body_hash = canonical_json_hash(vector.body.as_bytes()).expect("body hash");
        assert_eq!(hex_encode(&body_hash), vector.body_hash);
        assert_eq!(
            remote_protocol::canonical_request_target(&vector.request_target)
                .expect("request target"),
            vector.canonical_request_target
        );

        let api_input = canonical_api_request_bytes(
            &vector.method,
            &vector.request_target,
            &body_hash,
            &vector.request_id,
            &vector.device_id,
            &vector.account_id,
            vector.timestamp_epoch_millis,
            &vector.api_nonce,
        )
        .expect("API canonical");
        assert_eq!(sha256_hex(&api_input), vector.api_input_hash);
        assert_eq!(
            operation_binding_hash(
                &vector.account_id,
                &vector.device_id,
                &vector.purpose,
                &vector.method,
                &vector.request_target,
                &body_hash,
                &vector.request_id,
                vector.expires_at_epoch_millis,
            )
            .expect("operation binding"),
            vector.operation_binding_hash
        );
        let idempotency = canonical_idempotency_binding_bytes(
            &vector.account_id,
            &vector.device_id,
            &vector.method,
            &vector.request_target,
            &body_hash,
        )
        .expect("idempotency binding");
        assert_eq!(sha256_hex(&idempotency), vector.idempotency_binding_hash);
    }

    #[test]
    fn request_body_hash_follows_content_type_and_rejects_duplicate_json_keys() {
        let body = br#"{"z":1.0,"a":"text"}"#;
        assert_eq!(
            canonical_request_body_hash(body, Some("Application/JSON; charset=utf-8"))
                .expect("JSON hash"),
            canonical_json_hash(body).expect("JCS hash")
        );
        assert_eq!(
            canonical_request_body_hash(body, Some("application/octet-stream")).expect("raw hash"),
            sha256(body)
        );
        assert!(
            canonical_request_body_hash(br#"{"a":1,"a":2}"#, Some("application/json")).is_err()
        );
    }

    #[test]
    fn device_signature_accepts_canonical_equivalent_request_targets() {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        let body = br#"{"z":1.0,"a":"text"}"#;
        let signature = sign_device_request_for_test(
            &signing_key,
            "post",
            "/v1/a/./b/../devices?b=2&a=3&a=1",
            body,
            "request-1",
            "desktop-test",
            "account-1",
            42,
            "nonce-1",
        );
        assert!(verify_device_signature(
            &signing_key.verifying_key().to_bytes(),
            "POST",
            "/v1/a/devices?a=1&a=3&b=2",
            body,
            Some("application/json"),
            "request-1",
            "desktop-test",
            "account-1",
            42,
            "nonce-1",
            &signature,
        )
        .is_ok());
    }
}
