use std::{io, net::SocketAddr, time::Duration};

use remote_protocol::SessionRole;
use thiserror::Error;
use tokio::net::UdpSocket;
use zeroize::Zeroize;

use crate::{
    observe_result_binding_hash, validate_observe_authorization, validate_observe_result,
    BindingError, EphemeralToken, ObserveAuthorization, ValidatedObserveResult,
};

const OBSERVE_REQUEST_MAGIC: [u8; 4] = *b"RCO1";
const OBSERVE_RESPONSE_MAGIC: [u8; 4] = *b"RCO2";
const MAX_OBSERVE_DATAGRAM_BYTES: usize = 4_096;
const MAX_TOKEN_BYTES: usize = 2_048;
const MAX_TEXT_BYTES: usize = 512;

#[derive(Debug, Error)]
pub enum ObserveError {
    #[error("observe binding validation failed: {0:?}")]
    Binding(BindingError),
    #[error("malformed UDP observe packet")]
    MalformedPacket,
    #[error("UDP observe packet exceeds the size limit")]
    PacketTooLarge,
    #[error("UDP observe response came from an unexpected endpoint")]
    UnexpectedResponder,
    #[error("UDP observe timed out")]
    Timeout,
    #[error("UDP observe I/O failed")]
    Io,
    #[error("observe result ID generation failed")]
    ResultIdUnavailable,
}

impl From<BindingError> for ObserveError {
    fn from(value: BindingError) -> Self {
        Self::Binding(value)
    }
}

/// Handles one authorized UDP observe request. `verify_token` is the service
/// boundary for validating the signal-server token signature/HMAC. The
/// observed endpoint is always derived from this socket's `recv_from` result.
pub async fn handle_udp_observe_once<V, G>(
    socket: &UdpSocket,
    now_epoch_millis: u64,
    verify_token: V,
    generate_result_id: G,
) -> Result<ValidatedObserveResult, ObserveError>
where
    V: FnOnce(&ObserveAuthorization) -> Result<(), BindingError>,
    G: FnOnce() -> Result<String, ObserveError>,
{
    let mut packet = vec![0_u8; MAX_OBSERVE_DATAGRAM_BYTES + 1];
    let (packet_len, peer) = socket
        .recv_from(&mut packet)
        .await
        .map_err(|_| ObserveError::Io)?;
    if packet_len > MAX_OBSERVE_DATAGRAM_BYTES {
        packet.zeroize();
        return Err(ObserveError::PacketTooLarge);
    }
    let authorization = decode_observe_request(&packet[..packet_len]);
    packet.zeroize();
    let authorization = authorization?;
    validate_observe_authorization(&authorization, now_epoch_millis)?;
    verify_token(&authorization)?;

    let observe_result_id = generate_result_id()?;
    if observe_result_id.is_empty() || observe_result_id.len() > MAX_TEXT_BYTES {
        return Err(ObserveError::ResultIdUnavailable);
    }
    let mut result = ValidatedObserveResult {
        session_id: authorization.session_id,
        device_id: authorization.device_id.clone(),
        role: authorization.role,
        local_socket_nonce: authorization.local_socket_nonce,
        observed_endpoint: peer.to_string(),
        observe_result_id,
        binding_hash: [0; 32],
        expires_at_epoch_millis: authorization.expires_at_epoch_millis(),
    };
    result.binding_hash = observe_result_binding_hash(&result)?;
    let response = encode_observe_response(&result)?;
    socket
        .send_to(&response, peer)
        .await
        .map_err(|_| ObserveError::Io)?;
    Ok(result)
}

/// Uses the caller-owned UDP socket for observe and leaves it available for a
/// subsequent P2P probe and QUIC adoption.
pub async fn request_udp_observe(
    socket: &UdpSocket,
    server: SocketAddr,
    authorization: &ObserveAuthorization,
    now_epoch_millis: u64,
    timeout: Duration,
) -> Result<ValidatedObserveResult, ObserveError> {
    validate_observe_authorization(authorization, now_epoch_millis)?;
    let mut request = encode_observe_request(authorization)?;
    let sent = socket
        .send_to(&request, server)
        .await
        .map_err(|_| ObserveError::Io)?;
    request.zeroize();
    if sent == 0 {
        return Err(ObserveError::Io);
    }

    let mut response = vec![0_u8; MAX_OBSERVE_DATAGRAM_BYTES + 1];
    let (response_len, responder) = tokio::time::timeout(timeout, socket.recv_from(&mut response))
        .await
        .map_err(|_| ObserveError::Timeout)?
        .map_err(|_| ObserveError::Io)?;
    if responder != server {
        return Err(ObserveError::UnexpectedResponder);
    }
    if response_len > MAX_OBSERVE_DATAGRAM_BYTES {
        return Err(ObserveError::PacketTooLarge);
    }
    let result = decode_observe_response(&response[..response_len])?;
    validate_observe_result(&result, authorization, now_epoch_millis)?;
    Ok(result)
}

pub fn udp_socket_into_std(socket: UdpSocket) -> Result<std::net::UdpSocket, ObserveError> {
    socket.into_std().map_err(|_| ObserveError::Io)
}

fn encode_observe_request(authorization: &ObserveAuthorization) -> Result<Vec<u8>, ObserveError> {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(&OBSERVE_REQUEST_MAGIC);
    bytes.extend_from_slice(&authorization.session_id.to_be_bytes());
    push_text(&mut bytes, &authorization.device_id)?;
    bytes.push(role_byte(authorization.role));
    bytes.extend_from_slice(&authorization.local_socket_nonce);
    bytes.extend_from_slice(&authorization.expires_at_epoch_millis().to_be_bytes());
    bytes.extend_from_slice(authorization.binding_hash());
    push_bytes(
        &mut bytes,
        authorization.token().expose_for_transport(),
        MAX_TOKEN_BYTES,
    )?;
    Ok(bytes)
}

fn decode_observe_request(bytes: &[u8]) -> Result<ObserveAuthorization, ObserveError> {
    let mut reader = PacketReader::new(bytes);
    reader.expect_magic(OBSERVE_REQUEST_MAGIC)?;
    let session_id = reader.u128()?;
    let device_id = reader.text(MAX_TEXT_BYTES)?;
    let role = decode_role(reader.u8()?)?;
    let local_socket_nonce = reader.array()?;
    let expires_at_epoch_millis = reader.u64()?;
    let binding_hash = reader.array()?;
    let token = EphemeralToken::new(reader.bytes(MAX_TOKEN_BYTES)?);
    reader.finish()?;
    Ok(ObserveAuthorization {
        session_id,
        device_id,
        role,
        local_socket_nonce,
        token,
        binding_hash,
        expires_at_epoch_millis,
    })
}

fn encode_observe_response(result: &ValidatedObserveResult) -> Result<Vec<u8>, ObserveError> {
    let mut bytes = Vec::with_capacity(256);
    bytes.extend_from_slice(&OBSERVE_RESPONSE_MAGIC);
    bytes.extend_from_slice(&result.session_id.to_be_bytes());
    push_text(&mut bytes, &result.device_id)?;
    bytes.push(role_byte(result.role));
    bytes.extend_from_slice(&result.local_socket_nonce);
    push_text(&mut bytes, &result.observed_endpoint)?;
    push_text(&mut bytes, &result.observe_result_id)?;
    bytes.extend_from_slice(result.binding_hash());
    bytes.extend_from_slice(&result.expires_at_epoch_millis().to_be_bytes());
    Ok(bytes)
}

fn decode_observe_response(bytes: &[u8]) -> Result<ValidatedObserveResult, ObserveError> {
    let mut reader = PacketReader::new(bytes);
    reader.expect_magic(OBSERVE_RESPONSE_MAGIC)?;
    let result = ValidatedObserveResult {
        session_id: reader.u128()?,
        device_id: reader.text(MAX_TEXT_BYTES)?,
        role: decode_role(reader.u8()?)?,
        local_socket_nonce: reader.array()?,
        observed_endpoint: reader.text(MAX_TEXT_BYTES)?,
        observe_result_id: reader.text(MAX_TEXT_BYTES)?,
        binding_hash: reader.array()?,
        expires_at_epoch_millis: reader.u64()?,
    };
    reader.finish()?;
    Ok(result)
}

fn role_byte(role: SessionRole) -> u8 {
    match role {
        SessionRole::Controller => 1,
        SessionRole::Controlled => 2,
    }
}

fn decode_role(value: u8) -> Result<SessionRole, ObserveError> {
    match value {
        1 => Ok(SessionRole::Controller),
        2 => Ok(SessionRole::Controlled),
        _ => Err(ObserveError::MalformedPacket),
    }
}

fn push_text(bytes: &mut Vec<u8>, value: &str) -> Result<(), ObserveError> {
    push_bytes(bytes, value.as_bytes(), MAX_TEXT_BYTES)
}

fn push_bytes(bytes: &mut Vec<u8>, value: &[u8], max: usize) -> Result<(), ObserveError> {
    if value.is_empty() || value.len() > max {
        return Err(ObserveError::MalformedPacket);
    }
    let len = u16::try_from(value.len()).map_err(|_| ObserveError::PacketTooLarge)?;
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(value);
    if bytes.len() > MAX_OBSERVE_DATAGRAM_BYTES {
        return Err(ObserveError::PacketTooLarge);
    }
    Ok(())
}

struct PacketReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> PacketReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn expect_magic(&mut self, expected: [u8; 4]) -> Result<(), ObserveError> {
        if self.take(4)? != expected {
            return Err(ObserveError::MalformedPacket);
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, ObserveError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ObserveError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| ObserveError::MalformedPacket)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, ObserveError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| ObserveError::MalformedPacket)?,
        ))
    }

    fn u128(&mut self) -> Result<u128, ObserveError> {
        Ok(u128::from_be_bytes(
            self.take(16)?
                .try_into()
                .map_err(|_| ObserveError::MalformedPacket)?,
        ))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ObserveError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ObserveError::MalformedPacket)
    }

    fn text(&mut self, max: usize) -> Result<String, ObserveError> {
        String::from_utf8(self.bytes(max)?).map_err(|_| ObserveError::MalformedPacket)
    }

    fn bytes(&mut self, max: usize) -> Result<Vec<u8>, ObserveError> {
        let len = usize::from(self.u16()?);
        if len == 0 || len > max {
            return Err(ObserveError::MalformedPacket);
        }
        Ok(self.take(len)?.to_vec())
    }

    fn finish(self) -> Result<(), ObserveError> {
        if self.offset != self.bytes.len() {
            return Err(ObserveError::MalformedPacket);
        }
        Ok(())
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ObserveError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(ObserveError::MalformedPacket)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ObserveError::MalformedPacket)?;
        self.offset = end;
        Ok(value)
    }
}

impl From<io::Error> for ObserveError {
    fn from(_: io::Error) -> Self {
        Self::Io
    }
}

#[cfg(test)]
mod tests {
    use remote_protocol::ObserveTokenIssued;

    use super::*;
    use crate::observe_token_binding_hash;

    fn authorization(now: u64) -> ObserveAuthorization {
        let expires_at = now + 20_000;
        let mut issued = ObserveTokenIssued {
            session_id: 77,
            device_id: "controller".to_owned(),
            role: SessionRole::Controller,
            local_socket_nonce: [3; 32],
            observe_token: b"observe-token".to_vec(),
            observe_token_binding_hash: [0; 32],
            expires_at_epoch_millis: expires_at,
        };
        issued.observe_token_binding_hash = observe_token_binding_hash(
            issued.session_id,
            &issued.device_id,
            issued.role,
            &issued.local_socket_nonce,
            expires_at,
        )
        .expect("binding");
        ObserveAuthorization::from_issued(issued, now).expect("authorization")
    }

    #[tokio::test]
    async fn udp_observe_uses_recv_from_endpoint_and_validates_response() {
        let now = 10_000;
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("server");
        let server_addr = server.local_addr().expect("server address");
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
        let client_addr = client.local_addr().expect("client address");
        let authorization = authorization(now);

        let server_task = tokio::spawn(async move {
            handle_udp_observe_once(
                &server,
                now,
                |request| {
                    if request.token().constant_time_eq(b"observe-token") {
                        Ok(())
                    } else {
                        Err(BindingError::TokenSignatureInvalid)
                    }
                },
                || Ok("observe-result-1".to_owned()),
            )
            .await
            .expect("observe handled")
        });

        let result = request_udp_observe(
            &client,
            server_addr,
            &authorization,
            now,
            Duration::from_secs(2),
        )
        .await
        .expect("observe result");
        let server_result = server_task.await.expect("server task");
        assert_eq!(result.observed_endpoint, client_addr.to_string());
        assert_eq!(server_result.observed_endpoint, client_addr.to_string());
        assert_ne!(result.observed_endpoint, "203.0.113.10:443");
    }
}
