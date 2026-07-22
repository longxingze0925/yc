use std::fmt;

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Number, Value};

pub const CANONICAL_LENGTH_BYTES: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalError {
    NameTooLong,
    ValueTooLong,
    JsonCanonicalization,
    InvalidHttpMethod,
    InvalidRequestTarget,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CanonicalWriter {
    bytes: Vec<u8>,
}

impl CanonicalWriter {
    pub fn new(domain: &str) -> Result<Self, CanonicalError> {
        let mut writer = Self::default();
        writer.push_field("domain", domain.as_bytes())?;
        Ok(writer)
    }

    pub fn without_domain() -> Self {
        Self::default()
    }

    pub fn push_field(&mut self, name: &str, value: &[u8]) -> Result<&mut Self, CanonicalError> {
        let name_len = u32::try_from(name.len()).map_err(|_| CanonicalError::NameTooLong)?;
        let value_len = u32::try_from(value.len()).map_err(|_| CanonicalError::ValueTooLong)?;
        self.bytes.extend_from_slice(&name_len.to_be_bytes());
        self.bytes.extend_from_slice(name.as_bytes());
        self.bytes.extend_from_slice(&value_len.to_be_bytes());
        self.bytes.extend_from_slice(value);
        Ok(self)
    }

    pub fn push_str(&mut self, name: &str, value: &str) -> Result<&mut Self, CanonicalError> {
        self.push_field(name, value.as_bytes())
    }

    pub fn push_optional_str(
        &mut self,
        name: &str,
        value: Option<&str>,
    ) -> Result<&mut Self, CanonicalError> {
        self.push_field(name, value.unwrap_or_default().as_bytes())
    }

    pub fn push_bool(&mut self, name: &str, value: bool) -> Result<&mut Self, CanonicalError> {
        self.push_field(name, &[u8::from(value)])
    }

    pub fn push_u16(&mut self, name: &str, value: u16) -> Result<&mut Self, CanonicalError> {
        self.push_field(name, &value.to_be_bytes())
    }

    pub fn push_u32(&mut self, name: &str, value: u32) -> Result<&mut Self, CanonicalError> {
        self.push_field(name, &value.to_be_bytes())
    }

    pub fn push_u64(&mut self, name: &str, value: u64) -> Result<&mut Self, CanonicalError> {
        self.push_field(name, &value.to_be_bytes())
    }

    pub fn push_u128(&mut self, name: &str, value: u128) -> Result<&mut Self, CanonicalError> {
        self.push_field(name, &value.to_be_bytes())
    }

    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    serde_json_canonicalizer::to_vec(value).map_err(|_| CanonicalError::JsonCanonicalization)
}

pub fn canonical_json_bytes_from_slice(bytes: &[u8]) -> Result<Vec<u8>, CanonicalError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = UniqueJsonValue::deserialize(&mut deserializer)
        .map_err(|_| CanonicalError::JsonCanonicalization)?;
    deserializer
        .end()
        .map_err(|_| CanonicalError::JsonCanonicalization)?;
    canonical_json_bytes(&value.0)
}

pub fn canonical_request_target(value: &str) -> Result<String, CanonicalError> {
    if value.is_empty()
        || !value.starts_with('/')
        || !value.is_ascii()
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'\\' || byte == b'#')
    {
        return Err(CanonicalError::InvalidRequestTarget);
    }

    let (path, query) = value
        .split_once('?')
        .map_or((value, None), |(path, query)| (path, Some(query)));
    let normalized_path = remove_dot_segments(&normalize_path(path)?);
    if normalized_path.is_empty() || !normalized_path.starts_with('/') {
        return Err(CanonicalError::InvalidRequestTarget);
    }

    let Some(query) = query else {
        return Ok(normalized_path);
    };
    if query.is_empty() {
        return Ok(normalized_path);
    }
    if query.as_bytes().contains(&b'+') {
        return Err(CanonicalError::InvalidRequestTarget);
    }

    let mut pairs = query
        .split('&')
        .map(|pair| {
            if pair.is_empty() {
                return Err(CanonicalError::InvalidRequestTarget);
            }
            let (key, value, had_equals) = pair
                .split_once('=')
                .map_or((pair, "", false), |(key, value)| (key, value, true));
            if key.is_empty() {
                return Err(CanonicalError::InvalidRequestTarget);
            }
            Ok((
                normalize_query_component(key)?,
                normalize_query_component(value)?,
                had_equals,
            ))
        })
        .collect::<Result<Vec<_>, CanonicalError>>()?;
    pairs.sort_unstable();

    let mut output = normalized_path;
    output.push('?');
    for (index, (key, value, had_equals)) in pairs.into_iter().enumerate() {
        if index != 0 {
            output.push('&');
        }
        output.push_str(&key);
        if had_equals {
            output.push('=');
            output.push_str(&value);
        }
    }
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
pub fn canonical_api_request_bytes(
    method: &str,
    request_target: &str,
    body_hash: &[u8; 32],
    request_id: &str,
    device_id: &str,
    account_id: &str,
    timestamp_epoch_millis: u64,
    api_nonce: &str,
) -> Result<Vec<u8>, CanonicalError> {
    let method = canonical_http_method(method)?;
    let request_target = canonical_request_target(request_target)?;
    let mut writer = CanonicalWriter::new("rctl-api-input-v1")?;
    writer
        .push_str("method", &method)?
        .push_str("path", &request_target)?
        .push_field("body_hash", body_hash)?
        .push_str("request_id", request_id)?
        .push_str("device_id", device_id)?
        .push_str("account_id", account_id)?
        .push_u64("timestamp", timestamp_epoch_millis)?
        .push_str("api_nonce", api_nonce)?;
    Ok(writer.finish())
}

#[allow(clippy::too_many_arguments)]
pub fn canonical_operation_binding_bytes(
    account_id: &str,
    device_id: &str,
    purpose: &str,
    method: &str,
    request_target: &str,
    body_hash: &[u8; 32],
    request_id: &str,
    expires_at_epoch_millis: u64,
) -> Result<Vec<u8>, CanonicalError> {
    let method = canonical_http_method(method)?;
    let request_target = canonical_request_target(request_target)?;
    let mut writer = CanonicalWriter::new("rctl-operation-binding-v1")?;
    writer
        .push_str("account_id", account_id)?
        .push_str("device_id", device_id)?
        .push_str("purpose", purpose)?
        .push_str("method", &method)?
        .push_str("path", &request_target)?
        .push_field("body_hash", body_hash)?
        .push_str("request_id", request_id)?
        .push_u64("expires_at_epoch_millis", expires_at_epoch_millis)?;
    Ok(writer.finish())
}

pub fn canonical_idempotency_binding_bytes(
    account_id: &str,
    device_id: &str,
    method: &str,
    request_target: &str,
    body_hash: &[u8; 32],
) -> Result<Vec<u8>, CanonicalError> {
    let method = canonical_http_method(method)?;
    let request_target = canonical_request_target(request_target)?;
    let mut writer = CanonicalWriter::new("rctl-idempotency-binding-v1")?;
    writer
        .push_str("account_id", account_id)?
        .push_str("device_id", device_id)?
        .push_str("method", &method)?
        .push_str("path", &request_target)?
        .push_field("body_hash", body_hash)?;
    Ok(writer.finish())
}

fn canonical_http_method(method: &str) -> Result<String, CanonicalError> {
    if method.is_empty()
        || !method.is_ascii()
        || !method.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
    {
        return Err(CanonicalError::InvalidHttpMethod);
    }
    Ok(method.to_ascii_uppercase())
}

fn normalize_path(path: &str) -> Result<String, CanonicalError> {
    normalize_percent_encoding(path, |byte| {
        is_unreserved(byte)
            || matches!(
                byte,
                b'/' | b':'
                    | b'@'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
            )
    })
}

fn normalize_query_component(value: &str) -> Result<String, CanonicalError> {
    normalize_percent_encoding(value, is_unreserved)
}

fn normalize_percent_encoding(
    value: &str,
    is_allowed_raw: impl Fn(u8) -> bool,
) -> Result<String, CanonicalError> {
    let bytes = value.as_bytes();
    let mut output = String::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len() {
                return Err(CanonicalError::InvalidRequestTarget);
            }
            let high = hex_nibble(bytes[index + 1]).ok_or(CanonicalError::InvalidRequestTarget)?;
            let low = hex_nibble(bytes[index + 2]).ok_or(CanonicalError::InvalidRequestTarget)?;
            let decoded = (high << 4) | low;
            if is_unreserved(decoded) {
                output.push(char::from(decoded));
            } else {
                push_percent_encoded(&mut output, decoded);
            }
            index += 3;
            continue;
        }
        if is_allowed_raw(byte) {
            output.push(char::from(byte));
        } else {
            push_percent_encoded(&mut output, byte);
        }
        index += 1;
    }
    Ok(output)
}

fn remove_dot_segments(value: &str) -> String {
    let mut input = value.to_owned();
    let mut output = String::with_capacity(value.len());
    while !input.is_empty() {
        if let Some(rest) = input
            .strip_prefix("../")
            .or_else(|| input.strip_prefix("./"))
        {
            input = rest.to_owned();
        } else if let Some(rest) = input.strip_prefix("/./") {
            input = format!("/{rest}");
        } else if input == "/." {
            input = "/".to_owned();
        } else if let Some(rest) = input.strip_prefix("/../") {
            input = format!("/{rest}");
            remove_last_path_segment(&mut output);
        } else if input == "/.." {
            input = "/".to_owned();
            remove_last_path_segment(&mut output);
        } else if input == "." || input == ".." {
            input.clear();
        } else {
            let segment_end = if let Some(rest) = input.strip_prefix('/') {
                rest.find('/').map_or(input.len(), |index| index + 1)
            } else {
                input.find('/').unwrap_or(input.len())
            };
            output.push_str(&input[..segment_end]);
            input.drain(..segment_end);
        }
    }
    output
}

fn remove_last_path_segment(output: &mut String) {
    output.truncate(output.rfind('/').unwrap_or(0));
}

const fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn push_percent_encoded(output: &mut String, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    output.push('%');
    output.push(char::from(HEX[usize::from(byte >> 4)]));
    output.push(char::from(HEX[usize::from(byte & 0x0f)]));
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

struct UniqueJsonValue(Value);

impl<'de> Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueJsonValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<UniqueJsonValue>()? {
            values.push(value.0);
        }
        Ok(UniqueJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom("duplicate JSON object key"));
            }
            let value = object.next_value::<UniqueJsonValue>()?;
            values.insert(key, value.0);
        }
        Ok(UniqueJsonValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn length_prefixed_vector_is_stable() {
        let mut writer = CanonicalWriter::new("rctl-test-v1").expect("canonical");
        writer
            .push_u16("version", 1)
            .expect("version")
            .push_optional_str("relay_node_id", None)
            .expect("nullable");

        assert_eq!(
            hex(&writer.finish()),
            "00000006646f6d61696e0000000c7263746c2d746573742d76310000000776657273696f6e0000000200010000000d72656c61795f6e6f64655f696400000000"
        );
    }

    #[test]
    fn json_uses_rfc8785_key_and_number_canonicalization() {
        let canonical = canonical_json_bytes(&json!({"z": 1.0, "a": "text"})).expect("jcs");

        assert_eq!(canonical, br#"{"a":"text","z":1}"#);
    }

    #[test]
    fn raw_json_rejects_duplicate_keys_at_every_depth() {
        assert!(canonical_json_bytes_from_slice(br#"{"a":1,"a":2}"#).is_err());
        assert!(canonical_json_bytes_from_slice(br#"{"a":{"b":1,"b":2}}"#).is_err());
        assert!(canonical_json_bytes_from_slice(br#"{"a":1} trailing"#).is_err());
        assert_eq!(
            canonical_json_bytes_from_slice(br#"{"z":1.0,"a":null}"#).expect("JCS"),
            br#"{"a":null,"z":1}"#
        );
    }

    #[test]
    fn request_target_removes_dot_segments_and_sorts_encoded_query_pairs() {
        assert_eq!(
            canonical_request_target("/v1/a/./b/../c/%7euser?b=2&a=3&a=1&empty&space=%20&slash=/")
                .expect("canonical target"),
            "/v1/a/c/~user?a=1&a=3&b=2&empty&slash=%2F&space=%20"
        );
        assert_eq!(
            canonical_request_target("/v1/a/%2e%2E/b?reserved=%2f&tilde=%7e")
                .expect("encoded dot segment"),
            "/v1/b?reserved=%2F&tilde=~"
        );
        assert_eq!(
            canonical_request_target("/v1/x?a=&a").expect("empty value forms"),
            "/v1/x?a&a="
        );
    }

    #[test]
    fn request_target_rejects_ambiguous_or_invalid_input() {
        for invalid in [
            "v1/devices",
            "/v1/devices?name=a+b",
            "/v1/devices?bad=%",
            "/v1/devices?a&&b=1",
            "/v1/devices?=empty-key",
            "/v1/devices#fragment",
            "/v1\\devices",
            "/v1/设备",
        ] {
            assert_eq!(
                canonical_request_target(invalid),
                Err(CanonicalError::InvalidRequestTarget),
                "{invalid}"
            );
        }
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
