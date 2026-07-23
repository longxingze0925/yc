use crate::secret_store::{PersistentSecretStore, SecretPersistence, SecretStoreError};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use remote_crypto::{sha256, DeviceKeyPair};
use remote_protocol::{canonical_api_request_bytes, canonical_json_bytes};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroize;

const IDENTITY_STORE_KEY: &str = "device.identity.v1";

pub struct DeviceIdentity {
    device_id: String,
    key_pair: DeviceKeyPair,
    public_key_id: Option<String>,
    public_key_version: u32,
}

impl DeviceIdentity {
    pub fn generate() -> Self {
        Self {
            device_id: format!("desktop-{}", Uuid::new_v4().simple()),
            key_pair: DeviceKeyPair::generate(),
            public_key_id: None,
            public_key_version: 0,
        }
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.key_pair.public_key
    }

    pub fn encoded_public_key(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public_key())
    }

    pub fn public_key_id(&self) -> Option<&str> {
        self.public_key_id.as_deref()
    }

    pub const fn public_key_version(&self) -> u32 {
        self.public_key_version
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_api_request<T: Serialize>(
        &self,
        method: &str,
        path: &str,
        body: &T,
        request_id: &str,
        account_id: &str,
        timestamp_epoch_millis: u64,
        api_nonce: &str,
    ) -> Result<String, IdentityError> {
        let canonical_body = canonical_json_bytes(body).map_err(|_| IdentityError::Canonical)?;
        let body_hash = sha256(&canonical_body);
        let canonical = canonical_api_request_bytes(
            method,
            path,
            &body_hash,
            request_id,
            &self.device_id,
            account_id,
            timestamp_epoch_millis,
            api_nonce,
        )
        .map_err(|_| IdentityError::Canonical)?;
        Ok(URL_SAFE_NO_PAD.encode(self.key_pair.sign_canonical(&canonical)))
    }

    pub fn sign_canonical(&self, canonical_bytes: &[u8]) -> [u8; 64] {
        self.key_pair.sign_canonical(canonical_bytes)
    }
}

impl fmt::Debug for DeviceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceIdentity")
            .field("device_id", &self.device_id)
            .field("public_key", &self.encoded_public_key())
            .field("public_key_id", &self.public_key_id)
            .field("public_key_version", &self.public_key_version)
            .field("private_key", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    Store(SecretStoreError),
    InvalidRecord,
    Canonical,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "{error}"),
            Self::InvalidRecord => formatter.write_str("设备身份存储数据无效"),
            Self::Canonical => formatter.write_str("设备签名 canonical 编码失败"),
        }
    }
}

impl std::error::Error for IdentityError {}

impl From<SecretStoreError> for IdentityError {
    fn from(error: SecretStoreError) -> Self {
        Self::Store(error)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityLoadReport {
    pub created: bool,
    pub durably_persisted: bool,
}

pub struct DeviceIdentityManager {
    store: Arc<dyn PersistentSecretStore>,
    current: Option<Arc<DeviceIdentity>>,
}

impl DeviceIdentityManager {
    pub fn new(store: Arc<dyn PersistentSecretStore>) -> Self {
        Self {
            store,
            current: None,
        }
    }

    pub fn load_or_create(&mut self) -> Result<IdentityLoadReport, IdentityError> {
        if self.current.is_some() {
            return Ok(IdentityLoadReport {
                created: false,
                durably_persisted: self.store.persistence().is_durable(),
            });
        }
        if let Some(mut bytes) = self.store.load(IDENTITY_STORE_KEY)? {
            let mut record: IdentityRecord =
                serde_json::from_slice(&bytes).map_err(|_| IdentityError::InvalidRecord)?;
            bytes.zeroize();
            let mut private_key: [u8; 32] = URL_SAFE_NO_PAD
                .decode(&record.private_key)
                .map_err(|_| IdentityError::InvalidRecord)?
                .try_into()
                .map_err(|_| IdentityError::InvalidRecord)?;
            record.private_key.zeroize();
            let identity = DeviceIdentity {
                device_id: record.device_id,
                key_pair: DeviceKeyPair::from_private_key(private_key),
                public_key_id: record.public_key_id,
                public_key_version: record.public_key_version,
            };
            private_key.zeroize();
            self.current = Some(Arc::new(identity));
            return Ok(IdentityLoadReport {
                created: false,
                durably_persisted: self.store.persistence().is_durable(),
            });
        }

        let identity = DeviceIdentity::generate();
        let mut record = IdentityRecord {
            version: 1,
            device_id: identity.device_id.clone(),
            private_key: URL_SAFE_NO_PAD
                .encode(identity.key_pair.private_key_for_platform_crypto()),
            public_key_id: None,
            public_key_version: 0,
        };
        let mut bytes = serde_json::to_vec(&record).map_err(|_| IdentityError::InvalidRecord)?;
        let result = self.store.store(IDENTITY_STORE_KEY, &bytes);
        bytes.zeroize();
        record.private_key.zeroize();
        result?;
        self.current = Some(Arc::new(identity));
        Ok(IdentityLoadReport {
            created: true,
            durably_persisted: self.store.persistence() == SecretPersistence::DurablePlatformStore,
        })
    }

    pub fn current(&self) -> Option<&DeviceIdentity> {
        self.current.as_deref()
    }

    pub fn shared_current(&self) -> Option<Arc<DeviceIdentity>> {
        self.current.clone()
    }

    pub fn update_registration(
        &mut self,
        public_key_id: impl Into<String>,
        public_key_version: u32,
    ) -> Result<(), IdentityError> {
        let current = self.current.as_ref().ok_or(IdentityError::InvalidRecord)?;
        let public_key_id = public_key_id.into();
        if public_key_id.trim().is_empty() || public_key_version == 0 {
            return Err(IdentityError::InvalidRecord);
        }
        let mut private_key = *current.key_pair.private_key_for_platform_crypto();
        let mut record = IdentityRecord {
            version: 1,
            device_id: current.device_id.clone(),
            private_key: URL_SAFE_NO_PAD.encode(private_key),
            public_key_id: Some(public_key_id.clone()),
            public_key_version,
        };
        let mut bytes = serde_json::to_vec(&record).map_err(|_| IdentityError::InvalidRecord)?;
        let result = self.store.store(IDENTITY_STORE_KEY, &bytes);
        bytes.zeroize();
        record.private_key.zeroize();
        result?;
        self.current = Some(Arc::new(DeviceIdentity {
            device_id: record.device_id,
            key_pair: DeviceKeyPair::from_private_key(private_key),
            public_key_id: Some(public_key_id),
            public_key_version,
        }));
        private_key.zeroize();
        Ok(())
    }
}

impl fmt::Debug for DeviceIdentityManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceIdentityManager")
            .field("identity_loaded", &self.current.is_some())
            .field("private_key", &"<redacted>")
            .field("persistence", &self.store.persistence())
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
struct IdentityRecord {
    version: u16,
    device_id: String,
    private_key: String,
    #[serde(default)]
    public_key_id: Option<String>,
    #[serde(default)]
    public_key_version: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_store::ProcessSecretStore;
    use remote_crypto::verify_canonical_signature;
    use remote_protocol::CanonicalWriter;
    use serde_json::json;

    #[test]
    fn identity_round_trips_through_the_secret_store_abstraction() {
        let store = Arc::new(ProcessSecretStore::default());
        let mut first = DeviceIdentityManager::new(store.clone());
        let report = first.load_or_create().expect("create identity");
        assert!(report.created);
        assert!(!report.durably_persisted);
        let device_id = first.current().expect("identity").device_id().to_owned();
        let public_key = first.current().expect("identity").public_key();

        let mut second = DeviceIdentityManager::new(store);
        let report = second.load_or_create().expect("load identity");
        assert!(!report.created);
        assert_eq!(second.current().expect("identity").device_id(), device_id);
        assert_eq!(second.current().expect("identity").public_key(), public_key);
        second
            .update_registration("key-1", 1)
            .expect("persist registration");
        assert_eq!(
            second.current().expect("identity").public_key_id(),
            Some("key-1")
        );
    }

    #[test]
    fn signed_api_request_matches_the_frozen_canonical_order() {
        let identity = DeviceIdentity {
            device_id: "desktop-test".into(),
            key_pair: DeviceKeyPair::from_private_key([7; 32]),
            public_key_id: None,
            public_key_version: 0,
        };
        let body = json!({"z": 1.0, "a": "value"});
        let signature = identity
            .sign_api_request(
                "POST",
                "/v1/a/./b/../devices?b=2&a=3&a=1",
                &body,
                "request-1",
                "account-1",
                42,
                "nonce-1",
            )
            .expect("signature");

        let body_hash = sha256(&canonical_json_bytes(&body).expect("jcs"));
        let mut writer = CanonicalWriter::new("rctl-api-input-v1").expect("canonical");
        writer
            .push_str("method", "POST")
            .expect("method")
            .push_str("path", "/v1/a/devices?a=1&a=3&b=2")
            .expect("path")
            .push_field("body_hash", &body_hash)
            .expect("body hash")
            .push_str("request_id", "request-1")
            .expect("request")
            .push_str("device_id", "desktop-test")
            .expect("device")
            .push_str("account_id", "account-1")
            .expect("account")
            .push_u64("timestamp", 42)
            .expect("timestamp")
            .push_str("api_nonce", "nonce-1")
            .expect("nonce");
        let signature: [u8; 64] = URL_SAFE_NO_PAD
            .decode(signature)
            .expect("base64")
            .try_into()
            .expect("signature bytes");
        verify_canonical_signature(&identity.public_key(), &writer.finish(), &signature)
            .expect("signature verifies");
    }

    #[test]
    fn identity_debug_redacts_private_key() {
        let identity = DeviceIdentity {
            device_id: "desktop-test".into(),
            key_pair: DeviceKeyPair::from_private_key([7; 32]),
            public_key_id: None,
            public_key_version: 0,
        };
        let debug = format!("{identity:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("7, 7, 7"));
    }
}
