use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use zeroize::Zeroize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretPersistence {
    ProcessOnly,
    DurablePlatformStore,
}

impl SecretPersistence {
    pub const fn is_durable(self) -> bool {
        matches!(self, Self::DurablePlatformStore)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretStoreError {
    Unavailable(&'static str),
    Backend(String),
    InvalidData,
}

impl fmt::Display for SecretStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(reason) => write!(formatter, "安全存储不可用: {reason}"),
            Self::Backend(_) => formatter.write_str("安全存储操作失败"),
            Self::InvalidData => formatter.write_str("安全存储中的数据无效"),
        }
    }
}

impl std::error::Error for SecretStoreError {}

pub trait PersistentSecretStore: Send + Sync {
    fn persistence(&self) -> SecretPersistence;
    fn load(&self, key: &str) -> Result<Option<Vec<u8>>, SecretStoreError>;
    fn store(&self, key: &str, value: &[u8]) -> Result<(), SecretStoreError>;
    fn delete(&self, key: &str) -> Result<(), SecretStoreError>;
}

#[derive(Debug, Clone, Default)]
pub struct ProcessSecretStore {
    values: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
}

impl PersistentSecretStore for ProcessSecretStore {
    fn persistence(&self) -> SecretPersistence {
        SecretPersistence::ProcessOnly
    }

    fn load(&self, key: &str) -> Result<Option<Vec<u8>>, SecretStoreError> {
        Ok(self
            .values
            .lock()
            .map_err(|_| SecretStoreError::Backend("secret store lock poisoned".into()))?
            .get(key)
            .cloned())
    }

    fn store(&self, key: &str, value: &[u8]) -> Result<(), SecretStoreError> {
        let replaced = self
            .values
            .lock()
            .map_err(|_| SecretStoreError::Backend("secret store lock poisoned".into()))?
            .insert(key.to_owned(), value.to_vec());
        if let Some(mut replaced) = replaced {
            replaced.zeroize();
        }
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<(), SecretStoreError> {
        if let Some(mut value) = self
            .values
            .lock()
            .map_err(|_| SecretStoreError::Backend("secret store lock poisoned".into()))?
            .remove(key)
        {
            value.zeroize();
        }
        Ok(())
    }
}

pub struct SecretText(String);

impl SecretText {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretText(<redacted>)")
    }
}

impl Drop for SecretText {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct AccountTokens {
    pub account_id: String,
    access_token: SecretText,
    refresh_token: SecretText,
    pub access_token_expires_at_epoch_millis: u64,
    pub refresh_token_expires_at_epoch_millis: u64,
}

impl AccountTokens {
    pub fn new(
        account_id: String,
        access_token: String,
        refresh_token: String,
        access_token_expires_at_epoch_millis: u64,
        refresh_token_expires_at_epoch_millis: u64,
    ) -> Self {
        Self {
            account_id,
            access_token: SecretText::new(access_token),
            refresh_token: SecretText::new(refresh_token),
            access_token_expires_at_epoch_millis,
            refresh_token_expires_at_epoch_millis,
        }
    }

    pub fn access_token(&self, now_epoch_millis: u64) -> Option<&str> {
        (self.access_token_expires_at_epoch_millis > now_epoch_millis)
            .then(|| self.access_token.expose())
    }

    pub fn refresh_token(&self, now_epoch_millis: u64) -> Option<&str> {
        (self.refresh_token_expires_at_epoch_millis > now_epoch_millis)
            .then(|| self.refresh_token.expose())
    }
}

impl fmt::Debug for AccountTokens {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountTokens")
            .field("account_id", &self.account_id)
            .field("access_token", &"<redacted>")
            .field("refresh_token", &"<redacted>")
            .field(
                "access_token_expires_at_epoch_millis",
                &self.access_token_expires_at_epoch_millis,
            )
            .field(
                "refresh_token_expires_at_epoch_millis",
                &self.refresh_token_expires_at_epoch_millis,
            )
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenInstallReport {
    pub durably_persisted: bool,
}

pub struct AccountTokenManager {
    store: Arc<dyn PersistentSecretStore>,
    current: Option<AccountTokens>,
}

impl AccountTokenManager {
    const STORE_KEY: &'static str = "account.tokens.v1";

    pub fn new(store: Arc<dyn PersistentSecretStore>) -> Self {
        Self {
            store,
            current: None,
        }
    }

    pub fn restore(&mut self) -> Result<bool, SecretStoreError> {
        let Some(mut bytes) = self.store.load(Self::STORE_KEY)? else {
            return Ok(false);
        };
        let record: TokenRecord =
            serde_json::from_slice(&bytes).map_err(|_| SecretStoreError::InvalidData)?;
        bytes.zeroize();
        self.current = Some(record.into());
        Ok(true)
    }

    pub fn install(
        &mut self,
        tokens: AccountTokens,
    ) -> Result<TokenInstallReport, SecretStoreError> {
        let mut record = TokenRecord::from(&tokens);
        let mut bytes = serde_json::to_vec(&record).map_err(|_| SecretStoreError::InvalidData)?;
        let result = self.store.store(Self::STORE_KEY, &bytes);
        bytes.zeroize();
        record.access_token.zeroize();
        record.refresh_token.zeroize();
        result?;
        self.current = Some(tokens);
        Ok(TokenInstallReport {
            durably_persisted: self.store.persistence().is_durable(),
        })
    }

    pub fn current(&self) -> Option<&AccountTokens> {
        self.current.as_ref()
    }

    pub fn clear(&mut self) -> Result<(), SecretStoreError> {
        self.current = None;
        self.store.delete(Self::STORE_KEY)
    }
}

impl fmt::Debug for AccountTokenManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountTokenManager")
            .field("has_current_tokens", &self.current.is_some())
            .field("tokens", &"<redacted>")
            .field("persistence", &self.store.persistence())
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
struct TokenRecord {
    account_id: String,
    access_token: String,
    refresh_token: String,
    access_token_expires_at_epoch_millis: u64,
    refresh_token_expires_at_epoch_millis: u64,
}

impl From<&AccountTokens> for TokenRecord {
    fn from(tokens: &AccountTokens) -> Self {
        Self {
            account_id: tokens.account_id.clone(),
            access_token: tokens.access_token.expose().to_owned(),
            refresh_token: tokens.refresh_token.expose().to_owned(),
            access_token_expires_at_epoch_millis: tokens.access_token_expires_at_epoch_millis,
            refresh_token_expires_at_epoch_millis: tokens.refresh_token_expires_at_epoch_millis,
        }
    }
}

impl From<TokenRecord> for AccountTokens {
    fn from(record: TokenRecord) -> Self {
        Self::new(
            record.account_id,
            record.access_token,
            record.refresh_token,
            record.access_token_expires_at_epoch_millis,
            record.refresh_token_expires_at_epoch_millis,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens() -> AccountTokens {
        AccountTokens::new(
            "account-1".into(),
            "access-private-value".into(),
            "refresh-private-value".into(),
            2_000,
            3_000,
        )
    }

    #[test]
    fn tokens_stay_in_memory_and_use_the_persistence_abstraction() {
        let store = Arc::new(ProcessSecretStore::default());
        let mut first = AccountTokenManager::new(store.clone());
        let report = first.install(tokens()).expect("install");
        assert!(!report.durably_persisted);

        let mut second = AccountTokenManager::new(store);
        assert!(second.restore().expect("restore"));
        let restored = second.current().expect("tokens");
        assert_eq!(restored.account_id, "account-1");
        assert_eq!(restored.access_token(1_000), Some("access-private-value"));
        assert_eq!(restored.access_token(2_000), None);
    }

    #[test]
    fn token_debug_output_never_contains_token_material() {
        let tokens = tokens();
        let debug = format!("{tokens:?}");
        assert!(!debug.contains("access-private-value"));
        assert!(!debug.contains("refresh-private-value"));
        assert!(debug.contains("<redacted>"));
    }
}
