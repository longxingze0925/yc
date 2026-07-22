use crate::{RecordKey, RecordKind, Repository, StoreError, StoredRecord};
use std::collections::BTreeMap;

#[derive(Debug, Default)]
pub struct MemoryRepository {
    records: BTreeMap<RecordKey, StoredRecord>,
}

impl MemoryRepository {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

impl Repository for MemoryRepository {
    fn insert(&mut self, record: StoredRecord) -> Result<(), StoreError> {
        let key = record.key();
        if self.records.contains_key(&key) {
            return Err(StoreError::Duplicate(key));
        }
        self.records.insert(key, record);
        Ok(())
    }

    fn replace(&mut self, record: StoredRecord) -> Result<(), StoreError> {
        let key = record.key();
        if record.kind().is_append_only() {
            return Err(StoreError::Immutable(record.kind()));
        }
        if !self.records.contains_key(&key) {
            return Err(StoreError::NotFound(key));
        }
        self.records.insert(key, record);
        Ok(())
    }

    fn get(&self, key: &RecordKey) -> Result<Option<StoredRecord>, StoreError> {
        Ok(self.records.get(key).cloned())
    }

    fn list(&self, kind: RecordKind) -> Result<Vec<StoredRecord>, StoreError> {
        Ok(self
            .records
            .values()
            .filter(|record| record.kind() == kind)
            .cloned()
            .collect())
    }

    fn remove(&mut self, key: &RecordKey) -> Result<Option<StoredRecord>, StoreError> {
        if key.kind().is_append_only() {
            return Err(StoreError::Immutable(key.kind()));
        }
        Ok(self.records.remove(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccountRecord, AccountStatus, AuditLogRecord, JsonObject, PasswordHash};

    fn account() -> StoredRecord {
        StoredRecord::Account(AccountRecord {
            account_id: "account-1".to_owned(),
            email: "owner@example.test".to_owned(),
            display_name: "Owner".to_owned(),
            password_hash: PasswordHash("argon2id-hash".to_owned()),
            status: AccountStatus::Active,
            created_at_epoch_millis: 1,
            updated_at_epoch_millis: 1,
        })
    }

    #[test]
    fn inserts_reads_and_replaces_mutable_records() {
        let mut store = MemoryRepository::new();
        store.insert(account()).expect("insert");

        let key = RecordKey::new(RecordKind::Account, "account-1");
        assert_eq!(store.get(&key).expect("get"), Some(account()));

        let mut changed = match account() {
            StoredRecord::Account(record) => record,
            _ => unreachable!(),
        };
        changed.display_name = "Changed".to_owned();
        store
            .replace(StoredRecord::Account(changed.clone()))
            .expect("replace");

        assert_eq!(
            store.get(&key).expect("get changed"),
            Some(StoredRecord::Account(changed))
        );
    }

    #[test]
    fn duplicate_insert_is_rejected() {
        let mut store = MemoryRepository::new();
        store.insert(account()).expect("first insert");
        assert!(matches!(
            store.insert(account()),
            Err(StoreError::Duplicate(_))
        ));
    }

    #[test]
    fn append_only_records_cannot_be_replaced_or_removed() {
        let mut store = MemoryRepository::new();
        let audit = StoredRecord::AuditLog(AuditLogRecord {
            audit_id: "audit-1".to_owned(),
            actor_type: "system".to_owned(),
            actor_account_id: None,
            actor_device_id: None,
            actor_role: "none".to_owned(),
            actor_service: None,
            target_device_id: None,
            session_id: None,
            resource_type: None,
            resource_id: None,
            action: "session_failed".to_owned(),
            result: "failure".to_owned(),
            reason: Some("timeout".to_owned()),
            metadata: JsonObject::default(),
            actor_account_snapshot: None,
            actor_device_snapshot: None,
            target_device_snapshot: None,
            ip_address: None,
            user_agent: None,
            request_id: None,
            created_at_epoch_millis: 1,
        });
        let key = audit.key();
        store.insert(audit.clone()).expect("append audit");

        assert_eq!(
            store.replace(audit),
            Err(StoreError::Immutable(RecordKind::AuditLog))
        );
        assert_eq!(
            store.remove(&key),
            Err(StoreError::Immutable(RecordKind::AuditLog))
        );
    }
}
