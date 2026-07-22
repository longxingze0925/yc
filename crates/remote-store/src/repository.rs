use crate::{RecordKey, RecordKind, StoredRecord};
use std::fmt;

pub trait Repository {
    fn insert(&mut self, record: StoredRecord) -> Result<(), StoreError>;

    fn replace(&mut self, record: StoredRecord) -> Result<(), StoreError>;

    fn get(&self, key: &RecordKey) -> Result<Option<StoredRecord>, StoreError>;

    fn list(&self, kind: RecordKind) -> Result<Vec<StoredRecord>, StoreError>;

    fn remove(&mut self, key: &RecordKey) -> Result<Option<StoredRecord>, StoreError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    Duplicate(RecordKey),
    NotFound(RecordKey),
    Immutable(RecordKind),
    Backend(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate(key) => write!(formatter, "record already exists: {key:?}"),
            Self::NotFound(key) => write!(formatter, "record not found: {key:?}"),
            Self::Immutable(kind) => write!(formatter, "record kind is append-only: {kind:?}"),
            Self::Backend(message) => write!(formatter, "store backend failed: {message}"),
        }
    }
}

impl std::error::Error for StoreError {}
