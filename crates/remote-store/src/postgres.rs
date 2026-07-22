use crate::{RecordKey, RecordKind, Repository, StoreError, StoredRecord};

pub trait PostgresExecutor {
    fn insert_record(&mut self, record: &StoredRecord) -> Result<(), StoreError>;

    fn replace_record(&mut self, record: &StoredRecord) -> Result<(), StoreError>;

    fn fetch_record(&self, key: &RecordKey) -> Result<Option<StoredRecord>, StoreError>;

    fn list_records(&self, kind: RecordKind) -> Result<Vec<StoredRecord>, StoreError>;

    fn delete_record(&mut self, key: &RecordKey) -> Result<Option<StoredRecord>, StoreError>;
}

#[derive(Debug)]
pub struct PostgresRepository<E> {
    executor: E,
}

impl<E> PostgresRepository<E> {
    pub fn new(executor: E) -> Self {
        Self { executor }
    }

    pub fn executor(&self) -> &E {
        &self.executor
    }

    pub fn executor_mut(&mut self) -> &mut E {
        &mut self.executor
    }

    pub fn into_executor(self) -> E {
        self.executor
    }
}

impl<E: PostgresExecutor> Repository for PostgresRepository<E> {
    fn insert(&mut self, record: StoredRecord) -> Result<(), StoreError> {
        self.executor.insert_record(&record)
    }

    fn replace(&mut self, record: StoredRecord) -> Result<(), StoreError> {
        if record.kind().is_append_only() {
            return Err(StoreError::Immutable(record.kind()));
        }
        self.executor.replace_record(&record)
    }

    fn get(&self, key: &RecordKey) -> Result<Option<StoredRecord>, StoreError> {
        self.executor.fetch_record(key)
    }

    fn list(&self, kind: RecordKind) -> Result<Vec<StoredRecord>, StoreError> {
        self.executor.list_records(kind)
    }

    fn remove(&mut self, key: &RecordKey) -> Result<Option<StoredRecord>, StoreError> {
        if key.kind().is_append_only() {
            return Err(StoreError::Immutable(key.kind()));
        }
        self.executor.delete_record(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Default)]
    struct StubExecutor {
        inserted: Vec<RecordKey>,
    }

    impl PostgresExecutor for StubExecutor {
        fn insert_record(&mut self, record: &StoredRecord) -> Result<(), StoreError> {
            self.inserted.push(record.key());
            Ok(())
        }

        fn replace_record(&mut self, _record: &StoredRecord) -> Result<(), StoreError> {
            Ok(())
        }

        fn fetch_record(&self, _key: &RecordKey) -> Result<Option<StoredRecord>, StoreError> {
            Ok(None)
        }

        fn list_records(&self, _kind: RecordKind) -> Result<Vec<StoredRecord>, StoreError> {
            Ok(Vec::new())
        }

        fn delete_record(&mut self, _key: &RecordKey) -> Result<Option<StoredRecord>, StoreError> {
            Ok(None)
        }
    }

    #[test]
    fn adapter_exposes_driver_boundary_without_selecting_a_driver() {
        let repository = PostgresRepository::new(StubExecutor::default());
        assert!(repository.executor().inserted.is_empty());
    }
}
