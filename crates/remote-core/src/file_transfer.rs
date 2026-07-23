use sha2::{Digest, Sha256};

pub const MAX_FILE_TRANSFER_BYTES: u64 = 100 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferState {
    Requested,
    Accepted,
    Running,
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileTransferError {
    EmptyName,
    PathTraversal,
    InvalidName,
    TooLarge,
    InvalidState,
}

pub fn validate_file_name(name: &str, size: u64) -> Result<(), FileTransferError> {
    if name.trim().is_empty() {
        return Err(FileTransferError::EmptyName);
    }
    if size > MAX_FILE_TRANSFER_BYTES {
        return Err(FileTransferError::TooLarge);
    }
    if name == "." || name == ".." || name.contains('/') || name.contains('\\') {
        return Err(FileTransferError::PathTraversal);
    }
    if name.chars().any(|character| character.is_control()) {
        return Err(FileTransferError::InvalidName);
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return Err(FileTransferError::InvalidName);
    }
    Ok(())
}

#[derive(Debug)]
pub struct TransferLedger {
    state: TransferState,
    expected_size: u64,
    received: u64,
    digest: Sha256,
}

impl TransferLedger {
    pub fn new(name: &str, size: u64) -> Result<Self, FileTransferError> {
        validate_file_name(name, size)?;
        Ok(Self {
            state: TransferState::Requested,
            expected_size: size,
            received: 0,
            digest: Sha256::new(),
        })
    }

    pub fn accept(&mut self) -> Result<(), FileTransferError> {
        if self.state != TransferState::Requested {
            return Err(FileTransferError::InvalidState);
        }
        self.state = TransferState::Accepted;
        Ok(())
    }

    pub fn append(&mut self, chunk: &[u8]) -> Result<(), FileTransferError> {
        if !matches!(self.state, TransferState::Accepted | TransferState::Running) {
            return Err(FileTransferError::InvalidState);
        }
        let next = self.received.saturating_add(chunk.len() as u64);
        if next > self.expected_size {
            return Err(FileTransferError::TooLarge);
        }
        self.digest.update(chunk);
        self.received = next;
        self.state = TransferState::Running;
        Ok(())
    }

    pub fn finish(&mut self, expected_sha256: [u8; 32]) -> Result<(), FileTransferError> {
        if self.received != self.expected_size || !matches!(self.state, TransferState::Running) {
            return Err(FileTransferError::InvalidState);
        }
        if <[u8; 32]>::from(self.digest.clone().finalize()) != expected_sha256 {
            self.state = TransferState::Failed;
            return Err(FileTransferError::InvalidState);
        }
        self.state = TransferState::Completed;
        Ok(())
    }

    pub fn cancel(&mut self) {
        self.state = TransferState::Cancelled;
        self.digest = Sha256::new();
    }

    pub const fn state(&self) -> TransferState {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use remote_crypto::sha256;

    #[test]
    fn transfer_requires_confirmation_and_hash_match() {
        let mut ledger = TransferLedger::new("report.txt", 3).expect("ledger");
        ledger.accept().expect("accept");
        ledger.append(b"abc").expect("chunk");
        assert_eq!(ledger.finish(sha256(b"abc")), Ok(()));
        assert_eq!(ledger.state(), TransferState::Completed);
    }

    #[test]
    fn paths_are_rejected_before_io() {
        assert_eq!(
            validate_file_name("../secret", 1),
            Err(FileTransferError::PathTraversal)
        );
        assert_eq!(
            validate_file_name("safe.txt", MAX_FILE_TRANSFER_BYTES + 1),
            Err(FileTransferError::TooLarge)
        );
    }
}
