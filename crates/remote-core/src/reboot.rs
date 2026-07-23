use remote_crypto::sha256;
use subtle::ConstantTimeEq;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebootState {
    Requested,
    Accepted,
    Cancelled,
    Executed,
    Resumed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeToken {
    id: String,
    secret_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeTokenError {
    Malformed,
    Mismatch,
    Consumed,
}

impl ResumeToken {
    pub fn issue(id: impl Into<String>, secret: &[u8]) -> Result<(Self, String), ResumeTokenError> {
        let id = id.into();
        if id.is_empty() || secret.is_empty() || id.contains('.') {
            return Err(ResumeTokenError::Malformed);
        }
        let token = format!("{id}.{}", hex(secret));
        Ok((
            Self {
                id,
                secret_hash: sha256(secret),
            },
            token,
        ))
    }

    pub fn verify(&self, token: &str) -> Result<(), ResumeTokenError> {
        let (id, secret) = token.split_once('.').ok_or(ResumeTokenError::Malformed)?;
        if id != self.id || secret.is_empty() {
            return Err(ResumeTokenError::Mismatch);
        }
        let decoded = decode_hex(secret).ok_or(ResumeTokenError::Malformed)?;
        if bool::from(self.secret_hash.ct_eq(&sha256(&decoded))) {
            Ok(())
        } else {
            Err(ResumeTokenError::Mismatch)
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resume_secret_is_verified_without_storing_plaintext() {
        let (token, wire) = ResumeToken::issue("resume-1", b"secret").expect("issue");
        assert_eq!(token.verify(&wire), Ok(()));
        assert_eq!(
            token.verify("resume-1.73656372657400"),
            Err(ResumeTokenError::Mismatch)
        );
        let debug = format!("{token:?}");
        assert!(!debug.contains(&wire));
        assert!(!debug.contains("736563726574"));
    }
}
