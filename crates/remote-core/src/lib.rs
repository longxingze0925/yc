use std::collections::HashMap;

use remote_protocol::{DeviceStatus, Permissions, PlatformKind, VerificationCode};

mod clipboard;
mod display;
mod file_transfer;
mod input;
mod media;
mod policy;
mod privacy;
mod reboot;
mod session_crypto;

pub use clipboard::*;
pub use display::*;
pub use file_transfer::*;
pub use input::*;
pub use media::*;
pub use policy::*;
pub use privacy::*;
pub use reboot::*;
pub use session_crypto::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceIdentity {
    pub device_id: String,
    pub display_name: String,
    pub platform: PlatformKind,
    pub os_version: String,
    pub arch: String,
    pub public_key: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceRole {
    Controller,
    Controlled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionState {
    Created,
    WaitingForApproval,
    Approved,
    Connecting,
    Connected,
    Degraded,
    Reconnecting,
    Closed,
    Failed(SessionFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionFailure {
    Rejected,
    Unauthorized,
    TransportUnavailable,
    TimedOut,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    pub identity: DeviceIdentity,
    pub status: DeviceStatus,
    pub last_seen_epoch_millis: u64,
}

#[derive(Debug, Clone, Default)]
pub struct DeviceRegistry {
    devices: HashMap<String, DeviceRecord>,
}

impl DeviceRegistry {
    pub fn register(&mut self, identity: DeviceIdentity, seen_at_epoch_millis: u64) {
        let device_id = identity.device_id.clone();
        let record = DeviceRecord {
            identity,
            status: DeviceStatus::Online,
            last_seen_epoch_millis: seen_at_epoch_millis,
        };

        self.devices.insert(device_id, record);
    }

    pub fn mark_status(
        &mut self,
        device_id: &str,
        status: DeviceStatus,
        seen_at_epoch_millis: u64,
    ) -> Result<(), DeviceRegistryError> {
        let record = self
            .devices
            .get_mut(device_id)
            .ok_or(DeviceRegistryError::UnknownDevice)?;

        record.status = status;
        record.last_seen_epoch_millis = seen_at_epoch_millis;

        Ok(())
    }

    pub fn get(&self, device_id: &str) -> Option<&DeviceRecord> {
        self.devices.get(device_id)
    }

    pub fn list_online(&self) -> Vec<&DeviceRecord> {
        let mut records = self
            .devices
            .values()
            .filter(|record| record.status == DeviceStatus::Online)
            .collect::<Vec<_>>();

        records.sort_by(|left, right| left.identity.device_id.cmp(&right.identity.device_id));
        records
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceRegistryError {
    UnknownDevice,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationChallenge {
    code: VerificationCode,
    attempts_remaining: u8,
}

impl VerificationChallenge {
    pub fn new(code: VerificationCode) -> Self {
        Self {
            attempts_remaining: code.max_attempts,
            code,
        }
    }

    pub fn verify(&mut self, candidate: &str, now_epoch_millis: u64) -> VerificationResult {
        if now_epoch_millis > self.code.expires_at_epoch_millis {
            return VerificationResult::Expired;
        }

        if self.attempts_remaining == 0 {
            return VerificationResult::AttemptsExceeded;
        }

        if candidate == self.code.code {
            VerificationResult::Accepted
        } else {
            self.attempts_remaining -= 1;
            VerificationResult::Rejected {
                attempts_remaining: self.attempts_remaining,
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationResult {
    Accepted,
    Rejected { attempts_remaining: u8 },
    Expired,
    AttemptsExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPolicy {
    pub permissions: Permissions,
    pub require_controlled_side_prompt: bool,
    pub audit_required: bool,
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            permissions: Permissions::default(),
            require_controlled_side_prompt: true,
            audit_required: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub session_id: u128,
    pub controller: DeviceIdentity,
    pub controlled: DeviceIdentity,
    pub state: SessionState,
    pub policy: SessionPolicy,
}

impl Session {
    pub fn new(
        session_id: u128,
        controller: DeviceIdentity,
        controlled: DeviceIdentity,
        policy: SessionPolicy,
    ) -> Self {
        Self {
            session_id,
            controller,
            controlled,
            state: SessionState::Created,
            policy,
        }
    }

    pub fn request_approval(&mut self) {
        self.state = SessionState::WaitingForApproval;
    }

    pub fn approve(&mut self) {
        self.state = SessionState::Approved;
    }

    pub fn connect(&mut self) {
        self.state = SessionState::Connecting;
    }

    pub fn mark_connected(&mut self) {
        self.state = SessionState::Connected;
    }

    pub fn close(&mut self) {
        self.state = SessionState::Closed;
    }

    pub fn fail(&mut self, reason: SessionFailure) {
        self.state = SessionState::Failed(reason);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(device_id: &str, platform: PlatformKind) -> DeviceIdentity {
        DeviceIdentity {
            device_id: device_id.to_owned(),
            display_name: device_id.to_owned(),
            platform,
            os_version: "26.04".to_owned(),
            arch: "x86_64".to_owned(),
            public_key: [1_u8; 32],
        }
    }

    #[test]
    fn session_moves_through_minimal_lifecycle() {
        let mut session = Session::new(
            9,
            device("ios-controller", PlatformKind::Ios),
            device("ubuntu-controlled", PlatformKind::Ubuntu),
            SessionPolicy::default(),
        );

        assert_eq!(session.state, SessionState::Created);
        session.request_approval();
        assert_eq!(session.state, SessionState::WaitingForApproval);
        session.approve();
        assert_eq!(session.state, SessionState::Approved);
        session.connect();
        assert_eq!(session.state, SessionState::Connecting);
        session.mark_connected();
        assert_eq!(session.state, SessionState::Connected);
        session.close();
        assert_eq!(session.state, SessionState::Closed);
    }

    #[test]
    fn default_policy_requires_prompt_and_audit() {
        let policy = SessionPolicy::default();

        assert!(policy.require_controlled_side_prompt);
        assert!(policy.audit_required);
    }

    #[test]
    fn device_registry_tracks_online_devices() {
        let mut registry = DeviceRegistry::default();
        registry.register(device("ubuntu-controlled", PlatformKind::Ubuntu), 100);
        registry.register(device("windows-controlled", PlatformKind::Windows), 101);

        registry
            .mark_status("ubuntu-controlled", DeviceStatus::Offline, 200)
            .expect("known device");

        let online = registry.list_online();

        assert_eq!(online.len(), 1);
        assert_eq!(online[0].identity.device_id, "windows-controlled");
    }

    #[test]
    fn verification_challenge_rejects_wrong_code_and_tracks_attempts() {
        let mut challenge = VerificationChallenge::new(VerificationCode {
            device_id: "controlled".to_owned(),
            code: "123456".to_owned(),
            expires_at_epoch_millis: 1_000,
            max_attempts: 2,
        });

        assert_eq!(
            challenge.verify("000000", 100),
            VerificationResult::Rejected {
                attempts_remaining: 1
            }
        );
        assert_eq!(
            challenge.verify("123456", 100),
            VerificationResult::Accepted
        );
    }

    #[test]
    fn verification_challenge_expires() {
        let mut challenge = VerificationChallenge::new(VerificationCode {
            device_id: "controlled".to_owned(),
            code: "123456".to_owned(),
            expires_at_epoch_millis: 1_000,
            max_attempts: 2,
        });

        assert_eq!(
            challenge.verify("123456", 1_001),
            VerificationResult::Expired
        );
    }
}
