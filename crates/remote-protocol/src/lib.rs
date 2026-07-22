mod candidates;
mod canonical;
mod header;
mod input;
mod media;
mod permissions;
mod security;

pub use candidates::*;
pub use canonical::{
    canonical_api_request_bytes, canonical_idempotency_binding_bytes, canonical_json_bytes,
    canonical_json_bytes_from_slice, canonical_operation_binding_bytes, canonical_request_target,
    CanonicalError, CanonicalWriter, CANONICAL_LENGTH_BYTES,
};
pub use header::*;
pub use input::*;
pub use media::*;
pub use permissions::*;
pub use security::*;

use serde::{Deserialize, Serialize};

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u16)]
pub enum ErrorCode {
    Unauthorized = 1,
    DeviceOffline = 2,
    PermissionDenied = 3,
    SessionExpired = 4,
    UnsupportedVersion = 5,
    InvalidPayload = 6,
    UnsupportedMessageKind = 7,
    InvalidChannel = 8,
    ReplayDetected = 9,
    AuthenticationFailed = 10,
    Internal = 500,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRegistration {
    pub device_id: String,
    pub display_name: String,
    pub platform: PlatformKind,
    pub os_version: String,
    pub arch: String,
    pub public_key: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlatformKind {
    Windows,
    Ubuntu,
    Ios,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceStatus {
    Online,
    Offline,
    Busy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStateKind {
    Invited,
    Accepted,
    Rejected,
    Connecting,
    Connected,
    Degraded,
    Reconnecting,
    Closed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInvite {
    pub session_id: u128,
    pub controller_device_id: String,
    pub controlled_device_id: String,
    // Compatibility for the pre-freeze Signal stub. Security code uses SessionPermissions.
    pub requested_permissions: Permissions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationCode {
    pub device_id: String,
    pub code: String,
    pub expires_at_epoch_millis: u64,
    pub max_attempts: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceSummary {
    pub device_id: String,
    pub display_name: String,
    pub platform: PlatformKind,
    pub os_version: String,
    pub arch: String,
    pub status: DeviceStatus,
    pub last_seen_epoch_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SignalClientMessage {
    Ping,
    Hello,
    RegisterDevice(DeviceRegistration),
    SetDeviceStatus {
        device_id: String,
        status: DeviceStatus,
        seen_at_epoch_millis: u64,
    },
    ListOnlineDevices,
    InviteSession(SessionInvite),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SignalServerMessage {
    Pong,
    Hello {
        protocol_version: u16,
    },
    DeviceRegistered {
        device_id: String,
    },
    DeviceStatusUpdated {
        device_id: String,
        status: DeviceStatus,
    },
    OnlineDevices {
        devices: Vec<DeviceSummary>,
    },
    SessionInviteQueued {
        session_id: u128,
    },
    Error {
        code: ErrorCode,
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_message_serializes_with_snake_case_type() {
        assert_eq!(
            serde_json::to_string(&SignalClientMessage::Ping).expect("json"),
            r#"{"type":"ping"}"#
        );
    }

    #[test]
    fn platform_kind_is_independent_from_os_version() {
        assert_eq!(
            serde_json::to_string(&PlatformKind::Ubuntu).expect("json"),
            r#""ubuntu""#
        );
    }
}
