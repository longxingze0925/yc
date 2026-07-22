use serde::{Deserialize, Serialize};

use crate::PROTOCOL_VERSION;

pub const HEADER_LEN: usize = 40;
pub const MAX_SECURE_SEQUENCE: u64 = (1_u64 << 48) - 1;
const MAGIC: [u8; 4] = *b"RCTL";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u16)]
pub enum ChannelId {
    SecureControl = 0,
    InputReliable = 1,
    InputRealtime = 2,
    MediaControl = 3,
    Video = 4,
    Clipboard = 5,
    FileTransfer = 6,
    DeviceControl = 7,
    Telemetry = 8,
}

impl TryFrom<u16> for ChannelId {
    type Error = ProtocolError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::SecureControl),
            1 => Ok(Self::InputReliable),
            2 => Ok(Self::InputRealtime),
            3 => Ok(Self::MediaControl),
            4 => Ok(Self::Video),
            5 => Ok(Self::Clipboard),
            6 => Ok(Self::FileTransfer),
            7 => Ok(Self::DeviceControl),
            8 => Ok(Self::Telemetry),
            _ => Err(ProtocolError::UnknownChannel(value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u16)]
pub enum MessageKind {
    KeyExchangeMessage = 0x0001,
    KeyConfirm = 0x0002,
    MediaCapabilities = 0x0100,
    MediaConfigRequest = 0x0101,
    MediaConfigState = 0x0102,
    MediaQualityRequest = 0x0103,
    MediaQualityState = 0x0104,
    KeyframeRequest = 0x0105,
    VideoFrameInfo = 0x0110,
    VideoFrameData = 0x0111,
    InputEvent = 0x0200,
    ClipboardPermissionRequest = 0x0300,
    ClipboardPermissionState = 0x0301,
    ClipboardText = 0x0302,
    DisplayList = 0x0400,
    DisplaySelect = 0x0401,
    DisplayChanged = 0x0402,
    FileTransferRequest = 0x0500,
    FileTransferAck = 0x0501,
    FileChunk = 0x0502,
    FileTransferCancel = 0x0503,
    PrivacyModeRequest = 0x0600,
    PrivacyModeState = 0x0601,
    PrivacyModeRestore = 0x0602,
    RebootRequest = 0x0700,
    RebootState = 0x0701,
    RebootCancel = 0x0702,
    RebootResumeHint = 0x0703,
    Stats = 0x0800,
    ErrorReport = 0xffff,
}

impl MessageKind {
    pub const fn default_channel(self) -> ChannelId {
        match self {
            Self::KeyExchangeMessage | Self::KeyConfirm | Self::ErrorReport => {
                ChannelId::SecureControl
            }
            Self::MediaCapabilities
            | Self::MediaConfigRequest
            | Self::MediaConfigState
            | Self::MediaQualityRequest
            | Self::MediaQualityState
            | Self::KeyframeRequest => ChannelId::MediaControl,
            Self::VideoFrameInfo | Self::VideoFrameData => ChannelId::Video,
            Self::InputEvent => ChannelId::InputReliable,
            Self::ClipboardPermissionRequest
            | Self::ClipboardPermissionState
            | Self::ClipboardText => ChannelId::Clipboard,
            Self::FileTransferRequest
            | Self::FileTransferAck
            | Self::FileChunk
            | Self::FileTransferCancel => ChannelId::FileTransfer,
            Self::DisplayList
            | Self::DisplaySelect
            | Self::DisplayChanged
            | Self::PrivacyModeRequest
            | Self::PrivacyModeState
            | Self::PrivacyModeRestore
            | Self::RebootRequest
            | Self::RebootState
            | Self::RebootCancel
            | Self::RebootResumeHint => ChannelId::DeviceControl,
            Self::Stats => ChannelId::Telemetry,
        }
    }

    pub const fn accepts_channel(self, channel: ChannelId) -> bool {
        if matches!(self, Self::InputEvent) {
            matches!(channel, ChannelId::InputReliable | ChannelId::InputRealtime)
        } else {
            self.default_channel() as u16 == channel as u16
        }
    }
}

impl TryFrom<u16> for MessageKind {
    type Error = ProtocolError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Self::KeyExchangeMessage),
            0x0002 => Ok(Self::KeyConfirm),
            0x0100 => Ok(Self::MediaCapabilities),
            0x0101 => Ok(Self::MediaConfigRequest),
            0x0102 => Ok(Self::MediaConfigState),
            0x0103 => Ok(Self::MediaQualityRequest),
            0x0104 => Ok(Self::MediaQualityState),
            0x0105 => Ok(Self::KeyframeRequest),
            0x0110 => Ok(Self::VideoFrameInfo),
            0x0111 => Ok(Self::VideoFrameData),
            0x0200 => Ok(Self::InputEvent),
            0x0300 => Ok(Self::ClipboardPermissionRequest),
            0x0301 => Ok(Self::ClipboardPermissionState),
            0x0302 => Ok(Self::ClipboardText),
            0x0400 => Ok(Self::DisplayList),
            0x0401 => Ok(Self::DisplaySelect),
            0x0402 => Ok(Self::DisplayChanged),
            0x0500 => Ok(Self::FileTransferRequest),
            0x0501 => Ok(Self::FileTransferAck),
            0x0502 => Ok(Self::FileChunk),
            0x0503 => Ok(Self::FileTransferCancel),
            0x0600 => Ok(Self::PrivacyModeRequest),
            0x0601 => Ok(Self::PrivacyModeState),
            0x0602 => Ok(Self::PrivacyModeRestore),
            0x0700 => Ok(Self::RebootRequest),
            0x0701 => Ok(Self::RebootState),
            0x0702 => Ok(Self::RebootCancel),
            0x0703 => Ok(Self::RebootResumeHint),
            0x0800 => Ok(Self::Stats),
            0xffff => Ok(Self::ErrorReport),
            _ => Err(ProtocolError::UnknownMessageKind(value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolError {
    InvalidMagic,
    IncompleteHeader,
    UnsupportedVersion(u16),
    PayloadTooLarge,
    UnknownMessageKind(u16),
    UnknownChannel(u16),
    InvalidChannel {
        kind: MessageKind,
        channel: ChannelId,
    },
    SequenceExhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageHeader {
    pub version: u16,
    pub kind: MessageKind,
    pub flags: u16,
    pub channel_id: ChannelId,
    pub session_id: u128,
    pub sequence: u64,
    pub payload_len: u32,
}

impl MessageHeader {
    pub fn new(kind: MessageKind, session_id: u128, sequence: u64, payload_len: u32) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            kind,
            flags: 0,
            channel_id: kind.default_channel(),
            session_id,
            sequence,
            payload_len,
        }
    }

    pub fn new_on_channel(
        kind: MessageKind,
        channel_id: ChannelId,
        session_id: u128,
        sequence: u64,
        payload_len: u32,
    ) -> Result<Self, ProtocolError> {
        let header = Self {
            channel_id,
            ..Self::new(kind, session_id, sequence, payload_len)
        };
        header.validate_kind_channel()?;
        Ok(header)
    }

    pub fn validate_kind_channel(self) -> Result<(), ProtocolError> {
        if self.kind.accepts_channel(self.channel_id) {
            Ok(())
        } else {
            Err(ProtocolError::InvalidChannel {
                kind: self.kind,
                channel: self.channel_id,
            })
        }
    }
}

pub fn encode_header(header: MessageHeader) -> [u8; HEADER_LEN] {
    let mut out = [0_u8; HEADER_LEN];
    out[0..4].copy_from_slice(&MAGIC);
    out[4..6].copy_from_slice(&header.version.to_be_bytes());
    out[6..8].copy_from_slice(&(header.kind as u16).to_be_bytes());
    out[8..10].copy_from_slice(&header.flags.to_be_bytes());
    out[10..12].copy_from_slice(&(header.channel_id as u16).to_be_bytes());
    out[12..28].copy_from_slice(&header.session_id.to_be_bytes());
    out[28..36].copy_from_slice(&header.sequence.to_be_bytes());
    out[36..40].copy_from_slice(&header.payload_len.to_be_bytes());
    out
}

pub fn decode_header(input: &[u8]) -> Result<MessageHeader, ProtocolError> {
    if input.len() < HEADER_LEN {
        return Err(ProtocolError::IncompleteHeader);
    }
    if input[0..4] != MAGIC {
        return Err(ProtocolError::InvalidMagic);
    }

    let version = u16::from_be_bytes([input[4], input[5]]);
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(version));
    }
    let kind = MessageKind::try_from(u16::from_be_bytes([input[6], input[7]]))?;
    let channel_id = ChannelId::try_from(u16::from_be_bytes([input[10], input[11]]))?;
    let header = MessageHeader {
        version,
        kind,
        flags: u16::from_be_bytes([input[8], input[9]]),
        channel_id,
        session_id: u128::from_be_bytes(input[12..28].try_into().expect("fixed header slice")),
        sequence: u64::from_be_bytes(input[28..36].try_into().expect("fixed header slice")),
        payload_len: u32::from_be_bytes(input[36..40].try_into().expect("fixed header slice")),
    };
    header.validate_kind_channel()?;
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_40_byte_header_vector_round_trips() {
        let header = MessageHeader::new_on_channel(
            MessageKind::InputEvent,
            ChannelId::InputRealtime,
            0x00112233445566778899aabbccddeeff,
            0x0102030405060708,
            0x10203040,
        )
        .expect("header");

        let encoded = encode_header(header);
        assert_eq!(encoded.len(), 40);
        assert_eq!(
            hex(&encoded),
            "5243544c000102000000000200112233445566778899aabbccddeeff010203040506070810203040"
        );
        assert_eq!(decode_header(&encoded), Ok(header));
    }

    #[test]
    fn rejects_wrong_kind_channel_pair() {
        let mut encoded = encode_header(MessageHeader::new(MessageKind::VideoFrameData, 1, 0, 16));
        encoded[10..12].copy_from_slice(&(ChannelId::FileTransfer as u16).to_be_bytes());

        assert_eq!(
            decode_header(&encoded),
            Err(ProtocolError::InvalidChannel {
                kind: MessageKind::VideoFrameData,
                channel: ChannelId::FileTransfer
            })
        );
    }

    #[test]
    fn input_event_is_the_only_dual_channel_kind() {
        assert!(MessageKind::InputEvent.accepts_channel(ChannelId::InputReliable));
        assert!(MessageKind::InputEvent.accepts_channel(ChannelId::InputRealtime));
        assert!(!MessageKind::KeyConfirm.accepts_channel(ChannelId::InputRealtime));
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
