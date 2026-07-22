use serde::{Deserialize, Serialize};

use crate::SessionRole;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VideoCodec {
    H264,
    H265Reserved,
    Av1Reserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QualityProfile {
    Balanced,
    TextClear,
    LowBandwidth,
    LowLatency,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodecCapability {
    pub codec: VideoCodec,
    pub profiles: Vec<String>,
    pub pixel_formats: Vec<String>,
    pub color_modes: Vec<String>,
    pub max_width: u32,
    pub max_height: u32,
    pub max_fps: u32,
    pub hardware_encode: bool,
    pub hardware_decode: bool,
    pub software_encode: bool,
    pub software_decode: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisplayCapability {
    pub max_displays: u16,
    pub max_width: u32,
    pub max_height: u32,
    pub rotation: bool,
    pub dynamic_resize: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputCapability {
    pub mouse: bool,
    pub physical_keyboard: bool,
    pub text_commit: bool,
    pub ime_composition: bool,
    pub touch: bool,
    pub external_pointer: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaCapabilities {
    pub session_id: u128,
    pub role: SessionRole,
    pub codec_capabilities: Vec<CodecCapability>,
    pub display_capabilities: DisplayCapability,
    pub input_capabilities: InputCapability,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaConfigRequest {
    pub session_id: u128,
    pub display_id: String,
    pub preferred_codec: VideoCodec,
    pub max_width: u32,
    pub max_height: u32,
    pub max_fps: u32,
    pub max_bitrate_kbps: u32,
    pub quality_profile: QualityProfile,
    pub color_mode: String,
    pub timestamp_epoch_millis: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaConfigStatus {
    Active,
    Degraded,
    Unsupported,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaConfigState {
    pub session_id: u128,
    pub display_id: String,
    pub codec: VideoCodec,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate_kbps: u32,
    pub profile: String,
    pub pixel_format: String,
    pub color_mode: String,
    pub hardware_acceleration: bool,
    pub state: MediaConfigStatus,
    pub reason: Option<String>,
    pub timestamp_epoch_millis: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaQualityReason {
    LinkLossHigh,
    RttHigh,
    JitterHigh,
    EncodeBackpressure,
    DecodeBackpressure,
    CpuHigh,
    ThermalLimit,
    BatterySaver,
    KeyframeLoss,
    UserRequested,
    PolicyLimited,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaQualityRequest {
    pub session_id: u128,
    pub display_id: String,
    pub quality_profile: QualityProfile,
    pub reason: MediaQualityReason,
    pub timestamp_epoch_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaQualityState {
    pub session_id: u128,
    pub display_id: String,
    pub rtt_ms: u32,
    pub loss_ppm: u32,
    pub jitter_ms: u32,
    pub bitrate_kbps: u32,
    pub fps: u32,
    pub dropped_frames: u64,
    pub encode_ms: u32,
    pub decode_ms: u32,
    pub cpu_percent: u16,
    pub memory_mb: u32,
    pub timestamp_epoch_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyframeRequest {
    pub session_id: u128,
    pub display_id: String,
    pub reason: MediaQualityReason,
    pub last_received_frame_id: u64,
    pub timestamp_epoch_millis: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VideoFrameInfo {
    pub session_id: u128,
    pub display_id: String,
    pub frame_id: u64,
    pub codec: VideoCodec,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub pixel_format: String,
    pub color_space: String,
    pub rotation: u16,
    pub is_keyframe: bool,
    pub pts_millis: u64,
    pub frame_bytes_len: u32,
}
