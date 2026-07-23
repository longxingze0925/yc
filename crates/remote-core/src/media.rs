use remote_protocol::{
    CodecCapability, MediaCapabilities, MediaConfigRequest, MediaConfigState, MediaConfigStatus,
    MediaQualityState, QualityProfile, VideoCodec,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaError {
    SessionMismatch,
    DisplayMissing,
    H264Unavailable,
    InvalidRequest,
}

pub struct MediaNegotiator;

impl MediaNegotiator {
    pub fn negotiate(
        sender: &MediaCapabilities,
        receiver: &MediaCapabilities,
        request: &MediaConfigRequest,
    ) -> Result<MediaConfigState, MediaError> {
        if sender.session_id != request.session_id || receiver.session_id != request.session_id {
            return Err(MediaError::SessionMismatch);
        }
        if request.preferred_codec != VideoCodec::H264 {
            return Err(MediaError::H264Unavailable);
        }
        if request.display_id.is_empty()
            || request.max_width == 0
            || request.max_height == 0
            || request.max_fps == 0
            || request.max_bitrate_kbps == 0
        {
            return Err(MediaError::InvalidRequest);
        }
        if receiver.display_capabilities.max_displays == 0 {
            return Err(MediaError::DisplayMissing);
        }
        let sender_h264 =
            find_h264(&sender.codec_capabilities).ok_or(MediaError::H264Unavailable)?;
        let receiver_h264 =
            find_h264(&receiver.codec_capabilities).ok_or(MediaError::H264Unavailable)?;
        let width = request
            .max_width
            .min(sender_h264.max_width)
            .min(receiver_h264.max_width);
        let height = request
            .max_height
            .min(sender_h264.max_height)
            .min(receiver_h264.max_height);
        let fps = request
            .max_fps
            .min(sender_h264.max_fps)
            .min(receiver_h264.max_fps);
        if width == 0 || height == 0 || fps == 0 {
            return Err(MediaError::InvalidRequest);
        }
        let hardware_acceleration = sender_h264.hardware_encode && receiver_h264.hardware_decode;
        Ok(MediaConfigState {
            session_id: request.session_id,
            display_id: request.display_id.clone(),
            codec: VideoCodec::H264,
            width,
            height,
            fps,
            bitrate_kbps: request.max_bitrate_kbps,
            profile: quality_name(request.quality_profile).into(),
            pixel_format: choose_pixel_format(sender_h264, receiver_h264),
            color_mode: request.color_mode.clone(),
            hardware_acceleration,
            state: MediaConfigStatus::Active,
            reason: None,
            timestamp_epoch_millis: request.timestamp_epoch_millis,
        })
    }

    pub fn adapt(current: &MediaConfigState, metrics: &MediaQualityState) -> MediaConfigState {
        let severe =
            metrics.loss_ppm >= 100_000 || metrics.rtt_ms >= 500 || metrics.cpu_percent >= 95;
        let moderate =
            metrics.loss_ppm >= 30_000 || metrics.rtt_ms >= 250 || metrics.jitter_ms >= 80;
        let (factor, state, reason) = if severe {
            (0.5, MediaConfigStatus::Degraded, "link_or_cpu_degraded")
        } else if moderate {
            (0.75, MediaConfigStatus::Degraded, "link_quality_reduced")
        } else {
            (1.0, MediaConfigStatus::Active, "link_quality_recovered")
        };
        let bitrate = ((current.bitrate_kbps as f32 * factor) as u32).max(128);
        let fps = ((current.fps as f32 * factor) as u32).max(1);
        MediaConfigState {
            bitrate_kbps: bitrate,
            fps,
            state,
            reason: Some(reason.into()),
            ..current.clone()
        }
    }
}

fn find_h264(capabilities: &[CodecCapability]) -> Option<&CodecCapability> {
    capabilities
        .iter()
        .find(|cap| cap.codec == VideoCodec::H264)
}

fn choose_pixel_format(sender: &CodecCapability, receiver: &CodecCapability) -> String {
    sender
        .pixel_formats
        .iter()
        .find(|format| receiver.pixel_formats.contains(format))
        .cloned()
        .unwrap_or_else(|| "nv12".into())
}

const fn quality_name(profile: QualityProfile) -> &'static str {
    match profile {
        QualityProfile::Balanced => "balanced",
        QualityProfile::TextClear => "text_clear",
        QualityProfile::LowBandwidth => "low_bandwidth",
        QualityProfile::LowLatency => "low_latency",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use remote_protocol::{DisplayCapability, InputCapability, SessionRole};

    fn caps(session_id: u128, role: SessionRole) -> MediaCapabilities {
        MediaCapabilities {
            session_id,
            role,
            codec_capabilities: vec![CodecCapability {
                codec: VideoCodec::H264,
                profiles: vec!["baseline".into()],
                pixel_formats: vec!["nv12".into()],
                color_modes: vec!["bt709".into()],
                max_width: 1920,
                max_height: 1080,
                max_fps: 60,
                hardware_encode: true,
                hardware_decode: true,
                software_encode: true,
                software_decode: true,
            }],
            display_capabilities: DisplayCapability {
                max_displays: 1,
                max_width: 1920,
                max_height: 1080,
                rotation: true,
                dynamic_resize: true,
            },
            input_capabilities: InputCapability {
                mouse: true,
                physical_keyboard: true,
                text_commit: true,
                ime_composition: true,
                touch: false,
                external_pointer: false,
            },
        }
    }

    #[test]
    fn h264_intersection_and_degrade_are_deterministic() {
        let request = MediaConfigRequest {
            session_id: 7,
            display_id: "primary".into(),
            preferred_codec: VideoCodec::H264,
            max_width: 2560,
            max_height: 1440,
            max_fps: 60,
            max_bitrate_kbps: 4000,
            quality_profile: QualityProfile::Balanced,
            color_mode: "bt709".into(),
            timestamp_epoch_millis: 1,
        };
        let state = MediaNegotiator::negotiate(
            &caps(7, SessionRole::Controlled),
            &caps(7, SessionRole::Controller),
            &request,
        )
        .expect("negotiation");
        assert_eq!(state.width, 1920);
        let degraded = MediaNegotiator::adapt(
            &state,
            &MediaQualityState {
                session_id: 7,
                display_id: "primary".into(),
                rtt_ms: 600,
                loss_ppm: 120_000,
                jitter_ms: 1,
                bitrate_kbps: state.bitrate_kbps,
                fps: state.fps,
                dropped_frames: 0,
                encode_ms: 1,
                decode_ms: 1,
                cpu_percent: 40,
                memory_mb: 1,
                timestamp_epoch_millis: 2,
            },
        );
        assert!(degraded.bitrate_kbps < state.bitrate_kbps);
    }
}
