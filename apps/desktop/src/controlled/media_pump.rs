use std::fmt;

use remote_capture::{CaptureError, MonitorInfo, ScreenCapturer};
use remote_codec::{EncodedAccessUnit, VideoEncoder, VideoEncoderConfig, VideoEncoderError};

const DEFAULT_MAX_ACCESS_UNIT_BYTES: usize = 8 * 1024 * 1024;

pub trait EncodedVideoSink: Send {
    fn send_access_unit(&mut self, access_unit: &EncodedAccessUnit) -> Result<(), String>;
}

impl<T: EncodedVideoSink + ?Sized> EncodedVideoSink for Box<T> {
    fn send_access_unit(&mut self, access_unit: &EncodedAccessUnit) -> Result<(), String> {
        (**self).send_access_unit(access_unit)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediaPumpSnapshot {
    pub monitor: MonitorInfo,
    pub frames_sent: u64,
    pub bytes_sent: u64,
    pub last_frame_id: Option<u64>,
    pub last_presentation_time_micros: Option<u64>,
}

#[derive(Debug)]
pub enum MediaPumpError {
    InvalidFrameRate,
    Capture(CaptureError),
    NoMonitor,
    Encode(VideoEncoderError),
    Sink(String),
    Stopped,
}

impl fmt::Display for MediaPumpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFrameRate => {
                formatter.write_str("media frame rate must be between 1 and 60")
            }
            Self::Capture(error) => write!(formatter, "screen capture failed: {error}"),
            Self::NoMonitor => formatter.write_str("screen capture returned no monitor"),
            Self::Encode(error) => write!(formatter, "H.264 encoding failed: {error}"),
            Self::Sink(error) => write!(formatter, "encoded video sink failed: {error}"),
            Self::Stopped => formatter.write_str("controlled media session is stopped"),
        }
    }
}

impl std::error::Error for MediaPumpError {}

impl From<CaptureError> for MediaPumpError {
    fn from(value: CaptureError) -> Self {
        Self::Capture(value)
    }
}

impl From<VideoEncoderError> for MediaPumpError {
    fn from(value: VideoEncoderError) -> Self {
        Self::Encode(value)
    }
}

pub struct ControlledMediaSession<S: EncodedVideoSink> {
    capturer: Box<dyn ScreenCapturer>,
    encoder: VideoEncoder,
    sink: S,
    snapshot: MediaPumpSnapshot,
    keyframe_requested: bool,
    stopped: bool,
}

impl<S: EncodedVideoSink> ControlledMediaSession<S> {
    pub fn start(
        mut capturer: Box<dyn ScreenCapturer>,
        sink: S,
        frame_rate: u32,
    ) -> Result<Self, MediaPumpError> {
        if !(1..=60).contains(&frame_rate) {
            return Err(MediaPumpError::InvalidFrameRate);
        }
        capturer.start()?;
        let monitor = match capturer.monitors() {
            Ok(monitors) => monitors
                .iter()
                .find(|monitor| monitor.is_primary)
                .or_else(|| monitors.first())
                .cloned()
                .ok_or(MediaPumpError::NoMonitor),
            Err(error) => Err(MediaPumpError::Capture(error)),
        };
        let monitor = match monitor {
            Ok(monitor) => monitor,
            Err(error) => {
                let _ = capturer.stop();
                return Err(error);
            }
        };
        let encoder = match VideoEncoder::new(VideoEncoderConfig {
            width: monitor.width,
            height: monitor.height,
            frame_rate,
            keyframe_interval: frame_rate.saturating_mul(2),
            max_access_unit_bytes: DEFAULT_MAX_ACCESS_UNIT_BYTES,
            ..VideoEncoderConfig::default()
        }) {
            Ok(encoder) => encoder,
            Err(error) => {
                let _ = capturer.stop();
                return Err(error.into());
            }
        };
        Ok(Self {
            capturer,
            encoder,
            sink,
            snapshot: MediaPumpSnapshot {
                monitor,
                frames_sent: 0,
                bytes_sent: 0,
                last_frame_id: None,
                last_presentation_time_micros: None,
            },
            keyframe_requested: false,
            stopped: false,
        })
    }

    pub fn pump_once(&mut self) -> Result<MediaPumpSnapshot, MediaPumpError> {
        if self.stopped {
            return Err(MediaPumpError::Stopped);
        }
        let frame = self
            .capturer
            .capture_frame(self.snapshot.monitor.monitor_id)?;
        let access_unit = self
            .encoder
            .encode_with_options(&frame, self.keyframe_requested)?;
        self.keyframe_requested = false;
        self.sink
            .send_access_unit(&access_unit)
            .map_err(MediaPumpError::Sink)?;
        self.snapshot.frames_sent = self.snapshot.frames_sent.saturating_add(1);
        self.snapshot.bytes_sent = self
            .snapshot
            .bytes_sent
            .saturating_add(access_unit.data.len() as u64);
        self.snapshot.last_frame_id = Some(access_unit.frame_id);
        self.snapshot.last_presentation_time_micros = Some(access_unit.pts);
        Ok(self.snapshot.clone())
    }

    pub fn snapshot(&self) -> &MediaPumpSnapshot {
        &self.snapshot
    }

    pub fn request_keyframe(&mut self) {
        if !self.stopped {
            self.keyframe_requested = true;
        }
    }

    pub fn stop(&mut self) {
        if self.stopped {
            return;
        }
        let _ = self.encoder.stop();
        let _ = self.capturer.stop();
        self.stopped = true;
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped
    }
}

impl<S: EncodedVideoSink> Drop for ControlledMediaSession<S> {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use remote_capture::{MonitorInfo, SafeMockCapturer};
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct RecordingSink {
        access_units: Arc<Mutex<Vec<EncodedAccessUnit>>>,
    }

    impl EncodedVideoSink for RecordingSink {
        fn send_access_unit(&mut self, access_unit: &EncodedAccessUnit) -> Result<(), String> {
            self.access_units
                .lock()
                .map_err(|_| "recording sink lock poisoned".to_owned())?
                .push(access_unit.clone());
            Ok(())
        }
    }

    #[test]
    fn capture_encode_sink_and_stop_form_a_real_h264_slice() {
        let capturer = SafeMockCapturer::new(vec![MonitorInfo {
            monitor_id: 7,
            name: "test display".into(),
            x: 0,
            y: 0,
            width: 4,
            height: 4,
            scale_factor_milli: 1_000,
            is_primary: true,
        }]);
        let sink = RecordingSink::default();
        let observer = sink.clone();
        let mut session = ControlledMediaSession::start(Box::new(capturer), sink, 30)
            .expect("start controlled media");

        let snapshot = session.pump_once().expect("pump first frame");
        assert_eq!(snapshot.monitor.monitor_id, 7);
        assert_eq!(snapshot.frames_sent, 1);
        assert!(snapshot.bytes_sent > 0);
        let access_units = observer.access_units.lock().expect("recorded access units");
        assert_eq!(access_units.len(), 1);
        assert!(access_units[0].data.starts_with(&[0, 0, 0, 1]));
        assert!(access_units[0].is_keyframe);
        drop(access_units);

        session.stop();
        session.stop();
        assert!(session.is_stopped());
        assert!(matches!(session.pump_once(), Err(MediaPumpError::Stopped)));
    }
}
