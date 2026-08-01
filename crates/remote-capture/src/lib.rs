use std::error::Error;
use std::fmt;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
pub use linux::{
    LinuxDesktopSession, PortalCapability, PortalInputError, PortalSessionState,
    UbuntuWaylandPortalCapturer, UbuntuWaylandPortalInput, UbuntuX11Capturer, WaylandPortalStatus,
    X11Capturer,
};
#[cfg(target_os = "windows")]
pub use windows::WindowsCapturer;

pub const MAX_CAPTURE_WIDTH: u32 = 16_384;
pub const MAX_CAPTURE_HEIGHT: u32 = 16_384;
pub const MAX_CAPTURE_FRAME_BYTES: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureBackend {
    WindowsGraphicsCapture,
    DxgiDesktopDuplication,
    UbuntuWaylandPipeWire,
    UbuntuX11Damage,
    UbuntuX11GetImage,
    SafeMock,
    UnsupportedPlatform,
}

impl fmt::Display for CaptureBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::WindowsGraphicsCapture => "Windows Graphics Capture",
            Self::DxgiDesktopDuplication => "DXGI Desktop Duplication",
            Self::UbuntuWaylandPipeWire => "Ubuntu Wayland / PipeWire",
            Self::UbuntuX11Damage => "Ubuntu X11 / XDamage",
            Self::UbuntuX11GetImage => "Ubuntu X11 / GetImage",
            Self::SafeMock => "safe mock capture",
            Self::UnsupportedPlatform => "unsupported platform capture",
        };
        formatter.write_str(name)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureState {
    Idle,
    Running,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureAuthorizationState {
    NotRequired,
    NotChecked,
    Required,
    Requesting,
    Granted,
    Denied,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    Bgra8,
    Nv12,
    Rgba8,
}

impl PixelFormat {
    fn minimum_stride(self, width: u32) -> Option<u32> {
        match self {
            Self::Bgra8 | Self::Rgba8 => width.checked_mul(4),
            Self::Nv12 => Some(width),
        }
    }

    fn required_bytes(self, stride: u32, height: u32) -> Option<usize> {
        let stride = usize::try_from(stride).ok()?;
        let height = usize::try_from(height).ok()?;
        match self {
            Self::Bgra8 | Self::Rgba8 => stride.checked_mul(height),
            Self::Nv12 => {
                if height % 2 != 0 {
                    return None;
                }
                stride
                    .checked_mul(height)?
                    .checked_add(stride.checked_mul(height / 2)?)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonitorInfo {
    pub monitor_id: u32,
    pub name: String,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub scale_factor_milli: u32,
    pub is_primary: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameMetadata {
    pub monitor_id: u32,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub pixel_format: PixelFormat,
    pub timestamp_micros: u64,
}

/// An owned frame whose storage remains valid independently of subsequent captures.
#[derive(Debug, PartialEq, Eq)]
pub struct CapturedFrame {
    metadata: FrameMetadata,
    bytes: Box<[u8]>,
}

impl CapturedFrame {
    pub fn try_new(
        metadata: FrameMetadata,
        bytes: Vec<u8>,
        limits: CaptureLimits,
    ) -> CaptureResult<Self> {
        let required_bytes = limits.validate_layout(
            metadata.width,
            metadata.height,
            metadata.stride,
            metadata.pixel_format,
        )?;
        if bytes.len() != required_bytes {
            return Err(CaptureError::InvalidFrame(
                "pixel byte length does not exactly match stride and height",
            ));
        }
        Ok(Self {
            metadata,
            bytes: bytes.into_boxed_slice(),
        })
    }

    pub fn metadata(&self) -> FrameMetadata {
        self.metadata
    }

    pub fn monitor_id(&self) -> u32 {
        self.metadata.monitor_id
    }

    pub fn width(&self) -> u32 {
        self.metadata.width
    }

    pub fn height(&self) -> u32 {
        self.metadata.height
    }

    pub fn stride(&self) -> u32 {
        self.metadata.stride
    }

    pub fn pixel_format(&self) -> PixelFormat {
        self.metadata.pixel_format
    }

    pub fn timestamp_micros(&self) -> u64 {
        self.metadata.timestamp_micros
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Box<[u8]> {
        self.bytes
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureLimits {
    max_width: u32,
    max_height: u32,
    max_frame_bytes: usize,
}

impl CaptureLimits {
    pub const DEFAULT: Self = Self {
        max_width: MAX_CAPTURE_WIDTH,
        max_height: MAX_CAPTURE_HEIGHT,
        max_frame_bytes: MAX_CAPTURE_FRAME_BYTES,
    };

    pub fn try_new(max_width: u32, max_height: u32, max_frame_bytes: usize) -> CaptureResult<Self> {
        if max_width == 0
            || max_height == 0
            || max_frame_bytes == 0
            || max_width > MAX_CAPTURE_WIDTH
            || max_height > MAX_CAPTURE_HEIGHT
            || max_frame_bytes > MAX_CAPTURE_FRAME_BYTES
        {
            return Err(CaptureError::InvalidLimits);
        }
        Ok(Self {
            max_width,
            max_height,
            max_frame_bytes,
        })
    }

    pub fn max_width(self) -> u32 {
        self.max_width
    }

    pub fn max_height(self) -> u32 {
        self.max_height
    }

    pub fn max_frame_bytes(self) -> usize {
        self.max_frame_bytes
    }

    pub(crate) fn validate_dimensions(self, width: u32, height: u32) -> CaptureResult<()> {
        if width == 0 || height == 0 {
            return Err(CaptureError::InvalidFrame(
                "frame width and height must be non-zero",
            ));
        }
        if width > self.max_width || height > self.max_height {
            return Err(CaptureError::FrameTooLarge {
                width,
                height,
                bytes: 0,
                max_bytes: self.max_frame_bytes,
            });
        }
        Ok(())
    }

    pub(crate) fn validate_layout(
        self,
        width: u32,
        height: u32,
        stride: u32,
        pixel_format: PixelFormat,
    ) -> CaptureResult<usize> {
        self.validate_dimensions(width, height)?;
        if pixel_format == PixelFormat::Nv12
            && (!width.is_multiple_of(2) || !height.is_multiple_of(2))
        {
            return Err(CaptureError::InvalidFrame(
                "NV12 frame width and height must be even",
            ));
        }
        let minimum_stride = pixel_format
            .minimum_stride(width)
            .ok_or(CaptureError::InvalidFrame("pixel stride overflow"))?;
        if stride < minimum_stride {
            return Err(CaptureError::InvalidFrame(
                "stride is smaller than the pixel row",
            ));
        }
        let required_bytes = pixel_format
            .required_bytes(stride, height)
            .ok_or(CaptureError::InvalidFrame("pixel layout size overflowed"))?;
        if required_bytes > self.max_frame_bytes {
            return Err(CaptureError::FrameTooLarge {
                width,
                height,
                bytes: required_bytes,
                max_bytes: self.max_frame_bytes,
            });
        }
        Ok(required_bytes)
    }
}

impl Default for CaptureLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    PermissionDenied,
    BackendUnavailable,
    MonitorNotFound,
    FrameUnavailable,
    InvalidState,
    InvalidLimits,
    InvalidFrame(&'static str),
    FrameTooLarge {
        width: u32,
        height: u32,
        bytes: usize,
        max_bytes: usize,
    },
    BackendFailure {
        backend: CaptureBackend,
        operation: &'static str,
        reason: String,
    },
    Unsupported {
        backend: CaptureBackend,
        reason: String,
    },
}

impl fmt::Display for CaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionDenied => formatter.write_str("screen capture permission denied"),
            Self::BackendUnavailable => formatter.write_str("screen capture backend unavailable"),
            Self::MonitorNotFound => formatter.write_str("screen capture monitor not found"),
            Self::FrameUnavailable => formatter.write_str("screen capture frame unavailable"),
            Self::InvalidState => formatter.write_str("screen capture is not running"),
            Self::InvalidLimits => formatter.write_str("screen capture limits are invalid"),
            Self::InvalidFrame(reason) => write!(formatter, "screen capture frame is invalid: {reason}"),
            Self::FrameTooLarge {
                width,
                height,
                bytes,
                max_bytes,
            } => write!(
                formatter,
                "screen capture frame {width}x{height} ({bytes} bytes) exceeds the configured {max_bytes}-byte limit"
            ),
            Self::BackendFailure {
                backend,
                operation,
                reason,
            } => write!(formatter, "{backend} failed during {operation}: {reason}"),
            Self::Unsupported { backend, reason } => {
                write!(formatter, "{backend} is unsupported: {reason}")
            }
        }
    }
}

impl Error for CaptureError {}

pub type CaptureResult<T> = Result<T, CaptureError>;

pub trait ScreenCapturer: Send {
    fn backend(&self) -> CaptureBackend;
    fn state(&self) -> CaptureState;
    fn authorization_state(&self) -> CaptureAuthorizationState;
    fn start(&mut self) -> CaptureResult<()>;
    fn monitors(&self) -> CaptureResult<Vec<MonitorInfo>>;
    fn capture_frame(&mut self, monitor_id: u32) -> CaptureResult<CapturedFrame>;
    fn stop(&mut self) -> CaptureResult<()>;
}

impl<C: ScreenCapturer + ?Sized> ScreenCapturer for Box<C> {
    fn backend(&self) -> CaptureBackend {
        (**self).backend()
    }

    fn state(&self) -> CaptureState {
        (**self).state()
    }

    fn authorization_state(&self) -> CaptureAuthorizationState {
        (**self).authorization_state()
    }

    fn start(&mut self) -> CaptureResult<()> {
        (**self).start()
    }

    fn monitors(&self) -> CaptureResult<Vec<MonitorInfo>> {
        (**self).monitors()
    }

    fn capture_frame(&mut self, monitor_id: u32) -> CaptureResult<CapturedFrame> {
        (**self).capture_frame(monitor_id)
    }

    fn stop(&mut self) -> CaptureResult<()> {
        (**self).stop()
    }
}

pub struct CaptureLease<C: ScreenCapturer> {
    capturer: Option<C>,
}

impl<C: ScreenCapturer> CaptureLease<C> {
    pub fn start(mut capturer: C) -> CaptureResult<Self> {
        capturer.start()?;
        Ok(Self {
            capturer: Some(capturer),
        })
    }

    pub fn capturer(&self) -> &C {
        self.capturer.as_ref().expect("capture lease is active")
    }

    pub fn capturer_mut(&mut self) -> &mut C {
        self.capturer.as_mut().expect("capture lease is active")
    }

    pub fn stop(mut self) -> CaptureResult<C> {
        let mut capturer = self.capturer.take().expect("capture lease is active");
        capturer.stop()?;
        Ok(capturer)
    }
}

impl<C: ScreenCapturer> Drop for CaptureLease<C> {
    fn drop(&mut self) {
        if let Some(capturer) = self.capturer.as_mut() {
            let _ = capturer.stop();
        }
    }
}

#[derive(Debug)]
pub struct SafeMockCapturer {
    state: CaptureState,
    monitors: Vec<MonitorInfo>,
    next_timestamp_micros: u64,
    limits: CaptureLimits,
}

impl Default for SafeMockCapturer {
    fn default() -> Self {
        Self::new(vec![MonitorInfo {
            monitor_id: 1,
            name: "Safe mock display".into(),
            x: 0,
            y: 0,
            width: 1280,
            height: 720,
            scale_factor_milli: 1_000,
            is_primary: true,
        }])
    }
}

impl SafeMockCapturer {
    pub fn new(monitors: Vec<MonitorInfo>) -> Self {
        Self::with_limits(monitors, CaptureLimits::default())
    }

    pub fn with_limits(monitors: Vec<MonitorInfo>, limits: CaptureLimits) -> Self {
        Self {
            state: CaptureState::Idle,
            monitors,
            next_timestamp_micros: 0,
            limits,
        }
    }

    fn validate_monitors(&self) -> CaptureResult<()> {
        for (index, monitor) in self.monitors.iter().enumerate() {
            self.limits
                .validate_dimensions(monitor.width, monitor.height)?;
            if monitor.monitor_id == 0 || monitor.scale_factor_milli == 0 {
                return Err(CaptureError::InvalidFrame(
                    "monitor id and scale factor must be non-zero",
                ));
            }
            if self.monitors[..index]
                .iter()
                .any(|candidate| candidate.monitor_id == monitor.monitor_id)
            {
                return Err(CaptureError::InvalidFrame("monitor ids must be unique"));
            }
        }
        Ok(())
    }
}

impl ScreenCapturer for SafeMockCapturer {
    fn backend(&self) -> CaptureBackend {
        CaptureBackend::SafeMock
    }

    fn state(&self) -> CaptureState {
        self.state
    }

    fn authorization_state(&self) -> CaptureAuthorizationState {
        CaptureAuthorizationState::NotRequired
    }

    fn start(&mut self) -> CaptureResult<()> {
        self.validate_monitors()?;
        self.state = CaptureState::Running;
        Ok(())
    }

    fn monitors(&self) -> CaptureResult<Vec<MonitorInfo>> {
        if self.state != CaptureState::Running {
            return Err(CaptureError::InvalidState);
        }
        Ok(self.monitors.clone())
    }

    fn capture_frame(&mut self, monitor_id: u32) -> CaptureResult<CapturedFrame> {
        if self.state != CaptureState::Running {
            return Err(CaptureError::InvalidState);
        }
        let monitor = self
            .monitors
            .iter()
            .find(|monitor| monitor.monitor_id == monitor_id)
            .ok_or(CaptureError::MonitorNotFound)?;
        let stride = monitor
            .width
            .checked_mul(4)
            .ok_or(CaptureError::InvalidFrame("pixel stride overflow"))?;
        let bytes_len = self.limits.validate_layout(
            monitor.width,
            monitor.height,
            stride,
            PixelFormat::Rgba8,
        )?;

        let mut bytes = vec![0_u8; bytes_len];
        for (index, pixel) in bytes.chunks_exact_mut(4).enumerate() {
            let x = (index % usize::try_from(monitor.width).unwrap_or(1)) as u8;
            let y = (index / usize::try_from(monitor.width).unwrap_or(1)) as u8;
            pixel.copy_from_slice(&[x, y, x ^ y, u8::MAX]);
        }
        self.next_timestamp_micros = self.next_timestamp_micros.saturating_add(16_667);
        CapturedFrame::try_new(
            FrameMetadata {
                monitor_id,
                width: monitor.width,
                height: monitor.height,
                stride,
                pixel_format: PixelFormat::Rgba8,
                timestamp_micros: self.next_timestamp_micros,
            },
            bytes,
            self.limits,
        )
    }

    fn stop(&mut self) -> CaptureResult<()> {
        self.state = CaptureState::Stopped;
        Ok(())
    }
}

impl Drop for SafeMockCapturer {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[derive(Debug)]
pub struct UnsupportedCapturer {
    backend: CaptureBackend,
    reason: String,
}

impl UnsupportedCapturer {
    pub fn new(backend: CaptureBackend, reason: impl Into<String>) -> Self {
        Self {
            backend,
            reason: reason.into(),
        }
    }

    fn error(&self) -> CaptureError {
        CaptureError::Unsupported {
            backend: self.backend,
            reason: self.reason.clone(),
        }
    }
}

impl ScreenCapturer for UnsupportedCapturer {
    fn backend(&self) -> CaptureBackend {
        self.backend
    }

    fn state(&self) -> CaptureState {
        CaptureState::Stopped
    }

    fn authorization_state(&self) -> CaptureAuthorizationState {
        CaptureAuthorizationState::Unavailable
    }

    fn start(&mut self) -> CaptureResult<()> {
        Err(self.error())
    }

    fn monitors(&self) -> CaptureResult<Vec<MonitorInfo>> {
        Err(self.error())
    }

    fn capture_frame(&mut self, _monitor_id: u32) -> CaptureResult<CapturedFrame> {
        Err(self.error())
    }

    fn stop(&mut self) -> CaptureResult<()> {
        Ok(())
    }
}

#[cfg(target_os = "windows")]
pub fn platform_capturer() -> Box<dyn ScreenCapturer> {
    Box::new(WindowsCapturer::default())
}

#[cfg(target_os = "linux")]
pub fn platform_capturer() -> Box<dyn ScreenCapturer> {
    linux::platform_capturer()
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn platform_capturer() -> Box<dyn ScreenCapturer> {
    Box::new(UnsupportedCapturer::new(
        CaptureBackend::UnsupportedPlatform,
        "desktop capture is only planned for Windows and Ubuntu",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    struct StopTrackingCapturer {
        stopped: Arc<AtomicBool>,
        state: CaptureState,
    }

    impl ScreenCapturer for StopTrackingCapturer {
        fn backend(&self) -> CaptureBackend {
            CaptureBackend::SafeMock
        }

        fn state(&self) -> CaptureState {
            self.state
        }

        fn authorization_state(&self) -> CaptureAuthorizationState {
            CaptureAuthorizationState::NotRequired
        }

        fn start(&mut self) -> CaptureResult<()> {
            self.state = CaptureState::Running;
            Ok(())
        }

        fn monitors(&self) -> CaptureResult<Vec<MonitorInfo>> {
            Ok(Vec::new())
        }

        fn capture_frame(&mut self, _monitor_id: u32) -> CaptureResult<CapturedFrame> {
            Err(CaptureError::FrameUnavailable)
        }

        fn stop(&mut self) -> CaptureResult<()> {
            self.stopped.store(true, Ordering::SeqCst);
            self.state = CaptureState::Stopped;
            Ok(())
        }
    }

    #[test]
    fn owned_frame_rejects_bad_stride_and_length() {
        let metadata = FrameMetadata {
            monitor_id: 1,
            width: 2,
            height: 2,
            stride: 7,
            pixel_format: PixelFormat::Rgba8,
            timestamp_micros: 1,
        };
        assert!(matches!(
            CapturedFrame::try_new(metadata, vec![0; 14], CaptureLimits::default()),
            Err(CaptureError::InvalidFrame(_))
        ));

        let metadata = FrameMetadata {
            stride: 8,
            ..metadata
        };
        assert!(matches!(
            CapturedFrame::try_new(metadata, vec![0; 15], CaptureLimits::default()),
            Err(CaptureError::InvalidFrame(_))
        ));
    }

    #[test]
    fn owned_frame_rejects_odd_nv12_dimensions() {
        let metadata = FrameMetadata {
            monitor_id: 1,
            width: 3,
            height: 2,
            stride: 3,
            pixel_format: PixelFormat::Nv12,
            timestamp_micros: 1,
        };
        assert!(matches!(
            CapturedFrame::try_new(metadata, vec![0; 9], CaptureLimits::default()),
            Err(CaptureError::InvalidFrame(_))
        ));
    }

    #[test]
    fn frame_limits_have_a_non_bypassable_hard_ceiling() {
        assert_eq!(
            CaptureLimits::try_new(
                MAX_CAPTURE_WIDTH + 1,
                MAX_CAPTURE_HEIGHT,
                MAX_CAPTURE_FRAME_BYTES
            ),
            Err(CaptureError::InvalidLimits)
        );
        assert_eq!(
            CaptureLimits::try_new(
                MAX_CAPTURE_WIDTH,
                MAX_CAPTURE_HEIGHT,
                MAX_CAPTURE_FRAME_BYTES + 1
            ),
            Err(CaptureError::InvalidLimits)
        );
    }

    #[test]
    fn safe_mock_returns_owned_non_empty_pixels() {
        let mut capturer = SafeMockCapturer::default();
        assert_eq!(capturer.backend(), CaptureBackend::SafeMock);
        assert_eq!(capturer.monitors(), Err(CaptureError::InvalidState));

        capturer.start().expect("safe mock should start");
        let frame = capturer.capture_frame(1).expect("safe mock frame");
        assert_eq!((frame.width(), frame.height()), (1280, 720));
        assert_eq!(frame.stride(), 1280 * 4);
        assert_eq!(frame.pixel_format(), PixelFormat::Rgba8);
        assert_eq!(frame.bytes().len(), 1280 * 720 * 4);
        assert!(frame.bytes().iter().any(|byte| *byte != 0));
    }

    #[test]
    fn capture_lease_stops_the_backend() {
        let capturer = SafeMockCapturer::default();
        let lease = CaptureLease::start(capturer).expect("lease should start");
        let capturer = lease.stop().expect("lease should stop");
        assert_eq!(capturer.state(), CaptureState::Stopped);
    }

    #[test]
    fn dropping_capture_lease_stops_the_backend() {
        let stopped = Arc::new(AtomicBool::new(false));
        {
            let capturer: Box<dyn ScreenCapturer> = Box::new(StopTrackingCapturer {
                stopped: Arc::clone(&stopped),
                state: CaptureState::Idle,
            });
            let _lease = CaptureLease::start(capturer).expect("lease should start");
        }
        assert!(stopped.load(Ordering::SeqCst));
    }

    #[test]
    fn unsupported_backend_never_reports_success() {
        let mut capturer =
            UnsupportedCapturer::new(CaptureBackend::UbuntuWaylandPipeWire, "test boundary");
        assert!(matches!(
            capturer.start(),
            Err(CaptureError::Unsupported { .. })
        ));
        assert!(matches!(
            capturer.capture_frame(1),
            Err(CaptureError::Unsupported { .. })
        ));
    }
}
