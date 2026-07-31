use std::sync::mpsc::{self, Receiver, SyncSender};
use std::time::{Duration, Instant};

use windows_capture::capture::{CaptureControl, Context, GraphicsCaptureApiHandler};
use windows_capture::dxgi_duplication_api::{
    DxgiDuplicationApi, DxgiDuplicationFormat, Error as DxgiError,
};
use windows_capture::frame::Frame;
use windows_capture::graphics_capture_api::InternalCaptureControl;
use windows_capture::monitor::Monitor;
use windows_capture::settings::{
    ColorFormat, CursorCaptureSettings, DirtyRegionSettings, DrawBorderSettings,
    MinimumUpdateIntervalSettings, SecondaryWindowSettings, Settings,
};

use crate::{
    CaptureAuthorizationState, CaptureBackend, CaptureError, CaptureLimits, CaptureResult,
    CaptureState, CapturedFrame, FrameMetadata, MonitorInfo, PixelFormat, ScreenCapturer,
};

const WGC_FIRST_FRAME_TIMEOUT: Duration = Duration::from_millis(750);
const WGC_CHANGED_FRAME_TIMEOUT: Duration = Duration::from_millis(20);
const DXGI_FRAME_TIMEOUT_MILLIS: u32 = 50;
const DXGI_INITIAL_ATTEMPTS: usize = 10;

#[derive(Clone)]
struct RawFrame {
    width: u32,
    height: u32,
    pixel_format: PixelFormat,
    bytes: Vec<u8>,
}

struct WgcFrameHandler {
    sender: SyncSender<RawFrame>,
}

impl GraphicsCaptureApiHandler for WgcFrameHandler {
    type Flags = SyncSender<RawFrame>;
    type Error = String;

    fn new(context: Context<Self::Flags>) -> Result<Self, Self::Error> {
        Ok(Self {
            sender: context.flags,
        })
    }

    fn on_frame_arrived(
        &mut self,
        frame: &mut Frame,
        _capture_control: InternalCaptureControl,
    ) -> Result<(), Self::Error> {
        let width = frame.width();
        let height = frame.height();
        let mut staging = Vec::new();
        let buffer = frame
            .buffer()
            .map_err(|error| format!("could not map the WGC frame: {error}"))?;
        let bytes = buffer.as_nopadding_buffer(&mut staging).to_vec();
        let captured = RawFrame {
            width,
            height,
            pixel_format: PixelFormat::Bgra8,
            bytes,
        };

        match self.sender.try_send(captured) {
            Ok(()) | Err(mpsc::TrySendError::Full(_)) => Ok(()),
            Err(mpsc::TrySendError::Disconnected(_)) => Err("WGC frame receiver closed".into()),
        }
    }
}

struct WgcSession {
    control: Option<CaptureControl<WgcFrameHandler, String>>,
    receiver: Receiver<RawFrame>,
    latest: Option<RawFrame>,
}

impl WgcSession {
    fn start(monitor: Monitor) -> Result<Self, String> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let settings = Settings::new(
            monitor,
            CursorCaptureSettings::WithCursor,
            DrawBorderSettings::Default,
            SecondaryWindowSettings::Default,
            MinimumUpdateIntervalSettings::Default,
            DirtyRegionSettings::Default,
            ColorFormat::Bgra8,
            sender,
        );
        let control = WgcFrameHandler::start_free_threaded(settings)
            .map_err(|error| format!("could not start Windows Graphics Capture: {error}"))?;
        Ok(Self {
            control: Some(control),
            receiver,
            latest: None,
        })
    }

    fn capture(&mut self) -> Result<RawFrame, String> {
        let timeout = if self.latest.is_some() {
            WGC_CHANGED_FRAME_TIMEOUT
        } else {
            WGC_FIRST_FRAME_TIMEOUT
        };
        match self.receiver.recv_timeout(timeout) {
            Ok(frame) => {
                self.latest = Some(frame);
                while let Ok(frame) = self.receiver.try_recv() {
                    self.latest = Some(frame);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) if self.latest.is_some() => {}
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err("Windows Graphics Capture did not deliver its first frame".into());
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("Windows Graphics Capture stopped delivering frames".into());
            }
        }
        self.latest
            .clone()
            .ok_or_else(|| "Windows Graphics Capture has no reusable frame".into())
    }

    fn stop(&mut self) -> Result<(), String> {
        let Some(control) = self.control.take() else {
            return Ok(());
        };
        control
            .stop()
            .map_err(|error| format!("could not stop Windows Graphics Capture: {error}"))
    }
}

impl Drop for WgcSession {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

struct DxgiSession {
    api: DxgiDuplicationApi,
    latest: Option<RawFrame>,
}

enum DxgiCaptureFailure {
    AccessLost,
    Failed(String),
}

impl DxgiSession {
    fn start(monitor: Monitor) -> Result<Self, String> {
        let api = DxgiDuplicationApi::new_options(
            monitor,
            &[DxgiDuplicationFormat::Bgra8, DxgiDuplicationFormat::Rgba8],
        )
        .map_err(|error| format!("could not start DXGI Desktop Duplication: {error}"))?;
        Ok(Self { api, latest: None })
    }

    fn capture(&mut self) -> Result<RawFrame, DxgiCaptureFailure> {
        let attempts = if self.latest.is_some() {
            1
        } else {
            DXGI_INITIAL_ATTEMPTS
        };
        for _ in 0..attempts {
            let raw = match self.api.acquire_next_frame(DXGI_FRAME_TIMEOUT_MILLIS) {
                Ok(mut frame) => {
                    let width = frame.width();
                    let height = frame.height();
                    let pixel_format = match frame.format() {
                        DxgiDuplicationFormat::Bgra8 | DxgiDuplicationFormat::Bgra8Srgb => {
                            PixelFormat::Bgra8
                        }
                        DxgiDuplicationFormat::Rgba8 | DxgiDuplicationFormat::Rgba8Srgb => {
                            PixelFormat::Rgba8
                        }
                        format => {
                            return Err(DxgiCaptureFailure::Failed(format!(
                                "DXGI returned unsupported pixel format {format:?}"
                            )));
                        }
                    };
                    let mut staging = Vec::new();
                    let buffer = frame.buffer().map_err(|error| {
                        DxgiCaptureFailure::Failed(format!("could not map the DXGI frame: {error}"))
                    })?;
                    RawFrame {
                        width,
                        height,
                        pixel_format,
                        bytes: buffer.as_nopadding_buffer(&mut staging).to_vec(),
                    }
                }
                Err(DxgiError::Timeout) if self.latest.is_some() => {
                    return self.latest.clone().ok_or_else(|| {
                        DxgiCaptureFailure::Failed("DXGI has no reusable frame".into())
                    });
                }
                Err(DxgiError::Timeout) => continue,
                Err(DxgiError::AccessLost) => return Err(DxgiCaptureFailure::AccessLost),
                Err(error) => {
                    return Err(DxgiCaptureFailure::Failed(format!(
                        "DXGI frame acquisition failed: {error}"
                    )));
                }
            };
            self.latest = Some(raw.clone());
            return Ok(raw);
        }
        Err(DxgiCaptureFailure::Failed(
            "DXGI did not deliver its first frame before the capture deadline".into(),
        ))
    }
}

struct NativeMonitor {
    info: MonitorInfo,
    handle: Monitor,
}

enum ActiveCapture {
    Wgc {
        monitor_id: u32,
        session: WgcSession,
    },
    Dxgi {
        monitor_id: u32,
        session: DxgiSession,
    },
}

impl ActiveCapture {
    fn monitor_id(&self) -> u32 {
        match self {
            Self::Wgc { monitor_id, .. } | Self::Dxgi { monitor_id, .. } => *monitor_id,
        }
    }

    fn backend(&self) -> CaptureBackend {
        match self {
            Self::Wgc { .. } => CaptureBackend::WindowsGraphicsCapture,
            Self::Dxgi { .. } => CaptureBackend::DxgiDesktopDuplication,
        }
    }

    fn stop(&mut self) -> Result<(), String> {
        match self {
            Self::Wgc { session, .. } => session.stop(),
            Self::Dxgi { .. } => Ok(()),
        }
    }
}

pub struct WindowsCapturer {
    state: CaptureState,
    monitors: Vec<NativeMonitor>,
    active: Option<ActiveCapture>,
    started_at: Option<Instant>,
    limits: CaptureLimits,
}

impl Default for WindowsCapturer {
    fn default() -> Self {
        Self {
            state: CaptureState::Idle,
            monitors: Vec::new(),
            active: None,
            started_at: None,
            limits: CaptureLimits::default(),
        }
    }
}

impl WindowsCapturer {
    pub fn with_limits(limits: CaptureLimits) -> Self {
        let mut capturer = Self::default();
        capturer.limits = limits;
        capturer
    }

    fn enumerate_monitors(&self) -> CaptureResult<Vec<NativeMonitor>> {
        let handles = Monitor::enumerate().map_err(|error| CaptureError::BackendFailure {
            backend: CaptureBackend::WindowsGraphicsCapture,
            operation: "monitor enumeration",
            reason: error.to_string(),
        })?;
        let primary = Monitor::primary().ok();
        let mut monitors = Vec::with_capacity(handles.len());
        for (index, handle) in handles.into_iter().enumerate() {
            let monitor_id = u32::try_from(index + 1).map_err(|_| {
                CaptureError::InvalidFrame(
                    "Windows monitor count exceeds the supported identifier range",
                )
            })?;
            let width = handle
                .width()
                .map_err(|error| CaptureError::BackendFailure {
                    backend: CaptureBackend::WindowsGraphicsCapture,
                    operation: "monitor width query",
                    reason: error.to_string(),
                })?;
            let height = handle
                .height()
                .map_err(|error| CaptureError::BackendFailure {
                    backend: CaptureBackend::WindowsGraphicsCapture,
                    operation: "monitor height query",
                    reason: error.to_string(),
                })?;
            self.limits.validate_dimensions(width, height)?;
            let name = handle
                .name()
                .ok()
                .filter(|name| !name.trim().is_empty())
                .or_else(|| handle.device_name().ok())
                .unwrap_or_else(|| format!("Windows display {monitor_id}"));
            monitors.push(NativeMonitor {
                info: MonitorInfo {
                    monitor_id,
                    name,
                    x: 0,
                    y: 0,
                    width,
                    height,
                    scale_factor_milli: 1_000,
                    is_primary: primary == Some(handle),
                },
                handle,
            });
        }
        if monitors.is_empty() {
            return Err(CaptureError::BackendUnavailable);
        }
        Ok(monitors)
    }

    fn monitor_handle(&self, monitor_id: u32) -> CaptureResult<Monitor> {
        self.monitors
            .iter()
            .find(|monitor| monitor.info.monitor_id == monitor_id)
            .map(|monitor| monitor.handle)
            .ok_or(CaptureError::MonitorNotFound)
    }

    fn activate_wgc_or_dxgi(&mut self, monitor_id: u32) -> CaptureResult<()> {
        if self.active.as_ref().map(ActiveCapture::monitor_id) == Some(monitor_id) {
            return Ok(());
        }
        if let Some(mut active) = self.active.take() {
            let _ = active.stop();
        }
        let monitor = self.monitor_handle(monitor_id)?;
        self.active = Some(match WgcSession::start(monitor) {
            Ok(session) => ActiveCapture::Wgc {
                monitor_id,
                session,
            },
            Err(_) => ActiveCapture::Dxgi {
                monitor_id,
                session: DxgiSession::start(monitor).map_err(|reason| {
                    CaptureError::BackendFailure {
                        backend: CaptureBackend::DxgiDesktopDuplication,
                        operation: "backend startup after WGC fallback",
                        reason,
                    }
                })?,
            },
        });
        Ok(())
    }

    fn fallback_to_dxgi(&mut self, monitor_id: u32, wgc_reason: String) -> CaptureResult<()> {
        if let Some(mut active) = self.active.take() {
            let _ = active.stop();
        }
        let monitor = self.monitor_handle(monitor_id)?;
        let session =
            DxgiSession::start(monitor).map_err(|dxgi_reason| CaptureError::BackendFailure {
                backend: CaptureBackend::DxgiDesktopDuplication,
                operation: "runtime fallback from Windows Graphics Capture",
                reason: format!("WGC: {wgc_reason}; DXGI: {dxgi_reason}"),
            })?;
        self.active = Some(ActiveCapture::Dxgi {
            monitor_id,
            session,
        });
        Ok(())
    }

    fn recreate_dxgi(&mut self, monitor_id: u32) -> CaptureResult<()> {
        self.active.take();
        let monitor = self.monitor_handle(monitor_id)?;
        let session =
            DxgiSession::start(monitor).map_err(|reason| CaptureError::BackendFailure {
                backend: CaptureBackend::DxgiDesktopDuplication,
                operation: "recreate after access loss",
                reason,
            })?;
        self.active = Some(ActiveCapture::Dxgi {
            monitor_id,
            session,
        });
        Ok(())
    }

    fn capture_active(&mut self, monitor_id: u32) -> CaptureResult<RawFrame> {
        let result = match self.active.as_mut() {
            Some(ActiveCapture::Wgc { session, .. }) => {
                session.capture().map_err(EitherFailure::Wgc)
            }
            Some(ActiveCapture::Dxgi { session, .. }) => {
                session.capture().map_err(EitherFailure::Dxgi)
            }
            None => return Err(CaptureError::InvalidState),
        };
        match result {
            Ok(frame) => Ok(frame),
            Err(EitherFailure::Wgc(reason)) => {
                self.fallback_to_dxgi(monitor_id, reason)?;
                self.capture_active(monitor_id)
            }
            Err(EitherFailure::Dxgi(DxgiCaptureFailure::AccessLost)) => {
                self.recreate_dxgi(monitor_id)?;
                match self.active.as_mut() {
                    Some(ActiveCapture::Dxgi { session, .. }) => {
                        session
                            .capture()
                            .map_err(|failure| CaptureError::BackendFailure {
                                backend: CaptureBackend::DxgiDesktopDuplication,
                                operation: "first frame after access-loss recovery",
                                reason: failure.reason(),
                            })
                    }
                    _ => Err(CaptureError::InvalidState),
                }
            }
            Err(EitherFailure::Dxgi(failure)) => Err(CaptureError::BackendFailure {
                backend: CaptureBackend::DxgiDesktopDuplication,
                operation: "frame acquisition",
                reason: failure.reason(),
            }),
        }
    }
}

enum EitherFailure {
    Wgc(String),
    Dxgi(DxgiCaptureFailure),
}

impl DxgiCaptureFailure {
    fn reason(self) -> String {
        match self {
            Self::AccessLost => "DXGI duplication access was lost again".into(),
            Self::Failed(reason) => reason,
        }
    }
}

impl ScreenCapturer for WindowsCapturer {
    fn backend(&self) -> CaptureBackend {
        self.active.as_ref().map_or(
            CaptureBackend::WindowsGraphicsCapture,
            ActiveCapture::backend,
        )
    }

    fn state(&self) -> CaptureState {
        self.state
    }

    fn authorization_state(&self) -> CaptureAuthorizationState {
        CaptureAuthorizationState::NotRequired
    }

    fn start(&mut self) -> CaptureResult<()> {
        if let Some(mut active) = self.active.take() {
            let _ = active.stop();
        }
        self.monitors = self.enumerate_monitors()?;
        self.started_at = Some(Instant::now());
        self.state = CaptureState::Running;
        Ok(())
    }

    fn monitors(&self) -> CaptureResult<Vec<MonitorInfo>> {
        if self.state != CaptureState::Running {
            return Err(CaptureError::InvalidState);
        }
        Ok(self
            .monitors
            .iter()
            .map(|monitor| monitor.info.clone())
            .collect())
    }

    fn capture_frame(&mut self, monitor_id: u32) -> CaptureResult<CapturedFrame> {
        if self.state != CaptureState::Running {
            return Err(CaptureError::InvalidState);
        }
        self.activate_wgc_or_dxgi(monitor_id)?;
        let raw = self.capture_active(monitor_id)?;
        let stride = raw
            .width
            .checked_mul(4)
            .ok_or(CaptureError::InvalidFrame("Windows pixel stride overflow"))?;
        let timestamp_micros = self
            .started_at
            .ok_or(CaptureError::InvalidState)?
            .elapsed()
            .as_micros()
            .min(u128::from(u64::MAX)) as u64;
        CapturedFrame::try_new(
            FrameMetadata {
                monitor_id,
                width: raw.width,
                height: raw.height,
                stride,
                pixel_format: raw.pixel_format,
                timestamp_micros,
            },
            raw.bytes,
            self.limits,
        )
    }

    fn stop(&mut self) -> CaptureResult<()> {
        let stop_result = if let Some(mut active) = self.active.take() {
            active
                .stop()
                .map_err(|reason| CaptureError::BackendFailure {
                    backend: active.backend(),
                    operation: "resource release",
                    reason,
                })
        } else {
            Ok(())
        };
        self.monitors.clear();
        self.started_at = None;
        self.state = CaptureState::Stopped;
        stop_result
    }
}

impl Drop for WindowsCapturer {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
