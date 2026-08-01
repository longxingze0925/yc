use std::collections::{HashMap, HashSet};
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use ashpd::desktop::remote_desktop::{
    DeviceType, KeyState, NotifyKeyboardKeycodeOptions, NotifyKeyboardKeysymOptions,
    NotifyPointerAxisOptions, NotifyPointerButtonOptions, NotifyPointerMotionAbsoluteOptions,
    RemoteDesktop, SelectDevicesOptions,
};
use ashpd::desktop::screencast::{
    CursorMode, Screencast, SelectSourcesOptions, SourceType, Stream as PortalStream,
};
use ashpd::desktop::{PersistMode, ResponseError, Session};
use futures_util::StreamExt;
use pipewire as pw;
use pw::properties::properties;
use pw::spa;
use tokio::sync::mpsc as tokio_mpsc;
use zbus::blocking::{Connection, Proxy};

use crate::{
    CaptureAuthorizationState, CaptureBackend, CaptureError, CaptureLimits, CaptureResult,
    CaptureState, CapturedFrame, FrameMetadata, MonitorInfo, PixelFormat, ScreenCapturer,
};

const PORTAL_DESTINATION: &str = "org.freedesktop.portal.Desktop";
const PORTAL_PATH: &str = "/org/freedesktop/portal/desktop";
const SCREEN_CAST_INTERFACE: &str = "org.freedesktop.portal.ScreenCast";
const REMOTE_DESKTOP_INTERFACE: &str = "org.freedesktop.portal.RemoteDesktop";
const SOURCE_TYPE_MONITOR: u32 = 1;
const CURSOR_MODE_HIDDEN: u32 = 1;
const CURSOR_MODE_EMBEDDED: u32 = 2;
const DEVICE_TYPE_KEYBOARD: u32 = 1;
const DEVICE_TYPE_POINTER: u32 = 2;
const MAX_PORTAL_STREAMS: usize = 16;
const PIPEWIRE_START_TIMEOUT: Duration = Duration::from_secs(10);
const PORTAL_INPUT_TIMEOUT: Duration = Duration::from_secs(5);

static NEXT_PORTAL_SESSION_ID: AtomicU64 = AtomicU64::new(1);
static ACTIVE_PORTAL_INPUT: OnceLock<Mutex<Option<ActivePortalInput>>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortalCapability {
    NotChecked,
    Available {
        version: u32,
        source_types: u32,
        cursor_modes: u32,
        remote_desktop_version: u32,
        device_types: u32,
    },
    Unavailable {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortalSessionState {
    NotRequested,
    ReadyForUserAuthorization,
    RequestingUserAuthorization,
    Active { stream_count: usize },
    Denied,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaylandPortalStatus {
    pub capability: PortalCapability,
    pub session: PortalSessionState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortalInputError {
    SessionInactive,
    InvalidInput(&'static str),
    PortalFailure(String),
    TimedOut,
}

impl std::fmt::Display for PortalInputError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionInactive => {
                formatter.write_str("Wayland RemoteDesktop portal session is inactive")
            }
            Self::InvalidInput(reason) => {
                write!(formatter, "Wayland portal input is invalid: {reason}")
            }
            Self::PortalFailure(reason) => write!(
                formatter,
                "Wayland RemoteDesktop portal input failed: {reason}"
            ),
            Self::TimedOut => formatter.write_str("Wayland RemoteDesktop portal input timed out"),
        }
    }
}

impl std::error::Error for PortalInputError {}

#[derive(Debug, Clone, Default)]
pub struct UbuntuWaylandPortalInput;

impl UbuntuWaylandPortalInput {
    pub fn is_active(&self) -> bool {
        active_portal_input()
            .lock()
            .ok()
            .and_then(|active| {
                active
                    .as_ref()
                    .map(|active| active.active.load(Ordering::Acquire))
            })
            .unwrap_or(false)
    }

    pub fn keycode(&self, keycode: i32, pressed: bool) -> Result<(), PortalInputError> {
        if keycode <= 0 {
            return Err(PortalInputError::InvalidInput(
                "evdev keycode must be positive",
            ));
        }
        self.dispatch(|response| PortalCommand::Keycode {
            keycode,
            pressed,
            response,
        })
    }

    pub fn button(&self, button: i32, pressed: bool) -> Result<(), PortalInputError> {
        if button <= 0 {
            return Err(PortalInputError::InvalidInput(
                "evdev pointer button must be positive",
            ));
        }
        self.dispatch(|response| PortalCommand::Button {
            button,
            pressed,
            response,
        })
    }

    pub fn move_pointer(&self, x_norm: f64, y_norm: f64) -> Result<(), PortalInputError> {
        if !x_norm.is_finite()
            || !y_norm.is_finite()
            || !(0.0..=1.0).contains(&x_norm)
            || !(0.0..=1.0).contains(&y_norm)
        {
            return Err(PortalInputError::InvalidInput(
                "pointer coordinates must be finite normalized values",
            ));
        }
        self.dispatch(|response| PortalCommand::PointerMove {
            x_norm,
            y_norm,
            response,
        })
    }

    pub fn wheel(&self, delta_x: f64, delta_y: f64) -> Result<(), PortalInputError> {
        if !delta_x.is_finite() || !delta_y.is_finite() {
            return Err(PortalInputError::InvalidInput(
                "wheel deltas must be finite",
            ));
        }
        self.dispatch(|response| PortalCommand::PointerAxis {
            delta_x,
            delta_y,
            response,
        })
    }

    pub fn text_commit(&self, text: &str) -> Result<(), PortalInputError> {
        if text.is_empty() {
            return Err(PortalInputError::InvalidInput("text commit is empty"));
        }
        self.dispatch(|response| PortalCommand::TextCommit {
            text: text.to_owned(),
            response,
        })
    }

    pub fn release_all(&self) -> Result<(), PortalInputError> {
        if !self.is_active() {
            return Ok(());
        }
        self.dispatch(|response| PortalCommand::ReleaseAll { response })
    }

    fn dispatch(
        &self,
        command: impl FnOnce(mpsc::SyncSender<PortalCommandResult>) -> PortalCommand,
    ) -> Result<(), PortalInputError> {
        let active = active_portal_input()
            .lock()
            .map_err(|_| PortalInputError::SessionInactive)?
            .as_ref()
            .filter(|active| active.active.load(Ordering::Acquire))
            .cloned()
            .ok_or(PortalInputError::SessionInactive)?;
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        active
            .sender
            .send(command(response_sender))
            .map_err(|_| PortalInputError::SessionInactive)?;
        response_receiver
            .recv_timeout(PORTAL_INPUT_TIMEOUT)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => PortalInputError::TimedOut,
                mpsc::RecvTimeoutError::Disconnected => PortalInputError::SessionInactive,
            })?
            .map_err(PortalInputError::PortalFailure)
    }
}

type PortalCommandResult = Result<(), String>;

#[derive(Clone)]
struct ActivePortalInput {
    session_id: u64,
    sender: tokio_mpsc::UnboundedSender<PortalCommand>,
    active: Arc<AtomicBool>,
}

fn active_portal_input() -> &'static Mutex<Option<ActivePortalInput>> {
    ACTIVE_PORTAL_INPUT.get_or_init(|| Mutex::new(None))
}

fn register_portal_input(active: ActivePortalInput) -> CaptureResult<()> {
    let mut slot = active_portal_input()
        .lock()
        .map_err(|_| backend_failure("register portal input", "active input lock was poisoned"))?;
    if slot
        .as_ref()
        .is_some_and(|current| current.active.load(Ordering::Acquire))
    {
        return Err(CaptureError::BackendFailure {
            backend: CaptureBackend::UbuntuWaylandPipeWire,
            operation: "register portal input",
            reason: "another Wayland RemoteDesktop portal session is already active".into(),
        });
    }
    *slot = Some(active);
    Ok(())
}

fn unregister_portal_input(session_id: u64) {
    if let Ok(mut slot) = active_portal_input().lock() {
        if slot
            .as_ref()
            .is_some_and(|active| active.session_id == session_id)
        {
            *slot = None;
        }
    }
}

enum PortalCommand {
    Keycode {
        keycode: i32,
        pressed: bool,
        response: mpsc::SyncSender<PortalCommandResult>,
    },
    Button {
        button: i32,
        pressed: bool,
        response: mpsc::SyncSender<PortalCommandResult>,
    },
    PointerMove {
        x_norm: f64,
        y_norm: f64,
        response: mpsc::SyncSender<PortalCommandResult>,
    },
    PointerAxis {
        delta_x: f64,
        delta_y: f64,
        response: mpsc::SyncSender<PortalCommandResult>,
    },
    TextCommit {
        text: String,
        response: mpsc::SyncSender<PortalCommandResult>,
    },
    ReleaseAll {
        response: mpsc::SyncSender<PortalCommandResult>,
    },
    Close {
        response: mpsc::SyncSender<PortalCommandResult>,
    },
}

pub struct UbuntuWaylandPortalCapturer {
    state: CaptureState,
    status: WaylandPortalStatus,
    limits: CaptureLimits,
    portal_worker: Option<PortalWorker>,
    pipewire_consumer: Option<PipeWireConsumer>,
}

impl std::fmt::Debug for UbuntuWaylandPortalCapturer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UbuntuWaylandPortalCapturer")
            .field("state", &self.state)
            .field("status", &self.status)
            .field("limits", &self.limits)
            .field("portal_session_open", &self.portal_worker.is_some())
            .field("pipewire_running", &self.pipewire_consumer.is_some())
            .finish()
    }
}

impl Default for UbuntuWaylandPortalCapturer {
    fn default() -> Self {
        Self::new(CaptureLimits::default())
    }
}

impl UbuntuWaylandPortalCapturer {
    pub fn new(limits: CaptureLimits) -> Self {
        Self {
            state: CaptureState::Idle,
            status: WaylandPortalStatus {
                capability: PortalCapability::NotChecked,
                session: PortalSessionState::NotRequested,
            },
            limits,
            portal_worker: None,
            pipewire_consumer: None,
        }
    }

    pub fn portal_status(&self) -> &WaylandPortalStatus {
        &self.status
    }

    /// Queries the real desktop portal over the user's D-Bus session without
    /// opening a RemoteDesktop/ScreenCast session or triggering a permission prompt.
    pub fn probe_portal(&mut self) -> CaptureResult<WaylandPortalStatus> {
        let result = self.probe_portal_inner();
        match result {
            Ok(status) => {
                self.status = status.clone();
                Ok(status)
            }
            Err(error) => {
                self.status = WaylandPortalStatus {
                    capability: PortalCapability::Unavailable {
                        reason: error.to_string(),
                    },
                    session: PortalSessionState::NotRequested,
                };
                Err(error)
            }
        }
    }

    fn probe_portal_inner(&self) -> CaptureResult<WaylandPortalStatus> {
        let connection = Connection::session().map_err(|error| portal_failure("connect", error))?;
        let screencast_proxy = Proxy::new(
            &connection,
            PORTAL_DESTINATION,
            PORTAL_PATH,
            SCREEN_CAST_INTERFACE,
        )
        .map_err(|error| portal_failure("create ScreenCast proxy", error))?;
        let version = screencast_proxy
            .get_property::<u32>("version")
            .map_err(|error| portal_failure("read ScreenCast portal version", error))?;
        let source_types = screencast_proxy
            .get_property::<u32>("AvailableSourceTypes")
            .map_err(|error| portal_failure("read available source types", error))?;
        let cursor_modes = screencast_proxy
            .get_property::<u32>("AvailableCursorModes")
            .map_err(|error| portal_failure("read available cursor modes", error))?;
        let remote_desktop_proxy = Proxy::new(
            &connection,
            PORTAL_DESTINATION,
            PORTAL_PATH,
            REMOTE_DESKTOP_INTERFACE,
        )
        .map_err(|error| portal_failure("create RemoteDesktop proxy", error))?;
        let remote_desktop_version = remote_desktop_proxy
            .get_property::<u32>("version")
            .map_err(|error| portal_failure("read RemoteDesktop portal version", error))?;
        let device_types = remote_desktop_proxy
            .get_property::<u32>("AvailableDeviceTypes")
            .map_err(|error| portal_failure("read available remote desktop devices", error))?;

        if source_types & SOURCE_TYPE_MONITOR == 0 {
            return Err(CaptureError::Unsupported {
                backend: CaptureBackend::UbuntuWaylandPipeWire,
                reason: format!(
                    "the compositor portal exposes source mask {source_types:#x} without monitor capture"
                ),
            });
        }
        if cursor_modes & (CURSOR_MODE_EMBEDDED | CURSOR_MODE_HIDDEN) == 0 {
            return Err(CaptureError::Unsupported {
                backend: CaptureBackend::UbuntuWaylandPipeWire,
                reason: format!(
                    "the compositor portal exposes unsupported cursor mode mask {cursor_modes:#x}"
                ),
            });
        }
        let required_devices = DEVICE_TYPE_KEYBOARD | DEVICE_TYPE_POINTER;
        if device_types & required_devices != required_devices {
            return Err(CaptureError::Unsupported {
                backend: CaptureBackend::UbuntuWaylandPipeWire,
                reason: format!(
                    "the compositor RemoteDesktop portal exposes device mask {device_types:#x} without keyboard and pointer control"
                ),
            });
        }

        Ok(WaylandPortalStatus {
            capability: PortalCapability::Available {
                version,
                source_types,
                cursor_modes,
                remote_desktop_version,
                device_types,
            },
            session: PortalSessionState::ReadyForUserAuthorization,
        })
    }

    fn cursor_mode(&self) -> CaptureResult<CursorMode> {
        let PortalCapability::Available { cursor_modes, .. } = self.status.capability else {
            return Err(CaptureError::InvalidState);
        };
        if cursor_modes & CURSOR_MODE_EMBEDDED != 0 {
            Ok(CursorMode::Embedded)
        } else if cursor_modes & CURSOR_MODE_HIDDEN != 0 {
            Ok(CursorMode::Hidden)
        } else {
            Err(CaptureError::Unsupported {
                backend: CaptureBackend::UbuntuWaylandPipeWire,
                reason: "the portal offers neither embedded nor hidden cursor mode".into(),
            })
        }
    }

    fn mark_start_failure(&mut self, error: &CaptureError) {
        self.state = CaptureState::Stopped;
        self.status.session = if matches!(error, CaptureError::PermissionDenied) {
            PortalSessionState::Denied
        } else {
            PortalSessionState::Closed
        };
    }
}

impl ScreenCapturer for UbuntuWaylandPortalCapturer {
    fn backend(&self) -> CaptureBackend {
        CaptureBackend::UbuntuWaylandPipeWire
    }

    fn state(&self) -> CaptureState {
        self.state
    }

    fn authorization_state(&self) -> CaptureAuthorizationState {
        if matches!(self.status.session, PortalSessionState::Active { .. })
            && self
                .portal_worker
                .as_ref()
                .is_some_and(|worker| !worker.is_active())
        {
            return CaptureAuthorizationState::Unavailable;
        }
        match (&self.status.capability, &self.status.session) {
            (PortalCapability::NotChecked, _) => CaptureAuthorizationState::NotChecked,
            (PortalCapability::Unavailable { .. }, _) => CaptureAuthorizationState::Unavailable,
            (_, PortalSessionState::ReadyForUserAuthorization) => {
                CaptureAuthorizationState::Required
            }
            (_, PortalSessionState::RequestingUserAuthorization) => {
                CaptureAuthorizationState::Requesting
            }
            (_, PortalSessionState::Active { .. }) => CaptureAuthorizationState::Granted,
            (_, PortalSessionState::Denied) => CaptureAuthorizationState::Denied,
            (_, PortalSessionState::Closed) => CaptureAuthorizationState::Unavailable,
            (_, PortalSessionState::NotRequested) => CaptureAuthorizationState::NotChecked,
        }
    }

    fn start(&mut self) -> CaptureResult<()> {
        if self.state == CaptureState::Running {
            return Ok(());
        }

        if let Err(error) = self.probe_portal() {
            self.mark_start_failure(&error);
            return Err(error);
        }
        let cursor_mode = self.cursor_mode()?;
        self.status.session = PortalSessionState::RequestingUserAuthorization;

        let (mut portal_worker, remote_fd, streams) = match PortalWorker::start(cursor_mode) {
            Ok(started) => started,
            Err(error) => {
                self.mark_start_failure(&error);
                return Err(error);
            }
        };
        if streams.is_empty() || streams.len() > MAX_PORTAL_STREAMS {
            let _ = portal_worker.stop();
            let error = CaptureError::Unsupported {
                backend: CaptureBackend::UbuntuWaylandPipeWire,
                reason: format!(
                    "the portal returned {} streams; expected between 1 and {MAX_PORTAL_STREAMS}",
                    streams.len()
                ),
            };
            self.mark_start_failure(&error);
            return Err(error);
        }

        let pipewire_consumer = match PipeWireConsumer::start(remote_fd, streams, self.limits) {
            Ok(consumer) => consumer,
            Err(error) => {
                let _ = portal_worker.stop();
                self.mark_start_failure(&error);
                return Err(error);
            }
        };
        let stream_count = pipewire_consumer.stream_count();
        self.portal_worker = Some(portal_worker);
        self.pipewire_consumer = Some(pipewire_consumer);
        self.status.session = PortalSessionState::Active { stream_count };
        self.state = CaptureState::Running;
        Ok(())
    }

    fn monitors(&self) -> CaptureResult<Vec<MonitorInfo>> {
        if self.state != CaptureState::Running {
            return Err(CaptureError::InvalidState);
        }
        if self
            .portal_worker
            .as_ref()
            .is_some_and(|worker| !worker.is_active())
        {
            return Err(CaptureError::BackendUnavailable);
        }
        self.pipewire_consumer
            .as_ref()
            .ok_or(CaptureError::InvalidState)?
            .monitors()
    }

    fn capture_frame(&mut self, monitor_id: u32) -> CaptureResult<CapturedFrame> {
        if self.state != CaptureState::Running {
            return Err(CaptureError::InvalidState);
        }
        if self
            .portal_worker
            .as_ref()
            .is_some_and(|worker| !worker.is_active())
        {
            let _ = self.stop();
            return Err(CaptureError::BackendUnavailable);
        }
        self.pipewire_consumer
            .as_ref()
            .ok_or(CaptureError::InvalidState)?
            .capture_frame(monitor_id)
    }

    fn stop(&mut self) -> CaptureResult<()> {
        let pipewire_result = self
            .pipewire_consumer
            .take()
            .map_or(Ok(()), |mut consumer| consumer.stop());
        let portal_result = self
            .portal_worker
            .take()
            .map_or(Ok(()), |mut worker| worker.stop());
        self.state = CaptureState::Stopped;
        self.status.session = PortalSessionState::Closed;
        pipewire_result.and(portal_result)
    }
}

impl Drop for UbuntuWaylandPortalCapturer {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

#[derive(Debug, Clone)]
struct PortalStreamDescriptor {
    monitor_id: u32,
    name: String,
    position: (i32, i32),
    portal_size: Option<(u32, u32)>,
    is_primary: bool,
}

impl PortalStreamDescriptor {
    fn from_portal(stream: &PortalStream, index: usize) -> CaptureResult<Self> {
        if stream
            .source_type()
            .is_some_and(|source| source != SourceType::Monitor)
        {
            return Err(CaptureError::Unsupported {
                backend: CaptureBackend::UbuntuWaylandPipeWire,
                reason: "the ScreenCast portal returned a non-monitor stream".into(),
            });
        }
        let portal_size = stream
            .size()
            .map(|(width, height)| {
                let width = u32::try_from(width).map_err(|_| {
                    CaptureError::InvalidFrame("portal stream width must be positive")
                })?;
                let height = u32::try_from(height).map_err(|_| {
                    CaptureError::InvalidFrame("portal stream height must be positive")
                })?;
                if width == 0 || height == 0 {
                    return Err(CaptureError::InvalidFrame(
                        "portal stream dimensions must be non-zero",
                    ));
                }
                Ok((width, height))
            })
            .transpose()?;
        Ok(Self {
            monitor_id: stream.pipe_wire_node_id(),
            name: stream
                .id()
                .filter(|id| !id.is_empty())
                .map_or_else(|| format!("Wayland monitor {}", index + 1), str::to_owned),
            position: stream.position().unwrap_or((0, 0)),
            portal_size,
            is_primary: index == 0,
        })
    }

    fn monitor_info(&self, width: u32, height: u32) -> MonitorInfo {
        MonitorInfo {
            monitor_id: self.monitor_id,
            name: self.name.clone(),
            x: self.position.0,
            y: self.position.1,
            width,
            height,
            scale_factor_milli: 1_000,
            is_primary: self.is_primary,
        }
    }
}

struct PortalWorker {
    session_id: u64,
    command_sender: Option<tokio_mpsc::UnboundedSender<PortalCommand>>,
    join_handle: Option<JoinHandle<Result<(), String>>>,
    active: Arc<AtomicBool>,
}

impl PortalWorker {
    fn start(
        cursor_mode: CursorMode,
    ) -> CaptureResult<(Self, OwnedFd, Vec<PortalStreamDescriptor>)> {
        let session_id = NEXT_PORTAL_SESSION_ID.fetch_add(1, Ordering::Relaxed);
        let (setup_sender, setup_receiver) = mpsc::sync_channel(1);
        let (command_sender, command_receiver) = tokio_mpsc::unbounded_channel();
        let active = Arc::new(AtomicBool::new(true));
        let worker_active = Arc::clone(&active);
        let join_handle = thread::Builder::new()
            .name("remote-capture-portal".into())
            .spawn(move || {
                portal_thread(
                    session_id,
                    cursor_mode,
                    setup_sender,
                    command_receiver,
                    worker_active,
                )
            })
            .map_err(|error| backend_failure("spawn portal worker", error))?;

        match setup_receiver.recv() {
            Ok(Ok((remote_fd, streams))) => {
                let mut worker = Self {
                    session_id,
                    command_sender: Some(command_sender.clone()),
                    join_handle: Some(join_handle),
                    active: Arc::clone(&active),
                };
                if let Err(error) = register_portal_input(ActivePortalInput {
                    session_id,
                    sender: command_sender,
                    active,
                }) {
                    let _ = worker.stop();
                    return Err(error);
                }
                Ok((worker, remote_fd, streams))
            }
            Ok(Err(failure)) => {
                active.store(false, Ordering::Release);
                let _ = join_handle.join();
                Err(failure.into_capture_error())
            }
            Err(error) => {
                active.store(false, Ordering::Release);
                let _ = join_handle.join();
                Err(backend_failure("receive portal setup", error))
            }
        }
    }

    fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    fn stop(&mut self) -> CaptureResult<()> {
        unregister_portal_input(self.session_id);
        let command_result = if self.active.swap(false, Ordering::AcqRel) {
            self.command_sender.take().map_or(Ok(()), |sender| {
                let (response_sender, response_receiver) = mpsc::sync_channel(1);
                if sender
                    .send(PortalCommand::Close {
                        response: response_sender,
                    })
                    .is_err()
                {
                    return Ok(());
                }
                match response_receiver.recv_timeout(PORTAL_INPUT_TIMEOUT) {
                    Ok(result) => result.map_err(|reason| CaptureError::BackendFailure {
                        backend: CaptureBackend::UbuntuWaylandPipeWire,
                        operation: "close portal session",
                        reason,
                    }),
                    Err(mpsc::RecvTimeoutError::Disconnected) => Ok(()),
                    Err(mpsc::RecvTimeoutError::Timeout) => Err(backend_failure(
                        "close portal session",
                        "portal worker did not acknowledge close before the timeout",
                    )),
                }
            })
        } else {
            self.command_sender.take();
            Ok(())
        };
        let join_result = if let Some(join_handle) = self.join_handle.take() {
            match join_handle.join() {
                Ok(Ok(())) => Ok(()),
                Ok(Err(reason)) => Err(CaptureError::BackendFailure {
                    backend: CaptureBackend::UbuntuWaylandPipeWire,
                    operation: "close portal session",
                    reason,
                }),
                Err(_) => Err(CaptureError::BackendFailure {
                    backend: CaptureBackend::UbuntuWaylandPipeWire,
                    operation: "join portal worker",
                    reason: "portal worker panicked".into(),
                }),
            }
        } else {
            Ok(())
        };
        match (command_result, join_result) {
            (Err(error), _) | (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }
}

impl Drop for PortalWorker {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

enum PortalStartFailure {
    Denied,
    Failed(String),
}

impl PortalStartFailure {
    fn from_error(error: ashpd::Error) -> Self {
        if matches!(
            error,
            ashpd::Error::Response(ResponseError::Cancelled | ResponseError::Other)
                | ashpd::Error::Portal(
                    ashpd::PortalError::Cancelled(_) | ashpd::PortalError::NotAllowed(_)
                )
        ) {
            Self::Denied
        } else {
            Self::Failed(error.to_string())
        }
    }

    fn into_capture_error(self) -> CaptureError {
        match self {
            Self::Denied => CaptureError::PermissionDenied,
            Self::Failed(reason) => CaptureError::BackendFailure {
                backend: CaptureBackend::UbuntuWaylandPipeWire,
                operation: "authorize portal RemoteDesktop session",
                reason,
            },
        }
    }
}

fn portal_thread(
    session_id: u64,
    cursor_mode: CursorMode,
    setup_sender: mpsc::SyncSender<
        Result<(OwnedFd, Vec<PortalStreamDescriptor>), PortalStartFailure>,
    >,
    command_receiver: tokio_mpsc::UnboundedReceiver<PortalCommand>,
    active: Arc<AtomicBool>,
) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    let opened = runtime.block_on(open_portal_session(cursor_mode));
    let (remote_desktop, screencast, session, remote_fd, streams) = match opened {
        Ok(opened) => opened,
        Err(error) => {
            active.store(false, Ordering::Release);
            let _ = setup_sender.send(Err(PortalStartFailure::from_error(error)));
            return Ok(());
        }
    };
    let input_target = PortalInputTarget::from_streams(&streams);
    if setup_sender.send(Ok((remote_fd, streams))).is_err() {
        active.store(false, Ordering::Release);
        return runtime
            .block_on(session.close())
            .map_err(|error| error.to_string());
    }

    let result = runtime.block_on(run_portal_session(
        &remote_desktop,
        &session,
        input_target,
        command_receiver,
    ));
    active.store(false, Ordering::Release);
    unregister_portal_input(session_id);
    drop(screencast);
    result
}

async fn open_portal_session(
    cursor_mode: CursorMode,
) -> Result<
    (
        RemoteDesktop,
        Screencast,
        Session<RemoteDesktop>,
        OwnedFd,
        Vec<PortalStreamDescriptor>,
    ),
    ashpd::Error,
> {
    let remote_desktop = RemoteDesktop::new().await?;
    let screencast = Screencast::new().await?;
    let session = remote_desktop.create_session(Default::default()).await?;
    let open_result = async {
        remote_desktop
            .select_devices(
                &session,
                SelectDevicesOptions::default()
                    .set_devices(DeviceType::Keyboard | DeviceType::Pointer)
                    .set_persist_mode(PersistMode::DoNot),
            )
            .await?
            .response()?;
        screencast
            .select_sources(
                &session,
                SelectSourcesOptions::default()
                    .set_cursor_mode(cursor_mode)
                    .set_sources(enumflags2::BitFlags::from(SourceType::Monitor))
                    .set_multiple(true)
                    .set_persist_mode(PersistMode::DoNot),
            )
            .await?
            .response()?;
        let response = remote_desktop
            .start(&session, None, Default::default())
            .await?
            .response()?;
        let required_devices = DeviceType::Keyboard | DeviceType::Pointer;
        if !response.devices().contains(required_devices) {
            return Err(ashpd::Error::IO(std::io::Error::other(format!(
                "the user-authorized portal session omitted required input devices: {:?}",
                response.devices()
            ))));
        }
        let streams = response
            .streams()
            .iter()
            .enumerate()
            .map(|(index, stream)| PortalStreamDescriptor::from_portal(stream, index))
            .collect::<CaptureResult<Vec<_>>>()
            .map_err(|error| ashpd::Error::IO(std::io::Error::other(error)))?;
        let remote_fd = screencast
            .open_pipe_wire_remote(&session, Default::default())
            .await?;
        Ok((remote_fd, streams))
    }
    .await;

    match open_result {
        Ok((remote_fd, streams)) => Ok((remote_desktop, screencast, session, remote_fd, streams)),
        Err(error) => {
            let _ = session.close().await;
            Err(error)
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct PortalInputTarget {
    stream_id: u32,
    width: u32,
    height: u32,
}

impl PortalInputTarget {
    fn from_streams(streams: &[PortalStreamDescriptor]) -> Option<Self> {
        let stream = streams
            .iter()
            .find(|stream| stream.is_primary)
            .or_else(|| streams.first())?;
        let (width, height) = stream.portal_size?;
        Some(Self {
            stream_id: stream.monitor_id,
            width,
            height,
        })
    }

    fn coordinates(self, x_norm: f64, y_norm: f64) -> (f64, f64) {
        (
            x_norm * f64::from(self.width.saturating_sub(1)),
            y_norm * f64::from(self.height.saturating_sub(1)),
        )
    }
}

#[derive(Default)]
struct PortalPressedInputs {
    keycodes: HashSet<i32>,
    keysyms: HashSet<i32>,
    buttons: HashSet<i32>,
}

async fn run_portal_session(
    remote_desktop: &RemoteDesktop,
    session: &Session<RemoteDesktop>,
    input_target: Option<PortalInputTarget>,
    mut command_receiver: tokio_mpsc::UnboundedReceiver<PortalCommand>,
) -> Result<(), String> {
    let mut closed = session
        .receive_closed()
        .await
        .map_err(|error| error.to_string())?;
    let mut pressed = PortalPressedInputs::default();
    loop {
        tokio::select! {
            _ = closed.next() => {
                return Ok(());
            }
            command = command_receiver.recv() => {
                let Some(command) = command else {
                    let _ = release_portal_inputs(remote_desktop, session, &mut pressed).await;
                    return session.close().await.map_err(|error| error.to_string());
                };
                match command {
                    PortalCommand::Keycode { keycode, pressed: is_pressed, response } => {
                        let result = notify_portal_keycode(
                            remote_desktop,
                            session,
                            &mut pressed,
                            keycode,
                            is_pressed,
                        ).await;
                        let _ = response.send(result);
                    }
                    PortalCommand::Button { button, pressed: is_pressed, response } => {
                        let result = notify_portal_button(
                            remote_desktop,
                            session,
                            &mut pressed,
                            button,
                            is_pressed,
                        ).await;
                        let _ = response.send(result);
                    }
                    PortalCommand::PointerMove { x_norm, y_norm, response } => {
                        let result = match input_target {
                            Some(target) => {
                                let (x, y) = target.coordinates(x_norm, y_norm);
                                remote_desktop
                                    .notify_pointer_motion_absolute(
                                        session,
                                        target.stream_id,
                                        x,
                                        y,
                                        NotifyPointerMotionAbsoluteOptions::default(),
                                    )
                                    .await
                                    .map_err(|error| error.to_string())
                            }
                            None => Err("the portal did not provide logical monitor dimensions for absolute pointer input".into()),
                        };
                        let _ = response.send(result);
                    }
                    PortalCommand::PointerAxis { delta_x, delta_y, response } => {
                        let result = remote_desktop
                            .notify_pointer_axis(
                                session,
                                delta_x,
                                delta_y,
                                NotifyPointerAxisOptions::default().set_finish(true),
                            )
                            .await
                            .map_err(|error| error.to_string());
                        let _ = response.send(result);
                    }
                    PortalCommand::TextCommit { text, response } => {
                        let result = notify_portal_text(
                            remote_desktop,
                            session,
                            &mut pressed,
                            &text,
                        ).await;
                        let _ = response.send(result);
                    }
                    PortalCommand::ReleaseAll { response } => {
                        let result = release_portal_inputs(remote_desktop, session, &mut pressed).await;
                        let _ = response.send(result);
                    }
                    PortalCommand::Close { response } => {
                        let release_result = release_portal_inputs(remote_desktop, session, &mut pressed).await;
                        let close_result = session.close().await.map_err(|error| error.to_string());
                        let result = release_result.and(close_result);
                        let _ = response.send(result);
                        return Ok(());
                    }
                }
            }
        }
    }
}

async fn notify_portal_keycode(
    remote_desktop: &RemoteDesktop,
    session: &Session<RemoteDesktop>,
    pressed: &mut PortalPressedInputs,
    keycode: i32,
    is_pressed: bool,
) -> PortalCommandResult {
    remote_desktop
        .notify_keyboard_keycode(
            session,
            keycode,
            if is_pressed {
                KeyState::Pressed
            } else {
                KeyState::Released
            },
            NotifyKeyboardKeycodeOptions::default(),
        )
        .await
        .map_err(|error| error.to_string())?;
    if is_pressed {
        pressed.keycodes.insert(keycode);
    } else {
        pressed.keycodes.remove(&keycode);
    }
    Ok(())
}

async fn notify_portal_button(
    remote_desktop: &RemoteDesktop,
    session: &Session<RemoteDesktop>,
    pressed: &mut PortalPressedInputs,
    button: i32,
    is_pressed: bool,
) -> PortalCommandResult {
    remote_desktop
        .notify_pointer_button(
            session,
            button,
            if is_pressed {
                KeyState::Pressed
            } else {
                KeyState::Released
            },
            NotifyPointerButtonOptions::default(),
        )
        .await
        .map_err(|error| error.to_string())?;
    if is_pressed {
        pressed.buttons.insert(button);
    } else {
        pressed.buttons.remove(&button);
    }
    Ok(())
}

async fn notify_portal_text(
    remote_desktop: &RemoteDesktop,
    session: &Session<RemoteDesktop>,
    pressed: &mut PortalPressedInputs,
    text: &str,
) -> PortalCommandResult {
    for character in text.chars() {
        let keysym = unicode_keysym(character)?;
        remote_desktop
            .notify_keyboard_keysym(
                session,
                keysym,
                KeyState::Pressed,
                NotifyKeyboardKeysymOptions::default(),
            )
            .await
            .map_err(|error| error.to_string())?;
        pressed.keysyms.insert(keysym);
        if let Err(error) = remote_desktop
            .notify_keyboard_keysym(
                session,
                keysym,
                KeyState::Released,
                NotifyKeyboardKeysymOptions::default(),
            )
            .await
        {
            let _ = release_portal_inputs(remote_desktop, session, pressed).await;
            return Err(error.to_string());
        }
        pressed.keysyms.remove(&keysym);
    }
    Ok(())
}

fn unicode_keysym(character: char) -> Result<i32, String> {
    let keysym = match character {
        '\n' | '\r' => 0xff0d,
        '\t' => 0xff09,
        character if character.is_control() => {
            return Err("text commit contains an unsupported control character".into());
        }
        character if u32::from(character) <= 0xff => u32::from(character),
        character => 0x0100_0000 | u32::from(character),
    };
    i32::try_from(keysym).map_err(|_| "text commit keysym exceeds the portal range".into())
}

async fn release_portal_inputs(
    remote_desktop: &RemoteDesktop,
    session: &Session<RemoteDesktop>,
    pressed: &mut PortalPressedInputs,
) -> PortalCommandResult {
    let mut failure = None;
    for keysym in pressed.keysyms.drain() {
        if let Err(error) = remote_desktop
            .notify_keyboard_keysym(
                session,
                keysym,
                KeyState::Released,
                NotifyKeyboardKeysymOptions::default(),
            )
            .await
        {
            failure.get_or_insert_with(|| error.to_string());
        }
    }
    for keycode in pressed.keycodes.drain() {
        if let Err(error) = remote_desktop
            .notify_keyboard_keycode(
                session,
                keycode,
                KeyState::Released,
                NotifyKeyboardKeycodeOptions::default(),
            )
            .await
        {
            failure.get_or_insert_with(|| error.to_string());
        }
    }
    for button in pressed.buttons.drain() {
        if let Err(error) = remote_desktop
            .notify_pointer_button(
                session,
                button,
                KeyState::Released,
                NotifyPointerButtonOptions::default(),
            )
            .await
        {
            failure.get_or_insert_with(|| error.to_string());
        }
    }
    failure.map_or(Ok(()), Err)
}

struct PipeWireConsumer {
    stop_sender: Option<pw::channel::Sender<()>>,
    join_handle: Option<JoinHandle<Result<(), String>>>,
    monitors: Arc<Mutex<HashMap<u32, MonitorInfo>>>,
    frame_slots: HashMap<u32, Arc<Mutex<Option<CaptureResult<CapturedFrame>>>>>,
    healthy: Arc<AtomicBool>,
}

impl PipeWireConsumer {
    fn start(
        remote_fd: OwnedFd,
        streams: Vec<PortalStreamDescriptor>,
        limits: CaptureLimits,
    ) -> CaptureResult<Self> {
        let mut monitor_ids = HashSet::with_capacity(streams.len());
        let mut initial_monitors = HashMap::with_capacity(streams.len());
        let mut frame_slots = HashMap::with_capacity(streams.len());
        for stream in &streams {
            if !monitor_ids.insert(stream.monitor_id) {
                return Err(CaptureError::InvalidFrame(
                    "portal returned duplicate PipeWire node IDs",
                ));
            }
            let (width, height) = stream.portal_size.unwrap_or((1, 1));
            limits.validate_dimensions(width, height)?;
            initial_monitors.insert(stream.monitor_id, stream.monitor_info(width, height));
            frame_slots.insert(stream.monitor_id, Arc::new(Mutex::new(None)));
        }

        let monitors = Arc::new(Mutex::new(initial_monitors));
        let healthy = Arc::new(AtomicBool::new(false));
        let (startup_sender, startup_receiver) = mpsc::channel();
        let (stop_sender, stop_receiver) = pw::channel::channel();
        let thread_monitors = Arc::clone(&monitors);
        let thread_slots = frame_slots.clone();
        let thread_healthy = Arc::clone(&healthy);
        let join_handle = thread::Builder::new()
            .name("remote-capture-pipewire".into())
            .spawn(move || {
                let result = run_pipewire(PipeWireRuntime {
                    remote_fd,
                    descriptors: streams,
                    limits,
                    monitors: thread_monitors,
                    frame_slots: thread_slots,
                    healthy: Arc::clone(&thread_healthy),
                    startup_sender: startup_sender.clone(),
                    stop_receiver,
                });
                if let Err(reason) = &result {
                    thread_healthy.store(false, Ordering::Release);
                    let _ = startup_sender.send(PipeWireStartupEvent::Failed(reason.clone()));
                }
                result
            })
            .map_err(|error| backend_failure("spawn PipeWire consumer", error))?;

        let mut ready = HashSet::with_capacity(monitor_ids.len());
        let deadline = Instant::now() + PIPEWIRE_START_TIMEOUT;
        while ready.len() < monitor_ids.len() {
            let timeout = deadline.saturating_duration_since(Instant::now());
            let event = startup_receiver.recv_timeout(timeout).map_err(|error| {
                CaptureError::BackendFailure {
                    backend: CaptureBackend::UbuntuWaylandPipeWire,
                    operation: "negotiate PipeWire streams",
                    reason: error.to_string(),
                }
            });
            match event {
                Ok(PipeWireStartupEvent::FormatReady(monitor_id)) => {
                    if monitor_ids.contains(&monitor_id) {
                        ready.insert(monitor_id);
                    }
                }
                Ok(PipeWireStartupEvent::Failed(reason)) => {
                    let mut consumer = Self {
                        stop_sender: Some(stop_sender),
                        join_handle: Some(join_handle),
                        monitors,
                        frame_slots,
                        healthy,
                    };
                    let _ = consumer.stop();
                    return Err(CaptureError::BackendFailure {
                        backend: CaptureBackend::UbuntuWaylandPipeWire,
                        operation: "negotiate PipeWire streams",
                        reason,
                    });
                }
                Err(error) => {
                    let mut consumer = Self {
                        stop_sender: Some(stop_sender),
                        join_handle: Some(join_handle),
                        monitors,
                        frame_slots,
                        healthy,
                    };
                    let _ = consumer.stop();
                    return Err(error);
                }
            }
        }
        healthy.store(true, Ordering::Release);
        Ok(Self {
            stop_sender: Some(stop_sender),
            join_handle: Some(join_handle),
            monitors,
            frame_slots,
            healthy,
        })
    }

    fn stream_count(&self) -> usize {
        self.frame_slots.len()
    }

    fn monitors(&self) -> CaptureResult<Vec<MonitorInfo>> {
        let monitors = self.monitors.lock().map_err(|_| lock_failure("monitors"))?;
        let mut monitors = monitors.values().cloned().collect::<Vec<_>>();
        monitors.sort_by_key(|monitor| (!monitor.is_primary, monitor.monitor_id));
        Ok(monitors)
    }

    fn capture_frame(&self, monitor_id: u32) -> CaptureResult<CapturedFrame> {
        let slot = self
            .frame_slots
            .get(&monitor_id)
            .ok_or(CaptureError::MonitorNotFound)?;
        if let Some(frame) = slot.lock().map_err(|_| lock_failure("frame slot"))?.take() {
            return frame;
        }
        if !self.healthy.load(Ordering::Acquire) {
            return Err(CaptureError::BackendUnavailable);
        }
        Err(CaptureError::FrameUnavailable)
    }

    fn stop(&mut self) -> CaptureResult<()> {
        self.healthy.store(false, Ordering::Release);
        if let Some(sender) = self.stop_sender.take() {
            let _ = sender.send(());
        }
        let Some(join_handle) = self.join_handle.take() else {
            return Ok(());
        };
        match join_handle.join() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(reason)) => Err(CaptureError::BackendFailure {
                backend: CaptureBackend::UbuntuWaylandPipeWire,
                operation: "stop PipeWire consumer",
                reason,
            }),
            Err(_) => Err(CaptureError::BackendFailure {
                backend: CaptureBackend::UbuntuWaylandPipeWire,
                operation: "join PipeWire consumer",
                reason: "PipeWire consumer panicked".into(),
            }),
        }
    }
}

impl Drop for PipeWireConsumer {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

enum PipeWireStartupEvent {
    FormatReady(u32),
    Failed(String),
}

#[derive(Debug, Clone, Copy)]
struct NegotiatedFormat {
    width: u32,
    height: u32,
    pixel_format: PixelFormat,
    force_opaque_alpha: bool,
}

struct PipeWireUserData {
    descriptor: PortalStreamDescriptor,
    negotiated: Option<NegotiatedFormat>,
    limits: CaptureLimits,
    monitor_map: Arc<Mutex<HashMap<u32, MonitorInfo>>>,
    frame_slot: Arc<Mutex<Option<CaptureResult<CapturedFrame>>>>,
    healthy: Arc<AtomicBool>,
    startup_sender: mpsc::Sender<PipeWireStartupEvent>,
    started_at: Instant,
    last_timestamp_micros: u64,
}

impl PipeWireUserData {
    fn next_timestamp_micros(&mut self) -> u64 {
        let elapsed = u64::try_from(self.started_at.elapsed().as_micros()).unwrap_or(u64::MAX);
        let timestamp = elapsed.max(self.last_timestamp_micros.saturating_add(1));
        self.last_timestamp_micros = timestamp;
        timestamp
    }

    fn report_error(&self, operation: &'static str, reason: impl Into<String>) {
        self.healthy.store(false, Ordering::Release);
        let reason = reason.into();
        replace_frame_slot(
            &self.frame_slot,
            Err(CaptureError::BackendFailure {
                backend: CaptureBackend::UbuntuWaylandPipeWire,
                operation,
                reason: reason.clone(),
            }),
        );
        let _ = self
            .startup_sender
            .send(PipeWireStartupEvent::Failed(reason));
    }
}

struct PipeWireRuntime {
    remote_fd: OwnedFd,
    descriptors: Vec<PortalStreamDescriptor>,
    limits: CaptureLimits,
    monitors: Arc<Mutex<HashMap<u32, MonitorInfo>>>,
    frame_slots: HashMap<u32, Arc<Mutex<Option<CaptureResult<CapturedFrame>>>>>,
    healthy: Arc<AtomicBool>,
    startup_sender: mpsc::Sender<PipeWireStartupEvent>,
    stop_receiver: pw::channel::Receiver<()>,
}

fn run_pipewire(runtime: PipeWireRuntime) -> Result<(), String> {
    let PipeWireRuntime {
        remote_fd,
        descriptors,
        limits,
        monitors,
        frame_slots,
        healthy,
        startup_sender,
        stop_receiver,
    } = runtime;
    pw::init();
    let mainloop = pw::main_loop::MainLoop::new(None).map_err(|error| error.to_string())?;
    let context = pw::context::Context::new(&mainloop).map_err(|error| error.to_string())?;
    let core = context
        .connect_fd(remote_fd, None)
        .map_err(|error| error.to_string())?;
    let streams = descriptors
        .iter()
        .map(|descriptor| {
            pw::stream::Stream::new(
                &core,
                &format!("remote-capture-{}", descriptor.monitor_id),
                properties! {
                    *pw::keys::MEDIA_TYPE => "Video",
                    *pw::keys::MEDIA_CATEGORY => "Capture",
                    *pw::keys::MEDIA_ROLE => "Screen",
                },
            )
            .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;

    let listeners = streams
        .iter()
        .zip(descriptors.iter())
        .map(|(stream, descriptor)| {
            let frame_slot = frame_slots
                .get(&descriptor.monitor_id)
                .cloned()
                .ok_or_else(|| "missing frame slot for portal stream".to_string())?;
            let user_data = PipeWireUserData {
                descriptor: descriptor.clone(),
                negotiated: None,
                limits,
                monitor_map: Arc::clone(&monitors),
                frame_slot,
                healthy: Arc::clone(&healthy),
                startup_sender: startup_sender.clone(),
                started_at: Instant::now(),
                last_timestamp_micros: 0,
            };
            stream
                .add_local_listener_with_user_data(user_data)
                .state_changed(|_, user_data, _, state| match state {
                    pw::stream::StreamState::Error(reason) => {
                        user_data.report_error("run PipeWire stream", reason);
                    }
                    pw::stream::StreamState::Unconnected if user_data.negotiated.is_some() => {
                        user_data.report_error(
                            "run PipeWire stream",
                            "the portal PipeWire stream disconnected",
                        );
                    }
                    _ => {}
                })
                .param_changed(|_, user_data, id, param| {
                    if id != spa::param::ParamType::Format.as_raw() {
                        return;
                    }
                    let Some(param) = param else {
                        user_data.report_error(
                            "negotiate PipeWire format",
                            "the stream cleared its negotiated format",
                        );
                        return;
                    };
                    match parse_negotiated_format(param, user_data.limits) {
                        Ok(negotiated) => {
                            user_data.negotiated = Some(negotiated);
                            match user_data.monitor_map.lock() {
                                Ok(mut monitor_map) => {
                                    monitor_map.insert(
                                        user_data.descriptor.monitor_id,
                                        user_data
                                            .descriptor
                                            .monitor_info(negotiated.width, negotiated.height),
                                    );
                                    let _ = user_data.startup_sender.send(
                                        PipeWireStartupEvent::FormatReady(
                                            user_data.descriptor.monitor_id,
                                        ),
                                    );
                                }
                                Err(_) => user_data.report_error(
                                    "update PipeWire monitor",
                                    "monitor state lock was poisoned",
                                ),
                            }
                        }
                        Err(error) => {
                            user_data.report_error("negotiate PipeWire format", error.to_string())
                        }
                    }
                })
                .process(|stream, user_data| {
                    let Some(negotiated) = user_data.negotiated else {
                        return;
                    };
                    let timestamp_micros = user_data.next_timestamp_micros();
                    let frame = stream
                        .dequeue_buffer()
                        .ok_or(CaptureError::FrameUnavailable)
                        .and_then(|mut buffer| {
                            let datas = buffer.datas_mut();
                            if datas.len() != 1 {
                                return Err(CaptureError::InvalidFrame(
                                    "packed RGB PipeWire frames must contain one data plane",
                                ));
                            }
                            captured_frame_from_data(
                                &mut datas[0],
                                user_data.descriptor.monitor_id,
                                negotiated,
                                timestamp_micros,
                                user_data.limits,
                            )
                        });
                    replace_frame_slot(&user_data.frame_slot, frame);
                })
                .register()
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;

    let pod_bytes = supported_video_format_pod()?;
    for (stream, descriptor) in streams.iter().zip(descriptors.iter()) {
        let pod = spa::pod::Pod::from_bytes(&pod_bytes)
            .ok_or_else(|| "failed to parse the PipeWire video format pod".to_string())?;
        let mut params = [pod];
        stream
            .connect(
                spa::utils::Direction::Input,
                Some(descriptor.monitor_id),
                pw::stream::StreamFlags::AUTOCONNECT | pw::stream::StreamFlags::MAP_BUFFERS,
                &mut params,
            )
            .map_err(|error| error.to_string())?;
    }

    let attached_stop = stop_receiver.attach(mainloop.loop_(), {
        let mainloop = mainloop.clone();
        move |_| mainloop.quit()
    });
    mainloop.run();
    healthy.store(false, Ordering::Release);
    drop(attached_stop);
    drop(listeners);
    for stream in &streams {
        let _ = stream.disconnect();
    }
    Ok(())
}

fn supported_video_format_pod() -> Result<Vec<u8>, String> {
    let object = spa::pod::object!(
        spa::utils::SpaTypes::ObjectParamFormat,
        spa::param::ParamType::EnumFormat,
        spa::pod::property!(
            spa::param::format::FormatProperties::MediaType,
            Id,
            spa::param::format::MediaType::Video
        ),
        spa::pod::property!(
            spa::param::format::FormatProperties::MediaSubtype,
            Id,
            spa::param::format::MediaSubtype::Raw
        ),
        spa::pod::property!(
            spa::param::format::FormatProperties::VideoFormat,
            Choice,
            Enum,
            Id,
            spa::param::video::VideoFormat::BGRx,
            spa::param::video::VideoFormat::BGRx,
            spa::param::video::VideoFormat::BGRA,
            spa::param::video::VideoFormat::RGBx,
            spa::param::video::VideoFormat::RGBA
        ),
        spa::pod::property!(
            spa::param::format::FormatProperties::VideoSize,
            Choice,
            Range,
            Rectangle,
            spa::utils::Rectangle {
                width: 1_920,
                height: 1_080
            },
            spa::utils::Rectangle {
                width: 1,
                height: 1
            },
            spa::utils::Rectangle {
                width: crate::MAX_CAPTURE_WIDTH,
                height: crate::MAX_CAPTURE_HEIGHT
            }
        ),
        spa::pod::property!(
            spa::param::format::FormatProperties::VideoFramerate,
            Choice,
            Range,
            Fraction,
            spa::utils::Fraction { num: 30, denom: 1 },
            spa::utils::Fraction { num: 0, denom: 1 },
            spa::utils::Fraction { num: 144, denom: 1 }
        )
    );
    spa::pod::serialize::PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &spa::pod::Value::Object(object),
    )
    .map(|(cursor, _)| cursor.into_inner())
    .map_err(|error| error.to_string())
}

fn parse_negotiated_format(
    param: &spa::pod::Pod,
    limits: CaptureLimits,
) -> CaptureResult<NegotiatedFormat> {
    let (media_type, media_subtype) = spa::param::format_utils::parse_format(param)
        .map_err(|_| CaptureError::InvalidFrame("invalid PipeWire format pod"))?;
    if media_type != spa::param::format::MediaType::Video
        || media_subtype != spa::param::format::MediaSubtype::Raw
    {
        return Err(CaptureError::InvalidFrame(
            "PipeWire negotiated a non-raw-video format",
        ));
    }
    let mut info = spa::param::video::VideoInfoRaw::new();
    info.parse(param)
        .map_err(|_| CaptureError::InvalidFrame("invalid PipeWire raw-video format"))?;
    let (pixel_format, force_opaque_alpha) = map_video_format(info.format())?;
    let size = info.size();
    limits.validate_dimensions(size.width, size.height)?;
    Ok(NegotiatedFormat {
        width: size.width,
        height: size.height,
        pixel_format,
        force_opaque_alpha,
    })
}

fn map_video_format(format: spa::param::video::VideoFormat) -> CaptureResult<(PixelFormat, bool)> {
    match format {
        spa::param::video::VideoFormat::BGRx => Ok((PixelFormat::Bgra8, true)),
        spa::param::video::VideoFormat::BGRA => Ok((PixelFormat::Bgra8, false)),
        spa::param::video::VideoFormat::RGBx => Ok((PixelFormat::Rgba8, true)),
        spa::param::video::VideoFormat::RGBA => Ok((PixelFormat::Rgba8, false)),
        _ => Err(CaptureError::InvalidFrame(
            "PipeWire negotiated an unsupported pixel format",
        )),
    }
}

fn captured_frame_from_data(
    data: &mut spa::buffer::Data,
    monitor_id: u32,
    negotiated: NegotiatedFormat,
    timestamp_micros: u64,
    limits: CaptureLimits,
) -> CaptureResult<CapturedFrame> {
    let chunk = data.chunk();
    if chunk.flags().contains(spa::buffer::ChunkFlags::CORRUPTED) {
        return Err(CaptureError::FrameUnavailable);
    }
    let offset = usize::try_from(chunk.offset())
        .map_err(|_| CaptureError::InvalidFrame("PipeWire chunk offset overflow"))?;
    let chunk_size = usize::try_from(chunk.size())
        .map_err(|_| CaptureError::InvalidFrame("PipeWire chunk size overflow"))?;
    let stride = u32::try_from(chunk.stride())
        .map_err(|_| CaptureError::InvalidFrame("PipeWire packed RGB stride must be positive"))?;
    let mapped = data.data().ok_or(CaptureError::FrameUnavailable)?;
    let bytes = copy_packed_frame(
        mapped,
        offset,
        chunk_size,
        negotiated.width,
        negotiated.height,
        stride,
        negotiated.pixel_format,
        negotiated.force_opaque_alpha,
        limits,
    )?;
    CapturedFrame::try_new(
        FrameMetadata {
            monitor_id,
            width: negotiated.width,
            height: negotiated.height,
            stride,
            pixel_format: negotiated.pixel_format,
            timestamp_micros,
        },
        bytes,
        limits,
    )
}

#[allow(clippy::too_many_arguments)]
fn copy_packed_frame(
    mapped: &[u8],
    offset: usize,
    chunk_size: usize,
    width: u32,
    height: u32,
    stride: u32,
    pixel_format: PixelFormat,
    force_opaque_alpha: bool,
    limits: CaptureLimits,
) -> CaptureResult<Vec<u8>> {
    if !matches!(pixel_format, PixelFormat::Bgra8 | PixelFormat::Rgba8) {
        return Err(CaptureError::InvalidFrame(
            "PipeWire packed frame must use a four-byte RGB format",
        ));
    }
    let destination_len = limits.validate_layout(width, height, stride, pixel_format)?;
    let row_bytes = usize::try_from(
        width
            .checked_mul(4)
            .ok_or(CaptureError::InvalidFrame("PipeWire row size overflow"))?,
    )
    .map_err(|_| CaptureError::InvalidFrame("PipeWire row size overflow"))?;
    let stride = usize::try_from(stride)
        .map_err(|_| CaptureError::InvalidFrame("PipeWire stride overflow"))?;
    let height = usize::try_from(height)
        .map_err(|_| CaptureError::InvalidFrame("PipeWire height overflow"))?;
    let minimum_source_len = stride
        .checked_mul(height.saturating_sub(1))
        .and_then(|bytes| bytes.checked_add(row_bytes))
        .ok_or(CaptureError::InvalidFrame(
            "PipeWire source layout size overflow",
        ))?;
    if chunk_size < minimum_source_len {
        return Err(CaptureError::InvalidFrame(
            "PipeWire chunk is smaller than the negotiated frame layout",
        ));
    }
    let chunk_end = offset
        .checked_add(chunk_size)
        .ok_or(CaptureError::InvalidFrame("PipeWire chunk range overflow"))?;
    if chunk_end > mapped.len() {
        return Err(CaptureError::InvalidFrame(
            "PipeWire chunk exceeds the mapped buffer",
        ));
    }

    let mut destination = vec![0; destination_len];
    for row in 0..height {
        let source_start = offset + row * stride;
        let destination_start = row * stride;
        destination[destination_start..destination_start + row_bytes]
            .copy_from_slice(&mapped[source_start..source_start + row_bytes]);
        if force_opaque_alpha {
            for alpha in destination[destination_start + 3..destination_start + row_bytes]
                .iter_mut()
                .step_by(4)
            {
                *alpha = u8::MAX;
            }
        }
    }
    Ok(destination)
}

fn replace_frame_slot(
    slot: &Mutex<Option<CaptureResult<CapturedFrame>>>,
    frame: CaptureResult<CapturedFrame>,
) {
    if let Ok(mut slot) = slot.lock() {
        *slot = Some(frame);
    }
}

fn portal_failure(operation: &'static str, error: zbus::Error) -> CaptureError {
    CaptureError::BackendFailure {
        backend: CaptureBackend::UbuntuWaylandPipeWire,
        operation,
        reason: error.to_string(),
    }
}

fn backend_failure(operation: &'static str, error: impl std::fmt::Display) -> CaptureError {
    CaptureError::BackendFailure {
        backend: CaptureBackend::UbuntuWaylandPipeWire,
        operation,
        reason: error.to_string(),
    }
}

fn lock_failure(resource: &'static str) -> CaptureError {
    CaptureError::BackendFailure {
        backend: CaptureBackend::UbuntuWaylandPipeWire,
        operation: "read PipeWire state",
        reason: format!("{resource} lock was poisoned"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wayland_never_claims_capture_before_portal_authorization() {
        let capturer = UbuntuWaylandPortalCapturer::default();
        assert_eq!(capturer.state(), CaptureState::Idle);
        assert_eq!(
            capturer.authorization_state(),
            CaptureAuthorizationState::NotChecked
        );
        assert_eq!(
            capturer.portal_status().session,
            PortalSessionState::NotRequested
        );
    }

    #[test]
    fn authorization_state_distinguishes_request_grant_and_denial() {
        let mut capturer = UbuntuWaylandPortalCapturer::default();
        capturer.status.capability = PortalCapability::Available {
            version: 5,
            source_types: SOURCE_TYPE_MONITOR,
            cursor_modes: CURSOR_MODE_EMBEDDED,
            remote_desktop_version: 2,
            device_types: DEVICE_TYPE_KEYBOARD | DEVICE_TYPE_POINTER,
        };
        capturer.status.session = PortalSessionState::RequestingUserAuthorization;
        assert_eq!(
            capturer.authorization_state(),
            CaptureAuthorizationState::Requesting
        );
        capturer.status.session = PortalSessionState::Active { stream_count: 1 };
        assert_eq!(
            capturer.authorization_state(),
            CaptureAuthorizationState::Granted
        );
        capturer.status.session = PortalSessionState::Denied;
        assert_eq!(
            capturer.authorization_state(),
            CaptureAuthorizationState::Denied
        );
    }

    #[test]
    fn portal_input_rejects_invalid_values_without_an_active_session() {
        let input = UbuntuWaylandPortalInput;
        assert_eq!(
            input.move_pointer(f64::NAN, 0.5),
            Err(PortalInputError::InvalidInput(
                "pointer coordinates must be finite normalized values"
            ))
        );
        assert_eq!(
            input.wheel(0.0, f64::INFINITY),
            Err(PortalInputError::InvalidInput(
                "wheel deltas must be finite"
            ))
        );
        assert_eq!(input.release_all(), Ok(()));
    }

    #[test]
    fn unicode_text_uses_xkb_keysyms_without_logging_content() {
        assert_eq!(unicode_keysym('A'), Ok(0x41));
        assert_eq!(unicode_keysym('\n'), Ok(0xff0d));
        assert_eq!(unicode_keysym('\t'), Ok(0xff09));
        assert_eq!(unicode_keysym('\u{4e2d}'), Ok(0x0100_4e2d));
        assert!(unicode_keysym('\0').is_err());
    }

    #[test]
    fn normalized_pointer_coordinates_map_to_portal_stream_space() {
        let target = PortalInputTarget {
            stream_id: 42,
            width: 1_920,
            height: 1_080,
        };
        assert_eq!(target.coordinates(0.0, 0.0), (0.0, 0.0));
        assert_eq!(target.coordinates(1.0, 1.0), (1_919.0, 1_079.0));
        assert_eq!(target.coordinates(0.5, 0.5), (959.5, 539.5));
    }

    #[test]
    fn packed_frame_copy_honors_offset_stride_and_owned_storage() {
        let limits = CaptureLimits::try_new(8, 8, 1_024).expect("limits");
        let mut mapped = vec![0xEE; 40];
        mapped[4..12].copy_from_slice(&[1, 2, 3, 0, 5, 6, 7, 0]);
        mapped[16..24].copy_from_slice(&[9, 10, 11, 0, 13, 14, 15, 0]);
        let copied = copy_packed_frame(&mapped, 4, 20, 2, 2, 12, PixelFormat::Bgra8, true, limits)
            .expect("valid frame");
        mapped.fill(0);
        assert_eq!(copied.len(), 24);
        assert_eq!(&copied[..8], &[1, 2, 3, 255, 5, 6, 7, 255]);
        assert_eq!(&copied[8..12], &[0; 4]);
        assert_eq!(&copied[12..20], &[9, 10, 11, 255, 13, 14, 15, 255]);
        assert_eq!(&copied[20..24], &[0; 4]);
    }

    #[test]
    fn packed_frame_rejects_short_chunk_and_out_of_bounds_range() {
        let limits = CaptureLimits::try_new(8, 8, 1_024).expect("limits");
        let mapped = vec![0; 64];
        assert!(matches!(
            copy_packed_frame(&mapped, 0, 19, 2, 2, 12, PixelFormat::Rgba8, false, limits,),
            Err(CaptureError::InvalidFrame(
                "PipeWire chunk is smaller than the negotiated frame layout"
            ))
        ));
        assert!(matches!(
            copy_packed_frame(&mapped, 60, 20, 2, 2, 12, PixelFormat::Rgba8, false, limits,),
            Err(CaptureError::InvalidFrame(
                "PipeWire chunk exceeds the mapped buffer"
            ))
        ));
    }

    #[test]
    fn packed_frame_enforces_configured_size_and_stride_limits() {
        let limits = CaptureLimits::try_new(4, 4, 32).expect("limits");
        assert!(matches!(
            copy_packed_frame(&[0; 64], 0, 64, 4, 4, 16, PixelFormat::Bgra8, false, limits,),
            Err(CaptureError::FrameTooLarge { .. })
        ));
        assert!(matches!(
            copy_packed_frame(
                &[0; 64],
                0,
                64,
                4,
                1,
                15,
                PixelFormat::Bgra8,
                false,
                CaptureLimits::default(),
            ),
            Err(CaptureError::InvalidFrame(
                "stride is smaller than the pixel row"
            ))
        ));
    }

    #[test]
    fn stopping_without_a_session_is_idempotent() {
        let mut capturer = UbuntuWaylandPortalCapturer::default();
        capturer.stop().expect("first stop");
        capturer.stop().expect("second stop");
        assert_eq!(capturer.state(), CaptureState::Stopped);
        assert_eq!(capturer.portal_status().session, PortalSessionState::Closed);
    }

    #[test]
    #[ignore = "requires a live user D-Bus session and xdg-desktop-portal"]
    fn live_portal_probe_reports_capability_without_prompting() {
        let mut capturer = UbuntuWaylandPortalCapturer::default();
        let status = capturer.probe_portal().expect("portal capability probe");
        assert!(matches!(
            status.capability,
            PortalCapability::Available { .. }
        ));
        assert_eq!(
            status.session,
            PortalSessionState::ReadyForUserAuthorization
        );
    }

    #[test]
    #[ignore = "opens the real portal authorization dialog and requires a Wayland desktop"]
    fn live_portal_authorization_enables_capture_and_remote_desktop_input() {
        let mut capturer = UbuntuWaylandPortalCapturer::default();
        capturer
            .start()
            .expect("portal authorization and PipeWire start");
        let monitor = capturer
            .monitors()
            .expect("portal monitors")
            .into_iter()
            .next()
            .expect("at least one monitor");
        let deadline = Instant::now() + Duration::from_secs(10);
        let frame = loop {
            match capturer.capture_frame(monitor.monitor_id) {
                Ok(frame) => break frame,
                Err(CaptureError::FrameUnavailable) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("capture failed: {error}"),
            }
        };
        assert!(!frame.bytes().is_empty());
        assert_eq!(frame.width(), monitor.width);
        assert_eq!(frame.height(), monitor.height);
        let input = UbuntuWaylandPortalInput;
        assert!(input.is_active());
        input.release_all().expect("portal release all");
        capturer.stop().expect("portal and PipeWire cleanup");
        assert!(!input.is_active());
    }
}
