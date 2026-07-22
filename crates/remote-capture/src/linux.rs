#[path = "linux/portal.rs"]
mod portal;
#[path = "linux/x11.rs"]
mod x11;

use std::env;

use crate::{CaptureBackend, ScreenCapturer, UnsupportedCapturer};

pub use portal::{
    PortalCapability, PortalSessionState, UbuntuWaylandPortalCapturer, WaylandPortalStatus,
};
pub use x11::UbuntuX11Capturer;

// Compatibility name retained for the first X11 implementation that landed in parallel.
pub type X11Capturer = UbuntuX11Capturer;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxDesktopSession {
    Wayland,
    X11,
    Unknown,
}

impl LinuxDesktopSession {
    pub fn detect() -> Self {
        Self::from_environment(
            env::var("XDG_SESSION_TYPE").ok().as_deref(),
            env::var("WAYLAND_DISPLAY").ok().as_deref(),
            env::var("DISPLAY").ok().as_deref(),
        )
    }

    fn from_environment(
        session_type: Option<&str>,
        wayland_display: Option<&str>,
        x11_display: Option<&str>,
    ) -> Self {
        if session_type.is_some_and(|value| value.eq_ignore_ascii_case("wayland"))
            || wayland_display.is_some_and(|value| !value.is_empty())
        {
            return Self::Wayland;
        }
        if session_type.is_some_and(|value| value.eq_ignore_ascii_case("x11"))
            || x11_display.is_some_and(|value| !value.is_empty())
        {
            return Self::X11;
        }
        Self::Unknown
    }
}

pub(crate) fn platform_capturer() -> Box<dyn ScreenCapturer> {
    match LinuxDesktopSession::detect() {
        LinuxDesktopSession::Wayland => Box::new(UbuntuWaylandPortalCapturer::default()),
        LinuxDesktopSession::X11 => Box::new(UbuntuX11Capturer::default()),
        LinuxDesktopSession::Unknown => Box::new(UnsupportedCapturer::new(
            CaptureBackend::UnsupportedPlatform,
            "no Wayland or X11 desktop session was detected",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wayland_wins_over_xwayland_display() {
        assert_eq!(
            LinuxDesktopSession::from_environment(Some("wayland"), Some("wayland-0"), Some(":0")),
            LinuxDesktopSession::Wayland
        );
    }

    #[test]
    fn display_without_wayland_selects_x11() {
        assert_eq!(
            LinuxDesktopSession::from_environment(None, None, Some(":1")),
            LinuxDesktopSession::X11
        );
    }
}
