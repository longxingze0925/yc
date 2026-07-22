use super::{DesktopPlatform, PlatformSnapshot};
use crate::input::{InputBackend, UnsupportedInputBackend};

#[derive(Debug, Clone, Copy)]
enum UbuntuSession {
    Wayland,
    X11,
    Unknown,
}

impl UbuntuSession {
    fn detect() -> Self {
        let session = std::env::var("XDG_SESSION_TYPE")
            .unwrap_or_default()
            .to_ascii_lowercase();
        if session == "wayland" || std::env::var_os("WAYLAND_DISPLAY").is_some() {
            Self::Wayland
        } else if session == "x11" || std::env::var_os("DISPLAY").is_some() {
            Self::X11
        } else {
            Self::Unknown
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Wayland => "Wayland",
            Self::X11 => "X11",
            Self::Unknown => "未检测到图形会话",
        }
    }

    fn input_backend(self) -> UnsupportedInputBackend {
        match self {
            Self::Wayland => UnsupportedInputBackend::new(
                "xdg-desktop-portal RemoteDesktop",
                "portal RemoteDesktop integration is not linked in this milestone",
            ),
            Self::X11 => UnsupportedInputBackend::new(
                "XTest/uinput",
                "XTest and uinput integration is not linked in this milestone",
            ),
            Self::Unknown => UnsupportedInputBackend::new(
                "Ubuntu input",
                "no Wayland or X11 desktop session was detected",
            ),
        }
    }
}

#[derive(Debug)]
pub struct UbuntuPlatform {
    session: UbuntuSession,
}

impl UbuntuPlatform {
    pub fn detect() -> Self {
        Self {
            session: UbuntuSession::detect(),
        }
    }
}

impl DesktopPlatform for UbuntuPlatform {
    fn snapshot(&self) -> PlatformSnapshot {
        let hostname = std::env::var("HOSTNAME")
            .ok()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| "Ubuntu Desktop".into());
        PlatformSnapshot {
            platform_label: "Ubuntu Desktop 26.04 LTS".into(),
            local_device_name: hostname,
            session_kind: self.session.label().into(),
            capture_status: match self.session {
                UbuntuSession::Wayland => {
                    "unsupported: PipeWire + xdg-desktop-portal ScreenCast 未接入".into()
                }
                UbuntuSession::X11 => "unsupported: XDamage + XShm 未接入".into(),
                UbuntuSession::Unknown => "unsupported: 未检测到 Wayland/X11".into(),
            },
            render_status: "unsupported: OpenGL/Vulkan 原生表面未接入".into(),
            input_status: match self.session {
                UbuntuSession::Wayland => {
                    "unsupported: xdg-desktop-portal RemoteDesktop 未接入".into()
                }
                UbuntuSession::X11 => "unsupported: XTest/uinput 未接入".into(),
                UbuntuSession::Unknown => "unsupported: 未检测到 Wayland/X11".into(),
            },
            privacy_status: "unsupported: 隐私屏与本地输入保护未接入".into(),
        }
    }

    fn input_backend(&self) -> Box<dyn InputBackend> {
        Box::new(self.session.input_backend())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ubuntu_capabilities_do_not_claim_native_support() {
        let snapshot = UbuntuPlatform::detect().snapshot();
        assert!(snapshot.capture_status.starts_with("unsupported:"));
        assert!(snapshot.render_status.starts_with("unsupported:"));
        assert!(snapshot.input_status.starts_with("unsupported:"));
        assert!(snapshot.privacy_status.starts_with("unsupported:"));
    }
}
