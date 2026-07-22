use super::{DesktopPlatform, PlatformSnapshot};
use crate::input::{InputBackend, UnsupportedInputBackend};

#[derive(Debug)]
pub struct WindowsPlatform;

impl WindowsPlatform {
    pub fn detect() -> Self {
        Self
    }
}

impl DesktopPlatform for WindowsPlatform {
    fn snapshot(&self) -> PlatformSnapshot {
        let hostname = std::env::var("COMPUTERNAME")
            .ok()
            .filter(|name| !name.trim().is_empty())
            .unwrap_or_else(|| "Windows Desktop".into());
        PlatformSnapshot {
            platform_label: "Windows 10/11".into(),
            local_device_name: hostname,
            session_kind: "Windows desktop".into(),
            capture_status: "unsupported: WGC/DXGI 未接入".into(),
            render_status: "unsupported: D3D11/DirectComposition 未接入".into(),
            input_status: "unsupported: SendInput/Unicode 输入未接入".into(),
            privacy_status: "unsupported: 隐私屏与本地输入保护未接入".into(),
        }
    }

    fn input_backend(&self) -> Box<dyn InputBackend> {
        Box::new(UnsupportedInputBackend::new(
            "Windows SendInput",
            "SendInput integration is not linked in this milestone",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_capabilities_do_not_claim_native_support() {
        let snapshot = WindowsPlatform::detect().snapshot();
        assert!(snapshot.capture_status.starts_with("unsupported:"));
        assert!(snapshot.render_status.starts_with("unsupported:"));
        assert!(snapshot.input_status.starts_with("unsupported:"));
        assert!(snapshot.privacy_status.starts_with("unsupported:"));
    }
}
