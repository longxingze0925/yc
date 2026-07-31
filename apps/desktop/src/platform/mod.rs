use crate::input::InputBackend;

#[cfg(target_os = "linux")]
mod ubuntu;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(any(target_os = "windows", test))]
mod windows_keymap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformSnapshot {
    pub platform_label: String,
    pub local_device_name: String,
    pub session_kind: String,
    pub capture_status: String,
    pub render_status: String,
    pub input_status: String,
    pub privacy_status: String,
}

pub trait DesktopPlatform {
    fn snapshot(&self) -> PlatformSnapshot;
    fn input_backend(&self) -> Box<dyn InputBackend>;
}

#[cfg(target_os = "linux")]
pub fn current_platform() -> Box<dyn DesktopPlatform> {
    Box::new(ubuntu::UbuntuPlatform::detect())
}

#[cfg(target_os = "windows")]
pub fn current_platform() -> Box<dyn DesktopPlatform> {
    Box::new(windows::WindowsPlatform::detect())
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn current_platform() -> Box<dyn DesktopPlatform> {
    use crate::input::UnsupportedInputBackend;

    struct UnsupportedPlatform;

    impl DesktopPlatform for UnsupportedPlatform {
        fn snapshot(&self) -> PlatformSnapshot {
            PlatformSnapshot {
                platform_label: "Unsupported desktop platform".into(),
                local_device_name: "Desktop device".into(),
                session_kind: "unknown".into(),
                capture_status: "unsupported: Windows/Ubuntu only".into(),
                render_status: "unsupported: Windows/Ubuntu only".into(),
                input_status: "unsupported: Windows/Ubuntu only".into(),
                privacy_status: "unsupported: Windows/Ubuntu only".into(),
            }
        }

        fn input_backend(&self) -> Box<dyn InputBackend> {
            Box::new(UnsupportedInputBackend::new(
                "unsupported platform input",
                "desktop input is only planned for Windows and Ubuntu",
            ))
        }
    }

    Box::new(UnsupportedPlatform)
}
