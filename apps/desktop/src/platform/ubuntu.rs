use super::{DesktopPlatform, PlatformSnapshot};
use crate::input::{InputBackend, InputError, PhysicalKey, PointerButton, UnsupportedInputBackend};
use remote_capture::{PortalInputError, UbuntuWaylandPortalInput};
use std::collections::BTreeSet;
use x11rb::connection::Connection;
use x11rb::protocol::xproto::{
    Window, BUTTON_PRESS_EVENT, BUTTON_RELEASE_EVENT, KEY_PRESS_EVENT, KEY_RELEASE_EVENT,
    MOTION_NOTIFY_EVENT,
};
use x11rb::protocol::xtest::ConnectionExt as XtestConnectionExt;
use x11rb::rust_connection::RustConnection;

const CURRENT_TIME: u32 = 0;
const CORE_POINTER_DEVICE: u8 = 0;
const MAX_WHEEL_STEPS_PER_EVENT: f64 = 120.0;

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

    fn input_backend(self) -> Box<dyn InputBackend> {
        match self {
            Self::Wayland => Box::new(WaylandInputBackend::default()),
            Self::X11 => X11InputBackend::connect().map_or_else(
                |error| Box::new(UnsupportedInputBackend::new("X11 XTest", error)) as _,
                |backend| Box::new(backend) as _,
            ),
            Self::Unknown => Box::new(UnsupportedInputBackend::new(
                "Ubuntu input",
                "no Wayland or X11 desktop session was detected",
            )),
        }
    }
}

#[derive(Debug, Default)]
struct WaylandInputBackend {
    portal: UbuntuWaylandPortalInput,
}

impl WaylandInputBackend {
    fn portal_result(result: Result<(), PortalInputError>) -> Result<(), InputError> {
        result.map_err(|error| match error {
            PortalInputError::SessionInactive => InputError::Unsupported(
                "the RemoteDesktop portal session is not active or authorization was revoked",
            ),
            PortalInputError::InvalidInput(reason) => InputError::InjectionFailed(reason),
            PortalInputError::PortalFailure(_) => {
                InputError::InjectionFailed("the RemoteDesktop portal rejected input injection")
            }
            PortalInputError::TimedOut => {
                InputError::InjectionFailed("the RemoteDesktop portal input request timed out")
            }
        })
    }
}

impl InputBackend for WaylandInputBackend {
    fn name(&self) -> &'static str {
        "xdg-desktop-portal RemoteDesktop"
    }

    fn key_down(&mut self, key: PhysicalKey) -> Result<(), InputError> {
        let keycode = hid_usage_to_evdev_keycode(key).ok_or(InputError::Unsupported(
            "the HID usage is not mapped to a Linux evdev keycode",
        ))?;
        Self::portal_result(self.portal.keycode(keycode, true))
    }

    fn key_up(&mut self, key: PhysicalKey) -> Result<(), InputError> {
        let keycode = hid_usage_to_evdev_keycode(key).ok_or(InputError::Unsupported(
            "the HID usage is not mapped to a Linux evdev keycode",
        ))?;
        Self::portal_result(self.portal.keycode(keycode, false))
    }

    fn button_down(&mut self, button: PointerButton) -> Result<(), InputError> {
        Self::portal_result(self.portal.button(pointer_button_to_evdev(button), true))
    }

    fn button_up(&mut self, button: PointerButton) -> Result<(), InputError> {
        Self::portal_result(self.portal.button(pointer_button_to_evdev(button), false))
    }

    fn move_pointer(&mut self, x_norm: f64, y_norm: f64) -> Result<(), InputError> {
        Self::portal_result(self.portal.move_pointer(x_norm, y_norm))
    }

    fn wheel(&mut self, delta_x: f64, delta_y: f64) -> Result<(), InputError> {
        Self::portal_result(self.portal.wheel(delta_x, delta_y))
    }

    fn text_commit(&mut self, text: &str) -> Result<(), InputError> {
        Self::portal_result(self.portal.text_commit(text))
    }

    fn release_all(&mut self) -> Result<(), InputError> {
        Self::portal_result(self.portal.release_all())
    }
}

fn pointer_button_to_evdev(button: PointerButton) -> i32 {
    match button {
        PointerButton::Left => 0x110,
        PointerButton::Right => 0x111,
        PointerButton::Middle => 0x112,
        PointerButton::Back => 0x113,
        PointerButton::Forward => 0x114,
    }
}

fn hid_usage_to_evdev_keycode(key: PhysicalKey) -> Option<i32> {
    let keycode = match key.0 {
        0x04 => 30,
        0x05 => 48,
        0x06 => 46,
        0x07 => 32,
        0x08 => 18,
        0x09 => 33,
        0x0a => 34,
        0x0b => 35,
        0x0c => 23,
        0x0d => 36,
        0x0e => 37,
        0x0f => 38,
        0x10 => 50,
        0x11 => 49,
        0x12 => 24,
        0x13 => 25,
        0x14 => 16,
        0x15 => 19,
        0x16 => 31,
        0x17 => 20,
        0x18 => 22,
        0x19 => 47,
        0x1a => 17,
        0x1b => 45,
        0x1c => 21,
        0x1d => 44,
        0x1e..=0x27 => 2 + i32::try_from(key.0 - 0x1e).ok()?,
        0x28 => 28,
        0x29 => 1,
        0x2a => 14,
        0x2b => 15,
        0x2c => 57,
        0x2d => 12,
        0x2e => 13,
        0x2f => 26,
        0x30 => 27,
        0x31 => 43,
        0x33 => 39,
        0x34 => 40,
        0x35 => 41,
        0x36 => 51,
        0x37 => 52,
        0x38 => 53,
        0x39 => 58,
        0x3a..=0x43 => 59 + i32::try_from(key.0 - 0x3a).ok()?,
        0x44 => 87,
        0x45 => 88,
        0x4a => 102,
        0x4b => 104,
        0x4c => 111,
        0x4d => 107,
        0x4e => 109,
        0x4f => 106,
        0x50 => 105,
        0x51 => 108,
        0x52 => 103,
        0xe0 => 29,
        0xe1 => 42,
        0xe2 => 56,
        0xe3 => 125,
        0xe4 => 97,
        0xe5 => 54,
        0xe6 => 100,
        0xe7 => 126,
        _ => return None,
    };
    Some(keycode)
}

#[derive(Debug)]
struct X11InputBackend {
    connection: RustConnection,
    root: Window,
    root_width: u16,
    root_height: u16,
    pressed_keys: BTreeSet<u8>,
    pressed_buttons: BTreeSet<u8>,
    horizontal_wheel_remainder: f64,
    vertical_wheel_remainder: f64,
}

impl X11InputBackend {
    fn connect() -> Result<Self, &'static str> {
        let (connection, screen_number) =
            x11rb::connect(None).map_err(|_| "could not connect to the current X11 display")?;
        connection
            .xtest_get_version(2, 2)
            .map_err(|_| "the X11 server does not expose XTest")?
            .reply()
            .map_err(|_| "the X11 server rejected XTest initialization")?;
        let (root, root_width, root_height) = {
            let screen = connection
                .setup()
                .roots
                .get(screen_number)
                .ok_or("the X11 display has no selected screen")?;
            (screen.root, screen.width_in_pixels, screen.height_in_pixels)
        };

        Ok(Self {
            connection,
            root,
            root_width,
            root_height,
            pressed_keys: BTreeSet::new(),
            pressed_buttons: BTreeSet::new(),
            horizontal_wheel_remainder: 0.0,
            vertical_wheel_remainder: 0.0,
        })
    }

    fn fake_input(&self, event_type: u8, detail: u8, x: i16, y: i16) -> Result<(), InputError> {
        self.connection
            .xtest_fake_input(
                event_type,
                detail,
                CURRENT_TIME,
                self.root,
                x,
                y,
                CORE_POINTER_DEVICE,
            )
            .map_err(|_| InputError::InjectionFailed("XTest request failed"))?;
        self.connection
            .flush()
            .map_err(|_| InputError::InjectionFailed("X11 flush failed"))
    }

    fn key_event(&self, keycode: u8, pressed: bool) -> Result<(), InputError> {
        self.fake_input(
            if pressed {
                KEY_PRESS_EVENT
            } else {
                KEY_RELEASE_EVENT
            },
            keycode,
            0,
            0,
        )
    }

    fn button_event(&self, button: u8, pressed: bool) -> Result<(), InputError> {
        self.fake_input(
            if pressed {
                BUTTON_PRESS_EVENT
            } else {
                BUTTON_RELEASE_EVENT
            },
            button,
            0,
            0,
        )
    }

    fn click_button(&self, button: u8) -> Result<(), InputError> {
        self.button_event(button, true)?;
        self.button_event(button, false)
    }

    fn normalized_coordinate(value: f64, dimension: u16) -> Result<i16, InputError> {
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err(InputError::InjectionFailed(
                "pointer coordinates must be finite normalized values",
            ));
        }
        let maximum = dimension.saturating_sub(1);
        let coordinate = (value * f64::from(maximum)).round() as i32;
        Ok(coordinate.clamp(0, i32::from(i16::MAX)) as i16)
    }

    fn wheel_steps(delta: f64, remainder: &mut f64) -> Result<i32, InputError> {
        if !delta.is_finite() {
            return Err(InputError::InjectionFailed("wheel delta must be finite"));
        }
        *remainder =
            (*remainder + delta).clamp(-MAX_WHEEL_STEPS_PER_EVENT, MAX_WHEEL_STEPS_PER_EVENT);
        let steps = remainder.trunc() as i32;
        *remainder -= f64::from(steps);
        Ok(steps)
    }

    fn emit_wheel_steps(
        &self,
        steps: i32,
        negative_button: u8,
        positive_button: u8,
    ) -> Result<(), InputError> {
        for _ in 0..steps.unsigned_abs() {
            self.click_button(if steps.is_negative() {
                negative_button
            } else {
                positive_button
            })?;
        }
        Ok(())
    }
}

impl InputBackend for X11InputBackend {
    fn name(&self) -> &'static str {
        "X11 XTest"
    }

    fn key_down(&mut self, key: PhysicalKey) -> Result<(), InputError> {
        let keycode = hid_usage_to_x11_keycode(key).ok_or(InputError::Unsupported(
            "the HID usage is not mapped to an X11 keycode",
        ))?;
        self.key_event(keycode, true)?;
        self.pressed_keys.insert(keycode);
        Ok(())
    }

    fn key_up(&mut self, key: PhysicalKey) -> Result<(), InputError> {
        let keycode = hid_usage_to_x11_keycode(key).ok_or(InputError::Unsupported(
            "the HID usage is not mapped to an X11 keycode",
        ))?;
        self.key_event(keycode, false)?;
        self.pressed_keys.remove(&keycode);
        Ok(())
    }

    fn button_down(&mut self, button: PointerButton) -> Result<(), InputError> {
        let button = pointer_button_to_x11(button);
        self.button_event(button, true)?;
        self.pressed_buttons.insert(button);
        Ok(())
    }

    fn button_up(&mut self, button: PointerButton) -> Result<(), InputError> {
        let button = pointer_button_to_x11(button);
        self.button_event(button, false)?;
        self.pressed_buttons.remove(&button);
        Ok(())
    }

    fn move_pointer(&mut self, x_norm: f64, y_norm: f64) -> Result<(), InputError> {
        let x = Self::normalized_coordinate(x_norm, self.root_width)?;
        let y = Self::normalized_coordinate(y_norm, self.root_height)?;
        self.fake_input(MOTION_NOTIFY_EVENT, 0, x, y)
    }

    fn wheel(&mut self, delta_x: f64, delta_y: f64) -> Result<(), InputError> {
        let horizontal_steps = Self::wheel_steps(delta_x, &mut self.horizontal_wheel_remainder)?;
        let vertical_steps = Self::wheel_steps(delta_y, &mut self.vertical_wheel_remainder)?;
        self.emit_wheel_steps(horizontal_steps, 6, 7)?;
        self.emit_wheel_steps(vertical_steps, 5, 4)
    }

    fn text_commit(&mut self, text: &str) -> Result<(), InputError> {
        for character in text.chars() {
            let (key, shift) = ascii_character_to_hid(character).ok_or(InputError::Unsupported(
                "X11 text commit currently supports ASCII text only",
            ))?;
            let keycode = hid_usage_to_x11_keycode(key).ok_or(InputError::Unsupported(
                "the text character is not mapped to an X11 keycode",
            ))?;
            let shift_keycode = hid_usage_to_x11_keycode(PhysicalKey(0xe1)).unwrap_or(50);
            let shift_already_pressed = self.pressed_keys.contains(&shift_keycode);
            if shift && !shift_already_pressed {
                self.key_event(shift_keycode, true)?;
            }
            let result = self
                .key_event(keycode, true)
                .and_then(|()| self.key_event(keycode, false));
            if shift && !shift_already_pressed {
                let release_result = self.key_event(shift_keycode, false);
                result.and(release_result)?;
            } else {
                result?;
            }
        }
        Ok(())
    }

    fn release_all(&mut self) -> Result<(), InputError> {
        let keys: Vec<_> = self.pressed_keys.iter().copied().collect();
        let buttons: Vec<_> = self.pressed_buttons.iter().copied().collect();
        let mut failure = None;
        for keycode in keys {
            if let Err(error) = self.key_event(keycode, false) {
                failure.get_or_insert(error);
            }
        }
        for button in buttons {
            if let Err(error) = self.button_event(button, false) {
                failure.get_or_insert(error);
            }
        }
        self.pressed_keys.clear();
        self.pressed_buttons.clear();
        failure.map_or(Ok(()), Err)
    }
}

impl Drop for X11InputBackend {
    fn drop(&mut self) {
        let _ = self.release_all();
    }
}

fn pointer_button_to_x11(button: PointerButton) -> u8 {
    match button {
        PointerButton::Left => 1,
        PointerButton::Middle => 2,
        PointerButton::Right => 3,
        PointerButton::Back => 8,
        PointerButton::Forward => 9,
    }
}

fn hid_usage_to_x11_keycode(key: PhysicalKey) -> Option<u8> {
    let usage = key.0;
    match usage {
        0x04 => Some(38),
        0x05 => Some(56),
        0x06 => Some(54),
        0x07 => Some(40),
        0x08 => Some(26),
        0x09 => Some(41),
        0x0a => Some(42),
        0x0b => Some(43),
        0x0c => Some(31),
        0x0d => Some(44),
        0x0e => Some(45),
        0x0f => Some(46),
        0x10 => Some(58),
        0x11 => Some(57),
        0x12 => Some(32),
        0x13 => Some(33),
        0x14 => Some(24),
        0x15 => Some(27),
        0x16 => Some(39),
        0x17 => Some(28),
        0x18 => Some(30),
        0x19 => Some(55),
        0x1a => Some(25),
        0x1b => Some(53),
        0x1c => Some(29),
        0x1d => Some(52),
        0x1e..=0x27 => Some(10 + (usage - 0x1e) as u8),
        0x28 => Some(36),
        0x29 => Some(9),
        0x2a => Some(22),
        0x2b => Some(23),
        0x2c => Some(65),
        0x2d => Some(20),
        0x2e => Some(21),
        0x2f => Some(34),
        0x30 => Some(35),
        0x31 => Some(51),
        0x33 => Some(47),
        0x34 => Some(48),
        0x35 => Some(49),
        0x36 => Some(59),
        0x37 => Some(60),
        0x38 => Some(61),
        0x4f => Some(114),
        0x50 => Some(113),
        0x51 => Some(116),
        0x52 => Some(111),
        0xe0 => Some(37),
        0xe1 => Some(50),
        0xe2 => Some(64),
        0xe3 => Some(133),
        0xe4 => Some(105),
        0xe5 => Some(62),
        0xe6 => Some(108),
        0xe7 => Some(134),
        _ => None,
    }
}

fn ascii_character_to_hid(character: char) -> Option<(PhysicalKey, bool)> {
    let value = match character {
        'a'..='z' => (0x04 + u32::from(character) - u32::from('a'), false),
        'A'..='Z' => (0x04 + u32::from(character) - u32::from('A'), true),
        '1'..='9' => (0x1e + u32::from(character) - u32::from('1'), false),
        '0' => (0x27, false),
        '\n' | '\r' => (0x28, false),
        '\t' => (0x2b, false),
        ' ' => (0x2c, false),
        '-' => (0x2d, false),
        '_' => (0x2d, true),
        '=' => (0x2e, false),
        '+' => (0x2e, true),
        '[' => (0x2f, false),
        '{' => (0x2f, true),
        ']' => (0x30, false),
        '}' => (0x30, true),
        '\\' => (0x31, false),
        '|' => (0x31, true),
        ';' => (0x33, false),
        ':' => (0x33, true),
        '\'' => (0x34, false),
        '"' => (0x34, true),
        '`' => (0x35, false),
        '~' => (0x35, true),
        ',' => (0x36, false),
        '<' => (0x36, true),
        '.' => (0x37, false),
        '>' => (0x37, true),
        '/' => (0x38, false),
        '?' => (0x38, true),
        '!' => (0x1e, true),
        '@' => (0x1f, true),
        '#' => (0x20, true),
        '$' => (0x21, true),
        '%' => (0x22, true),
        '^' => (0x23, true),
        '&' => (0x24, true),
        '*' => (0x25, true),
        '(' => (0x26, true),
        ')' => (0x27, true),
        _ => return None,
    };
    Some((PhysicalKey(value.0), value.1))
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
                    "PipeWire + xdg-desktop-portal ScreenCast: 已接入，等待用户授权".into()
                }
                UbuntuSession::X11 => "X11 GetImage: 已接入".into(),
                UbuntuSession::Unknown => "unsupported: 未检测到 Wayland/X11".into(),
            },
            render_status: "unsupported: OpenGL/Vulkan 原生表面未接入".into(),
            input_status: match self.session {
                UbuntuSession::Wayland => {
                    "xdg-desktop-portal RemoteDesktop: 已接入，会话启动时与屏幕共同授权".into()
                }
                UbuntuSession::X11 => "X11 XTest: 会话启动时连接并验证".into(),
                UbuntuSession::Unknown => "unsupported: 未检测到 Wayland/X11".into(),
            },
            privacy_status: "unsupported: 隐私屏与本地输入保护未接入".into(),
        }
    }

    fn input_backend(&self) -> Box<dyn InputBackend> {
        self.session.input_backend()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ubuntu_capabilities_report_actual_capture_and_input_boundaries() {
        let snapshot = UbuntuPlatform::detect().snapshot();
        assert!(snapshot.render_status.starts_with("unsupported:"));
        assert!(snapshot.privacy_status.starts_with("unsupported:"));
    }

    #[test]
    fn wayland_reports_joint_screencast_and_remote_desktop_authorization() {
        let snapshot = UbuntuPlatform {
            session: UbuntuSession::Wayland,
        }
        .snapshot();
        assert!(snapshot.capture_status.contains("ScreenCast"));
        assert!(snapshot.input_status.contains("RemoteDesktop"));
        assert!(!snapshot.input_status.starts_with("unsupported:"));
    }

    #[test]
    fn x11_maps_common_hid_usages_to_standard_keycodes() {
        assert_eq!(hid_usage_to_x11_keycode(PhysicalKey(0x04)), Some(38));
        assert_eq!(hid_usage_to_x11_keycode(PhysicalKey(0x05)), Some(56));
        assert_eq!(hid_usage_to_x11_keycode(PhysicalKey(0x1d)), Some(52));
        assert_eq!(hid_usage_to_x11_keycode(PhysicalKey(0x1e)), Some(10));
        assert_eq!(hid_usage_to_x11_keycode(PhysicalKey(0x28)), Some(36));
        assert_eq!(hid_usage_to_x11_keycode(PhysicalKey(0x52)), Some(111));
        assert_eq!(hid_usage_to_x11_keycode(PhysicalKey(0xe0)), Some(37));
        assert_eq!(hid_usage_to_x11_keycode(PhysicalKey(0xe7)), Some(134));
        assert_eq!(hid_usage_to_x11_keycode(PhysicalKey(0xff)), None);
    }

    #[test]
    fn wayland_maps_hid_usages_to_linux_evdev_keycodes() {
        assert_eq!(hid_usage_to_evdev_keycode(PhysicalKey(0x04)), Some(30));
        assert_eq!(hid_usage_to_evdev_keycode(PhysicalKey(0x1d)), Some(44));
        assert_eq!(hid_usage_to_evdev_keycode(PhysicalKey(0x28)), Some(28));
        assert_eq!(hid_usage_to_evdev_keycode(PhysicalKey(0x52)), Some(103));
        assert_eq!(hid_usage_to_evdev_keycode(PhysicalKey(0xe0)), Some(29));
        assert_eq!(hid_usage_to_evdev_keycode(PhysicalKey(0xe7)), Some(126));
        assert_eq!(hid_usage_to_evdev_keycode(PhysicalKey(0xff)), None);
    }

    #[test]
    fn wayland_pointer_buttons_use_linux_evdev_codes() {
        assert_eq!(pointer_button_to_evdev(PointerButton::Left), 0x110);
        assert_eq!(pointer_button_to_evdev(PointerButton::Right), 0x111);
        assert_eq!(pointer_button_to_evdev(PointerButton::Middle), 0x112);
        assert_eq!(pointer_button_to_evdev(PointerButton::Back), 0x113);
        assert_eq!(pointer_button_to_evdev(PointerButton::Forward), 0x114);
    }

    #[test]
    fn normalized_coordinates_cover_the_x11_root_bounds() {
        assert_eq!(X11InputBackend::normalized_coordinate(0.0, 1920), Ok(0));
        assert_eq!(X11InputBackend::normalized_coordinate(1.0, 1920), Ok(1919));
        assert!(X11InputBackend::normalized_coordinate(f64::NAN, 1920).is_err());
    }

    #[test]
    fn x11_pointer_buttons_and_fractional_wheel_deltas_have_stable_mappings() {
        assert_eq!(pointer_button_to_x11(PointerButton::Left), 1);
        assert_eq!(pointer_button_to_x11(PointerButton::Middle), 2);
        assert_eq!(pointer_button_to_x11(PointerButton::Right), 3);
        assert_eq!(pointer_button_to_x11(PointerButton::Back), 8);
        assert_eq!(pointer_button_to_x11(PointerButton::Forward), 9);

        let mut remainder = 0.0;
        assert_eq!(X11InputBackend::wheel_steps(0.4, &mut remainder), Ok(0));
        assert_eq!(X11InputBackend::wheel_steps(0.7, &mut remainder), Ok(1));
        assert!((remainder - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn ascii_text_maps_to_hid_keys_without_claiming_ime_support() {
        assert_eq!(
            ascii_character_to_hid('a'),
            Some((PhysicalKey(0x04), false))
        );
        assert_eq!(ascii_character_to_hid('A'), Some((PhysicalKey(0x04), true)));
        assert_eq!(ascii_character_to_hid('!'), Some((PhysicalKey(0x1e), true)));
        assert_eq!(
            ascii_character_to_hid('\n'),
            Some((PhysicalKey(0x28), false))
        );
        assert_eq!(ascii_character_to_hid('中'), None);
    }
}
