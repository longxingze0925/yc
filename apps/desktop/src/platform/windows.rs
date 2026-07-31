use super::windows_keymap::{hid_usage_to_windows_key, WindowsSemanticKey};
use super::{DesktopPlatform, PlatformSnapshot};
use crate::input::{InputBackend, InputError, PhysicalKey, PointerButton};
use enigo::{Axis, Button, Coordinate, Direction, Enigo, Key, Keyboard, Mouse, Settings};
use std::collections::BTreeSet;

const MAX_WHEEL_STEPS_PER_EVENT: f64 = 120.0;

pub struct WindowsInputBackend {
    enigo: Enigo,
    pressed_keys: BTreeSet<PhysicalKey>,
    pressed_buttons: BTreeSet<PointerButton>,
    horizontal_wheel_remainder: f64,
    vertical_wheel_remainder: f64,
}

impl WindowsInputBackend {
    fn connect() -> Result<Self, &'static str> {
        let enigo = Enigo::new(&Settings::default())
            .map_err(|_| "could not initialize the Windows SendInput backend")?;
        Ok(Self {
            enigo,
            pressed_keys: BTreeSet::new(),
            pressed_buttons: BTreeSet::new(),
            horizontal_wheel_remainder: 0.0,
            vertical_wheel_remainder: 0.0,
        })
    }

    fn send_key(&mut self, key: PhysicalKey, direction: Direction) -> Result<(), InputError> {
        let mapping = hid_usage_to_windows_key(key).ok_or(InputError::Unsupported(
            "the HID usage is not mapped to a Windows key",
        ))?;
        let result = match mapping.semantic {
            Some(semantic) => self.enigo.key(semantic_key(semantic), direction),
            None => self.enigo.raw(mapping.scan_code, direction),
        };
        result.map_err(|_| InputError::InjectionFailed("Windows SendInput key event failed"))
    }

    fn send_button(
        &mut self,
        button: PointerButton,
        direction: Direction,
    ) -> Result<(), InputError> {
        self.enigo
            .button(pointer_button(button), direction)
            .map_err(|_| InputError::InjectionFailed("Windows SendInput mouse button failed"))
    }

    fn normalized_coordinate(value: f64, dimension: i32) -> Result<i32, InputError> {
        if !value.is_finite() || !(0.0..=1.0).contains(&value) || dimension <= 0 {
            return Err(InputError::InjectionFailed(
                "pointer coordinates must be finite normalized values",
            ));
        }
        Ok((value * f64::from(dimension.saturating_sub(1))).round() as i32)
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
}

impl InputBackend for WindowsInputBackend {
    fn name(&self) -> &'static str {
        "Windows SendInput"
    }

    fn key_down(&mut self, key: PhysicalKey) -> Result<(), InputError> {
        self.send_key(key, Direction::Press)?;
        self.pressed_keys.insert(key);
        Ok(())
    }

    fn key_up(&mut self, key: PhysicalKey) -> Result<(), InputError> {
        self.send_key(key, Direction::Release)?;
        self.pressed_keys.remove(&key);
        Ok(())
    }

    fn button_down(&mut self, button: PointerButton) -> Result<(), InputError> {
        self.send_button(button, Direction::Press)?;
        self.pressed_buttons.insert(button);
        Ok(())
    }

    fn button_up(&mut self, button: PointerButton) -> Result<(), InputError> {
        self.send_button(button, Direction::Release)?;
        self.pressed_buttons.remove(&button);
        Ok(())
    }

    fn move_pointer(&mut self, x_norm: f64, y_norm: f64) -> Result<(), InputError> {
        let (width, height) = self
            .enigo
            .main_display()
            .map_err(|_| InputError::InjectionFailed("Windows display bounds query failed"))?;
        let x = Self::normalized_coordinate(x_norm, width)?;
        let y = Self::normalized_coordinate(y_norm, height)?;
        self.enigo
            .move_mouse(x, y, Coordinate::Abs)
            .map_err(|_| InputError::InjectionFailed("Windows SendInput pointer move failed"))
    }

    fn wheel(&mut self, delta_x: f64, delta_y: f64) -> Result<(), InputError> {
        let horizontal_steps = Self::wheel_steps(delta_x, &mut self.horizontal_wheel_remainder)?;
        let vertical_steps = Self::wheel_steps(delta_y, &mut self.vertical_wheel_remainder)?;
        if horizontal_steps != 0 {
            self.enigo
                .scroll(horizontal_steps, Axis::Horizontal)
                .map_err(|_| {
                    InputError::InjectionFailed("Windows SendInput horizontal wheel failed")
                })?;
        }
        if vertical_steps != 0 {
            // X11 button 4/5 and SendInput use opposite signs for vertical wheel motion.
            self.enigo
                .scroll(-vertical_steps, Axis::Vertical)
                .map_err(|_| {
                    InputError::InjectionFailed("Windows SendInput vertical wheel failed")
                })?;
        }
        Ok(())
    }

    fn text_commit(&mut self, text: &str) -> Result<(), InputError> {
        self.enigo
            .text(text)
            .map_err(|_| InputError::InjectionFailed("Windows Unicode text input failed"))
    }

    fn release_all(&mut self) -> Result<(), InputError> {
        let keys: Vec<_> = self.pressed_keys.iter().copied().collect();
        let buttons: Vec<_> = self.pressed_buttons.iter().copied().collect();
        let mut failure = None;
        for key in keys {
            if let Err(error) = self.send_key(key, Direction::Release) {
                failure.get_or_insert(error);
            }
        }
        for button in buttons {
            if let Err(error) = self.send_button(button, Direction::Release) {
                failure.get_or_insert(error);
            }
        }
        self.pressed_keys.clear();
        self.pressed_buttons.clear();
        failure.map_or(Ok(()), Err)
    }
}

impl Drop for WindowsInputBackend {
    fn drop(&mut self) {
        let _ = self.release_all();
    }
}

fn semantic_key(key: WindowsSemanticKey) -> Key {
    match key {
        WindowsSemanticKey::LeftControl => Key::LControl,
        WindowsSemanticKey::LeftAlt => Key::LMenu,
        WindowsSemanticKey::LeftMeta => Key::LWin,
        WindowsSemanticKey::RightControl => Key::RControl,
        WindowsSemanticKey::RightAlt => Key::RMenu,
        WindowsSemanticKey::RightMeta => Key::RWin,
        WindowsSemanticKey::PrintScreen => Key::PrintScr,
        WindowsSemanticKey::Pause => Key::Pause,
        WindowsSemanticKey::Insert => Key::Insert,
        WindowsSemanticKey::Home => Key::Home,
        WindowsSemanticKey::PageUp => Key::PageUp,
        WindowsSemanticKey::Delete => Key::Delete,
        WindowsSemanticKey::End => Key::End,
        WindowsSemanticKey::PageDown => Key::PageDown,
        WindowsSemanticKey::RightArrow => Key::RightArrow,
        WindowsSemanticKey::LeftArrow => Key::LeftArrow,
        WindowsSemanticKey::DownArrow => Key::DownArrow,
        WindowsSemanticKey::UpArrow => Key::UpArrow,
        WindowsSemanticKey::NumLock => Key::Numlock,
        WindowsSemanticKey::NumpadDivide => Key::Divide,
        WindowsSemanticKey::Application => Key::Apps,
    }
}

fn pointer_button(button: PointerButton) -> Button {
    match button {
        PointerButton::Left => Button::Left,
        PointerButton::Right => Button::Right,
        PointerButton::Middle => Button::Middle,
        PointerButton::Back => Button::Back,
        PointerButton::Forward => Button::Forward,
    }
}

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
            capture_status: "Windows Graphics Capture + DXGI fallback: 已接入".into(),
            render_status: "unsupported: D3D11/DirectComposition 未接入".into(),
            input_status: "Windows SendInput + Unicode: 会话启动时初始化".into(),
            privacy_status: "unsupported: 隐私屏与本地输入保护未接入".into(),
        }
    }

    fn input_backend(&self) -> Box<dyn InputBackend> {
        match WindowsInputBackend::connect() {
            Ok(backend) => Box::new(backend),
            Err(reason) => Box::new(crate::input::UnsupportedInputBackend::new(
                "Windows SendInput",
                reason,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_capabilities_report_controlled_side_support() {
        let snapshot = WindowsPlatform::detect().snapshot();
        assert!(snapshot.capture_status.contains("已接入"));
        assert!(snapshot.render_status.starts_with("unsupported:"));
        assert!(snapshot.input_status.contains("SendInput"));
        assert!(snapshot.privacy_status.starts_with("unsupported:"));
    }

    #[test]
    fn normalized_coordinates_cover_the_primary_display_bounds() {
        assert_eq!(WindowsInputBackend::normalized_coordinate(0.0, 1920), Ok(0));
        assert_eq!(
            WindowsInputBackend::normalized_coordinate(1.0, 1920),
            Ok(1919)
        );
        assert!(WindowsInputBackend::normalized_coordinate(f64::NAN, 1920).is_err());
    }

    #[test]
    fn wheel_accumulation_is_fractional_and_bounded() {
        let mut remainder = 0.0;
        assert_eq!(WindowsInputBackend::wheel_steps(0.4, &mut remainder), Ok(0));
        assert_eq!(WindowsInputBackend::wheel_steps(0.7, &mut remainder), Ok(1));
        assert!((remainder - 0.1).abs() < f64::EPSILON);
        assert_eq!(
            WindowsInputBackend::wheel_steps(10_000.0, &mut remainder),
            Ok(MAX_WHEEL_STEPS_PER_EVENT as i32)
        );
    }
}
