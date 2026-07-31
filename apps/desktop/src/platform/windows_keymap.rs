use crate::input::PhysicalKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WindowsSemanticKey {
    LeftControl,
    LeftAlt,
    LeftMeta,
    RightControl,
    RightAlt,
    RightMeta,
    PrintScreen,
    Pause,
    Insert,
    Home,
    PageUp,
    Delete,
    End,
    PageDown,
    RightArrow,
    LeftArrow,
    DownArrow,
    UpArrow,
    NumLock,
    NumpadDivide,
    Application,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct WindowsKeyMapping {
    pub scan_code: u16,
    pub semantic: Option<WindowsSemanticKey>,
}

const fn raw(scan_code: u16) -> WindowsKeyMapping {
    WindowsKeyMapping {
        scan_code,
        semantic: None,
    }
}

const fn semantic(scan_code: u16, key: WindowsSemanticKey) -> WindowsKeyMapping {
    WindowsKeyMapping {
        scan_code,
        semantic: Some(key),
    }
}

/// Maps USB HID keyboard-page usages to Windows Set 1 scan codes.
///
/// Extended and multi-byte keys carry a semantic key because `SendInput` must
/// set the extended-key flag instead of submitting the `E0` prefix as data.
pub(super) fn hid_usage_to_windows_key(key: PhysicalKey) -> Option<WindowsKeyMapping> {
    let mapping = match key.0 {
        0x04 => raw(0x1e),
        0x05 => raw(0x30),
        0x06 => raw(0x2e),
        0x07 => raw(0x20),
        0x08 => raw(0x12),
        0x09 => raw(0x21),
        0x0a => raw(0x22),
        0x0b => raw(0x23),
        0x0c => raw(0x17),
        0x0d => raw(0x24),
        0x0e => raw(0x25),
        0x0f => raw(0x26),
        0x10 => raw(0x32),
        0x11 => raw(0x31),
        0x12 => raw(0x18),
        0x13 => raw(0x19),
        0x14 => raw(0x10),
        0x15 => raw(0x13),
        0x16 => raw(0x1f),
        0x17 => raw(0x14),
        0x18 => raw(0x16),
        0x19 => raw(0x2f),
        0x1a => raw(0x11),
        0x1b => raw(0x2d),
        0x1c => raw(0x15),
        0x1d => raw(0x2c),
        0x1e..=0x26 => raw(0x02 + (key.0 - 0x1e) as u16),
        0x27 => raw(0x0b),
        0x28 => raw(0x1c),
        0x29 => raw(0x01),
        0x2a => raw(0x0e),
        0x2b => raw(0x0f),
        0x2c => raw(0x39),
        0x2d => raw(0x0c),
        0x2e => raw(0x0d),
        0x2f => raw(0x1a),
        0x30 => raw(0x1b),
        0x31 => raw(0x2b),
        0x32 => raw(0x2b),
        0x33 => raw(0x27),
        0x34 => raw(0x28),
        0x35 => raw(0x29),
        0x36 => raw(0x33),
        0x37 => raw(0x34),
        0x38 => raw(0x35),
        0x39 => raw(0x3a),
        0x3a..=0x43 => raw(0x3b + (key.0 - 0x3a) as u16),
        0x44 => raw(0x57),
        0x45 => raw(0x58),
        0x46 => semantic(0x37, WindowsSemanticKey::PrintScreen),
        0x47 => raw(0x46),
        0x48 => semantic(0x45, WindowsSemanticKey::Pause),
        0x49 => semantic(0x52, WindowsSemanticKey::Insert),
        0x4a => semantic(0x47, WindowsSemanticKey::Home),
        0x4b => semantic(0x49, WindowsSemanticKey::PageUp),
        0x4c => semantic(0x53, WindowsSemanticKey::Delete),
        0x4d => semantic(0x4f, WindowsSemanticKey::End),
        0x4e => semantic(0x51, WindowsSemanticKey::PageDown),
        0x4f => semantic(0x4d, WindowsSemanticKey::RightArrow),
        0x50 => semantic(0x4b, WindowsSemanticKey::LeftArrow),
        0x51 => semantic(0x50, WindowsSemanticKey::DownArrow),
        0x52 => semantic(0x48, WindowsSemanticKey::UpArrow),
        0x53 => semantic(0x45, WindowsSemanticKey::NumLock),
        0x54 => semantic(0x35, WindowsSemanticKey::NumpadDivide),
        0x55 => raw(0x37),
        0x56 => raw(0x4a),
        0x57 => raw(0x4e),
        // Enigo documents EXT (0xff00) as the marker for E0-prefixed raw scan codes.
        0x58 => raw(0xff1c),
        0x59 => raw(0x4f),
        0x5a => raw(0x50),
        0x5b => raw(0x51),
        0x5c => raw(0x4b),
        0x5d => raw(0x4c),
        0x5e => raw(0x4d),
        0x5f => raw(0x47),
        0x60 => raw(0x48),
        0x61 => raw(0x49),
        0x62 => raw(0x52),
        0x63 => raw(0x53),
        0x64 => raw(0x56),
        0x65 => semantic(0x5d, WindowsSemanticKey::Application),
        0xe0 => semantic(0x1d, WindowsSemanticKey::LeftControl),
        0xe1 => raw(0x2a),
        0xe2 => semantic(0x38, WindowsSemanticKey::LeftAlt),
        0xe3 => semantic(0x5b, WindowsSemanticKey::LeftMeta),
        0xe4 => semantic(0x1d, WindowsSemanticKey::RightControl),
        0xe5 => raw(0x36),
        0xe6 => semantic(0x38, WindowsSemanticKey::RightAlt),
        0xe7 => semantic(0x5c, WindowsSemanticKey::RightMeta),
        _ => return None,
    };
    Some(mapping)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_usb_hid_letters_digits_and_modifiers_to_windows_set_one() {
        assert_eq!(hid_usage_to_windows_key(PhysicalKey(0x04)), Some(raw(0x1e)));
        assert_eq!(hid_usage_to_windows_key(PhysicalKey(0x1d)), Some(raw(0x2c)));
        assert_eq!(hid_usage_to_windows_key(PhysicalKey(0x1e)), Some(raw(0x02)));
        assert_eq!(hid_usage_to_windows_key(PhysicalKey(0x27)), Some(raw(0x0b)));
        assert_eq!(hid_usage_to_windows_key(PhysicalKey(0xe1)), Some(raw(0x2a)));
        assert_eq!(hid_usage_to_windows_key(PhysicalKey(0xe5)), Some(raw(0x36)));
    }

    #[test]
    fn extended_keys_keep_semantics_needed_by_send_input() {
        assert_eq!(
            hid_usage_to_windows_key(PhysicalKey(0xe4)),
            Some(semantic(0x1d, WindowsSemanticKey::RightControl))
        );
        assert_eq!(
            hid_usage_to_windows_key(PhysicalKey(0x52)),
            Some(semantic(0x48, WindowsSemanticKey::UpArrow))
        );
        assert_eq!(
            hid_usage_to_windows_key(PhysicalKey(0x46)),
            Some(semantic(0x37, WindowsSemanticKey::PrintScreen))
        );
    }

    #[test]
    fn unsupported_and_ambiguous_hid_usages_are_rejected() {
        assert_eq!(hid_usage_to_windows_key(PhysicalKey(0)), None);
        assert_eq!(hid_usage_to_windows_key(PhysicalKey(0xffff)), None);
    }

    #[test]
    fn maps_keypad_enter_and_iso_keyboard_positions_without_conflating_them() {
        assert_eq!(
            hid_usage_to_windows_key(PhysicalKey(0x58)),
            Some(raw(0xff1c))
        );
        assert_eq!(hid_usage_to_windows_key(PhysicalKey(0x32)), Some(raw(0x2b)));
        assert_eq!(hid_usage_to_windows_key(PhysicalKey(0x64)), Some(raw(0x56)));
    }
}
