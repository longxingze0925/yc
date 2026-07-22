use serde::{Deserialize, Serialize};

use crate::ChannelId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputKind {
    MouseMove,
    MouseButton,
    MouseWheel,
    PhysicalKey,
    TextCommit,
    ImeComposition,
    Shortcut,
    TouchGesture,
    ReleaseAllKeys,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyEventKind {
    Down,
    Up,
    Repeat,
    Tap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    Back,
    Forward,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompositionState {
    Started,
    Updated,
    Committed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InputEvent {
    pub session_id: u128,
    pub event_id: u128,
    pub display_id: String,
    pub input_kind: InputKind,
    pub key_event_kind: Option<KeyEventKind>,
    pub physical_code: Option<String>,
    pub scan_code: Option<u32>,
    pub virtual_key: Option<u32>,
    pub logical_key: Option<String>,
    pub x_norm: Option<f64>,
    pub y_norm: Option<f64>,
    pub button: Option<MouseButton>,
    pub key_code: u32,
    pub modifiers: u32,
    pub wheel_delta_x: i32,
    pub wheel_delta_y: i32,
    pub text: Option<String>,
    pub composition_text: Option<String>,
    pub composition_state: Option<CompositionState>,
    pub keyboard_layout: Option<String>,
    pub is_auto_repeat: bool,
    pub timestamp_epoch_millis: u64,
}

impl InputEvent {
    pub fn accepts_channel(&self, channel: ChannelId) -> bool {
        match self.input_kind {
            InputKind::MouseMove => {
                matches!(channel, ChannelId::InputReliable | ChannelId::InputRealtime)
            }
            _ => channel == ChannelId::InputReliable,
        }
    }

    pub fn validate(&self) -> Result<(), InputValidationError> {
        for coordinate in [self.x_norm, self.y_norm].into_iter().flatten() {
            if !coordinate.is_finite() || !(0.0..=1.0).contains(&coordinate) {
                return Err(InputValidationError::InvalidNormalizedCoordinate);
            }
        }
        if self.input_kind == InputKind::ReleaseAllKeys
            && (self.text.is_some() || self.composition_text.is_some())
        {
            return Err(InputValidationError::UnexpectedText);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputValidationError {
    InvalidNormalizedCoordinate,
    UnexpectedText,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: InputKind) -> InputEvent {
        InputEvent {
            session_id: 1,
            event_id: 2,
            display_id: "primary".to_owned(),
            input_kind: kind,
            key_event_kind: None,
            physical_code: None,
            scan_code: None,
            virtual_key: None,
            logical_key: None,
            x_norm: None,
            y_norm: None,
            button: None,
            key_code: 0,
            modifiers: 0,
            wheel_delta_x: 0,
            wheel_delta_y: 0,
            text: None,
            composition_text: None,
            composition_state: None,
            keyboard_layout: None,
            is_auto_repeat: false,
            timestamp_epoch_millis: 3,
        }
    }

    #[test]
    fn only_mouse_move_can_use_realtime_channel() {
        assert!(event(InputKind::MouseMove).accepts_channel(ChannelId::InputRealtime));
        assert!(!event(InputKind::PhysicalKey).accepts_channel(ChannelId::InputRealtime));
        assert!(!event(InputKind::ReleaseAllKeys).accepts_channel(ChannelId::InputRealtime));
    }
}
