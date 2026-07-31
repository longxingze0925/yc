use serde::{Deserialize, Serialize};
use uuid::Uuid;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputModifier {
    Ctrl,
    Alt,
    Shift,
    Meta,
    CapsLock,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InputEvent {
    pub session_id: Uuid,
    pub event_id: Uuid,
    pub display_id: String,
    pub input_kind: InputKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_event_kind: Option<KeyEventKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub physical_code: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan_code: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virtual_key: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logical_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x_norm: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y_norm: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub button: Option<MouseButton>,
    #[serde(default)]
    pub key_code: u32,
    #[serde(default)]
    pub modifiers: Vec<InputModifier>,
    #[serde(default)]
    pub wheel_delta_x: f64,
    #[serde(default)]
    pub wheel_delta_y: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub composition_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub composition_state: Option<CompositionState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keyboard_layout: Option<String>,
    #[serde(default)]
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
        if !self.wheel_delta_x.is_finite() || !self.wheel_delta_y.is_finite() {
            return Err(InputValidationError::InvalidWheelDelta);
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
    InvalidWheelDelta,
    UnexpectedText,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(kind: InputKind) -> InputEvent {
        InputEvent {
            session_id: Uuid::from_u128(1),
            event_id: Uuid::from_u128(2),
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
            modifiers: Vec::new(),
            wheel_delta_x: 0.0,
            wheel_delta_y: 0.0,
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

    #[test]
    fn ios_input_fixture_round_trips_with_frozen_wire_types() {
        let fixture = include_str!("../../../fixtures/protocol/input_event_v1.json");
        let event: InputEvent = serde_json::from_str(fixture).expect("decode iOS fixture");
        assert_eq!(
            event.session_id,
            Uuid::parse_str("00000000-0000-4000-8000-000000000001").expect("session UUID")
        );
        assert_eq!(event.physical_code, Some(4));
        assert_eq!(event.key_code, 4);
        assert_eq!(event.modifiers, vec![InputModifier::Ctrl]);
        assert_eq!(event.wheel_delta_x, 0.0);
        assert_eq!(event.wheel_delta_y, 0.0);
        assert_eq!(
            serde_json::to_value(event).expect("encode fixture"),
            serde_json::from_str::<serde_json::Value>(fixture).expect("fixture JSON")
        );
    }

    #[test]
    fn missing_defaultable_input_fields_decode_for_compact_events() {
        let event: InputEvent = serde_json::from_str(
            r#"{
                "session_id":"00000000-0000-4000-8000-000000000001",
                "event_id":"00000000-0000-4000-8000-000000000002",
                "display_id":"display-1",
                "input_kind":"release_all_keys",
                "timestamp_epoch_millis":1234
            }"#,
        )
        .expect("decode compact input");
        assert_eq!(event.key_code, 0);
        assert!(event.modifiers.is_empty());
        assert_eq!(event.wheel_delta_x, 0.0);
        assert_eq!(event.wheel_delta_y, 0.0);
        event.validate().expect("valid release-all");
    }
}
