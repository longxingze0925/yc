use std::collections::HashSet;

use remote_protocol::{InputEvent, InputKind, KeyEventKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputApplyResult {
    Forward,
    KeyPressed,
    KeyReleased,
    ReleasedAll { count: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputStateError {
    InvalidEvent,
    KeyNotPressed,
}

#[derive(Debug, Default)]
pub struct InputState {
    pressed_keys: HashSet<u32>,
}

impl InputState {
    pub fn apply(&mut self, event: &InputEvent) -> Result<InputApplyResult, InputStateError> {
        event
            .validate()
            .map_err(|_| InputStateError::InvalidEvent)?;
        if event.input_kind == InputKind::ReleaseAllKeys {
            return Ok(self.release_all());
        }
        if event.input_kind != InputKind::PhysicalKey {
            return Ok(InputApplyResult::Forward);
        }
        let key = event.key_code;
        if key == 0 {
            return Err(InputStateError::InvalidEvent);
        }
        match event.key_event_kind {
            Some(KeyEventKind::Down) => {
                self.pressed_keys.insert(key);
                Ok(InputApplyResult::KeyPressed)
            }
            Some(KeyEventKind::Repeat) => self
                .pressed_keys
                .contains(&key)
                .then_some(InputApplyResult::Forward)
                .ok_or(InputStateError::KeyNotPressed),
            Some(KeyEventKind::Up) | Some(KeyEventKind::Tap) => {
                if !self.pressed_keys.remove(&key) {
                    return Err(InputStateError::KeyNotPressed);
                }
                Ok(InputApplyResult::KeyReleased)
            }
            None => Err(InputStateError::InvalidEvent),
        }
    }

    pub fn release_all(&mut self) -> InputApplyResult {
        let count = self.pressed_keys.len();
        self.pressed_keys.clear();
        InputApplyResult::ReleasedAll { count }
    }

    pub fn pressed_count(&self) -> usize {
        self.pressed_keys.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(kind: KeyEventKind, code: u32) -> InputEvent {
        InputEvent {
            session_id: uuid::Uuid::from_u128(1),
            event_id: uuid::Uuid::from_u128(code as u128),
            display_id: "primary".into(),
            input_kind: InputKind::PhysicalKey,
            key_event_kind: Some(kind),
            physical_code: Some(code),
            scan_code: None,
            virtual_key: None,
            logical_key: Some("a".into()),
            x_norm: None,
            y_norm: None,
            button: None,
            key_code: code,
            modifiers: Vec::new(),
            wheel_delta_x: 0.0,
            wheel_delta_y: 0.0,
            text: None,
            composition_text: None,
            composition_state: None,
            keyboard_layout: Some("en-US".into()),
            is_auto_repeat: false,
            timestamp_epoch_millis: 1,
        }
    }

    #[test]
    fn disconnect_release_clears_every_key() {
        let mut state = InputState::default();
        state.apply(&key(KeyEventKind::Down, 30)).expect("down");
        state.apply(&key(KeyEventKind::Down, 31)).expect("down");
        assert_eq!(state.pressed_count(), 2);
        assert_eq!(
            state.release_all(),
            InputApplyResult::ReleasedAll { count: 2 }
        );
        assert_eq!(state.pressed_count(), 0);
    }
}
