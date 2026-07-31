use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhysicalKey(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PointerButton {
    Left,
    Right,
    Middle,
    Back,
    Forward,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InputEvent {
    KeyDown(PhysicalKey),
    KeyUp(PhysicalKey),
    ButtonDown(PointerButton),
    ButtonUp(PointerButton),
    PointerMove { x_norm: f64, y_norm: f64 },
    Wheel { delta_x: f64, delta_y: f64 },
    TextCommit(String),
    ReleaseAll,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputError {
    Unsupported(&'static str),
    InjectionFailed(&'static str),
}

impl fmt::Display for InputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(reason) => write!(formatter, "input unsupported: {reason}"),
            Self::InjectionFailed(reason) => write!(formatter, "input injection failed: {reason}"),
        }
    }
}

impl Error for InputError {}

pub trait InputBackend: Send {
    fn name(&self) -> &'static str;
    fn key_down(&mut self, key: PhysicalKey) -> Result<(), InputError>;
    fn key_up(&mut self, key: PhysicalKey) -> Result<(), InputError>;
    fn button_down(&mut self, button: PointerButton) -> Result<(), InputError>;
    fn button_up(&mut self, button: PointerButton) -> Result<(), InputError>;
    fn move_pointer(&mut self, _x_norm: f64, _y_norm: f64) -> Result<(), InputError> {
        Err(InputError::Unsupported(
            "pointer movement is not supported by this backend",
        ))
    }
    fn wheel(&mut self, _delta_x: f64, _delta_y: f64) -> Result<(), InputError> {
        Err(InputError::Unsupported(
            "pointer wheel is not supported by this backend",
        ))
    }
    fn text_commit(&mut self, _text: &str) -> Result<(), InputError> {
        Err(InputError::Unsupported(
            "text commit is not supported by this backend",
        ))
    }
    fn release_all(&mut self) -> Result<(), InputError>;
}

impl<T: InputBackend + ?Sized> InputBackend for Box<T> {
    fn name(&self) -> &'static str {
        (**self).name()
    }

    fn key_down(&mut self, key: PhysicalKey) -> Result<(), InputError> {
        (**self).key_down(key)
    }

    fn key_up(&mut self, key: PhysicalKey) -> Result<(), InputError> {
        (**self).key_up(key)
    }

    fn button_down(&mut self, button: PointerButton) -> Result<(), InputError> {
        (**self).button_down(button)
    }

    fn button_up(&mut self, button: PointerButton) -> Result<(), InputError> {
        (**self).button_up(button)
    }

    fn move_pointer(&mut self, x_norm: f64, y_norm: f64) -> Result<(), InputError> {
        (**self).move_pointer(x_norm, y_norm)
    }

    fn wheel(&mut self, delta_x: f64, delta_y: f64) -> Result<(), InputError> {
        (**self).wheel(delta_x, delta_y)
    }

    fn text_commit(&mut self, text: &str) -> Result<(), InputError> {
        (**self).text_commit(text)
    }

    fn release_all(&mut self) -> Result<(), InputError> {
        (**self).release_all()
    }
}

#[derive(Debug)]
pub struct InputManager<B: InputBackend> {
    backend: B,
    pressed_keys: BTreeSet<PhysicalKey>,
    pressed_buttons: BTreeSet<PointerButton>,
}

impl<B: InputBackend> InputManager<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            pressed_keys: BTreeSet::new(),
            pressed_buttons: BTreeSet::new(),
        }
    }

    pub fn backend_name(&self) -> &'static str {
        self.backend.name()
    }

    pub fn key_down(&mut self, key: PhysicalKey) -> Result<(), InputError> {
        self.backend.key_down(key)?;
        self.pressed_keys.insert(key);
        Ok(())
    }

    pub fn key_up(&mut self, key: PhysicalKey) -> Result<(), InputError> {
        let result = self.backend.key_up(key);
        self.pressed_keys.remove(&key);
        result
    }

    pub fn button_down(&mut self, button: PointerButton) -> Result<(), InputError> {
        self.backend.button_down(button)?;
        self.pressed_buttons.insert(button);
        Ok(())
    }

    pub fn button_up(&mut self, button: PointerButton) -> Result<(), InputError> {
        let result = self.backend.button_up(button);
        self.pressed_buttons.remove(&button);
        result
    }

    pub fn move_pointer(&mut self, x_norm: f64, y_norm: f64) -> Result<(), InputError> {
        self.backend.move_pointer(x_norm, y_norm)
    }

    pub fn wheel(&mut self, delta_x: f64, delta_y: f64) -> Result<(), InputError> {
        self.backend.wheel(delta_x, delta_y)
    }

    pub fn text_commit(&mut self, text: &str) -> Result<(), InputError> {
        self.backend.text_commit(text)
    }

    pub fn apply_protocol_event(
        &mut self,
        event: &remote_protocol::InputEvent,
    ) -> Result<(), InputError> {
        use remote_protocol::{InputKind, KeyEventKind};

        event
            .validate()
            .map_err(|_| InputError::InjectionFailed("remote input event failed validation"))?;
        match event.input_kind {
            InputKind::MouseMove => {
                let (Some(x), Some(y)) = (event.x_norm, event.y_norm) else {
                    return Err(InputError::InjectionFailed(
                        "mouse move is missing normalized coordinates",
                    ));
                };
                self.move_pointer(x, y)
            }
            InputKind::MouseButton => {
                let button = event
                    .button
                    .map(protocol_pointer_button)
                    .ok_or(InputError::InjectionFailed("mouse button is missing"))?;
                if let (Some(x), Some(y)) = (event.x_norm, event.y_norm) {
                    self.move_pointer(x, y)?;
                }
                match event.key_event_kind {
                    Some(KeyEventKind::Down) => self.button_down(button),
                    Some(KeyEventKind::Up) => self.button_up(button),
                    Some(KeyEventKind::Tap) => {
                        self.button_down(button)?;
                        self.button_up(button)
                    }
                    _ => Err(InputError::InjectionFailed("mouse button state is invalid")),
                }
            }
            InputKind::MouseWheel => self.wheel(event.wheel_delta_x, event.wheel_delta_y),
            InputKind::PhysicalKey => {
                let code = event
                    .physical_code
                    .filter(|code| *code != 0)
                    .or((event.key_code != 0).then_some(event.key_code))
                    .ok_or(InputError::InjectionFailed("physical key code is missing"))?;
                let key = PhysicalKey(code);
                match event.key_event_kind {
                    Some(KeyEventKind::Down | KeyEventKind::Repeat) => self.key_down(key),
                    Some(KeyEventKind::Up) => self.key_up(key),
                    Some(KeyEventKind::Tap) => {
                        self.key_down(key)?;
                        self.key_up(key)
                    }
                    None => Err(InputError::InjectionFailed("physical key state is missing")),
                }
            }
            InputKind::TextCommit => self.text_commit(
                event
                    .text
                    .as_deref()
                    .ok_or(InputError::InjectionFailed("text commit is empty"))?,
            ),
            InputKind::Shortcut => self.apply_shortcut(
                event
                    .logical_key
                    .as_deref()
                    .ok_or(InputError::InjectionFailed("shortcut name is missing"))?,
            ),
            InputKind::ReleaseAllKeys => self.release_all(),
            InputKind::ImeComposition | InputKind::TouchGesture => Err(InputError::Unsupported(
                "IME composition and touch gestures are not mapped by this desktop backend",
            )),
        }
    }

    fn apply_shortcut(&mut self, shortcut: &str) -> Result<(), InputError> {
        let (modifier, key) = match shortcut {
            "ctrl_c" => (PhysicalKey(0xe0), Some(PhysicalKey(0x06))),
            "ctrl_v" => (PhysicalKey(0xe0), Some(PhysicalKey(0x19))),
            "ctrl_x" => (PhysicalKey(0xe0), Some(PhysicalKey(0x1b))),
            "ctrl_z" => (PhysicalKey(0xe0), Some(PhysicalKey(0x1d))),
            "ctrl_y" => (PhysicalKey(0xe0), Some(PhysicalKey(0x1c))),
            "alt_tab" => (PhysicalKey(0xe2), Some(PhysicalKey(0x2b))),
            "super_win" => (PhysicalKey(0xe3), None),
            _ => return Err(InputError::Unsupported("shortcut is not supported")),
        };
        self.key_down(modifier)?;
        let result = if let Some(key) = key {
            self.key_down(key)
                .and_then(|()| self.key_up(key))
                .and_then(|()| self.key_up(modifier))
        } else {
            self.key_up(modifier)
        };
        if result.is_err() {
            let _ = self.release_all();
        }
        result
    }

    pub fn release_all(&mut self) -> Result<(), InputError> {
        let result = self.backend.release_all();
        self.pressed_keys.clear();
        self.pressed_buttons.clear();
        result
    }

    pub fn has_pressed_inputs(&self) -> bool {
        !self.pressed_keys.is_empty() || !self.pressed_buttons.is_empty()
    }
}

fn protocol_pointer_button(button: remote_protocol::MouseButton) -> PointerButton {
    match button {
        remote_protocol::MouseButton::Left => PointerButton::Left,
        remote_protocol::MouseButton::Right => PointerButton::Right,
        remote_protocol::MouseButton::Middle => PointerButton::Middle,
        remote_protocol::MouseButton::Back => PointerButton::Back,
        remote_protocol::MouseButton::Forward => PointerButton::Forward,
    }
}

impl<B: InputBackend> Drop for InputManager<B> {
    fn drop(&mut self) {
        let _ = self.release_all();
    }
}

#[derive(Debug, Clone, Default)]
pub struct SafeMockInputBackend {
    events: Arc<Mutex<Vec<InputEvent>>>,
}

impl SafeMockInputBackend {
    pub fn events(&self) -> Vec<InputEvent> {
        self.events.lock().expect("mock input log lock").clone()
    }

    fn record(&self, event: InputEvent) {
        self.events.lock().expect("mock input log lock").push(event);
    }
}

impl InputBackend for SafeMockInputBackend {
    fn name(&self) -> &'static str {
        "safe mock input"
    }

    fn key_down(&mut self, key: PhysicalKey) -> Result<(), InputError> {
        self.record(InputEvent::KeyDown(key));
        Ok(())
    }

    fn key_up(&mut self, key: PhysicalKey) -> Result<(), InputError> {
        self.record(InputEvent::KeyUp(key));
        Ok(())
    }

    fn button_down(&mut self, button: PointerButton) -> Result<(), InputError> {
        self.record(InputEvent::ButtonDown(button));
        Ok(())
    }

    fn button_up(&mut self, button: PointerButton) -> Result<(), InputError> {
        self.record(InputEvent::ButtonUp(button));
        Ok(())
    }

    fn move_pointer(&mut self, x_norm: f64, y_norm: f64) -> Result<(), InputError> {
        self.record(InputEvent::PointerMove { x_norm, y_norm });
        Ok(())
    }

    fn wheel(&mut self, delta_x: f64, delta_y: f64) -> Result<(), InputError> {
        self.record(InputEvent::Wheel { delta_x, delta_y });
        Ok(())
    }

    fn text_commit(&mut self, text: &str) -> Result<(), InputError> {
        self.record(InputEvent::TextCommit(text.into()));
        Ok(())
    }

    fn release_all(&mut self) -> Result<(), InputError> {
        self.record(InputEvent::ReleaseAll);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UnsupportedInputBackend {
    name: &'static str,
    reason: &'static str,
}

impl UnsupportedInputBackend {
    pub const fn new(name: &'static str, reason: &'static str) -> Self {
        Self { name, reason }
    }

    fn error(&self) -> InputError {
        InputError::Unsupported(self.reason)
    }
}

impl InputBackend for UnsupportedInputBackend {
    fn name(&self) -> &'static str {
        self.name
    }

    fn key_down(&mut self, _key: PhysicalKey) -> Result<(), InputError> {
        Err(self.error())
    }

    fn key_up(&mut self, _key: PhysicalKey) -> Result<(), InputError> {
        Err(self.error())
    }

    fn button_down(&mut self, _button: PointerButton) -> Result<(), InputError> {
        Err(self.error())
    }

    fn button_up(&mut self, _button: PointerButton) -> Result<(), InputError> {
        Err(self.error())
    }

    fn move_pointer(&mut self, _x_norm: f64, _y_norm: f64) -> Result<(), InputError> {
        Err(self.error())
    }

    fn wheel(&mut self, _delta_x: f64, _delta_y: f64) -> Result<(), InputError> {
        Err(self.error())
    }

    fn text_commit(&mut self, _text: &str) -> Result<(), InputError> {
        Err(self.error())
    }

    fn release_all(&mut self) -> Result<(), InputError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_all_clears_every_pressed_input() {
        let backend = SafeMockInputBackend::default();
        let observer = backend.clone();
        let mut input = InputManager::new(backend);
        input.key_down(PhysicalKey(0x04)).expect("key down");
        input.button_down(PointerButton::Left).expect("button down");
        assert!(input.has_pressed_inputs());

        input.release_all().expect("release all");
        assert!(!input.has_pressed_inputs());
        assert_eq!(observer.events().last(), Some(&InputEvent::ReleaseAll));
    }

    #[test]
    fn dropping_input_manager_releases_all() {
        let backend = SafeMockInputBackend::default();
        let observer = backend.clone();
        {
            let mut input = InputManager::new(backend);
            input.key_down(PhysicalKey(0xE0)).expect("control down");
        }
        assert_eq!(observer.events().last(), Some(&InputEvent::ReleaseAll));
    }

    #[test]
    fn manager_forwards_pointer_wheel_and_text_events() {
        let backend = SafeMockInputBackend::default();
        let observer = backend.clone();
        let mut input = InputManager::new(backend);

        input.move_pointer(0.25, 0.75).expect("pointer move");
        input.wheel(-1.0, 2.0).expect("wheel");
        input
            .text_commit("text is only recorded in this test")
            .expect("text commit");

        assert_eq!(
            observer.events(),
            vec![
                InputEvent::PointerMove {
                    x_norm: 0.25,
                    y_norm: 0.75,
                },
                InputEvent::Wheel {
                    delta_x: -1.0,
                    delta_y: 2.0,
                },
                InputEvent::TextCommit("text is only recorded in this test".into()),
            ]
        );
    }

    fn protocol_event(kind: remote_protocol::InputKind) -> remote_protocol::InputEvent {
        remote_protocol::InputEvent {
            session_id: uuid::Uuid::from_u128(1),
            event_id: uuid::Uuid::from_u128(2),
            display_id: "primary".into(),
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
            timestamp_epoch_millis: 1,
        }
    }

    #[test]
    fn protocol_pointer_and_shortcut_reach_the_backend_in_order() {
        let backend = SafeMockInputBackend::default();
        let observer = backend.clone();
        let mut input = InputManager::new(backend);
        let mut pointer = protocol_event(remote_protocol::InputKind::MouseMove);
        pointer.x_norm = Some(0.25);
        pointer.y_norm = Some(0.75);
        input.apply_protocol_event(&pointer).expect("pointer");

        let mut shortcut = protocol_event(remote_protocol::InputKind::Shortcut);
        shortcut.logical_key = Some("ctrl_c".into());
        input.apply_protocol_event(&shortcut).expect("shortcut");

        assert_eq!(
            observer.events(),
            vec![
                InputEvent::PointerMove {
                    x_norm: 0.25,
                    y_norm: 0.75,
                },
                InputEvent::KeyDown(PhysicalKey(0xe0)),
                InputEvent::KeyDown(PhysicalKey(0x06)),
                InputEvent::KeyUp(PhysicalKey(0x06)),
                InputEvent::KeyUp(PhysicalKey(0xe0)),
            ]
        );
        assert!(!input.has_pressed_inputs());
    }
}
