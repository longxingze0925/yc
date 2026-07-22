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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputEvent {
    KeyDown(PhysicalKey),
    KeyUp(PhysicalKey),
    ButtonDown(PointerButton),
    ButtonUp(PointerButton),
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

pub trait InputBackend {
    fn name(&self) -> &'static str;
    fn key_down(&mut self, key: PhysicalKey) -> Result<(), InputError>;
    fn key_up(&mut self, key: PhysicalKey) -> Result<(), InputError>;
    fn button_down(&mut self, button: PointerButton) -> Result<(), InputError>;
    fn button_up(&mut self, button: PointerButton) -> Result<(), InputError>;
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
}
