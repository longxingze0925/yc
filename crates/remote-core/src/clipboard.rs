#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardDirection {
    ControllerToControlled,
    ControlledToController,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardState {
    Disabled,
    Requested,
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardError {
    Disabled,
    Pending,
    InvalidPayload,
    TooLarge,
}

pub const MAX_CLIPBOARD_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClipboardGate {
    enabled: bool,
    state: ClipboardState,
    direction: ClipboardDirection,
}

impl ClipboardGate {
    pub const fn new(direction: ClipboardDirection) -> Self {
        Self {
            enabled: false,
            state: ClipboardState::Disabled,
            direction,
        }
    }

    pub const fn direction(&self) -> ClipboardDirection {
        self.direction
    }

    pub const fn state(&self) -> ClipboardState {
        self.state
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        self.state = if enabled {
            ClipboardState::Requested
        } else {
            ClipboardState::Disabled
        };
    }

    pub fn respond(&mut self, accepted: bool) -> Result<(), ClipboardError> {
        if !self.enabled || self.state != ClipboardState::Requested {
            return Err(ClipboardError::Pending);
        }
        self.state = if accepted {
            ClipboardState::Accepted
        } else {
            ClipboardState::Rejected
        };
        Ok(())
    }

    pub fn validate_payload(&self, payload: &[u8]) -> Result<(), ClipboardError> {
        if !self.enabled {
            return Err(ClipboardError::Disabled);
        }
        if self.state != ClipboardState::Accepted {
            return Err(ClipboardError::Pending);
        }
        if payload.is_empty() {
            return Err(ClipboardError::InvalidPayload);
        }
        if payload.len() > MAX_CLIPBOARD_BYTES {
            return Err(ClipboardError::TooLarge);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clipboard_requires_independent_confirmation() {
        let mut gate = ClipboardGate::new(ClipboardDirection::ControllerToControlled);
        gate.set_enabled(true);
        assert_eq!(gate.validate_payload(b"x"), Err(ClipboardError::Pending));
        gate.respond(true).expect("accept");
        assert_eq!(gate.validate_payload(b"x"), Ok(()));
        gate.set_enabled(false);
        assert_eq!(gate.validate_payload(b"x"), Err(ClipboardError::Disabled));
    }
}
