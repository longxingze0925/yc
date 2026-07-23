#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyCapability {
    Supported,
    PermissionRequired,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyState {
    Disabled,
    Enabling,
    Enabled,
    Restoring,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivacyError {
    Unsupported,
    PermissionRequired,
    InvalidState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrivacyController {
    capability: PrivacyCapability,
    state: PrivacyState,
}

impl PrivacyController {
    pub const fn new(capability: PrivacyCapability) -> Self {
        Self {
            capability,
            state: PrivacyState::Disabled,
        }
    }

    pub const fn state(&self) -> PrivacyState {
        self.state
    }
    pub const fn capability(&self) -> PrivacyCapability {
        self.capability
    }

    pub fn enable(&mut self) -> Result<(), PrivacyError> {
        match self.capability {
            PrivacyCapability::Unsupported => Err(PrivacyError::Unsupported),
            PrivacyCapability::PermissionRequired => Err(PrivacyError::PermissionRequired),
            PrivacyCapability::Supported if self.state == PrivacyState::Disabled => {
                self.state = PrivacyState::Enabled;
                Ok(())
            }
            PrivacyCapability::Supported => Err(PrivacyError::InvalidState),
        }
    }

    pub fn disable(&mut self) {
        self.state = PrivacyState::Disabled;
    }

    pub fn connection_lost(&mut self) {
        if self.state == PrivacyState::Enabled {
            self.state = PrivacyState::Restoring;
        }
    }

    pub fn restore_local_state(&mut self) {
        if self.state == PrivacyState::Restoring {
            self.state = PrivacyState::Disabled;
        }
    }

    pub fn mark_failed(&mut self) {
        self.state = PrivacyState::Failed;
    }

    pub fn restore_after_failure(&mut self) {
        if self.state != PrivacyState::Failed {
            return;
        }
        self.state = PrivacyState::Disabled;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privacy_mode_always_restores_after_disconnect() {
        let mut controller = PrivacyController::new(PrivacyCapability::Supported);
        controller.enable().expect("permission");
        controller.connection_lost();
        assert_eq!(controller.state(), PrivacyState::Restoring);
        controller.restore_local_state();
        assert_eq!(controller.state(), PrivacyState::Disabled);
    }
}
