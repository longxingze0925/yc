use remote_protocol::TransportPath;

pub const DEFAULT_RECONNECT_WINDOW_MILLIS: u64 = 30_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionPhase {
    Idle,
    Preparing,
    GatheringCandidates,
    ExchangingCandidates,
    Racing,
    EstablishingSecureSession,
    Connected,
    Degraded,
    Reconnecting,
    Closed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconnectTrigger {
    HeartbeatTimeout,
    TransportClosed,
    SustainedHighRtt,
    SustainedHighLoss,
    NetworkInterfaceChanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyReuseDecision {
    ResumeExistingKeys,
    RekeyRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurePathBinding {
    pub transport_path: TransportPath,
    pub candidate_pair_id: u128,
    pub relay_node_id: Option<String>,
    pub permissions_digest: [u8; 32],
}

impl SecurePathBinding {
    pub fn validate(&self) -> bool {
        self.transport_path.is_relay() == self.relay_node_id.is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconnectConfig {
    pub key_reuse_window_millis: u64,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            key_reuse_window_millis: DEFAULT_RECONNECT_WINDOW_MILLIS,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconnectError {
    InvalidState,
    InvalidPathBinding,
    ReconnectForbidden,
}

#[derive(Debug, Clone)]
pub struct ConnectionStateMachine {
    phase: ConnectionPhase,
    config: ReconnectConfig,
    active_binding: Option<SecurePathBinding>,
    pending_binding: Option<SecurePathBinding>,
    last_authenticated_activity_epoch_millis: Option<u64>,
    reconnect_forbidden: bool,
}

impl ConnectionStateMachine {
    pub fn new(config: ReconnectConfig) -> Self {
        Self {
            phase: ConnectionPhase::Idle,
            config,
            active_binding: None,
            pending_binding: None,
            last_authenticated_activity_epoch_millis: None,
            reconnect_forbidden: false,
        }
    }

    pub fn phase(&self) -> ConnectionPhase {
        self.phase
    }

    pub fn active_binding(&self) -> Option<&SecurePathBinding> {
        self.active_binding.as_ref()
    }

    pub fn start(&mut self) -> Result<(), ReconnectError> {
        self.transition(ConnectionPhase::Idle, ConnectionPhase::Preparing)
    }

    pub fn permissions_prepared(&mut self) -> Result<(), ReconnectError> {
        self.transition(
            ConnectionPhase::Preparing,
            ConnectionPhase::GatheringCandidates,
        )
    }

    pub fn candidates_gathered(&mut self) -> Result<(), ReconnectError> {
        self.transition(
            ConnectionPhase::GatheringCandidates,
            ConnectionPhase::ExchangingCandidates,
        )
    }

    pub fn candidates_exchanged(&mut self) -> Result<(), ReconnectError> {
        self.transition(
            ConnectionPhase::ExchangingCandidates,
            ConnectionPhase::Racing,
        )
    }

    pub fn initial_path_selected(
        &mut self,
        binding: SecurePathBinding,
    ) -> Result<KeyReuseDecision, ReconnectError> {
        if self.phase != ConnectionPhase::Racing {
            return Err(ReconnectError::InvalidState);
        }
        self.set_pending_binding(binding)?;
        self.phase = ConnectionPhase::EstablishingSecureSession;
        Ok(KeyReuseDecision::RekeyRequired)
    }

    pub fn secure_session_established(
        &mut self,
        now_epoch_millis: u64,
    ) -> Result<(), ReconnectError> {
        if self.phase != ConnectionPhase::EstablishingSecureSession {
            return Err(ReconnectError::InvalidState);
        }
        if let Some(binding) = self.pending_binding.take() {
            self.active_binding = Some(binding);
        }
        if self.active_binding.is_none() {
            return Err(ReconnectError::InvalidState);
        }
        self.last_authenticated_activity_epoch_millis = Some(now_epoch_millis);
        self.phase = ConnectionPhase::Connected;
        Ok(())
    }

    pub fn record_authenticated_activity(
        &mut self,
        now_epoch_millis: u64,
    ) -> Result<(), ReconnectError> {
        if !matches!(
            self.phase,
            ConnectionPhase::Connected | ConnectionPhase::Degraded
        ) {
            return Err(ReconnectError::InvalidState);
        }
        self.last_authenticated_activity_epoch_millis = Some(now_epoch_millis);
        Ok(())
    }

    pub fn mark_degraded(&mut self) -> Result<(), ReconnectError> {
        self.transition(ConnectionPhase::Connected, ConnectionPhase::Degraded)
    }

    pub fn begin_reconnect(&mut self, _trigger: ReconnectTrigger) -> Result<(), ReconnectError> {
        if self.reconnect_forbidden {
            return Err(ReconnectError::ReconnectForbidden);
        }
        if !matches!(
            self.phase,
            ConnectionPhase::Connected | ConnectionPhase::Degraded
        ) {
            return Err(ReconnectError::InvalidState);
        }
        self.phase = ConnectionPhase::Reconnecting;
        Ok(())
    }

    pub fn reconnect_path_selected(
        &mut self,
        binding: SecurePathBinding,
        now_epoch_millis: u64,
    ) -> Result<KeyReuseDecision, ReconnectError> {
        if self.reconnect_forbidden {
            return Err(ReconnectError::ReconnectForbidden);
        }
        if self.phase != ConnectionPhase::Reconnecting {
            return Err(ReconnectError::InvalidState);
        }
        if !binding.validate() {
            return Err(ReconnectError::InvalidPathBinding);
        }

        let within_window = self
            .last_authenticated_activity_epoch_millis
            .is_some_and(|last| {
                now_epoch_millis.saturating_sub(last) <= self.config.key_reuse_window_millis
            });
        let unchanged = self.active_binding.as_ref() == Some(&binding);
        let decision = if within_window && unchanged {
            KeyReuseDecision::ResumeExistingKeys
        } else {
            KeyReuseDecision::RekeyRequired
        };
        self.pending_binding = Some(binding);
        self.phase = ConnectionPhase::EstablishingSecureSession;
        Ok(decision)
    }

    pub fn close_by_local_or_remote_user(&mut self) {
        self.forbid_reconnect_and_close();
    }

    pub fn close_for_remote_reboot(&mut self) {
        self.forbid_reconnect_and_close();
    }

    pub fn fail(&mut self) {
        self.pending_binding = None;
        self.phase = ConnectionPhase::Failed;
    }

    fn set_pending_binding(&mut self, binding: SecurePathBinding) -> Result<(), ReconnectError> {
        if !binding.validate() {
            return Err(ReconnectError::InvalidPathBinding);
        }
        self.pending_binding = Some(binding);
        Ok(())
    }

    fn transition(
        &mut self,
        expected: ConnectionPhase,
        next: ConnectionPhase,
    ) -> Result<(), ReconnectError> {
        if self.phase != expected {
            return Err(ReconnectError::InvalidState);
        }
        self.phase = next;
        Ok(())
    }

    fn forbid_reconnect_and_close(&mut self) {
        self.reconnect_forbidden = true;
        self.active_binding = None;
        self.pending_binding = None;
        self.last_authenticated_activity_epoch_millis = None;
        self.phase = ConnectionPhase::Closed;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p2p_binding(pair_id: u128) -> SecurePathBinding {
        SecurePathBinding {
            transport_path: TransportPath::UdpP2p,
            candidate_pair_id: pair_id,
            relay_node_id: None,
            permissions_digest: [1_u8; 32],
        }
    }

    fn connected_machine(now: u64) -> ConnectionStateMachine {
        let mut machine = ConnectionStateMachine::new(ReconnectConfig::default());
        machine.start().expect("start");
        machine.permissions_prepared().expect("permissions");
        machine.candidates_gathered().expect("gathered");
        machine.candidates_exchanged().expect("exchanged");
        assert_eq!(
            machine.initial_path_selected(p2p_binding(7)),
            Ok(KeyReuseDecision::RekeyRequired)
        );
        machine.secure_session_established(now).expect("secure");
        machine
    }

    #[test]
    fn follows_frozen_connection_phases() {
        let machine = connected_machine(1_000);
        assert_eq!(machine.phase(), ConnectionPhase::Connected);
        assert_eq!(machine.active_binding(), Some(&p2p_binding(7)));
    }

    #[test]
    fn same_pair_within_thirty_seconds_can_resume_keys() {
        let mut machine = connected_machine(1_000);
        machine
            .begin_reconnect(ReconnectTrigger::HeartbeatTimeout)
            .expect("reconnect");
        assert_eq!(
            machine.reconnect_path_selected(p2p_binding(7), 31_000),
            Ok(KeyReuseDecision::ResumeExistingKeys)
        );
    }

    #[test]
    fn changed_pair_path_or_permissions_requires_rekey() {
        let mut machine = connected_machine(1_000);
        machine
            .begin_reconnect(ReconnectTrigger::NetworkInterfaceChanged)
            .expect("reconnect");
        assert_eq!(
            machine.reconnect_path_selected(p2p_binding(8), 2_000),
            Ok(KeyReuseDecision::RekeyRequired)
        );

        machine.secure_session_established(2_100).expect("secure");
        machine
            .begin_reconnect(ReconnectTrigger::TransportClosed)
            .expect("reconnect");
        let relay = SecurePathBinding {
            transport_path: TransportPath::QuicRelay,
            candidate_pair_id: 8,
            relay_node_id: Some("relay-a".to_owned()),
            permissions_digest: [1_u8; 32],
        };
        assert_eq!(
            machine.reconnect_path_selected(relay, 3_000),
            Ok(KeyReuseDecision::RekeyRequired)
        );
    }

    #[test]
    fn expired_window_and_remote_reboot_do_not_reuse_keys() {
        let mut machine = connected_machine(1_000);
        machine
            .begin_reconnect(ReconnectTrigger::HeartbeatTimeout)
            .expect("reconnect");
        assert_eq!(
            machine.reconnect_path_selected(p2p_binding(7), 31_001),
            Ok(KeyReuseDecision::RekeyRequired)
        );

        let mut rebooted = connected_machine(1_000);
        rebooted.close_for_remote_reboot();
        assert_eq!(rebooted.phase(), ConnectionPhase::Closed);
        assert_eq!(
            rebooted.begin_reconnect(ReconnectTrigger::TransportClosed),
            Err(ReconnectError::ReconnectForbidden)
        );
    }
}
