use remote_crypto::sha256;
use remote_protocol::SessionPermissions;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AntiAbuseDecision {
    Allow,
    WarnUser,
    Cooldown,
    Deny,
    Suspend,
    RelayQuarantine,
}

impl AntiAbuseDecision {
    const fn blocks_session(self) -> bool {
        matches!(self, Self::Cooldown | Self::Deny | Self::Suspend)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAccessDecision {
    Allow,
    RequirePrompt,
    RequireMfa,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyInput {
    pub requested: SessionPermissions,
    pub controlled_capabilities: SessionPermissions,
    pub mfa_verified: bool,
    pub mfa_required: bool,
    pub blacklisted: bool,
    pub anti_abuse: AntiAbuseDecision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyDecision {
    pub access: SessionAccessDecision,
    pub anti_abuse: AntiAbuseDecision,
    pub effective_permissions: SessionPermissions,
    pub permissions_digest: [u8; 32],
}

impl PolicyDecision {
    pub fn evaluate(input: PolicyInput) -> Self {
        let blocked = input.blacklisted || input.anti_abuse.blocks_session();
        let mut permissions = intersect(input.requested, input.controlled_capabilities);
        permissions.require_prompt = input.requested.require_prompt;
        if matches!(input.anti_abuse, AntiAbuseDecision::RelayQuarantine) {
            permissions.allow_relay = false;
        }
        if !input.mfa_verified {
            permissions.unattended = false;
            permissions.privacy_screen = false;
            permissions.block_local_input = false;
        }

        let access = if blocked {
            permissions = SessionPermissions::default();
            SessionAccessDecision::Deny
        } else if input.mfa_required && !input.mfa_verified {
            SessionAccessDecision::RequireMfa
        } else if permissions.require_prompt {
            SessionAccessDecision::RequirePrompt
        } else {
            SessionAccessDecision::Allow
        };
        let permissions_digest = permissions
            .canonical_bytes()
            .map(|bytes| sha256(&bytes))
            .unwrap_or([0; 32]);
        Self {
            access,
            anti_abuse: input.anti_abuse,
            effective_permissions: permissions,
            permissions_digest,
        }
    }
}

fn intersect(left: SessionPermissions, right: SessionPermissions) -> SessionPermissions {
    SessionPermissions {
        remote_desktop: left.remote_desktop && right.remote_desktop,
        input_control: left.input_control && right.input_control,
        clipboard: left.clipboard && right.clipboard,
        file_transfer: left.file_transfer && right.file_transfer,
        unattended: left.unattended && right.unattended,
        privacy_screen: left.privacy_screen && right.privacy_screen,
        block_local_input: left.block_local_input && right.block_local_input,
        require_prompt: left.require_prompt || right.require_prompt,
        allow_relay: left.allow_relay && right.allow_relay,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> SessionPermissions {
        SessionPermissions {
            remote_desktop: true,
            input_control: true,
            clipboard: true,
            file_transfer: true,
            unattended: true,
            privacy_screen: true,
            block_local_input: true,
            require_prompt: false,
            allow_relay: true,
        }
    }

    #[test]
    fn deny_and_relay_quarantine_fail_closed() {
        let denied = PolicyDecision::evaluate(PolicyInput {
            requested: full(),
            controlled_capabilities: full(),
            mfa_verified: true,
            mfa_required: false,
            blacklisted: true,
            anti_abuse: AntiAbuseDecision::Allow,
        });
        assert_eq!(denied.access, SessionAccessDecision::Deny);
        assert_eq!(denied.effective_permissions, SessionPermissions::default());

        let quarantined = PolicyDecision::evaluate(PolicyInput {
            requested: full(),
            controlled_capabilities: full(),
            mfa_verified: true,
            mfa_required: false,
            blacklisted: false,
            anti_abuse: AntiAbuseDecision::RelayQuarantine,
        });
        assert!(!quarantined.effective_permissions.allow_relay);
    }

    #[test]
    fn mfa_gate_removes_privileged_capabilities() {
        let decision = PolicyDecision::evaluate(PolicyInput {
            requested: full(),
            controlled_capabilities: full(),
            mfa_verified: false,
            mfa_required: true,
            blacklisted: false,
            anti_abuse: AntiAbuseDecision::WarnUser,
        });
        assert_eq!(decision.access, SessionAccessDecision::RequireMfa);
        assert!(!decision.effective_permissions.unattended);
        assert!(!decision.effective_permissions.privacy_screen);
    }
}
