mod memory;
mod model;
mod repository;

#[cfg(feature = "postgres")]
pub mod postgres;

pub use memory::MemoryRepository;
pub use model::*;
pub use repository::{Repository, StoreError};

pub const INITIAL_SCHEMA_SQL: &str =
    include_str!("../../../infra/migrations/0001_initial_schema.sql");
pub const INITIAL_SCHEMA_RUNNER: &str = include_str!("../../../infra/migrations/run-0001.sh");
pub const INITIAL_SCHEMA_VERIFICATION_SQL: &str =
    include_str!("../../../infra/migrations/verify-0001.sql");

pub const V1_TABLES: &[&str] = &[
    "accounts",
    "account_sessions",
    "account_mfa_factors",
    "mfa_recovery_code_deliveries",
    "account_recovery_codes",
    "account_risk_challenges",
    "device_enrollment_grants",
    "trusted_controller_devices",
    "abuse_reports",
    "abuse_cases",
    "abuse_enforcement_actions",
    "abuse_risk_events",
    "api_idempotency_keys",
    "devices",
    "device_policies",
    "device_access_rules",
    "device_local_security_settings",
    "access_policies",
    "access_policy_assignments",
    "policy_evaluations",
    "verification_codes",
    "unattended_secrets",
    "relay_nodes",
    "sessions",
    "remote_reboot_requests",
    "connection_candidates",
    "connection_candidate_pairs",
    "session_events",
    "audit_logs",
    "relay_session_stats",
    "file_transfers",
    "organizations",
    "organization_devices",
    "organization_members",
    "roles",
    "role_permissions",
    "organization_policies",
    "device_groups",
    "device_group_members",
    "device_group_policies",
    "client_release_channels",
    "client_release_artifacts",
    "client_update_checks",
];

pub const DEFERRED_M8_TABLES: &[&str] = &[
    "organization_region_policies",
    "region_catalog",
    "object_storage_locations",
    "session_recording_policies",
    "session_recordings",
    "session_recording_access_logs",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn table_definition(table: &str) -> &str {
        INITIAL_SCHEMA_SQL
            .split(&format!("CREATE TABLE {table} ("))
            .nth(1)
            .and_then(|rest| rest.split("\n);").next())
            .unwrap_or_else(|| panic!("missing table definition: {table}"))
    }

    fn normalized(value: &str) -> String {
        value.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn table_columns(table: &str) -> Vec<&str> {
        table_definition(table)
            .lines()
            .filter(|line| line.starts_with("    ") && !line.starts_with("        "))
            .map(str::trim)
            .map(|line| {
                line.split_whitespace()
                    .next()
                    .expect("column definition")
                    .trim_end_matches(',')
            })
            .filter(|name| {
                name.chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_')
                    && !matches!(*name, "CONSTRAINT" | "UNIQUE" | "FOREIGN" | "CHECK")
            })
            .collect()
    }

    fn assert_values_present(table: &str, values: &[&str]) {
        let definition = table_definition(table);
        for value in values {
            assert!(
                definition.contains(&format!("'{value}'")),
                "{table} is missing frozen value {value}"
            );
        }
    }

    #[test]
    fn migration_contains_exact_v1_table_set() {
        let mut actual = INITIAL_SCHEMA_SQL
            .lines()
            .filter_map(|line| line.strip_prefix("CREATE TABLE "))
            .filter_map(|line| line.split_whitespace().next())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        let mut expected = V1_TABLES
            .iter()
            .map(|table| (*table).to_owned())
            .collect::<Vec<_>>();

        actual.sort();
        expected.sort();

        assert_eq!(actual, expected);
        assert!(DEFERRED_M8_TABLES
            .iter()
            .all(|table| !INITIAL_SCHEMA_SQL.contains(&format!("CREATE TABLE {table} "))));
    }

    #[test]
    fn candidate_table_has_no_probe_token_columns() {
        let candidate_table = table_definition("connection_candidates");

        assert!(!candidate_table.contains("candidate_token"));
        assert!(!candidate_table.contains("candidate_token_binding_hash"));
        assert!(!candidate_table.contains("expires_at_epoch_millis"));
        assert!(candidate_table.contains("observe_result_id TEXT"));
        assert_values_present(
            "connection_candidates",
            &[
                "controller",
                "controlled",
                "lan_direct",
                "udp_p2p",
                "quic_relay",
                "tls_443_relay",
                "udp_observed",
                "local_interface",
                "relay_allocated",
                "static_config",
            ],
        );
    }

    #[test]
    fn migration_is_final_and_transactional() {
        assert!(INITIAL_SCHEMA_SQL.starts_with("-- SCHEMA_FREEZE_STATUS=FINAL\nBEGIN;"));
        assert!(INITIAL_SCHEMA_SQL.trim_end().ends_with("COMMIT;"));
        assert!(!INITIAL_SCHEMA_SQL.contains("SCHEMA_FREEZE_STATUS=DRAFT"));
        assert!(!INITIAL_SCHEMA_SQL.contains("SCHEMA_FREEZE_STATUS=SKELETON"));
        assert!(!INITIAL_SCHEMA_SQL.contains("jsonb_object_length"));
    }

    #[test]
    fn migration_runner_requires_confirmation_and_an_empty_target() {
        for required in [
            "SCHEMA_FREEZE_CONFIRMED",
            "SCHEMA_TARGET_EMPTY_CONFIRMED",
            "SCHEMA_FREEZE_STATUS=FINAL",
            "target public schema is not empty",
            "ROLLBACK;",
        ] {
            assert!(
                INITIAL_SCHEMA_RUNNER.contains(required),
                "runner guard: {required}"
            );
        }
        assert!(INITIAL_SCHEMA_VERIFICATION_SQL.contains("expected exactly 43 V1 tables"));
        assert!(INITIAL_SCHEMA_VERIFICATION_SQL.contains("missing frozen CHECK constraints"));
    }

    #[test]
    fn account_identity_contract_is_frozen_in_the_initial_schema() {
        assert_eq!(
            table_columns("account_sessions"),
            [
                "account_session_id",
                "account_id",
                "refresh_token_hash",
                "device_label",
                "ip_address",
                "user_agent",
                "mfa_verified",
                "expires_at_epoch_millis",
                "revoked_at_epoch_millis",
                "revoked_reason",
                "created_at_epoch_millis",
                "updated_at_epoch_millis",
            ]
        );
        assert_eq!(
            table_columns("account_risk_challenges"),
            [
                "risk_challenge_id",
                "account_id",
                "device_id",
                "purpose",
                "operation_binding_hash",
                "risk_level",
                "required_methods",
                "status",
                "attempts_remaining",
                "ip_address",
                "user_agent",
                "expires_at_epoch_millis",
                "created_at_epoch_millis",
                "verified_at_epoch_millis",
                "consumed_at_epoch_millis",
                "login_device_state",
                "login_device_id",
                "login_device_public_key",
                "login_device_public_key_fingerprint",
                "login_public_key_id",
                "login_public_key_version",
                "login_client_nonce",
                "login_server_nonce",
                "login_request_binding_hash",
                "login_ip_address_hash",
                "login_user_agent_hash",
                "login_trusted_device_id",
                "login_protocol_version",
                "login_attempts_limit",
                "login_account_updated_at_epoch_millis",
            ]
        );
        assert_eq!(
            table_columns("device_enrollment_grants"),
            [
                "grant_id",
                "grant_secret_hash",
                "account_id",
                "device_id",
                "device_public_key_fingerprint",
                "login_challenge_id",
                "login_challenge_binding_hash",
                "trust_proof_type",
                "trust_level",
                "establish_trust",
                "protocol_version",
                "issued_account_session_id",
                "issued_at_epoch_millis",
                "expires_at_epoch_millis",
                "consumed_at_epoch_millis",
                "registration_request_binding_hash",
                "registered_public_key_id",
                "registered_trusted_device_id",
                "created_at_epoch_millis",
            ]
        );
        assert_eq!(
            table_columns("mfa_recovery_code_deliveries"),
            [
                "delivery_id",
                "account_id",
                "account_session_id",
                "factor_id",
                "idempotency_key_hash",
                "finish_request_binding_hash",
                "client_ephemeral_public_key",
                "server_ephemeral_public_key",
                "nonce",
                "ciphertext",
                "recovery_code_count",
                "created_at_epoch_millis",
                "expires_at_epoch_millis",
                "acknowledged_at_epoch_millis",
            ]
        );

        assert_values_present(
            "account_sessions",
            &[
                "logout",
                "password_changed",
                "mfa_enabled",
                "mfa_disabled",
                "account_locked",
                "device_unbound",
                "refresh_replay",
            ],
        );
        assert_values_present(
            "device_enrollment_grants",
            &[
                "device_signature_and_mfa",
                "device_signature_and_recovery_code",
                "standard",
                "high_risk_step_up_required",
            ],
        );

        let sql = normalized(INITIAL_SCHEMA_SQL);
        for fragment in [
            "mfa_verified BOOLEAN NOT NULL",
            "revoked_reason TEXT CHECK",
            "login_device_public_key BYTEA CHECK (octet_length(login_device_public_key) = 32)",
            "login_device_state TEXT CHECK (login_device_state IN ('registered', 'pending_enrollment'))",
            "CONSTRAINT ck_account_risk_challenges_device_identity CHECK",
            "WHEN purpose = 'login_mfa' AND login_device_state = 'registered' THEN device_id IS NOT NULL AND login_device_id IS NOT NULL AND device_id = login_device_id",
            "WHEN purpose = 'login_mfa' AND login_device_state = 'pending_enrollment' THEN device_id IS NULL",
            "WHEN purpose = 'new_controller_device' THEN device_id IS NULL",
            "device_id TEXT REFERENCES devices(device_id) ON DELETE RESTRICT",
            "AND login_protocol_version BETWEEN 1 AND 65535",
            "AND login_attempts_limit BETWEEN 1 AND 5",
            "AND login_account_updated_at_epoch_millis IS NOT NULL",
            "AND login_account_updated_at_epoch_millis IS NULL",
            "UNIQUE (account_session_id, account_id)",
            "CONSTRAINT fk_device_enrollment_grants_challenge_account FOREIGN KEY (login_challenge_id, account_id) REFERENCES account_risk_challenges(risk_challenge_id, account_id) ON DELETE RESTRICT",
            "CONSTRAINT fk_device_enrollment_grants_session_account FOREIGN KEY (issued_account_session_id, account_id) REFERENCES account_sessions(account_session_id, account_id) ON DELETE RESTRICT",
            "CONSTRAINT uq_device_enrollment_grants_secret_hash UNIQUE (grant_secret_hash)",
            "CONSTRAINT uq_device_enrollment_grants_login_challenge UNIQUE (login_challenge_id)",
            "CONSTRAINT ck_device_enrollment_grants_trust_policy CHECK",
            "CHECK (expires_at_epoch_millis <= issued_at_epoch_millis + 300000)",
            "CONSTRAINT ck_device_enrollment_grants_registration_result CHECK",
            "CONSTRAINT fk_device_enrollment_grants_registered_trusted_device FOREIGN KEY (registered_trusted_device_id, device_id, account_id) REFERENCES trusted_controller_devices(trusted_device_id, controller_device_id, account_id) ON DELETE RESTRICT",
            "CONSTRAINT ck_trusted_controller_devices_trust_policy CHECK",
            "CONSTRAINT uq_mfa_recovery_code_deliveries_idempotency UNIQUE (account_id, idempotency_key_hash)",
            "CONSTRAINT fk_mfa_recovery_code_deliveries_session_account FOREIGN KEY (account_session_id, account_id) REFERENCES account_sessions(account_session_id, account_id) ON DELETE RESTRICT",
            "CONSTRAINT fk_mfa_recovery_code_deliveries_factor_account FOREIGN KEY (factor_id, account_id) REFERENCES account_mfa_factors(factor_id, account_id) ON DELETE RESTRICT",
            "nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 12)",
            "CHECK (expires_at_epoch_millis <= created_at_epoch_millis + 86400000)",
            "CREATE INDEX idx_device_enrollment_grants_account_device_active",
            "CREATE INDEX idx_device_enrollment_grants_expiry",
            "CREATE INDEX idx_mfa_recovery_code_deliveries_expiry",
            "'device_enrollment_grant_consumed'",
        ] {
            assert!(sql.contains(fragment), "missing account identity constraint: {fragment}");
        }

        let grant = table_definition("device_enrollment_grants");
        assert!(grant.contains("grant_secret_hash BYTEA NOT NULL"));
        assert!(!grant.contains("grant_secret BYTEA"));

        let delivery = table_definition("mfa_recovery_code_deliveries");
        assert!(delivery.contains("ciphertext BYTEA NOT NULL"));
        assert!(!delivery.contains("recovery_codes"));
        assert!(!delivery.contains("server_ephemeral_private_key"));

        let account_sessions = table_definition("account_sessions");
        assert!(!account_sessions.contains("mfa_verified BOOLEAN NOT NULL DEFAULT"));
        assert!(!account_sessions.contains("mfa_verified BOOLEAN DEFAULT"));

        for verification_guard in [
            "unexpected account_sessions columns",
            "account_sessions.mfa_verified must be BOOLEAN NOT NULL without a default",
            "unexpected device_enrollment_grants columns",
            "unexpected mfa_recovery_code_deliveries columns",
            "account identity security tables contain forbidden plaintext columns",
            "required account identity foreign key is missing",
            "device enrollment trust proof and level policy is missing",
            "trusted device proof, level, and TTL policy is missing",
            "account risk challenge device_id foreign key is missing",
            "account risk challenge device identity constraint is missing",
            "account risk challenge device identity mismatch",
        ] {
            assert!(
                INITIAL_SCHEMA_VERIFICATION_SQL.contains(verification_guard),
                "missing account identity verification guard: {verification_guard}"
            );
        }
    }

    #[test]
    fn risk_challenge_required_methods_are_purpose_bound() {
        let definition = normalized(table_definition("account_risk_challenges"));

        for fragment in [
            "CONSTRAINT ck_account_risk_challenges_required_methods CHECK",
            "purpose = 'login_mfa' AND required_methods IN ('[]'::JSONB, '[\"totp\",\"recovery_code\"]'::JSONB)",
            "purpose = 'password_change' AND required_methods IN ('[\"password\"]'::JSONB, '[\"totp\",\"recovery_code\"]'::JSONB)",
            "purpose NOT IN ('login_mfa', 'password_change') AND required_methods = '[\"totp\",\"recovery_code\"]'::JSONB",
        ] {
            assert!(
                definition.contains(fragment),
                "missing required_methods policy fragment: {fragment}"
            );
        }

        for forbidden in [
            "'[\"recovery_code\",\"totp\"]'::JSONB",
            "'[\"totp\"]'::JSONB",
            "'[\"recovery_code\"]'::JSONB",
            "'[\"webauthn\"]'::JSONB",
        ] {
            assert!(
                !definition.contains(forbidden),
                "required_methods policy admits a non-frozen array: {forbidden}"
            );
        }

        for verification_guard in [
            "account risk challenge required_methods policy constraint is missing",
            "account risk challenge required_methods policy mismatch",
            "'[\"recovery_code\",\"totp\"]'::JSONB, FALSE",
            "'[\"totp\",\"recovery_code\",\"recovery_code\"]'::JSONB, FALSE",
            "'[\"webauthn\"]'::JSONB, FALSE",
        ] {
            assert!(
                INITIAL_SCHEMA_VERIFICATION_SQL.contains(verification_guard),
                "missing required_methods verification guard: {verification_guard}"
            );
        }
    }

    #[test]
    fn frozen_status_event_and_actor_enums_are_complete() {
        assert_values_present(
            "sessions",
            &[
                "pending_code_verification",
                "pending_unattended_verification",
                "code_verified",
                "unattended_verified",
                "waiting_approval",
                "accepted",
                "connected",
                "degraded",
                "reconnecting",
                "cancelled",
                "closed",
                "rejected",
                "failed",
            ],
        );
        let sessions = table_definition("sessions");
        assert!(!sessions.contains("'invited'"));
        assert!(!sessions.contains("'connecting'"));

        assert_values_present(
            "session_events",
            &[
                "invite_created",
                "invite_accepted",
                "invite_rejected",
                "code_verified",
                "unattended_verified",
                "waiting_approval",
                "cancelled",
                "candidate_exchanged",
                "candidate_pair_selected",
                "transport_selected",
                "key_exchange_started",
                "key_exchange_completed",
                "key_exchange_failed",
                "reboot_requested",
                "reboot_accepted",
                "reboot_cancelled",
                "reboot_started",
                "reboot_resume_ready",
                "reboot_resumed",
                "reboot_failed",
                "connected",
                "degraded",
                "reconnecting",
                "closed",
                "failed",
            ],
        );

        for table in ["session_events", "audit_logs"] {
            assert_values_present(
                table,
                &[
                    "anonymous",
                    "account",
                    "device",
                    "service",
                    "system",
                    "controller",
                    "controlled",
                    "none",
                    "api_server",
                    "signal_server",
                    "relay_server",
                    "release_checker",
                    "scheduler",
                ],
            );
        }
    }

    #[test]
    fn v1_frozen_enum_checks_are_present() {
        let sql = normalized(INITIAL_SCHEMA_SQL);
        for fragment in [
            "factor_type TEXT NOT NULL CHECK (factor_type IN ('totp'))",
            "status TEXT NOT NULL CHECK (status IN ('active', 'disabled'))",
            "challenge_status TEXT NOT NULL CHECK (challenge_status IN ('active', 'consumed', 'expired', 'replaced'))",
            "proof_scheme TEXT NOT NULL CHECK (proof_scheme = 'opaque_ristretto255_sha512_v1')",
            "trust_level TEXT NOT NULL CHECK (trust_level IN ('standard', 'high_risk_step_up_required'))",
            "rule_type TEXT NOT NULL CHECK (rule_type IN ('allow', 'deny', 'trusted'))",
            "scope_type TEXT NOT NULL CHECK (scope_type IN ('account', 'organization', 'device_group', 'device'))",
            "target_type TEXT NOT NULL CHECK (target_type IN ('account', 'organization', 'role', 'device_group', 'device'))",
            "access_decision TEXT NOT NULL CHECK (access_decision IN ('allow', 'deny', 'require_mfa', 'require_prompt'))",
            "anti_abuse_decision TEXT NOT NULL CHECK (anti_abuse_decision IN ('allow', 'warn_user', 'cooldown', 'deny_session'))",
            "direction TEXT NOT NULL CHECK (direction IN ('controller_to_controlled', 'controlled_to_controller'))",
            "channel TEXT NOT NULL CHECK (channel IN ('stable', 'beta', 'internal', 'private'))",
            "scope_type TEXT NOT NULL CHECK (scope_type IN ('official', 'organization'))",
            "event_type TEXT NOT NULL CHECK (event_type IN ('checked', 'downloaded', 'verified', 'failed'))",
            "platform TEXT NOT NULL CHECK (platform IN ('windows', 'ubuntu', 'ios'))",
            "arch TEXT NOT NULL CHECK (arch IN ('x86_64', 'aarch64'))",
            "api_request_hash_status TEXT NOT NULL CHECK (api_request_hash_status IN ('pending', 'accepted'))",
            "mode TEXT NOT NULL CHECK (mode IN ('normal', 'safe_mode_reserved'))",
            "auto_resume_consent TEXT NOT NULL DEFAULT 'none' CHECK (auto_resume_consent IN ('none', 'once_by_controlled_user'))",
            "role TEXT NOT NULL CHECK (role IN ('controller', 'controlled'))",
            "kind TEXT NOT NULL CHECK (kind IN ('lan_direct', 'udp_p2p', 'quic_relay', 'tls_443_relay'))",
            "source TEXT NOT NULL CHECK (source IN ('udp_observed', 'local_interface', 'relay_allocated', 'static_config'))",
            "status TEXT NOT NULL CHECK (status IN ('probing', 'selected', 'degraded', 'closed'))",
            "status TEXT NOT NULL CHECK (status IN ('active', 'draining', 'disabled', 'quarantined'))",
        ] {
            assert!(sql.contains(fragment), "missing frozen SQL CHECK: {fragment}");
        }

        assert_values_present(
            "remote_reboot_requests",
            &[
                "pending",
                "accepted",
                "cancelled",
                "executing",
                "device_offline",
                "resume_ready",
                "resumed",
                "failed",
                "expired",
                "normal",
                "safe_mode_reserved",
                "none",
                "once_by_controlled_user",
                "controlled_device",
                "manual_revoked",
            ],
        );
        assert_values_present(
            "file_transfers",
            &[
                "requested",
                "accepted",
                "rejected",
                "transferring",
                "completed",
                "failed",
                "cancelled",
                "save_as_new",
                "overwrite_confirmed",
                "reject_conflict",
                "temporary_cleanup_failed",
            ],
        );
        assert_values_present(
            "abuse_enforcement_actions",
            &[
                "account",
                "device",
                "organization",
                "relay_node",
                "session",
                "file_transfer",
                "manual_review",
            ],
        );
    }

    #[test]
    fn permissions_fk_index_and_deletion_boundaries_are_frozen() {
        let sql = normalized(INITIAL_SCHEMA_SQL);
        for permission in [
            "remote_desktop",
            "input_control",
            "clipboard",
            "file_transfer",
            "unattended",
            "privacy_screen",
            "block_local_input",
            "require_prompt",
            "allow_relay",
        ] {
            assert!(
                sql.contains(&format!("'{permission}'")),
                "permission: {permission}"
            );
        }
        for fragment in [
            "AND (SELECT count(*) FROM jsonb_object_keys(value)) = 9",
            "policy_evaluation_id TEXT NOT NULL REFERENCES policy_evaluations(policy_evaluation_id) ON DELETE RESTRICT",
            "CREATE UNIQUE INDEX uq_remote_reboot_resume_token_id ON remote_reboot_requests(reboot_resume_token_id)",
            "CREATE INDEX idx_remote_reboot_history ON remote_reboot_requests( controller_account_id, controller_device_id, controlled_device_id, created_at_epoch_millis )",
            "FOREIGN KEY (controller_device_id, controller_account_id) REFERENCES devices(device_id, account_id) ON DELETE RESTRICT",
            "FOREIGN KEY (controller_candidate_id, session_id) REFERENCES connection_candidates(candidate_id, session_id) ON DELETE RESTRICT",
            "FOREIGN KEY (controlled_candidate_id, session_id) REFERENCES connection_candidates(candidate_id, session_id) ON DELETE RESTRICT",
            "FOREIGN KEY (selected_candidate_pair_id, session_id) REFERENCES connection_candidate_pairs(candidate_pair_id, session_id) ON DELETE RESTRICT",
            "FOREIGN KEY (device_group_id, organization_id) REFERENCES device_groups(device_group_id, organization_id) ON DELETE RESTRICT",
            "FOREIGN KEY (organization_id, device_id) REFERENCES organization_devices(organization_id, device_id) ON DELETE RESTRICT",
            "CREATE TRIGGER trg_validate_organization_member_role",
            "CREATE TRIGGER trg_validate_verification_code_session",
            "CREATE TRIGGER trg_validate_remote_reboot_request",
            "CREATE TRIGGER trg_validate_connection_candidate",
            "CREATE TRIGGER trg_validate_candidate_pair",
            "CREATE TRIGGER trg_validate_session_bindings",
            "CREATE TRIGGER trg_validate_file_transfer",
            "remote reboot API hash snapshot is immutable",
        ] {
            assert!(sql.contains(fragment), "missing FK/index/boundary: {fragment}");
        }
        assert!(!sql.contains("ON DELETE CASCADE"));
        assert!(!sql.contains("ON DELETE SET NULL"));
    }

    #[test]
    fn permissions_serialize_all_nine_canonical_fields() {
        let permissions = EffectivePermissions {
            remote_desktop: true,
            input_control: true,
            clipboard: false,
            file_transfer: false,
            unattended: false,
            privacy_screen: false,
            block_local_input: false,
            require_prompt: true,
            allow_relay: true,
        };

        let value = serde_json::to_value(permissions).expect("permissions json");
        assert_eq!(value.as_object().expect("object").len(), 9);
        assert_eq!(value["require_prompt"], true);
        assert_eq!(value["allow_relay"], true);
    }

    #[test]
    fn credential_models_expose_only_protected_material() {
        let source = include_str!("model.rs");
        for forbidden in [
            "pub password: ",
            "pub refresh_token: ",
            "pub verification_code: ",
            "pub unattended_password: ",
            "pub reboot_resume_token_secret: ",
            "pub candidate_token: ",
            "pub grant_secret: ",
            "pub recovery_codes: ",
            "pub server_ephemeral_private_key: ",
        ] {
            assert!(
                !source.contains(forbidden),
                "forbidden model field: {forbidden}"
            );
        }
    }
}
