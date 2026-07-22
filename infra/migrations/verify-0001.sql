\set ON_ERROR_STOP on

DO $verify$
DECLARE
    account_session_columns TEXT[];
    candidate_columns TEXT[];
    enrollment_grant_columns TEXT[];
    login_challenge_columns TEXT[];
    recovery_delivery_columns TEXT[];
    missing_check_columns TEXT[];
    device_identity_constraint_expression TEXT;
    device_identity_case RECORD;
    device_identity_accepted BOOLEAN;
    required_methods_constraint_expression TEXT;
    required_methods_case RECORD;
    required_methods_accepted BOOLEAN;
BEGIN
    IF (SELECT count(*) FROM pg_tables WHERE schemaname = 'public') <> 43 THEN
        RAISE EXCEPTION 'expected exactly 43 V1 tables';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_tables
        WHERE schemaname = 'public'
          AND tablename IN (
              'organization_region_policies',
              'region_catalog',
              'object_storage_locations',
              'session_recording_policies',
              'session_recordings',
              'session_recording_access_logs'
          )
    ) THEN
        RAISE EXCEPTION 'M8/V2 deferred tables must not exist in V1';
    END IF;

    SELECT array_agg(column_name::TEXT ORDER BY ordinal_position)
    INTO account_session_columns
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'account_sessions';

    IF account_session_columns IS DISTINCT FROM ARRAY[
        'account_session_id',
        'account_id',
        'refresh_token_hash',
        'device_label',
        'ip_address',
        'user_agent',
        'mfa_verified',
        'expires_at_epoch_millis',
        'revoked_at_epoch_millis',
        'revoked_reason',
        'created_at_epoch_millis',
        'updated_at_epoch_millis'
    ]::TEXT[] THEN
        RAISE EXCEPTION 'unexpected account_sessions columns: %', account_session_columns;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'account_sessions'
          AND column_name = 'mfa_verified'
          AND data_type = 'boolean'
          AND is_nullable = 'NO'
          AND column_default IS NULL
    ) THEN
        RAISE EXCEPTION 'account_sessions.mfa_verified must be BOOLEAN NOT NULL without a default';
    END IF;

    SELECT array_agg(column_name::TEXT ORDER BY ordinal_position)
    INTO candidate_columns
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'connection_candidates';

    IF candidate_columns IS DISTINCT FROM ARRAY[
        'candidate_id',
        'session_id',
        'device_id',
        'role',
        'kind',
        'endpoint',
        'source',
        'observe_result_id',
        'priority',
        'rtt_ms',
        'loss_ppm',
        'jitter_ms',
        'relay_node_id',
        'created_at_epoch_millis'
    ]::TEXT[] THEN
        RAISE EXCEPTION 'unexpected connection_candidates columns: %', candidate_columns;
    END IF;

    SELECT array_agg(column_name::TEXT ORDER BY ordinal_position)
    INTO enrollment_grant_columns
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'device_enrollment_grants';

    IF enrollment_grant_columns IS DISTINCT FROM ARRAY[
        'grant_id',
        'grant_secret_hash',
        'account_id',
        'device_id',
        'device_public_key_fingerprint',
        'login_challenge_id',
        'login_challenge_binding_hash',
        'trust_proof_type',
        'trust_level',
        'establish_trust',
        'protocol_version',
        'issued_account_session_id',
        'issued_at_epoch_millis',
        'expires_at_epoch_millis',
        'consumed_at_epoch_millis',
        'registration_request_binding_hash',
        'registered_public_key_id',
        'registered_trusted_device_id',
        'created_at_epoch_millis'
    ]::TEXT[] THEN
        RAISE EXCEPTION 'unexpected device_enrollment_grants columns: %', enrollment_grant_columns;
    END IF;

    IF EXISTS (
        WITH expected(column_name, data_type) AS (
            VALUES
                ('registration_request_binding_hash', 'bytea'),
                ('registered_public_key_id', 'text'),
                ('registered_trusted_device_id', 'text')
        )
        SELECT 1
        FROM expected
        WHERE NOT EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = 'device_enrollment_grants'
              AND information_schema.columns.column_name = expected.column_name
              AND information_schema.columns.data_type = expected.data_type
              AND is_nullable = 'YES'
        )
    ) THEN
        RAISE EXCEPTION 'device enrollment registration-result columns must have the frozen nullable types';
    END IF;

    SELECT array_agg(column_name::TEXT ORDER BY ordinal_position)
    INTO login_challenge_columns
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'account_risk_challenges';

    IF login_challenge_columns IS DISTINCT FROM ARRAY[
        'risk_challenge_id',
        'account_id',
        'device_id',
        'purpose',
        'operation_binding_hash',
        'risk_level',
        'required_methods',
        'status',
        'attempts_remaining',
        'ip_address',
        'user_agent',
        'expires_at_epoch_millis',
        'created_at_epoch_millis',
        'verified_at_epoch_millis',
        'consumed_at_epoch_millis',
        'login_device_state',
        'login_device_id',
        'login_device_public_key',
        'login_device_public_key_fingerprint',
        'login_public_key_id',
        'login_public_key_version',
        'login_client_nonce',
        'login_server_nonce',
        'login_request_binding_hash',
        'login_ip_address_hash',
        'login_user_agent_hash',
        'login_trusted_device_id',
        'login_protocol_version',
        'login_attempts_limit'
    ]::TEXT[] THEN
        RAISE EXCEPTION 'unexpected account_risk_challenges columns: %', login_challenge_columns;
    END IF;

    SELECT array_agg(column_name::TEXT ORDER BY ordinal_position)
    INTO recovery_delivery_columns
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'mfa_recovery_code_deliveries';

    IF recovery_delivery_columns IS DISTINCT FROM ARRAY[
        'delivery_id',
        'account_id',
        'account_session_id',
        'factor_id',
        'idempotency_key_hash',
        'finish_request_binding_hash',
        'client_ephemeral_public_key',
        'server_ephemeral_public_key',
        'nonce',
        'ciphertext',
        'recovery_code_count',
        'created_at_epoch_millis',
        'expires_at_epoch_millis',
        'acknowledged_at_epoch_millis'
    ]::TEXT[] THEN
        RAISE EXCEPTION 'unexpected mfa_recovery_code_deliveries columns: %', recovery_delivery_columns;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name IN ('device_enrollment_grants', 'mfa_recovery_code_deliveries')
          AND column_name IN (
              'grant_secret',
              'recovery_codes',
              'server_ephemeral_private_key'
          )
    ) THEN
        RAISE EXCEPTION 'account identity security tables contain forbidden plaintext columns';
    END IF;

    IF EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE contype = 'f'
          AND connamespace = 'public'::regnamespace
          AND confdeltype <> 'r'
    ) THEN
        RAISE EXCEPTION 'all V1 foreign keys must use ON DELETE RESTRICT';
    END IF;

    WITH expected(table_name, column_name) AS (
        VALUES
            ('account_sessions', 'revoked_reason'),
            ('device_enrollment_grants', 'grant_secret_hash'),
            ('device_enrollment_grants', 'device_public_key_fingerprint'),
            ('device_enrollment_grants', 'login_challenge_binding_hash'),
            ('device_enrollment_grants', 'trust_proof_type'),
            ('device_enrollment_grants', 'trust_level'),
            ('device_enrollment_grants', 'establish_trust'),
            ('device_enrollment_grants', 'protocol_version'),
            ('device_enrollment_grants', 'expires_at_epoch_millis'),
            ('device_enrollment_grants', 'consumed_at_epoch_millis'),
            ('device_enrollment_grants', 'registration_request_binding_hash'),
            ('device_enrollment_grants', 'registered_public_key_id'),
            ('device_enrollment_grants', 'registered_trusted_device_id'),
            ('mfa_recovery_code_deliveries', 'idempotency_key_hash'),
            ('mfa_recovery_code_deliveries', 'finish_request_binding_hash'),
            ('mfa_recovery_code_deliveries', 'client_ephemeral_public_key'),
            ('mfa_recovery_code_deliveries', 'server_ephemeral_public_key'),
            ('mfa_recovery_code_deliveries', 'nonce'),
            ('mfa_recovery_code_deliveries', 'ciphertext'),
            ('mfa_recovery_code_deliveries', 'recovery_code_count'),
            ('mfa_recovery_code_deliveries', 'expires_at_epoch_millis'),
            ('mfa_recovery_code_deliveries', 'acknowledged_at_epoch_millis'),
            ('sessions', 'status'),
            ('sessions', 'permissions'),
            ('sessions', 'auth_method'),
            ('sessions', 'transport_path'),
            ('session_events', 'event_type'),
            ('session_events', 'actor_type'),
            ('session_events', 'actor_role'),
            ('session_events', 'actor_service'),
            ('audit_logs', 'action'),
            ('audit_logs', 'actor_type'),
            ('audit_logs', 'actor_role'),
            ('audit_logs', 'actor_service'),
            ('verification_codes', 'challenge_status'),
            ('verification_codes', 'proof_scheme'),
            ('unattended_secrets', 'proof_scheme'),
            ('account_mfa_factors', 'factor_type'),
            ('account_mfa_factors', 'status'),
            ('account_recovery_codes', 'status'),
            ('account_risk_challenges', 'purpose'),
            ('account_risk_challenges', 'risk_level'),
            ('account_risk_challenges', 'required_methods'),
            ('account_risk_challenges', 'status'),
            ('account_risk_challenges', 'login_device_state'),
            ('account_risk_challenges', 'login_device_public_key'),
            ('account_risk_challenges', 'login_device_public_key_fingerprint'),
            ('account_risk_challenges', 'login_protocol_version'),
            ('account_risk_challenges', 'login_attempts_limit'),
            ('trusted_controller_devices', 'trust_level'),
            ('trusted_controller_devices', 'status'),
            ('trusted_controller_devices', 'trust_proof_type'),
            ('access_policies', 'scope_type'),
            ('access_policies', 'status'),
            ('access_policies', 'conditions'),
            ('access_policies', 'effects'),
            ('access_policy_assignments', 'target_type'),
            ('access_policy_assignments', 'status'),
            ('policy_evaluations', 'access_decision'),
            ('policy_evaluations', 'anti_abuse_decision'),
            ('policy_evaluations', 'session_access_decision'),
            ('device_access_rules', 'rule_type'),
            ('client_release_channels', 'channel'),
            ('client_release_channels', 'scope_type'),
            ('client_release_channels', 'status'),
            ('client_release_artifacts', 'platform'),
            ('client_release_artifacts', 'arch'),
            ('client_release_artifacts', 'status'),
            ('client_update_checks', 'platform'),
            ('client_update_checks', 'arch'),
            ('client_update_checks', 'event_type'),
            ('file_transfers', 'status'),
            ('file_transfers', 'direction'),
            ('file_transfers', 'failure_reason'),
            ('file_transfers', 'receiver_save_policy'),
            ('remote_reboot_requests', 'status'),
            ('remote_reboot_requests', 'api_request_hash_status'),
            ('remote_reboot_requests', 'mode'),
            ('remote_reboot_requests', 'auto_resume_consent'),
            ('remote_reboot_requests', 'consent_revoked_by_actor_type'),
            ('remote_reboot_requests', 'consent_revoked_reason'),
            ('remote_reboot_requests', 'reboot_resume_token_invalidation_reason'),
            ('abuse_reports', 'status'),
            ('abuse_reports', 'category'),
            ('abuse_cases', 'status'),
            ('abuse_cases', 'risk_level'),
            ('abuse_enforcement_actions', 'subject_type'),
            ('abuse_enforcement_actions', 'action'),
            ('abuse_enforcement_actions', 'created_by_actor_type'),
            ('abuse_risk_events', 'event_type'),
            ('abuse_risk_events', 'decision'),
            ('abuse_risk_events', 'risk_level'),
            ('connection_candidates', 'role'),
            ('connection_candidates', 'kind'),
            ('connection_candidates', 'source'),
            ('connection_candidate_pairs', 'status'),
            ('connection_candidate_pairs', 'selected_transport_path'),
            ('relay_nodes', 'status'),
            ('relay_nodes', 'data_residency_class'),
            ('devices', 'platform'),
            ('devices', 'arch')
    )
    SELECT array_agg(expected.table_name || '.' || expected.column_name ORDER BY 1)
    INTO missing_check_columns
    FROM expected
    WHERE NOT EXISTS (
        SELECT 1
        FROM pg_constraint AS constraint_record
        JOIN pg_class AS table_record
          ON table_record.oid = constraint_record.conrelid
        JOIN pg_namespace AS namespace_record
          ON namespace_record.oid = table_record.relnamespace
        JOIN pg_attribute AS column_record
          ON column_record.attrelid = table_record.oid
         AND column_record.attnum = ANY(constraint_record.conkey)
        WHERE constraint_record.contype = 'c'
          AND namespace_record.nspname = 'public'
          AND table_record.relname = expected.table_name
          AND column_record.attname = expected.column_name
    );

    IF missing_check_columns IS NOT NULL THEN
        RAISE EXCEPTION 'missing frozen CHECK constraints: %', missing_check_columns;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint AS constraint_record
        JOIN pg_attribute AS column_record
          ON column_record.attrelid = constraint_record.conrelid
         AND column_record.attnum = ANY(constraint_record.conkey)
        WHERE constraint_record.conrelid = 'public.account_risk_challenges'::regclass
          AND constraint_record.confrelid = 'public.devices'::regclass
          AND constraint_record.contype = 'f'
          AND constraint_record.confdeltype = 'r'
          AND column_record.attname = 'device_id'
    ) THEN
        RAISE EXCEPTION 'account risk challenge device_id foreign key is missing';
    END IF;

    SELECT pg_get_expr(conbin, conrelid)
    INTO device_identity_constraint_expression
    FROM pg_constraint
    WHERE conname = 'ck_account_risk_challenges_device_identity'
      AND conrelid = 'public.account_risk_challenges'::regclass
      AND contype = 'c';

    IF device_identity_constraint_expression IS NULL THEN
        RAISE EXCEPTION 'account risk challenge device identity constraint is missing';
    END IF;

    FOR device_identity_case IN
        SELECT purpose, device_id, login_device_state, login_device_id, should_accept
        FROM (
            VALUES
                ('login_mfa'::TEXT, 'device-1'::TEXT, 'registered'::TEXT, 'device-1'::TEXT, TRUE),
                ('login_mfa'::TEXT, 'device-1'::TEXT, 'registered'::TEXT, 'device-2'::TEXT, FALSE),
                ('login_mfa'::TEXT, NULL::TEXT, 'registered'::TEXT, 'device-1'::TEXT, FALSE),
                ('login_mfa'::TEXT, NULL::TEXT, 'pending_enrollment'::TEXT, 'device-new'::TEXT, TRUE),
                ('login_mfa'::TEXT, 'device-new'::TEXT, 'pending_enrollment'::TEXT, 'device-new'::TEXT, FALSE),
                ('new_controller_device'::TEXT, NULL::TEXT, NULL::TEXT, NULL::TEXT, TRUE),
                ('new_controller_device'::TEXT, 'device-new'::TEXT, NULL::TEXT, NULL::TEXT, FALSE),
                ('password_change'::TEXT, 'device-1'::TEXT, NULL::TEXT, NULL::TEXT, TRUE)
        ) AS cases(purpose, device_id, login_device_state, login_device_id, should_accept)
    LOOP
        EXECUTE format(
            'SELECT (%s) FROM (VALUES ($1::TEXT, $2::TEXT, $3::TEXT, $4::TEXT)) AS account_risk_challenges(purpose, device_id, login_device_state, login_device_id)',
            device_identity_constraint_expression
        )
        INTO device_identity_accepted
        USING device_identity_case.purpose,
              device_identity_case.device_id,
              device_identity_case.login_device_state,
              device_identity_case.login_device_id;

        IF device_identity_accepted IS DISTINCT FROM device_identity_case.should_accept THEN
            RAISE EXCEPTION
                'account risk challenge device identity mismatch for purpose %, device %, state %, login device %: expected %, got %',
                device_identity_case.purpose,
                device_identity_case.device_id,
                device_identity_case.login_device_state,
                device_identity_case.login_device_id,
                device_identity_case.should_accept,
                device_identity_accepted;
        END IF;
    END LOOP;

    SELECT pg_get_expr(conbin, conrelid)
    INTO required_methods_constraint_expression
    FROM pg_constraint
    WHERE conname = 'ck_account_risk_challenges_required_methods'
      AND conrelid = 'public.account_risk_challenges'::regclass
      AND contype = 'c';

    IF required_methods_constraint_expression IS NULL THEN
        RAISE EXCEPTION 'account risk challenge required_methods policy constraint is missing';
    END IF;

    FOR required_methods_case IN
        WITH step_up_purposes(purpose) AS (
            VALUES
                ('new_controller_device'::TEXT),
                ('trusted_device_change'::TEXT),
                ('mfa_factor_change'::TEXT),
                ('recovery_code_rotate'::TEXT),
                ('device_key_rotation'::TEXT),
                ('unattended_secret_change'::TEXT),
                ('require_prompt_relax'::TEXT),
                ('allow_privacy_screen'::TEXT),
                ('allow_block_local_input'::TEXT),
                ('allow_remote_reboot'::TEXT),
                ('remote_reboot'::TEXT),
                ('access_policy_change'::TEXT),
                ('client_release_change'::TEXT),
                ('region_policy_change'::TEXT)
        ),
        step_up_method_cases(required_methods, should_accept) AS (
            VALUES
                ('["totp","recovery_code"]'::JSONB, TRUE),
                ('[]'::JSONB, FALSE),
                ('["password"]'::JSONB, FALSE),
                ('["recovery_code","totp"]'::JSONB, FALSE),
                ('["totp"]'::JSONB, FALSE),
                ('["recovery_code"]'::JSONB, FALSE),
                ('["totp","recovery_code","recovery_code"]'::JSONB, FALSE),
                ('["totp","recovery_code","password"]'::JSONB, FALSE),
                ('["webauthn"]'::JSONB, FALSE)
        ),
        required_methods_cases(purpose, required_methods, should_accept) AS (
            VALUES
                ('login_mfa'::TEXT, '[]'::JSONB, TRUE),
                ('login_mfa'::TEXT, '["totp","recovery_code"]'::JSONB, TRUE),
                ('login_mfa'::TEXT, '["password"]'::JSONB, FALSE),
                ('login_mfa'::TEXT, '["recovery_code","totp"]'::JSONB, FALSE),
                ('login_mfa'::TEXT, '["totp"]'::JSONB, FALSE),
                ('login_mfa'::TEXT, '["recovery_code"]'::JSONB, FALSE),
                ('login_mfa'::TEXT, '["totp","recovery_code","recovery_code"]'::JSONB, FALSE),
                ('login_mfa'::TEXT, '["totp","recovery_code","password"]'::JSONB, FALSE),
                ('login_mfa'::TEXT, '["webauthn"]'::JSONB, FALSE),
                ('password_change'::TEXT, '["password"]'::JSONB, TRUE),
                ('password_change'::TEXT, '["totp","recovery_code"]'::JSONB, TRUE),
                ('password_change'::TEXT, '[]'::JSONB, FALSE),
                ('password_change'::TEXT, '["recovery_code","totp"]'::JSONB, FALSE),
                ('password_change'::TEXT, '["totp"]'::JSONB, FALSE),
                ('password_change'::TEXT, '["recovery_code"]'::JSONB, FALSE),
                ('password_change'::TEXT, '["totp","recovery_code","recovery_code"]'::JSONB, FALSE),
                ('password_change'::TEXT, '["totp","recovery_code","password"]'::JSONB, FALSE),
                ('password_change'::TEXT, '["webauthn"]'::JSONB, FALSE)
            UNION ALL
            SELECT purpose, required_methods, should_accept
            FROM step_up_purposes
            CROSS JOIN step_up_method_cases
        )
        SELECT purpose, required_methods, should_accept
        FROM required_methods_cases
    LOOP
        EXECUTE format(
            'SELECT (%s) FROM (VALUES ($1::TEXT, $2::JSONB)) AS account_risk_challenges(purpose, required_methods)',
            required_methods_constraint_expression
        )
        INTO required_methods_accepted
        USING required_methods_case.purpose, required_methods_case.required_methods;

        IF required_methods_accepted IS DISTINCT FROM required_methods_case.should_accept THEN
            RAISE EXCEPTION
                'account risk challenge required_methods policy mismatch for purpose % and methods %: expected %, got %',
                required_methods_case.purpose,
                required_methods_case.required_methods,
                required_methods_case.should_accept,
                required_methods_accepted;
        END IF;
    END LOOP;

    IF to_regclass('public.uq_remote_reboot_resume_token_id') IS NULL
       OR to_regclass('public.idx_remote_reboot_history') IS NULL
       OR to_regclass('public.idx_connection_candidates_observe_result') IS NULL
       OR to_regclass('public.idx_connection_candidate_pairs_session_status') IS NULL
       OR to_regclass('public.uq_device_enrollment_grants_secret_hash') IS NULL
       OR to_regclass('public.uq_device_enrollment_grants_login_challenge') IS NULL
       OR to_regclass('public.idx_device_enrollment_grants_account_device_active') IS NULL
       OR to_regclass('public.idx_device_enrollment_grants_expiry') IS NULL
       OR to_regclass('public.idx_device_enrollment_grants_issued_session') IS NULL
       OR to_regclass('public.uq_mfa_recovery_code_deliveries_idempotency') IS NULL
       OR to_regclass('public.idx_mfa_recovery_code_deliveries_session') IS NULL
       OR to_regclass('public.idx_mfa_recovery_code_deliveries_expiry') IS NULL THEN
        RAISE EXCEPTION 'required Schema Freeze index is missing';
    END IF;

    IF EXISTS (
        WITH required_foreign_key(constraint_name) AS (
            VALUES
                ('fk_device_enrollment_grants_challenge_account'),
                ('fk_device_enrollment_grants_session_account'),
                ('fk_device_enrollment_grants_registered_trusted_device'),
                ('fk_mfa_recovery_code_deliveries_session_account'),
                ('fk_mfa_recovery_code_deliveries_factor_account')
        )
        SELECT 1
        FROM required_foreign_key
        WHERE NOT EXISTS (
            SELECT 1
            FROM pg_constraint
            WHERE conname = required_foreign_key.constraint_name
              AND connamespace = 'public'::regnamespace
              AND contype = 'f'
              AND confdeltype = 'r'
        )
    ) THEN
        RAISE EXCEPTION 'required account identity foreign key is missing';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'fk_device_enrollment_grants_registered_trusted_device'
          AND conrelid = 'public.device_enrollment_grants'::regclass
          AND confrelid = 'public.trusted_controller_devices'::regclass
          AND pg_get_constraintdef(oid) =
              'FOREIGN KEY (registered_trusted_device_id, device_id, account_id) REFERENCES trusted_controller_devices(trusted_device_id, controller_device_id, account_id) ON DELETE RESTRICT'
    ) THEN
        RAISE EXCEPTION 'device enrollment trust result foreign key has unexpected columns or target';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'ck_device_enrollment_grants_registration_binding_length'
          AND conrelid = 'public.device_enrollment_grants'::regclass
          AND contype = 'c'
          AND lower(pg_get_constraintdef(oid)) LIKE '%octet_length(registration_request_binding_hash) = 32%'
    ) THEN
        RAISE EXCEPTION 'device enrollment registration binding must be exactly 32 bytes when present';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'ck_device_enrollment_grants_registration_result'
          AND conrelid = 'public.device_enrollment_grants'::regclass
          AND contype = 'c'
          AND regexp_replace(lower(pg_get_constraintdef(oid)), '[^a-z0-9_]+', ' ', 'g')
              LIKE '%consumed_at_epoch_millis is null and registration_request_binding_hash is null and registered_public_key_id is null and registered_trusted_device_id is null%'
          AND regexp_replace(lower(pg_get_constraintdef(oid)), '[^a-z0-9_]+', ' ', 'g')
              LIKE '%consumed_at_epoch_millis is not null and registration_request_binding_hash is not null and registered_public_key_id is not null and establish_trust and registered_trusted_device_id is not null%'
          AND regexp_replace(lower(pg_get_constraintdef(oid)), '[^a-z0-9_]+', ' ', 'g')
              LIKE '%not establish_trust and registered_trusted_device_id is null%'
    ) THEN
        RAISE EXCEPTION 'device enrollment registration-result state constraint is missing or incomplete';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'ck_device_enrollment_grants_trust_policy'
          AND conrelid = 'public.device_enrollment_grants'::regclass
          AND contype = 'c'
          AND lower(pg_get_constraintdef(oid)) LIKE '%device_signature_and_mfa%standard%'
          AND lower(pg_get_constraintdef(oid))
              LIKE '%device_signature_and_recovery_code%high_risk_step_up_required%'
    ) THEN
        RAISE EXCEPTION 'device enrollment trust proof and level policy is missing';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'ck_trusted_controller_devices_trust_policy'
          AND conrelid = 'public.trusted_controller_devices'::regclass
          AND contype = 'c'
          AND lower(pg_get_constraintdef(oid))
              LIKE '%device_signature_and_mfa%standard%2592000000%'
          AND lower(pg_get_constraintdef(oid))
              LIKE '%device_signature_and_recovery_code%high_risk_step_up_required%86400000%'
    ) THEN
        RAISE EXCEPTION 'trusted device proof, level, and TTL policy is missing';
    END IF;

    IF EXISTS (
        WITH required_trigger(trigger_name) AS (
            VALUES
                ('trg_validate_organization_member_role'),
                ('trg_validate_verification_code_session'),
                ('trg_validate_remote_reboot_request'),
                ('trg_validate_connection_candidate'),
                ('trg_validate_candidate_pair'),
                ('trg_validate_session_bindings'),
                ('trg_validate_file_transfer')
        )
        SELECT 1
        FROM required_trigger
        WHERE NOT EXISTS (
            SELECT 1
            FROM pg_trigger
            WHERE tgname = required_trigger.trigger_name
              AND NOT tgisinternal
        )
    ) THEN
        RAISE EXCEPTION 'required consistency trigger is missing';
    END IF;

    IF NOT v1_permissions_valid(
        '{
            "remote_desktop": true,
            "input_control": true,
            "clipboard": false,
            "file_transfer": false,
            "unattended": false,
            "privacy_screen": false,
            "block_local_input": false,
            "require_prompt": true,
            "allow_relay": true
        }'::JSONB
    ) THEN
        RAISE EXCEPTION 'valid 9-field permissions object was rejected';
    END IF;

    IF v1_permissions_valid(
        '{
            "remote_desktop": true,
            "input_control": true,
            "clipboard": false,
            "file_transfer": false,
            "unattended": false,
            "privacy_screen": false,
            "block_local_input": false,
            "require_prompt": true,
            "allow_relay": true,
            "extra": false
        }'::JSONB
    ) THEN
        RAISE EXCEPTION 'permissions object with an unknown field was accepted';
    END IF;
END
$verify$;

SELECT 'schema verification passed' AS result;
