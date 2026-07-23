-- SCHEMA_FREEZE_STATUS=FINAL
BEGIN;

CREATE FUNCTION jsonb_has_only_keys(value JSONB, allowed_keys TEXT[])
RETURNS BOOLEAN
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT jsonb_typeof(value) = 'object'
       AND NOT EXISTS (
           SELECT 1
           FROM jsonb_object_keys(value) AS key
           WHERE NOT (key = ANY (allowed_keys))
       );
$$;

CREATE FUNCTION v1_permissions_valid(value JSONB)
RETURNS BOOLEAN
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT jsonb_typeof(value) = 'object'
       AND (SELECT count(*) FROM jsonb_object_keys(value)) = 9
       AND value ?& ARRAY[
           'remote_desktop',
           'input_control',
           'clipboard',
           'file_transfer',
           'unattended',
           'privacy_screen',
           'block_local_input',
           'require_prompt',
           'allow_relay'
       ]
       AND NOT EXISTS (
           SELECT 1
           FROM jsonb_each(value) AS item
           WHERE jsonb_typeof(item.value) <> 'boolean'
       );
$$;

CREATE FUNCTION access_conditions_valid(value JSONB)
RETURNS BOOLEAN
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT jsonb_has_only_keys(
        value,
        ARRAY[
            'country',
            'ip_range',
            'asn',
            'device_posture',
            'login_mfa',
            'step_up',
            'recent_activity',
            'device_trust',
            'connection_kind',
            'time_window'
        ]
    );
$$;

CREATE FUNCTION access_effects_valid(value JSONB)
RETURNS BOOLEAN
LANGUAGE SQL
IMMUTABLE
STRICT
PARALLEL SAFE
AS $$
    SELECT jsonb_has_only_keys(
        value,
        ARRAY[
            'deny_session',
            'require_mfa',
            'require_prompt',
            'disable_relay',
            'disable_clipboard',
            'disable_file_transfer',
            'disable_privacy_screen',
            'disable_block_local_input',
            'disable_remote_reboot'
        ]
    )
       AND NOT EXISTS (
           SELECT 1
           FROM jsonb_each(value) AS item
           WHERE jsonb_typeof(item.value) <> 'boolean'
       );
$$;

CREATE TABLE accounts (
    account_id TEXT PRIMARY KEY CHECK (btrim(account_id) <> ''),
    email TEXT NOT NULL UNIQUE CHECK (email = lower(btrim(email)) AND position('@' IN email) > 1),
    display_name TEXT NOT NULL CHECK (btrim(display_name) <> ''),
    password_hash TEXT NOT NULL CHECK (btrim(password_hash) <> ''),
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled', 'locked')),
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    updated_at_epoch_millis BIGINT NOT NULL CHECK (updated_at_epoch_millis >= created_at_epoch_millis)
);

CREATE TABLE account_sessions (
    account_session_id TEXT PRIMARY KEY CHECK (btrim(account_session_id) <> ''),
    account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE RESTRICT,
    refresh_token_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(refresh_token_hash) = 32),
    device_label TEXT NOT NULL CHECK (btrim(device_label) <> ''),
    ip_address INET,
    user_agent TEXT,
    mfa_verified BOOLEAN NOT NULL,
    expires_at_epoch_millis BIGINT NOT NULL,
    revoked_at_epoch_millis BIGINT,
    revoked_reason TEXT CHECK (
        revoked_reason IS NULL
        OR revoked_reason IN (
            'logout',
            'password_changed',
            'mfa_enabled',
            'mfa_disabled',
            'account_locked',
            'device_unbound',
            'refresh_replay'
        )
    ),
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    updated_at_epoch_millis BIGINT NOT NULL,
    UNIQUE (account_session_id, account_id),
    CHECK (expires_at_epoch_millis > created_at_epoch_millis),
    CHECK (
        (revoked_at_epoch_millis IS NULL AND revoked_reason IS NULL)
        OR (
            revoked_at_epoch_millis IS NOT NULL
            AND revoked_at_epoch_millis >= created_at_epoch_millis
            AND revoked_reason IS NOT NULL
        )
    ),
    CHECK (updated_at_epoch_millis >= created_at_epoch_millis)
);

CREATE INDEX idx_account_sessions_account_active
    ON account_sessions(account_id, expires_at_epoch_millis)
    WHERE revoked_at_epoch_millis IS NULL;

CREATE TABLE organizations (
    organization_id TEXT PRIMARY KEY CHECK (btrim(organization_id) <> ''),
    name TEXT NOT NULL CHECK (btrim(name) <> ''),
    organization_type TEXT NOT NULL CHECK (organization_type IN ('personal', 'team', 'enterprise')),
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    created_by_account_id TEXT REFERENCES accounts(account_id) ON DELETE RESTRICT,
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    updated_at_epoch_millis BIGINT NOT NULL CHECK (updated_at_epoch_millis >= created_at_epoch_millis)
);

CREATE INDEX idx_organizations_created_by ON organizations(created_by_account_id);

CREATE TABLE roles (
    role_id TEXT PRIMARY KEY CHECK (btrim(role_id) <> ''),
    organization_id TEXT REFERENCES organizations(organization_id) ON DELETE RESTRICT,
    scope TEXT NOT NULL CHECK (scope IN ('system', 'organization')),
    role_key TEXT NOT NULL CHECK (btrim(role_key) <> ''),
    display_name TEXT NOT NULL CHECK (btrim(display_name) <> ''),
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    updated_at_epoch_millis BIGINT NOT NULL CHECK (updated_at_epoch_millis >= created_at_epoch_millis),
    UNIQUE (organization_id, role_key),
    CHECK (
        (scope = 'system' AND organization_id IS NULL AND role_key IN ('owner', 'admin', 'member', 'viewer'))
        OR (scope = 'organization' AND organization_id IS NOT NULL)
    )
);

CREATE INDEX idx_roles_organization_status ON roles(organization_id, status);

CREATE TABLE organization_members (
    organization_member_id TEXT PRIMARY KEY CHECK (btrim(organization_member_id) <> ''),
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id) ON DELETE RESTRICT,
    account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE RESTRICT,
    role_id TEXT NOT NULL REFERENCES roles(role_id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'removed')),
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    updated_at_epoch_millis BIGINT NOT NULL CHECK (updated_at_epoch_millis >= created_at_epoch_millis),
    UNIQUE (organization_id, account_id)
);

CREATE INDEX idx_organization_members_account ON organization_members(account_id, status);
CREATE INDEX idx_organization_members_role ON organization_members(role_id);

CREATE FUNCTION validate_organization_member_role()
RETURNS TRIGGER
LANGUAGE PLPGSQL
AS $$
DECLARE
    role_scope TEXT;
    role_organization_id TEXT;
BEGIN
    SELECT scope, organization_id
    INTO role_scope, role_organization_id
    FROM roles
    WHERE role_id = NEW.role_id;

    IF role_scope = 'organization'
       AND role_organization_id IS DISTINCT FROM NEW.organization_id THEN
        RAISE EXCEPTION 'organization member role belongs to another organization';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_organization_member_role
BEFORE INSERT OR UPDATE OF organization_id, role_id ON organization_members
FOR EACH ROW EXECUTE FUNCTION validate_organization_member_role();

CREATE TABLE devices (
    device_id TEXT PRIMARY KEY CHECK (btrim(device_id) <> ''),
    account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE RESTRICT,
    primary_organization_id TEXT REFERENCES organizations(organization_id) ON DELETE RESTRICT,
    display_name TEXT NOT NULL CHECK (btrim(display_name) <> ''),
    platform TEXT NOT NULL CHECK (platform IN ('windows', 'ubuntu', 'ios')),
    os_version TEXT NOT NULL CHECK (btrim(os_version) <> ''),
    arch TEXT NOT NULL CHECK (arch IN ('x86_64', 'aarch64')),
    public_key_id TEXT NOT NULL CHECK (btrim(public_key_id) <> ''),
    public_key BYTEA NOT NULL CHECK (octet_length(public_key) = 32),
    public_key_version INTEGER NOT NULL CHECK (public_key_version >= 1),
    public_key_revoked_at_epoch_millis BIGINT,
    status TEXT NOT NULL CHECK (status IN ('online', 'offline', 'busy', 'suspended', 'disabled', 'unbound')),
    unattended_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    last_seen_epoch_millis BIGINT CHECK (last_seen_epoch_millis IS NULL OR last_seen_epoch_millis >= 0),
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    updated_at_epoch_millis BIGINT NOT NULL CHECK (updated_at_epoch_millis >= created_at_epoch_millis),
    UNIQUE (public_key_id),
    UNIQUE (device_id, account_id),
    CHECK (
        public_key_revoked_at_epoch_millis IS NULL
        OR public_key_revoked_at_epoch_millis >= created_at_epoch_millis
    )
);

CREATE INDEX idx_devices_account_status ON devices(account_id, status);
CREATE INDEX idx_devices_primary_organization ON devices(primary_organization_id, status);
CREATE INDEX idx_devices_last_seen ON devices(last_seen_epoch_millis);

CREATE TABLE organization_devices (
    organization_device_id TEXT PRIMARY KEY CHECK (btrim(organization_device_id) <> ''),
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id) ON DELETE RESTRICT,
    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    membership_type TEXT NOT NULL CHECK (membership_type IN ('primary', 'member', 'managed')),
    status TEXT NOT NULL CHECK (status IN ('active', 'removed')),
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    updated_at_epoch_millis BIGINT NOT NULL CHECK (updated_at_epoch_millis >= created_at_epoch_millis),
    UNIQUE (organization_id, device_id)
);

CREATE INDEX idx_organization_devices_device ON organization_devices(device_id, status);

CREATE TABLE role_permissions (
    role_id TEXT PRIMARY KEY REFERENCES roles(role_id) ON DELETE RESTRICT,
    allow_remote_desktop BOOLEAN NOT NULL DEFAULT FALSE,
    allow_input_control BOOLEAN NOT NULL DEFAULT FALSE,
    allow_clipboard BOOLEAN NOT NULL DEFAULT FALSE,
    allow_file_transfer BOOLEAN NOT NULL DEFAULT FALSE,
    allow_unattended BOOLEAN NOT NULL DEFAULT FALSE,
    allow_privacy_screen BOOLEAN NOT NULL DEFAULT FALSE,
    allow_block_local_input BOOLEAN NOT NULL DEFAULT FALSE,
    allow_relay BOOLEAN NOT NULL DEFAULT FALSE,
    can_bypass_prompt BOOLEAN NOT NULL DEFAULT FALSE,
    allow_remote_reboot BOOLEAN NOT NULL DEFAULT FALSE,
    can_manage_organization BOOLEAN NOT NULL DEFAULT FALSE,
    can_manage_devices BOOLEAN NOT NULL DEFAULT FALSE,
    can_manage_policies BOOLEAN NOT NULL DEFAULT FALSE,
    can_view_audit_logs BOOLEAN NOT NULL DEFAULT FALSE,
    can_manage_releases BOOLEAN NOT NULL DEFAULT FALSE,
    can_manage_abuse_cases BOOLEAN NOT NULL DEFAULT FALSE,
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    updated_at_epoch_millis BIGINT NOT NULL CHECK (updated_at_epoch_millis >= created_at_epoch_millis)
);

CREATE TABLE organization_policies (
    organization_policy_id TEXT PRIMARY KEY CHECK (btrim(organization_policy_id) <> ''),
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id) ON DELETE RESTRICT,
    priority INTEGER NOT NULL DEFAULT 0,
    allow_remote_desktop TEXT NOT NULL DEFAULT 'inherit' CHECK (allow_remote_desktop IN ('inherit', 'allow', 'deny')),
    allow_input_control TEXT NOT NULL DEFAULT 'inherit' CHECK (allow_input_control IN ('inherit', 'allow', 'deny')),
    allow_clipboard TEXT NOT NULL DEFAULT 'inherit' CHECK (allow_clipboard IN ('inherit', 'allow', 'deny')),
    allow_file_transfer TEXT NOT NULL DEFAULT 'inherit' CHECK (allow_file_transfer IN ('inherit', 'allow', 'deny')),
    allow_unattended TEXT NOT NULL DEFAULT 'inherit' CHECK (allow_unattended IN ('inherit', 'allow', 'deny')),
    allow_privacy_screen TEXT NOT NULL DEFAULT 'inherit' CHECK (allow_privacy_screen IN ('inherit', 'allow', 'deny')),
    allow_block_local_input TEXT NOT NULL DEFAULT 'inherit' CHECK (allow_block_local_input IN ('inherit', 'allow', 'deny')),
    allow_relay TEXT NOT NULL DEFAULT 'inherit' CHECK (allow_relay IN ('inherit', 'allow', 'deny')),
    require_prompt TEXT NOT NULL DEFAULT 'inherit' CHECK (require_prompt IN ('inherit', 'require', 'no_prompt')),
    allow_remote_reboot TEXT NOT NULL DEFAULT 'inherit' CHECK (allow_remote_reboot IN ('inherit', 'allow', 'deny')),
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    updated_by_account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE RESTRICT,
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    updated_at_epoch_millis BIGINT NOT NULL CHECK (updated_at_epoch_millis >= created_at_epoch_millis)
);

CREATE INDEX idx_organization_policies_evaluation
    ON organization_policies(organization_id, status, priority DESC, created_at_epoch_millis);

CREATE TABLE device_groups (
    device_group_id TEXT PRIMARY KEY CHECK (btrim(device_group_id) <> ''),
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id) ON DELETE RESTRICT,
    name TEXT NOT NULL CHECK (btrim(name) <> ''),
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled', 'deleted')),
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    updated_at_epoch_millis BIGINT NOT NULL CHECK (updated_at_epoch_millis >= created_at_epoch_millis),
    UNIQUE (organization_id, name),
    UNIQUE (device_group_id, organization_id)
);

CREATE TABLE device_group_members (
    device_group_member_id TEXT PRIMARY KEY CHECK (btrim(device_group_member_id) <> ''),
    device_group_id TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'removed')),
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    updated_at_epoch_millis BIGINT NOT NULL CHECK (updated_at_epoch_millis >= created_at_epoch_millis),
    UNIQUE (device_group_id, device_id),
    FOREIGN KEY (device_group_id, organization_id)
        REFERENCES device_groups(device_group_id, organization_id) ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, device_id)
        REFERENCES organization_devices(organization_id, device_id) ON DELETE RESTRICT
);

CREATE INDEX idx_device_group_members_device ON device_group_members(device_id, status);

CREATE TABLE device_group_policies (
    device_group_policy_id TEXT PRIMARY KEY CHECK (btrim(device_group_policy_id) <> ''),
    device_group_id TEXT NOT NULL REFERENCES device_groups(device_group_id) ON DELETE RESTRICT,
    priority INTEGER NOT NULL DEFAULT 0,
    allow_remote_desktop TEXT NOT NULL DEFAULT 'inherit' CHECK (allow_remote_desktop IN ('inherit', 'allow', 'deny')),
    allow_input_control TEXT NOT NULL DEFAULT 'inherit' CHECK (allow_input_control IN ('inherit', 'allow', 'deny')),
    allow_clipboard TEXT NOT NULL DEFAULT 'inherit' CHECK (allow_clipboard IN ('inherit', 'allow', 'deny')),
    allow_file_transfer TEXT NOT NULL DEFAULT 'inherit' CHECK (allow_file_transfer IN ('inherit', 'allow', 'deny')),
    allow_unattended TEXT NOT NULL DEFAULT 'inherit' CHECK (allow_unattended IN ('inherit', 'allow', 'deny')),
    allow_privacy_screen TEXT NOT NULL DEFAULT 'inherit' CHECK (allow_privacy_screen IN ('inherit', 'allow', 'deny')),
    allow_block_local_input TEXT NOT NULL DEFAULT 'inherit' CHECK (allow_block_local_input IN ('inherit', 'allow', 'deny')),
    allow_relay TEXT NOT NULL DEFAULT 'inherit' CHECK (allow_relay IN ('inherit', 'allow', 'deny')),
    require_prompt TEXT NOT NULL DEFAULT 'inherit' CHECK (require_prompt IN ('inherit', 'require', 'no_prompt')),
    allow_remote_reboot TEXT NOT NULL DEFAULT 'inherit' CHECK (allow_remote_reboot IN ('inherit', 'allow', 'deny')),
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    updated_by_account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE RESTRICT,
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    updated_at_epoch_millis BIGINT NOT NULL CHECK (updated_at_epoch_millis >= created_at_epoch_millis)
);

CREATE INDEX idx_device_group_policies_evaluation
    ON device_group_policies(device_group_id, status, priority DESC, created_at_epoch_millis);

CREATE TABLE account_mfa_factors (
    factor_id TEXT PRIMARY KEY CHECK (btrim(factor_id) <> ''),
    account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE RESTRICT,
    factor_type TEXT NOT NULL CHECK (factor_type IN ('totp')),
    encrypted_secret BYTEA NOT NULL CHECK (octet_length(encrypted_secret) > 0),
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    last_used_at_epoch_millis BIGINT,
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    disabled_at_epoch_millis BIGINT,
    UNIQUE (factor_id, account_id),
    CHECK (last_used_at_epoch_millis IS NULL OR last_used_at_epoch_millis >= created_at_epoch_millis),
    CHECK (
        (status = 'active' AND disabled_at_epoch_millis IS NULL)
        OR (
            status = 'disabled'
            AND disabled_at_epoch_millis IS NOT NULL
            AND disabled_at_epoch_millis >= created_at_epoch_millis
        )
    )
);

CREATE UNIQUE INDEX uq_account_mfa_active_totp
    ON account_mfa_factors(account_id, factor_type)
    WHERE status = 'active';

CREATE TABLE mfa_recovery_code_deliveries (
    delivery_id TEXT PRIMARY KEY CHECK (btrim(delivery_id) <> ''),
    account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE RESTRICT,
    account_session_id TEXT NOT NULL,
    factor_id TEXT NOT NULL,
    idempotency_key_hash BYTEA NOT NULL CHECK (octet_length(idempotency_key_hash) = 32),
    finish_request_binding_hash BYTEA NOT NULL CHECK (octet_length(finish_request_binding_hash) = 32),
    client_ephemeral_public_key BYTEA NOT NULL CHECK (octet_length(client_ephemeral_public_key) = 32),
    server_ephemeral_public_key BYTEA NOT NULL CHECK (octet_length(server_ephemeral_public_key) = 32),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
    ciphertext BYTEA NOT NULL CHECK (octet_length(ciphertext) >= 16),
    recovery_code_count SMALLINT NOT NULL CHECK (recovery_code_count > 0),
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    expires_at_epoch_millis BIGINT NOT NULL,
    acknowledged_at_epoch_millis BIGINT,
    CONSTRAINT uq_mfa_recovery_code_deliveries_idempotency
        UNIQUE (account_id, idempotency_key_hash),
    CONSTRAINT fk_mfa_recovery_code_deliveries_session_account
        FOREIGN KEY (account_session_id, account_id)
        REFERENCES account_sessions(account_session_id, account_id) ON DELETE RESTRICT,
    CONSTRAINT fk_mfa_recovery_code_deliveries_factor_account
        FOREIGN KEY (factor_id, account_id)
        REFERENCES account_mfa_factors(factor_id, account_id) ON DELETE RESTRICT,
    CHECK (expires_at_epoch_millis > created_at_epoch_millis),
    CHECK (expires_at_epoch_millis <= created_at_epoch_millis + 86400000),
    CHECK (
        acknowledged_at_epoch_millis IS NULL
        OR acknowledged_at_epoch_millis BETWEEN created_at_epoch_millis AND expires_at_epoch_millis
    )
);

CREATE INDEX idx_mfa_recovery_code_deliveries_session
    ON mfa_recovery_code_deliveries(account_session_id, expires_at_epoch_millis);
CREATE INDEX idx_mfa_recovery_code_deliveries_expiry
    ON mfa_recovery_code_deliveries(expires_at_epoch_millis)
    WHERE acknowledged_at_epoch_millis IS NULL;

CREATE TABLE account_recovery_codes (
    recovery_code_id TEXT PRIMARY KEY CHECK (btrim(recovery_code_id) <> ''),
    account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE RESTRICT,
    code_hash BYTEA NOT NULL UNIQUE CHECK (octet_length(code_hash) = 32),
    status TEXT NOT NULL CHECK (status IN ('active', 'used', 'expired', 'revoked')),
    used_at_epoch_millis BIGINT,
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    expires_at_epoch_millis BIGINT,
    CHECK (expires_at_epoch_millis IS NULL OR expires_at_epoch_millis > created_at_epoch_millis),
    CHECK (
        (
            status = 'used'
            AND used_at_epoch_millis IS NOT NULL
            AND used_at_epoch_millis >= created_at_epoch_millis
        )
        OR (status <> 'used' AND used_at_epoch_millis IS NULL)
    )
);

CREATE INDEX idx_account_recovery_codes_account_status
    ON account_recovery_codes(account_id, status, expires_at_epoch_millis);

CREATE TABLE account_risk_challenges (
    risk_challenge_id TEXT PRIMARY KEY CHECK (btrim(risk_challenge_id) <> ''),
    account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE RESTRICT,
    device_id TEXT REFERENCES devices(device_id) ON DELETE RESTRICT,
    purpose TEXT NOT NULL CHECK (
        purpose IN (
            'login_mfa',
            'new_controller_device',
            'trusted_device_change',
            'password_change',
            'mfa_factor_change',
            'recovery_code_rotate',
            'device_key_rotation',
            'unattended_secret_change',
            'require_prompt_relax',
            'allow_privacy_screen',
            'allow_block_local_input',
            'allow_remote_reboot',
            'remote_reboot',
            'access_policy_change',
            'client_release_change',
            'region_policy_change'
        )
    ),
    operation_binding_hash BYTEA NOT NULL CHECK (octet_length(operation_binding_hash) = 32),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('low', 'medium', 'high')),
    required_methods JSONB NOT NULL CHECK (jsonb_typeof(required_methods) = 'array'),
    status TEXT NOT NULL CHECK (status IN ('issued', 'verified', 'failed', 'consumed', 'expired', 'cancelled')),
    attempts_remaining SMALLINT NOT NULL CHECK (attempts_remaining BETWEEN 0 AND 5),
    ip_address INET,
    user_agent TEXT,
    expires_at_epoch_millis BIGINT NOT NULL,
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    verified_at_epoch_millis BIGINT,
    consumed_at_epoch_millis BIGINT,
    login_device_state TEXT CHECK (login_device_state IN ('registered', 'pending_enrollment')),
    login_device_id TEXT,
    login_device_public_key BYTEA CHECK (octet_length(login_device_public_key) = 32),
    login_device_public_key_fingerprint BYTEA CHECK (octet_length(login_device_public_key_fingerprint) = 32),
    login_public_key_id TEXT,
    login_public_key_version INTEGER,
    login_client_nonce BYTEA CHECK (octet_length(login_client_nonce) = 32),
    login_server_nonce BYTEA CHECK (octet_length(login_server_nonce) = 32),
    login_request_binding_hash BYTEA CHECK (octet_length(login_request_binding_hash) = 32),
    login_ip_address_hash BYTEA CHECK (octet_length(login_ip_address_hash) = 32),
    login_user_agent_hash BYTEA CHECK (octet_length(login_user_agent_hash) = 32),
    login_trusted_device_id TEXT,
    login_protocol_version INTEGER,
    login_attempts_limit SMALLINT,
    login_account_updated_at_epoch_millis BIGINT CHECK (login_account_updated_at_epoch_millis >= 0),
    UNIQUE (risk_challenge_id, account_id),
    CONSTRAINT ck_account_risk_challenges_device_identity CHECK (
        CASE
            WHEN purpose = 'login_mfa' AND login_device_state = 'registered' THEN
                device_id IS NOT NULL
                AND login_device_id IS NOT NULL
                AND device_id = login_device_id
            WHEN purpose = 'login_mfa' AND login_device_state = 'pending_enrollment' THEN
                device_id IS NULL
            WHEN purpose = 'new_controller_device' THEN
                device_id IS NULL
            WHEN purpose = 'login_mfa' THEN
                FALSE
            ELSE
                TRUE
        END
    ),
    CONSTRAINT ck_account_risk_challenges_required_methods CHECK (
        (
            purpose = 'login_mfa'
            AND required_methods IN ('[]'::JSONB, '["totp","recovery_code"]'::JSONB)
        )
        OR (
            purpose = 'password_change'
            AND required_methods IN ('["password"]'::JSONB, '["totp","recovery_code"]'::JSONB)
        )
        OR (
            purpose NOT IN ('login_mfa', 'password_change')
            AND required_methods = '["totp","recovery_code"]'::JSONB
        )
    ),
    CHECK (expires_at_epoch_millis > created_at_epoch_millis),
    CHECK (expires_at_epoch_millis <= created_at_epoch_millis + 300000),
    CHECK (verified_at_epoch_millis IS NULL OR verified_at_epoch_millis >= created_at_epoch_millis),
    CHECK (consumed_at_epoch_millis IS NULL OR consumed_at_epoch_millis >= created_at_epoch_millis),
    CHECK (status <> 'consumed' OR consumed_at_epoch_millis IS NOT NULL),
    CHECK (
        (
            purpose = 'login_mfa'
            AND login_device_state IS NOT NULL
            AND login_device_id IS NOT NULL
            AND btrim(login_device_id) <> ''
            AND login_device_public_key IS NOT NULL
            AND login_device_public_key_fingerprint IS NOT NULL
            AND login_public_key_version IS NOT NULL
            AND login_client_nonce IS NOT NULL
            AND login_server_nonce IS NOT NULL
            AND login_request_binding_hash IS NOT NULL
            AND login_ip_address_hash IS NOT NULL
            AND login_user_agent_hash IS NOT NULL
            AND login_protocol_version IS NOT NULL
            AND login_protocol_version BETWEEN 1 AND 65535
            AND login_attempts_limit IS NOT NULL
            AND login_attempts_limit BETWEEN 1 AND 5
            AND login_account_updated_at_epoch_millis IS NOT NULL
            AND attempts_remaining <= login_attempts_limit
            AND (
                (
                    login_device_state = 'registered'
                    AND login_public_key_id IS NOT NULL
                    AND btrim(login_public_key_id) <> ''
                    AND login_public_key_version > 0
                )
                OR (
                    login_device_state = 'pending_enrollment'
                    AND login_public_key_id IS NULL
                    AND login_public_key_version = 0
                    AND login_trusted_device_id IS NULL
                )
            )
        )
        OR (
            purpose <> 'login_mfa'
            AND login_device_state IS NULL
            AND login_device_id IS NULL
            AND login_device_public_key IS NULL
            AND login_device_public_key_fingerprint IS NULL
            AND login_public_key_id IS NULL
            AND login_public_key_version IS NULL
            AND login_client_nonce IS NULL
            AND login_server_nonce IS NULL
            AND login_request_binding_hash IS NULL
            AND login_ip_address_hash IS NULL
            AND login_user_agent_hash IS NULL
            AND login_trusted_device_id IS NULL
            AND login_protocol_version IS NULL
            AND login_attempts_limit IS NULL
            AND login_account_updated_at_epoch_millis IS NULL
        )
    )
);

CREATE INDEX idx_account_risk_challenges_account_status
    ON account_risk_challenges(account_id, status, expires_at_epoch_millis);
CREATE INDEX idx_account_risk_challenges_device ON account_risk_challenges(device_id);

CREATE TABLE device_enrollment_grants (
    grant_id TEXT PRIMARY KEY CHECK (btrim(grant_id) <> ''),
    grant_secret_hash BYTEA NOT NULL CHECK (octet_length(grant_secret_hash) = 32),
    account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE RESTRICT,
    device_id TEXT NOT NULL CHECK (btrim(device_id) <> ''),
    device_public_key_fingerprint BYTEA NOT NULL CHECK (octet_length(device_public_key_fingerprint) = 32),
    login_challenge_id TEXT NOT NULL,
    login_challenge_binding_hash BYTEA NOT NULL CHECK (octet_length(login_challenge_binding_hash) = 32),
    trust_proof_type TEXT CHECK (
        trust_proof_type IS NULL
        OR trust_proof_type IN ('device_signature_and_mfa', 'device_signature_and_recovery_code')
    ),
    trust_level TEXT CHECK (
        trust_level IS NULL
        OR trust_level IN ('standard', 'high_risk_step_up_required')
    ),
    establish_trust BOOLEAN NOT NULL,
    protocol_version INTEGER NOT NULL CHECK (protocol_version BETWEEN 1 AND 65535),
    issued_account_session_id TEXT NOT NULL,
    issued_at_epoch_millis BIGINT NOT NULL CHECK (issued_at_epoch_millis >= 0),
    expires_at_epoch_millis BIGINT NOT NULL,
    consumed_at_epoch_millis BIGINT,
    registration_request_binding_hash BYTEA
        CONSTRAINT ck_device_enrollment_grants_registration_binding_length
        CHECK (
            registration_request_binding_hash IS NULL
            OR octet_length(registration_request_binding_hash) = 32
        ),
    registered_public_key_id TEXT
        CONSTRAINT ck_device_enrollment_grants_registered_public_key_id
        CHECK (registered_public_key_id IS NULL OR btrim(registered_public_key_id) <> ''),
    registered_trusted_device_id TEXT
        CONSTRAINT ck_device_enrollment_grants_registered_trusted_device_id
        CHECK (registered_trusted_device_id IS NULL OR btrim(registered_trusted_device_id) <> ''),
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    CONSTRAINT uq_device_enrollment_grants_secret_hash UNIQUE (grant_secret_hash),
    CONSTRAINT uq_device_enrollment_grants_login_challenge UNIQUE (login_challenge_id),
    CONSTRAINT fk_device_enrollment_grants_challenge_account
        FOREIGN KEY (login_challenge_id, account_id)
        REFERENCES account_risk_challenges(risk_challenge_id, account_id) ON DELETE RESTRICT,
    CONSTRAINT fk_device_enrollment_grants_session_account
        FOREIGN KEY (issued_account_session_id, account_id)
        REFERENCES account_sessions(account_session_id, account_id) ON DELETE RESTRICT,
    CONSTRAINT ck_device_enrollment_grants_trust_presence CHECK (
        (establish_trust AND trust_proof_type IS NOT NULL AND trust_level IS NOT NULL)
        OR (NOT establish_trust AND trust_proof_type IS NULL AND trust_level IS NULL)
    ),
    CONSTRAINT ck_device_enrollment_grants_trust_policy CHECK (
        NOT establish_trust
        OR (
            trust_proof_type = 'device_signature_and_mfa'
            AND trust_level = 'standard'
        )
        OR (
            trust_proof_type = 'device_signature_and_recovery_code'
            AND trust_level = 'high_risk_step_up_required'
        )
    ),
    CHECK (issued_at_epoch_millis >= created_at_epoch_millis),
    CHECK (expires_at_epoch_millis > issued_at_epoch_millis),
    CHECK (expires_at_epoch_millis <= issued_at_epoch_millis + 300000),
    CHECK (
        consumed_at_epoch_millis IS NULL
        OR consumed_at_epoch_millis BETWEEN issued_at_epoch_millis AND expires_at_epoch_millis
    ),
    CONSTRAINT ck_device_enrollment_grants_registration_result CHECK (
        (
            consumed_at_epoch_millis IS NULL
            AND registration_request_binding_hash IS NULL
            AND registered_public_key_id IS NULL
            AND registered_trusted_device_id IS NULL
        )
        OR (
            consumed_at_epoch_millis IS NOT NULL
            AND registration_request_binding_hash IS NOT NULL
            AND registered_public_key_id IS NOT NULL
            AND (
                (establish_trust AND registered_trusted_device_id IS NOT NULL)
                OR (NOT establish_trust AND registered_trusted_device_id IS NULL)
            )
        )
    )
);

CREATE INDEX idx_device_enrollment_grants_account_device_active
    ON device_enrollment_grants(account_id, device_id, expires_at_epoch_millis)
    WHERE consumed_at_epoch_millis IS NULL;
CREATE INDEX idx_device_enrollment_grants_expiry
    ON device_enrollment_grants(expires_at_epoch_millis)
    WHERE consumed_at_epoch_millis IS NULL;
CREATE INDEX idx_device_enrollment_grants_issued_session
    ON device_enrollment_grants(issued_account_session_id, created_at_epoch_millis);

CREATE TABLE trusted_controller_devices (
    trusted_device_id TEXT PRIMARY KEY CHECK (btrim(trusted_device_id) <> ''),
    account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE RESTRICT,
    controller_device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    device_fingerprint_hash BYTEA NOT NULL CHECK (octet_length(device_fingerprint_hash) = 32),
    trust_level TEXT NOT NULL CHECK (trust_level IN ('standard', 'high_risk_step_up_required')),
    status TEXT NOT NULL CHECK (status IN ('active', 'expired', 'revoked')),
    trust_proof_type TEXT NOT NULL CHECK (
        trust_proof_type IN ('device_signature_and_mfa', 'device_signature_and_recovery_code')
    ),
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    last_used_at_epoch_millis BIGINT,
    expires_at_epoch_millis BIGINT NOT NULL,
    revoked_at_epoch_millis BIGINT,
    CONSTRAINT uq_trusted_controller_devices_identity
        UNIQUE (trusted_device_id, controller_device_id, account_id),
    FOREIGN KEY (controller_device_id, account_id)
        REFERENCES devices(device_id, account_id) ON DELETE RESTRICT,
    CHECK (expires_at_epoch_millis > created_at_epoch_millis),
    CONSTRAINT ck_trusted_controller_devices_trust_policy CHECK (
        (
            trust_proof_type = 'device_signature_and_mfa'
            AND trust_level = 'standard'
            AND expires_at_epoch_millis <= created_at_epoch_millis + 2592000000
        )
        OR (
            trust_proof_type = 'device_signature_and_recovery_code'
            AND trust_level = 'high_risk_step_up_required'
            AND expires_at_epoch_millis <= created_at_epoch_millis + 86400000
        )
    ),
    CHECK (last_used_at_epoch_millis IS NULL OR last_used_at_epoch_millis >= created_at_epoch_millis),
    CHECK (
        (
            status = 'revoked'
            AND revoked_at_epoch_millis IS NOT NULL
            AND revoked_at_epoch_millis >= created_at_epoch_millis
        )
        OR (status <> 'revoked' AND revoked_at_epoch_millis IS NULL)
    )
);

CREATE UNIQUE INDEX uq_trusted_controller_devices_active
    ON trusted_controller_devices(account_id, controller_device_id)
    WHERE status = 'active';

ALTER TABLE device_enrollment_grants
    ADD CONSTRAINT fk_device_enrollment_grants_registered_trusted_device
    FOREIGN KEY (registered_trusted_device_id, device_id, account_id)
    REFERENCES trusted_controller_devices(trusted_device_id, controller_device_id, account_id)
    ON DELETE RESTRICT;

CREATE TABLE device_policies (
    device_id TEXT PRIMARY KEY REFERENCES devices(device_id) ON DELETE RESTRICT,
    allow_remote_desktop BOOLEAN NOT NULL DEFAULT FALSE,
    allow_input_control BOOLEAN NOT NULL DEFAULT FALSE,
    allow_clipboard BOOLEAN NOT NULL DEFAULT FALSE,
    allow_file_transfer BOOLEAN NOT NULL DEFAULT FALSE,
    allow_unattended BOOLEAN NOT NULL DEFAULT FALSE,
    allow_privacy_screen BOOLEAN NOT NULL DEFAULT FALSE,
    allow_block_local_input BOOLEAN NOT NULL DEFAULT FALSE,
    require_prompt BOOLEAN NOT NULL DEFAULT TRUE,
    allow_relay BOOLEAN NOT NULL DEFAULT FALSE,
    allow_remote_reboot BOOLEAN NOT NULL DEFAULT FALSE,
    last_high_risk_allow_step_up_challenge_id TEXT REFERENCES account_risk_challenges(risk_challenge_id) ON DELETE RESTRICT,
    last_high_risk_allow_step_up_verified_at_epoch_millis BIGINT,
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    updated_at_epoch_millis BIGINT NOT NULL CHECK (updated_at_epoch_millis >= created_at_epoch_millis),
    CHECK (
        (last_high_risk_allow_step_up_challenge_id IS NULL)
        = (last_high_risk_allow_step_up_verified_at_epoch_millis IS NULL)
    )
);

CREATE TABLE device_access_rules (
    device_access_rule_id TEXT PRIMARY KEY CHECK (btrim(device_access_rule_id) <> ''),
    controlled_device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    controller_account_id TEXT REFERENCES accounts(account_id) ON DELETE RESTRICT,
    controller_device_id TEXT REFERENCES devices(device_id) ON DELETE RESTRICT,
    rule_type TEXT NOT NULL CHECK (rule_type IN ('allow', 'deny', 'trusted')),
    reason TEXT CHECK (reason IS NULL OR btrim(reason) <> ''),
    created_by_account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE RESTRICT,
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    expires_at_epoch_millis BIGINT,
    CHECK (controller_account_id IS NOT NULL OR controller_device_id IS NOT NULL),
    CHECK (expires_at_epoch_millis IS NULL OR expires_at_epoch_millis > created_at_epoch_millis)
);

CREATE INDEX idx_device_access_rules_evaluation
    ON device_access_rules(controlled_device_id, rule_type, expires_at_epoch_millis);
CREATE INDEX idx_device_access_rules_controller
    ON device_access_rules(controller_account_id, controller_device_id);

CREATE TABLE device_local_security_settings (
    device_id TEXT PRIMARY KEY REFERENCES devices(device_id) ON DELETE RESTRICT,
    allow_privacy_screen BOOLEAN NOT NULL DEFAULT FALSE,
    allow_block_local_input BOOLEAN NOT NULL DEFAULT FALSE,
    local_escape_hint_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    privacy_screen_supported BOOLEAN NOT NULL DEFAULT FALSE,
    block_local_input_supported BOOLEAN NOT NULL DEFAULT FALSE,
    last_capability_probe_at_epoch_millis BIGINT,
    last_allow_step_up_challenge_id TEXT REFERENCES account_risk_challenges(risk_challenge_id) ON DELETE RESTRICT,
    last_allow_step_up_verified_at_epoch_millis BIGINT,
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    updated_at_epoch_millis BIGINT NOT NULL CHECK (updated_at_epoch_millis >= created_at_epoch_millis),
    CHECK (last_capability_probe_at_epoch_millis IS NULL OR last_capability_probe_at_epoch_millis >= created_at_epoch_millis),
    CHECK (
        (last_allow_step_up_challenge_id IS NULL)
        = (last_allow_step_up_verified_at_epoch_millis IS NULL)
    )
);

CREATE TABLE api_idempotency_keys (
    idempotency_key TEXT NOT NULL CHECK (btrim(idempotency_key) <> ''),
    account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE RESTRICT,
    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    method TEXT NOT NULL CHECK (method ~ '^[A-Z]+$'),
    path TEXT NOT NULL CHECK (left(path, 1) = '/'),
    body_hash BYTEA NOT NULL CHECK (octet_length(body_hash) = 32),
    request_id TEXT NOT NULL CHECK (btrim(request_id) <> ''),
    resource_type TEXT CHECK (resource_type IS NULL OR btrim(resource_type) <> ''),
    resource_id TEXT CHECK (resource_id IS NULL OR btrim(resource_id) <> ''),
    response_status SMALLINT CHECK (response_status BETWEEN 100 AND 599),
    response_body_hash BYTEA CHECK (response_body_hash IS NULL OR octet_length(response_body_hash) = 32),
    expires_at_epoch_millis BIGINT NOT NULL,
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    PRIMARY KEY (account_id, device_id, method, path, idempotency_key),
    UNIQUE (request_id),
    CHECK (expires_at_epoch_millis > created_at_epoch_millis)
);

CREATE INDEX idx_api_idempotency_keys_expiry ON api_idempotency_keys(expires_at_epoch_millis);

CREATE TABLE abuse_reports (
    abuse_report_id TEXT PRIMARY KEY CHECK (btrim(abuse_report_id) <> ''),
    reporter_account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE RESTRICT,
    reporter_device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    reported_account_id TEXT REFERENCES accounts(account_id) ON DELETE RESTRICT,
    reported_device_id TEXT REFERENCES devices(device_id) ON DELETE RESTRICT,
    session_id TEXT,
    category TEXT NOT NULL CHECK (
        category IN ('impersonation', 'scam_assistance', 'unauthorized_access', 'blackmail', 'harassment', 'payment_fraud', 'other')
    ),
    reason TEXT CHECK (reason IS NULL OR btrim(reason) <> ''),
    status TEXT NOT NULL CHECK (status IN ('received', 'triaging', 'accepted', 'rejected', 'merged_into_case')),
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    CHECK (reported_account_id IS NOT NULL OR reported_device_id IS NOT NULL)
);

CREATE INDEX idx_abuse_reports_subject
    ON abuse_reports(reported_account_id, reported_device_id, created_at_epoch_millis);
CREATE INDEX idx_abuse_reports_session ON abuse_reports(session_id);

CREATE TABLE abuse_cases (
    abuse_case_id TEXT PRIMARY KEY CHECK (btrim(abuse_case_id) <> ''),
    primary_report_id TEXT NOT NULL REFERENCES abuse_reports(abuse_report_id) ON DELETE RESTRICT,
    subject_account_id TEXT REFERENCES accounts(account_id) ON DELETE RESTRICT,
    subject_device_id TEXT REFERENCES devices(device_id) ON DELETE RESTRICT,
    risk_level TEXT NOT NULL CHECK (risk_level IN ('low', 'medium', 'high', 'critical')),
    status TEXT NOT NULL CHECK (status IN ('open', 'investigating', 'action_taken', 'closed_no_action', 'closed_with_action', 'reopened')),
    assigned_to_account_id TEXT REFERENCES accounts(account_id) ON DELETE RESTRICT,
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    updated_at_epoch_millis BIGINT NOT NULL CHECK (updated_at_epoch_millis >= created_at_epoch_millis),
    closed_at_epoch_millis BIGINT,
    CHECK (subject_account_id IS NOT NULL OR subject_device_id IS NOT NULL),
    CHECK (closed_at_epoch_millis IS NULL OR closed_at_epoch_millis >= created_at_epoch_millis)
);

CREATE INDEX idx_abuse_cases_subject_status
    ON abuse_cases(subject_account_id, subject_device_id, status);

CREATE TABLE abuse_enforcement_actions (
    enforcement_action_id TEXT PRIMARY KEY CHECK (btrim(enforcement_action_id) <> ''),
    abuse_case_id TEXT NOT NULL REFERENCES abuse_cases(abuse_case_id) ON DELETE RESTRICT,
    subject_type TEXT NOT NULL CHECK (subject_type IN ('account', 'device', 'organization', 'relay_node', 'session', 'file_transfer')),
    subject_id TEXT NOT NULL CHECK (btrim(subject_id) <> ''),
    action TEXT NOT NULL CHECK (
        action IN (
            'warn_user',
            'require_mfa',
            'require_prompt',
            'cooldown',
            'throttle_session',
            'throttle_relay',
            'deny_session',
            'suspend_device',
            'suspend_account',
            'quarantine_relay',
            'blacklist_controller',
            'blacklist_device',
            'revoke_trust',
            'manual_review'
        )
    ),
    reason TEXT NOT NULL CHECK (btrim(reason) <> ''),
    starts_at_epoch_millis BIGINT NOT NULL CHECK (starts_at_epoch_millis >= 0),
    expires_at_epoch_millis BIGINT,
    created_by_actor_type TEXT NOT NULL CHECK (created_by_actor_type IN ('system', 'service', 'account')),
    created_by_account_id TEXT REFERENCES accounts(account_id) ON DELETE RESTRICT,
    revoked_at_epoch_millis BIGINT,
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    CHECK (expires_at_epoch_millis IS NULL OR expires_at_epoch_millis > starts_at_epoch_millis),
    CHECK (revoked_at_epoch_millis IS NULL OR revoked_at_epoch_millis >= starts_at_epoch_millis),
    CHECK (
        (created_by_actor_type = 'account' AND created_by_account_id IS NOT NULL)
        OR (created_by_actor_type IN ('system', 'service') AND created_by_account_id IS NULL)
    )
);

CREATE INDEX idx_abuse_enforcement_active
    ON abuse_enforcement_actions(subject_type, subject_id, starts_at_epoch_millis, expires_at_epoch_millis)
    WHERE revoked_at_epoch_millis IS NULL;

CREATE TABLE abuse_risk_events (
    risk_event_id TEXT PRIMARY KEY CHECK (btrim(risk_event_id) <> ''),
    account_id TEXT REFERENCES accounts(account_id) ON DELETE RESTRICT,
    device_id TEXT REFERENCES devices(device_id) ON DELETE RESTRICT,
    session_id TEXT,
    event_type TEXT NOT NULL CHECK (
        event_type IN (
            'login',
            'new_controller_device',
            'short_assistance_spike',
            'unfamiliar_controlled_device',
            'unfamiliar_country',
            'relay_abuse',
            'rate_limited',
            'reported_by_controlled',
            'blacklist_hit',
            'cooldown_exceeded'
        )
    ),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('low', 'medium', 'high')),
    signals JSONB NOT NULL CHECK (jsonb_typeof(signals) = 'object'),
    decision TEXT NOT NULL CHECK (decision IN ('allow', 'warn_user', 'require_mfa', 'require_prompt', 'cooldown', 'deny_session')),
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0)
);

CREATE INDEX idx_abuse_risk_events_subject_time
    ON abuse_risk_events(account_id, device_id, created_at_epoch_millis);
CREATE INDEX idx_abuse_risk_events_session ON abuse_risk_events(session_id);

CREATE TABLE access_policies (
    access_policy_id TEXT PRIMARY KEY CHECK (btrim(access_policy_id) <> ''),
    scope_type TEXT NOT NULL CHECK (scope_type IN ('account', 'organization', 'device_group', 'device')),
    scope_id TEXT NOT NULL CHECK (btrim(scope_id) <> ''),
    name TEXT NOT NULL CHECK (btrim(name) <> ''),
    priority INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled', 'deleted')),
    conditions JSONB NOT NULL DEFAULT '{}'::JSONB CHECK (access_conditions_valid(conditions)),
    effects JSONB NOT NULL DEFAULT '{}'::JSONB CHECK (access_effects_valid(effects)),
    created_by_account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE RESTRICT,
    updated_by_account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE RESTRICT,
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    updated_at_epoch_millis BIGINT NOT NULL CHECK (updated_at_epoch_millis >= created_at_epoch_millis)
);

CREATE INDEX idx_access_policies_evaluation
    ON access_policies(scope_type, scope_id, status, priority DESC, created_at_epoch_millis);

CREATE TABLE access_policy_assignments (
    assignment_id TEXT PRIMARY KEY CHECK (btrim(assignment_id) <> ''),
    access_policy_id TEXT NOT NULL REFERENCES access_policies(access_policy_id) ON DELETE RESTRICT,
    target_type TEXT NOT NULL CHECK (target_type IN ('account', 'organization', 'role', 'device_group', 'device')),
    target_id TEXT NOT NULL CHECK (btrim(target_id) <> ''),
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled', 'deleted')),
    created_by_account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE RESTRICT,
    disabled_at_epoch_millis BIGINT,
    deleted_at_epoch_millis BIGINT,
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    UNIQUE (access_policy_id, target_type, target_id),
    CHECK (disabled_at_epoch_millis IS NULL OR disabled_at_epoch_millis >= created_at_epoch_millis),
    CHECK (deleted_at_epoch_millis IS NULL OR deleted_at_epoch_millis >= created_at_epoch_millis),
    CHECK (status <> 'disabled' OR disabled_at_epoch_millis IS NOT NULL),
    CHECK (status <> 'deleted' OR deleted_at_epoch_millis IS NOT NULL)
);

CREATE INDEX idx_access_policy_assignments_target
    ON access_policy_assignments(target_type, target_id, status);

CREATE TABLE relay_nodes (
    relay_node_id TEXT PRIMARY KEY CHECK (btrim(relay_node_id) <> ''),
    region TEXT NOT NULL CHECK (btrim(region) <> ''),
    country TEXT NOT NULL CHECK (btrim(country) <> ''),
    provider TEXT NOT NULL CHECK (btrim(provider) <> ''),
    public_endpoint TEXT NOT NULL UNIQUE CHECK (btrim(public_endpoint) <> ''),
    status TEXT NOT NULL CHECK (status IN ('active', 'draining', 'disabled', 'quarantined')),
    max_sessions INTEGER NOT NULL CHECK (max_sessions >= 0),
    active_sessions INTEGER NOT NULL DEFAULT 0 CHECK (active_sessions >= 0 AND active_sessions <= max_sessions),
    supports_quic BOOLEAN NOT NULL DEFAULT TRUE,
    supports_tls_443 BOOLEAN NOT NULL DEFAULT FALSE,
    data_residency_class TEXT CHECK (data_residency_class IS NULL OR btrim(data_residency_class) <> ''),
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    updated_at_epoch_millis BIGINT NOT NULL CHECK (updated_at_epoch_millis >= created_at_epoch_millis),
    CHECK (supports_quic OR supports_tls_443)
);

CREATE INDEX idx_relay_nodes_allocation
    ON relay_nodes(region, status, active_sessions, max_sessions);

CREATE TABLE policy_evaluations (
    policy_evaluation_id TEXT PRIMARY KEY CHECK (btrim(policy_evaluation_id) <> ''),
    account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE RESTRICT,
    controller_device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    controlled_device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    session_id TEXT CHECK (
        session_id IS NULL
        OR session_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    request_type TEXT NOT NULL CHECK (btrim(request_type) <> ''),
    access_decision TEXT NOT NULL CHECK (access_decision IN ('allow', 'deny', 'require_mfa', 'require_prompt')),
    anti_abuse_decision TEXT NOT NULL CHECK (anti_abuse_decision IN ('allow', 'warn_user', 'cooldown', 'deny_session')),
    session_access_decision TEXT NOT NULL CHECK (
        session_access_decision IN ('allow', 'warn_user', 'require_prompt', 'require_mfa', 'cooldown', 'deny_session')
    ),
    effective_permissions JSONB NOT NULL CHECK (v1_permissions_valid(effective_permissions)),
    permissions_digest BYTEA NOT NULL CHECK (octet_length(permissions_digest) = 32),
    matched_policy_ids JSONB NOT NULL DEFAULT '[]'::JSONB CHECK (jsonb_typeof(matched_policy_ids) = 'array'),
    abuse_actions JSONB NOT NULL DEFAULT '[]'::JSONB CHECK (jsonb_typeof(abuse_actions) = 'array'),
    risk_challenge_id TEXT REFERENCES account_risk_challenges(risk_challenge_id) ON DELETE RESTRICT,
    cooldown_until_epoch_millis BIGINT,
    user_warnings JSONB NOT NULL DEFAULT '[]'::JSONB CHECK (jsonb_typeof(user_warnings) = 'array'),
    deny_reason TEXT CHECK (deny_reason IS NULL OR btrim(deny_reason) <> ''),
    metadata JSONB NOT NULL DEFAULT '{}'::JSONB CHECK (jsonb_typeof(metadata) = 'object'),
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    FOREIGN KEY (controller_device_id, account_id)
        REFERENCES devices(device_id, account_id) ON DELETE RESTRICT,
    CHECK (controller_device_id <> controlled_device_id),
    CHECK (cooldown_until_epoch_millis IS NULL OR cooldown_until_epoch_millis > created_at_epoch_millis),
    CHECK (access_decision <> 'deny' OR session_access_decision = 'deny_session'),
    CHECK (anti_abuse_decision <> 'deny_session' OR session_access_decision = 'deny_session')
);

CREATE INDEX idx_policy_evaluations_session ON policy_evaluations(session_id);
CREATE INDEX idx_policy_evaluations_devices_time
    ON policy_evaluations(controller_device_id, controlled_device_id, created_at_epoch_millis);

CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY CHECK (
        session_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ),
    controller_account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE RESTRICT,
    controller_device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    controlled_device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    auth_method TEXT NOT NULL CHECK (auth_method IN ('temporary_code', 'unattended', 'account_prompt')),
    status TEXT NOT NULL CHECK (
        status IN (
            'pending_code_verification',
            'pending_unattended_verification',
            'code_verified',
            'unattended_verified',
            'waiting_approval',
            'accepted',
            'connected',
            'degraded',
            'reconnecting',
            'cancelled',
            'closed',
            'rejected',
            'failed'
        )
    ),
    permissions JSONB NOT NULL CHECK (v1_permissions_valid(permissions)),
    permissions_digest BYTEA NOT NULL CHECK (octet_length(permissions_digest) = 32),
    permissions_digest_last_changed_at_epoch_millis BIGINT NOT NULL,
    policy_evaluation_id TEXT NOT NULL REFERENCES policy_evaluations(policy_evaluation_id) ON DELETE RESTRICT,
    relay_token_epoch BIGINT NOT NULL DEFAULT 1 CHECK (relay_token_epoch >= 1),
    session_expires_at_epoch_millis BIGINT NOT NULL,
    transport_path TEXT CHECK (
        transport_path IS NULL
        OR transport_path IN ('lan_direct', 'udp_p2p', 'quic_relay', 'tls_443_relay')
    ),
    selected_candidate_pair_id TEXT,
    relay_node_id TEXT REFERENCES relay_nodes(relay_node_id) ON DELETE RESTRICT,
    started_at_epoch_millis BIGINT,
    ended_at_epoch_millis BIGINT,
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    updated_at_epoch_millis BIGINT NOT NULL,
    FOREIGN KEY (controller_device_id, controller_account_id)
        REFERENCES devices(device_id, account_id) ON DELETE RESTRICT,
    CHECK (controller_device_id <> controlled_device_id),
    CHECK (session_expires_at_epoch_millis > created_at_epoch_millis),
    CHECK (permissions_digest_last_changed_at_epoch_millis >= created_at_epoch_millis),
    CHECK (updated_at_epoch_millis >= created_at_epoch_millis),
    CHECK (started_at_epoch_millis IS NULL OR started_at_epoch_millis >= created_at_epoch_millis),
    CHECK (ended_at_epoch_millis IS NULL OR ended_at_epoch_millis >= created_at_epoch_millis),
    CHECK ((transport_path IS NULL) = (selected_candidate_pair_id IS NULL)),
    CHECK (
        (transport_path IN ('quic_relay', 'tls_443_relay') AND relay_node_id IS NOT NULL)
        OR (transport_path IS NULL AND relay_node_id IS NULL)
        OR (transport_path IN ('lan_direct', 'udp_p2p') AND relay_node_id IS NULL)
    )
);

ALTER TABLE policy_evaluations
    ADD CONSTRAINT fk_policy_evaluations_session
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE INDEX idx_sessions_controller_account_status
    ON sessions(controller_account_id, status, created_at_epoch_millis);
CREATE INDEX idx_sessions_controller_device_status
    ON sessions(controller_device_id, status, created_at_epoch_millis);
CREATE INDEX idx_sessions_controlled_device_status
    ON sessions(controlled_device_id, status, created_at_epoch_millis);
CREATE INDEX idx_sessions_policy_evaluation ON sessions(policy_evaluation_id);
CREATE INDEX idx_sessions_relay_node ON sessions(relay_node_id) WHERE relay_node_id IS NOT NULL;
CREATE INDEX idx_sessions_expiry ON sessions(session_expires_at_epoch_millis);

ALTER TABLE abuse_reports
    ADD CONSTRAINT fk_abuse_reports_session
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE RESTRICT;

ALTER TABLE abuse_risk_events
    ADD CONSTRAINT fk_abuse_risk_events_session
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE RESTRICT;

CREATE TABLE verification_codes (
    code_id TEXT PRIMARY KEY CHECK (btrim(code_id) <> ''),
    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    code_verifier_record BYTEA NOT NULL CHECK (octet_length(code_verifier_record) > 0),
    code_verifier_salt BYTEA NOT NULL CHECK (octet_length(code_verifier_salt) > 0),
    proof_scheme TEXT NOT NULL CHECK (proof_scheme = 'opaque_ristretto255_sha512_v1'),
    active_challenge_id TEXT,
    active_session_id TEXT REFERENCES sessions(session_id) ON DELETE RESTRICT,
    server_nonce BYTEA,
    challenge_status TEXT NOT NULL CHECK (challenge_status IN ('active', 'consumed', 'expired', 'replaced')),
    challenge_issued_at_epoch_millis BIGINT,
    challenge_expires_at_epoch_millis BIGINT,
    expires_at_epoch_millis BIGINT NOT NULL,
    attempts_remaining SMALLINT NOT NULL CHECK (attempts_remaining BETWEEN 0 AND 5),
    consumed_at_epoch_millis BIGINT,
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    CHECK (expires_at_epoch_millis > created_at_epoch_millis),
    CHECK (expires_at_epoch_millis <= created_at_epoch_millis + 86400000),
    CHECK (
        challenge_expires_at_epoch_millis IS NULL
        OR (
            challenge_issued_at_epoch_millis IS NOT NULL
            AND challenge_expires_at_epoch_millis > challenge_issued_at_epoch_millis
            AND challenge_expires_at_epoch_millis <= challenge_issued_at_epoch_millis + 300000
            AND challenge_expires_at_epoch_millis <= expires_at_epoch_millis
        )
    ),
    CHECK (
        challenge_status <> 'active'
        OR (
            active_challenge_id IS NOT NULL
            AND active_session_id IS NOT NULL
            AND server_nonce IS NOT NULL
            AND challenge_issued_at_epoch_millis IS NOT NULL
            AND challenge_expires_at_epoch_millis IS NOT NULL
            AND consumed_at_epoch_millis IS NULL
        )
    ),
    CHECK (consumed_at_epoch_millis IS NULL OR consumed_at_epoch_millis >= created_at_epoch_millis)
);

CREATE INDEX idx_verification_codes_device_expiry
    ON verification_codes(device_id, expires_at_epoch_millis);
CREATE INDEX idx_verification_codes_active_session ON verification_codes(active_session_id);
CREATE UNIQUE INDEX uq_verification_codes_active_device
    ON verification_codes(device_id)
    WHERE challenge_status = 'active' AND consumed_at_epoch_millis IS NULL;

CREATE FUNCTION validate_verification_code_session()
RETURNS TRIGGER
LANGUAGE PLPGSQL
AS $$
DECLARE
    session_controlled_device_id TEXT;
    session_auth_method TEXT;
    session_status TEXT;
BEGIN
    IF NEW.active_session_id IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT controlled_device_id, auth_method, status
    INTO session_controlled_device_id, session_auth_method, session_status
    FROM sessions
    WHERE session_id = NEW.active_session_id;

    IF session_controlled_device_id IS DISTINCT FROM NEW.device_id
       OR session_auth_method IS DISTINCT FROM 'temporary_code' THEN
        RAISE EXCEPTION 'verification code session binding is invalid';
    END IF;

    IF NEW.challenge_status = 'active'
       AND session_status IS DISTINCT FROM 'pending_code_verification' THEN
        RAISE EXCEPTION 'active verification challenge requires a pending code session';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_verification_code_session
BEFORE INSERT OR UPDATE OF device_id, active_session_id, challenge_status ON verification_codes
FOR EACH ROW EXECUTE FUNCTION validate_verification_code_session();

CREATE TABLE unattended_secrets (
    unattended_secret_id TEXT PRIMARY KEY CHECK (btrim(unattended_secret_id) <> ''),
    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    credential_record BYTEA NOT NULL CHECK (octet_length(credential_record) > 0),
    credential_salt BYTEA NOT NULL CHECK (octet_length(credential_salt) > 0),
    proof_scheme TEXT NOT NULL CHECK (proof_scheme = 'opaque_ristretto255_sha512_v1'),
    version INTEGER NOT NULL CHECK (version >= 1),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    rotated_at_epoch_millis BIGINT,
    disabled_at_epoch_millis BIGINT,
    UNIQUE (device_id, version),
    CHECK (rotated_at_epoch_millis IS NULL OR rotated_at_epoch_millis >= created_at_epoch_millis),
    CHECK (
        (enabled AND disabled_at_epoch_millis IS NULL)
        OR (
            NOT enabled
            AND disabled_at_epoch_millis IS NOT NULL
            AND disabled_at_epoch_millis >= created_at_epoch_millis
        )
    )
);

CREATE UNIQUE INDEX uq_unattended_secrets_enabled_device
    ON unattended_secrets(device_id) WHERE enabled;

CREATE TABLE remote_reboot_requests (
    reboot_request_id TEXT PRIMARY KEY CHECK (btrim(reboot_request_id) <> ''),
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE RESTRICT,
    controller_account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE RESTRICT,
    controller_device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    controlled_device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (
        status IN ('pending', 'accepted', 'cancelled', 'executing', 'device_offline', 'resume_ready', 'resumed', 'failed', 'expired')
    ),
    api_request_hash BYTEA NOT NULL CHECK (octet_length(api_request_hash) = 32),
    api_request_hash_status TEXT NOT NULL CHECK (api_request_hash_status IN ('pending', 'accepted')),
    mode TEXT NOT NULL CHECK (mode IN ('normal', 'safe_mode_reserved')),
    reason_hash BYTEA NOT NULL CHECK (octet_length(reason_hash) = 32),
    countdown_seconds INTEGER NOT NULL CHECK (countdown_seconds BETWEEN 10 AND 3600),
    reconnect_after_reboot BOOLEAN NOT NULL,
    allow_remote_reboot BOOLEAN NOT NULL CHECK (allow_remote_reboot),
    allow_remote_reboot_last_changed_at_epoch_millis BIGINT NOT NULL,
    step_up_challenge_id TEXT NOT NULL REFERENCES account_risk_challenges(risk_challenge_id) ON DELETE RESTRICT,
    step_up_verified_at_epoch_millis BIGINT NOT NULL,
    step_up_expires_at_epoch_millis BIGINT NOT NULL,
    idempotency_key_hash BYTEA NOT NULL CHECK (octet_length(idempotency_key_hash) = 32),
    policy_evaluation_id TEXT NOT NULL REFERENCES policy_evaluations(policy_evaluation_id) ON DELETE RESTRICT,
    policy_evaluated_at_epoch_millis BIGINT NOT NULL,
    permissions_digest BYTEA NOT NULL CHECK (octet_length(permissions_digest) = 32),
    permissions_digest_last_changed_at_epoch_millis BIGINT NOT NULL,
    auto_resume_consent TEXT NOT NULL DEFAULT 'none' CHECK (auto_resume_consent IN ('none', 'once_by_controlled_user')),
    consent_at_epoch_millis BIGINT,
    consent_controlled_device_id TEXT REFERENCES devices(device_id) ON DELETE RESTRICT,
    consent_local_user_principal_hash BYTEA CHECK (
        consent_local_user_principal_hash IS NULL OR octet_length(consent_local_user_principal_hash) = 32
    ),
    consent_revoked_at_epoch_millis BIGINT,
    consent_revoked_by_actor_type TEXT CHECK (
        consent_revoked_by_actor_type IS NULL OR consent_revoked_by_actor_type IN ('controlled_device', 'account', 'system')
    ),
    consent_revoked_reason TEXT CHECK (
        consent_revoked_reason IS NULL
        OR consent_revoked_reason IN (
            'controlled_user_revoked',
            'unattended_disabled',
            'device_unbound',
            'mfa_reset',
            'policy_changed',
            'token_invalidated'
        )
    ),
    local_consent_token_hash BYTEA CHECK (
        local_consent_token_hash IS NULL OR octet_length(local_consent_token_hash) = 32
    ),
    auto_resume_consumed_at_epoch_millis BIGINT,
    reboot_resume_token_id TEXT,
    reboot_resume_token_secret_hash BYTEA CHECK (
        reboot_resume_token_secret_hash IS NULL OR octet_length(reboot_resume_token_secret_hash) = 32
    ),
    reboot_resume_token_consumed_at_epoch_millis BIGINT,
    reboot_resume_token_invalidated_at_epoch_millis BIGINT,
    reboot_resume_token_invalidation_reason TEXT CHECK (
        reboot_resume_token_invalidation_reason IS NULL
        OR reboot_resume_token_invalidation_reason IN (
            'expired',
            'cancelled',
            'resume_failed',
            'policy_changed',
            'permissions_changed',
            'device_key_revoked',
            'manual_revoked'
        )
    ),
    resume_expires_at_epoch_millis BIGINT,
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    expires_at_epoch_millis BIGINT NOT NULL,
    requested_at_epoch_millis BIGINT NOT NULL,
    accepted_at_epoch_millis BIGINT,
    executed_at_epoch_millis BIGINT,
    cancelled_at_epoch_millis BIGINT,
    failure_reason TEXT CHECK (failure_reason IS NULL OR btrim(failure_reason) <> ''),
    FOREIGN KEY (controller_device_id, controller_account_id)
        REFERENCES devices(device_id, account_id) ON DELETE RESTRICT,
    CHECK (controller_device_id <> controlled_device_id),
    CHECK (expires_at_epoch_millis > created_at_epoch_millis),
    CHECK (requested_at_epoch_millis >= created_at_epoch_millis),
    CHECK (step_up_verified_at_epoch_millis <= step_up_expires_at_epoch_millis),
    CHECK (
        step_up_verified_at_epoch_millis >= GREATEST(
            permissions_digest_last_changed_at_epoch_millis,
            allow_remote_reboot_last_changed_at_epoch_millis,
            policy_evaluated_at_epoch_millis
        )
    ),
    CHECK (
        auto_resume_consent = 'none'
        OR (
            consent_at_epoch_millis IS NOT NULL
            AND consent_controlled_device_id = controlled_device_id
            AND consent_local_user_principal_hash IS NOT NULL
            AND local_consent_token_hash IS NOT NULL
        )
    ),
    CHECK (
        (consent_revoked_at_epoch_millis IS NULL
            AND consent_revoked_by_actor_type IS NULL
            AND consent_revoked_reason IS NULL)
        OR (consent_revoked_at_epoch_millis IS NOT NULL
            AND consent_revoked_by_actor_type IS NOT NULL
            AND consent_revoked_reason IS NOT NULL)
    ),
    CHECK (
        (reboot_resume_token_id IS NULL AND reboot_resume_token_secret_hash IS NULL)
        OR (
            reboot_resume_token_id IS NOT NULL
            AND btrim(reboot_resume_token_id) <> ''
            AND reboot_resume_token_secret_hash IS NOT NULL
            AND resume_expires_at_epoch_millis IS NOT NULL
        )
    ),
    CHECK (
        NOT (
            reboot_resume_token_consumed_at_epoch_millis IS NOT NULL
            AND reboot_resume_token_invalidated_at_epoch_millis IS NOT NULL
        )
    ),
    CHECK (
        (reboot_resume_token_invalidated_at_epoch_millis IS NULL)
        = (reboot_resume_token_invalidation_reason IS NULL)
    ),
    CHECK (resume_expires_at_epoch_millis IS NULL OR resume_expires_at_epoch_millis > created_at_epoch_millis),
    CHECK (
        reboot_resume_token_consumed_at_epoch_millis IS NULL
        OR (
            reboot_resume_token_id IS NOT NULL
            AND reboot_resume_token_consumed_at_epoch_millis >= created_at_epoch_millis
        )
    ),
    CHECK (
        reboot_resume_token_invalidated_at_epoch_millis IS NULL
        OR (
            reboot_resume_token_id IS NOT NULL
            AND reboot_resume_token_invalidated_at_epoch_millis >= created_at_epoch_millis
        )
    ),
    CHECK (
        status NOT IN ('accepted', 'executing', 'device_offline', 'resume_ready', 'resumed')
        OR accepted_at_epoch_millis IS NOT NULL
    ),
    CHECK (
        status NOT IN ('executing', 'device_offline', 'resume_ready', 'resumed')
        OR executed_at_epoch_millis IS NOT NULL
    ),
    CHECK ((status = 'cancelled') = (cancelled_at_epoch_millis IS NOT NULL)),
    CHECK (status <> 'failed' OR failure_reason IS NOT NULL),
    CHECK (accepted_at_epoch_millis IS NULL OR accepted_at_epoch_millis >= requested_at_epoch_millis),
    CHECK (executed_at_epoch_millis IS NULL OR executed_at_epoch_millis >= requested_at_epoch_millis),
    CHECK (cancelled_at_epoch_millis IS NULL OR cancelled_at_epoch_millis >= requested_at_epoch_millis)
);

CREATE FUNCTION validate_remote_reboot_request()
RETURNS TRIGGER
LANGUAGE PLPGSQL
AS $$
DECLARE
    session_controller_account_id TEXT;
    session_controller_device_id TEXT;
    session_controlled_device_id TEXT;
    session_policy_evaluation_id TEXT;
    session_permissions_digest BYTEA;
    challenge_account_id TEXT;
    challenge_device_id TEXT;
    challenge_purpose TEXT;
    challenge_status TEXT;
    challenge_verified_at_epoch_millis BIGINT;
BEGIN
    IF TG_OP = 'UPDATE' AND ROW(
        NEW.session_id,
        NEW.controller_account_id,
        NEW.controller_device_id,
        NEW.controlled_device_id,
        NEW.api_request_hash,
        NEW.api_request_hash_status,
        NEW.mode,
        NEW.reason_hash,
        NEW.countdown_seconds,
        NEW.reconnect_after_reboot,
        NEW.allow_remote_reboot,
        NEW.allow_remote_reboot_last_changed_at_epoch_millis,
        NEW.step_up_challenge_id,
        NEW.step_up_verified_at_epoch_millis,
        NEW.step_up_expires_at_epoch_millis,
        NEW.idempotency_key_hash,
        NEW.policy_evaluation_id,
        NEW.policy_evaluated_at_epoch_millis,
        NEW.permissions_digest,
        NEW.permissions_digest_last_changed_at_epoch_millis,
        NEW.created_at_epoch_millis,
        NEW.expires_at_epoch_millis
    ) IS DISTINCT FROM ROW(
        OLD.session_id,
        OLD.controller_account_id,
        OLD.controller_device_id,
        OLD.controlled_device_id,
        OLD.api_request_hash,
        OLD.api_request_hash_status,
        OLD.mode,
        OLD.reason_hash,
        OLD.countdown_seconds,
        OLD.reconnect_after_reboot,
        OLD.allow_remote_reboot,
        OLD.allow_remote_reboot_last_changed_at_epoch_millis,
        OLD.step_up_challenge_id,
        OLD.step_up_verified_at_epoch_millis,
        OLD.step_up_expires_at_epoch_millis,
        OLD.idempotency_key_hash,
        OLD.policy_evaluation_id,
        OLD.policy_evaluated_at_epoch_millis,
        OLD.permissions_digest,
        OLD.permissions_digest_last_changed_at_epoch_millis,
        OLD.created_at_epoch_millis,
        OLD.expires_at_epoch_millis
    ) THEN
        RAISE EXCEPTION 'remote reboot API hash snapshot is immutable';
    END IF;

    IF TG_OP = 'INSERT' THEN
        SELECT controller_account_id, controller_device_id, controlled_device_id,
               policy_evaluation_id, permissions_digest
        INTO session_controller_account_id, session_controller_device_id,
             session_controlled_device_id, session_policy_evaluation_id,
             session_permissions_digest
        FROM sessions
        WHERE session_id = NEW.session_id;

        IF ROW(
            session_controller_account_id,
            session_controller_device_id,
            session_controlled_device_id,
            session_policy_evaluation_id,
            session_permissions_digest
        ) IS DISTINCT FROM ROW(
            NEW.controller_account_id,
            NEW.controller_device_id,
            NEW.controlled_device_id,
            NEW.policy_evaluation_id,
            NEW.permissions_digest
        ) THEN
            RAISE EXCEPTION 'remote reboot request does not match session bindings';
        END IF;

        SELECT account_id, device_id, purpose, status, verified_at_epoch_millis
        INTO challenge_account_id, challenge_device_id, challenge_purpose,
             challenge_status, challenge_verified_at_epoch_millis
        FROM account_risk_challenges
        WHERE risk_challenge_id = NEW.step_up_challenge_id;

        IF challenge_account_id IS DISTINCT FROM NEW.controller_account_id
           OR challenge_device_id IS DISTINCT FROM NEW.controller_device_id
           OR challenge_purpose IS DISTINCT FROM 'remote_reboot'
           OR challenge_status IS DISTINCT FROM 'consumed'
           OR challenge_verified_at_epoch_millis IS DISTINCT FROM NEW.step_up_verified_at_epoch_millis THEN
            RAISE EXCEPTION 'remote reboot step-up challenge binding is invalid';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_remote_reboot_request
BEFORE INSERT OR UPDATE ON remote_reboot_requests
FOR EACH ROW EXECUTE FUNCTION validate_remote_reboot_request();

COMMENT ON COLUMN remote_reboot_requests.api_request_hash_status IS
    'Immutable snapshot of protocol canonical field request_status; allowed values are pending or accepted.';

CREATE UNIQUE INDEX uq_remote_reboot_resume_token_id
    ON remote_reboot_requests(reboot_resume_token_id)
    WHERE reboot_resume_token_id IS NOT NULL;
CREATE INDEX idx_remote_reboot_policy_evaluation ON remote_reboot_requests(policy_evaluation_id);
CREATE INDEX idx_remote_reboot_session_status ON remote_reboot_requests(session_id, status);
CREATE INDEX idx_remote_reboot_history
    ON remote_reboot_requests(
        controller_account_id,
        controller_device_id,
        controlled_device_id,
        created_at_epoch_millis
    );
CREATE INDEX idx_remote_reboot_expiry ON remote_reboot_requests(expires_at_epoch_millis);

CREATE TABLE connection_candidates (
    candidate_id TEXT PRIMARY KEY CHECK (btrim(candidate_id) <> ''),
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE RESTRICT,
    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    role TEXT NOT NULL CHECK (role IN ('controller', 'controlled')),
    kind TEXT NOT NULL CHECK (kind IN ('lan_direct', 'udp_p2p', 'quic_relay', 'tls_443_relay')),
    endpoint TEXT NOT NULL CHECK (btrim(endpoint) <> ''),
    source TEXT NOT NULL CHECK (source IN ('udp_observed', 'local_interface', 'relay_allocated', 'static_config')),
    observe_result_id TEXT CHECK (observe_result_id IS NULL OR btrim(observe_result_id) <> ''),
    priority INTEGER NOT NULL,
    rtt_ms INTEGER CHECK (rtt_ms IS NULL OR rtt_ms >= 0),
    loss_ppm INTEGER CHECK (loss_ppm IS NULL OR loss_ppm BETWEEN 0 AND 1000000),
    jitter_ms INTEGER CHECK (jitter_ms IS NULL OR jitter_ms >= 0),
    relay_node_id TEXT REFERENCES relay_nodes(relay_node_id) ON DELETE RESTRICT,
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    UNIQUE (candidate_id, session_id),
    CHECK (
        (kind = 'lan_direct' AND source = 'local_interface' AND observe_result_id IS NULL AND relay_node_id IS NULL)
        OR (kind = 'udp_p2p' AND source = 'udp_observed' AND observe_result_id IS NOT NULL AND relay_node_id IS NULL)
        OR (kind IN ('quic_relay', 'tls_443_relay') AND source IN ('relay_allocated', 'static_config') AND observe_result_id IS NULL AND relay_node_id IS NOT NULL)
    )
);

CREATE FUNCTION validate_connection_candidate()
RETURNS TRIGGER
LANGUAGE PLPGSQL
AS $$
DECLARE
    session_controller_device_id TEXT;
    session_controlled_device_id TEXT;
BEGIN
    SELECT controller_device_id, controlled_device_id
    INTO session_controller_device_id, session_controlled_device_id
    FROM sessions
    WHERE session_id = NEW.session_id;

    IF (NEW.role = 'controller' AND NEW.device_id IS DISTINCT FROM session_controller_device_id)
       OR (NEW.role = 'controlled' AND NEW.device_id IS DISTINCT FROM session_controlled_device_id) THEN
        RAISE EXCEPTION 'candidate role does not match session device';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_connection_candidate
BEFORE INSERT OR UPDATE OF session_id, device_id, role ON connection_candidates
FOR EACH ROW EXECUTE FUNCTION validate_connection_candidate();

CREATE INDEX idx_connection_candidates_session_role
    ON connection_candidates(session_id, role, priority DESC);
CREATE INDEX idx_connection_candidates_device_session
    ON connection_candidates(device_id, session_id);
CREATE INDEX idx_connection_candidates_relay_node
    ON connection_candidates(relay_node_id) WHERE relay_node_id IS NOT NULL;
CREATE INDEX idx_connection_candidates_observe_result
    ON connection_candidates(observe_result_id) WHERE observe_result_id IS NOT NULL;

CREATE TABLE connection_candidate_pairs (
    candidate_pair_id TEXT PRIMARY KEY CHECK (btrim(candidate_pair_id) <> ''),
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE RESTRICT,
    controller_candidate_id TEXT NOT NULL,
    controlled_candidate_id TEXT NOT NULL,
    selected_transport_path TEXT NOT NULL CHECK (
        selected_transport_path IN ('lan_direct', 'udp_p2p', 'quic_relay', 'tls_443_relay')
    ),
    relay_node_id TEXT REFERENCES relay_nodes(relay_node_id) ON DELETE RESTRICT,
    selected_at_epoch_millis BIGINT,
    rtt_ms INTEGER CHECK (rtt_ms IS NULL OR rtt_ms >= 0),
    loss_ppm INTEGER CHECK (loss_ppm IS NULL OR loss_ppm BETWEEN 0 AND 1000000),
    jitter_ms INTEGER CHECK (jitter_ms IS NULL OR jitter_ms >= 0),
    status TEXT NOT NULL CHECK (status IN ('probing', 'selected', 'degraded', 'closed')),
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    UNIQUE (candidate_pair_id, session_id),
    FOREIGN KEY (controller_candidate_id, session_id)
        REFERENCES connection_candidates(candidate_id, session_id) ON DELETE RESTRICT,
    FOREIGN KEY (controlled_candidate_id, session_id)
        REFERENCES connection_candidates(candidate_id, session_id) ON DELETE RESTRICT,
    CHECK (controller_candidate_id <> controlled_candidate_id),
    CHECK (
        (selected_transport_path IN ('quic_relay', 'tls_443_relay') AND relay_node_id IS NOT NULL)
        OR (selected_transport_path IN ('lan_direct', 'udp_p2p') AND relay_node_id IS NULL)
    ),
    CHECK (selected_at_epoch_millis IS NULL OR selected_at_epoch_millis >= created_at_epoch_millis),
    CHECK (status <> 'selected' OR selected_at_epoch_millis IS NOT NULL)
);

CREATE FUNCTION validate_candidate_pair()
RETURNS TRIGGER
LANGUAGE PLPGSQL
AS $$
DECLARE
    controller_role TEXT;
    controlled_role TEXT;
    controller_kind TEXT;
    controlled_kind TEXT;
    controller_relay_node_id TEXT;
    controlled_relay_node_id TEXT;
BEGIN
    SELECT role, kind, relay_node_id
    INTO controller_role, controller_kind, controller_relay_node_id
    FROM connection_candidates
    WHERE candidate_id = NEW.controller_candidate_id AND session_id = NEW.session_id;

    SELECT role, kind, relay_node_id
    INTO controlled_role, controlled_kind, controlled_relay_node_id
    FROM connection_candidates
    WHERE candidate_id = NEW.controlled_candidate_id AND session_id = NEW.session_id;

    IF controller_role IS DISTINCT FROM 'controller' OR controlled_role IS DISTINCT FROM 'controlled' THEN
        RAISE EXCEPTION 'candidate pair roles do not match controller/controlled';
    END IF;

    IF controller_kind IS DISTINCT FROM NEW.selected_transport_path
       OR controlled_kind IS DISTINCT FROM NEW.selected_transport_path THEN
        RAISE EXCEPTION 'candidate pair transport does not match candidate kinds';
    END IF;

    IF NEW.relay_node_id IS NOT NULL
       AND (controller_relay_node_id IS DISTINCT FROM NEW.relay_node_id
            OR controlled_relay_node_id IS DISTINCT FROM NEW.relay_node_id) THEN
        RAISE EXCEPTION 'candidate pair relay node does not match candidates';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_candidate_pair
BEFORE INSERT OR UPDATE ON connection_candidate_pairs
FOR EACH ROW EXECUTE FUNCTION validate_candidate_pair();

CREATE INDEX idx_connection_candidate_pairs_session_status
    ON connection_candidate_pairs(session_id, status, selected_at_epoch_millis);
CREATE INDEX idx_connection_candidate_pairs_relay_node
    ON connection_candidate_pairs(relay_node_id) WHERE relay_node_id IS NOT NULL;

ALTER TABLE sessions
    ADD CONSTRAINT fk_sessions_selected_candidate_pair
    FOREIGN KEY (selected_candidate_pair_id, session_id)
    REFERENCES connection_candidate_pairs(candidate_pair_id, session_id)
    ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE FUNCTION validate_session_bindings()
RETURNS TRIGGER
LANGUAGE PLPGSQL
AS $$
DECLARE
    evaluation_account_id TEXT;
    evaluation_controller_device_id TEXT;
    evaluation_controlled_device_id TEXT;
    evaluation_session_id TEXT;
    pair_transport_path TEXT;
    pair_relay_node_id TEXT;
    pair_status TEXT;
BEGIN
    SELECT account_id, controller_device_id, controlled_device_id, session_id
    INTO evaluation_account_id, evaluation_controller_device_id,
         evaluation_controlled_device_id, evaluation_session_id
    FROM policy_evaluations
    WHERE policy_evaluation_id = NEW.policy_evaluation_id;

    IF ROW(
        evaluation_account_id,
        evaluation_controller_device_id,
        evaluation_controlled_device_id,
        evaluation_session_id
    ) IS DISTINCT FROM ROW(
        NEW.controller_account_id,
        NEW.controller_device_id,
        NEW.controlled_device_id,
        NEW.session_id
    ) THEN
        RAISE EXCEPTION 'session does not match policy evaluation bindings';
    END IF;

    IF NEW.selected_candidate_pair_id IS NOT NULL THEN
        SELECT selected_transport_path, relay_node_id, status
        INTO pair_transport_path, pair_relay_node_id, pair_status
        FROM connection_candidate_pairs
        WHERE candidate_pair_id = NEW.selected_candidate_pair_id
          AND session_id = NEW.session_id;

        IF pair_transport_path IS DISTINCT FROM NEW.transport_path
           OR pair_relay_node_id IS DISTINCT FROM NEW.relay_node_id
           OR pair_status NOT IN ('selected', 'degraded') THEN
            RAISE EXCEPTION 'session selected path does not match candidate pair';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_session_bindings
BEFORE INSERT OR UPDATE OF controller_account_id, controller_device_id,
    controlled_device_id, policy_evaluation_id, transport_path,
    selected_candidate_pair_id, relay_node_id ON sessions
FOR EACH ROW EXECUTE FUNCTION validate_session_bindings();

CREATE INDEX idx_sessions_selected_candidate_pair
    ON sessions(selected_candidate_pair_id) WHERE selected_candidate_pair_id IS NOT NULL;

CREATE TABLE session_events (
    event_id TEXT PRIMARY KEY CHECK (btrim(event_id) <> ''),
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE RESTRICT,
    event_type TEXT NOT NULL CHECK (
        event_type IN (
            'invite_created',
            'invite_accepted',
            'invite_rejected',
            'code_verified',
            'unattended_verified',
            'waiting_approval',
            'cancelled',
            'candidate_exchanged',
            'candidate_pair_selected',
            'transport_selected',
            'key_exchange_started',
            'key_exchange_completed',
            'key_exchange_failed',
            'reboot_requested',
            'reboot_accepted',
            'reboot_cancelled',
            'reboot_started',
            'reboot_resume_ready',
            'reboot_resumed',
            'reboot_failed',
            'connected',
            'degraded',
            'reconnecting',
            'closed',
            'failed'
        )
    ),
    actor_type TEXT NOT NULL CHECK (actor_type IN ('anonymous', 'account', 'device', 'service', 'system')),
    actor_account_id TEXT REFERENCES accounts(account_id) ON DELETE RESTRICT,
    actor_device_id TEXT REFERENCES devices(device_id) ON DELETE RESTRICT,
    actor_role TEXT NOT NULL DEFAULT 'none' CHECK (actor_role IN ('controller', 'controlled', 'none')),
    actor_service TEXT CHECK (
        actor_service IS NULL
        OR actor_service IN ('api_server', 'signal_server', 'relay_server', 'release_checker', 'scheduler')
    ),
    reason TEXT CHECK (reason IS NULL OR btrim(reason) <> ''),
    metadata JSONB NOT NULL DEFAULT '{}'::JSONB CHECK (jsonb_typeof(metadata) = 'object'),
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    CHECK (
        (actor_type = 'anonymous' AND actor_account_id IS NULL AND actor_device_id IS NULL AND actor_role = 'none' AND actor_service IS NULL)
        OR (actor_type = 'account' AND actor_account_id IS NOT NULL AND actor_device_id IS NULL AND actor_role = 'none' AND actor_service IS NULL)
        OR (actor_type = 'device' AND actor_account_id IS NOT NULL AND actor_device_id IS NOT NULL AND actor_role IN ('controller', 'controlled') AND actor_service IS NULL)
        OR (actor_type = 'service' AND actor_account_id IS NULL AND actor_device_id IS NULL AND actor_role = 'none' AND actor_service IS NOT NULL)
        OR (actor_type = 'system' AND actor_account_id IS NULL AND actor_device_id IS NULL AND actor_role = 'none' AND actor_service IS NULL)
    )
);

CREATE INDEX idx_session_events_session_time ON session_events(session_id, created_at_epoch_millis);
CREATE INDEX idx_session_events_type_time ON session_events(event_type, created_at_epoch_millis);

CREATE TABLE relay_session_stats (
    relay_session_stat_id TEXT PRIMARY KEY CHECK (btrim(relay_session_stat_id) <> ''),
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE RESTRICT,
    relay_node_id TEXT NOT NULL REFERENCES relay_nodes(relay_node_id) ON DELETE RESTRICT,
    region TEXT NOT NULL CHECK (btrim(region) <> ''),
    region_policy_id TEXT,
    region_policy_version BIGINT CHECK (region_policy_version IS NULL OR region_policy_version >= 1),
    transport TEXT NOT NULL CHECK (transport IN ('quic_relay', 'tls_443_relay')),
    bytes_in BIGINT NOT NULL DEFAULT 0 CHECK (bytes_in >= 0),
    bytes_out BIGINT NOT NULL DEFAULT 0 CHECK (bytes_out >= 0),
    rtt_ms INTEGER CHECK (rtt_ms IS NULL OR rtt_ms >= 0),
    loss_ppm INTEGER CHECK (loss_ppm IS NULL OR loss_ppm BETWEEN 0 AND 1000000),
    started_at_epoch_millis BIGINT NOT NULL CHECK (started_at_epoch_millis >= 0),
    ended_at_epoch_millis BIGINT,
    disconnect_reason TEXT CHECK (disconnect_reason IS NULL OR btrim(disconnect_reason) <> ''),
    CHECK ((region_policy_id IS NULL) = (region_policy_version IS NULL)),
    CHECK (ended_at_epoch_millis IS NULL OR ended_at_epoch_millis >= started_at_epoch_millis)
);

CREATE INDEX idx_relay_session_stats_session ON relay_session_stats(session_id, started_at_epoch_millis);
CREATE INDEX idx_relay_session_stats_node_time ON relay_session_stats(relay_node_id, started_at_epoch_millis);
CREATE INDEX idx_relay_session_stats_region_time ON relay_session_stats(region, started_at_epoch_millis);

CREATE TABLE file_transfers (
    file_transfer_id TEXT PRIMARY KEY CHECK (btrim(file_transfer_id) <> ''),
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE RESTRICT,
    sender_device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    receiver_device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    direction TEXT NOT NULL CHECK (direction IN ('controller_to_controlled', 'controlled_to_controller')),
    file_name TEXT NOT NULL CHECK (
        btrim(file_name) <> ''
        AND file_name !~ '[\\/]'
        AND file_name !~ '[[:cntrl:]]'
    ),
    safe_file_name TEXT CHECK (
        safe_file_name IS NULL
        OR (
            btrim(safe_file_name) <> ''
            AND safe_file_name !~ '[\\/]'
            AND safe_file_name !~ '[[:cntrl:]]'
        )
    ),
    file_size_bytes BIGINT NOT NULL CHECK (file_size_bytes BETWEEN 0 AND 104857600),
    sha256 BYTEA NOT NULL CHECK (octet_length(sha256) = 32),
    status TEXT NOT NULL CHECK (status IN ('requested', 'accepted', 'rejected', 'transferring', 'completed', 'failed', 'cancelled')),
    confirmed_by_controlled BOOLEAN NOT NULL DEFAULT FALSE,
    confirmed_by_device_id TEXT REFERENCES devices(device_id) ON DELETE RESTRICT,
    confirmed_at_epoch_millis BIGINT,
    receiver_save_policy TEXT NOT NULL DEFAULT 'save_as_new' CHECK (
        receiver_save_policy IN ('save_as_new', 'overwrite_confirmed', 'reject_conflict')
    ),
    temporary_path_hash BYTEA CHECK (temporary_path_hash IS NULL OR octet_length(temporary_path_hash) = 32),
    final_path_hash BYTEA CHECK (final_path_hash IS NULL OR octet_length(final_path_hash) = 32),
    bytes_transferred BIGINT NOT NULL DEFAULT 0 CHECK (bytes_transferred >= 0 AND bytes_transferred <= file_size_bytes),
    cancelled_by_device_id TEXT REFERENCES devices(device_id) ON DELETE RESTRICT,
    cancelled_at_epoch_millis BIGINT,
    started_at_epoch_millis BIGINT,
    ended_at_epoch_millis BIGINT,
    failure_reason TEXT CHECK (
        failure_reason IS NULL
        OR failure_reason IN (
            'permission_denied',
            'hash_mismatch',
            'session_closed',
            'receiver_rejected',
            'storage_unavailable',
            'timeout',
            'sender_cancelled',
            'controlled_rejected',
            'size_exceeded',
            'path_traversal',
            'invalid_file_name',
            'symlink_rejected',
            'insufficient_space',
            'write_permission_denied',
            'temporary_cleanup_failed'
        )
    ),
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    updated_at_epoch_millis BIGINT NOT NULL CHECK (updated_at_epoch_millis >= created_at_epoch_millis),
    CHECK (sender_device_id <> receiver_device_id),
    CHECK (
        (confirmed_by_controlled AND confirmed_by_device_id IS NOT NULL AND confirmed_at_epoch_millis IS NOT NULL)
        OR (NOT confirmed_by_controlled AND confirmed_by_device_id IS NULL AND confirmed_at_epoch_millis IS NULL)
    ),
    CHECK (
        (status = 'cancelled' AND cancelled_by_device_id IS NOT NULL AND cancelled_at_epoch_millis IS NOT NULL)
        OR (status <> 'cancelled' AND cancelled_by_device_id IS NULL AND cancelled_at_epoch_millis IS NULL)
    ),
    CHECK (started_at_epoch_millis IS NULL OR started_at_epoch_millis >= created_at_epoch_millis),
    CHECK (ended_at_epoch_millis IS NULL OR ended_at_epoch_millis >= created_at_epoch_millis),
    CHECK (status <> 'completed' OR (bytes_transferred = file_size_bytes AND ended_at_epoch_millis IS NOT NULL)),
    CHECK (status NOT IN ('failed', 'rejected', 'cancelled') OR failure_reason IS NOT NULL)
);

CREATE FUNCTION validate_file_transfer()
RETURNS TRIGGER
LANGUAGE PLPGSQL
AS $$
DECLARE
    session_controller_device_id TEXT;
    session_controlled_device_id TEXT;
BEGIN
    SELECT controller_device_id, controlled_device_id
    INTO session_controller_device_id, session_controlled_device_id
    FROM sessions
    WHERE session_id = NEW.session_id;

    IF NEW.direction = 'controller_to_controlled'
       AND (NEW.sender_device_id IS DISTINCT FROM session_controller_device_id
            OR NEW.receiver_device_id IS DISTINCT FROM session_controlled_device_id) THEN
        RAISE EXCEPTION 'file transfer direction does not match session roles';
    END IF;

    IF NEW.direction = 'controlled_to_controller'
       AND (NEW.sender_device_id IS DISTINCT FROM session_controlled_device_id
            OR NEW.receiver_device_id IS DISTINCT FROM session_controller_device_id) THEN
        RAISE EXCEPTION 'file transfer direction does not match session roles';
    END IF;

    IF NEW.confirmed_by_controlled
       AND NEW.confirmed_by_device_id IS DISTINCT FROM session_controlled_device_id THEN
        RAISE EXCEPTION 'file transfer confirmation must be attributed to controlled device';
    END IF;

    IF NEW.cancelled_by_device_id IS NOT NULL
       AND NEW.cancelled_by_device_id NOT IN (session_controller_device_id, session_controlled_device_id) THEN
        RAISE EXCEPTION 'file transfer cancellation actor is not part of session';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_validate_file_transfer
BEFORE INSERT OR UPDATE ON file_transfers
FOR EACH ROW EXECUTE FUNCTION validate_file_transfer();

CREATE INDEX idx_file_transfers_session_status ON file_transfers(session_id, status, created_at_epoch_millis);
CREATE INDEX idx_file_transfers_sender_time ON file_transfers(sender_device_id, created_at_epoch_millis);
CREATE INDEX idx_file_transfers_receiver_time ON file_transfers(receiver_device_id, created_at_epoch_millis);

CREATE TABLE client_release_channels (
    release_channel_id TEXT PRIMARY KEY CHECK (btrim(release_channel_id) <> ''),
    channel TEXT NOT NULL CHECK (channel IN ('stable', 'beta', 'internal', 'private')),
    scope_type TEXT NOT NULL CHECK (scope_type IN ('official', 'organization')),
    scope_id TEXT REFERENCES organizations(organization_id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    release_public_key_id TEXT NOT NULL CHECK (btrim(release_public_key_id) <> ''),
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    updated_at_epoch_millis BIGINT NOT NULL CHECK (updated_at_epoch_millis >= created_at_epoch_millis),
    UNIQUE (channel, scope_type, scope_id),
    CHECK (
        (scope_type = 'official' AND scope_id IS NULL AND channel IN ('stable', 'beta', 'internal'))
        OR (scope_type = 'organization' AND scope_id IS NOT NULL AND channel = 'private')
    )
);

CREATE INDEX idx_client_release_channels_lookup
    ON client_release_channels(scope_type, scope_id, channel, status);

CREATE TABLE client_release_artifacts (
    artifact_id TEXT PRIMARY KEY CHECK (btrim(artifact_id) <> ''),
    release_channel_id TEXT NOT NULL REFERENCES client_release_channels(release_channel_id) ON DELETE RESTRICT,
    version TEXT NOT NULL CHECK (btrim(version) <> ''),
    build_number BIGINT NOT NULL CHECK (build_number >= 0),
    platform TEXT NOT NULL CHECK (platform IN ('windows', 'ubuntu', 'ios')),
    arch TEXT NOT NULL CHECK (arch IN ('x86_64', 'aarch64')),
    artifact_url TEXT NOT NULL CHECK (artifact_url ~ '^https://'),
    storage_location_id TEXT,
    artifact_sha256 BYTEA NOT NULL CHECK (octet_length(artifact_sha256) = 32),
    artifact_size_bytes BIGINT NOT NULL CHECK (artifact_size_bytes > 0),
    manifest_version INTEGER NOT NULL CHECK (manifest_version >= 1),
    min_supported_version TEXT NOT NULL CHECK (btrim(min_supported_version) <> ''),
    rollout_percent SMALLINT NOT NULL CHECK (rollout_percent BETWEEN 0 AND 100),
    mandatory BOOLEAN NOT NULL DEFAULT FALSE,
    release_notes_url TEXT CHECK (release_notes_url IS NULL OR release_notes_url ~ '^https://'),
    manifest_expires_at_epoch_millis BIGINT NOT NULL,
    manifest_signature BYTEA NOT NULL CHECK (octet_length(manifest_signature) = 64),
    sbom_url TEXT NOT NULL CHECK (sbom_url ~ '^https://'),
    status TEXT NOT NULL CHECK (status IN ('draft', 'published', 'revoked')),
    published_by_actor_type TEXT CHECK (
        published_by_actor_type IS NULL OR published_by_actor_type IN ('account', 'service')
    ),
    published_by_account_id TEXT REFERENCES accounts(account_id) ON DELETE RESTRICT,
    published_by_service TEXT CHECK (published_by_service IS NULL OR btrim(published_by_service) <> ''),
    published_at_epoch_millis BIGINT,
    revoked_at_epoch_millis BIGINT,
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    updated_at_epoch_millis BIGINT NOT NULL CHECK (updated_at_epoch_millis >= created_at_epoch_millis),
    UNIQUE (release_channel_id, version, build_number, platform, arch),
    CHECK (manifest_expires_at_epoch_millis > created_at_epoch_millis),
    CHECK (
        (published_by_actor_type IS NULL AND published_by_account_id IS NULL AND published_by_service IS NULL)
        OR (published_by_actor_type = 'account' AND published_by_account_id IS NOT NULL AND published_by_service IS NULL)
        OR (published_by_actor_type = 'service' AND published_by_account_id IS NULL AND published_by_service IS NOT NULL)
    ),
    CHECK (status = 'draft' OR (published_by_actor_type IS NOT NULL AND published_at_epoch_millis IS NOT NULL)),
    CHECK (status <> 'revoked' OR revoked_at_epoch_millis IS NOT NULL)
);

CREATE INDEX idx_client_release_artifacts_latest
    ON client_release_artifacts(release_channel_id, platform, arch, status, published_at_epoch_millis DESC);
CREATE INDEX idx_client_release_artifacts_sha256 ON client_release_artifacts(artifact_sha256);

CREATE TABLE client_update_checks (
    update_check_id TEXT PRIMARY KEY CHECK (btrim(update_check_id) <> ''),
    account_id TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE RESTRICT,
    device_id TEXT NOT NULL REFERENCES devices(device_id) ON DELETE RESTRICT,
    platform TEXT NOT NULL CHECK (platform IN ('windows', 'ubuntu', 'ios')),
    arch TEXT NOT NULL CHECK (arch IN ('x86_64', 'aarch64')),
    current_version TEXT NOT NULL CHECK (btrim(current_version) <> ''),
    channel TEXT NOT NULL CHECK (channel IN ('stable', 'beta', 'internal', 'private')),
    event_type TEXT NOT NULL CHECK (event_type IN ('checked', 'downloaded', 'verified', 'failed')),
    result TEXT NOT NULL CHECK (btrim(result) <> ''),
    artifact_id TEXT REFERENCES client_release_artifacts(artifact_id) ON DELETE RESTRICT,
    manifest_signature_valid BOOLEAN,
    artifact_hash_valid BOOLEAN,
    platform_signature_valid BOOLEAN,
    failure_reason TEXT CHECK (failure_reason IS NULL OR btrim(failure_reason) <> ''),
    checked_at_epoch_millis BIGINT NOT NULL CHECK (checked_at_epoch_millis >= 0),
    downloaded_at_epoch_millis BIGINT,
    verified_at_epoch_millis BIGINT,
    failed_at_epoch_millis BIGINT,
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    CHECK (event_type <> 'downloaded' OR downloaded_at_epoch_millis IS NOT NULL),
    CHECK (
        event_type <> 'verified'
        OR (
            verified_at_epoch_millis IS NOT NULL
            AND manifest_signature_valid IS TRUE
            AND artifact_hash_valid IS TRUE
            AND platform_signature_valid IS TRUE
        )
    ),
    CHECK (event_type <> 'failed' OR (failed_at_epoch_millis IS NOT NULL AND failure_reason IS NOT NULL))
);

CREATE INDEX idx_client_update_checks_device_time
    ON client_update_checks(device_id, created_at_epoch_millis);
CREATE INDEX idx_client_update_checks_artifact_event
    ON client_update_checks(artifact_id, event_type, created_at_epoch_millis);

CREATE TABLE audit_logs (
    audit_id TEXT PRIMARY KEY CHECK (btrim(audit_id) <> ''),
    actor_type TEXT NOT NULL CHECK (actor_type IN ('anonymous', 'account', 'device', 'service', 'system')),
    actor_account_id TEXT REFERENCES accounts(account_id) ON DELETE RESTRICT,
    actor_device_id TEXT REFERENCES devices(device_id) ON DELETE RESTRICT,
    actor_role TEXT NOT NULL DEFAULT 'none' CHECK (actor_role IN ('controller', 'controlled', 'none')),
    actor_service TEXT CHECK (
        actor_service IS NULL
        OR actor_service IN ('api_server', 'signal_server', 'relay_server', 'release_checker', 'scheduler')
    ),
    target_device_id TEXT REFERENCES devices(device_id) ON DELETE RESTRICT,
    session_id TEXT REFERENCES sessions(session_id) ON DELETE RESTRICT,
    resource_type TEXT CHECK (resource_type IS NULL OR btrim(resource_type) <> ''),
    resource_id TEXT CHECK (resource_id IS NULL OR btrim(resource_id) <> ''),
    action TEXT NOT NULL CHECK (
        action IN (
            'login_succeeded',
            'login_failed',
            'logout',
            'token_refreshed',
            'password_changed',
            'account_locked',
            'account_unlocked',
            'account_disabled',
            'account_session_revoked',
            'device_enrollment_grant_consumed',
            'mfa_factor_enrolled',
            'mfa_factor_disabled',
            'mfa_recovery_codes_rotated',
            'mfa_recovery_code_used',
            'mfa_challenge_issued',
            'mfa_challenge_succeeded',
            'mfa_challenge_failed',
            'risk_challenge_issued',
            'risk_challenge_succeeded',
            'risk_challenge_failed',
            'step_up_revalidated',
            'trusted_device_added',
            'trusted_device_revoked',
            'abuse_report_created',
            'abuse_case_opened',
            'abuse_case_updated',
            'abuse_case_closed',
            'abuse_risk_evaluated',
            'abuse_warning_shown',
            'abuse_enforcement_applied',
            'abuse_enforcement_revoked',
            'session_rate_limited',
            'verification_code_rate_limited',
            'unattended_rate_limited',
            'relay_rate_limited',
            'device_registered',
            'device_unregistered',
            'device_public_key_rotated',
            'device_public_key_revoked',
            'device_status_changed',
            'device_policy_updated',
            'device_access_rule_updated',
            'verification_code_created',
            'verification_code_challenge_issued',
            'verification_code_failed',
            'verification_code_consumed',
            'session_invited',
            'session_accepted',
            'session_rejected',
            'session_cancelled',
            'session_connected',
            'session_degraded',
            'session_reconnecting',
            'session_ended',
            'session_failed',
            'key_exchange_failed',
            'transport_selected',
            'relay_allocated',
            'relay_token_rejected',
            'candidate_pair_selected',
            'clipboard_permission_requested',
            'clipboard_permission_accepted',
            'clipboard_permission_rejected',
            'file_transfer_requested',
            'file_transfer_accepted',
            'file_transfer_rejected',
            'file_transfer_started',
            'file_transfer_ended',
            'file_transfer_failed',
            'file_transfer_cancelled',
            'clipboard_used',
            'unattended_enabled',
            'unattended_challenge_issued',
            'unattended_auth_succeeded',
            'unattended_auth_failed',
            'unattended_disabled',
            'unattended_rotated',
            'privacy_screen_requested',
            'privacy_screen_enabled',
            'privacy_screen_disabled',
            'privacy_screen_failed',
            'local_input_block_requested',
            'local_input_block_enabled',
            'local_input_block_disabled',
            'local_input_block_failed',
            'local_input_restored',
            'media_capability_reported',
            'media_quality_changed',
            'media_keyframe_requested',
            'remote_reboot_requested',
            'remote_reboot_prompt_shown',
            'remote_reboot_accepted',
            'remote_reboot_cancelled',
            'remote_reboot_started',
            'remote_reboot_device_offline',
            'remote_reboot_device_online',
            'remote_reboot_resume_ready',
            'remote_reboot_resumed',
            'remote_reboot_failed',
            'remote_reboot_expired',
            'remote_reboot_auto_resume_consent_granted',
            'remote_reboot_auto_resume_consent_used',
            'remote_reboot_auto_resume_consent_revoked',
            'access_policy_created',
            'access_policy_updated',
            'access_policy_deleted',
            'access_policy_assigned',
            'access_policy_unassigned',
            'access_policy_evaluated',
            'access_policy_denied',
            'organization_policy_updated',
            'device_group_policy_updated',
            'role_permissions_updated',
            'client_update_checked',
            'client_update_downloaded',
            'client_update_verified',
            'client_update_failed',
            'client_release_published',
            'client_release_revoked',
            'client_release_rollout_updated',
            'region_policy_created',
            'region_policy_updated',
            'region_policy_evaluated',
            'region_policy_denied',
            'relay_region_selected',
            'relay_region_denied',
            'object_storage_region_selected',
            'data_residency_violation_detected'
        )
    ),
    result TEXT NOT NULL CHECK (result IN ('success', 'failure', 'denied', 'pending')),
    reason TEXT CHECK (reason IS NULL OR btrim(reason) <> ''),
    metadata JSONB NOT NULL DEFAULT '{}'::JSONB CHECK (jsonb_typeof(metadata) = 'object'),
    actor_account_snapshot JSONB CHECK (actor_account_snapshot IS NULL OR jsonb_typeof(actor_account_snapshot) = 'object'),
    actor_device_snapshot JSONB CHECK (actor_device_snapshot IS NULL OR jsonb_typeof(actor_device_snapshot) = 'object'),
    target_device_snapshot JSONB CHECK (target_device_snapshot IS NULL OR jsonb_typeof(target_device_snapshot) = 'object'),
    ip_address INET,
    user_agent TEXT,
    request_id TEXT CHECK (request_id IS NULL OR btrim(request_id) <> ''),
    created_at_epoch_millis BIGINT NOT NULL CHECK (created_at_epoch_millis >= 0),
    CHECK (
        (actor_type = 'anonymous' AND actor_account_id IS NULL AND actor_device_id IS NULL AND actor_role = 'none' AND actor_service IS NULL)
        OR (actor_type = 'account' AND actor_account_id IS NOT NULL AND actor_device_id IS NULL AND actor_role = 'none' AND actor_service IS NULL)
        OR (actor_type = 'device' AND actor_account_id IS NOT NULL AND actor_device_id IS NOT NULL AND actor_service IS NULL)
        OR (actor_type = 'service' AND actor_account_id IS NULL AND actor_device_id IS NULL AND actor_role = 'none' AND actor_service IS NOT NULL)
        OR (actor_type = 'system' AND actor_account_id IS NULL AND actor_device_id IS NULL AND actor_role = 'none' AND actor_service IS NULL)
    )
);

CREATE INDEX idx_audit_logs_actor_account_time ON audit_logs(actor_account_id, created_at_epoch_millis);
CREATE INDEX idx_audit_logs_actor_device_time ON audit_logs(actor_device_id, created_at_epoch_millis);
CREATE INDEX idx_audit_logs_target_device_time ON audit_logs(target_device_id, created_at_epoch_millis);
CREATE INDEX idx_audit_logs_session_time ON audit_logs(session_id, created_at_epoch_millis);
CREATE INDEX idx_audit_logs_resource_time ON audit_logs(resource_type, resource_id, created_at_epoch_millis);
CREATE INDEX idx_audit_logs_action_time ON audit_logs(action, created_at_epoch_millis);
CREATE INDEX idx_audit_logs_request_id ON audit_logs(request_id) WHERE request_id IS NOT NULL;

COMMIT;
