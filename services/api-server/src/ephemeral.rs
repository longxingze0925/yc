use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

use crate::model::{AuthChallenge, ChallengePurpose};
use crate::security::{canonical_fields, random_uuid_v4, sha256_hex};

const KEY_PREFIX: &str = "rctl:api:v1";
const SIGNAL_KEY_PREFIX: &str = "rctl:signal:v1";
const ATTEMPT_LEASE_MILLIS: u64 = 30_000;
const PENDING_TOTP_ENVELOPE_VERSION: u8 = 2;
const PENDING_TOTP_NONCE_BYTES: usize = 12;
const REDIS_CONNECTION_TIMEOUT: Duration = Duration::from_secs(3);
const REDIS_RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);
const REDIS_CONNECTION_RETRIES: usize = 3;

const PUT_CHALLENGE_SCRIPT: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 1 then
    return 0
end
redis.call(
    'HSET', KEYS[1],
    'payload', ARGV[1],
    'kind', ARGV[2],
    'status', 'issued',
    'attempts_remaining', ARGV[3],
    'expires_at_epoch_millis', ARGV[4],
    'account_id', ARGV[5],
    'device_id', ARGV[6],
    'purpose', ARGV[7],
    'operation_binding_hash', ARGV[8]
)
redis.call('PEXPIREAT', KEYS[1], ARGV[4])
return 1
"#;

const BEGIN_CHALLENGE_ATTEMPT_SCRIPT: &str = r#"
local payload = redis.call('HGET', KEYS[1], 'payload')
if not payload then
    return cjson.encode({code = 'rejected'})
end
local expires_at = tonumber(redis.call('HGET', KEYS[1], 'expires_at_epoch_millis'))
if not expires_at or expires_at <= tonumber(ARGV[1]) then
    redis.call('DEL', KEYS[1])
    return cjson.encode({code = 'rejected', payload = payload})
end
local status = redis.call('HGET', KEYS[1], 'status')
local kind = redis.call('HGET', KEYS[1], 'kind')
local attempts = tonumber(redis.call('HGET', KEYS[1], 'attempts_remaining')) or 0
if status ~= 'issued' or kind ~= ARGV[2] or attempts <= 0 then
    return cjson.encode({code = 'rejected', payload = payload})
end
local lease_until = tonumber(redis.call('HGET', KEYS[1], 'lease_until_epoch_millis')) or 0
if lease_until > tonumber(ARGV[1]) then
    return cjson.encode({code = 'rejected', payload = payload})
end
redis.call(
    'HSET', KEYS[1],
    'lease_token', ARGV[3],
    'lease_until_epoch_millis', ARGV[4]
)
return cjson.encode({code = 'started', payload = payload})
"#;

const FINISH_CHALLENGE_ATTEMPT_SCRIPT: &str = r#"
local lease_token = redis.call('HGET', KEYS[1], 'lease_token')
local status = redis.call('HGET', KEYS[1], 'status')
if not lease_token or lease_token ~= ARGV[1] or status ~= 'issued' then
    return -1
end
local attempts = tonumber(redis.call('HGET', KEYS[1], 'attempts_remaining')) or 0
if ARGV[2] == '1' then
    if ARGV[3] == '1' then
        redis.call(
            'HSET', KEYS[1],
            'status', 'consumed',
            'verified_at_epoch_millis', ARGV[4],
            'consumed_at_epoch_millis', ARGV[4]
        )
    else
        redis.call(
            'HSET', KEYS[1],
            'status', 'verified',
            'verified_at_epoch_millis', ARGV[4]
        )
    end
else
    attempts = math.max(0, attempts - 1)
    redis.call('HSET', KEYS[1], 'attempts_remaining', attempts)
    if attempts == 0 then
        redis.call('HSET', KEYS[1], 'status', 'failed')
    end
end
redis.call('HDEL', KEYS[1], 'lease_token', 'lease_until_epoch_millis')
return attempts
"#;

const ABORT_CHALLENGE_ATTEMPT_SCRIPT: &str = r#"
local lease_token = redis.call('HGET', KEYS[1], 'lease_token')
if not lease_token or lease_token ~= ARGV[1] then
    return 0
end
redis.call('HDEL', KEYS[1], 'lease_token', 'lease_until_epoch_millis')
return 1
"#;

const CONSUME_STEP_UP_SCRIPT: &str = r#"
local expires_at = tonumber(redis.call('HGET', KEYS[1], 'expires_at_epoch_millis'))
if not expires_at or expires_at <= tonumber(ARGV[1]) then
    redis.call('DEL', KEYS[1])
    return 0
end
if redis.call('HGET', KEYS[1], 'status') ~= 'verified'
    or redis.call('HGET', KEYS[1], 'kind') ~= 'step_up'
    or redis.call('HGET', KEYS[1], 'account_id') ~= ARGV[2]
    or redis.call('HGET', KEYS[1], 'device_id') ~= ARGV[3]
    or redis.call('HGET', KEYS[1], 'purpose') ~= ARGV[4]
    or redis.call('HGET', KEYS[1], 'operation_binding_hash') ~= ARGV[5] then
    return 0
end
redis.call(
    'HSET', KEYS[1],
    'status', 'consumed',
    'consumed_at_epoch_millis', ARGV[1]
)
return 1
"#;

const RECORD_LOGIN_FAILURE_SCRIPT: &str = r#"
local now = tonumber(ARGV[1])
local attempts = tonumber(redis.call('HGET', KEYS[1], 'attempts')) or 0
local locked_until = tonumber(redis.call('HGET', KEYS[1], 'locked_until_epoch_millis')) or 0
if locked_until > now then
    redis.call('PEXPIRE', KEYS[1], ARGV[4])
    return {attempts, locked_until, 0}
end
if locked_until > 0 then
    attempts = 0
    locked_until = 0
end
attempts = attempts + 1
local newly_locked = 0
if attempts >= tonumber(ARGV[2]) then
    attempts = 0
    locked_until = now + tonumber(ARGV[3])
    newly_locked = 1
end
redis.call(
    'HSET', KEYS[1],
    'attempts', attempts,
    'locked_until_epoch_millis', locked_until
)
redis.call('PEXPIRE', KEYS[1], ARGV[4])
return {attempts, locked_until, newly_locked}
"#;

const PUT_PENDING_TOTP_ENROLLMENT_SCRIPT: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 1 then
    local existing_account_id = redis.call('HGET', KEYS[1], 'account_id')
    local existing_expires_at = tonumber(
        redis.call('HGET', KEYS[1], 'expires_at_epoch_millis')
    )
    if not existing_account_id or not existing_expires_at then
        return -1
    end
    if existing_account_id ~= ARGV[1] then
        return -1
    end
    if existing_expires_at > tonumber(ARGV[7]) then
        return 0
    end
    redis.call('DEL', KEYS[1])
end
redis.call(
    'HSET', KEYS[1],
    'account_id', ARGV[1],
    'factor_id', ARGV[2],
    'encrypted_payload', ARGV[3],
    'created_at_epoch_millis', ARGV[4],
    'attempts_remaining', ARGV[5],
    'expires_at_epoch_millis', ARGV[6]
)
redis.call('HDEL', KEYS[1], 'lease_token', 'lease_until_epoch_millis')
redis.call('PEXPIREAT', KEYS[1], ARGV[6])
return 1
"#;

const BEGIN_PENDING_TOTP_ATTEMPT_SCRIPT: &str = r#"
local values = redis.call(
    'HMGET', KEYS[1],
    'account_id',
    'factor_id',
    'encrypted_payload',
    'created_at_epoch_millis',
    'attempts_remaining',
    'expires_at_epoch_millis',
    'lease_until_epoch_millis'
)
if not values[1] then
    return {0, '', 0, 0, 0}
end
local created_at = tonumber(values[4])
local attempts = tonumber(values[5])
local expires_at = tonumber(values[6])
if not values[2] or not values[3] or not created_at or not attempts or not expires_at then
    return {-1, '', 0, 0, 0}
end
if values[1] ~= ARGV[1] or values[2] ~= ARGV[2] then
    return {0, '', 0, 0, 0}
end
if expires_at <= tonumber(ARGV[3]) or attempts <= 0 then
    redis.call('DEL', KEYS[1])
    return {0, '', 0, 0, 0}
end
local lease_until = tonumber(values[7]) or 0
if lease_until > tonumber(ARGV[3]) then
    return {0, '', 0, 0, 0}
end
redis.call(
    'HSET', KEYS[1],
    'lease_token', ARGV[4],
    'lease_until_epoch_millis', ARGV[5]
)
return {1, values[3], created_at, attempts, expires_at}
"#;

const FINISH_PENDING_TOTP_ATTEMPT_SCRIPT: &str = r#"
local values = redis.call(
    'HMGET', KEYS[1],
    'account_id',
    'factor_id',
    'attempts_remaining',
    'expires_at_epoch_millis',
    'lease_token',
    'lease_until_epoch_millis'
)
if not values[1] then
    return {0, 0}
end
local attempts = tonumber(values[3])
local expires_at = tonumber(values[4])
local lease_until = tonumber(values[6])
if not values[2] or not attempts or not expires_at or not values[5] or not lease_until then
    return {-1, 0}
end
if values[1] ~= ARGV[1] or values[2] ~= ARGV[2] or values[5] ~= ARGV[3] then
    return {0, 0}
end
if expires_at <= tonumber(ARGV[4]) then
    redis.call('DEL', KEYS[1])
    return {0, 0}
end
if lease_until <= tonumber(ARGV[4]) then
    redis.call('HDEL', KEYS[1], 'lease_token', 'lease_until_epoch_millis')
    return {0, 0}
end
if attempts <= 0 then
    redis.call('DEL', KEYS[1])
    return {0, 0}
end
if ARGV[5] == '1' then
    redis.call('DEL', KEYS[1])
    return {1, attempts}
end
attempts = attempts - 1
if attempts <= 0 then
    redis.call('DEL', KEYS[1])
else
    redis.call('HSET', KEYS[1], 'attempts_remaining', attempts)
    redis.call('HDEL', KEYS[1], 'lease_token', 'lease_until_epoch_millis')
end
return {1, attempts}
"#;

const ABORT_PENDING_TOTP_ATTEMPT_SCRIPT: &str = r#"
if redis.call('HGET', KEYS[1], 'account_id') ~= ARGV[1]
    or redis.call('HGET', KEYS[1], 'factor_id') ~= ARGV[2]
    or redis.call('HGET', KEYS[1], 'lease_token') ~= ARGV[3] then
    return 0
end
redis.call('HDEL', KEYS[1], 'lease_token', 'lease_until_epoch_millis')
return 1
"#;

const REMOVE_PENDING_TOTP_ENROLLMENT_SCRIPT: &str = r#"
if redis.call('HGET', KEYS[1], 'account_id') ~= ARGV[1]
    or redis.call('HGET', KEYS[1], 'factor_id') ~= ARGV[2] then
    return 0
end
redis.call('DEL', KEYS[1])
return 1
"#;

#[derive(Debug)]
pub struct EphemeralError(String);

impl EphemeralError {
    fn invalid_data(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for EphemeralError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for EphemeralError {}

impl From<redis::RedisError> for EphemeralError {
    fn from(error: redis::RedisError) -> Self {
        Self(format!("Redis operation failed: {error}"))
    }
}

pub type EphemeralFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, EphemeralError>> + Send + 'a>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedChallengeKind {
    Login,
    StepUp,
}

impl ExpectedChallengeKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::StepUp => "step_up",
        }
    }

    fn matches(self, purpose: &ChallengePurpose) -> bool {
        matches!(
            (self, purpose),
            (Self::Login, ChallengePurpose::LoginMfa) | (Self::StepUp, ChallengePurpose::StepUp(_))
        )
    }
}

#[derive(Debug, Clone)]
pub struct ChallengeAttempt {
    pub challenge: AuthChallenge,
    lease_token: String,
}

#[derive(Debug, Clone)]
pub enum ChallengeAttemptStart {
    Started(Box<ChallengeAttempt>),
    Rejected { account_id: Option<String> },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LoginFailureState {
    pub attempts: u8,
    pub locked_until_epoch_millis: Option<u64>,
    pub newly_locked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingTotpEnrollment {
    pub factor_id: String,
    pub account_id: String,
    pub secret_base32: String,
    pub recovery_delivery_public_key: [u8; 32],
    pub created_at_epoch_millis: u64,
    pub expires_at_epoch_millis: u64,
    pub attempts_remaining: u8,
}

#[derive(Debug, Clone)]
pub struct PendingTotpEnrollmentAttempt {
    pub enrollment: PendingTotpEnrollment,
    lease_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct PendingTotpSecretPayload {
    secret_base32: String,
    recovery_delivery_public_key: [u8; 32],
}

impl LoginFailureState {
    pub fn is_locked_at(self, now_epoch_millis: u64) -> bool {
        self.locked_until_epoch_millis
            .is_some_and(|expires| expires > now_epoch_millis)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevicePresenceStatus {
    Online,
    Busy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePresence {
    pub device_id: String,
    pub status: DevicePresenceStatus,
    pub last_seen_epoch_millis: u64,
}

#[derive(Debug)]
pub struct StepUpConsumption<'a> {
    pub challenge_id: &'a str,
    pub account_id: &'a str,
    pub device_id: &'a str,
    pub purpose: &'a str,
    pub operation_binding_hash: &'a str,
}

pub trait EphemeralState: Send + Sync {
    fn backend_name(&self) -> &'static str;

    fn health(&self) -> EphemeralFuture<'_, ()>;

    fn put_pending_totp_enrollment<'a>(
        &'a self,
        enrollment: &'a PendingTotpEnrollment,
        now_epoch_millis: u64,
    ) -> EphemeralFuture<'a, bool>;

    fn begin_pending_totp_enrollment_attempt<'a>(
        &'a self,
        account_id: &'a str,
        factor_id: &'a str,
        now_epoch_millis: u64,
    ) -> EphemeralFuture<'a, Option<PendingTotpEnrollmentAttempt>>;

    fn finish_pending_totp_enrollment_attempt<'a>(
        &'a self,
        attempt: &'a PendingTotpEnrollmentAttempt,
        accepted: bool,
        now_epoch_millis: u64,
    ) -> EphemeralFuture<'a, Option<PendingTotpEnrollment>>;

    fn abort_pending_totp_enrollment_attempt<'a>(
        &'a self,
        attempt: &'a PendingTotpEnrollmentAttempt,
    ) -> EphemeralFuture<'a, bool>;

    fn remove_pending_totp_enrollment<'a>(
        &'a self,
        account_id: &'a str,
        factor_id: &'a str,
    ) -> EphemeralFuture<'a, bool>;

    fn list_device_presence<'a>(
        &'a self,
        account_id: &'a str,
    ) -> EphemeralFuture<'a, Vec<DevicePresence>>;

    fn record_nonce<'a>(
        &'a self,
        nonce_binding: &'a str,
        now_epoch_millis: u64,
        ttl_millis: u64,
    ) -> EphemeralFuture<'a, bool>;

    fn login_failure_state<'a>(
        &'a self,
        account_id: &'a str,
        now_epoch_millis: u64,
    ) -> EphemeralFuture<'a, LoginFailureState>;

    #[allow(clippy::too_many_arguments)]
    fn record_login_failure<'a>(
        &'a self,
        account_id: &'a str,
        now_epoch_millis: u64,
        max_attempts: u8,
        lock_millis: u64,
        state_ttl_millis: u64,
    ) -> EphemeralFuture<'a, LoginFailureState>;

    fn clear_login_failures<'a>(&'a self, account_id: &'a str) -> EphemeralFuture<'a, ()>;

    fn put_challenge<'a>(&'a self, challenge: &'a AuthChallenge) -> EphemeralFuture<'a, bool>;

    fn begin_challenge_attempt<'a>(
        &'a self,
        challenge_id: &'a str,
        expected_kind: ExpectedChallengeKind,
        now_epoch_millis: u64,
    ) -> EphemeralFuture<'a, ChallengeAttemptStart>;

    fn finish_challenge_attempt<'a>(
        &'a self,
        attempt: &'a ChallengeAttempt,
        accepted: bool,
        consume_on_success: bool,
        now_epoch_millis: u64,
    ) -> EphemeralFuture<'a, Option<AuthChallenge>>;

    fn abort_challenge_attempt<'a>(
        &'a self,
        attempt: &'a ChallengeAttempt,
    ) -> EphemeralFuture<'a, ()>;

    fn consume_step_up<'a>(
        &'a self,
        binding: &'a StepUpConsumption<'a>,
        now_epoch_millis: u64,
    ) -> EphemeralFuture<'a, bool>;
}

#[derive(Debug, Default)]
pub struct MemoryEphemeralState {
    state: Mutex<MemoryState>,
}

#[derive(Debug, Default)]
struct MemoryState {
    nonces: HashMap<String, u64>,
    login_failures: HashMap<String, MemoryLoginFailure>,
    challenges: HashMap<String, MemoryChallenge>,
    pending_totp_enrollments: HashMap<String, MemoryPendingTotpEnrollment>,
}

#[derive(Debug, Clone)]
struct MemoryPendingTotpEnrollment {
    enrollment: PendingTotpEnrollment,
    lease: Option<(String, u64)>,
}

#[derive(Debug, Clone, Copy)]
struct MemoryLoginFailure {
    attempts: u8,
    locked_until_epoch_millis: Option<u64>,
    expires_at_epoch_millis: u64,
}

#[derive(Debug, Clone)]
struct MemoryChallenge {
    challenge: AuthChallenge,
    status: ChallengeStatus,
    lease: Option<(String, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChallengeStatus {
    Issued,
    Verified,
    Consumed,
    Failed,
}

impl EphemeralState for MemoryEphemeralState {
    fn backend_name(&self) -> &'static str {
        "memory"
    }

    fn health(&self) -> EphemeralFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }

    fn put_pending_totp_enrollment<'a>(
        &'a self,
        enrollment: &'a PendingTotpEnrollment,
        now_epoch_millis: u64,
    ) -> EphemeralFuture<'a, bool> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            if state
                .pending_totp_enrollments
                .get(&enrollment.account_id)
                .is_some_and(|record| record.enrollment.expires_at_epoch_millis > now_epoch_millis)
            {
                return Ok(false);
            }
            state.pending_totp_enrollments.insert(
                enrollment.account_id.clone(),
                MemoryPendingTotpEnrollment {
                    enrollment: enrollment.clone(),
                    lease: None,
                },
            );
            Ok(true)
        })
    }

    fn begin_pending_totp_enrollment_attempt<'a>(
        &'a self,
        account_id: &'a str,
        factor_id: &'a str,
        now_epoch_millis: u64,
    ) -> EphemeralFuture<'a, Option<PendingTotpEnrollmentAttempt>> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            let Some(record) = state.pending_totp_enrollments.get_mut(account_id) else {
                return Ok(None);
            };
            if record.enrollment.factor_id != factor_id {
                return Ok(None);
            }
            if record.enrollment.expires_at_epoch_millis <= now_epoch_millis
                || record.enrollment.attempts_remaining == 0
            {
                state.pending_totp_enrollments.remove(account_id);
                return Ok(None);
            }
            if record
                .lease
                .as_ref()
                .is_some_and(|(_, expires_at)| *expires_at > now_epoch_millis)
            {
                return Ok(None);
            }
            let lease_token = random_uuid_v4();
            record.lease = Some((
                lease_token.clone(),
                now_epoch_millis.saturating_add(ATTEMPT_LEASE_MILLIS),
            ));
            Ok(Some(PendingTotpEnrollmentAttempt {
                enrollment: record.enrollment.clone(),
                lease_token,
            }))
        })
    }

    fn finish_pending_totp_enrollment_attempt<'a>(
        &'a self,
        attempt: &'a PendingTotpEnrollmentAttempt,
        accepted: bool,
        now_epoch_millis: u64,
    ) -> EphemeralFuture<'a, Option<PendingTotpEnrollment>> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            let account_id = &attempt.enrollment.account_id;
            let Some(record) = state.pending_totp_enrollments.get_mut(account_id) else {
                return Ok(None);
            };
            if record.enrollment.factor_id != attempt.enrollment.factor_id {
                return Ok(None);
            }
            if record.enrollment.expires_at_epoch_millis <= now_epoch_millis {
                state.pending_totp_enrollments.remove(account_id);
                return Ok(None);
            }
            if !record.lease.as_ref().is_some_and(|(token, expires_at)| {
                token == &attempt.lease_token && *expires_at > now_epoch_millis
            }) {
                return Ok(None);
            }

            let result = if accepted {
                record.enrollment.clone()
            } else {
                record.enrollment.attempts_remaining =
                    record.enrollment.attempts_remaining.saturating_sub(1);
                record.lease = None;
                record.enrollment.clone()
            };
            if accepted || result.attempts_remaining == 0 {
                state.pending_totp_enrollments.remove(account_id);
            }
            Ok(Some(result))
        })
    }

    fn abort_pending_totp_enrollment_attempt<'a>(
        &'a self,
        attempt: &'a PendingTotpEnrollmentAttempt,
    ) -> EphemeralFuture<'a, bool> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            let Some(record) = state
                .pending_totp_enrollments
                .get_mut(&attempt.enrollment.account_id)
            else {
                return Ok(false);
            };
            if record.enrollment.factor_id != attempt.enrollment.factor_id
                || record.lease.as_ref().map(|(token, _)| token) != Some(&attempt.lease_token)
            {
                return Ok(false);
            }
            record.lease = None;
            Ok(true)
        })
    }

    fn remove_pending_totp_enrollment<'a>(
        &'a self,
        account_id: &'a str,
        factor_id: &'a str,
    ) -> EphemeralFuture<'a, bool> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            if state
                .pending_totp_enrollments
                .get(account_id)
                .is_none_or(|record| record.enrollment.factor_id != factor_id)
            {
                return Ok(false);
            }
            state.pending_totp_enrollments.remove(account_id);
            Ok(true)
        })
    }

    fn list_device_presence<'a>(
        &'a self,
        _account_id: &'a str,
    ) -> EphemeralFuture<'a, Vec<DevicePresence>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn record_nonce<'a>(
        &'a self,
        nonce_binding: &'a str,
        now_epoch_millis: u64,
        ttl_millis: u64,
    ) -> EphemeralFuture<'a, bool> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            state
                .nonces
                .retain(|_, expires| *expires > now_epoch_millis);
            if state.nonces.contains_key(nonce_binding) {
                return Ok(false);
            }
            state.nonces.insert(
                nonce_binding.to_owned(),
                now_epoch_millis.saturating_add(ttl_millis),
            );
            Ok(true)
        })
    }

    fn login_failure_state<'a>(
        &'a self,
        account_id: &'a str,
        now_epoch_millis: u64,
    ) -> EphemeralFuture<'a, LoginFailureState> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            let Some(value) = state.login_failures.get(account_id).copied() else {
                return Ok(LoginFailureState::default());
            };
            if value.expires_at_epoch_millis <= now_epoch_millis {
                state.login_failures.remove(account_id);
                return Ok(LoginFailureState::default());
            }
            Ok(LoginFailureState {
                attempts: value.attempts,
                locked_until_epoch_millis: value.locked_until_epoch_millis,
                newly_locked: false,
            })
        })
    }

    fn record_login_failure<'a>(
        &'a self,
        account_id: &'a str,
        now_epoch_millis: u64,
        max_attempts: u8,
        lock_millis: u64,
        state_ttl_millis: u64,
    ) -> EphemeralFuture<'a, LoginFailureState> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            let current = state.login_failures.get(account_id).copied();
            if current.is_some_and(|value| {
                value
                    .locked_until_epoch_millis
                    .is_some_and(|until| until > now_epoch_millis)
            }) {
                let value = current.expect("checked login failure state");
                return Ok(LoginFailureState {
                    attempts: value.attempts,
                    locked_until_epoch_millis: value.locked_until_epoch_millis,
                    newly_locked: false,
                });
            }
            let mut attempts = current
                .filter(|value| value.expires_at_epoch_millis > now_epoch_millis)
                .and_then(|value| {
                    value
                        .locked_until_epoch_millis
                        .is_none()
                        .then_some(value.attempts)
                })
                .unwrap_or(0)
                .saturating_add(1);
            let newly_locked = attempts >= max_attempts;
            let locked_until_epoch_millis =
                newly_locked.then(|| now_epoch_millis.saturating_add(lock_millis));
            if newly_locked {
                attempts = 0;
            }
            state.login_failures.insert(
                account_id.to_owned(),
                MemoryLoginFailure {
                    attempts,
                    locked_until_epoch_millis,
                    expires_at_epoch_millis: now_epoch_millis.saturating_add(state_ttl_millis),
                },
            );
            Ok(LoginFailureState {
                attempts,
                locked_until_epoch_millis,
                newly_locked,
            })
        })
    }

    fn clear_login_failures<'a>(&'a self, account_id: &'a str) -> EphemeralFuture<'a, ()> {
        Box::pin(async move {
            self.state.lock().await.login_failures.remove(account_id);
            Ok(())
        })
    }

    fn put_challenge<'a>(&'a self, challenge: &'a AuthChallenge) -> EphemeralFuture<'a, bool> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            if state.challenges.contains_key(&challenge.challenge_id) {
                return Ok(false);
            }
            state.challenges.insert(
                challenge.challenge_id.clone(),
                MemoryChallenge {
                    challenge: challenge.clone(),
                    status: ChallengeStatus::Issued,
                    lease: None,
                },
            );
            Ok(true)
        })
    }

    fn begin_challenge_attempt<'a>(
        &'a self,
        challenge_id: &'a str,
        expected_kind: ExpectedChallengeKind,
        now_epoch_millis: u64,
    ) -> EphemeralFuture<'a, ChallengeAttemptStart> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            let Some(record) = state.challenges.get_mut(challenge_id) else {
                return Ok(ChallengeAttemptStart::Rejected { account_id: None });
            };
            if record.challenge.expires_at_epoch_millis <= now_epoch_millis {
                let account_id = Some(record.challenge.account_id.clone());
                state.challenges.remove(challenge_id);
                return Ok(ChallengeAttemptStart::Rejected { account_id });
            }
            let active_lease = record
                .lease
                .as_ref()
                .is_some_and(|(_, expires)| *expires > now_epoch_millis);
            if record.status != ChallengeStatus::Issued
                || record.challenge.attempts_remaining == 0
                || !expected_kind.matches(&record.challenge.purpose)
                || active_lease
            {
                return Ok(ChallengeAttemptStart::Rejected {
                    account_id: Some(record.challenge.account_id.clone()),
                });
            }
            let lease_token = random_uuid_v4();
            record.lease = Some((
                lease_token.clone(),
                now_epoch_millis.saturating_add(ATTEMPT_LEASE_MILLIS),
            ));
            Ok(ChallengeAttemptStart::Started(Box::new(ChallengeAttempt {
                challenge: record.challenge.clone(),
                lease_token,
            })))
        })
    }

    fn finish_challenge_attempt<'a>(
        &'a self,
        attempt: &'a ChallengeAttempt,
        accepted: bool,
        consume_on_success: bool,
        now_epoch_millis: u64,
    ) -> EphemeralFuture<'a, Option<AuthChallenge>> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            let Some(record) = state.challenges.get_mut(&attempt.challenge.challenge_id) else {
                return Ok(None);
            };
            if record.status != ChallengeStatus::Issued
                || record.lease.as_ref().map(|lease| &lease.0) != Some(&attempt.lease_token)
            {
                return Ok(None);
            }
            record.lease = None;
            if accepted {
                record.challenge.verified_at_epoch_millis = Some(now_epoch_millis);
                if consume_on_success {
                    record.status = ChallengeStatus::Consumed;
                    record.challenge.consumed_at_epoch_millis = Some(now_epoch_millis);
                } else {
                    record.status = ChallengeStatus::Verified;
                }
            } else {
                record.challenge.attempts_remaining =
                    record.challenge.attempts_remaining.saturating_sub(1);
                if record.challenge.attempts_remaining == 0 {
                    record.status = ChallengeStatus::Failed;
                }
            }
            Ok(Some(record.challenge.clone()))
        })
    }

    fn abort_challenge_attempt<'a>(
        &'a self,
        attempt: &'a ChallengeAttempt,
    ) -> EphemeralFuture<'a, ()> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            if let Some(record) = state.challenges.get_mut(&attempt.challenge.challenge_id) {
                if record.lease.as_ref().map(|lease| &lease.0) == Some(&attempt.lease_token) {
                    record.lease = None;
                }
            }
            Ok(())
        })
    }

    fn consume_step_up<'a>(
        &'a self,
        binding: &'a StepUpConsumption<'a>,
        now_epoch_millis: u64,
    ) -> EphemeralFuture<'a, bool> {
        Box::pin(async move {
            let mut state = self.state.lock().await;
            let Some(record) = state.challenges.get_mut(binding.challenge_id) else {
                return Ok(false);
            };
            let purpose_matches = matches!(
                &record.challenge.purpose,
                ChallengePurpose::StepUp(purpose) if purpose == binding.purpose
            );
            if record.status != ChallengeStatus::Verified
                || record.challenge.expires_at_epoch_millis <= now_epoch_millis
                || record.challenge.account_id != binding.account_id
                || record.challenge.device_id.as_deref() != Some(binding.device_id)
                || record.challenge.operation_binding_hash.as_deref()
                    != Some(binding.operation_binding_hash)
                || !purpose_matches
            {
                return Ok(false);
            }
            record.status = ChallengeStatus::Consumed;
            record.challenge.consumed_at_epoch_millis = Some(now_epoch_millis);
            Ok(true)
        })
    }
}

#[derive(Clone)]
pub struct RedisEphemeralState {
    connection: ConnectionManager,
    mfa_secret_key: [u8; 32],
}

impl RedisEphemeralState {
    pub async fn connect(url: &str, mfa_secret_key: [u8; 32]) -> Result<Self, EphemeralError> {
        let client = redis::Client::open(url)
            .map_err(|error| EphemeralError(format!("invalid REDIS_URL: {error}")))?;
        let config = ConnectionManagerConfig::new()
            .set_number_of_retries(REDIS_CONNECTION_RETRIES)
            .set_max_delay(500)
            .set_connection_timeout(REDIS_CONNECTION_TIMEOUT)
            .set_response_timeout(REDIS_RESPONSE_TIMEOUT);
        let backend = Self {
            connection: client
                .get_connection_manager_with_config(config)
                .await
                .map_err(|error| EphemeralError(format!("cannot connect to Redis: {error}")))?,
            mfa_secret_key,
        };
        backend.health().await?;
        Ok(backend)
    }

    fn nonce_key(binding: &str) -> String {
        hashed_key("nonce", binding)
    }

    fn login_key(account_id: &str) -> String {
        hashed_key("login-failure", account_id)
    }

    fn challenge_key(challenge_id: &str) -> String {
        hashed_key("challenge", challenge_id)
    }

    fn pending_totp_enrollment_key(account_id: &str) -> String {
        hashed_key("pending-totp-enrollment", account_id)
    }
}

impl EphemeralState for RedisEphemeralState {
    fn backend_name(&self) -> &'static str {
        "redis"
    }

    fn health(&self) -> EphemeralFuture<'_, ()> {
        Box::pin(async move {
            let mut connection = self.connection.clone();
            let response: String = redis::cmd("PING").query_async(&mut connection).await?;
            if response != "PONG" {
                return Err(EphemeralError::invalid_data(
                    "Redis PING returned an unexpected response",
                ));
            }
            Ok(())
        })
    }

    fn put_pending_totp_enrollment<'a>(
        &'a self,
        enrollment: &'a PendingTotpEnrollment,
        now_epoch_millis: u64,
    ) -> EphemeralFuture<'a, bool> {
        Box::pin(async move {
            let encrypted_payload = encrypt_pending_totp_secret(&self.mfa_secret_key, enrollment)?;
            let mut connection = self.connection.clone();
            let inserted: i64 = redis::Script::new(PUT_PENDING_TOTP_ENROLLMENT_SCRIPT)
                .key(Self::pending_totp_enrollment_key(&enrollment.account_id))
                .arg(&enrollment.account_id)
                .arg(&enrollment.factor_id)
                .arg(encrypted_payload)
                .arg(enrollment.created_at_epoch_millis)
                .arg(enrollment.attempts_remaining)
                .arg(enrollment.expires_at_epoch_millis)
                .arg(now_epoch_millis)
                .invoke_async(&mut connection)
                .await?;
            match inserted {
                1 => Ok(true),
                0 => Ok(false),
                _ => Err(EphemeralError::invalid_data(
                    "Redis pending TOTP enrollment is malformed",
                )),
            }
        })
    }

    fn begin_pending_totp_enrollment_attempt<'a>(
        &'a self,
        account_id: &'a str,
        factor_id: &'a str,
        now_epoch_millis: u64,
    ) -> EphemeralFuture<'a, Option<PendingTotpEnrollmentAttempt>> {
        Box::pin(async move {
            let lease_token = random_uuid_v4();
            let lease_until = now_epoch_millis.saturating_add(ATTEMPT_LEASE_MILLIS);
            let mut connection = self.connection.clone();
            let (code, encrypted_payload, created_at, attempts, expires_at): (
                i64,
                Vec<u8>,
                u64,
                u8,
                u64,
            ) = redis::Script::new(BEGIN_PENDING_TOTP_ATTEMPT_SCRIPT)
                .key(Self::pending_totp_enrollment_key(account_id))
                .arg(account_id)
                .arg(factor_id)
                .arg(now_epoch_millis)
                .arg(&lease_token)
                .arg(lease_until)
                .invoke_async(&mut connection)
                .await?;
            match code {
                0 => Ok(None),
                1 => {
                    let payload = decrypt_pending_totp_secret(
                        &self.mfa_secret_key,
                        account_id,
                        factor_id,
                        &encrypted_payload,
                    )?;
                    Ok(Some(PendingTotpEnrollmentAttempt {
                        enrollment: PendingTotpEnrollment {
                            factor_id: factor_id.to_owned(),
                            account_id: account_id.to_owned(),
                            secret_base32: payload.secret_base32,
                            recovery_delivery_public_key: payload.recovery_delivery_public_key,
                            created_at_epoch_millis: created_at,
                            expires_at_epoch_millis: expires_at,
                            attempts_remaining: attempts,
                        },
                        lease_token,
                    }))
                }
                _ => Err(EphemeralError::invalid_data(
                    "Redis pending TOTP enrollment is malformed",
                )),
            }
        })
    }

    fn finish_pending_totp_enrollment_attempt<'a>(
        &'a self,
        attempt: &'a PendingTotpEnrollmentAttempt,
        accepted: bool,
        now_epoch_millis: u64,
    ) -> EphemeralFuture<'a, Option<PendingTotpEnrollment>> {
        Box::pin(async move {
            let mut connection = self.connection.clone();
            let (code, attempts_remaining): (i64, i64) =
                redis::Script::new(FINISH_PENDING_TOTP_ATTEMPT_SCRIPT)
                    .key(Self::pending_totp_enrollment_key(
                        &attempt.enrollment.account_id,
                    ))
                    .arg(&attempt.enrollment.account_id)
                    .arg(&attempt.enrollment.factor_id)
                    .arg(&attempt.lease_token)
                    .arg(now_epoch_millis)
                    .arg(u8::from(accepted))
                    .invoke_async(&mut connection)
                    .await?;
            match code {
                0 => Ok(None),
                1 => {
                    let attempts_remaining = u8::try_from(attempts_remaining).map_err(|_| {
                        EphemeralError::invalid_data("Redis pending TOTP attempt count is invalid")
                    })?;
                    let mut enrollment = attempt.enrollment.clone();
                    enrollment.attempts_remaining = attempts_remaining;
                    Ok(Some(enrollment))
                }
                _ => Err(EphemeralError::invalid_data(
                    "Redis pending TOTP enrollment is malformed",
                )),
            }
        })
    }

    fn abort_pending_totp_enrollment_attempt<'a>(
        &'a self,
        attempt: &'a PendingTotpEnrollmentAttempt,
    ) -> EphemeralFuture<'a, bool> {
        Box::pin(async move {
            let mut connection = self.connection.clone();
            let aborted: u8 = redis::Script::new(ABORT_PENDING_TOTP_ATTEMPT_SCRIPT)
                .key(Self::pending_totp_enrollment_key(
                    &attempt.enrollment.account_id,
                ))
                .arg(&attempt.enrollment.account_id)
                .arg(&attempt.enrollment.factor_id)
                .arg(&attempt.lease_token)
                .invoke_async(&mut connection)
                .await?;
            Ok(aborted == 1)
        })
    }

    fn remove_pending_totp_enrollment<'a>(
        &'a self,
        account_id: &'a str,
        factor_id: &'a str,
    ) -> EphemeralFuture<'a, bool> {
        Box::pin(async move {
            let mut connection = self.connection.clone();
            let removed: u8 = redis::Script::new(REMOVE_PENDING_TOTP_ENROLLMENT_SCRIPT)
                .key(Self::pending_totp_enrollment_key(account_id))
                .arg(account_id)
                .arg(factor_id)
                .invoke_async(&mut connection)
                .await?;
            Ok(removed == 1)
        })
    }

    fn list_device_presence<'a>(
        &'a self,
        account_id: &'a str,
    ) -> EphemeralFuture<'a, Vec<DevicePresence>> {
        Box::pin(async move {
            let account_key = signal_account_presence_key(account_id);
            let mut connection = self.connection.clone();
            let device_ids: Vec<String> = redis::cmd("SMEMBERS")
                .arg(&account_key)
                .query_async(&mut connection)
                .await?;
            let mut devices = Vec::with_capacity(device_ids.len());
            for indexed_device_id in device_ids {
                let fields: (
                    Option<String>,
                    Option<String>,
                    Option<String>,
                    Option<String>,
                ) = redis::cmd("HMGET")
                    .arg(signal_device_presence_key(account_id, &indexed_device_id))
                    .arg("account_id")
                    .arg("device_id")
                    .arg("status")
                    .arg("last_seen_epoch_millis")
                    .query_async(&mut connection)
                    .await?;
                if fields.0.is_none()
                    && fields.1.is_none()
                    && fields.2.is_none()
                    && fields.3.is_none()
                {
                    let exists: bool = redis::cmd("EXISTS")
                        .arg(signal_device_presence_key(account_id, &indexed_device_id))
                        .query_async(&mut connection)
                        .await?;
                    if !exists {
                        continue;
                    }
                }
                devices.push(device_presence_from_fields(
                    account_id,
                    &indexed_device_id,
                    fields,
                )?);
            }
            devices.sort_by(|left, right| left.device_id.cmp(&right.device_id));
            Ok(devices)
        })
    }

    fn record_nonce<'a>(
        &'a self,
        nonce_binding: &'a str,
        _now_epoch_millis: u64,
        ttl_millis: u64,
    ) -> EphemeralFuture<'a, bool> {
        Box::pin(async move {
            let mut connection = self.connection.clone();
            let response: Option<String> = redis::cmd("SET")
                .arg(Self::nonce_key(nonce_binding))
                .arg("1")
                .arg("NX")
                .arg("PX")
                .arg(ttl_millis)
                .query_async(&mut connection)
                .await?;
            Ok(response.is_some())
        })
    }

    fn login_failure_state<'a>(
        &'a self,
        account_id: &'a str,
        now_epoch_millis: u64,
    ) -> EphemeralFuture<'a, LoginFailureState> {
        Box::pin(async move {
            let mut connection = self.connection.clone();
            let values: (Option<u8>, Option<u64>) = redis::cmd("HMGET")
                .arg(Self::login_key(account_id))
                .arg("attempts")
                .arg("locked_until_epoch_millis")
                .query_async(&mut connection)
                .await?;
            let locked_until_epoch_millis = values.1.filter(|until| *until > now_epoch_millis);
            Ok(LoginFailureState {
                attempts: values.0.unwrap_or(0),
                locked_until_epoch_millis,
                newly_locked: false,
            })
        })
    }

    fn record_login_failure<'a>(
        &'a self,
        account_id: &'a str,
        now_epoch_millis: u64,
        max_attempts: u8,
        lock_millis: u64,
        state_ttl_millis: u64,
    ) -> EphemeralFuture<'a, LoginFailureState> {
        Box::pin(async move {
            let mut connection = self.connection.clone();
            let (attempts, locked_until, newly_locked): (u8, u64, u8) =
                redis::Script::new(RECORD_LOGIN_FAILURE_SCRIPT)
                    .key(Self::login_key(account_id))
                    .arg(now_epoch_millis)
                    .arg(max_attempts)
                    .arg(lock_millis)
                    .arg(state_ttl_millis)
                    .invoke_async(&mut connection)
                    .await?;
            Ok(LoginFailureState {
                attempts,
                locked_until_epoch_millis: (locked_until > now_epoch_millis)
                    .then_some(locked_until),
                newly_locked: newly_locked == 1,
            })
        })
    }

    fn clear_login_failures<'a>(&'a self, account_id: &'a str) -> EphemeralFuture<'a, ()> {
        Box::pin(async move {
            let mut connection = self.connection.clone();
            redis::cmd("DEL")
                .arg(Self::login_key(account_id))
                .query_async::<u64>(&mut connection)
                .await?;
            Ok(())
        })
    }

    fn put_challenge<'a>(&'a self, challenge: &'a AuthChallenge) -> EphemeralFuture<'a, bool> {
        Box::pin(async move {
            let payload = serde_json::to_string(challenge)
                .map_err(|error| EphemeralError::invalid_data(error.to_string()))?;
            let (kind, purpose) = challenge_kind_and_purpose(&challenge.purpose);
            let mut connection = self.connection.clone();
            let inserted: u8 = redis::Script::new(PUT_CHALLENGE_SCRIPT)
                .key(Self::challenge_key(&challenge.challenge_id))
                .arg(payload)
                .arg(kind)
                .arg(challenge.attempts_remaining)
                .arg(challenge.expires_at_epoch_millis)
                .arg(&challenge.account_id)
                .arg(challenge.device_id.as_deref().unwrap_or(""))
                .arg(purpose)
                .arg(challenge.operation_binding_hash.as_deref().unwrap_or(""))
                .invoke_async(&mut connection)
                .await?;
            Ok(inserted == 1)
        })
    }

    fn begin_challenge_attempt<'a>(
        &'a self,
        challenge_id: &'a str,
        expected_kind: ExpectedChallengeKind,
        now_epoch_millis: u64,
    ) -> EphemeralFuture<'a, ChallengeAttemptStart> {
        Box::pin(async move {
            let lease_token = random_uuid_v4();
            let lease_until = now_epoch_millis.saturating_add(ATTEMPT_LEASE_MILLIS);
            let mut connection = self.connection.clone();
            let response: String = redis::Script::new(BEGIN_CHALLENGE_ATTEMPT_SCRIPT)
                .key(Self::challenge_key(challenge_id))
                .arg(now_epoch_millis)
                .arg(expected_kind.as_str())
                .arg(&lease_token)
                .arg(lease_until)
                .invoke_async(&mut connection)
                .await?;
            let response: BeginChallengeResponse = serde_json::from_str(&response)
                .map_err(|error| EphemeralError::invalid_data(error.to_string()))?;
            let challenge = response
                .payload
                .as_deref()
                .map(serde_json::from_str)
                .transpose()
                .map_err(|error| EphemeralError::invalid_data(error.to_string()))?;
            if response.code == "started" {
                let challenge = challenge.ok_or_else(|| {
                    EphemeralError::invalid_data("Redis challenge payload is missing")
                })?;
                Ok(ChallengeAttemptStart::Started(Box::new(ChallengeAttempt {
                    challenge,
                    lease_token,
                })))
            } else {
                Ok(ChallengeAttemptStart::Rejected {
                    account_id: challenge.map(|value: AuthChallenge| value.account_id),
                })
            }
        })
    }

    fn finish_challenge_attempt<'a>(
        &'a self,
        attempt: &'a ChallengeAttempt,
        accepted: bool,
        consume_on_success: bool,
        now_epoch_millis: u64,
    ) -> EphemeralFuture<'a, Option<AuthChallenge>> {
        Box::pin(async move {
            let mut connection = self.connection.clone();
            let attempts_remaining: i64 = redis::Script::new(FINISH_CHALLENGE_ATTEMPT_SCRIPT)
                .key(Self::challenge_key(&attempt.challenge.challenge_id))
                .arg(&attempt.lease_token)
                .arg(u8::from(accepted))
                .arg(u8::from(consume_on_success))
                .arg(now_epoch_millis)
                .invoke_async(&mut connection)
                .await?;
            if attempts_remaining < 0 {
                return Ok(None);
            }
            let mut challenge = attempt.challenge.clone();
            challenge.attempts_remaining = u8::try_from(attempts_remaining)
                .map_err(|_| EphemeralError::invalid_data("invalid Redis attempt count"))?;
            if accepted {
                challenge.verified_at_epoch_millis = Some(now_epoch_millis);
                if consume_on_success {
                    challenge.consumed_at_epoch_millis = Some(now_epoch_millis);
                }
            }
            Ok(Some(challenge))
        })
    }

    fn abort_challenge_attempt<'a>(
        &'a self,
        attempt: &'a ChallengeAttempt,
    ) -> EphemeralFuture<'a, ()> {
        Box::pin(async move {
            let mut connection = self.connection.clone();
            redis::Script::new(ABORT_CHALLENGE_ATTEMPT_SCRIPT)
                .key(Self::challenge_key(&attempt.challenge.challenge_id))
                .arg(&attempt.lease_token)
                .invoke_async::<u8>(&mut connection)
                .await?;
            Ok(())
        })
    }

    fn consume_step_up<'a>(
        &'a self,
        binding: &'a StepUpConsumption<'a>,
        now_epoch_millis: u64,
    ) -> EphemeralFuture<'a, bool> {
        Box::pin(async move {
            let mut connection = self.connection.clone();
            let consumed: u8 = redis::Script::new(CONSUME_STEP_UP_SCRIPT)
                .key(Self::challenge_key(binding.challenge_id))
                .arg(now_epoch_millis)
                .arg(binding.account_id)
                .arg(binding.device_id)
                .arg(binding.purpose)
                .arg(binding.operation_binding_hash)
                .invoke_async(&mut connection)
                .await?;
            Ok(consumed == 1)
        })
    }
}

#[derive(serde::Deserialize)]
struct BeginChallengeResponse {
    code: String,
    payload: Option<String>,
}

fn encrypt_pending_totp_secret(
    key: &[u8; 32],
    enrollment: &PendingTotpEnrollment,
) -> Result<Vec<u8>, EphemeralError> {
    let plaintext = serde_json::to_vec(&PendingTotpSecretPayload {
        secret_base32: enrollment.secret_base32.clone(),
        recovery_delivery_public_key: enrollment.recovery_delivery_public_key,
    })
    .map_err(|_| EphemeralError::invalid_data("cannot encode pending TOTP secret"))?;
    let mut nonce_bytes = [0_u8; PENDING_TOTP_NONCE_BYTES];
    rand::rng().fill_bytes(&mut nonce_bytes);
    let aad = pending_totp_aad(&enrollment.account_id, &enrollment.factor_id);
    let ciphertext = ChaCha20Poly1305::new(key.into())
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| EphemeralError::invalid_data("cannot encrypt pending TOTP secret"))?;
    let mut envelope = Vec::with_capacity(1 + PENDING_TOTP_NONCE_BYTES + ciphertext.len());
    envelope.push(PENDING_TOTP_ENVELOPE_VERSION);
    envelope.extend_from_slice(&nonce_bytes);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

fn decrypt_pending_totp_secret(
    key: &[u8; 32],
    account_id: &str,
    factor_id: &str,
    envelope: &[u8],
) -> Result<PendingTotpSecretPayload, EphemeralError> {
    if envelope.len() <= 1 + PENDING_TOTP_NONCE_BYTES
        || envelope[0] != PENDING_TOTP_ENVELOPE_VERSION
    {
        return Err(EphemeralError::invalid_data(
            "pending TOTP secret envelope is invalid",
        ));
    }
    let aad = pending_totp_aad(account_id, factor_id);
    let plaintext = ChaCha20Poly1305::new(key.into())
        .decrypt(
            Nonce::from_slice(&envelope[1..1 + PENDING_TOTP_NONCE_BYTES]),
            Payload {
                msg: &envelope[1 + PENDING_TOTP_NONCE_BYTES..],
                aad: &aad,
            },
        )
        .map_err(|_| EphemeralError::invalid_data("pending TOTP secret authentication failed"))?;
    let payload: PendingTotpSecretPayload = serde_json::from_slice(&plaintext)
        .map_err(|_| EphemeralError::invalid_data("cannot decode pending TOTP secret"))?;
    Ok(payload)
}

fn pending_totp_aad(account_id: &str, factor_id: &str) -> Vec<u8> {
    canonical_fields(
        "rctl-pending-totp-enrollment-v1",
        &[
            ("account_id", account_id.as_bytes()),
            ("factor_id", factor_id.as_bytes()),
        ],
    )
}

fn hashed_key(scope: &str, value: &str) -> String {
    format!("{KEY_PREFIX}:{scope}:{}", sha256_hex(value.as_bytes()))
}

fn signal_account_presence_key(account_id: &str) -> String {
    format!("{SIGNAL_KEY_PREFIX}:presence:account:{account_id}")
}

fn signal_device_presence_key(account_id: &str, device_id: &str) -> String {
    format!("{SIGNAL_KEY_PREFIX}:presence:device:{account_id}:{device_id}")
}

fn device_presence_from_fields(
    account_id: &str,
    indexed_device_id: &str,
    fields: (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ),
) -> Result<DevicePresence, EphemeralError> {
    let stored_account_id = presence_field(fields.0, "account_id")?;
    let device_id = presence_field(fields.1, "device_id")?;
    if stored_account_id != account_id || device_id != indexed_device_id {
        return Err(EphemeralError::invalid_data(
            "Redis presence identity does not match its account index",
        ));
    }
    let status = match presence_field(fields.2, "status")?.as_str() {
        "online" => DevicePresenceStatus::Online,
        "busy" => DevicePresenceStatus::Busy,
        _ => {
            return Err(EphemeralError::invalid_data(
                "Redis presence status must be online or busy",
            ));
        }
    };
    let last_seen_epoch_millis = presence_field(fields.3, "last_seen_epoch_millis")?
        .parse()
        .map_err(|_| EphemeralError::invalid_data("invalid Redis last_seen_epoch_millis"))?;
    Ok(DevicePresence {
        device_id,
        status,
        last_seen_epoch_millis,
    })
}

fn presence_field(value: Option<String>, field: &'static str) -> Result<String, EphemeralError> {
    value.ok_or_else(|| EphemeralError::invalid_data(format!("Redis presence is missing {field}")))
}

fn challenge_kind_and_purpose(purpose: &ChallengePurpose) -> (&'static str, &str) {
    match purpose {
        ChallengePurpose::LoginMfa => ("login", "login_mfa"),
        ChallengePurpose::StepUp(purpose) => ("step_up", purpose),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MFA_SECRET_KEY: [u8; 32] = [0x42; 32];

    fn login_challenge(id: &str, now: u64, attempts: u8) -> AuthChallenge {
        AuthChallenge {
            challenge_id: id.to_owned(),
            account_id: "account-1".to_owned(),
            device_id: None,
            purpose: ChallengePurpose::LoginMfa,
            operation_binding_hash: None,
            login: None,
            attempts_remaining: attempts,
            expires_at_epoch_millis: now + 300_000,
            verified_at_epoch_millis: None,
            consumed_at_epoch_millis: None,
        }
    }

    fn step_up_challenge(id: &str, now: u64) -> AuthChallenge {
        AuthChallenge {
            challenge_id: id.to_owned(),
            account_id: "account-1".to_owned(),
            device_id: Some("device-1".to_owned()),
            purpose: ChallengePurpose::StepUp("device_key_rotation".to_owned()),
            operation_binding_hash: Some("binding-1".to_owned()),
            login: None,
            attempts_remaining: 5,
            expires_at_epoch_millis: now + 300_000,
            verified_at_epoch_millis: None,
            consumed_at_epoch_millis: None,
        }
    }

    fn pending_totp_enrollment(
        account_id: &str,
        factor_id: &str,
        now: u64,
        attempts_remaining: u8,
    ) -> PendingTotpEnrollment {
        PendingTotpEnrollment {
            factor_id: factor_id.to_owned(),
            account_id: account_id.to_owned(),
            secret_base32: format!("SECRET-{factor_id}"),
            recovery_delivery_public_key: [0x42; 32],
            created_at_epoch_millis: now,
            expires_at_epoch_millis: now + 300_000,
            attempts_remaining,
        }
    }

    async fn verify_ephemeral_contract(state: &dyn EphemeralState) {
        let now = 1_000_000;
        assert!(state
            .record_nonce("nonce-1", now, 60_000)
            .await
            .expect("first nonce"));
        assert!(!state
            .record_nonce("nonce-1", now, 60_000)
            .await
            .expect("replayed nonce"));

        for _ in 0..4 {
            let status = state
                .record_login_failure("account-1", now, 5, 60_000, 900_000)
                .await
                .expect("login failure");
            assert!(!status.newly_locked);
        }
        let locked = state
            .record_login_failure("account-1", now, 5, 60_000, 900_000)
            .await
            .expect("locking failure");
        assert!(locked.newly_locked);
        assert!(state
            .login_failure_state("account-1", now)
            .await
            .expect("login state")
            .is_locked_at(now));
        state
            .clear_login_failures("account-1")
            .await
            .expect("clear failures");

        let challenge = login_challenge("login-1", now, 2);
        assert!(state
            .put_challenge(&challenge)
            .await
            .expect("put challenge"));
        let ChallengeAttemptStart::Started(attempt) = state
            .begin_challenge_attempt("login-1", ExpectedChallengeKind::Login, now)
            .await
            .expect("begin challenge")
        else {
            panic!("challenge should start");
        };
        let failed = state
            .finish_challenge_attempt(&attempt, false, true, now)
            .await
            .expect("finish failed attempt")
            .expect("challenge remains");
        assert_eq!(failed.attempts_remaining, 1);

        let ChallengeAttemptStart::Started(attempt) = state
            .begin_challenge_attempt("login-1", ExpectedChallengeKind::Login, now)
            .await
            .expect("begin challenge again")
        else {
            panic!("challenge should start again");
        };
        let consumed = state
            .finish_challenge_attempt(&attempt, true, true, now)
            .await
            .expect("finish successful attempt")
            .expect("challenge remains until TTL");
        assert_eq!(consumed.consumed_at_epoch_millis, Some(now));
        assert!(matches!(
            state
                .begin_challenge_attempt("login-1", ExpectedChallengeKind::Login, now)
                .await
                .expect("consumed challenge result"),
            ChallengeAttemptStart::Rejected { .. }
        ));

        let challenge = step_up_challenge("step-up-1", now);
        assert!(state.put_challenge(&challenge).await.expect("put step-up"));
        let ChallengeAttemptStart::Started(attempt) = state
            .begin_challenge_attempt("step-up-1", ExpectedChallengeKind::StepUp, now)
            .await
            .expect("begin step-up")
        else {
            panic!("step-up should start");
        };
        state
            .finish_challenge_attempt(&attempt, true, false, now)
            .await
            .expect("verify step-up")
            .expect("step-up remains until TTL");
        let binding = StepUpConsumption {
            challenge_id: "step-up-1",
            account_id: "account-1",
            device_id: "device-1",
            purpose: "device_key_rotation",
            operation_binding_hash: "binding-1",
        };
        assert!(state
            .consume_step_up(&binding, now)
            .await
            .expect("first consumption"));
        assert!(!state
            .consume_step_up(&binding, now)
            .await
            .expect("replayed consumption"));
    }

    #[tokio::test]
    async fn memory_backend_enforces_ephemeral_security_contract() {
        verify_ephemeral_contract(&MemoryEphemeralState::default()).await;
    }

    #[tokio::test]
    async fn memory_backend_returns_no_signal_presence() {
        let presence = MemoryEphemeralState::default()
            .list_device_presence("account-1")
            .await
            .expect("memory presence query");
        assert!(presence.is_empty());
    }

    #[tokio::test]
    async fn memory_pending_totp_enrollment_is_first_writer_wins_until_expired() {
        let state = MemoryEphemeralState::default();
        let now = 1_000_000;
        let first = pending_totp_enrollment("account-1", "factor-1", now, 3);
        let second = pending_totp_enrollment("account-1", "factor-2", now + 1, 3);

        assert!(state
            .put_pending_totp_enrollment(&first, now)
            .await
            .expect("put first enrollment"));
        assert!(!state
            .put_pending_totp_enrollment(&second, now + 1)
            .await
            .expect("reject concurrent enrollment"));
        assert!(state
            .begin_pending_totp_enrollment_attempt("account-1", "factor-2", now + 1)
            .await
            .expect("check rejected enrollment")
            .is_none());
        let attempt = state
            .begin_pending_totp_enrollment_attempt("account-1", "factor-1", now + 1)
            .await
            .expect("begin first enrollment")
            .expect("first enrollment remains active");
        assert_eq!(attempt.enrollment, first);
        assert!(state
            .abort_pending_totp_enrollment_attempt(&attempt)
            .await
            .expect("abort first attempt"));
        assert!(!state
            .remove_pending_totp_enrollment("account-1", "factor-2")
            .await
            .expect("reject stale factor removal"));

        assert!(state
            .put_pending_totp_enrollment(&second, first.expires_at_epoch_millis)
            .await
            .expect("replace expired enrollment"));
        assert!(state
            .begin_pending_totp_enrollment_attempt(
                "account-1",
                "factor-1",
                first.expires_at_epoch_millis,
            )
            .await
            .expect("check expired enrollment")
            .is_none());
        assert!(state
            .remove_pending_totp_enrollment("account-1", "factor-2")
            .await
            .expect("remove replacement enrollment"));
    }

    #[tokio::test]
    async fn memory_pending_totp_attempts_are_leased_and_limited() {
        let state = MemoryEphemeralState::default();
        let now = 1_000_000;
        let enrollment = pending_totp_enrollment("account-1", "factor-1", now, 2);
        assert!(state
            .put_pending_totp_enrollment(&enrollment, now)
            .await
            .expect("put enrollment"));

        let first = state
            .begin_pending_totp_enrollment_attempt("account-1", "factor-1", now)
            .await
            .expect("begin first attempt")
            .expect("first attempt starts");
        assert!(state
            .begin_pending_totp_enrollment_attempt("account-1", "factor-1", now)
            .await
            .expect("begin concurrent attempt")
            .is_none());
        assert!(state
            .abort_pending_totp_enrollment_attempt(&first)
            .await
            .expect("abort first attempt"));
        assert!(!state
            .abort_pending_totp_enrollment_attempt(&first)
            .await
            .expect("reject repeated abort"));

        let second = state
            .begin_pending_totp_enrollment_attempt("account-1", "factor-1", now)
            .await
            .expect("begin second attempt")
            .expect("second attempt starts after abort");
        let failed = state
            .finish_pending_totp_enrollment_attempt(&second, false, now)
            .await
            .expect("finish failed attempt")
            .expect("failed attempt owns lease");
        assert_eq!(failed.attempts_remaining, 1);
        assert!(state
            .finish_pending_totp_enrollment_attempt(&second, false, now)
            .await
            .expect("reject replayed finish")
            .is_none());

        let final_attempt = state
            .begin_pending_totp_enrollment_attempt("account-1", "factor-1", now)
            .await
            .expect("begin final attempt")
            .expect("one attempt remains");
        let exhausted = state
            .finish_pending_totp_enrollment_attempt(&final_attempt, false, now)
            .await
            .expect("finish final failed attempt")
            .expect("final attempt owns lease");
        assert_eq!(exhausted.attempts_remaining, 0);
        assert!(state
            .begin_pending_totp_enrollment_attempt("account-1", "factor-1", now)
            .await
            .expect("check exhausted enrollment")
            .is_none());
    }

    #[tokio::test]
    async fn memory_pending_totp_expired_lease_cannot_consume_new_attempt() {
        let state = MemoryEphemeralState::default();
        let now = 1_000_000;
        let enrollment = pending_totp_enrollment("account-1", "factor-1", now, 3);
        assert!(state
            .put_pending_totp_enrollment(&enrollment, now)
            .await
            .expect("put enrollment"));
        let expired_attempt = state
            .begin_pending_totp_enrollment_attempt("account-1", "factor-1", now)
            .await
            .expect("begin expiring attempt")
            .expect("attempt starts");
        let lease_expired_at = now + ATTEMPT_LEASE_MILLIS;
        let current_attempt = state
            .begin_pending_totp_enrollment_attempt("account-1", "factor-1", lease_expired_at)
            .await
            .expect("begin after lease expiry")
            .expect("new attempt starts");
        assert!(state
            .finish_pending_totp_enrollment_attempt(&expired_attempt, true, lease_expired_at)
            .await
            .expect("reject expired attempt")
            .is_none());
        assert!(state
            .finish_pending_totp_enrollment_attempt(&current_attempt, true, lease_expired_at)
            .await
            .expect("consume current attempt")
            .is_some());
        assert!(state
            .begin_pending_totp_enrollment_attempt("account-1", "factor-1", lease_expired_at,)
            .await
            .expect("check consumed enrollment")
            .is_none());
    }

    #[tokio::test]
    async fn memory_pending_totp_expired_enrollment_is_rejected() {
        let state = MemoryEphemeralState::default();
        let now = 1_000_000;
        let mut enrollment = pending_totp_enrollment("account-1", "factor-1", now, 3);
        enrollment.expires_at_epoch_millis = now + 1;
        assert!(state
            .put_pending_totp_enrollment(&enrollment, now)
            .await
            .expect("put enrollment"));
        assert!(state
            .begin_pending_totp_enrollment_attempt("account-1", "factor-1", now + 1)
            .await
            .expect("begin expired enrollment")
            .is_none());
    }

    #[test]
    fn pending_totp_secret_encryption_binds_account_and_factor() {
        let enrollment = pending_totp_enrollment("account-1", "factor-1", 1_000_000, 3);
        let encrypted = encrypt_pending_totp_secret(&TEST_MFA_SECRET_KEY, &enrollment)
            .expect("encrypt pending TOTP secret");
        assert!(!encrypted
            .windows(enrollment.secret_base32.len())
            .any(|window| window == enrollment.secret_base32.as_bytes()));
        let decrypted = decrypt_pending_totp_secret(
            &TEST_MFA_SECRET_KEY,
            &enrollment.account_id,
            &enrollment.factor_id,
            &encrypted,
        )
        .expect("decrypt pending TOTP secret");
        assert_eq!(decrypted.secret_base32, enrollment.secret_base32);
        assert_eq!(
            decrypted.recovery_delivery_public_key,
            enrollment.recovery_delivery_public_key
        );
        assert!(decrypt_pending_totp_secret(
            &TEST_MFA_SECRET_KEY,
            "account-2",
            &enrollment.factor_id,
            &encrypted,
        )
        .is_err());
        assert!(decrypt_pending_totp_secret(
            &TEST_MFA_SECRET_KEY,
            &enrollment.account_id,
            "factor-2",
            &encrypted,
        )
        .is_err());
    }

    #[test]
    fn presence_fields_accept_only_complete_online_or_busy_records() {
        assert_eq!(
            device_presence_from_fields(
                "account-1",
                "device-1",
                (
                    Some("account-1".to_owned()),
                    Some("device-1".to_owned()),
                    Some("online".to_owned()),
                    Some("123".to_owned()),
                ),
            )
            .expect("valid online presence"),
            DevicePresence {
                device_id: "device-1".to_owned(),
                status: DevicePresenceStatus::Online,
                last_seen_epoch_millis: 123,
            }
        );
        assert!(device_presence_from_fields(
            "account-1",
            "device-1",
            (
                Some("account-1".to_owned()),
                Some("device-1".to_owned()),
                Some("offline".to_owned()),
                Some("123".to_owned()),
            ),
        )
        .is_err());
        assert!(device_presence_from_fields(
            "account-1",
            "device-1",
            (
                Some("account-1".to_owned()),
                Some("device-1".to_owned()),
                Some("busy".to_owned()),
                None,
            ),
        )
        .is_err());
    }

    #[tokio::test]
    async fn invalid_redis_url_is_rejected_without_fallback() {
        assert!(
            RedisEphemeralState::connect("http://not-redis", TEST_MFA_SECRET_KEY)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    #[ignore = "requires Redis in API_TEST_REDIS_URL or at 127.0.0.1:16379"]
    async fn redis_backend_enforces_nonce_challenge_and_login_lock_contract() {
        let url = std::env::var("API_TEST_REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:16379/0".to_owned());
        let state = RedisEphemeralState::connect(&url, TEST_MFA_SECRET_KEY)
            .await
            .expect("connect test Redis");
        let suffix = random_uuid_v4();
        let now = crate::security::now_epoch_millis();

        assert!(state
            .record_nonce(&format!("nonce-{suffix}"), now, 60_000)
            .await
            .expect("first nonce"));
        assert!(!state
            .record_nonce(&format!("nonce-{suffix}"), now, 60_000)
            .await
            .expect("replayed nonce"));

        let account_id = format!("account-{suffix}");
        for _ in 0..4 {
            state
                .record_login_failure(&account_id, now, 5, 60_000, 900_000)
                .await
                .expect("login failure");
        }
        assert!(
            state
                .record_login_failure(&account_id, now, 5, 60_000, 900_000)
                .await
                .expect("account lock")
                .newly_locked
        );

        let mut challenge = login_challenge(&format!("challenge-{suffix}"), now, 2);
        challenge.account_id = account_id;
        assert!(state
            .put_challenge(&challenge)
            .await
            .expect("put challenge"));
        let ChallengeAttemptStart::Started(attempt) = state
            .begin_challenge_attempt(&challenge.challenge_id, ExpectedChallengeKind::Login, now)
            .await
            .expect("begin attempt")
        else {
            panic!("challenge should start");
        };
        assert_eq!(
            state
                .finish_challenge_attempt(&attempt, false, true, now)
                .await
                .expect("finish attempt")
                .expect("challenge exists")
                .attempts_remaining,
            1
        );
        let ChallengeAttemptStart::Started(attempt) = state
            .begin_challenge_attempt(&challenge.challenge_id, ExpectedChallengeKind::Login, now)
            .await
            .expect("begin second attempt")
        else {
            panic!("challenge should start a second time");
        };
        state
            .finish_challenge_attempt(&attempt, true, true, now)
            .await
            .expect("consume challenge")
            .expect("challenge exists");
        assert!(matches!(
            state
                .begin_challenge_attempt(
                    &challenge.challenge_id,
                    ExpectedChallengeKind::Login,
                    now,
                )
                .await
                .expect("replay result"),
            ChallengeAttemptStart::Rejected { .. }
        ));

        let mut step_up = step_up_challenge(&format!("step-up-{suffix}"), now);
        step_up.account_id = challenge.account_id.clone();
        assert!(state
            .put_challenge(&step_up)
            .await
            .expect("put step-up challenge"));
        let ChallengeAttemptStart::Started(attempt) = state
            .begin_challenge_attempt(&step_up.challenge_id, ExpectedChallengeKind::StepUp, now)
            .await
            .expect("begin step-up attempt")
        else {
            panic!("step-up challenge should start");
        };
        state
            .finish_challenge_attempt(&attempt, true, false, now)
            .await
            .expect("verify step-up")
            .expect("verified step-up exists");
        let binding = StepUpConsumption {
            challenge_id: &step_up.challenge_id,
            account_id: &step_up.account_id,
            device_id: "device-1",
            purpose: "device_key_rotation",
            operation_binding_hash: "binding-1",
        };
        assert!(state
            .consume_step_up(&binding, now)
            .await
            .expect("consume step-up"));
        assert!(!state
            .consume_step_up(&binding, now)
            .await
            .expect("reject step-up replay"));

        let expired = AuthChallenge {
            challenge_id: format!("expired-{suffix}"),
            expires_at_epoch_millis: now.saturating_sub(1),
            ..login_challenge("unused", now, 1)
        };
        state
            .put_challenge(&expired)
            .await
            .expect("put expired challenge");
        assert!(matches!(
            state
                .begin_challenge_attempt(&expired.challenge_id, ExpectedChallengeKind::Login, now,)
                .await
                .expect("expired result"),
            ChallengeAttemptStart::Rejected { .. }
        ));
    }

    #[tokio::test]
    #[ignore = "requires Redis in API_TEST_REDIS_URL or at 127.0.0.1:16379"]
    async fn redis_pending_totp_is_encrypted_and_leased_across_instances() {
        let url = std::env::var("API_TEST_REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:16379/0".to_owned());
        let first_instance = RedisEphemeralState::connect(&url, TEST_MFA_SECRET_KEY)
            .await
            .expect("connect first test Redis instance");
        let second_instance = RedisEphemeralState::connect(&url, TEST_MFA_SECRET_KEY)
            .await
            .expect("connect second test Redis instance");
        let suffix = random_uuid_v4();
        let account_id = format!("pending-totp-account-{suffix}");
        let factor_id = format!("pending-totp-factor-{suffix}");
        let competing_factor_id = format!("pending-totp-competing-{suffix}");
        let now = crate::security::now_epoch_millis();
        let enrollment = pending_totp_enrollment(&account_id, &factor_id, now, 3);
        let competing = pending_totp_enrollment(&account_id, &competing_factor_id, now + 1, 3);

        assert!(first_instance
            .put_pending_totp_enrollment(&enrollment, now)
            .await
            .expect("put pending enrollment"));
        assert!(!second_instance
            .put_pending_totp_enrollment(&competing, now + 1)
            .await
            .expect("reject competing enrollment"));

        let key = RedisEphemeralState::pending_totp_enrollment_key(&account_id);
        let mut connection = first_instance.connection.clone();
        let fields: Vec<(Vec<u8>, Vec<u8>)> = redis::cmd("HGETALL")
            .arg(&key)
            .query_async(&mut connection)
            .await
            .expect("read pending enrollment hash");
        assert!(!fields.iter().any(|(_, value)| {
            value
                .windows(enrollment.secret_base32.len())
                .any(|window| window == enrollment.secret_base32.as_bytes())
        }));

        let first_attempt = second_instance
            .begin_pending_totp_enrollment_attempt(&account_id, &factor_id, now)
            .await
            .expect("begin cross-instance attempt")
            .expect("pending enrollment is shared");
        assert_eq!(first_attempt.enrollment, enrollment);
        assert!(first_instance
            .begin_pending_totp_enrollment_attempt(&account_id, &factor_id, now)
            .await
            .expect("begin concurrent attempt")
            .is_none());
        assert!(first_instance
            .abort_pending_totp_enrollment_attempt(&first_attempt)
            .await
            .expect("abort attempt from another instance"));

        let failed_attempt = first_instance
            .begin_pending_totp_enrollment_attempt(&account_id, &factor_id, now)
            .await
            .expect("begin failed attempt")
            .expect("lease was released");
        let failed = second_instance
            .finish_pending_totp_enrollment_attempt(&failed_attempt, false, now)
            .await
            .expect("finish failed attempt from another instance")
            .expect("failed attempt owns lease");
        assert_eq!(failed.attempts_remaining, 2);
        assert!(!first_instance
            .remove_pending_totp_enrollment(&account_id, &competing_factor_id)
            .await
            .expect("reject stale factor removal"));

        let accepted_attempt = second_instance
            .begin_pending_totp_enrollment_attempt(&account_id, &factor_id, now)
            .await
            .expect("begin accepted attempt")
            .expect("attempt remains after one failure");
        assert!(first_instance
            .finish_pending_totp_enrollment_attempt(&accepted_attempt, true, now)
            .await
            .expect("consume enrollment from another instance")
            .is_some());
        assert!(second_instance
            .begin_pending_totp_enrollment_attempt(&account_id, &factor_id, now)
            .await
            .expect("check consumed enrollment")
            .is_none());

        let mut expiring = pending_totp_enrollment(
            &account_id,
            &format!("pending-totp-expiring-{suffix}"),
            now,
            3,
        );
        expiring.expires_at_epoch_millis = now + 60_000;
        let replacement = pending_totp_enrollment(
            &account_id,
            &format!("pending-totp-replacement-{suffix}"),
            expiring.expires_at_epoch_millis,
            3,
        );
        assert!(first_instance
            .put_pending_totp_enrollment(&expiring, now)
            .await
            .expect("put expiring enrollment"));
        assert!(second_instance
            .put_pending_totp_enrollment(&replacement, expiring.expires_at_epoch_millis)
            .await
            .expect("replace expired enrollment"));
        assert!(first_instance
            .remove_pending_totp_enrollment(&account_id, &replacement.factor_id)
            .await
            .expect("clean up replacement enrollment"));
    }

    #[tokio::test]
    #[ignore = "requires Redis in API_TEST_REDIS_URL or at 127.0.0.1:16379"]
    async fn redis_backend_reads_signal_presence_without_cleaning_stale_index_entries() {
        let url = std::env::var("API_TEST_REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:16379/0".to_owned());
        let state = RedisEphemeralState::connect(&url, TEST_MFA_SECRET_KEY)
            .await
            .expect("connect test Redis");
        let suffix = random_uuid_v4();
        let account_id = format!("presence-account-{suffix}");
        let online_device_id = format!("device-online-{suffix}");
        let busy_device_id = format!("device-busy-{suffix}");
        let stale_device_id = format!("device-stale-{suffix}");
        let malformed_device_id = format!("device-malformed-{suffix}");
        let account_key = signal_account_presence_key(&account_id);
        let online_key = signal_device_presence_key(&account_id, &online_device_id);
        let busy_key = signal_device_presence_key(&account_id, &busy_device_id);
        let malformed_key = signal_device_presence_key(&account_id, &malformed_device_id);
        let mut connection = state.connection.clone();

        redis::pipe()
            .atomic()
            .cmd("SADD")
            .arg(&account_key)
            .arg(&online_device_id)
            .arg(&busy_device_id)
            .arg(&stale_device_id)
            .ignore()
            .cmd("HSET")
            .arg(&online_key)
            .arg("account_id")
            .arg(&account_id)
            .arg("device_id")
            .arg(&online_device_id)
            .arg("status")
            .arg("online")
            .arg("last_seen_epoch_millis")
            .arg(101_u64)
            .arg("connection_id")
            .arg("must-not-be-returned")
            .arg("public_key_id")
            .arg("must-not-be-returned")
            .ignore()
            .cmd("HSET")
            .arg(&busy_key)
            .arg("account_id")
            .arg(&account_id)
            .arg("device_id")
            .arg(&busy_device_id)
            .arg("status")
            .arg("busy")
            .arg("last_seen_epoch_millis")
            .arg(202_u64)
            .ignore()
            .cmd("PEXPIRE")
            .arg(&account_key)
            .arg(60_000_u64)
            .ignore()
            .cmd("PEXPIRE")
            .arg(&online_key)
            .arg(60_000_u64)
            .ignore()
            .cmd("PEXPIRE")
            .arg(&busy_key)
            .arg(60_000_u64)
            .ignore()
            .query_async::<()>(&mut connection)
            .await
            .expect("seed Signal presence fixture");

        let presence = state
            .list_device_presence(&account_id)
            .await
            .expect("list Signal presence");
        assert_eq!(
            presence,
            vec![
                DevicePresence {
                    device_id: busy_device_id.clone(),
                    status: DevicePresenceStatus::Busy,
                    last_seen_epoch_millis: 202,
                },
                DevicePresence {
                    device_id: online_device_id.clone(),
                    status: DevicePresenceStatus::Online,
                    last_seen_epoch_millis: 101,
                },
            ]
        );
        let stale_still_indexed: bool = redis::cmd("SISMEMBER")
            .arg(&account_key)
            .arg(&stale_device_id)
            .query_async(&mut connection)
            .await
            .expect("check stale Signal index entry");
        assert!(stale_still_indexed);

        redis::pipe()
            .atomic()
            .cmd("SADD")
            .arg(&account_key)
            .arg(&malformed_device_id)
            .ignore()
            .cmd("HSET")
            .arg(&malformed_key)
            .arg("account_id")
            .arg(&account_id)
            .arg("device_id")
            .arg(&malformed_device_id)
            .arg("status")
            .arg("offline")
            .arg("last_seen_epoch_millis")
            .arg(303_u64)
            .ignore()
            .cmd("PEXPIRE")
            .arg(&malformed_key)
            .arg(60_000_u64)
            .ignore()
            .query_async::<()>(&mut connection)
            .await
            .expect("seed malformed Signal presence fixture");
        assert!(state.list_device_presence(&account_id).await.is_err());

        redis::cmd("DEL")
            .arg(&account_key)
            .arg(&online_key)
            .arg(&busy_key)
            .arg(&malformed_key)
            .query_async::<u64>(&mut connection)
            .await
            .expect("clean up Signal presence fixture");
    }
}
