use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use remote_protocol::DeviceStatus;
use tokio::sync::{Mutex, RwLock};

use super::{security::decode_array, OnlineDevice};

const KEY_PREFIX: &str = "rctl:signal:v1";
pub(super) const PRESENCE_TTL_MILLIS: u64 = 90_000;
const MAX_MEMORY_REPLAY_ENTRIES: usize = 10_000;
const REDIS_CONNECTION_TIMEOUT: Duration = Duration::from_secs(3);
const REDIS_RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);
const REDIS_CONNECTION_RETRIES: usize = 3;

type PresenceIdentity = (String, String);
type MemoryReplayKey = (String, String, [u8; 32]);
type MemoryReplayCache = HashMap<MemoryReplayKey, u64>;

const UPDATE_PRESENCE_SCRIPT: &str = r#"
local connection_id = redis.call('HGET', KEYS[1], 'connection_id')
if not connection_id then
    return 0
end
if connection_id ~= ARGV[1] then
    return -1
end
redis.call('HSET', KEYS[1], 'status', ARGV[2], 'last_seen_epoch_millis', ARGV[3])
redis.call('SADD', KEYS[2], ARGV[4])
redis.call('PEXPIRE', KEYS[1], ARGV[5])
redis.call('PEXPIRE', KEYS[2], ARGV[5])
return 1
"#;

const REFRESH_PRESENCE_SCRIPT: &str = r#"
local connection_id = redis.call('HGET', KEYS[1], 'connection_id')
if not connection_id then
    return 0
end
if connection_id ~= ARGV[1] then
    return -1
end
redis.call('SADD', KEYS[2], ARGV[2])
redis.call('PEXPIRE', KEYS[1], ARGV[3])
redis.call('PEXPIRE', KEYS[2], ARGV[3])
return 1
"#;

const REMOVE_PRESENCE_SCRIPT: &str = r#"
local connection_id = redis.call('HGET', KEYS[1], 'connection_id')
if not connection_id or connection_id ~= ARGV[1] then
    return 0
end
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[2])
return 1
"#;

#[derive(Debug)]
pub(super) struct BackendError(String);

impl BackendError {
    fn invalid_data(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for BackendError {}

impl From<redis::RedisError> for BackendError {
    fn from(error: redis::RedisError) -> Self {
        Self(format!("Redis operation failed: {error}"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PresenceMutation {
    Updated,
    Missing,
    Superseded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReplayRecord {
    Recorded,
    Duplicate,
    Full,
}

#[derive(Clone)]
pub(super) enum StateBackend {
    Redis(RedisBackend),
    Memory(Arc<MemoryBackend>),
}

impl StateBackend {
    pub(super) async fn connect_redis(url: &str) -> Result<Self, BackendError> {
        let client = redis::Client::open(url)
            .map_err(|error| BackendError(format!("invalid REDIS_URL: {error}")))?;
        let connection_config = ConnectionManagerConfig::new()
            .set_number_of_retries(REDIS_CONNECTION_RETRIES)
            .set_max_delay(500)
            .set_connection_timeout(REDIS_CONNECTION_TIMEOUT)
            .set_response_timeout(REDIS_RESPONSE_TIMEOUT);
        let backend = RedisBackend {
            connection: client
                .get_connection_manager_with_config(connection_config)
                .await
                .map_err(|error| BackendError(format!("cannot connect to Redis: {error}")))?,
        };
        backend.health().await?;
        Ok(Self::Redis(backend))
    }

    pub(super) fn memory() -> Self {
        Self::Memory(Arc::new(MemoryBackend::default()))
    }

    pub(super) fn name(&self) -> &'static str {
        match self {
            Self::Redis(_) => "redis",
            Self::Memory(_) => "memory",
        }
    }

    pub(super) async fn health(&self) -> Result<(), BackendError> {
        match self {
            Self::Redis(backend) => backend.health().await,
            Self::Memory(_) => Ok(()),
        }
    }

    pub(super) async fn put_presence(&self, device: OnlineDevice) -> Result<(), BackendError> {
        match self {
            Self::Redis(backend) => backend.put_presence(&device).await,
            Self::Memory(backend) => {
                backend.online.write().await.insert(
                    presence_identity(&device.account_id, &device.device_id),
                    device,
                );
                Ok(())
            }
        }
    }

    pub(super) async fn list_presence(
        &self,
        account_id: &str,
    ) -> Result<Vec<OnlineDevice>, BackendError> {
        match self {
            Self::Redis(backend) => backend.list_presence(account_id).await,
            Self::Memory(backend) => {
                let mut devices = backend
                    .online
                    .read()
                    .await
                    .values()
                    .filter(|device| device.account_id == account_id)
                    .cloned()
                    .collect::<Vec<_>>();
                devices.sort_by(|left, right| left.device_id.cmp(&right.device_id));
                Ok(devices)
            }
        }
    }

    pub(super) async fn update_presence(
        &self,
        account_id: &str,
        device_id: &str,
        connection_id: &str,
        status: DeviceStatus,
        last_seen_epoch_millis: u64,
    ) -> Result<PresenceMutation, BackendError> {
        match self {
            Self::Redis(backend) => {
                backend
                    .update_presence(
                        account_id,
                        device_id,
                        connection_id,
                        status,
                        last_seen_epoch_millis,
                    )
                    .await
            }
            Self::Memory(backend) => {
                let mut online = backend.online.write().await;
                let Some(device) = online.get_mut(&presence_identity(account_id, device_id)) else {
                    return Ok(PresenceMutation::Missing);
                };
                if device.connection_id != connection_id {
                    return Ok(PresenceMutation::Superseded);
                }
                device.status = status;
                device.last_seen_epoch_millis = last_seen_epoch_millis;
                Ok(PresenceMutation::Updated)
            }
        }
    }

    pub(super) async fn refresh_presence(
        &self,
        account_id: &str,
        device_id: &str,
        connection_id: &str,
    ) -> Result<PresenceMutation, BackendError> {
        match self {
            Self::Redis(backend) => {
                backend
                    .refresh_presence(account_id, device_id, connection_id)
                    .await
            }
            Self::Memory(backend) => {
                let online = backend.online.read().await;
                let Some(device) = online.get(&presence_identity(account_id, device_id)) else {
                    return Ok(PresenceMutation::Missing);
                };
                if device.connection_id == connection_id {
                    Ok(PresenceMutation::Updated)
                } else {
                    Ok(PresenceMutation::Superseded)
                }
            }
        }
    }

    pub(super) async fn remove_presence(
        &self,
        account_id: &str,
        device_id: &str,
        connection_id: &str,
    ) -> Result<bool, BackendError> {
        match self {
            Self::Redis(backend) => {
                backend
                    .remove_presence(account_id, device_id, connection_id)
                    .await
            }
            Self::Memory(backend) => {
                let mut online = backend.online.write().await;
                let identity = presence_identity(account_id, device_id);
                if online
                    .get(&identity)
                    .is_some_and(|device| device.connection_id == connection_id)
                {
                    online.remove(&identity);
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }

    pub(super) async fn record_hello_nonce_once(
        &self,
        account_id: &str,
        device_id: &str,
        client_nonce: &[u8; 32],
        expires_at_epoch_millis: u64,
        now_epoch_millis: u64,
    ) -> Result<ReplayRecord, BackendError> {
        match self {
            Self::Redis(backend) => {
                backend
                    .record_hello_nonce_once(
                        account_id,
                        device_id,
                        client_nonce,
                        expires_at_epoch_millis,
                        now_epoch_millis,
                    )
                    .await
            }
            Self::Memory(backend) => {
                let mut replays = backend.hello_replays.lock().await;
                replays.retain(|_, expires_at| *expires_at > now_epoch_millis);
                if replays.len() >= MAX_MEMORY_REPLAY_ENTRIES {
                    return Ok(ReplayRecord::Full);
                }
                let key = (account_id.to_owned(), device_id.to_owned(), *client_nonce);
                if replays.insert(key, expires_at_epoch_millis).is_some() {
                    Ok(ReplayRecord::Duplicate)
                } else {
                    Ok(ReplayRecord::Recorded)
                }
            }
        }
    }

    #[cfg(test)]
    pub(super) async fn online_count(&self) -> Result<usize, BackendError> {
        match self {
            Self::Redis(backend) => backend.online_count().await,
            Self::Memory(backend) => Ok(backend.online.read().await.len()),
        }
    }
}

#[derive(Default)]
pub(super) struct MemoryBackend {
    online: RwLock<HashMap<PresenceIdentity, OnlineDevice>>,
    hello_replays: Mutex<MemoryReplayCache>,
}

#[derive(Clone)]
pub(super) struct RedisBackend {
    connection: ConnectionManager,
}

impl RedisBackend {
    async fn health(&self) -> Result<(), BackendError> {
        let mut connection = self.connection.clone();
        let response: String = redis::cmd("PING").query_async(&mut connection).await?;
        if response == "PONG" {
            Ok(())
        } else {
            Err(BackendError::invalid_data(
                "Redis PING returned an invalid response",
            ))
        }
    }

    async fn put_presence(&self, device: &OnlineDevice) -> Result<(), BackendError> {
        let presence_key = presence_key(&device.account_id, &device.device_id);
        let account_key = account_presence_key(&device.account_id);
        let mut connection = self.connection.clone();
        redis::pipe()
            .atomic()
            .cmd("HSET")
            .arg(&presence_key)
            .arg("account_id")
            .arg(&device.account_id)
            .arg("device_id")
            .arg(&device.device_id)
            .arg("public_key_id")
            .arg(&device.public_key_id)
            .arg("public_key_version")
            .arg(device.public_key_version)
            .arg("public_key")
            .arg(&device.public_key)
            .arg("client_capabilities_hash")
            .arg(&device.client_capabilities_hash)
            .arg("status")
            .arg(device_status_name(device.status))
            .arg("last_seen_epoch_millis")
            .arg(device.last_seen_epoch_millis)
            .arg("connection_id")
            .arg(&device.connection_id)
            .ignore()
            .cmd("PEXPIRE")
            .arg(&presence_key)
            .arg(PRESENCE_TTL_MILLIS)
            .ignore()
            .cmd("SADD")
            .arg(&account_key)
            .arg(&device.device_id)
            .ignore()
            .cmd("PEXPIRE")
            .arg(&account_key)
            .arg(PRESENCE_TTL_MILLIS)
            .ignore()
            .query_async::<()>(&mut connection)
            .await?;
        Ok(())
    }

    async fn list_presence(&self, account_id: &str) -> Result<Vec<OnlineDevice>, BackendError> {
        let account_key = account_presence_key(account_id);
        let mut connection = self.connection.clone();
        let device_ids: Vec<String> = redis::cmd("SMEMBERS")
            .arg(&account_key)
            .query_async(&mut connection)
            .await?;
        let mut devices = Vec::with_capacity(device_ids.len());
        let mut stale_device_ids = Vec::new();
        for device_id in device_ids {
            let values: HashMap<String, String> = redis::cmd("HGETALL")
                .arg(presence_key(account_id, &device_id))
                .query_async(&mut connection)
                .await?;
            if values.is_empty() {
                stale_device_ids.push(device_id);
                continue;
            }
            let device = online_device_from_hash(values)?;
            if device.account_id != account_id || device.device_id != device_id {
                return Err(BackendError::invalid_data(
                    "Redis presence identity does not match its index",
                ));
            }
            devices.push(device);
        }
        if !stale_device_ids.is_empty() {
            redis::cmd("SREM")
                .arg(&account_key)
                .arg(stale_device_ids)
                .query_async::<()>(&mut connection)
                .await?;
        }
        devices.sort_by(|left, right| left.device_id.cmp(&right.device_id));
        Ok(devices)
    }

    async fn update_presence(
        &self,
        account_id: &str,
        device_id: &str,
        connection_id: &str,
        status: DeviceStatus,
        last_seen_epoch_millis: u64,
    ) -> Result<PresenceMutation, BackendError> {
        let mut connection = self.connection.clone();
        let result: i64 = redis::cmd("EVAL")
            .arg(UPDATE_PRESENCE_SCRIPT)
            .arg(2)
            .arg(presence_key(account_id, device_id))
            .arg(account_presence_key(account_id))
            .arg(connection_id)
            .arg(device_status_name(status))
            .arg(last_seen_epoch_millis)
            .arg(device_id)
            .arg(PRESENCE_TTL_MILLIS)
            .query_async(&mut connection)
            .await?;
        presence_mutation(result)
    }

    async fn refresh_presence(
        &self,
        account_id: &str,
        device_id: &str,
        connection_id: &str,
    ) -> Result<PresenceMutation, BackendError> {
        let mut connection = self.connection.clone();
        let result: i64 = redis::cmd("EVAL")
            .arg(REFRESH_PRESENCE_SCRIPT)
            .arg(2)
            .arg(presence_key(account_id, device_id))
            .arg(account_presence_key(account_id))
            .arg(connection_id)
            .arg(device_id)
            .arg(PRESENCE_TTL_MILLIS)
            .query_async(&mut connection)
            .await?;
        presence_mutation(result)
    }

    async fn remove_presence(
        &self,
        account_id: &str,
        device_id: &str,
        connection_id: &str,
    ) -> Result<bool, BackendError> {
        let mut connection = self.connection.clone();
        let removed: i64 = redis::cmd("EVAL")
            .arg(REMOVE_PRESENCE_SCRIPT)
            .arg(2)
            .arg(presence_key(account_id, device_id))
            .arg(account_presence_key(account_id))
            .arg(connection_id)
            .arg(device_id)
            .query_async(&mut connection)
            .await?;
        Ok(removed == 1)
    }

    async fn record_hello_nonce_once(
        &self,
        account_id: &str,
        device_id: &str,
        client_nonce: &[u8; 32],
        expires_at_epoch_millis: u64,
        now_epoch_millis: u64,
    ) -> Result<ReplayRecord, BackendError> {
        let ttl_millis = expires_at_epoch_millis.saturating_sub(now_epoch_millis);
        if ttl_millis == 0 {
            return Ok(ReplayRecord::Duplicate);
        }
        let mut connection = self.connection.clone();
        let result: Option<String> = redis::cmd("SET")
            .arg(replay_key(account_id, device_id, client_nonce))
            .arg("1")
            .arg("NX")
            .arg("PX")
            .arg(ttl_millis)
            .query_async(&mut connection)
            .await?;
        if result.is_some() {
            Ok(ReplayRecord::Recorded)
        } else {
            Ok(ReplayRecord::Duplicate)
        }
    }

    #[cfg(test)]
    async fn online_count(&self) -> Result<usize, BackendError> {
        let mut connection = self.connection.clone();
        let mut cursor = 0_u64;
        let mut count = 0_usize;
        loop {
            let (next_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(format!("{KEY_PREFIX}:presence:device:*"))
                .arg("COUNT")
                .arg(100)
                .query_async(&mut connection)
                .await?;
            count = count.saturating_add(keys.len());
            cursor = next_cursor;
            if cursor == 0 {
                return Ok(count);
            }
        }
    }
}

fn presence_mutation(value: i64) -> Result<PresenceMutation, BackendError> {
    match value {
        1 => Ok(PresenceMutation::Updated),
        0 => Ok(PresenceMutation::Missing),
        -1 => Ok(PresenceMutation::Superseded),
        _ => Err(BackendError::invalid_data(
            "Redis presence script returned an invalid result",
        )),
    }
}

fn online_device_from_hash(
    mut values: HashMap<String, String>,
) -> Result<OnlineDevice, BackendError> {
    let account_id = take_field(&mut values, "account_id")?;
    let device_id = take_field(&mut values, "device_id")?;
    let public_key_id = take_field(&mut values, "public_key_id")?;
    let public_key_version = take_field(&mut values, "public_key_version")?
        .parse()
        .map_err(|_| BackendError::invalid_data("invalid Redis public_key_version"))?;
    let public_key = take_field(&mut values, "public_key")?;
    decode_array::<32>(&public_key)
        .map_err(|_| BackendError::invalid_data("invalid Redis public_key"))?;
    let client_capabilities_hash = take_field(&mut values, "client_capabilities_hash")?;
    let status = parse_device_status(&take_field(&mut values, "status")?)?;
    let last_seen_epoch_millis = take_field(&mut values, "last_seen_epoch_millis")?
        .parse()
        .map_err(|_| BackendError::invalid_data("invalid Redis last_seen_epoch_millis"))?;
    let connection_id = take_field(&mut values, "connection_id")?;
    Ok(OnlineDevice {
        account_id,
        device_id,
        public_key_id,
        public_key_version,
        public_key,
        client_capabilities_hash,
        status,
        last_seen_epoch_millis,
        connection_id,
    })
}

fn take_field(
    values: &mut HashMap<String, String>,
    field: &'static str,
) -> Result<String, BackendError> {
    values
        .remove(field)
        .ok_or_else(|| BackendError::invalid_data(format!("Redis presence is missing {field}")))
}

fn device_status_name(status: DeviceStatus) -> &'static str {
    match status {
        DeviceStatus::Online => "online",
        DeviceStatus::Offline => "offline",
        DeviceStatus::Busy => "busy",
    }
}

fn parse_device_status(value: &str) -> Result<DeviceStatus, BackendError> {
    match value {
        "online" => Ok(DeviceStatus::Online),
        "offline" => Ok(DeviceStatus::Offline),
        "busy" => Ok(DeviceStatus::Busy),
        _ => Err(BackendError::invalid_data("invalid Redis device status")),
    }
}

fn presence_identity(account_id: &str, device_id: &str) -> PresenceIdentity {
    (account_id.to_owned(), device_id.to_owned())
}

fn presence_key(account_id: &str, device_id: &str) -> String {
    format!("{KEY_PREFIX}:presence:device:{account_id}:{device_id}")
}

fn account_presence_key(account_id: &str) -> String {
    format!("{KEY_PREFIX}:presence:account:{account_id}")
}

fn replay_key(account_id: &str, device_id: &str, client_nonce: &[u8; 32]) -> String {
    format!(
        "{KEY_PREFIX}:hello-replay:{account_id}:{device_id}:{}",
        hex(client_nonce)
    )
}

fn hex(value: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}
