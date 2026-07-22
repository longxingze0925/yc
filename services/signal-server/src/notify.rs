use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot, OwnedRwLockReadGuard, RwLock};

const DEFAULT_NOTIFICATION_QUEUE_CAPACITY: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EnqueueError {
    Offline,
    Overloaded,
}

struct ConnectionEntry {
    connection_id: String,
    notifications: mpsc::Sender<String>,
    superseded: Option<oneshot::Sender<()>>,
}

type ConnectionMap = HashMap<String, ConnectionEntry>;

pub(super) struct ConnectionRegistration {
    pub(super) notifications: mpsc::Receiver<String>,
    pub(super) superseded: oneshot::Receiver<()>,
}

pub(super) struct OwnershipGuard {
    _connections: OwnedRwLockReadGuard<ConnectionMap>,
}

#[derive(Clone)]
pub(super) struct ConnectionRegistry {
    connections: Arc<RwLock<ConnectionMap>>,
    queue_capacity: usize,
}

impl Default for ConnectionRegistry {
    fn default() -> Self {
        Self::new(DEFAULT_NOTIFICATION_QUEUE_CAPACITY)
    }
}

impl ConnectionRegistry {
    pub(super) fn new(queue_capacity: usize) -> Self {
        assert!(
            queue_capacity > 0,
            "notification queue must be bounded and non-empty"
        );
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            queue_capacity,
        }
    }

    pub(super) async fn register(
        &self,
        device_id: &str,
        connection_id: &str,
    ) -> ConnectionRegistration {
        let (notification_sender, notifications) = mpsc::channel(self.queue_capacity);
        let (superseded_sender, superseded) = oneshot::channel();
        let entry = ConnectionEntry {
            connection_id: connection_id.to_owned(),
            notifications: notification_sender,
            superseded: Some(superseded_sender),
        };

        let previous = self
            .connections
            .write()
            .await
            .insert(device_id.to_owned(), entry);
        if let Some(mut previous) = previous {
            if let Some(superseded) = previous.superseded.take() {
                let _ = superseded.send(());
            }
        }

        ConnectionRegistration {
            notifications,
            superseded,
        }
    }

    pub(super) async fn enqueue(
        &self,
        device_id: &str,
        notification: String,
    ) -> Result<(), EnqueueError> {
        let connections = self.connections.read().await;
        let Some(connection) = connections.get(device_id) else {
            return Err(EnqueueError::Offline);
        };
        connection
            .notifications
            .try_send(notification)
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => EnqueueError::Overloaded,
                mpsc::error::TrySendError::Closed(_) => EnqueueError::Offline,
            })
    }

    pub(super) async fn acquire_ownership(
        &self,
        device_id: &str,
        connection_id: &str,
    ) -> Option<OwnershipGuard> {
        let connections = self.connections.clone().read_owned().await;
        let is_owner = connections
            .get(device_id)
            .is_some_and(|connection| connection.connection_id == connection_id);
        is_owner.then_some(OwnershipGuard {
            _connections: connections,
        })
    }

    pub(super) async fn unregister(&self, device_id: &str, connection_id: &str) -> bool {
        let mut connections = self.connections.write().await;
        let is_owner = connections
            .get(device_id)
            .is_some_and(|connection| connection.connection_id == connection_id);
        if !is_owner {
            return false;
        }
        if let Some(mut connection) = connections.remove(device_id) {
            if let Some(superseded) = connection.superseded.take() {
                let _ = superseded.send(());
            }
        }
        true
    }

    #[cfg(test)]
    pub(super) async fn is_owner(&self, device_id: &str, connection_id: &str) -> bool {
        self.connections
            .read()
            .await
            .get(device_id)
            .is_some_and(|connection| connection.connection_id == connection_id)
    }
}
