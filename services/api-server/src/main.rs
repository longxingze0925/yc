use std::net::SocketAddr;
use std::sync::Arc;

use api_server::{
    build_router, AppConfig, AppState, EphemeralState, PostgresRepository, RedisEphemeralState,
    Repository, SignalNotifier, StorageBackend,
};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("api_server=info,tower_http=info")),
        )
        .init();

    let config = AppConfig::from_env()?;
    let notifier =
        SignalNotifier::new(config.signal_push_url.clone(), config.service_token.clone());
    let repository: Arc<dyn Repository> = match config.storage_backend {
        StorageBackend::Memory => {
            return Err(std::io::Error::other("memory storage is test-only").into());
        }
        StorageBackend::Postgres => {
            let database_url = config
                .database_url
                .as_deref()
                .ok_or_else(|| std::io::Error::other("DATABASE_URL is required"))?;
            let mfa_secret_key = config
                .mfa_secret_key
                .ok_or_else(|| std::io::Error::other("REMOTE_MFA_SECRET_KEY is required"))?;
            Arc::new(
                PostgresRepository::connect(database_url, mfa_secret_key)
                    .await
                    .map_err(std::io::Error::other)?,
            )
        }
    };
    let redis_url = config
        .redis_url
        .as_deref()
        .ok_or_else(|| std::io::Error::other("REDIS_URL is required"))?;
    let mfa_secret_key = config
        .mfa_secret_key
        .ok_or_else(|| std::io::Error::other("REMOTE_MFA_SECRET_KEY is required"))?;
    let ephemeral: Arc<dyn EphemeralState> = Arc::new(
        RedisEphemeralState::connect(redis_url, mfa_secret_key)
            .await
            .map_err(std::io::Error::other)?,
    );
    let storage = repository.backend_name();
    let ephemeral_backend = ephemeral.backend_name();
    let state = AppState::with_ephemeral(repository, ephemeral, config.clone(), notifier);
    let listener = TcpListener::bind(config.bind).await?;

    info!(address = %config.bind, storage, ephemeral_backend, "api-server listening");
    axum::serve(
        listener,
        build_router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
