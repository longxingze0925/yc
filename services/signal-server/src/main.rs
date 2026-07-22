use signal_server::{build_router, AppConfig, AppState};
use tokio::net::TcpListener;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("signal_server=info")),
        )
        .init();

    let config = AppConfig::from_env()?;
    let state = AppState::new(config.clone()).await?;
    let listener = TcpListener::bind(config.bind).await?;
    let backend = state.backend_name();

    info!(
        address = %config.bind,
        online_backend = backend,
        hello_replay_backend = backend,
        "signal-server listening"
    );
    axum::serve(listener, build_router(state)).await?;
    Ok(())
}
