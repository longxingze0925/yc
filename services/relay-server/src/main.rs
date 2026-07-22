use relay_server::{run, AppConfig, AppState};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("relay_server=info")),
        )
        .init();

    let config = AppConfig::from_env()?;
    let state = AppState::new(config.clone());
    info!(
        quic_address = %config.quic_bind,
        tls_address = %config.tls_bind,
        health_address = %config.health_bind,
        relay_node_id = %config.relay_node_id,
        transport_modes = "quic_relay,tls_443_relay",
        replay_backend = "memory_single_instance",
        "relay-server starting"
    );
    run(state).await?;
    Ok(())
}
