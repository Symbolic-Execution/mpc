use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    let process_config = match mpc::config::MpcProcessConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("mpc: {error}");
            return ExitCode::from(2);
        }
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(process_config.log_filter)),
        )
        .init();

    let state = mpc::state::AppState::local_ephemeral();
    let app = mpc::api::router(state);
    let listener = match tokio::net::TcpListener::bind(process_config.bind_addr).await {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("mpc: failed to bind {}: {error}", process_config.bind_addr);
            return ExitCode::from(3);
        }
    };

    tracing::info!(addr = %process_config.bind_addr, "starting MPC HTTP service");
    if let Err(error) = axum::serve(listener, app).await {
        eprintln!("mpc: server failed: {error}");
        return ExitCode::from(4);
    }

    ExitCode::SUCCESS
}
