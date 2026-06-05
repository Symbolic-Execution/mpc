use std::net::SocketAddr;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let addr: SocketAddr = std::env::var("MPC_BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:3000".to_string())
        .parse()
        .expect("MPC_BIND_ADDR must be a socket address");

    let state = mpc::state::AppState::local_ephemeral();
    let app = mpc::api::router(state);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("bind MPC HTTP listener");

    tracing::info!(%addr, "starting MPC HTTP service");
    axum::serve(listener, app)
        .await
        .expect("run MPC HTTP service");
}
