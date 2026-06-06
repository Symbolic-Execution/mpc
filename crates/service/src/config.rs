use std::net::SocketAddr;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MpcProcessConfig {
    pub bind_addr: SocketAddr,
    pub log_filter: String,
}

impl MpcProcessConfig {
    pub fn from_env() -> Result<Self, String> {
        let bind_addr = std::env::var("MPC_BIND_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:3000".to_string())
            .parse()
            .map_err(|error| format!("invalid MPC_BIND_ADDR: {error}"))?;
        let log_filter = std::env::var("MPC_LOG_FILTER").unwrap_or_else(|_| "mpc=info".to_string());

        Ok(Self {
            bind_addr,
            log_filter,
        })
    }
}
