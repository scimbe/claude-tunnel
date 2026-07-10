//! Claude Tunnel Edge daemon (M5.1a).
//!
//! Reads [`EdgeConfig`] from the environment, binds the QUIC endpoint to the
//! configured listen address, and accepts connections. Rendezvous + relay
//! orchestration (pairing Client and Agent connections via the registry) is
//! M5.1b; this skeleton makes the Edge a runnable container node for the testbed.

use ct_edge::config::EdgeConfig;
use ct_edge::transport::build_server_endpoint_at;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = EdgeConfig::from_env()?;
    eprintln!(
        "ct-edge: listening on {} (pow_difficulty={})",
        config.listen, config.pow_difficulty
    );

    let (endpoint, _cert) = build_server_endpoint_at(config.listen)?;

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            if let Ok(conn) = incoming.await {
                eprintln!("ct-edge: accepted connection from {}", conn.remote_address());
            }
        });
    }

    Ok(())
}
