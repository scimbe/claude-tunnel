//! Claude Tunnel Client tool (M5.3a).
//!
//! Reads [`ClientConfig`] from the environment. Importing the Capability,
//! rendezvous, and the Noise-E2E data path to the Origin land in M5.3b.

use ct_client::config::ClientConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = ClientConfig::from_env();
    eprintln!(
        "ct-client: capability={} edge_cert={}",
        config.capability_file, config.edge_cert_file
    );
    Ok(())
}
