//! Claude Tunnel Agent daemon (M5.2a).
//!
//! Reads [`AgentConfig`] from the environment. Dialing the Edge, registering the
//! tunnel, and serving the local Origin land in M5.2b; this skeleton makes the
//! Agent a configurable container node for the testbed.

use ct_agent::config::AgentConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = AgentConfig::from_env()?;
    eprintln!(
        "ct-agent: edge={} origin={}",
        config.edge, config.origin
    );
    Ok(())
}
