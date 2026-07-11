//! Claude Tunnel Control-Plane service (M13.3).
//!
//! Serves the enrollment + registry/rendezvous HTTP API over TCP. Thin and
//! stateless-of-secrets (ADR-0017): holds no Agent private key or payload.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use ct_control_plane::enrollment::Enrollment;
use ct_control_plane::http::control_plane_router;
use ct_control_plane::registry::TunnelRegistry;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listen: SocketAddr = std::env::var("CT_CONTROL_PLANE_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:8090".to_string())
        .parse()?;

    let enrollment = Arc::new(Mutex::new(Enrollment::new()));
    let registry = Arc::new(Mutex::new(TunnelRegistry::new()));
    let app = control_plane_router(enrollment, registry);

    let listener = tokio::net::TcpListener::bind(listen).await?;
    eprintln!("ct-control-plane: listening on {listen}");
    axum::serve(listener, app).await?;
    Ok(())
}
