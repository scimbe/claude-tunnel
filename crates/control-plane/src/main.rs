//! Claude Tunnel Control-Plane service (M13.3, durable since M18.4d).
//!
//! Serves the enrollment + registry/rendezvous + billing HTTP API over TCP,
//! backed by a durable SQLite database so state survives a restart. Thin and
//! stateless-of-secrets (ADR-0017): holds no Agent private key or payload.
//!
//! Configuration: `CT_CONTROL_PLANE_LISTEN` (default `0.0.0.0:8090`) and
//! `CT_CONTROL_PLANE_DB` (default `control-plane.db`).

use std::net::SocketAddr;

use ct_control_plane::service::persistent_control_plane_router;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listen: SocketAddr = std::env::var("CT_CONTROL_PLANE_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:8090".to_string())
        .parse()?;
    let db = std::env::var("CT_CONTROL_PLANE_DB").unwrap_or_else(|_| "control-plane.db".to_string());

    let app = persistent_control_plane_router(&db)?;

    let listener = tokio::net::TcpListener::bind(listen).await?;
    eprintln!("ct-control-plane: listening on {listen}, db={db}");
    axum::serve(listener, app).await?;
    Ok(())
}
