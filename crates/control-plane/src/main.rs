//! Claude Tunnel Control-Plane service (M13.3, durable since M18.4d).
//!
//! Serves the enrollment + registry/rendezvous + billing HTTP API over TCP,
//! backed by a durable SQLite database so state survives a restart. Thin and
//! stateless-of-secrets (ADR-0017): holds no Agent private key or payload.
//!
//! Configuration: `CT_CONTROL_PLANE_LISTEN` (default `0.0.0.0:8090`),
//! `CT_CONTROL_PLANE_DB` (default `control-plane.db`) and
//! `CT_PAYMENT_WEBHOOK_SECRET` (the payment provider's webhook signing secret;
//! if unset, a random secret is used so the webhook accepts nothing — payment is
//! effectively disabled until a real secret is configured).

use std::net::SocketAddr;

use ct_control_plane::service::persistent_control_plane_router;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listen: SocketAddr = std::env::var("CT_CONTROL_PLANE_LISTEN")
        .unwrap_or_else(|_| "0.0.0.0:8090".to_string())
        .parse()?;
    let db = std::env::var("CT_CONTROL_PLANE_DB").unwrap_or_else(|_| "control-plane.db".to_string());

    // The webhook signing secret must match the payment provider's. If it is
    // unconfigured, fall back to an unguessable random secret so no attacker can
    // forge a "payment succeeded" event — payment is simply inert until set.
    let webhook_secret = match std::env::var("CT_PAYMENT_WEBHOOK_SECRET") {
        Ok(s) if !s.is_empty() => s.into_bytes(),
        _ => {
            eprintln!(
                "ct-control-plane: CT_PAYMENT_WEBHOOK_SECRET unset — payment webhook disabled"
            );
            let mut buf = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf);
            buf.to_vec()
        }
    };

    let app = persistent_control_plane_router(&db, &webhook_secret)?;

    let listener = tokio::net::TcpListener::bind(listen).await?;
    eprintln!("ct-control-plane: listening on {listen}, db={db}");
    axum::serve(listener, app).await?;
    Ok(())
}
