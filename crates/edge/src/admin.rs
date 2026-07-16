//! Edge admin API (#27 RB4) — an authenticated `POST /admin/revoke/:token` the
//! control plane calls when a customer revokes a tunnel. The edge then tears the
//! tunnel down and blocks its re-registration (see [`EdgeState::revoke_token`]).
//!
//! This is the HTTP counterpart of the QUIC `'R'` op (RB3b); the thin,
//! HTTP-based control plane calls it with `reqwest` rather than opening a QUIC
//! client. It is served on its own listener (`CT_EDGE_ADMIN_LISTEN`) so an
//! operator can bind it to a private interface, and every request must carry the
//! shared admin secret (`x-ct-admin-token`), checked in constant time.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;
use quinn::Connection;

use crate::state::EdgeState;
use ct_common::RoutingToken;

/// Build the admin router: `POST /admin/revoke/:token` (token = 64-hex).
pub fn admin_router(state: Arc<EdgeState<Connection>>) -> Router {
    Router::new()
        .route("/admin/revoke/:token", post(revoke))
        .with_state(state)
}

/// Serve the admin API on `listen` until the process ends.
pub async fn serve_admin(
    state: Arc<EdgeState<Connection>>,
    listen: SocketAddr,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, admin_router(state))
        .await
        .map_err(std::io::Error::other)
}

async fn revoke(
    State(state): State<Arc<EdgeState<Connection>>>,
    headers: HeaderMap,
    Path(token): Path<String>,
) -> StatusCode {
    // Authenticate with the shared admin secret (constant-time in the state).
    let authed = headers
        .get("x-ct-admin-token")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_token_hex)
        .is_some_and(|a| state.admin_revoke_ok(&a));
    if !authed {
        return StatusCode::UNAUTHORIZED;
    }
    match parse_token_hex(&token) {
        Some(t) => {
            state.revoke_token(&RoutingToken(t));
            StatusCode::OK
        }
        None => StatusCode::BAD_REQUEST,
    }
}

/// Parse a 64-hex string into 32 bytes.
fn parse_token_hex(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut t = [0u8; 32];
    for (i, b) in t.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn revoke_endpoint_authenticates_then_revokes() {
        let state = Arc::new(EdgeState::<Connection>::new());
        let secret = [0x22u8; 32];
        state.set_admin_token(secret);
        let secret_hex: String = secret.iter().map(|b| format!("{b:02x}")).collect();
        let target = "aa".repeat(32);
        let target_token = RoutingToken([0xaa; 32]);

        let post = |auth: Option<String>, tok: &str| {
            let app = admin_router(state.clone());
            let mut req = Request::post(format!("/admin/revoke/{tok}"));
            if let Some(a) = auth {
                req = req.header("x-ct-admin-token", a);
            }
            app.oneshot(req.body(Body::empty()).unwrap())
        };

        // No / wrong admin token -> 401, nothing revoked.
        assert_eq!(post(None, &target).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        let wrong: String = [0x00u8; 32].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(post(Some(wrong), &target).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        assert!(!state.is_revoked(&target_token), "not revoked without valid auth");

        // Correct admin token -> 200 and the token is revoked.
        assert_eq!(
            post(Some(secret_hex.clone()), &target).await.unwrap().status(),
            StatusCode::OK
        );
        assert!(state.is_revoked(&target_token), "token revoked");

        // Malformed token with valid auth -> 400.
        assert_eq!(
            post(Some(secret_hex), "not-hex").await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }
}
