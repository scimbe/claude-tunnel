//! Persistent HTTP surface (M18.4): the same JSON API as [`crate::http`], but
//! backed by the durable SQLite stores instead of in-memory state, so a service
//! restart preserves enrollment / registry / billing. This module grows one
//! router per store; M18.4a wires enrollment.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::enrollment::{EnrollError, JoinToken};
use crate::registry::TunnelInfo;
use crate::storage::{RedeemError, SqliteEnrollment, SqliteRegistry};
use ct_common::{AgentId, RoutingToken, TenantId};

/// Build the persistent enrollment router: `POST /enroll/issue`,
/// `POST /enroll/redeem`, backed by a durable [`SqliteEnrollment`].
pub fn enrollment_router_sqlite(store: Arc<SqliteEnrollment>) -> Router {
    Router::new()
        .route("/enroll/issue", post(issue))
        .route("/enroll/redeem", post(redeem))
        .with_state(store)
}

#[derive(Deserialize)]
struct IssueReq {
    tenant: String,
}
#[derive(Serialize, Deserialize)]
struct IssueResp {
    token: String,
}

async fn issue(
    State(store): State<Arc<SqliteEnrollment>>,
    Json(req): Json<IssueReq>,
) -> Result<Json<IssueResp>, (StatusCode, String)> {
    let token = store
        .issue_join_token(&TenantId(req.tenant))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(IssueResp {
        token: hex_encode(&token.0),
    }))
}

#[derive(Deserialize)]
struct RedeemReq {
    token: String,
    agent: String,
    pubkey: String,
}
#[derive(Serialize, Deserialize)]
struct RedeemResp {
    tenant: String,
}

async fn redeem(
    State(store): State<Arc<SqliteEnrollment>>,
    Json(req): Json<RedeemReq>,
) -> Result<Json<RedeemResp>, (StatusCode, String)> {
    let token =
        hex_decode_32(&req.token).ok_or((StatusCode::BAD_REQUEST, "malformed token".to_string()))?;
    let pubkey = hex_decode_32(&req.pubkey)
        .ok_or((StatusCode::BAD_REQUEST, "malformed pubkey".to_string()))?;
    let tenant = store
        .redeem(&JoinToken(token), &AgentId(req.agent), pubkey)
        .map_err(|e| {
            let code = match &e {
                RedeemError::Enroll(EnrollError::TokenAlreadyUsed) => StatusCode::CONFLICT,
                RedeemError::Enroll(EnrollError::UnknownToken) => StatusCode::NOT_FOUND,
                RedeemError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (code, e.to_string())
        })?;
    Ok(Json(RedeemResp { tenant: tenant.0 }))
}

/// Build the persistent registry router: `POST /registry/register`,
/// `GET /registry/resolve/:token`, backed by a durable [`SqliteRegistry`].
pub fn registry_router_sqlite(store: Arc<SqliteRegistry>) -> Router {
    Router::new()
        .route("/registry/register", post(register_tunnel))
        .route("/registry/resolve/:token", get(resolve_tunnel))
        .with_state(store)
}

#[derive(Deserialize)]
struct RegisterReq {
    token: String,
    tenant: String,
    agent: String,
}

async fn register_tunnel(
    State(store): State<Arc<SqliteRegistry>>,
    Json(req): Json<RegisterReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    let token =
        hex_decode_32(&req.token).ok_or((StatusCode::BAD_REQUEST, "malformed token".to_string()))?;
    store
        .register(
            &RoutingToken(token),
            &TunnelInfo {
                tenant: TenantId(req.tenant),
                agent: AgentId(req.agent),
            },
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::OK)
}

#[derive(Serialize, Deserialize)]
struct ResolveResp {
    tenant: String,
    agent: String,
}

async fn resolve_tunnel(
    State(store): State<Arc<SqliteRegistry>>,
    Path(token_hex): Path<String>,
) -> Result<Json<ResolveResp>, StatusCode> {
    let token = hex_decode_32(&token_hex).ok_or(StatusCode::BAD_REQUEST)?;
    let info = store
        .lookup(&RoutingToken(token))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(ResolveResp {
        tenant: info.tenant.0,
        agent: info.agent.0,
    }))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex_decode_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ControlPlaneClient;

    fn temp_db_path() -> String {
        let mut b = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
        let name: String = b.iter().map(|x| format!("{x:02x}")).collect();
        std::env::temp_dir()
            .join(format!("ct_svc_{name}.db"))
            .to_string_lossy()
            .into_owned()
    }

    /// Serve the persistent enrollment router (on `db_path`) on an ephemeral
    /// port; returns the base URL. Simulates one process instance.
    async fn spawn(db_path: &str) -> String {
        let store = Arc::new(SqliteEnrollment::open(db_path).unwrap());
        let app = enrollment_router_sqlite(store);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    /// The production requirement at the service level: state survives a restart.
    /// Enroll against one service instance, then start a fresh instance on the
    /// same DB file and confirm the consumed token stays consumed.
    #[tokio::test]
    async fn enrollment_survives_service_restart() {
        let db = temp_db_path();
        let agent = AgentId("agent-x".to_string());
        let token;
        {
            let cp = ControlPlaneClient::new(spawn(&db).await);
            token = cp
                .issue_join_token(&TenantId("tenant-x".to_string()))
                .await
                .unwrap();
            let tenant = cp.redeem(&token, &agent, &[7u8; 32]).await.unwrap();
            assert_eq!(tenant.0, "tenant-x", "redeem binds the tenant");
        }

        // Fresh service instance on the same database (a restart).
        let cp2 = ControlPlaneClient::new(spawn(&db).await);
        let replay = cp2.redeem(&token, &agent, &[7u8; 32]).await;
        assert!(
            matches!(replay, Err(crate::client::CpError::Status(_))),
            "the token stays consumed across a service restart"
        );

        let _ = std::fs::remove_file(&db);
    }

    /// Serve the persistent registry router (on `db_path`) on an ephemeral port.
    async fn spawn_registry(db_path: &str) -> String {
        let store = Arc::new(SqliteRegistry::open(db_path).unwrap());
        let app = registry_router_sqlite(store);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn registry_survives_service_restart() {
        let db = temp_db_path();
        let token = RoutingToken([0x5a; 32]);
        {
            let cp = ControlPlaneClient::new(spawn_registry(&db).await);
            cp.register(&token, &TenantId("t".to_string()), &AgentId("a".to_string()))
                .await
                .unwrap();
        }
        // Fresh instance on the same DB file.
        let cp2 = ControlPlaneClient::new(spawn_registry(&db).await);
        let (t, a) = cp2.resolve(&token).await.unwrap();
        assert_eq!(
            (t.0.as_str(), a.0.as_str()),
            ("t", "a"),
            "registration survives a service restart"
        );
        let _ = std::fs::remove_file(&db);
    }
}
