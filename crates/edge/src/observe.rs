//! Edge observability endpoint (#10, ADR-0016).
//!
//! Serves the Edge's data-plane gauges over HTTP in the Prometheus text
//! exposition format so a scraper can read `GET /metrics`. The Edge is
//! provider-blind, so this exposes **only metadata/counters** — how many tunnels
//! and Agent registrations the Edge is serving — never any payload.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use quinn::Connection;

use crate::state::EdgeState;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Render the Edge's live gauges in the Prometheus text exposition format.
/// Generic over the handle type so it is unit-testable without live QUIC
/// connections (O1: live gauges; cumulative counters land in O2).
pub fn render_edge_metrics<H: Clone>(state: &EdgeState<H>) -> String {
    format!(
        "# HELP ct_edge_active_tunnels Distinct routing tokens with at least one live agent.\n\
         # TYPE ct_edge_active_tunnels gauge\n\
         ct_edge_active_tunnels {tunnels}\n\
         # HELP ct_edge_active_agents Total live agent registrations (redundant agents counted).\n\
         # TYPE ct_edge_active_agents gauge\n\
         ct_edge_active_agents {agents}\n",
        tunnels = state.active_tunnels(),
        agents = state.total_registrations(),
    )
}

/// Build the metrics router: `GET /metrics` renders the current gauges.
pub fn metrics_router(state: Arc<EdgeState<Connection>>) -> Router {
    Router::new().route("/metrics", get(render)).with_state(state)
}

async fn render(State(state): State<Arc<EdgeState<Connection>>>) -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/plain; version=0.0.4")],
        render_edge_metrics(&*state),
    )
}

/// Bind `listen` and serve the Edge metrics endpoint until the process exits.
pub async fn serve_metrics(
    listen: SocketAddr,
    state: Arc<EdgeState<Connection>>,
) -> Result<(), BoxError> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    axum::serve(listener, metrics_router(state)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use ct_common::RoutingToken;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn token(b: u8) -> RoutingToken {
        RoutingToken([b; 32])
    }

    #[test]
    fn gauges_reflect_registered_agents() {
        // Two agents on token A (redundant, #8) + one on token B → 2 tunnels,
        // 3 registrations. Generic over the handle so no live QUIC is needed.
        let state: EdgeState<u32> = EdgeState::new();
        state.register(token(1), 10);
        state.register(token(1), 11);
        state.register(token(2), 20);
        let body = render_edge_metrics(&state);
        assert!(body.contains("ct_edge_active_tunnels 2"), "{body}");
        assert!(body.contains("ct_edge_active_agents 3"), "{body}");
    }

    #[tokio::test]
    async fn metrics_endpoint_serves_prometheus() {
        let state = Arc::new(EdgeState::<Connection>::new());
        let app = metrics_router(state);
        let resp = app
            .oneshot(Request::builder().uri("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "text/plain; version=0.0.4"
        );
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("ct_edge_active_tunnels 0"), "empty edge → 0 tunnels: {text}");
        assert!(text.contains("ct_edge_active_agents 0"));
    }
}
