//! #782: the owner-facing export of a tunnel's **signed forensic receipts** --
//! `GET /portal/tunnels/:id/receipts.jsonl` -- fetched from the edge's admin API and
//! handed out as JSON lines an offline verifier (`verify_receipts`, crates/agent-tools,
//! or anything using `ct_common::receipt::verify_chain`) checks without trusting this
//! control plane: the header line carries the edge's receipts public key, and every
//! following line is one receipt exactly as the edge signed it. What a receipt proves
//! and does not prove is documented on `ct_common::receipt`.
//!
//! A child module of `portal_api` (like `uptime.rs`) so it can use the parent's private
//! state and helpers (`ApiState`, `edge_presence_http_client`, `session_claims_for`)
//! without widening them; registered through [`routes`] at one merge site.

use super::*;
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use ct_common::receipt::{to_jsonl, ExportHeader, Receipt};

/// Receipts asked of the edge per export -- the edge route's own page cap
/// (`crates/edge/src/admin.rs`). A longer chain is exported in pages: the file's last
/// `seq` goes back in as `?since=`.
const EXPORT_LIMIT: usize = 1000;

#[derive(Deserialize, Default)]
struct ReceiptsQuery {
    /// Export receipts with `seq` strictly greater than this (the last seq of a
    /// previous export); absent -> from the oldest the edge retains.
    #[serde(default)]
    since: Option<u64>,
}

/// The edge's `GET /internal/tunnel/receipts/:token_hex` body.
#[derive(Deserialize)]
struct EdgeReceiptsPage {
    pubkey: String,
    edge_id: String,
    #[serde(default)]
    receipts: Vec<Receipt>,
}

/// The routes this module owns; merged into the portal API router by its builder.
pub(super) fn routes() -> Router<ApiState> {
    Router::new().route("/portal/tunnels/:id/receipts.jsonl", get(tunnel_receipts_jsonl))
}

/// `GET /portal/tunnels/:id/receipts.jsonl?since=<seq>` (#782): owner-scoped -- an
/// unknown or foreign id is a 404, never a 403, like every other owner-scoped tunnel
/// route. NOT fail-open, unlike the uptime page: an export that silently came back
/// empty would read as "nothing happened", so an unreachable edge, an edge with
/// receipts disabled (its 404), or a malformed answer is a `502` with a one-line
/// explanation instead. Body: the header line `{"pubkey","edge_id","tunnel"}` then one
/// receipt per line, served as a download.
async fn tunnel_receipts_jsonl(
    State(st): State<ApiState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Query(q): Query<ReceiptsQuery>,
) -> Response {
    let Some(claims) = session_claims_for(&st.session_key, &headers) else {
        return Redirect::to("/portal").into_response();
    };
    let tunnel = match st.tunnels.owned_tunnel(&claims.subject, &id) {
        Ok(Some(t)) => t,
        Ok(None) => return (StatusCode::NOT_FOUND, "unknown tunnel").into_response(),
        Err(e) => return internal_error("tunnel_receipts_jsonl/owned_tunnel", e).into_response(),
    };
    let page = match edge_receipts(&st, &tunnel.routing_token, q.since).await {
        Ok(page) => page,
        Err(why) => return (StatusCode::BAD_GATEWAY, why).into_response(),
    };
    let header = ExportHeader { pubkey: page.pubkey, edge_id: page.edge_id, tunnel: Some(tunnel.name.clone()) };
    let body = to_jsonl(&header, &page.receipts);
    // `tunnel.id` is this deployment's own hex id (owner-scoped lookup above), so it is
    // safe inside a quoted filename.
    let filename = match q.since {
        Some(s) => format!("receipts-{}-since-{s}.jsonl", tunnel.id),
        None => format!("receipts-{}.jsonl", tunnel.id),
    };
    (
        [
            (CONTENT_TYPE, "application/x-ndjson; charset=utf-8".to_string()),
            (CONTENT_DISPOSITION, format!("attachment; filename=\"{filename}\"")),
        ],
        body,
    )
        .into_response()
}

/// Fetch one page of `routing_token_hex`'s receipts from the edge. Bounded by
/// [`edge_presence_http_client`]'s 2 s timeout like the history fetch. `Err` carries the
/// text the 502 shows the owner -- never the edge's URL or the token.
async fn edge_receipts(st: &ApiState, routing_token_hex: &str, since: Option<u64>) -> Result<EdgeReceiptsPage, String> {
    let Some(edge) = st.edge_admin.as_ref() else {
        return Err("receipts unavailable: no edge admin endpoint is configured on this control plane".into());
    };
    let endpoint = format!("{}/internal/tunnel/receipts/{routing_token_hex}", edge.url.trim_end_matches('/'));
    let mut req = edge_presence_http_client()
        .get(&endpoint)
        .query(&[("limit", EXPORT_LIMIT)])
        .header("x-ct-admin-token", edge.token.as_ref());
    if let Some(since) = since {
        req = req.query(&[("since", since)]);
    }
    let resp = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            eprintln!("ct-cp portal: receipts fetch from the edge failed: {e}");
            return Err("receipts unavailable: the edge could not be reached".into());
        }
    };
    match resp.status() {
        s if s.as_u16() == 404 => {
            Err("receipts unavailable: the edge has receipts disabled or does not support them yet".into())
        }
        s if !s.is_success() => {
            eprintln!("ct-cp portal: receipts fetch from the edge answered {s}");
            Err(format!("receipts unavailable: the edge answered {}", s.as_u16()))
        }
        _ => resp.json::<EdgeReceiptsPage>().await.map_err(|e| {
            eprintln!("ct-cp portal: receipts fetch from the edge returned a malformed body: {e}");
            "receipts unavailable: the edge returned a malformed receipts page".to_string()
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::portal::sign_session_for_test;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use ct_common::receipt::{self, ReceiptSigner};
    use tower::ServiceExt;

    const KEY: &[u8] = b"receipts-test-key";

    /// Same deliberately identical copy of the parent's private fixture as `fleet.rs`.
    fn app_with_edge(edge_url: Option<String>) -> (Router, Arc<SqliteTunnelStore>) {
        let holder = ed25519_dalek::SigningKey::from_bytes(&[0x11u8; 32]);
        let tunnels = Arc::new(SqliteTunnelStore::open_in_memory().unwrap());
        let app = portal_api_router_with_verifier(
            KEY,
            Arc::new(SqliteLedger::open_in_memory().unwrap()),
            tunnels.clone(),
            Arc::new(SqliteEnrollment::open_in_memory().unwrap()),
            Arc::new(SqliteBootstrap::open_in_memory().unwrap()),
            "https://portal.example",
            edge_url.map(|u| (u, "edge-secret".to_string())),
            None,
            None,
            None,
            EdgeMeshHandle::new(
                Arc::new(crate::edge_mesh::SqliteEdgeMesh::open_in_memory().unwrap()),
                Arc::from("test-edge"),
            ),
            None,
            None,
            None,
            Some((holder, [0x22u8; 32], "127.0.0.1:1".parse().unwrap(), "127.0.0.1:2".parse().unwrap())),
            Arc::new(crate::storage::SqliteChannelStore::open_in_memory().unwrap()),
        );
        (app, tunnels)
    }

    async fn get(app: &Router, path: &str, subject: Option<&str>) -> (StatusCode, HeaderMap, String) {
        let mut req = Request::get(path);
        if let Some(s) = subject {
            req = req.header("cookie", format!("ct_portal_session={}", sign_session_for_test(KEY, s)));
        }
        let resp = app.clone().oneshot(req.body(Body::empty()).unwrap()).await.unwrap();
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, headers, String::from_utf8(body.to_vec()).unwrap())
    }

    fn signer() -> ReceiptSigner {
        ReceiptSigner::from_seed(&[0x78u8; 32], "edge-78")
    }

    /// A three-receipt chain (open, bytes, close) for the token whose raw bytes are `tok`.
    fn chain_for(tok: &[u8; 32]) -> Vec<Receipt> {
        let s = signer();
        let th = receipt::routing_token_hash(tok);
        let r1 = s.sign(
            1,
            receipt::GENESIS_PREV_HASH,
            1_757_100_000,
            receipt::KIND_SESSION_OPEN,
            &th,
            serde_json::json!({ "connected_at": 1_757_100_000, "transport": "quic" }),
        );
        let r2 = s.sign(
            2,
            &r1.hash,
            1_757_103_600,
            receipt::KIND_BYTES,
            &th,
            serde_json::json!({ "bytes_in": 10, "bytes_out": 20, "connected_at": 1_757_100_000 }),
        );
        let r3 = s.sign(
            3,
            &r2.hash,
            1_757_107_200,
            receipt::KIND_SESSION_CLOSE,
            &th,
            serde_json::json!({
                "bytes_in": 30, "bytes_out": 40, "connected_at": 1_757_100_000,
                "disconnected_at": 1_757_107_200, "reason": "removed"
            }),
        );
        vec![r1, r2, r3]
    }

    /// `(token_hex, raw query)` the mock was last asked with.
    type Asked = Arc<std::sync::Mutex<Option<(String, Option<String>)>>>;

    /// A mock edge serving `/internal/tunnel/receipts/:token_hex` with the chain for
    /// whatever token is asked (decoding the hex), recording the ask and asserting the
    /// admin header; `serve_receipts = false` mounts no receipts route at all (an edge
    /// with receipts disabled, or an older edge: 404).
    async fn mock_edge(serve_receipts: bool) -> (String, Asked) {
        let asked: Asked = Arc::new(std::sync::Mutex::new(None));
        let mut mock = Router::new();
        if serve_receipts {
            let asked = asked.clone();
            mock = mock.route(
                "/internal/tunnel/receipts/:token_hex",
                axum::routing::get(
                    move |headers: HeaderMap,
                          axum::extract::Path(token_hex): axum::extract::Path<String>,
                          axum::extract::RawQuery(query): axum::extract::RawQuery| {
                        let asked = asked.clone();
                        async move {
                            assert_eq!(
                                headers.get("x-ct-admin-token").and_then(|v| v.to_str().ok()),
                                Some("edge-secret"),
                                "the receipts call authenticates like every other edge-admin call"
                            );
                            let tok: [u8; 32] = hex_decode(&token_hex).unwrap().try_into().unwrap();
                            *asked.lock().unwrap() = Some((token_hex, query));
                            Json(serde_json::json!({
                                "pubkey": signer().pubkey_hex(),
                                "edge_id": "edge-78",
                                "receipts": chain_for(&tok),
                            }))
                        }
                    },
                ),
            );
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });
        (format!("http://{addr}"), asked)
    }

    #[tokio::test]
    async fn receipts_export_streams_the_header_then_one_receipt_per_line_782() {
        let (edge_url, asked) = mock_edge(true).await;
        let (app, tunnels) = app_with_edge(Some(edge_url));
        let t = tunnels.create("alice", "web", None).unwrap().created().expect("created");

        let path = format!("/portal/tunnels/{}/receipts.jsonl", t.id);
        let (status, headers, body) = get(&app, &path, Some("alice")).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(headers[CONTENT_TYPE].to_str().unwrap().starts_with("application/x-ndjson"));
        assert_eq!(
            headers[CONTENT_DISPOSITION].to_str().unwrap(),
            format!("attachment; filename=\"receipts-{}.jsonl\"", t.id)
        );
        assert_eq!(body.lines().count(), 4, "header + 3 receipts:\n{body}");
        let parsed = receipt::parse_jsonl(&body).expect("well-formed export");
        assert_eq!(parsed.header.pubkey, signer().pubkey_hex());
        assert_eq!(parsed.header.edge_id, "edge-78");
        assert_eq!(parsed.header.tunnel.as_deref(), Some("web"));
        let tok: [u8; 32] = hex_decode(&t.routing_token).unwrap().try_into().unwrap();
        assert_eq!(parsed.receipts, chain_for(&tok), "receipts pass through byte-for-byte in content");
        let key = receipt::pubkey_from_hex(&parsed.header.pubkey).unwrap();
        let summary = receipt::verify_chain(&parsed.receipts, &key).expect("the export verifies offline");
        assert_eq!((summary.count, summary.sessions_opened, summary.sessions_closed), (3, 1, 1));
        assert!(!body.contains(&t.routing_token), "the raw routing token is never in the file");
        assert!(body.contains(&receipt::routing_token_hash(&tok)), "only its hash");

        let (token_hex, query) = asked.lock().unwrap().clone().expect("the edge was asked");
        assert_eq!(token_hex, t.routing_token, "asked about this tunnel's routing token");
        assert_eq!(query.as_deref(), Some("limit=1000"), "no `since` -> from the oldest retained");

        // `since` passes through as the edge's exclusive cursor and names the file.
        let (status, headers, _) =
            get(&app, &format!("/portal/tunnels/{}/receipts.jsonl?since=3", t.id), Some("alice")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(asked.lock().unwrap().clone().unwrap().1.as_deref(), Some("limit=1000&since=3"));
        assert!(headers[CONTENT_DISPOSITION].to_str().unwrap().contains("-since-3.jsonl"));
    }

    #[tokio::test]
    async fn receipts_export_is_owner_scoped_and_needs_a_session_782() {
        let (edge_url, asked) = mock_edge(true).await;
        let (app, tunnels) = app_with_edge(Some(edge_url));
        let t = tunnels.create("alice", "web", None).unwrap().created().expect("created");
        let path = format!("/portal/tunnels/{}/receipts.jsonl", t.id);

        let (status, _, _) = get(&app, &path, None).await;
        assert_eq!(status, StatusCode::SEE_OTHER, "no session -> portal shell");
        let (status, _, _) = get(&app, &path, Some("bob")).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "another account's tunnel is unknown, not forbidden");
        let (status, _, _) = get(&app, "/portal/tunnels/nope/receipts.jsonl", Some("alice")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(asked.lock().unwrap().is_none(), "the edge is never asked for a tunnel the caller doesn't own");
    }

    #[tokio::test]
    async fn receipts_export_answers_502_with_text_when_the_edge_has_no_receipts_782() {
        // The edge 404s (receipts disabled, or an older edge): NOT an empty file.
        let (edge_url, _asked) = mock_edge(false).await;
        let (app, tunnels) = app_with_edge(Some(edge_url));
        let t = tunnels.create("alice", "web", None).unwrap().created().expect("created");
        let (status, _, body) = get(&app, &format!("/portal/tunnels/{}/receipts.jsonl", t.id), Some("alice")).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(body.contains("receipts unavailable") && body.contains("disabled"), "{body}");

        // No edge configured at all: same posture, its own explanation.
        let (app, tunnels) = app_with_edge(None);
        let t = tunnels.create("alice", "web", None).unwrap().created().expect("created");
        let (status, _, body) = get(&app, &format!("/portal/tunnels/{}/receipts.jsonl", t.id), Some("alice")).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(body.contains("no edge admin endpoint"), "{body}");
    }

    #[tokio::test]
    async fn uptime_page_links_to_the_receipts_download_782() {
        let (app, tunnels) = app_with_edge(None);
        let t = tunnels.create("alice", "web", None).unwrap().created().expect("created");
        let (status, _, html) = get(&app, &format!("/portal/tunnels/{}/uptime", t.id), Some("alice")).await;
        assert_eq!(status, StatusCode::OK);
        assert!(html.contains(&format!(r#"href="/portal/tunnels/{}/receipts.jsonl""#, t.id)), "{html}");
        assert!(html.contains("Download receipts"), "{html}");
        assert!(html.contains("verify_receipts"), "the page names the offline verifier: {html}");
    }
}
