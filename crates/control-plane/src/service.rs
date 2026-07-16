//! Persistent HTTP surface (M18.4): the same JSON API as [`crate::http`], but
//! backed by the durable SQLite stores instead of in-memory state, so a service
//! restart preserves enrollment / registry / billing. This module grows one
//! router per store; M18.4a wires enrollment.

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::accounts::{AccountId, LedgerError};
use crate::enrollment::{EnrollError, JoinToken};
use crate::oidc::OidcVerifier;
use crate::payment::{PaymentError, PaymentId};
use crate::payment_provider::WebhookVerifier;
use crate::registry::TunnelInfo;
use crate::storage::{
    LedgerOpError, PaymentOpError, RedeemError, SqliteEnrollment, SqliteLedger, SqliteRegistry,
};
use ct_common::ratelimit::KeyedRateLimiter;
use ct_common::{AgentId, RoutingToken, TenantId};
use ct_common::sync::MutexExt;

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

/// Build the persistent billing router (accounts / payment / credit-gated
/// issuance) backed by a durable [`SqliteLedger`].
pub fn billing_router_sqlite(store: Arc<SqliteLedger>) -> Router {
    Router::new()
        .route("/accounts/open", post(open_account))
        .route("/payment/intent", post(create_payment_intent))
        .route("/payment/confirm", post(confirm_payment))
        .route("/billing/issue", post(buy_token))
        .with_state(store)
}

#[derive(Serialize, Deserialize)]
struct AccountResp {
    account: String,
}

async fn open_account(
    State(store): State<Arc<SqliteLedger>>,
) -> Result<Json<AccountResp>, (StatusCode, String)> {
    let account = store
        .open_account()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(AccountResp {
        account: hex_encode(&account.0),
    }))
}

#[derive(Deserialize)]
struct IntentReq {
    account: String,
    credits: u64,
}
#[derive(Serialize, Deserialize)]
struct IntentResp {
    payment: String,
}

async fn create_payment_intent(
    State(store): State<Arc<SqliteLedger>>,
    Json(req): Json<IntentReq>,
) -> Result<Json<IntentResp>, (StatusCode, String)> {
    let account = hex_decode_32(&req.account)
        .ok_or((StatusCode::BAD_REQUEST, "malformed account".to_string()))?;
    let id = store
        .create_intent(&AccountId(account), req.credits)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(IntentResp {
        payment: hex_encode(&id.0),
    }))
}

#[derive(Deserialize)]
struct ConfirmReq {
    payment: String,
}
#[derive(Serialize, Deserialize)]
struct BalanceResp {
    balance: u64,
}

async fn confirm_payment(
    State(store): State<Arc<SqliteLedger>>,
    Json(req): Json<ConfirmReq>,
) -> Result<Json<BalanceResp>, (StatusCode, String)> {
    let payment = hex_decode_32(&req.payment)
        .ok_or((StatusCode::BAD_REQUEST, "malformed payment".to_string()))?;
    let balance = store.confirm_payment(&PaymentId(payment)).map_err(|e| {
        let code = match &e {
            PaymentOpError::Payment(PaymentError::AlreadyConfirmed) => StatusCode::CONFLICT,
            PaymentOpError::Payment(_) => StatusCode::NOT_FOUND,
            PaymentOpError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (code, e.to_string())
    })?;
    Ok(Json(BalanceResp { balance }))
}

#[derive(Deserialize)]
struct BuyReq {
    account: String,
    price: u64,
}
#[derive(Serialize, Deserialize)]
struct TokenResp {
    token: String,
}

async fn buy_token(
    State(store): State<Arc<SqliteLedger>>,
    Json(req): Json<BuyReq>,
) -> Result<Json<TokenResp>, (StatusCode, String)> {
    let account = hex_decode_32(&req.account)
        .ok_or((StatusCode::BAD_REQUEST, "malformed account".to_string()))?;
    // Debit first: only mint the token if the account can pay.
    store.debit(&AccountId(account), req.price).map_err(|e| {
        let code = match &e {
            LedgerOpError::Ledger(LedgerError::InsufficientCredit { .. }) => {
                StatusCode::PAYMENT_REQUIRED
            }
            LedgerOpError::Ledger(LedgerError::UnknownAccount) => StatusCode::NOT_FOUND,
            LedgerOpError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (code, e.to_string())
    })?;
    let mut token = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut token);
    Ok(Json(TokenResp {
        token: hex_encode(&token),
    }))
}

/// Shared state for the payment webhook: the durable ledger and the provider
/// webhook signature verifier.
#[derive(Clone)]
pub struct WebhookState {
    ledger: Arc<SqliteLedger>,
    verifier: Arc<WebhookVerifier>,
}

/// Build the payment **webhook** router (M24.2): `POST /payment/webhook`.
///
/// This is the *real* payment path — a credit is applied only for an event whose
/// signature verifies against the provider's shared secret, replacing the M18
/// stub where any caller could confirm a payment. The provider echoes our
/// `PaymentId` (attached as intent metadata) in the event body, so no separate
/// intent→payment mapping is needed. Delivery is idempotent (a replayed event
/// acks `200` without double-crediting).
///
/// The provider signs `"<timestamp>.<raw-body>"`; the timestamp and hex
/// signature arrive in the `X-CT-Webhook-Timestamp` / `X-CT-Webhook-Signature`
/// headers.
pub fn payment_webhook_router(
    ledger: Arc<SqliteLedger>,
    verifier: Arc<WebhookVerifier>,
) -> Router {
    Router::new()
        .route("/payment/webhook", post(payment_webhook))
        .with_state(WebhookState { ledger, verifier })
}

#[derive(Deserialize)]
struct WebhookEvent {
    /// Hex-encoded `PaymentId` we attached to the provider intent as metadata.
    payment: String,
    /// Provider event status; we credit only on `"succeeded"`.
    status: String,
}

async fn payment_webhook(
    State(state): State<WebhookState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, (StatusCode, String)> {
    let timestamp = headers
        .get("x-ct-webhook-timestamp")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or((
            StatusCode::BAD_REQUEST,
            "missing or invalid X-CT-Webhook-Timestamp".to_string(),
        ))?;
    let signature = headers
        .get("x-ct-webhook-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or((
            StatusCode::BAD_REQUEST,
            "missing X-CT-Webhook-Signature".to_string(),
        ))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Authenticate the event against the provider secret before trusting it.
    state
        .verifier
        .verify(timestamp, &body, signature, now)
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;

    let event: WebhookEvent = serde_json::from_slice(&body)
        .map_err(|_| (StatusCode::BAD_REQUEST, "malformed event body".to_string()))?;
    // Acknowledge non-terminal events without crediting.
    if event.status != "succeeded" {
        return Ok(StatusCode::OK);
    }
    let payment = hex_decode_32(&event.payment)
        .ok_or((StatusCode::BAD_REQUEST, "malformed payment id".to_string()))?;
    match state.ledger.confirm_payment(&PaymentId(payment)) {
        // Fresh confirmation credited the account.
        Ok(_) => Ok(StatusCode::OK),
        // Provider retried a delivered event — idempotent, do not double-credit.
        Err(PaymentOpError::Payment(PaymentError::AlreadyConfirmed)) => Ok(StatusCode::OK),
        Err(PaymentOpError::Payment(PaymentError::UnknownPayment)) => {
            Err((StatusCode::NOT_FOUND, "unknown payment".to_string()))
        }
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// Accepted age (seconds, either direction) of a payment webhook timestamp (M24.3).
const WEBHOOK_TOLERANCE_SECS: u64 = 300;

/// Per-subject `/me/issue` cap per window on the production authed router (M26.1).
const AUTHED_ISSUES_PER_WINDOW: u32 = 60;

/// Fixed window (seconds) for the per-subject issuance rate limit (M23.1).
const ISSUE_WINDOW_SECS: u64 = 60;

/// Shared state for the authenticated billing endpoints: the durable ledger, the
/// OIDC verifier, and a per-subject issuance rate limiter (M23.1).
#[derive(Clone)]
pub struct AuthedState {
    ledger: Arc<SqliteLedger>,
    verifier: Arc<OidcVerifier>,
    /// Caps `/me/issue` requests per authenticated subject per fixed window, so
    /// a single account cannot exhaust the control plane with issuance calls.
    issue_limiter: Arc<Mutex<KeyedRateLimiter<String>>>,
}

/// Build the **authenticated** billing router (M19.3): the account is derived
/// from the verified `Authorization: Bearer` token's subject rather than passed
/// in the request, so only an authenticated (Keycloak) user can act, and always
/// on their own account.
///
/// * `GET /me/account` → `{account, balance, subject}` for the authenticated subject
/// * `POST /me/issue` `{price}` → `{token}` (402 on insufficient credit, 429 over
///   the per-subject rate limit of `max_issues_per_window` per fixed window)
pub fn authed_billing_router(
    ledger: Arc<SqliteLedger>,
    verifier: Arc<OidcVerifier>,
    max_issues_per_window: u32,
) -> Router {
    Router::new()
        .route("/me/account", get(me_account))
        .route("/me/issue", post(me_issue))
        .with_state(AuthedState {
            ledger,
            verifier,
            issue_limiter: Arc::new(Mutex::new(KeyedRateLimiter::new(max_issues_per_window))),
        })
}

/// Extract + verify the bearer token, returning the authenticated subject.
fn authed_subject(state: &AuthedState, headers: &HeaderMap) -> Result<String, (StatusCode, String)> {
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, "missing bearer token".to_string()))?;
    state
        .verifier
        .subject(token)
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))
}

/// The authenticated customer's own account view (#26): account id, current
/// credit balance (Guthaben) and the verified subject. Strictly self-scoped —
/// the subject comes from the verified token, never from the request body — so a
/// caller can only ever see their own account. Serves the portal account page.
#[derive(Serialize, Deserialize)]
struct MeAccountResp {
    account: String,
    balance: u64,
    subject: String,
}

async fn me_account(
    State(state): State<AuthedState>,
    headers: HeaderMap,
) -> Result<Json<MeAccountResp>, (StatusCode, String)> {
    let sub = authed_subject(&state, &headers)?;
    let account = state
        .ledger
        .account_for_subject(&sub)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let balance = state
        .ledger
        .balance(&account)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(MeAccountResp {
        account: hex_encode(&account.0),
        balance,
        subject: sub,
    }))
}

#[derive(Deserialize)]
struct MeIssueReq {
    price: u64,
}

async fn me_issue(
    State(state): State<AuthedState>,
    headers: HeaderMap,
    Json(req): Json<MeIssueReq>,
) -> Result<Json<TokenResp>, (StatusCode, String)> {
    let sub = authed_subject(&state, &headers)?;
    // Per-subject rate limit (M23.1): reject over-limit callers before touching
    // the ledger, so a throttled request spends no credit.
    let window = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / ISSUE_WINDOW_SECS)
        .unwrap_or(0);
    if !state.issue_limiter.lock_safe().allow(&sub, window) {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "issue rate limit exceeded".to_string(),
        ));
    }
    let account = state
        .ledger
        .account_for_subject(&sub)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Debit the authenticated user's own account; mint only if they can pay.
    state.ledger.debit(&account, req.price).map_err(|e| {
        let code = match &e {
            LedgerOpError::Ledger(LedgerError::InsufficientCredit { .. }) => {
                StatusCode::PAYMENT_REQUIRED
            }
            LedgerOpError::Ledger(LedgerError::UnknownAccount) => StatusCode::NOT_FOUND,
            LedgerOpError::Db(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (code, e.to_string())
    })?;
    let mut token = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut token);
    Ok(Json(TokenResp {
        token: hex_encode(&token),
    }))
}

/// Build the health/readiness router (M21.1a): `GET /healthz` (liveness, always
/// `200`) and `GET /readyz` (readiness — `200` if the database is reachable,
/// else `503`). Used by orchestrator liveness/readiness probes.
pub fn health_router(ledger: Arc<SqliteLedger>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route("/readyz", get(readyz))
        .with_state(ledger)
}

async fn readyz(State(ledger): State<Arc<SqliteLedger>>) -> StatusCode {
    match ledger.ping() {
        Ok(()) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

/// Shared state for the operator status view (F4.1): the three durable stores
/// plus the service start instant for uptime (F4.2).
#[derive(Clone)]
pub struct StatusState {
    enrollment: Arc<SqliteEnrollment>,
    registry: Arc<SqliteRegistry>,
    ledger: Arc<SqliteLedger>,
    started: std::time::Instant,
    /// When set, `/status.tunnels` reports the edge's live registration count
    /// scraped from this URL (the edge's `/metrics` `ct_edge_active_tunnels`
    /// gauge, #10) instead of the CP rendezvous registry — which the live
    /// onboard/serve path never writes, so it read 0 even with active tunnels
    /// (#17). Falls back to the registry count if the scrape fails or is unset.
    edge_metrics_url: Option<String>,
    http: reqwest::Client,
}

/// Aggregated operator status — health plus metadata counts the operator
/// legitimately sees (never payload; consistent with ADR-0016 / the threat model).
#[derive(Serialize, Deserialize)]
pub struct StatusResp {
    /// Database reachable (same signal as `/readyz`).
    pub ready: bool,
    /// Registered tunnels.
    pub tunnels: i64,
    /// Enrolled agents (bound public keys).
    pub agents: i64,
    /// Open accounts.
    pub accounts: i64,
    /// Confirmed payments.
    pub payments_confirmed: i64,
    /// Seconds since the control plane started.
    pub uptime_seconds: u64,
}

/// Build the status router (F4.1): `GET /status` returns aggregated counts as
/// JSON, backing the operator landing page (F4.2).
pub fn status_router(
    enrollment: Arc<SqliteEnrollment>,
    registry: Arc<SqliteRegistry>,
    ledger: Arc<SqliteLedger>,
    edge_metrics_url: Option<String>,
) -> Router {
    Router::new().route("/status", get(status_handler)).with_state(StatusState {
        enrollment,
        registry,
        ledger,
        started: std::time::Instant::now(),
        edge_metrics_url,
        http: reqwest::Client::new(),
    })
}

async fn status_handler(State(s): State<StatusState>) -> Json<StatusResp> {
    Json(StatusResp {
        ready: s.ledger.ping().is_ok(),
        tunnels: live_tunnel_count(&s).await,
        agents: s.enrollment.agent_count().unwrap_or(0),
        accounts: s.ledger.account_count().unwrap_or(0),
        payments_confirmed: s.ledger.confirmed_payment_count().unwrap_or(0),
        uptime_seconds: s.started.elapsed().as_secs(),
    })
}

/// Resolve the operator "registered tunnels" count. The live tunnel registry
/// lives in the **edge** (`EdgeState`, evicted on drop, #8), exposed as the
/// `ct_edge_active_tunnels` gauge on the edge `/metrics` (#10). When an edge
/// metrics URL is configured, report that live count; otherwise (or if the
/// scrape fails) fall back to the CP rendezvous registry. The CP registry is not
/// written by the onboard/serve path, so without this `/status.tunnels` read 0
/// even with active tunnels (#17).
async fn live_tunnel_count(s: &StatusState) -> i64 {
    if let Some(url) = &s.edge_metrics_url {
        if let Ok(resp) = s
            .http
            .get(url.as_str())
            .timeout(std::time::Duration::from_secs(2))
            .send()
            .await
        {
            if let Ok(body) = resp.text().await {
                if let Some(n) = parse_metric(&body, "ct_edge_active_tunnels") {
                    return n;
                }
            }
        }
    }
    s.registry.tunnel_count().unwrap_or(0)
}

/// Parse a Prometheus gauge value by metric name from a metrics exposition body:
/// the first `<name> <value>` sample line, ignoring `# HELP`/`# TYPE` comments.
fn parse_metric(body: &str, name: &str) -> Option<i64> {
    body.lines()
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| {
            let mut it = l.split_whitespace();
            match (it.next(), it.next()) {
                (Some(k), Some(v)) if k == name => v.parse::<f64>().ok().map(|f| f as i64),
                _ => None,
            }
        })
}

/// The operator landing page (F4.2): a single self-contained HTML document (no
/// external assets, CSP-safe) that fetches `/status` and renders the health and
/// metadata counts, auto-refreshing. Shows only what the operator legitimately
/// sees — never payload.
const LANDING_HTML: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>claude-tunnel — operator status</title>
<style>
 body{font-family:system-ui,sans-serif;margin:2rem;background:#0e1116;color:#e6edf3}
 h1{font-size:1.3rem} .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-top:1rem}
 .card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:1rem}
 .n{font-size:2rem;font-weight:700} .l{color:#8b949e;font-size:.85rem}
 .ok{color:#3fb950} .bad{color:#f85149} .foot{color:#8b949e;font-size:.8rem;margin-top:1.5rem}
</style></head><body>
<h1>claude-tunnel — operator status</h1>
<div id="health" class="l">loading…</div>
<div class="grid">
 <div class="card"><div class="n" id="tunnels">–</div><div class="l">registered tunnels</div></div>
 <div class="card"><div class="n" id="agents">–</div><div class="l">enrolled agents</div></div>
 <div class="card"><div class="n" id="accounts">–</div><div class="l">accounts</div></div>
 <div class="card"><div class="n" id="payments">–</div><div class="l">confirmed payments</div></div>
 <div class="card"><div class="n" id="uptime">–</div><div class="l">uptime (s)</div></div>
</div>
<div class="foot">Operator view — structural health and metadata only; the payload is end-to-end encrypted and never visible here.</div>
<script>
 async function refresh(){
  try{
   const r=await fetch('/status'); const s=await r.json();
   document.getElementById('health').innerHTML = s.ready ? '<span class="ok">● ready</span>' : '<span class="bad">● not ready</span>';
   document.getElementById('tunnels').textContent=s.tunnels;
   document.getElementById('agents').textContent=s.agents;
   document.getElementById('accounts').textContent=s.accounts;
   document.getElementById('payments').textContent=s.payments_confirmed;
   document.getElementById('uptime').textContent=s.uptime_seconds;
  }catch(e){ document.getElementById('health').innerHTML='<span class="bad">● unreachable</span>'; }
 }
 refresh(); setInterval(refresh,5000);
</script></body></html>"#;

/// Build the landing-page router (F4.2): `GET /` serves [`LANDING_HTML`].
pub fn landing_router() -> Router {
    Router::new().route("/", get(landing_handler))
}

async fn landing_handler() -> axum::response::Html<&'static str> {
    axum::response::Html(LANDING_HTML)
}

/// Build the CA-publish router (#11 C1): `GET /pki/ca` serves the edge CA root
/// DER read from `cert_path` — the same file the edge writes (`CT_EDGE_CERT_OUT`),
/// co-located with the control plane on the central host. This is **public key
/// material** (the trust root, never the signing key), so publishing it over HTTP
/// lets remote agents/clients fetch the root instead of copying it out of band.
/// Returns 503 until the edge has written its cert. The root is stable across
/// edge redeploys now that the CA persists (#2 `f9e64e9`).
pub fn pki_router(cert_path: String) -> Router {
    Router::new()
        .route("/pki/ca", get(ca_handler))
        .with_state(Arc::new(cert_path))
}

async fn ca_handler(State(path): State<Arc<String>>) -> axum::response::Response {
    use axum::response::IntoResponse;
    match std::fs::read(path.as_str()) {
        Ok(der) => (
            StatusCode::OK,
            [(axum::http::header::CONTENT_TYPE, "application/x-x509-ca-cert")],
            der,
        )
            .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "edge CA root not published yet",
        )
            .into_response(),
    }
}

/// Build the full persistent control-plane router: enrollment + registry +
/// billing + health, all backed by durable SQLite stores opened on **one**
/// database file (`db_path`). The three stores share the file via separate
/// connections; each owns its own tables. This is what a real deployment serves.
pub fn persistent_control_plane_router(
    db_path: &str,
    webhook_secret: &[u8],
    oidc: Option<Arc<OidcVerifier>>,
) -> rusqlite::Result<Router> {
    let enrollment = Arc::new(SqliteEnrollment::open(db_path)?);
    let registry = Arc::new(SqliteRegistry::open(db_path)?);
    let ledger = Arc::new(SqliteLedger::open(db_path)?);
    let tunnels = Arc::new(crate::storage::SqliteTunnelStore::open(db_path)?);
    let verifier = Arc::new(WebhookVerifier::new(
        webhook_secret.to_vec(),
        WEBHOOK_TOLERANCE_SECS,
    ));
    // Production billing surface: accounts, payment intents and credit-gated
    // issuance, but **no** client-callable `/payment/confirm` — credits flow only
    // from a signature-verified provider webhook (M24). That defuses the M18 stub
    // where any caller could top up an account for free.
    let billing = Router::new()
        .route("/accounts/open", post(open_account))
        .route("/payment/intent", post(create_payment_intent))
        .route("/billing/issue", post(buy_token))
        .with_state(ledger.clone());
    // Operator status view + landing page (F4.1/F4.2): aggregate counts across
    // the three stores, plus a self-contained HTML dashboard at `/`.
    let status = status_router(
        enrollment.clone(),
        registry.clone(),
        ledger.clone(),
        std::env::var("CT_CP_EDGE_METRICS_URL")
            .ok()
            .filter(|u| !u.is_empty()),
    );
    // Publish the edge CA root (#11): read from the path the edge writes it to,
    // co-located on the central host (CT_CP_EDGE_CERT_PATH, default matches the
    // edge's CT_EDGE_CERT_OUT).
    let pki = pki_router(
        std::env::var("CT_CP_EDGE_CERT_PATH").unwrap_or_else(|_| "/shared/edge-cert.der".to_string()),
    );
    let mut app = enrollment_router_sqlite(enrollment)
        .merge(registry_router_sqlite(registry))
        .merge(billing)
        .merge(payment_webhook_router(ledger.clone(), verifier))
        .merge(status)
        .merge(landing_router())
        .merge(crate::portal::portal_router(
            crate::portal::PortalOidc::from_env(),
            webhook_secret,
        ))
        .merge(crate::portal_api::portal_api_router(
            webhook_secret,
            ledger.clone(),
            tunnels.clone(),
        ))
        .merge(pki);
    // Authenticated per-subject endpoints (`/me/*`) — mounted only when an OIDC
    // verifier is configured (M26.1). Without one they are simply absent (404).
    if let Some(oidc) = oidc {
        app = app.merge(authed_billing_router(
            ledger.clone(),
            oidc,
            AUTHED_ISSUES_PER_WINDOW,
        ));
    }
    Ok(app.merge(health_router(ledger)))
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

    /// Serve the persistent billing router (on `db_path`) on an ephemeral port.
    async fn spawn_billing(db_path: &str) -> String {
        let store = Arc::new(SqliteLedger::open(db_path).unwrap());
        let app = billing_router_sqlite(store);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn billing_survives_service_restart() {
        let db = temp_db_path();
        let account;
        let payment;
        {
            let cp = ControlPlaneClient::new(spawn_billing(&db).await);
            account = cp.open_account().await.unwrap();
            payment = cp.create_payment_intent(&account, 3).await.unwrap();
            cp.confirm_payment(&payment).await.unwrap(); // balance -> 3
        }
        // Fresh instance on the same DB file.
        let cp2 = ControlPlaneClient::new(spawn_billing(&db).await);
        // Balance persisted -> buying a token succeeds (debits the credit).
        let token = cp2.buy_token(&account, 1).await.unwrap();
        assert_ne!(token.0, [0u8; 32], "a token is minted for the funded account");
        // Idempotency persisted -> confirming the same payment again is refused.
        let replay = cp2.confirm_payment(&payment).await;
        assert!(
            matches!(replay, Err(crate::client::CpError::Status(_))),
            "payment stays confirmed across a service restart"
        );
        let _ = std::fs::remove_file(&db);
    }

    /// Serve the full unified persistent control-plane on an ephemeral port.
    /// The webhook secret the unified-router tests sign their credit events with.
    const TEST_WEBHOOK_SECRET: &[u8] = b"whsec_unified_test";

    async fn spawn_unified(db_path: &str) -> String {
        let app = persistent_control_plane_router(db_path, TEST_WEBHOOK_SECRET, None).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    /// Credit an account by posting a signed "payment succeeded" webhook to a
    /// live unified router — the production top-up path (there is no client
    /// `/payment/confirm`). Returns the HTTP status.
    async fn credit_via_webhook(base: &str, payment: &[u8; 32]) -> reqwest::StatusCode {
        let verifier = WebhookVerifier::new(TEST_WEBHOOK_SECRET.to_vec(), 300);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = format!(
            r#"{{"payment":"{}","status":"succeeded"}}"#,
            hex_encode(payment)
        );
        let sig = verifier.sign(now, body.as_bytes());
        reqwest::Client::new()
            .post(format!("{base}/payment/webhook"))
            .header("x-ct-webhook-timestamp", now.to_string())
            .header("x-ct-webhook-signature", sig)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap()
            .status()
    }

    /// The milestone E2E: the whole control plane (enrollment + registry +
    /// billing on one DB) survives a restart. Drive all three against one
    /// instance, restart on the same file, and confirm every concern persisted.
    #[tokio::test]
    async fn unified_control_plane_survives_restart() {
        let db = temp_db_path();
        let agent = AgentId("agent-u".to_string());
        let token = RoutingToken([0x33; 32]);
        let join;
        let account;
        {
            let base = spawn_unified(&db).await;
            let cp = ControlPlaneClient::new(base.clone());
            // enrollment
            join = cp.issue_join_token(&TenantId("tu".to_string())).await.unwrap();
            cp.redeem(&join, &agent, &[5u8; 32]).await.unwrap();
            // registry
            cp.register(&token, &TenantId("tu".to_string()), &agent).await.unwrap();
            // billing — credit via the signed provider webhook (production path;
            // there is no client-callable /payment/confirm on the unified router).
            account = cp.open_account().await.unwrap();
            let p = cp.create_payment_intent(&account, 2).await.unwrap();
            let status = credit_via_webhook(&base, &p).await;
            assert!(status.is_success(), "signed webhook credits the account");
        }

        // Restart on the same database file.
        let cp2 = ControlPlaneClient::new(spawn_unified(&db).await);
        assert!(
            cp2.redeem(&join, &agent, &[5u8; 32]).await.is_err(),
            "enrollment persisted (token consumed)"
        );
        let (t, a) = cp2.resolve(&token).await.unwrap();
        assert_eq!((t.0.as_str(), a.0.as_str()), ("tu", "agent-u"), "registry persisted");
        let bought = cp2.buy_token(&account, 1).await.unwrap();
        assert_ne!(bought.0, [0u8; 32], "billing persisted (funded account buys a token)");

        let _ = std::fs::remove_file(&db);
    }

    /// M19.3: issuance is tied to the authenticated OIDC subject. Without a valid
    /// bearer token the request is 401; with one, the debit hits the subject's
    /// own account (derived from `sub`, not from the request body).
    #[tokio::test]
    async fn authed_issue_uses_the_subject_account_and_requires_a_token() {
        use axum::body::Body;
        use axum::http::Request;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};
        use tower::ServiceExt;

        let secret = b"realm-secret";
        let issuer = "https://kc/realms/ct";
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let verifier = Arc::new(OidcVerifier::from_hs_secret(secret, issuer));

        // Pre-credit the account bound to the subject so issuance can succeed.
        let account = ledger.account_for_subject("user-1").unwrap();
        ledger.credit(&account, 5).unwrap();

        let app = authed_billing_router(ledger.clone(), verifier, 100);

        // No token -> 401.
        let resp = app
            .clone()
            .oneshot(
                Request::post("/me/issue")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"price":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "no bearer token");

        // Valid token -> 200 and the subject's own account is debited.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = serde_json::json!({ "sub": "user-1", "iss": issuer, "exp": now + 3600 });
        let jwt = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();
        let resp = app
            .clone()
            .oneshot(
                Request::post("/me/issue")
                    .header("authorization", format!("Bearer {jwt}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"price":1}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "authenticated issue succeeds");
        assert_eq!(
            ledger.balance(&account).unwrap(),
            4,
            "the subject's account was debited"
        );
    }

    #[tokio::test]
    async fn authed_issue_is_rate_limited_per_subject() {
        use axum::body::Body;
        use axum::http::Request;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};
        use tower::ServiceExt;

        let secret = b"realm-secret";
        let issuer = "https://kc/realms/ct";
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let verifier = Arc::new(OidcVerifier::from_hs_secret(secret, issuer));

        // Cap issuance at 2 per window for each subject.
        let app = authed_billing_router(ledger, verifier, 2);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = serde_json::json!({ "sub": "user-1", "iss": issuer, "exp": now + 3600 });
        let jwt = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();
        // price 0 so issuance never fails on credit — isolates the rate limit.
        let issue = || {
            app.clone().oneshot(
                Request::post("/me/issue")
                    .header("authorization", format!("Bearer {jwt}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"price":0}"#))
                    .unwrap(),
            )
        };

        // All three requests land in the same wall-clock window.
        assert_eq!(issue().await.unwrap().status(), StatusCode::OK, "1st allowed");
        assert_eq!(issue().await.unwrap().status(), StatusCode::OK, "2nd allowed");
        assert_eq!(
            issue().await.unwrap().status(),
            StatusCode::TOO_MANY_REQUESTS,
            "3rd over the per-subject cap is throttled"
        );
    }

    #[tokio::test]
    async fn payment_webhook_credits_only_on_a_valid_signature() {
        use axum::body::Body;
        use axum::http::Request;
        use std::time::{SystemTime, UNIX_EPOCH};
        use tower::ServiceExt;

        let secret = b"whsec_test";
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let verifier = Arc::new(WebhookVerifier::new(secret.to_vec(), 300));

        // A pending intent for 7 credits on a fresh account.
        let account = ledger.open_account().unwrap();
        let payment = ledger.create_intent(&account, 7).unwrap();
        assert_eq!(ledger.balance(&account).unwrap(), 0);

        let app = payment_webhook_router(ledger.clone(), verifier.clone());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = format!(
            r#"{{"payment":"{}","status":"succeeded"}}"#,
            hex_encode(&payment.0)
        );

        let post = |ts: u64, sig: String, body: String| {
            app.clone().oneshot(
                Request::post("/payment/webhook")
                    .header("x-ct-webhook-timestamp", ts.to_string())
                    .header("x-ct-webhook-signature", sig)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
        };

        // Forged signature -> 401, no credit.
        let resp = post(now, "deadbeef".to_string(), body.clone()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "forged webhook rejected");
        assert_eq!(ledger.balance(&account).unwrap(), 0, "no credit on a bad signature");

        // Valid signature -> 200, account credited.
        let sig = verifier.sign(now, body.as_bytes());
        let resp = post(now, sig.clone(), body.clone()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "signed webhook accepted");
        assert_eq!(ledger.balance(&account).unwrap(), 7, "credited exactly the intent");

        // Replayed valid event -> 200 (idempotent), still credited once.
        let resp = post(now, sig, body).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "replay acknowledged");
        assert_eq!(
            ledger.balance(&account).unwrap(),
            7,
            "idempotent: no double credit"
        );
    }

    #[tokio::test]
    async fn payment_webhook_rejects_a_stale_event() {
        use axum::body::Body;
        use axum::http::Request;
        use std::time::{SystemTime, UNIX_EPOCH};
        use tower::ServiceExt;

        let secret = b"whsec_test";
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let verifier = Arc::new(WebhookVerifier::new(secret.to_vec(), 300));
        let account = ledger.open_account().unwrap();
        let payment = ledger.create_intent(&account, 5).unwrap();

        let app = payment_webhook_router(ledger.clone(), verifier.clone());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Timestamp 10 minutes in the past; tolerance is 5 minutes. The signature
        // is valid for that timestamp, but the event is too old to accept.
        let stale = now - 600;
        let body = format!(
            r#"{{"payment":"{}","status":"succeeded"}}"#,
            hex_encode(&payment.0)
        );
        let sig = verifier.sign(stale, body.as_bytes());
        let resp = app
            .oneshot(
                Request::post("/payment/webhook")
                    .header("x-ct-webhook-timestamp", stale.to_string())
                    .header("x-ct-webhook-signature", sig)
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "stale event rejected");
        assert_eq!(ledger.balance(&account).unwrap(), 0, "no credit for a replay");
    }

    #[tokio::test]
    async fn production_router_mounts_oidc_authed_endpoints_when_configured() {
        use axum::body::Body;
        use axum::http::Request;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};
        use tower::ServiceExt;

        let secret = b"realm-secret";
        let issuer = "https://kc/realms/ct";
        let oidc = Arc::new(OidcVerifier::from_hs_secret(secret, issuer));
        let app =
            persistent_control_plane_router(":memory:", b"whsec", Some(oidc)).unwrap();

        // Without a bearer token the mounted endpoint rejects with 401 (not 404).
        let resp = app
            .clone()
            .oneshot(Request::get("/me/account").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "authed endpoint is gated");

        // A valid token resolves the subject's account through the production router.
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = serde_json::json!({ "sub": "user-1", "iss": issuer, "exp": now + 3600 });
        let jwt = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();
        let resp = app
            .oneshot(
                Request::get("/me/account")
                    .header("authorization", format!("Bearer {jwt}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "authenticated subject gets an account");
    }

    #[tokio::test]
    async fn me_account_exposes_balance_and_subject_for_the_authenticated_customer() {
        // #26 PP1: the self-service account view carries the credit balance
        // (Guthaben) and the verified subject, self-scoped to the caller.
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};
        use tower::ServiceExt;

        let secret = b"realm-secret";
        let issuer = "https://kc/realms/ct";
        let oidc = Arc::new(OidcVerifier::from_hs_secret(secret, issuer));
        let app = persistent_control_plane_router(":memory:", b"whsec", Some(oidc)).unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let claims = serde_json::json!({ "sub": "kc-user-42", "iss": issuer, "exp": now + 3600 });
        let jwt = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();
        let resp = app
            .oneshot(
                Request::get("/me/account")
                    .header("authorization", format!("Bearer {jwt}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["subject"], "kc-user-42", "echoes the verified subject");
        assert_eq!(v["balance"], 0, "a fresh account starts with zero credit");
        assert!(
            v["account"].as_str().is_some_and(|a| !a.is_empty()),
            "carries the account id"
        );
    }

    #[tokio::test]
    async fn production_router_omits_authed_endpoints_without_oidc() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        // With no OIDC verifier configured, /me/* is not mounted at all -> 404.
        let app = persistent_control_plane_router(":memory:", b"whsec", None).unwrap();
        let resp = app
            .oneshot(Request::get("/me/account").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "authed endpoints absent when OIDC is unconfigured"
        );
    }

    #[tokio::test]
    async fn production_router_has_no_client_payment_confirm() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        // The unified production router must not expose the M18 stub endpoint —
        // credits come only from the signed webhook (proven crediting-side by
        // unified_control_plane_survives_restart).
        let app = persistent_control_plane_router(":memory:", b"whsec_prod", None).unwrap();
        let resp = app
            .oneshot(
                Request::post("/payment/confirm")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"payment":"00"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "client-callable /payment/confirm is removed from production"
        );
    }

    #[tokio::test]
    async fn landing_page_serves_self_contained_html() {
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        // The full production router serves the landing page at `/`.
        let app = persistent_control_plane_router(":memory:", b"whsec", None).unwrap();
        let resp = app
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(ct.starts_with("text/html"), "serves HTML, got {ct}");
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let html = String::from_utf8_lossy(&body);
        // Self-contained (no external asset URLs) and renders the status figures.
        assert!(html.contains("operator status"), "has a title");
        assert!(html.contains("fetch('/status')"), "fetches the status endpoint");
        assert!(
            html.contains("registered tunnels") && html.contains("uptime"),
            "renders the key metadata figures"
        );
        assert!(
            !html.contains("http://") && !html.contains("https://") && !html.contains("//cdn"),
            "no external assets (CSP-safe)"
        );
    }

    #[tokio::test]
    async fn pki_endpoint_publishes_the_edge_ca_root() {
        // #11 C1: GET /pki/ca serves the edge CA root DER read from the shared
        // path, and 503s until it exists.
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        let der: &[u8] = b"\x30\x82\x01\x0a-fake-ca-root-der";
        let path = std::env::temp_dir().join(format!("ct-cp-ca-{}.der", std::process::id()));
        std::fs::write(&path, der).unwrap();

        let app = pki_router(path.to_string_lossy().into_owned());
        let resp = app
            .oneshot(Request::get("/pki/ca").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "application/x-x509-ca-cert"
        );
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], der, "serves the exact CA root DER");

        // Missing file (edge hasn't published yet) → 503.
        let app2 = pki_router("/nonexistent/ct-edge-ca.der".to_string());
        let resp2 = app2
            .oneshot(Request::get("/pki/ca").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::SERVICE_UNAVAILABLE);

        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn status_endpoint_reports_aggregated_counts() {
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        let enrollment = Arc::new(SqliteEnrollment::open_in_memory().unwrap());
        let registry = Arc::new(SqliteRegistry::open_in_memory().unwrap());
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());

        // Seed one of each metadata kind.
        let tenant = TenantId("t".into());
        let jt = enrollment.issue_join_token(&tenant).unwrap();
        enrollment
            .redeem(&jt, &AgentId("a".into()), [1u8; 32])
            .unwrap();
        registry
            .register(
                &RoutingToken([2u8; 32]),
                &TunnelInfo {
                    tenant: tenant.clone(),
                    agent: AgentId("a".into()),
                },
            )
            .unwrap();
        let acct = ledger.open_account().unwrap();
        let pid = ledger.create_intent(&acct, 5).unwrap();
        ledger.confirm_payment(&pid).unwrap();

        let app = status_router(enrollment, registry, ledger, None);
        let resp = app
            .oneshot(Request::get("/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let s: StatusResp = serde_json::from_slice(&body).unwrap();
        assert!(s.ready, "db reachable");
        assert_eq!(s.tunnels, 1, "no edge url -> falls back to the CP registry count");
        assert_eq!(s.agents, 1);
        assert_eq!(s.accounts, 1);
        assert_eq!(s.payments_confirmed, 1);
    }

    #[test]
    fn parse_metric_reads_the_named_gauge() {
        let body = "# HELP ct_edge_active_tunnels x\n\
                    # TYPE ct_edge_active_tunnels gauge\n\
                    ct_edge_active_tunnels 4\n\
                    ct_edge_active_agents 9\n";
        assert_eq!(parse_metric(body, "ct_edge_active_tunnels"), Some(4));
        assert_eq!(parse_metric(body, "ct_edge_active_agents"), Some(9));
        assert_eq!(parse_metric(body, "nonexistent"), None);
    }

    #[tokio::test]
    async fn status_reports_live_edge_tunnels_when_configured() {
        // #17: the live tunnel registry lives in the edge, not the CP rendezvous
        // registry (which the onboard/serve path never writes). With an edge
        // metrics URL configured, /status.tunnels must report the edge's live
        // ct_edge_active_tunnels gauge — even when the CP registry is EMPTY.
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        // Mock edge /metrics reporting 3 live tunnels (7 redundant agents).
        let metrics = "# HELP ct_edge_active_tunnels x\n\
                       # TYPE ct_edge_active_tunnels gauge\n\
                       ct_edge_active_tunnels 3\n\
                       # TYPE ct_edge_active_agents gauge\n\
                       ct_edge_active_agents 7\n";
        let edge = Router::new().route("/metrics", get(move || async move { metrics }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, edge).await.unwrap() });

        // CP stores with an EMPTY registry (0 rendezvous entries).
        let enrollment = Arc::new(SqliteEnrollment::open_in_memory().unwrap());
        let registry = Arc::new(SqliteRegistry::open_in_memory().unwrap());
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());

        let app = status_router(
            enrollment,
            registry,
            ledger,
            Some(format!("http://{addr}/metrics")),
        );
        let resp = app
            .oneshot(Request::get("/status").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let s: StatusResp = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            s.tunnels, 3,
            "reports the live edge tunnel count, not the empty CP registry"
        );
    }

    #[tokio::test]
    async fn health_and_readiness_endpoints() {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let app = persistent_control_plane_router(":memory:", b"whsec_health", None).unwrap();

        let health = app
            .clone()
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK, "liveness ok");

        let ready = app
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(ready.status(), StatusCode::OK, "readiness ok (db reachable)");
    }
}
