//! Persistent HTTP surface (M18.4): the same JSON API as [`crate::http`], but
//! backed by the durable SQLite stores instead of in-memory state, so a service
//! restart preserves enrollment / registry / billing. This module grows one
//! router per store; M18.4a wires enrollment.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
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
    BootstrapError, LedgerOpError, PaymentOpError, RedeemError, SqliteBootstrap, SqliteChannelStore,
    SqliteEnrollment, SqliteLedger, SqliteRegistry,
};
use ct_common::channel::ChannelId;
use ct_common::ratelimit::KeyedRateLimiter;
use ct_common::{AgentId, RoutingToken, TenantId};
use ct_common::sync::MutexExt;

/// State for the enrollment router: the durable store plus, when configured, the
/// shared admin token that gates `/enroll/issue` (#87 SEC87b-auth).
#[derive(Clone)]
struct EnrollState {
    store: Arc<SqliteEnrollment>,
    /// When `Some`, `/enroll/issue` requires this token (machine-to-machine auth —
    /// minting join tokens is an operator action, not a public one). `None` leaves it
    /// open (dev/back-compat); the live CP sets it from `CT_CP_EDGE_ADMIN_TOKEN`.
    issue_admin_token: Option<[u8; 32]>,
}

/// Build the persistent enrollment router: `POST /enroll/issue`,
/// `POST /enroll/redeem`, backed by a durable [`SqliteEnrollment`]. `/enroll/issue`
/// is unauthenticated (dev/back-compat); use [`enrollment_router_sqlite_with_admin`]
/// to require the admin token on issuance.
pub fn enrollment_router_sqlite(store: Arc<SqliteEnrollment>) -> Router {
    enrollment_router_sqlite_with_admin(store, None)
}

/// Like [`enrollment_router_sqlite`] but gates `POST /enroll/issue` behind the shared
/// admin token (#87 SEC87b-auth): a caller must present `x-ct-admin-token`. `/enroll/redeem`
/// stays open — an agent redeems with its single-use join token + proof-of-possession,
/// which is its own auth. Only the *issuance* of join tokens is restricted here.
pub fn enrollment_router_sqlite_with_admin(
    store: Arc<SqliteEnrollment>,
    issue_admin_token: Option<[u8; 32]>,
) -> Router {
    Router::new()
        .route("/enroll/issue", post(issue))
        .route("/enroll/redeem", post(redeem))
        .with_state(EnrollState { store, issue_admin_token })
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
    State(st): State<EnrollState>,
    headers: HeaderMap,
    Json(req): Json<IssueReq>,
) -> Result<Json<IssueResp>, (StatusCode, String)> {
    // #87 SEC87b-auth: when configured, minting a join token requires the admin token
    // (constant-time compare) — closing "anyone mints a join token for any tenant".
    if let Some(expected) = st.issue_admin_token {
        let ok = headers
            .get("x-ct-admin-token")
            .and_then(|v| v.to_str().ok())
            .and_then(hex_decode_32)
            .map(|t| ct_token_eq(&t, &expected))
            .unwrap_or(false);
        if !ok {
            return Err((StatusCode::UNAUTHORIZED, "join-token issuance requires the admin token".to_string()));
        }
    }
    let token = st
        .store
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
    /// Hex ed25519 signature over the join token by `pubkey` (#88 SEC88c).
    proof: String,
}
#[derive(Serialize, Deserialize)]
struct RedeemResp {
    tenant: String,
}

async fn redeem(
    State(st): State<EnrollState>,
    Json(req): Json<RedeemReq>,
) -> Result<Json<RedeemResp>, (StatusCode, String)> {
    let token =
        hex_decode_32(&req.token).ok_or((StatusCode::BAD_REQUEST, "malformed token".to_string()))?;
    let pubkey = hex_decode_32(&req.pubkey)
        .ok_or((StatusCode::BAD_REQUEST, "malformed pubkey".to_string()))?;
    let proof = hex_decode_64(&req.proof)
        .ok_or((StatusCode::BAD_REQUEST, "malformed proof".to_string()))?;
    let tenant = st
        .store
        .redeem_with_proof(&JoinToken(token), &AgentId(req.agent), pubkey, &proof)
        .map_err(|e| {
            let code = match &e {
                RedeemError::Enroll(EnrollError::TokenAlreadyUsed) => StatusCode::CONFLICT,
                RedeemError::Enroll(EnrollError::UnknownToken) => StatusCode::NOT_FOUND,
                RedeemError::Enroll(EnrollError::BadProof) => StatusCode::FORBIDDEN,
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

/// Build the **production** registry router with the write route (`POST
/// /registry/register`) optionally gated behind the shared admin token (#87
/// SEC87b-auth-registry), while the read route (`GET /registry/resolve/:token`)
/// stays open (the rendezvous lookup a client needs, no durable write).
///
/// `/registry/register` maps a client-supplied routing token → `(tenant, agent)`
/// in the durable registry; left open it is an unauthenticated durable-SQLite
/// writer surface (#87). No live customer path uses it — the agent registers its
/// tunnel over the **QUIC data path to the edge** (`register_tunnel_stream`), not
/// this HTTP route; the only HTTP caller is the operator selftest (`cp_selftest`),
/// which now presents the admin token. So — like `/enroll/issue` and the billing
/// writers — it's gated with the same `CT_CP_EDGE_ADMIN_TOKEN`. When `admin_token`
/// is `None` it stays open (dev/back-compat).
pub fn registry_router_sqlite_gated(store: Arc<SqliteRegistry>, admin_token: Option<[u8; 32]>) -> Router {
    let resolve = Router::new()
        .route("/registry/resolve/:token", get(resolve_tunnel))
        .with_state(store.clone());
    let register = Router::new()
        .route("/registry/register", post(register_tunnel))
        .with_state(store);
    let register = match admin_token {
        Some(token) => register.layer(from_fn_with_state(AdminGate { token }, require_admin_token)),
        None => register,
    };
    resolve.merge(register)
}

/// Default TTL (seconds) for a minted bootstrap token (#90/#97 SEC90b-wire): short,
/// because it exists only to be redeemed once, promptly, by the install one-liner.
const BOOTSTRAP_TTL_SECS: u64 = 600;

/// Shared state for the bootstrap-token exchange routes.
#[derive(Clone)]
struct BootstrapState {
    store: Arc<SqliteBootstrap>,
}

/// Build the **bootstrap-token exchange** router (#90/#97 SEC90b-wire): the wire
/// half of the exchange whose durable core is [`SqliteBootstrap`]. It lets the
/// install/channel one-liner carry only a short-lived, single-use opaque token
/// instead of the real secrets (which today are embedded in the shown command and so
/// land in shell history / `ps`).
///
/// * `POST /bootstrap/mint` `{secret, ttl_secs?}` → `{token}` — **admin-gated** (minting
///   hands off control of a secret bundle; same `CT_CP_EDGE_ADMIN_TOKEN` as the other
///   operator writers). The operator/portal mints when generating an install one-liner.
/// * `POST /bootstrap/redeem` `{token}` → `{secret}` — **public**: possession of the
///   short-lived single-use token is the authorization, and it is handed off over TLS
///   in the response body (never on the command line). `404` unknown, `409` already
///   used, `410` expired.
pub fn bootstrap_router(store: Arc<SqliteBootstrap>, admin_token: Option<[u8; 32]>) -> Router {
    let redeem = Router::new()
        .route("/bootstrap/redeem", post(bootstrap_redeem))
        .with_state(BootstrapState { store: store.clone() });
    let mint = Router::new()
        .route("/bootstrap/mint", post(bootstrap_mint))
        .with_state(BootstrapState { store });
    let mint = match admin_token {
        Some(token) => mint.layer(from_fn_with_state(AdminGate { token }, require_admin_token)),
        None => mint,
    };
    redeem.merge(mint)
}

/// Seconds since the Unix epoch (wall clock), for the bootstrap-token TTL.
fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Deserialize)]
struct BootstrapMintReq {
    secret: String,
    ttl_secs: Option<u64>,
}
#[derive(Serialize, Deserialize)]
struct BootstrapMintResp {
    token: String,
}

async fn bootstrap_mint(
    State(st): State<BootstrapState>,
    Json(req): Json<BootstrapMintReq>,
) -> Result<Json<BootstrapMintResp>, (StatusCode, String)> {
    let ttl = req.ttl_secs.unwrap_or(BOOTSTRAP_TTL_SECS);
    let token = st
        .store
        .mint(&req.secret, ttl, now_secs())
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(BootstrapMintResp {
        token: hex_encode(&token),
    }))
}

#[derive(Deserialize)]
struct BootstrapRedeemReq {
    token: String,
}
#[derive(Serialize, Deserialize)]
struct BootstrapRedeemResp {
    secret: String,
}

async fn bootstrap_redeem(
    State(st): State<BootstrapState>,
    Json(req): Json<BootstrapRedeemReq>,
) -> Result<Json<BootstrapRedeemResp>, (StatusCode, String)> {
    let token = hex_decode_32(&req.token)
        .ok_or((StatusCode::BAD_REQUEST, "malformed token".to_string()))?;
    match st.store.redeem(&token, now_secs()) {
        Ok(secret) => Ok(Json(BootstrapRedeemResp { secret })),
        Err(BootstrapError::UnknownToken) => {
            Err((StatusCode::NOT_FOUND, "unknown bootstrap token".to_string()))
        }
        Err(BootstrapError::AlreadyUsed) => {
            Err((StatusCode::CONFLICT, "bootstrap token already used".to_string()))
        }
        Err(BootstrapError::Expired) => {
            Err((StatusCode::GONE, "bootstrap token expired".to_string()))
        }
        Err(BootstrapError::Db(e)) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
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

/// Shared token for a machine/operator-writer admin gate (#87 SEC87b-auth): the
/// `x-ct-admin-token` a caller must present to reach a gated durable-writer route.
#[derive(Clone)]
struct AdminGate {
    token: [u8; 32],
}

/// Reject a request that does not carry the correct `x-ct-admin-token`
/// (constant-time compare). Applied as a layer only when the CP has an admin
/// token configured; shared by the billing and registry writer gates.
async fn require_admin_token(
    State(state): State<AdminGate>,
    headers: HeaderMap,
    req: Request,
    next: Next,
) -> Response {
    let ok = headers
        .get("x-ct-admin-token")
        .and_then(|v| v.to_str().ok())
        .and_then(hex_decode_32)
        .map(|got| ct_token_eq(&got, &state.token))
        .unwrap_or(false);
    if ok {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            "this control-plane write requires the admin token\n",
        )
            .into_response()
    }
}

/// Build the **production** billing-writer router — `/accounts/open`,
/// `/payment/intent`, `/billing/issue` — optionally gated behind the shared admin
/// token (#87 SEC87b-auth-billing).
///
/// These three routes take a **client-supplied** account (or mint an anonymous one),
/// so left open they are an unauthenticated durable-SQLite writer surface (#87). The
/// real customer top-up path is **not** here: it is the session-authenticated portal
/// (`POST /portal/account/credits`, which derives the account from the verified
/// subject and calls the ledger in-process). So — exactly like `/enroll/issue` — these
/// HTTP routes are a machine/operator surface, gated with the same
/// `CT_CP_EDGE_ADMIN_TOKEN` the edge/operator already hold rather than an OIDC user
/// bearer. When `admin_token` is `None` they stay open (dev/back-compat). `/payment/webhook`
/// (provider-signature-authed) and the customer `/me/*` / portal paths are unaffected.
pub fn billing_writers_gated(store: Arc<SqliteLedger>, admin_token: Option<[u8; 32]>) -> Router {
    let writers = Router::new()
        .route("/accounts/open", post(open_account))
        .route("/payment/intent", post(create_payment_intent))
        .route("/billing/issue", post(buy_token))
        .with_state(store);
    match admin_token {
        Some(token) => writers.layer(from_fn_with_state(AdminGate { token }, require_admin_token)),
        None => writers,
    }
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
    // #87 SEC87a: a token costs at least TOKEN_PRICE — reject an underpayment
    // (notably price:0) before touching the ledger, so it can't mint a free token.
    if !crate::billing::issuance_price_ok(req.price) {
        return Err((
            StatusCode::PAYMENT_REQUIRED,
            format!("a routing token costs at least {} credit(s)", crate::billing::TOKEN_PRICE),
        ));
    }
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

/// Shared state for the authenticated Agent-Fabric channel registry (#81 SEC81c-b):
/// the durable channel store + the OIDC verifier. The channel `owner` is always the
/// verified token subject, never a request field, so a caller can only register or
/// manage channels they own.
#[derive(Clone)]
pub struct AuthedChannelState {
    channels: Arc<SqliteChannelStore>,
    verifier: Arc<OidcVerifier>,
}

/// Build the **authenticated** Agent-Fabric channel-registry router (#81 SEC81c-b):
/// owner-scoped channel registration + membership management, backed by
/// [`SqliteChannelStore`]. Like `/me/*`, mounted only when an OIDC verifier is
/// configured; the `owner` is the verified subject, so this adds **no** unauthenticated
/// DB-writing surface (cf. #87). It provides the operator-key + membership records that
/// the edge channel broker's `authorize` lookup (SEC81c-a `authorize_holder`) reads.
///
/// * `POST /me/channels` `{channel, operator_pubkey}` → register (owner = subject); `403` if
///   the channel is already owned by another subject
/// * `POST /me/channels/:channel/members` `{holder}` → add a member (owner-scoped)
/// * `POST /me/channels/:channel/members/:holder/remove` → remove a member (revocation)
pub fn authed_channel_router(
    channels: Arc<SqliteChannelStore>,
    verifier: Arc<OidcVerifier>,
) -> Router {
    Router::new()
        .route("/me/channels", post(channel_register))
        .route("/me/channels/:channel/members", post(channel_add_member))
        .route(
            "/me/channels/:channel/members/:holder/remove",
            post(channel_remove_member),
        )
        .with_state(AuthedChannelState { channels, verifier })
}

#[derive(Deserialize)]
struct ChannelRegisterReq {
    channel: String,
    operator_pubkey: String,
}

async fn channel_register(
    State(state): State<AuthedChannelState>,
    headers: HeaderMap,
    Json(req): Json<ChannelRegisterReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    let owner = subject_of(&state.verifier, &headers)?;
    let channel = hex_decode_32(&req.channel)
        .ok_or((StatusCode::BAD_REQUEST, "malformed channel".to_string()))?;
    let operator = hex_decode_32(&req.operator_pubkey)
        .ok_or((StatusCode::BAD_REQUEST, "malformed operator_pubkey".to_string()))?;
    let ok = state
        .channels
        .register_channel(&ChannelId(channel), &operator, &owner)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // `register_channel` returns false only when the channel already belongs to a
    // different subject — never let one owner re-key another's channel.
    if ok {
        Ok(StatusCode::OK)
    } else {
        Err((StatusCode::FORBIDDEN, "channel owned by another subject".to_string()))
    }
}

#[derive(Deserialize)]
struct MemberReq {
    holder: String,
    /// The member's X25519 Noise static key (#72 AF4) — the peer pins this for the
    /// direct-path Noise_IK handshake.
    noise_pubkey: String,
    /// The member's attestation over `noise_pubkey` (#101): the holder's ed25519
    /// signature over `member_noise_attest_bytes(channel, holder, noise_pubkey)`,
    /// hex. The CP verifies it, so an un-attested / operator-forged key is rejected.
    noise_attestation: String,
}

async fn channel_add_member(
    State(state): State<AuthedChannelState>,
    headers: HeaderMap,
    Path(channel_hex): Path<String>,
    Json(req): Json<MemberReq>,
) -> Result<StatusCode, (StatusCode, String)> {
    let owner = subject_of(&state.verifier, &headers)?;
    let channel = hex_decode_32(&channel_hex)
        .ok_or((StatusCode::BAD_REQUEST, "malformed channel".to_string()))?;
    let holder = hex_decode_32(&req.holder)
        .ok_or((StatusCode::BAD_REQUEST, "malformed holder".to_string()))?;
    let noise_pubkey = hex_decode_32(&req.noise_pubkey)
        .ok_or((StatusCode::BAD_REQUEST, "malformed noise_pubkey".to_string()))?;
    let noise_attestation = hex_decode_64(&req.noise_attestation)
        .ok_or((StatusCode::BAD_REQUEST, "malformed noise_attestation".to_string()))?;
    // #101 SEC101b: the Noise key must be attested by the holder — a signature over
    // (channel, holder, noise_pubkey) under the holder key. Reject an un-attested or
    // forged key so a DB-controlling operator can't seed a MITM key.
    if !ct_common::channel::verify_member_noise_attestation(
        &ChannelId(channel),
        &holder,
        &noise_pubkey,
        &noise_attestation,
    ) {
        return Err((
            StatusCode::BAD_REQUEST,
            "noise_attestation does not verify against the holder key".to_string(),
        ));
    }
    let ok = state
        .channels
        .add_member(&ChannelId(channel), &owner, &holder, &noise_pubkey, &noise_attestation)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // false → not the owner (or unknown channel): only the owner manages members.
    if ok {
        Ok(StatusCode::OK)
    } else {
        Err((StatusCode::FORBIDDEN, "not the channel owner".to_string()))
    }
}

async fn channel_remove_member(
    State(state): State<AuthedChannelState>,
    headers: HeaderMap,
    Path((channel_hex, holder_hex)): Path<(String, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let owner = subject_of(&state.verifier, &headers)?;
    let channel = hex_decode_32(&channel_hex)
        .ok_or((StatusCode::BAD_REQUEST, "malformed channel".to_string()))?;
    let holder = hex_decode_32(&holder_hex)
        .ok_or((StatusCode::BAD_REQUEST, "malformed holder".to_string()))?;
    let ok = state
        .channels
        .remove_member(&ChannelId(channel), &owner, &holder)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if ok {
        Ok(StatusCode::OK)
    } else {
        Err((StatusCode::FORBIDDEN, "not the channel owner".to_string()))
    }
}

/// Extract + verify the `Authorization: Bearer` token against `verifier`,
/// returning the authenticated subject. Shared by every self-scoped endpoint so
/// the acting identity always comes from a verified token, never the request body.
fn subject_of(
    verifier: &OidcVerifier,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, String)> {
    let token = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or((StatusCode::UNAUTHORIZED, "missing bearer token".to_string()))?;
    verifier
        .subject(token)
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))
}

/// Extract + verify the bearer token, returning the authenticated subject.
fn authed_subject(state: &AuthedState, headers: &HeaderMap) -> Result<String, (StatusCode, String)> {
    subject_of(&state.verifier, headers)
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
    // #87 SEC87a: reject an underpayment (notably price:0) before the ledger, so a
    // funded, in-rate subject still cannot mint a token for less than TOKEN_PRICE.
    if !crate::billing::issuance_price_ok(req.price) {
        return Err((
            StatusCode::PAYMENT_REQUIRED,
            format!("a routing token costs at least {} credit(s)", crate::billing::TOKEN_PRICE),
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
 .top{display:flex;align-items:baseline;justify-content:space-between;flex-wrap:wrap;gap:.75rem}
 a.btn{display:inline-block;background:#238636;color:#fff;padding:.55rem 1.1rem;border-radius:8px;font-weight:600;text-decoration:none}
 a.btn:hover{background:#2ea043}
</style></head><body>
<div class="top">
 <h1>claude-tunnel — operator status</h1>
 <a class="btn" href="/portal">Zum Kundenportal — Anmelden &rarr;</a>
</div>
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
/// Fixed window (seconds) for the unauthenticated-writer rate limit (#87 SEC87b-rl).
const UNAUTH_WRITE_WINDOW_SECS: u64 = 60;

/// The unauthenticated, DB-writing endpoints a flood could grow the durable SQLite
/// store with (#87). They take no bearer token, so the only stable caller key is the
/// client IP — the per-IP limiter is applied to exactly these `POST` paths.
const UNAUTH_WRITE_PATHS: &[&str] = &[
    "/enroll/issue",
    "/accounts/open",
    "/registry/register",
    "/payment/intent",
];

/// Per-client-IP fixed-window limiter state for the unauthenticated DB-writers.
#[derive(Clone)]
struct UnauthWriteLimit {
    limiter: Arc<Mutex<KeyedRateLimiter<IpAddr>>>,
}

/// Wrap `app` so that each unauthenticated DB-writing `POST` (see
/// [`UNAUTH_WRITE_PATHS`]) is capped at `per_window` requests per client IP per
/// fixed window (#87 SEC87b-rl) — a flood from one source gets `429` before it can
/// grow the durable store, bounding the disk-DoS. Only those paths are metered;
/// every other request (reads, authed `/me/*`, health) passes straight through. The
/// client IP comes from the connection (`ConnectInfo`); if it can't be determined
/// the request fails **open** (passes through) rather than erroring.
pub(crate) fn with_unauth_write_limit(app: Router, per_window: u32) -> Router {
    let state = UnauthWriteLimit {
        limiter: Arc::new(Mutex::new(KeyedRateLimiter::new(per_window))),
    };
    app.layer(from_fn_with_state(state, limit_unauth_writes))
}

async fn limit_unauth_writes(
    State(state): State<UnauthWriteLimit>,
    peer: Option<ConnectInfo<SocketAddr>>,
    req: Request,
    next: Next,
) -> Response {
    let metered =
        req.method() == Method::POST && UNAUTH_WRITE_PATHS.contains(&req.uri().path());
    if let (true, Some(ConnectInfo(addr))) = (metered, peer) {
        let window = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() / UNAUTH_WRITE_WINDOW_SECS)
            .unwrap_or(0);
        if !state.limiter.lock_safe().allow(&addr.ip(), window) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                "rate limit: too many unauthenticated requests from your address\n",
            )
                .into_response();
        }
    }
    next.run(req).await
}

pub fn persistent_control_plane_router(
    db_path: &str,
    webhook_secret: &[u8],
    oidc: Option<Arc<OidcVerifier>>,
) -> rusqlite::Result<Router> {
    let enrollment = Arc::new(SqliteEnrollment::open(db_path)?);
    let registry = Arc::new(SqliteRegistry::open(db_path)?);
    let ledger = Arc::new(SqliteLedger::open(db_path)?);
    let tunnels = Arc::new(crate::storage::SqliteTunnelStore::open(db_path)?);
    let channels = Arc::new(SqliteChannelStore::open(db_path)?);
    let bootstrap = Arc::new(SqliteBootstrap::open(db_path)?);
    let verifier = Arc::new(WebhookVerifier::new(
        webhook_secret.to_vec(),
        WEBHOOK_TOLERANCE_SECS,
    ));
    // Production billing surface: accounts, payment intents and credit-gated
    // issuance, but **no** client-callable `/payment/confirm` — credits flow only
    // from a signature-verified provider webhook (M24). That defuses the M18 stub
    // where any caller could top up an account for free. #87 SEC87b-auth-billing:
    // these three client-supplied-account writers are gated behind the shared admin
    // token when the CP has one configured (the customer path is the session-authed
    // portal, not these HTTP routes); wired just below with `issue_admin_token`.
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
    // #87 SEC87b-auth: gate the machine/operator durable-writer surfaces behind the
    // shared admin token when the CP has one configured (the same CT_CP_EDGE_ADMIN_TOKEN
    // the edge/operator hold), so a public deployment can't have anyone mint join tokens
    // (`/enroll/issue`), grow the billing store with client-supplied accounts
    // (`/accounts/open`, `/payment/intent`, `/billing/issue`), or write the durable
    // routing registry (`/registry/register`). The real customer/agent flows (in-process
    // portal mint / session-authed top-up / QUIC tunnel registration to the edge) don't
    // use these routes, so this is transparent to customers; `/registry/resolve` (read)
    // stays open. The operator selftest presents the token via ControlPlaneClient.
    let admin_token = std::env::var("CT_CP_EDGE_ADMIN_TOKEN")
        .ok()
        .filter(|s| !s.is_empty())
        .and_then(|s| hex_decode_32(&s));
    let mut app = enrollment_router_sqlite_with_admin(enrollment.clone(), admin_token)
        .merge(registry_router_sqlite_gated(registry, admin_token))
        .merge(billing_writers_gated(ledger.clone(), admin_token))
        // #90/#97 SEC90b-wire: bootstrap-token exchange — /bootstrap/mint (admin-gated)
        // + /bootstrap/redeem (public, single-use short-TTL token handed off over TLS).
        .merge(bootstrap_router(bootstrap, admin_token))
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
            enrollment.clone(),
            &std::env::var("CT_PORTAL_BASE_URL").unwrap_or_else(|_| "https://localhost".to_string()),
            // #27 RB4b: propagate tunnel revokes to the edge when both the admin
            // URL and shared secret are configured.
            match (
                std::env::var("CT_CP_EDGE_ADMIN_URL").ok().filter(|s| !s.is_empty()),
                std::env::var("CT_CP_EDGE_ADMIN_TOKEN").ok().filter(|s| !s.is_empty()),
            ) {
                (Some(url), Some(token)) => Some((url, token)),
                _ => None,
            },
            // #38 DL2: automatic tunnel-hostname DNS via deSEC, pointing A records
            // at the edge's public IP. Enabled when the deSEC config + edge IP are set.
            match (
                ct_dns::provider::DesecClient::from_env(),
                std::env::var("CT_CP_DNS_EDGE_IP").ok().filter(|s| !s.is_empty()),
            ) {
                (Some(client), Some(ip)) => Some((client, ip)),
                _ => None,
            },
        ))
        .merge(pki)
        // #75 IS3b: serve /install.sh + /install.ps1 (the portal one-liner targets
        // that were 404ing). CT_RELEASE_BASE overrides the GitHub-Releases asset
        // base the served scripts download the prebuilt ct-agent from.
        .merge(crate::installer::installer_router(
            std::env::var("CT_RELEASE_BASE")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| crate::installer::DEFAULT_RELEASE_BASE.to_string()),
        ));
    // #81 SEC81c-c (c-i): the live edge queries this to authorize channel-joins (the
    // broker's `authorize` closure). Gated by the shared edge↔CP admin token; mounted
    // only when CT_CP_EDGE_ADMIN_TOKEN is a valid 64-hex value.
    if let Some(admin_tok) = std::env::var("CT_CP_EDGE_ADMIN_TOKEN")
        .ok()
        .filter(|s| !s.is_empty())
        .and_then(|s| hex_decode_32(&s))
    {
        app = app.merge(internal_channel_authorize_router(channels.clone(), admin_tok));
    }
    // Authenticated per-subject endpoints (`/me/*`) — mounted only when an OIDC
    // verifier is configured (M26.1). Without one they are simply absent (404).
    if let Some(oidc) = oidc {
        app = app
            .merge(authed_billing_router(
                ledger.clone(),
                oidc.clone(),
                AUTHED_ISSUES_PER_WINDOW,
            ))
            // #81 SEC81c-b: authenticated Agent-Fabric channel registry (owner =
            // verified subject), so it carries no unauthenticated write surface.
            .merge(authed_channel_router(channels, oidc));
    }
    let app = app.merge(health_router(ledger));
    // #87 SEC87b-rl: optional per-IP flood cap on the unauthenticated DB-writers.
    // Off by default (no behavior change — the auth model + a default-on policy are
    // the maintainer decision this doesn't presume); set CT_CP_UNAUTH_WRITE_PER_MIN
    // to a positive integer to bound the disk-DoS from a single address.
    let app = match std::env::var("CT_CP_UNAUTH_WRITE_PER_MIN")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|&n| n > 0)
    {
        Some(per_min) => with_unauth_write_limit(app, per_min),
        None => app,
    };
    Ok(app)
}

/// Shared state for the edge-facing channel-authorize endpoint (#81 SEC81c-c c-i):
/// the channel registry + the shared edge↔CP admin token the edge presents.
#[derive(Clone)]
pub struct AdminChannelState {
    channels: Arc<SqliteChannelStore>,
    admin_token: [u8; 32],
}

/// Constant-time 32-byte token comparison (avoid leaking the admin token via timing).
fn ct_token_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Build the **edge-facing** channel-authorize router (#81 SEC81c-c c-i): the live edge
/// broker's admission gate needs `authorize(channel, holder) -> Option<operator_pubkey>`
/// (the operator key iff the holder is a current member — folding gap-2 membership/
/// revocation into the key source). The registry lives in the control plane, so the edge
/// queries this endpoint, presenting the shared edge↔CP admin token. Read-only; mounted
/// only when the admin token is configured.
///
/// * `POST /internal/channel/authorize` `{channel, holder}` + header `x-ct-admin-token`
///   → `200 {operator_pubkey}` iff member; `401` bad/missing token; `404` non-member.
fn internal_channel_authorize_router(
    channels: Arc<SqliteChannelStore>,
    admin_token: [u8; 32],
) -> Router {
    Router::new()
        .route("/internal/channel/authorize", post(channel_authorize))
        .with_state(AdminChannelState {
            channels,
            admin_token,
        })
}

#[derive(Deserialize)]
struct AuthorizeReq {
    channel: String,
    holder: String,
}
#[derive(Serialize, Deserialize)]
struct AuthorizeResp {
    operator_pubkey: String,
    /// The member's attested Noise static key (hex), when the registry has one
    /// (#72 AF4 / #100): the edge broker relays it to the paired peer so an A2A
    /// initiator can pin it without the operator pasting it. Absent for members
    /// enrolled before AF4-keydist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    noise_pubkey: Option<String>,
    /// The member's holder-signed attestation over `noise_pubkey` (#101, hex): the
    /// broker relays it so the peer can verify the Noise key is genuinely the holder's
    /// before pinning it (rejecting a DB-substituted key). Absent for members enrolled
    /// before attestation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    noise_attestation: Option<String>,
}

async fn channel_authorize(
    State(state): State<AdminChannelState>,
    headers: HeaderMap,
    Json(req): Json<AuthorizeReq>,
) -> Result<Json<AuthorizeResp>, StatusCode> {
    // Verify the shared edge↔CP admin token (constant time) before any lookup.
    let ok = headers
        .get("x-ct-admin-token")
        .and_then(|v| v.to_str().ok())
        .and_then(hex_decode_32)
        .map(|t| ct_token_eq(&t, &state.admin_token))
        .unwrap_or(false);
    if !ok {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let channel = hex_decode_32(&req.channel).ok_or(StatusCode::BAD_REQUEST)?;
    let holder = hex_decode_32(&req.holder).ok_or(StatusCode::BAD_REQUEST)?;
    match state
        .channels
        .authorize_holder(&ChannelId(channel), &holder)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    {
        Some(op) => {
            // Also hand back the member's attested Noise key (if registered) so the
            // broker can deliver it to the paired peer (#72 AF4 / #100).
            let noise = state
                .channels
                .member_noise_key(&ChannelId(channel), &holder)
                .ok()
                .flatten()
                .map(|n| hex_encode(&n));
            let attestation = state
                .channels
                .member_noise_attestation(&ChannelId(channel), &holder)
                .ok()
                .flatten()
                .map(|a| hex_encode(&a));
            Ok(Json(AuthorizeResp {
                operator_pubkey: hex_encode(&op),
                noise_pubkey: noise,
                noise_attestation: attestation,
            }))
        }
        None => Err(StatusCode::NOT_FOUND),
    }
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

fn hex_decode_64(s: &str) -> Option<[u8; 64]> {
    if s.len() != 128 {
        return None;
    }
    let mut out = [0u8; 64];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ControlPlaneClient;

    #[tokio::test]
    async fn enroll_issue_requires_the_admin_token_when_configured() {
        // #87 SEC87b-auth: with an admin token configured, POST /enroll/issue requires
        // x-ct-admin-token (401 without / wrong, 200 with). With none configured it's
        // open (dev/back-compat). /enroll/redeem is unaffected (agent-authed by its
        // single-use token + proof).
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let admin = [0x7au8; 32];
        let store = Arc::new(SqliteEnrollment::open_in_memory().unwrap());
        let app = enrollment_router_sqlite_with_admin(store, Some(admin));
        let issue = |tok: Option<String>| {
            let mut req = Request::post("/enroll/issue").header("content-type", "application/json");
            if let Some(t) = tok {
                req = req.header("x-ct-admin-token", t);
            }
            app.clone().oneshot(req.body(Body::from(r#"{"tenant":"t1"}"#)).unwrap())
        };
        assert_eq!(issue(None).await.unwrap().status(), StatusCode::UNAUTHORIZED, "no token -> 401");
        assert_eq!(
            issue(Some(hex_encode(&[0u8; 32]))).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "wrong token -> 401"
        );
        assert_eq!(
            issue(Some(hex_encode(&admin))).await.unwrap().status(),
            StatusCode::OK,
            "correct admin token issues a join token"
        );

        // No admin token configured -> issuance is open (dev/back-compat).
        let open = enrollment_router_sqlite_with_admin(Arc::new(SqliteEnrollment::open_in_memory().unwrap()), None);
        let r = open
            .oneshot(
                Request::post("/enroll/issue")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"tenant":"t"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "issuance open when no admin token is configured");
    }

    #[tokio::test]
    async fn billing_writers_require_the_admin_token_when_configured() {
        // #87 SEC87b-auth-billing: with an admin token configured, the client-supplied-account
        // billing writers (/accounts/open, /payment/intent, /billing/issue) require
        // x-ct-admin-token (401 without / wrong). With none configured they stay open
        // (dev/back-compat). The customer path is the session-authed portal, not these routes.
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let admin = [0x3cu8; 32];
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let gated = billing_writers_gated(ledger.clone(), Some(admin));
        let open_req = |tok: Option<String>| {
            let mut req = Request::post("/accounts/open").header("content-type", "application/json");
            if let Some(t) = tok {
                req = req.header("x-ct-admin-token", t);
            }
            gated.clone().oneshot(req.body(Body::from("{}")).unwrap())
        };
        assert_eq!(open_req(None).await.unwrap().status(), StatusCode::UNAUTHORIZED, "no token -> 401");
        assert_eq!(
            open_req(Some(hex_encode(&[0u8; 32]))).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "wrong token -> 401"
        );
        // Correct token opens an account (200 with a JSON account id).
        let r = open_req(Some(hex_encode(&admin))).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK, "correct admin token opens an account");

        // /payment/intent is gated too (needs a real account first — open one with the token).
        let intent_no_tok = gated
            .clone()
            .oneshot(
                Request::post("/payment/intent")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"account":"00","credits":5}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(intent_no_tok.status(), StatusCode::UNAUTHORIZED, "/payment/intent gated");

        // No admin token configured -> writers stay open (dev/back-compat).
        let open = billing_writers_gated(Arc::new(SqliteLedger::open_in_memory().unwrap()), None);
        let r = open
            .oneshot(
                Request::post("/accounts/open")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "billing writers open when no admin token is configured");
    }

    #[tokio::test]
    async fn registry_register_requires_the_admin_token_but_resolve_stays_open() {
        // #87 SEC87b-auth-registry: with an admin token configured, POST /registry/register
        // requires x-ct-admin-token (401 without / wrong, 200 with), while GET
        // /registry/resolve stays open (a read, no durable write). With no token
        // configured, register is open (dev/back-compat).
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;

        let admin = [0x5eu8; 32];
        let store = Arc::new(SqliteRegistry::open_in_memory().unwrap());
        let gated = registry_router_sqlite_gated(store.clone(), Some(admin));
        let tok = hex_encode(&[0x11u8; 32]); // routing token to register/resolve
        let reg = |admin_hdr: Option<String>| {
            let mut req = Request::post("/registry/register").header("content-type", "application/json");
            if let Some(t) = admin_hdr {
                req = req.header("x-ct-admin-token", t);
            }
            gated.clone().oneshot(
                req.body(Body::from(format!(
                    r#"{{"token":"{tok}","tenant":"t","agent":"a"}}"#
                )))
                .unwrap(),
            )
        };
        assert_eq!(reg(None).await.unwrap().status(), StatusCode::UNAUTHORIZED, "no token -> 401");
        assert_eq!(
            reg(Some(hex_encode(&[0u8; 32]))).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "wrong token -> 401"
        );
        assert_eq!(
            reg(Some(hex_encode(&admin))).await.unwrap().status(),
            StatusCode::OK,
            "correct admin token registers"
        );
        // Resolve (read) is open even with a token configured, and returns the row
        // the authorized register just wrote.
        let resolved = gated
            .clone()
            .oneshot(Request::get(format!("/registry/resolve/{tok}")).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resolved.status(), StatusCode::OK, "resolve stays open (no admin token needed)");

        // No admin token configured -> register is open (dev/back-compat).
        let open = registry_router_sqlite_gated(Arc::new(SqliteRegistry::open_in_memory().unwrap()), None);
        let r = open
            .oneshot(
                Request::post("/registry/register")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"token":"{tok}","tenant":"t","agent":"a"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "register open when no admin token is configured");
    }

    #[tokio::test]
    async fn bootstrap_mint_is_admin_gated_and_redeem_hands_off_once() {
        // #90/#97 SEC90b-wire: /bootstrap/mint is admin-gated (minting hands off a
        // secret bundle); /bootstrap/redeem is public (possession of the short-lived
        // single-use token is the auth) and returns the secret in the TLS body exactly
        // once — 409 on reuse, 404 on unknown.
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        let admin = [0x9au8; 32];
        let store = Arc::new(SqliteBootstrap::open_in_memory().unwrap());
        let app = bootstrap_router(store, Some(admin));

        // Mint requires the admin token.
        let mint_no = app
            .clone()
            .oneshot(
                Request::post("/bootstrap/mint")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"secret":"join=aa;routing=bb"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mint_no.status(), StatusCode::UNAUTHORIZED, "mint needs the admin token");

        // Mint with the admin token returns a bootstrap token.
        let mint = app
            .clone()
            .oneshot(
                Request::post("/bootstrap/mint")
                    .header("content-type", "application/json")
                    .header("x-ct-admin-token", hex_encode(&admin))
                    .body(Body::from(r#"{"secret":"join=aa;routing=bb"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mint.status(), StatusCode::OK);
        let mb = to_bytes(mint.into_body(), 1 << 16).await.unwrap();
        let minted: BootstrapMintResp = serde_json::from_slice(&mb).unwrap();

        let redeem = |tok: String| {
            app.clone().oneshot(
                Request::post("/bootstrap/redeem")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"token":"{tok}"}}"#)))
                    .unwrap(),
            )
        };

        // Redeem is public and hands off the exact secret once.
        let r1 = redeem(minted.token.clone()).await.unwrap();
        assert_eq!(r1.status(), StatusCode::OK, "redeem is public");
        let b1 = to_bytes(r1.into_body(), 1 << 16).await.unwrap();
        let got: BootstrapRedeemResp = serde_json::from_slice(&b1).unwrap();
        assert_eq!(got.secret, "join=aa;routing=bb", "hands off the exact minted secret");

        // Second redemption -> 409 (single-use), unknown token -> 404.
        assert_eq!(
            redeem(minted.token.clone()).await.unwrap().status(),
            StatusCode::CONFLICT,
            "single-use: second redeem is 409"
        );
        assert_eq!(
            redeem(hex_encode(&[0u8; 32])).await.unwrap().status(),
            StatusCode::NOT_FOUND,
            "unknown token -> 404"
        );

        // With no admin token configured, mint is open (dev/back-compat).
        let open = bootstrap_router(Arc::new(SqliteBootstrap::open_in_memory().unwrap()), None);
        let r = open
            .oneshot(
                Request::post("/bootstrap/mint")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"secret":"x"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK, "mint open when no admin token is configured");
    }

    #[tokio::test]
    async fn unauthenticated_writers_are_rate_limited_per_ip() {
        // #87 SEC87b-rl: a per-IP fixed-window cap on the unauthenticated
        // DB-writers. One address that floods a metered POST is `429`'d past the
        // limit; a different address has its own budget; a non-listed path and a
        // read are never metered.
        use axum::body::Body;
        use tower::ServiceExt;

        let app = with_unauth_write_limit(
            Router::new()
                .route("/accounts/open", post(|| async { StatusCode::OK }))
                .route("/other", post(|| async { StatusCode::OK }))
                .route("/registry/resolve/x", get(|| async { StatusCode::OK })),
            2,
        );

        let a: SocketAddr = "203.0.113.5:5000".parse().unwrap();
        let b: SocketAddr = "203.0.113.6:5000".parse().unwrap();
        async fn call(app: &Router, method: Method, path: &str, peer: SocketAddr) -> StatusCode {
            let mut req = Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap();
            req.extensions_mut().insert(ConnectInfo(peer));
            app.clone().oneshot(req).await.unwrap().status()
        }

        // A: first two metered POSTs pass, the third is throttled.
        assert_eq!(call(&app, Method::POST, "/accounts/open", a).await, StatusCode::OK);
        assert_eq!(call(&app, Method::POST, "/accounts/open", a).await, StatusCode::OK);
        assert_eq!(
            call(&app, Method::POST, "/accounts/open", a).await,
            StatusCode::TOO_MANY_REQUESTS,
            "the 3rd metered POST from the same IP is rate limited"
        );
        // B: a different address keeps its own budget.
        assert_eq!(
            call(&app, Method::POST, "/accounts/open", b).await,
            StatusCode::OK,
            "a different client IP is not affected"
        );
        // A non-listed POST and a read are never metered, even for the throttled IP.
        assert_eq!(
            call(&app, Method::POST, "/other", a).await,
            StatusCode::OK,
            "a path outside the unauth-writer set is not metered"
        );
        assert_eq!(
            call(&app, Method::GET, "/registry/resolve/x", a).await,
            StatusCode::OK,
            "reads are not metered"
        );
    }

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
        use ed25519_dalek::{Signer, SigningKey};
        let db = temp_db_path();
        let agent = AgentId("agent-x".to_string());
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pubkey = sk.verifying_key().to_bytes();
        let token;
        let proof;
        {
            let cp = ControlPlaneClient::new(spawn(&db).await);
            token = cp
                .issue_join_token(&TenantId("tenant-x".to_string()))
                .await
                .unwrap();
            proof = sk.sign(&token).to_bytes();
            let tenant = cp.redeem(&token, &agent, &pubkey, &proof).await.unwrap();
            assert_eq!(tenant.0, "tenant-x", "redeem binds the tenant");
        }

        // Fresh service instance on the same database (a restart).
        let cp2 = ControlPlaneClient::new(spawn(&db).await);
        let replay = cp2.redeem(&token, &agent, &pubkey, &proof).await;
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
        use ed25519_dalek::{Signer, SigningKey};
        let db = temp_db_path();
        let agent = AgentId("agent-u".to_string());
        let token = RoutingToken([0x33; 32]);
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let pubkey = sk.verifying_key().to_bytes();
        let join;
        let proof;
        let account;
        {
            let base = spawn_unified(&db).await;
            let cp = ControlPlaneClient::new(base.clone());
            // enrollment
            join = cp.issue_join_token(&TenantId("tu".to_string())).await.unwrap();
            proof = sk.sign(&join).to_bytes();
            cp.redeem(&join, &agent, &pubkey, &proof).await.unwrap();
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
            cp2.redeem(&join, &agent, &pubkey, &proof).await.is_err(),
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

        // Fund user-1 so issuance at the token price succeeds and only the rate
        // limit — not credit or the #87 price floor — decides the outcome.
        let acct = ledger.account_for_subject("user-1").unwrap();
        ledger.credit(&acct, 2).unwrap();
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
        // price 1 (the token price) with a funded account — issuance succeeds until
        // the rate limit bites, which is what this test isolates.
        let issue = || {
            app.clone().oneshot(
                Request::post("/me/issue")
                    .header("authorization", format!("Bearer {jwt}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"price":1}"#))
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
    async fn issuance_rejects_price_below_the_token_price() {
        // #87 SEC87a: /me/issue took a client-supplied `price`, and price:0 minted a
        // routing token for free (debiting nothing). A funded, in-rate subject must
        // still not be able to buy a token below TOKEN_PRICE, and a refusal must not
        // touch the ledger.
        use axum::body::Body;
        use axum::http::Request;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};
        use tower::ServiceExt;

        let secret = b"realm-secret";
        let issuer = "https://kc/realms/ct";
        let ledger = Arc::new(SqliteLedger::open_in_memory().unwrap());
        let verifier = Arc::new(OidcVerifier::from_hs_secret(secret, issuer));

        // Fund the subject so any refusal is the price floor, not insufficient credit,
        // and set a high rate cap so the limiter never interferes.
        let acct = ledger.account_for_subject("payer").unwrap();
        ledger.credit(&acct, 5).unwrap();
        let probe = ledger.clone();
        let app = authed_billing_router(ledger, verifier, 100);

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let claims = serde_json::json!({ "sub": "payer", "iss": issuer, "exp": now + 3600 });
        let jwt = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();
        let issue = |price: u64| {
            app.clone().oneshot(
                Request::post("/me/issue")
                    .header("authorization", format!("Bearer {jwt}"))
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"price":{price}}}"#)))
                    .unwrap(),
            )
        };

        // price:0 is refused and mints/debits nothing — the free-token hole is closed.
        assert_eq!(
            issue(0).await.unwrap().status(),
            StatusCode::PAYMENT_REQUIRED,
            "price:0 must not mint a free token"
        );
        assert_eq!(probe.balance(&acct).unwrap(), 5, "a refused issuance debits nothing");

        // Paying the token price succeeds and debits exactly that.
        assert_eq!(issue(1).await.unwrap().status(), StatusCode::OK, "paying TOKEN_PRICE mints a token");
        assert_eq!(probe.balance(&acct).unwrap(), 4, "the token price was debited");
    }

    #[tokio::test]
    async fn authed_channel_registry_is_owner_scoped() {
        // #81 SEC81c-b: the channel registry is authenticated and owner-scoped —
        // owner = verified subject. Only the owner registers/manages a channel; a
        // non-owner is forbidden; and the records drive the SEC81c-a authorize
        // lookup (add → resolvable, remove → denied).
        use axum::body::Body;
        use axum::http::Request;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use std::time::{SystemTime, UNIX_EPOCH};
        use tower::ServiceExt;

        let secret = b"realm-secret";
        let issuer = "https://kc/realms/ct";
        let channels = Arc::new(SqliteChannelStore::open_in_memory().unwrap());
        let verifier = Arc::new(OidcVerifier::from_hs_secret(secret, issuer));
        let probe = channels.clone();
        let app = authed_channel_router(channels, verifier);

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let jwt_for = |sub: &str| {
            let claims = serde_json::json!({ "sub": sub, "iss": issuer, "exp": now + 3600 });
            encode(
                &Header::new(Algorithm::HS256),
                &claims,
                &EncodingKey::from_secret(secret),
            )
            .unwrap()
        };
        let alice = jwt_for("alice");
        let mallory = jwt_for("mallory");
        let post = |path: String, bearer: Option<String>, body: String| {
            let mut req = Request::post(&path).header("content-type", "application/json");
            if let Some(b) = &bearer {
                req = req.header("authorization", format!("Bearer {b}"));
            }
            app.clone().oneshot(req.body(Body::from(body)).unwrap())
        };

        use ed25519_dalek::{Signer, SigningKey};
        let ch = "a1".repeat(32);
        let op = "b2".repeat(32);
        let chan = ChannelId(hex_decode_32(&ch).unwrap());
        // #101: the member attests its Noise key with its holder key, so the holder
        // must be a real keypair and the POST must carry a valid attestation.
        let holder_sk = SigningKey::from_bytes(&[0xc3u8; 32]);
        let hbytes = holder_sk.verifying_key().to_bytes();
        let holder = hex_encode(&hbytes);
        let nk_bytes = [0xd4u8; 32];
        let attest = |sk: &SigningKey, hb: &[u8; 32]| {
            hex_encode(&sk.sign(&ct_common::channel::member_noise_attest_bytes(&chan, hb, &nk_bytes)).to_bytes())
        };

        // Unauthenticated registration is rejected.
        let s = post(
            "/me/channels".into(),
            None,
            format!(r#"{{"channel":"{ch}","operator_pubkey":"{op}"}}"#),
        )
        .await
        .unwrap()
        .status();
        assert_eq!(s, StatusCode::UNAUTHORIZED, "no bearer -> 401");

        // Alice registers her channel and adds a member.
        let s = post(
            "/me/channels".into(),
            Some(alice.clone()),
            format!(r#"{{"channel":"{ch}","operator_pubkey":"{op}"}}"#),
        )
        .await
        .unwrap()
        .status();
        assert_eq!(s, StatusCode::OK, "owner registers");
        let nk = hex_encode(&nk_bytes);
        let att = attest(&holder_sk, &hbytes);
        let s = post(
            format!("/me/channels/{ch}/members"),
            Some(alice.clone()),
            format!(r#"{{"holder":"{holder}","noise_pubkey":"{nk}","noise_attestation":"{att}"}}"#),
        )
        .await
        .unwrap()
        .status();
        assert_eq!(s, StatusCode::OK, "owner adds a member");
        assert_eq!(
            probe.authorize_holder(&chan, &hbytes).unwrap(),
            Some(hex_decode_32(&op).unwrap()),
            "an added member resolves the operator key (drives SEC81c-a)"
        );
        assert_eq!(
            probe.member_noise_key(&chan, &hbytes).unwrap(),
            Some(hex_decode_32(&nk).unwrap()),
            "the member's pinned X25519 Noise key round-trips (AF4 key distribution)"
        );

        // #101 SEC101b: a member POST whose attestation doesn't verify (here all-zero)
        // is rejected — the CP won't store an un-attested / operator-forged Noise key.
        let s = post(
            format!("/me/channels/{ch}/members"),
            Some(alice.clone()),
            format!(r#"{{"holder":"{holder}","noise_pubkey":"{nk}","noise_attestation":"{}"}}"#, "00".repeat(64)),
        )
        .await
        .unwrap()
        .status();
        assert_eq!(s, StatusCode::BAD_REQUEST, "an unattested Noise key is rejected (#101)");

        // Mallory cannot manage or re-key alice's channel (valid attestation, so the
        // rejection is on ownership at 403, not the attestation check).
        let m_sk = SigningKey::from_bytes(&[0xeeu8; 32]);
        let m_h = hex_encode(&m_sk.verifying_key().to_bytes());
        let m_att = attest(&m_sk, &m_sk.verifying_key().to_bytes());
        let s = post(
            format!("/me/channels/{ch}/members"),
            Some(mallory.clone()),
            format!(r#"{{"holder":"{m_h}","noise_pubkey":"{nk}","noise_attestation":"{m_att}"}}"#),
        )
        .await
        .unwrap()
        .status();
        assert_eq!(s, StatusCode::FORBIDDEN, "non-owner cannot add members");
        let s = post(
            "/me/channels".into(),
            Some(mallory),
            format!(r#"{{"channel":"{ch}","operator_pubkey":"{}"}}"#, "ff".repeat(32)),
        )
        .await
        .unwrap()
        .status();
        assert_eq!(s, StatusCode::FORBIDDEN, "non-owner cannot re-key");
        assert_eq!(
            probe.operator_pubkey(&chan).unwrap(),
            Some(hex_decode_32(&op).unwrap()),
            "operator key unchanged by the refused re-key"
        );

        // Alice revokes the member → the authorize lookup denies it.
        let s = post(
            format!("/me/channels/{ch}/members/{holder}/remove"),
            Some(alice),
            String::new(),
        )
        .await
        .unwrap()
        .status();
        assert_eq!(s, StatusCode::OK, "owner removes a member");
        assert_eq!(
            probe.authorize_holder(&chan, &hbytes).unwrap(),
            None,
            "a revoked member is no longer authorized"
        );
    }

    #[tokio::test]
    async fn internal_channel_authorize_requires_admin_token_and_membership() {
        // #81 SEC81c-c c-i: the edge queries this (with the shared admin token) to
        // source the broker's `authorize` closure — operator key iff the holder is a
        // current member; bad/missing token -> 401; non-member -> 404.
        use axum::body::{to_bytes, Body};
        use axum::http::Request;
        use tower::ServiceExt;

        let admin = [0x7au8; 32];
        let channels = Arc::new(SqliteChannelStore::open_in_memory().unwrap());
        let ch = ChannelId([0xC5u8; 32]);
        let op = [0xEEu8; 32];
        let member = [0x33u8; 32];
        assert!(channels.register_channel(&ch, &op, "alice").unwrap());
        assert!(channels.add_member(&ch, "alice", &member, &[0xd4u8; 32], &[0u8; 64]).unwrap());

        let app = internal_channel_authorize_router(channels, admin);
        let admin_hex = hex_encode(&admin);
        let wrong_hex = hex_encode(&[0u8; 32]);
        let ch_hex = hex_encode(&ch.0);
        let post = |tok: Option<String>, holder: [u8; 32]| {
            let mut req =
                Request::post("/internal/channel/authorize").header("content-type", "application/json");
            if let Some(t) = tok {
                req = req.header("x-ct-admin-token", t);
            }
            let body = format!(r#"{{"channel":"{ch_hex}","holder":"{}"}}"#, hex_encode(&holder));
            app.clone().oneshot(req.body(Body::from(body)).unwrap())
        };

        // Correct token + member -> 200 + the operator key.
        let r = post(Some(admin_hex.clone()), member).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let bytes = to_bytes(r.into_body(), 1 << 16).await.unwrap();
        let resp: AuthorizeResp = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(resp.operator_pubkey, hex_encode(&op), "member resolves the operator key");
        assert_eq!(
            resp.noise_pubkey.as_deref(),
            Some(hex_encode(&[0xd4u8; 32]).as_str()),
            "the member's attested Noise key is served for A2A key delivery (#72/#100)"
        );

        // Wrong / missing token -> 401 (before any lookup).
        assert_eq!(post(Some(wrong_hex), member).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        assert_eq!(post(None, member).await.unwrap().status(), StatusCode::UNAUTHORIZED);
        // Valid token, non-member holder -> 404.
        assert_eq!(
            post(Some(admin_hex), [0x44u8; 32]).await.unwrap().status(),
            StatusCode::NOT_FOUND
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
        // #64: the apex landing page must offer a discoverable path to the customer
        // Portal (sign-up/sign-in). A relative /portal link keeps it host-agnostic.
        assert!(
            html.contains(r#"href="/portal""#),
            "links to the customer portal (#64)"
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
