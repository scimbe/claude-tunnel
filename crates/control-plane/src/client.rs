//! HTTP client for the running control-plane service (M13.4a).
//!
//! The service exposes enrollment + registry/rendezvous over JSON (see
//! [`crate::http`]). This client lets an Agent enroll and register its tunnel,
//! and a Client resolve a routing token, against a *running* control plane —
//! the piece that turns the in-memory library into a hosted service (ADR-0017).
//! Plaintext HTTP only; the control plane holds no trust material or payload.

use serde::Deserialize;

use ct_common::{AgentId, RoutingToken, TenantId};

/// A thin HTTP client bound to one control-plane base URL (e.g.
/// `http://control-plane:8090`).
pub struct ControlPlaneClient {
    base: String,
    http: reqwest::Client,
}

/// Errors talking to the control-plane service.
#[derive(Debug)]
pub enum CpError {
    /// Transport-level failure (connect, timeout, body).
    Http(reqwest::Error),
    /// The service answered with a non-success status.
    Status(reqwest::StatusCode),
    /// A field could not be decoded (e.g. a token that is not 32 hex bytes).
    Malformed,
}

impl std::fmt::Display for CpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CpError::Http(e) => write!(f, "control-plane request failed: {e}"),
            CpError::Status(s) => write!(f, "control-plane returned status {s}"),
            CpError::Malformed => write!(f, "control-plane returned a malformed field"),
        }
    }
}

impl std::error::Error for CpError {}

impl From<reqwest::Error> for CpError {
    fn from(e: reqwest::Error) -> Self {
        CpError::Http(e)
    }
}

type CpResult<T> = Result<T, CpError>;

impl ControlPlaneClient {
    /// Bind the client to a base URL. A trailing slash is trimmed.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base: base_url.into().trim_end_matches('/').to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// `POST /enroll/issue` — mint a single-use join token for a tenant.
    pub async fn issue_join_token(&self, tenant: &TenantId) -> CpResult<[u8; 32]> {
        let resp = self
            .http
            .post(format!("{}/enroll/issue", self.base))
            .json(&serde_json::json!({ "tenant": tenant.0 }))
            .send()
            .await?;
        let resp = ok(resp)?;
        let body: TokenBody = resp.json().await?;
        hex_decode_32(&body.token).ok_or(CpError::Malformed)
    }

    /// `POST /enroll/redeem` — redeem a join token, binding this Agent's public
    /// key to the tenant. `proof` is the Agent's ed25519 signature over the join
    /// token (#88 SEC88c), proving it holds the private key for `pubkey`; the
    /// durable control plane rejects a redemption whose proof doesn't match.
    /// Returns the bound tenant.
    pub async fn redeem(
        &self,
        join_token: &[u8; 32],
        agent: &AgentId,
        pubkey: &[u8; 32],
        proof: &[u8; 64],
    ) -> CpResult<TenantId> {
        let resp = self
            .http
            .post(format!("{}/enroll/redeem", self.base))
            .json(&serde_json::json!({
                "token": hex_encode(join_token),
                "agent": agent.0,
                "pubkey": hex_encode(pubkey),
                "proof": hex_encode(proof),
            }))
            .send()
            .await?;
        let resp = ok(resp)?;
        let body: TenantBody = resp.json().await?;
        Ok(TenantId(body.tenant))
    }

    /// `GET /pki/ca` — fetch the edge CA root DER the control plane publishes
    /// (#11), so a cross-host Agent/Client can obtain the trust root over HTTP
    /// instead of copying it out of band. Public key material only.
    pub async fn fetch_edge_cert(&self) -> CpResult<Vec<u8>> {
        let resp = self.http.get(format!("{}/pki/ca", self.base)).send().await?;
        let resp = ok(resp)?;
        Ok(resp.bytes().await?.to_vec())
    }

    /// `POST /registry/register` — register a tunnel's routing token.
    pub async fn register(
        &self,
        token: &RoutingToken,
        tenant: &TenantId,
        agent: &AgentId,
    ) -> CpResult<()> {
        let resp = self
            .http
            .post(format!("{}/registry/register", self.base))
            .json(&serde_json::json!({
                "token": hex_encode(&token.0),
                "tenant": tenant.0,
                "agent": agent.0,
            }))
            .send()
            .await?;
        ok(resp)?;
        Ok(())
    }

    /// `GET /registry/resolve/:token` — the Rendezvous lookup. Returns the
    /// `(tenant, agent)` bound to the routing token, or [`CpError::Status`]
    /// (404) if unknown.
    pub async fn resolve(&self, token: &RoutingToken) -> CpResult<(TenantId, AgentId)> {
        let resp = self
            .http
            .get(format!("{}/registry/resolve/{}", self.base, hex_encode(&token.0)))
            .send()
            .await?;
        let resp = ok(resp)?;
        let body: ResolveBody = resp.json().await?;
        Ok((TenantId(body.tenant), AgentId(body.agent)))
    }

    /// `POST /accounts/open` — open a fresh pseudonymous account (M15.4b).
    pub async fn open_account(&self) -> CpResult<[u8; 32]> {
        let resp = self
            .http
            .post(format!("{}/accounts/open", self.base))
            .send()
            .await?;
        let resp = ok(resp)?;
        let body: AccountBody = resp.json().await?;
        hex_decode_32(&body.account).ok_or(CpError::Malformed)
    }

    /// `POST /payment/intent` — register a prepaid top-up intent; returns the
    /// opaque payment id to confirm.
    pub async fn create_payment_intent(&self, account: &[u8; 32], credits: u64) -> CpResult<[u8; 32]> {
        let resp = self
            .http
            .post(format!("{}/payment/intent", self.base))
            .json(&serde_json::json!({ "account": hex_encode(account), "credits": credits }))
            .send()
            .await?;
        let resp = ok(resp)?;
        let body: PaymentBody = resp.json().await?;
        hex_decode_32(&body.payment).ok_or(CpError::Malformed)
    }

    /// `POST /payment/confirm` — confirm a payment; returns the new balance.
    pub async fn confirm_payment(&self, payment: &[u8; 32]) -> CpResult<u64> {
        let resp = self
            .http
            .post(format!("{}/payment/confirm", self.base))
            .json(&serde_json::json!({ "payment": hex_encode(payment) }))
            .send()
            .await?;
        let resp = ok(resp)?;
        let body: BalanceBody = resp.json().await?;
        Ok(body.balance)
    }

    /// `POST /billing/issue` — buy a routing token, charging `price` credits to
    /// the account. A [`CpError::Status`] (402) means insufficient credit.
    pub async fn buy_token(&self, account: &[u8; 32], price: u64) -> CpResult<RoutingToken> {
        let resp = self
            .http
            .post(format!("{}/billing/issue", self.base))
            .json(&serde_json::json!({ "account": hex_encode(account), "price": price }))
            .send()
            .await?;
        let resp = ok(resp)?;
        let body: TokenBody = resp.json().await?;
        Ok(RoutingToken(hex_decode_32(&body.token).ok_or(CpError::Malformed)?))
    }
}

/// Map a non-success status to [`CpError::Status`].
fn ok(resp: reqwest::Response) -> CpResult<reqwest::Response> {
    let status = resp.status();
    if status.is_success() {
        Ok(resp)
    } else {
        Err(CpError::Status(status))
    }
}

#[derive(Deserialize)]
struct TokenBody {
    token: String,
}
#[derive(Deserialize)]
struct TenantBody {
    tenant: String,
}
#[derive(Deserialize)]
struct AccountBody {
    account: String,
}
#[derive(Deserialize)]
struct PaymentBody {
    payment: String,
}
#[derive(Deserialize)]
struct BalanceBody {
    balance: u64,
}
#[derive(Deserialize)]
struct ResolveBody {
    tenant: String,
    agent: String,
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
    use crate::enrollment::Enrollment;
    use crate::http::{control_plane_router, BillingState};
    use crate::registry::TunnelRegistry;
    use std::sync::{Arc, Mutex};

    /// Spawn the full control-plane router on an ephemeral port; returns its base URL.
    async fn spawn_service() -> String {
        let enr = Arc::new(Mutex::new(Enrollment::new()));
        let reg = Arc::new(Mutex::new(TunnelRegistry::new()));
        let bill = Arc::new(Mutex::new(BillingState::default()));
        let app = control_plane_router(enr, reg, bill);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    /// Full E2E against a *running* service over a real TCP socket: an Agent
    /// enrolls (issue → redeem) and registers its tunnel, then a Client
    /// resolves the routing token — the hosted-control-plane flow (M13.4).
    #[tokio::test]
    async fn client_drives_live_control_plane_service() {
        // Spin up the real service on an ephemeral port.
        let enr = Arc::new(Mutex::new(Enrollment::new()));
        let reg = Arc::new(Mutex::new(TunnelRegistry::new()));
        let app = control_plane_router(enr, reg, Arc::new(Mutex::new(BillingState::default())));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // The listener is already bound, so connections queue even before serve
        // starts accepting — no startup race for the client below.
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let cp = ControlPlaneClient::new(format!("http://{addr}"));
        let agent = AgentId("agent-x".to_string());

        // Agent enrolls: issue a join token, then redeem it to bind the tenant.
        let join = cp
            .issue_join_token(&TenantId("tenant-x".to_string()))
            .await
            .unwrap();
        let tenant = cp.redeem(&join, &agent, &[7u8; 32], &[0u8; 64]).await.unwrap();
        assert_eq!(tenant.0, "tenant-x", "redeem binds the issuing tenant");

        // Agent registers its tunnel's routing token.
        let token = RoutingToken([0x5a; 32]);
        cp.register(&token, &tenant, &agent).await.unwrap();

        // Client resolves it via Rendezvous.
        let (t, a) = cp.resolve(&token).await.unwrap();
        assert_eq!(
            (t.0.as_str(), a.0.as_str()),
            ("tenant-x", "agent-x"),
            "resolve returns the registered binding"
        );

        // An unregistered token → 404 error, not a panic.
        let unknown = cp.resolve(&RoutingToken([0x11; 32])).await;
        assert!(matches!(unknown, Err(CpError::Status(_))), "unknown token errors");
    }

    #[tokio::test]
    async fn redeem_reuse_surfaces_a_status_error() {
        let enr = Arc::new(Mutex::new(Enrollment::new()));
        let reg = Arc::new(Mutex::new(TunnelRegistry::new()));
        let app = control_plane_router(enr, reg, Arc::new(Mutex::new(BillingState::default())));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let cp = ControlPlaneClient::new(format!("http://{addr}"));
        let agent = AgentId("a".to_string());
        let join = cp.issue_join_token(&TenantId("t".to_string())).await.unwrap();

        cp.redeem(&join, &agent, &[1u8; 32], &[0u8; 64]).await.unwrap();
        // Single-use: the second redemption is rejected (409) as a Status error.
        let second = cp.redeem(&join, &agent, &[1u8; 32], &[0u8; 64]).await;
        assert!(matches!(second, Err(CpError::Status(_))), "join token is single-use");
    }

    #[tokio::test]
    async fn fetch_edge_cert_downloads_the_published_root() {
        // #11 C2: the client fetches the edge CA root the CP publishes at /pki/ca.
        let der: &[u8] = b"\x30\x82\x01\x0a-fetched-ca-root";
        let path = std::env::temp_dir().join(format!("ct-cpc-ca-{}.der", std::process::id()));
        std::fs::write(&path, der).unwrap();
        let app = crate::service::pki_router(path.to_string_lossy().into_owned());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let cp = ControlPlaneClient::new(format!("http://{addr}"));
        let got = cp.fetch_edge_cert().await.unwrap();
        assert_eq!(got, der, "fetches the exact published CA root DER");

        let _ = std::fs::remove_file(&path);
    }

    /// The full M15 billing flow over a real socket: open account → a broke
    /// account is denied a token (402) → top up (intent + confirm) → buy a token.
    #[tokio::test]
    async fn client_drives_account_topup_and_gated_issuance() {
        let cp = ControlPlaneClient::new(spawn_service().await);

        let account = cp.open_account().await.unwrap();

        // Broke: buying a token is refused with a status error (402).
        let broke = cp.buy_token(&account, 1).await;
        assert!(matches!(broke, Err(CpError::Status(_))), "zero-balance issuance denied");

        // Top up 3 credits via an intent + confirmation.
        let payment = cp.create_payment_intent(&account, 3).await.unwrap();
        let balance = cp.confirm_payment(&payment).await.unwrap();
        assert_eq!(balance, 3, "confirmed payment credited the account");

        // Now issuance succeeds and returns a routing token.
        let token = cp.buy_token(&account, 1).await.unwrap();
        assert_ne!(token.0, [0u8; 32], "a real routing token was issued");

        // Confirming the same payment again is rejected (idempotent, 409).
        let replay = cp.confirm_payment(&payment).await;
        assert!(matches!(replay, Err(CpError::Status(_))), "confirmation is single-use");
    }
}
