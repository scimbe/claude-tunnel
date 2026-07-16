//! DNS-01 provider abstraction (#31 AD5): publish/clear `_acme-challenge` TXT
//! records for an ACME client, over one of two interchangeable backends —
//!
//! - [`Dns01Provider::SelfHosted`]: the in-process `ct-dns` store (AD1–AD3), for a
//!   fully self-contained deployment;
//! - [`Dns01Provider::Desec`]: **deSEC** (<https://desec.io>), a free managed DNS
//!   with a REST API — the alternative when you'd rather not run your own `:53`.
//!
//! Both stay available; the operator selects one (see `docs/dns01-desec.md` and
//! the `.env`). The deSEC token is read from the environment at startup and never
//! logged.

use std::sync::Arc;

use crate::store::AcmeDnsStore;

/// A configured DNS-01 backend the ACME client drives via `set_txt`/`clear_txt`.
pub enum Dns01Provider {
    /// Self-hosted `ct-dns` store (in-process).
    SelfHosted(Arc<AcmeDnsStore>),
    /// deSEC managed DNS via its REST API.
    Desec(DesecClient),
}

impl Dns01Provider {
    /// Publish (replace) the TXT value for an `_acme-challenge` name.
    pub async fn set_txt(&self, name: &str, value: &str) -> Result<(), String> {
        match self {
            Dns01Provider::SelfHosted(store) => {
                store.set_txt(name, value);
                Ok(())
            }
            Dns01Provider::Desec(client) => client.set_txt(name, value).await,
        }
    }

    /// Remove the challenge TXT (cleanup hook).
    pub async fn clear_txt(&self, name: &str) -> Result<(), String> {
        match self {
            Dns01Provider::SelfHosted(store) => {
                store.clear(name);
                Ok(())
            }
            Dns01Provider::Desec(client) => client.clear_txt(name).await,
        }
    }
}

/// deSEC (<https://desec.io>) DNS-01 client. Configured from the environment (a
/// `.env` the operator supplies): `DESEC_TOKEN` (API token), `DESEC_DOMAIN` (the
/// zone managed at deSEC), optional `DESEC_API_BASE` (default
/// `https://desec.io/api/v1`). The token is held in memory and never logged.
pub struct DesecClient {
    token: String,
    domain: String,
    base: String,
    http: reqwest::Client,
}

impl DesecClient {
    /// Build from process environment, or `None` if `DESEC_TOKEN`/`DESEC_DOMAIN`
    /// are not both set.
    pub fn from_env() -> Option<Self> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Testable core of [`from_env`].
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Option<Self> {
        let nonempty = |k: &str| get(k).map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
        let token = nonempty("DESEC_TOKEN")?;
        let domain = nonempty("DESEC_DOMAIN")?;
        let base =
            nonempty("DESEC_API_BASE").unwrap_or_else(|| "https://desec.io/api/v1".to_string());
        Some(Self {
            token,
            domain,
            base,
            http: reqwest::Client::new(),
        })
    }

    /// Upsert the TXT record via a bulk PATCH (leaves other records untouched);
    /// deSEC requires TXT values wrapped in double quotes.
    pub async fn set_txt(&self, name: &str, value: &str) -> Result<(), String> {
        self.patch_rrset(name, vec![format!("\"{value}\"")]).await
    }

    /// Clear the challenge TXT — an empty `records` list removes the RRset.
    pub async fn clear_txt(&self, name: &str) -> Result<(), String> {
        self.patch_rrset(name, Vec::new()).await
    }

    async fn patch_rrset(&self, name: &str, records: Vec<String>) -> Result<(), String> {
        // Bulk PATCH is an upsert of the listed RRsets only (min TTL 3600).
        let body = serde_json::json!([{
            "subname": subname_of(name, &self.domain),
            "type": "TXT",
            "ttl": 3600,
            "records": records,
        }]);
        let url = format!(
            "{}/domains/{}/rrsets/",
            self.base.trim_end_matches('/'),
            self.domain
        );
        let resp = self
            .http
            .patch(&url)
            .header("Authorization", format!("Token {}", self.token))
            .json(&body)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("deSEC returned {} for {name}", resp.status()))
        }
    }
}

/// Derive the deSEC `subname` for a full record name under `domain`
/// (`_acme-challenge.app.example.org` under `example.org` -> `_acme-challenge.app`;
/// a name equal to the domain -> ""). ACME challenge names are always a subname,
/// never the bare apex.
pub fn subname_of(name: &str, domain: &str) -> String {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let domain = domain.trim_end_matches('.').to_ascii_lowercase();
    if name == domain {
        return String::new();
    }
    name.strip_suffix(&format!(".{domain}"))
        .map(str::to_string)
        .unwrap_or(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::patch;
    use axum::Router;
    use std::sync::Mutex;

    #[test]
    fn subname_is_derived_relative_to_the_zone() {
        assert_eq!(
            subname_of("_acme-challenge.bunsenbrenner.org", "bunsenbrenner.org"),
            "_acme-challenge"
        );
        assert_eq!(
            subname_of("_acme-challenge.app1.Bunsenbrenner.ORG", "bunsenbrenner.org"),
            "_acme-challenge.app1"
        );
        assert_eq!(subname_of("bunsenbrenner.org", "bunsenbrenner.org"), "");
    }

    #[test]
    fn desec_from_lookup_needs_token_and_domain() {
        let ok = DesecClient::from_lookup(|k| match k {
            "DESEC_TOKEN" => Some("t".into()),
            "DESEC_DOMAIN" => Some("z.org".into()),
            _ => None,
        });
        assert!(ok.is_some());
        assert_eq!(ok.unwrap().base, "https://desec.io/api/v1", "default base");
        assert!(DesecClient::from_lookup(|k| (k == "DESEC_TOKEN").then(|| "t".into())).is_none());
    }

    #[tokio::test]
    async fn desec_set_and_clear_hit_the_bulk_rrset_endpoint_with_auth() {
        // Mock deSEC: capture (path, auth header, body) of the PATCH.
        type Captured = Arc<Mutex<Option<(String, String, String)>>>;
        let captured: Captured = Arc::new(Mutex::new(None));
        let app = Router::new()
            .route(
                "/domains/:domain/rrsets/",
                patch(
                    |State(cap): State<Captured>, headers: HeaderMap, uri: axum::http::Uri, body: String| async move {
                        let auth = headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_string();
                        *cap.lock().unwrap() = Some((uri.path().to_string(), auth, body));
                        StatusCode::OK
                    },
                ),
            )
            .with_state(captured.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let client = DesecClient::from_lookup(|k| match k {
            "DESEC_TOKEN" => Some("secret-token".into()),
            "DESEC_DOMAIN" => Some("bunsenbrenner.org".into()),
            "DESEC_API_BASE" => Some(format!("http://{addr}")),
            _ => None,
        })
        .unwrap();

        // set_txt publishes the quoted value at the right RRset endpoint with auth.
        client.set_txt("_acme-challenge.bunsenbrenner.org", "tok-123").await.unwrap();
        let (path, auth, body) = captured.lock().unwrap().clone().expect("deSEC called");
        assert_eq!(path, "/domains/bunsenbrenner.org/rrsets/");
        assert_eq!(auth, "Token secret-token", "bearer via Token scheme");
        assert!(body.contains("_acme-challenge"), "carries the subname");
        assert!(body.contains("tok-123"), "carries the (quoted) TXT value");
        assert!(body.contains("TXT"));

        // clear_txt sends an empty records list (deletes the RRset).
        client.clear_txt("_acme-challenge.bunsenbrenner.org").await.unwrap();
        let (_p, _a, body) = captured.lock().unwrap().clone().unwrap();
        assert!(body.contains("\"records\":[]"), "empty records clears it");
    }
}
