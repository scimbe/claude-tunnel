//! Agent-side public-CA certificate material (#23 BP4c, ADR-0003). The Browser
//! Plane serves a publicly-trusted cert for the agent's public hostname; both the
//! Let's Encrypt DNS-01 path and the BYO-cert path start from the same artifact —
//! a private key plus a PKCS#10 CSR naming the hostname. This module (BP4c-a)
//! produces that deterministically from a hostname; the ACME order + DNS-01
//! provisioning (BP4c-b/c) consume the CSR, and the BYO path (BP4c-d) supplies
//! its own leaf instead. Keeping CSR generation standalone lets it be unit-tested
//! with no network and shared across both paths.

use rcgen::{CertificateParams, DnType, KeyPair};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A freshly-generated keypair and a CSR requesting a leaf for one hostname.
pub struct CsrBundle {
    /// The private key, PKCS#8 PEM. Held by the agent; never sent to the CA.
    pub key_pem: String,
    /// The PKCS#10 certificate-signing request, PEM (for inspection / BYO issuers).
    pub csr_pem: String,
    /// The same CSR as DER — the form ACME finalize (BP4c-c) base64url-encodes into
    /// the order's `csr` field.
    pub csr_der: Vec<u8>,
}

/// Generate a keypair and a CSR for `hostname` (as CommonName + a DNS SAN) — the
/// artifact the CA (Let's Encrypt via DNS-01, or a BYO issuer) signs into the
/// Browser-Plane leaf. The hostname is normalized/validated (RFC-1123) via
/// [`ct_common::normalize_hostname`] first, so the SAN always matches what the
/// edge routes on; an invalid name is rejected rather than yielding a bogus CSR.
pub fn generate_csr(hostname: &str) -> Result<CsrBundle, BoxError> {
    let host = ct_common::normalize_hostname(hostname)
        .ok_or("invalid hostname for a certificate request")?;
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::new(vec![host.clone()])?;
    params.distinguished_name.push(DnType::CommonName, host);
    let csr = params.serialize_request(&key)?;
    Ok(CsrBundle {
        key_pem: key.serialize_pem(),
        csr_pem: csr.pem()?,
        csr_der: csr.der().as_ref().to_vec(),
    })
}

// ---------------------------------------------------------------------------
// #23 BP4c-b — ACME (RFC 8555) protocol message handling. The account/order
// dance is network I/O (BP4c-c, tested against a local Pebble server, not the
// hermetic gate), but the message PARSING and the DNS-01 derivation are pure and
// belong here so the network layer is thin and the tricky bits are unit-tested.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The ACME directory (RFC 8555 §7.1.1): the entry-point URLs a client POSTs to.
#[derive(Debug, PartialEq, Eq)]
pub struct AcmeDirectory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
}

/// Parse a directory document, returning `None` if a required endpoint is absent.
pub fn parse_directory(json: &Value) -> Option<AcmeDirectory> {
    Some(AcmeDirectory {
        new_nonce: json.get("newNonce")?.as_str()?.to_string(),
        new_account: json.get("newAccount")?.as_str()?.to_string(),
        new_order: json.get("newOrder")?.as_str()?.to_string(),
    })
}

/// An ACME order (RFC 8555 §7.1.3): its status, the per-identifier authorization
/// URLs, the finalize URL (where the CSR is submitted), and — once issued — the
/// certificate URL.
#[derive(Debug, PartialEq, Eq)]
pub struct AcmeOrder {
    pub status: String,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: Option<String>,
}

/// Parse an order object.
pub fn parse_order(json: &Value) -> Option<AcmeOrder> {
    Some(AcmeOrder {
        status: json.get("status")?.as_str()?.to_string(),
        authorizations: json
            .get("authorizations")?
            .as_array()?
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        finalize: json.get("finalize")?.as_str()?.to_string(),
        certificate: json.get("certificate").and_then(|v| v.as_str()).map(String::from),
    })
}

/// The `dns-01` challenge of an authorization (RFC 8555 §8.4): its `token` and the
/// `url` to POST once the TXT record is published.
#[derive(Debug, PartialEq, Eq)]
pub struct Dns01Challenge {
    pub token: String,
    pub url: String,
}

/// Select the `dns-01` challenge from an authorization's `challenges` list,
/// skipping `http-01`/`tls-alpn-01`. `None` if the authorization offers no DNS-01.
pub fn select_dns01(authorization: &Value) -> Option<Dns01Challenge> {
    authorization.get("challenges")?.as_array()?.iter().find_map(|c| {
        if c.get("type")?.as_str()? != "dns-01" {
            return None;
        }
        Some(Dns01Challenge {
            token: c.get("token")?.as_str()?.to_string(),
            url: c.get("url")?.as_str()?.to_string(),
        })
    })
}

/// The record name a DNS-01 TXT challenge is published at (RFC 8555 §8.4):
/// `_acme-challenge.<domain>` (a trailing dot on the domain is tolerated).
pub fn dns01_record_name(domain: &str) -> String {
    format!("_acme-challenge.{}", domain.trim_end_matches('.'))
}

/// The DNS-01 TXT value (RFC 8555 §8.4): `base64url(SHA256(key_authorization))`.
/// The `key_authorization` — `token "." base64url(thumbprint(accountKey))` — is
/// formed by the ACME client once it holds the account key; this hashes it into
/// the value published as the TXT record.
pub fn dns01_txt_value(key_authorization: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(key_authorization.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_csr_binds_the_normalized_hostname_and_a_usable_key() {
        // #23 BP4c-a: the CSR requests exactly the normalized hostname (so it
        // matches what the edge routes on), and the private key is a usable PKCS#8
        // keypair the agent keeps.
        let bundle = generate_csr("Shop.Example.Test").expect("csr generated");

        assert!(bundle.key_pem.contains("PRIVATE KEY"), "PKCS#8 PEM key");
        KeyPair::from_pem(&bundle.key_pem).expect("the private key roundtrips");

        // Well-formed PEM + DER, and the DER carries the NORMALIZED hostname
        // verbatim (SAN/CN are stored as the ASCII name) — not the mixed-case
        // input. This grounds the request without pulling in a CSR parser.
        assert!(bundle.csr_pem.contains("CERTIFICATE REQUEST"), "PKCS#10 PEM CSR");
        assert!(!bundle.csr_der.is_empty(), "DER form present for ACME finalize");
        let host = b"shop.example.test";
        assert!(
            bundle.csr_der.windows(host.len()).any(|w| w == host),
            "CSR requests the normalized hostname"
        );
        let mixed = b"Shop.Example.Test";
        assert!(
            !bundle.csr_der.windows(mixed.len()).any(|w| w == mixed),
            "input case was normalized away"
        );
    }

    #[test]
    fn generate_csr_rejects_an_invalid_hostname() {
        assert!(generate_csr("not a host name!").is_err(), "invalid host -> no CSR");
        assert!(generate_csr("").is_err(), "empty host -> no CSR");
    }

    #[test]
    fn parses_acme_directory_order_and_selects_dns01() {
        // #23 BP4c-b: the ACME response parsers.
        let dir = serde_json::json!({
            "newNonce": "https://acme/nonce",
            "newAccount": "https://acme/acct",
            "newOrder": "https://acme/order",
            "keyChange": "https://acme/kc"
        });
        assert_eq!(
            parse_directory(&dir),
            Some(AcmeDirectory {
                new_nonce: "https://acme/nonce".into(),
                new_account: "https://acme/acct".into(),
                new_order: "https://acme/order".into(),
            })
        );
        // A directory missing a required endpoint -> None.
        assert_eq!(parse_directory(&serde_json::json!({ "newNonce": "x" })), None);

        let order = serde_json::json!({
            "status": "pending",
            "authorizations": ["https://acme/authz/1"],
            "finalize": "https://acme/finalize/1"
        });
        let o = parse_order(&order).expect("order");
        assert_eq!(o.status, "pending");
        assert_eq!(o.authorizations, vec!["https://acme/authz/1".to_string()]);
        assert_eq!(o.finalize, "https://acme/finalize/1");
        assert_eq!(o.certificate, None);

        // DNS-01 is selected from among the offered challenges; http-01 is skipped.
        let authz = serde_json::json!({
            "identifier": { "type": "dns", "value": "shop.example.test" },
            "challenges": [
                { "type": "http-01", "token": "http-tok", "url": "https://acme/chall/http" },
                { "type": "dns-01", "token": "dns-tok", "url": "https://acme/chall/dns" }
            ]
        });
        assert_eq!(
            select_dns01(&authz),
            Some(Dns01Challenge { token: "dns-tok".into(), url: "https://acme/chall/dns".into() })
        );
        let http_only = serde_json::json!({
            "challenges": [ { "type": "http-01", "token": "t", "url": "u" } ]
        });
        assert_eq!(select_dns01(&http_only), None, "no dns-01 -> None");
    }

    #[test]
    fn dns01_record_name_and_txt_value_follow_rfc8555() {
        // #23 BP4c-b: the DNS-01 derivation.
        assert_eq!(dns01_record_name("shop.example.test"), "_acme-challenge.shop.example.test");
        assert_eq!(dns01_record_name("shop.example.test."), "_acme-challenge.shop.example.test");

        // Independent known vector: base64url(SHA256("")) — the SHA-256 of the
        // empty string, url-safe and unpadded. Proves the digest+encoding, not a
        // tautology against our own primitives.
        assert_eq!(dns01_txt_value(""), "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
        // 32-byte digest -> 43 base64url chars; distinct inputs -> distinct values.
        assert_eq!(dns01_txt_value("key-auth").len(), 43);
        assert_ne!(dns01_txt_value("a"), dns01_txt_value("b"));
    }
}
