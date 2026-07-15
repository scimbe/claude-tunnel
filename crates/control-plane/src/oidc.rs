//! OIDC bearer-token verification (M19.2, Keycloak).
//!
//! A client authenticates to the control plane with a Keycloak-issued JWT
//! access token in the `Authorization: Bearer` header. This module validates the
//! token (signature, expiry, issuer) and returns its `sub` claim, which is
//! mapped to an account via [`crate::storage::SqliteLedger::account_for_subject`]
//! (M19.1). The tunnel data path is unaffected and stays end-to-end encrypted.
//!
//! Production uses RS256 with the realm's RSA public key
//! ([`OidcVerifier::from_rsa_pem`]); a symmetric HS256 constructor
//! ([`OidcVerifier::from_hs_secret`]) is available for local/dev and drives the
//! tests, since the validation and claim-extraction logic is identical across
//! algorithms.

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::Deserialize;

/// Why token verification failed (invalid signature, expired, wrong issuer, …).
#[derive(Debug)]
pub struct OidcError(String);

impl std::fmt::Display for OidcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "oidc verification failed: {}", self.0)
    }
}
impl std::error::Error for OidcError {}
impl From<jsonwebtoken::errors::Error> for OidcError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        OidcError(e.to_string())
    }
}

/// The subset of claims the control plane needs. `exp` is validated by the
/// library; `iss` is checked against the configured issuer; `sub` is returned.
#[derive(Deserialize)]
struct Claims {
    sub: String,
    #[allow(dead_code)]
    exp: usize,
    #[allow(dead_code)]
    iss: String,
}

/// Verifies bearer tokens against a fixed key + expected issuer.
pub struct OidcVerifier {
    key: DecodingKey,
    validation: Validation,
}

impl OidcVerifier {
    fn build(key: DecodingKey, alg: Algorithm, issuer: &str) -> Self {
        let mut validation = Validation::new(alg);
        validation.set_issuer(&[issuer]);
        validation.validate_exp = true;
        // Keycloak access-token audiences vary by client; the account binding
        // relies on `sub` + `iss`, so audience is not required here.
        validation.validate_aud = false;
        Self { key, validation }
    }

    /// Build a verifier for RS256 tokens from the realm's RSA **public** key
    /// (PEM) and the expected issuer (the realm URL). This is the Keycloak path.
    pub fn from_rsa_pem(pem: &[u8], issuer: &str) -> Result<Self, OidcError> {
        let key = DecodingKey::from_rsa_pem(pem).map_err(OidcError::from)?;
        Ok(Self::build(key, Algorithm::RS256, issuer))
    }

    /// Build a verifier for HS256 tokens from a shared secret and expected
    /// issuer. For local/dev and tests; production uses [`Self::from_rsa_pem`].
    pub fn from_hs_secret(secret: &[u8], issuer: &str) -> Self {
        Self::build(DecodingKey::from_secret(secret), Algorithm::HS256, issuer)
    }

    /// Verify `token` and return its subject (`sub`). Fails on a bad signature,
    /// an expired token, or a mismatched issuer.
    pub fn subject(&self, token: &str) -> Result<String, OidcError> {
        let data = decode::<Claims>(token, &self.key, &self.validation)?;
        Ok(data.claims.sub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use std::time::{SystemTime, UNIX_EPOCH};

    const SECRET: &[u8] = b"test-realm-secret";
    const ISSUER: &str = "https://keycloak.example/realms/claude-tunnel";

    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn make_token(secret: &[u8], sub: &str, iss: &str, exp: u64) -> String {
        let claims = serde_json::json!({ "sub": sub, "iss": iss, "exp": exp });
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(secret),
        )
        .unwrap()
    }

    #[test]
    fn valid_token_yields_subject() {
        let v = OidcVerifier::from_hs_secret(SECRET, ISSUER);
        let token = make_token(SECRET, "user-42", ISSUER, now() + 3600);
        assert_eq!(v.subject(&token).unwrap(), "user-42");
    }

    #[test]
    fn expired_token_is_rejected() {
        // Well beyond jsonwebtoken's default 60s exp leeway.
        let v = OidcVerifier::from_hs_secret(SECRET, ISSUER);
        let token = make_token(SECRET, "user-42", ISSUER, now() - 3600);
        assert!(v.subject(&token).is_err(), "expired token rejected");
    }

    #[test]
    fn wrong_issuer_is_rejected() {
        let v = OidcVerifier::from_hs_secret(SECRET, ISSUER);
        let token = make_token(SECRET, "user-42", "https://evil.example/realms/x", now() + 3600);
        assert!(v.subject(&token).is_err(), "mismatched issuer rejected");
    }

    #[test]
    fn bad_signature_is_rejected() {
        let v = OidcVerifier::from_hs_secret(SECRET, ISSUER);
        let token = make_token(b"other-secret", "user-42", ISSUER, now() + 3600);
        assert!(v.subject(&token).is_err(), "token signed with the wrong key rejected");
    }

    // #21 WC3: cover the RS256/Keycloak production constructor (from_rsa_pem) and
    // the OidcError Display — the HS256 tests above already exercise the shared
    // verification logic in subject(). A PUBLIC key is safe to embed (the
    // secret-guard only flags PRIVATE keys); it verifies key parsing, not signing.
    const RSA_PUBLIC_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoPFTleJfOSawf6FySZR1
9ysb7sezGSmNWL4K79aioS06m1/ymzDnXpt5gWcQzLGfP9yydIgbOP6tp2IYBpXb
yKdI5/CLdOV0g7TLSwUtAGAXH+Pl+QvyOL+oTAl2vqKczQ3nwhjDABey0eyBdshh
8DbP9jx72Seq7u9PWz0fk68wxd+QVW5qfcCVJYaCyS2o1OFzF5U1RE2cmQvVs03I
SXkvNCOPHmkffFR4TPb4k9UM1yS+gT1lSm8vTewgKNzLS3mDhsxYq2+bRhtshOEg
Zeq0yWDrACqZViurIS/kcGLrXHcMKGElE6LSdfm+QBzTuwPVpVa8IoKdh4ng5QVx
ZQIDAQAB
-----END PUBLIC KEY-----"#;

    #[test]
    fn from_rsa_pem_builds_a_verifier_from_a_public_key() {
        let v = OidcVerifier::from_rsa_pem(RSA_PUBLIC_PEM.as_bytes(), ISSUER);
        assert!(v.is_ok(), "a valid RSA public key builds an RS256 verifier");
    }

    #[test]
    fn from_rsa_pem_rejects_malformed_pem() {
        let err = OidcVerifier::from_rsa_pem(b"-----BEGIN PUBLIC KEY-----\nnope\n", ISSUER)
            .err()
            .expect("malformed PEM must error");
        assert!(err.to_string().contains("oidc verification failed"), "{err}");
    }

    #[test]
    fn oidc_error_displays_a_reason() {
        let v = OidcVerifier::from_hs_secret(SECRET, ISSUER);
        let token = make_token(b"wrong-key", "user-42", ISSUER, now() + 3600);
        let err = v.subject(&token).err().expect("bad signature errors");
        assert!(
            format!("{err}").starts_with("oidc verification failed:"),
            "Display renders the reason"
        );
    }
}
