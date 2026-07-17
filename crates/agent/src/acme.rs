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
}
