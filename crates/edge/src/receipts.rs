//! #782: the edge's dedicated receipts signing key -- `edge-receipts-key.bin` beside the
//! persisted CA key, a 32-byte ed25519 seed drawn from `OsRng` once and reloaded on
//! every later boot -- plus the env toggle that turns receipt signing off.
//!
//! A SEPARATE key from `edge-ca-key.pem` on purpose: that key is the TLS/mesh root of
//! trust every pinned Agent/Client depends on; signing an append-only metadata log with
//! it would give the log the same blast radius as the CA (and force a CA rotation to
//! retire a receipts key). This one signs receipts and nothing else, so it can be
//! rotated -- delete the file, restart -- without touching any pin; verifiers then hold
//! two public keys, one per chain epoch.
//!
//! What the chain built on this key proves and does not prove is documented on
//! `ct_common::receipt` (the shared verifier); the emission itself lives in
//! `tunnel_history.rs`, which owns the SQLite store the receipts are appended to.

use ct_common::receipt::ReceiptSigner;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// File name of the persisted seed, placed beside the CA key.
pub const KEY_FILE_NAME: &str = "edge-receipts-key.bin";

/// The seed is exactly one ed25519 seed; any other length is a corrupt or foreign file.
const SEED_LEN: usize = 32;

/// `CT_EDGE_RECEIPTS`: `off`/`0`/`false` disables receipt signing (the history store
/// then keeps its session rows but appends no receipts and the receipts routes 404).
/// Unset/empty/anything else -> enabled. Same convention as `CT_EDGE_TUNNEL_HISTORY`.
pub fn receipts_enabled(toggle: Option<&str>) -> bool {
    match toggle.map(str::trim) {
        Some(v) => !(v == "0" || v.eq_ignore_ascii_case("off") || v.eq_ignore_ascii_case("false")),
        None => true,
    }
}

/// `edge-receipts-key.bin` in the directory of `ca_key_path` (the edge's one durable
/// volume), or a bare file name when the CA key path has no directory.
pub fn receipts_key_path_for(ca_key_path: &str) -> String {
    let ca = std::path::Path::new(ca_key_path);
    match ca.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir.join(KEY_FILE_NAME).to_string_lossy().into_owned(),
        _ => KEY_FILE_NAME.to_string(),
    }
}

/// `CT_EDGE_ID`, defaulting to `"primary"` -- the same default the mesh heartbeat in
/// `serve.rs` and the control plane's local-edge id use, so every receipt names the
/// edge the way the control plane already does.
pub fn edge_id_from_env() -> String {
    std::env::var("CT_EDGE_ID")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "primary".into())
}

/// Load the 32-byte seed at `path`, or create it (`OsRng`, written owner-only via the
/// same atomic-0600 helper the CA key uses, #277) when the file does not exist. A file
/// of any other length is refused loudly rather than silently replaced: overwriting it
/// would start a second chain under a new key with no trace of why.
pub fn load_or_create_seed(path: &str) -> Result<zeroize::Zeroizing<[u8; 32]>, BoxError> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let bytes = zeroize::Zeroizing::new(bytes);
            if bytes.len() != SEED_LEN {
                return Err(format!(
                    "receipts key file {path} has {} bytes, expected {SEED_LEN}; refusing to overwrite it (#782)",
                    bytes.len()
                )
                .into());
            }
            // Re-assert the owner-only mode on every load, as the CA key does (#424).
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            }
            let mut seed = zeroize::Zeroizing::new([0u8; SEED_LEN]);
            seed.copy_from_slice(&bytes);
            Ok(seed)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            use rand::RngCore;
            let mut seed = zeroize::Zeroizing::new([0u8; SEED_LEN]);
            rand::rngs::OsRng.fill_bytes(&mut *seed);
            crate::pki::write_owner_only(path, &*seed)?;
            eprintln!("ct-edge: created receipts signing key at {path} (#782)");
            Ok(seed)
        }
        Err(e) => Err(format!("receipts key file {path}: {e}").into()),
    }
}

/// The signer for this edge: [`load_or_create_seed`] at `path`, keyed to `edge_id`.
pub fn load_or_create_signer(path: &str, edge_id: &str) -> Result<ReceiptSigner, BoxError> {
    let seed = load_or_create_seed(path)?;
    Ok(ReceiptSigner::from_seed(&seed, edge_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_key_path() -> String {
        use rand::RngCore;
        let mut b = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut b);
        let name: String = b.iter().map(|x| format!("{x:02x}")).collect();
        std::env::temp_dir().join(format!("ct_receipts_{name}.bin")).to_string_lossy().into_owned()
    }

    #[test]
    fn key_is_created_owner_only_and_reloads_to_the_same_public_key() {
        let path = temp_key_path();
        assert!(!std::path::Path::new(&path).exists());
        let first = load_or_create_signer(&path, "edge-a").unwrap();
        assert!(std::path::Path::new(&path).exists(), "created on first load");
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 32);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "receipts key must be owner-only, got {mode:o}");
            // A widened mode is re-narrowed on the next load.
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let second = load_or_create_signer(&path, "edge-a").unwrap();
        assert_eq!(first.pubkey_hex(), second.pubkey_hex(), "the same seed -> the same key across boots");
        assert_eq!(second.edge_id(), "edge-a");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // Two edges never share a key by accident: a fresh path is a fresh seed.
        let other = temp_key_path();
        let third = load_or_create_signer(&other, "edge-b").unwrap();
        assert_ne!(first.pubkey_hex(), third.pubkey_hex());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&other);
    }

    #[test]
    fn a_seed_file_of_the_wrong_length_is_refused_not_overwritten() {
        let path = temp_key_path();
        std::fs::write(&path, b"not a seed").unwrap();
        let err = load_or_create_seed(&path).unwrap_err().to_string();
        assert!(err.contains("expected 32"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), b"not a seed", "left untouched");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn toggle_and_path_helpers() {
        assert!(receipts_enabled(None));
        assert!(receipts_enabled(Some("")));
        assert!(receipts_enabled(Some("on")));
        for off in ["off", "OFF", "0", "false", " false "] {
            assert!(!receipts_enabled(Some(off)), "{off}");
        }
        assert_eq!(receipts_key_path_for("/shared/edge-ca-key.pem"), "/shared/edge-receipts-key.bin");
        assert_eq!(receipts_key_path_for("edge-ca-key.pem"), KEY_FILE_NAME);
    }
}
