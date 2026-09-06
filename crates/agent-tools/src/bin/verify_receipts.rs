//! #782: offline verifier for a tunnel's signed forensic receipts export.
//!
//! ```text
//! verify_receipts <receipts.jsonl> [--pubkey <64 hex>] [--anchor <64 hex>]
//! ```
//!
//! Reads the JSON-lines file the portal serves at `/portal/tunnels/:id/receipts.jsonl`
//! (header line, then one receipt per line), verifies every receipt's hash, signature
//! and chain link with `ct_common::receipt::verify_chain`, prints a summary, and exits
//! `0` when the whole chain verifies, `1` when it does not (naming the first failing
//! `seq`), `2` on a usage or file error.
//!
//! `--pubkey` overrides the key in the file's header: a verifier that fetched the edge's
//! key out of band (`GET /internal/receipts/pubkey` on the edge, or an earlier export)
//! should pass it, since a file whose header AND receipts were both replaced would
//! otherwise verify under the replacement key. `--anchor` pins the first receipt's
//! `prev_hash` to a previous export's `last_hash` (or the 64-zero genesis hash), so two
//! consecutive exports can be shown to be one unbroken chain.
//!
//! What a verified chain proves -- and does not -- is documented on
//! `ct_common::receipt`: the named edge attested these metadata events in this order;
//! nothing about payload contents, and timestamps are the edge's own clock.

use std::io::Write;
use std::process::ExitCode;

use ct_common::receipt::{parse_jsonl, pubkey_from_hex, verify_chain_anchored, VerifiedSummary, GENESIS_PREV_HASH};

const USAGE: &str = "usage: verify_receipts <receipts.jsonl> [--pubkey <64 hex>] [--anchor <64 hex>]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut out = std::io::stdout().lock();
    match run(&args, &mut out) {
        0 => ExitCode::SUCCESS,
        code => ExitCode::from(code),
    }
}

struct Opts {
    file: String,
    pubkey: Option<String>,
    anchor: Option<String>,
}

fn parse_args(args: &[String]) -> Result<Opts, String> {
    let mut file = None;
    let mut pubkey = None;
    let mut anchor = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--pubkey" => pubkey = Some(it.next().ok_or("--pubkey needs a value")?.clone()),
            "--anchor" => anchor = Some(it.next().ok_or("--anchor needs a value")?.clone()),
            "-h" | "--help" => return Err(USAGE.to_string()),
            other if other.starts_with('-') => return Err(format!("unknown option {other}\n{USAGE}")),
            other if file.is_none() => file = Some(other.to_string()),
            other => return Err(format!("unexpected argument {other}\n{USAGE}")),
        }
    }
    Ok(Opts { file: file.ok_or(USAGE)?, pubkey, anchor })
}

/// The whole program minus process exit, so tests can drive it: returns the exit code.
fn run(args: &[String], out: &mut dyn Write) -> u8 {
    let opts = match parse_args(args) {
        Ok(o) => o,
        Err(e) => {
            let _ = writeln!(out, "{e}");
            return 2;
        }
    };
    let text = match std::fs::read_to_string(&opts.file) {
        Ok(t) => t,
        Err(e) => {
            let _ = writeln!(out, "{}: {e}", opts.file);
            return 2;
        }
    };
    let export = match parse_jsonl(&text) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(out, "{}: {e}", opts.file);
            return 2;
        }
    };
    let (pubkey_hex, key_source) = match &opts.pubkey {
        Some(k) => (k.trim().to_ascii_lowercase(), "--pubkey"),
        None => (export.header.pubkey.to_ascii_lowercase(), "file header"),
    };
    let Some(pubkey) = pubkey_from_hex(&pubkey_hex) else {
        let _ = writeln!(out, "public key ({key_source}) is not 64 hex chars: {pubkey_hex}");
        return 2;
    };
    if opts.pubkey.is_some() && !export.header.pubkey.eq_ignore_ascii_case(&pubkey_hex) {
        let _ = writeln!(
            out,
            "note: the file header names a different key ({}); verifying under --pubkey",
            export.header.pubkey
        );
    }
    let anchor = opts.anchor.as_deref().map(str::trim);
    if let Some(a) = anchor {
        if pubkey_from_hex(a).is_none() {
            let _ = writeln!(out, "--anchor is not 64 hex chars: {a}");
            return 2;
        }
    }

    let result = verify_chain_anchored(&export.receipts, &pubkey, anchor);
    let _ = writeln!(out, "file:      {}", opts.file);
    let _ = writeln!(out, "edge_id:   {}", export.header.edge_id);
    if let Some(t) = &export.header.tunnel {
        let _ = writeln!(out, "tunnel:    {t}");
    }
    let _ = writeln!(out, "pubkey:    {pubkey_hex} ({key_source})");
    match result {
        Ok(summary) => {
            print_summary(out, &summary, anchor);
            let _ = writeln!(out, "receipts: OK ({} verified)", summary.count);
            0
        }
        Err(e) => {
            // Everything before the failing seq verified; say how much that was.
            let verified_before = e
                .seq()
                .and_then(|failing| export.receipts.iter().position(|r| r.seq == failing))
                .unwrap_or(0);
            let _ = writeln!(out, "verified:  {verified_before} receipt(s) before the failure");
            match e.seq() {
                Some(seq) => {
                    let _ = writeln!(out, "receipts: FAILED at seq {seq}: {e}");
                }
                None => {
                    let _ = writeln!(out, "receipts: FAILED: {e}");
                }
            }
            1
        }
    }
}

fn print_summary(out: &mut dyn Write, s: &VerifiedSummary, anchor: Option<&str>) {
    let Some((first, last)) = s.first_seq.zip(s.last_seq) else {
        let _ = writeln!(out, "receipts:  0 (an empty export verifies trivially)");
        return;
    };
    let start = match anchor {
        Some(a) if a.eq_ignore_ascii_case(GENESIS_PREV_HASH) => "anchored at genesis",
        Some(_) => "anchored to the previous export",
        None if s.from_genesis => "from genesis",
        None => "mid-chain (prev_hash of the first receipt not checked; pass --anchor)",
    };
    let _ = writeln!(out, "receipts:  {} (seq {first}..{last}, {start})", s.count);
    if let Some((a, b)) = s.first_ts.zip(s.last_ts) {
        let _ = writeln!(out, "span:      {} .. {} ({} s)", iso_utc(a), iso_utc(b), b.saturating_sub(a));
    }
    let _ = writeln!(out, "sessions:  {} opened, {} closed", s.sessions_opened, s.sessions_closed);
    let _ = writeln!(out, "bytes:     {} in / {} out (from close receipts)", s.bytes_in, s.bytes_out);
    if let Some(h) = &s.first_prev_hash {
        let _ = writeln!(out, "first_prev_hash: {h}");
    }
    if let Some(h) = &s.last_hash {
        let _ = writeln!(out, "last_hash: {h}   (--anchor for the next export)");
    }
}

/// `YYYY-MM-DDTHH:MM:SSZ` for a Unix timestamp (proleptic Gregorian, Howard Hinnant's
/// `civil_from_days`), so the summary needs no date crate.
fn iso_utc(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", secs / 3_600, (secs / 60) % 60, secs % 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ct_common::receipt::test_support::{sample_jsonl, signer};

    fn temp_file(contents: &str) -> String {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir()
            .join(format!("ct_verify_receipts_{}_{n}.jsonl", std::process::id()))
            .to_string_lossy()
            .into_owned();
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn run_capturing(args: &[&str]) -> (u8, String) {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let mut out = Vec::new();
        let code = run(&args, &mut out);
        (code, String::from_utf8(out).unwrap())
    }

    #[test]
    fn verify_receipts_accepts_a_valid_fixture_782() {
        let path = temp_file(&sample_jsonl());
        let (code, out) = run_capturing(&[&path]);
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("receipts: OK (5 verified)"), "{out}");
        assert!(out.contains("edge_id:   edge-test"), "{out}");
        assert!(out.contains("tunnel:    demo"), "{out}");
        assert!(out.contains("seq 1..5, from genesis"), "{out}");
        assert!(out.contains("sessions:  2 opened, 2 closed"), "{out}");
        assert!(out.contains("bytes:     155 in / 67 out"), "{out}");
        assert!(out.contains("span:      1970-01-01T00:16:40Z .. 1970-01-01T01:48:20Z (5500 s)"), "{out}");
        assert!(out.contains("(file header)"), "{out}");
        // The same key passed explicitly, and the genesis anchor, verify too.
        let (code, out) = run_capturing(&[&path, "--pubkey", &signer().pubkey_hex(), "--anchor", GENESIS_PREV_HASH]);
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("(--pubkey)") && out.contains("anchored at genesis"), "{out}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn verify_receipts_rejects_a_tampered_line_and_names_the_seq_782() {
        let text = sample_jsonl();
        // Edit the third receipt's (seq 3) close payload in the text itself.
        assert_eq!(text.matches("\"bytes_in\":150").count(), 1);
        let tampered = text.replace("\"bytes_in\":150", "\"bytes_in\":151");
        let path = temp_file(&tampered);
        let (code, out) = run_capturing(&[&path]);
        assert_eq!(code, 1, "{out}");
        assert!(out.contains("receipts: FAILED at seq 3"), "{out}");
        assert!(out.contains("hash does not match"), "{out}");
        assert!(out.contains("verified:  2 receipt(s) before the failure"), "{out}");
        let _ = std::fs::remove_file(&path);

        // The wrong key: everything fails at seq 1, and the header mismatch is noted.
        let path = temp_file(&text);
        let wrong = ct_common::receipt::ReceiptSigner::from_seed(&[0x01u8; 32], "x").pubkey_hex();
        let (code, out) = run_capturing(&[&path, "--pubkey", &wrong]);
        assert_eq!(code, 1, "{out}");
        assert!(out.contains("FAILED at seq 1") && out.contains("signature"), "{out}");
        assert!(out.contains("names a different key"), "{out}");

        // A dropped line is a gap at the next seq.
        let mut lines: Vec<&str> = text.lines().collect();
        lines.remove(2);
        let gapped = temp_file(&lines.join("\n"));
        let (code, out) = run_capturing(&[&gapped]);
        assert_eq!(code, 1, "{out}");
        assert!(out.contains("FAILED at seq 3") && out.contains("expected seq 2"), "{out}");

        // A wrong anchor is a broken link at the first receipt.
        let (code, out) = run_capturing(&[&path, "--anchor", &"ab".repeat(32)]);
        assert_eq!(code, 1, "{out}");
        assert!(out.contains("FAILED at seq 1") && out.contains("prev_hash"), "{out}");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&gapped);
    }

    #[test]
    fn usage_and_file_errors_exit_2() {
        let (code, out) = run_capturing(&[]);
        assert_eq!(code, 2);
        assert!(out.contains("usage:"), "{out}");
        let (code, out) = run_capturing(&["--bogus"]);
        assert_eq!(code, 2);
        assert!(out.contains("unknown option"), "{out}");
        let (code, out) = run_capturing(&["/nonexistent/receipts-782.jsonl"]);
        assert_eq!(code, 2);
        assert!(out.contains("/nonexistent/receipts-782.jsonl"), "{out}");
        let path = temp_file("{\"not\":\"a header\"}\n");
        let (code, out) = run_capturing(&[&path]);
        assert_eq!(code, 2);
        assert!(out.contains("line 1"), "{out}");
        let (code, out) = run_capturing(&[&path, "--pubkey", "zz"]);
        assert_eq!(code, 2, "{out}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn iso_utc_formats_known_instants() {
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso_utc(1_757_100_000), "2025-09-05T19:20:00Z");
        assert_eq!(iso_utc(-1), "1969-12-31T23:59:59Z");
    }
}
