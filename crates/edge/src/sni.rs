//! TLS SNI extraction for the Browser Plane (#23, sub-packet 1).
//!
//! The Edge routes a browser's TLS connection to a tunnel **by the SNI hostname
//! in its ClientHello**, without terminating TLS: the ClientHello is sent in the
//! clear at the start of a TLS connection, so the Edge can read the `server_name`
//! extension, look up the target tunnel, and then pass the raw TLS bytes through
//! to the Origin (which holds the certificate). The Edge therefore sees only the
//! hostname and ciphertext — the payload stays blind (ADR-0010 trade-off: the
//! Browser Plane reveals the hostname the Mesh Plane hides).

use tokio::io::{AsyncRead, AsyncReadExt};

/// ALPN protocol id the tunnel data plane advertises on the unified :443 front
/// door (#31): a ClientHello carrying it is routed to the edge TLS-TCP relay.
pub const CT_EDGE_ALPN: &str = "ct-edge";

/// Return the raw `extensions` block of a buffered TLS ClientHello record, or
/// `None` if `buf` is not a ClientHello. Fully bounds-checked — never panics.
fn client_hello_extensions(buf: &[u8]) -> Option<&[u8]> {
    // TLS record header: content_type(1)=0x16 handshake, version(2), length(2).
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let hs = buf.get(5..5 + rec_len)?;
    // Handshake: msg_type(1)=0x01 ClientHello, length(3), then the body.
    if hs.len() < 4 || hs[0] != 0x01 {
        return None;
    }
    let body = hs.get(4..)?;
    // client_version(2) + random(32).
    let mut p = 34usize;
    // session_id: len(1) + id.
    let sid = *body.get(p)? as usize;
    p += 1 + sid;
    // cipher_suites: len(2) + suites.
    let cs = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
    p += 2 + cs;
    // compression_methods: len(1) + methods.
    let cm = *body.get(p)? as usize;
    p += 1 + cm;
    // extensions: len(2) + extensions.
    let ext_total = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
    p += 2;
    body.get(p..p + ext_total)
}

/// Find the first extension of type `want` in `exts` and map its data with `f`.
fn find_extension<T>(exts: &[u8], want: u16, f: impl Fn(&[u8]) -> Option<T>) -> Option<T> {
    let mut q = 0usize;
    while q + 4 <= exts.len() {
        let etype = u16::from_be_bytes([exts[q], exts[q + 1]]);
        let elen = u16::from_be_bytes([exts[q + 2], exts[q + 3]]) as usize;
        let edata = exts.get(q + 4..q + 4 + elen)?;
        if etype == want {
            return f(edata);
        }
        q += 4 + elen;
    }
    None
}

/// Parse the SNI `host_name` from a buffered TLS ClientHello record (the raw
/// bytes starting at the TLS record header). Returns the lowercased hostname, or
/// `None` if `buf` is not a ClientHello record or carries no SNI. Fully
/// bounds-checked — never panics on malformed input.
pub fn peek_sni(buf: &[u8]) -> Option<String> {
    let exts = client_hello_extensions(buf)?;
    // server_name (0x0000): list len(2) + first entry type(1)=0 host_name,
    // name_len(2), name.
    find_extension(exts, 0x0000, |edata| {
        if edata.len() < 2 {
            return None;
        }
        let list_len = u16::from_be_bytes([edata[0], edata[1]]) as usize;
        let list = edata.get(2..2 + list_len)?;
        if list.len() < 3 || list[0] != 0x00 {
            return None;
        }
        let name_len = u16::from_be_bytes([list[1], list[2]]) as usize;
        let name = list.get(3..3 + name_len)?;
        std::str::from_utf8(name).ok().map(|s| s.to_ascii_lowercase())
    })
}

/// Parse the ALPN protocol list from a buffered TLS ClientHello (#31 FD1).
/// Returns the advertised protocols in order, or an empty vec if absent/malformed.
pub fn peek_alpn(buf: &[u8]) -> Vec<String> {
    let Some(exts) = client_hello_extensions(buf) else {
        return Vec::new();
    };
    // application_layer_protocol_negotiation (0x0010): ProtocolNameList =
    // list_len(2) + entries of len(1) + name.
    find_extension(exts, 0x0010, |edata| {
        if edata.len() < 2 {
            return None;
        }
        let list_len = u16::from_be_bytes([edata[0], edata[1]]) as usize;
        let list = edata.get(2..2 + list_len)?;
        let mut out = Vec::new();
        let mut i = 0usize;
        while i < list.len() {
            let l = *list.get(i)? as usize;
            let name = list.get(i + 1..i + 1 + l)?;
            if let Ok(s) = std::str::from_utf8(name) {
                out.push(s.to_string());
            }
            i += 1 + l;
        }
        Some(out)
    })
    .unwrap_or_default()
}

/// Where the unified :443 front door should route a peeked ClientHello (#31 FD1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrontDoorRoute {
    /// Tunnel data plane — the client advertised the `ct-edge` ALPN: hand off to
    /// the edge TLS-TCP relay (the ADR-0004 fallback rung on :443).
    EdgeRelay,
    /// Control-plane / portal — reverse-proxy to the control plane's HTTP.
    ControlPlane,
    /// Browser-Plane passthrough, routed by this SNI hostname against the host
    /// registry (an unknown host is rejected downstream, not here).
    BrowserTunnel(String),
    /// Nothing matched — refuse the connection.
    Reject,
}

/// Classify a peeked ClientHello for the unified :443 front door (#31 FD1).
///
/// Precedence: the tunnel data-plane ALPN wins; then the configured portal
/// hostname; then any other SNI is a Browser-Plane passthrough candidate; a
/// web ALPN with no SNI (e.g. `curl https://<ip>/`) lands on the control plane;
/// anything else is refused.
pub fn classify_front_door(
    alpn: &[String],
    sni: Option<&str>,
    portal_host: Option<&str>,
) -> FrontDoorRoute {
    if alpn.iter().any(|p| p == CT_EDGE_ALPN) {
        return FrontDoorRoute::EdgeRelay;
    }
    let sni = sni.map(|s| s.to_ascii_lowercase());
    if let (Some(sni), Some(portal)) = (sni.as_deref(), portal_host) {
        if sni == portal.to_ascii_lowercase() {
            return FrontDoorRoute::ControlPlane;
        }
    }
    if let Some(sni) = sni {
        return FrontDoorRoute::BrowserTunnel(sni);
    }
    if alpn.iter().any(|p| p == "http/1.1" || p == "h2") {
        return FrontDoorRoute::ControlPlane;
    }
    FrontDoorRoute::Reject
}

/// Read the first TLS record (the ClientHello) from `stream` and return the
/// buffered bytes plus the SNI hostname. The buffered bytes must be forwarded
/// verbatim to the Origin so the TLS handshake completes end-to-end. Returns
/// `None` if the stream does not start with a ClientHello carrying SNI.
pub async fn read_client_hello<S: AsyncRead + Unpin>(stream: &mut S) -> Option<(Vec<u8>, String)> {
    let mut buf = vec![0u8; 5];
    stream.read_exact(&mut buf).await.ok()?;
    if buf[0] != 0x16 {
        return None;
    }
    let rec_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    // A ClientHello fits in one TLS record; cap at the record-size maximum.
    if rec_len == 0 || rec_len > 16384 {
        return None;
    }
    buf.resize(5 + rec_len, 0);
    stream.read_exact(&mut buf[5..]).await.ok()?;
    let sni = peek_sni(&buf)?;
    Some((buf, sni))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TLS ClientHello record carrying `host` as its only SNI.
    fn client_hello_with_sni(host: &str) -> Vec<u8> {
        let h = host.as_bytes();
        // server_name entry: type(0) + name_len(2) + name.
        let mut entry = vec![0x00];
        entry.extend_from_slice(&(h.len() as u16).to_be_bytes());
        entry.extend_from_slice(h);
        // server_name_list: list_len(2) + entry.
        let mut snl = (entry.len() as u16).to_be_bytes().to_vec();
        snl.extend_from_slice(&entry);
        // extension: type(0x0000) + len(2) + data.
        let mut ext = vec![0x00, 0x00];
        ext.extend_from_slice(&(snl.len() as u16).to_be_bytes());
        ext.extend_from_slice(&snl);
        // ClientHello body: version(2)+random(32)+sid_len(0)+cs_len(2)+cs(2)
        // +cm_len(1)+cm(1)+ext_total(2)+ext.
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0x00); // session_id length 0
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites length
        body.extend_from_slice(&[0x13, 0x01]); // one suite
        body.push(0x01); // compression_methods length
        body.push(0x00); // null compression
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        // Handshake header: msg_type(0x01) + length(3).
        let mut hs = vec![0x01];
        let bl = body.len();
        hs.extend_from_slice(&[(bl >> 16) as u8, (bl >> 8) as u8, bl as u8]);
        hs.extend_from_slice(&body);
        // Record header: type(0x16) + version(2) + length(2).
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    /// Build a ClientHello with an optional SNI and an optional ALPN list.
    fn client_hello(sni: Option<&str>, alpn: &[&str]) -> Vec<u8> {
        let mut exts = Vec::new();
        if let Some(host) = sni {
            let h = host.as_bytes();
            let mut entry = vec![0x00];
            entry.extend_from_slice(&(h.len() as u16).to_be_bytes());
            entry.extend_from_slice(h);
            let mut snl = (entry.len() as u16).to_be_bytes().to_vec();
            snl.extend_from_slice(&entry);
            exts.extend_from_slice(&[0x00, 0x00]);
            exts.extend_from_slice(&(snl.len() as u16).to_be_bytes());
            exts.extend_from_slice(&snl);
        }
        if !alpn.is_empty() {
            let mut list = Vec::new();
            for p in alpn {
                list.push(p.len() as u8);
                list.extend_from_slice(p.as_bytes());
            }
            let mut data = (list.len() as u16).to_be_bytes().to_vec();
            data.extend_from_slice(&list);
            exts.extend_from_slice(&[0x00, 0x10]);
            exts.extend_from_slice(&(data.len() as u16).to_be_bytes());
            exts.extend_from_slice(&data);
        }
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0u8; 32]);
        body.push(0x00);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(0x01);
        body.push(0x00);
        body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        body.extend_from_slice(&exts);
        let mut hs = vec![0x01];
        let bl = body.len();
        hs.extend_from_slice(&[(bl >> 16) as u8, (bl >> 8) as u8, bl as u8]);
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend_from_slice(&hs);
        rec
    }

    #[test]
    fn peek_sni_extracts_and_lowercases_the_hostname() {
        let ch = client_hello_with_sni("App.Example.Test");
        assert_eq!(peek_sni(&ch).as_deref(), Some("app.example.test"));
    }

    #[test]
    fn peek_alpn_parses_the_protocol_list_alongside_sni() {
        // #31 FD1: ALPN list parsed in order; SNI still readable in the same hello.
        let ch = client_hello(Some("h.test"), &["h2", "http/1.1"]);
        assert_eq!(peek_alpn(&ch), vec!["h2".to_string(), "http/1.1".to_string()]);
        assert_eq!(peek_sni(&ch).as_deref(), Some("h.test"));
        // Absent / malformed -> empty, never a panic.
        assert!(peek_alpn(&client_hello(Some("h.test"), &[])).is_empty());
        assert!(peek_alpn(b"").is_empty());
    }

    #[test]
    fn classify_front_door_routes_by_alpn_then_sni() {
        // #31 FD1: the demux precedence for the unified :443 front door.
        let s = |v: &str| v.to_string();
        // Tunnel data-plane ALPN wins, even with an SNI present.
        assert_eq!(
            classify_front_door(&[s("ct-edge")], Some("whatever.z"), Some("portal.z")),
            FrontDoorRoute::EdgeRelay
        );
        // Configured portal host -> control plane (case-insensitive).
        assert_eq!(
            classify_front_door(&[s("h2")], Some("Portal.Z"), Some("portal.z")),
            FrontDoorRoute::ControlPlane
        );
        // Any other SNI -> Browser-Plane passthrough candidate.
        assert_eq!(
            classify_front_door(&[], Some("app1.z"), Some("portal.z")),
            FrontDoorRoute::BrowserTunnel("app1.z".into())
        );
        // Web ALPN, no SNI (curl to the bare IP) -> control plane.
        assert_eq!(
            classify_front_door(&[s("http/1.1")], None, Some("portal.z")),
            FrontDoorRoute::ControlPlane
        );
        // Nothing usable -> reject.
        assert_eq!(classify_front_door(&[], None, Some("portal.z")), FrontDoorRoute::Reject);
    }

    #[test]
    fn peek_sni_rejects_non_clienthello_and_malformed() {
        assert_eq!(peek_sni(b""), None);
        assert_eq!(peek_sni(&[0x17, 0x03, 0x03, 0x00, 0x01, 0x00]), None); // not handshake
        let mut ch = client_hello_with_sni("x.test");
        ch.truncate(ch.len() - 3); // chop the SNI name -> out of bounds
        assert_eq!(peek_sni(&ch), None);
    }

    #[tokio::test]
    async fn read_client_hello_buffers_the_record_and_returns_sni() {
        let ch = client_hello_with_sni("host.test");
        let mut stream = std::io::Cursor::new(ch.clone());
        let (buf, sni) = read_client_hello(&mut stream).await.expect("sni");
        assert_eq!(sni, "host.test");
        assert_eq!(buf, ch, "the full ClientHello is buffered for passthrough");
    }
}
