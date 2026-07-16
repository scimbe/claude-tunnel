//! Minimal DNS message codec for the ACME DNS-01 responder (#31 FD4 / #23 BP4c).
//!
//! Only what an authoritative `_acme-challenge` responder needs: parse a single
//! question and build a response carrying TXT answers (or an empty NOERROR when
//! there is nothing to serve). Hand-rolled and fully bounds-checked — never
//! panics on malformed input (like the edge's TLS ClientHello parser).

/// DNS TXT record type.
pub const TYPE_TXT: u16 = 16;
/// DNS `IN` class.
pub const CLASS_IN: u16 = 1;

/// A parsed DNS question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// Transaction id (echoed in the response).
    pub id: u16,
    /// Lowercased query name (labels joined by `.`), e.g. `_acme-challenge.host`.
    pub name: String,
    /// Query type (16 = TXT).
    pub qtype: u16,
    /// Query class (1 = IN).
    pub qclass: u16,
}

/// Parse the first question from a raw DNS query datagram. Returns `None` on a
/// truncated/malformed packet or a name that uses compression (a query's qname
/// never does). Fully bounds-checked.
pub fn parse_query(buf: &[u8]) -> Option<Query> {
    // Header: id(2) flags(2) qdcount(2) ancount(2) nscount(2) arcount(2).
    if buf.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount < 1 {
        return None;
    }
    // Question qname: sequence of length-prefixed labels ending in a 0 length.
    let mut p = 12usize;
    let mut labels = Vec::new();
    loop {
        let len = *buf.get(p)? as usize;
        if len == 0 {
            p += 1;
            break;
        }
        if len & 0xC0 != 0 {
            return None; // compression pointer is illegal in a question qname
        }
        let label = buf.get(p + 1..p + 1 + len)?;
        labels.push(std::str::from_utf8(label).ok()?.to_ascii_lowercase());
        p += 1 + len;
    }
    let qtype = u16::from_be_bytes([*buf.get(p)?, *buf.get(p + 1)?]);
    let qclass = u16::from_be_bytes([*buf.get(p + 2)?, *buf.get(p + 3)?]);
    Some(Query {
        id,
        name: labels.join("."),
        qtype,
        qclass,
    })
}

/// Build an authoritative response for `query`, carrying one TXT answer per entry
/// in `txts` (only for a TXT question; other qtypes get an empty NOERROR). Sets
/// QR + AA and echoes the question. TXT strings longer than 255 bytes are split
/// into DNS character-strings per the wire format.
pub fn build_response(query: &Query, txts: &[String]) -> Vec<u8> {
    let answers: u16 = if query.qtype == TYPE_TXT {
        txts.len() as u16
    } else {
        0
    };
    let mut out = Vec::new();
    out.extend_from_slice(&query.id.to_be_bytes());
    // flags: QR=1, opcode=0, AA=1, TC=0, RD=0, RA=0, rcode=0 -> 0x8400.
    out.extend_from_slice(&0x8400u16.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    out.extend_from_slice(&answers.to_be_bytes()); // ancount
    out.extend_from_slice(&0u16.to_be_bytes()); // nscount
    out.extend_from_slice(&0u16.to_be_bytes()); // arcount

    // Question, re-encoded from the parsed name (the qname starts at offset 12).
    encode_name(&mut out, &query.name);
    out.extend_from_slice(&query.qtype.to_be_bytes());
    out.extend_from_slice(&query.qclass.to_be_bytes());

    // Answers: point the RR name back at the question qname (offset 12 = 0xC00C).
    if query.qtype == TYPE_TXT {
        for txt in txts {
            out.extend_from_slice(&[0xC0, 0x0C]);
            out.extend_from_slice(&TYPE_TXT.to_be_bytes());
            out.extend_from_slice(&CLASS_IN.to_be_bytes());
            out.extend_from_slice(&60u32.to_be_bytes()); // TTL
            let mut rdata = Vec::new();
            for chunk in txt.as_bytes().chunks(255) {
                rdata.push(chunk.len() as u8);
                rdata.extend_from_slice(chunk);
            }
            out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            out.extend_from_slice(&rdata);
        }
    }
    out
}

/// Encode a dotted name as length-prefixed labels ending in a zero byte.
fn encode_name(out: &mut Vec<u8>, name: &str) {
    if !name.is_empty() {
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
    }
    out.push(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a raw query datagram for `name` / `qtype`.
    fn query_bytes(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&id.to_be_bytes());
        b.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
        b.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        b.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // an/ns/ar counts
        encode_name(&mut b, name);
        b.extend_from_slice(&qtype.to_be_bytes());
        b.extend_from_slice(&CLASS_IN.to_be_bytes());
        b
    }

    #[test]
    fn parse_query_reads_the_question() {
        let q = parse_query(&query_bytes(0x1234, "_acme-challenge.Example.Org", TYPE_TXT)).unwrap();
        assert_eq!(q.id, 0x1234);
        assert_eq!(q.name, "_acme-challenge.example.org", "lowercased");
        assert_eq!(q.qtype, TYPE_TXT);
        assert_eq!(q.qclass, CLASS_IN);
    }

    #[test]
    fn parse_query_rejects_truncated_and_compressed() {
        assert!(parse_query(b"").is_none());
        assert!(parse_query(&[0u8; 8]).is_none(), "shorter than a header");
        // A compression pointer where the qname must start is rejected.
        let mut b = query_bytes(1, "x.test", TYPE_TXT);
        b[12] = 0xC0;
        assert!(parse_query(&b).is_none());
    }

    #[test]
    fn build_response_carries_the_txt_answer() {
        let q = parse_query(&query_bytes(0xABCD, "_acme-challenge.host.test", TYPE_TXT)).unwrap();
        let resp = build_response(&q, &["token-value-123".to_string()]);
        // Header: echoed id, QR+AA set, one answer.
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0xABCD);
        assert_eq!(resp[2] & 0x80, 0x80, "QR set");
        assert_eq!(resp[2] & 0x04, 0x04, "AA set");
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1, "one answer");
        // The TXT value appears in the response rdata.
        let needle = b"token-value-123";
        assert!(
            resp.windows(needle.len()).any(|w| w == needle),
            "response contains the TXT value"
        );
        // The answer RR name is a compression pointer to the question (0xC00C).
        assert!(
            resp.windows(2).any(|w| w == [0xC0, 0x0C]),
            "answer name compresses to the question"
        );
    }

    #[test]
    fn build_response_is_empty_for_a_non_txt_or_unknown_name() {
        let q = parse_query(&query_bytes(1, "host.test", TYPE_TXT)).unwrap();
        // Unknown name -> NOERROR with zero answers.
        let resp = build_response(&q, &[]);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0, "no answers");
        // Non-TXT question -> no answers even if TXT values exist.
        let a = parse_query(&query_bytes(1, "host.test", 1 /* A */)).unwrap();
        let resp = build_response(&a, &["ignored".to_string()]);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0, "TXT not served for an A query");
    }
}
