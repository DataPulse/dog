//! Walking and mutating raw DNS and HTTP messages.
//!
//! Offsets are always found by walking the real captured message, never
//! hard-coded, so a mutation still lands in the right place if a fixture is
//! re-captured and its layout shifts.

use std::ops::Range;

/// The length of a DNS message header.
pub const HEADER_LEN: usize = 12;

/// The QR bit: set in responses, clear in queries.
pub const QR: u16 = 0x8000;

/// The AA (authoritative answer) bit.
pub const AA: u16 = 0x0400;

/// The TC (truncated) bit.
pub const TC: u16 = 0x0200;

/// Reads a big-endian `u16` at `at`.
pub fn get_u16(buf: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([buf[at], buf[at + 1]])
}

/// Writes a big-endian `u16` at `at`.
pub fn set_u16(buf: &mut [u8], at: usize, value: u16) {
    buf[at .. at + 2].copy_from_slice(&value.to_be_bytes());
}

/// The message’s transaction ID.
pub fn txid(message: &[u8]) -> u16 {
    get_u16(message, 0)
}

/// A copy of the message with a different transaction ID.
pub fn with_txid(message: &[u8], id: u16) -> Vec<u8> {
    let mut out = message.to_vec();
    set_u16(&mut out, 0, id);
    out
}

/// The message’s flags field.
pub fn flags(message: &[u8]) -> u16 {
    get_u16(message, 2)
}

/// A copy of the message with the given flag bits cleared.
pub fn without_flag(message: &[u8], flag: u16) -> Vec<u8> {
    let mut out = message.to_vec();
    set_u16(&mut out, 2, flags(message) & !flag);
    out
}

/// A copy of the message with the given flag bits set.
pub fn with_flag(message: &[u8], flag: u16) -> Vec<u8> {
    let mut out = message.to_vec();
    set_u16(&mut out, 2, flags(message) | flag);
    out
}

/// A copy of the message with a different 4-bit header rcode.
pub fn with_rcode(message: &[u8], rcode: u16) -> Vec<u8> {
    let mut out = message.to_vec();
    set_u16(&mut out, 2, (flags(message) & !0xF) | (rcode & 0xF));
    out
}

/// The four section counts: questions, answers, authorities, additionals.
pub fn counts(message: &[u8]) -> [u16; 4] {
    [get_u16(message, 4), get_u16(message, 6), get_u16(message, 8), get_u16(message, 10)]
}

/// A copy of the message with one section count changed (0 = questions).
pub fn with_count(message: &[u8], section: usize, count: u16) -> Vec<u8> {
    let mut out = message.to_vec();
    set_u16(&mut out, 4 + 2 * section, count);
    out
}

/// The offset just past the (possibly compressed) name that starts at `at`.
pub fn skip_name(buf: &[u8], mut at: usize) -> usize {
    loop {
        let length = buf[at];
        if length == 0 {
            return at + 1;
        }
        if length & 0xC0 == 0xC0 {
            return at + 2;
        }
        at += 1 + usize::from(length);
    }
}

/// The offset just past the question section.
pub fn question_end(message: &[u8]) -> usize {
    let mut at = HEADER_LEN;
    for _ in 0 .. counts(message)[0] {
        at = skip_name(message, at) + 4;
    }
    at
}

/// Which section of a message a record is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Answer,
    Authority,
    Additional,
}

/// Where one resource record lives inside a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrSpan {
    pub section: Section,
    pub name_at: usize,
    pub rtype: u16,
    pub rdlength_at: usize,
    pub rdata: Range<usize>,
}

/// Every resource record in the message, in wire order.
pub fn rr_spans(message: &[u8]) -> Vec<RrSpan> {
    let [_, answers, authorities, additionals] = counts(message);
    let sections = [
        (Section::Answer, answers),
        (Section::Authority, authorities),
        (Section::Additional, additionals),
    ];

    let mut at = question_end(message);
    let mut spans = Vec::new();
    for (section, count) in sections {
        for _ in 0 .. count {
            let span = rr_span_at(message, at, section);
            at = span.rdata.end;
            spans.push(span);
        }
    }
    spans
}

fn rr_span_at(message: &[u8], name_at: usize, section: Section) -> RrSpan {
    let type_at = skip_name(message, name_at);
    let rdlength_at = type_at + 8;
    let start = rdlength_at + 2;
    let end = start + usize::from(get_u16(message, rdlength_at));
    RrSpan { section, name_at, rtype: get_u16(message, type_at), rdlength_at, rdata: start .. end }
}

/// The first record of the given type, from any section.
///
/// # Panics
///
/// Panics if the message has no such record.
pub fn first_rr(message: &[u8], rtype: u16) -> RrSpan {
    rr_spans(message).into_iter().find(|span| span.rtype == rtype)
        .unwrap_or_else(|| panic!("no record of type {rtype} in the message"))
}

/// A copy of the message with one record’s rdlength field changed.
pub fn with_rdlength(message: &[u8], span: &RrSpan, rdlength: u16) -> Vec<u8> {
    let mut out = message.to_vec();
    set_u16(&mut out, span.rdlength_at, rdlength);
    out
}

/// A copy of the message with `range` replaced by `replacement`.
pub fn splice(message: &[u8], range: Range<usize>, replacement: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len() + replacement.len());
    out.extend_from_slice(&message[.. range.start]);
    out.extend_from_slice(replacement);
    out.extend_from_slice(&message[range.end ..]);
    out
}

/// The first `len` bytes of the message.
pub fn truncate(message: &[u8], len: usize) -> Vec<u8> {
    message[.. len].to_vec()
}

/// The offset just past the blank line that ends an HTTP message’s head.
pub fn http_header_end(message: &[u8]) -> Option<usize> {
    message.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// The status line and header lines of an HTTP message, without the blank line.
///
/// # Panics
///
/// Panics if the head never ends or is not UTF-8.
pub fn http_head_lines(message: &[u8]) -> Vec<String> {
    let end = http_header_end(message).expect("the HTTP message has a complete head");
    let head = std::str::from_utf8(&message[.. end - 4]).expect("the HTTP head is UTF-8");
    head.split("\r\n").map(str::to_owned).collect()
}

/// The body of an HTTP message.
///
/// # Panics
///
/// Panics if the head never ends.
pub fn http_body(message: &[u8]) -> &[u8] {
    let end = http_header_end(message).expect("the HTTP message has a complete head");
    &message[end ..]
}

/// Rebuilds an HTTP message from head lines and a body.
pub fn http_message(lines: &[String], body: &[u8]) -> Vec<u8> {
    let mut out = lines.join("\r\n").into_bytes();
    out.extend_from_slice(b"\r\n\r\n");
    out.extend_from_slice(body);
    out
}

/// A copy of an HTTP message with each header line passed through `f`,
/// which returns the replacement line, or `None` to drop it. The status line
/// is kept as it is.
pub fn map_http_headers(message: &[u8], f: impl Fn(&str) -> Option<String>) -> Vec<u8> {
    let mut lines = http_head_lines(message);
    let status = lines.remove(0);
    let mut kept = vec![status];
    kept.extend(lines.iter().filter_map(|line| f(line)));
    http_message(&kept, http_body(message))
}

/// Whether an HTTP message’s Content-Type is `application/dns-message`.
pub fn http_is_dns(message: &[u8]) -> bool {
    http_header_end(message).is_some() && http_head_lines(message).iter().skip(1).any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("content-type")
                && value.trim().eq_ignore_ascii_case("application/dns-message")
        })
    })
}

/// A copy of an HTTP message with the DNS transaction ID in its body replaced.
///
/// # Panics
///
/// Panics if the message has no complete head or a body shorter than two bytes.
pub fn patch_body_txid(message: &[u8], id: u16) -> Vec<u8> {
    let end = http_header_end(message).expect("the HTTP message has a complete head");
    assert!(message.len() >= end + 2, "the HTTP body is too short to hold a DNS header");
    let mut out = message.to_vec();
    set_u16(&mut out, end, id);
    out
}


#[cfg(test)]
mod test {
    use super::*;

    // A real response captured from 1.1.1.1 for `A dns.lookup.dog`, as found
    // in dns/tests/wire_parsing_tests.rs: one question, one answer, one OPT.
    const RESPONSE: &[u8] = &[
        0x0d, 0xcd, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        0x03, 0x64, 0x6e, 0x73, 0x06, 0x6c, 0x6f, 0x6f, 0x6b, 0x75, 0x70, 0x03,
        0x64, 0x6f, 0x67, 0x00, 0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x03, 0xa5, 0x00, 0x04,
        0x8a, 0x44, 0x75, 0x5e,
        0x00, 0x00, 0x29, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn header_fields() {
        assert_eq!(txid(RESPONSE), 0x0dcd);
        assert_eq!(flags(RESPONSE), 0x8180);
        assert_eq!(counts(RESPONSE), [1, 1, 0, 1]);
        assert_eq!(txid(&with_txid(RESPONSE, 0xbeef)), 0xbeef);
        assert_eq!(flags(&without_flag(RESPONSE, QR)), 0x0180);
        assert_eq!(flags(&with_flag(RESPONSE, TC)), 0x8380);
        assert_eq!(flags(&with_rcode(RESPONSE, 3)), 0x8183);
        assert_eq!(counts(&with_count(RESPONSE, 1, 7)), [1, 7, 0, 1]);
    }

    #[test]
    fn walks_records() {
        assert_eq!(question_end(RESPONSE), 32);
        let spans = rr_spans(RESPONSE);
        assert_eq!(spans.len(), 2);
        assert_eq!(spans[0], RrSpan { section: Section::Answer, name_at: 32, rtype: 1, rdlength_at: 42, rdata: 44 .. 48 });
        assert_eq!(spans[1].section, Section::Additional);
        assert_eq!(spans[1].rtype, 41);
        assert_eq!(spans[1].rdata.end, RESPONSE.len());
        assert_eq!(first_rr(RESPONSE, 41), spans[1]);
    }

    #[test]
    #[should_panic(expected = "no record of type 99")]
    fn first_rr_missing() {
        first_rr(RESPONSE, 99);
    }

    #[test]
    fn edits() {
        let span = first_rr(RESPONSE, 1);
        assert_eq!(get_u16(&with_rdlength(RESPONSE, &span, 9), span.rdlength_at), 9);
        assert_eq!(splice(b"abcdef", 1 .. 3, b"XYZ"), b"aXYZdef");
        assert_eq!(truncate(b"abcdef", 2), b"ab");
    }

    #[test]
    fn http_helpers() {
        let message = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: 2\r\n\r\n\x12\x34";
        assert_eq!(http_header_end(message), Some(message.len() - 2));
        assert_eq!(http_body(message), b"\x12\x34");
        assert!(http_is_dns(message));
        assert_eq!(http_body(&patch_body_txid(message, 0xabcd)), b"\xab\xcd");

        let lowered = map_http_headers(message, |line| Some(line.to_ascii_lowercase()));
        assert!(lowered.starts_with(b"HTTP/1.1 200 OK\r\ncontent-type"));
        let dropped = map_http_headers(message, |line| (!line.starts_with("Content-Type")).then(|| line.to_owned()));
        assert!(!http_is_dns(&dropped));
        assert!(!http_is_dns(b"HTTP/1.1 200 OK"));
    }
}
