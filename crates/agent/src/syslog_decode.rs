//! Syslog ingestion — the protocol-layer decoder for RFC 3164 (BSD, legacy) and RFC 5424
//! (structured) syslog messages, both over UDP (direct user decision 2026-09-06: real
//! network gear overwhelmingly sends syslog over UDP, so UDP-only keeps the surface area
//! proportionate to what's actually needed — TCP framing is real added complexity for a
//! transport this project's target hardware essentially never uses).
//!
//! Deliberately never fails on malformed input — a genuinely garbled or non-compliant
//! packet degrades to empty/best-guess fields rather than being dropped outright, same
//! "the fact that we received *something* on the port is itself worth trying to use"
//! philosophy `discovery-snmp::trap::decode` follows for a single bad varbind (there it's
//! one field; here, since there's no schema to partially fail against, it's the whole
//! header). The one thing `decode()` never guesses at is a device identity — that stays
//! `discovery-agent::syslog_ingest`'s job, purely from the packet's source IP.
use std::net::SocketAddr;

/// One decoded syslog message, protocol layer only — no device/profile concepts, no
/// knowledge of `discovery-dsl::SyslogEventSpec`. `severity`/`facility`/`hostname` are
/// always populated (with best-effort defaults on a malformed/absent header, see
/// [`decode`]'s docs) — `discovery-agent::syslog_ingest` exposes all three as automatic
/// row fields regardless of what a binding's `pattern` itself captures.
#[derive(Debug, Clone)]
pub struct DecodedSyslogMessage {
    pub source: SocketAddr,
    /// 0=emerg .. 7=debug, lower is more severe.
    pub severity: u8,
    /// 0=kernel .. 23=local7.
    pub facility: u8,
    /// Empty string if the header carried none (RFC5424 `-` NILVALUE), or a malformed
    /// header made it unrecoverable.
    pub hostname: String,
    /// The message body only — never includes PRI/TIMESTAMP/HOSTNAME (RFC5424
    /// additionally strips VERSION/APP-NAME/PROCID/MSGID/STRUCTURED-DATA). RFC3164's
    /// TAG/PID prefix, if present, remains part of this string — a profile's own
    /// `pattern` is expected to account for it, same as it would for any other
    /// vendor-specific text quirk.
    pub message: String,
}

/// Fallback facility/severity for a packet with no parseable `<PRI>` prefix at all —
/// "user-level, notice" is the conventional default most syslog receivers use for a
/// non-compliant sender, not a value this project invented.
const DEFAULT_FACILITY: u8 = 1;
const DEFAULT_SEVERITY: u8 = 5;

/// Decodes one UDP datagram's payload. Infallible by design — see this module's docs.
pub fn decode(bytes: &[u8], source: SocketAddr) -> DecodedSyslogMessage {
    let raw = String::from_utf8_lossy(bytes);
    let (facility, severity, rest) = parse_pri(&raw);

    let (hostname, message) = match rest.strip_prefix("1 ") {
        // RFC3164 always starts with a 3-letter month abbreviation right after PRI, never
        // a digit — "1 " immediately after PRI unambiguously means RFC5424's VERSION field.
        Some(after_version) => parse_rfc5424(after_version),
        None => parse_rfc3164(rest),
    };

    DecodedSyslogMessage {
        source,
        severity,
        facility,
        hostname,
        message,
    }
}

/// Parses a leading `<PRI>` and splits it off. Falls back to
/// `(DEFAULT_FACILITY, DEFAULT_SEVERITY, whole_input)` for anything that doesn't look like
/// a well-formed PRI (max value 191, `facility*8+severity` for facility 0..=23,
/// severity 0..=7) — never an error, see this module's docs.
fn parse_pri(input: &str) -> (u8, u8, &str) {
    if let Some(rest) = input.strip_prefix('<') {
        if let Some(end) = rest.find('>') {
            if end >= 1 && end <= 3 {
                if let Ok(pri) = rest[..end].parse::<u16>() {
                    if pri <= 191 {
                        return ((pri / 8) as u8, (pri % 8) as u8, &rest[end + 1..]);
                    }
                }
            }
        }
    }
    (DEFAULT_FACILITY, DEFAULT_SEVERITY, input)
}

/// Splits `s` on the first space: `("token", "rest")`, or `(s, "")` if there is none.
fn take_token(s: &str) -> (&str, &str) {
    match s.split_once(' ') {
        Some((token, rest)) => (token, rest),
        None => (s, ""),
    }
}

/// RFC5424's `-` NILVALUE convention — this project only keeps `hostname` out of the five
/// header tokens it otherwise discards, so this is the only place nil-normalization
/// actually matters.
fn nil_to_empty(s: &str) -> String {
    if s == "-" {
        String::new()
    } else {
        s.to_string()
    }
}

/// `input` is everything after the `"1 "` VERSION token [`parse_pri`]'s caller already
/// stripped. Consumes TIMESTAMP/APP-NAME/PROCID/MSGID positionally without keeping them —
/// this project has no use for them today, and inventing fields nothing reads would be
/// unused surface, not faithfulness to the RFC.
fn parse_rfc5424(input: &str) -> (String, String) {
    let (_timestamp, rest) = take_token(input);
    let (hostname, rest) = take_token(rest);
    let (_app_name, rest) = take_token(rest);
    let (_proc_id, rest) = take_token(rest);
    let (_msg_id, rest) = take_token(rest);
    let message = skip_structured_data(rest);
    // RFC5424 MSG may be prefixed with a UTF-8 BOM (RFC 5424 §6.4).
    let message = message.strip_prefix('\u{FEFF}').unwrap_or(message);
    (nil_to_empty(hostname), message.to_string())
}

/// Consumes the STRUCTURED-DATA field — `-` (nil), or one or more back-to-back
/// bracket-delimited SD-ELEMENTs whose PARAM-VALUEs may themselves contain spaces and
/// escaped quotes — and returns whatever follows it (MSG, with the single separating space
/// already stripped). Bracket/quote-aware on purpose: a naive space-split here would
/// truncate MSG at the first space *inside* a structured-data parameter value.
fn skip_structured_data(input: &str) -> &str {
    if let Some(rest) = input.strip_prefix('-') {
        return rest.strip_prefix(' ').unwrap_or(rest);
    }
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i] == b'[' {
        i += 1;
        let mut in_quotes = false;
        while i < bytes.len() {
            match bytes[i] {
                b'\\' if in_quotes => i += 1, // backslash escapes the next char inside quotes
                b'"' => in_quotes = !in_quotes,
                b']' if !in_quotes => break,
                _ => {}
            }
            i += 1;
        }
        i += 1; // step past ']' (or off the end — harmless, the loop below stops either way)
    }
    input
        .get(i..)
        .map(|s| s.strip_prefix(' ').unwrap_or(s))
        .unwrap_or("")
}

/// RFC3164's fixed-width timestamp: 3-letter month, space(s), 1-2 digit day (a single-digit
/// day is conventionally space-padded, hence tolerating a run of spaces rather than
/// exactly one), `HH:MM:SS`. Best-effort on purpose — plenty of real devices don't follow
/// this exactly; anything that doesn't match falls all the way back to "no hostname, whole
/// remainder is the message" rather than misparsing arbitrary text as one.
fn strip_rfc3164_timestamp(input: &str) -> Option<&str> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    if input.len() < 3 || !MONTHS.contains(&&input[..3]) {
        return None;
    }
    let bytes = input.as_bytes();
    let mut i = 3;
    let skip_spaces = |i: &mut usize| {
        while bytes.get(*i) == Some(&b' ') {
            *i += 1;
        }
    };
    skip_spaces(&mut i);
    let day_start = i;
    while bytes.get(i).is_some_and(u8::is_ascii_digit) {
        i += 1;
    }
    if !(1..=2).contains(&(i - day_start)) {
        return None;
    }
    skip_spaces(&mut i);
    let time_start = i;
    while bytes
        .get(i)
        .is_some_and(|b| b.is_ascii_digit() || *b == b':')
    {
        i += 1;
    }
    if i - time_start != 8 {
        // "HH:MM:SS" — anything else isn't a real RFC3164 timestamp.
        return None;
    }
    skip_spaces(&mut i);
    input.get(i..)
}

fn parse_rfc3164(input: &str) -> (String, String) {
    match strip_rfc3164_timestamp(input) {
        Some(rest) => {
            let (hostname, message) = take_token(rest);
            (hostname.to_string(), message.to_string())
        }
        None => (String::new(), input.to_string()),
    }
}

/// A long-lived UDP syslog receiver — one per `discovery-agent` process while
/// `[syslog].enabled = true`. Unlike `discovery-snmp::TrapListener`, never needs rebuilding
/// — syslog has no protocol-level authentication/identity registration to react to (see
/// `discovery-agent::syslog_ingest`'s docs for the accepted "source IP only" trust model).
pub struct SyslogListener {
    socket: tokio::net::UdpSocket,
}

impl SyslogListener {
    pub async fn bind(addr: &str) -> anyhow::Result<Self> {
        let socket = tokio::net::UdpSocket::bind(addr).await?;
        Ok(Self { socket })
    }

    pub fn local_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    /// Blocks until the next datagram, decoding it — never errors on the message content
    /// itself (see [`decode`]'s docs); only a genuine socket-level failure propagates.
    pub async fn recv(&self) -> anyhow::Result<DecodedSyslogMessage> {
        let mut buf = [0u8; 8192];
        let (len, source) = self.socket.recv_from(&mut buf).await?;
        Ok(decode(&buf[..len], source))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        "127.0.0.1:12345".parse().unwrap()
    }

    #[test]
    fn decodes_rfc5424_with_structured_data() {
        let msg = b"<134>1 2026-09-06T10:00:00Z sw-vrn-01 sshd 1234 ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"App\"] user admin logged in";
        let decoded = decode(msg, addr());
        assert_eq!(decoded.facility, 16, "134 / 8 = 16 (local0)");
        assert_eq!(decoded.severity, 6, "134 % 8 = 6 (info)");
        assert_eq!(decoded.hostname, "sw-vrn-01");
        assert_eq!(decoded.message, "user admin logged in");
    }

    #[test]
    fn decodes_rfc5424_with_nil_structured_data() {
        let msg = b"<13>1 - - - - - - hello world";
        let decoded = decode(msg, addr());
        assert_eq!(decoded.facility, 1);
        assert_eq!(decoded.severity, 5);
        assert_eq!(
            decoded.hostname, "",
            "RFC5424 '-' NILVALUE must normalize to empty, not the literal dash"
        );
        assert_eq!(decoded.message, "hello world");
    }

    #[test]
    fn decodes_rfc5424_message_strips_leading_bom() {
        let msg = "<134>1 2026-09-06T10:00:00Z host app 1 - - \u{FEFF}hello".as_bytes();
        let decoded = decode(msg, addr());
        assert_eq!(decoded.message, "hello");
    }

    #[test]
    fn decodes_valid_rfc3164() {
        let msg = b"<38>Jan 12 10:00:00 sw-vrn-01 sshd[1234]: Accepted password for admin";
        let decoded = decode(msg, addr());
        assert_eq!(decoded.facility, 4, "38 / 8 = 4 (auth)");
        assert_eq!(decoded.severity, 6, "38 % 8 = 6 (info)");
        assert_eq!(decoded.hostname, "sw-vrn-01");
        assert_eq!(
            decoded.message, "sshd[1234]: Accepted password for admin",
            "TAG/PID stays part of the message body, not stripped"
        );
    }

    #[test]
    fn decodes_rfc3164_with_double_space_padded_single_digit_day() {
        let msg = b"<13>Jan  1 00:00:00 host testmsg";
        let decoded = decode(msg, addr());
        assert_eq!(decoded.hostname, "host");
        assert_eq!(decoded.message, "testmsg");
    }

    #[test]
    fn malformed_header_degrades_gracefully_instead_of_erroring() {
        let decoded = decode(b"this is not syslog at all", addr());
        assert_eq!(decoded.facility, DEFAULT_FACILITY);
        assert_eq!(decoded.severity, DEFAULT_SEVERITY);
        assert_eq!(decoded.hostname, "");
        assert_eq!(decoded.message, "this is not syslog at all");
    }

    #[test]
    fn valid_pri_with_non_compliant_body_still_extracts_severity_facility() {
        let decoded = decode(b"<13>random garbage without a timestamp", addr());
        assert_eq!(decoded.facility, 1);
        assert_eq!(decoded.severity, 5);
        assert_eq!(
            decoded.hostname, "",
            "no RFC3164 timestamp to anchor a hostname split on"
        );
        assert_eq!(decoded.message, "random garbage without a timestamp");
    }

    /// Real UDP round trip (not our own encoder) — a plain `UdpSocket::send_to` sends bytes
    /// built by hand, `SyslogListener` receives and decodes them. `bind("127.0.0.1:0")`
    /// picks a free port so tests never collide, same pattern as
    /// `discovery-snmp::trap`'s real-UDP tests.
    #[tokio::test]
    async fn real_udp_round_trip_rfc3164() {
        let listener = SyslogListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(
                b"<38>Jan 12 10:00:00 sw-vrn-01 sshd[1234]: Accepted password for admin",
                addr,
            )
            .await
            .unwrap();

        let decoded = tokio::time::timeout(std::time::Duration::from_secs(5), listener.recv())
            .await
            .expect("must receive within timeout")
            .unwrap();
        assert_eq!(decoded.facility, 4);
        assert_eq!(decoded.severity, 6);
        assert_eq!(decoded.hostname, "sw-vrn-01");
        assert_eq!(decoded.message, "sshd[1234]: Accepted password for admin");
    }

    #[tokio::test]
    async fn real_udp_round_trip_rfc5424() {
        let listener = SyslogListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender
            .send_to(
                b"<134>1 2026-09-06T10:00:00Z sw-vrn-01 sshd 1234 ID47 [exampleSDID@32473 iut=\"3\"] user admin logged in",
                addr,
            )
            .await
            .unwrap();

        let decoded = tokio::time::timeout(std::time::Duration::from_secs(5), listener.recv())
            .await
            .expect("must receive within timeout")
            .unwrap();
        assert_eq!(decoded.facility, 16);
        assert_eq!(decoded.severity, 6);
        assert_eq!(decoded.hostname, "sw-vrn-01");
        assert_eq!(decoded.message, "user admin logged in");
    }
}
