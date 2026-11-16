//! Bounded SOCKS dissection for TCP 1080: version 5 per RFC 1928 (method
//! greeting, method selection, request, reply) and the classic version
//! 4/4a request/reply shape (the SOCKS4 protocol plus the 4a hostname
//! extension), honest and minimal. One packet is one row: no session
//! pairing, no proxying state, nothing beyond the captured segment.
//!
//! Honesty contracts, enforced everywhere below:
//! - A row claims only a version byte (4 or 5) plus a structurally valid
//!   message for that version in the direction the port side dictates
//!   (client→server sends greetings/requests, server→client sends
//!   selections/replies). The port alone is not SOCKS evidence; a payload
//!   with no valid shape keeps the plain transport row.
//! - Version 5 requests and replies share the same VER/REP/RSV/ATYP
//!   prefix, so the direction gate routes the shape check; it never
//!   invents a direction-specific field. Version 4 request and reply
//!   layouts are disjoint, so a wrong-direction payload claims nothing.
//! - Every list is capped (8 methods) and every decode that stops early
//!   says why ("not decoded (…)", raw codes, "+N trailing byte(s)").
//! - User-ids and 4a hostnames are bounded and printable-ASCII validated;
//!   beyond a cap or a capture boundary the row says so instead of
//!   rendering unbounded bytes.
//! - Authentication bytes are never interpreted: methods are named, and
//!   the username/password subnegotiation is out of scope.

use crate::Layer;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Method lists are shown up to this many entries (RFC 1928 allows up to
/// 255 methods; beyond the cap the row counts the rest).
const MAX_METHODS: usize = 8;
/// A greeting cannot announce more methods than this; larger values are
/// treated as a non-SOCKS shape rather than decoded.
const MAX_NMETHODS: usize = 32;
/// User-ids and 4a hostnames are shown up to this many characters.
const MAX_NAME_CHARS: usize = 128;

pub(super) struct SocksService {
    pub protocol: &'static str,
    pub info: String,
    pub layers: Vec<Layer>,
}

fn layer(label: &str, value: impl ToString) -> Layer {
    Layer {
        label: label.into(),
        value: value.to_string(),
    }
}

fn be16(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        data.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn socks_done(info: String, layers: Vec<Layer>) -> SocksService {
    SocksService {
        protocol: "SOCKS",
        info,
        layers,
    }
}

/// Render trailing bytes after the first message honestly: one packet is
/// one row and later bytes are counted, never decoded.
fn trailing_note(payload: &[u8], consumed: usize) -> String {
    match payload.len().checked_sub(consumed) {
        Some(0) | None => String::new(),
        Some(extra) => format!(" (+{extra} trailing byte(s) not decoded)"),
    }
}

fn method_name(method: u8) -> String {
    match method {
        0x00 => "no authentication required".into(),
        0x01 => "GSSAPI".into(),
        0x02 => "username/password".into(),
        0xff => "no acceptable methods".into(),
        0x03..=0x7f => format!("IANA assigned (0x{method:02x})"),
        _ => format!("private (0x{method:02x})"),
    }
}

/// SOCKS5 request/reply address (RFC 1928 §4/§5): ATYP 1 IPv4, 3 domain,
/// 4 IPv6. Returns the address string and the byte length of the address
/// field, or a refusal reason.
fn socks5_address(payload: &[u8], atyp: u8, at: usize) -> Result<(String, usize), String> {
    match atyp {
        1 => {
            let start = at
                .checked_add(4)
                .ok_or("IPv4 address truncated at capture boundary")?;
            let bytes: [u8; 4] = payload
                .get(at..start)
                .ok_or("IPv4 address truncated at capture boundary")?
                .try_into()
                .map_err(|_| "IPv4 address truncated at capture boundary".to_string())?;
            Ok((Ipv4Addr::from(bytes).to_string(), 4))
        }
        3 => {
            let len = *payload
                .get(at)
                .ok_or("domain length truncated at capture boundary")?
                as usize;
            let start = at
                .checked_add(1)
                .ok_or("domain truncated at capture boundary")?;
            let end = start
                .checked_add(len)
                .ok_or("domain truncated at capture boundary")?;
            let bytes = payload
                .get(start..end)
                .ok_or("domain truncated at capture boundary")?;
            if len > MAX_NAME_CHARS {
                return Err(format!(
                    "domain exceeds the {MAX_NAME_CHARS}-character bound"
                ));
            }
            let text =
                std::str::from_utf8(bytes).map_err(|_| "domain is not valid UTF-8".to_string())?;
            if !text.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                return Err("domain contains control characters".into());
            }
            Ok((text.to_string(), 1 + len))
        }
        4 => {
            let start = at
                .checked_add(16)
                .ok_or("IPv6 address truncated at capture boundary")?;
            let bytes: [u8; 16] = payload
                .get(at..start)
                .ok_or("IPv6 address truncated at capture boundary")?
                .try_into()
                .map_err(|_| "IPv6 address truncated at capture boundary".to_string())?;
            Ok((Ipv6Addr::from(bytes).to_string(), 16))
        }
        _ => Err(format!("address type {atyp} (not 1/3/4)")),
    }
}

fn socks5_command_name(cmd: u8) -> Option<&'static str> {
    Some(match cmd {
        1 => "CONNECT",
        2 => "BIND",
        3 => "UDP-ASSOCIATE",
        _ => return None,
    })
}

fn socks5_reply_name(rep: u8) -> String {
    match rep {
        0 => "succeeded".into(),
        1 => "general SOCKS server failure".into(),
        2 => "connection not allowed by ruleset".into(),
        3 => "network unreachable".into(),
        4 => "host unreachable".into(),
        5 => "connection refused".into(),
        6 => "TTL expired".into(),
        7 => "command not supported".into(),
        8 => "address type not supported".into(),
        _ => format!("0x{rep:02x}"),
    }
}

/// SOCKS5 client→server (RFC 1928): either a method greeting (VER=5,
/// NMETHODS ≥ 1, METHODS…) or a request (VER=5, CMD, RSV=0, ATYP, DST,
/// port). An exact-length greeting wins; otherwise the stricter request
/// shape is tried, and only then a greeting whose method list is cut by
/// the capture boundary or followed by trailing bytes.
fn socks5_client(payload: &[u8]) -> Option<SocksService> {
    let nmethods = *payload.get(1)? as usize;
    if !(1..=MAX_NMETHODS).contains(&nmethods) {
        return None;
    }
    if payload.len() == 2 + nmethods {
        return Some(socks5_greeting(payload, nmethods));
    }
    if let Some(service) = socks5_request(payload) {
        return Some(service);
    }
    // VER=5 plus a plausible NMETHODS is already shape evidence: the
    // greeting is claimed and every missing byte is stated, not guessed.
    Some(socks5_greeting(payload, nmethods))
}

fn socks5_greeting(payload: &[u8], nmethods: usize) -> SocksService {
    let captured = payload.len().saturating_sub(2).min(nmethods);
    let mut listed = Vec::new();
    for &method in payload.iter().skip(2).take(captured) {
        if listed.len() == MAX_METHODS {
            break;
        }
        listed.push(method_name(method));
    }
    let mut summary = if listed.len() < nmethods {
        format!(
            "{nmethods} method(s): {}, +{} more (cap {MAX_METHODS})",
            listed.join(", "),
            nmethods - listed.len()
        )
    } else {
        format!("{nmethods} method(s): {}", listed.join(", "))
    };
    if captured < nmethods {
        summary.push_str(&format!(
            "; method list truncated at capture boundary ({captured} of {nmethods} captured)"
        ));
    }
    let mut info = format!("SOCKS5 method greeting, {summary}");
    let trailing = trailing_note(payload, 2 + nmethods);
    info.push_str(&trailing);
    let mut layers = vec![layer("SOCKS5 greeting", summary)];
    if let Some(extra) = trailing.strip_prefix(" (") {
        layers.push(layer(
            "SOCKS5 trailing bytes",
            extra.trim_end_matches(')').to_string(),
        ));
    }
    socks_done(info, layers)
}

/// SOCKS5 request (RFC 1928 §5): VER=5, CMD, RSV=0, ATYP, address, port.
/// The RSV byte must be zero and the address length must be consistent
/// with the address type — those checks are the marker, not the port.
fn socks5_request(payload: &[u8]) -> Option<SocksService> {
    let cmd = *payload.get(1)?;
    let command = socks5_command_name(cmd)?;
    if *payload.get(2)? != 0 {
        return None; // RSV must be zero
    }
    let atyp = *payload.get(3)?;
    let (address, address_len) = match socks5_address(payload, atyp, 4) {
        Ok(found) => found,
        Err(reason) => {
            if !matches!(atyp, 1 | 3 | 4) {
                return None;
            }
            // A structurally valid request with an undecodable target
            // still claims the row: the shape is the marker, the target
            // is refused honestly and never guessed from nearby bytes.
            return Some(socks_done(
                format!("SOCKS5 {command}, target not decoded ({reason})"),
                vec![
                    layer("SOCKS5 command", command),
                    layer("SOCKS5 target", format!("not decoded ({reason})")),
                ],
            ));
        }
    };
    let port = be16(payload, 4 + address_len)?;
    let consumed = 4 + address_len + 2;
    let target = if atyp == 4 {
        format!("[{address}]:{port}")
    } else {
        format!("{address}:{port}")
    };
    let info = format!(
        "SOCKS5 {command} to {target}{}",
        trailing_note(payload, consumed)
    );
    let layers = vec![
        layer("SOCKS5 command", command),
        layer("SOCKS5 target", target),
    ];
    Some(socks_done(info, layers))
}

/// SOCKS5 server→client: either a method selection (VER=5, METHOD) or a
/// reply (VER=5, REP, RSV=0, ATYP, BND, port).
fn socks5_server(payload: &[u8]) -> Option<SocksService> {
    if payload.len() == 2 {
        let method = method_name(*payload.get(1)?);
        return Some(socks_done(
            format!("SOCKS5 method selection, {method}"),
            vec![layer("SOCKS5 method", method.clone())],
        ));
    }
    if let Some(service) = socks5_reply(payload) {
        return Some(service);
    }
    // Longer payloads that fail the reply shape still carry a selection
    // byte; it is named, and the rest is counted, never decoded.
    let method = method_name(*payload.get(1)?);
    let trailing = trailing_note(payload, 2);
    let mut layers = vec![layer("SOCKS5 method", method.clone())];
    if let Some(extra) = trailing.strip_prefix(" (") {
        layers.push(layer(
            "SOCKS5 trailing bytes",
            extra.trim_end_matches(')').to_string(),
        ));
    }
    Some(socks_done(
        format!("SOCKS5 method selection, {method}{trailing}"),
        layers,
    ))
}

/// SOCKS5 reply (RFC 1928 §6): VER=5, REP, RSV=0, ATYP, BND.ADDR,
/// BND.PORT. RSV zero and a consistent address length gate the claim.
fn socks5_reply(payload: &[u8]) -> Option<SocksService> {
    let rep = *payload.get(1)?;
    if *payload.get(2)? != 0 {
        return None;
    }
    let atyp = *payload.get(3)?;
    let status = socks5_reply_name(rep);
    let (bound, consumed) = match socks5_address(payload, atyp, 4) {
        Ok((address, len)) => {
            let port = be16(payload, 4 + len)?;
            (
                if atyp == 4 {
                    format!("[{address}]:{port}")
                } else {
                    format!("{address}:{port}")
                },
                4 + len + 2,
            )
        }
        Err(reason) => {
            if !matches!(atyp, 1 | 3 | 4) {
                return None;
            }
            (format!("not decoded ({reason})"), payload.len())
        }
    };
    if payload.len() < consumed {
        return None;
    }
    let info = format!("SOCKS5 reply, {status}{}", trailing_note(payload, consumed));
    let layers = vec![
        layer("SOCKS5 reply status", status),
        layer("SOCKS5 bound address", bound),
    ];
    Some(socks_done(info, layers))
}

/// Bytes from `at` up to the first null byte, printable-ASCII validated and
/// capped. The error names the exact reason the field was not decoded.
fn null_terminated(payload: &[u8], at: usize, cap: usize) -> Result<String, &'static str> {
    let rest = payload
        .get(at..)
        .ok_or("not present in the captured bytes")?;
    let end = rest
        .iter()
        .position(|&b| b == 0)
        .ok_or("no null terminator in the captured bytes")?;
    let bytes = &rest[..end];
    if bytes.len() > cap {
        return Err("exceeds the 128-character bound");
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "not printable ASCII")?;
    if !text.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        return Err("not printable ASCII");
    }
    Ok(text.to_string())
}

/// SOCKS4 request: VER=4, CMD, port, IPv4 destination, null-terminated
/// user-id; the 4a extension carries a null-terminated hostname when the
/// address is the 0.0.0.x local form. Bounded and honest.
fn socks4_request(payload: &[u8]) -> Option<SocksService> {
    let command = match payload.get(1) {
        Some(1) => "CONNECT",
        Some(2) => "BIND",
        _ => return None,
    };
    let port = be16(payload, 2)?;
    let ip_bytes: [u8; 4] = payload.get(4..8)?.try_into().ok()?;
    let ip = Ipv4Addr::from(ip_bytes);
    let mut layers = vec![
        layer("SOCKS4 command", command),
        layer("SOCKS4 port", port),
        layer("SOCKS4 address", ip.to_string()),
    ];
    let user = null_terminated(payload, 8, MAX_NAME_CHARS);
    let user_detail = match &user {
        Ok(text) if text.is_empty() => "absent".to_string(),
        Ok(text) => format!("\"{text}\""),
        Err(reason) => format!("not decoded ({reason})"),
    };
    layers.push(layer("SOCKS4 user id", user_detail.clone()));
    // 4a: 0.0.0.x (x != 0) marks the hostname-after-user-id extension.
    let hostname = if ip_bytes[0] == 0 && ip_bytes[1] == 0 && ip_bytes[2] == 0 && ip_bytes[3] != 0 {
        match &user {
            Ok(text) => match null_terminated(payload, 8 + text.len() + 1, MAX_NAME_CHARS) {
                Ok(name) => {
                    if name.is_empty() {
                        layers.push(layer("SOCKS4a hostname", "absent"));
                    } else {
                        layers.push(layer("SOCKS4a hostname", name.clone()));
                    }
                    Some(name)
                }
                Err(_) => None,
            },
            // The hostname rides after the user-id null; without a decoded
            // user-id its position cannot be located, so it is not guessed.
            Err(_) => None,
        }
    } else {
        None
    };
    let user_part = match &user {
        Ok(text) if !text.is_empty() => format!(", user-id \"{text}\""),
        Ok(_) => String::new(),
        Err(_) => ", user-id not decoded".into(),
    };
    let target = match &hostname {
        Some(name) => format!("{name}:{port}"),
        None => format!("{ip}:{port}"),
    };
    let version = if hostname.is_some() {
        "SOCKS4a"
    } else {
        "SOCKS4"
    };
    Some(socks_done(
        format!("{version} {command} to {target}{user_part}"),
        layers,
    ))
}

/// SOCKS4 reply: 8 bytes, VN null, CD 90-93 (90 granted, 91 rejected or
/// failed, 92 cannot reach identd, 93 different user ids). Anything else
/// claims nothing.
fn socks4_reply(payload: &[u8]) -> Option<SocksService> {
    if payload.len() < 8 || *payload.first()? != 0 {
        return None;
    }
    let status = match payload.get(1) {
        Some(90) => "request granted",
        Some(91) => "request rejected or failed",
        Some(92) => "request rejected: cannot reach identd",
        Some(93) => "request rejected: different user ids",
        _ => return None,
    };
    let port = be16(payload, 2)?;
    let ip_bytes: [u8; 4] = payload.get(4..8)?.try_into().ok()?;
    let bound = format!("{}:{port}", Ipv4Addr::from(ip_bytes));
    Some(socks_done(
        format!("SOCKS4 reply, {status}"),
        vec![
            layer("SOCKS4 reply status", status),
            layer("SOCKS4 bound address", bound),
        ],
    ))
}

/// Dissect one TCP payload already matched to port 1080 where the HTTP and
/// TLS checks declined. `client_to_server` comes from the port side and
/// gates which message version may claim the row: greetings/requests are
/// client messages, selections/replies server messages (the SOCKS4 reply
/// carries a null version byte per its wire format). Returns None when
/// there is no version/shape evidence so the caller keeps the plain
/// transport row.
pub(super) fn dissect(payload: &[u8], client_to_server: bool) -> Option<SocksService> {
    match (payload.first()?, client_to_server) {
        (5, true) => socks5_client(payload),
        (5, false) => socks5_server(payload),
        (4, true) => socks4_request(payload),
        (0, false) => socks4_reply(payload),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socks5_ipv4_request() -> Vec<u8> {
        let mut request = vec![5u8, 1, 0, 1, 10, 0, 0, 1];
        request.extend_from_slice(&8080u16.to_be_bytes());
        request
    }

    fn socks5_domain_request() -> Vec<u8> {
        let mut request = vec![5u8, 1, 0, 3, 7];
        request.extend_from_slice(b"example");
        request.extend_from_slice(&443u16.to_be_bytes());
        request
    }

    fn socks5_v6_request() -> Vec<u8> {
        let mut request = vec![5u8, 3, 0, 4];
        request.extend_from_slice(&[0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        request.extend_from_slice(&9050u16.to_be_bytes());
        request
    }

    fn socks5_reply_succeeded() -> Vec<u8> {
        let mut reply = vec![5u8, 0, 0, 1, 198, 51, 100, 7];
        reply.extend_from_slice(&3128u16.to_be_bytes());
        reply
    }

    fn socks4a_request() -> Vec<u8> {
        let mut request = vec![4u8, 1];
        request.extend_from_slice(&443u16.to_be_bytes());
        request.extend_from_slice(&[0, 0, 0, 1]);
        request.extend_from_slice(b"u\0host.example\0");
        request
    }

    #[test]
    fn socks5_greeting_lists_bounded_methods() {
        let greeting = [5u8, 2, 0x00, 0x02];
        let service = dissect(&greeting, true).unwrap();
        assert_eq!(service.protocol, "SOCKS");
        assert_eq!(
            service.info,
            "SOCKS5 method greeting, 2 method(s): no authentication required, username/password"
        );
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "SOCKS5 greeting" && l.value.contains("2 method(s)")));

        // Ten methods list eight and count the overflow.
        let mut many = vec![5u8, 10];
        many.extend(std::iter::repeat_n(0x80u8, 10));
        let service = dissect(&many, true).unwrap();
        assert!(service.info.contains("+2 more (cap 8)"), "{}", service.info);
        assert!(service.layers.iter().any(|l| l.value.contains("cap 8")));

        // Zero methods is not a greeting (RFC 1928 requires at least one).
        assert!(dissect(&[5u8, 0], true).is_none());
    }

    #[test]
    fn socks5_method_selection_names_common_methods() {
        let service = dissect(&[5u8, 0x00], false).unwrap();
        assert_eq!(
            service.info,
            "SOCKS5 method selection, no authentication required"
        );
        let service = dissect(&[5u8, 0x02], false).unwrap();
        assert_eq!(service.info, "SOCKS5 method selection, username/password");
        let service = dissect(&[5u8, 0xff], false).unwrap();
        assert_eq!(
            service.info,
            "SOCKS5 method selection, no acceptable methods"
        );
        let service = dissect(&[5u8, 0x99, 0xde, 0xad], false).unwrap();
        assert!(
            service
                .info
                .contains("private (0x99) (+2 trailing byte(s) not decoded)"),
            "{}",
            service.info
        );
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "SOCKS5 trailing bytes" && l.value.contains("2 trailing")));
    }

    #[test]
    fn socks5_requests_decode_each_address_type() {
        let service = dissect(&socks5_ipv4_request(), true).unwrap();
        assert_eq!(service.info, "SOCKS5 CONNECT to 10.0.0.1:8080");
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "SOCKS5 target" && l.value == "10.0.0.1:8080"));
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "SOCKS5 command" && l.value == "CONNECT"));

        let service = dissect(&socks5_domain_request(), true).unwrap();
        assert_eq!(service.info, "SOCKS5 CONNECT to example:443");

        let service = dissect(&socks5_v6_request(), true).unwrap();
        assert_eq!(service.info, "SOCKS5 UDP-ASSOCIATE to [2001:db8::1]:9050");

        // Trailing bytes after the first request are counted, not decoded.
        let mut pipelined = socks5_ipv4_request();
        pipelined.push(0xde);
        let service = dissect(&pipelined, true).unwrap();
        assert!(
            service.info.contains("(+1 trailing byte(s) not decoded)"),
            "{}",
            service.info
        );
    }

    #[test]
    fn socks5_replies_name_common_statuses() {
        let service = dissect(&socks5_reply_succeeded(), false).unwrap();
        assert_eq!(service.info, "SOCKS5 reply, succeeded");
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "SOCKS5 bound address" && l.value == "198.51.100.7:3128"));

        let mut refused = vec![5u8, 5, 0, 1, 0, 0, 0, 0, 0, 0];
        let service = dissect(&refused, false).unwrap();
        assert_eq!(service.info, "SOCKS5 reply, connection refused");
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "SOCKS5 bound address" && l.value == "0.0.0.0:0"));

        // An unassigned reply code keeps the raw value.
        refused[1] = 0x0a;
        let service = dissect(&refused, false).unwrap();
        assert!(service.info.contains("0x0a"), "{}", service.info);
    }

    #[test]
    fn socks4_requests_are_honest_and_4a_extracts_hostname() {
        let mut request = vec![4u8, 1];
        request.extend_from_slice(&8080u16.to_be_bytes());
        request.extend_from_slice(&[10, 0, 0, 2]);
        request.extend_from_slice(b"user\0");
        let service = dissect(&request, true).unwrap();
        assert_eq!(
            service.info,
            "SOCKS4 CONNECT to 10.0.0.2:8080, user-id \"user\""
        );
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "SOCKS4 address" && l.value == "10.0.0.2"));

        // 4a local form 0.0.0.x carries the hostname after the user-id null.
        let service = dissect(&socks4a_request(), true).unwrap();
        assert_eq!(
            service.info,
            "SOCKS4a CONNECT to host.example:443, user-id \"u\""
        );
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "SOCKS4a hostname" && l.value == "host.example"));

        // A user-id without its null terminator is refused honestly, and
        // the 4a hostname (which rides after it) decodes nothing.
        let mut unterminated = vec![4u8, 2];
        unterminated.extend_from_slice(&1080u16.to_be_bytes());
        unterminated.extend_from_slice(&[127, 0, 0, 1]);
        unterminated.extend_from_slice(b"no-terminator");
        let service = dissect(&unterminated, true).unwrap();
        assert!(
            service.info.contains("user-id not decoded"),
            "{}",
            service.info
        );
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "SOCKS4 user id" && l.value.contains("no null terminator")));
    }

    #[test]
    fn socks4_replies_gate_on_null_version_and_known_codes() {
        let granted = [0u8, 90, 0, 0, 0, 0, 0, 0];
        let service = dissect(&granted, false).unwrap();
        assert_eq!(service.info, "SOCKS4 reply, request granted");
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "SOCKS4 bound address" && l.value == "0.0.0.0:0"));

        // A nonzero VN byte is not a SOCKS4 reply.
        let wrong_vn = [4u8, 90, 0, 0, 0, 0, 0, 0];
        assert!(dissect(&wrong_vn, false).is_none());
        // Unknown CD codes claim nothing.
        let unknown = [0u8, 0x7f, 0, 0, 0, 0, 0, 0];
        assert!(dissect(&unknown, false).is_none());
        // A SOCKS4 request shape from the server side claims nothing.
        assert!(dissect(&socks4a_request(), false).is_none());
        // A SOCKS4 reply shape from the client side claims nothing.
        assert!(dissect(&granted, true).is_none());
    }

    #[test]
    fn direction_and_shape_gating_keep_the_transport_row() {
        // A greeting shape from the server side is never named a greeting:
        // it degrades to the honest selection fallback.
        let service = dissect(&[5u8, 1, 0], false).unwrap();
        assert!(
            service.info.contains("method selection"),
            "{}",
            service.info
        );
        assert!(!service.info.contains("greeting"), "{}", service.info);

        // A reply-shaped payload from the client side is refused: the
        // greeting/request handlers do not accept reply layouts.
        assert!(dissect(&socks5_reply_succeeded(), true).is_none());
        // RSV != 0 fails the request shape; the bytes still form a legal
        // greeting with trailing bytes, which is what the row names.
        let mut bad_rsv = socks5_ipv4_request();
        bad_rsv[2] = 1;
        let service = dissect(&bad_rsv, true).unwrap();
        assert!(service.info.contains("method greeting"), "{}", service.info);
        assert!(!service.info.contains("CONNECT"), "{}", service.info);
        // Unknown ATYP fails the request shape; the bytes it fits are a
        // legal 1-method greeting with trailing bytes, not a request row.
        let bad_atyp = [5u8, 1, 0, 7, 1, 2, 3, 4, 0, 0];
        let service = dissect(&bad_atyp, true).unwrap();
        assert!(service.info.contains("method greeting"), "{}", service.info);
        assert!(!service.info.contains("CONNECT"), "{}", service.info);
        // Version 3 is neither 4 nor 5.
        assert!(dissect(&[3u8, 1, 0], true).is_none());
        // Random bytes claim nothing.
        assert!(dissect(b"plain tcp payload", true).is_none());
    }

    #[test]
    fn truncated_shapes_refuse_or_degrade_honestly() {
        // A request cut before its port no longer fits the request shape;
        // the bytes it does fit are a legal 1-method greeting with
        // trailing bytes, which is what the row names.
        let request = socks5_ipv4_request();
        let service = dissect(&request[..9], true).unwrap();
        assert!(service.info.contains("method greeting"), "{}", service.info);
        assert!(
            service.info.contains("(+6 trailing byte(s) not decoded)"),
            "{}",
            service.info
        );

        // A greeting cut inside its method list still claims the honest
        // truncated row because VER=5 + NMETHODS is already shape evidence.
        let greeting = [5u8, 2, 0x00, 0x02];
        let service = dissect(&greeting[..3], true).unwrap();
        assert!(service.info.contains("method greeting"), "{}", service.info);
        assert!(
            service
                .info
                .contains("method list truncated at capture boundary"),
            "{}",
            service.info
        );

        // A domain request whose bytes are cut inside the name decodes the
        // command and refuses the target.
        let domain = socks5_domain_request();
        let service = dissect(&domain[..8], true).unwrap();
        assert!(
            service.info.contains("target not decoded"),
            "{}",
            service.info
        );
        assert!(
            service.info.contains("truncated at capture boundary"),
            "{}",
            service.info
        );

        // An oversized domain is refused against the bound, not rendered.
        let mut long = vec![5u8, 1, 0, 3, 200];
        long.extend(vec![b'x'; 200]);
        long.extend_from_slice(&443u16.to_be_bytes());
        let service = dissect(&long, true).unwrap();
        assert!(
            service.info.contains("128-character bound"),
            "{}",
            service.info
        );
    }

    /// Truncations and adversarial byte mutations across every fixture must
    /// either refuse or produce an honest SOCKS row — never panic and never
    /// leave the SOCKS protocol name off a claimed row.
    #[test]
    fn fuzz_truncations_and_mutations_refuse_or_degrade_honestly() {
        let mut many = vec![5u8, 10];
        many.extend(std::iter::repeat_n(0x80u8, 10));
        let fixtures: Vec<Vec<u8>> = vec![
            socks5_ipv4_request(),
            socks5_domain_request(),
            socks5_v6_request(),
            socks5_reply_succeeded(),
            socks4a_request(),
            many,
            vec![5u8, 2, 0x00, 0x02],
            vec![5u8, 0x00],
            vec![0u8, 90, 0, 0, 0, 0, 0, 0],
        ];
        let mut checked = 0usize;
        for fixture in &fixtures {
            for cut in 0..fixture.len() {
                for client_to_server in [true, false] {
                    if let Some(service) = dissect(&fixture[..cut], client_to_server) {
                        assert_eq!(service.protocol, "SOCKS", "cut {cut}");
                        assert!(!service.info.is_empty());
                    }
                    checked += 1;
                }
            }
            for position in (0..fixture.len()).step_by(2) {
                for value in [0x00u8, 0x01, 0x80, 0xfe, 0xff] {
                    let mut mutated = fixture.clone();
                    mutated[position] = value;
                    if let Some(service) =
                        dissect(&mutated, true).or_else(|| dissect(&mutated, false))
                    {
                        assert_eq!(
                            service.protocol, "SOCKS",
                            "position {position} value {value:#x}"
                        );
                    }
                    checked += 1;
                }
            }
        }
        assert!(checked > 450, "coverage too small: {checked}");
    }
}
