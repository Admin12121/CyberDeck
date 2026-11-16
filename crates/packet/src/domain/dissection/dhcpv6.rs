//! Bounded DHCPv6 dissection for UDP 546/547 (RFC 8415). Clients listen on
//! UDP 546 and servers/relays on 547 over link-local UDP, so the port side
//! decides the direction a captured datagram travels and which message
//! types may claim the row. The message header (RFC 8415 §7.3: msg-type,
//! 3-byte transaction id) and a bounded option walk (§7.4: 16-bit code,
//! 16-bit length, value) are decoded; relay messages are named but their
//! relayed payloads are not. One datagram is one row: no client/server
//! session pairing, nothing beyond the captured datagram.
//!
//! Honesty contracts, enforced everywhere below:
//! - Only a complete datagram claims a row: every option must end exactly
//!   at the datagram boundary (the UDP length checks upstream guarantee
//!   the payload is the declared datagram), the walk is capped at 32
//!   options, and any overrun refuses the row entirely rather than
//!   decoding a partial option.
//! - Direction is evidence: client message types (SOLICIT…) claim rows
//!   only from client→server datagrams, server types (ADVERTISE, REPLY,
//!   RECONFIGURE) only from server→client, relay types only on 547↔547.
//!   A SOLICIT arriving on the server side claims nothing.
//! - RFC 8415 §21.2/§21.3 make the client identifier mandatory in client
//!   messages and the server identifier mandatory in server messages; a
//!   message type without its mandatory identifier is refused, not guessed.
//! - Duplicate client/server identifiers or status codes refuse the row
//!   (the DHCPv4 discipline); option details are capped and any decode
//!   that stops early says why ("not decoded (…)"). Authentication and
//!   encrypted options are never interpreted.

use crate::Layer;

/// Options are walked up to this many entries; more is treated as a
/// malformed datagram, not decoded.
const MAX_OPTIONS: usize = 32;
/// The option summary lists up to this many codes (like the SMB dialect
/// list); the rest are counted.
const MAX_LISTED_OPTIONS: usize = 8;
/// DUID hex and option payloads are shown up to this many bytes.
const MAX_DUID_BYTES: usize = 16;
/// A status message string is shown up to this many characters.
const MAX_STATUS_CHARS: usize = 64;
/// A DHCPv6 datagram is at least msg-type + transaction id (4 bytes) and
/// stays within a bounded Ethernet-sized datagram.
const MAX_DATAGRAM: usize = 1500;
/// Relay header (RFC 8415 §7.5): msg-type, hop-count, 16-byte link
/// address, 16-byte peer address.
const RELAY_HEADER: usize = 34;

#[derive(Clone)]
pub(super) enum Direction {
    ClientToServer,
    ServerToClient,
    Relay,
}

pub(super) struct Dhcpv6Service {
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

fn be32(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        data.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn dhcpv6_done(info: String, layers: Vec<Layer>) -> Dhcpv6Service {
    Dhcpv6Service {
        protocol: "DHCPv6",
        info,
        layers,
    }
}

fn message_name(kind: u8) -> Option<&'static str> {
    Some(match kind {
        1 => "SOLICIT",
        2 => "ADVERTISE",
        3 => "REQUEST",
        4 => "CONFIRM",
        5 => "RENEW",
        6 => "REBIND",
        7 => "REPLY",
        8 => "RELEASE",
        9 => "DECLINE",
        10 => "RECONFIGURE",
        11 => "INFORMATION-REQUEST",
        12 => "RELAY-FORW",
        13 => "RELAY-REPL",
        _ => return None,
    })
}

/// Which side sends this message type, for the direction gate.
fn is_client_message(kind: u8) -> bool {
    matches!(kind, 1 | 3 | 4 | 5 | 6 | 8 | 9 | 11)
}

fn is_server_message(kind: u8) -> bool {
    matches!(kind, 2 | 7 | 10)
}

/// Documented option codes (RFC 8415 §21, RFC 3646) that office captures
/// actually produce; everything outside the table keeps the raw code.
fn option_name(code: u16) -> Option<&'static str> {
    Some(match code {
        1 => "client identifier",
        2 => "server identifier",
        3 => "IA_NA",
        4 => "IA_TA",
        5 => "IAADDR",
        6 => "option request",
        7 => "preference",
        8 => "elapsed time",
        9 => "relay message",
        10 => "authentication",
        13 => "status code",
        14 => "rapid commit",
        23 => "DNS servers",
        24 => "domain list",
        _ => return None,
    })
}

/// Documented status codes (RFC 8415 §21.13); everything else keeps the
/// raw code.
fn status_name(code: u16) -> String {
    match code {
        0 => "Success".into(),
        1 => "UnspecFail".into(),
        2 => "NoAddrsAvail".into(),
        3 => "NoBinding".into(),
        4 => "NotOnLink".into(),
        5 => "UseMulticast".into(),
        6 => "NoPrefixAvail".into(),
        _ => format!("0x{code:04x}"),
    }
}

fn hex_bounded(bytes: &[u8], cap: usize) -> String {
    let shown = bytes.len().min(cap);
    let mut text = String::new();
    for (index, byte) in bytes[..shown].iter().enumerate() {
        if index != 0 {
            text.push(':');
        }
        text.push_str(&format!("{byte:02x}"));
    }
    if bytes.len() > cap {
        text.push_str(&format!(" +{} more", bytes.len() - cap));
    }
    text
}

/// One decoded option: the summary token plus any detail layer it earned.
struct DecodedOption {
    token: String,
    detail: Option<Layer>,
}

fn decode_option(code: u16, data: &[u8]) -> DecodedOption {
    let token = match option_name(code) {
        Some(name) => format!("{code} ({name})"),
        None => format!("{code}"),
    };
    let detail = match (code, data.len()) {
        (1, _) if data.is_empty() => Some(layer("client identifier", "not decoded (empty)")),
        (1, _) => Some(layer(
            "client identifier",
            format!("DUID {}", hex_bounded(data, MAX_DUID_BYTES)),
        )),
        (2, _) if data.is_empty() => Some(layer("server identifier", "not decoded (empty)")),
        (2, _) => Some(layer(
            "server identifier",
            format!("DUID {}", hex_bounded(data, MAX_DUID_BYTES)),
        )),
        (3, _) if data.len() < 12 => Some(layer(
            "IA_NA",
            format!("malformed, {} byte(s) (IAID/T1/T2 need 12)", data.len()),
        )),
        (3, _) => Some(layer(
            "IA_NA",
            format!(
                "IAID 0x{:08x}, T1 {}s, T2 {}s (sub-options not decoded)",
                be32(data, 0).unwrap_or(0),
                be32(data, 4).unwrap_or(0),
                be32(data, 8).unwrap_or(0)
            ),
        )),
        (4, _) if data.len() < 4 => Some(layer(
            "IA_TA",
            format!("malformed, {} byte(s) (IAID needs 4)", data.len()),
        )),
        (4, _) => Some(layer(
            "IA_TA",
            format!(
                "IAID 0x{:08x} (sub-options not decoded)",
                be32(data, 0).unwrap_or(0)
            ),
        )),
        (5, _) if data.len() < 24 => Some(layer(
            "IAADDR",
            format!(
                "malformed, {} byte(s) (address/lifetimes need 24)",
                data.len()
            ),
        )),
        (5, _) => Some(layer("IAADDR", iaaddr_value(data))),
        (6, _) if data.len() < 2 => Some(layer("option request", "not decoded (empty)")),
        (6, _) => Some(layer("option request", oro_summary(data))),
        (7, 1) => Some(layer("preference", data[0])),
        (7, _) => Some(layer(
            "preference",
            format!("malformed, {} byte(s) (needs 1)", data.len()),
        )),
        (8, 2) => Some(layer(
            "elapsed time",
            format!(
                "{} cs ({} s)",
                be16(data, 0).unwrap_or(0),
                be16(data, 0).unwrap_or(0) as f64 / 100.0
            ),
        )),
        (8, _) => Some(layer(
            "elapsed time",
            format!("malformed, {} byte(s) (needs 2)", data.len()),
        )),
        (13, _) if data.len() < 2 => Some(layer(
            "status code",
            format!("malformed, {} byte(s) (code needs 2)", data.len()),
        )),
        (13, _) => {
            let name = status_name(be16(data, 0).unwrap_or(0));
            let message = std::str::from_utf8(&data[2..])
                .ok()
                .map(|text| {
                    let chars = text.chars().count();
                    if chars > MAX_STATUS_CHARS {
                        format!(" (message exceeds the {MAX_STATUS_CHARS}-character bound)")
                    } else if text.chars().any(|c| c.is_control()) {
                        " (message contains control characters)".to_string()
                    } else {
                        format!(" \"{text}\"")
                    }
                })
                .unwrap_or_else(|| " (message not printable)".to_string());
            Some(layer("status code", format!("{name}{message}")))
        }
        (14, 0) => Some(layer("rapid commit", "present")),
        (23, _) if data.len() % 16 != 0 || data.is_empty() => Some(layer(
            "DNS servers",
            format!(
                "malformed, {} byte(s) (not whole 16-byte addresses)",
                data.len()
            ),
        )),
        (23, _) => {
            let mut listed = Vec::new();
            for index in 0..(data.len() / 16).min(2) {
                let start = index * 16;
                let bytes: [u8; 16] = data[start..start + 16].try_into().unwrap_or([0; 16]);
                listed.push(std::net::Ipv6Addr::from(bytes).to_string());
            }
            let mut value = listed.join(", ");
            if data.len() / 16 > 2 {
                value.push_str(&format!(", +{} more", data.len() / 16 - 2));
            }
            Some(layer("DNS servers", value))
        }
        (24, _) => Some(layer("domain list", domain_list_value(data))),
        _ => None,
    };
    DecodedOption { token, detail }
}

/// IAADDR (RFC 8415 §21.6): 16-byte address, preferred and valid lifetimes,
/// then sub-options that are never decoded here.
fn iaaddr_value(data: &[u8]) -> String {
    let bytes: [u8; 16] = data[..16].try_into().unwrap_or([0; 16]);
    format!(
        "{} (preferred {}s, valid {}s, sub-options not decoded)",
        std::net::Ipv6Addr::from(bytes),
        be32(data, 16).unwrap_or(0),
        be32(data, 20).unwrap_or(0)
    )
}

/// Option Request option (RFC 8415 §21.7): a list of option codes, named
/// for the codes the table knows and raw otherwise.
fn oro_summary(data: &[u8]) -> String {
    let count = data.len() / 2;
    let mut listed = Vec::new();
    for index in 0..count.min(MAX_LISTED_OPTIONS) {
        let code = be16(data, index * 2).unwrap_or(0);
        let token = match option_name(code) {
            Some(name) => format!("{code} ({name})"),
            None => format!("{code}"),
        };
        listed.push(token);
    }
    let mut value = format!(
        "{} requested: {}",
        count,
        if listed.is_empty() {
            "none decodable".to_string()
        } else {
            listed.join(", ")
        }
    );
    if count > MAX_LISTED_OPTIONS {
        value.push_str(&format!(
            ", +{} more (cap {MAX_LISTED_OPTIONS})",
            count - MAX_LISTED_OPTIONS
        ));
    }
    value
}

/// Domain Search List (RFC 3646 §2.2): a sequence of DNS-encoded names,
/// decoded bounded; a malformed label walk degrades to an honest note.
fn domain_list_value(data: &[u8]) -> String {
    let mut names = Vec::new();
    let mut at = 0usize;
    while at < data.len() && names.len() < 3 {
        let mut name = String::new();
        let mut cursor = at;
        let mut walked = false;
        while cursor < data.len() {
            let len = data[cursor] as usize;
            cursor += 1;
            if len == 0 {
                walked = true;
                break;
            }
            let end = match cursor.checked_add(len) {
                Some(end) if end <= data.len() => end,
                _ => return format!("not decoded (malformed labels)"),
            };
            let Ok(label) = std::str::from_utf8(&data[cursor..end]) else {
                return "not decoded (labels are not UTF-8)".to_string();
            };
            if label.chars().any(|c| c.is_control()) || name.len() > 64 {
                return "not decoded (malformed labels)".to_string();
            }
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(label);
            cursor = end;
        }
        if !walked {
            return format!(
                "not decoded (truncated at capture boundary), {} name(s) before the cut",
                names.len()
            );
        }
        if !name.is_empty() {
            names.push(name);
        }
        at = cursor;
    }
    if names.is_empty() {
        "not decoded (no names in the captured bytes)".to_string()
    } else {
        let mut value = names.join(", ");
        if at < data.len() {
            value.push_str(", +more (3 shown)");
        }
        value
    }
}

/// Dissect one UDP datagram payload already matched to ports 546/547.
/// `direction` comes from the port side in the UDP dispatch. Returns None
/// when there is no DHCPv6 evidence so the caller keeps the plain
/// transport row — the port alone is not DHCPv6 evidence.
pub(super) fn dissect(payload: &[u8], direction: Direction) -> Option<Dhcpv6Service> {
    if !(4..=MAX_DATAGRAM).contains(&payload.len()) {
        return None;
    }
    let kind = payload[0];
    let kind_name = message_name(kind)?;
    if (is_client_message(kind) && !matches!(direction, Direction::ClientToServer))
        || (is_server_message(kind) && !matches!(direction, Direction::ServerToClient))
        || (matches!(kind, 12 | 13) && !matches!(direction, Direction::Relay))
    {
        // The direction the ports dictate does not carry this message type.
        return None;
    }
    let direction_value = match direction {
        Direction::ClientToServer => "client → server",
        Direction::ServerToClient => "server → client",
        Direction::Relay => "relay",
    };
    let mut layers = vec![
        layer("DHCPv6 message", kind_name),
        layer(
            "DHCPv6 direction",
            format!("{direction_value} (link-local UDP 546/547)"),
        ),
    ];
    if matches!(kind, 12 | 13) {
        // Relay messages (RFC 8415 §7.5) carry a different header and a
        // nested relayed message; the header is named, the payload is not.
        if payload.len() < RELAY_HEADER {
            return None;
        }
        layers.push(layer("relay hop count", payload[1]));
        let link: [u8; 16] = <[u8; 16]>::try_from(&payload[2..18]).unwrap_or([0; 16]);
        let peer: [u8; 16] = <[u8; 16]>::try_from(&payload[18..34]).unwrap_or([0; 16]);
        layers.push(layer(
            "relay addresses",
            format!(
                "link {}, peer {} (relayed message not decoded)",
                std::net::Ipv6Addr::from(link),
                std::net::Ipv6Addr::from(peer),
            ),
        ));
        return Some(dhcpv6_done(format!("DHCPv6 {kind_name} (relay)"), layers));
    }
    let xid = &payload[1..4];
    let xid_value = format!(
        "0x{:02x}{:02x}{:02x}",
        u32::from(xid[0]),
        u32::from(xid[1]),
        u32::from(xid[2])
    );
    layers.push(layer("DHCPv6 transaction id", xid_value.clone()));
    let mut listed = Vec::new();
    let mut total = 0usize;
    let mut client_id = None;
    let mut server_id = None;
    let mut status = None;
    let mut at = 4usize;
    while at < payload.len() {
        let code = be16(payload, at)?;
        let length = be16(payload, at + 2)? as usize;
        let data = payload.get(at + 4..at.checked_add(4)?.checked_add(length)?)?;
        at = at + 4 + length;
        total += 1;
        if total > MAX_OPTIONS {
            return None;
        }
        match code {
            1 => {
                if client_id.replace(data.to_vec()).is_some() {
                    return None; // duplicate client identifier
                }
            }
            2 => {
                if server_id.replace(data.to_vec()).is_some() {
                    return None; // duplicate server identifier
                }
            }
            13 => {
                if status.replace(be16(payload, at - length)?).is_some() {
                    return None; // duplicate status code
                }
            }
            _ => {}
        }
        let decoded = decode_option(code, data);
        if listed.len() < MAX_LISTED_OPTIONS {
            listed.push(decoded.token);
        }
        if let Some(detail) = decoded.detail {
            layers.push(detail);
        }
    }
    if listed.len() < total {
        layers.push(layer(
            "DHCPv6 options",
            format!(
                "{total} present: {}, +{} more (cap {MAX_LISTED_OPTIONS})",
                listed.join(", "),
                total - listed.len()
            ),
        ));
    } else if total > 0 {
        layers.push(layer(
            "DHCPv6 options",
            format!("{total} present: {}", listed.join(", ")),
        ));
    }
    // RFC 8415 §21.2/§21.3: client messages must carry the client
    // identifier; server messages must carry the server identifier.
    if is_client_message(kind) && client_id.is_none() {
        return None;
    }
    if is_server_message(kind) && server_id.is_none() {
        return None;
    }
    let mut info = format!("DHCPv6 {kind_name} xid={xid_value}");
    if let Some(code) = status {
        info.push_str(&format!(", status {}", status_name(code)));
    }
    Some(dhcpv6_done(info, layers))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn option(code: u16, data: &[u8]) -> Vec<u8> {
        let mut out = code.to_be_bytes().to_vec();
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    fn datagram(kind: u8, xid: &[u8; 3], options: &[Vec<u8>]) -> Vec<u8> {
        let mut out = vec![kind];
        out.extend_from_slice(xid);
        for option in options {
            out.extend_from_slice(option);
        }
        out
    }

    fn solicit() -> Vec<u8> {
        datagram(
            1,
            &[0x01, 0x02, 0x03],
            &[
                option(
                    1,
                    &[
                        0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                    ],
                ),
                option(6, &[0x00, 0x17, 0x00, 0x18]),
                option(8, &[0x00, 0x64]),
                option(14, &[]),
            ],
        )
    }

    fn advertise() -> Vec<u8> {
        datagram(
            2,
            &[0x04, 0x05, 0x06],
            &[
                option(
                    1,
                    &[
                        0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                    ],
                ),
                option(
                    2,
                    &[
                        0x00, 0x02, 0x00, 0x0a, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                    ],
                ),
                option(
                    3,
                    &[
                        0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 30, 0, 0, 0, 60, 0, 5, 0, 24, 0x20, 0x01,
                        0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 120, 0, 0, 1, 44,
                    ],
                ),
                option(
                    5,
                    &[
                        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 120,
                        0, 0, 1, 44,
                    ],
                ),
            ],
        )
    }

    fn reply_with_status(code: u16, message: &str) -> Vec<u8> {
        let mut status_data = code.to_be_bytes().to_vec();
        status_data.extend_from_slice(message.as_bytes());
        datagram(
            7,
            &[0x0a, 0x0b, 0x0c],
            &[
                option(
                    1,
                    &[
                        0x00, 0x01, 0x00, 0x0e, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                    ],
                ),
                option(
                    2,
                    &[
                        0x00, 0x02, 0x00, 0x0a, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                    ],
                ),
                option(13, &status_data),
            ],
        )
    }

    fn relay(kind: u8) -> Vec<u8> {
        let mut out = vec![kind, 2]; // msg-type, hop count
        out.extend([0u8; 16]); // link address (unspecified)
        out.extend([
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x01,
        ]); // peer
        out.extend_from_slice(&option(9, &solicit())); // relay message option
        out
    }

    #[test]
    fn solicit_decodes_transaction_id_and_bounded_options() {
        let service = dissect(&solicit(), Direction::ClientToServer).unwrap();
        assert_eq!(service.protocol, "DHCPv6");
        assert_eq!(service.info, "DHCPv6 SOLICIT xid=0x010203");
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "DHCPv6 transaction id" && l.value == "0x010203"));
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "DHCPv6 direction" && l.value.contains("client → server")));
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "client identifier" && l.value.contains("DUID 00:01:00:0e")));
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "option request" && l.value.contains("23 (DNS servers)")));
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "elapsed time" && l.value.contains("100 cs")));
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "rapid commit" && l.value == "present"));
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "DHCPv6 options" && l.value.starts_with("4 present:")));
    }

    #[test]
    fn advertise_decodes_iana_iaaddr_and_requires_server_id() {
        let service = dissect(&advertise(), Direction::ServerToClient).unwrap();
        assert_eq!(service.info, "DHCPv6 ADVERTISE xid=0x040506");
        assert!(service.layers.iter().any(|l| l.label == "IA_NA"
            && l.value.contains("IAID 0xdeadbeef")
            && l.value.contains("T1 30s")));
        // IA_NA sub-options are named as present, never decoded.
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "IA_NA" && l.value.contains("sub-options not decoded")));
        assert!(service.layers.iter().any(|l| l.label == "IAADDR"
            && l.value.contains("2001:db8::2")
            && l.value.contains("valid 300s")));
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "server identifier" && l.value.contains("DUID 00:02")));

        // A server message without its mandatory server identifier is
        // refused, not guessed (RFC 8415 §21.3).
        let mut missing = advertise();
        // Remove the server-id option (code 2): it starts after the 4-byte
        // header, the client-id option (16 bytes) and a 2+2 prefix.
        let start = 4 + 16;
        let len = usize::from(missing[start + 2]) << 8 | usize::from(missing[start + 3]);
        missing.drain(start..start + 4 + len);
        assert!(dissect(&missing, Direction::ServerToClient).is_none());
    }

    #[test]
    fn reply_names_status_codes_and_messages() {
        let service = dissect(&reply_with_status(0, ""), Direction::ServerToClient).unwrap();
        assert_eq!(service.info, "DHCPv6 REPLY xid=0x0a0b0c, status Success");

        let service = dissect(
            &reply_with_status(2, "no addresses"),
            Direction::ServerToClient,
        )
        .unwrap();
        assert!(
            service.info.contains("status NoAddrsAvail"),
            "{}",
            service.info
        );
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "status code" && l.value.contains("\"no addresses\"")));

        // Undocumented status codes keep the raw value.
        let service = dissect(&reply_with_status(0x99, ""), Direction::ServerToClient).unwrap();
        assert!(service.info.contains("status 0x0099"), "{}", service.info);
    }

    #[test]
    fn direction_gate_refuses_wrong_side_types() {
        // A SOLICIT on the server→client side claims nothing.
        assert!(dissect(&solicit(), Direction::ServerToClient).is_none());
        // An ADVERTISE on the client→server side claims nothing.
        assert!(dissect(&advertise(), Direction::ClientToServer).is_none());
        // A relay message outside 547↔547 claims nothing.
        assert!(dissect(&relay(12), Direction::ClientToServer).is_none());
    }

    #[test]
    fn mandatory_client_id_is_refused_when_missing() {
        // SOLICIT without the client identifier option is not a claimable
        // SOLICIT (RFC 8415 §21.2).
        let bare = datagram(1, &[0x01, 0x02, 0x03], &[option(8, &[0x00, 0x64])]);
        assert!(dissect(&bare, Direction::ClientToServer).is_none());
        // Duplicate client identifier refuses the row too.
        let duplicated = datagram(
            1,
            &[0x01, 0x02, 0x03],
            &[option(1, &[0xaa]), option(1, &[0xbb])],
        );
        assert!(dissect(&duplicated, Direction::ClientToServer).is_none());
    }

    #[test]
    fn relay_messages_are_named_but_never_unwrapped() {
        let service = dissect(&relay(12), Direction::Relay).unwrap();
        assert_eq!(service.protocol, "DHCPv6");
        assert_eq!(service.info, "DHCPv6 RELAY-FORW (relay)");
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "relay hop count" && l.value == "2"));
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "relay addresses" && l.value.contains("not decoded")));
        // RELAY-REPL rides the same 547↔547 path.
        let service = dissect(&relay(13), Direction::Relay).unwrap();
        assert!(service.info.contains("RELAY-REPL"), "{}", service.info);
        // A relay header cut short is refused.
        let short = relay(12)[..20].to_vec();
        assert!(dissect(&short, Direction::Relay).is_none());
    }

    #[test]
    fn option_walk_bounds_and_overruns_refuse() {
        // An option length running past the datagram boundary refuses the
        // row: the walk must end exactly at the datagram end.
        let mut overrun = datagram(1, &[0x01, 0x02, 0x03], &[]);
        overrun.extend_from_slice(&[0x00, 0x01, 0xff, 0xff]);
        overrun.extend_from_slice(&[0xaa; 8]);
        assert!(dissect(&overrun, Direction::ClientToServer).is_none());

        // More than 32 options is malformed, not decoded.
        let mut many = datagram(1, &[0x01, 0x02, 0x03], &[option(1, &[0xaa])]);
        for _ in 0..40 {
            many.extend_from_slice(&option(14, &[]));
        }
        assert!(dissect(&many, Direction::ClientToServer).is_none());

        // The option summary counts the overflow honestly.
        let mut wide = datagram(1, &[0x01, 0x02, 0x03], &[option(1, &[0xaa])]);
        for index in 0..12u16 {
            wide.extend_from_slice(&option(200 + index, &[]));
        }
        let service = dissect(&wide, Direction::ClientToServer).unwrap();
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "DHCPv6 options" && l.value.contains("+5 more (cap 8)")));
    }

    #[test]
    fn truncated_or_malformed_datagrams_keep_the_transport_row() {
        // Bare or short datagrams are refused entirely.
        assert!(dissect(&[], Direction::ClientToServer).is_none());
        assert!(dissect(&[1u8, 0, 0], Direction::ClientToServer).is_none());
        // Unknown message types are refused.
        assert!(dissect(&[0u8, 1, 2, 3], Direction::ClientToServer).is_none());
        assert!(dissect(&[14u8, 1, 2, 3], Direction::ClientToServer).is_none());
        // An option header cut by the datagram end is refused (the UDP
        // payload is the declared datagram, so this is malformed).
        let mut cut = datagram(1, &[0x01, 0x02, 0x03], &[]);
        cut.extend_from_slice(&[0x00, 0x01, 0x00]);
        assert!(dissect(&cut, Direction::ClientToServer).is_none());
        // Random bytes on 546/547 keep the plain transport row.
        assert!(dissect(b"plain udp payload", Direction::ClientToServer).is_none());
    }

    /// Truncations and adversarial byte mutations across every fixture must
    /// either refuse or produce an honest DHCPv6 row — never panic and
    /// never leave the DHCPv6 protocol name off a claimed row.
    #[test]
    fn fuzz_truncations_and_mutations_refuse_or_degrade_honestly() {
        let fixtures: Vec<Vec<u8>> = vec![
            solicit(),
            advertise(),
            reply_with_status(0, "ok"),
            reply_with_status(2, "no addresses"),
            relay(12),
            relay(13),
        ];
        let directions = [
            Direction::ClientToServer,
            Direction::ServerToClient,
            Direction::Relay,
        ];
        let mut checked = 0usize;
        for fixture in &fixtures {
            for cut in 0..fixture.len() {
                for direction in &directions {
                    if let Some(service) = dissect(&fixture[..cut], direction.clone()) {
                        assert_eq!(service.protocol, "DHCPv6", "cut {cut}");
                        assert!(!service.info.is_empty());
                    }
                    checked += 1;
                }
            }
            for position in (0..fixture.len()).step_by(2) {
                for value in [0x00u8, 0x01, 0x80, 0xfe, 0xff] {
                    let mut mutated = fixture.clone();
                    mutated[position] = value;
                    for direction in &directions {
                        if let Some(service) = dissect(&mutated, direction.clone()) {
                            assert_eq!(
                                service.protocol, "DHCPv6",
                                "position {position} value {value:#x}"
                            );
                        }
                    }
                    checked += 1;
                }
            }
        }
        assert!(checked > 2_000, "coverage too small: {checked}");
    }
}
