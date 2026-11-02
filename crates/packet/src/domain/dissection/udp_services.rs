//! Passive, bounded DHCPv4, NTP and STUN dissectors. No network operations.
//! Every derived claim requires a complete, structurally valid datagram.
//! Original packet bytes and evidence remain untouched.
use crate::Layer;
use std::net::{Ipv4Addr, Ipv6Addr};

pub(super) struct UdpService {
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
fn be16(bytes: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(bytes.get(..2)?.try_into().ok()?))
}
fn be32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?))
}
fn ip4(bytes: &[u8]) -> Option<Ipv4Addr> {
    Some(Ipv4Addr::from(<[u8; 4]>::try_from(bytes.get(..4)?).ok()?))
}
fn hex6(bytes: &[u8]) -> String {
    let mut s = String::new();
    for (i, b) in bytes.iter().take(6).enumerate() {
        if i != 0 {
            s.push(':');
        }
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}
fn dhcp_message_name(kind: u8) -> Option<&'static str> {
    Some(match kind {
        1 => "Discover",
        2 => "Offer",
        3 => "Request",
        4 => "Decline",
        5 => "ACK",
        6 => "NAK",
        7 => "Release",
        8 => "Inform",
        _ => return None,
    })
}
/// Parse DHCP with only Ethernet hardware addresses. BOOTP without the magic
/// cookie is intentionally not promoted to DHCP. Options are TLV-validated,
/// including an END marker and non-data padding.
pub(super) fn dhcp(payload: &[u8]) -> Option<UdpService> {
    if !(240..=1500).contains(&payload.len())
        || !matches!(payload[0], 1 | 2)
        || payload[1] != 1
        || payload[2] != 6
        || payload[236..240] != [99, 130, 83, 99]
    {
        return None;
    }
    let xid = be32(payload.get(4..8)?)?;
    let client = hex6(payload.get(28..34)?);
    let assigned = ip4(payload.get(16..20)?)?;
    let mut message = None;
    let mut server = None;
    let mut router = None;
    let mut dns = None;
    let mut lease = None;
    let mut at = 240usize;
    let mut options = 0usize;
    let mut ended = false;
    while at < payload.len() {
        let kind = payload[at];
        at += 1;
        if kind == 255 {
            ended = true;
            break;
        }
        if kind == 0 {
            continue;
        }
        options += 1;
        if options > 128 {
            return None;
        }
        let size = *payload.get(at)? as usize;
        at += 1;
        let end = at.checked_add(size)?;
        let data = payload.get(at..end)?;
        at = end;
        match kind {
            53 if size == 1 => {
                let m = dhcp_message_name(data[0])?;
                if message.replace(m).is_some() {
                    return None;
                }
            }
            54 if size == 4 => {
                if server.replace(ip4(data)?).is_some() {
                    return None;
                }
            }
            3 if size >= 4 && size % 4 == 0 => {
                router = Some(ip4(data)?);
            }
            6 if size >= 4 && size % 4 == 0 => {
                dns = Some(ip4(data)?);
            }
            51 if size == 4 => {
                lease = Some(be32(data)?);
            }
            53 | 54 | 3 | 6 | 51 => return None,
            _ => {}
        }
    }
    if !ended || payload[at..].iter().any(|b| *b != 0) {
        return None;
    }
    let kind = message?;
    let info = format!("DHCP {kind} xid=0x{xid:08x} client={client}");
    let mut layers = vec![
        layer("DHCP message", kind),
        layer("DHCP transaction ID", format!("0x{xid:08x}")),
        layer("DHCP client MAC", client),
    ];
    if !assigned.is_unspecified() {
        layers.push(layer("DHCP offered IPv4", assigned));
    }
    if let Some(s) = server {
        layers.push(layer("DHCP server identifier", s));
    }
    if let Some(r) = router {
        layers.push(layer("DHCP gateway claim", r));
    }
    if let Some(d) = dns {
        layers.push(layer("DHCP DNS server claim", d));
    }
    if let Some(seconds) = lease {
        layers.push(layer("DHCP lease seconds", seconds));
    }
    Some(UdpService {
        protocol: "DHCP",
        info,
        layers,
    })
}
/// NTP header only, no clock update or trust decision. Extension fields and
/// authentication data are not parsed or used to certify timestamps.
pub(super) fn ntp(payload: &[u8]) -> Option<UdpService> {
    if payload.len() < 48 || payload.len() > 1232 {
        return None;
    }
    let leap = payload[0] >> 6;
    let version = (payload[0] >> 3) & 7;
    let mode = payload[0] & 7;
    if !(3..=4).contains(&version) || !(1..=7).contains(&mode) {
        return None;
    }
    let mode_name = match mode {
        1 => "symmetric-active",
        2 => "symmetric-passive",
        3 => "client",
        4 => "server",
        5 => "broadcast",
        6 => "control",
        7 => "private",
        _ => return None,
    };
    let stratum = payload[1];
    let tx_seconds = be32(payload.get(40..44)?)?;
    let tx_fraction = be32(payload.get(44..48)?)?;
    let info = format!("NTPv{version} {mode_name} stratum={stratum}");
    Some(UdpService {
        protocol: "NTP",
        info,
        layers: vec![
            layer("NTP version", version),
            layer("NTP mode", mode_name),
            layer("NTP leap indicator", leap),
            layer("NTP stratum", stratum),
            layer(
                "NTP transmit timestamp (unverified)",
                format!("{tx_seconds:08x}.{tx_fraction:08x}"),
            ),
        ],
    })
}
/// STUN RFC5389 Binding messages, transaction bytes and optional XOR-mapped
/// address. The endpoint is explicitly a server-supplied, unverified claim.
pub(super) fn stun(payload: &[u8]) -> Option<UdpService> {
    if payload.len() < 20
        || payload.len() > 1232
        || payload[0] & 0xc0 != 0
        || payload[4..8] != [0x21, 0x12, 0xa4, 0x42]
    {
        return None;
    }
    let kind = be16(payload)?;
    let label = match kind {
        1 => "Binding Request",
        0x101 => "Binding Success",
        0x111 => "Binding Error",
        _ => return None,
    };
    let len = be16(payload.get(2..4)?)? as usize;
    if len % 4 != 0 || len + 20 != payload.len() {
        return None;
    }
    let nonce = &payload[8..20];
    let nonce_string = nonce.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let mut layers = vec![
        layer("STUN message", label),
        layer("STUN transaction ID", &nonce_string),
    ];
    let mut offset = 20usize;
    let mut seen_mapped = false;
    for _ in 0..128 {
        if offset == payload.len() {
            break;
        }
        let header = payload.get(offset..offset.checked_add(4)?)?;
        let attribute = be16(header)?;
        let size = be16(header.get(2..4)?)? as usize;
        let body = payload.get(offset + 4..offset.checked_add(4)?.checked_add(size)?)?;
        let padded = size.checked_add(3)? & !3usize;
        offset = offset.checked_add(4)?.checked_add(padded)?;
        if offset > payload.len() {
            return None;
        }
        if attribute == 0x0020 {
            if seen_mapped || size < 8 || body[0] != 0 {
                return None;
            }
            seen_mapped = true;
            let port = be16(body.get(2..4)?)? ^ 0x2112;
            if port == 0 {
                return None;
            }
            let endpoint = match (body[1], size) {
                (1, 8) => {
                    let mut addr = [0; 4];
                    for i in 0..4 {
                        addr[i] = body[i + 4] ^ [0x21, 0x12, 0xa4, 0x42][i];
                    }
                    let parsed = Ipv4Addr::from(addr);
                    if parsed.is_multicast() || parsed.is_unspecified() {
                        return None;
                    }
                    format!("{parsed}:{port}")
                }
                (2, 20) => {
                    let mut addr = [0; 16];
                    for i in 0..16 {
                        addr[i] = body[i + 4]
                            ^ if i < 4 {
                                [0x21, 0x12, 0xa4, 0x42][i]
                            } else {
                                nonce[i - 4]
                            };
                    }
                    let parsed = Ipv6Addr::from(addr);
                    if parsed.is_multicast() || parsed.is_unspecified() {
                        return None;
                    }
                    format!("[{parsed}]:{port}")
                }
                _ => return None,
            };
            layers.push(layer("STUN XOR-MAPPED-ADDRESS (unverified)", endpoint));
        }
    }
    if offset != payload.len() {
        return None;
    }
    Some(UdpService {
        protocol: "STUN",
        info: format!("STUN {label} transaction={nonce_string}"),
        layers,
    })
}

/// Multicast DNS (5353) and Link-Local Multicast Name Resolution (5355)
/// share DNS wire framing but have distinct discovery semantics. Decode only
/// complete bounded questions/answers, not arbitrary traffic on those ports.
fn multicast_names(payload: &[u8], llmnr: bool) -> Option<UdpService> {
    if payload.len() < 17 || payload.len() > 4096 {
        return None;
    }
    let flags = be16(payload.get(2..4)?)?;
    // Standard opcode, no "truncated" claim, and at least a valid question
    // or decoded answer. The DNS decoder enforces name compression bounds.
    if flags & 0x7800 != 0 || flags & 0x0200 != 0 {
        return None;
    }
    let report = crate::dns::parse_dns(payload)?;
    if report.questions == 0 && report.answers == 0 {
        return None;
    }
    // Never mistake a non-DNS payload with a plausible header for LLMNR or
    // mDNS without a complete, parsed question/answer.
    if report.first_question.is_none() && report.answer_records.is_empty() {
        return None;
    }
    let protocol = if llmnr { "LLMNR" } else { "MDNS" };
    let context = if llmnr {
        "Link-local name resolution"
    } else {
        "Multicast DNS"
    };
    let action = if report.is_response {
        "response"
    } else {
        "query"
    };
    let mut layers = vec![layer(
        context,
        format!(
            "{action}, id=0x{:04x}, {} answer(s)",
            report.transaction_id, report.answers
        ),
    )];
    if let Some(question) = &report.first_question {
        layers.push(layer(
            "Name resolution question",
            format!(
                "{} {}",
                question.name,
                crate::dns::record_type_label(question.record_type)
            ),
        ));
    }
    for (i, answer) in report.answer_records.iter().enumerate() {
        layers.push(layer(
            &format!("{protocol} answer {}", i + 1),
            format!(
                "{} {} = {} (TTL {}s)",
                answer.name,
                crate::dns::record_type_label(answer.record_type),
                answer.value,
                answer.ttl_seconds
            ),
        ));
    }
    if report.answers_limited {
        layers.push(layer(
            "Name resolution limit",
            "Only the first 16 answers decoded",
        ));
    }
    Some(UdpService {
        protocol,
        info: format!(
            "{protocol} {action} {} question(s), {} answer(s)",
            report.questions, report.answers
        ),
        layers,
    })
}
pub(super) fn mdns(payload: &[u8]) -> Option<UdpService> {
    multicast_names(payload, false)
}
pub(super) fn llmnr(payload: &[u8]) -> Option<UdpService> {
    multicast_names(payload, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn dhcp_packet() -> Vec<u8> {
        let mut b = vec![0u8; 240];
        b[0] = 2;
        b[1] = 1;
        b[2] = 6;
        b[4..8].copy_from_slice(&0x124578acu32.to_be_bytes());
        b[16..20].copy_from_slice(&[192, 0, 2, 11]);
        b[28..34].copy_from_slice(&[2, 0, 0, 1, 2, 3]);
        b[236..240].copy_from_slice(&[99, 130, 83, 99]);
        b.extend([53, 1, 5, 54, 4, 192, 0, 2, 1, 51, 4, 0, 0, 0, 60, 255]);
        b
    }
    #[test]
    fn mdns_and_llmnr_decode_complete_questions_and_reject_corrupt_labels() {
        let mut query = vec![0u8; 12];
        query[4..6].copy_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(b"\x04host\x05local\x00\x00\x01\x00\x01");
        let dns = mdns(&query).unwrap();
        assert_eq!(dns.protocol, "MDNS");
        assert!(dns.layers.iter().any(|x| x.value.contains("host.local")));
        let mut llmnr_query = query.clone();
        llmnr_query[0..2].copy_from_slice(&0x3210u16.to_be_bytes());
        let resolved = llmnr(&llmnr_query).unwrap();
        assert_eq!(resolved.protocol, "LLMNR");
        assert!(resolved.layers[0].value.contains("3210"));
        let mut truncated = query.clone();
        truncated.pop();
        assert!(mdns(&truncated).is_none());
        let mut cyclic = query.clone();
        cyclic[12] = 0xc0;
        cyclic[13] = 12;
        assert!(llmnr(&cyclic).is_none());
        let mut other = query.clone();
        other[2] = 0x02;
        assert!(mdns(&other).is_none());
        let mut other = query.clone();
        other[2] = 0x18;
        assert!(llmnr(&other).is_none());
        assert!(mdns(&query[..12]).is_none());
    }
    #[test]
    fn dhcp_options_are_bounded_and_never_accepted_when_incomplete() {
        let p = dhcp_packet();
        let decoded = dhcp(&p).unwrap();
        assert!(decoded.info.contains("ACK"));
        assert!(decoded.layers.iter().any(|x| x.value == "192.0.2.1"));
        let mut b = p.clone();
        b[239] = 0;
        assert!(dhcp(&b).is_none());
        let mut b = p.clone();
        b.pop();
        assert!(dhcp(&b).is_none());
        let mut b = p.clone();
        b[242] = 9;
        assert!(dhcp(&b).is_none());
        let mut b = p.clone();
        b.extend([53, 1, 2]);
        assert!(dhcp(&b).is_none());
        let mut b = p.clone();
        b[0] = 3;
        assert!(dhcp(&b).is_none());
        assert!(dhcp(&p[..239]).is_none());
    }
    #[test]
    fn ntp_header_requires_complete_valid_version_and_mode() {
        let mut p = [0u8; 48];
        p[0] = (4 << 3) | 4;
        p[1] = 2;
        p[40..44].copy_from_slice(&0x01020304u32.to_be_bytes());
        assert!(ntp(&p).unwrap().info.contains("server"));
        assert!(ntp(&p[..47]).is_none());
        p[0] = 0;
        assert!(ntp(&p).is_none());
        p[0] = (7 << 3) | 4;
        assert!(ntp(&p).is_none());
    }
    #[test]
    fn stun_transaction_and_xor_mapping_are_cautious() {
        let mut p = vec![0u8; 32];
        p[..2].copy_from_slice(&0x0101u16.to_be_bytes());
        p[2..4].copy_from_slice(&12u16.to_be_bytes());
        p[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        p[8..20].copy_from_slice(&[1; 12]);
        p[20..24].copy_from_slice(&[0, 0x20, 0, 8]);
        p[25] = 1;
        p[26..28].copy_from_slice(&(5555u16 ^ 0x2112).to_be_bytes());
        for (i, b) in [192u8, 0, 2, 11].iter().enumerate() {
            p[28 + i] = *b ^ [0x21, 0x12, 0xa4, 0x42][i];
        }
        let d = stun(&p).unwrap();
        assert_eq!(d.protocol, "STUN");
        assert!(d.layers.iter().any(|l| l.value == "192.0.2.11:5555"));
        let mut bad = p.clone();
        bad[6] ^= 1;
        assert!(stun(&bad).is_none());
        let mut bad = p.clone();
        bad[3] = 16;
        assert!(stun(&bad).is_none());
        let mut bad = p.clone();
        bad[25] = 3;
        assert!(stun(&bad).is_none());
        assert!(stun(&p[..31]).is_none());
    }
}
