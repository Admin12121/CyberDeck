//! Bounded ICMPv4 and ICMPv6 dissection.
//!
//! Type/code names and fixed header fields only, plus the Neighbor
//! Discovery link-layer address option that ARP-equivalent workflows need.
//! Echo payload bytes are counted, never decoded.

use crate::{Dissected, Layer};

fn color_for(protocol: &str) -> String {
    super::link::color_for(protocol)
}

/// ICMPv4 type numbers carry names worth showing; codes only for types
/// whose codes have distinct operational meanings.
fn icmpv4_type_name(type_number: u8) -> Option<&'static str> {
    Some(match type_number {
        0 => "Echo Reply",
        3 => "Destination Unreachable",
        4 => "Source Quench (deprecated)",
        5 => "Redirect",
        8 => "Echo Request",
        9 => "Router Advertisement",
        10 => "Router Solicitation",
        11 => "Time Exceeded",
        12 => "Parameter Problem",
        13 => "Timestamp Request",
        14 => "Timestamp Reply",
        _ => return None,
    })
}

fn icmpv4_code_name(type_number: u8, code: u8) -> Option<&'static str> {
    Some(match (type_number, code) {
        (3, 0) => "Network unreachable",
        (3, 1) => "Host unreachable",
        (3, 2) => "Protocol unreachable",
        (3, 3) => "Port unreachable",
        (3, 4) => "Fragmentation needed and DF set",
        (3, 5) => "Source route failed",
        (3, 13) => "Communication administratively prohibited",
        (11, 0) => "TTL expired in transit",
        (11, 1) => "Fragment reassembly time exceeded",
        (5, 1) => "Redirect for host",
        _ => return None,
    })
}

fn icmpv6_type_name(type_number: u8) -> Option<&'static str> {
    Some(match type_number {
        1 => "Destination Unreachable",
        2 => "Packet Too Big",
        3 => "Time Exceeded",
        4 => "Parameter Problem",
        128 => "Echo Request",
        129 => "Echo Reply",
        133 => "Router Solicitation",
        134 => "Router Advertisement",
        135 => "Neighbor Solicitation",
        136 => "Neighbor Advertisement",
        _ => return None,
    })
}

fn icmpv6_code_name(type_number: u8, code: u8) -> Option<&'static str> {
    Some(match (type_number, code) {
        (1, 0) => "No route to destination",
        (1, 1) => "Communication with destination administratively prohibited",
        (1, 3) => "Address unreachable",
        (1, 4) => "Port unreachable",
        (3, 0) => "Hop limit exceeded in transit",
        (3, 1) => "Fragment reassembly time exceeded",
        (4, 0) => "Erroneous header field",
        (4, 1) => "Unrecognized next header type",
        _ => return None,
    })
}

/// Neighbor Discovery options: bounded single-option walk for the link-layer
/// address entries that make ARP-equivalent host tables possible.
/// Option 1 = Source Link-Layer Address, Option 2 = Target Link-Layer Address.
fn nd_option_label(option_type: u8) -> Option<&'static str> {
    match option_type {
        1 => Some("Source Link-Layer Address"),
        2 => Some("Target Link-Layer Address"),
        _ => None,
    }
}

fn mac_to_string(bytes: &[u8]) -> String {
    super::link::mac_to_string(bytes)
}

pub(super) fn dissect_icmpv4(transport: &[u8], layers: Vec<Layer>) -> Dissected {
    if transport.is_empty() {
        return empty_icmp(&layers, "ICMP");
    }
    let type_number = transport[0];
    let code = transport.get(1).copied().unwrap_or(0);
    let type_name = icmpv4_type_name(type_number);
    let code_name = icmpv4_code_name(type_number, code);
    let description = match (type_name, code_name) {
        (Some(t), Some(c)) => format!("{t} ({c})"),
        (Some(t), None) => format!("{t} (code {code})"),
        (None, _) => format!("ICMP type={type_number} code={code}"),
    };
    let mut out_layers = layers;
    out_layers.push(Layer {
        label: "Internet Control Message Protocol".into(),
        value: description.clone(),
    });
    out_layers.push(Layer {
        label: "type".into(),
        value: type_number.to_string(),
    });
    out_layers.push(Layer {
        label: "code".into(),
        value: code.to_string(),
    });
    // Echo request/reply carry identifier and sequence in the fixed header.
    if (type_number == 0 || type_number == 8) && transport.len() >= 8 {
        let identifier = u16::from_be_bytes([transport[4], transport[5]]);
        let sequence = u16::from_be_bytes([transport[6], transport[7]]);
        out_layers.push(Layer {
            label: "identifier".into(),
            value: format!("0x{identifier:04x}"),
        });
        out_layers.push(Layer {
            label: "sequence".into(),
            value: sequence.to_string(),
        });
        out_layers.push(Layer {
            label: "echo payload".into(),
            value: format!("{} byte(s), not decoded", transport.len().saturating_sub(8)),
        });
    }
    // Dest-unreachable bodies quote the original IP header; only the byte
    // count is reported, the quoted datagram is not re-dissected.
    if type_number == 3 && transport.len() > 8 {
        out_layers.push(Layer {
            label: "quoted datagram".into(),
            value: format!("{} byte(s) of the original packet follow the header", transport.len() - 8),
        });
    }
    let info = format!("ICMP {description}");
    Dissected {
        source: String::new(),
        destination: String::new(),
        protocol: "ICMP".into(),
        info,
        color_hint: color_for("ICMP"),
        layers: out_layers,
        stream_id: None,
        tcp: None,
        payload: transport.to_vec(),
    }
}

fn empty_icmp(layers: &[Layer], protocol: &str) -> Dissected {
    Dissected {
        source: String::new(),
        destination: String::new(),
        protocol: protocol.into(),
        info: "truncated ICMP header".into(),
        color_hint: color_for("ICMP"),
        layers: layers.to_vec(),
        stream_id: None,
        tcp: None,
        payload: Vec::new(),
    }
}

/// ICMPv6 needs at minimum the 4-byte type/code/checksum header; Neighbor
/// Discovery messages carry a 16-byte target address after that. The
/// containing IPv6 header supplies source/destination at the call site.
pub(super) fn dissect_icmpv6(transport: &[u8], layers: Vec<Layer>) -> Dissected {
    if transport.len() < 4 {
        return empty_icmp(&layers, "ICMPv6");
    }
    let type_number = transport[0];
    let code = transport[1];
    let type_name = icmpv6_type_name(type_number);
    let code_name = icmpv6_code_name(type_number, code);
    let description = match (type_name, code_name) {
        (Some(t), Some(c)) => format!("{t} ({c})"),
        (Some(t), None) => format!("{t} (code {code})"),
        (None, _) => format!("ICMPv6 type={type_number} code={code}"),
    };
    let mut out_layers = layers;
    out_layers.push(Layer {
        label: "Internet Control Message Protocol v6".into(),
        value: description.clone(),
    });
    out_layers.push(Layer {
        label: "type".into(),
        value: type_number.to_string(),
    });
    out_layers.push(Layer {
        label: "code".into(),
        value: code.to_string(),
    });
    // Echo request/reply: identifier + sequence after the 4-byte header.
    if (type_number == 128 || type_number == 129) && transport.len() >= 8 {
        let identifier = u16::from_be_bytes([transport[4], transport[5]]);
        let sequence = u16::from_be_bytes([transport[6], transport[7]]);
        out_layers.push(Layer {
            label: "identifier".into(),
            value: format!("0x{identifier:04x}"),
        });
        out_layers.push(Layer {
            label: "sequence".into(),
            value: sequence.to_string(),
        });
    }
    // Neighbor Solicitation (135) and Advertisement (136) expose the target
    // address; the advertisement adds R/S/O flags. Options follow.
    if (type_number == 135 || type_number == 136) && transport.len() >= 24 {
        let target = format_ipv6(&transport[8..24]);
        out_layers.push(Layer {
            label: "target address".into(),
            value: target.clone(),
        });
        if type_number == 136 {
            let flags = transport[4];
            out_layers.push(Layer {
                label: "advertisement flags".into(),
                value: format!(
                    "router={} solicited={} override={}",
                    flags & 0x80 != 0,
                    flags & 0x40 != 0,
                    flags & 0x20 != 0
                ),
            });
        }
        for option in nd_options(&transport[24..], 4) {
            out_layers.push(option);
        }
    }
    // Router Advertisement (134): current hop limit, router lifetime, then
    // options (bounded to the first four, prefix information is byte-counted).
    if type_number == 134 && transport.len() >= 16 {
        out_layers.push(Layer {
            label: "current hop limit".into(),
            value: transport[4].to_string(),
        });
        let lifetime = u16::from_be_bytes([transport[6], transport[7]]);
        out_layers.push(Layer {
            label: "router lifetime".into(),
            value: format!("{lifetime} s"),
        });
        for option in nd_options(&transport[16..], 4) {
            out_layers.push(option);
        }
    }
    let info = format!("ICMPv6 {description}");
    Dissected {
        source: String::new(),
        destination: String::new(),
        protocol: "ICMPv6".into(),
        info,
        color_hint: color_for("ICMP"),
        layers: out_layers,
        stream_id: None,
        tcp: None,
        payload: transport.to_vec(),
    }
}

/// Bounded option walk: at most `max` options, each length-validated against
/// the remaining bytes. Per RFC 4861 the option length field counts 8-octet
/// units. A malformed length stops the walk without discarding the layers
/// already decoded.
fn nd_options(bytes: &[u8], max: usize) -> Vec<Layer> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    for _ in 0..max {
        if cursor + 2 > bytes.len() {
            break;
        }
        let option_type = bytes[cursor];
        let total = bytes[cursor + 1] as usize * 8;
        if total < 8 || cursor + total > bytes.len() {
            out.push(Layer {
                label: "ND option warning".into(),
                value: format!(
                    "option type {option_type} claims {} byte(s), truncated",
                    bytes[cursor + 1]
                ),
            });
            break;
        }
        if let Some(label) = nd_option_label(option_type) {
            // Link-layer address options: 2-byte header, then the address
            // bytes (6 for Ethernet-sized options).
            out.push(Layer {
                label: label.into(),
                value: mac_to_string(&bytes[cursor + 2..cursor + total]),
            });
        }
        cursor += total;
    }
    out
}

fn format_ipv6(bytes: &[u8]) -> String {
    match <[u8; 16]>::try_from(bytes) {
        Ok(addr) => std::net::Ipv6Addr::from(addr).to_string(),
        Err(_) => String::new(),
    }
}
