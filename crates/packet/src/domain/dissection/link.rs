//! Ethernet, Linux cooked capture, raw-IP dispatch, and ARP dissection.
use super::network::{dissect_ipv4, dissect_ipv6};
use crate::{Dissected, Layer};

pub(super) fn mac_to_string(bytes: &[u8]) -> String {
    // One bounded output allocation instead of six formatted strings plus a Vec.
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len().saturating_mul(3).saturating_sub(1));
    for (index, byte) in bytes.iter().enumerate() {
        if index != 0 {
            text.push(':');
        }
        text.push(HEX[usize::from(byte >> 4)] as char);
        text.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    text
}

pub(super) fn ipv4_to_string(bytes: &[u8]) -> String {
    format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3])
}

pub(super) fn color_for(protocol: &str) -> String {
    match protocol {
        "DNS" | "MDNS" | "LLMNR" => "dns",
        "DHCP" | "NTP" | "STUN" => "udp",
        "HTTP" => "http",
        "TLS" | "TLSv1.2" | "TLSv1.3" => "tls",
        "ARP" => "arp",
        "ICMP" => "icmp",
        "UDP" => "udp",
        "IPv6" => "ipv6",
        "TCP" => "tcp",
        _ => "other",
    }
    .to_string()
}

/// Dissect one link-layer frame. Unknown protocols still produce a usable
/// frame row with the raw hex prefix as info.
pub fn dissect(linktype: u32, frame: &[u8]) -> Dissected {
    match linktype {
        1 => dissect_ethernet(frame),
        101 => dissect_raw_ip(frame),    // LINKTYPE_RAW
        113 => dissect_linux_sll(frame), // Linux cooked capture v1: 16-byte header
        _ => Dissected {
            source: String::new(),
            destination: String::new(),
            protocol: "LINK".to_string(),
            info: format!("linktype {linktype} frame, {} bytes", frame.len()),
            color_hint: "other".to_string(),
            layers: vec![Layer {
                label: "Frame".to_string(),
                value: format!("{} bytes", frame.len()),
            }],
            stream_id: None,
            tcp: None,
            payload: Vec::new(),
        },
    }
}

/// Linux cooked capture v1 has a 16-byte header, not an Ethernet header.
fn dissect_linux_sll(frame: &[u8]) -> Dissected {
    if frame.len() < 16 {
        return empty_frame();
    }
    let protocol = u16::from_be_bytes([frame[14], frame[15]]);
    let layer = Layer {
        label: "Linux cooked capture".to_string(),
        value: format!("protocol 0x{protocol:04x}"),
    };
    let mut d = match protocol {
        0x0800 => dissect_ipv4(&frame[16..], &[]),
        0x86dd => dissect_ipv6(&frame[16..], &[]),
        0x0806 => dissect_arp(&frame[16..]),
        _ => {
            let mut d = empty_frame();
            d.protocol = "SLL".to_string();
            d.info = format!("Linux cooked protocol 0x{protocol:04x}");
            d
        }
    };
    d.layers.insert(0, layer);
    d
}

fn dissect_raw_ip(frame: &[u8]) -> Dissected {
    if frame.is_empty() {
        return empty_frame();
    }
    match frame[0] >> 4 {
        4 => dissect_ipv4(frame, &[]),
        6 => dissect_ipv6(frame, &[]),
        _ => empty_frame(),
    }
}

pub(super) fn empty_frame() -> Dissected {
    Dissected {
        source: String::new(),
        destination: String::new(),
        protocol: "MALFORMED".to_string(),
        info: "truncated frame".to_string(),
        color_hint: "other".to_string(),
        layers: vec![Layer {
            label: "Frame".to_string(),
            value: "truncated".to_string(),
        }],
        stream_id: None,
        tcp: None,
        payload: Vec::new(),
    }
}

fn dissect_ethernet(frame: &[u8]) -> Dissected {
    if frame.len() < 14 {
        return empty_frame();
    }
    let dst_mac = mac_to_string(&frame[0..6]);
    let src_mac = mac_to_string(&frame[6..12]);
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let payload = &frame[14..];
    let mut layers = vec![
        Layer {
            label: "Ethernet II".to_string(),
            value: format!("{src_mac} → {dst_mac}"),
        },
        Layer {
            label: "EtherType".to_string(),
            value: format!("0x{ethertype:04x}"),
        },
    ];
    let mut d = match ethertype {
        0x0800 => dissect_ipv4(payload, &layers),
        0x86dd => dissect_ipv6(payload, &layers),
        0x0806 => dissect_arp(payload),
        _ => {
            let mut d = empty_frame();
            d.protocol = "ETH".to_string();
            d.info = format!("ethertype 0x{ethertype:04x}, {} bytes", payload.len());
            d
        }
    };
    // ethernet layers prefix everything from the network layer up
    let mut prefixed = layers;
    prefixed.extend(d.layers.drain(..));
    d.layers = prefixed;
    d
}

fn dissect_arp(payload: &[u8]) -> Dissected {
    if payload.len() < 28 {
        return empty_frame();
    }
    let operation = u16::from_be_bytes([payload[6], payload[7]]);
    let sender_ip = ipv4_to_string(&payload[14..18]);
    let target_ip = ipv4_to_string(&payload[24..28]);
    let info = match operation {
        1 => format!("Who has {target_ip}? Tell {sender_ip}"),
        2 => format!(
            "{sender_ip} is at {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            payload[8], payload[9], payload[10], payload[11], payload[12], payload[13]
        ),
        _ => format!("ARP operation {operation}"),
    };
    Dissected {
        source: sender_ip.clone(),
        destination: target_ip.clone(),
        protocol: "ARP".to_string(),
        info: info.clone(),
        color_hint: color_for("ARP"),
        stream_id: None,
        tcp: None,
        payload: Vec::new(),
        layers: vec![
            Layer {
                label: "Address Resolution Protocol".to_string(),
                value: info,
            },
            Layer {
                label: "sender IP".to_string(),
                value: sender_ip,
            },
            Layer {
                label: "target IP".to_string(),
                value: target_ip,
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::mac_to_string;

    #[test]
    fn ethernet_mac_formatting_retains_lowercase_and_leading_zeros() {
        assert_eq!(
            mac_to_string(&[0, 0x0a, 0x10, 0xff, 0x80, 0x01]),
            "00:0a:10:ff:80:01"
        );
        assert_eq!(mac_to_string(&[]), "");
    }
}
