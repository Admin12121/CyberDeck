//! Bettercap-mode lab event engine: derives a bounded, chronological event
//! timeline from captured packets — new hosts, new services, ARP conflicts
//! and gateway identity changes. Pure and deterministic: the same capture
//! always produces the same timeline. This is passive observation only; the
//! module never transmits, injects or alters anything.

use crate::arp_watch;
use crate::PacketMeta;
use serde::Serialize;

/// Hard bounds: a long capture cannot inflate the timeline or host table.
pub const MAX_EVENTS: usize = 512;
pub const MAX_TRACKED_HOSTS: usize = 4096;
/// ARP observations retained for conflict/gateway correlation.
pub const MAX_ARP_OBSERVATIONS: usize = 4096;

/// Event kinds in the lab timeline. `detail` carries the human-readable
/// evidence line; timestamps are absolute epoch milliseconds when the
/// capture has wall-clock provenance (else 0 and the UI renders "unknown").
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LabEvent {
    pub timestamp_ms: u64,
    pub kind: LabEventKind,
    pub subject: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LabEventKind {
    NewHost,
    NewService,
    ArpConflict,
    GatewayChanged,
}

/// Mutable correlation state across the packet walk.
#[derive(Default)]
struct LabState {
    /// ip -> first MAC seen (host identity for NewHost/changes).
    host_mac: std::collections::HashMap<String, String>,
    /// ip -> service identity set ("443/tcp"), tracked per host.
    host_services: std::collections::HashMap<String, std::collections::BTreeSet<String>>,
    /// ip -> MAC claims for conflict detection (mirrors arp_watch semantics).
    mac_claims: std::collections::HashMap<String, std::collections::BTreeMap<String, u64>>,
    gateway_mac: Option<String>,
    arp_observations: Vec<arp_watch::ArpObservation>,
    /// IPs whose conflict event already fired: one event per IP, not per
    /// repeat claim — a long capture must not spam the timeline.
    conflict_fired: std::collections::HashSet<String>,
}

fn mac_from_layers(layers: &[crate::Layer]) -> Option<String> {
    // The Ethernet II layer value is "src → dst"; the sender MAC is src.
    let value = layers
        .iter()
        .find(|l| l.label == "Ethernet II")
        .map(|l| l.value.as_str())?;
    let src = value.split(" → ").next()?;
    // A MAC-looking token: six hex groups. Anything else is not an address.
    let groups: Vec<&str> = src.split(':').collect();
    if groups.len() == 6 && groups.iter().all(|g| g.len() == 2 && g.chars().all(|c| c.is_ascii_hexdigit())) {
        Some(src.to_ascii_lowercase())
    } else {
        None
    }
}

fn service_from(layers: &[crate::Layer], protocol: &str) -> Option<String> {
    // Transport port layers exist for TCP and UDP; the display protocol gives
    // the application identity where the dissector recognized one.
    let port = layers
        .iter()
        .find(|l| l.label == "destination port")
        .and_then(|l| l.value.parse::<u16>().ok())?;
    let proto = if protocol == "TCP" || protocol == "UDP" {
        protocol.to_ascii_lowercase()
    } else {
        // HTTP/TLS/DNS etc. ride on TCP; UDP services keep their protocol.
        "tcp".to_string()
    };
    Some(format!("{port}/{proto}"))
}

/// Derive the lab event timeline for one capture, oldest first. `router_ip`
/// (when the operator provides the gateway) enables gateway-identity
/// monitoring: a MAC change behind the same gateway IP is the strongest
/// passive MITM indicator the lab can raise.
pub fn derive_events(packets: &[PacketMeta], router_ip: Option<&str>) -> Vec<LabEvent> {
    let mut state = LabState::default();
    let mut events: Vec<LabEvent> = Vec::new();
    let router = router_ip.map(|s| s.trim().to_string());

    for packet in packets {
        if events.len() >= MAX_EVENTS && state.arp_observations.len() >= MAX_ARP_OBSERVATIONS {
            break;
        }
        let d = &packet.dissected;
        let ts = u64::from(packet.ts_sec).saturating_mul(1000)
            + u64::from(packet.ts_subsec / 1_000); // ns-normalized subseconds
        let mac = mac_from_layers(&d.layers);

        // ARP frames: host identity + conflict + gateway correlation.
        if d.protocol == "ARP" {
            if let (Some(sender_ip), Some(sender_mac)) = (
                d.layers
                    .iter()
                    .find(|l| l.label == "sender IP")
                    .map(|l| l.value.clone()),
                mac_from_layers(&d.layers),
            ) {
                if state.arp_observations.len() < MAX_ARP_OBSERVATIONS {
                    state.arp_observations.push(arp_watch::ArpObservation {
                        sender_ip: sender_ip.clone(),
                        sender_mac: sender_mac.clone(),
                        // Claims drive conflict detection; the reply/request
                        // distinction lives in the info line, not here.
                        operation: arp_watch::ArpOperation::Reply,
                        is_gratuitous: false,
                        timestamp_ms: ts,
                    });
                }
                let claims = state.mac_claims.entry(sender_ip.clone()).or_default();
                *claims.entry(sender_mac.clone()).or_insert(0) += 1;
                if claims.len() >= 2
                    && !state.conflict_fired.contains(&sender_ip)
                    && events.len() < MAX_EVENTS
                {
                    state.conflict_fired.insert(sender_ip.clone());
                    let macs: Vec<String> = claims.keys().cloned().collect();
                    events.push(LabEvent {
                        timestamp_ms: ts,
                        kind: LabEventKind::ArpConflict,
                        subject: sender_ip.clone(),
                        detail: format!(
                            "IP {} claimed by {} MACs ({})",
                            sender_ip,
                            claims.len(),
                            macs.join(", ")
                        ),
                    });
                }
                if let Some(router) = &router {
                    if &sender_ip == router {
                        match &state.gateway_mac {
                            None => {
                                state.gateway_mac = Some(sender_mac.clone());
                                if events.len() < MAX_EVENTS {
                                    events.push(LabEvent {
                                        timestamp_ms: ts,
                                        kind: LabEventKind::NewHost,
                                        subject: sender_ip.clone(),
                                        detail: format!(
                                            "gateway {router} first seen at {sender_mac}"
                                        ),
                                    });
                                }
                            }
                            Some(previous) if previous != &sender_mac && events.len() < MAX_EVENTS => {
                                events.push(LabEvent {
                                    timestamp_ms: ts,
                                    kind: LabEventKind::GatewayChanged,
                                    subject: sender_ip.clone(),
                                    detail: format!(
                                        "gateway {router} MAC changed {previous} → {sender_mac}"
                                    ),
                                });
                                state.gateway_mac = Some(sender_mac.clone());
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        // IP endpoints: host discovery + service inventory.
        for endpoint in [d.source.as_str(), d.destination.as_str()] {
            // Only parseable IP addresses become hosts; MAC-shaped tokens
            // (six hex groups) and hostnames never pass the IP parse.
            if endpoint.parse::<std::net::IpAddr>().is_err() {
                continue;
            }
            if !state.host_mac.contains_key(endpoint) && state.host_mac.len() < MAX_TRACKED_HOSTS {
                state.host_mac.insert(endpoint.to_string(), mac.clone().unwrap_or_default());
                if events.len() < MAX_EVENTS {
                    events.push(LabEvent {
                        timestamp_ms: ts,
                        kind: LabEventKind::NewHost,
                        subject: endpoint.to_string(),
                        detail: match &mac {
                            Some(mac) => format!("host {endpoint} first seen at {mac}"),
                            None => format!("host {endpoint} first seen (no link-layer address)"),
                        },
                    });
                }
            }
        }

        // Services: first sighting of each (host, port/proto) pair.
        if let Some(service) = service_from(&d.layers, &d.protocol) {
            let entry = state.host_services.entry(d.destination.clone()).or_default();
            if !entry.contains(&service) && events.len() < MAX_EVENTS {
                entry.insert(service.clone());
                // Skip the very first packet pair noise: a service event is
                // only raised once per (host, service) across the capture.
                events.push(LabEvent {
                    timestamp_ms: ts,
                    kind: LabEventKind::NewService,
                    subject: d.destination.clone(),
                    detail: format!("service {service} observed on {}", d.destination),
                });
            }
        }
    }

    // ARP findings from the dedicated analyzer are authoritative for
    // impersonation/gateway impersonation wording; merge any finding kinds
    // the quick walk above cannot name (gateway impersonation vs conflict).
    if let Some(router) = &router {
        let findings = arp_watch::analyze_arp(&state.arp_observations, Some(router));
        for finding in findings.iter().take(MAX_EVENTS.saturating_sub(events.len())) {
            if finding.kind == arp_watch::ArpFindingKind::GatewayImpersonation
                && !events.iter().any(|e| {
                    e.kind == LabEventKind::GatewayChanged && e.subject == finding.ip
                })
            {
                events.push(LabEvent {
                    timestamp_ms: finding.last_seen_ms,
                    kind: LabEventKind::GatewayChanged,
                    subject: finding.ip.clone(),
                    detail: format!("gateway impersonation: {}", finding.detail),
                });
            }
        }
    }
    events.sort_by_key(|event| (event.timestamp_ms, event.subject.clone()));
    events.truncate(MAX_EVENTS);
    events
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Layer;

    fn meta(ts_sec: u32, source: &str, destination: &str, protocol: &str, layers: Vec<Layer>) -> PacketMeta {
        PacketMeta {
            offset: 0,
            incl_len: 60,
            orig_len: 60,
            ts_sec: u64::from(ts_sec),
            ts_subsec: 0,
            dissected: crate::Dissected {
                source: source.into(),
                destination: destination.into(),
                protocol: protocol.into(),
                info: String::new(),
                color_hint: "other".into(),
                layers,
                stream_id: None,
                tcp: None,
                payload: Vec::new(),
            },
        }
    }

    fn eth(mac_src: &str) -> Vec<Layer> {
        vec![Layer {
            label: "Ethernet II".into(),
            value: format!("{mac_src} → aa:aa:aa:aa:aa:aa"),
        }]
    }

    fn arp_layers(mac: &str, sender_ip: &str) -> Vec<Layer> {
        let mut layers = eth(mac);
        layers.push(Layer { label: "sender IP".into(), value: sender_ip.into() });
        layers.push(Layer { label: "target IP".into(), value: sender_ip.into() });
        layers
    }

    fn tcp_layers(dst_port: u16) -> Vec<Layer> {
        vec![
            Layer { label: "destination port".into(), value: dst_port.to_string() },
            Layer { label: "Transmission Control Protocol".into(), value: "syn".into() },
        ]
    }

    #[test]
    fn new_hosts_and_services_appear_once_in_chronological_order() {
        let packets = vec![
            meta(100, "10.0.0.1", "10.0.0.2", "TCP", tcp_layers(443)),
            meta(200, "10.0.0.2", "10.0.0.1", "TCP", tcp_layers(50000)),
            meta(300, "10.0.0.1", "10.0.0.2", "TCP", tcp_layers(443)), // repeat: no event
        ];
        let events = derive_events(&packets, None);
        let new_hosts = events.iter().filter(|e| e.kind == LabEventKind::NewHost).count();
        let services = events.iter().filter(|e| e.kind == LabEventKind::NewService).count();
        // hosts: 10.0.0.1, 10.0.0.2 (each endpoint pair, deduped across dirs)
        assert_eq!(new_hosts, 2);
        // services: 443/tcp on .2, 50000/tcp on .1
        assert_eq!(services, 2);
        assert!(events.windows(2).all(|w| w[0].timestamp_ms <= w[1].timestamp_ms));
        assert!(events.len() <= MAX_EVENTS);
    }

    #[test]
    fn arp_conflict_fires_when_a_second_mac_claims_the_same_ip() {
        let packets = vec![
            meta(100, "10.0.0.1", "ff:ff:ff:ff:ff:ff", "ARP", arp_layers("aa:aa:aa:aa:aa:aa", "10.0.0.5")),
            meta(200, "10.0.0.1", "ff:ff:ff:ff:ff:ff", "ARP", arp_layers("bb:bb:bb:bb:bb:bb", "10.0.0.5")),
            meta(300, "10.0.0.1", "ff:ff:ff:ff:ff:ff", "ARP", arp_layers("aa:aa:aa:aa:aa:aa", "10.0.0.5")),
        ];
        let events = derive_events(&packets, None);
        let conflicts: Vec<_> = events.iter().filter(|e| e.kind == LabEventKind::ArpConflict).collect();
        assert_eq!(conflicts.len(), 1, "conflict fires once, not per repeat");
        assert!(conflicts[0].detail.contains("aa:aa:aa:aa:aa:aa"));
        assert!(conflicts[0].detail.contains("bb:bb:bb:bb:bb:bb"));
    }

    #[test]
    fn gateway_mac_change_is_the_strongest_event_and_never_duplicated() {
        let packets = vec![
            meta(100, "10.0.0.1", "ff:ff:ff:ff:ff:ff", "ARP", arp_layers("aa:aa:aa:aa:aa:aa", "10.0.0.1")),
            meta(200, "10.0.0.1", "ff:ff:ff:ff:ff:ff", "ARP", arp_layers("cc:cc:cc:cc:cc:cc", "10.0.0.1")),
            meta(300, "10.0.0.1", "ff:ff:ff:ff:ff:ff", "ARP", arp_layers("cc:cc:cc:cc:cc:cc", "10.0.0.1")),
        ];
        let events = derive_events(&packets, Some("10.0.0.1"));
        let changes: Vec<_> = events.iter().filter(|e| e.kind == LabEventKind::GatewayChanged).collect();
        assert_eq!(changes.len(), 1);
        assert!(changes[0].detail.contains("aa:aa:aa:aa:aa:aa → cc:cc:cc:cc:cc:cc"));
    }

    #[test]
    fn non_ip_frames_never_become_hosts_and_caps_hold() {
        let mut packets = Vec::new();
        for i in 0..(MAX_TRACKED_HOSTS + 32) {
            let ip = format!("10.{}.{}.1", i / 256, i % 256);
            packets.push(meta(i as u32, "10.0.0.1", &ip, "TCP", tcp_layers(80)));
        }
        let events = derive_events(&packets, None);
        assert!(events.len() <= MAX_EVENTS);
        // MAC-only frames (no parseable IP endpoints) contribute no hosts.
        let weird = meta(1, "not-an-ip", "also-not", "TCP", tcp_layers(80));
        assert!(derive_events(&[weird], None).iter().all(|e| e.kind != LabEventKind::NewHost));
    }

    #[test]
    fn mac_extraction_refuses_non_address_tokens() {
        assert_eq!(mac_from_layers(&eth("aa:bb:cc:dd:ee:ff")).as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(mac_from_layers(&eth("not-a-mac")), None);
    }
}
