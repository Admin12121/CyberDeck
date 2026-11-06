//! Bettercap-mode live lab commands: the Network Lab subscribes to a RUNNING
//! Packet Studio capture session (one capture, many modules) instead of
//! starting its own. Read-only and stateless — every poll revalidates the
//! caller's case-revision ownership through the same gate as the capture
//! commands, then re-derives the passive event timeline and ARP findings from
//! the session's retained packet snapshot. This module never starts, stops,
//! transmits or injects anything on the wire.

use std::net::IpAddr;

use cyberdeck_packet::arp_watch::{analyze_arp, ArpObservation, ArpOperation};
use cyberdeck_packet::lab_events::{derive_events_wire, LabEvent};
use cyberdeck_packet::{Dissected, PacketMeta, MAX_CAPTURE_PACKETS};
use serde::Serialize;
use tauri::State;

use super::capture::CaptureCtx;
use crate::features::shared::session::CaseSessionCtx;

/// Defensive observation cap mirroring the capture parser's own bound
/// (identical to the opened-capture lab in network_lab.rs).
const MAX_LIVE_OBSERVATIONS: usize = MAX_CAPTURE_PACKETS;

/// Frontend-safe live lab status. Wire names are snake_case and are mirrored
/// by lib/network-lab-live-ipc.ts; no raw bytes, paths or case secrets here.
#[derive(Debug, Serialize)]
pub struct LabLiveStatusWire {
    /// True while the subscribed capture session is running or stopping.
    pub active: bool,
    /// Manager phase, snake_case: running | stopping | completed | failed.
    pub phase: String,
    pub interface: String,
    /// Packets the timeline was actually derived from. While the capture is
    /// still running the manager retains only progress counters, so this is
    /// 0 until the session's bounded result is published.
    pub sampled_packets: usize,
    /// Live capture progress counter (packets captured so far), honest even
    /// before dissection exists.
    pub captured_packets: usize,
    /// Passive event timeline, oldest first, capped at 512 events.
    pub events: Vec<LabEvent>,
    pub new_hosts: usize,
    pub new_services: usize,
    pub conflicts: usize,
    pub gateway_changes: usize,
    pub truncated: bool,
    /// ARP claims reduced from the same snapshot and cross-checked with the
    /// dedicated arp_watch analyzer (same reduction as the opened-capture
    /// lab), so impersonation/burst findings stay consistent across modes.
    pub arp_observations: usize,
    pub arp_findings: usize,
    pub gratuitous_bursts: usize,
}

/// Mirror the opened-capture lab's timestamp normalization. The native live
/// engine always writes classic usec pcap (0xa1b2c3d4), but parse_capture
/// reports the real magic, so nanosecond captures stay correct too.
fn frame_timestamp_ms(meta: &PacketMeta, nanosecond: bool) -> u64 {
    let sub_ms: u32 = if nanosecond {
        meta.ts_subsec / 1_000_000
    } else {
        meta.ts_subsec / 1_000
    };
    meta.ts_sec
        .saturating_mul(1000)
        .saturating_add(u64::from(sub_ms))
}

fn looks_like_mac(value: &str) -> bool {
    let mut groups = value.split(':');
    let matched = groups
        .by_ref()
        .take(7)
        .filter(|g| g.len() == 2 && g.bytes().all(|b| b.is_ascii_hexdigit()))
        .count();
    matched == 6 && groups.next().is_none()
}

fn layer_value<'a>(dissected: &'a Dissected, label: &str) -> Option<&'a str> {
    dissected
        .layers
        .iter()
        .find(|l| l.label == label)
        .map(|l| l.value.as_str())
}

/// Reduce one dissected frame to an analyzer observation. Semantics match
/// network_lab.rs exactly (ARP only; request/reply split via the info line;
/// gratuitous = reply where sender == target) so both lab modes agree.
fn observation_from_dissected(dissected: &Dissected, timestamp_ms: u64) -> Option<ArpObservation> {
    if dissected.protocol != "ARP" {
        return None;
    }
    let sender_ip = layer_value(dissected, "sender IP")?.to_string();
    let target_ip = layer_value(dissected, "target IP")?.to_string();
    let (operation, sender_mac) = if dissected.info.starts_with("Who has ") {
        let src = layer_value(dissected, "Ethernet II")
            .and_then(|v| v.split_once(" → "))
            .map(|(src, _)| src)?;
        if !looks_like_mac(src) {
            return None;
        }
        (ArpOperation::Request, src.to_string())
    } else if let Some((_, mac)) = dissected.info.rsplit_once(" is at ") {
        if !looks_like_mac(mac) {
            return None;
        }
        (ArpOperation::Reply, mac.to_string())
    } else {
        return None;
    };
    let is_gratuitous = operation == ArpOperation::Reply && sender_ip == target_ip;
    Some(ArpObservation {
        sender_ip,
        sender_mac,
        operation,
        is_gratuitous,
        timestamp_ms,
    })
}

/// Pure analysis core over one owned snapshot (no Tauri types): the command
/// is a thin gate-and-forward around this, so the derivation is testable.
fn live_status_from_snapshot(
    snapshot: super::capture::LabPacketSnapshot,
    router_ip: Option<&str>,
) -> LabLiveStatusWire {
    let mut observations: Vec<ArpObservation> = Vec::new();
    for meta in &snapshot.packets {
        if observations.len() >= MAX_LIVE_OBSERVATIONS {
            break;
        }
        if let Some(obs) =
            observation_from_dissected(&meta.dissected, frame_timestamp_ms(meta, snapshot.nanosecond))
        {
            observations.push(obs);
        }
    }
    let findings = analyze_arp(&observations, router_ip);
    let gratuitous_bursts = findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.kind,
                cyberdeck_packet::arp_watch::ArpFindingKind::GratuitousBurst
            )
        })
        .count();
    let events = derive_events_wire(&snapshot.packets, router_ip);
    LabLiveStatusWire {
        active: snapshot.active,
        phase: format!("{:?}", snapshot.phase).to_ascii_lowercase(),
        interface: snapshot.interface,
        sampled_packets: snapshot.packets.len(),
        captured_packets: snapshot.progress_packets,
        events: events.events,
        new_hosts: events.new_hosts,
        new_services: events.new_services,
        conflicts: events.conflicts,
        gateway_changes: events.gateway_changes,
        truncated: events.truncated,
        arp_observations: observations.len(),
        arp_findings: findings.len(),
        gratuitous_bursts,
    }
}

/// Live lab status for one subscribed capture session. Polling contract: the
/// frontend calls this every ~2s while live mode is enabled; the command is
/// read-only, stateless and never mutates the session. Ownership is validated
/// with the exact capture.rs gate (`owner_for` before the read, `valid_after`
/// after), so a revoked or case-switched session can never be read here.
#[tauri::command]
pub fn network_lab_live_status_v1(
    session_id: u64,
    router_ip: Option<String>,
    session: State<'_, CaseSessionCtx>,
    capture: State<'_, CaptureCtx>,
) -> Result<LabLiveStatusWire, String> {
    let router_ip = match router_ip
        .map(|ip| ip.trim().to_string())
        .filter(|ip| !ip.is_empty())
    {
        Some(ip) => {
            let parsed: IpAddr = ip
                .parse()
                .map_err(|_| format!("router IP is not a valid address: {ip}"))?;
            Some(parsed.to_string())
        }
        None => None,
    };
    let snapshot = capture.packet_snapshot(&session, session_id)?;
    Ok(live_status_from_snapshot(snapshot, router_ip.as_deref()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::network::ipc::capture::{CaptureCtx, LabPacketSnapshot};
    use crate::features::shared::session::CaseSessionCtx;
    use cyberdeck_packet::application::live_session::Phase;
    use cyberdeck_packet::live::{
        capture_from, CaptureInterface, CaptureLimits, FrameSource, ReceivedFrame,
    };
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, UNIX_EPOCH};

    fn captured_frame() -> Vec<u8> {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&[
            0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2, 0x80, 0x00,
            0x00, 0x35, 0, 8, 0, 0,
        ]);
        frame
    }

    /// One real completed capture run: the same fixture shape capture.rs
    /// tests use, so the snapshot carries genuine live-engine pcap bytes.
    fn fixture_pcap_packets() -> Vec<PacketMeta> {
        struct Source(Option<Vec<u8>>);
        impl FrameSource for Source {
            fn receive(
                &mut self,
                output: &mut [u8],
                _: Duration,
            ) -> Result<Option<ReceivedFrame>, cyberdeck_packet::live::CaptureError> {
                let Some(bytes) = self.0.take() else {
                    return Ok(None);
                };
                output[..bytes.len()].copy_from_slice(&bytes);
                Ok(Some(ReceivedFrame {
                    length: bytes.len(),
                    timestamp: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
                }))
            }
        }
        let result = capture_from(
            &mut Source(Some(captured_frame())),
            CaptureInterface {
                name: "fixture0".into(),
                index: 1,
                ethernet: true,
                up: true,
                loopback: false,
            },
            &CaptureLimits {
                max_packets: 1,
                ..CaptureLimits::default()
            },
            &AtomicBool::new(false),
        )
        .unwrap();
        cyberdeck_packet::parse_capture(&result.pcap_bytes)
            .unwrap()
            .packets
    }

    fn snapshot_for(packets: Vec<PacketMeta>) -> LabPacketSnapshot {
        LabPacketSnapshot {
            active: false,
            phase: Phase::Completed,
            interface: "fixture0".into(),
            progress_packets: packets.len(),
            packets,
            nanosecond: false,
        }
    }

    #[test]
    fn live_status_derives_hosts_services_and_timeline_from_a_snapshot() {
        let packets = fixture_pcap_packets();
        assert_eq!(packets.len(), 1);
        let wire = live_status_from_snapshot(snapshot_for(packets), None);
        assert!(!wire.active);
        assert_eq!(wire.phase, "completed");
        assert_eq!(wire.interface, "fixture0");
        assert_eq!(wire.sampled_packets, 1);
        assert_eq!(wire.captured_packets, 1);
        assert!(wire.new_hosts >= 2, "both IP endpoints become hosts");
        assert!(wire.new_services >= 1, "the UDP/53 service is inventoried");
        assert_eq!(wire.events.len(), wire.new_hosts + wire.new_services);
        assert!(!wire.truncated);
        // The same timeline the opened-capture lab renders, oldest first.
        assert!(wire
            .events
            .windows(2)
            .all(|pair| pair[0].timestamp_ms <= pair[1].timestamp_ms));
    }

    #[test]
    fn running_sessions_report_active_with_honest_zero_samples() {
        let snapshot = LabPacketSnapshot {
            active: true,
            phase: Phase::Running,
            interface: "eth0".into(),
            progress_packets: 42,
            packets: Vec::new(),
            nanosecond: false,
        };
        let wire = live_status_from_snapshot(snapshot, None);
        assert!(wire.active);
        assert_eq!(wire.phase, "running");
        assert_eq!(wire.captured_packets, 42, "live progress stays honest");
        assert_eq!(wire.sampled_packets, 0);
        assert!(wire.events.is_empty());
    }

    #[test]
    fn arp_reduction_matches_opened_capture_lab_semantics() {
        let dissected = Dissected {
            source: "10.0.0.5".into(),
            destination: "ff:ff:ff:ff:ff:ff".into(),
            protocol: "ARP".into(),
            info: "10.0.0.5 is at aa:bb:cc:dd:ee:ff".into(),
            color_hint: "other".into(),
            layers: vec![
                cyberdeck_packet::Layer {
                    label: "Ethernet II".into(),
                    value: "aa:bb:cc:dd:ee:ff → ff:ff:ff:ff:ff:ff".into(),
                },
                cyberdeck_packet::Layer {
                    label: "sender IP".into(),
                    value: "10.0.0.5".into(),
                },
                cyberdeck_packet::Layer {
                    label: "target IP".into(),
                    value: "10.0.0.5".into(),
                },
            ],
            stream_id: None,
            tcp: None,
            payload: Vec::new(),
        };
        let obs = observation_from_dissected(&dissected, 1234).unwrap();
        assert_eq!(obs.sender_ip, "10.0.0.5");
        assert_eq!(obs.sender_mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(obs.operation, ArpOperation::Reply);
        assert!(obs.is_gratuitous, "reply where sender == target");
        // Non-ARP frames never become observations.
        let mut tcp = dissected.clone();
        tcp.protocol = "TCP".into();
        assert!(observation_from_dissected(&tcp, 0).is_none());
    }

    #[test]
    fn unowned_sessions_fail_closed_before_any_read() {
        let temp = tempfile::tempdir().unwrap();
        let store = cyberdeck_storage::ArtifactStore::open(&temp.path().join("case.sqlite"))
            .unwrap();
        let case = store.create_case("Live Lab", "").unwrap();
        let session = CaseSessionCtx::default();
        session.select(&store, &case.id).unwrap();
        let ctx = CaptureCtx::default();
        // No owner is registered for any session in this context: the
        // snapshot (and therefore the lab command) must refuse before
        // touching any packet data, exactly like every other capture read.
        assert!(ctx.packet_snapshot(&session, 999).is_err());
    }
}

