//! Raw TCP scan-type probes beyond SYN (FIN/NULL/Xmas/ACK/Window) plus pure
//! service-probe helpers. The port-state semantics follow documented nmap
//! behavior (reference/nmap/scan_engine_raw.cc, set_default_port_state in
//! scan_engine.cc), re-implemented as original bounded Rust:
//!
//! - FIN/NULL/Xmas probe: TCP RST means closed; silence means open|filtered;
//!   ICMPv4 unreachable means filtered.
//! - ACK probe: TCP RST means unfiltered (open and closed are not told apart);
//!   silence or ICMP unreachable means filtered.
//! - Window probe: TCP RST with a nonzero window means open; RST with a zero
//!   window means closed; silence means filtered.
//!
//! Silence is classified as the documented default, never as affirmative
//! evidence. Every plan is bounded (hosts, ports, probes, per-probe timeout)
//! and every send requires an upstream authorization gate that the caller owns.
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Scan kinds and per-port states
// ---------------------------------------------------------------------------

/// The raw TCP flag scans. SYN scanning lives in `active_syn`; this module
/// covers the probe types that nmap documents as depending on how stacks
/// respond to unusual or non-connection flag combinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanKind {
    /// FIN flag only.
    Fin,
    /// No TCP flags at all.
    Null,
    /// FIN + URG + PSH together ("Christmas tree").
    Xmas,
    /// ACK only; distinguishes filtered from unfiltered, never open/closed.
    Ack,
    /// ACK only, but RST window size separates open (nonzero) from closed.
    Window,
}

impl ScanKind {
    /// TCP header flag byte for this scan type. Xmas is FIN|PSH|URG, exactly
    /// the combination nmap sends; ACK and Window probes carry the same wire
    /// flags and differ only in how the RST reply is interpreted.
    pub fn tcp_flags(self) -> u8 {
        match self {
            ScanKind::Fin => 0x01,
            ScanKind::Null => 0x00,
            ScanKind::Xmas => 0x01 | 0x08 | 0x20,
            ScanKind::Ack | ScanKind::Window => 0x10,
        }
    }
    /// Human-readable wire label used in findings and case evidence.
    pub fn label(self) -> &'static str {
        match self {
            ScanKind::Fin => "fin",
            ScanKind::Null => "null",
            ScanKind::Xmas => "xmas",
            ScanKind::Ack => "ack",
            ScanKind::Window => "window",
        }
    }
    /// Default state for a port that never answers, per nmap's
    /// `set_default_port_state`: FIN/NULL/Xmas cannot distinguish an open
    /// port behind a firewall from a filtered one, so silence is
    /// open|filtered; ACK/Window silence is filtered.
    pub fn silence_state(self) -> PortState {
        match self {
            ScanKind::Fin | ScanKind::Null | ScanKind::Xmas => PortState::OpenFiltered,
            ScanKind::Ack | ScanKind::Window => PortState::Filtered,
        }
    }
    /// Parse a scan kind from a stable lowercase wire label.
    pub fn parse(label: &str) -> Option<Self> {
        match label {
            "fin" => Some(ScanKind::Fin),
            "null" => Some(ScanKind::Null),
            "xmas" => Some(ScanKind::Xmas),
            "ack" => Some(ScanKind::Ack),
            "window" => Some(ScanKind::Window),
            _ => None,
        }
    }
}

/// Per-port outcome of one raw scan type. None of these states authenticate
/// the responder; they classify one probe's observed treatment only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortState {
    Open,
    Closed,
    /// ACK/Window probe got a RST: the port is reachable, open/closed unknown.
    Unfiltered,
    /// Network policy answered (ICMP unreachable) or the probe went silent for
    /// scan types where silence means filtered.
    Filtered,
    /// FIN/NULL/Xmas silence: the port may be open behind a filtering device.
    OpenFiltered,
}

impl PortState {
    pub fn as_str(self) -> &'static str {
        match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Unfiltered => "unfiltered",
            PortState::Filtered => "filtered",
            PortState::OpenFiltered => "open_filtered",
        }
    }
}

// ---------------------------------------------------------------------------
// Bounded plans
// ---------------------------------------------------------------------------

pub const MAX_DEPTH_HOSTS: usize = 32;
pub const MAX_DEPTH_PORTS: usize = 128;
pub const MAX_DEPTH_PROBES: usize = 2048;
/// Per-probe response wait. Deliberately short: raw scan types classify
/// silence anyway, so a long wait would only delay honest "silence" verdicts.
pub const PROBE_TIMEOUT: Duration = Duration::from_millis(600);
const SEND_GAP: Duration = Duration::from_millis(40);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepthErrorCode {
    Unsupported,
    InvalidScope,
    Permission,
    Device,
    Io,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepthScanError {
    pub code: DepthErrorCode,
    pub message: String,
}
impl DepthScanError {
    pub fn new(code: DepthErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepthFinding {
    pub host: Ipv4Addr,
    pub port: u16,
    pub state: PortState,
    pub reason: &'static str,
    pub elapsed_ms: u64,
}

fn validate_plan(hosts: &[Ipv4Addr], ports: &[u16]) -> Result<(), DepthScanError> {
    if hosts.is_empty()
        || hosts.len() > MAX_DEPTH_HOSTS
        || ports.is_empty()
        || ports.len() > MAX_DEPTH_PORTS
        || hosts
            .len()
            .checked_mul(ports.len())
            .is_none_or(|count| count > MAX_DEPTH_PROBES)
    {
        return Err(DepthScanError::new(
            DepthErrorCode::InvalidScope,
            "raw flag scan exceeds 32 hosts, 128 ports, or 2048 probes",
        ));
    }
    if hosts
        .iter()
        .any(|host| host.is_unspecified() || host.is_multicast() || host.is_broadcast())
        || ports.contains(&0)
    {
        return Err(DepthScanError::new(
            DepthErrorCode::InvalidScope,
            "raw flag scanning requires unicast IPv4 targets and nonzero ports",
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Probe frame builders (IPv4 + TCP, and Ethernet + IPv4 + TCP)
// ---------------------------------------------------------------------------

/// Reuse `scan_packets`' packet-level validation error so callers only handle
/// one builder failure type for this crate's IPv4/TCP probes.
pub use crate::scan_packets::PacketBuildError;

fn valid_ipv4_source(source: Ipv4Addr) -> bool {
    !source.is_unspecified() && !source.is_multicast() && !source.is_broadcast()
}
fn valid_ipv4_target(target: Ipv4Addr) -> bool {
    !target.is_unspecified() && !target.is_multicast() && !target.is_broadcast()
}
fn valid_ports(local: u16, target: u16) -> bool {
    local != 0 && target != 0
}

/// RFC 1071 one's complement checksum over even-length chunks.
fn checksum(even_chunks: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    for chunk in even_chunks {
        debug_assert!(chunk.len() % 2 == 0);
        for word in chunk.chunks_exact(2) {
            sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ipv4_header(
    source: Ipv4Addr,
    target: Ipv4Addr,
    length: u16,
    protocol: u8,
    identification: u16,
    hop_limit: u8,
) -> [u8; 20] {
    let mut header = [0u8; 20];
    header[0] = 0x45;
    header[2..4].copy_from_slice(&length.to_be_bytes());
    header[4..6].copy_from_slice(&identification.to_be_bytes());
    header[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // do not fragment
    header[8] = hop_limit;
    header[9] = protocol;
    header[12..16].copy_from_slice(&source.octets());
    header[16..20].copy_from_slice(&target.octets());
    let sum = checksum(&[&header]);
    header[10..12].copy_from_slice(&sum.to_be_bytes());
    header
}

/// Probe TCP header: fixed 20 bytes, caller-chosen flags, and a probe window
/// of 1024 (the conventional scan-probe window; only RST replies' windows are
/// interpreted, never our own).
fn tcp_probe_header(
    local_port: u16,
    remote_port: u16,
    sequence: u32,
    flags: u8,
    window: u16,
) -> [u8; 20] {
    let mut header = [0u8; 20];
    header[0..2].copy_from_slice(&local_port.to_be_bytes());
    header[2..4].copy_from_slice(&remote_port.to_be_bytes());
    header[4..8].copy_from_slice(&sequence.to_be_bytes());
    header[12] = 0x50; // fixed 20-byte header, no TCP options
    header[13] = flags;
    header[14..16].copy_from_slice(&window.to_be_bytes());
    header
}

/// 40-byte IPv4/TCP flag probe (FIN/NULL/Xmas/ACK/Window). Does not spoof
/// identities: the caller must prove `source` is assigned to the selected
/// interface, exactly as for the SYN probe builder.
pub fn ipv4_tcp_scan_probe(
    source: Ipv4Addr,
    target: Ipv4Addr,
    local_port: u16,
    target_port: u16,
    kind: ScanKind,
    initial_sequence: u32,
    identification: u16,
    hop_limit: u8,
) -> Result<[u8; 40], PacketBuildError> {
    if !valid_ipv4_source(source) || !valid_ipv4_target(target) {
        return Err(PacketBuildError::InvalidAddress);
    }
    if !valid_ports(local_port, target_port) {
        return Err(PacketBuildError::InvalidPort);
    }
    if hop_limit == 0 {
        return Err(PacketBuildError::InvalidHopLimit);
    }
    let mut packet = [0u8; 40];
    packet[..20].copy_from_slice(&ipv4_header(
        source,
        target,
        40,
        6,
        identification,
        hop_limit,
    ));
    let mut tcp = tcp_probe_header(
        local_port,
        target_port,
        initial_sequence,
        kind.tcp_flags(),
        1024,
    );
    let mut pseudo = [0u8; 12];
    pseudo[..4].copy_from_slice(&source.octets());
    pseudo[4..8].copy_from_slice(&target.octets());
    pseudo[9] = 6;
    pseudo[10..12].copy_from_slice(&20u16.to_be_bytes());
    let value = checksum(&[&pseudo, &tcp]);
    tcp[16..18].copy_from_slice(&value.to_be_bytes());
    packet[20..].copy_from_slice(&tcp);
    Ok(packet)
}

/// 54-byte Ethernet II + IPv4 + TCP flag probe for a future AF_PACKET send
/// path. Both MACs must be real unicast hardware addresses: the source is the
/// selected interface and the destination must be a resolved neighbor or
/// gateway for the target, never a guessed broadcast.
pub fn ethernet_ipv4_tcp_scan_probe(
    source_mac: [u8; 6],
    destination_mac: [u8; 6],
    source: Ipv4Addr,
    target: Ipv4Addr,
    local_port: u16,
    target_port: u16,
    kind: ScanKind,
    initial_sequence: u32,
    identification: u16,
    hop_limit: u8,
) -> Result<[u8; 54], PacketBuildError> {
    if source_mac == [0; 6] || source_mac[0] & 1 != 0 {
        return Err(PacketBuildError::InvalidMac);
    }
    if destination_mac == [0; 6] || destination_mac[0] & 1 != 0 {
        return Err(PacketBuildError::InvalidMac);
    }
    let ip = ipv4_tcp_scan_probe(
        source,
        target,
        local_port,
        target_port,
        kind,
        initial_sequence,
        identification,
        hop_limit,
    )?;
    let mut frame = [0u8; 54];
    frame[..6].copy_from_slice(&destination_mac);
    frame[6..12].copy_from_slice(&source_mac);
    frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    frame[14..].copy_from_slice(&ip);
    Ok(frame)
}

// ---------------------------------------------------------------------------
// Reply classification
// ---------------------------------------------------------------------------

/// The 4-tuple plus sequence that identifies one outstanding probe. Sequence
/// matching only applies to ICMP-quoted copies of the original probe; RST
/// replies are correlated by the 4-tuple on an interface-bound socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeKey {
    pub local: Ipv4Addr,
    pub target: Ipv4Addr,
    pub local_port: u16,
    pub target_port: u16,
    pub sequence: u32,
}

/// One classified response for an outstanding probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeReply {
    /// TCP RST from the probe's target; `window` is the RST's advertised
    /// window, which Window scan interprets (nonzero = open).
    TcpReset { window: u16 },
    /// ICMPv4 destination-unreachable/time-exceeded treatment of the probe.
    IcmpUnreachable { icmp_kind: u8, code: u8 },
}

/// Map one classified reply (or silence) to the documented per-port state.
pub fn classify_reply(kind: ScanKind, reply: Option<ProbeReply>) -> PortState {
    match reply {
        Some(ProbeReply::TcpReset { window }) => match kind {
            // Window scan is the only flag scan that separates open from
            // closed; historic stacks lie about RST windows, so this is a
            // claim by the remote stack, not proof.
            ScanKind::Window if window != 0 => PortState::Open,
            ScanKind::Window => PortState::Closed,
            ScanKind::Ack => PortState::Unfiltered,
            ScanKind::Fin | ScanKind::Null | ScanKind::Xmas => PortState::Closed,
        },
        Some(ProbeReply::IcmpUnreachable { .. }) => PortState::Filtered,
        None => kind.silence_state(),
    }
}

fn be16(bytes: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(bytes.get(..2)?.try_into().ok()?))
}

/// Classify one received frame (Ethernet II with up to two VLAN tags, or a
/// bare IPv4 datagram) against an outstanding probe. Refuses truncated,
/// fragmented and non-matching traffic. Returns the observed reply, not a
/// final port state; combine with `classify_reply` once the wait is over.
pub fn classify_frame(kind: ScanKind, frame: &[u8], probe: &ProbeKey) -> Option<ProbeReply> {
    // Silence the unused parameter on platforms where only classification is
    // exercised today; kind is part of the stable signature.
    let _ = kind;
    let (ip, vlan_end) = strip_link_layer(frame)?;
    let ip = &ip[vlan_end..];
    if ip.len() < 20 || ip[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(ip[0] & 15) * 4;
    if ihl < 20 || ihl > ip.len() {
        return None;
    }
    // Never classify replies built from IPv4 fragments: the TCP header would
    // be reconstructed from partial evidence.
    if be16(&ip[6..8])? & 0x3fff != 0 {
        return None;
    }
    let total = usize::from(be16(&ip[2..4])?).min(ip.len());
    if total < ihl {
        return None;
    }
    let body = &ip[ihl..total];
    if ip[9] == 6 {
        // TCP response must come from the probed target to our probe socket.
        if IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15])) != IpAddr::V4(probe.target)
            || IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19])) != IpAddr::V4(probe.local)
            || body.len() < 20
        {
            return None;
        }
        let data_offset = usize::from(body[12] >> 4) * 4;
        if data_offset < 20 || data_offset > body.len() {
            return None;
        }
        if be16(&body[..2]) != Some(probe.target_port)
            || be16(&body[2..4]) != Some(probe.local_port)
        {
            return None;
        }
        let flags = body[13];
        // Only RST carries interpretable evidence for these scan types. A
        // SYN-ACK to a FIN/NULL/Xmas probe is anomalous stack behavior and is
        // deliberately not promoted to any state.
        if flags & 0x04 != 0 {
            Some(ProbeReply::TcpReset {
                window: be16(&body[14..16])?,
            })
        } else {
            None
        }
    } else if ip[9] == 1 {
        // ICMPv4 error: destination unreachable (3) or time exceeded (11).
        // Routers legitimately report these, so the outer source is not
        // matched; the quoted original packet must identify our exact probe.
        if body.len() < 8 || !matches!(body[0], 3 | 11) {
            return None;
        }
        let quoted = &body[8..];
        if quoted.len() < 20 + 8 || quoted[0] >> 4 != 4 {
            return None;
        }
        let quoted_ihl = usize::from(quoted[0] & 15) * 4;
        if quoted_ihl < 20 || quoted_ihl > quoted.len() {
            return None;
        }
        if be16(&quoted[6..8])? & 0x1fff != 0 {
            return None; // quoted fragment: not the original header
        }
        if quoted[9] != 6
            || Ipv4Addr::new(quoted[12], quoted[13], quoted[14], quoted[15]) != probe.local
            || Ipv4Addr::new(quoted[16], quoted[17], quoted[18], quoted[19]) != probe.target
        {
            return None;
        }
        let quoted_tcp = &quoted[quoted_ihl..];
        if quoted_tcp.len() < 8
            || be16(&quoted_tcp[..2]) != Some(probe.local_port)
            || be16(&quoted_tcp[2..4]) != Some(probe.target_port)
            || u32::from_be_bytes(quoted_tcp[4..8].try_into().ok()?) != probe.sequence
        {
            return None;
        }
        Some(ProbeReply::IcmpUnreachable {
            icmp_kind: body[0],
            code: body[1],
        })
    } else {
        None
    }
}

/// Split an optional Ethernet II header (including up to two VLAN tags) and
/// return the IPv4 datagram slice. Returns `(frame, 0)` for bare IP input.
fn strip_link_layer(frame: &[u8]) -> Option<(&[u8], usize)> {
    if frame.len() >= 14 {
        let mut ethertype = be16(&frame[12..14])?;
        let mut cursor = 14usize;
        for _ in 0..2 {
            if !matches!(ethertype, 0x8100 | 0x88a8) {
                break;
            }
            ethertype = be16(frame.get(cursor + 2..cursor + 4)?)?;
            cursor += 4;
        }
        if matches!(ethertype, 0x0800) {
            return Some((frame, cursor));
        }
    }
    // Bare IPv4 datagram (cooked socket or test input).
    if frame.first().is_some_and(|b| b >> 4 == 4) {
        return Some((frame, 0));
    }
    None
}

// ---------------------------------------------------------------------------
// Plan runner over an injected raw link (platform-independent)
// ---------------------------------------------------------------------------

/// Transport abstraction so the bounded plan runner is testable without raw
/// sockets. The Linux implementation sends from one AF_INET raw socket and
/// receives from one interface-bound AF_PACKET socket, exactly like the SYN
/// backend in `active_syn`.
pub trait RawProbeLink {
    /// The verified IPv4 address of the selected interface; every probe is
    /// sourced from it, never from a caller-supplied address.
    fn source_address(&self) -> Ipv4Addr;
    fn send_probe(&mut self, packet: &[u8], target: Ipv4Addr) -> Result<(), DepthScanError>;
    /// Copy at most `buffer.len()` bytes of one received frame; `None` means
    /// nothing arrived within `timeout`.
    fn receive_frame(
        &mut self,
        buffer: &mut [u8],
        timeout: Duration,
    ) -> Result<Option<usize>, DepthScanError>;
}

/// Execute one bounded FIN/NULL/Xmas/ACK/Window plan over `link`. Cancellation
/// and scope revocation are checked before every send and while waiting; the
/// final state for silence is the scan type's documented default, marked as
/// such in `reason`.
pub fn run_flag_probe_plan(
    link: &mut impl RawProbeLink,
    kind: ScanKind,
    interface_mtu_cap: usize,
    hosts: &[Ipv4Addr],
    ports: &[u16],
    stop: &AtomicBool,
    scope_active: &(impl Fn() -> bool + Sync),
    progress: &(impl Fn(usize, usize) + Sync),
) -> Result<Vec<DepthFinding>, DepthScanError> {
    validate_plan(hosts, ports)?;
    if stop.load(Ordering::Acquire) || !scope_active() {
        return Err(DepthScanError::new(
            DepthErrorCode::Cancelled,
            "raw scan scope revoked",
        ));
    }
    let mut identity = RandomIdentity::new();
    let total = hosts.len() * ports.len();
    let mut findings = Vec::with_capacity(total);
    let mut frame_buffer = [0u8; 1514];
    let mut last_send: Option<Instant> = None;
    for &target in hosts {
        for &port in ports {
            if cancelled(stop, scope_active) {
                return Err(DepthScanError::new(
                    DepthErrorCode::Cancelled,
                    "raw flag scan revoked",
                ));
            }
            if let Some(last) = last_send {
                while last.elapsed() < SEND_GAP {
                    if cancelled(stop, scope_active) {
                        return Err(DepthScanError::new(
                            DepthErrorCode::Cancelled,
                            "raw flag scan revoked",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            let (local_port, sequence, identification) = identity.next()?;
            let packet = ipv4_tcp_scan_probe(
                link.source_address(),
                target,
                local_port,
                port,
                kind,
                sequence,
                identification,
                64,
            )
            .map_err(|_| {
                DepthScanError::new(
                    DepthErrorCode::InvalidScope,
                    "invalid raw flag probe source or destination",
                )
            })?;
            if packet.len() > interface_mtu_cap {
                return Err(DepthScanError::new(
                    DepthErrorCode::InvalidScope,
                    "probe exceeds the selected interface MTU budget",
                ));
            }
            let started = Instant::now();
            link.send_probe(&packet, target)?;
            last_send = Some(started);
            let key = ProbeKey {
                local: link.source_address(),
                target,
                local_port,
                target_port: port,
                sequence,
            };
            let mut observed: Option<ProbeReply> = None;
            while started.elapsed() < PROBE_TIMEOUT {
                if cancelled(stop, scope_active) {
                    return Err(DepthScanError::new(
                        DepthErrorCode::Cancelled,
                        "raw flag scan revoked",
                    ));
                }
                let remaining = PROBE_TIMEOUT.saturating_sub(started.elapsed());
                let received = link
                    .receive_frame(&mut frame_buffer, remaining.min(Duration::from_millis(50)))?;
                if cancelled(stop, scope_active) {
                    return Err(DepthScanError::new(
                        DepthErrorCode::Cancelled,
                        "raw flag scan revoked",
                    ));
                }
                if let Some(length) = received {
                    if let Some(reply) = classify_frame(kind, &frame_buffer[..length], &key) {
                        observed = Some(reply);
                        break;
                    }
                }
            }
            let state = classify_reply(kind, observed);
            let reason: &'static str = match observed {
                Some(ProbeReply::TcpReset { .. }) => "tcp_rst_matching_tuple",
                Some(ProbeReply::IcmpUnreachable { .. }) => "icmp_ipv4_unreachable",
                None => match kind.silence_state() {
                    PortState::OpenFiltered => "no_response_default_openfiltered",
                    _ => "no_response_default_filtered",
                },
            };
            findings.push(DepthFinding {
                host: target,
                port,
                state,
                reason,
                elapsed_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            });
            progress(findings.len(), total);
        }
    }
    Ok(findings)
}

fn cancelled(stop: &AtomicBool, scope: &(impl Fn() -> bool + Sync)) -> bool {
    stop.load(Ordering::Acquire) || !scope()
}

/// Backend-generated probe identity: an ephemeral source port, a random
/// initial sequence and a random IPv4 identification, all read from the OS
/// CSPRNG. The sequence is the only correlation secret for ICMP-quoted errors.
struct RandomIdentity {
    pool: [u8; 32],
    used: usize,
}
impl RandomIdentity {
    fn new() -> Self {
        // `used` starts at the pool length so the very first probe refills
        // from the OS CSPRNG instead of reading uninitialized bytes.
        Self {
            pool: [0; 32],
            used: 32,
        }
    }
    const POOL_BYTES: usize = 8;
    fn next(&mut self) -> Result<(u16, u32, u16), DepthScanError> {
        if self.used >= self.pool.len() {
            use std::io::Read;
            std::fs::File::open("/dev/urandom")
                .and_then(|mut r| r.read_exact(&mut self.pool))
                .map_err(|e| {
                    DepthScanError::new(
                        DepthErrorCode::Io,
                        format!("OS random identity unavailable: {e}"),
                    )
                })?;
            self.used = 0;
        }
        let b = &self.pool[self.used..self.used + Self::POOL_BYTES];
        self.used += Self::POOL_BYTES;
        let port = 49152 + (u16::from_be_bytes([b[0], b[1]]) % 16384);
        let sequence = u32::from_be_bytes([b[2], b[3], b[4], b[5]]);
        let identification = u16::from_be_bytes([b[6], b[7]]);
        Ok((port, sequence, identification))
    }
}

/// Public entry point mirroring `active_syn::scan_ipv4_syn`. Linux only; other
/// platforms receive a structured Unsupported error rather than a silent
/// fallback, because a faked scan would be dishonest evidence.
pub fn scan_ipv4_depth(
    interface_name: &str,
    kind: ScanKind,
    hosts: &[Ipv4Addr],
    ports: &[u16],
    stop: &AtomicBool,
    scope_active: &(impl Fn() -> bool + Sync),
    progress: &(impl Fn(usize, usize) + Sync),
) -> Result<Vec<DepthFinding>, DepthScanError> {
    #[cfg(target_os = "linux")]
    {
        linux::scan(
            interface_name,
            kind,
            hosts,
            ports,
            stop,
            scope_active,
            progress,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            interface_name,
            kind,
            hosts,
            ports,
            stop,
            scope_active,
            progress,
        );
        Err(DepthScanError::new(
            DepthErrorCode::Unsupported,
            "raw FIN/NULL/Xmas/ACK/Window scanning requires Linux CAP_NET_RAW",
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::live::{discover_interfaces, select_interface};
    use std::ffi::{c_int, c_ulong, c_void};
    use std::io;
    use std::os::fd::RawFd;

    const AF_INET: c_int = 2;
    const AF_PACKET: c_int = 17;
    const SOCK_RAW: c_int = 3;
    const SOCK_DGRAM: c_int = 2;
    const SOCK_CLOEXEC: c_int = 0o2000000;
    const ETH_P_IP: u16 = 0x0800;
    const IPPROTO_RAW: c_int = 255;
    const SOL_SOCKET: c_int = 1;
    const SO_BINDTODEVICE: c_int = 25;
    const SIOCGIFADDR: c_ulong = 0x8915;
    const POLLIN: i16 = 1;
    const MTU_BUDGET: usize = 1500;

    #[repr(C)]
    struct SockAddrLl {
        family: u16,
        protocol: u16,
        ifindex: c_int,
        hatype: u16,
        pkttype: u8,
        halen: u8,
        addr: [u8; 8],
    }
    #[repr(C)]
    struct SockAddrIn {
        family: u16,
        port: u16,
        addr: [u8; 4],
        zero: [u8; 8],
    }
    #[repr(C)]
    struct Ifreq {
        name: [u8; 16],
        payload: [u8; 24],
    }
    #[repr(C)]
    struct PollFd {
        fd: c_int,
        events: i16,
        revents: i16,
    }

    unsafe extern "C" {
        fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
        fn bind(fd: c_int, addr: *const c_void, len: u32) -> c_int;
        fn setsockopt(fd: c_int, level: c_int, opt: c_int, val: *const c_void, len: u32) -> c_int;
        fn ioctl(fd: c_int, request: c_ulong, arg: *mut c_void) -> c_int;
        fn sendto(
            fd: c_int,
            buf: *const c_void,
            len: usize,
            flags: c_int,
            addr: *const c_void,
            addr_len: u32,
        ) -> isize;
        fn recv(fd: c_int, buf: *mut c_void, len: usize, flags: c_int) -> isize;
        fn poll(fds: *mut PollFd, count: usize, timeout: c_int) -> c_int;
        fn close(fd: c_int) -> c_int;
    }

    struct Fd(RawFd);
    impl Drop for Fd {
        fn drop(&mut self) {
            unsafe {
                close(self.0);
            }
        }
    }
    fn err(context: &str) -> DepthScanError {
        let e = io::Error::last_os_error();
        let code = if e.kind() == io::ErrorKind::PermissionDenied {
            DepthErrorCode::Permission
        } else {
            DepthErrorCode::Io
        };
        DepthScanError::new(code, format!("{context}: {e}"))
    }
    fn selected_source(device: &str) -> Result<Ipv4Addr, DepthScanError> {
        if device.is_empty()
            || device.len() >= 16
            || !device
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
        {
            return Err(DepthScanError::new(
                DepthErrorCode::InvalidScope,
                "invalid interface name",
            ));
        }
        let fd = Fd(unsafe { socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0) });
        if fd.0 < 0 {
            return Err(err("read local interface IPv4"));
        }
        let mut request = Ifreq {
            name: [0; 16],
            payload: [0; 24],
        };
        request.name[..device.len()].copy_from_slice(device.as_bytes());
        if unsafe { ioctl(fd.0, SIOCGIFADDR, (&raw mut request).cast()) } < 0 {
            return Err(err("verify selected interface IPv4"));
        }
        let octets: [u8; 4] = request.payload[4..8]
            .try_into()
            .expect("fixed ifreq layout");
        let address = Ipv4Addr::from(octets);
        if address.is_unspecified() || address.is_multicast() || address.is_broadcast() {
            return Err(DepthScanError::new(
                DepthErrorCode::InvalidScope,
                "interface has no usable IPv4",
            ));
        }
        Ok(address)
    }
    fn bind_interface(fd: c_int, interface: &str) -> Result<(), DepthScanError> {
        let mut device = interface.as_bytes().to_vec();
        device.push(0);
        if unsafe {
            setsockopt(
                fd,
                SOL_SOCKET,
                SO_BINDTODEVICE,
                device.as_ptr().cast(),
                device.len() as u32,
            )
        } < 0
        {
            return Err(err("bind raw scan to explicitly selected interface"));
        }
        Ok(())
    }

    /// Linux `RawProbeLink`: raw IPv4 transmitter + interface-bound packet
    /// receiver, both tied to the operator-selected device.
    struct LinuxProbeLink {
        send_fd: Fd,
        receive_fd: Fd,
        source: Ipv4Addr,
    }
    impl LinuxProbeLink {
        fn open(interface_name: &str) -> Result<Self, DepthScanError> {
            let interfaces = discover_interfaces()
                .map_err(|e| DepthScanError::new(DepthErrorCode::Device, e.message))?;
            let selected = select_interface(&interfaces, interface_name)
                .map_err(|e| DepthScanError::new(DepthErrorCode::Device, e.message))?;
            let source = selected_source(&selected.name)?;
            let send_fd = Fd(unsafe { socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_RAW) });
            if send_fd.0 < 0 {
                return Err(err("open native raw IPv4 flag-probe transmitter"));
            }
            bind_interface(send_fd.0, &selected.name)?;
            let protocol = ETH_P_IP.to_be();
            let receive_fd =
                Fd(unsafe { socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, c_int::from(protocol)) });
            if receive_fd.0 < 0 {
                return Err(err("open native Ethernet IPv4 response receiver"));
            }
            let index = c_int::try_from(selected.index).map_err(|_| {
                DepthScanError::new(DepthErrorCode::Device, "interface index overflow")
            })?;
            let address = SockAddrLl {
                family: AF_PACKET as u16,
                protocol,
                ifindex: index,
                hatype: 0,
                pkttype: 0,
                halen: 0,
                addr: [0; 8],
            };
            if unsafe {
                bind(
                    receive_fd.0,
                    (&raw const address).cast(),
                    std::mem::size_of::<SockAddrLl>() as u32,
                )
            } < 0
            {
                return Err(err("bind raw IPv4 response receiver to selected interface"));
            }
            Ok(Self {
                send_fd,
                receive_fd,
                source,
            })
        }
    }
    impl RawProbeLink for LinuxProbeLink {
        fn send_probe(&mut self, packet: &[u8], target: Ipv4Addr) -> Result<(), DepthScanError> {
            let destination = SockAddrIn {
                family: AF_INET as u16,
                port: 0,
                addr: target.octets(),
                zero: [0; 8],
            };
            let wrote = unsafe {
                sendto(
                    self.send_fd.0,
                    packet.as_ptr().cast(),
                    packet.len(),
                    0,
                    (&raw const destination).cast(),
                    std::mem::size_of::<SockAddrIn>() as u32,
                )
            };
            if wrote != packet.len() as isize {
                return Err(err("send bounded native TCP flag probe"));
            }
            Ok(())
        }
        fn receive_frame(
            &mut self,
            buffer: &mut [u8],
            timeout: Duration,
        ) -> Result<Option<usize>, DepthScanError> {
            let mut pfd = PollFd {
                fd: self.receive_fd.0,
                events: POLLIN,
                revents: 0,
            };
            let wait = (timeout.as_millis().min(50) as c_int).max(1);
            let ready = unsafe { poll(&raw mut pfd, 1, wait) };
            if ready < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    return Ok(None);
                }
                return Err(err("poll native flag-probe responses"));
            }
            if ready == 0 || pfd.revents & POLLIN == 0 {
                return Ok(None);
            }
            let received = unsafe {
                recv(
                    self.receive_fd.0,
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    0,
                )
            };
            if received < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    return Ok(None);
                }
                return Err(err("read native flag-probe response"));
            }
            Ok(Some(received as usize))
        }
        fn source_address(&self) -> Ipv4Addr {
            self.source
        }
    }

    pub(super) fn scan(
        interface_name: &str,
        kind: ScanKind,
        hosts: &[Ipv4Addr],
        ports: &[u16],
        stop: &AtomicBool,
        scope: &(impl Fn() -> bool + Sync),
        progress: &(impl Fn(usize, usize) + Sync),
    ) -> Result<Vec<DepthFinding>, DepthScanError> {
        let mut link = LinuxProbeLink::open(interface_name)?;
        run_flag_probe_plan(
            &mut link, kind, MTU_BUDGET, hosts, ports, stop, scope, progress,
        )
    }
}

// ---------------------------------------------------------------------------
// Pure service-probe helpers (payloads + conservative response classification)
// ---------------------------------------------------------------------------

pub const MAX_SERVICE_EXCERPT: usize = 160;
pub const MAX_SERVICE_CLAIM: usize = 80;
/// Maximum response bytes read per probe. Protocol identifiers live at the
/// start of a greeting; reading megabytes of body would be wasted exposure.
pub const MAX_SERVICE_RESPONSE_BYTES: usize = 8 * 1024;
pub const MAX_SERVICE_PROBES_PER_PORT: usize = 4;

/// Bounded high-value subset of documented service probes (see
/// reference/nmap/nmap-service-probes). `Banner` is the NULL probe: connect
/// and read whatever the service sends first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceProbe {
    Banner,
    HttpGet,
    HttpOptions,
    TlsHello,
    DnsVersionBind,
    RedisPing,
}

impl ServiceProbe {
    pub fn needs_payload(self) -> bool {
        !matches!(self, ServiceProbe::Banner)
    }
    pub fn label(self) -> &'static str {
        match self {
            ServiceProbe::Banner => "banner",
            ServiceProbe::HttpGet => "http_get",
            ServiceProbe::HttpOptions => "http_options",
            ServiceProbe::TlsHello => "tls_client_hello",
            ServiceProbe::DnsVersionBind => "dns_version_bind",
            ServiceProbe::RedisPing => "redis_ping",
        }
    }
}

/// Port-directed probe order. Mirrors the probe database's `ports`/`sslports`
/// hints with a bounded registry: TLS-first on TLS ports (a TLS 1.2 hello is
/// offered so the certificate stays plaintext), banner-first elsewhere, HTTP
/// fallbacks for likely-web ports.
pub fn probe_registry_for_port(port: u16) -> &'static [ServiceProbe] {
    const TLS: &[ServiceProbe] = &[ServiceProbe::TlsHello, ServiceProbe::HttpGet];
    const WEB: &[ServiceProbe] = &[ServiceProbe::HttpGet, ServiceProbe::HttpOptions];
    const BANNER: &[ServiceProbe] = &[ServiceProbe::Banner];
    const BANNER_REDIS: &[ServiceProbe] = &[ServiceProbe::Banner, ServiceProbe::RedisPing];
    const BANNER_DNS: &[ServiceProbe] = &[ServiceProbe::Banner, ServiceProbe::DnsVersionBind];
    match port {
        443 | 8443 => TLS,
        80 | 8000 | 8080 | 8888 => WEB,
        53 => BANNER_DNS,
        6379 => BANNER_REDIS,
        // FTP(21), SSH(22), SMTP(25), POP3(110), IMAP(143), MySQL(3306) all
        // greet on connect; other ports get one polite banner read too.
        _ => BANNER,
    }
}

/// Build the payload for one probe. `nonce` supplies OS-random bytes so the
/// TLS ClientHello and DNS transaction id are never constant across runs.
pub fn probe_payload(probe: ServiceProbe, nonce: &[u8; 32]) -> Vec<u8> {
    match probe {
        ServiceProbe::Banner => Vec::new(),
        ServiceProbe::HttpGet => b"GET / HTTP/1.0\r\n\r\n".to_vec(),
        ServiceProbe::HttpOptions => b"OPTIONS / HTTP/1.0\r\n\r\n".to_vec(),
        ServiceProbe::RedisPing => b"*1\r\n$4\r\nPING\r\n".to_vec(),
        ServiceProbe::DnsVersionBind => {
            dns_version_bind_query(u16::from_be_bytes([nonce[0], nonce[1]])).to_vec()
        }
        ServiceProbe::TlsHello => tls_client_hello(nonce),
    }
}

/// DNS-over-TCP `version.bind TXT CHAOS` query. The transaction id comes from
/// caller-provided randomness so replies can be correlated.
pub fn dns_version_bind_query(id: u16) -> [u8; 32] {
    let mut query = [0u8; 32];
    query[0..2].copy_from_slice(&30u16.to_be_bytes()); // TCP length prefix
    query[2..4].copy_from_slice(&id.to_be_bytes());
    query[4..6].copy_from_slice(&0x0100u16.to_be_bytes()); // recursion desired
    query[6..8].copy_from_slice(&1u16.to_be_bytes()); // one question
                                                      // 07 "version" 04 "bind" 00, type TXT (0x0010), class CHAOS (0x0003)
    query[12] = 7;
    query[13..20].copy_from_slice(b"version");
    query[20] = 4;
    query[21..25].copy_from_slice(b"bind");
    query[26..28].copy_from_slice(&0x0010u16.to_be_bytes());
    query[28..30].copy_from_slice(&0x0003u16.to_be_bytes());
    query
}

/// Minimal TLS 1.2-compatible ClientHello. Offering only TLS-1.2-era cipher
/// suites and no supported_versions extension keeps the server below TLS 1.3,
/// where the certificate is encrypted and could not be read without a TLS
/// stack. No SNI extension: the probed hostname is deliberately not leaked
/// into the payload.
pub fn tls_client_hello(nonce: &[u8; 32]) -> Vec<u8> {
    // handshake body: version(2) + random(32) + session_id_len(1)
    //   + cipher_suites(2 + 8) + compression(2) + extensions_len(2)
    const BODY_LEN: usize = 2 + 32 + 1 + 2 + 8 + 2 + 2;
    const RECORD_LEN: usize = 4 + BODY_LEN; // handshake header + body
    let mut hello = Vec::with_capacity(5 + RECORD_LEN);
    hello.extend_from_slice(&[0x16, 0x03, 0x01]); // handshake, TLS 1.0 record version
    hello.extend_from_slice(&(RECORD_LEN as u16).to_be_bytes());
    hello.extend_from_slice(&[0x01]); // ClientHello
    hello.extend_from_slice(&(BODY_LEN as u32).to_be_bytes()[1..]);
    hello.extend_from_slice(&[0x03, 0x03]); // client_version TLS 1.2
    hello.extend_from_slice(nonce);
    hello.push(0x00); // empty session id
    hello.extend_from_slice(&8u16.to_be_bytes());
    // TLS 1.2 cipher suites only: ECDHE_RSA_AES_128/256_CBC_SHA,
    // RSA_AES_128/256_CBC_SHA.
    hello.extend_from_slice(&[0xc0, 0x13, 0xc0, 0x14, 0x00, 0x2f, 0x00, 0x35]);
    hello.extend_from_slice(&[0x01, 0x00]); // compression: null
    hello.extend_from_slice(&[0x00, 0x00]); // empty extensions
    hello
}

/// One conservative classification of a probe response. `soft` marks a
/// softmatch (weaker evidence, e.g. any 220 greeting implies FTP-like text
/// service); `claim` is an UNVERIFIED remote software/version assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceMatch {
    pub service: &'static str,
    pub soft: bool,
    pub claim: Option<String>,
}

/// Reduce raw response bytes to an honest trimmed excerpt: printable ASCII is
/// kept, control bytes become spaces, non-ASCII becomes '?', and the result is
/// capped so hostile banners cannot flood UI or case storage.
pub fn sanitize_excerpt(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().min(MAX_SERVICE_EXCERPT));
    for &b in bytes.iter().take(MAX_SERVICE_EXCERPT) {
        match b {
            0x20..=0x7e => text.push(b as char),
            0x09 | 0x0a | 0x0d => text.push(' '),
            _ => text.push('?'),
        }
    }
    text.trim_end().to_string()
}

fn sanitize_claim(bytes: &[u8]) -> Option<String> {
    let text = sanitize_excerpt(bytes);
    if text.is_empty() || text.len() > MAX_SERVICE_CLAIM || text.chars().all(|c| c == '?') {
        return None;
    }
    Some(text)
}

fn first_line(response: &[u8]) -> &[u8] {
    let end = response
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(response.len());
    let line = &response[..end];
    match line.last() {
        Some(b'\r') => &line[..line.len() - 1],
        _ => line,
    }
}

fn contains_ci(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

/// Known product claims for 220-style text greetings. A tiny hand-written
/// table replaces nmap's regex database; absence from this table means no
/// claim, never a guess.
fn greeting_claim(banner: &[u8]) -> Option<String> {
    const PRODUCTS: &[(&[u8], &str)] = &[
        (b"vsftpd", "vsftpd"),
        (b"ProFTPD", "ProFTPD"),
        (b"FileZilla", "FileZilla Server"),
        (b"Pure-FTPd", "Pure-FTPd"),
        (b"Postfix", "Postfix"),
        (b"Exim", "Exim"),
        (b"Sendmail", "Sendmail"),
        (b"Microsoft ESMTP", "IIS SMTP"),
    ];
    for (needle, product) in PRODUCTS {
        if contains_ci(banner, needle) {
            return Some((*product).to_string());
        }
    }
    None
}

fn http_server_claim(response: &[u8]) -> Option<String> {
    // Scan only the header block (bounded), case-insensitive "server:".
    let head: &[u8] = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| &response[..i])
        .unwrap_or(&response[..response.len().min(2 * 1024)]);
    let mut cursor = 0usize;
    while let Some(line_end) = head[cursor..].iter().position(|&b| b == b'\n') {
        let line = &head[cursor..cursor + line_end];
        cursor += line_end + 1;
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            if line[..colon].eq_ignore_ascii_case(b"server") {
                let value = &line[colon + 1..];
                let value = value
                    .strip_prefix(b" ")
                    .or_else(|| value.strip_prefix(b"\t"))
                    .unwrap_or(value);
                return sanitize_claim(value);
            }
        }
    }
    None
}

/// MySQL server greeting: 3-byte little-endian payload length, sequence 0,
/// then a protocol byte (10 = handshake v10, 0/1 = legacy) followed by a
/// NUL-terminated server version string. 0xff is an error packet; nmap also
/// identifies MySQL from those when the text names the server.
fn mysql_greeting(response: &[u8]) -> Option<ServiceMatch> {
    if response.len() < 5 || response[3] != 0 {
        return None;
    }
    // The 3-byte little-endian payload length must describe the actual bytes
    // received; otherwise this is not a MySQL framing at all.
    let payload_len =
        usize::from(response[0]) | usize::from(response[1]) << 8 | usize::from(response[2]) << 16;
    if payload_len < 1 || 4 + payload_len > response.len() {
        return None;
    }
    let protocol = response[4];
    if protocol == 0xff {
        if contains_ci(response, b"MySQL") || contains_ci(response, b"MariaDB") {
            return Some(ServiceMatch {
                service: "mysql",
                soft: false,
                claim: None,
            });
        }
        return None;
    }
    if protocol == 10 || protocol == 0 || protocol == 1 {
        let version_end = response[5..]
            .iter()
            .position(|&b| b == 0)
            .map(|i| 5 + i)
            .unwrap_or(response.len());
        let claim = sanitize_claim(&response[5..version_end]);
        // A v10 greeting without a plausible version string is still MySQL.
        return Some(ServiceMatch {
            service: "mysql",
            soft: false,
            claim,
        });
    }
    None
}

/// Extract the LAST commonName in a DER certificate. The subject comes after
/// the issuer in X.509, so the final 2.5.4.3 attribute is the subject CN in
/// well-formed certificates; this bounded scan is a claim, not a parser
/// guarantee.
fn certificate_subject_cn(cert: &[u8]) -> Option<String> {
    let mut found: Option<String> = None;
    let mut cursor = 0usize;
    while cursor + 7 <= cert.len() {
        if cert[cursor..cursor + 5] == [0x06, 0x03, 0x55, 0x04, 0x03] {
            let tag = cert[cursor + 5];
            if tag == 0x0c || tag == 0x13 || tag == 0x1a {
                let length = usize::from(cert[cursor + 6]);
                if length > 0 && cursor + 7 + length <= cert.len() && length <= MAX_SERVICE_CLAIM {
                    if let Some(claim) = sanitize_claim(&cert[cursor + 7..cursor + 7 + length]) {
                        found = Some(claim);
                    }
                }
            }
        }
        cursor += 1;
    }
    found
}

/// Walk the TLS record/handshake stream after a ServerHello to find a
/// plaintext Certificate handshake (TLS 1.2 and below only).
fn tls_certificate_after_server_hello(response: &[u8]) -> Option<String> {
    let mut cursor = 0usize;
    let mut handshake = None;
    let mut saw_server_hello = false;
    // Bounded walk over records.
    while cursor + 5 <= response.len() && handshake.is_none() {
        if response[cursor] != 0x16 {
            break;
        }
        let record_len = usize::from(be16(&response[cursor + 3..cursor + 5])?);
        let body_start = cursor + 5;
        let body_end = body_start.checked_add(record_len)?;
        if body_end > response.len() {
            // Truncated final record: work with what arrived.
            break;
        }
        let mut inner = body_start;
        while inner + 4 <= body_end {
            let hand_type = response[inner];
            let length = usize::from(response[inner + 1]) << 16
                | usize::from(be16(&response[inner + 2..inner + 4])?);
            let start = inner + 4;
            let end = start.checked_add(length)?;
            if end > body_end {
                return None;
            }
            if hand_type == 0x02 {
                saw_server_hello = true;
            } else if hand_type == 0x0b && saw_server_hello {
                handshake = Some(&response[start..end]);
                break;
            } else if saw_server_hello {
                // Any other handshake after ServerHello (e.g. ServerHelloDone)
                // means no certificate is coming in this flight.
                return None;
            }
            inner = end;
        }
        cursor = body_end;
    }
    let certificates = handshake?;
    if certificates.len() < 6 {
        return None;
    }
    let cert_len = usize::from(be16(&certificates[3..5])?) << 8 | usize::from(certificates[5]);
    // certificates: total_len(3) + first cert len(3) + bytes
    if cert_len == 0 || 6 + cert_len > certificates.len() || cert_len > 64 * 1024 {
        return None;
    }
    certificate_subject_cn(&certificates[6..6 + cert_len])
}

/// Classify one probe response. Returns `None` when the response carries no
/// interpretable evidence for the probe, letting the caller try the next
/// registry entry. All claims are remote assertions, never verified facts.
pub fn classify_service_response(probe: ServiceProbe, response: &[u8]) -> Option<ServiceMatch> {
    if response.is_empty() {
        return None;
    }
    match probe {
        ServiceProbe::Banner => {
            let line = first_line(response);
            if line.starts_with(b"SSH-") {
                // e.g. "SSH-2.0-OpenSSH_9.6": the software token after the
                // protocol version is the unverified claim.
                let rest = &line[4..];
                let claim = rest
                    .iter()
                    .position(|&b| b == b'-')
                    .map(|i| &rest[i + 1..])
                    .map(|token| {
                        &token[..token.iter().position(|&b| b == b' ').unwrap_or(token.len())]
                    })
                    .and_then(sanitize_claim);
                return Some(ServiceMatch {
                    service: "ssh",
                    soft: false,
                    claim,
                });
            }
            if line.starts_with(b"+OK") {
                return Some(ServiceMatch {
                    service: "pop3",
                    soft: false,
                    claim: None,
                });
            }
            if line.starts_with(b"* OK") || line.starts_with(b"* BYE") {
                return Some(ServiceMatch {
                    service: "imap",
                    soft: line.starts_with(b"* BYE"),
                    claim: None,
                });
            }
            if line.starts_with(b"220 ") || line.starts_with(b"220-") {
                // Text protocols often share the 220 greeting. SMTP is named
                // in its banner; FTP gets nmap's softmatch otherwise.
                if contains_ci(line, b"SMTP") || contains_ci(line, b"ESMTP") {
                    return Some(ServiceMatch {
                        service: "smtp",
                        soft: false,
                        claim: greeting_claim(line),
                    });
                }
                if contains_ci(line, b"FTP") {
                    return Some(ServiceMatch {
                        service: "ftp",
                        soft: false,
                        claim: greeting_claim(line),
                    });
                }
                return Some(ServiceMatch {
                    service: "ftp",
                    soft: true,
                    claim: None,
                });
            }
            if let Some(mysql) = mysql_greeting(response) {
                return Some(mysql);
            }
            // Printable banner without a known protocol shape: honest unknown.
            if !line.is_empty()
                && line
                    .iter()
                    .all(|&b| (0x20..=0x7e).contains(&b) || matches!(b, b'\t' | b'\r'))
            {
                return Some(ServiceMatch {
                    service: "unknown",
                    soft: true,
                    claim: None,
                });
            }
            None
        }
        ServiceProbe::HttpGet | ServiceProbe::HttpOptions => {
            if response.starts_with(b"HTTP/") {
                return Some(ServiceMatch {
                    service: "http",
                    soft: false,
                    claim: http_server_claim(response),
                });
            }
            None
        }
        ServiceProbe::TlsHello => {
            // TLS alert record: a TLS endpoint rejected the handshake, which
            // is itself service evidence without a software claim.
            if response[0] == 0x15 && response.len() >= 6 {
                return Some(ServiceMatch {
                    service: "ssl",
                    soft: true,
                    claim: None,
                });
            }
            if response[0] == 0x16 && response.len() >= 9 && response[5] == 0x02 {
                let claim = tls_certificate_after_server_hello(response);
                return Some(ServiceMatch {
                    service: "ssl",
                    soft: false,
                    claim,
                });
            }
            None
        }
        ServiceProbe::DnsVersionBind => classify_dns_version_bind(response),
        ServiceProbe::RedisPing => {
            if response.starts_with(b"+PONG") {
                return Some(ServiceMatch {
                    service: "redis",
                    soft: false,
                    claim: None,
                });
            }
            // RESP error replies ("-ERR ...", "-NOAUTH ...") still identify a
            // RESP speaker, but only as a softmatch.
            if response[0] == b'-' {
                return Some(ServiceMatch {
                    service: "redis",
                    soft: true,
                    claim: None,
                });
            }
            None
        }
    }
}

fn classify_dns_version_bind(response: &[u8]) -> Option<ServiceMatch> {
    // Strip the DNS-over-TCP length prefix when present.
    let dns = if response.len() >= 14 && usize::from(be16(&response[..2])?) == response.len() - 2 {
        &response[2..]
    } else {
        response
    };
    if dns.len() < 12 || dns[2] & 0x80 == 0 {
        return None; // QR bit must be set: only responses classify.
    }
    const QUESTION: &[u8] = b"\x07version\x04bind\x00";
    let question_at = dns
        .windows(QUESTION.len())
        .position(|w| w == QUESTION)
        .map(|i| i + QUESTION.len())?;
    // Skip the question's type (TXT) and class (CHAOS) to reach the answer
    // section, then walk one answer record.
    let mut cursor = question_at.saturating_add(4);
    let mut answer = None;
    while cursor + 10 <= dns.len() && answer.is_none() {
        // Skip one name: compression pointer (0xc0..) or label chain ending 0.
        if dns[cursor] & 0xc0 == 0xc0 {
            cursor += 2;
        } else {
            while cursor < dns.len() && dns[cursor] != 0 && dns[cursor] & 0xc0 != 0xc0 {
                cursor += 1 + usize::from(dns[cursor]);
            }
            cursor += 1;
        }
        if cursor + 10 > dns.len() {
            break;
        }
        let r#type = be16(&dns[cursor..cursor + 2])?;
        let class = be16(&dns[cursor + 2..cursor + 4])?;
        let rdlength = usize::from(be16(&dns[cursor + 8..cursor + 10])?);
        if r#type == 0x0010
            && class == 0x0003
            && rdlength >= 1
            && cursor + 10 + rdlength <= dns.len()
        {
            let rdata = &dns[cursor + 10..cursor + 10 + rdlength];
            let text_len = usize::from(rdata[0]);
            if text_len > 0 && 1 + text_len <= rdata.len() {
                answer = sanitize_claim(&rdata[1..1 + text_len]);
            }
            break;
        }
        cursor += 10 + rdlength;
    }
    Some(ServiceMatch {
        service: "domain",
        soft: answer.is_none(),
        claim: answer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip4(value: &str) -> Ipv4Addr {
        value.parse().expect("test address")
    }
    fn nonce() -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = (i * 7 + 3) as u8;
        }
        bytes
    }

    // -- frame builders -----------------------------------------------------

    #[test]
    fn scan_kinds_use_documented_flag_combinations() {
        assert_eq!(ScanKind::Fin.tcp_flags(), 0x01);
        assert_eq!(ScanKind::Null.tcp_flags(), 0x00);
        assert_eq!(ScanKind::Xmas.tcp_flags(), 0x29);
        assert_eq!(ScanKind::Ack.tcp_flags(), 0x10);
        assert_eq!(ScanKind::Window.tcp_flags(), 0x10);
        assert_eq!(ScanKind::parse("xmas"), Some(ScanKind::Xmas));
        assert_eq!(ScanKind::parse("syn"), None);
    }

    #[test]
    fn flag_probe_headers_and_both_checksums_are_correct() {
        let local = ip4("192.0.2.1");
        let target = ip4("192.0.2.2");
        for kind in [
            ScanKind::Fin,
            ScanKind::Null,
            ScanKind::Xmas,
            ScanKind::Ack,
            ScanKind::Window,
        ] {
            let packet = ipv4_tcp_scan_probe(local, target, 40000, 443, kind, 0x11223344, 7, 64)
                .expect("valid probe");
            assert_eq!(packet.len(), 40);
            assert_eq!(packet[0], 0x45);
            assert_eq!(&packet[2..4], &40u16.to_be_bytes());
            assert_eq!(packet[9], 6);
            assert_eq!(packet[33], kind.tcp_flags());
            assert_eq!(checksum(&[&packet[..20]]), 0);
            let mut pseudo = [0u8; 12];
            pseudo[..4].copy_from_slice(&local.octets());
            pseudo[4..8].copy_from_slice(&target.octets());
            pseudo[9] = 6;
            pseudo[10..12].copy_from_slice(&20u16.to_be_bytes());
            assert_eq!(checksum(&[&pseudo, &packet[20..]]), 0);
        }
    }

    #[test]
    fn probe_builders_refuse_non_unicast_targets_and_bad_headers() {
        let local = ip4("192.0.2.1");
        assert_eq!(
            ipv4_tcp_scan_probe(
                Ipv4Addr::UNSPECIFIED,
                local,
                40000,
                80,
                ScanKind::Fin,
                1,
                1,
                64
            ),
            Err(PacketBuildError::InvalidAddress)
        );
        assert_eq!(
            ipv4_tcp_scan_probe(local, ip4("224.0.0.1"), 40000, 80, ScanKind::Fin, 1, 1, 64),
            Err(PacketBuildError::InvalidAddress)
        );
        assert_eq!(
            ipv4_tcp_scan_probe(local, local, 0, 80, ScanKind::Fin, 1, 1, 64),
            Err(PacketBuildError::InvalidPort)
        );
        assert_eq!(
            ipv4_tcp_scan_probe(local, local, 40000, 0, ScanKind::Ack, 1, 1, 64),
            Err(PacketBuildError::InvalidPort)
        );
        assert_eq!(
            ipv4_tcp_scan_probe(local, local, 40000, 80, ScanKind::Fin, 1, 1, 0),
            Err(PacketBuildError::InvalidHopLimit)
        );
    }

    #[test]
    fn ethernet_probe_frames_mac_and_ethertype_then_inner_ipv4() {
        let mac = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let frame = ethernet_ipv4_tcp_scan_probe(
            mac,
            mac,
            ip4("192.0.2.1"),
            ip4("192.0.2.2"),
            40000,
            22,
            ScanKind::Xmas,
            9,
            1,
            64,
        )
        .expect("valid frame");
        assert_eq!(frame.len(), 54);
        assert_eq!(&frame[..6], &mac);
        assert_eq!(&frame[6..12], &mac);
        assert_eq!(&frame[12..14], &0x0800u16.to_be_bytes());
        // IPv4 header ends at 14 + 20; TCP flags live 13 bytes into the TCP header.
        assert_eq!(frame[14 + 20 + 13], ScanKind::Xmas.tcp_flags());
        assert!(ethernet_ipv4_tcp_scan_probe(
            [0xff; 6],
            mac,
            ip4("192.0.2.1"),
            ip4("192.0.2.2"),
            40000,
            22,
            ScanKind::Fin,
            9,
            1,
            64
        )
        .is_err());
        assert!(ethernet_ipv4_tcp_scan_probe(
            mac,
            [0; 6],
            ip4("192.0.2.1"),
            ip4("192.0.2.2"),
            40000,
            22,
            ScanKind::Fin,
            9,
            1,
            64
        )
        .is_err());
    }

    // -- reply classification ----------------------------------------------

    fn probe_key() -> ProbeKey {
        ProbeKey {
            local: ip4("192.0.2.1"),
            target: ip4("192.0.2.2"),
            local_port: 40000,
            target_port: 443,
            sequence: 0x11223344,
        }
    }
    fn rst_frame(window: u16) -> Vec<u8> {
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&443u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&40000u16.to_be_bytes());
        tcp[8..12].copy_from_slice(&1u32.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = 0x04 | 0x10; // RST+ACK as stacks answer a probe segment
        tcp[14..16].copy_from_slice(&window.to_be_bytes());
        bare_ipv4(6, [192, 0, 2, 2], [192, 0, 2, 1], &tcp)
    }
    fn bare_ipv4(protocol: u8, src: [u8; 4], dst: [u8; 4], body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; 20 + body.len()];
        bytes[0] = 0x45;
        let size = u16::try_from(bytes.len()).expect("test packet fits u16");
        bytes[2..4].copy_from_slice(&size.to_be_bytes());
        bytes[9] = protocol;
        bytes[12..16].copy_from_slice(&src);
        bytes[16..20].copy_from_slice(&dst);
        bytes[20..].copy_from_slice(body);
        bytes
    }
    fn icmp_unreachable_frame() -> Vec<u8> {
        let original = ipv4_tcp_scan_probe(
            ip4("192.0.2.1"),
            ip4("192.0.2.2"),
            40000,
            443,
            ScanKind::Fin,
            0x11223344,
            9,
            64,
        )
        .expect("probe");
        let mut error = vec![3u8, 1, 0, 0, 0, 0, 0, 0];
        error.extend_from_slice(&original);
        bare_ipv4(1, [192, 0, 2, 254], [192, 0, 2, 1], &error)
    }

    #[test]
    fn reply_matrix_matches_documented_scan_semantics() {
        for kind in [ScanKind::Fin, ScanKind::Null, ScanKind::Xmas] {
            assert_eq!(
                classify_reply(kind, Some(ProbeReply::TcpReset { window: 0 })),
                PortState::Closed
            );
            assert_eq!(classify_reply(kind, None), PortState::OpenFiltered);
        }
        assert_eq!(
            classify_reply(ScanKind::Ack, Some(ProbeReply::TcpReset { window: 0 })),
            PortState::Unfiltered
        );
        assert_eq!(classify_reply(ScanKind::Ack, None), PortState::Filtered);
        assert_eq!(
            classify_reply(ScanKind::Window, Some(ProbeReply::TcpReset { window: 512 })),
            PortState::Open
        );
        assert_eq!(
            classify_reply(ScanKind::Window, Some(ProbeReply::TcpReset { window: 0 })),
            PortState::Closed
        );
        assert_eq!(classify_reply(ScanKind::Window, None), PortState::Filtered);
        for kind in [
            ScanKind::Fin,
            ScanKind::Null,
            ScanKind::Xmas,
            ScanKind::Ack,
            ScanKind::Window,
        ] {
            assert_eq!(
                classify_reply(
                    kind,
                    Some(ProbeReply::IcmpUnreachable {
                        icmp_kind: 3,
                        code: 1
                    })
                ),
                PortState::Filtered
            );
        }
    }

    #[test]
    fn frame_classifier_reads_rst_window_and_rejects_nonmatching_traffic() {
        let key = probe_key();
        assert_eq!(
            classify_frame(ScanKind::Window, &rst_frame(1024), &key),
            Some(ProbeReply::TcpReset { window: 1024 })
        );
        assert_eq!(
            classify_frame(ScanKind::Ack, &rst_frame(0), &key),
            Some(ProbeReply::TcpReset { window: 0 })
        );
        // Ethernet framing with two VLAN tags still classifies: MACs (12),
        // 0x8100 + TCI, 0x88a8 + TCI, real 0x0800 ethertype, then IPv4.
        let mut vlan = vec![
            0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        ];
        vlan.extend_from_slice(&[0x81, 0x00, 0x00, 0x0a, 0x88, 0xa8, 0x00, 0x01]);
        vlan.extend_from_slice(&0x0800u16.to_be_bytes());
        vlan.extend_from_slice(&rst_frame(64));
        assert_eq!(
            classify_frame(ScanKind::Fin, &vlan, &key),
            Some(ProbeReply::TcpReset { window: 64 })
        );
        // SYN-ACK is not evidence for these scan types.
        let mut synack = rst_frame(0);
        synack[20 + 13] = 0x12;
        assert_eq!(classify_frame(ScanKind::Fin, &synack, &key), None);
        // Wrong ports and truncated frames are refused.
        assert_eq!(
            classify_frame(ScanKind::Fin, &rst_frame(0)[..30], &key),
            None
        );
        let mut wrong_ports = rst_frame(0);
        wrong_ports[20 + 1] = 0x00; // reply source port 443 -> 256
        assert_eq!(classify_frame(ScanKind::Fin, &wrong_ports, &key), None);
        // Fragmented replies are never classified.
        let mut fragmented = rst_frame(0);
        fragmented[6..8].copy_from_slice(&0x2001u16.to_be_bytes());
        assert_eq!(classify_frame(ScanKind::Fin, &fragmented, &key), None);
    }

    #[test]
    fn icmp_unreachable_requires_exact_quoted_probe_identity() {
        let key = probe_key();
        assert_eq!(
            classify_frame(ScanKind::Fin, &icmp_unreachable_frame(), &key),
            Some(ProbeReply::IcmpUnreachable {
                icmp_kind: 3,
                code: 1
            })
        );
        let mut wrong_sequence = probe_key();
        wrong_sequence.sequence = 1;
        assert_eq!(
            classify_frame(ScanKind::Fin, &icmp_unreachable_frame(), &wrong_sequence),
            None
        );
        let mut echo_instead = icmp_unreachable_frame();
        echo_instead[20] = 8; // echo request is not an error
        assert_eq!(classify_frame(ScanKind::Fin, &echo_instead, &key), None);
        let mut truncated = icmp_unreachable_frame();
        truncated.truncate(20 + 8 + 24);
        assert_eq!(classify_frame(ScanKind::Fin, &truncated, &key), None);
    }

    // -- bounded plan runner over a fixture link -----------------------------

    /// A link fixture that answers each sent probe with a crafted response
    /// built from the ACTUAL sent bytes, so correlation keys (ports, sequence)
    /// always match without predicting the runner's random identities.
    struct FixtureLink {
        /// Factory for the response to each probe: receives the sent IPv4
        /// packet. Returning None simulates silence.
        respond: Box<dyn FnMut(&[u8]) -> Option<Vec<u8>>>,
        replies: std::collections::VecDeque<Vec<u8>>,
        sent: usize,
    }
    impl RawProbeLink for FixtureLink {
        fn send_probe(&mut self, packet: &[u8], _target: Ipv4Addr) -> Result<(), DepthScanError> {
            self.sent += 1;
            if let Some(reply) = (self.respond)(packet) {
                self.replies.push_back(reply);
            }
            Ok(())
        }
        fn receive_frame(
            &mut self,
            buffer: &mut [u8],
            _timeout: Duration,
        ) -> Result<Option<usize>, DepthScanError> {
            let Some(frame) = self.replies.pop_front() else {
                return Ok(None);
            };
            let n = frame.len().min(buffer.len());
            buffer[..n].copy_from_slice(&frame[..n]);
            Ok(Some(n))
        }
        fn source_address(&self) -> Ipv4Addr {
            ip4("192.0.2.1")
        }
    }
    /// Craft a matching RST to a sent probe packet: swap the 4-tuple and quote
    /// the probe's sequence in the acknowledgment, like a real TCP stack.
    fn rst_reply_to(sent: &[u8], window: u16) -> Vec<u8> {
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&sent[22..24]); // reply src = probe dst port
        tcp[2..4].copy_from_slice(&sent[20..22]); // reply dst = probe src port
        tcp[8..12].copy_from_slice(
            &u32::from_be_bytes(sent[28..32].try_into().expect("seq"))
                .wrapping_add(1)
                .to_be_bytes(),
        );
        tcp[12] = 0x50;
        tcp[13] = 0x04 | 0x10; // RST+ACK
        tcp[14..16].copy_from_slice(&window.to_be_bytes());
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        let size = u16::try_from(20 + tcp.len()).expect("fixture size");
        ip[2..4].copy_from_slice(&size.to_be_bytes());
        ip[9] = 6;
        ip[12..16].copy_from_slice(&sent[16..20]); // reply src = probe target
        ip[16..20].copy_from_slice(&sent[12..16]); // reply dst = probe source
        let mut frame = ip;
        frame.extend_from_slice(&tcp);
        frame
    }
    /// Craft an ICMPv4 host-unreachable that quotes the entire sent probe.
    fn icmp_unreachable_reply_to(sent: &[u8]) -> Vec<u8> {
        let mut icmp = vec![3u8, 1, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(sent);
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        let size = u16::try_from(20 + icmp.len()).expect("fixture size");
        ip[2..4].copy_from_slice(&size.to_be_bytes());
        ip[9] = 1;
        ip[12..16].copy_from_slice(&[198, 51, 100, 254]); // upstream router
        ip[16..20].copy_from_slice(&sent[12..16]);
        let mut frame = ip;
        frame.extend_from_slice(&icmp);
        frame
    }
    fn silent_link() -> FixtureLink {
        FixtureLink {
            respond: Box::new(|_| None),
            replies: Default::default(),
            sent: 0,
        }
    }

    #[test]
    fn plan_runner_classifies_matching_rst_then_documented_silence() {
        // Window scan: ONLY the first probe is answered with a matching-tuple
        // RST carrying a nonzero window (open claim); later probes stay
        // silent, which Window scan must classify as filtered.
        let mut remaining = 1;
        let mut link = FixtureLink {
            respond: Box::new(move |sent| {
                if remaining > 0 {
                    remaining -= 1;
                    Some(rst_reply_to(sent, 1024))
                } else {
                    None
                }
            }),
            replies: Default::default(),
            sent: 0,
        };
        let stop = AtomicBool::new(false);
        let hosts = [ip4("192.0.2.2")];
        let progress = std::sync::atomic::AtomicUsize::new(0);
        let findings = run_flag_probe_plan(
            &mut link,
            ScanKind::Window,
            1500,
            &hosts,
            &[22, 80],
            &stop,
            &|| true,
            &|done, total| {
                assert_eq!(total, 2);
                progress.store(done, std::sync::atomic::Ordering::Release);
            },
        )
        .expect("bounded plan");
        assert_eq!(progress.load(std::sync::atomic::Ordering::Acquire), 2);
        assert_eq!(findings.len(), 2);
        // The first probe consumed the crafted RST for its exact 4-tuple.
        assert_eq!(findings[0].state, PortState::Open);
        assert_eq!(findings[0].reason, "tcp_rst_matching_tuple");
        assert_eq!(findings[1].state, PortState::Filtered);
        assert_eq!(findings[1].reason, "no_response_default_filtered");
    }

    #[test]
    fn fin_scan_silence_is_openfiltered_and_rst_is_closed() {
        let mut remaining = 1;
        let mut link = FixtureLink {
            respond: Box::new(move |sent| {
                if remaining > 0 {
                    remaining -= 1;
                    Some(rst_reply_to(sent, 0))
                } else {
                    None
                }
            }),
            replies: Default::default(),
            sent: 0,
        };
        let stop = AtomicBool::new(false);
        let hosts = [ip4("192.0.2.2")];
        let findings = run_flag_probe_plan(
            &mut link,
            ScanKind::Fin,
            1500,
            &hosts,
            &[443, 8443],
            &stop,
            &|| true,
            &|_, _| {},
        )
        .expect("bounded plan");
        assert_eq!(findings[0].state, PortState::Closed);
        assert_eq!(findings[1].state, PortState::OpenFiltered);
        assert_eq!(findings[1].reason, "no_response_default_openfiltered");
    }

    #[test]
    fn icmp_unreachable_classifies_every_kind_as_filtered() {
        for kind in [
            ScanKind::Fin,
            ScanKind::Null,
            ScanKind::Xmas,
            ScanKind::Ack,
            ScanKind::Window,
        ] {
            let mut link = FixtureLink {
                respond: Box::new(|sent| Some(icmp_unreachable_reply_to(sent))),
                replies: Default::default(),
                sent: 0,
            };
            let stop = AtomicBool::new(false);
            let findings = run_flag_probe_plan(
                &mut link,
                kind,
                1500,
                &[ip4("192.0.2.2")],
                &[993],
                &stop,
                &|| true,
                &|_, _| {},
            )
            .expect("bounded plan");
            assert_eq!(findings[0].state, PortState::Filtered, "{kind:?}");
            assert_eq!(findings[0].reason, "icmp_ipv4_unreachable");
        }
    }

    #[test]
    fn progress_counts_every_probe_exactly_once() {
        let mut link = silent_link();
        let stop = AtomicBool::new(false);
        let last = std::sync::atomic::AtomicUsize::new(0);
        let hosts = [ip4("192.0.2.2"), ip4("192.0.2.3")];
        let findings = run_flag_probe_plan(
            &mut link,
            ScanKind::Xmas,
            1500,
            &hosts,
            &[25, 587],
            &stop,
            &|| true,
            &|done, total| {
                last.store(done * 1000 + total, std::sync::atomic::Ordering::Release);
            },
        )
        .expect("bounded plan");
        assert_eq!(findings.len(), 4);
        assert_eq!(
            last.load(std::sync::atomic::Ordering::Acquire),
            4 * 1000 + 4
        );
        assert_eq!(link.sent, 4);
    }

    #[test]
    fn plan_runner_rejects_oversize_empty_and_zero_port_plans() {
        let mut link = silent_link();
        let stop = AtomicBool::new(false);
        let host = ip4("192.0.2.2");
        let scope = &|| true;
        let progress = &|_, _| {};
        assert!(run_flag_probe_plan(
            &mut link,
            ScanKind::Fin,
            1500,
            &[],
            &[80],
            &stop,
            scope,
            progress
        )
        .is_err());
        assert!(run_flag_probe_plan(
            &mut link,
            ScanKind::Fin,
            1500,
            &[host],
            &[],
            &stop,
            scope,
            progress
        )
        .is_err());
        assert!(run_flag_probe_plan(
            &mut link,
            ScanKind::Fin,
            1500,
            &vec![host; 33],
            &[80],
            &stop,
            scope,
            progress
        )
        .is_err());
        assert!(run_flag_probe_plan(
            &mut link,
            ScanKind::Fin,
            1500,
            &[host],
            &vec![1u16; 129],
            &stop,
            scope,
            progress
        )
        .is_err());
        assert!(run_flag_probe_plan(
            &mut link,
            ScanKind::Fin,
            1500,
            &[host],
            &[0],
            &stop,
            scope,
            progress
        )
        .is_err());
        assert!(run_flag_probe_plan(
            &mut link,
            ScanKind::Fin,
            1500,
            &vec![host; 32],
            &vec![80u16; 128],
            &stop,
            scope,
            progress
        )
        .is_err());
        assert_eq!(link.sent, 0);
    }

    #[test]
    fn revoked_scope_or_stop_never_sends_a_probe() {
        let mut link = silent_link();
        let stopped = AtomicBool::new(true);
        let err = run_flag_probe_plan(
            &mut link,
            ScanKind::Null,
            1500,
            &[ip4("192.0.2.2")],
            &[80],
            &stopped,
            &|| true,
            &|_, _| {},
        )
        .unwrap_err();
        assert_eq!(err.code, DepthErrorCode::Cancelled);
        let err = run_flag_probe_plan(
            &mut link,
            ScanKind::Null,
            1500,
            &[ip4("192.0.2.2")],
            &[80],
            &AtomicBool::new(false),
            &|| false,
            &|_, _| {},
        )
        .unwrap_err();
        assert_eq!(err.code, DepthErrorCode::Cancelled);
        assert_eq!(link.sent, 0);
    }

    #[test]
    fn public_entry_reports_unsupported_off_linux() {
        // On Linux this would open real sockets, so only assert the
        // non-Linux structured error path; the Linux path is exercised by the
        // fixture-based plan tests above plus the platform's own integration.
        if !cfg!(target_os = "linux") {
            let err = scan_ipv4_depth(
                "eth0",
                ScanKind::Fin,
                &[ip4("192.0.2.2")],
                &[80],
                &AtomicBool::new(false),
                &|| true,
                &|_, _| {},
            )
            .unwrap_err();
            assert_eq!(err.code, DepthErrorCode::Unsupported);
        }
    }

    // -- service probes ------------------------------------------------------

    #[test]
    fn registries_are_bounded_and_tls_first_on_tls_ports() {
        for port in [0u16, 21, 22, 25, 80, 110, 143, 443, 3306, 6379, 8443, 4455] {
            let registry = probe_registry_for_port(port);
            assert!(!registry.is_empty());
            assert!(registry.len() <= MAX_SERVICE_PROBES_PER_PORT);
        }
        assert_eq!(probe_registry_for_port(443)[0], ServiceProbe::TlsHello);
        assert_eq!(probe_registry_for_port(8443)[0], ServiceProbe::TlsHello);
        assert_eq!(probe_registry_for_port(8080)[0], ServiceProbe::HttpGet);
        assert_eq!(
            probe_registry_for_port(6379),
            &[ServiceProbe::Banner, ServiceProbe::RedisPing]
        );
        assert_eq!(
            probe_registry_for_port(53),
            &[ServiceProbe::Banner, ServiceProbe::DnsVersionBind]
        );
        assert_eq!(probe_registry_for_port(22), &[ServiceProbe::Banner]);
    }

    #[test]
    fn payload_builder_emits_expected_protocol_bytes() {
        let bytes = nonce();
        assert!(probe_payload(ServiceProbe::Banner, &bytes).is_empty());
        assert_eq!(
            probe_payload(ServiceProbe::RedisPing, &bytes),
            b"*1\r\n$4\r\nPING\r\n"
        );
        assert_eq!(
            probe_payload(ServiceProbe::HttpGet, &bytes),
            b"GET / HTTP/1.0\r\n\r\n"
        );
        let tls = probe_payload(ServiceProbe::TlsHello, &bytes);
        assert_eq!(
            &tls[..9],
            &[0x16, 0x03, 0x01, 0x00, 0x35, 0x01, 0x00, 0x00, 0x31]
        );
        assert_eq!(&tls[9..11], &[0x03, 0x03]);
        assert_eq!(&tls[11..43], &bytes);
        assert_eq!(&tls[tls.len() - 2..], &[0x00, 0x00]);
        let dns = probe_payload(ServiceProbe::DnsVersionBind, &bytes);
        assert_eq!(dns.len(), 32);
        assert_eq!(&dns[..2], &30u16.to_be_bytes());
        assert_eq!(&dns[13..20], b"version");
        assert_eq!(&dns[26..28], &0x0010u16.to_be_bytes());
        assert_eq!(&dns[28..30], &0x0003u16.to_be_bytes());
    }

    #[test]
    fn banner_matcher_identifies_ssh_pop3_imap_and_220_greetings() {
        let ssh = classify_service_response(
            ServiceProbe::Banner,
            b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n",
        )
        .expect("ssh");
        assert_eq!(ssh.service, "ssh");
        assert!(!ssh.soft);
        assert_eq!(ssh.claim.as_deref(), Some("OpenSSH_9.6p1"));

        let pop3 = classify_service_response(ServiceProbe::Banner, b"+OK Dovecot ready.\r\n")
            .expect("pop3");
        assert_eq!(pop3.service, "pop3");

        let imap = classify_service_response(ServiceProbe::Banner, b"* OK IMAP4rev1 ready\r\n")
            .expect("imap");
        assert_eq!(imap.service, "imap");
        assert!(!imap.soft);
        let imap_bye =
            classify_service_response(ServiceProbe::Banner, b"* BYE autologout\r\n").expect("imap");
        assert!(imap_bye.soft);

        let smtp = classify_service_response(
            ServiceProbe::Banner,
            b"220 mail.example.com ESMTP Postfix (Debian/GNU)\r\n",
        )
        .expect("smtp");
        assert_eq!(smtp.service, "smtp");
        assert!(!smtp.soft);
        assert_eq!(smtp.claim.as_deref(), Some("Postfix"));

        let ftp =
            classify_service_response(ServiceProbe::Banner, b"220 ProFTPD 1.3.8 Server ready\r\n")
                .expect("ftp");
        assert_eq!(ftp.service, "ftp");
        assert!(!ftp.soft);
        assert_eq!(ftp.claim.as_deref(), Some("ProFTPD"));

        // Bare 220 without protocol hints is an honest softmatch.
        let soft =
            classify_service_response(ServiceProbe::Banner, b"220 welcome\r\n").expect("soft");
        assert_eq!(soft.service, "ftp");
        assert!(soft.soft);
        assert_eq!(soft.claim, None);

        let unknown =
            classify_service_response(ServiceProbe::Banner, b"some binary gibberish line\r\n")
                .expect("unknown");
        assert_eq!(unknown.service, "unknown");
        assert!(unknown.soft);

        // Binary garbage that is not a printable line has no claim at all.
        assert!(
            classify_service_response(ServiceProbe::Banner, &[0x00, 0x01, 0x02, 0xff]).is_none()
        );
        assert!(classify_service_response(ServiceProbe::Banner, b"").is_none());
    }

    #[test]
    fn mysql_greeting_is_recognized_with_version_claim() {
        // Header: 3-byte LE payload length, sequence 0; payload: protocol
        // version byte + NUL-terminated server version + capability bytes.
        let mut payload = vec![10u8];
        payload.extend_from_slice(b"8.0.36-log\0");
        payload.extend_from_slice(&[0x21, 0x00, 0x00, 0x00]);
        let mut greeting = vec![(payload.len() & 0xff) as u8, 0, 0, 0];
        greeting.extend_from_slice(&payload);
        let matched = classify_service_response(ServiceProbe::Banner, &greeting).expect("mysql");
        assert_eq!(matched.service, "mysql");
        assert!(!matched.soft);
        assert_eq!(matched.claim.as_deref(), Some("8.0.36-log"));

        let mut error_payload = vec![0xffu8];
        error_payload
            .extend_from_slice(b"#28000Host 'x' is not allowed to connect to this MySQL server");
        let mut error = vec![(error_payload.len() & 0xff) as u8, 0, 0, 0];
        error.extend_from_slice(&error_payload);
        let matched = classify_service_response(ServiceProbe::Banner, &error).expect("mysql error");
        assert_eq!(matched.service, "mysql");
        assert_eq!(matched.claim, None);

        // Framing that lies about its payload length never classifies.
        let mut lying = greeting.clone();
        lying[0] = 0x7f;
        assert!(classify_service_response(ServiceProbe::Banner, &lying).is_none());
    }

    #[test]
    fn http_probes_extract_server_header_claim() {
        let response = b"HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nContent-Length: 0\r\n\r\n";
        for probe in [ServiceProbe::HttpGet, ServiceProbe::HttpOptions] {
            let matched = classify_service_response(probe, response).expect("http");
            assert_eq!(matched.service, "http");
            assert!(!matched.soft);
            assert_eq!(matched.claim.as_deref(), Some("nginx/1.25.3"));
        }
        let no_header =
            classify_service_response(ServiceProbe::HttpGet, b"HTTP/1.0 302 Found\r\n\r\n")
                .expect("http no server");
        assert_eq!(no_header.claim, None);
        assert!(classify_service_response(ServiceProbe::HttpGet, b"not http at all").is_none());
    }

    #[test]
    fn tls_matcher_reads_server_hello_and_subject_cn_only() {
        // Build a synthetic certificate body: issuer CN first, subject CN last.
        let mut cert = Vec::new();
        cert.extend_from_slice(b"\x30\x82\x01\x00"); // SEQUENCE header-ish
        cert.extend_from_slice(b"issuer-padding-records");
        cert.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a]);
        cert.extend_from_slice(b"Issuer CA.");
        cert.extend_from_slice(b"\x82\x01padding");
        cert.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x0a]);
        cert.extend_from_slice(b"demo.local");
        let build_flight = |cert: &[u8]| {
            let mut server_hello = vec![0u8; 4 + 38];
            server_hello[0] = 0x02;
            server_hello[1..4].copy_from_slice(&38u32.to_be_bytes()[1..]);
            let mut cert_body = Vec::new();
            cert_body.extend_from_slice(&(cert.len() as u32).to_be_bytes()[1..]);
            cert_body.extend_from_slice(&(cert.len() as u32).to_be_bytes()[1..]);
            cert_body.extend_from_slice(cert);
            let mut certificate = Vec::new();
            certificate.push(0x0b);
            certificate.extend_from_slice(&(cert_body.len() as u32).to_be_bytes()[1..]);
            certificate.extend_from_slice(&cert_body);
            let mut handshake = Vec::new();
            handshake.extend_from_slice(&server_hello);
            handshake.extend_from_slice(&certificate);
            let mut record = vec![0x16, 0x03, 0x03];
            record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
            record.extend_from_slice(&handshake);
            record
        };
        let matched = classify_service_response(ServiceProbe::TlsHello, &build_flight(&cert))
            .expect("tls serverhello");
        assert_eq!(matched.service, "ssl");
        assert!(!matched.soft);
        // The LAST CN (subject) wins over the issuer claim.
        assert_eq!(matched.claim.as_deref(), Some("demo.local"));

        // A TLS alert is a soft TLS identification without a claim.
        let alert = classify_service_response(
            ServiceProbe::TlsHello,
            &[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28],
        )
        .expect("alert");
        assert_eq!(alert.service, "ssl");
        assert!(alert.soft);
        assert!(classify_service_response(ServiceProbe::TlsHello, b"plaintext").is_none());
    }

    #[test]
    fn redis_and_dns_probes_classify_with_and_without_version() {
        let pong = classify_service_response(ServiceProbe::RedisPing, b"+PONG\r\n").expect("pong");
        assert_eq!(pong.service, "redis");
        assert!(!pong.soft);
        let err = classify_service_response(ServiceProbe::RedisPing, b"-ERR unknown command\r\n")
            .expect("resp error");
        assert_eq!(err.service, "redis");
        assert!(err.soft);
        assert!(
            classify_service_response(ServiceProbe::RedisPing, b"HTTP/1.1 400 Bad\r\n").is_none()
        );

        // DNS/TCP reply: header (QR set) + question + TXT CHAOS answer.
        let mut reply = Vec::new();
        reply.extend_from_slice(&[0x12, 0x34, 0x81, 0x80]);
        reply.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 0]);
        reply.extend_from_slice(b"\x07version\x04bind\x00\x00\x10\x00\x03");
        // answer: pointer to question, TXT CHAOS, TTL, rdata "9.0.1"
        reply.extend_from_slice(&[0xc0, 0x0c, 0x00, 0x10, 0x00, 0x03, 0, 0, 0, 0, 0, 7]);
        reply.push(6);
        reply.extend_from_slice(b"9.0.1.");
        let mut framed = (reply.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&reply);
        let matched =
            classify_service_response(ServiceProbe::DnsVersionBind, &framed).expect("dns");
        assert_eq!(matched.service, "domain");
        assert!(!matched.soft);
        assert_eq!(matched.claim.as_deref(), Some("9.0.1."));

        // QR set but version withheld: DNS softmatch, no claim.
        let mut quiet = Vec::new();
        quiet.extend_from_slice(&[0x12, 0x34, 0x81, 0x80]);
        quiet.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
        quiet.extend_from_slice(b"\x07version\x04bind\x00\x00\x10\x00\x03");
        let soft =
            classify_service_response(ServiceProbe::DnsVersionBind, &quiet).expect("dns soft");
        assert_eq!(soft.service, "domain");
        assert!(soft.soft);
        assert_eq!(soft.claim, None);
        // Query (QR clear) never classifies.
        let mut query_only = quiet.clone();
        query_only[2] = 0x01; // flags high byte: recursion desired, no QR
        assert!(classify_service_response(ServiceProbe::DnsVersionBind, &query_only).is_none());
    }

    #[test]
    fn excerpt_sanitizer_bounds_length_and_neutralizes_control_bytes() {
        let hostile: Vec<u8> = std::iter::once(b'\x01')
            .chain(std::iter::repeat(b'a').take(MAX_SERVICE_EXCERPT + 40))
            .collect();
        let text = sanitize_excerpt(&hostile);
        assert_eq!(text.len(), MAX_SERVICE_EXCERPT);
        assert!(text.starts_with('?'));
        assert_eq!(sanitize_excerpt(b"line\r\nnext"), "line  next");
        assert_eq!(sanitize_excerpt(&[0xff, 0xfe]), "??");
        assert_eq!(sanitize_excerpt(b""), "");
    }
}
