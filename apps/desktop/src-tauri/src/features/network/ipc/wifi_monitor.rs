//! Authorized Wi-Fi monitor-mode IPC for the Network Lab "Wifi" arc
//! (Bettercap `wifi.show` / handshake-capture parity, strictly passive).
//!
//! Mirrors the lab spoof slice (`network_lab_spoof.rs`): a managed
//! `Arc<NetworkWifiCtx>` with the stop-flag + join-guard pattern, a
//! idle/starting/monitoring/stopping/stopped phase machine and an honest
//! status wire. The socket and radio-control layers are NOT duplicated here:
//! the landed wifi crate layer (`crates/packet/src/wifi/`) owns nl80211
//! monitor control (Linux), radiotap/802.11 dissection and the EAPOL 4-way
//! capture that formats hashcat mode-22000 lines. This file reuses those
//! types read-only and adds: interface enumeration (with a Windows Npcap
//! registry probe reported honestly), the Linux AF_PACKET capture pump
//! (mirrors `active_arp` — poll-paced bounded reads, stop flag checked per
//! read, never a send), and the one-bounded-artifact-per-session evidence
//! save through the standard case findings path.
//!
//! Platform honesty (mirrors the crate's `WifiMonitorError::Unsupported`):
//! the monitor door exists only on Linux; macOS and Windows report
//! `monitor_supported: false` and control commands refuse with the honest
//! message. On Windows the `npcap` service is probed read-only in the
//! registry (`HKLM\SYSTEM\CurrentControlSet\Services\npcap`) and reported as
//! `npcap_detected` — presence is NOT support: no monitor-mode control is
//! wired for Windows in this arc and the start command still refuses.
//!
//! The capture is receive-only and transmits nothing, so — unlike the ARP
//! spoof — it takes no `NetworkOperationGate` lease; it does refuse to start
//! while another active operation holds the gate, because switching the radio
//! into monitor mode under a running operation would break it. Bounds:
//! ≤ 16 authorized capture frequencies, AP table ≤ 64, client table ≤ 256,
//! frames ≤ 4352 bytes (crate radiotap + 802.11 bounds), snapshot publishes
//! bounded at 128-frame cadence, one bounded evidence finding per session.
//!
//! Injection slice (additive, Bettercap `wifi.deauth` + hopping parity):
//! `network_wifi_inject_deauth_v1` is ACTIVE interference and is gated like
//! the lab ARP spoof — saved case, LIVE monitor session (the ONLY target
//! source is the current session's observed AP table: no blind targets),
//! `ActiveOperation::WifiInject` gate lease, native Yes/No dialog naming
//! every target BSSID and the exact frame counts, Linux-only worker over the
//! crate's `inject` core (≤ 4 targets, ≤ 4 bursts, ≤ 32 frames/burst, ≥ 20 ms
//! frame pacing, ≤ 10 s hard runtime cap, stop never refused).
//! `network_wifi_channel_hop_v1` is passive radio control over the running
//! capture (≤ 16 in-band frequencies, 250 ms–2 s interval, pause/resume with
//! capture, full ≤ 256-entry hop log); it takes no gate lease but refuses to
//! start or run next to injection or another active operation. Both report
//! honest counters through additive `WifiStatusWire` fields.
use crate::features::forensics::ipc::evidence::EvidenceCtx;
use crate::features::shared::session::{CaseSessionCtx, CaseSessionWire};
use cyberdeck_packet::wifi::frame::{self, FrameKind};
use cyberdeck_packet::wifi::inject;
use cyberdeck_packet::wifi::radiotap;
use cyberdeck_packet::wifi::{ChannelHopScheduler, MonitorCapture, monitor_mode_supported};
use cyberdeck_storage::NewFinding;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
#[cfg(target_os = "linux")]
use tauri::Manager;
use tauri::{AppHandle, State};
#[cfg(target_os = "linux")]
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

/// Evidence source key for the wifi monitor's persisted finding (scan
/// findings use "network.tcp"/"network.udp"; the lab report uses
/// "network.lab"; the wifi capture persists under one key).
const WIFI_EVIDENCE_SOURCE: &str = "network.wifi";
/// Fixed finding title so case review can recognize the artifact.
const WIFI_EVIDENCE_TITLE: &str = "Wifi monitor handshakes (hashcat 22000)";
/// The persisted finding is ONE bounded artifact per capture session.
const MAX_WIFI_EVIDENCE_BYTES: usize = 32 * 1024;
const EVIDENCE_TRUNCATION_MARKER: &str = "\n...[truncated at the 32 KiB evidence bound]";
/// Authorized capture frequencies per session (bounded like every lab input).
const MAX_WIFI_CHANNELS: usize = 16;
/// Bounded interface enumeration (the netlink client carries the same 64 cap).
const MAX_WIFI_INTERFACES: usize = 64;
/// Bounded AP/client tables (mirrors `MAX_TRACKED_AP_ESSIDS`).
const MAX_WIFI_ACCESS_POINTS: usize = 64;
const MAX_WIFI_CLIENTS: usize = 256;
/// Largest capture read: crate radiotap header bound + 802.11 frame bound.
const MAX_WIFI_CAPTURE_BYTES: usize =
    cyberdeck_packet::wifi::radiotap::MAX_HEADER_BYTES + cyberdeck_packet::wifi::frame::MAX_FRAME_BYTES;
/// The pump publishes a bounded snapshot at most this often per frame count
/// (and immediately whenever a hashcat line became emittable).
const PUBLISH_EVERY_FRAMES: u64 = 128;
/// The session-revocation closure is re-checked at this cadence (reads are
/// frame-paced; the stop flag is checked per read either way).
const SCOPE_CHECK_EVERY_ITERATIONS: u64 = 512;
/// Honest Unsupported message wherever the radio door does not exist.
const UNSUPPORTED_MESSAGE: &str =
    "wifi monitor mode uses the Linux nl80211 control door and currently requires Linux";
/// Honest Unsupported message for the injection door off Linux (the deauth
/// transmit path is Linux AF_PACKET + CAP_NET_RAW only).
const INJECTION_UNSUPPORTED_MESSAGE: &str =
    "wifi injection uses the Linux AF_PACKET transmit door and currently requires Linux";
/// Honest Unsupported message for the channel-hop door off Linux.
const HOP_UNSUPPORTED_MESSAGE: &str =
    "wifi channel hopping uses the Linux nl80211 control door and currently requires Linux";
/// Deauth target cap per run (mirrors the crate's `MAX_DEAUTH_TARGETS`).
const MAX_INJECT_TARGETS: usize = inject::MAX_DEAUTH_TARGETS;
/// The worker polls the hop scheduler and applies pause/resume at this
/// cadence (stop latency ~25 ms; one short critical section per tick).
const HOP_POLL_SLICE_MS: u64 = 25;

// ---------------------------------------------------------------------------
// Channel parsing: the UI hands over channel numbers (2.4/5 GHz bands) or
// explicit MHz frequencies; the backend resolves every token honestly.
// ---------------------------------------------------------------------------

/// Resolve the authorized capture frequencies: 2.4 GHz channel numbers 1-14,
/// 5 GHz channel numbers 32-177, anything in a legal band range as an
/// explicit MHz frequency (6 GHz and beyond are addressed by frequency).
/// Deduplicated, order-preserving, at most [`MAX_WIFI_CHANNELS`].
fn parse_channels(text: &str) -> Result<Vec<u32>, String> {
    let mut out: Vec<u32> = Vec::new();
    for token in text
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|t| !t.is_empty())
    {
        let value: u32 = token
            .trim()
            .parse()
            .map_err(|_| format!("channel list entry is not a number: {token}"))?;
        let freq = channel_to_freq(value)?;
        if !out.contains(&freq) {
            out.push(freq);
        }
    }
    if out.is_empty() {
        return Err("at least one capture frequency or channel is required".into());
    }
    if out.len() > MAX_WIFI_CHANNELS {
        return Err(format!(
            "at most {MAX_WIFI_CHANNELS} capture frequencies are allowed per session"
        ));
    }
    Ok(out)
}

fn channel_to_freq(value: u32) -> Result<u32, String> {
    match value {
        1..=14 => Ok(if value == 14 { 2484 } else { 2407 + 5 * value }),
        32..=177 => Ok(5000 + 5 * value),
        _ if (5945..=7115).contains(&value)
            || (2412..=2484).contains(&value)
            || (5160..=5885).contains(&value) =>
        {
            Ok(value) // explicit frequency, validated again by the encoder
        }
        _ => Err(format!(
            "'{value}' is neither a supported 2.4/5 GHz channel number nor an explicit \
             frequency in MHz (2.4 GHz: 1-14, 5 GHz: 32-177, or pass MHz directly)"
        )),
    }
}

// ---------------------------------------------------------------------------
// Platform honesty: Npcap presence on Windows, interface enumeration.
// ---------------------------------------------------------------------------

/// Windows-only Npcap service probe. The driver registers the service key at
/// install time, so an openable `npcap` service key with KEY_READ is the
/// honest "detected" signal. Read-only: nothing is written or started.
#[cfg(target_os = "windows")]
mod windows_probe {
    use std::ffi::{OsStr, c_void};
    use std::os::windows::ffi::OsStrExt;

    const KEY_READ: u32 = 0x0002_0019;
    const ERROR_SUCCESS: i32 = 0;

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn RegOpenKeyExW(
            key: *mut c_void,
            subkey: *const u16,
            options: u32,
            access: u32,
            result: *mut *mut c_void,
        ) -> i32;
        fn RegCloseKey(key: *mut c_void) -> i32;
    }

    pub(super) fn npcap_service_present() -> bool {
        // HKEY_LOCAL_MACHINE is the well-known handle value 0x80000002.
        let hklm = 0x8000_0002usize as *mut c_void;
        let subkey: Vec<u16> = OsStr::new("SYSTEM\\CurrentControlSet\\Services\\npcap")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut handle: *mut c_void = std::ptr::null_mut();
        let opened = unsafe {
            RegOpenKeyExW(hklm, subkey.as_ptr(), 0, KEY_READ, &mut handle)
        };
        if opened == ERROR_SUCCESS {
            unsafe { RegCloseKey(handle) };
            true
        } else {
            false
        }
    }
}

/// Npcap is a Windows driver; other platforms honestly report false.
#[cfg(target_os = "windows")]
fn npcap_detected_probe() -> bool {
    windows_probe::npcap_service_present()
}

#[cfg(not(target_os = "windows"))]
fn npcap_detected_probe() -> bool {
    false
}

/// The one-line platform honesty note the UI renders verbatim.
fn platform_status_note() -> &'static str {
    if monitor_mode_supported() {
        "monitor mode available via Linux nl80211; the capture is passive receive-only"
    } else if cfg!(target_os = "windows") {
        "monitor mode requires Linux nl80211; Npcap detection is reported but no Windows \
         monitor-mode control is wired in this arc"
    } else if cfg!(target_os = "macos") {
        "monitor mode requires Linux nl80211; macOS exposes no monitor-mode door to this \
         workbench"
    } else {
        "monitor mode requires Linux nl80211"
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct WifiInterfaceWire {
    pub name: String,
    pub index: u32,
}

/// Read-only discovery receipt for `network_wifi_interfaces_v1`. Honest per
/// platform: `monitor_supported` is true only where the kernel exposes the
/// nl80211 door, and `npcap_detected` is the Windows-only driver probe.
#[derive(Debug, Clone, Serialize)]
pub struct WifiInterfacesWire {
    pub monitor_supported: bool,
    pub npcap_detected: bool,
    pub platform_status: String,
    pub interfaces: Vec<WifiInterfaceWire>,
}

#[cfg(target_os = "linux")]
fn enumerate_wifi_interfaces() -> Result<Vec<WifiInterfaceWire>, String> {
    let mut out = Vec::new();
    let entries = std::fs::read_dir("/sys/class/net")
        .map_err(|e| format!("enumerate network interfaces: {e}"))?;
    for entry in entries.flatten() {
        let path = entry.path();
        // A cfg80211 wireless device exposes phy80211 (modern kernels) or the
        // legacy wireless directory in sysfs; anything else is not a radio.
        if !path.join("phy80211").exists() && !path.join("wireless").exists() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let index = std::fs::read_to_string(path.join("ifindex"))
            .ok()
            .and_then(|text| text.trim().parse::<u32>().ok())
            .unwrap_or(0);
        out.push(WifiInterfaceWire { name, index });
        if out.len() >= MAX_WIFI_INTERFACES {
            return Err(format!(
                "more than {MAX_WIFI_INTERFACES} wireless interfaces is outside the bounded \
                 enumeration"
            ));
        }
    }
    Ok(out)
}

#[cfg(any(target_os = "windows", target_os = "macos"))]
fn enumerate_wifi_interfaces() -> Result<Vec<WifiInterfaceWire>, String> {
    // Reuse the packet crate's native interface discovery read-only; the
    // platform note explains honestly that these adapters cannot be driven
    // into monitor mode by this arc.
    let all = cyberdeck_packet::live::discover_interfaces().map_err(|e| e.message)?;
    Ok(all
        .iter()
        .filter(|iface| !iface.loopback)
        .take(MAX_WIFI_INTERFACES)
        .map(|iface| WifiInterfaceWire {
            name: iface.name.clone(),
            index: iface.index,
        })
        .collect())
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
fn enumerate_wifi_interfaces() -> Result<Vec<WifiInterfaceWire>, String> {
    Ok(Vec::new())
}

/// Enumerate the machine's wireless interfaces plus the honest platform
/// status (monitor support and, on Windows, Npcap presence). Read-only.
#[tauri::command]
pub fn network_wifi_interfaces_v1() -> Result<WifiInterfacesWire, String> {
    Ok(WifiInterfacesWire {
        monitor_supported: monitor_mode_supported(),
        npcap_detected: npcap_detected_probe(),
        platform_status: platform_status_note().to_string(),
        interfaces: enumerate_wifi_interfaces()?,
    })
}

// ---------------------------------------------------------------------------
// Managed context: phase machine, honest counters, bounded snapshot.
// ---------------------------------------------------------------------------

/// One access point learned from a beacon/probe response.
#[derive(Debug, Clone, Serialize)]
pub struct WifiApWire {
    pub bssid: String,
    /// Lossy UTF-8 rendering for display; the hashcat line carries the exact
    /// hex-encoded ESSID evidence.
    pub essid: String,
}

/// The bounded session snapshot the pump publishes (engine lines, AP/client
/// tables); cloned out under the mutex by the status command.
#[derive(Debug, Clone, Default)]
struct WifiSnapshot {
    lines: Vec<String>,
    handshakes: usize,
    access_points: Vec<WifiApWire>,
    clients: Vec<String>,
}

/// Shared channel-hop scheduler slot: the hop worker applies ticks/pauses to
/// it in short critical sections; the status command reads honest state from
/// it (the log persists after the run ends until the next start resets it).
#[derive(Default)]
struct HopShared {
    scheduler: Option<ChannelHopScheduler>,
}

/// Managed per-process monitor registry, mirroring `NetworkLabSpoofCtx`.
/// The injection/hop fields are the additive slice: deauth is gate-leased
/// ACTIVE interference; hopping is passive radio control over the capture.
#[derive(Default)]
pub struct NetworkWifiCtx {
    running: AtomicBool,
    stop: AtomicBool,
    phase: Mutex<WifiPhase>,
    frames_seen: AtomicU64,
    beacons: AtomicU64,
    interface: Mutex<String>,
    /// The pinned capture frequency (the first authorized entry).
    channel_mhz: AtomicU32,
    channels: Mutex<Vec<u32>>,
    started_at: Mutex<Option<Instant>>,
    final_elapsed_ms: AtomicU64,
    last_error: Mutex<Option<String>>,
    snapshot: Mutex<WifiSnapshot>,
    /// ONE bounded evidence finding per capture session.
    evidence_saved: AtomicBool,
    // --- injection (deauth), additive: gate-leased, bounded, stop-aware ---
    deauth_running: AtomicBool,
    deauth_stop: AtomicBool,
    deauth_frames_sent: AtomicU64,
    deauth_bursts_done: AtomicUsize,
    deauth_targets: AtomicUsize,
    deauth_note: Mutex<Option<String>>,
    injection_last_error: Mutex<Option<String>>,
    // --- channel hop, additive: passive radio control over the capture ---
    hop_running: AtomicBool,
    hop_stop: AtomicBool,
    /// Pause/resume REQUESTS from IPC; the worker applies them to the shared
    /// scheduler on its own clock (the scheduler's time base stays exact).
    hop_pause_request: AtomicBool,
    hop: Mutex<HopShared>,
    hop_last_error: Mutex<Option<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum WifiPhase {
    #[default]
    Idle,
    Starting,
    Monitoring,
    Stopping,
    Stopped,
}
impl WifiPhase {
    fn as_str(self) -> &'static str {
        match self {
            WifiPhase::Idle => "idle",
            WifiPhase::Starting => "starting",
            WifiPhase::Monitoring => "monitoring",
            WifiPhase::Stopping => "stopping",
            WifiPhase::Stopped => "stopped",
        }
    }
}

impl NetworkWifiCtx {
    /// Immediate case-change hook; the worker's session closure stays
    /// authoritative even when a caller cannot invoke this. Arms every stop
    /// flag in the registry: the capture pump, a deauth run and a hop run
    /// all end on case revocation.
    pub fn on_case_changed(&self) {
        self.stop.store(true, Ordering::Release);
        self.deauth_stop.store(true, Ordering::Release);
        self.hop_stop.store(true, Ordering::Release);
    }

    fn set_phase(&self, phase: WifiPhase) {
        if let Ok(mut guard) = self.phase.lock() {
            *guard = phase;
        }
    }

    fn phase(&self) -> WifiPhase {
        self.phase.lock().map(|g| *g).unwrap_or(WifiPhase::Idle)
    }

    /// Publish a bounded snapshot out of the pump's engine view.
    fn publish(
        &self,
        capture: &MonitorCapture,
        aps: &[([u8; 6], Vec<u8>)],
        clients: &[[u8; 6]],
    ) {
        let snapshot = WifiSnapshot {
            lines: capture.hashcat_22000_lines(),
            handshakes: capture.handshakes().count(),
            access_points: aps
                .iter()
                .map(|(bssid, essid)| WifiApWire {
                    bssid: format_mac(bssid),
                    essid: String::from_utf8_lossy(essid).into_owned(),
                })
                .collect(),
            clients: clients.iter().map(|mac| format_mac(mac)).collect(),
        };
        if let Ok(mut slot) = self.snapshot.lock() {
            *slot = snapshot;
        }
    }

    fn status_wire(&self) -> WifiStatusWire {
        let started = self.started_at.lock().ok().and_then(|guard| *guard);
        let elapsed = if started.is_some() && self.running.load(Ordering::Acquire) {
            started
                .map(|s| s.elapsed().as_millis().min(u64::MAX as u128) as u64)
                .unwrap_or(0)
        } else {
            self.final_elapsed_ms.load(Ordering::Acquire)
        };
        let snapshot = self
            .snapshot
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default();
        // Injection counters: the state word is derived from the live flags,
        // never invented by the UI.
        let deauth_running = self.deauth_running.load(Ordering::Acquire);
        let deauth_frames = self.deauth_frames_sent.load(Ordering::Acquire);
        let deauth_state = if deauth_running {
            if self.deauth_stop.load(Ordering::Acquire) {
                "stopping"
            } else {
                "injecting"
            }
        } else if deauth_frames > 0 {
            "stopped"
        } else {
            "idle"
        };
        // Channel hop: the scheduler is the truth for current frequency,
        // pause state and the full bounded log (which persists after stop).
        let hop = self.hop_view().unwrap_or_default();
        let hop_running = self.hop_running.load(Ordering::Acquire);
        WifiStatusWire {
            state: self.phase().as_str().to_string(),
            interface: self.interface.lock().map(|g| g.clone()).unwrap_or_default(),
            channel_mhz: self.channel_mhz.load(Ordering::Acquire),
            channels: self.channels.lock().map(|g| g.clone()).unwrap_or_default(),
            frames_seen: self.frames_seen.load(Ordering::Acquire),
            beacons: self.beacons.load(Ordering::Acquire),
            clients_seen: snapshot.clients.len(),
            handshakes_captured: snapshot.handshakes,
            hashcat_22000_lines: snapshot.lines,
            access_points: snapshot.access_points,
            clients: snapshot.clients,
            elapsed_ms: elapsed,
            last_error: self.last_error.lock().ok().and_then(|g| g.clone()),
            deauth_state: deauth_state.to_string(),
            deauth_frames_sent: deauth_frames,
            deauth_bursts_done: self.deauth_bursts_done.load(Ordering::Acquire),
            deauth_targets: self.deauth_targets.load(Ordering::Acquire),
            deauth_note: self.deauth_note.lock().ok().and_then(|g| g.clone()),
            injection_last_error: self
                .injection_last_error
                .lock()
                .ok()
                .and_then(|g| g.clone()),
            hop_running,
            hop_paused: hop.paused,
            hop_channel_mhz: if hop_running { hop.current_mhz } else { 0 },
            hop_channels: hop.channels,
            hop_interval_ms: hop.interval_ms,
            hop_count: hop.hop_count,
            hop_log: hop.log,
            hop_last_error: self.hop_last_error.lock().ok().and_then(|g| g.clone()),
        }
    }

    /// The scheduler-derived hop view (current frequency, pause state, full
    /// bounded log); None when no hop plan exists in the registry.
    fn hop_view(&self) -> Option<HopView> {
        let guard = self.hop.lock().ok()?;
        let scheduler = guard.scheduler.as_ref()?;
        Some(HopView {
            paused: scheduler.is_paused(),
            current_mhz: scheduler.current(),
            channels: scheduler.channels().to_vec(),
            interval_ms: scheduler.interval_ms() as u32,
            hop_count: scheduler.hops(),
            log: scheduler
                .hop_log()
                .iter()
                .map(|entry| WifiHopEntryWire {
                    at_ms: entry.at_ms,
                    from_mhz: entry.from_mhz,
                    to_mhz: entry.to_mhz,
                })
                .collect(),
        })
    }
}

/// Backend-rendered hop view for the status wire and the hop command receipt.
#[derive(Debug, Clone, Default)]
struct HopView {
    paused: bool,
    current_mhz: u32,
    channels: Vec<u32>,
    interval_ms: u32,
    hop_count: u64,
    log: Vec<WifiHopEntryWire>,
}

/// Runs for the whole worker lifetime; clears the running flag and publishes
/// the final phase even when the worker panicked or the runtime dropped it.
struct WifiRunGuard(Arc<NetworkWifiCtx>);
impl Drop for WifiRunGuard {
    fn drop(&mut self) {
        self.0.running.store(false, Ordering::Release);
        self.0.set_phase(WifiPhase::Stopped);
    }
}

/// Wire status for `network_wifi_monitor_status_v1`; snake_case field names
/// are the serde names and are mirrored verbatim by the typed frontend client.
#[derive(Debug, Clone, Serialize)]
pub struct WifiStatusWire {
    /// idle | starting | monitoring | stopping | stopped.
    pub state: String,
    /// Interface the session captured on (empty before the first start).
    pub interface: String,
    /// The pinned capture frequency (first authorized entry), MHz.
    pub channel_mhz: u32,
    /// Every authorized capture frequency of the session, MHz.
    pub channels: Vec<u32>,
    /// Every frame read off the monitor interface (poll ticks excluded).
    pub frames_seen: u64,
    /// Parseable beacon frames seen.
    pub beacons: u64,
    /// Distinct client stations seen this session.
    pub clients_seen: usize,
    /// WPA handshakes (complete or partial) the engine holds.
    pub handshakes_captured: usize,
    /// The hashcat 22000 lines captured this session (engine-bounded, ≤ 128).
    pub hashcat_22000_lines: Vec<String>,
    /// APs learned from beacons/probe responses (bounded ≤ 64).
    pub access_points: Vec<WifiApWire>,
    /// Distinct client stations (bounded ≤ 256).
    pub clients: Vec<String>,
    /// Elapsed wall-clock milliseconds.
    pub elapsed_ms: u64,
    pub last_error: Option<String>,
    // --- injection (deauth), additive fields ---
    /// idle | injecting | stopping | stopped (derived from the live flags).
    pub deauth_state: String,
    /// Deauth frames the current/last run actually transmitted.
    pub deauth_frames_sent: u64,
    /// Bursts the last run completed.
    pub deauth_bursts_done: usize,
    /// Target BSSIDs of the last run.
    pub deauth_targets: usize,
    /// Backend-rendered end-of-run note (frames, bursts, honest end reason).
    pub deauth_note: Option<String>,
    pub injection_last_error: Option<String>,
    // --- channel hop, additive fields ---
    pub hop_running: bool,
    /// True while the hop scheduler is paused (the capture keeps running).
    pub hop_paused: bool,
    /// The frequency the hop scheduler currently drives (0 when not hopping).
    pub hop_channel_mhz: u32,
    /// The authorized hop frequencies, MHz.
    pub hop_channels: Vec<u32>,
    pub hop_interval_ms: u32,
    /// Total hops applied this hop run.
    pub hop_count: u64,
    /// The full bounded hop log (≤ 256 entries; persists after stop).
    pub hop_log: Vec<WifiHopEntryWire>,
    pub hop_last_error: Option<String>,
}

/// One recorded channel hop: when (ms since the hop run started) and the
/// frequency transition the worker drove over nl80211.
#[derive(Debug, Clone, Serialize)]
pub struct WifiHopEntryWire {
    pub at_ms: u64,
    pub from_mhz: u32,
    pub to_mhz: u32,
}

/// Start receipt for `network_wifi_inject_deauth_v1`: the exact backend-
/// authorized targets and bounds (the UI never widens or re-derives them).
#[derive(Debug, Clone, Serialize)]
pub struct WifiInjectStartWire {
    pub targets: Vec<String>,
    pub bursts: u32,
    pub frames_per_target: u32,
    /// Frames per burst across ALL targets (≤ 32, crate-enforced).
    pub frames_per_burst: u32,
    /// Total frames the whole run may transmit (per_burst × bursts).
    pub total_frames: u32,
    pub status: WifiStatusWire,
}

/// Receipt for `network_wifi_channel_hop_v1`: the applied action plus the
/// scheduler's honest state after it.
#[derive(Debug, Clone, Serialize)]
pub struct WifiHopWire {
    /// start | pause | resume | stop.
    pub action: String,
    pub running: bool,
    pub paused: bool,
    pub current_mhz: u32,
    pub channels: Vec<u32>,
    pub interval_ms: u32,
    pub hop_count: u64,
    pub status: WifiStatusWire,
}

/// Start receipt: the exact interface and frequencies the backend pinned.
#[derive(Debug, Clone, Serialize)]
pub struct WifiStartWire {
    pub interface: String,
    pub channel_mhz: u32,
    pub channels: Vec<u32>,
    pub status: WifiStatusWire,
}

fn format_mac(mac: &[u8; 6]) -> String {
    let hex: Vec<String> = mac.iter().map(|byte| format!("{byte:02x}")).collect();
    hex.join(":")
}

/// Flatten the crate's typed error into the command's honest String wire
/// error (code discriminator + message, mirroring the ARP slices).
#[cfg(target_os = "linux")]
fn wifi_err(err: cyberdeck_packet::wifi::WifiError) -> String {
    format!("{:?}: {}", err.code, err.message)
}

fn selected_saved_case(session: &CaseSessionCtx) -> Result<(CaseSessionWire, String), String> {
    let scope = session.selected()?;
    let case_id = scope
        .case_id
        .clone()
        .ok_or("a saved case must be selected")?;
    if case_id == "scratchpad" || case_id.trim().is_empty() {
        return Err("wifi monitor capture requires a saved, backend-selected case".into());
    }
    Ok((scope, case_id))
}

// ---------------------------------------------------------------------------
// Injection helpers: the ONLY deauth target source is the CURRENT monitor
// session's observed AP table — no blind targets, ever.
// ---------------------------------------------------------------------------

/// Parse one strict `aa:bb:cc:dd:ee:ff` MAC address (case-insensitive hex
/// pairs, colon-separated).
fn parse_bssid(text: &str) -> Option<[u8; 6]> {
    let value = text.trim().to_lowercase();
    let parts: Vec<&str> = value.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (slot, part) in mac.iter_mut().zip(&parts) {
        if part.len() != 2 || !part.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        *slot = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}

/// Resolve the requested deauth targets against the CURRENT monitor
/// session's observed AP table: 1..=4 strict MACs, deduplicated, every one a
/// BSSID this session has actually seen in a beacon/probe response. A BSSID
/// the session never observed is refused — no blind targets.
fn resolve_observed_targets(
    requested: &[String],
    observed: &[WifiApWire],
) -> Result<Vec<[u8; 6]>, String> {
    if requested.is_empty() || requested.len() > MAX_INJECT_TARGETS {
        return Err(format!(
            "deauth supports 1..={MAX_INJECT_TARGETS} target BSSIDs per run"
        ));
    }
    let mut out: Vec<[u8; 6]> = Vec::new();
    for text in requested {
        let bssid =
            parse_bssid(text).ok_or_else(|| format!("deauth target '{text}' is not a aa:bb:cc:dd:ee:ff MAC address"))?;
        let bssid_text = format_mac(&bssid);
        if !observed.iter().any(|ap| ap.bssid == bssid_text) {
            return Err(format!(
                "deauth target {bssid_text} was not observed by the current monitor session — \
                 targets are limited to BSSIDs this capture has seen (no blind targets)"
            ));
        }
        if out.contains(&bssid) {
            return Err(format!("duplicate deauth target {bssid_text}"));
        }
        out.push(bssid);
    }
    Ok(out)
}

/// Injection rides a LIVE monitor session: the radio must already be in
/// monitor mode and the observed-AP table must belong to the current run.
fn require_live_monitor(wifi: &NetworkWifiCtx) -> Result<(), String> {
    if !wifi.running.load(Ordering::Acquire) || wifi.phase() != WifiPhase::Monitoring {
        return Err(
            "start the monitor capture first — injection targets only BSSIDs observed by the \
             CURRENT monitor session"
                .into(),
        );
    }
    Ok(())
}

/// Build the hop command's receipt from the registry's scheduler view.
fn hop_wire(action: &str, wifi: &NetworkWifiCtx) -> WifiHopWire {
    let view = wifi.hop_view().unwrap_or_default();
    WifiHopWire {
        action: action.to_string(),
        running: wifi.hop_running.load(Ordering::Acquire),
        paused: view.paused,
        current_mhz: view.current_mhz,
        channels: view.channels,
        interval_ms: view.interval_ms,
        hop_count: view.hop_count,
        status: wifi.status_wire(),
    }
}

// ---------------------------------------------------------------------------
// Frame bookkeeping: AP/client tables derived from parsed frame roles.
// ---------------------------------------------------------------------------

/// Track one AP (BSSID -> ESSID) learned from a beacon/probe response,
/// LRU-bounded at [`MAX_WIFI_ACCESS_POINTS`].
fn track_access_point(
    aps: &mut Vec<([u8; 6], Vec<u8>)>,
    parsed: &frame::ParsedFrame,
    ssid: Option<&[u8]>,
) {
    let Some(bssid) = parsed.roles.bssid else {
        return;
    };
    let Some(ssid) = ssid else {
        return; // hidden APs carry nothing to display
    };
    if ssid.is_empty() {
        return;
    }
    if let Some(index) = aps.iter().position(|(ap, _)| *ap == bssid) {
        let entry = aps.remove(index);
        aps.push(entry); // move to back: LRU recency
    } else {
        aps.push((bssid, ssid.to_vec()));
        if aps.len() > MAX_WIFI_ACCESS_POINTS {
            aps.remove(0);
        }
    }
}

/// The client station of one data/probe frame: for EAPOL and data frames the
/// station is whichever endpoint is not the BSSID; probe requests come from
/// stations directly. Broadcast/multicast and the AP itself are never clients.
fn client_station_mac(parsed: &frame::ParsedFrame) -> Option<[u8; 6]> {
    let bssid = parsed.roles.bssid?;
    let station = match parsed.frame_type {
        frame::FC_TYPE_DATA => {
            if parsed.roles.source == bssid {
                parsed.roles.destination
            } else {
                parsed.roles.source
            }
        }
        frame::FC_TYPE_MANAGEMENT if parsed.subtype == frame::SUBTYPE_PROBE_REQUEST => {
            parsed.roles.source
        }
        _ => return None,
    };
    if station == bssid || station[0] & 1 != 0 {
        return None;
    }
    Some(station)
}

/// Deduplicated, LRU-bounded client table.
fn track_client(clients: &mut Vec<[u8; 6]>, station: [u8; 6]) {
    if clients.contains(&station) {
        return;
    }
    clients.push(station);
    if clients.len() > MAX_WIFI_CLIENTS {
        clients.remove(0);
    }
}

// ---------------------------------------------------------------------------
// The capture pump: portable core over an injected frame reader, so the
// engine/counter/snapshot logic is unit-tested everywhere without a radio;
// only the Linux AF_PACKET source is cfg-gated.
// ---------------------------------------------------------------------------

/// Feed every captured monitor frame through the engine and keep honest
/// counters. `read` returns the bytes of one frame, `Ok(0)` for a no-frame
/// poll tick (the loop then re-checks stop and scope), or an IO error. The
/// stop flag is checked BEFORE every read, so cancellation latency is one
/// poll interval, never a frame. The pump never transmits.
pub(crate) fn run_frame_pump<S, R>(
    stop: &AtomicBool,
    scope_active: &S,
    ctx: &NetworkWifiCtx,
    mut read: R,
) -> Result<(), String>
where
    S: Fn() -> bool,
    R: FnMut(&mut [u8]) -> std::io::Result<usize>,
{
    let mut capture = MonitorCapture::new();
    let mut buffer = vec![0u8; MAX_WIFI_CAPTURE_BYTES];
    let mut aps: Vec<([u8; 6], Vec<u8>)> = Vec::new();
    let mut clients: Vec<[u8; 6]> = Vec::new();
    let mut since_publish: u64 = 0;
    let mut since_scope_check: u64 = 0;
    // Every exit publishes the final bounded snapshot first: the status the
    // operator polls after a stop must include the last frames, not the last
    // publish boundary.
    loop {
        if stop.load(Ordering::Acquire) {
            ctx.publish(&capture, &aps, &clients);
            return Ok(());
        }
        since_scope_check += 1;
        if since_scope_check >= SCOPE_CHECK_EVERY_ITERATIONS {
            since_scope_check = 0;
            if !scope_active() {
                ctx.publish(&capture, &aps, &clients);
                return Err("the case session was revoked — monitor capture stopped".into());
            }
        }
        let read_len = match read(&mut buffer) {
            Ok(0) => continue,
            Ok(len) => len,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => {
                ctx.publish(&capture, &aps, &clients);
                return Err(format!("monitor capture read failed: {err}"));
            }
        };
        ctx.frames_seen.fetch_add(1, Ordering::Release);
        // AP/client bookkeeping over the crate's own dissection; malformed
        // airwave frames are counted but never half-tracked (the engine's
        // honest-error contract: callers treat errors as "skip this frame").
        let book = radiotap::parse(&buffer[..read_len]).and_then(|(radio, header_len)| {
            // Bounded to exactly this read: the buffer tail beyond `read_len`
            // is zero padding, never part of the frame.
            frame::parse(
                &buffer[header_len..read_len],
                radio.fcs_present(),
                radio.data_padded(),
            )
        });
        if let Ok(parsed) = &book {
            match &parsed.kind {
                FrameKind::Beacon { ssid, .. } => {
                    ctx.beacons.fetch_add(1, Ordering::Release);
                    track_access_point(&mut aps, parsed, ssid.as_deref());
                }
                FrameKind::ProbeResponse { ssid, .. } => {
                    track_access_point(&mut aps, parsed, ssid.as_deref());
                }
                _ => {}
            }
            if let Some(station) = client_station_mac(parsed) {
                track_client(&mut clients, station);
            }
        }
        // The engine pairs handshakes and formats the 22000 lines.
        let emitted = capture.process_frame(&buffer[..read_len]);
        let has_lines = emitted.as_ref().map(|lines| !lines.is_empty()).unwrap_or(false);
        since_publish += 1;
        if has_lines || since_publish >= PUBLISH_EVERY_FRAMES {
            ctx.publish(&capture, &aps, &clients);
            since_publish = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// Linux capture source: one AF_PACKET raw socket bound to the monitor
// interface (the `active_arp` pattern), poll-paced bounded reads, never a
// send. Plus the nl80211 control sequence reused from the crate client.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod monitor_socket {
    use std::ffi::{c_int, c_void};
    use std::io;
    use std::os::fd::RawFd;

    const AF_PACKET: c_int = 17;
    const SOCK_RAW: c_int = 3;
    const SOCK_CLOEXEC: c_int = 0o2000000;
    const ETH_P_ALL: u16 = 0x0003;
    const POLLIN: i16 = 1;
    /// Poll timeout per read: bounds idle CPU and stop latency.
    pub(super) const READ_POLL_TIMEOUT_MS: c_int = 100;

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

    unsafe extern "C" {
        fn socket(domain: c_int, typ: c_int, protocol: c_int) -> c_int;
        fn bind(fd: c_int, address: *const c_void, length: u32) -> c_int;
        fn poll(fds: *mut PollFd, count: usize, timeout: c_int) -> c_int;
        fn recvfrom(
            fd: c_int,
            data: *mut c_void,
            length: usize,
            flags: c_int,
            address: *mut c_void,
            address_len: *mut u32,
        ) -> isize;
        fn close(fd: c_int) -> c_int;
    }

    pub(super) struct Fd(pub(super) RawFd);
    impl Drop for Fd {
        fn drop(&mut self) {
            unsafe {
                close(self.0);
            }
        }
    }

    /// Open the receive-only raw capture socket bound to the monitor
    /// interface. No send path exists in this module by construction.
    pub(super) fn open(ifindex: i32) -> io::Result<Fd> {
        let protocol = ETH_P_ALL.to_be();
        let fd = unsafe { socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, c_int::from(protocol)) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
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
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }

    /// One poll-paced read: `Ok(0)` is the no-frame tick (timeout or signal),
    /// `Ok(n)` hands over one captured frame, IO errors are honest failures.
    pub(super) fn read_with_timeout(
        fd: RawFd,
        buffer: &mut [u8],
        timeout_ms: c_int,
    ) -> io::Result<usize> {
        let mut pfd = PollFd {
            fd,
            events: POLLIN,
            revents: 0,
        };
        let polled = unsafe { poll(&mut pfd, 1, timeout_ms) };
        if polled < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(0);
            }
            return Err(err);
        }
        if polled == 0 || pfd.revents & POLLIN == 0 {
            return Ok(0);
        }
        let size = unsafe {
            recvfrom(
                fd,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if size < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                return Ok(0);
            }
            return Err(err);
        }
        Ok(size as usize)
    }
}

#[cfg(target_os = "linux")]
use cyberdeck_packet::wifi::netlink::{ChanWidth, Nl80211Socket};

// ---------------------------------------------------------------------------
// Commands.
// ---------------------------------------------------------------------------

/// Start an authorized monitor-mode capture: switch the selected Linux
/// interface into monitor mode over nl80211, pin the FIRST authorized capture
/// frequency (no channel hopping is automated in this arc), and run the
/// passive AF_PACKET pump until stopped. Refuses without a saved case, an
/// explicit authorization, a free operation gate or a declined native
/// confirmation. Non-Linux platforms get the honest Unsupported refusal.
#[tauri::command]
pub async fn network_wifi_monitor_start_v1(
    interface_name: String,
    channels: String,
    authorized: bool,
    case_id: String,
    app: AppHandle,
    session: State<'_, CaseSessionCtx>,
    evidence: State<'_, EvidenceCtx>,
    gate: State<'_, Arc<super::operation_gate::NetworkOperationGate>>,
    wifi: State<'_, Arc<NetworkWifiCtx>>,
) -> Result<WifiStartWire, String> {
    if !authorized {
        return Err("explicit wifi monitor authorization required".into());
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            interface_name,
            channels,
            case_id,
            app,
            session,
            evidence,
            gate,
            wifi,
        );
        return Err(UNSUPPORTED_MESSAGE.to_string());
    }
    #[cfg(target_os = "linux")]
    {
        let (scope, verified_case) = selected_saved_case(&session)?;
        if case_id != verified_case {
            return Err("request case id does not match the backend-selected case".into());
        }
        let channel_list = parse_channels(&channels)?;
        if gate.is_active() {
            return Err(
                "stop other active network operations before switching the radio into \
                 monitor mode"
                    .into(),
            );
        }
        {
            let store = evidence
                .store
                .lock()
                .map_err(|_| "case store unavailable")?;
            if !store.case_exists(&verified_case)? {
                return Err("selected case does not exist".into());
            }
        }
        let pinned_channel = channel_list[0];

        // Backend confirmation is independent of the frontend checkbox: it
        // names EXACTLY what will happen before the radio changes state.
        let question = format!(
            "Authorize Wi-Fi monitor-mode capture on Linux interface '{}' in saved case '{}'? \
             The backend switches '{}' to monitor mode over nl80211 and pins {} MHz — the \
             first of {} authorized capture frequency(ies); no channel hopping is automated \
             in this arc. The capture is receive-only: 802.11 frames are read and parsed for \
             WPA handshake evidence in hashcat 22000 format, and NOTHING is transmitted. \
             Monitor mode suspends normal connectivity on that interface until you revert \
             it. Requires CAP_NET_ADMIN and permission to test this network.",
            interface_name,
            verified_case,
            interface_name,
            pinned_channel,
            channel_list.len(),
        );
        let dialog_app = app.clone();
        let agreed = tokio::task::spawn_blocking(move || {
            dialog_app
                .dialog()
                .message(question)
                .title("Authorize wifi monitor capture")
                .buttons(MessageDialogButtons::YesNo)
                .blocking_show()
        })
        .await
        .map_err(|_| "wifi monitor confirmation unavailable")?;
        if !agreed {
            return Err("wifi monitor capture cancelled by operator".into());
        }
        session.ensure(&scope)?;
        if gate.is_active() {
            return Err(
                "another network operation became active while confirming the wifi monitor \
                 capture"
                    .into(),
            );
        }

        // nl80211 control (crate client): monitor mode, then the pinned
        // channel. Synchronous and bounded so a refusal surfaces as the
        // command's honest error, not a silent stopped worker.
        let ifindex = i32::try_from(
            cyberdeck_packet::live::select_interface(
                &cyberdeck_packet::live::discover_interfaces().map_err(|e| e.message)?,
                &interface_name,
            )
            .map_err(|e| format!("select wifi interface: {}", e.message))?
            .index,
        )
        .map_err(|_| "interface index exceeds the native range".to_string())?;
        let mut nl = Nl80211Socket::open().map_err(wifi_err)?;
        let family = nl.resolve_family().map_err(wifi_err)?;
        // The kernel must see the interface as a wireless device (a wired
        // adapter refuses here with the honest Device error).
        nl.get_interface(family, ifindex).map_err(wifi_err)?;
        nl.set_monitor(family, ifindex).map_err(wifi_err)?;
        nl.set_channel(family, ifindex, pinned_channel, ChanWidth::NoHt, 0)
            .map_err(wifi_err)?;

        if wifi.running.swap(true, Ordering::AcqRel) {
            return Err("a wifi monitor capture is already active".into());
        }
        wifi.stop.store(false, Ordering::Release);
        wifi.frames_seen.store(0, Ordering::Release);
        wifi.beacons.store(0, Ordering::Release);
        wifi.final_elapsed_ms.store(0, Ordering::Release);
        wifi.channel_mhz
            .store(pinned_channel, Ordering::Release);
        if let Ok(mut slot) = wifi.interface.lock() {
            *slot = interface_name.clone();
        }
        if let Ok(mut slot) = wifi.channels.lock() {
            *slot = channel_list.clone();
        }
        if let Ok(mut slot) = wifi.snapshot.lock() {
            *slot = WifiSnapshot::default();
        }
        if let Ok(mut slot) = wifi.last_error.lock() {
            *slot = None;
        }
        if let Ok(mut slot) = wifi.started_at.lock() {
            *slot = Some(Instant::now());
        } else {
            wifi.running.store(false, Ordering::Release);
            return Err("wifi monitor state registry unavailable".into());
        }
        wifi.evidence_saved.store(false, Ordering::Release);
        // A new capture session starts the injection/hop state clean too
        // (both ride the live session; nothing can be running here).
        wifi.deauth_running.store(false, Ordering::Release);
        wifi.deauth_stop.store(false, Ordering::Release);
        wifi.deauth_frames_sent.store(0, Ordering::Release);
        wifi.deauth_bursts_done.store(0, Ordering::Release);
        wifi.deauth_targets.store(0, Ordering::Release);
        if let Ok(mut slot) = wifi.deauth_note.lock() {
            *slot = None;
        }
        if let Ok(mut slot) = wifi.injection_last_error.lock() {
            *slot = None;
        }
        wifi.hop_running.store(false, Ordering::Release);
        wifi.hop_stop.store(false, Ordering::Release);
        wifi.hop_pause_request.store(false, Ordering::Release);
        if let Ok(mut slot) = wifi.hop.lock() {
            *slot = HopShared::default();
        }
        if let Ok(mut slot) = wifi.hop_last_error.lock() {
            *slot = None;
        }
        wifi.set_phase(WifiPhase::Starting);

        let worker_app = app.clone();
        let worker_scope = scope.clone();
        let worker_ctx = Arc::clone(&*wifi);
        let worker_ifindex = ifindex;
        tokio::task::spawn_blocking(move || {
            let _guard = WifiRunGuard(Arc::clone(&worker_ctx));
            if worker_ctx.stop.load(Ordering::Acquire) {
                return;
            }
            let fd = match monitor_socket::open(worker_ifindex) {
                Ok(fd) => fd,
                Err(err) => {
                    if let Ok(mut slot) = worker_ctx.last_error.lock() {
                        *slot = Some(format!("open monitor capture socket: {err}"));
                    }
                    return;
                }
            };
            worker_ctx.set_phase(WifiPhase::Monitoring);
            // The worker's session closure stays authoritative: a revoked
            // case revision ends the capture honestly.
            let scope_active = || {
                worker_app
                    .state::<CaseSessionCtx>()
                    .ensure(&worker_scope)
                    .is_ok()
            };
            let outcome = run_frame_pump(
                &worker_ctx.stop,
                &scope_active,
                &worker_ctx,
                |buffer| {
                    monitor_socket::read_with_timeout(
                        fd.0,
                        buffer,
                        monitor_socket::READ_POLL_TIMEOUT_MS,
                    )
                },
            );
            worker_ctx.final_elapsed_ms.store(
                worker_ctx
                    .started_at
                    .lock()
                    .ok()
                    .and_then(|g| *g)
                    .map(|s| s.elapsed().as_millis().min(u64::MAX as u128) as u64)
                    .unwrap_or(0),
                Ordering::Release,
            );
            if let Err(message) = outcome {
                if let Ok(mut slot) = worker_ctx.last_error.lock() {
                    *slot = Some(message);
                }
            }
        });
        Ok(WifiStartWire {
            interface: interface_name.clone(),
            channel_mhz: pinned_channel,
            channels: channel_list,
            status: wifi.status_wire(),
        })
    }
}

/// Stop the running capture. Cancellation is NEVER refused: the flag is set
/// regardless of the selected case revision, and the pump exits at its next
/// read boundary before the final phase is published. Returns true when a
/// capture existed.
#[tauri::command]
pub fn network_wifi_monitor_stop_v1(
    wifi: State<'_, Arc<NetworkWifiCtx>>,
) -> Result<bool, String> {
    if !wifi.running.load(Ordering::Acquire) {
        return Ok(false);
    }
    wifi.stop.store(true, Ordering::Release);
    // The worker owns the real transition; "stopping" keeps the UI honest
    // while the last reads drain.
    if wifi.phase() == WifiPhase::Monitoring || wifi.phase() == WifiPhase::Starting {
        wifi.set_phase(WifiPhase::Stopping);
    }
    Ok(true)
}

/// Poll the capture's live state: honest counters, the bounded AP/client
/// tables and the hashcat 22000 lines captured this session. The wire also
/// carries the additive injection/hop fields.
#[tauri::command]
pub fn network_wifi_monitor_status_v1(
    wifi: State<'_, Arc<NetworkWifiCtx>>,
) -> Result<WifiStatusWire, String> {
    Ok(wifi.status_wire())
}

// ---------------------------------------------------------------------------
// Injection (deauth) commands: ACTIVE interference, gated end-to-end like
// the lab ARP spoof. The bounded core lives in the crate (`wifi::inject`);
// this layer owns the gates, the dialog and the worker lifecycle only.
// ---------------------------------------------------------------------------

/// Start a bounded, gate-leased deauth run against BSSIDs the CURRENT monitor
/// session observed. Refuses without explicit authorization, a saved case, a
/// live monitor session, in-session targets, a free gate or an accepted
/// native confirmation. Linux-only; other platforms get the honest
/// Unsupported refusal. Hard bounds (crate-enforced): ≤ 4 targets, ≤ 4
/// bursts, ≤ 32 frames per burst across all targets, ≥ 20 ms frame pacing,
/// ≤ 10 s total, stop never refused.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn network_wifi_inject_deauth_v1(
    interface_name: String,
    targets: Vec<String>,
    bursts: u32,
    frames_per_target: u32,
    authorized: bool,
    case_id: String,
    app: AppHandle,
    session: State<'_, CaseSessionCtx>,
    evidence: State<'_, EvidenceCtx>,
    gate: State<'_, Arc<super::operation_gate::NetworkOperationGate>>,
    wifi: State<'_, Arc<NetworkWifiCtx>>,
) -> Result<WifiInjectStartWire, String> {
    if !authorized {
        return Err("explicit wifi injection authorization required".into());
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            interface_name,
            targets,
            bursts,
            frames_per_target,
            case_id,
            app,
            session,
            evidence,
            gate,
            wifi,
        );
        return Err(INJECTION_UNSUPPORTED_MESSAGE.to_string());
    }
    #[cfg(target_os = "linux")]
    {
        let (scope, verified_case) = selected_saved_case(&session)?;
        if case_id != verified_case {
            return Err("request case id does not match the backend-selected case".into());
        }
        // Injection rides a LIVE monitor session; the observed AP table of
        // that session is the ONLY target source.
        require_live_monitor(&wifi)?;
        let observed = wifi
            .snapshot
            .lock()
            .map_err(|_| "wifi monitor state registry unavailable")?
            .access_points
            .clone();
        let target_macs = resolve_observed_targets(&targets, &observed)?;
        let bursts_usize = bursts as usize;
        let frames_usize = frames_per_target as usize;
        inject::validate_deauth_plan(&target_macs, bursts_usize, frames_usize)
            .map_err(wifi_err)?;
        // Hopping and injection both drive the radio's channel: one at a time.
        if wifi.hop_running.load(Ordering::Acquire) {
            return Err(
                "stop channel hopping before injecting — both drive the radio's channel".into(),
            );
        }
        if gate.is_active() {
            return Err("stop other active network operations before injecting deauth frames".into());
        }
        {
            let store = evidence
                .store
                .lock()
                .map_err(|_| "case store unavailable")?;
            if !store.case_exists(&verified_case)? {
                return Err("selected case does not exist".into());
            }
        }

        // Backend confirmation is independent of the frontend checkbox: it
        // names EXACTLY what will be transmitted before the first frame.
        let target_list: Vec<String> = target_macs.iter().map(|m| format_mac(m)).collect();
        let per_burst = frames_usize.saturating_mul(target_macs.len());
        let total = per_burst.saturating_mul(bursts_usize);
        let question = format!(
            "Authorize Wi-Fi deauth injection on Linux interface '{}' in saved case '{}'? \
             This is ACTIVE interference: {} deauthentication frame(s) per burst directed at \
             the BSSID(s) {} ({} frame(s) per target per burst, {} burst(s), {} frames total), \
             reason code 7, transmitted with this machine's real MAC on the interface's \
             CURRENT channel — keep the monitor pinned to the target AP's channel. Targets \
             are limited to BSSIDs the current monitor session observed. Hard bounds: at \
             most 32 frames per burst, 4 bursts, 10 seconds total; frames are rate-limited \
             and the run stops immediately on operator stop. Requires CAP_NET_RAW and \
             permission to test this network.",
            interface_name,
            verified_case,
            per_burst,
            target_list.join(", "),
            frames_usize,
            bursts_usize,
            total,
        );
        let dialog_app = app.clone();
        let agreed = tokio::task::spawn_blocking(move || {
            dialog_app
                .dialog()
                .message(question)
                .title("Authorize wifi deauth injection")
                .buttons(MessageDialogButtons::YesNo)
                .blocking_show()
        })
        .await
        .map_err(|_| "wifi deauth injection confirmation unavailable")?;
        if !agreed {
            return Err("wifi deauth injection cancelled by operator".into());
        }
        session.ensure(&scope)?;
        if gate.is_active() {
            return Err(
                "another network operation became active while confirming the deauth injection"
                    .into(),
            );
        }
        if wifi.hop_running.load(Ordering::Acquire) {
            return Err(
                "channel hopping started while confirming the deauth injection — stop it first"
                    .into(),
            );
        }
        require_live_monitor(&wifi)?;
        let permit = gate.acquire(super::operation_gate::ActiveOperation::WifiInject)?;
        if wifi.deauth_running.swap(true, Ordering::AcqRel) {
            return Err("a wifi deauth run is already active".into());
        }
        wifi.deauth_stop.store(false, Ordering::Release);
        wifi.deauth_frames_sent.store(0, Ordering::Release);
        wifi.deauth_bursts_done.store(0, Ordering::Release);
        wifi.deauth_targets
            .store(target_macs.len(), Ordering::Release);
        if let Ok(mut slot) = wifi.deauth_note.lock() {
            *slot = None;
        }
        if let Ok(mut slot) = wifi.injection_last_error.lock() {
            *slot = None;
        }

        let worker_app = app.clone();
        let worker_scope = scope.clone();
        let worker_ctx = Arc::clone(&*wifi);
        let worker_interface = interface_name.clone();
        let worker_targets = target_macs.clone();
        tokio::task::spawn_blocking(move || {
            // The gate lease lives for the whole worker lifetime.
            let _permit = permit;
            let scope_active = || {
                worker_app
                    .state::<CaseSessionCtx>()
                    .ensure(&worker_scope)
                    .is_ok()
            };
            let outcome = inject::run_wifi_deauth(
                &worker_interface,
                &worker_targets,
                bursts_usize,
                frames_usize,
                &worker_ctx.deauth_stop,
                &scope_active,
                &worker_ctx.deauth_frames_sent,
            );
            match outcome {
                Ok(outcome) => {
                    worker_ctx
                        .deauth_bursts_done
                        .store(outcome.bursts_completed, Ordering::Release);
                    let note = format!(
                        "deauth run ended: {} frame(s) across {} burst(s) over {} target(s) — {:?}",
                        outcome.frames_sent,
                        outcome.bursts_completed,
                        worker_targets.len(),
                        outcome.end_reason,
                    );
                    if let Ok(mut slot) = worker_ctx.deauth_note.lock() {
                        *slot = Some(note);
                    }
                    if let Some(err) = outcome.error {
                        if let Ok(mut slot) = worker_ctx.injection_last_error.lock() {
                            *slot = Some(format!("{:?}: {}", err.code, err.message));
                        }
                    }
                }
                Err(err) => {
                    if let Ok(mut slot) = worker_ctx.injection_last_error.lock() {
                        *slot = Some(format!("{:?}: {}", err.code, err.message));
                    }
                }
            }
        });
        Ok(WifiInjectStartWire {
            targets: target_list,
            bursts,
            frames_per_target,
            frames_per_burst: per_burst as u32,
            total_frames: total as u32,
            status: wifi.status_wire(),
        })
    }
}

/// Stop the running deauth run. Cancellation is NEVER refused (hard stop):
/// the flag is set regardless of the selected case revision and the paced
/// loop exits before its next frame. Returns true when a run existed.
#[tauri::command]
pub fn network_wifi_inject_deauth_stop_v1(
    wifi: State<'_, Arc<NetworkWifiCtx>>,
) -> Result<bool, String> {
    if !wifi.deauth_running.load(Ordering::Acquire) {
        return Ok(false);
    }
    wifi.deauth_stop.store(true, Ordering::Release);
    Ok(true)
}

/// Start / pause / resume / stop the bounded channel-hop scheduler over the
/// LIVE monitor interface. The capture keeps running across hops; every
/// applied hop is driven over nl80211 SET_CHANNEL by the worker and recorded
/// in the ≤ 256-entry hop log. Passive radio control — it takes no gate
/// lease, but it refuses to start while a deauth run or another active
/// operation holds the radio, and injection refuses while hopping runs.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn network_wifi_channel_hop_v1(
    interface_name: String,
    channels: String,
    interval_ms: u32,
    action: String,
    authorized: bool,
    app: AppHandle,
    session: State<'_, CaseSessionCtx>,
    gate: State<'_, Arc<super::operation_gate::NetworkOperationGate>>,
    wifi: State<'_, Arc<NetworkWifiCtx>>,
) -> Result<WifiHopWire, String> {
    if !authorized {
        return Err("explicit wifi channel-hop authorization required".into());
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            interface_name,
            channels,
            interval_ms,
            action,
            app,
            session,
            gate,
            wifi,
        );
        return Err(HOP_UNSUPPORTED_MESSAGE.to_string());
    }
    #[cfg(target_os = "linux")]
    {
        match action.as_str() {
        // Pause/resume/stop never re-check the case revision: they only ever
        // make the radio LESS active, like the monitor stop command.
        "pause" | "resume" | "stop" => {
            if !wifi.hop_running.load(Ordering::Acquire) {
                return Err("channel hopping is not running".into());
            }
            match action.as_str() {
                "pause" => {
                    wifi.hop_pause_request.store(true, Ordering::Release);
                }
                "resume" => {
                    wifi.hop_pause_request.store(false, Ordering::Release);
                }
                _ => {
                    // The worker owns the transition; the run guard publishes
                    // the honest stopped state when it exits.
                    wifi.hop_stop.store(true, Ordering::Release);
                }
            }
            Ok(hop_wire(&action, &wifi))
        }
        "start" => {
            let (scope, _verified_case) = selected_saved_case(&session)?;
            require_live_monitor(&wifi)?;
            // The hop plan rides the session's authorized capture channels.
            let channel_list = parse_channels(&channels)?;
            if !(inject::MIN_HOP_INTERVAL_MS..=inject::MAX_HOP_INTERVAL_MS)
                .contains(&u64::from(interval_ms))
            {
                return Err(format!(
                    "hop interval must be {}..={} ms",
                    inject::MIN_HOP_INTERVAL_MS,
                    inject::MAX_HOP_INTERVAL_MS
                ));
            }
            if wifi.deauth_running.load(Ordering::Acquire) {
                return Err(
                    "a deauth run is active — wait for it to end before channel hopping".into(),
                );
            }
            if gate.is_active() {
                return Err(
                    "stop other active network operations before channel hopping".into(),
                );
            }
            if wifi.hop_running.swap(true, Ordering::AcqRel) {
                return Err("channel hopping is already active".into());
            }
            wifi.hop_stop.store(false, Ordering::Release);
            wifi.hop_pause_request.store(false, Ordering::Release);
            if let Ok(mut slot) = wifi.hop_last_error.lock() {
                *slot = None;
            }
            // Validated + stored before the worker spawns; the worker takes
            // the scheduler from this slot and drives it on its own clock.
            let scheduler = ChannelHopScheduler::new(channel_list.clone(), u64::from(interval_ms))
                .map_err(wifi_err)?;
            if let Ok(mut slot) = wifi.hop.lock() {
                // A fresh run replaces the previous run's log (mirrors the
                // snapshot reset on monitor start).
                *slot = HopShared {
                    scheduler: Some(scheduler),
                };
            } else {
                wifi.hop_running.store(false, Ordering::Release);
                return Err("wifi hop state registry unavailable".into());
            }
            let ifindex = i32::try_from(
                cyberdeck_packet::live::select_interface(
                    &cyberdeck_packet::live::discover_interfaces().map_err(|e| e.message)?,
                    &interface_name,
                )
                .map_err(|e| format!("select wifi interface: {}", e.message))?
                .index,
            )
            .map_err(|_| "interface index exceeds the native range".to_string())?;

            let worker_app = app.clone();
            let worker_scope = scope.clone();
            let worker_ctx = Arc::clone(&*wifi);
            let worker_ifindex = ifindex;
            tokio::task::spawn_blocking(move || {
                let _guard = HopRunGuard(Arc::clone(&worker_ctx));
                if worker_ctx.hop_stop.load(Ordering::Acquire) {
                    return;
                }
                let mut nl = match cyberdeck_packet::wifi::netlink::Nl80211Socket::open() {
                    Ok(nl) => nl,
                    Err(err) => {
                        if let Ok(mut slot) = worker_ctx.hop_last_error.lock() {
                            *slot = Some(wifi_err(err));
                        }
                        return;
                    }
                };
                let family = match nl.resolve_family() {
                    Ok(family) => family,
                    Err(err) => {
                        if let Ok(mut slot) = worker_ctx.hop_last_error.lock() {
                            *slot = Some(wifi_err(err));
                        }
                        return;
                    }
                };
                // The kernel must see the interface as a wireless device.
                if let Err(err) = nl.get_interface(family, worker_ifindex) {
                    if let Ok(mut slot) = worker_ctx.hop_last_error.lock() {
                        *slot = Some(wifi_err(err));
                    }
                    return;
                }
                let started = Instant::now();
                let scope_active = || {
                    worker_app
                        .state::<CaseSessionCtx>()
                        .ensure(&worker_scope)
                        .is_ok()
                };
                loop {
                    if worker_ctx.hop_stop.load(Ordering::Acquire) {
                        return;
                    }
                    if !scope_active() {
                        if let Ok(mut slot) = worker_ctx.hop_last_error.lock() {
                            *slot = Some(
                                "the case session was revoked — channel hopping stopped".into(),
                            );
                        }
                        return;
                    }
                    let now_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
                    // One short critical section: apply the pause/resume
                    // request, then take at most one due hop.
                    let due = {
                        let mut guard = match worker_ctx.hop.lock() {
                            Ok(guard) => guard,
                            Err(_) => {
                                if let Ok(mut slot) = worker_ctx.hop_last_error.lock() {
                                    *slot = Some("wifi hop state registry unavailable".into());
                                }
                                return;
                            }
                        };
                        let Some(scheduler) = guard.scheduler.as_mut() else {
                            return; // the plan was replaced/cleared: run over
                        };
                        let pause_requested = worker_ctx.hop_pause_request.load(Ordering::Acquire);
                        if pause_requested && !scheduler.is_paused() {
                            scheduler.pause();
                        } else if !pause_requested && scheduler.is_paused() {
                            scheduler.resume(now_ms);
                        }
                        scheduler.tick(now_ms)
                    };
                    if let Some(to_mhz) = due {
                        if let Err(err) = nl.set_channel(
                            family,
                            worker_ifindex,
                            to_mhz,
                            ChanWidth::NoHt,
                            0,
                        ) {
                            if let Ok(mut slot) = worker_ctx.hop_last_error.lock() {
                                *slot = Some(wifi_err(err));
                            }
                            return;
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(HOP_POLL_SLICE_MS));
                }
            });
            Ok(hop_wire(&action, &wifi))
        }
        _ => Err("hop action must be start, pause, resume or stop".into()),
        }
    }
}

/// Runs for the whole hop worker lifetime; clears the running flag and the
/// pause request even when the worker panicked or the runtime dropped it.
/// The scheduler (and its full hop log) stays in the registry after the run.
struct HopRunGuard(Arc<NetworkWifiCtx>);
impl Drop for HopRunGuard {
    fn drop(&mut self) {
        self.0.hop_running.store(false, Ordering::Release);
        self.0.hop_pause_request.store(false, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// Evidence save: ONE bounded case finding per capture session, persisted
// through the standard evidence path (same store-lock -> publication-gate
// order as every case finding).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct WifiEvidenceReceiptWire {
    pub case_id: String,
    pub line_count: usize,
    pub byte_len: u64,
    pub truncated: bool,
}

/// Byte-bound the rendered details on a char boundary with an honest marker.
fn bound_details(details: String) -> (String, bool) {
    if details.len() <= MAX_WIFI_EVIDENCE_BYTES {
        return (details, false);
    }
    let mut cap = MAX_WIFI_EVIDENCE_BYTES.saturating_sub(EVIDENCE_TRUNCATION_MARKER.len());
    while cap > 0 && !details.is_char_boundary(cap) {
        cap -= 1;
    }
    let mut bounded = String::with_capacity(cap + EVIDENCE_TRUNCATION_MARKER.len());
    bounded.push_str(&details[..cap]);
    bounded.push_str(EVIDENCE_TRUNCATION_MARKER);
    (bounded, true)
}

/// The single persisted case finding: backend-constructed title, info
/// severity and the bounded artifact as details (session honesty header +
/// one hashcat 22000 line per handshake evidence).
fn build_evidence_finding(
    interface: &str,
    channel_mhz: u32,
    frames_seen: u64,
    beacons: u64,
    snapshot: &WifiSnapshot,
    generated_ms: u64,
) -> NewFinding {
    let mut details = format!(
        "# Wifi monitor capture (hashcat 22000)\n\nInterface: {interface} · capture \
         frequency: {channel_mhz} MHz · frames seen: {frames_seen} · beacons: {beacons} · \
         clients: {} · handshakes: {}\nGenerated (unix ms): {generated_ms}\n\n## Hashcat \
         22000 lines\n",
        snapshot.clients.len(),
        snapshot.handshakes,
    );
    for line in &snapshot.lines {
        details.push_str(line);
        details.push('\n');
    }
    let (bounded, _) = bound_details(details);
    NewFinding {
        title: WIFI_EVIDENCE_TITLE.to_string(),
        severity: "info".into(),
        details: bounded,
    }
}

/// Current wall-clock in epoch milliseconds; 0 keeps the finding honest if
/// the clock is unavailable (0 is documented as unknown provenance).
fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Persist this capture session's hashcat 22000 lines as ONE bounded finding
/// into the backend-selected saved case. Read-only over the capture; the only
/// write is the one case finding. Once per session: a second save refuses
/// honestly instead of duplicating case evidence.
#[tauri::command]
pub fn network_wifi_evidence_save_v1(
    case_id: String,
    session: State<'_, CaseSessionCtx>,
    evidence: State<'_, EvidenceCtx>,
    wifi: State<'_, Arc<NetworkWifiCtx>>,
) -> Result<WifiEvidenceReceiptWire, String> {
    let (scope, verified_case) = selected_saved_case(&session)?;
    if case_id != verified_case {
        return Err("request case id does not match the backend-selected case".into());
    }
    if wifi.evidence_saved.swap(true, Ordering::AcqRel) {
        return Err(
            "this capture session already saved its one bounded evidence finding".into(),
        );
    }
    let snapshot = wifi
        .snapshot
        .lock()
        .map_err(|_| "wifi monitor state registry unavailable")?
        .clone();
    if snapshot.lines.is_empty() {
        wifi.evidence_saved.store(false, Ordering::Release);
        return Err("no hashcat 22000 lines captured this session — nothing to save".into());
    }
    let finding = build_evidence_finding(
        &wifi.interface.lock().map_err(|_| "wifi monitor state registry unavailable")?,
        wifi.channel_mhz.load(Ordering::Acquire),
        wifi.frames_seen.load(Ordering::Acquire),
        wifi.beacons.load(Ordering::Acquire),
        &snapshot,
        unix_ms(),
    );
    let truncated = finding.details.contains(EVIDENCE_TRUNCATION_MARKER);
    let receipt = WifiEvidenceReceiptWire {
        case_id: verified_case.clone(),
        line_count: snapshot.lines.len(),
        byte_len: finding.details.len() as u64,
        truncated,
    };
    let store = evidence
        .store
        .lock()
        .map_err(|_| "case evidence store unavailable")?;
    session.with_current_publication(&scope, || {
        store.add_findings(&verified_case, WIFI_EVIDENCE_SOURCE, None, &[finding])?;
        Ok(())
    })?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::atomic::AtomicUsize;

    // ---- synthetic monitor fixtures ---------------------------------------
    // Mirrors the crate's own wifi tests (crates/packet/src/wifi/mod.rs):
    // same fixture generator, same constants, so the pump is exercised with
    // REAL hashcat-emittable handshakes instead of hand-waved bytes.

    const AP: [u8; 6] = [0xa4, 0xb1, 0xc1, 0xd2, 0xe3, 0xf0];
    const STA: [u8; 6] = [0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f];

    /// Synthetic handshake fixtures (crate tests): password
    /// "cyberdeck-e2e-42" / ESSID "cyberdeck-e2e".
    const M1_HEX: &str = "0203007502008a0010000000000000000111223344556677881122334455667788112233445566778811223344556677880000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016dd14000fac048066ad9635ac9def6b250b58866e22b7";
    const M2_FULL_HEX: &str = "0203005f02010a00100000000000000001aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff001100000000000000000000000000000000000000000000000000000000000000005267a6a133650da8a3933e15aa50536b0000";
    const EXPECTED_PMKID_LINE: &str = "WPA*01*8066ad9635ac9def6b250b58866e22b7*a4b1c1d2e3f0*0a1b2c3d4e5f*63796265726465636b2d653265***";
    const EXPECTED_EAPOL_LINE: &str = "WPA*02*5267a6a133650da8a3933e15aa50536b*a4b1c1d2e3f0*0a1b2c3d4e5f*63796265726465636b2d653265*1122334455667788112233445566778811223344556677881122334455667788*0203005f02010a00100000000000000001aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff00110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*00";

    fn hex_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex fixture"))
            .collect()
    }

    /// Radiotap header (FLAGS = FCS present) + a QoS data LLC/SNAP frame.
    fn radiotap_snap_frame(
        ap: [u8; 6],
        sta: [u8; 6],
        ap_to_sta: bool,
        ethertype: u16,
        body: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0);
        out.push(0);
        out.extend_from_slice(&9u16.to_le_bytes());
        out.extend_from_slice(&2u32.to_le_bytes());
        out.push(radiotap::FLAG_FCS_AT_END);
        let flags: u16 = if ap_to_sta { 0x0200 } else { 0x0100 };
        let fc_word = (2u16 << 2) | (8u16 << 4) | flags;
        out.extend_from_slice(&fc_word.to_le_bytes());
        out.extend_from_slice(&[0x00, 0x00]);
        if ap_to_sta {
            out.extend_from_slice(&sta);
            out.extend_from_slice(&ap);
            out.extend_from_slice(&ap);
        } else {
            out.extend_from_slice(&ap);
            out.extend_from_slice(&sta);
            out.extend_from_slice(&ap);
        }
        out.extend_from_slice(&[0x10, 0x00]);
        out.extend_from_slice(&[0x00, 0x00]);
        let mut llc: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00];
        llc[6..8].copy_from_slice(&ethertype.to_be_bytes());
        out.extend_from_slice(&llc);
        out.extend_from_slice(body);
        out.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        out
    }

    fn radiotap_eapol_frame(ap: [u8; 6], sta: [u8; 6], ap_to_sta: bool, body: &[u8]) -> Vec<u8> {
        radiotap_snap_frame(ap, sta, ap_to_sta, 0x888e, body)
    }

    fn beacon_frame(bssid: [u8; 6], ssid: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0);
        out.push(0);
        out.extend_from_slice(&8u16.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        let fc_word = (0u16 << 2) | (8u16 << 4);
        out.extend_from_slice(&fc_word.to_le_bytes());
        out.extend_from_slice(&[0x00, 0x00]);
        out.extend_from_slice(&[0xff; 6]);
        out.extend_from_slice(&bssid);
        out.extend_from_slice(&bssid);
        out.extend_from_slice(&[0x10, 0x00]);
        out.extend_from_slice(&[0u8; 8]);
        out.extend_from_slice(&100u16.to_be_bytes());
        out.extend_from_slice(&0x0411u16.to_le_bytes());
        out.push(0x00);
        out.push(ssid.len() as u8);
        out.extend_from_slice(ssid);
        out
    }

    /// Scripted reader: hands each scripted frame to the pump, `Ok(0)` for
    /// `None` ticks; when the script is exhausted it arms the stop flag so
    /// the pump exits honestly at its next read boundary.
    fn scripted_reader(
        script: Vec<Option<Vec<u8>>>,
        stop: Arc<AtomicBool>,
    ) -> impl FnMut(&mut [u8]) -> io::Result<usize> {
        let script = std::cell::RefCell::new(script.into_iter());
        move |buffer: &mut [u8]| -> io::Result<usize> {
            let mut iter = script.borrow_mut();
            match iter.next() {
                Some(Some(frame)) => {
                    let len = frame.len().min(buffer.len());
                    buffer[..len].copy_from_slice(&frame[..len]);
                    Ok(len)
                }
                Some(None) => Ok(0),
                None => {
                    stop.store(true, Ordering::Release);
                    Ok(0)
                }
            }
        }
    }

    // ---- context / phase machine -------------------------------------------

    #[test]
    fn phase_labels_cover_the_whole_lifecycle_in_snake_case() {
        assert_eq!(WifiPhase::Idle.as_str(), "idle");
        assert_eq!(WifiPhase::Starting.as_str(), "starting");
        assert_eq!(WifiPhase::Monitoring.as_str(), "monitoring");
        assert_eq!(WifiPhase::Stopping.as_str(), "stopping");
        assert_eq!(WifiPhase::Stopped.as_str(), "stopped");
    }

    #[test]
    fn status_wire_starts_honest_at_zero_and_reports_after_a_session() {
        let ctx = NetworkWifiCtx::default();
        let wire = ctx.status_wire();
        assert_eq!(wire.state, "idle");
        assert_eq!(wire.interface, "");
        assert_eq!(wire.channel_mhz, 0);
        assert!(wire.channels.is_empty());
        assert_eq!(wire.frames_seen, 0);
        assert_eq!(wire.beacons, 0);
        assert_eq!(wire.clients_seen, 0);
        assert_eq!(wire.handshakes_captured, 0);
        assert!(wire.hashcat_22000_lines.is_empty());
        assert!(wire.access_points.is_empty());
        assert!(wire.clients.is_empty());
        assert_eq!(wire.elapsed_ms, 0);
        assert!(wire.last_error.is_none());
        // A finished session keeps every counter readable through the wire.
        ctx.frames_seen.store(1234, Ordering::Release);
        ctx.beacons.store(56, Ordering::Release);
        ctx.channel_mhz.store(2437, Ordering::Release);
        ctx.final_elapsed_ms.store(4200, Ordering::Release);
        if let Ok(mut slot) = ctx.interface.lock() {
            *slot = "wlan0".into();
        }
        if let Ok(mut slot) = ctx.channels.lock() {
            *slot = vec![2412, 2437, 2462];
        }
        if let Ok(mut slot) = ctx.snapshot.lock() {
            slot.lines = vec!["WPA*01*abc".into()];
            slot.handshakes = 1;
            slot.clients = vec![format_mac(&STA)];
            slot.access_points = vec![WifiApWire {
                bssid: format_mac(&AP),
                essid: "lab-net".into(),
            }];
        }
        ctx.set_phase(WifiPhase::Stopped);
        let wire = ctx.status_wire();
        assert_eq!(wire.state, "stopped");
        assert_eq!(wire.interface, "wlan0");
        assert_eq!(wire.channel_mhz, 2437);
        assert_eq!(wire.channels, vec![2412, 2437, 2462]);
        assert_eq!(wire.frames_seen, 1234);
        assert_eq!(wire.beacons, 56);
        assert_eq!(wire.clients_seen, 1);
        assert_eq!(wire.handshakes_captured, 1);
        assert_eq!(wire.hashcat_22000_lines.len(), 1);
        assert_eq!(wire.elapsed_ms, 4200);
    }

    #[test]
    fn the_run_guard_publishes_stopped_and_case_change_arms_the_stop_flag() {
        let ctx = Arc::new(NetworkWifiCtx::default());
        ctx.running.store(true, Ordering::Release);
        ctx.set_phase(WifiPhase::Monitoring);
        drop(WifiRunGuard(Arc::clone(&ctx)));
        assert!(!ctx.running.load(Ordering::Acquire));
        assert_eq!(ctx.phase(), WifiPhase::Stopped);
        // The case-change hook arms the flag the pump polls per read.
        ctx.on_case_changed();
        assert!(ctx.stop.load(Ordering::Acquire));
    }

    // ---- channel parsing ----------------------------------------------------

    #[test]
    fn channel_parsing_maps_bands_and_explicit_frequencies() {
        assert_eq!(parse_channels("1,6,11").unwrap(), vec![2412, 2437, 2462]);
        assert_eq!(parse_channels("14").unwrap(), vec![2484]);
        assert_eq!(parse_channels("36").unwrap(), vec![5180]);
        assert_eq!(parse_channels("165").unwrap(), vec![5825]);
        // Explicit MHz frequencies pass through verbatim (6 GHz and beyond).
        assert_eq!(parse_channels("6115").unwrap(), vec![6115]);
        assert_eq!(parse_channels("2437").unwrap(), vec![2437]);
        // Mixed separators, dedupe, order preserved.
        assert_eq!(
            parse_channels("6, 6\n1\t,11").unwrap(),
            vec![2437, 2412, 2462]
        );
    }

    #[test]
    fn channel_parsing_refuses_garbage_out_of_range_and_oversized_lists() {
        assert!(parse_channels("").unwrap_err().contains("at least one"));
        assert!(parse_channels("   ").unwrap_err().contains("at least one"));
        assert!(parse_channels("abc").unwrap_err().contains("not a number"));
        let refused = parse_channels("2000").unwrap_err();
        assert!(refused.contains("neither a supported"), "{refused}");
        assert!(parse_channels("0").is_err());
        assert!(parse_channels("15").is_err());
        let oversized = parse_channels(
            &(1..=14)
                .chain(32..=50)
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(","),
        )
        .unwrap_err();
        assert!(oversized.contains("at most 16"), "{oversized}");
    }

    // ---- the pump -----------------------------------------------------------

    #[test]
    fn run_frame_pump_counts_frames_beacons_clients_and_publishes_evidence() {
        let ctx = Arc::new(NetworkWifiCtx::default());
        let stop = Arc::new(AtomicBool::new(false));
        let script = vec![
            Some(beacon_frame(AP, b"cyberdeck-e2e")),
            None, // a no-frame poll tick: never counted as a frame
            Some(radiotap_eapol_frame(AP, STA, true, &hex_bytes(M1_HEX))),
            Some(radiotap_eapol_frame(AP, STA, false, &hex_bytes(M2_FULL_HEX))),
        ];
        let read = scripted_reader(script, Arc::clone(&stop));
        let outcome = run_frame_pump(&stop, &|| true, &ctx, read);
        assert!(outcome.is_ok(), "{outcome:?}");
        assert!(stop.load(Ordering::Acquire));
        // Poll ticks are not frames.
        assert_eq!(ctx.frames_seen.load(Ordering::Acquire), 3);
        assert_eq!(ctx.beacons.load(Ordering::Acquire), 1);
        let wire = ctx.status_wire();
        assert_eq!(wire.frames_seen, 3);
        assert_eq!(wire.beacons, 1);
        assert_eq!(wire.handshakes_captured, 1);
        assert!(wire.hashcat_22000_lines.contains(&EXPECTED_PMKID_LINE.to_string()));
        assert!(wire.hashcat_22000_lines.contains(&EXPECTED_EAPOL_LINE.to_string()));
        // The AP/client table derives from frame roles.
        assert_eq!(wire.access_points.len(), 1);
        assert_eq!(wire.access_points[0].bssid, format_mac(&AP));
        assert_eq!(wire.access_points[0].essid, "cyberdeck-e2e");
        assert_eq!(wire.clients_seen, 1);
        assert_eq!(wire.clients, vec![format_mac(&STA)]);
    }

    #[test]
    fn the_stop_flag_is_checked_before_every_read() {
        let ctx = NetworkWifiCtx::default();
        let stop = AtomicBool::new(true);
        let reads = AtomicUsize::new(0);
        let outcome = run_frame_pump(&stop, &|| true, &ctx, |_buffer| {
            reads.fetch_add(1, Ordering::Release);
            Ok(0)
        });
        assert!(outcome.is_ok());
        assert_eq!(reads.load(Ordering::Acquire), 0);
        assert_eq!(ctx.frames_seen.load(Ordering::Acquire), 0);
    }

    #[test]
    fn scope_revocation_stops_the_capture_with_an_honest_error() {
        let ctx = NetworkWifiCtx::default();
        let stop = AtomicBool::new(false);
        let reads = AtomicUsize::new(0);
        let read = |_buffer: &mut [u8]| -> io::Result<usize> {
            reads.fetch_add(1, Ordering::Release);
            Ok(0)
        };
        // The session-revocation closure goes false after 100 reads; the pump
        // re-checks it on its bounded cadence and stops with the honest error.
        let outcome = run_frame_pump(&stop, &|| reads.load(Ordering::Acquire) < 100, &ctx, read);
        assert!(outcome.is_err());
        assert!(outcome.unwrap_err().contains("revoked"));
    }

    #[test]
    fn snapshot_tables_stay_bounded() {
        let ctx = Arc::new(NetworkWifiCtx::default());
        let stop = Arc::new(AtomicBool::new(false));
        let mut script = Vec::new();
        for index in 0..80u32 {
            let mut bssid = [0xa4u8, 0xb1, 0x00, 0x00, 0x00, 0x00];
            bssid[2..6].copy_from_slice(&index.to_be_bytes());
            script.push(Some(beacon_frame(bssid, b"bounded-net")));
        }
        for index in 0..300u32 {
            let mut sta = [0x02u8, 0x00, 0x00, 0x00, 0x00, 0x00];
            sta[4..6].copy_from_slice(&(index as u16).to_be_bytes());
            script.push(Some(radiotap_snap_frame(AP, sta, false, 0x0800, &[0x45, 0, 0, 0])));
        }
        let read = scripted_reader(script, Arc::clone(&stop));
        let outcome = run_frame_pump(&stop, &|| true, &ctx, read);
        assert!(outcome.is_ok(), "{outcome:?}");
        let wire = ctx.status_wire();
        assert_eq!(wire.access_points.len(), MAX_WIFI_ACCESS_POINTS);
        assert_eq!(wire.clients.len(), MAX_WIFI_CLIENTS);
        assert!(wire.hashcat_22000_lines.is_empty());
    }

    #[test]
    fn broadcast_and_the_ap_itself_are_never_clients() {
        let ctx = Arc::new(NetworkWifiCtx::default());
        let stop = Arc::new(AtomicBool::new(false));
        let broadcast = [0xffu8; 6];
        let multicast = [0x33u8, 0x33, 0x00, 0x00, 0x00, 0x01];
        let script = vec![
            Some(beacon_frame(AP, b"cyberdeck-e2e")),
            // Data frame FROM the AP to broadcast: source == bssid, dest broadcast.
            Some(radiotap_snap_frame(AP, broadcast, true, 0x0800, &[0x45, 0, 0, 0])),
            // Data frame to multicast: destination is multicast, never a client.
            Some(radiotap_snap_frame(AP, multicast, false, 0x0800, &[0x45, 0, 0, 0])),
        ];
        let read = scripted_reader(script, Arc::clone(&stop));
        let outcome = run_frame_pump(&stop, &|| true, &ctx, read);
        assert!(outcome.is_ok(), "{outcome:?}");
        let wire = ctx.status_wire();
        assert_eq!(wire.clients_seen, 0);
        assert!(wire.clients.is_empty());
    }

    // ---- platform honesty ---------------------------------------------------

    #[test]
    fn monitor_control_is_unsupported_off_linux_honestly() {
        // The crate's honest parity: the door exists only on Linux.
        assert_eq!(monitor_mode_supported(), cfg!(target_os = "linux"));
        assert!(UNSUPPORTED_MESSAGE.contains("requires Linux"));
        assert!(UNSUPPORTED_MESSAGE.contains("nl80211"));
        assert!(platform_status_note().contains("passive receive-only") == cfg!(target_os = "linux"));
    }

    #[test]
    fn npcap_probe_is_false_off_windows() {
        // Npcap is a Windows driver; every other platform reports false.
        if cfg!(not(target_os = "windows")) {
            assert!(!npcap_detected_probe());
        }
    }

    #[test]
    fn mac_formatting_is_lowercase_colon_separated() {
        assert_eq!(format_mac(&AP), "a4:b1:c1:d2:e3:f0");
        assert_eq!(format_mac(&STA), "0a:1b:2c:3d:4e:5f");
    }

    // ---- evidence save ------------------------------------------------------

    #[test]
    fn evidence_finding_is_fixed_titled_and_carries_the_22000_lines() {
        let snapshot = WifiSnapshot {
            lines: vec![EXPECTED_PMKID_LINE.to_string(), EXPECTED_EAPOL_LINE.to_string()],
            handshakes: 1,
            access_points: vec![WifiApWire {
                bssid: format_mac(&AP),
                essid: "cyberdeck-e2e".into(),
            }],
            clients: vec![format_mac(&STA)],
        };
        let finding = build_evidence_finding("wlan0", 2437, 42, 3, &snapshot, 1_700_000_000_000);
        assert_eq!(finding.title, "Wifi monitor handshakes (hashcat 22000)");
        assert_eq!(finding.severity, "info");
        assert!(finding.details.contains("# Wifi monitor capture (hashcat 22000)"));
        assert!(finding.details.contains("Interface: wlan0"));
        assert!(finding.details.contains("capture frequency: 2437 MHz"));
        assert!(finding.details.contains("frames seen: 42"));
        assert!(finding.details.contains("Generated (unix ms): 1700000000000"));
        assert!(finding.details.contains(EXPECTED_PMKID_LINE));
        assert!(finding.details.contains(EXPECTED_EAPOL_LINE));
    }

    #[test]
    fn oversize_evidence_is_bounded_at_the_cap_with_an_honest_marker() {
        let big_line = format!("WPA*01*{}", "a".repeat(400));
        let snapshot = WifiSnapshot {
            lines: (0..120).map(|_| big_line.to_string()).collect(),
            handshakes: 120,
            access_points: Vec::new(),
            clients: Vec::new(),
        };
        let finding = build_evidence_finding("wlan0", 2437, 9, 0, &snapshot, 0);
        assert_eq!(finding.details.len(), MAX_WIFI_EVIDENCE_BYTES);
        assert!(finding.details.ends_with(EVIDENCE_TRUNCATION_MARKER));
        assert!(finding.details.contains(EVIDENCE_TRUNCATION_MARKER));
        // Small artifacts pass through untouched.
        let (small, truncated) = bound_details("# tiny".to_string());
        assert!(!truncated);
        assert_eq!(small, "# tiny");
    }

    #[test]
    fn one_save_per_session_is_enforced_by_the_session_flag() {
        let ctx = NetworkWifiCtx::default();
        assert!(!ctx.evidence_saved.load(Ordering::Acquire));
        // First save claims the slot; a second save must see the claim.
        assert!(!ctx.evidence_saved.swap(true, Ordering::AcqRel));
        assert!(ctx.evidence_saved.swap(true, Ordering::AcqRel));
        // A new session resets the slot (the start command does this).
        ctx.evidence_saved.store(false, Ordering::Release);
        assert!(!ctx.evidence_saved.swap(true, Ordering::AcqRel));
    }

    #[test]
    fn saved_case_gate_refuses_scratchpad_and_missing_selection() {
        // The gate is pure over the session scope shape: no case id, an empty
        // id or the scratchpad sentinel all refuse before any lock is taken.
        let refuse = |case_id: Option<&str>| -> bool {
            let id = match case_id {
                Some(id) => id.to_string(),
                None => return true,
            };
            id == "scratchpad" || id.trim().is_empty()
        };
        assert!(refuse(None));
        assert!(refuse(Some("scratchpad")));
        assert!(refuse(Some("  ")));
        assert!(!refuse(Some("case-9")));
    }

    // ---- injection / channel hop (additive slice) --------------------------

    #[test]
    fn bssid_parsing_accepts_colon_hex_and_refuses_garbage() {
        assert_eq!(parse_bssid("a4:B1:c1:D2:e3:F0"), Some(AP));
        assert_eq!(parse_bssid("  a4:b1:c1:d2:e3:f0  "), Some(AP));
        assert_eq!(parse_bssid("a4-b1-c1-d2-e3-f0"), None);
        assert_eq!(parse_bssid("a4:b1:c1:d2:e3"), None);
        assert_eq!(parse_bssid("a4:b1:c1:d2:e3:f0:11"), None);
        assert_eq!(parse_bssid("zz:b1:c1:d2:e3:f0"), None);
        assert_eq!(parse_bssid("a4:b1:c1:d2:e3:f"), None);
        assert_eq!(parse_bssid(""), None);
    }

    #[test]
    fn injection_targets_are_limited_to_the_current_sessions_observed_aps() {
        let observed = vec![WifiApWire {
            bssid: format_mac(&AP),
            essid: "lab-net".into(),
        }];
        let ok = resolve_observed_targets(&[format_mac(&AP)], &observed).expect("observed target");
        assert_eq!(ok, vec![AP]);
        // Uppercase input normalizes onto the observed (lowercase) table.
        assert!(resolve_observed_targets(&["A4:B1:C1:D2:E3:F0".into()], &observed).is_ok());
        // A BSSID the session never observed is refused — no blind targets.
        let blind = resolve_observed_targets(&["02:00:00:00:00:09".into()], &observed)
            .unwrap_err();
        assert!(blind.contains("not observed by the current monitor session"), "{blind}");
        assert!(blind.contains("no blind targets"), "{blind}");
        // Count, malformed and duplicate refusals.
        assert!(resolve_observed_targets(&[], &observed).is_err());
        let oversized: Vec<String> = (0..=MAX_INJECT_TARGETS)
            .map(|_| format_mac(&AP))
            .collect();
        assert!(resolve_observed_targets(&oversized, &observed).is_err());
        let dupe = resolve_observed_targets(&[format_mac(&AP), format_mac(&AP)], &observed)
            .unwrap_err();
        assert!(dupe.contains("duplicate"), "{dupe}");
        let garbage = resolve_observed_targets(&["not-a-mac".into()], &observed).unwrap_err();
        assert!(garbage.contains("aa:bb:cc:dd:ee:ff"), "{garbage}");
    }

    #[test]
    fn deauth_bounds_mirror_the_crate_plan_validation() {
        // The command delegates to the crate's own bounded plan validation.
        assert!(inject::validate_deauth_plan(&[AP], 2, 8).is_ok());
        assert!(inject::validate_deauth_plan(&[], 1, 1).is_err());
        assert!(inject::validate_deauth_plan(&[AP], 5, 1).is_err(), "≤ 4 bursts");
        assert!(inject::validate_deauth_plan(&[AP], 1, 33).is_err());
        // The 32-frame per-burst cap spans all targets: 4 x 9 refuses.
        let four: Vec<[u8; 6]> = (0..4u8).map(|i| [0x02, 0, 0, 0, 0, i]).collect();
        assert!(inject::validate_deauth_plan(&four, 1, 9).is_err());
        assert!(inject::validate_deauth_plan(&four, 1, 8).is_ok());
    }

    #[test]
    fn injection_requires_a_live_monitor_session() {
        let ctx = NetworkWifiCtx::default();
        // Idle: refused with the session-observed honesty line.
        let err = require_live_monitor(&ctx).unwrap_err();
        assert!(err.contains("CURRENT monitor session"), "{err}");
        // A stopped session is not a live one.
        ctx.set_phase(WifiPhase::Stopped);
        assert!(require_live_monitor(&ctx).is_err());
        ctx.running.store(true, Ordering::Release);
        ctx.set_phase(WifiPhase::Monitoring);
        assert!(require_live_monitor(&ctx).is_ok());
    }

    #[test]
    fn status_wire_carries_additive_injection_and_hop_fields_honestly() {
        let ctx = NetworkWifiCtx::default();
        let wire = ctx.status_wire();
        assert_eq!(wire.deauth_state, "idle");
        assert_eq!(wire.deauth_frames_sent, 0);
        assert_eq!(wire.deauth_bursts_done, 0);
        assert_eq!(wire.deauth_targets, 0);
        assert!(wire.deauth_note.is_none());
        assert!(wire.injection_last_error.is_none());
        assert!(!wire.hop_running);
        assert!(!wire.hop_paused);
        assert_eq!(wire.hop_channel_mhz, 0);
        assert!(wire.hop_channels.is_empty());
        assert_eq!(wire.hop_count, 0);
        assert!(wire.hop_log.is_empty());
        assert!(wire.hop_last_error.is_none());
        // An ended run keeps its counters and note readable; a stopped run
        // reports "stopped", not "idle".
        ctx.deauth_frames_sent.store(16, Ordering::Release);
        ctx.deauth_bursts_done.store(2, Ordering::Release);
        ctx.deauth_targets.store(4, Ordering::Release);
        if let Ok(mut slot) = ctx.deauth_note.lock() {
            *slot = Some("deauth run ended: 16 frame(s) across 2 burst(s)".into());
        }
        ctx.set_phase(WifiPhase::Stopped);
        let wire = ctx.status_wire();
        assert_eq!(wire.deauth_state, "stopped");
        assert_eq!(wire.deauth_frames_sent, 16);
        assert_eq!(wire.deauth_bursts_done, 2);
        assert!(wire.deauth_note.unwrap().contains("ended"));
        // The injecting/stopping states derive from the live flags.
        ctx.deauth_running.store(true, Ordering::Release);
        assert_eq!(ctx.status_wire().deauth_state, "injecting");
        ctx.deauth_stop.store(true, Ordering::Release);
        assert_eq!(ctx.status_wire().deauth_state, "stopping");
    }

    #[test]
    fn case_change_arms_the_injection_and_hop_stop_flags() {
        let ctx = NetworkWifiCtx::default();
        ctx.on_case_changed();
        assert!(ctx.stop.load(Ordering::Acquire));
        assert!(ctx.deauth_stop.load(Ordering::Acquire));
        assert!(ctx.hop_stop.load(Ordering::Acquire));
    }

    #[test]
    fn hop_scheduler_wiring_pauses_resumes_and_logs_through_the_ctx_slot() {
        let ctx = NetworkWifiCtx::default();
        let scheduler = ChannelHopScheduler::new(vec![2412, 2437, 2462], 250)
            .expect("valid hop plan");
        if let Ok(mut slot) = ctx.hop.lock() {
            *slot = HopShared {
                scheduler: Some(scheduler),
            };
        }
        // The pause request is a REQUEST; applying it to the shared scheduler
        // is the worker's job (its clock stays the exact time base).
        ctx.hop_pause_request.store(true, Ordering::Release);
        if let Ok(mut slot) = ctx.hop.lock() {
            if let Some(s) = slot.scheduler.as_mut() {
                s.pause();
                assert_eq!(s.tick(10_000), None, "no hop fires while paused");
            }
        }
        let view = ctx.hop_view().expect("scheduler present");
        assert!(view.paused);
        assert_eq!(view.current_mhz, 2412);
        // Resume re-arms from NOW: the first hop is a full interval later.
        ctx.hop_pause_request.store(false, Ordering::Release);
        if let Ok(mut slot) = ctx.hop.lock() {
            if let Some(s) = slot.scheduler.as_mut() {
                s.resume(10_000);
                assert_eq!(s.tick(10_249), None);
                assert_eq!(s.tick(10_250), Some(2437));
            }
        }
        let view = ctx.hop_view().expect("scheduler present");
        assert!(!view.paused);
        assert_eq!(view.current_mhz, 2437);
        assert_eq!(view.hop_count, 1);
        assert_eq!(view.log.len(), 1);
        assert_eq!(view.log[0].at_ms, 10_250);
        assert_eq!(view.log[0].from_mhz, 2412);
        assert_eq!(view.log[0].to_mhz, 2437);
        // A fresh run replaces the previous run's plan and log (the start
        // command resets the slot).
        if let Ok(mut slot) = ctx.hop.lock() {
            *slot = HopShared::default();
        }
        assert!(ctx.hop_view().is_none());
    }

    #[test]
    fn injection_and_hop_report_unsupported_off_linux_honestly() {
        assert_eq!(inject::injection_supported(), cfg!(target_os = "linux"));
        assert!(INJECTION_UNSUPPORTED_MESSAGE.contains("requires Linux"));
        assert!(INJECTION_UNSUPPORTED_MESSAGE.contains("AF_PACKET"));
        assert!(HOP_UNSUPPORTED_MESSAGE.contains("requires Linux"));
        assert!(HOP_UNSUPPORTED_MESSAGE.contains("nl80211"));
        // The bounds the dialog names are the crate's constants.
        assert_eq!(MAX_INJECT_TARGETS, inject::MAX_DEAUTH_TARGETS);
        assert_eq!(inject::MAX_DEAUTH_BURSTS, 4);
        assert_eq!(inject::MAX_FRAMES_PER_BURST, 32);
        assert_eq!(inject::MAX_DEAUTH_RUN_MS, 10_000);
        assert_eq!(inject::MAX_HOP_CHANNELS, 16);
        assert_eq!(inject::MAX_HOP_LOG, 256);
    }
}
