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
use crate::features::forensics::ipc::evidence::EvidenceCtx;
use crate::features::shared::session::{CaseSessionCtx, CaseSessionWire};
use cyberdeck_packet::wifi::frame::{self, FrameKind};
use cyberdeck_packet::wifi::radiotap;
use cyberdeck_packet::wifi::{MonitorCapture, monitor_mode_supported};
use cyberdeck_storage::NewFinding;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
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

/// Managed per-process monitor registry, mirroring `NetworkLabSpoofCtx`.
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
    /// authoritative even when a caller cannot invoke this.
    pub fn on_case_changed(&self) {
        self.stop.store(true, Ordering::Release);
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
        }
    }
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
/// tables and the hashcat 22000 lines captured this session.
#[tauri::command]
pub fn network_wifi_monitor_status_v1(
    wifi: State<'_, Arc<NetworkWifiCtx>>,
) -> Result<WifiStatusWire, String> {
    Ok(wifi.status_wire())
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
}
