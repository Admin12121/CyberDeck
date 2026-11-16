//! Authorized BLE advertising-scan IPC for the console dock (Bettercap
//! `ble.recon` parity at the capture level, strictly passive).
//!
//! Mirrors the wifi monitor slice (`wifi_monitor.rs`): a managed
//! `Arc<NetworkBleCtx>` with the stop-flag + join-guard pattern, an
//! idle/starting/scanning/stopping/stopped phase machine and an honest
//! status wire. The HCI and dissection layers are NOT duplicated here: the
//! landed BLE crate layer (`crates/packet/src/ble/`) owns the raw-HCI
//! framing and socket (Linux, cfg-gated), the advertising PDU dissection
//! and the bounded per-session store (`BleScanState`, ≤ 128 advertisers
//! LRU). This file adds: the managed context, the native authorization
//! dialog, the Linux scan pump (poll-paced bounded reads over the crate
//! socket, stop flag checked per read, never a send) and the four typed
//! commands the console dock drives.
//!
//! Platform honesty (mirrors the crate's `BleErrorCode::Unsupported`): the
//! raw-HCI door exists only on Linux and needs CAP_NET_ADMIN (typically
//! root); macOS and Windows report `ble_supported: false` and the start
//! command refuses with the honest message before touching the OS.
//!
//! Passive by construction: the pump only reads LE advertising reports —
//! nothing is transmitted toward advertisers and no connections are made.
//! The scan takes no `NetworkOperationGate` lease (it touches a different
//! radio than the wifi/ARP operations) but refuses to start while another
//! operation holds the gate, keeping the "one active operation" rule.
//!
//! DEFERRED ARC NOTE: evidence persistence for BLE is NOT in this slice —
//! it lands together with the deferred BLE UI arc (as the wifi evidence
//! save did after its own arc), so this layer keeps no case-session
//! binding and there is no scope-revocation closure yet; the stop flag is
//! the only cancellation source and it is never refused.
//!
//! Bounds: device store ≤ 128 (crate LRU), event reads ≤ 64 KiB (crate),
//! refusal notes truncated to 200 chars, snapshot reads bounded under a
//! short mutex, and every malformed event/report is counted with its
//! reason, never half-tracked.
use crate::features::network::ipc::operation_gate::NetworkOperationGate;
use cyberdeck_packet::ble::{self, BleCounters, BleDevice, BleScanState, MAX_TRACKED_DEVICES};
#[cfg(target_os = "linux")]
use cyberdeck_packet::ble::advertising;
#[cfg(target_os = "linux")]
use cyberdeck_packet::ble::hci;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tauri::AppHandle;
use tauri::State;
#[cfg(target_os = "linux")]
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

/// Honest Unsupported message wherever the raw-HCI door does not exist.
const UNSUPPORTED_MESSAGE: &str =
    "BLE advertising scanning uses the Linux raw-HCI socket door and currently requires Linux";
/// Refusal notes kept on the ctx are bounded so a hostile airwave cannot
/// grow the status wire.
#[cfg(target_os = "linux")]
const LAST_ERROR_NOTE_CHARS: usize = 200;

// ---------------------------------------------------------------------------
// Managed context: phase machine, honest counters, bounded snapshot reads.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum BlePhase {
    #[default]
    Idle,
    Starting,
    Scanning,
    Stopping,
    Stopped,
}

/// Managed per-process BLE scan registry (the `NetworkWifiCtx` pattern).
#[derive(Default)]
pub struct NetworkBleCtx {
    running: AtomicBool,
    stop: AtomicBool,
    phase: Mutex<BlePhase>,
    hci_index: AtomicU16,
    started_at: Mutex<Option<Instant>>,
    final_elapsed_ms: AtomicU64,
    last_error: Mutex<Option<String>>,
    /// The crate-owned bounded store; the pump drives start/stop/tick and
    /// the status/results commands clone bounded snapshots under this short
    /// critical section.
    scan: Mutex<BleScanState>,
}

impl NetworkBleCtx {
    fn set_phase(&self, phase: BlePhase) {
        if let Ok(mut slot) = self.phase.lock() {
            *slot = phase;
        }
    }

    fn phase(&self) -> BlePhase {
        self.phase.lock().ok().map(|slot| *slot).unwrap_or_default()
    }

    fn phase_label(&self) -> &'static str {
        match self.phase() {
            BlePhase::Idle => "idle",
            BlePhase::Starting => "starting",
            BlePhase::Scanning => "scanning",
            BlePhase::Stopping => "stopping",
            BlePhase::Stopped => "stopped",
        }
    }

    #[cfg(target_os = "linux")]
    fn note_error(&self, message: impl Into<String>) {
        if let Ok(mut slot) = self.last_error.lock() {
            *slot = Some(bounded_note(&message.into()));
        }
    }

    fn elapsed_ms(&self) -> u64 {
        if self.running.load(Ordering::Acquire) {
            self.started_at
                .lock()
                .ok()
                .and_then(|slot| *slot)
                .map(|started| {
                    started
                        .elapsed()
                        .as_millis()
                        .min(u64::MAX as u128) as u64
                })
                .unwrap_or(0)
        } else {
            self.final_elapsed_ms.load(Ordering::Acquire)
        }
    }

    /// Bounded store read: counters plus the latest honest error.
    fn read_counters(&self) -> (BleCounters, usize, Option<String>) {
        self.scan
            .lock()
            .map(|state| {
                (
                    state.counters(),
                    state.device_count(),
                    state.last_error().map(str::to_string),
                )
            })
            .unwrap_or_default()
    }

    /// Bounded store read: the full device snapshot (≤ 128 entries).
    fn read_devices(&self) -> Vec<BleDevice> {
        self.scan
            .lock()
            .map(|state| state.devices())
            .unwrap_or_default()
    }

    /// Build the honest status wire from one bounded read of the store and
    /// the phase machine (shared by the status command and start receipts).
    fn status_wire(&self) -> BleStatusWire {
        let (counters, device_count, store_error) = self.read_counters();
        let last_error = self
            .last_error
            .lock()
            .ok()
            .and_then(|slot| slot.clone())
            .or(store_error);
        BleStatusWire {
            ble_supported: ble::ble_supported(),
            platform_status: platform_status_note().to_string(),
            state: self.phase_label().to_string(),
            hci_index: self.hci_index.load(Ordering::Acquire),
            device_count,
            device_capacity: MAX_TRACKED_DEVICES,
            elapsed_ms: self.elapsed_ms(),
            events_seen: counters.events_seen,
            events_malformed: counters.events_malformed,
            events_other: counters.events_other,
            reports_parsed: counters.reports_parsed,
            reports_refused: counters.reports_refused,
            devices_evicted: counters.devices_evicted,
            last_error,
        }
    }
}

/// Runs for the whole worker lifetime; clears the running flag and publishes
/// the final phase even when the worker panicked or the runtime dropped it.
#[cfg(target_os = "linux")]
struct BleRunGuard(Arc<NetworkBleCtx>);
#[cfg(target_os = "linux")]
impl Drop for BleRunGuard {
    fn drop(&mut self) {
        self.0.running.store(false, Ordering::Release);
        self.0.set_phase(BlePhase::Stopped);
    }
}

#[cfg(target_os = "linux")]
fn bounded_note(message: &str) -> String {
    message.chars().take(LAST_ERROR_NOTE_CHARS).collect()
}

/// Flatten the crate's typed error into the command's honest String wire
/// error (code discriminator + message, mirroring the wifi/ARP slices).
#[cfg(target_os = "linux")]
fn ble_err(err: ble::BleError) -> String {
    format!("{:?}: {}", err.code, err.message)
}

/// The one-line platform honesty note the UI renders verbatim.
fn platform_status_note() -> &'static str {
    if ble::ble_supported() {
        "BLE scanning available via the Linux raw-HCI door; the scan is passive \
         receive-only and requires CAP_NET_ADMIN"
    } else if cfg!(target_os = "windows") {
        "BLE advertising scanning requires the Linux raw-HCI door; Windows exposes no \
         raw-HCI scanning door to this workbench"
    } else if cfg!(target_os = "macos") {
        "BLE advertising scanning requires the Linux raw-HCI door; macOS exposes no \
         raw-HCI scanning door to this workbench"
    } else {
        "BLE advertising scanning requires the Linux raw-HCI door"
    }
}

// ---------------------------------------------------------------------------
// Wire types (snake_case serde names, mirrored verbatim by the typed
// frontend client once the deferred UI arc lands).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct BleService16Wire {
    pub uuid: u16,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BleDeviceWire {
    pub address: String,
    /// public | random-static | random-resolvable-private |
    /// random-non-resolvable-private | random-reserved-for-future.
    pub address_kind: String,
    /// Set for private addresses: identity seen but not resolved.
    pub address_identity_note: Option<String>,
    pub name: Option<String>,
    /// True when the latest learned name came from a Shortened Local Name.
    pub name_shortened: bool,
    pub rssi_last_dbm: Option<i8>,
    pub rssi_min_dbm: Option<i8>,
    pub rssi_max_dbm: Option<i8>,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub adv_count: u64,
    pub scan_response_count: u64,
    pub flags: Option<u8>,
    pub tx_power_dbm: Option<i8>,
    pub services_16: Vec<BleService16Wire>,
    /// 128-bit UUIDs hex-encoded, byte order exactly as transmitted.
    pub services_128: Vec<String>,
    pub manufacturer_id: Option<u16>,
    pub manufacturer_name: Option<String>,
}

fn device_wire(device: &BleDevice) -> BleDeviceWire {
    BleDeviceWire {
        address: device.address.clone(),
        address_kind: device.address_kind.label().to_string(),
        address_identity_note: device.address_note.map(str::to_string),
        name: device.name.clone(),
        name_shortened: device.name_shortened,
        rssi_last_dbm: device.rssi_last_dbm,
        rssi_min_dbm: device.rssi_min_dbm,
        rssi_max_dbm: device.rssi_max_dbm,
        first_seen_ms: device.first_seen_ms,
        last_seen_ms: device.last_seen_ms,
        adv_count: device.adv_count,
        scan_response_count: device.scan_response_count,
        flags: device.flags,
        tx_power_dbm: device.tx_power_dbm,
        services_16: device
            .services_16
            .iter()
            .map(|service| BleService16Wire {
                uuid: service.uuid,
                name: service.name.map(str::to_string),
            })
            .collect(),
        services_128: device
            .services_128
            .iter()
            .map(|uuid| uuid.iter().map(|byte| format!("{byte:02x}")).collect())
            .collect(),
        manufacturer_id: device.manufacturer_id,
        manufacturer_name: device.manufacturer_name.map(str::to_string),
    }
}

/// Wire status for `network_ble_status_v1`.
#[derive(Debug, Clone, Serialize)]
pub struct BleStatusWire {
    /// True only where the kernel exposes the raw-HCI door (Linux).
    pub ble_supported: bool,
    pub platform_status: String,
    /// idle | starting | scanning | stopping | stopped.
    pub state: String,
    /// The HCI device index this session scans on (0 = default adapter).
    pub hci_index: u16,
    pub device_count: usize,
    /// The tracked-device bound (crate LRU cap) so the UI can render it.
    pub device_capacity: usize,
    pub elapsed_ms: u64,
    pub events_seen: u64,
    pub events_malformed: u64,
    pub events_other: u64,
    pub reports_parsed: u64,
    pub reports_refused: u64,
    pub devices_evicted: u64,
    pub last_error: Option<String>,
}

/// Results receipt for `network_ble_scan_results_v1`: the bounded snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct BleResultsWire {
    /// idle | starting | scanning | stopping | stopped.
    pub state: String,
    pub device_count: usize,
    pub device_capacity: usize,
    pub devices: Vec<BleDeviceWire>,
    pub elapsed_ms: u64,
    pub events_seen: u64,
    pub events_malformed: u64,
    pub reports_parsed: u64,
    pub reports_refused: u64,
    pub last_error: Option<String>,
}

/// Start receipt for `network_ble_scan_start_v1`: the exact backend-bound
/// scan parameters (the UI never widens or re-derives them).
#[derive(Debug, Clone, Serialize)]
pub struct BleStartWire {
    pub hci_index: u16,
    /// Always "passive": this slice offers no active scanning.
    pub scan_type: String,
    pub scan_interval_slots: u16,
    pub scan_window_slots: u16,
    pub status: BleStatusWire,
}

// ---------------------------------------------------------------------------
// Linux scan pump: poll-paced bounded reads over the crate socket, stop
// flag checked per read, never a send. Mirrors the wifi frame pump.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn run_scan_pump(ctx: &Arc<NetworkBleCtx>, socket: &hci::HciSocket, started: Instant) {
    let mut buffer = vec![0u8; hci::MAX_EVENT_BYTES];
    loop {
        if ctx.stop.load(Ordering::Acquire) {
            return;
        }
        let frame = match socket.read_event(&mut buffer) {
            Ok(None) => continue, // idle tick (timeout or signal)
            Ok(Some(frame)) => frame,
            Err(err) => {
                ctx.note_error(format!("BLE scan read failed: {err}"));
                return;
            }
        };
        let now_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        match hci::parse_hci_event(frame) {
            Ok(hci::HciEvent::LeAdvertisingReports(reports)) => {
                // Malformed airwave input is counted with its reason and
                // skipped; it never stops the scan nor half-tracks a device.
                if let Ok(mut state) = ctx.scan.lock() {
                    state.note_event(true);
                    for report in &reports {
                        match advertising::parse_report(report) {
                            Ok(parsed) => {
                                state.tick(&parsed, now_ms);
                            }
                            Err(err) => {
                                state.note_refused_report();
                                ctx.note_error(format!("report refused: {}", err.message));
                            }
                        }
                    }
                }
            }
            Ok(_) => {
                if let Ok(mut state) = ctx.scan.lock() {
                    state.note_skipped_event();
                }
            }
            Err(err) => {
                if let Ok(mut state) = ctx.scan.lock() {
                    state.note_event(false);
                }
                ctx.note_error(format!("HCI event refused: {}", err.message));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Commands.
// ---------------------------------------------------------------------------

/// Poll the scan's live state: the honest platform note, phase, counters
/// and device count. Read-only; safe to call on any platform.
#[tauri::command]
pub fn network_ble_status_v1(
    ble_ctx: State<'_, Arc<NetworkBleCtx>>,
) -> Result<BleStatusWire, String> {
    Ok(ble_ctx.status_wire())
}

/// Read the bounded results snapshot of the current/last session: ≤ 128
/// tracked advertisers with name, RSSI last/min/max, first/last seen,
/// advertisement counts and the AD summary.
#[tauri::command]
pub fn network_ble_scan_results_v1(
    ble_ctx: State<'_, Arc<NetworkBleCtx>>,
) -> Result<BleResultsWire, String> {
    let (counters, device_count, store_error) = ble_ctx.read_counters();
    let devices = ble_ctx.read_devices();
    let last_error = ble_ctx
        .last_error
        .lock()
        .ok()
        .and_then(|slot| slot.clone())
        .or(store_error);
    Ok(BleResultsWire {
        state: ble_ctx.phase_label().to_string(),
        device_count,
        device_capacity: MAX_TRACKED_DEVICES,
        devices: devices.iter().map(device_wire).collect(),
        elapsed_ms: ble_ctx.elapsed_ms(),
        events_seen: counters.events_seen,
        events_malformed: counters.events_malformed,
        reports_parsed: counters.reports_parsed,
        reports_refused: counters.reports_refused,
        last_error,
    })
}

/// Stop the running scan. Cancellation is NEVER refused; the pump exits at
/// its next read boundary, a best-effort LE Set Scan Enable (disable) is
/// sent, and the results snapshot stays readable afterwards. Returns true
/// when a scan existed.
#[tauri::command]
pub fn network_ble_scan_stop_v1(
    ble_ctx: State<'_, Arc<NetworkBleCtx>>,
) -> Result<bool, String> {
    if !ble_ctx.running.load(Ordering::Acquire) {
        return Ok(false);
    }
    ble_ctx.stop.store(true, Ordering::Release);
    if ble_ctx.phase() == BlePhase::Scanning || ble_ctx.phase() == BlePhase::Starting {
        ble_ctx.set_phase(BlePhase::Stopping);
    }
    Ok(true)
}

/// Start an authorized passive BLE advertising scan over the raw-HCI door
/// on the given device index (0 = default adapter). Requires the explicit
/// authorization flag AND an accepted native confirmation that names
/// exactly what will happen; Linux-only (other platforms get the honest
/// Unsupported refusal before any OS call). Hard bounds are crate-enforced:
/// ≤ 128 tracked advertisers (LRU), ≤ 64 KiB event reads, passive scan
/// type only, stop never refused.
#[tauri::command]
pub async fn network_ble_scan_start_v1(
    hci_index: u16,
    authorized: bool,
    app: AppHandle,
    gate: State<'_, Arc<NetworkOperationGate>>,
    ble_ctx: State<'_, Arc<NetworkBleCtx>>,
) -> Result<BleStartWire, String> {
    if !authorized {
        return Err("explicit BLE scan authorization required".into());
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (hci_index, app, gate, ble_ctx);
        return Err(UNSUPPORTED_MESSAGE.to_string());
    }
    #[cfg(target_os = "linux")]
    {
        if gate.is_active() {
            return Err(
                "stop other active network operations before opening the raw-HCI scan door"
                    .into(),
            );
        }
        if ble_ctx.running.swap(true, Ordering::AcqRel) {
            return Err("a BLE advertising scan is already active".into());
        }

        // Backend confirmation is independent of the frontend checkbox: it
        // names EXACTLY what will happen before the socket opens.
        let question = format!(
            "Authorize BLE advertising scanning over raw HCI on device index {hci_index}? \
             The backend opens the Linux raw-HCI socket (requires CAP_NET_ADMIN, typically \
             root), sends the passive LE Set Scan Parameters + LE Set Scan Enable commands, \
             and reads advertising reports ONLY: nothing is transmitted toward advertisers \
             and no connections are made. The session tracks at most {MAX_TRACKED_DEVICES} \
             advertisers (LRU) with names, RSSI and advertised services; malformed input is \
             refused and counted. Permission to test these advertisers is assumed granted."
        );
        let dialog_app = app.clone();
        let agreed = tokio::task::spawn_blocking(move || {
            dialog_app
                .dialog()
                .message(question)
                .title("Authorize BLE advertising scan")
                .buttons(MessageDialogButtons::YesNo)
                .blocking_show()
        })
        .await
        .map_err(|_| "BLE scan confirmation unavailable")?;
        if !agreed {
            ble_ctx.running.store(false, Ordering::Release);
            return Err("BLE scan cancelled by operator".into());
        }
        if gate.is_active() {
            ble_ctx.running.store(false, Ordering::Release);
            return Err(
                "another network operation became active while confirming the BLE scan".into(),
            );
        }

        // Reset the session state before the worker starts.
        ble_ctx.stop.store(false, Ordering::Release);
        ble_ctx.hci_index.store(hci_index, Ordering::Release);
        ble_ctx.final_elapsed_ms.store(0, Ordering::Release);
        if let Ok(mut slot) = ble_ctx.last_error.lock() {
            *slot = None;
        }
        if let Ok(mut state) = ble_ctx.scan.lock() {
            state.start();
        } else {
            ble_ctx.running.store(false, Ordering::Release);
            return Err("BLE scan state registry unavailable".into());
        }
        if let Ok(mut slot) = ble_ctx.started_at.lock() {
            *slot = Some(Instant::now());
        } else {
            ble_ctx.running.store(false, Ordering::Release);
            return Err("BLE scan state registry unavailable".into());
        }
        ble_ctx.set_phase(BlePhase::Starting);

        let worker_ctx = Arc::clone(&*ble_ctx);
        tokio::task::spawn_blocking(move || {
            let _guard = BleRunGuard(Arc::clone(&worker_ctx));
            if worker_ctx.stop.load(Ordering::Acquire) {
                return;
            }
            let started = Instant::now();
            let socket = match hci::HciSocket::open(worker_ctx.hci_index.load(Ordering::Acquire)) {
                Ok(socket) => socket,
                Err(err) => {
                    worker_ctx.note_error(ble_err(err));
                    return;
                }
            };
            if let Err(err) = socket.configure_le_passive_scan(&hci::LeScanParams::passive_default())
            {
                worker_ctx.note_error(format!("controller refused the passive scan: {}", ble_err(err)));
                return;
            }
            worker_ctx.set_phase(BlePhase::Scanning);
            run_scan_pump(&worker_ctx, &socket, started);
            // Best-effort scan disable; stopping must never be refused hard.
            if let Err(err) = socket.disable_le_scan() {
                worker_ctx.note_error(format!("scan disable failed: {}", ble_err(err)));
            }
            worker_ctx.final_elapsed_ms.store(
                started.elapsed().as_millis().min(u64::MAX as u128) as u64,
                Ordering::Release,
            );
        });
        Ok(BleStartWire {
            hci_index,
            scan_type: "passive".to_string(),
            scan_interval_slots: hci::LeScanParams::passive_default().interval_slots,
            scan_window_slots: hci::LeScanParams::passive_default().window_slots,
            status: ble_ctx.status_wire(),
        })
    }
}
