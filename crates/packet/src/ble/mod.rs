//! BLE advertising scanning for the packet engine: a hand-rolled raw-HCI
//! scanner (Linux-only socket door) with platform-independent advertising
//! dissection — Bettercap `ble.recon` parity at the capture level.
//!
//! Policy (mirrors `active_arp` and the wifi layer): this is a passive,
//! receive-only capture surface for the explicitly authorized pentest
//! workbench. Linux is the only platform whose kernel exposes a raw-HCI
//! door (`AF_BLUETOOTH`/`BTPROTO_HCI`, HCI_CHANNEL_RAW, CAP_NET_ADMIN);
//! every other platform reports the honest `Unsupported`, and the pure
//! layers (HCI framing, advertising dissection, the bounded session store)
//! work — and are tested — everywhere. The scan is passive by
//! construction: LE Set Scan Parameters (passive type) + LE Set Scan
//! Enable; there is no connect, write or active-probe path in this crate.
//!
//! Bounds everywhere: ≤ [`MAX_TRACKED_DEVICES`] tracked advertisers (LRU),
//! event reads ≤ 64 KiB, ≤ 16 reports per event, legacy report data ≤ 31
//! bytes, names ≤ 32 chars, per-device service stores capped, and every
//! counter is honest (`events_seen` / `events_malformed` / `events_other` /
//! `reports_parsed` / `devices_evicted`). Malformed frames and reports are
//! refused with a stated reason and skipped, never half-tracked.
//!
//! Module layout:
//! - [`hci`]: command builders (spec-pinned byte frames, testable
//!   anywhere), event parser, cfg-Linux raw socket;
//! - [`advertising`]: AD-structure walk and the honest per-report summary
//!   (platform-independent);
//! - [`BleScanState`]: the bounded per-session store the IPC pump drives
//!   via start / stop / tick.
//!
//! NOTE (deferred arc): evidence persistence for BLE is NOT in this slice —
//! it lands together with the deferred BLE UI arc, exactly like the wifi
//! monitor evidence save did after its own UI landed.
pub mod advertising;
pub mod hci;

pub use advertising::{
    AdStructure, AddressKind, AdvEventType, ParsedAdvertisement, ServiceUuid16,
};
pub use hci::{HciEvent, HciSocket, LeScanParams, LeScanType, RawReport};

/// Honest error taxonomy for the whole BLE layer (the `WifiMonitorError`
/// pattern): `Unsupported` off Linux, `Permission`/`Device` for OS-level
/// refusals, `Protocol` for malformed input, `Io` for the rest,
/// `Cancelled` for revoked sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BleErrorCode {
    /// The platform offers no public door to the raw HCI radio (non-Linux).
    Unsupported,
    /// The OS refused the operation (missing CAP_NET_ADMIN, rfkill, ...).
    Permission,
    /// The HCI device index does not exist or the controller refused.
    Device,
    /// The protocol layer received malformed or out-of-bounds input.
    Protocol,
    /// Everything else at the OS boundary.
    Io,
    /// The authorized session was revoked.
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BleError {
    pub code: BleErrorCode,
    pub message: String,
}

impl BleError {
    pub fn new(code: BleErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for BleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

/// True only where the OS exposes the raw-HCI door (Linux).
pub fn ble_supported() -> bool {
    cfg!(target_os = "linux")
}

/// Upper bound on tracked advertisers per session (LRU store).
pub const MAX_TRACKED_DEVICES: usize = 128;

/// Session phase of the bounded store: the crate tracks the honest minimum
/// (the IPC layer layers starting/stopping on top of this).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BleScanPhase {
    #[default]
    Idle,
    Scanning,
    /// Stopped but the store is retained so results stay readable.
    Stopped,
}

/// One tracked advertiser: address, latest honest name, RSSI last/min/max,
/// first/last seen, advertisement counts and a bounded AD summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BleDevice {
    /// Conventional MSB-first display form.
    pub address: String,
    pub address_kind: AddressKind,
    /// Set for private addresses: identity seen but not resolved.
    pub address_note: Option<&'static str>,
    pub name: Option<String>,
    /// True when the latest learned name came from a Shortened Local Name.
    pub name_shortened: bool,
    pub rssi_last_dbm: Option<i8>,
    pub rssi_min_dbm: Option<i8>,
    pub rssi_max_dbm: Option<i8>,
    /// Caller-supplied monotonic milliseconds (session-relative).
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    /// Every report counted (scan responses included).
    pub adv_count: u64,
    /// Subset counted from SCAN_RSP reports.
    pub scan_response_count: u64,
    pub flags: Option<u8>,
    pub tx_power_dbm: Option<i8>,
    pub services_16: Vec<ServiceUuid16>,
    pub services_128: Vec<[u8; 16]>,
    pub manufacturer_id: Option<u16>,
    pub manufacturer_name: Option<&'static str>,
}

/// What one tick did: created/touched a device, possibly evicted an older
/// one, and how many devices the store now holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TickOutcome {
    pub device_new: bool,
    pub device_evicted: Option<String>,
    pub devices_tracked: usize,
}

/// Honest session counters (mirrored on the wire by the IPC layer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BleCounters {
    pub events_seen: u64,
    /// Refused event frames (each stated a reason) that were skipped.
    pub events_malformed: u64,
    /// Events parsed but not part of the scan payload (Command Complete,
    /// other codes, extended reports named-not-decoded).
    pub events_other: u64,
    pub reports_parsed: u64,
    /// Individual reports refused inside an otherwise parsed event (each
    /// stated a reason; the rest of the event still parses).
    pub reports_refused: u64,
    pub devices_evicted: u64,
}

/// The bounded per-session BLE scan store. The IPC pump drives it via
/// [`BleScanState::start`], [`BleScanState::tick`] and
/// [`BleScanState::stop`]; status/results commands read [`BleScanState::devices`]
/// snapshots.
#[derive(Debug, Default)]
pub struct BleScanState {
    devices: Vec<BleDevice>,
    phase: BleScanPhase,
    counters: BleCounters,
    last_error: Option<String>,
}

impl BleScanState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Begin (or restart) a session: the store and counters reset and the
    /// phase moves to `Scanning`.
    pub fn start(&mut self) {
        self.devices.clear();
        self.counters = BleCounters::default();
        self.last_error = None;
        self.phase = BleScanPhase::Scanning;
    }

    /// Stop the session. The store is retained so the results command can
    /// still read the snapshot; a new start resets it.
    pub fn stop(&mut self) {
        if self.phase == BleScanPhase::Scanning {
            self.phase = BleScanPhase::Stopped;
        }
    }

    pub fn phase(&self) -> BleScanPhase {
        self.phase
    }

    /// Count one read event: parsed-ok events are tracked separately from
    /// refused ones (skip+count is the only malformed-input policy here).
    pub fn note_event(&mut self, parsed_ok: bool) {
        self.counters.events_seen += 1;
        if !parsed_ok {
            self.counters.events_malformed += 1;
        }
    }

    /// Count one parsed-but-uninteresting event (Command Complete, other
    /// codes, extended reports named-not-decoded).
    pub fn note_skipped_event(&mut self) {
        self.counters.events_seen += 1;
        self.counters.events_other += 1;
    }

    /// Count one refused report inside an otherwise parsed event (its
    /// refusal reason is expected to land in the session's last-error note).
    pub fn note_refused_report(&mut self) {
        self.counters.reports_refused += 1;
    }

    /// Record one parsed advertisement at caller-supplied monotonic
    /// session milliseconds. Creates or LRU-touches the advertiser entry,
    /// merging name (complete local names win over shortened), RSSI
    /// last/min/max, advertisement counts and the bounded AD summary.
    pub fn tick(&mut self, adv: &ParsedAdvertisement, now_ms: u64) -> TickOutcome {
        self.counters.reports_parsed += 1;
        let position = self.devices.iter().position(|d| d.address == adv.address);
        let outcome = match position {
            Some(index) => {
                let device = self.devices.remove(index);
                self.devices.push(device); // LRU: refresh recency
                TickOutcome {
                    device_new: false,
                    device_evicted: None,
                    devices_tracked: self.devices.len(),
                }
            }
            None => {
                let evicted = if self.devices.len() >= MAX_TRACKED_DEVICES {
                    let oldest = self.devices.remove(0);
                    self.counters.devices_evicted += 1;
                    Some(oldest.address)
                } else {
                    None
                };
                self.devices.push(BleDevice {
                    address: adv.address.clone(),
                    address_kind: adv.address_kind,
                    address_note: adv.address_note,
                    name: None,
                    name_shortened: false,
                    rssi_last_dbm: None,
                    rssi_min_dbm: None,
                    rssi_max_dbm: None,
                    first_seen_ms: now_ms,
                    last_seen_ms: now_ms,
                    adv_count: 0,
                    scan_response_count: 0,
                    flags: None,
                    tx_power_dbm: None,
                    services_16: Vec::new(),
                    services_128: Vec::new(),
                    manufacturer_id: None,
                    manufacturer_name: None,
                });
                TickOutcome {
                    device_new: true,
                    device_evicted: evicted,
                    devices_tracked: self.devices.len(),
                }
            }
        };
        let device = self
            .devices
            .last_mut()
            .expect("the tick above pushed the device");
        if let Some(rssi) = adv.rssi_dbm {
            device.rssi_last_dbm = Some(rssi);
            device.rssi_min_dbm = Some(match device.rssi_min_dbm {
                Some(current) => current.min(rssi),
                None => rssi,
            });
            device.rssi_max_dbm = Some(match device.rssi_max_dbm {
                Some(current) => current.max(rssi),
                None => rssi,
            });
        }
        if let Some(name) = &adv.local_name {
            // Complete local names win over shortened ones; a shortened name
            // only fills an empty slot.
            if !adv.local_name_shortened {
                device.name = Some(name.clone());
                device.name_shortened = false;
            } else if device.name.is_none() {
                device.name = Some(name.clone());
                device.name_shortened = true;
            }
        }
        device.adv_count += 1;
        if adv.event_type == AdvEventType::ScanResponse {
            device.scan_response_count += 1;
        }
        device.last_seen_ms = now_ms;
        if adv.flags.is_some() {
            device.flags = adv.flags;
        }
        if adv.tx_power_dbm.is_some() {
            device.tx_power_dbm = adv.tx_power_dbm;
        }
        for service in &adv.services_16 {
            if device.services_16.len() >= advertising::MAX_SERVICE_UUIDS_16 {
                break;
            }
            if !device.services_16.iter().any(|known| known.uuid == service.uuid) {
                device.services_16.push(*service);
            }
        }
        for uuid in &adv.services_128 {
            if device.services_128.len() >= advertising::MAX_SERVICE_UUIDS_128 {
                break;
            }
            if !device.services_128.contains(uuid) {
                device.services_128.push(*uuid);
            }
        }
        if adv.manufacturer_id.is_some() {
            device.manufacturer_id = adv.manufacturer_id;
            device.manufacturer_name = adv.manufacturer_name;
        }
        outcome
    }

    /// Bounded snapshot: clones the tracked devices (≤ 128 entries).
    pub fn devices(&self) -> Vec<BleDevice> {
        self.devices.clone()
    }

    pub fn device_count(&self) -> usize {
        self.devices.len()
    }

    pub fn counters(&self) -> BleCounters {
        self.counters
    }

    /// Keep the latest honest refusal message (bounded: one string).
    pub fn set_last_error(&mut self, message: impl Into<String>) {
        self.last_error = Some(message.into());
    }

    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal honest advertisement fixture for the store tests.
    fn adv(
        address: &str,
        kind: AddressKind,
        event_type: AdvEventType,
        rssi: Option<i8>,
        name: Option<&str>,
        name_shortened: bool,
    ) -> ParsedAdvertisement {
        ParsedAdvertisement {
            event_type,
            address: address.to_string(),
            address_kind: kind,
            address_note: kind.unresolved_note(),
            rssi_dbm: rssi,
            flags: None,
            flags_summary: Vec::new(),
            local_name: name.map(str::to_string),
            local_name_shortened: name_shortened,
            tx_power_dbm: None,
            services_16: Vec::new(),
            services_128: Vec::new(),
            manufacturer_id: None,
            manufacturer_name: None,
            manufacturer_data: Vec::new(),
            manufacturer_data_full_len: 0,
            ad_types_seen: Vec::new(),
            refusals: Vec::new(),
        }
    }

    fn device_at(index: u32) -> String {
        format!("AA:BB:CC:00:00:{index:02X}")
    }

    #[test]
    fn store_is_bounded_with_lru_eviction() {
        let mut state = BleScanState::new();
        state.start();
        for index in 0u32..(MAX_TRACKED_DEVICES as u32 + 8) {
            let a = adv(&device_at(index), AddressKind::Public, AdvEventType::AdvInd, Some(-50), None, false);
            let outcome = state.tick(&a, index as u64);
            assert_eq!(outcome.device_new, true);
            if index >= MAX_TRACKED_DEVICES as u32 {
                assert_eq!(
                    outcome.device_evicted,
                    Some(device_at(index - MAX_TRACKED_DEVICES as u32)),
                    "eviction should track the oldest entry"
                );
            } else {
                assert_eq!(outcome.device_evicted, None);
            }
        }
        assert_eq!(state.device_count(), MAX_TRACKED_DEVICES);
        assert_eq!(state.counters().devices_evicted, 8);
        // The oldest eight addresses are gone; the newest survive.
        let snapshot = state.devices();
        assert!(snapshot.iter().all(|d| d.address != device_at(0)));
        assert!(snapshot
            .iter()
            .any(|d| d.address == device_at(MAX_TRACKED_DEVICES as u32 + 7)));
    }

    #[test]
    fn touching_a_device_refreshes_its_recency() {
        let mut state = BleScanState::new();
        state.start();
        // A and B enter; A is touched; then MAX new devices flood the store.
        let a = adv(&device_at(0), AddressKind::Public, AdvEventType::AdvInd, Some(-40), Some("alpha"), false);
        let b = adv(&device_at(1), AddressKind::Public, AdvEventType::AdvInd, Some(-41), Some("beta"), false);
        state.tick(&a, 0);
        state.tick(&b, 1);
        let outcome = state.tick(&a, 2);
        assert_eq!(outcome.device_new, false);
        assert_eq!(outcome.devices_tracked, 2);
        // 127 new devices fill the store to the cap; the single eviction
        // takes B (the least recently touched) and leaves A in place.
        for index in 2u32..=(MAX_TRACKED_DEVICES as u32) {
            let a = adv(&device_at(index), AddressKind::Public, AdvEventType::AdvInd, None, None, false);
            state.tick(&a, index as u64);
        }
        let snapshot = state.devices();
        assert_eq!(snapshot.len(), MAX_TRACKED_DEVICES);
        assert!(snapshot.iter().any(|d| d.address == device_at(0)));
        assert!(!snapshot.iter().any(|d| d.address == device_at(1)));
    }

    #[test]
    fn rssi_last_min_max_are_merged_across_reports() {
        let mut state = BleScanState::new();
        state.start();
        let address = device_at(7);
        for rssi in [-40i8, -80, -60] {
            let a = adv(&address, AddressKind::Public, AdvEventType::AdvInd, Some(rssi), None, false);
            state.tick(&a, 0);
        }
        let device = &state.devices()[0];
        assert_eq!(device.rssi_last_dbm, Some(-60));
        assert_eq!(device.rssi_min_dbm, Some(-80));
        assert_eq!(device.rssi_max_dbm, Some(-40));
        assert_eq!(device.adv_count, 3);
        assert_eq!(device.first_seen_ms, 0);
        assert_eq!(device.last_seen_ms, 0);
    }

    #[test]
    fn scan_responses_count_separately_and_first_seen_is_stable() {
        let mut state = BleScanState::new();
        state.start();
        let address = device_at(9);
        let scan = adv(&address, AddressKind::Public, AdvEventType::AdvInd, Some(-55), None, false);
        state.tick(&scan, 10);
        let response = adv(&address, AddressKind::Public, AdvEventType::ScanResponse, Some(-54), Some("Deck Probe"), false);
        let outcome = state.tick(&response, 25);
        assert_eq!(outcome.device_new, false);
        let device = &state.devices()[0];
        assert_eq!(device.adv_count, 2);
        assert_eq!(device.scan_response_count, 1);
        assert_eq!(device.first_seen_ms, 10);
        assert_eq!(device.last_seen_ms, 25);
        assert_eq!(device.name.as_deref(), Some("Deck Probe"));
        assert!(!device.name_shortened);
    }

    #[test]
    fn complete_names_win_over_shortened_names() {
        let mut state = BleScanState::new();
        state.start();
        let address = device_at(3);
        let shortened = adv(&address, AddressKind::Public, AdvEventType::AdvInd, None, Some("De"), true);
        state.tick(&shortened, 0);
        let device = &state.devices()[0];
        assert_eq!(device.name.as_deref(), Some("De"));
        assert!(device.name_shortened);
        // A complete name replaces a shortened one.
        let complete = adv(&address, AddressKind::Public, AdvEventType::AdvInd, None, Some("Deck Probe"), false);
        state.tick(&complete, 1);
        let device = &state.devices()[0];
        assert_eq!(device.name.as_deref(), Some("Deck Probe"));
        assert!(!device.name_shortened);
        // A later shortened name never downgrades a complete one.
        state.tick(&shortened, 2);
        let device = &state.devices()[0];
        assert_eq!(device.name.as_deref(), Some("Deck Probe"));
        assert!(!device.name_shortened);
    }

    #[test]
    fn service_and_manufacturer_summaries_merge_deduplicated_and_bounded() {
        let mut state = BleScanState::new();
        state.start();
        let address = device_at(4);
        let mut a = adv(&address, AddressKind::Public, AdvEventType::AdvInd, None, None, false);
        a.services_16 = vec![
            ServiceUuid16 { uuid: 0x180F, name: Some("Battery") },
            ServiceUuid16 { uuid: 0x180F, name: Some("Battery") },
            ServiceUuid16 { uuid: 0x180A, name: Some("Device Information") },
        ];
        a.services_128 = vec![[1u8; 16], [1u8; 16], [2u8; 16]];
        a.manufacturer_id = Some(0x004C);
        a.manufacturer_name = Some("Apple, Inc.");
        for now in 0..3u64 {
            state.tick(&a, now);
        }
        let device = &state.devices()[0];
        assert_eq!(
            device.services_16.iter().map(|s| s.uuid).collect::<Vec<_>>(),
            vec![0x180F, 0x180A]
        );
        assert_eq!(device.services_128, vec![[1u8; 16], [2u8; 16]]);
        assert_eq!(device.manufacturer_id, Some(0x004C));
        assert_eq!(device.manufacturer_name, Some("Apple, Inc."));
        // The store bound applies to merges too.
        for uuid in 0..(advertising::MAX_SERVICE_UUIDS_16 as u16 * 2) {
            a.services_16 = vec![ServiceUuid16 { uuid, name: None }];
            state.tick(&a, 10);
        }
        let device = &state.devices()[0];
        assert!(device.services_16.len() <= advertising::MAX_SERVICE_UUIDS_16);
    }

    #[test]
    fn start_resets_the_store_and_counters_stop_retains_results() {
        let mut state = BleScanState::new();
        assert_eq!(state.phase(), BleScanPhase::Idle);
        state.start();
        let a = adv(&device_at(1), AddressKind::Public, AdvEventType::AdvInd, Some(-50), None, false);
        state.tick(&a, 0);
        state.note_event(true);
        state.note_skipped_event();
        state.note_event(false);
        state.set_last_error("report refused: bad length");
        assert_eq!(state.device_count(), 1);
        assert_eq!(
            state.counters(),
            BleCounters {
                events_seen: 3,
                events_malformed: 1,
                events_other: 1,
                reports_parsed: 1,
                reports_refused: 0,
                devices_evicted: 0,
            }
        );
        state.note_refused_report();
        assert_eq!(state.counters().reports_refused, 1);
        state.stop();
        assert_eq!(state.phase(), BleScanPhase::Stopped);
        // Results remain readable after stop.
        assert_eq!(state.device_count(), 1);
        assert_eq!(state.last_error(), Some("report refused: bad length"));
        // A new start wipes everything honestly.
        state.start();
        assert_eq!(state.phase(), BleScanPhase::Scanning);
        assert_eq!(state.device_count(), 0);
        assert_eq!(state.counters(), BleCounters::default());
        assert_eq!(state.last_error(), None);
    }

    #[test]
    fn events_are_counted_honestly_per_kind() {
        let mut state = BleScanState::new();
        state.start();
        for _ in 0..4 {
            state.note_event(true);
        }
        for _ in 0..3 {
            state.note_event(false);
        }
        for _ in 0..2 {
            state.note_skipped_event();
        }
        let counters = state.counters();
        assert_eq!(counters.events_seen, 9);
        assert_eq!(counters.events_malformed, 3);
        assert_eq!(counters.events_other, 2);
    }

    #[test]
    fn supported_tracks_the_linux_door_honestly() {
        assert_eq!(ble_supported(), cfg!(target_os = "linux"));
    }
}
