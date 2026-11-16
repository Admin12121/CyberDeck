//! Wi-Fi monitor-mode support for the packet engine: a hand-rolled
//! nl80211/netlink control client, radiotap and 802.11 frame dissection, and
//! 802.1X EAPOL 4-way-handshake capture that formats hashcat mode-22000 hash
//! lines.
//!
//! Policy (mirrors `active_arp`): this layer is for explicitly authorized
//! pentest workbench captures. Linux is the only platform whose kernel
//! exposes a public door to the radio (cfg-gated nl80211 client); other
//! platforms get the honest `WifiMonitorError::Unsupported`, and pure parsing
//! (radiotap, 802.11, EAPOL, hash-line formatting) works everywhere. The
//! packet crate deliberately stays out of the verification business: it never
//! derives PMKs, never computes or checks MICs, and never touches a password
//! — it produces `WPA*01*`/`WPA*02*` lines whose format is pinned byte-for-byte
//! against the vendored hashcat `module_22000.c`.
//!
//! Bounds everywhere: radiotap headers ≤ 256 bytes with ≤ 8 present words,
//! frames ≤ 4096 bytes, netlink messages ≤ 64 KiB with ≤ 256 attributes and
//! ≤ 64 interfaces per dump, EAPOL frames ≤ 512 bytes, and ≤ 64-entry LRU
//! stores for handshakes and tracked ESSIDs. Malformed input is refused with
//! a coded error, never unwrapped, never panicking.
//!
//! Authorized injection (`inject`, Bettercap `wifi.deauth` parity) adds its
//! own hard bounds: ≤ 4 session-observed target BSSIDs, ≤ 4 bursts, ≤ 32
//! deauth frames per burst, ≥ 20 ms frame pacing, ≤ 10 s per run; channel
//! hops are bounded to ≤ 16 in-band frequencies at 250 ms–2 s with a
//! ≤ 256-entry hop log. The transmit door is Linux AF_PACKET only.
pub mod eapol;
pub mod frame;
pub mod inject;
pub mod netlink;
pub mod radiotap;

pub use eapol::{HandshakeCollector, HandshakeEvent, WpaHandshake};
pub use frame::ParsedFrame;
pub use inject::{ChannelHopScheduler, DeauthEndReason, DeauthOutcome, HopEntry};
pub use radiotap::Radiotap;

/// Honest error taxonomy for the whole wifi layer (the `ArpErrorCode`
/// pattern): `Unsupported` off Linux, `Permission`/`Device` for OS-level
/// refusals, `Protocol` for malformed input, `Io` for the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WifiMonitorError {
    /// The platform offers no public door to the radio (non-Linux control).
    Unsupported,
    /// The radio or interface does not exist / is not a wireless device.
    Device,
    /// The OS refused the operation (missing capabilities, rfkill).
    Permission,
    /// The protocol layer received malformed or out-of-bounds input.
    Protocol,
    /// Everything else at the OS boundary.
    Io,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiError {
    pub code: WifiMonitorError,
    pub message: String,
}

impl WifiError {
    pub fn new(code: WifiMonitorError, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for WifiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

/// True only where the OS exposes monitor-mode control (Linux nl80211).
pub fn monitor_mode_supported() -> bool {
    cfg!(target_os = "linux")
}

/// Upper bound on tracked access-point ESSIDs (LRU alongside the handshake
/// bound).
pub const MAX_TRACKED_AP_ESSIDS: usize = 64;

/// The capture pipeline: feed monitor-mode frames (radiotap-prefixed, as an
/// AF_PACKET monitor socket or a pcap hands them over), track beacons for
/// ESSIDs, pair handshakes, and collect hashcat 22000 lines. Pure parsing —
/// runnable on every platform, no sockets, no syscalls.
#[derive(Debug, Default)]
pub struct MonitorCapture {
    handshakes: HandshakeCollector,
    /// (BSSID, ESSID) learned from beacons/probe responses, LRU-ordered.
    essids: Vec<([u8; 6], Vec<u8>)>,
}

impl MonitorCapture {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn handshakes(&self) -> impl Iterator<Item = &WpaHandshake> {
        self.handshakes.handshakes()
    }

    /// Every emittable hashcat 22000 line across the whole capture so far.
    pub fn hashcat_22000_lines(&self) -> Vec<String> {
        self.handshakes.hashcat_22000_lines()
    }

    /// Learn the ESSID of a BSSID from a beacon/probe response, with LRU
    /// eviction at [`MAX_TRACKED_AP_ESSIDS`]. Returns lines that became
    /// emittable because of the new ESSID.
    fn track_essid(&mut self, bssid: &[u8; 6], essid: &[u8]) -> Vec<String> {
        if essid.is_empty() {
            return Vec::new(); // hidden APs: nothing to track
        }
        if let Some(index) = self.essids.iter().position(|(ap, _)| ap == bssid) {
            let entry = self.essids.remove(index);
            self.essids.push(entry); // move to back: LRU recency
        } else {
            self.essids.push((*bssid, essid.to_vec()));
            if self.essids.len() > MAX_TRACKED_AP_ESSIDS {
                self.essids.remove(0); // evict least recently touched
            }
        }
        self.handshakes.attach_essid(bssid, essid)
    }

    /// Feed one capture frame: radiotap header + 802.11 frame. Returns the
    /// hashcat 22000 lines that this frame completed (PMKID capture or
    /// finished 4-way handshake). Malformed frames are refused per the
    /// honest-error contract; callers treat errors as "skip this frame".
    pub fn process_frame(&mut self, capture: &[u8]) -> Result<Vec<String>, WifiError> {
        let (radio, header_len) = radiotap::parse(capture)?;
        let parsed = frame::parse(
            &capture[header_len..],
            radio.fcs_present(),
            radio.data_padded(),
        )?;
        let mut lines = Vec::new();
        match &parsed.kind {
            frame::FrameKind::Beacon { ssid, .. }
            | frame::FrameKind::ProbeResponse { ssid, .. } => {
                if let (Some(bssid), Some(ssid)) = (parsed.roles.bssid, ssid) {
                    lines.extend(self.track_essid(&bssid, ssid));
                }
            }
            frame::FrameKind::Snap { ethertype, payload }
                if *ethertype == frame::ETHERTYPE_EAPOL =>
            {
                // EAPOL runs STA<->AP: the AP side is whichever address
                // matches the BSSID, the station side is the other one.
                if let Some(bssid) = parsed.roles.bssid {
                    let (ap, sta) = if parsed.roles.source == bssid {
                        (bssid, parsed.roles.destination)
                    } else {
                        (bssid, parsed.roles.source)
                    };
                    let event = self.handshakes.feed(ap, sta, payload)?;
                    lines.extend(event.lines);
                    // A handshake entry created by this frame may need the
                    // ESSID we learned earlier for this BSSID (beacons often
                    // arrive before the client connects).
                    if let Some((_, essid)) =
                        self.essids.iter().find(|(known_ap, _)| known_ap == &ap)
                    {
                        lines.extend(self.handshakes.attach_essid(&ap, essid));
                    }
                }
            }
            _ => {}
        }
        Ok(lines)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AP: [u8; 6] = [0xa4, 0xb1, 0xc1, 0xd2, 0xe3, 0xf0];
    const STA: [u8; 6] = [0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f];

    /// Synthetic handshake fixtures, generated with the Python stdlib
    /// (hmac/pbkdf2) for password "cyberdeck-e2e-42" / ESSID "cyberdeck-e2e".
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
    /// When `ap_to_sta` the frame travels fromDS (AP -> STA, e.g. M1),
    /// otherwise toDS (STA -> AP, e.g. M2). Body goes before the trailing FCS.
    fn radiotap_snap_frame(
        ap: [u8; 6],
        sta: [u8; 6],
        ap_to_sta: bool,
        ethertype: u16,
        body: &[u8],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0); // radiotap version
        out.push(0); // pad
        out.extend_from_slice(&9u16.to_le_bytes()); // it_len: 4 hdr + 4 present + 1 flags
        out.extend_from_slice(&2u32.to_le_bytes()); // present: FLAGS (bit 1)
        out.push(radiotap::FLAG_FCS_AT_END);
        let flags: u16 = if ap_to_sta { 0x0200 } else { 0x0100 };
        let fc_word = (2u16 << 2) | (8u16 << 4) | flags; // type data, QoS
        out.extend_from_slice(&fc_word.to_le_bytes());
        out.extend_from_slice(&[0x00, 0x00]); // duration
        if ap_to_sta {
            // fromDS: DA=addr1(STA), SA=addr2(AP), BSSID=addr3(AP)
            out.extend_from_slice(&sta);
            out.extend_from_slice(&ap);
            out.extend_from_slice(&ap);
        } else {
            // toDS: RA=addr1(AP), SA=addr2(STA), DA=addr3(AP)
            out.extend_from_slice(&ap);
            out.extend_from_slice(&sta);
            out.extend_from_slice(&ap);
        }
        out.extend_from_slice(&[0x10, 0x00]); // seq-ctrl
        out.extend_from_slice(&[0x00, 0x00]); // QoS control
        let mut llc: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00];
        llc[6..8].copy_from_slice(&ethertype.to_be_bytes());
        out.extend_from_slice(&llc);
        out.extend_from_slice(body);
        out.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // FCS
        out
    }

    /// EAPOL-flavoured helper over [`radiotap_snap_frame`].
    fn radiotap_eapol_frame(ap: [u8; 6], sta: [u8; 6], ap_to_sta: bool, body: &[u8]) -> Vec<u8> {
        radiotap_snap_frame(ap, sta, ap_to_sta, 0x888e, body)
    }

    fn beacon_frame(bssid: [u8; 6], ssid: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0);
        out.push(0);
        out.extend_from_slice(&8u16.to_le_bytes()); // it_len: 4 hdr + 4 present, no fields
        out.extend_from_slice(&0u32.to_le_bytes()); // empty present bitmap
        let fc_word = (0u16 << 2) | (8u16 << 4); // management beacon
        out.extend_from_slice(&fc_word.to_le_bytes());
        out.extend_from_slice(&[0x00, 0x00]); // duration
        out.extend_from_slice(&[0xff; 6]); // DA broadcast
        out.extend_from_slice(&bssid); // SA
        out.extend_from_slice(&bssid); // BSSID
        out.extend_from_slice(&[0x10, 0x00]); // seq-ctrl
        out.extend_from_slice(&[0u8; 8]); // timestamp
        out.extend_from_slice(&100u16.to_be_bytes()); // interval
        out.extend_from_slice(&0x0411u16.to_le_bytes()); // capability
        out.push(0x00); // SSID IE id
        out.push(ssid.len() as u8);
        out.extend_from_slice(ssid);
        out
    }

    #[test]
    fn unsupported_off_linux_for_the_monitor_door() {
        // The honest contract: the control door exists only on Linux.
        assert_eq!(monitor_mode_supported(), cfg!(target_os = "linux"));
    }

    #[test]
    fn beacon_then_m1_then_m2_produces_both_22000_lines() {
        let mut capture = MonitorCapture::new();
        // Beacon teaches the ESSID; no lines yet.
        let beacon_lines = capture
            .process_frame(&beacon_frame(AP, b"cyberdeck-e2e"))
            .expect("beacon parses");
        assert!(beacon_lines.is_empty());
        // M1 (AP -> STA): PMKID captured, line emitted (ESSID already known).
        let m1_lines = capture
            .process_frame(&radiotap_eapol_frame(AP, STA, true, &hex_bytes(M1_HEX)))
            .expect("M1 frame parses");
        assert!(
            m1_lines.contains(&EXPECTED_PMKID_LINE.to_string()),
            "{m1_lines:?}"
        );
        // M2 (STA -> AP): handshake complete, EAPOL line emitted.
        let m2_lines = capture
            .process_frame(&radiotap_eapol_frame(
                AP,
                STA,
                false,
                &hex_bytes(M2_FULL_HEX),
            ))
            .expect("M2 frame parses");
        assert!(
            m2_lines.contains(&EXPECTED_EAPOL_LINE.to_string()),
            "{m2_lines:?}"
        );
        // Both lines are stable across the whole-capture view.
        let all = capture.hashcat_22000_lines();
        assert!(all.contains(&EXPECTED_PMKID_LINE.to_string()));
        assert!(all.contains(&EXPECTED_EAPOL_LINE.to_string()));
        assert_eq!(all.len(), 2);
        assert_eq!(capture.handshakes().count(), 1);
    }

    #[test]
    fn pmkid_line_waits_for_the_essid_until_a_beacon_arrives() {
        let mut capture = MonitorCapture::new();
        // M1 first, before any beacon: nothing emittable yet.
        let m1_lines = capture
            .process_frame(&radiotap_eapol_frame(AP, STA, true, &hex_bytes(M1_HEX)))
            .expect("M1 frame parses");
        assert!(m1_lines.is_empty());
        // The beacon then completes the PMKID line.
        let beacon_lines = capture
            .process_frame(&beacon_frame(AP, b"cyberdeck-e2e"))
            .expect("beacon parses");
        assert!(beacon_lines.contains(&EXPECTED_PMKID_LINE.to_string()));
    }

    #[test]
    fn station_and_ap_roles_flip_with_data_direction() {
        let mut capture = MonitorCapture::new();
        capture
            .process_frame(&beacon_frame(AP, b"cyberdeck-e2e"))
            .expect("beacon");
        // M1 arrives AP->STA (fromDS), M2 STA->AP (toDS): both pair into the
        // same (AP, STA) handshake despite the address-role flip.
        capture
            .process_frame(&radiotap_eapol_frame(AP, STA, true, &hex_bytes(M1_HEX)))
            .expect("M1 fromDS");
        let lines = capture
            .process_frame(&radiotap_eapol_frame(
                AP,
                STA,
                false,
                &hex_bytes(M2_FULL_HEX),
            ))
            .expect("M2 toDS");
        assert!(lines.contains(&EXPECTED_EAPOL_LINE.to_string()));
    }

    #[test]
    fn malformed_frames_refuse_honestly() {
        let mut capture = MonitorCapture::new();
        // Truncated radiotap.
        assert_eq!(
            capture.process_frame(&[0u8; 4]).unwrap_err().code,
            WifiMonitorError::Protocol
        );
        // Valid radiotap over a truncated 802.11 frame.
        let mut frame = beacon_frame(AP, b"x");
        frame.truncate(20);
        assert_eq!(
            capture.process_frame(&frame).unwrap_err().code,
            WifiMonitorError::Protocol
        );
        // EAPOL body truncated: refused, not half-fed.
        let mut eapol = hex_bytes(M1_HEX);
        eapol.truncate(50);
        let mut frame = radiotap_eapol_frame(AP, STA, true, &eapol);
        frame.truncate(frame.len() - 1);
        assert_eq!(
            capture.process_frame(&frame).unwrap_err().code,
            WifiMonitorError::Protocol
        );
        // No handshakes were polluted by the failures.
        assert!(capture.hashcat_22000_lines().is_empty());
    }

    #[test]
    fn non_eapol_snap_and_untracked_frames_are_ignored() {
        let mut capture = MonitorCapture::new();
        // IPv4 LLC/SNAP frame: parsed, ignored, no lines.
        let ipv4: [u8; 4] = [0x45, 0x00, 0x00, 0x14];
        let lines = capture
            .process_frame(&radiotap_snap_frame(AP, STA, true, 0x0800, &ipv4))
            .expect("ipv4 frame parses");
        assert!(lines.is_empty());
        // Beacon for another AP does not disturb the (absent) handshakes.
        let lines = capture
            .process_frame(&beacon_frame(
                [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
                b"othernet",
            ))
            .expect("beacon parses");
        assert!(lines.is_empty());
        assert!(capture.hashcat_22000_lines().is_empty());
    }

    #[test]
    fn essid_map_is_bounded_with_lru_eviction() {
        let mut capture = MonitorCapture::new();
        for index in 0u32..MAX_TRACKED_AP_ESSIDS as u32 + 8 {
            let mut bssid = [0x02u8, 0x00, 0x00, 0x00, 0x00, 0x01];
            bssid[2..6].copy_from_slice(&index.to_be_bytes());
            capture
                .process_frame(&beacon_frame(bssid, b"network"))
                .expect("beacon parses");
        }
        assert!(capture.hashcat_22000_lines().is_empty());
        // Internally the map stays bounded; re-feeding the oldest BSSID must
        // not panic and simply re-attaches.
        let oldest = [0x02u8, 0x00, 0x00, 0x00, 0x00, 0x01];
        capture
            .process_frame(&beacon_frame(oldest, b"network"))
            .expect("oldest beacon parses");
    }

    #[test]
    fn whole_capture_truncation_never_panics() {
        let beacon = beacon_frame(AP, b"cyberdeck-e2e");
        for cut in 0..beacon.len() {
            let mut capture = MonitorCapture::new();
            let _ = capture.process_frame(&beacon[..cut]);
        }
        let eapol_frame = radiotap_eapol_frame(AP, STA, true, &hex_bytes(M1_HEX));
        for cut in 0..eapol_frame.len() {
            let mut capture = MonitorCapture::new();
            let _ = capture.process_frame(&eapol_frame[..cut]);
        }
    }
}
