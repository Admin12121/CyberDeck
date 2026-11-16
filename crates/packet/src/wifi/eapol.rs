//! 802.1X EAPOL-Key parsing, 4-way-handshake pairing, and hashcat mode 22000
//! hash-line emission.
//!
//! Field layout mirrors the vendored hashcat module's `auth_packet_t`
//! (module_22000.c): descriptor type, key-information word, key length,
//! replay counter, nonce, IV, RSC, key id, MIC (bytes 81..97 of the EAPOL
//! frame), key-data length and key data. Message classification (M1..M4)
//! follows the ack/mic/secure/key-type bits; PMKIDs are extracted from M1/M2
//! key data (PMKID KDE 00:0f:ac:04, or the PMKID list of an RSN IE).
//!
//! The collector pairs M1+M2 per (AP, STA) in a bounded LRU map and emits
//! hashcat 22000 lines byte-for-byte in module_22000.c's `module_hash_encode`
//! field order. This crate deliberately does NOT verify MICs — verification
//! lives in the crypto crate; the packet crate only produces the lines.
use crate::wifi::{WifiError, WifiMonitorError};

/// EAPOL-Key frames are tiny; the bound also rejects absurd truncation games.
pub const MAX_EAPOL_KEY_BYTES: usize = 512;
/// hashcat caps the EAPOL hex field at `WPA_EAPOL_LEN_MAX` = 256 bytes.
pub const HASHCAT_MAX_EAPOL_BYTES: usize = 256;
/// hashcat requires the EAPOL field to cover the whole `auth_packet_t` (99 bytes).
pub const HASHCAT_MIN_EAPOL_BYTES: usize = 99;
/// hashcat caps the ESSID at 32 bytes (64 hex characters).
pub const HASHCAT_MAX_ESSID_BYTES: usize = 32;
/// Bounded handshake store (LRU eviction at the cap).
pub const MAX_HANDSHAKES: usize = 64;
/// Offset of the 16-byte Key MIC field inside the EAPOL frame (`auth_packet_t`).
pub const KEY_MIC_OFFSET: usize = 81;

// EAPOL-Key key-information bits (big-endian word, IEEE 802.11-2020 12.7.2).
pub const KEY_INFO_ACK: u16 = 0x0080;
pub const KEY_INFO_MIC: u16 = 0x0100;
pub const KEY_INFO_SECURE: u16 = 0x0200;
pub const KEY_INFO_PAIRWISE: u16 = 0x0008;
pub const KEY_INFO_KEYVER_MASK: u16 = 0x0007;

/// Message pair values hashcat understands (hcxpcapngtool semantics).
pub const MESSAGE_PAIR_M1_M2: u8 = 0x00;
/// Bit 7: replay counter was not checked / differs — hcxtools marks this.
pub const MESSAGE_PAIR_REPLAY_UNCHECKED: u8 = 0x80;

/// Parsed EAPOL-Key frame, with slices borrowed from the capture buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapolKey<'a> {
    /// Descriptor type: 1 = WPA, 2 = RSN, 254 = pre-standard WPA2.
    pub descriptor_type: u8,
    pub key_information: u16,
    pub key_length: u16,
    pub replay_counter: u64,
    /// ANonce (M1/M3) or SNonce (M2/M4), 32 bytes.
    pub nonce: &'a [u8],
    /// Key MIC field, 16 bytes, as transmitted.
    pub mic: &'a [u8],
    /// Key data section (KDEs), possibly empty.
    pub key_data: &'a [u8],
}

impl EapolKey<'_> {
    pub fn keyver(&self) -> u16 {
        self.key_information & KEY_INFO_KEYVER_MASK
    }
    pub fn is_pairwise(&self) -> bool {
        self.key_information & KEY_INFO_PAIRWISE != 0
    }
    pub fn has_ack(&self) -> bool {
        self.key_information & KEY_INFO_ACK != 0
    }
    pub fn has_mic(&self) -> bool {
        self.key_information & KEY_INFO_MIC != 0
    }
    pub fn is_secure(&self) -> bool {
        self.key_information & KEY_INFO_SECURE != 0
    }

    /// Classic message classification: M1 (ack, no MIC), M2 (MIC, no ack, not
    /// secure), M3 (ack+MIC+secure), M4 (MIC+secure, no ack). `None` for
    /// messages that fit no classic role (group-key traffic and the like).
    pub fn message_number(&self) -> Option<u8> {
        let (ack, mic, secure) = (self.has_ack(), self.has_mic(), self.is_secure());
        if self.is_pairwise() && ack && !mic {
            Some(1)
        } else if self.is_pairwise() && !ack && mic && !secure {
            Some(2)
        } else if self.is_pairwise() && ack && mic && secure {
            Some(3)
        } else if self.is_pairwise() && !ack && mic && secure {
            Some(4)
        } else {
            None
        }
    }
}

fn protocol(message: impl Into<String>) -> WifiError {
    WifiError::new(WifiMonitorError::Protocol, message)
}

/// Parse the EAPOL-Key frame (starts at the EAPOL version/type/length header,
/// i.e. exactly what a `WPA*02*` line's eapol field holds).
pub fn parse_eapol_key(payload: &[u8]) -> Result<EapolKey<'_>, WifiError> {
    if payload.len() > MAX_EAPOL_KEY_BYTES {
        return Err(protocol(format!(
            "EAPOL-Key frame exceeds {MAX_EAPOL_KEY_BYTES} bytes"
        )));
    }
    // auth_packet_t: 4 (EAPOL header) + 95 (fixed EAPOL-Key fields) = 99.
    if payload.len() < HASHCAT_MIN_EAPOL_BYTES {
        return Err(protocol(format!(
            "EAPOL-Key frame truncated: {} bytes, need {HASHCAT_MIN_EAPOL_BYTES}",
            payload.len()
        )));
    }
    Ok(EapolKey {
        descriptor_type: payload[4],
        key_information: u16::from_be_bytes([payload[5], payload[6]]),
        key_length: u16::from_be_bytes([payload[7], payload[8]]),
        replay_counter: u64::from_be_bytes(payload[9..17].try_into().expect("bounded slice")),
        nonce: &payload[17..49],
        mic: &payload[KEY_MIC_OFFSET..KEY_MIC_OFFSET + 16],
        key_data: &payload[99..],
    })
}

/// Extract the first PMKID from EAPOL key data: either the PMKID KDE
/// (vendor type 00:0f:ac type 4) or the PMKID list of an embedded RSN IE.
pub fn extract_pmkid(key_data: &[u8]) -> Option<[u8; 16]> {
    for (id, payload) in crate::wifi::frame::walk_information_elements(key_data).ok()? {
        match id {
            // PMKID KDE: 0xDD, OUI 00:0f:ac, type 4, 16 bytes.
            0xDD => {
                if payload.len() == 20 && payload[0..3] == [0x00, 0x0f, 0xac] && payload[3] == 0x04
                {
                    let mut pmkid = [0u8; 16];
                    pmkid.copy_from_slice(&payload[4..20]);
                    return Some(pmkid);
                }
            }
            // RSN IE inside key data: PMKID list after the capabilities field.
            48 => {
                if let Some(pmkid) = pmkid_from_rsn_ie(payload) {
                    return Some(pmkid);
                }
            }
            _ => {}
        }
    }
    None
}

/// PMKID list position inside an RSN IE: version(2) group(4) pairwise
/// count(2)+n*4 akm count(2)+m*4 capabilities(2) [pmkid count(2)+k*16].
fn pmkid_from_rsn_ie(ie: &[u8]) -> Option<[u8; 16]> {
    if ie.len() < 2 || u16::from_le_bytes([ie[0], ie[1]]) != 1 {
        return None;
    }
    let mut pos = 2 + 4;
    if pos + 2 > ie.len() {
        return None;
    }
    let pairwise = u16::from_le_bytes([ie[pos], ie[pos + 1]]) as usize;
    pos += 2;
    if pairwise > 16 {
        return None;
    }
    pos += pairwise * 4;
    if pos + 2 > ie.len() {
        return None;
    }
    let akms = u16::from_le_bytes([ie[pos], ie[pos + 1]]) as usize;
    pos += 2;
    if akms > 16 {
        return None;
    }
    pos += akms * 4;
    if pos + 2 > ie.len() {
        return None;
    }
    pos += 2; // RSN capabilities
    if pos + 2 > ie.len() {
        return None;
    }
    let pmkid_count = u16::from_le_bytes([ie[pos], ie[pos + 1]]) as usize;
    pos += 2;
    if pmkid_count == 0 || pmkid_count > 8 || pos + 16 > ie.len() {
        return None;
    }
    let mut pmkid = [0u8; 16];
    pmkid.copy_from_slice(&ie[pos..pos + 16]);
    Some(pmkid)
}

/// Lowercase colon-less MAC, hashcat convention.
pub fn format_mac(mac: &[u8; 6]) -> String {
    mac.iter().map(|b| format!("{b:02x}")).collect()
}

/// Lowercase hex, hashcat convention (no separators, no prefix).
pub fn format_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One tracked handshake. Pair identity is (AP, STA); the ESSID attaches from
/// beacons/probe responses for that BSSID.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WpaHandshake {
    pub ap: [u8; 6],
    pub sta: [u8; 6],
    pub essid: Option<Vec<u8>>,
    /// ANonce from M1.
    pub anonce: Option<[u8; 32]>,
    /// SNonce from M2 (also embedded in the stored M2 frame).
    pub snonce: Option<[u8; 32]>,
    /// M2 EAPOL frame with the MIC field zeroed (hashcat line convention).
    pub m2_eapol_zeroed: Option<Vec<u8>>,
    /// M2 MIC as transmitted (the 22000 line's keymic field).
    pub m2_mic: Option<[u8; 16]>,
    /// M1 replay counter, for the replay-checked bit of the message pair.
    pub m1_replay: Option<u64>,
    pub m2_replay: Option<u64>,
    pub m1_seen: bool,
    pub m2_seen: bool,
    pub m3_seen: bool,
    pub m4_seen: bool,
    pub keyver: Option<u16>,
    pub pmkid: Option<[u8; 16]>,
}

impl WpaHandshake {
    /// The 4-way handshake is hashcat-usable when M1 and M2 are paired.
    pub fn is_complete(&self) -> bool {
        self.m1_seen && self.m2_seen
    }

    /// `WPA*02*...` line per module_22000.c `module_hash_encode` for type 2:
    /// `WPA*02*keymic*mac_ap*mac_sta*essid_hex*anonce*eapol_hex*message_pair`.
    /// The EAPOL field carries the M2 frame with the MIC zeroed; the message
    /// pair is M1+M2 (0x00), with the replay-unchecked bit (0x80) when the M2
    /// replay counter differs from the M1's.
    pub fn hashcat_eapol_22000(&self) -> Option<String> {
        let essid = self.essid.as_ref()?;
        if essid.is_empty() || essid.len() > HASHCAT_MAX_ESSID_BYTES {
            return None;
        }
        let anonce = self.anonce.as_ref()?;
        let eapol = self.m2_eapol_zeroed.as_ref()?;
        let mic = self.m2_mic.as_ref()?;
        if eapol.len() < HASHCAT_MIN_EAPOL_BYTES || eapol.len() > HASHCAT_MAX_EAPOL_BYTES {
            return None;
        }
        let mut message_pair = MESSAGE_PAIR_M1_M2;
        if let (Some(m1_replay), Some(m2_replay)) = (self.m1_replay, self.m2_replay) {
            if m1_replay != m2_replay {
                message_pair |= MESSAGE_PAIR_REPLAY_UNCHECKED;
            }
        }
        Some(format!(
            "WPA*02*{}*{}*{}*{}*{}*{}*{message_pair:02x}",
            format_hex(mic),
            format_mac(&self.ap),
            format_mac(&self.sta),
            format_hex(essid),
            format_hex(anonce),
            format_hex(eapol),
        ))
    }

    /// `WPA*01*...` PMKID line per module_22000.c type 1:
    /// `WPA*01*pmkid*mac_ap*mac_sta*essid_hex***` — the trailing message-pair
    /// field stays empty except for key version 3, which hcxpcapngtool marks
    /// `03` (HMAC-SHA256 PMKID, e.g. SAE).
    pub fn hashcat_pmkid_22000(&self) -> Option<String> {
        let pmkid = self.pmkid.as_ref()?;
        let essid = self.essid.as_ref()?;
        if essid.is_empty() || essid.len() > HASHCAT_MAX_ESSID_BYTES {
            return None;
        }
        let message_pair = if self.keyver == Some(3) { "03" } else { "" };
        Some(format!(
            "WPA*01*{}*{}*{}*{}***{message_pair}",
            format_hex(pmkid),
            format_mac(&self.ap),
            format_mac(&self.sta),
            format_hex(essid),
        ))
    }
}

/// What one fed EAPOL frame caused: a completed handshake and/or a captured
/// PMKID. Lines are hashcat-ready.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeEvent {
    pub ap: [u8; 6],
    pub sta: [u8; 6],
    pub handshake_complete: bool,
    pub pmkid_captured: bool,
    /// Lines for THIS event only.
    pub lines: Vec<String>,
}

/// Bounded (AP, STA) handshake store with LRU eviction.
#[derive(Debug, Default)]
pub struct HandshakeCollector {
    entries: Vec<LruEntry>,
    tick: u64,
}

#[derive(Debug)]
struct LruEntry {
    handshake: WpaHandshake,
    last_touched: u64,
}

fn valid_station(mac: &[u8; 6]) -> bool {
    // Zero MAC or multicast/broadcast first octet: not a station pair.
    !mac.iter().all(|b| *b == 0) && mac[0] & 0x01 == 0
}

impl HandshakeCollector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn handshakes(&self) -> impl Iterator<Item = &WpaHandshake> {
        self.entries.iter().map(|entry| &entry.handshake)
    }

    /// Hashcat lines for every stored handshake that can emit one.
    pub fn hashcat_22000_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        for entry in &self.entries {
            let handshake = &entry.handshake;
            if let Some(line) = handshake.hashcat_eapol_22000() {
                lines.push(line);
            }
            if let Some(line) = handshake.hashcat_pmkid_22000() {
                lines.push(line);
            }
        }
        lines
    }

    /// Attach an ESSID learned from a beacon/probe response for this BSSID.
    /// Returns lines for handshakes that became emittable with the ESSID.
    pub fn attach_essid(&mut self, bssid: &[u8; 6], essid: &[u8]) -> Vec<String> {
        if essid.is_empty() || essid.len() > HASHCAT_MAX_ESSID_BYTES {
            return Vec::new();
        }
        let mut lines = Vec::new();
        for entry in &mut self.entries {
            let handshake = &mut entry.handshake;
            if handshake.ap == *bssid && handshake.essid.as_deref() != Some(essid) {
                let was_emittable_eapol = handshake.hashcat_eapol_22000().is_some();
                let was_emittable_pmkid = handshake.hashcat_pmkid_22000().is_some();
                handshake.essid = Some(essid.to_vec());
                if !was_emittable_eapol {
                    if let Some(line) = handshake.hashcat_eapol_22000() {
                        lines.push(line);
                    }
                }
                if !was_emittable_pmkid {
                    if let Some(line) = handshake.hashcat_pmkid_22000() {
                        lines.push(line);
                    }
                }
            }
        }
        lines
    }

    /// Feed one EAPOL frame from the wire (SA = transmitter, DA = receiver;
    /// the AP side is whichever address matches the BSSID).
    pub fn feed(
        &mut self,
        ap: [u8; 6],
        sta: [u8; 6],
        eapol_frame: &[u8],
    ) -> Result<HandshakeEvent, WifiError> {
        if !valid_station(&ap) || !valid_station(&sta) {
            return Err(protocol(
                "EAPOL frame has a zero or multicast station address",
            ));
        }
        let parsed = parse_eapol_key(eapol_frame)?;
        let mut event = HandshakeEvent {
            ap,
            sta,
            handshake_complete: false,
            pmkid_captured: false,
            lines: Vec::new(),
        };
        let message = parsed.message_number();
        let keyver = parsed.keyver();
        let pmkid = extract_pmkid(parsed.key_data);
        let entry = self.entry_for(ap, sta);
        let handshake = &mut entry.handshake;
        handshake.keyver = Some(keyver);
        match message {
            Some(1) => {
                handshake.m1_seen = true;
                let mut anonce = [0u8; 32];
                anonce.copy_from_slice(parsed.nonce);
                handshake.anonce = Some(anonce);
                handshake.m1_replay = Some(parsed.replay_counter);
                if let Some(pmkid) = pmkid {
                    if handshake.pmkid.is_none() {
                        handshake.pmkid = Some(pmkid);
                        event.pmkid_captured = true;
                        if let Some(line) = handshake.hashcat_pmkid_22000() {
                            event.lines.push(line);
                        }
                    }
                }
            }
            Some(2) => {
                handshake.m2_seen = true;
                let mut snonce = [0u8; 32];
                snonce.copy_from_slice(parsed.nonce);
                handshake.snonce = Some(snonce);
                handshake.m2_replay = Some(parsed.replay_counter);
                let mut mic = [0u8; 16];
                mic.copy_from_slice(parsed.mic);
                handshake.m2_mic = Some(mic);
                // The stored frame carries a zeroed MIC: hashcat hashes the
                // eapol field as-is (m22000-pure.cl hmac_update_global over
                // the raw bytes), so the zeroed form is the line convention.
                let mut zeroed = eapol_frame.to_vec();
                zeroed[KEY_MIC_OFFSET..KEY_MIC_OFFSET + 16].fill(0);
                handshake.m2_eapol_zeroed = Some(zeroed);
                if let Some(pmkid) = pmkid {
                    if handshake.pmkid.is_none() {
                        handshake.pmkid = Some(pmkid);
                        event.pmkid_captured = true;
                        if let Some(line) = handshake.hashcat_pmkid_22000() {
                            event.lines.push(line);
                        }
                    }
                }
            }
            Some(3) => handshake.m3_seen = true,
            Some(4) => handshake.m4_seen = true,
            _ => {} // group-key or non-pairwise traffic: tracked keyver only
        }
        event.handshake_complete = handshake.is_complete();
        if handshake.is_complete() && event.lines.is_empty() {
            if let Some(line) = handshake.hashcat_eapol_22000() {
                event.lines.push(line);
            }
        }
        Ok(event)
    }

    /// Get-or-insert with LRU eviction past `MAX_HANDSHAKES`.
    fn entry_for(&mut self, ap: [u8; 6], sta: [u8; 6]) -> &mut LruEntry {
        self.tick = self.tick.wrapping_add(1);
        let tick = self.tick;
        let index = match self
            .entries
            .iter()
            .position(|entry| entry.handshake.ap == ap && entry.handshake.sta == sta)
        {
            Some(index) => {
                self.entries[index].last_touched = tick;
                index
            }
            None => {
                self.entries.push(LruEntry {
                    handshake: WpaHandshake {
                        ap,
                        sta,
                        ..WpaHandshake::default()
                    },
                    last_touched: tick,
                });
                // Evict the least-recently-touched entry; the freshly pushed
                // one carries the highest tick and can never be the victim.
                if self.entries.len() > MAX_HANDSHAKES {
                    let victim = self
                        .entries
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, entry)| entry.last_touched)
                        .map(|(index, _)| index)
                        .unwrap_or(0);
                    self.entries.remove(victim);
                }
                self.entries.len() - 1
            }
        };
        &mut self.entries[index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AP: [u8; 6] = [0xa4, 0xb1, 0xc1, 0xd2, 0xe3, 0xf0];
    const STA: [u8; 6] = [0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f];

    /// Synthetic handshake fixtures (RFC 5737/7042 doc values), generated
    /// with the Python stdlib (hmac/pbkdf2) for the password
    /// "cyberdeck-e2e-42" and ESSID "cyberdeck-e2e".
    const ANONCE_HEX: &str = "1122334455667788112233445566778811223344556677881122334455667788";
    const SNONCE_HEX: &str = "aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011";
    /// PMKID as it travels on the wire: 128-bit truncation of
    /// HMAC-SHA1(PMK, "PMK Name" || ap || sta) — hashcat's 32-hex field.
    const PMKID_HEX: &str = "8066ad9635ac9def6b250b58866e22b7";
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

    fn feed_pair() -> (HandshakeCollector, HandshakeEvent, HandshakeEvent) {
        let mut collector = HandshakeCollector::new();
        let m1 = hex_bytes(M1_HEX);
        let m2 = hex_bytes(M2_FULL_HEX);
        let e1 = collector.feed(AP, STA, &m1).expect("M1 parses");
        let e2 = collector.feed(AP, STA, &m2).expect("M2 parses");
        (collector, e1, e2)
    }

    #[test]
    fn eapol_key_fields_decode_per_auth_packet_t() {
        let m1 = hex_bytes(M1_HEX);
        let key = parse_eapol_key(&m1).expect("M1 parses");
        assert_eq!(key.descriptor_type, 0x02);
        assert_eq!(key.key_information, 0x008a); // ack | pairwise | keyver 2
        assert_eq!(key.key_length, 16);
        assert_eq!(key.replay_counter, 1);
        assert_eq!(key.nonce, &hex_bytes(ANONCE_HEX));
        assert_eq!(key.mic, &[0u8; 16]);
        assert_eq!(key.keyver(), 2);
        assert_eq!(key.message_number(), Some(1));

        let m2 = hex_bytes(M2_FULL_HEX);
        let key = parse_eapol_key(&m2).expect("M2 parses");
        assert_eq!(key.key_information, 0x010a); // mic | pairwise | keyver 2
        assert_eq!(key.replay_counter, 1); // echoes the M1 replay counter
        assert_eq!(key.nonce, &hex_bytes(SNONCE_HEX));
        assert_eq!(
            key.mic,
            &hex_bytes(M2_FULL_HEX)[KEY_MIC_OFFSET..KEY_MIC_OFFSET + 16]
        );
        assert_eq!(key.message_number(), Some(2));
    }

    #[test]
    fn pmkid_kde_is_extracted_from_m1_key_data() {
        let m1 = hex_bytes(M1_HEX);
        let key = parse_eapol_key(&m1).expect("M1 parses");
        let expected: [u8; 16] = hex_bytes(PMKID_HEX)
            .as_slice()
            .try_into()
            .expect("16-byte PMKID");
        assert_eq!(
            extract_pmkid(key.key_data).expect("PMKID present"),
            expected
        );
    }

    #[test]
    fn pmkid_line_matches_module_22000_byte_for_byte() {
        let (mut collector, e1, _) = feed_pair();
        collector.attach_essid(&AP, b"cyberdeck-e2e");
        assert!(e1.pmkid_captured);
        // ESSID attached after M1: the PMKID line emits through all_lines.
        assert!(collector
            .hashcat_22000_lines()
            .iter()
            .any(|line| line == EXPECTED_PMKID_LINE));
    }

    #[test]
    fn pmkid_line_emits_when_the_essid_arrives() {
        let mut collector = HandshakeCollector::new();
        let m1 = hex_bytes(M1_HEX);
        // M1 before any beacon: the PMKID is captured but no line exists yet
        // (hashcat needs the ESSID), then attach_essid emits it.
        let event = collector.feed(AP, STA, &m1).expect("M1 parses");
        assert!(event.pmkid_captured);
        assert!(event.lines.is_empty());
        let lines = collector.attach_essid(&AP, b"cyberdeck-e2e");
        assert_eq!(lines, vec![EXPECTED_PMKID_LINE.to_string()]);
    }

    #[test]
    fn eapol_line_matches_module_22000_byte_for_byte() {
        let (mut collector, _, e2) = feed_pair();
        collector.attach_essid(&AP, b"cyberdeck-e2e");
        assert!(e2.handshake_complete || collector.hashcat_22000_lines().len() == 1);
        let lines = collector.hashcat_22000_lines();
        assert!(
            lines.iter().any(|line| line == EXPECTED_EAPOL_LINE),
            "EAPOL line mismatch:\n got {lines:?}\n want {EXPECTED_EAPOL_LINE}"
        );
    }

    #[test]
    fn event_lines_surface_the_completed_handshake_line() {
        // With the ESSID already attached, the M2 event emits the WPA*02* line.
        let mut collector = HandshakeCollector::new();
        collector.feed(AP, STA, &hex_bytes(M1_HEX)).expect("M1");
        collector.attach_essid(&AP, b"cyberdeck-e2e");
        let event = collector
            .feed(AP, STA, &hex_bytes(M2_FULL_HEX))
            .expect("M2");
        assert!(event.handshake_complete);
        assert_eq!(event.lines, vec![EXPECTED_EAPOL_LINE.to_string()]);
    }

    #[test]
    fn message_classification_covers_m1_to_m4() {
        // M3: ack+mic+secure, M4: mic+secure without ack.
        let m3_hex = "0203005f02038a0010000000000000000211223344556677881122334455667788112233445566778811223344556677880000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let m4_hex = "0203005f02030a00100000000000000002aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff00110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        let m3_bytes = hex_bytes(m3_hex);
        let m4_bytes = hex_bytes(m4_hex);
        let m3 = parse_eapol_key(&m3_bytes).expect("M3 parses");
        let m4 = parse_eapol_key(&m4_bytes).expect("M4 parses");
        assert_eq!(m3.message_number(), Some(3));
        assert_eq!(m4.message_number(), Some(4));
        let mut collector = HandshakeCollector::new();
        collector.feed(AP, STA, &hex_bytes(M1_HEX)).expect("M1");
        collector
            .feed(AP, STA, &hex_bytes(M2_FULL_HEX))
            .expect("M2");
        collector.feed(AP, STA, &hex_bytes(m3_hex)).expect("M3");
        collector.feed(AP, STA, &hex_bytes(m4_hex)).expect("M4");
        let entry = collector.handshakes().next().expect("handshake stored");
        assert!(entry.m3_seen && entry.m4_seen);
        assert!(entry.is_complete());
    }

    #[test]
    fn replay_counter_mismatch_sets_message_pair_bit() {
        let mut collector = HandshakeCollector::new();
        collector.feed(AP, STA, &hex_bytes(M1_HEX)).expect("M1");
        // M2 with a bumped replay counter.
        let mut m2 = hex_bytes(M2_FULL_HEX);
        m2[9..17].copy_from_slice(&99u64.to_be_bytes());
        collector.feed(AP, STA, &m2).expect("M2");
        collector.attach_essid(&AP, b"cyberdeck-e2e");
        let lines = collector.hashcat_22000_lines();
        let eapol_line = lines
            .iter()
            .find(|l| l.starts_with("WPA*02*"))
            .expect("line");
        assert!(eapol_line.ends_with("*80"), "replay bit: {eapol_line}");
    }

    #[test]
    fn store_is_bounded_with_lru_eviction() {
        let mut collector = HandshakeCollector::new();
        let m1 = hex_bytes(M1_HEX);
        for index in 0u32..MAX_HANDSHAKES as u32 + 16 {
            let mut sta = [0u8; 6];
            sta[0] = 0x02; // unicast local
            sta[2..6].copy_from_slice(&index.to_be_bytes());
            collector.feed(AP, sta, &m1).expect("M1 parses");
        }
        assert_eq!(collector.len(), MAX_HANDSHAKES);
    }

    #[test]
    fn zero_and_multicast_station_addresses_are_refused() {
        let mut collector = HandshakeCollector::new();
        let m1 = hex_bytes(M1_HEX);
        let err = collector
            .feed(AP, [0u8; 6], &m1)
            .expect_err("zero STA refuses");
        assert_eq!(err.code, WifiMonitorError::Protocol);
        let err = collector
            .feed([0xff; 6], STA, &m1)
            .expect_err("broadcast AP refuses");
        assert_eq!(err.code, WifiMonitorError::Protocol);
    }

    #[test]
    fn truncated_and_malicious_frames_refuse_without_panics() {
        let m1 = hex_bytes(M1_HEX);
        let mut collector = HandshakeCollector::new();
        for cut in 0..m1.len() {
            let result = collector.feed(AP, STA, &m1[..cut]);
            if cut < HASHCAT_MIN_EAPOL_BYTES {
                assert!(result.is_err(), "truncated frame of {cut} bytes parsed");
            }
        }
        // Oversized.
        assert_eq!(
            collector
                .feed(AP, STA, &vec![0u8; MAX_EAPOL_KEY_BYTES + 1])
                .unwrap_err()
                .code,
            WifiMonitorError::Protocol
        );
        // Fuzz-ish random prefixes of the M2 must never panic.
        let m2 = hex_bytes(M2_FULL_HEX);
        for cut in 0..m2.len() {
            let _ = collector.feed(AP, STA, &m2[..cut]);
        }
    }

    #[test]
    fn essid_rules_match_hashcat_caps() {
        let (mut collector, _, _) = feed_pair();
        // No ESSID: no lines.
        assert!(collector.hashcat_22000_lines().is_empty());
        // Empty ESSID is refused by attach_essid.
        collector.attach_essid(&AP, b"");
        assert!(collector.hashcat_22000_lines().is_empty());
        // 33-byte ESSID refused.
        let oversized = vec![0x61u8; HASHCAT_MAX_ESSID_BYTES + 1];
        collector.attach_essid(&AP, &oversized);
        assert!(collector.hashcat_22000_lines().is_empty());
        // 32-byte ESSID accepted: both the PMKID and the EAPOL line appear.
        let max = vec![0x61u8; HASHCAT_MAX_ESSID_BYTES];
        collector.attach_essid(&AP, &max);
        assert_eq!(collector.hashcat_22000_lines().len(), 2);
    }

    #[test]
    fn mac_and_hex_formatting_is_colonless_lowercase() {
        assert_eq!(format_mac(&AP), "a4b1c1d2e3f0");
        assert_eq!(format_hex(&[0x0f, 0xa0]), "0fa0");
    }
}
