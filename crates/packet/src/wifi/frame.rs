//! Bounded 802.11 MAC frame parsing.
//!
//! Version/type/subtype decode, to/from-DS four-address resolution per the
//! address assignment tables (IEEE 802.11-2020 §9.3.3 / RFC 9490), QoS plus
//! HT-Control length handling, the protected-frame flag, and FCS stripping
//! when the radiotap flags say an FCS trails the frame. Management bodies are
//! parsed per subtype with a bounded information-element walk; data frames
//! carrying LLC/SNAP ethertype 0x888e surface their EAPOL payload for the
//! handshake collector. Truncated or malicious input is refused, never
//! unwrapped, and never panics.
use crate::wifi::{WifiError, WifiMonitorError};

/// Capture-size bound for one 802.11 frame (radiotap stripped already).
pub const MAX_FRAME_BYTES: usize = 4096;
/// Information-element cap per management body (bounded walk).
pub const MAX_MGMT_IES: usize = 64;
/// SSID length cap per 802.11 (the IE header allows 255 but the spec says 32).
pub const MAX_SSID_BYTES: usize = 32;
/// LLC/SNAP ethertype for 802.1X EAPOL.
pub const ETHERTYPE_EAPOL: u16 = 0x888e;

pub const FC_TYPE_MANAGEMENT: u8 = 0;
pub const FC_TYPE_CONTROL: u8 = 1;
pub const FC_TYPE_DATA: u8 = 2;

// Management subtypes.
pub const SUBTYPE_ASSOCIATION_REQUEST: u8 = 0;
pub const SUBTYPE_ASSOCIATION_RESPONSE: u8 = 1;
pub const SUBTYPE_PROBE_REQUEST: u8 = 4;
pub const SUBTYPE_PROBE_RESPONSE: u8 = 5;
pub const SUBTYPE_BEACON: u8 = 8;
pub const SUBTYPE_DISASSOCIATION: u8 = 10;
pub const SUBTYPE_AUTHENTICATION: u8 = 11;
pub const SUBTYPE_DEAUTHENTICATION: u8 = 12;
pub const SUBTYPE_ACTION: u8 = 13;
/// QoS data = data (0) with the subtype high bit set.
pub const SUBTYPE_FLAG_QOS: u8 = 0x8;

/// Fixed 802.11 MAC addresses as they appear on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Addresses {
    pub addr1: [u8; 6],
    pub addr2: [u8; 6],
    pub addr3: [u8; 6],
    /// Present only on four-address (WDS/mesh) data frames.
    pub addr4: Option<[u8; 6]>,
}

/// Address roles resolved through the to/from-DS table. For management
/// frames: DA=addr1, SA=addr2, BSSID=addr3. For data frames the table maps
/// RA/TA/DA/SA/BSSID per direction; `bssid` is None only for WDS frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameRoles {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub bssid: Option<[u8; 6]>,
    /// First receiving/transmitting address (addr1/addr2 as received).
    pub receiver: [u8; 6],
    pub transmitter: [u8; 6],
}

/// RSN (Robust Security Network) information from a beacon/probe RSN IE,
/// bounded to the suites the parser can store.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RsnInfo {
    pub version: u16,
    /// AKM suite selectors, each `[oui0, oui1, oui2, type]`, at most 8.
    pub akm_suites: Vec<[u8; 4]>,
    /// True when any AKM is 802.1X (00:0f:ac:01 or 00:0f:ac:03+) instead of PSK.
    pub uses_8021x: bool,
}

/// Dissected frame body, with slices borrowed from the capture buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameKind<'a> {
    Beacon {
        ssid: Option<&'a [u8]>,
        rsn: Option<RsnInfo>,
    },
    ProbeRequest {
        ssid: Option<&'a [u8]>,
    },
    ProbeResponse {
        ssid: Option<&'a [u8]>,
        rsn: Option<RsnInfo>,
    },
    Authentication {
        algorithm: u16,
        sequence: u16,
        status: u16,
    },
    Deauthentication {
        reason: u16,
    },
    Disassociation {
        reason: u16,
    },
    AssociationRequest {
        capability: u16,
        listen_interval: u16,
    },
    AssociationResponse {
        capability: u16,
        status: u16,
    },
    /// Management frame subtype without a dedicated parser.
    Management,
    /// Control frame (RTS/CTS/ACK/...): address parse only.
    Control,
    /// Plain data or null-function frame with no LLC/SNAP payload surfaced.
    Data,
    /// Data frame whose LLC/SNAP ethertype was recognized.
    Snap {
        ethertype: u16,
        payload: &'a [u8],
    },
}

/// Fully dissected 802.11 frame. `body` is the payload after the MAC header
/// (FCS already stripped when radiotap said one was present); for management
/// frames it is the information-element section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedFrame<'a> {
    pub version: u8,
    pub frame_type: u8,
    pub subtype: u8,
    pub to_ds: bool,
    pub from_ds: bool,
    pub protected: bool,
    pub retry: bool,
    pub qos: bool,
    pub addresses: Addresses,
    pub roles: FrameRoles,
    pub kind: FrameKind<'a>,
    /// Payload after the MAC header, FCS stripped when `fcs_present` was set.
    pub body: &'a [u8],
}

fn protocol(message: impl Into<String>) -> WifiError {
    WifiError::new(WifiMonitorError::Protocol, message)
}

fn mac_at(bytes: &[u8], offset: usize) -> [u8; 6] {
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&bytes[offset..offset + 6]);
    mac
}

/// Walk a bounded information-element section: `(id, payload)` pairs.
/// Refuses on truncated headers, oversized elements, or more than
/// `MAX_MGMT_IES` elements.
pub fn walk_information_elements(body: &[u8]) -> Result<Vec<(u8, &[u8])>, WifiError> {
    let mut ies = Vec::new();
    let mut pos = 0usize;
    while pos < body.len() {
        if ies.len() == MAX_MGMT_IES {
            return Err(protocol(format!(
                "management body carries more than {MAX_MGMT_IES} IEs"
            )));
        }
        if pos + 2 > body.len() {
            return Err(protocol("truncated IE header"));
        }
        let id = body[pos];
        let length = body[pos + 1] as usize;
        let end = pos
            .checked_add(2)
            .and_then(|p| p.checked_add(length))
            .ok_or_else(|| protocol("IE length overflow"))?;
        if end > body.len() {
            return Err(protocol("IE length exceeds the management body"));
        }
        ies.push((id, &body[pos + 2..end]));
        pos = end;
    }
    Ok(ies)
}

/// Bounded RSN IE parse: version, group cipher, pairwise suites, AKM suites,
/// capabilities. The PMKID list (802.11r) is skipped here; the handshake
/// collector reads PMKIDs from EAPOL key data instead.
pub fn parse_rsn_ie(ie: &[u8]) -> Option<RsnInfo> {
    if ie.len() < 2 {
        return None;
    }
    let version = u16::from_le_bytes([ie[0], ie[1]]);
    if version != 1 {
        return None;
    }
    // version(2) + group cipher(4) + pairwise count(2) minimum.
    if ie.len() < 8 {
        return None;
    }
    let mut pos = 2 + 4;
    if pos + 2 > ie.len() {
        return None;
    }
    let pairwise_count = u16::from_le_bytes([ie[pos], ie[pos + 1]]) as usize;
    pos += 2;
    if pairwise_count > 16
        || pos
            .checked_add(pairwise_count * 4)
            .is_none_or(|p| p > ie.len())
    {
        return None;
    }
    pos += pairwise_count * 4;
    if pos + 2 > ie.len() {
        return None;
    }
    let akm_count = u16::from_le_bytes([ie[pos], ie[pos + 1]]) as usize;
    pos += 2;
    if akm_count > 8 || pos.checked_add(akm_count * 4).is_none_or(|p| p > ie.len()) {
        return None;
    }
    let mut akm_suites = Vec::with_capacity(akm_count.min(8));
    for _ in 0..akm_count {
        let suite = [ie[pos], ie[pos + 1], ie[pos + 2], ie[pos + 3]];
        akm_suites.push(suite);
        pos += 4;
    }
    let uses_8021x = akm_suites
        .iter()
        .any(|s| s[..3] == [0x00, 0x0f, 0xac] && s[3] != 0x02 && s[3] != 0x08);
    Some(RsnInfo {
        version,
        akm_suites,
        uses_8021x,
    })
}

struct SsidRsn<'a> {
    ssid: Option<&'a [u8]>,
    rsn: Option<RsnInfo>,
}

/// First SSID IE and first RSN IE from a bounded walk.
fn extract_ssid_and_rsn<'a>(body: &'a [u8]) -> Result<SsidRsn<'a>, WifiError> {
    let mut found = SsidRsn {
        ssid: None,
        rsn: None,
    };
    for (id, payload) in walk_information_elements(body)? {
        match id {
            0 => {
                if found.ssid.is_none() {
                    if payload.len() > MAX_SSID_BYTES {
                        return Err(protocol(format!("SSID IE exceeds {MAX_SSID_BYTES} bytes")));
                    }
                    found.ssid = Some(payload);
                }
            }
            48 => {
                if found.rsn.is_none() {
                    found.rsn = parse_rsn_ie(payload);
                }
            }
            _ => {}
        }
    }
    Ok(found)
}

fn be16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

/// 802.11 MAC header fields (frame control, QoS control, sequence control)
/// are little-endian on the wire; only body fields are big-endian.
fn le16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

/// Parse an 802.11 frame. `fcs_present` and `data_pad` come from the radiotap
/// FLAGS field: when `fcs_present`, four FCS bytes are stripped from the end;
/// when `data_pad`, the body start is aligned to four bytes as some chips do.
pub fn parse<'a>(
    bytes: &'a [u8],
    fcs_present: bool,
    data_pad: bool,
) -> Result<ParsedFrame<'a>, WifiError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(protocol(format!(
            "802.11 frame exceeds {MAX_FRAME_BYTES} bytes"
        )));
    }
    if bytes.len() < 10 {
        return Err(protocol("802.11 frame shorter than the address fields"));
    }
    let fc = u16::from_le_bytes([bytes[0], bytes[1]]);
    let version = (fc & 0x0003) as u8;
    if version != 0 {
        return Err(protocol(format!("unsupported 802.11 version {version}")));
    }
    let frame_type = ((fc >> 2) & 0x0003) as u8;
    let subtype = ((fc >> 4) & 0x000f) as u8;
    let to_ds = fc & 0x0100 != 0;
    let from_ds = fc & 0x0200 != 0;
    let protected = fc & 0x4000 != 0;
    let retry = fc & 0x0800 != 0;

    let addr1 = mac_at(bytes, 4);
    // addr2/addr3 exist only from 16/22 bytes on; control frames may stop at
    // 10 bytes (ACK/CTS carry no transmitter address).
    let addr2 = if bytes.len() >= 16 {
        mac_at(bytes, 10)
    } else {
        [0; 6]
    };
    let mut addresses = Addresses {
        addr1,
        addr2,
        addr3: [0; 6],
        addr4: None,
    };
    let mut header_len = 24usize;

    match frame_type {
        // Management: DA=addr1, SA=addr2, BSSID=addr3; seq-ctrl ends the header.
        FC_TYPE_MANAGEMENT => {
            if bytes.len() < header_len {
                return Err(protocol("management frame truncated before seq-ctrl"));
            }
            addresses.addr3 = mac_at(bytes, 16);
        }
        // Control: RA=addr1, TA=addr2 (CTS/ACK carry only RA). Minimal parse.
        FC_TYPE_CONTROL => {
            header_len = 10;
            addresses.addr3 = [0; 6];
        }
        // Data: three fixed addresses, optional addr4 (WDS), QoS, HT control.
        FC_TYPE_DATA => {
            if bytes.len() < header_len {
                return Err(protocol("data frame truncated before seq-ctrl"));
            }
            addresses.addr3 = mac_at(bytes, 16);
            if to_ds && from_ds {
                if bytes.len() < header_len + 6 {
                    return Err(protocol("four-address data frame truncated before addr4"));
                }
                addresses.addr4 = Some(mac_at(bytes, header_len));
                header_len += 6;
            }
            let qos = subtype & SUBTYPE_FLAG_QOS != 0;
            if qos {
                if bytes.len() < header_len + 2 {
                    return Err(protocol("QoS data frame truncated before QoS control"));
                }
                // RFC 9490: the HT Control field is present when bit 8 of the
                // QoS Control field is set (or the FC Order bit on QoS data).
                let qos_control = le16_at(bytes, header_len);
                let ht_control = if qos_control & 0x0100 != 0 || fc & 0x8000 != 0 {
                    4
                } else {
                    0
                };
                if bytes.len() < header_len + 2 + ht_control {
                    return Err(protocol("QoS data frame truncated before HT control"));
                }
                header_len += 2 + ht_control;
            }
        }
        _ => return Err(protocol(format!("unsupported 802.11 type {frame_type}"))),
    }

    // Address roles per the 802.11-2020 / RFC 9490 tables.
    let roles = match (frame_type, to_ds, from_ds) {
        (FC_TYPE_MANAGEMENT, _, _) | (FC_TYPE_DATA, false, false) => FrameRoles {
            destination: addr1,
            source: addr2,
            bssid: Some(addresses.addr3),
            receiver: addr1,
            transmitter: addr2,
        },
        (FC_TYPE_DATA, true, false) => FrameRoles {
            destination: addresses.addr3,
            source: addr2,
            bssid: Some(addr1),
            receiver: addr1,
            transmitter: addr2,
        },
        (FC_TYPE_DATA, false, true) => FrameRoles {
            destination: addr1,
            source: addresses.addr3,
            bssid: Some(addr2),
            receiver: addr1,
            transmitter: addr2,
        },
        (FC_TYPE_DATA, true, true) => FrameRoles {
            destination: addresses.addr3,
            source: addresses
                .addr4
                .ok_or_else(|| protocol("WDS data frame without addr4 in the roles table"))?,
            bssid: None, // WDS/mesh frames carry no BSSID
            receiver: addr1,
            transmitter: addr2,
        },
        (FC_TYPE_CONTROL, _, _) => FrameRoles {
            destination: addr1,
            source: addr2,
            bssid: None,
            receiver: addr1,
            transmitter: addr2,
        },
        _ => unreachable!("type 3 refused above"),
    };

    // Body: after the header (4-aligned when the chip pads), FCS stripped.
    let mut body_start = header_len;
    if data_pad && frame_type == FC_TYPE_DATA {
        body_start = body_start.div_ceil(4) * 4;
    }
    let mut body_end = bytes.len();
    if fcs_present {
        body_end = body_end
            .checked_sub(4)
            .ok_or_else(|| protocol("radiotap claims an FCS the frame does not carry"))?;
    }
    if body_start > body_end {
        return Err(protocol("802.11 body start past the (stripped) frame end"));
    }
    let body = &bytes[body_start..body_end];

    let kind = match frame_type {
        FC_TYPE_CONTROL => FrameKind::Control,
        FC_TYPE_MANAGEMENT => parse_management(subtype, body)?,
        FC_TYPE_DATA => parse_data(subtype, body)?,
        _ => unreachable!("type 3 refused above"),
    };

    Ok(ParsedFrame {
        version,
        frame_type,
        subtype,
        to_ds,
        from_ds,
        protected,
        retry,
        qos: frame_type == FC_TYPE_DATA && subtype & SUBTYPE_FLAG_QOS != 0,
        addresses,
        roles,
        kind,
        body,
    })
}

fn parse_management<'a>(subtype: u8, body: &'a [u8]) -> Result<FrameKind<'a>, WifiError> {
    match subtype {
        SUBTYPE_BEACON | SUBTYPE_PROBE_RESPONSE => {
            // timestamp(8) + interval(2) + capability(2), then IEs.
            if body.len() < 12 {
                return Err(protocol(format!(
                    "subtype {subtype} body shorter than 12 bytes"
                )));
            }
            let found = extract_ssid_and_rsn(&body[12..])?;
            if subtype == SUBTYPE_BEACON {
                Ok(FrameKind::Beacon {
                    ssid: found.ssid,
                    rsn: found.rsn,
                })
            } else {
                Ok(FrameKind::ProbeResponse {
                    ssid: found.ssid,
                    rsn: found.rsn,
                })
            }
        }
        SUBTYPE_PROBE_REQUEST => {
            let found = extract_ssid_and_rsn(body)?;
            Ok(FrameKind::ProbeRequest { ssid: found.ssid })
        }
        // All 2-byte management body fields are little-endian on the wire,
        // like every MAC-layer field (802.11-2020 9.x: LSB first).
        SUBTYPE_AUTHENTICATION => {
            if body.len() < 6 {
                return Err(protocol("authentication body shorter than 6 bytes"));
            }
            Ok(FrameKind::Authentication {
                algorithm: le16_at(body, 0),
                sequence: le16_at(body, 2),
                status: le16_at(body, 4),
            })
        }
        SUBTYPE_DEAUTHENTICATION => {
            if body.len() < 2 {
                return Err(protocol("deauthentication body shorter than 2 bytes"));
            }
            Ok(FrameKind::Deauthentication {
                reason: le16_at(body, 0),
            })
        }
        SUBTYPE_DISASSOCIATION => {
            if body.len() < 2 {
                return Err(protocol("disassociation body shorter than 2 bytes"));
            }
            Ok(FrameKind::Disassociation {
                reason: le16_at(body, 0),
            })
        }
        SUBTYPE_ASSOCIATION_REQUEST => {
            if body.len() < 4 {
                return Err(protocol("association request body shorter than 4 bytes"));
            }
            Ok(FrameKind::AssociationRequest {
                capability: le16_at(body, 0),
                listen_interval: le16_at(body, 2),
            })
        }
        SUBTYPE_ASSOCIATION_RESPONSE => {
            if body.len() < 6 {
                return Err(protocol("association response body shorter than 6 bytes"));
            }
            Ok(FrameKind::AssociationResponse {
                capability: le16_at(body, 0),
                status: le16_at(body, 2),
            })
        }
        _ => Ok(FrameKind::Management),
    }
}

fn parse_data<'a>(subtype: u8, body: &'a [u8]) -> Result<FrameKind<'a>, WifiError> {
    // Null-function and CF frames carry no body worth dissecting.
    let data_subtypes_without_body: [u8; 5] = [0x04, 0x05, 0x06, 0x07, 0x0c];
    if data_subtypes_without_body.contains(&subtype) {
        return Ok(FrameKind::Data);
    }
    // LLC/SNAP: AA AA 03 00 00 00 + 2-byte ethertype.
    if body.len() < 8 || body[0..3] != [0xaa, 0xaa, 0x03] || body[3..6] != [0x00, 0x00, 0x00] {
        return Ok(FrameKind::Data);
    }
    let ethertype = be16(body, 6);
    Ok(FrameKind::Snap {
        ethertype,
        payload: &body[8..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const AP: [u8; 6] = [0xa4, 0xb1, 0xc1, 0xd2, 0xe3, 0xf0];
    const STA: [u8; 6] = [0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f];
    const BCAST: [u8; 6] = [0xff; 6];

    fn fc(type_: u8, subtype: u8, flags: u16) -> [u8; 2] {
        (((type_ << 2) | (subtype << 4)) as u16 | flags).to_le_bytes()
    }

    fn header(
        type_: u8,
        subtype: u8,
        flags: u16,
        a1: [u8; 6],
        a2: [u8; 6],
        a3: [u8; 6],
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&fc(type_, subtype, flags));
        out.extend_from_slice(&[0x00, 0x00]); // duration
        out.extend_from_slice(&a1);
        out.extend_from_slice(&a2);
        out.extend_from_slice(&a3);
        out.extend_from_slice(&[0x10, 0x00]); // seq-ctrl
        out
    }

    fn beacon_body(ssid: &[u8], with_rsn: bool) -> Vec<u8> {
        let mut body = vec![0u8; 8]; // timestamp
        body.extend_from_slice(&100u16.to_be_bytes()); // interval
        body.extend_from_slice(&0x0411u16.to_le_bytes()); // capability
        body.push(0x00);
        body.push(ssid.len() as u8);
        body.extend_from_slice(ssid);
        if with_rsn {
            let rsn: [u8; 20] = [
                0x01, 0x00, // version 1
                0x00, 0x0f, 0xac, 0x04, // group CCMP
                0x01, 0x00, // 1 pairwise
                0x00, 0x0f, 0xac, 0x04, // CCMP
                0x01, 0x00, // 1 AKM
                0x00, 0x0f, 0xac, 0x02, // PSK
                0x00, 0x00, // capabilities
            ];
            body.push(48);
            body.push(rsn.len() as u8);
            body.extend_from_slice(&rsn);
        }
        body
    }

    #[test]
    fn beacon_parses_ssid_and_rsn_akm_suites() {
        let mut frame = header(0, SUBTYPE_BEACON, 0, BCAST, AP, AP);
        frame.extend(beacon_body(b"cyberdeck-e2e", true));
        let parsed = parse(&frame, false, false).expect("beacon parses");
        assert_eq!(parsed.frame_type, FC_TYPE_MANAGEMENT);
        assert_eq!(parsed.roles.bssid, Some(AP));
        assert_eq!(parsed.roles.source, AP);
        assert_eq!(parsed.roles.destination, BCAST);
        match parsed.kind {
            FrameKind::Beacon { ssid, rsn } => {
                assert_eq!(ssid, Some(b"cyberdeck-e2e".as_slice()));
                let rsn = rsn.expect("RSN IE present");
                assert_eq!(rsn.version, 1);
                assert!(!rsn.uses_8021x);
                assert_eq!(rsn.akm_suites, vec![[0x00, 0x0f, 0xac, 0x02]]);
            }
            other => panic!("unexpected kind {other:?}"),
        }
    }

    #[test]
    fn probe_request_and_response_parse() {
        let mut req = header(0, SUBTYPE_PROBE_REQUEST, 0, BCAST, AP, BCAST);
        req.extend([0x00, 0x04, b'a', b'b', b'c', b'd']);
        match parse(&req, false, false).expect("probe req parses").kind {
            FrameKind::ProbeRequest { ssid } => assert_eq!(ssid, Some(b"abcd".as_slice())),
            other => panic!("unexpected kind {other:?}"),
        }
        let mut resp = header(0, SUBTYPE_PROBE_RESPONSE, 0, STA, AP, AP);
        resp.extend(beacon_body(b"cyberdeck-e2e", false));
        match parse(&resp, false, false).expect("probe resp parses").kind {
            FrameKind::ProbeResponse { ssid, rsn } => {
                assert_eq!(ssid, Some(b"cyberdeck-e2e".as_slice()));
                assert!(rsn.is_none());
            }
            other => panic!("unexpected kind {other:?}"),
        }
    }

    #[test]
    fn deauth_reason_code_and_auth_fields_parse() {
        let mut deauth = header(0, SUBTYPE_DEAUTHENTICATION, 0, STA, AP, AP);
        deauth.extend(7u16.to_le_bytes());
        match parse(&deauth, false, false).expect("deauth parses").kind {
            FrameKind::Deauthentication { reason } => assert_eq!(reason, 7),
            other => panic!("unexpected kind {other:?}"),
        }
        let mut auth = header(0, SUBTYPE_AUTHENTICATION, 0, STA, AP, AP);
        auth.extend(0u16.to_le_bytes()); // open
        auth.extend(2u16.to_le_bytes()); // seq 2
        auth.extend(0u16.to_le_bytes()); // success
        match parse(&auth, false, false).expect("auth parses").kind {
            FrameKind::Authentication {
                algorithm,
                sequence,
                status,
            } => {
                assert_eq!((algorithm, sequence, status), (0, 2, 0));
            }
            other => panic!("unexpected kind {other:?}"),
        }
        let mut assoc = header(0, SUBTYPE_ASSOCIATION_RESPONSE, 0, STA, AP, AP);
        assoc.extend(0x0411u16.to_le_bytes());
        assoc.extend(0u16.to_le_bytes());
        assoc.extend(1u16.to_le_bytes()); // AID
        match parse(&assoc, false, false).expect("assoc resp parses").kind {
            FrameKind::AssociationResponse { capability, status } => {
                assert_eq!((capability, status), (0x0411, 0));
            }
            other => panic!("unexpected kind {other:?}"),
        }
    }

    #[test]
    fn data_frame_to_ds_resolves_sta_ap_roles() {
        // STA -> AP: toDS, DA=addr3, SA=addr2, BSSID=addr1.
        let mut frame = header(2, 0, 0x0100, AP, STA, AP);
        let llc: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00];
        frame.extend(llc);
        let parsed = parse(&frame, false, false).expect("data frame parses");
        assert!(parsed.to_ds && !parsed.from_ds);
        assert_eq!(parsed.roles.bssid, Some(AP));
        assert_eq!(parsed.roles.source, STA);
        assert_eq!(parsed.roles.destination, AP);
        assert!(matches!(
            parsed.kind,
            FrameKind::Snap {
                ethertype: 0x0800,
                ..
            }
        ));
    }

    #[test]
    fn data_frame_from_ds_resolves_ap_sta_roles() {
        // AP -> STA: fromDS, DA=addr1, SA=addr3, BSSID=addr2.
        let frame = header(2, 0, 0x0200, STA, AP, AP);
        let parsed = parse(&frame, false, false).expect("data frame parses");
        assert!(!parsed.to_ds && parsed.from_ds);
        assert_eq!(parsed.roles.bssid, Some(AP));
        assert_eq!(parsed.roles.source, AP);
        assert_eq!(parsed.roles.destination, STA);
    }

    #[test]
    fn qos_data_frame_carries_two_extra_bytes_and_ht_bit_adds_four() {
        // QoS data: subtype 8 with toDS; QoS control word zero (no HT).
        let mut frame = header(2, 8, 0x0100, AP, STA, AP);
        frame.extend(&[0x00, 0x00]); // QoS control, no HT present
        frame.extend(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e]);
        frame.extend(&[0x02, 0x03, 0x00, 0x10]); // short EAPOL-looking body
        let parsed = parse(&frame, false, false).expect("QoS frame parses");
        assert!(parsed.qos);
        match parsed.kind {
            FrameKind::Snap { ethertype, payload } => {
                assert_eq!(ethertype, ETHERTYPE_EAPOL);
                assert_eq!(payload, &[0x02, 0x03, 0x00, 0x10]);
            }
            other => panic!("unexpected kind {other:?}"),
        }

        // Same frame with the HT Control present bit (bit 8 of QoS control).
        let mut ht = header(2, 8, 0x0100, AP, STA, AP);
        ht.extend(&[0x00, 0x01]); // QoS control with HT present
        ht.extend(&[0x00; 4]); // HT control field
        ht.extend(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e]);
        ht.extend(&[0x02, 0x03, 0x00, 0x10]);
        let parsed_ht = parse(&ht, false, false).expect("HT QoS frame parses");
        match parsed_ht.kind {
            FrameKind::Snap { payload, .. } => assert_eq!(payload, &[0x02, 0x03, 0x00, 0x10]),
            other => panic!("unexpected kind {other:?}"),
        }
    }

    #[test]
    fn four_address_wds_frame_parses_without_bssid() {
        let mut frame = header(2, 0, 0x0300, AP, AP, STA); // RA, TA, DA
        frame.extend(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // addr4 = SA
        frame.extend(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00]);
        let parsed = parse(&frame, false, false).expect("WDS frame parses");
        assert_eq!(
            parsed.addresses.addr4,
            Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        );
        assert_eq!(parsed.roles.source, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(parsed.roles.bssid, None);
    }

    #[test]
    fn fcs_is_stripped_only_when_radiotap_says_present() {
        let mut frame = header(2, 0, 0x0100, AP, STA, AP);
        frame.extend(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e]);
        frame.extend(&[0xde, 0xad, 0xbe, 0xef]); // fake FCS
        let with_strip = parse(&frame, true, false).expect("parses with FCS strip");
        assert_eq!(with_strip.body.len(), 8);
        let without_strip = parse(&frame, false, false).expect("parses without strip");
        assert_eq!(without_strip.body.len(), 12);
    }

    #[test]
    fn data_pad_aligns_body_start_to_four_bytes() {
        // QoS data toDS header is 26 bytes; padding takes the body to 28.
        let mut frame = header(2, 8, 0x0100, AP, STA, AP);
        frame.extend(&[0x00, 0x00]); // QoS control
        frame.extend(&[0x00, 0x00]); // 2 pad bytes inserted by the chip
        frame.extend(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e]);
        let padded = parse(&frame, false, true).expect("padded frame parses");
        match padded.kind {
            FrameKind::Snap { ethertype, .. } => assert_eq!(ethertype, ETHERTYPE_EAPOL),
            other => panic!("unexpected kind {other:?}"),
        }
        // Without the flag the pad bytes break the LLC magic: honest Data.
        let unpadded = parse(&frame, false, false).expect("unpadded parse");
        assert!(matches!(unpadded.kind, FrameKind::Data));
    }

    #[test]
    fn protected_flag_and_retry_bits_surface() {
        let frame = header(2, 0, 0x4900, AP, STA, AP); // protected+retry+toDS
        let parsed = parse(&frame, false, false).expect("parses");
        assert!(parsed.protected);
        assert!(parsed.retry);
    }

    #[test]
    fn truncated_and_malformed_frames_refuse_without_panics() {
        // Sub-minimum buffers.
        for size in 0..10 {
            assert_eq!(
                parse(&vec![0xff; size], false, false).unwrap_err().code,
                WifiMonitorError::Protocol
            );
        }
        // Version 3 refuses.
        let mut bad = header(0, SUBTYPE_BEACON, 0, BCAST, AP, AP);
        bad[0] |= 0x03;
        assert_eq!(
            parse(&bad, false, false).unwrap_err().code,
            WifiMonitorError::Protocol
        );
        // Truncated beacon body.
        let mut short = header(0, SUBTYPE_BEACON, 0, BCAST, AP, AP);
        short.extend(&[0u8; 5]);
        assert_eq!(
            parse(&short, false, false).unwrap_err().code,
            WifiMonitorError::Protocol
        );
        // IE length running past the body.
        let mut bad_ie = header(0, SUBTYPE_PROBE_REQUEST, 0, BCAST, AP, BCAST);
        bad_ie.extend(&[0x00, 0xff, 1, 2, 3]);
        assert_eq!(
            parse(&bad_ie, false, false).unwrap_err().code,
            WifiMonitorError::Protocol
        );
        // FCS claimed but the frame is too short to hold header + FCS.
        let mut tiny = header(2, 0, 0x0100, AP, STA, AP);
        tiny.extend(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e]);
        tiny.truncate(26);
        assert_eq!(
            parse(&tiny, true, false).unwrap_err().code,
            WifiMonitorError::Protocol
        );
        // Every truncation of a valid frame refuses or parses without panic.
        let mut full = header(2, 8, 0x0100, AP, STA, AP);
        full.extend(&[0x00, 0x00]);
        full.extend(&[0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e]);
        full.extend(&[0x02, 0x03, 0x00, 0x10, 0x02, 0x01, 0x0a]);
        for cut in 0..full.len() {
            let _ = parse(&full[..cut], cut % 2 == 0, cut % 3 == 0);
        }
    }

    #[test]
    fn oversized_frame_refuses() {
        let frame = vec![0xff; MAX_FRAME_BYTES + 1];
        assert_eq!(
            parse(&frame, false, false).unwrap_err().code,
            WifiMonitorError::Protocol
        );
    }

    #[test]
    fn ssid_over_32_bytes_refuses() {
        let mut frame = header(0, SUBTYPE_PROBE_REQUEST, 0, BCAST, AP, BCAST);
        frame.extend(&[0x00, 33]);
        frame.extend([0x61u8; 33]);
        let err = parse(&frame, false, false).expect_err("oversized SSID refuses");
        assert_eq!(err.code, WifiMonitorError::Protocol);
    }

    #[test]
    fn control_frames_parse_minimally() {
        // ACK: fc + duration + RA only.
        let mut ack = header(1, 11, 0, AP, [0; 6], [0; 6]);
        ack.truncate(10);
        let parsed = parse(&ack, false, false).expect("ACK parses");
        assert!(matches!(parsed.kind, FrameKind::Control));
        assert_eq!(parsed.roles.receiver, AP);
    }
}
