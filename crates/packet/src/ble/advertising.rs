//! BLE advertising-channel PDU dissection, platform-independent and fully
//! testable anywhere (BLE Core Spec 5.x, Vol 6 Part B §2.3 advertising
//! channel PDUs; AD structures per Vol 3 Part C §11 + Core Spec Supplement).
//!
//! The HCI layer (`super::hci`) hands over raw per-report fields from an
//! LE Advertising Report event; this module turns each report into an
//! honest [`ParsedAdvertisement`]: event type honored, advertiser address
//! classified (public / random-static honored, resolvable-private honestly
//! labeled as unresolved), the AD-structure walk (length + type + value)
//! with the common AD types decoded and everything else named-not-decoded.
//!
//! Honesty contracts (mirrors the wifi layer):
//! - every refusal states its reason — structural failures are coded
//!   `Protocol` errors, field-level problems are recorded verbatim in
//!   [`ParsedAdvertisement::refusals`] and never silently dropped;
//! - local names are UTF-8 validated and capped at
//!   [`MAX_LOCAL_NAME_CHARS`]; invalid or oversized names are refused with
//!   the reason in `refusals`, the rest of the report still parses;
//! - extended advertising (≤ 255-byte chains) is named-not-decoded here:
//!   this slice decodes legacy report data (≤ 31 bytes) only;
//! - service-UUID and manufacturer-ID name tables are deliberately small
//!   ("the very common set"); unknown IDs are reported raw, never guessed.
//!
//! Bounds everywhere: data ≤ 31 bytes (legacy) / ≤ 255 bytes (extended
//! chain cap), ≤ [`MAX_AD_STRUCTURES`] structures per walk, names ≤ 32
//! chars, ≤ 16 stored 16-bit UUIDs, ≤ 8 stored 128-bit UUIDs, ≤ 64 bytes
//! of manufacturer data retained (full length reported alongside).
use super::hci::RawReport;
use super::{BleError, BleErrorCode};

/// Legacy advertising data cap (BLE Core Spec: legacy ADV data ≤ 31 octets).
pub const MAX_LEGACY_DATA_BYTES: usize = 31;
/// Extended-chain cap: longer data is refused, not guessed at.
pub const MAX_EXTENDED_DATA_BYTES: usize = 255;
/// Local names over this are refused with a stated reason.
pub const MAX_LOCAL_NAME_CHARS: usize = 32;
/// The AD-structure walk refuses to follow more than this many structures.
pub const MAX_AD_STRUCTURES: usize = 32;
/// 16-bit service UUIDs stored per advertisement (deduplicated).
pub const MAX_SERVICE_UUIDS_16: usize = 16;
/// 128-bit service UUIDs stored per advertisement (deduplicated).
pub const MAX_SERVICE_UUIDS_128: usize = 8;
/// Manufacturer data bytes retained; the full length is reported alongside.
pub const MAX_MANUFACTURER_DATA_BYTES: usize = 64;
/// RSSI 0x7F means "not available" per the BLE spec (mapped to `None`).
pub const RSSI_UNAVAILABLE: i8 = 127;
/// TX power 0x7F means "unknown" per the spec (mapped to `None`).
pub const TX_POWER_UNKNOWN: i8 = 127;

// AD structure type identifiers (Common Data Format; assigned numbers).
pub const AD_TYPE_FLAGS: u8 = 0x01;
pub const AD_TYPE_UUID16_INCOMPLETE: u8 = 0x02;
pub const AD_TYPE_UUID16_COMPLETE: u8 = 0x03;
pub const AD_TYPE_UUID32_INCOMPLETE: u8 = 0x04;
pub const AD_TYPE_UUID32_COMPLETE: u8 = 0x05;
pub const AD_TYPE_UUID128_INCOMPLETE: u8 = 0x06;
pub const AD_TYPE_UUID128_COMPLETE: u8 = 0x07;
pub const AD_TYPE_SHORTENED_LOCAL_NAME: u8 = 0x08;
pub const AD_TYPE_COMPLETE_LOCAL_NAME: u8 = 0x09;
pub const AD_TYPE_TX_POWER: u8 = 0x0A;
pub const AD_TYPE_SERVICE_DATA_16: u8 = 0x16;
pub const AD_TYPE_APPEARANCE: u8 = 0x19;
pub const AD_TYPE_MANUFACTURER_DATA: u8 = 0xFF;

// Flags AD bits (Flags AD type).
pub const FLAGS_LE_LIMITED_DISCOVERABLE: u8 = 0x01;
pub const FLAGS_LE_GENERAL_DISCOVERABLE: u8 = 0x02;
pub const FLAGS_BR_EDR_NOT_SUPPORTED: u8 = 0x04;
pub const FLAGS_SIMULTANEOUS_CONTROLLER: u8 = 0x08;
pub const FLAGS_SIMULTANEOUS_HOST: u8 = 0x10;

/// Advertising PDU type from the LE Advertising Report event type byte.
/// Reserved/RFU codes are refused with a stated reason, never guessed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvEventType {
    /// 0x00: connectable, scannable, undirected.
    AdvInd,
    /// 0x01: connectable, directed (high duty cycle or low duty).
    AdvDirectInd,
    /// 0x02: scannable, undirected (formerly ADV_SCAN_IND).
    AdvScanInd,
    /// 0x03: non-connectable, non-scannable, undirected.
    AdvNonconnInd,
    /// 0x04: scan response to a scannable advertisement.
    ScanResponse,
}

impl AdvEventType {
    pub fn from_code(code: u8) -> Result<Self, BleError> {
        Ok(match code {
            0x00 => AdvEventType::AdvInd,
            0x01 => AdvEventType::AdvDirectInd,
            0x02 => AdvEventType::AdvScanInd,
            0x03 => AdvEventType::AdvNonconnInd,
            0x04 => AdvEventType::ScanResponse,
            other => {
                return Err(BleError::new(
                    BleErrorCode::Protocol,
                    format!(
                        "advertising event type 0x{other:02X} is outside the legacy report set \
                         (0x00 ADV_IND / 0x01 ADV_DIRECT_IND / 0x02 ADV_SCAN_IND / \
                         0x03 ADV_NONCONN_IND / 0x04 SCAN_RSP)"
                    ),
                ))
            }
        })
    }

    pub fn label(self) -> &'static str {
        match self {
            AdvEventType::AdvInd => "ADV_IND",
            AdvEventType::AdvDirectInd => "ADV_DIRECT_IND",
            AdvEventType::AdvScanInd => "ADV_SCAN_IND",
            AdvEventType::AdvNonconnInd => "ADV_NONCONN_IND",
            AdvEventType::ScanResponse => "SCAN_RSP",
        }
    }
}

/// Advertiser address kind. Public and random-static addresses are honored;
/// private (RPA) addresses are honestly labeled as seen-but-unresolved —
/// this slice never attempts identity resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressKind {
    /// HCI address type 0x00.
    Public,
    /// Random address with the two most significant bits set (0b11).
    RandomStatic,
    /// Random address, top bits 0b01: resolvable private — NOT resolved.
    RandomResolvablePrivate,
    /// Random address, top bits 0b00: non-resolvable private.
    RandomNonResolvablePrivate,
    /// Random address, top bits 0b10: reserved for future use per the spec.
    RandomReservedForFuture,
}

impl AddressKind {
    /// Classify from the HCI address-type byte and the 6-byte address as
    /// reported over HCI (LSB first; the top two bits of the most
    /// significant octet — `address[5]` — classify random addresses).
    pub fn classify(address_type: u8, address: &[u8; 6]) -> Result<Self, BleError> {
        Ok(match address_type {
            0x00 => AddressKind::Public,
            0x01 => match address[5] >> 6 {
                0b00 => AddressKind::RandomNonResolvablePrivate,
                0b01 => AddressKind::RandomResolvablePrivate,
                0b10 => AddressKind::RandomReservedForFuture,
                _ => AddressKind::RandomStatic,
            },
            other => {
                return Err(BleError::new(
                    BleErrorCode::Protocol,
                    format!(
                        "advertising address type 0x{other:02X} is outside the report set \
                         (0x00 public / 0x01 random)"
                    ),
                ))
            }
        })
    }

    pub fn label(self) -> &'static str {
        match self {
            AddressKind::Public => "public",
            AddressKind::RandomStatic => "random-static",
            AddressKind::RandomResolvablePrivate => "random-resolvable-private",
            AddressKind::RandomNonResolvablePrivate => "random-non-resolvable-private",
            AddressKind::RandomReservedForFuture => "random-reserved-for-future",
        }
    }

    /// The honest note carried for private addresses (identity unresolved).
    pub fn unresolved_note(self) -> Option<&'static str> {
        match self {
            AddressKind::RandomResolvablePrivate => {
                Some("resolvable private address (RPA): identity not resolved in this slice")
            }
            AddressKind::RandomNonResolvablePrivate => {
                Some("non-resolvable private address: identity not resolved")
            }
            _ => None,
        }
    }
}

/// Format an HCI-order address (bytes as reported, LSB first) in the
/// conventional MSB-first display form.
pub fn format_address(address: &[u8; 6]) -> String {
    let mut out = String::with_capacity(17);
    for index in (0..6).rev() {
        if !out.is_empty() {
            out.push(':');
        }
        out.push_str(&format!("{:02X}", address[index]));
    }
    out
}

/// One walked AD structure: the raw type byte and its value slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdStructure<'a> {
    pub ad_type: u8,
    pub payload: &'a [u8],
}

/// A decoded 16-bit service UUID with its name from the small honest table
/// (`None` = not in the table; the raw UUID is always carried).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceUuid16 {
    pub uuid: u16,
    pub name: Option<&'static str>,
}

/// Very-common 16-bit GATT/SDP service names — a deliberately small honest
/// table; anything else is reported raw, never guessed.
pub fn uuid16_name(uuid: u16) -> Option<&'static str> {
    Some(match uuid {
        0x1800 => "Generic Access",
        0x1801 => "Generic Attribute",
        0x180A => "Device Information",
        0x180D => "Heart Rate",
        0x180F => "Battery",
        0xFE2C => "Google FastPair",
        _ => return None,
    })
}

/// The ≤ 12 well-known Bluetooth SIG company identifiers this slice names;
/// any other ID is reported raw with the data bytes.
pub fn company_name(id: u16) -> Option<&'static str> {
    Some(match id {
        0x0000 => "Ericsson Technology Licensing",
        0x0001 => "Nokia Mobile Phones",
        0x0002 => "Intel Corp.",
        0x0006 => "Microsoft Corporation",
        0x004C => "Apple, Inc.",
        0x0075 => "Samsung Electronics Co. Ltd.",
        0x0087 => "Garmin International Inc.",
        0x00E0 => "Google",
        0x012D => "Sony Corporation",
        0x0131 => "Tile",
        0x02E5 => "Fitbit Inc.",
        0x038F => "Xiaomi Inc.",
        _ => return None,
    })
}

/// The name for a common AD type; unknown types are named-not-decoded with
/// the raw byte carried so the summary stays honest.
pub fn ad_type_name(ad_type: u8) -> String {
    let name = match ad_type {
        AD_TYPE_FLAGS => "Flags",
        AD_TYPE_UUID16_INCOMPLETE => "Incomplete List of 16-bit Service UUIDs",
        AD_TYPE_UUID16_COMPLETE => "Complete List of 16-bit Service UUIDs",
        AD_TYPE_UUID32_INCOMPLETE => "Incomplete List of 32-bit Service UUIDs",
        AD_TYPE_UUID32_COMPLETE => "Complete List of 32-bit Service UUIDs",
        AD_TYPE_UUID128_INCOMPLETE => "Incomplete List of 128-bit Service UUIDs",
        AD_TYPE_UUID128_COMPLETE => "Complete List of 128-bit Service UUIDs",
        AD_TYPE_SHORTENED_LOCAL_NAME => "Shortened Local Name",
        AD_TYPE_COMPLETE_LOCAL_NAME => "Complete Local Name",
        AD_TYPE_TX_POWER => "TX Power Level",
        AD_TYPE_SERVICE_DATA_16 => "Service Data - 16-bit UUID",
        AD_TYPE_APPEARANCE => "Appearance",
        AD_TYPE_MANUFACTURER_DATA => "Manufacturer Specific Data",
        _ => return format!("unknown AD type 0x{ad_type:02X} (named, not decoded)"),
    };
    name.to_string()
}

/// The parsed, honest summary of one advertising report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAdvertisement {
    pub event_type: AdvEventType,
    /// Conventional MSB-first display form.
    pub address: String,
    pub address_kind: AddressKind,
    /// Set for private addresses: identity seen but not resolved.
    pub address_note: Option<&'static str>,
    /// `None` when the report carried the spec's "unavailable" 0x7F.
    pub rssi_dbm: Option<i8>,
    pub flags: Option<u8>,
    /// Human-readable names for the set flag bits (common set only).
    pub flags_summary: Vec<&'static str>,
    pub local_name: Option<String>,
    /// True when the name came from a Shortened Local Name structure.
    pub local_name_shortened: bool,
    pub tx_power_dbm: Option<i8>,
    pub services_16: Vec<ServiceUuid16>,
    pub services_128: Vec<[u8; 16]>,
    pub manufacturer_id: Option<u16>,
    pub manufacturer_name: Option<&'static str>,
    /// Retained manufacturer-specific bytes (≤ 64; full length below).
    pub manufacturer_data: Vec<u8>,
    pub manufacturer_data_full_len: usize,
    /// Every AD structure of the walk, named (decoded ones included).
    pub ad_types_seen: Vec<String>,
    /// Every field-level refusal, each stating its reason verbatim.
    pub refusals: Vec<String>,
}

fn protocol(message: impl Into<String>) -> BleError {
    BleError::new(BleErrorCode::Protocol, message)
}

/// Walk the AD structures of an advertising data buffer: each structure is
/// one length byte + one type byte + (length-1) value bytes. A zero length
/// byte is the spec's zero padding and ends the walk. Refuses — with a
/// stated reason — truncated length fields, lengths that run past the
/// buffer, over-long data and structure-count overruns.
pub fn parse_ad_data(data: &[u8], legacy: bool) -> Result<Vec<AdStructure<'_>>, BleError> {
    if data.len() > MAX_EXTENDED_DATA_BYTES {
        return Err(protocol(format!(
            "advertising data is {} bytes, over the {}-byte extended-chain bound",
            data.len(),
            MAX_EXTENDED_DATA_BYTES
        )));
    }
    if legacy && data.len() > MAX_LEGACY_DATA_BYTES {
        return Err(protocol(format!(
            "legacy advertising data is {} bytes, over the {}-byte legacy bound",
            data.len(),
            MAX_LEGACY_DATA_BYTES
        )));
    }
    let mut structures = Vec::new();
    let mut pos = 0usize;
    while pos < data.len() {
        if structures.len() >= MAX_AD_STRUCTURES {
            return Err(protocol(format!(
                "advertising data carries more than {MAX_AD_STRUCTURES} AD structures"
            )));
        }
        let length = data[pos] as usize;
        if length == 0 {
            break; // zero padding: the spec-defined end of the structure list
        }
        let total = length + 1; // length byte + payload
        if pos + total > data.len() {
            return Err(protocol(format!(
                "AD structure length {length} at offset {pos} extends past the {}-byte buffer",
                data.len()
            )));
        }
        let body = &data[pos + 1..pos + total];
        if body.is_empty() {
            return Err(protocol(format!(
                "AD structure at offset {pos} has a length byte but no type byte"
            )));
        }
        structures.push(AdStructure {
            ad_type: body[0],
            payload: &body[1..],
        });
        pos += total;
    }
    Ok(structures)
}

/// Parse one raw LE Advertising Report entry into an honest
/// [`ParsedAdvertisement`]. Structural failures are coded errors; field
/// level problems (bad UTF-8 names, oversized names, dangling UUID bytes,
/// short manufacturer data) are recorded in `refusals` with reasons and the
/// rest of the report still parses.
pub fn parse_report(report: &RawReport) -> Result<ParsedAdvertisement, BleError> {
    let event_type = AdvEventType::from_code(report.event_type)?;
    let address_kind = AddressKind::classify(report.address_type, &report.address)?;
    let mut out = ParsedAdvertisement {
        event_type,
        address: format_address(&report.address),
        address_kind,
        address_note: address_kind.unresolved_note(),
        rssi_dbm: if report.rssi == RSSI_UNAVAILABLE {
            None
        } else {
            Some(report.rssi)
        },
        flags: None,
        flags_summary: Vec::new(),
        local_name: None,
        local_name_shortened: false,
        tx_power_dbm: None,
        services_16: Vec::new(),
        services_128: Vec::new(),
        manufacturer_id: None,
        manufacturer_name: None,
        manufacturer_data: Vec::new(),
        manufacturer_data_full_len: 0,
        ad_types_seen: Vec::new(),
        refusals: Vec::new(),
    };
    for structure in parse_ad_data(&report.data, true)? {
        out.ad_types_seen.push(ad_type_name(structure.ad_type));
        match structure.ad_type {
            AD_TYPE_FLAGS => {
                if structure.payload.len() == 1 {
                    let flags = structure.payload[0];
                    out.flags = Some(flags);
                    out.flags_summary = flags_summary(flags);
                } else {
                    out.refusals.push(format!(
                        "Flags AD structure carries {} value bytes, expected exactly 1; refused",
                        structure.payload.len()
                    ));
                }
            }
            AD_TYPE_SHORTENED_LOCAL_NAME => {
                if let Some(name) = decode_name(structure.payload, true, &mut out.refusals) {
                    out.local_name = Some(name);
                    out.local_name_shortened = true;
                }
            }
            AD_TYPE_COMPLETE_LOCAL_NAME => {
                if let Some(name) = decode_name(structure.payload, false, &mut out.refusals) {
                    out.local_name = Some(name);
                    out.local_name_shortened = false;
                }
            }
            AD_TYPE_TX_POWER => {
                if structure.payload.len() == 1 {
                    let raw = structure.payload[0] as i8;
                    out.tx_power_dbm = if raw == TX_POWER_UNKNOWN {
                        None
                    } else {
                        Some(raw)
                    };
                } else {
                    out.refusals.push(format!(
                        "TX Power AD structure carries {} value bytes, expected exactly 1; refused",
                        structure.payload.len()
                    ));
                }
            }
            AD_TYPE_UUID16_INCOMPLETE | AD_TYPE_UUID16_COMPLETE => {
                decode_uuids16(structure.payload, &mut out.services_16, &mut out.refusals);
            }
            AD_TYPE_UUID128_INCOMPLETE | AD_TYPE_UUID128_COMPLETE => {
                decode_uuids128(structure.payload, &mut out.services_128, &mut out.refusals);
            }
            AD_TYPE_MANUFACTURER_DATA => {
                decode_manufacturer(structure.payload, &mut out);
            }
            // 32-bit UUID lists, service data, appearance and anything else:
            // named above, deliberately not decoded.
            _ => {}
        }
    }
    Ok(out)
}

fn flags_summary(flags: u8) -> Vec<&'static str> {
    let mut out = Vec::new();
    if flags & FLAGS_LE_LIMITED_DISCOVERABLE != 0 {
        out.push("LE Limited Discoverable Mode");
    }
    if flags & FLAGS_LE_GENERAL_DISCOVERABLE != 0 {
        out.push("LE General Discoverable Mode");
    }
    if flags & FLAGS_BR_EDR_NOT_SUPPORTED != 0 {
        out.push("BR/EDR Not Supported");
    }
    if flags & FLAGS_SIMULTANEOUS_CONTROLLER != 0 {
        out.push("Simultaneous LE and BR/EDR (Controller)");
    }
    if flags & FLAGS_SIMULTANEOUS_HOST != 0 {
        out.push("Simultaneous LE and BR/EDR (Host)");
    }
    out
}

/// UTF-8 validate and cap a local name. Every rejection records its reason;
/// invalid or oversized names never reach the parsed output.
fn decode_name(bytes: &[u8], shortened: bool, refusals: &mut Vec<String>) -> Option<String> {
    let kind = if shortened { "shortened" } else { "complete" };
    match std::str::from_utf8(bytes) {
        Err(_) => {
            refusals.push(format!(
                "{kind} local name is not valid UTF-8 ({} bytes); refused",
                bytes.len()
            ));
            None
        }
        Ok(text) => {
            let chars = text.chars().count();
            if chars > MAX_LOCAL_NAME_CHARS {
                refusals.push(format!(
                    "{kind} local name is {chars} characters, over the \
                     {MAX_LOCAL_NAME_CHARS}-character bound; refused"
                ));
                None
            } else {
                Some(text.to_string())
            }
        }
    }
}

/// Decode a 16-bit service UUID list (little-endian pairs per spec). A
/// dangling odd byte is refused with a reason; the list is deduplicated and
/// capped, overflow stated honestly.
fn decode_uuids16(
    bytes: &[u8],
    out: &mut Vec<ServiceUuid16>,
    refusals: &mut Vec<String>,
) {
    if bytes.len() % 2 != 0 {
        refusals.push(format!(
            "16-bit service UUID list has a dangling byte after {} complete pairs; \
             the trailing byte is refused",
            bytes.len() / 2
        ));
    }
    for pair in bytes.chunks_exact(2) {
        let uuid = u16::from_le_bytes([pair[0], pair[1]]);
        if out.iter().any(|known| known.uuid == uuid) {
            continue;
        }
        if out.len() >= MAX_SERVICE_UUIDS_16 {
            refusals.push(format!(
                "16-bit service UUID list exceeds the {MAX_SERVICE_UUIDS_16}-UUID store bound; \
                 later UUIDs are dropped"
            ));
            return;
        }
        out.push(ServiceUuid16 {
            uuid,
            name: uuid16_name(uuid),
        });
    }
}

/// Decode a 128-bit service UUID list (16-byte chunks, byte order exactly
/// as transmitted). Capped with an honest overflow note.
fn decode_uuids128(bytes: &[u8], out: &mut Vec<[u8; 16]>, refusals: &mut Vec<String>) {
    if bytes.len() % 16 != 0 {
        refusals.push(format!(
            "128-bit service UUID list has {} trailing bytes after {} complete UUIDs; \
             the trailing bytes are refused",
            bytes.len() % 16,
            bytes.len() / 16
        ));
    }
    for chunk in bytes.chunks_exact(16) {
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(chunk);
        if out.contains(&uuid) {
            continue;
        }
        if out.len() >= MAX_SERVICE_UUIDS_128 {
            refusals.push(format!(
                "128-bit service UUID list exceeds the {MAX_SERVICE_UUIDS_128}-UUID store bound; \
                 later UUIDs are dropped"
            ));
            return;
        }
        out.push(uuid);
    }
}

/// Decode manufacturer-specific data: first two bytes are the SIG company
/// ID (little-endian per spec), the rest is retained up to the bound with
/// the full length reported alongside.
fn decode_manufacturer(payload: &[u8], out: &mut ParsedAdvertisement) {
    if payload.len() < 2 {
        out.refusals.push(format!(
            "Manufacturer Specific Data carries {} bytes, expected at least the 2-byte \
             company ID; refused",
            payload.len()
        ));
        return;
    }
    let id = u16::from_le_bytes([payload[0], payload[1]]);
    let rest = &payload[2..];
    out.manufacturer_id = Some(id);
    out.manufacturer_name = company_name(id);
    out.manufacturer_data_full_len = rest.len();
    let retained = rest.len().min(MAX_MANUFACTURER_DATA_BYTES);
    out.manufacturer_data = rest[..retained].to_vec();
    if rest.len() > MAX_MANUFACTURER_DATA_BYTES {
        out.refusals.push(format!(
            "manufacturer data is {} bytes; kept the first {MAX_MANUFACTURER_DATA_BYTES}",
            rest.len()
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADV_IND fixture: public address, Flags + Complete Local Name +
    /// Complete 16-bit UUID list (Battery, Device Information) + TX power +
    /// Apple manufacturer data. HCI reports the address LSB first.
    fn deck_probe_report() -> RawReport {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x02, AD_TYPE_FLAGS, 0x06]);
        data.extend_from_slice(&[0x0B, AD_TYPE_COMPLETE_LOCAL_NAME]);
        data.extend_from_slice(b"Deck Probe");
        data.extend_from_slice(&[0x05, AD_TYPE_UUID16_COMPLETE, 0x0F, 0x18, 0x0A, 0x18]);
        data.extend_from_slice(&[0x02, AD_TYPE_TX_POWER, 0xE8]); // -24 dBm
        data.extend_from_slice(&[0x05, AD_TYPE_MANUFACTURER_DATA, 0x4C, 0x00, 0x10, 0x20]);
        assert!(data.len() <= MAX_LEGACY_DATA_BYTES);
        RawReport {
            event_type: 0x00, // ADV_IND
            address_type: 0x00,
            address: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            data,
            rssi: -71i8,
        }
    }

    #[test]
    fn adv_ind_with_name_services_and_manufacturer_parses_honestly() {
        let adv = parse_report(&deck_probe_report()).expect("fixture parses");
        assert_eq!(adv.event_type, AdvEventType::AdvInd);
        assert_eq!(adv.event_type.label(), "ADV_IND");
        assert_eq!(adv.address, "66:55:44:33:22:11");
        assert_eq!(adv.address_kind, AddressKind::Public);
        assert_eq!(adv.rssi_dbm, Some(-71));
        assert_eq!(adv.local_name.as_deref(), Some("Deck Probe"));
        assert!(!adv.local_name_shortened);
        assert_eq!(adv.flags, Some(0x06));
        assert!(adv.flags_summary.contains(&"LE General Discoverable Mode"));
        assert!(adv.flags_summary.contains(&"BR/EDR Not Supported"));
        assert_eq!(adv.tx_power_dbm, Some(-24));
        let uuids: Vec<u16> = adv.services_16.iter().map(|s| s.uuid).collect();
        assert_eq!(uuids, vec![0x180F, 0x180A]);
        assert_eq!(adv.services_16[0].name, Some("Battery"));
        assert_eq!(adv.services_16[1].name, Some("Device Information"));
        assert_eq!(adv.manufacturer_id, Some(0x004C));
        assert_eq!(adv.manufacturer_name, Some("Apple, Inc."));
        assert_eq!(adv.manufacturer_data, vec![0x10, 0x20]);
        assert_eq!(adv.manufacturer_data_full_len, 2);
        assert!(adv.address_note.is_none());
        assert!(adv.refusals.is_empty(), "{:?}", adv.refusals);
        assert!(adv
            .ad_types_seen
            .iter()
            .any(|name| name == "Complete Local Name"));
    }

    #[test]
    fn scan_response_event_type_is_honored() {
        let mut report = deck_probe_report();
        report.event_type = 0x04;
        let adv = parse_report(&report).expect("scan response parses");
        assert_eq!(adv.event_type, AdvEventType::ScanResponse);
        assert_eq!(adv.event_type.label(), "SCAN_RSP");
    }

    #[test]
    fn unknown_event_types_are_refused_with_the_reason() {
        let mut report = deck_probe_report();
        report.event_type = 0x05; // RFU in the legacy report set
        let err = parse_report(&report).unwrap_err();
        assert_eq!(err.code, BleErrorCode::Protocol);
        assert!(err.message.contains("0x05"), "{}", err.message);
    }

    #[test]
    fn unknown_address_types_are_refused_with_the_reason() {
        let mut report = deck_probe_report();
        report.address_type = 0x02; // reserved for future use
        let err = parse_report(&report).unwrap_err();
        assert_eq!(err.code, BleErrorCode::Protocol);
        assert!(err.message.contains("address type"), "{}", err.message);
    }

    #[test]
    fn random_address_subtypes_are_classified_from_the_top_bits() {
        let cases = [
            (0x40, AddressKind::RandomResolvablePrivate), // top bits 01
            (0x80, AddressKind::RandomReservedForFuture), // top bits 10
            (0xC0, AddressKind::RandomStatic),            // top bits 11
            (0x1F, AddressKind::RandomNonResolvablePrivate), // top bits 00
        ];
        for (msb, expected) in cases {
            let mut report = deck_probe_report();
            report.address_type = 0x01;
            report.address = [0x01, 0x02, 0x03, 0x04, 0x05, msb];
            let adv = parse_report(&report).expect("random address parses");
            assert_eq!(adv.address_kind, expected, "msb {msb:#04x}");
            assert_eq!(adv.address_kind.label(), expected.label());
            if expected == AddressKind::RandomResolvablePrivate {
                assert_eq!(
                    adv.address_note,
                    Some("resolvable private address (RPA): identity not resolved in this slice")
                );
            }
        }
    }

    #[test]
    fn malformed_ad_length_refuses_with_offset_and_bound() {
        let mut report = deck_probe_report();
        // A tight buffer whose last structure claims a length that runs
        // past the buffer.
        report.data = vec![0x02, AD_TYPE_FLAGS, 0x06, 0x10, AD_TYPE_APPEARANCE];
        let err = parse_report(&report).unwrap_err();
        assert_eq!(err.code, BleErrorCode::Protocol);
        assert!(err.message.contains("extends past"), "{}", err.message);
    }

    #[test]
    fn legacy_data_over_31_bytes_refuses() {
        let mut report = deck_probe_report();
        report.data = vec![0x41; MAX_LEGACY_DATA_BYTES + 1];
        let err = parse_report(&report).unwrap_err();
        assert_eq!(err.code, BleErrorCode::Protocol);
        assert!(err.message.contains("legacy"), "{}", err.message);
    }

    #[test]
    fn extended_sized_data_is_accepted_up_to_the_255_byte_chain_bound() {
        // 8 x 30-byte structures = 240 bytes, inside the extended bound.
        let mut data = Vec::new();
        for _ in 0..8 {
            data.push(0x1E); // length 30: type byte + 29 value bytes
            data.push(AD_TYPE_SERVICE_DATA_16);
            data.extend_from_slice(&[0x42u8; 29]);
        }
        let structures = parse_ad_data(&data, false).expect("extended chain parses");
        assert_eq!(structures.len(), 8);
        // A ninth structure pushes the buffer over the 255-byte bound.
        let mut over = data.clone();
        over.push(0x1E);
        over.push(AD_TYPE_SERVICE_DATA_16);
        over.extend_from_slice(&[0x42u8; 29]);
        let err = parse_ad_data(&over, false).unwrap_err();
        assert!(err.message.contains("255"), "{}", err.message);
    }

    #[test]
    fn zero_padding_ends_the_walk() {
        let data = [0x02, AD_TYPE_FLAGS, 0x06, 0x00, 0x00, 0x00];
        let structures = parse_ad_data(&data, true).expect("padding ends the walk");
        assert_eq!(structures.len(), 1);
        assert_eq!(structures[0].ad_type, AD_TYPE_FLAGS);
    }

    #[test]
    fn names_over_32_chars_or_invalid_utf8_are_refused_with_reasons() {
        // The 32-character cap is a guard on top of the byte-level bounds
        // (legacy AD values can only carry 29 name bytes), so the cap itself
        // is probed through the shared decode path.
        let mut refusals = Vec::new();
        let long = "x".repeat(MAX_LOCAL_NAME_CHARS + 1);
        assert_eq!(decode_name(long.as_bytes(), false, &mut refusals), None);
        assert!(refusals.iter().any(|r| r.contains("33 characters")));
        let mut refusals = Vec::new();
        assert_eq!(
            decode_name("ok".repeat(MAX_LOCAL_NAME_CHARS / 2).as_bytes(), false, &mut refusals),
            Some("ok".repeat(MAX_LOCAL_NAME_CHARS / 2))
        );
        assert!(refusals.is_empty());
        // Invalid UTF-8 is likewise refused with a reason, not lossy-guessed,
        // through the full report path.
        let mut bad = deck_probe_report();
        bad.data = vec![0x03, AD_TYPE_COMPLETE_LOCAL_NAME, 0xFF, 0xFE];
        let adv = parse_report(&bad).expect("walk succeeds");
        assert_eq!(adv.local_name, None);
        assert!(adv.refusals.iter().any(|r| r.contains("not valid UTF-8")));
    }

    #[test]
    fn rssi_127_is_the_spec_unavailable_marker() {
        let mut report = deck_probe_report();
        report.rssi = RSSI_UNAVAILABLE;
        let adv = parse_report(&report).expect("parses");
        assert_eq!(adv.rssi_dbm, None);
    }

    #[test]
    fn dangling_uuid_bytes_and_short_manufacturer_data_are_refused_with_reasons() {
        let mut report = deck_probe_report();
        report.data = Vec::new();
        // Three bytes for a 16-bit list: one dangling byte.
        report
            .data
            .extend_from_slice(&[0x04, AD_TYPE_UUID16_COMPLETE, 0x0F, 0x18, 0x00]);
        // Manufacturer data with only one byte past nothing: < 2 bytes total.
        report.data.extend_from_slice(&[0x02, AD_TYPE_MANUFACTURER_DATA, 0x4C]);
        let adv = parse_report(&report).expect("walk succeeds");
        assert!(adv.refusals.iter().any(|r| r.contains("dangling byte")));
        assert!(adv
            .refusals
            .iter()
            .any(|r| r.contains("expected at least the 2-byte company ID")));
        assert_eq!(adv.manufacturer_id, None);
        assert_eq!(adv.services_16.len(), 1);
    }

    #[test]
    fn oversized_manufacturer_data_is_truncated_with_an_honest_note() {
        // The 64-byte retention cap sits above what a legacy report can
        // carry, so it is probed through the shared decode path with a
        // 74-byte manufacturer payload.
        let mut adv = ParsedAdvertisement {
            event_type: AdvEventType::AdvInd,
            address: "00:00:00:00:00:01".into(),
            address_kind: AddressKind::Public,
            address_note: None,
            rssi_dbm: None,
            flags: None,
            flags_summary: Vec::new(),
            local_name: None,
            local_name_shortened: false,
            tx_power_dbm: None,
            services_16: Vec::new(),
            services_128: Vec::new(),
            manufacturer_id: None,
            manufacturer_name: None,
            manufacturer_data: Vec::new(),
            manufacturer_data_full_len: 0,
            ad_types_seen: Vec::new(),
            refusals: Vec::new(),
        };
        let mut payload = 0x00E0u16.to_le_bytes().to_vec();
        payload.extend_from_slice(&[0x5Au8; MAX_MANUFACTURER_DATA_BYTES + 8]);
        decode_manufacturer(&payload, &mut adv);
        assert_eq!(adv.manufacturer_id, Some(0x00E0));
        assert_eq!(adv.manufacturer_name, Some("Google"));
        assert_eq!(adv.manufacturer_data.len(), MAX_MANUFACTURER_DATA_BYTES);
        assert_eq!(
            adv.manufacturer_data_full_len,
            MAX_MANUFACTURER_DATA_BYTES + 8
        );
        assert!(adv.refusals.iter().any(|r| r.contains("kept the first")));
    }

    #[test]
    fn small_honest_name_tables_cover_the_common_set_only() {
        assert_eq!(uuid16_name(0x180F), Some("Battery"));
        assert_eq!(uuid16_name(0x180A), Some("Device Information"));
        assert_eq!(uuid16_name(0xFE2C), Some("Google FastPair"));
        assert_eq!(uuid16_name(0xFFFF), None);
        assert_eq!(company_name(0x004C), Some("Apple, Inc."));
        assert_eq!(company_name(0x00E0), Some("Google"));
        assert_eq!(company_name(0x004D), None);
        assert_eq!(ad_type_name(0xFF), "Manufacturer Specific Data");
        assert_eq!(ad_type_name(0x99), "unknown AD type 0x99 (named, not decoded)");
    }

    #[test]
    fn truncated_ad_data_never_panics_or_overshoots() {
        let full = deck_probe_report();
        for cut in 0..=full.data.len() {
            let mut report = full.clone();
            report.data = full.data[..cut].to_vec();
            // Either an honest refusal or an honest parse; never a panic and
            // never more structures than the data can hold.
            match parse_report(&report) {
                Ok(adv) => assert!(adv.ad_types_seen.len() <= MAX_AD_STRUCTURES),
                Err(err) => assert_eq!(err.code, BleErrorCode::Protocol),
            }
        }
    }
}
