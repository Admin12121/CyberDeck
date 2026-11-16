//! Bounded RDP dissection for TCP 3389: TPKT framing (RFC 1006 §4: version
//! 3, reserved zero, 16-bit length covering the whole frame) plus the X.224
//! (ITU-T X.224) TPDU underneath. The connection request/confirm (CR/CC)
//! TPDUs carry the MS-RDPBCGR §2.2.1.1 RDP Negotiation Request/Response —
//! requested and selected protocol flags (PROTOCOL_RDP/SSL/HYBRID/RDSTLS/
//! HYBRID_EX) and the documented negotiation failure codes. Beyond
//! negotiation the session is never decoded: X.224 data TPDUs surface the
//! honest "RDP session (NLA) — not decoded" row. One packet is one row: no
//! connection state, nothing beyond the captured segment.
//!
//! Honesty contracts, enforced everywhere below:
//! - A row claims only TPKT version 3 with a zero reserved byte plus an
//!   X.224 TPDU code in the RDP set (CR/CC/DT/DR), with the direction the
//!   port side dictates: a CR claims only client→server, a CC only
//!   server→client. The port alone is not RDP evidence.
//! - The TPKT length field is validated against the capture: a declared
//!   length beyond the capture is named ("truncated at capture boundary"),
//!   trailing bytes of a further TPKT are counted, never decoded, and a
//!   length below the X.224 minimum is refused with the raw value.
//! - X.224 data TPDUs are gated on the class-0 shape (length indicator 2,
//!   end-of-TSDU flag 0x00/0x80); the session bytes inside are never
//!   interpreted — no NLA/CredSSP structures, no decrypted content.
//! - The mstshash routing cookie is reported as presence only; negotiation
//!   protocol flags and failure codes keep the documented names or raw hex,
//!   never guesses.

use crate::Layer;

/// Negotiation structures (MS-RDPBCGR §2.2.1.1): type, flags, u16 length 8,
/// then the u32 protocol field. The scan for them stays inside this window.
const MAX_NEGOTIATION_WINDOW: usize = 256;

pub(super) struct RdpService {
    pub protocol: &'static str,
    pub info: String,
    pub layers: Vec<Layer>,
}

fn layer(label: &str, value: impl ToString) -> Layer {
    Layer {
        label: label.into(),
        value: value.to_string(),
    }
}

fn rdp_done(info: String, layers: Vec<Layer>) -> RdpService {
    RdpService {
        protocol: "RDP",
        info,
        layers,
    }
}

/// MS-RDPBCGR §2.2.1.1 protocol flags; the standard-security value 0 means
/// none of the flags are set.
fn protocol_names(protocols: u32) -> String {
    let mut names: Vec<String> = Vec::new();
    if protocols & 0x01 != 0 {
        names.push("SSL".into());
    }
    if protocols & 0x02 != 0 {
        names.push("HYBRID (CredSSP/NLA)".into());
    }
    if protocols & 0x04 != 0 {
        names.push("RDSTLS".into());
    }
    if protocols & 0x08 != 0 {
        names.push("HYBRID_EX".into());
    }
    let unknown = protocols & !0x0f;
    if unknown != 0 {
        names.push(format!("0x{unknown:08x}"));
    }
    if names.is_empty() {
        "RDP (standard security)".to_string()
    } else {
        names.join(", ")
    }
}

/// MS-RDPBCGR §2.2.1.1.1 negotiation failure codes.
fn failure_name(code: u32) -> String {
    match code {
        0x0000_0001 => "SSL_REQUIRED_BY_SERVER".into(),
        0x0000_0002 => "SSL_NOT_ALLOWED_BY_SERVER".into(),
        0x0000_0003 => "SSL_CERT_NOT_ON_SERVER".into(),
        0x0000_0004 => "INCONSISTENT_FLAGS".into(),
        0x0000_0005 => "HYBRID_REQUIRED_BY_SERVER".into(),
        0x0000_0006 => "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER".into(),
        _ => format!("0x{code:08x}"),
    }
}

/// MS-RDPBCGR §2.2.1.1.1 request flags.
fn neg_flags(flags: u8) -> String {
    let mut parts: Vec<String> = Vec::new();
    if flags & 0x01 != 0 {
        parts.push("restricted admin".into());
    }
    if flags & 0x02 != 0 {
        parts.push("redirected auth".into());
    }
    if flags & !0x03 != 0 {
        parts.push(format!("0x{:02x}", flags & !0x03));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(", ")
    }
}

/// Bounded scan for one RDP Negotiation structure inside the X.224
/// variable part: type 0x01/0x02/0x03, any flags, u16 length 8, then the
/// u32 protocol field (little-endian per MS-RDPBCGR).
fn scan_negotiation(window: &[u8], expected_type: u8) -> Option<(u8, u32)> {
    for at in 0..window.len() {
        if window[at] != expected_type
            || window.get(at + 2) != Some(&0x08)
            || window.get(at + 3) != Some(&0x00)
        {
            continue;
        }
        let bytes: [u8; 4] = window.get(at + 4..at + 8)?.try_into().ok()?;
        return Some((
            window.get(at + 1).copied().unwrap_or(0),
            u32::from_le_bytes(bytes),
        ));
    }
    None
}

fn x224_window(payload: &[u8], declared: usize) -> &[u8] {
    let end = payload.len().min(declared);
    payload.get(11..end).unwrap_or(&[])
}

/// The X.224 variable part capped to the negotiation scan bound, plus
/// whether the cap cut bytes that were never scanned.
fn negotiation_window(payload: &[u8], declared: usize) -> (&[u8], bool) {
    let window = x224_window(payload, declared);
    let capped = window.len() > MAX_NEGOTIATION_WINDOW;
    (&window[..window.len().min(MAX_NEGOTIATION_WINDOW)], capped)
}

enum Kind {
    ConnectionRequest,
    ConnectionConfirm,
    Data,
    DisconnectRequest,
}

pub(super) fn dissect(payload: &[u8], client_to_server: bool) -> Option<RdpService> {
    // TPKT header (4 bytes) + X.224 length indicator + TPDU code is the
    // minimum marker; anything shorter claims nothing.
    if payload.len() < 6 {
        return None;
    }
    if payload[0] != 3 || payload[1] != 0 {
        // RFC 1006 §4: version 3, reserved byte zero.
        return None;
    }
    let declared = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    let captured = payload.len();
    let kind = match payload[5] {
        0xE0 => {
            if !client_to_server {
                return None; // a CR travels client → server
            }
            Kind::ConnectionRequest
        }
        0xD0 => {
            if client_to_server {
                return None; // a CC travels server → client
            }
            Kind::ConnectionConfirm
        }
        0xF0 => {
            if payload.len() >= 7 && payload[6] & 0x7f != 0 {
                return None; // X.224 class 0 DT: EOT flag is 0x00 or 0x80
            }
            Kind::Data
        }
        0x50 => Kind::DisconnectRequest,
        _ => return None,
    };
    let mut layers = vec![
        layer("TPKT", format!("version 3, {declared} byte(s) declared")),
        layer(
            "X.224",
            match kind {
                Kind::ConnectionRequest => "connection request (CR)",
                Kind::ConnectionConfirm => "connection confirm (CC)",
                Kind::Data => "data (DT)",
                Kind::DisconnectRequest => "disconnect request (DR)",
            },
        ),
    ];
    let mut info = match kind {
        Kind::ConnectionRequest => "RDP connection request".to_string(),
        Kind::ConnectionConfirm => "RDP connection confirm".to_string(),
        Kind::Data => "RDP session (NLA) — not decoded".to_string(),
        Kind::DisconnectRequest => "RDP disconnect request".to_string(),
    };
    // TPKT length validation against the capture.
    let mut notes: Vec<String> = Vec::new();
    if matches!(kind, Kind::ConnectionRequest | Kind::ConnectionConfirm) && declared < 11 {
        notes.push(format!(
            "TPKT length {declared} below the 11-byte X.224 minimum"
        ));
    }
    if matches!(kind, Kind::Data | Kind::DisconnectRequest) && declared < 7 {
        notes.push(format!(
            "TPKT length {declared} below the 7-byte X.224 minimum"
        ));
    }
    if captured < declared {
        notes.push(format!(
            "truncated at capture boundary ({captured} of {declared} byte(s))"
        ));
    }
    if captured > declared {
        notes.push(format!(
            "+{} trailing byte(s) not decoded",
            captured - declared
        ));
    }
    match kind {
        Kind::ConnectionRequest => {
            if payload.len() >= 11 && payload[10] != 0 {
                layers.push(layer(
                    "RDP negotiation",
                    format!(
                        "not decoded (X.224 class {} — RDP requires class 0)",
                        payload[10]
                    ),
                ));
            } else {
                let (window, capped) = negotiation_window(payload, declared);
                if payload.len() >= 11 && find_bytes(window, b"Cookie: ") {
                    layers.push(layer("mstshash cookie", "present (value not extracted)"));
                }
                match scan_negotiation(window, 0x01) {
                    Some((flags, protocols)) => {
                        let names = protocol_names(protocols);
                        layers.push(layer(
                            "RDP negotiation",
                            format!("request, flags {}, requested {names}", neg_flags(flags)),
                        ));
                        info.push_str(&format!(", requested {names}"));
                    }
                    None => {
                        layers.push(layer(
                            "RDP negotiation",
                            if capped {
                                format!(
                                    "not decoded (negotiation beyond the {MAX_NEGOTIATION_WINDOW}-byte scan window)"
                                )
                            } else if payload.len() >= 11 {
                                "absent (standard RDP security implied)".to_string()
                            } else {
                                "not decoded (X.224 header truncated at capture boundary)"
                                    .to_string()
                            },
                        ));
                    }
                }
            }
        }
        Kind::ConnectionConfirm => {
            if payload.len() >= 11 && payload[10] != 0 {
                layers.push(layer(
                    "RDP negotiation",
                    format!(
                        "not decoded (X.224 class {} — RDP requires class 0)",
                        payload[10]
                    ),
                ));
            } else {
                let (window, capped) = negotiation_window(payload, declared);
                if let Some((flags, protocols)) = scan_negotiation(window, 0x02) {
                    let names = protocol_names(protocols);
                    layers.push(layer(
                        "RDP negotiation",
                        format!("response, flags {}, selected {names}", neg_flags(flags)),
                    ));
                    info.push_str(&format!(", selected {names}"));
                } else if let Some((_, failure)) = scan_negotiation(window, 0x03) {
                    let name = failure_name(failure);
                    layers.push(layer("RDP negotiation", format!("failure, {name}")));
                    info = format!("RDP negotiation failure, {name}");
                } else if capped {
                    layers.push(layer(
                        "RDP negotiation",
                        format!(
                            "not decoded (negotiation beyond the {MAX_NEGOTIATION_WINDOW}-byte scan window)"
                        ),
                    ));
                } else if payload.len() >= 11 {
                    layers.push(layer(
                        "RDP negotiation",
                        "no negotiation response (standard RDP security expected)".to_string(),
                    ));
                } else {
                    layers.push(layer(
                        "RDP negotiation",
                        "not decoded (X.224 header truncated at capture boundary)".to_string(),
                    ));
                }
            }
        }
        Kind::Data => {
            if payload.len() >= 5 && payload[4] != 2 {
                // X.224 class 0 data TPDUs carry length indicator 2.
                return None;
            }
            let session_bytes = captured.min(declared).saturating_sub(7);
            layers.push(layer(
                "X.224 data",
                format!(
                    "{session_bytes} session byte(s) not decoded (NLA, TLS-wrapped or standard-RDP encrypted)"
                ),
            ));
        }
        Kind::DisconnectRequest => {
            if payload.len() >= 11 {
                layers.push(layer(
                    "X.224 reason",
                    format!("0x{:02x} (not interpreted)", payload[10]),
                ));
            }
        }
    }
    if !notes.is_empty() {
        layers.push(layer("TPKT validation", notes.join("; ")));
        for note in &notes {
            info.push_str("; ");
            info.push_str(note);
        }
    }
    Some(rdp_done(info, layers))
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// X.224 CR with an RDP Negotiation Request: SSL | HYBRID (0x03).
    fn cr_with_negotiation() -> Vec<u8> {
        let mut frame = vec![3u8, 0];
        frame.extend_from_slice(&19u16.to_be_bytes()); // TPKT length
        frame.push(0x0e); // length indicator
        frame.push(0xE0); // CR
        frame.extend_from_slice(&[0, 0, 0, 0]); // dst/src refs
        frame.push(0x00); // class 0
        frame.extend_from_slice(&[0x01, 0x00, 0x08, 0x00]); // neg request
        frame.extend_from_slice(&3u32.to_le_bytes()); // SSL | HYBRID
        frame
    }

    /// X.224 CR with a mstshash cookie plus the negotiation request.
    fn cr_with_cookie() -> Vec<u8> {
        let cookie = b"Cookie: mstshash=abc\r\n";
        let length = 5 + 6 + cookie.len() + 8;
        let mut frame = vec![3u8, 0];
        frame.extend_from_slice(&(length as u16).to_be_bytes());
        frame.push((length - 5) as u8); // length indicator
        frame.push(0xE0);
        frame.extend_from_slice(&[0, 0, 0, 0]);
        frame.push(0x00);
        frame.extend_from_slice(cookie);
        frame.extend_from_slice(&[0x01, 0x00, 0x08, 0x00]);
        frame.extend_from_slice(&2u32.to_le_bytes()); // HYBRID only
        frame
    }

    /// X.224 CC with an RDP Negotiation Response selecting HYBRID.
    fn cc_with_negotiation() -> Vec<u8> {
        let mut frame = vec![3u8, 0];
        frame.extend_from_slice(&19u16.to_be_bytes());
        frame.push(0x0e);
        frame.push(0xD0); // CC
        frame.extend_from_slice(&[0, 0, 0, 0]);
        frame.push(0x00);
        frame.extend_from_slice(&[0x02, 0x00, 0x08, 0x00]); // neg response
        frame.extend_from_slice(&2u32.to_le_bytes()); // HYBRID
        frame
    }

    #[test]
    fn cr_names_requested_protocols() {
        let service = dissect(&cr_with_negotiation(), true).unwrap();
        assert_eq!(service.protocol, "RDP");
        assert_eq!(
            service.info,
            "RDP connection request, requested SSL, HYBRID (CredSSP/NLA)"
        );
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "TPKT" && l.value.contains("19 byte(s) declared")));
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "X.224" && l.value.contains("connection request")));
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "RDP negotiation" && l.value.contains("requested SSL")));

        let service = dissect(&cr_with_cookie(), true).unwrap();
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "mstshash cookie" && l.value.contains("value not extracted")));
        assert_eq!(
            service.info,
            "RDP connection request, requested HYBRID (CredSSP/NLA)"
        );

        // A CR without negotiation implies standard RDP security.
        let mut plain = cr_with_negotiation();
        plain.truncate(11);
        plain[2] = 0;
        plain[3] = 11;
        plain[4] = 6;
        let service = dissect(&plain, true).unwrap();
        assert_eq!(service.info, "RDP connection request");
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "RDP negotiation" && l.value.contains("standard RDP security")));
    }

    #[test]
    fn cc_names_selected_protocols_and_failures() {
        let service = dissect(&cc_with_negotiation(), false).unwrap();
        assert_eq!(
            service.info,
            "RDP connection confirm, selected HYBRID (CredSSP/NLA)"
        );
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "RDP negotiation" && l.value.contains("selected HYBRID")));

        let mut failure = cc_with_negotiation();
        failure[11] = 0x03; // negotiation failure
        failure[15] = 0x05; // HYBRID_REQUIRED_BY_SERVER
        let service = dissect(&failure, false).unwrap();
        assert_eq!(
            service.info,
            "RDP negotiation failure, HYBRID_REQUIRED_BY_SERVER"
        );
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "RDP negotiation" && l.value.contains("failure")));

        // An unassigned failure code keeps the raw value.
        let mut odd = cc_with_negotiation();
        odd[11] = 0x03;
        odd[15] = 0x42;
        let service = dissect(&odd, false).unwrap();
        assert!(service.info.contains("0x00000042"), "{}", service.info);

        // A CC without a negotiation response expects standard security.
        let mut plain = cc_with_negotiation();
        plain.truncate(11);
        plain[2] = 0;
        plain[3] = 11;
        plain[4] = 6;
        let service = dissect(&plain, false).unwrap();
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "RDP negotiation" && l.value.contains("no negotiation response")));
    }

    #[test]
    fn data_tpdus_surface_the_honest_session_row() {
        let mut frame = vec![3u8, 0];
        frame.extend_from_slice(&13u16.to_be_bytes());
        frame.push(2); // class 0 DT length indicator
        frame.push(0xF0); // DT
        frame.push(0x80); // end of TSDU
        frame.extend_from_slice(b"sessio");
        let service = dissect(&frame, true).unwrap();
        assert_eq!(service.info, "RDP session (NLA) — not decoded");
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "X.224 data" && l.value.contains("6 session byte(s) not decoded")));
        // DT claims in either direction.
        assert!(dissect(&frame, false).is_some());
        // A nonzero EOT flag is not an X.224 class 0 DT.
        let mut bad_eot = frame.clone();
        bad_eot[6] = 0x01;
        assert!(dissect(&bad_eot, true).is_none());
        // A length indicator other than 2 is not a class 0 DT.
        let mut bad_li = frame.clone();
        bad_li[4] = 3;
        assert!(dissect(&bad_li, true).is_none());
    }

    #[test]
    fn disconnect_request_is_named_without_interpreting() {
        let mut frame = vec![3u8, 0];
        frame.extend_from_slice(&11u16.to_be_bytes());
        frame.push(6);
        frame.push(0x50); // DR
        frame.extend_from_slice(&[0, 0, 0, 0, 0x03]);
        let service = dissect(&frame, true).unwrap();
        assert_eq!(service.info, "RDP disconnect request");
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "X.224 reason" && l.value.contains("not interpreted")));
    }

    #[test]
    fn direction_and_marker_gating_keep_the_transport_row() {
        // A CR from the server side claims nothing; a CC from the client
        // side likewise.
        assert!(dissect(&cr_with_negotiation(), false).is_none());
        assert!(dissect(&cc_with_negotiation(), true).is_none());
        // TPKT version other than 3 and a nonzero reserved byte refuse.
        let mut bad_version = cr_with_negotiation();
        bad_version[0] = 2;
        assert!(dissect(&bad_version, true).is_none());
        let mut bad_reserved = cr_with_negotiation();
        bad_reserved[1] = 1;
        assert!(dissect(&bad_reserved, true).is_none());
        // X.224 codes outside the RDP set refuse.
        let mut odd_code = cr_with_negotiation();
        odd_code[5] = 0x90;
        assert!(dissect(&odd_code, true).is_none());
        // Shorter than TPKT + LI + code claims nothing.
        assert!(dissect(&[3u8, 0, 0, 19, 14], true).is_none());
        // Random bytes keep the plain transport row.
        assert!(dissect(b"plain tcp payload", true).is_none());
    }

    #[test]
    fn tpkt_length_validation_is_honest() {
        // A declared length below the X.224 minimum is named with the raw
        // value, not silently decoded.
        let mut short = cr_with_negotiation();
        short[2] = 0;
        short[3] = 9;
        let service = dissect(&short, true).unwrap();
        assert!(
            service
                .info
                .contains("TPKT length 9 below the 11-byte X.224 minimum"),
            "{}",
            service.info
        );

        // A declared length beyond the capture states the cut.
        let mut truncated = cr_with_negotiation();
        truncated[2] = 0;
        truncated[3] = 40;
        let service = dissect(&truncated, true).unwrap();
        assert!(
            service
                .info
                .contains("truncated at capture boundary (19 of 40 byte(s))"),
            "{}",
            service.info
        );
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "TPKT validation" && l.value.contains("truncated")));

        // Bytes beyond the declared frame are counted, never decoded.
        let mut trailing = cr_with_negotiation();
        trailing.push(0xde);
        trailing.push(0xad);
        let service = dissect(&trailing, true).unwrap();
        assert!(
            service.info.contains("; +2 trailing byte(s) not decoded"),
            "{}",
            service.info
        );

        // A CR cut before the X.224 class byte degrades to the honest note.
        let cut = cr_with_negotiation()[..8].to_vec();
        let service = dissect(&cut, true).unwrap();
        assert!(service.layers.iter().any(|l| l.label == "RDP negotiation"
            && l.value.contains("header truncated at capture boundary")));
    }

    /// Truncations and adversarial byte mutations across every fixture must
    /// either refuse or produce an honest RDP row — never panic and never
    /// leave the RDP protocol name off a claimed row.
    #[test]
    fn fuzz_truncations_and_mutations_refuse_or_degrade_honestly() {
        let mut data = vec![3u8, 0];
        data.extend_from_slice(&13u16.to_be_bytes());
        data.push(2);
        data.push(0xF0);
        data.push(0x80);
        data.extend_from_slice(b"session");
        let mut dr = vec![3u8, 0];
        dr.extend_from_slice(&11u16.to_be_bytes());
        dr.push(6);
        dr.push(0x50);
        dr.extend_from_slice(&[0, 0, 0, 0, 0x03]);
        let fixtures: Vec<Vec<u8>> = vec![
            cr_with_negotiation(),
            cr_with_cookie(),
            cc_with_negotiation(),
            data,
            dr,
        ];
        let mut checked = 0usize;
        for fixture in &fixtures {
            for cut in 0..fixture.len() {
                for client_to_server in [true, false] {
                    if let Some(service) = dissect(&fixture[..cut], client_to_server) {
                        assert_eq!(service.protocol, "RDP", "cut {cut}");
                        assert!(!service.info.is_empty());
                    }
                    checked += 1;
                }
            }
            for position in (0..fixture.len()).step_by(2) {
                for value in [0x00u8, 0x01, 0x80, 0xfe, 0xff] {
                    let mut mutated = fixture.clone();
                    mutated[position] = value;
                    if let Some(service) =
                        dissect(&mutated, true).or_else(|| dissect(&mutated, false))
                    {
                        assert_eq!(
                            service.protocol, "RDP",
                            "position {position} value {value:#x}"
                        );
                    }
                    checked += 1;
                }
            }
        }
        assert!(checked > 450, "coverage too small: {checked}");
    }
}
