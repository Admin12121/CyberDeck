//! Bounded MQTT 3.1/3.1.1/5.0 dissection for TCP 1883, plus the honest TLS
//! hand-off for TLS-wrapped MQTT on 8883 (the transport hook surfaces that
//! note; this module never sees encrypted bytes). Fixed headers are decoded
//! per the OASIS MQTT standards: MQTT 3.1.1 §2.2 (fixed header: type
//! 1-14, flags nibble), §2.3.1 (Remaining Length varint, 1-4 bytes),
//! §3.1.2 (CONNECT protocol name "MQTT"/"MQIsdp" and level), §3.3.1
//! (PUBLISH topic, QoS, RETAIN); MQTT 5.0 §3.1.3 (property block, skipped
//! and named). One packet is one row: no session state, no subscription
//! pairing, nothing beyond the captured segment.
//!
//! Honesty contracts, enforced everywhere below:
//! - Only a complete, legal-shaped message claims an MQTT row: a fixed
//!   header whose type is 1-14 and whose flags nibble is legal for that
//!   type (reserved bits zero, the spec-mandated 0b0010 for
//!   PUBREL/SUBSCRIBE/UNSUBSCRIBE, QoS 3 refused), a complete
//!   remaining-length varint, and the declared bytes within the capture.
//!   MQTT has no magic marker, so a message cut by a capture boundary is a
//!   stream position, not evidence — it claims nothing, and a bare type
//!   byte claims nothing; the port alone is not MQTT evidence.
//! - Strings are UTF-8 validated and capped; beyond a cap the row says so
//!   instead of printing unbounded bytes.
//! - CONNECT decodes only the bounded variable header and the client
//!   identifier; will payloads, usernames, passwords and 5.0 properties are
//!   never interpreted.
//! - Bytes of a further message pipelined into the same segment are
//!   counted, never decoded; malformed bodies degrade to an honest MQTT
//!   row with exactly what the captured bytes support, never a fabricated
//!   field.

use crate::Layer;

/// Topics, protocol names and client identifiers are shown up to this many
/// characters (MQTT allows more; beyond the bound the row says so instead).
const MAX_TOPIC_CHARS: usize = 128;
const MAX_PROTOCOL_NAME_CHARS: usize = 32;
const MAX_CLIENT_ID_CHARS: usize = 128;
/// The Remaining Length varint is exactly 1-4 bytes (MQTT 3.1.1 §2.3.1).
const MAX_VARINT_BYTES: usize = 4;

pub(super) struct MqttService {
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

fn be16(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        data.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn mqtt_done(info: String, layers: Vec<Layer>) -> MqttService {
    MqttService {
        protocol: "MQTT",
        info,
        layers,
    }
}

fn mqtt_type_name(kind: u8) -> Option<&'static str> {
    Some(match kind {
        1 => "CONNECT",
        2 => "CONNACK",
        3 => "PUBLISH",
        4 => "PUBACK",
        5 => "PUBREC",
        6 => "PUBREL",
        7 => "PUBCOMP",
        8 => "SUBSCRIBE",
        9 => "SUBACK",
        10 => "UNSUBSCRIBE",
        11 => "UNSUBACK",
        12 => "PINGREQ",
        13 => "PINGRESP",
        14 => "DISCONNECT",
        _ => return None,
    })
}

/// Legal fixed-header flags nibble per packet type (MQTT 3.1.1 §2.2.2):
/// reserved flags must be zero except PUBREL/SUBSCRIBE/UNSUBSCRIBE, which
/// mandate exactly 0b0010; PUBLISH carries DUP/QoS/RETAIN and QoS 3 is
/// reserved. This table is the MQTT marker — the port is not evidence.
fn fixed_flags_are_valid(kind: u8, flags: u8) -> bool {
    match kind {
        3 => (flags & 0x06) != 0x06,
        6 | 8 | 10 => flags == 0x02,
        _ => flags == 0,
    }
}

/// Remaining Length varint (MQTT 3.1.1 §2.3.1): 1-4 bytes, 7 bits each,
/// continuation in the high bit. Returns (value, varint byte count); None
/// when truncated mid-varint or malformed beyond 4 bytes.
fn remaining_length(data: &[u8]) -> Option<(usize, usize)> {
    let mut value = 0usize;
    let mut multiplier = 1usize;
    for index in 0..MAX_VARINT_BYTES {
        let byte = *data.get(index)?;
        value += usize::from(byte & 0x7f) * multiplier;
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
        multiplier *= 128;
    }
    None
}

/// UTF-8 string decode with a character cap and a control-character
/// refusal, like the SMB share-name discipline. `what` names the field in
/// the refusal reason.
fn utf8_bounded(bytes: &[u8], cap: usize, what: &str) -> Result<String, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| format!("{what} is not valid UTF-8"))?;
    let chars = text.chars().count();
    if chars > cap {
        return Err(format!("{what} exceeds the {cap}-character bound"));
    }
    if text.chars().any(|c| c.is_control()) {
        return Err(format!("{what} contains control characters"));
    }
    Ok(text.to_string())
}

fn truncated_reason() -> &'static str {
    "malformed body"
}

/// CONNECT variable header and payload (MQTT 3.1.1 §3.1, MQTT 5.0 §3.1):
/// protocol name, level, connect flags, keepalive, the 5.0 property block
/// (skipped and named, never interpreted), then the client identifier.
/// Returns the info detail; every step that stops early says why.
fn connect_summary(body: &[u8], layers: &mut Vec<Layer>) -> String {
    let reason = truncated_reason();
    let mut detail = String::new();
    let Some(name_len) = be16(body, 0) else {
        layers.push(layer("protocol name", format!("not decoded ({reason})")));
        return detail;
    };
    let name_bytes = match body.get(2..2 + name_len as usize) {
        Some(bytes) => bytes,
        None => {
            layers.push(layer("protocol name", format!("not decoded ({reason})")));
            return detail;
        }
    };
    let name = match utf8_bounded(name_bytes, MAX_PROTOCOL_NAME_CHARS, "protocol name") {
        Ok(name) => name,
        Err(reason) => {
            layers.push(layer("protocol name", format!("not decoded ({reason})")));
            return detail;
        }
    };
    if name != "MQTT" && name != "MQIsdp" {
        // MQTT 3.1.1 §3.1.2: servers must close the connection on any other
        // protocol name. The raw name is surfaced; nothing deeper is decoded.
        layers.push(layer(
            "protocol name",
            format!("\"{name}\" (not the MQTT 3.1.1/5.0 marker name)"),
        ));
        detail.push_str(&format!("protocol name \"{name}\""));
        return detail;
    }
    let Some(&level) = body.get(2 + name_len as usize) else {
        layers.push(layer("protocol level", format!("not decoded ({reason})")));
        return detail;
    };
    let label = match (name.as_str(), level) {
        ("MQTT", 4) => "MQTT 3.1.1".to_string(),
        ("MQTT", 5) => "MQTT 5.0".to_string(),
        ("MQIsdp", 3) => "MQTT 3.1".to_string(),
        _ => {
            layers.push(layer(
                "protocol level",
                format!("{level} (unexpected for name \"{name}\")"),
            ));
            format!("protocol level {level}")
        }
    };
    if !label.is_empty() {
        layers.push(layer("protocol level", label.clone()));
        detail.push_str(&label);
    }
    let mut at = 3 + name_len as usize;
    let Some(&connect_flags) = body.get(at) else {
        layers.push(layer("connect flags", format!("not decoded ({reason})")));
        return detail;
    };
    at += 1;
    if connect_flags & 0x01 != 0 {
        layers.push(layer(
            "connect flags",
            "reserved flag bit set (malformed per MQTT 3.1.1 §3.1.2.3)",
        ));
    }
    let flags_summary = connect_flags_summary(connect_flags);
    if !flags_summary.is_empty() {
        layers.push(layer("connect flags", flags_summary));
    }
    let Some(keepalive) = be16(body, at) else {
        layers.push(layer("keepalive", format!("not decoded ({reason})")));
        return detail;
    };
    at += 2;
    layers.push(layer("keepalive", format!("{keepalive}s")));
    detail.push_str(&format!(", keepalive {keepalive}s"));
    if level == 5 {
        // MQTT 5.0 §3.1.3.2.1 property block: skipped and named, the
        // properties themselves are never interpreted.
        match remaining_length(body.get(at..).unwrap_or(&[])) {
            Some((prop_len, prop_bytes)) => {
                at += prop_bytes;
                if at
                    .checked_add(prop_len)
                    .map_or(true, |end| end > body.len())
                {
                    layers.push(layer(
                        "MQTT 5.0 properties",
                        format!("declared {prop_len} byte(s), truncated at capture boundary; client id not decoded"),
                    ));
                    return detail;
                }
                if prop_len == 0 {
                    layers.push(layer("MQTT 5.0 properties", "absent"));
                } else {
                    layers.push(layer(
                        "MQTT 5.0 properties",
                        format!("{prop_len} byte(s) present (not decoded)"),
                    ));
                }
                at += prop_len;
            }
            None => {
                layers.push(layer(
                    "MQTT 5.0 properties",
                    format!("not decoded ({reason}); client id not decoded"),
                ));
                return detail;
            }
        }
    }
    let Some(client_len) = be16(body, at) else {
        layers.push(layer("client id", format!("not decoded ({reason})")));
        return detail;
    };
    let client_bytes = body
        .get(
            at + 2
                ..at.checked_add(2 + client_len as usize)
                    .unwrap_or(usize::MAX),
        )
        .unwrap_or(&[]);
    if client_bytes.len() != client_len as usize {
        layers.push(layer(
            "client id",
            format!("present, {client_len} byte(s) (not decoded ({reason}))"),
        ));
        return detail;
    }
    if client_len == 0 {
        layers.push(layer("client id", "absent (server-assigned)"));
        return detail;
    }
    match utf8_bounded(client_bytes, MAX_CLIENT_ID_CHARS, "client id") {
        Ok(id) => {
            layers.push(layer("client id", format!("\"{id}\"")));
            detail.push_str(&format!(", client-id \"{id}\""));
        }
        Err(reason) => {
            layers.push(layer(
                "client id",
                format!("present, {client_len} byte(s) (not decoded ({reason}))"),
            ));
        }
    }
    detail
}

fn connect_flags_summary(flags: u8) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if flags & 0x02 != 0 {
        parts.push("clean session");
    }
    if flags & 0x04 != 0 {
        parts.push("will");
    }
    if (flags >> 3) & 3 == 3 && flags & 0x04 != 0 {
        parts.push("will QoS 3 (reserved)");
    }
    if flags & 0x20 != 0 {
        parts.push("will retain");
    }
    if flags & 0x40 != 0 {
        parts.push("password");
    }
    if flags & 0x80 != 0 {
        parts.push("username");
    }
    parts.join(", ")
}

/// PUBLISH (MQTT 3.1.1 §3.3.1): bounded topic extraction, QoS bits, RETAIN
/// and DUP flags, and the packet id for QoS > 0. The payload bytes of the
/// message are never decoded.
fn publish_summary(body: &[u8], flags: u8, layers: &mut Vec<Layer>) -> String {
    let reason = truncated_reason();
    let qos = (flags >> 1) & 3;
    let mut detail = format!("QoS {qos}");
    if flags & 0x01 != 0 {
        detail.push_str(", retained");
    }
    if flags & 0x08 != 0 {
        layers.push(layer("PUBLISH dup", "duplicate delivery flag set"));
    }
    let Some(topic_len) = be16(body, 0) else {
        layers.push(layer("topic", format!("not decoded ({reason})")));
        return detail;
    };
    let topic_bytes = &body.get(2..2 + topic_len as usize).unwrap_or(&[])[..];
    if topic_bytes.len() != topic_len as usize {
        layers.push(layer(
            "topic",
            format!("declared {topic_len} byte(s), not decoded ({reason})"),
        ));
        return detail;
    }
    match utf8_bounded(topic_bytes, MAX_TOPIC_CHARS, "topic") {
        Ok(topic) => {
            layers.push(layer("topic", format!("\"{topic}\"")));
            detail.insert_str(0, &format!("topic \"{topic}\", "));
        }
        Err(reason) => {
            layers.push(layer("topic", format!("not decoded ({reason})")));
        }
    }
    if qos > 0 {
        match be16(body, 2 + topic_len as usize) {
            Some(packet_id) => layers.push(layer("packet id", packet_id)),
            None => layers.push(layer("packet id", format!("not decoded ({reason})"))),
        }
    }
    detail
}

/// Documented 3.1.1 CONNACK return codes (§3.2.2.3); MQTT 5.0 shares the
/// accepted code 0x00 and keeps reason codes elsewhere, so anything above
/// the 3.1.1 table stays raw rather than guessed.
fn connack_code_name(code: u8) -> String {
    match code {
        0 => "connection accepted".into(),
        1 => "unacceptable protocol version".into(),
        2 => "identifier rejected".into(),
        3 => "server unavailable".into(),
        4 => "bad user name or password".into(),
        5 => "not authorized".into(),
        _ => format!("0x{code:02x}"),
    }
}

fn connack_summary(body: &[u8], layers: &mut Vec<Layer>) -> String {
    let reason = truncated_reason();
    match body.first() {
        Some(&ack_flags) => layers.push(layer(
            "session present",
            if ack_flags & 0x01 != 0 {
                "true"
            } else {
                "false"
            },
        )),
        None => {
            layers.push(layer("session present", format!("not decoded ({reason})")));
            return String::new();
        }
    }
    match body.get(1) {
        Some(&code) => {
            let name = connack_code_name(code);
            layers.push(layer("return code", name.clone()));
            if code == 0 {
                name
            } else {
                format!("return code {name}")
            }
        }
        None => {
            layers.push(layer("return code", format!("not decoded ({reason})")));
            String::new()
        }
    }
}

pub(super) fn dissect(payload: &[u8]) -> Option<MqttService> {
    let header = *payload.first()?;
    let kind = header >> 4;
    let flags = header & 0x0f;
    let kind_name = mqtt_type_name(kind)?;
    if !fixed_flags_are_valid(kind, flags) {
        return None;
    }
    let (declared, varint_bytes) = remaining_length(payload.get(1..)?)?;
    let captured = payload.len().saturating_sub(1 + varint_bytes);
    // MQTT has no magic marker: a message whose declared bytes run past the
    // capture is a stream cut, not evidence — it claims nothing rather than
    // guessing at an unverifiable stream position.
    if declared > captured {
        return None;
    }
    let mut layers = vec![
        layer("MQTT packet", kind_name),
        layer(
            "MQTT fixed header",
            format!("flags 0x{flags:02x}, remaining length {declared} byte(s)"),
        ),
    ];
    if captured > declared {
        layers.push(layer(
            "MQTT trailing bytes",
            format!("{} trailing byte(s) not decoded", captured - declared),
        ));
    }
    let body = &payload[1 + varint_bytes..1 + varint_bytes + declared];
    let mut info = format!("MQTT {kind_name}");
    let detail = match kind {
        1 => connect_summary(body, &mut layers),
        2 => connack_summary(body, &mut layers),
        3 => publish_summary(body, flags, &mut layers),
        4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 => {
            match be16(body, 0) {
                Some(packet_id) => layers.push(layer("packet id", packet_id)),
                None if declared > 0 => layers.push(layer(
                    "packet id",
                    format!("not decoded ({})", truncated_reason()),
                )),
                None => {}
            }
            String::new()
        }
        14 => {
            if let Some(&reason_code) = body.first() {
                layers.push(layer("reason code", format!("0x{reason_code:02x}")));
            } else if declared > 0 {
                layers.push(layer(
                    "reason code",
                    format!("not decoded ({})", truncated_reason()),
                ));
            }
            String::new()
        }
        _ => String::new(),
    };
    if !detail.is_empty() {
        info.push_str(", ");
        info.push_str(&detail);
    }
    Some(mqtt_done(info, layers))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mqtt_string(value: &str) -> Vec<u8> {
        let mut out = (value.len() as u16).to_be_bytes().to_vec();
        out.extend_from_slice(value.as_bytes());
        out
    }

    fn connect(level: u8, client_id: &str, properties: &[u8]) -> Vec<u8> {
        let mut body = mqtt_string("MQTT");
        body.push(level);
        body.push(0x02); // clean session
        body.extend_from_slice(&60u16.to_be_bytes());
        body.extend_from_slice(properties);
        body.extend_from_slice(&mqtt_string(client_id));
        let mut packet = vec![0x10u8];
        push_remaining_length(&mut packet, body.len());
        packet.extend_from_slice(&body);
        packet
    }

    fn push_remaining_length(packet: &mut Vec<u8>, length: usize) {
        let mut value = length;
        loop {
            let mut byte = (value % 128) as u8;
            value /= 128;
            if value > 0 {
                byte |= 0x80;
            }
            packet.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    fn publish(topic: &str, qos_flags: u8, packet_id: Option<u16>) -> Vec<u8> {
        let mut body = mqtt_string(topic);
        if let Some(id) = packet_id {
            body.extend_from_slice(&id.to_be_bytes());
        }
        let mut packet = vec![0x30u8 | qos_flags];
        push_remaining_length(&mut packet, body.len());
        packet.extend_from_slice(&body);
        packet
    }

    #[test]
    fn mqtt_connect_decodes_level_keepalive_and_client_id() {
        let service = dissect(&connect(4, "sensor-1", &[])).unwrap();
        assert_eq!(service.protocol, "MQTT");
        assert_eq!(
            service.info,
            "MQTT CONNECT, MQTT 3.1.1, keepalive 60s, client-id \"sensor-1\""
        );
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "MQTT packet" && l.value == "CONNECT"));
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "connect flags" && l.value == "clean session"));
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "client id" && l.value == "\"sensor-1\""));
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "MQTT fixed header" && l.value.contains("remaining length")));
    }

    #[test]
    fn mqtt5_connect_skips_properties_and_names_level() {
        // 5.0 property block of 5 bytes (e.g. session expiry) is skipped and
        // named, never interpreted; the client id after it still decodes.
        let properties = [5u8, 0x11, 0x00, 0x00, 0x27, 0x30];
        let service = dissect(&connect(5, "dev-1", &properties)).unwrap();
        assert_eq!(
            service.info,
            "MQTT CONNECT, MQTT 5.0, keepalive 60s, client-id \"dev-1\""
        );
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "MQTT 5.0 properties"
                && l.value.contains("5 byte(s) present (not decoded)")));
    }

    #[test]
    fn mqtt_connect_with_wrong_protocol_name_refuses_to_go_deeper() {
        let mut body = mqtt_string("WRAP");
        body.push(4);
        body.push(0);
        body.extend_from_slice(&60u16.to_be_bytes());
        let mut packet = vec![0x10u8];
        push_remaining_length(&mut packet, body.len());
        packet.extend_from_slice(&body);
        let service = dissect(&packet).unwrap();
        assert!(service.layers.iter().any(|l| l.label == "protocol name"
            && l.value.contains("not the MQTT 3.1.1/5.0 marker name")));
        assert!(!service.layers.iter().any(|l| l.label == "keepalive"));
    }

    #[test]
    fn mqtt_publish_extracts_bounded_topic_qos_and_retain() {
        let packet = publish("sensor/temp", 0x03, Some(0x002A)); // QoS 1 + retain
        let service = dissect(&packet).unwrap();
        assert_eq!(
            service.info,
            "MQTT PUBLISH, topic \"sensor/temp\", QoS 1, retained"
        );
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "topic" && l.value == "\"sensor/temp\""));
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "packet id" && l.value == "42"));
    }

    #[test]
    fn mqtt_publish_qos0_has_no_packet_id_and_dup_is_named() {
        let packet = publish("a/b", 0x08, None); // DUP set, QoS 0
        let service = dissect(&packet).unwrap();
        assert_eq!(service.info, "MQTT PUBLISH, topic \"a/b\", QoS 0");
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "PUBLISH dup" && l.value.contains("duplicate")));
        assert!(!service.layers.iter().any(|l| l.label == "packet id"));
    }

    #[test]
    fn oversized_or_invalid_topics_refuse_not_guess() {
        let long = "x".repeat(200);
        let service = dissect(&publish(&long, 0, None)).unwrap();
        let topic = service.layers.iter().find(|l| l.label == "topic").unwrap();
        assert!(
            topic.value.contains("128-character bound"),
            "{}",
            topic.value
        );

        // Invalid UTF-8 in the topic bytes is named, not rendered.
        let mut bad = publish("ok", 0, None);
        let at = bad.len() - 1;
        bad[at] = 0xff;
        let service = dissect(&bad).unwrap();
        let topic = service.layers.iter().find(|l| l.label == "topic").unwrap();
        assert!(topic.value.contains("not valid UTF-8"), "{}", topic.value);
    }

    #[test]
    fn mqtt_connack_names_return_codes_and_session_present() {
        let mut ack = vec![0x20u8, 0x02, 0x01, 0x00];
        let service = dissect(&ack).unwrap();
        assert_eq!(service.info, "MQTT CONNACK, connection accepted");
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "session present" && l.value == "true"));
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "return code" && l.value == "connection accepted"));

        ack[2] = 0;
        ack[3] = 2;
        let service = dissect(&ack).unwrap();
        assert_eq!(
            service.info,
            "MQTT CONNACK, return code identifier rejected"
        );

        // Codes outside the 3.1.1 table keep the raw value.
        ack[3] = 0x81;
        let service = dissect(&ack).unwrap();
        assert!(service.info.contains("0x81"), "{}", service.info);
    }

    #[test]
    fn mqtt_header_only_rows_and_disconnect_reason() {
        let service = dissect(&[0xC0u8, 0x00]).unwrap(); // PINGREQ
        assert_eq!(service.info, "MQTT PINGREQ");
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "MQTT packet" && l.value == "PINGREQ"));

        let service = dissect(&[0xD0u8, 0x00]).unwrap(); // PINGRESP
        assert_eq!(service.info, "MQTT PINGRESP");

        // MQTT 5.0 DISCONNECT carries a reason code; it stays raw hex.
        let service = dissect(&[0xE0u8, 0x01, 0x00]).unwrap();
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "reason code" && l.value == "0x00"));

        // PUBACK reports the packet id.
        let service = dissect(&[0x40u8, 0x02, 0x00, 0x07]).unwrap();
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "packet id" && l.value == "7"));
    }

    #[test]
    fn marker_gating_refuses_bad_types_flags_and_varints() {
        // Type 0 and type 15 are reserved.
        assert!(dissect(&[0x00, 0x00]).is_none());
        assert!(dissect(&[0xF0, 0x00]).is_none());
        // CONNECT with a nonzero flags nibble is not a marker.
        assert!(dissect(&[0x11, 0x00]).is_none());
        // SUBSCRIBE without the mandated 0b0010 nibble is not a marker.
        assert!(dissect(&[0x80, 0x00]).is_none());
        // PUBLISH with reserved QoS 3 is not a marker.
        assert!(dissect(&[0x36, 0x00]).is_none());
        // A bare type byte claims nothing; a varint cut by the capture
        // boundary claims nothing either.
        assert!(dissect(&[0x10]).is_none());
        assert!(dissect(&[0x10, 0x80]).is_none());
        // A varint malformed beyond 4 bytes claims nothing.
        assert!(dissect(&[0x10, 0xff, 0xff, 0xff, 0xff, 0x01]).is_none());
        // Random bytes keep the plain transport row.
        assert!(dissect(b"plain tcp payload").is_none());
    }

    #[test]
    fn capture_cuts_refuse_and_malformed_bodies_degrade_honestly() {
        let full = connect(4, "sensor-1", &[]);
        // A message cut by the capture boundary is a stream position, not
        // evidence: it claims nothing.
        for cut in [4usize, 8, 14, full.len() - 1] {
            assert!(
                dissect(&full[..cut.min(full.len())]).is_none(),
                "cut {cut}: truncated streams must refuse"
            );
        }
        // A declared length beyond the captured bytes claims nothing.
        assert!(dissect(&[0x10, 0x20]).is_none());

        // A complete CONNECT whose body is too short for its fields names
        // the packet and refuses the fields instead of inventing them.
        let service = dissect(&[0x10, 0x01, 0x00]).unwrap();
        assert_eq!(service.info, "MQTT CONNECT");
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "protocol name" && l.value.contains("not decoded")));

        // A declared client-id that overruns the body is refused.
        let mut overruns = connect(4, "sensor-1", &[]);
        overruns[13] = 0x40; // client-id length claims 64 bytes
        let service = dissect(&overruns).unwrap();
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "client id" && l.value.contains("not decoded")));
    }

    #[test]
    fn mqtt_trailing_bytes_after_the_first_message_are_counted() {
        let mut pipelined = publish("a/b", 0, None);
        pipelined.push(0xC0);
        pipelined.push(0x00);
        let service = dissect(&pipelined).unwrap();
        assert_eq!(service.info, "MQTT PUBLISH, topic \"a/b\", QoS 0");
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "MQTT trailing bytes" && l.value.contains("2 trailing")));
    }

    /// Truncations and adversarial byte mutations across every fixture must
    /// either refuse or produce an honest MQTT row — never panic and never
    /// leave the MQTT protocol name off a claimed row.
    #[test]
    fn fuzz_truncations_and_mutations_refuse_or_degrade_honestly() {
        let fixtures: Vec<Vec<u8>> = vec![
            connect(4, "sensor-1", &[]),
            connect(5, "dev-1", &[5u8, 0x11, 0, 0, 0x27, 0x30]),
            publish("sensor/temp", 0x03, Some(0x002A)),
            publish("a/b", 0x08, None),
            vec![0x20, 0x02, 0x01, 0x00],
            vec![0xC0, 0x00],
            vec![0xE0, 0x01, 0x00],
            vec![0x82, 0x02, 0x00, 0x05],
        ];
        let mut checked = 0usize;
        for fixture in &fixtures {
            for cut in 0..fixture.len() {
                if let Some(service) = dissect(&fixture[..cut]) {
                    assert_eq!(service.protocol, "MQTT", "cut {cut}");
                    assert!(!service.info.is_empty());
                }
                checked += 1;
            }
            for position in (0..fixture.len()).step_by(2) {
                for value in [0x00u8, 0x01, 0x80, 0xfe, 0xff] {
                    let mut mutated = fixture.clone();
                    mutated[position] = value;
                    if let Some(service) = dissect(&mutated) {
                        assert_eq!(
                            service.protocol, "MQTT",
                            "position {position} value {value:#x}"
                        );
                    }
                    checked += 1;
                }
            }
        }
        assert!(checked > 280, "coverage too small: {checked}");
    }
}
