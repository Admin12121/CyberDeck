//! Bounded HTTP/2 dissection: prior-knowledge magic detection plus the first
//! frame headers after the preface. HEADERS frame payloads are decoded with
//! the bounded HPACK decoder (`crate::hpack`, static table only): each decoded
//! header becomes its own layer, and anything that cannot be decoded honestly
//! — dynamic-table state, Huffman strings, truncation at a capture boundary —
//! degrades to an explicit placeholder or a single error layer instead of a
//! guess. Frame payloads other than HEADERS are never interpreted.

use super::link::{color_for, empty_frame};
use crate::{Dissected, Layer};

/// RFC 7541 §3.5 prior-knowledge preface (24 bytes).
const MAGIC: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const MAX_FRAMES_PARSED: usize = 4;
const FRAME_HEADER_LEN: usize = 9;
/// HEADERS frame type byte (RFC 7540 §6.2).
const FRAME_TYPE_HEADERS: u8 = 1;
/// HEADERS flags: padded (0x08) and priority (0x20) framing around the block.
const FLAG_PADDED: u8 = 0x08;
const FLAG_PRIORITY: u8 = 0x20;
/// Cap on headers decoded (and emitted as layers) per HEADERS frame.
const MAX_DECODED_HEADERS: usize = 8;
/// Header values are shown truncated at this many characters.
const MAX_VALUE_DISPLAY_CHARS: usize = 128;

fn frame_type_name(type_byte: u8) -> String {
    match type_byte {
        0 => "DATA".into(),
        1 => "HEADERS".into(),
        2 => "PRIORITY".into(),
        3 => "RST_STREAM".into(),
        4 => "SETTINGS".into(),
        5 => "PUSH_PROMISE".into(),
        6 => "PING".into(),
        7 => "GOAWAY".into(),
        8 => "WINDOW_UPDATE".into(),
        9 => "CONTINUATION".into(),
        other => format!("type {other}"),
    }
}

/// True when the TCP payload begins with the HTTP/2 client preface.
pub fn is_http2_preface(payload: &[u8]) -> bool {
    payload.len() >= MAGIC.len() && &payload[..MAGIC.len()] == MAGIC
}

/// Strip the PADDED and PRIORITY framing around the HPACK block of a HEADERS
/// frame (RFC 7540 §6.2). Layout: optional pad-length byte (0x08), optional
/// 5-byte priority fields (0x20), the header block fragment, optional end
/// padding. Every length is validated before use — a lie in the flags or pad
/// length is refused rather than sliced blindly.
fn hpack_block(body: &[u8], flags: u8) -> Result<&[u8], &'static str> {
    let mut at = 0usize;
    let mut pad = 0usize;
    if flags & FLAG_PADDED != 0 {
        pad = usize::from(*body
            .first()
            .ok_or("PADDED flag set but the frame body is empty")?);
        at += 1;
    }
    if flags & FLAG_PRIORITY != 0 {
        if body.len() < at + 5 {
            return Err("PRIORITY flag set but the frame body is shorter than 5 priority bytes");
        }
        at += 5;
    }
    let end = body
        .len()
        .checked_sub(pad)
        .ok_or("PADDED pad length exceeds the frame body")?;
    if at > end {
        return Err("PADDED/priority fields consume the whole header block");
    }
    Ok(&body[at..end])
}

/// Decode a HEADERS frame body into per-header layers: one layer per decoded
/// header ("name: value", values shown truncated), capped at
/// [`MAX_DECODED_HEADERS`]. Any decode failure — typed HPACK error or invalid
/// flag framing — degrades to a single honest error layer instead of dropping
/// the frame or inventing headers.
fn push_header_layers(body: &[u8], flags: u8, layers: &mut Vec<Layer>) {
    let block = match hpack_block(body, flags) {
        Ok(block) => block,
        Err(reason) => {
            layers.push(Layer {
                label: "HTTP/2 headers".into(),
                value: format!("HPACK block unavailable: {reason}"),
            });
            return;
        }
    };
    match crate::hpack::decode_header_block(block, MAX_DECODED_HEADERS) {
        Ok(headers) => {
            for (name, value) in headers {
                layers.push(Layer {
                    label: "HTTP/2 header".into(),
                    value: format!("{name}: {}", display_value(&value)),
                });
            }
        }
        Err(err) => layers.push(Layer {
            label: "HTTP/2 headers".into(),
            value: format!("HPACK decode failed: {err}"),
        }),
    }
}

/// Header values are display-truncated at a fixed character bound with an
/// ellipsis marking that the value continues.
fn display_value(value: &str) -> String {
    if value.chars().count() <= MAX_VALUE_DISPLAY_CHARS {
        return value.to_owned();
    }
    let mut out: String = value.chars().take(MAX_VALUE_DISPLAY_CHARS).collect();
    out.push('…');
    out
}

/// Dissect an HTTP/2 connection preface: the magic plus up to four frame
/// headers. Returns None for any payload that is not an HTTP/2 preface so
/// the caller keeps its HTTP/1 path.
pub fn dissect_http2(payload: &[u8], mut layers: Vec<Layer>) -> Option<Dissected> {
    if !is_http2_preface(payload) {
        return None;
    }
    layers.push(Layer {
        label: "HTTP/2".into(),
        value: "connection preface (magic) + frames".into(),
    });
    let mut info = "HTTP/2 connection preface".to_string();
    let mut cursor = MAGIC.len();
    let mut parsed = 0usize;
    while cursor + FRAME_HEADER_LEN <= payload.len() && parsed < MAX_FRAMES_PARSED {
        let length = (usize::from(payload[cursor]) << 16)
            | (usize::from(payload[cursor + 1]) << 8)
            | usize::from(payload[cursor + 2]);
        let type_byte = payload[cursor + 3];
        let flags = payload[cursor + 4];
        let stream = (u32::from(payload[cursor + 5]) & 0x7f) << 24
            | u32::from(payload[cursor + 6]) << 16
            | u32::from(payload[cursor + 7]) << 8
            | u32::from(payload[cursor + 8]);
        let Some(body_end) = cursor
            .checked_add(FRAME_HEADER_LEN)
            .and_then(|header_end| header_end.checked_add(length))
            .filter(|end| *end <= payload.len())
        else {
            // A frame claiming more bytes than the segment carries is normal
            // at capture boundaries; report the boundary honestly and stop.
            layers.push(Layer {
                label: "HTTP/2 frame".into(),
                value: format!(
                    "{} truncated at capture boundary (claims {length} byte(s))",
                    frame_type_name(type_byte)
                ),
            });
            info.push_str(&format!(
                ", {} truncated at capture boundary",
                frame_type_name(type_byte)
            ));
            break;
        };
        layers.push(Layer {
            label: "HTTP/2 frame".into(),
            value: format!(
                "{} len={length} stream={stream}",
                frame_type_name(type_byte)
            ),
        });
        info.push_str(&format!(", {}(s{})", frame_type_name(type_byte), stream));
        // A HEADERS frame body is the HPACK block (plus optional PADDED /
        // priority framing). Decode it boundedly; a block continued in
        // CONTINUATION frames may truncate here and degrades honestly.
        if type_byte == FRAME_TYPE_HEADERS {
            let body = &payload[cursor + FRAME_HEADER_LEN..body_end];
            push_header_layers(body, flags, &mut layers);
        }
        cursor += FRAME_HEADER_LEN + length;
        parsed += 1;
    }
    Some(Dissected {
        source: String::new(),
        destination: String::new(),
        protocol: "HTTP2".into(),
        info,
        color_hint: color_for("HTTP"),
        layers,
        stream_id: None,
        tcp: None,
        payload: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(type_byte: u8, stream: u32, body: &[u8]) -> Vec<u8> {
        let mut out = vec![
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
            type_byte,
            0,
        ];
        out.push(((stream >> 24) & 0x7f) as u8);
        out.extend_from_slice(&(stream & 0x00ff_ffff).to_be_bytes()[1..4]);
        out.extend_from_slice(body);
        out
    }

    fn with_magic(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        for frame in frames {
            out.extend_from_slice(frame);
        }
        out
    }

    fn headers_frame(stream: u32, flags: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![
            (body.len() >> 16) as u8,
            (body.len() >> 8) as u8,
            body.len() as u8,
            1, // HEADERS
            flags,
        ];
        out.push(((stream >> 24) & 0x7f) as u8);
        out.extend_from_slice(&(stream & 0x00ff_ffff).to_be_bytes()[1..4]);
        out.extend_from_slice(body);
        out
    }

    fn header_layers(d: &Dissected) -> Vec<&Layer> {
        d.layers.iter().filter(|l| l.label == "HTTP/2 header").collect()
    }

    fn error_layer(d: &Dissected) -> Option<&Layer> {
        d.layers.iter().find(|l| l.label == "HTTP/2 headers")
    }

    #[test]
    fn magic_plus_settings_frame_is_recognized() {
        let payload = with_magic(&[frame(4, 0, &[0, 1])]);
        let d = dissect_http2(&payload, Vec::new()).expect("http2");
        assert_eq!(d.protocol, "HTTP2");
        assert!(d.layers.iter().any(|l| l.label == "HTTP/2" && l.value.contains("preface")));
        assert!(d.layers.iter().any(|l| l.label == "HTTP/2 frame" && l.value.contains("SETTINGS") && l.value.contains("stream=0")));
    }

    #[test]
    fn multiple_frames_parse_in_order_up_to_the_cap() {
        let payload = with_magic(&[frame(4, 0, &[]), frame(8, 0, &[]), frame(1, 1, &[0xaa])]);
        let d = dissect_http2(&payload, Vec::new()).unwrap();
        let frames: Vec<_> = d.layers.iter().filter(|l| l.label == "HTTP/2 frame").collect();
        assert_eq!(frames.len(), 3);
        assert!(frames[0].value.contains("SETTINGS"));
        assert!(frames[1].value.contains("WINDOW_UPDATE"));
        assert!(frames[2].value.contains("HEADERS") && frames[2].value.contains("stream=1"));
    }

    #[test]
    fn truncated_frame_reports_the_boundary_honestly() {
        let mut payload = with_magic(&[frame(4, 0, &[0, 1, 2, 3])]);
        payload.truncate(MAGIC.len() + FRAME_HEADER_LEN + 2); // header present, body cut
        let d = dissect_http2(&payload, Vec::new()).unwrap();
        assert!(d.layers.iter().any(|l| l.label == "HTTP/2 frame" && l.value.contains("truncated at capture boundary")));
    }

    #[test]
    fn non_magic_payloads_return_none() {
        assert!(dissect_http2(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", Vec::new()).is_none());
        assert!(dissect_http2(b"PRI * HTTP/2.0\r\n", Vec::new()).is_none());
        assert!(dissect_http2(&[], Vec::new()).is_none());
    }

    #[test]
    fn stream_id_high_bit_is_masked() {
        let mut f = frame(4, 0, &[]);
        f[5] |= 0x80; // reserved bit must not leak into the stream id
        let payload = with_magic(&[f]);
        let d = dissect_http2(&payload, Vec::new()).unwrap();
        assert!(d.layers.iter().any(|l| l.value.contains("stream=0")));
    }

    /// Static-table indexed fields become one "HTTP/2 header" layer each,
    /// shown as "name: value".
    #[test]
    fn headers_frame_static_table_entries_become_layers() {
        let payload = with_magic(&[headers_frame(1, 0, &[0x82, 0x84, 0x87])]);
        let d = dissect_http2(&payload, Vec::new()).unwrap();
        let headers = header_layers(&d);
        assert_eq!(
            headers.iter().map(|l| l.value.as_str()).collect::<Vec<_>>(),
            [":method: GET", ":path: /", ":scheme: https"]
        );
    }

    /// A literal instruction decodes custom names and values verbatim.
    #[test]
    fn headers_frame_literal_custom_header_becomes_layer() {
        let mut body = vec![0x40]; // incremental indexing, new name
        body.push(b"custom-key".len() as u8);
        body.extend_from_slice(b"custom-key");
        body.push(b"custom-value".len() as u8);
        body.extend_from_slice(b"custom-value");
        let payload = with_magic(&[headers_frame(1, 0, &body)]);
        let d = dissect_http2(&payload, Vec::new()).unwrap();
        assert_eq!(
            header_layers(&d).iter().map(|l| l.value.as_str()).collect::<Vec<_>>(),
            ["custom-key: custom-value"]
        );
    }

    /// A dynamic-table reference is connection state the segment cannot
    /// carry; the layer says so honestly instead of guessing a header.
    #[test]
    fn headers_frame_dynamic_reference_is_honest_about_state() {
        let payload = with_magic(&[headers_frame(1, 0, &[0xbe])]);
        let d = dissect_http2(&payload, Vec::new()).unwrap();
        assert_eq!(
            header_layers(&d).iter().map(|l| l.value.as_str()).collect::<Vec<_>>(),
            ["dynamic table entry 62: (state unavailable)"]
        );
    }

    /// Huffman-coded strings are never expanded and never overclaimed: the
    /// placeholder states exactly what happened.
    #[test]
    fn headers_frame_huffman_string_degrades_without_overclaiming() {
        let mut body = vec![0x00, 0x04];
        body.extend_from_slice(b"host");
        body.push(0x80 | 9); // Huffman flag set, 9 encoded bytes follow
        body.extend_from_slice(&[0x41, 0x74, 0x17, 0x1a, 0x66, 0x3d, 0x6c, 0x62, 0x7f]);
        let payload = with_magic(&[headers_frame(1, 0, &body)]);
        let d = dissect_http2(&payload, Vec::new()).unwrap();
        assert_eq!(
            header_layers(&d).iter().map(|l| l.value.as_str()).collect::<Vec<_>>(),
            ["host: <Huffman-encoded (not decoded)>"]
        );
    }

    /// A truncated HPACK block degrades to ONE error layer; the frame layer
    /// itself is still present, so the frame is never dropped.
    #[test]
    fn truncated_hpack_block_degrades_to_single_error_layer() {
        let payload = with_magic(&[headers_frame(1, 0, &[0x40, 0x0a, b'a'])]);
        let d = dissect_http2(&payload, Vec::new()).unwrap();
        assert!(d.layers.iter().any(|l| l.label == "HTTP/2 frame" && l.value.contains("HEADERS")));
        let err = error_layer(&d).expect("degraded header layer");
        assert!(err.value.contains("truncated"), "{}", err.value);
        assert!(header_layers(&d).is_empty(), "no partial headers may be invented");
    }

    /// PADDED (0x08) and PRIORITY (0x20) framing is stripped before decoding;
    /// a pad length that lies about the body is refused honestly.
    #[test]
    fn padded_and_priority_framing_is_stripped_before_decode() {
        // PADDED only: pad byte 0, fragment, no trailing padding.
        let payload = with_magic(&[headers_frame(1, 0x08, &[0x00, 0x82])]);
        let d = dissect_http2(&payload, Vec::new()).unwrap();
        assert_eq!(
            header_layers(&d).iter().map(|l| l.value.as_str()).collect::<Vec<_>>(),
            [":method: GET"]
        );

        // PADDED + PRIORITY: pad byte, 5 priority bytes, fragment, 2 pad bytes.
        let mut body = vec![2];
        body.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x10]); // E=0 dep=0 weight=16
        body.push(0x82);
        body.extend_from_slice(&[0xde, 0xad]);
        let payload = with_magic(&[headers_frame(3, 0x28, &body)]);
        let d = dissect_http2(&payload, Vec::new()).unwrap();
        assert_eq!(
            header_layers(&d).iter().map(|l| l.value.as_str()).collect::<Vec<_>>(),
            [":method: GET"]
        );

        // A pad length larger than the remaining body is refused, not sliced.
        let payload = with_magic(&[headers_frame(1, 0x08, &[0x10, 0x82])]);
        let d = dissect_http2(&payload, Vec::new()).unwrap();
        let err = error_layer(&d).expect("degraded header layer");
        assert!(err.value.contains("pad length exceeds"), "{}", err.value);

        // A PRIORITY flag with a too-short body is refused as well.
        let payload = with_magic(&[headers_frame(1, 0x20, &[0x82, 0x82])]);
        let d = dissect_http2(&payload, Vec::new()).unwrap();
        let err = error_layer(&d).expect("degraded header layer");
        assert!(err.value.contains("PRIORITY flag"), "{}", err.value);
    }

    /// A field beyond the byte bounds stops with the typed reason in the
    /// degraded layer.
    #[test]
    fn oversized_header_field_degrades_with_typed_reason() {
        // Name of 257 bytes: 0x7f 0x81 0x01 is the length encoding of 256,
        // so use 257 = 127 + 2 + 1*128 -> 0x7f 0x82 0x01.
        let mut body = vec![0x00, 0x7f, 0x82, 0x01];
        body.extend(std::iter::repeat(b'a').take(257));
        let payload = with_magic(&[headers_frame(1, 0, &body)]);
        let d = dissect_http2(&payload, Vec::new()).unwrap();
        let err = error_layer(&d).expect("degraded header layer");
        assert!(err.value.contains("257 bytes"), "{}", err.value);
    }

    /// More headers than the per-frame cap is an honest degradation, not a
    /// silent truncation.
    #[test]
    fn more_than_cap_headers_degrade_to_error_layer() {
        let body: Vec<u8> = (1..=9u8).map(|i| 0x80 | i).collect();
        let payload = with_magic(&[headers_frame(1, 0, &body)]);
        let d = dissect_http2(&payload, Vec::new()).unwrap();
        let err = error_layer(&d).expect("degraded header layer");
        assert!(err.value.contains("more than 8 headers"), "{}", err.value);
        assert!(header_layers(&d).is_empty());
    }

    /// Long header values are display-truncated with an ellipsis; the name
    /// and the rest of the block are unaffected.
    #[test]
    fn long_values_are_truncated_for_display() {
        // 200 as a plain string length needs the 7-bit continuation path
        // (200 = 127 + 73): 0x7f keeps the Huffman flag clear, 0x49 adds 73.
        let mut body = vec![0x00, 0x01, b'x', 0x7f, 0x49];
        body.extend(std::iter::repeat(b'v').take(200));
        let payload = with_magic(&[headers_frame(1, 0, &body)]);
        let d = dissect_http2(&payload, Vec::new()).unwrap();
        let headers = header_layers(&d);
        assert_eq!(headers.len(), 1);
        let value = headers[0].value.trim_start_matches("x: ");
        let chars = value.chars().count();
        assert_eq!(chars, 129, "128 kept chars + ellipsis, got {chars}");
        assert!(value.ends_with('…'));
    }
}
