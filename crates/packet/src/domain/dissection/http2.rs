//! Bounded HTTP/2 dissection: prior-knowledge magic detection plus the first
//! frame headers after the preface. Frame payloads (HEADERS block data) are
//! HPACK-compressed — never decoded or claimed here.

use super::link::{color_for, empty_frame};
use crate::{Dissected, Layer};

/// RFC 7541 §3.5 prior-knowledge preface (24 bytes).
const MAGIC: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const MAX_FRAMES_PARSED: usize = 4;
const FRAME_HEADER_LEN: usize = 9;

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
        let _flags = payload[cursor + 4];
        let stream = (u32::from(payload[cursor + 5]) & 0x7f) << 24
            | u32::from(payload[cursor + 6]) << 16
            | u32::from(payload[cursor + 7]) << 8
            | u32::from(payload[cursor + 8]);
        let Some(_body_end) = cursor
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
}
