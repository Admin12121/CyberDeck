//! Bounded offline TCP stream reconstruction from captured packet metadata.
//! TCP segments are ordered by sequence per direction, suppress retransmitted
//! bytes, flag conflicting overlaps, and preserve explicit gaps. This is not a full
//! TCP state machine: captures may begin midstream and overlapping conflicting
//! payloads, multiple sessions on one tuple, and >2GiB seq spans are not solved.
//!
//! TLS 1.3 decryption is strictly opt-in: only `follow_stream_with_keylog`
//! attempts it, only with a user-supplied keylog whose ClientHello random
//! matches the stream, and only per verified GCM tag. The plain
//! `follow_stream` path never touches key material.

use crate::crypto::keylog::KeylogStore;
use crate::crypto::tls13;
use crate::PacketMeta;
use serde::Serialize;

/// Give each observed TCP connection epoch a distinct stream ID even when
/// sequential connections reuse the same endpoint pair. This is intentionally
/// conservative: a missing initial handshake cannot be reconstructed.
pub fn assign_tcp_sessions(packets: &mut [PacketMeta]) {
    use std::collections::HashMap;

    struct Epoch {
        number: usize,
        initial_syn: Option<(String, u32)>,
        seen_packets: bool,
        fin_sources: Vec<String>,
        closed: bool,
    }

    let mut epochs: HashMap<String, Epoch> = HashMap::new();
    for packet in packets {
        let dissected = &mut packet.dissected;
        let (Some(base), Some(tcp)) = (dissected.stream_id.as_ref(), dissected.tcp.as_ref()) else {
            continue;
        };
        if !base.starts_with("tcp|") {
            continue;
        }
        let base = base.clone();
        let syn_start = tcp.flags & 0x02 != 0 && tcp.flags & 0x10 == 0;
        let sender = format!("{}:{}", dissected.source, tcp.source_port);
        let marker = (sender.clone(), tcp.sequence);
        let state = epochs.entry(base.clone()).or_insert_with(|| Epoch {
            number: 1,
            initial_syn: None,
            seen_packets: false,
            fin_sources: Vec::new(),
            closed: false,
        });
        if syn_start {
            // Identical retransmitted initial SYN is not a new connection.
            // Without a prior SYN, the capture may have started midstream.
            let fresh = state.closed
                || state
                    .initial_syn
                    .as_ref()
                    .is_some_and(|initial| initial != &marker)
                || (state.initial_syn.is_none() && state.seen_packets);
            if fresh {
                state.number = state.number.saturating_add(1);
                state.fin_sources.clear();
                state.closed = false;
            }
            state.initial_syn = Some(marker);
        }
        state.seen_packets = true;
        if tcp.flags & 0x04 != 0 {
            state.closed = true;
        }
        if tcp.flags & 0x01 != 0 && !state.fin_sources.contains(&sender) {
            state.fin_sources.push(sender);
            if state.fin_sources.len() >= 2 {
                state.closed = true;
            }
        }
        dissected.stream_id = Some(format!("{base}#{}", state.number));
    }
}

pub const MAX_STREAM_BYTES_PER_DIRECTION: usize = 512 * 1024;
pub const MAX_STREAM_SEGMENTS: usize = 4096;
pub const MAX_STREAM_CHUNKS: usize = 512;
const MAX_OVERLAP_COMPARE_BYTES: usize = 4 * MAX_STREAM_BYTES_PER_DIRECTION;
// Cap sequence displacements well below TCP's ambiguous signed half-range.
const MAX_STREAM_SEQUENCE_DISTANCE: i64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct StreamChunk {
    pub dir: String,
    pub text: String,
    pub kind: String,
    /// Exact bytes for this output fragment, encoded as hex for lossless IPC.
    pub hex_data: Option<String>,
}

/// Passive metadata from one complete leading application message after
/// assembling bounded, gap-free TCP payload fragments.
#[derive(Debug, Clone, Serialize)]
pub struct StreamApplicationHint {
    pub dir: String,
    pub protocol: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamTranscript {
    pub protocol: String,
    pub chunks: Vec<StreamChunk>,
    pub gaps: usize,
    pub retransmissions: usize,
    /// Conflicting overlapping TCP segments; the result is unsafe for automatic handoff.
    pub conflicts: usize,
    pub truncated: bool,
    pub application_hints: Vec<StreamApplicationHint>,
}

struct Segment<'a> {
    relative_sequence: i64,
    arrival: usize,
    data: &'a [u8],
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        out.push(HEX[usize::from(byte >> 4)] as char);
        out.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    out
}

fn display_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len());
    for &byte in bytes {
        match byte {
            b'\n' => out.push('\n'),
            b'\r' => out.push('\r'),
            b'\t' => out.push('\t'),
            0x20..=0x7e => out.push(byte as char),
            other => {
                out.push('\\');
                out.push('x');
                out.push(HEX[usize::from(other >> 4)] as char);
                out.push(HEX[usize::from(other & 0x0f)] as char);
            }
        }
    }
    out
}

fn note(out: &mut StreamTranscript, dir: &str, message: impl Into<String>) {
    if out.chunks.len() < MAX_STREAM_CHUNKS {
        out.chunks.push(StreamChunk {
            dir: dir.to_string(),
            text: message.into(),
            kind: "notice".into(),
            hex_data: None,
        });
    }
}

fn follow_tcp_side(
    packets: &[PacketMeta],
    id: &str,
    endpoint_a: &str,
    dir: &str,
    transcript: &mut StreamTranscript,
) -> Vec<u8> {
    let mut segments: Vec<Segment<'_>> = Vec::new();
    let mut first_seq = None;
    let mut sequence_limit_reported = false;
    for (arrival, packet) in packets.iter().enumerate() {
        let d = &packet.dissected;
        if d.stream_id.as_deref() != Some(id) || d.payload.is_empty() {
            continue;
        }
        let Some(tcp) = &d.tcp else { continue };
        let from_a = format!("{}:{}", d.source, tcp.source_port) == endpoint_a;
        if (dir == "A") != from_a {
            continue;
        }
        if segments.len() == MAX_STREAM_SEGMENTS {
            transcript.truncated = true;
            break;
        }
        let sequence = tcp.sequence.wrapping_add(u32::from(tcp.flags & 0x02 != 0));
        let base = *first_seq.get_or_insert(sequence);
        let relative_sequence = (sequence.wrapping_sub(base) as i32) as i64;
        if relative_sequence.abs() > MAX_STREAM_SEQUENCE_DISTANCE {
            transcript.truncated = true;
            if !sequence_limit_reported {
                note(
                    transcript,
                    dir,
                    "TCP sequence displacement exceeds the 64 MiB safety limit",
                );
                sequence_limit_reported = true;
            }
            continue;
        }
        segments.push(Segment {
            relative_sequence,
            arrival,
            data: &d.payload,
        });
    }
    segments.sort_by_key(|seg| (seg.relative_sequence, seg.arrival));
    let mut cursor = segments
        .first()
        .map(|seg| seg.relative_sequence)
        .unwrap_or(0);
    let mut written = 0usize;
    let mut dropped = 0usize;
    let mut gaps = 0usize;
    let mut duplicates = 0usize;
    let mut conflicts = 0usize;
    let mut compared_bytes = 0usize;
    // Nonoverlapping accepted runs, sorted by sequence. Keep borrowed slices:
    // maximum retained output is capped at 512 KiB per direction.
    let mut accepted: Vec<(i64, &[u8])> = Vec::new();
    let mut reconstructed = Vec::new();
    'segments: for segment in segments {
        let start = segment.relative_sequence;
        let end = start.saturating_add(segment.data.len() as i64);
        // A retransmitted range can disagree with previously reconstructed
        // bytes. Count those conflicts and prevent handing off an ambiguous
        // transcript as complete. Comparing is CPU-bounded as well.
        let overlap_end = end.min(cursor);
        if start < overlap_end {
            let first = accepted
                .partition_point(|(base, bytes)| base.saturating_add(bytes.len() as i64) <= start);
            let mut conflicting = false;
            for (base, bytes) in accepted[first..].iter() {
                let lo = start.max(*base);
                let hi = overlap_end.min(base.saturating_add(bytes.len() as i64));
                if hi <= lo {
                    continue;
                }
                let length = (hi - lo) as usize;
                if compared_bytes.saturating_add(length) > MAX_OVERLAP_COMPARE_BYTES {
                    transcript.truncated = true;
                    note(
                        transcript,
                        dir,
                        "Overlap verification exceeded safety limit",
                    );
                    break 'segments;
                }
                compared_bytes += length;
                let candidate = &segment.data[(lo - start) as usize..(hi - start) as usize];
                let original = &bytes[(lo - *base) as usize..(hi - *base) as usize];
                if candidate != original {
                    conflicting = true;
                    break;
                }
            }
            if conflicting {
                conflicts += 1;
                transcript.truncated = true;
            }
        }
        if end <= cursor {
            duplicates += 1;
            continue;
        }
        if start > cursor {
            gaps += 1;
            if transcript.chunks.len() < MAX_STREAM_CHUNKS {
                transcript.chunks.push(StreamChunk {
                    dir: dir.into(),
                    text: format!("Missing {} TCP sequence byte(s)", start - cursor),
                    kind: "gap".into(),
                    hex_data: None,
                });
            } else {
                transcript.truncated = true;
                break;
            }
            cursor = start;
        }
        let skip = (cursor - start).max(0) as usize;
        let new_data = &segment.data[skip..];
        let room = MAX_STREAM_BYTES_PER_DIRECTION.saturating_sub(written);
        if room == 0 || transcript.chunks.len() >= MAX_STREAM_CHUNKS.saturating_sub(2) {
            transcript.truncated = true;
            dropped += 1;
            break;
        }
        let take = room.min(new_data.len());
        if take == 0 {
            continue;
        }
        let accepted_start = cursor;
        transcript.chunks.push(StreamChunk {
            dir: dir.into(),
            text: display_bytes(&new_data[..take]),
            kind: "data".into(),
            hex_data: Some(hex_bytes(&new_data[..take])),
        });
        accepted.push((accepted_start, &new_data[..take]));
        reconstructed.extend_from_slice(&new_data[..take]);
        written += take;
        cursor += take as i64;
        if take < new_data.len() {
            transcript.truncated = true;
            dropped += 1;
            break;
        }
    }
    transcript.gaps += gaps;
    transcript.retransmissions += duplicates;
    transcript.conflicts += conflicts;
    if conflicts > 0 {
        note(transcript, dir, format!("{conflicts} conflicting TCP overlap(s); transcript is ambiguous and cannot be sent to Recipes"));
    }
    if duplicates > 0 {
        note(
            transcript,
            dir,
            format!("{duplicates} fully retransmitted/overlapping segment(s) omitted"),
        );
    }
    if dropped > 0 {
        note(
            transcript,
            dir,
            "Stream output truncated at the per-direction size/chunk limit",
        );
    }
    reconstructed
}

/// TCP port 53 uses two-byte length framing, independent of TCP segments.
fn dns_over_tcp_hint(stream_id: &str, payload: &[u8]) -> Option<String> {
    let (_, endpoints) = stream_id.split_once('|')?;
    let (left, right) = endpoints.split_once('|')?;
    let port_a = left.rsplit_once(':')?.1;
    let port_b = right.rsplit_once(':')?.1.split('#').next()?;
    if port_a != "53" && port_b != "53" {
        return None;
    }
    let prefix = payload.get(..2)?;
    let n = u16::from_be_bytes([prefix[0], prefix[1]]) as usize;
    if n < 12 || payload.len() < n.checked_add(2)? {
        return None;
    }
    Some(crate::dns::describe_dns(&crate::dns::parse_dns(
        &payload[2..n + 2],
    )?))
}

/// Return two direction-grouped TCP transcripts or a capture-order UDP datagram
/// list. No network I/O, filesystem access or external executables, and no
/// decryption: every existing caller keeps exactly the prior behavior.
pub fn follow_stream(packets: &[PacketMeta], stream_id: &str) -> Result<StreamTranscript, String> {
    if stream_id.len() > 512 {
        return Err("stream identifier too long".into());
    }
    let (protocol, endpoints) = stream_id
        .split_once('|')
        .ok_or("invalid stream identifier")?;
    let (endpoint_a, _endpoint_b) = endpoints
        .split_once('|')
        .ok_or("invalid stream endpoint pair")?;
    if endpoint_a.is_empty() {
        return Err("invalid stream endpoint".into());
    }
    if !matches!(protocol, "tcp" | "udp") {
        return Err("unsupported stream transport".into());
    }
    let mut result = StreamTranscript {
        protocol: protocol.to_uppercase(),
        chunks: Vec::new(),
        gaps: 0,
        retransmissions: 0,
        conflicts: 0,
        truncated: false,
        application_hints: Vec::new(),
    };
    if protocol == "tcp" {
        let a = follow_tcp_side(packets, stream_id, endpoint_a, "A", &mut result);
        let b = follow_tcp_side(packets, stream_id, endpoint_a, "B", &mut result);
        // Do not interpret reconstructed data as a complete application
        // message when any direction has missing or conflicting bytes.
        if result.gaps == 0 && !result.truncated {
            for (dir, data) in [("A", &a), ("B", &b)] {
                if let Some(summary) = dns_over_tcp_hint(stream_id, data) {
                    result.application_hints.push(StreamApplicationHint {
                        dir: dir.into(),
                        protocol: "DNS".into(),
                        summary,
                    });
                } else if let Some(line) = crate::application::http_start_line(data) {
                    result.application_hints.push(StreamApplicationHint {
                        dir: dir.into(),
                        protocol: "HTTP".into(),
                        summary: line,
                    });
                } else if let Some(hello) = crate::application::tls_hello(data) {
                    result.application_hints.push(StreamApplicationHint {
                        dir: dir.into(),
                        protocol: "TLS".into(),
                        summary: crate::application::tls_description(&hello),
                    });
                }
            }
        }
    } else {
        let mut total = 0usize;
        for packet in packets {
            let d = &packet.dissected;
            if d.stream_id.as_deref() != Some(stream_id) || d.payload.is_empty() {
                continue;
            }
            let room = 2 * MAX_STREAM_BYTES_PER_DIRECTION - total;
            if room == 0 || result.chunks.len() >= MAX_STREAM_CHUNKS {
                result.truncated = true;
                break;
            }
            let take = room.min(d.payload.len());
            // Source port disambiguates localhost and IPv6 UDP directions.
            let a = d
                .layers
                .iter()
                .find(|l| l.label == "source port")
                .map(|p| format!("{}:{}", d.source, p.value) == endpoint_a)
                .unwrap_or_else(|| {
                    d.source == endpoint_a.rsplit_once(':').map(|v| v.0).unwrap_or("")
                });
            result.chunks.push(StreamChunk {
                dir: if a { "A" } else { "B" }.into(),
                kind: "datagram".into(),
                text: display_bytes(&d.payload[..take]),
                hex_data: Some(hex_bytes(&d.payload[..take])),
            });
            total += take;
            if take < d.payload.len() {
                result.truncated = true;
                break;
            }
        }
    }
    Ok(result)
}

/// [`follow_stream`] with an optional user-imported NSS keylog attached.
/// When a keylog is present and its ClientHello random matches this stream,
/// each direction is walked as TLS 1.3 records and every record whose GCM
/// tag verifies is emitted as decrypted content; everything else stays
/// ciphertext with an honest marker. Without a keylog the output is
/// byte-identical to [`follow_stream`].
pub fn follow_stream_with_keylog(
    packets: &[PacketMeta],
    stream_id: &str,
    keylog: Option<&KeylogStore>,
) -> Result<StreamTranscript, String> {
    let transcript = follow_stream(packets, stream_id)?;
    Ok(match keylog {
        Some(store) => apply_keylog_to_transcript(&transcript, store),
        None => transcript,
    })
}

/// Pure post-processing step that applies a user-imported keylog to an
/// already-built [`StreamTranscript`]. The IPC layer calls this on the
/// transcript its (unchanged) follow-stream helpers produce, so decryption
/// stays a strictly additive, verifiable transformation of packet-crate
/// output. TCP transcripts only; the transformation is exact: each
/// direction's `data` chunks carry the direction's reconstructed bytes as
/// hex, which is precisely the byte sequence the TLS record walk consumes.
pub fn apply_keylog_to_transcript(
    transcript: &StreamTranscript,
    store: &KeylogStore,
) -> StreamTranscript {
    let mut result = transcript.clone();
    if result.protocol != "TCP" {
        return result;
    }
    let empty = Vec::new();
    let mut direction_bytes: Vec<(&str, Vec<u8>)> = Vec::new();
    for dir in ["A", "B"] {
        let mut bytes = Vec::new();
        for chunk in &result.chunks {
            if chunk.dir != dir || chunk.kind != "data" {
                continue;
            }
            let hex = chunk.hex_data.as_deref().unwrap_or("");
            for pair in hex.as_bytes().chunks_exact(2) {
                let hi = (pair[0] as char).to_digit(16).unwrap_or(0) as u8;
                let lo = (pair[1] as char).to_digit(16).unwrap_or(0) as u8;
                bytes.push((hi << 4) | lo);
            }
        }
        direction_bytes.push((dir, bytes));
    }
    let a = direction_bytes
        .iter()
        .find(|(dir, _)| *dir == "A")
        .map(|(_, bytes)| bytes)
        .unwrap_or(&empty);
    let b = direction_bytes
        .iter()
        .find(|(dir, _)| *dir == "B")
        .map(|(_, bytes)| bytes)
        .unwrap_or(&empty);
    apply_tls13_keylog(&mut result, a, b, store);
    result
}

/// True when the direction's first bytes frame as a TLS record, used only
/// to decide whether an honest "ciphertext" marker is warranted for a
/// direction the keylog cannot open.
fn looks_like_tls_stream(data: &[u8]) -> bool {
    data.len() >= 5 && matches!(data[0], 20..=23) && data[1] == 3
}

/// Apply a user-imported keylog to a reconstructed TCP transcript. Every
/// decrypted record here passed its GCM tag with keys the keylog explicitly
/// provided for this stream's ClientHello random; nothing is ever guessed.
fn apply_tls13_keylog(result: &mut StreamTranscript, a: &[u8], b: &[u8], store: &KeylogStore) {
    if result.gaps > 0 || result.truncated {
        note(
            result,
            "A",
            "TLS 1.3 keylog attached: transcript has gaps or conflicts — decryption skipped",
        );
        return;
    }
    // Bind the keylog entry through the stream's own ClientHello random:
    // the hello may sit in either direction depending on the capture's
    // endpoint ordering.
    let mut hello_dir: Option<&str> = None;
    let mut client_random: Option<[u8; 32]> = None;
    for (dir, data) in [("A", a), ("B", b)] {
        if let Some(hello) = crate::application::tls_hello(data) {
            if hello.client {
                if let Some(random) = tls13::client_hello_random(&hello.payload) {
                    hello_dir = Some(dir);
                    client_random = Some(random);
                    break;
                }
            }
        }
    }
    let (Some(hello_dir), Some(client_random)) = (hello_dir, client_random) else {
        note(
            result,
            "A",
            "TLS 1.3 keylog attached: no ClientHello found in this stream — nothing decrypted",
        );
        return;
    };
    let Some(mut decryptor) = tls13::Tls13Decryptor::new(store, &client_random) else {
        note(
            result,
            hello_dir,
            "TLS 1.3 keylog attached: no keylog entry matches this stream's ClientHello — ciphertext left as-is",
        );
        return;
    };
    let client_is_a = hello_dir == "A";
    for (dir, data) in [("A", a), ("B", b)] {
        let from_client = (dir == "A") == client_is_a;
        let has_keys = decryptor.direction_has_keys(from_client);
        let walk = tls13::walk_stream(&mut decryptor, from_client, data);
        if walk.decrypted_records > 0 {
            // The decrypted view replaces this direction's ciphertext data
            // chunks; gap/notice chunks stay (they describe TCP events).
            result
                .chunks
                .retain(|chunk| !(chunk.dir == dir && chunk.kind == "data"));
            let mut summary = format!(
                "side {dir}: decrypted (TLS 1.3, keylog): {} record(s), {} byte(s)",
                walk.decrypted_records,
                walk.plaintext.len(),
            );
            if walk.undecryptable_records > 0 {
                summary.push_str(&format!(
                    "; {} record(s) stayed ciphertext (tag mismatch)",
                    walk.undecryptable_records
                ));
            }
            if !walk.complete {
                summary.push_str("; record walk stopped at a framing/limit bound");
            }
            if result.chunks.len() < crate::streams::MAX_STREAM_CHUNKS {
                note(result, dir, summary);
            } else {
                result.truncated = true;
            }
            if result.chunks.len() < crate::streams::MAX_STREAM_CHUNKS {
                result.chunks.push(StreamChunk {
                    dir: dir.to_string(),
                    text: display_bytes(&walk.plaintext),
                    kind: "decrypted".into(),
                    hex_data: Some(hex_bytes(&walk.plaintext)),
                });
            } else {
                result.truncated = true;
            }
            // Decrypted application data feeds the same hint surface the
            // plaintext path uses, anchored on each decrypted
            // application-data record (handshake bytes precede application
            // bytes in the concatenated stream).
            for record in &walk.app_records {
                if let Some(line) = crate::application::http_start_line(record) {
                    result.application_hints.push(StreamApplicationHint {
                        dir: dir.to_string(),
                        protocol: "HTTP".into(),
                        summary: format!("decrypted (TLS 1.3, keylog): {line}"),
                    });
                    break;
                }
                if let Some(hint) = http2_hint(record) {
                    result.application_hints.push(StreamApplicationHint {
                        dir: dir.to_string(),
                        protocol: "HTTP/2".into(),
                        summary: hint,
                    });
                    break;
                }
            }
        } else if !has_keys && looks_like_tls_stream(data) {
            note(
                result,
                dir,
                format!(
                    "side {dir}: ciphertext — no matching keylog entry for this direction ({} TLS record(s))",
                    walk.plain_records + walk.undecryptable_records,
                ),
            );
        } else if has_keys && walk.undecryptable_records > 0 {
            note(
                result,
                dir,
                format!(
                    "side {dir}: {} TLS record(s) could not be decrypted — GCM verification failed (missing key phase or capture mismatch)",
                    walk.undecryptable_records,
                ),
            );
        }
    }
    if decryptor.limit_reached() {
        note(
            result,
            "A",
            format!(
                "TLS 1.3 decryption stopped at the {} record bound; remaining records left as ciphertext",
                tls13::MAX_DECRYPTED_RECORDS,
            ),
        );
    }
}

/// Bounded HTTP/2 hint over decrypted application data: the prior-knowledge
/// preface plus the first frames' names, mirroring the packet dissector's
/// bounded walk. A HEADERS body is decoded only when the static HPACK
/// table suffices; anything needing connection state degrades honestly.
fn http2_hint(payload: &[u8]) -> Option<String> {
    const MAGIC: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    if payload.len() < MAGIC.len() || &payload[..MAGIC.len()] != MAGIC {
        return None;
    }
    let mut summary = String::from("HTTP/2 connection preface");
    let mut at = MAGIC.len();
    for _ in 0..4 {
        if at + 9 > payload.len() {
            break;
        }
        let length = (usize::from(payload[at]) << 16)
            | (usize::from(payload[at + 1]) << 8)
            | usize::from(payload[at + 2]);
        let type_byte = payload[at + 3];
        let flags = payload[at + 4];
        let stream = (u32::from(payload[at + 5]) & 0x7f) << 24
            | u32::from(payload[at + 6]) << 16
            | u32::from(payload[at + 7]) << 8
            | u32::from(payload[at + 8]);
        let body_at = at + 9;
        let body_end = match body_at.checked_add(length) {
            Some(end) if end <= payload.len() => end,
            _ => {
                summary.push_str(", frame truncated at record boundary");
                break;
            }
        };
        if type_byte == 1 {
            // HEADERS: strip PADDED/PRIORITY framing, then decode with the
            // static-table-only HPACK decoder (bounded, honest on error).
            let body = &payload[body_at..body_end];
            let mut start = 0usize;
            let mut pad = 0usize;
            if flags & 0x08 != 0 && !body.is_empty() {
                pad = usize::from(body[0]);
                start = 1;
            }
            if flags & 0x20 != 0 {
                start += 5;
            }
            let block_end = body.len().saturating_sub(pad);
            let block = if start <= block_end {
                &body[start..block_end]
            } else {
                &body[..0]
            };
            match crate::hpack::decode_header_block(block, 4) {
                Ok(headers) if !headers.is_empty() => {
                    let shown: Vec<String> = headers
                        .iter()
                        .take(3)
                        .map(|(name, value)| format!("{name}={value}"))
                        .collect();
                    summary.push_str(&format!(", HEADERS(s{stream}) {}", shown.join(" ")));
                }
                Ok(_) => summary.push_str(&format!(", HEADERS(s{stream}) (no decodable headers)")),
                Err(_) => summary.push_str(&format!(
                    ", HEADERS(s{stream}) body needs connection HPACK state (not decoded)"
                )),
            }
            break;
        }
        at = body_end;
    }
    Some(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Dissected, Layer, TcpMeta};

    #[test]
    fn byte_rendering_preserves_exact_lowercase_and_escaped_contents() {
        let all_bytes: Vec<u8> = (0..=255u8).collect();
        let reference = all_bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(hex_bytes(&all_bytes), reference);
        assert_eq!(
            display_bytes(&[0, 31, 128, 255, b'A']),
            "\\x00\\x1f\\x80\\xffA"
        );
        assert_eq!(display_bytes(b"a\n\r\t"), "a\n\r\t");
    }

    const ID: &str = "tcp|10.0.0.1:1234|10.0.0.2:80";
    fn packet(dir: &str, seq: u32, flags: u8, payload: &[u8]) -> PacketMeta {
        let (source, destination, src_port, dst_port) = if dir == "A" {
            ("10.0.0.1", "10.0.0.2", 1234, 80)
        } else {
            ("10.0.0.2", "10.0.0.1", 80, 1234)
        };
        PacketMeta {
            offset: 0,
            incl_len: payload.len(),
            orig_len: payload.len(),
            ts_sec: 0,
            ts_subsec: 0,
            dissected: Dissected {
                source: source.into(),
                destination: destination.into(),
                protocol: "TCP".into(),
                info: String::new(),
                color_hint: "tcp".into(),
                layers: Vec::<Layer>::new(),
                stream_id: Some(ID.into()),
                tcp: Some(TcpMeta {
                    source_port: src_port,
                    destination_port: dst_port,
                    sequence: seq,
                    flags,
                }),
                payload: payload.to_vec(),
            },
        }
    }
    fn text_chunks(out: &StreamTranscript, dir: &str) -> String {
        out.chunks
            .iter()
            .filter(|chunk| chunk.dir == dir && chunk.kind == "data")
            .map(|chunk| chunk.text.as_str())
            .collect::<String>()
    }
    #[test]
    fn sorts_out_of_order_segments_and_deduplicates_retransmits() {
        let data = vec![
            packet("A", 100, 0, b"hell"),
            packet("A", 108, 0, b"rld"),
            packet("A", 104, 0, b"o wo"),
            packet("A", 104, 0, b"o wo"),
            packet("B", 500, 0, b"HTTP"),
        ];
        let out = follow_stream(&data, ID).unwrap();
        assert_eq!(text_chunks(&out, "A"), "hello world");
        assert_eq!(text_chunks(&out, "B"), "HTTP");
        assert_eq!(out.gaps, 0);
        assert_eq!(out.retransmissions, 1);
    }
    #[test]
    fn announces_gaps_and_does_not_fabricate_missing_data() {
        let out = follow_stream(
            &[packet("A", 100, 0, b"AB"), packet("A", 106, 0, b"EF")],
            ID,
        )
        .unwrap();
        assert_eq!(text_chunks(&out, "A"), "ABEF");
        assert_eq!(out.gaps, 1);
        assert!(out
            .chunks
            .iter()
            .any(|c| c.kind == "gap" && c.text.contains('4')));
    }
    #[test]
    fn honors_syn_and_sequence_wrap() {
        let out = follow_stream(
            &[
                packet("A", u32::MAX - 2, 0x02, b"a"),
                packet("A", u32::MAX, 0, b"b"),
                packet("A", 0, 0, b"cd"),
            ],
            ID,
        )
        .unwrap();
        assert_eq!(text_chunks(&out, "A"), "abcd");
        assert_eq!(out.gaps, 0);
    }
    #[test]
    fn implausible_large_tcp_sequence_displacement_fails_closed() {
        let out = follow_stream(
            &[
                packet("A", 100, 0, b"GET / HTTP/1.1\r\n\r\n"),
                packet("A", 100u32.wrapping_add(100_000_000), 0, b"bogus"),
                packet("A", 100u32.wrapping_sub(100_000_000), 0, b"backwards"),
                packet("A", 100u32.wrapping_add(200_000_000), 0, b"more"),
            ],
            ID,
        )
        .unwrap();
        assert!(out.truncated);
        assert!(out.application_hints.is_empty());
        assert_eq!(out.gaps, 0);
        assert_eq!(text_chunks(&out, "A"), "GET / HTTP/1.1\r\n\r\n");
        assert_eq!(
            out.chunks
                .iter()
                .filter(|chunk| chunk.kind == "notice" && chunk.text.contains("64 MiB"))
                .count(),
            1
        );
    }

    #[test]
    fn near_sequence_limit_does_not_discard_as_ambiguous() {
        let out = follow_stream(
            &[
                packet("A", 100, 0, b"start"),
                packet("A", 100 + MAX_STREAM_SEQUENCE_DISTANCE as u32, 0, b"end"),
            ],
            ID,
        )
        .unwrap();
        assert!(!out.truncated);
        assert_eq!(out.gaps, 1);
        assert_eq!(text_chunks(&out, "A"), "startend");
    }

    #[test]
    fn rejects_unknown_ids_and_preserves_udp_datagrams() {
        assert!(follow_stream(&[], "something").is_err());
        let mut a = packet("A", 1, 0, b"x\0y");
        a.dissected.tcp = None;
        a.dissected.stream_id = Some("udp|10.0.0.1:1234|10.0.0.2:80".into());
        let out = follow_stream(&[a], "udp|10.0.0.1:1234|10.0.0.2:80").unwrap();
        assert_eq!(out.chunks[0].text, "x\\x00y");
        assert_eq!(out.chunks[0].hex_data.as_deref(), Some("780079"));
        assert_eq!(out.chunks[0].kind, "datagram");
    }
    #[test]
    fn bounds_memory_and_output() {
        let mut packets = Vec::new();
        for i in 0..(MAX_STREAM_SEGMENTS + 5) {
            packets.push(packet("A", (i * 128) as u32, 0, &[b'x'; 128]));
        }
        let out = follow_stream(&packets, ID).unwrap();
        assert!(out.truncated);
        assert!(out.chunks.len() <= MAX_STREAM_CHUNKS);
    }

    #[test]
    fn new_syn_after_close_creates_distinct_session_without_mixing_payloads() {
        let mut packets = vec![
            packet("A", 100, 0x02, b""), // initial SYN
            packet("A", 100, 0x02, b""), // SYN retransmission
            packet("B", 400, 0x12, b""), // SYN ACK
            packet("A", 101, 0x18, b"first"),
            packet("A", 106, 0x11, b""),  // FIN from A
            packet("B", 401, 0x11, b""),  // FIN from B
            packet("A", 1000, 0x02, b""), // new connection, same endpoints
            packet("A", 1001, 0x18, b"second"),
        ];
        assign_tcp_sessions(&mut packets);
        let first = packets[0].dissected.stream_id.as_deref().unwrap();
        assert_eq!(first, packets[1].dissected.stream_id.as_deref().unwrap());
        assert_eq!(first, packets[3].dissected.stream_id.as_deref().unwrap());
        assert!(first.ends_with("#1"));
        let second = packets[7].dissected.stream_id.as_deref().unwrap();
        assert!(second.ends_with("#2"));
        assert_ne!(first, second);
        assert_eq!(
            text_chunks(&follow_stream(&packets, first).unwrap(), "A"),
            "first"
        );
        assert_eq!(
            text_chunks(&follow_stream(&packets, second).unwrap(), "A"),
            "second"
        );
    }

    #[test]
    fn midstream_capture_starts_first_session_until_a_new_initial_syn() {
        let mut packets = vec![
            packet("A", 100, 0x18, b"partial"),
            packet("A", 900, 0x02, b""),
            packet("A", 901, 0x18, b"fresh"),
        ];
        assign_tcp_sessions(&mut packets);
        assert!(packets[0]
            .dissected
            .stream_id
            .as_ref()
            .unwrap()
            .ends_with("#1"));
        assert!(packets[2]
            .dissected
            .stream_id
            .as_ref()
            .unwrap()
            .ends_with("#2"));
    }

    #[test]
    fn conflicting_overlap_is_flagged_and_blocks_complete_handoff() {
        let out = follow_stream(
            &[
                packet("A", 100, 0, b"abcde"),
                packet("A", 102, 0, b"cde"),
                packet("A", 103, 0, b"XYZ"),
            ],
            ID,
        )
        .unwrap();
        assert_eq!(out.conflicts, 1);
        assert!(out.truncated);
        assert_eq!(text_chunks(&out, "A"), "abcdeZ");
        assert!(out
            .chunks
            .iter()
            .any(|chunk| chunk.kind == "notice" && chunk.text.contains("conflicting")));
    }

    #[test]
    fn unchanged_overlaps_do_not_trigger_conflict() {
        let out = follow_stream(
            &[
                packet("A", 100, 0, b"abcdef"),
                packet("A", 102, 0, b"cdefgh"),
            ],
            ID,
        )
        .unwrap();
        assert_eq!(out.conflicts, 0);
        assert!(!out.truncated);
        assert_eq!(text_chunks(&out, "A"), "abcdefgh");
    }

    #[test]
    fn http_start_line_across_three_out_of_order_tcp_segments() {
        let line = b"GET /hello HTTP/1.1\r\nHost: example.test\r\n\r\n";
        let packets = vec![
            packet("A", 100, 0, &line[..4]),
            packet("A", 120, 0, &line[20..]),
            packet("A", 104, 0, &line[4..20]),
        ];
        let result = follow_stream(&packets, ID).unwrap();
        assert_eq!(result.gaps, 0);
        assert_eq!(result.conflicts, 0);
        assert_eq!(result.application_hints.len(), 1);
        assert_eq!(result.application_hints[0].protocol, "HTTP");
        assert_eq!(result.application_hints[0].dir, "A");
        assert_eq!(result.application_hints[0].summary, "GET /hello HTTP/1.1");
    }

    fn fixture_tls_client_hello() -> Vec<u8> {
        let mut hello = vec![3, 3];
        hello.extend_from_slice(&[0x4a; 32]);
        hello.push(0); // session id length
        hello.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
        let mut message = vec![1, 0, 0, hello.len() as u8];
        message.extend_from_slice(&hello);
        let mut record = vec![22, 3, 3];
        record.extend_from_slice(&(message.len() as u16).to_be_bytes());
        record.extend(message);
        record
    }

    #[test]
    fn tls_handshake_split_across_packets_has_passive_hint() {
        let record = fixture_tls_client_hello();
        let result = follow_stream(
            &[
                packet("A", 1000, 0, &record[..8]),
                packet("A", 1008, 0, &record[8..]),
            ],
            ID,
        )
        .unwrap();
        assert_eq!(result.application_hints.len(), 1);
        assert_eq!(result.application_hints[0].protocol, "TLS");
        assert!(result.application_hints[0].summary.contains("ClientHello"));
    }

    #[test]
    fn missing_or_conflicting_payload_must_never_give_app_hint() {
        let line = b"GET / HTTP/1.1\r\n";
        let gapped = follow_stream(
            &[packet("A", 1, 0, &line[..4]), packet("A", 8, 0, &line[4..])],
            ID,
        )
        .unwrap();
        assert!(gapped.gaps > 0);
        assert!(gapped.application_hints.is_empty());

        let conflicted = follow_stream(
            &[
                packet("A", 1, 0, line),
                packet("A", 1, 0, b"GET / HTTP/1.0\r\n"),
            ],
            ID,
        )
        .unwrap();
        assert!(conflicted.conflicts > 0);
        assert!(conflicted.application_hints.is_empty());
    }

    #[test]
    fn dns_tcp_reassembles_across_out_of_order_segments() {
        let mut query = vec![0x7a, 0x23, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        query.extend_from_slice(b"\x07example\x03org\x00\x00\x01\x00\x01");
        let mut data = (query.len() as u16).to_be_bytes().to_vec();
        data.extend(query);
        let id = "tcp|10.0.0.1:1234|10.0.0.2:53#1";
        let mut packets = vec![
            packet("A", 101, 0, &data[..1]),
            packet("A", 108, 0, &data[7..]),
            packet("A", 102, 0, &data[1..7]),
        ];
        for p in &mut packets {
            p.dissected.stream_id = Some(id.into());
        }
        let out = follow_stream(&packets, id).unwrap();
        assert_eq!(out.gaps, 0);
        assert_eq!(out.conflicts, 0);
        assert_eq!(out.application_hints.len(), 1);
        assert_eq!(out.application_hints[0].dir, "A");
        assert_eq!(out.application_hints[0].protocol, "DNS");
        assert!(out.application_hints[0].summary.contains("example.org A"));
    }

    #[test]
    fn dns_tcp_invalid_length_and_wrong_port_are_not_decoded() {
        let id = "tcp|10.0.0.1:1234|10.0.0.2:53";
        let mut packet1 = packet("A", 1, 0, b"\x00\x20short");
        packet1.dissected.stream_id = Some(id.into());
        assert!(follow_stream(&[packet1], id)
            .unwrap()
            .application_hints
            .is_empty());
        assert!(
            dns_over_tcp_hint("tcp|10.0.0.1:1234|10.0.0.2:80", b"\x00\x0c012345678901").is_none()
        );
        assert!(dns_over_tcp_hint(id, b"\x00\x00").is_none());
        assert!(dns_over_tcp_hint(id, b"\xff\xfftiny").is_none());
        assert!(dns_over_tcp_hint(
            "tcp|[2001:db8::1]:53|[2001:db8::2]:1234#1",
            b"\x00\x0c012345678901"
        )
        .is_none());
    }

    #[test]
    fn dns_tcp_conflicts_or_gaps_never_get_application_hint() {
        let mut query = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        query.extend_from_slice(b"\x03www\x04test\x00\x00\x01\x00\x01");
        let mut data = (query.len() as u16).to_be_bytes().to_vec();
        data.extend(query);
        let id = "tcp|10.0.0.1:1234|10.0.0.2:53";
        let mut a = packet("A", 100, 0, &data);
        a.dissected.stream_id = Some(id.into());
        let mut mismatch = packet("A", 100, 0, b"\x00\x11bad");
        mismatch.dissected.stream_id = Some(id.into());
        let out = follow_stream(&[a, mismatch], id).unwrap();
        assert!(out.conflicts > 0);
        assert!(out.application_hints.is_empty());
    }

    #[test]
    fn udp_same_ip_opposite_ports_preserve_direction() {
        let id = "udp|127.0.0.1:1234|127.0.0.1:5678";
        let mut a = packet("A", 1, 0, b"query");
        a.dissected.source = "127.0.0.1".into();
        a.dissected.tcp = None;
        a.dissected.stream_id = Some(id.into());
        a.dissected.layers = vec![Layer {
            label: "source port".into(),
            value: "1234".into(),
        }];
        let mut b = packet("B", 1, 0, b"reply");
        b.dissected.source = "127.0.0.1".into();
        b.dissected.tcp = None;
        b.dissected.stream_id = Some(id.into());
        b.dissected.layers = vec![Layer {
            label: "source port".into(),
            value: "5678".into(),
        }];
        let result = follow_stream(&[a, b], id).unwrap();
        assert_eq!(result.chunks[0].dir, "A");
        assert_eq!(result.chunks[1].dir, "B");
    }

    // ------------------------------------------------- TLS 1.3 keylog ----

    use crate::crypto::gcm;
    use crate::crypto::hkdf::hkdf_expand_label;
    use crate::crypto::keylog::KeylogStore;

    const KLOG_RANDOM: [u8; 32] = [0x4au8; 32];

    /// Derive the AES-128-GCM traffic keys exactly as the decryptor does.
    fn traffic_keys(secret: &[u8; 32]) -> ([u8; 16], [u8; 12]) {
        let mut key = [0u8; 16];
        let mut iv = [0u8; 12];
        assert!(hkdf_expand_label(secret, b"key", &[], &mut key));
        assert!(hkdf_expand_label(secret, b"iv", &[], &mut iv));
        (key, iv)
    }

    /// Encrypt one TLS 1.3 record the way the wire carries it, using the
    /// crate's own primitives (encrypt-then-decrypt self-consistency).
    fn seal_tls13_record(secret: &[u8; 32], seq: u64, content: &[u8], content_type: u8) -> Vec<u8> {
        let (key, iv) = traffic_keys(secret);
        let mut inner = content.to_vec();
        inner.push(content_type);
        let body_len = (inner.len() as u16 + 16).to_be_bytes();
        let header = [23u8, 3, 3, body_len[0], body_len[1]];
        let mut nonce = iv;
        let seq_bytes = seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        let mut record = header.to_vec();
        record.extend_from_slice(&gcm::seal(&key, &nonce, &header, &inner));
        record
    }

    fn keylog_entry(label: &str, secret: &[u8; 32]) -> String {
        let mut hex = String::new();
        for byte in secret {
            hex.push_str(&format!("{byte:02x}"));
        }
        let mut random = String::new();
        for byte in KLOG_RANDOM {
            random.push_str(&format!("{byte:02x}"));
        }
        format!("{label} {random} {hex}\n")
    }

    fn full_keylog() -> KeylogStore {
        let hs = [0x11u8; 32];
        let app = [0x22u8; 32];
        let text = format!(
            "{}{}{}{}",
            keylog_entry("CLIENT_HANDSHAKE_TRAFFIC_SECRET", &hs),
            keylog_entry("SERVER_HANDSHAKE_TRAFFIC_SECRET", &hs),
            keylog_entry("CLIENT_TRAFFIC_SECRET_0", &app),
            keylog_entry("SERVER_TRAFFIC_SECRET_0", &app),
        );
        KeylogStore::parse(&text).unwrap()
    }

    fn tls13_packets() -> Vec<PacketMeta> {
        let client_hs = [0x11u8; 32];
        let client_app = [0x22u8; 32];
        let server_app = [0x22u8; 32];
        // A->B: plaintext ClientHello, encrypted client Finished, CCS, app.
        let mut a_bytes = fixture_tls_client_hello();
        a_bytes.extend_from_slice(&seal_tls13_record(&client_hs, 0, b"finished", 22));
        a_bytes.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
        a_bytes.extend_from_slice(&seal_tls13_record(
            &client_app,
            0,
            b"GET /a HTTP/1.1\r\n",
            23,
        ));
        // B->A: server app data under the server application secret.
        let b_bytes = seal_tls13_record(&server_app, 0, b"HTTP/1.1 200 OK\r\n", 23);
        let mut packets = Vec::new();
        let mut seq = 1000u32;
        for chunk in a_bytes.chunks(24) {
            packets.push(packet("A", seq, 0, chunk));
            seq += chunk.len() as u32;
        }
        let mut seq = 5000u32;
        for chunk in b_bytes.chunks(24) {
            packets.push(packet("B", seq, 0, chunk));
            seq += chunk.len() as u32;
        }
        packets
    }

    fn notice_texts(out: &StreamTranscript) -> Vec<String> {
        out.chunks
            .iter()
            .filter(|c| c.kind == "notice")
            .map(|c| c.text.clone())
            .collect()
    }

    #[test]
    fn keylog_decrypts_synthetic_tls13_stream_round_trip() {
        let store = full_keylog();
        let packets = tls13_packets();
        let out = follow_stream_with_keylog(&packets, ID, Some(&store)).unwrap();
        // Decrypted chunks replace the ciphertext data chunks.
        let decrypted: Vec<&StreamChunk> = out
            .chunks
            .iter()
            .filter(|c| c.kind == "decrypted")
            .collect();
        assert_eq!(decrypted.len(), 2);
        let a_plain = decrypted.iter().find(|c| c.dir == "A").unwrap();
        assert!(a_plain.text.contains("GET /a HTTP/1.1"));
        assert!(a_plain
            .hex_data
            .as_deref()
            .unwrap()
            .contains("474554202f61"));
        let b_plain = decrypted.iter().find(|c| c.dir == "B").unwrap();
        assert!(b_plain.text.contains("HTTP/1.1 200 OK"));
        // Honest per-direction labels.
        let notices = notice_texts(&out).join("\n");
        assert!(notices.contains("side A: decrypted (TLS 1.3, keylog)"));
        assert!(notices.contains("side B: decrypted (TLS 1.3, keylog)"));
        // Ciphertext data chunks are gone.
        assert!(out.chunks.iter().all(|c| c.kind != "data"));
        // Decrypted application data feeds the existing hint surface.
        assert!(out.application_hints.iter().any(|h| {
            h.protocol == "HTTP" && h.summary.starts_with("decrypted (TLS 1.3, keylog): GET /a")
        }));
        // Sending to Recipes uses the decrypted hex.
        let hex = out
            .chunks
            .iter()
            .filter(|c| c.dir == "A" && (c.kind == "data" || c.kind == "decrypted"))
            .map(|c| c.hex_data.as_deref().unwrap_or(""))
            .collect::<String>();
        assert!(hex.contains("474554202f6120485454502f312e310d0a"));
    }

    #[test]
    fn wrong_client_hello_random_leaves_ciphertext_with_honest_marker() {
        let store = full_keylog();
        // Same packets but a ClientHello random the keylog does not know.
        let mut hello = vec![3, 3];
        hello.extend_from_slice(&[0x4b; 32]);
        hello.push(0);
        hello.extend_from_slice(&[0, 2, 0x13, 0x01, 1, 0]);
        let mut message = vec![1, 0, 0, hello.len() as u8];
        message.extend_from_slice(&hello);
        let mut record = vec![22, 3, 3];
        record.extend_from_slice(&(message.len() as u16).to_be_bytes());
        record.extend(message);
        let mut p = packet("A", 1000, 0, &record);
        p.dissected.stream_id = Some(ID.into());
        let out = follow_stream_with_keylog(&[p], ID, Some(&store)).unwrap();
        assert!(out.chunks.iter().all(|c| c.kind != "decrypted"));
        assert!(notice_texts(&out)
            .iter()
            .any(|t| t.contains("no keylog entry matches this stream's ClientHello")));
    }

    #[test]
    fn direction_without_keylog_entry_is_labeled_ciphertext() {
        // Only CLIENT secrets in the keylog: side B stays labeled ciphertext.
        let client_hs = [0x11u8; 32];
        let text = keylog_entry("CLIENT_HANDSHAKE_TRAFFIC_SECRET", &client_hs)
            + &keylog_entry("CLIENT_TRAFFIC_SECRET_0", &[0x22u8; 32]);
        let store = KeylogStore::parse(&text).unwrap();
        let out = follow_stream_with_keylog(&tls13_packets(), ID, Some(&store)).unwrap();
        let notices = notice_texts(&out).join("\n");
        assert!(notices.contains("side B: ciphertext — no matching keylog entry"));
        assert!(out.chunks.iter().any(|c| c.dir == "B" && c.kind == "data"));
        assert!(out
            .chunks
            .iter()
            .any(|c| c.dir == "A" && c.kind == "decrypted"));
    }

    #[test]
    fn keylog_attached_but_gapped_stream_skips_decryption() {
        let store = full_keylog();
        let mut packets = tls13_packets();
        // Introduce a sequence gap in A by shifting the later packets.
        for p in packets
            .iter_mut()
            .skip(2)
            .filter(|p| p.dissected.source == "10.0.0.1")
        {
            if let Some(tcp) = &mut p.dissected.tcp {
                tcp.sequence = tcp.sequence.wrapping_add(64);
            }
        }
        let out = follow_stream_with_keylog(&packets, ID, Some(&store)).unwrap();
        assert!(out.chunks.iter().all(|c| c.kind != "decrypted"));
        assert!(notice_texts(&out)
            .iter()
            .any(|t| t.contains("gaps or conflicts — decryption skipped")));
        assert!(out.application_hints.is_empty());
    }

    #[test]
    fn keylog_without_clienthello_or_stream_without_tls_is_not_decrypted() {
        let store = full_keylog();
        // A plaintext HTTP stream never claims decryption under a keylog.
        let line = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let out =
            follow_stream_with_keylog(&[packet("A", 100, 0, line)], ID, Some(&store)).unwrap();
        assert!(out.chunks.iter().all(|c| c.kind != "decrypted"));
        assert!(notice_texts(&out)
            .iter()
            .any(|t| t.contains("no ClientHello found")));
    }

    #[test]
    fn plain_follow_stream_and_none_keylog_are_byte_identical() {
        let packets = tls13_packets();
        let plain = follow_stream(&packets, ID).unwrap();
        let none = follow_stream_with_keylog(&packets, ID, None).unwrap();
        assert_eq!(plain.chunks.len(), none.chunks.len());
        for (a, b) in plain.chunks.iter().zip(&none.chunks) {
            assert_eq!(a.dir, b.dir);
            assert_eq!(a.text, b.text);
            assert_eq!(a.kind, b.kind);
            assert_eq!(a.hex_data, b.hex_data);
        }
        assert_eq!(plain.application_hints.len(), none.application_hints.len());
        for (a, b) in plain.application_hints.iter().zip(&none.application_hints) {
            assert_eq!(a.dir, b.dir);
            assert_eq!(a.protocol, b.protocol);
            assert_eq!(a.summary, b.summary);
        }
        assert_eq!(plain.gaps, none.gaps);
        assert_eq!(plain.truncated, none.truncated);
        // And no keylog ever produces a decrypted claim.
        assert!(plain.chunks.iter().all(|c| c.kind != "decrypted"));
    }

    #[test]
    fn decrypted_http2_application_data_feeds_the_http2_hint() {
        let server_app = [0x22u8; 32];
        // Preface + SETTINGS + HEADERS with static-table HPACK bytes.
        let mut plain = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
        plain.extend_from_slice(&[0, 0, 0, 4, 0, 0, 0, 0, 0]); // empty SETTINGS
        plain.extend_from_slice(&[0, 0, 2, 1, 0, 0, 0, 0, 1, 0x82, 0x84]); // HEADERS :method=GET :path=/
        let b_bytes = seal_tls13_record(&server_app, 0, &plain, 23);
        let mut packets = Vec::new();
        for (i, chunk) in b_bytes.chunks(24).enumerate() {
            packets.push(packet("B", (5000 + i * 24) as u32, 0, chunk));
        }
        let mut hello_packet = packet("A", 1000, 0, &fixture_tls_client_hello());
        // Client direction must exist for the hello binding; give A no keys
        // so only B decrypts.
        packets.push(hello_packet);
        let text = keylog_entry("CLIENT_HANDSHAKE_TRAFFIC_SECRET", &[0x11u8; 32])
            + &keylog_entry("SERVER_TRAFFIC_SECRET_0", &[0x22u8; 32]);
        let store = KeylogStore::parse(&text).unwrap();
        let out = follow_stream_with_keylog(&packets, ID, Some(&store)).unwrap();
        let hint = out
            .application_hints
            .iter()
            .find(|h| h.protocol == "HTTP/2")
            .expect("HTTP/2 hint from decrypted bytes");
        assert_eq!(hint.dir, "B");
        assert!(hint.summary.contains("decrypted") || hint.summary.contains("preface"));
        assert!(hint.summary.contains("HEADERS(s1)"));
        assert!(hint.summary.contains(":method=GET"));
    }
}
