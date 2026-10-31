//! Bounded DNS query and answer decoding (RFC 1035 common records).
//! Compression pointers are validated and capped; untrusted record counts
//! cannot trigger unbounded loops or allocations.

use std::fmt::Write;
use std::net::{Ipv4Addr, Ipv6Addr};

const MAX_POINTERS: usize = 16;
const MAX_LABELS: usize = 64;
const MAX_NAME_LEN: usize = 255;
const MAX_DNS_PACKET: usize = 65535;
const MAX_QUESTIONS: usize = 16;
const MAX_ANSWERS: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub record_type: u16,
    pub class: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsAnswer {
    pub name: String,
    pub record_type: u16,
    pub class: u16,
    pub ttl_seconds: u32,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSummary {
    pub transaction_id: u16,
    pub is_response: bool,
    pub questions: u16,
    pub answers: u16,
    pub response_code: u8,
    pub first_question: Option<DnsQuestion>,
    pub answer_records: Vec<DnsAnswer>,
    /// Some records were not decoded because the response exceeds our limit.
    pub answers_limited: bool,
}

fn read_u16(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        data.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn read_u32(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        data.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn escape_label(bytes: &[u8]) -> String {
    let mut text = String::new();
    for &byte in bytes {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' => text.push(byte as char),
            _ => {
                let _ = write!(text, "\\x{byte:02x}");
            }
        }
    }
    text
}

pub fn read_dns_name(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut cursor = start;
    let mut next = None;
    let mut pointers = 0usize;
    let mut labels = Vec::new();
    let mut expanded_len = 0usize;
    let mut visited = [usize::MAX; MAX_POINTERS];
    loop {
        let size = *data.get(cursor)?;
        if size == 0 {
            let end = next.unwrap_or(cursor.checked_add(1)?);
            return Some((
                if labels.is_empty() {
                    ".".into()
                } else {
                    labels.join(".")
                },
                end,
            ));
        }
        match size & 0xc0 {
            0x00 => {
                if size > 63 || labels.len() >= MAX_LABELS {
                    return None;
                }
                let count = size as usize;
                let from = cursor.checked_add(1)?;
                let to = from.checked_add(count)?;
                let label = data.get(from..to)?;
                expanded_len = expanded_len.checked_add(count + 1)?;
                if expanded_len > MAX_NAME_LEN {
                    return None;
                }
                labels.push(escape_label(label));
                cursor = to;
            }
            0xc0 => {
                if pointers == MAX_POINTERS {
                    return None;
                }
                let next_byte = *data.get(cursor.checked_add(1)?)?;
                let target = (((size & 0x3f) as usize) << 8) | next_byte as usize;
                if visited[..pointers].contains(&target) || target >= data.len() {
                    return None;
                }
                visited[pointers] = target;
                pointers += 1;
                if next.is_none() {
                    next = cursor.checked_add(2);
                }
                cursor = target;
            }
            _ => return None,
        }
    }
}

pub fn record_type_label(n: u16) -> String {
    match n {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        41 => "OPT".into(),
        65 => "HTTPS".into(),
        255 => "ANY".into(),
        other => format!("TYPE{other}"),
    }
}

fn decode_rdata(packet: &[u8], start: usize, end: usize, kind: u16) -> Option<String> {
    let bytes = packet.get(start..end)?;
    match kind {
        1 if bytes.len() == 4 => {
            Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string())
        }
        28 if bytes.len() == 16 => {
            Some(Ipv6Addr::from(<[u8; 16]>::try_from(bytes).ok()?).to_string())
        }
        2 | 5 | 12 => {
            let (name, consumed) = read_dns_name(packet, start)?;
            if consumed > end {
                return None;
            }
            Some(name)
        }
        15 if bytes.len() >= 3 => {
            let priority = read_u16(packet, start)?;
            let (name, consumed) = read_dns_name(packet, start + 2)?;
            if consumed > end {
                return None;
            }
            Some(format!("{priority} {name}"))
        }
        16 => {
            let mut pos = 0usize;
            let mut parts = Vec::new();
            while pos < bytes.len() {
                let len = *bytes.get(pos)? as usize;
                pos += 1;
                let val = bytes.get(pos..pos.checked_add(len)?)?;
                pos += len;
                if parts.len() < 4 {
                    let mut text = escape_label(val);
                    text.truncate(192.min(text.len()));
                    parts.push(format!("\"{text}\""));
                }
            }
            Some(parts.join(" "))
        }
        _ => Some(format!("{} byte(s) of RDATA", bytes.len())),
    }
}

pub fn parse_dns(data: &[u8]) -> Option<DnsSummary> {
    if data.len() < 12 || data.len() > MAX_DNS_PACKET {
        return None;
    }
    let id = read_u16(data, 0)?;
    let flags = read_u16(data, 2)?;
    let questions = read_u16(data, 4)?;
    let answers = read_u16(data, 6)?;
    // The DNS header supports far larger counts, but our bounded inspector
    // cannot safely walk arbitrary numbers of variable-length questions.
    if questions as usize > MAX_QUESTIONS {
        return None;
    }
    let mut cursor = 12usize;
    let mut first_question = None;
    for i in 0..questions {
        let (name, after_name) = read_dns_name(data, cursor)?;
        let record_type = read_u16(data, after_name)?;
        let class = read_u16(data, after_name.checked_add(2)?)?;
        cursor = after_name.checked_add(4)?;
        if i == 0 {
            first_question = Some(DnsQuestion {
                name,
                record_type,
                class,
            });
        }
    }
    let mut answer_records = Vec::new();
    for _ in 0..answers.min(MAX_ANSWERS as u16) {
        let (name, after_name) = read_dns_name(data, cursor)?;
        let record_type = read_u16(data, after_name)?;
        let class = read_u16(data, after_name.checked_add(2)?)?;
        let ttl_seconds = read_u32(data, after_name.checked_add(4)?)?;
        let len = read_u16(data, after_name.checked_add(8)?)? as usize;
        let start = after_name.checked_add(10)?;
        let end = start.checked_add(len)?;
        data.get(start..end)?;
        let value = decode_rdata(data, start, end, record_type)?;
        answer_records.push(DnsAnswer {
            name,
            record_type,
            class,
            ttl_seconds,
            value,
        });
        cursor = end;
    }
    Some(DnsSummary {
        transaction_id: id,
        is_response: flags & 0x8000 != 0,
        response_code: (flags & 0xf) as u8,
        questions,
        answers,
        first_question,
        answer_records,
        answers_limited: answers as usize > MAX_ANSWERS,
    })
}

pub fn describe_dns(dns: &DnsSummary) -> String {
    let kind = if dns.is_response { "response" } else { "query" };
    let question = dns
        .first_question
        .as_ref()
        .map(|q| format!("{} {}", q.name, record_type_label(q.record_type)))
        .unwrap_or_else(|| "(no question)".into());
    let answer = dns
        .answer_records
        .first()
        .map(|r| {
            format!(
                "; {} {} = {}",
                r.name,
                record_type_label(r.record_type),
                r.value
            )
        })
        .unwrap_or_default();
    format!(
        "DNS {kind} id=0x{:04x} {question}, {} answer(s), rcode={}{}{}",
        dns.transaction_id,
        dns.answers,
        dns.response_code,
        answer,
        if dns.answers_limited {
            " (answers capped)"
        } else {
            ""
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_bytes() -> Vec<u8> {
        let mut out = vec![0x11, 0x22, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        out.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        out
    }

    fn response_prefix(kind: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
        let mut data = query_bytes();
        data[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
        data[6..8].copy_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&[0xc0, 0x0c]);
        data.extend_from_slice(&kind.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&ttl.to_be_bytes());
        data.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        data.extend_from_slice(rdata);
        data
    }

    #[test]
    fn reads_standard_dns_query() {
        let dns = parse_dns(&query_bytes()).unwrap();
        assert_eq!(dns.transaction_id, 0x1122);
        assert_eq!(dns.first_question.as_ref().unwrap().name, "example.com");
        assert!(describe_dns(&dns).contains("query"));
    }

    #[test]
    fn compression_pointer_and_offset_are_safe() {
        let response = response_prefix(1, 60, &[127, 0, 0, 1]);
        let dns = parse_dns(&response).unwrap();
        assert!(dns.is_response);
        assert_eq!(dns.answer_records[0].name, "example.com");
        assert_eq!(dns.answer_records[0].value, "127.0.0.1");
        assert_eq!(dns.answer_records[0].ttl_seconds, 60);
        assert!(describe_dns(&dns).contains("127.0.0.1"));
        let pointer_at = response.len() - 16;
        let (name, _) = read_dns_name(&response, pointer_at).unwrap();
        assert_eq!(name, "example.com");
    }

    #[test]
    fn parses_aaaa_cname_and_mx_answers() {
        let ipv6 = response_prefix(28, 42, &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(parse_dns(&ipv6).unwrap().answer_records[0].value, "::1");
        let cname = response_prefix(5, 99, b"\x04mail\xc0\x0c");
        assert_eq!(
            parse_dns(&cname).unwrap().answer_records[0].value,
            "mail.example.com"
        );
        let mx = response_prefix(15, 12, b"\x00\x0a\x04mail\xc0\x0c");
        assert_eq!(
            parse_dns(&mx).unwrap().answer_records[0].value,
            "10 mail.example.com"
        );
    }

    #[test]
    fn malformed_answers_are_rejected_not_truncated_to_succeed() {
        let mut response = response_prefix(1, 60, &[127, 0, 0, 1]);
        response.pop();
        assert!(parse_dns(&response).is_none());
        let mut looping = response_prefix(5, 99, b"\xc0\x00");
        let pos = looping.len() - 2;
        looping[pos + 1] = pos as u8;
        assert!(parse_dns(&looping).is_none());
    }

    #[test]
    fn answer_count_is_bounded_without_overread() {
        let mut response = response_prefix(1, 60, &[127, 0, 0, 1]);
        response[6..8].copy_from_slice(&1000u16.to_be_bytes());
        // 1 answer and an excessive advertised count: failing closed is safer
        // than reporting a fabricated complete response.
        assert!(parse_dns(&response).is_none());
        let mut data = query_bytes();
        data[4..6].copy_from_slice(&100u16.to_be_bytes());
        assert!(parse_dns(&data).is_none());
    }

    #[test]
    fn rejects_pointer_cycles_and_out_of_range_pointers() {
        let mut data = query_bytes();
        data[12] = 0xc0;
        data[13] = 12;
        assert!(parse_dns(&data).is_none());
        data[13] = 255;
        assert!(parse_dns(&data).is_none());
        data[12] = 0x80;
        assert!(parse_dns(&data).is_none());
    }

    #[test]
    fn malformed_questions_and_labels_are_rejected() {
        assert!(parse_dns(&query_bytes()[..11]).is_none());
        let mut data = query_bytes();
        data.truncate(16);
        assert!(parse_dns(&data).is_none());
        let mut long = vec![0u8; 12];
        long[4] = 0;
        long[5] = 1;
        for label in [b'a', b'b', b'c', b'd'] {
            long.push(63);
            long.extend_from_slice(&[label; 63]);
        }
        long.extend_from_slice(&[0, 0, 1, 0, 1]);
        assert!(parse_dns(&long).is_none());
    }
}
