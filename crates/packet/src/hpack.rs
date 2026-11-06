//! Bounded HPACK (RFC 7541) header decoding for HTTP/2 HEADERS frames.
//!
//! Guard rails, in the house style: every length is validated against fixed
//! bounds before use, malformed or truncated input yields typed errors (never
//! a panic), and nothing is ever guessed. Two honesty rules shape the output:
//!
//! * The dynamic table is connection state carried in earlier traffic, not in
//!   this capture segment, so it cannot be reconstructed here. A dynamic-table
//!   reference therefore degrades to `dynamic table entry N (state unavailable)`
//!   instead of inventing a name or value.
//! * Huffman-coded string literals are not decoded on this arc. A literal that
//!   carries a Huffman string degrades to the explicit placeholder
//!   `<Huffman-encoded (not decoded)>` rather than failing the block or
//!   pretending the text is known.
//!
//! Only the static table (RFC 7541 Appendix A, 61 entries) resolves indices.

/// Hard cap on decoded headers per block.
pub const MAX_HEADERS: usize = 32;
/// Hard cap on a single header name, in bytes.
pub const MAX_NAME_BYTES: usize = 256;
/// Hard cap on a single header value, in bytes.
pub const MAX_VALUE_BYTES: usize = 256;
/// Hard cap on the whole header block, in bytes.
pub const MAX_BLOCK_BYTES: usize = 4096;
/// Largest index still treated as a plausible table reference; anything above
/// cannot exist even at the maximum dynamic-table size and is refused.
const MAX_TABLE_INDEX: u64 = 4096;
/// Placeholder shown for Huffman-coded strings, which this decoder does not
/// expand. Wording is part of the honesty contract surfaced in the UI.
pub const HUFFMAN_PLACEHOLDER: &str = "<Huffman-encoded (not decoded)>";

/// Why a header block could not be (fully) decoded. Every variant is a bound
/// or a structural refusal; none of them panic or truncate silently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HpackError {
    /// The header block exceeds the per-segment decoding bound.
    BlockTooLarge { size: usize, max: usize },
    /// The block holds more headers than the caller's cap allows.
    TooManyHeaders { max: usize },
    /// A name or value exceeds its byte bound.
    StringTooLong {
        field: &'static str,
        size: u64,
        max: usize,
    },
    /// The block ends, or the declared length runs past, before a field
    /// completes — the usual capture-boundary situation.
    Truncated { detail: &'static str, at: usize },
    /// An integer continuation run never terminates within the bound.
    IntegerOverflow { at: usize },
    /// An indexed reference points at index 0 (a decoding error per RFC 7541)
    /// or beyond any plausible table.
    InvalidIndex { index: u64 },
}

impl std::fmt::Display for HpackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BlockTooLarge { size, max } => write!(
                f,
                "HPACK header block is {size} bytes, above the {max}-byte decoding bound"
            ),
            Self::TooManyHeaders { max } => {
                write!(f, "HPACK header block holds more than {max} headers")
            }
            Self::StringTooLong { field, size, max } => write!(
                f,
                "HPACK {field} is {size} bytes, above the {max}-byte bound"
            ),
            Self::Truncated { detail, at } => {
                write!(f, "HPACK block truncated: {detail} incomplete at byte {at}")
            }
            Self::IntegerOverflow { at } => {
                write!(f, "HPACK integer at byte {at} exceeds the decoding bound")
            }
            Self::InvalidIndex { index } => {
                write!(
                    f,
                    "HPACK index {index} is outside the decodable table range"
                )
            }
        }
    }
}

impl std::error::Error for HpackError {}

/// RFC 7541 Appendix A static table, entries for indices 1..=61.
/// Values shown here verbatim; the empty string is a real entry value.
const STATIC_TABLE: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

fn static_entry(index: u64) -> Option<(&'static str, &'static str)> {
    STATIC_TABLE.get(index.checked_sub(1)? as usize).copied()
}

/// RFC 7541 §5.1 variable-length integer. `prefix` is the already-read first
/// byte, `prefix_bits` the number of significant bits it carries (1..=8).
/// A continuation run is structurally capped at five bytes (35 bits), so any
/// longer run — never legitimate at our bounds — is an overflow error.
fn decode_integer(
    block: &[u8],
    pos: &mut usize,
    prefix: u8,
    prefix_bits: u32,
) -> Result<u64, HpackError> {
    let mask: u8 = if prefix_bits >= 8 {
        0xff
    } else {
        ((1u16 << prefix_bits) - 1) as u8
    };
    let mut value = u64::from(prefix & mask);
    if value < u64::from(mask) {
        return Ok(value);
    }
    let mut shift = 0u32;
    loop {
        let byte = *block.get(*pos).ok_or(HpackError::Truncated {
            detail: "integer",
            at: *pos,
        })?;
        *pos += 1;
        value += u64::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        if shift > 28 {
            return Err(HpackError::IntegerOverflow { at: *pos });
        }
    }
}

/// A string literal as it sits in the block: either plain bytes or a
/// Huffman-coded string whose bytes are consumed but not expanded.
enum RawString {
    Plain(Vec<u8>),
    Huffman,
}

/// RFC 7541 §5.2 string literal: a Huffman flag plus a 7-bit-prefixed length,
/// then that many bytes. `field` names the role for bound violations.
fn decode_string(
    block: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<RawString, HpackError> {
    let first = *block.get(*pos).ok_or(HpackError::Truncated {
        detail: "string",
        at: *pos,
    })?;
    *pos += 1;
    let huffman = first & 0x80 != 0;
    let length = decode_integer(block, pos, first & 0x7f, 7)?;
    if length > MAX_VALUE_BYTES as u64 {
        return Err(HpackError::StringTooLong {
            field,
            size: length,
            max: MAX_VALUE_BYTES,
        });
    }
    let length = length as usize;
    if length > block.len().saturating_sub(*pos) {
        return Err(HpackError::Truncated {
            detail: "string",
            at: *pos,
        });
    }
    let bytes = block[*pos..*pos + length].to_vec();
    *pos += length;
    Ok(if huffman {
        RawString::Huffman
    } else {
        RawString::Plain(bytes)
    })
}

/// Render a decoded string for display. Plain bytes that are not valid UTF-8
/// are byte-escaped losslessly (`\xNN`) rather than guessed at or replaced.
fn finish_string(raw: RawString) -> String {
    match raw {
        RawString::Huffman => HUFFMAN_PLACEHOLDER.to_owned(),
        RawString::Plain(bytes) => match std::str::from_utf8(&bytes) {
            Ok(text) => text.to_owned(),
            Err(_) => bytes.iter().map(|b| format!("\\x{b:02x}")).collect(),
        },
    }
}

/// One literal header (RFC 7541 §6.2): an optional indexed or literal name
/// followed by a literal value. A dynamic-table name index degrades to the
/// honest unavailable marker; the value, which is genuinely present in the
/// block, is still decoded.
fn decode_literal(
    block: &[u8],
    pos: &mut usize,
    prefix: u8,
    prefix_bits: u32,
) -> Result<(String, String), HpackError> {
    let name = if prefix == 0 {
        finish_string(decode_string(block, pos, "name")?)
    } else {
        let index = decode_integer(block, pos, prefix, prefix_bits)?;
        if index == 0 || index > MAX_TABLE_INDEX {
            return Err(HpackError::InvalidIndex { index });
        }
        match static_entry(index) {
            Some((name, _)) => name.to_owned(),
            None => format!("dynamic table entry {index} (state unavailable)"),
        }
    };
    let value = finish_string(decode_string(block, pos, "value")?);
    Ok((name, value))
}

/// Resolve an indexed header field (RFC 7541 §6.1). Static indices decode
/// directly; dynamic indices — state the segment cannot carry — degrade to an
/// honest marker pair instead of a guessed header.
fn push_indexed(headers: &mut Vec<(String, String)>, index: u64) -> Result<(), HpackError> {
    if index == 0 || index > MAX_TABLE_INDEX {
        return Err(HpackError::InvalidIndex { index });
    }
    if let Some((name, value)) = static_entry(index) {
        headers.push((name.to_owned(), value.to_owned()));
    } else {
        headers.push((
            format!("dynamic table entry {index}"),
            "(state unavailable)".into(),
        ));
    }
    Ok(())
}

/// Decode a bounded HPACK header block from a single captured segment.
///
/// `max_headers` is clamped to [`MAX_HEADERS`]; a block holding more headers
/// than the clamped cap is refused with [`HpackError::TooManyHeaders`]. The
/// block itself must fit in [`MAX_BLOCK_BYTES`], each name in
/// [`MAX_NAME_BYTES`] and each value in [`MAX_VALUE_BYTES`]. Static-table
/// entries decode exactly; dynamic-table references and Huffman strings
/// degrade honestly as documented on the module. Any structural problem —
/// truncation at a capture boundary, an impossible index, an oversized field —
/// stops with a typed error and nothing partial is invented.
pub fn decode_header_block(
    block: &[u8],
    max_headers: usize,
) -> Result<Vec<(String, String)>, HpackError> {
    if block.len() > MAX_BLOCK_BYTES {
        return Err(HpackError::BlockTooLarge {
            size: block.len(),
            max: MAX_BLOCK_BYTES,
        });
    }
    let max_headers = max_headers.min(MAX_HEADERS);
    let mut headers = Vec::new();
    let mut pos = 0usize;
    while pos < block.len() {
        if headers.len() >= max_headers {
            return Err(HpackError::TooManyHeaders { max: max_headers });
        }
        let first = block[pos];
        pos += 1;
        if first & 0x80 != 0 {
            // §6.1 indexed header field (1xxxxxxx).
            let index = decode_integer(block, &mut pos, first & 0x7f, 7)?;
            push_indexed(&mut headers, index)?;
        } else if first & 0xc0 == 0x40 {
            // §6.2.1 literal with incremental indexing (01xxxxxx); entries are
            // not added to any dynamic table here, so later references to them
            // degrade to the unavailable marker.
            let header = decode_literal(block, &mut pos, first & 0x3f, 6)?;
            headers.push(header);
        } else if first & 0xe0 == 0x20 {
            // §6.3 dynamic table size update (001xxxxx). No dynamic table is
            // kept, so the new size is validated only as an integer and
            // consumes no header slot.
            let _size = decode_integer(block, &mut pos, first & 0x1f, 5)?;
        } else {
            // §6.2.2 literal without indexing (0000xxxx) and §6.2.3 literal
            // never indexed (0001xxxx) share the 4-bit name-index prefix.
            let header = decode_literal(block, &mut pos, first & 0x0f, 4)?;
            headers.push(header);
        }
    }
    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7541 C.1.1: 10 with a 5-bit prefix fits the prefix. `pos` starts
    /// past the already-read prefix byte.
    #[test]
    fn c1_integer_encoding_small_value_uses_prefix_only() {
        let mut pos = 1;
        assert_eq!(decode_integer(&[0x0a], &mut pos, 0x0a, 5).unwrap(), 10);
        assert_eq!(pos, 1);
    }

    /// RFC 7541 C.1.2: 1337 with a 5-bit prefix needs two continuations.
    #[test]
    fn c1_integer_encoding_1337_with_continuations() {
        let mut pos = 1;
        assert_eq!(
            decode_integer(&[0x1f, 0x9a, 0x0a], &mut pos, 0x1f, 5).unwrap(),
            1337
        );
        assert_eq!(pos, 3);
    }

    /// RFC 7541 C.1.3: 42 with an 8-bit prefix fits the prefix.
    #[test]
    fn c1_integer_encoding_42_with_8bit_prefix() {
        let mut pos = 1;
        assert_eq!(decode_integer(&[42], &mut pos, 42, 8).unwrap(), 42);
        assert_eq!(pos, 1);
    }

    /// A 256-byte string length (7-bit prefix) exercises the multi-byte path:
    /// 256 = 127 + 1 + 1*128.
    #[test]
    fn integer_256_needs_one_continuation_byte() {
        let mut pos = 1;
        assert_eq!(
            decode_integer(&[0x7f, 0x81, 0x01], &mut pos, 0x7f, 7).unwrap(),
            256
        );
        assert_eq!(pos, 3);
    }

    /// RFC 7541 C.2.1: a plain (non-Huffman) string literal decodes verbatim.
    #[test]
    fn c2_plain_string_literal_decodes_verbatim() {
        let mut block = [0u8; 1 + 15];
        block[0] = 15; // no Huffman flag, 7-bit prefix, length 15
        block[1..].copy_from_slice(b"www.example.com");
        let mut pos = 0;
        let raw = decode_string(&block, &mut pos, "name").unwrap();
        assert_eq!(finish_string(raw), "www.example.com");
        assert_eq!(pos, block.len());
    }

    /// RFC 7541 C.2.2-style: a Huffman-flagged string is consumed but never
    /// decoded; the placeholder states that honestly.
    #[test]
    fn c2_huffman_string_degrades_to_explicit_placeholder() {
        // "www.example.com" Huffman-coded is 0xd1 0x53 0x74 0x8e 0x8d 0x1f
        // 0x3b 0x3f 0x4c 0x7f in the RFC; the bytes are irrelevant here since
        // they must NOT be expanded — only the flag matters.
        let huffman = [0xd1, 0x53, 0x74, 0x8e, 0x8d, 0x1f, 0x3b, 0x3f, 0x4c, 0x7f];
        let mut block = vec![0x80 | huffman.len() as u8];
        block.extend_from_slice(&huffman);
        let mut pos = 0;
        let raw = decode_string(&block, &mut pos, "name").unwrap();
        assert_eq!(finish_string(raw), HUFFMAN_PLACEHOLDER);
        assert_eq!(pos, block.len(), "Huffman bytes must still be consumed");
    }

    /// RFC 7541 C.3.1: the whole header block is one indexed static entry.
    #[test]
    fn c3_indexed_static_field_decodes_from_static_table() {
        assert_eq!(
            decode_header_block(&[0x82], MAX_HEADERS).unwrap(),
            vec![(":method".to_owned(), "GET".to_owned())]
        );
        assert_eq!(
            decode_header_block(&[0x83], MAX_HEADERS).unwrap(),
            vec![(":method".to_owned(), "POST".to_owned())]
        );
        assert_eq!(
            decode_header_block(&[0x84], MAX_HEADERS).unwrap(),
            vec![(":path".to_owned(), "/".to_owned())]
        );
        assert_eq!(
            decode_header_block(&[0x87], MAX_HEADERS).unwrap(),
            vec![(":scheme".to_owned(), "https".to_owned())]
        );
        assert_eq!(
            decode_header_block(&[0x88], MAX_HEADERS).unwrap(),
            vec![(":status".to_owned(), "200".to_owned())]
        );
    }

    /// RFC 7541 C.3.2/C.4.2: literal "custom-key: custom-value" via the
    /// incremental-indexing (0x40) and no-indexing (0x00) instruction forms.
    #[test]
    fn c3_c4_literal_custom_header_decodes() {
        let custom = |first: u8| {
            let mut block = vec![first];
            block.push(b"custom-key".len() as u8);
            block.extend_from_slice(b"custom-key");
            block.push(b"custom-value".len() as u8);
            block.extend_from_slice(b"custom-value");
            decode_header_block(&block, MAX_HEADERS).unwrap()
        };
        assert_eq!(
            custom(0x40), // 01xxxxxx, new name, incremental indexing
            vec![("custom-key".to_owned(), "custom-value".to_owned())]
        );
        assert_eq!(
            custom(0x00), // 0000xxxx, new name, no indexing
            vec![("custom-key".to_owned(), "custom-value".to_owned())]
        );
        assert_eq!(
            custom(0x10), // 0001xxxx, new name, never indexed
            vec![("custom-key".to_owned(), "custom-value".to_owned())]
        );
    }

    /// RFC 7541 C.3-style round: a literal carrying a static-table name index
    /// (e.g. 0x4f = incremental indexing, name index 15, accept-charset).
    #[test]
    fn literal_with_static_name_index_uses_static_table_name() {
        let mut block = vec![0x4f]; // 01 001111: incremental, name index 15
        block.push(5);
        block.extend_from_slice(b"utf-8");
        assert_eq!(
            decode_header_block(&block, MAX_HEADERS).unwrap(),
            vec![("accept-charset".to_owned(), "utf-8".to_owned())]
        );
    }

    /// A dynamic-table index is connection state this segment cannot carry,
    /// so the reference degrades to the honest unavailable marker — the name
    /// and value are never guessed.
    #[test]
    fn dynamic_table_reference_degrades_to_honest_unavailable_marker() {
        // 0xbe = 1xxxxxxx, index 62: the first dynamic-table entry.
        assert_eq!(
            decode_header_block(&[0xbe], MAX_HEADERS).unwrap(),
            vec![(
                "dynamic table entry 62".to_owned(),
                "(state unavailable)".to_owned()
            )]
        );
    }

    /// A literal whose NAME comes from the dynamic table still shows the
    /// literal value, but the name is marked honestly unavailable.
    #[test]
    fn literal_with_dynamic_name_index_marks_name_unavailable_but_keeps_value() {
        // 0x7f: 01xxxxxx with a 6-bit prefix of all ones -> continuation byte
        // 0x30 contributes 48, so the name index is 63 + 48 = 111 (dynamic).
        let mut block = vec![0x7f, 0x30];
        block.push(b"token".len() as u8);
        block.extend_from_slice(b"token");
        assert_eq!(
            decode_header_block(&block, MAX_HEADERS).unwrap(),
            vec![(
                "dynamic table entry 111 (state unavailable)".to_owned(),
                "token".to_owned()
            )]
        );
    }

    /// §6.3 dynamic table size updates are consumed without producing a
    /// header and without erroring — no table is kept to update.
    #[test]
    fn dynamic_table_size_update_is_consumed_without_output() {
        // 0x3f 0x0a: 5-bit prefix all-ones + continuation 10 -> size 41.
        assert_eq!(
            decode_header_block(&[0x3f, 0x0a], MAX_HEADERS).unwrap(),
            vec![]
        );
    }

    /// A block cut mid-field is refused, not guessed: missing integer
    /// continuation, missing string body, and missing string length each
    /// yield the typed truncation error.
    #[test]
    fn truncated_blocks_are_refused_with_typed_errors() {
        // Indexed instruction whose integer continuation never arrives.
        assert_eq!(
            decode_header_block(&[0xff], MAX_HEADERS),
            Err(HpackError::Truncated {
                detail: "integer",
                at: 1
            })
        );
        // Literal instruction announcing a string that never arrives.
        assert_eq!(
            decode_header_block(&[0x40, 0x0a, b'a'], MAX_HEADERS),
            Err(HpackError::Truncated {
                detail: "string",
                at: 2
            })
        );
        // Literal instruction whose string length byte is missing.
        assert_eq!(
            decode_header_block(&[0x40], MAX_HEADERS),
            Err(HpackError::Truncated {
                detail: "string",
                at: 1
            })
        );
        // Declared string length runs past the end of the block.
        assert_eq!(
            decode_header_block(&[0x00, 0x8a, b'a', b'b', b'c'], MAX_HEADERS),
            Err(HpackError::Truncated {
                detail: "string",
                at: 2
            })
        );
    }

    /// Index 0 is a decoding error per RFC 7541 §6.1; an index beyond any
    /// plausible table is refused rather than fabricated.
    #[test]
    fn invalid_indices_are_refused() {
        assert_eq!(
            decode_header_block(&[0x80], MAX_HEADERS),
            Err(HpackError::InvalidIndex { index: 0 })
        );
        // 0xff 0x82 0x1f: 127 + 2 + 31*128 = 4097, past the table bound.
        assert_eq!(
            decode_header_block(&[0xff, 0x82, 0x1f], MAX_HEADERS),
            Err(HpackError::InvalidIndex { index: 4097 })
        );
        // A literal name index of 0 (0x41 has prefix value 1; force 0 via
        // the all-ones path is impossible for index 0, so use a 4-bit prefix:
        // 0x00 is new-name; the smallest indexed-name form is 0x01..0x0f, and
        // an explicit zero arrives through the continuation path only for
        // larger prefixes. Index 0 via 1xxxxxxx is covered above.)
    }

    /// Blocks and fields beyond the bounds are refused with typed errors.
    #[test]
    fn bounds_are_enforced_with_typed_errors() {
        // Whole block above the 4096-byte cap.
        let big = vec![0u8; MAX_BLOCK_BYTES + 1];
        assert_eq!(
            decode_header_block(&big, MAX_HEADERS),
            Err(HpackError::BlockTooLarge {
                size: big.len(),
                max: MAX_BLOCK_BYTES
            })
        );
        // A name of 257 bytes (127 + 2 + 1*128) is refused.
        let mut long_name = vec![0x00, 0x7f, 0x82, 0x01];
        long_name.extend(std::iter::repeat(b'a').take(257));
        assert_eq!(
            decode_header_block(&long_name, MAX_HEADERS),
            Err(HpackError::StringTooLong {
                field: "name",
                size: 257,
                max: MAX_NAME_BYTES
            })
        );
        // A value of 300 bytes (127 + 45 + 1*128) is refused.
        let mut long_value = vec![0x00, 0x03, b'a', b'b', b'c', 0x7f, 0xad, 0x01];
        long_value.extend(std::iter::repeat(b'v').take(300));
        assert_eq!(
            decode_header_block(&long_value, MAX_HEADERS),
            Err(HpackError::StringTooLong {
                field: "value",
                size: 300,
                max: MAX_VALUE_BYTES
            })
        );
    }

    /// The caller's header cap is enforced and clamped to the crate maximum.
    #[test]
    fn header_count_cap_is_enforced_and_clamped() {
        let three = [0x82, 0x83, 0x84];
        assert_eq!(
            decode_header_block(&three, 2),
            Err(HpackError::TooManyHeaders { max: 2 })
        );
        // A cap above the crate maximum is clamped to MAX_HEADERS (32): a
        // block with 33 headers must still be refused with max 32.
        let mut block = Vec::new();
        for index in 1..=33u64 {
            block.push(0x80 | index as u8);
        }
        assert_eq!(
            decode_header_block(&block, usize::MAX),
            Err(HpackError::TooManyHeaders { max: MAX_HEADERS })
        );
    }

    /// Static-table entries are name/value pairs shown verbatim, including
    /// the one non-empty encoding value and empty values.
    #[test]
    fn static_table_holds_all_61_entries_verbatim() {
        assert_eq!(STATIC_TABLE.len(), 61);
        assert_eq!(STATIC_TABLE[0], (":authority", ""));
        assert_eq!(STATIC_TABLE[1], (":method", "GET"));
        assert_eq!(STATIC_TABLE[2], (":method", "POST"));
        assert_eq!(STATIC_TABLE[3], (":path", "/"));
        assert_eq!(STATIC_TABLE[4], (":path", "/index.html"));
        assert_eq!(STATIC_TABLE[6], (":scheme", "https"));
        assert_eq!(STATIC_TABLE[13], (":status", "500"));
        assert_eq!(STATIC_TABLE[15], ("accept-encoding", "gzip, deflate"));
        assert_eq!(STATIC_TABLE[60], ("www-authenticate", ""));
        // Every index 1..=61 resolves; index 62 does not.
        for index in 1..=61u64 {
            assert!(
                static_entry(index).is_some(),
                "static index {index} missing"
            );
        }
        assert!(static_entry(62).is_none());
    }

    /// A whole C.3-style request block decodes in order, mixing indexed and
    /// literal instructions.
    #[test]
    fn c3_style_request_block_decodes_in_order() {
        // :method GET | custom-key: custom-value | :path /index.html
        let mut block = vec![0x82, 0x40];
        block.push(b"custom-key".len() as u8);
        block.extend_from_slice(b"custom-key");
        block.push(b"custom-value".len() as u8);
        block.extend_from_slice(b"custom-value");
        block.push(0x85); // :path /index.html
        assert_eq!(
            decode_header_block(&block, MAX_HEADERS).unwrap(),
            vec![
                (":method".to_owned(), "GET".to_owned()),
                ("custom-key".to_owned(), "custom-value".to_owned()),
                (":path".to_owned(), "/index.html".to_owned()),
            ]
        );
    }

    /// A literal header whose VALUE is Huffman-coded keeps the decoded name
    /// and degrades only the value, with no overclaimed text.
    #[test]
    fn literal_with_huffman_value_keeps_name_and_marks_value() {
        let mut block = vec![0x00, 0x04];
        block.extend_from_slice(b"host");
        block.push(0x80 | 9); // Huffman flag set, 9 encoded bytes
        block.extend_from_slice(&[0x41, 0x74, 0x17, 0x1a, 0x66, 0x3d, 0x6c, 0x62, 0x7f]);
        assert_eq!(
            decode_header_block(&block, MAX_HEADERS).unwrap(),
            vec![("host".to_owned(), HUFFMAN_PLACEHOLDER.to_owned())]
        );
    }

    /// A literal header whose NAME is Huffman-coded degrades the name and
    /// keeps the plain value.
    #[test]
    fn literal_with_huffman_name_marks_name_and_keeps_value() {
        let mut block = vec![0x00, 0x80 | 3];
        block.extend_from_slice(&[0x75, 0x9a, 0x7f]); // 3 Huffman bytes, not expanded
        block.push(5);
        block.extend_from_slice(b"value");
        assert_eq!(
            decode_header_block(&block, MAX_HEADERS).unwrap(),
            vec![(HUFFMAN_PLACEHOLDER.to_owned(), "value".to_owned())]
        );
    }

    /// Plain bytes that are not valid UTF-8 are escaped losslessly, never
    /// replaced with invented text.
    #[test]
    fn non_utf8_strings_are_byte_escaped_losslessly() {
        let mut block = vec![0x00, 0x03, 0xff, 0xfe, 0x01];
        block.push(1);
        block.extend_from_slice(b"x");
        assert_eq!(
            decode_header_block(&block, MAX_HEADERS).unwrap(),
            vec![("\\xff\\xfe\\x01".to_owned(), "x".to_owned())]
        );
    }

    /// An empty block decodes to zero headers — e.g. an empty HEADERS frame.
    #[test]
    fn empty_block_yields_no_headers() {
        assert_eq!(decode_header_block(&[], MAX_HEADERS).unwrap(), vec![]);
    }
}
