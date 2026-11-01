//! Bounded, dependency-free IOC extraction for native Recipes parity.
//! These find candidates in operator-supplied text; no network requests occur.

const LIMIT: usize = 8 * 1024 * 1024;

fn push(dst: &mut Vec<u8>, piece: &[u8]) -> Result<(), String> {
    if dst
        .len()
        .checked_add(piece.len())
        .is_none_or(|size| size > LIMIT)
    {
        return Err("recipe output size limit exceeded".into());
    }
    dst.extend_from_slice(piece);
    Ok(())
}

fn append_line(out: &mut Vec<u8>, value: &str) -> Result<(), String> {
    if !out.is_empty() {
        push(out, b"\n")?;
    }
    push(out, value.as_bytes())
}

fn extract_urls(input: &[u8]) -> Result<Vec<u8>, String> {
    let source = String::from_utf8_lossy(input);
    let mut at = 0;
    let mut out = Vec::new();
    while at < source.len() {
        let rest = &source[at..];
        let prefix = if rest.starts_with("https://") {
            Some(8)
        } else if rest.starts_with("http://") {
            Some(7)
        } else {
            None
        };
        if let Some(prefix_len) = prefix {
            let mut end = prefix_len;
            for ch in rest[prefix_len..].chars() {
                // Matches the JS /[^\s"'<>]+/ class, including Unicode whitespace.
                if ch.is_whitespace() || ch == '\u{feff}' || matches!(ch, '"' | '\'' | '<' | '>') {
                    break;
                }
                end += ch.len_utf8();
            }
            if end > prefix_len {
                append_line(&mut out, &rest[..end])?;
                at += end;
                continue;
            }
        }
        at += rest
            .chars()
            .next()
            .expect("valid string boundary")
            .len_utf8();
    }
    Ok(out)
}

fn word_byte(value: u8) -> bool {
    value.is_ascii_alphanumeric() || value == b'_'
}

/// Mirrors JS \b + (25[0-5]|2[0-4]\d|1?\d?\d) octets with dots.
/// Two-digit leading zeros are accepted; three-digit octets must start 1 or 2.
fn ipv4_at(bytes: &[u8], index: usize) -> Option<usize> {
    if index > 0 && word_byte(bytes[index - 1]) {
        return None;
    }
    let mut at = index;
    for octet_index in 0..4 {
        let start = at;
        let mut value = 0u16;
        while at < bytes.len() && bytes[at].is_ascii_digit() && at - start < 3 {
            value = value * 10 + u16::from(bytes[at] - b'0');
            at += 1;
        }
        let count = at - start;
        if count == 0 || value > 255 || (count == 3 && !matches!(bytes[start], b'1' | b'2')) {
            return None;
        }
        if octet_index < 3 {
            if bytes.get(at) != Some(&b'.') {
                return None;
            }
            at += 1;
        }
    }
    if at < bytes.len() && word_byte(bytes[at]) {
        return None;
    }
    Some(at)
}

fn extract_ips(input: &[u8]) -> Result<Vec<u8>, String> {
    let source = String::from_utf8_lossy(input);
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < bytes.len() {
        if bytes[at].is_ascii_digit() {
            if let Some(end) = ipv4_at(bytes, at) {
                if !out.is_empty() {
                    push(&mut out, b"\n")?;
                }
                push(&mut out, &bytes[at..end])?;
                at = end;
                continue;
            }
        }
        at += 1;
    }
    Ok(out)
}

pub(crate) fn supports(id: &str) -> bool {
    matches!(id, "extract_urls" | "extract_ips")
}

pub(crate) fn apply(id: &str, input: &[u8]) -> Result<Vec<u8>, String> {
    match id {
        "extract_urls" => extract_urls(input),
        "extract_ips" => extract_ips(input),
        _ => Err("unknown IOC recipe operation".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_extraction_fixture() {
        assert_eq!(
            extract_urls(
                "Visit http://example.org/a?x=1; https://t.example/ok\nbad HTTP://BAD".as_bytes()
            )
            .unwrap(),
            b"http://example.org/a?x=1;\nhttps://t.example/ok"
        );
        assert_eq!(extract_urls(b"http:// https://"), Ok(Vec::new()));
        assert_eq!(
            extract_urls(b"https://x\"suffix http://y<>").unwrap(),
            b"https://x\nhttp://y"
        );
    }

    #[test]
    fn ipv4_boundary_and_range_fixture() {
        assert_eq!(
            extract_ips(b"127.0.0.1 256.2.3.4 001.002.003.004 8.8.8.8! 1x8.8.4.4").unwrap(),
            b"127.0.0.1\n8.8.8.8"
        );
        assert_eq!(
            extract_ips(b"250.255.0.9 255.256.0.1").unwrap(),
            b"250.255.0.9"
        );
    }

    #[test]
    fn production_recipe_dispatch_preserves_reference_matches() {
        use base64::Engine as _;
        let examples = [
            (
                "extract_urls",
                "Visit http://example.org/a?x=1; https://t.example/ok\nbad HTTP://BAD",
                "http://example.org/a?x=1;\nhttps://t.example/ok",
            ),
            (
                "extract_ips",
                "127.0.0.1 256.2.3.4 001.002.003.004 8.8.8.8! 1x8.8.4.4",
                "127.0.0.1\n8.8.8.8",
            ),
        ];
        for (id, source, expected) in examples {
            assert!(crate::recipes::native_operation(id));
            let result = crate::recipes::execute_recipe(
                source,
                &[crate::recipes::RecipeStep {
                    op_id: id.into(),
                    enabled: true,
                    param: None,
                }],
            );
            assert!(result.error.is_none(), "{id}: {:?}", result.error);
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(result.output_b64)
                .unwrap();
            assert_eq!(bytes, expected.as_bytes(), "{id} JS reference parity");
        }
    }

    #[test]
    fn bounded_extraction_large_fixture() {
        assert!(extract_ips(&"1.1.1.1 ".repeat(1_300_000).into_bytes()).is_err());
        assert!(extract_urls(&"http://x ".repeat(1_000_000).into_bytes()).is_err());
    }
}
