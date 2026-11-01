//! Additional recipe transformations matching the existing TypeScript catalog.
//! Keep this module dependency-free, bounded, and byte-preserving where applicable.

const LIMIT: usize = 8 * 1024 * 1024;
const LIMIT_ERROR: &str = "recipe output size limit exceeded";

pub(crate) fn supports(id: &str) -> bool {
    matches!(
        id,
        "hex_dump"
            | "from_hexdump"
            | "html_encode"
            | "html_decode"
            | "strip_html_tags"
            | "to_charcode"
            | "from_charcode"
    )
}

fn push(dst: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    if dst.len().checked_add(bytes.len()).is_none_or(|n| n > LIMIT) {
        return Err(LIMIT_ERROR.into());
    }
    dst.extend_from_slice(bytes);
    Ok(())
}

fn write_char(dst: &mut Vec<u8>, value: char) -> Result<(), String> {
    let mut buf = [0_u8; 4];
    push(dst, value.encode_utf8(&mut buf).as_bytes())
}

fn lossy(input: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(input)
}

/// TextEncoder and JS Array.from(text) operate on Unicode scalar values.
fn to_charcode(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for (i, ch) in lossy(input).chars().enumerate() {
        if i > 0 {
            push(&mut out, b" ")?;
        }
        push(&mut out, (ch as u32).to_string().as_bytes())?;
    }
    Ok(out)
}

/// JS String.fromCodePoint accepts surrogate integers, but TextEncoder then
/// emits U+FFFD for the unmatched surrogate.
fn from_charcode(input: &[u8]) -> Result<Vec<u8>, String> {
    let src = lossy(input);
    let mut out = Vec::new();
    for code in src
        .split(|ch: char| !ch.is_ascii_digit())
        .filter(|s| !s.is_empty())
    {
        let number: u32 = code.parse().map_err(|_| "invalid codepoint list")?;
        if number > 0x10ffff {
            return Err("invalid codepoint list".into());
        }
        write_char(&mut out, char::from_u32(number).unwrap_or('\u{fffd}'))?;
    }
    Ok(out)
}

fn html_encode(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for ch in lossy(input).chars() {
        match ch {
            '&' => push(&mut out, b"&amp;")?,
            '<' => push(&mut out, b"&lt;")?,
            '>' => push(&mut out, b"&gt;")?,
            '"' => push(&mut out, b"&quot;")?,
            '\'' => push(&mut out, b"&#39;")?,
            other => write_char(&mut out, other)?,
        }
    }
    Ok(out)
}

fn html_numeric_pass(input: &str, hex: bool) -> Result<String, String> {
    let mut output = String::new();
    let mut rest = input;
    while let Some(start) = rest.find('&') {
        if output.len().checked_add(start).is_none_or(|n| n > LIMIT) {
            return Err(LIMIT_ERROR.into());
        }
        output.push_str(&rest[..start]);
        rest = &rest[start..];
        let prefix = if hex { "&#x" } else { "&#" };
        if let Some(after) = rest.strip_prefix(prefix) {
            if let Some(end) = after.find(';') {
                let num = &after[..end];
                let valid = !num.is_empty()
                    && num.bytes().all(|b| {
                        if hex {
                            b.is_ascii_hexdigit()
                        } else {
                            b.is_ascii_digit()
                        }
                    });
                if valid {
                    let parsed = u32::from_str_radix(num, if hex { 16 } else { 10 })
                        .map_err(|_| "invalid HTML numeric entity")?;
                    if parsed > 0x10ffff {
                        return Err("invalid HTML numeric entity".into());
                    }
                    output.push(char::from_u32(parsed).unwrap_or('\u{fffd}'));
                    rest = &after[end + 1..];
                    if output.len() > LIMIT {
                        return Err(LIMIT_ERROR.into());
                    }
                    continue;
                }
            }
        }
        output.push('&');
        rest = &rest[1..];
    }
    if output
        .len()
        .checked_add(rest.len())
        .is_none_or(|n| n > LIMIT)
    {
        return Err(LIMIT_ERROR.into());
    }
    output.push_str(rest);
    Ok(output)
}

fn html_decode(input: &[u8]) -> Result<Vec<u8>, String> {
    let source = lossy(input);
    let hex = html_numeric_pass(&source, true)?;
    let decimal = html_numeric_pass(&hex, false)?;
    let mut out = Vec::new();
    let mut rest = decimal.as_str();
    while let Some(start) = rest.find('&') {
        push(&mut out, rest[..start].as_bytes())?;
        rest = &rest[start..];
        if let Some(end) = rest.find(';') {
            let name = &rest[1..end];
            // The TS source only matches one or more ASCII letters.
            if !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphabetic()) {
                let value = match name.to_ascii_lowercase().as_str() {
                    "amp" => Some("&"),
                    "lt" => Some("<"),
                    "gt" => Some(">"),
                    "quot" => Some("\""),
                    "apos" => Some("'"),
                    "nbsp" => Some(" "),
                    "copy" => Some("©"),
                    "reg" => Some("®"),
                    "hellip" => Some("…"),
                    "mdash" | "ndash" => Some("-"),
                    _ => None,
                };
                if let Some(value) = value {
                    push(&mut out, value.as_bytes())?;
                    rest = &rest[end + 1..];
                    continue;
                }
            }
        }
        push(&mut out, b"&")?;
        rest = &rest[1..];
    }
    push(&mut out, rest.as_bytes())?;
    Ok(out)
}

/// Mirrors /<[^>]*>/g: the first closing '>' wins; an unterminated '<'
/// remains unchanged, including across newlines.
fn strip_html_tags(input: &[u8]) -> Result<Vec<u8>, String> {
    let source = lossy(input);
    let mut rest = source.as_ref();
    let mut out = Vec::new();
    while let Some(at) = rest.find('<') {
        push(&mut out, rest[..at].as_bytes())?;
        let candidate = &rest[at + 1..];
        if let Some(end) = candidate.find('>') {
            rest = &candidate[end + 1..];
        } else {
            push(&mut out, rest[at..].as_bytes())?;
            return Ok(out);
        }
    }
    push(&mut out, rest.as_bytes())?;
    Ok(out)
}

fn hex_dump(input: &[u8], param: Option<&str>) -> Result<Vec<u8>, String> {
    // JS parseInt(param, 10) || 16, clamped to [4,64].
    let parsed = param
        .and_then(|s| s.trim_start().split(|ch: char| !ch.is_ascii_digit()).next())
        .and_then(|n| n.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(16);
    let width = parsed.clamp(4, 64);
    let mut out = Vec::new();
    for (index, chunk) in input.chunks(width).enumerate() {
        if index > 0 {
            push(&mut out, b"\n")?;
        }
        let offset = index.saturating_mul(width);
        push(&mut out, format!("{offset:08x}  ").as_bytes())?;
        for (at, byte) in chunk.iter().enumerate() {
            if at > 0 {
                push(&mut out, b" ")?;
            }
            push(&mut out, format!("{byte:02x}").as_bytes())?;
        }
        let width_chars = width * 3 - 1;
        let written = chunk.len() * 3 - 1;
        let padding = width_chars - written + 2;
        push(&mut out, &vec![b' '; padding])?;
        for &byte in chunk {
            push(
                &mut out,
                &[if (0x20..=0x7e).contains(&byte) {
                    byte
                } else {
                    b'.'
                }],
            )?;
        }
    }
    Ok(out)
}

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn from_hexdump(input: &[u8]) -> Result<Vec<u8>, String> {
    let source = lossy(input);
    let mut out = Vec::new();
    for raw in source.split('\n') {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let mut body = line;
        let no_prefix = body
            .strip_prefix("0x")
            .or_else(|| body.strip_prefix("0X"))
            .unwrap_or(body);
        let digits = no_prefix.bytes().take_while(u8::is_ascii_hexdigit).count();
        if (2..=16).contains(&digits) {
            let after = &no_prefix[digits..];
            let spaces = after
                .bytes()
                .take_while(|&b| b.is_ascii_whitespace() || b == b':')
                .count();
            if (1..=4).contains(&spaces) {
                body = &after[spaces..];
            }
        }
        // JS splits on the first 2+ consecutive whitespace characters.
        let bb = body.as_bytes();
        let mut end = bb.len();
        for at in 1..bb.len() {
            if bb[at].is_ascii_whitespace() && bb[at - 1].is_ascii_whitespace() {
                end = at - 1;
                break;
            }
        }
        let col = &bb[..end];
        for at in 0..col.len().saturating_sub(1) {
            if !col[at].is_ascii_hexdigit() || !col[at + 1].is_ascii_hexdigit() {
                continue;
            }
            let left = at == 0 || !is_word(col[at - 1]);
            let right = at + 2 == col.len() || !is_word(col[at + 2]);
            if left && right {
                let pair = std::str::from_utf8(&col[at..at + 2]).map_err(|_| "invalid hex dump")?;
                let byte = u8::from_str_radix(pair, 16).map_err(|_| "invalid hex dump")?;
                push(&mut out, &[byte])?;
            }
        }
    }
    Ok(out)
}

pub(crate) fn apply(id: &str, input: &[u8], param: Option<&str>) -> Result<Vec<u8>, String> {
    match id {
        "hex_dump" => hex_dump(input, param),
        "from_hexdump" => from_hexdump(input),
        "html_encode" => html_encode(input),
        "html_decode" => html_decode(input),
        "strip_html_tags" => strip_html_tags(input),
        "to_charcode" => to_charcode(input),
        "from_charcode" => from_charcode(input),
        _ => Err("unknown recipe parity operation".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_entities_and_tags_golden() {
        assert_eq!(
            apply("html_encode", "A<&\"'©".as_bytes(), None).unwrap(),
            b"A&lt;&amp;&quot;&#39;\xc2\xa9"
        );
        assert_eq!(
            apply(
                "html_decode",
                b"&LT;&amp;&#x1F600;&#169;&unknown;&mdash;",
                None
            )
            .unwrap(),
            "<&😀©&unknown;-".as_bytes()
        );
        assert_eq!(
            apply("strip_html_tags", b"<a>one\n<b>two</b>!</a><broken", None).unwrap(),
            b"one\ntwo!<broken"
        );
    }

    #[test]
    fn numeric_and_charcode_boundaries() {
        assert_eq!(
            apply("to_charcode", "A😀".as_bytes(), None).unwrap(),
            b"65 128512"
        );
        assert_eq!(
            apply("from_charcode", b"65, 128512", None).unwrap(),
            "A😀".as_bytes()
        );
        assert_eq!(
            apply("from_charcode", b"55296", None).unwrap(),
            "�".as_bytes()
        );
        assert!(apply("from_charcode", b"1114112", None).is_err());
        assert!(apply("html_decode", b"&#x110000;", None).is_err());
    }

    #[test]
    fn hex_dump_roundtrip_binary_and_widths() {
        let bytes = b"ABC\x00\xff!xyz";
        for width in [4, 16, 64] {
            let dump = hex_dump(bytes, Some(&width.to_string())).unwrap();
            assert_eq!(from_hexdump(&dump).unwrap(), bytes);
        }
        assert!(hex_dump(&vec![0x41; 3_000_000], Some("16")).is_err());
    }

    #[test]
    fn actual_recipe_dispatch_preserves_js_reference_vectors() {
        use base64::Engine as _;
        let examples = [
            ("html_encode", "A<&\"'©", "A&lt;&amp;&quot;&#39;©"),
            (
                "html_decode",
                "&LT;&amp;&#x1F600;&#169;&unknown;&mdash;",
                "<&😀©&unknown;-",
            ),
            (
                "strip_html_tags",
                "<a>one\n<b>two</b>!</a><broken",
                "one\ntwo!<broken",
            ),
            ("to_charcode", "A😀", "65 128512"),
            ("from_charcode", "65, 128512", "A😀"),
            (
                "from_hexdump",
                "00000000  41 42 43                                          ABC",
                "ABC",
            ),
            (
                "hex_dump",
                "ABC!xyz",
                "00000000  41 42 43 21 78 79 7a                             ABC!xyz",
            ),
        ];
        for (id, input, expected) in examples {
            assert!(super::supports(id), "{id} missing native registry");
            assert!(
                crate::recipes::native_operation(id),
                "{id} missing public dispatcher"
            );
            let result = crate::recipes::execute_recipe(
                input,
                &[crate::recipes::RecipeStep {
                    op_id: id.to_owned(),
                    enabled: true,
                    param: None,
                }],
            );
            assert!(result.error.is_none(), "{id}: {:?}", result.error);
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(result.output_b64)
                .unwrap();
            assert_eq!(
                bytes,
                expected.as_bytes(),
                "cross-language reference mismatch: {id}"
            );
        }
    }

    #[test]
    fn adversarial_bounded_input() {
        assert!(html_encode(&vec![b'&'; 2_000_000]).is_err());
        assert!(to_charcode(&vec![b'a'; 3_000_000]).is_err());
        assert!(strip_html_tags(&vec![b'x'; LIMIT + 1]).is_err());
        assert!(from_hexdump(&vec![b'0'; LIMIT + 1]).unwrap().len() <= LIMIT);
    }
}
