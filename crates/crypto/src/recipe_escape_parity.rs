//! Bounded string escaping parity with CyberDeck's legacy TypeScript Recipes.

const LIMIT: usize = 8 * 1024 * 1024;

fn push(dst: &mut Vec<u8>, chunk: &[u8]) -> Result<(), String> {
    if dst
        .len()
        .checked_add(chunk.len())
        .is_none_or(|size| size > LIMIT)
    {
        return Err("recipe output size limit exceeded".into());
    }
    dst.extend_from_slice(chunk);
    Ok(())
}

fn escape_string(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for ch in String::from_utf8_lossy(input).chars() {
        match ch {
            '\\' => push(&mut out, b"\\\\")?,
            '"' => push(&mut out, b"\\\"")?,
            '\n' => push(&mut out, b"\\n")?,
            '\r' => push(&mut out, b"\\r")?,
            '\t' => push(&mut out, b"\\t")?,
            ch => {
                let mut buf = [0; 4];
                push(&mut out, ch.encode_utf8(&mut buf).as_bytes())?;
            }
        }
    }
    Ok(out)
}

fn unescape_string(input: &[u8]) -> Result<Vec<u8>, String> {
    // Mirror legacy JavaScript: wrap input in JSON quotes after
    // escaping real newlines/carriage returns and literal double quotes.
    // Invalid backslash escape sequences remain errors.
    let mut literal = Vec::new();
    push(&mut literal, b"\"")?;
    for ch in String::from_utf8_lossy(input).chars() {
        match ch {
            '\n' => push(&mut literal, b"\\n")?,
            '\r' => push(&mut literal, b"\\r")?,
            '"' => push(&mut literal, b"\\\"")?,
            ch => {
                let mut buf = [0; 4];
                push(&mut literal, ch.encode_utf8(&mut buf).as_bytes())?;
            }
        }
    }
    push(&mut literal, b"\"")?;
    let decoded: String = serde_json::from_slice(&literal)
        .map_err(|error| format!("invalid escaped string: {error}"))?;
    if decoded.len() > LIMIT {
        return Err("recipe output size limit exceeded".into());
    }
    Ok(decoded.into_bytes())
}

pub(crate) fn supports(id: &str) -> bool {
    matches!(id, "escape_string" | "unescape_string")
}

pub(crate) fn apply(id: &str, input: &[u8]) -> Result<Vec<u8>, String> {
    match id {
        "escape_string" => escape_string(input),
        "unescape_string" => unescape_string(input),
        _ => Err("unknown escape recipe operation".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn escaping_reference_fixtures() {
        assert_eq!(
            escape_string(b"hello\n\"a\"\t\\").unwrap(),
            b"hello\\n\\\"a\\\"\\t\\\\"
        );
        assert_eq!(
            unescape_string(b"hello\\nworld\\t").unwrap(),
            b"hello\nworld\t"
        );
        assert_eq!(unescape_string(b"\\u0041\\n").unwrap(), b"A\n");
        // Preserve the legacy JS JSON.parse failure for backslash-escaped quotes.
        assert!(unescape_string(b"hello\\n\\\"a\\\"\\t\\\\").is_err());
        assert!(unescape_string(b"not\\qvalid").is_err());
    }
    #[test]
    fn expansion_cap() {
        assert!(escape_string(&vec![b'\n'; 5_000_000]).is_err());
        assert!(unescape_string(&vec![b'a'; LIMIT + 1]).is_err());
    }
}
