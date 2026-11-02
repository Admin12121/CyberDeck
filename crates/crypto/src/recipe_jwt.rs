//! Offline, bounded JWT display decoding. No signature verification, token
//! trust decision or network interaction is performed by this recipe.
use base64::Engine as _;
const MAX: usize = 8 * 1024 * 1024;

fn decode_piece(source: &str) -> Result<Vec<u8>, String> {
    // Browser TextDecoder and atob reference behavior: ignore whitespace and
    // tolerate omitted or up to two trailing Base64URL padding characters.
    let clean: String = source.chars().filter(|c| !c.is_whitespace() && *c != '\u{feff}').collect();
    if clean.len() > MAX || clean.as_bytes().iter().any(|b| !b.is_ascii_alphanumeric() && !matches!(*b, b'-' | b'_' | b'=')) {
        return Err("input is not valid Base64URL".into());
    }
    let bare = clean.trim_end_matches('=');
    if clean.len() - bare.len() > 2 || bare.contains('=') {
        return Err("input is not valid Base64URL".into());
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(bare.as_bytes()).map_err(|_| "input is not valid Base64URL")?;
    if decoded.len() > MAX {
        return Err("recipe output size limit exceeded".into());
    }
    Ok(decoded)
}

fn printable_json(label: &str, bytes: &[u8]) -> Result<String, String> {
    let raw = String::from_utf8_lossy(bytes);
    let rendered = match serde_json::from_str::<serde_json::Value>(&raw) {
        Ok(value) => serde_json::to_string_pretty(&value)
            .map_err(|_| "JSON display serialization failed")?,
        Err(_) => raw.into_owned(),
    };
    if rendered.len() > MAX {
        return Err("recipe output size limit exceeded".into());
    }
    Ok(format!("// {label}\n{rendered}"))
}

pub(crate) fn decode(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.len() > MAX {
        return Err("recipe input size limit exceeded".into());
    }
    let source = String::from_utf8_lossy(input);
    let parts: Vec<&str> = source.trim().split('.').collect();
    if parts.len() < 2 {
        return Err("JWT needs at least header.payload".into());
    }
    let header = decode_piece(parts[0])?;
    let payload = decode_piece(parts[1])?;
    let mut output = printable_json("header", &header)?;
    output.push_str("\n\n");
    output.push_str(&printable_json("payload", &payload)?);
    if let Some(signature) = parts.get(2).filter(|part| !part.is_empty()) {
        let signature = decode_piece(signature)?;
        output.push_str("\n\n// signature (hex)\n");
        output.push_str(&hex::encode(signature));
    }
    if output.len() > MAX {
        return Err("recipe output size limit exceeded".into());
    }
    Ok(output.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn jwt_reference_render_and_signature() {
        let enc = |value: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value);
        let token = format!("{}.{}.AQID", enc(r#"{"typ":"JWT","alg":"HS256"}"#), enc(r#"{"sub":"123","admin":false}"#));
        let rendered = String::from_utf8(decode(token.as_bytes()).unwrap()).unwrap();
        assert_eq!(rendered, "// header\n{\n  \"typ\": \"JWT\",\n  \"alg\": \"HS256\"\n}\n\n// payload\n{\n  \"sub\": \"123\",\n  \"admin\": false\n}\n\n// signature (hex)\n010203");
        let result = crate::recipes::execute_recipe(&token, &[crate::recipes::RecipeStep {
            op_id: "jwt_decode".into(), enabled: true, param: None,
        }]);
        assert!(result.error.is_none(), "{:?}", result.error);
        assert_eq!(base64::engine::general_purpose::STANDARD.decode(result.output_b64).unwrap(), rendered.as_bytes());
    }
    #[test]
    fn jwt_invalid_segments_and_size_limit_fail_closed() {
        assert!(decode(b"not.a.jwt token").is_err());
        assert!(decode(b"onlyone").is_err());
        assert!(decode(b"!!.e30").is_err());
        assert!(decode(&vec![b'a'; MAX + 1]).is_err());
        // A JWT decode recipe is a display operation, never a validation claim.
        assert_eq!(decode(b"e30.e30").unwrap(), b"// header\n{}\n\n// payload\n{}");
    }
}
