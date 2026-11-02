//! The native byte-oriented recipe engine.
//! This module implements CyberDeck's existing transformation semantics in Rust.
//! Unported operations continue to run in the TypeScript implementation until
//! reference and parity tests prove their Rust equivalents.

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Instant;

const MAX_RECIPE_BYTES: usize = 8 * 1024 * 1024;
const MAX_RECIPE_STEPS: usize = 64;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipeStep {
    pub op_id: String,
    pub enabled: bool,
    pub param: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipeFailure {
    pub step_index: usize,
    pub op_id: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeRecipeResult {
    pub output_b64: String,
    pub byte_length: usize,
    pub elapsed_ms: f64,
    pub error: Option<RecipeFailure>,
}

pub fn native_operation(id: &str) -> bool {
    matches!(
        id,
        "to_base64"
            | "from_base64"
            | "to_base64url"
            | "from_base64url"
            | "to_base32"
            | "url_encode"
            | "url_decode"
            | "defang"
            | "refang"
            | "from_base32"
            | "to_hex"
            | "from_hex"
            | "to_binary"
            | "from_binary"
            | "to_decimal"
            | "from_decimal"
            | "rot_n"
            | "rot13"
            | "rot47"
            | "atbash"
            | "xor"
            | "reverse"
            | "swap_endianness"
            | "rotate_bytes"
            | "bit_shift_left"
            | "bit_shift_right"
            | "to_uppercase"
            | "to_lowercase"
            | "trim_lines"
            | "add_line_numbers"
            | "unique_lines"
            | "reverse_lines"
            | "filter_lines"
            | "head_lines"
            | "tail_lines"
            | "text_split"
            | "find_replace"
            | "json_beautify"
            | "json_minify"
            | "slice_bytes"
            | "to_utf8"
            | "hex_dump"
            | "from_hexdump"
            | "html_encode"
            | "html_decode"
            | "strip_html_tags"
            | "to_charcode"
            | "from_charcode"
            | "vigenere"
            | "nato_encode"
            | "morse_encode"
            | "morse_decode"
            | "escape_string"
            | "unescape_string"
            | "extract_urls"
            | "extract_ips"
            | "extract_emails"
            | "extract_domains"
            | "jwt_decode"
    )
}

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 padded Base32, with a checked output size before allocation.
fn base32_encode(input: &[u8]) -> Result<Vec<u8>, String> {
    let required = input
        .len()
        .checked_add(4)
        .and_then(|n| n.checked_div(5))
        .and_then(|n| n.checked_mul(8))
        .ok_or("recipe output size limit exceeded")?;
    if required > MAX_RECIPE_BYTES {
        return Err("recipe output size limit exceeded".into());
    }
    let mut output = Vec::with_capacity(required);
    let mut value = 0u32;
    let mut bits = 0u32;
    for &byte in input {
        value = (value << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            output.push(BASE32_ALPHABET[((value >> (bits - 5)) & 31) as usize]);
            bits -= 5;
        }
    }
    if bits > 0 {
        output.push(BASE32_ALPHABET[((value << (5 - bits)) & 31) as usize]);
    }
    while output.len() % 8 != 0 {
        output.push(b'=');
    }
    Ok(output)
}

/// Mirror the TS decoder: uppercase input, ignore whitespace and '=' anywhere,
/// reject other characters and ignore incomplete trailing 5-bit groups.
fn base32_decode(input: &[u8]) -> Result<Vec<u8>, String> {
    let decoded = text(input);
    let mut output = Vec::with_capacity(input.len().saturating_mul(5) / 8);
    let mut value = 0u32;
    let mut bits = 0u32;
    for ch in decoded.chars().flat_map(char::to_uppercase) {
        if ch.is_whitespace() || ch == '\u{feff}' || ch == '=' {
            continue;
        }
        let digit = match ch {
            'A'..='Z' => u32::from(ch as u8 - b'A'),
            '2'..='7' => u32::from(ch as u8 - b'2') + 26,
            _ => return Err("input is not valid Base32".into()),
        };
        value = (value << 5) | digit;
        bits += 5;
        if bits >= 8 {
            output.push((value >> (bits - 8)) as u8);
            bits -= 8;
        }
    }
    Ok(output)
}

/// Match TS split(/\r?\n/) followed by right-aligned, 1-based line numbers.
fn add_line_numbers(input: &[u8]) -> Result<Vec<u8>, String> {
    let value = text(input);
    let line_count = value.split('\n').count();
    let width = line_count.to_string().len();
    let mut output = Vec::with_capacity(value.len().min(MAX_RECIPE_BYTES));
    for (i, raw) in value.split('\n').enumerate() {
        // The JS /\r?\n/ splitter consumes a CR only when adjacent to LF.
        let line = if i + 1 < line_count {
            raw.strip_suffix('\r').unwrap_or(raw)
        } else {
            raw
        };
        let number = (i + 1).to_string();
        let growth = usize::from(i > 0)
            .checked_add(width)
            .and_then(|n| n.checked_add(1))
            .and_then(|n| n.checked_add(line.len()))
            .ok_or("recipe output size limit exceeded")?;
        if output
            .len()
            .checked_add(growth)
            .is_none_or(|n| n > MAX_RECIPE_BYTES)
        {
            return Err("recipe output size limit exceeded".into());
        }
        if i > 0 {
            output.push(b'\n');
        }
        output.extend(std::iter::repeat_n(b' ', width - number.len()));
        output.extend_from_slice(number.as_bytes());
        output.push(b' ');
        output.extend_from_slice(line.as_bytes());
    }
    Ok(output)
}

fn url_encode(input: &[u8]) -> Result<Vec<u8>, String> {
    let source = text(input);
    let is_safe = |b: u8| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
            )
    };
    let mut required = 0usize;
    for &byte in source.as_bytes() {
        required = required
            .checked_add(if is_safe(byte) { 1 } else { 3 })
            .ok_or("recipe output size limit exceeded")?;
        if required > MAX_RECIPE_BYTES {
            return Err("recipe output size limit exceeded".into());
        }
    }
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = Vec::with_capacity(required);
    for &byte in source.as_bytes() {
        if is_safe(byte) {
            encoded.push(byte);
        } else {
            encoded.extend_from_slice(&[
                b'%',
                HEX[(byte >> 4) as usize],
                HEX[(byte & 15) as usize],
            ]);
        }
    }
    Ok(encoded)
}

fn url_decode(input: &[u8]) -> Result<Vec<u8>, String> {
    let source = text(input);
    if source.len() > MAX_RECIPE_BYTES {
        return Err("recipe output size limit exceeded".into());
    }
    let mut decoded = Vec::with_capacity(source.len());
    let bytes = source.as_bytes();
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'+' => decoded.push(b' '),
            b'%' => {
                if at + 2 >= bytes.len() {
                    return Err("URI malformed".into());
                }
                let nibble = |b: u8| match b {
                    b'0'..=b'9' => Some(b - b'0'),
                    b'a'..=b'f' => Some(b - b'a' + 10),
                    b'A'..=b'F' => Some(b - b'A' + 10),
                    _ => None,
                };
                let hi = nibble(bytes[at + 1]).ok_or("URI malformed")?;
                let lo = nibble(bytes[at + 2]).ok_or("URI malformed")?;
                decoded.push((hi << 4) | lo);
                at += 2;
            }
            byte => decoded.push(byte),
        }
        at += 1;
    }
    std::str::from_utf8(&decoded).map_err(|_| "URI malformed")?;
    Ok(decoded)
}

fn defang(input: &[u8]) -> Result<Vec<u8>, String> {
    let source = text(input);
    let replacements = source.bytes().filter(|c| *c == b'.' || *c == b'@').count();
    let upper_bound = source
        .len()
        .checked_add(
            replacements
                .checked_mul(2)
                .ok_or("recipe output size limit exceeded")?,
        )
        .ok_or("recipe output size limit exceeded")?;
    if upper_bound > MAX_RECIPE_BYTES {
        return Err("recipe output size limit exceeded".into());
    }
    let substituted = source.replace('.', "[.]").replace('@', "[@]");
    let mut output = String::with_capacity(substituted.len());
    let mut at = 0;
    while at < substituted.len() {
        let rest = &substituted[at..];
        if rest
            .get(..8)
            .is_some_and(|v| v.eq_ignore_ascii_case("https://"))
        {
            output.push_str(if rest.starts_with("https") {
                "hXXps://"
            } else {
                "hXXp://"
            });
            at += 8;
        } else if rest
            .get(..7)
            .is_some_and(|v| v.eq_ignore_ascii_case("http://"))
        {
            output.push_str("hXXp://");
            at += 7;
        } else {
            let ch = rest.chars().next().expect("valid text boundary");
            output.push(ch);
            at += ch.len_utf8();
        }
    }
    Ok(output.into_bytes())
}

fn refang(input: &[u8]) -> Result<Vec<u8>, String> {
    let source = text(input);
    if source.len() > MAX_RECIPE_BYTES {
        return Err("recipe output size limit exceeded".into());
    }
    let substituted = source
        .replace("[.]", ".")
        .replace("[@]", "@")
        .replace("(.)", ".");
    let mut output = String::with_capacity(substituted.len());
    let mut at = 0;
    while at < substituted.len() {
        let rest = &substituted[at..];
        let b = rest.as_bytes();
        if b.len() >= 7
            && b[0].eq_ignore_ascii_case(&b'h')
            && (b[1].eq_ignore_ascii_case(&b'x') || b[1] == b'*')
            && (b[2].eq_ignore_ascii_case(&b'x') || b[2] == b'*')
            && b[3].eq_ignore_ascii_case(&b'p')
        {
            let has_s = b.get(4).is_some_and(|v| v.eq_ignore_ascii_case(&b's'));
            let suffix = if has_s { 5 } else { 4 };
            if b.get(suffix..suffix + 3) == Some(b"://") {
                output.push_str(if has_s { "https://" } else { "http://" });
                at += suffix + 3;
                continue;
            }
        }
        let ch = rest.chars().next().expect("valid text boundary");
        output.push(ch);
        at += ch.len_utf8();
    }
    Ok(output.into_bytes())
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn number(param: Option<&str>, fallback: i64) -> i64 {
    param
        .and_then(|p| p.trim().parse::<i64>().ok())
        .filter(|n| *n != 0)
        .unwrap_or(fallback)
}

fn transform(op: &str, bytes: &[u8], param: Option<&str>) -> Result<Vec<u8>, String> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    if crate::recipe_native_parity::supports(op) {
        return crate::recipe_native_parity::apply(op, bytes, param);
    }
    if crate::recipe_text_parity::supports(op) {
        return crate::recipe_text_parity::apply(op, bytes, param);
    }
    if crate::recipe_escape_parity::supports(op) {
        return crate::recipe_escape_parity::apply(op, bytes);
    }
    if crate::recipe_ioc_parity::supports(op) {
        return crate::recipe_ioc_parity::apply(op, bytes);
    }
    if crate::recipe_ioc_extra::supports(op) {
        return crate::recipe_ioc_extra::apply(op, bytes);
    }
    if op == "jwt_decode" {
        return crate::recipe_jwt::decode(bytes);
    }
    match op {
        "to_base64" => Ok(STANDARD.encode(bytes).into_bytes()),
        "from_base64" => STANDARD
            .decode(text(bytes).split_whitespace().collect::<String>())
            .map_err(|_| "input is not valid Base64".to_string()),
        "to_base64url" => Ok(URL_SAFE_NO_PAD.encode(bytes).into_bytes()),
        "from_base64url" => URL_SAFE_NO_PAD
            .decode(
                text(bytes)
                    .split_whitespace()
                    .collect::<String>()
                    .trim_end_matches('='),
            )
            .map_err(|_| "input is not valid Base64URL".to_string()),
        "url_encode" => url_encode(bytes),
        "url_decode" => url_decode(bytes),
        "defang" => defang(bytes),
        "refang" => refang(bytes),
        "to_base32" => base32_encode(bytes),
        "from_base32" => base32_decode(bytes),
        "to_hex" => Ok(hex::encode(bytes).into_bytes()),
        "from_hex" => {
            let clean: String = text(bytes)
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .collect();
            if clean.len() % 2 != 0 {
                return Err("hex input has an odd number of digits".into());
            }
            hex::decode(clean).map_err(|e| e.to_string())
        }
        "to_binary" => Ok(bytes
            .iter()
            .map(|b| format!("{b:08b}"))
            .collect::<Vec<_>>()
            .join(" ")
            .into_bytes()),
        "from_binary" => {
            let clean: Vec<u8> = bytes
                .iter()
                .filter(|b| **b == b'0' || **b == b'1')
                .copied()
                .collect();
            if clean.len() % 8 != 0 {
                return Err("binary input length must be a multiple of 8".into());
            }
            clean
                .chunks(8)
                .map(|chunk| {
                    let s = std::str::from_utf8(chunk).expect("ASCII binary digits");
                    u8::from_str_radix(s, 2).map_err(|e| e.to_string())
                })
                .collect()
        }
        "to_decimal" => Ok(bytes
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(" ")
            .into_bytes()),
        "from_decimal" => text(bytes)
            .split(|c: char| !c.is_ascii_digit())
            .filter(|s| !s.is_empty())
            .enumerate()
            .map(|(index, s)| {
                s.parse::<u8>()
                    .map_err(|_| format!("decimal value out of byte range at position {index}"))
            })
            .collect(),
        "rot_n" | "rot13" | "atbash" | "rot47" => {
            let n = if op == "rot13" {
                13
            } else {
                number(param, 13).rem_euclid(26) as u8
            };
            Ok(bytes
                .iter()
                .map(|&b| match op {
                    "rot47" if (33..=126).contains(&b) => 33 + (b - 33 + 47) % 94,
                    "atbash" if b.is_ascii_uppercase() => b'A' + 25 - (b - b'A'),
                    "atbash" if b.is_ascii_lowercase() => b'a' + 25 - (b - b'a'),
                    "rot_n" | "rot13" if b.is_ascii_uppercase() => b'A' + (b - b'A' + n) % 26,
                    "rot_n" | "rot13" if b.is_ascii_lowercase() => b'a' + (b - b'a' + n) % 26,
                    _ => b,
                })
                .collect())
        }
        "xor" => {
            let key = param.filter(|p| !p.is_empty()).unwrap_or("key").as_bytes();
            Ok(bytes
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ key[i % key.len()])
                .collect())
        }
        "reverse" => Ok(bytes.iter().rev().copied().collect()),
        "swap_endianness" => {
            let width = if number(param, 16) == 32 { 4 } else { 2 };
            if bytes.len() % width != 0 {
                return Err(format!(
                    "byte count must be a multiple of {width} for {}-bit swap",
                    width * 8
                ));
            }
            let mut out = bytes.to_vec();
            for chunk in out.chunks_mut(width) {
                chunk.reverse();
            }
            Ok(out)
        }
        "rotate_bytes" => {
            if bytes.is_empty() {
                return Ok(Vec::new());
            }
            let position = number(param, 1).rem_euclid(bytes.len() as i64) as usize;
            let mut out = bytes.to_vec();
            out.rotate_left(position);
            Ok(out)
        }
        "bit_shift_left" => {
            let n = number(param, 1).clamp(0, 7) as u32;
            Ok(bytes.iter().map(|b| b.wrapping_shl(n)).collect())
        }
        "bit_shift_right" => {
            let n = number(param, 1).clamp(0, 7) as u32;
            Ok(bytes.iter().map(|b| b >> n).collect())
        }
        "to_uppercase" => Ok(text(bytes).to_uppercase().into_bytes()),
        "to_lowercase" => Ok(text(bytes).to_lowercase().into_bytes()),
        "add_line_numbers" => add_line_numbers(bytes),
        "trim_lines" => Ok(text(bytes)
            .split('\n')
            .map(str::trim)
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes()),
        "unique_lines" => {
            let input = text(bytes);
            let mut seen = HashSet::new();
            Ok(input
                .split('\n')
                .map(|l| l.trim_end_matches('\r'))
                .filter(|line| seen.insert(line.to_string()))
                .collect::<Vec<_>>()
                .join("\n")
                .into_bytes())
        }
        "reverse_lines" => Ok(text(bytes)
            .split('\n')
            .map(|l| l.trim_end_matches('\r'))
            .rev()
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes()),
        "filter_lines" => {
            let needle = param.unwrap_or("").to_lowercase();
            Ok(text(bytes)
                .split('\n')
                .map(|l| l.trim_end_matches('\r').to_string())
                .filter(|l| l.to_lowercase().contains(&needle))
                .collect::<Vec<_>>()
                .join("\n")
                .into_bytes())
        }
        "head_lines" | "tail_lines" => {
            let input = text(bytes);
            let lines: Vec<_> = input
                .split('\n')
                .map(|l| l.trim_end_matches('\r'))
                .collect();
            let n = number(param, 10).max(0) as usize;
            let result = if op == "head_lines" {
                lines.iter().take(n).copied().collect::<Vec<_>>()
            } else {
                lines
                    .iter()
                    .skip(lines.len().saturating_sub(n))
                    .copied()
                    .collect::<Vec<_>>()
            };
            Ok(result.join("\n").into_bytes())
        }
        "text_split" => Ok(text(bytes)
            .split(param.filter(|p| !p.is_empty()).unwrap_or(","))
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes()),
        "find_replace" => {
            let value = param.unwrap_or(":");
            let (from, to) = value
                .split_once(':')
                .ok_or("parameter needs find:replace format")?;
            if from.is_empty() {
                return Err("find text must not be empty".into());
            }
            Ok(text(bytes).replace(from, to).into_bytes())
        }
        "json_beautify" | "json_minify" => {
            let value: serde_json::Value =
                serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
            let output = if op == "json_beautify" {
                serde_json::to_string_pretty(&value)
            } else {
                serde_json::to_string(&value)
            }
            .map_err(|e| e.to_string())?;
            Ok(output.into_bytes())
        }
        "slice_bytes" => {
            let mut parts = param.unwrap_or("0,64").split(',');
            let start = parts
                .next()
                .unwrap_or("0")
                .trim()
                .parse::<usize>()
                .unwrap_or(0)
                .min(bytes.len());
            let end = parts
                .next()
                .unwrap_or("")
                .trim()
                .parse::<usize>()
                .unwrap_or(bytes.len())
                .min(bytes.len());
            if end < start {
                return Err("slice end must not be before start".into());
            }
            Ok(bytes[start..end].to_vec())
        }
        "to_utf8" => Ok(bytes.to_vec()),
        _ => Err(format!("native recipe operation not implemented: {op}")),
    }
}

pub fn execute_recipe(input: &str, steps: &[RecipeStep]) -> NativeRecipeResult {
    use base64::engine::general_purpose::STANDARD;
    let started = Instant::now();
    let mut data = input.as_bytes().to_vec();
    let mut error = None;
    if data.len() > MAX_RECIPE_BYTES || steps.len() > MAX_RECIPE_STEPS {
        error = Some(RecipeFailure {
            step_index: 0,
            op_id: "recipe".into(),
            message: "recipe input or step limit exceeded".into(),
        });
    } else {
        for (index, step) in steps.iter().enumerate() {
            if !step.enabled {
                continue;
            }
            if !native_operation(&step.op_id) {
                error = Some(RecipeFailure {
                    step_index: index,
                    op_id: step.op_id.clone(),
                    message: "operation not yet ported to native Rust".into(),
                });
                break;
            }
            match transform(&step.op_id, &data, step.param.as_deref()) {
                Ok(next) if next.len() <= MAX_RECIPE_BYTES => data = next,
                Ok(_) => {
                    error = Some(RecipeFailure {
                        step_index: index,
                        op_id: step.op_id.clone(),
                        message: "recipe output size limit exceeded".into(),
                    });
                    break;
                }
                Err(message) => {
                    error = Some(RecipeFailure {
                        step_index: index,
                        op_id: step.op_id.clone(),
                        message,
                    });
                    break;
                }
            }
        }
    }
    let output_b64 = if error.is_some() {
        String::new()
    } else {
        STANDARD.encode(&data)
    };
    NativeRecipeResult {
        output_b64,
        byte_length: data.len(),
        elapsed_ms: started.elapsed().as_secs_f64() * 1000.0,
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn step(op_id: &str, param: Option<&str>) -> RecipeStep {
        RecipeStep {
            op_id: op_id.to_string(),
            enabled: true,
            param: param.map(str::to_owned),
        }
    }
    fn run(input: &str, steps: &[RecipeStep]) -> Vec<u8> {
        let result = execute_recipe(input, steps);
        assert!(result.error.is_none(), "{:?}", result.error);
        base64::engine::general_purpose::STANDARD
            .decode(result.output_b64)
            .unwrap()
    }

    #[test]
    fn chained_encodings_roundtrip() {
        assert_eq!(
            run(
                "hello",
                &[step("to_base64", None), step("from_base64", None)]
            ),
            b"hello"
        );
        assert_eq!(
            run("hello", &[step("to_hex", None), step("from_hex", None)]),
            b"hello"
        );
    }
    #[test]
    fn binary_and_decimal_roundtrip() {
        assert_eq!(
            run("Hi", &[step("to_binary", None), step("from_binary", None)]),
            b"Hi"
        );
        assert_eq!(
            run(
                "Hi",
                &[step("to_decimal", None), step("from_decimal", None)]
            ),
            b"Hi"
        );
    }
    #[test]
    fn transformations_are_deterministic() {
        assert_eq!(run("Hello", &[step("rot13", None)]), b"Uryyb");
        assert_eq!(
            run("abc", &[step("xor", Some("k")), step("xor", Some("k"))]),
            b"abc"
        );
        assert_eq!(run("abcdef", &[step("slice_bytes", Some("1,4"))]), b"bcd");
    }
    #[test]
    fn invalid_input_reports_step_index() {
        let result = execute_recipe("abc", &[step("reverse", None), step("from_hex", None)]);
        assert_eq!(result.error.unwrap().step_index, 1);
    }
    #[test]
    fn rejects_excessive_step_count() {
        let result = execute_recipe("abc", &vec![step("reverse", None); 65]);
        assert!(result.error.is_some());
    }
}

#[cfg(test)]
mod added_recipe_parity {
    use super::*;

    fn step(op_id: &str) -> RecipeStep {
        RecipeStep {
            op_id: op_id.into(),
            enabled: true,
            param: None,
        }
    }

    #[test]
    fn base32_matches_rfc4648_and_ts_byte_roundtrip() {
        for (plain, expected) in [
            ("", ""),
            ("f", "MY======"),
            ("fo", "MZXQ===="),
            ("foo", "MZXW6==="),
            ("foob", "MZXW6YQ="),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI======"),
        ] {
            assert_eq!(
                base32_encode(plain.as_bytes()).unwrap(),
                expected.as_bytes()
            );
            assert_eq!(
                base32_decode(expected.as_bytes()).unwrap(),
                plain.as_bytes()
            );
        }
        let original = [0, 255, 128, 0, 254, 42];
        let encoded = base32_encode(&original).unwrap();
        assert_eq!(base32_decode(&encoded).unwrap(), original);
        // The TS implementation deliberately strips whitespace and '=' anywhere.
        assert_eq!(base32_decode(b"m=z x w 6===").unwrap(), b"foo");
        assert_eq!(
            base32_decode(" \u{feff}MZXW6===\t".as_bytes()).unwrap(),
            b"foo"
        );
        assert_eq!(base32_decode(b"MZXW6").unwrap(), b"foo");
        let result = execute_recipe("foobar", &[step("to_base32"), step("from_base32")]);
        assert!(result.error.is_none());
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(result.output_b64)
                .unwrap(),
            b"foobar"
        );
    }

    #[test]
    fn base32_malformed_failure_coordinates_and_bounds() {
        for invalid in [b"not@base32".as_slice(), b"ABC1", b"MZXW6!", b"invalid_"] {
            assert_eq!(
                base32_decode(invalid).unwrap_err(),
                "input is not valid Base32"
            );
        }
        let result = execute_recipe("!a", &[step("reverse"), step("from_base32")]);
        let error = result.error.unwrap();
        assert_eq!(error.step_index, 1);
        assert_eq!(error.op_id, "from_base32");
        assert_eq!(error.message, "input is not valid Base32");
        let excessive = vec![b'a'; MAX_RECIPE_BYTES];
        assert!(base32_encode(&excessive).unwrap_err().contains("limit"));
        let result = execute_recipe(&"a".repeat(5_242_881), &[step("to_base32")]);
        let error = result.error.unwrap();
        assert_eq!(error.op_id, "to_base32");
        assert_eq!(error.step_index, 0);
        assert!(error.message.contains("limit"));
    }

    #[test]
    fn line_numbering_matches_ts_line_splitting_and_output_limit() {
        assert_eq!(
            add_line_numbers(b"a\r\nb\nc\r").unwrap(),
            b"1 a\n2 b\n3 c\r"
        );
        assert_eq!(add_line_numbers(b"").unwrap(), b"1 ");
        assert_eq!(add_line_numbers(b"one\n").unwrap(), b"1 one\n2 ");
        let many = "x\n".repeat(11);
        let result = add_line_numbers(many.as_bytes()).unwrap();
        assert!(result.starts_with(b" 1 x\n 2 x"));
        assert!(result.ends_with(b"12 "));
        let pipeline = execute_recipe("A\r\nB", &[step("add_line_numbers")]);
        assert!(pipeline.error.is_none());
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(pipeline.output_b64)
                .unwrap(),
            b"1 A\n2 B"
        );
        assert!(add_line_numbers(&vec![b'\n'; 1_100_000])
            .unwrap_err()
            .contains("limit"));
        assert!(
            native_operation("to_base32")
                && native_operation("from_base32")
                && native_operation("add_line_numbers")
        );
    }
}

#[cfg(test)]
mod p4_web_recipe_parity {
    use super::*;

    fn result(op: &str, input: &str) -> Result<Vec<u8>, String> {
        let output = execute_recipe(
            input,
            &[RecipeStep {
                op_id: op.to_owned(),
                enabled: true,
                param: None,
            }],
        );
        match output.error {
            Some(error) => Err(error.message),
            None => base64::engine::general_purpose::STANDARD
                .decode(output.output_b64)
                .map_err(|e| e.to_string()),
        }
    }

    #[test]
    fn url_encoding_matches_typescript_encode_uri_component() {
        for (source, expected) in [
            ("", ""),
            (
                "hello world! /?a=1&b=雪+%",
                "hello%20world!%20%2F%3Fa%3D1%26b%3D%E9%9B%AA%2B%25",
            ),
            ("!*'()~_-.,é😃", "!*'()~_-.%2C%C3%A9%F0%9F%98%83"),
            ("a+b%=", "a%2Bb%25%3D"),
        ] {
            assert_eq!(result("url_encode", source).unwrap(), expected.as_bytes());
        }
        assert_eq!(url_encode(b"\xff").unwrap(), b"%EF%BF%BD");
    }

    #[test]
    fn url_decoding_matches_typescript_and_rejects_invalid_utf8() {
        for (source, expected) in [
            (
                "hello+world%21%20%2F%3Fa%3D1%26b%3D%E9%9B%AA%2B%25",
                "hello world! /?a=1&b=雪+%",
            ),
            ("%C3%A9%F0%9F%98%83", "é😃"),
            ("%2b+%41%7a", "+ Az"),
            ("hello%00world", "hello\0world"),
        ] {
            assert_eq!(result("url_decode", source).unwrap(), expected.as_bytes());
        }
        for invalid in ["%ZZ", "%FF", "%E2%82", "trailing%", "%0", "%C0%AF"] {
            assert_eq!(result("url_decode", invalid), Err("URI malformed".into()));
        }
        let pipeline = execute_recipe(
            "hello + 雪",
            &[
                RecipeStep {
                    op_id: "url_encode".into(),
                    enabled: true,
                    param: None,
                },
                RecipeStep {
                    op_id: "url_decode".into(),
                    enabled: true,
                    param: None,
                },
            ],
        );
        assert!(pipeline.error.is_none());
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(pipeline.output_b64)
                .unwrap(),
            "hello + 雪".as_bytes()
        );
    }

    #[test]
    fn defang_matches_typescript_with_case_sensitive_prefix_quirk() {
        for (source, expected) in [
            (
                "https://example.com/a.b?u=x@y.org HTTP://Foo.Bar http://a.b",
                "hXXps://example[.]com/a[.]b?u=x[@]y[.]org hXXp://Foo[.]Bar hXXp://a[.]b",
            ),
            (
                "HttPS://a.b http://one.two",
                "hXXp://a[.]b hXXp://one[.]two",
            ),
            ("a@b.com [.] and 🛡️", "a[@]b[.]com [[.]] and 🛡️"),
        ] {
            assert_eq!(result("defang", source).unwrap(), expected.as_bytes());
        }
    }

    #[test]
    fn refang_matches_typescript_and_does_not_fetch_urls() {
        for (source, expected) in [
            (
                "hXXps://example[.]com h**p://x[.]y bob[@]site(.)org",
                "https://example.com http://x.y bob@site.org",
            ),
            (
                "HXXPS://A[.]B hXXp://test[.]com",
                "https://A.B http://test.com",
            ),
            ("https://unmodified.example", "https://unmodified.example"),
        ] {
            assert_eq!(result("refang", source).unwrap(), expected.as_bytes());
        }
    }

    #[test]
    fn output_boundaries_are_checked_before_expansion() {
        assert_eq!(
            url_encode(&vec![b'!'; MAX_RECIPE_BYTES]).unwrap().len(),
            MAX_RECIPE_BYTES
        );
        assert_eq!(
            url_encode(&vec![b' '; MAX_RECIPE_BYTES / 3 + 1]).unwrap_err(),
            "recipe output size limit exceeded"
        );
        assert_eq!(
            defang(&vec![b'.'; MAX_RECIPE_BYTES / 3 + 1]).unwrap_err(),
            "recipe output size limit exceeded"
        );
        assert_eq!(
            url_decode(&vec![b'%'; MAX_RECIPE_BYTES + 1]).unwrap_err(),
            "recipe output size limit exceeded"
        );
        assert_eq!(
            refang(&vec![b'a'; MAX_RECIPE_BYTES + 1]).unwrap_err(),
            "recipe output size limit exceeded"
        );
        for op in ["url_encode", "url_decode", "defang", "refang"] {
            assert!(native_operation(op));
        }
        let fail = execute_recipe(
            "%ZZ",
            &[RecipeStep {
                op_id: "url_decode".into(),
                enabled: true,
                param: None,
            }],
        );
        let err = fail.error.unwrap();
        assert_eq!(err.step_index, 0);
        assert_eq!(err.op_id, "url_decode");
        assert_eq!(err.message, "URI malformed");
    }
}
