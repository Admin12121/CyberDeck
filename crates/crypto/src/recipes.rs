//! The native byte-oriented recipe engine.
//! This module implements HackTool's existing transformation semantics in Rust.
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
    )
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
