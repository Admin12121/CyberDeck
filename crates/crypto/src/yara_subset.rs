//! Bounded, offline detection using an explicitly documented subset of YARA
//! strings syntax. NOT a full YARA interpreter or YARA rule compatibility.
//! No regexes, imports, modules, variables, files, arbitrary conditions,
//! complex hex jumps or execution. Unsupported syntax fails closed.
use std::collections::HashSet;

pub const MAX_RULE_SOURCE_BYTES: usize = 4096;
pub const MAX_RULE_PATTERNS: usize = 16;
pub const MAX_PATTERN_LEN: usize = 64;
pub const MAX_RULE_SCAN_BYTES: usize = 1024 * 1024;
pub const MAX_COMPARISONS: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern {
    pub identifier: String,
    pub bytes: Vec<Option<u8>>,
    pub nocase: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledRule {
    pub name: String,
    pub patterns: Vec<Pattern>,
    pub require_all: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleHit {
    pub identifier: String,
    pub offset: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleResult {
    pub rule: String,
    pub matched: bool,
    pub hits: Vec<RuleHit>,
    pub analyzed_bytes: usize,
}

fn ident(value: &str) -> bool {
    value.len() <= 64
        && value
            .as_bytes()
            .first()
            .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_')
        && value
            .as_bytes()
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

fn parse_quoted(src: &str) -> Result<(Vec<Option<u8>>, &str), String> {
    let bytes = src.as_bytes();
    if bytes.first() != Some(&b'"') {
        return Err("expected quoted literal".into());
    }
    let mut i = 1;
    let mut out = Vec::new();
    while i < bytes.len() {
        match bytes[i] {
            b'"' => return Ok((out, &src[i + 1..])),
            b'\\' => {
                i += 1;
                if i >= bytes.len() {
                    return Err("truncated literal escape".into());
                }
                let v = match bytes[i] {
                    b'\\' => b'\\',
                    b'"' => b'"',
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'x' => {
                        if i + 2 >= bytes.len() {
                            return Err("short hex escape".into());
                        }
                        let token = &src[i + 1..i + 3];
                        let n = u8::from_str_radix(token, 16).map_err(|_| "invalid hex escape")?;
                        i += 2;
                        n
                    }
                    _ => return Err("unsupported literal escape".into()),
                };
                out.push(Some(v));
            }
            c if c.is_ascii() && !c.is_ascii_control() => out.push(Some(c)),
            _ => return Err("non-ASCII or control character in literal".into()),
        }
        if out.len() > MAX_PATTERN_LEN {
            return Err("literal exceeds bounded size".into());
        }
        i += 1;
    }
    Err("unterminated quoted literal".into())
}
fn parse_pattern(src: &str, id: String) -> Result<Pattern, String> {
    let src = src.trim();
    let (bytes, nocase) = if src.starts_with('"') {
        let (bytes, tail) = parse_quoted(src)?;
        let modifier = tail.trim();
        let nocase = match modifier {
            "" | "ascii" => false,
            "nocase" | "ascii nocase" => true,
            _ => return Err("unsupported literal modifier".into()),
        };
        (bytes, nocase)
    } else if let Some(hex) = src.strip_prefix('{') {
        let (inside, tail) = hex.split_once('}').ok_or("unterminated hex pattern")?;
        if !tail.trim().is_empty() {
            return Err("unsupported hex modifier".into());
        }
        let mut out = Vec::new();
        for token in inside.split_ascii_whitespace() {
            let value = if token == "??" {
                None
            } else if token.len() == 2 {
                Some(u8::from_str_radix(token, 16).map_err(|_| "invalid hex byte")?)
            } else {
                return Err("hex patterns support full bytes and ?? only".into());
            };
            out.push(value);
            if out.len() > MAX_PATTERN_LEN {
                return Err("hex pattern exceeds bounded size".into());
            }
        }
        (out, false)
    } else {
        return Err("unsupported YARA subset pattern".into());
    };
    if bytes.is_empty() || bytes.len() > MAX_PATTERN_LEN || bytes.iter().all(Option::is_none) {
        return Err("empty or all-wildcard pattern is not supported".into());
    }
    Ok(Pattern {
        identifier: id,
        bytes,
        nocase,
    })
}

/// Accepted grammar:
/// rule NAME {
///   strings:
///     $name = "ASCII" [ascii] [nocase]
///     $other = { 4D 5A ?? 00 }
///   condition:
///     any of them | all of them
/// }
///
/// Rule must be <=4 KiB, with 1..=16 patterns of <=64 bytes each.
pub fn compile_yara_subset(src: &str) -> Result<CompiledRule, String> {
    if src.len() > MAX_RULE_SOURCE_BYTES || !src.is_ascii() {
        return Err("YARA subset source must be ASCII and <=4KiB".into());
    }
    let mut lines = src.lines().map(str::trim).filter(|line| !line.is_empty());
    let first = lines.next().ok_or("empty rule")?;
    let header = first.split_ascii_whitespace().collect::<Vec<_>>();
    if header.len() != 3 || header[0] != "rule" || header[2] != "{" || !ident(header[1]) {
        return Err("expected rule NAME {".into());
    }
    if lines.next() != Some("strings:") {
        return Err("expected strings: section".into());
    }
    let mut patterns = Vec::new();
    let mut identifiers = HashSet::new();
    let mut found_condition = false;
    for line in &mut lines {
        if line == "condition:" {
            found_condition = true;
            break;
        }
        if patterns.len() >= MAX_RULE_PATTERNS {
            return Err("too many rule patterns".into());
        }
        let (raw_id, raw_pattern) = line.split_once('=').ok_or("expected $id = pattern")?;
        let id = raw_id
            .trim()
            .strip_prefix('$')
            .ok_or("missing $identifier")?;
        if !ident(id) || !identifiers.insert(id.to_owned()) {
            return Err("invalid or duplicate YARA identifier".into());
        }
        patterns.push(parse_pattern(raw_pattern, id.to_owned())?);
    }
    if !found_condition || patterns.is_empty() {
        return Err("missing condition or patterns".into());
    }
    let require_all = match lines.next() {
        Some("any of them") => false,
        Some("all of them") => true,
        _ => return Err("only any/all of them conditions supported".into()),
    };
    if lines.next() != Some("}") || lines.next().is_some() {
        return Err("unexpected trailing rule syntax".into());
    }
    Ok(CompiledRule {
        name: header[1].to_owned(),
        patterns,
        require_all,
    })
}

/// Performs a bounded literal/hex scan. On resource exhaustion return an
/// error rather than silently treating an unexamined file as negative.
pub fn evaluate_yara_subset(
    rule: &CompiledRule,
    data: &[u8],
    base: u64,
) -> Result<RuleResult, String> {
    if data.len() > MAX_RULE_SCAN_BYTES
        || rule.patterns.is_empty()
        || rule.patterns.len() > MAX_RULE_PATTERNS
    {
        return Err("YARA subset scan bounds exceeded".into());
    }
    base.checked_add(data.len() as u64)
        .ok_or("YARA source offset overflow")?;
    let mut comparisons = 0usize;
    let mut hits = Vec::new();
    for pattern in &rule.patterns {
        if pattern.bytes.is_empty() || pattern.bytes.len() > MAX_PATTERN_LEN {
            return Err("invalid compiled pattern bounds".into());
        }
        if data.len() < pattern.bytes.len() {
            continue;
        }
        'window: for pos in 0..=data.len() - pattern.bytes.len() {
            for (i, value) in pattern.bytes.iter().enumerate() {
                comparisons += 1;
                if comparisons > MAX_COMPARISONS {
                    return Err("YARA subset work budget exceeded".into());
                }
                if let Some(value) = value {
                    let b = data[pos + i];
                    if !(b == *value || (pattern.nocase && b.eq_ignore_ascii_case(value))) {
                        continue 'window;
                    }
                }
            }
            hits.push(RuleHit {
                identifier: pattern.identifier.clone(),
                offset: base + pos as u64,
            });
            break;
        }
    }
    let matched = if rule.require_all {
        hits.len() == rule.patterns.len()
    } else {
        !hits.is_empty()
    };
    Ok(RuleResult {
        rule: rule.name.clone(),
        matched,
        hits,
        analyzed_bytes: data.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_ascii_nocase_hex_wildcard_with_source_offsets() {
        let src = r#"rule firmware_marker {
 strings:
  $a = "PAYLOAD" nocase
  $b = { 4D 5A ?? 90 }
 condition:
  all of them
}"#;
        let compiled = compile_yara_subset(src).unwrap();
        let sample = b"prefix-payload-and-MZ\x01\x90-trailer";
        let result = evaluate_yara_subset(&compiled, sample, 4096).unwrap();
        assert!(result.matched);
        assert_eq!(result.hits.len(), 2);
        assert_eq!(result.hits[0].offset, 4096 + 7);
        assert_eq!(result.hits[1].offset, 4096 + 19);
        assert!(
            !evaluate_yara_subset(&compiled, b"unrelated data", 0)
                .unwrap()
                .matched
        );
    }
    #[test]
    fn rejects_malformed_unsupported_and_duplicate_rules() {
        for rule in [
            "",
            "rule r {",
            "rule r {\nstrings:\n$a = \"\"\ncondition:\nany of them\n}",
            "rule r {\nstrings:\n$a = { ?? ?? }\ncondition:\nany of them\n}",
            "rule r {\nstrings:\n$a = { 4D ?0 }\ncondition:\nany of them\n}",
            "rule r {\nstrings:\n$a = \"abc\"\n$a = \"def\"\ncondition:\nall of them\n}",
            "rule r {\nstrings:\n$a = \"abc\"\ncondition:\nuint16(0) == 10\n}",
            "import \"pe\"\nrule r {\nstrings:\n$a = \"abc\"\ncondition:\nany of them\n}",
        ] {
            assert!(
                compile_yara_subset(rule).is_err(),
                "unexpectedly accepted {rule}"
            );
        }
    }
    #[test]
    fn deterministic_bounded_work_and_offset_overflow() {
        let rule =
            compile_yara_subset("rule r {\nstrings:\n$a = \"AAAAAB\"\ncondition:\nany of them\n}")
                .unwrap();
        assert!(evaluate_yara_subset(&rule, &[0; MAX_RULE_SCAN_BYTES + 1], 0).is_err());
        assert!(evaluate_yara_subset(&rule, b"abc", u64::MAX).is_err());
        assert!(
            !evaluate_yara_subset(&rule, &vec![b'A'; 1024], 0)
                .unwrap()
                .matched
        );
        let expensive = compile_yara_subset(&format!(
            "rule r {{\nstrings:\n$a = \"{}B\"\ncondition:\nany of them\n}}",
            "A".repeat(MAX_PATTERN_LEN - 1)
        ))
        .unwrap();
        assert!(evaluate_yara_subset(&expensive, &vec![b'A'; MAX_RULE_SCAN_BYTES], 0).is_err());
    }
}
