//! Native bounded offline recovery engine. No external tool execution or secret persistence.
use crate::{apply_op, kdf_format, verify_kdf};
use serde::Serialize;

pub const MAX_FAST_CANDIDATES: u64 = 10_000_000;
pub const MAX_KDF_CANDIDATES: u64 = 10_000;
pub const MAX_MATCHES: usize = 100;
pub const MAX_CANDIDATE_BYTES: usize = 4096;
pub const MAX_MASK_KEYSPACE: u64 = 1_000_000;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FastHash {
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Ntlm,
}
impl FastHash {
    fn name(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha512 => "sha512",
            Self::Ntlm => "ntlm",
        }
    }
    fn size(self) -> usize {
        match self {
            Self::Md5 | Self::Ntlm => 16,
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }
}
#[derive(Debug, Clone)]
pub enum RecoveryTarget {
    Digest {
        algorithm: FastHash,
        bytes: Vec<u8>,
    },
    Kdf {
        format: &'static str,
        encoded: String,
    },
}
fn check_param(text: &str, prefix: &str, maximum: u32) -> Result<u32, String> {
    let mut found = None;
    for part in text.split('$').flat_map(|section| section.split(',')) {
        if let Some(v) = part.strip_prefix(prefix) {
            if found.is_some() {
                return Err(format!("duplicate KDF parameter {prefix}"));
            }
            let n: u32 = v
                .parse()
                .map_err(|_| format!("invalid KDF parameter {prefix}"))?;
            if n == 0 || n > maximum {
                return Err(format!("unsafe KDF parameter {prefix}"));
            }
            found = Some(n);
        }
    }
    found.ok_or_else(|| format!("missing KDF parameter {prefix}"))
}
fn check_scrypt_memory(log_n: u32, r: u32) -> Result<(), String> {
    let memory_bytes = (1u64 << log_n)
        .checked_mul(r as u64)
        .and_then(|n| n.checked_mul(128))
        .ok_or("scrypt memory overflow")?;
    if memory_bytes > 128 * 1024 * 1024 {
        return Err("scrypt memory cost exceeds 128 MiB limit".into());
    }
    Ok(())
}

impl RecoveryTarget {
    pub fn parse(algo: &str, text: &str) -> Result<Self, String> {
        let text = text.trim();
        if text.is_empty() {
            return Err("target is empty".into());
        }
        if let Some(format) = kdf_format(text) {
            match format {
                "bcrypt" => {
                    let cost: u32 = text
                        .split('$')
                        .nth(2)
                        .unwrap_or("")
                        .parse()
                        .map_err(|_| "invalid bcrypt cost")?;
                    if !(4..=14).contains(&cost) {
                        return Err("bcrypt cost exceeds recovery policy".into());
                    }
                }
                "argon2i" | "argon2id" | "argon2d" => {
                    check_param(text, "m=", 65536)?;
                    check_param(text, "t=", 10)?;
                    check_param(text, "p=", 8)?;
                }
                "scrypt" => {
                    let ln = check_param(text, "ln=", 20)?;
                    let r = check_param(text, "r=", 16)?;
                    check_param(text, "p=", 8)?;
                    check_scrypt_memory(ln, r)?;
                }
                f if f.starts_with("pbkdf2") => {
                    check_param(text, "i=", 500_000)?;
                }
                // Compact yescrypt cost fields need a dedicated bounded parser.
                "yescrypt" => return Err("yescrypt cost bounds not implemented".into()),
                _ => return Err("unsupported KDF".into()),
            }
            return Ok(Self::Kdf {
                format,
                encoded: text.to_string(),
            });
        }
        if text.starts_with('$') {
            return Err("unsupported modular hash format".into());
        }
        let algorithm = match algo.to_ascii_lowercase().as_str() {
            "md5" => FastHash::Md5,
            "sha1" => FastHash::Sha1,
            "sha256" => FastHash::Sha256,
            "sha512" => FastHash::Sha512,
            "ntlm" => FastHash::Ntlm,
            _ => return Err("unsupported raw digest algorithm".into()),
        };
        let bytes = hex::decode(text).map_err(|_| "digest is not valid hexadecimal")?;
        if bytes.len() != algorithm.size() {
            return Err(format!(
                "{} digest requires {} hex digits",
                algorithm.name(),
                algorithm.size() * 2
            ));
        }
        Ok(Self::Digest { algorithm, bytes })
    }
    pub fn is_match(&self, candidate: &[u8]) -> Result<bool, String> {
        match self {
            Self::Digest { algorithm, bytes } => {
                let digest = apply_op(algorithm.name(), candidate, None)?;
                let diff = digest
                    .iter()
                    .zip(bytes)
                    .fold(0u8, |acc, (a, b)| acc | (a ^ b));
                Ok(diff == 0)
            }
            Self::Kdf { encoded, .. } => {
                let value =
                    std::str::from_utf8(candidate).map_err(|_| "KDF candidate is not UTF-8")?;
                verify_kdf(encoded, value)
            }
        }
    }
    pub fn is_kdf(&self) -> bool {
        matches!(self, Self::Kdf { .. })
    }
}
#[derive(Debug, Clone, Copy)]
pub struct RecoveryLimits {
    pub max_candidates: u64,
    pub max_matches: usize,
}
impl Default for RecoveryLimits {
    fn default() -> Self {
        Self {
            max_candidates: 1_000_000,
            max_matches: 1,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveryHit {
    pub index: u64,
    pub candidate: Vec<u8>,
}
#[derive(Debug, Serialize)]
pub struct RecoveryResult {
    pub engine: &'static str,
    pub tried: u64,
    pub hits: Vec<RecoveryHit>,
    pub cancelled: bool,
    pub limit_reached: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveryProgress {
    /// Successfully checked candidates; never a speculative chunk offset.
    pub tried: u64,
    /// Effective global operation limit (KDF vs fast hash), not a wordlist size.
    pub budget: u64,
    pub matches: usize,
}

/// Lazy candidate stream with a global attempt ceiling and early cancellation.
/// No next candidate is requested after the limit or a cancellation signal.
pub fn recover<I, B, F>(
    target: &RecoveryTarget,
    candidates: I,
    limits: RecoveryLimits,
    cancel: F,
) -> Result<RecoveryResult, String>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
    F: FnMut() -> bool,
{
    recover_checked(
        target,
        candidates.into_iter().map(Ok::<B, String>),
        limits,
        cancel,
        |_| {},
    )
}

/// Native byte-preserving, bounded wordlist recovery that never collects the
/// entire wordlist. Reader failures and oversized lines stop with an error.
/// The core CPU attempt quota is shared across the entire streaming session.
pub fn recover_wordlist<R, F>(
    target: &RecoveryTarget,
    reader: R,
    limits: RecoveryLimits,
    cancel: F,
) -> Result<RecoveryResult, String>
where
    R: std::io::BufRead,
    F: FnMut() -> bool,
{
    recover_wordlist_with_progress(target, reader, limits, cancel, |_| {})
}

/// Wordlist recovery with bounded, monotonic, non-secret progress snapshots.
/// Progress reports are emitted at most once per 25 KDF or 4096 fast attempts,
/// plus a final snapshot on return. They contain no candidate material.
pub fn recover_wordlist_with_progress<R, F, P>(
    target: &RecoveryTarget,
    reader: R,
    limits: RecoveryLimits,
    cancel: F,
    on_progress: P,
) -> Result<RecoveryResult, String>
where
    R: std::io::BufRead,
    F: FnMut() -> bool,
    P: FnMut(RecoveryProgress),
{
    recover_checked(
        target,
        crate::candidates::WordlistCandidates::new(reader),
        limits,
        cancel,
        on_progress,
    )
}

/// Streams per-word compiled rule variants into the same globally limited
/// CPU recovery service. Never materializes the expanded dictionary.
pub fn recover_wordlist_with_rules<R, F, P>(
    target: &RecoveryTarget,
    reader: R,
    rules: Vec<CompiledRule>,
    limits: RecoveryLimits,
    cancel: F,
    on_progress: P,
) -> Result<RecoveryResult, String>
where
    R: std::io::BufRead,
    F: FnMut() -> bool,
    P: FnMut(RecoveryProgress),
{
    let source = crate::candidates::WordlistCandidates::new(reader);
    let expanded = crate::candidates::RuleCandidates::new(source, rules)?;
    recover_checked(target, expanded, limits, cancel, on_progress)
}

fn recover_checked<I, B, F, P>(
    target: &RecoveryTarget,
    mut candidates: I,
    limits: RecoveryLimits,
    mut cancel: F,
    mut on_progress: P,
) -> Result<RecoveryResult, String>
where
    I: Iterator<Item = Result<B, String>>,
    B: AsRef<[u8]>,
    F: FnMut() -> bool,
    P: FnMut(RecoveryProgress),
{
    if limits.max_candidates == 0 || limits.max_matches == 0 || limits.max_matches > MAX_MATCHES {
        return Err("invalid limits".into());
    }
    let cap = limits.max_candidates.min(if target.is_kdf() {
        MAX_KDF_CANDIDATES
    } else {
        MAX_FAST_CANDIDATES
    });
    let mut result = RecoveryResult {
        engine: "cyberdeck-crypto-cpu",
        tried: 0,
        hits: Vec::new(),
        cancelled: false,
        limit_reached: false,
    };
    let interval = if target.is_kdf() { 25 } else { 4096 };
    let mut last_reported = 0u64;
    loop {
        if cancel() {
            result.cancelled = true;
            break;
        }
        if result.tried >= cap {
            result.limit_reached = true;
            break;
        }
        let candidate = match candidates.next() {
            Some(Ok(candidate)) => candidate,
            Some(Err(message)) => return Err(message),
            None => break,
        };
        let candidate = candidate.as_ref();
        if candidate.len() > MAX_CANDIDATE_BYTES {
            return Err("candidate too long".into());
        }
        let index = result.tried;
        result.tried += 1;
        if target.is_match(candidate)? {
            result.hits.push(RecoveryHit {
                index,
                candidate: candidate.to_vec(),
            });
            if result.hits.len() == limits.max_matches {
                break;
            }
        }
        if result.tried % interval == 0 {
            on_progress(RecoveryProgress {
                tried: result.tried,
                budget: cap,
                matches: result.hits.len(),
            });
            last_reported = result.tried;
        }
    }
    if result.tried != last_reported || result.tried == 0 {
        on_progress(RecoveryProgress {
            tried: result.tried,
            budget: cap,
            matches: result.hits.len(),
        });
    }
    Ok(result)
}

/// A bounded native byte-oriented rule subset; not full JtR/Hashcat syntax.
pub const MAX_RULE_INSTRUCTIONS: usize = 64;
pub const MAX_RULES_PER_STREAM: usize = 256;
#[derive(Clone, Debug, PartialEq, Eq)]
enum RuleAction {
    Identity,
    Lower,
    Upper,
    Capitalize,
    Reverse,
    Duplicate,
    Append(u8),
    Prepend(u8),
    Toggle(usize),
    Substitute(u8, u8),
    DeleteFirst,
    DeleteLast,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledRule {
    actions: Vec<RuleAction>,
}
impl CompiledRule {
    /// Syntax: : l u c r d $X ^X TN sXY [ ]; N is 0-9/A-Z.
    pub fn parse(source: &str) -> Result<Self, String> {
        if source.is_empty() || source.bytes().any(|b| !(0x20..=0x7e).contains(&b)) {
            return Err("rule must be nonempty printable ASCII".into());
        }
        let chars = source.as_bytes();
        let mut cursor = 0;
        let mut actions = Vec::new();
        while cursor < chars.len() {
            if actions.len() >= MAX_RULE_INSTRUCTIONS {
                return Err("rule too complex".into());
            }
            let op = chars[cursor];
            cursor += 1;
            let mut arg = || {
                let byte = *chars.get(cursor).ok_or("missing rule argument")?;
                cursor += 1;
                Ok::<u8, String>(byte)
            };
            let action = match op {
                b':' => RuleAction::Identity,
                b'l' => RuleAction::Lower,
                b'u' => RuleAction::Upper,
                b'c' => RuleAction::Capitalize,
                b'r' => RuleAction::Reverse,
                b'd' => RuleAction::Duplicate,
                b'$' => RuleAction::Append(arg()?),
                b'^' => RuleAction::Prepend(arg()?),
                b'T' => {
                    let digit = arg()?;
                    let n = match digit {
                        b'0'..=b'9' => usize::from(digit - b'0'),
                        b'A'..=b'Z' => usize::from(digit - b'A' + 10),
                        _ => return Err("toggle position must be 0-9 or A-Z".into()),
                    };
                    RuleAction::Toggle(n)
                }
                b's' => RuleAction::Substitute(arg()?, arg()?),
                b'[' => RuleAction::DeleteFirst,
                b']' => RuleAction::DeleteLast,
                _ => return Err(format!("unsupported rule opcode {}", op as char)),
            };
            actions.push(action);
        }
        Ok(Self { actions })
    }
    pub fn apply(&self, candidate: &[u8]) -> Result<Vec<u8>, String> {
        if candidate.len() > MAX_CANDIDATE_BYTES {
            return Err("candidate too long".into());
        }
        let mut bytes = candidate.to_vec();
        for action in &self.actions {
            match *action {
                RuleAction::Identity => {}
                RuleAction::Lower => bytes.make_ascii_lowercase(),
                RuleAction::Upper => bytes.make_ascii_uppercase(),
                RuleAction::Capitalize => {
                    bytes.make_ascii_lowercase();
                    if let Some(first) = bytes.first_mut() {
                        first.make_ascii_uppercase();
                    }
                }
                RuleAction::Reverse => bytes.reverse(),
                RuleAction::Duplicate => {
                    if bytes.len().saturating_mul(2) > MAX_CANDIDATE_BYTES {
                        return Err("rule expansion exceeds byte cap".into());
                    }
                    let cloned = bytes.clone();
                    bytes.extend_from_slice(&cloned);
                }
                RuleAction::Append(v) => {
                    if bytes.len() >= MAX_CANDIDATE_BYTES {
                        return Err("rule expansion exceeds byte cap".into());
                    }
                    bytes.push(v);
                }
                RuleAction::Prepend(v) => {
                    if bytes.len() >= MAX_CANDIDATE_BYTES {
                        return Err("rule expansion exceeds byte cap".into());
                    }
                    bytes.insert(0, v);
                }
                RuleAction::Toggle(n) => {
                    if let Some(byte) = bytes.get_mut(n) {
                        if byte.is_ascii_lowercase() {
                            byte.make_ascii_uppercase();
                        } else if byte.is_ascii_uppercase() {
                            byte.make_ascii_lowercase();
                        }
                    }
                }
                RuleAction::Substitute(from, to) => {
                    for byte in &mut bytes {
                        if *byte == from {
                            *byte = to;
                        }
                    }
                }
                RuleAction::DeleteFirst => {
                    if !bytes.is_empty() {
                        bytes.remove(0);
                    }
                }
                RuleAction::DeleteLast => {
                    bytes.pop();
                }
            }
        }
        Ok(bytes)
    }
}

/// Parses bounded newline-delimited CyberDeck rules from a local file.
/// Empty lines and full-line comments starting with '#' are ignored.
pub fn parse_rule_lines<R: std::io::BufRead>(reader: R) -> Result<Vec<CompiledRule>, String> {
    let mut rules = Vec::new();
    for (index, line) in crate::candidates::WordlistCandidates::new(reader).enumerate() {
        let line = line.map_err(|e| format!("rule line {}: {e}", index + 1))?;
        if line.is_empty() || line.first() == Some(&b'#') {
            continue;
        }
        if rules.len() == MAX_RULES_PER_STREAM {
            return Err("rule file exceeds maximum rules".into());
        }
        let script = std::str::from_utf8(&line)
            .map_err(|_| format!("rule line {} is not ASCII/UTF-8", index + 1))?;
        rules.push(
            CompiledRule::parse(script).map_err(|e| format!("rule line {}: {e}", index + 1))?,
        );
    }
    if rules.is_empty() {
        return Err("no valid rules in file".into());
    }
    Ok(rules)
}

#[derive(Debug, Clone, Copy)]
pub enum Rule {
    Identity,
    Lower,
    Upper,
    Capitalize,
    Reverse,
    Duplicate,
    Append(u8),
    Prepend(u8),
    ToggleFirst,
}
pub fn apply_rule(candidate: &[u8], rule: Rule) -> Result<Vec<u8>, String> {
    if candidate.len() > MAX_CANDIDATE_BYTES {
        return Err("candidate too long".into());
    }
    let result: Vec<u8> = match rule {
        Rule::Identity => candidate.to_vec(),
        Rule::Lower => candidate.iter().map(u8::to_ascii_lowercase).collect(),
        Rule::Upper => candidate.iter().map(u8::to_ascii_uppercase).collect(),
        Rule::Capitalize => candidate
            .iter()
            .enumerate()
            .map(|(i, v)| {
                if i == 0 {
                    v.to_ascii_uppercase()
                } else {
                    v.to_ascii_lowercase()
                }
            })
            .collect(),
        Rule::Reverse => candidate.iter().rev().copied().collect(),
        Rule::Duplicate => [candidate, candidate].concat(),
        Rule::Append(x) => [candidate, &[x]].concat(),
        Rule::Prepend(x) => [&[x][..], candidate].concat(),
        Rule::ToggleFirst => candidate
            .iter()
            .enumerate()
            .map(|(i, v)| {
                if i != 0 {
                    *v
                } else if v.is_ascii_lowercase() {
                    v.to_ascii_uppercase()
                } else {
                    v.to_ascii_lowercase()
                }
            })
            .collect(),
    };
    if result.len() > MAX_CANDIDATE_BYTES {
        return Err("rule expansion exceeds limit".into());
    }
    Ok(result)
}
/// Bounded byte-oriented mask enumeration. Supports ?l ?u ?d ?s ?a ??.
pub struct MaskCandidates {
    alphabet: Vec<Vec<u8>>,
    cursor: Vec<usize>,
    remaining: u64,
    total: u64,
}
impl MaskCandidates {
    pub fn parse(mask: &str) -> Result<Self, String> {
        let bytes = mask.as_bytes();
        let mut alphabet = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let chars = if bytes[i] == b'?' {
                i += 1;
                match *bytes.get(i).ok_or("unfinished mask")? {
                    b'l' => (b'a'..=b'z').collect(),
                    b'u' => (b'A'..=b'Z').collect(),
                    b'd' => (b'0'..=b'9').collect(),
                    b's' => b"!@#$%^&*()-_=+[]{};:,.<>/".to_vec(),
                    b'a' => (b' '..=b'~').collect(),
                    b'?' => vec![b'?'],
                    _ => return Err("unsupported mask token".into()),
                }
            } else {
                if !bytes[i].is_ascii() {
                    return Err("masks must be ASCII".into());
                }
                vec![bytes[i]]
            };
            alphabet.push(chars);
            if alphabet.len() > 16 {
                return Err("mask has too many positions".into());
            }
            i += 1;
        }
        if alphabet.is_empty() {
            return Err("empty mask".into());
        }
        let mut keyspace = 1u64;
        for chars in &alphabet {
            keyspace = keyspace
                .checked_mul(chars.len() as u64)
                .ok_or("mask overflow")?;
            if keyspace > MAX_MASK_KEYSPACE {
                return Err("mask exceeds keyspace limit".into());
            }
        }
        Ok(Self {
            cursor: vec![0; alphabet.len()],
            alphabet,
            remaining: keyspace,
            total: keyspace,
        })
    }
    /// Resume deterministic enumeration at a candidate-index offset, without
    /// enumerating earlier combinations. The offset is validated against the
    /// bounded keyspace, not trusted as a serializable full-session state.
    pub fn parse_from_offset(mask: &str, offset: u64) -> Result<Self, String> {
        let mut stream = Self::parse(mask)?;
        if offset > stream.total {
            return Err("mask resume offset exceeds keyspace".into());
        }
        let mut index = offset;
        for slot in (0..stream.cursor.len()).rev() {
            let radix = stream.alphabet[slot].len() as u64;
            stream.cursor[slot] = (index % radix) as usize;
            index /= radix;
        }
        stream.remaining -= offset;
        Ok(stream)
    }
    pub fn total(&self) -> u64 { self.total }
    pub fn position(&self) -> u64 { self.total - self.remaining }
    pub fn remaining(&self) -> u64 { self.remaining }
}
impl Iterator for MaskCandidates {
    type Item = Vec<u8>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let out = self
            .alphabet
            .iter()
            .zip(self.cursor.iter())
            .map(|(set, i)| set[*i])
            .collect();
        self.remaining -= 1;
        for i in (0..self.cursor.len()).rev() {
            self.cursor[i] += 1;
            if self.cursor[i] < self.alphabet[i].len() {
                break;
            }
            self.cursor[i] = 0;
        }
        Some(out)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn progress_is_monotonic_budgeted_and_contains_no_password() {
        use std::io::{BufReader, Cursor};
        let target = RecoveryTarget::parse("sha256", &"ab".repeat(32)).unwrap();
        let lines = "bad\n".repeat(10_000);
        let mut samples = Vec::new();
        let result = recover_wordlist_with_progress(
            &target,
            BufReader::new(Cursor::new(lines)),
            RecoveryLimits {
                max_candidates: 9_000,
                max_matches: 1,
            },
            || false,
            |progress| samples.push(progress),
        )
        .unwrap();
        assert_eq!(result.tried, 9_000);
        assert!(result.limit_reached);
        assert_eq!(
            samples.iter().map(|p| p.tried).collect::<Vec<_>>(),
            vec![4096, 8192, 9000]
        );
        assert!(samples.iter().all(|p| p.budget == 9000 && p.matches == 0));
        assert_eq!(samples.last().unwrap().tried, result.tried);
        // Serialization is intentionally candidate-free for case/event logs.
        assert_eq!(
            serde_json::to_string(samples.last().unwrap()).unwrap(),
            r#"{"tried":9000,"budget":9000,"matches":0}"#
        );
    }

    #[test]
    fn streaming_compiled_rules_integrate_with_global_recovery() {
        use std::io::Cursor;
        let hash = hex::encode(apply_op("sha256", b"Pass1", None).unwrap());
        let target = RecoveryTarget::parse("sha256", &hash).unwrap();
        let rules = vec![
            CompiledRule::parse("l").unwrap(),
            CompiledRule::parse("c$1").unwrap(),
        ];
        let mut snapshots = Vec::new();
        let result = recover_wordlist_with_rules(
            &target,
            Cursor::new(b"paSS\nignored\n".as_slice()),
            rules,
            RecoveryLimits {
                max_candidates: 4,
                max_matches: 1,
            },
            || false,
            |progress| snapshots.push(progress),
        )
        .unwrap();
        assert_eq!(result.tried, 2);
        assert_eq!(result.hits[0].index, 1);
        assert_eq!(result.hits[0].candidate, b"Pass1");
        assert_eq!(snapshots.last().unwrap().tried, 2);
    }

    #[test]
    fn wordlist_streaming_matches_and_preserves_global_indices() {
        use std::io::{BufReader, Cursor};
        let target = RecoveryTarget::parse(
            "sha256",
            &hex::encode(apply_op("sha256", b"secret", None).unwrap()),
        )
        .unwrap();
        let bytes = b"bad\n\xff\x00\nsecret\nignored";
        let result = recover_wordlist(
            &target,
            BufReader::with_capacity(2, Cursor::new(bytes.as_slice())),
            RecoveryLimits::default(),
            || false,
        )
        .unwrap();
        assert_eq!(result.tried, 3);
        assert_eq!(result.hits[0].index, 2);
        assert_eq!(result.hits[0].candidate, b"secret");
    }

    #[test]
    fn wordlist_limits_and_cancel_do_not_prefetch() {
        use std::io::{BufReader, Cursor};
        let target = RecoveryTarget::parse("md5", "5d41402abc4b2a76b9719d911017c592").unwrap();
        // A malformed, oversized second line is never read past the budget.
        let source = [b"bad\n".to_vec(), vec![b'X'; MAX_CANDIDATE_BYTES + 9]].concat();
        let limits = RecoveryLimits {
            max_candidates: 1,
            max_matches: 1,
        };
        let result = recover_wordlist(
            &target,
            BufReader::with_capacity(2, Cursor::new(source)),
            limits,
            || false,
        )
        .unwrap();
        assert_eq!(result.tried, 1);
        assert!(result.limit_reached);
        let cancelled = recover_wordlist(
            &target,
            BufReader::new(Cursor::new(b"anything\n".as_slice())),
            RecoveryLimits::default(),
            || true,
        )
        .unwrap();
        assert_eq!(cancelled.tried, 0);
        assert!(cancelled.cancelled);
    }

    #[test]
    fn recover_core_does_not_poll_candidate_past_cap() {
        use std::cell::Cell;
        let target = RecoveryTarget::parse("md5", "5d41402abc4b2a76b9719d911017c592").unwrap();
        let pulls = Cell::new(0usize);
        let candidates = std::iter::from_fn(|| {
            pulls.set(pulls.get() + 1);
            Some(b"bad".to_vec())
        });
        let result = recover(
            &target,
            candidates,
            RecoveryLimits {
                max_candidates: 2,
                max_matches: 1,
            },
            || false,
        )
        .unwrap();
        assert_eq!(result.tried, 2);
        assert_eq!(pulls.get(), 2);
        assert!(result.limit_reached);
    }

    #[test]
    fn sha256_reference_recovery() {
        let target = RecoveryTarget::parse(
            "sha256",
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        )
        .unwrap();
        let result = recover(
            &target,
            ["bad", "hello", "other"],
            RecoveryLimits::default(),
            || false,
        )
        .unwrap();
        assert_eq!(result.tried, 2);
        assert_eq!(
            result.hits[0],
            RecoveryHit {
                index: 1,
                candidate: b"hello".to_vec()
            }
        );
    }
    #[test]
    fn ntlm_and_non_utf8_md5() {
        let ntlm = RecoveryTarget::parse("ntlm", "8846f7eaee8fb117ad06bdd830b7586c").unwrap();
        assert!(ntlm.is_match(b"password").unwrap());
        let input = [255u8, 0u8];
        let digest = hex::encode(apply_op("md5", &input, None).unwrap());
        assert!(RecoveryTarget::parse("md5", &digest)
            .unwrap()
            .is_match(&input)
            .unwrap());
    }
    #[test]
    fn validation_rejects_malformed_and_unbounded_cost() {
        assert!(RecoveryTarget::parse("sha256", "zz").is_err());
        assert!(RecoveryTarget::parse("sha256", "abcd").is_err());
        assert!(RecoveryTarget::parse("", "$6$salt$hash").is_err());
        assert!(RecoveryTarget::parse("", "$2b$31$abcdefghijklmnopqrstuv").is_err());
        assert!(RecoveryTarget::parse("", "$argon2id$v=19$m=999999,t=2,p=1$a$b").is_err());
        assert!(RecoveryTarget::parse("", "$pbkdf2-sha256$i=900000000$a$b").is_err());
        assert!(RecoveryTarget::parse("", "$argon2id$v=19$t=2,p=1$a$b").is_err());
        assert!(RecoveryTarget::parse("", "$argon2id$v=19$m=8192,m=8192,t=2,p=1$a$b").is_err());
        assert!(RecoveryTarget::parse("", "$scrypt$ln=20,r=16,p=1$a$b").is_err());
        assert!(RecoveryTarget::parse("", "$scrypt$ln=16,r=8$a$b").is_err());
        assert!(RecoveryTarget::parse("", "$pbkdf2-sha256$salt$hash").is_err());
    }
    #[test]
    fn cancellation_and_global_limit() {
        let target = RecoveryTarget::parse("md5", "5d41402abc4b2a76b9719d911017c592").unwrap();
        let outcome = recover(
            &target,
            std::iter::repeat("bad").take(8),
            RecoveryLimits {
                max_candidates: 3,
                max_matches: 1,
            },
            || false,
        )
        .unwrap();
        assert_eq!(outcome.tried, 3);
        assert!(outcome.limit_reached);
        let mut polls = 0;
        let outcome = recover(&target, ["bad", "hello"], RecoveryLimits::default(), || {
            polls += 1;
            polls > 1
        })
        .unwrap();
        assert_eq!(outcome.tried, 1);
        assert!(outcome.cancelled);
    }
    #[test]
    fn bounded_bcrypt_stream_recovery() {
        let encoded = bcrypt::hash("secret", 4).unwrap();
        let target = RecoveryTarget::parse("", &encoded).unwrap();
        let result = recover(
            &target,
            ["bad", "secret"],
            RecoveryLimits::default(),
            || false,
        )
        .unwrap();
        assert_eq!(result.tried, 2);
        assert_eq!(result.hits[0].candidate, b"secret");
    }
    #[test]
    fn parse_compiled_rules_from_bounded_source_file() {
        use std::io::Cursor;
        let rules = parse_rule_lines(Cursor::new(b"# comment\r\n\r\nc$1\nl\n".as_slice())).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].apply(b"pASSWORD").unwrap(), b"Password1");
        assert_eq!(rules[1].apply(b"ABC").unwrap(), b"abc");
        assert!(parse_rule_lines(Cursor::new(b"# only comments\n".as_slice())).is_err());
        let huge = [vec![b'l'; MAX_CANDIDATE_BYTES + 8], b"\n".to_vec()].concat();
        assert!(parse_rule_lines(Cursor::new(huge)).is_err());
        let too_many = ":\n".repeat(MAX_RULES_PER_STREAM + 1);
        assert!(parse_rule_lines(Cursor::new(too_many)).is_err());
    }

    #[test]
    fn compiled_rule_subset_is_bounded_and_byte_preserving() {
        assert_eq!(
            CompiledRule::parse("c$1")
                .unwrap()
                .apply(b"pASSWORD")
                .unwrap(),
            b"Password1"
        );
        assert_eq!(
            CompiledRule::parse("uT0").unwrap().apply(b"test").unwrap(),
            b"tEST"
        );
        assert_eq!(
            CompiledRule::parse("saz^!")
                .unwrap()
                .apply(b"banana")
                .unwrap(),
            b"!bznznz"
        );
        assert_eq!(
            CompiledRule::parse("r[]").unwrap().apply(b"abcd").unwrap(),
            b"cb"
        );
        assert_eq!(
            CompiledRule::parse(":").unwrap().apply(&[255, 0]).unwrap(),
            vec![255, 0]
        );
        assert!(CompiledRule::parse("d")
            .unwrap()
            .apply(&vec![b'x'; 2049])
            .is_err());
        assert!(CompiledRule::parse("$!")
            .unwrap()
            .apply(&vec![b'x'; 4096])
            .is_err());
        for bad in ["", "$", "T?", "sA", "z", "\n"] {
            assert!(CompiledRule::parse(bad).is_err());
        }
        assert!(CompiledRule::parse(&"l".repeat(MAX_RULE_INSTRUCTIONS + 1)).is_err());
    }

    #[test]
    fn mask_resume_by_offset_matches_deterministic_source() {
        let reference = MaskCandidates::parse("A?d??").unwrap().collect::<Vec<_>>();
        assert_eq!(reference.len(), 10);
        let mut resumed = MaskCandidates::parse_from_offset("A?d??", 7).unwrap();
        assert_eq!(resumed.total(), 10);
        assert_eq!(resumed.position(), 7);
        assert_eq!(resumed.remaining(), 3);
        assert_eq!(resumed.next().unwrap(), reference[7]);
        assert_eq!(resumed.position(), 8);
        assert_eq!(resumed.collect::<Vec<_>>(), reference[8..].to_vec());
        assert_eq!(MaskCandidates::parse_from_offset("A?d??", 10).unwrap().next(), None);
        assert!(MaskCandidates::parse_from_offset("A?d??", 11).is_err());
        assert!(MaskCandidates::parse_from_offset("?a?a?a?a", 0).is_err());
    }

    #[test]
    fn masks_and_rules_are_bounded() {
        let mut items = MaskCandidates::parse("A?d??").unwrap();
        assert_eq!(items.remaining(), 10);
        assert_eq!(items.next().unwrap(), b"A0?");
        assert_eq!(items.last().unwrap(), b"A9?");
        assert!(MaskCandidates::parse("?a?a?a?a").is_err());
        assert_eq!(apply_rule(b"Pass", Rule::Lower).unwrap(), b"pass");
        assert!(apply_rule(&vec![b'x'; 4096], Rule::Duplicate).is_err());
    }
}
