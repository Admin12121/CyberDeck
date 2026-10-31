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
/// Lazy candidate stream with a global attempt ceiling and early cancellation.
pub fn recover<I, B, F>(
    target: &RecoveryTarget,
    candidates: I,
    limits: RecoveryLimits,
    mut cancel: F,
) -> Result<RecoveryResult, String>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
    F: FnMut() -> bool,
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
    for candidate in candidates {
        if cancel() {
            result.cancelled = true;
            break;
        }
        if result.tried >= cap {
            result.limit_reached = true;
            break;
        }
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
    }
    Ok(result)
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
        })
    }
    pub fn remaining(&self) -> u64 {
        self.remaining
    }
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
