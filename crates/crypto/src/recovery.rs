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

// Keep the public recovery API stable while separating independent algorithms.
#[path = "recovery_rules.rs"]
mod rule_engine;
pub use rule_engine::{
    apply_rule, parse_rule_lines, CompiledRule, Rule, MAX_RULES_PER_STREAM, MAX_RULE_INSTRUCTIONS,
};
#[path = "recovery_mask.rs"]
mod mask_engine;
pub use mask_engine::MaskCandidates;

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;
