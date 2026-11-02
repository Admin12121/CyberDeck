//! Native bounded offline recovery engine. No external tool execution or secret persistence.
use crate::{apply_op, kdf_format, verify_kdf, verify_kdf_format};
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
    Sha3_256,
    Sha3_512,
    Sha512,
    Ntlm,
    Ripemd160,
    Whirlpool,
    Blake2b512,
    Mysql5,
    Lm,
}
impl FastHash {
    fn name(self) -> &'static str {
        match self {
            Self::Md5 => "md5",
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha3_256 => "sha3_256",
            Self::Sha3_512 => "sha3_512",
            Self::Sha512 => "sha512",
            Self::Ntlm => "ntlm",
            Self::Ripemd160 => "ripemd160",
            Self::Whirlpool => "whirlpool",
            Self::Blake2b512 => "blake2b512",
            Self::Mysql5 => "mysql5",
            Self::Lm => "lm",
        }
    }
    fn size(self) -> usize {
        match self {
            Self::Md5 | Self::Ntlm | Self::Lm => 16,
            Self::Sha1 | Self::Mysql5 | Self::Ripemd160 => 20,
            Self::Sha256 | Self::Sha3_256 => 32,
            Self::Sha512 | Self::Sha3_512 | Self::Whirlpool | Self::Blake2b512 => 64,
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
    /// One pass over a candidate stream checked against many targets
    /// (hash files, unshadow output). Bounded by MAX_TARGETS.
    Multi(Vec<RecoveryTarget>),
}

pub const MAX_TARGETS: usize = 1024;
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

/// Only permit canonical yescrypt RW parameters whose cost is bounded
/// before invoking the existing yescrypt verifier (which supports $y$).
/// The three-character form excludes optional p/t/g/NROM fields.
fn check_yescrypt_recovery_hash(hash: &str) -> Result<(), String> {
    const MAX_MEMORY: u64 = 32 * 1024 * 1024;
    const MAX_N: u64 = 8192;
    const MAX_R: u32 = 32;
    fn crypt64(text: &str) -> bool {
        text.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'/')
    }
    if hash.len() > 160 || !hash.starts_with("$y$") {
        return Err("unsupported yescrypt recovery encoding (requires $y$)".into());
    }
    let mut parts = hash.split('$');
    if parts.next() != Some("") || parts.next() != Some("y") {
        return Err("invalid yescrypt hash fields".into());
    }
    let encoded = parts.next().ok_or("missing yescrypt cost parameters")?;
    let salt = parts.next().ok_or("missing yescrypt salt")?;
    let digest = parts.next().ok_or("missing yescrypt digest")?;
    if parts.next().is_some() || encoded.len() != 3 || !encoded.starts_with('j') {
        return Err("unsupported yescrypt parameters or hash fields".into());
    }
    // Reject variable-width cost extensions BEFORE upstream param decoding.
    let alphabet = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    if !encoded.as_bytes()[1..].iter().all(|c| {
        alphabet
            .iter()
            .position(|a| a == c)
            .is_some_and(|i| i <= 47)
    }) {
        return Err("noncanonical yescrypt cost encoding".into());
    }
    if !(8..=64).contains(&salt.len()) || !crypt64(salt) || digest.len() != 43 || !crypt64(digest) {
        return Err("invalid yescrypt salt or digest encoding".into());
    }
    let params: yescrypt::Params = encoded
        .parse()
        .map_err(|_| "invalid yescrypt cost parameters")?;
    let n = params.n();
    let r = params.r();
    let memory = n
        .checked_mul(u64::from(r))
        .and_then(|cost| cost.checked_mul(128))
        .ok_or("yescrypt memory calculation overflow")?;
    if n < 16 || n > MAX_N || r < 8 || r > MAX_R || memory > MAX_MEMORY {
        return Err("yescrypt recovery cost exceeds CPU/memory policy".into());
    }
    // Round-trip proves mode=RW, p=1, t=0, g=0, NROM=0: no optional work.
    let canonical = yescrypt::Params::new(yescrypt::Mode::Rw, n, r, 1)
        .map_err(|_| "unsupported yescrypt recovery parameters")?;
    if canonical.to_string() != encoded {
        return Err("noncanonical or unsupported yescrypt recovery parameters".into());
    }
    yescrypt::PasswordHashRef::new(hash).map_err(|_| "invalid yescrypt modular hash encoding")?;
    Ok(())
}

impl RecoveryTarget {
    pub fn parse(algo: &str, text: &str) -> Result<Self, String> {
        let text = text.trim();
        if text.is_empty() {
            return Err("target is empty".into());
        }
        // Composed salted/HMAC digests are hint-driven: "digest:salt" wire shape.
    const COMPOSED: &[(&str, usize)] = &[
        ("md5-pass-salt", 32),
        ("md5-salt-pass", 32),
        ("sha1-pass-salt", 40),
        ("sha1-salt-pass", 40),
        ("hmac-md5", 32),
        ("hmac-sha1", 40),
    ];
    if let Some((_, digest_len)) = COMPOSED.iter().find(|(name, _)| *name == algo) {
        let (digest_hex, salt) = text
            .split_once(':')
            .ok_or("composed target requires digest:salt")?;
        if digest_hex.len() != *digest_len || !digest_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "{algo} digest must be {} hex characters",
                digest_len
            ));
        }
        if salt.is_empty() || salt.len() > 256 {
            return Err("composed salt must be 1..=256 characters".into());
        }
        return Ok(Self::Kdf {
            format: Box::leak(algo.to_ascii_lowercase().into_boxed_str()),
            encoded: text.to_string(),
        });
    }
    // descrypt is hint-driven (no self-detecting marker).
    if algo == "descrypt" {
        return Ok(Self::Kdf { format: "descrypt", encoded: text.to_string() });
    }
    // mscash is hint-driven when the wire shape is "digest:salt" (hashcat);
    // the tagged "user#digest" and "M$user#digest" shapes self-detect.
    if algo == "mscash" {
        if !(text.contains('#') || text.contains(':')) {
            return Err("mscash target requires user#digest or digest:salt".into());
        }
        return Ok(Self::Kdf {
            format: "mscash",
            encoded: text.to_string(),
        });
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
                "yescrypt" => check_yescrypt_recovery_hash(text)?,
                "gost-yescrypt" => {
                    return Err(
                        "gost-yescrypt is not native yet; route it through the john sidecar"
                            .into(),
                    )
                }
                "md5crypt" | "apr1" => {
                    super::unix_crypt::validate_md5_crypt(text)?;
                }
                "mssql-2005" | "mssql-2012" => {
                    // Prefix and length checks happen in kdf_format; the
                    // verifier enforces the rest.
                }
                "mscash" => {
                    if !text.contains('#') {
                        return Err("invalid mscash encoding".into());
                    }
                }
                "mscash2" => {
                    let iter = text
                        .strip_prefix("$DCC2$")
                        .and_then(|rest| rest.split('#').next())
                        .and_then(|iter| iter.parse::<u32>().ok())
                        .unwrap_or(10240);
                    if !(1..=100_000).contains(&iter) {
                        return Err("mscash2 iterations exceed the recovery policy cap".into());
                    }
                }
                "netntlm-v1" | "netntlm-v2" => {
                    // Field shapes are enforced by the verifiers on match;
                    // nothing secret is computed at parse time.
                }
                "phpass" => {
                    // Shape validation; verify_phpass enforces the cost cap.
                    let body = &text[3..];
                    if !(text.starts_with("$P$") || text.starts_with("$H$"))
                        || body.len() != 31
                        || !body.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'/')
                    {
                        return Err("invalid phpass encoding".into());
                    }
                }
                "sha512crypt" | "sha256crypt" | "sha1crypt" => {
                    super::unix_crypt::validate_sha_crypt(text)?;
                    let rounds = super::unix_crypt::crypt_rounds(text)?;
                    if rounds > super::unix_crypt::MAX_CRYPT_ROUNDS {
                        return Err(format!(
                            "crypt rounds {rounds} exceed the recovery policy cap {}",
                            super::unix_crypt::MAX_CRYPT_ROUNDS
                        ));
                    }
                }
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
        // MySQL 4.1+ digests are canonically written with a leading '*'.
        let text = text.strip_prefix('*').unwrap_or(text);
        let algorithm = match algo.to_ascii_lowercase().as_str() {
            "md5" => FastHash::Md5,
            "sha1" => FastHash::Sha1,
            "sha256" => FastHash::Sha256,
            "sha3_256" | "sha3-256" => FastHash::Sha3_256,
            "sha3_512" | "sha3-512" => FastHash::Sha3_512,
            "sha512" => FastHash::Sha512,
            "ntlm" => FastHash::Ntlm,
            "ripemd160" | "ripemd-160" => FastHash::Ripemd160,
            "whirlpool" => FastHash::Whirlpool,
            "blake2b512" | "blake2b" | "blake2b-512" => FastHash::Blake2b512,
            "mysql5" | "mysql" => FastHash::Mysql5,
            "lm" => FastHash::Lm,
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

    /// Parse a batch of hash-file lines into one multi-target. Lines may be
    /// raw `user:hash` (john/shadow style; the hash is taken after the last
    /// colon) or bare hashes. The algorithm hint applies to bare raw digests;
    /// modular KDF strings detect their own family.
    pub fn parse_multi(
        algo: &str,
        lines: &[String],
    ) -> Result<Self, String> {
        if lines.is_empty() {
            return Err("hash list is empty".into());
        }
        if lines.len() > MAX_TARGETS {
            return Err(format!("hash list exceeds {} targets", MAX_TARGETS));
        }
        let mut targets = Vec::with_capacity(lines.len());
        for (index, line) in lines.iter().enumerate() {
            let text = line.trim();
            if text.is_empty() || text.starts_with('#') {
                continue;
            }
            // user:hash extraction for unshadow-style files; a bare digest
            // never contains ':'.
            let hash_part = match text.split_once(':') {
                Some((_, rest)) if !rest.is_empty() => rest,
                _ => text,
            };
            // Fast digests that carry their own marker override the hint.
            let parsed = if hash_part.starts_with('$') {
                Self::parse(algo, hash_part)?
            } else if hash_part.starts_with('*') && hash_part.len() == 41 {
                Self::parse("mysql5", &hash_part[1..])?
            } else {
                Self::parse(algo, hash_part)?
            };
            targets.push(parsed);
        }
        if targets.is_empty() {
            return Err("hash list has no parsable targets".into());
        }
        if targets.len() == 1 {
            return Ok(targets.remove(0));
        }
        Ok(Self::Multi(targets))
    }
    pub fn is_match(&self, candidate: &[u8]) -> Result<bool, String> {
        Ok(self.match_target(candidate)?.is_some())
    }
    /// Returns the ordinal of the first matching target, if any.
    pub fn match_target(&self, candidate: &[u8]) -> Result<Option<usize>, String> {
        match self {
            Self::Digest { algorithm, bytes } => {
                let digest = apply_op(algorithm.name(), candidate, None)?;
                let diff = digest
                    .iter()
                    .zip(bytes)
                    .fold(0u8, |acc, (a, b)| acc | (a ^ b));
                Ok((diff == 0).then_some(0))
            }
            Self::Kdf { format, encoded } => {
                let value =
                    std::str::from_utf8(candidate).map_err(|_| "KDF candidate is not UTF-8")?;
                Ok(verify_kdf_format(format, encoded, value)?.then_some(0))
            }
            Self::Multi(targets) => {
                for (ordinal, target) in targets.iter().enumerate() {
                    if target.match_target(candidate)? == Some(0) {
                        return Ok(Some(ordinal));
                    }
                }
                Ok(None)
            }
        }
    }
    pub fn is_kdf(&self) -> bool {
        match self {
            Self::Kdf { .. } => true,
            Self::Multi(targets) => targets.iter().any(RecoveryTarget::is_kdf),
            Self::Digest { .. } => false,
        }
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
    /// Which target in a multi-hash run matched; absent for single targets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<usize>,
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

/// Resume a wordlist run at a previous candidate ordinal: the first `skip`
/// candidates are streamed past (never verified) and the attempt budget
/// applies to the new candidates only. The returned result carries the next
/// resume position so a cancelled or capped run can continue later.
pub fn recover_wordlist_resumable<R, F, P>(
    target: &RecoveryTarget,
    reader: R,
    skip: u64,
    limits: RecoveryLimits,
    mut cancel: F,
    mut on_progress: P,
) -> Result<RecoveryResult, String>
where
    R: std::io::BufRead,
    F: FnMut() -> bool,
    P: FnMut(RecoveryProgress),
{
    let mut candidates = crate::candidates::WordlistCandidates::new(reader);
    for index in 0..skip {
        if cancel() {
            return Ok(RecoveryResult {
                engine: "cyberdeck-crypto-cpu",
                tried: 0,
                hits: Vec::new(),
                cancelled: true,
                limit_reached: false,
            });
        }
        if candidates.next().is_none() {
            // The stream is shorter than the remembered position: start over.
            let _ = index;
            break;
        }
    }
    recover_checked(
        target,
        candidates,
        limits,
        cancel,
        on_progress,
    )
}

/// Multi-core wordlist recovery. The file is partitioned into contiguous
/// line-aligned ranges, one worker each; a shared atomic hands out the
/// global candidate ordinal so the attempt budget, match cap and cancellation
/// stay exact regardless of worker count. Same engine, N cores.
pub fn recover_wordlist_parallel(
    target: &RecoveryTarget,
    path: &std::path::Path,
    limits: RecoveryLimits,
    is_cancelled: &(dyn Fn() -> bool + Send + Sync),
    progress: &(dyn Fn(RecoveryProgress) + Send + Sync),
) -> Result<RecoveryResult, String> {
    use std::io::{BufRead, BufReader, Seek, SeekFrom};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Arc;

    if target.is_kdf() && limits.max_candidates > MAX_KDF_CANDIDATES {
        return Err("KDF candidate budget exceeds the engine cap".into());
    }
    let file_size = std::fs::metadata(path)
        .map_err(|e| format!("cannot open wordlist: {e}"))?
        .len();
    if file_size == 0 {
        return Ok(RecoveryResult {
            engine: "cyberdeck-crypto-cpu",
            tried: 0,
            hits: Vec::new(),
            cancelled: false,
            limit_reached: false,
        });
    }
    let cap = limits.max_candidates.min(if target.is_kdf() {
        MAX_KDF_CANDIDATES
    } else {
        MAX_FAST_CANDIDATES
    });
    let workers = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
        .min(8)
        .min((file_size / 4096).max(1) as usize);
    if workers <= 1 {
        // Too small to partition: the sequential streaming path.
        let file = std::fs::File::open(path).map_err(|e| format!("cannot open wordlist: {e}"))?;
        return recover_wordlist_with_progress(target, BufReader::with_capacity(1 << 20, file), limits, is_cancelled, progress);
    }

    let tried = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let hits: Arc<std::sync::Mutex<Vec<RecoveryHit>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let first_error: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
    let started = std::time::Instant::now();
    std::thread::scope(|scope| {
    for worker in 0..workers {
        let target = target.clone();
        let path = path.to_path_buf();
        let is_cancelled = &*is_cancelled;
        let progress = &*progress;
        let tried = Arc::clone(&tried);
        let stop = Arc::clone(&stop);
        let hits = Arc::clone(&hits);
        let first_error = Arc::clone(&first_error);
        let range_start = file_size * worker as u64 / workers as u64;
        let range_end = file_size * (worker as u64 + 1) / workers as u64;
        scope.spawn(move || {
            let file = match std::fs::File::open(path) {
                Ok(file) => file,
                Err(e) => {
                    *first_error.lock().unwrap() = Some(format!("cannot open wordlist: {e}"));
                    return;
                }
            };
            let mut reader = BufReader::with_capacity(1 << 20, file);
            if range_start > 0 {
                // Align forward to the byte after the next newline: the
                // partial line belongs to the previous worker.
                if reader.seek(SeekFrom::Start(range_start - 1)).is_err() {
                    return;
                }
                let mut skip = Vec::new();
                if reader.read_until(b'\n', &mut skip).is_err() {
                    return;
                }
            }
            let mut local_line = Vec::new();
            let mut bytes_seen: u64 = reader.stream_position().unwrap_or(range_start);
            loop {
                if stop.load(Ordering::Acquire) || is_cancelled() {
                    return;
                }
                local_line.clear();
                match reader.read_until(b'\n', &mut local_line) {
                    Ok(0) => return,
                    Ok(_) => {}
                    Err(e) => {
                        *first_error.lock().unwrap() = Some(format!("wordlist read error: {e}"));
                        return;
                    }
                }
                bytes_seen += local_line.len() as u64;
                if bytes_seen > range_end && worker + 1 != workers {
                    return; // handed our last full line to the next range
                }
                if local_line.last() == Some(&b'\n') || local_line.last() == Some(&b'\r') {
                    while local_line
                        .last()
                        .is_some_and(|b| *b == b'\n' || *b == b'\r')
                    {
                        local_line.pop();
                    }
                }
                if local_line.is_empty() {
                    continue;
                }
                if local_line.len() > MAX_CANDIDATE_BYTES {
                    *first_error.lock().unwrap() =
                        Some("wordlist line exceeds the candidate byte limit".into());
                    return;
                }
                let ordinal = tried.fetch_add(1, Ordering::AcqRel);
                if ordinal >= cap {
                    stop.store(true, Ordering::Release);
                    return;
                }
                match target.match_target(&local_line) {
                    Ok(Some(hit_index)) => {
                        let mut all = hits.lock().unwrap();
                        all.push(RecoveryHit {
                            index: ordinal,
                            candidate: local_line.clone(),
                            target: (hit_index != 0).then_some(hit_index),
                        });
                        if all.len() >= limits.max_matches {
                            stop.store(true, Ordering::Release);
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        *first_error.lock().unwrap() = Some(e);
                        return;
                    }
                }
                if ordinal % 4096 == 0 {
                    progress(RecoveryProgress {
                        tried: tried.load(Ordering::Acquire),
                        budget: cap,
                        matches: hits.lock().unwrap().len(),
                    });
                }
            }
        });
    }
    });
    if let Some(error) = first_error.lock().unwrap().take() {
        return Err(error);
    }
    let all = Arc::try_unwrap(hits)
        .map(|mutex| mutex.into_inner().unwrap())
        .unwrap_or_default();
    let tried_total = tried.load(Ordering::Acquire);
    progress(RecoveryProgress {
        tried: tried_total,
        budget: cap,
        matches: all.len(),
    });
    let cancelled = is_cancelled();
    Ok(RecoveryResult {
        engine: "cyberdeck-crypto-cpu",
        tried: tried_total,
        hits: all,
        cancelled,
        limit_reached: tried_total >= cap && !cancelled,
    })
}

/// Recovery over any bounded candidate stream (masks, enumerators). Shares
/// the same attempt budget, cancellation and progress policy as wordlists.
pub fn recover_candidates_with_progress<I, B, F, P>(
    target: &RecoveryTarget,
    candidates: I,
    limits: RecoveryLimits,
    cancel: F,
    on_progress: P,
) -> Result<RecoveryResult, String>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
    F: FnMut() -> bool,
    P: FnMut(RecoveryProgress),
{
    recover_checked(
        target,
        candidates.into_iter().map(Ok::<B, String>),
        limits,
        cancel,
        on_progress,
    )
}

/// Explicit recovery device selection for a single SHA-256 wordlist session.
/// The first desktop integration slice is SHA-256 only. GPU availability is
/// not implied by the presence of the OpenCL Cargo feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "backend", rename_all = "snake_case")]
pub enum RecoveryBackend {
    Cpu,
    OpenCl {
        device_index: usize,
        batch_size: usize,
    },
}

/// One native SHA-256 wordlist service shared by future desktop CPU and GPU
/// handlers. Hits are returned to the caller; this service never persists them.
/// Progress reports contain only completed verifications, not wordlist content.
pub fn recover_sha256_wordlist_on_backend<R, F, P>(
    backend: RecoveryBackend,
    target_hex: &str,
    reader: R,
    limits: RecoveryLimits,
    cancel: F,
    mut on_progress: P,
) -> Result<RecoveryResult, String>
where
    R: std::io::BufRead,
    F: FnMut() -> bool,
    P: FnMut(RecoveryProgress),
{
    // Validate target and limits before touching the candidate stream.
    let target = RecoveryTarget::parse("sha256", target_hex)?;
    if !matches!(
        target,
        RecoveryTarget::Digest {
            algorithm: FastHash::Sha256,
            ..
        }
    ) {
        return Err("selected-backend service requires a raw SHA-256 digest".into());
    }
    if limits.max_candidates == 0 || limits.max_matches == 0 || limits.max_matches > MAX_MATCHES {
        return Err("invalid limits".into());
    }
    match backend {
        RecoveryBackend::Cpu => {
            recover_wordlist_with_progress(&target, reader, limits, cancel, on_progress)
        }
        RecoveryBackend::OpenCl {
            device_index,
            batch_size,
        } => {
            let cap = limits.max_candidates.min(MAX_FAST_CANDIDATES);
            let result = crate::gpu::recover_results_on_device_with_batch_progress(
                crate::gpu::GpuHash::Sha256,
                device_index,
                batch_size,
                target_hex,
                crate::candidates::WordlistCandidates::new(reader),
                cap,
                limits.max_matches,
                cancel,
                |snapshot| {
                    on_progress(RecoveryProgress {
                        tried: snapshot.tried,
                        budget: cap,
                        matches: snapshot.matches,
                    });
                },
            )?;
            Ok(RecoveryResult {
                engine: result.engine,
                tried: result.tried,
                hits: result
                    .hits
                    .into_iter()
                    .map(|hit| RecoveryHit {
                        index: hit.index,
                        candidate: hit.candidate,
                        target: None,
                    })
                    .collect(),
                cancelled: result.cancelled,
                limit_reached: result.limit_reached,
            })
        }
    }
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
        if let Some(target) = target.match_target(candidate)? {
            result.hits.push(RecoveryHit {
                index,
                candidate: candidate.to_vec(),
                target: (target != 0).then_some(target),
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
    apply_rule, parse_rule_file_tolerant, parse_rule_lines, CompiledRule, ParsedRuleFile, Rule,
    MAX_RULES_PER_STREAM, MAX_RULE_INSTRUCTIONS,
};
#[path = "recovery_mask.rs"]
mod mask_engine;
pub use mask_engine::MaskCandidates;

#[cfg(test)]
#[path = "recovery_tests.rs"]
mod tests;
