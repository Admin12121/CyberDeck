//! Rule-based and mask attacks (Master Plan §5.5). These are our own Rust
//! implementations, not bundled john/hashcat code: no license gate applies to
//! the algorithms themselves. GPU acceleration stays gated on the OpenCL/CUDA
//! runtime redistribution review (§7.2); device probing reports honestly what
//! is present.

use std::time::Instant;

use serde::Serialize;

use crate::evidence::MAX_IMPORT_BYTES;

const SUPPORTED: &[&str] = &["md5", "sha1", "sha256", "sha512"];
const MAX_CANDIDATES: u64 = 20_000_000;
const MAX_REPORTED_MATCHES: usize = 100;

#[derive(Debug, Clone, Serialize)]
pub struct AttackMatch {
    pub line_no: u64,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AttackResultWire {
    pub mode: String,
    pub algo: String,
    pub target_hash: String,
    pub source: String,
    pub tried: u64,
    pub generated: u64,
    pub cap_reached: bool,
    pub matches: Vec<AttackMatch>,
    pub duration_ms: u64,
    pub engine: String,
    pub engine_version: String,
}

struct AttackSession {
    target: String,
    tried: u64,
    generated: u64,
    matches: Vec<AttackMatch>,
    cap_reached: bool,
}

impl AttackSession {
    fn new(target: &str) -> Self {
        Self { target: target.to_lowercase(), tried: 0, generated: 0, matches: Vec::new(), cap_reached: false }
    }

    /// Hash one candidate and record a hit. Returns false when the cap stops
    /// the session.
    fn test(&mut self, algo: &str, candidate: &str, line_no: u64) -> bool {
        self.generated += 1;
        if self.generated > MAX_CANDIDATES {
            self.cap_reached = true;
            return false;
        }
        self.tried += 1;
        if let Ok(digest) = hacktool_crypto::apply_op(algo, candidate.as_bytes(), None) {
            if hex::encode(digest) == self.target {
                self.matches.push(AttackMatch { line_no, password: candidate.to_string() });
                if self.matches.len() >= MAX_REPORTED_MATCHES {
                    self.cap_reached = true;
                    return false;
                }
            }
        }
        true
    }
}

/// Built-in rule set, hashcat-flavored mangling implemented in our own code.
fn rule_variants(word: &str) -> Vec<String> {
    let mut out = vec![word.to_string()];
    let lower = word.to_lowercase();
    let upper = word.to_uppercase();
    let mut cap = String::new();
    if let Some(first) = lower.chars().next() {
        cap = first.to_uppercase().collect::<String>() + &lower[first.len_utf8()..];
    }
    out.push(cap.clone());
    out.push(upper.clone());
    out.push(lower.clone());
    out.push(word.chars().rev().collect());
    for d in 0..=9 {
        out.push(format!("{word}{d}"));
    }
    for d in 0..100 {
        out.push(format!("{word}{d:02}"));
    }
    for suffix in ["123", "1234", "12345", "!", "!!", "@", "#", "*", "2024", "2025", "2026"] {
        out.push(format!("{word}{suffix}"));
    }
    out.push(cap.clone() + "123");
    out.push(cap + "!");
    out.push(lower + "123");
    // leetspeak
    out.push(word.replace(['a', 'A'], "4").replace(['e', 'E'], "3").replace(['i', 'I'], "1").replace(['o', 'O'], "0").replace(['s', 'S'], "5").replace(['t', 'T'], "7"));
    out
}

/// Apply built-in rules over a wordlist body; candidates stream from the
/// caller so giant wordlists never allocate twice.
fn run_rules(algo: &str, target: &str, words: impl Iterator<Item = String>) -> AttackSession {
    let mut session = AttackSession::new(target);
    'outer: for (line_no, word) in words.enumerate() {
        let word = word.trim_end_matches('\r').to_string();
        if word.is_empty() {
            continue;
        }
        for (variant_no, candidate) in rule_variants(&word).into_iter().enumerate() {
            let id = (line_no as u64) * 1000 + variant_no as u64;
            if !session.test(algo, &candidate, id) {
                break 'outer;
            }
        }
    }
    session
}

#[derive(Debug, Serialize)]
pub struct MaskPlan {
    pub candidate_count: u64,
    pub charset_sizes: Vec<usize>,
}

fn mask_charset(kind: char) -> Option<Vec<char>> {
    match kind {
        'l' => Some(('a'..='z').collect()),
        'u' => Some(('A'..='Z').collect()),
        'd' => Some(('0'..='9').collect()),
        's' => Some("!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~ ".chars().collect()),
        'a' => Some((' '..='~').collect()),
        _ => None,
    }
}

fn plan_mask(mask: &str) -> Result<MaskPlan, String> {
    let mut sizes = Vec::new();
    let mut chars = mask.chars().peekable();
    let mut literals = 0u64;
    while let Some(c) = chars.next() {
        if c == '?' {
            let kind = chars.next().ok_or("mask ends with a dangling '?'")?;
            match kind {
                'l' | 'u' | 'd' | 's' | 'a' => sizes.push(mask_charset(kind).unwrap().len()),
                '?' => literals += 1, // escaped literal '?'
                other => return Err(format!("unknown mask class ?{other}")),
            }
        } else {
            literals += 1;
        }
    }
    if sizes.is_empty() {
        return Err("mask needs at least one class like ?l ?u ?d ?s ?a".to_string());
    }
    let mut count: u64 = 1;
    for size in &sizes {
        count = count.saturating_mul(*size as u64);
    }
    Ok(MaskPlan { candidate_count: count, charset_sizes: sizes })
}

fn run_mask(algo: &str, target: &str, mask: &str) -> Result<AttackSession, String> {
    let plan = plan_mask(mask)?;
    if plan.candidate_count > MAX_CANDIDATES {
        return Err(format!(
            "mask generates {} candidates; the cap this arc is {}",
            plan.candidate_count, MAX_CANDIDATES
        ));
    }
    // Build the odometer: classes in order, literals fixed.
    #[derive(Clone)]
    enum Slot {
        Class(Vec<char>),
        Literal(char),
    }
    let mut slots: Vec<Slot> = Vec::new();
    let mut chars = mask.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '?' {
            let kind = chars.next().unwrap();
            match kind {
                'l' | 'u' | 'd' | 's' | 'a' => slots.push(Slot::Class(mask_charset(kind).unwrap())),
                '?' => slots.push(Slot::Literal('?')),
                _ => unreachable!("validated by plan_mask"),
            }
        } else {
            slots.push(Slot::Literal(c));
        }
    }
    let class_count = slots.iter().filter(|s| matches!(s, Slot::Class(_))).count();
    let mut counters = vec![0usize; class_count];
    let mut session = AttackSession::new(target);
    let total = plan.candidate_count;
    for i in 0..total {
        let mut candidate = String::with_capacity(slots.len());
        let mut class_index = 0usize;
        for slot in &slots {
            match slot {
                Slot::Literal(ch) => candidate.push(*ch),
                Slot::Class(set) => {
                    candidate.push(set[counters[class_index]]);
                    class_index += 1;
                }
            }
        }
        // line_no doubles as the candidate ordinal for mask mode
        if !session.test(algo, &candidate, i + 1) {
            break;
        }
        // increment odometer (last class is the fast digit)
        for pos in (0..class_count).rev() {
            if let Some(slot) = slots.iter().filter(|s| matches!(s, Slot::Class(_))).nth(pos) {
                if let Slot::Class(set) = slot {
                    counters[pos] += 1;
                    if counters[pos] < set.len() {
                        break;
                    }
                    counters[pos] = 0;
                }
            }
        }
    }
    Ok(session)
}

fn guard(algo: &str, target: &str) -> Result<String, String> {
    if hacktool_crypto::kdf_format(target).is_some() {
        return Err("KDF hashes (bcrypt/argon2) crack at password-hashing speed; use the wordlist recovery mode, rules and masks would run for years".to_string());
    }
    if !SUPPORTED.contains(&algo) {
        return Err(format!("attacks support {} this arc", SUPPORTED.join(", ")));
    }
    let target = target.trim().to_lowercase();
    if target.is_empty() {
        return Err("target hash is empty".to_string());
    }
    Ok(target)
}

fn wire(mode: &str, algo: String, target: String, source: String, session: AttackSession, duration_ms: u64) -> AttackResultWire {
    AttackResultWire {
        mode: mode.to_string(),
        algo,
        target_hash: target,
        source,
        tried: session.tried,
        generated: session.generated,
        cap_reached: session.cap_reached,
        matches: session.matches,
        duration_ms,
        engine: "hacktool-crypto".to_string(),
        engine_version: hacktool_crypto::ENGINE_VERSION.to_string(),
    }
}

/// Wordlist + built-in rules. The wordlist body arrives from the caller
/// (dialog in the command, bytes in tests) so the file read stays testable.
pub fn rules_over_bytes(algo: &str, target: &str, body: &[u8]) -> Result<AttackResultWire, String> {
    let target = guard(algo, target)?;
    let started = Instant::now();
    let text = String::from_utf8_lossy(body);
    let session = run_rules(algo, &target, text.lines().map(str::to_string));
    Ok(wire("rules", algo.to_string(), target, "wordlist + built-in rules".to_string(), session, started.elapsed().as_millis() as u64))
}

#[tauri::command]
pub fn crack_rules_dialog(
    app: tauri::AppHandle,
    algo: String,
    target_hash: String,
) -> Result<AttackResultWire, String> {
    use tauri_plugin_dialog::DialogExt;
    let target = guard(&algo, &target_hash)?;
    let picked = app.dialog().file().blocking_pick_file().ok_or("cancelled")?;
    let path = picked.as_path().ok_or("unsupported file location")?.to_path_buf();
    let meta = std::fs::metadata(&path).map_err(|e| format!("cannot read wordlist metadata: {e}"))?;
    if meta.len() > MAX_IMPORT_BYTES {
        return Err(format!(
            "wordlist is {} MB; the limit this arc is {} MB",
            meta.len() / (1024 * 1024),
            MAX_IMPORT_BYTES / (1024 * 1024)
        ));
    }
    let body = std::fs::read(&path).map_err(|e| format!("cannot read wordlist: {e}"))?;
    let mut result = rules_over_bytes(&algo, &target, &body)?;
    result.source = format!("{} + built-in rules", path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default());
    Ok(result)
}

/// Mask attack: pattern like ?l?l?l?d?d?d?d with classes l/u/d/s/a.
#[tauri::command]
pub fn crack_mask(algo: String, target_hash: String, mask: String) -> Result<AttackResultWire, String> {
    let target = guard(&algo, &target_hash)?;
    let started = Instant::now();
    let session = run_mask(&algo, &target, &mask)?;
    Ok(wire("mask", algo, target, mask, session, started.elapsed().as_millis() as u64))
}

#[derive(Debug, Serialize)]
pub struct GpuDevice {
    pub name: String,
    pub backend: String,
    pub usable: bool,
}

#[derive(Debug, Serialize)]
pub struct DeviceInfoWire {
    pub cpu_arch: String,
    pub cpu_cores: usize,
    pub cpu_engine: String,
    pub gpu_devices: Vec<GpuDevice>,
    pub planner_note: String,
}

fn detect_gpus() -> Vec<GpuDevice> {
    // Query the NVIDIA SMI tool when present; it is a read-only system query
    // executed by the native core, never by the frontend (§2.4).
    let output = std::process::Command::new("nvidia-smi")
        .args(["--query-gpu=name", "--format=csv,noheader"])
        .output();
    match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|name| GpuDevice {
                name: name.trim().to_string(),
                backend: "cuda (driver present; engine gated on license review)".to_string(),
                usable: false,
            })
            .collect(),
        _ => Vec::new(),
    }
}

#[tauri::command]
pub fn device_info() -> DeviceInfoWire {
    let cpu_cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let gpu_devices = detect_gpus();
    let planner_note = if gpu_devices.is_empty() {
        "no GPU runtime detected; CPU engine is active and this is reported honestly (§7.2)"
    } else {
        "GPU hardware present; GPU compute waits on the OpenCL/CUDA bundling review"
    };
    DeviceInfoWire {
        cpu_arch: std::env::consts::ARCH.to_string(),
        cpu_cores,
        cpu_engine: "hacktool-crypto (rust)".to_string(),
        gpu_devices,
        planner_note: planner_note.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA256_HELLO: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    #[test]
    fn rules_find_capitalized_and_suffixed_variants() {
        // "hello" won't match, but "Hello123" will via the rules
        let body = b"hello\nworld\n";
        let target = hacktool_crypto::apply_op("sha256", b"Hello123", None).unwrap();
        let result = rules_over_bytes("sha256", &hex::encode(target), body).unwrap();
        assert_eq!(result.mode, "rules");
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].password, "Hello123");
        assert!(result.tried > 20);
    }

    #[test]
    fn rules_report_no_match_cleanly() {
        let result = rules_over_bytes("md5", "0".repeat(32).as_str(), b"hello\n").unwrap();
        assert!(result.matches.is_empty());
        assert!(!result.cap_reached);
    }

    #[test]
    fn mask_plan_counts_candidates() {
        assert_eq!(plan_mask("?d?d").unwrap().candidate_count, 100);
        assert_eq!(plan_mask("?l?l?l").unwrap().candidate_count, 17_576);
        assert!(plan_mask("abc").is_err());
        assert!(plan_mask("?x").is_err());
    }

    #[test]
    fn mask_finds_the_needle() {
        // sha256("42")
        let target = hacktool_crypto::apply_op("sha256", b"42", None).unwrap();
        let result = crack_mask("sha256".to_string(), hex::encode(target), "?d?d".to_string()).unwrap();
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].password, "42");
        // the odometer completes the space; hits are collected, not early-exited
        assert_eq!(result.tried, 100);
    }

    #[test]
    fn mask_respects_candidate_cap() {
        // 6 lowercase letters = 308M candidates, over the 20M cap
        let err = crack_mask("md5".to_string(), SHA256_HELLO.to_string(), "?l?l?l?l?l?l".to_string()).unwrap_err();
        assert!(err.contains("cap"));
    }

    #[test]
    fn mask_escapes_literal_question_mark() {
        // ?? is an escaped literal '?', so "a?d?d" = literal a + two digit classes
        assert_eq!(plan_mask("a?d?d").unwrap().candidate_count, 100);
        // "a??d" is a, ?, d: three literals, zero classes
        assert!(plan_mask("a??d").is_err());
    }

    #[test]
    fn device_info_is_honest() {
        let info = device_info();
        assert!(info.cpu_cores >= 1);
        assert!(!info.cpu_arch.is_empty());
        // every reported GPU is explicitly marked not-yet-usable
        assert!(info.gpu_devices.iter().all(|g| !g.usable));
    }
}
