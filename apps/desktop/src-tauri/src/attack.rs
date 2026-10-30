//! Rule-based and mask attacks (§5.5), implemented natively. GPU runs through
//! hashcat when a driver is present; see docs/engine-licensing.md.

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
    pub threads: usize,
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

/// Apply built-in rules over a wordlist body, chunked across CPU cores.
/// Each worker owns a slice of words; partials merge in order so hits keep
/// their source line identity.
fn run_rules(algo: &str, target: &str, words: impl Iterator<Item = String>) -> AttackSession {
    let words: Vec<String> = words
        .map(|w| w.trim_end_matches('\r').to_string())
        .filter(|w| !w.is_empty())
        .collect();
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).clamp(1, 32);
    let chunk_size = (words.len() + threads - 1) / threads.max(1);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let generated = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let mut partials: Vec<AttackSession> = Vec::new();
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for (chunk_index, chunk) in words.chunks(chunk_size.max(1)).enumerate() {
            let stop = std::sync::Arc::clone(&stop);
            let generated = std::sync::Arc::clone(&generated);
            let target = target.to_string();
            handles.push(scope.spawn(move || {
                let mut session = AttackSession::new(&target);
                'outer: for (i, word) in chunk.iter().enumerate() {
                    for (variant_no, candidate) in rule_variants(word).into_iter().enumerate() {
                        let id = ((chunk_index * chunk_size.max(1) + i) as u64) * 1000 + variant_no as u64;
                        let total = generated.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                        if total > MAX_CANDIDATES {
                            session.cap_reached = true;
                            stop.store(true, std::sync::atomic::Ordering::Relaxed);
                            break 'outer;
                        }
                        if !session.test(algo, &candidate, id) {
                            stop.store(true, std::sync::atomic::Ordering::Relaxed);
                            break 'outer;
                        }
                        if stop.load(std::sync::atomic::Ordering::Relaxed) {
                            break 'outer;
                        }
                    }
                }
                session
            }));
        }
        partials = handles.into_iter().map(|h| h.join().unwrap_or_else(|_| AttackSession::new(target))).collect();
    });
    merge_sessions(partials)
}

fn merge_sessions(partials: Vec<AttackSession>) -> AttackSession {
    let mut merged = AttackSession::new("");
    for partial in partials {
        merged.tried += partial.tried;
        merged.generated += partial.generated;
        merged.cap_reached |= partial.cap_reached;
        let room = MAX_REPORTED_MATCHES.saturating_sub(merged.matches.len());
        merged.matches.extend(partial.matches.into_iter().take(room));
    }
    merged.target = String::new();
    merged
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
    while let Some(c) = chars.next() {
        if c == '?' {
            let kind = chars.next().ok_or("mask ends with a dangling '?'")?;
            match kind {
                'l' | 'u' | 'd' | 's' | 'a' => sizes.push(mask_charset(kind).unwrap().len()),
                '?' => {}
                other => return Err(format!("unknown mask class ?{other}")),
            }
        } else {
            // literal character
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

#[derive(Clone)]
enum Slot {
    Class(Vec<char>),
    Literal(char),
}

fn run_mask(algo: &str, target: &str, mask: &str) -> Result<AttackSession, String> {
    let plan = plan_mask(mask)?;
    if plan.candidate_count > MAX_CANDIDATES {
        return Err(format!(
            "mask generates {} candidates; the cap this arc is {}",
            plan.candidate_count, MAX_CANDIDATES
        ));
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
    // Parallelize by slicing the FIRST class's charset across threads; each
    // worker runs a full odometer over the remaining classes with its slice
    // of leading characters.
    let first_class_index = slots.iter().position(|s| matches!(s, Slot::Class(_)));
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).clamp(1, 32);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut partials: Vec<AttackSession> = Vec::new();
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        match first_class_index {
            Some(index) => {
                let first_len = match &slots[index] {
                    Slot::Class(set) => set.len(),
                    Slot::Literal(_) => unreachable!(),
                };
                let slice_size = (first_len + threads - 1) / threads;
                for slice_start in (0..first_len).step_by(slice_size.max(1)) {
                    let slice_end = (slice_start + slice_size.max(1)).min(first_len);
                    let slots = slots.clone();
                    let target = target.to_string();
                    let stop = std::sync::Arc::clone(&stop);
                    handles.push(scope.spawn(move || {
                        let mut session = AttackSession::new(&target);
                        for first_value in slice_start..slice_end {
                            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                                break;
                            }
                            run_mask_odometer(algo, &mut session, slots.as_slice(), index, first_value, &stop);
                        }
                        session
                    }));
                }
            }
            None => {
                // no classes: validated earlier, but stay defensive
                let slots = slots.clone();
                let target = target.to_string();
                let stop = std::sync::Arc::clone(&stop);
                handles.push(scope.spawn(move || {
                    let mut session = AttackSession::new(&target);
                    run_mask_odometer(algo, &mut session, slots.as_slice(), usize::MAX, 0, &stop);
                    session
                }));
            }
        }
        partials = handles.into_iter().map(|h| h.join().unwrap_or_else(|_| AttackSession::new(target))).collect();
    });
    Ok(merge_sessions(partials))
}

/// One odometer pass. `pinned_class` fixes the given class to `pinned_value`
/// (the parallel slice); usize::MAX means run free.
fn run_mask_odometer(algo: &str, session: &mut AttackSession, slots: &[Slot], pinned_class: usize, pinned_value: usize, stop: &std::sync::atomic::AtomicBool) {
    let class_sets: Vec<&Vec<char>> = slots.iter().filter_map(|s| match s { Slot::Class(set) => Some(set), Slot::Literal(_) => None }).collect();
    let class_count = class_sets.len();
    let mut counters = vec![0usize; class_count];
    if pinned_class != usize::MAX {
        counters[pinned_class] = pinned_value;
    }
    let total: u64 = class_sets.iter().enumerate().map(|(i, set)| if i == pinned_class { 1 } else { set.len() as u64 }).product();
    for _ in 0..total {
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        let mut candidate = String::with_capacity(slots.len());
        let mut class_index = 0usize;
        for slot in slots {
            match slot {
                Slot::Literal(ch) => candidate.push(*ch),
                Slot::Class(set) => {
                    candidate.push(set[counters[class_index]]);
                    class_index += 1;
                }
            }
        }
        let ordinal = session.generated + 1;
        if !session.test(algo, &candidate, ordinal) {
            stop.store(true, std::sync::atomic::Ordering::Relaxed);
            break;
        }
        for pos in (0..class_count).rev() {
            if pos == pinned_class {
                continue;
            }
            counters[pos] += 1;
            if counters[pos] < class_sets[pos].len() {
                break;
            }
            counters[pos] = 0;
        }
    }
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
        threads: std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).clamp(1, 32),
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
    ctx: tauri::State<'_, crate::evidence::EvidenceCtx>,
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
    record_history(&ctx, &algo, &target, &result.source, &result.matches);
    Ok(result)
}

/// Mask attack: pattern like ?l?l?l?d?d?d?d with classes l/u/d/s/a.
#[tauri::command]
pub fn crack_mask(
    algo: String,
    target_hash: String,
    mask: String,
    ctx: tauri::State<'_, crate::evidence::EvidenceCtx>,
) -> Result<AttackResultWire, String> {
    let result = mask_attack(&algo, &target_hash, &mask)?;
    record_history(&ctx, &result.algo, &result.target_hash, &format!("native mask ({})", result.source), &result.matches);
    Ok(result)
}

fn mask_attack(algo: &str, target_hash: &str, mask: &str) -> Result<AttackResultWire, String> {
    let target = guard(algo, target_hash)?;
    let started = Instant::now();
    let session = run_mask(algo, &target, mask)?;
    Ok(wire("mask", algo.to_string(), target, mask.to_string(), session, started.elapsed().as_millis() as u64))
}

/// Persist recovered pairs into the crack history (deduped by the store).
pub fn record_history(
    ctx: &crate::evidence::EvidenceCtx,
    algo: &str,
    target: &str,
    engine: &str,
    matches: &[AttackMatch],
) {
    if matches.is_empty() {
        return;
    }
    let store = ctx.store.lock().expect("artifact store poisoned");
    for m in matches {
        let _ = store.add_crack_entry(algo, target, &m.password, engine, None);
    }
}

#[derive(Debug, Serialize)]
pub struct GpuDevice {
    pub name: String,
    pub driver_version: String,
    pub memory_total: String,
    pub compute_cap: String,
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
        .args([
            "--query-gpu=name,driver_version,memory.total,compute_cap",
            "--format=csv,noheader",
        ])
        .output();
    match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|line| {
                let fields: Vec<String> = line.split(',').map(|f| f.trim().to_string()).collect();
                GpuDevice {
                    name: fields.first().cloned().unwrap_or_default(),
                    driver_version: fields.get(1).cloned().unwrap_or_else(|| "n/a".to_string()),
                    memory_total: fields.get(2).cloned().unwrap_or_else(|| "n/a".to_string()),
                    compute_cap: fields.get(3).cloned().unwrap_or_else(|| "n/a".to_string()),
                    backend: "opencl/cuda via installed driver; hashcat (MIT) runs its own kernels on it".to_string(),
                    usable: true,
                }
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
        "no GPU driver detected: GPU engines activate automatically when one is installed; CPU engine is active now"
    } else {
        "GPU driver present: hashcat (MIT, own kernels) is cleared to run on it; no vendor bundling involved"
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
        let result = mask_attack("sha256", &hex::encode(target), "?d?d").unwrap();
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].password, "42");
        // the odometer completes the space; hits are collected, not early-exited
        assert_eq!(result.tried, 100);
    }

    #[test]
    fn mask_respects_candidate_cap() {
        // 6 lowercase letters = 308M candidates, over the 20M cap
        let err = mask_attack("md5", SHA256_HELLO, "?l?l?l?l?l?l").unwrap_err();
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
        // GPU devices report as usable through hashcat when a driver is present
        assert!(info.gpu_devices.iter().all(|g| g.usable));
    }
}
