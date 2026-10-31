//! Rule-based and mask attacks (§5.5), implemented natively. GPU runs through
//! hashcat when a driver is present; see docs/engine-licensing.md.

use serde::Serialize;
use std::time::{Duration, Instant};

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

/// Char-safe drops and rotations: byte slicing panics on multi-byte words.
fn drop_first(word: &str) -> String {
    word.chars().skip(1).collect()
}

fn drop_last(word: &str) -> String {
    let mut chars = word.chars();
    chars.next_back();
    chars.as_str().to_string()
}

fn rotate_left(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => chars.as_str().to_string() + &first.to_string(),
        None => String::new(),
    }
}

fn rotate_right(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next_back() {
        Some(last) => last.to_string() + chars.as_str(),
        None => String::new(),
    }
}

/// Built-in rule set, hashcat-flavored mangling implemented in our own code.
fn rule_variants(word: &str) -> Vec<String> {
    let lower = word.to_lowercase();
    let upper = word.to_uppercase();
    let mut cap = String::new();
    if let Some(first) = lower.chars().next() {
        cap = first.to_uppercase().collect::<String>() + &lower[first.len_utf8()..];
    }
    let rev: String = word.chars().rev().collect();
    let leet_full = word
        .replace(['a', 'A'], "4")
        .replace(['e', 'E'], "3")
        .replace(['i', 'I'], "1")
        .replace(['o', 'O'], "0")
        .replace(['s', 'S'], "5")
        .replace(['t', 'T'], "7");
    let leet_vowels = word.replace(['a', 'A'], "4").replace(['e', 'E'], "3").replace(['o', 'O'], "0");

    let mut out: Vec<String> = vec![
        word.to_string(),
        cap.clone(),
        upper.clone(),
        lower.clone(),
        rev.clone(),
        format!("{word}{word}"), // duplicate
        drop_first(word),
        drop_last(word),
        rotate_left(word),
        rotate_right(word),
        leet_full.clone(),
        leet_vowels,
    ];
    // append digits
    for d in 0..=9 {
        out.push(format!("{word}{d}"));
    }
    for d in 0..100 {
        out.push(format!("{word}{d:02}"));
    }
    // append specials and combos
    for suffix in [
        "123", "1234", "12345", "!", "!!", "@", "#", "*", ".", "-", "_", "+", "?", "=", "$", "%",
        "!!!", "@#", "#@", "$$", "2023", "2024", "2025", "2026",
    ] {
        out.push(format!("{word}{suffix}"));
    }
    out.push(format!("{word}{word}")); // dup (kept: differs from base when short)
    // prepend digits and specials
    for d in 0..=9 {
        out.push(format!("{d}{word}"));
    }
    for prefix in ["!", "@", "#", "$", "_", "-", "1", "123"] {
        out.push(format!("{prefix}{word}"));
    }
    // cap combos
    out.push(cap.clone() + "123");
    out.push(cap.clone() + "!");
    out.push(cap.clone() + "1234");
    out.push(lower + "123");
    out.push(format!("{upper}!"));
    // leet + suffix
    out.push(format!("{leet_full}!"));
    out.push(format!("{leet_full}123"));
    // years
    for year in 1990..=2026 {
        out.push(format!("{word}{year}"));
        out.push(format!("{cap}{year}"));
    }
    // dedup, keep order
    let mut seen = std::collections::HashSet::new();
    out.retain(|c| seen.insert(c.clone()) && !c.is_empty());
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

fn mask_slots(mask: &str) -> Result<Vec<Slot>, String> {
    let mut slots: Vec<Slot> = Vec::new();
    let mut chars = mask.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '?' {
            let kind = chars.next().ok_or("mask ends with a dangling '?'")?;
            match kind {
                'l' | 'u' | 'd' | 's' | 'a' => slots.push(Slot::Class(mask_charset(kind).unwrap())),
                '?' => slots.push(Slot::Literal('?')),
                other => return Err(format!("unknown mask class ?{other}")),
            }
        } else {
            slots.push(Slot::Literal(c));
        }
    }
    Ok(slots)
}

fn run_mask(algo: &str, target: &str, mask: &str) -> Result<AttackSession, String> {
    let plan = plan_mask(mask)?;
    if plan.candidate_count > MAX_CANDIDATES {
        return Err(format!(
            "mask generates {} candidates; the cap this arc is {}",
            plan.candidate_count, MAX_CANDIDATES
        ));
    }
    let slots = mask_slots(mask)?;
    // Parallelize by slicing the FIRST class's charset across threads; each
    // worker runs a full odometer over the remaining classes with its slice
    // of leading characters.
    // Slot index (used to slice the charset), not the class index the
    // odometer counts in: literals such as a leading 'a' occupy slots too.
    let first_class_slot = slots.iter().position(|s| matches!(s, Slot::Class(_)));
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1).clamp(1, 32);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut partials: Vec<AttackSession> = Vec::new();
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        match first_class_slot {
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
                            // The first class slot is always class 0 for the odometer.
                            run_mask_odometer(algo, &mut session, slots.as_slice(), 0, first_value, &stop);
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
        if let Some(counter) = counters.get_mut(pinned_class) {
            *counter = pinned_value;
        }
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

/// Expand a validated mask into up to `limit` concrete strings in odometer
/// order. Literals are copied, classes cycle over their charsets.
fn expand_mask(slots: &[Slot], limit: usize) -> Vec<String> {
    let sets: Vec<&Vec<char>> = slots
        .iter()
        .filter_map(|s| match s {
            Slot::Class(set) => Some(set),
            Slot::Literal(_) => None,
        })
        .collect();
    let mut counters = vec![0usize; sets.len()];
    let mut out = Vec::with_capacity(limit);
    for _ in 0..limit {
        let mut candidate = String::new();
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
        out.push(candidate);
        for pos in (0..counters.len()).rev() {
            counters[pos] += 1;
            if counters[pos] < sets[pos].len() {
                break;
            }
            counters[pos] = 0;
        }
    }
    out
}

/// Validate a hybrid mask and expand at most 1024 entries. The mask's full
/// space is cap-checked first, so this only bounds per-word work.
fn mask_expansions(mask: &str) -> Result<Vec<String>, String> {
    let plan = plan_mask(mask)?;
    if plan.candidate_count > MAX_CANDIDATES {
        return Err(format!(
            "mask generates {} candidates per word; the cap this arc is {}",
            plan.candidate_count, MAX_CANDIDATES
        ));
    }
    let slots = mask_slots(mask)?;
    Ok(expand_mask(&slots, plan.candidate_count.min(1024) as usize))
}

fn words_from_bytes(body: &[u8], limit: usize) -> Vec<String> {
    String::from_utf8_lossy(body)
        .lines()
        .map(|l| l.trim_end_matches(char::is_control).to_string())
        .filter(|l| !l.is_empty())
        .take(limit)
        .collect()
}

/// Hybrid attack: every wordlist word (capped) + mask suffix.
/// Word list arrives as raw bytes so the dialog read stays testable.
pub fn hybrid_over_bytes(algo: &str, target: &str, mask: &str, body: &[u8]) -> Result<AttackResultWire, String> {
    let t = guard(algo, target)?;
    let suffixes = mask_expansions(mask)?;
    let words = words_from_bytes(body, 500); // word cap keeps the product bounded
    let started = Instant::now();
    let mut session = AttackSession::new(&t);
    'outer: for word in &words {
        for suffix in &suffixes {
            let candidate = format!("{word}{suffix}");
            if !session.test(algo, &candidate, session.generated + 1) {
                break 'outer;
            }
        }
    }
    Ok(wire("hybrid", algo.to_string(), t, format!("wordlist + {mask}"), session, started.elapsed().as_millis() as u64))
}

/// Reverse hybrid: mask prefix + every wordlist word (capped).
pub fn hybrid_reverse_over_bytes(algo: &str, target: &str, mask: &str, body: &[u8]) -> Result<AttackResultWire, String> {
    let t = guard(algo, target)?;
    let prefixes = mask_expansions(mask)?;
    let words = words_from_bytes(body, 500);
    let started = Instant::now();
    let mut session = AttackSession::new(&t);
    'outer: for prefix in &prefixes {
        for word in &words {
            let candidate = format!("{prefix}{word}");
            if !session.test(algo, &candidate, session.generated + 1) {
                break 'outer;
            }
        }
    }
    Ok(wire("hybrid-reverse", algo.to_string(), t, format!("{mask} + wordlist"), session, started.elapsed().as_millis() as u64))
}

/// Full combinator: first wordlist x second wordlist, both capped at 500.
pub fn combinator_over_bytes(algo: &str, target: &str, first_body: &[u8], second_body: &[u8]) -> Result<AttackResultWire, String> {
    let t = guard(algo, target)?;
    let first = words_from_bytes(first_body, 500);
    let second = words_from_bytes(second_body, 500);
    let started = Instant::now();
    let mut session = AttackSession::new(&t);
    'outer: for a in &first {
        for b in &second {
            let candidate = format!("{a}{b}");
            if !session.test(algo, &candidate, session.generated + 1) {
                break 'outer;
            }
        }
    }
    Ok(wire(
        "combinator",
        algo.to_string(),
        t,
        format!("wordlist x wordlist ({} x {})", first.len(), second.len()),
        session,
        started.elapsed().as_millis() as u64,
    ))
}

#[tauri::command]
pub fn crack_hybrid_dialog(
    app: tauri::AppHandle,
    algo: String,
    target_hash: String,
    mask: String,
    wordlist_path: Option<String>,
    ctx: tauri::State<'_, crate::evidence::EvidenceCtx>,
) -> Result<AttackResultWire, String> {
    let target = guard(&algo, &target_hash)?;
    // The UI's chosen wordlist is reused; a dialog opens only when none is set.
    let (path, name) = crate::crack::resolved_wordlist(&app, wordlist_path.as_deref())?;
    let body = std::fs::read(&path).map_err(|e| format!("cannot read wordlist: {e}"))?;
    let mut result = hybrid_over_bytes(&algo, &target, &mask, &body)?;
    result.source = format!("{name} + {mask}");
    record_history(&ctx, &algo, &target, &format!("hybrid wordlist + {mask}"), &result.matches);
    Ok(result)
}

#[tauri::command]
pub fn crack_hybrid_reverse_dialog(
    app: tauri::AppHandle,
    algo: String,
    target_hash: String,
    mask: String,
    wordlist_path: Option<String>,
    ctx: tauri::State<'_, crate::evidence::EvidenceCtx>,
) -> Result<AttackResultWire, String> {
    let target = guard(&algo, &target_hash)?;
    let (path, name) = crate::crack::resolved_wordlist(&app, wordlist_path.as_deref())?;
    let body = std::fs::read(&path).map_err(|e| format!("cannot read wordlist: {e}"))?;
    let mut result = hybrid_reverse_over_bytes(&algo, &target, &mask, &body)?;
    result.source = format!("{mask} + {name}");
    record_history(&ctx, &algo, &target, &format!("hybrid mask + wordlist ({mask})"), &result.matches);
    Ok(result)
}

#[tauri::command]
pub fn crack_combinator_dialog(
    app: tauri::AppHandle,
    algo: String,
    target_hash: String,
    wordlist_path: Option<String>,
    second_wordlist_path: Option<String>,
    ctx: tauri::State<'_, crate::evidence::EvidenceCtx>,
) -> Result<AttackResultWire, String> {
    let target = guard(&algo, &target_hash)?;
    let (first_path, first_name) = crate::crack::resolved_wordlist(&app, wordlist_path.as_deref())?;
    let (second_path, second_name) =
        crate::crack::resolved_wordlist(&app, second_wordlist_path.as_deref())?;
    let first_body = std::fs::read(&first_path).map_err(|e| format!("cannot read first wordlist: {e}"))?;
    let second_body = std::fs::read(&second_path).map_err(|e| format!("cannot read second wordlist: {e}"))?;
    let mut result = combinator_over_bytes(&algo, &target, &first_body, &second_body)?;
    result.source = format!("{first_name} x {second_name}");
    record_history(
        &ctx,
        &algo,
        &target,
        &format!("combinator {first_name} x {second_name}"),
        &result.matches,
    );
    Ok(result)
}

#[derive(Debug, Serialize)]
pub struct BenchmarkWire {
    pub algo: String,
    pub hashes_per_second: f64,
    pub duration_ms: u64,
    pub threads: usize,
}

/// Measure the native engine's digest rate for an algorithm.
#[tauri::command]
pub fn benchmark(algo: String, duration_ms: Option<u64>) -> Result<BenchmarkWire, String> {
    if hacktool_crypto::kdf_format(&algo).is_some() {
        return Err("KDF formats are deliberately slow; benchmark a digest instead".to_string());
    }
    hacktool_crypto::apply_op(&algo, b"bench", None)?; // validate algo
    let budget = Duration::from_millis(duration_ms.unwrap_or(2000).clamp(200, 10_000));
    let started = Instant::now();
    let mut count: u64 = 0;
    let mut input = *b"benchmark-input-0000";
    while started.elapsed() < budget {
        for i in 0..1000u32 {
            input[16..20].copy_from_slice(&i.to_be_bytes());
            let _ = hacktool_crypto::apply_op(&algo, &input, None)?;
            count += 1;
        }
    }
    let elapsed = started.elapsed();
    let hps = count as f64 / elapsed.as_secs_f64();
    Ok(BenchmarkWire {
        algo,
        hashes_per_second: hps,
        duration_ms: elapsed.as_millis() as u64,
        threads: 1,
    })
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
    fn mask_with_leading_literal_finds_the_needle() {
        // The literal before the classes takes a slot but is not a class; the
        // odometer must index classes, not slots, and still walk the whole space.
        assert_eq!(plan_mask("a?d?d").unwrap().candidate_count, 100);
        let target = hacktool_crypto::apply_op("sha256", b"a99", None).unwrap();
        let result = mask_attack("sha256", &hex::encode(target), "a?d?d").unwrap();
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].password, "a99");
        assert_eq!(result.tried, 100);
    }

    #[test]
    fn mask_with_non_ascii_literal_finds_the_needle() {
        let target = hacktool_crypto::apply_op("sha256", "é7".as_bytes(), None).unwrap();
        let result = mask_attack("sha256", &hex::encode(target), "é?d").unwrap();
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].password, "é7");
        assert_eq!(result.tried, 10);
    }

    #[test]
    fn rules_handle_non_ascii_wordlist_entries() {
        // Multi-byte words used to panic on byte-index slicing inside the rules.
        let target = hacktool_crypto::apply_op("sha256", "Café123".as_bytes(), None).unwrap();
        let result = rules_over_bytes("sha256", &hex::encode(target), "é\n日本\ncafé\n".as_bytes()).unwrap();
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].password, "Café123");
        assert!(result.tried > 0);
    }

    #[test]
    fn hybrid_handles_literal_prefixed_masks_and_non_ascii_words() {
        // "a?d?d" yields 100 suffixes despite the leading literal, and the
        // non-ASCII wordlist words must survive byte handling intact.
        let target = hacktool_crypto::apply_op("sha256", "caféa99".as_bytes(), None).unwrap();
        let result = hybrid_over_bytes("sha256", &hex::encode(target), "a?d?d", "café\n日本\n".as_bytes()).unwrap();
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].password, "caféa99");
        assert_eq!(result.tried, 200); // 2 words x 100 suffixes
        assert!(!result.cap_reached);
    }

    #[test]
    fn reverse_hybrid_finds_mask_prefixed_word() {
        let target = hacktool_crypto::apply_op("sha256", b"42hello", None).unwrap();
        let result = hybrid_reverse_over_bytes("sha256", &hex::encode(target), "?d?d", b"hello\nworld\n").unwrap();
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].password, "42hello");
        assert_eq!(result.tried, 200); // 100 prefixes x 2 words
    }

    #[test]
    fn combinator_finds_joined_words() {
        let target = hacktool_crypto::apply_op("sha256", b"helloworld", None).unwrap();
        let result = combinator_over_bytes("sha256", &hex::encode(target), b"hello\nfoo\n", b"world\nbar\n").unwrap();
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].password, "helloworld");
        assert_eq!(result.tried, 4);
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
