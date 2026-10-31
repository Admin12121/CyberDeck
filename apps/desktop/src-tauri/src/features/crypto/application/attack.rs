//! Native CPU attack use cases. No Tauri commands or external processes.
use super::masks::{mask_slots, plan_mask, Slot, MAX_CANDIDATES};
use super::attack_domain::AttackMatch;
use super::rules::rule_variants;

const MAX_REPORTED_MATCHES: usize = 100;

pub(super) struct AttackSession {
    pub(super) target: Vec<u8>,
    pub(super) tried: u64,
    pub(super) generated: u64,
    pub(super) matches: Vec<AttackMatch>,
    pub(super) cap_reached: bool,
}

impl AttackSession {
    pub(super) fn new(target: &str) -> Self {
        Self {
            target: hex::decode(target).unwrap_or_default(),
            tried: 0,
            generated: 0,
            matches: Vec::new(),
            cap_reached: false,
        }
    }

    /// Compare decoded digest bytes; avoid hex formatting per candidate.
    /// Hash one candidate and record a hit. Returns false when the cap stops
    /// the session.
    pub(super) fn test(&mut self, algo: &str, candidate: &str, line_no: u64) -> bool {
        self.generated += 1;
        if self.generated > MAX_CANDIDATES {
            self.cap_reached = true;
            return false;
        }
        self.tried += 1;
        if let Ok(digest) = cyberdeck_crypto::apply_op(algo, candidate.as_bytes(), None) {
            if digest == self.target {
                self.matches.push(AttackMatch {
                    line_no,
                    password: candidate.to_string(),
                });
                if self.matches.len() >= MAX_REPORTED_MATCHES {
                    self.cap_reached = true;
                    return false;
                }
            }
        }
        true
    }
}



/// Stream built-in rule candidates through a bounded multi-worker queue.
/// A single atomic quota covers every worker, not an allocation per partition.
pub(super) fn run_rules(
    algo: &str,
    target: &str,
    words: impl Iterator<Item = Result<String, String>>,
) -> Result<AttackSession, String> {
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::mpsc::{sync_channel, TrySendError};
    use std::sync::Mutex;

    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 32);
    let (sender, receiver) = sync_channel::<(u64, String)>(256);
    let receiver = Mutex::new(receiver);
    let stop = AtomicBool::new(false);
    let generated = AtomicU64::new(0);
    let hit_count = AtomicUsize::new(0);

    let (partials, read_error) = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let receiver = &receiver;
            let stop = &stop;
            let generated = &generated;
            let hit_count = &hit_count;
            handles.push(scope.spawn(move || {
                let mut session = AttackSession::new(target);
                'work: loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    let item = receiver.lock().expect("rule queue poisoned").recv();
                    let (word_index, word) = match item {
                        Ok(item) => item,
                        Err(_) => break,
                    };
                    for (variant_index, candidate) in rule_variants(&word).into_iter().enumerate() {
                        if stop.load(Ordering::Relaxed) {
                            break 'work;
                        }
                        if generated
                            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                                (n < MAX_CANDIDATES).then_some(n + 1)
                            })
                            .is_err()
                        {
                            session.cap_reached = true;
                            stop.store(true, Ordering::Relaxed);
                            break 'work;
                        }
                        let id = word_index.saturating_mul(1000).saturating_add(variant_index as u64);
                        let before = session.matches.len();
                        if !session.test(algo, &candidate, id) {
                            stop.store(true, Ordering::Relaxed);
                            break 'work;
                        }
                        if session.matches.len() != before
                            && hit_count.fetch_add(1, Ordering::Relaxed) + 1 >= MAX_REPORTED_MATCHES
                        {
                            session.cap_reached = true;
                            stop.store(true, Ordering::Relaxed);
                            break 'work;
                        }
                    }
                }
                session
            }));
        }

        let mut next_word = 0u64;
        let mut read_error = None;
        'produce: for word in words {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let word = match word {
                Ok(word) => word,
                Err(error) => {
                    read_error = Some(error);
                    stop.store(true, Ordering::Relaxed);
                    break;
                }
            };
            let trimmed = word.trim_end_matches('\r');
            if trimmed.is_empty() {
                continue;
            }
            let mut item = (next_word, trimmed.to_owned());
            next_word = next_word.saturating_add(1);
            loop {
                if stop.load(Ordering::Relaxed) {
                    break 'produce;
                }
                match sender.try_send(item) {
                    Ok(()) => break,
                    Err(TrySendError::Full(pending)) => {
                        item = pending;
                        std::thread::yield_now();
                    }
                    Err(TrySendError::Disconnected(_)) => {
                        read_error = Some("rule workers disconnected".to_owned());
                        break 'produce;
                    }
                }
            }
        }
        drop(sender);
        let partials = handles.into_iter()
            .map(|handle| handle.join().unwrap_or_else(|_| AttackSession::new(target)))
            .collect::<Vec<_>>();
        (partials, read_error)
    });
    if let Some(error) = read_error {
        return Err(error);
    }
    let mut merged = merge_sessions(partials);
    merged.generated = generated.load(std::sync::atomic::Ordering::Relaxed);
    Ok(merged)
}

pub(super) fn merge_sessions(partials: Vec<AttackSession>) -> AttackSession {
    let mut merged = AttackSession::new("");
    for partial in partials {
        merged.tried += partial.tried;
        merged.generated += partial.generated;
        merged.cap_reached |= partial.cap_reached;
        merged.matches.extend(partial.matches);
    }
    merged.matches.sort_by_key(|hit| hit.line_no);
    merged.matches.truncate(MAX_REPORTED_MATCHES);
    merged.target.clear();
    merged
}

pub(super) fn run_mask(algo: &str, target: &str, mask: &str) -> Result<AttackSession, String> {
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
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 32);
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
                            run_mask_odometer(
                                algo,
                                &mut session,
                                slots.as_slice(),
                                0,
                                first_value,
                                &stop,
                            );
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
        partials = handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|_| AttackSession::new(target)))
            .collect();
    });
    Ok(merge_sessions(partials))
}

/// One odometer pass. `pinned_class` fixes the given class to `pinned_value`
/// (the parallel slice); usize::MAX means run free.
fn run_mask_odometer(
    algo: &str,
    session: &mut AttackSession,
    slots: &[Slot],
    pinned_class: usize,
    pinned_value: usize,
    stop: &std::sync::atomic::AtomicBool,
) {
    let class_sets: Vec<&Vec<char>> = slots
        .iter()
        .filter_map(|s| match s {
            Slot::Class(set) => Some(set),
            Slot::Literal(_) => None,
        })
        .collect();
    let class_count = class_sets.len();
    let mut counters = vec![0usize; class_count];
    if pinned_class != usize::MAX {
        if let Some(counter) = counters.get_mut(pinned_class) {
            *counter = pinned_value;
        }
    }
    let total: u64 = class_sets
        .iter()
        .enumerate()
        .map(|(i, set)| {
            if i == pinned_class {
                1
            } else {
                set.len() as u64
            }
        })
        .product();
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

use std::time::Instant;
use super::attack_domain::AttackResultWire;
use super::masks::mask_expansions;

const SUPPORTED: &[&str] = &["md5", "sha1", "sha256", "sha512"];

pub(super) fn guard(algo: &str, target: &str) -> Result<String, String> {
    if cyberdeck_crypto::kdf_format(target).is_some() {
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

fn wire(
    mode: &str,
    algo: String,
    target: String,
    source: String,
    session: AttackSession,
    duration_ms: u64,
) -> AttackResultWire {
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
        threads: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            .clamp(1, 32),
        engine: "cyberdeck-crypto".to_string(),
        engine_version: cyberdeck_crypto::ENGINE_VERSION.to_string(),
    }
}

/// Wordlist + built-in rules. The wordlist body arrives from the caller
/// (dialog in the command, bytes in tests) so the file read stays testable.
pub fn rules_over_bytes(algo: &str, target: &str, body: &[u8]) -> Result<AttackResultWire, String> {
    let text = String::from_utf8_lossy(body);
    rules_over_lines(algo, target, text.lines().map(|line| Ok(line.to_string())))
}

pub fn rules_over_lines(
    algo: &str,
    target: &str,
    words: impl Iterator<Item = Result<String, String>>,
) -> Result<AttackResultWire, String> {
    let target = guard(algo, target)?;
    let started = Instant::now();
    let session = run_rules(algo, &target, words)?;
    Ok(wire(
        "rules",
        algo.to_string(),
        target,
        "wordlist + built-in rules".to_string(),
        session,
        started.elapsed().as_millis() as u64,
    ))
}

pub(super) fn mask_attack(algo: &str, target_hash: &str, mask: &str) -> Result<AttackResultWire, String> {
    let target = guard(algo, target_hash)?;
    let started = Instant::now();
    let session = run_mask(algo, &target, mask)?;
    Ok(wire(
        "mask",
        algo.to_string(),
        target,
        mask.to_string(),
        session,
        started.elapsed().as_millis() as u64,
    ))
}

/// Expand a validated mask into up to `limit` concrete strings in odometer
/// order. Literals are copied, classes cycle over their charsets.
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
pub fn hybrid_over_bytes(
    algo: &str,
    target: &str,
    mask: &str,
    body: &[u8],
) -> Result<AttackResultWire, String> {
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
    Ok(wire(
        "hybrid",
        algo.to_string(),
        t,
        format!("wordlist + {mask}"),
        session,
        started.elapsed().as_millis() as u64,
    ))
}

/// Reverse hybrid: mask prefix + every wordlist word (capped).
pub fn hybrid_reverse_over_bytes(
    algo: &str,
    target: &str,
    mask: &str,
    body: &[u8],
) -> Result<AttackResultWire, String> {
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
    Ok(wire(
        "hybrid-reverse",
        algo.to_string(),
        t,
        format!("{mask} + wordlist"),
        session,
        started.elapsed().as_millis() as u64,
    ))
}

/// Full combinator: first wordlist x second wordlist, both capped at 500.
pub fn combinator_over_bytes(
    algo: &str,
    target: &str,
    first_body: &[u8],
    second_body: &[u8],
) -> Result<AttackResultWire, String> {
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



#[cfg(test)]
mod streaming_tests {
    use super::*;

    #[test]
    fn rule_stream_preserves_legacy_candidate_generation() {
        let target = hex::encode(cyberdeck_crypto::apply_op("sha256", b"Hello123", None).unwrap());
        let words = ["hello", "world"].into_iter().map(|word| Ok(word.to_owned()));
        let result = rules_over_lines("sha256", &target, words).unwrap();
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].password, "Hello123");
        assert!(result.tried > 0);
    }

    #[test]
    fn rule_stream_propagates_io_failures() {
        let target = "0".repeat(32);
        let words = vec![
            Ok("hello".to_owned()),
            Err("injected wordlist read error".to_owned()),
        ].into_iter();
        let failure = rules_over_lines("md5", &target, words).unwrap_err();
        assert!(failure.contains("injected wordlist read error"));
    }
}
