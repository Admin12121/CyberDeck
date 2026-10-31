//! Deterministic built-in rule expansion, independent of Tauri/IPC.

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
pub(super) fn rule_variants(word: &str) -> Vec<String> {
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
    let leet_vowels = word
        .replace(['a', 'A'], "4")
        .replace(['e', 'E'], "3")
        .replace(['o', 'O'], "0");

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
    // prepend digits and specials (the duplicate candidate is already above)
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
