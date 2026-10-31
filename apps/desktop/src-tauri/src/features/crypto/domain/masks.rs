//! Native mask grammar, keyspace accounting and bounded expansion.
//! No Tauri, persistence, or external process dependencies.
use serde::Serialize;

pub(super) const MAX_CANDIDATES: u64 = 20_000_000;
const SPECIAL_CHARSET: &str = "!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~ ";

#[derive(Debug, Serialize)]
pub struct MaskPlan {
    pub candidate_count: u64,
    pub charset_sizes: Vec<usize>,
}

fn charset_size(kind: char) -> Option<usize> {
    match kind {
        'l' | 'u' => Some(26),
        'd' => Some(10),
        's' => Some(SPECIAL_CHARSET.chars().count()),
        'a' => Some(95),
        _ => None,
    }
}

fn mask_charset(kind: char) -> Option<Vec<char>> {
    match kind {
        'l' => Some(('a'..='z').collect()),
        'u' => Some(('A'..='Z').collect()),
        'd' => Some(('0'..='9').collect()),
        's' => Some(SPECIAL_CHARSET.chars().collect()),
        'a' => Some((' '..='~').collect()),
        _ => None,
    }
}

pub(super) fn plan_mask(mask: &str) -> Result<MaskPlan, String> {
    let mut sizes = Vec::new();
    let mut chars = mask.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '?' {
            let kind = chars.next().ok_or("mask ends with a dangling '?'")?;
            match kind {
                'l' | 'u' | 'd' | 's' | 'a' => sizes.push(charset_size(kind).unwrap()),
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
    Ok(MaskPlan {
        candidate_count: count,
        charset_sizes: sizes,
    })
}

#[derive(Clone)]
pub(super) enum Slot {
    Class(Vec<char>),
    Literal(char),
}

pub(super) fn mask_slots(mask: &str) -> Result<Vec<Slot>, String> {
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
pub(super) fn mask_expansions(mask: &str) -> Result<Vec<String>, String> {
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
