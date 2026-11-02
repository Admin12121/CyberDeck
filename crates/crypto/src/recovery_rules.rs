//! Bounded native password-recovery rule engine.
//! A byte-oriented implementation of the Hashcat rule grammar written from
//! scratch in Rust; semantics were translated from the documented upstream
//! rule definitions (reference/hashcat, MIT). Memory opcodes (M 4 6 X Q) and
//! character-class operands are not implemented; rule library files are
//! parsed tolerantly and unsupported lines are skipped with a count.
use super::MAX_CANDIDATE_BYTES;

/// Hashcat itself caps a rule at 31 operations; we allow some headroom.
pub const MAX_RULE_INSTRUCTIONS: usize = 64;
pub const MAX_RULES_PER_STREAM: usize = 65_536;

#[derive(Clone, Debug, PartialEq, Eq)]
enum RuleAction {
    Identity,
    Lower,
    Upper,
    Capitalize,
    CapitalizeInvert,
    ToggleAll,
    Toggle(usize),
    ToggleAfterOccurrence(usize, u8),
    Reverse,
    Duplicate,
    DuplicateTimes(usize),
    Reflect,
    RotateLeft,
    RotateRight,
    Append(u8),
    Prepend(u8),
    DeleteFirst,
    DeleteLast,
    DeleteAt(usize),
    Extract(usize, usize),
    Omit(usize, usize),
    InsertAt(usize, u8),
    InsertEvery(usize, u8),
    OverwriteAt(usize, u8),
    TruncateAt(usize),
    Substitute(u8, u8),
    PurgeChar(u8),
    DupeCharFirst(usize),
    DupeCharLast(usize),
    DupeCharAll,
    SwapFirstTwo,
    SwapLastTwo,
    SwapAt(usize, usize),
    ChrShiftLeft(usize),
    ChrShiftRight(usize),
    ChrIncr(usize),
    ChrDecr(usize),
    ChrAdd(usize, u8),
    ReplaceNext(usize),
    ReplacePrev(usize),
    DupeBlockFirst(usize),
    DupeBlockLast(usize),
    TitleAll,
    TitleAfter(u8),
    ToHexLower,
    ToHexUpper,
    RejectLess(usize),
    RejectGreater(usize),
    RejectNotEqual(usize),
    RejectContains(u8),
    RejectNotContains(u8),
    RejectFirst(u8),
    RejectLast(u8),
    RejectAt(usize, u8),
    RejectCountLess(usize, u8),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledRule {
    actions: Vec<RuleAction>,
}

/// Upstream positional operands use 0-9 then A-Z (values 0..=35).
fn conv_digit(byte: u8) -> Option<usize> {
    match byte {
        b'0'..=b'9' => Some(usize::from(byte - b'0')),
        b'A'..=b'Z' => Some(usize::from(byte - b'A') + 10),
        _ => None,
    }
}

struct Parser<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Parser<'a> {
    fn next(&mut self) -> Result<u8, String> {
        let byte = *self
            .bytes
            .get(self.cursor)
            .ok_or("missing rule argument")?;
        self.cursor += 1;
        Ok(byte)
    }
    fn position(&mut self) -> Result<usize, String> {
        let byte = self.next()?;
        conv_digit(byte).ok_or_else(|| {
            format!("rule position must be 0-9 or A-Z, got {}", byte as char)
        })
    }
    /// Character operands accept \xHH for untypeable bytes.
    fn char_operand(&mut self) -> Result<u8, String> {
        if self.bytes.get(self.cursor) == Some(&b'\\') && self.bytes.get(self.cursor + 1) == Some(&b'x') {
            let high = *self
                .bytes
                .get(self.cursor + 2)
                .ok_or("incomplete \\x escape")?;
            let low = *self
                .bytes
                .get(self.cursor + 3)
                .ok_or("incomplete \\x escape")?;
            let hex = |b: u8| -> Option<u8> {
                match b {
                    b'0'..=b'9' => Some(b - b'0'),
                    b'a'..=b'f' => Some(b - b'a' + 10),
                    b'A'..=b'F' => Some(b - b'A' + 10),
                    _ => None,
                }
            };
            let value = hex(high)
                .and_then(|h| hex(low).map(|l| h * 16 + l))
                .ok_or("invalid \\x escape digits")?;
            self.cursor += 4;
            return Ok(value);
        }
        self.next()
    }
}

fn checked_push(bytes: &mut Vec<u8>, count: usize) -> Result<(), String> {
    if bytes.len().saturating_add(count) > MAX_CANDIDATE_BYTES {
        return Err("rule expansion exceeds byte cap".into());
    }
    Ok(())
}

impl CompiledRule {
    /// Strict parse of one rule line; syntax: Hashcat rule subset.
    pub fn parse(source: &str) -> Result<Self, String> {
        Self::parse_bytes(source.as_bytes())
    }

    fn parse_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() {
            return Err("rule must be nonempty".into());
        }
        let mut parser = Parser { bytes, cursor: 0 };
        let mut actions = Vec::new();
        while parser.cursor < bytes.len() {
            if actions.len() >= MAX_RULE_INSTRUCTIONS {
                return Err("rule too complex".into());
            }
            // Upstream treats a space in opcode position as padding; an opcode
            // that reads a character operand still consumes it (e.g. `$ `).
            if bytes[parser.cursor] == b' ' {
                parser.cursor += 1;
                continue;
            }
            let op = parser.next()?;
            let action = match op {
                b':' => RuleAction::Identity,
                b'l' => RuleAction::Lower,
                b'u' => RuleAction::Upper,
                b'c' => RuleAction::Capitalize,
                b'C' => RuleAction::CapitalizeInvert,
                b't' => RuleAction::ToggleAll,
                b'T' => RuleAction::Toggle(parser.position()?),
                b'3' => {
                    let occurrences = parser.position()?;
                    let separator = parser.char_operand()?;
                    RuleAction::ToggleAfterOccurrence(occurrences, separator)
                }
                b'r' => RuleAction::Reverse,
                b'd' => RuleAction::Duplicate,
                b'p' => RuleAction::DuplicateTimes(parser.position()?),
                b'f' => RuleAction::Reflect,
                b'{' => RuleAction::RotateLeft,
                b'}' => RuleAction::RotateRight,
                b'$' => RuleAction::Append(parser.char_operand()?),
                b'^' => RuleAction::Prepend(parser.char_operand()?),
                b'[' => RuleAction::DeleteFirst,
                b']' => RuleAction::DeleteLast,
                b'D' => RuleAction::DeleteAt(parser.position()?),
                b'x' => {
                    let position = parser.position()?;
                    let count = parser.position()?;
                    RuleAction::Extract(position, count)
                }
                b'O' => {
                    let position = parser.position()?;
                    let count = parser.position()?;
                    RuleAction::Omit(position, count)
                }
                b'i' => {
                    let position = parser.position()?;
                    let value = parser.char_operand()?;
                    RuleAction::InsertAt(position, value)
                }
                b'v' => {
                    let every = parser.position()?;
                    let value = parser.char_operand()?;
                    RuleAction::InsertEvery(every, value)
                }
                b'o' => {
                    let position = parser.position()?;
                    let value = parser.char_operand()?;
                    RuleAction::OverwriteAt(position, value)
                }
                b'\'' => RuleAction::TruncateAt(parser.position()?),
                b's' => {
                    let from = parser.char_operand()?;
                    let to = parser.char_operand()?;
                    RuleAction::Substitute(from, to)
                }
                b'@' => RuleAction::PurgeChar(parser.char_operand()?),
                b'z' => RuleAction::DupeCharFirst(parser.position()?),
                b'Z' => RuleAction::DupeCharLast(parser.position()?),
                b'q' => RuleAction::DupeCharAll,
                b'k' => RuleAction::SwapFirstTwo,
                b'K' => RuleAction::SwapLastTwo,
                b'*' => {
                    let first = parser.position()?;
                    let second = parser.position()?;
                    RuleAction::SwapAt(first, second)
                }
                b'L' => RuleAction::ChrShiftLeft(parser.position()?),
                b'R' => RuleAction::ChrShiftRight(parser.position()?),
                b'+' => RuleAction::ChrIncr(parser.position()?),
                b'-' => RuleAction::ChrDecr(parser.position()?),
                b'B' => {
                    let position = parser.position()?;
                    let value = parser.position()?;
                    RuleAction::ChrAdd(position, value as u8)
                }
                b'.' => RuleAction::ReplaceNext(parser.position()?),
                b',' => RuleAction::ReplacePrev(parser.position()?),
                b'y' => RuleAction::DupeBlockFirst(parser.position()?),
                b'Y' => RuleAction::DupeBlockLast(parser.position()?),
                b'E' => RuleAction::TitleAll,
                b'e' => RuleAction::TitleAfter(parser.char_operand()?),
                b'h' => RuleAction::ToHexLower,
                b'H' => RuleAction::ToHexUpper,
                b'<' => RuleAction::RejectLess(parser.position()?),
                b'>' => RuleAction::RejectGreater(parser.position()?),
                b'_' => RuleAction::RejectNotEqual(parser.position()?),
                b'!' => RuleAction::RejectContains(parser.char_operand()?),
                b'/' => RuleAction::RejectNotContains(parser.char_operand()?),
                b'(' => RuleAction::RejectFirst(parser.char_operand()?),
                b')' => RuleAction::RejectLast(parser.char_operand()?),
                b'=' => {
                    let position = parser.position()?;
                    let value = parser.char_operand()?;
                    RuleAction::RejectAt(position, value)
                }
                b'%' => {
                    let minimum = parser.position()?;
                    let value = parser.char_operand()?;
                    RuleAction::RejectCountLess(minimum, value)
                }
                _ => return Err(format!("unsupported rule opcode {}", op as char)),
            };
            actions.push(action);
        }
        Ok(Self { actions })
    }

    /// Applies the rule to a candidate. `Ok(None)` means the rule rejected the
    /// candidate (upstream rejection opcodes); the candidate yields no variant.
    pub fn apply(&self, candidate: &[u8]) -> Result<Option<Vec<u8>>, String> {
        if candidate.len() > MAX_CANDIDATE_BYTES {
            return Err("candidate too long".into());
        }
        let mut bytes = candidate.to_vec();
        for action in &self.actions {
            let reject = match *action {
                RuleAction::Identity => false,
                RuleAction::Lower => {
                    bytes.make_ascii_lowercase();
                    false
                }
                RuleAction::Upper => {
                    bytes.make_ascii_uppercase();
                    false
                }
                RuleAction::Capitalize => {
                    bytes.make_ascii_lowercase();
                    if let Some(first) = bytes.first_mut() {
                        first.make_ascii_uppercase();
                    }
                    false
                }
                RuleAction::CapitalizeInvert => {
                    bytes.make_ascii_uppercase();
                    if let Some(first) = bytes.first_mut() {
                        first.make_ascii_lowercase();
                    }
                    false
                }
                RuleAction::ToggleAll => {
                    for byte in &mut bytes {
                        if byte.is_ascii_lowercase() {
                            byte.make_ascii_uppercase();
                        } else if byte.is_ascii_uppercase() {
                            byte.make_ascii_lowercase();
                        }
                    }
                    false
                }
                RuleAction::Toggle(n) => {
                    if let Some(byte) = bytes.get_mut(n) {
                        if byte.is_ascii_lowercase() {
                            byte.make_ascii_uppercase();
                        } else if byte.is_ascii_uppercase() {
                            byte.make_ascii_lowercase();
                        }
                    }
                    false
                }
                RuleAction::ToggleAfterOccurrence(occurrences, separator) => {
                    let mut seen = 0usize;
                    for index in 0..bytes.len() {
                        if bytes[index] == separator {
                            seen += 1;
                            if seen == occurrences {
                                if let Some(byte) = bytes.get_mut(index + 1) {
                                    if byte.is_ascii_lowercase() {
                                        byte.make_ascii_uppercase();
                                    } else if byte.is_ascii_uppercase() {
                                        byte.make_ascii_lowercase();
                                    }
                                }
                                break;
                            }
                        }
                    }
                    false
                }
                RuleAction::Reverse => {
                    bytes.reverse();
                    false
                }
                RuleAction::Duplicate => {
                    let length = bytes.len();
                    checked_push(&mut bytes, length)?;
                    let cloned = bytes.clone();
                    bytes.extend_from_slice(&cloned);
                    false
                }
                RuleAction::DuplicateTimes(times) => {
                    // Upstream: the original word plus `times` additional copies.
                    let word = bytes.clone();
                    checked_push(&mut bytes, word.len().saturating_mul(times))?;
                    for _ in 0..times {
                        bytes.extend_from_slice(&word);
                    }
                    false
                }
                RuleAction::Reflect => {
                    let mut tail = bytes.clone();
                    tail.reverse();
                    checked_push(&mut bytes, tail.len())?;
                    bytes.extend_from_slice(&tail);
                    false
                }
                RuleAction::RotateLeft => {
                    if !bytes.is_empty() {
                        bytes.rotate_left(1);
                    }
                    false
                }
                RuleAction::RotateRight => {
                    if !bytes.is_empty() {
                        bytes.rotate_right(1);
                    }
                    false
                }
                RuleAction::Append(value) => {
                    checked_push(&mut bytes, 1)?;
                    bytes.push(value);
                    false
                }
                RuleAction::Prepend(value) => {
                    checked_push(&mut bytes, 1)?;
                    bytes.insert(0, value);
                    false
                }
                RuleAction::DeleteFirst => {
                    if !bytes.is_empty() {
                        bytes.remove(0);
                    }
                    false
                }
                RuleAction::DeleteLast => {
                    bytes.pop();
                    false
                }
                RuleAction::DeleteAt(position) => {
                    if position < bytes.len() {
                        bytes.remove(position);
                    }
                    false
                }
                RuleAction::Extract(position, count) => {
                    // Upstream leaves the word unchanged when out of range.
                    if position < bytes.len() && position + count <= bytes.len() {
                        bytes.truncate(position + count);
                        bytes.drain(..position);
                    }
                    false
                }
                RuleAction::Omit(position, count) => {
                    if position < bytes.len() && position + count <= bytes.len() {
                        bytes.drain(position..position + count);
                    }
                    false
                }
                RuleAction::InsertAt(position, value) => {
                    if position <= bytes.len() {
                        checked_push(&mut bytes, 1)?;
                        bytes.insert(position.min(MAX_CANDIDATE_BYTES), value);
                    }
                    false
                }
                RuleAction::InsertEvery(every, value) => {
                    if every == 0 {
                        return Ok(Some(bytes));
                    }
                    let mut output = Vec::with_capacity(bytes.len() + bytes.len() / every + 1);
                    for (index, byte) in bytes.iter().enumerate() {
                        if index > 0 && index % every == 0 {
                            checked_push(&mut output, 1)?;
                            output.push(value);
                        }
                        checked_push(&mut output, 1)?;
                        output.push(*byte);
                    }
                    bytes = output;
                    false
                }
                RuleAction::OverwriteAt(position, value) => {
                    if let Some(byte) = bytes.get_mut(position) {
                        *byte = value;
                    }
                    false
                }
                RuleAction::TruncateAt(position) => {
                    if position < bytes.len() {
                        bytes.truncate(position);
                    }
                    false
                }
                RuleAction::Substitute(from, to) => {
                    for byte in &mut bytes {
                        if *byte == from {
                            *byte = to;
                        }
                    }
                    false
                }
                RuleAction::PurgeChar(value) => {
                    bytes.retain(|byte| *byte != value);
                    false
                }
                RuleAction::DupeCharFirst(times) => {
                    if let Some(&first) = bytes.first() {
                        if times > 0 {
                            checked_push(&mut bytes, times)?;
                            let mut prefix = vec![first; times];
                            prefix.extend_from_slice(&bytes);
                            bytes = prefix;
                        }
                    }
                    false
                }
                RuleAction::DupeCharLast(times) => {
                    if let Some(&last) = bytes.last().copied().as_ref() {
                        if times > 0 {
                            checked_push(&mut bytes, times)?;
                            bytes.extend(std::iter::repeat_n(last, times));
                        }
                    }
                    false
                }
                RuleAction::DupeCharAll => {
                    let original = bytes.clone();
                    bytes = original
                        .iter()
                        .flat_map(|byte| [*byte, *byte])
                        .collect::<Vec<u8>>();
                    false
                }
                RuleAction::SwapFirstTwo => {
                    if bytes.len() >= 2 {
                        bytes.swap(0, 1);
                    }
                    false
                }
                RuleAction::SwapLastTwo => {
                    if bytes.len() >= 2 {
                        let last = bytes.len() - 1;
                        bytes.swap(last - 1, last);
                    }
                    false
                }
                RuleAction::SwapAt(first, second) => {
                    if first < bytes.len() && second < bytes.len() {
                        bytes.swap(first, second);
                    }
                    false
                }
                RuleAction::ChrShiftLeft(position) => {
                    if let Some(byte) = bytes.get_mut(position) {
                        *byte = byte.wrapping_shl(1);
                    }
                    false
                }
                RuleAction::ChrShiftRight(position) => {
                    if let Some(byte) = bytes.get_mut(position) {
                        *byte = byte.wrapping_shr(1);
                    }
                    false
                }
                RuleAction::ChrIncr(position) => {
                    if let Some(byte) = bytes.get_mut(position) {
                        *byte = byte.wrapping_add(1);
                    }
                    false
                }
                RuleAction::ChrDecr(position) => {
                    if let Some(byte) = bytes.get_mut(position) {
                        *byte = byte.wrapping_sub(1);
                    }
                    false
                }
                RuleAction::ChrAdd(position, value) => {
                    if let Some(byte) = bytes.get_mut(position) {
                        *byte = byte.wrapping_add(value);
                    }
                    false
                }
                RuleAction::ReplaceNext(position) => {
                    if position < bytes.len() {
                        if let Some(next) = bytes.get(position + 1).copied() {
                            bytes[position] = next;
                        }
                    }
                    false
                }
                RuleAction::ReplacePrev(position) => {
                    if position > 0 && position < bytes.len() {
                        let previous = bytes[position - 1];
                        bytes[position] = previous;
                    }
                    false
                }
                RuleAction::DupeBlockFirst(count) => {
                    if count > 0 && count <= bytes.len() {
                        checked_push(&mut bytes, count)?;
                        let block = bytes[..count].to_vec();
                        bytes.splice(..0, block);
                    }
                    false
                }
                RuleAction::DupeBlockLast(count) => {
                    if count > 0 && count <= bytes.len() {
                        checked_push(&mut bytes, count)?;
                        let start = bytes.len() - count;
                        let block = bytes[start..].to_vec();
                        bytes.extend_from_slice(&block);
                    }
                    false
                }
                RuleAction::TitleAll => {
                    bytes.make_ascii_lowercase();
                    capitalize_after(&mut bytes, |index, bytes| {
                        index == 0 || index > 0 && bytes[index - 1] == b' '
                    });
                    false
                }
                RuleAction::TitleAfter(separator) => {
                    bytes.make_ascii_lowercase();
                    capitalize_after(&mut bytes, |index, bytes| {
                        index == 0 || index > 0 && bytes[index - 1] == separator
                    });
                    false
                }
                RuleAction::ToHexLower => {
                    bytes = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>().into_bytes();
                    if bytes.len() > MAX_CANDIDATE_BYTES {
                        return Err("rule expansion exceeds byte cap".into());
                    }
                    false
                }
                RuleAction::ToHexUpper => {
                    bytes = bytes.iter().map(|b| format!("{b:02X}")).collect::<String>().into_bytes();
                    if bytes.len() > MAX_CANDIDATE_BYTES {
                        return Err("rule expansion exceeds byte cap".into());
                    }
                    false
                }
                RuleAction::RejectLess(limit) => bytes.len() > limit,
                RuleAction::RejectGreater(minimum) => bytes.len() < minimum,
                RuleAction::RejectNotEqual(length) => bytes.len() != length,
                RuleAction::RejectContains(value) => bytes.contains(&value),
                RuleAction::RejectNotContains(value) => !bytes.contains(&value),
                RuleAction::RejectFirst(value) => bytes.first() != Some(&value),
                RuleAction::RejectLast(value) => bytes.last() != Some(&value),
                RuleAction::RejectAt(position, value) => {
                    position + 1 > bytes.len() || bytes.get(position) != Some(&value)
                }
                RuleAction::RejectCountLess(minimum, value) => {
                    let count = bytes.iter().filter(|byte| **byte == value).count();
                    count < minimum
                }
            };
            if reject {
                return Ok(None);
            }
        }
        Ok(Some(bytes))
    }
}

fn capitalize_after(bytes: &mut [u8], at: impl Fn(usize, &[u8]) -> bool) {
    for index in 0..bytes.len() {
        if at(index, bytes) && bytes[index].is_ascii_lowercase() {
            bytes[index].make_ascii_uppercase();
        }
    }
}

/// Strict parse of newline-delimited rules; any unsupported line is an error.
pub fn parse_rule_lines<R: std::io::BufRead>(reader: R) -> Result<Vec<CompiledRule>, String> {
    parse_rule_stream(reader, false).map(|parsed| parsed.rules)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRuleFile {
    pub rules: Vec<CompiledRule>,
    /// Lines rejected by the bounded grammar (memory opcodes, classes, unknown).
    pub skipped: u64,
}

/// Tolerant parse for rule library files: unsupported lines are skipped and
/// counted so an operator can see exactly how much of a shipped set is active.
pub fn parse_rule_file_tolerant<R: std::io::BufRead>(reader: R) -> Result<ParsedRuleFile, String> {
    parse_rule_stream(reader, true)
}

fn parse_rule_stream<R: std::io::BufRead>(
    reader: R,
    tolerant: bool,
) -> Result<ParsedRuleFile, String> {
    let mut rules = Vec::new();
    let mut skipped = 0u64;
    for (index, line) in crate::candidates::WordlistCandidates::new(reader).enumerate() {
        let line = line.map_err(|e| format!("rule line {}: {e}", index + 1))?;
        if line.is_empty() || line.first() == Some(&b'#') {
            continue;
        }
        if rules.len() == MAX_RULES_PER_STREAM {
            return Err("rule file exceeds maximum rules".into());
        }
        let script = std::str::from_utf8(&line).unwrap_or("\u{fffd}");
        match CompiledRule::parse(script) {
            Ok(rule) => rules.push(rule),
            Err(error) => {
                if !tolerant {
                    return Err(format!("rule line {}: {error}", index + 1));
                }
                skipped += 1;
            }
        }
    }
    if rules.is_empty() {
        return Err("no valid rules in file".into());
    }
    Ok(ParsedRuleFile { rules, skipped })
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
                } else if v.is_ascii_uppercase() {
                    v.to_ascii_lowercase()
                } else {
                    *v
                }
            })
            .collect(),
    };
    if result.len() > MAX_CANDIDATE_BYTES {
        return Err("rule expansion exceeds limit".into());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply_ok(rule: &str, word: &str) -> Option<String> {
        CompiledRule::parse(rule)
            .unwrap()
            .apply(word.as_bytes())
            .unwrap()
            .map(|bytes| String::from_utf8(bytes).unwrap())
    }

    #[test]
    fn upstream_mangle_semantics_match_reference_examples() {
        assert_eq!(apply_ok(":", "hello").as_deref(), Some("hello"));
        assert_eq!(apply_ok("l", "HeLLo").as_deref(), Some("hello"));
        assert_eq!(apply_ok("u", "hello").as_deref(), Some("HELLO"));
        assert_eq!(apply_ok("c", "hELLO").as_deref(), Some("Hello"));
        assert_eq!(apply_ok("C", "hello").as_deref(), Some("hELLO"));
        assert_eq!(apply_ok("t", "HeLLo").as_deref(), Some("hEllO"));
        assert_eq!(apply_ok("T1", "hello").as_deref(), Some("hEllo"));
        assert_eq!(apply_ok("r", "hello").as_deref(), Some("olleh"));
        assert_eq!(apply_ok("d", "hello").as_deref(), Some("hellohello"));
        assert_eq!(apply_ok("p1", "hello").as_deref(), Some("hellohello"));
        assert_eq!(apply_ok("p2", "ab").as_deref(), Some("ababab"));
        assert_eq!(apply_ok("f", "hello").as_deref(), Some("helloolleh"));
        assert_eq!(apply_ok("{", "hello").as_deref(), Some("elloh"));
        assert_eq!(apply_ok("}", "hello").as_deref(), Some("ohell"));
        assert_eq!(apply_ok("$1", "hello").as_deref(), Some("hello1"));
        assert_eq!(apply_ok("^1", "hello").as_deref(), Some("1hello"));
        assert_eq!(apply_ok("[", "hello").as_deref(), Some("ello"));
        assert_eq!(apply_ok("]", "hello").as_deref(), Some("hell"));
        assert_eq!(apply_ok("D1", "hello").as_deref(), Some("hllo"));
        assert_eq!(apply_ok("x13", "hello").as_deref(), Some("ell"));
        assert_eq!(apply_ok("O13", "hello").as_deref(), Some("ho"));
        assert_eq!(apply_ok("i2@", "hello").as_deref(), Some("he@llo"));
        assert_eq!(apply_ok("o1@", "hello").as_deref(), Some("h@llo"));
        assert_eq!(apply_ok("'3", "hello").as_deref(), Some("hel"));
        assert_eq!(apply_ok("sAB", "aXbX").as_deref(), Some("aXbX"));
        assert_eq!(apply_ok("sX@", "aXbX").as_deref(), Some("a@b@"));
        assert_eq!(apply_ok("@l", "hello").as_deref(), Some("heo"));
        assert_eq!(apply_ok("z2", "hello").as_deref(), Some("hhhello"));
        assert_eq!(apply_ok("Z2", "hello").as_deref(), Some("hellooo"));
        assert_eq!(apply_ok("q", "hello").as_deref(), Some("hheelllloo"));
        assert_eq!(apply_ok("k", "hello").as_deref(), Some("ehllo"));
        assert_eq!(apply_ok("K", "hello").as_deref(), Some("helol"));
        assert_eq!(apply_ok("*03", "hello").as_deref(), Some("lelho"));
        assert_eq!(apply_ok("y2", "hello").as_deref(), Some("hehello"));
        assert_eq!(apply_ok("Y2", "hello").as_deref(), Some("hellolo"));
        assert_eq!(apply_ok("E", "hello world").as_deref(), Some("Hello World"));
        assert_eq!(apply_ok("e ", "hello world").as_deref(), Some("Hello World"));
    }

    #[test]
    fn positional_character_ops_match_upstream() {
        assert_eq!(apply_ok("+5", "hello0").as_deref(), Some("hello1"));
        assert_eq!(apply_ok("-5", "hello1").as_deref(), Some("hello0"));
        assert_eq!(apply_ok(".0", "ab").as_deref(), Some("bb"));
        assert_eq!(apply_ok(",1", "ab").as_deref(), Some("aa"));
        assert_eq!(apply_ok("L5", "hello0").as_deref(), Some("hello`"));
        assert_eq!(apply_ok("R5", "hello`").as_deref(), Some("hello0"));
        assert_eq!(apply_ok("B5X", "hello0").as_deref(), Some("helloQ"));
    }

    #[test]
    fn hex_conversion_and_rejection_opcodes() {
        assert_eq!(apply_ok("h", "ab").as_deref(), Some("6162"));
        assert_eq!(apply_ok("H", "ab").as_deref(), Some("6162".to_uppercase()).as_deref());
        let rejected = CompiledRule::parse("<4").unwrap().apply(b"hello").unwrap();
        assert!(rejected.is_none());
        let accepted = CompiledRule::parse("<4").unwrap().apply(b"hey").unwrap();
        assert_eq!(accepted.as_deref(), Some(b"hey".as_slice()));
        assert!(CompiledRule::parse(">4").unwrap().apply(b"hey").unwrap().is_none());
        assert_eq!(CompiledRule::parse(">2").unwrap().apply(b"hey").unwrap().as_deref(), Some(b"hey".as_slice()));
        assert!(CompiledRule::parse("_3").unwrap().apply(b"hey!").unwrap().is_none());
        assert!(CompiledRule::parse("!e").unwrap().apply(b"hello").unwrap().is_none());
        assert!(CompiledRule::parse("/e").unwrap().apply(b"no").unwrap().is_none());
        assert!(CompiledRule::parse("(h").unwrap().apply(b"ello").unwrap().is_none());
        assert!(CompiledRule::parse(")o").unwrap().apply(b"hell").unwrap().is_none());
        assert!(CompiledRule::parse("=1e").unwrap().apply(b"hello").unwrap().is_some());
        assert!(CompiledRule::parse("=1x").unwrap().apply(b"hello").unwrap().is_none());
        assert_eq!(CompiledRule::parse("%2l").unwrap().apply(b"hello").unwrap().as_deref(), Some(b"hello".as_slice()));
        assert!(CompiledRule::parse("%2l").unwrap().apply(b"helo").unwrap().is_none());
    }

    #[test]
    fn hex_escapes_emit_raw_bytes() {
        let out = CompiledRule::parse("$\\x41").unwrap().apply(b"w").unwrap().unwrap();
        assert_eq!(out, b"wA");
        let out = CompiledRule::parse("^\\x41^\\x42").unwrap().apply(b"w").unwrap().unwrap();
        assert_eq!(out, b"BAw");
        let out = CompiledRule::parse("i1\\x00").unwrap().apply(b"ab").unwrap().unwrap();
        assert_eq!(out, b"a\x00b");
    }

    #[test]
    fn unsupported_memory_opcodes_are_rejected_strictly() {
        assert!(CompiledRule::parse("M").is_err());
        assert!(CompiledRule::parse("4").is_err());
        assert!(CompiledRule::parse("X02").is_err());
    }

    #[test]
    fn tolerant_parse_counts_unsupported_lines() {
        let input = ":\nM\n$1\nX02\nl\n";
        let parsed = parse_rule_file_tolerant(std::io::Cursor::new(input)).unwrap();
        assert_eq!(parsed.rules.len(), 3);
        assert_eq!(parsed.skipped, 2);
    }

    #[test]
    fn expansion_is_bounded_by_candidate_cap() {
        let parsed = CompiledRule::parse("pP").unwrap();
        let word = vec![b'a'; 3000];
        assert!(parsed.apply(&word).is_err());
    }
}
