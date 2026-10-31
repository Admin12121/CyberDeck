//! Bounded native password-recovery rule grammar and transformations.
use super::MAX_CANDIDATE_BYTES;

/// A bounded native byte-oriented rule subset; not full JtR/Hashcat syntax.
pub const MAX_RULE_INSTRUCTIONS: usize = 64;
pub const MAX_RULES_PER_STREAM: usize = 256;
#[derive(Clone, Debug, PartialEq, Eq)]
enum RuleAction {
    Identity,
    Lower,
    Upper,
    Capitalize,
    Reverse,
    Duplicate,
    Append(u8),
    Prepend(u8),
    Toggle(usize),
    Substitute(u8, u8),
    DeleteFirst,
    DeleteLast,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledRule {
    actions: Vec<RuleAction>,
}
impl CompiledRule {
    /// Syntax: : l u c r d $X ^X TN sXY [ ]; N is 0-9/A-Z.
    pub fn parse(source: &str) -> Result<Self, String> {
        if source.is_empty() || source.bytes().any(|b| !(0x20..=0x7e).contains(&b)) {
            return Err("rule must be nonempty printable ASCII".into());
        }
        let chars = source.as_bytes();
        let mut cursor = 0;
        let mut actions = Vec::new();
        while cursor < chars.len() {
            if actions.len() >= MAX_RULE_INSTRUCTIONS {
                return Err("rule too complex".into());
            }
            let op = chars[cursor];
            cursor += 1;
            let mut arg = || {
                let byte = *chars.get(cursor).ok_or("missing rule argument")?;
                cursor += 1;
                Ok::<u8, String>(byte)
            };
            let action = match op {
                b':' => RuleAction::Identity,
                b'l' => RuleAction::Lower,
                b'u' => RuleAction::Upper,
                b'c' => RuleAction::Capitalize,
                b'r' => RuleAction::Reverse,
                b'd' => RuleAction::Duplicate,
                b'$' => RuleAction::Append(arg()?),
                b'^' => RuleAction::Prepend(arg()?),
                b'T' => {
                    let digit = arg()?;
                    let n = match digit {
                        b'0'..=b'9' => usize::from(digit - b'0'),
                        b'A'..=b'Z' => usize::from(digit - b'A' + 10),
                        _ => return Err("toggle position must be 0-9 or A-Z".into()),
                    };
                    RuleAction::Toggle(n)
                }
                b's' => RuleAction::Substitute(arg()?, arg()?),
                b'[' => RuleAction::DeleteFirst,
                b']' => RuleAction::DeleteLast,
                _ => return Err(format!("unsupported rule opcode {}", op as char)),
            };
            actions.push(action);
        }
        Ok(Self { actions })
    }
    pub fn apply(&self, candidate: &[u8]) -> Result<Vec<u8>, String> {
        if candidate.len() > MAX_CANDIDATE_BYTES {
            return Err("candidate too long".into());
        }
        let mut bytes = candidate.to_vec();
        for action in &self.actions {
            match *action {
                RuleAction::Identity => {}
                RuleAction::Lower => bytes.make_ascii_lowercase(),
                RuleAction::Upper => bytes.make_ascii_uppercase(),
                RuleAction::Capitalize => {
                    bytes.make_ascii_lowercase();
                    if let Some(first) = bytes.first_mut() {
                        first.make_ascii_uppercase();
                    }
                }
                RuleAction::Reverse => bytes.reverse(),
                RuleAction::Duplicate => {
                    if bytes.len().saturating_mul(2) > MAX_CANDIDATE_BYTES {
                        return Err("rule expansion exceeds byte cap".into());
                    }
                    let cloned = bytes.clone();
                    bytes.extend_from_slice(&cloned);
                }
                RuleAction::Append(v) => {
                    if bytes.len() >= MAX_CANDIDATE_BYTES {
                        return Err("rule expansion exceeds byte cap".into());
                    }
                    bytes.push(v);
                }
                RuleAction::Prepend(v) => {
                    if bytes.len() >= MAX_CANDIDATE_BYTES {
                        return Err("rule expansion exceeds byte cap".into());
                    }
                    bytes.insert(0, v);
                }
                RuleAction::Toggle(n) => {
                    if let Some(byte) = bytes.get_mut(n) {
                        if byte.is_ascii_lowercase() {
                            byte.make_ascii_uppercase();
                        } else if byte.is_ascii_uppercase() {
                            byte.make_ascii_lowercase();
                        }
                    }
                }
                RuleAction::Substitute(from, to) => {
                    for byte in &mut bytes {
                        if *byte == from {
                            *byte = to;
                        }
                    }
                }
                RuleAction::DeleteFirst => {
                    if !bytes.is_empty() {
                        bytes.remove(0);
                    }
                }
                RuleAction::DeleteLast => {
                    bytes.pop();
                }
            }
        }
        Ok(bytes)
    }
}

/// Parses bounded newline-delimited CyberDeck rules from a local file.
/// Empty lines and full-line comments starting with '#' are ignored.
pub fn parse_rule_lines<R: std::io::BufRead>(reader: R) -> Result<Vec<CompiledRule>, String> {
    let mut rules = Vec::new();
    for (index, line) in crate::candidates::WordlistCandidates::new(reader).enumerate() {
        let line = line.map_err(|e| format!("rule line {}: {e}", index + 1))?;
        if line.is_empty() || line.first() == Some(&b'#') {
            continue;
        }
        if rules.len() == MAX_RULES_PER_STREAM {
            return Err("rule file exceeds maximum rules".into());
        }
        let script = std::str::from_utf8(&line)
            .map_err(|_| format!("rule line {} is not ASCII/UTF-8", index + 1))?;
        rules.push(
            CompiledRule::parse(script).map_err(|e| format!("rule line {}: {e}", index + 1))?,
        );
    }
    if rules.is_empty() {
        return Err("no valid rules in file".into());
    }
    Ok(rules)
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
