//! Bounded, case-private wordlist transformations for the embedded Hashcat
//! wordlist attack. These are explicitly NOT upstream Hashcat rule scripts;
//! Hashcat still performs native digest recovery on the generated candidates.
//! The generated list is held only in the supervisor's ephemeral TempDir.
use cyberdeck_crypto::recovery::{CompiledRule, MAX_FAST_CANDIDATES, MAX_RULES_PER_STREAM};
use serde::Deserialize;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

const MAX_CANDIDATE_BYTES: usize = 4096;
const MAX_DERIVED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CANDIDATES: u64 = 1_000_000;
/// Rules expansions substitute for a whole wordlist, so their private file
/// cap matches the wordlist import policy (256 MiB) rather than the smaller
/// generated-preset cap; the chunked GPU executor splits the file into
/// 1M-candidate sessions afterwards.
pub const MAX_EXPANSION_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WordlistPreset {
    #[default]
    Plain,
    Uppercase,
    AppendOne,
}

/// Reads at most a single 4KiB candidate, even when an untrusted input
/// contains an unterminated multi-gigabyte line.
pub(super) fn read_line_bounded<R: BufRead>(
    reader: &mut R,
    line: &mut Vec<u8>,
) -> Result<bool, String> {
    line.fill(0);
    line.clear();
    loop {
        let (take, newline) = {
            let block = reader.fill_buf().map_err(|_| "could not read wordlist")?;
            if block.is_empty() {
                return Ok(!line.is_empty());
            }
            let n = block
                .iter()
                .position(|b| *b == b'\n')
                .map_or(block.len(), |at| at + 1);
            if line
                .len()
                .checked_add(n)
                .is_none_or(|len| len > MAX_CANDIDATE_BYTES + 2)
            {
                return Err("wordlist candidate exceeds the 4096-byte limit".into());
            }
            line.extend_from_slice(&block[..n]);
            (n, block[n - 1] == b'\n')
        };
        reader.consume(take);
        if newline {
            return Ok(true);
        }
    }
}

/// Return None for the unchanged operator-owned list, or the exact number of
/// generated candidates for the temporary list.
pub fn generate(
    source: &Path,
    destination: &Path,
    budget: u64,
    preset: WordlistPreset,
    mut cancelled: impl FnMut() -> bool,
) -> Result<Option<u64>, String> {
    // Plain passes the operator list through untransformed; its size is
    // bounded by the chunked sessions in execute_path, not by the transform
    // budget, so check the budget only for generating presets.
    if preset == WordlistPreset::Plain {
        return Ok(None);
    }
    if budget == 0 || budget > MAX_CANDIDATES {
        return Err("invalid candidate budget".into());
    }
    let input = File::open(source).map_err(|_| "wordlist became unavailable")?;
    // Never overwrite an existing evidence file, even inside private scratch.
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|_| "private generated wordlist unavailable")?;
    let mut reader = BufReader::new(input);
    let mut writer = BufWriter::new(output);
    let mut line = Vec::new();
    let mut count = 0u64;
    let mut written = 0u64;
    while count < budget {
        if cancelled() {
            return Err("recovery cancelled".into());
        }
        if !read_line_bounded(&mut reader, &mut line)? {
            break;
        }
        let data = line.strip_suffix(b"\n").unwrap_or(&line);
        let data = data.strip_suffix(b"\r").unwrap_or(data);
        if data.len() > MAX_CANDIDATE_BYTES {
            return Err("wordlist candidate exceeds the 4096-byte limit".into());
        }
        let mut transformed: Vec<u8> = match preset {
            WordlistPreset::Plain => unreachable!(),
            WordlistPreset::Uppercase => data.iter().map(u8::to_ascii_uppercase).collect(),
            WordlistPreset::AppendOne => {
                if data.len() == MAX_CANDIDATE_BYTES {
                    return Err("append-one candidate exceeds the 4096-byte limit".into());
                }
                let mut candidate = Vec::with_capacity(data.len() + 1);
                candidate.extend_from_slice(data);
                candidate.push(b'1');
                candidate
            }
        };
        let size = (transformed.len() as u64) + 1;
        written = written
            .checked_add(size)
            .ok_or("generated wordlist size overflow")?;
        if written > MAX_DERIVED_BYTES {
            return Err("generated wordlist exceeds the 64MiB limit".into());
        }
        writer
            .write_all(&transformed)
            .and_then(|_| writer.write_all(b"\n"))
            .map_err(|_| "could not write private generated wordlist")?;
        transformed.fill(0);
        count += 1;
    }
    line.fill(0);
    writer
        .flush()
        .map_err(|_| "cannot flush private generated wordlist")?;
    Ok(Some(count))
}

/// Stream a wordlist through compiled rules into a private candidates file,
/// word-major then rule-major — the exact expansion order of the native CPU
/// rules engine. Never materializes the expanded set: one source word and
/// one candidate are resident at a time, and cancellation is checked per
/// word. Stops at the operator budget exactly like the CPU engine; errors
/// when the bytes would exceed MAX_EXPANSION_BYTES (or a rule rejects the
/// candidate bounds) so the caller can fall back to the streaming CPU rules
/// engine instead of silently shrinking coverage. Returns the candidate count.
pub fn expand_rules(
    source: &Path,
    destination: &Path,
    rules: &[CompiledRule],
    budget: u64,
    cancelled: impl FnMut() -> bool,
) -> Result<u64, String> {
    expand_rules_with_cap(
        source,
        destination,
        rules,
        budget,
        MAX_EXPANSION_BYTES,
        cancelled,
    )
}

fn expand_rules_with_cap(
    source: &Path,
    destination: &Path,
    rules: &[CompiledRule],
    budget: u64,
    cap_bytes: u64,
    mut cancelled: impl FnMut() -> bool,
) -> Result<u64, String> {
    if rules.is_empty()
        || rules.len() > MAX_RULES_PER_STREAM
        || budget == 0
        || budget > MAX_FAST_CANDIDATES
    {
        return Err("invalid rules expansion bounds".into());
    }
    let input = File::open(source).map_err(|_| "wordlist became unavailable")?;
    // Never overwrite an existing evidence file, even inside private scratch.
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|_| "private expanded wordlist unavailable")?;
    let mut reader = BufReader::new(input);
    let mut writer = BufWriter::new(output);
    let mut line = Vec::new();
    let mut count = 0u64;
    let mut written = 0u64;
    while count < budget {
        if cancelled() {
            return Err("recovery cancelled".into());
        }
        if !read_line_bounded(&mut reader, &mut line)? {
            break;
        }
        let data = line.strip_suffix(b"\n").unwrap_or(&line);
        let data = data.strip_suffix(b"\r").unwrap_or(data);
        if data.len() > MAX_CANDIDATE_BYTES {
            return Err("wordlist candidate exceeds the 4096-byte limit".into());
        }
        for rule in rules {
            let Some(mut variant) = rule.apply(data)? else {
                continue; // rejection opcodes emit no variant for this word
            };
            let size = (variant.len() as u64) + 1;
            written = written
                .checked_add(size)
                .ok_or("expanded wordlist size overflow")?;
            if written > cap_bytes {
                return Err("expanded candidates exceed the private file cap".into());
            }
            writer
                .write_all(&variant)
                .and_then(|_| writer.write_all(b"\n"))
                .map_err(|_| "could not write private expanded wordlist")?;
            variant.fill(0);
            count += 1;
            if count >= budget {
                break;
            }
        }
    }
    line.fill(0);
    writer
        .flush()
        .map_err(|_| "cannot flush private expanded wordlist")?;
    Ok(count)
}

/// Copy a wordlist after skipping the first `skip` candidate lines into a
/// private tail file, so a re-issued chunked GPU run resumes at the next
/// 1M-session boundary instead of replaying finished sessions. Writes at
/// most `budget` candidates (the re-issued run's remaining budget). Streaming
/// and cancellation-aware like every other private transform here; returns
/// the exact candidate count (zero when nothing is left).
pub fn write_skip_tail(
    source: &Path,
    destination: &Path,
    skip: u64,
    budget: u64,
    mut cancelled: impl FnMut() -> bool,
) -> Result<u64, String> {
    if budget == 0 || budget > MAX_FAST_CANDIDATES {
        return Err("invalid resume tail bounds".into());
    }
    let input = File::open(source).map_err(|_| "wordlist became unavailable")?;
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|_| "private resume tail unavailable")?;
    let mut reader = BufReader::new(input);
    let mut writer = BufWriter::new(output);
    let mut line = Vec::new();
    let mut skipped = 0u64;
    let mut written = 0u64;
    while skipped < skip {
        if cancelled() {
            return Err("recovery cancelled".into());
        }
        if !read_line_bounded(&mut reader, &mut line)? {
            break; // the file shrank below the remembered boundary
        }
        skipped += 1;
    }
    while written < budget {
        if cancelled() {
            return Err("recovery cancelled".into());
        }
        if !read_line_bounded(&mut reader, &mut line)? {
            break;
        }
        let data = line.strip_suffix(b"\n").unwrap_or(&line);
        let data = data.strip_suffix(b"\r").unwrap_or(data);
        if data.len() > MAX_CANDIDATE_BYTES {
            return Err("wordlist candidate exceeds the 4096-byte limit".into());
        }
        writer
            .write_all(data)
            .and_then(|_| writer.write_all(b"\n"))
            .map_err(|_| "could not write private resume tail")?;
        written += 1;
    }
    line.fill(0);
    writer
        .flush()
        .map_err(|_| "cannot flush private resume tail")?;
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_transforms_generate_exact_expected_candidates() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("operator.words");
        std::fs::write(&source, b"admin\r\nPassword\ncyberDeck\n").unwrap();
        assert_eq!(
            generate(
                &source,
                &dir.path().join("noop"),
                2,
                WordlistPreset::Plain,
                || false
            ),
            Ok(None)
        );
        let upper = dir.path().join("upper.words");
        assert_eq!(
            generate(&source, &upper, 2, WordlistPreset::Uppercase, || false),
            Ok(Some(2))
        );
        assert_eq!(std::fs::read(&upper).unwrap(), b"ADMIN\nPASSWORD\n");
        let appended = dir.path().join("append.words");
        assert_eq!(
            generate(&source, &appended, 3, WordlistPreset::AppendOne, || false),
            Ok(Some(3))
        );
        assert_eq!(
            std::fs::read(&appended).unwrap(),
            b"admin1\nPassword1\ncyberDeck1\n"
        );
        assert!(generate(&source, &upper, 2, WordlistPreset::Uppercase, || false).is_err());
    }
    #[test]
    fn rejects_unbounded_lines_and_cannot_overwrite_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("operator.words");
        std::fs::write(&source, vec![b'a'; 100_000]).unwrap();
        assert!(generate(
            &source,
            &dir.path().join("long.words"),
            10,
            WordlistPreset::Uppercase,
            || false
        )
        .is_err());
        assert!(generate(
            &source,
            &dir.path().join("budget.words"),
            1_000_001,
            WordlistPreset::Uppercase,
            || false
        )
        .is_err());
        std::fs::write(&source, vec![b'a'; MAX_CANDIDATE_BYTES]).unwrap();
        assert!(generate(
            &source,
            &dir.path().join("overflow.words"),
            1,
            WordlistPreset::AppendOne,
            || false
        )
        .is_err());
    }
    #[test]
    fn cancellation_aborts_before_any_scratch_publication() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("input.words");
        std::fs::write(&source, b"admin\npassword\n").unwrap();
        let dest = dir.path().join("cancelled.words");
        assert_eq!(
            generate(&source, &dest, 100, WordlistPreset::Uppercase, || true),
            Err("recovery cancelled".into())
        );
        assert_eq!(std::fs::read(&dest).unwrap(), b"");
    }

    #[test]
    fn stops_at_budget_before_excess_input_and_preserves_original() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("words");
        std::fs::write(&source, b"one\ntwo\nTHREE\n").unwrap();
        let original = std::fs::read(&source).unwrap();
        let dest = dir.path().join("generated");
        assert_eq!(
            generate(&source, &dest, 2, WordlistPreset::AppendOne, || false),
            Ok(Some(2))
        );
        assert_eq!(std::fs::read(&dest).unwrap(), b"one1\ntwo1\n");
        assert_eq!(std::fs::read(&source).unwrap(), original);
    }

    fn parsed_rules(text: &[u8]) -> Vec<CompiledRule> {
        cyberdeck_crypto::recovery::parse_rule_lines(std::io::Cursor::new(text)).unwrap()
    }

    #[test]
    fn rules_expansion_matches_cpu_word_then_rule_order_and_rejections() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("words");
        std::fs::write(&source, b"one\ntwo\n").unwrap();
        // ":" identity, "$1" append, and "o0X" overwrite; word-major order.
        let rules = parsed_rules(b":\n$1\no0X\n");
        let dest = dir.path().join("expanded.words");
        assert_eq!(
            expand_rules(&source, &dest, &rules, 100, || false),
            Ok(6)
        );
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"one\none1\nXne\ntwo\ntwo1\nXwo\n"
        );
        // Budget truncation mirrors the CPU engine's word-major cap.
        let capped = dir.path().join("capped.words");
        assert_eq!(
            expand_rules(&source, &capped, &rules, 4, || false),
            Ok(4)
        );
        assert_eq!(std::fs::read(&capped).unwrap(), b"one\none1\nXne\ntwo\n");
    }

    #[test]
    fn rules_expansion_rejects_oversized_output_and_bad_bounds() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("words");
        std::fs::write(&source, format!("{}\n{}\n", "w".repeat(4000), "v".repeat(4000)).as_bytes())
            .unwrap();
        // Each appended candidate is 4001 bytes; a 5 KiB cap trips mid-stream
        // exactly like the real 256 MiB cap would for a giant expansion.
        let rules = parsed_rules(b"$x\n");
        assert_eq!(
            expand_rules_with_cap(&source, &dir.path().join("out"), &rules, 10, 5 * 1024, || false),
            Err("expanded candidates exceed the private file cap".into())
        );
        assert!(expand_rules(&source, &dir.path().join("out"), &rules, 0, || false).is_err());
        assert!(expand_rules(&source, &dir.path().join("out"), &rules, 10_000_001, || false)
            .is_err());
        assert!(expand_rules(&source, &dir.path().join("out"), &[], 10, || false).is_err());
        // Cancellation aborts before completion.
        let cancelled = dir.path().join("cancelled.words");
        assert_eq!(
            expand_rules(&source, &cancelled, &rules, 10, || true),
            Err("recovery cancelled".into())
        );
        assert_eq!(std::fs::read(&cancelled).unwrap(), b"");
    }

    #[test]
    fn resume_tail_skips_exact_boundaries_and_caps_budget() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("words");
        std::fs::write(&source, b"a\nb\nc\nd\ne\n").unwrap();
        let tail = dir.path().join("tail.words");
        assert_eq!(write_skip_tail(&source, &tail, 2, 2, || false), Ok(2));
        assert_eq!(std::fs::read(&tail).unwrap(), b"c\nd\n");
        // Skipping past the end yields an empty tail: nothing left to run.
        let exhausted = dir.path().join("exhausted.words");
        assert_eq!(write_skip_tail(&source, &exhausted, 10, 2, || false), Ok(0));
        assert_eq!(std::fs::read(&exhausted).unwrap(), b"");
        let rest = dir.path().join("rest.words");
        assert_eq!(write_skip_tail(&source, &rest, 3, 100, || false), Ok(2));
        assert_eq!(std::fs::read(&rest).unwrap(), b"d\ne\n");
        assert_eq!(
            write_skip_tail(&source, &dir.path().join("bad"), 0, 0, || false),
            Err("invalid resume tail bounds".into())
        );
        assert_eq!(
            write_skip_tail(&source, &dir.path().join("bad"), 0, 2, || true),
            Err("recovery cancelled".into())
        );
    }
}
