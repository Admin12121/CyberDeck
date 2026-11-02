//! Bounded, case-private wordlist transformations for the embedded Hashcat
//! wordlist attack. These are explicitly NOT upstream Hashcat rule scripts;
//! Hashcat still performs native digest recovery on the generated candidates.
//! The generated list is held only in the supervisor's ephemeral TempDir.
use serde::Deserialize;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

const MAX_CANDIDATE_BYTES: usize = 4096;
const MAX_DERIVED_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CANDIDATES: u64 = 1_000_000;

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
pub(super) fn read_line_bounded<R: BufRead>(reader: &mut R, line: &mut Vec<u8>) -> Result<bool, String> {
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
    if budget == 0 || budget > MAX_CANDIDATES {
        return Err("invalid candidate budget".into());
    }
    if preset == WordlistPreset::Plain {
        return Ok(None);
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_transforms_generate_exact_expected_candidates() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("operator.words");
        std::fs::write(&source, b"admin\r\nPassword\ncyberDeck\n").unwrap();
        assert_eq!(
            generate(&source, &dir.path().join("noop"), 2, WordlistPreset::Plain, || false),
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
            WordlistPreset::Uppercase, || false
        )
        .is_err());
        assert!(generate(
            &source,
            &dir.path().join("budget.words"),
            1_000_001,
            WordlistPreset::Uppercase, || false
        )
        .is_err());
        std::fs::write(&source, vec![b'a'; MAX_CANDIDATE_BYTES]).unwrap();
        assert!(generate(
            &source,
            &dir.path().join("overflow.words"),
            1,
            WordlistPreset::AppendOne, || false
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
}
