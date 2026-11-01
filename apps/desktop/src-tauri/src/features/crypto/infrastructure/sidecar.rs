//! Pure host-process adapters for optional Hashcat and John executables.
//! This module owns process arguments, captured output, scratch files and parsing.
//! Desktop dialogs, IPC and evidence persistence remain in the root controller.
use std::path::Path;
use std::process::{Command, ExitStatus};
use std::time::Duration;

use crate::features::crypto::ipc::attack::AttackMatch;
use super::engine_formats::{parse_hashcat_outfile, parse_john_show};
use super::process::run_with_timeout;
use super::scratch::ScratchDir;

const PROCESS_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_REPORTED_MATCHES: usize = 100;

pub struct EngineRun {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub matches: Vec<AttackMatch>,
}

pub fn hashcat(
    binary: &Path,
    hash_mode: u32,
    target: &str,
    mode: &str,
    mask: Option<&str>,
    wordlist: Option<&Path>,
    scratch: &ScratchDir,
) -> Result<EngineRun, String> {
    let hash_file = scratch.write_hash_file(target)?;
    let outfile = scratch.join("hashcat.out");
    let mut command = Command::new(binary);
    command
        .arg("-m")
        .arg(hash_mode.to_string())
        .arg("--potfile-disable")
        .arg("-o")
        .arg(&outfile);
    match mode {
        "mask" => {
            let mask = mask.filter(|value| !value.is_empty())
                .ok_or("mask attack needs a mask pattern")?;
            command.arg("-a").arg("3").arg(&hash_file).arg(mask);
        }
        "wordlist" => {
            let path = wordlist.ok_or("wordlist mode requires a selected file")?;
            command.arg("-a").arg("0").arg(&hash_file).arg(path);
        }
        _ => return Err("unsupported engine mode".into()),
    }
    let (status, stdout, stderr) = run_with_timeout(command, PROCESS_TIMEOUT)?;
    // The outfile contains recovered passwords. Bound its size before parsing.
    let output_text = match std::fs::metadata(&outfile) {
        Ok(meta) if meta.len() > 4 * 1024 * 1024 => {
            return Err("hashcat output exceeds the 4 MiB safety limit".into());
        }
        Ok(_) => std::fs::read_to_string(&outfile)
            .map_err(|e| format!("cannot read hashcat output: {e}"))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(format!("cannot inspect hashcat output: {error}")),
    };
    let mut matches = parse_hashcat_outfile(&output_text);
    matches.truncate(MAX_REPORTED_MATCHES);
    Ok(EngineRun { status, stdout, stderr, matches })
}

pub fn john(
    binary: &Path,
    format: &str,
    target: &str,
    wordlist: &Path,
    scratch: &ScratchDir,
) -> Result<EngineRun, String> {
    let hash_file = scratch.write_hash_file(target)?;
    let potfile = scratch.join("john.pot");
    let session = scratch.join("john-session");
    let mut command = Command::new(binary);
    command
        .arg(format!("--pot={}", potfile.display()))
        .arg(format!("--session={}", session.display()))
        .arg(format!("--format={format}"))
        .arg(format!("--wordlist={}", wordlist.display()))
        .arg(&hash_file);
    let (status, stdout, stderr) = run_with_timeout(command, PROCESS_TIMEOUT)?;

    // Read the isolated pot rather than exposing or modifying the user's
    // existing John password history.
    let mut show = Command::new(binary);
    show.arg("--show")
        .arg(format!("--pot={}", potfile.display()))
        .arg(format!("--format={format}"))
        .arg(&hash_file);
    let (show_status, show_out, _) = run_with_timeout(show, Duration::from_secs(30))?;
    if !show_status.success() {
        return Err("john could not read the isolated result pot".into());
    }
    let mut matches = parse_john_show(&String::from_utf8_lossy(&show_out));
    matches.truncate(MAX_REPORTED_MATCHES);
    Ok(EngineRun { status, stdout, stderr, matches })
}

pub fn capture_tail(stdout: &[u8], stderr: &[u8], max_bytes: usize) -> String {
    let mut output = format!(
        "{}{}",
        String::from_utf8_lossy(stdout),
        String::from_utf8_lossy(stderr)
    );
    if output.len() > max_bytes {
        let mut end = max_bytes;
        while !output.is_char_boundary(end) {
            end -= 1;
        }
        output.truncate(end);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdout_log_truncation_never_splits_utf8() {
        let output = capture_tail("é".repeat(20).as_bytes(), b"", 7);
        assert_eq!(output, "ééé");
    }
}
