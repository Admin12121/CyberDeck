//! Bounded, deadlock-resistant external engine process execution.
//! Child stdout and stderr are drained concurrently before exit/timeout.
use std::io::Read;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_CAPTURE_BYTES: usize = 1024 * 1024;

fn collect_bounded<R: Read + Send + 'static>(mut reader: R) -> thread::JoinHandle<Vec<u8>> {
    thread::spawn(move || {
        let mut result = Vec::new();
        let mut buffer = [0u8; 8192];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    let remaining = MAX_CAPTURE_BYTES.saturating_sub(result.len());
                    result.extend_from_slice(&buffer[..read.min(remaining)]);
                    // Keep draining to prevent child pipe backpressure, but
                    // discard bytes beyond the bounded diagnostic capture.
                }
            }
        }
        result
    })
}

pub fn run_with_timeout(
    mut command: Command,
    timeout: Duration,
) -> Result<(ExitStatus, Vec<u8>, Vec<u8>), String> {
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|e| format!("cannot start process: {e}"))?;
    let stdout = child.stdout.take().map(collect_bounded);
    let stderr = child.stderr.take().map(collect_bounded);
    let started = Instant::now();
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() >= timeout => {
                timed_out = true;
                let _ = child.kill();
                break child.wait().map_err(|e| e.to_string())?;
            }
            Ok(None) => thread::sleep(Duration::from_millis(25)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("cannot await external engine: {e}"));
            }
        }
    };
    let out = match stdout {
        Some(handle) => handle.join().map_err(|_| "stdout drain worker panicked")?,
        None => Vec::new(),
    };
    let err = match stderr {
        Some(handle) => handle.join().map_err(|_| "stderr drain worker panicked")?,
        None => Vec::new(),
    };
    if timed_out {
        return Err(format!(
            "engine exceeded the {}s timeout; output discarded",
            timeout.as_secs()
        ));
    }
    Ok((status, out, err))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn verbose_child_cannot_block_on_a_full_stdout_pipe() {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("head -c 131072 /dev/zero");
        let (status, output, _) = run_with_timeout(cmd, Duration::from_secs(5)).unwrap();
        assert!(status.success());
        assert_eq!(output.len(), 131072);
    }

    #[cfg(unix)]
    #[test]
    fn stdout_capture_is_bounded() {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("head -c 1200000 /dev/zero");
        let (status, output, _) = run_with_timeout(cmd, Duration::from_secs(5)).unwrap();
        assert!(status.success());
        assert_eq!(output.len(), MAX_CAPTURE_BYTES);
    }
}
