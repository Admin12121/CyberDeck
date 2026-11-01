//! Optional external tool adapters, not replacements for the native Web engine.
use super::scan_domain::require_authorization;
use super::{EngineScanResult, WebEngineStatus};
use crate::features::crypto::ipc::engines::which_exists;
use std::time::{Duration, Instant};

pub(super) async fn detect_engines() -> Vec<WebEngineStatus> {
    let mut out = vec![WebEngineStatus {
        id: "cyberdeck-native".to_string(),
        label: "CyberDeck Native Web Scanner".to_string(),
        license: "MIT".to_string(),
        available: true,
        version: "0.1".to_string(),
    }];
    for (id, label, license, version_args) in [
        ("nikto", "Nikto", "GPL-2.0-only", vec!["-Version"]),
        ("sqlmap", "sqlmap", "GPL-2.0-only", vec!["--version"]),
        ("xsstrike", "XSStrike", "GPL-3.0-only", vec!["--help"]),
    ] {
        let available = which_exists(id);
        let mut version = String::new();
        if available {
            let mut probe = tokio::process::Command::new(id);
            probe.args(&version_args);
            if let Ok((stdout, _stderr)) =
                run_tool_bounded(&mut probe, 1024, Duration::from_secs(4)).await
            {
                version = String::from_utf8_lossy(&stdout)
                    .lines()
                    .find(|l| !l.trim().is_empty())
                    .unwrap_or("")
                    .chars()
                    .take(60)
                    .collect();
            }
        }
        out.push(WebEngineStatus {
            id: id.to_string(),
            label: label.to_string(),
            license: license.to_string(),
            available,
            version,
        });
    }
    out
}

/// Run an approved external web engine against the target when it is on PATH.
pub(super) async fn run_engine(
    tool: String,
    target: String,
    authorized: bool,
) -> Result<EngineScanResult, String> {
    require_authorization(authorized)?;
    let target = target.trim().to_string();
    let started = Instant::now();
    if tool == "cyberdeck-native" {
        let findings = super::scan_application::run_scan(
            &super::client_infrastructure::http_client(),
            target,
            true,
        )
        .await?;
        return Ok(EngineScanResult {
            tool,
            raw: serde_json::to_string_pretty(&findings)
                .map_err(|e| format!("cannot encode scanner result: {e}"))?,
            duration_ms: started.elapsed().as_millis() as u64,
        });
    }
    let checked =
        reqwest::Url::parse(&target).map_err(|e| format!("invalid scan target URL: {e}"))?;
    if !matches!(checked.scheme(), "http" | "https")
        || checked.host_str().is_none()
        || !checked.username().is_empty()
        || checked.password().is_some()
    {
        return Err("target must be HTTP(S) without URL credentials".to_string());
    }
    let mut command = tokio::process::Command::new(&tool);
    command.kill_on_drop(true);
    match tool.as_str() {
        "nikto" => {
            command.args(["-h", &target, "-Format", "txt"]);
        }
        "sqlmap" => {
            command.args(["-u", &target, "--batch", "--forms"]);
        }
        "xsstrike" => {
            command.args(["-u", &target, "--crawl"]);
        }
        other => return Err(format!("unknown engine: {other}")),
    }
    let (out, err) = run_tool_bounded(&mut command, 20_000, Duration::from_secs(90))
        .await
        .map_err(|err| format!("{tool} execution failed: {err}"))?;
    let mut raw = format!(
        "{}{}",
        String::from_utf8_lossy(&out),
        String::from_utf8_lossy(&err)
    );
    if raw.len() > 20_000 {
        let mut end = 20_000;
        while !raw.is_char_boundary(end) {
            end -= 1;
        }
        raw.truncate(end);
    }
    Ok(EngineScanResult {
        tool,
        raw,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}

/// Bound both memory and elapsed time while draining each pipe, so even a
/// verbose tool cannot block the process on full stdout/stderr buffers.
async fn run_tool_bounded(
    command: &mut tokio::process::Command,
    capture_limit: usize,
    duration: Duration,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    command
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    let mut stdout = child.stdout.take().ok_or("stdout unavailable")?;
    let mut stderr = child.stderr.take().ok_or("stderr unavailable")?;
    let (out, err, _status) = tokio::time::timeout(duration, async {
        tokio::try_join!(
            read_bounded(&mut stdout, capture_limit),
            read_bounded(&mut stderr, capture_limit),
            child.wait(),
        )
    })
    .await
    .map_err(|_| "process exceeded time limit".to_string())?
    .map_err(|e| e.to_string())?;
    Ok((out, err))
}

async fn read_bounded<R: tokio::io::AsyncRead + Unpin>(
    stream: &mut R,
    max_capture: usize,
) -> std::io::Result<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let mut capture = Vec::with_capacity(max_capture.min(4096));
    let mut buf = [0_u8; 8192];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        let kept = n.min(max_capture.saturating_sub(capture.len()));
        capture.extend_from_slice(&buf[..kept]);
    }
    Ok(capture)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn verbose_sidecar_output_is_drained_but_bounded() {
        let (mut writer, mut reader) = tokio::io::duplex(4096);
        let send = tokio::spawn(async move {
            writer.write_all(&vec![0xfe; 128 * 1024]).await.unwrap();
        });
        let captured =
            tokio::time::timeout(Duration::from_secs(5), read_bounded(&mut reader, 2048))
                .await
                .unwrap()
                .unwrap();
        send.await.unwrap();
        assert_eq!(captured.len(), 2048);
        assert!(captured.iter().all(|byte| *byte == 0xfe));
    }
}
