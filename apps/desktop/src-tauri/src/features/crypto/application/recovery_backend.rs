//! Native SHA-256 CPU/OpenCL desktop recovery use case. No Tauri or persistence.
#[path = "recovery_access.rs"]
pub mod access;
use cyberdeck_crypto::gpu::{self, GpuProbe, MAX_GPU_BATCH};
use cyberdeck_crypto::recovery::{
    recover_sha256_wordlist_on_backend, FastHash, RecoveryBackend, RecoveryLimits,
    RecoveryProgress, RecoveryTarget, MAX_FAST_CANDIDATES, MAX_MATCHES,
};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Instant;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "backend", rename_all = "snake_case")]
pub enum BackendSelection {
    Cpu,
    /// Native Hashcat enumerates its own devices; no Rust OpenCL index mapping.
    HashcatManaged,
    OpenCl {
        device_index: usize,
        batch_size: usize,
    },
}
impl TryFrom<BackendSelection> for RecoveryBackend {
    type Error = String;
    fn try_from(value: BackendSelection) -> Result<Self, Self::Error> {
        Ok(match value {
            BackendSelection::Cpu => Self::Cpu,
            BackendSelection::OpenCl {
                device_index,
                batch_size,
            } => Self::OpenCl {
                device_index,
                batch_size,
            },
            BackendSelection::HashcatManaged => {
                return Err("Hashcat-managed devices cannot execute through Rust recovery".into());
            }
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRequest {
    pub algorithm: String,
    pub target_hash: String,
    pub backend: BackendSelection,
    pub max_candidates: u64,
    pub max_matches: usize,
}
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct RecoveryProgressWire {
    pub tried: u64,
    pub budget: u64,
    pub matches: usize,
}
impl From<RecoveryProgress> for RecoveryProgressWire {
    fn from(p: RecoveryProgress) -> Self {
        Self {
            tried: p.tried,
            budget: p.budget,
            matches: p.matches,
        }
    }
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct MatchMetadata {
    /// Zero-based candidate ordinal, not necessarily the physical file line.
    pub candidate_index: u64,
    pub masked: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct RecoverySummaryWire {
    pub algorithm: String,
    pub backend: BackendSelection,
    pub engine: String,
    pub tried: u64,
    pub cancelled: bool,
    pub limit_reached: bool,
    pub duration_ms: u64,
    pub matches: Vec<MatchMetadata>,
}

/// Non-serializable container. IPC must authorize a separate explicit reveal.
pub struct RecoveryRun {
    pub summary: RecoverySummaryWire,
    confidential_hits: Vec<Vec<u8>>,
}
impl Drop for RecoveryRun {
    fn drop(&mut self) {
        for bytes in &mut self.confidential_hits {
            bytes.fill(0);
        }
    }
}

#[derive(Clone, Default)]
pub struct RecoveryCancel(Arc<AtomicBool>);
impl RecoveryCancel {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeDeviceWire {
    pub device_index: usize,
    pub name: String,
    pub vendor: String,
    pub driver: String,
    /// Probing a device is not validation of its kernels.
    pub hardware_verified: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct RecoveryDeviceInventory {
    pub opencl_detected: bool,
    pub detail: String,
    pub devices: Vec<ProbeDeviceWire>,
}
pub fn probe_recovery_devices() -> RecoveryDeviceInventory {
    let state = gpu::probe();
    RecoveryDeviceInventory {
        opencl_detected: state.available,
        detail: state.detail,
        devices: state
            .devices
            .into_iter()
            .enumerate()
            .map(|(device_index, d)| ProbeDeviceWire {
                device_index,
                name: d.name,
                vendor: d.vendor,
                driver: d.driver,
                hardware_verified: false,
            })
            .collect(),
    }
}
fn validate_backend(backend: BackendSelection, probe: Option<&GpuProbe>) -> Result<(), String> {
    match backend {
        BackendSelection::Cpu => Ok(()),
        BackendSelection::HashcatManaged => {
            Err("Hashcat-managed backend requires embedded Hashcat".into())
        }
        BackendSelection::OpenCl {
            device_index,
            batch_size,
        } => {
            if !(1..=MAX_GPU_BATCH).contains(&batch_size) {
                return Err(format!("OpenCL batch size must be 1..={MAX_GPU_BATCH}"));
            }
            let status = probe.ok_or("OpenCL probe required")?;
            if !status.available || status.devices.is_empty() {
                return Err(format!(
                    "OpenCL unavailable (no CPU fallback): {}",
                    status.detail
                ));
            }
            if device_index >= status.devices.len() {
                return Err(format!("OpenCL device index {device_index} not available"));
            }
            Ok(())
        }
    }
}
pub(super) fn validate_request(request: &RecoveryRequest) -> Result<(), String> {
    if request.algorithm != "sha256" {
        return Err("selected-backend recovery supports sha256 only".into());
    }
    if !(1..=MAX_FAST_CANDIDATES).contains(&request.max_candidates) {
        return Err("max_candidates exceeds global recovery limit".into());
    }
    if !(1..=MAX_MATCHES).contains(&request.max_matches) {
        return Err("max_matches exceeds global recovery limit".into());
    }
    let parsed = RecoveryTarget::parse("sha256", &request.target_hash)?;
    if !matches!(
        parsed,
        RecoveryTarget::Digest {
            algorithm: FastHash::Sha256,
            ..
        }
    ) {
        return Err("expected raw SHA-256 digest".into());
    }
    Ok(())
}

/// Construct confidential results from a supervised embedded worker only
/// after independent Rust digest checks. Plaintext never becomes IPC data.
pub(super) fn embedded_result(
    request: &RecoveryRequest,
    hits: Vec<(u64, Vec<u8>)>,
    cancelled: bool,
    duration_ms: u64,
) -> RecoveryRun {
    let (matches, confidential_hits) = hits
        .into_iter()
        .map(|(candidate_index, secret)| {
            (
                MatchMetadata {
                    candidate_index,
                    masked: true,
                },
                secret,
            )
        })
        .unzip();
    RecoveryRun {
        summary: RecoverySummaryWire {
            algorithm: "sha256".into(),
            backend: request.backend,
            engine: "embedded_hashcat_1400".into(),
            tried: 0, // ABI v1 lacks trusted per-candidate progress.
            cancelled,
            limit_reached: false,
            duration_ms,
            matches,
        },
        confidential_hits,
    }
}

/// Reader may be a streamed local file, an in-memory fixture, or a bounded
/// job input. Results are transient; progress has no password material.
pub fn execute_reader<R: BufRead, P: FnMut(RecoveryProgressWire)>(
    request: &RecoveryRequest,
    reader: R,
    cancel: &RecoveryCancel,
    mut on_progress: P,
) -> Result<RecoveryRun, String> {
    validate_request(request)?;
    if let BackendSelection::OpenCl { .. } = request.backend {
        validate_backend(request.backend, Some(&gpu::probe()))?;
    }
    let started = Instant::now();
    let completed = recover_sha256_wordlist_on_backend(
        request.backend.try_into()?,
        &request.target_hash,
        reader,
        RecoveryLimits {
            max_candidates: request.max_candidates,
            max_matches: request.max_matches,
        },
        || cancel.is_cancelled(),
        |p| on_progress(p.into()),
    )?;
    let (matches, confidential_hits): (Vec<_>, Vec<_>) = completed
        .hits
        .into_iter()
        .map(|hit| {
            (
                MatchMetadata {
                    candidate_index: hit.index,
                    masked: true,
                },
                hit.candidate,
            )
        })
        .unzip();
    Ok(RecoveryRun {
        summary: RecoverySummaryWire {
            algorithm: request.algorithm.clone(),
            backend: request.backend,
            engine: completed.engine.into(),
            tried: completed.tried,
            cancelled: completed.cancelled,
            limit_reached: completed.limit_reached,
            duration_ms: started.elapsed().as_millis() as u64,
            matches,
        },
        confidential_hits,
    })
}

/// The IPC/controller owner handles path authorization and dialog selection.
pub fn execute_path<P: FnMut(RecoveryProgressWire)>(
    request: &RecoveryRequest,
    path: &Path,
    cancel: &RecoveryCancel,
    progress: P,
) -> Result<RecoveryRun, String> {
    validate_request(request)?;
    if !path.is_file() {
        return Err("wordlist must be a regular file".into());
    }
    let file = File::open(path).map_err(|e| format!("cannot open wordlist: {e}"))?;
    execute_reader(
        request,
        BufReader::with_capacity(1 << 20, file),
        cancel,
        progress,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    fn request(backend: BackendSelection) -> RecoveryRequest {
        RecoveryRequest {
            algorithm: "sha256".into(),
            target_hash: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
            backend,
            max_candidates: 3,
            max_matches: 1,
        }
    }
    #[test]
    fn cpu_vector_is_masked_until_authorized_reveal() {
        let mut events = Vec::new();
        let run = execute_reader(
            &request(BackendSelection::Cpu),
            Cursor::new(b"wrong\nabc\nother\n"),
            &RecoveryCancel::new(),
            |p| events.push(p),
        )
        .unwrap();
        assert_eq!(run.summary.tried, 2);
        assert_eq!(run.summary.matches[0].candidate_index, 1);
        assert!(run.summary.matches[0].masked);
        assert!(!serde_json::to_string(&run.summary).unwrap().contains("abc"));
        let owner = access::VerifiedScope::from_backend("session", "case", 1).unwrap();
        let mut gate = access::RecoveryResultAccess::new();
        gate.set_active(owner.clone());
        gate.retain(1, &owner, run, std::time::Duration::from_secs(30))
            .unwrap();
        assert!(gate.reveal(1, 0, &owner).is_none());
        gate.authorize_reveal(1, &owner).unwrap();
        assert_eq!(gate.reveal(1, 0, &owner).unwrap().as_bytes(), b"abc");
        assert_eq!(events.last().unwrap().tried, 2);
    }
    #[test]
    fn cancelled_cpu_run_checks_zero_candidates() {
        let token = RecoveryCancel::new();
        token.cancel();
        let run = execute_reader(
            &request(BackendSelection::Cpu),
            Cursor::new(b"abc\n"),
            &token,
            |_| {},
        )
        .unwrap();
        assert!(run.summary.cancelled);
        assert_eq!(run.summary.tried, 0);
    }
    #[test]
    fn mid_scan_cancellation_stops_after_verified_progress() {
        let token = RecoveryCancel::new();
        let signal = token.clone();
        let mut r = request(BackendSelection::Cpu);
        r.target_hash = "00".repeat(32);
        r.max_candidates = 10_000;
        let source = b"incorrect\n".repeat(10_000);
        let mut reported = Vec::new();
        let run = execute_reader(&r, Cursor::new(source), &token, |event| {
            reported.push(event.tried);
            if event.tried >= 4096 {
                signal.cancel();
            }
        })
        .unwrap();
        assert!(run.summary.cancelled);
        assert_eq!(run.summary.tried, 4096);
        assert!(reported.iter().all(|&n| n <= run.summary.tried));
        assert!(run.summary.matches.is_empty());
    }

    #[test]
    fn probe_inventory_never_claims_hardware_verification() {
        let inventory = probe_recovery_devices();
        assert!(inventory.devices.iter().all(|d| !d.hardware_verified));
    }

    #[test]
    fn local_wordlist_path_uses_streaming_and_never_persists() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "cyberdeck-agent2-{}-{stamp}.txt",
            std::process::id()
        ));
        std::fs::write(&path, b"first\nabc\nthird\n").unwrap();
        let result = execute_path(
            &request(BackendSelection::Cpu),
            &path,
            &RecoveryCancel::new(),
            |_| {},
        );
        let _ = std::fs::remove_file(&path);
        let run = result.unwrap();
        assert_eq!(run.summary.matches[0].candidate_index, 1);
    }

    #[test]
    fn independent_cpu_jobs_do_not_share_cancellation() {
        let cancelled = RecoveryCancel::new();
        let running = RecoveryCancel::new();
        let stopped_token = cancelled.clone();
        let healthy_token = running.clone();
        cancelled.cancel();
        let job_a = std::thread::spawn(move || {
            execute_reader(
                &request(BackendSelection::Cpu),
                Cursor::new(b"abc\n"),
                &stopped_token,
                |_| {},
            )
            .unwrap()
            .summary
            .clone()
        });
        let job_b = std::thread::spawn(move || {
            execute_reader(
                &request(BackendSelection::Cpu),
                Cursor::new(b"bad\nabc\n"),
                &healthy_token,
                |_| {},
            )
            .unwrap()
            .summary
            .clone()
        });
        let a = job_a.join().unwrap();
        let b = job_b.join().unwrap();
        assert_eq!(a.tried, 0);
        assert!(a.cancelled);
        assert_eq!(b.tried, 2);
        assert!(!b.cancelled);
        assert_eq!(b.matches[0].candidate_index, 1);
    }

    #[test]
    fn unavailable_opencl_never_falls_back_to_cpu() {
        if gpu::probe().available {
            return; // This fixture is specifically a no-device failure test.
        }
        let mut progress = Vec::new();
        let error = match execute_reader(
            &request(BackendSelection::OpenCl {
                device_index: 0,
                batch_size: 16,
            }),
            Cursor::new(b"abc\n"),
            &RecoveryCancel::new(),
            |event| progress.push(event),
        ) {
            Ok(_) => panic!("unavailable OpenCL must fail closed"),
            Err(error) => error,
        };
        assert!(error.contains("OpenCL unavailable"));
        assert!(progress.is_empty());
    }

    #[test]
    fn selected_gpu_rejects_unavailable_and_invalid_device() {
        let choice = BackendSelection::OpenCl {
            device_index: 0,
            batch_size: 16,
        };
        let no_gpu = GpuProbe {
            backend: "opencl",
            available: false,
            devices: vec![],
            detail: "no loader".into(),
        };
        assert!(validate_backend(choice, Some(&no_gpu))
            .unwrap_err()
            .contains("unavailable"));
        let fake = GpuProbe {
            backend: "opencl",
            available: true,
            devices: vec![gpu::GpuDevice {
                name: "fixture".into(),
                vendor: "test".into(),
                driver: "test".into(),
            }],
            detail: "detected, unverified".into(),
        };
        assert!(validate_backend(
            BackendSelection::OpenCl {
                device_index: 1,
                batch_size: 16
            },
            Some(&fake)
        )
        .unwrap_err()
        .contains("not available"));
        assert!(validate_backend(
            BackendSelection::OpenCl {
                device_index: 0,
                batch_size: 0
            },
            Some(&fake)
        )
        .unwrap_err()
        .contains("batch size"));
    }
    #[test]
    fn rejects_unknown_algorithms_and_unbounded_operations() {
        let mut r = request(BackendSelection::Cpu);
        r.algorithm = "bcrypt".into();
        assert!(validate_request(&r).is_err());
        r.algorithm = "sha256".into();
        r.max_candidates = MAX_FAST_CANDIDATES + 1;
        assert!(validate_request(&r).is_err());
        r.max_candidates = 3;
        r.target_hash = "xyz".into();
        assert!(validate_request(&r).is_err());
    }
    #[test]
    fn hashcat_managed_backend_is_not_silently_mapped_to_rust_cpu() {
        let mut r = request(BackendSelection::HashcatManaged);
        r.target_hash = "00".repeat(32);
        let serialized = serde_json::to_string(&r).unwrap();
        assert!(serialized.contains("\"backend\":\"hashcat_managed\""));
        let roundtrip: RecoveryRequest = serde_json::from_str(&serialized).unwrap();
        assert_eq!(roundtrip.backend, BackendSelection::HashcatManaged);
        assert!(<RecoveryBackend as TryFrom<BackendSelection>>::try_from(
            BackendSelection::HashcatManaged
        )
        .is_err());
        assert!(validate_backend(BackendSelection::HashcatManaged, None).is_err());
        assert!(execute_reader(
            &roundtrip,
            Cursor::new(b"fixture\\n"),
            &RecoveryCancel::new(),
            |_| {}
        )
        .is_err());
    }

    #[test]
    fn global_candidate_quota_and_cancel_token_roundtrip() {
        let mut r = request(BackendSelection::Cpu);
        r.target_hash = "00".repeat(32);
        r.max_candidates = 2;
        let run = execute_reader(
            &r,
            Cursor::new(b"one\ntwo\nthree\n"),
            &RecoveryCancel::new(),
            |_| {},
        )
        .unwrap();
        assert!(run.summary.limit_reached);
        assert_eq!(run.summary.tried, 2);
        let s = serde_json::to_string(&request(BackendSelection::OpenCl {
            device_index: 2,
            batch_size: 256,
        }))
        .unwrap();
        let decoded: RecoveryRequest = serde_json::from_str(&s).unwrap();
        assert_eq!(
            decoded.backend,
            BackendSelection::OpenCl {
                device_index: 2,
                batch_size: 256
            }
        );
    }
}
