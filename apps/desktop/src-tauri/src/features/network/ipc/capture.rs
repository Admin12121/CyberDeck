//! Native Linux capture IPC: bounded, case-revision scoped, operator-confirmed.
//! No arbitrary PCAP bytes or file paths are exposed through this transport.
use crate::features::forensics::ipc::evidence::EvidenceCtx;
use crate::features::shared::session::{CaseSessionCtx, CaseSessionWire};
use cyberdeck_packet::application::live_session::{
    CapturePage, CaptureSessionManager, CaptureStatus, FramePage,
};
use cyberdeck_packet::inventory::{FlowObservation, HostObservation};
use cyberdeck_packet::live::{self, CaptureInterface, CaptureLimits, FrameProvenance};
use cyberdeck_storage::NetworkCaptureSource;
use serde::Deserialize;
use serde::Serialize;
use std::sync::Mutex;
use std::time::Duration;
use tauri::Manager;
use tauri::{AppHandle, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

#[derive(Debug, Clone, Deserialize)]
pub struct CaptureLimitsWire {
    pub max_packets: usize,
    pub max_bytes: usize,
    pub duration_ms: u64,
}

impl CaptureLimitsWire {
    fn into_native(self) -> Result<CaptureLimits, String> {
        let limits = CaptureLimits {
            max_packets: self.max_packets,
            max_bytes: self.max_bytes,
            duration: Duration::from_millis(self.duration_ms),
            poll_interval: Duration::from_millis(100),
        };
        limits.validate().map_err(|error| error.message)?;
        Ok(limits)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Owner {
    scope: CaseSessionWire,
    session_id: u64,
}

#[derive(Default)]
pub struct CaptureCtx {
    manager: CaptureSessionManager,
    owner: Mutex<Option<Owner>>,
}
impl CaptureCtx {
    pub fn on_case_changed(&self) {
        let prior = self.owner.lock().ok().and_then(|mut o| o.take());
        if let Some(owner) = prior {
            if let Some(case) = owner.scope.case_id {
                let _ = self.manager.revoke(&case, owner.session_id);
            }
        }
    }
    fn owner_for(&self, session: &CaseSessionCtx, id: u64) -> Result<Owner, String> {
        let current = session.selected()?;
        let owner = self
            .owner
            .lock()
            .map_err(|_| "capture session unavailable")?
            .clone()
            .ok_or("no capture associated with the selected case")?;
        if current != owner.scope || owner.session_id != id {
            return Err("capture belongs to a different case revision or session".into());
        }
        Ok(owner)
    }
    fn valid_after<T>(
        &self,
        session: &CaseSessionCtx,
        owner: &Owner,
        result: T,
    ) -> Result<T, String> {
        session.ensure(&owner.scope)?;
        let active = self
            .owner
            .lock()
            .map_err(|_| "capture session unavailable")?;
        if active.as_ref() != Some(owner) {
            return Err("capture session was revoked while reading".into());
        }
        Ok(result)
    }
}

/// Existing interface fields stay compatible; support is independently reported
/// so discovery never falsely advertises capture-ready Windows adapters.
#[derive(serde::Serialize)]
pub struct CaptureInterfaceWire {
    #[serde(flatten)]
    interface: CaptureInterface,
    capture_supported: bool,
}

#[tauri::command]
pub fn capture_interfaces_v1() -> Result<Vec<CaptureInterfaceWire>, String> {
    Ok(live::discover_interfaces()
        .map_err(|error| error.message)?
        .into_iter()
        .map(|interface| CaptureInterfaceWire {
            interface,
            capture_supported: cfg!(target_os = "linux"),
        })
        .collect())
}

/// The operator must select a real Linux interface. The OS prompt is a
/// deliberate confirmation, never a substitute for OS CAP_NET_RAW.
#[tauri::command]
pub async fn capture_start_v1(
    app: AppHandle,
    interface_name: String,
    limits: CaptureLimitsWire,
    session: State<'_, CaseSessionCtx>,
    capture: State<'_, CaptureCtx>,
) -> Result<CaptureStatus, String> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (app, interface_name, limits, session, capture);
        return Err("native live capture is currently available only on Linux".into());
    }
    #[cfg(target_os = "linux")]
    {
        let scope = session.selected()?;
        let limits = limits.into_native()?;
        let message = format!(
            "Capture passive Ethernet frames from interface '{}' in the currently selected case? Capturing may include sensitive network metadata. The OS must independently authorize raw sockets.",
            interface_name
        );
        let accepted = tokio::task::spawn_blocking(move || {
            app.dialog()
                .message(message)
                .title("Confirm native packet capture")
                .buttons(MessageDialogButtons::YesNo)
                .blocking_show()
        })
        .await
        .map_err(|_| "capture confirmation unavailable")?;
        if !accepted {
            return Err("capture cancelled by operator".into());
        }
        session.ensure(&scope)?;
        let case = scope.case_id.as_deref().ok_or("no selected case")?;
        let status = capture
            .manager
            .start_linux(case, &interface_name, limits)
            .map_err(|e| format!("{:?}: {}", e.code, e.message))?;
        let owner = Owner {
            scope: scope.clone(),
            session_id: status.session_id,
        };
        if let Ok(mut lock) = capture.owner.lock() {
            *lock = Some(owner.clone());
        } else {
            let _ = capture.manager.revoke(case, status.session_id);
            return Err("capture session registry unavailable".into());
        }
        capture
            .valid_after(&session, &owner, status)
            .or_else(|err| {
                let _ = capture.manager.revoke(case, owner.session_id);
                Err(err)
            })
    }
}

#[tauri::command]
pub fn capture_status_v1(
    session_id: u64,
    session: State<'_, CaseSessionCtx>,
    capture: State<'_, CaptureCtx>,
) -> Result<CaptureStatus, String> {
    let owner = capture.owner_for(&session, session_id)?;
    let status = capture
        .manager
        .status(owner.scope.case_id.as_deref().unwrap_or(""), session_id)
        .map_err(|e| format!("{:?}: {}", e.code, e.message))?;
    capture.valid_after(&session, &owner, status)
}

#[tauri::command]
pub fn capture_stop_v1(
    session_id: u64,
    session: State<'_, CaseSessionCtx>,
    capture: State<'_, CaptureCtx>,
) -> Result<CaptureStatus, String> {
    let owner = capture.owner_for(&session, session_id)?;
    let status = capture
        .manager
        .stop(owner.scope.case_id.as_deref().unwrap_or(""), session_id)
        .map_err(|e| format!("{:?}: {}", e.code, e.message))?;
    capture.valid_after(&session, &owner, status)
}

#[tauri::command]
pub fn capture_hosts_v1(
    session_id: u64,
    offset: usize,
    len: usize,
    session: State<'_, CaseSessionCtx>,
    capture: State<'_, CaptureCtx>,
) -> Result<CapturePage<HostObservation>, String> {
    let owner = capture.owner_for(&session, session_id)?;
    let result = capture
        .manager
        .hosts(
            owner.scope.case_id.as_deref().unwrap_or(""),
            session_id,
            offset,
            len,
        )
        .map_err(|e| format!("{:?}: {}", e.code, e.message))?;
    capture.valid_after(&session, &owner, result)
}

#[tauri::command]
pub fn capture_flows_v1(
    session_id: u64,
    offset: usize,
    len: usize,
    session: State<'_, CaseSessionCtx>,
    capture: State<'_, CaptureCtx>,
) -> Result<CapturePage<FlowObservation>, String> {
    let owner = capture.owner_for(&session, session_id)?;
    let result = capture
        .manager
        .flows(
            owner.scope.case_id.as_deref().unwrap_or(""),
            session_id,
            offset,
            len,
        )
        .map_err(|e| format!("{:?}: {}", e.code, e.message))?;
    capture.valid_after(&session, &owner, result)
}

#[tauri::command]
pub fn capture_provenance_v1(
    session_id: u64,
    offset: usize,
    len: usize,
    session: State<'_, CaseSessionCtx>,
    capture: State<'_, CaptureCtx>,
) -> Result<CapturePage<FrameProvenance>, String> {
    let owner = capture.owner_for(&session, session_id)?;
    let result = capture
        .manager
        .provenance(
            owner.scope.case_id.as_deref().unwrap_or(""),
            session_id,
            offset,
            len,
        )
        .map_err(|e| format!("{:?}: {}", e.code, e.message))?;
    capture.valid_after(&session, &owner, result)
}

#[tauri::command]
pub fn capture_frame_page_v1(
    session_id: u64,
    index: usize,
    offset: usize,
    len: usize,
    session: State<'_, CaseSessionCtx>,
    capture: State<'_, CaptureCtx>,
) -> Result<FramePage, String> {
    let owner = capture.owner_for(&session, session_id)?;
    let result = capture
        .manager
        .frame_page(
            owner.scope.case_id.as_deref().unwrap_or(""),
            session_id,
            index,
            offset,
            len,
        )
        .map_err(|e| format!("{:?}: {}", e.code, e.message))?;
    capture.valid_after(&session, &owner, result)
}

/// Full native frame dissection (layers, protocol, stream ID) from original
/// bytes using the same Rust parser as opened PCAP files. Never changes the
/// currently opened offline capture cache.
#[tauri::command]
pub fn capture_packet_details_v1(
    session_id: u64,
    index: usize,
    session: State<'_, CaseSessionCtx>,
    capture: State<'_, CaptureCtx>,
) -> Result<crate::features::network::ipc::pcap::PcapPacketWire, String> {
    let owner = capture.owner_for(&session, session_id)?;
    let case = owner.scope.case_id.as_deref().ok_or("no selected case")?;
    let result = capture
        .manager
        .completed_for_case(case, session_id)
        .map_err(|error| format!("{:?}: {}", error.code, error.message))?;
    let offset = result
        .frame_provenance
        .get(index)
        .ok_or("capture frame index out of range")?
        .pcap_frame_offset;
    let packet = crate::features::network::ipc::pcap::original_capture_packet(
        &result.pcap_bytes,
        index,
        offset,
    )?;
    capture.valid_after(&session, &owner, packet)
}

/// Native bounded follow-stream projection. Only streams in the original
/// completed case/session can be reconstructed, and no full PCAP is returned.
#[tauri::command]
pub fn capture_follow_stream_v1(
    session_id: u64,
    stream_id: String,
    session: State<'_, CaseSessionCtx>,
    capture: State<'_, CaptureCtx>,
) -> Result<cyberdeck_packet::streams::StreamTranscript, String> {
    if stream_id.is_empty() || stream_id.len() > 256 {
        return Err("invalid capture stream identity".into());
    }
    let owner = capture.owner_for(&session, session_id)?;
    let case = owner.scope.case_id.as_deref().ok_or("no selected case")?;
    let result = capture
        .manager
        .completed_for_case(case, session_id)
        .map_err(|error| format!("{:?}: {}", error.code, error.message))?;
    let parsed = cyberdeck_packet::parse_capture(&result.pcap_bytes)?;
    if parsed.malformed_tail
        || parsed.packets.len() != result.frame_provenance.len()
        || parsed
            .packets
            .iter()
            .zip(&result.frame_provenance)
            .any(|(packet, frame)| packet.offset != frame.pcap_frame_offset)
    {
        return Err("original captured packet provenance is malformed".into());
    }
    let transcript = cyberdeck_packet::streams::follow_stream(&parsed.packets, &stream_id)?;
    capture.valid_after(&session, &owner, transcript)
}

/// Frontend-safe original-capture receipt: no bytes, evidence path or case secrets.
#[derive(Debug, Clone, Serialize)]
pub struct CaptureSaveReceipt {
    pub artifact_id: String,
    pub case_id: String,
    pub session_id: u64,
    pub interface: String,
    pub frame_count: usize,
    pub size: u64,
    pub sha256: String,
}

/// Trusted synchronous adapter. Capture session gate -> evidence store mutex ->
/// authoritative case publication gate matches the existing case-select lock
/// order (store -> publication). Never call a capture manager method inside its
/// publication callback or expose its CaptureResult through IPC.
fn save_original_capture(
    session: &CaseSessionCtx,
    capture: &CaptureCtx,
    evidence: &EvidenceCtx,
    expected: &Owner,
) -> Result<CaptureSaveReceipt, String> {
    if capture.owner_for(session, expected.session_id)? != *expected {
        return Err("capture identity was replaced before saving".into());
    }
    let case_id = expected
        .scope
        .case_id
        .as_deref()
        .ok_or("select a persistent case before saving capture")?;
    if case_id == "scratchpad" {
        return Err("temporary workspace is not a persistent evidence case".into());
    }
    capture
        .manager
        .publish_completed(case_id, expected.session_id, |result| {
            if result.frame_provenance.is_empty() {
                return Err("cannot save a capture without original frames".into());
            }
            // Case-selection IPC locks store before its publication gate.
            // Acquire the same order to avoid a concurrent case-switch deadlock.
            let store = evidence
                .store
                .lock()
                .map_err(|_| "case evidence store unavailable")?;
            session.with_current_publication(&expected.scope, || {
                // Owner registry may have changed even if the case revision did not.
                capture.valid_after(session, expected, ())?;
                let offsets: Vec<usize> = result
                    .frame_provenance
                    .iter()
                    .map(|frame| frame.pcap_frame_offset)
                    .collect();
                let source = NetworkCaptureSource {
                    session_id: expected.session_id,
                    interface: &result.interface.name,
                    frame_offsets: &offsets,
                    bytes: &result.pcap_bytes,
                };
                let record = store.import_original_network_capture(
                    &evidence.artifacts_dir,
                    case_id,
                    &source,
                )?;
                // Storage verifies original-byte readback using a pinned handle.
                // Never serialize record.stored_path or raw PCAP into the response.
                Ok(CaptureSaveReceipt {
                    artifact_id: record.id,
                    case_id: record.case_id,
                    session_id: expected.session_id,
                    interface: result.interface.name.clone(),
                    frame_count: offsets.len(),
                    size: record.size,
                    sha256: record.sha256,
                })
            })
        })
        .map_err(|error| format!("{:?}: {}", error.code, error.message))
}

/// Explicit native confirmation is mandatory. A frontend case ID, path, PCAP
/// byte array or consent flag is never accepted as an IPC argument.
#[tauri::command]
pub async fn capture_save_v1(
    app: AppHandle,
    session_id: u64,
    session: State<'_, CaseSessionCtx>,
    capture: State<'_, CaptureCtx>,
) -> Result<CaptureSaveReceipt, String> {
    let expected = capture.owner_for(&session, session_id)?;
    let case = expected
        .scope
        .case_id
        .as_deref()
        .ok_or("no selected case")?;
    if !capture
        .manager
        .status(case, session_id)
        .map_err(|error| format!("{:?}: {}", error.code, error.message))?
        .results_available
    {
        return Err("capture is not completed with original evidence".into());
    }
    let name = expected
        .scope
        .case_id
        .as_deref()
        .ok_or("select a persistent case before saving capture")?
        .to_owned();
    let accepted = tokio::task::spawn_blocking({
        let app = app.clone();
        move || {
            app.dialog()
                .message(format!(
                    "Save the exact original PCAP from capture session {session_id} as immutable evidence in case '{name}'? The case and capture authorization will be verified again before import."
                ))
                .title("Confirm original capture evidence import")
                .buttons(MessageDialogButtons::YesNo)
                .blocking_show()
        }
    })
    .await
    .map_err(|_| "capture save confirmation unavailable")?;
    if !accepted {
        return Err("capture save cancelled by operator".into());
    }
    tokio::task::spawn_blocking(move || {
        let session = app.state::<CaseSessionCtx>();
        let capture = app.state::<CaptureCtx>();
        let evidence = app.state::<EvidenceCtx>();
        save_original_capture(&session, &capture, &evidence, &expected)
    })
    .await
    .map_err(|_| "capture evidence worker unavailable".to_owned())?
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyberdeck_packet::live::{CaptureError, CaptureErrorCode};
    use cyberdeck_storage::ArtifactStore;

    use cyberdeck_packet::application::live_session::Phase;
    use cyberdeck_packet::live::{
        capture_from, CaptureInterface, CaptureLimits, FrameSource, ReceivedFrame,
    };
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant, UNIX_EPOCH};

    fn captured_frame() -> Vec<u8> {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&[
            0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2, 0x80, 0x00,
            0x00, 0x35, 0, 8, 0, 0,
        ]);
        frame
    }

    fn finished_capture(flag: &AtomicBool) -> cyberdeck_packet::live::CaptureResult {
        struct Source(Option<Vec<u8>>);
        impl FrameSource for Source {
            fn receive(
                &mut self,
                output: &mut [u8],
                _: Duration,
            ) -> Result<Option<ReceivedFrame>, cyberdeck_packet::live::CaptureError> {
                let Some(bytes) = self.0.take() else {
                    return Ok(None);
                };
                output[..bytes.len()].copy_from_slice(&bytes);
                Ok(Some(ReceivedFrame {
                    length: bytes.len(),
                    timestamp: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
                }))
            }
        }
        capture_from(
            &mut Source(Some(captured_frame())),
            CaptureInterface {
                name: "fixture0".into(),
                index: 1,
                ethernet: true,
                up: true,
                loopback: false,
            },
            &CaptureLimits {
                max_packets: 1,
                ..CaptureLimits::default()
            },
            flag,
        )
        .unwrap()
    }

    fn prepare_capture() -> (
        tempfile::TempDir,
        EvidenceCtx,
        CaseSessionCtx,
        CaptureCtx,
        Owner,
        Vec<u8>,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&temp.path().join("case.sqlite")).unwrap();
        let case = store.create_case("N2 Capture Evidence", "").unwrap();
        let scope_ctx = CaseSessionCtx::default();
        let revision = scope_ctx.select(&store, &case.id).unwrap();
        let evidence = EvidenceCtx {
            store: Mutex::new(store),
            artifacts_dir: temp.path().join("artifacts"),
        };
        let ctx = CaptureCtx::default();
        let started = ctx
            .manager
            .start_with(&case.id, "fixture0", |stop, _| Ok(finished_capture(&stop)))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if ctx
                .manager
                .status(&case.id, started.session_id)
                .unwrap()
                .phase
                == Phase::Completed
            {
                break;
            }
            assert!(Instant::now() < deadline, "fixture did not finish capture");
            std::thread::sleep(Duration::from_millis(2));
        }
        let result = ctx
            .manager
            .completed_for_case(&case.id, started.session_id)
            .unwrap();
        let bytes = result.pcap_bytes.clone();
        *ctx.owner.lock().unwrap() = Some(Owner {
            scope: revision.clone(),
            session_id: started.session_id,
        });
        (
            temp,
            evidence,
            scope_ctx,
            ctx,
            Owner {
                scope: revision,
                session_id: started.session_id,
            },
            bytes,
        )
    }

    #[cfg(unix)]
    #[test]
    fn save_capture_exact_original_pcap_and_digest_readback() {
        let (_tmp, evidence, selected, ctx, owner, original) = prepare_capture();
        let receipt = save_original_capture(&selected, &ctx, &evidence, &owner).unwrap();
        assert_eq!(receipt.session_id, owner.session_id);
        assert_eq!(receipt.frame_count, 1);
        assert_eq!(receipt.interface, "fixture0");
        assert_eq!(receipt.size as usize, original.len());
        assert_eq!(receipt.sha256.len(), 64);
        let store = evidence.store.lock().unwrap();
        let artifact = store.get_artifact(&receipt.artifact_id).unwrap().unwrap();
        assert_eq!(artifact.sha256, receipt.sha256);
        let mut reader =
            cyberdeck_storage::open_verified_case_artifact(&artifact, &evidence.artifacts_dir)
                .unwrap();
        let reopened = reader
            .read_window(0, original.len(), 16 * 1024 * 1024)
            .unwrap();
        assert_eq!(reopened, original);
        assert_eq!(
            store.list_events(&receipt.case_id).unwrap()[0].source,
            "network.capture"
        );
        assert_eq!(store.list_artifacts(&receipt.case_id).unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn save_capture_refuses_cross_case_revision_and_revoked_sessions() {
        let (_tmp, evidence, selected, ctx, owner, _bytes) = prepare_capture();
        let initial = owner.scope.case_id.clone().unwrap();
        let different = {
            evidence
                .store
                .lock()
                .unwrap()
                .create_case("Other", "")
                .unwrap()
        };
        {
            let store = evidence.store.lock().unwrap();
            selected.select(&store, &different.id).unwrap();
        }
        assert!(save_original_capture(&selected, &ctx, &evidence, &owner).is_err());
        assert!(evidence
            .store
            .lock()
            .unwrap()
            .list_artifacts(&initial)
            .unwrap()
            .is_empty());
        {
            let store = evidence.store.lock().unwrap();
            selected.select(&store, &initial).unwrap();
        }
        assert!(save_original_capture(&selected, &ctx, &evidence, &owner).is_err());
        // New case revision is never an authorization to resurrect old capture.
        ctx.on_case_changed();
        assert!(save_original_capture(&selected, &ctx, &evidence, &owner).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn save_capture_rejects_another_session_identity_without_side_effects() {
        let (_tmp, evidence, selected, ctx, owner, _original) = prepare_capture();
        let false_owner = Owner {
            scope: owner.scope.clone(),
            session_id: owner.session_id + 1,
        };
        assert!(save_original_capture(&selected, &ctx, &evidence, &false_owner).is_err());
        let case = owner.scope.case_id.as_deref().unwrap();
        let store = evidence.store.lock().unwrap();
        assert!(store.list_artifacts(case).unwrap().is_empty());
        assert!(store.list_events(case).unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn save_capture_failure_preserves_original_and_allows_authorized_retry() {
        let (_tmp, evidence, selected, ctx, owner, original) = prepare_capture();
        // Create a regular file at the evidence directory path, forcing importer error.
        std::fs::write(&evidence.artifacts_dir, b"blocked root").unwrap();
        let rejected = save_original_capture(&selected, &ctx, &evidence, &owner).unwrap_err();
        assert!(
            rejected.starts_with("ImportFailed: "),
            "expected a structured failed import"
        );
        assert_eq!(
            ctx.manager
                .completed_for_case(owner.scope.case_id.as_deref().unwrap(), owner.session_id)
                .unwrap()
                .pcap_bytes,
            original,
        );
        assert!(evidence
            .store
            .lock()
            .unwrap()
            .list_artifacts(owner.scope.case_id.as_deref().unwrap())
            .unwrap()
            .is_empty());
        std::fs::remove_file(&evidence.artifacts_dir).unwrap();
        std::fs::create_dir_all(&evidence.artifacts_dir).unwrap();
        let saved = save_original_capture(&selected, &ctx, &evidence, &owner).unwrap();
        assert_eq!(saved.size as usize, original.len());
        ctx.on_case_changed();
        assert!(save_original_capture(&selected, &ctx, &evidence, &owner).is_err());
    }

    #[test]
    fn capture_revoke_blocks_cross_case_reads_and_cancels_old_worker() {
        let temp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&temp.path().join("cases.db")).unwrap();
        let session = CaseSessionCtx::default();
        let old = session.select(&store, "scratchpad").unwrap();
        let ctx = CaptureCtx::default();
        let started = ctx
            .manager
            .start_with("scratchpad", "synthetic-test", |cancel, _| {
                for _ in 0..50 {
                    if cancel.load(std::sync::atomic::Ordering::Acquire) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(CaptureError {
                    code: CaptureErrorCode::Io,
                    message: "fixture stopped".into(),
                })
            })
            .unwrap();
        *ctx.owner.lock().unwrap() = Some(Owner {
            scope: old.clone(),
            session_id: started.session_id,
        });
        assert!(ctx.owner_for(&session, started.session_id).is_ok());
        let replacement = session.select(&store, "scratchpad").unwrap();
        assert_ne!(replacement.revision, old.revision);
        ctx.on_case_changed();
        assert!(ctx.owner_for(&session, started.session_id).is_err());
        assert!(ctx
            .manager
            .status("scratchpad", started.session_id)
            .is_err());
        ctx.manager.shutdown();
    }
}
