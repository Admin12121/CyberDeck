//! Native Linux capture IPC: bounded, case-revision scoped, operator-confirmed.
//! No arbitrary PCAP bytes or file paths are exposed through this transport.
use crate::features::shared::session::{CaseSessionCtx, CaseSessionWire};
use cyberdeck_packet::application::live_session::{
    CapturePage, CaptureSessionManager, CaptureStatus, FramePage,
};
use cyberdeck_packet::inventory::{FlowObservation, HostObservation};
use cyberdeck_packet::live::{self, CaptureInterface, CaptureLimits, FrameProvenance};
use serde::Deserialize;
use std::sync::Mutex;
use std::time::Duration;
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

#[tauri::command]
pub fn capture_interfaces_v1() -> Result<Vec<CaptureInterface>, String> {
    live::discover_interfaces().map_err(|e| e.message)
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

#[cfg(test)]
mod tests {
    use super::*;
    use cyberdeck_packet::live::{CaptureError, CaptureErrorCode};
    use cyberdeck_storage::ArtifactStore;

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
