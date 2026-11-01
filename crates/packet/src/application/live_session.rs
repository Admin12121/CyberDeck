//! N2 single-session capture lifecycle. No desktop or storage dependency.
//! All read access is scoped by the immutable case and session identity.
use crate::inventory::{FlowObservation, HostObservation, PassiveInventory};
use crate::live::{
    self, CaptureError, CaptureErrorCode, CaptureInterface, CaptureLimits, CaptureProgress,
    CaptureResult, FrameProvenance, StopReason,
};
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

pub const MAX_PAGE_ROWS: usize = 256;
pub const MAX_FRAME_PAGE_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Running,
    Stopping,
    Completed,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionErrorCode {
    Busy,
    InvalidCase,
    UnauthorizedSession,
    NotReady,
    InvalidPage,
    ImportFailed,
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SessionError {
    pub code: SessionErrorCode,
    pub message: String,
}
impl SessionError {
    fn new(code: SessionErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CaptureStatus {
    pub session_id: u64,
    pub case_id: String,
    pub interface: String,
    pub phase: Phase,
    pub progress: CaptureProgress,
    pub stop_reason: Option<StopReason>,
    pub error: Option<CaptureError>,
    pub results_available: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct CapturePage<T> {
    pub total: usize,
    pub offset: usize,
    pub entries: Vec<T>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FramePage {
    pub index: usize,
    pub frame_length: usize,
    pub offset: usize,
    /// At most MAX_FRAME_PAGE_BYTES; no unrestricted PCAP buffer IPC.
    pub bytes: Vec<u8>,
}

struct Session {
    id: u64,
    case_id: String,
    interface: String,
    phase: Phase,
    revoked: bool,
    cancel: Arc<AtomicBool>,
    progress: CaptureProgress,
    result: Option<Arc<CaptureResult>>,
    stop_reason: Option<StopReason>,
    error: Option<CaptureError>,
}
impl Session {
    fn status(&self) -> CaptureStatus {
        CaptureStatus {
            session_id: self.id,
            case_id: self.case_id.clone(),
            interface: self.interface.clone(),
            phase: self.phase,
            progress: self.progress.clone(),
            stop_reason: self.stop_reason,
            error: self.error.clone(),
            results_available: !self.revoked
                && self.phase == Phase::Completed
                && self.result.is_some(),
        }
    }
}

#[derive(Default)]
struct Shared {
    session: Option<Session>,
}

/// One active worker maximum, even across case-switch revocation. Cloning is
/// intentionally unsupported so all UI consumers must share a single manager.
pub struct CaptureSessionManager {
    shared: Arc<Mutex<Shared>>,
    worker: Mutex<Option<JoinHandle<()>>>,
    /// Serializes publication with replacement and revocation without blocking
    /// ordinary status, stop, or paginated result reads during a disk commit.
    publication_gate: Mutex<()>,
    next_id: AtomicU64,
    /// A stopped desktop session manager must not spawn or publish again.
    closed: AtomicBool,
}

impl Default for CaptureSessionManager {
    fn default() -> Self {
        Self {
            shared: Arc::new(Mutex::new(Shared::default())),
            worker: Mutex::new(None),
            publication_gate: Mutex::new(()),
            next_id: AtomicU64::new(1),
            closed: AtomicBool::new(false),
        }
    }
}

impl CaptureSessionManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a real Linux capture on a caller-authorized, case-selected interface.
    /// The caller must validate case membership and user consent against backend
    /// policy before calling this application service.
    pub fn start_linux(
        &self,
        case_id: &str,
        interface_name: &str,
        limits: CaptureLimits,
    ) -> Result<CaptureStatus, SessionError> {
        limits
            .validate()
            .map_err(|e| SessionError::new(SessionErrorCode::InvalidPage, e.message))?;
        let devices = live::discover_interfaces()
            .map_err(|e| SessionError::new(SessionErrorCode::Internal, e.message))?;
        let selected = live::select_interface(&devices, interface_name)
            .map_err(|e| SessionError::new(SessionErrorCode::InvalidPage, e.message))?;
        let interface = selected.name;
        let worker_interface = interface.clone();
        self.start_with(case_id, &interface, move |cancel, progress| {
            live::capture_linux_with_progress(&worker_interface, &limits, &cancel, progress)
        })
    }

    /// Start one case-scoped Windows capture via CyberDeck's own kernel device.
    /// Frontend permission confirmation remains in the trusted Tauri boundary.
    #[cfg(target_os = "windows")]
    pub fn start_windows(
        &self,
        case_id: &str,
        interface_name: &str,
        expected_luid: u64,
        limits: CaptureLimits,
    ) -> Result<CaptureStatus, SessionError> {
        limits
            .validate()
            .map_err(|e| SessionError::new(SessionErrorCode::InvalidPage, e.message))?;
        let devices = live::discover_interfaces()
            .map_err(|e| SessionError::new(SessionErrorCode::Internal, e.message))?;
        let selected = live::select_interface(&devices, interface_name)
            .map_err(|e| SessionError::new(SessionErrorCode::InvalidPage, e.message))?;
        let current_luid = live::authorized_windows_interface_luid(interface_name)
            .map_err(|e| SessionError::new(SessionErrorCode::InvalidPage, e.message))?;
        if current_luid != expected_luid {
            return Err(SessionError::new(
                SessionErrorCode::UnauthorizedSession,
                "selected Windows interface identity changed after operator consent",
            ));
        }
        let interface = selected.name;
        let worker_interface = interface.clone();
        self.start_with(case_id, &interface, move |cancel, progress| {
            live::capture_windows_with_progress(
                &worker_interface,
                expected_luid,
                &limits,
                &cancel,
                progress,
            )
        })
    }

    /// Injectable worker for deterministic lifecycle tests. The engine owns
    /// the stop flag; the worker must honor it within its bounded poll period.
    pub fn start_with<F>(
        &self,
        case_id: &str,
        interface: &str,
        run: F,
    ) -> Result<CaptureStatus, SessionError>
    where
        F: FnOnce(
                Arc<AtomicBool>,
                Box<dyn FnMut(CaptureProgress) + Send>,
            ) -> Result<CaptureResult, CaptureError>
            + Send
            + 'static,
    {
        let _publication = self.publication_gate.lock().map_err(|_| {
            SessionError::new(
                SessionErrorCode::Internal,
                "capture publication gate unavailable",
            )
        })?;
        if self.closed.load(Ordering::Acquire) {
            return Err(SessionError::new(
                SessionErrorCode::NotReady,
                "capture manager is shut down",
            ));
        }
        let case_id = case_id.trim();
        if case_id.is_empty() || case_id.len() > 128 || interface.is_empty() || interface.len() > 64
        {
            return Err(SessionError::new(
                SessionErrorCode::InvalidCase,
                "valid selected case and interface required",
            ));
        }
        let mut shared = self.shared.lock().map_err(|_| {
            SessionError::new(SessionErrorCode::Internal, "capture state unavailable")
        })?;
        if shared
            .session
            .as_ref()
            .is_some_and(|s| matches!(s.phase, Phase::Running | Phase::Stopping))
        {
            return Err(SessionError::new(
                SessionErrorCode::Busy,
                "one capture is already active or stopping",
            ));
        }
        // A finished worker can be reaped without waiting on an active one.
        let old = self
            .worker
            .lock()
            .map_err(|_| SessionError::new(SessionErrorCode::Internal, "worker state unavailable"))?
            .take();
        if let Some(handle) = old {
            // Completion phase is published from the worker immediately before it exits.
            // Join outside the shared lock to avoid a deadlock.
            drop(shared);
            let _ = handle.join();
            shared = self.shared.lock().map_err(|_| {
                SessionError::new(SessionErrorCode::Internal, "capture state unavailable")
            })?;
            if shared
                .session
                .as_ref()
                .is_some_and(|s| matches!(s.phase, Phase::Running | Phase::Stopping))
            {
                return Err(SessionError::new(
                    SessionErrorCode::Busy,
                    "capture was restarted concurrently",
                ));
            }
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let flag = Arc::new(AtomicBool::new(false));
        shared.session = Some(Session {
            id,
            case_id: case_id.to_string(),
            interface: interface.to_string(),
            phase: Phase::Running,
            revoked: false,
            cancel: Arc::clone(&flag),
            progress: CaptureProgress {
                packets: 0,
                stored_pcap_bytes: 0,
                oversized_frames_discarded: 0,
            },
            result: None,
            stop_reason: None,
            error: None,
        });
        let initial = shared
            .session
            .as_ref()
            .expect("new session exists")
            .status();
        let state = Arc::clone(&self.shared);
        let worker = std::thread::spawn(move || {
            let progress_state = Arc::clone(&state);
            let progress = Box::new(move |value: CaptureProgress| {
                if let Ok(mut guard) = progress_state.lock() {
                    if let Some(active) =
                        guard.session.as_mut().filter(|s| s.id == id && !s.revoked)
                    {
                        // Progress can only advance and must remain bounded.
                        if value.packets >= active.progress.packets
                            && value.stored_pcap_bytes >= active.progress.stored_pcap_bytes
                        {
                            active.progress = value;
                        }
                    }
                }
            });
            let outcome =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(flag, progress)));
            if let Ok(mut guard) = state.lock() {
                if let Some(active) = guard.session.as_mut().filter(|s| s.id == id) {
                    match outcome {
                        Ok(Ok(value)) => {
                            active.stop_reason = Some(value.stop_reason);
                            if !active.revoked {
                                active.progress = CaptureProgress {
                                    packets: value.frame_provenance.len(),
                                    stored_pcap_bytes: value.pcap_bytes.len(),
                                    oversized_frames_discarded: value.oversized_frames_discarded,
                                };
                                active.result = Some(Arc::new(value));
                            }
                            active.phase = Phase::Completed;
                        }
                        Ok(Err(error)) => {
                            active.error = Some(error);
                            active.phase = Phase::Failed;
                        }
                        Err(_) => {
                            active.error = Some(CaptureError {
                                code: CaptureErrorCode::Io,
                                message: "capture worker failed unexpectedly".into(),
                            });
                            active.phase = Phase::Failed;
                        }
                    }
                }
            }
        });
        *self.worker.lock().map_err(|_| {
            SessionError::new(SessionErrorCode::Internal, "worker state unavailable")
        })? = Some(worker);
        Ok(initial)
    }

    pub fn stop(&self, case_id: &str, id: u64) -> Result<CaptureStatus, SessionError> {
        let mut guard = self.shared.lock().map_err(|_| {
            SessionError::new(SessionErrorCode::Internal, "capture state unavailable")
        })?;
        let s = checked_mut(&mut guard, case_id, id)?;
        if s.phase == Phase::Running {
            s.phase = Phase::Stopping;
            s.cancel.store(true, Ordering::Release);
        }
        Ok(s.status())
    }

    /// Revoke results immediately on case-switch. No new session may start
    /// before the old worker has actually published its terminal state.
    pub fn revoke(&self, case_id: &str, id: u64) -> Result<(), SessionError> {
        let _publication = self.publication_gate.lock().map_err(|_| {
            SessionError::new(
                SessionErrorCode::Internal,
                "capture publication gate unavailable",
            )
        })?;
        let mut guard = self.shared.lock().map_err(|_| {
            SessionError::new(SessionErrorCode::Internal, "capture state unavailable")
        })?;
        let s = checked_mut(&mut guard, case_id, id)?;
        s.revoked = true;
        s.result = None;
        s.cancel.store(true, Ordering::Release);
        if s.phase == Phase::Running {
            s.phase = Phase::Stopping;
        }
        Ok(())
    }

    pub fn status(&self, case_id: &str, id: u64) -> Result<CaptureStatus, SessionError> {
        let guard = self.shared.lock().map_err(|_| {
            SessionError::new(SessionErrorCode::Internal, "capture state unavailable")
        })?;
        Ok(checked(&guard, case_id, id)?.status())
    }

    /// Internal-only: gives case backend the *exact* original PCAP bytes for
    /// immutable artifact import. Never forward this Arc as raw IPC bytes.
    pub fn completed_for_case(
        &self,
        case_id: &str,
        id: u64,
    ) -> Result<Arc<CaptureResult>, SessionError> {
        let guard = self.shared.lock().map_err(|_| {
            SessionError::new(SessionErrorCode::Internal, "capture state unavailable")
        })?;
        let s = checked(&guard, case_id, id)?;
        s.result.clone().ok_or_else(|| {
            SessionError::new(
                SessionErrorCode::NotReady,
                "capture is not completed successfully",
            )
        })
    }

    /// Trusted backend evidence publication boundary. A separate gate
    /// serializes this callback with session revocation and replacement; the
    /// ordinary session-state mutex is released before any storage I/O.
    ///
    /// The publisher must independently revalidate authoritative selected-case
    /// revision/consent in Agent5's storage transaction immediately before
    /// committing. Neither a caller-supplied case ID nor this gate authorizes
    /// persistent evidence. The callback must not reenter start, revoke or
    /// publish on this manager (those operations acquire the same gate).
    /// Status, stop and paginated reads remain responsive during publication.
    /// A failed publisher leaves the original PCAP result intact for retry.
    pub fn publish_completed<T>(
        &self,
        case_id: &str,
        id: u64,
        publish: impl FnOnce(&CaptureResult) -> Result<T, String>,
    ) -> Result<T, SessionError> {
        let _publication = self.publication_gate.lock().map_err(|_| {
            SessionError::new(
                SessionErrorCode::Internal,
                "capture publication gate unavailable",
            )
        })?;
        if self.closed.load(Ordering::Acquire) {
            return Err(SessionError::new(
                SessionErrorCode::NotReady,
                "capture manager is shut down",
            ));
        }
        let result = {
            let guard = self.shared.lock().map_err(|_| {
                SessionError::new(SessionErrorCode::Internal, "capture state unavailable")
            })?;
            let session = checked(&guard, case_id, id)?;
            session.result.clone().ok_or_else(|| {
                SessionError::new(
                    SessionErrorCode::NotReady,
                    "capture is not completed successfully",
                )
            })?
        };
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| publish(&result))) {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(SessionError::new(SessionErrorCode::ImportFailed, error)),
            Err(_) => Err(SessionError::new(
                SessionErrorCode::ImportFailed,
                "capture evidence publisher failed unexpectedly",
            )),
        }
    }

    pub fn hosts(
        &self,
        case_id: &str,
        id: u64,
        offset: usize,
        len: usize,
    ) -> Result<CapturePage<HostObservation>, SessionError> {
        let value = self.completed_for_case(case_id, id)?;
        page(&value.inventory.hosts, offset, len)
    }
    pub fn flows(
        &self,
        case_id: &str,
        id: u64,
        offset: usize,
        len: usize,
    ) -> Result<CapturePage<FlowObservation>, SessionError> {
        let value = self.completed_for_case(case_id, id)?;
        page(&value.inventory.flows, offset, len)
    }
    pub fn provenance(
        &self,
        case_id: &str,
        id: u64,
        offset: usize,
        len: usize,
    ) -> Result<CapturePage<FrameProvenance>, SessionError> {
        let value = self.completed_for_case(case_id, id)?;
        page(&value.frame_provenance, offset, len)
    }
    pub fn frame_page(
        &self,
        case_id: &str,
        id: u64,
        index: usize,
        offset: usize,
        len: usize,
    ) -> Result<FramePage, SessionError> {
        if len == 0 || len > MAX_FRAME_PAGE_BYTES {
            return Err(SessionError::new(
                SessionErrorCode::InvalidPage,
                "frame page limit is 4096 bytes",
            ));
        }
        let value = self.completed_for_case(case_id, id)?;
        let frame = value.original_frame(index).ok_or_else(|| {
            SessionError::new(
                SessionErrorCode::InvalidPage,
                "packet index is out of bounds",
            )
        })?;
        if offset > frame.len() {
            return Err(SessionError::new(
                SessionErrorCode::InvalidPage,
                "frame offset is out of bounds",
            ));
        }
        Ok(FramePage {
            index,
            frame_length: frame.len(),
            offset,
            bytes: frame[offset..frame.len().min(offset.saturating_add(len))].to_vec(),
        })
    }

    /// Join only after signaling cancellation. Used for deterministic lifecycle
    /// acceptance and graceful desktop shutdown, not from a UI render thread.
    pub fn shutdown(&self) {
        // Linearize terminal shutdown with active capture publication and new
        // sessions, then cancel/finish the worker without holding this gate.
        // A caller must not invoke shutdown from inside a publisher callback.
        let Ok(_publication) = self.publication_gate.lock() else {
            return;
        };
        self.closed.store(true, Ordering::Release);
        if let Ok(mut guard) = self.shared.lock() {
            if let Some(s) = guard.session.as_mut() {
                s.revoked = true;
                s.cancel.store(true, Ordering::Release);
                s.result = None;
            }
        }
        drop(_publication);
        if let Ok(mut worker) = self.worker.lock() {
            if let Some(handle) = worker.take() {
                let _ = handle.join();
            }
        }
    }
}

impl Drop for CaptureSessionManager {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn checked<'a>(guard: &'a Shared, case_id: &str, id: u64) -> Result<&'a Session, SessionError> {
    guard
        .session
        .as_ref()
        .filter(|s| s.id == id && s.case_id == case_id && !s.revoked)
        .ok_or_else(|| {
            SessionError::new(
                SessionErrorCode::UnauthorizedSession,
                "capture session is unavailable for this case",
            )
        })
}
fn checked_mut<'a>(
    guard: &'a mut Shared,
    case_id: &str,
    id: u64,
) -> Result<&'a mut Session, SessionError> {
    guard
        .session
        .as_mut()
        .filter(|s| s.id == id && s.case_id == case_id && !s.revoked)
        .ok_or_else(|| {
            SessionError::new(
                SessionErrorCode::UnauthorizedSession,
                "capture session is unavailable for this case",
            )
        })
}
fn page<T: Clone>(all: &[T], offset: usize, len: usize) -> Result<CapturePage<T>, SessionError> {
    if len == 0 || len > MAX_PAGE_ROWS || offset > all.len() {
        return Err(SessionError::new(
            SessionErrorCode::InvalidPage,
            "inventory page limit is 256 rows",
        ));
    }
    Ok(CapturePage {
        total: all.len(),
        offset,
        entries: all[offset..all.len().min(offset.saturating_add(len))].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live::{CaptureInterface, FrameSource, ReceivedFrame};
    use std::sync::mpsc;
    use std::time::{Duration, Instant, UNIX_EPOCH};

    fn sample_frame() -> Vec<u8> {
        let mut bytes = vec![0u8; 12];
        bytes.extend_from_slice(&0x0800u16.to_be_bytes());
        bytes.extend_from_slice(&[
            0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 198, 51, 100, 2, 0x80, 0x00,
            0x00, 0x35, 0, 8, 0, 0,
        ]);
        bytes
    }
    fn result(cancel: &AtomicBool) -> CaptureResult {
        struct Once(Option<Vec<u8>>);
        impl FrameSource for Once {
            fn receive(
                &mut self,
                out: &mut [u8],
                _timeout: Duration,
            ) -> Result<Option<ReceivedFrame>, CaptureError> {
                let Some(frame) = self.0.take() else {
                    return Ok(None);
                };
                out[..frame.len()].copy_from_slice(&frame);
                Ok(Some(ReceivedFrame {
                    length: frame.len(),
                    timestamp: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
                }))
            }
        }
        let mut source = Once(Some(sample_frame()));
        let interface = CaptureInterface {
            name: "fixture0".into(),
            index: 1,
            ethernet: true,
            up: true,
            loopback: false,
        };
        live::capture_from(
            &mut source,
            interface,
            &CaptureLimits {
                max_packets: 1,
                ..CaptureLimits::default()
            },
            cancel,
        )
        .unwrap()
    }
    fn until(manager: &CaptureSessionManager, case: &str, id: u64, expected: Phase) {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if manager.status(case, id).unwrap().phase == expected {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "capture phase did not become {:?}",
                expected
            );
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    #[test]
    fn completed_results_are_case_bound_paged_and_original_bytes() {
        let manager = CaptureSessionManager::new();
        let start = manager
            .start_with("case-A", "fixture0", |flag, _| Ok(result(&flag)))
            .unwrap();
        assert_eq!(start.phase, Phase::Running);
        until(&manager, "case-A", start.session_id, Phase::Completed);
        let status = manager.status("case-A", start.session_id).unwrap();
        assert_eq!(status.stop_reason, Some(StopReason::PacketLimit));
        assert!(status.results_available);
        assert_eq!(status.progress.packets, 1);
        assert_eq!(
            manager.status("case-B", start.session_id).unwrap_err().code,
            SessionErrorCode::UnauthorizedSession
        );
        assert_eq!(
            manager
                .completed_for_case("case-B", start.session_id)
                .unwrap_err()
                .code,
            SessionErrorCode::UnauthorizedSession
        );
        let original = manager
            .completed_for_case("case-A", start.session_id)
            .unwrap();
        assert_eq!(original.original_frame(0).unwrap(), sample_frame());
        assert_eq!(
            manager
                .provenance("case-A", start.session_id, 0, 2)
                .unwrap()
                .total,
            1
        );
        assert_eq!(
            manager
                .hosts("case-A", start.session_id, 0, 2)
                .unwrap()
                .total,
            2
        );
        assert_eq!(
            manager
                .flows("case-A", start.session_id, 0, 2)
                .unwrap()
                .total,
            1
        );
        let page = manager
            .frame_page("case-A", start.session_id, 0, 5, 3)
            .unwrap();
        assert_eq!(page.bytes, sample_frame()[5..8]);
        assert_eq!(page.frame_length, sample_frame().len());
        assert_eq!(
            manager
                .frame_page("case-A", start.session_id, 0, 0, MAX_FRAME_PAGE_BYTES + 1)
                .unwrap_err()
                .code,
            SessionErrorCode::InvalidPage
        );
        assert_eq!(
            manager
                .hosts("case-A", start.session_id, 0, MAX_PAGE_ROWS + 1)
                .unwrap_err()
                .code,
            SessionErrorCode::InvalidPage
        );
    }

    #[test]
    fn concurrent_start_rejected_repeated_stop_is_safe_and_replacement_succeeds() {
        let manager = CaptureSessionManager::new();
        let (entered, receive) = mpsc::channel();
        let current = manager
            .start_with("case-A", "fixture0", move |flag, _| {
                entered.send(()).unwrap();
                while !flag.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Ok(result(&flag))
            })
            .unwrap();
        receive.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(
            manager
                .start_with("case-B", "fixture0", |flag, _| Ok(result(&flag)))
                .unwrap_err()
                .code,
            SessionErrorCode::Busy
        );
        assert_eq!(
            manager.stop("case-B", current.session_id).unwrap_err().code,
            SessionErrorCode::UnauthorizedSession
        );
        assert_eq!(
            manager.stop("case-A", current.session_id).unwrap().phase,
            Phase::Stopping
        );
        assert_eq!(
            manager.stop("case-A", current.session_id).unwrap().phase,
            Phase::Stopping
        );
        until(&manager, "case-A", current.session_id, Phase::Completed);
        assert_eq!(
            manager
                .status("case-A", current.session_id)
                .unwrap()
                .stop_reason,
            Some(StopReason::Cancelled)
        );
        let next = manager
            .start_with("case-B", "fixture0", |flag, _| Ok(result(&flag)))
            .unwrap();
        assert!(next.session_id > current.session_id);
        assert_eq!(
            manager
                .status("case-A", current.session_id)
                .unwrap_err()
                .code,
            SessionErrorCode::UnauthorizedSession
        );
        until(&manager, "case-B", next.session_id, Phase::Completed);
    }

    #[test]
    fn case_switch_revokes_results_and_cancels_old_worker_before_new_start() {
        let manager = CaptureSessionManager::new();
        let (entered, receive) = mpsc::channel();
        let (release, release_rx) = mpsc::channel::<()>();
        let first = manager
            .start_with("case-A", "fixture0", move |flag, _| {
                entered.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                Ok(result(&flag))
            })
            .unwrap();
        receive.recv_timeout(Duration::from_secs(2)).unwrap();
        manager.revoke("case-A", first.session_id).unwrap();
        assert_eq!(
            manager.status("case-A", first.session_id).unwrap_err().code,
            SessionErrorCode::UnauthorizedSession
        );
        assert_eq!(
            manager
                .start_with("case-B", "fixture0", |flag, _| Ok(result(&flag)))
                .unwrap_err()
                .code,
            SessionErrorCode::Busy
        );
        release.send(()).unwrap();
        // Revoked state can no longer be inspected, but worker must finish
        // before its replacement becomes eligible.
        let deadline = Instant::now() + Duration::from_secs(3);
        let second = loop {
            match manager.start_with("case-B", "fixture0", |flag, _| Ok(result(&flag))) {
                Ok(value) => break value,
                Err(e) if e.code == SessionErrorCode::Busy => {
                    assert!(Instant::now() < deadline);
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(e) => panic!("unexpected start error: {e:?}"),
            }
        };
        until(&manager, "case-B", second.session_id, Phase::Completed);
        assert!(manager
            .completed_for_case("case-A", first.session_id)
            .is_err());
    }

    #[test]
    fn failure_is_typed_and_new_session_clears_old_failure() {
        let manager = CaptureSessionManager::new();
        let bad = manager
            .start_with("c", "fixture0", |_, _| {
                Err(CaptureError {
                    code: CaptureErrorCode::PermissionDenied,
                    message: "requires CAP_NET_RAW".into(),
                })
            })
            .unwrap();
        until(&manager, "c", bad.session_id, Phase::Failed);
        let status = manager.status("c", bad.session_id).unwrap();
        assert_eq!(
            status.error.unwrap().code,
            CaptureErrorCode::PermissionDenied
        );
        assert!(!status.results_available);
        assert_eq!(
            manager
                .completed_for_case("c", bad.session_id)
                .unwrap_err()
                .code,
            SessionErrorCode::NotReady
        );
        let good = manager
            .start_with("c", "fixture0", |flag, _| Ok(result(&flag)))
            .unwrap();
        until(&manager, "c", good.session_id, Phase::Completed);
        assert!(manager
            .status("c", good.session_id)
            .unwrap()
            .error
            .is_none());
    }

    #[test]
    fn progress_is_scoped_to_current_session_and_never_moves_backwards() {
        let manager = CaptureSessionManager::new();
        let (sent, recv) = mpsc::channel();
        let (resume, await_resume) = mpsc::channel::<()>();
        let session = manager
            .start_with("c", "eth0", move |flag, mut progress| {
                progress(CaptureProgress {
                    packets: 2,
                    stored_pcap_bytes: 300,
                    oversized_frames_discarded: 0,
                });
                progress(CaptureProgress {
                    packets: 1,
                    stored_pcap_bytes: 20,
                    oversized_frames_discarded: 0,
                });
                sent.send(()).unwrap();
                await_resume.recv_timeout(Duration::from_secs(2)).unwrap();
                Ok(result(&flag))
            })
            .unwrap();
        recv.recv_timeout(Duration::from_secs(2)).unwrap();
        let status = manager.status("c", session.session_id).unwrap();
        assert_eq!(status.progress.packets, 2);
        assert_eq!(status.progress.stored_pcap_bytes, 300);
        assert!(!status.results_available);
        resume.send(()).unwrap();
        until(&manager, "c", session.session_id, Phase::Completed);
        assert_eq!(
            manager
                .status("c", session.session_id)
                .unwrap()
                .progress
                .packets,
            1
        );
    }

    #[test]
    fn interface_loss_surfaces_structured_io_error_without_reusable_capture() {
        let manager = CaptureSessionManager::new();
        let run = manager
            .start_with("case", "eth0", |_, _| {
                Err(CaptureError {
                    code: CaptureErrorCode::Io,
                    message: "selected interface disappeared during receive".into(),
                })
            })
            .unwrap();
        until(&manager, "case", run.session_id, Phase::Failed);
        let status = manager.status("case", run.session_id).unwrap();
        assert_eq!(status.error.unwrap().code, CaptureErrorCode::Io);
        assert!(!status.results_available);
        assert!(manager
            .frame_page("case", run.session_id, 0, 0, 10)
            .is_err());
    }

    #[test]
    fn shutdown_cancels_and_joins_without_leaking_background_workers() {
        let manager = CaptureSessionManager::new();
        let (started_tx, started_rx) = mpsc::channel();
        let finished = Arc::new(AtomicBool::new(false));
        let finished_worker = Arc::clone(&finished);
        manager
            .start_with("case", "eth0", move |flag, _| {
                started_tx.send(()).unwrap();
                while !flag.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(2));
                }
                finished_worker.store(true, Ordering::Release);
                Ok(result(&flag))
            })
            .unwrap();
        started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        manager.shutdown();
        assert!(finished.load(Ordering::Acquire));
    }

    #[test]
    fn panic_in_worker_is_terminal_and_does_not_poison_session_manager() {
        let manager = CaptureSessionManager::new();
        let session = manager
            .start_with("case", "eth0", |_, _| {
                panic!("controlled fixture panic");
            })
            .unwrap();
        until(&manager, "case", session.session_id, Phase::Failed);
        assert_eq!(
            manager
                .status("case", session.session_id)
                .unwrap()
                .error
                .unwrap()
                .code,
            CaptureErrorCode::Io
        );
        let next = manager
            .start_with("case", "eth0", |flag, _| Ok(result(&flag)))
            .unwrap();
        until(&manager, "case", next.session_id, Phase::Completed);
    }

    #[test]
    fn case_import_handoff_preserves_identical_pcap_bytes_and_retries_failure() {
        let manager = CaptureSessionManager::new();
        let run = manager
            .start_with("case-A", "fixture0", |cancel, _| Ok(result(&cancel)))
            .unwrap();
        until(&manager, "case-A", run.session_id, Phase::Completed);
        let expected = manager
            .completed_for_case("case-A", run.session_id)
            .unwrap();
        let mut original = Vec::<u8>::new();
        let imported = manager
            .publish_completed("case-A", run.session_id, |result| {
                assert_eq!(result.pcap_bytes, expected.pcap_bytes);
                assert_eq!(result.original_frame(0).unwrap(), sample_frame());
                original.extend_from_slice(&result.pcap_bytes);
                Err::<(), _>("storage transaction rejected; no commit".to_string())
            })
            .unwrap_err();
        assert_eq!(imported.code, SessionErrorCode::ImportFailed);
        assert!(imported.message.contains("transaction rejected"));
        assert_eq!(
            manager
                .status("case-A", run.session_id)
                .unwrap()
                .results_available,
            true
        );
        let expected_bytes = expected.pcap_bytes.clone();
        let stored = manager
            .publish_completed("case-A", run.session_id, |result| {
                assert_eq!(result.pcap_bytes, original);
                Ok(result.pcap_bytes.clone())
            })
            .unwrap();
        assert_eq!(stored, expected_bytes);
        assert_eq!(stored[40..], sample_frame());
        assert_eq!(
            manager
                .provenance("case-A", run.session_id, 0, 1)
                .unwrap()
                .entries[0]
                .pcap_frame_offset,
            40
        );
    }

    #[test]
    fn panicking_importer_does_not_poison_publication_or_destroy_original_capture() {
        let manager = CaptureSessionManager::new();
        let started = manager
            .start_with("case-A", "fixture0", |stop, _| Ok(result(&stop)))
            .unwrap();
        until(&manager, "case-A", started.session_id, Phase::Completed);
        let attempted = manager.publish_completed("case-A", started.session_id, |_result| {
            panic!("injected storage callback panic");
            #[allow(unreachable_code)]
            Ok::<(), String>(())
        });
        let error = attempted.unwrap_err();
        assert_eq!(error.code, SessionErrorCode::ImportFailed);
        assert!(error.message.contains("unexpectedly"));
        let bytes = manager
            .publish_completed("case-A", started.session_id, |capture| {
                Ok::<_, String>(capture.pcap_bytes.clone())
            })
            .unwrap();
        assert_eq!(&bytes[40..], sample_frame());
        assert_eq!(
            manager.status("case-A", started.session_id).unwrap().phase,
            Phase::Completed
        );
        manager.revoke("case-A", started.session_id).unwrap();
    }

    #[test]
    fn status_and_stop_remain_responsive_while_evidence_publisher_is_blocked() {
        let manager = Arc::new(CaptureSessionManager::new());
        let run = manager
            .start_with("case-A", "fixture0", |cancel, _| Ok(result(&cancel)))
            .unwrap();
        until(&manager, "case-A", run.session_id, Phase::Completed);
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let publishing = Arc::clone(&manager);
        let publisher = std::thread::spawn(move || {
            publishing.publish_completed("case-A", run.session_id, |capture| {
                entered_tx.send(capture.pcap_bytes.len()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                Ok::<_, String>(capture.pcap_bytes.len())
            })
        });
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let (status_tx, status_rx) = mpsc::channel();
        let checking = Arc::clone(&manager);
        let reader = std::thread::spawn(move || {
            status_tx
                .send((
                    checking.status("case-A", run.session_id),
                    checking.stop("case-A", run.session_id),
                ))
                .unwrap();
        });
        let responsiveness = status_rx.recv_timeout(Duration::from_millis(400));
        release_tx.send(()).unwrap();
        let completed = publisher.join().unwrap().unwrap();
        reader.join().unwrap();
        let (status, stop) = responsiveness.expect("status and stop blocked by storage callback");
        assert_eq!(status.unwrap().phase, Phase::Completed);
        assert_eq!(stop.unwrap().phase, Phase::Completed);
        assert!(completed > 24);
    }

    #[test]
    fn cross_case_or_revoked_publish_is_denied_before_callback() {
        let manager = CaptureSessionManager::new();
        let run = manager
            .start_with("case-A", "fixture0", |cancel, _| Ok(result(&cancel)))
            .unwrap();
        until(&manager, "case-A", run.session_id, Phase::Completed);
        assert_eq!(
            manager
                .publish_completed("case-B", run.session_id, |_| {
                    panic!("wrong case must never receive bytes");
                    #[allow(unreachable_code)]
                    Ok::<(), String>(())
                })
                .unwrap_err()
                .code,
            SessionErrorCode::UnauthorizedSession,
        );
        manager.revoke("case-A", run.session_id).unwrap();
        assert_eq!(
            manager
                .publish_completed("case-A", run.session_id, |_| {
                    panic!("revoked case must never receive bytes");
                    #[allow(unreachable_code)]
                    Ok::<(), String>(())
                })
                .unwrap_err()
                .code,
            SessionErrorCode::UnauthorizedSession,
        );
    }

    #[test]
    fn case_revocation_serializes_with_authorized_import_publication() {
        let manager = Arc::new(CaptureSessionManager::new());
        let run = manager
            .start_with("case-A", "fixture0", |cancel, _| Ok(result(&cancel)))
            .unwrap();
        until(&manager, "case-A", run.session_id, Phase::Completed);
        let (inside_tx, inside_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let publisher_manager = Arc::clone(&manager);
        let publisher = std::thread::spawn(move || {
            publisher_manager.publish_completed("case-A", run.session_id, |result| {
                inside_tx.send(result.pcap_bytes.len()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                Ok::<_, String>(result.pcap_bytes.len())
            })
        });
        assert!(inside_rx.recv_timeout(Duration::from_secs(2)).unwrap() > 24);
        let (attempt_tx, attempt_rx) = mpsc::channel();
        let (revoked_tx, revoked_rx) = mpsc::channel();
        let revoke_manager = Arc::clone(&manager);
        let revoker = std::thread::spawn(move || {
            attempt_tx.send(()).unwrap();
            let outcome = revoke_manager.revoke("case-A", run.session_id);
            revoked_tx.send(outcome).unwrap();
        });
        attempt_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        // The callback currently holds the session's publication/revocation
        // gate, so a revocation cannot complete until the callback returns.
        assert!(matches!(
            revoked_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        release_tx.send(()).unwrap();
        assert!(publisher.join().unwrap().unwrap() > 24);
        revoked_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        revoker.join().unwrap();
        assert_eq!(
            manager.status("case-A", run.session_id).unwrap_err().code,
            SessionErrorCode::UnauthorizedSession
        );
    }

    #[test]
    fn shutdown_waits_for_inflight_publication_then_denies_new_commit() {
        let manager = Arc::new(CaptureSessionManager::new());
        let started = manager
            .start_with("case-A", "fixture0", |stop, _| Ok(result(&stop)))
            .unwrap();
        until(&manager, "case-A", started.session_id, Phase::Completed);

        let (publishing_tx, publishing_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let owned = Arc::clone(&manager);
        let publisher = std::thread::spawn(move || {
            owned.publish_completed("case-A", started.session_id, |result| {
                publishing_tx.send(result.pcap_bytes.len()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(2)).unwrap();
                Ok::<_, String>(result.pcap_bytes.len())
            })
        });
        publishing_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        let (shutting_down_tx, shutting_down_rx) = mpsc::channel();
        let (shutdown_done_tx, shutdown_done_rx) = mpsc::channel();
        let shutting_down = Arc::clone(&manager);
        let joiner = std::thread::spawn(move || {
            shutting_down_tx.send(()).unwrap();
            shutting_down.shutdown();
            shutdown_done_tx.send(()).unwrap();
        });
        shutting_down_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        // A running publisher holds the publication gate, so shutdown must
        // not finish before that already-authorized publication returns.
        assert!(matches!(
            shutdown_done_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        release_tx.send(()).unwrap();
        assert!(publisher.join().unwrap().unwrap() > 24);
        shutdown_done_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap();
        joiner.join().unwrap();
        assert_eq!(
            manager
                .publish_completed("case-A", started.session_id, |_| {
                    panic!("commit after shutdown");
                    #[allow(unreachable_code)]
                    Ok::<(), String>(())
                })
                .unwrap_err()
                .code,
            SessionErrorCode::NotReady,
        );
    }

    #[test]
    fn shutdown_rejects_new_workers_and_publications_after_return() {
        let manager = CaptureSessionManager::new();
        let first = manager
            .start_with("case-A", "fixture0", |stop, _| Ok(result(&stop)))
            .unwrap();
        until(&manager, "case-A", first.session_id, Phase::Completed);
        manager.shutdown();
        assert_eq!(
            manager
                .completed_for_case("case-A", first.session_id)
                .unwrap_err()
                .code,
            SessionErrorCode::UnauthorizedSession,
            "shutdown must revoke completed confidential capture bytes",
        );
        let published = manager.publish_completed("case-A", first.session_id, |_original| {
            panic!("shutdown must prevent evidence publication");
            #[allow(unreachable_code)]
            Ok::<(), String>(())
        });
        assert_eq!(published.unwrap_err().code, SessionErrorCode::NotReady);
        let attempted = manager.start_with("case-A", "fixture0", |_, _| {
            panic!("shutdown must prevent spawning a capture worker");
        });
        assert_eq!(attempted.unwrap_err().code, SessionErrorCode::NotReady);
        manager.shutdown();
    }

    #[test]
    fn invalid_cases_do_not_spawn_workers() {
        let manager = CaptureSessionManager::new();
        assert_eq!(
            manager
                .start_with("", "eth0", |_, _| panic!("should not run"))
                .unwrap_err()
                .code,
            SessionErrorCode::InvalidCase
        );
        assert_eq!(
            manager.status("x", 99).unwrap_err().code,
            SessionErrorCode::UnauthorizedSession
        );
    }
}
