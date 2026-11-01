//! Scan session lifecycle, cancellation and progress (no Tauri dependency).
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use super::scan_service::{self, ScanTransport};
use super::{ScanCtx, ScanEntry, ScanHistoryItem, ScanObservation, ScanProgress};
use crate::features::shared::session::CaseSessionWire;

pub(super) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Start a bounded worker and update observable state. All persistence uses a
/// callback port: only the infrastructure adapter knows about the case store.
pub(super) fn start<P, G, F>(
    ctx: &ScanCtx,
    scope: CaseSessionWire,
    hosts: Vec<IpAddr>,
    port_list: Vec<u16>,
    targets: String,
    ports: String,
    on_progress: P,
    scope_is_active: G,
    save_findings: F,
) -> Result<u64, String>
where
    P: Fn(ScanProgress) + Sync + Send + 'static,
    G: Fn() -> bool + Sync + Send + 'static,
    F: FnOnce(u64, &[ScanEntry], &[ScanObservation]) -> Result<usize, String> + Send + 'static,
{
    start_with_transport(
        ctx,
        ScanTransport::Tcp,
        scope,
        hosts,
        port_list,
        targets,
        ports,
        on_progress,
        scope_is_active,
        save_findings,
    )
}

/// Additive transport selection. Existing callers keep start() TCP semantics.
pub(super) fn start_with_transport<P, G, F>(
    ctx: &ScanCtx,
    transport: ScanTransport,
    scope: CaseSessionWire,
    hosts: Vec<IpAddr>,
    port_list: Vec<u16>,
    targets: String,
    ports: String,
    on_progress: P,
    scope_is_active: G,
    save_findings: F,
) -> Result<u64, String>
where
    P: Fn(ScanProgress) + Sync + Send + 'static,
    G: Fn() -> bool + Sync + Send + 'static,
    F: FnOnce(u64, &[ScanEntry], &[ScanObservation]) -> Result<usize, String> + Send + 'static,
{
    let host_count = hosts.len();
    scan_service::scan_probe_count(host_count, port_list.len())?;
    if ctx.running.swap(true, Ordering::AcqRel) {
        return Err("a scan is already running; stop it first".into());
    }

    {
        let mut active = ctx
            .active_scope
            .lock()
            .map_err(|_| "scan scope unavailable")?;
        if active.as_ref() != Some(&scope) {
            ctx.history
                .lock()
                .map_err(|_| "scan history unavailable")?
                .clear();
        }
        *active = Some(scope);
    }

    *ctx.last_save_error
        .lock()
        .expect("scan error state poisoned") = None;
    ctx.saved_findings.store(0, Ordering::Relaxed);
    ctx.stop.store(false, Ordering::Relaxed);
    ctx.results.lock().expect("scan results poisoned").clear();
    ctx.observations
        .lock()
        .expect("scan observations poisoned")
        .clear();

    let id = ctx.next_id.fetch_add(1, Ordering::Relaxed);
    let started = Instant::now();
    let results_out = Arc::clone(&ctx.results);
    let observed_out = Arc::clone(&ctx.observations);
    let stop_when_full = Arc::clone(&ctx.stop);
    let stop_out = Arc::clone(&ctx.stop);
    let running_out = Arc::clone(&ctx.running);
    let history_out = Arc::clone(&ctx.history);
    let save_error_out = Arc::clone(&ctx.last_save_error);
    let saved_out = Arc::clone(&ctx.saved_findings);

    std::thread::spawn(move || {
        let entries = scan_service::run_scan_into_scoped_transport(
            transport,
            hosts,
            port_list,
            &stop_out,
            &on_progress,
            &results_out,
            &scope_is_active,
            &|observed| {
                let mut data = observed_out.lock().expect("scan observations poisoned");
                if data.len() < 20_000 {
                    data.push(observed);
                } else {
                    stop_when_full.store(true, Ordering::Release);
                }
            },
        );
        let open = if transport == ScanTransport::Udp {
            observed_out
                .lock()
                .expect("scan observations poisoned")
                .iter()
                .filter(|observation| observation.state == "open")
                .count()
        } else {
            entries.len()
        };
        let duration = started.elapsed().as_millis() as u64;
        if !stop_out.load(Ordering::Acquire) && scope_is_active() {
            let observed = observed_out.lock().expect("scan observations poisoned");
            if !observed.is_empty() {
                match save_findings(id, &entries, &observed) {
                    Ok(count) => saved_out.store(count as u64, Ordering::Relaxed),
                    Err(error) => {
                        *save_error_out.lock().expect("scan error state poisoned") = Some(error);
                    }
                }
            }
        }
        // The workers already published and sorted the same shared results.
        // Avoid copying the entire set of open services back into that store.
        history_out
            .lock()
            .expect("scan history poisoned")
            .push(ScanHistoryItem {
                id,
                targets,
                ports,
                hosts_scanned: host_count,
                open_ports: open,
                duration_ms: duration,
                at_ms: now_ms(),
            });
        // Report completion only after the final history entry is visible.
        running_out.store(false, Ordering::Release);
    });
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::channel;
    use std::time::Duration;

    #[test]
    fn revoked_case_scan_never_invokes_durable_findings_callback() {
        let ctx = ScanCtx::default();
        let (tx, rx) = channel();
        let _id = start(
            &ctx,
            CaseSessionWire {
                case_id: Some("case-a".into()),
                revision: 1,
            },
            vec!["127.0.0.1".parse().unwrap()],
            vec![65000],
            "127.0.0.1".into(),
            "65000".into(),
            |_| {},
            || false,
            move |_, _, _| {
                tx.send(()).unwrap();
                Ok(1)
            },
        )
        .unwrap();
        for _ in 0..100 {
            if !ctx.running.load(Ordering::Acquire) {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(!ctx.running.load(Ordering::Acquire));
        assert!(ctx.stop.load(Ordering::Acquire));
        assert!(ctx.results.lock().unwrap().is_empty());
        assert!(
            rx.try_recv().is_err(),
            "revoked scan must not save findings"
        );
    }

    #[test]
    fn empty_scan_closes_session_and_records_history() {
        let ctx = ScanCtx::default();
        let (tx, rx) = channel();
        let id = start(
            &ctx,
            CaseSessionWire {
                case_id: Some("test-case".into()),
                revision: 1,
            },
            vec![],
            vec![80],
            "127.0.0.1".into(),
            "80".into(),
            |_| {},
            || true,
            move |_, _, _| {
                tx.send(()).unwrap();
                Ok(0)
            },
        )
        .unwrap();
        assert_eq!(id, 1);
        for _ in 0..100 {
            if !ctx.running.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(!ctx.running.load(Ordering::Relaxed));
        assert_eq!(ctx.history.lock().unwrap().len(), 1);
        assert_eq!(ctx.history.lock().unwrap()[0].open_ports, 0);
        // No findings are persisted for an empty scan.
        assert!(rx.try_recv().is_err());
    }
}
