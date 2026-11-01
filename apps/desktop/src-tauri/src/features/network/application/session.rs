//! Scan session lifecycle, cancellation and progress (no Tauri dependency).
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use super::scan_service;
use super::{ScanCtx, ScanEntry, ScanHistoryItem, ScanProgress};
use crate::features::shared::session::CaseSessionWire;

pub(super) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Start a bounded worker and update observable state. All persistence uses a
/// callback port: only the infrastructure adapter knows about the case store.
pub(super) fn start<P, F>(
    ctx: &ScanCtx,
    scope: CaseSessionWire,
    hosts: Vec<IpAddr>,
    port_list: Vec<u16>,
    targets: String,
    ports: String,
    on_progress: P,
    save_findings: F,
) -> Result<u64, String>
where
    P: Fn(ScanProgress) + Sync + Send + 'static,
    F: FnOnce(u64, &[ScanEntry]) -> Result<usize, String> + Send + 'static,
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

    let id = ctx.next_id.fetch_add(1, Ordering::Relaxed);
    let started = Instant::now();
    let results_out = Arc::clone(&ctx.results);
    let stop_out = Arc::clone(&ctx.stop);
    let running_out = Arc::clone(&ctx.running);
    let history_out = Arc::clone(&ctx.history);
    let save_error_out = Arc::clone(&ctx.last_save_error);
    let saved_out = Arc::clone(&ctx.saved_findings);

    std::thread::spawn(move || {
        let entries =
            scan_service::run_scan_into(hosts, port_list, &stop_out, &on_progress, &results_out);
        let open = entries.len();
        let duration = started.elapsed().as_millis() as u64;
        if !entries.is_empty() {
            match save_findings(id, &entries) {
                Ok(count) => saved_out.store(count as u64, Ordering::Relaxed),
                Err(error) => {
                    *save_error_out.lock().expect("scan error state poisoned") = Some(error);
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
            move |_, _| {
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
