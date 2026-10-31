//! Bounded concurrent connect scanner. This service accepts a progress sink
//! rather than depending on Tauri Channels or application state.
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use super::tcp_probe::{probe, well_known_service};
use super::{ScanEntry, ScanProgress};

const MAX_RESULTS: usize = 20_000;

/// Bound scan plans rather than allocating millions of pending host/port jobs.
const MAX_SCAN_PROBES: u64 = 250_000;

pub(super) fn scan_probe_count(host_count: usize, port_count: usize) -> Result<u64, String> {
    let count = (host_count as u64)
        .checked_mul(port_count as u64)
        .ok_or("scan target count overflow")?;
    if count > MAX_SCAN_PROBES {
        return Err(format!(
            "{count} probes exceed the per-run limit of {MAX_SCAN_PROBES}; split the scan into smaller scopes"
        ));
    }
    Ok(count)
}

fn report_progress(
    on_progress: &(impl Fn(ScanProgress) + Sync),
    reported: &StdMutex<u64>,
    tried: u64,
    total: u64,
) {
    let mut last = reported.lock().expect("scan progress poisoned");
    if tried > *last {
        *last = tried;
        on_progress(ScanProgress {
            tried,
            total,
            percent: (tried * 100 / total.max(1)) as u32,
        });
    }
}

/// A bounded pool claims indexes without materializing the full host x port
/// matrix. Open results are published as they arrive, not only at completion.
pub(super) fn run_scan_into(
    hosts: Vec<IpAddr>,
    ports: Vec<u16>,
    stop: &AtomicBool,
    on_progress: &(impl Fn(ScanProgress) + Sync),
    results: &Arc<StdMutex<Vec<ScanEntry>>>,
) -> Vec<ScanEntry> {
    let total = (hosts.len() as u64).saturating_mul(ports.len() as u64);
    if total == 0 || total > MAX_SCAN_PROBES {
        return Vec::new();
    }

    let next = AtomicU64::new(0);
    let completed = AtomicU64::new(0);
    let reported = StdMutex::new(0u64);
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 32)
        .min(total as usize);

    std::thread::scope(|scope| {
        for _ in 0..workers {
            let results = Arc::clone(results);
            let next = &next;
            let completed = &completed;
            let reported = &reported;
            let hosts = &hosts;
            let ports = &ports;
            scope.spawn(move || loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= total {
                    break;
                }
                let offset = index as usize;
                let host = hosts[offset / ports.len()];
                let port = ports[offset % ports.len()];
                let (state, banner) = probe(host, port);
                if state == "open" {
                    let mut output = results.lock().expect("scan results poisoned");
                    if output.len() >= MAX_RESULTS {
                        stop.store(true, Ordering::Relaxed);
                    } else {
                        let service = well_known_service(port);
                        output.push(ScanEntry {
                            host: host.to_string(),
                            port,
                            state,
                            service: if service.is_empty() {
                                "unknown".into()
                            } else {
                                service.into()
                            },
                            banner,
                        });
                    }
                }
                let tried = completed.fetch_add(1, Ordering::Relaxed) + 1;
                if tried % 32 == 0 || tried == total {
                    report_progress(on_progress, reported, tried, total);
                }
            });
        }
    });

    // Cancellation is not 100% completion; preserve the actual attempted count.
    report_progress(
        on_progress,
        &reported,
        completed.load(Ordering::Relaxed),
        total,
    );
    let mut final_results = results.lock().expect("scan results poisoned");
    final_results.sort_by(|a, b| a.host.cmp(&b.host).then(a.port.cmp(&b.port)));
    final_results.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_prevents_tcp_connect_attempts_and_false_completion() {
        let stop = AtomicBool::new(true);
        let results = Arc::new(StdMutex::new(Vec::new()));
        let progress = StdMutex::new(Vec::new());
        let sink = |item: ScanProgress| progress.lock().unwrap().push(item);
        let scanned = run_scan_into(
            vec!["127.0.0.1".parse().unwrap()],
            vec![1, 2, 3],
            &stop,
            &sink,
            &results,
        );
        assert!(scanned.is_empty());
        assert!(results.lock().unwrap().is_empty());
        assert!(progress.lock().unwrap().is_empty());
    }

    #[test]
    fn progress_only_reports_new_attempt_counts_and_correct_percentages() {
        let reported = StdMutex::new(0u64);
        let history = StdMutex::new(Vec::new());
        let sink = |progress: ScanProgress| history.lock().unwrap().push(progress);
        report_progress(&sink, &reported, 10, 100);
        report_progress(&sink, &reported, 8, 100);
        report_progress(&sink, &reported, 10, 100);
        report_progress(&sink, &reported, 25, 100);
        let history = history.lock().unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!((history[0].tried, history[0].percent), (10, 10));
        assert_eq!((history[1].tried, history[1].percent), (25, 25));
        assert!(history.iter().all(|item| item.total == 100));
    }
}
