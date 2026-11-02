//! Bounded concurrent connect scanner. This service accepts a progress sink
//! rather than depending on Tauri Channels or application state.
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use super::scan_timing::HostProbeBudget;
use super::tcp_probe::probe_observation_timed;
use super::udp_probe::probe_udp_observation_timed;

/// Native scan protocol; the original seven netscan commands remain TCP-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ScanTransport {
    Tcp,
    Udp,
}
use super::{ScanEntry, ScanObservation, ScanProgress};

const MAX_RESULTS: usize = 20_000;
/// Avoid flooding a single target when many ports are queued.
const MAX_HOST_INFLIGHT: usize = 4;

struct HostSlot<'a>(&'a AtomicUsize);
impl Drop for HostSlot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}

fn try_host_slot(active: &AtomicUsize) -> Option<HostSlot<'_>> {
    let mut old = active.load(Ordering::Acquire);
    loop {
        if old >= MAX_HOST_INFLIGHT {
            return None;
        }
        match active.compare_exchange_weak(old, old + 1, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Some(HostSlot(active)),
            Err(updated) => old = updated,
        }
    }
}

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
    run_scan_into_scoped(hosts, ports, stop, on_progress, results, &|| true)
}

/// Each native probe independently checks the backend selected case generation.
/// Revocation causes Stop and suppresses results, even between progress events.
pub(super) fn run_scan_into_scoped(
    hosts: Vec<IpAddr>,
    ports: Vec<u16>,
    stop: &AtomicBool,
    on_progress: &(impl Fn(ScanProgress) + Sync),
    results: &Arc<StdMutex<Vec<ScanEntry>>>,
    scope_is_active: &(impl Fn() -> bool + Sync),
) -> Vec<ScanEntry> {
    run_scan_into_scoped_v1(
        hosts,
        ports,
        stop,
        on_progress,
        results,
        scope_is_active,
        &|_| {},
    )
}

/// Observe every completed TCP connect attempt, not only open-port results.
/// Callbacks receive bounded, independently observed state and reason records.
pub(super) fn run_scan_into_scoped_v1(
    hosts: Vec<IpAddr>,
    ports: Vec<u16>,
    stop: &AtomicBool,
    on_progress: &(impl Fn(ScanProgress) + Sync),
    results: &Arc<StdMutex<Vec<ScanEntry>>>,
    scope_is_active: &(impl Fn() -> bool + Sync),
    on_observation: &(impl Fn(ScanObservation) + Sync),
) -> Vec<ScanEntry> {
    run_scan_into_scoped_transport(
        ScanTransport::Tcp,
        hosts,
        ports,
        stop,
        on_progress,
        results,
        scope_is_active,
        on_observation,
    )
}

/// UDP uses the same bounded worker/case-revision/cancellation pipeline but
/// publishes typed observations rather than altering legacy open-TCP results.
pub(super) fn run_scan_into_scoped_transport(
    transport: ScanTransport,
    hosts: Vec<IpAddr>,
    ports: Vec<u16>,
    stop: &AtomicBool,
    on_progress: &(impl Fn(ScanProgress) + Sync),
    results: &Arc<StdMutex<Vec<ScanEntry>>>,
    scope_is_active: &(impl Fn() -> bool + Sync),
    on_observation: &(impl Fn(ScanObservation) + Sync),
) -> Vec<ScanEntry> {
    let total = (hosts.len() as u64).saturating_mul(ports.len() as u64);
    if total == 0 || total > MAX_SCAN_PROBES {
        return Vec::new();
    }

    // Per-host timing state is private to this authorized, bounded scan.
    let timing: Vec<_> = (0..hosts.len())
        .map(|_| StdMutex::new(HostProbeBudget::new(transport)))
        .collect();
    let host_slots: Vec<_> = (0..hosts.len()).map(|_| AtomicUsize::new(0)).collect();
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
            let timing = &timing;
            let host_slots = &host_slots;
            scope.spawn(move || loop {
                if stop.load(Ordering::Acquire) || !scope_is_active() {
                    stop.store(true, Ordering::Release);
                    break;
                }
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= total {
                    break;
                }
                let offset = index as usize;
                // Spread adjacent work across hosts to avoid host bursts.
                let host = hosts[offset % hosts.len()];
                let port = ports[offset / hosts.len()];
                if stop.load(Ordering::Acquire) || !scope_is_active() {
                    stop.store(true, Ordering::Release);
                    break;
                }
                let host_index = offset % hosts.len();
                // Held through any retry and released automatically on all
                // break/return paths, including case revocation.
                let slot = loop {
                    if stop.load(Ordering::Acquire) || !scope_is_active() {
                        stop.store(true, Ordering::Release);
                        break None;
                    }
                    if let Some(slot) = try_host_slot(&host_slots[host_index]) {
                        break Some(slot);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                };
                let Some(_slot) = slot else { break };
                let timeout = timing[host_index]
                    .lock()
                    .expect("host timing poisoned")
                    .timeout();
                let mut observation = match transport {
                    ScanTransport::Tcp => probe_observation_timed(host, port, timeout),
                    ScanTransport::Udp => probe_udp_observation_timed(host, port, timeout),
                };
                if stop.load(Ordering::Acquire) || !scope_is_active() {
                    stop.store(true, Ordering::Release);
                    break;
                }
                if HostProbeBudget::should_retry(&observation) {
                    let retry_timeout = {
                        let mut stats = timing[host_index].lock().expect("host timing poisoned");
                        stats.note_silence();
                        stats.timeout()
                    };
                    let retry_pause = HostProbeBudget::retry_pause();
                    std::thread::sleep(retry_pause);
                    if stop.load(Ordering::Acquire) || !scope_is_active() {
                        stop.store(true, Ordering::Release);
                        break;
                    }
                    let mut retried = match transport {
                        ScanTransport::Tcp => probe_observation_timed(host, port, retry_timeout),
                        ScanTransport::Udp => {
                            probe_udp_observation_timed(host, port, retry_timeout)
                        }
                    };
                    if stop.load(Ordering::Acquire) || !scope_is_active() {
                        stop.store(true, Ordering::Release);
                        break;
                    }
                    let response_elapsed = retried.elapsed_ms;
                    retried.elapsed_ms = retried
                        .elapsed_ms
                        .saturating_add(observation.elapsed_ms)
                        .saturating_add(retry_pause.as_millis() as u64);
                    retried.started_at_ms = observation.started_at_ms;
                    retried.attempts = 2;
                    retried.retries = 1;
                    let mut stats = timing[host_index].lock().expect("host timing poisoned");
                    if matches!(retried.state.as_str(), "open" | "closed") {
                        stats.note_response(response_elapsed);
                    } else if HostProbeBudget::should_retry(&retried) {
                        stats.note_silence();
                    }
                    observation = retried;
                } else {
                    timing[host_index]
                        .lock()
                        .expect("host timing poisoned")
                        .note_final(&observation);
                }
                // Callback owns the bounded case-scoped store. The underlying
                // original status is never changed by service-name inference.
                if transport == ScanTransport::Tcp && observation.state == "open" {
                    let mut output = results.lock().expect("scan results poisoned");
                    if output.len() >= MAX_RESULTS {
                        stop.store(true, Ordering::Relaxed);
                    } else {
                        output.push(ScanEntry {
                            host: observation.host.clone(),
                            port,
                            state: observation.state.clone(),
                            service: observation.service.clone(),
                            banner: observation.banner.clone(),
                        });
                    }
                }
                on_observation(observation);
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
    fn concurrent_host_slot_is_bounded_and_released_after_drop() {
        let slots = AtomicUsize::new(0);
        let held: Vec<_> = (0..MAX_HOST_INFLIGHT)
            .map(|_| try_host_slot(&slots).expect("slot available"))
            .collect();
        assert_eq!(slots.load(Ordering::Acquire), MAX_HOST_INFLIGHT);
        assert!(try_host_slot(&slots).is_none());
        drop(held);
        assert_eq!(slots.load(Ordering::Acquire), 0);
        assert!(try_host_slot(&slots).is_some());
    }

    #[test]
    fn round_robin_work_plan_covers_every_host_port_pair() {
        let hosts = ["192.0.2.1", "192.0.2.2", "192.0.2.3"];
        let ports = [22, 80, 443];
        let planned: Vec<_> = (0..(hosts.len() * ports.len()))
            .map(|i| (hosts[i % hosts.len()], ports[i / hosts.len()]))
            .collect();
        assert_eq!(
            &planned[..3],
            &[("192.0.2.1", 22), ("192.0.2.2", 22), ("192.0.2.3", 22)]
        );
        for host in hosts {
            for port in ports {
                assert_eq!(
                    planned
                        .iter()
                        .filter(|(h, p)| *h == host && *p == port)
                        .count(),
                    1
                );
            }
        }
    }

    #[test]
    fn confirmed_loopback_connection_stays_a_single_attempt() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let observed = StdMutex::new(Vec::<ScanObservation>::new());
        let stop = AtomicBool::new(false);
        let results = Arc::new(StdMutex::new(Vec::new()));
        run_scan_into_scoped_v1(
            vec!["127.0.0.1".parse().unwrap()],
            vec![port],
            &stop,
            &|_| {},
            &results,
            &|| true,
            &|record| observed.lock().unwrap().push(record),
        );
        let rows = observed.lock().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].state, "open");
        assert_eq!(rows[0].attempts, 1);
        assert_eq!(rows[0].retries, 0);
        assert_eq!(results.lock().unwrap().len(), 1);
    }

    #[test]
    fn udp_worker_respects_revoked_case_without_sending_datagrams() {
        let stop = AtomicBool::new(false);
        let results = Arc::new(StdMutex::new(Vec::new()));
        let observations = StdMutex::new(Vec::new());
        let output = run_scan_into_scoped_transport(
            ScanTransport::Udp,
            vec!["127.0.0.1".parse().unwrap()],
            vec![53],
            &stop,
            &|_| {},
            &results,
            &|| false,
            &|obs| observations.lock().unwrap().push(obs),
        );
        assert!(output.is_empty());
        assert!(observations.lock().unwrap().is_empty());
        assert!(stop.load(Ordering::Acquire));
    }

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
    fn scope_revocation_prevents_any_probe_or_persisted_result() {
        let stop = AtomicBool::new(false);
        let results = Arc::new(StdMutex::new(Vec::new()));
        let seen = AtomicU64::new(0);
        let output = run_scan_into_scoped(
            vec!["127.0.0.1".parse().unwrap()],
            vec![22, 80, 443],
            &stop,
            &|_| {},
            &results,
            &|| {
                seen.fetch_add(1, Ordering::Relaxed);
                false
            },
        );
        assert!(output.is_empty());
        assert!(results.lock().unwrap().is_empty());
        assert_eq!(seen.load(Ordering::Relaxed), 1);
        assert!(stop.load(Ordering::Acquire));
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
