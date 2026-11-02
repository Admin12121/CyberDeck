//! Authorization-scoped native TCP host discovery. Connection refusals are
//! positive host-response evidence, but silence is not proof of a host down.
//! The legacy IPC preserves its Vec<String> return; the caller enforces the
//! authoritative backend case revision before and after this worker pool.
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const DISCOVERY_PORTS: &[u16] = &[80, 443, 22, 445, 3389];
pub(super) const MAX_DISCOVERY_HOSTS: usize = 512;
const DISCOVERY_DEADLINE: Duration = Duration::from_secs(30);
const CONNECT_BUDGET: Duration = Duration::from_millis(500);
const MAX_WORKERS: usize = 12;

fn refusal_is_response(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::ConnectionRefused
}

/// Bounded work and native-case cancellation between each attempted port.
/// The caller rechecks the selected revision after the worker pool completes,
/// so a late response can never be returned to another case.
pub(super) fn responding_hosts_scoped(
    hosts: Vec<IpAddr>,
    scope_is_active: &(impl Fn() -> bool + Sync),
) -> Result<Vec<String>, String> {
    if hosts.len() > MAX_DISCOVERY_HOSTS {
        return Err(format!(
            "discovery accepts up to {MAX_DISCOVERY_HOSTS} hosts per run"
        ));
    }
    if hosts.is_empty() {
        return Ok(Vec::new());
    }
    let started = Instant::now();
    let next = AtomicUsize::new(0);
    let found = Mutex::new(Vec::<IpAddr>::new());
    let workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, MAX_WORKERS)
        .min(hosts.len());

    std::thread::scope(|scope| {
        for _ in 0..workers {
            let found = &found;
            let next = &next;
            let hosts = &hosts;
            scope.spawn(move || loop {
                if !scope_is_active() || started.elapsed() >= DISCOVERY_DEADLINE {
                    break;
                }
                let index = next.fetch_add(1, Ordering::Relaxed);
                let Some(&host) = hosts.get(index) else { break };
                let mut alive = false;
                for port in DISCOVERY_PORTS {
                    if !scope_is_active() {
                        break;
                    }
                    let remain = DISCOVERY_DEADLINE.saturating_sub(started.elapsed());
                    if remain.is_zero() {
                        break;
                    }
                    let timeout = remain.min(CONNECT_BUDGET);
                    let reply = TcpStream::connect_timeout(&SocketAddr::new(host, *port), timeout);
                    if match reply {
                        Ok(_) => true,
                        Err(ref error) => refusal_is_response(error),
                    } {
                        alive = true;
                        break;
                    }
                }
                if alive && scope_is_active() {
                    found
                        .lock()
                        .expect("discovery host list poisoned")
                        .push(host);
                }
            });
        }
    });
    if !scope_is_active() {
        return Err("discovery cancelled or selected case revision changed".into());
    }
    let mut hosts = found
        .into_inner()
        .map_err(|_| "discovery results unavailable")?;
    hosts.sort_unstable();
    hosts.dedup();
    Ok(hosts.into_iter().map(|host| host.to_string()).collect())
}

/// Preserve the existing unscoped internal helper for callers and tests.
pub(super) fn responding_hosts(hosts: Vec<IpAddr>) -> Vec<String> {
    responding_hosts_scoped(hosts, &|| true).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn tcp_refusal_is_a_response_but_timeout_is_not() {
        use std::io::{Error, ErrorKind};
        assert!(refusal_is_response(&Error::from(
            ErrorKind::ConnectionRefused
        )));
        assert!(!refusal_is_response(&Error::from(ErrorKind::TimedOut)));
        assert!(!refusal_is_response(&Error::from(
            ErrorKind::NetworkUnreachable
        )));
    }

    #[test]
    fn no_targets_produces_no_discovery() {
        assert!(responding_hosts(Vec::new()).is_empty());
    }

    #[test]
    fn discovery_rejects_large_scope_without_network_work() {
        assert!(
            responding_hosts_scoped(vec!["127.0.0.1".parse().unwrap(); 513], &|| true).is_err()
        );
    }

    #[test]
    fn revoked_discovery_never_probes_hosts_or_returns_results() {
        let checked = AtomicUsize::new(0);
        let hosts = vec!["127.0.0.1".parse().unwrap()];
        let result = responding_hosts_scoped(hosts, &|| {
            checked.fetch_add(1, Ordering::Relaxed);
            false
        });
        assert!(result.is_err());
        assert!(checked.load(Ordering::Relaxed) >= 1);
    }
}
