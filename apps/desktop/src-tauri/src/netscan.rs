//! Native TCP connect scanner (§5.3): hosts/CIDR resolution, port presets or
//! ranges, connect attempts across all cores, banner grabbing on open ports.
//! Original code — external engines add depth later. Runs require an explicit
//! authorization acknowledgment from the UI (§9.3).

use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};

use crate::evidence::EvidenceCtx;
use cyberdeck_storage::NewFinding;
use serde::Serialize;
use tauri::ipc::Channel;
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::DialogExt;

const CONNECT_TIMEOUT: Duration = Duration::from_millis(900);
const BANNER_TIMEOUT: Duration = Duration::from_millis(400);
const MAX_HOSTS: usize = 4096;
const MAX_PORTS: usize = 1024;
const MAX_RESULTS: usize = 20_000;

#[derive(Debug, Clone, Serialize)]
pub struct ScanEntry {
    pub host: String,
    pub port: u16,
    pub state: String,
    pub service: String,
    pub banner: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanProgress {
    pub tried: u64,
    pub total: u64,
    pub percent: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanHistoryItem {
    pub id: u64,
    pub targets: String,
    pub ports: String,
    pub hosts_scanned: usize,
    pub open_ports: usize,
    pub duration_ms: u64,
    pub at_ms: u64,
}

/// Shared scan state: results stream in from the worker thread while the UI
/// polls; history persists per session.
pub struct ScanCtx {
    pub results: Arc<StdMutex<Vec<ScanEntry>>>,
    pub running: Arc<AtomicBool>,
    pub stop: Arc<AtomicBool>,
    pub history: Arc<StdMutex<Vec<ScanHistoryItem>>>,
    pub next_id: Arc<AtomicU64>,
    pub last_save_error: Arc<StdMutex<Option<String>>>,
    pub saved_findings: Arc<AtomicU64>,
}

impl Default for ScanCtx {
    fn default() -> Self {
        Self {
            results: Arc::new(StdMutex::new(Vec::new())),
            running: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(AtomicBool::new(false)),
            history: Arc::new(StdMutex::new(Vec::new())),
            next_id: Arc::new(AtomicU64::new(1)),
            last_save_error: Arc::new(StdMutex::new(None)),
            saved_findings: Arc::new(AtomicU64::new(0)),
        }
    }
}

/// Curated CyberDeck TCP port preset, not Nmap's popularity-ranked port list.
pub const TOP_PORTS_100: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
    8443, 67, 69, 123, 161, 389, 636, 1080, 1433, 1521, 2049, 2121, 3128, 3268, 4444, 554, 5432, 5555, 6379, 8000,
    8008, 8081, 8888, 9000, 9090, 9200, 10000, 27017, 50000, 5985, 1, 7, 9, 13, 17, 19, 20, 26, 37, 42,
    43, 49, 70, 79, 81, 88, 102, 106, 109, 113, 119, 137, 138, 179, 194, 199, 264, 427, 465, 500,
    512, 513, 514, 515, 524, 548, 563, 587, 593, 623, 631, 873, 902, 989, 990, 992, 1194, 1883, 2375, 5060,
];

/// Expand target spec: single IP, hostname, CIDR (IPv4 /24-/32), comma lists.
pub fn parse_targets(spec: &str) -> Result<Vec<IpAddr>, String> {
    let mut hosts = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((ip_str, mask_str)) = part.split_once('/') {
            let ip: IpAddr = ip_str
                .parse()
                .map_err(|_| format!("bad address in target: {ip_str}"))?;
            let mask: u8 = mask_str
                .parse()
                .map_err(|_| format!("bad mask: {mask_str}"))?;
            match ip {
                IpAddr::V4(v4) => {
                    if mask > 32 {
                        return Err(format!("bad IPv4 mask: /{mask}"));
                    }
                    let bits = u32::from(v4);
                    let suffix = 32u32.saturating_sub(mask as u32);
                    let count = 1u64 << suffix;
                    // The /0 size check must run before shifting by 32 bits.
                    if count > MAX_HOSTS as u64 {
                        return Err(format!(
                            "/{mask} expands to {count} hosts; the cap is {MAX_HOSTS}"
                        ));
                    }
                    let base = bits & u32::MAX.checked_shl(suffix).unwrap_or(0);
                    for i in 0..count {
                        hosts.push(IpAddr::V4(std::net::Ipv4Addr::from(base + i as u32)));
                    }
                }
                IpAddr::V6(_) => return Err("IPv6 CIDR targets arrive in a later arc".to_string()),
            }
        } else if let Ok(ip) = part.parse::<IpAddr>() {
            hosts.push(ip);
        } else {
            let resolved = (part, 0u16)
                .to_socket_addrs()
                .map_err(|e| format!("cannot resolve {part}: {e}"))?
                .map(|a| a.ip())
                .take(4)
                .collect::<Vec<_>>();
            if resolved.is_empty() {
                return Err(format!("cannot resolve {part}"));
            }
            hosts.extend(resolved);
        }
        if hosts.len() > MAX_HOSTS {
            return Err(format!(
                "target expands past {MAX_HOSTS} hosts; narrow the scope"
            ));
        }
    }
    if hosts.is_empty() {
        return Err("no targets parsed".to_string());
    }
    hosts.sort_unstable();
    hosts.dedup();
    Ok(hosts)
}

/// Port spec: "top25", "top100", "1-1024", or explicit "80,443,8000-8100".
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    let spec = spec.trim().to_lowercase();
    let mut ports: Vec<u16> = Vec::new();
    let push_range = |ports: &mut Vec<u16>, start: u16, end: u16| {
        for p in start..=end {
            ports.push(p);
        }
    };
    match spec.as_str() {
        "top25" => ports.extend_from_slice(&TOP_PORTS_100[..25]),
        "top100" => ports.extend_from_slice(TOP_PORTS_100),
        "1-1024" | "wellknown" => push_range(&mut ports, 1, 1024),
        _ => {
            for part in spec.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                if let Some((a, b)) = part.split_once('-') {
                    let start: u16 = a.trim().parse().map_err(|_| format!("bad port: {a}"))?;
                    let end: u16 = b.trim().parse().map_err(|_| format!("bad port: {b}"))?;
                    if end < start || (end - start) as usize > MAX_PORTS {
                        return Err(format!("port range too large: {part}"));
                    }
                    push_range(&mut ports, start, end);
                } else {
                    let p: u16 = part.parse().map_err(|_| format!("bad port: {part}"))?;
                    ports.push(p);
                }
            }
        }
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        return Err("no ports parsed".to_string());
    }
    if ports.len() > MAX_PORTS {
        return Err(format!(
            "{} ports exceed the cap of {MAX_PORTS}",
            ports.len()
        ));
    }
    Ok(ports)
}

fn well_known_service(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "domain",
        80 => "http",
        110 => "pop3",
        143 => "imap",
        443 => "https",
        445 => "microsoft-ds",
        1433 => "ms-sql",
        3306 => "mysql",
        3389 => "ms-wbt",
        5432 => "postgresql",
        6379 => "redis",
        8080 => "http-proxy",
        8443 => "https-alt",
        9200 => "elasticsearch",
        27017 => "mongodb",
        _ => "",
    }
}

/// Condense a raw service banner to the informative first line / header.
fn summarize_banner(raw: &str) -> String {
    let first_line = raw.lines().next().unwrap_or("").trim().to_string();
    if first_line.to_lowercase().starts_with("http/") {
        let server = raw
            .lines()
            .find(|l| l.to_lowercase().starts_with("server:"))
            .map(|l| l.trim().to_string())
            .unwrap_or_default();
        if server.is_empty() {
            first_line
        } else {
            format!("{first_line} · {server}")
        }
    } else {
        first_line.chars().take(120).collect()
    }
}

/// Do not mistake a timeout for a refused TCP connection.
fn classify_connect_error(kind: std::io::ErrorKind) -> &'static str {
    use std::io::ErrorKind;
    match kind {
        ErrorKind::ConnectionRefused => "closed",
        ErrorKind::TimedOut | ErrorKind::WouldBlock => "no-response",
        ErrorKind::NetworkUnreachable | ErrorKind::HostUnreachable => "unreachable",
        _ => "unknown",
    }
}

/// Connect + optional banner grab for one host:port.
fn probe(host: IpAddr, port: u16) -> (String, String) {
    let addr = std::net::SocketAddr::new(host, port);
    match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
        Err(error) => (classify_connect_error(error.kind()).to_string(), String::new()),
        Ok(mut stream) => {
            let _ = stream.set_read_timeout(Some(BANNER_TIMEOUT));
            let _ = stream.set_write_timeout(Some(BANNER_TIMEOUT));
            let mut banner = String::new();
            // light service probes: HTTP HEAD on web ports, SSH announces itself
            if matches!(port, 80 | 8080 | 8000 | 8888) {
                let probe = format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
                let _ = std::io::Write::write_all(&mut stream, probe.as_bytes());
            }
            let mut buf = [0u8; 512];
            if let Ok(n) = std::io::Read::read(&mut stream, &mut buf) {
                if n > 0 {
                    banner = summarize_banner(&String::from_utf8_lossy(&buf[..n]));
                }
            }
            ("open".to_string(), banner)
        }
    }
}

/// Bound scan plans rather than allocating millions of pending host/port jobs.
const MAX_SCAN_PROBES: u64 = 250_000;

fn scan_probe_count(host_count: usize, port_count: usize) -> Result<u64, String> {
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
    on_progress: &Channel<ScanProgress>,
    reported: &StdMutex<u64>,
    tried: u64,
    total: u64,
) {
    let mut last = reported.lock().expect("scan progress poisoned");
    if tried > *last {
        *last = tried;
        let _ = on_progress.send(ScanProgress {
            tried,
            total,
            percent: (tried * 100 / total.max(1)) as u32,
        });
    }
}

/// Backward-compatible API for internal callers not tracking live scan state.
pub fn run_scan(
    hosts: Vec<IpAddr>,
    ports: Vec<u16>,
    stop: &AtomicBool,
    on_progress: &Channel<ScanProgress>,
) -> Vec<ScanEntry> {
    let results = Arc::new(StdMutex::new(Vec::new()));
    run_scan_into(hosts, ports, stop, on_progress, &results)
}

/// A bounded pool claims indexes without materializing the full host x port
/// matrix. Open results are published as they arrive, not only at completion.
fn run_scan_into(
    hosts: Vec<IpAddr>,
    ports: Vec<u16>,
    stop: &AtomicBool,
    on_progress: &Channel<ScanProgress>,
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
            scope.spawn(move || {
                loop {
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
                }
            });
        }
    });

    // Cancellation is not 100% completion; preserve the actual attempted count.
    report_progress(on_progress, &reported, completed.load(Ordering::Relaxed), total);
    let mut final_results = results.lock().expect("scan results poisoned");
    final_results.sort_by(|a, b| a.host.cmp(&b.host).then(a.port.cmp(&b.port)));
    final_results.clone()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn status_inner(ctx: &ScanCtx) -> NetscanStatusWire {
    NetscanStatusWire {
        running: ctx.running.load(Ordering::Relaxed),
        results: ctx.results.lock().expect("scan results poisoned").len(),
        saved_findings: ctx.saved_findings.load(Ordering::Relaxed) as usize,
        save_error: ctx
            .last_save_error
            .lock()
            .expect("scan error state poisoned")
            .clone(),
    }
}

#[derive(Debug, Serialize)]
pub struct NetscanStatusWire {
    pub running: bool,
    pub results: usize,
    pub saved_findings: usize,
    pub save_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ScanSummaryWire {
    pub id: u64,
    pub targets: String,
    pub ports: String,
    pub hosts_scanned: usize,
    pub open_ports: usize,
    pub duration_ms: u64,
    pub at_ms: u64,
}

#[tauri::command]
pub fn netscan_status(ctx: State<'_, ScanCtx>) -> NetscanStatusWire {
    status_inner(&ctx)
}

/// Start an authorized scan in a background thread; results stream into the
/// shared store and the UI polls them. The UI gates on an explicit
/// authorization checkbox before calling this (§9.3).
#[tauri::command]
pub fn netscan_start(
    targets: String,
    ports: String,
    on_progress: Channel<ScanProgress>,
    authorized: bool,
    case_id: String,
    app: AppHandle,
    evidence: State<'_, EvidenceCtx>,
    ctx: State<'_, ScanCtx>,
) -> Result<ScanSummaryWire, String> {
    if !authorized {
        return Err("explicit scan authorization acknowledgment required".to_string());
    }
    if !evidence
        .store
        .lock()
        .map_err(|_| "case store unavailable")?
        .case_exists(&case_id)?
    {
        return Err("selected case does not exist".into());
    }
    let hosts = parse_targets(&targets)?;
    let host_count = hosts.len();
    let port_list = parse_ports(&ports)?;
    scan_probe_count(host_count, port_list.len())?;
    if ctx.running.swap(true, Ordering::AcqRel) {
        return Err("a scan is already running; stop it first".to_string());
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
    let targets_spec = targets.clone();
    let ports_spec = ports.clone();

    std::thread::spawn(move || {
        let entries = run_scan_into(hosts, port_list, &stop_out, &on_progress, &results_out);
        let open = entries.len();
        let duration = started.elapsed().as_millis() as u64;
        if !entries.is_empty() {
            let mut findings = entries
                .iter()
                .take(256)
                .map(|entry| NewFinding {
                    title: format!("Open TCP {}:{}", entry.host, entry.port),
                    severity: "info".into(),
                    details: format!(
                        "Authorized TCP scan #{id}\nHost: {}\nPort: {}\nService: {}\nState: {}",
                        entry.host, entry.port, entry.service, entry.state
                    ),
                })
                .collect::<Vec<_>>();
            if open > 256 {
                findings.push(NewFinding {
                    title: "Additional open services not indexed".into(),
                    severity: "info".into(),
                    details: format!(
                        "Scan #{id} discovered {open} open services; first 256 saved in the case. Full scan remains in the scan results."
                    ),
                });
            }
            let outcome = (|| -> Result<usize, String> {
                let context = app.state::<EvidenceCtx>();
                let store = context.store.lock().map_err(|_| "case store unavailable")?;
                let mut count = 0;
                for batch in findings.chunks(128) {
                    count += store.add_findings(&case_id, "network.tcp", None, batch)?;
                }
                Ok(count)
            })();
            match outcome {
                Ok(count) => saved_out.store(count as u64, Ordering::Relaxed),
                Err(error) => {
                    *save_error_out.lock().expect("scan error state poisoned") = Some(error)
                }
            }
        }
        *results_out.lock().expect("scan results poisoned") = entries;
        running_out.store(false, Ordering::Relaxed);
        history_out
            .lock()
            .expect("scan history poisoned")
            .push(ScanHistoryItem {
                id,
                targets: targets_spec,
                ports: ports_spec,
                hosts_scanned: host_count,
                open_ports: open,
                duration_ms: duration,
                at_ms: now_ms(),
            });
    });

    Ok(ScanSummaryWire {
        id,
        targets: targets.clone(),
        ports: ports.clone(),
        hosts_scanned: host_count,
        open_ports: 0,
        duration_ms: 0,
        at_ms: now_ms(),
    })
}

/// Latest live results (polled by the UI while a scan runs).
#[tauri::command]
pub fn netscan_results(ctx: State<'_, ScanCtx>) -> Vec<ScanEntry> {
    ctx.results.lock().expect("scan results poisoned").clone()
}

#[tauri::command]
pub fn netscan_stop(ctx: State<'_, ScanCtx>) {
    ctx.stop.store(true, Ordering::Relaxed);
}

#[tauri::command]
pub fn netscan_history(ctx: State<'_, ScanCtx>) -> Vec<ScanHistoryItem> {
    ctx.history.lock().expect("scan history poisoned").clone()
}

/// Save the current results to a user-chosen file as JSON or CSV.
#[tauri::command]
pub fn netscan_export(
    app: AppHandle,
    format: String,
    ctx: State<'_, ScanCtx>,
) -> Result<String, String> {
    let results = ctx.results.lock().expect("scan results poisoned").clone();
    if results.is_empty() {
        return Err("no results to export".to_string());
    }
    let ext = if format == "csv" { "csv" } else { "json" };
    let picked = app
        .dialog()
        .file()
        .add_filter("Scan export", &[ext])
        .blocking_save_file()
        .ok_or("cancelled")?;
    let path = picked
        .as_path()
        .ok_or("unsupported file location")?
        .to_path_buf();
    let content = if format == "csv" {
        let mut csv = String::from("host,port,state,service,banner\n");
        for r in &results {
            let banner = r.banner.replace('"', "\"\"");
            csv.push_str(&format!(
                "{},{},{},{},\"{}\"\n",
                r.host, r.port, r.state, r.service, banner
            ));
        }
        csv
    } else {
        serde_json::to_string_pretty(&results).map_err(|e| format!("serialize failed: {e}"))?
    };
    std::fs::write(&path, content).map_err(|e| format!("cannot write export: {e}"))?;
    Ok(path.to_string_lossy().to_string())
}

/// Host discovery pre-pass: TCP ping a few common ports per host; returns the
/// hosts that answered (used to skip clearly-down hosts before a full scan).
#[tauri::command]
pub fn netscan_discover_hosts(targets: String, authorized: bool) -> Result<Vec<String>, String> {
    if !authorized {
        return Err("explicit scan authorization acknowledgment required".to_string());
    }
    let hosts = parse_targets(&targets)?;
    let discovery_ports: &[u16] = &[80, 443, 22, 445, 3389];
    let mut up = Vec::new();
    for host in hosts {
        let alive = discovery_ports.iter().any(|p| {
            TcpStream::connect_timeout(
                &std::net::SocketAddr::new(host, *p),
                Duration::from_millis(500),
            )
            .is_ok()
        });
        if alive {
            up.push(host.to_string());
        }
    }
    Ok(up)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cidr_and_single_hosts() {
        assert_eq!(parse_targets("127.0.0.1").unwrap().len(), 1);
        assert_eq!(parse_targets("192.168.1.0/30").unwrap().len(), 4);
    }

    #[test]
    fn cidr_cap_enforced() {
        assert!(parse_targets("10.0.0.0/8").is_err());
    }

    #[test]
    fn preset_port_counts_are_truthful_and_unique() {
        assert_eq!(TOP_PORTS_100.len(), 100);
        let unique = TOP_PORTS_100.iter().copied().collect::<std::collections::HashSet<_>>();
        assert_eq!(unique.len(), 100);
        assert_eq!(parse_ports("top25").unwrap().len(), 25);
        assert_eq!(parse_ports("top100").unwrap().len(), 100);
    }

    #[test]
    fn ipv4_slash_zero_is_a_bounded_error_not_a_shift_panic() {
        assert!(parse_targets("192.0.2.1/0").is_err());
    }

    #[test]
    fn connect_error_states_are_distinct() {
        use std::io::ErrorKind;
        assert_eq!(classify_connect_error(ErrorKind::ConnectionRefused), "closed");
        assert_eq!(classify_connect_error(ErrorKind::TimedOut), "no-response");
        assert_eq!(classify_connect_error(ErrorKind::NetworkUnreachable), "unreachable");
    }

    #[test]
    fn parses_port_specs() {
        assert_eq!(parse_ports("top25").unwrap().len(), 25);
        let ports = parse_ports("80,443,8000-8002").unwrap();
        assert_eq!(ports, vec![80, 443, 8000, 8001, 8002]);
        assert!(parse_ports("9000-99999").is_err());
    }

    #[test]
    fn scan_probe_budget_rejects_excessive_work_without_allocating_jobs() {
        assert_eq!(scan_probe_count(2, 100).unwrap(), 200);
        assert!(scan_probe_count(4096, 1024).is_err());
        assert_eq!(scan_probe_count(0, 0).unwrap(), 0);
    }

    #[test]
    fn repeated_host_targets_are_deduplicated() {
        let targets = parse_targets("127.0.0.1,127.0.0.1,127.0.0.2").unwrap();
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn banner_summary_pulls_server_header() {
        let raw = "HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\n\r\nbody";
        assert!(summarize_banner(raw).contains("nginx"));
    }

    #[test]
    fn banner_summary_keeps_first_line_for_non_http() {
        assert_eq!(
            summarize_banner("SSH-2.0-OpenSSH_9.6\r\n"),
            "SSH-2.0-OpenSSH_9.6"
        );
    }
}
