//! Scan Insights: ndiff-semantics scan comparison and topology projection.
//!
//! Two bounded, read-only commands over the SAME in-memory scanner storage the
//! `netscan_*` commands use (`ScanCtx`): no new probes, no filesystem access.
//!
//! - `netscan_diff_v1(a, b)` compares two completed scan sessions with the
//!   host/port state-diff semantics of nmap's ndiff (reference:
//!   reference/nmap/ndiff/ndiff.py): hosts pair on the IP string identity,
//!   ports pair on the "port/proto" spec, and only affirmative state deltas
//!   are reported. A host counts as up when at least one port answered open —
//!   the connect scanner never observes a host status header, so "up" must be
//!   inferred from affirmative evidence only, never from silence.
//! - `netscan_topology_v1(session_id)` projects one session onto a bounded
//!   node/edge graph. Edge kinds are honest about their evidence: the storage
//!   retains no ARP or MAC records, so a host-to-host "l2" adjacency cannot be
//!   claimed; the only on-link adjacency this deck truly observes is its own
//!   segment, and every other same-subnet relation stays the inferred
//!   "subnet" kind.
//!
//! `ScanCtx` keeps the observations of the most recent session only (they are
//! cleared when the next scan starts), so this module additionally retains a
//! bounded per-session snapshot store. Snapshots are captured lazily, at
//! command time, from the same read-only `ScanCtx` storage: whenever a scan
//! has completed and its session id is not yet stored, its observations are
//! pinned (bounded). Nothing here mutates scanner state; the frontend Insights
//! view calls the commands for each new completed session, which doubles as
//! the capture step.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::{IpAddr, UdpSocket};
use std::sync::atomic::Ordering;
use std::sync::{Mutex as StdMutex, OnceLock};

use serde::Serialize;
use tauri::State;

use super::netscan::{ScanCtx, ScanEntry, ScanObservation};
use crate::features::shared::session::{CaseSessionCtx, CaseSessionWire};

/// Bounded result contract: never more hosts than this in one diff response.
const MAX_DIFF_HOSTS: usize = 4096;
/// Bounded result contract: never more port-level changes per changed host.
const MAX_CHANGES_PER_HOST: usize = 4096;
/// Bounded result contract: topology never exceeds this node count.
const MAX_TOPOLOGY_NODES: usize = 512;
/// Bounded result contract: topology never exceeds this edge count.
const MAX_TOPOLOGY_EDGES: usize = 2048;
/// Retained completed sessions per selected case (oldest evicted first).
const MAX_SNAPSHOTS: usize = 8;
/// Per-session observation rows retained; matches the live observation cap.
const MAX_SNAPSHOT_ROWS: usize = 20_000;

// ---------------------------------------------------------------------------
// Wire payloads
// ---------------------------------------------------------------------------

/// One port-level state transition, ndiff style. `port` is the "port/proto"
/// spec identity (e.g. "80/tcp"), `from`/`to` are observed states.
#[derive(Debug, Clone, Serialize)]
pub struct ScanDiffStateChangeWire {
    pub port: String,
    pub from: String,
    pub to: String,
}

/// One host that stayed identified across both sessions but changed ports.
#[derive(Debug, Clone, Serialize)]
pub struct ScanDiffHostWire {
    pub host: String,
    pub ports_added: Vec<String>,
    pub ports_removed: Vec<String>,
    pub state_changes: Vec<ScanDiffStateChangeWire>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanDiffSummaryWire {
    pub hosts_up_a: u32,
    pub hosts_up_b: u32,
    pub ports_open_a: u32,
    pub ports_open_b: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanDiffWire {
    pub session_a_id: u64,
    pub session_b_id: u64,
    pub new_hosts: Vec<String>,
    pub lost_hosts: Vec<String>,
    pub changed_hosts: Vec<ScanDiffHostWire>,
    pub summary: ScanDiffSummaryWire,
}

#[derive(Debug, Clone, Serialize)]
pub struct TopologyNodeWire {
    pub id: String,
    pub label: String,
    pub open_port_count: u32,
    pub is_local: bool,
}

/// `kind` is "l2" (on-link adjacency of this deck's own segment) or "subnet"
/// (same /24 or /64 inferred grouping); see the module docs for the evidence
/// honesty reasoning.
#[derive(Debug, Clone, Serialize)]
pub struct TopologyEdgeWire {
    pub a: String,
    pub b: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanTopologyWire {
    pub session_id: u64,
    pub nodes: Vec<TopologyNodeWire>,
    pub edges: Vec<TopologyEdgeWire>,
    /// True when more hosts were observed than the node bound retained.
    pub truncated: bool,
}

// ---------------------------------------------------------------------------
// Snapshot model
// ---------------------------------------------------------------------------

/// One retained probe verdict. Deduplicated to the scanner's final outcome per
/// (host, port, protocol): later observations are retries that supersede the
/// earlier inconclusive attempt for the same key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionRow {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub state: String,
}

impl SessionRow {
    fn key(&self) -> (String, u16, String) {
        (self.host.clone(), self.port, self.protocol.clone())
    }
}

/// A completed scan session pinned from `ScanCtx`, scoped to its case so a
/// case switch can never leak observations across investigations.
#[derive(Debug, Clone)]
struct SessionSnapshot {
    case_id: String,
    session_id: u64,
    rows: Vec<SessionRow>,
}

/// Bounded per-session snapshot store owned by this slice. Purely advisory
/// in-memory state like every other network workspace context; the case store
/// remains the record of truth for persisted findings.
#[derive(Default)]
pub struct InsightsCtx {
    snapshots: StdMutex<VecDeque<SessionSnapshot>>,
}

impl InsightsCtx {
    fn retain(&self, case_id: &str, session_id: u64, rows: Vec<SessionRow>) {
        let Ok(mut snapshots) = self.snapshots.lock() else {
            return;
        };
        // One snapshot per session id: re-capture replaces the stored copy.
        snapshots.retain(|snapshot| snapshot.session_id != session_id);
        snapshots.push_back(SessionSnapshot {
            case_id: case_id.to_string(),
            session_id,
            rows,
        });
        while snapshots.len() > MAX_SNAPSHOTS {
            snapshots.pop_front();
        }
    }

    /// Drop snapshots belonging to other cases before reading, then clone the
    /// requested session. The retain-on-read keeps case switches hygienic
    /// without needing a hook into the shared scanner state.
    fn snapshot(
        &self,
        scope: &CaseSessionWire,
        session_id: u64,
    ) -> Result<Vec<SessionRow>, String> {
        let mut snapshots = self
            .snapshots
            .lock()
            .map_err(|_| "insights snapshot store unavailable")?;
        let Some(case_id) = scope.case_id.as_deref() else {
            return Err("scan insights require a saved case".into());
        };
        snapshots.retain(|snapshot| snapshot.case_id == case_id);
        let found = snapshots
            .iter()
            .find(|snapshot| snapshot.session_id == session_id)
            .ok_or_else(|| {
                format!(
                    "scan session {session_id} observations are not retained; insights keep the \
                     last {MAX_SNAPSHOTS} completed scans of this case while it stays selected"
                )
            })?;
        Ok(found.rows.clone())
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.snapshots.lock().map(|s| s.len()).unwrap_or(0)
    }
}

/// Deduplicate one session's observations to the final verdict per
/// (host, port, protocol) key, bounded like the live observation store.
pub(crate) fn rows_from_observations(observations: &[ScanObservation]) -> Vec<SessionRow> {
    let mut index: BTreeMap<(String, u16, String), SessionRow> = BTreeMap::new();
    for observation in observations.iter().take(MAX_SNAPSHOT_ROWS) {
        let row = SessionRow {
            host: observation.host.clone(),
            port: observation.port,
            protocol: observation.protocol.clone(),
            state: observation.state.clone(),
        };
        index.insert(row.key(), row);
    }
    index.into_values().collect()
}

/// Compatibility path for sessions that only produced open-entry results.
pub(crate) fn rows_from_entries(entries: &[ScanEntry]) -> Vec<SessionRow> {
    let mut index: BTreeMap<(String, u16, String), SessionRow> = BTreeMap::new();
    for entry in entries.iter().take(MAX_SNAPSHOT_ROWS) {
        let row = SessionRow {
            host: entry.host.clone(),
            port: entry.port,
            protocol: "tcp".to_string(),
            state: entry.state.clone(),
        };
        index.insert(row.key(), row);
    }
    index.into_values().collect()
}

/// Pin the latest completed scan of the selected case into the snapshot store.
/// Read-only over `ScanCtx`; a running scan is never captured because its
/// observations are still accumulating.
fn sync_current_session(
    ctx: &ScanCtx,
    insights: &InsightsCtx,
    scope: &CaseSessionWire,
) -> Option<u64> {
    if ctx.running.load(Ordering::Acquire) {
        return None;
    }
    let history = ctx.history.lock().ok()?;
    let latest = history.last()?;
    let session_id = latest.id;
    let observations = ctx.observations.lock().ok()?;
    let entries = ctx.results.lock().ok()?;
    let rows = if observations.is_empty() {
        rows_from_entries(&entries)
    } else {
        rows_from_observations(&observations)
    };
    drop(observations);
    drop(entries);
    drop(history);
    let Some(case_id) = scope.case_id.as_deref() else {
        return None;
    };
    insights.retain(case_id, session_id, rows);
    Some(session_id)
}

// ---------------------------------------------------------------------------
// Pure diff semantics (ndiff reference: reference/nmap/ndiff/ndiff.py)
// ---------------------------------------------------------------------------

/// Structured port identity; formatting to "port/proto" happens only at the
/// wire boundary so numeric ordering stays correct ("9/tcp" sorts before
/// "80/tcp" unlike its string form).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct PortKey {
    port: u16,
    protocol: String,
}

impl PortKey {
    fn spec(&self) -> String {
        format!("{}/{}", self.port, self.protocol)
    }
}

/// Per-host observed port states for one session.
type HostPorts = HashMap<PortKey, String>;

fn index_by_host(rows: &[SessionRow]) -> BTreeMap<String, HostPorts> {
    let mut hosts: BTreeMap<String, HostPorts> = BTreeMap::new();
    for row in rows {
        hosts
            .entry(row.host.clone())
            .or_default()
            .entry(PortKey {
                port: row.port,
                protocol: row.protocol.clone(),
            })
            .or_insert_with(|| row.state.clone());
    }
    hosts
}

/// Deterministic IP ordering: IPv4 numerically first, then IPv6, then any
/// non-literal host string last. String ordering would mis-sort
/// "10.0.0.10" before "10.0.0.2".
pub(crate) fn ip_sort_key(host: &str) -> (u8, [u16; 8], String) {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            let mut segments = [0u16; 8];
            for (i, octet) in v4.octets().into_iter().enumerate() {
                segments[i] = octet as u16;
            }
            (0, segments, String::new())
        }
        Ok(IpAddr::V6(v6)) => {
            let mut segments = [0u16; 8];
            for (i, group) in v6.segments().into_iter().enumerate() {
                segments[i] = group;
            }
            (1, segments, String::new())
        }
        Err(_) => (2, [0u16; 8], host.to_string()),
    }
}

/// A host is up when affirmative open-port evidence exists. Silence, closed
/// and unreachable outcomes are never treated as host presence (connect
/// scans do not observe a host status header; ndiff "Host is up/down" maps
/// onto this inference).
fn hosts_up(index: &BTreeMap<String, HostPorts>) -> HashSet<String> {
    index
        .iter()
        .filter(|(_, ports)| ports.values().any(|state| state == "open"))
        .map(|(host, _)| host.clone())
        .collect()
}

/// ndiff-style comparison of two sessions. Hosts pair on the IP string,
/// ports pair on the "port/proto" spec; a port observed in one session only
/// with an open state is added/removed, a port observed in both with
/// different states is a state change (ndiff compares the reported states,
/// including closed, rather than collapsing everything into added/removed).
pub(crate) fn diff_sessions(
    session_a_id: u64,
    session_b_id: u64,
    rows_a: &[SessionRow],
    rows_b: &[SessionRow],
) -> ScanDiffWire {
    let index_a = index_by_host(rows_a);
    let index_b = index_by_host(rows_b);
    let up_a = hosts_up(&index_a);
    let up_b = hosts_up(&index_b);

    let mut new_hosts: Vec<&String> = up_b.difference(&up_a).collect();
    new_hosts.sort_by_key(|host| ip_sort_key(host));
    let mut lost_hosts: Vec<&String> = up_a.difference(&up_b).collect();
    lost_hosts.sort_by_key(|host| ip_sort_key(host));

    // Summary is computed from the full sets so the bounds below never hide
    // totals from the operator; only the per-item listings are capped.
    let summary = ScanDiffSummaryWire {
        hosts_up_a: up_a.len() as u32,
        hosts_up_b: up_b.len() as u32,
        ports_open_a: rows_a.iter().filter(|row| row.state == "open").count() as u32,
        ports_open_b: rows_b.iter().filter(|row| row.state == "open").count() as u32,
    };

    let mut changed_hosts = Vec::new();
    for (host, ports_a) in index_a.iter() {
        if changed_hosts.len() >= MAX_DIFF_HOSTS {
            break;
        }
        let Some(ports_b) = index_b.get(host) else {
            continue;
        };
        // Hosts that never answered open in either session have no port story
        // to tell; ndiff likewise skips hosts whose diff cost is zero.
        let up_in_a = up_a.contains(host);
        let up_in_b = up_b.contains(host);
        if !up_in_a && !up_in_b {
            continue;
        }
        let diff = diff_host_ports(ports_a, ports_b);
        if !diff.is_empty() {
            changed_hosts.push(ScanDiffHostWire {
                host: host.clone(),
                ports_added: diff.added,
                ports_removed: diff.removed,
                state_changes: diff.changes,
            });
        }
    }

    ScanDiffWire {
        session_a_id,
        session_b_id,
        new_hosts: new_hosts.into_iter().cloned().collect(),
        lost_hosts: lost_hosts.into_iter().cloned().collect(),
        changed_hosts,
        summary,
    }
}

struct HostPortDiff {
    added: Vec<String>,
    removed: Vec<String>,
    changes: Vec<ScanDiffStateChangeWire>,
}

impl HostPortDiff {
    fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changes.is_empty()
    }
}

fn diff_host_ports(ports_a: &HostPorts, ports_b: &HostPorts) -> HostPortDiff {
    let mut keys: Vec<&PortKey> = ports_a.keys().chain(ports_b.keys()).collect();
    keys.sort();
    keys.dedup();
    let mut diff = HostPortDiff {
        added: Vec::new(),
        removed: Vec::new(),
        changes: Vec::new(),
    };
    for key in keys {
        if diff.added.len() + diff.removed.len() + diff.changes.len() >= MAX_CHANGES_PER_HOST {
            break;
        }
        let state_a = ports_a.get(key);
        let state_b = ports_b.get(key);
        match (state_a, state_b) {
            (None, Some(state)) if state == "open" => diff.added.push(key.spec()),
            (Some(state), None) if state == "open" => diff.removed.push(key.spec()),
            (Some(from), Some(to)) if from != to => {
                diff.changes.push(ScanDiffStateChangeWire {
                    port: key.spec(),
                    from: from.clone(),
                    to: to.clone(),
                });
            }
            // A non-open port observed in one session only is not affirmative
            // evidence of anything (the other scan may simply not have probed
            // it), so it stays unreported; open-equal ports are unchanged.
            _ => {}
        }
    }
    diff
}

// ---------------------------------------------------------------------------
// Pure topology projection (radialnet concepts, original implementation)
// ---------------------------------------------------------------------------

/// The deck's own primary outbound address, detected without sending any
/// packet: a connected UDP socket consults the routing table only. Fails
/// closed to None when no suitable route exists, leaving loopback detection.
fn primary_local_address() -> Option<IpAddr> {
    static PRIMARY: OnceLock<Option<IpAddr>> = OnceLock::new();
    PRIMARY
        .get_or_init(|| {
            let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
            // TEST-NET-1 is never written to; connect() on a UDP socket sends
            // nothing, it only selects a route.
            socket.connect(("192.0.2.1", 9)).ok()?;
            socket.local_addr().ok().map(|addr| addr.ip())
        })
        .clone()
}

/// A node is local when it is a loopback address or this deck's own primary
/// address. Whole RFC1918 ranges are deliberately NOT "local": being
/// privately addressable does not make a scanned host this machine.
pub(crate) fn classify_local(addr: IpAddr, primary: Option<IpAddr>) -> bool {
    addr.is_loopback() || Some(addr) == primary
}

/// Same /24 for IPv4, same /64 for IPv6; mixed families never group.
pub(crate) fn same_subnet(a: IpAddr, b: IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(x), IpAddr::V4(y)) => x.octets()[0..3] == y.octets()[0..3],
        (IpAddr::V6(x), IpAddr::V6(y)) => x.octets()[0..8] == y.octets()[0..8],
        _ => false,
    }
}

pub(crate) fn topology_from_session(
    session_id: u64,
    rows: &[SessionRow],
    primary: Option<IpAddr>,
) -> ScanTopologyWire {
    let mut hosts: BTreeMap<String, HashSet<PortKey>> = BTreeMap::new();
    for row in rows {
        if row.state == "open" {
            hosts.entry(row.host.clone()).or_default().insert(PortKey {
                port: row.port,
                protocol: row.protocol.clone(),
            });
        }
    }
    // Deterministic retention: sort by IP key, keep the first 512, report the
    // truncation so the UI can tell the operator what was left out.
    let mut ordered: Vec<(&String, usize)> = hosts
        .iter()
        .map(|(host, ports)| (host, ports.len()))
        .collect();
    ordered.sort_by(|a, b| ip_sort_key(a.0).cmp(&ip_sort_key(b.0)));
    let truncated = ordered.len() > MAX_TOPOLOGY_NODES;
    let retained: Vec<(&String, usize)> = ordered.into_iter().take(MAX_TOPOLOGY_NODES).collect();

    let nodes: Vec<TopologyNodeWire> = retained
        .iter()
        .map(|(host, open_ports)| {
            let is_local = host
                .parse::<IpAddr>()
                .map(|addr| classify_local(addr, primary))
                .unwrap_or(false);
            TopologyNodeWire {
                id: (*host).clone(),
                label: (*host).clone(),
                open_port_count: *open_ports as u32,
                is_local,
            }
        })
        .collect();

    // Edges are honest about evidence: no ARP or MAC records exist in the
    // retained storage, so a host-to-host "l2" adjacency cannot be claimed.
    // The only on-link adjacency this deck actually observes is its own
    // segment (local node to a same-subnet host); every other same-subnet
    // relation stays the inferred "subnet" kind.
    let mut edges = Vec::new();
    'pairs: for i in 0..nodes.len() {
        for j in (i + 1)..nodes.len() {
            if edges.len() >= MAX_TOPOLOGY_EDGES {
                break 'pairs;
            }
            let (Ok(a), Ok(b)) = (nodes[i].id.parse::<IpAddr>(), nodes[j].id.parse::<IpAddr>())
            else {
                continue;
            };
            if !same_subnet(a, b) {
                continue;
            }
            let kind = match (nodes[i].is_local, nodes[j].is_local) {
                (true, false) | (false, true) => "l2",
                (false, false) => "subnet",
                // Two local endpoints never group into one link relation.
                (true, true) => continue,
            };
            edges.push(TopologyEdgeWire {
                a: nodes[i].id.clone(),
                b: nodes[j].id.clone(),
                kind: kind.to_string(),
            });
        }
    }

    ScanTopologyWire {
        session_id,
        nodes,
        edges,
        truncated,
    }
}

// ---------------------------------------------------------------------------
// IPC commands
// ---------------------------------------------------------------------------

fn insights_scope(
    selected: &State<'_, CaseSessionCtx>,
    ctx: &State<'_, ScanCtx>,
) -> Result<CaseSessionWire, String> {
    let scope = selected.selected()?;
    // Same authorization gate as the netscan reads: scan storage belongs to
    // the backend-selected case revision only.
    if !ctx.visible_for(&selected) {
        return Err(
            "scan insights require a completed scan in the backend-selected case revision".into(),
        );
    }
    Ok(scope)
}

/// ndiff-style comparison of two completed scan sessions of the selected case.
#[tauri::command]
pub fn netscan_diff_v1(
    session_a_id: u64,
    session_b_id: u64,
    ctx: State<'_, ScanCtx>,
    insights: State<'_, InsightsCtx>,
    selected: State<'_, CaseSessionCtx>,
) -> Result<ScanDiffWire, String> {
    let scope = insights_scope(&selected, &ctx)?;
    sync_current_session(&ctx, &insights, &scope);
    let rows_a = insights.snapshot(&scope, session_a_id)?;
    let rows_b = insights.snapshot(&scope, session_b_id)?;
    // Re-verify after the reads, mirroring the observation page command.
    selected.ensure(&scope)?;
    Ok(diff_sessions(session_a_id, session_b_id, &rows_a, &rows_b))
}

/// Bounded node/edge topology projection of one completed scan session.
#[tauri::command]
pub fn netscan_topology_v1(
    session_id: u64,
    ctx: State<'_, ScanCtx>,
    insights: State<'_, InsightsCtx>,
    selected: State<'_, CaseSessionCtx>,
) -> Result<ScanTopologyWire, String> {
    let scope = insights_scope(&selected, &ctx)?;
    sync_current_session(&ctx, &insights, &scope);
    let rows = insights.snapshot(&scope, session_id)?;
    selected.ensure(&scope)?;
    Ok(topology_from_session(
        session_id,
        &rows,
        primary_local_address(),
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn row(host: &str, port: u16, protocol: &str, state: &str) -> SessionRow {
        SessionRow {
            host: host.to_string(),
            port,
            protocol: protocol.to_string(),
            state: state.to_string(),
        }
    }

    fn observation(host: &str, port: u16, protocol: &str, state: &str) -> ScanObservation {
        ScanObservation {
            host: host.to_string(),
            port,
            protocol: protocol.to_string(),
            state: state.to_string(),
            reason: "test".into(),
            method: "test".into(),
            service: "unknown".into(),
            service_basis: "none".into(),
            remote_software_claim: None,
            banner: String::new(),
            started_at_ms: 1,
            elapsed_ms: 1,
            attempts: 1,
            retries: 0,
            os_error_code: None,
        }
    }

    // ---- ndiff diff semantics ---------------------------------------------

    #[test]
    fn diff_reports_new_lost_and_port_level_changes() {
        let a = vec![
            row("192.0.2.10", 22, "tcp", "open"),
            row("192.0.2.10", 80, "tcp", "open"),
            row("192.0.2.11", 443, "tcp", "open"),
            // Down host in A: observed but never open, must not be reported.
            row("192.0.2.12", 80, "tcp", "closed"),
        ];
        let b = vec![
            row("192.0.2.10", 22, "tcp", "open"),
            // 80/tcp went open -> closed (state change, not removal).
            row("192.0.2.10", 80, "tcp", "closed"),
            // 8443/tcp newly open.
            row("192.0.2.10", 8443, "tcp", "open"),
            // .11 vanished entirely from B -> lost host.
            // .13 is new.
            row("192.0.2.13", 53, "udp", "open"),
        ];
        let diff = diff_sessions(1, 2, &a, &b);
        assert_eq!(diff.new_hosts, vec!["192.0.2.13".to_string()]);
        assert_eq!(diff.lost_hosts, vec!["192.0.2.11".to_string()]);
        assert_eq!(diff.changed_hosts.len(), 1);
        let changed = &diff.changed_hosts[0];
        assert_eq!(changed.host, "192.0.2.10");
        assert_eq!(changed.ports_added, vec!["8443/tcp".to_string()]);
        assert!(changed.ports_removed.is_empty());
        assert_eq!(changed.state_changes.len(), 1);
        assert_eq!(changed.state_changes[0].port, "80/tcp");
        assert_eq!(changed.state_changes[0].from, "open");
        assert_eq!(changed.state_changes[0].to, "closed");
        assert_eq!((diff.summary.hosts_up_a, diff.summary.hosts_up_b), (2, 2));
        assert_eq!(
            (diff.summary.ports_open_a, diff.summary.ports_open_b),
            (3, 3)
        );
    }

    #[test]
    fn diff_closed_to_open_is_a_state_change_not_an_addition() {
        // ndiff compares reported states: a port scanned as closed in A and
        // open in B is a transition, more informative than "added".
        let a = vec![row("192.0.2.7", 80, "tcp", "closed")];
        let b = vec![row("192.0.2.7", 80, "tcp", "open")];
        let diff = diff_sessions(1, 2, &a, &b);
        assert!(diff.new_hosts.contains(&"192.0.2.7".to_string()));
        assert_eq!(diff.changed_hosts.len(), 1);
        assert!(diff.changed_hosts[0].ports_added.is_empty());
        assert_eq!(diff.changed_hosts[0].state_changes.len(), 1);
        assert_eq!(diff.changed_hosts[0].state_changes[0].from, "closed");
        assert_eq!(diff.changed_hosts[0].state_changes[0].to, "open");
    }

    #[test]
    fn diff_of_identical_sessions_is_empty() {
        let rows = vec![row("192.0.2.10", 22, "tcp", "open")];
        let diff = diff_sessions(3, 3, &rows, &rows);
        assert!(diff.new_hosts.is_empty());
        assert!(diff.lost_hosts.is_empty());
        assert!(diff.changed_hosts.is_empty());
        assert_eq!(diff.summary.hosts_up_a, 1);
        assert_eq!(diff.summary.ports_open_b, 1);
    }

    #[test]
    fn diff_is_bounded_per_host_and_across_hosts() {
        // One host with more changes than the per-host bound stays capped.
        let mut a = Vec::new();
        let mut b = Vec::new();
        for port in 1..(MAX_CHANGES_PER_HOST as u16 + 64) {
            a.push(row("192.0.2.9", port, "tcp", "open"));
            b.push(row("192.0.2.9", port, "tcp", "closed"));
        }
        let diff = diff_sessions(1, 2, &a, &b);
        let total: usize = diff.changed_hosts[0].ports_added.len()
            + diff.changed_hosts[0].ports_removed.len()
            + diff.changed_hosts[0].state_changes.len();
        assert!(total <= MAX_CHANGES_PER_HOST);

        // Many changed hosts stay under the host bound and deterministic.
        let mut many_a = Vec::new();
        let mut many_b = Vec::new();
        for i in 0..(MAX_DIFF_HOSTS + 32) {
            let host = format!("10.{}.{}.{}", (i / 65536) % 256, (i / 256) % 256, i % 256);
            many_a.push(row(&host, 80, "tcp", "open"));
            many_b.push(row(&host, 80, "tcp", "closed"));
        }
        let capped = diff_sessions(1, 2, &many_a, &many_b);
        assert!(capped.changed_hosts.len() <= MAX_DIFF_HOSTS);
        // Deterministic numeric order: 10.0.0.2 precedes 10.0.0.10.
        let first = &capped.changed_hosts[0].host;
        let second = &capped.changed_hosts[1].host;
        assert!(ip_sort_key(first) < ip_sort_key(second));
    }

    // ---- observation ingestion ---------------------------------------------

    #[test]
    fn retry_observations_supersede_earlier_attempts_per_key() {
        let observations = vec![
            observation("192.0.2.5", 443, "tcp", "inconclusive"),
            observation("192.0.2.5", 443, "tcp", "open"),
            observation("192.0.2.5", 80, "tcp", "open"),
        ];
        let rows = rows_from_observations(&observations);
        assert_eq!(rows.len(), 2);
        let https = rows
            .iter()
            .find(|row| row.port == 443)
            .expect("443 retained");
        assert_eq!(https.state, "open", "final attempt wins");
    }

    #[test]
    fn entries_fallback_preserves_open_tcp_rows() {
        let entries = vec![ScanEntry {
            host: "192.0.2.30".into(),
            port: 8080,
            state: "open".into(),
            service: "http".into(),
            banner: String::new(),
        }];
        let rows = rows_from_entries(&entries);
        assert_eq!(rows, vec![row("192.0.2.30", 8080, "tcp", "open")]);
    }

    // ---- topology -----------------------------------------------------------

    #[test]
    fn topology_links_same_subnet_hosts_and_local_segment() {
        let rows = vec![
            row("192.168.1.5", 22, "tcp", "open"),
            row("192.168.1.20", 443, "tcp", "open"),
            row("192.168.1.77", 53, "udp", "open"),
            row("192.168.2.20", 443, "tcp", "open"),
            row("10.0.0.1", 80, "tcp", "open"),
            // A closed-only host has no affirmative presence, so it is not a
            // topology node at all (silence is not host evidence).
            row("192.168.1.99", 80, "tcp", "closed"),
        ];
        let primary: Option<IpAddr> = "192.168.1.5".parse().ok();
        let topology = topology_from_session(7, &rows, primary);
        assert_eq!(topology.nodes.len(), 5);
        assert!(!topology.truncated);
        assert!(
            topology.nodes.iter().all(|node| node.id != "192.168.1.99"),
            "closed-only host is not a node"
        );
        let local = topology
            .nodes
            .iter()
            .find(|node| node.id == "192.168.1.5")
            .expect("local node present");
        assert!(local.is_local);
        assert_eq!(local.open_port_count, 1);
        // The deck's own segment claims l2; remote-to-remote same-subnet
        // pairs stay the inferred subnet kind.
        let l2: Vec<_> = topology.edges.iter().filter(|e| e.kind == "l2").collect();
        assert_eq!(l2.len(), 2);
        for edge in &l2 {
            assert_eq!(edge.a, "192.168.1.5");
        }
        let l2_peers: Vec<_> = l2.iter().map(|edge| edge.b.as_str()).collect();
        assert_eq!(l2_peers, vec!["192.168.1.20", "192.168.1.77"]);
        let subnets: Vec<_> = topology
            .edges
            .iter()
            .filter(|e| e.kind == "subnet")
            .collect();
        assert_eq!(subnets.len(), 1);
        assert_eq!(subnets[0].a, "192.168.1.20");
        assert_eq!(subnets[0].b, "192.168.1.77");
    }

    #[test]
    fn topology_never_groups_mixed_families_or_two_local_nodes() {
        let rows = vec![
            row("192.168.1.5", 22, "tcp", "open"),
            row("2001:db8::5", 22, "tcp", "open"),
        ];
        let primary: Option<IpAddr> = "192.168.1.5".parse().ok();
        let topology = topology_from_session(1, &rows, primary);
        assert!(topology.edges.is_empty(), "v4 and v6 do not group");
        let loopback_rows = vec![
            row("127.0.0.1", 8080, "tcp", "open"),
            row("127.0.0.2", 8081, "tcp", "open"),
        ];
        let topology = topology_from_session(1, &loopback_rows, primary);
        assert!(
            topology.edges.is_empty(),
            "two local endpoints never form one link"
        );
    }

    #[test]
    fn topology_is_bounded_and_deterministic() {
        let mut rows = Vec::new();
        for i in 0..(MAX_TOPOLOGY_NODES + 16) {
            let host = format!("10.{}.{}.{}", (i / 65536) % 256, (i / 256) % 256, i % 256);
            rows.push(row(&host, 80, "tcp", "open"));
        }
        let topology = topology_from_session(2, &rows, None);
        assert_eq!(topology.nodes.len(), MAX_TOPOLOGY_NODES);
        assert!(topology.truncated);
        let ids: Vec<_> = topology.nodes.iter().map(|n| n.id.clone()).collect();
        let mut sorted = ids.clone();
        sorted.sort_by_key(|host| ip_sort_key(host));
        assert_eq!(ids, sorted, "node order is the deterministic IP order");

        // Edge bound: a full /24 of same-subnet pairs would exceed 2048.
        let mut dense = Vec::new();
        for i in 0..MAX_TOPOLOGY_NODES {
            let host = format!("10.9.{}.{}", (i / 256) % 256, i % 256);
            dense.push(row(&host, 80, "tcp", "open"));
        }
        let dense_topology = topology_from_session(2, &dense, None);
        assert!(dense_topology.edges.len() <= MAX_TOPOLOGY_EDGES);
    }

    // ---- helpers --------------------------------------------------------------

    #[test]
    fn ip_sort_key_orders_numerically_not_lexically() {
        assert!(ip_sort_key("10.0.0.2") < ip_sort_key("10.0.0.10"));
        assert!(ip_sort_key("192.0.2.1") < ip_sort_key("2001:db8::1"));
        assert!(ip_sort_key("2001:db8::1") < ip_sort_key("fe80::1"));
        assert!(ip_sort_key("10.0.0.1") < ip_sort_key("not-an-ip"));
    }

    #[test]
    fn local_classification_is_loopback_or_own_address_only() {
        let primary: Option<IpAddr> = "192.168.1.5".parse().ok();
        assert!(classify_local("127.0.0.1".parse().unwrap(), None));
        assert!(classify_local("192.168.1.5".parse().unwrap(), primary));
        assert!(!classify_local("192.168.1.6".parse().unwrap(), primary));
        assert!(classify_local("::1".parse().unwrap(), None));
    }

    #[test]
    fn subnet_grouping_uses_24_and_64_prefixes() {
        assert!(same_subnet(
            "192.168.1.5".parse().unwrap(),
            "192.168.1.250".parse().unwrap()
        ));
        assert!(!same_subnet(
            "192.168.1.5".parse().unwrap(),
            "192.168.2.5".parse().unwrap()
        ));
        assert!(same_subnet(
            "2001:db8:1:2::5".parse().unwrap(),
            "2001:db8:1:2::99".parse().unwrap()
        ));
        assert!(!same_subnet(
            "2001:db8:1:2::5".parse().unwrap(),
            "2001:db8:1:3::5".parse().unwrap()
        ));
    }

    #[test]
    fn snapshot_store_is_bounded_scoped_and_replaceable() {
        let insights = InsightsCtx::default();
        let scope_a = CaseSessionWire {
            case_id: Some("case-a".into()),
            revision: 1,
        };
        let last_id = (MAX_SNAPSHOTS + 1) as u64;
        for id in 0..last_id + 1 {
            insights.retain("case-a", id, vec![row("192.0.2.1", 80, "tcp", "open")]);
        }
        assert_eq!(insights.len(), MAX_SNAPSHOTS, "oldest snapshots evicted");
        assert!(insights.snapshot(&scope_a, 0).is_err(), "evicted id gone");
        assert!(insights.snapshot(&scope_a, last_id).is_ok());
        // Re-capture replaces the stored rows for the same session id.
        insights.retain("case-a", last_id, vec![]);
        assert_eq!(insights.snapshot(&scope_a, last_id).unwrap().len(), 0);
        // Another case cannot read or keep this case's snapshots.
        let scope_b = CaseSessionWire {
            case_id: Some("case-b".into()),
            revision: 1,
        };
        assert!(insights.snapshot(&scope_b, last_id).is_err());
        assert_eq!(insights.len(), 0, "foreign-case read prunes the store");
    }
}
