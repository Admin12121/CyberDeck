//! Authorized, allowlist-gated DNS responder for the Network Lab
//! (Bettercap-parity `dns.spoof` arc). FOR AUTHORIZED LAB USE ONLY: the
//! embedding application MUST hold the shared `NetworkOperationGate` lease,
//! show the native confirmation dialog and verify the backend-selected saved
//! case before calling any entry point here — the module itself never widens
//! or re-derives an authorization.
//!
//! What it does, exactly: binds ONE UDP socket on the configured port
//! (default 53, configurable; ports below 1024 need administrator privileges
//! and a refused bind surfaces as an honest `Permission` error) and answers
//! queries ONLY for the operator's authorized domain allowlist (exact names
//! plus bounded leading `*.domain` wildcards, at most
//! [`MAX_DOMAINS`] entries). A queries for allowlisted names are answered
//! with the authorized IPv4; OTHER record types for allowlisted names get an
//! empty NOERROR (NODATA) answer so the real upstream address can never leak
//! for a domain the operator claimed. Every non-allowlisted query is
//! FORWARDED to the system resolver and its response relayed back, so
//! ordinary LAN clients keep resolving. Forward honesty: this responder is a
//! RESOLVER, not a transparent interceptor — it answers only clients that
//! send queries to this machine's port; it never intercepts traffic between
//! a client and another resolver (pair it with the lab ARP spoofer to become
//! the on-path resolver).
//!
//! Bounds and stop discipline: the full request/answer log is a bounded ring
//! ([`MAX_LOG_ENTRIES`] entries; oldest dropped with an honest drop counter),
//! requests are rate-limited to the configured ≤ [`MAX_RATE_PER_SEC`]
//! requests/s (excess is dropped and counted, never answered), upstream
//! forwards time out at [`UPSTREAM_TIMEOUT_MS`] with at most
//! [`MAX_CONCURRENT_FORWARDS`] in flight, distinct clients are tracked up to
//! [`MAX_CLIENTS_TRACKED`], and the session hard-caps at 30 minutes
//! (auto-stop). Stop is honored between datagrams (≤ ~150 ms latency); on
//! ANY end the log ring is frozen, marked flushed and stays readable — the
//! last state always reports what was answered, for whom, from spoof or
//! upstream.
//!
//! Inbound queries are decoded with the crate's bounded parser
//! (`cyberdeck_packet::dns::parse_dns`) — compression pointers, label
//! counts and packet sizes are already capped there, so untrusted datagrams
//! cannot loop or over-allocate. Malformed or truncated datagrams are
//! refused (counted, logged, never answered, never forwarded). The pure UDP
//! core is platform-independent and fully testable on localhost with real
//! datagrams; there is no raw-socket or platform shim in this module.

use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cyberdeck_packet::dns::parse_dns;
use tokio::net::UdpSocket;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

/// Authorized allowlist size cap: at most 16 domains (exact or wildcard).
pub const MAX_DOMAINS: usize = 16;
/// Bounded request/answer log ring: at most 512 entries, oldest dropped.
pub const MAX_LOG_ENTRIES: usize = 512;
/// Hard request rate cap: at most 32 answered/forwarded requests per second.
pub const MAX_RATE_PER_SEC: u32 = 32;
/// Operator default rate (well under the hard cap; gentle on the LAN).
pub const DEFAULT_RATE_PER_SEC: u32 = 8;
/// Hard session runtime cap: 30 minutes, then the loop auto-stops.
pub const MAX_RUNTIME_MS: u64 = 30 * 60 * 1000;
/// Upstream forward timeout: 3 seconds, then the forward is dropped honestly.
pub const UPSTREAM_TIMEOUT_MS: u64 = 3000;
/// At most 64 upstream forwards in flight; excess requests are refused.
pub const MAX_CONCURRENT_FORWARDS: usize = 64;
/// Largest datagram we read: anything bigger (or truncated) fails the
/// bounded parse and is refused, never answered or forwarded.
pub const MAX_QUERY_BYTES: usize = 4096;
/// TTL on spoofed answers — deliberately short so a stopped lab recovers
/// quickly once clients re-query the real resolver.
pub const ANSWER_TTL_SECONDS: u32 = 10;
/// Distinct client tracking cap (bounded memory; the counter stops growing).
pub const MAX_CLIENTS_TRACKED: usize = 256;
/// Stop/scope/runtime re-check cadence while idle on recv.
const PARK_INTERVAL: Duration = Duration::from_millis(150);
/// Upstream relay sockets bind here (loopback ephemeral).
const RELAY_BIND: &str = "127.0.0.1";

// ---------------------------------------------------------------------------
// Error type (mirrors arp_spoof::SpoofError: code discriminator + message).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsErrorCode {
    /// Bad configuration: ports, allowlist entries, answer address, caps.
    InvalidScope,
    /// UDP bind refused (administrator privileges required for low ports).
    Permission,
    /// Socket I/O failure.
    Io,
    /// Run never started because stop was already requested or scope gone.
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSpoofError {
    pub code: DnsErrorCode,
    pub message: String,
}
impl DnsSpoofError {
    pub fn new(code: DnsErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Domain allowlist: the ONLY answering scope. Exact names plus bounded
// leading wildcards. Validated entries are LDH+underscore, 1..=253 bytes.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum AllowlistEntry {
    Exact(String),
    /// Stores the dotted suffix (".domain") of a leading `*.domain` entry.
    Wildcard(String),
}

/// The parsed authorized allowlist. `matches` is the single answering gate:
/// a query name not matched here is forwarded upstream, never answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainAllowlist {
    entries: Vec<AllowlistEntry>,
}

impl DomainAllowlist {
    /// Build from raw entries. REFUSES an empty list (no allowlist, no
    /// answers), anything over the 16-domain cap, malformed labels and
    /// duplicates — refusal, never truncation or silent deduplication.
    pub fn build(entries: &[String]) -> Result<Self, DnsSpoofError> {
        if entries.is_empty() {
            return Err(DnsSpoofError::new(
                DnsErrorCode::InvalidScope,
                "the authorized domain allowlist is empty — the responder refuses to \
                 answer anything without an explicit allowlist",
            ));
        }
        if entries.len() > MAX_DOMAINS {
            return Err(DnsSpoofError::new(
                DnsErrorCode::InvalidScope,
                format!("at most {MAX_DOMAINS} allowlist domains are allowed per session"),
            ));
        }
        let mut out = Vec::new();
        for raw in entries {
            let (value, wildcard) = normalize_domain_entry(raw)?;
            let entry = if wildcard {
                AllowlistEntry::Wildcard(format!(".{value}"))
            } else {
                AllowlistEntry::Exact(value.clone())
            };
            if out.contains(&entry) {
                return Err(DnsSpoofError::new(
                    DnsErrorCode::InvalidScope,
                    format!("duplicate allowlist entry: {raw}"),
                ));
            }
            out.push(entry);
        }
        Ok(Self { entries: out })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Case-insensitive name gate: exact entries match the whole name;
    /// wildcard entries match any name one-or-more labels under the suffix.
    /// The apex of a wildcard entry is NOT matched unless authorized
    /// explicitly as its own exact entry.
    pub fn matches(&self, name: &str) -> bool {
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if name.is_empty() {
            return false;
        }
        self.entries.iter().any(|entry| match entry {
            AllowlistEntry::Exact(exact) => *exact == name,
            AllowlistEntry::Wildcard(suffix) => {
                name.len() > suffix.len() && name.ends_with(suffix.as_str())
            }
        })
    }
}

/// Validate one raw allowlist entry; returns the normalized lowercase value
/// and whether it was a leading `*.` wildcard. Only the leading wildcard is
/// supported (bounded, predictable matching); `*` anywhere else is refused.
fn normalize_domain_entry(raw: &str) -> Result<(String, bool), DnsSpoofError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(DnsSpoofError::new(
            DnsErrorCode::InvalidScope,
            "allowlist entries must not be empty",
        ));
    }
    let (value, wildcard) = match trimmed.strip_prefix("*.") {
        Some(rest) if !rest.is_empty() => (rest, true),
        Some(_) => {
            return Err(DnsSpoofError::new(
                DnsErrorCode::InvalidScope,
                "a bare '*' is not a domain — use '*.domain' to authorize subdomains",
            ));
        }
        None => (trimmed, false),
    };
    let value = value.to_ascii_lowercase();
    if value.contains('*') {
        return Err(DnsSpoofError::new(
            DnsErrorCode::InvalidScope,
            format!("wildcards are only supported as a leading '*.' — {value} mixes '*' into a name"),
        ));
    }
    if value.len() > 253 {
        return Err(DnsSpoofError::new(
            DnsErrorCode::InvalidScope,
            "allowlist entries must be at most 253 bytes",
        ));
    }
    for label in value.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DnsSpoofError::new(
                DnsErrorCode::InvalidScope,
                format!("allowlist label must be 1..=63 characters: {value}"),
            ));
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(DnsSpoofError::new(
                DnsErrorCode::InvalidScope,
                format!("allowlist labels must be letters, digits, '-' or '_': {value}"),
            ));
        }
    }
    Ok((value, wildcard))
}

// ---------------------------------------------------------------------------
// Wire helpers: bounded question extraction + authorized response encoding.
// ---------------------------------------------------------------------------

/// Extract the first question's wire span from a raw query: returns
/// (question_end_offset, qtype, qclass) so the question section can be
/// echoed byte-for-byte into the authorized response. REFUSES compressed
/// question names (a pointer in the question section is not a legal query
/// encoding and cannot be echoed safely) — such queries are forwarded, not
/// spoofed.
fn question_wire_span(data: &[u8]) -> Option<(usize, u16, u16)> {
    if data.len() < 12 {
        return None;
    }
    let mut cursor = 12usize;
    loop {
        let len = *data.get(cursor)?;
        if len == 0 {
            cursor += 1;
            break;
        }
        if len & 0xc0 != 0 {
            return None; // compressed question: refuse to echo
        }
        cursor += 1 + len as usize;
        if cursor > 12 + 256 {
            return None; // name exceeds the wire maximum: refuse
        }
    }
    let end = cursor.checked_add(4)?;
    if end > data.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
    let qclass = u16::from_be_bytes([data[cursor + 2], data[cursor + 3]]);
    Some((end, qtype, qclass))
}

/// Build the authorized response: the client's transaction id and RD bit are
/// echoed, QR+AA+RA set, rcode NOERROR. `answer_ip == Some` yields one A
/// record (pointer to the echoed question, [`ANSWER_TTL_SECONDS`] TTL);
/// `None` yields NODATA (ancount 0) — used for non-A record types so the
/// real address never leaks for an allowlisted name.
fn encode_authorized_response(
    query: &[u8],
    question_end: usize,
    answer_ip: Option<Ipv4Addr>,
) -> Vec<u8> {
    let rd = query.get(2).copied().unwrap_or(0) & 0x01;
    let mut out = Vec::with_capacity(question_end + 16);
    out.extend_from_slice(&query[0..2]); // transaction id echoed
    out.push(0x84 | rd); // QR + AA + opcode 0 + the query's RD bit
    out.push(0x80); // RA, rcode NOERROR
    out.extend_from_slice(&1u16.to_be_bytes()); // qdcount: the echoed question
    out.extend_from_slice(&u16::from(answer_ip.is_some()).to_be_bytes()); // ancount
    out.extend_from_slice(&[0, 0, 0, 0]); // nscount, arcount
    out.extend_from_slice(&query[12..question_end]);
    if let Some(ip) = answer_ip {
        out.extend_from_slice(&[0xc0, 0x0c]); // pointer to the question name
        out.extend_from_slice(&1u16.to_be_bytes()); // type A
        out.extend_from_slice(&1u16.to_be_bytes()); // class IN
        out.extend_from_slice(&ANSWER_TTL_SECONDS.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes()); // rdlength
        out.extend_from_slice(&ip.octets());
    }
    out
}

/// Current wall-clock in epoch milliseconds; 0 keeps log entries honest if
/// the clock is unavailable (0 is documented as unknown provenance).
fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Telemetry: live counters + the bounded request/answer log ring, shared
// with the IPC layer so `status` polls honest numbers mid-run.
// ---------------------------------------------------------------------------

/// One logged request/answer: `answered_from` is "spoof" | "upstream" |
/// "refused" | "rate_limited"; `answer_ip` is the A value for spoofed and
/// relayed answers, None otherwise.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct QueryLogEntry {
    pub timestamp_ms: u64,
    pub client: String,
    pub name: String,
    pub answered_from: String,
    pub answer_ip: Option<String>,
}

/// Live responder state. The engine updates this in place; the embedding IPC
/// layer reads it for the status wire. Every field is bounded.
#[derive(Debug, Default)]
pub struct ResponderTelemetry {
    queries_seen: AtomicU64,
    spoofed_count: AtomicU64,
    forwarded_count: AtomicU64,
    refused_count: AtomicU64,
    rate_limited_count: AtomicU64,
    io_error_count: AtomicU64,
    ring: Mutex<VecDeque<QueryLogEntry>>,
    ring_dropped: AtomicU64,
    clients: Mutex<HashSet<IpAddr>>,
    flushed: AtomicBool,
}

impl ResponderTelemetry {
    /// Fresh-session reset (start command calls this before the worker runs).
    pub fn reset(&self) {
        self.queries_seen.store(0, Ordering::Release);
        self.spoofed_count.store(0, Ordering::Release);
        self.forwarded_count.store(0, Ordering::Release);
        self.refused_count.store(0, Ordering::Release);
        self.rate_limited_count.store(0, Ordering::Release);
        self.io_error_count.store(0, Ordering::Release);
        self.ring_dropped.store(0, Ordering::Release);
        if let Ok(mut ring) = self.ring.lock() {
            ring.clear();
        }
        if let Ok(mut clients) = self.clients.lock() {
            clients.clear();
        }
        self.flushed.store(false, Ordering::Release);
    }

    pub fn queries_seen(&self) -> u64 {
        self.queries_seen.load(Ordering::Acquire)
    }
    pub fn spoofed_count(&self) -> u64 {
        self.spoofed_count.load(Ordering::Acquire)
    }
    pub fn forwarded_count(&self) -> u64 {
        self.forwarded_count.load(Ordering::Acquire)
    }
    pub fn refused_count(&self) -> u64 {
        self.refused_count.load(Ordering::Acquire)
    }
    pub fn rate_limited_count(&self) -> u64 {
        self.rate_limited_count.load(Ordering::Acquire)
    }
    pub fn io_error_count(&self) -> u64 {
        self.io_error_count.load(Ordering::Acquire)
    }
    pub fn ring_dropped(&self) -> u64 {
        self.ring_dropped.load(Ordering::Acquire)
    }
    pub fn clients_seen(&self) -> usize {
        self.clients.lock().map(|g| g.len()).unwrap_or(0)
    }
    pub fn is_flushed(&self) -> bool {
        self.flushed.load(Ordering::Acquire)
    }

    /// Bounded snapshot of the log ring (oldest first).
    pub fn log_snapshot(&self) -> Vec<QueryLogEntry> {
        self.ring
            .lock()
            .map(|ring| ring.iter().cloned().collect())
            .unwrap_or_default()
    }

    fn record_client(&self, ip: IpAddr) {
        if let Ok(mut set) = self.clients.lock() {
            if set.contains(&ip) || set.len() < MAX_CLIENTS_TRACKED {
                set.insert(ip);
            }
        }
    }

    /// Bounded push: past [`MAX_LOG_ENTRIES`] the oldest entry is dropped and
    /// the drop counter grows — honest truncation, never silent loss. Every
    /// logged request also records its client (distinct IPs, bounded set).
    fn push_log(&self, client: &SocketAddr, name: &str, answered_from: &str, answer_ip: Option<String>) {
        self.record_client(client.ip());
        let entry = QueryLogEntry {
            timestamp_ms: unix_ms(),
            client: client.ip().to_string(),
            name: name.chars().take(255).collect(),
            answered_from: answered_from.to_string(),
            answer_ip,
        };
        if let Ok(mut ring) = self.ring.lock() {
            if ring.len() >= MAX_LOG_ENTRIES {
                ring.pop_front();
                self.ring_dropped.fetch_add(1, Ordering::Release);
            }
            ring.push_back(entry);
        }
    }

    pub fn spoof_answer(&self, client: &SocketAddr, name: &str, answer_ip: Option<String>) {
        self.spoofed_count.fetch_add(1, Ordering::Release);
        self.push_log(client, name, "spoof", answer_ip);
    }

    pub fn forward_answer(&self, client: &SocketAddr, name: &str, answer_ip: Option<String>) {
        self.forwarded_count.fetch_add(1, Ordering::Release);
        self.push_log(client, name, "upstream", answer_ip);
    }

    pub fn refuse(&self, client: &SocketAddr, name: &str) {
        self.refused_count.fetch_add(1, Ordering::Release);
        self.push_log(client, name, "refused", None);
    }

    pub fn rate_limit(&self, client: &SocketAddr, name: &str) {
        self.rate_limited_count.fetch_add(1, Ordering::Release);
        self.push_log(client, name, "rate_limited", None);
    }

    fn bump_io_errors(&self) {
        self.io_error_count.fetch_add(1, Ordering::Release);
    }

    fn mark_flushed(&self) {
        self.flushed.store(true, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// Configuration and validation.
// ---------------------------------------------------------------------------

/// One responder session's configuration. `upstream` is explicit (the IPC
/// layer resolves the system resolver via [`system_upstream`]) so tests can
/// point forwards at a mock socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponderConfig {
    /// Address to bind (IPv4 or IPv6; the IPC layer uses 0.0.0.0).
    pub bind_ip: IpAddr,
    /// UDP port (default 53; 1..=65535).
    pub port: u16,
    /// Raw allowlist entries (validated by [`validate_config`]).
    pub domains: Vec<String>,
    /// The authorized A-record answer for allowlisted names.
    pub answer_ip: Ipv4Addr,
    /// Where non-allowlisted queries are forwarded.
    pub upstream: SocketAddr,
    /// Answered/forwarded requests per second (≤ [`MAX_RATE_PER_SEC`]).
    pub rate_per_sec: u32,
    /// Session runtime cap ms (≤ [`MAX_RUNTIME_MS`]; smaller for tests).
    pub runtime_cap_ms: u64,
}

/// Full preflight: port, rate, runtime cap, answer address and allowlist.
/// Refusal, never correction.
pub fn validate_config(config: &ResponderConfig) -> Result<DomainAllowlist, DnsSpoofError> {
    if config.port == 0 {
        return Err(DnsSpoofError::new(
            DnsErrorCode::InvalidScope,
            "the responder port must be 1..=65535",
        ));
    }
    if config.rate_per_sec == 0 || config.rate_per_sec > MAX_RATE_PER_SEC {
        return Err(DnsSpoofError::new(
            DnsErrorCode::InvalidScope,
            format!("rate limit must be 1..={MAX_RATE_PER_SEC} requests/s"),
        ));
    }
    if config.runtime_cap_ms == 0 || config.runtime_cap_ms > MAX_RUNTIME_MS {
        return Err(DnsSpoofError::new(
            DnsErrorCode::InvalidScope,
            format!("runtime cap must be 1..={} minutes", MAX_RUNTIME_MS / 60_000),
        ));
    }
    if config.answer_ip.is_unspecified()
        || config.answer_ip.is_multicast()
        || config.answer_ip.is_broadcast()
    {
        return Err(DnsSpoofError::new(
            DnsErrorCode::InvalidScope,
            format!(
                "authorized answer {0} is not a usable unicast host address",
                config.answer_ip
            ),
        ));
    }
    if config.upstream.port() == 0 {
        return Err(DnsSpoofError::new(
            DnsErrorCode::InvalidScope,
            "the upstream resolver address must carry a port",
        ));
    }
    DomainAllowlist::build(&config.domains)
}

/// Bind the responder socket (preflight validated). A privileged-port bind
/// refusal surfaces as an honest `Permission` error naming the privilege
/// requirement — the UI shows it verbatim.
pub async fn bind_responder(config: &ResponderConfig) -> Result<BoundResponder, DnsSpoofError> {
    validate_config(config)?;
    let addr = SocketAddr::new(config.bind_ip, config.port);
    match UdpSocket::bind(addr).await {
        Ok(socket) => {
            let local_addr = socket.local_addr().map_err(|e| {
                DnsSpoofError::new(DnsErrorCode::Io, format!("query responder local address: {e}"))
            })?;
            Ok(BoundResponder {
                socket: Arc::new(socket),
                local_addr,
            })
        }
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => Err(DnsSpoofError::new(
            DnsErrorCode::Permission,
            format!(
                "binding UDP port {} was refused — DNS answering on ports below 1024 \
                 requires administrator privileges; run elevated or pick a high port",
                config.port
            ),
        )),
        Err(err) => Err(DnsSpoofError::new(
            DnsErrorCode::Io,
            format!("bind UDP responder on {addr}: {err}"),
        )),
    }
}

/// A bound responder socket plus the address clients should query.
#[derive(Debug, Clone)]
pub struct BoundResponder {
    pub socket: Arc<UdpSocket>,
    pub local_addr: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsEndReason {
    OperatorStop,
    ScopeRevoked,
    RuntimeCapReached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponderOutcome {
    pub end_reason: DnsEndReason,
    pub queries_seen: u64,
    pub spoofed_count: u64,
    pub forwarded_count: u64,
    pub refused_count: u64,
    pub rate_limited_count: u64,
    pub elapsed_ms: u64,
}

/// Resolve the system resolver address from /etc/resolv.conf (first
/// nameserver, port 53). Honest error when no resolver can be found — the
/// responder needs an upstream to forward non-allowlisted queries to.
pub fn system_upstream() -> Result<SocketAddr, DnsSpoofError> {
    let text = std::fs::read_to_string("/etc/resolv.conf").map_err(|e| {
        DnsSpoofError::new(
            DnsErrorCode::Io,
            format!("read /etc/resolv.conf for the upstream resolver: {e}"),
        )
    })?;
    for line in text.lines().take(128) {
        let line = line.trim();
        if let Some(server) = line.strip_prefix("nameserver") {
            if let Ok(ip) = server.trim().parse::<IpAddr>() {
                return Ok(SocketAddr::new(ip, 53));
            }
        }
    }
    Err(DnsSpoofError::new(
        DnsErrorCode::Io,
        "no nameserver entry found in /etc/resolv.conf — forwarding needs an upstream \
         resolver",
    ))
}

/// Allocate a free localhost UDP port for tests (probe socket closed before
/// the responder rebinds it; the race is accepted on loopback only).
pub fn allocate_free_port() -> u16 {
    std::net::UdpSocket::bind((RELAY_BIND, 0))
        .expect("bind ephemeral probe socket")
        .local_addr()
        .expect("probe local address")
        .port()
}

// ---------------------------------------------------------------------------
// The responder loop.
// ---------------------------------------------------------------------------

/// The authorized entry point: run the bound responder until operator stop,
/// scope revocation or the runtime cap. Every received datagram is parsed
/// with the crate's bounded DNS parser; allowlisted A queries are answered
/// with the authorized address, allowlisted non-A queries get NODATA, and
/// everything else is forwarded upstream (bounded timeout, bounded
/// concurrency) and relayed. On ANY end the telemetry ring is frozen and
/// marked flushed before the outcome is returned.
pub async fn run_responder(
    bound: BoundResponder,
    config: ResponderConfig,
    stop: Arc<AtomicBool>,
    scope_active: Arc<dyn Fn() -> bool + Send + Sync>,
    telemetry: Arc<ResponderTelemetry>,
) -> Result<ResponderOutcome, DnsSpoofError> {
    let allowlist = validate_config(&config)?;
    let forward_permits = Arc::new(Semaphore::new(MAX_CONCURRENT_FORWARDS));
    let started = std::time::Instant::now();
    let mut window: VecDeque<std::time::Instant> = VecDeque::new();
    let mut buf = vec![0u8; MAX_QUERY_BYTES];
    let mut tick = tokio::time::interval(PARK_INTERVAL);
    let end_reason = loop {
        tokio::select! {
            _ = tick.tick() => {
                if stop.load(Ordering::Acquire) {
                    break DnsEndReason::OperatorStop;
                }
                if !(scope_active)() {
                    break DnsEndReason::ScopeRevoked;
                }
                if started.elapsed() >= Duration::from_millis(config.runtime_cap_ms) {
                    break DnsEndReason::RuntimeCapReached;
                }
            }
            received = bound.socket.recv_from(&mut buf) => {
                let (size, client) = match received {
                    Ok(value) => value,
                    Err(_) => {
                        telemetry.bump_io_errors();
                        continue;
                    }
                };
                if stop.load(Ordering::Acquire) {
                    break DnsEndReason::OperatorStop;
                }
                let datagram = &buf[..size];
                let Some(summary) = parse_dns(datagram) else {
                    telemetry.refuse(&client, "(unparseable)");
                    continue;
                };
                // A response arriving at a resolver port is never answered or
                // forwarded — it is refused (and logged) as unusable input.
                if summary.is_response {
                    telemetry.refuse(&client, "(response)");
                    continue;
                }
                let Some(question) = &summary.first_question else {
                    telemetry.refuse(&client, "(no question)");
                    continue;
                };
                telemetry.queries_seen.fetch_add(1, Ordering::Release);
                // Sliding 1-second window: admitted requests (spoof or
                // forward) enter the window; excess is dropped and counted.
                let now = std::time::Instant::now();
                while let Some(front) = window.front() {
                    if now.duration_since(*front) > Duration::from_secs(1) {
                        window.pop_front();
                    } else {
                        break;
                    }
                }
                if window.len() >= config.rate_per_sec as usize {
                    telemetry.rate_limit(&client, &question.name);
                    continue;
                }
                window.push_back(now);
                if allowlist.matches(&question.name) {
                    answer_authorized(
                        &bound.socket,
                        datagram,
                        &client,
                        &question.name,
                        config.answer_ip,
                        &telemetry,
                    )
                    .await;
                } else {
                    let Ok(permit) = forward_permits.clone().try_acquire_owned() else {
                        telemetry.refuse(&client, &question.name);
                        continue;
                    };
                    tokio::spawn(forward_upstream(
                        datagram.to_vec(),
                        client,
                        question.name.clone(),
                        Arc::clone(&bound.socket),
                        config.upstream,
                        Arc::clone(&telemetry),
                        permit,
                    ));
                }
            }
        }
    };
    // Final log flush: the ring is frozen as-is, marked flushed and stays
    // readable through the status wire. Nothing is answered after stop.
    telemetry.mark_flushed();
    Ok(ResponderOutcome {
        end_reason,
        queries_seen: telemetry.queries_seen(),
        spoofed_count: telemetry.spoofed_count(),
        forwarded_count: telemetry.forwarded_count(),
        refused_count: telemetry.refused_count(),
        rate_limited_count: telemetry.rate_limited_count(),
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

/// Answer one allowlisted query: A questions get the authorized address;
/// any other record type gets an empty NOERROR so the real upstream answer
/// for an allowlisted name can never leak through this responder.
async fn answer_authorized(
    socket: &UdpSocket,
    datagram: &[u8],
    client: &SocketAddr,
    name: &str,
    answer_ip: Ipv4Addr,
    telemetry: &ResponderTelemetry,
) {
    let Some((question_end, qtype, qclass)) = question_wire_span(datagram) else {
        telemetry.refuse(client, name);
        return;
    };
    if qclass != 1 {
        // Only IN-class questions are answered; anything else is refused.
        telemetry.refuse(client, name);
        return;
    }
    let answer = if qtype == 1 { Some(answer_ip) } else { None };
    let response = encode_authorized_response(datagram, question_end, answer);
    let _ = socket.send_to(&response, client).await;
    telemetry.spoof_answer(client, name, answer.map(|ip| ip.to_string()));
}

/// Forward one non-allowlisted query to the upstream resolver and relay the
/// response to the client from OUR bound port (clients expect the answer
/// from the resolver port they queried). Bounded: one datagram reply, 3 s
/// timeout, semaphore permit held for the attempt. On timeout or failure the
/// forward is dropped and counted as refused — nothing is invented.
async fn forward_upstream(
    query: Vec<u8>,
    client: SocketAddr,
    name: String,
    socket: Arc<UdpSocket>,
    upstream: SocketAddr,
    telemetry: Arc<ResponderTelemetry>,
    _permit: OwnedSemaphorePermit,
) {
    let attempt = timeout(
        Duration::from_millis(UPSTREAM_TIMEOUT_MS),
        async {
            let relay = UdpSocket::bind((RELAY_BIND, 0)).await?;
            relay.send_to(&query, upstream).await?;
            let mut buf = vec![0u8; MAX_QUERY_BYTES];
            let (size, _) = relay.recv_from(&mut buf).await?;
            Ok::<Vec<u8>, std::io::Error>(buf[..size].to_vec())
        },
    )
    .await;
    match attempt {
        Ok(Ok(response)) => {
            let answer_ip = parse_dns(&response)
                .and_then(|summary| {
                    summary
                        .answer_records
                        .into_iter()
                        .find(|record| record.record_type == 1)
                })
                .map(|record| record.value);
            let _ = socket.send_to(&response, client).await;
            telemetry.forward_answer(&client, &name, answer_ip);
        }
        _ => {
            telemetry.refuse(&client, &format!("{name} (upstream timeout)"));
        }
    }
}

// ---------------------------------------------------------------------------
// Tests: real UDP datagrams on localhost, a mock upstream socket, bounded
// clocks. Fully self-contained; no privileges required.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn a_query(txid: u16, name: &str) -> Vec<u8> {
        encode_query(txid, name, 1)
    }

    fn encode_query(txid: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&txid.to_be_bytes());
        out.extend_from_slice(&[0x01, 0x00]); // RD set, standard query
        out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // ancount, nscount, arcount
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // class IN
        out
    }

    fn test_config(domains: &[&str], port: u16, upstream: SocketAddr) -> ResponderConfig {
        ResponderConfig {
            bind_ip: IpAddr::from([127, 0, 0, 1]),
            port,
            domains: domains.iter().map(|d| d.to_string()).collect(),
            answer_ip: Ipv4Addr::new(10, 0, 0, 42),
            upstream,
            rate_per_sec: MAX_RATE_PER_SEC,
            runtime_cap_ms: MAX_RUNTIME_MS,
        }
    }

    async fn spawn_responder(
        config: ResponderConfig,
    ) -> (
        SocketAddr,
        Arc<AtomicBool>,
        Arc<ResponderTelemetry>,
        tokio::task::JoinHandle<Result<ResponderOutcome, DnsSpoofError>>,
    ) {
        let bound = bind_responder(&config).await.expect("bind responder");
        let addr = bound.local_addr;
        let stop = Arc::new(AtomicBool::new(false));
        let telemetry = Arc::new(ResponderTelemetry::default());
        let handle = tokio::spawn(run_responder(
            bound,
            config,
            Arc::clone(&stop),
            Arc::new(|| true),
            Arc::clone(&telemetry),
        ));
        (addr, stop, telemetry, handle)
    }

    async fn stop_and_join(
        stop: &AtomicBool,
        handle: tokio::task::JoinHandle<Result<ResponderOutcome, DnsSpoofError>>,
    ) -> ResponderOutcome {
        stop.store(true, Ordering::Release);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("responder joins after stop")
            .expect("responder task")
            .expect("responder outcome")
    }

    /// Mock upstream: replies to at most `max_queries` A queries with the
    /// given answer; counts received queries.
    async fn spawn_mock_upstream(
        answer: [u8; 4],
        max_queries: usize,
    ) -> (SocketAddr, Arc<AtomicUsize>) {
        let socket = UdpSocket::bind((RELAY_BIND, 0)).await.expect("mock bind");
        let addr = socket.local_addr().expect("mock local addr");
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_worker = Arc::clone(&hits);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..max_queries {
                let (size, client) = match socket.recv_from(&mut buf).await {
                    Ok(value) => value,
                    Err(_) => break,
                };
                hits_worker.fetch_add(1, Ordering::SeqCst);
                let mut response = buf[..size].to_vec();
                response[2] = 0x81; // QR + RD
                response[3] = 0x80; // RA
                response[6] = 0;
                response[7] = 1; // ancount = 1
                response.extend_from_slice(&[
                    0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4,
                ]);
                response.extend_from_slice(&answer);
                let _ = socket.send_to(&response, client).await;
            }
        });
        (addr, hits)
    }

    async fn exchange(
        client: &UdpSocket,
        target: SocketAddr,
        query: &[u8],
        ms: u64,
    ) -> Option<Vec<u8>> {
        client.send_to(query, target).await.ok()?;
        let mut buf = vec![0u8; 2048];
        let received = timeout(Duration::from_millis(ms), client.recv_from(&mut buf))
            .await
            .ok()?
            .ok()?;
        Some(buf[..received.0].to_vec())
    }

    async fn wait_until(check: impl Fn() -> bool, ms: u64) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_millis(ms);
        while std::time::Instant::now() < deadline {
            if check() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
        check()
    }

    #[tokio::test]
    async fn allowlisted_exact_query_gets_the_authorized_a_answer() {
        let (upstream, _hits) = spawn_mock_upstream([203, 0, 113, 9], 4).await;
        let (addr, stop, telemetry, handle) =
            spawn_responder(test_config(&["lab.test"], allocate_free_port(), upstream)).await;
        let client = UdpSocket::bind((RELAY_BIND, 0)).await.expect("client bind");
        let response = exchange(&client, addr, &a_query(0x1122, "lab.test"), 2000)
            .await
            .expect("spoofed answer arrives");
        let summary = parse_dns(&response).expect("answer parses");
        assert!(summary.is_response);
        assert_eq!(summary.transaction_id, 0x1122);
        assert_eq!(summary.first_question.as_ref().unwrap().name, "lab.test");
        assert_eq!(
            summary.answer_records[0].value,
            "10.0.0.42",
            "the authorized address is the answer, never the upstream's"
        );
        let outcome = stop_and_join(&stop, handle).await;
        assert_eq!(outcome.end_reason, DnsEndReason::OperatorStop);
        assert_eq!(outcome.queries_seen, 1);
        assert_eq!(outcome.spoofed_count, 1);
        assert_eq!(outcome.forwarded_count, 0);
        assert_eq!(telemetry.clients_seen(), 1);
        let log = telemetry.log_snapshot();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].answered_from, "spoof");
        assert_eq!(log[0].answer_ip.as_deref(), Some("10.0.0.42"));
        assert!(telemetry.is_flushed(), "stop flushes the log ring");
    }

    #[tokio::test]
    async fn wildcard_matches_subdomains_but_the_apex_is_forwarded_without_an_exact_entry() {
        let (upstream, hits) = spawn_mock_upstream([198, 51, 100, 7], 4).await;
        let (addr, stop, telemetry, handle) =
            spawn_responder(test_config(&["*.wild.test"], allocate_free_port(), upstream)).await;
        let client = UdpSocket::bind((RELAY_BIND, 0)).await.expect("client bind");
        // Subdomain (even multi-label) matches the wildcard and is spoofed.
        let response = exchange(&client, addr, &a_query(1, "host.wild.test"), 2000)
            .await
            .expect("spoofed subdomain answer");
        assert_eq!(
            parse_dns(&response).unwrap().answer_records[0].value,
            "10.0.0.42"
        );
        // A deeper subdomain still matches the bounded wildcard.
        let response = exchange(&client, addr, &a_query(2, "a.b.wild.test"), 2000)
            .await
            .expect("spoofed deep subdomain answer");
        assert_eq!(
            parse_dns(&response).unwrap().answer_records[0].value,
            "10.0.0.42"
        );
        // The apex is NOT covered by "*.wild.test": forwarded upstream and
        // the mock's answer is relayed verbatim.
        let response = exchange(&client, addr, &a_query(3, "wild.test"), 2000)
            .await
            .expect("relayed upstream answer");
        let summary = parse_dns(&response).expect("relay parses");
        assert_eq!(
            summary.answer_records[0].value,
            "198.51.100.7",
            "non-allowlisted names get the upstream answer, not the spoof"
        );
        let outcome = stop_and_join(&stop, handle).await;
        assert_eq!(outcome.spoofed_count, 2);
        assert_eq!(outcome.forwarded_count, 1);
        assert_eq!(hits.load(Ordering::SeqCst), 1, "only the apex hit upstream");
        let log = telemetry.log_snapshot();
        assert_eq!(log[2].answered_from, "upstream");
        assert_eq!(log[2].answer_ip.as_deref(), Some("198.51.100.7"));
    }

    #[tokio::test]
    async fn forwarded_queries_relay_the_upstream_response_within_the_bounded_timeout() {
        let (upstream, hits) = spawn_mock_upstream([192, 0, 2, 77], 4).await;
        let (addr, stop, _telemetry, handle) =
            spawn_responder(test_config(&["lab.test"], allocate_free_port(), upstream)).await;
        let client = UdpSocket::bind((RELAY_BIND, 0)).await.expect("client bind");
        let response = exchange(&client, addr, &a_query(0x0A0B, "other.example"), 2000)
            .await
            .expect("relayed answer arrives");
        let summary = parse_dns(&response).expect("relay parses");
        assert_eq!(summary.transaction_id, 0x0A0B, "txid preserved end to end");
        assert_eq!(summary.answer_records[0].value, "192.0.2.77");
        let outcome = stop_and_join(&stop, handle).await;
        assert_eq!(outcome.forwarded_count, 1);
        assert_eq!(outcome.spoofed_count, 0);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn malformed_and_response_datagrams_are_refused_not_answered_or_forwarded() {
        let (upstream, hits) = spawn_mock_upstream([203, 0, 113, 9], 4).await;
        let (addr, stop, telemetry, handle) =
            spawn_responder(test_config(&["lab.test"], allocate_free_port(), upstream)).await;
        let client = UdpSocket::bind((RELAY_BIND, 0)).await.expect("client bind");
        // Garbage bytes.
        client.send_to(&[0xde, 0xad, 0xbe, 0xef], addr).await.unwrap();
        // A RESPONSE packet arriving at the resolver port.
        let mut reply = a_query(9, "lab.test");
        reply[2] = 0x81;
        client.send_to(&reply, addr).await.unwrap();
        // A query claiming an absurd question count (parser refuses).
        let mut bogus = a_query(10, "lab.test");
        bogus[4] = 0xff;
        bogus[5] = 0xff;
        client.send_to(&bogus, addr).await.unwrap();
        let refused = wait_until(|| telemetry.refused_count() == 3, 2000).await;
        assert!(refused, "all three datagrams refused: {:?}", telemetry.log_snapshot());
        // No client receives anything for them.
        let mut buf = [0u8; 512];
        let nothing = timeout(Duration::from_millis(300), client.recv_from(&mut buf)).await;
        assert!(nothing.is_err(), "refused datagrams must not be answered");
        assert_eq!(hits.load(Ordering::SeqCst), 0, "malformed bytes never forwarded");
        let outcome = stop_and_join(&stop, handle).await;
        assert_eq!(outcome.refused_count, 3);
        assert_eq!(outcome.queries_seen, 0);
    }

    #[tokio::test]
    async fn rate_limit_drops_requests_beyond_the_configured_rate() {
        let (upstream, _hits) = spawn_mock_upstream([203, 0, 113, 9], 4).await;
        let mut config = test_config(&["lab.test"], allocate_free_port(), upstream);
        config.rate_per_sec = 2;
        let (addr, stop, telemetry, handle) = spawn_responder(config).await;
        let client = UdpSocket::bind((RELAY_BIND, 0)).await.expect("client bind");
        for txid in 1..=5u16 {
            client.send_to(&a_query(txid, "lab.test"), addr).await.unwrap();
        }
        let drained =
            wait_until(|| telemetry.spoofed_count() + telemetry.rate_limited_count() == 5, 3000)
                .await;
        assert!(drained, "every request is accounted for");
        let outcome = stop_and_join(&stop, handle).await;
        assert_eq!(outcome.spoofed_count, 2, "only the first window admits");
        assert_eq!(outcome.rate_limited_count, 3, "the burst excess is dropped");
        let log = telemetry.log_snapshot();
        assert_eq!(log[0].answered_from, "spoof");
        assert_eq!(log[2].answered_from, "rate_limited");
    }

    #[tokio::test]
    async fn runtime_cap_auto_stops_the_responder() {
        let (upstream, _hits) = spawn_mock_upstream([203, 0, 113, 9], 4).await;
        let mut config = test_config(&["lab.test"], allocate_free_port(), upstream);
        config.runtime_cap_ms = 150;
        let (_addr, _stop, telemetry, handle) = spawn_responder(config).await;
        let outcome = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("cap fires promptly")
            .expect("task joins")
            .expect("outcome");
        assert_eq!(outcome.end_reason, DnsEndReason::RuntimeCapReached);
        assert!(outcome.elapsed_ms >= 150);
        assert_eq!(outcome.queries_seen, 0);
        assert!(telemetry.is_flushed());
    }

    #[tokio::test]
    async fn operator_stop_keeps_the_final_log_readable_and_flushed() {
        let (upstream, _hits) = spawn_mock_upstream([203, 0, 113, 9], 4).await;
        let (addr, stop, telemetry, handle) =
            spawn_responder(test_config(&["lab.test"], allocate_free_port(), upstream)).await;
        let client = UdpSocket::bind((RELAY_BIND, 0)).await.expect("client bind");
        exchange(&client, addr, &a_query(7, "lab.test"), 2000).await.expect("answer");
        assert!(wait_until(|| telemetry.spoofed_count() == 1, 2000).await);
        let outcome = stop_and_join(&stop, handle).await;
        assert_eq!(outcome.end_reason, DnsEndReason::OperatorStop);
        assert!(telemetry.is_flushed());
        let log = telemetry.log_snapshot();
        assert_eq!(log.len(), 1, "the final log stays readable after stop");
        assert_eq!(log[0].name, "lab.test");
        assert_eq!(log[0].answered_from, "spoof");
        assert!(log[0].timestamp_ms > 0);
    }

    #[test]
    fn log_ring_is_bounded_with_an_honest_drop_count() {
        let telemetry = ResponderTelemetry::default();
        let client: SocketAddr = "127.0.0.1:53001".parse().unwrap();
        for i in 0..(MAX_LOG_ENTRIES + 33) {
            telemetry.spoof_answer(&client, &format!("host{i}.lab.test"), Some("10.0.0.42".into()));
        }
        assert_eq!(telemetry.log_snapshot().len(), MAX_LOG_ENTRIES);
        assert_eq!(telemetry.ring_dropped(), 33);
        assert_eq!(
            telemetry.log_snapshot()[0].name,
            "host33.lab.test",
            "the OLDEST entries are the ones dropped"
        );
    }

    #[test]
    fn allowlist_validation_refuses_oversized_malformed_or_duplicate_entries() {
        let entries = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        // Empty: no allowlist, no answers.
        assert!(DomainAllowlist::build(&entries(&[])).is_err());
        // Over the cap: refusal, not truncation.
        let over: Vec<String> = (0..MAX_DOMAINS + 1).map(|i| format!("d{i}.test")).collect();
        let err = DomainAllowlist::build(&over).unwrap_err();
        assert!(err.message.contains("at most 16"), "{err:?}");
        // Malformed entries.
        assert!(DomainAllowlist::build(&entries(&["bad entry!"])).is_err());
        assert!(DomainAllowlist::build(&entries(&["a..b.test"])).is_err());
        assert!(DomainAllowlist::build(&entries(&["*"])).is_err());
        assert!(DomainAllowlist::build(&entries(&["x.*.y.test"])).is_err());
        assert!(DomainAllowlist::build(&entries(&[""])).is_err());
        // Duplicates are refused (exact-exact and exact-wildcard overlap).
        assert!(DomainAllowlist::build(&entries(&["a.test", "a.test"])).is_err());
        assert!(DomainAllowlist::build(&entries(&["*.a.test", "*.a.test"])).is_err());
        // A valid 16-entry list with wildcards builds.
        let full: Vec<String> = (0..MAX_DOMAINS).map(|i| format!("*.w{i}.test")).collect();
        let list = DomainAllowlist::build(&full).expect("16 wildcard entries ok");
        assert_eq!(list.len(), MAX_DOMAINS);
        assert!(list.matches("host.w3.test"));
        assert!(!list.matches("w3.test"));
        assert!(!list.matches("host.w3.test.evil.example"), "suffix must end at a label");
        // Case-insensitive and trailing-dot tolerant.
        let list = DomainAllowlist::build(&entries(&["Lab.Test", "*.Wild.Test"])).unwrap();
        assert!(list.matches("LAB.TEST"));
        assert!(list.matches("Host.Wild.Test."));
    }

    #[tokio::test]
    async fn non_a_questions_for_allowlisted_names_get_nodata_never_the_real_answer() {
        let (upstream, hits) = spawn_mock_upstream([203, 0, 113, 9], 4).await;
        let (addr, stop, telemetry, handle) =
            spawn_responder(test_config(&["lab.test"], allocate_free_port(), upstream)).await;
        let client = UdpSocket::bind((RELAY_BIND, 0)).await.expect("client bind");
        let response = exchange(&client, addr, &encode_query(0x22, "lab.test", 28), 2000)
            .await
            .expect("NODATA answer arrives");
        let summary = parse_dns(&response).expect("NODATA parses");
        assert!(summary.is_response);
        assert_eq!(summary.answers, 0, "AAAA gets an empty answer, no records");
        assert_eq!(summary.response_code, 0);
        let outcome = stop_and_join(&stop, handle).await;
        assert_eq!(outcome.spoofed_count, 1, "NODATA still counts as our answer");
        assert_eq!(outcome.forwarded_count, 0);
        assert_eq!(hits.load(Ordering::SeqCst), 0, "the real AAAA never leaks upstream");
        assert_eq!(telemetry.log_snapshot()[0].answer_ip, None);
    }

    #[test]
    fn clients_seen_counts_distinct_clients_only_up_to_the_bound() {
        // Every logged request records its client; repeats stay one client.
        let telemetry = ResponderTelemetry::default();
        let client_a: SocketAddr = "10.0.0.5:53001".parse().unwrap();
        let client_b: SocketAddr = "10.0.0.9:53002".parse().unwrap();
        telemetry.spoof_answer(&client_a, "lab.test", Some("10.0.0.42".into()));
        telemetry.spoof_answer(&client_a, "lab.test", Some("10.0.0.42".into()));
        assert_eq!(telemetry.clients_seen(), 1);
        telemetry.spoof_answer(&client_b, "lab.test", Some("10.0.0.42".into()));
        assert_eq!(telemetry.clients_seen(), 2);
        // Fill to the tracking bound; further clients are not recorded but
        // their requests are still logged (bounded memory, honest counts).
        for i in 0..MAX_CLIENTS_TRACKED.saturating_sub(2) {
            let octet4 = (i % 254 + 1) as u8;
            let client: SocketAddr = format!("10.0.1.{octet4}:53000").parse().unwrap();
            telemetry.spoof_answer(&client, "lab.test", Some("10.0.0.42".into()));
        }
        assert_eq!(telemetry.clients_seen(), MAX_CLIENTS_TRACKED);
        let extra: SocketAddr = "10.99.99.99:53000".parse().unwrap();
        telemetry.spoof_answer(&extra, "lab.test", Some("10.0.0.42".into()));
        assert_eq!(telemetry.clients_seen(), MAX_CLIENTS_TRACKED, "bounded tracking");
        assert_eq!(
            telemetry.log_snapshot().len(),
            MAX_CLIENTS_TRACKED + 2,
            "all requests are still logged even past the client bound"
        );
    }

    #[tokio::test]
    async fn bind_refuses_privileged_ports_with_an_honest_error() {
        if std::env::var("USER").as_deref() == Ok("root") {
            return; // root can bind low ports; the honesty claim does not apply
        }
        let (upstream, _hits) = spawn_mock_upstream([203, 0, 113, 9], 1).await;
        let config = test_config(&["lab.test"], 1, upstream);
        let err = bind_responder(&config).await.unwrap_err();
        assert_eq!(err.code, DnsErrorCode::Permission);
        assert!(err.message.contains("administrator privileges"), "{err:?}");
    }

    #[test]
    fn configuration_bounds_are_enforced_before_any_socket_exists() {
        let upstream: SocketAddr = "127.0.0.1:15353".parse().unwrap();
        // port 0 refused
        let mut config = test_config(&["lab.test"], 0, upstream);
        assert!(validate_config(&config).is_err());
        // rate bounds
        config = test_config(&["lab.test"], 53, upstream);
        config.rate_per_sec = 0;
        assert!(validate_config(&config).is_err());
        config.rate_per_sec = MAX_RATE_PER_SEC + 1;
        assert!(validate_config(&config).is_err());
        // runtime cap bounds
        config.rate_per_sec = DEFAULT_RATE_PER_SEC;
        config.runtime_cap_ms = 0;
        assert!(validate_config(&config).is_err());
        config.runtime_cap_ms = MAX_RUNTIME_MS + 1;
        assert!(validate_config(&config).is_err());
        config.runtime_cap_ms = MAX_RUNTIME_MS;
        // unusable answer addresses
        config.answer_ip = Ipv4Addr::UNSPECIFIED;
        assert!(validate_config(&config).is_err());
        config.answer_ip = Ipv4Addr::new(224, 0, 0, 1);
        assert!(validate_config(&config).is_err());
        config.answer_ip = Ipv4Addr::new(10, 0, 0, 42);
        // upstream without a port
        config.upstream = "127.0.0.1:0".parse().unwrap();
        assert!(validate_config(&config).is_err());
        config.upstream = upstream;
        // empty allowlist refused even with everything else valid
        config.domains.clear();
        assert!(validate_config(&config).is_err());
        config.domains = vec!["lab.test".to_string()];
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn question_span_and_encoder_reject_compressed_or_short_questions() {
        let query = a_query(1, "lab.test");
        let (end, qtype, qclass) = question_wire_span(&query).expect("plain question spans");
        assert_eq!(qtype, 1);
        assert_eq!(qclass, 1);
        assert_eq!(end, query.len());
        // Compressed question name: refuse (forward instead of spoof).
        let mut compressed = query.clone();
        compressed[12] = 0xc0;
        compressed[13] = 0x0c;
        assert!(question_wire_span(&compressed).is_none());
        // Truncated question tail: refuse.
        assert!(question_wire_span(&query[..query.len() - 2]).is_none());
        // Encoder: A answer bytes match a hand-built fixture.
        let packet = encode_authorized_response(&query, end, Some(Ipv4Addr::new(10, 0, 0, 42)));
        assert_eq!(&packet[0..2], &[0x00, 0x01], "txid echoed");
        assert_eq!(&packet[2..4], &[0x85, 0x80], "QR|AA|RD|RA, NOERROR");
        assert_eq!(&packet[4..6], &1u16.to_be_bytes(), "qdcount");
        assert_eq!(&packet[6..8], &1u16.to_be_bytes(), "ancount");
        let answer = &packet[query.len()..];
        assert_eq!(answer, &[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 10, 0, 4, 10, 0, 0, 42]);
        // NODATA: ancount 0 and no answer section.
        let nodata = encode_authorized_response(&query, end, None);
        assert_eq!(&nodata[6..8], &0u16.to_be_bytes());
        assert_eq!(nodata.len(), query.len());
    }
}
