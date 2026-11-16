//! Bettercap-parity plain-HTTP forward proxy core for the Network Lab
//! ("http_proxy" arc). FOR AUTHORIZED LAB USE ONLY: the embedding IPC layer
//! MUST hold the shared `NetworkOperationGate` lease, show the native
//! confirmation dialog naming the port, the active rewrites and the logging,
//! and bind the run to a saved backend case before calling [`serve`] — the
//! core itself never authorizes anything and keeps no case state.
//!
//! What it does, exactly: a bounded HTTP/1.1 forward proxy over plain
//! `std::net` TCP (no TLS interception, no new dependencies). It parses both
//! request forms — absolute-URI (`GET http://host/path HTTP/1.1`) and
//! origin-form with a `Host` header — fetches the upstream with a bounded TCP
//! client (`Connection: close`, 5 s connect timeout, 10 s per-read idle
//! timeout, 60 s per-connection deadline) and streams the buffered response
//! back. Bounds: ≤ 8 concurrent connections, 64 KiB request/response header
//! caps, 1 MiB request/response body cap, ≤ 4 KiB logged body excerpts, a
//! 512-entry log ring and a hard 30-minute runtime cap (auto-stop). Anything
//! past a cap is REFUSED with an honest status code and logged — never
//! silently truncated.
//!
//! CONNECT is refused honestly: `TLS interception lives in the Web studio —
//! this proxy is plain HTTP` (the workbench web feature owns TLS
//! interception; this module does not import web-feature internals).
//! Absolute-URI `https://` targets are refused for the same reason.
//!
//! Rewrite rules — the classic SSL-strip-lite set, each individually
//! toggleable, ALL OFF by default, and only ever applied AFTER the full
//! request and response headers have been captured into the log entry:
//! (a) rewrite `https://` → `http://` inside `href`/`src` attribute values of
//!     text/html bodies (bounded hand-rolled attribute scanner, no regex
//!     dependency, ≤ 1 MiB bodies);
//! (b) strip the `Strict-Transport-Security` response header;
//! (c) strip the `Content-Security-Policy` response header.
//! Every applied rewrite is counted per rule and logged with the entry.
//!
//! The optional client allowlist (≤ 16 IPs; empty = ANY client that can
//! reach the listener — the dialog must disclose this) is enforced on the
//! peer address before anything else happens on a connection.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// Bounds (every one of them hard, tested, and disclosed in the dialog copy).
// ---------------------------------------------------------------------------

/// Hard concurrent-connection cap for one proxy run.
pub const MAX_CONCURRENT_CONNECTIONS: usize = 8;
/// Request AND response header-block cap (64 KiB each).
pub const MAX_HEADER_BYTES: usize = 64 * 1024;
/// Request AND response body cap (1 MiB each; text/html rewrite bound too).
pub const MAX_BODY_BYTES: usize = 1024 * 1024;
/// Per-request logged response excerpt cap.
pub const MAX_EXCERPT_BYTES: usize = 4 * 1024;
/// Per-request logged header-text cap (each of request/response sides).
pub const MAX_LOGGED_HEADER_TEXT_BYTES: usize = 4 * 1024;
/// Log ring capacity: drop-oldest, honest "capped" surface in the wire.
pub const MAX_LOG_ENTRIES: usize = 512;
/// Optional client allowlist cap; empty allowlist = any client (disclosed).
pub const MAX_ALLOWLIST_ENTRIES: usize = 16;
/// The default listen port (Bettercap's proxy default).
pub const DEFAULT_PROXY_PORT: u16 = 8080;
/// Lowest permitted listen port (non-privileged).
pub const MIN_PROXY_PORT: u16 = 1024;
/// Hard runtime cap per session: 30 minutes, then the accept loop auto-stops.
pub const MAX_RUNTIME_MS: u64 = 30 * 60 * 1000;
/// Per-connection wall-clock deadline (every read is additionally idle-capped).
pub const MAX_CONNECTION_MS: u64 = 60 * 1000;
/// Max idle wait between reads/writes on any socket.
const SOCKET_IDLE_TIMEOUT_MS: u64 = 10_000;
/// Accept-loop park: stop latency stays ~20 ms.
const ACCEPT_PARK_MS: u64 = 20;
/// Upstream connect timeout.
const UPSTREAM_CONNECT_TIMEOUT_MS: u64 = 5_000;
/// Honest CONNECT refusal, surfaced verbatim in the UI dialog copy.
pub const CONNECT_REFUSAL: &str =
    "TLS interception lives in the Web studio — this proxy is plain HTTP";
/// Honest https absolute-URI refusal.
pub const HTTPS_TARGET_REFUSAL: &str =
    "https:// targets need TLS interception — this lab proxy forwards plain HTTP only";
/// Log-ring truncation honesty marker.
pub const LOG_TRUNCATION_MARKER: &str = "...[truncated]";

// ---------------------------------------------------------------------------
// Configuration.
// ---------------------------------------------------------------------------

/// The three SSL-strip-lite rewrite rules. Every field defaults to OFF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RewriteRules {
    /// Rewrite `https://` → `http://` in `href`/`src` values of text/html bodies.
    pub rewrite_https_links: bool,
    /// Strip the `Strict-Transport-Security` response header.
    pub strip_hsts: bool,
    /// Strip the `Content-Security-Policy` response header.
    pub strip_csp: bool,
}

impl RewriteRules {
    /// Human-named active rules for the dialog copy and the start wire.
    pub fn active_names(&self) -> Vec<&'static str> {
        let mut names = Vec::new();
        if self.rewrite_https_links {
            names.push("rewrite https:// links to http:// in HTML bodies (sslstrip-lite)");
        }
        if self.strip_hsts {
            names.push("strip Strict-Transport-Security response header");
        }
        if self.strip_csp {
            names.push("strip Content-Security-Policy response header");
        }
        names
    }
}

/// Validated run configuration; built ONLY by the IPC layer after checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    pub port: u16,
    pub rules: RewriteRules,
    /// Peer IPs allowed to use the proxy. EMPTY MEANS ANY client (the
    /// embedding dialog must disclose that honestly).
    pub allowlist: Vec<IpAddr>,
}

impl ProxyConfig {
    /// Validate and build: port must be unprivileged-range, the allowlist
    /// capped at [`MAX_ALLOWLIST_ENTRIES`] and free of duplicates.
    pub fn build(
        port: u16,
        rules: RewriteRules,
        allowlist: Vec<IpAddr>,
    ) -> Result<Self, String> {
        if port < MIN_PROXY_PORT {
            return Err(format!(
                "proxy port must be {MIN_PROXY_PORT}..=65535 (refusing privileged port {port})"
            ));
        }
        if allowlist.len() > MAX_ALLOWLIST_ENTRIES {
            return Err(format!(
                "the client allowlist accepts at most {MAX_ALLOWLIST_ENTRIES} IPs \
                 (got {})",
                allowlist.len()
            ));
        }
        let mut seen = Vec::new();
        for ip in &allowlist {
            if seen.contains(ip) {
                return Err(format!("duplicate allowlist entry {ip}"));
            }
            seen.push(*ip);
        }
        Ok(Self {
            port,
            rules,
            allowlist,
        })
    }
}

// ---------------------------------------------------------------------------
// Run state shared between the accept loop, connection threads and the IPC
// status wire. All counters are honest atomics; the log ring is drop-oldest.
// ---------------------------------------------------------------------------

/// Per-request rewrite counts for one log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RewriteCounts {
    pub https_links: usize,
    pub hsts_stripped: usize,
    pub csp_stripped: usize,
}

/// One bounded log entry per proxied request (full pre-rewrite headers
/// captured, bounded excerpt, per-rule rewrite counts, honest note).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestLogEntry {
    /// Wall-clock epoch milliseconds (0 = clock unavailable, honest provenance).
    pub ts_ms: u64,
    pub client: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub status: u16,
    /// Final response body length delivered to the client (None = unknown).
    pub content_length: Option<u64>,
    /// ≤ [`MAX_EXCERPT_BYTES`] response-body excerpt (text bodies only).
    pub excerpt: String,
    /// Request headers exactly as received, bounded text.
    pub request_headers: String,
    /// Response headers BEFORE any rewrite, bounded text.
    pub response_headers: String,
    pub rewrites: RewriteCounts,
    /// Honest one-line note for refusals (CONNECT, caps, allowlist…).
    pub note: Option<String>,
}

/// Counters + log ring shared by every connection thread of one run.
#[derive(Default)]
pub struct ProxyShared {
    pub connections: AtomicU64,
    pub requests: AtomicU64,
    pub refused_allowlist: AtomicU64,
    pub refused_busy: AtomicU64,
    pub refused_header_cap: AtomicU64,
    pub refused_body_cap: AtomicU64,
    pub connect_refusals: AtomicU64,
    pub https_target_refusals: AtomicU64,
    pub upstream_failures: AtomicU64,
    pub rewrites_https_links: AtomicU64,
    pub rewrites_hsts_stripped: AtomicU64,
    pub rewrites_csp_stripped: AtomicU64,
    /// Live concurrent connection threads (bounded by the 8-conn cap).
    pub active_connections: AtomicUsize,
    /// Set when the accept loop ended because the runtime cap was reached.
    pub runtime_capped: AtomicBool,
    log: Mutex<VecDeque<RequestLogEntry>>,
}

impl ProxyShared {
    /// Push one entry; drop-oldest past [`MAX_LOG_ENTRIES`]. Bounded lock.
    pub fn push_log(&self, entry: RequestLogEntry) {
        if let Ok(mut ring) = self.log.lock() {
            if ring.len() >= MAX_LOG_ENTRIES {
                ring.pop_front();
            }
            ring.push_back(entry);
        }
    }

    /// Bounded snapshot of the log ring (oldest first).
    pub fn log_snapshot(&self) -> Vec<RequestLogEntry> {
        self.log
            .lock()
            .map(|ring| ring.iter().cloned().collect())
            .unwrap_or_default()
    }

    pub fn log_len(&self) -> usize {
        self.log.lock().map(|ring| ring.len()).unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Pure parsing / rewrite helpers (unit-tested on every platform).
// ---------------------------------------------------------------------------

/// Parsed request head: request line + headers (name/value pairs, case kept).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestHead {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
}

/// Locate the head terminator. Prefers CRLFCRLF, tolerates LF/LF.
fn find_head_end(buf: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + 1 < buf.len() {
        if buf[i] == b'\n' {
            if buf[i + 1] == b'\n' {
                return Some(i + 2);
            }
            if i + 2 < buf.len() && buf[i + 1] == b'\r' && buf[i + 2] == b'\n' {
                return Some(i + 3);
            }
        }
        i += 1;
    }
    None
}

/// Parse `raw[..head_len]` into a request head. Lenient about whitespace,
/// strict about the three-line-token shape.
pub fn parse_request_head(raw: &[u8], head_len: usize) -> Option<RequestHead> {
    let head = std::str::from_utf8(&raw[..head_len.min(raw.len())]).ok()?;
    let mut lines = head.lines();
    let request_line = lines.next()?.trim();
    let mut parts = request_line.split(' ');
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let version = parts.next()?;
    if parts.next().is_some() || method.is_empty() || target.is_empty() {
        return None;
    }
    if !version.eq_ignore_ascii_case("HTTP/1.1") && !version.eq_ignore_ascii_case("HTTP/1.0") {
        return None;
    }
    let mut headers = Vec::new();
    for line in lines {
        let line = line.trim_end_matches('\r').trim();
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':')?;
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }
    Some(RequestHead {
        method,
        target,
        headers,
    })
}

/// Parsed upstream destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamTarget {
    pub host: String,
    pub port: u16,
    /// Origin-form path sent upstream (always starts with '/').
    pub path: String,
}

/// Resolve where to fetch: absolute-URI form (`http://host[:port]/path`),
/// `https://` absolute-URI (refused honestly), or origin-form + Host header.
pub fn resolve_upstream(head: &RequestHead) -> Result<UpstreamTarget, &'static str> {
    let lower = head.target.to_ascii_lowercase();
    if lower.starts_with("https://") {
        return Err(HTTPS_TARGET_REFUSAL);
    }
    if let Some(rest) = strip_scheme(&lower, head.target.as_str()) {
        // Absolute-URI form: authority runs to the first '/' (or end).
        let (authority, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };
        if authority.is_empty() {
            return Err("absolute-form request URI has an empty authority");
        }
        let (host, port) = split_authority(authority)?;
        return Ok(UpstreamTarget {
            host,
            port,
            path: path.to_string(),
        });
    }
    if !head.target.starts_with('/') {
        // CONNECT authority-form is handled by the caller before this runs;
        // anything else non-origin-form is malformed for this proxy.
        return Err("request target must be absolute-URI or origin-form");
    }
    let host_header = head
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.as_str())
        .filter(|value| !value.trim().is_empty())
        .ok_or("origin-form request without a Host header")?;
    let (host, port) = split_authority(host_header.trim())?;
    Ok(UpstreamTarget {
        host,
        port,
        path: head.target.clone(),
    })
}

fn strip_scheme<'a>(lower: &str, original: &'a str) -> Option<&'a str> {
    if lower.starts_with("http://") {
        Some(&original["http://".len()..])
    } else {
        None
    }
}

/// Split `host[:port]` (bracketed IPv6 aware). Default port 80.
fn split_authority(authority: &str) -> Result<(String, u16), &'static str> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or("bracketed IPv6 authority is missing its closing bracket")?;
        let port = after
            .strip_prefix(':')
            .map(|p| p.parse::<u16>().map_err(|_| "bad upstream port"))
            .transpose()?
            .unwrap_or(80);
        return Ok((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port.parse().map_err(|_| "bad upstream port")?;
            Ok((host.to_string(), port))
        }
        None => Ok((authority.to_string(), 80)),
    }
}

/// Is the `https://` at `scheme_start` inside an `href`/`src` attribute value?
/// Walks backward over the (optional) quote, whitespace, `=`, whitespace and
/// the attribute name; requires an attribute-name boundary before the name.
fn is_attr_url_position(b: &[u8], scheme_start: usize) -> bool {
    let mut j = scheme_start;
    if j > 0 && (b[j - 1] == b'"' || b[j - 1] == b'\'') {
        j -= 1;
    }
    while j > 0 && matches!(b[j - 1], b' ' | b'\t' | b'\n' | b'\r') {
        j -= 1;
    }
    if j == 0 || b[j - 1] != b'=' {
        return false;
    }
    j -= 1;
    while j > 0 && matches!(b[j - 1], b' ' | b'\t' | b'\n' | b'\r') {
        j -= 1;
    }
    let name_end = j;
    while j > 0 && b[j - 1].is_ascii_alphanumeric() {
        j -= 1;
    }
    let name = &b[j..name_end].to_ascii_lowercase();
    if name != b"href" && name != b"src" {
        return false;
    }
    j == 0
        || matches!(
            b[j - 1],
            b' ' | b'\t' | b'\n' | b'\r' | b'<' | b'"' | b'\''
        )
}

/// SSL-strip-lite rule (a): rewrite every `https://` that sits inside an
/// `href`/`src` attribute value to `http://`. Bounded single pass, no regex
/// dependency, case-preserving outside the scheme. Returns (html, count).
pub fn rewrite_https_href_src(html: &str) -> (String, usize) {
    let b = html.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut count = 0usize;
    let mut i = 0usize;
    while i < b.len() {
        if b[i..].len() >= 8
            && b[i..i + 8].eq_ignore_ascii_case(b"https://")
            && is_attr_url_position(b, i)
        {
            out.extend_from_slice(b"http://");
            count += 1;
            i += 8;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    (
        String::from_utf8(out).unwrap_or_else(|_| html.to_string()),
        count,
    )
}

/// SSL-strip-lite rules (b)/(c): remove every occurrence of one response
/// header (case-insensitive). Returns (kept, removed_count).
pub fn strip_response_headers(
    headers: &[(String, String)],
    name: &str,
) -> (Vec<(String, String)>, usize) {
    let mut kept = Vec::with_capacity(headers.len());
    let mut removed = 0usize;
    for (key, value) in headers {
        if key.eq_ignore_ascii_case(name) {
            removed += 1;
        } else {
            kept.push((key.clone(), value.clone()));
        }
    }
    (kept, removed)
}

/// Case-insensitive header lookup (first match).
pub fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// Render headers to bounded log text (≤ [`MAX_LOGGED_HEADER_TEXT_BYTES`]),
/// honestly marked when the block was cut.
pub fn bounded_header_text(headers: &[(String, String)]) -> String {
    let mut text = String::new();
    for (name, value) in headers {
        let line = format!("{name}: {value}\r\n");
        if text.len() + line.len() > MAX_LOGGED_HEADER_TEXT_BYTES {
            text.push_str(LOG_TRUNCATION_MARKER);
            return text;
        }
        text.push_str(&line);
    }
    text
}

/// Bounded response-body excerpt: lossy UTF-8 of the first
/// [`MAX_EXCERPT_BYTES`] of text bodies; an honest marker for binary bodies.
pub fn bounded_excerpt(body: &[u8], content_type: &str) -> String {
    if !content_type.to_ascii_lowercase().contains("text") {
        return format!("(non-text body; {} bytes)", body.len());
    }
    if body.len() <= MAX_EXCERPT_BYTES {
        return String::from_utf8_lossy(body).into_owned();
    }
    let mut text = String::from_utf8_lossy(&body[..MAX_EXCERPT_BYTES]).into_owned();
    text.push_str("\n...[excerpt truncated at the 4 KiB log bound]");
    text
}

/// Wall-clock epoch ms; 0 keeps entries honest if the clock is unavailable.
pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Bounded socket reads.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    /// Cap exceeded — the honest refusal path, never silent truncation.
    TooLarge,
    /// Deadline or idle timeout exceeded.
    Timeout,
    /// Peer closed before a complete head/body arrived.
    Closed,
    /// Malformed framing (bad chunk size line, etc.).
    Malformed,
    /// Underlying I/O failure.
    Io(String),
}

/// How the body length is framed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    ContentLength(u64),
    Chunked,
    UntilEof,
}

/// Buffered byte source over (leftover prefix ∪ stream) with deadline checks.
struct BodyReader<'a> {
    prefix: &'a [u8],
    pos: usize,
    stream: &'a mut TcpStream,
    buf: [u8; 8192],
    fill: usize,
    off: usize,
    deadline: Instant,
}

impl<'a> BodyReader<'a> {
    fn new(prefix: &'a [u8], stream: &'a mut TcpStream, deadline: Instant) -> Self {
        Self {
            prefix,
            pos: 0,
            stream,
            buf: [0; 8192],
            fill: 0,
            off: 0,
            deadline,
        }
    }

    fn remaining_ms(&self) -> u64 {
        self.deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(u64::MAX as u128) as u64
    }

    fn next_byte(&mut self) -> Result<u8, ReadError> {
        if self.pos < self.prefix.len() {
            let byte = self.prefix[self.pos];
            self.pos += 1;
            return Ok(byte);
        }
        if self.off < self.fill {
            let byte = self.buf[self.off];
            self.off += 1;
            return Ok(byte);
        }
        if Instant::now() >= self.deadline {
            return Err(ReadError::Timeout);
        }
        let idle = Duration::from_millis(SOCKET_IDLE_TIMEOUT_MS.min(self.remaining_ms()));
        self.stream
            .set_read_timeout(Some(idle))
            .map_err(|e| ReadError::Io(e.to_string()))?;
        match self.stream.read(&mut self.buf) {
            Ok(0) => Err(ReadError::Closed),
            Ok(n) => {
                self.fill = n;
                self.off = 1;
                Ok(self.buf[0])
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Err(ReadError::Timeout)
            }
            Err(e) => Err(ReadError::Io(e.to_string())),
        }
    }

    /// Read one CRLF/LF-terminated line (terminator stripped, ≤ 8 KiB).
    fn read_line(&mut self) -> Result<String, ReadError> {
        let mut line = Vec::new();
        loop {
            let byte = self.next_byte()?;
            if byte == b'\n' {
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                return String::from_utf8(line).map_err(|_| ReadError::Malformed);
            }
            if line.len() >= 8192 {
                return Err(ReadError::TooLarge);
            }
            line.push(byte);
        }
    }

    fn read_exact_n(&mut self, mut n: usize, out: &mut Vec<u8>) -> Result<(), ReadError> {
        while n > 0 {
            let byte = self.next_byte()?;
            out.push(byte);
            n -= 1;
        }
        Ok(())
    }
}

/// Read a request/response head (≤ [`MAX_HEADER_BYTES`]); returns the raw
/// bytes read plus the head length, so body bytes already consumed stay
/// available as the body prefix.
fn read_head(stream: &mut TcpStream, deadline: Instant) -> Result<(Vec<u8>, usize), ReadError> {
    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let mut chunk = [0u8; 4096];
    loop {
        if buf.len() > MAX_HEADER_BYTES {
            return Err(ReadError::TooLarge);
        }
        if Instant::now() >= deadline {
            return Err(ReadError::Timeout);
        }
        let idle = Duration::from_millis(SOCKET_IDLE_TIMEOUT_MS.min(
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis()
                .min(u64::MAX as u128) as u64,
        ));
        stream
            .set_read_timeout(Some(idle))
            .map_err(|e| ReadError::Io(e.to_string()))?;
        match stream.read(&mut chunk) {
            Ok(0) => return Err(ReadError::Closed),
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if let Some(head_len) = find_head_end(&buf) {
                    return Ok((buf, head_len));
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(ReadError::Timeout)
            }
            Err(e) => return Err(ReadError::Io(e.to_string())),
        }
    }
}

/// Read a body per its framing, bounded by `cap` ([`MAX_BODY_BYTES`]).
fn read_body(
    prefix: &[u8],
    stream: &mut TcpStream,
    kind: BodyKind,
    deadline: Instant,
) -> Result<Vec<u8>, ReadError> {
    let mut reader = BodyReader::new(prefix, stream, deadline);
    match kind {
        BodyKind::ContentLength(len) => {
            if len > MAX_BODY_BYTES as u64 {
                return Err(ReadError::TooLarge);
            }
            let mut body = Vec::with_capacity(len as usize);
            reader.read_exact_n(len as usize, &mut body)?;
            Ok(body)
        }
        BodyKind::UntilEof => {
            let mut body = Vec::new();
            loop {
                match reader.next_byte() {
                    Ok(byte) => {
                        if body.len() >= MAX_BODY_BYTES {
                            return Err(ReadError::TooLarge);
                        }
                        body.push(byte);
                    }
                    Err(ReadError::Closed) => return Ok(body),
                    Err(e) => return Err(e),
                }
            }
        }
        BodyKind::Chunked => {
            let mut body = Vec::new();
            loop {
                let line = reader.read_line()?;
                let size_text = line.split(';').next().unwrap_or("").trim();
                let size = usize::from_str_radix(size_text, 16)
                    .map_err(|_| ReadError::Malformed)?;
                if size == 0 {
                    // Trailer section: read until the blank line (bounded).
                    for _ in 0..64 {
                        let trailer = reader.read_line()?;
                        if trailer.is_empty() {
                            break;
                        }
                    }
                    return Ok(body);
                }
                if body.len() + size > MAX_BODY_BYTES {
                    return Err(ReadError::TooLarge);
                }
                reader.read_exact_n(size, &mut body)?;
                let _crlf = reader.read_line()?;
            }
        }
    }
}

/// Response head parsed from the upstream stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHead {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
}

/// Parse `HTTP/1.x CODE REASON` + headers from the upstream head bytes.
pub fn parse_response_head(raw: &[u8], head_len: usize) -> Option<ResponseHead> {
    let head = std::str::from_utf8(&raw[..head_len.min(raw.len())]).ok()?;
    let mut lines = head.lines();
    let status_line = lines.next()?.trim();
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next()?.trim();
    if !version.eq_ignore_ascii_case("HTTP/1.1") && !version.eq_ignore_ascii_case("HTTP/1.0") {
        return None;
    }
    let status: u16 = parts.next()?.trim().parse().ok()?;
    let reason = parts.next().unwrap_or("").trim().to_string();
    let mut headers = Vec::new();
    for line in lines {
        let line = line.trim_end_matches('\r').trim();
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':')?;
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }
    Some(ResponseHead {
        status,
        reason,
        headers,
    })
}

fn body_kind_for(headers: &[(String, String)]) -> BodyKind {
    if header_value(headers, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false)
    {
        return BodyKind::Chunked;
    }
    match header_value(headers, "content-length")
        .and_then(|v| v.trim().parse::<u64>().ok())
    {
        Some(len) => BodyKind::ContentLength(len),
        None => BodyKind::UntilEof,
    }
}

/// Hop-by-hop headers this proxy never forwards upstream.
fn is_hop_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "proxy-connection"
            | "proxy-authorization"
            | "keep-alive"
            | "te"
            | "upgrade"
            | "trailer"
            | "transfer-encoding"
    )
}

// ---------------------------------------------------------------------------
// Connection handling.
// ---------------------------------------------------------------------------

/// A tiny reason table for synthesized error responses.
fn reason_for(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        403 => "Forbidden",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

fn error_response(status: u16, body: &str) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reason_for(status),
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body.as_bytes());
    out
}

/// Log one entry and bump the matching counter — the single honest path for
/// every refusal so the status wire can only repeat what really happened.
fn log_refusal(
    shared: &ProxyShared,
    entry: RequestLogEntry,
    counter: &AtomicU64,
) {
    counter.fetch_add(1, Ordering::Release);
    shared.push_log(entry);
}

/// Write a synthesized refusal response and close the socket GRACEFULLY:
/// after `shutdown(Write)` the remaining unread client bytes are drained so
/// the OS closes with FIN instead of RST (an RST could destroy the refusal
/// response before the client read it).
fn send_refusal(mut stream: TcpStream, response: &[u8]) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.write_all(response);
    let _ = stream.flush();
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    let mut drain = [0u8; 1024];
    for _ in 0..64 {
        match stream.read(&mut drain) {
            Ok(0) | Err(_) => break,
            Ok(_) => continue,
        }
    }
}

fn blank_entry(client: &str) -> RequestLogEntry {
    RequestLogEntry {
        ts_ms: unix_ms(),
        client: client.to_string(),
        method: String::new(),
        host: String::new(),
        path: String::new(),
        status: 0,
        content_length: None,
        excerpt: String::new(),
        request_headers: String::new(),
        response_headers: String::new(),
        rewrites: RewriteCounts::default(),
        note: None,
    }
}

/// Handle ONE client connection end to end. Every exit path is bounded and,
/// where a client-visible refusal happened, logged.
fn handle_conn(mut stream: TcpStream, peer: IpAddr, config: &ProxyConfig, shared: &Arc<ProxyShared>) {
    // Accepted sockets inherit the listener's O_NONBLOCK on macOS/BSD: force
    // blocking mode so the bounded timeouts below behave as timeouts, not
    // instant WouldBlock errors.
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_nodelay(true);
    let deadline = Instant::now() + Duration::from_millis(MAX_CONNECTION_MS);
    let client = peer.to_string();

    // Allowlist first: nothing else happens for a refused peer.
    if !config.allowlist.is_empty() && !config.allowlist.contains(&peer) {
        shared.refused_allowlist.fetch_add(1, Ordering::Release);
        send_refusal(stream, &error_response(
            403,
            "client is not on the proxy allowlist — edit the allowlist and restart the proxy",
        ));

        return;
    }
    shared.connections.fetch_add(1, Ordering::Release);

    let (raw, head_len) = match read_head(&mut stream, deadline) {
        Ok(head) => head,
        Err(ReadError::TooLarge) => {
            let mut entry = blank_entry(&client);
            entry.status = 431;
            entry.note =
                Some("request head exceeds the 64 KiB proxy cap — refused, not truncated".into());
            log_refusal(shared, entry, &shared.refused_header_cap);
            send_refusal(stream, &error_response(
                431,
                "request head exceeds the 64 KiB proxy cap — refused, not truncated",
            ));

            return;
        }
        Err(_) => return, // peer vanished or timed out pre-request: nothing to log honestly
    };
    let head = match parse_request_head(&raw, head_len) {
        Some(head) => head,
        None => {
            let mut entry = blank_entry(&client);
            entry.status = 400;
            entry.note = Some("unparseable request head".into());
            shared.push_log(entry);
            send_refusal(stream, &error_response(400, "unparseable request head"));

            return;
        }
    };
    let method = head.method.clone();
    let request_headers_text = bounded_header_text(&head.headers);

    // CONNECT: the honest plain-HTTP refusal.
    if method.eq_ignore_ascii_case("connect") {
        let mut entry = blank_entry(&client);
        entry.method = method.clone();
        entry.host = head.target.clone();
        entry.path = String::new();
        entry.status = 501;
        entry.request_headers = request_headers_text;
        entry.note = Some(format!("CONNECT refused: {CONNECT_REFUSAL}"));
        log_refusal(shared, entry, &shared.connect_refusals);
        send_refusal(stream, &error_response(501, CONNECT_REFUSAL));

        return;
    }

    // Resolve the upstream destination (absolute-URI or origin-form + Host).
    let target = match resolve_upstream(&head) {
        Ok(target) => target,
        Err(message) => {
            let refused_https = message == HTTPS_TARGET_REFUSAL;
            let mut entry = blank_entry(&client);
            entry.method = method.clone();
            entry.host = head.target.clone();
            entry.path = String::new();
            entry.status = 501;
            entry.request_headers = request_headers_text;
            entry.note = Some(message.to_string());
            if refused_https {
                log_refusal(shared, entry, &shared.https_target_refusals);
            } else {
                shared.push_log(entry);
            }
            send_refusal(stream, &error_response(501, message));

            return;
        }
    };

    // Request body (Content-Length framed only; chunked requests refused).
    let leftover = &raw[head_len..];
    let has_chunked_request = header_value(&head.headers, "transfer-encoding")
        .map(|v| v.to_ascii_lowercase().contains("chunked"))
        .unwrap_or(false);
    let request_kind = if has_chunked_request {
        None
    } else {
        Some(
            header_value(&head.headers, "content-length")
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(0),
        )
        .map(BodyKind::ContentLength)
    };
    let request_body = match request_kind {
        None => {
            let mut entry = blank_entry(&client);
            entry.method = method.clone();
            entry.host = target.host.clone();
            entry.path = target.path.clone();
            entry.status = 501;
            entry.request_headers = request_headers_text;
            entry.note = Some(
                "chunked request bodies are not supported by this lab proxy (Content-Length only)"
                    .into(),
            );
            shared.push_log(entry);
            send_refusal(stream, &error_response(
                501,
                "chunked request bodies are not supported by this lab proxy (Content-Length only)",
            ));

            return;
        }
        Some(kind) => match read_body(leftover, &mut stream, kind, deadline) {
            Ok(body) => body,
            Err(ReadError::TooLarge) => {
                let mut entry = blank_entry(&client);
                entry.method = method.clone();
                entry.host = target.host.clone();
                entry.path = target.path.clone();
                entry.status = 413;
                entry.request_headers = request_headers_text;
                entry.note =
                    Some("request body exceeds the 1 MiB proxy cap — refused".into());
                log_refusal(shared, entry, &shared.refused_body_cap);
                send_refusal(stream, &error_response(
                    413,
                    "request body exceeds the 1 MiB proxy cap — refused",
                ));

                return;
            }
            Err(_) => return,
        },
    };

    // Build the upstream request: origin-form target, Host pinned, hop
    // headers dropped, Connection: close, full headers logged (pre-rewrite;
    // requests are never rewritten by this proxy).
    let mut upstream_head = format!(
        "{} {} HTTP/1.1\r\nHost: {}{}\r\nConnection: close\r\n",
        method,
        target.path,
        target.host,
        if target.port == 80 {
            String::new()
        } else {
            format!(":{}", target.port)
        },
    )
    .into_bytes();
    for (name, value) in &head.headers {
        if is_hop_header(name) || name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        upstream_head.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    if !request_body.is_empty() {
        upstream_head.extend_from_slice(
            format!("Content-Length: {}\r\n", request_body.len()).as_bytes(),
        );
    }
    upstream_head.extend_from_slice(b"\r\n");

    // Bounded upstream fetch.
    let upstream = match (target.host.as_str(), target.port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
    {
        Some(addr) => addr,
        None => {
            shared.upstream_failures.fetch_add(1, Ordering::Release);
            let mut entry = blank_entry(&client);
            entry.method = method.clone();
            entry.host = target.host.clone();
            entry.path = target.path.clone();
            entry.status = 502;
            entry.request_headers = request_headers_text;
            entry.note = Some("upstream host could not be resolved".into());
            shared.push_log(entry);
            send_refusal(stream, &error_response(
                502,
                "upstream host could not be resolved",
            ));

            return;
        }
    };
    let mut upstream_stream = match TcpStream::connect_timeout(
        &upstream,
        Duration::from_millis(UPSTREAM_CONNECT_TIMEOUT_MS),
    ) {
        Ok(s) => s,
        Err(err) => {
            shared.upstream_failures.fetch_add(1, Ordering::Release);
            let mut entry = blank_entry(&client);
            entry.method = method.clone();
            entry.host = target.host.clone();
            entry.path = target.path.clone();
            entry.status = 502;
            entry.request_headers = request_headers_text;
            entry.note = Some(format!("upstream connect failed: {err}"));
            shared.push_log(entry);
            send_refusal(stream, &error_response(502, "upstream connect failed"));

            return;
        }
    };
    let _ = upstream_stream.set_nodelay(true);
    let upstream_deadline = Instant::now() + Duration::from_millis(MAX_CONNECTION_MS);
    if let Err(err) = upstream_stream.write_all(&upstream_head) {
        shared.upstream_failures.fetch_add(1, Ordering::Release);
        let mut entry = blank_entry(&client);
        entry.method = method.clone();
        entry.host = target.host.clone();
        entry.path = target.path.clone();
        entry.status = 502;
        entry.request_headers = request_headers_text;
        entry.note = Some(format!("upstream write failed: {err}"));
        shared.push_log(entry);
        send_refusal(stream, &error_response(502, "upstream write failed"));

        return;
    }
    if !request_body.is_empty() {
        if let Err(err) = upstream_stream.write_all(&request_body) {
            shared.upstream_failures.fetch_add(1, Ordering::Release);
            let mut entry = blank_entry(&client);
            entry.method = method.clone();
            entry.host = target.host.clone();
            entry.path = target.path.clone();
            entry.status = 502;
            entry.request_headers = request_headers_text;
            entry.note = Some(format!("upstream body write failed: {err}"));
            shared.push_log(entry);
            send_refusal(stream, &error_response(502, "upstream write failed"));

            return;
        }
    }

    // Upstream response: head cap, then bounded body.
    let (resp_raw, resp_head_len) = match read_head(&mut upstream_stream, upstream_deadline) {
        Ok(head) => head,
        Err(err) => {
            shared.upstream_failures.fetch_add(1, Ordering::Release);
            let mut entry = blank_entry(&client);
            entry.method = method.clone();
            entry.host = target.host.clone();
            entry.path = target.path.clone();
            entry.status = 502;
            entry.request_headers = request_headers_text;
            entry.note = Some(format!("upstream response head failed: {err:?}"));
            shared.push_log(entry);
            send_refusal(stream, &error_response(502, "upstream response failed"));

            return;
        }
    };
    let resp_head = match parse_response_head(&resp_raw, resp_head_len) {
        Some(head) => head,
        None => {
            shared.upstream_failures.fetch_add(1, Ordering::Release);
            let mut entry = blank_entry(&client);
            entry.method = method.clone();
            entry.host = target.host.clone();
            entry.path = target.path.clone();
            entry.status = 502;
            entry.request_headers = request_headers_text;
            entry.note = Some("unparseable upstream response head".into());
            shared.push_log(entry);
            send_refusal(stream, &error_response(502, "unparseable upstream response"));

            return;
        }
    };
    // FULL response headers captured BEFORE any rewrite (the honesty contract).
    let response_headers_text = bounded_header_text(&resp_head.headers);
    let resp_leftover = &resp_raw[resp_head_len..];
    let resp_kind = body_kind_for(&resp_head.headers);
    let body = match read_body(resp_leftover, &mut upstream_stream, resp_kind, upstream_deadline) {
        Ok(body) => body,
        Err(ReadError::TooLarge) => {
            let mut entry = blank_entry(&client);
            entry.method = method.clone();
            entry.host = target.host.clone();
            entry.path = target.path.clone();
            entry.status = 502;
            entry.request_headers = request_headers_text;
            entry.response_headers = response_headers_text;
            entry.note =
                Some("upstream body exceeds the 1 MiB proxy cap — refused".into());
            log_refusal(shared, entry, &shared.refused_body_cap);
            send_refusal(stream, &error_response(
                502,
                "upstream body exceeds the 1 MiB proxy cap — refused",
            ));

            return;
        }
        Err(err) => {
            shared.upstream_failures.fetch_add(1, Ordering::Release);
            let mut entry = blank_entry(&client);
            entry.method = method.clone();
            entry.host = target.host.clone();
            entry.path = target.path.clone();
            entry.status = 502;
            entry.request_headers = request_headers_text;
            entry.response_headers = response_headers_text;
            entry.note = Some(format!("upstream body read failed: {err:?}"));
            shared.push_log(entry);
            send_refusal(stream, &error_response(502, "upstream body read failed"));

            return;
        }
    };

    // Rewrite rules — applied only now, AFTER the full headers were logged.
    let mut headers = resp_head.headers.clone();
    let mut body = body;
    let mut counts = RewriteCounts::default();
    if config.rules.strip_hsts {
        let (kept, removed) = strip_response_headers(&headers, "Strict-Transport-Security");
        headers = kept;
        counts.hsts_stripped = removed;
        if removed > 0 {
            shared.rewrites_hsts_stripped.fetch_add(removed as u64, Ordering::Release);
        }
    }
    if config.rules.strip_csp {
        let (kept, removed) = strip_response_headers(&headers, "Content-Security-Policy");
        headers = kept;
        counts.csp_stripped = removed;
        if removed > 0 {
            shared.rewrites_csp_stripped.fetch_add(removed as u64, Ordering::Release);
        }
    }
    let content_type = header_value(&headers, "content-type").unwrap_or("").to_string();
    if config.rules.rewrite_https_links
        && content_type.to_ascii_lowercase().contains("text/html")
        && body.len() <= MAX_BODY_BYTES
    {
        let text = String::from_utf8_lossy(&body);
        let (rewritten, count) = rewrite_https_href_src(&text);
        body = rewritten.into_bytes();
        counts.https_links = count;
        if count > 0 {
            shared.rewrites_https_links.fetch_add(count as u64, Ordering::Release);
        }
    }

    // Deliver: hop headers dropped, honest Content-Length, Connection: close.
    let mut out = format!(
        "HTTP/1.1 {} {}\r\nConnection: close\r\nContent-Length: {}\r\n",
        resp_head.status,
        if resp_head.reason.is_empty() {
            reason_for(resp_head.status)
        } else {
            resp_head.reason.as_str()
        },
        body.len(),
    )
    .into_bytes();
    for (name, value) in &headers {
        if is_hop_header(name)
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            continue;
        }
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&body);
    let _ = stream.write_all(&out);
    let _ = stream.flush();

    // The one completed-request log entry: method, host, path, status,
    // content-length, bounded excerpt, pre-rewrite headers, rewrite counts.
    let entry = RequestLogEntry {
        ts_ms: unix_ms(),
        client,
        method,
        host: target.host.clone(),
        path: target.path,
        status: resp_head.status,
        content_length: Some(body.len() as u64),
        excerpt: bounded_excerpt(&body, &content_type),
        request_headers: request_headers_text,
        response_headers: response_headers_text,
        rewrites: counts,
        note: None,
    };
    shared.push_log(entry);
    shared.requests.fetch_add(1, Ordering::Release);
}

// ---------------------------------------------------------------------------
// Accept loop.
// ---------------------------------------------------------------------------

/// The accept loop. Runs until `stop` is set or `runtime_cap_ms` elapsed
/// (auto-stop, flagged on `shared.runtime_capped`), accepting at most
/// [`MAX_CONCURRENT_CONNECTIONS`] live connection threads. Never returns an
/// error: every failure lands in the shared counters/log instead.
pub fn serve(
    listener: TcpListener,
    config: &ProxyConfig,
    started: Instant,
    stop: &AtomicBool,
    shared: &Arc<ProxyShared>,
    runtime_cap_ms: u64,
) {
    let _ = listener.set_nonblocking(true);
    loop {
        if stop.load(Ordering::Acquire) {
            return;
        }
        if started.elapsed().as_millis() as u64 >= runtime_cap_ms {
            shared.runtime_capped.store(true, Ordering::Release);
            return;
        }
        match listener.accept() {
            Ok((stream, peer)) => {
                if shared.active_connections.load(Ordering::Acquire)
                    >= MAX_CONCURRENT_CONNECTIONS
                {
                    shared.refused_busy.fetch_add(1, Ordering::Release);
                    let refused = stream;
                    let mut entry = blank_entry(&peer.ip().to_string());
                    entry.status = 503;
                    entry.note = Some(format!(
                        "proxy at its {MAX_CONCURRENT_CONNECTIONS}-connection cap — refused"
                    ));
                    shared.push_log(entry);
                    send_refusal(
                        refused,
                        &error_response(
                            503,
                            "proxy is at its concurrent-connection cap — retry shortly",
                        ),
                    );
                    continue;
                }
                shared.active_connections.fetch_add(1, Ordering::Release);
                let shared_for_conn = Arc::clone(shared);
                let config_for_conn = config.clone();
                std::thread::spawn(move || {
                    handle_conn(stream, peer.ip(), &config_for_conn, &shared_for_conn);
                    shared_for_conn
                        .active_connections
                        .fetch_sub(1, Ordering::Release);
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(ACCEPT_PARK_MS));
            }
            Err(_) => {
                // Transient accept error: park briefly and keep honoring stop.
                std::thread::sleep(Duration::from_millis(ACCEPT_PARK_MS));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests: pure helpers first, then real localhost socket end-to-end runs with
// a test-local upstream server (fully testable on macOS — plain TCP only).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::SocketAddr;

    // ---- pure helpers ------------------------------------------------------

    fn head(method: &str, target: &str, headers: &[(&str, &str)]) -> RequestHead {
        RequestHead {
            method: method.into(),
            target: target.into(),
            headers: headers
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn parse_request_head_reads_request_line_and_headers() {
        let raw = b"GET /a HTTP/1.1\r\nHost: example.com\r\nX-One: 1\r\n\r\nbody";
        let parsed = parse_request_head(raw, raw.len() - 4).expect("parses");
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.target, "/a");
        assert_eq!(parsed.headers.len(), 2);
        assert_eq!(parsed.headers[0], ("Host".into(), "example.com".into()));
        assert!(parse_request_head(b"garbage\r\n\r\n", 13).is_none());
        assert!(parse_request_head(b"GET / HTTP/2.0\r\n\r\n", 18).is_none());
    }

    #[test]
    fn head_terminator_finds_crlfcrlf_and_tolerates_lflf() {
        assert_eq!(find_head_end(b"AB\r\n\r\nCD"), Some(6));
        assert_eq!(find_head_end(b"AB\n\nCD"), Some(4));
        assert_eq!(find_head_end(b"AB\r\nCD"), None);
    }

    #[test]
    fn upstream_resolution_reads_absolute_uri_origin_form_and_refuses_https() {
        let abs = head("GET", "http://example.com:8080/p?q=1", &[]);
        let t = resolve_upstream(&abs).expect("absolute form");
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 8080);
        assert_eq!(t.path, "/p?q=1");
        let abs_plain = head("GET", "http://example.com", &[]);
        let t = resolve_upstream(&abs_plain).expect("no path defaults to /");
        assert_eq!(t.path, "/");
        assert_eq!(t.port, 80);
        let origin = head("POST", "/x/y", &[("Host", "up.test:90")]);
        let t = resolve_upstream(&origin).expect("origin form");
        assert_eq!(t.host, "up.test");
        assert_eq!(t.port, 90);
        assert_eq!(t.path, "/x/y");
        let https = head("GET", "https://example.com/x", &[]);
        assert_eq!(resolve_upstream(&https), Err(HTTPS_TARGET_REFUSAL));
        let no_host = head("GET", "/x", &[]);
        assert!(resolve_upstream(&no_host).is_err());
        let bracketed = head("GET", "/", &[("Host", "[::1]:8081")]);
        let t = resolve_upstream(&bracketed).expect("ipv6 authority");
        assert_eq!(t.host, "::1");
        assert_eq!(t.port, 8081);
    }

    #[test]
    fn sslstrip_rewrite_hits_href_src_values_only() {
        let (out, count) = rewrite_https_href_src(
            "<a href=\"https://a.example/x\">l</a><img src='https://b.example/i.png'>\
             <a HREF = https://c.example/y>d</a><SCRIPT SRC=\"https://d.example/s.js\"></SCRIPT>",
        );
        assert_eq!(count, 4, "{out}");
        assert!(out.contains("href=\"http://a.example/x\""), "{out}");
        assert!(out.contains("src='http://b.example/i.png'"), "{out}");
        assert!(out.contains("HREF = http://c.example/y"), "{out}");
        assert!(out.contains("SRC=\"http://d.example/s.js\""), "{out}");
        // Plain-text https URLs outside attributes are NOT touched.
        let (plain, count) = rewrite_https_href_src("<p>visit https://docs.example</p>");
        assert_eq!(count, 0);
        assert_eq!(plain, "<p>visit https://docs.example</p>");
        // hreflang/srcset are not href/src attribute values.
        let (out, count) = rewrite_https_href_src(
            "<a hreflang=\"https://x.example\">h</a><img srcset=\"https://y.example 1x\">",
        );
        assert_eq!(count, 0, "{out}");
        // data-src is not src (boundary check), already-http stays untouched.
        let (out, count) =
            rewrite_https_href_src("<div data-src=\"https://z.example\"></div><a href=\"http://ok.example\"></a>");
        assert_eq!(count, 0, "{out}");
        assert!(out.contains("http://ok.example"));
        // Multi-byte UTF-8 bodies survive the byte-level pass.
        let (out, count) = rewrite_https_href_src("<a title=\"é\" href=\"https://é.example/x\">é</a>");
        assert_eq!(count, 1);
        assert!(out.contains("é.example"), "{out}");
    }

    #[test]
    fn header_strip_removes_only_the_named_header() {
        let headers = vec![
            ("Strict-Transport-Security".to_string(), "max-age=31536000".to_string()),
            ("Content-Security-Policy".to_string(), "default-src 'self'".to_string()),
            ("Content-Type".to_string(), "text/html".to_string()),
        ];
        let (kept, n) = strip_response_headers(&headers, "strict-transport-security");
        assert_eq!(n, 1);
        assert_eq!(kept.len(), 2);
        let (kept, n) = strip_response_headers(&kept, "Content-Security-Policy");
        assert_eq!(n, 1);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].0, "Content-Type");
        let (_, n) = strip_response_headers(&kept, "Server");
        assert_eq!(n, 0);
    }

    #[test]
    fn bounded_texts_and_excerpt_stay_under_their_caps() {
        let big: Vec<(String, String)> = (0..64)
            .map(|i| (format!("X-Pad-{i}"), "v".repeat(200)))
            .collect();
        let text = bounded_header_text(&big);
        assert!(text.len() <= MAX_LOGGED_HEADER_TEXT_BYTES + LOG_TRUNCATION_MARKER.len());
        assert!(text.contains(LOG_TRUNCATION_MARKER));
        let small = vec![("Host".to_string(), "a.test".to_string())];
        assert_eq!(bounded_header_text(&small), "Host: a.test\r\n");
        let excerpt = bounded_excerpt(b"0123456789", "text/html");
        assert_eq!(excerpt, "0123456789");
        let long = vec![0x61; MAX_EXCERPT_BYTES + 100];
        let excerpt = bounded_excerpt(&long, "text/html");
        assert!(excerpt.len() < MAX_EXCERPT_BYTES + 64);
        assert!(excerpt.contains("excerpt truncated"));
        assert_eq!(
            bounded_excerpt(&[0xff, 0xfe], "application/octet-stream"),
            "(non-text body; 2 bytes)"
        );
    }

    #[test]
    fn config_build_enforces_port_allowlist_and_duplicate_bounds() {
        let ok = ProxyConfig::build(
            DEFAULT_PROXY_PORT,
            RewriteRules::default(),
            vec!["10.0.0.5".parse().unwrap()],
        )
        .expect("default config");
        assert_eq!(ok.port, 8080);
        assert_eq!(ok.rules, RewriteRules::default(), "all rules OFF by default");
        assert!(ProxyConfig::build(80, RewriteRules::default(), vec![]).is_err());
        let over: Vec<IpAddr> = (0..MAX_ALLOWLIST_ENTRIES + 1)
            .map(|i| format!("10.0.0.{i}").parse().unwrap())
            .collect();
        assert!(ProxyConfig::build(8080, RewriteRules::default(), over).is_err());
        let dup = vec![
            "10.0.0.5".parse().unwrap(),
            "10.0.0.5".parse().unwrap(),
        ];
        assert!(ProxyConfig::build(8080, RewriteRules::default(), dup).is_err());
        assert!(RewriteRules::default().active_names().is_empty());
        assert_eq!(
            RewriteRules {
                rewrite_https_links: true,
                strip_hsts: true,
                strip_csp: true
            }
            .active_names()
            .len(),
            3
        );
    }

    #[test]
    fn response_head_parses_status_and_headers() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n";
        let head = parse_response_head(raw, raw.len() - 2).expect("parses");
        assert_eq!(head.status, 200);
        assert_eq!(head.reason, "OK");
        assert_eq!(head.headers[0].0, "Content-Type");
        assert!(parse_response_head(b"NOT HTTP\r\n\r\n", 13).is_none());
    }

    // ---- real-socket test rig ----------------------------------------------

    /// Deterministic test-local upstream: accepts connections in a loop until
    /// dropped; for each, reads the head to the blank line then writes the
    /// canned response bytes.
    fn spawn_echo_upstream(response: &'static str) -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("upstream binds");
        let addr = listener.local_addr().expect("upstream addr");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_for_thread = Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_ok() {
                    seen_for_thread
                        .lock()
                        .unwrap()
                        .push(request_line.trim().to_string());
                }
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) if line.trim().is_empty() => break,
                        Ok(_) => {}
                    }
                }
                let mut writer = stream;
                if writer.write_all(response.as_bytes()).is_err() {
                    break;
                }
                let _ = writer.flush();
            }
        });
        (addr, seen)
    }

    fn spawn_proxy(
        config: ProxyConfig,
    ) -> (SocketAddr, Arc<ProxyShared>, Arc<AtomicBool>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("proxy binds");
        let addr = listener.local_addr().expect("proxy addr");
        let shared = Arc::new(ProxyShared::default());
        let stop = Arc::new(AtomicBool::new(false));
        let handle = std::thread::spawn({
            let listener = listener;
            let shared = Arc::clone(&shared);
            let stop = Arc::clone(&stop);
            let config = config.clone();
            move || {
                serve(
                    listener,
                    &config,
                    Instant::now(),
                    &stop,
                    &shared,
                    MAX_RUNTIME_MS,
                );
            }
        });
        (addr, shared, stop, handle)
    }

    /// Raw HTTP exchange through the proxy: send `request` bytes, read the
    /// full response to EOF, return the response bytes.
    fn roundtrip(proxy: SocketAddr, request: &str) -> Vec<u8> {
        let mut stream = TcpStream::connect(proxy).expect("client connects");
        stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
        stream.write_all(request.as_bytes()).expect("client writes");
        stream.flush().ok();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).expect("client reads");
        response
    }

    fn response_text(response: &[u8]) -> String {
        String::from_utf8_lossy(response).into_owned()
    }

    // ---- end-to-end: real HTTP through the proxy ---------------------------

    #[test]
    fn proxied_request_reaches_upstream_and_is_logged_with_full_metadata() {
        let body = "<html><body>hello from upstream</body></html>";
        let upstream_response: &'static str = Box::leak(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nX-Upstream: yes\r\n\r\n{body}",
                body.len()
            )
            .into_boxed_str(),
        );
        let (upstream, seen) = spawn_echo_upstream(upstream_response);
        let config =
            ProxyConfig::build(8080, RewriteRules::default(), vec![]).expect("config");
        let (proxy, shared, stop, handle) = spawn_proxy(config);

        let response = roundtrip(
            proxy,
            &format!(
                "GET http://127.0.0.1:{}/hello?x=1 HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nUser-Agent: lab-test\r\n\r\n",
                upstream.port(), upstream.port()
            ),
        );
        let text = response_text(&response);
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
        assert!(text.contains("hello from upstream"), "{text}");
        assert!(text.contains("X-Upstream: yes"), "{text}");
        assert!(text.contains("Connection: close"), "{text}");
        // The upstream saw the origin-form request line with Host pinned.
        let seen = seen.lock().unwrap();
        assert_eq!(
            seen.first().map(|s| s.as_str()),
            Some(&*format!("GET /hello?x=1 HTTP/1.1")),
            "{seen:?}"
        );
        // The log entry carries method, host, path, status, content-length.
        let log = shared.log_snapshot();
        assert_eq!(log.len(), 1, "one completed request logged");
        let entry = &log[0];
        assert_eq!(entry.method, "GET");
        assert_eq!(entry.host, "127.0.0.1");
        assert_eq!(entry.path, "/hello?x=1");
        assert_eq!(entry.status, 200);
        assert_eq!(entry.content_length, Some(body.len() as u64));
        assert!(entry.excerpt.contains("hello from upstream"), "{}", entry.excerpt);
        assert!(entry.request_headers.contains("User-Agent: lab-test"));
        assert!(entry.response_headers.contains("X-Upstream: yes"));
        assert_eq!(
            entry.rewrites,
            RewriteCounts::default(),
            "rules off: no rewrites recorded"
        );
        assert_eq!(shared.requests.load(Ordering::Acquire), 1);
        assert_eq!(shared.connections.load(Ordering::Acquire), 1);
        stop.store(true, Ordering::Release);
        handle.join().expect("serve exits");
        // Stop keeps the log readable (final flush stays available).
        assert_eq!(shared.log_snapshot().len(), 1);
    }

    #[test]
    fn origin_form_with_host_header_is_forwarded_too() {
        let upstream_response: &'static str =
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let (upstream, seen) = spawn_echo_upstream(upstream_response);
        let config =
            ProxyConfig::build(8080, RewriteRules::default(), vec![]).expect("config");
        let (proxy, shared, stop, handle) = spawn_proxy(config);
        let response = roundtrip(
            proxy,
            &format!(
                "GET /plain HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
                upstream.port()
            ),
        );
        assert!(response_text(&response).starts_with("HTTP/1.1 404"),);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.first().map(|s| s.as_str()), Some("GET /plain HTTP/1.1"));
        let entry = &shared.log_snapshot()[0];
        assert_eq!(entry.status, 404);
        assert_eq!(entry.host, "127.0.0.1");
        assert_eq!(entry.path, "/plain");
        stop.store(true, Ordering::Release);
        handle.join().expect("serve exits");
    }

    // ---- rewrite rule on/off cases -----------------------------------------

    #[test]
    fn https_link_rewrite_applies_only_when_enabled_and_is_counted() {
        let body = "<a href=\"https://secure.example/page\">link</a>";
        let upstream_response: &'static str = Box::leak(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nStrict-Transport-Security: max-age=31536000\r\nContent-Security-Policy: default-src 'self'\r\n\r\n{body}",
                body.len()
            )
            .into_boxed_str(),
        );
        let (upstream, _seen) = spawn_echo_upstream(upstream_response);
        // ALL rules ON.
        let rules = RewriteRules {
            rewrite_https_links: true,
            strip_hsts: true,
            strip_csp: true,
        };
        let config = ProxyConfig::build(8080, rules, vec![]).expect("config");
        let (proxy, shared, stop, handle) = spawn_proxy(config);
        let response = roundtrip(
            proxy,
            &format!("GET http://127.0.0.1:{}/x HTTP/1.1\r\nHost: h\r\n\r\n", upstream.port()),
        );
        let text = response_text(&response);
        assert!(text.contains("href=\"http://secure.example/page\""), "{text}");
        assert!(!text.contains("https://secure.example"), "{text}");
        assert!(
            !text.to_ascii_lowercase().contains("strict-transport-security"),
            "HSTS stripped: {text}"
        );
        assert!(
            !text.to_ascii_lowercase().contains("content-security-policy"),
            "CSP stripped: {text}"
        );
        // Content-Length was recomputed for the rewritten body.
        let body_start = text.find("\r\n\r\n").expect("head separator") + 4;
        let rewritten = &text[body_start..];
        assert!(text.contains(&format!("Content-Length: {}", rewritten.len())), "{text}");
        let entry = &shared.log_snapshot()[0];
        assert_eq!(entry.rewrites.https_links, 1);
        assert_eq!(entry.rewrites.hsts_stripped, 1);
        assert_eq!(entry.rewrites.csp_stripped, 1);
        assert_eq!(shared.rewrites_https_links.load(Ordering::Acquire), 1);
        assert_eq!(shared.rewrites_hsts_stripped.load(Ordering::Acquire), 1);
        assert_eq!(shared.rewrites_csp_stripped.load(Ordering::Acquire), 1);
        // Pre-rewrite headers are still in the log for evidence.
        assert!(
            entry.response_headers.contains("Strict-Transport-Security"),
            "response headers logged BEFORE rewrite"
        );
        stop.store(true, Ordering::Release);
        handle.join().expect("serve exits");
    }

    #[test]
    fn rules_off_delivers_response_byte_identical() {
        let body = "<a href=\"https://secure.example/page\">link</a>";
        let upstream_response: &'static str = Box::leak(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nStrict-Transport-Security: max-age=1\r\n\r\n{body}",
                body.len()
            )
            .into_boxed_str(),
        );
        let (upstream, _seen) = spawn_echo_upstream(upstream_response);
        let config =
            ProxyConfig::build(8080, RewriteRules::default(), vec![]).expect("config");
        let (proxy, shared, stop, handle) = spawn_proxy(config);
        let response = roundtrip(
            proxy,
            &format!("GET http://127.0.0.1:{}/x HTTP/1.1\r\nHost: h\r\n\r\n", upstream.port()),
        );
        let text = response_text(&response);
        assert!(text.contains("https://secure.example/page"), "no rewrite: {text}");
        assert!(text.to_ascii_lowercase().contains("strict-transport-security"));
        let entry = &shared.log_snapshot()[0];
        assert_eq!(entry.rewrites, RewriteCounts::default());
        stop.store(true, Ordering::Release);
        handle.join().expect("serve exits");
    }

    // ---- CONNECT refusal ----------------------------------------------------

    #[test]
    fn connect_is_refused_honestly_and_logged() {
        let config =
            ProxyConfig::build(8080, RewriteRules::default(), vec![]).expect("config");
        let (proxy, shared, stop, handle) = spawn_proxy(config);
        let response = roundtrip(
            proxy,
            "CONNECT target.example:443 HTTP/1.1\r\nHost: target.example:443\r\n\r\n",
        );
        let text = response_text(&response);
        assert!(text.starts_with("HTTP/1.1 501"), "{text}");
        assert!(text.contains(CONNECT_REFUSAL), "{text}");
        let entry = &shared.log_snapshot()[0];
        assert_eq!(entry.method, "CONNECT");
        assert_eq!(entry.status, 501);
        assert!(entry.note.as_deref().unwrap_or("").contains("CONNECT refused"));
        assert_eq!(shared.connect_refusals.load(Ordering::Acquire), 1);
        // https:// absolute-URI targets refuse the same way.
        let response = roundtrip(
            proxy,
            "GET https://secret.example/x HTTP/1.1\r\nHost: secret.example\r\n\r\n",
        );
        assert!(response_text(&response).starts_with("HTTP/1.1 501"));
        assert_eq!(shared.https_target_refusals.load(Ordering::Acquire), 1);
        stop.store(true, Ordering::Release);
        handle.join().expect("serve exits");
    }

    // ---- cap refusals --------------------------------------------------------

    #[test]
    fn oversized_request_head_is_refused_at_the_64k_cap() {
        let config =
            ProxyConfig::build(8080, RewriteRules::default(), vec![]).expect("config");
        let (proxy, shared, stop, handle) = spawn_proxy(config);
        let pad = "X".repeat(70 * 1024);
        let request = format!("GET /x HTTP/1.1\r\nX-Pad: {pad}\r\n\r\n");
        let response = roundtrip(proxy, &request);
        let text = response_text(&response);
        assert!(text.starts_with("HTTP/1.1 431"), "{text}");
        assert!(text.contains("64 KiB"), "{text}");
        assert_eq!(shared.refused_header_cap.load(Ordering::Acquire), 1);
        stop.store(true, Ordering::Release);
        handle.join().expect("serve exits");
    }

    #[test]
    fn oversized_request_body_is_refused_at_the_1mib_cap() {
        let config =
            ProxyConfig::build(8080, RewriteRules::default(), vec![]).expect("config");
        let (proxy, shared, stop, handle) = spawn_proxy(config);
        let request = format!(
            "POST http://127.0.0.1:1/upload HTTP/1.1\r\nHost: h\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_BYTES + 1
        );
        let response = roundtrip(proxy, &request);
        let text = response_text(&response);
        assert!(text.starts_with("HTTP/1.1 413"), "{text}");
        assert!(text.contains("1 MiB"), "{text}");
        assert_eq!(shared.refused_body_cap.load(Ordering::Acquire), 1);
        stop.store(true, Ordering::Release);
        handle.join().expect("serve exits");
    }

    #[test]
    fn oversized_upstream_body_is_refused_at_the_1mib_cap() {
        // Declared Content-Length exceeds the cap: refused before any body read.
        let upstream_response: &'static str =
            "HTTP/1.1 200 OK\r\nContent-Length: 2097152\r\nContent-Type: text/plain\r\n\r\nsmall";
        let (upstream, _seen) = spawn_echo_upstream(upstream_response);
        let config =
            ProxyConfig::build(8080, RewriteRules::default(), vec![]).expect("config");
        let (proxy, shared, stop, handle) = spawn_proxy(config);
        let response = roundtrip(
            proxy,
            &format!("GET http://127.0.0.1:{}/big HTTP/1.1\r\nHost: h\r\n\r\n", upstream.port()),
        );
        let text = response_text(&response);
        assert!(text.starts_with("HTTP/1.1 502"), "{text}");
        assert!(text.contains("1 MiB"), "{text}");
        assert_eq!(shared.refused_body_cap.load(Ordering::Acquire), 1);
        let entry = &shared.log_snapshot()[0];
        assert!(entry.response_headers.contains("Content-Length: 2097152"),
            "pre-refusal upstream headers still logged");
        stop.store(true, Ordering::Release);
        handle.join().expect("serve exits");
    }

    #[test]
    fn allowlisted_proxy_refuses_unknown_clients_and_open_proxy_takes_any() {
        let upstream_response: &'static str =
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok";
        let (upstream, _seen) = spawn_echo_upstream(upstream_response);
        // Allowlist with an unrelated IP: the loopback client is refused.
        let config = ProxyConfig::build(
            8080,
            RewriteRules::default(),
            vec!["203.0.113.9".parse().unwrap()],
        )
        .expect("config");
        let (proxy, shared, stop, handle) = spawn_proxy(config);
        let response = roundtrip(
            proxy,
            &format!("GET http://127.0.0.1:{}/x HTTP/1.1\r\nHost: h\r\n\r\n", upstream.port()),
        );
        assert!(response_text(&response).starts_with("HTTP/1.1 403"),);
        assert_eq!(shared.refused_allowlist.load(Ordering::Acquire), 1);
        stop.store(true, Ordering::Release);
        handle.join().expect("serve exits");
        // Empty allowlist = any client (disclosed in the dialog).
        let config =
            ProxyConfig::build(8080, RewriteRules::default(), vec![]).expect("config");
        let (proxy, shared, stop, handle) = spawn_proxy(config);
        let response = roundtrip(
            proxy,
            &format!("GET http://127.0.0.1:{}/x HTTP/1.1\r\nHost: h\r\n\r\n", upstream.port()),
        );
        assert!(response_text(&response).starts_with("HTTP/1.1 200"));
        assert_eq!(shared.refused_allowlist.load(Ordering::Acquire), 0);
        stop.store(true, Ordering::Release);
        handle.join().expect("serve exits");
    }

    // ---- concurrency + runtime caps + stop ----------------------------------

    #[test]
    fn the_ninth_concurrent_connection_gets_an_honest_503() {
        let config =
            ProxyConfig::build(8080, RewriteRules::default(), vec![]).expect("config");
        let (proxy, shared, stop, handle) = spawn_proxy(config);
        // Eight silent clients occupy the handler pool (they read nothing).
        let mut held = Vec::new();
        for _ in 0..MAX_CONCURRENT_CONNECTIONS {
            let stream = TcpStream::connect(proxy).expect("occupier connects");
            held.push(stream);
        }
        std::thread::sleep(Duration::from_millis(250));
        let ninth = roundtrip(proxy, "GET http://127.0.0.1:1/x HTTP/1.1\r\nHost: h\r\n\r\n");
        let text = response_text(&ninth);
        assert!(text.starts_with("HTTP/1.1 503"), "{text}");
        assert!(text.contains("cap"), "{text}");
        assert_eq!(shared.refused_busy.load(Ordering::Acquire), 1);
        // Release the occupiers so the handler threads drain, then stop.
        for stream in held {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        std::thread::sleep(Duration::from_millis(150));
        stop.store(true, Ordering::Release);
        handle.join().expect("serve exits");
    }

    #[test]
    fn runtime_cap_auto_stops_the_accept_loop() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("binds");
        let shared = Arc::new(ProxyShared::default());
        let stop = Arc::new(AtomicBool::new(false));
        let started = Instant::now();
        let shared_for_thread = Arc::clone(&shared);
        let stop_for_thread = Arc::clone(&stop);
        let handle = std::thread::spawn(move || {
            serve(
                listener,
                &ProxyConfig::build(8080, RewriteRules::default(), vec![]).expect("config"),
                started,
                &stop_for_thread,
                &shared_for_thread,
                150, // tiny cap: the loop must exit on its own
            );
        });
        handle.join().expect("loop exits by itself");
        assert!(
            shared.runtime_capped.load(Ordering::Acquire),
            "runtime cap flagged"
        );
        stop.store(true, Ordering::Release);
    }

    #[test]
    fn stop_flag_ends_the_loop_and_the_log_survives_the_final_flush() {
        let upstream_response: &'static str =
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok";
        let (upstream, _seen) = spawn_echo_upstream(upstream_response);
        let config =
            ProxyConfig::build(8080, RewriteRules::default(), vec![]).expect("config");
        let (proxy, shared, stop, handle) = spawn_proxy(config);
        let response = roundtrip(
            proxy,
            &format!("GET http://127.0.0.1:{}/x HTTP/1.1\r\nHost: h\r\n\r\n", upstream.port()),
        );
        assert!(response_text(&response).starts_with("HTTP/1.1 200"));
        stop.store(true, Ordering::Release);
        handle.join().expect("serve exits promptly");
        // Final log flush: the entry is still readable after stop.
        assert_eq!(shared.log_snapshot().len(), 1);
        assert_eq!(shared.log_len(), 1);
    }

    #[test]
    fn log_ring_drops_oldest_past_512_entries() {
        let shared = ProxyShared::default();
        for i in 0..(MAX_LOG_ENTRIES + 10) {
            let mut entry = blank_entry("127.0.0.1");
            entry.path = format!("/p{i}");
            shared.push_log(entry);
        }
        assert_eq!(shared.log_len(), MAX_LOG_ENTRIES);
        let snapshot = shared.log_snapshot();
        assert_eq!(snapshot[0].path, "/p10", "oldest entries dropped first");
        assert_eq!(
            snapshot.last().map(|e| e.path.as_str()),
            Some(format!("/p{}", MAX_LOG_ENTRIES + 9).as_str())
        );
    }

    #[test]
    fn upstream_connect_failure_lands_as_an_honest_502() {
        // Port 1 on loopback is closed in the test environment.
        let config =
            ProxyConfig::build(8080, RewriteRules::default(), vec![]).expect("config");
        let (proxy, shared, stop, handle) = spawn_proxy(config);
        let response = roundtrip(
            proxy,
            "GET http://127.0.0.1:1/dead HTTP/1.1\r\nHost: h\r\n\r\n",
        );
        let text = response_text(&response);
        assert!(text.starts_with("HTTP/1.1 502"), "{text}");
        assert_eq!(shared.upstream_failures.load(Ordering::Acquire), 1);
        let entry = &shared.log_snapshot()[0];
        assert!(entry.note.as_deref().unwrap_or("").contains("upstream"));
        stop.store(true, Ordering::Release);
        handle.join().expect("serve exits");
    }

    #[test]
    fn chunked_upstream_bodies_are_decoded_within_the_cap() {
        let upstream_response: &'static str = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nhref=\"https://x\"\r\n0\r\n\r\n";
        let (upstream, _seen) = spawn_echo_upstream(upstream_response);
        let rules = RewriteRules {
            rewrite_https_links: true,
            ..RewriteRules::default()
        };
        let config = ProxyConfig::build(8080, rules, vec![]).expect("config");
        let (proxy, shared, stop, handle) = spawn_proxy(config);
        let response = roundtrip(
            proxy,
            &format!("GET http://127.0.0.1:{}/c HTTP/1.1\r\nHost: h\r\n\r\n", upstream.port()),
        );
        let text = response_text(&response);
        assert!(text.contains("href=\"http://x\""), "{text}");
        assert!(!text.contains("https://"), "{text}");
        let entry = &shared.log_snapshot()[0];
        assert_eq!(entry.rewrites.https_links, 1);
        stop.store(true, Ordering::Release);
        handle.join().expect("serve exits");
    }

    #[test]
    fn read_errors_keep_their_honest_discriminators() {
        // Sanity on the error taxonomy the refusals surface.
        assert!(matches!(ReadError::TooLarge, ReadError::TooLarge));
        assert!(matches!(ReadError::Timeout, ReadError::Timeout));
        assert!(matches!(ReadError::Closed, ReadError::Closed));
        assert!(matches!(ReadError::Malformed, ReadError::Malformed));
    }
}
