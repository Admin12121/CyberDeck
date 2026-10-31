//! Web studio backend (§5.2): HTTP sender, native review scanner, spider,
//! HTTP-only proxy, and sidecar slots for nikto/sqlmap/XSStrike.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

use serde::Serialize;
use tauri::State;

use crate::engines::which_exists;

const MAX_BODY_BYTES: usize = 512 * 1024;
const MAX_CAPTURED_REQUESTS: usize = 10_000;
const MAX_PENDING_REQUESTS: usize = 100;
const MAX_PROXY_BODY: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MatchReplaceRule {
    pub find: String,
    pub replace: String,
}

/// A request held by the interceptor until forwarded or dropped.
pub struct PendingRequest {
    pub stream: ProxyStream,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub info: CapturedRequest,
}

/// A waiting browser connection may be plaintext HTTP or an intercepted TLS
/// session. Both must be able to receive Forward/Drop decisions.
pub enum ProxyStream {
    Plain(TcpStream),
    Tls(tokio_rustls::server::TlsStream<TcpStream>),
}

impl ProxyStream {
    async fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;
        match self {
            Self::Plain(stream) => stream.write_all(bytes).await,
            Self::Tls(stream) => stream.write_all(bytes).await,
        }
    }
}

pub struct ProxyShared {
    pub running: AtomicBool,
    pub intercept: AtomicBool,
    pub port: AtomicU16,
    pub rules: Mutex<Vec<MatchReplaceRule>>,
    pub captured: Mutex<Vec<CapturedRequest>>,
    pub pending: Mutex<HashMap<u64, PendingRequest>>,
    pub next_id: AtomicU64,
    /// CA state for TLS interception, set by proxy_start.
    pub ca: Mutex<Option<Arc<crate::webtls::CaState>>>,
    /// Relayed WebSocket connections, recorded during TLS interception.
    pub ws: Mutex<Vec<crate::webtls::WsConnection>>,
}

pub struct WebCtx {
    pub proxy_running: AtomicBool,
    pub proxy_port: AtomicU16,
    pub proxy_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub shared: Arc<ProxyShared>,
    pub ca: Mutex<Option<Arc<crate::webtls::CaState>>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapturedRequest {
    pub id: u64,
    pub method: String,
    pub host: String,
    pub path: String,
    pub status: u16,
    pub size: usize,
    pub at_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct ProxyStatusWire {
    pub running: bool,
    pub port: u16,
    pub captured: usize,
}

#[derive(Debug, Serialize)]
pub struct HttpResponseWire {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub body_truncated: bool,
    pub size: usize,
    pub duration_ms: u64,
    pub url: String,
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("CyberDeck-Workbench/0.1")
        .build()
        .expect("http client")
}

/// Parse a raw HTTP request into (method, url, headers, body). The Host or
/// absolute-URI supplies the target; scheme defaults to http.
pub fn parse_raw_request(
    raw: &str,
    scheme: &str,
) -> Result<(String, String, Vec<(String, String)>, String), String> {
    let (head, body) = match raw.split_once("\r\n\r\n") {
        Some((h, b)) => (h, b.to_string()),
        None if raw.contains("\n\n") => {
            let (h, b) = raw.split_once("\n\n").unwrap();
            (h, b.to_string())
        }
        None => (raw, String::new()),
    };
    let mut lines = head.lines();
    let request_line = lines.next().ok_or("empty request")?.trim().to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("missing method")?.to_uppercase();
    let target = parts.next().ok_or("missing path")?.to_string();
    let mut host = String::new();
    let mut headers = Vec::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_string();
            let value = value.trim().to_string();
            if name.eq_ignore_ascii_case("host") {
                host = value.clone();
            }
            headers.push((name, value));
        }
    }
    let url = if target.starts_with("http://") || target.starts_with("https://") {
        target
    } else if !host.is_empty() {
        format!("{scheme}://{host}{target}")
    } else {
        return Err("request needs a Host header or absolute URL".to_string());
    };
    Ok((method, url, headers, body))
}

/// Send an editable raw request (Repeater). Real network call, no mocks.
#[tauri::command]
pub async fn http_send(request_raw: String) -> Result<HttpResponseWire, String> {
    let (method, url, headers, body) = parse_raw_request(&request_raw, "http")?;
    let client = http_client();
    let method_req =
        reqwest::Method::from_bytes(method.as_bytes()).map_err(|e| format!("bad method: {e}"))?;
    let mut request = client.request(method_req, &url);
    for (name, value) in &headers {
        if name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        request = request.header(name, value);
    }
    if !body.is_empty() && !matches!(method.as_str(), "GET" | "HEAD") {
        request = request.body(body.clone());
    }
    let started = Instant::now();
    let mut response = request
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    let status = response.status().as_u16();
    let resp_headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("<binary>").to_string()))
        .collect();
    let size_hint = response
        .content_length()
        .unwrap_or(0)
        .min(usize::MAX as u64) as usize;
    let mut body_bytes = Vec::new();
    let mut truncated = false;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("body read failed: {e}"))?
    {
        let space = MAX_BODY_BYTES.saturating_sub(body_bytes.len());
        if chunk.len() > space {
            body_bytes.extend_from_slice(&chunk[..space]);
            truncated = true;
            break;
        }
        body_bytes.extend_from_slice(&chunk);
    }
    let size = if truncated {
        size_hint.max(body_bytes.len())
    } else {
        body_bytes.len()
    };
    let body_text = String::from_utf8_lossy(&body_bytes).to_string();
    Ok(HttpResponseWire {
        status,
        headers: resp_headers,
        body: body_text,
        body_truncated: truncated,
        size,
        duration_ms: started.elapsed().as_millis() as u64,
        url,
    })
}

// --- native web review scanner (our own checks) ------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: String, // info | low | medium | high
    pub title: String,
    pub detail: String,
    pub evidence: String,
}

const INTERESTING_PATHS: &[(&str, &str)] = &[
    (
        "/robots.txt",
        "robots.txt present; review disallowed entries for hidden paths",
    ),
    ("/sitemap.xml", "sitemap.xml present"),
    ("/.env", ".env file exposed: secrets leak"),
    ("/.git/HEAD", ".git directory exposed: source leak"),
    ("/admin", "/admin responded; review authentication"),
    ("/administrator", "/administrator responded"),
    ("/phpmyadmin", "phpMyAdmin reachable"),
    ("/wp-login.php", "WordPress login reachable"),
    ("/backup", "/backup responded; possible data exposure"),
    ("/server-status", "Apache server-status reachable"),
];

const SECURITY_HEADERS: &[(&str, &str)] = &[
    ("content-security-policy", "Content-Security-Policy"),
    ("strict-transport-security", "Strict-Transport-Security"),
    ("x-frame-options", "X-Frame-Options"),
    ("x-content-type-options", "X-Content-Type-Options"),
];

/// Native active review of a target: reachable paths, header hygiene, banner
/// disclosure. Our own checks; external engines add depth via slots below.
#[tauri::command]
pub async fn web_scan(target_url: String, authorized: bool) -> Result<Vec<Finding>, String> {
    require_authorization(authorized)?;
    let mut origin = reqwest::Url::parse(target_url.trim())
        .map_err(|e| format!("invalid scan target URL: {e}"))?;
    if !matches!(origin.scheme(), "http" | "https")
        || origin.host_str().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
    {
        return Err("target must be HTTP(S) without URL credentials".to_string());
    }
    origin.set_path("/");
    origin.set_query(None);
    origin.set_fragment(None);
    let base = origin.as_str().trim_end_matches('/').to_string();
    let client = http_client();
    let mut findings: Vec<Finding> = Vec::new();

    let root = client.get(&base).send().await;
    let root_headers = if let Ok(resp) = &root {
        let mut map = Vec::new();
        for (k, v) in resp.headers() {
            map.push((
                k.to_string().to_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            ));
        }
        Some(map)
    } else {
        None
    };

    if let Some(headers) = &root_headers {
        for (header, title) in SECURITY_HEADERS {
            if *header == "strict-transport-security" && origin.scheme() != "https" {
                continue;
            }
            if *header == "x-frame-options" && headers.iter().any(|(k, v)| {
                k == "content-security-policy" && v.to_ascii_lowercase().contains("frame-ancestors")
            }) {
                continue;
            }
            if !headers.iter().any(|(k, _)| k == header) {
                findings.push(Finding {
                    severity: "low".to_string(),
                    title: format!("missing security header: {title}"),
                    detail: "the response did not include this header; adds hardening against common web attacks".to_string(),
                    evidence: base.clone(),
                });
            }
        }
        if let Some((_, server)) = headers.iter().find(|(k, _)| k == "server") {
            findings.push(Finding {
                severity: "info".to_string(),
                title: "server banner disclosed".to_string(),
                detail: "the Server header reveals software and version; suppress it".to_string(),
                evidence: format!("server: {server}"),
            });
        }
    }

    for (path, note) in INTERESTING_PATHS {
        let url = format!("{base}{path}");
        if let Ok(resp) = client.get(&url).send().await {
            let status = resp.status().as_u16();
            if status == 200 {
                let sensitive = matches!(*path, "/.env" | "/.git/HEAD");
                if sensitive {
                    let mut response = resp;
                    let mut preview = Vec::new();
                    while let Ok(Some(chunk)) = response.chunk().await {
                        if preview.len().saturating_add(chunk.len()) > 4096 {
                            break;
                        }
                        preview.extend_from_slice(&chunk);
                    }
                    if !confirmed_exposure(path, &preview) {
                        continue;
                    }
                }
                let severity = if sensitive { "high" } else { "info" };
                findings.push(Finding {
                    severity: severity.to_string(),
                    title: format!("found {path}"),
                    detail: note.to_string(),
                    evidence: format!("{url} -> {status}"),
                });
            }
        }
    }
    Ok(findings)
}

/// A generic HTTP 200 response is frequently an SPA fallback.
/// Recognize actual sensitive-file contents before reporting high severity.
fn confirmed_exposure(path: &str, body: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(body) else { return false; };
    match path {
        "/.git/HEAD" => {
            let value = text.trim();
            (value.starts_with("ref: refs/heads/") && value.len() < 200)
                || (value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit()))
        }
        "/.env" => {
            if text.to_ascii_lowercase().contains("<html") { return false; }
            text.lines().any(|line| {
                let Some((name, _)) = line.trim().split_once('=') else { return false };
                matches!(name, "APP_KEY" | "APP_SECRET" | "DB_PASSWORD" |
                    "DATABASE_URL" | "AWS_SECRET_ACCESS_KEY" | "SECRET_KEY" |
                    "DB_HOST" | "DB_DATABASE" | "APP_ENV")
            })
        }
        _ => false,
    }
}

/// Resolve a link only if its parsed origin matches the authorized origin.
/// Substring hostname comparisons and automatic redirects are not safe scope checks.
fn resolve_scoped_link(
    origin: &reqwest::Url,
    page: &reqwest::Url,
    href: &str,
) -> Option<reqwest::Url> {
    let mut url = page.join(href).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.origin() != origin.origin()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    url.set_fragment(None);
    Some(url)
}

fn require_authorization(authorized: bool) -> Result<(), String> {
    if authorized {
        Ok(())
    } else {
        Err("explicit authorization acknowledgment required".to_string())
    }
}

/// Limit each crawled response; do not buffer an unbounded remote page.
async fn fetch_crawl_page(client: &reqwest::Client, url: &reqwest::Url) -> Option<String> {
    const MAX_PAGE: usize = 1024 * 1024;
    let mut resp = client.get(url.clone()).send().await.ok()?;
    if !resp.status().is_success() || resp.content_length().unwrap_or(0) > MAX_PAGE as u64 {
        return None;
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.ok()? {
        if body.len().saturating_add(chunk.len()) > MAX_PAGE {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    Some(String::from_utf8_lossy(&body).into_owned())
}

/// A bounded same-origin crawler; redirects are disabled in http_client().
#[tauri::command]
pub async fn spider_scan(
    target_url: String,
    max_depth: u8,
    authorized: bool,
) -> Result<Vec<String>, String> {
    require_authorization(authorized)?;
    let base =
        reqwest::Url::parse(target_url.trim()).map_err(|e| format!("invalid target URL: {e}"))?;
    if !matches!(base.scheme(), "http" | "https")
        || base.host_str().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
    {
        return Err("target must be HTTP(S) without URL credentials".to_string());
    }
    let client = http_client();
    let mut seen: HashSet<String> = HashSet::new();
    seen.insert(base.to_string());
    let mut queue = VecDeque::from([(base.clone(), 0_u8)]);
    let mut links = vec![base.to_string()];
    while let Some((url, depth)) = queue.pop_front() {
        if depth >= max_depth.min(4) || links.len() >= 60 {
            continue;
        }
        let Some(html) = fetch_crawl_page(&client, &url).await else {
            continue;
        };
        // A deliberate first-stage parser: full HTML tokenization is a later native port.
        for chunk in html.split("href=\"").skip(1) {
            let Some(end) = chunk.find('"') else { continue };
            let Some(absolute) = resolve_scoped_link(&base, &url, &chunk[..end]) else {
                continue;
            };
            if absolute.query().is_some() {
                continue;
            }
            let key = absolute.to_string();
            if seen.insert(key.clone()) {
                links.push(key);
                if links.len() >= 60 {
                    break;
                }
                queue.push_back((absolute, depth + 1));
            }
        }
    }
    links.sort();
    Ok(links)
}

#[cfg(test)]
mod scope_tests {
    use super::*;

    #[test]
    fn origin_match_is_not_hostname_substring_match() {
        let base = reqwest::Url::parse("https://example.com/path").unwrap();
        assert!(resolve_scoped_link(&base, &base, "https://example.com.evil.test/path").is_none());
        assert!(resolve_scoped_link(&base, &base, "https://evil.test/example.com").is_none());
        assert!(resolve_scoped_link(&base, &base, "http://example.com/path").is_none());
        assert!(resolve_scoped_link(&base, &base, "javascript:alert(1)").is_none());
        assert_eq!(
            resolve_scoped_link(&base, &base, "../next")
                .unwrap()
                .as_str(),
            "https://example.com/next"
        );
    }

    #[test]
    fn connect_target_requires_unambiguous_authority() {
        assert_eq!(parse_connect_target("example.com:443").unwrap(), ("example.com".to_string(), 443));
        assert_eq!(parse_connect_target("[::1]:8443").unwrap(), ("::1".to_string(), 8443));
        for bad in ["example.com", "example.com:0", "example.com:abc", "::1:443",
                    "user@example.com:443", "https://example.com:443", "example.com:65536"] {
            assert!(parse_connect_target(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn tls_tunnel_rejects_host_confusion() {
        let headers = vec![("Host".into(), "example.com:8443".into())];
        assert!(tls_host_matches(&headers, "example.com", 8443));
        assert!(!tls_host_matches(&headers, "example.com", 443));
        assert!(!tls_host_matches(&headers, "other.example", 8443));
        assert!(!tls_host_matches(&[("Host".into(), "example.com".into()),
                ("host".into(), "evil.invalid".into())], "example.com", 443));
    }

    #[test]
    fn rules_preserve_non_utf8_payloads() {
        let source = vec![0xff, 0x00, b'A', b'B', 0xfe];
        assert_eq!(replace_bytes_limited(source, b"AB", b"XYZ"),
                   vec![0xff, 0x00, b'X', b'Y', b'Z', 0xfe]);
    }

    #[test]
    fn generic_spa_fallbacks_are_not_sensitive_exposures() {
        assert!(!confirmed_exposure("/.env", b"<html>index.html</html>"));
        assert!(!confirmed_exposure("/.git/HEAD", b"<html>index.html</html>"));
        assert!(confirmed_exposure("/.env", b"APP_KEY=sample-value\n"));
        assert!(confirmed_exposure("/.git/HEAD", b"ref: refs/heads/main\n"));
    }

    #[test]
    fn active_scans_require_acknowledgment() {
        assert!(require_authorization(false).is_err());
        assert!(require_authorization(true).is_ok());
    }
}

// --- HTTP interception proxy ---------------------------------------------------

/// Start the local interception proxy on 127.0.0.1:port. Plain-HTTP requests
/// are captured and forwarded (or held when interception is on); CONNECT
/// tunnels pass through without interception until the CA arc lands.
#[tauri::command]
pub async fn proxy_start(
    app: tauri::AppHandle,
    port: u16,
    ctx: State<'_, WebCtx>,
) -> Result<ProxyStatusWire, String> {
    // CA is initialized with the proxy so HTTPS interception is ready at once
    let ca_dir = crate::storage_paths::data_dir(&app)?;
    let ca = crate::webtls::init_ca(&ca_dir)?;
    *ctx.shared.ca.lock().expect("ca poisoned") = Some(Arc::clone(&ca));
    *ctx.ca.lock().expect("ca poisoned") = Some(ca);
    if ctx.shared.running.load(Ordering::Relaxed) {
        return Err("proxy already running; stop it first".to_string());
    }
    let addr: SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .map_err(|e| format!("bad port: {e}"))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("cannot bind 127.0.0.1:{port}: {e}"))?;
    ctx.shared.running.store(true, Ordering::Relaxed);
    ctx.shared.port.store(port, Ordering::Relaxed);
    ctx.proxy_running.store(true, Ordering::Relaxed);
    ctx.proxy_port.store(port, Ordering::Relaxed);
    let shared = Arc::clone(&ctx.shared);
    let handle = tokio::spawn(async move {
        loop {
            if !shared.running.load(Ordering::Relaxed) {
                break;
            }
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let shared = Arc::clone(&shared);
            tokio::spawn(async move {
                let _ = handle_conn(stream, shared).await;
            });
        }
    });
    *ctx.proxy_handle.lock().expect("proxy handle poisoned") = Some(handle);
    Ok(ProxyStatusWire {
        running: true,
        port,
        captured: ctx.shared.captured.lock().expect("captured poisoned").len(),
    })
}

async fn handle_conn(mut stream: TcpStream, shared: Arc<ProxyShared>) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let (head, body_bytes) = tokio::time::timeout(
        Duration::from_secs(15),
        crate::webtls::read_http_message(&mut stream),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "HTTP request timed out"))??;
    if head.starts_with("CONNECT ") {
        return connect_tunnel(stream, shared, &head).await;
    }
    // Headers are textual; bodies are arbitrary bytes and must never undergo
    // lossy UTF-8 decoding when forwarded or intercepted.
    let Ok((method, url, headers, _)) = parse_raw_request(&head, "http") else {
        return Ok(());
    };
    let Ok(parsed) = reqwest::Url::parse(&url) else { return Ok(()); };
    if !matches!(parsed.scheme(), "http" | "https") { return Ok(()); }
    let host = parsed.host_str().unwrap_or_default().to_string();
    let path = match parsed.query() {
        Some(query) => format!("{}?{query}", parsed.path()),
        None => parsed.path().to_string(),
    };
    let body = body_bytes;

    // interceptor holds the request (and the browser connection) until the
    // user forwards or drops it
    if shared.intercept.load(Ordering::Relaxed) {
        let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
        let info = CapturedRequest {
            id,
            method: method.clone(),
            host: host.clone(),
            path: path.clone(),
            status: 0,
            size: body.len(),
            at_ms: now_ms(),
        };
        let request = PendingRequest {
            stream: ProxyStream::Plain(stream),
            method,
            url,
            headers,
            body,
            info,
        };
        let rejected = {
            let mut pending = shared.pending.lock().expect("pending poisoned");
            if pending.len() >= MAX_PENDING_REQUESTS {
                Some(request)
            } else {
                pending.insert(id, request);
                None
            }
        };
        if let Some(mut rejected) = rejected {
            rejected.stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await?;
        }
        return Ok(());
    }

    let rules = shared.rules.lock().expect("rules poisoned").clone();
    let (method, url, headers, body) = apply_rules(method, url, headers, body, &rules);
    let (status, resp_headers, resp_body) = execute_request(&method, &url, &headers, &body).await;
    let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
    push_capture(
        &shared,
        CapturedRequest {
            id,
            method,
            host,
            path,
            status,
            size: resp_body.len(),
            at_ms: now_ms(),
        },
    );

    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\n",
        reason = reason_phrase(status)
    );
    for (name, value) in &resp_headers {
        if name.eq_ignore_ascii_case("content-length") || is_hop_header(name) {
            continue;
        }
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str(&format!(
        "content-length: {}\r\nconnection: close\r\n\r\n",
        resp_body.len()
    ));
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(&resp_body).await?;
    Ok(())
}

/// CONNECT tunnel: raw TCP passthrough when interception is off; full TLS
/// MITM (per-host leaf certs, rules, history, WS relay) when on.
async fn connect_tunnel(
    mut stream: TcpStream,
    shared: Arc<ProxyShared>,
    head_text: &str,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let target = head_text.split_whitespace().nth(1).unwrap_or_default();
    let (host, port) = parse_connect_target(target)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let intercepting = shared.intercept.load(Ordering::Relaxed);
    let ca = shared.ca.lock().expect("ca poisoned").clone();

    if !intercepting || ca.is_none() {
        // honest passthrough: relay raw bytes to the upstream host
        let mut upstream = tokio::time::timeout(
            Duration::from_secs(15), TcpStream::connect((host.as_str(), port)),
        )
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream CONNECT timed out"))??;
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        // Preserve half-closes; select! previously discarded the other direction.
        tokio::io::copy_bidirectional(&mut stream, &mut upstream).await?;
        return Ok(());
    }

    let _ = stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await;
    let ca = ca.expect("ca checked");
    let acceptor = crate::webtls::tls_acceptor(&ca, &host).map_err(|e| std::io::Error::other(e))?;
    let mut tls_stream = acceptor
        .accept(stream)
        .await
        .map_err(|e| std::io::Error::other(format!("tls handshake with client failed: {e}")))?;
    let (head_text, body_bytes) = tokio::time::timeout(
        Duration::from_secs(15),
        crate::webtls::read_http_message(&mut tls_stream),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "HTTPS request timed out"))??;
    let request_line = head_text.lines().next().unwrap_or_default().to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    let headers: Vec<(String, String)> = head_text
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let body = body_bytes;

    // Refuse authority mismatches inside an authenticated CONNECT tunnel.
    if !path.starts_with('/') || path.starts_with("//")
        || !tls_host_matches(&headers, &host, port)
    {
        tls_stream.write_all(b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await?;
        return Ok(());
    }

    // Only treat a properly declared WebSocket upgrade as a raw duplex stream.
    if headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("upgrade") && v.eq_ignore_ascii_case("websocket")
    }) && headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("connection") &&
            v.split(',').any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
    }) {
        let tcp = TcpStream::connect((host.as_str(), port))
            .await
            .map_err(|e| std::io::Error::other(format!("ws upstream connect failed: {e}")))?;
        let connector = crate::webtls::tls_client().map_err(|e| std::io::Error::other(e))?;
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|e| std::io::Error::other(format!("bad sni: {e}")))?;
        let mut upstream = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| std::io::Error::other(format!("ws upstream tls failed: {e}")))?;
        upstream.write_all(head_text.as_bytes()).await?;
        upstream.write_all(&body).await?;
        let (mut c_read, mut c_write) = tokio::io::split(tls_stream);
        let (mut u_read, mut u_write) = tokio::io::split(upstream);
        let started = now_ms();
        {
            let mut ws = shared.ws.lock().expect("ws poisoned");
            if ws.len() >= 1000 { ws.remove(0); }
            ws.push(crate::webtls::WsConnection {
                host: host.clone(),
                bytes_client_to_server: 0,
                bytes_server_to_client: 0,
                at_ms: started,
            });
        }
        let (c2u, u2c) = tokio::join!(
            tokio::io::copy(&mut c_read, &mut u_write),
            tokio::io::copy(&mut u_read, &mut c_write)
        );
        let mut ws = shared.ws.lock().expect("ws poisoned");
        if let Some(record) = ws.iter_mut().rev().find(|w| w.at_ms == started && w.host == host) {
            record.bytes_client_to_server = c2u.unwrap_or(0);
            record.bytes_server_to_client = u2c.unwrap_or(0);
        }
        return Ok(());
    }

    // CONNECT interception must share the same Forward/Drop queue as HTTP.
    // Retain the authenticated TLS stream until the operator decides.
    let url = format!("https://{target}{path}");
    if shared.intercept.load(Ordering::Relaxed) {
        let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
        let info = CapturedRequest {
            id, method: method.clone(), host: host.clone(), path: path.clone(),
            status: 0, size: body.len(), at_ms: now_ms(),
        };
        let request = PendingRequest {
            stream: ProxyStream::Tls(tls_stream),
            method, url, headers, body, info,
        };
        let rejected = {
            let mut pending = shared.pending.lock().expect("pending poisoned");
            if pending.len() >= MAX_PENDING_REQUESTS {
                Some(request)
            } else {
                pending.insert(id, request);
                None
            }
        };
        if let Some(mut rejected) = rejected {
            rejected.stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await?;
        }
        return Ok(());
    }

    // plain HTTP inside TLS: same rules + capture path as plain proxying
    let rules = shared.rules.lock().expect("rules poisoned").clone();
    let (r_method, r_url, r_headers, r_body) = apply_rules(
        method.clone(),
        url,
        headers,
        body,
        &rules,
    );
    let (status, resp_headers, resp_body) =
        execute_request(&r_method, &r_url, &r_headers, &r_body).await;
    let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
    push_capture(
        &shared,
        CapturedRequest {
            id,
            method: r_method,
            host: host.clone(),
            path: path.clone(),
            status,
            size: resp_body.len(),
            at_ms: now_ms(),
        },
    );
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\n",
        reason = reason_phrase(status)
    );
    for (name, value) in &resp_headers {
        if name.eq_ignore_ascii_case("content-length") || is_hop_header(name) {
            continue;
        }
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str(&format!(
        "content-length: {}\r\nconnection: close\r\n\r\n",
        resp_body.len()
    ));
    tls_stream.write_all(response.as_bytes()).await?;
    tls_stream.write_all(&resp_body).await?;
    Ok(())
}

/// CONNECT authority must contain an explicit valid TCP port. Splitting on
/// the first colon is incorrect for bracketed IPv6 literals.
fn parse_connect_target(authority: &str) -> Result<(String, u16), String> {
    let (raw_host, raw_port) = authority.rsplit_once(':')
        .ok_or("CONNECT target must include host:port")?;
    let port = raw_port.parse::<u16>()
        .map_err(|_| "invalid CONNECT port")?;
    if port == 0 { return Err("CONNECT port must not be zero".to_string()); }
    let host = if raw_host.starts_with('[') && raw_host.ends_with(']') {
        let inner = &raw_host[1..raw_host.len()-1];
        inner.parse::<std::net::Ipv6Addr>()
            .map_err(|_| "invalid CONNECT IPv6 literal")?;
        inner.to_string()
    } else {
        if raw_host.contains(':') { return Err("IPv6 CONNECT host must be bracketed".to_string()); }
        raw_host.to_string()
    };
    if host.is_empty() || host.chars().any(|c| matches!(c, '/' | '@' | '#' | '?')) {
        return Err("invalid CONNECT hostname".to_string());
    }
    let url = reqwest::Url::parse(&format!("https://{authority}/"))
        .map_err(|_| "invalid CONNECT authority")?;
    if !url.username().is_empty() || url.password().is_some() || url.host_str().is_none() {
        return Err("invalid CONNECT authority".to_string());
    }
    Ok((host, port))
}

/// Match the inner Host authority against the CONNECT destination. Without
/// this guard a TLS tunnel for one hostname could proxy an unrelated origin.
fn tls_host_matches(headers: &[(String, String)], host: &str, port: u16) -> bool {
    let hosts: Vec<&str> = headers.iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.as_str()).collect();
    if hosts.len() != 1 { return false; }
    let authority = hosts[0].trim();
    if authority.contains(['/', '@', '#', '?', ' ', '\t', '\r', '\n']) {
        return false;
    }
    let Ok(url) = reqwest::Url::parse(&format!("https://{authority}/")) else { return false; };
    let Some(actual_host) = url.host_str() else { return false; };
    actual_host.eq_ignore_ascii_case(host) && url.port_or_known_default() == Some(port)
}

fn is_hop_header(name: &str) -> bool {
    ["connection", "proxy-connection", "keep-alive", "transfer-encoding",
     "te", "trailer", "upgrade", "proxy-authorization", "proxy-authenticate"]
    .iter().any(|header| name.eq_ignore_ascii_case(header))
}

/// Text match-and-replace must preserve bytes outside the matched byte ranges.
/// If a rule would expand a body beyond the bounded proxy limit, do not apply it.
fn replace_bytes_limited(source: Vec<u8>, find: &[u8], replace: &[u8]) -> Vec<u8> {
    if find.is_empty() || find == replace { return source; }
    let mut output = Vec::with_capacity(source.len().min(MAX_PROXY_BODY));
    let mut cursor = 0;
    while let Some(pos) = source[cursor..].windows(find.len()).position(|slice| slice == find) {
        let start = cursor + pos;
        if output.len().saturating_add(start - cursor).saturating_add(replace.len()) > MAX_PROXY_BODY {
            return source;
        }
        output.extend_from_slice(&source[cursor..start]);
        output.extend_from_slice(replace);
        cursor = start + find.len();
    }
    if output.len().saturating_add(source.len() - cursor) > MAX_PROXY_BODY { return source; }
    output.extend_from_slice(&source[cursor..]);
    output
}

fn push_capture(shared: &ProxyShared, request: CapturedRequest) {
    let mut captured = shared.captured.lock().expect("captured poisoned");
    if captured.len() >= MAX_CAPTURED_REQUESTS {
        let remove = captured.len() - MAX_CAPTURED_REQUESTS + 1;
        captured.drain(0..remove);
    }
    captured.push(request);
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn reason_phrase(status: u16) -> &'static str {
    reqwest::StatusCode::from_u16(status)
        .ok()
        .and_then(|status| status.canonical_reason())
        .unwrap_or("Unknown")
}

/// Apply match-and-replace rules to path, headers and body.
fn apply_rules(
    mut method: String,
    mut url: String,
    mut headers: Vec<(String, String)>,
    mut body: Vec<u8>,
    rules: &[MatchReplaceRule],
) -> (String, String, Vec<(String, String)>, Vec<u8>) {
    for rule in rules {
        if rule.find.is_empty() {
            continue;
        }
        url = url.replace(&rule.find, &rule.replace);
        body = replace_bytes_limited(body, rule.find.as_bytes(), rule.replace.as_bytes());
        for (name, value) in &mut headers {
            *value = value.replace(&rule.find, &rule.replace);
            *name = name.replace(&rule.find, &rule.replace);
        }
        method = method.replace(&rule.find, &rule.replace);
    }
    (method, url, headers, body)
}

/// Forward a parsed request through the HTTP client; returns response parts.
async fn execute_request(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("CyberDeck-Workbench/0.1")
        .build()
        .expect("http client");
    let Ok(method_req) = reqwest::Method::from_bytes(method.as_bytes()) else {
        return (400, vec![], b"bad method".to_vec());
    };
    let mut request = client.request(method_req, url);
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("content-length")
            || is_hop_header(name)
        {
            continue;
        }
        request = request.header(name, value);
    }
    if !body.is_empty() {
        request = request.body(body.to_vec());
    }
    let Ok(resp) = request.send().await else {
        return (502, vec![], b"CyberDeck: upstream request failed".to_vec());
    };
    let status = resp.status().as_u16();
    let resp_headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("<binary>").to_string()))
        .collect();
    let mut response = resp;
    let mut bytes = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if bytes.len().saturating_add(chunk.len()) > MAX_PROXY_BODY {
                    return (
                        502,
                        vec![],
                        b"CyberDeck: upstream response exceeds proxy body limit".to_vec(),
                    );
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => {
                return (
                    502,
                    vec![],
                    b"CyberDeck: upstream body read failed".to_vec(),
                )
            }
        }
    }
    (status, resp_headers, bytes)
}

#[tauri::command]
pub async fn proxy_stop(ctx: State<'_, WebCtx>) -> Result<ProxyStatusWire, String> {
    ctx.shared.running.store(false, Ordering::Relaxed);
    ctx.proxy_running.store(false, Ordering::Relaxed);
    ctx.shared.pending.lock().expect("pending poisoned").clear();
    if let Some(handle) = ctx
        .proxy_handle
        .lock()
        .expect("proxy handle poisoned")
        .take()
    {
        handle.abort();
    }
    Ok(proxy_status_inner(&ctx))
}

fn proxy_status_inner(ctx: &WebCtx) -> ProxyStatusWire {
    ProxyStatusWire {
        running: ctx.shared.running.load(Ordering::Relaxed),
        port: ctx.shared.port.load(Ordering::Relaxed),
        captured: ctx.shared.captured.lock().expect("captured poisoned").len(),
    }
}

#[tauri::command]
pub fn proxy_status(ctx: State<'_, WebCtx>) -> ProxyStatusWire {
    proxy_status_inner(&ctx)
}

#[tauri::command]
pub fn proxy_history(ctx: State<'_, WebCtx>) -> Vec<CapturedRequest> {
    ctx.shared
        .captured
        .lock()
        .expect("captured poisoned")
        .clone()
}

/// Toggle request interception. When on, requests are held in the pending
/// queue until forwarded or dropped; the browser waits for the decision.
#[tauri::command]
pub fn proxy_intercept(on: bool, ctx: State<'_, WebCtx>) -> bool {
    ctx.shared.intercept.store(on, Ordering::Relaxed);
    on
}

#[derive(Debug, Serialize)]
pub struct PendingWire {
    pub id: u64,
    pub method: String,
    pub url: String,
    pub host: String,
    pub path: String,
    pub body_preview: String,
}

#[tauri::command]
pub fn proxy_pending(ctx: State<'_, WebCtx>) -> Vec<PendingWire> {
    ctx.shared
        .pending
        .lock()
        .expect("pending poisoned")
        .values()
        .map(|p| PendingWire {
            id: p.info.id,
            method: p.method.clone(),
            url: p.url.clone(),
            host: p.info.host.clone(),
            path: p.info.path.clone(),
            body_preview: p.body.chars().take(200).collect(),
        })
        .collect()
}

/// Forward a held request: applies match-and-replace, executes, writes the
/// real response back to the waiting browser, and records it in history.
#[tauri::command]
pub async fn proxy_forward(id: u64, ctx: State<'_, WebCtx>) -> Result<u16, String> {
    let pending = ctx
        .shared
        .pending
        .lock()
        .expect("pending poisoned")
        .remove(&id);
    let Some(pending) = pending else {
        return Err("request no longer pending (browser timeout)".to_string());
    };
    let rules = ctx.shared.rules.lock().expect("rules poisoned").clone();
    let (method, url, headers, body) = apply_rules(
        pending.method,
        pending.url,
        pending.headers,
        pending.body,
        &rules,
    );
    let mut stream = pending.stream;
    use tokio::io::AsyncWriteExt;
    let (status, resp_headers, resp_body) = execute_request(&method, &url, &headers, &body).await;
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\n",
        reason = reason_phrase(status)
    );
    for (name, value) in &resp_headers {
        if name.eq_ignore_ascii_case("content-length") || is_hop_header(name) {
            continue;
        }
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str(&format!(
        "content-length: {}\r\nconnection: close\r\n\r\n",
        resp_body.len()
    ));
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.write_all(&resp_body).await;
    push_capture(
        &ctx.shared,
        CapturedRequest {
            id,
            method,
            host: pending.info.host,
            path: pending.info.path,
            status,
            size: resp_body.len(),
            at_ms: now_ms(),
        },
    );
    Ok(status)
}

/// Drop a held request; the browser receives a 502.
#[tauri::command]
pub async fn proxy_drop(id: u64, ctx: State<'_, WebCtx>) -> Result<(), String> {
    let pending = ctx
        .shared
        .pending
        .lock()
        .expect("pending poisoned")
        .remove(&id);
    if let Some(mut pending) = pending {
        use tokio::io::AsyncWriteExt;
        let _ = pending
            .stream
            .write_all(b"HTTP/1.1 502 CyberDeck: request dropped by interceptor\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
            .await;
    }
    Ok(())
}

/// Replace the match-and-replace rule list.
#[tauri::command]
pub fn proxy_set_rules(rules: Vec<MatchReplaceRule>, ctx: State<'_, WebCtx>) -> usize {
    *ctx.shared.rules.lock().expect("rules poisoned") = rules;
    ctx.shared.rules.lock().expect("rules poisoned").len()
}

/// Export the CA certificate PEM for browser trust-store installation.
#[tauri::command]
pub async fn proxy_ca_pem(app: tauri::AppHandle, ctx: State<'_, WebCtx>) -> Result<String, String> {
    if let Some(ca) = ctx.ca.lock().expect("ca poisoned").as_ref() {
        return Ok(ca.cert_pem.clone());
    }
    let ca_dir = crate::storage_paths::data_dir(&app)?;
    let ca = crate::webtls::init_ca(&ca_dir)?;
    *ctx.ca.lock().expect("ca poisoned") = Some(Arc::clone(&ca));
    Ok(ca.cert_pem.clone())
}

#[derive(Debug, Serialize)]
pub struct WsConnectionWire {
    pub host: String,
    pub bytes_client_to_server: u64,
    pub bytes_server_to_client: u64,
    pub at_ms: u64,
}

#[tauri::command]
pub fn ws_list(ctx: State<'_, WebCtx>) -> Vec<WsConnectionWire> {
    ctx.shared
        .ws
        .lock()
        .expect("ws poisoned")
        .iter()
        .map(|w| WsConnectionWire {
            host: w.host.clone(),
            bytes_client_to_server: w.bytes_client_to_server,
            bytes_server_to_client: w.bytes_server_to_client,
            at_ms: w.at_ms,
        })
        .collect()
}

// --- external engine slots (GPLv2, user-approved) ------------------------------

#[derive(Debug, Serialize)]
pub struct WebEngineStatus {
    pub id: String,
    pub label: String,
    pub license: String,
    pub available: bool,
    pub version: String,
}

#[tauri::command]
pub async fn web_engines_detect() -> Vec<WebEngineStatus> {
    let mut out = Vec::new();
    for (id, label, license, version_args) in [
        ("nikto", "Nikto", "GPL-2.0-only", vec!["-Version"]),
        ("sqlmap", "sqlmap", "GPL-2.0-only", vec!["--version"]),
        ("xsstrike", "XSStrike", "GPL-3.0-only", vec!["--help"]),
    ] {
        let available = which_exists(id);
        let mut version = String::new();
        if available {
            let output = tokio::process::Command::new(id)
                .args(&version_args)
                .output()
                .await;
            if let Ok(out) = output {
                version = String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .find(|l| !l.trim().is_empty())
                    .unwrap_or("")
                    .chars()
                    .take(60)
                    .collect();
            }
        }
        out.push(WebEngineStatus {
            id: id.to_string(),
            label: label.to_string(),
            license: license.to_string(),
            available,
            version,
        });
    }
    out
}

#[derive(Debug, Serialize)]
pub struct EngineScanResult {
    pub tool: String,
    pub raw: String,
    pub duration_ms: u64,
}

/// Run an approved external web engine against the target when it is on PATH.
#[tauri::command]
pub async fn engine_scan(
    tool: String,
    target: String,
    authorized: bool,
) -> Result<EngineScanResult, String> {
    require_authorization(authorized)?;
    let target = target.trim().to_string();
    if !target.starts_with("http") {
        return Err("target must start with http:// or https://".to_string());
    }
    let mut command = tokio::process::Command::new(&tool);
    match tool.as_str() {
        "nikto" => {
            command.args(["-h", &target, "-Format", "txt"]);
        }
        "sqlmap" => {
            command.args(["-u", &target, "--batch", "--forms"]);
        }
        "xsstrike" => {
            command.args(["-u", &target, "--crawl"]);
        }
        other => return Err(format!("unknown engine: {other}")),
    }
    let started = Instant::now();
    let output = command.output().await.map_err(|e| {
        format!("{tool} is not available on PATH ({e}); bundled sidecars arrive with the installer")
    })?;
    let mut raw = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    raw.truncate(20_000);
    Ok(EngineScanResult {
        tool,
        raw,
        duration_ms: started.elapsed().as_millis() as u64,
    })
}
