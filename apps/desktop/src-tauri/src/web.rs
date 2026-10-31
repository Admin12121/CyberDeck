//! Web studio backend (§5.2): HTTP sender, native review scanner, spider,
//! HTTP-only proxy, and sidecar slots for nikto/sqlmap/XSStrike.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

use serde::Serialize;
use tauri::{Manager, State};

use crate::engines::which_exists;

const MAX_BODY_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MatchReplaceRule {
    pub find: String,
    pub replace: String,
}

/// A request held by the interceptor until forwarded or dropped.
pub struct PendingRequest {
    pub stream: TcpStream,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub info: CapturedRequest,
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
        .user_agent("HackTool-Workbench/0.1")
        .build()
        .expect("http client")
}

/// Parse a raw HTTP request into (method, url, headers, body). The Host or
/// absolute-URI supplies the target; scheme defaults to http.
pub fn parse_raw_request(raw: &str, scheme: &str) -> Result<(String, String, Vec<(String, String)>, String), String> {
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
    let method_req = reqwest::Method::from_bytes(method.as_bytes()).map_err(|e| format!("bad method: {e}"))?;
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
    let response = request.send().await.map_err(|e| format!("request failed: {e}"))?;
    let status = response.status().as_u16();
    let resp_headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("<binary>").to_string()))
        .collect();
    let bytes = response.bytes().await.map_err(|e| format!("body read failed: {e}"))?;
    let size = bytes.len();
    let truncated = size > MAX_BODY_BYTES;
    let body_text = String::from_utf8_lossy(&bytes[..size.min(MAX_BODY_BYTES)]).to_string();
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
    ("/robots.txt", "robots.txt present; review disallowed entries for hidden paths"),
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
pub async fn web_scan(target_url: String) -> Result<Vec<Finding>, String> {
    let base = target_url.trim().trim_end_matches('/').to_string();
    if !base.starts_with("http://") && !base.starts_with("https://") {
        return Err("target must start with http:// or https://".to_string());
    }
    let client = http_client();
    let mut findings: Vec<Finding> = Vec::new();

    let root = client.get(&base).send().await;
    let root_headers = if let Ok(resp) = &root {
        let mut map = Vec::new();
        for (k, v) in resp.headers() {
            map.push((k.to_string().to_lowercase(), v.to_str().unwrap_or("").to_string()));
        }
        Some(map)
    } else {
        None
    };

    if let Some(headers) = &root_headers {
        for (header, title) in SECURITY_HEADERS {
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
                let severity = if path.contains(".env") || path.contains(".git") || path.contains("backup") { "high" } else { "info" };
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

/// Depth-limited same-host spider (GET only). Returns discovered URLs.
#[tauri::command]
pub async fn spider_scan(target_url: String, max_depth: u8) -> Result<Vec<String>, String> {
    let base = target_url.trim().trim_end_matches('/').to_string();
    if !base.starts_with("http://") && !base.starts_with("https://") {
        return Err("target must start with http:// or https://".to_string());
    }
    let host = base
        .split('/')
        .nth(2)
        .ok_or("cannot parse host")?
        .to_string();
    let client = http_client();
    let mut seen = vec![base.clone()];
    let mut queue: VecDeque<(String, u8)> = VecDeque::new();
    queue.push_back((base.clone(), 0));
    let mut links: Vec<String> = vec![base.clone()];
    while let Some((url, depth)) = queue.pop_front() {
        if depth >= max_depth || links.len() >= 60 {
            break;
        }
        let Ok(resp) = client.get(&url).send().await else { continue };
        let Ok(text) = resp.text().await else { continue };
        for chunk in text.split("href=\"").skip(1) {
            let Some(end) = chunk.find('"') else { continue };
            let href = &chunk[..end];
            let absolute = if href.starts_with("http://") || href.starts_with("https://") {
                href.to_string()
            } else if href.starts_with('/') {
                let origin = url.split('/').take(3).collect::<Vec<_>>().join("/");
                format!("{origin}{href}")
            } else {
                continue;
            };
            if !absolute.contains(&host) || seen.contains(&absolute) || absolute.contains('?') {
                continue;
            }
            seen.push(absolute.clone());
            links.push(absolute.clone());
            queue.push_back((absolute, depth + 1));
        }
    }
    links.sort();
    Ok(links)
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
    let ca_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("cannot resolve app data dir: {e}"))?
        .join("hacktool");
    let ca = crate::webtls::init_ca(&ca_dir)?;
    *ctx.ca.lock().expect("ca poisoned") = Some(ca);
    if ctx.shared.running.load(Ordering::Relaxed) {
        return Err("proxy already running; stop it first".to_string());
    }
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().map_err(|e| format!("bad port: {e}"))?;
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
            let Ok((stream, _)) = listener.accept().await else { continue };
            let shared = Arc::clone(&shared);
            tokio::spawn(async move {
                let _ = handle_conn(stream, shared).await;
            });
        }
    });
    *ctx.proxy_handle.lock().expect("proxy handle poisoned") = Some(handle);
    Ok(ProxyStatusWire { running: true, port, captured: ctx.shared.captured.lock().expect("captured poisoned").len() })
}

async fn handle_conn(mut stream: TcpStream, shared: Arc<ProxyShared>) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 65536];
    let read = stream.read(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf[..read]).to_string();
    if text.starts_with("CONNECT") {
        return connect_tunnel(stream, shared, &text).await;
    }
    let Ok((method, url, headers, body)) = parse_raw_request(&text, "http") else { return Ok(()) };
    let host = url.split('/').nth(2).unwrap_or_default().to_string();
    let path = format!("/{}", url.splitn(4, '/').nth(3).unwrap_or(""));

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
        shared
            .pending
            .lock()
            .expect("pending poisoned")
            .insert(id, PendingRequest { stream, method, url, headers, body, info });
        return Ok(());
    }

    let rules = shared.rules.lock().expect("rules poisoned").clone();
    let (method, url, headers, body) = apply_rules(method, url, headers, body, &rules);
    let (status, resp_headers, resp_body) = execute_request(&method, &url, &headers, &body).await;
    let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
    shared.captured.lock().expect("captured poisoned").push(CapturedRequest {
        id,
        method,
        host,
        path,
        status,
        size: resp_body.len(),
        at_ms: now_ms(),
    });

    let mut response = format!("HTTP/1.1 {status} {reason}\r\n", reason = reason_phrase(status));
    for (name, value) in &resp_headers {
        if name.eq_ignore_ascii_case("transfer-encoding") || name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str(&format!("content-length: {}\r\nconnection: close\r\n\r\n", resp_body.len()));
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
    let target = head_text
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_string();
    let intercepting = shared.intercept.load(Ordering::Relaxed);
    let ca = shared.ca.lock().expect("ca poisoned").clone();

    if !intercepting || ca.is_none() {
        // honest passthrough: relay raw bytes to the upstream host
        let _ = stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await;
        let upstream = TcpStream::connect(&target).await?;
        let (mut s_read, mut s_write) = tokio::io::split(stream);
        let (mut u_read, mut u_write) = tokio::io::split(upstream);
        tokio::select! {
            _ = tokio::io::copy(&mut s_read, &mut u_write) => {},
            _ = tokio::io::copy(&mut u_read, &mut s_write) => {},
        }
        return Ok(());
    }

    let host = target.split(':').next().unwrap_or_default().to_string();
    let _ = stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await;
    let ca = ca.expect("ca checked");
    let acceptor = crate::webtls::tls_acceptor(&ca, &host).map_err(|e| std::io::Error::other(e))?;
    let mut tls_stream = acceptor.accept(stream).await.map_err(|e| {
        std::io::Error::other(format!("tls handshake with client failed: {e}"))
    })?;
    let (head_text, body_bytes) = crate::webtls::read_http_message(&mut tls_stream).await?;
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
    let body = String::from_utf8_lossy(&body_bytes).to_string();

    // WebSocket upgrade: relay frames both ways and list the connection
    if head_text.to_lowercase().contains("upgrade: websocket") {
        let tcp = TcpStream::connect((host.as_str(), 443))
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
        upstream.write_all(body.as_bytes()).await?;
        let (mut c_read, mut c_write) = tokio::io::split(tls_stream);
        let (mut u_read, mut u_write) = tokio::io::split(upstream);
        let c2u = tokio::io::copy(&mut c_read, &mut u_write);
        let u2c = tokio::io::copy(&mut u_read, &mut c_write);
        let (a, b) = tokio::join!(c2u, u2c);
        shared.ws.lock().expect("ws poisoned").push(crate::webtls::WsConnection {
            host: host.clone(),
            at_ms: now_ms(),
        });
        let _ = (a, b);
        return Ok(());
    }

    // plain HTTP inside TLS: same rules + capture path as plain proxying
    let rules = shared.rules.lock().expect("rules poisoned").clone();
    let (r_method, r_url, r_headers, r_body) =
        apply_rules(method.clone(), format!("https://{host}{path}"), headers, body, &rules);
    let (status, resp_headers, resp_body) =
        execute_request(&r_method, &r_url, &r_headers, &r_body).await;
    let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
    shared.captured.lock().expect("captured poisoned").push(CapturedRequest {
        id,
        method: r_method,
        host: host.clone(),
        path: path.clone(),
        status,
        size: resp_body.len(),
        at_ms: now_ms(),
    });
    let mut response = format!("HTTP/1.1 {status} {reason}\r\n", reason = reason_phrase(status));
    for (name, value) in &resp_headers {
        if name.eq_ignore_ascii_case("transfer-encoding") || name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str(&format!("content-length: {}\r\nconnection: close\r\n\r\n", resp_body.len()));
    tls_stream.write_all(response.as_bytes()).await?;
    tls_stream.write_all(&resp_body).await?;
    Ok(())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        301 | 308 => "Moved Permanently",
        302 | 307 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "OK",
    }
}

/// Apply match-and-replace rules to path, headers and body.
fn apply_rules(
    mut method: String,
    mut url: String,
    mut headers: Vec<(String, String)>,
    mut body: String,
    rules: &[MatchReplaceRule],
) -> (String, String, Vec<(String, String)>, String) {
    for rule in rules {
        if rule.find.is_empty() {
            continue;
        }
        url = url.replace(&rule.find, &rule.replace);
        body = body.replace(&rule.find, &rule.replace);
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
    body: &str,
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent("HackTool-Workbench/0.1")
        .build()
        .expect("http client");
    let Ok(method_req) = reqwest::Method::from_bytes(method.as_bytes()) else {
        return (400, vec![], b"bad method".to_vec());
    };
    let mut request = client.request(method_req, url);
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("connection")
        {
            continue;
        }
        request = request.header(name, value);
    }
    if !body.is_empty() && !matches!(method, "GET" | "HEAD") {
        request = request.body(body.to_string());
    }
    let Ok(resp) = request.send().await else {
        return (502, vec![], b"HackTool: upstream request failed".to_vec());
    };
    let status = resp.status().as_u16();
    let resp_headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("<binary>").to_string()))
        .collect();
    let Ok(bytes) = resp.bytes().await else {
        return (status, resp_headers, Vec::new());
    };
    (status, resp_headers, bytes.to_vec())
}

#[tauri::command]
pub async fn proxy_stop(ctx: State<'_, WebCtx>) -> Result<ProxyStatusWire, String> {
    ctx.shared.running.store(false, Ordering::Relaxed);
    ctx.proxy_running.store(false, Ordering::Relaxed);
    if let Some(handle) = ctx.proxy_handle.lock().expect("proxy handle poisoned").take() {
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
    ctx.shared.captured.lock().expect("captured poisoned").clone()
}

/// Toggle request interception. When on, requests are held in the pending
/// queue until forwarded or dropped; the browser waits for the decision.
#[derive(Debug, Serialize)]
pub struct StreamChunkWire {
    pub dir: String,
    pub text: String,
}

/// Reassemble one TCP/UDP stream into a printable transcript (A|B sides).
#[tauri::command]
pub fn pcap_follow_stream(
    pcap: State<'_, crate::pcap::PcapCtx>,
    stream_id: String,
) -> Result<Vec<StreamChunkWire>, String> {
    let guard = pcap.current.lock().expect("pcap cache poisoned");
    let capture = guard.as_ref().ok_or("no capture is open")?;
    let mut chunks: Vec<StreamChunkWire> = Vec::new();
    for meta in &capture.packets {
        if meta.dissected.stream_id.as_deref() != Some(stream_id.as_str()) || meta.dissected.payload.is_empty() {
            continue;
        }
        let frame = capture
            .bytes
            .get(meta.offset..meta.offset + meta.incl_len)
            .ok_or("capture bytes truncated")?;
        let end = frame.len();
        let start = end - meta.dissected.payload.len();
        let text: String = frame[start..end]
            .iter()
            .map(|&b| if (0x20..=0x7e).contains(&b) { b as char } else { '.' })
            .collect();
        chunks.push(StreamChunkWire {
            dir: if meta.dissected.source <= meta.dissected.destination { "A".to_string() } else { "B".to_string() },
            text,
        });
    }
    Ok(chunks)
}

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
    let pending = ctx.shared.pending.lock().expect("pending poisoned").remove(&id);
    let Some(pending) = pending else {
        return Err("request no longer pending (browser timeout)".to_string());
    };
    let rules = ctx.shared.rules.lock().expect("rules poisoned").clone();
    let (method, url, headers, body) = apply_rules(pending.method, pending.url, pending.headers, pending.body, &rules);
    let mut stream = pending.stream;
    use tokio::io::AsyncWriteExt;
    let (status, resp_headers, resp_body) = execute_request(&method, &url, &headers, &body).await;
    let mut response = format!("HTTP/1.1 {status} {reason}\r\n", reason = reason_phrase(status));
    for (name, value) in &resp_headers {
        if name.eq_ignore_ascii_case("transfer-encoding") || name.eq_ignore_ascii_case("content-length") {
            continue;
        }
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str(&format!("content-length: {}\r\nconnection: close\r\n\r\n", resp_body.len()));
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.write_all(&resp_body).await;
    ctx.shared.captured.lock().expect("captured poisoned").push(CapturedRequest {
        id,
        method,
        host: pending.info.host,
        path: pending.info.path,
        status,
        size: resp_body.len(),
        at_ms: now_ms(),
    });
    Ok(status)
}

/// Drop a held request; the browser receives a 502.
#[tauri::command]
pub async fn proxy_drop(id: u64, ctx: State<'_, WebCtx>) -> Result<(), String> {
    let pending = ctx.shared.pending.lock().expect("pending poisoned").remove(&id);
    if let Some(mut pending) = pending {
        use tokio::io::AsyncWriteExt;
        let _ = pending
            .stream
            .write_all(b"HTTP/1.1 502 HackTool: request dropped by interceptor\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
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
    let ca_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("cannot resolve app data dir: {e}"))?
        .join("hacktool");
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
            bytes_client_to_server: 0,
            bytes_server_to_client: 0,
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
        out.push(WebEngineStatus { id: id.to_string(), label: label.to_string(), license: license.to_string(), available, version });
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
pub async fn engine_scan(tool: String, target: String) -> Result<EngineScanResult, String> {
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
    let output = command
        .output()
        .await
        .map_err(|e| format!("{tool} is not available on PATH ({e}); bundled sidecars arrive with the installer"))?;
    let mut raw = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    raw.truncate(20_000);
    Ok(EngineScanResult { tool, raw, duration_ms: started.elapsed().as_millis() as u64 })
}
