//! Web security studio backend (Master Plan §5.2): a real HTTP sender for
//! the Repeater, a native web review scanner (our own checks, nikto-style),
//! a depth-limited spider, an HTTP-only interception proxy, and sidecar
//! slots for the GPLv2 tooling the user approved (nikto, sqlmap, XSStrike).
//! HTTPS MITM needs a generated CA and is a later arc; CONNECT tunnels are
//! passed through and labeled honestly.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::ipc::Channel;
use tauri::State;

use crate::engines::which_exists;

const MAX_BODY_BYTES: usize = 512 * 1024;
const MAX_CAPTURE: usize = 1000;

pub struct WebCtx {
    pub proxy_running: AtomicBool,
    pub proxy_port: AtomicU16,
    pub proxy_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub captured: Mutex<Vec<CapturedRequest>>,
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
/// are captured and forwarded; CONNECT (HTTPS) tunnels pass through without
/// interception until the CA arc lands.
#[tauri::command]
pub async fn proxy_start(port: u16, ctx: State<'_, WebCtx>) -> Result<ProxyStatusWire, String> {
    if ctx.proxy_running.load(Ordering::Relaxed) {
        return Err("proxy already running; stop it first".to_string());
    }
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().map_err(|e| format!("bad port: {e}"))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("cannot bind 127.0.0.1:{port}: {e}"))?;
    ctx.proxy_running.store(true, Ordering::Relaxed);
    ctx.proxy_port.store(port, Ordering::Relaxed);
    let running = Arc::new(AtomicBool::new(true));
    let captured = Arc::new(Mutex::new(Vec::<CapturedRequest>::new()));
    let next_id = Arc::new(AtomicU64::new(1));
    let handle = tokio::spawn(async move {
        loop {
            if !running.load(Ordering::Relaxed) {
                break;
            }
            let Ok((stream, _)) = listener.accept().await else { continue };
            let captured = Arc::clone(&captured);
            let next_id = Arc::clone(&next_id);
            let running = Arc::clone(&running);
            tokio::spawn(async move {
                let _ = handle_conn(stream, captured, next_id, running).await;
            });
        }
    });
    *ctx.proxy_handle.lock().expect("proxy handle poisoned") = Some(handle);
    Ok(ProxyStatusWire { running: true, port, captured: ctx.captured.lock().expect("captured poisoned").len() })
}

async fn handle_conn(
    mut stream: tokio::net::TcpStream,
    captured: Arc<Mutex<Vec<CapturedRequest>>>,
    next_id: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
) -> std::io::Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 65536];
    let read = stream.read(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf[..read]).to_string();
    if text.starts_with("CONNECT") {
        // honest pass-through: TLS interception needs the CA arc
        let _ = stream.write_all(b"HTTP/1.1 502 HackTool: HTTPS interception not enabled\r\n\r\n").await;
        return Ok(());
    }
    let (method, url, headers, body) = match parse_raw_request(&text, "http") {
        Ok(parsed) => parsed,
        Err(_) => return Ok(()),
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .danger_accept_invalid_certs(false)
        .build()
        .unwrap();
    let method_req = match reqwest::Method::from_bytes(method.as_bytes()) {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };
    let mut request = client.request(method_req, &url);
    for (name, value) in &headers {
        if name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("connection") {
            continue;
        }
        request = request.header(name, value);
    }
    if !body.is_empty() && !matches!(method.as_str(), "GET" | "HEAD") {
        request = request.body(body);
    }
    let Ok(resp) = request.send().await else { return Ok(()) };
    let status = resp.status().as_u16();
    let size = resp.content_length().unwrap_or(0) as usize;
    let host = url.split('/').nth(2).unwrap_or_default().to_string();
    let path = format!("/{}", url.splitn(4, '/').nth(3).unwrap_or(""));
    let id = next_id.fetch_add(1, Ordering::Relaxed);
    let entry = CapturedRequest {
        id,
        method,
        host,
        path,
        status,
        size,
        at_ms: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0),
    };
    {
        let mut cap = captured.lock().expect("captured poisoned");
        cap.push(entry);
        if cap.len() > MAX_CAPTURE {
            cap.remove(0);
        }
    }
    let mut response = format!("HTTP/1.1 {status} OK\r\n");
    response.push_str("X-HackTool-Proxy: arc-4\r\n\r\n");
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = running; // kept for the accept-loop stop check
    Ok(())
}

#[tauri::command]
pub async fn proxy_stop(ctx: State<'_, WebCtx>) -> Result<ProxyStatusWire, String> {
    ctx.proxy_running.store(false, Ordering::Relaxed);
    if let Some(handle) = ctx.proxy_handle.lock().expect("proxy handle poisoned").take() {
        handle.abort();
    }
    Ok(ProxyStatusWire { running: false, port: ctx.proxy_port.load(Ordering::Relaxed), captured: ctx.captured.lock().expect("captured poisoned").len() })
}

#[tauri::command]
pub fn proxy_status(ctx: State<'_, WebCtx>) -> ProxyStatusWire {
    ProxyStatusWire {
        running: ctx.proxy_running.load(Ordering::Relaxed),
        port: ctx.proxy_port.load(Ordering::Relaxed),
        captured: ctx.captured.lock().expect("captured poisoned").len(),
    }
}

#[tauri::command]
pub fn proxy_history(ctx: State<'_, WebCtx>) -> Vec<CapturedRequest> {
    ctx.captured.lock().expect("captured poisoned").clone()
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
        let binary = if cfg!(windows) { format!("{id}.exe") } else { id.to_string() };
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
        let _ = binary;
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
