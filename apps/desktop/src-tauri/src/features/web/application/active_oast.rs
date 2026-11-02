//! SPDX-License-Identifier: MIT
//! Self-hosted out-of-band (OAST) confirmation for blind SSRF.
//!
//! The collector is a bounded loopback/private HTTP listener. The operator
//! supplies the base URL the *target* can reach; each probe carries a unique
//! single-use token in its path. A finding is emitted only when the target
//! actually contacts the collector with that token, so no blind claim is made.
//!
//! Safety contract:
//! - The collector binds only to an explicit loopback or private address.
//! - Requests are capped at 8 KiB, read within 3 seconds, and concurrency is
//!   limited; unrelated traffic is read, answered and discarded.
//! - Only the path token is retained, never source addresses, headers or
//!   paths. Tokens are correlation values, not secrets.
//! - Probes are read-only GET requests against URL-like parameters only.
use super::active_query_application::{sensitive_name, single_mutation};
use super::scan_domain::Finding;
use reqwest::{Client, Url};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const MAX_REQUEST_BYTES: usize = 8 * 1024;
const MAX_CONCURRENT: usize = 32;
const MAX_TRACKED_TOKENS: usize = 256;
const READ_TIMEOUT: Duration = Duration::from_secs(3);
const TOKEN_HEX: usize = 16;
const MAX_PARAMS: usize = 8;
const MAX_URL_BYTES: usize = 4096;
const MAX_QUERY_BYTES: usize = 2048;

/// Operator configuration. `bind` is where the collector listens; `base` is
/// the address the target must be able to reach and is never reported.
#[derive(Clone)]
pub(super) struct OastConfig {
    pub bind: SocketAddr,
    pub base: Url,
}

impl OastConfig {
    pub(super) fn new(bind: &str, base_url: &str) -> Result<Self, String> {
        let bind: SocketAddr = bind
            .trim()
            .parse()
            .map_err(|_| "callback bind must be an IP:port".to_string())?;
        if bind.port() == 0 {
            return Err("callback bind port must be between 1 and 65535".into());
        }
        if !super::target_scope::private_address(bind.ip()) {
            return Err("callback collector must bind to a loopback or private address".into());
        }
        let base = Url::parse(base_url.trim()).map_err(|_| "callback base URL is invalid")?;
        if !matches!(base.scheme(), "http" | "https")
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
        {
            return Err("callback base must be an HTTP(S) URL without credentials".into());
        }
        Ok(Self { bind, base })
    }
}

/// Unpredictable enough for correlation; never treated as a credential.
pub(super) fn fresh_token(job_id: u64, index: usize) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    job_id.hash(&mut hasher);
    index.hash(&mut hasher);
    std::process::id().hash(&mut hasher);
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

fn extract_token(request: &[u8]) -> Option<String> {
    let line = std::str::from_utf8(request).ok()?.lines().next()?;
    let target = line.split_whitespace().nth(1)?;
    let path = target.split(['?', '#']).next()?;
    path.rsplit('/')
        .find(|segment| {
            segment.len() == TOKEN_HEX && segment.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
        .map(|segment| segment.to_ascii_lowercase())
}

pub(super) struct OastCollector {
    seen: Arc<Mutex<HashSet<String>>>,
    task: JoinHandle<()>,
    address: SocketAddr,
}

impl OastCollector {
    /// Port 0 is allowed here for tests and for callers that read the actual
    /// bound address; operator configuration rejects it.
    pub(super) async fn bind(bind: SocketAddr) -> Result<Self, String> {
        if !super::target_scope::private_address(bind.ip()) {
            return Err("callback collector must bind to a loopback or private address".into());
        }
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|_| "callback collector could not bind".to_string())?;
        let address = listener
            .local_addr()
            .map_err(|_| "callback collector address unavailable".to_string())?;
        let seen = Arc::new(Mutex::new(HashSet::new()));
        let task = tokio::spawn(serve(listener, Arc::clone(&seen)));
        Ok(Self {
            seen,
            task,
            address,
        })
    }

    pub(super) fn address(&self) -> SocketAddr {
        self.address
    }

    /// Polls until the token arrives or the bounded wait expires.
    pub(super) async fn wait(&self, token: &str, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self
                .seen
                .lock()
                .is_ok_and(|seen| seen.contains(token))
            {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

impl Drop for OastCollector {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(listener: TcpListener, seen: Arc<Mutex<HashSet<String>>>) {
    let permits = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT));
    loop {
        let Ok((mut stream, _peer)) = listener.accept().await else {
            return;
        };
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            continue;
        };
        let seen = Arc::clone(&seen);
        tokio::spawn(async move {
            let _permit = permit;
            let mut buffer = Vec::new();
            let mut chunk = [0u8; 512];
            let deadline = tokio::time::Instant::now() + READ_TIMEOUT;
            loop {
                match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                    Ok(Ok(read)) => {
                        buffer.extend_from_slice(&chunk[..read]);
                        if buffer.len() > MAX_REQUEST_BYTES
                            || buffer.windows(4).any(|window| window == b"\r\n\r\n")
                        {
                            break;
                        }
                    }
                }
            }
            if let Some(token) = extract_token(&buffer) {
                if let Ok(mut seen) = seen.lock() {
                    if seen.len() < MAX_TRACKED_TOKENS {
                        seen.insert(token);
                    }
                }
            }
            let _ = stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
        });
    }
}

fn callback_like_name(name: &str) -> bool {
    const PARTS: &[&str] = &[
        "url",
        "uri",
        "link",
        "redirect",
        "next",
        "callback",
        "webhook",
        "image",
        "img",
        "src",
        "dest",
        "destination",
        "target",
        "host",
        "domain",
        "feed",
        "fetch",
        "proxy",
        "return",
        "continue",
        "site",
    ];
    let lower = name.to_ascii_lowercase();
    PARTS.iter().any(|part| lower.contains(part))
}

fn vectors(url: &Url, max_mutations: usize) -> Result<Vec<usize>, String> {
    if max_mutations == 0 || max_mutations > MAX_PARAMS {
        return Err("out-of-band budget must be 1-8 parameters".into());
    }
    let query = url
        .query()
        .ok_or("out-of-band checks require URL parameters")?;
    if query.len() > MAX_QUERY_BYTES {
        return Err("out-of-band query exceeds the 2048-byte bound".into());
    }
    let mut out = Vec::new();
    let mut seen = 0usize;
    for (index, (name, value)) in url.query_pairs().enumerate() {
        seen += 1;
        if seen > MAX_PARAMS {
            return Err("out-of-band checks support one to eight query parameters".into());
        }
        if name.is_empty()
            || sensitive_name(&name)
            || name.len() > 128
            || value.len() > 1024
            || !callback_like_name(&name)
        {
            continue;
        }
        out.push(index);
    }
    if seen == 0 {
        return Err("out-of-band checks require URL parameters".into());
    }
    if out.is_empty() {
        return Err("no URL-like query parameter is eligible for out-of-band checks".into());
    }
    out.truncate(max_mutations);
    Ok(out)
}

fn callback_probe(base: &Url, token: &str) -> Result<Url, String> {
    let mut probe = base.clone();
    probe.set_path(&format!("{}/{}", base.path().trim_end_matches('/'), token));
    probe.set_query(None);
    probe.set_fragment(None);
    if probe.origin() != base.origin() {
        return Err("callback base attempted to change origin".into());
    }
    Ok(probe)
}

fn finding(url: &Url, index: usize) -> Finding {
    Finding {
        severity: "high".into(),
        title: "confirmed out-of-band callback (SSRF)".into(),
        detail: "A URL-like GET parameter accepted an operator-controlled callback address and the target contacted the local collector with the single-use token. This confirms server-side request forgery; review which destinations the parameter can reach before treating the impact as limited.".into(),
        evidence: format!(
            "Rule cd.ascan.oast-ssrf.v1; approved origin {}; GET parameter position {}; callback observed at the operator collector. Callback address and token withheld.",
            url.origin().ascii_serialization(),
            index + 1,
        ),
    }
}

/// Sends one bounded GET per eligible parameter and waits for the callback.
/// Values are never reported; only a confirmed interaction becomes a finding.
pub(super) async fn run_oast_with_budget(
    client: &Client,
    url: Url,
    callback_base: &Url,
    collector: &OastCollector,
    job_id: u64,
    max_mutations: usize,
    wait: Duration,
    on_progress: &impl Fn(usize, usize),
) -> Result<Vec<Finding>, String> {
    if url.as_str().len() > MAX_URL_BYTES
        || !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("invalid out-of-band target".into());
    }
    let vectors = vectors(&url, max_mutations)?;
    on_progress(0, 0);
    let mut found = Vec::new();
    for (position, index) in vectors.iter().copied().enumerate() {
        let token = fresh_token(job_id, index);
        let probe = callback_probe(callback_base, &token)?;
        let mutated = single_mutation(&url, index, probe.as_str())?;
        if mutated.origin() != url.origin() {
            return Err("out-of-band probe attempted to change the approved origin".into());
        }
        let delivered = client
            .get(mutated)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .is_ok();
        if delivered && collector.wait(&token, wait).await {
            found.push(finding(&url, index));
        }
        on_progress(position + 1, found.len());
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client() -> Client {
        Client::builder()
            .timeout(Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .unwrap()
    }

    #[test]
    fn configuration_requires_private_bind_and_clean_base() {
        assert!(OastConfig::new("127.0.0.1:9099", "http://127.0.0.1:9099").is_ok());
        assert!(OastConfig::new("0.0.0.0:9099", "http://127.0.0.1:9099").is_err());
        assert!(OastConfig::new("8.8.8.8:9099", "http://127.0.0.1:9099").is_err());
        assert!(OastConfig::new("127.0.0.1:0", "http://127.0.0.1:9099").is_err());
        assert!(OastConfig::new("127.0.0.1:9099", "ftp://127.0.0.1").is_err());
        assert!(OastConfig::new("127.0.0.1:9099", "http://user:pass@127.0.0.1").is_err());
        assert!(OastConfig::new("not-an-address", "http://127.0.0.1").is_err());
    }

    #[tokio::test]
    async fn collector_records_only_matching_tokens() {
        let collector = OastCollector::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let address = collector.address();
        let token = fresh_token(7, 0);
        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream
            .write_all(
                format!(
                    "GET /probe/{token} HTTP/1.1\r\nHost: collector\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        assert!(collector.wait(&token, Duration::from_secs(2)).await);

        let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
        stream
            .write_all(b"GET /favicon.ico HTTP/1.1\r\nHost: collector\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        assert!(!collector
            .wait(&fresh_token(9, 1), Duration::from_millis(300))
            .await);
    }

    #[tokio::test]
    async fn ssrf_callback_confirms_only_when_the_target_calls_back() {
        let collector = OastCollector::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let callback = Url::parse(&format!("http://{}", collector.address())).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = Url::parse(&format!(
            "http://{}/?url=placeholder&auth_token=SECRET",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (head, _) = crate::features::web::webtls::read_http_message(&mut socket)
                .await
                .unwrap();
            let line = head.lines().next().unwrap_or("");
            let request_target = line.split_whitespace().nth(1).unwrap_or("/");
            let parsed = Url::parse(&format!("http://local{request_target}")).unwrap();
            let callback_url = parsed
                .query_pairs()
                .find(|(key, _)| key == "url")
                .map(|(_, value)| value.into_owned())
                .unwrap_or_default();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let _ = client().get(callback_url).send().await;
        });
        let found = run_oast_with_budget(
            &client(),
            target,
            &callback,
            &collector,
            42,
            1,
            Duration::from_secs(2),
            &|_, _| {},
        )
        .await
        .unwrap();
        server.await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, "high");
        let rendered = serde_json::to_string(&found).unwrap();
        assert!(!rendered.contains("SECRET"));
        assert!(!rendered.contains("auth_token"));
        assert!(rendered.contains("cd.ascan.oast-ssrf.v1"));
    }

    #[tokio::test]
    async fn silent_targets_never_produce_a_finding() {
        let collector = OastCollector::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let callback = Url::parse(&format!("http://{}", collector.address())).unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = Url::parse(&format!(
            "http://{}/?url=placeholder",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let _ = crate::features::web::webtls::read_http_message(&mut socket).await;
            let _ = socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
        });
        let found = run_oast_with_budget(
            &client(),
            target,
            &callback,
            &collector,
            43,
            1,
            Duration::from_millis(300),
            &|_, _| {},
        )
        .await
        .unwrap();
        server.await.unwrap();
        assert!(found.is_empty());
    }

    #[tokio::test]
    async fn non_url_parameters_are_refused() {
        let collector = OastCollector::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let callback = Url::parse(&format!("http://{}", collector.address())).unwrap();
        let url = Url::parse("https://private.invalid/?q=test&page=2").unwrap();
        let error = run_oast_with_budget(
            &client(),
            url,
            &callback,
            &collector,
            44,
            1,
            Duration::from_millis(100),
            &|_, _| {},
        )
        .await
        .unwrap_err();
        assert!(error.contains("URL-like"));
    }
}
