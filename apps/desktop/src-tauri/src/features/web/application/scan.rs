//! Native authorized HTTP review application orchestration.
//! A bounded, manually started review, not a general vulnerability scanner.
use std::time::Duration;

use super::scan_domain::{
    confirmed_exposure, is_sensitive_path, require_authorization, session_cookie_findings, Finding,
};

/// Every probe is individually capped so one slow path cannot consume the
/// whole 60-second assessment budget or stall the remaining checks.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

const INTERESTING_PATHS: &[(&str, &str)] = &[
    (
        "/robots.txt",
        "robots.txt present; review disallowed entries for hidden paths",
    ),
    (
        "/.well-known/security.txt",
        "security.txt present; review the published contact channel",
    ),
    ("/.env", ".env file exposed: secrets leak"),
    ("/.git/HEAD", ".git directory exposed: source leak"),
    ("/.git/config", ".git configuration exposed: remote and branch metadata"),
    ("/.svn/entries", ".svn directory exposed: source leak"),
    ("/.DS_Store", "Finder metadata exposed: file name leak"),
    ("/WEB-INF/web.xml", "Java web deployment descriptor exposed"),
    ("/actuator/env", "Spring Actuator environment exposed: configuration leak"),
    ("/actuator/health", "Spring Actuator health endpoint reachable"),
    ("/swagger-ui.html", "API documentation UI reachable"),
    ("/openapi.json", "OpenAPI description exposed"),
    ("/phpmyadmin", "phpMyAdmin reachable"),
    ("/wp-login.php", "WordPress login reachable"),
    ("/admin", "/admin responded; review authentication"),
    ("/phpinfo.php", "PHP configuration page exposed"),
    ("/server-status", "Apache server-status reachable: request metadata leak"),
    ("/elmah.axd", "ELMAH error log handler reachable"),
    ("/backup.zip", "archive backup exposed"),
    ("/backup.sql", "database dump exposed"),
];

/// A non-secret, intentionally unrelated Origin used to test whether an
/// endpoint grants credentialed browser reads to an arbitrary web origin.
const CORS_PROBE_ORIGIN: &str = "https://cyberdeck-cors-probe.invalid";

fn credentialed_cors_reflection(headers: &reqwest::header::HeaderMap) -> bool {
    let origin = headers
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let credentials = headers
        .get("access-control-allow-credentials")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    origin == CORS_PROBE_ORIGIN && credentials.eq_ignore_ascii_case("true")
}

const SECURITY_HEADERS: &[(&str, &str)] = &[
    ("content-security-policy", "Content-Security-Policy"),
    ("strict-transport-security", "Strict-Transport-Security"),
    ("x-frame-options", "X-Frame-Options"),
    ("x-content-type-options", "X-Content-Type-Options"),
];

/// Login-looking redirect targets. A redirect value is inspected only to
/// decide whether the session still works; it is never stored or reported.
const LOGIN_HINTS: &[&str] = &[
    "login",
    "signin",
    "sign-in",
    "logon",
    "sso",
    "auth/",
    "session/new",
    "account/login",
];

fn redirects_to_login(location: Option<&str>) -> bool {
    let Some(location) = location else {
        return false;
    };
    let lowered = location.to_ascii_lowercase();
    LOGIN_HINTS.iter().any(|hint| lowered.contains(hint))
}

/// A rejected baseline proves the supplied session context is not valid for
/// this origin: 401/403, or a redirect to a login surface.
fn session_rejected(status: u16, location: Option<&str>) -> bool {
    matches!(status, 401 | 403)
        || (matches!(status, 301 | 302 | 303 | 307 | 308) && redirects_to_login(location))
}

fn session_rejected_finding(base: &str, status: u16) -> Finding {
    Finding {
        severity: "info".into(),
        title: "authenticated session was rejected before probing".into(),
        detail: "The approved target answered the baseline request with an authentication failure or a login redirect, so no probes were sent. Confirm the session cookie and header values are current and belong to this origin.".into(),
        evidence: format!(
            "Rule cd.session.rejected.v1; approved origin {base}; baseline HTTP {status}. No cookie, header or redirect target retained."
        ),
    }
}

fn session_stopped_finding(base: &str, requests: usize) -> Finding {
    Finding {
        severity: "info".into(),
        title: "authenticated session appears to have expired mid-review".into(),
        detail: "A probe was redirected to a login surface, so the remaining checks were skipped rather than run unauthenticated. Confirm the session lifetime and re-run with a fresh context.".into(),
        evidence: format!(
            "Rule cd.session.expired.v1; approved origin {base}; stopped after {requests} requests. No cookie, header or redirect target retained."
        ),
    }
}

/// Total bounded requests one review issues. Progress reporting and the
/// localhost fixtures both derive from this single value.
pub(super) fn planned_requests() -> usize {
    INTERESTING_PATHS.len() + 4
}

async fn bounded_body(response: &mut reqwest::Response, limit: usize) -> Vec<u8> {
    let mut body = Vec::new();
    while let Ok(Some(chunk)) = response.chunk().await {
        if body.len().saturating_add(chunk.len()) > limit {
            break;
        }
        body.extend_from_slice(&chunk);
    }
    body
}

fn header_pairs(response: &reqwest::Response) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for (key, value) in response.headers() {
        pairs.push((
            key.to_string().to_lowercase(),
            value.to_str().unwrap_or("").to_string(),
        ));
    }
    pairs
}

/// Native active review of a target: reachable paths, header hygiene, method
/// policy, banner disclosure. Our own checks; external engines add depth via
/// slots below.
pub(super) async fn run_scan(
    client: &reqwest::Client,
    target_url: String,
    authorized: bool,
) -> Result<Vec<Finding>, String> {
    run_scan_with_progress(client, target_url, authorized, false, &|_, _| {}).await
}

/// Reports real HTTP attempts completed, not a synthetic elapsed percentage.
pub(super) async fn run_scan_with_progress(
    client: &reqwest::Client,
    target_url: String,
    authorized: bool,
    authenticated: bool,
    on_progress: &impl Fn(usize, usize),
) -> Result<Vec<Finding>, String> {
    require_authorization(authorized)?;
    let total = planned_requests();
    on_progress(0, total);
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
    let https = origin.scheme() == "https";
    let mut findings: Vec<Finding> = Vec::new();
    let mut done = 0usize;

    let root = client.get(&base).timeout(PROBE_TIMEOUT).send().await.ok();
    let root_headers = root.as_ref().map(header_pairs);
    let root_status = root.as_ref().map(|response| response.status().as_u16());
    let root_location = root
        .as_ref()
        .and_then(|response| response.headers().get(reqwest::header::LOCATION))
        .and_then(|value| value.to_str().ok());
    done += 1;
    on_progress(done, total);
    if authenticated {
        if let Some(status) = root_status {
            if session_rejected(status, root_location) {
                on_progress(total, total);
                return Ok(vec![session_rejected_finding(&base, status)]);
            }
        }
    }

    if let (Some(headers), Some(status)) = (&root_headers, root_status) {
        // A 404/500 root is usually a fallback shell or an error page; policy
        // headers there say nothing about how the real documents are served.
        if (200..400).contains(&status) {
            for (header, title) in SECURITY_HEADERS {
                if *header == "strict-transport-security" && !https {
                    continue;
                }
                if *header == "x-frame-options"
                    && headers.iter().any(|(k, v)| {
                        k == "content-security-policy"
                            && v.to_ascii_lowercase().contains("frame-ancestors")
                    })
                {
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
            findings.extend(session_cookie_findings(headers, https, &base));
            if let Some((_, server)) = headers.iter().find(|(k, _)| k == "server") {
                findings.push(Finding {
                    severity: "info".to_string(),
                    title: "server banner disclosed".to_string(),
                    detail: "the Server header reveals software and version; suppress it".to_string(),
                    evidence: format!("server: {server}"),
                });
            }
            for (header, label) in [
                ("x-powered-by", "X-Powered-By"),
                ("x-aspnet-version", "X-AspNet-Version"),
                ("x-aspnetmvc-version", "X-AspNetMvc-Version"),
            ] {
                if let Some((_, value)) = headers.iter().find(|(k, _)| k == header) {
                    findings.push(Finding {
                        severity: "info".to_string(),
                        title: format!("framework banner disclosed: {label}"),
                        detail: "the response advertises the application framework; suppress unnecessary technology disclosure".to_string(),
                        evidence: format!("{header}: {value}"),
                    });
                }
            }
        }
    }

    // One extra bounded, origin-scoped active request. Wildcard ACAO with
    // credentials is deliberately NOT reported: browsers reject that pair.
    // Only a reflected arbitrary Origin together with credentials is a
    // potential issue, and the report asks for operator validation.
    let cors = client
        .get(&base)
        .timeout(PROBE_TIMEOUT)
        .header(reqwest::header::ORIGIN, CORS_PROBE_ORIGIN)
        .send()
        .await;
    if let Ok(response) = cors {
        if response.status().is_success() && credentialed_cors_reflection(response.headers()) {
            findings.push(Finding {
                severity: "medium".into(),
                title: "potential credentialed CORS origin reflection".into(),
                detail: "Server accepted an unrelated Origin with credentials. Verify authenticated browser read access and intended cross-origin policy before treating this as exploitable.".into(),
                evidence: format!("{base} -> Access-Control-Allow-Origin: {CORS_PROBE_ORIGIN}; Access-Control-Allow-Credentials: true"),
            });
        }
    }
    done += 1;
    on_progress(done, total);

    // Method policy: only diagnostic/proxy verbs are reportable. Advertised
    // PUT/DELETE/PATCH is normal REST design and is intentionally ignored.
    let options = client
        .request(reqwest::Method::OPTIONS, &base)
        .timeout(PROBE_TIMEOUT)
        .send()
        .await;
    if let Ok(response) = options {
        if let Some(allow) = response
            .headers()
            .get("allow")
            .and_then(|value| value.to_str().ok())
        {
            let diagnostic: Vec<&str> = ["TRACE", "CONNECT"]
                .into_iter()
                .filter(|verb| allow.split(',').any(|m| m.trim().eq_ignore_ascii_case(verb)))
                .collect();
            if !diagnostic.is_empty() {
                findings.push(Finding {
                    severity: "low".into(),
                    title: "diagnostic HTTP methods advertised".into(),
                    detail: "The Allow response lists a diagnostic or proxy verb. Confirm it is required in production.".into(),
                    evidence: format!("{base} -> Allow includes {}", diagnostic.join(", ")),
                });
            }
        }
    }
    done += 1;
    on_progress(done, total);

    // TRACE is idempotent and never changes server state; a 200 that echoes
    // the request line is the only accepted evidence.
    let trace = client
        .request(reqwest::Method::TRACE, &base)
        .timeout(PROBE_TIMEOUT)
        .send()
        .await;
    if let Ok(mut response) = trace {
        if response.status().is_success() {
            let body = bounded_body(&mut response, 2048).await;
            if body.starts_with(b"TRACE ") {
                findings.push(Finding {
                    severity: "medium".into(),
                    title: "HTTP TRACE method is enabled".into(),
                    detail: "The server echoed the request line for TRACE. Cross-site tracing can expose credentials to script in legacy clients; disable the method unless required.".into(),
                    evidence: format!("{base} -> 200 with an echoed TRACE request line"),
                });
            }
        }
    }
    done += 1;
    on_progress(done, total);

    for (path, note) in INTERESTING_PATHS {
        done += 1;
        on_progress(done, total);
        let url = format!("{base}{path}");
        let Ok(mut response) = client.get(&url).timeout(PROBE_TIMEOUT).send().await else {
            continue;
        };
        let status = response.status().as_u16();
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok());
        if authenticated && redirects_to_login(location) {
            findings.push(session_stopped_finding(&base, done));
            break;
        }
        if status != 200 {
            continue;
        }
        let sensitive = is_sensitive_path(path);
        if sensitive {
            let preview = bounded_body(&mut response, 4096).await;
            if !confirmed_exposure(path, &preview) {
                continue;
            }
        }
        findings.push(Finding {
            severity: if sensitive { "high" } else { "info" }.to_string(),
            title: format!("found {path}"),
            detail: note.to_string(),
            evidence: format!("{url} -> {status}"),
        });
    }
    on_progress(total, total);
    Ok(findings)
}

#[cfg(test)]
mod cors_probe_tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn only_credentialed_arbitrary_origin_reflection_is_reportable() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "access-control-allow-origin",
            reqwest::header::HeaderValue::from_static(CORS_PROBE_ORIGIN),
        );
        headers.insert(
            "access-control-allow-credentials",
            reqwest::header::HeaderValue::from_static("true"),
        );
        assert!(credentialed_cors_reflection(&headers));
        headers.insert(
            "access-control-allow-origin",
            reqwest::header::HeaderValue::from_static("*"),
        );
        assert!(!credentialed_cors_reflection(&headers));
        headers.insert(
            "access-control-allow-origin",
            reqwest::header::HeaderValue::from_static(CORS_PROBE_ORIGIN),
        );
        headers.insert(
            "access-control-allow-credentials",
            reqwest::header::HeaderValue::from_static("false"),
        );
        assert!(!credentialed_cors_reflection(&headers));
        headers.remove("access-control-allow-credentials");
        assert!(!credentialed_cors_reflection(&headers));
    }

    #[tokio::test]
    async fn localhost_scan_reports_only_confirmed_credentialed_cors_reflection() {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                for _ in 0..planned_requests() {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let (head, _) =
                        crate::features::web::webtls::read_http_message(&mut stream).await.unwrap();
                    let cors = head.to_ascii_lowercase().contains(&format!(
                        "origin: {CORS_PROBE_ORIGIN}"
                    ));
                    let response = if cors {
                        format!("HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: {CORS_PROBE_ORIGIN}\r\nAccess-Control-Allow-Credentials: true\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    } else {
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".into()
                    };
                    stream.write_all(response.as_bytes()).await.unwrap();
                }
            });
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(2))
                .redirect(reqwest::redirect::Policy::none()).no_proxy()
                .build().unwrap();
            let progress = std::sync::Mutex::new(Vec::new());
            let findings = run_scan_with_progress(&client, base.clone(), true, false, &|a,b| {
                progress.lock().unwrap().push((a,b));
            }).await.unwrap();
            let cors: Vec<_> = findings.iter()
                .filter(|f| f.title.contains("credentialed CORS")).collect();
            assert_eq!(cors.len(), 1);
            assert_eq!(cors[0].severity, "medium");
            assert!(!cors[0].evidence.contains("cookie"));
            assert_eq!(progress.lock().unwrap().last().copied(),
                Some((planned_requests(), planned_requests())));
            // A 404 root must not produce policy-header findings.
            assert!(findings.iter().all(|f| !f.title.contains("missing security header")));
            server.await.unwrap();
        }).await.expect("scoped CORS fixture timed out");
    }

    #[test]
    fn login_redirect_and_rejection_detection_is_bounded() {
        assert!(redirects_to_login(Some("/login?next=/admin")));
        assert!(redirects_to_login(Some("https://id.example.test/sso/start")));
        assert!(redirects_to_login(Some("/account/login")));
        assert!(!redirects_to_login(Some("/dashboard")));
        assert!(!redirects_to_login(None));
        assert!(session_rejected(401, None));
        assert!(session_rejected(403, None));
        assert!(session_rejected(302, Some("/signin")));
        assert!(!session_rejected(302, Some("/home")));
        assert!(!session_rejected(200, None));
    }

    #[tokio::test]
    async fn authenticated_scan_stops_immediately_when_baseline_is_rejected() {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let _ = crate::features::web::webtls::read_http_message(&mut stream)
                    .await
                    .unwrap();
                stream
                    .write_all(
                        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
            });
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(2))
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .build()
                .unwrap();
            let progress = std::sync::Mutex::new(Vec::new());
            let findings = run_scan_with_progress(&client, base, true, true, &|a, b| {
                progress.lock().unwrap().push((a, b));
            })
            .await
            .unwrap();
            server.await.unwrap();
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].severity, "info");
            assert!(findings[0].title.contains("session"));
            let rendered = serde_json::to_string(&findings).unwrap();
            assert!(!rendered.contains("sid="));
            assert!(!rendered.contains("Authorization"));
            assert_eq!(
                progress.lock().unwrap().last().copied(),
                Some((planned_requests(), planned_requests()))
            );
        })
        .await
        .expect("session rejection fixture timed out");
    }

    #[tokio::test]
    async fn unauthenticated_review_never_reports_session_state() {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                for _ in 0..planned_requests() {
                    let Ok((mut stream, _)) = listener.accept().await else {
                        return;
                    };
                    let _ = crate::features::web::webtls::read_http_message(&mut stream).await;
                    stream
                        .write_all(
                            b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .unwrap();
                }
            });
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(2))
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .build()
                .unwrap();
            let findings = run_scan_with_progress(&client, base, true, false, &|_, _| {})
                .await
                .unwrap();
            server.await.unwrap();
            assert!(findings.iter().all(|finding| !finding.title.contains("session")));
        })
        .await
        .expect("unauthenticated fixture timed out");
    }
}
