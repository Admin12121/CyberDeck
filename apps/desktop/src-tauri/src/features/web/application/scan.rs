//! Native authorized HTTP review application orchestration.
//! A bounded, manually started review, not a general vulnerability scanner.
use super::scan_domain::{
    confirmed_exposure, require_authorization, session_cookie_findings, Finding,
};

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

/// Native active review of a target: reachable paths, header hygiene, banner
/// disclosure. Our own checks; external engines add depth via slots below.
pub(super) async fn run_scan(
    client: &reqwest::Client,
    target_url: String,
    authorized: bool,
) -> Result<Vec<Finding>, String> {
    run_scan_with_progress(client, target_url, authorized, &|_, _| {}).await
}

/// Reports real HTTP attempts completed, not a synthetic elapsed percentage.
pub(super) async fn run_scan_with_progress(
    client: &reqwest::Client,
    target_url: String,
    authorized: bool,
    on_progress: &impl Fn(usize, usize),
) -> Result<Vec<Finding>, String> {
    require_authorization(authorized)?;
    let total = INTERESTING_PATHS.len() + 2;
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

    on_progress(1, total);
    if let Some(headers) = &root_headers {
        for (header, title) in SECURITY_HEADERS {
            if *header == "strict-transport-security" && origin.scheme() != "https" {
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
        findings.extend(session_cookie_findings(
            headers,
            origin.scheme() == "https",
            &base,
        ));
        if let Some((_, server)) = headers.iter().find(|(k, _)| k == "server") {
            findings.push(Finding {
                severity: "info".to_string(),
                title: "server banner disclosed".to_string(),
                detail: "the Server header reveals software and version; suppress it".to_string(),
                evidence: format!("server: {server}"),
            });
        }
    }

    // One extra bounded, origin-scoped active request. Wildcard ACAO with
    // credentials is deliberately NOT reported: browsers reject that pair.
    // Only a reflected arbitrary Origin together with credentials is a
    // potential issue, and the report asks for operator validation.
    let cors = client
        .get(&base)
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
    on_progress(2, total);
    for (index, (path, note)) in INTERESTING_PATHS.iter().enumerate() {
        on_progress(index + 2, total);
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
                for _ in 0..INTERESTING_PATHS.len() + 2 {
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
            let findings = run_scan_with_progress(&client, base.clone(), true, &|a,b| {
                progress.lock().unwrap().push((a,b));
            }).await.unwrap();
            let cors: Vec<_> = findings.iter()
                .filter(|f| f.title.contains("credentialed CORS")).collect();
            assert_eq!(cors.len(), 1);
            assert_eq!(cors[0].severity, "medium");
            assert!(!cors[0].evidence.contains("cookie"));
            assert_eq!(progress.lock().unwrap().last().copied(),
                Some((INTERESTING_PATHS.len() + 2, INTERESTING_PATHS.len() + 2)));
            server.await.unwrap();
        }).await.expect("scoped CORS fixture timed out");
    }
}
