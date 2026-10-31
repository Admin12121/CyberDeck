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
