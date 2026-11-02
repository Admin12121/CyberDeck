//! SPDX-License-Identifier: MIT
//! Independently authored, low-impact GET query parameter mutation and
//! HTML markup reflection rule. Studied ZAP ActiveScanController.startScan,
//! AbstractAppParamPlugin.scan and VariantAbstractQuery.setParameter, but no
//! Paros-origin source was translated or copied.
//!
//! - Only the already approved, DNS-pinned single-origin client may be used.
//! - Never mutate anti-CSRF/authentication/secret-bearing parameter names.
//! - Exactly one position changes per request (including duplicate names).
//! - Bounded requests, response bytes, target query, and source data.
//! - Markup probes are inert custom HTML elements, not executable payloads.
//! - Reports an *unescaped markup reflection*, never confirmed script XSS.
//! - No raw URLs, parameter names/values, HTTP bodies or secrets in findings.
use super::scan_domain::Finding;
use reqwest::{Client, Url};

const MAX_PARAM_COUNT: usize = 8;
const MAX_URL_BYTES: usize = 4096;
const MAX_QUERY_BYTES: usize = 2048;
const MAX_BODY_BYTES: usize = 128 * 1024;
pub(super) const MAX_REQUESTS: usize = MAX_PARAM_COUNT + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Policy {
    /// Safe, bounded, no JavaScript and no method/body mutation.
    InertHtmlElement,
}

#[derive(Debug, Clone)]
struct Vector {
    /// We never retain, report, or duplicate the parameter name/value.
    index: usize,
}

pub(super) fn sensitive_name(key: &str) -> bool {
    const PARTS: &[&str] = &[
        "csrf",
        "xsrf",
        "auth",
        "token",
        "secret",
        "password",
        "passwd",
        "session",
        "signature",
        "nonce",
        "apikey",
        "api_key",
        "access_key",
        "otp",
        "mfa",
        "state",
        "jwt",
        "credential",
        "sig",
        "key",
    ];
    let lower = key.to_ascii_lowercase();
    PARTS.iter().any(|part| lower.contains(part))
}

fn parameter_vectors(url: &Url) -> Result<Vec<Vector>, String> {
    let query = url
        .query()
        .ok_or("active query checks require URL parameters")?;
    if query.len() > MAX_QUERY_BYTES {
        return Err("active query exceeds 2048-byte bound".into());
    }
    let mut out = Vec::new();
    let mut seen = 0;
    for (index, (name, value)) in url.query_pairs().enumerate() {
        seen += 1;
        if seen > MAX_PARAM_COUNT {
            return Err("active rule supports one to eight query parameters".into());
        }
        if !name.is_empty() && !sensitive_name(&name) && name.len() <= 128 && value.len() <= 1024 {
            out.push(Vector { index });
        }
    }
    if seen == 0 {
        return Err("active query checks require URL parameters".into());
    }
    if out.is_empty() {
        return Err("all query parameters are protected or unsupported".into());
    }
    Ok(out)
}

fn single_mutation(base: &Url, index: usize, replacement: &str) -> Result<Url, String> {
    if !matches!(base.scheme(), "http" | "https") {
        return Err("active mutation requires HTTP(S)".into());
    }
    if !base.username().is_empty() || base.password().is_some() {
        return Err("URL credentials are not allowed".into());
    }
    let pairs = base
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect::<Vec<_>>();
    if index >= pairs.len() || pairs.len() > MAX_PARAM_COUNT {
        return Err("query position out of range".into());
    }
    let mut next = base.clone();
    next.set_fragment(None);
    {
        let mut query = next.query_pairs_mut();
        query.clear();
        for (i, (key, value)) in pairs.iter().enumerate() {
            query.append_pair(key, if i == index { replacement } else { value });
        }
    }
    if next.as_str().len() > MAX_URL_BYTES {
        return Err("mutated query exceeds URL bound".into());
    }
    Ok(next)
}

/// Returns None for non-HTML responses and rejects oversized bodies rather
/// than reading a stream to exhaustion. No response content is stored.
async fn bounded_html(client: &Client, url: Url) -> Result<Option<Vec<u8>>, String> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|_| "active query request failed")?;
    if response.status() != reqwest::StatusCode::OK {
        return Ok(None);
    }
    let html = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .and_then(|text| text.split(';').next())
        .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/html"));
    if !html {
        return Ok(None);
    }
    if response
        .content_length()
        .is_some_and(|bytes| bytes > MAX_BODY_BYTES as u64)
    {
        return Err("active query response exceeds 128 KiB bound".into());
    }
    let mut body = Vec::new();
    while let Some(bytes) = response
        .chunk()
        .await
        .map_err(|_| "active response body unavailable")?
    {
        if bytes.len() > MAX_BODY_BYTES.saturating_sub(body.len()) {
            return Err("active query response exceeds 128 KiB bound".into());
        }
        body.extend_from_slice(&bytes);
    }
    Ok(Some(body))
}

pub(super) fn candidate_is_reflected(baseline: &[u8], candidate: &[u8], marker: &[u8]) -> bool {
    // Exact inert custom-element text is sufficient to show unsanitized
    // HTML interpretation potential. Does NOT imply executable XSS.
    !baseline.windows(marker.len()).any(|span| span == marker)
        && candidate.windows(marker.len()).any(|span| span == marker)
}

/// Maximum nine GET requests, private DNS-pinned client, no redirects,
/// no cookies imported, no body mutation or state-changing methods.
/// Cancellation and 60s wallclock are owned by the assessment job wrapper.
pub(super) async fn run_active_query_with_progress(
    client: &Client,
    url: Url,
    job_id: u64,
    policy: Policy,
    on_progress: &impl Fn(usize, usize),
) -> Result<Vec<Finding>, String> {
    if url.as_str().len() > MAX_URL_BYTES
        || !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("invalid active query target".into());
    }
    if !matches!(policy, Policy::InertHtmlElement) {
        return Err("unsupported active rule policy".into());
    }
    let vectors = parameter_vectors(&url)?;
    let total = vectors.len() + 1;
    on_progress(0, 0);
    let baseline = bounded_html(client, url.clone())
        .await?
        .ok_or("baseline must return HTTP 200 text/html")?;
    on_progress(1, 0);
    let mut found = Vec::new();
    for (offset, vector) in vectors.iter().enumerate() {
        let marker = format!("<cyberdeck-probe-{job_id:x}-{:x}>", vector.index);
        let mutated = single_mutation(&url, vector.index, &marker)?;
        // Preserve the exact approved origin, not merely a similar hostname.
        if mutated.origin() != url.origin() {
            return Err("active query attempted to change approved origin".into());
        }
        if let Some(candidate) = bounded_html(client, mutated).await? {
            if candidate_is_reflected(&baseline, &candidate, marker.as_bytes()) {
                found.push(Finding {
                    severity: "low".into(),
                    title: "potential unescaped HTML parameter reflection".into(),
                    detail: "An inert custom-element marker was emitted as raw HTML markup after modifying one GET query parameter. This suggests unescaped HTML injection, NOT confirmed executable XSS; manually inspect its browser context and encoding policy.".into(),
                    evidence: format!(
                        "Rule cd.ascan.query-html-reflection.v1; approved origin {}; GET parameter position {}; HTTP 200 text/html. No query or response bytes retained.",
                        url.origin().ascii_serialization(),
                        vector.index + 1,
                    ),
                });
            }
        }
        on_progress(offset + 2, found.len());
    }
    debug_assert!(total <= MAX_REQUESTS);
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn duplicates_only_selected_position_mutated_without_removing_others() {
        let original = Url::parse("http://127.0.0.1/?k=first&k=second&a=three").unwrap();
        let next = single_mutation(&original, 1, "<cyberdeck-probe>").unwrap();
        assert_eq!(
            next.query_pairs().collect::<Vec<_>>(),
            vec![
                ("k".into(), "first".into()),
                ("k".into(), "<cyberdeck-probe>".into()),
                ("a".into(), "three".into()),
            ]
        );
        assert_eq!(original.query().unwrap(), "k=first&k=second&a=three");
    }

    #[test]
    fn sensitive_parameters_are_skipped_and_scope_bounded() {
        let target = Url::parse("http://127.0.0.1/a?auth_token=SECRET&q=test&csrf=CSRF").unwrap();
        let vectors = parameter_vectors(&target).unwrap();
        assert_eq!(vectors.len(), 1);
        assert_eq!(vectors[0].index, 1);
        assert!(
            parameter_vectors(&Url::parse("https://private.test/?session=SECRET").unwrap())
                .is_err()
        );
        assert!(parameter_vectors(
            &Url::parse("https://private.test/?a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8&i=9").unwrap()
        )
        .is_err());
        assert!(single_mutation(&target, 99, "probe").is_err());
    }

    #[test]
    fn raw_markup_is_different_from_html_escaped_or_static_reflection() {
        let raw = b"<cyberdeck-probe-123-0>";
        assert!(candidate_is_reflected(
            b"original",
            b"<html><cyberdeck-probe-123-0></html>",
            raw
        ));
        assert!(!candidate_is_reflected(
            b"original",
            b"&lt;cyberdeck-probe-123-0&gt;",
            raw
        ));
        assert!(!candidate_is_reflected(raw, raw, raw));
    }

    async fn fixture(escape: bool) -> (Url, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!(
            "http://{}/?q=baseline&token=SECRET",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut req = Vec::new();
                loop {
                    let mut chunk = [0u8; 512];
                    let size =
                        tokio::time::timeout(Duration::from_secs(2), socket.read(&mut chunk))
                            .await
                            .expect("fixture request timeout")
                            .expect("fixture read");
                    assert!(size > 0, "fixture must receive complete request");
                    req.extend_from_slice(&chunk[..size]);
                    assert!(req.len() <= 4096, "fixture request exceeded bound");
                    if req.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                        break;
                    }
                }
                let line = String::from_utf8_lossy(&req);
                let target = line.split_whitespace().nth(1).unwrap_or("/");
                let url = Url::parse(&format!("http://local{target}")).unwrap();
                let q = url
                    .query_pairs()
                    .find(|(k, _)| k == "q")
                    .unwrap()
                    .1
                    .into_owned();
                let body = if escape {
                    q.replace('<', "&lt;").replace('>', "&gt;")
                } else {
                    q
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(), body
                );
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        (url, server)
    }

    #[tokio::test]
    async fn localhost_active_rule_detects_inert_html_markup_without_exposing_auth_query() {
        let (url, server) = fixture(false).await;
        let client = Client::builder()
            .timeout(Duration::from_secs(2))
            .no_proxy()
            .build()
            .unwrap();
        let count = std::sync::atomic::AtomicUsize::new(0);
        let found = run_active_query_with_progress(
            &client,
            url,
            33,
            Policy::InertHtmlElement,
            &|processed, _| {
                count.store(processed, std::sync::atomic::Ordering::Release);
            },
        )
        .await
        .unwrap();
        server.await.unwrap();
        assert_eq!(count.load(std::sync::atomic::Ordering::Acquire), 2);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, "low");
        let encoded = serde_json::to_string(&found).unwrap();
        assert!(!encoded.contains("SECRET"));
        assert!(!encoded.contains("token="));
        assert!(!encoded.contains("<cyberdeck"));
    }

    #[tokio::test]
    async fn escaped_markup_does_not_raise_false_positive() {
        let (url, server) = fixture(true).await;
        let client = Client::builder()
            .timeout(Duration::from_secs(2))
            .no_proxy()
            .build()
            .unwrap();
        let found =
            run_active_query_with_progress(&client, url, 34, Policy::InertHtmlElement, &|_, _| {})
                .await
                .unwrap();
        server.await.unwrap();
        assert!(found.is_empty());
    }
}
