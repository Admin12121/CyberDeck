//! SPDX-License-Identifier: MIT
//! Independently implemented active injection probes for authorized Web
//! reviews. Studied ZAP's ActiveScanController/AbstractAppParamPlugin flow and
//! public SQL error taxonomies; no upstream source was translated or copied.
//!
//! Safety contract:
//! - Only the already approved, DNS-pinned single-origin client is used.
//! - Never mutate anti-CSRF/authentication/secret-bearing parameter names.
//! - GET only: no method change, no body, no state-changing verb.
//! - One position changes per request, exactly like the reflection rule.
//! - Payloads are read-only syntax probes: a quote, two AND clauses, and
//!   traversal sequences. No UNION, stacked statements, time delays, file
//!   writes, command execution or exfiltration payloads.
//! - Findings never contain URLs, parameter names, payloads or response
//!   bytes; only a positional reference and the approved origin.
use super::active_query_application::{sensitive_name, single_mutation};
use super::scan_domain::Finding;
use reqwest::{Client, Url};

const MAX_PARAM_COUNT: usize = 8;
const MAX_URL_BYTES: usize = 4096;
const MAX_QUERY_BYTES: usize = 2048;
const MAX_VALUE_BYTES: usize = 1024;
const MAX_BODY_BYTES: usize = 128 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Policy {
    /// Append one quote and look for a database syntax-error signature.
    SqlError,
    /// Paired tautology/contradiction clauses compared against the baseline.
    SqlBoolean,
    /// Substitute file-inclusion sequences and confirm a known file signature.
    Traversal,
}

impl Policy {
    fn requests_per_parameter(self) -> usize {
        match self {
            Self::SqlError => 1,
            Self::SqlBoolean => 2,
            Self::Traversal => 2,
        }
    }
    fn rule_id(self) -> &'static str {
        match self {
            Self::SqlError => "cd.ascan.sql-error.v1",
            Self::SqlBoolean => "cd.ascan.sql-boolean.v1",
            Self::Traversal => "cd.ascan.path-traversal.v1",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Vector {
    /// Position only: the parameter name and value are never retained.
    index: usize,
}

struct Reply {
    status: u16,
    body: Vec<u8>,
}

/// Parameter names that commonly address files or templates. Traversal is
/// only attempted where the name suggests a filesystem or path semantic.
fn file_like_name(name: &str) -> bool {
    const PARTS: &[&str] = &[
        "file",
        "path",
        "page",
        "doc",
        "template",
        "load",
        "include",
        "download",
        "img",
        "image",
        "view",
        "dir",
        "folder",
        "resource",
        "lang",
        "theme",
        "module",
        "src",
        "target",
        "url",
    ];
    let lower = name.to_ascii_lowercase();
    PARTS.iter().any(|part| lower.contains(part))
}

fn vectors(url: &Url, policy: Policy, max_mutations: usize) -> Result<Vec<Vector>, String> {
    if max_mutations == 0 || max_mutations > MAX_PARAM_COUNT {
        return Err("active injection budget must be 1-8 parameters".into());
    }
    let query = url
        .query()
        .ok_or("active injection checks require URL parameters")?;
    if query.len() > MAX_QUERY_BYTES {
        return Err("active injection query exceeds 2048-byte bound".into());
    }
    let mut out = Vec::new();
    let mut seen = 0usize;
    for (index, (name, value)) in url.query_pairs().enumerate() {
        seen += 1;
        if seen > MAX_PARAM_COUNT {
            return Err("active injection supports one to eight query parameters".into());
        }
        if name.is_empty()
            || sensitive_name(&name)
            || name.len() > 128
            || value.len() > MAX_VALUE_BYTES
        {
            continue;
        }
        if policy == Policy::Traversal && !file_like_name(&name) {
            continue;
        }
        out.push(Vector { index });
    }
    if seen == 0 {
        return Err("active injection checks require URL parameters".into());
    }
    if out.is_empty() {
        return Err(match policy {
            Policy::Traversal => {
                "no file-like query parameter is eligible for traversal checks".into()
            }
            _ => "all query parameters are protected or unsupported".into(),
        });
    }
    out.truncate(max_mutations);
    Ok(out)
}

/// Appends a probe suffix to the current value at one position. Reuses the
/// audited single-position mutation helper so duplicate names and origin
/// preservation behave exactly like the reflection rule.
fn appended(base: &Url, index: usize, suffix: &str) -> Result<Url, String> {
    let original = base
        .query_pairs()
        .nth(index)
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default();
    if original.len() + suffix.len() > MAX_VALUE_BYTES {
        return Err("injection payload exceeds the query value bound".into());
    }
    let mutated = single_mutation(base, index, &format!("{original}{suffix}"))?;
    if mutated.origin() != base.origin() {
        return Err("active probe attempted to change the approved origin".into());
    }
    Ok(mutated)
}

async fn fetch(client: &Client, url: Url) -> Result<Reply, String> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|_| "active probe request failed")?;
    let status = response.status().as_u16();
    if response
        .content_length()
        .is_some_and(|bytes| bytes > MAX_BODY_BYTES as u64)
    {
        return Err("active probe response exceeds 128 KiB bound".into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "active probe body unavailable")?
    {
        if chunk.len() > MAX_BODY_BYTES.saturating_sub(body.len()) {
            return Err("active probe response exceeds 128 KiB bound".into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Reply { status, body })
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|span| span == needle)
}

/// Vendor-specific engine messages. A marker only counts when it is absent
/// from the baseline, which removes the common false positive of a page that
/// already discusses SQL errors or ships a debugging console.
const SQL_ERROR_MARKERS: &[&str] = &[
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "syntax error at or near",
    "unterminated quoted string",
    "ora-00933",
    "ora-01756",
    "ora-00921",
    "microsoft ole db provider for sql server",
    "mysqli_sql_exception",
    "mysql_fetch_array",
    "sqlite3::",
    "sqlstate[",
    "pg_query(): query failed",
    "invalid input syntax for type",
];

fn sql_error_only_in_candidate(baseline: &[u8], candidate: &[u8]) -> bool {
    let (Ok(base), Ok(cand)) = (
        std::str::from_utf8(baseline),
        std::str::from_utf8(candidate),
    ) else {
        return false;
    };
    let base = base.to_ascii_lowercase();
    let cand = cand.to_ascii_lowercase();
    SQL_ERROR_MARKERS
        .iter()
        .any(|marker| cand.contains(marker) && !base.contains(marker))
}

/// Known-content signatures for the two traversal targets. Anything less
/// specific would report ordinary 404/SPA bodies.
fn traversal_signature(baseline: &[u8], candidate: &[u8]) -> Option<&'static str> {
    for (needle, label) in [
        (&b"root:x:0:0:"[..], "unix account file"),
        (&b"[fonts]"[..], "windows ini file"),
    ] {
        if contains(candidate, needle) && !contains(baseline, needle) {
            return Some(label);
        }
    }
    None
}

/// Length after removing every occurrence of the probe payload. Reflected
/// payloads then stop inflating the comparison, which is otherwise the main
/// source of boolean-differential false positives.
fn byte_len_without(haystack: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() {
        return haystack.len();
    }
    let mut length = haystack.len();
    let mut index = 0usize;
    while index + needle.len() <= haystack.len() {
        if &haystack[index..index + needle.len()] == needle {
            length -= needle.len();
            index += needle.len();
        } else {
            index += 1;
        }
    }
    length
}

fn boolean_divergence(
    baseline: &Reply,
    truth: &Reply,
    falsity: &Reply,
    truth_payload: &str,
    falsity_payload: &str,
) -> bool {
    if truth.status != 200 || falsity.status != 200 {
        return false;
    }
    let base = byte_len_without(&baseline.body, truth_payload.as_bytes());
    let true_len = byte_len_without(&truth.body, truth_payload.as_bytes());
    let false_len = byte_len_without(&falsity.body, falsity_payload.as_bytes());
    let unchanged = base.abs_diff(true_len) <= (base.max(true_len) / 20).max(32);
    let divergent = true_len.abs_diff(false_len) >= (true_len.max(false_len) / 10).max(64);
    unchanged && divergent
}

fn sql_finding(url: &Url, vector: Vector, policy: Policy) -> Finding {
    let (severity, title, detail) = match policy {
        Policy::SqlError => (
            "medium",
            "potential error-based SQL injection",
            "A single quote appended to one GET parameter produced a database syntax-error signature that was absent from the baseline. This indicates unhandled input reaching a query, not confirmed data access; inspect query construction and parameterization.",
        ),
        _ => (
            "low",
            "possible boolean-based SQL injection (heuristic)",
            "Tautological and contradictory AND clauses produced materially different response sizes while the tautology matched the baseline. This is a heuristic signal only: caching, CSRF tokens and render variance can produce the same effect. Confirm manually.",
        ),
    };
    Finding {
        severity: severity.into(),
        title: title.into(),
        detail: detail.into(),
        evidence: format!(
            "Rule {}; approved origin {}; GET parameter position {}; no query, parameter name, payload or response bytes retained.",
            policy.rule_id(),
            url.origin().ascii_serialization(),
            vector.index + 1,
        ),
    }
}

fn traversal_finding(url: &Url, vector: Vector, signature: &str) -> Finding {
    Finding {
        severity: "high".into(),
        title: "potential path traversal / local file inclusion".into(),
        detail: format!(
            "Substituting a traversal sequence for one file-like GET parameter returned a confirmed {signature} signature that was absent from the baseline. File content is withheld; confirm whether this parameter may address files outside its intended directory."
        ),
        evidence: format!(
            "Rule {}; approved origin {}; GET parameter position {}; matched signature only, no path or file content retained.",
            Policy::Traversal.rule_id(),
            url.origin().ascii_serialization(),
            vector.index + 1,
        ),
    }
}

/// Bounded active injection review. Cancellation, case revision and the
/// 60-second wallclock are owned by the assessment job wrapper.
pub(super) async fn run_active_injection_with_budget(
    client: &Client,
    url: Url,
    policy: Policy,
    max_mutations: usize,
    on_progress: &impl Fn(usize, usize),
) -> Result<Vec<Finding>, String> {
    if url.as_str().len() > MAX_URL_BYTES
        || !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("invalid active injection target".into());
    }
    let vectors = vectors(&url, policy, max_mutations)?;
    let total = 1 + vectors.len() * policy.requests_per_parameter();
    on_progress(0, 0);
    let baseline = fetch(client, url.clone()).await?;
    if !(200..300).contains(&baseline.status) {
        return Err("baseline must return a successful HTTP response".into());
    }
    on_progress(1, 0);
    let mut found = Vec::new();
    let mut processed = 1usize;
    for vector in vectors {
        match policy {
            Policy::SqlError => {
                if let Ok(candidate) = fetch(client, appended(&url, vector.index, "'")?).await {
                    if sql_error_only_in_candidate(&baseline.body, &candidate.body) {
                        found.push(sql_finding(&url, vector, policy));
                    }
                }
            }
            Policy::SqlBoolean => {
                let truth_payload = "' AND '1'='1";
                let falsity_payload = "' AND '1'='2";
                let truth = fetch(client, appended(&url, vector.index, truth_payload)?).await;
                let falsity = fetch(client, appended(&url, vector.index, falsity_payload)?).await;
                if let (Ok(truth), Ok(falsity)) = (truth, falsity) {
                    if boolean_divergence(
                        &baseline,
                        &truth,
                        &falsity,
                        truth_payload,
                        falsity_payload,
                    ) {
                        found.push(sql_finding(&url, vector, policy));
                    }
                }
            }
            Policy::Traversal => {
                // Both payloads are always issued so progress and request
                // counts stay deterministic, but one position reports once.
                let mut confirmed = false;
                for payload in [
                    "../../../../../../etc/passwd",
                    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
                ] {
                    if let Ok(candidate) = fetch(client, appended(&url, vector.index, payload)?).await
                    {
                        if let Some(signature) =
                            traversal_signature(&baseline.body, &candidate.body)
                        {
                            if !confirmed {
                                confirmed = true;
                                found.push(traversal_finding(&url, vector, signature));
                            }
                        }
                    }
                }
            }
        }
        processed += policy.requests_per_parameter();
        on_progress(processed, found.len());
    }
    debug_assert!(processed <= total);
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

    fn query_value(head: &str, name: &str) -> String {
        let target = head.split_whitespace().nth(1).unwrap_or("/");
        Url::parse(&format!("http://local{target}"))
            .ok()
            .and_then(|url| {
                url.query_pairs()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value.into_owned())
            })
            .unwrap_or_default()
    }

    async fn serve<F>(requests: usize, query: &str, handler: F) -> (Url, tokio::task::JoinHandle<()>)
    where
        F: Fn(&str) -> String + Send + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!(
            "http://{}/?{query}",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..requests {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let mut request = Vec::new();
                loop {
                    let mut chunk = [0u8; 1024];
                    let Ok(size) = socket.read(&mut chunk).await else {
                        return;
                    };
                    if size == 0 {
                        break;
                    }
                    request.extend_from_slice(&chunk[..size]);
                    if request.windows(4).any(|span| span == b"\r\n\r\n") {
                        break;
                    }
                    if request.len() > 8192 {
                        break;
                    }
                }
                let body = handler(&String::from_utf8_lossy(&request));
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });
        (url, server)
    }

    fn client() -> Client {
        Client::builder()
            .timeout(Duration::from_secs(2))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn quote_probe_reports_only_new_database_error_signatures() {
        let (url, server) = serve(2, "q=baseline&auth_token=SECRET", |head| {
            if query_value(head, "q").contains('\'') {
                "<html>You have an error in your SQL syntax; check the manual</html>".into()
            } else {
                "<html>ok</html>".into()
            }
        })
        .await;
        let found = run_active_injection_with_budget(&client(), url, Policy::SqlError, 1, &|_, _| {})
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, "medium");
        let rendered = serde_json::to_string(&found).unwrap();
        for secret in ["SECRET", "auth_token", "q=baseline", "SQL syntax"] {
            assert!(!rendered.contains(secret), "leaked {secret}");
        }
        assert!(rendered.contains("cd.ascan.sql-error.v1"));
    }

    #[tokio::test]
    async fn pre_existing_error_page_does_not_raise_a_finding() {
        let (url, server) = serve(2, "q=baseline", |_| {
            "<html>You have an error in your SQL syntax</html>".into()
        })
        .await;
        let found = run_active_injection_with_budget(&client(), url, Policy::SqlError, 1, &|_, _| {})
            .await
            .unwrap();
        server.await.unwrap();
        assert!(found.is_empty());
    }

    #[tokio::test]
    async fn traversal_requires_a_file_signature_and_withholds_content() {
        let (url, server) = serve(3, "file=docs&session=SECRET", |head| {
            let value = query_value(head, "file");
            if value.contains("etc/passwd") {
                "root:x:0:0:root:/root:/bin/bash\n".into()
            } else if value.contains("win.ini") {
                "[fonts]\n[extensions]\n".into()
            } else {
                "<html>docs</html>".into()
            }
        })
        .await;
        let found =
            run_active_injection_with_budget(&client(), url, Policy::Traversal, 1, &|_, _| {})
                .await
                .unwrap();
        server.await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, "high");
        let rendered = serde_json::to_string(&found).unwrap();
        for secret in ["root:x", "etc/passwd", "win.ini", "SECRET", "session="] {
            assert!(!rendered.contains(secret), "leaked {secret}");
        }
        assert!(rendered.contains("cd.ascan.path-traversal.v1"));
    }

    #[tokio::test]
    async fn traversal_rejects_targets_without_a_file_like_parameter() {
        let url = Url::parse("https://private.invalid/?q=test").unwrap();
        let error = run_active_injection_with_budget(&client(), url, Policy::Traversal, 1, &|_, _| {})
            .await
            .unwrap_err();
        assert!(error.contains("file-like"));
    }

    #[tokio::test]
    async fn boolean_probe_requires_baseline_match_and_clear_divergence() {
        let (url, server) = serve(3, "q=baseline", |head| {
            let value = query_value(head, "q");
            if value.contains("'1'='2") {
                format!("<html>{}</html>", "x".repeat(2048))
            } else {
                "<html>stable page body</html>".into()
            }
        })
        .await;
        let found = run_active_injection_with_budget(
            &client(),
            url,
            Policy::SqlBoolean,
            1,
            &|_, _| {},
        )
        .await
        .unwrap();
        server.await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].severity, "low");
        assert!(!serde_json::to_string(&found)
            .unwrap()
            .contains("' AND '"));
    }

    #[tokio::test]
    async fn boolean_probe_ignores_identical_responses() {
        let (url, server) = serve(3, "q=baseline", |_| "<html>stable page body</html>".into()).await;
        let found = run_active_injection_with_budget(
            &client(),
            url,
            Policy::SqlBoolean,
            1,
            &|_, _| {},
        )
        .await
        .unwrap();
        server.await.unwrap();
        assert!(found.is_empty());
    }

    #[tokio::test]
    async fn credential_parameters_are_never_probed() {
        let url = Url::parse("https://private.invalid/?auth_token=SECRET&csrf=TOKEN").unwrap();
        let error = run_active_injection_with_budget(&client(), url, Policy::SqlError, 1, &|_, _| {})
            .await
            .unwrap_err();
        assert!(error.contains("protected or unsupported"));
    }
}
