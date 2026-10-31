//! Bounded same-origin crawler application.
//! An authenticated/JS-aware browser crawler is not yet implemented.
use super::scan_domain::require_authorization;
use std::collections::{HashSet, VecDeque};

/// Extract href values from bounded HTML, recognizing single, double and
/// unquoted forms. Comment/script/style content is ignored by the crawler.
pub(super) fn extract_hrefs(html: &str) -> Vec<&str> {
    let bytes = html.as_bytes();
    let mut links = Vec::new();
    let mut i = 0;
    while i < bytes.len() && links.len() < 1000 {
        let Some(pos) = bytes[i..].iter().position(|&b| b == b'<') else {
            break;
        };
        i += pos + 1;
        if bytes[i..].starts_with(b"!--") {
            if let Some(end) = html[i..].find("-->") {
                i += end + 3;
            } else {
                break;
            }
            continue;
        }
        let name_start = i;
        while i < bytes.len() && bytes[i].is_ascii_alphabetic() {
            i += 1;
        }
        let tag = &html[name_start..i];
        if tag.eq_ignore_ascii_case("script") || tag.eq_ignore_ascii_case("style") {
            if let Some(end) = html[i..]
                .to_ascii_lowercase()
                .find(&format!("</{}", tag.to_ascii_lowercase()))
            {
                i += end + tag.len() + 2;
            }
            continue;
        }
        if !(tag.eq_ignore_ascii_case("a")
            || tag.eq_ignore_ascii_case("link")
            || tag.eq_ignore_ascii_case("area"))
        {
            continue;
        }
        while i < bytes.len() && bytes[i] != b'>' {
            while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'/') {
                i += 1;
            }
            let key_start = i;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'-' | b'_' | b':'))
            {
                i += 1;
            }
            if i == key_start {
                i += 1;
                continue;
            }
            let is_href = bytes[key_start..i].eq_ignore_ascii_case(b"href");
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if bytes.get(i) != Some(&b'=') {
                continue;
            }
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            let quote = if matches!(bytes.get(i), Some(b'\'' | b'"')) {
                let q = bytes[i];
                i += 1;
                Some(q)
            } else {
                None
            };
            let start = i;
            while i < bytes.len() {
                if quote.is_some_and(|q| bytes[i] == q) {
                    break;
                }
                if quote.is_none() && (bytes[i].is_ascii_whitespace() || bytes[i] == b'>') {
                    break;
                }
                i += 1;
            }
            if is_href {
                if let Some(href) = html.get(start..i) {
                    if !href.is_empty() {
                        links.push(href);
                    }
                }
            }
            if quote.is_some() && i < bytes.len() {
                i += 1;
            }
        }
    }
    links
}

/// Resolve a link only if its parsed origin matches the authorized origin.
/// Substring hostname comparisons and automatic redirects are not safe scope checks.
pub(super) fn resolve_scoped_link(
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
pub(super) async fn run_spider(
    client: &reqwest::Client,
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
        for href in extract_hrefs(&html) {
            let Some(absolute) = resolve_scoped_link(&base, &url, href) else {
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
