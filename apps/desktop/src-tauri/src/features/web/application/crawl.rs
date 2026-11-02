//! Bounded same-origin crawler application.
//! An authenticated/JS-aware browser crawler is not yet implemented.
use super::scan_domain::require_authorization;
use std::collections::{HashSet, VecDeque};

/// Extract safe navigational links and GET-form actions from bounded HTML.
/// POST forms are never submitted or converted into automatic GET requests.
/// Comment/script/style content is ignored by this deliberately limited parser.
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
        let is_form = tag.eq_ignore_ascii_case("form");
        if !(tag.eq_ignore_ascii_case("a")
            || tag.eq_ignore_ascii_case("link")
            || tag.eq_ignore_ascii_case("area")
            || is_form)
        {
            continue;
        }
        let mut form_action = None;
        let mut form_method = None;
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
            let is_href = !is_form && bytes[key_start..i].eq_ignore_ascii_case(b"href");
            let is_form_action = is_form && bytes[key_start..i].eq_ignore_ascii_case(b"action");
            let is_form_method = is_form && bytes[key_start..i].eq_ignore_ascii_case(b"method");
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
            if let Some(value) = html.get(start..i) {
                if is_href && !value.is_empty() {
                    links.push(value);
                }
                if is_form_action {
                    form_action = Some(value);
                }
                if is_form_method {
                    form_method = Some(value);
                }
            }
            if quote.is_some() && i < bytes.len() {
                i += 1;
            }
        }
        // HTML defaults missing method to GET. Unknown/POST methods are
        // intentionally skipped: no accidental form submissions.
        if is_form && form_method.is_none_or(|method: &str| method.eq_ignore_ascii_case("get")) {
            if let Some(action) = form_action.filter(|value: &&str| !value.is_empty()) {
                links.push(action);
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

/// robots.txt only supplies explicit Sitemap metadata, never Disallow paths
/// to attack. Limit hint scanning and ignore comments and unknown directives.
pub(super) fn sitemap_hints(robots: &str) -> Vec<&str> {
    let mut hints = Vec::new();
    for line in robots.lines().take(512) {
        let value = line.split('#').next().unwrap_or("").trim();
        let Some((name, link)) = value.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("sitemap") && !link.trim().is_empty() {
            hints.push(link.trim());
            if hints.len() >= 2 {
                break;
            }
        }
    }
    hints
}

/// Intentionally conservative XML subset: only explicit <urlset><loc>
/// entries (not entity-expanded XML, DTDs, sitemap indexes, or HTML).
/// URLs are subsequently re-parsed and exact-origin checked by caller.
pub(super) fn sitemap_locations(xml: &str) -> Vec<&str> {
    if !sitemap_root(xml, "<urlset") {
        return Vec::new();
    }
    let mut links = Vec::new();
    let mut index = 0;
    while index < xml.len() && links.len() < 60 {
        let Some(at) = xml[index..].find("<loc>") else {
            break;
        };
        let start = index + at + "<loc>".len();
        let Some(end) = xml[start..].find("</loc>") else {
            break;
        };
        let value = xml[start..start + end].trim();
        // No XML entity substitution; reject rather than reinterpret
        // ambiguous URLs, query-bearing URLs are later excluded.
        if !value.is_empty() && !value.contains('&') && value.len() <= 4096 {
            links.push(value);
        }
        index = start + end + "</loc>".len();
    }
    links
}

/// Only consume structurally recognizable sitemap XML documents. This is
/// not a general XML parser: no DTD, entities, namespaces, or external IO.
fn sitemap_root<'a>(xml: &'a str, root: &str) -> bool {
    if xml.contains("<!DOCTYPE") || xml.contains("<!ENTITY") {
        return false;
    }
    let mut head = xml.trim_start_matches('\u{feff}').trim_start();
    if head.starts_with("<?xml") {
        let Some(end) = head.find("?>") else {
            return false;
        };
        head = head[end + 2..].trim_start();
    }
    head.strip_prefix(root)
        .is_some_and(|rest| rest.starts_with('>') || rest.starts_with(char::is_whitespace))
}

/// Read one sitemap-index level; caller limits total XML fetches to two,
/// validates origin/pinned transport, and never follows a second index.
pub(super) fn sitemap_index_locations(xml: &str) -> Vec<&str> {
    if !sitemap_root(xml, "<sitemapindex") {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut cursor = 0;
    while cursor < xml.len() && out.len() < 2 {
        let Some(at) = xml[cursor..].find("<loc>") else {
            break;
        };
        let start = cursor + at + "<loc>".len();
        let Some(end) = xml[start..].find("</loc>") else {
            break;
        };
        let value = xml[start..start + end].trim();
        if !value.is_empty() && !value.contains('&') && value.len() <= 4096 {
            out.push(value);
        }
        cursor = start + end + "</loc>".len();
    }
    out
}

/// Optional discovery seeds: exactly one robots GET and at most two
/// same-origin XML GETs (including the conventional /sitemap.xml).
/// All data and destinations are bounded, and all requests use the
/// caller's already approved redirect-disabled DNS-pinned client.
async fn discover_sitemap_seeds(
    client: &reqwest::Client,
    base: &reqwest::Url,
    seen: &mut HashSet<String>,
    links: &mut Vec<String>,
    queue: &mut VecDeque<(reqwest::Url, u8)>,
) {
    let Some(robots_url) = resolve_scoped_link(base, base, "/robots.txt") else {
        return;
    };
    let robots = fetch_crawl_page(client, &robots_url)
        .await
        .unwrap_or_default();
    let mut sitemap_urls = VecDeque::new();
    if let Some(default) = resolve_scoped_link(base, base, "/sitemap.xml") {
        sitemap_urls.push_back(default);
    }
    for hint in sitemap_hints(&robots) {
        let Some(url) = resolve_scoped_link(base, &robots_url, hint) else {
            continue;
        };
        if url.query().is_none() && !sitemap_urls.contains(&url) && sitemap_urls.len() < 2 {
            sitemap_urls.push_back(url);
        }
    }
    let mut xml_requests = 0_usize;
    let mut expanded_one_index = false;
    while let Some(sitemap) = sitemap_urls.pop_front() {
        if links.len() >= 60 || xml_requests >= 2 {
            break;
        }
        xml_requests += 1;
        let Some(xml) = fetch_crawl_page(client, &sitemap).await else {
            continue;
        };
        if !expanded_one_index && sitemap_root(&xml, "<sitemapindex") {
            expanded_one_index = true;
            for hint in sitemap_index_locations(&xml) {
                let Some(child) = resolve_scoped_link(base, &sitemap, hint) else {
                    continue;
                };
                if child.query().is_none() && !sitemap_urls.contains(&child) && child != sitemap {
                    // Prioritize a child over another hinted XML root,
                    // but never recursively expand another index.
                    sitemap_urls.push_front(child);
                    break;
                }
            }
            continue;
        }
        for hint in sitemap_locations(&xml) {
            let Some(url) = resolve_scoped_link(base, &sitemap, hint) else {
                continue;
            };
            if url.query().is_some() || url.as_str().len() > 4096 {
                continue;
            }
            let key = url.to_string();
            if seen.insert(key.clone()) {
                links.push(key);
                queue.push_back((url, 1));
                if links.len() >= 60 {
                    break;
                }
            }
        }
    }
}

/// A bounded same-origin crawler; redirects are disabled in http_client().
pub(super) async fn run_spider(
    client: &reqwest::Client,
    target_url: String,
    max_depth: u8,
    authorized: bool,
) -> Result<Vec<String>, String> {
    run_spider_with_progress(client, target_url, max_depth, authorized, &|_, _| {}).await
}

/// Reports real pages attempted and URLs discovered to the native job.
pub(super) async fn run_spider_with_progress(
    client: &reqwest::Client,
    target_url: String,
    max_depth: u8,
    authorized: bool,
    on_progress: &impl Fn(usize, usize),
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
    let mut processed = 0usize;
    on_progress(0, links.len());
    if max_depth > 0 {
        discover_sitemap_seeds(client, &base, &mut seen, &mut links, &mut queue).await;
        on_progress(0, links.len());
    }
    while let Some((url, depth)) = queue.pop_front() {
        processed += 1;
        on_progress(processed, links.len());
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
    on_progress(processed, links.len());
    Ok(links)
}
