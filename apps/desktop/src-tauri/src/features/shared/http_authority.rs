//! Fail-closed active HTTP Repeater boundary. Agent3 owns the Web transport.
//! This controller preserves the existing `http_send(request_raw)` IPC wire.
//! Until verified DNS/address-pinning exists, only explicitly confirmed literal
//! private/loopback IP targets are allowed (never hostnames or metadata IPs).
use std::net::IpAddr;
use std::time::Duration;

use tauri::{AppHandle, State};
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

use crate::features::shared::session::CaseSessionCtx;
use crate::features::web::ipc::web::{self, HttpResponseWire};

const MAX_RAW: usize = 576 * 1024;
const MAX_HEAD: usize = 32 * 1024;
const MAX_HEADERS: usize = 128;
const MAX_URL: usize = 4096;
const MAX_BODY: usize = 512 * 1024;

/// Validate cheap source bounds before Agent3's domain parser makes copies.
/// Domain names are rejected in the integration boundary until Agent3 ships
/// pinned DNS resolution and address-class checks with deterministic tests.
fn inspect_request(raw: &str) -> Result<reqwest::Url, String> {
    if raw.len() > MAX_RAW {
        return Err("HTTP request exceeds 576 KiB limit".into());
    }
    let (head, body) = raw
        .split_once("\r\n\r\n")
        .or_else(|| raw.split_once("\n\n"))
        .unwrap_or((raw, ""));
    if head.len() > MAX_HEAD || head.lines().count().saturating_sub(1) > MAX_HEADERS {
        return Err("HTTP header size/count exceeds policy".into());
    }
    if body.len() > MAX_BODY {
        return Err("HTTP body exceeds 512 KiB limit".into());
    }
    let (_, url, _, _) = web::parse_raw_request(raw, "http")?;
    if url.len() > MAX_URL {
        return Err("HTTP URL exceeds 4096-byte limit".into());
    }
    let url = reqwest::Url::parse(&url).map_err(|_| "invalid HTTP target URL")?;
    let text_host = url.host_str().ok_or("HTTP target hostname missing")?;
    // URL authorities containing IPv6 addresses can be bracketed.
    let host = text_host.trim_start_matches('[').trim_end_matches(']');
    let address: IpAddr = host
        .parse()
        .map_err(|_| "DNS hostname targets require verified address-pinned transport")?;
    let trusted = match address {
        IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unique_local()
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_private() || v4.is_loopback())
        }
    };
    if !trusted || url.port_or_known_default().is_none() {
        return Err("target is outside allowed loopback/private IP scope".into());
    }
    if url.username() != "" || url.password().is_some() || !matches!(url.scheme(), "http" | "https")
    {
        return Err("only HTTP(S) targets without URL credentials are allowed".into());
    }
    Ok(url)
}

/// Name, request payload and serialized response are identical to the existing
/// public Tauri/TypeScript contract. State/AppHandle are injected by Tauri.
#[tauri::command(rename = "http_send")]
pub async fn http_send_scoped(
    request_raw: String,
    app: AppHandle,
    session: State<'_, CaseSessionCtx>,
) -> Result<HttpResponseWire, String> {
    let url = inspect_request(&request_raw)?;
    let selected = session.selected()?;
    // Exact origin shown. This is not an unbounded blanket HTTP permission.
    let origin = url.origin().ascii_serialization();
    let confirmed = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .message(format!(
                "Authorize one HTTP request to {origin} in the currently selected case? Only explicitly owned/test systems may be targeted. This request may disclose credentials and request data."
            ))
            .title("Authorize HTTP security test")
            .buttons(MessageDialogButtons::YesNo)
            .blocking_show()
    }).await.map_err(|_| "native HTTP authorization unavailable")?;
    if !confirmed {
        return Err("HTTP request was not authorized by operator".into());
    }
    session.ensure(&selected)?;
    // Revocation is checked while waiting for network response. Dropping
    // Agent3's request future aborts normal reqwest I/O on cancellation.
    let cancelled = async {
        let mut ticker = tokio::time::interval(Duration::from_millis(100));
        loop {
            ticker.tick().await;
            if let Err(error) = session.ensure(&selected) {
                break error;
            }
        }
    };
    let result = tokio::select! {
        biased;
        error = cancelled => return Err(error),
        reply = web::http_send(request_raw) => reply?,
    };
    // Serializes publication against case selection/reselection. A caller/UI
    // must still discard a reply received after it changes its local context.
    session.with_current_publication(&selected, || Ok(result))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_private_ipv4_loopback_and_unique_local_ipv6_are_allowed() {
        for authority in [
            "127.0.0.1:8080",
            "10.0.0.2",
            "192.168.1.10:3000",
            "[::1]:9001",
            "[fd00::1]:443",
        ] {
            let raw = format!("GET /fixture HTTP/1.1\r\nHost: {authority}\r\n\r\n");
            assert!(inspect_request(&raw).is_ok(), "{authority}");
        }
    }

    #[test]
    fn metadata_link_local_and_unscoped_hostnames_fail_closed() {
        for authority in [
            "169.254.169.254",
            "0.0.0.0",
            "224.0.0.1",
            "8.8.8.8",
            "example.com",
            "localhost",
            "[fe80::1]",
        ] {
            let raw = format!("GET / HTTP/1.1\r\nHost: {authority}\r\n\r\n");
            assert!(inspect_request(&raw).is_err(), "{authority}");
        }
    }

    #[test]
    fn caps_apply_before_parsing_and_block_unbounded_requests() {
        let base = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n";
        let long_body = format!("{base}\r\n{}", "x".repeat(MAX_BODY + 1));
        assert!(inspect_request(&long_body).is_err());
        let too_many = format!("{}\r\n", format!("{base}X: x\r\n").repeat(MAX_HEADERS + 1));
        assert!(inspect_request(&too_many).is_err());
        let huge = "a".repeat(MAX_RAW + 1);
        assert!(inspect_request(&huge).is_err());
    }

    #[test]
    fn absolute_url_userinfo_and_invalid_schemes_rejected() {
        for url in [
            "http://user:secret@127.0.0.1/",
            "file:///etc/passwd",
            "http://169.254.169.254/",
        ] {
            let raw = format!("GET {url} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
            assert!(inspect_request(&raw).is_err(), "{url}");
        }
    }

    #[test]
    fn no_hidden_unauthorized_target_fallback() {
        let raw = "POST / HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\nabc";
        assert_eq!(inspect_request(raw).unwrap().host_str(), Some("127.0.0.1"));
        assert!(inspect_request("GET / HTTP/1.1\r\n\r\n").is_err());
    }
}
