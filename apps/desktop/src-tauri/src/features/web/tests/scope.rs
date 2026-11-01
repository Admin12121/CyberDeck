//! Scope, request parser, content checks and proxy policy regression tests.

use super::*;

#[test]
fn origin_match_is_not_hostname_substring_match() {
    let base = reqwest::Url::parse("https://example.com/path").unwrap();
    assert!(resolve_scoped_link(&base, &base, "https://example.com.evil.test/path").is_none());
    assert!(resolve_scoped_link(&base, &base, "https://evil.test/example.com").is_none());
    assert!(resolve_scoped_link(&base, &base, "http://example.com/path").is_none());
    assert!(resolve_scoped_link(&base, &base, "javascript:alert(1)").is_none());
    assert_eq!(
        resolve_scoped_link(&base, &base, "../next")
            .unwrap()
            .as_str(),
        "https://example.com/next"
    );
}

#[test]
fn connect_target_requires_unambiguous_authority() {
    assert_eq!(
        parse_connect_target("example.com:443").unwrap(),
        ("example.com".to_string(), 443)
    );
    assert_eq!(
        parse_connect_target("[::1]:8443").unwrap(),
        ("::1".to_string(), 8443)
    );
    for bad in [
        "example.com",
        "example.com:0",
        "example.com:abc",
        "::1:443",
        "user@example.com:443",
        "https://example.com:443",
        "example.com:65536",
    ] {
        assert!(parse_connect_target(bad).is_err(), "{bad}");
    }
}

#[test]
fn tls_tunnel_rejects_host_confusion() {
    let headers = vec![("Host".into(), "example.com:8443".into())];
    assert!(tls_host_matches(&headers, "example.com", 8443));
    assert!(!tls_host_matches(&headers, "example.com", 443));
    assert!(!tls_host_matches(&headers, "other.example", 8443));
    assert!(!tls_host_matches(
        &[
            ("Host".into(), "example.com".into()),
            ("host".into(), "evil.invalid".into())
        ],
        "example.com",
        443
    ));
}

#[tokio::test]
async fn websocket_handshake_preserves_first_frame() {
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    let (mut writer, mut reader) = duplex(512);
    writer.write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n\x81\x02OK")
            .await.unwrap();
    let head = read_http_response_head(&mut reader).await.unwrap();
    assert!(is_websocket_switching_protocols(&head));
    let mut frame = [0u8; 4];
    reader.read_exact(&mut frame).await.unwrap();
    assert_eq!(&frame, b"\x81\x02OK");
}

#[test]
fn websocket_upgrade_accepts_status_without_reason_phrase() {
    assert!(is_websocket_switching_protocols(
        "HTTP/1.1 101\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
    ));
}

#[test]
fn websocket_upgrade_requires_confirmed_101() {
    assert!(is_websocket_switching_protocols(
            "HTTP/1.1 101 Switching Protocols\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n"));
    assert!(!is_websocket_switching_protocols(
        "HTTP/1.1 200 OK\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
    ));
    assert!(!is_websocket_switching_protocols(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"
    ));
}

#[test]
fn websocket_accept_requires_matching_rfc6455_nonce() {
    let req = "GET /ws HTTP/1.1\r\nHost: example.org\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    let good = "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
    assert!(websocket_accept_matches(req, good));
    assert!(!websocket_accept_matches(
        req,
        &good.replace("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", "wrong")
    ));
    assert!(!websocket_accept_matches(req, &good.replace("101", "200")));
    assert!(!websocket_accept_matches(
        req,
        &good.replace("Sec-WebSocket-Accept", "X-Invalid")
    ));
    assert!(!websocket_accept_matches(
        &req.replace("dGhlIHNhbXBsZSBub25jZQ==", "bad"),
        good
    ));
    assert!(!websocket_accept_matches(
        req,
        &good.replace("\r\n\r\n", "\r\nSec-WebSocket-Accept: duplicate\r\n\r\n")
    ));
}

#[test]
fn nominated_connection_headers_are_hop_by_hop() {
    let headers = vec![
        ("Connection".into(), "keep-alive, X-Internal-Relay".into()),
        ("X-Internal-Relay".into(), "metadata".into()),
        ("X-Application".into(), "retained".into()),
    ];
    assert!(is_hop_header_for_message("Connection", &headers));
    assert!(is_hop_header_for_message("x-internal-relay", &headers));
    assert!(!is_hop_header_for_message("X-Application", &headers));
}

#[test]
fn rules_preserve_non_utf8_payloads() {
    let source = vec![0xff, 0x00, b'A', b'B', 0xfe];
    assert_eq!(
        replace_bytes_limited(source, b"AB", b"XYZ"),
        vec![0xff, 0x00, b'X', b'Y', b'Z', 0xfe]
    );
}

#[test]
fn session_cookie_audit_redacts_values_and_respects_attributes() {
    let headers = vec![(
        "set-cookie".to_string(),
        "session=top-secret; Path=/; Secure; HttpOnly; SameSite=Lax".to_string(),
    )];
    assert!(session_cookie_findings(&headers, true, "https://example.test").is_empty());
    let insecure = vec![("set-cookie".into(), "session=top-secret; Path=/".into())];
    let result = session_cookie_findings(&insecure, true, "https://example.test");
    assert_eq!(result.len(), 3);
    assert!(result.iter().all(|f| !f.evidence.contains("top-secret")));
}

#[test]
fn generic_spa_fallbacks_are_not_sensitive_exposures() {
    assert!(!confirmed_exposure("/.env", b"<html>index.html</html>"));
    assert!(!confirmed_exposure(
        "/.git/HEAD",
        b"<html>index.html</html>"
    ));
    assert!(confirmed_exposure("/.env", b"APP_KEY=sample-value\n"));
    assert!(confirmed_exposure("/.git/HEAD", b"ref: refs/heads/main\n"));
}

#[test]
fn raw_request_rejects_ambiguous_host_and_malformed_headers() {
    assert!(parse_raw_request(
        "GET / HTTP/1.1\r\nHost: a.test\r\nhost: b.test\r\n\r\n",
        "http"
    )
    .is_err());
    assert!(parse_raw_request(
        "GET / HTTP/1.1\r\nHost: a.test\r\n Invalid: x\r\n\r\n",
        "http"
    )
    .is_err());
    assert!(parse_raw_request("GET / HTTP/1.1\r\nHost: a.test\r\nBroken\r\n\r\n", "http").is_err());
    assert!(parse_raw_request("GET / HTTP/1.1\r\nHost: a.test\r\n\r\n", "http").is_ok());
}

#[test]
fn spider_finds_multiple_href_forms_without_script_noise() {
    let html = "<a href='one'>x</a><A HREF = \"/two\">x</A><link href=/three>\
                    <script>const s = \"<a href='bad'>\";</script>\
                    <!-- <a href='comment'> --><a data-x='href=wrong' href=/four>x</a>";
    assert_eq!(extract_hrefs(html), vec!["one", "/two", "/three", "/four"]);
}

#[test]
fn active_scans_require_acknowledgment() {
    assert!(require_authorization(false).is_err());
    assert!(require_authorization(true).is_ok());
}

#[test]
fn get_form_action_discovery_never_turns_post_into_get() {
    let html = "<form method='POST' action='/submit'></form>        <form action='/search' method='GET'></form>        <form action=/lookup></form>        <form method='dialog' action='/dialog'></form>        <script>const x = \"<form action='/fake'>\";</script>        <!-- <form action='/comment'> -->        <a href=/home>Home</a>";
    assert_eq!(extract_hrefs(html), vec!["/search", "/lookup", "/home"]);
}

#[tokio::test]
async fn spider_get_forms_reach_only_same_origin_without_post_submission() {
    use tokio::io::AsyncWriteExt;
    tokio::time::timeout(std::time::Duration::from_secs(9), async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let pages = [
            "/", "/safe", "/default"
        ];
        let server = tokio::spawn(async move {
            let mut visited = Vec::new();
            for _ in 0..pages.len() {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (head, _) =
                    crate::features::web::webtls::read_http_message(&mut stream).await.unwrap();
                assert!(head.starts_with("GET "), "{head}");
                let path = head.split_whitespace().nth(1).unwrap_or("").to_owned();
                visited.push(path.clone());
                let body = if path == "/" {
                    "<form action='/safe' method='GET'></form>                     <form method='post' action='/submit'></form>                     <form action=/default></form>                     <form action='http://outside.invalid/escape'></form>"
                } else { "" };
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                stream.write_all(response.as_bytes()).await.unwrap();
                stream.write_all(body.as_bytes()).await.unwrap();
            }
            visited
        });
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .redirect(reqwest::redirect::Policy::none()).no_proxy().build().unwrap();
        let urls = crawl_application::run_spider_with_progress(
            &client, format!("http://127.0.0.1:{port}/"), 3, true, &|_, _| {}
        ).await.unwrap();
        assert_eq!(urls.len(), 3, "{urls:?}");
        assert!(urls.iter().any(|u| u.ends_with("/safe")));
        assert!(urls.iter().any(|u| u.ends_with("/default")));
        assert!(!urls.iter().any(|u| u.contains("/submit") || u.contains("outside.invalid")));
        assert_eq!(server.await.unwrap(), vec!["/", "/safe", "/default"]);
    }).await.expect("same-origin GET form crawler fixture timed out");
}
