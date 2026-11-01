//! Accepted HTTP connections, CONNECT tunnel negotiation, and TLS MITM.
//! Transport side effects stay separate from Tauri commands and domain rules.
use super::{
    apply_rules, execute_request, is_hop_header_for_message, is_websocket_switching_protocols,
    now_ms, parse_connect_target, parse_raw_request, push_capture, read_http_response_head,
    reason_phrase, relay_upgrade_rejection_body, relay_ws_counted, tls_host_matches, webhistory,
    websocket_accept_matches, CapturedRequest, PendingRequest, ProxyShared, ProxyStream,
    MAX_PENDING_REQUESTS,
};
use std::sync::{atomic::Ordering, Arc};
use std::time::Duration;
use tokio::net::TcpStream;

pub(super) async fn handle_conn(
    mut stream: TcpStream,
    shared: Arc<ProxyShared>,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    // Stamp before reading bytes: a case switch during a slow request body
    // must never attribute this connection to the newly selected case.
    let history_stamp = webhistory::capture_generation();
    let (head, body_bytes) = tokio::time::timeout(
        Duration::from_secs(15),
        crate::features::web::webtls::read_http_message(&mut stream),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "HTTP request timed out"))??;
    if head.starts_with("CONNECT ") {
        return connect_tunnel(stream, shared, &head, history_stamp).await;
    }
    // Headers are textual; bodies are arbitrary bytes and must never undergo
    // lossy UTF-8 decoding when forwarded or intercepted.
    let Ok((method, url, headers, _)) = parse_raw_request(&head, "http") else {
        return Ok(());
    };
    let Ok(parsed) = reqwest::Url::parse(&url) else {
        return Ok(());
    };
    if !matches!(parsed.scheme(), "http" | "https") {
        return Ok(());
    }
    let host = parsed.host_str().unwrap_or_default().to_string();
    let path = match parsed.query() {
        Some(query) => format!("{}?{query}", parsed.path()),
        None => parsed.path().to_string(),
    };
    let body = body_bytes;

    // interceptor holds the request (and the browser connection) until the
    // user forwards or drops it
    if shared.intercept.load(Ordering::Relaxed) {
        let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
        let info = CapturedRequest {
            id,
            method: method.clone(),
            host: host.clone(),
            path: path.clone(),
            status: 0,
            size: body.len(),
            at_ms: now_ms(),
        };
        let request = PendingRequest {
            stream: ProxyStream::Plain(stream),
            original_head: head.clone(),
            history_stamp,
            method,
            url,
            headers,
            body,
            info,
        };
        let rejected = {
            let mut pending = shared.pending.lock().expect("pending poisoned");
            if !shared.running.load(Ordering::Relaxed) || pending.len() >= MAX_PENDING_REQUESTS {
                Some(request)
            } else {
                pending.insert(id, request);
                None
            }
        };
        if let Some(mut rejected) = rejected {
            rejected.stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await?;
        }
        return Ok(());
    }

    // History must represent the browser's original request, not the
    // body/URL after match-and-replace rules have rewritten the upstream call.
    let original = webhistory::snapshot_original(history_stamp, &url, &body);
    let rules = shared.rules.lock().expect("rules poisoned").clone();
    let (method, url, headers, body) = apply_rules(method, url, headers, body, &rules);
    let forwarded = webhistory::snapshot_forwarded(history_stamp, &method, &url, &headers, &body);
    let (status, resp_headers, resp_body) = execute_request(&method, &url, &headers, &body).await;
    let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
    webhistory::capture_forwarded(
        history_stamp,
        id,
        original,
        &head,
        status,
        &resp_headers,
        &resp_body,
        forwarded,
    );
    push_capture(
        &shared,
        CapturedRequest {
            id,
            method,
            host,
            path,
            status,
            size: resp_body.len(),
            at_ms: now_ms(),
        },
    );

    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\n",
        reason = reason_phrase(status)
    );
    for (name, value) in &resp_headers {
        if name.eq_ignore_ascii_case("content-length")
            || is_hop_header_for_message(name, &resp_headers)
        {
            continue;
        }
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str(&format!(
        "content-length: {}\r\nconnection: close\r\n\r\n",
        resp_body.len()
    ));
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(&resp_body).await?;
    Ok(())
}

/// CONNECT tunnel: raw TCP passthrough when interception is off; full TLS
/// MITM (per-host leaf certs, rules, history, WS relay) when on.
pub(super) async fn connect_tunnel(
    stream: TcpStream,
    shared: Arc<ProxyShared>,
    head_text: &str,
    history_stamp: Option<u64>,
) -> std::io::Result<()> {
    connect_tunnel_with_ws_connector(stream, shared, head_text, history_stamp, None).await
}

/// A test-injected connector permits deterministic, fully authenticated WSS
/// localhost fixtures without replacing production root stores or bypassing
/// upstream TLS certificate validation.
pub(super) async fn connect_tunnel_with_ws_connector(
    mut stream: TcpStream,
    shared: Arc<ProxyShared>,
    head_text: &str,
    history_stamp: Option<u64>,
    ws_connector: Option<tokio_rustls::TlsConnector>,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let target = head_text.split_whitespace().nth(1).unwrap_or_default();
    let (host, port) = parse_connect_target(target)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let intercepting = shared.intercept.load(Ordering::Relaxed);
    let ca = shared.ca.lock().expect("ca poisoned").clone();

    if !intercepting || ca.is_none() {
        // honest passthrough: relay raw bytes to the upstream host
        let mut upstream = tokio::time::timeout(
            Duration::from_secs(15),
            TcpStream::connect((host.as_str(), port)),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream CONNECT timed out")
        })??;
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        // Preserve half-closes; select! previously discarded the other direction.
        tokio::io::copy_bidirectional(&mut stream, &mut upstream).await?;
        return Ok(());
    }

    let _ = stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await;
    let ca = ca.expect("ca checked");
    let acceptor = crate::features::web::webtls::tls_acceptor(&ca, &host)
        .map_err(|e| std::io::Error::other(e))?;
    let mut tls_stream = acceptor
        .accept(stream)
        .await
        .map_err(|e| std::io::Error::other(format!("tls handshake with client failed: {e}")))?;
    let (head_text, body_bytes) = tokio::time::timeout(
        Duration::from_secs(15),
        crate::features::web::webtls::read_http_message(&mut tls_stream),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "HTTPS request timed out"))??;
    let request_line = head_text.lines().next().unwrap_or_default().to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    let headers: Vec<(String, String)> = head_text
        .lines()
        .skip(1)
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    let body = body_bytes;

    // Refuse authority mismatches inside an authenticated CONNECT tunnel.
    if !path.starts_with('/') || path.starts_with("//") || !tls_host_matches(&headers, &host, port)
    {
        tls_stream
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            )
            .await?;
        return Ok(());
    }

    // Only treat a properly declared WebSocket upgrade as a raw duplex stream.
    if headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("upgrade") && v.eq_ignore_ascii_case("websocket"))
        && headers.iter().any(|(k, v)| {
            k.eq_ignore_ascii_case("connection")
                && v.split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
    {
        let tcp = tokio::time::timeout(
            Duration::from_secs(15),
            TcpStream::connect((host.as_str(), port)),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "ws upstream connect timed out",
            )
        })?
        .map_err(|e| std::io::Error::other(format!("ws upstream connect failed: {e}")))?;
        let connector = match ws_connector {
            Some(connector) => connector,
            None => crate::features::web::webtls::tls_client().map_err(std::io::Error::other)?,
        };
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|e| std::io::Error::other(format!("bad sni: {e}")))?;
        let mut upstream =
            tokio::time::timeout(Duration::from_secs(15), connector.connect(server_name, tcp))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "ws upstream tls timed out")
                })?
                .map_err(|e| std::io::Error::other(format!("ws upstream tls failed: {e}")))?;
        upstream.write_all(head_text.as_bytes()).await?;
        upstream.write_all(&body).await?;
        // A WebSocket session only exists after the upstream confirms 101.
        // Otherwise relay its ordinary response and do not record a WS session.
        let handshake = tokio::time::timeout(
            Duration::from_secs(15),
            read_http_response_head(&mut upstream),
        )
        .await
        .map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::TimedOut, "ws handshake timed out")
        })??;
        let declared_switch = is_websocket_switching_protocols(&handshake);
        let verified_switch = websocket_accept_matches(&head_text, &handshake);
        if declared_switch && !verified_switch {
            // Do not announce an authenticated upgrade or create a WS session
            // unless the upstream proves it saw the browser's nonce.
            tls_stream
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                )
                .await?;
            tls_stream.flush().await?;
            return Ok(());
        }
        tls_stream.write_all(handshake.as_bytes()).await?;
        tls_stream.flush().await?;
        if !verified_switch {
            tokio::time::timeout(
                Duration::from_secs(15),
                relay_upgrade_rejection_body(&handshake, &mut upstream, &mut tls_stream),
            )
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "ws upgrade rejection body timed out",
                )
            })??;
            return Ok(());
        }
        let (mut c_read, mut c_write) = tokio::io::split(tls_stream);
        let (mut u_read, mut u_write) = tokio::io::split(upstream);
        let started = now_ms();
        {
            let mut ws = shared.ws.lock().expect("ws poisoned");
            if ws.len() >= 1000 {
                ws.remove(0);
            }
            ws.push(crate::features::web::webtls::WsConnection {
                host: host.clone(),
                bytes_client_to_server: 0,
                bytes_server_to_client: 0,
                at_ms: started,
            });
        }
        // Record successfully forwarded bytes even if a TLS peer closes
        // without close_notify. tokio::io::copy would discard the byte
        // count when its final read returns UnexpectedEof.
        let (c2u, u2c) = tokio::join!(
            relay_ws_counted(&mut c_read, &mut u_write),
            relay_ws_counted(&mut u_read, &mut c_write)
        );
        let mut ws = shared.ws.lock().expect("ws poisoned");
        if let Some(record) = ws
            .iter_mut()
            .rev()
            .find(|w| w.at_ms == started && w.host == host)
        {
            record.bytes_client_to_server = c2u.0;
            record.bytes_server_to_client = u2c.0;
        }
        return Ok(());
    }

    // CONNECT interception must share the same Forward/Drop queue as HTTP.
    // Retain the authenticated TLS stream until the operator decides.
    let url = format!("https://{target}{path}");
    if shared.intercept.load(Ordering::Relaxed) {
        let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
        let info = CapturedRequest {
            id,
            method: method.clone(),
            host: host.clone(),
            path: path.clone(),
            status: 0,
            size: body.len(),
            at_ms: now_ms(),
        };
        let request = PendingRequest {
            stream: ProxyStream::Tls(tls_stream),
            original_head: head_text.clone(),
            history_stamp,
            method,
            url,
            headers,
            body,
            info,
        };
        let rejected = {
            let mut pending = shared.pending.lock().expect("pending poisoned");
            if !shared.running.load(Ordering::Relaxed) || pending.len() >= MAX_PENDING_REQUESTS {
                Some(request)
            } else {
                pending.insert(id, request);
                None
            }
        };
        if let Some(mut rejected) = rejected {
            rejected.stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await?;
        }
        return Ok(());
    }

    // Preserve the unmodified browser request before any rewrite rules.
    let original = webhistory::snapshot_original(history_stamp, &url, &body);
    // plain HTTP inside TLS: same rules + capture path as plain proxying
    let rules = shared.rules.lock().expect("rules poisoned").clone();
    let (r_method, r_url, r_headers, r_body) =
        apply_rules(method.clone(), url, headers, body, &rules);
    let forwarded =
        webhistory::snapshot_forwarded(history_stamp, &r_method, &r_url, &r_headers, &r_body);
    let (status, resp_headers, resp_body) =
        execute_request(&r_method, &r_url, &r_headers, &r_body).await;
    let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
    webhistory::capture_forwarded(
        history_stamp,
        id,
        original,
        &head_text,
        status,
        &resp_headers,
        &resp_body,
        forwarded,
    );
    push_capture(
        &shared,
        CapturedRequest {
            id,
            method: r_method,
            host: host.clone(),
            path: path.clone(),
            status,
            size: resp_body.len(),
            at_ms: now_ms(),
        },
    );
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\n",
        reason = reason_phrase(status)
    );
    for (name, value) in &resp_headers {
        if name.eq_ignore_ascii_case("content-length")
            || is_hop_header_for_message(name, &resp_headers)
        {
            continue;
        }
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    response.push_str(&format!(
        "content-length: {}\r\nconnection: close\r\n\r\n",
        resp_body.len()
    ));
    tls_stream.write_all(response.as_bytes()).await?;
    tls_stream.write_all(&resp_body).await?;
    tls_stream.flush().await?;
    Ok(())
}
