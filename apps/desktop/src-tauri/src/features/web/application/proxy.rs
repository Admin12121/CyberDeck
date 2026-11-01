//! Native proxy lifecycle, bounded capture, and held-request decisions.
use super::{
    apply_rules, execute_request, handle_conn, is_hop_header_for_message, webhistory,
    CapturedRequest, MatchReplaceRule, PendingWire, ProxyShared, ProxyStatusWire, WebCtx,
    WsConnectionWire, MAX_CAPTURED_REQUESTS,
};
use std::net::SocketAddr;
use std::sync::{atomic::Ordering, Arc};
use std::time::Duration;

/// Start the local interception proxy on 127.0.0.1:port. Plain-HTTP requests
/// are captured and forwarded (or held when interception is on); CONNECT
/// tunnels pass through without interception until the CA arc lands.
pub(super) async fn start_proxy(
    port: u16,
    ctx: &WebCtx,
    ca_dir: &std::path::Path,
) -> Result<ProxyStatusWire, String> {
    if port == 0 {
        return Err("proxy port must be between 1 and 65535".to_string());
    }
    if ctx.shared.running.load(Ordering::Relaxed) {
        return Err("proxy already running; stop it first".to_string());
    }
    // Starting a new proxy session cannot inherit sensitive captures/consent.
    webhistory::clear_session();
    // CA is initialized with the proxy so HTTPS interception is ready at once.
    let ca = crate::features::web::webtls::init_ca(ca_dir)?;
    *ctx.shared.ca.lock().expect("ca poisoned") = Some(Arc::clone(&ca));
    *ctx.ca.lock().expect("ca poisoned") = Some(ca);
    let addr: SocketAddr = format!("127.0.0.1:{port}")
        .parse()
        .map_err(|e| format!("bad port: {e}"))?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("cannot bind 127.0.0.1:{port}: {e}"))?;
    ctx.shared.running.store(true, Ordering::Relaxed);
    ctx.shared.port.store(port, Ordering::Relaxed);
    ctx.proxy_running.store(true, Ordering::Relaxed);
    ctx.proxy_port.store(port, Ordering::Relaxed);
    let shared = Arc::clone(&ctx.shared);
    // Long-lived WebSocket/CONNECT sessions otherwise create unbounded tasks.
    const MAX_ACTIVE_CONNECTIONS: usize = 256;
    let connection_slots = Arc::new(tokio::sync::Semaphore::new(MAX_ACTIVE_CONNECTIONS));
    let handle = tokio::spawn(async move {
        let mut expiry = tokio::time::interval(Duration::from_secs(5));
        let mut shutdown_check = tokio::time::interval(Duration::from_millis(100));
        // Own every accepted task. Dropping only the listener must never
        // leave established CONNECT / WebSocket tunnels behind.
        let mut connections = tokio::task::JoinSet::new();
        loop {
            if !shared.running.load(Ordering::Relaxed) {
                break;
            }
            tokio::select! {
                _ = shutdown_check.tick() => {}
                _ = connections.join_next(), if !connections.is_empty() => {}
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { continue };
                    let Ok(slot) = Arc::clone(&connection_slots).try_acquire_owned() else {
                        // A full connection budget fails closed; dropping the
                        // socket avoids an unbounded task per rejected client.
                        continue;
                    };
                    let shared = Arc::clone(&shared);
                    connections.spawn(async move {
                        let _slot = slot;
                        let _ = handle_conn(stream, shared).await;
                    });
                }
                _ = expiry.tick() => {
                    let expired = {
                        let mut pending = shared.pending.lock().expect("pending poisoned");
                        let now = now_ms();
                        let ids: Vec<u64> = pending.iter()
                            .filter(|(_, entry)| now.saturating_sub(entry.info.at_ms) > 120_000)
                            .map(|(id, _)| *id).collect();
                        ids.into_iter().filter_map(|id| pending.remove(&id)).collect::<Vec<_>>()
                    };
                    for mut request in expired {
                        let _ = request.stream.write_all(
                            b"HTTP/1.1 408 Request Timeout\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                        ).await;
                    }
                }
            }
        }
        // Complete cancellation before proxy_stop may return. Active sockets
        // are released even when a peer holds a tunnel open indefinitely.
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    });
    *ctx.proxy_handle.lock().expect("proxy handle poisoned") = Some(handle);
    Ok(ProxyStatusWire {
        running: true,
        port,
        captured: ctx.shared.captured.lock().expect("captured poisoned").len(),
    })
}

pub(super) fn push_capture(shared: &ProxyShared, mut request: CapturedRequest) {
    // Summary history is visible without revealing full capture data.
    // A query string may contain passwords, API keys or access tokens.
    if let Some((path, _)) = request.path.split_once('?') {
        request.path = format!("{path}?[query withheld]");
    }
    let mut captured = shared.captured.lock().expect("captured poisoned");
    if captured.len() >= MAX_CAPTURED_REQUESTS {
        let remove = captured.len() - MAX_CAPTURED_REQUESTS + 1;
        captured.drain(0..remove);
    }
    captured.push(request);
}

pub(super) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(super) fn reason_phrase(status: u16) -> &'static str {
    reqwest::StatusCode::from_u16(status)
        .ok()
        .and_then(|status| status.canonical_reason())
        .unwrap_or("Unknown")
}

pub(super) async fn stop_proxy(ctx: &WebCtx) -> Result<ProxyStatusWire, String> {
    webhistory::clear_session();
    ctx.proxy_running.store(false, Ordering::Relaxed);
    let held = {
        let mut pending = ctx.shared.pending.lock().expect("pending poisoned");
        // Queue insertion checks running under this same mutex, so no new
        // request can be held after the queue is drained on shutdown.
        ctx.shared.running.store(false, Ordering::Relaxed);
        std::mem::take(&mut *pending)
    };
    // Pending peers can stop reading. Notify with a bounded deadline in
    // parallel so one blocked TLS socket does not stall the entire shutdown.
    let mut notifications = tokio::task::JoinSet::new();
    for (_, mut request) in held {
        notifications.spawn(async move {
            let _ = tokio::time::timeout(
                Duration::from_secs(1),
                request.stream.write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                ),
            ).await;
        });
    }
    while notifications.join_next().await.is_some() {}
    let listener = ctx
        .proxy_handle
        .lock()
        .expect("proxy handle poisoned")
        .take();
    if let Some(mut handle) = listener {
        // Shutdown includes child cancellation and joins. An unresponsive
        // listener is forcibly aborted and reported, not silently accepted.
        if tokio::time::timeout(Duration::from_secs(3), &mut handle)
            .await
            .is_err()
        {
            handle.abort();
            let _ = handle.await;
            return Err("proxy listener shutdown timed out".to_string());
        }
    }
    Ok(proxy_status_inner(&ctx))
}

pub(super) fn proxy_status_inner(ctx: &WebCtx) -> ProxyStatusWire {
    ProxyStatusWire {
        running: ctx.shared.running.load(Ordering::Relaxed),
        port: ctx.shared.port.load(Ordering::Relaxed),
        captured: ctx.shared.captured.lock().expect("captured poisoned").len(),
    }
}

async fn wait_until_stopped(shared: &ProxyShared) {
    while shared.running.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Forward a held request: applies match-and-replace, executes, writes the
/// real response back to the waiting browser, and records it in history.
pub(super) async fn forward(id: u64, ctx: &WebCtx) -> Result<u16, String> {
    let pending = ctx
        .shared
        .pending
        .lock()
        .expect("pending poisoned")
        .remove(&id);
    let Some(pending) = pending else {
        return Err("request no longer pending (browser timeout)".to_string());
    };
    let original =
        webhistory::snapshot_original(pending.history_stamp, &pending.url, &pending.body);
    let rules = ctx.shared.rules.lock().expect("rules poisoned").clone();
    let (method, url, headers, body) = apply_rules(
        pending.method,
        pending.url,
        pending.headers,
        pending.body,
        &rules,
    );
    let history_stamp = pending.history_stamp;
    let forwarded = webhistory::snapshot_forwarded(history_stamp, &method, &url, &headers, &body);
    let mut stream = pending.stream;
    if !ctx.shared.running.load(Ordering::Acquire) {
        return Err("proxy stopped before forwarding".to_string());
    }
    let (status, resp_headers, resp_body) = tokio::select! {
        result = execute_request(&method, &url, &headers, &body) => result,
        _ = wait_until_stopped(&ctx.shared) => {
            return Err("proxy stopped during forwarding".to_string());
        }
    };
    if !ctx.shared.running.load(Ordering::Acquire) {
        return Err("proxy stopped during forwarding".to_string());
    }
    webhistory::capture_forwarded(
        history_stamp,
        id,
        original,
        &pending.original_head,
        status,
        &resp_headers,
        &resp_body,
        forwarded,
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
    tokio::time::timeout(Duration::from_secs(10), async {
        stream.write_all(response.as_bytes()).await?;
        stream.write_all(&resp_body).await
    })
    .await
    .map_err(|_| "proxy forward response write timed out".to_string())?
    .map_err(|e| format!("proxy forward response write failed: {e}"))?;
    if !ctx.shared.running.load(Ordering::Acquire) {
        return Err("proxy stopped during forwarding".to_string());
    }
    push_capture(
        &ctx.shared,
        CapturedRequest {
            id,
            method,
            host: pending.info.host,
            path: pending.info.path,
            status,
            size: resp_body.len(),
            at_ms: now_ms(),
        },
    );
    Ok(status)
}

pub(super) async fn drop_pending(id: u64, ctx: &WebCtx) -> Result<(), String> {
    let pending = ctx
        .shared
        .pending
        .lock()
        .expect("pending poisoned")
        .remove(&id);
    if let Some(mut pending) = pending {
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            pending.stream.write_all(
                b"HTTP/1.1 502 CyberDeck: request dropped by interceptor\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            ),
        ).await;
    }
    Ok(())
}

pub(super) fn list_pending(ctx: &WebCtx) -> Vec<PendingWire> {
    ctx.shared
        .pending
        .lock()
        .expect("pending poisoned")
        .values()
        .map(|p| PendingWire {
            id: p.info.id,
            method: p.method.clone(),
            url: p.url.clone(),
            host: p.info.host.clone(),
            path: p.info.path.clone(),
            // POST/JSON/form bodies may contain credentials; never preview them
            // without a separate explicit sensitive-data reveal action.
            body_preview: format!("[request body withheld: {} bytes]", p.body.len()),
        })
        .collect()
}

/// Replace the match-and-replace rule list.
pub(super) fn replace_rules(rules: Vec<MatchReplaceRule>, ctx: &WebCtx) -> usize {
    let mut current = ctx.shared.rules.lock().expect("rules poisoned");
    *current = rules;
    current.len()
}

pub(super) fn list_ws(ctx: &WebCtx) -> Vec<WsConnectionWire> {
    ctx.shared
        .ws
        .lock()
        .expect("ws poisoned")
        .iter()
        .map(|w| WsConnectionWire {
            host: w.host.clone(),
            bytes_client_to_server: w.bytes_client_to_server,
            bytes_server_to_client: w.bytes_server_to_client,
            at_ms: w.at_ms,
        })
        .collect()
}
