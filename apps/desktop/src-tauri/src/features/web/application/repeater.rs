//! Native HTTP Repeater. An editable UTF-8 draft is not an original network
//! capture. Binary bodies use a distinct typed request to avoid lossy replay.
use super::{http_client, is_hop_header_for_message, parse_raw_request, HttpResponseWire};
use std::time::Instant;

const MAX_BODY_BYTES: usize = 512 * 1024;

/// A logical HTTP message to replay, NOT byte-identical wire framing.
/// Headers and framing are normalized by the HTTP transport; body bytes are
/// forwarded unmodified, including non-UTF8, NULs and GET request bodies.
#[derive(Debug)]
pub(super) struct BinaryReplayRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Existing IPC compatibility: only an editable Unicode draft is accepted.
pub(super) async fn send(request_raw: String) -> Result<HttpResponseWire, String> {
    let (method, url, headers, body) = parse_raw_request(&request_raw, "http")?;
    send_binary(BinaryReplayRequest {
        method,
        url,
        headers,
        body: body.into_bytes(),
    })
    .await
}

/// Internal lossless-body replay. Do not advertise this as raw TCP/TLS bytes.
pub(super) async fn send_binary(request: BinaryReplayRequest) -> Result<HttpResponseWire, String> {
    if request.body.len() > MAX_BODY_BYTES {
        return Err("replay body exceeds 512 KiB limit".into());
    }
    let client = http_client();
    send_binary_with_client(&client, request).await
}

/// The check is a trusted backend-only case/consent authority. It is rerun
/// before dispatch, during header/body waits and on completion. Network
/// futures are dropped on revocation/expiry; remote bytes cannot be recalled.
pub(super) async fn send_binary_authorized(
    request: BinaryReplayRequest,
    authorize: &impl Fn() -> Result<(), String>,
) -> Result<HttpResponseWire, String> {
    let client = http_client();
    send_binary_authorized_with_client(&client, request, authorize).await
}

/// Use the exact pre-approved, pinned per-operation HTTP connector. No second
/// DNS lookup or shared connection pool can replace the authorized destination.
pub(super) async fn send_binary_authorized_with_client(
    client: &reqwest::Client,
    request: BinaryReplayRequest,
    authorize: &impl Fn() -> Result<(), String>,
) -> Result<HttpResponseWire, String> {
    send_binary_with_client_authorized(client, request, authorize).await
}

async fn await_authorized<T>(
    future: impl std::future::Future<Output = Result<T, String>>,
    authorize: &impl Fn() -> Result<(), String>,
) -> Result<T, String> {
    authorize()?;
    tokio::pin!(future);
    let mut ticker = tokio::time::interval(std::time::Duration::from_millis(100));
    loop {
        tokio::select! {
            biased;
            _ = ticker.tick() => authorize()?,
            result = &mut future => {
                authorize()?;
                return result;
            }
        }
    }
}

pub(super) async fn send_binary_with_client(
    client: &reqwest::Client,
    request: BinaryReplayRequest,
) -> Result<HttpResponseWire, String> {
    send_binary_with_client_authorized(client, request, &|| Ok(())).await
}

async fn send_binary_with_client_authorized(
    client: &reqwest::Client,
    request: BinaryReplayRequest,
    authorize: &impl Fn() -> Result<(), String>,
) -> Result<HttpResponseWire, String> {
    let method = reqwest::Method::from_bytes(request.method.as_bytes())
        .map_err(|e| format!("bad method: {e}"))?;
    let url = reqwest::Url::parse(&request.url).map_err(|e| format!("invalid replay URL: {e}"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("replay target must be HTTP(S) without URL credentials".into());
    }
    if request.body.len() > MAX_BODY_BYTES {
        return Err("replay body exceeds 512 KiB limit".into());
    }
    let mut builder = client.request(method, url.clone());
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("content-length")
            || is_hop_header_for_message(name, &request.headers)
        {
            continue;
        }
        builder = builder.header(name, value);
    }
    // Preserve any body regardless of method; GET/HEAD may carry one.
    // Supplying an empty body is intentional when the captured request had
    // Content-Length: 0; the transport may normalize this framing.
    if !request.body.is_empty() {
        builder = builder.body(request.body);
    }
    let started = Instant::now();
    let mut response = await_authorized(
        async {
            builder
                .send()
                .await
                .map_err(|_| "request failed".to_string())
        },
        authorize,
    )
    .await?;
    let status = response.status().as_u16();
    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("<binary>").to_string()))
        .collect();
    let size_hint = response
        .content_length()
        .unwrap_or(0)
        .min(usize::MAX as u64) as usize;
    let mut body_bytes = Vec::new();
    let mut truncated = false;
    while let Some(chunk) = await_authorized(
        async {
            response
                .chunk()
                .await
                .map_err(|_| "body read failed".to_string())
        },
        authorize,
    )
    .await?
    {
        let space = MAX_BODY_BYTES.saturating_sub(body_bytes.len());
        if chunk.len() > space {
            body_bytes.extend_from_slice(&chunk[..space]);
            truncated = true;
            break;
        }
        body_bytes.extend_from_slice(&chunk);
    }
    let size = if truncated {
        size_hint.max(body_bytes.len())
    } else {
        body_bytes.len()
    };
    use base64::Engine as _;
    let body_is_utf8 = std::str::from_utf8(&body_bytes).is_ok();
    // Legacy text field is for display only. Base64 is the exact binary body.
    let body_text = String::from_utf8_lossy(&body_bytes).to_string();
    let body_base64 = base64::engine::general_purpose::STANDARD.encode(&body_bytes);
    authorize()?;
    Ok(HttpResponseWire {
        status,
        headers,
        body: body_text,
        body_base64,
        body_is_utf8,
        body_truncated: truncated,
        size,
        duration_ms: started.elapsed().as_millis() as u64,
        url: url.to_string(),
    })
}

#[cfg(test)]
mod binary_replay_tests {
    use super::*;
    use base64::Engine as _;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn logical_replay_preserves_non_utf8_and_get_payload() {
        tokio::time::timeout(std::time::Duration::from_secs(8), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (head, payload) = crate::features::web::webtls::read_http_message(&mut stream)
                    .await
                    .unwrap();
                assert!(head.starts_with("GET /binary HTTP/1.1"), "{head}");
                assert_eq!(payload, [0xff, 0x00, 0x7f, 0x10]);
                stream
                    .write_all(
                        b"HTTP/1.1 201 Created\r\nContent-Length: 4\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .unwrap();
                stream.write_all(&[0xfe, 0x00, 0x12, 0x30]).await.unwrap();
            });
            let response = send_binary(BinaryReplayRequest {
                method: "GET".into(),
                url: format!("http://127.0.0.1:{port}/binary"),
                headers: vec![("Content-Type".into(), "application/octet-stream".into())],
                body: vec![0xff, 0x00, 0x7f, 0x10],
            })
            .await
            .unwrap();
            assert_eq!(response.status, 201);
            assert!(!response.body_is_utf8);
            assert_eq!(
                base64::engine::general_purpose::STANDARD
                    .decode(&response.body_base64)
                    .unwrap(),
                [0xfe, 0x00, 0x12, 0x30]
            );
            server.await.unwrap();
        })
        .await
        .expect("binary replay fixture timed out");
    }

    fn authorized(allowed: &std::sync::atomic::AtomicBool) -> Result<(), String> {
        if allowed.load(std::sync::atomic::Ordering::Acquire) {
            Ok(())
        } else {
            Err("HTTP replay authorization revoked".into())
        }
    }

    #[tokio::test]
    async fn revoked_before_dispatch_never_enters_network() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/no-dispatch", listener.local_addr().unwrap());
        let allowed = std::sync::atomic::AtomicBool::new(false);
        let result = send_binary_authorized(
            BinaryReplayRequest {
                method: "GET".into(),
                url,
                headers: vec![],
                body: vec![],
            },
            &|| authorized(&allowed),
        )
        .await;
        assert!(result.unwrap_err().contains("revoked"));
        // No socket can be accepted: authorization executes before send().
        let nonblocking =
            tokio::time::timeout(std::time::Duration::from_millis(25), listener.accept()).await;
        assert!(nonblocking.is_err());
    }

    #[tokio::test]
    async fn revoke_while_upstream_waits_for_headers_cancels_inflight() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use tokio::sync::oneshot;
        tokio::time::timeout(std::time::Duration::from_secs(7), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/pending", listener.local_addr().unwrap());
            let (seen_tx, seen_rx) = oneshot::channel();
            let (release_tx, release_rx) = oneshot::channel::<()>();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let (_, body) = crate::features::web::webtls::read_http_message(&mut stream)
                    .await
                    .unwrap();
                assert_eq!(body, [0xff, 0, 0x7f]);
                let _ = seen_tx.send(());
                let _ = release_rx.await;
            });
            let allowed = std::sync::Arc::new(AtomicBool::new(true));
            let state = allowed.clone();
            let job = tokio::spawn(async move {
                send_binary_authorized(
                    BinaryReplayRequest {
                        method: "POST".into(),
                        url,
                        headers: vec![],
                        body: vec![0xff, 0, 0x7f],
                    },
                    &|| authorized(&state),
                )
                .await
            });
            seen_rx.await.unwrap();
            allowed.store(false, Ordering::Release);
            let error = tokio::time::timeout(std::time::Duration::from_secs(2), job)
                .await
                .unwrap()
                .unwrap()
                .unwrap_err();
            assert!(error.contains("revoked"), "{error}");
            let _ = release_tx.send(());
            server.await.unwrap();
        })
        .await
        .expect("pending-header revocation fixture timed out");
    }

    #[tokio::test]
    async fn revoke_during_binary_response_stream_prevents_publication() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use tokio::sync::oneshot;
        tokio::time::timeout(std::time::Duration::from_secs(7), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/partial", listener.local_addr().unwrap());
            let (chunk_tx, chunk_rx) = oneshot::channel();
            let (release_tx, release_rx) = oneshot::channel::<()>();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let _ = crate::features::web::webtls::read_http_message(&mut stream).await.unwrap();
                stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\n").await.unwrap();
                stream.write_all(&[0xff, 0, 0x7f]).await.unwrap();
                stream.write_all(b"\r\n").await.unwrap();
                stream.flush().await.unwrap();
                let _ = chunk_tx.send(());
                let _ = release_rx.await;
            });
            let allowed = std::sync::Arc::new(AtomicBool::new(true));
            let state = allowed.clone();
            let job = tokio::spawn(async move {
                send_binary_authorized(BinaryReplayRequest {
                    method: "GET".into(), url, headers: vec![], body: vec![],
                }, &|| authorized(&state)).await
            });
            chunk_rx.await.unwrap();
            allowed.store(false, Ordering::Release);
            let error = tokio::time::timeout(std::time::Duration::from_secs(2), job)
                .await.unwrap().unwrap().unwrap_err();
            assert!(error.contains("revoked"), "{error}");
            let _ = release_tx.send(());
            server.await.unwrap();
        }).await.expect("partial-stream revocation fixture timed out");
    }

    #[tokio::test]
    async fn approved_pinned_hostname_replays_exact_binary_to_fixture() {
        tokio::time::timeout(std::time::Duration::from_secs(8), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let host = "private.replay.cyberdeck.test";
            let url = format!("http://{host}:{}/binary", addr.port());
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .resolve(host, addr)
                .build().unwrap();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let (headers, body) =
                    crate::features::web::webtls::read_http_message(&mut socket).await.unwrap();
                assert!(headers.starts_with("POST /binary HTTP/1.1"), "{headers}");
                assert!(headers.to_lowercase().contains(&format!(
                    "host: {host}:{}", addr.port()
                )), "{headers}");
                assert_eq!(body, [0xff, 0, 0x7f, 0x10]);
                socket.write_all(
                    b"HTTP/1.1 206 Partial Content\r\nContent-Length: 4\r\nConnection: close\r\n\r\n"
                ).await.unwrap();
                socket.write_all(&[0xfe, 0, 0x55, 0x40]).await.unwrap();
            });
            let response = send_binary_authorized_with_client(
                &client,
                BinaryReplayRequest {
                    method: "POST".into(),
                    url: url.clone(),
                    headers: vec![("Content-Type".into(), "application/octet-stream".into())],
                    body: vec![0xff, 0, 0x7f, 0x10],
                },
                &|| Ok(()),
            ).await.unwrap();
            assert_eq!(response.status, 206);
            assert_eq!(response.url, url);
            assert_eq!(
                base64::engine::general_purpose::STANDARD
                    .decode(&response.body_base64).unwrap(),
                [0xfe, 0, 0x55, 0x40]
            );
            server.await.unwrap();
        }).await.expect("pinned replay fixture timed out");
    }

    #[tokio::test]
    async fn oversized_replay_rejected_before_network() {
        let error = send_binary(BinaryReplayRequest {
            method: "POST".into(),
            url: "http://127.0.0.1:1/".into(),
            headers: Vec::new(),
            body: vec![0x42; MAX_BODY_BYTES + 1],
        })
        .await
        .unwrap_err();
        assert!(error.contains("512 KiB"));
    }
}
