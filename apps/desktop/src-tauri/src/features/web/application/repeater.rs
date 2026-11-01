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

pub(super) async fn send_binary_with_client(
    client: &reqwest::Client,
    request: BinaryReplayRequest,
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
    let mut response = builder
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
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
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("body read failed: {e}"))?
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
