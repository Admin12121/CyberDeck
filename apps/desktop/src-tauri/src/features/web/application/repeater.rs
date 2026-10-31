//! Native HTTP Repeater execution with bounded binary response capture.
use super::{http_client, is_hop_header_for_message, parse_raw_request, HttpResponseWire};
use std::time::Instant;
const MAX_BODY_BYTES: usize = 512 * 1024;

/// Send an editable raw request (Repeater). Real network call, no mocks.
pub(super) async fn send(request_raw: String) -> Result<HttpResponseWire, String> {
    let (method, url, headers, body) = parse_raw_request(&request_raw, "http")?;
    let client = http_client();
    let method_req =
        reqwest::Method::from_bytes(method.as_bytes()).map_err(|e| format!("bad method: {e}"))?;
    let mut request = client.request(method_req, &url);
    for (name, value) in &headers {
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("content-length")
            || is_hop_header_for_message(name, &headers)
        {
            continue;
        }
        request = request.header(name, value);
    }
    if !body.is_empty() && !matches!(method.as_str(), "GET" | "HEAD") {
        // The parsed body is no longer needed: move it into reqwest rather than cloning.
        request = request.body(body);
    }
    let started = Instant::now();
    let mut response = request
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    let status = response.status().as_u16();
    let resp_headers: Vec<(String, String)> = response
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
    let body_text = String::from_utf8_lossy(&body_bytes).to_string();
    let body_is_utf8 = std::str::from_utf8(&body_bytes).is_ok();
    let body_base64 = base64::engine::general_purpose::STANDARD.encode(&body_bytes);
    Ok(HttpResponseWire {
        status,
        headers: resp_headers,
        body: body_text,
        body_base64,
        body_is_utf8,
        body_truncated: truncated,
        size,
        duration_ms: started.elapsed().as_millis() as u64,
        url,
    })
}
