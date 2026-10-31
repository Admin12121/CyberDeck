//! Bounded outbound HTTP forwarding adapter for the interception proxy.
use super::client_infrastructure::http_client;
use super::proxy_policy_domain::is_hop_header_for_message;
use super::proxy_rules_domain::MAX_PROXY_BODY;

/// Forward a parsed request through the HTTP client; returns response parts.
pub(super) async fn execute_request(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let client = http_client();
    execute_request_with_client(&client, method, url, headers, body).await
}

/// Allow transport/TLS verification against a trusted localhost test server.
pub(super) async fn execute_request_with_client(
    client: &reqwest::Client,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let Ok(method_req) = reqwest::Method::from_bytes(method.as_bytes()) else {
        return (400, vec![], b"bad method".to_vec());
    };
    let mut request = client.request(method_req, url);
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("host")
            || name.eq_ignore_ascii_case("content-length")
            || is_hop_header_for_message(name, &headers)
        {
            continue;
        }
        request = request.header(name, value);
    }
    if !body.is_empty() {
        request = request.body(body.to_vec());
    }
    let Ok(resp) = request.send().await else {
        return (502, vec![], b"CyberDeck: upstream request failed".to_vec());
    };
    let status = resp.status().as_u16();
    let resp_headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("<binary>").to_string()))
        .collect();
    let mut response = resp;
    let mut bytes = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                if bytes.len().saturating_add(chunk.len()) > MAX_PROXY_BODY {
                    return (
                        502,
                        vec![],
                        b"CyberDeck: upstream response exceeds proxy body limit".to_vec(),
                    );
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => {
                return (
                    502,
                    vec![],
                    b"CyberDeck: upstream body read failed".to_vec(),
                )
            }
        }
    }
    (status, resp_headers, bytes)
}
