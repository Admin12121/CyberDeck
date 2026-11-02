//! Strict single-origin DNS scope, pinned at the HTTP connector.
//! Only loopback/private IPs are allowed pending backend-owned public-target grants.
use super::auth_context_application::AuthContext;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

const MAX_DNS_ANSWERS: usize = 16;

pub(super) struct PinnedTarget {
    pub url: reqwest::Url,
    pub client: reqwest::Client,
    pub sockets: Vec<SocketAddr>,
}

pub(super) fn private_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => !v4.is_unspecified() && (v4.is_loopback() || v4.is_private()),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return private_address(IpAddr::V4(mapped));
            }
            !v6.is_unspecified() && (v6.is_loopback() || v6.is_unique_local())
        }
    }
}

pub(super) fn parse_target(text: &str) -> Result<reqwest::Url, String> {
    if text.len() > 4096 {
        return Err("Web target exceeds 4096-byte limit".into());
    }
    let url = reqwest::Url::parse(text.trim()).map_err(|_| "invalid Web target URL")?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default().is_none()
    {
        return Err("target must be HTTP(S) without embedded credentials".into());
    }
    Ok(url)
}

/// Require *every* resolved result to be in scope, not only the first.
pub(super) fn vetted_answers(
    answers: impl IntoIterator<Item = SocketAddr>,
) -> Result<Vec<SocketAddr>, String> {
    let mut out = Vec::new();
    for socket in answers {
        if !private_address(socket.ip()) {
            return Err("DNS resolved to an out-of-scope address".into());
        }
        if out.len() >= MAX_DNS_ANSWERS {
            return Err("DNS answer limit exceeded".into());
        }
        if !out.contains(&socket) {
            out.push(socket);
        }
    }
    if out.is_empty() {
        return Err("DNS returned no addresses".into());
    }
    Ok(out)
}

fn configured_client(
    host: &str,
    sockets: &[SocketAddr],
    auth: &AuthContext,
) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .user_agent("CyberDeck-Workbench/0.1");
    // Keep the URL authority, TLS SNI and Host header unchanged while
    // replacing the connector's DNS answers with the already-validated set.
    if host.parse::<IpAddr>().is_err() {
        builder = builder.resolve_to_addrs(host, sockets);
    }
    if !auth.is_empty() {
        // Default headers apply to every request this pinned client makes.
        builder = builder.default_headers(auth.header_map());
    }
    builder
        .build()
        .map_err(|_| "failed to create scoped Web client".into())
}

/// DNS resolves once, BEFORE native confirmation, and the approved concrete
/// socket addresses are pinned into a fresh per-operation reqwest client.
/// No shared pooled transport or auto redirects can re-resolve the hostname.
pub(super) async fn prepare_private_target(text: &str) -> Result<PinnedTarget, String> {
    prepare_private_target_with_auth(text, &AuthContext::default()).await
}

/// Same single-origin pinned transport, with volatile operator session
/// context attached once as client default headers. Values never enter a
/// URL, history entry, job snapshot, error or finding.
pub(super) async fn prepare_private_target_with_auth(
    text: &str,
    auth: &AuthContext,
) -> Result<PinnedTarget, String> {
    let url = parse_target(text)?;
    let host = url.host_str().ok_or("Web hostname missing")?;
    let normalized = host.trim_start_matches('[').trim_end_matches(']');
    let port = url.port_or_known_default().ok_or("Web port missing")?;
    let addresses = match normalized.parse::<IpAddr>() {
        Ok(ip) => vetted_answers([SocketAddr::new(ip, port)])?,
        Err(_) => {
            let lookup = tokio::time::timeout(
                Duration::from_secs(3),
                tokio::net::lookup_host((normalized, port)),
            )
            .await
            .map_err(|_| "DNS resolution timed out")?
            .map_err(|_| "DNS resolution failed")?;
            vetted_answers(lookup)?
        }
    };
    let client = configured_client(normalized, &addresses, auth)?;
    Ok(PinnedTarget {
        url,
        client,
        sockets: addresses,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn dns_answers_reject_rebinding_metadata_and_unscoped_ips() {
        let allowed = "127.0.0.1:8080".parse::<SocketAddr>().unwrap();
        for bad in [
            "169.254.169.254:8080",
            "8.8.8.8:8080",
            "0.0.0.0:8080",
            "[fe80::1]:8080",
            "[::ffff:169.254.169.254]:8080",
            "[::]:8080",
            "224.0.0.1:8080",
        ] {
            let bad = bad.parse::<SocketAddr>().unwrap();
            assert!(vetted_answers([allowed, bad]).is_err(), "{bad}");
            assert!(vetted_answers([bad, allowed]).is_err(), "{bad}");
        }
        assert!(vetted_answers([allowed]).is_ok());
        assert!(vetted_answers(["[::1]:8080".parse().unwrap()]).is_ok());
        assert!(vetted_answers(["[fd00::9]:8080".parse().unwrap()]).is_ok());
        assert!(vetted_answers(["[::ffff:127.0.0.1]:8080".parse().unwrap()]).is_ok());
        assert!(vetted_answers(std::iter::empty()).is_err());
        assert!(vetted_answers(std::iter::repeat(allowed).take(MAX_DNS_ANSWERS + 1)).is_ok());
        // deduplicated answers
    }

    #[tokio::test]
    async fn pinned_client_attaches_operator_session_context() {
        tokio::time::timeout(Duration::from_secs(6), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let host = "session.cyberdeck.test";
            let url = format!("http://{host}:{port}/fixture");
            let sockets = vetted_answers([listener.local_addr().unwrap()]).unwrap();
            let auth = AuthContext::new(
                Some("sid=abc123; theme=dark"),
                &[("X-Lab-Role".to_string(), "operator".to_string())],
            )
            .unwrap();
            let client = configured_client(host, &sockets, &auth).unwrap();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let (head, _) = crate::features::web::webtls::read_http_message(&mut socket)
                    .await
                    .unwrap();
                let lowered = head.to_ascii_lowercase();
                assert!(lowered.contains("cookie: sid=abc123; theme=dark"), "{head}");
                assert!(lowered.contains("x-lab-role: operator"), "{head}");
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .unwrap();
            });
            let resp = client.get(url).send().await.unwrap();
            assert_eq!(resp.status(), reqwest::StatusCode::OK);
            assert_eq!(resp.bytes().await.unwrap().as_ref(), b"ok");
            server.await.unwrap();
        })
        .await
        .expect("session fixture timed out");
    }

    #[tokio::test]
    async fn pinned_unresolvable_hostname_uses_validated_socket_and_host_header() {
        tokio::time::timeout(Duration::from_secs(6), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let host = "nonexistent.cyberdeck.test";
            let url = format!("http://{host}:{port}/fixture");
            let sockets = vetted_answers([listener.local_addr().unwrap()]).unwrap();
            let client = configured_client(host, &sockets, &AuthContext::default()).unwrap();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let (head, _) = crate::features::web::webtls::read_http_message(&mut socket)
                    .await
                    .unwrap();
                assert!(
                    head.contains(&format!("host: {host}:{port}"))
                        || head.contains(&format!("Host: {host}:{port}")),
                    "{head}"
                );
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await
                    .unwrap();
            });
            let resp = client.get(url).send().await.unwrap();
            assert_eq!(resp.status(), reqwest::StatusCode::OK);
            assert_eq!(resp.bytes().await.unwrap().as_ref(), b"ok");
            server.await.unwrap();
        })
        .await
        .expect("pinned DNS fixture timed out");
    }
}
