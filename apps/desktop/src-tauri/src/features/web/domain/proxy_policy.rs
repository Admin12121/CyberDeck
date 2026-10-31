//! Pure CONNECT authority and HTTP hop-by-hop security policy.

/// CONNECT authority must contain an explicit valid TCP port. Splitting on
/// the first colon is incorrect for bracketed IPv6 literals.
pub(super) fn parse_connect_target(authority: &str) -> Result<(String, u16), String> {
    let (raw_host, raw_port) = authority
        .rsplit_once(':')
        .ok_or("CONNECT target must include host:port")?;
    let port = raw_port
        .parse::<u16>()
        .map_err(|_| "invalid CONNECT port")?;
    if port == 0 {
        return Err("CONNECT port must not be zero".to_string());
    }
    let host = if raw_host.starts_with('[') && raw_host.ends_with(']') {
        let inner = &raw_host[1..raw_host.len() - 1];
        inner
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| "invalid CONNECT IPv6 literal")?;
        inner.to_string()
    } else {
        if raw_host.contains(':') {
            return Err("IPv6 CONNECT host must be bracketed".to_string());
        }
        raw_host.to_string()
    };
    if host.is_empty() || host.chars().any(|c| matches!(c, '/' | '@' | '#' | '?')) {
        return Err("invalid CONNECT hostname".to_string());
    }
    let url = reqwest::Url::parse(&format!("https://{authority}/"))
        .map_err(|_| "invalid CONNECT authority")?;
    if !url.username().is_empty() || url.password().is_some() || url.host_str().is_none() {
        return Err("invalid CONNECT authority".to_string());
    }
    Ok((host, port))
}

/// Match the inner Host authority against the CONNECT destination. Without
/// this guard a TLS tunnel for one hostname could proxy an unrelated origin.
pub(super) fn tls_host_matches(headers: &[(String, String)], host: &str, port: u16) -> bool {
    // Reject duplicate Host headers without allocating a temporary Vec.
    let mut hosts = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.as_str());
    let Some(authority) = hosts.next() else {
        return false;
    };
    if hosts.next().is_some() {
        return false;
    }
    let authority = authority.trim();
    if authority
        .chars()
        .any(|c| matches!(c, '/' | '@' | '#' | '?' | ' ' | '\t' | '\r' | '\n'))
    {
        return false;
    }
    let Ok(url) = reqwest::Url::parse(&format!("https://{authority}/")) else {
        return false;
    };
    let Some(actual_host) = url.host_str() else {
        return false;
    };
    actual_host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .eq_ignore_ascii_case(host)
        && url.port_or_known_default() == Some(port)
}

pub(super) fn is_hop_header(name: &str) -> bool {
    [
        "connection",
        "proxy-connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "proxy-authorization",
        "proxy-authenticate",
    ]
    .iter()
    .any(|header| name.eq_ignore_ascii_case(header))
}

/// Strip both standard hop-by-hop headers and names nominated by Connection.
pub(super) fn is_hop_header_for_message(name: &str, headers: &[(String, String)]) -> bool {
    is_hop_header(name)
        || headers
            .iter()
            .filter(|(key, _)| {
                key.eq_ignore_ascii_case("connection")
                    || key.eq_ignore_ascii_case("proxy-connection")
            })
            .any(|(_, value)| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case(name))
            })
}
