//! Parse and validate outbound HTTP request messages used by Repeater.
//! Pure input normalization; no network operations or Tauri state.

/// Parse a raw HTTP request into (method, url, headers, body). The Host or
/// absolute-URI supplies the target; scheme defaults to http.
pub fn parse_raw_request(
    raw: &str,
    scheme: &str,
) -> Result<(String, String, Vec<(String, String)>, String), String> {
    let (head, body) = match raw.split_once("\r\n\r\n") {
        Some((h, b)) => (h, b.to_string()),
        None if raw.contains("\n\n") => {
            let (h, b) = raw.split_once("\n\n").unwrap();
            (h, b.to_string())
        }
        None => (raw, String::new()),
    };
    let mut lines = head.lines();
    let request_line = lines.next().ok_or("empty request")?.trim().to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or("missing method")?.to_uppercase();
    let target = parts.next().ok_or("missing path")?.to_string();
    if reqwest::Method::from_bytes(method.as_bytes()).is_err() {
        return Err("invalid HTTP request method".to_string());
    }
    if parts.next().is_none() || parts.next().is_some() {
        return Err("invalid HTTP request line".to_string());
    }
    let mut host = String::new();
    let mut headers = Vec::new();
    for line in lines {
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err("folded HTTP headers are unsupported".to_string());
        }
        let (name, value) = line.split_once(':').ok_or("malformed HTTP header")?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        {
            return Err("invalid HTTP header name".to_string());
        }
        let value = value.trim().to_string();
        if name.eq_ignore_ascii_case("host") {
            if !host.is_empty() {
                return Err("duplicate Host header".to_string());
            }
            host = value.clone();
        }
        headers.push((name.to_string(), value));
    }
    let url = if target.starts_with("http://") || target.starts_with("https://") {
        target
    } else if !host.is_empty() && target.starts_with('/') {
        format!("{scheme}://{host}{target}")
    } else {
        return Err("request needs a Host and origin-form path or absolute URL".to_string());
    };
    let parsed = reqwest::Url::parse(&url).map_err(|e| format!("invalid request URL: {e}"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err("request target must be HTTP(S) without URL credentials".to_string());
    }
    Ok((method, url, headers, body))
}
