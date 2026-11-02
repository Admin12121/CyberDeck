//! SPDX-License-Identifier: MIT
//! Volatile operator-supplied authenticated session context.
//!
//! The values exist only for the lifetime of one authorized assessment:
//! they are never written to a case, HTTP history, job snapshot, finding,
//! error string or log. There is intentionally no Debug implementation.
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, COOKIE};

pub(super) const MAX_HEADERS: usize = 8;
const MAX_COOKIE_BYTES: usize = 4096;
const MAX_NAME_BYTES: usize = 64;
const MAX_VALUE_BYTES: usize = 1024;

/// Headers that would change message framing, routing or connection
/// semantics. Session context may add credentials and policy headers; it can
/// never retarget the approved request or desynchronize its body framing.
const FORBIDDEN: &[&str] = &[
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "expect",
    "upgrade",
    "te",
    "trailer",
    "proxy-authorization",
    "proxy-connection",
];

#[derive(Clone, Default)]
pub(super) struct AuthContext {
    cookie: Option<HeaderValue>,
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl AuthContext {
    /// Validates and freezes operator input. Every rejection message is
    /// static: it never echoes a header name or value.
    pub(super) fn new(
        cookies: Option<&str>,
        headers: &[(String, String)],
    ) -> Result<Self, String> {
        if headers.len() > MAX_HEADERS {
            return Err(format!(
                "at most {MAX_HEADERS} session headers are supported"
            ));
        }
        let cookie = match cookies.map(str::trim).filter(|value| !value.is_empty()) {
            None => None,
            Some(value) => {
                if value.len() > MAX_COOKIE_BYTES {
                    return Err("session cookie exceeds the 4096-byte limit".into());
                }
                if value
                    .bytes()
                    .any(|byte| byte == b'\r' || byte == b'\n' || byte == 0)
                {
                    return Err("session cookie contains an invalid control character".into());
                }
                Some(
                    HeaderValue::from_str(value)
                        .map_err(|_| "session cookie is not a valid header value".to_string())?,
                )
            }
        };
        let mut parsed: Vec<(HeaderName, HeaderValue)> = Vec::new();
        for (name, value) in headers {
            let name = name.trim();
            if name.is_empty() {
                return Err("session header name is required".into());
            }
            if name.len() > MAX_NAME_BYTES {
                return Err("session header name exceeds the 64-byte limit".into());
            }
            if value.len() > MAX_VALUE_BYTES {
                return Err("session header value exceeds the 1024-byte limit".into());
            }
            let lowered = name.to_ascii_lowercase();
            if FORBIDDEN.contains(&lowered.as_str()) {
                return Err("session header may not change routing or message framing".into());
            }
            if lowered == "cookie" {
                return Err("use the session cookie field instead of a Cookie header".into());
            }
            let header_name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| "session header name is not a valid HTTP token".to_string())?;
            if parsed
                .iter()
                .any(|(existing, _)| *existing == header_name)
            {
                return Err("duplicate session header".into());
            }
            let header_value = HeaderValue::from_str(value).map_err(|_| {
                "session header value is not a valid HTTP header value".to_string()
            })?;
            if header_value.is_empty() {
                return Err("session header value is required".into());
            }
            parsed.push((header_name, header_value));
        }
        Ok(Self {
            cookie,
            headers: parsed,
        })
    }

    pub(super) fn is_empty(&self) -> bool {
        self.cookie.is_none() && self.headers.is_empty()
    }

    /// Applied once as client default headers, so every scanner, crawler and
    /// parameter probe inherits the same validated context automatically.
    pub(super) fn header_map(&self) -> HeaderMap {
        let mut map = HeaderMap::new();
        if let Some(cookie) = &self.cookie {
            map.insert(COOKIE, cookie.clone());
        }
        for (name, value) in &self.headers {
            map.insert(name.clone(), value.clone());
        }
        map
    }

    /// Dialog-safe phrase. Never contains a header name or value.
    pub(super) fn summary(&self) -> &'static str {
        match (self.cookie.is_some(), self.headers.is_empty()) {
            (false, true) => "",
            (true, true) => " with an operator-supplied session cookie",
            (false, false) => " with operator-supplied session headers",
            (true, false) => " with an operator-supplied session cookie and headers",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str, value: &str) -> (String, String) {
        (name.to_string(), value.to_string())
    }

    #[test]
    fn rejects_injection_framing_and_oversized_values() {
        assert!(AuthContext::new(Some("sid=1"), &[]).is_ok());
        assert!(AuthContext::new(Some("sid=1\r\nX-Evil: 1"), &[]).is_err());
        assert!(AuthContext::new(Some("sid=1\nX-Evil: 1"), &[]).is_err());
        for forbidden in [
            "Host",
            "Content-Length",
            "Transfer-Encoding",
            "Connection",
            "Expect",
            "Upgrade",
            "TE",
            "Trailer",
            "Proxy-Authorization",
        ] {
            assert!(
                AuthContext::new(None, &[header(forbidden, "x")]).is_err(),
                "{forbidden}"
            );
        }
        assert!(AuthContext::new(None, &[header("Cookie", "sid=1")]).is_err());
        assert!(AuthContext::new(None, &[header("Bad Name", "x")]).is_err());
        assert!(AuthContext::new(None, &[header("X-A", "a\r\nb")]).is_err());
        assert!(AuthContext::new(None, &[header("", "x")]).is_err());
        assert!(AuthContext::new(None, &[header("X-A", "")]).is_err());
        let nine = (0..9)
            .map(|index| header(&format!("X-{index}"), "v"))
            .collect::<Vec<_>>();
        assert!(AuthContext::new(None, &nine).is_err());
        assert!(AuthContext::new(
            Some("a".repeat(MAX_COOKIE_BYTES + 1).as_str()),
            &[]
        )
        .is_err());
        assert!(AuthContext::new(
            None,
            &[header("X-A", "v".repeat(MAX_VALUE_BYTES + 1).as_str())]
        )
        .is_err());
        assert!(AuthContext::new(
            None,
            &[
                header("X-Dup", "1"),
                header("x-dup", "2")
            ]
        )
        .is_err());
    }

    #[test]
    fn default_context_is_inert_and_summary_never_carries_a_secret() {
        let empty = AuthContext::default();
        assert!(empty.is_empty());
        assert!(empty.header_map().is_empty());
        assert_eq!(empty.summary(), "");

        let cookie_only = AuthContext::new(Some("sid=SECRET"), &[]).unwrap();
        assert_eq!(cookie_only.header_map().len(), 1);
        assert_eq!(cookie_only.summary(), " with an operator-supplied session cookie");

        let headers_only =
            AuthContext::new(None, &[header("Authorization", "Bearer SECRET")]).unwrap();
        assert_eq!(
            headers_only.summary(),
            " with operator-supplied session headers"
        );

        let both = AuthContext::new(
            Some("sid=SECRET"),
            &[header("Authorization", "Bearer SECRET")],
        )
        .unwrap();
        let map = both.header_map();
        assert_eq!(map.len(), 2);
        assert_eq!(
            both.summary(),
            " with an operator-supplied session cookie and headers"
        );
        assert!(!both.summary().contains("SECRET"));
    }
}
