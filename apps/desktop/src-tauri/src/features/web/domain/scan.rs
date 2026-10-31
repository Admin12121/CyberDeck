//! Web review findings and purely local detection rules.
//! No Tauri, HTTP clients or filesystem access in the domain layer.

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: String, // info | low | medium | high
    pub title: String,
    pub detail: String,
    pub evidence: String,
}

/// Report cookie hardening only for likely authentication cookies. Values
/// are never written to findings, history, or debug output.
pub(super) fn session_cookie_findings(
    headers: &[(String, String)],
    https: bool,
    endpoint: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (_, value) in headers.iter().filter(|(key, _)| key == "set-cookie") {
        let Some((raw_name, _)) = value.split_once('=') else {
            continue;
        };
        let name = raw_name.trim();
        let normalized = name.to_ascii_lowercase();
        if !matches!(
            normalized.as_str(),
            "session"
                | "sessionid"
                | "jsessionid"
                | "phpsessid"
                | "connect.sid"
                | "sid"
                | "auth"
                | "jwt"
                | "access_token"
                | "id_token"
        ) && !normalized.ends_with("_session")
        {
            continue;
        }
        // Inspect attributes without building a Vec or allocating a lowercase
        // copy for every attribute on every required-cookie check.
        for (required, reason) in [
            ("httponly", "session cookie accessible to browser scripts"),
            ("secure", "session cookie may be sent over unencrypted HTTP"),
            (
                "samesite",
                "session cookie lacks explicit cross-site request policy",
            ),
        ] {
            if required == "secure" && !https {
                continue;
            }
            if value.split(';').skip(1).map(str::trim).any(|attr| {
                attr.split_once('=')
                    .map_or(attr, |(key, _)| key)
                    .eq_ignore_ascii_case(required)
            }) {
                continue;
            }
            findings.push(Finding {
                severity: "low".to_string(),
                title: format!("session cookie missing {required}"),
                detail: reason.to_string(),
                evidence: format!("{endpoint} — cookie {name} (value redacted)"),
            });
        }
    }
    findings
}

/// A generic HTTP 200 response is frequently an SPA fallback.
/// Recognize actual sensitive-file contents before reporting high severity.
pub(super) fn confirmed_exposure(path: &str, body: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(body) else {
        return false;
    };
    match path {
        "/.git/HEAD" => {
            let value = text.trim();
            (value.starts_with("ref: refs/heads/") && value.len() < 200)
                || (value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit()))
        }
        "/.env" => {
            if text.to_ascii_lowercase().contains("<html") {
                return false;
            }
            text.lines().any(|line| {
                let Some((name, _)) = line.trim().split_once('=') else {
                    return false;
                };
                matches!(
                    name,
                    "APP_KEY"
                        | "APP_SECRET"
                        | "DB_PASSWORD"
                        | "DATABASE_URL"
                        | "AWS_SECRET_ACCESS_KEY"
                        | "SECRET_KEY"
                        | "DB_HOST"
                        | "DB_DATABASE"
                        | "APP_ENV"
                )
            })
        }
        _ => false,
    }
}

pub(super) fn require_authorization(authorized: bool) -> Result<(), String> {
    if authorized {
        Ok(())
    } else {
        Err("explicit authorization acknowledgment required".to_string())
    }
}
