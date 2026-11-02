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

/// Paths whose HTTP 200 is only reportable after the body is confirmed to
/// contain the artifact. An SPA that answers every path with index.html must
/// never be reported as a source or credential leak.
const SENSITIVE_PATHS: &[&str] = &[
    "/.env",
    "/.git/HEAD",
    "/.git/config",
    "/.svn/entries",
    "/.DS_Store",
    "/WEB-INF/web.xml",
    "/actuator/env",
    "/swagger-ui.html",
    "/openapi.json",
    "/phpinfo.php",
    "/server-status",
    "/elmah.axd",
    "/backup.zip",
    "/backup.sql",
    "/config.php.bak",
];

pub(super) fn is_sensitive_path(path: &str) -> bool {
    SENSITIVE_PATHS.contains(&path)
}

fn looks_like_html(text: &str) -> bool {
    let head: String = text.chars().take(512).collect::<String>().to_ascii_lowercase();
    head.contains("<!doctype html") || head.contains("<html")
}

/// A generic HTTP 200 response is frequently an SPA fallback.
/// Recognize actual sensitive-file contents before reporting high severity.
pub(super) fn confirmed_exposure(path: &str, body: &[u8]) -> bool {
    match path {
        "/.DS_Store" => return body.starts_with(b"\0\0\0\x01Bud1"),
        "/backup.zip" => return body.starts_with(b"PK\x03\x04"),
        _ => {}
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return false;
    };
    match path {
        "/.git/HEAD" => {
            let value = text.trim();
            (value.starts_with("ref: refs/heads/") && value.len() < 200)
                || (value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit()))
        }
        "/.git/config" => {
            let lowered = text.to_ascii_lowercase();
            lowered.contains("[core]") && lowered.contains("repositoryformatversion")
        }
        "/.svn/entries" => text
            .lines()
            .next()
            .map(str::trim)
            .is_some_and(|line| line == "dir" || line.parse::<u32>().is_ok()),
        "/WEB-INF/web.xml" => {
            let trimmed = text.trim_start_matches('\u{feff}').trim_start();
            trimmed.starts_with("<web-app")
                || trimmed.contains("<web-app>")
                || trimmed.contains("<web-app ")
        }
        "/actuator/env" => {
            let trimmed = text.trim_start();
            trimmed.starts_with('{')
                && (text.contains("\"propertySources\"") || text.contains("\"activeProfiles\""))
        }
        "/swagger-ui.html" => text.contains("Swagger UI") || text.contains("swagger-ui"),
        "/openapi.json" => {
            let trimmed = text.trim_start();
            trimmed.starts_with('{')
                && (text.contains("\"openapi\"") || text.contains("\"swagger\""))
        }
        "/phpinfo.php" => {
            text.contains("phpinfo()") || text.contains("PHP Version") || text.contains("php.ini")
        }
        "/server-status" => text.contains("Apache Server Status"),
        "/elmah.axd" => text.contains("Error Log for"),
        "/backup.sql" => {
            !looks_like_html(text)
                && (text.starts_with("-- MySQL dump")
                    || text.starts_with("--\n--")
                    || text.contains("CREATE TABLE"))
        }
        "/config.php.bak" => text.contains("<?php") && (text.contains("DB_") || text.contains("AUTH_KEY")),
        "/.env" => {
            if looks_like_html(text) {
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

#[cfg(test)]
mod exposure_confirmation_tests {
    use super::*;

    #[test]
    fn spa_fallbacks_never_confirm_a_sensitive_path() {
        let spa = b"<!doctype html><html><body>Not found</body></html>";
        for path in SENSITIVE_PATHS {
            assert!(!confirmed_exposure(path, spa), "{path}");
        }
        assert!(!confirmed_exposure("/.git/HEAD", b""));
        assert!(!confirmed_exposure("/actuator/env", br#"{"status":"UP"}"#));
        assert!(!confirmed_exposure("/openapi.json", b"<html>nope</html>"));
    }

    #[test]
    fn genuine_sensitive_artifacts_are_confirmed() {
        for (path, body) in [
            ("/.env", &b"APP_KEY=base64:secret\nDB_HOST=db\n"[..]),
            ("/.git/HEAD", &b"ref: refs/heads/main\n"[..]),
            ("/.git/config", &b"[core]\n\trepositoryformatversion = 0\n"[..]),
            ("/.svn/entries", &b"12\n"[..]),
            ("/.DS_Store", &b"\0\0\0\x01Bud1rest"[..]),
            (
                "/WEB-INF/web.xml",
                &b"<?xml version=\"1.0\"?><web-app></web-app>"[..],
            ),
            (
                "/actuator/env",
                &br#"{"activeProfiles":["prod"],"propertySources":[]}"#[..],
            ),
            ("/swagger-ui.html", &b"<title>Swagger UI</title>"[..]),
            ("/openapi.json", &br#"{"openapi":"3.1.0","paths":{}}"#[..]),
            ("/phpinfo.php", &b"<h1>PHP Version 8.3</h1>"[..]),
            (
                "/server-status",
                &b"<title>Apache Server Status for localhost</title>"[..],
            ),
            ("/elmah.axd", &b"<h2>Error Log for /</h2>"[..]),
            ("/backup.zip", &b"PK\x03\x04rest"[..]),
            (
                "/backup.sql",
                &b"-- MySQL dump 10.13\nCREATE TABLE users(id int);"[..],
            ),
            (
                "/config.php.bak",
                &b"<?php define('DB_PASSWORD', 'secret');"[..],
            ),
        ] {
            assert!(is_sensitive_path(path), "{path} must require confirmation");
            assert!(confirmed_exposure(path, body), "{path}");
        }
    }

    #[test]
    fn session_cookie_findings_never_report_values() {
        let headers = vec![
            (
                "set-cookie".to_string(),
                "sessionid=SUPER_SECRET; Path=/; Secure".to_string(),
            ),
            (
                "set-cookie".to_string(),
                "theme=dark; Path=/".to_string(),
            ),
        ];
        let findings = session_cookie_findings(&headers, true, "https://private.invalid/");
        assert_eq!(findings.len(), 2);
        let rendered = serde_json::to_string(&findings).unwrap();
        assert!(!rendered.contains("SUPER_SECRET"));
        assert!(!rendered.contains("theme"));
        assert!(rendered.contains("sessionid"));
    }
}
