//! SPDX-License-Identifier: MIT
//! CyberDeck independently implemented passive rule evaluation.
//! Source study: ZAP PassiveScanController.scan, PassiveScanTask.run,
//! PluginPassiveScanner newAlert, zap-extensions pscanrules CSP/SameSite.
//! No upstream Java code or protected HTTP content is copied or persisted.
use serde::Serialize;

pub(super) const MAX_OBSERVATIONS: usize = 64;
pub(super) const MAX_FINDINGS: usize = 128;

#[derive(Clone, Copy, Debug, Serialize)]
pub struct RuleInfo {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: &'static str,
}

pub(super) const RULES: [RuleInfo; 6] = [
    RuleInfo {
        id: "cd.pscan.csp-missing.v1",
        title: "Missing enforced Content-Security-Policy",
        severity: "low",
    },
    RuleInfo {
        id: "cd.pscan.nosniff-missing.v1",
        title: "Missing X-Content-Type-Options",
        severity: "low",
    },
    RuleInfo {
        id: "cd.pscan.hsts-missing.v1",
        title: "Missing HSTS on HTTPS",
        severity: "low",
    },
    RuleInfo {
        id: "cd.pscan.cookie-samesite.v1",
        title: "Cookie SameSite configuration",
        severity: "low",
    },
    RuleInfo {
        id: "cd.pscan.cookie-secure.v1",
        title: "HTTPS cookie missing Secure",
        severity: "low",
    },
    RuleInfo {
        id: "cd.pscan.cookie-httponly.v1",
        title: "Session cookie missing HttpOnly",
        severity: "low",
    },
];

pub(super) fn selected_rules(selected: &[String]) -> Result<Vec<&'static str>, String> {
    if selected.len() > RULES.len() {
        return Err("too many passive rules".into());
    }
    let mut out = Vec::new();
    for id in selected {
        let rule = RULES
            .iter()
            .find(|rule| rule.id == id)
            .ok_or("unknown passive rule")?;
        if out.contains(&rule.id) {
            return Err("duplicate passive rule".into());
        }
        out.push(rule.id);
    }
    if out.is_empty() {
        return Err("select at least one passive rule".into());
    }
    Ok(out)
}

/// Facts are deliberately minimal: no response body, URL, query, header
/// values, cookie names, cookie values, tokens or credential-bearing metadata
/// can be exported from the protected History lock into the scan job.
#[derive(Clone, Debug)]
pub(super) struct Observation {
    pub history_id: u64,
    pub status: u16,
    pub html: bool,
    pub https: bool,
    pub enforced_csp: bool,
    pub nosniff: bool,
    pub hsts: bool,
    pub cookies: Vec<CookieFacts>,
}

#[derive(Clone, Debug)]
pub(super) struct CookieFacts {
    pub same_site: SameSite,
    pub secure: bool,
    pub http_only: bool,
    pub session_named: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SameSite {
    Missing,
    Strict,
    Lax,
    None,
    Invalid,
}

pub(super) fn observe(
    id: u64,
    url: &str,
    status: u16,
    headers: &[(String, String)],
) -> Observation {
    let https = reqwest::Url::parse(url).is_ok_and(|url| url.scheme() == "https");
    let mut result = Observation {
        history_id: id,
        status,
        html: false,
        https,
        enforced_csp: false,
        nosniff: false,
        hsts: false,
        cookies: Vec::new(),
    };
    for (name, value) in headers.iter().take(128) {
        if name.eq_ignore_ascii_case("content-type") {
            result.html |= value
                .split(';')
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/html"));
        } else if name.eq_ignore_ascii_case("content-security-policy") {
            // Report-Only and obsolete CSP headers do NOT enforce restrictions.
            result.enforced_csp |= !value.trim().is_empty();
        } else if name.eq_ignore_ascii_case("x-content-type-options") {
            result.nosniff |= value.trim().eq_ignore_ascii_case("nosniff");
        } else if name.eq_ignore_ascii_case("strict-transport-security") {
            result.hsts |= value.split(';').next().is_some_and(|v| {
                v.trim().to_ascii_lowercase().starts_with("max-age=")
                    && v.trim()[8..].parse::<u64>().is_ok_and(|age| age > 0)
            });
        } else if name.eq_ignore_ascii_case("set-cookie") && result.cookies.len() < 16 {
            let mut components = value.split(';');
            let name = components
                .next()
                .unwrap_or("")
                .split('=')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if name.is_empty() {
                continue;
            }
            let session_named = ["sess", "auth", "login", "token", "jwt", "sid"]
                .iter()
                .any(|part| name.contains(part));
            let mut fact = CookieFacts {
                same_site: SameSite::Missing,
                secure: false,
                http_only: false,
                session_named,
            };
            for attr in components.take(32) {
                let (key, value) = attr.trim().split_once('=').unwrap_or((attr.trim(), ""));
                if key.eq_ignore_ascii_case("secure") {
                    fact.secure = true;
                } else if key.eq_ignore_ascii_case("httponly") {
                    fact.http_only = true;
                } else if key.eq_ignore_ascii_case("samesite") {
                    fact.same_site = match value.trim().to_ascii_lowercase().as_str() {
                        "strict" => SameSite::Strict,
                        "lax" => SameSite::Lax,
                        "none" => SameSite::None,
                        _ => SameSite::Invalid,
                    };
                }
            }
            result.cookies.push(fact);
        }
    }
    result
}

#[derive(Clone, Debug, Serialize)]
pub struct PassiveFinding {
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub confidence: String,
    pub detail: String,
    pub evidence: String,
    pub history_id: u64,
    pub status: u16,
}

fn finding(o: &Observation, id: &str, title: &str, severity: &str, detail: &str) -> PassiveFinding {
    PassiveFinding {
        rule_id: id.into(),
        title: title.into(),
        severity: severity.into(),
        confidence: "medium".into(),
        detail: detail.into(),
        evidence: format!(
            "Volatile HTTP history #{}; response status {}; checked response headers only",
            o.history_id, o.status
        ),
        history_id: o.history_id,
        status: o.status,
    }
}

/// Pure analysis: zero network I/O and zero raw HTTP/history serialization.
/// Header security findings are limited to successful HTML documents;
/// cookie checks inspect bounded attribute flags, never cookie values.
pub(super) fn analyze(o: &Observation, rules: &[&str]) -> Vec<PassiveFinding> {
    let enabled = |id| rules.contains(&id);
    let mut out = Vec::new();
    if o.status == 200 && o.html {
        if !o.enforced_csp && enabled(RULES[0].id) {
            out.push(finding(o, RULES[0].id, RULES[0].title, "low",
                "A successful HTML response has no enforcing CSP header; report-only CSP does not enforce. Check application policy before treating this as exposure."));
        }
        if !o.nosniff && enabled(RULES[1].id) {
            out.push(finding(o, RULES[1].id, RULES[1].title, "low",
                "The HTML response lacks X-Content-Type-Options: nosniff; confirm relevant browser MIME-handling behavior."));
        }
        if o.https && !o.hsts && enabled(RULES[2].id) {
            out.push(finding(o, RULES[2].id, RULES[2].title, "low",
                "HTTPS HTML response lacks a positive max-age Strict-Transport-Security policy; verify deployment-wide HTTPS before enabling."));
        }
    }
    if o.status < 200 || o.status >= 400 {
        return out;
    }
    // Aggregate each rule once per response to avoid disclosure of cookie
    // counts, names, values and duplicate findings for a cookie-heavy page.
    if enabled(RULES[3].id) {
        if o.cookies
            .iter()
            .any(|cookie| cookie.same_site == SameSite::Invalid)
        {
            out.push(finding(o, RULES[3].id, "Invalid SameSite cookie attribute", "low",
                "At least one Set-Cookie has an invalid SameSite value. Cookie names and values are intentionally withheld."));
        } else if o
            .cookies
            .iter()
            .any(|cookie| cookie.same_site == SameSite::None && !cookie.secure)
        {
            out.push(finding(o, RULES[3].id, "SameSite=None cookie without Secure", "low",
                "At least one Set-Cookie requests SameSite=None without Secure; browsers may reject it. No cookie values retained."));
        } else if o
            .cookies
            .iter()
            .any(|cookie| cookie.same_site == SameSite::Missing)
        {
            out.push(finding(o, RULES[3].id, RULES[3].title, "low",
                "At least one Set-Cookie lacks an explicit SameSite policy. This is configuration guidance, not proof of CSRF."));
        }
    }
    if o.https && enabled(RULES[4].id) && o.cookies.iter().any(|cookie| !cookie.secure) {
        out.push(finding(o, RULES[4].id, RULES[4].title, "low",
            "An HTTPS response sets a cookie without Secure; browser transport behavior and the cookie's purpose require verification."));
    }
    if enabled(RULES[5].id)
        && o.cookies
            .iter()
            .any(|cookie| cookie.session_named && !cookie.http_only)
    {
        out.push(finding(o, RULES[5].id, RULES[5].title, "low",
            "A cookie with a session-like name lacks HttpOnly. This name-based heuristic needs manual confirmation; neither the name nor value is recorded."));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rules_are_strictly_allowlisted() {
        assert_eq!(
            selected_rules(&[RULES[0].id.into()]).unwrap(),
            vec![RULES[0].id]
        );
        assert!(selected_rules(&[]).is_err());
        assert!(selected_rules(&["untrusted".into()]).is_err());
        assert!(selected_rules(&[RULES[0].id.into(), RULES[0].id.into()]).is_err());
    }
    #[test]
    fn positive_html_and_cookie_rules_never_include_secret_material() {
        let raw = vec![
            ("Content-Type".into(), "text/html; charset=utf8".into()),
            (
                "Content-Security-Policy-Report-Only".into(),
                "default-src 'none'".into(),
            ),
            (
                "Set-Cookie".into(),
                "session=TOPSECRET; Path=/; SameSite=None".into(),
            ),
            ("Location".into(), "/account?token=TOPSECRET".into()),
        ];
        let o = observe(17, "https://private.invalid/?secret=TOPSECRET", 200, &raw);
        let enabled = RULES.iter().map(|x| x.id).collect::<Vec<_>>();
        let alerts = analyze(&o, &enabled);
        assert!(alerts.iter().any(|f| f.rule_id == RULES[0].id));
        assert!(alerts.iter().any(|f| f.rule_id == RULES[1].id));
        assert!(alerts.iter().any(|f| f.rule_id == RULES[2].id));
        assert!(alerts.iter().any(|f| f.rule_id == RULES[3].id));
        assert!(alerts.iter().any(|f| f.rule_id == RULES[4].id));
        assert!(alerts.iter().any(|f| f.rule_id == RULES[5].id));
        let serialized = serde_json::to_string(&alerts).unwrap();
        assert!(!serialized.contains("TOPSECRET"));
        assert!(!serialized.contains("session="));
        assert!(!serialized.contains("private.invalid"));
    }
    #[test]
    fn negative_non_html_report_only_and_secure_cookie_cases() {
        let enabled = RULES.iter().map(|x| x.id).collect::<Vec<_>>();
        let headers = vec![
            ("content-type".into(), "application/json".into()),
            (
                "set-cookie".into(),
                "session=redacted; HttpOnly; Secure; SameSite=Strict".into(),
            ),
        ];
        assert!(analyze(&observe(1, "https://private.test", 200, &headers), &enabled).is_empty());
        let headers = vec![
            ("content-type".into(), "text/html".into()),
            (
                "content-security-policy".into(),
                "default-src 'self'".into(),
            ),
            ("x-content-type-options".into(), "nosniff".into()),
            (
                "strict-transport-security".into(),
                "max-age=31536000".into(),
            ),
        ];
        assert!(analyze(&observe(1, "https://private.test", 200, &headers), &enabled).is_empty());
        assert!(analyze(&observe(1, "https://private.test", 404, &[]), &enabled).is_empty());
    }
}
