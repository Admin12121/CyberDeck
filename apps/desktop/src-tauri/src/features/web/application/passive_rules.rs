//! SPDX-License-Identifier: MIT
//! CyberDeck independently implemented passive rule evaluation.
//! Source study: ZAP PassiveScanController.scan, PassiveScanTask.run,
//! PluginPassiveScanner newAlert, zap-extensions pscanrules CSP/SameSite/
//! Referrer-Policy/Cookie-prefix/CORS/COOP rules.
//! No upstream Java code or protected HTTP content is copied or persisted.
use serde::Serialize;

pub(super) const MAX_OBSERVATIONS: usize = 64;
pub(super) const MAX_FINDINGS: usize = 128;

/// Rule metadata is fixed, source-versioned and serialized to the UI.
/// Severity and confidence live here so a finding can never drift from its
/// catalog entry; the frontend never supplies either value.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct RuleInfo {
    pub id: &'static str,
    pub title: &'static str,
    pub severity: &'static str,
    pub confidence: &'static str,
    pub category: &'static str,
}

// Stable indices: existing rule IDs keep their historical positions so
// persisted case findings and UI selections remain interpretable.
const CSP_MISSING: usize = 0;
const NOSNIFF_MISSING: usize = 1;
const HSTS_MISSING: usize = 2;
const COOKIE_SAMESITE: usize = 3;
const COOKIE_SECURE: usize = 4;
const COOKIE_HTTPONLY: usize = 5;
const FRAME_PROTECTION: usize = 6;
const COOKIE_LOOSE_DOMAIN: usize = 7;
const CSP_REPORT_ONLY: usize = 8;
const CSP_UNSAFE_INLINE: usize = 9;
const CSP_UNSAFE_EVAL: usize = 10;
const CSP_WILDCARD: usize = 11;
const REFERRER_MISSING: usize = 12;
const REFERRER_UNSAFE: usize = 13;
const REFERRER_INVALID: usize = 14;
const PERMISSIONS_MISSING: usize = 15;
const COOP_MISSING: usize = 16;
const CACHE_MISSING: usize = 17;
const CONTENT_TYPE_MISSING: usize = 18;
const CHARSET_MISSING: usize = 19;
const SERVER_BANNER: usize = 20;
const POWERED_BY: usize = 21;
const LEGACY_XSS: usize = 22;
const LEGACY_CSP: usize = 23;
const CORS_WILDCARD: usize = 24;
const CORS_NULL: usize = 25;
const HSTS_SHORT: usize = 26;
const HSTS_SUBDOMAINS: usize = 27;
const COOKIE_PREFIX: usize = 28;
const COOKIE_LONG_LIVED: usize = 29;

pub(super) const RULES: [RuleInfo; 30] = [
    RuleInfo {
        id: "cd.pscan.csp-missing.v1",
        title: "Missing enforced Content-Security-Policy",
        severity: "low",
        confidence: "medium",
        category: "headers",
    },
    RuleInfo {
        id: "cd.pscan.nosniff-missing.v1",
        title: "Missing X-Content-Type-Options",
        severity: "low",
        confidence: "high",
        category: "headers",
    },
    RuleInfo {
        id: "cd.pscan.hsts-missing.v1",
        title: "Missing HSTS on HTTPS",
        severity: "low",
        confidence: "medium",
        category: "transport",
    },
    RuleInfo {
        id: "cd.pscan.cookie-samesite.v1",
        title: "Cookie SameSite configuration",
        severity: "low",
        confidence: "medium",
        category: "cookies",
    },
    RuleInfo {
        id: "cd.pscan.cookie-secure.v1",
        title: "HTTPS cookie missing Secure",
        severity: "low",
        confidence: "high",
        category: "cookies",
    },
    RuleInfo {
        id: "cd.pscan.cookie-httponly.v1",
        title: "Session cookie missing HttpOnly",
        severity: "low",
        confidence: "medium",
        category: "cookies",
    },
    RuleInfo {
        id: "cd.pscan.frame-protection.v1",
        title: "HTML framing protection",
        severity: "low",
        confidence: "medium",
        category: "headers",
    },
    RuleInfo {
        id: "cd.pscan.cookie-loose-domain.v1",
        title: "Cookie explicitly scoped to a parent domain",
        severity: "low",
        confidence: "medium",
        category: "cookies",
    },
    RuleInfo {
        id: "cd.pscan.csp-report-only.v1",
        title: "Only report-only CSP is configured",
        severity: "info",
        confidence: "high",
        category: "csp",
    },
    RuleInfo {
        id: "cd.pscan.csp-unsafe-inline.v1",
        title: "CSP allows inline script",
        severity: "low",
        confidence: "high",
        category: "csp",
    },
    RuleInfo {
        id: "cd.pscan.csp-unsafe-eval.v1",
        title: "CSP allows eval",
        severity: "low",
        confidence: "high",
        category: "csp",
    },
    RuleInfo {
        id: "cd.pscan.csp-wildcard-source.v1",
        title: "CSP script source is a wildcard",
        severity: "low",
        confidence: "high",
        category: "csp",
    },
    RuleInfo {
        id: "cd.pscan.referrer-policy-missing.v1",
        title: "Missing Referrer-Policy",
        severity: "low",
        confidence: "medium",
        category: "headers",
    },
    RuleInfo {
        id: "cd.pscan.referrer-policy-unsafe.v1",
        title: "Referrer-Policy sends full URLs cross-origin",
        severity: "medium",
        confidence: "high",
        category: "headers",
    },
    RuleInfo {
        id: "cd.pscan.referrer-policy-invalid.v1",
        title: "Unrecognized Referrer-Policy value",
        severity: "low",
        confidence: "high",
        category: "headers",
    },
    RuleInfo {
        id: "cd.pscan.permissions-policy-missing.v1",
        title: "Missing Permissions-Policy",
        severity: "info",
        confidence: "medium",
        category: "headers",
    },
    RuleInfo {
        id: "cd.pscan.coop-missing.v1",
        title: "Missing Cross-Origin-Opener-Policy",
        severity: "low",
        confidence: "medium",
        category: "headers",
    },
    RuleInfo {
        id: "cd.pscan.cache-control-missing.v1",
        title: "Cookie-bearing HTML response has no private cache directive",
        severity: "low",
        confidence: "medium",
        category: "headers",
    },
    RuleInfo {
        id: "cd.pscan.content-type-missing.v1",
        title: "Response has no Content-Type",
        severity: "low",
        confidence: "high",
        category: "headers",
    },
    RuleInfo {
        id: "cd.pscan.charset-missing.v1",
        title: "HTML response declares no charset",
        severity: "info",
        confidence: "medium",
        category: "headers",
    },
    RuleInfo {
        id: "cd.pscan.server-banner.v1",
        title: "Server banner disclosed",
        severity: "info",
        confidence: "high",
        category: "disclosure",
    },
    RuleInfo {
        id: "cd.pscan.framework-banner.v1",
        title: "Framework banner disclosed",
        severity: "info",
        confidence: "high",
        category: "disclosure",
    },
    RuleInfo {
        id: "cd.pscan.legacy-xss-header.v1",
        title: "Obsolete X-XSS-Protection header",
        severity: "info",
        confidence: "medium",
        category: "disclosure",
    },
    RuleInfo {
        id: "cd.pscan.legacy-csp-header.v1",
        title: "Obsolete legacy CSP header",
        severity: "info",
        confidence: "high",
        category: "disclosure",
    },
    RuleInfo {
        id: "cd.pscan.cors-wildcard.v1",
        title: "CORS allows any origin",
        severity: "info",
        confidence: "high",
        category: "cors",
    },
    RuleInfo {
        id: "cd.pscan.cors-null-origin.v1",
        title: "CORS allows the null origin",
        severity: "medium",
        confidence: "high",
        category: "cors",
    },
    RuleInfo {
        id: "cd.pscan.hsts-short-max-age.v1",
        title: "HSTS max-age below 180 days",
        severity: "low",
        confidence: "high",
        category: "transport",
    },
    RuleInfo {
        id: "cd.pscan.hsts-no-subdomains.v1",
        title: "HSTS does not cover subdomains",
        severity: "info",
        confidence: "high",
        category: "transport",
    },
    RuleInfo {
        id: "cd.pscan.cookie-prefix.v1",
        title: "Cookie prefix contract violated",
        severity: "medium",
        confidence: "high",
        category: "cookies",
    },
    RuleInfo {
        id: "cd.pscan.cookie-long-lived-session.v1",
        title: "Long-lived session cookie",
        severity: "info",
        confidence: "medium",
        category: "cookies",
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
    pub csp_report_only: bool,
    pub csp: CspWeaknesses,
    pub nosniff: bool,
    pub hsts: bool,
    pub hsts_max_age: Option<u64>,
    pub hsts_subdomains: bool,
    pub framing_restricted: bool,
    pub referrer_policy: ReferrerPolicy,
    pub permissions_policy: bool,
    pub coop: bool,
    pub has_content_type: bool,
    pub charset_declared: bool,
    pub cache_controlled: bool,
    pub server_banner: bool,
    pub powered_by: bool,
    pub legacy_xss_header: bool,
    pub legacy_csp_header: bool,
    pub acao: Acao,
    pub cookies: Vec<CookieFacts>,
}

#[derive(Clone, Debug)]
pub(super) struct CookieFacts {
    pub same_site: SameSite,
    pub secure: bool,
    pub http_only: bool,
    pub session_named: bool,
    pub parent_domain: bool,
    pub prefix_violation: bool,
    pub long_lived_session: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SameSite {
    Missing,
    Strict,
    Lax,
    None,
    Invalid,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct CspWeaknesses {
    pub unsafe_inline: bool,
    pub unsafe_eval: bool,
    pub wildcard: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ReferrerPolicy {
    Missing,
    Invalid,
    NoReferrer,
    SameOrigin,
    StrictOrigin,
    StrictOriginWhenCrossOrigin,
    Origin,
    OriginWhenCrossOrigin,
    NoReferrerWhenDowngrade,
    UnsafeUrl,
}

impl ReferrerPolicy {
    fn is_present(self) -> bool {
        !matches!(self, Self::Missing)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Acao {
    Missing,
    Wildcard,
    Null,
    Other,
}

fn parse_referrer_policy(value: &str) -> ReferrerPolicy {
    // Browsers use the first recognized policy in a comma-separated list.
    let token = value.split(',').next().unwrap_or("").trim();
    if token.is_empty() {
        return ReferrerPolicy::Invalid;
    }
    match token.to_ascii_lowercase().as_str() {
        "no-referrer" => ReferrerPolicy::NoReferrer,
        "same-origin" => ReferrerPolicy::SameOrigin,
        "strict-origin" => ReferrerPolicy::StrictOrigin,
        "strict-origin-when-cross-origin" => ReferrerPolicy::StrictOriginWhenCrossOrigin,
        "origin" => ReferrerPolicy::Origin,
        "origin-when-cross-origin" => ReferrerPolicy::OriginWhenCrossOrigin,
        "no-referrer-when-downgrade" => ReferrerPolicy::NoReferrerWhenDowngrade,
        "unsafe-url" => ReferrerPolicy::UnsafeUrl,
        _ => ReferrerPolicy::Invalid,
    }
}

/// Only the effective script source list is inspected: script-src when it is
/// declared, otherwise default-src as the browser fallback. Nonces and hashes
/// neutralize 'unsafe-inline', which the finding detail states explicitly.
fn csp_weaknesses(value: &str) -> CspWeaknesses {
    let mut default_src: Option<Vec<&str>> = None;
    let mut script_src: Option<Vec<&str>> = None;
    for directive in value.split(';') {
        let mut words = directive.split_ascii_whitespace();
        let Some(key) = words.next() else { continue };
        let sources: Vec<&str> = words.take(32).collect();
        if key.eq_ignore_ascii_case("default-src") {
            default_src = Some(sources);
        } else if key.eq_ignore_ascii_case("script-src") {
            script_src = Some(sources);
        }
    }
    let Some(sources) = script_src.or(default_src) else {
        return CspWeaknesses::default();
    };
    let mut weaknesses = CspWeaknesses::default();
    for source in sources {
        let lowered = source.to_ascii_lowercase();
        if lowered == "'unsafe-inline'" {
            weaknesses.unsafe_inline = true;
        } else if lowered == "'unsafe-eval'" {
            weaknesses.unsafe_eval = true;
        } else if lowered == "*" {
            weaknesses.wildcard = true;
        }
    }
    weaknesses
}

fn parse_acao(value: &str) -> Acao {
    let value = value.trim();
    if value.is_empty() {
        Acao::Missing
    } else if value == "*" {
        Acao::Wildcard
    } else if value.eq_ignore_ascii_case("null") {
        Acao::Null
    } else {
        Acao::Other
    }
}

/// Conservative scope heuristic, evaluated only under protected History.
/// This deliberately does not claim public-suffix or cookie-browser parity.
fn parent_cookie_domain(host: Option<&str>, domain: &str) -> bool {
    let Some(host) = host else { return false };
    let domain = domain.trim().trim_start_matches('.').trim_end_matches('.');
    if domain.len() < 3
        || domain.len() > 253
        || !domain.contains('.')
        || !domain.is_ascii()
        || !host.is_ascii()
        || domain
            .bytes()
            .any(|c| !(c.is_ascii_alphanumeric() || c == b'-' || c == b'.'))
        || host.parse::<std::net::IpAddr>().is_ok()
    {
        return false;
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let domain = domain.to_ascii_lowercase();
    host.len() > domain.len() + 1 && host.ends_with(&format!(".{domain}"))
}

pub(super) fn observe(
    id: u64,
    url: &str,
    status: u16,
    headers: &[(String, String)],
) -> Observation {
    let parsed_url = reqwest::Url::parse(url).ok();
    let https = parsed_url
        .as_ref()
        .is_some_and(|url| url.scheme() == "https");
    let origin_host = parsed_url.as_ref().and_then(|url| url.host_str());
    let mut xfo_count = 0u8;
    let mut xfo_strict = false;
    let mut csp_frame_restricted = false;
    let mut csp_frame_seen = false;
    let mut result = Observation {
        history_id: id,
        status,
        html: false,
        https,
        enforced_csp: false,
        csp_report_only: false,
        csp: CspWeaknesses::default(),
        nosniff: false,
        hsts: false,
        hsts_max_age: None,
        hsts_subdomains: false,
        framing_restricted: false,
        referrer_policy: ReferrerPolicy::Missing,
        permissions_policy: false,
        coop: false,
        has_content_type: false,
        charset_declared: false,
        cache_controlled: false,
        server_banner: false,
        powered_by: false,
        legacy_xss_header: false,
        legacy_csp_header: false,
        acao: Acao::Missing,
        cookies: Vec::new(),
    };
    for (name, value) in headers.iter().take(128) {
        if name.eq_ignore_ascii_case("content-type") {
            result.has_content_type |= !value.trim().is_empty();
            let mut parameters = value.split(';');
            result.html |= parameters
                .next()
                .is_some_and(|mime| mime.trim().eq_ignore_ascii_case("text/html"));
            result.charset_declared |= parameters.any(|parameter| {
                parameter
                    .split('=')
                    .next()
                    .is_some_and(|key| key.trim().eq_ignore_ascii_case("charset"))
            });
        } else if name.eq_ignore_ascii_case("content-security-policy") {
            // Report-Only and obsolete CSP headers do NOT enforce restrictions.
            let enforced = !value.trim().is_empty();
            result.enforced_csp |= enforced;
            if enforced {
                result.csp = csp_weaknesses(value);
            }
            for directive in value.split(';') {
                let mut words = directive.split_ascii_whitespace();
                if words
                    .next()
                    .is_some_and(|key| key.eq_ignore_ascii_case("frame-ancestors"))
                {
                    csp_frame_seen = true;
                    let sources: Vec<_> = words.take(4).collect();
                    if sources.len() == 1
                        && (sources[0].eq_ignore_ascii_case("'none'")
                            || sources[0].eq_ignore_ascii_case("'self'"))
                    {
                        csp_frame_restricted = true;
                    }
                }
            }
        } else if name.eq_ignore_ascii_case("content-security-policy-report-only") {
            result.csp_report_only |= !value.trim().is_empty();
        } else if name.eq_ignore_ascii_case("x-content-type-options") {
            result.nosniff |= value.trim().eq_ignore_ascii_case("nosniff");
        } else if name.eq_ignore_ascii_case("strict-transport-security") {
            for directive in value.split(';') {
                let directive = directive.trim();
                if let Some((key, raw)) = directive.split_once('=') {
                    if key.trim().eq_ignore_ascii_case("max-age") {
                        if let Ok(age) = raw.trim().parse::<u64>() {
                            result.hsts_max_age = Some(age);
                            result.hsts = age > 0;
                        }
                    }
                } else if directive.eq_ignore_ascii_case("includesubdomains") {
                    result.hsts_subdomains = true;
                }
            }
        } else if name.eq_ignore_ascii_case("x-frame-options") {
            xfo_count = xfo_count.saturating_add(1);
            xfo_strict |= value.trim().eq_ignore_ascii_case("deny")
                || value.trim().eq_ignore_ascii_case("sameorigin");
        } else if name.eq_ignore_ascii_case("referrer-policy") {
            result.referrer_policy = parse_referrer_policy(value);
        } else if name.eq_ignore_ascii_case("permissions-policy") {
            result.permissions_policy |= !value.trim().is_empty();
        } else if name.eq_ignore_ascii_case("cross-origin-opener-policy") {
            result.coop |= !value.trim().is_empty();
        } else if name.eq_ignore_ascii_case("cache-control") {
            let lowered = value.to_ascii_lowercase();
            result.cache_controlled |= lowered.contains("no-store")
                || lowered.contains("private")
                || lowered.contains("no-cache");
        } else if name.eq_ignore_ascii_case("pragma") {
            result.cache_controlled |= value.trim().eq_ignore_ascii_case("no-cache");
        } else if name.eq_ignore_ascii_case("server") {
            result.server_banner |= !value.trim().is_empty();
        } else if name.eq_ignore_ascii_case("x-powered-by")
            || name.eq_ignore_ascii_case("x-aspnet-version")
            || name.eq_ignore_ascii_case("x-aspnetmvc-version")
        {
            result.powered_by = true;
        } else if name.eq_ignore_ascii_case("x-xss-protection") {
            result.legacy_xss_header = true;
        } else if name.eq_ignore_ascii_case("x-content-security-policy")
            || name.eq_ignore_ascii_case("x-webkit-csp")
        {
            result.legacy_csp_header = true;
        } else if name.eq_ignore_ascii_case("access-control-allow-origin") {
            result.acao = parse_acao(value);
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
                parent_domain: false,
                prefix_violation: false,
                long_lived_session: false,
            };
            let mut path_is_root = false;
            let mut domain_present = false;
            let mut max_age = None;
            for attr in components.take(32) {
                let (key, value) = attr.trim().split_once('=').unwrap_or((attr.trim(), ""));
                if key.eq_ignore_ascii_case("secure") {
                    fact.secure = true;
                } else if key.eq_ignore_ascii_case("httponly") {
                    fact.http_only = true;
                } else if key.eq_ignore_ascii_case("path") {
                    path_is_root = value.trim() == "/";
                } else if key.eq_ignore_ascii_case("domain") {
                    domain_present = true;
                    fact.parent_domain |= parent_cookie_domain(origin_host, value);
                } else if key.eq_ignore_ascii_case("max-age") {
                    max_age = value.trim().parse::<i64>().ok();
                } else if key.eq_ignore_ascii_case("samesite") {
                    fact.same_site = match value.trim().to_ascii_lowercase().as_str() {
                        "strict" => SameSite::Strict,
                        "lax" => SameSite::Lax,
                        "none" => SameSite::None,
                        _ => SameSite::Invalid,
                    };
                }
            }
            // Cookie prefixes are a browser-enforced contract: __Secure- must
            // be Secure, __Host- must also be host-only with Path=/. Violations
            // cause silent cookie rejection rather than an exposure.
            fact.prefix_violation = (name.starts_with("__secure-") && !fact.secure)
                || (name.starts_with("__host-")
                    && (!fact.secure || !path_is_root || domain_present));
            fact.long_lived_session =
                fact.session_named && max_age.is_some_and(|age| age > 2_592_000);
            result.cookies.push(fact);
        }
    }
    result.framing_restricted = if csp_frame_seen {
        csp_frame_restricted
    } else {
        xfo_count == 1 && xfo_strict
    };
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

fn finding(o: &Observation, rule: &RuleInfo, detail: &str) -> PassiveFinding {
    PassiveFinding {
        rule_id: rule.id.into(),
        title: rule.title.into(),
        severity: rule.severity.into(),
        confidence: rule.confidence.into(),
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
/// Document policy findings are limited to successful HTML documents; cookie
/// checks inspect bounded attribute flags, never cookie names or values.
pub(super) fn analyze(o: &Observation, rules: &[&str]) -> Vec<PassiveFinding> {
    let enabled = |index: usize| rules.contains(&RULES[index].id);
    let mut out = Vec::new();
    let document = o.status == 200 && o.html;
    if document {
        if !o.enforced_csp && enabled(CSP_MISSING) {
            out.push(finding(o, &RULES[CSP_MISSING],
                "A successful HTML response has no enforcing CSP header; report-only CSP does not enforce. Check application policy before treating this as exposure."));
        }
        if o.csp_report_only && !o.enforced_csp && enabled(CSP_REPORT_ONLY) {
            out.push(finding(o, &RULES[CSP_REPORT_ONLY],
                "A CSP-Report-Only header is present without an enforcing Content-Security-Policy; violations are reported but never blocked."));
        }
        if o.enforced_csp {
            if o.csp.unsafe_inline && enabled(CSP_UNSAFE_INLINE) {
                out.push(finding(o, &RULES[CSP_UNSAFE_INLINE],
                    "The effective script source list permits 'unsafe-inline'. A nonce or hash neutralizes this allowance in modern browsers; verify the full policy."));
            }
            if o.csp.unsafe_eval && enabled(CSP_UNSAFE_EVAL) {
                out.push(finding(o, &RULES[CSP_UNSAFE_EVAL],
                    "The effective script source list permits 'unsafe-eval'; confirm whether evaluating string code is required."));
            }
            if o.csp.wildcard && enabled(CSP_WILDCARD) {
                out.push(finding(o, &RULES[CSP_WILDCARD],
                    "The effective script source list contains '*', which permits scripts from arbitrary origins."));
            }
        }
        if !o.nosniff && enabled(NOSNIFF_MISSING) {
            out.push(finding(o, &RULES[NOSNIFF_MISSING],
                "The HTML response lacks X-Content-Type-Options: nosniff; confirm relevant browser MIME-handling behavior."));
        }
        if !o.framing_restricted && enabled(FRAME_PROTECTION) {
            out.push(finding(o, &RULES[FRAME_PROTECTION],
                "No effective DENY/SAMEORIGIN X-Frame-Options or restrictive CSP frame-ancestors policy was observed in the HTML response. Check whether this page is intended to be embedded."));
        }
        if !o.referrer_policy.is_present() && enabled(REFERRER_MISSING) {
            out.push(finding(o, &RULES[REFERRER_MISSING],
                "No Referrer-Policy header was observed; cross-origin navigations fall back to the browser default. Confirm the intended leakage level."));
        }
        if o.referrer_policy == ReferrerPolicy::UnsafeUrl && enabled(REFERRER_UNSAFE) {
            out.push(finding(o, &RULES[REFERRER_UNSAFE],
                "Referrer-Policy is 'unsafe-url', so full paths and query strings are sent to other origins, including over plaintext HTTP."));
        }
        if o.referrer_policy == ReferrerPolicy::Invalid && enabled(REFERRER_INVALID) {
            out.push(finding(o, &RULES[REFERRER_INVALID],
                "The Referrer-Policy value is not a recognized token and is ignored by browsers, leaving the default policy in force."));
        }
        if !o.permissions_policy && enabled(PERMISSIONS_MISSING) {
            out.push(finding(o, &RULES[PERMISSIONS_MISSING],
                "No Permissions-Policy header was observed; powerful browser features remain available to embedded content. Advisory hardening only."));
        }
        if !o.coop && enabled(COOP_MISSING) {
            out.push(finding(o, &RULES[COOP_MISSING],
                "No Cross-Origin-Opener-Policy header was observed, so this document may share a browsing-context group with cross-origin openers."));
        }
        if !o.charset_declared && enabled(CHARSET_MISSING) {
            out.push(finding(o, &RULES[CHARSET_MISSING],
                "The HTML Content-Type declares no charset parameter; encoding is then inferred, which can enable charset-dependent parsing behavior."));
        }
        if o.https {
            if !o.hsts {
                if enabled(HSTS_MISSING) {
                    out.push(finding(o, &RULES[HSTS_MISSING],
                        "HTTPS HTML response lacks a positive max-age Strict-Transport-Security policy; verify deployment-wide HTTPS before enabling."));
                }
            } else {
                if o.hsts_max_age.is_some_and(|age| age < 15_552_000) && enabled(HSTS_SHORT) {
                    out.push(finding(o, &RULES[HSTS_SHORT],
                        "Strict-Transport-Security max-age is below the commonly recommended 180 days; short policies leave a downgrade window."));
                }
                if !o.hsts_subdomains && enabled(HSTS_SUBDOMAINS) {
                    out.push(finding(o, &RULES[HSTS_SUBDOMAINS],
                        "Strict-Transport-Security omits includeSubDomains, so sibling subdomains are not covered. Confirm the wider policy is safe."));
                }
            }
        }
        if !o.cache_controlled && !o.cookies.is_empty() && enabled(CACHE_MISSING) {
            out.push(finding(o, &RULES[CACHE_MISSING],
                "A cookie-bearing HTML response has no no-store/private/no-cache directive, so shared caches may retain an authenticated document."));
        }
        if o.server_banner && enabled(SERVER_BANNER) {
            out.push(finding(o, &RULES[SERVER_BANNER],
                "A Server response header is present. Its value is intentionally withheld; confirm whether product and version disclosure is acceptable."));
        }
        if o.powered_by && enabled(POWERED_BY) {
            out.push(finding(o, &RULES[POWERED_BY],
                "A framework banner header is present (X-Powered-By or ASP.NET version). Values are withheld; suppress unnecessary technology disclosure."));
        }
        if o.legacy_xss_header && enabled(LEGACY_XSS) {
            out.push(finding(o, &RULES[LEGACY_XSS],
                "X-XSS-Protection is obsolete and ignored by current browsers; in older engines it could introduce side channels."));
        }
        if o.legacy_csp_header && enabled(LEGACY_CSP) {
            out.push(finding(o, &RULES[LEGACY_CSP],
                "A legacy X-Content-Security-Policy or X-WebKit-CSP header is present; modern browsers ignore it, so it does not enforce anything."));
        }
    }
    if !(200..400).contains(&o.status) {
        return out;
    }
    if !o.has_content_type && enabled(CONTENT_TYPE_MISSING) {
        out.push(finding(o, &RULES[CONTENT_TYPE_MISSING],
            "The response has no Content-Type header; browsers may MIME-sniff the body. Confirm how the endpoint is consumed."));
    }
    if o.acao == Acao::Wildcard && enabled(CORS_WILDCARD) {
        out.push(finding(o, &RULES[CORS_WILDCARD],
            "Access-Control-Allow-Origin is '*'. Browsers refuse to combine a wildcard with credentials, so this is only reportable if the data is not sensitive."));
    }
    if o.acao == Acao::Null && enabled(CORS_NULL) {
        out.push(finding(o, &RULES[CORS_NULL],
            "Access-Control-Allow-Origin is 'null', which sandboxed frames and local files can send. Verify whether credentialed reads are intended."));
    }
    // Aggregate each rule once per response to avoid disclosure of cookie
    // counts, names, values and duplicate findings for a cookie-heavy page.
    if enabled(COOKIE_SAMESITE) {
        if o.cookies
            .iter()
            .any(|cookie| cookie.same_site == SameSite::Invalid)
        {
            out.push(finding(o, &RULES[COOKIE_SAMESITE],
                "At least one Set-Cookie has an invalid SameSite value. Cookie names and values are intentionally withheld."));
        } else if o
            .cookies
            .iter()
            .any(|cookie| cookie.same_site == SameSite::None && !cookie.secure)
        {
            out.push(finding(o, &RULES[COOKIE_SAMESITE],
                "At least one Set-Cookie requests SameSite=None without Secure; browsers may reject it. No cookie values retained."));
        } else if o
            .cookies
            .iter()
            .any(|cookie| cookie.same_site == SameSite::Missing)
        {
            out.push(finding(o, &RULES[COOKIE_SAMESITE],
                "At least one Set-Cookie lacks an explicit SameSite policy. This is configuration guidance, not proof of CSRF."));
        }
    }
    if o.https && enabled(COOKIE_SECURE) && o.cookies.iter().any(|cookie| !cookie.secure) {
        out.push(finding(o, &RULES[COOKIE_SECURE],
            "An HTTPS response sets a cookie without Secure; browser transport behavior and the cookie's purpose require verification."));
    }
    if enabled(COOKIE_LOOSE_DOMAIN) && o.cookies.iter().any(|c| c.parent_domain) {
        out.push(finding(o, &RULES[COOKIE_LOOSE_DOMAIN],
            "A Set-Cookie Domain attribute is broader than the origin hostname. This scope heuristic needs browser and public-suffix validation; cookie names, values and domain strings are withheld."));
    }
    if enabled(COOKIE_HTTPONLY)
        && o.cookies
            .iter()
            .any(|cookie| cookie.session_named && !cookie.http_only)
    {
        out.push(finding(o, &RULES[COOKIE_HTTPONLY],
            "A cookie with a session-like name lacks HttpOnly. This name-based heuristic needs manual confirmation; neither the name nor value is recorded."));
    }
    if enabled(COOKIE_PREFIX) && o.cookies.iter().any(|cookie| cookie.prefix_violation) {
        out.push(finding(o, &RULES[COOKIE_PREFIX],
            "A cookie with a security prefix omits a required Secure, Path=/ or host-only attribute. Browsers reject such a cookie; its name and value are withheld."));
    }
    if enabled(COOKIE_LONG_LIVED) && o.cookies.iter().any(|cookie| cookie.long_lived_session) {
        out.push(finding(o, &RULES[COOKIE_LONG_LIVED],
            "A session-like cookie declares Max-Age beyond 30 days. Confirm the retention period matches the authentication policy."));
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
        let all: Vec<String> = RULES.iter().map(|rule| rule.id.into()).collect();
        assert_eq!(selected_rules(&all).unwrap().len(), RULES.len());
        let mut too_many = all.clone();
        too_many.push(RULES[0].id.into());
        assert!(selected_rules(&too_many).is_err());
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
        assert!(alerts.iter().any(|f| f.rule_id == RULES[CSP_MISSING].id));
        assert!(alerts
            .iter()
            .any(|f| f.rule_id == RULES[NOSNIFF_MISSING].id));
        assert!(alerts.iter().any(|f| f.rule_id == RULES[HSTS_MISSING].id));
        assert!(alerts
            .iter()
            .any(|f| f.rule_id == RULES[COOKIE_SAMESITE].id));
        assert!(alerts.iter().any(|f| f.rule_id == RULES[COOKIE_SECURE].id));
        assert!(alerts
            .iter()
            .any(|f| f.rule_id == RULES[COOKIE_HTTPONLY].id));
        let serialized = serde_json::to_string(&alerts).unwrap();
        assert!(!serialized.contains("TOPSECRET"));
        assert!(!serialized.contains("session="));
        assert!(!serialized.contains("private.invalid"));
    }
    #[test]
    fn clickjacking_policy_is_bounded_header_only_and_redacted() {
        let enabled = vec![RULES[FRAME_PROTECTION].id];
        let html = ("Content-Type".to_string(), "text/html".to_string());
        let leaked = ("X-Custom".to_string(), "SECRET_MARKER".to_string());
        let absent = observe(
            9,
            "https://private.invalid/secret?token=SECRET_MARKER",
            200,
            &[html.clone(), leaked],
        );
        let findings = analyze(&absent, &enabled);
        assert_eq!(findings.len(), 1);
        let rendered = serde_json::to_string(&findings).unwrap();
        assert!(!rendered.contains("SECRET_MARKER"));
        assert!(!rendered.contains("private.invalid"));
        assert!(!rendered.contains("token"));
        for protected in [
            vec![html.clone(), ("X-Frame-Options".into(), "DENY".into())],
            vec![
                html.clone(),
                ("X-Frame-Options".into(), "sameorigin".into()),
            ],
            vec![
                html.clone(),
                (
                    "Content-Security-Policy".into(),
                    "default-src 'self'; frame-ancestors 'none'".into(),
                ),
            ],
            vec![
                html.clone(),
                (
                    "Content-Security-Policy".into(),
                    "frame-ancestors 'self'".into(),
                ),
            ],
        ] {
            assert!(analyze(
                &observe(10, "https://private.invalid/", 200, &protected),
                &enabled
            )
            .is_empty());
        }
        for not_protected in [
            vec![
                html.clone(),
                (
                    "Content-Security-Policy-Report-Only".into(),
                    "frame-ancestors 'none'".into(),
                ),
            ],
            vec![html.clone(), ("X-Frame-Options".into(), "ALLOWALL".into())],
            vec![
                html.clone(),
                ("X-Frame-Options".into(), "DENY".into()),
                ("X-Frame-Options".into(), "SAMEORIGIN".into()),
            ],
            vec![
                html.clone(),
                ("Content-Security-Policy".into(), "frame-ancestors *".into()),
                ("X-Frame-Options".into(), "DENY".into()),
            ],
        ] {
            assert_eq!(
                analyze(
                    &observe(11, "https://private.invalid/", 200, &not_protected),
                    &enabled
                )
                .len(),
                1
            );
        }
        assert!(analyze(
            &observe(12, "https://private.invalid/", 204, &[html.clone()]),
            &enabled
        )
        .is_empty());
        assert!(analyze(
            &observe(
                13,
                "https://private.invalid/",
                200,
                &[("Content-Type".into(), "application/json".into())]
            ),
            &enabled
        )
        .is_empty());
    }

    #[test]
    fn parent_domain_cookie_rule_never_reports_secret_domain_or_values() {
        let enabled = vec![RULES[COOKIE_LOOSE_DOMAIN].id];
        let headers = vec![
            (
                "Set-Cookie".into(),
                "session=VERY_SECRET; Domain=.example.test; Path=/; HttpOnly; Secure".into(),
            ),
            ("Other".into(), "PRIVATE_INTERNAL_TOKEN".into()),
        ];
        let o = observe(
            28,
            "https://app.example.test/private?auth=PRIVATE_INTERNAL_TOKEN",
            200,
            &headers,
        );
        assert!(o.cookies[0].parent_domain);
        let alerts = analyze(&o, &enabled);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_id, RULES[COOKIE_LOOSE_DOMAIN].id);
        let serialized = serde_json::to_string(&alerts).unwrap();
        for secret in [
            "VERY_SECRET",
            "PRIVATE_INTERNAL_TOKEN",
            "example.test",
            "session=",
        ] {
            assert!(
                !serialized.contains(secret),
                "leaked confidential domain or cookie"
            );
        }
        for (url, domain) in [
            ("https://example.test", ".example.test"),
            ("https://other.test", "example.test"),
            ("https://127.0.0.1", "example.test"),
            ("https://subexample.test", "example.test"),
            ("https://sub.example.test", "test"),
            ("https://sub.example.test", "bad/domain"),
        ] {
            let observed = observe(
                30,
                url,
                200,
                &[(
                    "Set-Cookie".into(),
                    format!("session=secret; Domain={domain}"),
                )],
            );
            assert!(analyze(&observed, &enabled).is_empty(), "{url} {domain}");
        }
        let restricted = observe(
            32,
            "https://app.example.test/",
            200,
            &[(
                "Set-Cookie".into(),
                "session=SECRET; Domain=app.example.test; Secure".into(),
            )],
        );
        assert!(analyze(&restricted, &enabled).is_empty());
        assert!(analyze(
            &observe(33, "https://app.example.test/", 404, &headers),
            &enabled
        )
        .is_empty());
    }

    #[test]
    fn fully_hardened_document_and_non_document_produce_no_findings() {
        let enabled = RULES.iter().map(|x| x.id).collect::<Vec<_>>();
        let headers = vec![
            ("content-type".into(), "application/json".into()),
            (
                "set-cookie".into(),
                "session=redacted; HttpOnly; Secure; SameSite=Strict".into(),
            ),
            ("cache-control".into(), "no-store".into()),
        ];
        assert!(analyze(&observe(1, "https://private.test", 200, &headers), &enabled).is_empty());
        let headers = vec![
            ("content-type".into(), "text/html; charset=utf-8".into()),
            (
                "content-security-policy".into(),
                "default-src 'self'; frame-ancestors 'none'".into(),
            ),
            ("x-content-type-options".into(), "nosniff".into()),
            (
                "strict-transport-security".into(),
                "max-age=31536000; includeSubDomains".into(),
            ),
            ("x-frame-options".into(), "DENY".into()),
            (
                "referrer-policy".into(),
                "strict-origin-when-cross-origin".into(),
            ),
            ("permissions-policy".into(), "geolocation=()".into()),
            ("cross-origin-opener-policy".into(), "same-origin".into()),
            ("cache-control".into(), "no-store".into()),
        ];
        assert!(analyze(&observe(1, "https://private.test", 200, &headers), &enabled).is_empty());
        assert!(analyze(&observe(1, "https://private.test", 404, &[]), &enabled).is_empty());
    }

    #[test]
    fn csp_quality_referrer_and_disclosure_rules_are_header_only() {
        let enabled = RULES.iter().map(|x| x.id).collect::<Vec<_>>();
        let headers = vec![
            ("content-type".into(), "text/html; charset=utf-8".into()),
            (
                "content-security-policy".into(),
                "script-src 'self' 'unsafe-inline' *".into(),
            ),
            ("referrer-policy".into(), "unsafe-url".into()),
            ("server".into(), "SECRET_PRODUCT/9.9".into()),
            ("x-powered-by".into(), "SECRET_FRAMEWORK".into()),
            ("x-xss-protection".into(), "0".into()),
            ("x-webkit-csp".into(), "default-src *".into()),
            ("access-control-allow-origin".into(), "*".into()),
            ("x-secret".into(), "DO_NOT_LEAK".into()),
        ];
        let o = observe(
            44,
            "https://private.invalid/?token=DO_NOT_LEAK",
            200,
            &headers,
        );
        let alerts = analyze(&o, &enabled);
        for rule in [
            CSP_UNSAFE_INLINE,
            CSP_WILDCARD,
            REFERRER_UNSAFE,
            SERVER_BANNER,
            POWERED_BY,
            LEGACY_XSS,
            LEGACY_CSP,
            CORS_WILDCARD,
        ] {
            assert!(
                alerts.iter().any(|f| f.rule_id == RULES[rule].id),
                "missing {}",
                RULES[rule].id
            );
        }
        let rendered = serde_json::to_string(&alerts).unwrap();
        for secret in [
            "SECRET_PRODUCT",
            "SECRET_FRAMEWORK",
            "DO_NOT_LEAK",
            "private.invalid",
        ] {
            assert!(!rendered.contains(secret));
        }
        assert!(!alerts
            .iter()
            .any(|f| f.rule_id == RULES[CSP_UNSAFE_EVAL].id));
        let invalid = observe(
            45,
            "https://private.invalid/",
            200,
            &[
                ("content-type".into(), "text/html".into()),
                ("referrer-policy".into(), "sometimes".into()),
            ],
        );
        assert!(analyze(&invalid, &enabled)
            .iter()
            .any(|f| f.rule_id == RULES[REFERRER_INVALID].id));
    }

    #[test]
    fn cookie_prefix_and_lifetime_rules_never_echo_cookie_material() {
        let enabled = RULES.iter().map(|x| x.id).collect::<Vec<_>>();
        let headers = vec![
            ("content-type".into(), "text/html".into()),
            (
                "set-cookie".into(),
                "__Host-session=SECRET_VALUE; Domain=.example.test; Path=/admin; SameSite=Strict"
                    .into(),
            ),
            (
                "set-cookie".into(),
                "__Secure-auth=OTHER_SECRET; Max-Age=99999999; SameSite=Lax".into(),
            ),
        ];
        let o = observe(51, "https://app.example.test/", 200, &headers);
        assert!(o.cookies[0].prefix_violation);
        assert!(o.cookies[1].prefix_violation);
        assert!(o.cookies[1].long_lived_session);
        let alerts = analyze(&o, &enabled);
        assert!(alerts.iter().any(|f| f.rule_id == RULES[COOKIE_PREFIX].id));
        assert!(alerts
            .iter()
            .any(|f| f.rule_id == RULES[COOKIE_LONG_LIVED].id));
        let rendered = serde_json::to_string(&alerts).unwrap();
        for secret in [
            "SECRET_VALUE",
            "OTHER_SECRET",
            "__Host-",
            "__Secure-",
            "example.test",
        ] {
            assert!(!rendered.contains(secret), "leaked {secret}");
        }
        let compliant = observe(
            52,
            "https://app.example.test/",
            200,
            &[(
                "set-cookie".into(),
                "__Host-sid=VALUE; Secure; HttpOnly; Path=/; SameSite=Strict".into(),
            )],
        );
        assert!(!compliant.cookies[0].prefix_violation);
        assert!(!compliant.cookies[0].long_lived_session);
    }
}
