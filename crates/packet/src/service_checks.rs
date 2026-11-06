//! NSE-lite: bounded, banner-classifiable service checks.
//!
//! Deliberately NOT a scripting engine: a fixed registry of named checks
//! evaluated against one captured probe excerpt. Each check states its
//! evidence basis; a check that cannot classify from the excerpt reports
//! nothing rather than guessing. No network I/O happens here — the caller
//! supplies the probe excerpt from its own authorized interaction.

use serde::Serialize;

/// Hard registry and output bounds.
pub const MAX_CHECKS: usize = 16;
pub const MAX_FINDINGS: usize = 16;
pub const MAX_EXCERPT_BYTES: usize = 2048;

/// Severity aligned with the finding model used across the workbench.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckSeverity {
    Info,
    Low,
    Medium,
}

/// One named check's outcome on a probe excerpt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ServiceCheckFinding {
    pub check: &'static str,
    pub severity: CheckSeverity,
    /// The evidence line: what in the excerpt triggered the finding.
    pub evidence: String,
}

/// The probe excerpt context checks evaluate: what the service sent first
/// (banner or response head), lowercased for matching, bounded.
pub struct ProbeExcerpt<'a> {
    pub service: &'a str,
    pub port: u16,
    pub text: &'a str,
}

struct CheckDefinition {
    name: &'static str,
    severity: CheckSeverity,
    /// Returns Some(evidence) when the excerpt triggers this check.
    evaluate: fn(&ProbeExcerpt) -> Option<String>,
}

/// Port-aware fallback: some checks only apply to their well-known port so
/// a matching banner on an unrelated port does not mislabel the service.
fn port_matches(check_port: u16, excerpt: &ProbeExcerpt) -> bool {
    excerpt.port == check_port
}

static REGISTRY: [CheckDefinition; 8] = [
    CheckDefinition {
        name: "ssh-version-disclosure",
        severity: CheckSeverity::Info,
        evaluate: |excerpt| {
            // "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4" style banners name
            // the exact product and OS patch level to any unauthenticated
            // client. Evidence quotes the case-normalized banner head.
            if excerpt.text.starts_with("ssh-") {
                let head: String = excerpt.text.chars().take(64).collect();
                Some(format!("SSH banner discloses product identity: {head}"))
            } else {
                None
            }
        },
    },
    CheckDefinition {
        name: "ftp-banner-disclosure",
        severity: CheckSeverity::Info,
        evaluate: |excerpt| {
            if port_matches(21, excerpt) && excerpt.text.starts_with("220 ") {
                let head: String = excerpt.text.chars().take(64).collect();
                Some(format!("FTP banner discloses server identity: {head}"))
            } else {
                None
            }
        },
    },
    CheckDefinition {
        name: "http-server-version-disclosure",
        severity: CheckSeverity::Low,
        evaluate: |excerpt| {
            if excerpt.port != 80 && excerpt.port != 8080 {
                return None;
            }
            // "Server: nginx/1.18.0 (Ubuntu)" — exact version disclosure.
            for line in excerpt.text.lines() {
                let lower = line.to_ascii_lowercase();
                if let Some(value) = lower.strip_prefix("server:") {
                    if value.contains('/') {
                        return Some(format!(
                            "HTTP Server header discloses exact version: {}",
                            value.trim()
                        ));
                    }
                }
            }
            None
        },
    },
    CheckDefinition {
        name: "redis-unauthenticated-access",
        severity: CheckSeverity::Medium,
        evaluate: |excerpt| {
            // A Redis that answers PING with +PONG (or replies with a Redis
            // error shape) before any AUTH is effectively unauthenticated.
            if excerpt.text.starts_with("+pong") || excerpt.text.starts_with("-err unknown command") {
                Some("Redis answered an unauthenticated PING; the service exposes commands without AUTH".into())
            } else {
                None
            }
        },
    },
    CheckDefinition {
        name: "memcached-open-service",
        severity: CheckSeverity::Medium,
        evaluate: |excerpt| {
            // "STAT pid 1" style output reveals an open memcached instance.
            if excerpt.text.starts_with("stat pid ") {
                Some("memcached answered stats without authentication".into())
            } else {
                None
            }
        },
    },
    CheckDefinition {
        name: "mysql-version-disclosure",
        severity: CheckSeverity::Info,
        evaluate: |excerpt| {
            // MySQL/ MariaDB greeting: [00] ... version N.N.NN, port 3306.
            if port_matches(3306, excerpt) {
                if let Some(position) = excerpt.text.find("mariadb").or_else(|| excerpt.text.find("mysql")) {
                    let head: String = excerpt.text[position..].chars().take(48).collect();
                    return Some(format!("MySQL greeting discloses distribution/version: {head}"));
                }
            }
            None
        },
    },
    CheckDefinition {
        name: "telnet-cleartext-service",
        severity: CheckSeverity::Medium,
        evaluate: |excerpt| {
            // Telnet banners (23) confirm a cleartext remote shell service.
            if port_matches(23, excerpt) && !excerpt.text.is_empty() {
                Some("telnet service presents a cleartext login banner; credentials transit unencrypted".into())
            } else {
                None
            }
        },
    },
    CheckDefinition {
        name: "smtp-banner-disclosure",
        severity: CheckSeverity::Info,
        evaluate: |excerpt| {
            if port_matches(25, excerpt) && excerpt.text.starts_with("220-") || port_matches(25, excerpt) && excerpt.text.starts_with("220 ") {
                let head: String = excerpt.text.chars().take(64).collect();
                Some(format!("SMTP banner discloses MTA identity: {head}"))
            } else {
                None
            }
        },
    },
];

/// Evaluate the registry against one probe excerpt. Excerpts longer than
/// [`MAX_EXCERPT_BYTES`] are truncated before matching; the excerpt is
/// lowercased once for case-insensitive classification.
pub fn evaluate(service: &str, port: u16, raw_excerpt: &str) -> Vec<ServiceCheckFinding> {
    let truncated: String = raw_excerpt
        .chars()
        .take(MAX_EXCERPT_BYTES)
        .collect::<String>()
        .to_ascii_lowercase();
    let excerpt = ProbeExcerpt {
        service,
        port,
        text: &truncated,
    };
    let mut findings = Vec::new();
    for check in REGISTRY.iter().take(MAX_CHECKS) {
        if findings.len() >= MAX_FINDINGS {
            break;
        }
        if let Some(evidence) = (check.evaluate)(&excerpt) {
            findings.push(ServiceCheckFinding {
                check: check.name,
                severity: check.severity,
                evidence,
            });
        }
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_banner_disclosure_fires_with_product_identity() {
        let findings = evaluate("SSH", 22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].check, "ssh-version-disclosure");
        assert!(findings[0].evidence.contains("openssh_8.9p1"));
    }

    #[test]
    fn redis_unauthenticated_ping_is_medium_and_redis_errors_also_fire() {
        let pong = evaluate("Redis", 6379, "+PONG\r\n");
        assert_eq!(pong[0].check, "redis-unauthenticated-access");
        assert_eq!(pong[0].severity, CheckSeverity::Medium);
        let err = evaluate("Redis", 6379, "-ERR unknown command 'GET'\r\n");
        assert_eq!(err[0].check, "redis-unauthenticated-access");
    }

    #[test]
    fn http_server_header_with_version_is_low_severity() {
        let response = "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (Ubuntu)\r\n\r\n";
        let findings = evaluate("HTTP", 80, response);
        assert!(findings
            .iter()
            .any(|f| f.check == "http-server-version-disclosure" && f.severity == CheckSeverity::Low));
        // No version slash → no disclosure claim.
        let plain = evaluate("HTTP", 80, "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n");
        assert!(!plain.iter().any(|f| f.check == "http-server-version-disclosure"));
    }

    #[test]
    fn port_gated_checks_do_not_fire_on_other_ports() {
        // An FTP-shaped banner on 8080 is not an FTP finding.
        assert!(evaluate("HTTP", 8080, "220 proftpd ready\r\n").is_empty());
        // A MySQL greeting on the right port fires.
        assert!(!evaluate("MySQL", 3306, "8.0.32-0ubuntu2 mysql-8.0\r\n").is_empty());
    }

    #[test]
    fn memcached_telnet_and_smtp_checks_classify() {
        assert!(evaluate("Memcached", 11211, "STAT pid 1\r\n")
            .iter()
            .any(|f| f.check == "memcached-open-service"));
        assert!(evaluate("Telnet", 23, "Welcome to router-lab\r\n")
            .iter()
            .any(|f| f.check == "telnet-cleartext-service"));
        assert!(evaluate("SMTP", 25, "220 mail.lab.test Postfix ready\r\n")
            .iter()
            .any(|f| f.check == "smtp-banner-disclosure"));
    }

    #[test]
    fn excerpts_are_bounded_and_lowercased() {
        let long = "SSH-2.0-".to_string() + &"x".repeat(MAX_EXCERPT_BYTES + 64);
        let findings = evaluate("SSH", 22, &long);
        assert_eq!(findings.len(), 1);
        // Case-insensitive: uppercase PONG matches.
        assert!(!evaluate("Redis", 6379, "+PONG\r\n").is_empty());
    }

    #[test]
    fn benign_excerpts_produce_no_findings() {
        assert!(evaluate("HTTP", 443, "").is_empty());
        assert!(evaluate("TLS", 443, "\x16\x03\x03\x00\x4a\x02").is_empty());
    }
}
