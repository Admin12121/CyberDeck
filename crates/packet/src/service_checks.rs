//! NSE-lite: bounded, banner-classifiable service checks.
//!
//! Deliberately NOT a scripting engine: a fixed registry of named checks
//! evaluated against one captured probe excerpt. Each check states its
//! evidence basis; a check that cannot classify from the excerpt reports
//! nothing rather than guessing. No network I/O happens here — the caller
//! supplies the probe excerpt from its own authorized interaction.

use serde::Serialize;

/// Hard registry and output bounds. MAX_CHECKS bounds how many registry
/// entries are evaluated per excerpt; it must stay >= REGISTRY.len() so the
/// registry is never silently truncated — raise it when the registry grows.
pub const MAX_CHECKS: usize = 40;
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

/// One-line, bounded quotation of the triggering excerpt for evidence.
/// Evidence quotes what matched — never invented context — and the ellipsis
/// marks a line truncated for display.
fn quote_line(text: &str, max_chars: usize) -> String {
    let line = text.split(['\r', '\n']).next().unwrap_or(text);
    let mut quoted: String = line.chars().take(max_chars).collect();
    if line.chars().count() > max_chars {
        quoted.push('…');
    }
    quoted
}

/// True when the excerpt is non-empty and every captured byte was
/// non-printable (the wire path's sanitize_excerpt renders those as '?').
/// Binary protocol heads survive only as this marker shape; the octets
/// inside them do not survive, so evidence may name the framing shape but
/// never its field values.
fn is_non_printable_response(text: &str) -> bool {
    !text.is_empty() && !text.chars().any(|c| c != '?')
}

static REGISTRY: [CheckDefinition; 32] = [
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
            if excerpt.text.starts_with("+pong") || excerpt.text.starts_with("-err unknown command")
            {
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
                if let Some(position) = excerpt
                    .text
                    .find("mariadb")
                    .or_else(|| excerpt.text.find("mysql"))
                {
                    let head: String = excerpt.text[position..].chars().take(48).collect();
                    return Some(format!(
                        "MySQL greeting discloses distribution/version: {head}"
                    ));
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
            if port_matches(25, excerpt) && excerpt.text.starts_with("220-")
                || port_matches(25, excerpt) && excerpt.text.starts_with("220 ")
            {
                let head: String = excerpt.text.chars().take(64).collect();
                Some(format!("SMTP banner discloses MTA identity: {head}"))
            } else {
                None
            }
        },
    },
    CheckDefinition {
        name: "pop3-banner-disclosure",
        severity: CheckSeverity::Info,
        evaluate: |excerpt| {
            if port_matches(110, excerpt) && excerpt.text.starts_with("+ok") {
                let head: String = excerpt.text.chars().take(64).collect();
                Some(format!("POP3 banner discloses server identity: {head}"))
            } else {
                None
            }
        },
    },
    CheckDefinition {
        name: "imap-capability-disclosure",
        severity: CheckSeverity::Info,
        evaluate: |excerpt| {
            // "* OK [CAPABILITY IMAP4rev1 ...]" enumerates the server's
            // supported extensions before any authentication.
            if port_matches(143, excerpt)
                && excerpt.text.starts_with("* ok")
                && excerpt.text.contains("capability")
            {
                let head: String = excerpt.text.chars().take(80).collect();
                Some(format!("IMAP pre-auth capability disclosure: {head}"))
            } else {
                None
            }
        },
    },
    CheckDefinition {
        name: "vnc-weak-protocol",
        severity: CheckSeverity::Medium,
        evaluate: |excerpt| {
            // RFB 003.008 predates the tighter 004/005 auth pairings; VNC's
            // challenge-response has well-known weaknesses either way.
            if port_matches(5900, excerpt) && excerpt.text.starts_with("rfb 003.") {
                Some("VNC RFB 3.x handshake: legacy authentication model on a remote-control service".into())
            } else {
                None
            }
        },
    },
    CheckDefinition {
        name: "docker-api-unauthenticated",
        severity: CheckSeverity::Medium,
        evaluate: |excerpt| {
            // An unauthenticated Docker Engine API (2375) returns the index
            // JSON on GET / — full container control with no TLS and no auth.
            if port_matches(2375, excerpt)
                && (excerpt.text.contains("docker") || excerpt.text.contains("/v1."))
            {
                Some("Docker Engine API answered without authentication; container control is exposed unencrypted".into())
            } else {
                None
            }
        },
    },
    CheckDefinition {
        name: "elasticsearch-cluster-disclosure",
        severity: CheckSeverity::Low,
        evaluate: |excerpt| {
            if port_matches(9200, excerpt) && excerpt.text.contains("cluster_name") {
                Some("Elasticsearch root index discloses cluster metadata (cluster_name, version) without authentication".into())
            } else {
                None
            }
        },
    },
    // --- wave 5 additions: honest banner-classifiable checks -------------------
    CheckDefinition {
        name: "ssh-protocol-1-deprecated",
        severity: CheckSeverity::Medium,
        evaluate: |excerpt| {
            // "SSH-1.99-…" (or SSH-1.x) announces support for SSH protocol
            // version 1, which is cryptographically deprecated (CRC-32
            // integrity flaws). Advertising it pre-auth is a real exposure,
            // not just identity disclosure. Not port-gated: the version
            // string is protocol-specific wherever it appears.
            if excerpt.text.starts_with("ssh-1.") {
                Some(format!(
                    "SSH banner negotiates deprecated protocol version 1: {}",
                    quote_line(excerpt.text, 48)
                ))
            } else {
                None
            }
        },
    },
    CheckDefinition {
        name: "smtp-auth-disclosure",
        severity: CheckSeverity::Low,
        evaluate: |excerpt| {
            // EHLO capability lines ("250-AUTH PLAIN LOGIN") enumerate the
            // authentication mechanisms an attacker can target before any
            // TLS is negotiated. Gated to SMTP ports so a stray "auth" in
            // another protocol's banner does not mislabel it.
            if excerpt.port == 25 || excerpt.port == 587 {
                for line in excerpt.text.lines() {
                    if (line.starts_with("250-") || line.starts_with("250 "))
                        && line.contains("auth")
                    {
                        return Some(format!(
                            "SMTP advertises authentication mechanisms before TLS: {}",
                            quote_line(line, 64)
                        ));
                    }
                }
            }
            None
        },
    },
    CheckDefinition {
        name: "smtp-cleartext-capabilities",
        severity: CheckSeverity::Medium,
        evaluate: |excerpt| {
            // Only a COMPLETE EHLO capability reply (multiline "250-…" list
            // terminated by a "250 " line) supports the conclusion that the
            // server offered no STARTTLS — a truncated head excerpt must not
            // invent the absence of an extension. Cleartext SMTP means
            // credentials transit unencrypted.
            if (excerpt.port == 25 || excerpt.port == 587)
                && excerpt.text.contains("250-")
                && excerpt.text.contains("250 ")
                && !excerpt.text.contains("starttls")
            {
                Some(format!(
                    "SMTP capability reply lists no STARTTLS; session stays cleartext: {}",
                    quote_line(excerpt.text, 64)
                ))
            } else {
                None
            }
        },
    },
    CheckDefinition {
        name: "ftp-anonymous-hint",
        severity: CheckSeverity::Info,
        evaluate: |excerpt| {
            // A 220 greeting that names anonymous access advertises the
            // credential path an operator must audit; it is a hint, not
            // proof of writable access.
            if port_matches(21, excerpt)
                && excerpt.text.starts_with("220")
                && excerpt.text.contains("anonymous")
            {
                Some(format!(
                    "FTP banner advertises anonymous access: {}",
                    quote_line(excerpt.text, 64)
                ))
            } else {
                None
            }
        },
    },
    CheckDefinition {
        name: "memcached-version-disclosure",
        severity: CheckSeverity::Info,
        evaluate: |excerpt| {
            // "VERSION 1.6.14\r\n" is the memcached reply to a version probe
            // and names the exact build; gated to 11211.
            if port_matches(11211, excerpt) && excerpt.text.starts_with("version ") {
                Some(format!(
                    "memcached VERSION reply discloses exact build: {}",
                    quote_line(excerpt.text, 40)
                ))
            } else {
                None
            }
        },
    },
    CheckDefinition {
        name: "redis-protected-mode-disclosure",
        severity: CheckSeverity::Info,
        evaluate: |excerpt| {
            // RESP error strings "-NOAUTH Authentication required" and
            // "-WRONGPASS …" prove the server answers unauthenticated
            // clients and that a password IS configured. Auth is enforced,
            // so this is configuration disclosure, not access. Not
            // port-gated, matching the sibling redis check's RESP-shape rule.
            if excerpt.text.starts_with("-noauth") || excerpt.text.starts_with("-wrongpass") {
                Some(format!(
                    "Redis RESP error discloses password enforcement while still answering unauthenticated: {}",
                    quote_line(excerpt.text, 64)
                ))
            } else {
                None
            }
        },
    },
    CheckDefinition {
        name: "mongodb-server-disclosure",
        severity: CheckSeverity::Info,
        evaluate: |excerpt| {
            // hello/isMaster wire replies embed "maxWireVersion"; the 28017
            // HTTP status page prints "MongoDB". Either marker names the
            // service honestly. Gated to the mongod + status ports.
            if excerpt.port == 27017 || excerpt.port == 28017 {
                let at = excerpt
                    .text
                    .find("mongodb")
                    .or_else(|| excerpt.text.find("maxwireversion"));
                if let Some(at) = at {
                    return Some(format!(
                        "MongoDB reply discloses server identity: {}",
                        quote_line(&excerpt.text[at..], 48)
                    ));
                }
            }
            None
        },
    },
    CheckDefinition {
        name: "postgresql-error-disclosure",
        severity: CheckSeverity::Info,
        evaluate: |excerpt| {
            // PostgreSQL answers malformed startup bytes with an
            // ErrorResponse whose payload is printable text, e.g. "invalid
            // startup packet layout: expected startup packet" or
            // "unsupported frontend protocol 1234.5678: server supports
            // 3.0 to 3.0" — the payload names both the product and its
            // protocol constraints. Gated to 5432.
            if port_matches(5432, excerpt) {
                let at = excerpt
                    .text
                    .find("invalid startup packet layout")
                    .or_else(|| excerpt.text.find("unsupported frontend protocol"));
                if let Some(at) = at {
                    return Some(format!(
                        "PostgreSQL error reply discloses protocol constraints: {}",
                        quote_line(&excerpt.text[at..], 72)
                    ));
                }
            }
            None
        },
    },
    CheckDefinition {
        name: "postgresql-auth-request-shape",
        severity: CheckSeverity::Info,
        evaluate: |excerpt| {
            // Authentication exchanges are binary 'R'-messages ('R' +
            // 4-byte length + auth-code). 'R' survives the wire path's
            // sanitizer; the length/code octets do not. "r?????" is honest
            // evidence of an auth exchange, and nothing more — the method
            // code (cleartext vs md5 vs ok) is NOT recoverable, so no claim
            // beyond the exchange itself is made here. Gated to 5432.
            if port_matches(5432, excerpt) && excerpt.text.starts_with("r?????") {
                Some(format!(
                    "PostgreSQL authentication exchange (R-message head) received; method code not recoverable from the sanitized excerpt: {}",
                    quote_line(excerpt.text, 12)
                ))
            } else {
                None
            }
        },
    },
    CheckDefinition {
        name: "mysql-auth-plugin-disclosure",
        severity: CheckSeverity::Info,
        evaluate: |excerpt| {
            // The MySQL/MariaDB greeting carries the default authentication
            // plugin name as printable trailing text ("mysql_native_password",
            // "caching_sha2_password", …) — enumerating the credential
            // scheme before any authentication. Gated to 3306.
            if port_matches(3306, excerpt) {
                for plugin in [
                    "caching_sha2_password",
                    "mysql_native_password",
                    "sha256_password",
                    "auth_gssapi_client",
                ] {
                    if let Some(at) = excerpt.text.find(plugin) {
                        return Some(format!(
                            "MySQL greeting discloses the default authentication plugin: {}",
                            quote_line(&excerpt.text[at..], 40)
                        ));
                    }
                }
            }
            None
        },
    },
    CheckDefinition {
        name: "cassandra-protocol-error-disclosure",
        severity: CheckSeverity::Info,
        evaluate: |excerpt| {
            // Cassandra answers invalid startup frames with an ERROR message
            // whose payload is printable text: "Invalid or unsupported
            // protocol version (…); supported versions are (3/v3, 4/v4, …)".
            // The error text names the product and its protocol range.
            // Gated to 9042.
            if port_matches(9042, excerpt)
                && (excerpt
                    .text
                    .contains("invalid or unsupported protocol version")
                    || excerpt.text.contains("supported versions are"))
            {
                Some(format!(
                    "Cassandra native protocol error discloses supported versions: {}",
                    quote_line(excerpt.text, 72)
                ))
            } else {
                None
            }
        },
    },
    CheckDefinition {
        name: "rabbitmq-amqp-negotiation-disclosure",
        severity: CheckSeverity::Info,
        evaluate: |excerpt| {
            // The AMQP 0-9-1 server opens with a literal "AMQP" followed by
            // the protocol version octets (00 00 09 01 → 0-9-1); the
            // sanitizer keeps "amqp" and renders the octets as '?'. The head
            // is protocol-specific wherever it appears, so no port gate.
            if excerpt.text.starts_with("amqp") {
                Some(format!(
                    "AMQP connection negotiation head discloses the broker protocol: {}",
                    quote_line(excerpt.text, 24)
                ))
            } else {
                None
            }
        },
    },
    CheckDefinition {
        name: "kerberos-kdc-error-response",
        severity: CheckSeverity::Info,
        evaluate: |excerpt| {
            // TCP Kerberos replies carry a 4-byte length prefix then the DER
            // APPLICATION-30 KRB-ERROR tag 0x7e ('~'), which is printable
            // and survives sanitization. "????~" is honest evidence of a
            // KRB-ERROR record; the error code itself is not recoverable.
            // AS-REP/AS-REQ tags (0x6b/0x6a) do not match. Gated to 88.
            if port_matches(88, excerpt) && excerpt.text.starts_with("????~") {
                Some(format!(
                    "Kerberos KDC replied with a KRB-ERROR record (0x7e DER tag); error code not recoverable from the sanitized excerpt: {}",
                    quote_line(excerpt.text, 12)
                ))
            } else {
                None
            }
        },
    },
    CheckDefinition {
        name: "rpc-binary-response",
        severity: CheckSeverity::Info,
        evaluate: |excerpt| {
            // ONC RPC (portmapper 111, NFS 2049) replies are XDR binary, so
            // only the all-non-printable marker shape survives. The port
            // gate plus that shape honestly confirms a binary RPC responder;
            // message type and program numbers are not recoverable.
            if (excerpt.port == 111 || excerpt.port == 2049)
                && is_non_printable_response(excerpt.text)
            {
                Some(format!(
                    "non-printable response on port {} consistent with an ONC RPC responder (portmapper/NFS); XDR fields not recoverable from the sanitized excerpt: {}",
                    excerpt.port,
                    quote_line(excerpt.text, 12)
                ))
            } else {
                None
            }
        },
    },
    CheckDefinition {
        name: "ldap-binary-response",
        severity: CheckSeverity::Info,
        evaluate: |excerpt| {
            // LDAP replies are BER-encoded; a notice-of-disconnection or
            // bind reply begins with the SEQUENCE tag 0x30 ('0' survives
            // sanitization) followed by length/content octets rendered as
            // '?'. "0???" on 389 is honest evidence of a BER responder —
            // the bind result code is NOT recoverable, so no claim about
            // unauthenticated binds is made. Gated to 389.
            if port_matches(389, excerpt) && excerpt.text.starts_with("0???") {
                Some(format!(
                    "LDAP port answered with a BER-encoded reply head (0x30 SEQUENCE tag); bind result not recoverable from the sanitized excerpt: {}",
                    quote_line(excerpt.text, 12)
                ))
            } else {
                None
            }
        },
    },
    CheckDefinition {
        name: "rdp-binary-response",
        severity: CheckSeverity::Info,
        evaluate: |excerpt| {
            // RDP speaks X.224/TPKT framing whose bytes are all
            // non-printable, so the sanitizer leaves only '?' markers. The
            // port gate plus that shape is honest evidence of a binary
            // protocol speaking on the RDP port; negotiation bytes
            // (PROTOCOL_HYBRID etc.) are NOT recoverable, so no claim about
            // NLA or encryption level is made. Gated to 3389.
            if port_matches(3389, excerpt) && is_non_printable_response(excerpt.text) {
                Some(format!(
                    "port 3389 answered with a non-printable response consistent with RDP X.224/TPKT framing; negotiation bytes not recoverable from the sanitized excerpt: {}",
                    quote_line(excerpt.text, 12)
                ))
            } else {
                None
            }
        },
    },
    CheckDefinition {
        name: "sip-response-disclosure",
        severity: CheckSeverity::Info,
        evaluate: |excerpt| {
            // "SIP/2.0 <status>" response heads plus their Server/User-Agent
            // headers name the SIP stack and often the UA product; SIP
            // requests (REGISTER/INVITE) do not match. Gated to 5060.
            if port_matches(5060, excerpt) && excerpt.text.starts_with("sip/2.0") {
                Some(format!(
                    "SIP response discloses server/UA identity: {}",
                    quote_line(excerpt.text, 64)
                ))
            } else {
                None
            }
        },
    },
    CheckDefinition {
        name: "http-allow-method-disclosure",
        severity: CheckSeverity::Low,
        evaluate: |excerpt| {
            // "Allow: GET, POST, DELETE" in an OPTIONS/405 response
            // enumerates the mutable methods the origin accepts, mapping
            // the write surface for an attacker. Gated to the cleartext
            // HTTP ports like the sibling http check.
            if excerpt.port == 80 || excerpt.port == 8080 {
                for line in excerpt.text.lines() {
                    if line.starts_with("allow:")
                        && (line.contains("delete") || line.contains("put"))
                    {
                        return Some(format!(
                            "HTTP Allow header discloses mutable methods: {}",
                            quote_line(line, 48)
                        ));
                    }
                }
            }
            None
        },
    },
    CheckDefinition {
        name: "imap-cleartext-capabilities",
        severity: CheckSeverity::Medium,
        evaluate: |excerpt| {
            // Only a COMPLETE pre-auth capability line ("…]") supports the
            // conclusion that STARTTLS is absent — a truncated excerpt must
            // not invent the absence. STARTTLS-less IMAP means credentials
            // would transit unencrypted. Complements the Info-level sibling
            // imap-capability-disclosure.
            if port_matches(143, excerpt) {
                for line in excerpt.text.lines() {
                    if line.starts_with("* ok")
                        && line.contains("capability")
                        && line.contains(']')
                        && !line.contains("starttls")
                    {
                        return Some(format!(
                            "IMAP pre-auth capabilities list no STARTTLS; authentication would transit cleartext: {}",
                            quote_line(line, 72)
                        ));
                    }
                }
            }
            None
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
        assert!(findings.iter().any(
            |f| f.check == "http-server-version-disclosure" && f.severity == CheckSeverity::Low
        ));
        // No version slash → no disclosure claim.
        let plain = evaluate("HTTP", 80, "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n");
        assert!(!plain
            .iter()
            .any(|f| f.check == "http-server-version-disclosure"));
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
    fn pop3_imap_vnc_docker_elasticsearch_checks_classify() {
        assert!(evaluate("POP3", 110, "+OK POP3 lab.test server ready\r\n")
            .iter()
            .any(|f| f.check == "pop3-banner-disclosure"));
        assert!(evaluate(
            "IMAP",
            143,
            "* OK [CAPABILITY IMAP4rev1 STARTTLS] ready\r\n"
        )
        .iter()
        .any(|f| f.check == "imap-capability-disclosure"));
        let vnc = evaluate("VNC", 5900, "RFB 003.008\r\n");
        assert_eq!(vnc[0].check, "vnc-weak-protocol");
        assert_eq!(vnc[0].severity, CheckSeverity::Medium);
        let docker = evaluate("HTTP", 2375, "{\"message\":\"Docker index\"}");
        assert_eq!(docker[0].check, "docker-api-unauthenticated");
        assert!(
            evaluate("HTTP", 9200, "{\"cluster_name\":\"lab\",\"version\":{}}")
                .iter()
                .any(|f| f.check == "elasticsearch-cluster-disclosure")
        );
    }

    #[test]
    fn benign_excerpts_produce_no_findings() {
        assert!(evaluate("HTTP", 443, "").is_empty());
        assert!(evaluate("TLS", 443, "\x16\x03\x03\x00\x4a\x02").is_empty());
    }

    // --- wave 5 check tests: trigger + no-trigger per check ---------------------

    #[test]
    fn registry_is_fully_evaluated_within_max_checks() {
        // MAX_CHECKS exists to bound work, not to hide checks: every
        // registered check must stay reachable, so the cap is >= registry size.
        assert_eq!(REGISTRY.len(), 32);
        assert!(REGISTRY.len() <= MAX_CHECKS);
    }

    #[test]
    fn ssh_protocol_1_banner_is_medium_and_v2_does_not_trigger() {
        let v1 = evaluate("SSH", 22, "SSH-1.99-OpenSSH_2.9p1\r\n");
        let hit = v1
            .iter()
            .find(|f| f.check == "ssh-protocol-1-deprecated")
            .expect("SSH-1.99 banner should fire the deprecation check");
        assert_eq!(hit.severity, CheckSeverity::Medium);
        assert!(hit.evidence.contains("ssh-1.99"));
        assert!(!evaluate("SSH", 22, "SSH-2.0-OpenSSH_8.9p1\r\n")
            .iter()
            .any(|f| f.check == "ssh-protocol-1-deprecated"));
    }

    #[test]
    fn redis_protected_mode_error_discloses_auth_enforcement() {
        let noauth = evaluate("Redis", 6379, "-NOAUTH Authentication required.\r\n");
        let hit = noauth
            .iter()
            .find(|f| f.check == "redis-protected-mode-disclosure")
            .expect("NOAUTH error should disclose password enforcement");
        assert_eq!(hit.severity, CheckSeverity::Info);
        assert!(hit.evidence.contains("-noauth"));
        // A generic Redis error does not disclose password enforcement.
        assert!(!evaluate("Redis", 6379, "-ERR unknown command 'GET'\r\n")
            .iter()
            .any(|f| f.check == "redis-protected-mode-disclosure"));
    }

    #[test]
    fn memcached_version_reply_is_port_gated() {
        let findings = evaluate("Memcached", 11211, "VERSION 1.6.14\r\n");
        let hit = findings
            .iter()
            .find(|f| f.check == "memcached-version-disclosure")
            .expect("VERSION reply should disclose the build");
        assert_eq!(hit.severity, CheckSeverity::Info);
        assert!(hit.evidence.contains("1.6.14"));
        // Same reply on an unrelated port is not memcached evidence.
        assert!(evaluate("Unknown", 9999, "VERSION 1.6.14\r\n")
            .iter()
            .all(|f| f.check != "memcached-version-disclosure"));
        // Non-version replies make no build claim.
        assert!(evaluate("Memcached", 11211, "STORED\r\n")
            .iter()
            .all(|f| f.check != "memcached-version-disclosure"));
    }

    #[test]
    fn mongodb_identity_markers_are_port_gated() {
        let hello = evaluate(
            "MongoDB",
            27017,
            "{\"maxWireVersion\":17,\"maxBsonObjectSize\":16777216}\r\n",
        );
        let hit = hello
            .iter()
            .find(|f| f.check == "mongodb-server-disclosure")
            .expect("maxWireVersion marker should name MongoDB");
        assert_eq!(hit.severity, CheckSeverity::Info);
        assert!(hit.evidence.contains("maxwireversion"));
        assert!(evaluate("HTTP", 28017, "<h1> mongodb status </h1>")
            .iter()
            .any(|f| f.check == "mongodb-server-disclosure"));
        // Same markers on an unrelated port do not name MongoDB.
        assert!(!evaluate("HTTP", 8080, "{\"maxWireVersion\":17}")
            .iter()
            .any(|f| f.check == "mongodb-server-disclosure"));
    }

    #[test]
    fn smtp_auth_advertisement_fires_only_in_capability_lines() {
        let caps = evaluate(
            "SMTP",
            25,
            "220 mail.lab.test ESMTP\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n",
        );
        let hit = caps
            .iter()
            .find(|f| f.check == "smtp-auth-disclosure")
            .expect("AUTH advertisement should fire");
        assert_eq!(hit.severity, CheckSeverity::Low);
        assert!(hit.evidence.contains("250-auth"));
        // No AUTH advertisement in the capability lines → no claim.
        assert!(!evaluate(
            "SMTP",
            25,
            "220 mail.lab.test ESMTP\r\n250-8BITMIME\r\n250 SIZE\r\n"
        )
        .iter()
        .any(|f| f.check == "smtp-auth-disclosure"));
    }

    #[test]
    fn smtp_cleartext_capabilities_requires_complete_capability_list() {
        let complete = evaluate(
            "SMTP",
            25,
            "250-mail.lab.test\r\n250-AUTH PLAIN\r\n250 8BITMIME\r\n",
        );
        let hit = complete
            .iter()
            .find(|f| f.check == "smtp-cleartext-capabilities")
            .expect("complete capability list without STARTTLS should fire");
        assert_eq!(hit.severity, CheckSeverity::Medium);
        // A complete list offering STARTTLS does not claim cleartext.
        assert!(!evaluate(
            "SMTP",
            25,
            "250-mail.lab.test\r\n250-STARTTLS\r\n250 AUTH PLAIN\r\n"
        )
        .iter()
        .any(|f| f.check == "smtp-cleartext-capabilities"));
        // A truncated list must not invent the absence of STARTTLS.
        assert!(!evaluate(
            "SMTP",
            25,
            "250-mail.lab.test\r\n250-AUTH PLAIN\r\n250-8BITMIME\r\n"
        )
        .iter()
        .any(|f| f.check == "smtp-cleartext-capabilities"));
    }

    #[test]
    fn ftp_anonymous_hint_requires_explicit_wording() {
        let hint = evaluate("FTP", 21, "220 lab FTP ready. Anonymous login allowed\r\n");
        let hit = hint
            .iter()
            .find(|f| f.check == "ftp-anonymous-hint")
            .expect("banner naming anonymous access should fire");
        assert_eq!(hit.severity, CheckSeverity::Info);
        assert!(hit.evidence.contains("anonymous"));
        assert!(!evaluate("FTP", 21, "220 proftpd ready\r\n")
            .iter()
            .any(|f| f.check == "ftp-anonymous-hint"));
    }

    #[test]
    fn rdp_binary_response_is_port_gated_and_shape_gated() {
        let binary = evaluate("RDP", 3389, "????????????");
        let hit = binary
            .iter()
            .find(|f| f.check == "rdp-binary-response")
            .expect("non-printable response on 3389 should fire");
        assert_eq!(hit.severity, CheckSeverity::Info);
        // Printable text on 3389 is not X.224 framing evidence.
        assert!(!evaluate("HTTP", 3389, "HTTP/1.1 400 bad request\r\n")
            .iter()
            .any(|f| f.check == "rdp-binary-response"));
        // Binary on an unrelated port does not name RDP.
        assert!(!evaluate("Unknown", 9999, "????????????")
            .iter()
            .any(|f| f.check == "rdp-binary-response"));
    }

    #[test]
    fn cassandra_protocol_error_discloses_supported_versions() {
        let err = evaluate(
            "Cassandra",
            9042,
            "Invalid or unsupported protocol version (99); supported versions are (3/v3, 4/v4, 5/v5)",
        );
        let hit = err
            .iter()
            .find(|f| f.check == "cassandra-protocol-error-disclosure")
            .expect("protocol-version error text should fire");
        assert_eq!(hit.severity, CheckSeverity::Info);
        assert!(hit.evidence.contains("supported versions"));
        // Binary-only responses carry no recoverable version claim.
        assert!(!evaluate("Cassandra", 9042, "?????????")
            .iter()
            .any(|f| f.check == "cassandra-protocol-error-disclosure"));
    }

    #[test]
    fn rabbitmq_amqp_negotiation_head_discloses_protocol() {
        let amqp = evaluate("RabbitMQ", 5672, "AMQP\x00\x00\x09\x01");
        let hit = amqp
            .iter()
            .find(|f| f.check == "rabbitmq-amqp-negotiation-disclosure")
            .expect("AMQP negotiation head should fire");
        assert_eq!(hit.severity, CheckSeverity::Info);
        assert!(hit.evidence.contains("amqp"));
        // Plain text that merely mentions amqp is not a negotiation head.
        assert!(!evaluate("TCP", 9999, "hello amqp server\r\n")
            .iter()
            .any(|f| f.check == "rabbitmq-amqp-negotiation-disclosure"));
    }

    #[test]
    fn mysql_greeting_discloses_auth_plugin() {
        let greeting =
            "5.7.40-log\x00lab\x00\x42\x0d\x00\x00\x00\x00\x08\x0c\x0e\x00mysql_native_password\x00";
        let findings = evaluate("MySQL", 3306, greeting);
        let hit = findings
            .iter()
            .find(|f| f.check == "mysql-auth-plugin-disclosure")
            .expect("greeting plugin name should fire");
        assert_eq!(hit.severity, CheckSeverity::Info);
        assert!(hit.evidence.contains("mysql_native_password"));
        // Greeting without a plugin name makes no plugin claim.
        assert!(!evaluate("MySQL", 3306, "8.0.32-0ubuntu2 mysql-8.0\r\n")
            .iter()
            .any(|f| f.check == "mysql-auth-plugin-disclosure"));
    }

    #[test]
    fn postgresql_error_reply_discloses_protocol_constraints() {
        let err = evaluate(
            "PostgreSQL",
            5432,
            "FATAL:  invalid startup packet layout: expected startup packet",
        );
        let hit = err
            .iter()
            .find(|f| f.check == "postgresql-error-disclosure")
            .expect("startup-packet error text should fire");
        assert_eq!(hit.severity, CheckSeverity::Info);
        assert!(hit.evidence.contains("invalid startup packet layout"));
        // Other text on 5432 makes no PostgreSQL protocol claim.
        assert!(!evaluate("HTTP", 5432, "HTTP/1.1 200 OK\r\n")
            .iter()
            .any(|f| f.check == "postgresql-error-disclosure"));
    }

    #[test]
    fn postgresql_auth_request_shape_is_binary_shaped_and_port_gated() {
        let auth = evaluate("PostgreSQL", 5432, "r????????z????");
        let hit = auth
            .iter()
            .find(|f| f.check == "postgresql-auth-request-shape")
            .expect("R-message head shape should fire");
        assert_eq!(hit.severity, CheckSeverity::Info);
        assert!(hit.evidence.contains("r????"));
        // Text replies are not R-message heads.
        assert!(!evaluate("PostgreSQL", 5432, "ready for queries\r\n")
            .iter()
            .any(|f| f.check == "postgresql-auth-request-shape"));
        // Same shape on an unrelated port does not name PostgreSQL.
        assert!(!evaluate("Unknown", 9999, "r????????")
            .iter()
            .any(|f| f.check == "postgresql-auth-request-shape"));
    }

    #[test]
    fn kerberos_kdc_error_tag_is_port_gated() {
        let krb = evaluate("Kerberos", 88, "????~?????????");
        let hit = krb
            .iter()
            .find(|f| f.check == "kerberos-kdc-error-response")
            .expect("KRB-ERROR tag shape on 88 should fire");
        assert_eq!(hit.severity, CheckSeverity::Info);
        assert!(hit.evidence.contains("????~"));
        // The AS-REP tag (0x6b) is not a KRB-ERROR claim.
        assert!(!evaluate("Kerberos", 88, "????k?????????")
            .iter()
            .any(|f| f.check == "kerberos-kdc-error-response"));
        // Same shape on an unrelated port does not name the KDC.
        assert!(!evaluate("Unknown", 9999, "????~?????????")
            .iter()
            .any(|f| f.check == "kerberos-kdc-error-response"));
    }

    #[test]
    fn rpc_binary_response_gated_to_portmapper_and_nfs_ports() {
        for port in [111, 2049] {
            let findings = evaluate("RPC", port, "????????????????");
            let hit = findings
                .iter()
                .find(|f| f.check == "rpc-binary-response")
                .expect("binary response on an RPC port should fire");
            assert_eq!(hit.severity, CheckSeverity::Info);
        }
        // Printable text is not XDR evidence.
        assert!(!evaluate("RPC", 111, "hello\r\n")
            .iter()
            .any(|f| f.check == "rpc-binary-response"));
        // Binary on unrelated ports does not name RPC.
        assert!(!evaluate("Unknown", 9999, "????????????????")
            .iter()
            .any(|f| f.check == "rpc-binary-response"));
    }

    #[test]
    fn ldap_binary_reply_head_gated_to_389() {
        let ldap = evaluate("LDAP", 389, "0????????????");
        let hit = ldap
            .iter()
            .find(|f| f.check == "ldap-binary-response")
            .expect("BER SEQUENCE head on 389 should fire");
        assert_eq!(hit.severity, CheckSeverity::Info);
        assert!(hit.evidence.contains("0???"));
        // "0x…" style text is not a BER head.
        assert!(!evaluate("LDAP", 389, "0x1f text reply\r\n")
            .iter()
            .any(|f| f.check == "ldap-binary-response"));
        assert!(!evaluate("Unknown", 9999, "0????????????")
            .iter()
            .any(|f| f.check == "ldap-binary-response"));
    }

    #[test]
    fn sip_response_head_discloses_identity() {
        let sip = evaluate("SIP", 5060, "SIP/2.0 200 OK\r\nServer: kamailio/5.5\r\n");
        let hit = sip
            .iter()
            .find(|f| f.check == "sip-response-disclosure")
            .expect("SIP/2.0 response head should fire");
        assert_eq!(hit.severity, CheckSeverity::Info);
        assert!(hit.evidence.contains("sip/2.0"));
        // SIP requests (REGISTER/INVITE) are not responses.
        assert!(!evaluate("SIP", 5060, "REGISTER sip:lab.test SIP/2.0\r\n")
            .iter()
            .any(|f| f.check == "sip-response-disclosure"));
    }

    #[test]
    fn http_allow_header_discloses_mutable_methods() {
        let allow = evaluate(
            "HTTP",
            8080,
            "HTTP/1.1 204 No Content\r\nAllow: GET, POST, DELETE\r\n\r\n",
        );
        let hit = allow
            .iter()
            .find(|f| f.check == "http-allow-method-disclosure")
            .expect("Allow header naming DELETE should fire");
        assert_eq!(hit.severity, CheckSeverity::Low);
        assert!(hit.evidence.contains("allow: get"));
        // Read-only Allow header is not a mutable-method disclosure.
        assert!(!evaluate(
            "HTTP",
            8080,
            "HTTP/1.1 204 No Content\r\nAllow: GET, HEAD\r\n\r\n"
        )
        .iter()
        .any(|f| f.check == "http-allow-method-disclosure"));
    }

    #[test]
    fn imap_cleartext_capabilities_requires_complete_capability_line() {
        let caps = evaluate(
            "IMAP",
            143,
            "* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] ready\r\n",
        );
        let hit = caps
            .iter()
            .find(|f| f.check == "imap-cleartext-capabilities")
            .expect("complete capability line without STARTTLS should fire");
        assert_eq!(hit.severity, CheckSeverity::Medium);
        assert!(hit.evidence.contains("* ok"));
        // STARTTLS advertised → no cleartext claim.
        assert!(!evaluate(
            "IMAP",
            143,
            "* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN] ready\r\n"
        )
        .iter()
        .any(|f| f.check == "imap-cleartext-capabilities"));
        // A truncated capability line must not invent the absence.
        assert!(!evaluate("IMAP", 143, "* OK [CAPABILITY IMAP4rev1 AUTH=PL")
            .iter()
            .any(|f| f.check == "imap-cleartext-capabilities"));
    }
}
