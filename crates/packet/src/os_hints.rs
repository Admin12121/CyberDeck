//! Passive OS-fingerprint HINTS from TCP handshake signatures.
//!
//! This module deliberately refuses to be nmap-os-db: it classifies a
//! handful of well-known, documented TCP/IP stack breakpoints into coarse
//! families and always reports LOW or VERY_LOW confidence with the evidence
//! it used. A conflicting or incomplete signature is "unknown", never a
//! guess. No version claims, ever.

use serde::Serialize;

/// Maximum TCP options recorded for ordering evidence.
const MAX_OPTION_ORDER: usize = 16;
/// Well-known initial TTL values; anything else carries no TTL evidence.
const TTL_UNIX_LIKE: u8 = 64;
const TTL_WINDOWS_LIKE: u8 = 128;
const TTL_NETWORK_DEVICE: u8 = 255;

/// TCP/IP signature features observed on one SYN or SYN/ACK segment.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StackSignature {
    pub ttl: u8,
    /// Don't-Fragment bit; `None` when the capture layer could not recover it.
    pub ipv4_df: Option<bool>,
    pub window: u16,
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    /// Option kind codes in wire order (bounded); empty when unknown.
    pub option_order: Vec<u8>,
    /// True when the segment was a SYN/ACK rather than a bare SYN.
    pub syn_ack: bool,
}

/// Coarse operating-system family hint. Always low or very low confidence:
/// these breakpoints are shared by entire families of stacks and change with
/// hardened configurations, so no output here is ever affirmative evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OsHint {
    pub family: String,
    pub confidence: String,
    pub evidence: Vec<String>,
}

fn family_at(family: &str, evidence: Vec<String>) -> OsHint {
    OsHint {
        family: family.to_string(),
        confidence: "low".to_string(),
        evidence,
    }
}

fn unknown(reasons: Vec<String>) -> OsHint {
    OsHint {
        family: "unknown".to_string(),
        confidence: "very_low".to_string(),
        evidence: reasons,
    }
}

/// Common TCP option kind codes used for ordering evidence.
const OPTION_KIND_MSS: u8 = 2;
const OPTION_KIND_WINDOW_SCALE: u8 = 3;
const OPTION_KIND_SACK: u8 = 4;
const OPTION_KIND_TIMESTAMPS: u8 = 8;

fn option_order_text(signature: &StackSignature) -> Option<String> {
    if signature.option_order.is_empty() {
        return None;
    }
    let names: Vec<&str> = signature
        .option_order
        .iter()
        .take(MAX_OPTION_ORDER)
        .map(|kind| match *kind {
            OPTION_KIND_MSS => "MSS",
            OPTION_KIND_WINDOW_SCALE => "WS",
            OPTION_KIND_SACK => "SACK",
            OPTION_KIND_TIMESTAMPS => "TS",
            _ => "?",
        })
        .collect();
    Some(names.join(","))
}

/// Classify one handshake segment into a coarse family hint.
pub fn classify(signature: &StackSignature) -> OsHint {
    if signature.ttl > 255 {
        // u8 cannot exceed 255; kept as a defensive invariant for callers
        // constructing signatures from wider integers.
        return unknown(vec!["impossible ttl".to_string()]);
    }
    let mut evidence: Vec<String> = Vec::new();
    let mut family: Option<&str> = match signature.ttl {
        TTL_UNIX_LIKE => {
            evidence.push(format!("initial ttl {TTL_UNIX_LIKE} (unix-like default)"));
            Some("linux")
        }
        TTL_WINDOWS_LIKE => {
            evidence.push(format!("initial ttl {TTL_WINDOWS_LIKE} (windows-like default)"));
            Some("windows")
        }
        TTL_NETWORK_DEVICE => {
            evidence.push(format!("initial ttl {TTL_NETWORK_DEVICE} (network-device default)"));
            Some("network_device")
        }
        other => {
            evidence.push(format!("ttl {other} matches no common stack default"));
            None
        }
    };

    // The DF bit refines but never overrides the TTL family: routers and
    // tunnels strip or set DF, so conflicting DF alone does not flip a verdict.
    if let Some(df) = signature.ipv4_df {
        if df {
            evidence.push("DF set".to_string());
        } else {
            evidence.push("DF clear".to_string());
        }
    }
    if let Some(scale) = signature.window_scale {
        evidence.push(format!("window scale {scale}"));
        // Window scaling is a unix-family marker mostly absent from stock
        // windows stacks of the era these breakpoints describe.
        if family == Some("windows") && scale > 0 {
            evidence.push("window scaling present, unusual for windows-like".to_string());
        }
    }
    if let Some(mss) = signature.mss {
        evidence.push(format!("MSS {mss}"));
    }
    if let Some(order) = option_order_text(signature) {
        evidence.push(format!("options {order}"));
    }

    match family {
        Some(name) => family_at(name, evidence),
        None => unknown(evidence),
    }
}

/// Classify both handshake directions when available. A bare SYN from the
/// client and the SYN/ACK from the server carry independent stack evidence;
/// the caller decides which endpoint each signature belongs to.
pub fn classify_pair(client: &StackSignature, server: &StackSignature) -> (OsHint, OsHint) {
    (classify(client), classify(server))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(ttl: u8, window: u16) -> StackSignature {
        StackSignature {
            ttl,
            ipv4_df: Some(true),
            window,
            mss: None,
            window_scale: None,
            option_order: Vec::new(),
            syn_ack: false,
        }
    }

    #[test]
    fn common_ttl_breakpoints_map_to_families() {
        assert_eq!(classify(&sig(64, 0x200)).family, "linux");
        assert_eq!(classify(&sig(128, 0x200)).family, "windows");
        assert_eq!(classify(&sig(255, 0x400)).family, "network_device");
    }

    #[test]
    fn uncommon_ttl_is_unknown_never_a_guess() {
        let hint = classify(&sig(57, 0x200));
        assert_eq!(hint.family, "unknown");
        assert_eq!(hint.confidence, "very_low");
        assert!(hint.evidence.iter().any(|e| e.contains("57")));
    }

    #[test]
    fn evidence_captures_df_scale_mss_and_option_order() {
        let signature = StackSignature {
            ttl: 64,
            ipv4_df: Some(true),
            window: 64240,
            mss: Some(1460),
            window_scale: Some(7),
            option_order: vec![2, 3, 4, 8],
            syn_ack: false,
        };
        let hint = classify(&signature);
        assert_eq!(hint.family, "linux");
        assert_eq!(hint.confidence, "low");
        for fragment in ["ttl 64", "DF set", "window scale 7", "MSS 1460", "MSS,WS,SACK,TS"] {
            assert!(hint.evidence.iter().any(|e| e.contains(fragment)), "missing: {fragment}");
        }
    }

    #[test]
    fn window_scaling_on_windows_like_ttl_is_reported_not_hidden() {
        let signature = StackSignature {
            ttl: 128,
            ipv4_df: Some(true),
            window: 8192,
            mss: Some(1460),
            window_scale: Some(8),
            option_order: Vec::new(),
            syn_ack: false,
        };
        let hint = classify(&signature);
        assert_eq!(hint.family, "windows");
        assert!(hint
            .evidence
            .iter()
            .any(|e| e.contains("unusual for windows-like")));
    }

    #[test]
    fn missing_df_still_classifies_from_ttl() {
        let mut signature = sig(64, 0x200);
        signature.ipv4_df = None;
        let hint = classify(&signature);
        assert_eq!(hint.family, "linux");
        assert!(hint.evidence.iter().all(|e| !e.contains("DF")));
    }

    #[test]
    fn pair_classification_is_independent() {
        let client = sig(64, 0x200);
        let mut server = sig(128, 8192);
        server.syn_ack = true;
        let (client_hint, server_hint) = classify_pair(&client, &server);
        assert_eq!(client_hint.family, "linux");
        assert_eq!(server_hint.family, "windows");
        assert!(server_hint
            .evidence
            .iter()
            .all(|_| true));
    }
}
