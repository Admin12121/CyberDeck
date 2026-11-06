//! Passive OS-family HINTS from TCP handshake signatures (SYN / SYN-ACK).
//!
//! HONESTY CONTRACT: every output is a low-confidence hint carrying its own
//! evidence basis — never a verdict and never a version claim. Classification
//! uses only well-known, documented breakpoints: the classic initial-TTL
//! defaults (64 unix-like / 128 Windows-like / 255 network devices, matched
//! with a hop-distance bucket because observed TTL counts hops) and the
//! documented SYN/SYN-ACK window shapes visible in the offline reference DB
//! (`reference/nmap/nmap-os-db`: Linux ECN windows 0x16D0/0x3908/…, Windows
//! 0x4000-SYN and 0x2000/0xFFFF SYN-ACK shapes, Darwin/macOS and FreeBSD 65535
//! SYN-ACK shapes). This module deliberately does NOT implement nmap's full
//! signature matching: one passive packet cannot justify that.
//!
//! macOS and FreeBSD share most coarse header shapes, so a hint that matches
//! both says so in its evidence instead of silently picking one. When
//! evidence is absent or contradicts itself the family is "unknown" and the
//! evidence states the reason. A standing disclaimer travels inside every
//! evidence list so the basis of the claim survives serialization.

/// Hard bound on retained TCP option kind codes. Real headers cannot carry
/// more than 40 option bytes, so 16 kinds is generous; longer input is
/// truncated rather than rejected because hints are advisory.
pub const MAX_OPTION_ORDER: usize = 16;
/// Hard bound on evidence lines (including the standing disclaimer).
pub const MAX_EVIDENCE: usize = 6;

/// Common TCP option kind codes used for ordering evidence.
pub const OPTION_KIND_MSS: u8 = 2;
pub const OPTION_KIND_WINDOW_SCALE: u8 = 3;
pub const OPTION_KIND_SACK_PERMITTED: u8 = 4;
pub const OPTION_KIND_SACK_BLOCKS: u8 = 5;
pub const OPTION_KIND_TIMESTAMPS: u8 = 8;

/// TCP/IP signature features observed on ONE SYN or SYN/ACK segment.
///
/// `ipv4_df` is optional because the shared IPv4 dissection does not emit a
/// DF layer this arc: an unobserved feature stays absent instead of being
/// inferred from raw bytes by callers.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StackSignature {
    /// Observed IP TTL. The caller only builds signatures when a TTL layer
    /// exists, so there is no honest "absent" case to model here.
    pub ttl: u8,
    /// Don't-Fragment bit; `None` when the capture layers could not recover it.
    pub ipv4_df: Option<bool>,
    pub window: u16,
    pub mss: Option<u16>,
    pub window_scale: Option<u8>,
    /// Option kind codes in wire order (bounded to MAX_OPTION_ORDER).
    pub option_order: Vec<u8>,
    /// True when the segment was a SYN/ACK rather than a bare client SYN.
    pub syn_ack: bool,
}

/// Coarse operating-system family hint, serialized exactly as the wire shape.
/// Confidence is always "low" or "very_low": these breakpoints are shared by
/// whole families of stacks and shift with hardening, so no passive single-
/// packet output here is ever affirmative evidence, and no version is claimed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsHint {
    pub family: String,
    pub confidence: String,
    pub evidence: Vec<String>,
}

pub const FAMILY_LINUX: &str = "linux";
pub const FAMILY_WINDOWS: &str = "windows";
pub const FAMILY_FREEBSD: &str = "freebsd";
pub const FAMILY_MACOS: &str = "macos";
pub const FAMILY_NETWORK_DEVICE: &str = "network_device";
pub const FAMILY_UNKNOWN: &str = "unknown";
pub const CONFIDENCE_LOW: &str = "low";
pub const CONFIDENCE_VERY_LOW: &str = "very_low";

/// Standing disclaimer appended to every hint's evidence list.
pub const STANDING_DISCLAIMER: &str =
    "passive header-field hint from one packet; never a verdict or a version claim";

/// SYN/ACK window values documented for Linux stack shapes in the offline
/// reference DB: 0x16D0 (5840), 0x16A0 (5792), 0x3908 (14600), 0x7210 (29200),
/// 0xAAAA (43690), 0x8018 (32792).
const LINUX_SYNACK_WINDOWS: [u16; 6] = [0x16D0, 0x16A0, 0x3908, 0x7210, 0xAAAA, 0x8018];
/// Client-SYN window values documented for Linux stack shapes: 0xFAF0 (64240)
/// and the smaller advertised windows above.
const LINUX_SYN_WINDOWS: [u16; 4] = [0xFAF0, 0x16D0, 0x3908, 0x7210];
/// Windows-class documented shapes: client SYN 0x4000 (16384); SYN/ACK
/// 0xFFFF (65535) and 0x2000 (8192).
const WINDOWS_SYN_WINDOW: u16 = 0x4000;
const WINDOWS_SYNACK_WINDOWS: [u16; 2] = [0xFFFF, 0x2000];
/// Darwin/macOS-documented SYN/ACK window (65535) with window scale. FreeBSD
/// 10.x sends a near-identical shape, so this hint is always very_low and its
/// evidence discloses the overlap.
const BSD_FAMILY_SYNACK_WINDOW: u16 = 0xFFFF;

/// Classic initial-TTL breakpoint the observed TTL is consistent with, using
/// hop-distance buckets (an observed TTL of 63 is evidence of an initial 64
/// one hop away, not of "no default"). Returns None for the legacy 1..=32
/// bucket: too many unrelated stacks share initial 32 to attribute a family.
fn initial_ttl_bucket(ttl: u8) -> Option<u16> {
    match ttl {
        0 => None, // TTL 0 never leaves a stack; no usable evidence
        1..=32 => None,
        33..=64 => Some(64),
        65..=128 => Some(128),
        129..=255 => Some(255),
    }
}

fn family_hint(family: &str, confidence: &str, evidence: &mut Vec<String>) -> OsHint {
    // The disclaimer always travels with the data; the bound guarantees room.
    if evidence.len() + 1 >= MAX_EVIDENCE {
        evidence.truncate(MAX_EVIDENCE - 1);
    }
    evidence.push(STANDING_DISCLAIMER.to_string());
    OsHint {
        family: family.to_string(),
        confidence: confidence.to_string(),
        evidence: std::mem::take(evidence),
    }
}

/// Push one evidence line, never consuming the slot reserved for the
/// standing disclaimer.
fn push_line(evidence: &mut Vec<String>, line: impl Into<String>) {
    if evidence.len() + 1 < MAX_EVIDENCE {
        evidence.push(line.into());
    }
}

/// Summarize the decoded option kinds. Descriptive only: the same option
/// sets appear across several families, so order never decides one.
fn option_summary(order: &[u8]) -> Option<String> {
    if order.is_empty() {
        return None;
    }
    let names: Vec<&str> = order
        .iter()
        .take(MAX_OPTION_ORDER)
        .map(|kind| match *kind {
            OPTION_KIND_MSS => "MSS",
            OPTION_KIND_WINDOW_SCALE => "WS",
            OPTION_KIND_SACK_PERMITTED => "SACK-perm",
            OPTION_KIND_SACK_BLOCKS => "SACK-blocks",
            OPTION_KIND_TIMESTAMPS => "TS",
            _ => "?",
        })
        .collect();
    Some(format!("options in wire order: {}", names.join(",")))
}

/// Classify one handshake segment into a coarse family hint.
pub fn classify(signature: &StackSignature) -> OsHint {
    let mut evidence: Vec<String> = Vec::new();
    let options = option_summary(&signature.option_order);

    // The TTL bucket is the primary breakpoint: it decides which documented
    // initial default the segment is compared against.
    let Some(bucket) = initial_ttl_bucket(signature.ttl) else {
        push_line(
            &mut evidence,
            format!(
                "observed TTL {} matches the legacy initial-32 bucket, shared by too many unrelated stacks to attribute a family",
                signature.ttl
            ),
        );
        if let Some(options) = options {
            push_line(&mut evidence, options);
        }
        return family_hint(FAMILY_UNKNOWN, CONFIDENCE_VERY_LOW, &mut evidence);
    };

    match bucket {
        // Initial TTL 255: documented default of many router/network-device
        // stacks. Window scale is atypical there and weakens the hint.
        255 => {
            push_line(
                &mut evidence,
                format!(
                    "observed TTL {} is consistent with the documented initial TTL 255 of router/network-device stacks",
                    signature.ttl
                ),
            );
            let confidence = if signature.window_scale.is_some() {
                push_line(
                    &mut evidence,
                    "window scale on an initial-255 stack is atypical for classic network devices; hint weakened",
                );
                CONFIDENCE_VERY_LOW
            } else {
                CONFIDENCE_LOW
            };
            if let Some(options) = options {
                push_line(&mut evidence, options);
            }
            family_hint(FAMILY_NETWORK_DEVICE, confidence, &mut evidence)
        }
        // Initial TTL 128: documented Windows TCP/IP default.
        128 => {
            push_line(
                &mut evidence,
                format!(
                    "observed TTL {} is consistent with the documented initial TTL 128 of the Windows TCP/IP stack",
                    signature.ttl
                ),
            );
            // Conflict: a strong documented Linux SYN/ACK window contradicts
            // the Windows-default TTL. TTL is commonly rewritten in transit,
            // so the honest output is "unknown", never a forced family.
            if signature.syn_ack && LINUX_SYNACK_WINDOWS.contains(&signature.window) {
                push_line(
                    &mut evidence,
                    format!(
                        "SYN/ACK window {} is a documented Linux stack shape and conflicts with the Windows initial-TTL default; no family attribution",
                        signature.window
                    ),
                );
                if let Some(options) = options {
                    push_line(&mut evidence, options);
                }
                return family_hint(FAMILY_UNKNOWN, CONFIDENCE_VERY_LOW, &mut evidence);
            }
            let corroborated = if signature.syn_ack {
                WINDOWS_SYNACK_WINDOWS.contains(&signature.window)
            } else {
                signature.window == WINDOWS_SYN_WINDOW
            };
            if corroborated {
                push_line(
                    &mut evidence,
                    format!(
                        "{} window {} matches the documented Windows shape in the offline reference DB",
                        if signature.syn_ack { "SYN/ACK" } else { "SYN" },
                        signature.window
                    ),
                );
                if let Some(options) = options {
                    push_line(&mut evidence, options);
                }
                family_hint(FAMILY_WINDOWS, CONFIDENCE_LOW, &mut evidence)
            } else {
                push_line(
                    &mut evidence,
                    "no corroborating TCP window breakpoint; TTL-only attribution",
                );
                if let Some(options) = options {
                    push_line(&mut evidence, options);
                }
                family_hint(FAMILY_WINDOWS, CONFIDENCE_VERY_LOW, &mut evidence)
            }
        }
        // Initial TTL 64: documented default shared by Linux, macOS, FreeBSD
        // and many unix-like embedded stacks. Refinement relies on the
        // documented window shapes below; without a breakpoint the honest
        // family is "unknown" even though the stack is unix-like.
        _ => {
            push_line(
                &mut evidence,
                format!(
                    "observed TTL {} is consistent with the documented initial TTL 64 shared by unix-like stacks (Linux, macOS, FreeBSD and others)",
                    signature.ttl
                ),
            );
            match signature.ipv4_df {
                Some(true) => push_line(
                    &mut evidence,
                    "DF set, matching the documented unix-like don't-fragment behavior",
                ),
                Some(false) => push_line(
                    &mut evidence,
                    "DF clear, which weakens the unix-like header expectation",
                ),
                None => push_line(&mut evidence, "DF not visible in the dissected layers"),
            }
            // The BSD-family 65535 shape outranks the Linux window set:
            // 65535 is not one of the documented Linux SYN/ACK shapes.
            if signature.syn_ack && signature.window == BSD_FAMILY_SYNACK_WINDOW {
                if let Some(scale) = signature.window_scale {
                    push_line(
                        &mut evidence,
                        format!(
                            "SYN/ACK window 65535 with window scale {scale} matches the documented Darwin/macOS shape in the offline reference DB"
                        ),
                    );
                    push_line(
                        &mut evidence,
                        "FreeBSD 10.x sends a near-identical shape and cannot be excluded; family hint only",
                    );
                    return family_hint(FAMILY_MACOS, CONFIDENCE_VERY_LOW, &mut evidence);
                }
                push_line(
                    &mut evidence,
                    "SYN/ACK window 65535 without a window scale matches the documented FreeBSD shape (e.g. MSS-only option sets)",
                );
                if let Some(options) = options {
                    push_line(&mut evidence, options);
                }
                return family_hint(FAMILY_FREEBSD, CONFIDENCE_LOW, &mut evidence);
            }
            if signature.syn_ack && LINUX_SYNACK_WINDOWS.contains(&signature.window) {
                push_line(
                    &mut evidence,
                    format!(
                        "SYN/ACK window {} matches the documented Linux stack shapes in the offline reference DB",
                        signature.window
                    ),
                );
                if let Some(options) = options {
                    push_line(&mut evidence, options);
                }
                return family_hint(FAMILY_LINUX, CONFIDENCE_LOW, &mut evidence);
            }
            if !signature.syn_ack {
                if LINUX_SYN_WINDOWS.contains(&signature.window) {
                    push_line(
                        &mut evidence,
                        format!(
                            "SYN window {} matches the documented Linux stack shapes in the offline reference DB",
                            signature.window
                        ),
                    );
                    if let Some(options) = options {
                        push_line(&mut evidence, options);
                    }
                    return family_hint(FAMILY_LINUX, CONFIDENCE_LOW, &mut evidence);
                }
                // Conflict: the Windows hallmark SYN window on a unix-like TTL.
                if signature.window == WINDOWS_SYN_WINDOW {
                    push_line(
                        &mut evidence,
                        "SYN window 16384 is a documented Windows marker while the observed TTL matches the unix-like initial-64 default; conflicting evidence",
                    );
                    return family_hint(FAMILY_UNKNOWN, CONFIDENCE_VERY_LOW, &mut evidence);
                }
            }
            // Unix-like markers without a window breakpoint: shared across
            // Linux/macOS/FreeBSD, so no single family is attributable.
            if signature.ipv4_df == Some(true) && signature.window_scale.is_some() {
                push_line(
                    &mut evidence,
                    format!(
                        "DF and window scale are unix-like markers, but window {} has no documented single-family breakpoint",
                        signature.window
                    ),
                );
            } else {
                push_line(
                    &mut evidence,
                    "no TCP window/option breakpoint to attribute one unix-like family",
                );
            }
            if let Some(options) = options {
                push_line(&mut evidence, options);
            }
            family_hint(FAMILY_UNKNOWN, CONFIDENCE_VERY_LOW, &mut evidence)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig(ttl: u8, window: u16) -> StackSignature {
        StackSignature {
            ttl,
            ipv4_df: None,
            window,
            mss: None,
            window_scale: None,
            option_order: Vec::new(),
            syn_ack: false,
        }
    }

    #[test]
    fn linux_synack_shape_is_attributed_low() {
        let mut s = sig(63, 0x16D0); // one hop below the initial-64 bucket
        s.ipv4_df = Some(true);
        s.window_scale = Some(7);
        s.mss = Some(1460);
        s.option_order = vec![2, 4, 3, 8];
        s.syn_ack = true;
        let hint = classify(&s);
        assert_eq!(hint.family, FAMILY_LINUX);
        assert_eq!(hint.confidence, CONFIDENCE_LOW);
        assert!(hint.evidence.iter().any(|e| e.contains("5840")));
        assert!(hint.evidence.iter().any(|e| e.contains("initial TTL 64")));
        assert!(hint
            .evidence
            .last()
            .is_some_and(|e| e.contains("never a verdict")));
    }

    #[test]
    fn linux_client_syn_shape_is_attributed_low() {
        let mut s = sig(61, 0xFAF0);
        s.ipv4_df = Some(true);
        let hint = classify(&s);
        assert_eq!(hint.family, FAMILY_LINUX);
        assert_eq!(hint.confidence, CONFIDENCE_LOW);
    }

    #[test]
    fn windows_syn_and_synack_shapes_are_attributed_low() {
        for (window, syn_ack) in [(0x4000u16, false), (0xFFFF, true), (0x2000, true)] {
            let mut s = sig(128, window);
            s.syn_ack = syn_ack;
            let hint = classify(&s);
            assert_eq!(hint.family, FAMILY_WINDOWS, "window {window:#x}");
            assert_eq!(hint.confidence, CONFIDENCE_LOW);
        }
    }

    #[test]
    fn windows_ttl_only_is_very_low() {
        let mut s = sig(120, 51234);
        s.syn_ack = true;
        let hint = classify(&s);
        assert_eq!(hint.family, FAMILY_WINDOWS);
        assert_eq!(hint.confidence, CONFIDENCE_VERY_LOW);
        assert!(hint.evidence.iter().any(|e| e.contains("TTL-only")));
    }

    #[test]
    fn macos_scaled_65535_synack_is_very_low_with_freebsd_caveat() {
        let mut s = sig(64, 0xFFFF);
        s.ipv4_df = Some(true);
        s.window_scale = Some(6);
        s.mss = Some(1460);
        s.syn_ack = true;
        let hint = classify(&s);
        assert_eq!(hint.family, FAMILY_MACOS);
        assert_eq!(hint.confidence, CONFIDENCE_VERY_LOW);
        assert!(hint.evidence.iter().any(|e| e.contains("FreeBSD")));
    }

    #[test]
    fn freebsd_unscaled_65535_synack_is_attributed_low() {
        let mut s = sig(64, 0xFFFF);
        s.ipv4_df = Some(true);
        s.mss = Some(1460);
        s.syn_ack = true;
        let hint = classify(&s);
        assert_eq!(hint.family, FAMILY_FREEBSD);
        assert_eq!(hint.confidence, CONFIDENCE_LOW);
    }

    #[test]
    fn network_device_ttl255_is_attributed() {
        let mut s = sig(253, 0x1000);
        s.syn_ack = true;
        let hint = classify(&s);
        assert_eq!(hint.family, FAMILY_NETWORK_DEVICE);
        assert_eq!(hint.confidence, CONFIDENCE_LOW);
        // Window scale is atypical for network devices and weakens the hint.
        let mut scaled = sig(255, 0x1000);
        scaled.window_scale = Some(2);
        scaled.syn_ack = true;
        let weak = classify(&scaled);
        assert_eq!(weak.family, FAMILY_NETWORK_DEVICE);
        assert_eq!(weak.confidence, CONFIDENCE_VERY_LOW);
    }

    #[test]
    fn conflicting_ttl_and_window_evidence_is_unknown() {
        // Windows-default TTL with a documented Linux SYN/ACK window.
        let mut s = sig(128, 0x16D0);
        s.ipv4_df = Some(true);
        s.window_scale = Some(7);
        s.syn_ack = true;
        let hint = classify(&s);
        assert_eq!(hint.family, FAMILY_UNKNOWN);
        assert!(hint.evidence.iter().any(|e| e.contains("conflicts")));
        // Unix-like TTL with the Windows hallmark SYN window.
        let hint = classify(&sig(64, 0x4000));
        assert_eq!(hint.family, FAMILY_UNKNOWN);
        assert!(hint.evidence.iter().any(|e| e.contains("conflicting")));
    }

    #[test]
    fn absent_evidence_degrades_to_unknown_with_reason() {
        // Legacy initial-32 bucket.
        let hint = classify(&sig(20, 0x16D0));
        assert_eq!(hint.family, FAMILY_UNKNOWN);
        assert!(hint
            .evidence
            .iter()
            .any(|e| e.contains("legacy initial-32 bucket")));

        // TTL 64 alone: unix-like but unattributable.
        let mut s = sig(64, 9999);
        s.syn_ack = true;
        let hint = classify(&s);
        assert_eq!(hint.family, FAMILY_UNKNOWN);
        assert!(hint
            .evidence
            .iter()
            .any(|e| e.contains("shared by unix-like stacks")));

        // Unix-like markers without a window breakpoint stay unknown.
        let mut s = sig(64, 44444);
        s.ipv4_df = Some(true);
        s.window_scale = Some(4);
        s.syn_ack = true;
        let hint = classify(&s);
        assert_eq!(hint.family, FAMILY_UNKNOWN);
        assert!(hint
            .evidence
            .iter()
            .any(|e| e.contains("no documented single-family breakpoint")));
    }

    #[test]
    fn evidence_is_bounded_even_with_every_feature_present() {
        let mut s = sig(64, 0x16D0);
        s.ipv4_df = Some(true);
        s.window_scale = Some(7);
        s.mss = Some(1460);
        s.option_order = vec![2, 4, 3, 8];
        s.syn_ack = true;
        let hint = classify(&s);
        assert!(hint.evidence.len() <= MAX_EVIDENCE);
        assert!(hint
            .evidence
            .last()
            .is_some_and(|e| e.contains("never a verdict")));

        // A pathological signature cannot balloon the evidence either.
        let mut s = sig(255, 0xFFFF);
        s.option_order = vec![1; 64];
        s.ipv4_df = Some(false);
        s.mss = Some(536);
        s.window_scale = Some(14);
        let hint = classify(&s);
        assert!(hint.evidence.len() <= MAX_EVIDENCE);
    }

    #[test]
    fn option_order_is_truncated_not_rejected() {
        let mut s = sig(128, 0x4000);
        s.option_order = vec![1; 40];
        let hint = classify(&s);
        assert_eq!(hint.family, FAMILY_WINDOWS);
    }

    #[test]
    fn family_and_confidence_strings_match_the_wire_contract() {
        for (value, expected) in [
            (FAMILY_LINUX, "linux"),
            (FAMILY_WINDOWS, "windows"),
            (FAMILY_FREEBSD, "freebsd"),
            (FAMILY_MACOS, "macos"),
            (FAMILY_NETWORK_DEVICE, "network_device"),
            (FAMILY_UNKNOWN, "unknown"),
            (CONFIDENCE_LOW, "low"),
            (CONFIDENCE_VERY_LOW, "very_low"),
        ] {
            assert_eq!(value, expected);
        }
    }
}
