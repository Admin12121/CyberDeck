//! NSS SSLKEYLOGFILE parsing (the Firefox/Chrome `SSLKEYLOGFILE` format).
//! A keylog is USER-SUPPLIED evidence: this parser only reads it, never
//! guesses keys. Every line must be well-formed or the whole import fails
//! honestly — partial silent acceptance would let a typo'd secret silently
//! produce undecryptable ciphertext that looks like an unmatched stream.
//!
//! Accepted labels (TLS 1.3; the traffic secrets themselves):
//! `CLIENT_EARLY_TRAFFIC_SECRET`, `CLIENT_HANDSHAKE_TRAFFIC_SECRET`,
//! `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`,
//! `SERVER_TRAFFIC_SECRET_0`. `CLIENT_RANDOM` lines carry the TLS 1.2
//! master secret and are RETAINED (random → 48-byte master secret lookup)
//! for the passive TLS 1.2 record decryptor (`super::tls12`); other TLS
//! 1.2-era labels (`RSA ...`, `EC ...`) remain recognized-but-ignored.
//! Both counters stay separate: `entry_count` still counts only TLS 1.3
//! traffic secrets.
//!
//! Bounds: at most 64 KiB of input and 1024 entries (TLS 1.3 and TLS 1.2
//! entries share the bound); duplicate (random, label) lines collapse
//! (last value wins, counted).

use std::collections::HashMap;

/// Maximum accepted keylog file size, in bytes.
pub const MAX_KEYLOG_BYTES: usize = 64 * 1024;
/// Maximum accepted keylog entries (deduped or not).
pub const MAX_KEYLOG_ENTRIES: usize = 1024;
/// One hex-encoded 32-byte value, as written by NSS keylogs.
const HEX_32: usize = 64;
/// One hex-encoded 48-byte value (the TLS 1.2 master secret).
const HEX_48: usize = 96;
/// Cap on a single line so a malformed file cannot force unbounded scans.
const MAX_LINE_BYTES: usize = 4096;

/// One connection's traffic secrets, keyed by the ClientHello random.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeylogSecrets {
    pub client_early: Option<[u8; 32]>,
    pub client_handshake: Option<[u8; 32]>,
    pub server_handshake: Option<[u8; 32]>,
    pub client_application: Option<[u8; 32]>,
    pub server_application: Option<[u8; 32]>,
}

/// Parsed keylog: lookup by ClientHello random (32 bytes). TLS 1.3 traffic
/// secrets and TLS 1.2 master secrets are stored separately; only the
/// latter feed the TLS 1.2 decryptor, only the former the TLS 1.3 one.
#[derive(Debug, Clone, Default)]
pub struct KeylogStore {
    connections: HashMap<[u8; 32], KeylogSecrets>,
    tls12: HashMap<[u8; 32], [u8; 48]>,
    entries: usize,
    tls12_entries: usize,
    duplicates: usize,
    ignored_tls12_lines: usize,
}

impl KeylogStore {
    /// Parse a bounded NSS keylog. Fails honestly on any malformed line,
    /// oversized input, or entry-count overflow; comments (`#...`) and blank
    /// lines are skipped, and recognized TLS 1.2 labels are ignored (counted,
    /// never silently dropped).
    pub fn parse(input: &str) -> Result<Self, String> {
        if input.len() > MAX_KEYLOG_BYTES {
            return Err(format!(
                "keylog exceeds the {} KiB import bound",
                MAX_KEYLOG_BYTES / 1024
            ));
        }
        let mut store = Self::default();
        for (index, raw_line) in input.lines().enumerate() {
            let line_no = index + 1;
            if raw_line.len() > MAX_LINE_BYTES {
                return Err(format!(
                    "keylog line {line_no} exceeds {MAX_LINE_BYTES} bytes"
                ));
            }
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_ascii_whitespace();
            let Some(label) = parts.next() else {
                continue;
            };
            // NSS TLS 1.2 CLIENT_RANDOM lines (`CLIENT_RANDOM <random>
            // <master_secret>`) carry the 48-byte TLS 1.2 master secret and
            // are retained for the TLS 1.2 decryptor. A CLIENT_RANDOM line
            // that does not parse carries no usable master secret — it is
            // counted and skipped whole (never partially interpreted), so
            // nothing can be silently mis-decrypted later.
            if label == "CLIENT_RANDOM" {
                if let Some((random, secret)) = parse_client_random(&mut parts) {
                    if store.entries + store.tls12_entries >= MAX_KEYLOG_ENTRIES {
                        return Err(format!(
                            "keylog exceeds the {MAX_KEYLOG_ENTRIES}-entry import bound at line {line_no}"
                        ));
                    }
                    // Duplicate (random, label) lines collapse with the
                    // last value winning, matching the TLS 1.3 dedupe
                    // semantics.
                    if store.tls12.insert(random, secret).is_some() {
                        store.duplicates += 1;
                    } else {
                        store.tls12_entries += 1;
                    }
                }
                // Counted among the non-TLS-1.3 lines whether retained or
                // not — see `ignored_line_count`.
                store.ignored_tls12_lines += 1;
                continue;
            }
            // Recognized TLS 1.3 labels are strictly `LABEL <random> <secret>`.
            // NSS TLS 1.2-era lines (e.g. `RSA <id> <random> <secret>`) carry
            // an extra middle field; they are never interpreted here, so any
            // unrecognized label is counted and skipped as a whole line.
            if !matches!(
                label,
                "CLIENT_EARLY_TRAFFIC_SECRET"
                    | "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
                    | "SERVER_HANDSHAKE_TRAFFIC_SECRET"
                    | "CLIENT_TRAFFIC_SECRET_0"
                    | "SERVER_TRAFFIC_SECRET_0"
            ) {
                store.ignored_tls12_lines += 1;
                continue;
            }
            let Some(random_hex) = parts.next() else {
                return Err(format!("keylog line {line_no}: missing ClientHello random"));
            };
            let Some(secret_hex) = parts.next() else {
                return Err(format!("keylog line {line_no}: missing secret value"));
            };
            if parts.next().is_some() {
                return Err(format!(
                    "keylog line {line_no}: unexpected trailing content"
                ));
            }
            let Some(secret) = decode_32(secret_hex) else {
                return Err(format!(
                    "keylog line {line_no}: secret must be {HEX_32} hex characters"
                ));
            };
            if decode_32(random_hex).is_none() {
                return Err(format!(
                    "keylog line {line_no}: ClientHello random must be {HEX_32} hex characters"
                ));
            }
            // The random is validated as hex above; decode again only here.
            let random = decode_32(random_hex).expect("validated above");
            match label {
                "CLIENT_EARLY_TRAFFIC_SECRET" => {
                    store.record(random, line_no, |s| &mut s.client_early, secret)?;
                }
                "CLIENT_HANDSHAKE_TRAFFIC_SECRET" => {
                    store.record(random, line_no, |s| &mut s.client_handshake, secret)?;
                }
                "SERVER_HANDSHAKE_TRAFFIC_SECRET" => {
                    store.record(random, line_no, |s| &mut s.server_handshake, secret)?;
                }
                "CLIENT_TRAFFIC_SECRET_0" => {
                    store.record(random, line_no, |s| &mut s.client_application, secret)?;
                }
                "SERVER_TRAFFIC_SECRET_0" => {
                    store.record(random, line_no, |s| &mut s.server_application, secret)?;
                }
                // TLS 1.2-era and unknown labels: never interpreted.
                _ => store.ignored_tls12_lines += 1,
            }
        }
        Ok(store)
    }

    /// Insert one entry; duplicate (random, label) lines collapse with the
    /// last value winning and are counted rather than silently re-parsed.
    fn record(
        &mut self,
        random: [u8; 32],
        line_no: usize,
        slot: impl FnOnce(&mut KeylogSecrets) -> &mut Option<[u8; 32]>,
        secret: [u8; 32],
    ) -> Result<(), String> {
        if self.entries >= MAX_KEYLOG_ENTRIES {
            return Err(format!(
                "keylog exceeds the {MAX_KEYLOG_ENTRIES}-entry import bound at line {line_no}"
            ));
        }
        let secrets = self.connections.entry(random).or_default();
        if slot(secrets).replace(secret).is_some() {
            self.duplicates += 1;
        } else {
            self.entries += 1;
        }
        Ok(())
    }

    /// The traffic secrets bound to one ClientHello random, if the keylog
    /// covers this connection. TLS 1.3 labels only — a TLS 1.2
    /// `CLIENT_RANDOM` entry alone does not appear here (see
    /// [`KeylogStore::master_secret_for`]).
    pub fn secrets_for(&self, client_random: &[u8; 32]) -> Option<&KeylogSecrets> {
        self.connections.get(client_random)
    }

    /// The TLS 1.2 master secret bound to one ClientHello random via a
    /// retained `CLIENT_RANDOM` line, if the keylog covers this connection.
    pub fn master_secret_for(&self, client_random: &[u8; 32]) -> Option<&[u8; 48]> {
        self.tls12.get(client_random)
    }

    /// Distinct connections (ClientHello randoms) covered by this keylog —
    /// TLS 1.3 traffic-secret entries and retained TLS 1.2 master secrets
    /// share the same ClientHello-random key space and are counted once.
    pub fn connection_count(&self) -> usize {
        self.connections.len()
            + self
                .tls12
                .keys()
                .filter(|random| !self.connections.contains_key(*random))
                .count()
    }

    /// Accepted TLS 1.3 traffic-secret entries.
    pub fn entry_count(&self) -> usize {
        self.entries
    }

    /// Retained TLS 1.2 `CLIENT_RANDOM` master secrets (TLS 1.3 entries are
    /// counted by [`KeylogStore::entry_count`]).
    pub fn tls12_master_secret_count(&self) -> usize {
        self.tls12_entries
    }

    /// Collapsed duplicate (random, label) lines.
    pub fn duplicate_count(&self) -> usize {
        self.duplicates
    }

    /// Lines outside the TLS 1.3 traffic-secret labels. TLS 1.2
    /// `CLIENT_RANDOM` lines are counted here (they are not TLS 1.3
    /// traffic secrets) while also being retained for the TLS 1.2
    /// decryptor — see [`KeylogStore::tls12_master_secret_count`]; other
    /// TLS 1.2-era and unknown labels are counted and skipped whole.
    pub fn ignored_line_count(&self) -> usize {
        self.ignored_tls12_lines
    }

    /// True when nothing usable was imported — no TLS 1.3 traffic secrets
    /// and no retained TLS 1.2 master secrets.
    pub fn is_empty(&self) -> bool {
        self.entries == 0 && self.tls12_entries == 0
    }
}

/// Decode exactly 64 lowercase-or-uppercase hex characters into 32 bytes.
/// Anything else — wrong length or any non-hex character — is refused.
fn decode_32(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != HEX_32 || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)? as u8;
        let lo = (pair[1] as char).to_digit(16)? as u8;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// Decode exactly 96 lowercase-or-uppercase hex characters into the 48-byte
/// TLS 1.2 master secret (`CLIENT_RANDOM` lines). Same refusal rules as
/// [`decode_32`].
fn decode_48(hex: &str) -> Option<[u8; 48]> {
    if hex.len() != HEX_48 || !hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 48];
    for (i, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)? as u8;
        let lo = (pair[1] as char).to_digit(16)? as u8;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

/// Parse the fields of a `CLIENT_RANDOM` line: exactly
/// `<32-byte hex random> <48-byte hex master secret>`. Anything else —
/// wrong lengths, non-hex, extra fields — is None and the whole line is
/// skipped by the caller.
fn parse_client_random(
    parts: &mut std::str::SplitAsciiWhitespace<'_>,
) -> Option<([u8; 32], [u8; 48])> {
    let random = decode_32(parts.next()?)?;
    let secret = decode_48(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    Some((random, secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RANDOM: &str = "b3b1b0aa97b0fdfbbfb17e26bfd11b7fb2b252db4f6dfe95f4a25a77ba01d988";
    const SECRET: &str = "9c98b6b62f8ff52fdbb6b4b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6";

    fn line(label: &str) -> String {
        format!("{label} {RANDOM} {SECRET}")
    }

    #[test]
    fn parses_all_five_tls13_labels() {
        let input = [
            line("CLIENT_HANDSHAKE_TRAFFIC_SECRET"),
            line("SERVER_HANDSHAKE_TRAFFIC_SECRET"),
            line("CLIENT_TRAFFIC_SECRET_0"),
            line("SERVER_TRAFFIC_SECRET_0"),
            line("CLIENT_EARLY_TRAFFIC_SECRET"),
        ]
        .join("\n");
        let store = KeylogStore::parse(&input).unwrap();
        assert_eq!(store.entry_count(), 5);
        assert_eq!(store.connection_count(), 1);
        assert_eq!(store.duplicate_count(), 0);
        assert_eq!(store.ignored_line_count(), 0);
        let secrets = store.secrets_for(&decode_32(RANDOM).unwrap()).unwrap();
        assert_eq!(secrets.client_handshake, Some(decode_32(SECRET).unwrap()));
        assert_eq!(secrets.server_handshake, Some(decode_32(SECRET).unwrap()));
        assert_eq!(secrets.client_application, Some(decode_32(SECRET).unwrap()));
        assert_eq!(secrets.server_application, Some(decode_32(SECRET).unwrap()));
        assert_eq!(secrets.client_early, Some(decode_32(SECRET).unwrap()));
    }

    #[test]
    fn comments_blank_lines_and_tls12_labels_are_ignored_but_counted() {
        let rsa = format!("RSA Session-ID:... {RANDOM} {SECRET}");
        let ec = format!("EC-Secret:... {RANDOM} {SECRET}");
        let client_random = format!("CLIENT_RANDOM {RANDOM} {SECRET}");
        let input = format!(
            "# NSS keylog\n\n{rsa}\n\n{ec}\n{client_random}\n{}",
            line("CLIENT_HANDSHAKE_TRAFFIC_SECRET")
        );
        let store = KeylogStore::parse(&input).unwrap();
        assert_eq!(store.entry_count(), 1);
        assert_eq!(store.ignored_line_count(), 3);
        assert!(store.secrets_for(&decode_32(RANDOM).unwrap()).is_some());
    }

    #[test]
    fn duplicate_random_label_collapses_and_counts() {
        let input = format!(
            "{}\n{}",
            line("CLIENT_TRAFFIC_SECRET_0"),
            line("CLIENT_TRAFFIC_SECRET_0")
        );
        let store = KeylogStore::parse(&input).unwrap();
        assert_eq!(store.entry_count(), 1);
        assert_eq!(store.duplicate_count(), 1);
        assert_eq!(store.connection_count(), 1);
    }

    #[test]
    fn malformed_lines_fail_with_honest_line_numbers() {
        // Bad hex in the secret.
        let bad_secret = format!("CLIENT_TRAFFIC_SECRET_0 {RANDOM} zz98b6b62f8ff52fdbb6b4b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6b6");
        let err = KeylogStore::parse(&bad_secret).unwrap_err();
        assert!(err.contains("line 1"), "{err}");
        assert!(err.contains("hex"), "{err}");
        // Wrong-length random.
        let short_random = format!("CLIENT_TRAFFIC_SECRET_0 {} {SECRET}", &RANDOM[..60]);
        assert!(KeylogStore::parse(&short_random)
            .unwrap_err()
            .contains("ClientHello random"));
        // Missing fields.
        assert!(KeylogStore::parse("CLIENT_TRAFFIC_SECRET_0")
            .unwrap_err()
            .contains("missing ClientHello random"));
        let one_field = format!("CLIENT_TRAFFIC_SECRET_0 {RANDOM}");
        assert!(KeylogStore::parse(&one_field)
            .unwrap_err()
            .contains("missing secret"));
        // Trailing garbage.
        let trailing = format!("{} extra", line("CLIENT_TRAFFIC_SECRET_0"));
        assert!(KeylogStore::parse(&trailing)
            .unwrap_err()
            .contains("trailing content"));
        // Empty file is valid but empty.
        assert!(KeylogStore::parse("").unwrap().is_empty());
        assert!(KeylogStore::parse("# only a comment\n").unwrap().is_empty());
    }

    #[test]
    fn bounds_are_enforced() {
        // Over 64 KiB: refused before any parsing.
        let big = format!("#{}\n", "x".repeat(MAX_KEYLOG_BYTES));
        assert!(KeylogStore::parse(&big).unwrap_err().contains("64 KiB"));
        // 1025 valid entries cannot fit under the 64 KiB byte bound (a
        // minimum NSS line is ~150 bytes), so the byte bound fires first;
        // the 1024-entry bound stays as defense in depth for future label
        // shapes. The same over-entry file is still refused honestly.
        let mut input = String::new();
        for i in 0..(MAX_KEYLOG_ENTRIES + 1) {
            let random = format!("{i:064x}");
            input.push_str(&format!("CLIENT_TRAFFIC_SECRET_0 {random} {SECRET}\n"));
        }
        let err = KeylogStore::parse(&input).unwrap_err();
        assert!(err.contains("64 KiB"), "{err}");
        // A single absurdly long line is refused.
        let long_line = format!(
            "CLIENT_TRAFFIC_SECRET_0 {RANDOM} {SECRET} {}",
            "y".repeat(5000)
        );
        assert!(KeylogStore::parse(&long_line).unwrap_err().contains("4096"));
    }

    #[test]
    fn uppercase_hex_and_distinct_randoms_are_accepted() {
        let upper_secret = SECRET.to_uppercase();
        let a = format!("CLIENT_TRAFFIC_SECRET_0 {RANDOM} {upper_secret}");
        let other_random = format!("{:064x}", 0xdead_beefu64);
        let b = format!("CLIENT_TRAFFIC_SECRET_0 {other_random} {SECRET}");
        let store = KeylogStore::parse(&format!("{a}\n{b}")).unwrap();
        assert_eq!(store.entry_count(), 2);
        assert_eq!(store.connection_count(), 2);
        assert_eq!(
            store
                .secrets_for(&decode_32(RANDOM).unwrap())
                .unwrap()
                .client_application,
            Some(decode_32(SECRET).unwrap())
        );
        assert!(store
            .secrets_for(&decode_32(&other_random).unwrap())
            .is_some());
        // An unknown random is not matched — never guessed.
        assert!(store.secrets_for(&[7u8; 32]).is_none());
    }

    // ------------------- TLS 1.2 CLIENT_RANDOM retention (additive) ----

    const MASTER: &str = concat!(
        "71717171717171717171717171717171", // 16 bytes
        "72727272727272727272727272727272", // 16 bytes
        "73737373737373737373737373737373", // 16 bytes
    );

    #[test]
    fn client_random_entries_are_retained_for_tls12_lookup() {
        let input = format!("CLIENT_RANDOM {RANDOM} {MASTER}\n");
        let store = KeylogStore::parse(&input).unwrap();
        // Retained master secret, with the TLS 1.3 counters untouched.
        assert_eq!(store.tls12_master_secret_count(), 1);
        assert_eq!(store.entry_count(), 0);
        assert_eq!(store.duplicate_count(), 0);
        assert_eq!(store.connection_count(), 1);
        assert!(!store.is_empty());
        assert_eq!(
            store
                .master_secret_for(&decode_32(RANDOM).unwrap())
                .unwrap(),
            &decode_48(MASTER).unwrap()
        );
        // Still counted among the non-TLS-1.3 lines, as before this slice.
        assert_eq!(store.ignored_line_count(), 1);
        // The TLS 1.3 lookup never sees a TLS 1.2-only entry.
        assert!(store.secrets_for(&decode_32(RANDOM).unwrap()).is_none());
        // An unknown random is not matched — never guessed.
        assert!(store.master_secret_for(&[7u8; 32]).is_none());
        // A 1.3-only keylog still reports no master secrets.
        let only13 = KeylogStore::parse(&line("CLIENT_TRAFFIC_SECRET_0")).unwrap();
        assert_eq!(only13.tls12_master_secret_count(), 0);
        assert!(only13
            .master_secret_for(&decode_32(RANDOM).unwrap())
            .is_none());
    }

    #[test]
    fn client_random_duplicates_collapse_and_malformed_lines_are_skipped() {
        let input = format!("CLIENT_RANDOM {RANDOM} {MASTER}\nCLIENT_RANDOM {RANDOM} {MASTER}\n");
        let store = KeylogStore::parse(&input).unwrap();
        assert_eq!(store.tls12_master_secret_count(), 1);
        assert_eq!(store.duplicate_count(), 1);
        assert_eq!(store.connection_count(), 1);
        // Last value wins: rewrite the master with a distinct value.
        let rewritten = format!(
            "CLIENT_RANDOM {RANDOM} {MASTER}\nCLIENT_RANDOM {RANDOM} {}\n",
            "3".repeat(96)
        );
        let store = KeylogStore::parse(&rewritten).unwrap();
        assert_eq!(
            store
                .master_secret_for(&decode_32(RANDOM).unwrap())
                .unwrap()[0],
            0x33
        );
        // Malformed CLIENT_RANDOM lines carry no usable master secret: they
        // are counted and skipped whole, exactly like other TLS 1.2-era
        // labels — never partially interpreted, never guessed around.
        for bad in [
            format!("CLIENT_RANDOM {RANDOM} {}", &MASTER[..90]), // short secret
            format!("CLIENT_RANDOM {} {MASTER}", &RANDOM[..60]), // short random
            format!("CLIENT_RANDOM {RANDOM} {}{MASTER}", "z"),   // non-hex secret
            "CLIENT_RANDOM".to_string(),                         // missing fields
            format!("CLIENT_RANDOM {RANDOM}"),                   // missing secret
            format!("CLIENT_RANDOM {RANDOM} {MASTER} extra"),    // trailing
        ] {
            let store = KeylogStore::parse(&bad).unwrap();
            assert_eq!(store.tls12_master_secret_count(), 0, "{bad}");
            assert_eq!(store.ignored_line_count(), 1, "{bad}");
            assert_eq!(store.duplicate_count(), 0, "{bad}");
        }
    }

    #[test]
    fn tls12_and_tls13_entries_share_the_entry_bound_and_connection_count() {
        // One connection covered by both a TLS 1.3 secret and a TLS 1.2
        // master secret counts once.
        let mixed = format!(
            "{}\nCLIENT_RANDOM {RANDOM} {MASTER}\n",
            line("CLIENT_HANDSHAKE_TRAFFIC_SECRET")
        );
        let store = KeylogStore::parse(&mixed).unwrap();
        assert_eq!(store.connection_count(), 1);
        assert_eq!(store.entry_count(), 1);
        assert_eq!(store.tls12_master_secret_count(), 1);
        // Two distinct randoms across the two label families count twice.
        let other_random = format!("{:064x}", 0xfeedu64);
        let distinct = format!("{mixed}CLIENT_RANDOM {other_random} {MASTER}\n");
        let store = KeylogStore::parse(&distinct).unwrap();
        assert_eq!(store.connection_count(), 2);
        // The 1024-entry bound spans both label families (defense in depth;
        // the 64 KiB byte bound still fires first for any real file).
        let mut many = String::new();
        for i in 0..(MAX_KEYLOG_ENTRIES + 1) {
            let random = format!("{i:064x}");
            many.push_str(&format!("CLIENT_RANDOM {random} {MASTER}\n"));
        }
        let err = KeylogStore::parse(&many).unwrap_err();
        assert!(err.contains("64 KiB"), "{err}");
        assert!(err.contains("entry") || err.contains("bound"), "{err}");
    }
}
