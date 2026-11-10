//! Regression tests for bounded native recovery, validation and progress.
use super::*;
#[test]
fn progress_is_monotonic_budgeted_and_contains_no_password() {
    use std::io::{BufReader, Cursor};
    let target = RecoveryTarget::parse("sha256", &"ab".repeat(32)).unwrap();
    let lines = "bad\n".repeat(10_000);
    let mut samples = Vec::new();
    let result = recover_wordlist_with_progress(
        &target,
        BufReader::new(Cursor::new(lines)),
        RecoveryLimits {
            max_candidates: 9_000,
            max_matches: 1,
        },
        || false,
        |progress| samples.push(progress),
    )
    .unwrap();
    assert_eq!(result.tried, 9_000);
    assert!(result.limit_reached);
    assert_eq!(
        samples.iter().map(|p| p.tried).collect::<Vec<_>>(),
        vec![4096, 8192, 9000]
    );
    assert!(samples.iter().all(|p| p.budget == 9000 && p.matches == 0));
    assert_eq!(samples.last().unwrap().tried, result.tried);
    // Serialization is intentionally candidate-free for case/event logs.
    assert_eq!(
        serde_json::to_string(samples.last().unwrap()).unwrap(),
        r#"{"tried":9000,"budget":9000,"matches":0}"#
    );
}

#[test]
fn streaming_compiled_rules_integrate_with_global_recovery() {
    use std::io::Cursor;
    let hash = hex::encode(apply_op("sha256", b"Pass1", None).unwrap());
    let target = RecoveryTarget::parse("sha256", &hash).unwrap();
    let rules = vec![
        CompiledRule::parse("l").unwrap(),
        CompiledRule::parse("c$1").unwrap(),
    ];
    let mut snapshots = Vec::new();
    let result = recover_wordlist_with_rules(
        &target,
        Cursor::new(b"paSS\nignored\n".as_slice()),
        rules,
        RecoveryLimits {
            max_candidates: 4,
            max_matches: 1,
        },
        || false,
        |progress| snapshots.push(progress),
    )
    .unwrap();
    assert_eq!(result.tried, 2);
    assert_eq!(result.hits[0].index, 1);
    assert_eq!(result.hits[0].candidate, b"Pass1");
    assert_eq!(snapshots.last().unwrap().tried, 2);
}

#[test]
fn wordlist_streaming_matches_and_preserves_global_indices() {
    use std::io::{BufReader, Cursor};
    let target = RecoveryTarget::parse(
        "sha256",
        &hex::encode(apply_op("sha256", b"secret", None).unwrap()),
    )
    .unwrap();
    let bytes = b"bad\n\xff\x00\nsecret\nignored";
    let result = recover_wordlist(
        &target,
        BufReader::with_capacity(2, Cursor::new(bytes.as_slice())),
        RecoveryLimits::default(),
        || false,
    )
    .unwrap();
    assert_eq!(result.tried, 3);
    assert_eq!(result.hits[0].index, 2);
    assert_eq!(result.hits[0].candidate, b"secret");
}

#[test]
fn wordlist_limits_and_cancel_do_not_prefetch() {
    use std::io::{BufReader, Cursor};
    let target = RecoveryTarget::parse("md5", "5d41402abc4b2a76b9719d911017c592").unwrap();
    // A malformed, oversized second line is never read past the budget.
    let source = [b"bad\n".to_vec(), vec![b'X'; MAX_CANDIDATE_BYTES + 9]].concat();
    let limits = RecoveryLimits {
        max_candidates: 1,
        max_matches: 1,
    };
    let result = recover_wordlist(
        &target,
        BufReader::with_capacity(2, Cursor::new(source)),
        limits,
        || false,
    )
    .unwrap();
    assert_eq!(result.tried, 1);
    assert!(result.limit_reached);
    let cancelled = recover_wordlist(
        &target,
        BufReader::new(Cursor::new(b"anything\n".as_slice())),
        RecoveryLimits::default(),
        || true,
    )
    .unwrap();
    assert_eq!(cancelled.tried, 0);
    assert!(cancelled.cancelled);
}

#[test]
fn recover_core_does_not_poll_candidate_past_cap() {
    use std::cell::Cell;
    let target = RecoveryTarget::parse("md5", "5d41402abc4b2a76b9719d911017c592").unwrap();
    let pulls = Cell::new(0usize);
    let candidates = std::iter::from_fn(|| {
        pulls.set(pulls.get() + 1);
        Some(b"bad".to_vec())
    });
    let result = recover(
        &target,
        candidates,
        RecoveryLimits {
            max_candidates: 2,
            max_matches: 1,
        },
        || false,
    )
    .unwrap();
    assert_eq!(result.tried, 2);
    assert_eq!(pulls.get(), 2);
    assert!(result.limit_reached);
}

#[test]
fn sha256_reference_recovery() {
    let target = RecoveryTarget::parse(
        "sha256",
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    )
    .unwrap();
    let result = recover(
        &target,
        ["bad", "hello", "other"],
        RecoveryLimits::default(),
        || false,
    )
    .unwrap();
    assert_eq!(result.tried, 2);
    assert_eq!(
        result.hits[0],
        RecoveryHit {
            target: None,
            index: 1,
            candidate: b"hello".to_vec()
        }
    );
}
#[test]
fn ntlm_and_non_utf8_md5() {
    let ntlm = RecoveryTarget::parse("ntlm", "8846f7eaee8fb117ad06bdd830b7586c").unwrap();
    assert!(ntlm.is_match(b"password").unwrap());
    let input = [255u8, 0u8];
    let digest = hex::encode(apply_op("md5", &input, None).unwrap());
    assert!(RecoveryTarget::parse("md5", &digest)
        .unwrap()
        .is_match(&input)
        .unwrap());
}
#[test]
fn validation_rejects_malformed_and_unbounded_cost() {
    assert!(RecoveryTarget::parse("sha256", "zz").is_err());
    assert!(RecoveryTarget::parse("sha256", "abcd").is_err());
    assert!(RecoveryTarget::parse("", "$6$salt$hash").is_err());
    assert!(RecoveryTarget::parse("", "$2b$31$abcdefghijklmnopqrstuv").is_err());
    assert!(RecoveryTarget::parse("", "$argon2id$v=19$m=999999,t=2,p=1$a$b").is_err());
    assert!(RecoveryTarget::parse("", "$pbkdf2-sha256$i=900000000$a$b").is_err());
    assert!(RecoveryTarget::parse("", "$argon2id$v=19$t=2,p=1$a$b").is_err());
    assert!(RecoveryTarget::parse("", "$argon2id$v=19$m=8192,m=8192,t=2,p=1$a$b").is_err());
    assert!(RecoveryTarget::parse("", "$scrypt$ln=20,r=16,p=1$a$b").is_err());
    assert!(RecoveryTarget::parse("", "$scrypt$ln=16,r=8$a$b").is_err());
    assert!(RecoveryTarget::parse("", "$pbkdf2-sha256$salt$hash").is_err());
}
#[test]
fn cancellation_and_global_limit() {
    let target = RecoveryTarget::parse("md5", "5d41402abc4b2a76b9719d911017c592").unwrap();
    let outcome = recover(
        &target,
        std::iter::repeat("bad").take(8),
        RecoveryLimits {
            max_candidates: 3,
            max_matches: 1,
        },
        || false,
    )
    .unwrap();
    assert_eq!(outcome.tried, 3);
    assert!(outcome.limit_reached);
    let mut polls = 0;
    let outcome = recover(&target, ["bad", "hello"], RecoveryLimits::default(), || {
        polls += 1;
        polls > 1
    })
    .unwrap();
    assert_eq!(outcome.tried, 1);
    assert!(outcome.cancelled);
}
#[test]
fn bounded_bcrypt_stream_recovery() {
    let encoded = bcrypt::hash("secret", 4).unwrap();
    let target = RecoveryTarget::parse("", &encoded).unwrap();
    let result = recover(
        &target,
        ["bad", "secret"],
        RecoveryLimits::default(),
        || false,
    )
    .unwrap();
    assert_eq!(result.tried, 2);
    assert_eq!(result.hits[0].candidate, b"secret");
}
#[test]
fn parse_compiled_rules_from_bounded_source_file() {
    use std::io::Cursor;
    let rules = parse_rule_lines(Cursor::new(b"# comment\r\n\r\nc$1\nl\n".as_slice())).unwrap();
    assert_eq!(rules.len(), 2);
    assert_eq!(
        rules[0].apply(b"pASSWORD").unwrap(),
        Some(b"Password1".to_vec())
    );
    assert_eq!(rules[1].apply(b"ABC").unwrap(), Some(b"abc".to_vec()));
    assert!(parse_rule_lines(Cursor::new(b"# only comments\n".as_slice())).is_err());
    let huge = [vec![b'l'; MAX_CANDIDATE_BYTES + 8], b"\n".to_vec()].concat();
    assert!(parse_rule_lines(Cursor::new(huge)).is_err());
    let too_many = ":\n".repeat(MAX_RULES_PER_STREAM + 1);
    assert!(parse_rule_lines(Cursor::new(too_many)).is_err());
}

#[test]
fn compiled_rule_subset_is_bounded_and_byte_preserving() {
    assert_eq!(
        CompiledRule::parse("c$1")
            .unwrap()
            .apply(b"pASSWORD")
            .unwrap(),
        Some(b"Password1".to_vec())
    );
    assert_eq!(
        CompiledRule::parse("uT0").unwrap().apply(b"test").unwrap(),
        Some(b"tEST".to_vec())
    );
    assert_eq!(
        CompiledRule::parse("saz^!")
            .unwrap()
            .apply(b"banana")
            .unwrap(),
        Some(b"!bznznz".to_vec())
    );
    assert_eq!(
        CompiledRule::parse("r[]").unwrap().apply(b"abcd").unwrap(),
        Some(b"cb".to_vec())
    );
    assert_eq!(
        CompiledRule::parse(":").unwrap().apply(&[255, 0]).unwrap(),
        Some(vec![255, 0])
    );
    assert!(CompiledRule::parse("d")
        .unwrap()
        .apply(&vec![b'x'; 2049])
        .is_err());
    assert!(CompiledRule::parse("$!")
        .unwrap()
        .apply(&vec![b'x'; 4096])
        .is_err());
    for bad in ["", "$", "T?", "sA", "z", "\n"] {
        assert!(CompiledRule::parse(bad).is_err());
    }
    assert!(CompiledRule::parse(&"l".repeat(MAX_RULE_INSTRUCTIONS + 1)).is_err());
}

#[test]
fn mask_resume_by_offset_matches_deterministic_source() {
    let reference = MaskCandidates::parse("A?d??").unwrap().collect::<Vec<_>>();
    assert_eq!(reference.len(), 10);
    let mut resumed = MaskCandidates::parse_from_offset("A?d??", 7).unwrap();
    assert_eq!(resumed.total(), 10);
    assert_eq!(resumed.position(), 7);
    assert_eq!(resumed.remaining(), 3);
    assert_eq!(resumed.next().unwrap(), reference[7]);
    assert_eq!(resumed.position(), 8);
    assert_eq!(resumed.collect::<Vec<_>>(), reference[8..].to_vec());
    assert_eq!(
        MaskCandidates::parse_from_offset("A?d??", 10)
            .unwrap()
            .next(),
        None
    );
    assert!(MaskCandidates::parse_from_offset("A?d??", 11).is_err());
    assert!(MaskCandidates::parse_from_offset("?a?a?a?a", 0).is_err());
}

#[test]
fn masks_and_rules_are_bounded() {
    let mut items = MaskCandidates::parse("A?d??").unwrap();
    assert_eq!(items.remaining(), 10);
    assert_eq!(items.next().unwrap(), b"A0?");
    assert_eq!(items.last().unwrap(), b"A9?");
    assert!(MaskCandidates::parse("?a?a?a?a").is_err());
    assert_eq!(apply_rule(b"Pass", Rule::Lower).unwrap(), b"pass");
    assert!(apply_rule(&vec![b'x'; 4096], Rule::Duplicate).is_err());
}

#[test]
fn sha256_backend_cpu_known_vector_progress_and_limit() {
    let target = hex::encode(crate::apply_op("sha256", b"secret", None).unwrap());
    let mut snapshots = Vec::new();
    let outcome = recover_sha256_wordlist_on_backend(
        RecoveryBackend::Cpu,
        &target,
        std::io::Cursor::new(b"wrong\nsecret\nignored\n".as_slice()),
        RecoveryLimits {
            max_candidates: 3,
            max_matches: 1,
        },
        || false,
        |snapshot| snapshots.push(snapshot),
    )
    .unwrap();
    assert_eq!(outcome.tried, 2);
    assert_eq!(outcome.hits.len(), 1);
    assert_eq!(outcome.hits[0].index, 1);
    assert_eq!(outcome.hits[0].candidate, b"secret");
    assert_eq!(snapshots.last().unwrap().tried, 2);
    assert_eq!(snapshots.last().unwrap().budget, 3);
}

#[test]
fn sha256_selected_gpu_cancel_before_hardware_and_no_secret_progress() {
    let mut snapshots = Vec::new();
    let result = recover_sha256_wordlist_on_backend(
        RecoveryBackend::OpenCl {
            device_index: 0,
            batch_size: 16,
        },
        &"00".repeat(32),
        std::io::Cursor::new(b"secret\n".as_slice()),
        RecoveryLimits {
            max_candidates: 1,
            max_matches: 1,
        },
        || true,
        |snapshot| snapshots.push(snapshot),
    )
    .unwrap();
    assert!(result.cancelled);
    assert_eq!(result.tried, 0);
    assert!(result.hits.is_empty());
    assert_eq!(snapshots.last().unwrap().tried, 0);
    assert!(!serde_json::to_string(snapshots.last().unwrap())
        .unwrap()
        .contains("secret"));
}

#[test]
fn sha256_backend_rejects_bad_target_without_reading() {
    let outcome = recover_sha256_wordlist_on_backend(
        RecoveryBackend::OpenCl {
            device_index: 0,
            batch_size: 16,
        },
        "not-a-hash",
        std::io::Cursor::new(b"anything\n".as_slice()),
        RecoveryLimits::default(),
        || false,
        |_| panic!("invalid target must never report completed work"),
    );
    assert!(outcome.is_err());
}

#[test]
fn sha256_backend_rejects_modular_kdf_targets() {
    let kdf = "$2b$04$CCCCCCCCCCCCCCCCCCCCCCabcdefghijklmnopqrstuvwxyZ1234567890AB";
    assert!(matches!(
        RecoveryTarget::parse("sha256", kdf),
        Ok(RecoveryTarget::Kdf { .. })
    ));
    let outcome = recover_sha256_wordlist_on_backend(
        RecoveryBackend::Cpu,
        kdf,
        std::io::Cursor::new(b"secret\n".as_slice()),
        RecoveryLimits::default(),
        || false,
        |_| panic!("non-SHA256 targets must be rejected before processing"),
    );
    assert!(outcome.unwrap_err().contains("raw SHA-256 digest"));
}

/// SHA3-256 is a distinct Keccak/SHA-3 digest, not an alias for SHA-256.
/// Golden value is SHA3-256("abc") from the standard FIPS 202 test vector.
#[test]
fn sha3_256_recovery_fips202_vector_with_binary_safe_wordlist() {
    use std::io::Cursor;
    const ABC_SHA3: &str = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
    let target = RecoveryTarget::parse("sha3_256", ABC_SHA3).unwrap();
    assert!(matches!(
        target,
        RecoveryTarget::Digest {
            algorithm: FastHash::Sha3_256,
            ..
        }
    ));
    assert!(!target.is_match(b"abd").unwrap());
    assert!(target.is_match(b"abc").unwrap());
    assert_eq!(
        hex::encode(apply_op("sha3_256", b"abc", None).unwrap()),
        ABC_SHA3
    );
    let mut progress = Vec::new();
    let report = recover_wordlist_with_progress(
        &target,
        Cursor::new(b"\xff\nwrong\r\nabc\nunused\n".as_slice()),
        RecoveryLimits {
            max_candidates: 4,
            max_matches: 1,
        },
        || false,
        |p| progress.push(p),
    )
    .unwrap();
    assert_eq!(report.tried, 3);
    assert!(!report.cancelled);
    assert_eq!(report.hits.len(), 1);
    assert_eq!(report.hits[0].index, 2);
    assert_eq!(report.hits[0].candidate, b"abc");
    assert_eq!(progress.last().unwrap().tried, 3);
    assert_eq!(progress.last().unwrap().budget, 4);
    assert_eq!(progress.last().unwrap().matches, 1);
    assert!(!serde_json::to_string(&progress).unwrap().contains("abc"));
}

#[test]
fn sha3_256_aliases_accept_uppercase_hex_but_reject_invalid_length_and_format() {
    const ABC_SHA3: &str = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
    let aliases = ["sha3_256", "sha3-256", "SHA3_256"];
    for alias in aliases {
        let target = RecoveryTarget::parse(alias, &ABC_SHA3.to_ascii_uppercase()).unwrap();
        assert!(target.is_match(b"abc").unwrap());
    }
    for bad in ["", "zz", "ab"] {
        assert!(RecoveryTarget::parse("sha3_256", bad).is_err());
    }
    assert!(RecoveryTarget::parse("sha3_256", &"00".repeat(33)).is_err());
    assert!(RecoveryTarget::parse("sha3_256", "$6$salt$hash").is_err());
    assert!(!RecoveryTarget::parse("sha256", &"00".repeat(32))
        .unwrap()
        .is_match(b"abc")
        .unwrap());
}

#[test]
fn sha3_256_global_limit_and_cancel_stay_lazy() {
    let target = RecoveryTarget::parse("sha3_256", &"00".repeat(32)).unwrap();
    let pulls = std::cell::Cell::new(0usize);
    let stream = std::iter::from_fn(|| {
        pulls.set(pulls.get() + 1);
        Some(b"bad".to_vec())
    });
    let capped = recover(
        &target,
        stream,
        RecoveryLimits {
            max_candidates: 2,
            max_matches: 1,
        },
        || false,
    )
    .unwrap();
    assert_eq!(capped.tried, 2);
    assert_eq!(pulls.get(), 2);
    assert!(capped.limit_reached);
    let mut checks = 0u32;
    let stopped = recover(
        &target,
        [b"a", b"b", b"c"],
        RecoveryLimits::default(),
        || {
            checks += 1;
            checks > 1
        },
    )
    .unwrap();
    assert!(stopped.cancelled);
    assert_eq!(stopped.tried, 1);
}

#[test]
fn yescrypt_bounded_known_password_and_streaming() {
    use yescrypt::password_hash::CustomizedPasswordHasher as _;
    let encoded = yescrypt::Yescrypt::default()
        .hash_password_customized(
            b"hello",
            b"0123456789abcdef",
            None,
            None,
            yescrypt::Params::default(),
        )
        .unwrap()
        .to_string();
    assert!(encoded.starts_with("$y$j9T$"));
    let target = RecoveryTarget::parse("", &encoded).unwrap();
    assert!(target.is_kdf());
    assert!(target.is_match(b"hello").unwrap());
    assert!(!target.is_match(b"wrong").unwrap());
    let mut progress = Vec::new();
    let result = recover_wordlist_with_progress(
        &target,
        std::io::Cursor::new(b"wrong\nhello\nunused\n".as_slice()),
        RecoveryLimits {
            max_candidates: 3,
            max_matches: 1,
        },
        || false,
        |update| progress.push(update),
    )
    .unwrap();
    assert_eq!(result.tried, 2);
    assert_eq!(result.hits[0].index, 1);
    assert_eq!(result.hits[0].candidate, b"hello");
    assert_eq!(progress.last().unwrap().tried, 2);
    assert_eq!(progress.last().unwrap().budget, 3);
    assert!(!serde_json::to_string(progress.last().unwrap())
        .unwrap()
        .contains("hello"));
}

#[test]
fn yescrypt_strict_encoding_and_cost_boundaries() {
    use yescrypt::{Mode, Params};
    let sample = |params: &str| ["$y$", params, "$0123456789abcdef1234$", &"x".repeat(43)].concat();
    let canonical = |n, r, p| Params::new(Mode::Rw, n, r, p).unwrap().to_string();
    for (n, r) in [(4096, 32), (8192, 32), (4096, 8)] {
        assert!(RecoveryTarget::parse("", &sample(&canonical(n, r, 1))).is_ok());
    }
    for (n, r) in [(16384, 32), (32768, 8), (4096, 64)] {
        assert!(RecoveryTarget::parse("", &sample(&canonical(n, r, 1))).is_err());
    }
    for params in [
        canonical(4096, 32, 2),
        Params::new_with_all_params(Mode::Rw, 4096, 32, 1, 1, 0)
            .unwrap()
            .to_string(),
        Params::new(Mode::Classic, 4096, 32, 1).unwrap().to_string(),
        "j9Tjunk".into(),
        "j9!".into(),
        "jzz".into(),
        "j9".into(),
    ] {
        assert!(
            RecoveryTarget::parse("", &sample(&params)).is_err(),
            "{params}"
        );
    }
    for malformed in [
        "$7$test$hash".to_string(),
        "$y$j9T$0123456789abcdef1234".into(),
        "$y$j9T$short$short".into(),
        "$y$j9T$0123456789abcdef1234$".into(),
        "$y$j9T$0123456789abcdef1234$abc!def".into(),
        ["$y$j9T$0123456789abcdef1234$", &"x".repeat(43), "$extra"].concat(),
        ["$y$j9T$", &"A".repeat(200), "$hash"].concat(),
    ] {
        assert!(
            RecoveryTarget::parse("", &malformed).is_err(),
            "{malformed}"
        );
    }
    for params in ["j..", "jzz", "j~~", "j9zzzzzz", "j9T."] {
        let input = sample(params);
        assert!(std::panic::catch_unwind(|| RecoveryTarget::parse("", &input)).is_ok());
        assert!(RecoveryTarget::parse("", &input).is_err());
    }
}

#[test]
fn yescrypt_cancel_and_global_candidate_cap_without_prefetch() {
    use yescrypt::password_hash::CustomizedPasswordHasher as _;
    let encoded = yescrypt::Yescrypt::default()
        .hash_password_customized(
            b"hello",
            b"0123456789abcdef",
            None,
            None,
            yescrypt::Params::default(),
        )
        .unwrap()
        .to_string();
    let target = RecoveryTarget::parse("", &encoded).unwrap();
    let stopped = recover_wordlist(
        &target,
        std::io::Cursor::new(b"hello\n".as_slice()),
        RecoveryLimits::default(),
        || true,
    )
    .unwrap();
    assert!(stopped.cancelled);
    assert_eq!(stopped.tried, 0);
    let input = [b"wrong\n".to_vec(), vec![b'X'; MAX_CANDIDATE_BYTES + 128]].concat();
    let limited = recover_wordlist(
        &target,
        std::io::Cursor::new(input),
        RecoveryLimits {
            max_candidates: 1,
            max_matches: 1,
        },
        || false,
    )
    .unwrap();
    assert_eq!(limited.tried, 1);
    assert!(limited.limit_reached);
    assert!(limited.hits.is_empty());
    assert!(recover_wordlist(
        &target,
        std::io::Cursor::new(b"hello\n".as_slice()),
        RecoveryLimits {
            max_candidates: 0,
            max_matches: 1
        },
        || false,
    )
    .is_err());
}

#[test]
fn batch7_9_targets_self_detect_or_verify_via_hints() {
    use crate::kdf_format;
    // The unified WPA record (mode 22000) supersedes the legacy 40-hex
    // PMKID form: the old windows_auth vector still verifies through the
    // new salted_variants verifier after the detection reroute.
    let legacy_pmkid = "WPA*01*8f1bddadd02e1417163f03af545892cc6998eff4*aabbccddeeff*112233445566*546573744e6574****";
    assert_eq!(kdf_format(legacy_pmkid), Some("wpa"));
    let target = RecoveryTarget::parse("", legacy_pmkid).unwrap();
    assert!(target.is_match(b"cyberdeck").unwrap());
    assert!(!target.is_match(b"Cyberdeck").unwrap());
    // The four-field PMKID capture (mode 16800) self-detects by shape.
    let pmkid = "2582a8281bf9d4308d6f5731d0e61c61:4604ba734d4e:89acf0e761f4:ed487162465a774bfba60eb603a39f3a";
    assert_eq!(kdf_format(pmkid), Some("wpa-pmkid"));
    assert!(RecoveryTarget::parse("", pmkid).unwrap().is_match(b"hashcat!").unwrap());
    // Self-describing batch 7/8/9 wires route through their verifiers.
    assert_eq!(kdf_format("0x01004b617433000000000000000000000000000000000000000051c88bd2152a6c7862d3db9c9b011e0513fbd941"), Some("mssql-2000"));
    assert!(RecoveryTarget::parse("", "0x01004b617433000000000000000000000000000000000000000051c88bd2152a6c7862d3db9c9b011e0513fbd941").unwrap().is_match(b"cyberdeck").unwrap());
    assert_eq!(kdf_format("$luks$1$ripemd160$aes$bad"), Some("luks"));
    assert_eq!(kdf_format("$rar5$16$00$00$00$00"), Some("rar5"));
    assert_eq!(kdf_format("$RAR3$*0*00*00"), Some("rar3-hp"));
    assert_eq!(kdf_format("$keepass$*4*2*ef636ddf*67108864*19*2*00*00*00*00"), Some("keepass-kdbx4"));
    assert_eq!(kdf_format("$keepass$*2*24569*0*a*b*c*d"), Some("keepass"));
    assert_eq!(kdf_format("$krb5tgs$17$user$realm$00$00"), Some("kerberos-tgs-rep-17"));
    assert_eq!(kdf_format("$krb5tgs$18$user$realm$00$00"), Some("kerberos-tgs-rep-18"));
    assert_eq!(kdf_format("$krb5tgs$23$user$realm$00$00"), Some("kerberos-tgs-rep"));
    assert_eq!(kdf_format("$pdf$5*5*256*0*0*16*00*32*00*0*00*0*00*0*00"), Some("pdf-1.7"));
    assert_eq!(kdf_format("$pdf$1*2*40*x"), Some("pdf-1.1-1.3"));
    // Bare-digest salted variants are hint-driven and verify via the
    // stored-format path exactly like the existing hint-driven ones.
    for (hint, encoded, password) in [
        ("mysql4.1", "87c7b8262d3208503687a0b37014057a334c19e4", "cyberdeck"),
        ("oracle-h", "ED122223D01263D6:cyberdeck", "cyberdeck"),
        ("smf", "d27c0a627a45db487af161fcc3a4005d88eb8a1f:25551135", "hashcat"),
        ("macos-salted-sha1", "86586886b8bd3c379d2e176243a7225e6aae969d293fe9a9", "hashcat"),
    ] {
        let target = RecoveryTarget::parse(hint, encoded).unwrap();
        assert!(target.is_match(password.as_bytes()).unwrap(), "{hint}");
        assert!(!target.is_match(b"not-the-solution").unwrap(), "{hint}");
    }
    assert!(kdf_format("87c7b8262d3208503687a0b37014057a334c19e4").is_none());
}

// --- SIMD batched fast-digest engine equivalence ---------------------------
//
// recover_checked routes bare md5/sha256 digests through the multi-buffer
// engine. These tests pin it to the per-candidate scalar engine: a fixed
// candidate set goes through both engines under identical limits and the
// full results — tried, hits (indices, candidates, target field), flags and
// progress samples — must be identical.

/// Deterministic byte pattern (mirrors simd_digest's test helper).
fn simd_test_pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(7)).collect()
}

/// Fresh owned stream over a fixed candidate set (engines consume iterators).
fn simd_test_stream(
    candidates: &[Vec<u8>],
) -> impl Iterator<Item = Result<Vec<u8>, String>> + use<'_> {
    candidates.iter().cloned().map(|c| Ok::<Vec<u8>, String>(c))
}

fn simd_test_limits(cap: u64, max_matches: usize) -> RecoveryLimits {
    RecoveryLimits {
        max_candidates: cap,
        max_matches,
    }
}

fn assert_engines_agree(
    scalar: &RecoveryResult,
    batched: &RecoveryResult,
    context: &str,
) {
    assert_eq!(scalar.engine, batched.engine, "{context}: engine id");
    assert_eq!(scalar.tried, batched.tried, "{context}: tried");
    assert_eq!(scalar.hits, batched.hits, "{context}: hits and indices");
    assert_eq!(scalar.cancelled, batched.cancelled, "{context}: cancelled");
    assert_eq!(
        scalar.limit_reached, batched.limit_reached,
        "{context}: limit_reached"
    );
}

/// The dispatcher must select the multi-buffer engine for bare md5/sha256
/// digests only; every other target shape keeps the scalar engine.
#[test]
fn simd_batch_engine_selects_only_bare_md5_and_sha256() {
    let md5 = RecoveryTarget::parse("md5", &"00".repeat(16)).unwrap();
    let sha256 = RecoveryTarget::parse("sha256", &"00".repeat(32)).unwrap();
    assert!(matches!(
        DigestBatch::for_target(&md5),
        Some(DigestBatch::Md5(_))
    ));
    assert!(matches!(
        DigestBatch::for_target(&sha256),
        Some(DigestBatch::Sha256(_))
    ));
    // Same 16-byte digest size, different family: scalar engine.
    let ntlm = RecoveryTarget::parse("ntlm", "8846f7eaee8fb117ad06bdd830b7586c").unwrap();
    let sha1 = RecoveryTarget::parse("sha1", &"00".repeat(20)).unwrap();
    let bcrypt = RecoveryTarget::parse(
        "sha256",
        "$2b$04$CCCCCCCCCCCCCCCCCCCCCCabcdefghijklmnopqrstuvwxyZ1234567890AB",
    )
    .unwrap();
    let multi = RecoveryTarget::parse_multi(
        "md5",
        &["5d41402abc4b2a76b9719d911017c592".to_string(), "00".repeat(16)],
    )
    .unwrap();
    for target in [&ntlm, &sha1, &bcrypt, &multi] {
        assert!(
            DigestBatch::for_target(target).is_none(),
            "{target:?} must keep the scalar engine"
        );
    }
}

/// Fixed candidate set, both engines, identical outcomes. The set spans a
/// full 4096 batch plus change, with matches at the edges (first, mid,
/// duplicated, last-of-batch, first-of-next-batch, tail) and an empty
/// candidate, against every match-quota and cap boundary that changes where
/// the scalar engine stops.
#[test]
fn simd_batched_fast_digest_engine_matches_scalar_engine_exactly() {
    // Prove the multi-buffer path itself is live on this machine (not the
    // in-module scalar fallback): AVX2 must select the 8-lane path.
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            assert_eq!(crate::simd_digest::active_path(), "avx2-8-lane");
        } else {
            assert_ne!(crate::simd_digest::active_path(), "scalar");
        }
    }

    let mut candidates: Vec<Vec<u8>> = vec![Vec::new()]; // empty candidate
    for len in [1usize, 3, 31, 54, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 255, 256] {
        candidates.push(simd_test_pattern(len));
    }
    let filler = simd_test_pattern(40);
    while candidates.len() < 4100 {
        candidates.push(filler.clone());
    }
    // Matches at stop-boundary-sensitive positions.
    candidates[1] = b"alpha-match".to_vec();
    candidates[2050] = b"mid-match".to_vec();
    candidates[2051] = b"mid-match".to_vec(); // duplicate: both must be hit
    candidates[4095] = b"boundary-match".to_vec(); // last of batch one
    candidates[4096] = b"post-boundary-match".to_vec(); // first of batch two
    candidates[4099] = b"tail-match".to_vec(); // last candidate overall

    for (algo, size) in [("md5", 16usize), ("sha256", 32)] {
        for password in [
            "alpha-match",
            "mid-match",
            "boundary-match",
            "post-boundary-match",
            "tail-match",
            "no-such-candidate",
        ] {
            let target = RecoveryTarget::parse(
                algo,
                &hex::encode(apply_op(algo, password.as_bytes(), None).unwrap()),
            )
            .unwrap();
            assert!(!target.is_kdf());
            let batch = DigestBatch::for_target(&target)
                .unwrap_or_else(|| panic!("{algo} digest must take the batched engine"));
            let expected = apply_op(algo, password.as_bytes(), None).unwrap();
            assert_eq!(expected.len(), size);
            match batch {
                DigestBatch::Md5(digest) => {
                    assert_eq!(&digest[..], &expected[..]);
                }
                DigestBatch::Sha256(digest) => {
                    assert_eq!(&digest[..], &expected[..]);
                }
            }
            for max_matches in [1usize, 2, 5] {
                for cap in [10u64, 4095, 4096, 4097, 5000, 1u64 << 40] {
                    let limits = simd_test_limits(cap, max_matches);
                    let context = format!("{algo} {password} max_matches={max_matches} cap={cap}");
                    let mut scalar_progress = Vec::new();
                    let scalar = recover_checked_scalar(
                        &target,
                        simd_test_stream(&candidates),
                        limits,
                        || false,
                        |p| scalar_progress.push(p),
                    )
                    .unwrap();
                    let mut batched_progress = Vec::new();
                    let batched = recover_checked_batched(
                        batch,
                        simd_test_stream(&candidates),
                        limits,
                        || false,
                        |p| batched_progress.push(p),
                    )
                    .unwrap();
                    assert_engines_agree(&scalar, &batched, &context);
                    assert_eq!(
                        scalar_progress, batched_progress,
                        "{context}: progress samples"
                    );
                    // Every recorded hit verifies through the scalar
                    // single-candidate path and maps back to its index.
                    for hit in &batched.hits {
                        assert_eq!(
                            target.match_target(&hit.candidate).unwrap(),
                            Some(0),
                            "{context}: hit must verify scalar-side"
                        );
                        assert_eq!(
                            candidates[hit.index as usize], hit.candidate,
                            "{context}: hit index must address its candidate"
                        );
                    }
                }
            }
        }
    }
}

/// Cancellation granularity: both engines poll once per pull attempt, so a
/// counter-based cancel flips at the same attempt and must stop both engines
/// at the same stream position with the same flags and poll counts.
#[test]
fn simd_batched_engine_cancellation_stops_at_the_same_position() {
    // Zero digest: no candidate ever matches, so quota never interferes.
    let target = RecoveryTarget::parse("md5", &"00".repeat(16)).unwrap();
    let batch = DigestBatch::for_target(&target).unwrap();
    let candidates: Vec<Vec<u8>> = (0..100u32).map(|i| simd_test_pattern(i as usize + 1)).collect();
    for flip_after in [0usize, 1, 50, 99, 100, 101, 4096] {
        let mut scalar_polls = 0usize;
        let scalar = recover_checked_scalar(
            &target,
            simd_test_stream(&candidates),
            simd_test_limits(1_000_000, 1),
            || {
                scalar_polls += 1;
                scalar_polls > flip_after
            },
            |_| {},
        )
        .unwrap();
        let mut batched_polls = 0usize;
        let batched = recover_checked_batched(
            batch,
            simd_test_stream(&candidates),
            simd_test_limits(1_000_000, 1),
            || {
                batched_polls += 1;
                batched_polls > flip_after
            },
            |_| {},
        )
        .unwrap();
        let context = format!("flip_after={flip_after}");
        assert_engines_agree(&scalar, &batched, &context);
        assert_eq!(scalar_polls, batched_polls, "{context}: cancel poll count");
    }
}

/// Error visibility: the scalar engine stops pulling once the match quota
/// fills, so a stream error or oversized candidate sitting after the
/// quota-filling candidate must never surface. The batched engine pulls it
/// during fill, so it defers the error and must reproduce the scalar
/// outcome in both directions.
#[test]
fn simd_batched_engine_error_visibility_matches_scalar_exactly() {
    let password = b"found-early";
    let target = RecoveryTarget::parse(
        "md5",
        &hex::encode(apply_op("md5", password, None).unwrap()),
    )
    .unwrap();
    let batch = DigestBatch::for_target(&target).unwrap();
    let wrong = RecoveryTarget::parse("md5", &"00".repeat(16)).unwrap();
    let wrong_batch = DigestBatch::for_target(&wrong).unwrap();
    let oversized = vec![b'X'; MAX_CANDIDATE_BYTES + 1];
    let limits = simd_test_limits(100, 1);

    // Oversized candidate after the quota-filling match: clean Ok on both.
    let after_match = vec![
        Ok(b"miss".to_vec()),
        Ok(password.to_vec()),
        Ok(oversized.clone()),
    ];
    let scalar = recover_checked_scalar(
        &target,
        after_match.clone().into_iter(),
        limits,
        || false,
        |_| {},
    )
    .unwrap();
    let batched = recover_checked_batched(
        batch,
        after_match.clone().into_iter(),
        limits,
        || false,
        |_| {},
    )
    .unwrap();
    assert_engines_agree(&scalar, &batched, "oversized after quota fill");
    assert_eq!(scalar.tried, 2);
    assert_eq!(scalar.hits[0].candidate, password);

    // Same oversized candidate with nothing matching: identical Err on both.
    let scalar = recover_checked_scalar(
        &wrong,
        after_match.clone().into_iter(),
        limits,
        || false,
        |_| {},
    );
    let batched = recover_checked_batched(
        wrong_batch,
        after_match.clone().into_iter(),
        limits,
        || false,
        |_| {},
    );
    assert_eq!(
        scalar.unwrap_err(),
        batched.unwrap_err(),
        "oversized with no quota fill must error on both engines"
    );

    // Stream error instead of an oversized candidate: same two directions.
    let with_error = vec![
        Ok(b"miss".to_vec()),
        Err("fixture disk error".to_string()),
        Ok(password.to_vec()),
    ];
    let scalar = recover_checked_scalar(
        &wrong,
        with_error.clone().into_iter(),
        limits,
        || false,
        |_| {},
    );
    let batched = recover_checked_batched(
        wrong_batch,
        with_error.clone().into_iter(),
        limits,
        || false,
        |_| {},
    );
    assert_eq!(scalar.unwrap_err(), batched.unwrap_err(), "stream error");
    let error_after_match = vec![Ok(password.to_vec()), Err("fixture disk error".to_string())];
    let scalar = recover_checked_scalar(
        &target,
        error_after_match.clone().into_iter(),
        limits,
        || false,
        |_| {},
    )
    .unwrap();
    let batched = recover_checked_batched(
        batch,
        error_after_match.clone().into_iter(),
        limits,
        || false,
        |_| {},
    )
    .unwrap();
    assert_engines_agree(&scalar, &batched, "stream error after quota fill");
    assert_eq!(scalar.tried, 1);
    assert_eq!(scalar.hits.len(), 1);
}

