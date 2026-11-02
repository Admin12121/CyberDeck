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
