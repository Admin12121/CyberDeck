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
    assert_eq!(rules[0].apply(b"pASSWORD").unwrap(), b"Password1");
    assert_eq!(rules[1].apply(b"ABC").unwrap(), b"abc");
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
        b"Password1"
    );
    assert_eq!(
        CompiledRule::parse("uT0").unwrap().apply(b"test").unwrap(),
        b"tEST"
    );
    assert_eq!(
        CompiledRule::parse("saz^!")
            .unwrap()
            .apply(b"banana")
            .unwrap(),
        b"!bznznz"
    );
    assert_eq!(
        CompiledRule::parse("r[]").unwrap().apply(b"abcd").unwrap(),
        b"cb"
    );
    assert_eq!(
        CompiledRule::parse(":").unwrap().apply(&[255, 0]).unwrap(),
        vec![255, 0]
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
