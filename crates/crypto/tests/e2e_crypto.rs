//! End-to-end suite over the public API only: recipe round-trips for every
//! encoding pair in the op catalog, the CPU recovery pipeline against temp
//! wordlists with storage-backed resume checkpoints, and the mongodb,
//! windows_auth and simd verifiers. All data is self-generated in tempdirs.
use base64::Engine as _;
use sha2::Digest as _;
use cyberdeck_crypto::recipes::{execute_recipe, native_operation, RecipeStep};
use cyberdeck_crypto::recovery::{
    recover_sha256_wordlist_on_backend, recover_wordlist_resumable, RecoveryBackend,
    RecoveryLimits, RecoveryTarget,
};
use cyberdeck_crypto::{apply_op, catalog, mongodb, simd_digest, windows_auth};

fn step(op_id: &str) -> RecipeStep {
    RecipeStep {
        op_id: op_id.to_string(),
        enabled: true,
        param: None,
    }
}

fn run_recipe(input: &str, steps: &[RecipeStep]) -> Vec<u8> {
    let result = execute_recipe(input, steps);
    assert!(result.error.is_none(), "{:?}", result.error);
    base64::engine::general_purpose::STANDARD
        .decode(&result.output_b64)
        .unwrap()
}

fn tempdir(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("cyberdeck-e2e-{tag}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// XORSHIFT-derived 1 MiB buffer for the binary pair round-trips.
fn large_binary() -> Vec<u8> {
    let mut state = 0x243f_6a88_85a3_08d3u64;
    let mut random = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state.to_le_bytes().to_vec()
    };
    let mut out = Vec::with_capacity(1024 * 1024);
    while out.len() < 1024 * 1024 {
        out.extend_from_slice(&random());
    }
    out.truncate(1024 * 1024);
    out
}

fn write_wordlist(dir: &std::path::Path, words: &[&str]) -> std::path::PathBuf {
    let path = dir.join("wordlist.txt");
    std::fs::write(&path, words.join("\n") + "\n").unwrap();
    path
}

/// Encoding pairs that round-trip arbitrary text, including the 1 MiB input:
/// every codec here is linear-time, so the full-size input stays fast.
fn encoding_pairs() -> Vec<(&'static str, &'static str)> {
    vec![
        ("to_base64", "from_base64"),
        ("to_hex", "from_hex"),
        ("url_encode", "url_decode"),
        ("to_base45", "from_base45"),
        ("to_base85", "from_base85"),
        ("to_base92", "from_base92"),
        ("to_bech32", "from_bech32"),
        ("to_octal", "from_octal"),
        ("escape_unicode", "unescape_unicode"),
        ("to_hex_content", "from_hex_content"),
        ("to_modhex", "from_modhex"),
        ("to_quoted_printable", "from_quoted_printable"),
        ("to_punycode", "from_punycode"),
        ("encode_text", "decode_text"),
    ]
}

/// COBS output is binary, so the pair cannot travel through the executor's
/// UTF-8 text pipeline; it round-trips through apply_op instead.
fn binary_pairs() -> Vec<(&'static str, &'static str)> {
    vec![("to_cobs", "from_cobs")]
}

/// Big-number codecs: CyberChef's digit-array method is quadratic, so these
/// round-trip over short inputs only.
fn big_number_pairs() -> Vec<(&'static str, &'static str)> {
    vec![
        ("to_base58", "from_base58"),
        ("to_base58check", "from_base58check"),
        ("to_base62", "from_base62"),
    ]
}

/// Number-string codecs: tested with inputs from their own domain.
fn domain_pairs() -> Vec<(&'static str, &'static str, Vec<&'static str>)> {
    vec![
        ("to_base", "from_base", vec!["0", "4276803"]),
        ("to_bcd", "from_bcd", vec!["0", "1234567890"]),
        ("to_float", "from_float", vec!["", "abcd1234"]),
    ]
}

#[test]
fn catalog_encoding_pairs_round_trip_through_recipe_executor() {
    let catalog = catalog();
    let encoding_ids: Vec<&str> = catalog
        .iter()
        .filter(|op| op.category == "encoding")
        .map(|op| op.id.as_str())
        .collect();
    let mut pair_ids: Vec<&str> = encoding_pairs()
        .iter()
        .chain(binary_pairs().iter())
        .chain(big_number_pairs().iter())
        .flat_map(|(e, d)| [*e, *d])
        .collect();
    pair_ids.extend(domain_pairs().iter().flat_map(|(e, d, _)| [*e, *d]));
    pair_ids.push("to_braille");
    pair_ids.push("from_braille");
    let mut expected = encoding_ids.clone();
    expected.sort_unstable();
    pair_ids.sort_unstable();
    assert_eq!(expected, pair_ids, "catalog encoding ops changed; update the pair table");
    for id in &pair_ids {
        assert!(native_operation(id), "{id} is not a native recipe op");
    }

    let mebibyte = "cyberdeck-e2e-42".repeat(65536);
    assert_eq!(mebibyte.len(), 1024 * 1024);
    let inputs: Vec<&str> = vec!["", "abc", "CyberDeck ❄️ héllo 雪 🔑", &mebibyte];
    for (encode, decode) in encoding_pairs() {
        for input in &inputs {
            let encoded_bytes = run_recipe(input, &[step(encode)]);
            let encoded = std::str::from_utf8(&encoded_bytes)
                .unwrap_or_else(|_| panic!("{encode} emitted non-UTF-8 output"));
            let restored = run_recipe(encoded, &[step(decode)]);
            assert_eq!(restored, input.as_bytes(), "{decode}({encode}(x)) != x");
        }
    }
    for (encode, decode) in big_number_pairs() {
        for input in ["", "abc", "CyberDeck ❄️ héllo 雪 🔑"] {
            let encoded_bytes = run_recipe(input, &[step(encode)]);
            let encoded = std::str::from_utf8(&encoded_bytes)
                .unwrap_or_else(|_| panic!("{encode} emitted non-UTF-8 output"));
            assert_eq!(run_recipe(encoded, &[step(decode)]), input.as_bytes());
        }
    }
    for (encode, decode, inputs) in domain_pairs() {
        for input in inputs {
            let encoded_bytes = run_recipe(input, &[step(encode)]);
            let encoded = std::str::from_utf8(&encoded_bytes)
                .unwrap_or_else(|_| panic!("{encode} emitted non-UTF-8 output"));
            assert_eq!(run_recipe(encoded, &[step(decode)]), input.as_bytes());
        }
    }
    for (encode, decode) in binary_pairs() {
        for input in [&Vec::new(), &b"abc\x00\x01\xfe"[..], &large_binary()] {
            let encoded = apply_op(encode, input, None).unwrap();
            assert_eq!(apply_op(decode, &encoded, None).unwrap(), *input);
        }
    }
    // CyberChef's To Braille uppercases before lookup, so the decode is the
    // uppercased text rather than the original.
    let encoded_bytes = run_recipe("Hello, World! 123", &[step("to_braille")]);
    let encoded = std::str::from_utf8(&encoded_bytes).unwrap();
    assert_eq!(run_recipe(encoded, &[step("from_braille")]), b"HELLO, WORLD! 123");
}

#[test]
fn disabled_steps_are_skipped_by_the_executor() {
    let mut skipped = step("to_base64");
    skipped.enabled = false;
    assert_eq!(
        run_recipe("abc", &[skipped, step("to_hex"), step("from_hex")]),
        b"abc"
    );
}

#[test]
fn binary_payloads_round_trip_through_public_ops() {
    // The recipe executor takes &str input, so non-UTF-8 bytes go through
    // apply_op — the same op layer the executor's ported steps call into.
    let mut state = 0x243f_6a88_85a3_08d3u64;
    let mut random = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state.to_le_bytes().to_vec()
    };
    let mut large = Vec::with_capacity(1024 * 1024);
    while large.len() < 1024 * 1024 {
        large.extend_from_slice(&random());
    }
    large.truncate(1024 * 1024);
    let empty: Vec<u8> = Vec::new();
    let short = vec![0xff, 0xfe, 0x00, 0x80];
    for input in [&empty, &short, &large] {
        for (encode, decode) in [("to_base64", "from_base64"), ("to_hex", "from_hex"), ("url_encode", "url_decode")] {
            let encoded = apply_op(encode, input, None).unwrap();
            assert_eq!(apply_op(decode, &encoded, None).unwrap(), *input, "{decode}({encode}(bytes)) != bytes");
        }
    }
}

#[test]
fn cpu_wordlist_request_finds_digest_in_temp_wordlist() {
    // RecoveryRequest shape on the wire (algorithm, target hash, CPU backend,
    // candidate budget) maps here to RecoveryTarget + RecoveryLimits +
    // RecoveryBackend::Cpu — the desktop layer feeds exactly these into
    // recover_sha256_wordlist_on_backend.
    let answer = "e2e-wordlist-answer-7741";
    let words = ["alpha", "bravo", "charlie", answer, "delta"];
    let digest_hex = hex::encode(apply_op("sha256", answer.as_bytes(), None).unwrap());

    let dir = tempdir("wordlist");
    let path = write_wordlist(&dir, &words);
    let read = |path: &std::path::Path| std::io::BufReader::new(std::fs::File::open(path).unwrap());
    let result = recover_sha256_wordlist_on_backend(
        RecoveryBackend::Cpu,
        &digest_hex,
        read(&path),
        RecoveryLimits { max_candidates: 1000, max_matches: 1 },
        || false,
        |_| {},
    )
    .unwrap();
    assert_eq!(result.engine, "cyberdeck-crypto-cpu");
    // A filled match quota ends the run at the quota-filling candidate.
    assert_eq!(result.tried, 4);
    assert!(!result.cancelled && !result.limit_reached);
    assert_eq!(result.hits.len(), 1);
    assert_eq!(result.hits[0].candidate, answer.as_bytes());
    assert_eq!(result.hits[0].index, 3);

    let absent = hex::encode(apply_op("sha256", b"no-such-candidate-in-list", None).unwrap());
    let miss = recover_sha256_wordlist_on_backend(
        RecoveryBackend::Cpu,
        &absent,
        read(&path),
        RecoveryLimits { max_candidates: 1000, max_matches: 1 },
        || false,
        |_| {},
    )
    .unwrap();
    assert!(miss.hits.is_empty());
    assert_eq!(miss.tried, words.len() as u64);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn suspended_checkpoint_reissues_and_resumes_the_wordlist_run() {
    let answer = "e2e-resume-answer-3307";
    let words = ["alpha", "bravo", answer, "delta", "echo"];
    let digest_hex = hex::encode(apply_op("sha256", answer.as_bytes(), None).unwrap());
    let target = RecoveryTarget::parse("sha256", &digest_hex).unwrap();

    let dir = tempdir("checkpoint");
    let store = cyberdeck_storage::ArtifactStore::open(&dir.join("index.db")).unwrap();
    let case = store.create_case("E2E Resume", "recovery checkpoint cycle").unwrap();

    // First work unit exhausts its budget before reaching the answer.
    let path = write_wordlist(&dir, &words);
    let read = || std::io::BufReader::new(std::fs::File::open(&path).unwrap());
    let first = recover_sha256_wordlist_on_backend(
        RecoveryBackend::Cpu,
        &digest_hex,
        read(),
        RecoveryLimits { max_candidates: 2, max_matches: 1 },
        || false,
        |_| {},
    )
    .unwrap();
    assert!(first.hits.is_empty() && first.limit_reached && first.tried == 2);

    let run = store
        .start_recovery_checkpoint(&cyberdeck_storage::NewRecoveryCheckpoint {
            case_id: case.id.clone(),
            run_kind: "wordlist_cpu".into(),
            resume_kind: "sequential".into(),
            algorithm: "sha256".into(),
            backend: "cpu".into(),
            target_hash: digest_hex.clone(),
            total_budget: words.len() as u64,
            max_matches: 1,
            stage_index: 0,
            stage_submitted: 0,
            wordlist_id: Some("e2e-list".into()),
            rules_set_id: None,
            preset: "plain".into(),
        })
        .unwrap();
    store
        .record_recovery_checkpoint(run, "running", first.tried, 0, 0)
        .unwrap();
    store
        .record_recovery_checkpoint(run, "suspended", first.tried, 0, 0)
        .unwrap();

    let resumable = store.list_resumable_recovery_checkpoints(&case.id).unwrap();
    assert_eq!(resumable.len(), 1);
    let row = &resumable[0];
    assert_eq!(row.id, run);
    assert_eq!(row.state, "suspended");
    assert_eq!(row.submitted, 2);
    assert_eq!(row.algorithm, "sha256");
    assert_eq!(row.target_hash, digest_hex);
    assert_eq!(row.total_budget, 5);

    let resumed = recover_wordlist_resumable(
        &target,
        read(),
        row.submitted,
        RecoveryLimits { max_candidates: words.len() as u64 - row.submitted, max_matches: 1 },
        || false,
        |_| {},
    )
    .unwrap();
    assert_eq!(resumed.hits.len(), 1);
    assert_eq!(resumed.hits[0].candidate, answer.as_bytes());
    assert_eq!(resumed.tried, 1);
    // Hit ordinals restart at the resume point; the global line ordinal is
    // skip + index.
    assert_eq!(row.submitted + resumed.hits[0].index, 2);

    store
        .record_recovery_checkpoint(run, "completed", row.submitted + resumed.tried, 0, 0)
        .unwrap();
    assert!(store.list_resumable_recovery_checkpoints(&case.id).unwrap().is_empty());
    drop(store);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn mongodb_scram_sha1_verifier_accepts_and_rejects() {
    // Upstream hashcat example vector: module_24100.c ST_HASH/ST_PASS,
    // docs/hashcat-example-hashes.md row 351.
    const ST_HASH: &str =
        "$mongodb-scram$*0*dXNlcg==*10000*4p+f1tKpK18hQqrVr0UGOw==*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw=";
    let parsed = mongodb::MongoDbScramSha1::parse(ST_HASH).unwrap();
    assert_eq!(parsed.user, b"user".to_vec());
    assert_eq!(parsed.iterations, 10000);
    assert!(parsed.verify("hashcat").unwrap());
    assert!(!parsed.verify("hashcau").unwrap());
    assert!(mongodb::MongoDbScramSha1::parse("$mongodb-scram$*1*dXNlcg==*10000*4p+f1tKpK18hQqrVr0UGOw==*Jv9lrpUQ2bVg2ZkXvRm2rppsqNw=").is_err());
}

#[test]
fn windows_auth_verifiers_accept_and_reject() {
    // john the Ripper mscash_common_plug.c / mscash2_common_plug.c vectors.
    assert!(windows_auth::verify_mscash("test1#64cd29e36a8431a2b111378564a10631", "test1").unwrap());
    assert!(!windows_auth::verify_mscash("test1#64cd29e36a8431a2b111378564a10631", "Test1").unwrap());
    assert!(
        windows_auth::verify_mscash2("$DCC2$10240#test1#607bbe89611e37446e736f7856515bf8", "test1")
            .unwrap()
    );
    assert!(
        !windows_auth::verify_mscash2("$DCC2$10240#test1#607bbe89611e37446e736f7856515bf8", "test2")
            .unwrap()
    );
}

#[test]
fn simd_batch_verifiers_match_the_scalar_reference() {
    let candidates: Vec<String> = (0..19)
        .map(|i| format!("simd-e2e-candidate-{i:02}"))
        .chain(std::iter::once("simd-needle-42".to_string()))
        .collect();
    let slices: Vec<&[u8]> = candidates.iter().map(String::as_bytes).collect();
    let needle_index = candidates.len() - 1;

    for (index, digest) in simd_digest::sha256_batch(&slices).iter().enumerate() {
        let reference: [u8; 32] = sha2::Sha256::digest(slices[index]).into();
        assert_eq!(*digest, reference, "sha256 lane {index} diverges from the scalar reference");
    }
    for (index, digest) in simd_digest::md5_batch(&slices).iter().enumerate() {
        let reference: [u8; 16] = md5::Md5::digest(slices[index]).into();
        assert_eq!(*digest, reference, "md5 lane {index} diverges from the scalar reference");
    }

    let sha_target: [u8; 32] = sha2::Sha256::digest(slices[needle_index]).into();
    assert_eq!(simd_digest::verify_sha256_batch(&slices, &sha_target), Some(needle_index));
    assert_eq!(simd_digest::sha256_batch_matches(&slices, &sha_target), vec![needle_index]);
    let absent_sha: [u8; 32] = sha2::Sha256::digest(b"not-a-candidate").into();
    assert_eq!(simd_digest::verify_sha256_batch(&slices, &absent_sha), None);
    assert!(simd_digest::sha256_batch_matches(&slices, &absent_sha).is_empty());
    assert_eq!(simd_digest::verify_sha256_batch(&[], &sha_target), None);

    let md5_target: [u8; 16] = md5::Md5::digest(slices[needle_index]).into();
    assert_eq!(simd_digest::verify_md5_batch(&slices, &md5_target), Some(needle_index));
    assert_eq!(simd_digest::md5_batch_matches(&slices, &md5_target), vec![needle_index]);
    let absent_md5: [u8; 16] = md5::Md5::digest(b"not-a-candidate").into();
    assert_eq!(simd_digest::verify_md5_batch(&slices, &absent_md5), None);
    assert!(simd_digest::md5_batch_matches(&slices, &absent_md5).is_empty());

    assert!(matches!(
        simd_digest::active_path(),
        "avx2-8-lane" | "sse4.1-4-lane" | "scalar"
    ));
}

/// Cross-crate round trip: the packet crate's wifi monitor pipeline turns a
/// synthetic authorized testbench 4-way handshake (synthetic testbench MACs,
/// crypto cross-checked against the Python stdlib) into a hashcat 22000
/// EAPOL line, and THIS crate's own verifier accepts the password and
/// rejects a case-mutation. PMKID line recomputes from the PMK derivation.
#[test]
fn wifi_monitor_capture_produces_a_verifying_wpa_eapol_22000_line() {
    use cyberdeck_packet::wifi::MonitorCapture;
    use hmac::{Hmac, Mac};
    use sha1::Sha1;
    const AP: [u8; 6] = [0xa4, 0xb1, 0xc1, 0xd2, 0xe3, 0xf0];
    const STA: [u8; 6] = [0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f];
    const ESSID: &str = "cyberdeck-e2e";
    const M1_HEX: &str = "0203007502008a0010000102030405060711223344556677881122334455667788112233445566778811223344556677880000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016dd14000fac048066ad9635ac9def6b250b58866e22b7";
    const M2_HEX: &str = "0203005f02010a00100001020304050607aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff00110000000000000000000000000000000000000000000000000000000000000000fda6fc92f7148868985fca1b39cc05ad0000";
    let hex = |h: &str| {
        (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
            .collect::<Vec<u8>>()
    };
    let frame = |mgmt_beacon: bool, to_ds: bool, body: &[u8]| {
        let mut f = vec![0u8, 0u8];
        let radio_len: u16 = if mgmt_beacon { 8 } else { 9 };
        f.extend_from_slice(&radio_len.to_le_bytes());
        let radio_fields: u32 = if mgmt_beacon { 0 } else { 2 };
        f.extend_from_slice(&radio_fields.to_le_bytes());
        if !mgmt_beacon {
            f.push(0x10); // radiotap FLAGS: FCS present at end
        }
        let data_bits: u16 = if mgmt_beacon { 8 << 4 } else { (2u16 << 2) | (8 << 4) };
        let dir_bits: u16 = if mgmt_beacon { 0 } else if to_ds { 0x0100 } else { 0x0200 };
        let fc: u16 = data_bits | dir_bits;
        f.extend_from_slice(&fc.to_le_bytes());
        f.extend_from_slice(&[0, 0]); // sequence control
        let (a1, a2, a3) = if mgmt_beacon {
            ([0xff; 6], AP, AP)
        } else if to_ds {
            (AP, STA, AP)
        } else {
            (STA, AP, AP)
        };
        for a in [a1, a2, a3] {
            f.extend_from_slice(&a);
        }
        f.extend_from_slice(&[0x10, 0x00]); // fixed: addr4 absent, seq already set
        if !mgmt_beacon {
            f.extend_from_slice(&[0, 0]); // QoS control
        }
        if mgmt_beacon {
            f.extend_from_slice(&[0u8; 8]); // timestamp
            f.extend_from_slice(&100u16.to_be_bytes()); // interval
            f.extend_from_slice(&0x0411u16.to_le_bytes()); // capability
            f.push(0x00);
            f.push(ESSID.len() as u8);
            f.extend_from_slice(ESSID.as_bytes());
        } else {
            f.extend_from_slice(&[0xaa, 0xaa, 0x03, 0, 0, 0, 0x88, 0x8e]); // LLC/SNAP EAPOL
        }
        f.extend_from_slice(body);
        if !mgmt_beacon {
            f.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]); // FCS placeholder
        }
        f
    };
    let mut capture = MonitorCapture::new();
    capture.process_frame(&frame(true, false, &[])).unwrap();
    capture.process_frame(&frame(false, false, &hex(M1_HEX))).unwrap();
    let lines = capture.process_frame(&frame(false, true, &hex(M2_HEX))).unwrap();
    let line = lines
        .iter()
        .find(|l| l.starts_with("WPA*02*"))
        .expect("EAPOL 22000 line")
        .clone();
    assert!(
        windows_auth::verify_wpa_eapol(&line, "cyberdeck-e2e-42").unwrap(),
        "our own verifier must accept the produced EAPOL line"
    );
    assert!(
        !windows_auth::verify_wpa_eapol(&line, "Cyberdeck-E2e-42").unwrap(),
        "a case-mutated password must not verify"
    );
    let pmkid_line = capture
        .hashcat_22000_lines()
        .iter()
        .find(|l| l.starts_with("WPA*01*"))
        .expect("PMKID 22000 line")
        .clone();
    let mut pmk = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha1::Sha1>(b"cyberdeck-e2e-42", ESSID.as_bytes(), 4096, &mut pmk);
    let pmkid = <Hmac<Sha1> as Mac>::new_from_slice(&pmk)
        .unwrap()
        .chain_update(b"PMK Name")
        .chain_update(AP)
        .chain_update(STA)
        .finalize()
        .into_bytes();
    assert_eq!(
        hex::encode(&pmkid[..16]),
        pmkid_line.split('*').nth(2).unwrap()
    );
}
