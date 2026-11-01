//! Native GPU host API regression tests; hardware checks are conditional.
use super::*;

#[test]
fn simulated_gpu_matches_are_sorted_and_deduplicated() {
    let results = stream_with_batch(
        &"00".repeat(32),
        [
            b"first".as_slice(),
            b"second".as_slice(),
            b"third".as_slice(),
        ],
        3,
        3,
        3,
        32,
        "mock-gpu",
        || false,
        |_, _| Ok(vec![2, 0, 2, 1]),
    )
    .unwrap();
    assert_eq!(results.tried, 3);
    assert_eq!(results.batches, 1);
    assert_eq!(
        results.hits.iter().map(|h| h.index).collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
}

#[test]
fn lazy_gpu_stream_counts_only_verified_batches() {
    let mut batches = 0;
    let run = stream_with(
        &"00".repeat(32),
        std::iter::repeat(b"bad".to_vec())
            .take(GPU_STREAM_BATCH)
            .chain(std::iter::once(b"hit".to_vec())),
        10_000,
        1,
        || false,
        |_, list| {
            batches += 1;
            Ok(list
                .iter()
                .enumerate()
                .filter_map(|(i, c)| if *c == b"hit" { Some(i) } else { None })
                .collect())
        },
    )
    .unwrap();
    assert_eq!(batches, 2);
    assert_eq!(run.tried, (GPU_STREAM_BATCH + 1) as u64);
    assert_eq!(run.hits[0].index, GPU_STREAM_BATCH as u64);
    assert_eq!(run.hits[0].candidate, b"hit");
}
#[test]
fn gpu_stream_limit_cancel_and_bad_return_indices() {
    let target = "00".repeat(32);
    let run = stream_with(
        &target,
        std::iter::repeat(b"x".to_vec()).take(9),
        3,
        1,
        || false,
        |_, _| Ok(vec![]),
    )
    .unwrap();
    assert_eq!(run.tried, 3);
    assert!(run.limit_reached);
    let mut polls = 0;
    let cancelled = stream_with(
        &target,
        [b"hello", b"world"],
        10,
        1,
        || {
            polls += 1;
            polls > 1
        },
        |_, _| Ok(vec![]),
    )
    .unwrap();
    assert!(cancelled.cancelled);
    assert_eq!(cancelled.tried, 0);
    assert!(stream_with(&target, [b"x"], 10, 1, || false, |_, _| Ok(vec![2])).is_err());
}

#[test]
fn streamed_gpu_ntlm_validates_before_opencl_access() {
    let result = recover_results_on_device_with_batch(
        GpuHash::Ntlm,
        0,
        1,
        &"00".repeat(16),
        vec![Ok::<Vec<u8>, String>("é".as_bytes().to_vec())],
        1,
        1,
        || false,
    );
    assert!(result.unwrap_err().contains("GPU NTLM supports only ASCII"));
}

#[test]
fn ntlm_gpu_rejects_bad_inputs_without_a_driver() {
    assert!(recover_ntlm("ab", &[b"a"]).is_err());
    assert!(recover_ntlm("zz", &[b"a"]).is_err());
    let target = "00".repeat(16);
    assert!(recover_ntlm(&target, &[&[b'a'; 28]]).is_err());
    assert!(recover_ntlm(&target, &[&[0xC3, 0xA9]]).is_err());
    assert!(recover_ntlm(&target, &vec![b"a".as_slice(); MAX_GPU_BATCH + 1]).is_err());
}

#[test]
fn ntlm_native_reference_vectors_are_stable() {
    use md4::Digest;
    fn ntlm(candidate: &[u8]) -> String {
        let mut utf16le = Vec::new();
        for byte in candidate {
            utf16le.extend_from_slice(&[*byte, 0]);
        }
        hex::encode(md4::Md4::digest(&utf16le))
    }
    assert_eq!(ntlm(b""), "31d6cfe0d16ae931b73c59d7e0c089c0");
    assert_eq!(ntlm(b"password"), "8846f7eaee8fb117ad06bdd830b7586c");
    assert_eq!(ntlm(b"Password123"), "58a478135a93ac3bf058a5ea0e8fdb71");
}

#[test]
fn md5_gpu_rejects_invalid_digest_and_candidate_size() {
    assert!(recover_md5("zz", &[b"x"]).is_err());
    assert!(recover_md5("ab", &[b"x"]).is_err());
    assert!(recover_md5(&"00".repeat(16), &[&[b'x'; 56]]).is_err());
    let too_many = vec![b"x".as_slice(); MAX_GPU_BATCH + 1];
    assert!(recover_md5(&"00".repeat(16), &too_many).is_err());
}
#[test]
fn md5_mock_stream_preserves_global_match_index() {
    use md5::Digest;
    let target = hex::encode(md5::Md5::digest(b"found"));
    let words = std::iter::repeat(b"bad".to_vec())
        .take(GPU_STREAM_BATCH)
        .chain(std::iter::once(b"found".to_vec()));
    let result = stream_with_checked(
        &target,
        words,
        10_000,
        1,
        16,
        "cyberdeck-crypto-opencl-md5",
        || false,
        |_, items| {
            Ok(items
                .iter()
                .enumerate()
                .filter_map(|(i, c)| if *c == b"found" { Some(i) } else { None })
                .collect())
        },
    )
    .unwrap();
    assert_eq!(result.tried, (GPU_STREAM_BATCH + 1) as u64);
    assert_eq!(result.hits[0].index, GPU_STREAM_BATCH as u64);
    assert_eq!(result.engine, "cyberdeck-crypto-opencl-md5");
}
#[test]
fn md5_hardware_reference_vectors_if_available() {
    #[cfg(feature = "gpu")]
    if probe().available {
        use md5::{Digest, Md5};
        let inputs = vec![
            vec![],
            b"a".to_vec(),
            b"abc".to_vec(),
            vec![0xff, 0x00],
            vec![b'x'; 54],
            vec![b'x'; 55],
        ];
        let refs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
        for (index, input) in inputs.iter().enumerate() {
            let target = hex::encode(Md5::digest(input));
            assert_eq!(recover_md5(&target, &refs).unwrap(), vec![index]);
        }
        let mut words = vec![b"not-match".to_vec(); GPU_STREAM_BATCH + 2];
        words[GPU_STREAM_BATCH] = b"hello".to_vec();
        let target = hex::encode(Md5::digest(b"hello"));
        let result = recover_md5_stream(&target, words, 10_000, 1, || false).unwrap();
        assert_eq!(result.hits[0].index, GPU_STREAM_BATCH as u64);
        assert_eq!(result.batches, 2);
    }
}

#[test]
fn sha1_gpu_rejects_invalid_digest_and_candidate_size() {
    assert!(recover_sha1("zz", &[b"x"]).is_err());
    assert!(recover_sha1("ab", &[b"x"]).is_err());
    assert!(recover_sha1(&"00".repeat(20), &[&[b'x'; 56]]).is_err());
    let too_many = vec![b"x".as_slice(); MAX_GPU_BATCH + 1];
    assert!(recover_sha1(&"00".repeat(20), &too_many).is_err());
}
#[test]
fn sha1_mock_stream_preserves_global_match_index() {
    use sha1::Digest;
    let target = hex::encode(sha1::Sha1::digest(b"found"));
    let words = std::iter::repeat(b"bad".to_vec())
        .take(GPU_STREAM_BATCH)
        .chain(std::iter::once(b"found".to_vec()));
    let result = stream_with_checked(
        &target,
        words,
        10_000,
        1,
        20,
        "cyberdeck-crypto-opencl-sha1",
        || false,
        |_, items| {
            Ok(items
                .iter()
                .enumerate()
                .filter_map(|(i, c)| if *c == b"found" { Some(i) } else { None })
                .collect())
        },
    )
    .unwrap();
    assert_eq!(result.tried, (GPU_STREAM_BATCH + 1) as u64);
    assert_eq!(result.hits[0].index, GPU_STREAM_BATCH as u64);
    assert_eq!(result.engine, "cyberdeck-crypto-opencl-sha1");
}
#[test]
fn sha1_hardware_reference_vectors_if_available() {
    #[cfg(feature = "gpu")]
    if probe().available {
        use sha1::{Digest, Sha1};
        let inputs = vec![
            vec![],
            b"a".to_vec(),
            b"abc".to_vec(),
            vec![0xff, 0x00],
            vec![b'x'; 54],
            vec![b'x'; 55],
        ];
        let refs: Vec<&[u8]> = inputs.iter().map(Vec::as_slice).collect();
        for (index, input) in inputs.iter().enumerate() {
            let target = hex::encode(Sha1::digest(input));
            assert_eq!(recover_sha1(&target, &refs).unwrap(), vec![index]);
        }
        let mut words = vec![b"not-match".to_vec(); GPU_STREAM_BATCH + 2];
        words[GPU_STREAM_BATCH] = b"hello".to_vec();
        let target = hex::encode(Sha1::digest(b"hello"));
        let result = recover_sha1_stream(&target, words, 10_000, 1, || false).unwrap();
        assert_eq!(result.hits[0].index, GPU_STREAM_BATCH as u64);
        assert_eq!(result.batches, 2);
    }
}

#[test]
fn gpu_fallible_candidate_stream_propagates_errors_and_respects_limit() {
    let hash = "00".repeat(32);
    let input: Vec<Result<Vec<u8>, String>> = vec![
        Ok(b"a".to_vec()),
        Ok(b"b".to_vec()),
        Err("disk read failed".into()),
    ];
    assert!(stream_with_batch_results(
        &hash,
        input.clone(),
        3,
        1,
        2,
        32,
        "test",
        || false,
        |_, _| Ok(vec![]),
    )
    .unwrap_err()
    .contains("disk read failed"));
    let mut sent = Vec::new();
    let result = stream_with_batch_results(
        &hash,
        input,
        2,
        1,
        2,
        32,
        "test",
        || false,
        |_, batch| {
            sent.push(batch.len());
            Ok(vec![])
        },
    )
    .unwrap();
    assert_eq!(result.tried, 2);
    assert!(result.limit_reached);
    assert_eq!(sent, vec![2]);
}

#[test]
fn gpu_rule_wordlist_errors_are_explicit_before_device_access() {
    use crate::recovery::CompiledRule;
    let rule = CompiledRule::parse("c$1").unwrap();
    let result = recover_rule_wordlist_on_device_with_batch(
        GpuHash::Sha256,
        0,
        128,
        "invalid",
        std::io::Cursor::new(b"test\n".as_slice()),
        vec![rule],
        10,
        1,
        || false,
    );
    assert!(result.is_err());
    let result = recover_rule_wordlist_on_device_with_batch(
        GpuHash::Sha256,
        0,
        0,
        &"00".repeat(32),
        std::io::Cursor::new(b"test\n".as_slice()),
        vec![CompiledRule::parse(":").unwrap()],
        10,
        1,
        || false,
    );
    assert!(result.is_err());
}

#[test]
fn gpu_wordlist_api_rejects_invalid_hash_without_driver_access() {
    let result = recover_wordlist_on_device_with_batch(
        GpuHash::Sha256,
        0,
        4,
        "invalid",
        std::io::Cursor::new(b"candidate\n".as_slice()),
        10,
        1,
        || false,
    );
    assert!(result.is_err());
}

#[test]
fn configurable_gpu_batch_size_accounts_for_partial_final_batch() {
    let hash = "00".repeat(32);
    let mut sizes = Vec::new();
    let result = stream_with_batch(
        &hash,
        std::iter::repeat_n(b"test".to_vec(), 1_025),
        2_000,
        1,
        128,
        32,
        "cyberdeck-crypto-opencl-sha256",
        || false,
        |_, batch| {
            sizes.push(batch.len());
            Ok(Vec::new())
        },
    )
    .unwrap();
    assert_eq!(result.tried, 1_025);
    assert_eq!(result.batches, 9);
    assert_eq!(sizes, [128, 128, 128, 128, 128, 128, 128, 128, 1]);
    for invalid_size in [0, MAX_GPU_BATCH + 1] {
        assert!(stream_with_batch(
            &hash,
            [b"x"],
            1,
            1,
            invalid_size,
            32,
            "cyberdeck-crypto-opencl-sha256",
            || false,
            |_, _| Ok(vec![]),
        )
        .is_err());
    }
}

#[test]
fn selected_gpu_stream_validates_target_before_device_access() {
    assert!(
        recover_stream_on_device(GpuHash::Sha256, 0, "zz", [b"test"], 5, 1, || false,).is_err()
    );
    assert!(
        recover_stream_on_device(GpuHash::Md5, 0, &"00".repeat(32), [b"test"], 5, 1, || false,)
            .is_err()
    );
    assert!(
        recover_stream_on_device(GpuHash::Sha1, 0, &"00".repeat(20), [b"test"], 0, 1, || {
            false
        },)
        .is_err()
    );
}

#[test]
fn explicit_device_index_parity_if_hardware_is_accessible() {
    #[cfg(feature = "gpu")]
    {
        use md4::{Digest as _, Md4};
        use md5::Md5;
        use sha1::Sha1;
        use sha2::{Digest, Sha256};

        let devices = probe().devices;
        for device_index in 0..devices.len() {
            for algorithm in [GpuHash::Sha256, GpuHash::Md5, GpuHash::Sha1, GpuHash::Ntlm] {
                let hash = |candidate: &[u8]| -> String {
                    let digest = match algorithm {
                        GpuHash::Sha256 => Sha256::digest(candidate).to_vec(),
                        GpuHash::Md5 => Md5::digest(candidate).to_vec(),
                        GpuHash::Sha1 => Sha1::digest(candidate).to_vec(),
                        GpuHash::Ntlm => {
                            let mut utf16le = Vec::new();
                            for byte in candidate {
                                utf16le.extend_from_slice(&[*byte, 0]);
                            }
                            Md4::digest(&utf16le).to_vec()
                        }
                    };
                    hex::encode(digest)
                };
                // Cover empty and maximum-size candidates on every GPU,
                // not only the first device returned by OpenCL.
                for candidate in [
                    Vec::new(),
                    vec![b'x'; if algorithm == GpuHash::Ntlm { 27 } else { 55 }],
                ] {
                    let result = recover_stream_on_device_with_batch(
                        algorithm,
                        device_index,
                        64,
                        &hash(&candidate),
                        vec![b"not-a-hit".to_vec(), candidate.clone()],
                        10,
                        1,
                        || false,
                    )
                    .expect("explicit GPU device failed reference vector");
                    assert_eq!(result.tried, 2, "device {device_index} {algorithm:?}");
                    assert_eq!(result.hits.len(), 1, "device {device_index} {algorithm:?}");
                    assert_eq!(result.hits[0].index, 1);
                    assert_eq!(result.hits[0].candidate, candidate);
                }
                // Partial last batch and global index across multiple
                // dispatches must work for every GPU vendor/algorithm.
                let last = vec![b'x'; if algorithm == GpuHash::Ntlm { 27 } else { 55 }];
                let batch = std::iter::repeat_n(b"not-a-hit".to_vec(), 257)
                    .chain(std::iter::once(last.clone()));
                let result = recover_stream_on_device_with_batch(
                    algorithm,
                    device_index,
                    128,
                    &hash(&last),
                    batch,
                    258,
                    1,
                    || false,
                )
                .expect("explicit GPU device failed cross-batch validation");
                assert_eq!(result.tried, 258);
                assert_eq!(result.batches, 3);
                assert_eq!(result.hits.len(), 1);
                assert_eq!(result.hits[0].index, 257);
                assert_eq!(result.hits[0].candidate, last);
            }
        }
        if !devices.is_empty() {
            let result = recover_stream_on_device(
                GpuHash::Sha256,
                devices.len(),
                &"00".repeat(32),
                [b"x"],
                1,
                1,
                || false,
            );
            assert!(result.is_err(), "out-of-range GPU index must fail");
        }
    }
}

#[test]
fn unsupported_gpu_inputs_are_rejected_before_driver_access() {
    assert!(recover_sha256("xx", &[b"abc"]).is_err());
    assert!(recover_sha256("ab", &[b"abc"]).is_err());
    assert!(recover_sha256(&"00".repeat(32), &[&[1u8; 56]]).is_err());
    let too_many = vec![b"x".as_slice(); MAX_GPU_BATCH + 1];
    assert!(recover_sha256(&"00".repeat(32), &too_many).is_err());
}
#[test]
fn gpu_reference_vectors_if_hardware_is_accessible() {
    #[cfg(feature = "gpu")]
    if probe().available {
        use sha2::{Digest, Sha256};
        let candidates = vec![
            vec![],
            b"a".to_vec(),
            b"hello".to_vec(),
            vec![b'x'; 54],
            vec![b'x'; 55],
        ];
        let refs: Vec<&[u8]> = candidates.iter().map(Vec::as_slice).collect();
        for (index, candidate) in candidates.iter().enumerate() {
            let digest = hex::encode(Sha256::digest(candidate));
            assert_eq!(recover_sha256(&digest, &refs).unwrap(), vec![index]);
        }

        let mut words = vec![b"incorrect".to_vec(); GPU_STREAM_BATCH + 3];
        words[GPU_STREAM_BATCH + 1] = b"known-target".to_vec();
        let digest = hex::encode(Sha256::digest(b"known-target"));
        let run = recover_sha256_stream(&digest, words, 10_000, 1, || false).unwrap();
        assert_eq!(run.batches, 2);
        assert_eq!(run.tried, (GPU_STREAM_BATCH + 3) as u64);
        assert_eq!(run.hits[0].index, (GPU_STREAM_BATCH + 1) as u64);
        assert_eq!(run.hits[0].candidate, b"known-target");
    }
}
#[test]
fn no_gpu_feature_never_claims_availability() {
    #[cfg(not(feature = "gpu"))]
    {
        let status = probe();
        assert!(!status.available);
        assert!(recover_sha256(&"00".repeat(32), &[b"x"]).is_err());
    }
}

#[test]
fn gpu_batch_progress_reports_only_verified_candidates() {
    let mut snapshots = Vec::new();
    let outcome = streaming::stream_with_batch_results_progress(
        &"00".repeat(32),
        [
            Ok::<Vec<u8>, String>(b"bad1".to_vec()),
            Ok(b"bad2".to_vec()),
            Ok(b"secret".to_vec()),
        ],
        3,
        1,
        2,
        32,
        "mock-gpu",
        || false,
        |_, batch| {
            Ok(batch
                .iter()
                .enumerate()
                .filter_map(|(i, c)| (*c == b"secret").then_some(i))
                .collect())
        },
        |snapshot| snapshots.push(snapshot),
    )
    .unwrap();
    assert_eq!(outcome.tried, 3);
    assert_eq!(outcome.hits.len(), 1);
    assert_eq!(outcome.hits[0].index, 2);
    assert_eq!(
        snapshots
            .iter()
            .map(|p| (p.tried, p.batches, p.matches))
            .collect::<Vec<_>>(),
        vec![(2, 1, 0), (3, 2, 1)]
    );
    assert!(!serde_json::to_string(&snapshots)
        .unwrap()
        .contains("secret"));
}
