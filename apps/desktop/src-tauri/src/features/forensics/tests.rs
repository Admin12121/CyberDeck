use super::*;
use cyberdeck_storage::{ArtifactStore, ImportEvent, NewFinding, DEFAULT_CASE};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

fn test_ctx(dir: &Path) -> EvidenceCtx {
    EvidenceCtx {
        store: Mutex::new(ArtifactStore::open(&dir.join("index.db")).unwrap()),
        artifacts_dir: dir.to_path_buf(),
    }
}

#[test]
fn verified_paged_hex_and_utf16_offsets_preserve_case_scope() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = test_ctx(dir.path());
    let mut bytes = vec![0u8; 4096];
    let utf16 = "Forensic 世界"
        .encode_utf16()
        .flat_map(|v| v.to_le_bytes())
        .collect::<Vec<_>>();
    bytes[101..101 + utf16.len()].copy_from_slice(&utf16);
    let artifact = import_bytes(&ctx, Path::new("sample.bin"), &bytes, DEFAULT_CASE, true).unwrap();
    let response = hex_view(&ctx, DEFAULT_CASE, &artifact.id, 96, 32).unwrap();
    assert_eq!(response.offset, 96);
    assert_eq!(response.total_size, 4096);
    assert_eq!(response.rows[0].offset, 96);
    assert!(!response.complete);
    let scanned = strings_scan(&ctx, DEFAULT_CASE, &artifact.id, 96, 512, 4, 100).unwrap();
    assert!(scanned.integrity_checked);
    assert!(scanned.coverage_truncated);
    assert_eq!(scanned.analyzed_offset, 96);
    assert!(scanned
        .hits
        .iter()
        .any(|h| h.encoding == "utf16le" && h.text.contains("Forensic 世界") && h.offset <= 101));
    let regions = entropy_scan(&ctx, DEFAULT_CASE, &artifact.id, 0, 1024, 256).unwrap();
    assert_eq!(regions.regions.len(), 4);
    assert_eq!(regions.regions[0].offset, 0);
    assert!(hex_view(&ctx, "other-case", &artifact.id, 0, 16).is_err());
    assert!(strings_scan(&ctx, "other-case", &artifact.id, 0, 512, 4, 10).is_err());
}

#[test]
fn large_signature_scan_verifies_full_sha256_not_only_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = test_ctx(dir.path());
    let mut bytes = vec![0u8; 16 * 1024 * 1024 + 17];
    bytes[..8].copy_from_slice(b"%PDF-1.7");
    let artifact = import_bytes(&ctx, Path::new("large.bin"), &bytes, DEFAULT_CASE, true).unwrap();
    let result = signature_scan(&ctx, DEFAULT_CASE, &artifact.id).unwrap();
    assert!(result.truncated);
    assert!(result.integrity_checked);
    assert!(result.hits.iter().any(|h| h.format == "pdf"));
    bytes[16 * 1024 * 1024 + 16] = 5;
    std::fs::write(&artifact.stored_path, &bytes).unwrap();
    assert!(signature_scan(&ctx, DEFAULT_CASE, &artifact.id).is_err());
    assert!(hex_view(&ctx, DEFAULT_CASE, &artifact.id, 0, 16).is_err());
}

#[test]
fn archive_batch_indexes_distinct_and_deduplicated_files_atomically() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = test_ctx(dir.path());
    let planned = vec![
        PlannedArchiveEntry {
            name: "one.bin".into(),
            bytes: b"same".to_vec(),
            provenance: "Parent: source-A > one.bin".into(),
            title: "Member one".into(),
        },
        PlannedArchiveEntry {
            name: "two.bin".into(),
            bytes: b"other".to_vec(),
            provenance: "Parent: source-A > two.bin".into(),
            title: "Member two".into(),
        },
        PlannedArchiveEntry {
            name: "duplicate.bin".into(),
            bytes: b"same".to_vec(),
            provenance: "Parent: source-A > duplicate.bin".into(),
            title: "Duplicate".into(),
        },
    ];
    let records = import_archive_batch(&ctx, DEFAULT_CASE, "forensics.archive", planned).unwrap();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].id, records[2].id);
    let store = ctx.store.lock().unwrap();
    assert_eq!(store.list_artifacts(DEFAULT_CASE).unwrap().len(), 2);
    assert_eq!(store.list_events(DEFAULT_CASE).unwrap().len(), 6);
    assert_eq!(store.list_findings(DEFAULT_CASE).unwrap().len(), 3);
}

#[test]
fn oversized_atomic_archive_batch_rejects_before_file_publication() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = test_ctx(dir.path());
    let planned = (0..33)
        .map(|i| PlannedArchiveEntry {
            name: format!("member-{i}.bin"),
            bytes: format!("distinct contents {i}").into_bytes(),
            provenance: format!("source member #{i}"),
            title: format!("Member {i}"),
        })
        .collect();
    assert!(
        import_archive_batch(&ctx, DEFAULT_CASE, "forensics.archive", planned)
            .unwrap_err()
            .contains("32 distinct")
    );
    let store = ctx.store.lock().unwrap();
    assert!(store.list_artifacts(DEFAULT_CASE).unwrap().is_empty());
    assert!(store.list_events(DEFAULT_CASE).unwrap().is_empty());
    assert!(!dir.path().join(DEFAULT_CASE).exists());
}

#[test]
fn nested_extraction_preserves_source_chain_and_rejects_tampering() {
    use flate2::{write::GzEncoder, Compression};
    let dir = tempfile::tempdir().unwrap();
    let ctx = test_ctx(dir.path());
    let case = ctx
        .store
        .lock()
        .unwrap()
        .create_case("Nested evidence", "")
        .unwrap();
    let mut header = [0u8; 512];
    header[..8].copy_from_slice(b"note.txt");
    header[124..136].copy_from_slice(b"00000000005\0");
    header[156] = b'0';
    header[257..263].copy_from_slice(b"ustar\0");
    header[148..156].fill(b' ');
    let checksum = header.iter().map(|&b| b as usize).sum::<usize>();
    header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    let mut tar = header.to_vec();
    tar.extend_from_slice(b"hello");
    tar.resize(512 + 512 + 1024, 0);
    let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
    gzip.write_all(&tar).unwrap();
    let compressed = gzip.finish().unwrap();
    let source = import_bytes(&ctx, Path::new("outer.gz"), &compressed, &case.id, true).unwrap();
    assert!(extract_nested_from_evidence(&ctx, DEFAULT_CASE, &source.id, "gzip", 0, 2).is_err());
    let imported = extract_nested_from_evidence(&ctx, &case.id, &source.id, "gzip", 0, 2).unwrap();
    assert_eq!(imported.len(), 1);
    assert_eq!(std::fs::read(&imported[0].stored_path).unwrap(), b"hello");
    let events = ctx.store.lock().unwrap().list_events(&case.id).unwrap();
    assert!(events.iter().any(|e| e.source == "forensics.nested"
        && e.action == "extract"
        && e.source_description.contains(&source.id)
        && e.source_description.contains("note.txt")));
    std::fs::write(&source.stored_path, b"modified").unwrap();
    assert!(extract_nested_from_evidence(&ctx, &case.id, &source.id, "gzip", 0, 2).is_err());
}

#[test]
fn repeat_evidence_import_keeps_identity_path_and_checks_original_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = test_ctx(dir.path());
    let first = import_bytes(
        &ctx,
        Path::new("initial.bin"),
        b"immutable sample",
        DEFAULT_CASE,
        true,
    )
    .unwrap();
    let next = import_bytes(
        &ctx,
        Path::new("renamed-copy.bin"),
        b"immutable sample",
        DEFAULT_CASE,
        true,
    )
    .unwrap();
    assert_eq!(first.id, next.id);
    assert_eq!(first.stored_path, next.stored_path);
    assert_eq!(first.name, next.name);
    assert_eq!(
        ctx.store
            .lock()
            .unwrap()
            .list_artifacts(DEFAULT_CASE)
            .unwrap()
            .len(),
        1
    );
    let copy_path = std::path::PathBuf::from(&first.stored_path);
    assert_eq!(std::fs::read(&copy_path).unwrap(), b"immutable sample");
    std::fs::write(&copy_path, b"modified evidence").unwrap();
    assert!(import_bytes(
        &ctx,
        Path::new("renamed-copy.bin"),
        b"immutable sample",
        DEFAULT_CASE,
        true
    )
    .is_err());
    assert_eq!(std::fs::read(&copy_path).unwrap(), b"modified evidence");
}

#[test]
fn invalid_second_import_event_does_not_index_artifact_or_findings() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = test_ctx(dir.path());
    let invalid_description = "X".repeat(513);
    let events = [
        ImportEvent {
            source: "forensics.archive",
            action: "derived",
            description: "entry.bin",
        },
        ImportEvent {
            source: "forensics.archive",
            action: "extract",
            description: &invalid_description,
        },
    ];
    let findings = [NewFinding {
        title: "Archive finding".into(),
        severity: "info".into(),
        details: "should roll back".into(),
    }];
    assert!(import_bytes_with_events(
        &ctx,
        Path::new("entry.bin"),
        b"artifact",
        DEFAULT_CASE,
        false,
        &events,
        &findings,
    )
    .is_err());
    let store = ctx.store.lock().unwrap();
    assert!(store.list_artifacts(DEFAULT_CASE).unwrap().is_empty());
    assert!(store.list_events(DEFAULT_CASE).unwrap().is_empty());
    assert!(store.list_findings(DEFAULT_CASE).unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn symlinked_case_directory_cannot_redirect_evidence_publication() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let ctx = test_ctx(dir.path());
    std::os::unix::fs::symlink(outside.path(), dir.path().join(DEFAULT_CASE)).unwrap();
    assert!(import_bytes(
        &ctx,
        Path::new("sample.bin"),
        b"blocked",
        DEFAULT_CASE,
        true
    )
    .unwrap_err()
    .contains("symlink"));
    assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none());
}

#[test]
fn preexisting_symlink_is_not_accepted_as_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = test_ctx(dir.path());
    let bytes = b"symlink fixture";
    let digest = digest_of("sha256", bytes).unwrap();
    let case_dir = dir.path().join(DEFAULT_CASE);
    std::fs::create_dir_all(&case_dir).unwrap();
    let target = dir.path().join("outside.bin");
    std::fs::write(&target, bytes).unwrap();
    let stored_path = case_dir.join(format!("{digest}.evidence"));
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&target, &stored_path).unwrap();
        assert!(import_bytes(&ctx, Path::new("sample.bin"), bytes, DEFAULT_CASE, true).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), bytes);
    }
    #[cfg(not(unix))]
    {
        assert!(!stored_path.exists());
    }
}

#[test]
fn binary_inspection_requires_case_membership_and_intact_evidence() {
    let temp = tempfile::tempdir().unwrap();
    let ctx = test_ctx(temp.path());
    let mut elf = vec![0u8; 64];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4..7].copy_from_slice(&[2, 1, 1]);
    elf[18..20].copy_from_slice(&183u16.to_le_bytes());
    let record = import_bytes(&ctx, Path::new("sample.elf"), &elf, DEFAULT_CASE, true).unwrap();
    assert_eq!(
        binary_inspect(&ctx, DEFAULT_CASE, &record.id)
            .unwrap()
            .architecture,
        "ARM64"
    );
    let another = ctx
        .store
        .lock()
        .unwrap()
        .create_case("Other case", "")
        .unwrap();
    assert!(binary_inspect(&ctx, &another.id, &record.id).is_err());
    std::fs::write(&record.stored_path, b"modified").unwrap();
    assert!(binary_inspect(&ctx, DEFAULT_CASE, &record.id)
        .unwrap_err()
        .contains("integrity"));
}

#[test]
fn derived_artifact_is_isolated_to_selected_case() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = test_ctx(dir.path());
    let new_case = ctx
        .store
        .lock()
        .unwrap()
        .create_case("Analysis Lab", "")
        .unwrap();
    let source = Path::new("recipe-output.bin");
    let derived = import_bytes(&ctx, source, b"hello", &new_case.id, false).unwrap();
    assert_eq!(derived.case_id, new_case.id);
    assert!(derived.original_path.is_none());
    assert!(derived.stored_path.contains(&new_case.id));
    let scratch = import_bytes(&ctx, source, b"hello", DEFAULT_CASE, true).unwrap();
    let generated_in_scratch = import_bytes(&ctx, source, b"hello", DEFAULT_CASE, false).unwrap();
    assert_ne!(scratch.id, generated_in_scratch.id);
    assert_eq!(scratch.original_path.as_deref(), Some("recipe-output.bin"));
    assert!(generated_in_scratch.original_path.is_none());
    assert_ne!(derived.id, scratch.id);
    assert_eq!(
        ctx.store
            .lock()
            .unwrap()
            .list_artifacts(&new_case.id)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        ctx.store
            .lock()
            .unwrap()
            .list_artifacts(DEFAULT_CASE)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn embedded_gzip_is_bounded_and_linked_to_case() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let ctx = test_ctx(dir.path());
    let case = ctx
        .store
        .lock()
        .unwrap()
        .create_case("Gzip lab", "")
        .unwrap();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(b"decompressed sample").unwrap();
    let gz = encoder.finish().unwrap();
    let mut fixture = b"prefix".to_vec();
    fixture.extend(gz);
    let src = import_bytes(&ctx, Path::new("firmware.bin"), &fixture, &case.id, true).unwrap();
    assert!(extract_gzip_from_evidence(&ctx, DEFAULT_CASE, &src.id, 6).is_err());
    assert!(extract_gzip_from_evidence(&ctx, &case.id, &src.id, 0).is_err());
    let out = extract_gzip_from_evidence(&ctx, &case.id, &src.id, 6).unwrap();
    assert_eq!(
        std::fs::read(&out.stored_path).unwrap(),
        b"decompressed sample"
    );
    assert!(ctx
        .store
        .lock()
        .unwrap()
        .list_events(&case.id)
        .unwrap()
        .iter()
        .any(|event| event.source_description.contains(&src.id)));
}

#[test]
fn signature_scan_is_case_scoped_and_checks_integrity() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = test_ctx(dir.path());
    let case = ctx
        .store
        .lock()
        .unwrap()
        .create_case("Analysis", "")
        .unwrap();
    let path = Path::new("firmware.bin");
    let mut data = b"prefix".to_vec();
    data.extend_from_slice(b"%PDF-1.7\n");
    let record = import_bytes(&ctx, path, &data, &case.id, false).unwrap();
    assert!(signature_scan(&ctx, DEFAULT_CASE, &record.id).is_err());
    let result = signature_scan(&ctx, &case.id, &record.id).unwrap();
    assert!(result.integrity_checked);
    assert!(result
        .hits
        .iter()
        .any(|h| h.format == "pdf" && h.offset == 6));
    std::fs::write(&record.stored_path, b"mismatch").unwrap();
    assert!(signature_scan(&ctx, &case.id, &record.id)
        .unwrap_err()
        .contains("integrity"));
}

#[test]
fn hex_and_strings_enforce_case_isolation() {
    let temp = tempfile::tempdir().unwrap();
    let ctx = test_ctx(temp.path());
    let private_case = ctx
        .store
        .lock()
        .unwrap()
        .create_case("Private", "")
        .unwrap();
    let record = import_bytes(
        &ctx,
        Path::new("secret.txt"),
        b"private-data",
        &private_case.id,
        true,
    )
    .unwrap();
    assert!(hex_view(&ctx, DEFAULT_CASE, &record.id, 0, 8).is_err());
    assert!(strings(&ctx, DEFAULT_CASE, &record.id, 3, 20).is_err());
    assert!(!hex_view(&ctx, &private_case.id, &record.id, 0, 16)
        .unwrap()
        .rows
        .is_empty());
}

#[test]
fn import_computes_digests_and_signature() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = test_ctx(dir.path());
    let src = dir.path().join("sample.zip");
    std::fs::write(&src, b"PK\x03\x04 fake zip body").unwrap();
    let bytes = std::fs::read(&src).unwrap();
    let record = import_bytes(&ctx, &src, &bytes, DEFAULT_CASE, true).unwrap();
    assert_eq!(record.signature.as_deref(), Some("ZIP archive"));
    assert_eq!(record.sha256.len(), 64);
    assert_eq!(record.md5.len(), 32);
    assert!(record.entropy > 0.0);
    assert!(record.stored_path.contains(&record.sha256));
    // content-addressed: re-import replaces, not duplicates
    let again = import_bytes(&ctx, &src, &bytes, DEFAULT_CASE, true).unwrap();
    assert_eq!(again.id, record.id);
    assert_eq!(
        ctx.store
            .lock()
            .unwrap()
            .list_artifacts(DEFAULT_CASE)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn hex_view_matches_known_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = test_ctx(dir.path());
    let src = dir.path().join("abc.txt");
    std::fs::write(&src, b"abc").unwrap();
    let bytes = std::fs::read(&src).unwrap();
    let record = import_bytes(&ctx, &src, &bytes, DEFAULT_CASE, true).unwrap();
    let view = hex_view(&ctx, DEFAULT_CASE, &record.id, 0, 16).unwrap();
    assert_eq!(view.rows[0].hex, "61 62 63");
    assert_eq!(view.rows[0].ascii, "abc");
    assert!(view.complete);
}

#[test]
fn strings_extracts_printable_runs() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = test_ctx(dir.path());
    let src = dir.path().join("bin.dat");
    std::fs::write(&src, b"\x00\x01\x02user=admin\x03\x04path=/bin\x00").unwrap();
    let bytes = std::fs::read(&src).unwrap();
    let record = import_bytes(&ctx, &src, &bytes, DEFAULT_CASE, true).unwrap();
    let hits = strings(&ctx, DEFAULT_CASE, &record.id, 4, 100).unwrap();
    let texts: Vec<_> = hits.into_iter().map(|h| h.text).collect();
    assert!(texts.contains(&"user=admin".to_string()));
    assert!(texts.contains(&"path=/bin".to_string()));
}

#[test]
fn streamed_dialog_digest_matches_import_record() {
    let dir = tempfile::tempdir().unwrap();
    let ctx = test_ctx(dir.path());
    let source = dir.path().join("picked.bin");
    let input = (0..150_003).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    std::fs::write(&source, &input).unwrap();
    let hashes = digest_disk_file(&source).unwrap();
    assert_eq!(hashes.name, "picked.bin");
    assert_eq!(hashes.size, input.len() as u64);
    let imported = import_file_from_path(&ctx, &source, DEFAULT_CASE).unwrap();
    assert_eq!(imported.sha256, hashes.sha256);
    assert_eq!(imported.sha1, hashes.sha1);
    assert_eq!(imported.md5, hashes.md5);
    assert_eq!(imported.crc32, hashes.crc32);
    assert_eq!(std::fs::read(&imported.stored_path).unwrap(), input);
}
