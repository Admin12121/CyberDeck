//! Case-scoped analysis application services. No Tauri bindings.
//! All byte acquisition uses the verified, bounded infrastructure window.
use super::{
    scoped_case_artifact, verified_record_window, EvidenceCtx, FileCarveResponse,
    ForensicEntropyResponse, ForensicMetadataResponse, ForensicStringsResponse,
    ForensicYaraSubsetHit, ForensicYaraSubsetResponse, HexResponse, HexRow, SignatureScanResponse,
    StringHit, MAX_HEX_REQUEST, MAX_STRINGS_HITS, MAX_STRINGS_SCAN,
};

pub(super) fn binary_inspect(
    ctx: &EvidenceCtx,
    case_id: &str,
    id: &str,
) -> Result<cyberdeck_crypto::formats::binary::BinaryInfo, String> {
    use cyberdeck_crypto::formats::binary::{inspect_binary, MAX_BINARY_BYTES};
    let record = scoped_case_artifact(ctx, case_id, id, "artifact not found in selected case")?;
    if record.size > MAX_BINARY_BYTES as u64 {
        return Err("binary inspection currently limited to 16 MiB evidence".into());
    }
    let (_, bytes) =
        verified_record_window(ctx, case_id, id, 0, MAX_BINARY_BYTES, MAX_BINARY_BYTES)?;
    inspect_binary(&bytes)
}

pub(super) fn signature_scan(
    ctx: &EvidenceCtx,
    case_id: &str,
    id: &str,
) -> Result<SignatureScanResponse, String> {
    use cyberdeck_crypto::formats::{scan_signatures, MAX_SIGNATURE_SCAN_BYTES};
    let (record, bytes) = verified_record_window(
        ctx,
        case_id,
        id,
        0,
        MAX_SIGNATURE_SCAN_BYTES,
        MAX_SIGNATURE_SCAN_BYTES,
    )?;
    let hits = scan_signatures(&bytes, 256);
    let hit_cap_reached = hits.len() == 256;
    Ok(SignatureScanResponse {
        hits,
        scanned_bytes: bytes.len(),
        file_bytes: record.size,
        truncated: record.size > bytes.len() as u64,
        integrity_checked: true,
        hit_cap_reached,
    })
}

pub(super) fn hex_view(
    ctx: &EvidenceCtx,
    case_id: &str,
    id: &str,
    offset: i64,
    len: i64,
) -> Result<HexResponse, String> {
    let wanted = len.clamp(1, MAX_HEX_REQUEST) as usize;
    let requested_offset = offset.max(0) as u64;
    let (record, bytes) = verified_record_window(
        ctx,
        case_id,
        id,
        requested_offset,
        wanted,
        MAX_HEX_REQUEST as usize,
    )?;
    let start = requested_offset.min(record.size) as usize;
    let end = (start as u64) + bytes.len() as u64;
    let mut rows = Vec::with_capacity(bytes.len().div_ceil(16));
    for (i, chunk) in bytes.chunks(16).enumerate() {
        let mut hex_str = String::with_capacity(chunk.len() * 3);
        for (index, byte) in chunk.iter().enumerate() {
            if index != 0 {
                hex_str.push(' ');
            }
            use std::fmt::Write as _;
            write!(&mut hex_str, "{byte:02x}").expect("writing to String cannot fail");
        }
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..=0x7e).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        rows.push(HexRow {
            offset: start + i * 16,
            hex: hex_str,
            ascii,
        });
    }
    Ok(HexResponse {
        complete: end >= record.size,
        offset: start as i64,
        total_size: record.size,
        rows,
    })
}

pub(super) fn strings(
    ctx: &EvidenceCtx,
    case_id: &str,
    id: &str,
    min_len: i32,
    max_hits: i32,
) -> Result<Vec<StringHit>, String> {
    let (_, bytes) =
        verified_record_window(ctx, case_id, id, 0, MAX_STRINGS_SCAN, MAX_STRINGS_SCAN)?;
    let scan = bytes.as_slice();
    let min_len = min_len.clamp(2, 128) as usize;
    let max_hits = max_hits.clamp(1, MAX_STRINGS_HITS as i32) as usize;
    let mut hits = Vec::new();
    let mut start: Option<usize> = None;
    let indexed = scan
        .iter()
        .copied()
        .enumerate()
        .chain(std::iter::once((scan.len(), 0u8)));
    for (i, b) in indexed {
        let printable = i < scan.len() && (0x20..=0x7e).contains(&b);
        if printable && start.is_none() {
            start = Some(i);
        }
        if !printable {
            if let Some(s) = start {
                if i - s >= min_len {
                    hits.push(StringHit {
                        offset: s,
                        text: String::from_utf8_lossy(&scan[s..i]).to_string(),
                    });
                    if hits.len() >= max_hits {
                        break;
                    }
                }
                start = None;
            }
        }
    }
    Ok(hits)
}

/// An explicitly bounded forensic read. The entire selected evidence is SHA-256
/// verified on the same handle first; coverage is distinct from integrity.

pub(super) fn strings_scan(
    ctx: &EvidenceCtx,
    case_id: &str,
    id: &str,
    offset: u64,
    len: usize,
    min_len: i32,
    max_hits: i32,
) -> Result<ForensicStringsResponse, String> {
    use cyberdeck_crypto::formats::forensic_native::{strings, MAX_STRING_HITS, MAX_WINDOW};
    if len == 0 || len > MAX_WINDOW {
        return Err("forensic strings window must be 1..8MiB".into());
    }
    let min_len = min_len.clamp(2, 128) as usize;
    let max_hits = max_hits.clamp(1, MAX_STRING_HITS as i32) as usize;
    let (record, bytes) = verified_record_window(ctx, case_id, id, offset, len, MAX_WINDOW)?;
    let (hits, hit_limit_reached) = strings(&bytes, offset.min(record.size), min_len, max_hits)?;
    let analyzed_offset = offset.min(record.size);
    let coverage_truncated =
        analyzed_offset != 0 || analyzed_offset + (bytes.len() as u64) < record.size;
    Ok(ForensicStringsResponse {
        hits,
        analyzed_offset,
        analyzed_bytes: bytes.len(),
        file_bytes: record.size,
        integrity_checked: true,
        coverage_truncated,
        hit_limit_reached,
    })
}

pub(super) fn entropy_scan(
    ctx: &EvidenceCtx,
    case_id: &str,
    id: &str,
    offset: u64,
    len: usize,
    block_size: usize,
) -> Result<ForensicEntropyResponse, String> {
    use cyberdeck_crypto::formats::forensic_native::{entropy_regions, MAX_WINDOW};
    if len == 0 || len > MAX_WINDOW {
        return Err("entropy window must be 1..8MiB".into());
    }
    let (record, bytes) = verified_record_window(ctx, case_id, id, offset, len, MAX_WINDOW)?;
    let analyzed_offset = offset.min(record.size);
    let regions = entropy_regions(&bytes, analyzed_offset, block_size)?;
    let coverage_truncated =
        analyzed_offset != 0 || analyzed_offset + (bytes.len() as u64) < record.size;
    Ok(ForensicEntropyResponse {
        regions,
        analyzed_offset,
        analyzed_bytes: bytes.len(),
        file_bytes: record.size,
        integrity_checked: true,
        coverage_truncated,
        block_size,
    })
}

pub(super) fn metadata_scan(
    ctx: &EvidenceCtx,
    case_id: &str,
    id: &str,
) -> Result<ForensicMetadataResponse, String> {
    use cyberdeck_crypto::formats::forensic_native::{metadata, MAX_METADATA_INPUT};
    let (record, bytes) =
        verified_record_window(ctx, case_id, id, 0, MAX_METADATA_INPUT, MAX_METADATA_INPUT)?;
    let report = metadata(&bytes, 0)?;
    let coverage_truncated = bytes.len() as u64 != record.size;
    Ok(ForensicMetadataResponse {
        report,
        analyzed_offset: 0,
        analyzed_bytes: bytes.len(),
        file_bytes: record.size,
        integrity_checked: true,
        coverage_truncated,
    })
}

/// Preview bounded PNG and RIFF/WAVE carving boundaries without modifying evidence.
/// Every byte is read through the same scoped integrity-checking adapter as
/// hex, extraction and metadata. The returned offsets refer to the source file.
pub(super) fn carve_preview(
    ctx: &EvidenceCtx,
    case_id: &str,
    id: &str,
    offset: u64,
    len: usize,
) -> Result<FileCarveResponse, String> {
    use cyberdeck_crypto::formats::carving::{preview_validated_carving, MAX_CARVE_SCAN_BYTES};
    if len == 0 || len > MAX_CARVE_SCAN_BYTES {
        return Err("carving preview window must be 1..4MiB".into());
    }
    let (record, bytes) =
        verified_record_window(ctx, case_id, id, offset, len, MAX_CARVE_SCAN_BYTES)?;
    let analyzed_offset = offset.min(record.size);
    let report = preview_validated_carving(&bytes, analyzed_offset)?;
    Ok(FileCarveResponse {
        candidates: report.candidates,
        analyzed_offset,
        analyzed_bytes: bytes.len(),
        file_bytes: record.size,
        integrity_checked: true,
        coverage_truncated: analyzed_offset != 0
            || analyzed_offset + (bytes.len() as u64) < record.size,
        rejected_or_incomplete: report.rejected_or_incomplete,
        candidate_limit_reached: report.candidate_limit_reached,
    })
}

/// Case-backed, read-only detection using only bounded YARA-style ASCII/hex
/// strings and bounded "any/all/N of them" conditions. Unsupported grammar fails.
pub(super) fn yara_subset_scan(
    ctx: &EvidenceCtx,
    case_id: &str,
    id: &str,
    offset: u64,
    len: usize,
    source_rule: &str,
) -> Result<ForensicYaraSubsetResponse, String> {
    use cyberdeck_crypto::formats::yara_subset::{
        compile_yara_subset, evaluate_yara_subset, MAX_RULE_SCAN_BYTES,
    };
    if len == 0 || len > MAX_RULE_SCAN_BYTES {
        return Err("YARA subset scan window must be 1..1MiB".into());
    }
    let rule = compile_yara_subset(source_rule)?;
    let (record, bytes) =
        verified_record_window(ctx, case_id, id, offset, len, MAX_RULE_SCAN_BYTES)?;
    let analyzed_offset = offset.min(record.size);
    let evaluation = evaluate_yara_subset(&rule, &bytes, analyzed_offset)?;
    Ok(ForensicYaraSubsetResponse {
        rule: evaluation.rule,
        matched: evaluation.matched,
        hits: evaluation
            .hits
            .into_iter()
            .map(|hit| ForensicYaraSubsetHit {
                identifier: hit.identifier,
                offset: hit.offset,
            })
            .collect(),
        analyzed_offset,
        analyzed_bytes: bytes.len(),
        file_bytes: record.size,
        integrity_checked: true,
        coverage_truncated: analyzed_offset != 0
            || analyzed_offset + (bytes.len() as u64) < record.size,
        language_subset: "YARA-literal-hex-any-all-count-v2",
    })
}
