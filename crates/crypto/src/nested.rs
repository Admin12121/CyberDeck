//! Depth-limited, provenance-preserving archive traversal.
//! No untrusted filename is used as a filesystem path. Callers import
//! returned leaf bytes through their case/evidence persistence boundary.
use super::{
    extract_gzip_member_limited, extract_tar_limited, extract_zip_limited,
    tar_header_checksum_valid, ExtractedEntry, MAX_ARCHIVE_ENTRIES,
    MAX_ARCHIVE_OUTPUT_BYTES,
};

pub const MAX_NESTED_DEPTH: usize = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveHop {
    /// The format of the archive containing this extracted item.
    pub format: &'static str,
    /// Original item name or a synthetic label for a Gzip member.
    pub item_name: String,
    /// Header position within the immediately enclosing input, not the root.
    pub source_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NestedEntry {
    /// Display-only path; never open a filesystem destination using this value.
    pub path: String,
    pub lineage: Vec<ArchiveHop>,
    pub bytes: Vec<u8>,
}

struct Budget {
    nodes: usize,
    expanded_bytes: usize,
    max_nodes: usize,
    max_bytes: usize,
    max_depth: usize,
}

fn archive_format(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        Some("zip")
    } else if data.len() >= 10
        && data.starts_with(b"\x1f\x8b\x08")
        && data[3] & 0xe0 == 0
    {
        Some("gzip")
    } else if data.len() >= 512
        && &data[257..262] == b"ustar"
        && tar_header_checksum_valid(&data[..512])
    {
        Some("tar")
    } else {
        None
    }
}

fn extract_one_layer(
    data: &[u8],
    format: &str,
    offset: usize,
    remaining_bytes: usize,
) -> Result<Vec<ExtractedEntry>, String> {
    match format {
        "zip" => extract_zip_limited(data, offset, remaining_bytes),
        "tar" => extract_tar_limited(data, offset, remaining_bytes),
        "gzip" => {
            let member = extract_gzip_member_limited(data, offset, remaining_bytes)?;
            Ok(vec![ExtractedEntry {
                path: "gzip-member".into(),
                bytes: member.bytes,
                source_offset: offset as u64,
            }])
        }
        _ => Err("only ZIP, TAR and Gzip support recursive extraction".into()),
    }
}

fn walk(
    data: &[u8],
    format: &'static str,
    offset: usize,
    depth: usize,
    ancestors: &[ArchiveHop],
    result: &mut Vec<NestedEntry>,
    budget: &mut Budget,
) -> Result<(), String> {
    if depth >= budget.max_depth {
        return Err("nested archive recursion depth exceeded".into());
    }
    let available = budget.max_bytes.checked_sub(budget.expanded_bytes)
        .ok_or("nested archive expansion budget exceeded")?;
    if available == 0 {
        return Err("nested archive expansion budget exhausted".into());
    }
    // Parse the whole layer before emitting any leaf from this layer.
    let entries = extract_one_layer(data, format, offset, available)?;
    for entry in entries {
        budget.nodes = budget.nodes.checked_add(1).ok_or("nested archive entry counter overflow")?;
        if budget.nodes > budget.max_nodes {
            return Err("nested archive entry count exceeded".into());
        }
        budget.expanded_bytes = budget.expanded_bytes.checked_add(entry.bytes.len())
            .ok_or("nested archive byte counter overflow")?;
        if budget.expanded_bytes > budget.max_bytes {
            return Err("nested archive expansion budget exceeded".into());
        }
        let mut lineage = ancestors.to_vec();
        lineage.push(ArchiveHop {
            format,
            item_name: entry.path.clone(),
            source_offset: entry.source_offset,
        });
        if let Some(child_format) = archive_format(&entry.bytes) {
            if depth + 1 >= budget.max_depth {
                return Err("nested archive recursion depth exceeded".into());
            }
            walk(&entry.bytes, child_format, 0, depth + 1, &lineage, result, budget)?;
        } else {
            let path = lineage.iter().map(|hop| hop.item_name.as_str())
                .collect::<Vec<_>>().join("!/");
            result.push(NestedEntry { path, lineage, bytes: entry.bytes });
        }
    }
    Ok(())
}

/// Explicit recursive extraction. Rejects archives exceeding any shared
/// depth, node-count or cumulative expanded-byte budget. Intermediate
/// decompressions count toward the same output budget as final leaf files.
pub fn extract_nested_limited(
    input: &[u8],
    format: &'static str,
    offset: usize,
    max_depth: usize,
    max_nodes: usize,
    max_expanded_bytes: usize,
) -> Result<Vec<NestedEntry>, String> {
    if max_depth == 0 || max_depth > MAX_NESTED_DEPTH
        || max_nodes == 0 || max_nodes > MAX_ARCHIVE_ENTRIES
        || max_expanded_bytes == 0 || max_expanded_bytes > MAX_ARCHIVE_OUTPUT_BYTES
    {
        return Err("invalid nested extraction resource limits".into());
    }
    let mut budget = Budget {
        nodes: 0, expanded_bytes: 0, max_nodes, max_bytes: max_expanded_bytes, max_depth
    };
    let mut result = Vec::new();
    walk(input, format, offset, 0, &[], &mut result, &mut budget)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;

    fn tar(name: &[u8], bytes: &[u8]) -> Vec<u8> {
        let mut h = [0u8; 512];
        h[..name.len()].copy_from_slice(name);
        h[124..136].copy_from_slice(format!("{:011o}\0", bytes.len()).as_bytes());
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[148..156].fill(b' ');
        let checksum = h.iter().map(|&x| x as usize).sum::<usize>();
        h[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        let mut result = h.to_vec();
        result.extend_from_slice(bytes);
        let padded = bytes.len().div_ceil(512) * 512;
        result.resize(512 + padded + 1024, 0);
        result
    }
    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut writer = GzEncoder::new(Vec::new(), Compression::fast());
        writer.write_all(bytes).unwrap();
        writer.finish().unwrap()
    }
    #[test]
    fn tar_gzip_tar_lineage_and_limits() {
        let inner = tar(b"leaf.bin", b"final bytes");
        let outer = tar(b"child.gz", &gzip(&inner));
        let entries = extract_nested_limited(&outer, "tar", 0, 3, 8, 8192).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].bytes, b"final bytes");
        assert_eq!(entries[0].path, "child.gz!/gzip-member!/leaf.bin");
        assert_eq!(entries[0].lineage.iter().map(|x| x.format).collect::<Vec<_>>(),
            ["tar", "gzip", "tar"]);
        assert!(extract_nested_limited(&outer, "tar", 0, 2, 8, 8192)
            .unwrap_err().contains("depth"));
        assert!(extract_nested_limited(&outer, "tar", 0, 3, 2, 8192)
            .unwrap_err().contains("count"));
        assert!(extract_nested_limited(&outer, "tar", 0, 3, 8, 100).is_err());
    }
    #[test]
    fn rejects_unsafe_nested_paths_and_excessive_options() {
        let bad = tar(b"../escape", b"payload");
        assert!(extract_nested_limited(&bad, "tar", 0, 3, 8, 4096).is_err());
        let good = tar(b"safe.txt", b"ok");
        assert!(extract_nested_limited(&good, "tar", 0, 4, 8, 4096).is_err());
        assert!(extract_nested_limited(&good, "tar", 0, 3, 129, 4096).is_err());
        assert!(extract_nested_limited(&good, "rar", 0, 3, 8, 4096).is_err());
    }
}
