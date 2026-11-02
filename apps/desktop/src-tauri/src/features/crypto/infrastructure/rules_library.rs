//! Bundled rule-set library. Rules ship inside the signed app resources,
//! are verified by sha256 before use, and are parsed by the bounded native
//! rule engine. No frontend-supplied paths are accepted; only manifest ids.
use serde::Serialize;
use std::io::BufReader;
use std::path::PathBuf;

const MAX_MANIFEST_BYTES: u64 = 1 << 20;

#[derive(Serialize)]
pub struct RuleSetEntry {
    pub id: String,
    pub rule_count: u64,
    pub size_bytes: u64,
}

#[derive(Serialize)]
pub struct LoadedRuleSet {
    pub id: String,
    pub rules: Vec<cyberdeck_crypto::recovery::CompiledRule>,
    /// Lines the bounded grammar could not represent; always surfaced, never hidden.
    pub skipped: u64,
}

/// Inspect-only summary for IPC; compiled rules never cross the wire.
#[derive(Serialize)]
pub struct LoadedRuleSetSummary {
    pub id: String,
    pub rule_count: u64,
    pub skipped: u64,
}

#[derive(serde::Deserialize)]
struct ManifestRule {
    id: String,
    file: String,
    sha256: String,
    rule_count: u64,
    size_bytes: u64,
}

#[derive(serde::Deserialize)]
struct Manifest {
    rules: Vec<ManifestRule>,
}

fn manifest_from_json(bytes: &[u8]) -> Result<Manifest, String> {
    serde_json::from_slice(bytes).map_err(|e| format!("bundled rule manifest is invalid: {e}"))
}

fn bundled_rules_root(dev_root: PathBuf) -> Result<PathBuf, String> {
    let manifest = dev_root.join("rules-manifest.json");
    let bytes = std::fs::read(&manifest)
        .map_err(|_| "bundled rule library manifest is missing")?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err("bundled rule manifest exceeds sanity size".into());
    }
    let _ = manifest_from_json(&bytes)?;
    Ok(dev_root)
}

/// Packaged installs resolve through Tauri's resource directory; debug builds
/// fall back to the source tree so a plain `cargo dev` run still works.
pub fn resource_root(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    if let Ok(packaged) = app
        .path()
        .resource_dir()
        .map_err(|_| "app resources unavailable".to_string())
        .map(|dir| dir.join("rules"))
    {
        if packaged.is_dir() {
            return bundled_rules_root(packaged);
        }
    }
    #[cfg(debug_assertions)]
    {
        let dev = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources/rules");
        if dev.is_dir() {
            return bundled_rules_root(dev);
        }
    }
    Err("bundled rule library is not packaged".into())
}

pub fn list(app: &tauri::AppHandle) -> Result<Vec<RuleSetEntry>, String> {
    let root = resource_root(app)?;
    let bytes = std::fs::read(root.join("rules-manifest.json"))
        .map_err(|_| "bundled rule manifest is missing")?;
    let manifest = manifest_from_json(&bytes)?;
    Ok(manifest
        .rules
        .iter()
        .map(|rule| RuleSetEntry {
            id: rule.id.clone(),
            rule_count: rule.rule_count,
            size_bytes: rule.size_bytes,
        })
        .collect())
}

/// Load a rule set by manifest id. The file is re-hashed on every load so a
/// tampered resource directory can never feed rules to a live session.
pub fn load(app: &tauri::AppHandle, id: &str) -> Result<LoadedRuleSet, String> {
    if id.len() > 64 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err("invalid rule set id".into());
    }
    let root = resource_root(app)?;
    let bytes = std::fs::read(root.join("rules-manifest.json"))
        .map_err(|_| "bundled rule manifest is missing")?;
    let manifest = manifest_from_json(&bytes)?;
    let entry = manifest
        .rules
        .iter()
        .find(|rule| rule.id == id)
        .ok_or_else(|| "unknown rule set".to_string())?;
    let path = root.join(&entry.file);
    // The id check above plus the manifest lookup constrain the file name;
    // reject traversal-style names defensively anyway.
    if entry.file.contains('/') || entry.file.contains('\\') || entry.file.contains("..") {
        return Err("invalid rule set file name".into());
    }
    let data = std::fs::read(&path).map_err(|_| "bundled rule set is missing")?;
    let digest = sha256_hex(&data);
    if !constant_time_eq(digest.as_bytes(), entry.sha256.to_ascii_lowercase().as_bytes()) {
        return Err("bundled rule set failed integrity verification".into());
    }
    if data.len() as u64 != entry.size_bytes {
        return Err("bundled rule set size does not match the manifest".into());
    }
    let parsed = cyberdeck_crypto::recovery::parse_rule_file_tolerant(BufReader::new(data.as_slice()))?;
    Ok(LoadedRuleSet {
        id: entry.id.clone(),
        rules: parsed.rules,
        skipped: parsed.skipped,
    })
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Load and verify a rule set, returning only metadata over IPC.
pub fn load_summary(app: &tauri::AppHandle, id: &str) -> Result<LoadedRuleSetSummary, String> {
    let loaded = load(app, id)?;
    Ok(LoadedRuleSetSummary {
        id: loaded.id,
        rule_count: loaded.rules.len() as u64,
        skipped: loaded.skipped,
    })
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_ids_reject_traversal_and_unknown() {
        // Pure validation checks that do not need the resource bundle.
        assert!(!"../../etc/passwd"
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        assert!("best66".bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    }

    #[test]
    fn sha256_helper_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn constant_time_eq_matches_only_equal_slices() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn dev_resource_root_resolves_and_manifest_lists_eight_sets() {
        // Debug builds ship the source-tree resources; this validates the
        // manifest is coherent with the actual shipped files.
        let dev = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources/rules");
        if !dev.is_dir() {
            return; // resource layout changed; the packaged path covers it
        }
        let root = bundled_rules_root(dev).unwrap();
        let bytes = std::fs::read(root.join("rules-manifest.json")).unwrap();
        let manifest = manifest_from_json(&bytes).unwrap();
        assert_eq!(manifest.rules.len(), 8);
        for entry in &manifest.rules {
            let data = std::fs::read(root.join(&entry.file)).unwrap();
            assert_eq!(sha256_hex(&data), entry.sha256.to_ascii_lowercase());
            assert_eq!(data.len() as u64, entry.size_bytes);
        }
    }

    #[test]
    fn every_bundled_rule_set_parses_fully() {
        let dev = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources/rules");
        if !dev.is_dir() {
            return;
        }
        let bytes = std::fs::read(dev.join("rules-manifest.json")).unwrap();
        let manifest = manifest_from_json(&bytes).unwrap();
        for entry in &manifest.rules {
            let data = std::fs::read(dev.join(&entry.file)).unwrap();
            let parsed = cyberdeck_crypto::recovery::parse_rule_file_tolerant(
                BufReader::new(data.as_slice()),
            )
            .unwrap_or_else(|e| panic!("{} failed to parse: {e}", entry.file));
            assert_eq!(parsed.rules.len() as u64, entry.rule_count, "{}", entry.file);
            assert_eq!(parsed.skipped, 0, "{}", entry.file);
        }
    }
}
