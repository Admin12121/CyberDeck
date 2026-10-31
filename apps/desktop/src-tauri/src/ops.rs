//! Native crypto ops over IPC; results carry Base64, hex and provenance (§6).

use base64::Engine as _;
use hacktool_crypto::{apply_op, catalog, OpInfo, ENGINE_ID, ENGINE_VERSION};
use serde::Serialize;
use hacktool_crypto::recipes::{execute_recipe, NativeRecipeResult, RecipeStep};

#[derive(Debug, Serialize)]
pub struct OpResult {
    pub output_b64: String,
    pub output_hex: String,
    pub engine: String,
    pub engine_version: String,
}

#[tauri::command]
pub fn crypto_op(op: String, data_b64: String, key_b64: Option<String>) -> Result<OpResult, String> {
    let data = base64::engine::general_purpose::STANDARD
        .decode(data_b64.as_bytes())
        .map_err(|e| format!("invalid input encoding: {e}"))?;
    let key = match key_b64 {
        Some(k) => Some(
            base64::engine::general_purpose::STANDARD
                .decode(k.as_bytes())
                .map_err(|e| format!("invalid key encoding: {e}"))?,
        ),
        None => None,
    };
    let out = apply_op(&op, &data, key.as_deref())?;
    Ok(OpResult {
        output_b64: base64::engine::general_purpose::STANDARD.encode(&out),
        output_hex: hex::encode(&out),
        engine: ENGINE_ID.to_string(),
        engine_version: ENGINE_VERSION.to_string(),
    })
}

#[tauri::command]
pub fn recipe_run(input: String, steps: Vec<RecipeStep>) -> NativeRecipeResult {
    execute_recipe(&input, &steps)
}

#[tauri::command]
pub fn crypto_catalog() -> Vec<OpInfo> {
    catalog()
}

/// Verify a candidate password against a bcrypt/argon2 PHC string.
#[tauri::command]
pub fn kdf_verify(hash: String, candidate: String) -> Result<bool, String> {
    hacktool_crypto::verify_kdf(hash.trim(), &candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crypto_op_hashes_and_reports_provenance() {
        let result = crypto_op("sha256".into(), base64::engine::general_purpose::STANDARD.encode(b"abc"), None).unwrap();
        assert_eq!(result.output_hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(result.engine, "hacktool-crypto");
        assert!(!result.engine_version.is_empty());
    }

    #[test]
    fn crypto_op_rejects_unknown_op() {
        assert!(crypto_op("nope".into(), String::new(), None).is_err());
    }
}
