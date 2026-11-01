//! Thin backward-compatible Tauri crypto IPC entry points.
//! Business logic and wire types are separated by feature-first ownership.

#[path = "../application/ops.rs"]
mod application;
#[path = "../domain/ops.rs"]
mod domain;

pub use domain::OpResult;

use cyberdeck_crypto::recipes::{NativeRecipeResult, RecipeStep};
use cyberdeck_crypto::OpInfo;

#[tauri::command]
pub fn crypto_op(
    op: String,
    data_b64: String,
    key_b64: Option<String>,
) -> Result<OpResult, String> {
    application::execute_crypto_op(&op, &data_b64, key_b64.as_deref())
}

#[tauri::command]
pub fn recipe_run(input: String, steps: Vec<RecipeStep>) -> NativeRecipeResult {
    application::execute_recipe_steps(&input, &steps)
}

#[tauri::command]
pub fn crypto_catalog() -> Vec<OpInfo> {
    application::available_ops()
}

#[tauri::command]
pub fn kdf_verify(hash: String, candidate: String) -> Result<bool, String> {
    application::verify_password_kdf(&hash, &candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    #[test]
    fn crypto_op_hashes_and_reports_provenance() {
        let result = crypto_op(
            "sha256".into(),
            base64::engine::general_purpose::STANDARD.encode(b"abc"),
            None,
        )
        .unwrap();
        assert_eq!(
            result.output_hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(result.engine, "cyberdeck-crypto");
        assert!(!result.engine_version.is_empty());
    }

    #[test]
    fn crypto_op_rejects_unknown_op() {
        assert!(crypto_op("nope".into(), String::new(), None).is_err());
    }
}
