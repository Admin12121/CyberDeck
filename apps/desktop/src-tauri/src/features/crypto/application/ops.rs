//! Crypto Ops use cases. No Tauri or desktop state dependencies.
use base64::Engine as _;
use cyberdeck_crypto::recipes::{execute_recipe, NativeRecipeResult, RecipeStep};
use cyberdeck_crypto::{apply_op, catalog, OpInfo, ENGINE_ID, ENGINE_VERSION};

use super::domain::OpResult;

pub fn execute_crypto_op(
    op: &str,
    data_b64: &str,
    key_b64: Option<&str>,
) -> Result<OpResult, String> {
    let codec = base64::engine::general_purpose::STANDARD;
    let data = codec
        .decode(data_b64.as_bytes())
        .map_err(|e| format!("invalid input encoding: {e}"))?;
    let key = key_b64
        .map(|encoded| {
            codec
                .decode(encoded.as_bytes())
                .map_err(|e| format!("invalid key encoding: {e}"))
        })
        .transpose()?;

    let output = apply_op(op, &data, key.as_deref())?;
    Ok(OpResult {
        output_b64: codec.encode(&output),
        output_hex: hex::encode(&output),
        engine: ENGINE_ID.to_string(),
        engine_version: ENGINE_VERSION.to_string(),
    })
}

pub fn execute_recipe_steps(input: &str, steps: &[RecipeStep]) -> NativeRecipeResult {
    execute_recipe(input, steps)
}

pub fn available_ops() -> Vec<OpInfo> {
    catalog()
}

pub fn verify_password_kdf(hash: &str, candidate: &str) -> Result<bool, String> {
    cyberdeck_crypto::verify_kdf(hash.trim(), candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_engine_returns_provenance_and_both_binary_encodings() {
        let result = execute_crypto_op("sha256", "YWJj", None).unwrap();
        assert_eq!(
            result.output_hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(result.engine, "cyberdeck-crypto");
        assert!(!result.engine_version.is_empty());
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(result.output_b64)
                .unwrap(),
            hex::decode(result.output_hex).unwrap()
        );
    }

    #[test]
    fn key_and_input_validation_are_independent() {
        assert!(execute_crypto_op("sha256", "!!", None)
            .unwrap_err()
            .starts_with("invalid input encoding:"));
        assert!(execute_crypto_op("hmac_sha256", "YWJj", Some("!!"))
            .unwrap_err()
            .starts_with("invalid key encoding:"));
    }
}
