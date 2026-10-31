//! Crypto operation wire result; stable field names for the desktop frontend.
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct OpResult {
    pub output_b64: String,
    pub output_hex: String,
    pub engine: String,
    pub engine_version: String,
}
