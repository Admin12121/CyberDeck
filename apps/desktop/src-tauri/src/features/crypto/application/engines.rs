//! External-engine use case policy and wire assembly, without Tauri dependencies.
use super::domain::EngineAttackResult;
use super::sidecar::{capture_tail, EngineRun};

pub fn normalized_target(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("target hash is empty".into());
    }
    if raw.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
        return Err("target hash must be one line".into());
    }
    // Hex digests are case-insensitive; modular crypt strings are not.
    Ok(if raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        raw.to_ascii_lowercase()
    } else {
        raw.to_owned()
    })
}

pub fn validate_mode(engine: &str, mode: &str, mask: Option<&str>) -> Result<(), String> {
    if !matches!(mode, "wordlist" | "mask") {
        return Err("engine attacks support wordlist and mask modes this arc".into());
    }
    match engine {
        "hashcat" if mode == "mask" && mask.is_none_or(str::is_empty) => {
            Err("mask attack needs a mask pattern".into())
        }
        "hashcat" => Ok(()),
        "john" if mode == "mask" => {
            Err("john mask mode arrives with the mask engine arc; use wordlist or native".into())
        }
        "john" => Ok(()),
        other => Err(format!("unknown engine: {other}")),
    }
}

pub fn report(
    engine: String,
    engine_version: String,
    algo: String,
    mode: String,
    duration_ms: u64,
    run: EngineRun,
) -> EngineAttackResult {
    let tried_note = match engine.as_str() {
        "hashcat" if run.status.success() => "completed",
        "hashcat" => "engine returned nonzero; see raw output",
        "john" if run.status.success() => "wordlist + john pot",
        _ => "engine returned nonzero; see raw output",
    };
    EngineAttackResult {
        engine,
        engine_version,
        algo,
        mode,
        tried_note: tried_note.to_owned(),
        matches: run.matches,
        duration_ms,
        raw_tail: capture_tail(&run.stdout, &run.stderr, 4000),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modular_hash_case_is_preserved() {
        assert_eq!(
            normalized_target("$2b$12$AbCdEfGhIjKlMnOp").unwrap(),
            "$2b$12$AbCdEfGhIjKlMnOp"
        );
        assert_eq!(normalized_target(" ABcDeF ").unwrap(), "abcdef");
    }

    #[test]
    fn rejects_embedded_newline_in_hash() {
        assert!(normalized_target("$2b$12$AbCd\nInjected").is_err());
    }

    #[test]
    fn john_mask_and_empty_hashcat_mask_are_rejected() {
        assert!(validate_mode("john", "mask", Some("?d")).is_err());
        assert!(validate_mode("hashcat", "mask", None).is_err());
        assert!(validate_mode("hashcat", "mask", Some("?d")).is_ok());
    }
}
