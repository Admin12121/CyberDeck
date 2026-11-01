//! Rule-based and mask attacks (§5.5), implemented in native Rust.
//! This Tauri attack path remains CPU-only. Native OpenCL kernels exist in the
//! crypto crate but are not yet connected to this desktop handler.

#[path = "../domain/masks.rs"]
mod masks;
use masks::plan_mask;
pub use masks::MaskPlan;

#[path = "../domain/attack.rs"]
mod attack_domain;
pub use attack_domain::{AttackMatch, AttackResultWire, BenchmarkWire, DeviceInfoWire};

#[path = "../domain/rules.rs"]
mod rules;

/// Apply built-in rules over a wordlist body, chunked across CPU cores.
/// Each worker owns a slice of words; partials merge in order so hits keep
/// their source line identity.
#[path = "../application/attack.rs"]
mod application;
pub use application::{
    combinator_over_bytes, hybrid_over_bytes, hybrid_reverse_over_bytes, rules_over_bytes,
};
use application::{guard, mask_attack};

#[tauri::command]
pub fn crack_rules_dialog(
    app: tauri::AppHandle,
    algo: String,
    target_hash: String,
    ctx: tauri::State<'_, crate::features::forensics::ipc::evidence::EvidenceCtx>,
) -> Result<AttackResultWire, String> {
    let target = guard(&algo, &target_hash)?;
    let (path, name) = crate::features::crypto::ipc::crack::resolved_wordlist(&app, None)?;
    let file = std::fs::File::open(&path).map_err(|e| format!("cannot read wordlist: {e}"))?;
    let reader = std::io::BufReader::with_capacity(1 << 20, file);
    let words = cyberdeck_crypto::candidates::WordlistCandidates::new(reader)
        .map(|item| item.map(|candidate| String::from_utf8_lossy(&candidate).into_owned()));
    let mut result = application::rules_over_lines(&algo, &target, words)?;
    result.source = format!("{name} + built-in rules");
    record_history(&ctx, &algo, &target, &result.source, &result.matches);
    Ok(result)
}

/// Mask attack: pattern like ?l?l?l?d?d?d?d with classes l/u/d/s/a.
#[tauri::command]
pub fn crack_mask(
    algo: String,
    target_hash: String,
    mask: String,
    ctx: tauri::State<'_, crate::features::forensics::ipc::evidence::EvidenceCtx>,
) -> Result<AttackResultWire, String> {
    let result = mask_attack(&algo, &target_hash, &mask)?;
    record_history(
        &ctx,
        &result.algo,
        &result.target_hash,
        &format!("native mask ({})", result.source),
        &result.matches,
    );
    Ok(result)
}

#[tauri::command]
pub fn crack_hybrid_dialog(
    app: tauri::AppHandle,
    algo: String,
    target_hash: String,
    mask: String,
    wordlist_path: Option<String>,
    ctx: tauri::State<'_, crate::features::forensics::ipc::evidence::EvidenceCtx>,
) -> Result<AttackResultWire, String> {
    let target = guard(&algo, &target_hash)?;
    // The UI's chosen wordlist is reused; a dialog opens only when none is set.
    let (path, name) =
        crate::features::crypto::ipc::crack::resolved_wordlist(&app, wordlist_path.as_deref())?;
    let body = crate::features::crypto::ipc::crack::read_wordlist_prefix(&path, 500)?;
    let mut result = hybrid_over_bytes(&algo, &target, &mask, &body)?;
    result.source = format!("{name} + {mask}");
    record_history(
        &ctx,
        &algo,
        &target,
        &format!("hybrid wordlist + {mask}"),
        &result.matches,
    );
    Ok(result)
}

#[tauri::command]
pub fn crack_hybrid_reverse_dialog(
    app: tauri::AppHandle,
    algo: String,
    target_hash: String,
    mask: String,
    wordlist_path: Option<String>,
    ctx: tauri::State<'_, crate::features::forensics::ipc::evidence::EvidenceCtx>,
) -> Result<AttackResultWire, String> {
    let target = guard(&algo, &target_hash)?;
    let (path, name) =
        crate::features::crypto::ipc::crack::resolved_wordlist(&app, wordlist_path.as_deref())?;
    let body = crate::features::crypto::ipc::crack::read_wordlist_prefix(&path, 500)?;
    let mut result = hybrid_reverse_over_bytes(&algo, &target, &mask, &body)?;
    result.source = format!("{mask} + {name}");
    record_history(
        &ctx,
        &algo,
        &target,
        &format!("hybrid mask + wordlist ({mask})"),
        &result.matches,
    );
    Ok(result)
}

#[tauri::command]
pub fn crack_combinator_dialog(
    app: tauri::AppHandle,
    algo: String,
    target_hash: String,
    wordlist_path: Option<String>,
    second_wordlist_path: Option<String>,
    ctx: tauri::State<'_, crate::features::forensics::ipc::evidence::EvidenceCtx>,
) -> Result<AttackResultWire, String> {
    let target = guard(&algo, &target_hash)?;
    let (first_path, first_name) =
        crate::features::crypto::ipc::crack::resolved_wordlist(&app, wordlist_path.as_deref())?;
    let (second_path, second_name) = crate::features::crypto::ipc::crack::resolved_wordlist(
        &app,
        second_wordlist_path.as_deref(),
    )?;
    let first_body = crate::features::crypto::ipc::crack::read_wordlist_prefix(&first_path, 500)?;
    let second_body = crate::features::crypto::ipc::crack::read_wordlist_prefix(&second_path, 500)?;
    let mut result = combinator_over_bytes(&algo, &target, &first_body, &second_body)?;
    result.source = format!("{first_name} x {second_name}");
    record_history(
        &ctx,
        &algo,
        &target,
        &format!("combinator {first_name} x {second_name}"),
        &result.matches,
    );
    Ok(result)
}

#[path = "../application/benchmark.rs"]
mod benchmark_app;

#[tauri::command]
pub fn benchmark(algo: String, duration_ms: Option<u64>) -> Result<BenchmarkWire, String> {
    benchmark_app::benchmark(algo, duration_ms)
}

/// Compatibility entry point for external engine adapters.
pub fn record_history(
    ctx: &crate::features::forensics::ipc::evidence::EvidenceCtx,
    algo: &str,
    target: &str,
    engine: &str,
    matches: &[AttackMatch],
) {
    crate::features::crypto::ipc::history::persist(
        ctx,
        algo,
        target,
        engine,
        None,
        matches.iter().map(|hit| hit.password.as_str()),
    );
}

#[path = "../infrastructure/gpu_discovery.rs"]
mod gpu_discovery;

#[tauri::command]
pub fn device_info() -> DeviceInfoWire {
    benchmark_app::device_info()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA256_HELLO: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    #[test]
    fn rules_find_capitalized_and_suffixed_variants() {
        // "hello" won't match, but "Hello123" will via the rules
        let body = b"hello\nworld\n";
        let target = cyberdeck_crypto::apply_op("sha256", b"Hello123", None).unwrap();
        let result = rules_over_bytes("sha256", &hex::encode(target), body).unwrap();
        assert_eq!(result.mode, "rules");
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].password, "Hello123");
        assert!(result.tried > 20);
    }

    #[test]
    fn rules_report_no_match_cleanly() {
        let result = rules_over_bytes("md5", "0".repeat(32).as_str(), b"hello\n").unwrap();
        assert!(result.matches.is_empty());
        assert!(!result.cap_reached);
    }

    #[test]
    fn mask_plan_counts_candidates() {
        assert_eq!(plan_mask("?d?d").unwrap().candidate_count, 100);
        assert_eq!(plan_mask("?l?l?l").unwrap().candidate_count, 17_576);
        assert!(plan_mask("abc").is_err());
        assert!(plan_mask("?x").is_err());
    }

    #[test]
    fn mask_finds_the_needle() {
        // sha256("42")
        let target = cyberdeck_crypto::apply_op("sha256", b"42", None).unwrap();
        let result = mask_attack("sha256", &hex::encode(target), "?d?d").unwrap();
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].password, "42");
        // the odometer completes the space; hits are collected, not early-exited
        assert_eq!(result.tried, 100);
    }

    #[test]
    fn mask_respects_candidate_cap() {
        // 6 lowercase letters = 308M candidates, over the 20M cap
        let err = mask_attack("md5", SHA256_HELLO, "?l?l?l?l?l?l").unwrap_err();
        assert!(err.contains("cap"));
    }

    #[test]
    fn mask_escapes_literal_question_mark() {
        // ?? is an escaped literal '?', so "a?d?d" = literal a + two digit classes
        assert_eq!(plan_mask("a?d?d").unwrap().candidate_count, 100);
        // "a??d" is a, ?, d: three literals, zero classes
        assert!(plan_mask("a??d").is_err());
    }

    #[test]
    fn mask_with_leading_literal_finds_the_needle() {
        // The literal before the classes takes a slot but is not a class; the
        // odometer must index classes, not slots, and still walk the whole space.
        assert_eq!(plan_mask("a?d?d").unwrap().candidate_count, 100);
        let target = cyberdeck_crypto::apply_op("sha256", b"a99", None).unwrap();
        let result = mask_attack("sha256", &hex::encode(target), "a?d?d").unwrap();
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].password, "a99");
        assert_eq!(result.tried, 100);
    }

    #[test]
    fn mask_with_non_ascii_literal_finds_the_needle() {
        let target = cyberdeck_crypto::apply_op("sha256", "é7".as_bytes(), None).unwrap();
        let result = mask_attack("sha256", &hex::encode(target), "é?d").unwrap();
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].password, "é7");
        assert_eq!(result.tried, 10);
    }

    #[test]
    fn rules_handle_non_ascii_wordlist_entries() {
        // Multi-byte words used to panic on byte-index slicing inside the rules.
        let target = cyberdeck_crypto::apply_op("sha256", "Café123".as_bytes(), None).unwrap();
        let result =
            rules_over_bytes("sha256", &hex::encode(target), "é\n日本\ncafé\n".as_bytes()).unwrap();
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].password, "Café123");
        assert!(result.tried > 0);
    }

    #[test]
    fn hybrid_handles_literal_prefixed_masks_and_non_ascii_words() {
        // "a?d?d" yields 100 suffixes despite the leading literal, and the
        // non-ASCII wordlist words must survive byte handling intact.
        let target = cyberdeck_crypto::apply_op("sha256", "caféa99".as_bytes(), None).unwrap();
        let result = hybrid_over_bytes(
            "sha256",
            &hex::encode(target),
            "a?d?d",
            "café\n日本\n".as_bytes(),
        )
        .unwrap();
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].password, "caféa99");
        assert_eq!(result.tried, 200); // 2 words x 100 suffixes
        assert!(!result.cap_reached);
    }

    #[test]
    fn reverse_hybrid_finds_mask_prefixed_word() {
        let target = cyberdeck_crypto::apply_op("sha256", b"42hello", None).unwrap();
        let result =
            hybrid_reverse_over_bytes("sha256", &hex::encode(target), "?d?d", b"hello\nworld\n")
                .unwrap();
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].password, "42hello");
        assert_eq!(result.tried, 200); // 100 prefixes x 2 words
    }

    #[test]
    fn combinator_finds_joined_words() {
        let target = cyberdeck_crypto::apply_op("sha256", b"helloworld", None).unwrap();
        let result = combinator_over_bytes(
            "sha256",
            &hex::encode(target),
            b"hello\nfoo\n",
            b"world\nbar\n",
        )
        .unwrap();
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.matches[0].password, "helloworld");
        assert_eq!(result.tried, 4);
    }

    #[test]
    fn device_info_is_honest() {
        let info = device_info();
        assert!(info.cpu_cores >= 1);
        assert!(!info.cpu_arch.is_empty());
        // Hardware detection must never imply an executable native GPU engine.
        assert!(info.gpu_devices.iter().all(|g| !g.usable));
    }
}
