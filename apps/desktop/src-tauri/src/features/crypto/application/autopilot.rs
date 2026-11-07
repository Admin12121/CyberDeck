//! Recovery autopilot planning. One detected hash becomes an ordered attack
//! ladder: every present algorithm candidate against the best available
//! wordlist, then rule escalation on the primary algorithm. Pure planning
//! logic; the IPC layer resolves what the library actually has on disk.
use serde::Serialize;

pub const WORDLIST_PREFERENCE: &[&str] = &[
    "rockyou",
    "seclists-top-1000000",
    "seclists-top-100000",
    "cyberdeck-common",
];

pub const RULES_PREFERENCE: &[&str] = &["best66", "rockyou-30000"];

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StageEngine {
    /// Native Rust, all cores.
    Cpu,
    /// Embedded pinned Hashcat core on the operator's GPU (KAT-verified modes only).
    Gpu,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AutopilotStagePlan {
    pub algorithm: String,
    pub wordlist_id: String,
    pub rules_set: Option<String>,
    /// Final mask fallback stage (e.g. four digits) when no wordlist pass hit.
    pub mask: Option<String>,
    pub engine: StageEngine,
    pub label: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AutopilotPlan {
    pub algorithm: String,
    pub kdf: bool,
    /// Human-readable family note from backend detection.
    pub detail: String,
    pub stages: Vec<AutopilotStagePlan>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detection {
    pub algorithms: Vec<&'static str>,
    pub kdf: bool,
    pub detail: String,
}

/// Backend-side detection so the frontend cannot claim an algorithm.
/// Ambiguous digest shapes expand into candidates tried in order.
pub fn detect_target(target_hash: &str) -> Result<Detection, String> {
    let text = target_hash.trim();
    if text.is_empty() {
        return Err("target is empty".into());
    }
    if let Some(format) = cyberdeck_crypto::kdf_format(text) {
        return Ok(Detection {
            algorithms: vec![match format {
                "wpa-pmkid" => "wpa-pmkid",
                "bcrypt" => "bcrypt",
                "argon2id" => "argon2id",
                "argon2i" => "argon2i",
                "argon2d" => "argon2d",
                "scrypt" => "scrypt",
                "yescrypt" => "yescrypt",
                other => other,
            }],
            kdf: true,
            detail: format!(
                "KDF hash detected ({format}); CPU wordlist attack with a bounded candidate budget"
            ),
        });
    }
    let is_mysql5 = text.starts_with('*') && text.len() == 41;
    let is_hex = !text.is_empty()
        && text.len() % 2 == 0
        && text.bytes().all(|byte| byte.is_ascii_hexdigit());
    if !is_hex && !is_mysql5 {
        return Err("target is neither a known modular hash nor a hexadecimal digest".into());
    }
    let algorithms: &[&'static str] = if is_mysql5 {
        &["mysql5"]
    } else {
        match text.len() / 2 {
            16 => &["md5", "ntlm", "lm"],
            20 => &["sha1"],
            32 => &["sha256", "sha3_256"],
            64 => &["sha512"],
            _ => {
                return Err(format!(
                    "no supported digest algorithm matches {} hex digits",
                    text.len()
                ))
            }
        }
    };
    let names = algorithms
        .iter()
        .map(|name| match *name {
            "md5" => "MD5",
            "ntlm" => "NTLM",
            "lm" => "LAN Manager",
            "mysql5" => "MySQL 4.1+",
            "sha1" => "SHA-1",
            "sha256" => "SHA-256",
            "sha3_256" => "SHA3-256",
            "sha512" => "SHA-512",
            other => other,
        })
        .collect::<Vec<_>>()
        .join(", then ");
    Ok(Detection {
        algorithms: algorithms.to_vec(),
        kdf: false,
        detail: format!("digest shape matches {names}; ambiguous shapes are tried in order"),
    })
}

/// Build the ladder from what the library actually has present. KDF targets
/// never receive rule stages: their candidate budget is tiny by design.
pub fn build_plan(
    detection: &Detection,
    present_wordlists: &[String],
    available_rules: &[String],
    gpu_algorithms: &[String],
) -> Result<AutopilotPlan, String> {
    let wordlist_id = WORDLIST_PREFERENCE
        .iter()
        .find(|id| present_wordlists.iter().any(|present| present == *id))
        .ok_or("no wordlist is available; download one in the wordlist library first")?;
    let wordlist_name = WORDLIST_PREFERENCE
        .iter()
        .find(|id| *id == wordlist_id)
        .copied()
        .unwrap_or(wordlist_id);
    let mut stages = Vec::new();
    let primary = detection
        .algorithms
        .first()
        .ok_or("no algorithm candidate")?;
    for algorithm in &detection.algorithms {
        let engine = if gpu_algorithms.iter().any(|gpu| gpu == algorithm) {
            StageEngine::Gpu
        } else {
            StageEngine::Cpu
        };
        stages.push(AutopilotStagePlan {
            algorithm: (*algorithm).to_string(),
            wordlist_id: (*wordlist_id).to_string(),
            rules_set: None,
            mask: None,
            engine,
            label: format!(
                "{wordlist_name} wordlist as {algorithm} ({})",
                if engine == StageEngine::Gpu {
                    "GPU"
                } else {
                    "CPU"
                }
            ),
        });
    }
    if !detection.kdf {
        for rules in RULES_PREFERENCE {
            if available_rules.iter().any(|available| available == rules) {
                // Rule escalation rides the GPU when the mode passed its KAT:
                // the supervisor CPU-expands the rules into a bounded private
                // file and runs the chunked GPU path; an expansion that
                // exceeds its bounds falls back to the CPU engine at run time.
                let engine = if gpu_algorithms.iter().any(|gpu| gpu == primary) {
                    StageEngine::Gpu
                } else {
                    StageEngine::Cpu
                };
                stages.push(AutopilotStagePlan {
                    algorithm: (*primary).to_string(),
                    wordlist_id: (*wordlist_id).to_string(),
                    rules_set: Some((*rules).to_string()),
                    mask: None,
                    engine,
                    label: format!(
                        "{wordlist_name} + {rules} rules as {primary} ({})",
                        if engine == StageEngine::Gpu {
                            "GPU · rules-expanded"
                        } else {
                            "CPU"
                        }
                    ),
                });
            }
        }
        // Bounded mask fallback: four digits catches year/pin tails cheaply.
        stages.push(AutopilotStagePlan {
            algorithm: (*primary).to_string(),
            wordlist_id: String::new(),
            rules_set: None,
            mask: Some("?d?d?d?d".to_string()),
            engine: StageEngine::Cpu,
            label: format!("mask ?d?d?d?d as {primary} (CPU)"),
        });
    }
    Ok(AutopilotPlan {
        algorithm: (*primary).to_string(),
        kdf: detection.kdf,
        detail: detection.detail.clone(),
        stages,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wordlists(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|id| id.to_string()).collect()
    }

    fn rules(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|id| id.to_string()).collect()
    }

    #[test]
    fn digest_shapes_expand_into_ordered_candidates() {
        let md5_like = detect_target("9a0364b9e99bb480dd25e1f0284c8555").unwrap();
        assert_eq!(md5_like.algorithms, vec!["md5", "ntlm", "lm"]);
        let mysql = detect_target("*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19").unwrap();
        assert_eq!(mysql.algorithms, vec!["mysql5"]);
        assert!(!md5_like.kdf);
        let sha1 = detect_target("a9993e364706816aba3e25717850c26c9cd0d89d").unwrap();
        assert_eq!(sha1.algorithms, vec!["sha1"]);
        let sha256 = detect_target(&"a".repeat(64)).unwrap();
        assert_eq!(sha256.algorithms, vec!["sha256", "sha3_256"]);
        let sha512 = detect_target(&"b".repeat(128)).unwrap();
        assert_eq!(sha512.algorithms, vec!["sha512"]);
    }

    #[test]
    fn kdf_hashes_route_to_cpu_kdf_detection() {
        let detection =
            detect_target("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy").unwrap();
        assert!(detection.kdf);
        assert_eq!(detection.algorithms, vec!["bcrypt"]);
        let yes = detect_target(
            "$y$j9T$T34kP0d0sF1IBASj4klp/1$CsTfhJK8YT9fXGSbIf3jFaDffkRq0VXfGbGj68cG0R9",
        )
        .unwrap();
        assert!(yes.kdf);
        assert_eq!(yes.algorithms, vec!["yescrypt"]);
    }

    #[test]
    fn rejects_non_digest_non_kdf_targets() {
        assert!(detect_target("hello world").is_err());
        assert!(detect_target("").is_err());
        assert!(detect_target("zzzz").is_err());
        assert!(detect_target(&"a".repeat(30)).is_err());
    }

    #[test]
    fn plan_prefers_largest_wordlist_and_escalates_rules() {
        let detection = detect_target("9a0364b9e99bb480dd25e1f0284c8555").unwrap();
        let plan = build_plan(
            &detection,
            &wordlists(&["seclists-top-100000", "rockyou", "cyberdeck-common"]),
            &rules(&["best66", "rockyou-30000"]),
            &vec!["md5".to_string(), "ntlm".to_string(), "lm".to_string()],
        )
        .unwrap();
        assert_eq!(plan.stages.len(), 6);
        assert_eq!(plan.stages[0].wordlist_id, "rockyou");
        assert_eq!(plan.stages[0].algorithm, "md5");
        assert_eq!(plan.stages[0].engine, StageEngine::Gpu);
        assert_eq!(plan.stages[1].algorithm, "ntlm");
        assert_eq!(plan.stages[1].engine, StageEngine::Gpu);
        assert_eq!(plan.stages[1].rules_set, None);
        // KAT-verified primaries send rule stages through the GPU
        // rules-expansion route; the mask fallback stays CPU.
        assert_eq!(plan.stages[3].engine, StageEngine::Gpu);
        assert!(plan.stages[3].label.contains("(GPU · rules-expanded)"));
        assert_eq!(plan.stages[5].engine, StageEngine::Cpu);
        assert_eq!(plan.stages[2].algorithm, "lm");
        assert_eq!(plan.stages[3].rules_set.as_deref(), Some("best66"));
        assert_eq!(plan.stages[3].algorithm, "md5");
        assert_eq!(plan.stages[4].rules_set.as_deref(), Some("rockyou-30000"));
        assert_eq!(plan.stages[4].wordlist_id, "rockyou");
        assert_eq!(plan.stages[5].mask.as_deref(), Some("?d?d?d?d"));
        assert_eq!(plan.stages[5].algorithm, "md5");
    }

    #[test]
    fn kdf_plan_never_receives_rule_stages() {
        let detection =
            detect_target("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy").unwrap();
        let plan = build_plan(
            &detection,
            &wordlists(&["rockyou", "cyberdeck-common"]),
            &rules(&["best66"]),
            &[],
        )
        .unwrap();
        assert_eq!(plan.stages.len(), 1);
        assert_eq!(plan.stages[0].rules_set, None);
        assert_eq!(plan.stages[0].algorithm, "bcrypt");
    }

    #[test]
    fn plan_falls_back_to_builtin_wordlist_and_skips_missing_rules() {
        let detection = detect_target("a9993e364706816aba3e25717850c26c9cd0d89d").unwrap();
        let plan = build_plan(&detection, &wordlists(&["cyberdeck-common"]), &[], &[]).unwrap();
        // wordlist-only stage plus the bounded mask fallback
        assert_eq!(plan.stages.len(), 2);
        assert_eq!(plan.stages[0].wordlist_id, "cyberdeck-common");
        assert_eq!(plan.stages[0].rules_set, None);
        assert_eq!(plan.stages[1].mask.as_deref(), Some("?d?d?d?d"));
    }

    #[test]
    fn rules_stages_stay_cpu_without_kat_verified_modes() {
        let detection = detect_target("9a0364b9e99bb480dd25e1f0284c8555").unwrap();
        let plan = build_plan(
            &detection,
            &wordlists(&["rockyou"]),
            &rules(&["best66"]),
            &[], // no mode passed its known-answer test on this machine
        )
        .unwrap();
        assert_eq!(plan.stages[0].engine, StageEngine::Cpu);
        assert_eq!(plan.stages[3].rules_set.as_deref(), Some("best66"));
        assert_eq!(plan.stages[3].engine, StageEngine::Cpu);
        assert!(plan.stages[3].label.ends_with("(CPU)"));
    }

    #[test]
    fn plan_requires_at_least_one_wordlist() {
        let detection = detect_target("a9993e364706816aba3e25717850c26c9cd0d89d").unwrap();
        let error = build_plan(&detection, &[], &rules(&["best66"]), &[]).unwrap_err();
        assert!(error.contains("no wordlist"));
    }
}
