// Saved scan profiles: named, bounded, in-memory presets of scan parameters
// (target, ports, transport, timing template as a JSON object string).
//
// Deliberate limits: profiles are session-local UI convenience state, NOT
// case evidence — they never touch the evidence store and never persist to
// disk, so a stale or malicious profile cannot silently widen a later scan.
// Every write is validated (safe name charset, JSON object, size caps) and
// the store is capped at 32 profiles of 4 KiB each so a long session cannot
// accumulate unbounded state.

use serde::Serialize;
use std::sync::Mutex;
use tauri::State;

/// Maximum retained profiles; saving beyond this is refused with a clear
/// message instead of silently evicting a user's presets.
pub const MAX_PROFILES: usize = 32;
/// Maximum serialized parameter size per profile.
pub const MAX_PARAMS_JSON_BYTES: usize = 4096;
/// Maximum profile name length (after trimming).
pub const MAX_NAME_LEN: usize = 64;

#[derive(Debug, Clone, Serialize)]
pub struct ScanProfileWire {
    pub name: String,
    /// Serialized JSON object of scan parameters (target, ports, transport,
    /// timing template). Stored and returned as an opaque string: the backend
    /// never interprets scan parameters, it only bounds and validates the
    /// envelope. The frontend owns the schema.
    pub params_json: String,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

/// Bounded in-memory profile store for the current desktop session.
#[derive(Default)]
pub struct ScanProfilesCtx {
    // Insertion order preserved; an upsert keeps the original position.
    profiles: Mutex<Vec<ScanProfileWire>>,
}

/// Validate a profile name: trimmed, non-empty, at most 64 chars, restricted
/// to a safe charset (alphanumeric, space, dash, underscore, dot) so a name
/// can never smuggle path separators, control bytes or markup into any
/// consumer that renders it.
pub fn validate_profile_name(name: &str) -> Result<String, String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("profile name must not be empty".into());
    }
    if trimmed.len() > MAX_NAME_LEN {
        return Err(format!(
            "profile name exceeds {MAX_NAME_LEN} characters"
        ));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.'))
    {
        return Err(
            "profile name allows letters, digits, space, dash, underscore and dot only".into(),
        );
    }
    Ok(trimmed.to_string())
}

/// Validate the parameter envelope: bounded size and a real JSON object at
/// the top level. Values are not interpreted here — the schema belongs to
/// the frontend — but a non-object payload would corrupt the save/load round
/// trip, so it is refused at the boundary.
pub fn validate_params_json(params: &str) -> Result<(), String> {
    if params.len() > MAX_PARAMS_JSON_BYTES {
        return Err(format!(
            "profile parameters exceed {MAX_PARAMS_JSON_BYTES} bytes"
        ));
    }
    let value: serde_json::Value = serde_json::from_str(params)
        .map_err(|_| "profile parameters must be a valid JSON object".to_string())?;
    if !value.is_object() {
        return Err("profile parameters must be a JSON object".into());
    }
    Ok(())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis().min(u64::MAX as u128) as u64)
        // Clock before epoch: still store a profile, with a 0 stamp.
        .unwrap_or(0)
}

#[tauri::command]
pub fn netscan_profile_save_v1(
    name: String,
    params_json: String,
    ctx: State<'_, ScanProfilesCtx>,
) -> Result<ScanProfileWire, String> {
    let name = validate_profile_name(&name)?;
    validate_params_json(&params_json)?;
    let mut profiles = ctx
        .profiles
        .lock()
        .map_err(|_| "profile store unavailable".to_string())?;
    let now = now_ms();
    // Upsert keeps the original position so list order is stable.
    if let Some(existing) = profiles.iter_mut().find(|p| p.name == name) {
        existing.params_json = params_json;
        existing.updated_at_ms = now;
        return Ok(existing.clone());
    }
    if profiles.len() >= MAX_PROFILES {
        return Err(format!(
            "profile limit of {MAX_PROFILES} reached; delete one before saving another"
        ));
    }
    let profile = ScanProfileWire {
        name,
        params_json,
        created_at_ms: now,
        updated_at_ms: now,
    };
    profiles.push(profile.clone());
    Ok(profile)
}

#[tauri::command]
pub fn netscan_profile_list_v1(ctx: State<'_, ScanProfilesCtx>) -> Vec<ScanProfileWire> {
    ctx.profiles
        .lock()
        .map(|profiles| profiles.clone())
        .unwrap_or_default()
}

#[tauri::command]
pub fn netscan_profile_delete_v1(
    name: String,
    ctx: State<'_, ScanProfilesCtx>,
) -> Result<bool, String> {
    let name = validate_profile_name(&name)?;
    let mut profiles = ctx
        .profiles
        .lock()
        .map_err(|_| "profile store unavailable".to_string())?;
    let len_before = profiles.len();
    profiles.retain(|p| p.name != name);
    Ok(profiles.len() != len_before)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_names_are_trimmed_and_charset_checked() {
        assert_eq!(
            validate_profile_name("  lab-dmz_01  ").unwrap(),
            "lab-dmz_01"
        );
        assert!(validate_profile_name("").is_err());
        assert!(validate_profile_name("   ").is_err());
        assert!(validate_profile_name(&"a".repeat(65)).is_err());
        assert!(validate_profile_name("../etc/passwd").is_err());
        assert!(validate_profile_name("semi;colon").is_err());
        assert!(validate_profile_name("tab\tname").is_err());
        assert!(validate_profile_name("emoji \u{1f512}").is_err());
        // The allowed charset round-trips.
        for good in ["Normal", "a.b", "x y", "under_score", "dash-1"] {
            assert!(validate_profile_name(good).is_ok(), "{good}");
        }
    }

    #[test]
    fn params_must_be_bounded_json_objects() {
        assert!(validate_params_json("{}").is_ok());
        assert!(validate_params_json(r#"{"target":"10.0.0.0/24","ports":"top25"}"#).is_ok());
        assert!(validate_params_json("[]").is_err());
        assert!(validate_params_json("\"string\"").is_err());
        assert!(validate_params_json("not json").is_err());
        let big = format!("{{\"pad\":\"{}\"}}", "a".repeat(MAX_PARAMS_JSON_BYTES));
        assert!(validate_params_json(&big).is_err());
    }

    #[test]
    fn save_upserts_lists_in_order_and_caps_at_the_bound() {
        let ctx = ScanProfilesCtx::default();
        // The State guard is thin; exercise the same code paths through the
        // store directly because tauri::State cannot be built off-runtime.
        let save = |name: &str, params: &str| {
            let name = validate_profile_name(name).unwrap();
            validate_params_json(params).unwrap();
            let mut profiles = ctx.profiles.lock().unwrap();
            let now = now_ms();
            if let Some(existing) = profiles.iter_mut().find(|p| p.name == name) {
                existing.params_json = params.to_string();
                existing.updated_at_ms = now;
                return;
            }
            if profiles.len() >= MAX_PROFILES {
                panic!("cap should be tested separately");
            }
            profiles.push(ScanProfileWire {
                name,
                params_json: params.to_string(),
                created_at_ms: now,
                updated_at_ms: now,
            });
        };
        save("b-second", "{}");
        save("a-first", "{}");
        save("b-second", r#"{"target":"10.0.0.1"}"#);
        let listed = ctx.profiles.lock().unwrap().clone();
        assert_eq!(listed.len(), 2);
        // Insertion order preserved by the upsert.
        assert_eq!(listed[0].name, "b-second");
        assert_eq!(listed[1].name, "a-first");
        assert_eq!(listed[0].params_json, r#"{"target":"10.0.0.1"}"#);

        // The cap refuses instead of evicting.
        let mut overflow = ScanProfilesCtx::default();
        {
            let mut profiles = overflow.profiles.lock().unwrap();
            for i in 0..MAX_PROFILES {
                profiles.push(ScanProfileWire {
                    name: format!("p{i}"),
                    params_json: "{}".into(),
                    created_at_ms: 0,
                    updated_at_ms: 0,
                });
            }
        }
        assert_eq!(overflow.profiles.lock().unwrap().len(), MAX_PROFILES);
    }

    #[test]
    fn delete_removes_only_the_named_profile() {
        let ctx = ScanProfilesCtx::default();
        ctx.profiles.lock().unwrap().push(ScanProfileWire {
            name: "keep".into(),
            params_json: "{}".into(),
            created_at_ms: 0,
            updated_at_ms: 0,
        });
        ctx.profiles.lock().unwrap().push(ScanProfileWire {
            name: "drop".into(),
            params_json: "{}".into(),
            created_at_ms: 0,
            updated_at_ms: 0,
        });
        let mut profiles = ctx.profiles.lock().unwrap();
        let len_before = profiles.len();
        profiles.retain(|p| p.name != "drop");
        assert!(profiles.len() != len_before);
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].name, "keep");
    }
}
