//! Backend-owned active-case consent for sensitive volatile HTTP capture.
//! This is a policy primitive, not an IPC command or a persisted setting.
use crate::{validate_case_id, ArtifactStore};
use std::time::{Duration, Instant};

/// Hard ceilings: callers can request stricter limits, never looser ones.
pub const MAX_CAPTURE_EVENTS: usize = 64;
pub const MAX_CAPTURE_TOTAL_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_CAPTURE_BODY_BYTES: usize = 64 * 1024;
pub const MAX_CAPTURE_DURATION: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryRetentionLimits {
    pub max_entries: usize,
    pub max_total_bytes: usize,
    pub max_body_bytes: usize,
    pub duration: Duration,
}

impl Default for HistoryRetentionLimits {
    fn default() -> Self {
        Self {
            max_entries: MAX_CAPTURE_EVENTS,
            max_total_bytes: MAX_CAPTURE_TOTAL_BYTES,
            max_body_bytes: MAX_CAPTURE_BODY_BYTES,
            duration: MAX_CAPTURE_DURATION,
        }
    }
}

impl HistoryRetentionLimits {
    pub fn validate(self) -> Result<Self, String> {
        if self.max_entries == 0
            || self.max_entries > MAX_CAPTURE_EVENTS
            || self.max_total_bytes == 0
            || self.max_total_bytes > MAX_CAPTURE_TOTAL_BYTES
            || self.max_body_bytes == 0
            || self.max_body_bytes > MAX_CAPTURE_BODY_BYTES
            || self.duration.is_zero()
            || self.duration > MAX_CAPTURE_DURATION
        {
            return Err("HTTP history retention exceeds backend safety limits".into());
        }
        Ok(self)
    }
}

/// A derived, non-secret capture stamp created by the backend when consent is
/// active. Stale in-flight captures must be rejected after switch/revocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryCaptureGrant {
    pub case_id: String,
    pub generation: u64,
    pub limits: HistoryRetentionLimits,
}

#[derive(Debug)]
struct ActiveConsent {
    expires_at: Instant,
    limits: HistoryRetentionLimits,
}

/// Must live in backend application state, protected by a mutex. Never trust a
/// caller-supplied case ID or opt-in boolean without comparison to this state.
#[derive(Debug, Default)]
pub struct ActiveCaseHistoryPolicy {
    active_case: Option<String>,
    generation: u64,
    consent: Option<ActiveConsent>,
}

impl ActiveCaseHistoryPolicy {
    /// The integration owner must invoke this when the server selects a case.
    /// Any switch (including switching to the same ID) drops existing consent.
    pub fn select_case(&mut self, store: &ArtifactStore, case_id: &str) -> Result<(), String> {
        validate_case_id(case_id)?;
        if !store.case_exists(case_id)? {
            return Err("selected case does not exist".into());
        }
        self.revoke();
        self.active_case = Some(case_id.to_owned());
        Ok(())
    }

    /// Called only after an explicit user consent event for the active case.
    pub fn enable_volatile_capture(
        &mut self,
        case_id: &str,
        limits: HistoryRetentionLimits,
    ) -> Result<HistoryCaptureGrant, String> {
        if self.active_case.as_deref() != Some(case_id) {
            return Err("sensitive history case is not active".into());
        }
        let limits = limits.validate()?;
        self.revoke();
        self.consent = Some(ActiveConsent {
            expires_at: Instant::now() + limits.duration,
            limits,
        });
        self.authorize_capture(case_id, self.generation)
    }

    /// The case and connection-generation must BOTH match backend-held state.
    pub fn authorize_capture(
        &self,
        case_id: &str,
        connection_generation: u64,
    ) -> Result<HistoryCaptureGrant, String> {
        self.authorize_capture_at(case_id, connection_generation, Instant::now())
    }

    fn authorize_capture_at(
        &self,
        case_id: &str,
        generation: u64,
        now: Instant,
    ) -> Result<HistoryCaptureGrant, String> {
        if self.active_case.as_deref() != Some(case_id) || self.generation != generation {
            return Err("HTTP history case or generation mismatch".into());
        }
        let consent = self.consent.as_ref().ok_or("HTTP capture is disabled")?;
        if now >= consent.expires_at {
            return Err("HTTP history consent has expired".into());
        }
        Ok(HistoryCaptureGrant {
            case_id: case_id.to_owned(),
            generation,
            limits: consent.limits,
        })
    }

    pub fn revoke(&mut self) {
        self.consent = None;
        self.generation = self.generation.wrapping_add(1);
    }

    /// Return the server-selected case, never a client-supplied alternative.
    pub fn active_case(&self) -> Option<&str> {
        self.active_case.as_deref()
    }

    pub fn current_generation(&self) -> u64 {
        self.generation
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_is_off_by_default_and_rejects_invented_cases() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&tmp.path().join("cases.db")).unwrap();
        let mut gate = ActiveCaseHistoryPolicy::default();
        assert!(gate
            .enable_volatile_capture("scratchpad", HistoryRetentionLimits::default())
            .is_err());
        assert!(gate.select_case(&store, "missing").is_err());
        gate.select_case(&store, "scratchpad").unwrap();
        assert!(gate
            .authorize_capture("scratchpad", gate.current_generation())
            .is_err());
    }

    #[test]
    fn case_switch_revoke_expiry_and_stale_connection_fail_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let store = ArtifactStore::open(&tmp.path().join("cases.db")).unwrap();
        store.create_case("Another", "").unwrap();
        let other = store
            .list_cases()
            .unwrap()
            .into_iter()
            .find(|c| c.id != "scratchpad")
            .unwrap();
        let mut gate = ActiveCaseHistoryPolicy::default();
        gate.select_case(&store, "scratchpad").unwrap();
        let stamp = gate
            .enable_volatile_capture("scratchpad", HistoryRetentionLimits::default())
            .unwrap();
        assert_eq!(stamp.case_id, "scratchpad");
        assert!(gate
            .authorize_capture("scratchpad", stamp.generation)
            .is_ok());
        assert!(gate.authorize_capture(&other.id, stamp.generation).is_err());
        assert!(gate
            .authorize_capture_at(
                "scratchpad",
                stamp.generation,
                Instant::now() + MAX_CAPTURE_DURATION
            )
            .is_err());
        gate.select_case(&store, &other.id).unwrap();
        assert!(gate
            .authorize_capture("scratchpad", stamp.generation)
            .is_err());
        assert!(gate
            .authorize_capture(&other.id, gate.current_generation())
            .is_err());
        gate.enable_volatile_capture(&other.id, HistoryRetentionLimits::default())
            .unwrap();
        gate.revoke();
        assert!(gate
            .authorize_capture(&other.id, gate.current_generation())
            .is_err());
    }

    #[test]
    fn cannot_increase_capture_retention_or_body_limits() {
        let too_big = HistoryRetentionLimits {
            max_total_bytes: MAX_CAPTURE_TOTAL_BYTES + 1,
            ..HistoryRetentionLimits::default()
        };
        assert!(too_big.validate().is_err());
        let excessive = HistoryRetentionLimits {
            duration: MAX_CAPTURE_DURATION + Duration::from_secs(1),
            ..HistoryRetentionLimits::default()
        };
        assert!(excessive.validate().is_err());
    }
}
