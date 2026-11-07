//! Backend-held, transient recovered-secret access policy.
//! The Tauri integrator MUST derive VerifiedScope from authenticated server-side
//! active case/session state, never from client-provided case IDs or booleans.
use super::RecoveryRun;
use std::collections::HashMap;
use std::time::{Duration, Instant};

pub const MAX_RETAINED_RECOVERY_JOBS: usize = 4;
pub const MAX_RECOVERY_SECRET_TTL: Duration = Duration::from_secs(300);

/// Not deserializable from IPC. Created only by the trusted backend controller.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedScope {
    session: String,
    case_id: String,
    revision: u64,
}

impl VerifiedScope {
    pub(crate) fn from_backend(
        session: &str,
        active_case: &str,
        revision: u64,
    ) -> Result<Self, String> {
        if session.is_empty() || active_case.is_empty() || revision == 0 {
            return Err("a verified session, active case and revision are required".into());
        }
        Ok(Self {
            session: session.to_owned(),
            case_id: active_case.to_owned(),
            revision,
        })
    }

    /// Authoritative case id for case-scoped persistence written by this scope.
    pub(crate) fn case_id(&self) -> &str {
        &self.case_id
    }
}

/// Temporary copy of a revealed candidate. No Serialize, Debug or Clone.
/// Drop uses best-effort overwriting; Rust cannot promise physical erasure.
pub struct SecretBuffer(Vec<u8>);
impl SecretBuffer {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl Drop for SecretBuffer {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

struct HeldResult {
    owner: VerifiedScope,
    run: RecoveryRun,
    expires: Instant,
    consent: bool,
}

/// Memory-only result gate. Agent 6 owns the separate async job registry,
/// Tauri IPC, and authoritative case/session/consent lifecycle.
#[derive(Default)]
pub struct RecoveryResultAccess {
    active: Option<VerifiedScope>,
    results: HashMap<u64, HeldResult>,
}

impl RecoveryResultAccess {
    pub fn new() -> Self {
        Self::default()
    }

    /// Revoke all retained results on any session, case or generation change.
    /// The caller must also cancel active unfinished work in its job registry.
    pub fn set_active(&mut self, verified: VerifiedScope) {
        if self.active.as_ref() != Some(&verified) {
            self.results.clear();
            self.active = Some(verified);
        }
    }

    pub fn revoke_all(&mut self) {
        self.results.clear();
        self.active = None;
    }

    fn is_active(&self, verified: &VerifiedScope) -> bool {
        self.active.as_ref() == Some(verified)
    }

    /// Remove every expired result and release its confidential buffers now.
    /// Call from the desktop job lifecycle even when no new requests arrive.
    /// Returns the number of expired entries removed.
    pub fn prune_expired(&mut self) -> usize {
        let now = Instant::now();
        let before = self.results.len();
        self.results.retain(|_, item| now < item.expires);
        before - self.results.len()
    }

    pub fn retain(
        &mut self,
        job_id: u64,
        verified: &VerifiedScope,
        run: RecoveryRun,
        ttl: Duration,
    ) -> Result<(), String> {
        if !self.is_active(verified) {
            return Err("recovery result session/case is no longer active".into());
        }
        self.prune_expired();
        if job_id == 0 || self.results.contains_key(&job_id) {
            return Err("invalid or duplicate recovery job identifier".into());
        }
        if self.results.len() >= MAX_RETAINED_RECOVERY_JOBS {
            return Err("too many retained recovery results".into());
        }
        if ttl.is_zero() || ttl > MAX_RECOVERY_SECRET_TTL {
            return Err("recovered-secret retention TTL exceeds policy".into());
        }
        if run.summary.cancelled {
            return Err("cancelled recovery jobs must not retain recovered candidates".into());
        }
        let expires = Instant::now()
            .checked_add(ttl)
            .ok_or("invalid recovered-secret expiry")?;
        self.results.insert(
            job_id,
            HeldResult {
                owner: verified.clone(),
                run,
                expires,
                consent: false,
            },
        );
        Ok(())
    }

    /// Called ONLY after the IPC layer authorizes an explicit reveal action
    /// against the server-held active session/job/case identity.
    pub fn authorize_reveal(
        &mut self,
        job_id: u64,
        verified: &VerifiedScope,
    ) -> Result<(), String> {
        if !self.is_active(verified) {
            return Err("active recovery session changed".into());
        }
        self.prune_expired();
        let result = self
            .results
            .get_mut(&job_id)
            .ok_or("unknown recovery job")?;
        if &result.owner != verified || Instant::now() >= result.expires {
            return Err("recovery grant expired or belongs to another session".into());
        }
        result.consent = true;
        Ok(())
    }

    /// No client-provided "authorized" boolean accepted.
    pub fn reveal(
        &mut self,
        job_id: u64,
        ordinal: usize,
        verified: &VerifiedScope,
    ) -> Option<SecretBuffer> {
        if !self.is_active(verified) {
            return None;
        }
        self.prune_expired();
        let item = self.results.get(&job_id)?;
        if &item.owner != verified || !item.consent {
            return None;
        }
        item.run
            .confidential_hits
            .get(ordinal)
            .map(|bytes| SecretBuffer(bytes.clone()))
    }

    pub fn discard(&mut self, job_id: u64, verified: &VerifiedScope) -> bool {
        if !self.is_active(verified) {
            return false;
        }
        self.prune_expired();
        if self
            .results
            .get(&job_id)
            .is_some_and(|x| &x.owner == verified)
        {
            self.results.remove(&job_id);
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::super::{execute_reader, BackendSelection, RecoveryCancel, RecoveryRequest};
    use super::*;
    use std::io::Cursor;

    fn scope(session: &str, case_id: &str, revision: u64) -> VerifiedScope {
        VerifiedScope::from_backend(session, case_id, revision).unwrap()
    }
    fn completed() -> RecoveryRun {
        execute_reader(
            &RecoveryRequest {
                algorithm: "sha256".into(),
                target_hash: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                    .into(),
                backend: BackendSelection::Cpu,
                max_candidates: 3,
                max_matches: 1,
                target_hashes: Vec::new(),
            },
            Cursor::new(b"bad\nabc\n"),
            &RecoveryCancel::new(),
            |_| {},
        )
        .unwrap()
    }

    #[test]
    fn reveal_requires_backend_consent_and_correct_active_scope() {
        let mut gate = RecoveryResultAccess::new();
        let owner = scope("session-one", "case-a", 1);
        let foreign = scope("session-two", "case-a", 1);
        gate.set_active(owner.clone());
        gate.retain(1, &owner, completed(), Duration::from_secs(30))
            .unwrap();
        assert!(gate.reveal(1, 0, &owner).is_none());
        assert!(gate.authorize_reveal(1, &foreign).is_err());
        gate.authorize_reveal(1, &owner).unwrap();
        assert!(gate.reveal(1, 0, &foreign).is_none());
        assert_eq!(gate.reveal(1, 0, &owner).unwrap().as_bytes(), b"abc");
    }

    #[test]
    fn case_switch_and_generation_change_revoke_secret_and_consent() {
        let mut gate = RecoveryResultAccess::new();
        let old = scope("session", "case-a", 1);
        gate.set_active(old.clone());
        gate.retain(10, &old, completed(), Duration::from_secs(30))
            .unwrap();
        gate.authorize_reveal(10, &old).unwrap();
        gate.set_active(scope("session", "case-b", 2));
        assert!(gate.reveal(10, 0, &old).is_none());
        let current = scope("session", "case-b", 2);
        assert!(gate.authorize_reveal(10, &current).is_err());
        gate.retain(11, &current, completed(), Duration::from_secs(30))
            .unwrap();
        gate.set_active(scope("session", "case-b", 3));
        assert!(gate.reveal(11, 0, &current).is_none());
    }

    #[test]
    fn concurrent_job_results_are_isolated_and_bounded() {
        let mut gate = RecoveryResultAccess::new();
        let owner = scope("session", "case", 1);
        gate.set_active(owner.clone());
        for id in 1..=MAX_RETAINED_RECOVERY_JOBS {
            gate.retain(id as u64, &owner, completed(), Duration::from_secs(30))
                .unwrap();
        }
        assert!(gate
            .retain(99, &owner, completed(), Duration::from_secs(30))
            .is_err());
        gate.authorize_reveal(2, &owner).unwrap();
        assert!(gate.reveal(1, 0, &owner).is_none());
        assert_eq!(gate.reveal(2, 0, &owner).unwrap().as_bytes(), b"abc");
        assert!(gate.discard(2, &owner));
        assert!(gate.reveal(2, 0, &owner).is_none());
        assert!(gate
            .retain(99, &owner, completed(), Duration::from_secs(30))
            .is_ok());
    }

    #[test]
    fn expired_explicit_consent_cannot_reveal_candidate() {
        let mut gate = RecoveryResultAccess::new();
        let owner = scope("session", "case", 1);
        gate.set_active(owner.clone());
        gate.retain(1, &owner, completed(), Duration::from_millis(1))
            .unwrap();
        gate.authorize_reveal(1, &owner).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        assert!(gate.reveal(1, 0, &owner).is_none());
        assert!(gate.authorize_reveal(1, &owner).is_err());
    }

    #[test]
    fn expired_four_job_capacity_is_recovered_on_next_retention() {
        let mut gate = RecoveryResultAccess::new();
        let owner = scope("owner", "case", 1);
        gate.set_active(owner.clone());
        for id in 1..=MAX_RETAINED_RECOVERY_JOBS {
            gate.retain(id as u64, &owner, completed(), Duration::from_millis(1))
                .unwrap();
        }
        std::thread::sleep(Duration::from_millis(10));
        gate.retain(5, &owner, completed(), Duration::from_secs(30))
            .unwrap();
        assert_eq!(gate.results.len(), 1);
        assert!(!gate.results.contains_key(&1));
        assert!(gate.reveal(1, 0, &owner).is_none());
        assert!(gate.authorize_reveal(1, &owner).is_err());
        gate.authorize_reveal(5, &owner).unwrap();
        assert_eq!(gate.reveal(5, 0, &owner).unwrap().as_bytes(), b"abc");
    }

    #[test]
    fn explicit_prune_releases_expired_results_even_without_reveal() {
        let mut gate = RecoveryResultAccess::new();
        let owner = scope("owner", "case", 1);
        gate.set_active(owner.clone());
        gate.retain(12, &owner, completed(), Duration::from_millis(1))
            .unwrap();
        gate.authorize_reveal(12, &owner).unwrap();
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(gate.prune_expired(), 1);
        assert!(gate.results.is_empty());
        assert_eq!(gate.prune_expired(), 0);
        assert!(gate.reveal(12, 0, &owner).is_none());
        let other = scope("owner", "other-case", 2);
        gate.set_active(other.clone());
        assert!(gate.reveal(12, 0, &other).is_none());
    }

    #[test]
    fn expired_entries_cannot_block_concurrent_session_replacement() {
        let mut gate = RecoveryResultAccess::new();
        let owner = scope("owner", "case-a", 1);
        gate.set_active(owner.clone());
        gate.retain(33, &owner, completed(), Duration::from_millis(1))
            .unwrap();
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(gate.prune_expired(), 1);
        let replacement = scope("other-session", "case-b", 2);
        gate.set_active(replacement.clone());
        gate.retain(33, &replacement, completed(), Duration::from_secs(30))
            .unwrap();
        assert!(gate.authorize_reveal(33, &owner).is_err());
        assert!(gate.reveal(33, 0, &replacement).is_none());
        gate.revoke_all();
        assert!(gate.reveal(33, 0, &replacement).is_none());
    }

    #[test]
    fn bad_scope_ttl_and_discard_are_fail_closed() {
        let mut gate = RecoveryResultAccess::new();
        assert!(VerifiedScope::from_backend("", "case", 1).is_err());
        let owner = scope("s", "case", 1);
        gate.set_active(owner.clone());
        assert!(gate.retain(1, &owner, completed(), Duration::ZERO).is_err());
        assert!(gate
            .retain(
                1,
                &owner,
                completed(),
                MAX_RECOVERY_SECRET_TTL + Duration::from_secs(1)
            )
            .is_err());
        gate.retain(1, &owner, completed(), Duration::from_secs(1))
            .unwrap();
        gate.revoke_all();
        assert!(gate.reveal(1, 0, &owner).is_none());
    }
}
