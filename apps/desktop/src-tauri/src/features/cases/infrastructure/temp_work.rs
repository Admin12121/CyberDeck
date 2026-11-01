//! Backend-owned, volatile, nonsecret Quick Tools outputs. No SQLite writes.
use cyberdeck_storage::{TemporaryEvidence, TEMP_MAX_ARTIFACTS, TEMP_MAX_TOTAL_BYTES};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

const TTL: Duration = Duration::from_secs(15 * 60);

#[derive(Clone, Serialize)]
pub struct TempOutputView {
    pub id: u64,
    pub name: String,
    pub kind: &'static str,
    pub bytes: usize,
    pub revision: u64,
}
#[derive(Serialize)]
pub struct TempOverview {
    pub revision: u64,
    pub outputs: Vec<TempOutputView>,
    pub retention_seconds: u64,
    pub max_artifacts: usize,
}

struct Entry {
    id: u64,
    name: String,
    bytes: Vec<u8>,
    source: &'static str,
}

#[derive(Default)]
pub struct TempWork {
    revision: u64,
    expires: Option<Instant>,
    next_id: u64,
    outputs: Vec<Entry>,
}

impl TempWork {
    pub fn clear(&mut self) {
        for output in &mut self.outputs { output.bytes.fill(0); }
        self.outputs.clear();
        self.expires = None;
        self.revision = 0;
    }
    fn enforce(&mut self, revision: u64) {
        if self.revision != revision || self.expires.is_some_and(|t| t <= Instant::now()) {
            self.clear();
            self.revision = revision;
        }
    }
    pub fn stage_digest(&mut self, revision: u64, input: &str) -> Result<TempOutputView,String> {
        self.enforce(revision);
        if input.is_empty() || input.len() > 65536 {
            return Err("temporary digest input requires 1-65536 bytes".into());
        }
        if self.outputs.len() >= TEMP_MAX_ARTIFACTS {
            return Err("temporary artifact count limit exceeded".into());
        }
        // Store only the derived digest; original input is never staged.
        // Recovery results, secrets and key material have no producer API.
        let hex = format!("{:x}", Sha256::digest(input.as_bytes()));
        let bytes = format!("SHA-256: {hex}\n").into_bytes();
        if self.outputs.iter().any(|o| o.bytes == bytes) {
            return Err("digest already staged".into());
        }
        let total: usize = self.outputs.iter().map(|o| o.bytes.len()).sum();
        if total + bytes.len() > TEMP_MAX_TOTAL_BYTES {
            return Err("temporary output memory budget exceeded".into());
        }
        self.next_id = self.next_id.checked_add(1).ok_or("temporary ID exhausted")?;
        let result = TempOutputView {
            id: self.next_id, name: format!("sha256-{}.txt",&hex[..16]),
            kind: "sha256-digest", bytes: bytes.len(), revision,
        };
        self.outputs.push(Entry {id: result.id,name:result.name.clone(),
            bytes, source:"temporary.sha256"});
        if self.expires.is_none() { self.expires = Instant::now().checked_add(TTL); }
        Ok(result)
    }
    pub fn overview(&mut self, revision: u64) -> TempOverview {
        self.enforce(revision);
        TempOverview { revision, retention_seconds: TTL.as_secs(),
            max_artifacts: TEMP_MAX_ARTIFACTS,
            outputs: self.outputs.iter().map(|o| TempOutputView {
                id:o.id,name:o.name.clone(),kind:"sha256-digest",bytes:o.bytes.len(),revision
            }).collect() }
    }
    /// Keep staged output if the SQLite transaction or readback fails, so an
    /// operator may retry without silently losing their work.
    pub fn promote<T>(&mut self, revision:u64, f:impl FnOnce(&[TemporaryEvidence<'_>])->Result<T,String>)
        -> Result<T,String> {
        self.enforce(revision);
        if self.outputs.is_empty() { return Err("no eligible temporary output".into()); }
        let items:Vec<TemporaryEvidence<'_>> = self.outputs.iter().map(|o| TemporaryEvidence {
            name:&o.name, bytes:&o.bytes, source:o.source
        }).collect();
        let result = f(&items)?;
        self.clear();
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn digest_output_is_bounded_and_does_not_retain_source_plaintext() {
        let mut t=TempWork::default();
        let secret="not-stored-input";
        t.stage_digest(1,secret).unwrap();
        assert!(!t.outputs[0].bytes.windows(secret.len()).any(|w|w==secret.as_bytes()));
        assert!(t.stage_digest(1,secret).is_err());
        assert!(t.stage_digest(1,"").is_err());
        assert_eq!(t.overview(1).outputs.len(),1);
    }
    #[test]
    fn revision_expiry_and_error_invalidate_or_keep_only_as_authorized() {
        let mut t=TempWork::default();
        t.stage_digest(1,"hello").unwrap();
        assert!(t.promote(1,|_|Err::<(),_>("db failure".into())).is_err());
        assert_eq!(t.overview(1).outputs.len(),1);
        t.stage_digest(1,"second").unwrap();
        assert!(t.overview(2).outputs.is_empty());
        t.stage_digest(2,"other").unwrap();
        t.expires=Some(Instant::now()-Duration::from_millis(1));
        assert!(t.overview(2).outputs.is_empty());
        t.stage_digest(2,"safe").unwrap();
        assert_eq!(t.promote(2,|a|Ok(a.len())).unwrap(),1);
        assert!(t.overview(2).outputs.is_empty());
    }
}
