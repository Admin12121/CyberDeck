//! Trusted Rust-only, path-free, backend case-authorized evidence handoff.
//! Never expose raw evidence or an authorization boolean through Tauri IPC.
use crate::features::forensics::ipc::evidence::EvidenceCtx;
use crate::features::shared::session::CaseSessionCtx;
use cyberdeck_storage::{ArtifactRecord, DEFAULT_CASE};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceConsumer {
    PacketAnalysis,
    ForensicsInspect,
    CryptoRecipe,
}

/// A consumer callback must be side-effect-free until the final session
/// generation check. Durable results need a distinct authorized publication
/// transaction. The original is pinned, hashed and read through one handle.
pub fn with_verified_artifact<T>(
    ctx: &EvidenceCtx,
    session: &CaseSessionCtx,
    artifact_id: &str,
    consumer: EvidenceConsumer,
    use_bytes: impl FnOnce(&ArtifactRecord, &[u8]) -> Result<T, String>,
) -> Result<T, String> {
    let scope = session.selected()?;
    let case = scope
        .case_id
        .as_deref()
        .ok_or("no saved investigation selected")?;
    if case == DEFAULT_CASE {
        return Err("temporary workspace is not persisted evidence".into());
    }
    let record = ctx
        .store
        .lock()
        .map_err(|_| "case store unavailable")?
        .get_artifact(artifact_id)?
        .filter(|record| record.case_id == case)
        .ok_or("artifact does not belong to current case")?;
    let limit: usize = match consumer {
        EvidenceConsumer::PacketAnalysis
            if record.signature.as_deref() == Some("Original Ethernet PCAP") =>
        {
            16 * 1024 * 1024
        }
        EvidenceConsumer::ForensicsInspect => 8 * 1024 * 1024,
        EvidenceConsumer::CryptoRecipe
            if record.signature.as_deref() == Some("Volatile verified output") =>
        {
            1024 * 1024
        }
        _ => return Err("artifact type is not supported by this verified consumer".into()),
    };
    if record.size == 0 || record.size > limit as u64 {
        return Err("verified artifact exceeds consumer size/eligibility limit".into());
    }
    let mut file = cyberdeck_storage::open_verified_case_artifact(&record, &ctx.artifacts_dir)?;
    let data = file.read_window(0, record.size as usize, limit)?;
    session.ensure(&scope)?;
    let outcome = use_bytes(&record, &data)?;
    session.ensure(&scope)?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cyberdeck_storage::{ArtifactStore, PromotionDestination, TemporaryEvidence};
    use std::sync::Mutex;

    #[cfg(unix)]
    #[test]
    fn verified_digest_handoff_reads_same_case_and_rejects_incompatible_consumers() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("artifacts");
        let store = ArtifactStore::open(&tmp.path().join("db.sqlite")).unwrap();
        let case = store.create_case("Case", "").unwrap();
        let other = store.create_case("Other", "").unwrap();
        let source = TemporaryEvidence {
            name: "digest.txt",
            bytes: b"SHA-256: abcdef123456\n",
            source: "temporary.sha256",
        };
        let promoted = store
            .promote_temporary_evidence(&root, PromotionDestination::Existing(&case.id), &[source])
            .unwrap();
        let artifact = promoted.artifacts[0].id.clone();
        let ctx = EvidenceCtx {
            store: Mutex::new(store),
            artifacts_dir: root,
        };
        let selection = CaseSessionCtx::default();
        selection
            .select(&ctx.store.lock().unwrap(), &case.id)
            .unwrap();
        let data = with_verified_artifact(
            &ctx,
            &selection,
            &artifact,
            EvidenceConsumer::CryptoRecipe,
            |_, data| Ok(data.to_vec()),
        )
        .unwrap();
        assert_eq!(data, b"SHA-256: abcdef123456\n");
        assert!(with_verified_artifact(
            &ctx,
            &selection,
            &artifact,
            EvidenceConsumer::PacketAnalysis,
            |_, _| Ok(())
        )
        .is_err());
        selection
            .select(&ctx.store.lock().unwrap(), &other.id)
            .unwrap();
        assert!(with_verified_artifact(
            &ctx,
            &selection,
            &artifact,
            EvidenceConsumer::CryptoRecipe,
            |_, _| Ok(())
        )
        .is_err());
    }

    #[test]
    fn unselected_and_cross_case_refs_are_not_bearer_authorization() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("artifacts");
        let store = ArtifactStore::open(&root.path().join("db.sqlite")).unwrap();
        let a = store.create_case("A", "").unwrap();
        let b = store.create_case("B", "").unwrap();
        let ctx = EvidenceCtx {
            store: Mutex::new(store),
            artifacts_dir: dir,
        };
        let session = CaseSessionCtx::default();
        assert!(with_verified_artifact(
            &ctx,
            &session,
            "wrong",
            EvidenceConsumer::ForensicsInspect,
            |_, _| Ok(())
        )
        .is_err());
        session.select(&ctx.store.lock().unwrap(), &a.id).unwrap();
        assert!(with_verified_artifact(
            &ctx,
            &session,
            "not-owned",
            EvidenceConsumer::ForensicsInspect,
            |_, _| Ok(())
        )
        .is_err());
        session.select(&ctx.store.lock().unwrap(), &b.id).unwrap();
        assert!(with_verified_artifact(
            &ctx,
            &session,
            "wrong",
            EvidenceConsumer::PacketAnalysis,
            |_, _| Ok(())
        )
        .is_err());
    }
}
