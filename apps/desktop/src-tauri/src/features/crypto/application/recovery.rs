//! Bounded native CPU wordlist recovery use case, independent of Tauri and persistence.
use std::io::BufRead;

use cyberdeck_crypto::recovery::{
    recover_wordlist_with_progress, RecoveryLimits, RecoveryTarget, MAX_FAST_CANDIDATES,
    MAX_KDF_CANDIDATES, MAX_MATCHES,
};

use super::domain::{CrackMatch, CrackProgress};

pub struct RecoveryOutcome {
    pub format: String,
    pub tried: u64,
    pub matches: Vec<CrackMatch>,
}

/// Emits progress based on completed checks, not speculative worker chunk offsets.
/// `total` is the physical wordlist line count, kept for the existing IPC contract.
pub fn execute<R, F>(
    reader: R,
    algorithm: &str,
    target_hash: &str,
    total: u64,
    mut progress: F,
) -> Result<RecoveryOutcome, String>
where
    R: BufRead,
    F: FnMut(CrackProgress),
{
    let target = RecoveryTarget::parse(algorithm, target_hash)?;
    let kdf = target.is_kdf();
    let cap = if kdf {
        MAX_KDF_CANDIDATES
    } else {
        MAX_FAST_CANDIDATES
    };
    let result = recover_wordlist_with_progress(
        &target,
        reader,
        RecoveryLimits {
            max_candidates: cap,
            max_matches: if kdf { 1 } else { MAX_MATCHES },
        },
        || false,
        |snapshot| {
            progress(CrackProgress {
                tried: snapshot.tried,
                total,
                percent: (snapshot.tried.saturating_mul(100) / total.max(1)).min(100) as u32,
            });
        },
    )?;
    let matches = result
        .hits
        .into_iter()
        .map(|hit| {
            Ok(CrackMatch {
                line_no: hit.index + 1,
                password: String::from_utf8(hit.candidate)
                    .map_err(|_| "matched candidate is not valid UTF-8")?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let format = if let Some(format) = cyberdeck_crypto::kdf_format(target_hash) {
        format.to_string()
    } else {
        algorithm.to_string()
    };
    Ok(RecoveryOutcome {
        format,
        tried: result.tried,
        matches,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn raw_recovery_preserves_line_number_and_progress() {
        let mut progress = Vec::new();
        let outcome = execute(
            Cursor::new(b"first\nhello\nlast\n".as_slice()),
            "md5",
            "5d41402abc4b2a76b9719d911017c592",
            3,
            |p| progress.push(p),
        )
        .unwrap();
        assert_eq!(outcome.format, "md5");
        assert_eq!(outcome.tried, 3);
        assert_eq!(outcome.matches.len(), 1);
        assert_eq!(outcome.matches[0].line_no, 2);
        assert_eq!(outcome.matches[0].password, "hello");
        assert_eq!(progress.last().unwrap().tried, outcome.tried);
        assert!(progress.windows(2).all(|p| p[0].tried <= p[1].tried));
    }

    #[test]
    fn invalid_digest_is_rejected_before_reading_candidates() {
        let error = execute(Cursor::new(Vec::<u8>::new()), "sha256", "xyz", 0, |_| {})
            .err()
            .unwrap();
        assert!(error.contains("digest"));
    }
}
