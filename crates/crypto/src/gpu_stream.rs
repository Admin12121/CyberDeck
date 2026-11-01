//! Bounded, cancellation-aware native GPU candidate-stream orchestration.
//! OpenCL device ownership and kernel execution remain in the GPU runtime.
use super::*;

pub const GPU_STREAM_BATCH: usize = 4096;
pub const MAX_GPU_STREAM_CANDIDATES: u64 = 10_000_000;
pub const MAX_GPU_STREAM_MATCHES: usize = 100;

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct GpuStreamHit {
    pub index: u64,
    pub candidate: Vec<u8>,
}
#[derive(Debug, Clone, serde::Serialize)]
pub struct GpuStreamResult {
    pub engine: &'static str,
    /// Number of candidates actually dispatched to the GPU and checked.
    pub tried: u64,
    pub batches: u64,
    pub hits: Vec<GpuStreamHit>,
    pub cancelled: bool,
    pub limit_reached: bool,
}
/// Lazy, bounded SHA-256 GPU candidate streaming with exact processed counts.
/// Does not silently switch to CPU when OpenCL fails.
pub fn recover_sha256_stream<I, B, F>(
    target_hex: &str,
    candidates: I,
    max_attempts: u64,
    max_matches: usize,
    cancel: F,
) -> Result<GpuStreamResult, String>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
    F: FnMut() -> bool,
{
    #[cfg(feature = "gpu")]
    {
        let mut session: Option<native::Session> = None;
        return stream_with(
            target_hex,
            candidates,
            max_attempts,
            max_matches,
            cancel,
            |hash, batch| {
                let target = hex::decode(hash).map_err(|_| "invalid SHA-256 target")?;
                if session.is_none() {
                    session = Some(native::Session::new(GPU_STREAM_BATCH)?);
                }
                session
                    .as_mut()
                    .expect("initialized GPU session")
                    .execute(&target, batch)
            },
        );
    }
    #[cfg(not(feature = "gpu"))]
    {
        stream_with(
            target_hex,
            candidates,
            max_attempts,
            max_matches,
            cancel,
            recover_sha256,
        )
    }
}

/// Run bounded MD5 GPU recovery using one native OpenCL session per stream.
pub fn recover_md5_stream<I, B, F>(
    target_hex: &str,
    candidates: I,
    max_attempts: u64,
    max_matches: usize,
    cancel: F,
) -> Result<GpuStreamResult, String>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
    F: FnMut() -> bool,
{
    #[cfg(feature = "gpu")]
    {
        let mut session: Option<native::Session> = None;
        return stream_with_checked(
            target_hex,
            candidates,
            max_attempts,
            max_matches,
            16,
            "cyberdeck-crypto-opencl-md5",
            cancel,
            |hash, batch| {
                let target = hex::decode(hash).map_err(|_| "invalid MD5 target")?;
                if session.is_none() {
                    session = Some(native::Session::new_for(
                        GPU_STREAM_BATCH,
                        native::Algorithm::Md5,
                    )?);
                }
                session
                    .as_mut()
                    .expect("MD5 session initialized")
                    .execute(&target, batch)
            },
        );
    }
    #[cfg(not(feature = "gpu"))]
    {
        stream_with_checked(
            target_hex,
            candidates,
            max_attempts,
            max_matches,
            16,
            "cyberdeck-crypto-opencl-md5",
            cancel,
            recover_md5,
        )
    }
}

/// Run bounded SHA-1 GPU recovery using one native OpenCL session per stream.
pub fn recover_sha1_stream<I, B, F>(
    target_hex: &str,
    candidates: I,
    max_attempts: u64,
    max_matches: usize,
    cancel: F,
) -> Result<GpuStreamResult, String>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
    F: FnMut() -> bool,
{
    #[cfg(feature = "gpu")]
    {
        let mut session: Option<native::Session> = None;
        return stream_with_checked(
            target_hex,
            candidates,
            max_attempts,
            max_matches,
            20,
            "cyberdeck-crypto-opencl-sha1",
            cancel,
            |hash, batch| {
                let target = hex::decode(hash).map_err(|_| "invalid SHA-1 target")?;
                if session.is_none() {
                    session = Some(native::Session::new_for(
                        GPU_STREAM_BATCH,
                        native::Algorithm::Sha1,
                    )?);
                }
                session
                    .as_mut()
                    .expect("SHA-1 session initialized")
                    .execute(&target, batch)
            },
        );
    }
    #[cfg(not(feature = "gpu"))]
    {
        stream_with_checked(
            target_hex,
            candidates,
            max_attempts,
            max_matches,
            20,
            "cyberdeck-crypto-opencl-sha1",
            cancel,
            recover_sha1,
        )
    }
}

/// Stream ASCII-only NTLM candidates through native OpenCL MD4.
pub fn recover_ntlm_stream<I, B, F>(
    target_hex: &str,
    candidates: I,
    max_attempts: u64,
    max_matches: usize,
    cancel: F,
) -> Result<GpuStreamResult, String>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
    F: FnMut() -> bool,
{
    recover_stream_on_device(
        GpuHash::Ntlm,
        0,
        target_hex,
        candidates,
        max_attempts,
        max_matches,
        cancel,
    )
}

pub(super) fn dispatch_batch<E>(
    target_hex: &str,
    batch: &mut Vec<Vec<u8>>,
    result: &mut GpuStreamResult,
    max_matches: usize,
    executor: &mut E,
) -> Result<(), String>
where
    E: FnMut(&str, &[&[u8]]) -> Result<Vec<usize>, String>,
{
    if batch.is_empty() {
        return Ok(());
    }
    let refs: Vec<&[u8]> = batch.iter().map(Vec::as_slice).collect();
    let mut hits = executor(target_hex, &refs)?;
    // Device implementations may return indices in a different order. Make
    // match ordering stable and avoid duplicate results from a faulty driver.
    hits.sort_unstable();
    hits.dedup();
    for index in hits {
        if index >= batch.len() {
            return Err("GPU returned an invalid match index".into());
        }
        if result.hits.len() < max_matches {
            result.hits.push(GpuStreamHit {
                index: result.tried + index as u64,
                candidate: batch[index].clone(),
            });
        }
    }
    result.tried += batch.len() as u64;
    result.batches += 1;
    batch.clear();
    Ok(())
}
pub(super) fn stream_with<I, B, F, E>(
    target_hex: &str,
    candidates: I,
    max_attempts: u64,
    max_matches: usize,
    cancel: F,
    executor: E,
) -> Result<GpuStreamResult, String>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
    F: FnMut() -> bool,
    E: FnMut(&str, &[&[u8]]) -> Result<Vec<usize>, String>,
{
    stream_with_checked(
        target_hex,
        candidates,
        max_attempts,
        max_matches,
        32,
        "cyberdeck-crypto-opencl-sha256",
        cancel,
        executor,
    )
}

pub(super) fn stream_with_checked<I, B, F, E>(
    target_hex: &str,
    candidates: I,
    max_attempts: u64,
    max_matches: usize,
    digest_bytes: usize,
    engine: &'static str,
    cancel: F,
    executor: E,
) -> Result<GpuStreamResult, String>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
    F: FnMut() -> bool,
    E: FnMut(&str, &[&[u8]]) -> Result<Vec<usize>, String>,
{
    stream_with_batch(
        target_hex,
        candidates,
        max_attempts,
        max_matches,
        GPU_STREAM_BATCH,
        digest_bytes,
        engine,
        cancel,
        executor,
    )
}

pub(super) fn stream_with_batch<I, B, F, E>(
    target_hex: &str,
    candidates: I,
    max_attempts: u64,
    max_matches: usize,
    batch_size: usize,
    digest_bytes: usize,
    engine: &'static str,
    cancel: F,
    executor: E,
) -> Result<GpuStreamResult, String>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
    F: FnMut() -> bool,
    E: FnMut(&str, &[&[u8]]) -> Result<Vec<usize>, String>,
{
    stream_with_batch_results(
        target_hex,
        candidates.into_iter().map(Ok::<B, String>),
        max_attempts,
        max_matches,
        batch_size,
        digest_bytes,
        engine,
        cancel,
        executor,
    )
}

/// Non-secret completed-batch progress; no password bytes or target hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct GpuStreamProgress {
    pub tried: u64,
    pub batches: u64,
    pub matches: usize,
}

pub(super) fn stream_with_batch_results<I, B, F, E>(
    target_hex: &str,
    candidates: I,
    max_attempts: u64,
    max_matches: usize,
    batch_size: usize,
    digest_bytes: usize,
    engine: &'static str,
    cancel: F,
    executor: E,
) -> Result<GpuStreamResult, String>
where
    I: IntoIterator<Item = Result<B, String>>,
    B: AsRef<[u8]>,
    F: FnMut() -> bool,
    E: FnMut(&str, &[&[u8]]) -> Result<Vec<usize>, String>,
{
    stream_with_batch_results_progress(
        target_hex,
        candidates,
        max_attempts,
        max_matches,
        batch_size,
        digest_bytes,
        engine,
        cancel,
        executor,
        |_| {},
    )
}

/// Reports only completed GPU batches, never queued candidates.
pub(super) fn stream_with_batch_results_progress<I, B, F, E, P>(
    target_hex: &str,
    candidates: I,
    max_attempts: u64,
    max_matches: usize,
    batch_size: usize,
    digest_bytes: usize,
    engine: &'static str,
    mut cancel: F,
    mut executor: E,
    mut on_progress: P,
) -> Result<GpuStreamResult, String>
where
    I: IntoIterator<Item = Result<B, String>>,
    B: AsRef<[u8]>,
    F: FnMut() -> bool,
    E: FnMut(&str, &[&[u8]]) -> Result<Vec<usize>, String>,
    P: FnMut(GpuStreamProgress),
{
    if hex::decode(target_hex)
        .map_err(|_| "invalid GPU digest")?
        .len()
        != digest_bytes
    {
        return Err("GPU digest has incorrect size".into());
    }
    if batch_size == 0 || batch_size > MAX_GPU_BATCH {
        return Err("GPU batch size must be 1..=65536".into());
    }
    if max_attempts == 0
        || max_attempts > MAX_GPU_STREAM_CANDIDATES
        || max_matches == 0
        || max_matches > MAX_GPU_STREAM_MATCHES
    {
        return Err("invalid streaming GPU limits".into());
    }
    let mut result = GpuStreamResult {
        engine,
        tried: 0,
        batches: 0,
        hits: Vec::new(),
        cancelled: false,
        limit_reached: false,
    };
    let mut batch: Vec<Vec<u8>> = Vec::with_capacity(batch_size);
    let mut generated = 0u64;
    let mut source = candidates.into_iter();
    loop {
        // Cancellation discards queued but undispatched candidates; 'tried'
        // only includes candidates actually checked on the GPU.
        if cancel() {
            result.cancelled = true;
            break;
        }
        if generated >= max_attempts {
            result.limit_reached = true;
            break;
        }
        let Some(candidate) = source.next() else {
            break;
        };
        let candidate = candidate?;
        let candidate = candidate.as_ref();
        if candidate.len() > MAX_GPU_CANDIDATE_BYTES {
            return Err("GPU streaming candidate exceeds 55-byte SHA-256 limit".into());
        }
        batch.push(candidate.to_vec());
        generated += 1;
        if batch.len() >= batch_size {
            dispatch_batch(
                target_hex,
                &mut batch,
                &mut result,
                max_matches,
                &mut executor,
            )?;
            on_progress(GpuStreamProgress {
                tried: result.tried,
                batches: result.batches,
                matches: result.hits.len(),
            });
            if result.hits.len() >= max_matches {
                return Ok(result);
            }
        }
    }
    if !result.cancelled && !batch.is_empty() {
        dispatch_batch(
            target_hex,
            &mut batch,
            &mut result,
            max_matches,
            &mut executor,
        )?;
        on_progress(GpuStreamProgress {
            tried: result.tried,
            batches: result.batches,
            matches: result.hits.len(),
        });
    }
    if result.tried == 0 {
        on_progress(GpuStreamProgress {
            tried: 0,
            batches: 0,
            matches: 0,
        });
    }
    Ok(result)
}
