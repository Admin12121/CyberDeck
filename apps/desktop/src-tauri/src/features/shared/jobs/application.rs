//! Shared job orchestration: lifecycle, bounded registration and cancellation.
//! Tauri transport and the worker implementation are separate modules.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

use super::domain::{JobEvent, JobKind};
use super::infrastructure;

/// Prevent unbounded subprocess/task registration, independent of UI limits.
pub const MAX_ACTIVE_JOBS: usize = 32;

type Registry = Arc<Mutex<HashMap<u64, CancellationToken>>>;

#[derive(Default)]
pub struct JobManager {
    next_id: AtomicU64,
    jobs: Registry,
}

impl JobManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn start(
        &self,
        kind: JobKind,
        emit: impl Fn(JobEvent) + Send + 'static,
    ) -> Result<u64, String> {
        let cancel = CancellationToken::new();
        let job_id = {
            let mut jobs = self
                .jobs
                .lock()
                .map_err(|_| "job registry unavailable".to_string())?;
            if jobs.len() >= MAX_ACTIVE_JOBS {
                return Err(format!(
                    "too many concurrent jobs (limit {MAX_ACTIVE_JOBS})"
                ));
            }
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            jobs.insert(id, cancel.clone());
            id
        };
        infrastructure::spawn_worker(kind, job_id, cancel, self.jobs.clone(), emit);
        Ok(job_id)
    }

    /// Returns true only while an active job is registered. The worker owns
    /// the terminal event and cleanup, including cancellation during a delay.
    pub fn cancel(&self, id: u64) -> bool {
        let Ok(jobs) = self.jobs.lock() else {
            return false;
        };
        if let Some(token) = jobs.get(&id) {
            token.cancel();
            true
        } else {
            false
        }
    }

    #[cfg(test)]
    fn active_count(&self) -> usize {
        self.jobs.lock().expect("test registry").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn cancellation_emits_terminal_event_and_releases_slot() {
        let manager = JobManager::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        let id = manager
            .start(JobKind::Demo, move |event| {
                let _ = tx.send(event);
            })
            .await
            .unwrap();
        assert_eq!(manager.active_count(), 1);
        assert!(manager.cancel(id));
        let mut terminal = None;
        for _ in 0..4 {
            match tokio::time::timeout(Duration::from_secs(2), rx.recv()).await {
                Ok(Some(JobEvent::Cancelled { job_id })) => {
                    terminal = Some(job_id);
                    break;
                }
                Ok(Some(_)) => {}
                _ => break,
            }
        }
        assert_eq!(terminal, Some(id));
        for _ in 0..100 {
            if manager.active_count() == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(manager.active_count(), 0);
        assert!(!manager.cancel(id));
    }

    #[tokio::test]
    async fn registry_capacity_is_bounded_and_does_not_consume_id_on_rejection() {
        let manager = JobManager::new();
        for _ in 0..MAX_ACTIVE_JOBS {
            manager.start(JobKind::Demo, |_| {}).await.unwrap();
        }
        assert_eq!(manager.active_count(), MAX_ACTIVE_JOBS);
        let next_id = manager.next_id.load(Ordering::Relaxed);
        assert!(manager.start(JobKind::Demo, |_| {}).await.is_err());
        assert_eq!(manager.next_id.load(Ordering::Relaxed), next_id);
        for id in 0..MAX_ACTIVE_JOBS as u64 {
            assert!(manager.cancel(id));
        }
    }
}
