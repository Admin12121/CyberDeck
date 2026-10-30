//! Shared job pipeline (Master Plan §8.3): queued/running/cancelled/failed
//! states, streamed progress events, safe cancellation. Arc 1 ships one demo
//! job class; engine jobs join the same registry and wire types in later arcs.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::ipc::Channel;
use tokio_util::sync::CancellationToken;

/// Wire events mirrored by `apps/desktop/state/jobs-model.ts` — keep in sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum JobEvent {
    Started {
        job_id: u64,
        total_steps: u32,
    },
    Progress {
        job_id: u64,
        step: u32,
        percent: u32,
        message: String,
    },
    Completed {
        job_id: u64,
        message: String,
    },
    Cancelled {
        job_id: u64,
    },
    Failed {
        job_id: u64,
        error: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    Demo,
}

struct JobHandle {
    cancel: CancellationToken,
}

#[derive(Default)]
pub struct JobManager {
    next_id: AtomicU64,
    // Tauri commands run on arbitrary threads; synchronous Mutex is correct here.
    jobs: Mutex<HashMap<u64, JobHandle>>,
}

impl JobManager {
    pub fn new() -> Self {
        Self::default()
    }
}

#[tauri::command]
pub async fn job_start(
    kind: JobKind,
    on_event: Channel<JobEvent>,
    manager: tauri::State<'_, JobManager>,
) -> Result<u64, String> {
    let job_id = manager.next_id.fetch_add(1, Ordering::Relaxed);
    let cancel = CancellationToken::new();
    manager
        .jobs
        .lock()
        .expect("job registry poisoned")
        .insert(job_id, JobHandle { cancel: cancel.clone() });

    let registry = manager.jobs.clone();
    tokio::spawn(async move {
        let total_steps = 50u32;
        let _ = on_event.send(JobEvent::Started { job_id, total_steps });
        for step in 1..=total_steps {
            if cancel.is_cancelled() {
                let _ = on_event.send(JobEvent::Cancelled { job_id });
                registry.lock().expect("job registry poisoned").remove(&job_id);
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let percent = step * 100 / total_steps;
            let _ = on_event.send(JobEvent::Progress {
                job_id,
                step,
                percent,
                message: format!("processing unit {step}/{total_steps}"),
            });
        }
        let _ = on_event.send(JobEvent::Completed {
            job_id,
            message: format!("demo job finished ({total_steps} units)"),
        });
        registry.lock().expect("job registry poisoned").remove(&job_id);
    });

    match kind {
        JobKind::Demo => {}
    }
    Ok(job_id)
}

/// Cancel means the worker observes the token and reports Cancelled itself;
/// partial state is the worker's responsibility to clean up (§8.3).
#[tauri::command]
pub fn job_cancel(id: u64, manager: tauri::State<'_, JobManager>) -> bool {
    match manager.jobs.lock().expect("job registry poisoned").get(&id) {
        Some(handle) => {
            handle.cancel.cancel();
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_event_wire_shape_matches_frontend() {
        let json = serde_json::to_string(&JobEvent::Progress {
            job_id: 1,
            step: 3,
            percent: 6,
            message: "processing unit 3/50".into(),
        })
        .unwrap();
        assert!(json.contains(r#""type":"progress""#));
        assert!(json.contains(r#""job_id":1"#));
        assert!(json.contains(r#""percent":6"#));
    }
}
