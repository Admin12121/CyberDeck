//! Background worker adapter; registration cleanup and cancellation are not IPC concerns.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use super::domain::{JobEvent, JobKind};

struct Registration {
    id: u64,
    registry: Arc<Mutex<HashMap<u64, CancellationToken>>>,
}

impl Drop for Registration {
    fn drop(&mut self) {
        if let Ok(mut jobs) = self.registry.lock() {
            jobs.remove(&self.id);
        }
    }
}

pub fn spawn_worker(
    kind: JobKind,
    id: u64,
    cancel: CancellationToken,
    registry: Arc<Mutex<HashMap<u64, CancellationToken>>>,
    emit: impl Fn(JobEvent) + Send + 'static,
) {
    tokio::spawn(async move {
        let _registration = Registration { id, registry };
        match kind {
            JobKind::Demo => run_demo(id, cancel, emit).await,
        }
    });
}

/// Preserve the legacy demo protocol; real operations use their own engines.
async fn run_demo(id: u64, cancel: CancellationToken, emit: impl Fn(JobEvent)) {
    const TOTAL_STEPS: u32 = 50;
    emit(JobEvent::Started {
        job_id: id,
        total_steps: TOTAL_STEPS,
    });
    for step in 1..=TOTAL_STEPS {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {
                emit(JobEvent::Cancelled { job_id: id });
                return;
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
        emit(JobEvent::Progress {
            job_id: id,
            step,
            percent: step * 100 / TOTAL_STEPS,
            message: format!("processing unit {step}/{TOTAL_STEPS}"),
        });
    }
    emit(JobEvent::Completed {
        job_id: id,
        message: format!("demo job finished ({TOTAL_STEPS} units)"),
    });
}
