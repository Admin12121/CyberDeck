//! Shared job domain types, independent of the desktop transport.
use serde::{Deserialize, Serialize};

/// Wire events mirrored by `apps/desktop/state/jobs-model.ts`.
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
