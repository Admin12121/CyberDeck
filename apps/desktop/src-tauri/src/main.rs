//! HackTool desktop entry point. The frontend never spawns processes or
//! touches the filesystem directly; every native action is a typed command
//! here (Master Plan §9.2).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod jobs;

use jobs::{JobManager, JobKind, JobEvent, job_cancel, job_start};

fn main() {
    tauri::Builder::default()
        .manage(JobManager::new())
        .invoke_handler(tauri::generate_handler![job_start, job_cancel])
        .run(tauri::generate_context!())
        .expect("HackTool desktop runtime failed to start");
}

// Re-exported so docs/examples can reference the wire types without the tauri macro context.
#[allow(unused_imports)]
use hacktool_core as _core;
#[allow(dead_code)]
fn _kind_and_event_compiles(_k: JobKind, _e: JobEvent) {}
