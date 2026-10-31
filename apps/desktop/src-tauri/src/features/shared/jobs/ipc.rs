//! Thin Tauri IPC controller. Job domain and execution live under the
//! feature-first shared jobs module.

#[path = "application.rs"]
mod application;
#[path = "domain.rs"]
mod domain;
#[path = "infrastructure.rs"]
mod infrastructure;

pub use application::JobManager;
use domain::{JobEvent, JobKind};
use tauri::ipc::Channel;

#[tauri::command]
pub async fn job_start(
    kind: JobKind,
    on_event: Channel<JobEvent>,
    manager: tauri::State<'_, JobManager>,
) -> Result<u64, String> {
    manager
        .start(kind, move |event| {
            let _ = on_event.send(event);
        })
        .await
}

#[tauri::command]
pub fn job_cancel(id: u64, manager: tauri::State<'_, JobManager>) -> bool {
    manager.cancel(id)
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
