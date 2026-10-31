//! Backward-compatible case command namespace. Implementation is feature-first.
//! Keep cases::case_* command paths stable for the main Tauri registry.
#[path = "features/cases/application/mod.rs"]
mod application;
#[path = "features/cases/domain/mod.rs"]
mod domain;
#[path = "features/cases/infrastructure/mod.rs"]
pub(crate) mod infrastructure;
#[path = "features/cases/ipc/mod.rs"]
mod ipc;

pub(crate) use ipc::*;
