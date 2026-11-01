//! Canonical case feature namespace. Implementation is feature-first.
//! Preserve all case command wire identifiers and storage semantics.
#[path = "application/mod.rs"]
mod application;
#[path = "domain/mod.rs"]
mod domain;
#[path = "infrastructure/mod.rs"]
pub(crate) mod infrastructure;
#[path = "ipc/mod.rs"]
mod ipc;

pub(crate) use ipc::*;
