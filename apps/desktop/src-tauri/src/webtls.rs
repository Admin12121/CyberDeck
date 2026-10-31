//! Stable web TLS transport compatibility facade.
//! Native implementation and framing tests live in features/web/infrastructure.

#[path = "features/web/infrastructure/tls.rs"]
mod implementation;

pub use implementation::*;
