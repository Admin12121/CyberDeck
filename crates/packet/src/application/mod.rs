//! Offline packet-engine use cases and the stable passive protocol API facade.
pub mod capture;

// Preserve the historical `cyberdeck_packet::application::*` API without
// making the pure domain dissectors depend on application orchestration.
pub use crate::domain::dissection::protocol::*;
