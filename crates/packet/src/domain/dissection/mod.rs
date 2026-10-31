//! Native pure packet dissection, split at link/network/transport responsibilities.
mod link;
mod network;
pub mod protocol;
mod transport;

pub use link::dissect;
