//! Native pure packet dissection, split at link/network/transport responsibilities.
// coordinator-insert: application dissector module registrations (mqtt, socks,
// dhcpv6, rdp) owned by the app-dissector slice.
mod dhcpv6;
mod http2;
mod icmp;
mod link;
mod mqtt;
mod network;
pub mod protocol;
mod quic;
mod rdp;
mod smb;
mod socks;
mod tcp_options;
mod tls_depth;
mod transport;
mod udp_services;

pub use link::dissect;
