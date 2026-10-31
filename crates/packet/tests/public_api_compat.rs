//! Compile-time compatibility checks for crate-root and historical public API paths.
use cyberdeck_packet::{
    application, dissect, domain, infrastructure, inventory, parse_capture, parse_pcap, Dissected,
    Endianness, Layer, PacketMeta, PcapFile, TcpMeta, MAX_CAPTURE_PACKETS, MAX_PACKET_BYTES,
};

#[test]
fn stable_root_entrypoints_and_protocol_facade_remain_public() {
    let _: fn(&[u8]) -> Result<PcapFile, String> = parse_capture;
    let _: fn(&[u8]) -> Result<PcapFile, String> = parse_pcap;
    let _: fn(u32, &[u8]) -> Dissected = dissect;
    let _: fn(&[PacketMeta]) -> inventory::PassiveInventory = inventory::observe;
    let _: fn(&[u8]) -> Option<String> = application::http_start_line;
    let _: fn(&[u8]) -> Option<application::TlsHello> = application::tls_hello;
    let _: fn(&application::TlsHello) -> String = application::tls_description;
    let _: fn(&[u8]) -> Result<PcapFile, String> = infrastructure::pcap::parse_pcap;
    let _: fn(u32, &[u8]) -> Dissected = domain::dissection::dissect;

    let _layer: Option<Layer> = None;
    let _tcp: Option<TcpMeta> = None;
    let _endian = Endianness::Little;
    assert_eq!(MAX_CAPTURE_PACKETS, 200_000);
    assert_eq!(MAX_PACKET_BYTES, 262_144);
}
