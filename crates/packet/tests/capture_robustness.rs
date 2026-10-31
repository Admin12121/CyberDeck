//! Deterministic malformed-capture inputs; no external files or live network required.
use cyberdeck_packet::{parse_capture, parse_pcap, PCAP_MAGIC_LE_USEC};

fn classic_header() -> Vec<u8> {
    let mut out = PCAP_MAGIC_LE_USEC.to_le_bytes().to_vec();
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&[0; 8]);
    out.extend_from_slice(&65_535u32.to_le_bytes());
    out.extend_from_slice(&1u32.to_le_bytes());
    out
}

fn record(out: &mut Vec<u8>, bytes: &[u8], original_len: u32) {
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(&original_len.to_le_bytes());
    out.extend_from_slice(bytes);
}

fn pcapng_block(out: &mut Vec<u8>, kind: u32, body: &[u8]) {
    assert_eq!(body.len() % 4, 0);
    let total = (body.len() + 12) as u32;
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(&total.to_le_bytes());
}

fn pcapng_fixture() -> Vec<u8> {
    let mut out = Vec::new();
    let mut shb = 0x1a2b_3c4du32.to_le_bytes().to_vec();
    shb.extend_from_slice(&1u16.to_le_bytes());
    shb.extend_from_slice(&0u16.to_le_bytes());
    shb.extend_from_slice(&(-1i64).to_le_bytes());
    pcapng_block(&mut out, 0x0a0d_0d0a, &shb);

    let mut idb = 1u16.to_le_bytes().to_vec();
    idb.extend_from_slice(&0u16.to_le_bytes());
    idb.extend_from_slice(&65_535u32.to_le_bytes());
    pcapng_block(&mut out, 1, &idb);

    let mut epb = vec![0; 12]; // interface 0, timestamp 0
    epb.extend_from_slice(&4u32.to_le_bytes()); // captured
    epb.extend_from_slice(&4u32.to_le_bytes()); // original
    epb.extend_from_slice(&[0; 4]);
    pcapng_block(&mut out, 6, &epb);
    out
}

#[test]
fn ethernet_ipv4_ethertype_does_not_decode_a_wrong_ip_version_as_udp() {
    let mut ip = vec![0x45u8, 0, 0, 28, 0, 1, 0, 0, 64, 17, 0, 0];
    ip.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
    ip.extend_from_slice(&[0x04, 0xd2, 0x1f, 0x90, 0, 8, 0, 0]);
    let mut eth = vec![0; 12];
    eth.extend_from_slice(&0x0800u16.to_be_bytes());
    eth.extend_from_slice(&ip);
    let good = cyberdeck_packet::dissect(1, &eth);
    assert_eq!(good.protocol, "UDP");

    // Malformed Ethernet frame advertises IPv4 but has an IPv6 version nibble.
    eth[14] = 0x65;
    let bad = cyberdeck_packet::dissect(1, &eth);
    assert_eq!(bad.protocol, "MALFORMED");
    assert!(bad.stream_id.is_none());
    assert!(bad.payload.is_empty());
}

#[test]
fn classic_pcap_rejects_capture_length_greater_than_original_without_promoting_bytes() {
    let mut input = classic_header();
    record(&mut input, &[1, 2, 3, 4], 4);
    record(&mut input, &[5, 6, 7, 8], 2);
    let output = parse_pcap(&input).expect("valid header and first record");
    assert_eq!(output.packets.len(), 1);
    assert!(output.malformed_tail);
    assert_eq!(output.packets[0].offset, 40);
    assert_eq!(output.packets[0].incl_len, 4);
}

#[test]
fn classic_pcap_rejects_frame_exceeding_declared_snapshot_length() {
    let mut input = classic_header();
    input[16..20].copy_from_slice(&2u32.to_le_bytes());
    record(&mut input, &[1, 2, 3, 4], 4);
    let output = parse_pcap(&input).expect("valid header");
    assert!(output.packets.is_empty());
    assert!(output.malformed_tail);
}

#[test]
fn well_formed_pcapng_fixture_preserves_exact_original_frame_offset() {
    let input = pcapng_fixture();
    let output = parse_capture(&input).expect("pcapng fixture");
    assert_eq!(output.packets.len(), 1);
    let packet = &output.packets[0];
    assert_eq!(
        &input[packet.offset..packet.offset + packet.incl_len],
        &[0; 4]
    );
    assert!(!output.malformed_tail);
}

#[test]
fn deterministic_mutations_never_panic_or_return_out_of_bounds_packet_offsets() {
    let mut classic = classic_header();
    record(&mut classic, &[0; 64], 64);
    let pcapng = pcapng_fixture();
    for (fixture_index, fixture) in [classic, pcapng].iter().enumerate() {
        let mut state = 0x9e37_79b9u32 ^ (fixture_index as u32);
        for iteration in 0..512usize {
            let mut input = fixture.clone();
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let byte_index = (state as usize) % input.len();
            input[byte_index] ^= (iteration as u8).wrapping_add(1);
            if iteration % 7 == 0 {
                input.truncate(iteration % input.len());
            }
            let result = std::panic::catch_unwind(|| parse_capture(&input));
            let parsed = result.expect("malformed capture must not panic");
            if let Ok(parsed) = parsed {
                for p in &parsed.packets {
                    let end = p.offset.checked_add(p.incl_len).expect("checked end");
                    assert!(end <= input.len(), "packet range outside input buffer");
                    assert!(p.incl_len <= p.orig_len, "captured length exceeds original");
                }
            }
        }
    }
}
