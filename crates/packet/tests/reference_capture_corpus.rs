//! Read-only, opt-in real-capture regression against an external reference corpus.
//! Reference captures are not copied to or shipped with CyberDeck.
//! Run from /workspace:
//! CYBERDECK_PACKET_REFERENCE_DIR=/workspace/reference/wireshark/test/captures \
//! cargo test --locked --offline -p cyberdeck-packet --test reference_capture_corpus -- --ignored --nocapture
use cyberdeck_packet::{parse_capture, MAX_CAPTURE_PACKETS, MAX_PACKET_BYTES};
use std::{fs, path::PathBuf};

struct CorpusFixture {
    name: &'static str,
    file_bytes: usize,
    frames: usize,
}
const REFERENCE_FILES: &[CorpusFixture] = &[
    CorpusFixture {
        name: "arp.pcap",
        file_bytes: 70,
        frames: 1,
    },
    CorpusFixture {
        name: "dns-ooo.pcap",
        file_bytes: 418,
        frames: 4,
    },
    CorpusFixture {
        name: "http-ooo.pcap",
        file_bytes: 1209,
        frames: 16,
    },
    CorpusFixture {
        name: "ipv6.pcap",
        file_bytes: 126,
        frames: 1,
    },
    CorpusFixture {
        name: "http-ooo-fuzzed.pcapng",
        file_bytes: 1584,
        frames: 16,
    },
    CorpusFixture {
        name: "tcp-badsegments.pcap",
        file_bytes: 1732,
        frames: 25,
    },
    CorpusFixture {
        name: "tls13-rfc8446.pcap",
        file_bytes: 4158,
        frames: 13,
    },
];

fn corpus_dir() -> PathBuf {
    std::env::var_os("CYBERDECK_PACKET_REFERENCE_DIR")
        .map(PathBuf::from)
        .expect("set CYBERDECK_PACKET_REFERENCE_DIR for ignored real-capture tests")
}

fn read_fixture(root: &std::path::Path, fixture: &CorpusFixture) -> Vec<u8> {
    let path = root.join(fixture.name);
    let metadata = fs::metadata(&path).expect("missing external fixture");
    assert!(metadata.is_file());
    assert!(
        metadata.len() <= 8 * 1024 * 1024,
        "unexpectedly large fixture"
    );
    assert_eq!(
        metadata.len() as usize,
        fixture.file_bytes,
        "fixture version changed"
    );
    fs::read(&path).expect("cannot read external capture fixture")
}

fn check_offsets(data: &[u8]) {
    if let Ok(parsed) = parse_capture(data) {
        assert!(parsed.packets.len() <= MAX_CAPTURE_PACKETS);
        for packet in &parsed.packets {
            assert!(packet.incl_len <= MAX_PACKET_BYTES);
            assert!(packet.incl_len <= packet.orig_len);
            let end = packet
                .offset
                .checked_add(packet.incl_len)
                .expect("offset overflow");
            assert!(end <= data.len(), "record exceeded source bytes");
        }
    }
}

#[test]
#[ignore = "requires read-only external Wireshark captures"]
fn reference_captures_match_pinned_packet_counts_and_byte_bounds() {
    let root = corpus_dir();
    for fixture in REFERENCE_FILES {
        let raw = read_fixture(&root, fixture);
        let capture = parse_capture(&raw).expect("reference capture must parse");
        assert_eq!(capture.packets.len(), fixture.frames, "{}", fixture.name);
        assert!(
            !capture.malformed_tail,
            "{} has malformed tail",
            fixture.name
        );
        check_offsets(&raw);
        let inventory = cyberdeck_packet::inventory::observe(&capture.packets);
        assert_eq!(inventory.packets_scanned, fixture.frames);
        assert!(inventory.skipped_non_ip_packets <= fixture.frames);
        assert!(inventory.hosts.len() <= cyberdeck_packet::inventory::MAX_INVENTORY_HOSTS);
        assert!(inventory.flows.len() <= cyberdeck_packet::inventory::MAX_INVENTORY_FLOWS);
        for host in &inventory.hosts {
            assert!(host.first_packet_index <= host.last_packet_index);
            assert!(host.last_packet_index < fixture.frames);
            assert!(host.address.parse::<std::net::IpAddr>().is_ok());
        }
        for flow in &inventory.flows {
            assert!(flow.first_packet_index <= flow.last_packet_index);
            assert!(flow.last_packet_index < fixture.frames);
        }
        eprintln!(
            "{}: bytes={}, frames={}",
            fixture.name,
            raw.len(),
            fixture.frames
        );
    }
}

#[test]
#[ignore = "requires read-only external Wireshark captures"]
fn external_capture_corruptions_never_panic_or_promote_out_of_bounds_frames() {
    let root = corpus_dir();
    for (fixture_index, fixture) in REFERENCE_FILES.iter().enumerate() {
        let raw = read_fixture(&root, fixture);
        let mut state = 0x9e37_79b9u32 ^ fixture_index as u32;
        for mutation in 0..128usize {
            let mut data = raw.clone();
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let position = state as usize % data.len();
            data[position] ^= (mutation as u8).wrapping_add(1);
            if mutation % 8 == 0 {
                let new_len = mutation % data.len();
                data.truncate(new_len);
            }
            let result = std::panic::catch_unwind(|| check_offsets(&data));
            assert!(
                result.is_ok(),
                "{} corruption {mutation} panicked",
                fixture.name
            );
        }
    }
}
