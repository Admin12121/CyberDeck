//! N2 Linux-first passive Ethernet capture.
//! Never opens an interface without an explicit selection and caller action.
//! Frames are serialized once into a bounded classic PCAP; original frame spans
//! are tracked in that immutable byte source for later evidence integration.

use crate::{inventory, parse_capture};
use serde::Serialize;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const MAX_LIVE_PACKETS: usize = 20_000;
pub const MAX_LIVE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_LIVE_DURATION: Duration = Duration::from_secs(600);
pub const MAX_POLL_INTERVAL: Duration = Duration::from_millis(250);
pub const MAX_FRAME_BYTES: usize = 65_535;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureErrorCode {
    UnsupportedPlatform,
    InterfaceNotFound,
    UnsupportedLinkLayer,
    PermissionDenied,
    InvalidConfig,
    Io,
    Parse,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CaptureError {
    pub code: CaptureErrorCode,
    pub message: String,
}

impl CaptureError {
    pub(crate) fn new(code: CaptureErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
    fn io(context: &str, error: io::Error) -> Self {
        let code = if error.kind() == io::ErrorKind::PermissionDenied {
            CaptureErrorCode::PermissionDenied
        } else {
            CaptureErrorCode::Io
        };
        let message = if code == CaptureErrorCode::PermissionDenied {
            format!("{context}: capture permission denied (Linux requires CAP_NET_RAW or equivalent authorization): {error}")
        } else {
            format!("{context}: {error}")
        };
        Self::new(code, message)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CaptureInterface {
    pub name: String,
    pub index: u32,
    pub ethernet: bool,
    pub up: bool,
    pub loopback: bool,
}

/// Enumerates native Linux kernel interfaces, not synthetic application profiles.
/// Discovery does not require opening a raw socket and is safe when unprivileged.
#[cfg(target_os = "linux")]
pub fn discover_interfaces() -> Result<Vec<CaptureInterface>, CaptureError> {
    discover_from(std::path::Path::new("/sys/class/net"))
}

#[cfg(target_os = "windows")]
pub fn discover_interfaces() -> Result<Vec<CaptureInterface>, CaptureError> {
    crate::infrastructure::windows_interfaces::discover()
}

/// macOS interface discovery via getifaddrs; unprivileged like /sys/class/net.
#[cfg(target_os = "macos")]
pub fn discover_interfaces() -> Result<Vec<CaptureInterface>, CaptureError> {
    crate::infrastructure::bpf_capture::discover_interfaces()
}

#[cfg(all(
    not(target_os = "linux"),
    not(target_os = "windows"),
    not(target_os = "macos")
))]
pub fn discover_interfaces() -> Result<Vec<CaptureInterface>, CaptureError> {
    Err(CaptureError::new(
        CaptureErrorCode::UnsupportedPlatform,
        "native live capture is currently supported only on Linux and macOS",
    ))
}

#[cfg(target_os = "linux")]
fn discover_from(root: &std::path::Path) -> Result<Vec<CaptureInterface>, CaptureError> {
    let entries =
        std::fs::read_dir(root).map_err(|e| CaptureError::io("enumerate network interfaces", e))?;
    let mut interfaces = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| CaptureError::io("read interface directory", e))?;
        let name = entry.file_name().to_string_lossy().to_string();
        if !valid_name(&name) {
            continue;
        }
        let root = entry.path();
        let parse = |key: &str| -> Option<String> {
            std::fs::read_to_string(root.join(key))
                .ok()
                .map(|s| s.trim().to_string())
        };
        let Some(index) = parse("ifindex")
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|n| *n > 0)
        else {
            continue;
        };
        let kind = parse("type")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(0);
        let flags = parse("flags")
            .and_then(|v| u32::from_str_radix(v.trim_start_matches("0x"), 16).ok())
            .unwrap_or(0);
        interfaces.push(CaptureInterface {
            name,
            index,
            ethernet: kind == 1,
            loopback: kind == 772 || flags & 0x8 != 0,
            up: flags & 0x1 != 0,
        });
    }
    interfaces.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(interfaces)
}

/// Shared interface-name validation: platform backends (including the macOS
/// BPF discovery) must apply the same strictness before names cross IPC.
pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 15
        && name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b':'))
}

pub fn select_interface(
    interfaces: &[CaptureInterface],
    name: &str,
) -> Result<CaptureInterface, CaptureError> {
    if !valid_name(name) {
        return Err(CaptureError::new(
            CaptureErrorCode::InterfaceNotFound,
            "invalid interface name",
        ));
    }
    let interface = interfaces
        .iter()
        .find(|interface| interface.name == name)
        .ok_or_else(|| {
            CaptureError::new(
                CaptureErrorCode::InterfaceNotFound,
                format!("interface '{name}' is not available"),
            )
        })?;
    if !interface.ethernet || interface.loopback {
        return Err(CaptureError::new(
            CaptureErrorCode::UnsupportedLinkLayer,
            format!("interface '{name}' is not Ethernet: only exact DLT_EN10MB frame capture is supported"),
        ));
    }
    if !interface.up {
        return Err(CaptureError::new(
            CaptureErrorCode::InvalidConfig,
            format!("interface '{name}' is down"),
        ));
    }
    Ok(interface.clone())
}

// --- bounded capture filters -------------------------------------------------
//
// The live-capture filter subset exists so an operator can bound what the
// kernel records WITHOUT shipping a full tcpdump expression language. The
// grammar accepts `host <ip>`, `port <n>` and the protocol words
// `tcp`/`udp`/`icmp`/`any`, joined by `and`; everything else is refused with
// the subset spelled out. The backend remains the only authority: the IPC
// layer re-parses every filter before a capture starts.

/// Transport protocols addressable by the bounded capture-filter subset.
/// `Any` carries no constraint (the word is accepted so the UI can express
/// "protocol is not a criterion" without special-casing).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpUdpIcmpAny {
    Tcp,
    Udp,
    Icmp,
    Any,
}

/// Classic BPF instruction. Linux `struct sock_filter` and BSD
/// `struct bpf_insn` share this exact 8-byte layout, so one program builder
/// serves both the AF_PACKET socket filter and the BPF device filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct BpfInstruction {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}
const _: () = assert!(std::mem::size_of::<BpfInstruction>() == 8);

// Classic BPF opcode encodings used by the builder (linux/filter.h groups).
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_LD_H_ABS: u16 = 0x28;
const BPF_LD_B_ABS: u16 = 0x30;
const BPF_LD_H_IND: u16 = 0x48;
const BPF_LDX_B_MSH: u16 = 0xb1;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;
/// Accept value used by libpcap for "keep the whole packet".
const BPF_ACCEPT_ALL: u32 = 0x0004_0000;

// Ethernet/IP field offsets the predicate and the BPF program share. IPv6
// transport offsets assume no extension headers (documented subset limit).
const ETHERTYPE_OFFSET: u32 = 12;
const ETHERTYPE_IPV4: u32 = 0x0800;
const ETHERTYPE_IPV6: u32 = 0x86dd;
/// u16 forms for matching the raw EtherType field in the reference predicate.
const ETHERTYPE_IPV4_U16: u16 = 0x0800;
const ETHERTYPE_IPV6_U16: u16 = 0x86dd;
const IPV4_PROTOCOL_OFFSET: u32 = 23;
const IPV4_SRC_OFFSET: u32 = 26;
const IPV4_DST_OFFSET: u32 = 30;
const IPV6_NEXT_HEADER_OFFSET: u32 = 20;
const IPV6_SRC_OFFSET: u32 = 22;
const IPV6_DST_OFFSET: u32 = 38;
const IPV6_SRC_PORT_OFFSET: u32 = 54;
const IPV6_DST_PORT_OFFSET: u32 = 56;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;

const MAX_FILTER_CHARS: usize = 256;
const MAX_FILTER_TERMS: usize = 16;

/// Honest platform probe for capture filters: the bounded AF_PACKET and BPF
/// backends install kernel programs; the Windows backend has no filter path
/// and must refuse instead of silently ignoring the operator's filter.
pub fn capture_filter_backend_supported() -> bool {
    cfg!(any(target_os = "linux", target_os = "macos"))
}

pub const CAPTURE_FILTER_UNSUPPORTED_MESSAGE: &str =
    "capture filters are not supported on this backend; they require the Linux AF_PACKET or macOS BPF capture backends";

/// A bounded capture-filter predicate: at most one host, one port and one
/// protocol term. Fields stay private so every construction path validates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct CaptureFilter {
    host: Option<std::net::IpAddr>,
    port: Option<u16>,
    protocol: Option<TcpUdpIcmpAny>,
}

impl CaptureFilter {
    pub fn host(&self) -> Option<std::net::IpAddr> {
        self.host
    }
    pub fn port(&self) -> Option<u16> {
        self.port
    }
    pub fn protocol(&self) -> Option<TcpUdpIcmpAny> {
        self.protocol
    }

    /// True when the filter carries no effective constraint. Empty strings
    /// parse to this value, and no kernel program is installed for it.
    pub fn is_empty(&self) -> bool {
        self.host.is_none()
            && self.port.is_none()
            && matches!(self.protocol, None | Some(TcpUdpIcmpAny::Any))
    }

    /// Parse the bounded display-style subset. Whitespace separates terms and
    /// the word `and` is accepted (and skipped) between terms; every other
    /// syntax is refused with a message naming the supported subset.
    pub fn parse(text: &str) -> Result<CaptureFilter, CaptureError> {
        let text = text.trim();
        if text.is_empty() {
            return Ok(CaptureFilter::default());
        }
        let refusal = |message: String| {
            CaptureError::new(CaptureErrorCode::InvalidConfig, message)
        };
        if text.chars().count() > MAX_FILTER_CHARS {
            return Err(refusal(format!(
                "capture filter exceeds {MAX_FILTER_CHARS} characters"
            )));
        }
        let terms: Vec<&str> = text.split_whitespace().collect();
        if terms.len() > MAX_FILTER_TERMS {
            return Err(refusal(format!(
                "capture filter exceeds {MAX_FILTER_TERMS} terms"
            )));
        }
        let subset = "supported subset: host <ip>, port <n>, tcp, udp, icmp, any, joined by 'and'";
        let mut filter = CaptureFilter::default();
        let mut index = 0usize;
        while index < terms.len() {
            match terms[index] {
                "and" => {
                    // `and` only joins two terms; leading or trailing use is
                    // a syntax error, not a silently ignored token.
                    if index == 0 || index + 1 == terms.len() {
                        return Err(refusal(
                            "capture filter 'and' must join two terms".into(),
                        ));
                    }
                }
                "host" => {
                    let Some(value) = terms.get(index + 1) else {
                        return Err(refusal(
                            "capture filter term 'host' requires an IPv4 or IPv6 address".into(),
                        ));
                    };
                    let Ok(address) = value.parse::<std::net::IpAddr>() else {
                        return Err(refusal(format!(
                            "capture filter host value '{value}' is not an IPv4 or IPv6 address; {subset}"
                        )));
                    };
                    if filter.host.is_some() {
                        return Err(refusal(
                            "capture filter supports at most one 'host' term".into(),
                        ));
                    }
                    filter.host = Some(address);
                    index += 1; // the address term was consumed with the keyword
                }
                "port" => {
                    let Some(value) = terms.get(index + 1) else {
                        return Err(refusal(
                            "capture filter term 'port' requires a number 0-65535".into(),
                        ));
                    };
                    let Ok(port) = value.parse::<u16>() else {
                        return Err(refusal(format!(
                            "capture filter port value '{value}' is not a number 0-65535; {subset}"
                        )));
                    };
                    if filter.port.is_some() {
                        return Err(refusal(
                            "capture filter supports at most one 'port' term".into(),
                        ));
                    }
                    filter.port = Some(port);
                    index += 1;
                }
                "tcp" | "udp" | "icmp" | "any" => {
                    let protocol = match terms[index] {
                        "tcp" => TcpUdpIcmpAny::Tcp,
                        "udp" => TcpUdpIcmpAny::Udp,
                        "icmp" => TcpUdpIcmpAny::Icmp,
                        _ => TcpUdpIcmpAny::Any,
                    };
                    if filter.protocol.is_some() {
                        return Err(refusal(
                            "capture filter supports at most one protocol term".into(),
                        ));
                    }
                    filter.protocol = Some(protocol);
                }
                "or" | "not" => {
                    return Err(refusal(format!(
                        "capture filter term '{}' is not supported; {subset}",
                        terms[index]
                    )));
                }
                other => {
                    return Err(refusal(format!(
                        "unsupported capture filter term '{other}'; {subset}"
                    )));
                }
            }
            index += 1;
        }
        Ok(filter)
    }

    /// Reference predicate over original Ethernet frames: every configured
    /// clause must hold. The kernel program built by [`Self::to_bpf_program`]
    /// implements exactly this predicate for well-formed frames, cross-checked
    /// by the in-module interpreter tests. Frames shorter than the fields a
    /// clause needs never match, and VLAN encapsulation (0x8100) is outside
    /// the bounded subset.
    pub fn matches_ethernet(&self, frame: &[u8]) -> bool {
        if self.is_empty() {
            // An unconstrained filter accepts every frame — the installed
            // kernel program is an unconditional accept, so the reference
            // predicate must agree (including non-IP frames like ARP).
            return true;
        }
        let Some(ethertype) = u16_be(frame, ETHERTYPE_OFFSET as usize) else {
            return false;
        };
        match ethertype {
            ETHERTYPE_IPV4_U16 => self.matches_ipv4(frame),
            ETHERTYPE_IPV6_U16 => self.matches_ipv6(frame),
            _ => false,
        }
    }

    fn matches_ipv4(&self, frame: &[u8]) -> bool {
        if let Some(host) = self.host {
            let Some(word) = ipv4_host_word(host) else {
                // A v6 host can never match a v4 frame.
                return false;
            };
            let source = u32_be(frame, IPV4_SRC_OFFSET as usize).unwrap_or(0);
            let destination = u32_be(frame, IPV4_DST_OFFSET as usize).unwrap_or(0);
            if source != word && destination != word {
                return false;
            }
        }
        if let Some(protocol) = self.protocol {
            if !matches!(protocol, TcpUdpIcmpAny::Any)
                && u8_at(frame, IPV4_PROTOCOL_OFFSET as usize) != Some(ipv4_protocol(protocol))
            {
                return false;
            }
        }
        if let Some(port) = self.port {
            // Port clauses are TCP/UDP-only, mirroring tcpdump's `port`.
            let protocol = u8_at(frame, IPV4_PROTOCOL_OFFSET as usize);
            if protocol != Some(IPPROTO_TCP) && protocol != Some(IPPROTO_UDP) {
                return false;
            }
            // Variable IHL: the transport header sits at 14 + IHL*4 bytes.
            let Some(ihl) = u8_at(frame, 14).map(|value| usize::from(value & 0x0f) * 4) else {
                return false;
            };
            if ihl < 20 {
                return false;
            }
            let transport = 14 + ihl;
            let source = u16_be(frame, transport).unwrap_or(0);
            let destination = u16_be(frame, transport + 2).unwrap_or(0);
            if source != port && destination != port {
                return false;
            }
        }
        true
    }

    fn matches_ipv6(&self, frame: &[u8]) -> bool {
        if let Some(host) = self.host {
            let Some(words) = ipv6_host_words(host) else {
                // A v4 host can never match a v6 frame.
                return false;
            };
            // The whole 16-byte address must match on one side.
            let source = words.iter().enumerate().all(|(index, word)| {
                u32_be(frame, IPV6_SRC_OFFSET as usize + index * 4) == Some(*word)
            });
            let destination = words.iter().enumerate().all(|(index, word)| {
                u32_be(frame, IPV6_DST_OFFSET as usize + index * 4) == Some(*word)
            });
            if !source && !destination {
                return false;
            }
        }
        if let Some(protocol) = self.protocol {
            if !matches!(protocol, TcpUdpIcmpAny::Any)
                && u8_at(frame, IPV6_NEXT_HEADER_OFFSET as usize) != Some(ipv6_protocol(protocol))
            {
                return false;
            }
        }
        if let Some(port) = self.port {
            let next_header = u8_at(frame, IPV6_NEXT_HEADER_OFFSET as usize);
            if next_header != Some(IPPROTO_TCP) && next_header != Some(IPPROTO_UDP) {
                return false;
            }
            let source = u16_be(frame, IPV6_SRC_PORT_OFFSET as usize).unwrap_or(0);
            let destination = u16_be(frame, IPV6_DST_PORT_OFFSET as usize).unwrap_or(0);
            if source != port && destination != port {
                return false;
            }
        }
        true
    }

    /// Compile the predicate into a classic BPF program for the kernel
    /// (AF_PACKET `SO_ATTACH_FILTER` on Linux, `BIOCSSETF` on macOS). Each
    /// clause is a straight-line snippet that RETs 0 (drop) when it cannot be
    /// satisfied and falls through when it can; a final RET accepts. Programs
    /// stay tiny (tens of instructions) by construction.
    pub fn to_bpf_program(&self) -> Vec<BpfInstruction> {
        let mut program = Program::default();
        match self.host {
            Some(std::net::IpAddr::V4(address)) => {
                emit_host_ipv4(&mut program, u32::from(address));
            }
            Some(std::net::IpAddr::V6(address)) => {
                emit_host_ipv6(&mut program, &ipv6_words(address));
            }
            None => {}
        }
        if let Some(port) = self.port {
            emit_port_clause(&mut program, port);
        }
        if let Some(protocol) = self.protocol {
            emit_protocol_clause(&mut program, protocol);
        }
        program.emit(BPF_RET_K, 0, 0, BPF_ACCEPT_ALL);
        program.insns
    }
}

fn u16_be(frame: &[u8], at: usize) -> Option<u16> {
    let bytes: [u8; 2] = frame.get(at..at.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

fn u32_be(frame: &[u8], at: usize) -> Option<u32> {
    let bytes: [u8; 4] = frame.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

fn u8_at(frame: &[u8], at: usize) -> Option<u8> {
    frame.get(at).copied()
}

/// IPv4 host addresses compare as one 32-bit word; v6 hosts have no v4 word.
fn ipv4_host_word(host: std::net::IpAddr) -> Option<u32> {
    match host {
        std::net::IpAddr::V4(address) => Some(u32::from(address)),
        std::net::IpAddr::V6(_) => None,
    }
}

fn ipv6_words(address: std::net::Ipv6Addr) -> [u32; 4] {
    let segments = address.segments();
    [
        (u32::from(segments[0]) << 16) | u32::from(segments[1]),
        (u32::from(segments[2]) << 16) | u32::from(segments[3]),
        (u32::from(segments[4]) << 16) | u32::from(segments[5]),
        (u32::from(segments[6]) << 16) | u32::from(segments[7]),
    ]
}

fn ipv6_host_words(host: std::net::IpAddr) -> Option<[u32; 4]> {
    match host {
        std::net::IpAddr::V4(_) => None,
        std::net::IpAddr::V6(address) => Some(ipv6_words(address)),
    }
}

fn ipv4_protocol(protocol: TcpUdpIcmpAny) -> u8 {
    match protocol {
        TcpUdpIcmpAny::Tcp => IPPROTO_TCP,
        TcpUdpIcmpAny::Udp => IPPROTO_UDP,
        TcpUdpIcmpAny::Icmp | TcpUdpIcmpAny::Any => IPPROTO_ICMP,
    }
}

fn ipv6_protocol(protocol: TcpUdpIcmpAny) -> u8 {
    match protocol {
        TcpUdpIcmpAny::Tcp => IPPROTO_TCP,
        TcpUdpIcmpAny::Udp => IPPROTO_UDP,
        TcpUdpIcmpAny::Icmp | TcpUdpIcmpAny::Any => IPPROTO_ICMPV6,
    }
}

/// Sequential program builder. Every jump target is a later instruction, so
/// relative offsets are always forward and resolved once the target index is
/// known; `jump_to` pins that invariant with a debug assert.
#[derive(Default)]
struct Program {
    insns: Vec<BpfInstruction>,
}

impl Program {
    fn emit(&mut self, code: u16, jt: u8, jf: u8, k: u32) -> usize {
        self.insns.push(BpfInstruction { code, jt, jf, k });
        self.insns.len() - 1
    }

    /// Point one jump field of the instruction at `at` to absolute index
    /// `target` (always strictly forward in this builder).
    fn jump_to(&mut self, at: usize, target: usize, taken: bool) {
        debug_assert!(target > at, "filter jump targets must be forward");
        let offset = (target - at - 1) as u8;
        let field = if taken {
            &mut self.insns[at].jt
        } else {
            &mut self.insns[at].jf
        };
        *field = offset;
    }
}

fn emit_host_ipv4(program: &mut Program, host: u32) {
    program.emit(BPF_LD_H_ABS, 0, 0, ETHERTYPE_OFFSET);
    let type_jeq = program.emit(BPF_JMP_JEQ_K, 0, 0, ETHERTYPE_IPV4);
    let src_load = program.emit(BPF_LD_W_ABS, 0, 0, IPV4_SRC_OFFSET);
    let src_jeq = program.emit(BPF_JMP_JEQ_K, 0, 0, host);
    let dst_load = program.emit(BPF_LD_W_ABS, 0, 0, IPV4_DST_OFFSET);
    let dst_jeq = program.emit(BPF_JMP_JEQ_K, 0, 0, host);
    let reject = program.emit(BPF_RET_K, 0, 0, 0);
    let pass = program.insns.len();
    program.jump_to(type_jeq, src_load, true);
    // A non-IPv4 frame can never host an IPv4 address.
    program.jump_to(type_jeq, reject, false);
    program.jump_to(src_jeq, pass, true);
    program.jump_to(src_jeq, dst_load, false);
    program.jump_to(dst_jeq, pass, true);
    program.jump_to(dst_jeq, reject, false);
}

/// The full 16-byte address must match on one side only, so the source words
/// chain into each other and fall to the destination chain on any mismatch.
fn emit_host_ipv6(program: &mut Program, words: &[u32; 4]) {
    let mut src_jeqs = [0usize; 4];
    for (index, word) in words.iter().enumerate() {
        program.emit(BPF_LD_W_ABS, 0, 0, IPV6_SRC_OFFSET + index as u32 * 4);
        src_jeqs[index] = program.emit(BPF_JMP_JEQ_K, 0, 0, *word);
    }
    let mut dst_loads = [0usize; 4];
    let mut dst_jeqs = [0usize; 4];
    for (index, word) in words.iter().enumerate() {
        dst_loads[index] = program.emit(BPF_LD_W_ABS, 0, 0, IPV6_DST_OFFSET + index as u32 * 4);
        dst_jeqs[index] = program.emit(BPF_JMP_JEQ_K, 0, 0, *word);
    }
    let reject = program.emit(BPF_RET_K, 0, 0, 0);
    let pass = program.insns.len();
    for index in 0..words.len() {
        if index + 1 < words.len() {
            // The next source load sits immediately after this comparison.
            program.jump_to(src_jeqs[index], src_jeqs[index] + 1, true);
            program.jump_to(dst_jeqs[index], dst_jeqs[index] + 1, true);
        }
        program.jump_to(src_jeqs[index], dst_loads[0], false);
        program.jump_to(dst_jeqs[index], reject, false);
    }
    program.jump_to(src_jeqs[3], pass, true);
    program.jump_to(dst_jeqs[3], pass, true);
}

/// `port <n>` applies to TCP and UDP on both IP versions (tcpdump semantics).
/// IPv4 uses the MSH/IND idiom so any IHL is honored; IPv6 assumes no
/// extension headers (documented subset limit).
fn emit_port_clause(program: &mut Program, port: u16) {
    // IPv4 side: TCP or UDP, ports at 14 + IHL*4 via the MSH/IND idiom.
    program.emit(BPF_LD_H_ABS, 0, 0, ETHERTYPE_OFFSET);
    let v4_type_jeq = program.emit(BPF_JMP_JEQ_K, 0, 0, ETHERTYPE_IPV4);
    let v4_proto_load = program.emit(BPF_LD_B_ABS, 0, 0, IPV4_PROTOCOL_OFFSET);
    let v4_tcp = program.emit(BPF_JMP_JEQ_K, 0, 0, u32::from(IPPROTO_TCP));
    let v4_udp = program.emit(BPF_JMP_JEQ_K, 0, 0, u32::from(IPPROTO_UDP));
    // The TCP/UDP taken-branches must land HERE: skipping the MSH load
    // leaves X at zero and the indirect port loads read the wrong bytes.
    let v4_msh = program.emit(BPF_LDX_B_MSH, 0, 0, 14);
    let v4_src_load = program.emit(BPF_LD_H_IND, 0, 0, 14);
    let v4_src_jeq = program.emit(BPF_JMP_JEQ_K, 0, 0, u32::from(port));
    let v4_dst_load = program.emit(BPF_LD_H_IND, 0, 0, 16);
    let v4_dst_jeq = program.emit(BPF_JMP_JEQ_K, 0, 0, u32::from(port));
    // A v4 frame that failed here can never take the IPv6 path.
    let v4_reject = program.emit(BPF_RET_K, 0, 0, 0);
    // IPv6 side: fixed offsets, no extension headers (documented subset limit).
    let v6_type_load = program.emit(BPF_LD_H_ABS, 0, 0, ETHERTYPE_OFFSET);
    let v6_type_jeq = program.emit(BPF_JMP_JEQ_K, 0, 0, ETHERTYPE_IPV6);
    let v6_nh_load = program.emit(BPF_LD_B_ABS, 0, 0, IPV6_NEXT_HEADER_OFFSET);
    let v6_tcp = program.emit(BPF_JMP_JEQ_K, 0, 0, u32::from(IPPROTO_TCP));
    let v6_udp = program.emit(BPF_JMP_JEQ_K, 0, 0, u32::from(IPPROTO_UDP));
    let v6_src_load = program.emit(BPF_LD_H_ABS, 0, 0, IPV6_SRC_PORT_OFFSET);
    let v6_src_jeq = program.emit(BPF_JMP_JEQ_K, 0, 0, u32::from(port));
    let v6_dst_load = program.emit(BPF_LD_H_ABS, 0, 0, IPV6_DST_PORT_OFFSET);
    let v6_dst_jeq = program.emit(BPF_JMP_JEQ_K, 0, 0, u32::from(port));
    let v6_reject = program.emit(BPF_RET_K, 0, 0, 0);
    let pass = program.insns.len();
    program.jump_to(v4_type_jeq, v4_proto_load, true);
    program.jump_to(v4_type_jeq, v6_type_load, false);
    program.jump_to(v4_tcp, v4_msh, true);
    program.jump_to(v4_udp, v4_msh, true);
    program.jump_to(v4_udp, v4_reject, false);
    program.jump_to(v4_src_jeq, pass, true);
    program.jump_to(v4_src_jeq, v4_dst_load, false);
    program.jump_to(v4_dst_jeq, pass, true);
    program.jump_to(v4_dst_jeq, v4_reject, false);
    program.jump_to(v6_type_jeq, v6_nh_load, true);
    program.jump_to(v6_type_jeq, v6_reject, false);
    program.jump_to(v6_tcp, v6_src_load, true);
    program.jump_to(v6_udp, v6_src_load, true);
    program.jump_to(v6_udp, v6_reject, false);
    program.jump_to(v6_src_jeq, pass, true);
    program.jump_to(v6_src_jeq, v6_dst_load, false);
    program.jump_to(v6_dst_jeq, pass, true);
    program.jump_to(v6_dst_jeq, v6_reject, false);
}

fn emit_protocol_clause(program: &mut Program, protocol: TcpUdpIcmpAny) {
    if protocol == TcpUdpIcmpAny::Any {
        // `any` adds no constraint.
        return;
    }
    let (ipv4, ipv6) = match protocol {
        TcpUdpIcmpAny::Tcp => (IPPROTO_TCP, IPPROTO_TCP),
        TcpUdpIcmpAny::Udp => (IPPROTO_UDP, IPPROTO_UDP),
        TcpUdpIcmpAny::Icmp => (IPPROTO_ICMP, IPPROTO_ICMPV6),
        TcpUdpIcmpAny::Any => return,
    };
    program.emit(BPF_LD_H_ABS, 0, 0, ETHERTYPE_OFFSET);
    let v4_type_jeq = program.emit(BPF_JMP_JEQ_K, 0, 0, ETHERTYPE_IPV4);
    let v4_proto_load = program.emit(BPF_LD_B_ABS, 0, 0, IPV4_PROTOCOL_OFFSET);
    let v4_jeq = program.emit(BPF_JMP_JEQ_K, 0, 0, u32::from(ipv4));
    let v4_reject = program.emit(BPF_RET_K, 0, 0, 0);
    let v6_type_load = program.emit(BPF_LD_H_ABS, 0, 0, ETHERTYPE_OFFSET);
    let v6_type_jeq = program.emit(BPF_JMP_JEQ_K, 0, 0, ETHERTYPE_IPV6);
    let v6_nh_load = program.emit(BPF_LD_B_ABS, 0, 0, IPV6_NEXT_HEADER_OFFSET);
    let v6_jeq = program.emit(BPF_JMP_JEQ_K, 0, 0, u32::from(ipv6));
    let v6_reject = program.emit(BPF_RET_K, 0, 0, 0);
    let pass = program.insns.len();
    program.jump_to(v4_type_jeq, v4_proto_load, true);
    program.jump_to(v4_type_jeq, v6_type_load, false);
    // A passing v4 check must skip the whole v6 block: falling into it would
    // re-check the ethertype and drop the very frame the clause accepted.
    program.jump_to(v4_jeq, pass, true);
    program.jump_to(v4_jeq, v4_reject, false);
    program.jump_to(v6_type_jeq, v6_nh_load, true);
    program.jump_to(v6_type_jeq, v6_reject, false);
    program.jump_to(v6_jeq, pass, true);
    program.jump_to(v6_jeq, v6_reject, false);
}

#[derive(Clone, Debug)]
pub struct CaptureLimits {
    pub max_packets: usize,
    /// Includes 24-byte PCAP header and 16-byte per-frame records.
    pub max_bytes: usize,
    pub duration: Duration,
    pub poll_interval: Duration,
}

impl Default for CaptureLimits {
    fn default() -> Self {
        Self {
            max_packets: 4_000,
            max_bytes: 8 * 1024 * 1024,
            duration: Duration::from_secs(60),
            poll_interval: Duration::from_millis(100),
        }
    }
}

impl CaptureLimits {
    pub fn validate(&self) -> Result<(), CaptureError> {
        if self.max_packets == 0
            || self.max_packets > MAX_LIVE_PACKETS
            || self.max_bytes < 40
            || self.max_bytes > MAX_LIVE_BYTES
            || self.duration.is_zero()
            || self.duration > MAX_LIVE_DURATION
            || self.poll_interval.is_zero()
            || self.poll_interval > MAX_POLL_INTERVAL
        {
            return Err(CaptureError::new(CaptureErrorCode::InvalidConfig,
                "capture limits exceed bounds (1..=20000 packets, 40..=16MiB, duration <=600s, poll <=250ms)"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Cancelled,
    PacketLimit,
    ByteLimit,
    DurationLimit,
}

#[derive(Clone, Copy, Debug)]
pub struct ReceivedFrame {
    pub length: usize,
    pub timestamp: SystemTime,
}

pub trait FrameSource {
    /// Return None on an idle timeout. A reported oversize length is discarded.
    fn receive(
        &mut self,
        buffer: &mut [u8],
        timeout: Duration,
    ) -> Result<Option<ReceivedFrame>, CaptureError>;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FrameProvenance {
    pub packet_index: usize,
    pub pcap_frame_offset: usize,
    pub captured_length: usize,
    pub wire_length: usize,
    /// The dissection index is derived from this exact PCAP frame, not synthesized.
    pub source: Option<String>,
    pub destination: Option<String>,
    pub stream_id: Option<String>,
}

#[derive(Debug)]
pub struct CaptureResult {
    pub interface: CaptureInterface,
    /// Original captured Ethernet frame bytes are stored only here, in original order.
    pub pcap_bytes: Vec<u8>,
    pub frame_provenance: Vec<FrameProvenance>,
    pub inventory: inventory::PassiveInventory,
    pub stop_reason: StopReason,
    pub oversized_frames_discarded: usize,
    pub duration_ms: u64,
}

/// Read the identical frame bytes that will be preserved in a future case artifact.
impl CaptureResult {
    pub fn original_frame(&self, index: usize) -> Option<&[u8]> {
        let entry = self.frame_provenance.get(index)?;
        let end = entry.pcap_frame_offset.checked_add(entry.captured_length)?;
        self.pcap_bytes.get(entry.pcap_frame_offset..end)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CaptureProgress {
    pub packets: usize,
    pub stored_pcap_bytes: usize,
    pub oversized_frames_discarded: usize,
}

/// One bounded synchronous capture run; the caller owns its cancellation flag
/// and may invoke this on a worker thread. No frames are sent or injected.
pub fn capture_from<S: FrameSource>(
    source: &mut S,
    interface: CaptureInterface,
    limits: &CaptureLimits,
    stop: &AtomicBool,
) -> Result<CaptureResult, CaptureError> {
    capture_from_with_progress(source, interface, limits, stop, |_| {})
}

/// Identical capture engine with monotonic bounded progress events for a future
/// Tauri Channel. No UI dependency or mandatory long-lived background task.
pub fn capture_from_with_progress<S: FrameSource>(
    source: &mut S,
    interface: CaptureInterface,
    limits: &CaptureLimits,
    stop: &AtomicBool,
    mut on_progress: impl FnMut(CaptureProgress),
) -> Result<CaptureResult, CaptureError> {
    limits.validate()?;
    if !interface.ethernet || interface.loopback {
        return Err(CaptureError::new(
            CaptureErrorCode::UnsupportedLinkLayer,
            "capture requires an Ethernet device",
        ));
    }
    let start = Instant::now();
    let mut pcap_bytes = Vec::with_capacity(limits.max_bytes.min(64 * 1024));
    pcap_bytes.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes());
    pcap_bytes.extend_from_slice(&2u16.to_le_bytes());
    pcap_bytes.extend_from_slice(&4u16.to_le_bytes());
    pcap_bytes.extend_from_slice(&0i32.to_le_bytes());
    pcap_bytes.extend_from_slice(&0u32.to_le_bytes());
    pcap_bytes.extend_from_slice(&(MAX_FRAME_BYTES as u32).to_le_bytes());
    pcap_bytes.extend_from_slice(&1u32.to_le_bytes()); // exact Ethernet frames (DLT_EN10MB)
    let mut frames = Vec::new();
    let mut oversized = 0usize;
    let mut buffer = [0u8; MAX_FRAME_BYTES];
    let reason = loop {
        if stop.load(Ordering::Acquire) {
            break StopReason::Cancelled;
        }
        if frames.len() >= limits.max_packets {
            break StopReason::PacketLimit;
        }
        if start.elapsed() >= limits.duration {
            break StopReason::DurationLimit;
        }
        let remaining = limits.max_bytes.saturating_sub(pcap_bytes.len());
        if remaining <= 16 {
            break StopReason::ByteLimit;
        }
        let timeout = limits
            .poll_interval
            .min(limits.duration.saturating_sub(start.elapsed()));
        if timeout.is_zero() {
            break StopReason::DurationLimit;
        }
        let received = source.receive(&mut buffer, timeout)?;
        if stop.load(Ordering::Acquire) {
            break StopReason::Cancelled;
        }
        let Some(frame) = received else { continue };
        if frame.length > MAX_FRAME_BYTES {
            oversized = oversized.saturating_add(1);
            continue;
        }
        if frame.length == 0 {
            continue;
        }
        let record_size = 16usize.saturating_add(frame.length);
        if record_size > remaining {
            break StopReason::ByteLimit;
        }
        let since_epoch = frame.timestamp.duration_since(UNIX_EPOCH).map_err(|_| {
            CaptureError::new(
                CaptureErrorCode::Io,
                "capture timestamp predates Unix epoch",
            )
        })?;
        let secs = u32::try_from(since_epoch.as_secs()).map_err(|_| {
            CaptureError::new(
                CaptureErrorCode::Io,
                "capture timestamp exceeds classic PCAP timestamp range",
            )
        })?;
        let offset = pcap_bytes.len().saturating_add(16);
        pcap_bytes.extend_from_slice(&secs.to_le_bytes());
        pcap_bytes.extend_from_slice(&since_epoch.subsec_micros().to_le_bytes());
        pcap_bytes.extend_from_slice(&(frame.length as u32).to_le_bytes());
        pcap_bytes.extend_from_slice(&(frame.length as u32).to_le_bytes());
        pcap_bytes.extend_from_slice(&buffer[..frame.length]);
        frames.push(FrameProvenance {
            packet_index: frames.len(),
            pcap_frame_offset: offset,
            captured_length: frame.length,
            wire_length: frame.length,
            source: None,
            destination: None,
            stream_id: None,
        });
        on_progress(CaptureProgress {
            packets: frames.len(),
            stored_pcap_bytes: pcap_bytes.len(),
            oversized_frames_discarded: oversized,
        });
    };
    let parsed =
        parse_capture(&pcap_bytes).map_err(|e| CaptureError::new(CaptureErrorCode::Parse, e))?;
    if parsed.malformed_tail || parsed.packets.len() != frames.len() {
        return Err(CaptureError::new(
            CaptureErrorCode::Parse,
            "captured PCAP failed exact frame identity validation",
        ));
    }
    for (packet, span) in parsed.packets.iter().zip(&mut frames) {
        if packet.offset != span.pcap_frame_offset || packet.incl_len != span.captured_length {
            return Err(CaptureError::new(
                CaptureErrorCode::Parse,
                "captured packet offset differs from original bytes",
            ));
        }
        if packet.dissected.source.parse::<std::net::IpAddr>().is_ok()
            && packet
                .dissected
                .destination
                .parse::<std::net::IpAddr>()
                .is_ok()
        {
            span.source = Some(packet.dissected.source.clone());
            span.destination = Some(packet.dissected.destination.clone());
        }
        span.stream_id = packet.dissected.stream_id.clone();
    }
    Ok(CaptureResult {
        interface,
        inventory: inventory::observe(&parsed.packets),
        pcap_bytes,
        frame_provenance: frames,
        stop_reason: reason,
        oversized_frames_discarded: oversized,
        duration_ms: start.elapsed().as_millis().min(u64::MAX as u128) as u64,
    })
}

/// Linux AF_PACKET, non-promiscuous Ethernet receive. No shell commands,
/// third-party utilities, implicit privilege escalation or interface changes.
pub fn capture_linux(
    interface_name: &str,
    limits: &CaptureLimits,
    cancel: &AtomicBool,
) -> Result<CaptureResult, CaptureError> {
    capture_linux_with_progress(interface_name, limits, cancel, |_| {})
}

/// Report only bounded counts during the run. The original capture is returned
/// once, after its offsets and inventory have been validated.
#[cfg(target_os = "linux")]
pub fn capture_linux_with_progress(
    interface_name: &str,
    limits: &CaptureLimits,
    cancel: &AtomicBool,
    progress: impl FnMut(CaptureProgress),
) -> Result<CaptureResult, CaptureError> {
    capture_linux_with_progress_filtered(interface_name, None, limits, cancel, progress)
}

/// Linux capture with an optional kernel-side filter: the bounded predicate is
/// compiled to a classic BPF program and attached to the AF_PACKET socket, so
/// filtered-out frames never reach the bounded engine or the evidence budget.
#[cfg(target_os = "linux")]
pub fn capture_linux_with_progress_filtered(
    interface_name: &str,
    filter: Option<&CaptureFilter>,
    limits: &CaptureLimits,
    cancel: &AtomicBool,
    progress: impl FnMut(CaptureProgress),
) -> Result<CaptureResult, CaptureError> {
    limits.validate()?;
    let selected = select_interface(&discover_interfaces()?, interface_name)?;
    let mut source = linux_socket::LinuxSocket::open(selected.index)?;
    if let Some(filter) = filter {
        source.attach_filter(&filter.to_bpf_program())?;
    }
    capture_from_with_progress(&mut source, selected, limits, cancel, progress)
}

/// Uses the CyberDeck-owned native driver when actually installed and
/// authorized; Windows adapter discovery alone does not enable capture.
#[cfg(target_os = "windows")]
pub fn windows_interface_alias(index: u32) -> Option<String> {
    crate::infrastructure::windows_capture::interface_alias(index)
}

#[cfg(target_os = "windows")]
pub fn authorized_windows_interface_luid(interface_name: &str) -> Result<u64, CaptureError> {
    let selected = select_interface(&discover_interfaces()?, interface_name)?;
    crate::infrastructure::windows_capture::interface_luid(selected.index)
}

#[cfg(target_os = "windows")]
pub fn capture_windows_with_progress(
    interface_name: &str,
    expected_luid: u64,
    limits: &CaptureLimits,
    cancel: &AtomicBool,
    progress: impl FnMut(CaptureProgress),
) -> Result<CaptureResult, CaptureError> {
    crate::infrastructure::windows_capture::capture_with_progress(
        interface_name,
        expected_luid,
        limits,
        cancel,
        progress,
    )
}

#[cfg(target_os = "windows")]
pub fn probe_windows_capture() -> Result<(), CaptureError> {
    crate::infrastructure::windows_capture::probe_driver()
}

/// macOS routes through this pre-registered session entry point (the
/// name predates macOS support); the BPF backend honors the identical
/// bounded engine, caps and progress contract as the Linux path.
#[cfg(target_os = "macos")]
pub fn capture_linux_with_progress(
    interface_name: &str,
    limits: &CaptureLimits,
    cancel: &AtomicBool,
    progress: impl FnMut(CaptureProgress),
) -> Result<CaptureResult, CaptureError> {
    capture_macos_with_progress(interface_name, limits, cancel, progress)
}

/// macOS alias for the session layer: the BPF backend installs the filter
/// program (BIOCSSETF) before the engine reads its first batch.
#[cfg(target_os = "macos")]
pub fn capture_linux_with_progress_filtered(
    interface_name: &str,
    filter: Option<&CaptureFilter>,
    limits: &CaptureLimits,
    cancel: &AtomicBool,
    progress: impl FnMut(CaptureProgress),
) -> Result<CaptureResult, CaptureError> {
    capture_macos_with_progress_filtered(interface_name, filter, limits, cancel, progress)
}

/// Windows has no kernel filter support this arc; an operator-supplied
/// filter is refused honestly instead of being silently ignored.
#[cfg(target_os = "windows")]
pub fn capture_linux_with_progress_filtered(
    _interface_name: &str,
    filter: Option<&CaptureFilter>,
    _limits: &CaptureLimits,
    _cancel: &AtomicBool,
    _progress: impl FnMut(CaptureProgress),
) -> Result<CaptureResult, CaptureError> {
    let _ = filter;
    Err(CaptureError::new(
        CaptureErrorCode::UnsupportedPlatform,
        "capture filters are not supported on the Windows capture backend",
    ))
}

/// Explicit macOS BPF (/dev/bpf) entry point for platform-aware callers.
/// Passive receive only: no frames are ever sent or injected.
#[cfg(target_os = "macos")]
pub fn capture_macos_with_progress(
    interface_name: &str,
    limits: &CaptureLimits,
    cancel: &AtomicBool,
    progress: impl FnMut(CaptureProgress),
) -> Result<CaptureResult, CaptureError> {
    capture_macos_with_progress_filtered(interface_name, None, limits, cancel, progress)
}

/// macOS capture with an optional kernel-side BPF filter installed through
/// BIOCSSETF before the bounded engine reads its first batch.
#[cfg(target_os = "macos")]
pub fn capture_macos_with_progress_filtered(
    interface_name: &str,
    filter: Option<&CaptureFilter>,
    limits: &CaptureLimits,
    cancel: &AtomicBool,
    progress: impl FnMut(CaptureProgress),
) -> Result<CaptureResult, CaptureError> {
    crate::infrastructure::bpf_capture::capture_with_progress_filtered(
        interface_name,
        filter,
        limits,
        cancel,
        progress,
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn capture_linux_with_progress(
    _interface_name: &str,
    _limits: &CaptureLimits,
    _cancel: &AtomicBool,
    _progress: impl FnMut(CaptureProgress),
) -> Result<CaptureResult, CaptureError> {
    Err(CaptureError::new(
        CaptureErrorCode::UnsupportedPlatform,
        "native live capture is currently supported only on Linux and macOS",
    ))
}

#[cfg(target_os = "linux")]
mod linux_socket {
    use super::*;
    use std::ffi::c_void;
    use std::os::raw::{c_int, c_short};

    const AF_PACKET: c_int = 17;
    const SOCK_RAW: c_int = 3;
    const SOCK_CLOEXEC: c_int = 0o2000000;
    const ETH_P_ALL: u16 = 3;
    const POLLIN: c_short = 1;
    const POLLERR: c_short = 8;
    const POLLHUP: c_short = 16;
    const MSG_TRUNC: c_int = 0x20;
    const SOL_SOCKET: c_int = 1;
    const SO_ATTACH_FILTER: c_int = 1;

    #[repr(C)]
    struct SockAddrLl {
        family: u16,
        protocol: u16,
        ifindex: c_int,
        hatype: u16,
        pkttype: u8,
        halen: u8,
        addr: [u8; 8],
    }
    #[repr(C)]
    struct PollFd {
        fd: c_int,
        events: c_short,
        revents: c_short,
    }
    /// Linux `struct sock_fprog`; the filter program must outlive only the
    /// setsockopt call, which copies it into the kernel.
    #[repr(C)]
    struct SockFprog {
        len: u16,
        filter: *const BpfInstruction,
    }

    unsafe extern "C" {
        fn socket(domain: c_int, typ: c_int, protocol: c_int) -> c_int;
        fn bind(fd: c_int, address: *const c_void, length: u32) -> c_int;
        fn recv(fd: c_int, buffer: *mut c_void, length: usize, flags: c_int) -> isize;
        fn poll(fds: *mut PollFd, nfds: usize, timeout: c_int) -> c_int;
        fn setsockopt(
            fd: c_int,
            level: c_int,
            option_name: c_int,
            value: *const c_void,
            option_len: u32,
        ) -> c_int;
        fn close(fd: c_int) -> c_int;
    }

    pub(super) struct LinuxSocket {
        fd: c_int,
    }
    impl Drop for LinuxSocket {
        fn drop(&mut self) {
            unsafe {
                close(self.fd);
            }
        }
    }
    impl LinuxSocket {
        pub(super) fn open(index: u32) -> Result<Self, CaptureError> {
            let protocol = ETH_P_ALL.to_be();
            let fd = unsafe { socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, c_int::from(protocol)) };
            if fd < 0 {
                return Err(CaptureError::io(
                    "open AF_PACKET raw capture socket",
                    io::Error::last_os_error(),
                ));
            }
            let source = Self { fd };
            let address = SockAddrLl {
                family: AF_PACKET as u16,
                protocol,
                ifindex: c_int::try_from(index).map_err(|_| {
                    CaptureError::new(CaptureErrorCode::InvalidConfig, "interface index overflow")
                })?,
                hatype: 0,
                pkttype: 0,
                halen: 0,
                addr: [0; 8],
            };
            let rc = unsafe {
                bind(
                    fd,
                    (&raw const address).cast(),
                    std::mem::size_of::<SockAddrLl>() as u32,
                )
            };
            if rc != 0 {
                return Err(CaptureError::io(
                    "bind AF_PACKET to selected interface",
                    io::Error::last_os_error(),
                ));
            }
            Ok(source)
        }

        /// Attach a classic BPF program (SO_ATTACH_FILTER) so the kernel drops
        /// frames outside the bounded capture-filter predicate before they
        /// reach the bounded engine. Programs built by CaptureFilter are tens
        /// of instructions, far under the kernel's per-filter limit; the u16
        /// length cast is still guarded instead of assumed.
        pub(super) fn attach_filter(&self, program: &[BpfInstruction]) -> Result<(), CaptureError> {
            let Ok(len) = u16::try_from(program.len()) else {
                return Err(CaptureError::new(
                    CaptureErrorCode::InvalidConfig,
                    "capture filter program exceeds the kernel instruction limit",
                ));
            };
            let fprog = SockFprog {
                len,
                filter: program.as_ptr(),
            };
            let rc = unsafe {
                setsockopt(
                    self.fd,
                    SOL_SOCKET,
                    SO_ATTACH_FILTER,
                    (&raw const fprog).cast(),
                    std::mem::size_of::<SockFprog>() as u32,
                )
            };
            if rc != 0 {
                return Err(CaptureError::io(
                    "attach AF_PACKET capture filter",
                    io::Error::last_os_error(),
                ));
            }
            Ok(())
        }
    }
    impl FrameSource for LinuxSocket {
        fn receive(
            &mut self,
            buffer: &mut [u8],
            timeout: Duration,
        ) -> Result<Option<ReceivedFrame>, CaptureError> {
            let mut descriptor = PollFd {
                fd: self.fd,
                events: POLLIN,
                revents: 0,
            };
            let timeout_ms = timeout.as_millis().max(1).min(c_int::MAX as u128) as c_int;
            let polled = unsafe { poll(&raw mut descriptor, 1, timeout_ms) };
            if polled == 0 {
                return Ok(None);
            }
            if polled < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    return Ok(None);
                }
                return Err(CaptureError::io("poll selected capture interface", e));
            }
            if descriptor.revents & (POLLERR | POLLHUP) != 0 {
                return Err(CaptureError::new(
                    CaptureErrorCode::Io,
                    "selected capture interface closed or reported an error",
                ));
            }
            if descriptor.revents & POLLIN == 0 {
                return Ok(None);
            }
            // MSG_TRUNC returns the full wire length so snaplen truncations
            // are discarded rather than falsely labeled as original frames.
            let size =
                unsafe { recv(self.fd, buffer.as_mut_ptr().cast(), buffer.len(), MSG_TRUNC) };
            if size < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted || e.kind() == io::ErrorKind::WouldBlock {
                    return Ok(None);
                }
                return Err(CaptureError::io("receive native Ethernet frame", e));
            }
            Ok(Some(ReceivedFrame {
                length: size as usize,
                timestamp: SystemTime::now(),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Arc;

    struct Fixture {
        frames: VecDeque<Vec<u8>>,
        stop_after: Option<usize>,
        received: usize,
        stop_ptr: Option<Arc<AtomicBool>>,
    }
    impl FrameSource for Fixture {
        fn receive(
            &mut self,
            out: &mut [u8],
            _timeout: Duration,
        ) -> Result<Option<ReceivedFrame>, CaptureError> {
            let Some(frame) = self.frames.pop_front() else {
                return Ok(None);
            };
            let n = frame.len();
            let copied = n.min(out.len());
            out[..copied].copy_from_slice(&frame[..copied]);
            self.received += 1;
            if self.stop_after == Some(self.received) {
                if let Some(flag) = self.stop_ptr.as_ref() {
                    flag.store(true, Ordering::Release);
                }
            }
            Ok(Some(ReceivedFrame {
                length: n,
                timestamp: UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            }))
        }
    }
    fn ethernet_ipv4() -> Vec<u8> {
        let mut frame = vec![0; 12];
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&[
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 1, 0, 0, 192, 0, 2, 10, 198, 51, 100, 7,
        ]);
        frame
    }
    fn selected() -> CaptureInterface {
        CaptureInterface {
            name: "fixture0".into(),
            index: 2,
            ethernet: true,
            up: true,
            loopback: false,
        }
    }
    fn fixture(frames: Vec<Vec<u8>>) -> Fixture {
        Fixture {
            frames: frames.into(),
            stop_after: None,
            received: 0,
            stop_ptr: None,
        }
    }
    #[test]
    fn captured_frames_roundtrip_from_original_pcap_and_observe_hosts() {
        let frame = ethernet_ipv4();
        let mut src = fixture(vec![frame.clone()]);
        let limits = CaptureLimits {
            max_packets: 1,
            ..Default::default()
        };
        let result = capture_from(&mut src, selected(), &limits, &AtomicBool::new(false)).unwrap();
        assert_eq!(result.stop_reason, StopReason::PacketLimit);
        assert_eq!(result.frame_provenance.len(), 1);
        assert_eq!(result.frame_provenance[0].pcap_frame_offset, 40);
        assert_eq!(&result.pcap_bytes[40..], frame.as_slice());
        assert_eq!(result.inventory.hosts.len(), 2);
        assert_eq!(result.inventory.packets_scanned, 1);
        assert_eq!(result.inventory.hosts[0].first_packet_index, 0);
    }
    fn ethernet_udp(
        source: [u8; 4],
        destination: [u8; 4],
        source_port: u16,
        destination_port: u16,
    ) -> Vec<u8> {
        let mut bytes = vec![0u8; 12];
        bytes.extend_from_slice(&0x0800u16.to_be_bytes());
        bytes.extend_from_slice(&[0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0]);
        bytes.extend_from_slice(&source);
        bytes.extend_from_slice(&destination);
        bytes.extend_from_slice(&source_port.to_be_bytes());
        bytes.extend_from_slice(&destination_port.to_be_bytes());
        bytes.extend_from_slice(&8u16.to_be_bytes());
        bytes.extend_from_slice(&[0, 0]);
        bytes
    }

    #[test]
    fn bidirectional_udp_flow_links_each_original_frame_to_inventory() {
        let a = ethernet_udp([192, 0, 2, 1], [198, 51, 100, 2], 43210, 53);
        let b = ethernet_udp([198, 51, 100, 2], [192, 0, 2, 1], 53, 43210);
        let mut source = fixture(vec![a.clone(), b.clone()]);
        let limits = CaptureLimits {
            max_packets: 2,
            ..Default::default()
        };
        let mut progress = Vec::new();
        let result = capture_from_with_progress(
            &mut source,
            selected(),
            &limits,
            &AtomicBool::new(false),
            |event| progress.push(event),
        )
        .unwrap();
        assert_eq!(result.inventory.hosts.len(), 2);
        assert_eq!(result.inventory.flows.len(), 1);
        assert_eq!(result.inventory.flows[0].packet_count, 2);
        assert_eq!(result.inventory.flows[0].first_packet_index, 0);
        assert_eq!(result.inventory.flows[0].last_packet_index, 1);
        assert_eq!(result.original_frame(0), Some(a.as_slice()));
        assert_eq!(result.original_frame(1), Some(b.as_slice()));
        assert_eq!(result.original_frame(2), None);
        assert_eq!(
            result.frame_provenance[0].source.as_deref(),
            Some("192.0.2.1")
        );
        assert_eq!(
            result.frame_provenance[1].destination.as_deref(),
            Some("192.0.2.1")
        );
        let stream = result.frame_provenance[0].stream_id.as_deref();
        assert!(stream.is_some());
        assert_eq!(stream, result.frame_provenance[1].stream_id.as_deref());
        assert_eq!(progress.len(), 2);
        assert_eq!((progress[0].packets, progress[1].packets), (1, 2));
        assert!(progress[1].stored_pcap_bytes > progress[0].stored_pcap_bytes);
        assert_eq!(progress[1].stored_pcap_bytes, result.pcap_bytes.len());
    }

    #[test]
    fn stop_before_start_does_not_consume_frames() {
        let stop = AtomicBool::new(true);
        let mut src = fixture(vec![ethernet_ipv4()]);
        let result = capture_from(&mut src, selected(), &CaptureLimits::default(), &stop).unwrap();
        assert_eq!(result.stop_reason, StopReason::Cancelled);
        assert_eq!(src.received, 0);
        assert_eq!(result.pcap_bytes.len(), 24);
    }
    #[test]
    fn cancellation_mid_stream_is_terminal_without_promoting_inflight_frame() {
        let stop = Arc::new(AtomicBool::new(false));
        let mut src = fixture(vec![ethernet_ipv4(), ethernet_ipv4()]);
        src.stop_after = Some(1);
        src.stop_ptr = Some(Arc::clone(&stop));
        let result = capture_from(&mut src, selected(), &CaptureLimits::default(), &stop).unwrap();
        assert_eq!(result.stop_reason, StopReason::Cancelled);
        assert!(result.frame_provenance.is_empty());
        assert_eq!(src.received, 1);
    }
    #[test]
    fn byte_budget_never_keeps_half_record_and_reports_limit() {
        let mut src = fixture(vec![ethernet_ipv4()]);
        let limits = CaptureLimits {
            max_bytes: 40,
            ..Default::default()
        };
        let result = capture_from(&mut src, selected(), &limits, &AtomicBool::new(false)).unwrap();
        assert_eq!(result.stop_reason, StopReason::ByteLimit);
        assert_eq!(result.pcap_bytes.len(), 24);
        assert!(result.frame_provenance.is_empty());
    }
    #[test]
    fn oversized_frame_is_not_misrepresented_as_original_bytes() {
        let mut source = fixture(vec![vec![0u8; MAX_FRAME_BYTES + 1], ethernet_ipv4()]);
        let limits = CaptureLimits {
            max_packets: 1,
            ..Default::default()
        };
        let result =
            capture_from(&mut source, selected(), &limits, &AtomicBool::new(false)).unwrap();
        assert_eq!(result.oversized_frames_discarded, 1);
        assert_eq!(result.frame_provenance.len(), 1);
        assert_eq!(result.original_frame(0), Some(ethernet_ipv4().as_slice()));
        assert_eq!(result.stop_reason, StopReason::PacketLimit);
    }

    #[test]
    fn cancellation_after_first_stored_frame_retains_only_that_frame() {
        let cancel = AtomicBool::new(false);
        let original = ethernet_ipv4();
        let mut source = fixture(vec![original.clone(), original.clone()]);
        let mut progress_count = 0;
        let result = capture_from_with_progress(
            &mut source,
            selected(),
            &CaptureLimits::default(),
            &cancel,
            |progress| {
                progress_count += 1;
                assert_eq!(progress.packets, 1);
                cancel.store(true, Ordering::Release);
            },
        )
        .unwrap();
        assert_eq!(result.stop_reason, StopReason::Cancelled);
        assert_eq!(progress_count, 1);
        assert_eq!(source.received, 1);
        assert_eq!(result.original_frame(0), Some(original.as_slice()));
        assert_eq!(result.original_frame(1), None);
    }

    #[test]
    fn permission_denied_is_structured_and_explains_linux_capability() {
        let error = CaptureError::io("open AF_PACKET", io::Error::from_raw_os_error(1));
        assert_eq!(error.code, CaptureErrorCode::PermissionDenied);
        assert!(error.message.contains("CAP_NET_RAW"));
    }

    #[test]
    fn idle_capture_stops_at_duration_limit_without_creating_fake_packets() {
        struct Idle;
        impl FrameSource for Idle {
            fn receive(
                &mut self,
                _buf: &mut [u8],
                timeout: Duration,
            ) -> Result<Option<ReceivedFrame>, CaptureError> {
                std::thread::sleep(timeout);
                Ok(None)
            }
        }
        let limits = CaptureLimits {
            duration: Duration::from_millis(3),
            poll_interval: Duration::from_millis(1),
            ..Default::default()
        };
        let result = capture_from(&mut Idle, selected(), &limits, &AtomicBool::new(false)).unwrap();
        assert_eq!(result.stop_reason, StopReason::DurationLimit);
        assert!(result.frame_provenance.is_empty());
        assert_eq!(result.pcap_bytes.len(), 24);
        assert_eq!(result.inventory.packets_scanned, 0);
    }

    #[test]
    fn strict_limits_reject_bad_config_before_receiving() {
        let mut src = fixture(vec![ethernet_ipv4()]);
        let limits = CaptureLimits {
            max_packets: MAX_LIVE_PACKETS + 1,
            ..Default::default()
        };
        assert_eq!(
            capture_from(&mut src, selected(), &limits, &AtomicBool::new(false))
                .unwrap_err()
                .code,
            CaptureErrorCode::InvalidConfig
        );
        assert_eq!(src.received, 0);
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn interface_discovery_and_selection_use_kernel_metadata() {
        let temp = tempfile_directory();
        std::fs::create_dir_all(temp.join("eth-test")).unwrap();
        std::fs::write(temp.join("eth-test/ifindex"), "7\n").unwrap();
        std::fs::write(temp.join("eth-test/type"), "1\n").unwrap();
        std::fs::write(temp.join("eth-test/flags"), "0x1003\n").unwrap();
        std::fs::create_dir_all(temp.join("lo")).unwrap();
        std::fs::write(temp.join("lo/ifindex"), "1\n").unwrap();
        std::fs::write(temp.join("lo/type"), "772\n").unwrap();
        std::fs::write(temp.join("lo/flags"), "0x9\n").unwrap();
        let list = discover_from(&temp).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(select_interface(&list, "eth-test").unwrap().index, 7);
        assert_eq!(
            select_interface(&list, "lo").unwrap_err().code,
            CaptureErrorCode::UnsupportedLinkLayer
        );
        assert_eq!(
            select_interface(&list, "../eth-test").unwrap_err().code,
            CaptureErrorCode::InterfaceNotFound
        );
        std::fs::remove_dir_all(&temp).unwrap();
    }
    #[cfg(target_os = "linux")]
    fn tempfile_directory() -> std::path::PathBuf {
        use std::sync::atomic::AtomicU64;
        static NEXT: AtomicU64 = AtomicU64::new(1);
        std::env::temp_dir().join(format!(
            "cyberdeck-live-iface-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    // --- bounded capture-filter model ---------------------------------------

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn filter(text: &str) -> CaptureFilter {
        CaptureFilter::parse(text).expect("valid filter fixture")
    }

    #[test]
    fn filter_parse_accepts_the_bounded_subset() {
        assert!(CaptureFilter::parse("").unwrap().is_empty());
        assert!(CaptureFilter::parse("   ").unwrap().is_empty());
        assert_eq!(
            filter("host 10.0.0.1"),
            CaptureFilter {
                host: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
                port: None,
                protocol: None,
            }
        );
        assert_eq!(filter("port 443").port(), Some(443));
        assert_eq!(
            filter("tcp and host 10.0.0.1").protocol(),
            Some(TcpUdpIcmpAny::Tcp)
        );
        // `and` is optional whitespace-level sugar; both forms parse equally.
        assert_eq!(filter("udp port 53"), filter("udp and port 53"));
        assert_eq!(
            filter("icmp"),
            CaptureFilter {
                host: None,
                port: None,
                protocol: Some(TcpUdpIcmpAny::Icmp),
            }
        );
        assert_eq!(filter("any").protocol(), Some(TcpUdpIcmpAny::Any));
        assert_eq!(filter("  tcp   and   host 10.0.0.1  "), filter("tcp and host 10.0.0.1"));
        let v6 = filter("host 2001:db8::1").host();
        assert_eq!(
            v6,
            Some(IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()))
        );
        // `any` carries no effective constraint.
        assert!(filter("any").is_empty());
    }

    #[test]
    fn filter_parse_refuses_everything_outside_the_subset() {
        for (text, expected) in [
            ("arp", "unsupported capture filter term 'arp'"),
            ("or", "term 'or' is not supported"),
            ("not tcp", "not supported"),
            ("vlan", "unsupported capture filter term 'vlan'"),
            ("and host 10.0.0.1", "'and' must join two terms"),
            ("host 10.0.0.1 and", "'and' must join two terms"),
            ("host", "'host' requires"),
            ("host 10.0.0.999", "not an IPv4 or IPv6 address"),
            ("host 2001:db8::zzzz", "not an IPv4 or IPv6 address"),
            ("port", "'port' requires"),
            ("port 65536", "not a number 0-65535"),
            ("port https", "not a number 0-65535"),
            ("host 10.0.0.1 host 10.0.0.2", "at most one 'host' term"),
            ("port 443 port 53", "at most one 'port' term"),
            ("tcp udp", "at most one protocol term"),
            ("host 10.0.0.1; rm -rf /", "is not an IPv4 or IPv6 address"),
        ] {
            let error = CaptureFilter::parse(text).expect_err(text);
            assert_eq!(error.code, CaptureErrorCode::InvalidConfig, "{text}");
            assert!(
                error.message.contains(expected),
                "filter '{text}' refused with unexpected message: {}",
                error.message
            );
        }
        let long = "x".repeat(MAX_FILTER_CHARS + 1);
        assert_eq!(
            CaptureFilter::parse(&long).unwrap_err().code,
            CaptureErrorCode::InvalidConfig
        );
        let many = "tcp and ".repeat(MAX_FILTER_TERMS);
        assert_eq!(
            CaptureFilter::parse(&many).unwrap_err().code,
            CaptureErrorCode::InvalidConfig
        );
    }

    /// One IPv4 TCP frame to host 10.0.0.2 port 443, source 10.0.0.1:50000.
    fn ethernet_ipv4_tcp(
        source: [u8; 4],
        destination: [u8; 4],
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Vec<u8> {
        let mut frame = vec![0u8; 14]; // Ethernet header
        frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        frame.push(0x45); // version 4, IHL 5
        // tos, total length, identification, flags+fragment offset.
        frame.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0]);
        frame.push(64); // ttl
        frame.push(protocol);
        frame.extend_from_slice(&[0, 0]); // checksum
        frame.extend_from_slice(&source);
        frame.extend_from_slice(&destination);
        frame.extend_from_slice(&src_port.to_be_bytes());
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame.extend_from_slice(&[0, 0]);
        frame
    }

    fn ethernet_ipv6(next_header: u8, dst: Ipv6Addr, dst_port: u16) -> Vec<u8> {
        let mut frame = vec![0u8; 14];
        frame[12..14].copy_from_slice(&0x86ddu16.to_be_bytes());
        // version/traffic-class/flow-label, payload length, next header, hop limit.
        frame.extend_from_slice(&[0x60, 0, 0, 0, 0, 0]);
        frame.push(next_header);
        frame.push(64);
        frame.extend_from_slice(&[0u8; 16]); // source
        frame.extend_from_slice(&dst.octets());
        frame.extend_from_slice(&[0x30, 0x39]); // src port 12345
        frame.extend_from_slice(&dst_port.to_be_bytes());
        frame
    }

    fn ethernet_arp() -> Vec<u8> {
        let mut frame = vec![0xff; 6];
        frame.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
        frame.extend_from_slice(&0x0806u16.to_be_bytes());
        frame.extend_from_slice(&[0u8; 28]);
        frame
    }

    #[test]
    fn filter_predicate_evaluates_original_ethernet_frames() {
        let tcp = ethernet_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 50_000, 443, IPPROTO_TCP);
        let udp = ethernet_ipv4_tcp([10, 0, 0, 2], [10, 0, 0, 1], 53, 50_000, IPPROTO_UDP);
        let icmp = ethernet_ipv4_tcp([10, 0, 0, 9], [10, 0, 0, 2], 0, 0, IPPROTO_ICMP);
        let arp = ethernet_arp();
        let v6 = ethernet_ipv6(IPPROTO_TCP, "2001:db8::1".parse().unwrap(), 443);

        let host = filter("host 10.0.0.2");
        assert!(host.matches_ethernet(&tcp));
        assert!(host.matches_ethernet(&udp));
        assert!(host.matches_ethernet(&icmp));
        // Truncated below the address fields: nothing can match.
        assert!(!host.matches_ethernet(&icmp[..20]));
        assert!(!host.matches_ethernet(&arp), "non-IP frames match no host clause");
        assert!(!host.matches_ethernet(&v6));

        let port = filter("port 443");
        assert!(port.matches_ethernet(&tcp));
        assert!(!port.matches_ethernet(&udp), "udp/53 does not carry port 443");
        assert!(!port.matches_ethernet(&icmp), "non-TCP/UDP frames match no port clause");
        assert!(!port.matches_ethernet(&arp));

        let tcp_only = filter("tcp");
        assert!(tcp_only.matches_ethernet(&tcp));
        assert!(!tcp_only.matches_ethernet(&udp));
        assert!(tcp_only.matches_ethernet(&v6), "tcp matches TCP over IPv6");

        let v6_host = filter("host 2001:db8::1");
        assert!(v6_host.matches_ethernet(&v6));
        assert!(!v6_host.matches_ethernet(&tcp), "a v6 host never matches a v4 frame");

        // Conjunctions AND their clauses.
        let combined = filter("tcp and host 10.0.0.1 and port 443");
        assert!(combined.matches_ethernet(&tcp));
        assert!(!combined.matches_ethernet(&udp));
        // Source address is 10.0.0.1 on the TCP frame; flipping the host clause
        // target must reject the same frame.
        let other_host = filter("tcp and host 10.0.0.7");
        assert!(!other_host.matches_ethernet(&tcp));

        // Empty filter accepts everything Ethernet-side, including ARP.
        assert!(CaptureFilter::default().matches_ethernet(&arp));
        // Truncated frames never match bounded clauses.
        assert!(!filter("host 10.0.0.2").matches_ethernet(&tcp[..18]));
    }

    #[test]
    fn ipv4_variable_ihl_is_honored_by_the_port_clause() {
        // IHL 6 (24-byte header, one option word): transport ports sit at 14+24.
        let mut frame = ethernet_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 50_000, 443, IPPROTO_TCP);
        frame[14] = 0x46;
        // Insert one option word after the fixed header, shifting the ports.
        let mut with_option = frame[..26].to_vec();
        with_option.extend_from_slice(&[1, 1, 1, 1]); // NOP option
        with_option.extend_from_slice(&frame[26..]);
        assert!(filter("port 443").matches_ethernet(&with_option));
        // IHL below the 20-byte minimum never matches (malformed frame).
        frame[14] = 0x44;
        assert!(!filter("port 443").matches_ethernet(&frame));
    }

    /// Minimal classic-BPF interpreter mirroring the kernel semantics the
    /// builder relies on: ABS/IND loads are big-endian and an out-of-bounds
    /// load drops the packet; MSH sets X from (byte & 0xf) << 2; JEQ takes jt
    /// when A == k; RET k accepts k bytes (0 = drop).
    fn run_bpf(program: &[BpfInstruction], packet: &[u8]) -> u32 {
        let mut a: u32 = 0;
        let mut x: usize = 0;
        let mut pc = 0usize;
        loop {
            let instruction = program.get(pc).expect("program ran past its end");
            pc += 1;
            match instruction.code {
                BPF_LD_W_ABS | BPF_LD_H_ABS | BPF_LD_B_ABS => {
                    let width = match instruction.code {
                        BPF_LD_W_ABS => 4,
                        BPF_LD_H_ABS => 2,
                        _ => 1,
                    };
                    let Some(value) = load(packet, instruction.k as usize, width) else {
                        return 0;
                    };
                    a = value;
                }
                BPF_LD_H_IND => {
                    let Some(value) = load(packet, x + instruction.k as usize, 2) else {
                        return 0;
                    };
                    a = value;
                }
                BPF_LDX_B_MSH => {
                    let Some(byte) = packet.get(instruction.k as usize) else {
                        return 0;
                    };
                    x = usize::from(byte & 0x0f) << 2;
                }
                BPF_JMP_JEQ_K => {
                    pc += if a == instruction.k {
                        usize::from(instruction.jt)
                    } else {
                        usize::from(instruction.jf)
                    };
                }
                BPF_RET_K => {
                    return instruction.k;
                }
                other => panic!("interpreter does not implement opcode {other:#x}"),
            }
        }
    }

    fn load(packet: &[u8], at: usize, width: usize) -> Option<u32> {
        let slice = packet.get(at..at.checked_add(width)?)?;
        // Big-endian right-alignment: the bytes read land at the END of the
        // word so a 16-bit load yields the 16-bit value, not value << 16.
        let mut bytes = [0u8; 4];
        bytes[4 - width..].copy_from_slice(slice);
        Some(u32::from_be_bytes(bytes))
    }

    #[test]
    fn bpf_program_implements_the_reference_predicate() {
        let frames: Vec<Vec<u8>> = vec![
            ethernet_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 50_000, 443, IPPROTO_TCP),
            ethernet_ipv4_tcp([10, 0, 0, 2], [10, 0, 0, 1], 53, 50_000, IPPROTO_UDP),
            ethernet_ipv4_tcp([192, 0, 2, 9], [198, 51, 100, 2], 1_234, 5_678, IPPROTO_TCP),
            ethernet_ipv4_tcp([10, 0, 0, 9], [10, 0, 0, 2], 0, 0, IPPROTO_ICMP),
            ethernet_ipv6(IPPROTO_TCP, "2001:db8::1".parse().unwrap(), 443),
            ethernet_ipv6(IPPROTO_UDP, "2001:db8::2".parse().unwrap(), 53),
            ethernet_arp(),
            Vec::new(),
            vec![0x45; 15],
        ];
        let filters = [
            CaptureFilter::parse("").unwrap(),
            CaptureFilter::parse("host 10.0.0.1").unwrap(),
            CaptureFilter::parse("host 10.0.0.2").unwrap(),
            CaptureFilter::parse("host 2001:db8::1").unwrap(),
            CaptureFilter::parse("host 2001:db8::2").unwrap(),
            CaptureFilter::parse("port 443").unwrap(),
            CaptureFilter::parse("port 53").unwrap(),
            CaptureFilter::parse("tcp").unwrap(),
            CaptureFilter::parse("udp").unwrap(),
            CaptureFilter::parse("icmp").unwrap(),
            CaptureFilter::parse("any").unwrap(),
            CaptureFilter::parse("tcp and host 10.0.0.1").unwrap(),
            CaptureFilter::parse("tcp and host 10.0.0.1 and port 443").unwrap(),
            CaptureFilter::parse("udp and port 53").unwrap(),
            CaptureFilter::parse("tcp and host 2001:db8::1 and port 443").unwrap(),
            CaptureFilter::parse("icmp and host 10.0.0.2").unwrap(),
        ];
        for (index, parsed) in filters.iter().enumerate() {
            let program = parsed.to_bpf_program();
            assert!(program.len() <= 64, "filter {index} program is unbounded");
            for frame in &frames {
                let expected = parsed.matches_ethernet(frame);
                let accepted = run_bpf(&program, frame) > 0;
                assert_eq!(
                    accepted, expected,
                    "filter {index} ({:?}) diverged on a {}-byte frame",
                    parsed, frame.len()
                );
            }
        }
    }

    #[test]
    fn impossible_conjunctions_compile_to_drop_everything() {
        // ICMP never carries TCP/UDP ports, so this parseable conjunction can
        // not hold for any frame; both the predicate and the program must
        // accept nothing rather than mislabel a protocol.
        let filter = filter("icmp and port 443");
        let program = filter.to_bpf_program();
        let tcp = ethernet_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 50_000, 443, IPPROTO_TCP);
        let icmp = ethernet_ipv4_tcp([10, 0, 0, 9], [10, 0, 0, 2], 0, 0, IPPROTO_ICMP);
        assert!(!filter.matches_ethernet(&tcp));
        assert!(!filter.matches_ethernet(&icmp));
        assert_eq!(run_bpf(&program, &tcp), 0);
        assert_eq!(run_bpf(&program, &icmp), 0);
    }

    #[test]
    fn empty_filter_compiles_to_a_single_accept_all_instruction() {
        let program = CaptureFilter::default().to_bpf_program();
        assert_eq!(
            program,
            vec![BpfInstruction {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: BPF_ACCEPT_ALL,
            }]
        );
        assert_eq!(run_bpf(&program, &ethernet_arp()), BPF_ACCEPT_ALL);
    }

    #[test]
    fn capture_filter_support_probe_is_honest_per_backend() {
        assert_eq!(
            capture_filter_backend_supported(),
            cfg!(any(target_os = "linux", target_os = "macos"))
        );
        assert!(!CAPTURE_FILTER_UNSUPPORTED_MESSAGE.is_empty());
    }
}

#[cfg(test)]
mod debug_dump {
    use super::*;
    #[test]
    fn dump_host_program() {
        let f = CaptureFilter::parse("host 10.0.0.1").unwrap();
        for (i, ins) in f.to_bpf_program().iter().enumerate() {
            println!("{}: code={:#06x} jt={} jf={} k={:#010x}", i, ins.code, ins.jt, ins.jf, ins.k);
        }
        let frame = {
            let mut frame = vec![0u8; 14];
            frame[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
            frame.push(0x45);
            frame.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0]);
            frame.push(64);
            frame.push(6);
            frame.extend_from_slice(&[0, 0]);
            frame.extend_from_slice(&[10, 0, 0, 1]);
            frame.extend_from_slice(&[10, 0, 0, 2]);
            frame.extend_from_slice(&[0xc3, 0x50]);
            frame.extend_from_slice(&[0x01, 0xbb]);
            frame.extend_from_slice(&[0, 0]);
            frame
        };
        println!("frame src word: {:?}", &frame[26..30]);
    }
}
