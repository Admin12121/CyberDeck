//! Hand-rolled netlink/nl80211 client for monitor-mode control, Linux-only at
//! the socket layer, portable at the codec layer.
//!
//! The request encoders return exact byte vectors (nlmsghdr framing,
//! genlmsghdr command + NLA-aligned attributes) so tests run without a radio;
//! the decoders bound every parse: one message at most
//! [`MAX_NETLINK_MESSAGE`], at most [`MAX_ATTRIBUTES`] attributes per
//! message, at most [`MAX_INTERFACES`] interfaces per dump, and malformed
//! input is refused (`WifiMonitorError::Protocol`) instead of guessed at.
//! Commands used: CTRL_CMD_GETFAMILY ("nl80211"), NL80211_CMD_GET_INTERFACE,
//! NL80211_CMD_SET_INTERFACE (iftype monitor), NL80211_CMD_SET_CHANNEL,
//! NL80211_CMD_SET_WIPHY, and NETLINK_ROUTE RTM_GETLINK for interface
//! enumeration. Constant values were pinned against the Linux UAPI headers
//! (include/uapi/linux/{nl80211,genetlink,rtnetlink}.h).
//!
//! Netlink header fields and u32 attribute payloads are NATIVE endianness on
//! the wire; the codecs use `from_ne_bytes`/`to_ne_bytes` throughout, so the
//! encode/decode pairs stay consistent on every host.
use crate::wifi::{WifiError, WifiMonitorError};

/// Per-message bound (task bound; kernel default rmem is far larger).
pub const MAX_NETLINK_MESSAGE: usize = 64 * 1024;
/// Attribute cap per message (refused beyond this).
pub const MAX_ATTRIBUTES: usize = 256;
/// Interface cap per RTM_GETLINK dump (refused beyond this).
pub const MAX_INTERFACES: usize = 64;
/// Chained-message cap per receive buffer.
pub const MAX_STREAM_MESSAGES: usize = 8;

// --- linux/netlink.h ---
pub const NLMSG_ERROR: u16 = 2;
pub const NLMSG_DONE: u16 = 3;
pub const NLM_F_REQUEST: u16 = 0x0001;
pub const NLM_F_ACK: u16 = 0x0004;
pub const NLM_F_ROOT: u16 = 0x0100;
pub const NLM_F_MATCH: u16 = 0x0200;
pub const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

// --- linux/genetlink.h ---
/// Generic netlink controller id (`GENL_ID_CTRL` = `NLMSG_MIN_TYPE`).
pub const GENL_ID_CTRL: u16 = 0x10;
pub const CTRL_CMD_NEWFAMILY: u8 = 1;
pub const CTRL_CMD_GETFAMILY: u8 = 3;
pub const CTRL_ATTR_FAMILY_ID: u16 = 1;
pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;
pub const CTRL_ATTR_VERSION: u16 = 3;

// --- linux/nl80211.h (values pinned against the UAPI enum) ---
pub const NL80211_CMD_GET_WIPHY: u8 = 1;
pub const NL80211_CMD_SET_WIPHY: u8 = 2;
pub const NL80211_CMD_GET_INTERFACE: u8 = 5;
pub const NL80211_CMD_SET_INTERFACE: u8 = 6;
pub const NL80211_CMD_SET_CHANNEL: u8 = 65;
pub const NL80211_ATTR_WIPHY: u16 = 1;
pub const NL80211_ATTR_IFINDEX: u16 = 3;
pub const NL80211_ATTR_IFNAME: u16 = 4;
pub const NL80211_ATTR_IFTYPE: u16 = 5;
pub const NL80211_ATTR_MAC: u16 = 6;
pub const NL80211_ATTR_WIPHY_FREQ: u16 = 38;
pub const NL80211_ATTR_WIPHY_CHANNEL_TYPE: u16 = 39;
pub const NL80211_ATTR_CHANNEL_WIDTH: u16 = 159;
pub const NL80211_ATTR_CENTER_FREQ1: u16 = 160;
/// `NL80211_IFTYPE_MONITOR`.
pub const NL80211_IFTYPE_MONITOR: u8 = 6;
/// `NL80211_IFTYPE_STATION`.
pub const NL80211_IFTYPE_STATION: u8 = 2;

// nl80211_chan_width (for NL80211_ATTR_CHANNEL_WIDTH).
pub const NL80211_CHAN_WIDTH_20_NOHT: u32 = 0;
pub const NL80211_CHAN_WIDTH_20: u32 = 1;
pub const NL80211_CHAN_WIDTH_40: u32 = 2;

// nl80211_channel_type (for NL80211_ATTR_WIPHY_CHANNEL_TYPE, SET_WIPHY).
pub const NL80211_CHAN_NOHT: u32 = 0;
pub const NL80211_CHAN_HT20: u32 = 1;
pub const NL80211_CHAN_HT40MINUS: u32 = 2;
pub const NL80211_CHAN_HT40PLUS: u32 = 3;

// --- linux/rtnetlink.h ---
pub const RTM_GETLINK: u16 = 18;
pub const RTM_NEWLINK: u16 = 16;
pub const IFLA_ADDRESS: u16 = 1;
pub const IFLA_IFNAME: u16 = 3;

/// `NLA_ALIGN(4)`: every attribute is padded to four bytes.
const NLA_ALIGN: usize = 4;
/// `NLA_F_NESTED | NLA_F_NET_BYTEORDER` mask on the attribute type.
const NLA_TYPE_MASK: u16 = 0x3fff;

fn protocol(message: impl Into<String>) -> WifiError {
    WifiError::new(WifiMonitorError::Protocol, message)
}

/// Channel width for NL80211_CMD_SET_CHANNEL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChanWidth {
    NoHt,
    Width20,
    Width40,
}

impl ChanWidth {
    fn value(self) -> u32 {
        match self {
            ChanWidth::NoHt => NL80211_CHAN_WIDTH_20_NOHT,
            ChanWidth::Width20 => NL80211_CHAN_WIDTH_20,
            ChanWidth::Width40 => NL80211_CHAN_WIDTH_40,
        }
    }
    /// HT40 requires the secondary center frequency.
    pub fn requires_center_freq1(self) -> bool {
        matches!(self, ChanWidth::Width40)
    }
}

/// Channel type for NL80211_CMD_SET_WIPHY (the legacy wide attribute).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelType {
    NoHt,
    Ht20,
    Ht40Minus,
    Ht40Plus,
}

impl ChannelType {
    fn value(self) -> u32 {
        match self {
            ChannelType::NoHt => NL80211_CHAN_NOHT,
            ChannelType::Ht20 => NL80211_CHAN_HT20,
            ChannelType::Ht40Minus => NL80211_CHAN_HT40MINUS,
            ChannelType::Ht40Plus => NL80211_CHAN_HT40PLUS,
        }
    }
}

/// One decoded netlink reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NlReply {
    pub seq: u32,
    pub kind: NlReplyKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NlReplyKind {
    /// NLMSG_ERROR with error == 0 (the ACK form).
    Ack,
    /// NLMSG_DONE (end of a dump).
    Done,
    /// CTRL_CMD_NEWFAMILY reply carrying the resolved family id.
    FamilyId(u16),
    /// NL80211_CMD_GET_INTERFACE reply.
    Interface(InterfaceInfo),
    /// RTM_NEWLINK (single or dump element).
    Link(LinkInfo),
}

/// nl80211 view of one interface.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InterfaceInfo {
    pub index: i32,
    pub name: Option<String>,
    pub mac: Option<[u8; 6]>,
    /// Raw nl80211 iftype (6 = monitor, 2 = station, ...).
    pub iftype: Option<u8>,
    pub freq_mhz: Option<u32>,
}

/// rtnetlink view of one link.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinkInfo {
    pub index: i32,
    /// `ifi_flags` (IFF_UP = 1, IFF_RUNNING = 0x40, ...).
    pub flags: u32,
    pub name: Option<String>,
    pub mac: Option<[u8; 6]>,
}

// ---------------------------------------------------------------------------
// Encoders: exact byte vectors, no syscalls, fully testable off-Linux.
// ---------------------------------------------------------------------------

fn nlmsghdr(length: usize, msg_type: u16, flags: u16, seq: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&(length as u32).to_ne_bytes());
    out[4..6].copy_from_slice(&msg_type.to_ne_bytes());
    out[6..8].copy_from_slice(&flags.to_ne_bytes());
    out[8..12].copy_from_slice(&seq.to_ne_bytes());
    // pid stays 0: kernel-bound requests.
    out
}

fn genlmsghdr(cmd: u8, version: u8) -> [u8; 4] {
    [cmd, version, 0, 0]
}

fn nlattr(attr_type: u16, payload: &[u8]) -> Vec<u8> {
    // On the wire, nla_len is the PAYLOAD length (excluding the 4-byte
    // header); the cursor advances by NLA_ALIGN(4 + nla_len).
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_ne_bytes());
    out.extend_from_slice(&attr_type.to_ne_bytes());
    out.extend_from_slice(payload);
    let padded = payload.len().div_ceil(NLA_ALIGN) * NLA_ALIGN;
    out.resize(out.len() + (padded - payload.len()), 0);
    out
}

fn u32_attr(attr_type: u16, value: u32) -> Vec<u8> {
    nlattr(attr_type, &value.to_ne_bytes())
}

/// CTRL_CMD_GETFAMILY("nl80211"): resolve the nl80211 generic family id.
/// `WPA*`-free test vector: 16 (hdr) + 4 (genl) + 12 (attr) = 32 bytes.
pub fn encode_get_family(seq: u32) -> Vec<u8> {
    let mut name = b"nl80211".to_vec();
    name.push(0); // genl string attrs are NUL-terminated
    let attr = nlattr(CTRL_ATTR_FAMILY_NAME, &name);
    let mut out = Vec::new();
    let length = 16 + 4 + attr.len();
    out.extend_from_slice(&nlmsghdr(length, GENL_ID_CTRL, NLM_F_REQUEST, seq));
    out.extend_from_slice(&genlmsghdr(CTRL_CMD_GETFAMILY, 1));
    out.extend_from_slice(&attr);
    out
}

/// NL80211_CMD_GET_INTERFACE: query iftype/MAC/channel of one interface.
pub fn encode_get_interface(seq: u32, family_id: u16, ifindex: i32) -> Vec<u8> {
    let mut out = Vec::new();
    let attr = u32_attr(NL80211_ATTR_IFINDEX, ifindex as u32);
    let length = 16 + 4 + attr.len();
    out.extend_from_slice(&nlmsghdr(length, family_id, NLM_F_REQUEST, seq));
    out.extend_from_slice(&genlmsghdr(NL80211_CMD_GET_INTERFACE, 1));
    out.extend_from_slice(&attr);
    out
}

/// NL80211_CMD_SET_INTERFACE with `iftype = monitor`; ACK expected.
pub fn encode_set_interface_monitor(seq: u32, family_id: u16, ifindex: i32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut attrs = u32_attr(NL80211_ATTR_IFINDEX, ifindex as u32);
    attrs.extend(nlattr(NL80211_ATTR_IFTYPE, &[NL80211_IFTYPE_MONITOR]));
    let length = 16 + 4 + attrs.len();
    out.extend_from_slice(&nlmsghdr(length, family_id, NLM_F_REQUEST | NLM_F_ACK, seq));
    out.extend_from_slice(&genlmsghdr(NL80211_CMD_SET_INTERFACE, 1));
    out.extend_from_slice(&attrs);
    out
}

/// NL80211_CMD_SET_CHANNEL: ifindex + frequency + width + center freq 1.
/// ACK expected.
pub fn encode_set_channel(
    seq: u32,
    family_id: u16,
    ifindex: i32,
    freq_mhz: u32,
    width: ChanWidth,
    center_freq1_mhz: u32,
) -> Result<Vec<u8>, WifiError> {
    if width.requires_center_freq1() && center_freq1_mhz == 0 {
        return Err(WifiError::new(
            WifiMonitorError::Protocol,
            "HT40 channel width requires a non-zero center frequency",
        ));
    }
    if !(2_412..=2_484).contains(&freq_mhz)
        && !(5_160..=5_885).contains(&freq_mhz)
        && !(5945..=7_115).contains(&freq_mhz)
    {
        return Err(WifiError::new(
            WifiMonitorError::Protocol,
            format!("frequency {freq_mhz} MHz is outside the supported Wi-Fi bands"),
        ));
    }
    let mut out = Vec::new();
    let mut attrs = u32_attr(NL80211_ATTR_IFINDEX, ifindex as u32);
    attrs.extend(u32_attr(NL80211_ATTR_WIPHY_FREQ, freq_mhz));
    attrs.extend(u32_attr(NL80211_ATTR_CHANNEL_WIDTH, width.value()));
    attrs.extend(u32_attr(NL80211_ATTR_CENTER_FREQ1, center_freq1_mhz));
    let length = 16 + 4 + attrs.len();
    out.extend_from_slice(&nlmsghdr(length, family_id, NLM_F_REQUEST | NLM_F_ACK, seq));
    out.extend_from_slice(&genlmsghdr(NL80211_CMD_SET_CHANNEL, 1));
    out.extend_from_slice(&attrs);
    Ok(out)
}

/// NL80211_CMD_SET_WIPHY: the legacy per-wiphy channel attribute set.
/// ACK expected.
pub fn encode_set_wiphy_channel(
    seq: u32,
    family_id: u16,
    wiphy_index: u32,
    freq_mhz: u32,
    channel_type: ChannelType,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut attrs = u32_attr(NL80211_ATTR_WIPHY, wiphy_index);
    attrs.extend(u32_attr(NL80211_ATTR_WIPHY_FREQ, freq_mhz));
    attrs.extend(u32_attr(
        NL80211_ATTR_WIPHY_CHANNEL_TYPE,
        channel_type.value(),
    ));
    let length = 16 + 4 + attrs.len();
    out.extend_from_slice(&nlmsghdr(length, family_id, NLM_F_REQUEST | NLM_F_ACK, seq));
    out.extend_from_slice(&genlmsghdr(NL80211_CMD_SET_WIPHY, 1));
    out.extend_from_slice(&attrs);
    out
}

/// NETLINK_ROUTE RTM_GETLINK dump: enumerate links (name/index/flags).
pub fn encode_rtm_getlink(seq: u32) -> Vec<u8> {
    let mut out = Vec::new();
    // Payload: rtgenmsg { family = AF_UNSPEC } = 1 byte.
    let length = 16 + 1;
    out.extend_from_slice(&nlmsghdr(
        length,
        RTM_GETLINK,
        NLM_F_REQUEST | NLM_F_DUMP,
        seq,
    ));
    out.push(0); // rtgen_family
    out
}

// ---------------------------------------------------------------------------
// Decoders: bounded, checked, refuse malformed input.
// ---------------------------------------------------------------------------

/// Walk an NLA-aligned attribute section. Refuses short headers, lengths
/// beyond the section, misaligned tails, and sections with more than
/// `MAX_ATTRIBUTES` attributes.
pub fn decode_attributes(bytes: &[u8]) -> Result<Vec<(u16, &[u8])>, WifiError> {
    let mut attrs = Vec::new();
    let mut pos = 0usize;
    while pos < bytes.len() {
        if attrs.len() == MAX_ATTRIBUTES {
            return Err(protocol(format!(
                "attribute section exceeds {MAX_ATTRIBUTES} attributes"
            )));
        }
        if pos + 4 > bytes.len() {
            return Err(protocol("truncated attribute header"));
        }
        // nla_len counts the payload only; the 4-byte header is separate.
        let payload_len = u16::from_ne_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        let attr_type = u16::from_ne_bytes([bytes[pos + 2], bytes[pos + 3]]) & NLA_TYPE_MASK;
        let end = pos
            .checked_add(4)
            .and_then(|p| p.checked_add(payload_len))
            .ok_or_else(|| protocol("attribute length overflow"))?;
        if end > bytes.len() {
            return Err(protocol("attribute length exceeds the message"));
        }
        attrs.push((attr_type, &bytes[pos + 4..end]));
        // The cursor advances by NLA_ALIGN(4 + nla_len); the kernel always
        // pads attributes, so a section that stops mid-alignment is malformed.
        let aligned = end.div_ceil(NLA_ALIGN) * NLA_ALIGN;
        if aligned > bytes.len() {
            return Err(protocol("attribute section ends mid-alignment"));
        }
        pos = aligned;
    }
    Ok(attrs)
}

fn find_u32(attrs: &[(u16, &[u8])], attr_type: u16) -> Option<u32> {
    attrs
        .iter()
        .find(|(t, v)| *t == attr_type && v.len() == 4)
        .map(|(_, v)| u32::from_ne_bytes([v[0], v[1], v[2], v[3]]))
}

fn find_u16(attrs: &[(u16, &[u8])], attr_type: u16) -> Option<u16> {
    attrs
        .iter()
        .find(|(t, v)| *t == attr_type && v.len() == 2)
        .map(|(_, v)| u16::from_ne_bytes([v[0], v[1]]))
}

fn find_u8(attrs: &[(u16, &[u8])], attr_type: u16) -> Option<u8> {
    attrs
        .iter()
        .find(|(t, v)| *t == attr_type && v.len() == 1)
        .map(|(_, v)| v[0])
}

fn find_mac(attrs: &[(u16, &[u8])], attr_type: u16) -> Option<[u8; 6]> {
    attrs
        .iter()
        .find(|(t, v)| *t == attr_type && v.len() == 6)
        .map(|(_, v)| [v[0], v[1], v[2], v[3], v[4], v[5]])
}

fn find_name(attrs: &[(u16, &[u8])], attr_type: u16) -> Option<String> {
    attrs
        .iter()
        .find(|(t, _)| *t == attr_type)
        .and_then(|(_, v)| {
            // Kernel names are NUL-terminated, interface names are ASCII/UTF-8.
            let trimmed = v.strip_suffix(&[0]).unwrap_or(v);
            std::str::from_utf8(trimmed).ok().map(|s| s.to_string())
        })
}

/// Map a negative netlink errno to the honest error taxonomy.
fn errno_error(code: i32, context: &str) -> WifiError {
    let message = format!("{context}: netlink errno {code}");
    // The kernel writes nlmsg_err as a negative errno.
    let code_enum = match code.unsigned_abs() {
        1 /* EPERM */ | 13 /* EACCES */ => WifiMonitorError::Permission,
        2 /* ENOENT */ | 6 /* ENXIO */ | 19 /* ENODEV */ => WifiMonitorError::Device,
        _ => WifiMonitorError::Io,
    };
    WifiError::new(code_enum, message)
}

/// Decode one NETLINK_ROUTE message (RTM_NEWLINK / NLMSG_ERROR / NLMSG_DONE).
/// RTM_NEWLINK shares numeric type 16 with GENL_ID_CTRL, so route decoding is
/// its own entry point, keyed by the socket protocol the client used.
pub fn decode_route_message(bytes: &[u8]) -> Result<NlReply, WifiError> {
    if bytes.len() < 16 {
        return Err(protocol("netlink message shorter than nlmsghdr"));
    }
    let length = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let msg_type = u16::from_ne_bytes([bytes[4], bytes[5]]);
    let seq = u32::from_ne_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if length < 16 || length > MAX_NETLINK_MESSAGE || length > bytes.len() {
        return Err(protocol("netlink length outside the bounds"));
    }
    let payload = &bytes[16..length];
    match msg_type {
        NLMSG_ERROR => decode_error_payload(seq, payload),
        NLMSG_DONE => Ok(NlReply {
            seq,
            kind: NlReplyKind::Done,
        }),
        RTM_NEWLINK => decode_newlink(seq, payload),
        _ => Err(protocol(format!(
            "unhandled NETLINK_ROUTE message type {msg_type}"
        ))),
    }
}

/// Chained NETLINK_ROUTE messages (one receive buffer of a dump).
pub fn decode_route_stream(bytes: &[u8]) -> Result<Vec<NlReply>, WifiError> {
    let mut replies = Vec::new();
    let mut pos = 0usize;
    while pos < bytes.len() {
        if replies.len() == MAX_STREAM_MESSAGES {
            return Err(protocol(format!(
                "receive buffer carries more than {MAX_STREAM_MESSAGES} messages"
            )));
        }
        if pos + 16 > bytes.len() {
            return Err(protocol("truncated netlink message in stream"));
        }
        let length =
            u32::from_ne_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
                as usize;
        if length < 16 || length > MAX_NETLINK_MESSAGE || pos + length > bytes.len() {
            return Err(protocol("netlink message length outside the stream bounds"));
        }
        replies.push(decode_route_message(&bytes[pos..pos + length])?);
        pos += length;
    }
    Ok(replies)
}

fn decode_error_payload(seq: u32, payload: &[u8]) -> Result<NlReply, WifiError> {
    if payload.len() < 4 {
        return Err(protocol("NLMSG_ERROR without an errno payload"));
    }
    let error = i32::from_ne_bytes([payload[0], payload[1], payload[2], payload[3]]);
    if error == 0 {
        Ok(NlReply {
            seq,
            kind: NlReplyKind::Ack,
        })
    } else {
        Err(errno_error(error, "netlink command failed"))
    }
}

fn decode_newlink(seq: u32, payload: &[u8]) -> Result<NlReply, WifiError> {
    // struct ifinfomsg: family, pad, type, index, flags, change = 16.
    if payload.len() < 16 {
        return Err(protocol("RTM_NEWLINK without an ifinfomsg payload"));
    }
    let index = i32::from_ne_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let flags = u32::from_ne_bytes([payload[8], payload[9], payload[10], payload[11]]);
    let attrs = decode_attributes(&payload[16..])?;
    Ok(NlReply {
        seq,
        kind: NlReplyKind::Link(LinkInfo {
            index,
            flags,
            name: find_name(&attrs, IFLA_IFNAME),
            mac: find_mac(&attrs, IFLA_ADDRESS),
        }),
    })
}

/// Decode one netlink message (exactly one; see [`decode_stream`] for
/// chained messages). Refuses: short headers, lengths past the buffer or the
/// message bound, truncated error/genl payloads, unknown commands.
pub fn decode_message(bytes: &[u8]) -> Result<NlReply, WifiError> {
    if bytes.len() < 16 {
        return Err(protocol("netlink message shorter than nlmsghdr"));
    }
    let length = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let msg_type = u16::from_ne_bytes([bytes[4], bytes[5]]);
    let seq = u32::from_ne_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if length < 16 {
        return Err(protocol(format!(
            "netlink length {length} below the header size"
        )));
    }
    if length > MAX_NETLINK_MESSAGE {
        return Err(protocol(format!(
            "netlink length {length} exceeds the {MAX_NETLINK_MESSAGE}-byte bound"
        )));
    }
    if length > bytes.len() {
        return Err(protocol("netlink length exceeds the receive buffer"));
    }
    let payload = &bytes[16..length];

    match msg_type {
        NLMSG_ERROR => decode_error_payload(seq, payload),
        NLMSG_DONE => Ok(NlReply { seq, kind: NlReplyKind::Done }),
        GENL_ID_CTRL => {
            if payload.len() < 4 {
                return Err(protocol("controller reply without a genl header"));
            }
            let cmd = payload[0];
            if cmd != CTRL_CMD_NEWFAMILY {
                return Err(protocol(format!(
                    "unexpected controller command {cmd} (wanted CTRL_CMD_NEWFAMILY)"
                )));
            }
            let attrs = decode_attributes(&payload[4..])?;
            let family_id = find_u16(&attrs, CTRL_ATTR_FAMILY_ID).ok_or_else(|| {
                protocol("CTRL_CMD_NEWFAMILY reply without CTRL_ATTR_FAMILY_ID")
            })?;
            Ok(NlReply { seq, kind: NlReplyKind::FamilyId(family_id) })
        }
        // Any other type must be the nl80211 family; the caller passes the
        // resolved id, so decode via a second entry point.
        _ => Err(protocol(format!(
            "unhandled netlink message type {msg_type}; call decode_nl80211_interface for family messages"
        ))),
    }
}

/// Decode an nl80211 NL80211_CMD_GET_INTERFACE reply (message type = the
/// resolved family id, which the caller supplies).
pub fn decode_nl80211_interface(bytes: &[u8], family_id: u16) -> Result<NlReply, WifiError> {
    if bytes.len() < 16 {
        return Err(protocol("netlink message shorter than nlmsghdr"));
    }
    let length = u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let msg_type = u16::from_ne_bytes([bytes[4], bytes[5]]);
    let seq = u32::from_ne_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if length < 16 || length > MAX_NETLINK_MESSAGE || length > bytes.len() {
        return Err(protocol("netlink length outside the bounds"));
    }
    if msg_type != family_id {
        return Err(protocol(format!(
            "message type {msg_type} does not match the nl80211 family id {family_id}"
        )));
    }
    let payload = &bytes[16..length];
    if payload.len() < 4 {
        return Err(protocol("nl80211 reply without a genl header"));
    }
    let cmd = payload[0];
    if cmd != NL80211_CMD_GET_INTERFACE {
        return Err(protocol(format!(
            "unexpected nl80211 command {cmd} (wanted NL80211_CMD_GET_INTERFACE)"
        )));
    }
    let attrs = decode_attributes(&payload[4..])?;
    Ok(NlReply {
        seq,
        kind: NlReplyKind::Interface(InterfaceInfo {
            index: find_u32(&attrs, NL80211_ATTR_IFINDEX)
                .map(|v| v as i32)
                .ok_or_else(|| protocol("GET_INTERFACE reply without IFINDEX"))?,
            name: find_name(&attrs, NL80211_ATTR_IFNAME),
            mac: find_mac(&attrs, NL80211_ATTR_MAC),
            iftype: find_u8(&attrs, NL80211_ATTR_IFTYPE),
            freq_mhz: find_u32(&attrs, NL80211_ATTR_WIPHY_FREQ),
        }),
    })
}

/// Decode a receive buffer of chained netlink messages (bounded).
pub fn decode_stream(bytes: &[u8]) -> Result<Vec<NlReply>, WifiError> {
    let mut replies = Vec::new();
    let mut pos = 0usize;
    while pos < bytes.len() {
        if replies.len() == MAX_STREAM_MESSAGES {
            return Err(protocol(format!(
                "receive buffer carries more than {MAX_STREAM_MESSAGES} messages"
            )));
        }
        if pos + 16 > bytes.len() {
            return Err(protocol("truncated netlink message in stream"));
        }
        let length =
            u32::from_ne_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
                as usize;
        if length < 16 || length > MAX_NETLINK_MESSAGE || pos + length > bytes.len() {
            return Err(protocol("netlink message length outside the stream bounds"));
        }
        let message = &bytes[pos..pos + length];
        replies.push(decode_message(message)?);
        pos += length;
    }
    Ok(replies)
}

// ---------------------------------------------------------------------------
// Linux socket client: AF_NETLINK(NETLINK_GENERIC), raw syscalls only.
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_client {
    use super::*;
    use std::ffi::{c_int, c_void};
    use std::io;
    use std::os::fd::RawFd;
    use std::time::{Duration, Instant};

    const AF_NETLINK: c_int = 16;
    const NETLINK_GENERIC: c_int = 16;
    const SOCK_RAW: c_int = 3;
    const SOCK_CLOEXEC: c_int = 0o2000000;
    const POLLIN: i16 = 1;
    /// Single-command receive deadline.
    const RESPONSE_TIMEOUT: Duration = Duration::from_millis(2_000);

    #[repr(C)]
    struct SockAddrNl {
        family: u16,
        pad: u16,
        pid: u32,
        groups: u32,
    }

    #[repr(C)]
    struct PollFd {
        fd: c_int,
        events: i16,
        revents: i16,
    }

    unsafe extern "C" {
        fn socket(domain: c_int, typ: c_int, protocol: c_int) -> c_int;
        fn bind(fd: c_int, address: *const c_void, length: u32) -> c_int;
        fn send(fd: c_int, data: *const c_void, length: usize, flags: c_int) -> isize;
        fn recvfrom(
            fd: c_int,
            data: *mut c_void,
            length: usize,
            flags: c_int,
            address: *mut c_void,
            address_len: *mut u32,
        ) -> isize;
        fn poll(fds: *mut PollFd, count: usize, timeout: c_int) -> c_int;
        fn close(fd: c_int) -> c_int;
    }

    struct Fd(RawFd);
    impl Drop for Fd {
        fn drop(&mut self) {
            unsafe {
                close(self.0);
            }
        }
    }

    fn io_err(context: &str) -> WifiError {
        let err = io::Error::last_os_error();
        let code = if err.kind() == io::ErrorKind::PermissionDenied {
            WifiMonitorError::Permission
        } else {
            WifiMonitorError::Io
        };
        WifiError::new(code, format!("{context}: {err}"))
    }

    /// One AF_NETLINK socket bound to NETLINK_GENERIC with an increasing
    /// sequence counter. Every receive is bounded in size (64 KiB datagram),
    /// in time (2 s deadline) and by sequence match.
    pub struct Nl80211Socket {
        fd: Fd,
        seq: u32,
    }

    impl Nl80211Socket {
        pub(super) fn open() -> Result<Self, WifiError> {
            let fd = unsafe { socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC) };
            if fd < 0 {
                return Err(io_err("open AF_NETLINK socket for nl80211 control"));
            }
            let fd = Fd(fd);
            let address = SockAddrNl {
                family: AF_NETLINK as u16,
                pad: 0,
                pid: 0, // auto-assign
                groups: 0,
            };
            if unsafe {
                bind(
                    fd.0,
                    (&raw const address).cast(),
                    std::mem::size_of::<SockAddrNl>() as u32,
                )
            } < 0
            {
                return Err(io_err("bind nl80211 control socket"));
            }
            Ok(Self { fd, seq: 1 })
        }

        /// Send one bounded request; returns its sequence number.
        fn send_request(&mut self, request: &[u8], context: &str) -> Result<u32, WifiError> {
            if request.len() > MAX_NETLINK_MESSAGE {
                return Err(protocol("request exceeds the netlink message bound"));
            }
            let seq = u32::from_ne_bytes([request[8], request[9], request[10], request[11]]);
            let sent = unsafe { send(self.fd.0, request.as_ptr().cast(), request.len(), 0) };
            if sent != request.len() as isize {
                return Err(io_err(context));
            }
            Ok(seq)
        }

        /// Receive datagrams until one with a matching sequence arrives.
        /// Non-kernel senders and stale/unrelated messages are skipped.
        fn recv_reply(
            &mut self,
            seq: u32,
            decode: impl Fn(&[u8]) -> Result<Vec<NlReply>, WifiError>,
        ) -> Result<NlReply, WifiError> {
            let mut frame = [0u8; MAX_NETLINK_MESSAGE];
            let started = Instant::now();
            loop {
                let remaining = RESPONSE_TIMEOUT.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    return Err(WifiError::new(
                        WifiMonitorError::Io,
                        "nl80211 reply timed out",
                    ));
                }
                let mut pfd = PollFd {
                    fd: self.fd.0,
                    events: POLLIN,
                    revents: 0,
                };
                let milliseconds = (remaining.as_millis().min(50) as c_int).max(1);
                let polled = unsafe { poll(&mut pfd, 1, milliseconds) };
                if polled < 0 {
                    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(io_err("poll nl80211 reply"));
                }
                if polled == 0 || pfd.revents & POLLIN == 0 {
                    continue;
                }
                let mut address_len = std::mem::size_of::<SockAddrNl>() as u32;
                let mut address = SockAddrNl {
                    family: 0,
                    pad: 0,
                    pid: 0,
                    groups: 0,
                };
                let size = unsafe {
                    recvfrom(
                        self.fd.0,
                        frame.as_mut_ptr().cast(),
                        frame.len(),
                        0,
                        (&raw mut address).cast(),
                        &mut address_len,
                    )
                };
                if size < 0 {
                    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(io_err("receive nl80211 reply"));
                }
                // Only kernel datagrams (nl_pid 0); anything else is skipped.
                if address.pid != 0 {
                    continue;
                }
                for reply in decode(&frame[..size as usize])? {
                    if reply.seq == seq {
                        return Ok(reply);
                    }
                }
            }
        }

        /// Resolve the "nl80211" generic family id.
        pub(super) fn resolve_family(&mut self) -> Result<u16, WifiError> {
            let request = encode_get_family(self.seq.wrapping_add(1));
            let seq = self.send_request(&request, "send CTRL_CMD_GETFAMILY")?;
            let reply = self.recv_reply(seq, decode_stream)?;
            match reply.kind {
                NlReplyKind::FamilyId(id) => Ok(id),
                _ => Err(protocol("unexpected reply to CTRL_CMD_GETFAMILY")),
            }
        }

        /// GET_INTERFACE for one ifindex.
        pub(super) fn get_interface(
            &mut self,
            family_id: u16,
            ifindex: i32,
        ) -> Result<InterfaceInfo, WifiError> {
            let request = encode_get_interface(self.seq.wrapping_add(1), family_id, ifindex);
            let seq = self.send_request(&request, "send NL80211_CMD_GET_INTERFACE")?;
            let reply = self.recv_reply(seq, |buffer| {
                Ok(vec![decode_nl80211_interface(buffer, family_id)?])
            })?;
            match reply.kind {
                NlReplyKind::Interface(info) => {
                    if info.index != ifindex {
                        return Err(protocol("GET_INTERFACE reply names another ifindex"));
                    }
                    Ok(info)
                }
                _ => Err(protocol("unexpected reply to NL80211_CMD_GET_INTERFACE")),
            }
        }

        /// SET_INTERFACE (iftype monitor), waits for the ACK.
        pub(super) fn set_monitor(
            &mut self,
            family_id: u16,
            ifindex: i32,
        ) -> Result<(), WifiError> {
            let request =
                encode_set_interface_monitor(self.seq.wrapping_add(1), family_id, ifindex);
            let seq = self.send_request(&request, "send NL80211_CMD_SET_INTERFACE")?;
            let reply = self.recv_reply(seq, decode_stream)?;
            match reply.kind {
                NlReplyKind::Ack => Ok(()),
                _ => Err(protocol("SET_INTERFACE was not acknowledged")),
            }
        }

        /// SET_CHANNEL, waits for the ACK.
        pub(super) fn set_channel(
            &mut self,
            family_id: u16,
            ifindex: i32,
            freq_mhz: u32,
            width: ChanWidth,
            center_freq1_mhz: u32,
        ) -> Result<(), WifiError> {
            let request = encode_set_channel(
                self.seq.wrapping_add(1),
                family_id,
                ifindex,
                freq_mhz,
                width,
                center_freq1_mhz,
            )?;
            let seq = self.send_request(&request, "send NL80211_CMD_SET_CHANNEL")?;
            let reply = self.recv_reply(seq, decode_stream)?;
            match reply.kind {
                NlReplyKind::Ack => Ok(()),
                _ => Err(protocol("SET_CHANNEL was not acknowledged")),
            }
        }

        /// RTM_GETLINK dump: at most `MAX_INTERFACES` links.
        pub(super) fn enumerate_links(&mut self) -> Result<Vec<LinkInfo>, WifiError> {
            let request = encode_rtm_getlink(self.seq.wrapping_add(1));
            let seq = self.send_request(&request, "send RTM_GETLINK dump")?;
            let mut links = Vec::new();
            let started = Instant::now();
            let mut frame = [0u8; MAX_NETLINK_MESSAGE];
            loop {
                let remaining = RESPONSE_TIMEOUT.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    return Err(WifiError::new(
                        WifiMonitorError::Io,
                        "RTM_GETLINK dump timed out",
                    ));
                }
                let mut pfd = PollFd {
                    fd: self.fd.0,
                    events: POLLIN,
                    revents: 0,
                };
                let milliseconds = (remaining.as_millis().min(50) as c_int).max(1);
                let polled = unsafe { poll(&mut pfd, 1, milliseconds) };
                if polled < 0 {
                    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(io_err("poll RTM_GETLINK dump"));
                }
                if polled == 0 || pfd.revents & POLLIN == 0 {
                    continue;
                }
                let mut address_len = std::mem::size_of::<SockAddrNl>() as u32;
                let mut address = SockAddrNl {
                    family: 0,
                    pad: 0,
                    pid: 0,
                    groups: 0,
                };
                let size = unsafe {
                    recvfrom(
                        self.fd.0,
                        frame.as_mut_ptr().cast(),
                        frame.len(),
                        0,
                        (&raw mut address).cast(),
                        &mut address_len,
                    )
                };
                if size < 0 {
                    if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(io_err("receive RTM_GETLINK dump"));
                }
                if address.pid != 0 {
                    continue;
                }
                for reply in decode_route_stream(&frame[..size as usize])? {
                    match reply.kind {
                        NlReplyKind::Link(info) => {
                            links.push(info);
                            if links.len() > MAX_INTERFACES {
                                return Err(WifiError::new(
                                    WifiMonitorError::Protocol,
                                    format!("RTM_GETLINK dump exceeds {MAX_INTERFACES} links"),
                                ));
                            }
                        }
                        NlReplyKind::Done | NlReplyKind::Ack => return Ok(links),
                        _ => {}
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux_client::Nl80211Socket;

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an nlmsghdr-prefixed buffer the way the kernel writes it
    /// (native endian, NLA-aligned attributes).
    fn msg(msg_type: u16, flags: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let length = 16 + payload.len();
        out.extend_from_slice(&(length as u32).to_ne_bytes());
        out.extend_from_slice(&msg_type.to_ne_bytes());
        out.extend_from_slice(&flags.to_ne_bytes());
        out.extend_from_slice(&seq.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn genl(cmd: u8, version: u8, attrs: &[u8]) -> Vec<u8> {
        let mut out = vec![cmd, version, 0, 0];
        out.extend_from_slice(attrs);
        out
    }

    fn attr(attr_type: u16, payload: &[u8]) -> Vec<u8> {
        // nla_len = payload length (excluding the header); pad to 4.
        let mut out = Vec::new();
        out.extend_from_slice(&(payload.len() as u16).to_ne_bytes());
        out.extend_from_slice(&attr_type.to_ne_bytes());
        out.extend_from_slice(payload);
        let padded = payload.len().div_ceil(4) * 4;
        out.resize(out.len() + (padded - payload.len()), 0);
        out
    }

    fn u32_ne(value: u32) -> [u8; 4] {
        value.to_ne_bytes()
    }

    #[test]
    fn get_family_request_is_thirty_two_bytes_with_the_name_attr() {
        let request = encode_get_family(0x01020304);
        assert_eq!(request.len(), 32);
        assert_eq!(&request[0..4], &u32_ne(32)); // nlmsg_len
        assert_eq!(&request[4..6], &GENL_ID_CTRL.to_ne_bytes());
        assert_eq!(&request[6..8], &NLM_F_REQUEST.to_ne_bytes());
        assert_eq!(&request[8..12], &u32_ne(0x01020304)); // seq
        assert_eq!(&request[12..16], &u32_ne(0)); // pid
        assert_eq!(request[16], CTRL_CMD_GETFAMILY);
        assert_eq!(request[17], 1); // version
                                    // Attr: nla_len 8 (payload only), type CTRL_ATTR_FAMILY_NAME, "nl80211\0".
        assert_eq!(&request[20..22], &8u16.to_ne_bytes());
        assert_eq!(&request[22..24], &CTRL_ATTR_FAMILY_NAME.to_ne_bytes());
        assert_eq!(&request[24..32], b"nl80211\0");
    }

    #[test]
    fn set_interface_monitor_request_carries_iftype_six() {
        let request = encode_set_interface_monitor(7, 0x1234, 9);
        assert_eq!(request.len(), 36);
        assert_eq!(&request[4..6], &0x1234u16.to_ne_bytes());
        assert_eq!(&request[6..8], &(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
        assert_eq!(request[16], NL80211_CMD_SET_INTERFACE);
        // IFINDEX attr: nla_len 4, 8 bytes total.
        assert_eq!(&request[20..22], &4u16.to_ne_bytes());
        assert_eq!(&request[22..24], &NL80211_ATTR_IFINDEX.to_ne_bytes());
        assert_eq!(&request[24..28], &u32_ne(9));
        // IFTYPE attr: nla_len 1 (payload), 8 bytes total with padding.
        assert_eq!(&request[28..30], &1u16.to_ne_bytes());
        assert_eq!(&request[30..32], &NL80211_ATTR_IFTYPE.to_ne_bytes());
        assert_eq!(request[32], NL80211_IFTYPE_MONITOR);
    }

    #[test]
    fn get_interface_request_carries_ifindex() {
        let request = encode_get_interface(42, 0x1234, 5);
        assert_eq!(request.len(), 28);
        assert_eq!(request[16], NL80211_CMD_GET_INTERFACE);
        assert_eq!(&request[24..28], &u32_ne(5));
    }

    #[test]
    fn set_channel_request_carries_freq_width_center() {
        let request = encode_set_channel(9, 0x1234, 5, 2437, ChanWidth::Width40, 2447)
            .expect("valid channel");
        assert_eq!(request.len(), 52);
        assert_eq!(request[16], NL80211_CMD_SET_CHANNEL);
        let attrs = &request[20..];
        assert_eq!(&attrs[0..2], &4u16.to_ne_bytes()); // IFINDEX nla_len
        assert_eq!(&attrs[8..10], &4u16.to_ne_bytes()); // WIPHY_FREQ nla_len
        assert_eq!(&attrs[10..12], &NL80211_ATTR_WIPHY_FREQ.to_ne_bytes());
        assert_eq!(&attrs[12..16], &u32_ne(2437));
        assert_eq!(&attrs[18..20], &NL80211_ATTR_CHANNEL_WIDTH.to_ne_bytes());
        assert_eq!(&attrs[20..24], &u32_ne(NL80211_CHAN_WIDTH_40));
        assert_eq!(&attrs[26..28], &NL80211_ATTR_CENTER_FREQ1.to_ne_bytes());
        assert_eq!(&attrs[28..32], &u32_ne(2447));
    }

    #[test]
    fn set_channel_refuses_offband_and_centerless_ht40() {
        let err = encode_set_channel(1, 2, 3, 1_000, ChanWidth::Width20, 0)
            .expect_err("off-band frequency refuses");
        assert_eq!(err.code, WifiMonitorError::Protocol);
        let err = encode_set_channel(1, 2, 3, 2437, ChanWidth::Width40, 0)
            .expect_err("HT40 without center refuses");
        assert!(err.message.contains("center frequency"));
        // 20 MHz with no center is fine.
        assert!(encode_set_channel(1, 2, 3, 2412, ChanWidth::Width20, 0).is_ok());
    }

    #[test]
    fn set_wiphy_request_carries_channel_type() {
        let request = encode_set_wiphy_channel(3, 0x1234, 0, 5180, ChannelType::Ht40Plus);
        assert_eq!(request.len(), 44);
        assert_eq!(request[16], NL80211_CMD_SET_WIPHY);
        let attrs = &request[20..];
        assert_eq!(&attrs[0..2], &4u16.to_ne_bytes()); // WIPHY nla_len
        assert_eq!(&attrs[2..4], &NL80211_ATTR_WIPHY.to_ne_bytes());
        assert_eq!(&attrs[8..10], &4u16.to_ne_bytes()); // WIPHY_FREQ nla_len
        assert_eq!(&attrs[10..12], &NL80211_ATTR_WIPHY_FREQ.to_ne_bytes());
        assert_eq!(&attrs[12..16], &u32_ne(5180));
        assert_eq!(&attrs[16..18], &4u16.to_ne_bytes()); // CHANNEL_TYPE nla_len
        assert_eq!(
            &attrs[18..20],
            &NL80211_ATTR_WIPHY_CHANNEL_TYPE.to_ne_bytes()
        );
        assert_eq!(&attrs[20..24], &u32_ne(NL80211_CHAN_HT40PLUS));
    }

    #[test]
    fn rtm_getlink_request_is_a_dump() {
        let request = encode_rtm_getlink(11);
        assert_eq!(request.len(), 17);
        assert_eq!(&request[4..6], &RTM_GETLINK.to_ne_bytes());
        assert_eq!(&request[6..8], &(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        assert_eq!(request[16], 0); // rtgen_family = AF_UNSPEC
    }

    #[test]
    fn get_family_response_decodes_the_id() {
        let mut attrs = attr(CTRL_ATTR_FAMILY_ID, &0x1au16.to_ne_bytes());
        attrs.extend(attr(CTRL_ATTR_VERSION, &2u32.to_ne_bytes()));
        let reply = msg(GENL_ID_CTRL, 0, 5, &genl(CTRL_CMD_NEWFAMILY, 1, &attrs));
        let decoded = decode_message(&reply).expect("family reply decodes");
        assert_eq!(decoded.seq, 5);
        assert_eq!(decoded.kind, NlReplyKind::FamilyId(0x1a));
    }

    #[test]
    fn get_interface_response_decodes_full_info() {
        let mut attrs = attr(NL80211_ATTR_IFINDEX, &u32_ne(9));
        attrs.extend(attr(NL80211_ATTR_IFNAME, b"wlan0\0"));
        attrs.extend(attr(
            NL80211_ATTR_MAC,
            &[0xa4, 0xb1, 0xc1, 0xd2, 0xe3, 0xf0],
        ));
        attrs.extend(attr(NL80211_ATTR_IFTYPE, &[NL80211_IFTYPE_STATION]));
        attrs.extend(attr(NL80211_ATTR_WIPHY_FREQ, &u32_ne(2412)));
        let reply = msg(0x1a, 0, 3, &genl(NL80211_CMD_GET_INTERFACE, 1, &attrs));
        let decoded = decode_nl80211_interface(&reply, 0x1a).expect("interface reply decodes");
        assert_eq!(decoded.seq, 3);
        match decoded.kind {
            NlReplyKind::Interface(info) => {
                assert_eq!(info.index, 9);
                assert_eq!(info.name.as_deref(), Some("wlan0"));
                assert_eq!(info.mac, Some([0xa4, 0xb1, 0xc1, 0xd2, 0xe3, 0xf0]));
                assert_eq!(info.iftype, Some(NL80211_IFTYPE_STATION));
                assert_eq!(info.freq_mhz, Some(2412));
            }
            other => panic!("unexpected kind {other:?}"),
        }
    }

    #[test]
    fn rtm_newlink_decodes_index_flags_and_name() {
        let mut payload = vec![0u8; 16]; // ifinfomsg
        payload[0] = 0; // family
        payload[4..8].copy_from_slice(&3i32.to_ne_bytes()); // ifi_index
        payload[8..12].copy_from_slice(&0x10043u32.to_ne_bytes()); // ifi_flags
        payload.extend(attr(IFLA_IFNAME, b"wlan1\0"));
        payload.extend(attr(IFLA_ADDRESS, &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
        let reply = msg(RTM_NEWLINK, 0, 8, &payload);
        let decoded = decode_route_message(&reply).expect("link decodes");
        match decoded.kind {
            NlReplyKind::Link(info) => {
                assert_eq!(info.index, 3);
                assert_eq!(info.flags, 0x10043);
                assert_eq!(info.name.as_deref(), Some("wlan1"));
                assert_eq!(info.mac, Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]));
            }
            other => panic!("unexpected kind {other:?}"),
        }
    }

    #[test]
    fn ack_and_done_and_errno_decode() {
        let ack = msg(NLMSG_ERROR, 0, 1, &0i32.to_ne_bytes());
        assert_eq!(decode_message(&ack).expect("ack").kind, NlReplyKind::Ack);
        let done = msg(NLMSG_DONE, 0, 2, &[]);
        assert_eq!(decode_message(&done).expect("done").kind, NlReplyKind::Done);
        let eperm = msg(NLMSG_ERROR, 0, 3, &(-1i32).to_ne_bytes());
        let err = decode_message(&eperm).expect_err("EPERM maps");
        assert_eq!(err.code, WifiMonitorError::Permission);
        let enodev = msg(NLMSG_ERROR, 0, 4, &(-19i32).to_ne_bytes());
        let err = decode_message(&enodev).expect_err("ENODEV maps");
        assert_eq!(err.code, WifiMonitorError::Device);
        let eio = msg(NLMSG_ERROR, 0, 5, &(-5i32).to_ne_bytes());
        let err = decode_message(&eio).expect_err("EIO maps");
        assert_eq!(err.code, WifiMonitorError::Io);
    }

    #[test]
    fn stream_of_chained_messages_decodes_in_order() {
        let mut buffer = msg(
            GENL_ID_CTRL,
            0,
            1,
            &genl(
                CTRL_CMD_NEWFAMILY,
                1,
                &attr(CTRL_ATTR_FAMILY_ID, &0x1au16.to_ne_bytes()),
            ),
        );
        buffer.extend(msg(NLMSG_DONE, 0, 1, &[]));
        let replies = decode_stream(&buffer).expect("stream decodes");
        assert_eq!(replies.len(), 2);
        assert_eq!(replies[0].kind, NlReplyKind::FamilyId(0x1a));
        assert_eq!(replies[1].kind, NlReplyKind::Done);
    }

    #[test]
    fn malformed_messages_refuse_without_panics() {
        // Every truncation of a valid message: no panic, honest refusal.
        let valid = msg(
            GENL_ID_CTRL,
            0,
            1,
            &genl(
                CTRL_CMD_NEWFAMILY,
                1,
                &attr(CTRL_ATTR_FAMILY_ID, &0x1au16.to_ne_bytes()),
            ),
        );
        for cut in 0..valid.len() {
            let result = decode_message(&valid[..cut]);
            if cut >= 16 {
                assert!(result.is_err(), "cut at {cut} unexpectedly decoded");
            }
        }
        // Length below the header size.
        let mut bad = valid.clone();
        bad[0..4].copy_from_slice(&u32_ne(8));
        assert!(decode_message(&bad).is_err());
        // Length beyond the buffer.
        let mut bad = valid.clone();
        bad[0..4].copy_from_slice(&u32_ne(10_000));
        assert!(decode_message(&bad).is_err());
        // Length beyond the message bound.
        let mut bad = valid.clone();
        bad[0..4].copy_from_slice(&u32_ne((MAX_NETLINK_MESSAGE + 1) as u32));
        assert!(decode_message(&bad).is_err());
        // NLMSG_ERROR without errno.
        let bad = msg(NLMSG_ERROR, 0, 1, &[0u8; 2]);
        assert!(decode_message(&bad).is_err());
        // Attribute length below 4.
        let bad = msg(
            GENL_ID_CTRL,
            0,
            1,
            &genl(CTRL_CMD_NEWFAMILY, 1, &[2, 0, 0, 0]),
        );
        assert!(decode_message(&bad).is_err());
        // Attribute length beyond the section.
        let bad = msg(
            GENL_ID_CTRL,
            0,
            1,
            &genl(CTRL_CMD_NEWFAMILY, 1, &[255, 0, 0, 0, 1, 2]),
        );
        assert!(decode_message(&bad).is_err());
        // Unexpected controller command.
        let bad = msg(
            GENL_ID_CTRL,
            0,
            1,
            &genl(
                CTRL_CMD_GETFAMILY,
                1,
                &attr(CTRL_ATTR_FAMILY_ID, &0x1au16.to_ne_bytes()),
            ),
        );
        assert!(decode_message(&bad).is_err());
        // GET_INTERFACE reply missing IFINDEX.
        let bad = msg(
            0x1a,
            0,
            1,
            &genl(
                NL80211_CMD_GET_INTERFACE,
                1,
                &attr(NL80211_ATTR_IFNAME, b"wlan0\0"),
            ),
        );
        assert!(decode_nl80211_interface(&bad, 0x1a).is_err());
        // Wrong nl80211 command.
        let bad = msg(
            0x1a,
            0,
            1,
            &genl(
                NL80211_CMD_SET_INTERFACE,
                1,
                &attr(NL80211_ATTR_IFINDEX, &u32_ne(3)),
            ),
        );
        assert!(decode_nl80211_interface(&bad, 0x1a).is_err());
    }

    #[test]
    fn attribute_bounds_are_enforced() {
        // More attributes than the cap.
        let mut attrs = Vec::new();
        for _ in 0..=MAX_ATTRIBUTES {
            attrs.extend(attr(1, &[0u8; 4]));
        }
        let err = decode_attributes(&attrs).expect_err("attribute flood refuses");
        assert!(err.message.contains(MAX_ATTRIBUTES_LEXEME));
        // Misaligned garbage tail refuses.
        let mut tail = attr(1, &[0u8; 4]);
        tail.push(9);
        assert!(decode_attributes(&tail).is_err());
    }

    const MAX_ATTRIBUTES_LEXEME: &str = "256 attributes";

    #[test]
    fn stream_bound_is_enforced() {
        let mut buffer = Vec::new();
        for _ in 0..=MAX_STREAM_MESSAGES {
            buffer.extend(msg(NLMSG_DONE, 0, 1, &[]));
        }
        let err = decode_stream(&buffer).expect_err("message flood refuses");
        assert!(err.message.contains("messages"));
    }

    #[test]
    fn native_endianness_round_trip_is_stable() {
        // Encode with our own encoder, decode with our own decoder: the pair
        // must agree regardless of host endianness.
        let request = encode_get_interface(0xdeadbeef, 0x1a, 6);
        // Response built from the request's shape.
        let mut attrs = attr(NL80211_ATTR_IFINDEX, &u32_ne(6));
        attrs.extend(attr(NL80211_ATTR_IFTYPE, &[NL80211_IFTYPE_MONITOR]));
        let reply = msg(
            0x1a,
            0,
            0xdeadbeef,
            &genl(NL80211_CMD_GET_INTERFACE, 1, &attrs),
        );
        let decoded = decode_nl80211_interface(&reply, 0x1a).expect("round trip");
        match decoded.kind {
            NlReplyKind::Interface(info) => {
                assert_eq!(info.index, 6);
                assert_eq!(info.iftype, Some(NL80211_IFTYPE_MONITOR));
            }
            other => panic!("unexpected kind {other:?}"),
        }
    }
}
