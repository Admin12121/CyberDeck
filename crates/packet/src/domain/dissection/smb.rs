//! Bounded SMB1/SMB2 dissection for TCP 445/139 Windows file sharing.
//! SMB rides behind the NetBIOS session service framing (MS-NBTS): a
//! 4-byte header whose type 0x00 session message carries exactly one SMB
//! message. SMB2 headers are 64 bytes (MS-SMB2 §2.2.1: protocol id
//! 0xFE "SMB", structure size 64, command, flags, message id, tree/
//! process/session ids); SMB1 headers are 32 bytes (MS-CIFS §2.2.3.1:
//! protocol id 0xFF "SMB", command, NT status, flags/flags2, TID/PID/
//! UID/MID). The interesting bodies are decoded boundedly: negotiate
//! dialects (≤ 8 listed), negotiate responses (selected dialect + max
//! credit), session-setup NTLMSSP presence and message type (MS-NLMP
//! §2.2.1 signature "NTLMSSP\0" + type), and tree-connect share names
//! (UTF-16LE, ≤ 128 chars, MS-SMB2 §2.2.9).
//!
//! Honesty contracts, enforced everywhere below:
//! - One packet is one row, like the single-record HTTP/TLS inspection:
//!   the first SMB message of the captured segment is decoded; compounded
//!   chains (NextCommand) and later messages are named, never decoded.
//!   Session pairing and file contents are out of scope — nothing here
//!   claims what a read or write carried.
//! - Only a verified NetBIOS session header plus an SMB marker (or its
//!   unambiguous prefix cut by a capture boundary) claims an SMB row. A
//!   session-message header without a marker, or any other payload, keeps
//!   the plain transport row — ports alone are not SMB evidence.
//! - Every list is capped and every decode that stops early says why
//!   ("not decoded (…)", raw codes, "+N more (cap 8)") instead of guessing.
//! - NTLMSSP is reported as marker presence and message type only; the
//!   authentication structures are never interpreted.
//! - Malformed or truncated messages degrade to an honest SMB row with
//!   exactly what the captured bytes support, never a fabricated field.

use crate::Layer;

/// SMB1 and SMB2 dialect lists are shown up to this many entries.
const MAX_DIALECTS: usize = 8;
/// One dialect token cannot exceed this many characters.
const MAX_DIALECT_CHARS: usize = 32;
/// SMB1 negotiate dialect tokens are parsed within this byte bound.
const MAX_DIALECT_WINDOW: usize = 256;
/// The NTLMSSP marker search stays inside this window after the header.
const MAX_NTLMSSP_WINDOW: usize = 1024;
/// Share names decode up to this many UTF-16 characters (MS-SMB2 §2.2.9
/// paths are longer in theory; beyond the bound the row says so instead).
const MAX_SHARE_CHARS: usize = 128;
const SMB1_HEADER: usize = 32;
const SMB2_HEADER: usize = 64;
const SMB1_MARKER: &[u8; 4] = b"\xffSMB";
const SMB2_MARKER: &[u8; 4] = b"\xfeSMB";
/// NTLMSSP message signature (MS-NLMP §2.2.1): the ASCII tag plus null.
const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

pub(super) struct SmbService {
    pub protocol: &'static str,
    pub info: String,
    pub layers: Vec<Layer>,
}

fn layer(label: &str, value: impl ToString) -> Layer {
    Layer {
        label: label.into(),
        value: value.to_string(),
    }
}

fn le16(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn le32(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn le64(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        data.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

fn be16(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        data.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn smb2_done(info: String, layers: Vec<Layer>) -> SmbService {
    SmbService {
        protocol: "SMB",
        info,
        layers,
    }
}

/// True when the captured bytes begin an SMB1 or SMB2 marker: the full
/// 4 bytes, or a prefix of at least two bytes cut by a capture boundary.
/// A bare 0xFE/0xFF byte claims nothing.
fn starts_with_smb_marker(bytes: &[u8]) -> bool {
    let Some(&first) = bytes.first() else {
        return false;
    };
    let marker: &[u8; 4] = if first == SMB1_MARKER[0] {
        SMB1_MARKER
    } else if first == SMB2_MARKER[0] {
        SMB2_MARKER
    } else {
        return false;
    };
    let available = bytes.len().min(marker.len());
    available >= 2 && bytes[..available] == marker[..available]
}

/// Dissect one TCP payload already matched to port 445/139 where the HTTP
/// and TLS checks declined. Returns None when there is no NetBIOS/SMB
/// evidence so the caller keeps the plain transport row.
pub(super) fn dissect(payload: &[u8]) -> Option<SmbService> {
    // Direct-hosted marker without NetBIOS framing is unambiguous when the
    // full 4 bytes are present.
    if payload.len() >= 4 && (&payload[..4] == SMB1_MARKER || &payload[..4] == SMB2_MARKER) {
        return Some(dissect_message(payload, None));
    }
    let kind = *payload.first()?;
    let flags = *payload.get(1)?;
    if kind == 0x00 {
        // NetBIOS session message (MS-NBTS): the length field is 17 bits,
        // with flag bit 0 carrying the extension above the low 16.
        let declared =
            (u32::from(flags & 0x01) << 16) | u32::from(be16(payload, 2).unwrap_or(0));
        let captured = payload.len().saturating_sub(4) as u32;
        let mut value = format!("session message, {declared} byte(s)");
        if declared > captured {
            value.push_str(&format!(
                "; truncated at capture boundary ({captured} captured)"
            ));
        }
        let nbss = layer("NetBIOS session", value);
        let inner = &payload[4.min(payload.len())..];
        if starts_with_smb_marker(inner) {
            return Some(dissect_message(inner, Some(nbss)));
        }
        // A valid session-message header without SMB evidence inside stays
        // transport evidence — the port did not make it SMB.
        return None;
    }
    if payload.len() < 4 {
        return None;
    }
    // The non-message session packet types (MS-NBTS) are named as-is; the
    // first-level-encoded request names are never decoded here.
    let name = match kind {
        0x81 => {
            return Some(SmbService {
                protocol: "NetBIOS",
                info: "NetBIOS session request".into(),
                layers: vec![layer(
                    "NetBIOS session",
                    format!(
                        "session request, {} byte(s) (names not decoded)",
                        payload.len() - 4
                    ),
                )],
            })
        }
        0x82 => "positive session response",
        0x83 => "negative session response",
        0x84 => "retarget session response",
        0x85 => "session keep-alive",
        _ => return None,
    };
    Some(SmbService {
        protocol: "NetBIOS",
        info: format!("NetBIOS {name}"),
        layers: vec![layer("NetBIOS session", name)],
    })
}

/// Dispatch a captured SMB message whose marker (or its two-byte prefix,
/// cut by a capture boundary) is verified. The optional NetBIOS layer
/// stays in front of the SMB layers like the UDP evidence the QUIC
/// dispatch keeps. Short captures degrade inside each header dissector.
fn dissect_message(msg: &[u8], nbss: Option<Layer>) -> SmbService {
    if msg.first() == Some(&SMB2_MARKER[0]) {
        dissect_smb2(msg, nbss)
    } else {
        dissect_smb1(msg, nbss)
    }
}

fn smb2_command_name(code: u16) -> Option<&'static str> {
    Some(match code {
        0 => "negotiate",
        1 => "session setup",
        2 => "logoff",
        3 => "tree connect",
        5 => "create",
        6 => "close",
        8 => "read",
        9 => "write",
        _ => return None,
    })
}

/// Documented NTSTATUS names for the codes office file-sharing captures
/// actually produce; everything outside the table keeps the raw code.
fn nt_status_name(code: u32) -> Option<&'static str> {
    Some(match code {
        0x0000_0000 => "STATUS_SUCCESS",
        0xC000_000D => "STATUS_INVALID_PARAMETER",
        0xC000_000F => "STATUS_NO_SUCH_FILE",
        0xC000_0016 => "STATUS_MORE_PROCESSING_REQUIRED",
        0xC000_0022 => "STATUS_ACCESS_DENIED",
        0xC000_0043 => "STATUS_SHARING_VIOLATION",
        0xC000_006D => "STATUS_LOGON_FAILURE",
        0xC000_009A => "STATUS_INSUFFICIENT_RESOURCES",
        0xC000_00BB => "STATUS_NOT_SUPPORTED",
        0xC000_00CC => "STATUS_BAD_NETWORK_NAME",
        _ => return None,
    })
}

fn status_label(status: u32) -> String {
    match nt_status_name(status) {
        Some(name) => name.to_string(),
        None => format!("0x{status:08x} (not in the NT status name table)"),
    }
}

fn smb2_dialect_name(code: u16) -> String {
    match code {
        0x0202 => "SMB 2.002".into(),
        0x0210 => "SMB 2.1".into(),
        0x0300 => "SMB 3.0".into(),
        0x0302 => "SMB 3.0.2".into(),
        0x0311 => "SMB 3.1.1".into(),
        _ => format!("0x{code:04x}"),
    }
}

/// Render a bounded dialect summary: the total, the listed names, an
/// overflow marker when the cap hid entries, and the reason parsing
/// stopped early.
fn dialect_summary(listed: &[String], total: usize, reason: Option<String>) -> String {
    let mut value = format!("{total} offered");
    if !listed.is_empty() {
        value.push_str(": ");
        value.push_str(&listed.join(", "));
    }
    if listed.len() < total {
        value.push_str(&format!(
            ", +{} more (cap {MAX_DIALECTS})",
            total - listed.len()
        ));
    }
    if let Some(reason) = reason {
        value.push_str("; ");
        value.push_str(&reason);
    }
    value
}

/// Bounded scan for the NTLMSSP signature (MS-NLMP §2.2.1) inside the
/// captured bytes after the SMB header. The claim is presence and message
/// type only — the authentication structures are never decoded.
fn ntlmssp_scan(window: &[u8]) -> Option<(String, String)> {
    if window.len() < NTLMSSP_SIGNATURE.len() {
        return None;
    }
    for at in 0..=window.len() - NTLMSSP_SIGNATURE.len() {
        if &window[at..at + NTLMSSP_SIGNATURE.len()] != &NTLMSSP_SIGNATURE[..] {
            continue;
        }
        let type_name = match le32(window, at + NTLMSSP_SIGNATURE.len()) {
            Some(1) => "negotiate".to_string(),
            Some(2) => "challenge".to_string(),
            Some(3) => "auth".to_string(),
            Some(code) => format!("type 0x{code:08x}"),
            None => "type not decoded (truncated message type)".to_string(),
        };
        let detail = format!("NTLMSSP {type_name}");
        let value = format!(
            "NTLMSSP authentication (details not decoded); message type {type_name}"
        );
        return Some((detail, value));
    }
    None
}

/// SMB2 tree-connect share name (MS-SMB2 §2.2.9): body is structure size
/// 9, reserved, PathOffset (from the SMB2 header start), PathLength; the
/// path is UTF-16LE. Every bound is validated before a byte is decoded.
fn smb2_tree_connect_share(body: &[u8], msg: &[u8]) -> Result<String, &'static str> {
    if le16(body, 0) != Some(9) {
        return Err("malformed tree connect body");
    }
    let offset = le16(body, 4).ok_or("malformed tree connect body")? as usize;
    let length = le16(body, 6).ok_or("malformed tree connect body")? as usize;
    if length == 0 || length % 2 != 0 {
        return Err("share path length is not whole UTF-16 units");
    }
    if length > MAX_SHARE_CHARS * 2 {
        return Err("share name exceeds the 128-character bound");
    }
    let end = offset
        .checked_add(length)
        .ok_or("share name truncated at capture boundary")?;
    if offset < SMB2_HEADER || end > msg.len() {
        return Err("share name truncated at capture boundary");
    }
    let units: Vec<u16> = msg[offset..end]
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let name = String::from_utf16(&units).map_err(|_| "share name is not valid UTF-16")?;
    if !name.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        return Err("share name contains control characters");
    }
    Ok(name)
}

/// SMB2 negotiate request dialects (MS-SMB2 §2.2.3): the 3.x form carries
/// a u16 dialect array behind the 36-byte fixed part; the dialects buffer
/// sits at header offset 64 + 36 and its length is DialectCount × 2. The
/// 2.002/2.1 string form does not satisfy those invariants and degrades
/// to the honest "not decoded" note instead of reading string bytes as
/// dialect codes.
fn smb2_negotiate_request_dialects(
    body: &[u8],
    msg: &[u8],
) -> Option<(Vec<String>, usize, Option<String>)> {
    if body.len() < 36 || le16(body, 0) != Some(0x25) {
        return None;
    }
    let count = le16(body, 30)? as usize;
    let offset = le16(body, 32)? as usize;
    let length = le16(body, 34)? as usize;
    if count == 0 || offset != SMB2_HEADER + 36 || length != count * 2 {
        return None;
    }
    let mut listed = Vec::new();
    let mut reason = None;
    let decodable = msg.len().saturating_sub(offset) / 2;
    if count > decodable {
        reason = Some("dialects truncated at capture boundary".to_string());
    }
    for index in 0..count.min(decodable) {
        let code = le16(msg, offset + index * 2).unwrap_or(0);
        if listed.len() < MAX_DIALECTS {
            listed.push(smb2_dialect_name(code));
        }
    }
    Some((listed, count, reason))
}

fn dissect_smb2(msg: &[u8], nbss: Option<Layer>) -> SmbService {
    let mut layers = Vec::new();
    if let Some(nbss) = nbss {
        layers.push(nbss);
    }
    if msg.len() < SMB2_HEADER {
        let mut info = format!(
            "SMB2 header truncated at capture boundary ({} of {SMB2_HEADER} byte(s)); not decoded",
            msg.len()
        );
        if msg.len() >= 6 {
            if let Some(size) = le16(msg, 4) {
                if size != SMB2_HEADER as u16 {
                    info = format!(
                        "SMB2 header malformed (structure size {size}, expected {SMB2_HEADER}); not decoded"
                    );
                }
            }
        }
        layers.push(layer("SMB2 header", info.clone()));
        return smb2_done(info, layers);
    }
    // Header bounds proven above; the fixed fields are read directly.
    if u16::from_le_bytes([msg[4], msg[5]]) != SMB2_HEADER as u16 {
        let size = u16::from_le_bytes([msg[4], msg[5]]);
        let info = format!(
            "SMB2 header malformed (structure size {size}, expected {SMB2_HEADER}); not decoded"
        );
        layers.push(layer("SMB2 header", info.clone()));
        return smb2_done(info, layers);
    }
    let status = le32(msg, 8).unwrap_or(0);
    let command_code = le16(msg, 12).unwrap_or(0);
    let flags = le32(msg, 16).unwrap_or(0);
    let next_command = le32(msg, 20).unwrap_or(0);
    let message_id = le64(msg, 24).unwrap_or(0);
    let process_id = le32(msg, 32).unwrap_or(0);
    let tree_id = le32(msg, 36).unwrap_or(0);
    let session_id = le64(msg, 40).unwrap_or(0);
    let response = flags & 0x0000_0001 != 0;
    let command = match smb2_command_name(command_code) {
        Some(name) => name.to_string(),
        None => format!("command {command_code}"),
    };
    layers.push(layer(
        "SMB2 header",
        format!(
            "message id {message_id}, tree {tree_id}, session {session_id}, process {process_id}"
        ),
    ));
    layers.push(layer("command", command.clone()));
    if next_command != 0 {
        layers.push(layer(
            "SMB2 compounding",
            format!("next message at +{next_command} (first message decoded)"),
        ));
    }
    let status_text = if response {
        Some(status_label(status))
    } else {
        None
    };
    if let Some(text) = &status_text {
        layers.push(layer("status", text.clone()));
    }
    let mut info = if response {
        format!("SMB2 {command} response")
    } else {
        format!("SMB2 {command}")
    };
    let body = &msg[SMB2_HEADER..];
    let mut detail = None;
    match (command_code, response) {
        (0, false) => match smb2_negotiate_request_dialects(body, msg) {
            Some((listed, total, reason)) => {
                layers.push(layer("dialects offered", dialect_summary(&listed, total, reason)));
                detail = Some(format!("{total} dialect(s) offered"));
            }
            None => layers.push(layer(
                "dialects offered",
                "not decoded (unsupported negotiate form or capture boundary)",
            )),
        },
        (0, true) => {
            // The granted credit count rides in the header (MS-SMB2 §2.2.1);
            // the response selects exactly one dialect (§2.2.4).
            layers.push(layer("max credit", le16(msg, 14).unwrap_or(0)));
            match le16(body, 4).map(smb2_dialect_name) {
                Some(name) => {
                    layers.push(layer("dialect selected", name.clone()));
                    detail = Some(format!("dialect {name}"));
                }
                None => layers.push(layer(
                    "dialect selected",
                    "not decoded (body truncated at capture boundary)",
                )),
            }
        }
        (1, _) => {
            let window_end = msg.len().min(SMB2_HEADER + MAX_NTLMSSP_WINDOW);
            if let Some((found_detail, value)) =
                ntlmssp_scan(&msg[SMB2_HEADER..window_end])
            {
                layers.push(layer("NTLMSSP", value));
                detail = Some(found_detail);
            }
        }
        (3, false) => match smb2_tree_connect_share(body, msg) {
            Ok(name) => {
                layers.push(layer("share name", name.clone()));
                detail = Some(format!("share {name}"));
            }
            Err(reason) => {
                layers.push(layer("share name", format!("not decoded ({reason})")));
            }
        },
        _ => {}
    }
    if let Some(detail) = detail {
        info.push_str(", ");
        info.push_str(&detail);
    } else if let Some(text) = &status_text {
        info.push_str(", ");
        info.push_str(text);
    }
    smb2_done(info, layers)
}

fn smb1_command_name(code: u8) -> Option<&'static str> {
    Some(match code {
        0x04 => "close",
        0x06 => "delete",
        0x07 => "rename",
        0x0A => "read",
        0x0B => "write",
        0x25 => "trans",
        0x2D => "open (ANDX)",
        0x2E => "read (ANDX)",
        0x2F => "write (ANDX)",
        0x32 => "trans2",
        0x70 => "tree connect",
        0x72 => "negotiate",
        0x73 => "session setup (ANDX)",
        0x74 => "logoff (ANDX)",
        0x75 => "tree connect (ANDX)",
        0x76 => "tree disconnect",
        0xA0 => "nt transact",
        0xA2 => "nt create (ANDX)",
        _ => return None,
    })
}

/// SMB1 flags/flags2 summary: the direction and capability bits that shape
/// how the message is interpreted, plus the raw values.
fn smb1_flags_summary(flags: u8, flags2: u16) -> String {
    let mut parts: Vec<&str> = Vec::new();
    if flags & 0x80 != 0 {
        parts.push("reply");
    }
    if flags2 & 0x4000 != 0 {
        parts.push("NT status");
    }
    if flags2 & 0x8000 != 0 {
        parts.push("unicode");
    }
    if flags2 & 0x0001 != 0 {
        parts.push("long names");
    }
    if parts.is_empty() {
        return format!("flags 0x{flags:02x}, flags2 0x{flags2:04x}");
    }
    format!(
        "{} (flags 0x{flags:02x}, flags2 0x{flags2:04x})",
        parts.join(", ")
    )
}

/// SMB1 response status (MS-CIFS §2.2.3.1): NT status codes when FLAGS2
/// announces them, otherwise the legacy DOS error class and code.
fn smb1_status_label(msg: &[u8], flags2: u16) -> String {
    if flags2 & 0x4000 != 0 {
        status_label(le32(msg, 5).unwrap_or(0))
    } else {
        let class = msg[5];
        let code = le16(msg, 7).unwrap_or(0);
        format!("error class 0x{class:02x} code 0x{code:04x} (not translated)")
    }
}

/// SMB1 negotiate request dialect tokens (MS-CIFS SMB_COM_NEGOTIATE):
/// after WordCount/ByteCount, each dialect is one 0x02 buffer-format byte
/// followed by a null-terminated ASCII string. Tokens are listed up to
/// [`MAX_DIALECTS`]; malformed or truncated tokens stop with a reason.
fn smb1_dialect_tokens(bytes: &[u8]) -> (Vec<String>, usize, Option<String>) {
    let mut listed: Vec<String> = Vec::new();
    let mut total = 0usize;
    let mut reason: Option<String> = None;
    let mut at = 0usize;
    while at < bytes.len() {
        if bytes[at] != 0x02 {
            reason = Some("token missing the 0x02 buffer format byte".to_string());
            break;
        }
        at += 1;
        let start = at;
        let mut terminated = false;
        while at < bytes.len() {
            if bytes[at] == 0x00 {
                terminated = true;
                break;
            }
            if at - start >= MAX_DIALECT_CHARS {
                break;
            }
            at += 1;
        }
        if !terminated {
            reason = Some(if at - start >= MAX_DIALECT_CHARS {
                format!("dialect string exceeds the {MAX_DIALECT_CHARS}-character bound")
            } else {
                "dialects truncated at capture boundary".to_string()
            });
            break;
        }
        let token = &bytes[start..at];
        at += 1;
        total += 1;
        let Ok(text) = std::str::from_utf8(token) else {
            reason = Some("non-ASCII dialect string".to_string());
            break;
        };
        if !text.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
            reason = Some("dialect string contains control characters".to_string());
            break;
        }
        if listed.len() < MAX_DIALECTS {
            listed.push(text.to_string());
        }
    }
    (listed, total, reason)
}

/// Decode the dialect tokens of an SMB1 negotiate request from the word
/// and byte counts. Anything structurally unusable degrades to an honest
/// "not decoded" layer without inventing names. Returns the number of
/// dialects actually listed when tokens were decoded.
fn smb1_negotiate_dialects(msg: &[u8], layers: &mut Vec<Layer>) -> Option<usize> {
    let Some(&word_count_byte) = msg.get(SMB1_HEADER) else {
        layers.push(layer(
            "dialects offered",
            "not decoded (word count beyond the captured bytes)",
        ));
        return None;
    };
    let word_count = usize::from(word_count_byte);
    let words_end = SMB1_HEADER + 1 + word_count * 2;
    if words_end
        .checked_add(2)
        .map_or(true, |with_count| with_count > msg.len())
    {
        layers.push(layer(
            "dialects offered",
            "not decoded (word/byte counts beyond the captured bytes)",
        ));
        return None;
    }
    let byte_count = le16(msg, words_end).unwrap_or(0) as usize;
    let bytes_start = words_end + 2;
    let mut reason = None;
    if bytes_start.saturating_add(byte_count) > msg.len() {
        reason = Some("byte area truncated at capture boundary".to_string());
    }
    let bytes_end = bytes_start.saturating_add(byte_count).min(msg.len());
    let window = &msg[bytes_start.min(msg.len())..bytes_end];
    let (listed, total, tokens_reason) = smb1_dialect_tokens(window);
    let reason = tokens_reason.or(reason);
    if total == 0 {
        let why = reason.unwrap_or_else(|| "no dialect tokens in the captured bytes".to_string());
        layers.push(layer("dialects offered", format!("not decoded ({why})")));
        None
    } else {
        layers.push(layer("dialects offered", dialect_summary(&listed, total, reason)));
        Some(total)
    }
}

fn dissect_smb1(msg: &[u8], nbss: Option<Layer>) -> SmbService {
    let mut layers = Vec::new();
    if let Some(nbss) = nbss {
        layers.push(nbss);
    }
    if msg.len() < SMB1_HEADER {
        let info = format!(
            "SMB1 header truncated at capture boundary ({} of {SMB1_HEADER} byte(s)); not decoded",
            msg.len()
        );
        layers.push(layer("SMB1 header", info.clone()));
        return smb2_done(info, layers);
    }
    // Header bounds proven above; the fixed fields are read directly.
    let command_code = msg[4];
    let flags = msg[9];
    let flags2 = le16(msg, 10).unwrap_or(0);
    let response = flags & 0x80 != 0;
    let tid = le16(msg, 24).unwrap_or(0);
    let pid = le16(msg, 26).unwrap_or(0);
    let uid = le16(msg, 28).unwrap_or(0);
    let mid = le16(msg, 30).unwrap_or(0);
    let command = match smb1_command_name(command_code) {
        Some(name) => name.to_string(),
        None => format!("command 0x{command_code:02x}"),
    };
    layers.push(layer(
        "SMB1 header",
        format!("tid {tid}, uid {uid}, pid {pid}, mid {mid}"),
    ));
    layers.push(layer("command", command.clone()));
    layers.push(layer("flags", smb1_flags_summary(flags, flags2)));
    let status_text = if response {
        Some(smb1_status_label(msg, flags2))
    } else {
        None
    };
    if let Some(text) = &status_text {
        layers.push(layer("status", text.clone()));
    }
    let mut info = if response {
        format!("SMB1 {command} response")
    } else {
        format!("SMB1 {command}")
    };
    let mut detail = None;
    if !response {
        match command_code {
            0x72 => {
                if let Some(total) = smb1_negotiate_dialects(msg, &mut layers) {
                    detail = Some(format!("{total} dialect(s) offered"));
                }
            }
            0x73 => {
                let window_end = msg.len().min(SMB1_HEADER + MAX_NTLMSSP_WINDOW);
                if let Some((found_detail, value)) =
                    ntlmssp_scan(&msg[SMB1_HEADER..window_end])
                {
                    layers.push(layer("NTLMSSP", value));
                    detail = Some(found_detail);
                }
            }
            _ => {}
        }
    }
    if let Some(detail) = detail {
        info.push_str(", ");
        info.push_str(&detail);
    } else if let Some(text) = &status_text {
        info.push_str(", ");
        info.push_str(text);
    }
    smb2_done(info, layers)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap one SMB message in a NetBIOS session-service header.
    fn nbss(msg: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8, 0];
        out.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        out.extend_from_slice(msg);
        out
    }

    /// Build an SMB2 header: marker, structure size 64, then the fixed
    /// fields in wire order (MS-SMB2 §2.2.1).
    fn smb2_header(command: u16, flags: u32, status: u32, credit: u16) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(SMB2_MARKER);
        h.extend_from_slice(&64u16.to_le_bytes()); // structure size
        h.extend_from_slice(&0u16.to_le_bytes()); // credit charge
        h.extend_from_slice(&status.to_le_bytes());
        h.extend_from_slice(&command.to_le_bytes());
        h.extend_from_slice(&credit.to_le_bytes());
        h.extend_from_slice(&flags.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes()); // next command
        h.extend_from_slice(&7u64.to_le_bytes()); // message id
        h.extend_from_slice(&0xFEFFu32.to_le_bytes()); // process id
        h.extend_from_slice(&1u32.to_le_bytes()); // tree id
        h.extend_from_slice(&1u64.to_le_bytes()); // session id
        h.extend_from_slice(&[0u8; 16]); // signature
        h
    }

    fn smb2_negotiate_request() -> Vec<u8> {
        let mut m = smb2_header(0, 0, 0, 0);
        let mut body = vec![0u8; 36];
        body[0..2].copy_from_slice(&37u16.to_le_bytes()); // structure size
        body[2..4].copy_from_slice(&1u16.to_le_bytes()); // security mode
        body[30..32].copy_from_slice(&3u16.to_le_bytes()); // dialect count
        body[32..34].copy_from_slice(&100u16.to_le_bytes()); // offset
        body[34..36].copy_from_slice(&6u16.to_le_bytes()); // length
        m.extend_from_slice(&body);
        m.extend_from_slice(&0x0202u16.to_le_bytes());
        m.extend_from_slice(&0x0210u16.to_le_bytes());
        m.extend_from_slice(&0x0311u16.to_le_bytes());
        m
    }

    fn smb2_negotiate_response() -> Vec<u8> {
        let mut m = smb2_header(0, 1, 0, 5);
        m.extend_from_slice(&65u16.to_le_bytes()); // structure size
        m.extend_from_slice(&1u16.to_le_bytes()); // security mode
        m.extend_from_slice(&0x0311u16.to_le_bytes()); // dialect revision
        m.extend_from_slice(&[0u8; 48]); // rest of the fixed part + slack
        m
    }

    fn smb2_session_setup(ctype: u32, response: bool) -> Vec<u8> {
        let flags = if response { 1 } else { 0 };
        let status = if response { 0xC000_0016 } else { 0 };
        let mut m = smb2_header(1, flags, status, 1);
        let mut body = vec![0u8; 8];
        body[0..2].copy_from_slice(&25u16.to_le_bytes()); // structure size
        body[2..4].copy_from_slice(&72u16.to_le_bytes()); // blob offset
        body[4..6].copy_from_slice(&16u16.to_le_bytes()); // blob length
        m.extend_from_slice(&body);
        m.extend_from_slice(&NTLMSSP_SIGNATURE[..]);
        m.extend_from_slice(&ctype.to_le_bytes());
        m.extend_from_slice(&[0u8; 4]);
        m
    }

    fn smb2_tree_connect(path: &str) -> Vec<u8> {
        let mut m = smb2_header(3, 0, 0, 1);
        let units: Vec<u16> = path.encode_utf16().collect();
        let path_bytes: usize = units.len() * 2;
        let mut body = vec![0u8; 8];
        body[0..2].copy_from_slice(&9u16.to_le_bytes()); // structure size
        body[4..6].copy_from_slice(&72u16.to_le_bytes()); // path offset
        body[6..8].copy_from_slice(&(path_bytes as u16).to_le_bytes());
        m.extend_from_slice(&body);
        for unit in units {
            m.extend_from_slice(&unit.to_le_bytes());
        }
        m
    }

    /// SMB1 header: marker, command, NT status, flags, flags2, then the
    /// fixed ids (MS-CIFS §2.2.3.1).
    fn smb1_header(command: u8, flags: u8, flags2: u16, status: u32) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(SMB1_MARKER);
        h.push(command);
        h.extend_from_slice(&status.to_le_bytes());
        h.push(flags);
        h.extend_from_slice(&flags2.to_le_bytes());
        h.extend_from_slice(&0u16.to_be_bytes()); // pid high
        h.extend_from_slice(&[0u8; 8]); // signature
        h.extend_from_slice(&[0u8; 2]); // reserved
        h.extend_from_slice(&0u16.to_le_bytes()); // tid
        h.extend_from_slice(&0x0102u16.to_le_bytes()); // pid
        h.extend_from_slice(&0x0800u16.to_le_bytes()); // uid
        h.extend_from_slice(&5u16.to_le_bytes()); // mid
        h
    }

    fn smb1_negotiate_request() -> Vec<u8> {
        let mut m = smb1_header(0x72, 0x18, 0x4001, 0);
        m.push(0); // word count
        let mut tokens = Vec::new();
        for dialect in ["PC NETWORK PROGRAM 1.0", "LANMAN1.0"] {
            tokens.push(0x02);
            tokens.extend_from_slice(dialect.as_bytes());
            tokens.push(0x00);
        }
        m.extend_from_slice(&(tokens.len() as u16).to_le_bytes());
        m.extend_from_slice(&tokens);
        m
    }

    #[test]
    fn smb2_negotiate_request_lists_bounded_dialects() {
        let service = dissect(&nbss(&smb2_negotiate_request())).unwrap();
        assert_eq!(service.protocol, "SMB");
        assert_eq!(service.info, "SMB2 negotiate, 3 dialect(s) offered");
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "NetBIOS session" && l.value.contains("session message, ")));
        assert!(service.layers.iter().any(|l| l.label == "command"
            && l.value == "negotiate"));
        assert!(service.layers.iter().any(|l| l.label == "SMB2 header"
            && l.value.contains("message id 7")
            && l.value.contains("session 1")));
        let dialects = service
            .layers
            .iter()
            .find(|l| l.label == "dialects offered")
            .unwrap();
        assert_eq!(
            dialects.value,
            "3 offered: SMB 2.002, SMB 2.1, SMB 3.1.1"
        );
    }

    #[test]
    fn smb2_negotiate_response_names_dialect_and_max_credit() {
        let service = dissect(&nbss(&smb2_negotiate_response())).unwrap();
        assert_eq!(service.info, "SMB2 negotiate response, dialect SMB 3.1.1");
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "max credit" && l.value == "5"));
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "dialect selected" && l.value == "SMB 3.1.1"));
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "status" && l.value == "STATUS_SUCCESS"));
    }

    #[test]
    fn smb2_session_setup_reports_ntlmssp_type_only() {
        let request = dissect(&smb2_session_setup(1, false)).unwrap();
        assert_eq!(request.info, "SMB2 session setup, NTLMSSP negotiate");
        let note = request.layers.iter().find(|l| l.label == "NTLMSSP").unwrap();
        assert!(note.value.contains("(details not decoded)"));
        assert!(note.value.contains("message type negotiate"));

        let response = dissect(&smb2_session_setup(2, true)).unwrap();
        assert_eq!(
            response.info,
            "SMB2 session setup response, NTLMSSP challenge"
        );
        assert!(response
            .layers
            .iter()
            .any(|l| l.label == "status" && l.value == "STATUS_MORE_PROCESSING_REQUIRED"));
    }

    #[test]
    fn smb2_tree_connect_decodes_bounded_share_name() {
        let service = dissect(&smb2_tree_connect("\\\\server\\share")).unwrap();
        assert_eq!(service.info, "SMB2 tree connect, share \\\\server\\share");
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "share name" && l.value == "\\\\server\\share"));
    }

    #[test]
    fn oversized_share_name_is_refused_not_guessed() {
        let long = format!("\\\\{}", "x".repeat(200));
        let service = dissect(&smb2_tree_connect(&long)).unwrap();
        let share = service
            .layers
            .iter()
            .find(|l| l.label == "share name")
            .unwrap();
        assert!(share.value.contains("not decoded"));
        assert!(share.value.contains("128-character bound"));

        // An odd path length cannot be whole UTF-16 units. The PathLength
        // field sits at header offset 64+6; force it to 1.
        let mut odd = smb2_tree_connect("\\\\ok");
        odd[70] = 0x01;
        let service = dissect(&odd).unwrap();
        let share = service
            .layers
            .iter()
            .find(|l| l.label == "share name")
            .unwrap();
        assert!(share.value.contains("whole UTF-16 units"), "{}", share.value);
    }

    #[test]
    fn smb2_command_names_and_unnamed_fallback() {
        let mut create = smb2_header(5, 0, 0, 1);
        create.extend_from_slice(&[0u8; 8]);
        let service = dissect(&create).unwrap();
        assert_eq!(service.info, "SMB2 create");
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "command" && l.value == "create"));

        let mut unknown = smb2_header(0x2A, 0, 0, 1);
        unknown.extend_from_slice(&[0u8; 8]);
        let service = dissect(&unknown).unwrap();
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "command" && l.value == "command 42"));
    }

    #[test]
    fn truncated_or_malformed_smb2_degrades_honestly() {
        let full = smb2_negotiate_request();
        // A full marker or its two-byte prefix claims the row; a capture
        // shorter than that claims nothing.
        for cut in [0usize, 2, 4, 10, 40] {
            let service = dissect(&nbss(&full[..cut.min(full.len())]));
            assert_eq!(
                service.is_some(),
                cut >= 2,
                "cut {cut}: only a verified marker claims a row"
            );
            if let Some(service) = service {
                assert!(
                    service.info.contains("truncated") || service.info.contains("not decoded"),
                    "cut {cut}: {}",
                    service.info
                );
            }
        }
        // A complete header with no body decodes the header honestly and
        // refuses the body fields instead of inventing them.
        let service = dissect(&nbss(&full[..64])).unwrap();
        assert_eq!(service.info, "SMB2 negotiate");
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "dialects offered" && l.value.contains("not decoded")));
        // One byte short of the negotiate dialect array: what is captured
        // is named and the cut is stated, not guessed.
        let service = dissect(&nbss(&full[..full.len() - 1])).unwrap();
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "dialects offered" && l.value.contains("truncated")));

        // A structure-size lie is refused with the raw value.
        let mut lying = smb2_negotiate_request();
        lying[4] = 63;
        lying[5] = 0;
        let service = dissect(&lying).unwrap();
        assert!(service
            .info
            .contains("structure size 63, expected 64); not decoded"));
    }

    #[test]
    fn nbss_rows_stay_honest() {
        // A keep-alive is a named NetBIOS row, never an SMB claim.
        let service = dissect(&[0x85, 0, 0, 0]).unwrap();
        assert_eq!(service.protocol, "NetBIOS");
        assert_eq!(service.info, "NetBIOS session keep-alive");

        let request = dissect(&[0x81, 0, 0, 12, b'a', b'b']).unwrap();
        assert_eq!(request.protocol, "NetBIOS");
        assert!(request.info.contains("session request"));
        assert!(request.layers.iter().any(|l| l.value.contains("names not decoded")));

        // A session message whose inner bytes carry no SMB marker keeps the
        // transport row: the port alone is not SMB evidence.
        assert!(dissect(&[0x00, 0, 0, 4, 1, 2, 3, 4]).is_none());
        // Random bytes are not claimed at all.
        assert!(dissect(b"plain tcp payload").is_none());
        // A declared length beyond the capture is named, and the marker
        // prefix inside still degrades to the truncated honest row.
        let mut split = vec![0x00, 0];
        split.extend_from_slice(&1000u16.to_be_bytes());
        split.extend_from_slice(&[0xfe, b'S']);
        let service = dissect(&split).unwrap();
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "NetBIOS session" && l.value.contains("truncated at capture boundary")));
        assert!(service.info.contains("truncated"));
    }

    #[test]
    fn smb1_negotiate_request_lists_dialects() {
        let service = dissect(&nbss(&smb1_negotiate_request())).unwrap();
        assert_eq!(service.protocol, "SMB");
        assert_eq!(
            service.info,
            "SMB1 negotiate, 2 dialect(s) offered"
        );
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "SMB1 header" && l.value.contains("mid 5")));
        assert!(service.layers.iter().any(
            |l| l.label == "flags" && l.value.contains("NT status") && l.value.contains("long names")
        ));
        let dialects = service
            .layers
            .iter()
            .find(|l| l.label == "dialects offered")
            .unwrap();
        assert_eq!(
            dialects.value,
            "2 offered: PC NETWORK PROGRAM 1.0, LANMAN1.0"
        );
    }

    #[test]
    fn smb1_dialect_cap_and_refusals_stay_bounded() {
        let mut m = smb1_header(0x72, 0x18, 0x4001, 0);
        m.push(0);
        let mut tokens = Vec::new();
        for index in 0..10 {
            tokens.push(0x02);
            tokens.extend_from_slice(format!("DIALECT {index}").as_bytes());
            tokens.push(0x00);
        }
        m.extend_from_slice(&(tokens.len() as u16).to_le_bytes());
        m.extend_from_slice(&tokens);
        let service = dissect(&m).unwrap();
        let dialects = service
            .layers
            .iter()
            .find(|l| l.label == "dialects offered")
            .unwrap();
        assert!(dialects.value.contains("+2 more (cap 8)"), "{}", dialects.value);

        // A byte area claiming more than captured is named, not guessed.
        let mut truncated = smb1_negotiate_request();
        let n = truncated.len();
        truncated.truncate(n - 4);
        let service = dissect(&truncated).unwrap();
        let dialects = service
            .layers
            .iter()
            .find(|l| l.label == "dialects offered")
            .unwrap();
        assert!(dialects.value.contains("truncated"), "{}", dialects.value);
    }

    #[test]
    fn smb1_session_setup_reports_ntlmssp_marker() {
        let mut m = smb1_header(0x73, 0x18, 0x4001, 0);
        m.push(12); // word count (blob layout is inside the words)
        m.extend_from_slice(&[0u8; 24]);
        let mut blob = Vec::new();
        blob.extend_from_slice(&NTLMSSP_SIGNATURE[..]);
        blob.extend_from_slice(&1u32.to_le_bytes());
        blob.extend_from_slice(&[0u8; 8]);
        m.extend_from_slice(&(blob.len() as u16).to_le_bytes());
        m.extend_from_slice(&blob);
        let service = dissect(&m).unwrap();
        assert_eq!(service.info, "SMB1 session setup (ANDX), NTLMSSP negotiate");
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "NTLMSSP" && l.value.contains("details not decoded")));
    }

    #[test]
    fn smb1_responses_carry_named_or_raw_status() {
        let mut response = smb1_header(0x73, 0x98, 0x4001, 0xC000_0016);
        response.push(0); // word count
        response.extend_from_slice(&0u16.to_le_bytes()); // byte count
        let service = dissect(&response).unwrap();
        assert_eq!(
            service.info,
            "SMB1 session setup (ANDX) response, STATUS_MORE_PROCESSING_REQUIRED"
        );
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "status" && l.value == "STATUS_MORE_PROCESSING_REQUIRED"));
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "flags" && l.value.contains("reply")));

        // An unnamed NT status keeps the raw code with the honest note.
        let mut odd = smb1_header(0x72, 0x98, 0x4001, 0xDEAD_BEEF);
        odd.push(0);
        odd.extend_from_slice(&0u16.to_le_bytes());
        let service = dissect(&odd).unwrap();
        assert!(service.info.contains("0xdeadbeef"), "{}", service.info);

        // Without the FLAGS2 NT status bit the legacy DOS class/code is
        // reported untranslated.
        let mut dos = smb1_header(0x72, 0x98, 0x0001, 0x0006_0002);
        dos.push(0);
        dos.extend_from_slice(&0u16.to_le_bytes());
        let service = dissect(&dos).unwrap();
        assert!(service
            .info
            .contains("error class 0x02 code 0x0006 (not translated)"));
    }

    #[test]
    fn truncated_smb1_header_degrades_honestly() {
        let full = smb1_negotiate_request();
        for cut in [1usize, 8, 31] {
            let service = dissect(&nbss(&full[..cut.min(full.len())]));
            let claimed = cut >= 4;
            assert_eq!(service.is_some(), claimed, "cut {cut}");
            if let Some(service) = service {
                assert!(
                    service.info.contains("truncated") || service.info.contains("not decoded"),
                    "cut {cut}: {}",
                    service.info
                );
            }
        }
        // With the full 32-byte header present the header decodes; the
        // dialect tokens that no longer fit are refused, not guessed.
        let service = dissect(&nbss(&full[..34])).unwrap();
        assert_eq!(service.info, "SMB1 negotiate");
        assert!(service
            .layers
            .iter()
            .any(|l| l.label == "dialects offered" && l.value.contains("not decoded")));
    }

    /// Truncations and adversarial byte mutations across every fixture must
    /// either refuse (None) or produce an honest row — never panic and
    /// never claim a protocol outside SMB/NetBIOS.
    #[test]
    fn fuzz_truncations_and_mutations_refuse_or_degrade_honestly() {
        let fixtures: Vec<Vec<u8>> = vec![
            nbss(&smb2_negotiate_request()),
            nbss(&smb2_negotiate_response()),
            nbss(&smb2_session_setup(1, false)),
            nbss(&smb2_session_setup(3, true)),
            nbss(&smb2_tree_connect("\\\\server\\share")),
            nbss(&smb1_negotiate_request()),
            smb1_negotiate_request(),
        ];
        let mut checked = 0usize;
        for fixture in &fixtures {
            for cut in 0..fixture.len() {
                if let Some(service) = dissect(&fixture[..cut]) {
                    assert!(
                        service.protocol == "SMB" || service.protocol == "NetBIOS",
                        "cut {cut}: protocol {}",
                        service.protocol
                    );
                    assert!(!service.info.is_empty());
                }
                checked += 1;
            }
            for position in (0..fixture.len()).step_by(2) {
                for value in [0x00u8, 0x01, 0x80, 0xfe, 0xff] {
                    let mut mutated = fixture.clone();
                    mutated[position] = value;
                    if let Some(service) = dissect(&mutated) {
                        assert!(
                            service.protocol == "SMB" || service.protocol == "NetBIOS",
                            "position {position} value {value:#x}: protocol {}",
                            service.protocol
                        );
                    }
                    checked += 1;
                }
            }
        }
        assert!(checked > 2_000, "coverage too small: {checked}");
    }
}
