//! TLS hello depth: named cipher suites, extension inventory, supported
//! versions, key-share groups and signature algorithms for a single captured
//! hello record. Passive and bounded: only bytes already captured are read,
//! every emitted list is capped, and anything that cannot be interpreted is
//! reported honestly ("not decoded", raw codes) instead of guessed.

const MAX_TLS_RECORD: usize = 18_432; // mirrors the protocol.rs record bound
const MAX_LISTED_EXTENSIONS: usize = 24;
const MAX_LISTED_VERSIONS: usize = 8;
const MAX_LISTED_GROUPS: usize = 8;
const MAX_LISTED_SIGALGS: usize = 8;
const NOT_DECODED: &str = "not decoded (malformed body)";

fn be16(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        data.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn field8<'a>(data: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let count = *data.get(*pos)? as usize;
    *pos = pos.checked_add(1)?;
    let end = pos.checked_add(count)?;
    let value = data.get(*pos..end)?;
    *pos = end;
    Some(value)
}
fn field16<'a>(data: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let count = be16(data, *pos)? as usize;
    *pos = pos.checked_add(2)?;
    let end = pos.checked_add(count)?;
    let value = data.get(*pos..end)?;
    *pos = end;
    Some(value)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsDepth {
    /// Named selected suite for a ServerHello. A ClientHello only offers a
    /// list of suites, so no single suite is claimed for it.
    pub cipher_name: Option<String>,
    /// Named extensions in wire order, capped. Codes outside the name table
    /// fall back to the honest `extension {code}` form.
    pub extensions: Vec<String>,
    /// Offered (ClientHello) or selected (ServerHello) protocol versions.
    pub supported_versions: Vec<String>,
    /// Named groups from the key_share extension (the HRR form names the
    /// bare selected group).
    pub key_share_groups: Vec<String>,
    /// Named algorithms from the signature_algorithms extension.
    pub signature_algorithms: Vec<String>,
}

fn push_capped(list: &mut Vec<String>, overflow: &mut usize, value: String, cap: usize) {
    if list.len() < cap {
        list.push(value);
    } else {
        *overflow += 1;
    }
}
fn note_overflow(list: &mut Vec<String>, overflow: usize, cap: usize) {
    if overflow > 0 {
        list.push(format!("+{overflow} more (cap {cap})"));
    }
}

fn version_name(version: u16) -> String {
    // Mirrors the protocol.rs version formatter so both descriptions agree.
    match version {
        0x0301 => "TLS1.0".into(),
        0x0302 => "TLS1.1".into(),
        0x0303 => "TLS1.2".into(),
        0x0304 => "TLS1.3".into(),
        v => format!("0x{v:04x}"),
    }
}

/// IANA-assigned names for the commonly deployed cipher suites; anything
/// outside the table degrades to the raw code instead of an invented name.
pub fn cipher_suite_name(code: u16) -> String {
    match code {
        0x1301 => "TLS_AES_128_GCM_SHA256".into(),
        0x1302 => "TLS_AES_256_GCM_SHA384".into(),
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256".into(),
        0x1304 => "TLS_AES_128_CCM_SHA256".into(),
        0x1305 => "TLS_AES_128_CCM_8_SHA256".into(),
        0x0005 => "TLS_RSA_WITH_RC4_128_SHA".into(),
        0x000A => "TLS_RSA_WITH_3DES_EDE_CBC_SHA".into(),
        0x002F => "TLS_RSA_WITH_AES_128_CBC_SHA".into(),
        0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA".into(),
        0x003C => "TLS_RSA_WITH_AES_128_CBC_SHA256".into(),
        0x003D => "TLS_RSA_WITH_AES_256_CBC_SHA256".into(),
        0x009C => "TLS_RSA_WITH_AES_128_GCM_SHA256".into(),
        0x009D => "TLS_RSA_WITH_AES_256_GCM_SHA384".into(),
        0xC009 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA".into(),
        0xC00A => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA".into(),
        0xC013 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA".into(),
        0xC014 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA".into(),
        0xC023 => "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256".into(),
        0xC024 => "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384".into(),
        0xC027 => "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256".into(),
        0xC028 => "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384".into(),
        0xC02B => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".into(),
        0xC02C => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".into(),
        0xC02F => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".into(),
        0xC030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".into(),
        0xCCA8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".into(),
        0xCCA9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".into(),
        0x00FF => "TLS_EMPTY_RENEGOTIATION_INFO_SCSV".into(),
        _ => format!("0x{code:04x}"),
    }
}

/// Named extensions from the IANA TLS extension registry; unknown codes
/// degrade to `extension {code}`.
pub fn extension_name(code: u16) -> String {
    match code {
        0 => "server_name".into(),
        1 => "max_fragment_length".into(),
        5 => "status_request".into(),
        10 => "supported_groups".into(),
        11 => "ec_point_formats".into(),
        13 => "signature_algorithms".into(),
        16 => "alpn".into(),
        17 => "status_request_v2".into(),
        18 => "signed_certificate_timestamp".into(),
        21 => "padding".into(),
        22 => "encrypt_then_mac".into(),
        23 => "extended_master_secret".into(),
        27 => "compress_certificate".into(),
        28 => "record_size_limit".into(),
        35 => "session_ticket".into(),
        41 => "pre_shared_key".into(),
        42 => "early_data".into(),
        43 => "supported_versions".into(),
        44 => "cookie".into(),
        45 => "psk_key_exchange_modes".into(),
        49 => "post_handshake_auth".into(),
        50 => "signature_algorithms_cert".into(),
        51 => "key_share".into(),
        57 => "quic_transport_parameters".into(),
        13172 => "next_protocol_negotiation".into(),
        65281 => "renegotiation_info".into(),
        _ => format!("extension {code}"),
    }
}

/// Named groups from the IANA TLS supported groups registry (EC curves,
/// x25519/x448 and the RFC 7919 ffdhe set); unknown codes degrade to
/// `group {code}`.
pub fn named_group_name(code: u16) -> String {
    match code {
        22 => "secp256k1".into(),
        23 => "secp256r1".into(),
        24 => "secp384r1".into(),
        25 => "secp521r1".into(),
        26 => "brainpoolP256r1".into(),
        27 => "brainpoolP384r1".into(),
        28 => "brainpoolP512r1".into(),
        29 => "x25519".into(),
        30 => "x448".into(),
        256 => "ffdhe2048".into(),
        257 => "ffdhe3072".into(),
        258 => "ffdhe4096".into(),
        259 => "ffdhe6144".into(),
        260 => "ffdhe8192".into(),
        _ => format!("group {code}"),
    }
}

/// Named signature algorithms from the IANA TLS SignatureScheme registry;
/// unknown codes degrade to the raw hex form.
pub fn signature_algorithm_name(code: u16) -> String {
    match code {
        0x0201 => "rsa_pkcs1_sha1".into(),
        0x0203 => "ecdsa_sha1".into(),
        0x0401 => "rsa_pkcs1_sha256".into(),
        0x0403 => "ecdsa_secp256r1_sha256".into(),
        0x0501 => "rsa_pkcs1_sha384".into(),
        0x0503 => "ecdsa_secp384r1_sha384".into(),
        0x0601 => "rsa_pkcs1_sha512".into(),
        0x0603 => "ecdsa_secp521r1_sha512".into(),
        0x0804 => "rsa_pss_rsae_sha256".into(),
        0x0805 => "rsa_pss_rsae_sha384".into(),
        0x0806 => "rsa_pss_rsae_sha512".into(),
        0x0807 => "ed25519".into(),
        0x0808 => "ed448".into(),
        0x0809 => "rsa_pss_pss_sha256".into(),
        0x080A => "rsa_pss_pss_sha384".into(),
        0x080B => "rsa_pss_pss_sha512".into(),
        _ => format!("0x{code:04x}"),
    }
}

fn supported_version_names(client: bool, body: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut overflow = 0usize;
    if client {
        let Some(&list_len) = body.first() else {
            out.push(NOT_DECODED.to_owned());
            return out;
        };
        if list_len as usize + 1 != body.len() || body.len() % 2 != 1 {
            out.push(NOT_DECODED.to_owned());
            return out;
        }
        for pair in body[1..].chunks_exact(2) {
            let offered = u16::from_be_bytes([pair[0], pair[1]]);
            push_capped(
                &mut out,
                &mut overflow,
                version_name(offered),
                MAX_LISTED_VERSIONS,
            );
        }
    } else {
        if body.len() != 2 {
            out.push(NOT_DECODED.to_owned());
            return out;
        }
        out.push(version_name(u16::from_be_bytes([body[0], body[1]])));
    }
    note_overflow(&mut out, overflow, MAX_LISTED_VERSIONS);
    out
}

fn key_share_groups(client: bool, body: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut overflow = 0usize;
    let mut degraded = false;
    if client {
        let list_len = match be16(body, 0) {
            Some(len) => len as usize,
            None => {
                degraded = true;
                0
            }
        };
        if !degraded && list_len + 2 != body.len() {
            degraded = true;
        }
        let mut at = 2usize;
        while !degraded && at < body.len() {
            let (Some(group), Some(kex_len)) = (be16(body, at), be16(body, at + 2)) else {
                degraded = true;
                break;
            };
            let end = at + 4 + kex_len as usize;
            if end > body.len() {
                degraded = true;
                break;
            }
            push_capped(
                &mut out,
                &mut overflow,
                named_group_name(group),
                MAX_LISTED_GROUPS,
            );
            at = end;
        }
    } else if body.len() == 2 {
        // HelloRetryRequest carries a bare selected group, no share.
        match be16(body, 0) {
            Some(group) => out.push(named_group_name(group)),
            None => degraded = true,
        }
    } else {
        match (be16(body, 0), be16(body, 2)) {
            (Some(group), Some(kex_len)) if 4 + kex_len as usize == body.len() => {
                out.push(named_group_name(group));
            }
            _ => degraded = true,
        }
    }
    if degraded {
        // Whatever parsed before the inconsistency stays; the marker claims
        // only that the remainder was not decoded.
        out.push(NOT_DECODED.to_owned());
    }
    note_overflow(&mut out, overflow, MAX_LISTED_GROUPS);
    out
}

fn signature_algorithm_names(body: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut overflow = 0usize;
    match be16(body, 0) {
        Some(list_len) if list_len as usize + 2 == body.len() && body.len() % 2 == 0 => {
            for pair in body[2..].chunks_exact(2) {
                let algorithm = u16::from_be_bytes([pair[0], pair[1]]);
                push_capped(
                    &mut out,
                    &mut overflow,
                    signature_algorithm_name(algorithm),
                    MAX_LISTED_SIGALGS,
                );
            }
        }
        _ => out.push(NOT_DECODED.to_owned()),
    }
    note_overflow(&mut out, overflow, MAX_LISTED_SIGALGS);
    out
}

/// Depth of one captured hello record, bounded and honest. The acceptance
/// discipline is inherited from the bounded hello walk: whatever
/// `protocol::tls_hello` refuses (record framing, bounds, malformed
/// SNI/ALPN/versions) yields no depth rather than a partial claim.
pub fn hello_depth(data: &[u8]) -> Option<TlsDepth> {
    let hello = super::protocol::tls_hello(data)?;
    // Locate the same record/handshake span the hello walk just validated;
    // only bytes inside the captured first record are ever read.
    let record_len = be16(data, 3)? as usize;
    if !(4..=MAX_TLS_RECORD).contains(&record_len) || data.len() < record_len + 5 {
        return None;
    }
    let record = &data[5..5 + record_len];
    let handshake_len =
        ((record[1] as usize) << 16) | ((record[2] as usize) << 8) | record[3] as usize;
    if handshake_len + 4 > record.len() {
        return None;
    }
    let hello_bytes = &record[4..4 + handshake_len];
    let client = hello.client;
    let mut cursor = 34usize; // legacy version + 32-byte random
    field8(hello_bytes, &mut cursor)?; // session ID
    let cipher_name = if client {
        let suites = field16(hello_bytes, &mut cursor)?;
        if suites.is_empty() || suites.len() % 2 != 0 {
            return None;
        }
        if field8(hello_bytes, &mut cursor)?.is_empty() {
            return None;
        }
        None
    } else {
        let selected = be16(hello_bytes, cursor)?;
        cursor += 2;
        hello_bytes.get(cursor)?; // legacy compression byte, parsed but unused
        cursor += 1;
        Some(cipher_suite_name(selected))
    };
    let extensions: &[u8] = if cursor == hello_bytes.len() {
        &[]
    } else {
        let block = field16(hello_bytes, &mut cursor)?;
        if cursor != hello_bytes.len() {
            return None;
        }
        block
    };
    let mut depth = TlsDepth {
        cipher_name,
        extensions: Vec::new(),
        supported_versions: Vec::new(),
        key_share_groups: Vec::new(),
        signature_algorithms: Vec::new(),
    };
    let mut at = 0usize;
    let mut unlisted = 0usize;
    while at < extensions.len() {
        let kind = be16(extensions, at)?;
        let count = be16(extensions, at + 2)? as usize;
        at += 4;
        let end = at.checked_add(count)?;
        let body = extensions.get(at..end)?;
        at = end;
        match kind {
            13 => depth.signature_algorithms = signature_algorithm_names(body),
            43 => depth.supported_versions = supported_version_names(client, body),
            51 => depth.key_share_groups = key_share_groups(client, body),
            _ => {}
        }
        if depth.extensions.len() < MAX_LISTED_EXTENSIONS {
            depth.extensions.push(extension_name(kind));
        } else {
            unlisted += 1;
        }
    }
    note_overflow(&mut depth.extensions, unlisted, MAX_LISTED_EXTENSIONS);
    Some(depth)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extension(code: u16, body: &[u8]) -> Vec<u8> {
        let mut out = code.to_be_bytes().to_vec();
        out.extend((body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }

    fn handshake(kind: u8, hello: &[u8]) -> Vec<u8> {
        let len = hello.len() as u16;
        let mut message = vec![kind, 0, (len >> 8) as u8, len as u8];
        message.extend_from_slice(hello);
        let mut out = vec![22, 3, 3];
        out.extend((message.len() as u16).to_be_bytes());
        out.extend_from_slice(&message);
        out
    }

    fn client_hello(extensions: &[u8]) -> Vec<u8> {
        let mut h = vec![3, 3];
        h.extend([7; 32]);
        h.push(0); // session ID
        h.extend([0, 2, 0x13, 0x01]); // cipher suites
        h.extend([1, 0]); // compression methods
        h.extend((extensions.len() as u16).to_be_bytes());
        h.extend_from_slice(extensions);
        h
    }

    fn server_hello(cipher: u16, extensions: &[u8]) -> Vec<u8> {
        let mut h = vec![3, 3];
        h.extend([9; 32]);
        h.push(0); // session ID
        h.extend(cipher.to_be_bytes());
        h.push(0); // compression
        h.extend((extensions.len() as u16).to_be_bytes());
        h.extend_from_slice(extensions);
        h
    }

    fn depth_client_hello() -> Vec<u8> {
        let mut extensions = Vec::new();
        let host = b"example.com";
        let mut sni_body = vec![0, (host.len() + 3) as u8, 0, 0, host.len() as u8];
        sni_body.extend(host);
        extensions.extend(extension(0, &sni_body));
        extensions.extend(extension(10, &[0, 4, 0x00, 0x1D, 0x00, 0x17]));
        extensions.extend(extension(13, &[0, 6, 0x04, 0x03, 0x08, 0x04, 0x08, 0x05]));
        let mut alpn_body = vec![0, 12, 2, b'h', b'2', 8];
        alpn_body.extend(b"http/1.1");
        extensions.extend(extension(16, &alpn_body));
        extensions.extend(extension(35, &[]));
        extensions.extend(extension(22, &[]));
        extensions.extend(extension(23, &[]));
        extensions.extend(extension(45, &[1, 1]));
        // supported_versions list length counts bytes, not entries.
        extensions.extend(extension(43, &[4, 3, 4, 3, 3]));
        let mut ks_body = vec![0, 36, 0x00, 0x1D, 0, 32];
        ks_body.extend([5; 32]);
        extensions.extend(extension(51, &ks_body));
        extensions.extend(extension(42, &[]));
        extensions.extend(extension(0x1234, &[0xAA]));
        handshake(1, &client_hello(&extensions))
    }

    fn depth_server_hello() -> Vec<u8> {
        let mut extensions = extension(43, &[3, 4]);
        let mut ks_body = vec![0x00, 0x1D, 0, 32];
        ks_body.extend([6; 32]);
        extensions.extend(extension(51, &ks_body));
        handshake(2, &server_hello(0x1302, &extensions))
    }

    #[test]
    fn name_tables_cover_the_documented_iana_entries() {
        assert_eq!(cipher_suite_name(0x1301), "TLS_AES_128_GCM_SHA256");
        assert_eq!(cipher_suite_name(0x1302), "TLS_AES_256_GCM_SHA384");
        assert_eq!(cipher_suite_name(0x1303), "TLS_CHACHA20_POLY1305_SHA256");
        assert_eq!(cipher_suite_name(0x002F), "TLS_RSA_WITH_AES_128_CBC_SHA");
        assert_eq!(cipher_suite_name(0x0035), "TLS_RSA_WITH_AES_256_CBC_SHA");
        assert_eq!(
            cipher_suite_name(0xC02F),
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        );
        assert_eq!(
            cipher_suite_name(0xCCA8),
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
        );
        assert_eq!(
            cipher_suite_name(0x00FF),
            "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
        );
        assert_eq!(cipher_suite_name(0xFFFF), "0xffff");
        assert_eq!(extension_name(0), "server_name");
        assert_eq!(extension_name(10), "supported_groups");
        assert_eq!(extension_name(11), "ec_point_formats");
        assert_eq!(extension_name(13), "signature_algorithms");
        assert_eq!(extension_name(16), "alpn");
        assert_eq!(extension_name(22), "encrypt_then_mac");
        assert_eq!(extension_name(23), "extended_master_secret");
        assert_eq!(extension_name(35), "session_ticket");
        assert_eq!(extension_name(41), "pre_shared_key");
        assert_eq!(extension_name(42), "early_data");
        assert_eq!(extension_name(43), "supported_versions");
        assert_eq!(extension_name(51), "key_share");
        assert_eq!(extension_name(65281), "renegotiation_info");
        assert_eq!(extension_name(4660), "extension 4660");
        assert_eq!(named_group_name(23), "secp256r1");
        assert_eq!(named_group_name(24), "secp384r1");
        assert_eq!(named_group_name(25), "secp521r1");
        assert_eq!(named_group_name(29), "x25519");
        assert_eq!(named_group_name(30), "x448");
        assert_eq!(named_group_name(256), "ffdhe2048");
        assert_eq!(named_group_name(260), "ffdhe8192");
        assert_eq!(named_group_name(999), "group 999");
        assert_eq!(signature_algorithm_name(0x0403), "ecdsa_secp256r1_sha256");
        assert_eq!(signature_algorithm_name(0x0804), "rsa_pss_rsae_sha256");
        assert_eq!(signature_algorithm_name(0x0805), "rsa_pss_rsae_sha384");
        assert_eq!(signature_algorithm_name(0x0806), "rsa_pss_rsae_sha512");
        assert_eq!(signature_algorithm_name(0x0401), "rsa_pkcs1_sha256");
        assert_eq!(signature_algorithm_name(0x7000), "0x7000");
    }

    #[test]
    fn clienthello_depth_inventories_named_extensions_and_lists() {
        let depth = hello_depth(&depth_client_hello()).unwrap();
        // A ClientHello offers many suites, so no single suite is named.
        assert_eq!(depth.cipher_name, None);
        assert_eq!(
            depth.extensions,
            [
                "server_name",
                "supported_groups",
                "signature_algorithms",
                "alpn",
                "session_ticket",
                "encrypt_then_mac",
                "extended_master_secret",
                "psk_key_exchange_modes",
                "supported_versions",
                "key_share",
                "early_data",
                "extension 4660",
            ]
        );
        assert_eq!(depth.supported_versions, ["TLS1.3", "TLS1.2"]);
        assert_eq!(depth.key_share_groups, ["x25519"]);
        assert_eq!(
            depth.signature_algorithms,
            [
                "ecdsa_secp256r1_sha256",
                "rsa_pss_rsae_sha256",
                "rsa_pss_rsae_sha384",
            ]
        );
    }

    #[test]
    fn serverhello_depth_names_the_selected_suite_and_share() {
        let depth = hello_depth(&depth_server_hello()).unwrap();
        assert_eq!(depth.cipher_name.as_deref(), Some("TLS_AES_256_GCM_SHA384"));
        assert_eq!(depth.extensions, ["supported_versions", "key_share"]);
        assert_eq!(depth.supported_versions, ["TLS1.3"]);
        assert_eq!(depth.key_share_groups, ["x25519"]);
        assert!(depth.signature_algorithms.is_empty());
    }

    #[test]
    fn hello_retry_request_names_the_bare_selected_group() {
        let data = handshake(2, &server_hello(0x1301, &extension(51, &[0x00, 0x1D])));
        let depth = hello_depth(&data).unwrap();
        assert_eq!(depth.key_share_groups, ["x25519"]);
    }

    #[test]
    fn hello_without_extensions_yields_empty_depth() {
        let depth = hello_depth(&handshake(1, &client_hello(&[]))).unwrap();
        assert!(depth.extensions.is_empty());
        assert!(depth.supported_versions.is_empty());
        assert!(depth.key_share_groups.is_empty());
        assert_eq!(depth.cipher_name, None);
        let server = hello_depth(&handshake(2, &server_hello(0xC02F, &[]))).unwrap();
        assert_eq!(
            server.cipher_name.as_deref(),
            Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
        );
        assert!(server.extensions.is_empty());
    }

    #[test]
    fn malformed_structured_bodies_degrade_without_dropping_the_hello() {
        // A signature_algorithms body whose declared list length overruns the
        // extension is still a well-formed hello: the depth pass reports the
        // failure honestly instead of refusing the whole record.
        let mut extensions = extension(13, &[0, 9, 0x04, 0x03]);
        // A first valid x25519 share, then a second entry whose declared
        // share length overruns the extension body.
        extensions.extend(extension(
            51,
            &[0, 12, 0x00, 0x1D, 0, 4, 1, 2, 3, 4, 0x00, 0x1D, 0, 40],
        ));
        let depth = hello_depth(&handshake(1, &client_hello(&extensions))).unwrap();
        assert_eq!(depth.signature_algorithms, ["not decoded (malformed body)"]);
        assert_eq!(
            depth.key_share_groups,
            ["x25519", "not decoded (malformed body)"]
        );
    }

    #[test]
    fn listing_caps_truncate_with_honest_markers() {
        // 30 extensions: the first 24 are named, the remainder summarized.
        let mut extensions = Vec::new();
        for _ in 0..30 {
            extensions.extend(extension(0x1FFF, &[]));
        }
        let depth = hello_depth(&handshake(1, &client_hello(&extensions))).unwrap();
        assert_eq!(depth.extensions.len(), MAX_LISTED_EXTENSIONS + 1);
        assert!(depth.extensions[..24]
            .iter()
            .all(|name| name == "extension 8191"));
        assert_eq!(depth.extensions[24], "+6 more (cap 24)");

        // 12 offered signature algorithms list 8 plus the honest remainder.
        let mut sigalgs = vec![0, 24];
        for _ in 0..12 {
            sigalgs.extend([0x04, 0x01]);
        }
        let depth = hello_depth(&handshake(1, &client_hello(&extension(13, &sigalgs)))).unwrap();
        assert_eq!(
            depth.signature_algorithms,
            [
                "rsa_pkcs1_sha256",
                "rsa_pkcs1_sha256",
                "rsa_pkcs1_sha256",
                "rsa_pkcs1_sha256",
                "rsa_pkcs1_sha256",
                "rsa_pkcs1_sha256",
                "rsa_pkcs1_sha256",
                "rsa_pkcs1_sha256",
                "+4 more (cap 8)",
            ]
        );
    }

    #[test]
    fn depth_refuses_exactly_what_the_hello_walk_refuses() {
        assert!(hello_depth(b"not tls").is_none());
        let mut truncated = depth_client_hello();
        truncated.pop();
        assert!(hello_depth(&truncated).is_none());
        let mut bad_record = depth_client_hello();
        bad_record[3] = 0xff;
        assert!(hello_depth(&bad_record).is_none());
    }

    #[test]
    fn mutated_and_hostile_buffers_never_panic_the_depth_pass() {
        let mut seed = 0x9e37_79b9u32;
        for len in 0..600 {
            let mut input = Vec::with_capacity(len);
            for _ in 0..len {
                seed ^= seed << 13;
                seed ^= seed >> 17;
                seed ^= seed << 5;
                input.push((seed & 0xff) as u8);
            }
            let _ = hello_depth(&input);
        }
        let base = depth_client_hello();
        for at in 0..base.len() {
            for value in [0u8, 1, 0x7f, 0xff] {
                let mut data = base.clone();
                data[at] = value;
                let _ = hello_depth(&data);
            }
        }
    }
}
