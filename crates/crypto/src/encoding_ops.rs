//! CyberChef "Data format" (the classic Encoding category) codec ops, ported
//! natively pure-std. Semantics and parameter defaults mirror the upstream
//! operations (gchq/CyberChef src/core/operations) unless noted on the op.
//! to_base58check and unicode_text_format are CyberDeck extras named in the
//! catalog request, not upstream ops.

use base64::Engine as _;

pub fn supports(id: &str) -> bool {
    matches!(
        id,
        "to_base45" | "from_base45"
            | "to_base58" | "from_base58"
            | "to_base58check" | "from_base58check"
            | "to_base62" | "from_base62"
            | "to_base85" | "from_base85"
            | "to_base92" | "from_base92"
            | "to_bech32" | "from_bech32"
            | "to_base" | "from_base"
            | "to_octal" | "from_octal"
            | "to_bcd" | "from_bcd"
            | "to_float" | "from_float"
            | "escape_unicode" | "unescape_unicode"
            | "escape_smart_chars"
            | "to_hex_content" | "from_hex_content"
            | "caret_m_decode"
            | "to_modhex" | "from_modhex"
            | "to_quoted_printable" | "from_quoted_printable"
            | "to_punycode" | "from_punycode"
            | "mime_decode"
            | "pem_to_hex" | "hex_to_pem"
            | "parse_asn1_hex_string"
            | "parse_tlv"
            | "change_ip_format"
            | "text_integer_conversion"
            | "to_braille" | "from_braille"
            | "to_cobs" | "from_cobs"
            | "encode_text" | "decode_text"
            | "unicode_text_format"
    )
}

fn text(input: &[u8]) -> String {
    String::from_utf8_lossy(input).into_owned()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX_UPPER[usize::from(b >> 4)] as char);
        out.push(HEX_UPPER[usize::from(b & 0x0f)] as char);
    }
    out
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if clean.len() % 2 != 0 {
        return Err("hex input has an odd number of digits".into());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// CyberChef's Utils.expandAlphRange: "0-9A-Za-z" tokens become inclusive
/// ranges, "\\-" is a literal hyphen.
fn expand_alph_range(spec: &str) -> Vec<u8> {
    let chars: Vec<char> = spec.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if i + 2 < chars.len() && chars[i + 1] == '-' && chars[i] != '\\' {
            for cp in (chars[i] as u32)..=(chars[i + 2] as u32) {
                out.push(cp as u8);
            }
            i += 3;
        } else if i + 1 < chars.len() && chars[i] == '\\' && chars[i + 1] == '-' {
            out.push(b'-');
            i += 2;
        } else {
            out.push(chars[i] as u8);
            i += 1;
        }
    }
    out
}

fn resolve_alphabet(
    param: Option<&str>,
    default_spec: &str,
    presets: &[(&str, &str)],
) -> Result<Vec<u8>, String> {
    let spec = param
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .unwrap_or(default_spec);
    for (name, value) in presets {
        if spec.eq_ignore_ascii_case(name) {
            return Ok(value.as_bytes().to_vec());
        }
    }
    let alphabet = expand_alph_range(spec);
    if alphabet.is_empty() {
        return Err("alphabet must not be empty".into());
    }
    Ok(alphabet)
}

// --- big-number base conversion (CyberChef's digit-array method) ------------

/// Bytes (big-endian number) to digits in `base`, LSB-first.
fn bytes_to_digits(input: &[u8], base: u32) -> Vec<u32> {
    let mut digits: Vec<u32> = Vec::new();
    for &byte in input {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut() {
            carry += *digit << 8;
            *digit = carry % base;
            carry /= base;
        }
        while carry > 0 {
            digits.push(carry % base);
            carry /= base;
        }
    }
    digits
}

/// Digits (LSB-first) in `base` to a big-endian byte string; leading zero
/// bytes of the number are absent.
fn digits_to_bytes(digits: impl IntoIterator<Item = u32>, base: u32) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for digit in digits {
        let mut carry = digit;
        for byte in out.iter_mut() {
            carry += u32::from(*byte) * base;
            *byte = (carry & 0xFF) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            out.push((carry & 0xFF) as u8);
            carry >>= 8;
        }
    }
    out.reverse();
    out
}

// --- Base45 (RFC 9285; CyberChef ToBase45/FromBase45) -----------------------

const BASE45_DEFAULT: &str = "0-9A-Z $%*+\\-./:";

fn base45_encode(input: &[u8], alphabet: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for pair in input.chunks(2) {
        let value = pair.iter().fold(0u32, |acc, &b| acc * 256 + u32::from(b));
        let mut chars = 0;
        let mut left = value;
        loop {
            out.push(alphabet[(left % 45) as usize]);
            chars += 1;
            left /= 45;
            if left == 0 {
                break;
            }
        }
        if chars < 2 {
            // CyberChef pads with the literal "0"; alphabet[0] is identical
            // for the RFC alphabet and stays consistent for custom ones.
            out.push(alphabet[0]);
            chars += 1;
        }
        if pair.len() > 1 && chars < 3 {
            out.push(alphabet[0]);
        }
    }
    Ok(out)
}

fn base45_decode(input: &[u8], alphabet: &[u8], strict: bool) -> Result<Vec<u8>, String> {
    let filtered: String = if strict {
        text(input)
    } else {
        text(input)
            .chars()
            .filter(|c| c.is_ascii() && alphabet.contains(&(*c as u8)))
            .collect()
    };
    let mut out = Vec::new();
    for triple in filtered.as_bytes().chunks(3) {
        let mut value = 0u32;
        for &ch in triple.iter().rev() {
            let idx = alphabet
                .iter()
                .position(|a| *a == ch)
                .ok_or_else(|| format!("Character not in alphabet: '{}'", ch as char))?;
            value = value * 45 + idx as u32;
        }
        if value > 65535 {
            return Err(format!("Triplet too large: '{}'", String::from_utf8_lossy(triple)));
        }
        if triple.len() > 2 {
            out.push((value >> 8) as u8);
        }
        out.push((value & 0xFF) as u8);
    }
    Ok(out)
}

// --- Base58 (CyberChef ToBase58/FromBase58) ---------------------------------

const BASE58_BITCOIN: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58_RIPPLE: &str = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

fn base58_alphabet(param: Option<&str>) -> Result<Vec<u8>, String> {
    let alphabet = resolve_alphabet(
        param,
        BASE58_BITCOIN,
        &[("bitcoin", BASE58_BITCOIN), ("ripple", BASE58_RIPPLE)],
    )?;
    if alphabet.len() != 58 {
        return Err("Error: alphabet must be of length 58".into());
    }
    Ok(alphabet)
}

fn base58_encode(input: &[u8], alphabet: &[u8]) -> Vec<u8> {
    let zero_prefix = input.iter().take_while(|&&b| b == 0).count();
    let digits = bytes_to_digits(input, 58);
    let mut out: Vec<u8> = digits.iter().rev().map(|&d| alphabet[d as usize]).collect();
    for _ in 0..zero_prefix {
        out.insert(0, alphabet[0]);
    }
    out
}

fn base58_decode(input: &[u8], alphabet: &[u8]) -> Result<Vec<u8>, String> {
    let source = text(input);
    let zero_prefix = source
        .chars()
        .take_while(|c| *c as u32 == u32::from(alphabet[0]))
        .count();
    let mut out = digits_to_bytes(
        source
            .chars()
            .filter_map(|c| alphabet.iter().position(|a| *a as char == c).map(|p| p as u32)),
        58,
    );
    for _ in 0..zero_prefix {
        out.insert(0, 0);
    }
    Ok(out)
}

// --- Base58Check (CyberDeck extra: Bitcoin developer reference) -------------

fn base58check_alphabet_and_version(param: Option<&str>) -> Result<(Vec<u8>, u8), String> {
    let (alphabet_param, version_param) = match param {
        Some(p) => p
            .split_once(',')
            .map_or((Some(p), None), |(a, v)| (Some(a), Some(v))),
        None => (None, None),
    };
    let alphabet = base58_alphabet(alphabet_param)?;
    let version = match version_param.map(str::trim).filter(|v| !v.is_empty()) {
        None => 0,
        Some(raw) => {
            let hex = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X"));
            match hex {
                Some(digits) => {
                    u8::from_str_radix(digits, 16).map_err(|_| "invalid version byte".to_string())?
                }
                None => raw.parse::<u8>().map_err(|_| "invalid version byte".to_string())?,
            }
        }
    };
    Ok((alphabet, version))
}

fn base58check_encode(input: &[u8], alphabet: &[u8], version: u8) -> Vec<u8> {
    let mut payload = vec![version];
    payload.extend_from_slice(input);
    let checksum = sha256d(&payload);
    payload.extend_from_slice(&checksum[..4]);
    base58_encode(&payload, alphabet)
}

fn base58check_decode(input: &[u8], alphabet: &[u8]) -> Result<Vec<u8>, String> {
    let payload = base58_decode(input, alphabet)?;
    if payload.len() < 5 {
        return Err("Base58Check input too short".into());
    }
    let (body, checksum) = payload.split_at(payload.len() - 4);
    if &sha256d(body)[..4] != checksum {
        return Err("Base58Check checksum mismatch".into());
    }
    Ok(body[1..].to_vec())
}

/// SHA-256 twice; Bitcoin derives the Base58Check checksum this way.
fn sha256d(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let first = Sha256::digest(data);
    Sha256::digest(&first).into()
}

// --- Base62 (CyberChef ToBase62/FromBase62) ---------------------------------

const BASE62_DEFAULT: &str = "0-9A-Za-z";

fn base62_alphabet(param: Option<&str>) -> Result<Vec<u8>, String> {
    let alphabet = resolve_alphabet(param, BASE62_DEFAULT, &[])?;
    if alphabet.len() != 62 {
        return Err("Error: alphabet must be of length 62".into());
    }
    Ok(alphabet)
}

fn base62_encode(input: &[u8], alphabet: &[u8]) -> Vec<u8> {
    bytes_to_digits(input, 62)
        .iter()
        .rev()
        .map(|&d| alphabet[d as usize])
        .collect()
}

fn base62_decode(input: &[u8], alphabet: &[u8]) -> Result<Vec<u8>, String> {
    let source = text(input);
    Ok(digits_to_bytes(
        source
            .chars()
            .filter_map(|c| alphabet.iter().position(|a| *a as char == c).map(|p| p as u32)),
        62,
    ))
}

// --- Base85 (CyberChef ToBase85/FromBase85) ---------------------------------

const BASE85_STANDARD: &str = "!-u";
const BASE85_Z85: &str = "0-9a-zA-Z.\\-:+=^!/*?&<>()[]{}@%$#";
const BASE85_IPV6: &str = "0-9A-Za-z!#$%&()*+\\-;<=>?@^_`{|}~";

fn base85_alphabet(param: Option<&str>) -> Result<(Vec<u8>, bool), String> {
    let spec = param
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .unwrap_or(BASE85_STANDARD);
    let (alphabet, standard) = if spec.eq_ignore_ascii_case("standard")
        || spec.eq_ignore_ascii_case("ascii85")
    {
        (expand_alph_range(BASE85_STANDARD), true)
    } else if spec.eq_ignore_ascii_case("z85") {
        (expand_alph_range(BASE85_Z85), false)
    } else if spec.eq_ignore_ascii_case("ipv6") || spec.eq_ignore_ascii_case("rfc1924") {
        (expand_alph_range(BASE85_IPV6), false)
    } else {
        (expand_alph_range(spec), expand_alph_range(spec) == expand_alph_range(BASE85_STANDARD))
    };
    if alphabet.len() != 85 {
        return Err("Error: Alphabet must be of length 85".into());
    }
    Ok((alphabet, standard))
}

fn base85_encode(input: &[u8], alphabet: &[u8], standard: bool, delimiter: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for start in (0..input.len()).step_by(4) {
        let chunk = &input[start..(start + 4).min(input.len())];
        let block = u32::from(chunk[0]) << 24
            | u32::from(chunk.get(1).copied().unwrap_or(0)) << 16
            | u32::from(chunk.get(2).copied().unwrap_or(0)) << 8
            | u32::from(chunk.get(3).copied().unwrap_or(0));
        if standard && block == 0 {
            out.push(b'z');
            continue;
        }
        let mut digits = [0u32; 5];
        let mut left = block;
        for digit in digits.iter_mut().rev() {
            *digit = left % 85;
            left /= 85;
        }
        let keep = if chunk.len() == 4 { 5 } else { chunk.len() + 1 };
        for &digit in digits.iter().take(keep) {
            out.push(alphabet[digit as usize]);
        }
    }
    if delimiter {
        let mut wrapped = b"<~".to_vec();
        wrapped.extend_from_slice(&out);
        wrapped.extend_from_slice(b"~>");
        out = wrapped;
    }
    out
}

fn base85_decode(input: &[u8], alphabet: &[u8], zero_char: u8) -> Result<Vec<u8>, String> {
    let mut source = text(input);
    if let Some(stripped) = source.strip_prefix("<~") {
        if let Some(body) = stripped.strip_suffix("~>") {
            source = body.to_string();
        }
    }
    let kept: Vec<u8> = source
        .chars()
        .filter(|c| {
            c.is_ascii() && (alphabet.contains(&(*c as u8)) || *c as u8 == zero_char)
        })
        .map(|c| c as u8)
        .collect();

    let mut out = Vec::new();
    let mut at = 0;
    while at < kept.len() {
        if kept[at] == zero_char {
            out.extend_from_slice(&[0, 0, 0, 0]);
            at += 1;
            continue;
        }
        let raw: Vec<u32> = kept[at..(at + 5).min(kept.len())]
            .iter()
            .map(|c| {
                alphabet
                    .iter()
                    .position(|a| *a == *c)
                    .map(|p| p as u32)
                    .ok_or_else(|| format!("Invalid character '{}' at index {}", *c as char, at))
            })
            .collect::<Result<_, _>>()?;
        let digit = |idx: usize| -> u32 {
            if idx < raw.len() {
                raw[idx]
            } else {
                84
            }
        };
        let block = u64::from(digit(0)) * 52200625
            + u64::from(digit(1)) * 614125
            + u64::from(digit(2)) * 7225
            + u64::from(digit(3)) * 85
            + u64::from(digit(4));
        if block > u64::from(u32::MAX) {
            return Err("Base85 group exceeds 32-bit range".into());
        }
        // A partial group encodes (chars - 1) bytes; a lone char yields none.
        let keep = raw.len().saturating_sub(1).min(4);
        out.extend_from_slice(&(block as u32).to_be_bytes()[..keep]);
        at += 5;
    }
    Ok(out)
}

// --- Base92 (CyberChef ToBase92/FromBase92) ---------------------------------

fn base92_chr(value: u32) -> Result<u8, String> {
    if value >= 91 {
        return Err("Invalid value".into());
    }
    Ok(match value {
        0 => b'!',
        1..=61 => b'#' + value as u8 - 1,
        _ => b'a' + value as u8 - 62,
    })
}

fn base92_ord(ch: u8) -> Result<u32, String> {
    match ch {
        b'!' => Ok(0),
        b'#'..=b'_' => Ok(u32::from(ch) - u32::from(b'#') + 1),
        b'a'..=b'}' => Ok(u32::from(ch) - u32::from(b'a') + 62),
        _ => Err(format!("{} is not a base92 character", ch as char)),
    }
}

fn base92_encode(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut bit_string = String::new();
    let mut out = Vec::new();
    for &byte in input {
        for shift in (0..8).rev() {
            bit_string.push(if (u32::from(byte) >> shift) & 1 == 1 { '1' } else { '0' });
        }
        while bit_string.len() >= 13 {
            let value = u32::from_str_radix(&bit_string[..13], 2).unwrap_or(0);
            out.push(base92_chr(value / 91)?);
            out.push(base92_chr(value % 91)?);
            bit_string = bit_string[13..].to_string();
        }
    }
    if !bit_string.is_empty() {
        if bit_string.len() < 7 {
            while bit_string.len() < 6 {
                bit_string.push('0');
            }
            out.push(base92_chr(u32::from_str_radix(&bit_string, 2).unwrap_or(0))?);
        } else {
            while bit_string.len() < 13 {
                bit_string.push('0');
            }
            let value = u32::from_str_radix(&bit_string[..13], 2).unwrap_or(0);
            out.push(base92_chr(value / 91)?);
            out.push(base92_chr(value % 91)?);
        }
    }
    Ok(out)
}

fn base92_decode(input: &[u8]) -> Result<Vec<u8>, String> {
    let chars: Vec<char> = text(input).chars().collect();
    let mut bit_string = String::new();
    let mut out = Vec::new();
    let mut at = 0;
    while at < chars.len() {
        let pair = at + 1 < chars.len();
        let value = if pair {
            base92_ord(chars[at] as u8)? * 91 + base92_ord(chars[at + 1] as u8)?
        } else {
            base92_ord(chars[at] as u8)?
        };
        let width = if pair { 13 } else { 6 };
        for shift in (0..width).rev() {
            bit_string.push(if (value >> shift) & 1 == 1 { '1' } else { '0' });
        }
        while bit_string.len() >= 8 {
            out.push(u8::from_str_radix(&bit_string[..8], 2).unwrap_or(0));
            bit_string = bit_string[8..].to_string();
        }
        at += 2;
    }
    Ok(out)
}

// --- Bech32 / Bech32m (BIP-0173 / BIP-0350) ---------------------------------

const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_CONST: u32 = 1;
const BECH32M_CONST: u32 = 0x2bc8_30a3;

fn bech32_polymod(values: &[u32]) -> u32 {
    const GENERATOR: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk = 1u32;
    for &v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ v;
        for (i, gen) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= gen;
            }
        }
    }
    chk
}

fn bech32_hrp_expand(hrp: &str) -> Vec<u32> {
    hrp.chars()
        .map(|c| u32::from(c) >> 5)
        .chain(std::iter::once(0))
        .chain(hrp.chars().map(|c| u32::from(c) & 31))
        .collect()
}

fn bech32_to_words(data: &[u8]) -> Vec<u32> {
    let mut value = 0u32;
    let mut bits = 0u32;
    let mut words = Vec::new();
    for &byte in data {
        value = (value << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            words.push((value >> bits) & 31);
        }
    }
    if bits > 0 {
        words.push((value << (5 - bits)) & 31);
    }
    words
}

fn bech32_from_words(words: &[u32]) -> Result<Vec<u8>, String> {
    let mut value = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for &word in words {
        value = (value << 5) | word;
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            out.push((value >> bits) as u8);
        }
    }
    if bits >= 5 {
        return Err("Invalid padding: too many bits remaining".into());
    }
    if bits > 0 && (value << (8 - bits)) & 255 != 0 {
        return Err("Invalid padding: non-zero bits in padding".into());
    }
    Ok(out)
}

fn bech32_encode_string(hrp: &str, data: &[u8], bech32m: bool) -> Result<String, String> {
    if hrp.is_empty() {
        return Err("Human-Readable Part (HRP) cannot be empty.".into());
    }
    let hrp = hrp.to_lowercase();
    let words = bech32_to_words(data);
    let constant = if bech32m { BECH32M_CONST } else { BECH32_CONST };
    let mut values = bech32_hrp_expand(&hrp);
    values.extend_from_slice(&words);
    values.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    let checksum = bech32_polymod(&values) ^ constant;
    let mut encoded = format!("{hrp}1");
    for &word in &words {
        encoded.push(BECH32_CHARSET[word as usize] as char);
    }
    for i in 0..6 {
        encoded.push(BECH32_CHARSET[((checksum >> (5 * (5 - i))) & 31) as usize] as char);
    }
    Ok(encoded)
}

fn bech32_decode_string(input: &str) -> Result<Vec<u8>, String> {
    let input = input.trim();
    let has_lower = input.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = input.chars().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err("Mixed case Bech32 string is invalid".into());
    }
    let input = input.to_lowercase();
    let sep = input.rfind('1').ok_or("Bech32 string requires a '1' separator")?;
    if sep == 0 || sep + 7 > input.len() {
        return Err("Invalid Bech32 separator position".into());
    }
    if !input[..sep].chars().all(|c| (33..=126).contains(&(c as u32))) {
        return Err("Invalid character in HRP".into());
    }
    let mut words = Vec::new();
    for c in input[sep + 1..].chars() {
        let digit = BECH32_CHARSET
            .iter()
            .position(|a| *a as char == c)
            .ok_or_else(|| format!("Invalid Bech32 character '{c}'"))?;
        words.push(digit as u32);
    }
    if words.len() < 6 {
        return Err("Bech32 checksum too short".into());
    }
    let mut values = bech32_hrp_expand(&input[..sep]);
    values.extend_from_slice(&words);
    let polymod = bech32_polymod(&values);
    if polymod != BECH32_CONST && polymod != BECH32M_CONST {
        return Err("Bech32 checksum mismatch".into());
    }
    bech32_from_words(&words[..words.len() - 6])
}

// --- To/From Base (arbitrary radix, CyberChef ToBase/FromBase) ---------------

fn number_to_radix(mut value: u128, radix: u32) -> String {
    if value == 0 {
        return "0".into();
    }
    const DIGITS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let mut out = Vec::new();
    while value > 0 {
        out.push(DIGITS[(value % u128::from(radix)) as usize]);
        value /= u128::from(radix);
    }
    out.iter().rev().map(|b| *b as char).collect()
}

fn from_radix_number(raw: &str, radix: u32) -> Result<String, String> {
    let (int_part, frac_part) = raw.split_once('.').unwrap_or((raw, ""));
    let int_value = u128::from_str_radix(int_part, radix)
        .map_err(|_| format!("'{int_part}' is not a valid base-{radix} integer"))?;
    if frac_part.is_empty() {
        return Ok(int_value.to_string());
    }
    let mut frac_value = 0f64;
    for (i, ch) in frac_part.chars().enumerate() {
        let digit = ch
            .to_digit(radix)
            .ok_or_else(|| format!("'{ch}' is not a base-{radix} digit"))?;
        frac_value += f64::from(digit) / (radix as f64).powi(i as i32 + 1);
    }
    let frac_text = format!("{frac_value}");
    let frac_digits = frac_text
        .strip_prefix("0.")
        .unwrap_or(frac_text.trim_start_matches('0').trim_start_matches('.'));
    Ok(format!("{int_value}.{frac_digits}")
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string())
}

// --- Octal (CyberChef ToOctal/FromOctal) ------------------------------------

fn octal_encode(input: &[u8], delimiter: &str) -> Vec<u8> {
    input
        .iter()
        .map(|b| format!("{b:o}"))
        .collect::<Vec<_>>()
        .join(delimiter)
        .into_bytes()
}

fn octal_decode(input: &[u8], delimiter: &str) -> Result<Vec<u8>, String> {
    let source = text(input);
    if source.is_empty() {
        return Ok(Vec::new());
    }
    source
        .split(delimiter)
        .map(|v| {
            u8::from_str_radix(v.trim(), 8).map_err(|_| format!("'{v}' is not an octal byte value"))
        })
        .collect()
}

// --- BCD (CyberChef ToBCD/FromBCD) ------------------------------------------

const BCD_SCHEMES: [(&str, [u8; 10]); 7] = [
    ("8 4 2 1", [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
    ("7 4 2 1", [0, 1, 2, 3, 4, 5, 6, 8, 9, 10]),
    ("4 2 2 1", [0, 1, 4, 5, 8, 9, 12, 13, 14, 15]),
    ("2 4 2 1", [0, 1, 2, 3, 4, 11, 12, 13, 14, 15]),
    ("8 4 -2 -1", [0, 7, 6, 5, 4, 11, 10, 9, 8, 15]),
    ("Excess-3", [3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
    ("IBM 8 4 2 1", [10, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
];

fn bcd_table(param: Option<&str>) -> Result<(&'static str, [u8; 10]), String> {
    let requested = param
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .unwrap_or("8 4 2 1")
        .to_lowercase();
    for (name, table) in BCD_SCHEMES.iter() {
        if requested == name.to_lowercase() {
            return Ok((name, *table));
        }
    }
    Err(format!("Unknown BCD scheme: {requested}"))
}

fn bcd_params(param: Option<&str>) -> Result<(u8, [u8; 10], bool, bool, String), String> {
    let raw = param.map(str::trim).unwrap_or("8 4 2 1");
    let mut parts = raw.split(',').map(str::trim);
    let (name, table) = bcd_table(parts.next())?;
    let mut packed = true;
    let mut signed = false;
    let mut format = "Nibbles".to_string();
    for flag in parts {
        match flag.to_lowercase().as_str() {
            "" => {}
            "packed" => packed = true,
            "unpacked" => packed = false,
            "signed" => signed = true,
            "unsigned" => signed = false,
            "nibbles" => format = "Nibbles".into(),
            "bytes" => format = "Bytes".into(),
            "raw" => format = "Raw".into(),
            other => return Err(format!("Unknown BCD parameter: {other}")),
        }
    }
    Ok((name.as_bytes()[0], table, packed, signed, format))
}

fn bcd_encode(
    input: &[u8],
    table: &[u8; 10],
    packed: bool,
    signed: bool,
    format: &str,
) -> Result<Vec<u8>, String> {
    let source = text(input).trim().to_string();
    let negative = source.starts_with('-');
    let digits_source = source.trim_start_matches(['-', '+']);
    if digits_source.is_empty() || !digits_source.chars().all(|c| c.is_ascii_digit()) {
        return Err("Invalid input".into());
    }
    let mut nibbles: Vec<u8> = digits_source
        .bytes()
        .map(|b| table[(b - b'0') as usize])
        .collect();
    if signed {
        if packed && nibbles.len() % 2 == 0 {
            nibbles.insert(0, table[0]);
        }
        nibbles.push(if negative { 13 } else { 12 });
    }
    let mut bytes = Vec::new();
    if packed {
        let mut encoded = 0u8;
        let mut little = false;
        for &n in &nibbles {
            encoded ^= if little { n } else { n << 4 };
            if little {
                bytes.push(encoded);
                encoded = 0;
            }
            little = !little;
        }
        if little {
            bytes.push(encoded);
        }
    } else {
        bytes.extend_from_slice(&nibbles);
        nibbles = nibbles.iter().flat_map(|n| [0, *n]).collect();
    }
    match format {
        "Nibbles" => Ok(nibbles
            .iter()
            .map(|n| format!("{n:04b}"))
            .collect::<Vec<_>>()
            .join(" ")
            .into_bytes()),
        "Bytes" => Ok(bytes
            .iter()
            .map(|b| format!("{b:08b}"))
            .collect::<Vec<_>>()
            .join(" ")
            .into_bytes()),
        "Raw" => Ok(bytes),
        other => Err(format!("Unknown BCD output format: {other}")),
    }
}

fn bcd_decode(
    input: &[u8],
    table: &[u8; 10],
    packed: bool,
    signed: bool,
    format: &str,
) -> Result<Vec<u8>, String> {
    let mut nibbles: Vec<u8> = match format {
        "Nibbles" | "Bytes" => {
            let compact: String = text(input).chars().filter(|c| !c.is_whitespace()).collect();
            if compact.len() % 4 != 0 {
                return Err("binary input length must be a multiple of 4".into());
            }
            (0..compact.len())
                .step_by(4)
                .map(|i| u8::from_str_radix(&compact[i..i + 4], 2).map_err(|e| e.to_string()))
                .collect::<Result<_, _>>()?
        }
        // Raw operates on the byte input itself, not its lossy text rendering.
        "Raw" => input.iter().copied().flat_map(|b| [b >> 4, b & 15]).collect(),
        other => return Err(format!("Unknown BCD input format: {other}")),
    };
    if !packed {
        nibbles = nibbles.into_iter().skip(1).step_by(2).collect();
    }
    let mut negative = false;
    if signed {
        if matches!(nibbles.last(), Some(13) | Some(11)) {
            negative = true;
        }
        nibbles.pop();
    }
    let mut digits = String::new();
    for n in &nibbles {
        let value = table
            .iter()
            .position(|v| v == n)
            .ok_or_else(|| format!("Value {n:04b} is not in the encoding scheme"))?;
        digits.push((b'0' + value as u8) as char);
    }
    // CyberChef returns a BigNumber, which normalises leading zeros away.
    let trimmed = digits.trim_start_matches('0');
    let mut out = String::new();
    if negative {
        out.push('-');
    }
    out.push_str(if trimmed.is_empty() { "0" } else { trimmed });
    Ok(out.into_bytes())
}

// --- Float (CyberChef ToFloat/FromFloat) ------------------------------------

fn float_param(param: Option<&str>) -> (bool, bool) {
    let raw = param.map(str::trim).unwrap_or("Big Endian");
    let mut little_endian = false;
    let mut double = false;
    for flag in raw.split(',').map(str::trim) {
        match flag.to_lowercase().as_str() {
            "little endian" | "little" | "le" => little_endian = true,
            "big endian" | "big" | "be" => little_endian = false,
            "double" | "8" => double = true,
            "float" | "4" => double = false,
            _ => {}
        }
    }
    (little_endian, double)
}

fn float_number_to_string(value: f64) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    if value.is_infinite() {
        return if value < 0.0 { "-Infinity".into() } else { "Infinity".into() };
    }
    format!("{value}")
}

fn float_decode(input: &[u8], delimiter: &str, double: bool) -> Result<Vec<u8>, String> {
    let source = text(input).trim().to_string();
    if source.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for token in source.split(delimiter) {
        let value: f64 = token
            .trim()
            .parse()
            .map_err(|_| format!("'{token}' is not a valid number"))?;
        if double {
            out.extend_from_slice(&value.to_bits().to_be_bytes());
        } else {
            out.extend_from_slice(&(value as f32).to_bits().to_be_bytes());
        }
    }
    Ok(out)
}

fn float_encode(
    input: &[u8],
    delimiter: &str,
    little_endian: bool,
    double: bool,
) -> Result<Vec<u8>, String> {
    let size = if double { 8 } else { 4 };
    if input.len() % size != 0 {
        return Err(format!("Input is not a multiple of {size}"));
    }
    let mut pieces = Vec::new();
    for chunk in input.chunks(size) {
        let bytes: Vec<u8> = if little_endian {
            chunk.iter().rev().copied().collect()
        } else {
            chunk.to_vec()
        };
        let value = if double {
            f64::from_bits(u64::from_be_bytes(bytes.try_into().expect("8 bytes")))
        } else {
            f64::from(f32::from_bits(u32::from_be_bytes(bytes.try_into().expect("4 bytes"))))
        };
        pieces.push(float_number_to_string(value));
    }
    Ok(pieces.join(delimiter).into_bytes())
}

// --- Unicode escapes (CyberChef Escape/UnescapeUnicodeCharacters) -----------

fn escape_unicode(input: &[u8], prefix: &str, encode_all: bool) -> Vec<u8> {
    let source = text(input);
    let mut out = String::new();
    for unit in source.encode_utf16() {
        if !encode_all && (32..=126).contains(&unit) {
            out.push(char::from_u32(u32::from(unit)).unwrap_or('\u{fffd}'));
            continue;
        }
        out.push_str(prefix);
        out.push_str(&format!("{unit:04X}"));
    }
    out.into_bytes()
}

/// CyberChef's \u/%u take exactly 4 hex digits, U+ takes 4..=6; escapes emit
/// UTF-16 code units so surrogate pairs recombine on unescape.
fn unescape_unicode(input: &[u8], prefix: &str) -> Result<Vec<u8>, String> {
    let (prefix, min, max) = match prefix {
        "\\u" => ("\\u", 4, 4),
        "%u" => ("%u", 4, 4),
        "U+" => ("U+", 4, 6),
        other => return Err(format!("Unknown prefix: {other}")),
    };
    let source = text(input);
    let mut units: Vec<u16> = Vec::new();
    let mut buffer = [0u16; 2];
    let mut rest = source.as_str();
    while let Some(at) = rest.find(prefix) {
        for ch in rest[..at].chars() {
            units.extend_from_slice(ch.encode_utf16(&mut buffer));
        }
        let after = &rest[at + prefix.len()..];
        let hex: String = after
            .chars()
            .take(max)
            .take_while(|c| c.is_ascii_hexdigit())
            .collect();
        if hex.len() < min {
            units.extend(prefix.encode_utf16());
            rest = after;
            continue;
        }
        let cp = u32::from_str_radix(&hex, 16).map_err(|_| "invalid unicode escape".to_string())?;
        if (0xD800..0xE000).contains(&cp) {
            units.push(cp as u16);
        } else if let Some(ch) = char::from_u32(cp) {
            units.extend_from_slice(ch.encode_utf16(&mut buffer));
        } else {
            units.push(0xFFFD);
        }
        rest = &after[hex.len()..];
    }
    for ch in rest.chars() {
        units.extend_from_slice(ch.encode_utf16(&mut buffer));
    }
    Ok(String::from_utf16_lossy(&units).into_bytes())
}

// --- Smart characters (CyberChef EscapeSmartCharacters) ---------------------

fn escape_smart_chars(input: &[u8], unmappable: &str) -> Vec<u8> {
    const SMART_MAP: &[(char, &str)] = &[
        ('\u{201C}', "\""), ('\u{201D}', "\""), ('\u{201E}', "\""), ('\u{201F}', "\""), ('\u{2033}', "\""),
        ('\u{2018}', "'"), ('\u{2019}', "'"), ('\u{201A}', "'"), ('\u{201B}', "'"), ('\u{2032}', "'"),
        ('\u{2010}', "-"), ('\u{2011}', "-"), ('\u{2012}', "-"), ('\u{2013}', "-"), ('\u{2014}', "--"),
        ('\u{2015}', "--"), ('\u{2026}', "..."),
        ('\u{00A9}', "(c)"), ('\u{00AE}', "(r)"), ('\u{2122}', "(tm)"),
        ('\u{2190}', "<--"), ('\u{2192}', "-->"), ('\u{2191}', "^"), ('\u{2193}', "v"), ('\u{2194}', "<->"),
        ('\u{21D0}', "<=="), ('\u{21D2}', "==>"), ('\u{21D4}', "<=>"),
        ('\u{00AB}', "<<"), ('\u{00BB}', ">>"), ('\u{2039}', "<"), ('\u{203A}', ">"),
        ('\u{00D7}', "x"), ('\u{00F7}', "/"), ('\u{00B1}', "+/-"), ('\u{2022}', "*"), ('\u{00B7}', "."),
        ('\u{00A0}', " "), ('\u{2002}', " "), ('\u{2003}', " "), ('\u{2009}', " "), ('\u{200A}', " "),
    ];
    let mut out = String::new();
    for ch in text(input).chars() {
        if (ch as u32) < 128 {
            out.push(ch);
            continue;
        }
        match SMART_MAP.iter().find(|(from, _)| *from == ch) {
            Some((_, to)) => out.push_str(to),
            None => match unmappable {
                "Remove" => {}
                "Replace with '.'" => out.push('.'),
                _ => out.push(ch),
            },
        }
    }
    out.into_bytes()
}

// --- Hex content (CyberChef To/FromHexContent) ------------------------------

fn hex_content_encode(input: &[u8], mode: &str, spaces: bool) -> Vec<u8> {
    if mode == "All chars" {
        let hex = if spaces {
            const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
            let mut buf = String::with_capacity(input.len() * 3);
            for (i, &b) in input.iter().enumerate() {
                if i > 0 {
                    buf.push(' ');
                }
                buf.push(HEX_UPPER[usize::from(b >> 4)] as char);
                buf.push(HEX_UPPER[usize::from(b & 0x0f)] as char);
            }
            buf
        } else {
            hex_encode(input)
        };
        return format!("|{hex}|").into_bytes();
    }
    let convert_spaces = mode == "Only special chars including spaces";
    let mut out = String::new();
    let mut in_hex = false;
    for &b in input {
        let escaped = (b == 32 && convert_spaces)
            || (b < 48 && b != 32)
            || (57 < b && b < 65)
            || (90 < b && b < 97)
            || b > 122;
        if escaped {
            if !in_hex {
                out.push('|');
                in_hex = true;
            } else if spaces {
                out.push(' ');
            }
            out.push_str(&hex_encode(&[b]));
        } else {
            if in_hex {
                out.push('|');
                in_hex = false;
            }
            out.push(b as char);
        }
    }
    if in_hex {
        out.push('|');
    }
    out.into_bytes()
}

/// Byte-level decode so high bytes inside |hex| runs survive the round trip
/// (a String detour would re-encode them as multi-byte UTF-8).
fn hex_content_decode(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(rel) = input[at..].iter().position(|&b| b == b'|') {
        let start = at + rel;
        let Some(end_rel) = input[start + 1..].iter().position(|&b| b == b'|') else {
            break;
        };
        let end = start + 1 + end_rel;
        out.extend_from_slice(&input[at..start]);
        let inner: Vec<u8> = input[start + 1..end].iter().copied().filter(|&b| b != b' ').collect();
        if inner.len() >= 2 && inner.len() % 2 == 0 && inner.iter().all(|b| b.is_ascii_hexdigit()) {
            for pair in inner.chunks(2) {
                let digits = std::str::from_utf8(pair).map_err(|_| "invalid hex content".to_string())?;
                out.push(u8::from_str_radix(digits, 16).map_err(|e| e.to_string())?);
            }
        } else {
            out.extend_from_slice(&input[start..=end]);
        }
        at = end + 1;
    }
    out.extend_from_slice(&input[at..]);
    Ok(out)
}

// --- Caret/M-decode (CyberChef CaretMdecode) --------------------------------

fn caret_m_decode(input: &[u8]) -> Vec<u8> {
    let source = text(input);
    let mut out = Vec::new();
    let mut pending = String::new();
    for ch in source.chars() {
        let code = ch as u32;
        match pending.as_str() {
            "M-^" => {
                if (63 < code) && code <= 95 {
                    out.push((code + 64) as u8);
                } else if code == 63 {
                    out.push(255);
                } else {
                    out.extend_from_slice(b"M-^");
                    out.push(code as u8);
                }
                pending.clear();
            }
            "M-" => {
                if ch == '^' {
                    pending.push('^');
                } else if (32..=126).contains(&code) {
                    out.push((code + 128) as u8);
                    pending.clear();
                } else {
                    out.extend_from_slice(b"M-");
                    out.push(code as u8);
                    pending.clear();
                }
            }
            "M" => {
                if ch == '-' {
                    pending.push('-');
                } else {
                    out.push(77);
                    out.push(code as u8);
                    pending.clear();
                }
            }
            "^" => {
                if (63 < code) && code <= 126 {
                    out.push((code - 64) as u8);
                } else if code == 63 {
                    out.push(127);
                } else {
                    out.push(94);
                    out.push(code as u8);
                }
                pending.clear();
            }
            _ => {
                if ch == 'M' {
                    pending.push('M');
                } else if ch == '^' {
                    pending.push('^');
                } else {
                    out.push(code as u8);
                }
            }
        }
    }
    out
}

// --- Modhex (CyberChef To/FromModhex) ---------------------------------------

const MODHEX_ALPHABET: &[u8] = b"cbdefghijklnrtuv";

fn modhex_encode(input: &[u8], delimiter: &str) -> Vec<u8> {
    let mapped: Vec<u8> = input
        .iter()
        .flat_map(|b| [MODHEX_ALPHABET[(b >> 4) as usize], MODHEX_ALPHABET[(b & 15) as usize]])
        .collect();
    let body = String::from_utf8(mapped).expect("modhex alphabet is ASCII");
    let pairs: Vec<String> = body
        .as_bytes()
        .chunks(2)
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .collect();
    pairs.join(delimiter).into_bytes()
}

fn modhex_decode(input: &[u8]) -> Result<Vec<u8>, String> {
    let source = text(input).to_lowercase();
    let mut hex_string = String::new();
    for ch in source.chars() {
        match MODHEX_ALPHABET.iter().position(|a| *a as char == ch) {
            Some(idx) => hex_string.push((b"0123456789abcdef"[idx]) as char),
            None if !ch.is_ascii_alphanumeric() => {}
            None => return Err(format!("Invalid modhex character '{ch}'")),
        }
    }
    if hex_string.len() % 2 != 0 {
        return Err("modhex input has an odd number of characters".into());
    }
    let bytes = hex_decode(&hex_string)?;
    Ok(bytes)
}

// --- Quoted-Printable (RFC 2045; CyberChef ToQuotedPrintable uses mimelib) --

fn qp_byte_allowed(b: u8) -> bool {
    matches!(b, 0x09 | 0x0A | 0x0D | 0x20 | 0x21)
        || (0x23..=0x3C).contains(&b)
        || b == 0x3E
        || (0x40..=0x5E).contains(&b)
        || (0x60..=0x7E).contains(&b)
}

/// RFC 2045 rule 5: no encoded line exceeds 76 characters; a token (=XX or a
/// literal char) is never split, and the '=' of a soft break closes the line.
fn qp_soft_linebreaks(encoded: &str) -> String {
    const MAX_LINE: usize = 76;
    let mut out = String::new();
    let mut line_len = 0usize;
    let chars: Vec<char> = encoded.chars().collect();
    let mut at = 0;
    while at < chars.len() {
        let ch = chars[at];
        if ch == '\r' && chars.get(at + 1) == Some(&'\n') {
            out.push_str("\r\n");
            line_len = 0;
            at += 2;
            continue;
        }
        if ch == '\n' {
            out.push_str("\r\n");
            line_len = 0;
            at += 1;
            continue;
        }
        let token_len = if ch == '='
            && chars.get(at + 1).is_some_and(|c| c.is_ascii_hexdigit())
            && chars.get(at + 2).is_some_and(|c| c.is_ascii_hexdigit())
        {
            3
        } else {
            1
        };
        // Content budget is 75 so the closing '=' fits inside 76 characters.
        if line_len + token_len > MAX_LINE - 1 {
            out.push_str("=\r\n");
            line_len = 0;
        }
        for token_char in &chars[at..at + token_len] {
            out.push(*token_char);
        }
        line_len += token_len;
        at += token_len;
    }
    out
}

/// Append "=XX" (uppercase hex) for one quoted-printable-escaped byte.
fn push_qp_escape(out: &mut String, byte: u8) {
    const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
    out.push('=');
    out.push(HEX_UPPER[usize::from(byte >> 4)] as char);
    out.push(HEX_UPPER[usize::from(byte & 0x0f)] as char);
}

fn quoted_printable_encode(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut normalized = String::new();
    let mut trailing = String::new();
    for &b in input {
        match b {
            b'\r' | b'\n' => {
                for c in trailing.chars() {
                    push_qp_escape(&mut normalized, c as u8);
                }
                trailing.clear();
                normalized.push_str("\r\n");
            }
            b' ' | b'\t' => trailing.push(b as char),
            _ => {
                normalized.push_str(&trailing);
                trailing.clear();
                if qp_byte_allowed(b) {
                    normalized.push(b as char);
                } else {
                    push_qp_escape(&mut normalized, b);
                }
            }
        }
    }
    for c in trailing.chars() {
        push_qp_escape(&mut normalized, c as u8);
    }
    Ok(qp_soft_linebreaks(&normalized).into_bytes())
}

fn quoted_printable_decode(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < input.len() {
        let b = input[at];
        if b == b'=' {
            if at + 1 >= input.len() {
                break;
            }
            if input[at + 1] == b'\r' && input.get(at + 2) == Some(&b'\n') {
                at += 3;
                continue;
            }
            if input[at + 1] == b'\n' {
                at += 2;
                continue;
            }
            if at + 2 < input.len()
                && input[at + 1].is_ascii_hexdigit()
                && input[at + 2].is_ascii_hexdigit()
            {
                let hex_pair = format!(
                    "{}{}",
                    input[at + 1] as char,
                    input[at + 2] as char
                );
                out.push(u8::from_str_radix(&hex_pair, 16).map_err(|e| e.to_string())?);
                at += 3;
                continue;
            }
        }
        out.push(b);
        at += 1;
    }
    Ok(out)
}

// --- Punycode (RFC 3492) ----------------------------------------------------

const PUNY_BASE: u32 = 36;
const PUNY_TMIN: u32 = 1;
const PUNY_TMAX: u32 = 26;
const PUNY_SKEW: u32 = 38;
const PUNY_DAMP: u32 = 700;
const PUNY_INITIAL_BIAS: u32 = 72;
const PUNY_INITIAL_N: u32 = 128;

fn puny_adapt(mut delta: u32, num_points: u32, first_time: bool) -> u32 {
    delta = if first_time { delta / PUNY_DAMP } else { delta / 2 };
    delta += delta / num_points;
    let mut k = 0u32;
    while delta > ((PUNY_BASE - PUNY_TMIN) * PUNY_TMAX) / 2 {
        delta /= PUNY_BASE - PUNY_TMIN;
        k += PUNY_BASE;
    }
    k + (((PUNY_BASE - PUNY_TMIN + 1) * delta) / (delta + PUNY_SKEW))
}

/// RFC 3492 threshold t = clamp(k - bias, tmin, tmax); k - bias can go
/// negative early on, so the subtraction stays in signed arithmetic.
fn puny_threshold(k: u32, bias: u32) -> u32 {
    let diff = k as i64 - bias as i64;
    diff.clamp(i64::from(PUNY_TMIN), i64::from(PUNY_TMAX)) as u32
}

fn puny_digit_char(digit: u32) -> char {
    if digit < 26 {
        (b'a' + digit as u8) as char
    } else {
        (b'0' + (digit - 26) as u8) as char
    }
}

fn puny_char_digit(ch: char) -> Option<u32> {
    match ch {
        'a'..='z' => Some(ch as u32 - 'a' as u32),
        'A'..='Z' => Some(ch as u32 - 'A' as u32),
        '0'..='9' => Some(ch as u32 - '0' as u32 + 26),
        _ => None,
    }
}

fn punycode_encode(input: &str) -> Result<String, String> {
    let chars: Vec<char> = input.chars().collect();
    let basic_count = chars.iter().filter(|c| (**c as u32) < 128).count();
    let mut out: String = chars.iter().filter(|c| (**c as u32) < 128).collect();
    if !out.is_empty() {
        out.push('-');
    }
    let mut n = PUNY_INITIAL_N;
    let mut delta = 0u32;
    let mut bias = PUNY_INITIAL_BIAS;
    let mut handled = basic_count;
    while handled < chars.len() {
        let m = chars
            .iter()
            .map(|c| *c as u32)
            .filter(|&cp| cp >= n)
            .min()
            .ok_or("punycode: no candidate code point")?;
        delta = delta
            .checked_add(
                (m - n)
                    .checked_mul((handled + 1) as u32)
                    .ok_or("punycode: overflow")?,
            )
            .ok_or("punycode: overflow")?;
        n = m;
        for &c in &chars {
            let cp = c as u32;
            if cp < n {
                delta += 1;
            }
            if cp == n {
                let mut q = delta;
                let mut k = PUNY_BASE;
                loop {
                    let t = puny_threshold(k, bias);
                    if q < t {
                        break;
                    }
                    out.push(puny_digit_char(t + (q - t) % (PUNY_BASE - t)));
                    q = (q - t) / (PUNY_BASE - t);
                    k += PUNY_BASE;
                }
                // punycode.js emits the remainder q directly (RFC 3492 ref).
                out.push(puny_digit_char(q));
                bias = puny_adapt(delta, (handled + 1) as u32, handled == basic_count);
                delta = 0;
                handled += 1;
            }
        }
        // punycode.js advances the decoder state by one per outer pass; this
        // is what excludes the just-encoded code point from the next search.
        delta += 1;
        n += 1;
    }
    Ok(out)
}

fn punycode_decode(input: &str) -> Result<String, String> {
    let chars: Vec<char> = input.chars().collect();
    let (basic, extended) = match chars.iter().rposition(|c| *c == '-') {
        Some(idx) => (&chars[..idx], &chars[idx + 1..]),
        None => (&chars[..0] as &[char], &chars[..]),
    };
    if basic.iter().any(|c| *c as u32 >= 128) {
        return Err("punycode: basic code points must be ASCII".into());
    }
    let mut out: Vec<char> = basic.to_vec();
    let mut n = PUNY_INITIAL_N;
    let mut i = 0u64;
    let mut bias = PUNY_INITIAL_BIAS;
    let mut at = 0;
    while at < extended.len() {
        let old_i = i;
        let mut w = 1u64;
        let mut k = PUNY_BASE;
        let mut threshold;
        while at < extended.len() {
            let digit = extended[at];
            let value = puny_char_digit(digit).ok_or("punycode: invalid digit")?;
            at += 1;
            i = i
                .checked_add(u64::from(value).checked_mul(w).ok_or("punycode: overflow")?)
                .ok_or("punycode: overflow")?;
            threshold = puny_threshold(k, bias);
            if value < threshold {
                break;
            }
            w = w
                .checked_mul(u64::from(PUNY_BASE - threshold))
                .ok_or("punycode: overflow")?;
            k += PUNY_BASE;
        }
        // punycode.js divides by the current output length + 1 in both the
        // bias adaptation and the n/i state update.
        let out_count = out.len() as u64 + 1;
        bias = puny_adapt(
            u32::try_from(i - old_i).map_err(|_| "punycode: overflow")?,
            out_count as u32,
            old_i == 0,
        );
        n += (i / out_count) as u32;
        i %= out_count;
        let ch = char::from_u32(n).ok_or("punycode: invalid code point")?;
        let insert_at = i as usize;
        if insert_at > out.len() {
            return Err("punycode: invalid insertion point".into());
        }
        out.insert(insert_at, ch);
        i += 1;
    }
    Ok(out.into_iter().collect())
}

// --- MIME decoding (CyberChef MIMEDecoding; RFC 2047 encoded-words) ---------

fn mime_charset_decode(charset: &str, bytes: &[u8]) -> Result<String, String> {
    match charset.to_lowercase().as_str() {
        "utf-8" | "utf8" => Ok(String::from_utf8_lossy(bytes).into_owned()),
        "us-ascii" | "ascii" => Ok(bytes.iter().map(|&b| b as char).collect()),
        "iso-8859-1" | "latin-1" | "latin1" => Ok(bytes.iter().map(|&b| b as char).collect()),
        other => Err(format!(
            "Unhandled Charset: {other} (only utf-8, us-ascii and iso-8859-1 are available natively)"
        )),
    }
}

fn mime_q_decode(word: &str) -> Result<Vec<u8>, String> {
    let bytes = word.as_bytes();
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'_' => {
                out.push(b' ');
                at += 1;
            }
            b'=' => {
                if at + 3 > bytes.len()
                    || !bytes[at + 1].is_ascii_hexdigit()
                    || !bytes[at + 2].is_ascii_hexdigit()
                {
                    return Err("Incorrectly Encoded Word".into());
                }
                let hex_pair = format!("{}{}", bytes[at + 1] as char, bytes[at + 2] as char);
                out.push(u8::from_str_radix(&hex_pair, 16).map_err(|e| e.to_string())?);
                at += 3;
            }
            b => {
                out.push(b);
                at += 1;
            }
        }
    }
    Ok(out)
}

fn mime_decode(input: &[u8]) -> Result<Vec<u8>, String> {
    let source = text(input).replace("\r\n", "\n");
    let mut decoded = String::new();
    let mut header = source.as_str();
    let mut between_words = false;
    while let Some(start) = header.find("=?") {
        let mut at = start + 2;
        let Some(charset_rel) = header[at..].find('?') else { break };
        let charset = header[at..at + charset_rel].to_string();
        at += charset_rel + 1;
        if header.len() < at + 3 {
            break;
        }
        let encoding_char = header[at..].chars().next().unwrap_or('\0');
        at += 1;
        if !header[at..].starts_with('?') {
            break;
        }
        at += 1;
        let Some(word_rel) = header[at..].find("?=") else { break };
        let word = header[at..at + word_rel].to_string();
        let end = at + word_rel + 2;
        let payload = match encoding_char.to_ascii_lowercase() {
            'b' => base64::engine::general_purpose::STANDARD
                .decode(word.split_whitespace().collect::<String>().as_bytes())
                .map_err(|_| "invalid base64 encoded-word".to_string())?,
            'q' => mime_q_decode(&word)?,
            _ => {
                decoded.push_str(&header[..start + 2]);
                header = &header[start + 2..];
                between_words = false;
                continue;
            }
        };
        if start > 0 && (!between_words || header[..start].contains(|c: char| !c.is_whitespace())) {
            decoded.push_str(&header[..start]);
        }
        decoded.push_str(&mime_charset_decode(&charset, &payload)?);
        header = &header[end..];
        between_words = true;
    }
    decoded.push_str(header);
    Ok(decoded.into_bytes())
}

// --- PEM / hex (CyberChef PEMToHex; RFC 7468 structure) ---------------------

fn pem_to_hex(input: &[u8]) -> Result<Vec<u8>, String> {
    let source = text(input);
    let mut outputs = Vec::new();
    let mut rest = source.as_str();
    while let Some(at) = rest.find("-----BEGIN ") {
        let after_label = &rest[at + "-----BEGIN ".len()..];
        let Some(label_rel) = after_label.find("-----") else { break };
        let label = &after_label[..label_rel];
        let chars: Vec<char> = label.chars().collect();
        let valid_label = chars.len() >= 3
            && chars[0].is_ascii_uppercase()
            && chars[chars.len() - 1].is_ascii_uppercase()
            && chars.iter().all(|c| c.is_ascii_uppercase() || *c == ' ');
        if !valid_label {
            rest = &after_label[label_rel..];
            continue;
        }
        let body_start = at + "-----BEGIN ".len() + label_rel + 5;
        let footer = format!("-----END {label}-----");
        let Some(footer_rel) = rest[body_start..].find(&footer) else {
            return Err(format!("PEM footer '{footer}' not found"));
        };
        let body = &rest[body_start..body_start + footer_rel];
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(body.split_whitespace().collect::<String>().as_bytes())
            .map_err(|_| "PEM body is not valid Base64".to_string())?;
        outputs.push(hex_encode(&bytes));
        rest = &rest[body_start + footer_rel + footer.len()..];
    }
    if outputs.is_empty() {
        return Err("No PEM blocks found".into());
    }
    Ok(outputs.join("\n").into_bytes())
}

fn hex_to_pem(input: &[u8], label: &str) -> Result<Vec<u8>, String> {
    let bytes = hex_decode(&text(input))?;
    let body = base64::engine::general_purpose::STANDARD.encode(&bytes);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----"));
    Ok(out.into_bytes())
}

// --- ASN.1 hex dump (CyberChef delegates rendering to jsrsasign ASN1HEX.dump)

fn asn1_tag_label(tag: u8) -> String {
    match tag {
        0x01 => "BOOLEAN".into(),
        0x02 => "INTEGER".into(),
        0x03 => "BITSTRING".into(),
        0x04 => "OCTETSTRING".into(),
        0x05 => "NULL".into(),
        0x06 => "ObjectIdentifier".into(),
        0x0A => "ENUMERATED".into(),
        0x0C => "UTF8String".into(),
        0x13 => "PrintableString".into(),
        0x14 => "TeletexString".into(),
        0x16 => "IA5String".into(),
        0x17 => "UTCTime".into(),
        0x18 => "GeneralizedTime".into(),
        0x30 => "SEQUENCE".into(),
        0x31 => "SET".into(),
        _ if tag & 0xA0 == 0xA0 => format!("[{}]", tag & 0x1F),
        _ => format!("UNKNOWN(0x{tag:02X})"),
    }
}

fn asn1_oid(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let first = bytes[0];
    let (arc1, arc2) = if first < 40 {
        (0u64, u64::from(first))
    } else if first < 80 {
        (1, u64::from(first - 40))
    } else {
        (2, u64::from(first - 80))
    };
    let mut parts = vec![arc1, arc2];
    let mut value = 0u64;
    for &b in &bytes[1..] {
        value = (value << 7) | u64::from(b & 0x7F);
        if b & 0x80 == 0 {
            parts.push(value);
            value = 0;
        }
    }
    parts.iter().map(u64::to_string).collect::<Vec<_>>().join(".")
}

fn asn1_skip_long_hex(hex: &str, limit: usize) -> String {
    if hex.len() <= limit * 2 {
        return hex.to_string();
    }
    let total = hex.len() / 2;
    let head: String = hex.chars().take(limit * 2).collect();
    let tail: String = hex
        .chars()
        .rev()
        .take(limit * 2)
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    format!("{head}..(total {total}bytes)..{tail}")
}

/// Returns (content length, header length) in hex-character units.
fn asn1_length(hex: &str, at: usize) -> Result<(u64, usize), String> {
    if hex.len() < at + 2 {
        return Err("truncated ASN.1 length".into());
    }
    let first = u8::from_str_radix(&hex[at..at + 2], 16).map_err(|_| "invalid ASN.1 length".to_string())?;
    if first & 0x80 == 0 {
        return Ok((u64::from(first) * 2, 2));
    }
    let count = (first & 0x7F) as usize;
    if count == 0 || hex.len() < at + 2 + count * 2 {
        return Err("unsupported indefinite or truncated ASN.1 length".into());
    }
    let mut value = 0u64;
    for i in 0..count {
        let byte = u8::from_str_radix(&hex[at + 2 + i * 2..at + 4 + i * 2], 16)
            .map_err(|_| "invalid ASN.1 length".to_string())?;
        value = (value << 8) | u64::from(byte);
    }
    Ok((value * 2, 2 + count * 2))
}

fn asn1_dump(hex: &str, truncate: usize, indent: &str, out: &mut String) -> Result<(), String> {
    if hex.len() < 4 {
        return Ok(());
    }
    let tag = u8::from_str_radix(&hex[..2], 16).map_err(|_| "invalid ASN.1 tag".to_string())?;
    // asn1_length measures from just after the tag, so the content starts at
    // 2 (tag) + length-field width.
    let (content_len, length_field) = asn1_length(hex, 2)?;
    let content_start = 2 + length_field;
    let content_end = content_start as u64 + content_len;
    if content_end > hex.len() as u64 {
        return Err("ASN.1 content length exceeds input".into());
    }
    let content = &hex[content_start..content_end as usize];
    let label = asn1_tag_label(tag);
    if tag & 0x20 != 0 {
        if content.is_empty() {
            out.push_str(&format!("{indent}{label} {{}}\n"));
            return Ok(());
        }
        out.push_str(&format!("{indent}{label}\n"));
        let mut rest = content;
        while !rest.is_empty() {
            let child_len = asn1_element_len(rest)?;
            asn1_dump(&rest[..child_len], truncate, &format!("{indent}  "), out)?;
            rest = &rest[child_len..];
        }
    } else {
        let rendered = match tag {
            0x05 => String::new(),
            0x01 if content == "01" => " TRUE".into(),
            0x01 => " FALSE".into(),
            0x06 => format!(" {} ({})", asn1_oid(&hex_decode(content)?), hex),
            0x0C | 0x13 | 0x14 | 0x16 => {
                format!(" '{}'", String::from_utf8_lossy(&hex_decode(content)?))
            }
            _ => format!(" {}", asn1_skip_long_hex(content, truncate)),
        };
        out.push_str(&format!("{indent}{label}{rendered}\n"));
    }
    Ok(())
}

fn asn1_element_len(hex: &str) -> Result<usize, String> {
    if hex.len() < 4 {
        return Err("truncated ASN.1 element".into());
    }
    let (content_len, length_field) = asn1_length(hex, 2)?;
    let end = 2 + length_field as u64 + content_len;
    if end > hex.len() as u64 {
        return Err("ASN.1 element exceeds input".into());
    }
    Ok(end as usize)
}

// --- TLV parsing (CyberChef ParseTLV) ---------------------------------------

fn tlv_length(input: &[u8], at: usize, length_size: usize, ber: bool) -> Result<(usize, usize), String> {
    if ber {
        if at >= input.len() {
            return Err("truncated TLV length".into());
        }
        let first = input[at];
        if first < 0x80 {
            return Ok((first as usize, 1));
        }
        let count = (first & 0x7F) as usize;
        if count == 0 || count > 4 || at + 1 + count > input.len() {
            return Err("invalid BER length".into());
        }
        let mut value = 0usize;
        for &b in &input[at + 1..at + 1 + count] {
            value = (value << 8) | b as usize;
        }
        Ok((value, count + 1))
    } else if length_size == 0 {
        Ok((0, 0))
    } else {
        if at + length_size > input.len() {
            return Err("truncated TLV length".into());
        }
        let mut value = 0usize;
        for &b in &input[at..at + length_size] {
            value = (value << 8) | b as usize;
        }
        Ok((value, length_size))
    }
}

fn parse_tlv(input: &[u8], type_size: usize, length_size: usize, ber: bool) -> Result<Vec<u8>, String> {
    if type_size == 0 && length_size == 0 {
        return Err("Type or Length size must be greater than 0".into());
    }
    use serde::Serialize;
    let mut entries: Vec<serde_json::Value> = Vec::new();
    let mut at = 0;
    while at < input.len() {
        let mut entry = serde_json::Map::new();
        if type_size > 0 {
            if at + type_size > input.len() {
                return Err("truncated TLV type field".into());
            }
            let key: Vec<u8> = input[at..at + type_size].to_vec();
            at += type_size;
            entry.insert(
                "key".into(),
                serde_json::Value::Array(key.iter().map(|b| serde_json::json!(b)).collect()),
            );
        }
        let (length, consumed) = tlv_length(input, at, length_size, ber)?;
        at += consumed;
        if at + length > input.len() {
            return Err("truncated TLV value".into());
        }
        let value: Vec<u8> = input[at..at + length].to_vec();
        at += length;
        entry.insert("length".into(), serde_json::json!(length));
        entry.insert(
            "value".into(),
            serde_json::Value::Array(value.iter().map(|b| serde_json::json!(b)).collect()),
        );
        entries.push(serde_json::Value::Object(entry));
    }
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
    let mut buffer = Vec::new();
    let mut serializer = serde_json::ser::Serializer::with_formatter(&mut buffer, formatter);
    entries
        .serialize(&mut serializer)
        .map_err(|e| e.to_string())?;
    Ok(buffer)
}

// --- Change IP format (CyberChef ChangeIPFormat) ----------------------------

fn change_ip_format(input: &[u8], in_format: &str, out_format: &str) -> Result<Vec<u8>, String> {
    let normalize = |f: &str| match f.to_lowercase().as_str() {
        "dotted decimal" | "dotted" | "dd" => "dd",
        "decimal" | "dec" => "decimal",
        "octal" | "oct" => "octal",
        "hex" => "hex",
        _ => "",
    };
    let (in_fmt, out_fmt) = (normalize(in_format), normalize(out_format));
    if in_fmt.is_empty() || out_fmt.is_empty() {
        return Err("Unsupported IP format".into());
    }
    let mut lines = Vec::new();
    for line in text(input).split('\n') {
        if line.trim().is_empty() {
            continue;
        }
        let bytes: Vec<u8> = match in_fmt {
            "dd" => {
                let octets: Vec<u8> = line
                    .trim()
                    .split('.')
                    .map(|o| o.parse::<u8>().map_err(|_| format!("invalid octet '{o}'")))
                    .collect::<Result<_, _>>()?;
                if octets.len() != 4 {
                    return Err("dotted decimal requires exactly 4 octets".into());
                }
                octets
            }
            _ => {
                let radix = match in_fmt {
                    "decimal" => 10,
                    "octal" => 8,
                    _ => 16,
                };
                u32::from_str_radix(line.trim(), radix)
                    .map_err(|_| format!("'{line}' is not a valid {in_fmt} IPv4 value"))?
                    .to_be_bytes()
                    .to_vec()
            }
        };
        let rendered = match out_fmt {
            "dd" => bytes.iter().map(u8::to_string).collect::<Vec<_>>().join("."),
            "decimal" => u32::from_be_bytes(bytes.try_into().expect("4 octets")).to_string(),
            "octal" => format!("0{:o}", u32::from_be_bytes(bytes.try_into().expect("4 octets"))),
            _ => hex_encode(&bytes).to_lowercase(),
        };
        lines.push(rendered);
    }
    Ok(lines.join("\n").into_bytes())
}

// --- Text-integer conversion (CyberChef TextIntegerConverter) ---------------

fn big_bytes_to_decimal(bytes: &[u8]) -> String {
    let mut digits: Vec<u32> = Vec::new();
    for &byte in bytes {
        let mut carry = u32::from(byte);
        for digit in digits.iter_mut() {
            carry += *digit << 8;
            *digit = carry % 10;
            carry /= 10;
        }
        while carry > 0 {
            digits.push(carry % 10);
            carry /= 10;
        }
    }
    if digits.is_empty() {
        return "0".into();
    }
    digits.iter().rev().map(|d| (b'0' + *d as u8) as char).collect()
}

fn big_decimal_to_bytes(raw: &str) -> Result<Vec<u8>, String> {
    if raw.is_empty() || !raw.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("'{raw}' is not a decimal integer"));
    }
    let digits: Vec<u32> = raw.bytes().map(|b| u32::from(b - b'0')).collect();
    Ok(digits_to_bytes(digits, 10))
}

fn text_integer_conversion(input: &[u8], output_format: &str) -> Result<Vec<u8>, String> {
    let trimmed = text(input).trim().to_string();
    let is_hex = trimmed.len() > 2
        && trimmed.to_lowercase().starts_with("0x")
        && trimmed[2..].chars().all(|c| c.is_ascii_hexdigit());
    let is_decimal = !trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_digit());
    let bytes: Vec<u8> = if is_hex {
        hex_decode(&trimmed[2..])?
    } else if is_decimal {
        big_decimal_to_bytes(&trimmed)?
    } else {
        let unquoted = trimmed
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .or_else(|| trimmed.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
            .unwrap_or(&trimmed);
        let mut bytes = Vec::new();
        for (index, ch) in unquoted.chars().enumerate() {
            if ch as u32 > 255 {
                return Err(format!(
                    "Character at position {index} exceeds Latin-1 range (0-255). Only ASCII and Latin-1 characters are supported."
                ));
            }
            bytes.push(ch as u8);
        }
        bytes
    };
    match output_format {
        "String" => Ok(bytes),
        "Decimal" => Ok(big_bytes_to_decimal(&bytes).into_bytes()),
        "Hexadecimal" => Ok(format!("0x{}", hex_encode(&bytes).to_lowercase()).into_bytes()),
        other => Err(format!("Unknown output format: {other}")),
    }
}

// --- Braille (CyberChef To/FromBraille) -------------------------------------

const BRAILLE_ASCII: &str = " A1B'K2L@CIF/MSP\"E3H9O6R^DJG>NTQ,*5<-U8V.%[$+X!&;:4\\0Z7(_?W]#Y)=";
const BRAILLE_DOT6: &str = "\u{2800}\u{2801}\u{2802}\u{2803}\u{2804}\u{2805}\u{2806}\u{2807}\u{2808}\u{2809}\u{280A}\u{280B}\u{280C}\u{280D}\u{280E}\u{280F}\u{2810}\u{2811}\u{2812}\u{2813}\u{2814}\u{2815}\u{2816}\u{2817}\u{2818}\u{2819}\u{281A}\u{281B}\u{281C}\u{281D}\u{281E}\u{281F}\u{2820}\u{2821}\u{2822}\u{2823}\u{2824}\u{2825}\u{2826}\u{2827}\u{2828}\u{2829}\u{282A}\u{282B}\u{282C}\u{282D}\u{282E}\u{282F}\u{2830}\u{2831}\u{2832}\u{2833}\u{2834}\u{2835}\u{2836}\u{2837}\u{2838}\u{2839}\u{283A}\u{283B}\u{283C}\u{283D}\u{283E}\u{283F}\u{2840}\u{2841}\u{2842}\u{2843}\u{2844}\u{2845}\u{2846}\u{2847}\u{2848}\u{2849}\u{284A}\u{284B}\u{284C}\u{284D}\u{284E}\u{284F}\u{2850}\u{2851}\u{2852}\u{2853}\u{2854}\u{2855}\u{2856}\u{2857}\u{2858}\u{2859}\u{285A}\u{285B}\u{285C}\u{285D}\u{285E}\u{285F}\u{2860}\u{2861}\u{2862}\u{2863}\u{2864}\u{2865}\u{2866}\u{2867}\u{2868}\u{2869}\u{286A}\u{286B}\u{286C}\u{286D}\u{286E}\u{286F}\u{2870}\u{2871}\u{2872}\u{2873}\u{2874}\u{2875}\u{2876}\u{2877}\u{2878}\u{2879}\u{287A}\u{287B}\u{287C}\u{287D}\u{287E}\u{287F}";

fn braille_encode(input: &[u8]) -> Vec<u8> {
    let mut out = String::new();
    for ch in text(input).chars() {
        let upper = ch.to_ascii_uppercase();
        match BRAILLE_ASCII.chars().position(|c| c == upper) {
            Some(idx) => out.push(BRAILLE_DOT6.chars().nth(idx).unwrap_or(ch)),
            None => out.push(ch),
        }
    }
    out.into_bytes()
}

fn braille_decode(input: &[u8]) -> Vec<u8> {
    let mut out = String::new();
    for ch in text(input).chars() {
        match BRAILLE_DOT6.chars().position(|c| c == ch) {
            Some(idx) => out.push(BRAILLE_ASCII.chars().nth(idx).unwrap_or(ch)),
            None => out.push(ch),
        }
    }
    out.into_bytes()
}

// --- COBS (CyberChef To/FromCOBS; examples from the Wikipedia article) ------

fn cobs_encode(input: &[u8]) -> Vec<u8> {
    if input.is_empty() {
        return Vec::new();
    }
    let mut data: Vec<u8> = Vec::with_capacity(input.len() + 1);
    data.push(0);
    data.extend_from_slice(input);
    let mut out = Vec::new();
    while !data.is_empty() {
        let end_index = data
            .iter()
            .enumerate()
            .skip(1)
            .find(|(_, &b)| b == 0)
            .map(|(i, _)| i);
        match end_index {
            Some(end) if end <= 254 => {
                out.push(end as u8);
                out.extend_from_slice(&data[1..end]);
                data = data[end..].to_vec();
            }
            _ => {
                if end_index.is_none() && data.len() <= 254 {
                    out.push(data.len() as u8);
                    out.extend_from_slice(&data[1..]);
                    break;
                }
                out.push(255);
                out.extend_from_slice(&data[1..255.min(data.len())]);
                data = data[255.min(data.len())..].to_vec();
                if !data.is_empty() {
                    data.insert(0, 0);
                }
            }
        }
    }
    out
}

fn cobs_decode(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.iter().any(|&b| b == 0) {
        return Err("Could not decode from COBS: payload must not contain a 0x00 byte".into());
    }
    if input.is_empty() {
        return Ok(Vec::new());
    }
    let mut out: Vec<u8> = vec![0];
    let mut at = 0;
    while at < input.len() {
        let block = input[at] as usize;
        if block == 0 || at + block > input.len() {
            return Err("invalid COBS block length".into());
        }
        out.extend_from_slice(&input[at + 1..at + block]);
        if block < 255 && at + block < input.len() {
            out.push(0);
        }
        at += block;
    }
    out.remove(0);
    Ok(out)
}

// --- Encode/Decode text (CyberChef EncodeText/DecodeText, charset subset) ---

fn resolve_charset(param: Option<&str>) -> Result<&'static str, String> {
    let raw = param
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .unwrap_or("UTF-8 (65001)");
    Ok(match raw.to_lowercase().as_str() {
        "utf-8 (65001)" | "utf-8" | "utf8" | "65001" => "utf-8",
        "utf-16le (1200)" | "utf-16le" | "utf16le" | "1200" => "utf-16le",
        "utf-16be (1201)" | "utf-16be" | "utf16be" | "1201" => "utf-16be",
        "utf-32le (12000)" | "utf-32le" | "utf32le" | "12000" => "utf-32le",
        "utf-32be (12001)" | "utf-32be" | "utf32be" | "12001" => "utf-32be",
        "windows-1252 latin (1252)" | "windows-1252" | "cp1252" | "1252" => "windows-1252",
        "iso-8859-1 latin 1 western european (28591)" | "iso-8859-1" | "latin1" | "latin-1"
        | "28591" => "iso-8859-1",
        other => {
            return Err(format!(
                "Unsupported encoding: {other}. Native charset support covers UTF-8, UTF-16LE/BE, UTF-32LE/BE, Windows-1252 and ISO-8859-1."
            ))
        }
    })
}

fn encode_text(input: &[u8], charset: &str) -> Result<Vec<u8>, String> {
    let source = text(input);
    match charset {
        "utf-8" => Ok(source.into_bytes()),
        "utf-16le" => Ok(source.encode_utf16().flat_map(u16::to_le_bytes).collect()),
        "utf-16be" => Ok(source.encode_utf16().flat_map(u16::to_be_bytes).collect()),
        "utf-32le" => Ok(source.chars().flat_map(|c| (c as u32).to_le_bytes()).collect()),
        "utf-32be" => Ok(source.chars().flat_map(|c| (c as u32).to_be_bytes()).collect()),
        "iso-8859-1" => source
            .chars()
            .map(|c| {
                if (c as u32) < 256 {
                    Ok(c as u8)
                } else {
                    Err("character outside ISO-8859-1 range".to_string())
                }
            })
            .collect(),
        "windows-1252" => source
            .chars()
            .map(|c| match c {
                '\u{20AC}' => Ok(0x80), '\u{201A}' => Ok(0x82), '\u{0192}' => Ok(0x83),
                '\u{201E}' => Ok(0x84), '\u{2026}' => Ok(0x85), '\u{2020}' => Ok(0x86),
                '\u{2021}' => Ok(0x87), '\u{02C6}' => Ok(0x88), '\u{2030}' => Ok(0x89),
                '\u{0160}' => Ok(0x8A), '\u{2039}' => Ok(0x8B), '\u{0152}' => Ok(0x8C),
                '\u{017D}' => Ok(0x8E), '\u{2018}' => Ok(0x91), '\u{2019}' => Ok(0x92),
                '\u{201C}' => Ok(0x93), '\u{201D}' => Ok(0x94), '\u{2022}' => Ok(0x95),
                '\u{2013}' => Ok(0x96), '\u{2014}' => Ok(0x97), '\u{02DC}' => Ok(0x98),
                '\u{2122}' => Ok(0x99), '\u{0161}' => Ok(0x9A), '\u{203A}' => Ok(0x9B),
                '\u{0153}' => Ok(0x9C), '\u{017E}' => Ok(0x9E), '\u{0178}' => Ok(0x9F),
                other if (other as u32) < 256 => Ok(other as u8),
                _ => Err("character outside Windows-1252 range".to_string()),
            })
            .collect(),
        other => Err(format!("Unsupported encoding: {other}")),
    }
}

fn decode_text(input: &[u8], charset: &str) -> Result<Vec<u8>, String> {
    match charset {
        "utf-8" => Ok(text(input).into_bytes()),
        "utf-16le" => {
            let units: Vec<u16> = input
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], *c.get(1).unwrap_or(&0)]))
                .collect();
            Ok(String::from_utf16_lossy(&units).into_bytes())
        }
        "utf-16be" => {
            let units: Vec<u16> = input
                .chunks(2)
                .map(|c| u16::from_be_bytes([*c.get(0).unwrap_or(&0), *c.get(1).unwrap_or(&0)]))
                .collect();
            Ok(String::from_utf16_lossy(&units).into_bytes())
        }
        "utf-32le" | "utf-32be" => {
            let big_endian = charset == "utf-32be";
            let mut out = String::new();
            for chunk in input.chunks(4) {
                let mut quad = [0u8; 4];
                for (i, b) in chunk.iter().enumerate() {
                    quad[i] = *b;
                }
                if big_endian {
                    quad.reverse();
                }
                out.push(char::from_u32(u32::from_le_bytes(quad)).unwrap_or('\u{fffd}'));
            }
            Ok(out.into_bytes())
        }
        "iso-8859-1" => Ok(input.iter().map(|&b| b as char).collect::<String>().into_bytes()),
        "windows-1252" => {
            let decoded: String = input
                .iter()
                .map(|&b| match b {
                    0x80 => '\u{20AC}', 0x82 => '\u{201A}', 0x83 => '\u{0192}',
                    0x84 => '\u{201E}', 0x85 => '\u{2026}', 0x86 => '\u{2020}',
                    0x87 => '\u{2021}', 0x88 => '\u{02C6}', 0x89 => '\u{2030}',
                    0x8A => '\u{0160}', 0x8B => '\u{2039}', 0x8C => '\u{0152}',
                    0x8E => '\u{017D}', 0x91 => '\u{2018}', 0x92 => '\u{2019}',
                    0x93 => '\u{201C}', 0x94 => '\u{201D}', 0x95 => '\u{2022}',
                    0x96 => '\u{2013}', 0x97 => '\u{2014}', 0x98 => '\u{02DC}',
                    0x99 => '\u{2122}', 0x9A => '\u{0161}', 0x9B => '\u{203A}',
                    0x9C => '\u{0153}', 0x9E => '\u{017E}', 0x9F => '\u{0178}',
                    other => other as char,
                })
                .collect();
            Ok(decoded.into_bytes())
        }
        other => Err(format!("Unsupported encoding: {other}")),
    }
}

// --- Unicode text format (CyberDeck extra named in the catalog request) -----

fn unicode_text_format(input: &[u8], mode: &str) -> Vec<u8> {
    let underline = matches!(mode, "underline" | "both");
    let strikethrough = matches!(mode, "strikethrough" | "both");
    let mut out = String::new();
    for ch in text(input).chars() {
        out.push(ch);
        if strikethrough {
            out.push('\u{0336}');
        }
        if underline {
            out.push('\u{0332}');
        }
    }
    out.into_bytes()
}

// --- Dispatch ---------------------------------------------------------------

fn base_param_tokens(param: Option<&str>) -> Vec<String> {
    param
        .map(|p| p.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default()
}

pub fn apply(op: &str, input: &[u8], param: Option<&str>) -> Result<Vec<u8>, String> {
    match op {
        "to_base45" => {
            let alphabet = resolve_alphabet(param, BASE45_DEFAULT, &[])?;
            base45_encode(input, &alphabet)
        }
        "from_base45" => {
            let tokens = base_param_tokens(param);
            let strict = tokens.iter().any(|t| t.eq_ignore_ascii_case("strict"));
            let alphabet = resolve_alphabet(tokens.first().map(String::as_str), BASE45_DEFAULT, &[])?;
            base45_decode(input, &alphabet, strict)
        }
        "to_base58" => base58_alphabet(param).map(|a| base58_encode(input, &a)),
        "from_base58" => base58_alphabet(param).and_then(|a| base58_decode(input, &a)),
        "to_base58check" => base58check_alphabet_and_version(param)
            .map(|(a, v)| base58check_encode(input, &a, v)),
        "from_base58check" => base58check_alphabet_and_version(param)
            .and_then(|(a, _)| base58check_decode(input, &a)),
        "to_base62" => base62_alphabet(param).map(|a| base62_encode(input, &a)),
        "from_base62" => base62_alphabet(param).and_then(|a| base62_decode(input, &a)),
        "to_base85" => {
            let (alphabet, standard) = base85_alphabet(param)?;
            Ok(base85_encode(input, &alphabet, standard, false))
        }
        "from_base85" => {
            let (alphabet, _) = base85_alphabet(param)?;
            // CyberChef's all-zero group char is "z"; when the alphabet itself
            // contains 'z' (Z85) the marker is disabled instead of erroring.
            let zero_char = if alphabet.contains(&b'z') { u8::MAX } else { b'z' };
            base85_decode(input, &alphabet, zero_char)
        }
        "to_base92" => base92_encode(input),
        "from_base92" => base92_decode(input),
        "to_bech32" => {
            let tokens = base_param_tokens(param);
            let hrp = tokens.first().map(String::as_str).unwrap_or("bc");
            let bech32m = tokens.get(1).is_some_and(|e| e.eq_ignore_ascii_case("bech32m"));
            bech32_encode_string(hrp, input, bech32m).map(String::into_bytes)
        }
        "from_bech32" => bech32_decode_string(&text(input)),
        "to_base" => {
            let radix = base_param_tokens(param)
                .first()
                .and_then(|r| r.parse::<u32>().ok())
                .unwrap_or(36);
            if !(2..=36).contains(&radix) {
                return Err("Error: Radix argument must be between 2 and 36".into());
            }
            let source = text(input).trim().to_string();
            let Some(dot) = source.find('.') else {
                let int_value: i128 = source
                    .trim()
                    .parse()
                    .map_err(|_| "Error: Input must be a number".to_string())?;
                if int_value < 0 {
                    return Ok(format!("-{}", number_to_radix(int_value.unsigned_abs(), radix)).into_bytes());
                }
                return Ok(number_to_radix(int_value as u128, radix).into_bytes());
            };
            let (int_part, frac_part) = source.split_at(dot);
            let int_value: f64 = int_part
                .trim()
                .parse()
                .map_err(|_| "Error: Input must be a number".to_string())?;
            let frac_value: f64 = format!("0.{}", &frac_part[1..])
                .parse()
                .unwrap_or(0.0);
            let sign = if int_value < 0.0 || (int_value == 0.0 && int_part.trim().starts_with('-')) {
                "-"
            } else {
                ""
            };
            let mut out = String::from(sign);
            out.push_str(&number_to_radix(int_value.trunc().abs() as u128, radix));
            let mut frac = frac_value.abs();
            if frac > 0.0 {
                out.push('.');
                for _ in 0..12 {
                    frac *= f64::from(radix);
                    let digit = frac.trunc();
                    out.push((b'0' + digit as u8) as char);
                    frac -= digit;
                    if frac == 0.0 {
                        break;
                    }
                }
            }
            Ok(out.into_bytes())
        }
        "from_base" => {
            let radix = base_param_tokens(param)
                .first()
                .and_then(|r| r.parse::<u32>().ok())
                .unwrap_or(36);
            if !(2..=36).contains(&radix) {
                return Err("Error: Radix argument must be between 2 and 36".into());
            }
            let source = text(input).split_whitespace().collect::<String>();
            from_radix_number(&source, radix).map(String::into_bytes)
        }
        "to_octal" => Ok(octal_encode(input, param.unwrap_or(" "))),
        "from_octal" => octal_decode(input, param.unwrap_or(" ")),
        "to_bcd" => {
            let (_, table, packed, signed, format) = bcd_params(param)?;
            bcd_encode(input, &table, packed, signed, &format)
        }
        "from_bcd" => {
            let (_, table, packed, signed, format) = bcd_params(param)?;
            bcd_decode(input, &table, packed, signed, &format)
        }
        "to_float" => {
            let (little_endian, double) = float_param(param);
            float_encode(input, " ", little_endian, double)
        }
        "from_float" => {
            let (_, double) = float_param(param);
            float_decode(input, " ", double)
        }
        "escape_unicode" => {
            let tokens = base_param_tokens(param);
            let prefix = tokens.first().map(String::as_str).unwrap_or("\\u");
            let encode_all = tokens.iter().any(|t| t.eq_ignore_ascii_case("all"));
            Ok(escape_unicode(input, prefix, encode_all))
        }
        "unescape_unicode" => unescape_unicode(input, param.unwrap_or("\\u")),
        "escape_smart_chars" => Ok(escape_smart_chars(input, param.unwrap_or("Include"))),
        "to_hex_content" => {
            let tokens = base_param_tokens(param);
            let mode = tokens
                .first()
                .map(|m| match m.to_lowercase().as_str() {
                    "all" | "all chars" => "All chars",
                    "spaces" | "including spaces" => "Only special chars including spaces",
                    _ => "Only special chars",
                })
                .unwrap_or("Only special chars");
            let spaces = tokens.iter().any(|t| t.eq_ignore_ascii_case("spaces"));
            Ok(hex_content_encode(input, mode, spaces))
        }
        "from_hex_content" => hex_content_decode(input),
        "caret_m_decode" => Ok(caret_m_decode(input)),
        "to_modhex" => Ok(modhex_encode(input, param.unwrap_or(" "))),
        "from_modhex" => modhex_decode(input),
        "to_quoted_printable" => quoted_printable_encode(input),
        "from_quoted_printable" => quoted_printable_decode(input),
        "to_punycode" => {
            let idn = base_param_tokens(param)
                .first()
                .is_some_and(|t| t.eq_ignore_ascii_case("idn") || t.eq_ignore_ascii_case("true"));
            if idn {
                let mut labels = Vec::new();
                for label in text(input).trim().split('.') {
                    if label.is_ascii() {
                        labels.push(label.to_string());
                    } else {
                        labels.push(format!("xn--{}", punycode_encode(label)?));
                    }
                }
                Ok(labels.join(".").into_bytes())
            } else {
                punycode_encode(&text(input)).map(String::into_bytes)
            }
        }
        "from_punycode" => {
            let idn = base_param_tokens(param)
                .first()
                .is_some_and(|t| t.eq_ignore_ascii_case("idn") || t.eq_ignore_ascii_case("true"));
            if idn {
                let mut labels = Vec::new();
                for label in text(input).trim().split('.') {
                    if let Some(body) = label
                        .strip_prefix("xn--")
                        .or_else(|| label.strip_prefix("XN--"))
                    {
                        labels.push(punycode_decode(body)?);
                    } else {
                        labels.push(label.to_string());
                    }
                }
                Ok(labels.join(".").into_bytes())
            } else {
                punycode_decode(&text(input)).map(String::into_bytes)
            }
        }
        "mime_decode" => mime_decode(input),
        "pem_to_hex" => pem_to_hex(input),
        "hex_to_pem" => {
            let label = param
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .unwrap_or("CERTIFICATE");
            hex_to_pem(input, label)
        }
        "parse_asn1_hex_string" => {
            let truncate = base_param_tokens(param)
                .first()
                .and_then(|t| t.parse::<usize>().ok())
                .unwrap_or(32);
            let cleaned: String = text(input)
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .collect::<String>()
                .to_lowercase();
            let mut out = String::new();
            asn1_dump(&cleaned, truncate, "", &mut out)?;
            Ok(out.into_bytes())
        }
        "parse_tlv" => {
            let tokens = base_param_tokens(param);
            let type_size = tokens
                .first()
                .and_then(|t| t.parse::<usize>().ok())
                .unwrap_or(1);
            let length_size = tokens
                .get(1)
                .and_then(|t| t.parse::<usize>().ok())
                .unwrap_or(1);
            let ber = tokens
                .get(2)
                .is_some_and(|t| t.eq_ignore_ascii_case("ber") || t.eq_ignore_ascii_case("true"));
            parse_tlv(input, type_size, length_size, ber)
        }
        "change_ip_format" => {
            let tokens = base_param_tokens(param);
            let in_format = tokens.first().map(String::as_str).unwrap_or("Dotted Decimal");
            let out_format = tokens.get(1).map(String::as_str).unwrap_or("Dotted Decimal");
            change_ip_format(input, in_format, out_format)
        }
        "text_integer_conversion" => text_integer_conversion(input, param.unwrap_or("String")),
        "to_braille" => Ok(braille_encode(input)),
        "from_braille" => Ok(braille_decode(input)),
        "to_cobs" => Ok(cobs_encode(input)),
        "from_cobs" => cobs_decode(input),
        "encode_text" => {
            let charset = resolve_charset(param)?;
            encode_text(input, charset)
        }
        "decode_text" => {
            let charset = resolve_charset(param)?;
            decode_text(input, charset)
        }
        "unicode_text_format" => Ok(unicode_text_format(input, param.unwrap_or("none"))),
        _ => Err(format!("operation not supported: {op}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply_ok(op: &str, input: &str, param: Option<&str>) -> Vec<u8> {
        apply(op, input.as_bytes(), param).unwrap_or_else(|e| panic!("{op} failed: {e}"))
    }
    fn s(bytes: Vec<u8>) -> String {
        String::from_utf8(bytes).unwrap()
    }

    // Base45 — RFC 9285 examples via CyberChef upstream tests/operations/tests/Base45.mjs
    #[test]
    fn base45_rfc9285_vectors() {
        assert_eq!(s(apply_ok("to_base45", "AB", None)), "BB8");
        assert_eq!(s(apply_ok("to_base45", "Hello!!", None)), "%69 VD92EX0");
        assert_eq!(s(apply_ok("to_base45", "base-45", None)), "UJCLQE7W581");
        assert_eq!(s(apply_ok("from_base45", "QED8WEX0", None)), "ietf!");
        assert_eq!(s(apply_ok("to_base45", "", None)), "");
        // CyberChef's declared default strips non-alphabet characters; the
        // upstream test exercises the strict path ("Character not in
        // alphabet: '!'"), which CyberDeck exposes as the strict flag.
        assert!(apply("from_base45", b"%69 VD92EX0", None).is_ok());
        assert!(apply("from_base45", b"!", Some("strict")).is_err());
        assert!(apply("from_base45", b"ZZZ", None).is_err());
        let encoded = apply_ok("to_base45", "ietf!", None);
        assert_eq!(apply_ok("from_base45", &s(encoded), None), b"ietf!");
    }

    // Base58 — CyberChef upstream tests/operations/tests/Base58.mjs
    #[test]
    fn base58_cyberchef_vectors() {
        assert_eq!(s(apply_ok("to_base58", "hello world", None)), "StV1DL6CwTryKyV");
        assert_eq!(
            s(apply_ok("to_base58", "hello world", Some("ripple"))),
            "StVrDLaUATiyKyV"
        );
        assert_eq!(s(apply_ok("from_base58", "StV1DL6CwTryKyV", None)), "hello world");
        assert_eq!(
            s(apply_ok("from_base58", "StVrDLaUATiyKyV", Some("ripple"))),
            "hello world"
        );
        let nulls = "\0\0\0\0\0\0";
        assert_eq!(s(apply_ok("to_base58", nulls, None)), "111111");
        assert_eq!(s(apply_ok("from_base58", "111111", None)), nulls);
        assert_eq!(s(apply_ok("to_base58", "\0\0\0Hello\0\0\0", None)), "111D7LMXYjHjTu");
        assert_eq!(s(apply_ok("from_base58", "111D7LMXYjHjTu", None)), "\0\0\0Hello\0\0\0");
        let binary: Vec<u8> = (0..=255u8).collect();
        let round = apply("to_base58", &binary, None).unwrap();
        assert_eq!(apply("from_base58", &round, None).unwrap(), binary);
    }

    // Base58Check — CyberDeck extra; checksum rule from the Bitcoin developer
    // reference (version + payload + sha256d[..4]); the all-zero payload is
    // the canonical burn address 1111111111111111111114oLvT2.
    #[test]
    fn base58check_roundtrip_and_known_value() {
        let round = apply_ok("to_base58check", "cyberdeck", None);
        assert_eq!(apply_ok("from_base58check", &s(round), None), b"cyberdeck");
        let decoded = apply("from_base58check", b"1111111111111111111114oLvT2", None).unwrap();
        assert_eq!(decoded, vec![0u8; 20]);
        assert!(apply("from_base58check", b"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", None).is_ok());
        assert!(apply("from_base58check", b"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb", None).is_err());
    }

    // Base62 — CyberChef upstream tests/operations/tests/Base62.mjs
    #[test]
    fn base62_cyberchef_vectors() {
        assert_eq!(s(apply_ok("to_base62", "Hello, World!", None)), "1wJfrzvdbtXUOlUjUf");
        assert_eq!(s(apply_ok("from_base62", "1wJfrzvdbtXUOlUjUf", None)), "Hello, World!");
        let georgian = "ნუ პანიკას";
        let encoded = s(apply_ok("to_base62", georgian, None));
        assert_eq!(encoded, "BPDNbjoGvDCDzHbKT77eWg0vGQrJuWRXltuRVZ");
        assert_eq!(apply_ok("from_base62", &encoded, None), georgian.as_bytes());
        assert_eq!(s(apply_ok("to_base62", "", None)), "");
    }

    // Base85 — CyberChef upstream tests/operations/tests/Base85.mjs; "hello
    // world" -> "BOu!rD]j7BEbo7" is the op's documented example
    #[test]
    fn base85_cyberchef_vectors() {
        assert_eq!(s(apply_ok("to_base85", "hello world", None)), "BOu!rD]j7BEbo7");
        assert_eq!(apply_ok("from_base85", "BOu!rD]j7BEbo7", None), b"hello world");
        let zeros = [0u8; 8];
        assert_eq!(apply("to_base85", &zeros, None).unwrap(), b"zz");
        assert_eq!(apply("from_base85", b"zz", None).unwrap(), zeros);
        assert_eq!(
            apply("from_base85", b"<~BOu!rD]j7BEbo7~>", None).unwrap(),
            b"hello world"
        );
        let z85 = apply("to_base85", b"hello world", Some("z85")).unwrap();
        assert_eq!(apply("from_base85", &z85, Some("z85")).unwrap(), b"hello world");
        assert!(z85.iter().all(|b| b.is_ascii_graphic()));
        let wp = "Man is distinguished, not only by his reason, but by this singular passion from other animals, which is a lust of the mind, that by a perseverance of delight in the continued and indefatigable generation of knowledge, exceeds the short vehemence of any carnal pleasure.";
        let out = apply("to_base85", wp.as_bytes(), None).unwrap();
        assert_eq!(apply("from_base85", &out, None).unwrap(), wp.as_bytes());
        assert!(s(out).starts_with("9jqo^BlbD-BleB1DJ+*+F(f,q/0JhKF<GL>Cj@.4Gp$d7F!,L7@<6@)/0JDEF<G%<+EV:2F!"));
        // Partial-group decode: 2 trailing chars yield 1 byte
        let partial = apply("from_base85", b"BOu!rD]j7BEb", None).unwrap();
        assert_eq!(&partial[..7], b"hello w");
    }

    // Base92 — CyberChef upstream tests/operations/tests/Base92.mjs
    #[test]
    fn base92_cyberchef_vectors() {
        assert_eq!(s(apply_ok("to_base92", "AB", None)), "8y2");
        assert_eq!(s(apply_ok("to_base92", "Hello!!", None)), ";K_$aOTo&");
        assert_eq!(s(apply_ok("to_base92", "base-92", None)), "DX2?V<Y(*");
        assert_eq!(s(apply_ok("from_base92", "G'_DW[B", None)), "ietf!");
        assert!(apply("from_base92", b"~", None).is_err());
        for plain in ["AB", "Hello!!", "base-92", "ietf!"] {
            let encoded = apply_ok("to_base92", plain, None);
            assert_eq!(apply_ok("from_base92", &s(encoded), None), plain.as_bytes());
        }
    }

    // Bech32 — CyberChef upstream tests/operations/tests/Bech32.mjs plus
    // BIP-0173 valid vector BC1QW508D6...
    #[test]
    fn bech32_cyberchef_and_bip_vectors() {
        assert_eq!(s(apply_ok("to_bech32", "", None)), "bc1gmk9yu");
        assert_eq!(s(apply_ok("to_bech32", "A", None)), "bc1gyufle22");
        assert_eq!(s(apply_ok("to_bech32", "Hello", None)), "bc1fpjkcmr0gzsgcg");
        assert_eq!(s(apply_ok("to_bech32", "test", Some("custom"))), "custom1w3jhxaq593qur");
        assert_eq!(s(apply_ok("to_bech32", "data", Some("tb"))), "tb1v3shgcg3x07jr");
        assert_eq!(s(apply_ok("to_bech32", "", Some("bc,bech32m"))), "bc1a8xfp7");
        assert_eq!(s(apply_ok("to_bech32", "A", Some("bc,bech32m"))), "bc1gyf4040g");
        assert_eq!(s(apply_ok("to_bech32", "Hello", Some("bc,bech32m"))), "bc1fpjkcmr0a7qya2");
        assert!(apply("to_bech32", b"x", Some("")).is_err());
        // BIP-0173 P2WPKH vector: Generic-mode decode hits the same fromWords
        // padding check CyberChef's lib applies (the address needs SegWit
        // mode, which CyberDeck does not port), so it must error cleanly.
        assert!(apply("from_bech32", b"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", None).is_err());
        for (data, hrp) in [(&b"A"[..], "bc"), (&b"Hello"[..], "custom")] {
            let encoded = apply("to_bech32", data, Some(hrp)).unwrap();
            assert_eq!(apply("from_bech32", &encoded, None).unwrap(), data);
        }
        assert!(apply("from_bech32", b"bc1fpjkcmr0gzsgcd", None).is_err());
    }

    // From Base — CyberChef upstream tests/operations/tests/FromBase.mjs
    #[test]
    fn base_radix_cyberchef_vectors() {
        assert_eq!(s(apply_ok("from_base", "1010", Some("2"))), "10");
        assert_eq!(s(apply_ok("from_base", "10.1", Some("2"))), "2.5");
        assert_eq!(s(apply_ok("from_base", "a.8", Some("16"))), "10.5");
        assert_eq!(s(apply_ok("from_base", "77", Some("8"))), "63");
        assert_eq!(s(apply_ok("from_base", "7.4", Some("8"))), "7.5");
        assert_eq!(s(apply_ok("to_base", "255", Some("16"))), "ff");
        assert_eq!(s(apply_ok("to_base", "10", Some("2"))), "1010");
        assert_eq!(s(apply_ok("to_base", "255", Some("36"))), "73");
        assert_eq!(s(apply_ok("to_base", "77", Some("16"))), "4d");
        assert_eq!(s(apply_ok("from_base", "ff", Some("16"))), "255");
        assert!(apply("from_base", b"zz", Some("2")).is_err());
    }

    // Octal — JS String-byte octal semantics (72 -> "110")
    #[test]
    fn octal_roundtrip_and_vector() {
        assert_eq!(s(apply_ok("to_octal", "H", None)), "110");
        assert_eq!(s(apply_ok("to_octal", "Hi", Some(","))), "110,151");
        assert_eq!(apply_ok("from_octal", "110 151", None), b"Hi");
        let data: Vec<u8> = (0..=255u8).collect();
        let encoded = apply("to_octal", &data, None).unwrap();
        assert_eq!(apply("from_octal", &encoded, None).unwrap(), data);
    }

    // BCD — CyberChef upstream tests/operations/tests/BCD.mjs
    #[test]
    fn bcd_cyberchef_vectors() {
        assert_eq!(s(apply_ok("to_bcd", "0", None)), "0000");
        assert_eq!(
            s(apply_ok("to_bcd", "1234567890", Some("8 4 2 1,unpacked"))),
            "0000 0001 0000 0010 0000 0011 0000 0100 0000 0101 0000 0110 0000 0111 0000 1000 0000 1001 0000 0000"
        );
        assert_eq!(
            s(apply_ok("to_bcd", "1234567890", Some("8 4 2 1,packed,signed,bytes"))),
            "00000001 00100011 01000101 01100111 10001001 00001100"
        );
        assert_eq!(
            s(apply_ok("to_bcd", "-1234567890", Some("8 4 -2 -1,packed,signed,nibbles"))),
            "0000 0111 0110 0101 0100 1011 1010 1001 1000 1111 0000 1101"
        );
        assert_eq!(s(apply_ok("from_bcd", "0000", None)), "0");
        assert_eq!(
            s(apply_ok(
                "from_bcd",
                "00000001 00100011 01000101 01100111 10001001 00001101",
                Some("8 4 2 1,packed,signed,bytes")
            )),
            "-1234567890"
        );
        assert_eq!(
            s(apply_ok(
                "from_bcd",
                "00000100 00000101 00000110 00000111 00001000 00001001 00001010 00001011 00001100 00000011",
                Some("Excess-3,unpacked")
            )),
            "1234567890"
        );
        let raw = apply_ok("to_bcd", "1234567890", Some("4 2 2 1,packed,signed,raw"));
        assert_eq!(
            apply("from_bcd", &raw, Some("4 2 2 1,packed,signed,raw")).unwrap(),
            b"1234567890"
        );
    }

    // Float — CyberChef upstream tests/operations/tests/Float.mjs
    #[test]
    fn float_cyberchef_vectors() {
        let half_be = hex::decode("3f0000003f000000").unwrap();
        assert_eq!(s(apply("to_float", &half_be, None).unwrap()), "0.5 0.5");
        let half_le = hex::decode("0000003f0000003f").unwrap();
        assert_eq!(s(apply("to_float", &half_le, Some("Little Endian")).unwrap()), "0.5 0.5");
        let half_double_be = hex::decode("3fe00000000000003fe0000000000000").unwrap();
        assert_eq!(s(apply("to_float", &half_double_be, Some("big,double")).unwrap()), "0.5 0.5");
        let half_double_le = hex::decode("000000000000e03f000000000000e03f").unwrap();
        assert_eq!(
            s(apply("to_float", &half_double_le, Some("little endian,double")).unwrap()),
            "0.5 0.5"
        );
        assert_eq!(hex::encode(apply("from_float", b"0.5 0.5", None).unwrap()), "3f0000003f000000");
        assert_eq!(hex::encode(apply("from_float", b"0.5", Some("big,double")).unwrap()), "3fe0000000000000");
        let pi_bytes = hex::decode("40490fdb").unwrap();
        assert_eq!(s(apply("to_float", &pi_bytes, None).unwrap()), "3.1415927410125732");
    }

    // Escape Unicode — CyberChef upstream tests/operations/tests/
    // UnescapeUnicodeCharacters.mjs and EscapeUnicodeCharacters defaults
    #[test]
    fn unicode_escape_vectors_and_roundtrip() {
        assert_eq!(s(apply_ok("unescape_unicode", "\\u03c3\\u03bf\\u03c5", None)), "σου");
        assert_eq!(s(apply_ok("unescape_unicode", "%u03c3%u03bf%u03c5", Some("%u"))), "σου");
        assert_eq!(s(apply_ok("unescape_unicode", "U+0041", Some("U+"))), "A");
        assert_eq!(s(apply_ok("unescape_unicode", "U+1F600", Some("U+"))), "\u{1F600}");
        assert_eq!(s(apply_ok("unescape_unicode", "U+000041", Some("U+"))), "A");
        assert_eq!(s(apply_ok("unescape_unicode", "U+0041 U+1F600 U+000042", Some("U+"))), "A \u{1F600} B");
        assert_eq!(s(apply_ok("unescape_unicode", "hello world", None)), "hello world");
        assert_eq!(s(apply_ok("escape_unicode", "a\u{03c3}b", None)), "a\\u03C3b");
        assert_eq!(s(apply_ok("escape_unicode", "a", Some("U+,all"))), "U+0061");
        let data = "CyberDeck ✓\u{1F600}".to_string();
        let encoded = s(apply_ok("escape_unicode", &data, Some("U+")));
        assert_eq!(s(apply_ok("unescape_unicode", &encoded, Some("U+"))), data);
    }

    // Escape Smart Characters — CyberChef upstream tests/operations/tests/EscapeSmartCharacters.mjs
    #[test]
    fn smart_chars_cyberchef_vectors() {
        assert_eq!(
            s(apply_ok("escape_smart_chars", "\u{201C}Hello,\u{201D} she said, \u{2018}yes.\u{2019}", None)),
            "\"Hello,\" she said, 'yes.'"
        );
        assert_eq!(
            s(apply_ok("escape_smart_chars", "page 1\u{2013}3 \u{2014} wait\u{2026}", None)),
            "page 1-3 -- wait..."
        );
        assert_eq!(
            s(apply_ok("escape_smart_chars", "Foo\u{00A9} Bar\u{00AE} Baz\u{2122}", None)),
            "Foo(c) Bar(r) Baz(tm)"
        );
        assert_eq!(
            s(apply_ok("escape_smart_chars", "\u{2190} \u{2192} \u{2194} \u{21D2} \u{00AB} \u{00BB}", None)),
            "<-- --> <-> ==> << >>"
        );
        assert_eq!(
            s(apply_ok("escape_smart_chars", "3 \u{00D7} 4 \u{00F7} 2 = 6, \u{00B1}0.5 \u{2022} item", None)),
            "3 x 4 / 2 = 6, +/-0.5 * item"
        );
        assert_eq!(s(apply_ok("escape_smart_chars", "warning: \u{2623} hazard", Some("Remove"))), "warning:  hazard");
        assert_eq!(
            s(apply_ok("escape_smart_chars", "warning: \u{2623} hazard", Some("Replace with '.'"))),
            "warning: . hazard"
        );
    }

    // Hex content — CyberChef ToHexContent/FromHexContent semantics
    #[test]
    fn hex_content_roundtrip() {
        assert_eq!(s(apply_ok("to_hex_content", "Hi!", None)), "Hi|21|");
        assert_eq!(s(apply_ok("to_hex_content", "Hi", Some("all"))), "|4869|");
        assert_eq!(s(apply_ok("to_hex_content", "a b", None)), "a b");
        assert_eq!(s(apply_ok("to_hex_content", "a b", Some("spaces"))), "a|20|b");
        assert_eq!(s(apply_ok("from_hex_content", "Hi|21|", None)), "Hi!");
        assert_eq!(s(apply_ok("from_hex_content", "|4869|", None)), "Hi");
        let mixed = "a\x01b";
        let encoded = apply_ok("to_hex_content", mixed, None);
        assert_eq!(apply_ok("from_hex_content", &s(encoded), None), mixed.as_bytes());
    }

    // Caret/M-decode — CyberChef upstream tests/operations/tests/CaretMdecode.mjs
    #[test]
    fn caret_m_decode_vectors() {
        assert_eq!(apply_ok("caret_m_decode", "^@", None), vec![0u8]);
        assert_eq!(apply_ok("caret_m_decode", "^?", None), vec![127u8]);
        assert_eq!(apply_ok("caret_m_decode", "M-^?", None), vec![255u8]);
        assert_eq!(apply_ok("caret_m_decode", "M-^A", None), vec![129u8]);
        assert_eq!(apply_ok("caret_m_decode", "M-a", None), vec![0xE1u8]);
        assert_eq!(apply_ok("caret_m_decode", "M-^@", None), vec![128u8]);
        assert_eq!(s(apply_ok("caret_m_decode", "C^HAT", None)), "C\u{8}AT");
        assert_eq!(apply_ok("caret_m_decode", "", None), Vec::<u8>::new());
        assert_eq!(apply_ok("caret_m_decode", "M-x", None), vec![0xF8u8]);
    }

    // Modhex — CyberChef upstream tests/operations/tests/Modhex.mjs
    #[test]
    fn modhex_cyberchef_vectors() {
        assert_eq!(s(apply_ok("to_modhex", "aberystwyth", Some(""))), "hbhdhgidikieifiiikifhj");
        assert_eq!(
            s(apply_ok("to_modhex", "aberystwyth", Some(":"))),
            "hb:hd:hg:id:ik:ie:if:ii:ik:if:hj"
        );
        assert_eq!(apply_ok("from_modhex", "uhkgkbuhkgkbugltlkugltkc", None), "救救孩子".as_bytes());
        assert_eq!(apply_ok("from_modhex", "uhKGkbUHkgkBUGltlkugltkc", None), "救救孩子".as_bytes());
        let round = apply_ok("to_modhex", "aberystwyth", Some(""));
        assert_eq!(apply_ok("from_modhex", &s(round), None), b"aberystwyth");
    }

    // Quoted-Printable — RFC 2045 §6.7 rules and round-trips
    #[test]
    fn quoted_printable_rfc2045_vectors() {
        assert_eq!(s(apply_ok("from_quoted_printable", "caf=C3=A9", None)), "café");
        assert_eq!(s(apply_ok("from_quoted_printable", "Sp=20ace", None)), "Sp ace");
        let with_space = apply_ok("to_quoted_printable", "hello \nworld", None);
        assert_eq!(s(with_space), "hello=20\r\nworld");
        let long_line = "x".repeat(300);
        let encoded_long = s(apply_ok("to_quoted_printable", &long_line, None));
        for line in encoded_long.split("=\r\n") {
            assert!(line.len() <= 76, "line too long: {}", line.len());
        }
        assert_eq!(apply_ok("from_quoted_printable", &encoded_long, None), long_line.as_bytes());
        let text = "Now's the time for all folk to come to the aid of their country.";
        let encoded = s(apply_ok("to_quoted_printable", text, None));
        assert_eq!(apply_ok("from_quoted_printable", &encoded, None), text.as_bytes());
        // =XX escapes are never split across soft breaks
        assert!(!encoded_long.contains("=\r\n0"));
        let utf8 = "café";
        let encoded_utf8 = s(apply_ok("to_quoted_printable", utf8, None));
        assert_eq!(apply_ok("from_quoted_printable", &encoded_utf8, None), utf8.as_bytes());
    }

    // Punycode — RFC 3492 §7.1 sample (L) plus vectors cross-verified against
    // Node's punycode module (the punycode.js implementation CyberChef wraps)
    #[test]
    fn punycode_rfc3492_vectors() {
        let spanish = "Por qu\u{00e9} no puede simplemente hablar en Espa\u{00f1}ol";
        assert_eq!(
            s(apply_ok("to_punycode", spanish, None)),
            "Por qu no puede simplemente hablar en Espaol-g4d81b"
        );
        assert_eq!(
            apply_ok("from_punycode", "Por qu no puede simplemente hablar en Espaol-g4d81b", None),
            spanish.as_bytes()
        );
        // decode side: RFC-derived string, value verified via Node punycode
        assert_eq!(
            s(apply_ok("from_punycode", "PorqunopuedensimplementehablarenEspaol-fmd56a", None)),
            "Porqu\u{00e9}nopuedensimplementehablarenEspa\u{00f1}ol"
        );
        // RFC 3492 §7.1 (L): 3年B組金八先生
        let japanese = "3\u{5e74}B\u{7d44}\u{91d1}\u{516b}\u{5148}\u{751f}";
        assert_eq!(s(apply_ok("to_punycode", japanese, None)), "3B-ww4c5e180e575a65lsy2b");
        assert_eq!(apply_ok("from_punycode", "3B-ww4c5e180e575a65lsy2b", None), japanese.as_bytes());
        // RFC 3492 §7.1 (S): all-ASCII keeps the trailing delimiter
        assert_eq!(s(apply_ok("to_punycode", "-> $1.00 <-", None)), "-> $1.00 <--");
        // RFC 3490 IDN example
        assert_eq!(s(apply_ok("to_punycode", "b\u{00fc}cher.example", Some("idn"))), "xn--bcher-kva.example");
        assert_eq!(
            s(apply_ok("from_punycode", "xn--bcher-kva.example", Some("idn"))),
            "b\u{00fc}cher.example"
        );
    }

    // MIME Decoding — CyberChef upstream tests/operations/tests/MIMEDecoding.mjs
    #[test]
    fn mime_decode_cyberchef_vectors() {
        assert_eq!(s(apply_ok("mime_decode", "(=?ISO-8859-1?Q?a?=)", None)), "(a)");
        assert_eq!(s(apply_ok("mime_decode", "(=?ISO-8859-1?Q?a?= b)", None)), "(a b)");
        assert_eq!(
            s(apply_ok("mime_decode", "(=?ISO-8859-1?Q?a?= =?ISO-8859-1?Q?b?=)", None)),
            "(ab)"
        );
        assert_eq!(
            s(apply_ok("mime_decode", "(=?ISO-8859-1?Q?a?=\r\n =?ISO-8859-1?Q?b?=)", None)),
            "(ab)"
        );
        assert_eq!(
            s(apply_ok(
                "mime_decode",
                "=?utf-8?q?=C3=89ric?= <eric@example.org>, =?utf-8?q?Ana=C3=AFs?= <anais@example.org>",
                None
            )),
            "Éric <eric@example.org>, Anaïs <anais@example.org>"
        );
        assert_eq!(s(apply_ok("mime_decode", "Subject: =?UTF-8?B?Y2Fmw6k=?=", None)), "Subject: café");
        assert_eq!(s(apply_ok("mime_decode", "Subject: =?UTF-8?B?5pel5pys6Kqe?=", None)), "Subject: 日本語");
        assert!(apply("mime_decode", b"=?iso-8859-2?Q?a?=", None).is_err());
    }

    // PEM — CyberChef PEM structure (RFC 7468); body verified via the base64 crate
    #[test]
    fn pem_roundtrip_and_fixture() {
        let pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----";
        assert_eq!(s(apply_ok("pem_to_hex", pem, None)), "308201");
        let round = apply_ok("hex_to_pem", "308201", Some("CERTIFICATE"));
        assert_eq!(s(round), "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----");
        assert_eq!(hex::encode(base64::engine::general_purpose::STANDARD.decode("MIIB").unwrap()), "308201");
        assert!(apply("pem_to_hex", b"-----BEGIN CERTIFICATE-----\nAA\n", None).is_err());
        assert!(apply("pem_to_hex", b"no pem here", None).is_err());
    }

    // ASN.1 — hand-built DER; tree layout follows the jsrsasign ASN1HEX.dump
    // shape CyberChef renders (SEQUENCE / INTEGER <hex> / ObjectIdentifier)
    #[test]
    fn asn1_dump_structure() {
        let hex_input = "300e02010206092a864886f70d01010b";
        let dumped = s(apply_ok("parse_asn1_hex_string", hex_input, None));
        assert!(dumped.contains("SEQUENCE"));
        assert!(dumped.contains("INTEGER 02"));
        assert!(dumped.contains("1.2.840.113549.1.1.11"));
        assert!(dumped.lines().any(|l| l.starts_with("  ")));
        let long = format!("0428{}", "41".repeat(40));
        let dumped_long = s(apply_ok("parse_asn1_hex_string", &long, None));
        assert!(dumped_long.contains("..(total 40bytes).."));
        assert!(apply("parse_asn1_hex_string", b"3005ff", None).is_err());
    }

    // Parse TLV — CyberChef upstream tests/operations/tests/ParseTLV.mjs
    #[test]
    fn parse_tlv_cyberchef_vectors() {
        let length_value = b"\x05House\x04room\x04door";
        let out = s(apply("parse_tlv", length_value, Some("0,1")).unwrap());
        assert!(out.contains("\"length\": 5"));
        assert!(out.contains("72,"));
        assert!(out.contains("111,"));
        assert!(!out.contains("\"key\""));
        let key_value = b"\x04\x05House\x05\x04room\x42\x04door";
        let out = s(apply("parse_tlv", key_value, Some("1,1")).unwrap());
        assert!(out.contains("\"key\""));
        assert!(out.contains("66"));
        let ber_input: Vec<u8> = {
            let mut v = vec![0x01, 0x82, 0x01, 0x00];
            v.extend(std::iter::repeat(b'A').take(256));
            v.extend_from_slice(b"\x02\x03ABC");
            v
        };
        let out = s(apply("parse_tlv", &ber_input, Some("1,1,ber")).unwrap());
        assert!(out.contains("\"length\": 256"));
        assert!(out.contains("\"length\": 3"));
    }

    // Change IP format — CyberChef upstream tests/operations/tests/ChangeIPFormat.mjs
    #[test]
    fn change_ip_format_cyberchef_vectors() {
        assert_eq!(s(apply_ok("change_ip_format", "192.168.1.1", Some("Dotted Decimal,Hex"))), "c0a80101");
        assert_eq!(s(apply_ok("change_ip_format", "3232235777", Some("Decimal,Dotted Decimal"))), "192.168.1.1");
        assert_eq!(s(apply_ok("change_ip_format", "c0a80101", Some("Hex,Octal"))), "030052000401");
        assert_eq!(s(apply_ok("change_ip_format", "030052000401", Some("Octal,Decimal"))), "3232235777");
        assert_eq!(s(apply_ok("change_ip_format", "192.168.1.1", None)), "192.168.1.1");
    }

    // Text-Integer — CyberChef upstream tests/operations/tests/TextIntegerConverter.mjs
    #[test]
    fn text_integer_cyberchef_vectors() {
        assert_eq!(s(apply_ok("text_integer_conversion", "\"ABC\"", Some("Decimal"))), "4276803");
        assert_eq!(s(apply_ok("text_integer_conversion", "\"ABC\"", Some("Hexadecimal"))), "0x414243");
        assert_eq!(s(apply_ok("text_integer_conversion", "'Hello'", Some("Decimal"))), "310939249775");
        assert_eq!(s(apply_ok("text_integer_conversion", "4276803", Some("String"))), "ABC");
        assert_eq!(s(apply_ok("text_integer_conversion", "0x48656C6C6F", Some("String"))), "Hello");
        let decimal = s(apply_ok("text_integer_conversion", "\"Test\"", Some("Decimal")));
        assert_eq!(apply_ok("text_integer_conversion", &decimal, Some("String")), b"Test");
        let hex_form = s(apply_ok("text_integer_conversion", "\"CyberChef\"", Some("Hexadecimal")));
        assert_eq!(apply_ok("text_integer_conversion", &hex_form, Some("String")), b"CyberChef");
    }

    // Braille — CyberChef lib/Braille.mjs BRAILLE_LOOKUP; ToBraille uppercases
    // before lookup and FromBraille returns the stored case, so the round trip
    // is case-insensitive (upstream has no Braille test file)
    #[test]
    fn braille_table_vectors() {
        assert_eq!(s(apply_ok("to_braille", "a", None)), "\u{2801}");
        assert_eq!(s(apply_ok("to_braille", "A1", None)), "\u{2801}\u{2802}");
        assert_eq!(s(apply_ok("from_braille", "\u{2801}\u{2802}", None)), "A1");
        assert_eq!(s(apply_ok("from_braille", "\u{2801}", None)), "A");
        let data = "Hello, World! 123";
        let encoded = apply_ok("to_braille", data, None);
        assert_eq!(s(apply_ok("from_braille", &s(encoded), None)), data.to_uppercase());
        assert_eq!(s(apply_ok("to_braille", "\u{2623}", None)), "\u{2623}");
    }

    // COBS — Wikipedia Consistent Overhead Byte Stuffing examples (also used
    // by CyberChef's upstream COBS.mjs tests)
    #[test]
    fn cobs_wikipedia_vectors() {
        let cases: &[(&str, &str)] = &[
            ("00", "0101"),
            ("0000", "010101"),
            ("001100", "010211 01"),
            ("11220033", "0311220233"),
            ("11223344", "0511223344"),
            ("11000000", "0211010101"),
        ];
        for (input_hex, expected) in cases {
            let input = hex::decode(&input_hex.replace(' ', "")).unwrap();
            let out = apply("to_cobs", &input, None).unwrap();
            assert_eq!(hex::encode(&out), expected.replace(' ', ""), "{input_hex}");
            assert_eq!(apply("from_cobs", &out, None).unwrap(), input);
        }
        let long: Vec<u8> = (0x01..=0xFE).collect();
        let out = apply("to_cobs", &long, None).unwrap();
        assert_eq!(out[0], 0xFF);
        assert_eq!(apply("from_cobs", &out, None).unwrap(), long);
        assert!(apply("from_cobs", &[0u8], None).is_err());
    }

    // Encode/Decode text — charset subset (UTF-16 vector: "Hi" -> 4800 6900)
    #[test]
    fn encode_decode_text_charsets() {
        assert_eq!(apply_ok("encode_text", "Hi", None), b"Hi");
        assert_eq!(apply_ok("encode_text", "Hi", Some("UTF-16LE (1200)")), &[0x48, 0x00, 0x69, 0x00]);
        assert_eq!(apply("decode_text", &[0x48, 0x00, 0x69, 0x00], Some("1200")).unwrap(), b"Hi");
        assert_eq!(apply_ok("encode_text", "Hi", Some("UTF-16BE (1201)")), &[0x00, 0x48, 0x00, 0x69]);
        let euro = "café €";
        let cp1252 = apply_ok("encode_text", euro, Some("Windows-1252 Latin (1252)"));
        assert_eq!(cp1252, b"caf\xE9 \x80".to_vec());
        assert_eq!(apply("decode_text", &cp1252, Some("windows-1252")).unwrap(), euro.as_bytes());
        let latin = "caf\u{00e9}";
        assert_eq!(apply_ok("encode_text", latin, Some("ISO-8859-1 Latin 1 Western European (28591)")), b"caf\xe9");
        assert_eq!(apply("decode_text", b"caf\xe9", Some("28591")).unwrap(), latin.as_bytes());
        assert!(apply("encode_text", b"x", Some("shift_jis")).is_err());
        let round = apply_ok("encode_text", "CyberDeck \u{1F600}", Some("UTF-32BE (12001)"));
        assert_eq!(apply("decode_text", &round, Some("12001")).unwrap(), "CyberDeck \u{1F600}".as_bytes());
    }

    // Unicode Text Format — CyberChef upstream tests/operations/tests/Unicode.mjs
    #[test]
    fn unicode_text_format_vectors() {
        assert_eq!(s(apply_ok("unicode_text_format", "a", Some("underline"))), "a\u{0332}");
        assert_eq!(s(apply_ok("unicode_text_format", "a", Some("strikethrough"))), "a\u{0336}");
        assert_eq!(s(apply_ok("unicode_text_format", "a", Some("both"))), "a\u{0336}\u{0332}");
        assert_eq!(s(apply_ok("unicode_text_format", "a", None)), "a");
    }

    #[test]
    fn unknown_op_reports_error() {
        assert!(apply("not_an_op", b"x", None).is_err());
    }
}
