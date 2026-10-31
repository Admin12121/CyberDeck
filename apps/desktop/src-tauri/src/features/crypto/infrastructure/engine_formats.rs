//! External engine format mappings and text parsers. No Tauri/process dependencies.
use crate::attack::AttackMatch;

pub fn parse_hashcat_version(output: &str) -> Option<String> {
    output
        .lines()
        .find_map(|line| {
            let trimmed = line.trim().trim_start_matches('v');
            let mut split = trimmed.split(|c: char| !c.is_ascii_digit() && c != '.');
            let head = split.next()?.to_string();
            head.contains('.').then_some(head)
        })
        .map(|v| format!("v{v}"))
}

pub fn parse_john_version(output: &str) -> Option<String> {
    output
        .lines()
        .find(|l| l.contains("John the Ripper"))
        .map(|l| {
            l.trim()
                .split_whitespace()
                .take(4)
                .collect::<Vec<_>>()
                .join(" ")
        })
}

pub fn hashcat_mode(algo: &str) -> Option<u32> {
    match algo {
        "md5" => Some(0),
        "sha1" => Some(100),
        "sha256" => Some(1400),
        "sha512" => Some(1700),
        "ntlm" => Some(1000),
        "md4" => Some(900),
        "lm" => Some(3000),
        "bcrypt" => Some(3200),
        "sha512crypt" => Some(1800),
        "sha256crypt" => Some(17400),
        "md5crypt" => Some(500),
        "apr1" => Some(1600),
        "phpass" => Some(400),
        "mscash2" => Some(2100),
        "sunmd5" => Some(7400),
        "yescrypt" => Some(22700),
        _ => None,
    }
}

pub fn john_format(algo: &str) -> Option<&'static str> {
    match algo {
        "md5" => Some("raw-md5"),
        "sha1" => Some("raw-sha1"),
        "sha256" => Some("raw-sha256"),
        "sha512" => Some("raw-sha512"),
        "bcrypt" => Some("bcrypt"),
        "sha512crypt" => Some("sha512crypt"),
        "sha256crypt" => Some("sha256crypt"),
        "md5crypt" => Some("md5crypt"),
        "apr1" => Some("apr1"),
        "phpass" => Some("phpass"),
        "mscash2" => Some("mscash2"),
        "sunmd5" => Some("sunmd5"),
        "yescrypt" => Some("yescrypt"),
        "lm" => Some("LM"),
        _ => None,
    }
}

/// Collect hash:plain pairs from a hashcat -o outfile.
pub fn parse_hashcat_outfile(text: &str) -> Vec<AttackMatch> {
    text.lines()
        .filter_map(|line| {
            let (hash, plain) = line.split_once(':')?;
            (!hash.is_empty() && !plain.is_empty()).then(|| AttackMatch {
                line_no: 0,
                password: plain.trim().to_string(),
            })
        })
        .collect()
}

/// Collect hash:plain pairs from `john --show`.
pub fn parse_john_show(text: &str) -> Vec<AttackMatch> {
    text.lines()
        .filter(|line| {
            line.contains(':') && !line.contains("password hashes") && !line.starts_with('\'')
        })
        .filter_map(|line| {
            let (hash, plain) = line.split_once(':')?;
            (!hash.trim().is_empty() && !plain.trim().is_empty()).then(|| AttackMatch {
                line_no: 0,
                password: plain.trim().to_string(),
            })
        })
        .collect()
}
