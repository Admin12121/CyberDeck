//! john-style unshadow: merge a passwd file with a shadow file into
//! `user:cipher` lines the recovery engine can consume directly. Pure text
//! processing; bounded input; nothing is written to disk here.
pub const MAX_LINES: usize = 10_000;
const MAX_LINE_BYTES: usize = 1024;

fn parse_account(line: &str) -> Option<(String, String)> {
    let line = line.trim_end_matches(['\r']);
    if line.is_empty() || line.starts_with('#') || line.len() > MAX_LINE_BYTES {
        return None;
    }
    let mut fields = line.split(':');
    let user = fields.next()?.trim().to_string();
    if user.is_empty() {
        return None;
    }
    Some((user, fields.next().unwrap_or("").to_string()))
}

/// Shadow cipher fields that mean "no crackable hash here".
fn is_locked_or_absent(cipher: &str) -> bool {
    cipher.is_empty()
        || cipher == "x"
        || cipher == "X"
        || cipher == "*"
        || cipher == "*LK*"
        || cipher == "NP"
        || cipher.starts_with('!')
}

/// Merge passwd+shadow into crackable `user:cipher` lines. Accounts that only
/// exist in passwd (or carry no hash) are skipped; a shadow account without a
/// passwd entry still yields a line under its own name.
pub fn unshadow(passwd: &str, shadow: &str) -> Result<Vec<String>, String> {
    let mut gecos: std::collections::HashMap<String, ()> = std::collections::HashMap::new();
    let mut count = 0usize;
    for line in passwd.lines() {
        if count >= MAX_LINES {
            return Err("passwd file exceeds the line limit".into());
        }
        if let Some((user, cipher_field)) = parse_account(line) {
            // Real-name column feeds nothing without GECOS cracking; only the
            // presence check matters here.
            let _ = cipher_field;
            gecos.insert(user, ());
            count += 1;
        }
    }
    let mut out = Vec::new();
    for line in shadow.lines() {
        if out.len() >= MAX_LINES {
            return Err("shadow file exceeds the line limit".into());
        }
        let Some((user, cipher)) = parse_account(line) else {
            continue;
        };
        if is_locked_or_absent(&cipher) {
            continue;
        }
        // Only pass through fields that look like modular crypt or classic
        // crypt(3): everything else is a misformatted shadow file.
        let looks_like_hash = cipher.starts_with('$') || (cipher.len() == 13 && cipher.bytes().all(|b| b.is_ascii_graphic()));
        if !looks_like_hash {
            continue;
        }
        out.push(format!("{user}:{cipher}"));
    }
    if out.is_empty() {
        return Err("no crackable shadow entries found".into());
    }
    let _ = gecos;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_and_skips_locked_accounts() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/sh\n";
        let shadow = "root:$6$rounds=100$salt$digest:19900:0:99999:7:::\nalice:!:19900:0:99999:7:::\nbob:$1$salt$digest:19900:0:99999:7:::\n";
        let merged = unshadow(passwd, shadow).unwrap();
        assert_eq!(
            merged,
            vec!["root:$6$rounds=100$salt$digest", "bob:$1$salt$digest"]
        );
        // locked alice is excluded.
        assert!(!merged.iter().any(|line| line.starts_with("alice:")));
    }

    #[test]
    fn accepts_classic_thirteen_char_crypt_and_rejects_garbage() {
        let passwd = "u:x:0:0::/:/bin/sh\n";
        let shadow = "u:hZbDsv1G7cc2s:19900:0:99999:7:::\nother:not-a-hash-field:1:0:::\n";
        let merged = unshadow(passwd, shadow).unwrap();
        assert_eq!(merged, vec!["u:hZbDsv1G7cc2s"]);
        assert!(unshadow(passwd, "# only a comment\n").is_err());
    }

    #[test]
    fn bounds_are_enforced() {
        let passwd = "u:x:0:0::/:/bin/sh\n";
        let too_many = "$1$s$d\n".repeat(MAX_LINES + 1);
        assert!(unshadow(passwd, &too_many).is_err());
    }
}
