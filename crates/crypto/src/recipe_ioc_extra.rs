//! Native email and domain recipe extractors, preserving the existing
//! TypeScript regex match order and bounded output. No network actions.

const LIMIT: usize = 8 * 1024 * 1024;

fn append(dst: &mut Vec<u8>, item: &[u8]) -> Result<(), String> {
    let growth = item.len() + usize::from(!dst.is_empty());
    if dst.len().checked_add(growth).is_none_or(|len| len > LIMIT) {
        return Err("recipe output size limit exceeded".into());
    }
    if !dst.is_empty() {
        dst.push(b'\n');
    }
    dst.extend_from_slice(item);
    Ok(())
}

fn local_part(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'%' | b'+' | b'-')
}
fn email_domain(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')
}
fn word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn extract_emails(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let source = String::from_utf8_lossy(bytes);
    let src = source.as_bytes();
    let mut at = 0;
    let mut out = Vec::new();
    while at < src.len() {
        if !local_part(src[at]) {
            at += 1;
            continue;
        }
        let start = at;
        while at < src.len() && local_part(src[at]) {
            at += 1;
        }
        if src.get(at) != Some(&b'@') {
            continue;
        }
        let after_at = at + 1;
        let mut domain_end = after_at;
        while domain_end < src.len() && email_domain(src[domain_end]) {
            domain_end += 1;
        }
        // The JS regex is greedy; find the farthest end that can satisfy
        // the final literal dot followed by at least two ASCII letters.
        let mut match_end = None;
        for dot in after_at + 1..domain_end {
            if src[dot] != b'.' {
                continue;
            }
            let mut suffix = dot + 1;
            while suffix < domain_end && src[suffix].is_ascii_alphabetic() {
                suffix += 1;
            }
            if suffix >= dot + 3 && match_end.is_none_or(|current| suffix > current) {
                match_end = Some(suffix);
            }
        }
        if let Some(end) = match_end {
            append(&mut out, &src[start..end])?;
            at = end;
        } else {
            at = after_at;
        }
    }
    Ok(out)
}

fn domain_label(source: &[u8], at: usize) -> Option<usize> {
    let mut end = at;
    if !source.get(end)?.is_ascii_alphanumeric() {
        return None;
    }
    end += 1;
    while end < source.len() && (source[end].is_ascii_alphanumeric() || source[end] == b'-') {
        end += 1;
    }
    // The JS label closes with an alphanumeric: ending '-' invalidates the
    // whole greedily consumed label, except for a possible earlier endpoint.
    while end > at && source[end - 1] == b'-' {
        end -= 1;
    }
    Some(end)
}

fn extract_domains(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let source = String::from_utf8_lossy(bytes);
    let src = source.as_bytes();
    let mut out = Vec::new();
    let mut at = 0;
    while at < src.len() {
        if !src[at].is_ascii_alphanumeric() || (at > 0 && word(src[at - 1])) {
            at += 1;
            continue;
        }
        let start = at;
        let mut position = start;
        let mut last_match = None;
        while let Some(label_end) = domain_label(src, position) {
            if src.get(label_end) != Some(&b'.') {
                break;
            }
            let after_dot = label_end + 1;
            // Existing JS /i TLD class is ASCII alpha >=2. A trailing
            // word character prevents the final \b, so "test.com3" fails.
            let mut tld_end = after_dot;
            while tld_end < src.len() && src[tld_end].is_ascii_alphabetic() {
                tld_end += 1;
            }
            if tld_end >= after_dot + 2 && (tld_end == src.len() || !word(src[tld_end])) {
                last_match = Some(tld_end);
            }
            position = after_dot;
        }
        if let Some(end) = last_match {
            append(&mut out, &src[start..end])?;
            at = end;
        } else {
            at += 1;
        }
    }
    Ok(out)
}

pub(crate) fn supports(id: &str) -> bool {
    matches!(id, "extract_emails" | "extract_domains")
}

pub(crate) fn apply(id: &str, input: &[u8]) -> Result<Vec<u8>, String> {
    match id {
        "extract_emails" => extract_emails(input),
        "extract_domains" => extract_domains(input),
        _ => Err("unknown IOC extraction operation".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn email_reference() {
        assert_eq!(
            extract_emails(
                b"hello A+B@example.com, x@sub.example.org and invalid @bad.aa +foo@example.com"
            )
            .unwrap(),
            b"A+B@example.com\nx@sub.example.org\n+foo@example.com"
        );
        assert_eq!(
            extract_emails(b"a@b.com1 foo@x.ab3 u@x..com u@x.COM").unwrap(),
            b"a@b.com\nfoo@x.ab\nu@x..com\nu@x.COM"
        );
    }
    #[test]
    fn domain_reference() {
        assert_eq!(
            extract_domains(b"See example.com sub.example.org and abc.-bad.com, a.b and foo.bar9")
                .unwrap(),
            b"example.com\nsub.example.org\nbad.com"
        );
        assert_eq!(
            extract_domains(b"user@site.com a_b.net test.com3 other.co.uk foo-bar.example.org")
                .unwrap(),
            b"site.com\nother.co.uk\nfoo-bar.example.org"
        );
    }
    #[test]
    fn expansion_limit() {
        assert!(extract_emails("a@b.co ".repeat(1_300_000).as_bytes()).is_err());
        assert!(extract_domains("x.co ".repeat(2_000_000).as_bytes()).is_err());
    }
}
