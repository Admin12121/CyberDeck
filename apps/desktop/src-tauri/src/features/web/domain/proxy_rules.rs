//! Immutable match/replace rule contract and bounded binary-safe transforms.
pub const MAX_PROXY_BODY: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MatchReplaceRule {
    pub find: String,
    pub replace: String,
}

/// Text match-and-replace must preserve bytes outside the matched byte ranges.
/// If a rule would expand a body beyond the bounded proxy limit, do not apply it.
pub(super) fn replace_bytes_limited(source: Vec<u8>, find: &[u8], replace: &[u8]) -> Vec<u8> {
    if find.is_empty() || find == replace {
        return source;
    }
    // Most rules do not match most bodies. Preserve the original allocation
    // instead of cloning even a large binary payload on that common path.
    let Some(first_match) = source.windows(find.len()).position(|chunk| chunk == find) else {
        return source;
    };
    let mut output = Vec::with_capacity(source.len().min(MAX_PROXY_BODY));
    let mut cursor = 0;
    let mut next_match = Some(first_match);
    while let Some(pos) = next_match {
        let start = cursor + pos;
        if output
            .len()
            .saturating_add(start - cursor)
            .saturating_add(replace.len())
            > MAX_PROXY_BODY
        {
            return source;
        }
        output.extend_from_slice(&source[cursor..start]);
        output.extend_from_slice(replace);
        cursor = start + find.len();
        next_match = source[cursor..]
            .windows(find.len())
            .position(|slice| slice == find);
    }
    if output.len().saturating_add(source.len() - cursor) > MAX_PROXY_BODY {
        return source;
    }
    output.extend_from_slice(&source[cursor..]);
    output
}

/// Apply match-and-replace rules to path, headers and body.
pub(super) fn apply_rules(
    mut method: String,
    mut url: String,
    mut headers: Vec<(String, String)>,
    mut body: Vec<u8>,
    rules: &[MatchReplaceRule],
) -> (String, String, Vec<(String, String)>, Vec<u8>) {
    for rule in rules {
        if rule.find.is_empty() {
            continue;
        }
        url = url.replace(&rule.find, &rule.replace);
        body = replace_bytes_limited(body, rule.find.as_bytes(), rule.replace.as_bytes());
        for (name, value) in &mut headers {
            *value = value.replace(&rule.find, &rule.replace);
            *name = name.replace(&rule.find, &rule.replace);
        }
        method = method.replace(&rule.find, &rule.replace);
    }
    (method, url, headers, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmatched_binary_rule_reuses_original_allocation() {
        let payload = vec![0xfe; 64 * 1024];
        let source_ptr = payload.as_ptr();
        let result = replace_bytes_limited(payload, b"not-present", b"changed");
        assert_eq!(result.len(), 64 * 1024);
        assert_eq!(result.as_ptr(), source_ptr);
    }
}
