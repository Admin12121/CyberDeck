//! Lazy, bounded, byte-preserving candidate generators for local recovery.
//! All generators emit one candidate at a time; callers control cancellation.
use crate::recovery::{MaskCandidates, MAX_CANDIDATE_BYTES, MAX_FAST_CANDIDATES};
use std::io::BufRead;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HybridOrder {
    /// Wordlist word before the generated mask.
    WordThenMask,
    /// Generated mask before the wordlist word.
    MaskThenWord,
}

/// Return deterministic left-major Cartesian-product candidates, preserving
/// arbitrary bytes (including NUL and non-UTF-8). Inputs are borrowed.
pub struct CombinatorCandidates<'a> {
    left: &'a [Vec<u8>],
    right: &'a [Vec<u8>],
    left_index: usize,
    right_index: usize,
    remaining: u64,
}
impl<'a> CombinatorCandidates<'a> {
    pub fn new(left: &'a [Vec<u8>], right: &'a [Vec<u8>]) -> Result<Self, String> {
        let total = (left.len() as u64)
            .checked_mul(right.len() as u64)
            .ok_or("combinator candidate count overflow")?;
        if total > MAX_FAST_CANDIDATES {
            return Err("combinator exceeds native candidate limit".into());
        }
        let max_left = left.iter().map(Vec::len).max().unwrap_or(0);
        let max_right = right.iter().map(Vec::len).max().unwrap_or(0);
        if max_left
            .checked_add(max_right)
            .is_none_or(|n| n > MAX_CANDIDATE_BYTES)
        {
            return Err("combinator would produce oversized candidates".into());
        }
        Ok(Self {
            left,
            right,
            left_index: 0,
            right_index: 0,
            remaining: total,
        })
    }
    pub fn remaining(&self) -> u64 {
        self.remaining
    }
}
impl Iterator for CombinatorCandidates<'_> {
    type Item = Vec<u8>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let left = &self.left[self.left_index];
        let right = &self.right[self.right_index];
        let mut output = Vec::with_capacity(left.len() + right.len());
        output.extend_from_slice(left);
        output.extend_from_slice(right);
        self.remaining -= 1;
        self.right_index += 1;
        if self.right_index == self.right.len() {
            self.right_index = 0;
            self.left_index += 1;
        }
        Some(output)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.remaining as usize;
        (n, Some(n))
    }
}
impl ExactSizeIterator for CombinatorCandidates<'_> {}

/// Generate a bounded mask for each word; no output list is materialized.
/// MaskCandidates interprets tokens ?l/?u/?d/?s/?a/?? as one output byte.
pub struct HybridCandidates<'a> {
    words: &'a [Vec<u8>],
    mask: &'a str,
    order: HybridOrder,
    current_mask: MaskCandidates,
    word_index: usize,
    remaining: u64,
    mask_keyspace: u64,
}
impl<'a> HybridCandidates<'a> {
    pub fn new(words: &'a [Vec<u8>], mask: &'a str, order: HybridOrder) -> Result<Self, String> {
        let mut current_mask = MaskCandidates::parse(mask)?;
        let mask_keyspace = current_mask.remaining();
        let mask_length = current_mask.next().ok_or("empty hybrid mask")?.len();
        let total = (words.len() as u64)
            .checked_mul(mask_keyspace)
            .ok_or("hybrid candidate count overflow")?;
        if total > MAX_FAST_CANDIDATES {
            return Err("hybrid exceeds native candidate limit".into());
        }
        if words.iter().any(|word| {
            word.len()
                .checked_add(mask_length)
                .is_none_or(|n| n > MAX_CANDIDATE_BYTES)
        }) {
            return Err("hybrid would produce oversized candidates".into());
        }
        current_mask = MaskCandidates::parse(mask)?;
        Ok(Self {
            words,
            mask,
            order,
            current_mask,
            word_index: 0,
            remaining: total,
            mask_keyspace,
        })
    }
    pub fn remaining(&self) -> u64 {
        self.remaining
    }
    pub fn mask_keyspace(&self) -> u64 {
        self.mask_keyspace
    }
}
impl Iterator for HybridCandidates<'_> {
    type Item = Vec<u8>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let suffix = self.current_mask.next()?;
        let word = &self.words[self.word_index];
        let mut out = Vec::with_capacity(word.len() + suffix.len());
        match self.order {
            HybridOrder::WordThenMask => {
                out.extend_from_slice(word);
                out.extend_from_slice(&suffix);
            }
            HybridOrder::MaskThenWord => {
                out.extend_from_slice(&suffix);
                out.extend_from_slice(word);
            }
        }
        self.remaining -= 1;
        if self.current_mask.remaining() == 0 {
            self.word_index += 1;
            // All future resets use the constructor-validated mask.
            if self.remaining > 0 {
                self.current_mask = MaskCandidates::parse(self.mask)
                    .expect("validated hybrid mask must remain valid");
            }
        }
        Some(out)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.remaining as usize;
        (n, Some(n))
    }
}
impl ExactSizeIterator for HybridCandidates<'_> {}

/// Iterates a wordlist without loading the file or materializing candidates.
/// The reader is consumed on demand, with at most MAX_CANDIDATE_BYTES + CRLF
/// held per word. Empty lines, NUL and non-UTF-8 bytes are valid candidates.
pub struct WordlistCandidates<R: BufRead> {
    reader: R,
    finished: bool,
}
impl<R: BufRead> WordlistCandidates<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            finished: false,
        }
    }
}
impl<R: BufRead> Iterator for WordlistCandidates<R> {
    type Item = Result<Vec<u8>, String>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        let mut candidate = Vec::new();
        loop {
            let chunk = match self.reader.fill_buf() {
                Ok(bytes) => bytes,
                Err(err) => {
                    self.finished = true;
                    return Some(Err(format!("wordlist read error: {err}")));
                }
            };
            if chunk.is_empty() {
                self.finished = true;
                return if candidate.is_empty() {
                    None
                } else if candidate.len() > MAX_CANDIDATE_BYTES {
                    Some(Err("wordlist candidate exceeds byte limit".into()))
                } else {
                    Some(Ok(candidate))
                };
            }
            let end = chunk.iter().position(|b| *b == b'\n');
            let take = end.map_or(chunk.len(), |index| index + 1);
            if candidate.len().saturating_add(take) > MAX_CANDIDATE_BYTES + 2 {
                self.finished = true;
                return Some(Err("wordlist candidate exceeds byte limit".into()));
            }
            candidate.extend_from_slice(&chunk[..take]);
            self.reader.consume(take);
            if end.is_some() {
                candidate.pop(); // LF, including a line consisting solely of LF.
                if candidate.last() == Some(&b'\r') {
                    candidate.pop(); // CRLF only: keep all other binary bytes.
                }
                if candidate.len() > MAX_CANDIDATE_BYTES {
                    self.finished = true;
                    return Some(Err("wordlist candidate exceeds byte limit".into()));
                }
                return Some(Ok(candidate));
            }
        }
    }
}

/// Applies a bounded list of compiled rules to each source word, one candidate
/// at a time. Does not materialize the Cartesian product. Ordering is
/// word-major, then rule-major, so indices are stable and reproducible.
pub struct RuleCandidates<I: Iterator<Item = Result<Vec<u8>, String>>> {
    input: I,
    rules: Vec<crate::recovery::CompiledRule>,
    word: Option<Vec<u8>>,
    next_rule: usize,
    finished: bool,
}
impl<I: Iterator<Item = Result<Vec<u8>, String>>> RuleCandidates<I> {
    pub fn new(input: I, rules: Vec<crate::recovery::CompiledRule>) -> Result<Self, String> {
        if rules.is_empty() || rules.len() > crate::recovery::MAX_RULES_PER_STREAM {
            return Err(format!(
                "rule count must be 1..={}",
                crate::recovery::MAX_RULES_PER_STREAM
            ));
        }
        Ok(Self {
            input,
            rules,
            word: None,
            next_rule: 0,
            finished: false,
        })
    }
}
impl<I: Iterator<Item = Result<Vec<u8>, String>>> Iterator for RuleCandidates<I> {
    type Item = Result<Vec<u8>, String>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        loop {
            if let Some(word) = &self.word {
                if let Some(rule) = self.rules.get(self.next_rule) {
                    self.next_rule += 1;
                    // Rejection opcodes yield no variant for this word; try the
                    // next rule against the same word instead of emitting.
                    match rule.apply(word) {
                        Ok(Some(variant)) => return Some(Ok(variant)),
                        Ok(None) => continue,
                        Err(error) => {
                            self.finished = true;
                            return Some(Err(error));
                        }
                    }
                }
            }
            self.word = None;
            match self.input.next() {
                Some(Ok(word)) => {
                    if word.len() > MAX_CANDIDATE_BYTES {
                        self.finished = true;
                        return Some(Err("source word exceeds candidate byte limit".into()));
                    }
                    self.word = Some(word);
                    self.next_rule = 0;
                }
                Some(Err(error)) => {
                    self.finished = true;
                    return Some(Err(error));
                }
                None => {
                    self.finished = true;
                    return None;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::{recover, RecoveryLimits, RecoveryTarget};
    #[test]
    fn wordlist_stream_preserves_binary_empty_and_crlf() {
        use std::io::{BufReader, Cursor};
        let source = b"\xff\0\r\n\nsecret\nlast";
        let reader = BufReader::with_capacity(1, Cursor::new(source.as_slice()));
        let output = WordlistCandidates::new(reader)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            output,
            vec![vec![0xff, 0], vec![], b"secret".to_vec(), b"last".to_vec()]
        );
        assert_eq!(
            WordlistCandidates::new(Cursor::new(b"".as_slice())).count(),
            0
        );
        assert_eq!(
            WordlistCandidates::new(Cursor::new(b"\n".as_slice()))
                .next()
                .unwrap()
                .unwrap(),
            b""
        );
    }

    #[test]
    fn wordlist_stream_bounds_line_allocation_and_propagates_io_error() {
        use std::io::{BufReader, Cursor, Error, ErrorKind, Read};
        let accepted = [vec![b'a'; MAX_CANDIDATE_BYTES], b"\r\n".to_vec()].concat();
        let mut it = WordlistCandidates::new(BufReader::with_capacity(2, Cursor::new(accepted)));
        assert_eq!(it.next().unwrap().unwrap().len(), MAX_CANDIDATE_BYTES);
        assert!(it.next().is_none());
        let too_long = vec![b'a'; MAX_CANDIDATE_BYTES + 3];
        let mut it = WordlistCandidates::new(Cursor::new(too_long));
        assert!(it.next().unwrap().is_err());
        assert!(it.next().is_none());

        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(Error::new(ErrorKind::PermissionDenied, "fixture failure"))
            }
        }
        let mut it = WordlistCandidates::new(BufReader::new(Broken));
        assert!(it.next().unwrap().unwrap_err().contains("fixture failure"));
        assert!(it.next().is_none());
    }

    #[test]
    fn rule_stream_preserves_word_major_order_and_binary_candidates() {
        use crate::recovery::CompiledRule;
        let data = vec![Ok(b"ab".to_vec()), Ok(vec![0xff, 0])];
        let rules = vec![
            CompiledRule::parse(":").unwrap(),
            CompiledRule::parse("$!").unwrap(),
        ];
        let out = RuleCandidates::new(data.into_iter(), rules)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            out,
            vec![
                b"ab".to_vec(),
                b"ab!".to_vec(),
                vec![0xff, 0],
                vec![0xff, 0, b'!']
            ]
        );
    }
    #[test]
    fn rule_stream_laziness_and_limits() {
        use crate::recovery::CompiledRule;
        use std::cell::Cell;
        let reads = Cell::new(0);
        let source = std::iter::from_fn(|| {
            reads.set(reads.get() + 1);
            Some(Ok(b"pass".to_vec()))
        });
        let rules = vec![
            CompiledRule::parse(":").unwrap(),
            CompiledRule::parse("$1").unwrap(),
        ];
        let mut stream = RuleCandidates::new(source, rules).unwrap();
        assert_eq!(stream.next().unwrap().unwrap(), b"pass");
        assert_eq!(stream.next().unwrap().unwrap(), b"pass1");
        assert_eq!(reads.get(), 1);
        assert_eq!(stream.next().unwrap().unwrap(), b"pass");
        assert_eq!(reads.get(), 2);
        assert!(
            RuleCandidates::new(std::iter::empty::<Result<Vec<u8>, String>>(), Vec::new(),)
                .is_err()
        );
        assert!(RuleCandidates::new(
            std::iter::empty::<Result<Vec<u8>, String>>(),
            vec![CompiledRule::parse(":").unwrap(); 65_537],
        )
        .is_err());
    }
    #[test]
    fn rule_stream_propagates_error_and_ends() {
        use crate::recovery::CompiledRule;
        let words = vec![
            Ok(b"a".to_vec()),
            Err("disk error".to_string()),
            Ok(b"b".to_vec()),
        ];
        let mut it =
            RuleCandidates::new(words.into_iter(), vec![CompiledRule::parse(":").unwrap()])
                .unwrap();
        assert_eq!(it.next().unwrap().unwrap(), b"a");
        assert!(it.next().unwrap().unwrap_err().contains("disk error"));
        assert!(it.next().is_none());
    }

    #[test]
    fn combinator_is_left_major_and_byte_preserving() {
        let left = vec![vec![0xff, 0], b"ab".to_vec()];
        let right = vec![b"1".to_vec(), b"2".to_vec()];
        let mut stream = CombinatorCandidates::new(&left, &right).unwrap();
        assert_eq!(stream.remaining(), 4);
        assert_eq!(stream.next().unwrap(), vec![0xff, 0, b'1']);
        assert_eq!(stream.next().unwrap(), vec![0xff, 0, b'2']);
        assert_eq!(stream.next().unwrap(), b"ab1");
        assert_eq!(stream.next().unwrap(), b"ab2");
        assert!(stream.next().is_none());
    }
    #[test]
    fn hybrid_orders_and_resume_match_reference_order() {
        let words = vec![b"pass".to_vec(), b"test".to_vec()];
        let mut suffix = HybridCandidates::new(&words, "?d", HybridOrder::WordThenMask).unwrap();
        assert_eq!(suffix.remaining(), 20);
        assert_eq!(suffix.next().unwrap(), b"pass0");
        assert_eq!(suffix.nth(8).unwrap(), b"pass9");
        assert_eq!(suffix.next().unwrap(), b"test0");
        let mut prefix = HybridCandidates::new(&words, "?d", HybridOrder::MaskThenWord).unwrap();
        assert_eq!(prefix.next().unwrap(), b"0pass");
    }
    #[test]
    fn streams_into_native_recovery_without_materialization() {
        let words = vec![b"hello".to_vec()];
        // Compute the fixture locally instead of trusting a transcribed digest.
        let digest = hex::encode(crate::apply_op("sha256", b"hello3", None).unwrap());
        let target = RecoveryTarget::parse("sha256", &digest).unwrap();
        let candidates = HybridCandidates::new(&words, "?d", HybridOrder::WordThenMask).unwrap();
        let result = recover(&target, candidates, RecoveryLimits::default(), || false).unwrap();
        assert_eq!(result.tried, 4);
        assert_eq!(result.hits[0].candidate, b"hello3");
    }
    #[test]
    fn rejects_excessive_search_spaces_and_candidate_lengths() {
        let large = vec![b"0".to_vec(); 100_001];
        assert!(HybridCandidates::new(&large, "?a?a?a", HybridOrder::WordThenMask).is_err());
        let huge = vec![vec![b'A'; MAX_CANDIDATE_BYTES]];
        assert!(HybridCandidates::new(&huge, "?d", HybridOrder::WordThenMask).is_err());
        assert!(CombinatorCandidates::new(&huge, &[vec![b'!']]).is_err());
        let empty: Vec<Vec<u8>> = vec![];
        assert!(CombinatorCandidates::new(&empty, &huge).is_ok());
    }
}
