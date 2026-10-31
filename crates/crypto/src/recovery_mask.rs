//! Deterministic bounded ASCII mask enumeration and resume offsets.
use super::MAX_MASK_KEYSPACE;

/// Bounded byte-oriented mask enumeration. Supports ?l ?u ?d ?s ?a ??.
pub struct MaskCandidates {
    alphabet: Vec<Vec<u8>>,
    cursor: Vec<usize>,
    remaining: u64,
    total: u64,
}
impl MaskCandidates {
    pub fn parse(mask: &str) -> Result<Self, String> {
        let bytes = mask.as_bytes();
        let mut alphabet = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let chars = if bytes[i] == b'?' {
                i += 1;
                match *bytes.get(i).ok_or("unfinished mask")? {
                    b'l' => (b'a'..=b'z').collect(),
                    b'u' => (b'A'..=b'Z').collect(),
                    b'd' => (b'0'..=b'9').collect(),
                    b's' => b"!@#$%^&*()-_=+[]{};:,.<>/".to_vec(),
                    b'a' => (b' '..=b'~').collect(),
                    b'?' => vec![b'?'],
                    _ => return Err("unsupported mask token".into()),
                }
            } else {
                if !bytes[i].is_ascii() {
                    return Err("masks must be ASCII".into());
                }
                vec![bytes[i]]
            };
            alphabet.push(chars);
            if alphabet.len() > 16 {
                return Err("mask has too many positions".into());
            }
            i += 1;
        }
        if alphabet.is_empty() {
            return Err("empty mask".into());
        }
        let mut keyspace = 1u64;
        for chars in &alphabet {
            keyspace = keyspace
                .checked_mul(chars.len() as u64)
                .ok_or("mask overflow")?;
            if keyspace > MAX_MASK_KEYSPACE {
                return Err("mask exceeds keyspace limit".into());
            }
        }
        Ok(Self {
            cursor: vec![0; alphabet.len()],
            alphabet,
            remaining: keyspace,
            total: keyspace,
        })
    }
    /// Resume deterministic enumeration at a candidate-index offset, without
    /// enumerating earlier combinations. The offset is validated against the
    /// bounded keyspace, not trusted as a serializable full-session state.
    pub fn parse_from_offset(mask: &str, offset: u64) -> Result<Self, String> {
        let mut stream = Self::parse(mask)?;
        if offset > stream.total {
            return Err("mask resume offset exceeds keyspace".into());
        }
        let mut index = offset;
        for slot in (0..stream.cursor.len()).rev() {
            let radix = stream.alphabet[slot].len() as u64;
            stream.cursor[slot] = (index % radix) as usize;
            index /= radix;
        }
        stream.remaining -= offset;
        Ok(stream)
    }
    pub fn total(&self) -> u64 {
        self.total
    }
    pub fn position(&self) -> u64 {
        self.total - self.remaining
    }
    pub fn remaining(&self) -> u64 {
        self.remaining
    }
}
impl Iterator for MaskCandidates {
    type Item = Vec<u8>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let out = self
            .alphabet
            .iter()
            .zip(self.cursor.iter())
            .map(|(set, i)| set[*i])
            .collect();
        self.remaining -= 1;
        for i in (0..self.cursor.len()).rev() {
            self.cursor[i] += 1;
            if self.cursor[i] < self.alphabet[i].len() {
                break;
            }
            self.cursor[i] = 0;
        }
        Some(out)
    }
}
