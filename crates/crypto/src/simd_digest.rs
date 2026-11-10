//! Multi-buffer (SIMD) raw-digest verification for SHA-256 and MD5.
//!
//! Raw digests only — no HMAC, no KDF, no hex encodings: exactly the
//! primitives `legacy_digests` and the GPU engine verify candidates against.
//! Candidates are hashed in lanes of eight (AVX2, `__m256i`) or four
//! (SSE4.1, `__m128i`) 32-bit words at a time, with per-lane padding so
//! messages of mixed lengths share one compression loop.
//!
//! Dispatch is runtime-gated with `is_x86_feature_detected!` behind
//! `#[cfg(target_arch = "x86_64")]`; every other target (and any x86_64
//! machine without those features) uses the scalar compressors at the
//! bottom of this file, so the module compiles everywhere. The scalar
//! compressors double as the in-file reference for the KAT tests.
//!
//! Adopted by the CPU recovery engine for bare MD5/SHA-256 targets
//! (recovery.rs `DigestBatch`); every other target shape stays scalar.

// ---------------------------------------------------------------- SHA-256

/// SHA-256 round constants (FIPS 180-4 section 4.2.2).
const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 initial hash values (FIPS 180-4 section 5.3.3).
const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// -------------------------------------------------------------------- MD5

/// MD5 round constants, floor(|sin(i + 1)| * 2^32) per RFC 1321. Note the
/// entry at i = 56 is 0x6fa87e4f — several widely-copied tables carry a
/// wrong 0x...4c there; the tests recompute the table from the definition.
const MD5_T: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

/// MD5 per-step left-rotation amounts (RFC 1321).
const fn md5_shifts() -> [u32; 64] {
    let per_round = [[7u32, 12, 17, 22], [5, 9, 14, 20], [4, 11, 16, 23], [6, 10, 15, 21]];
    let mut shifts = [0u32; 64];
    let mut step = 0;
    while step < 64 {
        shifts[step] = per_round[step / 16][step % 4];
        step += 1;
    }
    shifts
}

/// MD5 per-step message-word index (RFC 1321 rounds 1-4).
const fn md5_message_indices() -> [usize; 64] {
    let mut indices = [0usize; 64];
    let mut step = 0;
    while step < 64 {
        let i = step % 16;
        indices[step] = match step / 16 {
            0 => i,
            1 => (5 * i + 1) % 16,
            2 => (3 * i + 5) % 16,
            _ => (7 * i) % 16,
        };
        step += 1;
    }
    indices
}

const MD5_SHIFTS: [u32; 64] = md5_shifts();
const MD5_INDEX: [usize; 64] = md5_message_indices();

/// MD5 initial state (RFC 1321).
const MD5_IV: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

// ---------------------------------------------- shared padding & assembly

/// Number of 64-byte blocks a message occupies once Merkle-Damgard padding
/// (0x80 terminator, zero fill, 64-bit length) is applied.
fn padded_total_blocks(len: usize) -> usize {
    len / 64 + 1 + usize::from(len % 64 > 55)
}

/// One byte of the padded message stream at absolute offset `abs`.
///
/// Data bytes come first, then the 0x80 terminator, then zero fill; the
/// final eight bytes of the last block always carry the message length in
/// bits. `total_blocks` comes from [`padded_total_blocks`], which
/// guarantees the 0x80 byte never collides with the length field.
fn padded_byte(msg: &[u8], abs: usize, total_blocks: usize, big_endian_length: bool) -> u8 {
    let len = msg.len();
    if abs < len {
        return msg[abs];
    }
    let last_base = (total_blocks - 1) * 64;
    if abs >= last_base + 56 {
        let bit_len = (len as u64).wrapping_mul(8);
        let index = abs - last_base - 56;
        return if big_endian_length {
            (bit_len >> (56 - 8 * index)) as u8
        } else {
            (bit_len >> (8 * index)) as u8
        };
    }
    if abs == len {
        return 0x80;
    }
    0
}

/// The sixteen 32-bit words of one padded block. SHA-256 words (and the
/// length field) are big-endian; MD5 words are little-endian.
fn block_words(msg: &[u8], block: usize, total_blocks: usize, big_endian: bool) -> [u32; 16] {
    let mut words = [0u32; 16];
    for (index, slot) in words.iter_mut().enumerate() {
        let base = block * 64 + index * 4;
        let mut bytes = [0u8; 4];
        for (offset, byte) in bytes.iter_mut().enumerate() {
            *byte = padded_byte(msg, base + offset, total_blocks, big_endian);
        }
        *slot = if big_endian {
            u32::from_be_bytes(bytes)
        } else {
            u32::from_le_bytes(bytes)
        };
    }
    words
}

// --------------------------------------------- scalar compress (fallback)

/// Textbook SHA-256 compression function over one block of message words.
fn sha256_compress_scalar(state: &mut [u32; 8], block: &[u32; 16]) {
    let mut w = [0u32; 64];
    w[..16].copy_from_slice(block);
    for t in 16..64 {
        let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
        let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for t in 0..64 {
        let big_sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choose = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(big_sigma1)
            .wrapping_add(choose)
            .wrapping_add(SHA256_K[t])
            .wrapping_add(w[t]);
        let big_sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let t2 = big_sigma0.wrapping_add(majority);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    *state = [
        state[0].wrapping_add(a),
        state[1].wrapping_add(b),
        state[2].wrapping_add(c),
        state[3].wrapping_add(d),
        state[4].wrapping_add(e),
        state[5].wrapping_add(f),
        state[6].wrapping_add(g),
        state[7].wrapping_add(h),
    ];
}

/// Textbook MD5 compression function over one block of message words.
fn md5_compress_scalar(state: &mut [u32; 4], block: &[u32; 16]) {
    let [mut a, mut b, mut c, mut d] = *state;
    for step in 0..64 {
        let f = match step / 16 {
            0 => (b & c) | (!b & d),
            1 => (b & d) | (c & !d),
            2 => b ^ c ^ d,
            _ => c ^ (b | !d),
        };
        let sum = a
            .wrapping_add(f)
            .wrapping_add(MD5_T[step])
            .wrapping_add(block[MD5_INDEX[step]]);
        let rotated = sum.rotate_left(MD5_SHIFTS[step]);
        let new_b = b.wrapping_add(rotated);
        a = d;
        d = c;
        c = b;
        b = new_b;
    }
    *state = [
        state[0].wrapping_add(a),
        state[1].wrapping_add(b),
        state[2].wrapping_add(c),
        state[3].wrapping_add(d),
    ];
}

/// Raw SHA-256 of one message, scalar path (also the in-file reference).
fn sha256_one(msg: &[u8]) -> [u8; 32] {
    let mut state = SHA256_IV;
    let total_blocks = padded_total_blocks(msg.len());
    for block in 0..total_blocks {
        sha256_compress_scalar(&mut state, &block_words(msg, block, total_blocks, true));
    }
    let mut digest = [0u8; 32];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..][..4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

/// Raw MD5 of one message, scalar path (also the in-file reference).
fn md5_one(msg: &[u8]) -> [u8; 16] {
    let mut state = MD5_IV;
    let total_blocks = padded_total_blocks(msg.len());
    for block in 0..total_blocks {
        md5_compress_scalar(&mut state, &block_words(msg, block, total_blocks, false));
    }
    let mut digest = [0u8; 16];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..][..4].copy_from_slice(&word.to_le_bytes());
    }
    digest
}

// ------------------------------------------- packed lanes (x86_64 only)

#[cfg(target_arch = "x86_64")]
mod packed {
    use super::{MD5_INDEX, MD5_IV, MD5_T, SHA256_IV, SHA256_K, block_words,
        padded_total_blocks};

    /// Operations on a vector of `N` 32-bit lanes. All shift/rotate amounts
    /// in SHA-256 and MD5 are compile-time constants, so they are const
    /// generic parameters here and pair with their complement at the call
    /// site (`rotr!(x, 7)` is `shr::<7>(x) | shl::<25>(x)`).
    pub(super) trait Pack<const N: usize>: Copy {
        fn splat(v: u32) -> Self;
        fn add(a: Self, b: Self) -> Self;
        fn xor(a: Self, b: Self) -> Self;
        fn and(a: Self, b: Self) -> Self;
        fn or(a: Self, b: Self) -> Self;
        /// `!a & b`
        fn andnot(a: Self, b: Self) -> Self;
        fn shl<const BITS: i32>(a: Self) -> Self;
        fn shr<const BITS: i32>(a: Self) -> Self;
        /// Lane `i` of the result is `words[i]` (lane 0 = least significant).
        fn pack(words: &[u32; N]) -> Self;
        fn extract(self, lane: usize) -> u32;
    }

    macro_rules! splat {
        ($v:expr) => {
            <P as Pack<N>>::splat($v)
        };
    }
    macro_rules! add {
        ($a:expr, $b:expr) => {
            <P as Pack<N>>::add($a, $b)
        };
    }
    macro_rules! xor {
        ($a:expr, $b:expr) => {
            <P as Pack<N>>::xor($a, $b)
        };
    }
    macro_rules! and {
        ($a:expr, $b:expr) => {
            <P as Pack<N>>::and($a, $b)
        };
    }
    macro_rules! or {
        ($a:expr, $b:expr) => {
            <P as Pack<N>>::or($a, $b)
        };
    }
    macro_rules! andnot {
        ($a:expr, $b:expr) => {
            <P as Pack<N>>::andnot($a, $b)
        };
    }
    macro_rules! shr {
        ($x:expr, $bits:expr) => {
            <P as Pack<N>>::shr::<$bits>($x)
        };
    }
    macro_rules! shl {
        ($x:expr, $bits:expr) => {
            <P as Pack<N>>::shl::<$bits>($x)
        };
    }
    /// Rotate right by a compile-time constant.
    macro_rules! rotr {
        ($x:expr, $bits:expr) => {
            or!(shr!($x, $bits), shl!($x, { 32 - $bits }))
        };
    }
    /// Rotate left by a compile-time constant.
    macro_rules! rotl {
        ($x:expr, $bits:expr) => {
            or!(shl!($x, $bits), shr!($x, { 32 - $bits }))
        };
    }

    /// Eight 32-bit lanes in one 256-bit vector.
    #[repr(transparent)]
    #[derive(Copy, Clone)]
    pub(super) struct Avx2(std::arch::x86_64::__m256i);

    /// Four 32-bit lanes in one 128-bit vector.
    #[repr(transparent)]
    #[derive(Copy, Clone)]
    pub(super) struct Sse41(std::arch::x86_64::__m128i);

    impl Pack<8> for Avx2 {
        #[inline]
        fn splat(v: u32) -> Self {
            Self(unsafe { std::arch::x86_64::_mm256_set1_epi32(v as i32) })
        }
        #[inline]
        fn add(a: Self, b: Self) -> Self {
            Self(unsafe { std::arch::x86_64::_mm256_add_epi32(a.0, b.0) })
        }
        #[inline]
        fn xor(a: Self, b: Self) -> Self {
            Self(unsafe { std::arch::x86_64::_mm256_xor_si256(a.0, b.0) })
        }
        #[inline]
        fn and(a: Self, b: Self) -> Self {
            Self(unsafe { std::arch::x86_64::_mm256_and_si256(a.0, b.0) })
        }
        #[inline]
        fn or(a: Self, b: Self) -> Self {
            Self(unsafe { std::arch::x86_64::_mm256_or_si256(a.0, b.0) })
        }
        #[inline]
        fn andnot(a: Self, b: Self) -> Self {
            Self(unsafe { std::arch::x86_64::_mm256_andnot_si256(a.0, b.0) })
        }
        #[inline]
        fn shl<const BITS: i32>(a: Self) -> Self {
            Self(unsafe { std::arch::x86_64::_mm256_slli_epi32(a.0, BITS) })
        }
        #[inline]
        fn shr<const BITS: i32>(a: Self) -> Self {
            Self(unsafe { std::arch::x86_64::_mm256_srli_epi32(a.0, BITS) })
        }
        #[inline]
        fn pack(words: &[u32; 8]) -> Self {
            Self(unsafe {
                std::arch::x86_64::_mm256_set_epi32(
                    words[7] as i32,
                    words[6] as i32,
                    words[5] as i32,
                    words[4] as i32,
                    words[3] as i32,
                    words[2] as i32,
                    words[1] as i32,
                    words[0] as i32,
                )
            })
        }
        #[inline]
        fn extract(self, lane: usize) -> u32 {
            let mut lanes = [0u32; 8];
            unsafe {
                std::arch::x86_64::_mm256_storeu_si256(lanes.as_mut_ptr() as *mut _, self.0)
            };
            lanes[lane]
        }
    }

    impl Pack<4> for Sse41 {
        #[inline]
        fn splat(v: u32) -> Self {
            Self(unsafe { std::arch::x86_64::_mm_set1_epi32(v as i32) })
        }
        #[inline]
        fn add(a: Self, b: Self) -> Self {
            Self(unsafe { std::arch::x86_64::_mm_add_epi32(a.0, b.0) })
        }
        #[inline]
        fn xor(a: Self, b: Self) -> Self {
            Self(unsafe { std::arch::x86_64::_mm_xor_si128(a.0, b.0) })
        }
        #[inline]
        fn and(a: Self, b: Self) -> Self {
            Self(unsafe { std::arch::x86_64::_mm_and_si128(a.0, b.0) })
        }
        #[inline]
        fn or(a: Self, b: Self) -> Self {
            Self(unsafe { std::arch::x86_64::_mm_or_si128(a.0, b.0) })
        }
        #[inline]
        fn andnot(a: Self, b: Self) -> Self {
            Self(unsafe { std::arch::x86_64::_mm_andnot_si128(a.0, b.0) })
        }
        #[inline]
        fn shl<const BITS: i32>(a: Self) -> Self {
            Self(unsafe { std::arch::x86_64::_mm_slli_epi32(a.0, BITS) })
        }
        #[inline]
        fn shr<const BITS: i32>(a: Self) -> Self {
            Self(unsafe { std::arch::x86_64::_mm_srli_epi32(a.0, BITS) })
        }
        #[inline]
        fn pack(words: &[u32; 4]) -> Self {
            Self(unsafe {
                std::arch::x86_64::_mm_set_epi32(
                    words[3] as i32,
                    words[2] as i32,
                    words[1] as i32,
                    words[0] as i32,
                )
            })
        }
        #[inline]
        fn extract(self, lane: usize) -> u32 {
            let mut lanes = [0u32; 4];
            unsafe { std::arch::x86_64::_mm_storeu_si128(lanes.as_mut_ptr() as *mut _, self.0) };
            lanes[lane]
        }
    }

    /// SHA-256 compression across `N` lanes; `w` holds the current block's
    /// message words already transposed (lane i in lane i).
    ///
    /// The 16-word ring cannot hold all 64 schedule words, so the schedule
    /// is expanded in place as the rounds consume it: when round `t` runs,
    /// slot `t & 15` still holds `w[t - 16]` while `w[t - 15]`, `w[t - 7]`
    /// and `w[t - 2]` sit at their untouched ring positions.
    fn sha256_compress_packed<P: Pack<N>, const N: usize>(state: &mut [P; 8], w: &mut [P; 16]) {
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
        for t in 0..64 {
            if t >= 16 {
                let v = w[(t + 1) & 15]; // w[t - 15]
                let s0 = xor!(rotr!(v, 7), xor!(rotr!(v, 18), shr!(v, 3)));
                let u = w[(t + 14) & 15]; // w[t - 2]
                let s1 = xor!(rotr!(u, 17), xor!(rotr!(u, 19), shr!(u, 10)));
                let base = w[t & 15]; // w[t - 16]
                let middle = w[(t + 9) & 15]; // w[t - 7]
                w[t & 15] = add!(add!(add!(base, s0), middle), s1);
            }
            let big_sigma1 = xor!(rotr!(e, 6), xor!(rotr!(e, 11), rotr!(e, 25)));
            let choose = xor!(and!(e, f), andnot!(e, g));
            let t1 = add!(add!(add!(add!(h, big_sigma1), choose), splat!(SHA256_K[t])), w[t & 15]);
            let big_sigma0 = xor!(rotr!(a, 2), xor!(rotr!(a, 13), rotr!(a, 22)));
            let majority = xor!(xor!(and!(a, b), and!(a, c)), and!(b, c));
            let t2 = add!(big_sigma0, majority);
            h = g;
            g = f;
            f = e;
            e = add!(d, t1);
            d = c;
            c = b;
            b = a;
            a = add!(t1, t2);
        }
        let working = [a, b, c, d, e, f, g, h];
        for (index, slot) in state.iter_mut().enumerate() {
            *slot = add!(*slot, working[index]);
        }
    }

    /// MD5 compression across `N` lanes.
    fn md5_compress_packed<P: Pack<N>, const N: usize>(state: &mut [P; 4], w: &mut [P; 16]) {
        let [mut a, mut b, mut c, mut d] = *state;
        for step in 0..64 {
            let round = step / 16;
            let i = step % 16;
            let f = match round {
                0 => xor!(and!(b, c), andnot!(b, d)),               // F(b,c,d)
                1 => xor!(and!(b, d), andnot!(d, c)),               // G(b,c,d)
                2 => xor!(xor!(b, c), d),                           // H(b,c,d)
                _ => xor!(c, or!(b, andnot!(d, splat!(u32::MAX)))), // I(b,c,d)
            };
            let sum = add!(add!(add!(a, f), splat!(MD5_T[step])), w[MD5_INDEX[step]]);
            // The shift amount is fixed per (round, step % 4); every arm
            // instantiates a distinct compile-time rotation.
            let rotated = match (round, i % 4) {
                (0, 0) => rotl!(sum, 7),
                (0, 1) => rotl!(sum, 12),
                (0, 2) => rotl!(sum, 17),
                (0, 3) => rotl!(sum, 22),
                (1, 0) => rotl!(sum, 5),
                (1, 1) => rotl!(sum, 9),
                (1, 2) => rotl!(sum, 14),
                (1, 3) => rotl!(sum, 20),
                (2, 0) => rotl!(sum, 4),
                (2, 1) => rotl!(sum, 11),
                (2, 2) => rotl!(sum, 16),
                (2, 3) => rotl!(sum, 23),
                (_, 0) => rotl!(sum, 6),
                (_, 1) => rotl!(sum, 10),
                (_, 2) => rotl!(sum, 15),
                _ => rotl!(sum, 21),
            };
            let new_b = add!(b, rotated);
            a = d;
            d = c;
            c = b;
            b = new_b;
        }
        let working = [a, b, c, d];
        for (index, slot) in state.iter_mut().enumerate() {
            *slot = add!(*slot, working[index]);
        }
    }

    /// Hash one chunk of at most `N` candidates into `out` (same length).
    /// Each lane is padded to its own length; a lane that finishes early
    /// has its digest extracted immediately and is fed zero blocks after,
    /// whose results are discarded.
    fn sha256_chunk_lanes<P: Pack<N>, const N: usize>(chunk: &[&[u8]], out: &mut [[u8; 32]]) {
        debug_assert!(chunk.len() <= N && chunk.len() == out.len());
        let blocks: [usize; N] = core::array::from_fn(|lane| {
            if lane < chunk.len() {
                padded_total_blocks(chunk[lane].len())
            } else {
                1
            }
        });
        let rounds = blocks[..chunk.len()].iter().copied().max().unwrap_or(1);
        let mut state: [P; 8] = core::array::from_fn(|i| splat!(SHA256_IV[i]));
        let mut finished = [false; 8];
        let mut lane_words = [[0u32; 16]; N];
        let mut w: [P; 16] = core::array::from_fn(|_| splat!(0));
        for round in 0..rounds {
            for (lane, message) in chunk.iter().enumerate() {
                if round < blocks[lane] {
                    lane_words[lane] = block_words(message, round, blocks[lane], true);
                }
            }
            for (index, slot) in w.iter_mut().enumerate() {
                let column: [u32; N] = core::array::from_fn(|lane| lane_words[lane][index]);
                *slot = <P as Pack<N>>::pack(&column);
            }
            sha256_compress_packed::<P, N>(&mut state, &mut w);
            for lane in 0..chunk.len() {
                if !finished[lane] && round + 1 == blocks[lane] {
                    out[lane] = sha256_extract_lane::<P, N>(&state, lane);
                    finished[lane] = true;
                }
            }
        }
    }

    /// The packed compressors already fold the IV addition into `state`,
    /// so extraction reads the final digest words directly.
    fn sha256_extract_lane<P: Pack<N>, const N: usize>(state: &[P; 8], lane: usize) -> [u8; 32] {
        let mut digest = [0u8; 32];
        for (index, slot) in state.iter().enumerate() {
            let word = <P as Pack<N>>::extract(*slot, lane);
            digest[index * 4..][..4].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    /// Hash one chunk of at most `N` candidates into `out` (same length).
    fn md5_chunk_lanes<P: Pack<N>, const N: usize>(chunk: &[&[u8]], out: &mut [[u8; 16]]) {
        debug_assert!(chunk.len() <= N && chunk.len() == out.len());
        let blocks: [usize; N] = core::array::from_fn(|lane| {
            if lane < chunk.len() {
                padded_total_blocks(chunk[lane].len())
            } else {
                1
            }
        });
        let rounds = blocks[..chunk.len()].iter().copied().max().unwrap_or(1);
        let mut state: [P; 4] = core::array::from_fn(|i| splat!(MD5_IV[i]));
        let mut finished = [false; 8];
        let mut lane_words = [[0u32; 16]; N];
        let mut w: [P; 16] = core::array::from_fn(|_| splat!(0));
        for round in 0..rounds {
            for (lane, message) in chunk.iter().enumerate() {
                if round < blocks[lane] {
                    lane_words[lane] = block_words(message, round, blocks[lane], false);
                }
            }
            for (index, slot) in w.iter_mut().enumerate() {
                let column: [u32; N] = core::array::from_fn(|lane| lane_words[lane][index]);
                *slot = <P as Pack<N>>::pack(&column);
            }
            md5_compress_packed::<P, N>(&mut state, &mut w);
            for lane in 0..chunk.len() {
                if !finished[lane] && round + 1 == blocks[lane] {
                    out[lane] = md5_extract_lane::<P, N>(&state, lane);
                    finished[lane] = true;
                }
            }
        }
    }

    fn md5_extract_lane<P: Pack<N>, const N: usize>(state: &[P; 4], lane: usize) -> [u8; 16] {
        let mut digest = [0u8; 16];
        for (index, slot) in state.iter().enumerate() {
            let word = <P as Pack<N>>::extract(*slot, lane);
            digest[index * 4..][..4].copy_from_slice(&word.to_le_bytes());
        }
        digest
    }

    pub(super) fn sha256_batch_lanes<P: Pack<N>, const N: usize>(
        candidates: &[&[u8]],
    ) -> Vec<[u8; 32]> {
        let mut out = vec![[0u8; 32]; candidates.len()];
        for (start, chunk) in candidates.chunks(N).enumerate() {
            sha256_chunk_lanes::<P, N>(chunk, &mut out[start * N..start * N + chunk.len()]);
        }
        out
    }

    pub(super) fn md5_batch_lanes<P: Pack<N>, const N: usize>(
        candidates: &[&[u8]],
    ) -> Vec<[u8; 16]> {
        let mut out = vec![[0u8; 16]; candidates.len()];
        for (start, chunk) in candidates.chunks(N).enumerate() {
            md5_chunk_lanes::<P, N>(chunk, &mut out[start * N..start * N + chunk.len()]);
        }
        out
    }
}

// ------------------------------------------------------------ public API

/// Which implementation the batch helpers dispatch to on this machine:
/// `"avx2-8-lane"`, `"sse4.1-4-lane"` or `"scalar"`.
pub fn active_path() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            return "avx2-8-lane";
        }
        if is_x86_feature_detected!("sse4.1") {
            return "sse4.1-4-lane";
        }
    }
    "scalar"
}

/// Raw SHA-256 digests of every candidate, hashed in SIMD lanes where
/// available. Output is positionally aligned with the input.
pub fn sha256_batch(candidates: &[&[u8]]) -> Vec<[u8; 32]> {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            return packed::sha256_batch_lanes::<packed::Avx2, 8>(candidates);
        }
        if is_x86_feature_detected!("sse4.1") {
            return packed::sha256_batch_lanes::<packed::Sse41, 4>(candidates);
        }
    }
    candidates.iter().map(|message| sha256_one(message)).collect()
}

/// Raw MD5 digests of every candidate, hashed in SIMD lanes where
/// available. Output is positionally aligned with the input.
pub fn md5_batch(candidates: &[&[u8]]) -> Vec<[u8; 16]> {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            return packed::md5_batch_lanes::<packed::Avx2, 8>(candidates);
        }
        if is_x86_feature_detected!("sse4.1") {
            return packed::md5_batch_lanes::<packed::Sse41, 4>(candidates);
        }
    }
    candidates.iter().map(|message| md5_one(message)).collect()
}

/// Index of the first candidate whose raw SHA-256 equals `target`.
pub fn verify_sha256_batch(candidates: &[&[u8]], target: &[u8; 32]) -> Option<usize> {
    sha256_batch(candidates)
        .into_iter()
        .position(|digest| digest_eq(&digest, target))
}

/// Index of the first candidate whose raw MD5 equals `target`.
pub fn verify_md5_batch(candidates: &[&[u8]], target: &[u8; 16]) -> Option<usize> {
    md5_batch(candidates)
        .into_iter()
        .position(|digest| digest_eq(&digest, target))
}

/// Ascending indices of every candidate whose raw SHA-256 equals `target`.
/// This is the batched equivalent of comparing each candidate in order, so
/// the match set and positions are identical to a per-candidate scalar
/// comparison; unlike [`verify_sha256_batch`] it reports all matches, which
/// the recovery engine needs for `max_matches > 1` runs.
pub fn sha256_batch_matches(candidates: &[&[u8]], target: &[u8; 32]) -> Vec<usize> {
    sha256_batch(candidates)
        .iter()
        .enumerate()
        .filter_map(|(index, digest)| digest_eq(digest, target.as_slice()).then_some(index))
        .collect()
}

/// Ascending indices of every candidate whose raw MD5 equals `target`.
/// See [`sha256_batch_matches`] for the equivalence contract.
pub fn md5_batch_matches(candidates: &[&[u8]], target: &[u8; 16]) -> Vec<usize> {
    md5_batch(candidates)
        .iter()
        .enumerate()
        .filter_map(|(index, digest)| digest_eq(digest, target.as_slice()).then_some(index))
        .collect()
}

/// Constant-time digest comparison (same shape as `constant_time_eq` in
/// `archives.rs`).
fn digest_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

// ----------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic byte pattern covering the full 0..=255 range.
    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(7)).collect()
    }

    fn reference_sha256(input: &[u8]) -> [u8; 32] {
        <sha2::Sha256 as sha2::Digest>::digest(input).into()
    }

    fn reference_md5(input: &[u8]) -> [u8; 16] {
        <md5::Md5 as md5::Digest>::digest(input).into()
    }

    // Published FIPS 180-4 / RFC 1321 vectors.
    const SHA256_EMPTY: &str =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const SHA256_ABC: &str =
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const SHA256_56: &str =
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
    const SHA256_MILLION_A: &str =
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
    const MD5_EMPTY: &str = "d41d8cd98f00b204e9800998ecf8427e";
    const MD5_ABC: &str = "900150983cd24fb0d6963f7d28e17f72";
    const MD5_56: &str = "8215ef0796a20bcaaae116d3876c664a";
    const MD5_MILLION_A: &str = "7707d6ae4e027c70eea2a935c2296f21";

    const FIFTY_SIX: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

    #[test]
    fn rustcrypto_reference_matches_published_vectors() {
        assert_eq!(hex::encode(reference_sha256(b"")), SHA256_EMPTY);
        assert_eq!(hex::encode(reference_sha256(b"abc")), SHA256_ABC);
        assert_eq!(hex::encode(reference_sha256(FIFTY_SIX)), SHA256_56);
        let million_a = vec![b'a'; 1_000_000];
        assert_eq!(hex::encode(reference_sha256(&million_a)), SHA256_MILLION_A);

        assert_eq!(hex::encode(reference_md5(b"")), MD5_EMPTY);
        assert_eq!(hex::encode(reference_md5(b"abc")), MD5_ABC);
        assert_eq!(hex::encode(reference_md5(FIFTY_SIX)), MD5_56);
        assert_eq!(hex::encode(reference_md5(&million_a)), MD5_MILLION_A);
    }

    /// The MD5 round constants are defined as floor(|sin(i + 1)| * 2^32);
    /// recompute them so a hand-typed table (several widely-copied tables
    /// carry a wrong entry at i = 56) cannot regress silently.
    #[test]
    fn md5_constant_tables_match_their_definitions() {
        for (step, constant) in MD5_T.iter().enumerate() {
            let derived = ((step as f64 + 1.0).sin().abs() * 4_294_967_296.0).floor() as u32;
            assert_eq!(*constant, derived, "MD5_T[{step}]");
        }
        for (step, shift) in MD5_SHIFTS.iter().enumerate() {
            let derived = [
                [7u32, 12, 17, 22],
                [5, 9, 14, 20],
                [4, 11, 16, 23],
                [6, 10, 15, 21],
            ][step / 16][step % 4];
            assert_eq!(*shift, derived, "MD5_SHIFTS[{step}]");
        }
        for (step, index) in MD5_INDEX.iter().enumerate() {
            let i = step % 16;
            let derived = match step / 16 {
                0 => i,
                1 => (5 * i + 1) % 16,
                2 => (3 * i + 5) % 16,
                _ => (7 * i) % 16,
            };
            assert_eq!(*index, derived, "MD5_INDEX[{step}]");
        }
    }

    #[test]
    fn known_answer_vectors_hold_on_the_active_path() {
        // active_path() only reports; if neither AVX2 nor SSE4.1 is present
        // this still proves the dispatch surface works end to end.
        let path = active_path();
        assert!(matches!(path, "avx2-8-lane" | "sse4.1-4-lane" | "scalar"));

        let batch = [b"".as_slice(), b"abc".as_slice(), FIFTY_SIX];
        let sha = sha256_batch(&batch);
        assert_eq!(hex::encode(&sha[0]), SHA256_EMPTY);
        assert_eq!(hex::encode(&sha[1]), SHA256_ABC);
        assert_eq!(hex::encode(&sha[2]), SHA256_56);
        let md5s = md5_batch(&batch);
        assert_eq!(hex::encode(&md5s[0]), MD5_EMPTY);
        assert_eq!(hex::encode(&md5s[1]), MD5_ABC);
        assert_eq!(hex::encode(&md5s[2]), MD5_56);

        let million_a = vec![b'a'; 1_000_000];
        let long_batch = [million_a.as_slice()];
        assert_eq!(hex::encode(&sha256_batch(&long_batch)[0]), SHA256_MILLION_A);
        assert_eq!(hex::encode(&md5_batch(&long_batch)[0]), MD5_MILLION_A);

        assert_eq!(verify_sha256_batch(&batch, &reference_sha256(b"abc")), Some(1));
        assert_eq!(verify_md5_batch(&batch, &reference_md5(FIFTY_SIX)), Some(2));
    }

    #[test]
    fn simd_batch_matches_rustcrypto_across_lengths() {
        // 0..=130 walks every padding boundary (55/56, 63/64, 119/120,
        // 127/128); the extras push past a couple of full blocks. The
        // single batch of 137 messages also exercises chunk edges.
        let mut lengths: Vec<usize> = (0..=130).collect();
        lengths.extend([255, 256, 320, 1000, 4096, 4097]);
        let messages: Vec<Vec<u8>> = lengths.iter().map(|&len| pattern(len)).collect();
        let slices: Vec<&[u8]> = messages.iter().map(|message| message.as_slice()).collect();

        let sha = sha256_batch(&slices);
        let md5s = md5_batch(&slices);
        assert_eq!(sha.len(), slices.len());
        assert_eq!(md5s.len(), slices.len());
        for (index, message) in messages.iter().enumerate() {
            assert_eq!(
                sha[index],
                reference_sha256(message),
                "sha256 mismatch at length {}",
                lengths[index]
            );
            assert_eq!(
                md5s[index],
                reference_md5(message),
                "md5 mismatch at length {}",
                lengths[index]
            );
        }
    }

    #[test]
    fn simd_batch_matches_rustcrypto_across_batch_sizes() {
        // Partial final chunks: 1..=20 candidates against the same full set.
        let messages: Vec<Vec<u8>> = (0..20).map(|i| pattern(i * 13 + i)).collect();
        let slices: Vec<&[u8]> = messages.iter().map(|message| message.as_slice()).collect();
        for size in 1..=20 {
            let sha = sha256_batch(&slices[..size]);
            let md5s = md5_batch(&slices[..size]);
            for (index, message) in messages.iter().take(size).enumerate() {
                assert_eq!(sha[index], reference_sha256(message), "sha256 size {size}");
                assert_eq!(md5s[index], reference_md5(message), "md5 size {size}");
            }
        }
    }

    #[test]
    fn scalar_fallback_matches_rustcrypto_across_lengths() {
        let mut lengths: Vec<usize> = (0..=130).collect();
        lengths.extend([255, 256, 1000]);
        for len in lengths {
            let message = pattern(len);
            assert_eq!(sha256_one(&message), reference_sha256(&message), "len {len}");
            assert_eq!(md5_one(&message), reference_md5(&message), "len {len}");
        }
    }

    #[test]
    fn verify_sha256_batch_finds_the_real_match() {
        // Mixed lengths, empty candidate included; matches at the last
        // position, at index 0 and mid-batch.
        let lengths = [0usize, 3, 55, 56, 63, 64, 65, 119, 120, 200];
        let messages: Vec<Vec<u8>> = lengths.iter().map(|&len| pattern(len)).collect();
        let slices: Vec<&[u8]> = messages.iter().map(|message| message.as_slice()).collect();

        let last = reference_sha256(&messages[9]);
        assert_eq!(verify_sha256_batch(&slices, &last), Some(9));
        let first = reference_sha256(&messages[0]);
        assert_eq!(verify_sha256_batch(&slices, &first), Some(0));
        let middle = reference_sha256(&messages[4]);
        assert_eq!(verify_sha256_batch(&slices, &middle), Some(4));
        assert_eq!(verify_sha256_batch(&slices, &reference_sha256(b"no-candidate")), None);
        assert_eq!(verify_sha256_batch(&[], &last), None);

        // Duplicates resolve to the first index.
        let duplicated = [slices[4], slices[4], slices[9]];
        assert_eq!(verify_sha256_batch(&duplicated, &middle), Some(0));
    }

    #[test]
    fn verify_md5_batch_finds_the_real_match() {
        let lengths = [1usize, 31, 54, 55, 56, 57, 127, 128, 129, 333];
        let messages: Vec<Vec<u8>> = lengths.iter().map(|&len| pattern(len)).collect();
        let slices: Vec<&[u8]> = messages.iter().map(|message| message.as_slice()).collect();

        let last = reference_md5(&messages[9]);
        assert_eq!(verify_md5_batch(&slices, &last), Some(9));
        let middle = reference_md5(&messages[5]);
        assert_eq!(verify_md5_batch(&slices, &middle), Some(5));
        assert_eq!(verify_md5_batch(&slices, &reference_md5(b"no-candidate")), None);
        assert_eq!(verify_md5_batch(&[], &last), None);
    }

    /// Runtime dispatch always prefers AVX2 on a machine that has it, so
    /// the 4-lane SSE4.1 fallback width is exercised directly here. This
    /// stays inside the feature contract: it runs only where SSE4.1 exists.
    #[test]
    fn sse4_1_four_lane_path_matches_rustcrypto() {
        #[cfg(target_arch = "x86_64")]
        {
            if !is_x86_feature_detected!("sse4.1") {
                return;
            }
            let lengths = [0usize, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 200];
            let messages: Vec<Vec<u8>> = lengths.iter().map(|&len| pattern(len)).collect();
            let slices: Vec<&[u8]> = messages.iter().map(|message| message.as_slice()).collect();
            let sha = packed::sha256_batch_lanes::<packed::Sse41, 4>(&slices);
            let md5s = packed::md5_batch_lanes::<packed::Sse41, 4>(&slices);
            for (index, message) in messages.iter().enumerate() {
                assert_eq!(
                    sha[index],
                    reference_sha256(message),
                    "sse4.1 sha256 length {}",
                    lengths[index]
                );
                assert_eq!(
                    md5s[index],
                    reference_md5(message),
                    "sse4.1 md5 length {}",
                    lengths[index]
                );
            }
        }
    }
}
