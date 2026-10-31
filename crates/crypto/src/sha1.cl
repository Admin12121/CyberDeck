// CyberDeck original SHA-1 OpenCL single-block kernel (FIPS 180-4).
// Supports only candidate bytes <=55; every GPU hit is rechecked in Rust.
__kernel void sha1_match(__global const uchar *input,
                         __global const uint *lengths,
                         __global const uint *target,
                         __global uint *matched,
                         const uint count) {
    const size_t id = get_global_id(0);
    if (id >= count) return;
    const uint len = lengths[id];
    if (len > 55U) { matched[id] = 0U; return; }
    uint w[80];
    const size_t base = id * 64U;
    for (uint n = 0U; n < 16U; n++) {
        uint word = 0U;
        for (uint j = 0U; j < 4U; j++) {
            const uint pos = n * 4U + j;
            uint val = 0U;
            if (pos < len) val = (uint)input[base + pos];
            else if (pos == len) val = 0x80U;
            else if (pos == 62U) val = ((len * 8U) >> 8U) & 255U;
            else if (pos == 63U) val = (len * 8U) & 255U;
            word = (word << 8U) | val;
        }
        w[n] = word;
    }
    for (uint i = 16U; i < 80U; i++)
        w[i] = rotate(w[i-3U] ^ w[i-8U] ^ w[i-14U] ^ w[i-16U], 1U);
    uint a = 0x67452301U, b = 0xefcdab89U, c = 0x98badcfeU;
    uint d = 0x10325476U, e = 0xc3d2e1f0U;
    for (uint i = 0U; i < 80U; i++) {
        uint f, k;
        if (i < 20U) {
            f = (b & c) | ((~b) & d); k = 0x5a827999U;
        } else if (i < 40U) {
            f = b ^ c ^ d; k = 0x6ed9eba1U;
        } else if (i < 60U) {
            f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdcU;
        } else {
            f = b ^ c ^ d; k = 0xca62c1d6U;
        }
        const uint t = rotate(a, 5U) + f + e + k + w[i];
        e = d; d = c; c = rotate(b, 30U); b = a; a = t;
    }
    a += 0x67452301U; b += 0xefcdab89U; c += 0x98badcfeU;
    d += 0x10325476U; e += 0xc3d2e1f0U;
    matched[id] = (a == target[0] && b == target[1] &&
                   c == target[2] && d == target[3] &&
                   e == target[4]) ? 1U : 0U;
}
