// CyberDeck native NTLM (MD4 over UTF-16LE) single-block OpenCL kernel.
// This optimized path accepts ASCII input bytes of length 0..=27 only.
// Non-ASCII passwords require the existing Unicode-aware CPU recovery path.
// GPU positives are independently re-verified in Rust.
__kernel void ntlm_match(__global const uchar* input,
                         __global const uint* lengths,
                         __global const uint* target,
                         __global uint* matched,
                         const uint count) {
    const size_t id = get_global_id(0);
    if (id >= count) return;
    const uint len = lengths[id];
    if (len > 27U) { matched[id] = 0U; return; }
    const size_t base = id * 64U;
    for (uint j = 0U; j < len; ++j) {
        if ((uint)input[base + j] > 127U) {
            matched[id] = 0U;
            return;
        }
    }
    const uint bytes = 2U * len;
    uint x[16];
    for (uint i = 0U; i < 16U; ++i) {
        uint word = 0U;
        for (uint j = 0U; j < 4U; ++j) {
            const uint pos = i * 4U + j;
            uint c = 0U;
            if (pos < bytes) {
                c = (pos & 1U) == 0U ? (uint)input[base + pos/2U] : 0U;
            } else if (pos == bytes) {
                c = 0x80U;
            } else if (pos >= 56U && pos < 60U) {
                c = ((len * 16U) >> (8U * (pos - 56U))) & 255U;
            }
            word |= c << (8U * j);
        }
        x[i] = word;
    }
    const uint r1[4] = {3U,7U,11U,19U};
    const uint r2[4] = {3U,5U,9U,13U};
    const uint r3[4] = {3U,9U,11U,15U};
    const uint order3[16] = {
        0U,8U,4U,12U,2U,10U,6U,14U,
        1U,9U,5U,13U,3U,11U,7U,15U
    };
    uint a = 0x67452301U, b = 0xefcdab89U;
    uint c = 0x98badcfeU, d = 0x10325476U;
    for (uint i = 0U; i < 48U; ++i) {
        uint f, g, k, shift;
        const uint step = i & 15U;
        if (i < 16U) {
            f = (b & c) | (~b & d);
            g = step;
            k = 0U;
            shift = r1[step & 3U];
        } else if (i < 32U) {
            f = (b & c) | (b & d) | (c & d);
            g = (step & 3U) * 4U + (step >> 2U);
            k = 0x5a827999U;
            shift = r2[step & 3U];
        } else {
            f = b ^ c ^ d;
            g = order3[step];
            k = 0x6ed9eba1U;
            shift = r3[step & 3U];
        }
        const uint next = rotate(a + f + x[g] + k, shift);
        a = d; d = c; c = b; b = next;
    }
    a += 0x67452301U; b += 0xefcdab89U;
    c += 0x98badcfeU; d += 0x10325476U;
    matched[id] = (a == target[0] && b == target[1] &&
                   c == target[2] && d == target[3]) ? 1U : 0U;
}
