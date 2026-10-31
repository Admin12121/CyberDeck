// CyberDeck native MD5 OpenCL kernel (RFC 1321), single-block inputs <=55 bytes.
// MD5 is a legacy recovery format, not a recommended password-storage algorithm.
// The host re-verifies every reported hit using native Rust MD5.
__constant uint MD5_K[64] = {
  0xd76aa478U,   0xe8c7b756U,   0x242070dbU,   0xc1bdceeeU, 
  0xf57c0fafU,   0x4787c62aU,   0xa8304613U,   0xfd469501U, 
  0x698098d8U,   0x8b44f7afU,   0xffff5bb1U,   0x895cd7beU, 
  0x6b901122U,   0xfd987193U,   0xa679438eU,   0x49b40821U, 
  0xf61e2562U,   0xc040b340U,   0x265e5a51U,   0xe9b6c7aaU, 
  0xd62f105dU,   0x02441453U,   0xd8a1e681U,   0xe7d3fbc8U, 
  0x21e1cde6U,   0xc33707d6U,   0xf4d50d87U,   0x455a14edU, 
  0xa9e3e905U,   0xfcefa3f8U,   0x676f02d9U,   0x8d2a4c8aU, 
  0xfffa3942U,   0x8771f681U,   0x6d9d6122U,   0xfde5380cU, 
  0xa4beea44U,   0x4bdecfa9U,   0xf6bb4b60U,   0xbebfbc70U, 
  0x289b7ec6U,   0xeaa127faU,   0xd4ef3085U,   0x04881d05U, 
  0xd9d4d039U,   0xe6db99e5U,   0x1fa27cf8U,   0xc4ac5665U, 
  0xf4292244U,   0x432aff97U,   0xab9423a7U,   0xfc93a039U, 
  0x655b59c3U,   0x8f0ccc92U,   0xffeff47dU,   0x85845dd1U, 
  0x6fa87e4fU,   0xfe2ce6e0U,   0xa3014314U,   0x4e0811a1U, 
  0xf7537e82U,   0xbd3af235U,   0x2ad7d2bbU,   0xeb86d391U 
};
__constant uint MD5_S[64] = {
  7U,   12U,   17U,   22U,   7U,   12U,   17U,   22U, 
  7U,   12U,   17U,   22U,   7U,   12U,   17U,   22U, 
  5U,   9U,   14U,   20U,   5U,   9U,   14U,   20U, 
  5U,   9U,   14U,   20U,   5U,   9U,   14U,   20U, 
  4U,   11U,   16U,   23U,   4U,   11U,   16U,   23U, 
  4U,   11U,   16U,   23U,   4U,   11U,   16U,   23U, 
  6U,   10U,   15U,   21U,   6U,   10U,   15U,   21U, 
  6U,   10U,   15U,   21U,   6U,   10U,   15U,   21U 
};

__kernel void md5_match(__global const uchar* input,
                        __global const uint* lengths,
                        __global const uint* target,
                        __global uint* matched,
                        const uint count) {
    const size_t id = get_global_id(0);
    if (id >= count) return;
    uint len = lengths[id];
    if (len > 55U) { matched[id] = 0U; return; }
    uint w[16];
    const size_t base = id * 64U;
    for (uint n = 0U; n < 16U; n++) {
        uint value = 0U;
        for (uint b = 0U; b < 4U; b++) {
            uint pos = n * 4U + b;
            uint ch = 0U;
            if (pos < len) ch = (uint)input[base + pos];
            else if (pos == len) ch = 0x80U;
            else if (pos >= 56U && pos < 60U)
                ch = ((len * 8U) >> (8U * (pos - 56U))) & 255U;
            value |= ch << (8U * b);
        }
        w[n] = value;
    }
    uint a = 0x67452301U, b = 0xefcdab89U;
    uint c = 0x98badcfeU, d = 0x10325476U;
    for (uint i = 0U; i < 64U; i++) {
        uint f, g;
        if (i < 16U) {
            f = (b & c) | (~b & d);
            g = i;
        } else if (i < 32U) {
            f = (d & b) | (~d & c);
            g = (5U * i + 1U) & 15U;
        } else if (i < 48U) {
            f = b ^ c ^ d;
            g = (3U * i + 5U) & 15U;
        } else {
            f = c ^ (b | ~d);
            g = (7U * i) & 15U;
        }
        const uint rotated = rotate(a + f + MD5_K[i] + w[g], MD5_S[i]);
        a = d; d = c; c = b; b += rotated;
    }
    a += 0x67452301U; b += 0xefcdab89U;
    c += 0x98badcfeU; d += 0x10325476U;
    matched[id] = (a == target[0] && b == target[1] &&
                   c == target[2] && d == target[3]) ? 1U : 0U;
}
