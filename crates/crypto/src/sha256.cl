// CyberDeck native SHA-256 single-block OpenCL compute kernel.
// Independently implemented from the SHA-256 compression definition (FIPS 180-4).
// One work item per candidate, with a strict 55-byte maximum.
__constant uint K[64] = {
  0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
  0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
  0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
  0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
  0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
  0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
  0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
  0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
};
inline uint rr(uint a, uint n) { return rotate(a, (uint)(32U-n)); }
inline uint ch(uint x,uint y,uint z) { return (x & y) ^ (~x & z); }
inline uint maj(uint x,uint y,uint z) { return (x & y) ^ (x & z) ^ (y & z); }
inline uint big0(uint x) { return rr(x,2U)^rr(x,13U)^rr(x,22U); }
inline uint big1(uint x) { return rr(x,6U)^rr(x,11U)^rr(x,25U); }
inline uint small0(uint x) { return rr(x,7U)^rr(x,18U)^(x>>3U); }
inline uint small1(uint x) { return rr(x,17U)^rr(x,19U)^(x>>10U); }

__kernel void sha256_match(__global const uchar* input,
                           __global const uint* lengths,
                           __global const uint* target,
                           __global uint* matched,
                           const uint count) {
    const size_t id=get_global_id(0);
    if (id >= count) return;
    uint len=lengths[id];
    if (len>55U) { matched[id]=0U; return; }
    uint w[64];
    const size_t base=id*64U;
    for (uint n=0U;n<16U;n++) {
        uint word=0U;
        for (uint b=0U;b<4U;b++) {
            uint pos=n*4U+b;
            uint value=0U;
            if (pos<len) value=(uint)input[base+pos];
            else if (pos==len) value=0x80U;
            else if (pos==63U) value=(len*8U)&255U;
            else if (pos==62U) value=((len*8U)>>8U)&255U;
            word=(word<<8U)|value;
        }
        w[n]=word;
    }
    for (uint i=16U;i<64U;i++) {
        w[i]=w[i-16U]+small0(w[i-15U])+w[i-7U]+small1(w[i-2U]);
    }
    uint a=0x6a09e667U,b=0xbb67ae85U,c=0x3c6ef372U,d=0xa54ff53aU;
    uint e=0x510e527fU,f=0x9b05688cU,g=0x1f83d9abU,h=0x5be0cd19U;
    for (uint i=0U;i<64U;i++) {
        uint t1=h+big1(e)+ch(e,f,g)+K[i]+w[i];
        uint t2=big0(a)+maj(a,b,c);
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    a+=0x6a09e667U;b+=0xbb67ae85U;c+=0x3c6ef372U;d+=0xa54ff53aU;
    e+=0x510e527fU;f+=0x9b05688cU;g+=0x1f83d9abU;h+=0x5be0cd19U;
    matched[id]=(a==target[0] && b==target[1] && c==target[2] && d==target[3] &&
                 e==target[4] && f==target[5] && g==target[6] && h==target[7]) ? 1U : 0U;
}
