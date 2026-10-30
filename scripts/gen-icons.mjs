// Generates placeholder app icons (no external deps) for the Tauri bundle.
// Design: Dark Matter — near-black surface, blue analysis glyph, orange accent.
import { deflateSync, crc32 } from "node:zlib";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const outDir = join(root, "apps", "desktop", "src-tauri", "icons");
mkdirSync(outDir, { recursive: true });

const BG = [0x0d, 0x0d, 0x0e, 0xff];
const EDGE = [0x3b, 0x3b, 0x44, 0xff];
const BLUE = [0x3f, 0xc1, 0xff, 0xff];
const ORANGE = [0xff, 0x7b, 0x00, 0xff];

/** Paint an RGBA buffer of size×size with the placeholder mark. */
function paint(size) {
  const px = Buffer.alloc(size * size * 4);
  const put = (x, y, [r, g, b, a]) => {
    const i = (y * size + x) * 4;
    px[i] = r; px[i + 1] = g; px[i + 2] = b; px[i + 3] = a;
  };
  // background with 1px edge frame
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const edge = x === 0 || y === 0 || x === size - 1 || y === size - 1;
      put(x, y, edge ? EDGE : BG);
    }
  }
  // central blue square (analysis) with orange corner (active operation)
  const s = Math.max(4, Math.round(size * 0.34));
  const cx0 = Math.round(size / 2 - s / 2);
  const cy0 = Math.round(size / 2 - s / 2);
  const accent = Math.max(2, Math.round(s * 0.34));
  for (let y = 0; y < s; y++) {
    for (let x = 0; x < s; x++) {
      const inAccent = x >= s - accent && y < accent;
      put(cx0 + x, cy0 + y, inAccent ? ORANGE : BLUE);
    }
  }
  return px;
}

function pngChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const t = Buffer.from(type, "ascii");
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([t, data])) >>> 0);
  return Buffer.concat([len, t, data, crc]);
}

function encodePng(size, rgba) {
  const sig = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;  // bit depth
  ihdr[9] = 6;  // color type RGBA
  const stride = size * 4 + 1; // +1 filter byte per scanline
  const raw = Buffer.alloc(stride * size);
  for (let y = 0; y < size; y++) {
    raw[y * stride] = 0;
    rgba.copy(raw, y * stride + 1, y * size * 4, (y + 1) * size * 4);
  }
  return Buffer.concat([
    sig,
    pngChunk("IHDR", ihdr),
    pngChunk("IDAT", deflateSync(raw, { level: 9 })),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
}

/** 32bpp BMP-icon (BITMAPINFOHEADER + BGRA XOR + AND mask) for winres. */
function encodeIco32(rgba) {
  const size = 32;
  const xorSize = size * size * 4;       // BGRA pixels
  const andSize = size * Math.ceil(size / 8) * 1; // 1bit mask, row-padded to 32 bits
  const andStride = size % 32 === 0 ? size / 8 : Math.ceil(size / 32) * 4;
  const andRowBytes = andStride;
  const dataSize = 40 + xorSize + andRowBytes * size;
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0);   // reserved
  header.writeUInt16LE(1, 2);   // type icon
  header.writeUInt16LE(1, 4);   // count
  const entry = Buffer.alloc(16);
  entry[0] = size;              // width
  entry[1] = size;              // height
  entry[2] = 0;                 // palette
  entry[3] = 0;                 // reserved
  entry.writeUInt16LE(1, 4);    // planes
  entry.writeUInt16LE(32, 6);   // bpp
  entry.writeUInt32LE(dataSize, 8);
  entry.writeUInt32LE(22, 12);  // data offset (6 + 16)
  const bmp = Buffer.alloc(40);
  bmp.writeUInt32LE(40, 0);          // biSize
  bmp.writeInt32LE(size, 4);         // biWidth
  bmp.writeInt32LE(size * 2, 8);     // biHeight (XOR + AND)
  bmp.writeUInt16LE(1, 12);          // biPlanes
  bmp.writeUInt16LE(32, 14);         // biBitCount
  bmp.writeUInt32LE(0, 16);          // biCompression = BI_RGB
  bmp.writeUInt32LE(xorSize + andRowBytes * size, 20); // biSizeImage
  const xor = Buffer.alloc(xorSize);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const src = (y * size + x) * 4;
      const dst = ((size - 1 - y) * size + x) * 4; // bottom-up
      xor[dst] = rgba[src + 2];     // B
      xor[dst + 1] = rgba[src + 1]; // G
      xor[dst + 2] = rgba[src];     // R
      xor[dst + 3] = rgba[src + 3]; // A
    }
  }
  const and = Buffer.alloc(andRowBytes * size, 0xff); // opaque = 0 bits
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const alpha = rgba[(y * size + x) * 4 + 3];
      if (alpha < 128) {
        const row = size - 1 - y;
        and[row * andRowBytes + (x >> 3)] &= ~(0x80 >> (x & 7));
      }
    }
  }
  return Buffer.concat([header, entry, bmp, xor, and]);
}

for (const size of [32, 128, 256, 512]) {
  const png = encodePng(size, paint(size));
  const name = size <= 256 ? `${size}x${size}.png` : "icon.png";
  writeFileSync(join(outDir, name), png);
  console.log(`wrote ${name}`);
}
writeFileSync(join(outDir, "icon.ico"), encodeIco32(paint(32)));
console.log("wrote icon.ico");
