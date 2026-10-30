// Generates the app icon set from the project logo (logo.webp) using sharp.
// Outputs: Tauri bundle icons, Windows .ico, and the Next.js favicon.
import { deflateSync, crc32 } from "node:zlib";
import { writeFileSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import sharp from "sharp";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const logoPath = join(root, "logo.webp");
const tauriIconsDir = join(root, "apps", "desktop", "src-tauri", "icons");
const appDir = join(root, "apps", "desktop", "app");
mkdirSync(tauriIconsDir, { recursive: true });

/** Wrap raw RGBA pixels (32x32) in a maximally compatible ICO container. */
function encodeIco32(rgba) {
  const size = 32;
  const xorSize = size * size * 4;
  const andRowBytes = size / 8; // 32px rows are already 4-byte aligned
  const dataSize = 40 + xorSize + andRowBytes * size;
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(1, 4);
  const entry = Buffer.alloc(16);
  entry[0] = size;
  entry[1] = size;
  entry[2] = 0;
  entry[3] = 0;
  entry.writeUInt16LE(1, 4);
  entry.writeUInt16LE(32, 6);
  entry.writeUInt32LE(dataSize, 8);
  entry.writeUInt32LE(22, 12);
  const bmp = Buffer.alloc(40);
  bmp.writeUInt32LE(40, 0);
  bmp.writeInt32LE(size, 4);
  bmp.writeInt32LE(size * 2, 8);
  bmp.writeUInt16LE(1, 12);
  bmp.writeUInt16LE(32, 14);
  bmp.writeUInt32LE(0, 16);
  bmp.writeUInt32LE(xorSize + andRowBytes * size, 20);
  const xor = Buffer.alloc(xorSize);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const src = (y * size + x) * 4;
      const dst = ((size - 1 - y) * size + x) * 4;
      xor[dst] = rgba[src + 2];
      xor[dst + 1] = rgba[src + 1];
      xor[dst + 2] = rgba[src];
      xor[dst + 3] = rgba[src + 3];
    }
  }
  const and = Buffer.alloc(andRowBytes * size, 0x00); // alpha channel carries opacity
  return Buffer.concat([header, entry, bmp, xor, and]);
}

async function png(size) {
  return sharp(logoPath).resize(size, size, { fit: "cover" }).png().toBuffer();
}

async function main() {
  const iconPng = await sharp(logoPath).resize(64, 64, { fit: "cover" }).png().toBuffer();
  writeFileSync(join(appDir, "icon.png"), iconPng);
  console.log("wrote app/icon.png (favicon)");

  for (const size of [32, 128, 256]) {
    writeFileSync(join(tauriIconsDir, `${size}x${size}.png`), await png(size));
    console.log(`wrote ${size}x${size}.png`);
  }
  writeFileSync(join(tauriIconsDir, "icon.png"), await png(512));
  console.log("wrote icon.png (512)");

  const raw32 = await sharp(logoPath).resize(32, 32, { fit: "cover" }).ensureAlpha().raw().toBuffer();
  writeFileSync(join(tauriIconsDir, "icon.ico"), encodeIco32(new Uint8Array(raw32)));
  console.log("wrote icon.ico");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
