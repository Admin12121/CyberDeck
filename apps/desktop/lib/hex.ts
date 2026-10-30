/** Shared byte formatting for packet bytes, forensic hex and output panes. */

export function toHex(bytes: Uint8Array, separator = ""): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join(separator);
}

export function fromHex(text: string): Uint8Array {
  const clean = text.replace(/[^0-9a-fA-F]/g, "");
  if (clean.length % 2 !== 0) throw new Error("hex input has an odd number of digits");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error(`invalid hex byte at offset ${i * 2}`);
    out[i] = byte;
  }
  return out;
}

export interface HexRow {
  offset: number;
  hex: string;
  ascii: string;
}

export function hexDump(bytes: Uint8Array, bytesPerRow = 16): HexRow[] {
  const rows: HexRow[] = [];
  for (let i = 0; i < bytes.length; i += bytesPerRow) {
    const slice = bytes.slice(i, i + bytesPerRow);
    const hex = Array.from(slice, (b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = Array.from(slice, (b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".")).join("");
    rows.push({ offset: i, hex: hex.padEnd(bytesPerRow * 3 - 1, " "), ascii });
  }
  return rows;
}
