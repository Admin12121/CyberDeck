/**
 * Forensics feature controller layer.
 * Real string extraction and Shannon entropy over bytes. These run in the
 * webview for arc 1 sample sizes; the same contracts move to Rust streaming
 * workers for large evidence (§12: heavy parsing off the UI thread).
 */

export interface StringHit {
  offset: number;
  text: string;
}

/** Extract printable ASCII runs of at least `minLength` bytes. */
export function extractStrings(bytes: Uint8Array, minLength = 4): StringHit[] {
  const hits: StringHit[] = [];
  let start = -1;
  for (let i = 0; i <= bytes.length; i++) {
    const printable = i < bytes.length && bytes[i] >= 0x20 && bytes[i] <= 0x7e;
    if (printable && start === -1) start = i;
    if (!printable && start !== -1) {
      if (i - start >= minLength) {
        hits.push({ offset: start, text: String.fromCharCode(...bytes.slice(start, i)) });
      }
      start = -1;
    }
  }
  return hits;
}

/** Shannon entropy in bits/byte (0–8). */
export function shannonEntropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;
  const counts = new Array<number>(256).fill(0);
  for (const b of bytes) counts[b]++;
  let entropy = 0;
  for (const count of counts) {
    if (count === 0) continue;
    const p = count / bytes.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function formatEntropy(value: number): string {
  return `${value.toFixed(2)} bits/byte`;
}
