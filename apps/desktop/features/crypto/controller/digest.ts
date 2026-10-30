/**
 * Crypto feature — digest controller action.
 * Runs real hashing through the platform WebCrypto in the webview; native Rust
 * hashing with streaming/large-input support lands in arc 2 (Master Plan §5.4).
 */

export type DigestAlgorithm = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";

export async function digestText(algorithm: DigestAlgorithm, text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const buffer = await crypto.subtle.digest(algorithm, data);
  return Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, "0")).join("");
}
