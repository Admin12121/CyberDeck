import type { OpResult } from "@lib/ipc";

/** CRC32 is native ASCII-hex output. All other unkeyed catalog hashes return
 * raw digest bytes represented in OpResult.output_hex. */
export function verifyDigestOutput(
  algorithm: string,
  expectedHex: string,
  output: Pick<OpResult, "output_b64" | "output_hex">,
): boolean {
  const actualHex = algorithm === "crc32"
    ? atob(output.output_b64)
    : output.output_hex;
  return actualHex.toLowerCase() === expectedHex.toLowerCase();
}
