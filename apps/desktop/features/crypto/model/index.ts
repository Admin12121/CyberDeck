/**
 * Crypto feature model layer.
 * Pure types, catalog and pipeline evaluation for the Recipes workspace.
 * Operations run deterministically over bytes; hashes and HMAC stay in the
 * native engine (Crypto Ops) and heavier formats move to Rust as they need
 * them (Master Plan §5.4).
 */

export type OperationCategory = "encoding" | "transforms" | "parsing" | "formatting";

export interface Operation {
  id: string;
  label: string;
  category: OperationCategory;
  description: string;
  /** Operations with an editable parameter show an inline input on the step. */
  takesParam?: boolean;
  paramLabel?: string;
  paramDefault?: string;
}

export interface RecipeStep {
  opId: string;
  enabled: boolean;
  param?: string;
}

export interface RecipeState {
  steps: RecipeStep[];
  input: string;
  autoBake: boolean;
}

export interface RecipeError {
  stepIndex: number;
  opId: string;
  message: string;
}

export interface RecipeResult {
  output: string;
  /** Raw bytes behind the output; powers the image preview and hex view. */
  outputBytes: Uint8Array;
  byteLength: number;
  elapsedMs: number;
  error?: RecipeError;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const OPERATIONS: Operation[] = [
  // encoding
  { id: "to_base64", label: "To Base64", category: "encoding", description: "Encode bytes to Base64" },
  { id: "from_base64", label: "From Base64", category: "encoding", description: "Decode Base64 to bytes" },
  { id: "to_base32", label: "To Base32", category: "encoding", description: "Encode bytes to Base32 (RFC 4648)" },
  { id: "from_base32", label: "From Base32", category: "encoding", description: "Decode Base32 to bytes" },
  { id: "to_hex", label: "To Hex", category: "encoding", description: "Encode bytes to hexadecimal" },
  { id: "from_hex", label: "From Hex", category: "encoding", description: "Decode hexadecimal to bytes" },
  { id: "to_binary", label: "To Binary", category: "encoding", description: "Encode bytes to spaced 8-bit binary" },
  { id: "from_binary", label: "From Binary", category: "encoding", description: "Decode 8-bit binary to bytes" },
  { id: "url_encode", label: "URL Encode", category: "encoding", description: "Percent-encode text" },
  { id: "url_decode", label: "URL Decode", category: "encoding", description: "Decode percent-encoding" },
  // transforms
  { id: "rot_n", label: "ROT-N", category: "transforms", description: "Caesar shift letters by N", takesParam: true, paramLabel: "N", paramDefault: "13" },
  { id: "rot13", label: "ROT13", category: "transforms", description: "Classical Caesar shift by 13" },
  { id: "xor", label: "XOR with key", category: "transforms", description: "Byte-wise XOR against a repeating key", takesParam: true, paramLabel: "key", paramDefault: "key" },
  { id: "reverse", label: "Reverse", category: "transforms", description: "Reverse byte order" },
  { id: "to_uppercase", label: "To Uppercase", category: "transforms", description: "Upper-case the text" },
  { id: "to_lowercase", label: "To Lowercase", category: "transforms", description: "Lower-case the text" },
  { id: "trim_lines", label: "Trim Lines", category: "transforms", description: "Strip whitespace around each line" },
  // parsing
  { id: "json_beautify", label: "JSON Beautify", category: "parsing", description: "Pretty-print JSON with 2-space indent" },
  { id: "json_minify", label: "JSON Minify", category: "parsing", description: "Strip JSON whitespace" },
  { id: "jwt_decode", label: "JWT Decode", category: "parsing", description: "Decode JWT header and payload to JSON" },
  { id: "extract_urls", label: "Extract URLs", category: "parsing", description: "Pull http(s) URLs out of the text, one per line" },
  { id: "extract_emails", label: "Extract Emails", category: "parsing", description: "Pull email addresses out of the text, one per line" },
  { id: "to_utf8", label: "To Text (UTF-8)", category: "parsing", description: "Interpret bytes as UTF-8 text" },
  // formatting
  { id: "hex_dump", label: "Hex Dump", category: "formatting", description: "Offset | hex | ASCII dump of the bytes", takesParam: true, paramLabel: "width", paramDefault: "16" },
  { id: "from_hexdump", label: "From Hex Dump", category: "formatting", description: "Parse a hex dump back to bytes" },
];

export function operationById(id: string): Operation | undefined {
  return OPERATIONS.find((op) => op.id === id);
}

// --- codecs -----------------------------------------------------------------

const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function b32Encode(bytes: Uint8Array): string {
  let out = "";
  let bits = 0;
  let value = 0;
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32_ALPHABET[(value << (5 - bits)) & 31];
  while (out.length % 8 !== 0) out += "=";
  return out;
}

function b32Decode(text: string): Uint8Array {
  const clean = text.toUpperCase().replace(/[=\s]/g, "");
  if (!/^[A-Z2-7]*$/.test(clean)) throw new Error("input is not valid Base32");
  const out: number[] = [];
  let bits = 0;
  let value = 0;
  for (const ch of clean) {
    value = (value << 5) | B32_ALPHABET.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

function base64UrlDecode(text: string): Uint8Array {
  let b64 = text.replace(/-/g, "+").replace(/_/g, "/").replace(/\s+/g, "");
  while (b64.length % 4 !== 0) b64 += "=";
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) throw new Error("input is not valid Base64URL");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function hexDumpText(bytes: Uint8Array, width: number): string {
  const w = Math.max(4, Math.min(64, width));
  const lines: string[] = [];
  for (let i = 0; i < bytes.length; i += w) {
    const slice = bytes.slice(i, i + w);
    const hex = Array.from(slice, (b) => b.toString(16).padStart(2, "0")).join(" ");
    const ascii = Array.from(slice, (b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".")).join("");
    lines.push(`${i.toString(16).padStart(8, "0")}  ${hex.padEnd(w * 3 - 1, " ")}  ${ascii}`);
  }
  return lines.join("\n");
}

function fromHexDump(text: string): Uint8Array {
  const out: number[] = [];
  for (const rawLine of text.split(/\r?\n/)) {
    let line = rawLine.trim();
    if (!line) continue;
    line = line.replace(/^(?:0x)?[0-9a-f]{2,16}[\s:]{1,4}/i, ""); // offset column
    const hexColumn = line.split(/\s{2,}/)[0]; // drop the ASCII column
    for (const match of hexColumn.matchAll(/\b[0-9a-fA-F]{2}\b/g)) {
      out.push(Number.parseInt(match[0], 16));
    }
  }
  return new Uint8Array(out);
}

/** Apply one operation. Throws with a user-facing message on bad input. */
function applyOperation(opId: string, input: Uint8Array, param: string | undefined): Uint8Array {
  const text = () => decoder.decode(input);
  switch (opId) {
    case "to_base64": {
      const chunks: string[] = [];
      const size = 0x8000;
      const bin = Array.from(input, (b) => String.fromCharCode(b)).join("");
      for (let i = 0; i < bin.length; i += size) chunks.push(bin.slice(i, i + size));
      return encoder.encode(btoa(chunks.join("")));
    }
    case "from_base64": {
      const b64 = text().replace(/\s+/g, "");
      if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) throw new Error("input is not valid Base64");
      const bin = atob(b64);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }
    case "to_base32":
      return encoder.encode(b32Encode(input));
    case "from_base32":
      return b32Decode(text());
    case "to_hex":
      return encoder.encode(Array.from(input, (b) => b.toString(16).padStart(2, "0")).join(""));
    case "from_hex": {
      const clean = text().replace(/[^0-9a-fA-F]/g, "");
      if (clean.length % 2 !== 0) throw new Error("hex input has an odd number of digits");
      const out = new Uint8Array(clean.length / 2);
      for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
      return out;
    }
    case "to_binary":
      return encoder.encode(Array.from(input, (b) => b.toString(2).padStart(8, "0")).join(" "));
    case "from_binary": {
      const clean = text().replace(/[^01]/g, "");
      if (clean.length % 8 !== 0) throw new Error("binary input length must be a multiple of 8");
      const out = new Uint8Array(clean.length / 8);
      for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(clean.slice(i * 8, i * 8 + 8), 2);
      return out;
    }
    case "url_encode":
      return encoder.encode(encodeURIComponent(text()));
    case "url_decode":
      return encoder.encode(decodeURIComponent(text().replace(/\+/g, "%20")));
    case "rot_n": {
      const n = (((Number.parseInt(param ?? "13", 10) || 13) % 26) + 26) % 26;
      return encoder.encode(
        text().replace(/[a-zA-Z]/g, (ch) => {
          const base = ch <= "Z" ? 65 : 97;
          return String.fromCharCode(((ch.charCodeAt(0) - base + n) % 26) + base);
        }),
      );
    }
    case "rot13":
      return encoder.encode(
        text().replace(/[a-zA-Z]/g, (ch) => {
          const base = ch <= "Z" ? 65 : 97;
          return String.fromCharCode(((ch.charCodeAt(0) - base + 13) % 26) + base);
        }),
      );
    case "xor": {
      const key = encoder.encode(param && param.length > 0 ? param : "key");
      return Uint8Array.from(input, (b, i) => b ^ key[i % key.length]);
    }
    case "reverse": {
      const out = input.slice();
      out.reverse();
      return out;
    }
    case "to_uppercase":
      return encoder.encode(text().toUpperCase());
    case "to_lowercase":
      return encoder.encode(text().toLowerCase());
    case "trim_lines":
      return encoder.encode(
        text()
          .split(/\r?\n/)
          .map((line) => line.trim())
          .join("\n"),
      );
    case "json_beautify": {
      const parsed = JSON.parse(text()) as unknown;
      return encoder.encode(JSON.stringify(parsed, null, 2));
    }
    case "json_minify":
      return encoder.encode(JSON.stringify(JSON.parse(text())));
    case "jwt_decode": {
      const parts = text().trim().split(".");
      if (parts.length < 2) throw new Error("JWT needs at least header.payload");
      const header = decoder.decode(base64UrlDecode(parts[0]));
      const payload = decoder.decode(base64UrlDecode(parts[1]));
      const pretty = (label: string, raw: string) => {
        try {
          return `// ${label}\n${JSON.stringify(JSON.parse(raw), null, 2)}`;
        } catch {
          return `// ${label}\n${raw}`;
        }
      };
      let out = `${pretty("header", header)}\n\n${pretty("payload", payload)}`;
      if (parts[2]) {
        out += `\n\n// signature (hex)\n${Array.from(base64UrlDecode(parts[2]), (b) => b.toString(16).padStart(2, "0")).join("")}`;
      }
      return encoder.encode(out);
    }
    case "extract_urls": {
      const matches = text().match(/https?:\/\/[^\s"'<>]+/g) ?? [];
      return encoder.encode(matches.join("\n"));
    }
    case "extract_emails": {
      const matches = text().match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g) ?? [];
      return encoder.encode(matches.join("\n"));
    }
    case "to_utf8":
      return input; // identity on bytes; normalization happens at render
    case "hex_dump": {
      const width = Number.parseInt(param ?? "16", 10) || 16;
      return encoder.encode(hexDumpText(input, width));
    }
    case "from_hexdump":
      return fromHexDump(text());
    default:
      throw new Error(`unknown operation: ${opId}`);
  }
}

/**
 * Evaluate a recipe sequentially. On the first failing step the error carries
 * the step index (Master Plan §5.4: error location per operation).
 */
export function runRecipe(input: string, steps: RecipeStep[]): RecipeResult {
  const started = performance.now();
  let bytes: Uint8Array = encoder.encode(input);
  for (let i = 0; i < steps.length; i++) {
    const step = steps[i];
    if (!step.enabled) continue;
    try {
      bytes = applyOperation(step.opId, bytes, step.param);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        output: "",
        outputBytes: new Uint8Array(),
        byteLength: bytes.length,
        elapsedMs: performance.now() - started,
        error: { stepIndex: i, opId: step.opId, message },
      };
    }
  }
  return {
    output: decoder.decode(bytes),
    outputBytes: bytes,
    byteLength: bytes.length,
    elapsedMs: performance.now() - started,
  };
}

/** Detect an image format from magic bytes; powers the output preview. */
export function detectImageMime(bytes: Uint8Array): string | null {
  if (bytes.length < 12) return null;
  if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) return "image/png";
  if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) return "image/jpeg";
  if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46) return "image/gif";
  if (bytes[0] === 0x42 && bytes[1] === 0x4d) return "image/bmp";
  if (
    bytes[0] === 0x52 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x46 &&
    bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50
  ) {
    return "image/webp";
  }
  return null;
}
