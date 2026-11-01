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
  { id: "to_base64url", label: "To Base64URL", category: "encoding", description: "Encode bytes to URL-safe Base64" },
  { id: "from_base64url", label: "From Base64URL", category: "encoding", description: "Decode URL-safe Base64 to bytes" },
  { id: "to_base32", label: "To Base32", category: "encoding", description: "Encode bytes to Base32 (RFC 4648)" },
  { id: "from_base32", label: "From Base32", category: "encoding", description: "Decode Base32 to bytes" },
  { id: "to_hex", label: "To Hex", category: "encoding", description: "Encode bytes to hexadecimal" },
  { id: "from_hex", label: "From Hex", category: "encoding", description: "Decode hexadecimal to bytes" },
  { id: "to_binary", label: "To Binary", category: "encoding", description: "Encode bytes to spaced 8-bit binary" },
  { id: "from_binary", label: "From Binary", category: "encoding", description: "Decode 8-bit binary to bytes" },
  { id: "to_decimal", label: "To Decimal", category: "encoding", description: "Bytes as space-separated decimal values" },
  { id: "from_decimal", label: "From Decimal", category: "encoding", description: "Decimal values to bytes" },
  { id: "to_charcode", label: "To Charcode", category: "encoding", description: "Characters as decimal codepoints" },
  { id: "from_charcode", label: "From Charcode", category: "encoding", description: "Decimal codepoints to characters" },
  { id: "url_encode", label: "URL Encode", category: "encoding", description: "Percent-encode text" },
  { id: "url_decode", label: "URL Decode", category: "encoding", description: "Decode percent-encoding" },
  { id: "html_encode", label: "HTML Entity Encode", category: "encoding", description: "Escape HTML special characters" },
  { id: "html_decode", label: "HTML Entity Decode", category: "encoding", description: "Resolve HTML entities to characters" },
  // transforms
  { id: "rot_n", label: "ROT-N", category: "transforms", description: "Caesar shift letters by N", takesParam: true, paramLabel: "N", paramDefault: "13" },
  { id: "rot13", label: "ROT13", category: "transforms", description: "Classical Caesar shift by 13" },
  { id: "rot47", label: "ROT47", category: "transforms", description: "Rotate ASCII 33-126 by 47" },
  { id: "atbash", label: "Atbash", category: "transforms", description: "Mirror the alphabet (A↔Z)" },
  { id: "vigenere", label: "Vigenère Decode", category: "transforms", description: "Vigenère decode with a key", takesParam: true, paramLabel: "key", paramDefault: "key" },
  { id: "xor", label: "XOR with key", category: "transforms", description: "Byte-wise XOR against a repeating key", takesParam: true, paramLabel: "key", paramDefault: "key" },
  { id: "swap_endianness", label: "Swap Endianness", category: "transforms", description: "Reverse word order, format 16 or 32", takesParam: true, paramLabel: "bits", paramDefault: "16" },
  { id: "rotate_bytes", label: "Rotate Bytes", category: "transforms", description: "Rotate the buffer by N bytes", takesParam: true, paramLabel: "N", paramDefault: "1" },
  { id: "reverse", label: "Reverse", category: "transforms", description: "Reverse byte order" },
  { id: "bit_shift_left", label: "Bit Shift Left", category: "transforms", description: "Shift every byte left, dropping high bits", takesParam: true, paramLabel: "bits", paramDefault: "1" },
  { id: "bit_shift_right", label: "Bit Shift Right", category: "transforms", description: "Shift every byte right, dropping low bits", takesParam: true, paramLabel: "bits", paramDefault: "1" },
  { id: "to_uppercase", label: "To Uppercase", category: "transforms", description: "Upper-case the text" },
  { id: "to_lowercase", label: "To Lowercase", category: "transforms", description: "Lower-case the text" },
  { id: "normalize_unicode", label: "Normalize Unicode", category: "transforms", description: "Apply NFKC normalization" },
  { id: "trim_lines", label: "Trim Lines", category: "transforms", description: "Strip whitespace around each line" },
  { id: "sort_lines", label: "Sort Lines", category: "transforms", description: "Sort lines alphabetically" },
  { id: "unique_lines", label: "Unique Lines", category: "transforms", description: "Drop duplicate lines, keeping order" },
  { id: "reverse_lines", label: "Reverse Lines", category: "transforms", description: "Reverse the order of lines" },
  { id: "add_line_numbers", label: "Add Line Numbers", category: "transforms", description: "Prefix every line with its number" },
  { id: "filter_lines", label: "Filter Lines", category: "transforms", description: "Keep lines containing the text", takesParam: true, paramLabel: "contains", paramDefault: "" },
  { id: "find_replace", label: "Find / Replace", category: "transforms", description: "Replace text, format find:replace", takesParam: true, paramLabel: "find:repl", paramDefault: ":" },
  { id: "head_lines", label: "Head Lines", category: "transforms", description: "Keep the first N lines", takesParam: true, paramLabel: "N", paramDefault: "10" },
  { id: "tail_lines", label: "Tail Lines", category: "transforms", description: "Keep the last N lines", takesParam: true, paramLabel: "N", paramDefault: "10" },
  { id: "text_split", label: "Split To Lines", category: "transforms", description: "Split text on a delimiter", takesParam: true, paramLabel: "delimiter", paramDefault: "," },
  { id: "defang", label: "Defang IOCs", category: "transforms", description: "Defang URLs, IPs and emails for safe sharing" },
  { id: "refang", label: "Refang IOCs", category: "transforms", description: "Restore defanged URLs, IPs and emails" },
  { id: "strip_html_tags", label: "Strip HTML Tags", category: "transforms", description: "Remove HTML tags from the text" },
  // parsing
  { id: "json_beautify", label: "JSON Beautify", category: "parsing", description: "Pretty-print JSON with 2-space indent" },
  { id: "json_minify", label: "JSON Minify", category: "parsing", description: "Strip JSON whitespace" },
  { id: "jwt_decode", label: "JWT Decode", category: "parsing", description: "Decode JWT header and payload to JSON" },
  { id: "extract_urls", label: "Extract URLs", category: "parsing", description: "Pull http(s) URLs out of the text, one per line" },
  { id: "extract_emails", label: "Extract Emails", category: "parsing", description: "Pull email addresses out of the text, one per line" },
  { id: "extract_domains", label: "Extract Domains", category: "parsing", description: "Pull domain names out of the text, one per line" },
  { id: "extract_ips", label: "Extract IP Addresses", category: "parsing", description: "Pull IPv4 addresses out of the text, one per line" },
  { id: "escape_string", label: "Escape String", category: "parsing", description: "Backslash-escape control chars and quotes" },
  { id: "unescape_string", label: "Unescape String", category: "parsing", description: "Resolve backslash escape sequences" },
  { id: "nato_encode", label: "NATO Alphabet", category: "parsing", description: "Spell the text in NATO phonetic alphabet" },
  { id: "unix_to_datetime", label: "Unix To DateTime", category: "parsing", description: "Unix timestamp (s or ms) to ISO 8601" },
  { id: "datetime_to_unix", label: "DateTime To Unix", category: "parsing", description: "Parse a date string to Unix seconds", takesParam: true, paramLabel: "unit", paramDefault: "s" },
  { id: "morse_encode", label: "Morse Encode", category: "parsing", description: "Text to Morse code, words separated by /" },
  { id: "morse_decode", label: "Morse Decode", category: "parsing", description: "Morse code back to text" },
  { id: "to_utf8", label: "To Text (UTF-8)", category: "parsing", description: "Interpret bytes as UTF-8 text" },
  // formatting
  { id: "hex_dump", label: "Hex Dump", category: "formatting", description: "Offset | hex | ASCII dump of the bytes", takesParam: true, paramLabel: "width", paramDefault: "16" },
  { id: "from_hexdump", label: "From Hex Dump", category: "formatting", description: "Parse a hex dump back to bytes" },
  { id: "slice_bytes", label: "Slice Bytes", category: "formatting", description: "Keep a byte range, format start,end", takesParam: true, paramLabel: "start,end", paramDefault: "0,64" },
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

const HTML_NAMED: Record<string, string> = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", copy: "©", reg: "®", hellip: "…", mdash: "-", ndash: "-",
};

function htmlDecode(text: string): string {
  return text
    .replace(/&#x([0-9a-fA-F]+);/g, (_, hex) => String.fromCodePoint(Number.parseInt(hex, 16)))
    .replace(/&#(\d+);/g, (_, dec) => String.fromCodePoint(Number.parseInt(dec, 10)))
    .replace(/&([a-z]+);/gi, (raw, name: string) => HTML_NAMED[name.toLowerCase()] ?? raw);
}

const MORSE: Record<string, string> = {
  a: ".-", b: "-...", c: "-.-.", d: "-..", e: ".", f: "..-.", g: "--.", h: "....", i: "..", j: ".---",
  k: "-.-", l: ".-..", m: "--", n: "-.", o: "---", p: ".--.", q: "--.-", r: ".-.", s: "...", t: "-",
  u: "..-", v: "...-", w: ".--", x: "-..-", y: "-.--", z: "--..",
  "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-", "5": ".....",
  "6": "-....", "7": "--...", "8": "---..", "9": "----.",
  ".": ".-.-.-", ",": "--..--", "?": "..--..", "!": "-.-.--", "/": "-..-.", "@": ".--.-.", "=": "-...-",
};
const MORSE_REVERSE: Record<string, string> = Object.fromEntries(Object.entries(MORSE).map(([k, v]) => [v, k]));

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
    case "to_decimal":
      return encoder.encode(Array.from(input, (b) => b.toString(10)).join(" "));
    case "from_decimal": {
      const parts = text().trim().split(/[^0-9]+/).filter((p) => p.length > 0);
      const out = new Uint8Array(parts.length);
      for (let i = 0; i < parts.length; i++) {
        const value = Number.parseInt(parts[i], 10);
        if (Number.isNaN(value) || value > 255) throw new Error(`decimal value out of byte range at position ${i}`);
        out[i] = value;
      }
      return out;
    }
    case "to_charcode":
      return encoder.encode(Array.from(text(), (ch) => ch.codePointAt(0) ?? 0).join(" "));
    case "from_charcode": {
      const codes = text().trim().split(/[^0-9]+/).filter((p) => p.length > 0).map((p) => Number.parseInt(p, 10));
      if (codes.some((c) => Number.isNaN(c) || c < 0 || c > 0x10ffff)) throw new Error("invalid codepoint list");
      return encoder.encode(String.fromCodePoint(...codes));
    }
    case "html_encode":
      return encoder.encode(
        text().replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch] ?? ch),
      );
    case "html_decode":
      return encoder.encode(htmlDecode(text()));
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
    case "rot47":
      return encoder.encode(
        Array.from(text())
          .map((ch) => {
            const code = ch.charCodeAt(0);
            return code >= 33 && code <= 126 ? String.fromCharCode(33 + ((code - 33 + 47) % 94)) : ch;
          })
          .join(""),
      );
    case "atbash":
      return encoder.encode(
        text().replace(/[a-zA-Z]/g, (ch) => {
          const base = ch <= "Z" ? 65 : 97;
          return String.fromCharCode(base + 25 - (ch.charCodeAt(0) - base));
        }),
      );
    case "vigenere": {
      const key = (param && param.replace(/[^a-zA-Z]/g, "").toLowerCase()) || "key";
      if (key.length === 0) throw new Error("vigenere key needs letters");
      let keyIndex = 0;
      return encoder.encode(
        text().replace(/[a-zA-Z]/g, (ch) => {
          const base = ch <= "Z" ? 65 : 97;
          const shift = key.charCodeAt(keyIndex++ % key.length) - 97;
          return String.fromCharCode(((ch.charCodeAt(0) - base - shift + 26) % 26) + base);
        }),
      );
    }
    case "xor": {
      const key = encoder.encode(param && param.length > 0 ? param : "key");
      return Uint8Array.from(input, (b, i) => b ^ key[i % key.length]);
    }
    case "reverse": {
      const out = input.slice();
      out.reverse();
      return out;
    }
    case "swap_endianness": {
      const bits = Number.parseInt(param ?? "16", 10) === 32 ? 4 : 2;
      if (input.length % bits !== 0) throw new Error(`byte count must be a multiple of ${bits} for ${bits * 8}-bit swap`);
      const out = input.slice();
      for (let i = 0; i < out.length; i += bits) {
        for (let j = 0; j < bits / 2; j++) {
          const a = i + j;
          const b = i + bits - 1 - j;
          [out[a], out[b]] = [out[b], out[a]];
        }
      }
      return out;
    }
    case "rotate_bytes": {
      const n = ((Number.parseInt(param ?? "1", 10) || 1) % Math.max(1, input.length) + input.length) % Math.max(1, input.length);
      if (input.length === 0) return input;
      return Uint8Array.from([...input.slice(n), ...input.slice(0, n)]);
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
    case "sort_lines":
      return encoder.encode(text().split(/\r?\n/).sort((a, b) => a.localeCompare(b)).join("\n"));
    case "unique_lines": {
      const seen = new Set<string>();
      const lines = text().split(/\r?\n/).filter((line) => {
        if (seen.has(line)) return false;
        seen.add(line);
        return true;
      });
      return encoder.encode(lines.join("\n"));
    }
    case "reverse_lines":
      return encoder.encode(text().split(/\r?\n/).reverse().join("\n"));
    case "add_line_numbers": {
      const lines = text().split(/\r?\n/);
      const width = String(lines.length).length;
      return encoder.encode(lines.map((line, i) => `${String(i + 1).padStart(width, " ")} ${line}`).join("\n"));
    }
    case "filter_lines": {
      const needle = (param ?? "").toLowerCase();
      const lines = text().split(/\r?\n/).filter((line) => line.toLowerCase().includes(needle));
      return encoder.encode(lines.join("\n"));
    }
    case "find_replace": {
      const sep = (param ?? ":").indexOf(":");
      if (sep === -1) throw new Error("parameter needs find:replace format");
      const find = param!.slice(0, sep);
      const replace = param!.slice(sep + 1);
      if (find.length === 0) throw new Error("find text must not be empty");
      return encoder.encode(text().split(find).join(replace));
    }
    case "defang":
      return encoder.encode(
        text().replace(/\./g, "[.]").replace(/@/g, "[@]").replace(/https?:\/\//gi, (m) => (m.startsWith("https") ? "hXXps://" : "hXXp://")),
      );
    case "refang":
      return encoder.encode(
        text().replace(/\[\.\]/g, ".").replace(/\[@\]/g, "@").replace(/\(\.\)/g, ".").replace(/h(?:X|\*){2}ps?:\/\//gi, (m) => (m.toLowerCase().includes("s") ? "https://" : "http://")),
      );
    case "strip_html_tags":
      return encoder.encode(text().replace(/<[^>]*>/g, ""));
    case "normalize_unicode":
      return encoder.encode(text().normalize("NFKC"));
    case "head_lines": {
      const n = Math.max(0, Number.parseInt(param ?? "10", 10) || 10);
      return encoder.encode(text().split(/\r?\n/).slice(0, n).join("\n"));
    }
    case "tail_lines": {
      const n = Math.max(0, Number.parseInt(param ?? "10", 10) || 10);
      const lines = text().split(/\r?\n/);
      return encoder.encode(lines.slice(Math.max(0, lines.length - n)).join("\n"));
    }
    case "text_split": {
      const delimiter = param && param.length > 0 ? param : ",";
      return encoder.encode(text().split(delimiter).join("\n"));
    }
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
    case "extract_domains": {
      const matches = text().match(/\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b/gi) ?? [];
      return encoder.encode(matches.join("\n"));
    }
    case "extract_ips": {
      const matches = text().match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g) ?? [];
      return encoder.encode(matches.join("\n"));
    }
    case "escape_string":
      return encoder.encode(
        text()
          .replace(/\\/g, "\\\\")
          .replace(/"/g, '\\"')
          .replace(/\n/g, "\\n")
          .replace(/\r/g, "\\r")
          .replace(/\t/g, "\\t"),
      );
    case "unescape_string": {
      const parsed = JSON.parse(`"${text().replace(/\n/g, "\\n").replace(/\r/g, "\\r").replace(/"/g, '\\"')}"`) as string;
      return encoder.encode(parsed);
    }
    case "nato_encode": {
      const NATO: Record<string, string> = {
        a: "Alfa", b: "Bravo", c: "Charlie", d: "Delta", e: "Echo", f: "Foxtrot", g: "Golf", h: "Hotel",
        i: "India", j: "Juliett", k: "Kilo", l: "Lima", m: "Mike", n: "November", o: "Oscar", p: "Papa",
        q: "Quebec", r: "Romeo", s: "Sierra", t: "Tango", u: "Uniform", v: "Victor", w: "Whiskey",
        x: "X-ray", y: "Yankee", z: "Zulu",
        "0": "Zero", "1": "One", "2": "Two", "3": "Three", "4": "Four",
        "5": "Five", "6": "Six", "7": "Seven", "8": "Eight", "9": "Nine",
      };
      return encoder.encode(
        Array.from(text().toLowerCase())
          .map((ch) => NATO[ch] ?? (ch === " " ? "\n" : ch))
          .join(" "),
      );
    }
    case "to_utf8":
      return input; // identity on bytes; normalization happens at render
    case "unix_to_datetime": {
      const raw = text().trim();
      if (!/^-?\d+$/.test(raw)) throw new Error("input must be an integer Unix timestamp");
      const value = Number.parseInt(raw, 10);
      const date = new Date(raw.length >= 13 ? value : value * 1000);
      if (Number.isNaN(date.getTime())) throw new Error("timestamp out of range");
      return encoder.encode(`${date.toISOString()} (${raw.length >= 13 ? "ms" : "s"} input)`);
    }
    case "datetime_to_unix": {
      const parsed = Date.parse(text().trim());
      if (Number.isNaN(parsed)) throw new Error("unrecognized date; use ISO 8601 like 2026-10-31T12:00:00Z");
      return encoder.encode(param === "ms" ? String(parsed) : String(Math.floor(parsed / 1000)));
    }
    case "morse_encode": {
      const words = text().trim().toLowerCase().split(/\s+/);
      const encoded = words
        .filter((w) => w.length > 0)
        .map((word) =>
          Array.from(word)
            .map((ch) => {
              if (ch === " ") return "/";
              const code = MORSE[ch];
              if (!code) throw new Error(`no Morse mapping for "${ch}"`);
              return code;
            })
            .join(" "),
        );
      return encoder.encode(encoded.join(" / "));
    }
    case "morse_decode": {
      const words = text().trim().split(/\s*\/\s*/);
      const decoded = words
        .map((word) =>
          word
            .trim()
            .split(/\s+/)
            .filter((t) => t.length > 0)
            .map((token) => {
              const ch = MORSE_REVERSE[token];
              if (!ch) throw new Error(`unknown Morse token "${token}"`);
              return ch;
            })
            .join(""),
        )
        .join(" ");
      return encoder.encode(decoded);
    }
    case "hex_dump": {
      const width = Number.parseInt(param ?? "16", 10) || 16;
      return encoder.encode(hexDumpText(input, width));
    }
    case "from_hexdump":
      return fromHexDump(text());
    case "slice_bytes": {
      const [startRaw, endRaw] = (param ?? "0,64").split(",").map((p) => Number.parseInt(p.trim(), 10));
      const start = Math.max(0, Number.isNaN(startRaw) ? 0 : startRaw);
      const end = Math.min(input.length, Number.isNaN(endRaw) ? input.length : endRaw);
      if (end < start) throw new Error("slice end must not be before start");
      return input.slice(start, end);
    }
    case "bit_shift_left": {
      const bits = Math.max(0, Math.min(7, Number.parseInt(param ?? "1", 10) || 1));
      return Uint8Array.from(input, (b) => (b << bits) & 0xff);
    }
    case "bit_shift_right": {
      const bits = Math.max(0, Math.min(7, Number.parseInt(param ?? "1", 10) || 1));
      return Uint8Array.from(input, (b) => b >> bits);
    }
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

// --- magic auto-decode (CyberChef-style) --------------------------------------

export interface MagicDetection {
  opId: string;
  param?: string;
  reason: string;
}

/**
 * Identify the most likely encoding of the input and the operation that
 * decodes it. Claims stay conservative: a Base64 shape only counts when it
 * decodes to mostly printable bytes.
 */
export function detectEncoding(text: string): MagicDetection | null {
  const t = text.trim();
  if (!t || t.length < 4) return null;

  // JWT: three dot-separated base64url segments
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(t) && !t.includes(" ")) {
    return { opId: "jwt_decode", reason: "JWT structure (dot-separated base64url segments)" };
  }

  // percent-encoding
  if (/%[0-9a-fA-F]{2}/.test(t)) {
    try {
      const decoded = decodeURIComponent(t.replace(/\+/g, "%20"));
      if (decoded !== t) return { opId: "url_decode", reason: "percent-escapes present" };
    } catch {
      // malformed escapes; fall through
    }
  }

  // decimal byte list or binary (digits and whitespace only)
  if (/^[\s0-9]+$/.test(t)) {
    const nums = t.trim().split(/\s+/).map(Number);
    if (nums.length >= 2 && nums.every((n) => Number.isInteger(n) && n >= 0 && n <= 255)) {
      return { opId: "from_decimal", reason: "space-separated byte decimals" };
    }
    if (t.replace(/\s/g, "").length % 8 === 0) {
      return { opId: "from_binary", reason: "binary digits, multiple of 8" };
    }
  }

  // hexadecimal
  if (/^[0-9a-fA-F\s]+$/.test(t)) {
    const digits = t.replace(/\s/g, "");
    if (digits.length >= 2 && digits.length % 2 === 0) {
      return { opId: "from_hex", reason: "hexadecimal digits, even count" };
    }
  }

  // Base32
  if (/^[A-Z2-7=\s]+$/i.test(t)) {
    const clean = t.replace(/[=\s]/g, "");
    if (clean.length >= 8 && clean.length % 8 === 0) {
      return { opId: "from_base32", reason: "Base32 alphabet, valid block length" };
    }
  }

  // Base64 / Base64URL: shape plus a printable decode result
  const b64 = t.replace(/\s+/g, "");
  if (/^[A-Za-z0-9+/_-]+={0,2}$/.test(b64) && b64.length >= 8 && b64.length % 4 === 0) {
    try {
      const bin = atob(b64.replace(/-/g, "+").replace(/_/g, "/"));
      let printable = 0;
      for (const ch of bin) {
        const code = ch.charCodeAt(0);
        if ((code >= 9 && code <= 13) || (code >= 32 && code <= 126)) printable++;
      }
      if (printable / bin.length > 0.85) {
        return { opId: "from_base64", reason: "Base64 shape decoding to printable bytes" };
      }
    } catch {
      // not decodable; fall through
    }
  }

  // JSON document
  if (/^[[{]/.test(t)) {
    try {
      JSON.parse(t);
      return { opId: "json_beautify", reason: "valid JSON document" };
    } catch {
      // not JSON
    }
  }

  // HTML entities
  if (/&(?:amp|lt|gt|quot|apos|nbsp|#x?[0-9a-f]+);/i.test(t)) {
    return { opId: "html_decode", reason: "HTML entities present" };
  }

  return null;
}

/**
 * Build a multi-layer decode recipe: repeatedly detect the outermost encoding
 * and prepend its decoder, up to maxDepth layers.
 */
export function magicRecipe(input: string, maxDepth = 4): { steps: RecipeStep[]; path: string[] } {
  const steps: RecipeStep[] = [];
  const path: string[] = [];
  let current = input;
  for (let i = 0; i < maxDepth; i++) {
    const detection = detectEncoding(current);
    if (!detection) break;
    // avoid loops: the same decoder twice in a row only makes sense for hex
    const previous = steps[steps.length - 1]?.opId;
    if (previous === detection.opId && detection.opId !== "from_hex") break;
    const probe = runRecipe(current, [{ opId: detection.opId, enabled: true, param: detection.param }]);
    if (probe.error) break;
    steps.push({ opId: detection.opId, enabled: true, param: detection.param });
    path.push(detection.reason);
    current = probe.output;
  }
  return { steps, path };
}
