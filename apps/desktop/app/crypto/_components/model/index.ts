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
  { id: "to_base45", label: "To Base45", category: "encoding", description: "Encode bytes to Base45 (RFC 9285)", takesParam: true, paramLabel: "alphabet", paramDefault: "0-9A-Z $%*+\\-./:" },
  { id: "from_base45", label: "From Base45", category: "encoding", description: "Decode Base45 to bytes", takesParam: true, paramLabel: "alphabet", paramDefault: "0-9A-Z $%*+\\-./:" },
  { id: "to_base58", label: "To Base58", category: "encoding", description: "Encode bytes to Base58 (Bitcoin alphabet default)", takesParam: true, paramLabel: "alphabet", paramDefault: "bitcoin" },
  { id: "from_base58", label: "From Base58", category: "encoding", description: "Decode Base58 to bytes", takesParam: true, paramLabel: "alphabet", paramDefault: "bitcoin" },
  { id: "to_base58check", label: "To Base58Check", category: "encoding", description: "Encode with version byte and sha256d checksum", takesParam: true, paramLabel: "alphabet,version", paramDefault: "bitcoin,0" },
  { id: "from_base58check", label: "From Base58Check", category: "encoding", description: "Decode Base58Check to the payload", takesParam: true, paramLabel: "alphabet,version", paramDefault: "bitcoin,0" },
  { id: "to_base62", label: "To Base62", category: "encoding", description: "Encode bytes as a big-number in Base62", takesParam: true, paramLabel: "alphabet", paramDefault: "0-9A-Za-z" },
  { id: "from_base62", label: "From Base62", category: "encoding", description: "Decode a Base62 big-number to bytes", takesParam: true, paramLabel: "alphabet", paramDefault: "0-9A-Za-z" },
  { id: "to_base85", label: "To Base85", category: "encoding", description: "Encode bytes to Base85 (Ascii85, Z85 or RFC 1924)", takesParam: true, paramLabel: "scheme", paramDefault: "Standard" },
  { id: "from_base85", label: "From Base85", category: "encoding", description: "Decode Base85 to bytes", takesParam: true, paramLabel: "scheme", paramDefault: "Standard" },
  { id: "to_base92", label: "To Base92", category: "encoding", description: "Encode bytes to Base92" },
  { id: "from_base92", label: "From Base92", category: "encoding", description: "Decode Base92 to bytes" },
  { id: "to_bech32", label: "To Bech32", category: "encoding", description: "Encode bytes to a Bech32/Bech32m string", takesParam: true, paramLabel: "hrp,encoding", paramDefault: "bc" },
  { id: "from_bech32", label: "From Bech32", category: "encoding", description: "Decode a Bech32/Bech32m string to bytes" },
  { id: "to_base", label: "To Base", category: "encoding", description: "Convert a number to an arbitrary radix (2-36)", takesParam: true, paramLabel: "radix", paramDefault: "36" },
  { id: "from_base", label: "From Base", category: "encoding", description: "Convert a radix-encoded number back to decimal", takesParam: true, paramLabel: "radix", paramDefault: "36" },
  { id: "to_octal", label: "To Octal", category: "encoding", description: "Encode bytes to octal values", takesParam: true, paramLabel: "delimiter", paramDefault: " " },
  { id: "from_octal", label: "From Octal", category: "encoding", description: "Decode octal values to bytes", takesParam: true, paramLabel: "delimiter", paramDefault: " " },
  { id: "to_bcd", label: "To BCD", category: "encoding", description: "Encode a decimal number as Binary Coded Decimal", takesParam: true, paramLabel: "scheme,flags", paramDefault: "8 4 2 1" },
  { id: "from_bcd", label: "From BCD", category: "encoding", description: "Decode Binary Coded Decimal to a number", takesParam: true, paramLabel: "scheme,flags", paramDefault: "8 4 2 1" },
  { id: "to_float", label: "To Float", category: "encoding", description: "Decode IEEE-754 floats from bytes", takesParam: true, paramLabel: "endianness,size", paramDefault: "Big Endian" },
  { id: "from_float", label: "From Float", category: "encoding", description: "Encode numbers as IEEE-754 floats", takesParam: true, paramLabel: "endianness,size", paramDefault: "Big Endian" },
  { id: "escape_unicode", label: "Escape Unicode Characters", category: "encoding", description: "Escape non-ASCII characters as \\uXXXX / %uXXXX / U+XXXX", takesParam: true, paramLabel: "prefix", paramDefault: "\\u" },
  { id: "unescape_unicode", label: "Unescape Unicode Characters", category: "encoding", description: "Resolve unicode escape sequences to characters", takesParam: true, paramLabel: "prefix", paramDefault: "\\u" },
  { id: "to_hex_content", label: "To Hex Content", category: "encoding", description: "Escape non-alphanumeric bytes as |hex| runs", takesParam: true, paramLabel: "mode", paramDefault: "" },
  { id: "from_hex_content", label: "From Hex Content", category: "encoding", description: "Resolve |hex| runs back to bytes" },
  { id: "to_modhex", label: "To Modhex", category: "encoding", description: "Encode bytes to YubiKey modhex", takesParam: true, paramLabel: "delimiter", paramDefault: " " },
  { id: "from_modhex", label: "From Modhex", category: "encoding", description: "Decode modhex to bytes" },
  { id: "to_quoted_printable", label: "To Quoted Printable", category: "encoding", description: "Encode bytes as Quoted-Printable (RFC 2045)" },
  { id: "from_quoted_printable", label: "From Quoted Printable", category: "encoding", description: "Decode Quoted-Printable to bytes" },
  { id: "to_punycode", label: "To Punycode", category: "encoding", description: "Encode text with punycode (RFC 3492)", takesParam: true, paramLabel: "mode", paramDefault: "" },
  { id: "from_punycode", label: "From Punycode", category: "encoding", description: "Decode punycode to text", takesParam: true, paramLabel: "mode", paramDefault: "" },
  { id: "to_braille", label: "To Braille", category: "encoding", description: "Convert letters and digits to Braille patterns" },
  { id: "from_braille", label: "From Braille", category: "encoding", description: "Convert Braille patterns back to characters" },
  { id: "to_cobs", label: "To COBS", category: "encoding", description: "Consistent Overhead Byte Stuffing encode" },
  { id: "from_cobs", label: "From COBS", category: "encoding", description: "Consistent Overhead Byte Stuffing decode" },
  { id: "encode_text", label: "Encode text", category: "encoding", description: "Encode text to the chosen charset", takesParam: true, paramLabel: "encoding", paramDefault: "UTF-8 (65001)" },
  { id: "decode_text", label: "Decode text", category: "encoding", description: "Decode bytes from the chosen charset to text", takesParam: true, paramLabel: "encoding", paramDefault: "UTF-8 (65001)" },
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
  { id: "escape_smart_chars", label: "Escape Smart Characters", category: "transforms", description: "Replace smart quotes, dashes and symbols with ASCII", takesParam: true, paramLabel: "unmappable", paramDefault: "Include" },
  { id: "unicode_text_format", label: "Unicode Text Format", category: "transforms", description: "Append underline / strikethrough combining marks", takesParam: true, paramLabel: "mode", paramDefault: "" },
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
  { id: "caret_m_decode", label: "Caret/M-decode", category: "parsing", description: "Decode ^ and M- control notation to bytes" },
  { id: "mime_decode", label: "MIME Decoding", category: "parsing", description: "Decode RFC 2047 encoded-words (utf-8, us-ascii, iso-8859-1)" },
  { id: "parse_asn1_hex_string", label: "Parse ASN.1 hex string", category: "parsing", description: "Walk a DER structure and present the tree", takesParam: true, paramLabel: "truncate", paramDefault: "32" },
  { id: "parse_tlv", label: "Parse TLV", category: "parsing", description: "Parse type-length-value records to JSON", takesParam: true, paramLabel: "type,length,ber", paramDefault: "1,1" },
  { id: "change_ip_format", label: "Change IP format", category: "parsing", description: "Convert IPv4 addresses between dotted, decimal, octal and hex", takesParam: true, paramLabel: "in,out", paramDefault: "Dotted Decimal,Dotted Decimal" },
  { id: "text_integer_conversion", label: "Text-Integer Conversion", category: "parsing", description: "Convert Latin-1 text to a big integer and back", takesParam: true, paramLabel: "format", paramDefault: "String" },
  { id: "nato_encode", label: "NATO Alphabet", category: "parsing", description: "Spell the text in NATO phonetic alphabet" },
  { id: "unix_to_datetime", label: "Unix To DateTime", category: "parsing", description: "Unix timestamp (s or ms) to ISO 8601" },
  { id: "datetime_to_unix", label: "DateTime To Unix", category: "parsing", description: "Parse a date string to Unix seconds", takesParam: true, paramLabel: "unit", paramDefault: "s" },
  { id: "morse_encode", label: "Morse Encode", category: "parsing", description: "Text to Morse code, words separated by /" },
  { id: "morse_decode", label: "Morse Decode", category: "parsing", description: "Morse code back to text" },
  { id: "to_utf8", label: "To Text (UTF-8)", category: "parsing", description: "Interpret bytes as UTF-8 text" },
  // formatting
  { id: "hex_dump", label: "Hex Dump", category: "formatting", description: "Offset | hex | ASCII dump of the bytes", takesParam: true, paramLabel: "width", paramDefault: "16" },
  { id: "from_hexdump", label: "From Hex Dump", category: "formatting", description: "Parse a hex dump back to bytes" },
  { id: "pem_to_hex", label: "PEM to Hex", category: "formatting", description: "Extract PEM blocks as hex" },
  { id: "hex_to_pem", label: "Hex to PEM", category: "formatting", description: "Wrap hex data in a PEM header/footer", takesParam: true, paramLabel: "header", paramDefault: "CERTIFICATE" },
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

// --- CyberChef "Data format" codec helpers ----------------------------------
// Each helper mirrors the native Rust port in crates/crypto/src/encoding_ops.rs
// and the upstream CyberChef operation it was taken from.

function expandAlphRange(spec: string): string {
  let out = "";
  for (let i = 0; i < spec.length; i++) {
    if (i + 2 < spec.length && spec[i + 1] === "-" && spec[i] !== "\\") {
      for (let j = spec.charCodeAt(i); j <= spec.charCodeAt(i + 2); j++) out += String.fromCharCode(j);
      i += 2;
    } else if (i + 1 < spec.length && spec[i] === "\\" && spec[i + 1] === "-") {
      out += "-";
      i++;
    } else {
      out += spec[i];
    }
  }
  return out;
}

function bytesToDigits(bytes: Uint8Array, base: number): number[] {
  const digits: number[] = [];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] << 8;
      digits[i] = carry % base;
      carry = Math.floor(carry / base);
    }
    while (carry > 0) {
      digits.push(carry % base);
      carry = Math.floor(carry / base);
    }
  }
  return digits;
}

function digitsToBytes(digits: number[], base: number): Uint8Array {
  const out: number[] = [];
  for (const digit of digits) {
    let carry = digit;
    for (let i = 0; i < out.length; i++) {
      carry += out[i] * base;
      out[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      out.push(carry & 0xff);
      carry >>= 8;
    }
  }
  return new Uint8Array(out.reverse());
}

const BASE58_ALPHABETS: Record<string, string> = {
  bitcoin: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
  ripple: "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz",
};

function base58Alphabet(param: string | undefined): string {
  const spec = (param ?? "").trim() || "bitcoin";
  const preset = BASE58_ALPHABETS[spec.toLowerCase()];
  const alphabet = preset ?? expandAlphRange(spec);
  if (alphabet.length !== 58) throw new Error("Error: alphabet must be of length 58");
  return alphabet;
}

function base58Encode(input: Uint8Array, alphabet: string): string {
  let zeroPrefix = 0;
  while (zeroPrefix < input.length && input[zeroPrefix] === 0) zeroPrefix++;
  const result = bytesToDigits(input, 58).reverse().map((d) => alphabet[d]).join("");
  return alphabet[0].repeat(zeroPrefix) + result;
}

function base58Decode(input: string, alphabet: string): Uint8Array {
  let zeroPrefix = 0;
  while (zeroPrefix < input.length && input[zeroPrefix] === alphabet[0]) zeroPrefix++;
  const digits: number[] = [];
  for (const c of input) {
    const index = alphabet.indexOf(c);
    if (index >= 0) digits.push(index);
  }
  const out = digitsToBytes(digits, 58);
  const result = new Uint8Array(zeroPrefix + out.length);
  result.fill(0, 0, zeroPrefix);
  result.set(out, zeroPrefix);
  return result;
}

const BASE85_ALPHABETS: Record<string, string> = {
  standard: "!-u",
  ascii85: "!-u",
  z85: "0-9a-zA-Z.\\-:+=^!/*?&<>()[]{}@%$#",
  ipv6: "0-9A-Za-z!#$%&()*+\\-;<=>?@^_`{|}~",
  rfc1924: "0-9A-Za-z!#$%&()*+\\-;<=>?@^_`{|}~",
};

function base85Alphabet(param: string | undefined): { alphabet: string; standard: boolean } {
  const spec = (param ?? "").trim() || "standard";
  const preset = BASE85_ALPHABETS[spec.toLowerCase()];
  const expanded = expandAlphRange(preset ?? spec);
  if (expanded.length !== 85) throw new Error("Error: Alphabet must be of length 85");
  return { alphabet: expanded, standard: expanded === expandAlphRange("!-u") };
}

function base85Encode(input: Uint8Array, alphabet: string, standard: boolean): string {
  let out = "";
  for (let i = 0; i < input.length; i += 4) {
    const block = ((input[i] << 24) | ((input[i + 1] ?? 0) << 16) | ((input[i + 2] ?? 0) << 8) | (input[i + 3] ?? 0)) >>> 0;
    if (standard && block === 0) {
      out += "z";
      continue;
    }
    const digits: number[] = [];
    let left = block;
    for (let j = 0; j < 5; j++) {
      digits.unshift(left % 85);
      left = Math.floor(left / 85);
    }
    const keep = input.length < i + 4 ? (input.length - i) + 1 : 5;
    out += digits.slice(0, keep).map((d) => alphabet[d]).join("");
  }
  return out;
}

function base85Decode(input: string, alphabet: string): Uint8Array {
  let source = input.trim();
  const wrapped = source.match(/^<~(.+?)~>$/s);
  if (wrapped) source = wrapped[1];
  const zeroChar = alphabet.includes("z") ? "" : "z";
  const kept = [...source].filter((c) => alphabet.includes(c) || c === zeroChar).join("");
  const out: number[] = [];
  let i = 0;
  while (i < kept.length) {
    if (kept[i] === zeroChar) {
      out.push(0, 0, 0, 0);
      i++;
      continue;
    }
    const group = kept.slice(i, i + 5);
    const digits = [...group].map((c) => {
      const digit = alphabet.indexOf(c);
      if (digit < 0) throw new Error(`Invalid character '${c}' at index ${i}`);
      return digit;
    });
    const at = (idx: number) => (idx < digits.length ? digits[idx] : 84);
    const block = at(0) * 52200625 + at(1) * 614125 + at(2) * 7225 + at(3) * 85 + at(4);
    if (block > 0xffffffff) throw new Error("Base85 group exceeds 32-bit range");
    const keep = Math.min(Math.max(digits.length - 1, 0), 4);
    for (let shift = 3; shift >= 4 - keep; shift--) out.push((block >>> (8 * shift)) & 0xff);
    i += 5;
  }
  return new Uint8Array(out);
}

function base92Chr(value: number): string {
  if (value < 0 || value >= 91) throw new Error("Invalid value");
  if (value === 0) return "!";
  if (value <= 61) return String.fromCharCode(35 + value - 1);
  return String.fromCharCode(97 + value - 62);
}

function base92Ord(ch: string): number {
  if (ch === "!") return 0;
  if ("#" <= ch && ch <= "_") return ch.charCodeAt(0) - 35 + 1;
  if ("a" <= ch && ch <= "}") return ch.charCodeAt(0) - 97 + 62;
  throw new Error(`${ch} is not a base92 character`);
}

function base92Encode(input: Uint8Array): string {
  let bitString = "";
  let out = "";
  for (const byte of input) {
    bitString += byte.toString(2).padStart(8, "0");
    while (bitString.length >= 13) {
      const value = Number.parseInt(bitString.slice(0, 13), 2);
      out += base92Chr(Math.floor(value / 91)) + base92Chr(value % 91);
      bitString = bitString.slice(13);
    }
  }
  if (bitString.length > 0) {
    if (bitString.length < 7) {
      const value = Number.parseInt(bitString.padEnd(6, "0"), 2);
      out += base92Chr(value);
    } else {
      const value = Number.parseInt(bitString.padEnd(13, "0").slice(0, 13), 2);
      out += base92Chr(Math.floor(value / 91)) + base92Chr(value % 91);
    }
  }
  return out;
}

function base92Decode(input: string): Uint8Array {
  let bitString = "";
  const out: number[] = [];
  const chars = [...input];
  for (let i = 0; i < chars.length; i += 2) {
    if (i + 1 < chars.length) {
      const x = base92Ord(chars[i]) * 91 + base92Ord(chars[i + 1]);
      bitString += x.toString(2).padStart(13, "0");
    } else {
      bitString += base92Ord(chars[i]).toString(2).padStart(6, "0");
    }
    while (bitString.length >= 8) {
      out.push(Number.parseInt(bitString.slice(0, 8), 2));
      bitString = bitString.slice(8);
    }
  }
  return new Uint8Array(out);
}

const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

function bech32Polymod(values: number[]): number {
  const generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x01ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((top >>> i) & 1) chk ^= generator[i];
    }
  }
  return chk;
}

function bech32HrpExpand(hrp: string): number[] {
  return [
    ...[...hrp].map((c) => c.charCodeAt(0) >>> 5),
    0,
    ...[...hrp].map((c) => c.charCodeAt(0) & 31),
  ];
}

function bech32ToWords(data: Uint8Array): number[] {
  const words: number[] = [];
  let value = 0;
  let bits = 0;
  for (const byte of data) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      words.push((value >>> bits) & 31);
    }
  }
  if (bits > 0) words.push((value << (5 - bits)) & 31);
  return words;
}

function bech32FromWords(words: number[]): Uint8Array {
  const out: number[] = [];
  let value = 0;
  let bits = 0;
  for (const word of words) {
    value = (value << 5) | word;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 255);
    }
  }
  if (bits >= 5) throw new Error("Invalid padding: too many bits remaining");
  if (bits > 0 && (value << (8 - bits)) & 255) throw new Error("Invalid padding: non-zero bits in padding");
  return new Uint8Array(out);
}

function bech32Encode(hrp: string, data: Uint8Array, bech32m: boolean): string {
  if (!hrp) throw new Error("Human-Readable Part (HRP) cannot be empty.");
  const lower = hrp.toLowerCase();
  const words = bech32ToWords(data);
  const constant = bech32m ? 0x2bc830a3 : 1;
  const checksum = bech32Polymod([...bech32HrpExpand(lower), ...words, 0, 0, 0, 0, 0, 0]) ^ constant;
  let out = `${lower}1`;
  for (const word of words) out += BECH32_CHARSET[word];
  for (let i = 0; i < 6; i++) out += BECH32_CHARSET[(checksum >>> (5 * (5 - i))) & 31];
  return out;
}

function bech32Decode(input: string): Uint8Array {
  const trimmed = input.trim();
  if (/[a-z]/.test(trimmed) && /[A-Z]/.test(trimmed)) throw new Error("Mixed case Bech32 string is invalid");
  const lowered = trimmed.toLowerCase();
  const sep = lowered.lastIndexOf("1");
  if (sep < 1 || sep + 7 > lowered.length) throw new Error("Invalid Bech32 separator position");
  const words: number[] = [];
  for (const c of lowered.slice(sep + 1)) {
    const digit = BECH32_CHARSET.indexOf(c);
    if (digit < 0) throw new Error(`Invalid Bech32 character '${c}'`);
    words.push(digit);
  }
  if (words.length < 6) throw new Error("Bech32 checksum too short");
  const checksum = bech32Polymod([...bech32HrpExpand(lowered.slice(0, sep)), ...words]);
  if (checksum !== 1 && checksum !== 0x2bc830a3) throw new Error("Bech32 checksum mismatch");
  return bech32FromWords(words.slice(0, words.length - 6));
}

// Compact pure-TS SHA-256 for Base58Check's double-hash checksum.
function sha256(message: Uint8Array): Uint8Array {
  const k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  const h = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
  const withLength = new Uint8Array((((message.length + 8) >> 6) + 1) << 6);
  withLength.set(message);
  withLength[message.length] = 0x80;
  const bitLength = message.length * 8;
  new DataView(withLength.buffer).setUint32(withLength.length - 4, bitLength >>> 0);
  new DataView(withLength.buffer).setUint32(withLength.length - 8, Math.floor(bitLength / 2 ** 32));
  const words = new DataView(withLength.buffer);
  for (let block = 0; block < withLength.length; block += 64) {
    const w = new Array<number>(64);
    for (let i = 0; i < 16; i++) w[i] = words.getUint32(block + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = ((w[i - 15] >>> 7) | (w[i - 15] << 25)) ^ ((w[i - 15] >>> 18) | (w[i - 15] << 14)) ^ (w[i - 15] >>> 3);
      const s1 = ((w[i - 2] >>> 17) | (w[i - 2] << 15)) ^ ((w[i - 2] >>> 19) | (w[i - 2] << 13)) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
      const ch = (e & f) ^ (~e & g);
      const temp1 = (hh + S1 + ch + k[i] + w[i]) >>> 0;
      const S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e;
      e = (d + temp1) >>> 0;
      d = c; c = b; b = a;
      a = (temp1 + temp2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }
  return new Uint8Array(h.flatMap((word) => [(word >>> 24) & 0xff, (word >>> 16) & 0xff, (word >>> 8) & 0xff, word & 0xff]));
}

function base58checkAlphabetAndVersion(param: string | undefined): { alphabet: string; version: number } {
  const [alphabetParam = "", versionParam = "0"] = (param ?? "").split(",");
  const alphabet = base58Alphabet(alphabetParam.trim() || undefined);
  const raw = versionParam.trim() || "0";
  const version = raw.toLowerCase().startsWith("0x")
    ? Number.parseInt(raw.slice(2), 16)
    : Number.parseInt(raw, 10);
  if (Number.isNaN(version) || version < 0 || version > 255) throw new Error("invalid version byte");
  return { alphabet, version };
}

function base58checkEncode(input: Uint8Array, alphabet: string, version: number): string {
  const payload = new Uint8Array(input.length + 5);
  payload[0] = version;
  payload.set(input, 1);
  const first = sha256(payload.subarray(0, input.length + 1));
  const checksum = sha256(first);
  payload.set(checksum.subarray(0, 4), input.length + 1);
  return base58Encode(payload, alphabet);
}

function base58checkDecode(input: string, alphabet: string): Uint8Array {
  const payload = base58Decode(input, alphabet);
  if (payload.length < 5) throw new Error("Base58Check input too short");
  const body = payload.subarray(0, payload.length - 4);
  const checksum = sha256(sha256(body));
  for (let i = 0; i < 4; i++) {
    if (payload[payload.length - 4 + i] !== checksum[i]) throw new Error("Base58Check checksum mismatch");
  }
  return payload.subarray(1, payload.length - 4);
}

function base45Encode(input: Uint8Array, alphabet: string): string {
  let out = "";
  for (let i = 0; i < input.length; i += 2) {
    const pair = input.slice(i, i + 2);
    let value = 0;
    for (const byte of pair) value = value * 256 + byte;
    let chars = 0;
    do {
      out += alphabet[value % 45];
      chars++;
      value = Math.floor(value / 45);
    } while (value > 0);
    if (chars < 2) {
      out += alphabet[0];
      chars++;
    }
    if (pair.length > 1 && chars < 3) out += alphabet[0];
  }
  return out;
}

function base45Decode(input: string, alphabet: string, strict: boolean): Uint8Array {
  const source = strict ? input : [...input].filter((c) => alphabet.includes(c)).join("");
  const out: number[] = [];
  const chars = [...source];
  for (let i = 0; i < chars.length; i += 3) {
    const triple = chars.slice(i, i + 3).reverse();
    let value = 0;
    for (const c of triple) {
      const index = alphabet.indexOf(c);
      if (index < 0) throw new Error(`Character not in alphabet: '${c}'`);
      value = value * 45 + index;
    }
    if (value > 65535) throw new Error(`Triplet too large: '${triple.join("")}'`);
    if (triple.length > 2) out.push(value >> 8);
    out.push(value & 0xff);
  }
  return new Uint8Array(out);
}

function base62Alphabet(param: string | undefined): string {
  const alphabet = expandAlphRange((param ?? "").trim() || "0-9A-Za-z");
  if (alphabet.length !== 62) throw new Error("Error: alphabet must be of length 62");
  return alphabet;
}

function radixNumberToString(value: number, radix: number): string {
  return value.toString(radix);
}

function fromRadixNumber(raw: string, radix: number): string {
  const [intPart, fracPart] = raw.split(".");
  const intDigits = "0123456789abcdefghijklmnopqrstuvwxyz".slice(0, radix);
  let int = 0;
  for (const ch of intPart) {
    const digit = intDigits.indexOf(ch.toLowerCase());
    if (digit < 0) throw new Error(`'${ch}' is not a valid base-${radix} digit`);
    int = int * radix + digit;
  }
  if (!fracPart) return String(int);
  let frac = 0;
  for (let i = 0; i < fracPart.length; i++) {
    const digit = intDigits.indexOf(fracPart[i].toLowerCase());
    if (digit < 0) throw new Error(`'${fracPart[i]}' is not a valid base-${radix} digit`);
    frac += digit / radix ** (i + 1);
  }
  const fracText = String(frac);
  const fracDigits = fracText.startsWith("0.") ? fracText.slice(2) : fracText.replace(/^0+/, "");
  return `${int}.${fracDigits}`.replace(/0+$/, "").replace(/\.$/, "");
}

function octalEncode(input: Uint8Array, delimiter: string): string {
  return Array.from(input, (b) => b.toString(8)).join(delimiter);
}

function octalDecode(input: string, delimiter: string): Uint8Array {
  if (!input) return new Uint8Array();
  return new Uint8Array(input.split(delimiter).map((v) => {
    const value = Number.parseInt(v.trim(), 8);
    if (Number.isNaN(value) || value < 0 || value > 255) throw new Error(`'${v}' is not an octal byte value`);
    return value;
  }));
}

const BCD_SCHEMES: Array<[string, number[]]> = [
  ["8 4 2 1", [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]],
  ["7 4 2 1", [0, 1, 2, 3, 4, 5, 6, 8, 9, 10]],
  ["4 2 2 1", [0, 1, 4, 5, 8, 9, 12, 13, 14, 15]],
  ["2 4 2 1", [0, 1, 2, 3, 4, 11, 12, 13, 14, 15]],
  ["8 4 -2 -1", [0, 7, 6, 5, 4, 11, 10, 9, 8, 15]],
  ["Excess-3", [3, 4, 5, 6, 7, 8, 9, 10, 11, 12]],
  ["IBM 8 4 2 1", [10, 1, 2, 3, 4, 5, 6, 7, 8, 9]],
];

function bcdParams(param: string | undefined): { table: number[]; packed: boolean; signed: boolean; format: string } {
  const [scheme = "8 4 2 1", ...flags] = (param ?? "8 4 2 1").split(",").map((p) => p.trim());
  const entry = BCD_SCHEMES.find(([name]) => name.toLowerCase() === scheme.toLowerCase());
  if (!entry) throw new Error(`Unknown BCD scheme: ${scheme}`);
  const state = { table: entry[1], packed: true, signed: false, format: "Nibbles" };
  for (const flag of flags) {
    const key = flag.toLowerCase();
    if (key === "packed") state.packed = true;
    else if (key === "unpacked") state.packed = false;
    else if (key === "signed") state.signed = true;
    else if (key === "unsigned") state.signed = false;
    else if (key === "nibbles") state.format = "Nibbles";
    else if (key === "bytes") state.format = "Bytes";
    else if (key === "raw") state.format = "Raw";
    else if (key) throw new Error(`Unknown BCD parameter: ${flag}`);
  }
  return state;
}

function bcdEncode(input: string, table: number[], packed: boolean, signed: boolean, format: string): string | Uint8Array {
  const source = input.trim();
  const negative = source.startsWith("-");
  const digitsSource = source.replace(/^[-+]/, "");
  if (!digitsSource || !/^\d+$/.test(digitsSource)) throw new Error("Invalid input");
  const nibbles = [...digitsSource].map((d) => table[Number.parseInt(d, 10)]);
  if (signed) {
    if (packed && nibbles.length % 2 === 0) nibbles.unshift(table[0]);
    nibbles.push(negative ? 13 : 12);
  }
  const bytes: number[] = [];
  if (packed) {
    let encoded = 0;
    let little = false;
    for (const n of nibbles) {
      encoded ^= little ? n : n << 4;
      if (little) {
        bytes.push(encoded);
        encoded = 0;
      }
      little = !little;
    }
    if (little) bytes.push(encoded);
  } else {
    bytes.push(...nibbles);
  }
  if (format === "Raw") return new Uint8Array(bytes);
  const render = packed
    ? bytes
    : nibbles.flatMap((n) => [0, n]);
  const width = format === "Bytes" ? 8 : 4;
  return render.map((n) => n.toString(2).padStart(width, "0")).join(" ");
}

function bcdDecode(input: Uint8Array, table: number[], packed: boolean, signed: boolean, format: string): string {
  let nibbles: number[];
  if (format === "Raw") {
    nibbles = Array.from(input, (b) => [b >>> 4, b & 15]).flat();
  } else {
    const compact = new TextDecoder().decode(input).replace(/\s/g, "");
    if (compact.length % 4 !== 0) throw new Error("binary input length must be a multiple of 4");
    nibbles = [];
    for (let i = 0; i < compact.length; i += 4) nibbles.push(Number.parseInt(compact.slice(i, i + 4), 2));
  }
  if (!packed) nibbles = nibbles.filter((_, index) => index % 2 === 1);
  let negative = false;
  if (signed) {
    const sign = nibbles.pop();
    negative = sign === 13 || sign === 11;
  }
  let digits = nibbles.map((n) => {
    const value = table.indexOf(n);
    if (value < 0) throw new Error(`Value ${n.toString(2).padStart(4, "0")} is not in the encoding scheme`);
    return String(value);
  }).join("");
  digits = digits.replace(/^0+/, "") || "0";
  return (negative ? "-" : "") + digits;
}

function floatParam(param: string | undefined): { littleEndian: boolean; double: boolean } {
  const flags = (param ?? "Big Endian").split(",").map((f) => f.trim().toLowerCase());
  return {
    littleEndian: flags.includes("little endian") || flags.includes("little") || flags.includes("le"),
    double: flags.includes("double") || flags.includes("8"),
  };
}

function floatNumberToString(value: number): string {
  if (Number.isNaN(value)) return "NaN";
  if (!Number.isFinite(value)) return value < 0 ? "-Infinity" : "Infinity";
  return String(value);
}

function floatEncode(input: Uint8Array, littleEndian: boolean, double: boolean): string {
  const size = double ? 8 : 4;
  if (input.length % size !== 0) throw new Error(`Input is not a multiple of ${size}`);
  const view = new DataView(input.buffer, input.byteOffset, input.byteLength);
  const pieces: string[] = [];
  for (let i = 0; i < input.length; i += size) {
    pieces.push(floatNumberToString(double
      ? littleEndian ? view.getFloat64(i, true) : view.getFloat64(i)
      : littleEndian ? view.getFloat32(i, true) : view.getFloat32(i)));
  }
  return pieces.join(" ");
}

function floatDecode(input: string, double: boolean): Uint8Array {
  const tokens = input.trim().split(" ").filter((t) => t.length > 0);
  const size = double ? 8 : 4;
  const out = new Uint8Array(tokens.length * size);
  const view = new DataView(out.buffer);
  tokens.forEach((token, i) => {
    const value = Number.parseFloat(token);
    if (Number.isNaN(value) && token.trim().toLowerCase() !== "nan") throw new Error(`'${token}' is not a valid number`);
    if (double) view.setFloat64(i * size, value);
    else view.setFloat32(i * size, value);
  });
  return out;
}

function escapeUnicode(input: string, prefix: string, encodeAll: boolean): string {
  let out = "";
  for (const ch of input) {
    for (const unit of surrogateUnits(ch)) {
      if (!encodeAll && unit >= 32 && unit <= 126) {
        out += String.fromCharCode(unit);
        continue;
      }
      out += prefix + unit.toString(16).toUpperCase().padStart(4, "0");
    }
  }
  return out;
}

function surrogateUnits(ch: string): number[] {
  const units: number[] = [];
  for (let i = 0; i < ch.length; i++) units.push(ch.charCodeAt(i));
  return units;
}

function unescapeUnicode(input: string, prefix: string): string {
  const max = prefix === "U+" ? 6 : 4;
  const min = 4;
  let out = "";
  let rest = input;
  for (;;) {
    const at = rest.indexOf(prefix);
    if (at < 0) break;
    out += rest.slice(0, at);
    const after = rest.slice(at + prefix.length);
    const hex = after.slice(0, max).match(/^[0-9a-fA-F]*/)?.[0] ?? "";
    if (hex.length < min) {
      out += prefix;
      rest = after;
      continue;
    }
    out += String.fromCodePoint(Number.parseInt(hex, 16));
    rest = after.slice(hex.length);
  }
  return out + rest;
}

const SMART_MAP: Array<[string, string]> = [
  ["\u201C", "\""], ["\u201D", "\""], ["\u201E", "\""], ["\u201F", "\""], ["\u2033", "\""],
  ["\u2018", "'"], ["\u2019", "'"], ["\u201A", "'"], ["\u201B", "'"], ["\u2032", "'"],
  ["\u2010", "-"], ["\u2011", "-"], ["\u2012", "-"], ["\u2013", "-"], ["\u2014", "--"],
  ["\u2015", "--"], ["\u2026", "..."],
  ["\u00A9", "(c)"], ["\u00AE", "(r)"], ["\u2122", "(tm)"],
  ["\u2190", "<--"], ["\u2192", "-->"], ["\u2191", "^"], ["\u2193", "v"], ["\u2194", "<->"],
  ["\u21D0", "<=="], ["\u21D2", "==>"], ["\u21D4", "<=>"],
  ["\u00AB", "<<"], ["\u00BB", ">>"], ["\u2039", "<"], ["\u203A", ">"],
  ["\u00D7", "x"], ["\u00F7", "/"], ["\u00B1", "+/-"], ["\u2022", "*"], ["\u00B7", "."],
  ["\u00A0", " "], ["\u2002", " "], ["\u2003", " "], ["\u2009", " "], ["\u200A", " "],
];

function escapeSmartChars(input: string, unmappable: string): string {
  let out = "";
  for (const ch of input) {
    if (ch.charCodeAt(0) < 128) {
      out += ch;
      continue;
    }
    const mapped = SMART_MAP.find(([from]) => from === ch);
    if (mapped) {
      out += mapped[1];
    } else if (unmappable === "Remove") {
      // drop
    } else if (unmappable === "Replace with '.'") {
      out += ".";
    } else {
      out += ch;
    }
  }
  return out;
}

function hexContentEncode(input: Uint8Array, mode: string, spaces: boolean): string {
  if (mode === "All chars") {
    const hex = spaces
      ? Array.from(input, (b) => b.toString(16).padStart(2, "0").toUpperCase()).join(" ")
      : Array.from(input, (b) => b.toString(16).padStart(2, "0").toUpperCase()).join("");
    return `|${hex}|`;
  }
  const convertSpaces = mode === "Only special chars including spaces";
  let out = "";
  let inHex = false;
  for (const b of input) {
    const escaped = (b === 32 && convertSpaces)
      || (b < 48 && b !== 32) || (b > 57 && b < 65) || (b > 90 && b < 97) || b > 122;
    if (escaped) {
      if (!inHex) {
        out += "|";
        inHex = true;
      } else if (spaces) out += " ";
      out += b.toString(16).padStart(2, "0").toUpperCase();
    } else {
      if (inHex) {
        out += "|";
        inHex = false;
      }
      out += String.fromCharCode(b);
    }
  }
  return inHex ? `${out}|` : out;
}

function hexContentDecode(input: Uint8Array): Uint8Array {
  const out: number[] = [];
  let at = 0;
  for (;;) {
    const startRel = input.subarray(at).indexOf(0x7c);
    if (startRel < 0) break;
    const start = at + startRel;
    const endRel = input.subarray(start + 1).indexOf(0x7c);
    if (endRel < 0) break;
    const end = start + 1 + endRel;
    out.push(...input.subarray(at, start));
    const inner = input.subarray(start + 1, end).filter((b) => b !== 0x20);
    const hex = [...inner].every((b) => (b >= 48 && b <= 57) || (b >= 65 && b <= 70) || (b >= 97 && b <= 102));
    if (inner.length >= 2 && inner.length % 2 === 0 && hex) {
      for (let i = 0; i < inner.length; i += 2) {
        out.push(Number.parseInt(String.fromCharCode(inner[i], inner[i + 1]), 16));
      }
    } else {
      out.push(...input.subarray(start, end + 1));
    }
    at = end + 1;
  }
  out.push(...input.subarray(at));
  return new Uint8Array(out);
}

function caretMDecode(input: string): Uint8Array {
  const bytes: number[] = [];
  let prev = "";
  for (const ch of input) {
    const code = ch.charCodeAt(0);
    if (prev === "M-^") {
      if (code > 63 && code <= 95) bytes.push(code + 64);
      else if (code === 63) bytes.push(255);
      else bytes.push(77, 45, 94, code);
      prev = "";
    } else if (prev === "M-") {
      if (ch === "^") prev = "M-^";
      else if (code >= 32 && code <= 126) {
        bytes.push(code + 128);
        prev = "";
      } else {
        bytes.push(77, 45, code);
        prev = "";
      }
    } else if (prev === "M") {
      if (ch === "-") prev = "M-";
      else {
        bytes.push(77, code);
        prev = "";
      }
    } else if (prev === "^") {
      if (code > 63 && code <= 126) bytes.push(code - 64);
      else if (code === 63) bytes.push(127);
      else bytes.push(94, code);
      prev = "";
    } else if (ch === "M") {
      prev = "M";
    } else if (ch === "^") {
      prev = "^";
    } else {
      bytes.push(code);
    }
  }
  return new Uint8Array(bytes);
}

const MODHEX_ALPHABET = "cbdefghijklnrtuv";

function modhexEncode(input: Uint8Array, delimiter: string): string {
  const body = Array.from(input, (b) => MODHEX_ALPHABET[(b >>> 4) & 15] + MODHEX_ALPHABET[b & 15]).join("");
  return (body.match(/.{2}/g) ?? []).join(delimiter);
}

function modhexDecode(input: string): Uint8Array {
  let hex = "";
  for (const ch of input.toLowerCase()) {
    const index = MODHEX_ALPHABET.indexOf(ch);
    if (index >= 0) hex += "0123456789abcdef"[index];
    else if (!/[a-z0-9]/.test(ch)) continue;
    else throw new Error(`Invalid modhex character '${ch}'`);
  }
  if (hex.length % 2 !== 0) throw new Error("modhex input has an odd number of characters");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function qpByteAllowed(b: number): boolean {
  return [9, 10, 13, 32, 33].includes(b)
    || (b >= 0x23 && b <= 0x3c) || b === 0x3e
    || (b >= 0x40 && b <= 0x5e) || (b >= 0x60 && b <= 0x7e);
}

function qpSoftLinebreaks(encoded: string): string {
  const maxLine = 76;
  const chars = [...encoded];
  let out = "";
  let lineLen = 0;
  let at = 0;
  while (at < chars.length) {
    const ch = chars[at];
    if (ch === "\r" && chars[at + 1] === "\n") {
      out += "\r\n";
      lineLen = 0;
      at += 2;
      continue;
    }
    if (ch === "\n") {
      out += "\r\n";
      lineLen = 0;
      at += 1;
      continue;
    }
    const tokenLen = ch === "=" && chars[at + 1] !== undefined && chars[at + 2] !== undefined
      && chars[at + 1] !== "=" && isHexDigit(chars[at + 1]) && isHexDigit(chars[at + 2]) ? 3 : 1;
    if (lineLen + tokenLen > maxLine - 1) {
      out += "=\r\n";
      lineLen = 0;
    }
    out += chars.slice(at, at + tokenLen).join("");
    lineLen += tokenLen;
    at += tokenLen;
  }
  return out;
}

function isHexDigit(ch: string | undefined): boolean {
  return ch !== undefined && /^[0-9a-fA-F]$/.test(ch);
}

function quotedPrintableEncode(input: Uint8Array): string {
  let normalized = "";
  let trailing = "";
  for (const b of input) {
    if (b === 13 || b === 10) {
      normalized += [...trailing].map((c) => `=${c.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0")}`).join("");
      trailing = "";
      normalized += "\r\n";
    } else if (b === 32 || b === 9) {
      trailing += String.fromCharCode(b);
    } else {
      normalized += trailing;
      trailing = "";
      normalized += qpByteAllowed(b) ? String.fromCharCode(b) : `=${b.toString(16).toUpperCase().padStart(2, "0")}`;
    }
  }
  normalized += [...trailing].map((c) => `=${c.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0")}`).join("");
  return qpSoftLinebreaks(normalized);
}

function quotedPrintableDecode(input: Uint8Array): Uint8Array {
  const out: number[] = [];
  let at = 0;
  while (at < input.length) {
    const b = input[at];
    if (b === 0x3d) {
      if (at + 1 >= input.length) break;
      if (input[at + 1] === 13 && input[at + 2] === 10) {
        at += 3;
        continue;
      }
      if (input[at + 1] === 10) {
        at += 2;
        continue;
      }
      if (at + 2 < input.length && isHexDigit(String.fromCharCode(input[at + 1])) && isHexDigit(String.fromCharCode(input[at + 2]))) {
        out.push(Number.parseInt(String.fromCharCode(input[at + 1], input[at + 2]), 16));
        at += 3;
        continue;
      }
    }
    out.push(b);
    at += 1;
  }
  return new Uint8Array(out);
}

const PUNY_BASE = 36;
const PUNY_TMIN = 1;
const PUNY_TMAX = 26;
const PUNY_SKEW = 38;
const PUNY_DAMP = 700;
const PUNY_INITIAL_BIAS = 72;
const PUNY_INITIAL_N = 128;

function punyAdapt(deltaValue: number, numPoints: number, firstTime: boolean): number {
  let delta = firstTime ? Math.floor(deltaValue / PUNY_DAMP) : Math.floor(deltaValue / 2);
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > Math.floor(((PUNY_BASE - PUNY_TMIN) * PUNY_TMAX) / 2)) {
    delta = Math.floor(delta / (PUNY_BASE - PUNY_TMIN));
    k += PUNY_BASE;
  }
  return k + Math.floor(((PUNY_BASE - PUNY_TMIN + 1) * delta) / (delta + PUNY_SKEW));
}

function punyDigitChar(digit: number): string {
  return digit < 26 ? String.fromCharCode(97 + digit) : String.fromCharCode(48 + digit - 26);
}

function punyCharDigit(ch: string): number | null {
  if (ch >= "a" && ch <= "z") return ch.charCodeAt(0) - 97;
  if (ch >= "A" && ch <= "Z") return ch.charCodeAt(0) - 65;
  if (ch >= "0" && ch <= "9") return ch.charCodeAt(0) - 48 + 26;
  return null;
}

function punyThreshold(k: number, bias: number): number {
  const diff = k - bias;
  return Math.min(Math.max(diff, PUNY_TMIN), PUNY_TMAX);
}

function punycodeEncode(input: string): string {
  const chars = [...input];
  const basicCount = chars.filter((c) => c.charCodeAt(0) < 128).length;
  let out = chars.filter((c) => c.charCodeAt(0) < 128).join("");
  if (out.length > 0) out += "-";
  let n = PUNY_INITIAL_N;
  let delta = 0;
  let bias = PUNY_INITIAL_BIAS;
  let handled = basicCount;
  while (handled < chars.length) {
    let m = Number.MAX_SAFE_INTEGER;
    for (const c of chars) {
      if (c.charCodeAt(0) >= n && c.charCodeAt(0) < m) m = c.charCodeAt(0);
    }
    delta += (m - n) * (handled + 1);
    n = m;
    for (const c of chars) {
      if (c.charCodeAt(0) < n) delta += 1;
      if (c.charCodeAt(0) === n) {
        let q = delta;
        for (let k = PUNY_BASE; ; k += PUNY_BASE) {
          const t = punyThreshold(k, bias);
          if (q < t) break;
          out += punyDigitChar(t + ((q - t) % (PUNY_BASE - t)));
          q = Math.floor((q - t) / (PUNY_BASE - t));
        }
        out += punyDigitChar(q);
        bias = punyAdapt(delta, handled + 1, handled === basicCount);
        delta = 0;
        handled += 1;
      }
    }
    delta += 1;
    n += 1;
  }
  return out;
}

function punycodeDecode(input: string): string {
  const chars = [...input];
  let delim = -1;
  for (let i = chars.length - 1; i >= 0; i--) {
    if (chars[i] === "-") {
      delim = i;
      break;
    }
  }
  const basic = delim >= 0 ? chars.slice(0, delim) : [];
  const extended = delim >= 0 ? chars.slice(delim + 1) : chars;
  if (basic.some((c) => c.charCodeAt(0) >= 128)) throw new Error("punycode: basic code points must be ASCII");
  const output: string[] = basic;
  let n = PUNY_INITIAL_N;
  let i = 0;
  let bias = PUNY_INITIAL_BIAS;
  let at = 0;
  while (at < extended.length) {
    const oldi = i;
    let w = 1;
    for (let k = PUNY_BASE; ; k += PUNY_BASE) {
      const digit = extended[at++];
      const value = punyCharDigit(digit);
      if (value === null) throw new Error("punycode: invalid digit");
      i += value * w;
      const t = punyThreshold(k, bias);
      if (value < t) break;
      w *= PUNY_BASE - t;
    }
    const out = output.length + 1;
    bias = punyAdapt(i - oldi, out, oldi === 0);
    n += Math.floor(i / out);
    i %= out;
    const ch = String.fromCodePoint(n);
    output.splice(i, 0, ch);
    i += 1;
  }
  return output.join("");
}

const BRAILLE_ASCII = " A1B'K2L@CIF/MSP\"E3H9O6R^DJG>NTQ,*5<-U8V.%[$+X!&;:4\\0Z7(_?W]#Y)=";
const BRAILLE_DOT6 = Array.from({ length: 64 }, (_, i) => String.fromCodePoint(0x2800 + i)).join("");

function brailleEncode(input: string): string {
  return [...input].map((c) => {
    const index = BRAILLE_ASCII.indexOf(c.toUpperCase());
    return index < 0 ? c : BRAILLE_DOT6[index];
  }).join("");
}

function brailleDecode(input: string): string {
  return [...input].map((c) => {
    const index = BRAILLE_DOT6.indexOf(c);
    return index < 0 ? c : BRAILLE_ASCII[index];
  }).join("");
}

function cobsEncode(input: Uint8Array): Uint8Array {
  if (input.length === 0) return new Uint8Array();
  const data = [0, ...input];
  const out: number[] = [];
  while (data.length > 0) {
    let endIndex = -1;
    for (let i = 1; i < data.length; i++) {
      if (data[i] === 0) {
        endIndex = i;
        break;
      }
    }
    if ((endIndex < 0 || endIndex > 254) && data.length > 254) {
      out.push(255, ...data.slice(1, 255));
      const rest = data.slice(255);
      data.length = 0;
      if (rest.length > 0) data.push(0, ...rest);
    } else if (endIndex < 0) {
      out.push(data.length, ...data.slice(1));
      data.length = 0;
    } else {
      out.push(endIndex, ...data.slice(1, endIndex));
      const rest = data.slice(endIndex);
      data.length = 0;
      data.push(...rest);
    }
  }
  return new Uint8Array(out);
}

function cobsDecode(input: Uint8Array): Uint8Array {
  if (input.includes(0)) throw new Error("Could not decode from COBS: payload must not contain a 0x00 byte");
  if (input.length === 0) return new Uint8Array();
  const out: number[] = [0];
  let at = 0;
  while (at < input.length) {
    const block = input[at];
    if (block === 0 || at + block > input.length) throw new Error("invalid COBS block length");
    out.push(...input.slice(at + 1, at + block));
    if (block < 255 && at + block < input.length) out.push(0);
    at += block;
  }
  out.shift();
  return new Uint8Array(out);
}

const CHARSET_ALIASES: Record<string, string> = {
  "utf-8 (65001)": "utf-8", "utf-8": "utf-8", utf8: "utf-8", "65001": "utf-8",
  "utf-16le (1200)": "utf-16le", "utf-16le": "utf-16le", utf16le: "utf-16le", "1200": "utf-16le",
  "utf-16be (1201)": "utf-16be", "utf-16be": "utf-16be", utf16be: "utf-16be", "1201": "utf-16be",
  "utf-32le (12000)": "utf-32le", "utf-32le": "utf-32le", utf32le: "utf-32le", "12000": "utf-32le",
  "utf-32be (12001)": "utf-32be", "utf-32be": "utf-32be", utf32be: "utf-32be", "12001": "utf-32be",
  "windows-1252 latin (1252)": "windows-1252", "windows-1252": "windows-1252", cp1252: "windows-1252", "1252": "windows-1252",
  "iso-8859-1 latin 1 western european (28591)": "iso-8859-1", "iso-8859-1": "iso-8859-1", latin1: "iso-8859-1", "latin-1": "iso-8859-1", "28591": "iso-8859-1",
};

function resolveCharset(param: string | undefined): string {
  const key = (param ?? "UTF-8 (65001)").trim().toLowerCase();
  const charset = CHARSET_ALIASES[key];
  if (!charset) {
    throw new Error(`Unsupported encoding: ${key}. Charset support covers UTF-8, UTF-16LE/BE, UTF-32LE/BE, Windows-1252 and ISO-8859-1.`);
  }
  return charset;
}

const CP1252_ENCODE: Array<[string, number]> = [
  ["\u20AC", 0x80], ["\u201A", 0x82], ["\u0192", 0x83], ["\u201E", 0x84], ["\u2026", 0x85],
  ["\u2020", 0x86], ["\u2021", 0x87], ["\u02C6", 0x88], ["\u2030", 0x89], ["\u0160", 0x8a],
  ["\u2039", 0x8b], ["\u0152", 0x8c], ["\u017D", 0x8e], ["\u2018", 0x91], ["\u2019", 0x92],
  ["\u201C", 0x93], ["\u201D", 0x94], ["\u2022", 0x95], ["\u2013", 0x96], ["\u2014", 0x97],
  ["\u02DC", 0x98], ["\u2122", 0x99], ["\u0161", 0x9a], ["\u203A", 0x9b], ["\u0153", 0x9c],
  ["\u017E", 0x9e], ["\u0178", 0x9f],
];

const CP1252_DECODE: Record<number, string> = {
  0x80: "\u20AC", 0x82: "\u201A", 0x83: "\u0192", 0x84: "\u201E", 0x85: "\u2026",
  0x86: "\u2020", 0x87: "\u2021", 0x88: "\u02C6", 0x89: "\u2030", 0x8a: "\u0160",
  0x8b: "\u2039", 0x8c: "\u0152", 0x8e: "\u017D", 0x91: "\u2018", 0x92: "\u2019",
  0x93: "\u201C", 0x94: "\u201D", 0x95: "\u2022", 0x96: "\u2013", 0x97: "\u2014",
  0x98: "\u02DC", 0x99: "\u2122", 0x9a: "\u0161", 0x9b: "\u203A", 0x9c: "\u0153",
  0x9e: "\u017E", 0x9f: "\u0178",
};

function encodeText(input: string, charset: string): Uint8Array {
  if (charset === "utf-8") return encoder.encode(input);
  if (charset === "utf-16le" || charset === "utf-16be") {
    const bigEndian = charset === "utf-16be";
    const units: number[] = [];
    for (const ch of input) for (const unit of surrogateUnits(ch)) units.push(unit);
    const out = new Uint8Array(units.length * 2);
    units.forEach((unit, i) => {
      out[i * 2] = bigEndian ? unit >>> 8 : unit & 0xff;
      out[i * 2 + 1] = bigEndian ? unit & 0xff : unit >>> 8;
    });
    return out;
  }
  if (charset === "utf-32le" || charset === "utf-32be") {
    const bigEndian = charset === "utf-32be";
    const cps = [...input].map((c) => c.codePointAt(0) ?? 0);
    const out = new Uint8Array(cps.length * 4);
    cps.forEach((cp, i) => {
      const bytes = [cp & 0xff, (cp >>> 8) & 0xff, (cp >>> 16) & 0xff, (cp >>> 24) & 0xff];
      if (bigEndian) bytes.reverse();
      out.set(bytes, i * 4);
    });
    return out;
  }
  if (charset === "iso-8859-1") {
    const out = new Uint8Array(input.length);
    [...input].forEach((ch, i) => {
      if (ch.charCodeAt(0) > 255) throw new Error("character outside ISO-8859-1 range");
      out[i] = ch.charCodeAt(0);
    });
    return out;
  }
  if (charset === "windows-1252") {
    const bytes: number[] = [];
    for (const ch of input) {
      const mapped = CP1252_ENCODE.find(([from]) => from === ch);
      if (mapped) bytes.push(mapped[1]);
      else if (ch.charCodeAt(0) < 256) bytes.push(ch.charCodeAt(0));
      else throw new Error("character outside Windows-1252 range");
    }
    return new Uint8Array(bytes);
  }
  throw new Error(`Unsupported encoding: ${charset}`);
}

function decodeText(input: Uint8Array, charset: string): Uint8Array {
  if (charset === "utf-8") return input;
  if (charset === "utf-16le" || charset === "utf-16be") {
    const bigEndian = charset === "utf-16be";
    const units: number[] = [];
    for (let i = 0; i + 1 < input.length; i += 2) {
      units.push(bigEndian ? (input[i] << 8) | input[i + 1] : (input[i + 1] << 8) | input[i]);
    }
    return encoder.encode(String.fromCharCode(...units));
  }
  if (charset === "utf-32le" || charset === "utf-32be") {
    const bigEndian = charset === "utf-32be";
    let out = "";
    for (let i = 0; i + 3 < input.length; i += 4) {
      const bytes = [input[i], input[i + 1], input[i + 2], input[i + 3]];
      if (bigEndian) bytes.reverse();
      out += String.fromCodePoint(bytes[0] | (bytes[1] << 8) | (bytes[2] << 16) | (bytes[3] << 24));
    }
    return encoder.encode(out);
  }
  if (charset === "iso-8859-1") {
    return encoder.encode(Array.from(input, (b) => String.fromCharCode(b)).join(""));
  }
  if (charset === "windows-1252") {
    return encoder.encode(Array.from(input, (b) => CP1252_DECODE[b] ?? String.fromCharCode(b)).join(""));
  }
  throw new Error(`Unsupported encoding: ${charset}`);
}

function mimeCharsetDecode(charset: string, bytes: number[]): string {
  const key = charset.toLowerCase();
  if (key === "utf-8" || key === "utf8") return new TextDecoder("utf-8").decode(new Uint8Array(bytes));
  if (key === "us-ascii" || key === "ascii") return bytes.map((b) => String.fromCharCode(b)).join("");
  if (key === "iso-8859-1" || key === "latin-1" || key === "latin1") return bytes.map((b) => String.fromCharCode(b)).join("");
  throw new Error(`Unhandled Charset: ${charset} (only utf-8, us-ascii and iso-8859-1 are available natively)`);
}

function mimeQDecode(word: string): number[] {
  const bytes: number[] = [];
  for (let i = 0; i < word.length; i++) {
    if (word[i] === "_") bytes.push(32);
    else if (word[i] === "=") {
      const hex = word.slice(i + 1, i + 3);
      if (hex.length !== 2 || !/^[0-9a-fA-F]{2}$/.test(hex)) throw new Error("Incorrectly Encoded Word");
      bytes.push(Number.parseInt(hex, 16));
      i += 2;
    } else bytes.push(word.charCodeAt(i));
  }
  return bytes;
}

function mimeDecode(input: string): string {
  const source = input.replace(/\r\n/g, "\n");
  let decoded = "";
  let header = source;
  let betweenWords = false;
  for (;;) {
    const start = header.indexOf("=?");
    if (start < 0) break;
    let at = start + 2;
    const charsetRel = header.slice(at).indexOf("?");
    if (charsetRel < 0) break;
    const charset = header.slice(at, at + charsetRel);
    at += charsetRel + 1;
    if (header.length < at + 3) break;
    const encodingChar = header[at];
    at += 1;
    if (header[at] !== "?") break;
    at += 1;
    const wordRel = header.slice(at).indexOf("?=");
    if (wordRel < 0) break;
    const word = header.slice(at, at + wordRel);
    const end = at + wordRel + 2;
    let payload: number[];
    const encoding = encodingChar.toLowerCase();
    if (encoding === "b") {
      payload = Array.from(atob(word.replace(/\s+/g, "")), (c) => c.charCodeAt(0));
    } else if (encoding === "q") {
      payload = mimeQDecode(word);
    } else {
      decoded += header.slice(0, start + 2);
      header = header.slice(start + 2);
      betweenWords = false;
      continue;
    }
    if (start > 0 && (!betweenWords || /\S/.test(header.slice(0, start)))) {
      decoded += header.slice(0, start);
    }
    decoded += mimeCharsetDecode(charset, payload);
    header = header.slice(end);
    betweenWords = true;
  }
  return decoded + header;
}

function pemToHex(input: string): string {
  const outputs: string[] = [];
  const regex = /-----BEGIN ([A-Z][A-Z ]+[A-Z])-----/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(input)) !== null) {
    const bodyStart = match.index + match[0].length;
    const footer = `-----END ${match[1]}-----`;
    const footerAt = input.indexOf(footer, bodyStart);
    if (footerAt < 0) throw new Error(`PEM footer '${footer}' not found`);
    const body = input.slice(bodyStart, footerAt).replace(/\s+/g, "");
    const bin = atob(body);
    outputs.push(Array.from(bin, (c) => c.charCodeAt(0).toString(16).padStart(2, "0").toUpperCase()).join(""));
  }
  if (outputs.length === 0) throw new Error("No PEM blocks found");
  return outputs.join("\n");
}

function hexToPem(input: string, label: string): string {
  const clean = input.replace(/[^0-9a-fA-F]/g, "");
  if (clean.length % 2 !== 0) throw new Error("hex input has an odd number of digits");
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  const body = btoa(Array.from(bytes, (b) => String.fromCharCode(b)).join(""));
  const lines = (body.match(/.{1,64}/g) ?? []).join("\n");
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

const ASN1_TAGS: Record<number, string> = {
  0x01: "BOOLEAN", 0x02: "INTEGER", 0x03: "BITSTRING", 0x04: "OCTETSTRING", 0x05: "NULL",
  0x06: "ObjectIdentifier", 0x0a: "ENUMERATED", 0x0c: "UTF8String", 0x13: "PrintableString",
  0x14: "TeletexString", 0x16: "IA5String", 0x17: "UTCTime", 0x18: "GeneralizedTime",
  0x30: "SEQUENCE", 0x31: "SET",
};

function asn1TagLabel(tag: number): string {
  const known = ASN1_TAGS[tag];
  if (known) return known;
  if ((tag & 0xa0) === 0xa0) return `[${tag & 0x1f}]`;
  return `UNKNOWN(0x${tag.toString(16).padStart(2, "0")})`;
}

function asn1Oid(bytes: number[]): string {
  if (bytes.length === 0) return "";
  const first = bytes[0];
  const [arc1, arc2] = first < 40 ? [0, first] : first < 80 ? [1, first - 40] : [2, first - 80];
  const parts = [arc1, arc2];
  let value = 0;
  for (const b of bytes.slice(1)) {
    value = (value << 7) | (b & 0x7f);
    if ((b & 0x80) === 0) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join(".");
}

function asn1SkipLongHex(hex: string, limit: number): string {
  if (hex.length <= limit * 2) return hex;
  const total = hex.length / 2;
  return `${hex.slice(0, limit * 2)}..(total ${total}bytes)..${hex.slice(-limit * 2)}`;
}

function asn1ContentLength(hex: string, at: number): { length: number; width: number } | null {
  if (hex.length < at + 2) return null;
  const first = Number.parseInt(hex.slice(at, at + 2), 16);
  if (Number.isNaN(first)) return null;
  if ((first & 0x80) === 0) return { length: first * 2, width: 2 };
  const count = first & 0x7f;
  if (count === 0 || hex.length < at + 2 + count * 2) return null;
  let value = 0;
  for (let i = 0; i < count; i++) value = value * 256 + Number.parseInt(hex.slice(at + 2 + i * 2, at + 4 + i * 2), 16);
  return { length: value * 2, width: 2 + count * 2 };
}

function asn1Dump(hex: string, truncate: number, indent: string, out: string[]): void {
  if (hex.length < 4) return;
  const tag = Number.parseInt(hex.slice(0, 2), 16);
  const len = asn1ContentLength(hex, 2);
  if (!len) throw new Error("invalid ASN.1 length");
  const contentStart = 2 + len.width;
  const contentEnd = contentStart + len.length;
  if (contentEnd > hex.length) throw new Error("ASN.1 content length exceeds input");
  const content = hex.slice(contentStart, contentEnd);
  const label = asn1TagLabel(tag);
  if ((tag & 0x20) !== 0) {
    if (content.length === 0) {
      out.push(`${indent}${label} {}`);
      return;
    }
    out.push(`${indent}${label}`);
    let rest = content;
    while (rest.length > 0) {
      const child = asn1ContentLength(rest, 2);
      if (!child) throw new Error("truncated ASN.1 element");
      const childEnd = 2 + child.width + child.length;
      if (childEnd > rest.length) throw new Error("ASN.1 element exceeds input");
      asn1Dump(rest.slice(0, childEnd), truncate, `${indent}  `, out);
      rest = rest.slice(childEnd);
    }
  } else {
    let rendered = ` ${asn1SkipLongHex(content, truncate)}`;
    if (tag === 0x05) rendered = "";
    else if (tag === 0x01) rendered = content === "01" ? " TRUE" : " FALSE";
    else if (tag === 0x06) {
      const bytes: number[] = [];
      for (let i = 0; i < content.length; i += 2) bytes.push(Number.parseInt(content.slice(i, i + 2), 16));
      rendered = ` ${asn1Oid(bytes)} (${content})`;
    } else if ([0x0c, 0x13, 0x14, 0x16].includes(tag)) {
      const bytes: number[] = [];
      for (let i = 0; i < content.length; i += 2) bytes.push(Number.parseInt(content.slice(i, i + 2), 16));
      rendered = ` '${new TextDecoder().decode(new Uint8Array(bytes))}'`;
    }
    out.push(`${indent}${label}${rendered}`);
  }
}

function parseTlv(input: Uint8Array, typeSize: number, lengthSize: number, ber: boolean): string {
  if (typeSize === 0 && lengthSize === 0) throw new Error("Type or Length size must be greater than 0");
  const entries: Array<Record<string, unknown>> = [];
  let at = 0;
  const readLength = (): number => {
    if (ber) {
      const first = input[at];
      if (first < 0x80) {
        at += 1;
        return first;
      }
      const count = first & 0x7f;
      if (count === 0 || count > 4 || at + 1 + count > input.length) throw new Error("invalid BER length");
      let value = 0;
      for (const b of input.slice(at + 1, at + 1 + count)) value = (value << 8) | b;
      at += count + 1;
      return value;
    }
    if (lengthSize === 0) return 0;
    if (at + lengthSize > input.length) throw new Error("truncated TLV length");
    let value = 0;
    for (const b of input.slice(at, at + lengthSize)) value = (value << 8) | b;
    at += lengthSize;
    return value;
  };
  while (at < input.length) {
    const entry: Record<string, unknown> = {};
    if (typeSize > 0) {
      if (at + typeSize > input.length) throw new Error("truncated TLV type field");
      entry.key = Array.from(input.slice(at, at + typeSize));
      at += typeSize;
    }
    const length = readLength();
    if (at + length > input.length) throw new Error("truncated TLV value");
    entry.length = length;
    entry.value = Array.from(input.slice(at, at + length));
    at += length;
    entries.push(entry);
  }
  return JSON.stringify(entries, null, 4);
}

function changeIpFormat(input: string, inFormat: string, outFormat: string): string {
  const normalize = (f: string): string => {
    const key = f.trim().toLowerCase();
    if (key === "dotted decimal" || key === "dotted" || key === "dd") return "dd";
    if (key === "decimal" || key === "dec") return "decimal";
    if (key === "octal" || key === "oct") return "octal";
    if (key === "hex") return "hex";
    throw new Error("Unsupported IP format");
  };
  const inFmt = normalize(inFormat);
  const outFmt = normalize(outFormat);
  const lines: string[] = [];
  for (const line of input.split("\n")) {
    if (!line.trim()) continue;
    let bytes: number[];
    if (inFmt === "dd") {
      const octets = line.trim().split(".").map((o) => {
        const value = Number.parseInt(o, 10);
        if (Number.isNaN(value) || value < 0 || value > 255) throw new Error(`invalid octet '${o}'`);
        return value;
      });
      if (octets.length !== 4) throw new Error("dotted decimal requires exactly 4 octets");
      bytes = octets;
    } else {
      const radix = inFmt === "decimal" ? 10 : inFmt === "octal" ? 8 : 16;
      const value = Number.parseInt(line.trim(), radix);
      if (Number.isNaN(value) || value < 0 || value > 0xffffffff) {
        throw new Error(`'${line}' is not a valid ${inFmt} IPv4 value`);
      }
      bytes = [(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255];
    }
    if (outFmt === "dd") lines.push(bytes.join("."));
    else if (outFmt === "decimal") lines.push(String(((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0));
    else if (outFmt === "octal") lines.push(`0${(((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]) >>> 0).toString(8)}`);
    else lines.push(bytes.map((b) => b.toString(16).padStart(2, "0")).join(""));
  }
  return lines.join("\n");
}

function bigBytesToDecimal(bytes: number[]): string {
  const digits: number[] = [];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] << 8;
      digits[i] = carry % 10;
      carry = Math.floor(carry / 10);
    }
    while (carry > 0) {
      digits.push(carry % 10);
      carry = Math.floor(carry / 10);
    }
  }
  if (digits.length === 0) return "0";
  return digits.reverse().join("");
}

function bigDecimalToBytes(raw: string): number[] {
  if (!/^\d+$/.test(raw)) throw new Error(`'${raw}' is not a decimal integer`);
  const digits = [...raw].map((d) => Number.parseInt(d, 10));
  return Array.from(digitsToBytes(digits, 10));
}

function textIntegerConversion(input: string, outputFormat: string): string {
  const trimmed = input.trim();
  const isHex = trimmed.length > 2 && trimmed.toLowerCase().startsWith("0x") && /^[0-9a-f]*$/.test(trimmed.slice(2));
  const isDecimal = /^\d+$/.test(trimmed);
  let bytes: number[];
  if (isHex) {
    const clean = trimmed.slice(2);
    if (clean.length % 2 !== 0) throw new Error("hex input has an odd number of digits");
    bytes = [];
    for (let i = 0; i < clean.length; i += 2) bytes.push(Number.parseInt(clean.slice(i, i + 2), 16));
  } else if (isDecimal) {
    bytes = bigDecimalToBytes(trimmed);
  } else {
    const unquoted = (trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))
      ? trimmed.slice(1, -1)
      : trimmed;
    bytes = [];
    for (const [index, ch] of [...unquoted].entries()) {
      if (ch.charCodeAt(0) > 255) {
        throw new Error(`Character at position ${index} exceeds Latin-1 range (0-255).\nOnly ASCII and Latin-1 characters are supported.`);
      }
      bytes.push(ch.charCodeAt(0));
    }
  }
  if (outputFormat === "Decimal") return bigBytesToDecimal(bytes);
  if (outputFormat === "Hexadecimal") return `0x${bytes.map((b) => b.toString(16).padStart(2, "0")).join("")}`;
  return bytes.map((b) => String.fromCharCode(b)).join("");
}

function unicodeTextFormat(input: string, mode: string): string {
  const underline = mode === "underline" || mode === "both";
  const strikethrough = mode === "strikethrough" || mode === "both";
  let out = "";
  for (const ch of input) {
    out += ch;
    if (strikethrough) out += "\u0336";
    if (underline) out += "\u0332";
  }
  return out;
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
    case "to_base45": {
      const alphabet = expandAlphRange(param?.trim() || "0-9A-Z $%*+\\-./:");
      return encoder.encode(base45Encode(input, alphabet));
    }
    case "from_base45": {
      const tokens = (param ?? "").split(",").map((t) => t.trim());
      const strict = tokens.some((t) => t.toLowerCase() === "strict");
      const alphabet = expandAlphRange((tokens[0] || "").trim() || "0-9A-Z $%*+\\-./:");
      return base45Decode(decoder.decode(input), alphabet, strict);
    }
    case "to_base58": {
      return encoder.encode(base58Encode(input, base58Alphabet(param)));
    }
    case "from_base58": {
      return base58Decode(decoder.decode(input), base58Alphabet(param));
    }
    case "to_base58check": {
      const { alphabet, version } = base58checkAlphabetAndVersion(param);
      return encoder.encode(base58checkEncode(input, alphabet, version));
    }
    case "from_base58check": {
      const { alphabet } = base58checkAlphabetAndVersion(param);
      return base58checkDecode(decoder.decode(input), alphabet);
    }
    case "to_base62": {
      const alphabet = base62Alphabet(param);
      return encoder.encode(bytesToDigits(input, 62).reverse().map((d) => alphabet[d]).join(""));
    }
    case "from_base62": {
      const alphabet = base62Alphabet(param);
      const digits: number[] = [];
      for (const c of decoder.decode(input)) {
        const index = alphabet.indexOf(c);
        if (index >= 0) digits.push(index);
      }
      return digitsToBytes(digits, 62);
    }
    case "to_base85": {
      const { alphabet, standard } = base85Alphabet(param);
      return encoder.encode(base85Encode(input, alphabet, standard));
    }
    case "from_base85": {
      const { alphabet } = base85Alphabet(param);
      return base85Decode(decoder.decode(input), alphabet);
    }
    case "to_base92":
      return encoder.encode(base92Encode(input));
    case "from_base92":
      return base92Decode(decoder.decode(input));
    case "to_bech32": {
      const tokens = (param ?? "bc").split(",").map((t) => t.trim());
      const bech32m = (tokens[1] ?? "").toLowerCase() === "bech32m";
      return encoder.encode(bech32Encode(tokens[0] || "bc", input, bech32m));
    }
    case "from_bech32":
      return bech32Decode(decoder.decode(input));
    case "to_base": {
      const radix = Number.parseInt((param ?? "36").trim(), 10) || 36;
      if (radix < 2 || radix > 36) throw new Error("Error: Radix argument must be between 2 and 36");
      const source = decoder.decode(input).trim();
      const value = Number.parseFloat(source);
      if (Number.isNaN(value)) throw new Error("Error: Input must be a number");
      return encoder.encode(radixNumberToString(value, radix));
    }
    case "from_base": {
      const radix = Number.parseInt((param ?? "36").trim(), 10) || 36;
      if (radix < 2 || radix > 36) throw new Error("Error: Radix argument must be between 2 and 36");
      return encoder.encode(fromRadixNumber(decoder.decode(input).replace(/\s+/g, ""), radix));
    }
    case "to_octal":
      return encoder.encode(octalEncode(input, param ?? " "));
    case "from_octal":
      return octalDecode(decoder.decode(input), param ?? " ");
    case "to_bcd": {
      const { table, packed, signed, format } = bcdParams(param);
      const out = bcdEncode(decoder.decode(input), table, packed, signed, format);
      return typeof out === "string" ? encoder.encode(out) : out;
    }
    case "from_bcd": {
      const { table, packed, signed, format } = bcdParams(param);
      return encoder.encode(bcdDecode(input, table, packed, signed, format));
    }
    case "to_float": {
      const { littleEndian, double } = floatParam(param);
      return encoder.encode(floatEncode(input, littleEndian, double));
    }
    case "from_float": {
      const { double } = floatParam(param);
      return floatDecode(decoder.decode(input), double);
    }
    case "escape_unicode": {
      const tokens = (param ?? "\\u").split(",").map((t) => t.trim());
      const encodeAll = tokens.some((t) => t.toLowerCase() === "all");
      return encoder.encode(escapeUnicode(decoder.decode(input), tokens[0] || "\\u", encodeAll));
    }
    case "unescape_unicode":
      return encoder.encode(unescapeUnicode(decoder.decode(input), (param ?? "\\u").trim() || "\\u"));
    case "escape_smart_chars":
      return encoder.encode(escapeSmartChars(decoder.decode(input), param ?? "Include"));
    case "to_hex_content": {
      const tokens = (param ?? "").split(",").map((t) => t.trim());
      const mode = tokens[0]?.toLowerCase() === "all" ? "All chars"
        : tokens[0]?.toLowerCase() === "spaces" ? "Only special chars including spaces"
        : "Only special chars";
      return encoder.encode(hexContentEncode(input, mode, tokens.some((t) => t.toLowerCase() === "spaces")));
    }
    case "from_hex_content":
      return hexContentDecode(input);
    case "caret_m_decode":
      return caretMDecode(decoder.decode(input));
    case "to_modhex":
      return encoder.encode(modhexEncode(input, param ?? " "));
    case "from_modhex":
      return modhexDecode(decoder.decode(input));
    case "to_quoted_printable":
      return encoder.encode(quotedPrintableEncode(input));
    case "from_quoted_printable":
      return quotedPrintableDecode(input);
    case "to_punycode": {
      const mode = (param ?? "").trim().toLowerCase();
      const text = decoder.decode(input).trim();
      if (mode === "idn" || mode === "true") {
        return encoder.encode(text.split(".").map((label) => {
          if (/^[\x00-\x7f]*$/.test(label)) return label;
          return `xn--${punycodeEncode(label)}`;
        }).join("."));
      }
      return encoder.encode(punycodeEncode(decoder.decode(input)));
    }
    case "from_punycode": {
      const mode = (param ?? "").trim().toLowerCase();
      const text = decoder.decode(input).trim();
      if (mode === "idn" || mode === "true") {
        return encoder.encode(text.split(".").map((label) => {
          const lower = label.toLowerCase();
          if (lower.startsWith("xn--")) return punycodeDecode(lower.slice(4));
          return label;
        }).join("."));
      }
      return encoder.encode(punycodeDecode(decoder.decode(input)));
    }
    case "mime_decode":
      return encoder.encode(mimeDecode(decoder.decode(input)));
    case "pem_to_hex":
      return encoder.encode(pemToHex(decoder.decode(input)));
    case "hex_to_pem":
      return encoder.encode(hexToPem(decoder.decode(input), (param ?? "").trim() || "CERTIFICATE"));
    case "parse_asn1_hex_string": {
      const truncate = Number.parseInt((param ?? "32").trim(), 10) || 32;
      const cleaned = decoder.decode(input).replace(/[^0-9a-fA-F]/g, "").toLowerCase();
      const lines: string[] = [];
      asn1Dump(cleaned, truncate, "", lines);
      return encoder.encode(lines.join("\n") + "\n");
    }
    case "parse_tlv": {
      const tokens = (param ?? "1,1").split(",").map((t) => t.trim().toLowerCase());
      const typeSize = Number.parseInt(tokens[0] ?? "1", 10) || 0;
      const lengthSize = tokens.length > 1 ? Number.parseInt(tokens[1], 10) || 0 : 1;
      const ber = tokens[2] === "ber" || tokens[2] === "true";
      return encoder.encode(parseTlv(input, typeSize, lengthSize, ber));
    }
    case "change_ip_format": {
      const tokens = (param ?? "Dotted Decimal,Dotted Decimal").split(",");
      return encoder.encode(changeIpFormat(decoder.decode(input), tokens[0] ?? "Dotted Decimal", tokens[1] ?? "Dotted Decimal"));
    }
    case "text_integer_conversion":
      return encoder.encode(textIntegerConversion(decoder.decode(input), param ?? "String"));
    case "to_braille":
      return encoder.encode(brailleEncode(decoder.decode(input)));
    case "from_braille":
      return encoder.encode(brailleDecode(decoder.decode(input)));
    case "to_cobs":
      return cobsEncode(input);
    case "from_cobs":
      return cobsDecode(input);
    case "encode_text":
      return encodeText(decoder.decode(input), resolveCharset(param));
    case "decode_text":
      return decodeText(input, resolveCharset(param));
    case "unicode_text_format":
      return encoder.encode(unicodeTextFormat(decoder.decode(input), (param ?? "").trim().toLowerCase() || "none"));
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
