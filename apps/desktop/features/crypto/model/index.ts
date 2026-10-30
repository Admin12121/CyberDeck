/**
 * Crypto feature model layer.
 * Pure types, catalog and pipeline evaluation for the Recipes workspace.
 * Operations run deterministically over bytes; heavier crypto (hashes, HMAC)
 * moves to the Rust core in arc 2 (Master Plan §5.4).
 */

export type OperationCategory = "encoding" | "transforms" | "parsing";

export interface Operation {
  id: string;
  label: string;
  category: OperationCategory;
  description: string;
}

export interface RecipeStep {
  opId: string;
  enabled: boolean;
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
  byteLength: number;
  elapsedMs: number;
  error?: RecipeError;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const OPERATIONS: Operation[] = [
  { id: "to_base64", label: "To Base64", category: "encoding", description: "Encode bytes to Base64" },
  { id: "from_base64", label: "From Base64", category: "encoding", description: "Decode Base64 to bytes" },
  { id: "to_hex", label: "To Hex", category: "encoding", description: "Encode bytes to hexadecimal" },
  { id: "from_hex", label: "From Hex", category: "encoding", description: "Decode hexadecimal to bytes" },
  { id: "url_encode", label: "URL Encode", category: "encoding", description: "Percent-encode text" },
  { id: "url_decode", label: "URL Decode", category: "encoding", description: "Decode percent-encoding" },
  { id: "reverse", label: "Reverse", category: "transforms", description: "Reverse byte order" },
  { id: "rot13", label: "ROT13", category: "transforms", description: "Classical Caesar shift by 13" },
  { id: "to_utf8", label: "To Text (UTF-8)", category: "parsing", description: "Interpret bytes as UTF-8 text" },
];

export function operationById(id: string): Operation | undefined {
  return OPERATIONS.find((op) => op.id === id);
}

/** Apply one operation. Throws with a user-facing message on bad input. */
function applyOperation(opId: string, input: Uint8Array): Uint8Array {
  const text = () => decoder.decode(input);
  switch (opId) {
    case "to_base64": {
      const bin = Array.from(input, (b) => String.fromCharCode(b)).join("");
      // chunk to avoid argument limits on very large inputs
      const chunks: string[] = [];
      const size = 0x8000;
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
    case "to_hex":
      return encoder.encode(Array.from(input, (b) => b.toString(16).padStart(2, "0")).join(""));
    case "from_hex": {
      const clean = text().replace(/[^0-9a-fA-F]/g, "");
      if (clean.length % 2 !== 0) throw new Error("hex input has an odd number of digits");
      const out = new Uint8Array(clean.length / 2);
      for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
      return out;
    }
    case "url_encode":
      return encoder.encode(encodeURIComponent(text()));
    case "url_decode":
      return encoder.encode(decodeURIComponent(text().replace(/\+/g, "%20")));
    case "reverse": {
      const out = input.slice();
      out.reverse();
      return out;
    }
    case "rot13":
      return encoder.encode(
        text().replace(/[a-zA-Z]/g, (ch) => {
          const base = ch <= "Z" ? 65 : 97;
          return String.fromCharCode(((ch.charCodeAt(0) - base + 13) % 26) + base);
        }),
      );
    case "to_utf8":
      return input; // identity on bytes; normalization happens at render
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
      bytes = applyOperation(step.opId, bytes);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return {
        output: "",
        byteLength: bytes.length,
        elapsedMs: performance.now() - started,
        error: { stepIndex: i, opId: step.opId, message },
      };
    }
  }
  const printable = (() => {
    try {
      return decoder.decode(bytes);
    } catch {
      return "";
    }
  })();
  return {
    output: printable,
    byteLength: bytes.length,
    elapsedMs: performance.now() - started,
  };
}
