/**
 * Hash format identification: real heuristics over the input string.
 * Deliberately conservative: candidates carry confidence and are never
 * presented as fact (Master Plan §5.5: no guessing ambiguous algorithms).
 */

export interface HashFormatCandidate {
  format: string;
  confidence: "high" | "medium" | "low";
  note: string;
  gpuCapable: boolean;
}

const HEX_RE = /^[0-9a-fA-F]+$/;

export function detectHashFormats(input: string): HashFormatCandidate[] {
  const value = input.trim();
  if (!value) return [];
  const candidates: HashFormatCandidate[] = [];

  const hexLen = (len: number, format: string, gpuCapable: boolean, note: string, confidence: HashFormatCandidate["confidence"] = "high") => {
    if (value.length === len && HEX_RE.test(value)) {
      candidates.push({ format, confidence, note, gpuCapable });
    }
  };

  hexLen(32, "MD5 / NTLM / MD4 family", true, "32 hex characters; different algorithms share this shape", "medium");
  hexLen(40, "SHA-1 / MySQL5 / RIPEMD-160", true, "40 hex characters; multiple algorithms share this shape", "medium");
  hexLen(64, "SHA-256 / SHA3-256 / BLAKE2s-256", true, "64 hex characters; multiple algorithms share this shape", "medium");
  hexLen(96, "SHA-384", true, "96 hex chars");
  hexLen(128, "SHA-512 / Whirlpool / BLAKE2b-512", true, "128 hex characters; multiple algorithms share this shape", "medium");
  hexLen(16, "MySQL pre-4.1", false, "16 hex chars, legacy MySQL password hash", "medium");
  hexLen(41, "MySQL5 (SHA-1 with seed)", true, "leading '*' + 40 hex chars", "medium");

  if (/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(value)) {
    candidates.push({ format: "bcrypt", confidence: "high", note: "$2*$ modular crypt format", gpuCapable: false });
  }
  if (/^\$argon2(id|i|d)\$/.test(value)) {
    candidates.push({ format: "argon2 (id/i/d)", confidence: "high", note: "Memory-hard KDF; not supported by SHA-256 Recovery V1", gpuCapable: false });
  }
  if (/^\$y\$/.test(value)) {
    candidates.push({ format: "yescrypt", confidence: "high", note: "yescrypt-style prefix; outside SHA-256 Recovery V1", gpuCapable: true });
  }
  if (/^\$7\$/.test(value)) {
    candidates.push({ format: "yescrypt (scrypt field)", confidence: "medium", note: "libxcrypt scrypt-style prefix, often yescrypt in modern shadows", gpuCapable: true });
  }
  if (/^\$6\$/.test(value)) {
    candidates.push({ format: "sha512crypt", confidence: "high", note: "Unix crypt-style prefix; outside Recovery V1", gpuCapable: true });
  }
  if (/^\$5\$/.test(value)) {
    candidates.push({ format: "sha256crypt", confidence: "high", note: "Unix crypt-style prefix; outside Recovery V1", gpuCapable: true });
  }
  if (/^\$NT\$/.test(value)) {
    candidates.push({ format: "NTLM (pass-the-hash form)", confidence: "high", note: "$NT$ prefix", gpuCapable: true });
  }
  if (/^[a-f0-9]{32}:[a-f0-9]{32}:/.test(value.toLowerCase())) {
    candidates.push({ format: "NetNTLMv1/v2 challenge-response", confidence: "medium", note: "user:domain:response structure", gpuCapable: true });
  }
  if (/^\$krb5pa\$/.test(value) || /^\$krb5i?\$/.test(value)) {
    candidates.push({ format: "Kerberos AS-REP / TGS-REP", confidence: "high", note: "Kerberos etype hash", gpuCapable: true });
  }
  if (/^[A-Za-z0-9+/]{20,}={0,2}$/.test(value) && value.length >= 40 && !HEX_RE.test(value)) {
    candidates.push({ format: "unknown (base64-like)", confidence: "low", note: "not a recognized digest shape; inspect manually or via recipes", gpuCapable: false });
  }

  if (candidates.length === 0) {
    candidates.push({
      format: "unrecognized",
      confidence: "low",
      note: "no known format matches this input",
      gpuCapable: false,
    });
  }
  return candidates;
}
