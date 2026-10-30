/**
 * Forensics feature — model layer.
 * Sample evidence set for the evidence-first layout (§5.6): file tree, hex/
 * preview, metadata, signatures, entropy. Real parsers (signature scanning,
 * metadata extraction, YARA-X) arrive arc 2 through the Rust core; originals
 * stay immutable and every export records SHA-256.
 */

export interface EvidenceFile {
  id: string;
  name: string;
  path: string;
  size: number;
  sha256: string;
  signature: string;
  entropy: number;
  group: "samples" | "archives" | "logs";
}

export const SAMPLE_EVIDENCE: EvidenceFile[] = [
  {
    id: "note",
    name: "incident-note.txt",
    path: "samples/incident-note.txt",
    size: 84,
    sha256: "c1a0 Hawai… (arc 2: real hashing)",
    signature: "ASCII text",
    entropy: 4.2,
    group: "samples",
  },
  {
    id: "cfg",
    name: "service.cfg",
    path: "samples/service.cfg",
    size: 132,
    sha256: "(arc 2: real hashing)",
    signature: "ASCII text",
    entropy: 4.9,
    group: "samples",
  },
  {
    id: "bin",
    name: "firmware-header.bin",
    path: "archives/firmware-header.bin",
    size: 256,
    sha256: "(arc 2: real hashing)",
    signature: "data (unrecognized header)",
    entropy: 7.4,
    group: "archives",
  },
  {
    id: "log",
    name: "auth.log",
    path: "logs/auth.log",
    size: 210,
    sha256: "(arc 2: real hashing)",
    signature: "ASCII text",
    entropy: 5.1,
    group: "logs",
  },
];

/** Deterministic sample content per evidence id — stands in for arc-2 parsers. */
export function sampleContent(id: string): Uint8Array {
  const texts: Record<string, string> = {
    note:
      "Incident note: unauthorized login attempts observed from 10.0.0.90 between 02:00 and 02:15.\r\n" +
      "Related evidence: logs/auth.log, samples/service.cfg\r\n" +
      "Analyst: admin12121\r\n",
    cfg:
      "# service configuration (lab fixture)\r\n" +
      "listen=0.0.0.0:8080\r\n" +
      "tls=false\r\n" +
      "admin_password_hash=$2y$10$abcdefghijklmnopqrstuv\r\n" +
      "session_timeout=3600\r\n",
    log:
      "Oct 30 02:00:11 lab sshd[4211]: Failed password for admin from 10.0.0.90 port 51022\r\n" +
      "Oct 30 02:01:03 lab sshd[4211]: Failed password for admin from 10.0.0.90 port 51023\r\n" +
      "Oct 30 02:14:59 lab sshd[4211]: Accepted password for admin from 10.0.0.90 port 51190\r\n" +
      "Oct 30 02:15:02 lab sudo: admin : COMMAND=/usr/bin/id\r\n",
  };
  if (id === "bin") {
    // synthetic firmware-ish header: magic + padding + strings region
    const magic = new Uint8Array([0x46, 0x57, 0x48, 0x44, 0x01, 0x00, 0x00, 0x00]);
    const text = new TextEncoder().encode("FWHD v1.2 build 2026.10 vendor=LabCorp model=XW-40\0bootloader=uboot\0signed=yes\0");
    const padding = new Uint8Array(256 - magic.length - text.length).fill(0xff);
    const out = new Uint8Array(256);
    out.set(magic, 0);
    out.set(text, magic.length);
    out.set(padding, magic.length + text.length);
    return out;
  }
  return new TextEncoder().encode(texts[id] ?? "");
}

export interface MetadataRow {
  key: string;
  value: string;
}

export function sampleMetadata(file: EvidenceFile): MetadataRow[] {
  return [
    { key: "path", value: file.path },
    { key: "size", value: `${file.size} bytes` },
    { key: "signature", value: file.signature },
    { key: "entropy", value: `${file.entropy.toFixed(2)} bits/byte` },
    { key: "sha256", value: file.sha256 },
    { key: "imported", value: "2026-10-31 (session fixture)" },
    { key: "exiftool", value: "engine integration arc 2" },
  ];
}
