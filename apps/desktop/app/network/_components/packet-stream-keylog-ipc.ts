/**
 * Typed IPC client for the TLS 1.3 keylog import (Wireshark SSLKEYLOGFILE
 * parity, passive analysis of already-captured traffic).
 *
 * Component-local client following the pcap-export-ipc.ts convention: the
 * canonical client home is lib/ipc.ts; these wrappers mirror the Rust serde
 * struct `KeylogStatusWire` in
 * src-tauri/src/features/network/ipc/pcap.rs exactly. No keylog content
 * ever crosses this boundary — only counts and a file name.
 */
import { invoke } from "@tauri-apps/api/core";
import { isDesktop } from "@lib/ipc";

export interface KeylogStatusWire {
  attached: boolean;
  file_name: string;
  /** Accepted TLS 1.3 traffic-secret entries. */
  entries: number;
  /** Distinct connections (ClientHello randoms) the keylog covers. */
  connections: number;
  /** Collapsed duplicate (random, label) lines. */
  duplicates: number;
  /** Recognized-but-ignored lines (TLS 1.2-era labels). */
  ignored_lines: number;
  /** True when the attachment's case session matches the caller's. */
  active_for_session: boolean;
}

/**
 * Open the native file dialog, parse the NSS keylog (bounded, strict) and
 * attach it to the current case session. Replaces any prior attachment.
 */
export async function packetStreamKeylogAttachV1(): Promise<KeylogStatusWire> {
  if (!isDesktop()) throw new Error("keylog import requires the desktop runtime");
  return invoke<KeylogStatusWire>("packet_stream_keylog_attach_v1", {});
}

/** Current attachment status for the selected case session. */
export async function packetStreamKeylogStatusV1(): Promise<KeylogStatusWire> {
  if (!isDesktop()) throw new Error("keylog status requires the desktop runtime");
  return invoke<KeylogStatusWire>("packet_stream_keylog_status_v1", {});
}

/** Detach the keylog; transcripts fall back to the ciphertext view. */
export async function packetStreamKeylogClearV1(): Promise<KeylogStatusWire> {
  if (!isDesktop()) throw new Error("keylog clear requires the desktop runtime");
  return invoke<KeylogStatusWire>("packet_stream_keylog_clear_v1", {});
}

/** One-line import state for the card; honest when nothing is attached. */
export function keylogCardLine(status: KeylogStatusWire | null): string {
  if (!status || !status.attached) {
    return "TLS 1.3 keylog — none imported; stream transcripts stay ciphertext";
  }
  const scope = status.active_for_session
    ? "applied on stream follow"
    : "attached to another case session";
  return (
    `TLS 1.3 keylog — ${status.connections} connection(s) covered · ` +
    `${status.entries} secret(s) · ${status.file_name} · ${scope}`
  );
}
