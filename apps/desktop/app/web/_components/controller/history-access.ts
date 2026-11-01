/** Feature-local typed bridge. Server state, not UI, grants sensitive access. */
import { invoke } from "@tauri-apps/api/core";
import { isDesktop, type HttpResponseWire } from "@lib/ipc";

export interface ProtectedHistoryDetail {
  id: number;
  url: string;
  request_head: string;
  request_body_base64: string | null;
  status: number;
  response_headers: [string, string][];
  response_body_base64: string | null;
  request_truncated: boolean;
  response_truncated: boolean;
  decoded_message: boolean;
  forwarded_method: string | null;
  forwarded_url: string | null;
  forwarded_headers: [string, string][] | null;
  forwarded_body_base64: string | null;
  forwarded_truncated: boolean;
  forwarded_decoded_message: boolean;
  original_wire_exact: boolean;
}

export type ProtectedHistoryAccess =
  | { kind: "detail"; data: ProtectedHistoryDetail }
  | { kind: "replay"; data: HttpResponseWire & { body_base64: string; body_is_utf8: boolean } };

export async function protectedHistoryAccess(
  id: number, action: "detail" | "replay", forwarded = false,
): Promise<ProtectedHistoryAccess> {
  if (!isDesktop()) throw new Error("Protected History requires the desktop application");
  if (!Number.isSafeInteger(id) || id < 1) throw new Error("Invalid captured request ID");
  // The native command asks for OS approval and issues a one-use policy permit.
  // No user-supplied case/authorization bool or permit is carried here.
  return invoke<ProtectedHistoryAccess>("web_history_access_v1", { id, action, forwarded });
}

export function decodedBody(base64: string | null): Uint8Array | null {
  if (base64 === null) return null;
  try {
    const raw = atob(base64);
    return Uint8Array.from(raw, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

/** Editable Unicode draft ONLY; never turn captured binary into lossy text. */
export function editableHistoryDraft(
  detail: ProtectedHistoryDetail, forwarded: boolean,
): string | null {
  if (forwarded) {
    const url = detail.forwarded_url;
    const method = detail.forwarded_method;
    const headers = detail.forwarded_headers;
    if (!url || !method || !headers || detail.forwarded_truncated) return null;
    const body = decodedBody(detail.forwarded_body_base64);
    if (body === null) return null;
    let text: string;
    try { text = new TextDecoder("utf-8", { fatal: true }).decode(body); }
    catch { return null; }
    const endpoint = new URL(url);
    if (!["http:", "https:"].includes(endpoint.protocol)) return null;
    const supplied = headers.filter(([name]) => !["host", "content-length", "transfer-encoding"]
      .includes(name.toLowerCase()));
    return `${method} ${endpoint.pathname || "/"}${endpoint.search} HTTP/1.1\r\nHost: ${endpoint.host}\r\n${supplied.map(([name, value]) => `${name}: ${value}\r\n`).join("")}Content-Length: ${new TextEncoder().encode(text).length}\r\n\r\n${text}`;
  }
  if (detail.request_truncated) return null;
  const body = decodedBody(detail.request_body_base64);
  if (body === null) return null;
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(body);
    return `${detail.request_head.trimEnd()}\r\n\r\n${text}`;
  } catch { return null; }
}
