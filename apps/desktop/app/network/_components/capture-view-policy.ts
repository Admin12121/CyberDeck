/** Pure frontend bounds/identity policy. Backend authorization is always authoritative. */
export interface CaptureReference {
  id: number;
  revision: number;
}
export interface CaptureIdentity {
  session_id: number;
  case_id: string;
}
export function captureLimits(
  maxPackets: string,
  memoryMiB: string,
  durationSeconds: string,
): { max_packets: number; max_bytes: number; duration_ms: number } | null {
  const count = Number(maxPackets);
  const memory = Number(memoryMiB);
  const seconds = Number(durationSeconds);
  if (![count, memory, seconds].every(Number.isInteger)
    || count < 1 || count > 20_000
    || memory < 1 || memory > 16
    || seconds < 1 || seconds > 600) return null;
  return { max_packets: count, max_bytes: memory * 1024 * 1024, duration_ms: seconds * 1000 };
}
export function activeCaptureId(reference: CaptureReference | null, revision: number | null): number | null {
  return reference && revision !== null && reference.revision === revision
    && Number.isSafeInteger(reference.id) && reference.id > 0 ? reference.id : null;
}
export function matchesCaptureIdentity(
  status: CaptureIdentity,
  sessionId: number | null,
  selectedCase: string,
): boolean {
  return sessionId !== null && status.session_id === sessionId && status.case_id === selectedCase;
}
export function boundedPageOffset(current: number, total: number, delta: number, size = 100): number | null {
  if (!Number.isSafeInteger(current) || !Number.isSafeInteger(total)
    || !Number.isSafeInteger(delta) || size < 1 || size > 256) return null;
  const next = current + delta * size;
  return next >= 0 && next < total ? next : null;
}
