/** In-memory, nonsecret native capture session IDs across route mounts.
 * Backend still authorizes every read and stop using its active case generation.
 * Never store packet bytes, frame data, or sensitive payloads here.
 */
const sessions = new Map<string, number>();
const subscribers = new Set<() => void>();
const MAX_REFS = 12;
export function sessionKey(caseId: string, revision: number | null): string {
  return caseId + ":" + String(revision);
}
export function rememberNativeSession(key: string, id: number): void {
  if (!Number.isSafeInteger(id) || id <= 0) return;
  if (!sessions.has(key) && sessions.size >= MAX_REFS) {
    const oldest = sessions.keys().next().value;
    if (oldest) sessions.delete(oldest);
  }
  sessions.set(key, id);
  for (const notify of subscribers) notify();
}
export function currentNativeSession(key: string): number | null {
  return sessions.get(key) ?? null;
}
export function dropNativeSession(key: string): void {
  if (!sessions.delete(key)) return;
  for (const notify of subscribers) notify();
}
export function subscribeNativeSessions(notify: () => void): () => void {
  subscribers.add(notify);
  return () => { subscribers.delete(notify); };
}
