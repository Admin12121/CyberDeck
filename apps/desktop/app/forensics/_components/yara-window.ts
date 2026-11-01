/** Bounded native YARA-style scan window selection; no implicit whole-file claim. */
export const MAX_YARA_WINDOW_BYTES = 1024 * 1024;
export function yaraScanWindow(fileSize: number, offset: number): { offset: number; len: number } | null {
  if (!Number.isSafeInteger(fileSize) || !Number.isSafeInteger(offset) ||
      fileSize < 1 || offset < 0 || offset >= fileSize) return null;
  return { offset, len: Math.min(fileSize - offset, MAX_YARA_WINDOW_BYTES) };
}
