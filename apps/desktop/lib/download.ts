/** One browser download path for derived output, reports, and certificate exports. */
export function downloadContent(
  content: string | Uint8Array,
  filename: string,
  mime = "application/octet-stream",
): void {
  if ((typeof content === "string" ? content.length : content.byteLength) === 0) {
    throw new Error("Cannot download empty content");
  }
  const payload = typeof content === "string" ? content : Uint8Array.from(content);
  const url = URL.createObjectURL(new Blob([payload], { type: mime }));
  try {
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.click();
  } finally {
    // Some browsers need the object URL to survive until the download begins.
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}
