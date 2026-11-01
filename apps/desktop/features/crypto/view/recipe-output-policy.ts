export type RecipeOutputMode = "text" | "hex" | "image";

export interface RecipeOutputCapabilities {
  hasBytes: boolean;
  canText: boolean;
  canHex: boolean;
  canImage: boolean;
  canDownload: boolean;
  canCopy: boolean;
}

export function outputCapabilities(
  result: { outputBytes: Uint8Array; error?: unknown } | null,
  mode: RecipeOutputMode,
  imageMime: string | null,
  supportsImageClipboard = false,
): RecipeOutputCapabilities {
  const hasBytes = result !== null && !result.error && result.outputBytes.length > 0;
  let canText = false;
  if (hasBytes) {
    try {
      new TextDecoder("utf-8", { fatal: true }).decode(result.outputBytes);
      canText = true;
    } catch {
      canText = false;
    }
  }
  const canHex = hasBytes;
  const canImage = hasBytes && imageMime !== null;
  return {
    hasBytes,
    canText,
    canHex,
    canImage,
    canDownload: hasBytes,
    canCopy: (mode === "text" && canText)
      || (mode === "hex" && canHex)
      || (mode === "image" && canImage && imageMime === "image/png" && supportsImageClipboard),
  };
}
