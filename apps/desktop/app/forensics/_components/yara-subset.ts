/** Forensics-owned, strictly bounded native YARA-style literal scan interface. */
import { invoke } from "@tauri-apps/api/core";
import { isDesktop } from "@lib/ipc";

export const MAX_YARA_SOURCE_BYTES = 4096;
import { MAX_YARA_WINDOW_BYTES } from "./yara-window";

export interface YaraSubsetResponse {
  rule: string;
  matched: boolean;
  hits: { identifier: string; offset: number }[];
  analyzed_offset: number;
  analyzed_bytes: number;
  file_bytes: number;
  integrity_checked: boolean;
  coverage_truncated: boolean;
  language_subset: string;
}

/** Backend remains authoritative for case, artifact integrity, grammar and rule limits. */
export async function fileYaraSubsetScan(
  caseId: string, artifactId: string, offset: number, len: number, ruleSource: string,
): Promise<YaraSubsetResponse> {
  if (!isDesktop()) throw new Error("YARA-style literal scan requires native desktop runtime");
  if (!caseId.trim() || !artifactId.trim()) throw new Error("Case-backed artifact required");
  if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(len) ||
      len < 1 || len > MAX_YARA_WINDOW_BYTES) throw new Error("Invalid bounded scan window");
  if (!ruleSource || ruleSource.length > MAX_YARA_SOURCE_BYTES || !/^[\x00-\x7F]*$/.test(ruleSource)) {
    throw new Error("Rule must contain 1–4096 ASCII bytes");
  }
  return invoke<YaraSubsetResponse>("file_yara_subset_scan", {
    caseId, id: artifactId, offset, len, ruleSource,
  });
}
