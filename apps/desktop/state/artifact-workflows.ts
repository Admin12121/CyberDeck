import type { ToolId } from "@state/tool-registry";

/** A reference to backend-owned evidence; never an embedded byte payload. */
export type ArtifactDataKind =
  | "file" | "bytes" | "text" | "hash" | "http-request" | "http-response"
  | "packet-capture" | "packet" | "url" | "finding";

export interface ArtifactReference {
  caseId: string;
  artifactId: string;
  kind: ArtifactDataKind;
  sha256?: string;
  derivedFromId?: string;
  owner?: ToolId;
}

export type TransferVerb = "open" | "send" | "analyze" | "decode" | "save-evidence";

export interface ArtifactConsumer {
  toolId: ToolId;
  accepts: readonly ArtifactDataKind[];
  actions: readonly TransferVerb[];
}

/**
 * Capability discovery only. Actual transfer must call an authorized
 * Rust-backed operation that re-checks case, artifact and provenance.
 * Registration is intentionally empty until owning agents integrate.
 */
export function compatibleArtifactTargets(
  ref: ArtifactReference,
  activeCaseId: string,
  consumers: readonly ArtifactConsumer[],
): ArtifactConsumer[] {
  if (!ref.artifactId.trim() || !ref.caseId.trim() || ref.caseId !== activeCaseId ||
      activeCaseId === "scratchpad") return [];
  return consumers.filter((consumer) => consumer.accepts.includes(ref.kind));
}
