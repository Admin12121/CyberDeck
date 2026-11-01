import { invoke } from "@tauri-apps/api/core";
import { isDesktop, type CaseReportWire, type CaseIntegritySummaryWire } from "@lib/ipc";

export type ReviewState =
  | "indexed_verified" | "indexed_unverified" | "indexed_missing"
  | "indexed_tampered" | "unindexed_published" | "staged_incomplete"
  | "unrecognized_file" | "unsafe_entry";
export interface ReviewEntry {
  name: string;
  artifact_id: string | null;
  state: ReviewState;
  size: number | null;
  sha256: string | null;
}
export interface EvidenceReview {
  case_id: string;
  entries: ReviewEntry[];
  truncated: boolean;
}
export interface CaseArtifactReference {
  case_id: string;
  artifact_id: string;
  sha256: string;
  size: number;
  kind: "packet-capture" | "file";
  session_revision: number;
}
function requireNative() {
  if (!isDesktop()) throw new Error("Cases require the CyberDeck native desktop runtime.");
}
export async function resumeSelectedCase(): Promise<CaseReportWire> {
  requireNative();
  return invoke<CaseReportWire>("case_resume_scoped_v1");
}
export async function reviewSelectedEvidence(): Promise<EvidenceReview> {
  requireNative();
  return invoke<EvidenceReview>("case_evidence_review_scoped_v1");
}
export async function verifySelectedCase(): Promise<CaseIntegritySummaryWire> {
  requireNative();
  return invoke<CaseIntegritySummaryWire>("case_integrity_scoped_v1");
}
export async function scopedArtifactReference(artifactId: string): Promise<CaseArtifactReference> {
  requireNative();
  return invoke<CaseArtifactReference>("case_artifact_reference_scoped_v1", { artifactId });
}

export interface CopyReceiptV1 {
  source_case_id: string;
  target_case_id: string;
  artifact_id: string;
  sha256: string;
  size: number;
}
export async function copySelectedArtifactToExisting(artifactId: string, targetCaseId: string): Promise<CopyReceiptV1> {
  requireNative();
  return invoke<CopyReceiptV1>("case_copy_artifact_to_existing_v1", { artifactId, targetCaseId });
}
