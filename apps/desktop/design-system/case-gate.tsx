"use client";
/**
 * The ONE case gate. Any tool surface that can only persist results into a
 * saved case renders this strip; when the case is linked it renders nothing.
 * Tools never create cases here — the gate routes to the central surfaces
 * (start-page create form, Cases page) and the status bar remains the
 * universal case switcher. Replaces the per-view AuthorizedCaseAction banners
 * and their duplicated auto-create flows.
 */
import { useRouter } from "next/navigation";
import { FolderOpen, FolderPlus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { InfoTip } from "@ds/compact";
import { useCaseReady, useWorkbenchCase } from "@state/workbench";

export function CaseGate({ activity }: { activity: string }) {
  const router = useRouter();
  const { caseReady, isScratchpad } = useCaseReady();
  const { caseSession } = useWorkbenchCase();
  if (caseReady) return null;

  const state = caseSession.phase === "error"
    ? "Case unavailable"
    : caseSession.phase === "selecting"
      ? "Linking case…"
      : isScratchpad
        ? "Temporary workspace"
        : "Waiting for the selected case";

  return (
    <section aria-label="Saved case required" className="border-b border-line bg-panel px-3 py-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium text-fg">{state}</span>
        <InfoTip
          text={`${activity} requires a saved case so results, permissions and evidence stay isolated. Cases are created on the start page or managed on the Cases page; the status bar switches the active case at any time. Creating a case does not begin an active operation, and the backend re-authorizes every case selection.`}
        />
        <span className="flex-1" />
        <Button size="xs" onClick={() => router.push("/?new=1")}>
          <FolderPlus size={13} aria-hidden="true" /> New case
        </Button>
        <Button size="xs" variant="outline" onClick={() => router.push("/cases")}>
          <FolderOpen size={13} aria-hidden="true" /> Choose case
        </Button>
      </div>
      <p className="mt-1 text-2xs text-fg-muted">
        {activity} requires a saved case — results, permissions and evidence stay isolated.
      </p>
      {caseSession.phase === "error" && caseSession.error ? (
        <p role="alert" className="mt-1 text-xs text-err">{caseSession.error}</p>
      ) : null}
    </section>
  );
}
