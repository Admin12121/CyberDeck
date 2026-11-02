"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { FolderPlus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { caseCreate, isDesktop } from "@/lib/ipc";
import { useWorkbenchCase } from "@/state/workbench";

/**
 * Native active operations must have a backend-selected saved case.
 * Keep the secure constraint, but provide an immediately usable path
 * instead of presenting disabled controls with no next action.
 */
export function AuthorizedCaseAction({ activity, onCaseCreated }: { activity: string; onCaseCreated?: (caseId: string) => void }) {
  const { caseId, caseSession, setCaseId } = useWorkbenchCase();
  const router = useRouter();
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  if (caseId !== "scratchpad" && caseSession.phase === "ready" && caseSession.caseId === caseId) {
    return null;
  }
  const create = async () => {
    if (!isDesktop() || creating) return;
    setCreating(true);
    setError(null);
    try {
      const title = activity + " · " + new Date().toLocaleString();
      const record = await caseCreate(title, "Investigation created explicitly before " + activity.toLowerCase());
      // The shared workbench performs the authoritative native session selection.
      // Explicit create-case action may carry an operator-authored non-secret
      // draft into the new case; never transfer recovery results or credentials.
      onCaseCreated?.(record.id);
      setCaseId(record.id);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setCreating(false);
    }
  };
  return (
    <section aria-label="Enable authorized operation" className="border-b border-line bg-panel px-3 py-3">
      <p className="text-xs font-medium text-fg">
        {caseId === "scratchpad" ? "Select or create an investigation case" : "Waiting for the selected investigation"}
      </p>
      <p className="mt-1 text-[11px] leading-relaxed text-fg-muted">
        {activity} requires a saved case so results, permissions and evidence stay isolated.
        Creating a case does not begin an active operation.
      </p>
      <div className="mt-2 flex flex-wrap gap-2">
        <Button size="sm" onClick={() => void create()} disabled={!isDesktop() || creating}>
          <FolderPlus size={14} aria-hidden="true" /> {creating ? "Creating case…" : "Create case"}
        </Button>
        <Button size="sm" variant="outline" onClick={() => router.push("/cases")}>
          Choose existing case
        </Button>
      </div>
      {caseSession.phase === "error" && caseSession.error && <p role="alert" className="mt-2 text-xs text-err">{caseSession.error}</p>}
      {error && <p role="alert" className="mt-2 text-xs text-err">{error}</p>}
    </section>
  );
}
