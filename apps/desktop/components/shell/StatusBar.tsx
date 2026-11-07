"use client";
/**
 * Status bar: transport, case state, runtime (§3.5). Case management lives on
 * the home page (create, open) and the Cases page (full list); this bar only
 * READS OUT the current linkage state — no switcher, no create form.
 */
import { isDesktop } from "@lib/ipc";
import { useEffect, useState } from "react";
import { useCaseReady, useWorkbenchCase } from "@state/workbench";

export function StatusBar() {
  const { caseSession } = useWorkbenchCase();
  const { caseReady, isScratchpad } = useCaseReady();
  const [runtime, setRuntime] = useState<"checking" | "native" | "browser">("checking");
  useEffect(() => { setRuntime(isDesktop() ? "native" : "browser"); }, []);

  return (
    <footer className="flex min-h-9 shrink-0 items-center gap-2 overflow-x-auto whitespace-nowrap border-t border-line bg-sidebar px-3 text-xs text-fg-muted" aria-label="Case and runtime status">
      {caseSession.phase === "selecting" ? <span role="status">Linking…</span> : null}
      {caseReady ? <span role="status" title="Backend-selected active case">Linked</span> : null}
      {caseSession.phase === "idle" && isScratchpad ? <span role="status">Temporary workspace</span> : null}
      {caseSession.phase === "error" ? <span role="alert" className="max-w-56 truncate text-err" title={caseSession.error ?? undefined}>Case unavailable</span> : null}
      <span className="ml-auto shrink-0" title={runtime === "browser" ? "Native commands are unavailable in browser fallback" : undefined}>
        {runtime === "native" ? "Native" : runtime === "browser" ? "Browser · native unavailable" : "Checking runtime…"}
      </span>
    </footer>
  );
}
