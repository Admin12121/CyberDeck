"use client";
/** Status bar: transport, workspace, job state, engine status (§3.5). */
import { caseCreate, caseList, isDesktop, type CaseRecordWire } from "@lib/ipc";
import { useEffect, useState } from "react";
import { useWorkbenchCase } from "@state/workbench";

export function StatusBar() {
  const wb = useWorkbenchCase();
  const [cases, setCases] = useState<CaseRecordWire[]>([]);
  const [runtime, setRuntime] = useState<"checking" | "native" | "browser">("checking");
  useEffect(() => { setRuntime(isDesktop() ? "native" : "browser"); }, []);
  const [creating, setCreating] = useState(false);
  const [caseTitle, setCaseTitle] = useState("");
  const [caseError, setCaseError] = useState<string | null>(null);
  const [casesLoaded, setCasesLoaded] = useState(false);
  useEffect(() => {
    let active = true;
    void caseList().then((list) => { if (active) { setCases(list); setCasesLoaded(true); } })
      .catch((error: unknown) => { if (active) { setCaseError(String(error)); setCasesLoaded(true); } });
    return () => { active = false; };
  }, []);
  useEffect(() => {
    if (!casesLoaded) return;
    if (cases.length === 0) { if (wb.caseId !== "scratchpad") wb.setCaseId("scratchpad"); return; }
    // Never silently display case A while writes still target a stale case ID.
    if (!cases.some((item) => item.id === wb.caseId)) wb.setCaseId(cases[0].id);
  }, [cases, casesLoaded, wb.caseId, wb.setCaseId]);

  const createCase = async () => {
    if (!caseTitle.trim()) return;
    try {
      const created = await caseCreate(caseTitle.trim());
      setCases((previous) => [created, ...previous]);
      wb.setCaseId(created.id);
      setCaseTitle("");
      setCreating(false);
      setCaseError(null);
    } catch (error) { setCaseError(String(error)); }
  };

  const linked = wb.caseSession.phase === "ready" && wb.caseSession.caseId === wb.caseId;
  return (
    <footer className="flex min-h-9 shrink-0 items-center gap-2 overflow-x-auto whitespace-nowrap border-t border-line bg-sidebar px-3 text-xs text-fg-muted" aria-label="Case and runtime status">
      <label className="flex shrink-0 items-center gap-2">
        <span>Case</span>
        <select aria-label="Active case" disabled={!casesLoaded || !!caseError}
          value={wb.caseId} onChange={(event) => wb.setCaseId(event.target.value)}
          className="h-7 max-w-52 min-w-28 rounded-md border border-line bg-panel px-2 text-xs text-fg">
          {cases.map((item) => <option key={item.id} value={item.id}>{item.title}</option>)}
          {!cases.some((item) => item.id === wb.caseId) ? (
            <option value={wb.caseId}>{!casesLoaded ? "Loading…" : wb.caseId === "scratchpad" ? "Scratchpad" : "Resolving…"}</option>
          ) : null}
          {cases.length === 0 && wb.caseId !== "scratchpad" ? <option value="scratchpad">Scratchpad</option> : null}
        </select>
      </label>
      {creating ? (
        <form onSubmit={(event) => { event.preventDefault(); void createCase(); }} className="flex items-center gap-1">
          <input value={caseTitle} onChange={(event) => setCaseTitle(event.target.value)} maxLength={120}
            aria-label="New case title" placeholder="Case title" className="h-7 w-32 rounded-md border border-line bg-app px-2 text-xs text-fg" />
          <button type="submit" disabled={!caseTitle.trim() || runtime !== "native"}
            className="h-7 px-2 text-fg disabled:opacity-40">Save</button>
          <button type="button" onClick={() => setCreating(false)} className="h-7 px-2">Cancel</button>
        </form>
      ) : (
        <button type="button" disabled={runtime !== "native"} onClick={() => setCreating(true)}
          title="Create case" className="h-7 rounded-md px-2 text-fg hover:bg-raised disabled:opacity-40">+ Case</button>
      )}
      {wb.caseSession.phase === "selecting" ? <span role="status">Linking…</span> : null}
      {linked ? <span role="status" title="Backend-selected active case">Linked</span> : null}
      {wb.caseSession.phase === "error" ? <span role="alert" className="max-w-56 truncate text-err" title={wb.caseSession.error ?? undefined}>Case unavailable</span> : null}
      {caseError ? <span role="alert" className="max-w-40 truncate text-err" title={caseError}>Case error</span> : null}
      <span className="ml-auto shrink-0" title={runtime === "browser" ? "Native commands are unavailable in browser fallback" : undefined}>
        {runtime === "native" ? "Native" : runtime === "browser" ? "Browser · native unavailable" : "Checking runtime…"}
      </span>
    </footer>
  );
}
