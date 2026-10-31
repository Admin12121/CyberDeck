"use client";
/** Status bar: transport, workspace, job state, engine status (§3.5). */
import { caseCreate, caseList, isDesktop, type CaseRecordWire } from "@lib/ipc";
import { useEffect, useState } from "react";
import { useWorkbench } from "@state/workbench";
import { toolById } from "@features/registry";

export function StatusBar() {
  const wb = useWorkbench();
  const [cases, setCases] = useState<CaseRecordWire[]>([]);
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
  const tool = toolById(wb.tool);
  const running = Object.values(wb.jobs).filter((j) => j.status === "running").length;

  return (
    <footer className="flex h-6 shrink-0 items-center gap-3 border-t border-line bg-sidebar px-2 font-mono text-[10px] text-fg-muted">
      <span className={isDesktop() ? "text-ok" : "text-warn"}>{isDesktop() ? "ipc: tauri" : "ipc: browser fallback"}</span>
      <span>workspace: {tool ? `${tool.category} / ${tool.label}` : wb.tool}</span>
      <label className="flex items-center gap-1" title="Active evidence case">
        active case
        <select
          aria-label="Active case"
          disabled={!casesLoaded || !!caseError}
          value={wb.caseId}
          onChange={(event) => wb.setCaseId(event.target.value)}
          className="max-w-52 border border-orange/50 bg-panel px-1 text-[11px] text-fg"
        >
          {cases.map((item) => <option key={item.id} value={item.id}>{item.title}</option>)}
          {!cases.some((item) => item.id === wb.caseId) ? <option value={wb.caseId}>{!casesLoaded ? "Loading cases…" : cases.length === 0 && wb.caseId === "scratchpad" ? "Scratchpad (create a case to save evidence)" : "Resolving case…"}</option> : null}
          {cases.length === 0 && wb.caseId !== "scratchpad" ? <option value="scratchpad">Scratchpad (no saved case)</option> : null}
        </select>
      </label>
      {creating ? (
        <form onSubmit={(e) => { e.preventDefault(); void createCase(); }} className="flex items-center gap-1">
          <input value={caseTitle} onChange={(e) => setCaseTitle(e.target.value)} maxLength={120}
            aria-label="New case title" placeholder="Case title" className="w-28 border border-line bg-app px-1 text-[10px]" />
          <button type="submit" disabled={!caseTitle.trim() || !isDesktop()} className="text-orange disabled:opacity-40">save</button>
          <button type="button" onClick={() => setCreating(false)}>cancel</button>
        </form>
      ) : (
        <button type="button" disabled={!isDesktop()} onClick={() => setCreating(true)}
          title="Create a new case" className="border border-line px-1 disabled:opacity-40">+ case</button>
      )}
      {caseError ? <span className="max-w-44 truncate text-err" title={caseError}>case error</span> : null}
      <span className={running > 0 ? "text-orange" : ""}>jobs: {running > 0 ? `${running} running` : "idle"}</span>
      <span className="ml-auto flex items-center gap-3">
        <button
          type="button"
          onClick={() => {
            wb.setDockTab("console");
            wb.setDockOpen(true);
          }}
          className="border border-line px-2 py-0.5 hover:border-line-strong hover:text-fg"
        >
          console (Ctrl+`)
        </button>
        <span>CyberDeck v0.1.0 · local workbench</span>
      </span>
    </footer>
  );
}
