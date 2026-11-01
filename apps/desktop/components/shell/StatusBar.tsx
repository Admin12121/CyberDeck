"use client";
/** Status bar: transport, workspace, job state, engine status (§3.5). */
import { caseCreate, caseList, isDesktop, type CaseRecordWire } from "@lib/ipc";
import { useEffect, useState } from "react";
import { useWorkbenchCase } from "@state/workbench";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectItem, SelectPopup, SelectTrigger, SelectValue } from "@/components/ui/select";

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
    const reload = () => {
      void caseList().then((list) => {
        if (!active) return;
        setCases(list);
        setCaseError(null);
        setCasesLoaded(true);
      }).catch((error: unknown) => {
        if (!active) return;
        setCaseError(String(error));
        setCasesLoaded(true);
      });
    };
    reload();
    // A newly created case must become visible without recreating the global shell.
    window.addEventListener("cyberdeck:cases-changed", reload);
    return () => {
      active = false;
      window.removeEventListener("cyberdeck:cases-changed", reload);
    };
  }, []);
  // Never select a different case because a stale case-list snapshot lacks the
  // current ID. Backend session selection remains the authority for validity.

  const createCase = async () => {
    if (!caseTitle.trim()) return;
    try {
      const created = await caseCreate(caseTitle.trim());
      setCases((previous) => [created, ...previous]);
      window.dispatchEvent(new Event("cyberdeck:cases-changed"));
      wb.setCaseId(created.id);
      setCaseTitle("");
      setCreating(false);
      setCaseError(null);
    } catch (error) { setCaseError(String(error)); }
  };

  const linked = wb.caseSession.phase === "ready" && wb.caseSession.caseId === wb.caseId;
  return (
    <footer className="flex min-h-9 shrink-0 items-center gap-2 overflow-x-auto whitespace-nowrap border-t border-line bg-sidebar px-3 text-xs text-fg-muted" aria-label="Case and runtime status">
      <div className="flex shrink-0 items-center gap-2">
        <span>Case</span>
        <Select items={[
            { label: "Temporary workspace", value: "scratchpad" },
            ...cases.filter((item) => item.id !== "scratchpad").map((item) => ({ label: item.title, value: item.id })),
            ...(!cases.some((item) => item.id === wb.caseId) && wb.caseId !== "scratchpad"
              ? [{ label: "Resolving…", value: wb.caseId }] : []),
          ]} value={wb.caseId}
          onValueChange={(next) => { if (typeof next === "string") wb.setCaseId(next); }}>
          <SelectTrigger aria-label="Active case" size="sm"
            disabled={!casesLoaded || !!caseError}
            className="h-7 max-w-60 min-w-36 rounded-md text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectPopup alignItemWithTrigger={false} className="max-h-64">
            <SelectItem value="scratchpad">Temporary workspace</SelectItem>
            {cases.filter((item) => item.id !== "scratchpad").map((item) => (
              <SelectItem key={item.id} value={item.id}>{item.title}</SelectItem>
            ))}
            {!cases.some((item) => item.id === wb.caseId) && wb.caseId !== "scratchpad" ? (
              <SelectItem value={wb.caseId}>Resolving…</SelectItem>
            ) : null}
          </SelectPopup>
        </Select>
      </div>
      {creating ? (
        <form onSubmit={(event) => { event.preventDefault(); void createCase(); }}
          className="flex items-center gap-1">
          <Input size="sm" value={caseTitle} onChange={(event) => setCaseTitle(event.target.value)}
            maxLength={120} aria-label="New case title" placeholder="Case title"
            className="w-36" />
          <Button size="xs" type="submit" disabled={!caseTitle.trim() || runtime !== "native"}>
            Save
          </Button>
          <Button size="xs" variant="ghost" onClick={() => setCreating(false)}>
            Cancel
          </Button>
        </form>
      ) : (
        <Button size="xs" variant="ghost" disabled={runtime !== "native"}
          onClick={() => setCreating(true)} title="Create case">+ Case</Button>
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
