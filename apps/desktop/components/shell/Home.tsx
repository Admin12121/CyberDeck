"use client";

import { useEffect, useMemo, useState } from "react";
import { ArrowRight, FolderOpen, FolderPlus, History, ShieldCheck, Zap } from "lucide-react";
import { useRouter } from "next/navigation";
import { caseCreate, caseList, isDesktop, type CaseRecordWire } from "@lib/ipc";
import { CATEGORIES, toolById, type ToolId } from "@state/tool-registry";
import { useWorkbench } from "@state/workbench";

type StartupChoice = "temporary" | "new" | "existing";

export function Home() {
  const router = useRouter();
  const wb = useWorkbench();
  const [choice, setChoice] = useState<StartupChoice>("temporary");
  const [cases, setCases] = useState<CaseRecordWire[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [native, setNative] = useState(false);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastTool, setLastTool] = useState<ToolId | null>(null);

  useEffect(() => {
    let active = true;
    const desktop = isDesktop();
    setNative(desktop);
    try {
      const raw = window.localStorage.getItem("cyberdeck.location");
      if (raw) {
        const value: unknown = JSON.parse(raw);
        if (value && typeof value === "object" && "tool" in value) {
          const id = (value as { tool?: ToolId }).tool;
          if (id && !toolById(id)?.disabled && toolById(id)) setLastTool(id);
        }
      }
    } catch { /* last location is optional */ }
    void caseList().then((items) => {
      if (!active) return;
      const recent = items.filter((item) => item.id !== "scratchpad")
        .sort((a, b) => b.created_ms - a.created_ms);
      setCases(recent);
      setSelectedId((old) => old || recent[0]?.id || "");
      setLoading(false);
    }).catch((cause) => {
      if (!active) return;
      setError(String(cause));
      setLoading(false);
    });
    return () => { active = false; };
  }, []);

  const recent = useMemo(() => cases.slice(0, 8), [cases]);
  const actionEnabled = !submitting && (choice === "temporary" ||
    (native && choice === "new" && !!title.trim()) ||
    (native && choice === "existing" && !!selectedId));

  function goToWorkspace(tool?: ToolId) {
    if (tool && toolById(tool) && !toolById(tool)?.disabled) {
      wb.selectTool(tool);
    } else {
      wb.selectCategory("forensics");
    }
  }

  async function begin() {
    if (!actionEnabled) return;
    setError(null);
    if (choice === "temporary") {
      wb.setCaseId("scratchpad");
      goToWorkspace(lastTool ?? "crypto.recipes");
      return;
    }
    setSubmitting(true);
    try {
      if (choice === "new") {
        const record = await caseCreate(title.trim(), description.trim());
        wb.setCaseId(record.id);
        goToWorkspace("forensics.files");
      } else {
        if (!cases.some((record) => record.id === selectedId)) throw new Error("Select an existing case");
        wb.setCaseId(selectedId);
        goToWorkspace(lastTool ?? "forensics.files");
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="h-full overflow-y-auto bg-app px-4 py-6 text-fg sm:px-8">
      <section aria-label="Start CyberDeck" className="mx-auto flex min-h-[580px] w-full max-w-[850px] flex-col border border-line bg-panel shadow-xl">
        <header className="flex items-start justify-between gap-6 border-b border-line p-5">
          <div className="flex items-start gap-3">
            <ShieldCheck size={23} className="mt-0.5 shrink-0 text-fg-muted" />
            <div>
              <h1 className="text-base font-semibold">Welcome to CyberDeck</h1>
              <p className="mt-1 text-xs text-fg-muted">Choose how to start your investigation.</p>
            </div>
          </div>
          <div className="shrink-0 text-right">
            <div className="text-xl font-semibold tracking-tight">CyberDeck</div>
            <div className="text-[11px] text-fg-muted">Security Workbench</div>
          </div>
        </header>

        <div className="flex-1 p-5">
          <label className="flex cursor-pointer items-center gap-3 py-3 text-sm font-semibold">
            <input type="radio" name="start-choice" checked={choice === "temporary"}
              onChange={() => setChoice("temporary")} />
            Temporary workspace in memory
          </label>
          <div className="mb-4 border border-line bg-raised px-4 py-3 text-xs text-fg-muted">
            <strong className="text-fg">Quick Tools</strong> — Start without creating a saved case.
            Temporary work is not automatically promoted to case evidence.
          </div>

          <div className="border-t border-line py-4">
            <label className="flex cursor-pointer items-center gap-3 text-sm font-semibold">
              <input type="radio" name="start-choice" checked={choice === "new"}
                onChange={() => setChoice("new")} disabled={!native} />
              New investigation case
            </label>
            <div className="ml-7 mt-3 grid gap-2 sm:grid-cols-[115px_1fr] sm:items-center">
              <label htmlFor="cyberdeck-new-case-name" className="text-xs text-fg-muted">Name</label>
              <input id="cyberdeck-new-case-name" value={title} onChange={(e) => setTitle(e.target.value)}
                disabled={!native || choice !== "new"} maxLength={120} placeholder="Investigation name"
                className="h-8 min-w-0 rounded border border-line bg-app px-2 text-sm disabled:opacity-40" />
              <label htmlFor="cyberdeck-new-case-description" className="text-xs text-fg-muted">Description</label>
              <input id="cyberdeck-new-case-description" value={description}
                onChange={(e) => setDescription(e.target.value)}
                disabled={!native || choice !== "new"} maxLength={500} placeholder="Optional"
                className="h-8 min-w-0 rounded border border-line bg-app px-2 text-sm disabled:opacity-40" />
              <span className="sm:col-start-2 text-[11px] text-fg-muted">
                Case storage and original evidence are managed by the native backend.
              </span>
            </div>
          </div>

          <div className="border-t border-line py-4">
            <label className="flex cursor-pointer items-center gap-3 text-sm font-semibold">
              <input type="radio" name="start-choice" checked={choice === "existing"}
                onChange={() => setChoice("existing")} disabled={!native || cases.length === 0} />
              Open existing investigation
            </label>
            <div className="ml-7 mt-3 border border-line">
              <div className="grid grid-cols-[1fr_100px] gap-2 border-b border-line bg-raised px-3 py-2 text-xs text-fg-muted">
                <span>Name</span><span>Created</span>
              </div>
              <div className="max-h-44 min-h-32 overflow-y-auto" role="radiogroup" aria-label="Existing cases">
                {loading ? <p className="p-3 text-xs text-fg-muted">Loading cases…</p>
                  : recent.length === 0 ? <p className="p-3 text-xs text-fg-muted">No saved cases found</p>
                  : recent.map((record) => (
                    <label key={record.id}
                      className={`grid cursor-pointer grid-cols-[1fr_100px] gap-2 px-3 py-2 text-xs hover:bg-raised ${choice === "existing" && selectedId === record.id ? "bg-selected" : ""}`}>
                      <span className="flex min-w-0 items-center gap-2">
                        <input type="radio" name="existing-case" checked={selectedId === record.id}
                          disabled={!native || choice !== "existing"}
                          onChange={() => setSelectedId(record.id)} />
                        <span className="truncate">{record.title}</span>
                      </span>
                      <span className="text-fg-muted">{record.created_ms ? new Date(record.created_ms).toLocaleDateString() : "—"}</span>
                    </label>
                  ))}
              </div>
            </div>
          </div>

          <div className="border-t border-line pt-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h2 className="text-xs font-semibold uppercase tracking-wide text-fg-muted">Quick tools</h2>
              {lastTool && <button type="button" onClick={() => {
                // Resume returns to the saved tool; case identity remains authoritative.
                goToWorkspace(lastTool);
              }} className="flex items-center gap-1 text-xs text-fg hover:underline">
                <History size={13}/> Resume last workspace
              </button>}
            </div>
            <div className="mt-2 flex flex-wrap gap-2">
              {CATEGORIES.filter((category) => category.tools.some((tool) => !tool.disabled)).map((category) => (
                <button key={category.id} type="button"
                  onClick={() => { wb.setCaseId("scratchpad"); wb.selectCategory(category.id); }}
                  className="inline-flex items-center gap-2 rounded border border-line px-3 py-2 text-xs hover:bg-raised">
                  <category.icon size={14} /> {category.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        <footer className="flex flex-wrap items-center justify-between gap-3 border-t border-line p-4">
          <div role="status" className="max-w-lg text-xs text-fg-muted">
            {error ? <span role="alert" className="text-err">{error}</span>
              : !native ? "Saved case operations require the CyberDeck desktop runtime." :
                "Local-first investigations · originals preserved · no automatic sensitive-data persistence"}
          </div>
          <div className="ml-auto flex gap-2">
            <button type="button" onClick={() => router.push("/crypto")}
              className="rounded border border-line px-4 py-2 text-xs hover:bg-raised">Skip</button>
            <button type="button" onClick={() => void begin()} disabled={!actionEnabled}
              className="flex items-center gap-2 rounded bg-orange-600 px-4 py-2 text-xs font-semibold text-white hover:bg-orange-500 disabled:cursor-not-allowed disabled:opacity-40">
              {submitting ? "Opening…" : choice === "new" ? "Create Case" : "Next"} <ArrowRight size={14} />
            </button>
          </div>
        </footer>
      </section>
    </div>
  );
}
