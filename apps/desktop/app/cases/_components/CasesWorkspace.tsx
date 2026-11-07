"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useCaseReady, useCreateCase, useWorkbench } from "@state/workbench";
import {
  caseList, caseLineageScopedV1, caseSearchScopedV1, isDesktop,
  type CaseRecordWire, type CaseReportWire, type CaseLineageReportWire,
  type CaseSearchPageWire, type CaseIntegritySummaryWire,
} from "@lib/ipc";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Frame, FrameHeader, FramePanel } from "@/components/ui/frame";
import { Tabs, TabsList, TabsTab, TabsPanel } from "@/components/ui/tabs";
import { Table, TableHeader, TableBody, TableRow, TableHead, TableCell } from "@/components/ui/table";
import { FileSearch, FolderPlus, RefreshCcw, ShieldCheck, Search } from "lucide-react";
import {
  reviewSelectedEvidence, resumeSelectedCase, verifySelectedCase,
  scopedArtifactReference, copySelectedArtifactToExisting,
  stageTemporarySha256, temporaryOverview, discardTemporary, promoteTemporary,
  reviewUnregisteredCaseFolders,
  type EvidenceReview, type CaseArtifactReference, type CopyReceiptV1,
  type TemporaryOverviewWire, type UnregisteredCaseReviewWire,
} from "./native";

type View = "evidence" | "findings" | "timeline" | "lineage";
const describeError = (cause: unknown) => cause instanceof Error ? cause.message : String(cause);

export function CasesWorkspace() {
  const wb = useWorkbench();
  const router = useRouter();
  const native = isDesktop();
  const { caseReady } = useCaseReady();
  const createNewCase = useCreateCase();
  const [cases, setCases] = useState<CaseRecordWire[]>([]);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [view, setView] = useState<View>("evidence");
  const [report, setReport] = useState<CaseReportWire | null>(null);
  const [review, setReview] = useState<EvidenceReview | null>(null);
  const [integrity, setIntegrity] = useState<CaseIntegritySummaryWire | null>(null);
  const [lineage, setLineage] = useState<CaseLineageReportWire | null>(null);
  const [query, setQuery] = useState("");
  const [searchPage, setSearchPage] = useState<CaseSearchPageWire | null>(null);
  const [offset, setOffset] = useState(0);
  const [reference, setReference] = useState<CaseArtifactReference | null>(null);
  const [copyReceipt, setCopyReceipt] = useState<CopyReceiptV1 | null>(null);
  const [quickInput, setQuickInput] = useState("");
  const [temp, setTemp] = useState<TemporaryOverviewWire | null>(null);
  const [unregistered, setUnregistered] = useState<UnregisteredCaseReviewWire | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const selected = wb.caseSession;
  const ready = native && caseReady;
  const temporary = native && wb.caseId === "scratchpad" && selected.phase === "idle";
  const selectedKey = ready ? String(selected.caseId) + ":" + String(selected.revision) : "";

  const refreshCases = useCallback(async () => {
    try {
      setCases((await caseList()).filter((item) => item.id !== "scratchpad"));
    } catch (cause) { setError(describeError(cause)); }
  }, []);

  useEffect(() => { void refreshCases(); }, [refreshCases]);

  useEffect(() => {
    let active = true;
    setTemp(null);
    if (temporary) void temporaryOverview().then((data) => {
      if (active) setTemp(data);
    }).catch((cause) => { if (active) setError(describeError(cause)); });
    return () => { active = false; };
  }, [temporary]);

  useEffect(() => {
    let active = true;
    setReport(null); setReview(null); setIntegrity(null); setLineage(null);
    setSearchPage(null); setReference(null); setCopyReceipt(null); setQuery(""); setOffset(0);
    if (!selectedKey) return;
    setBusy("Restoring investigation");
    void Promise.all([resumeSelectedCase(), caseLineageScopedV1()])
      .then(([data, links]) => { if (active) { setReport(data); setLineage(links); setError(""); } })
      .catch((cause) => { if (active) setError(describeError(cause)); })
      .finally(() => { if (active) setBusy(""); });
    return () => { active = false; };
  }, [selectedKey]);

  async function task(name: string, work: () => Promise<void>) {
    if (!ready || busy) return;
    setBusy(name); setError("");
    try { await work(); } catch (cause) { setError(describeError(cause)); }
    finally { setBusy(""); }
  }

  async function createCase() {
    if (!native || !title.trim() || busy) return;
    setBusy("Creating investigation"); setError("");
    try {
      await createNewCase(title.trim(), description.trim());
      setTitle(""); setDescription("");
      await refreshCases();
    } catch (cause) { setError(describeError(cause)); }
    finally { setBusy(""); }
  }

  async function search(next: number) {
    await task("Searching case", async () => {
      setSearchPage(await caseSearchScopedV1(query, 30, next));
      setOffset(next);
    });
  }

  const artifacts = searchPage ? searchPage.artifacts : report?.artifacts ?? [];
  const findings = searchPage ? searchPage.findings : report?.findings ?? [];

  return (
    <div className="flex h-full min-h-0 flex-col bg-app text-fg" aria-label="Cases and Evidence">
      <div className="cd-workspace-toolbar flex shrink-0 items-center justify-between gap-3 px-4">
        <div className="flex items-center gap-2">
          <FileSearch className="size-4 text-fg-muted" aria-hidden />
          <h1 className="text-sm font-semibold">Cases &amp; Evidence</h1>
          <Badge size="sm" variant={ready ? "success" : "secondary"}>
            {ready ? "Case selected" : "No saved case selected"}
          </Badge>
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" disabled={!native || Boolean(busy)}
            onClick={() => void (async () => {
              setBusy("Reviewing unregistered evidence"); setError("");
              try { setUnregistered(await reviewUnregisteredCaseFolders()); }
              catch (cause) { setError(describeError(cause)); }
              finally { setBusy(""); }
            })()}>Review unregistered case folders</Button>
          <Button size="sm" variant="outline" disabled={Boolean(busy)}
            onClick={() => void refreshCases()}><RefreshCcw className="size-3.5" /> Refresh</Button>
        </div>
      </div>
      <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 overflow-y-auto p-3 lg:grid-cols-[260px_minmax(0,1fr)] lg:overflow-hidden">
        <Frame className="min-h-0 overflow-hidden">
          <FrameHeader className="px-3 py-3">
            <h2 className="text-sm font-semibold">Investigations</h2>
            <p className="text-xs text-fg-muted">Your saved cases</p>
          </FrameHeader>
          <FramePanel className="min-h-0 flex-1 space-y-2 overflow-y-auto p-3">
            {!native && <p className="text-xs text-fg-muted">Native case storage requires the installed desktop runtime.</p>}
            {cases.map((item) => (
              <Button key={item.id} type="button" size="sm"
                variant={ready && selected.caseId === item.id ? "secondary" : "ghost"}
                className="h-auto w-full justify-start whitespace-normal px-3 py-2 text-left"
                disabled={!native || Boolean(busy)} onClick={() => wb.setCaseId(item.id)}>
                <span className="min-w-0 truncate">{item.title}</span>
              </Button>
            ))}
            {cases.length === 0 && <p className="text-xs text-fg-muted">No saved investigations.</p>}
            <div className="mt-4 space-y-2 border-t border-line pt-3">
              <label htmlFor="case-new-title" className="text-xs font-medium">Create case</label>
              <Input id="case-new-title" size="sm" value={title}
                onChange={(e) => setTitle(e.target.value)} maxLength={120}
                placeholder="Investigation name" disabled={!native || Boolean(busy)} />
              <Input size="sm" value={description} aria-label="Case description"
                onChange={(e) => setDescription(e.target.value)} maxLength={500}
                placeholder="Optional description" disabled={!native || Boolean(busy)} />
              <Button size="sm" className="w-full" onClick={() => void createCase()}
                disabled={!native || !title.trim() || Boolean(busy)}>
                <FolderPlus className="size-3.5" /> Create saved case
              </Button>
            </div>
          </FramePanel>
        </Frame>
        <Frame className="min-h-0 overflow-hidden">
          <FrameHeader className="px-4 py-3">
            <h2 className="text-sm font-semibold">{report?.case.title ?? "Investigation overview"}</h2>
            <p className="text-xs text-fg-muted">
              {ready
                ? String(report?.artifacts.length ?? 0) + " artifacts · " +
                    String(report?.findings.length ?? 0) + " findings · " +
                    String(report?.events.length ?? 0) + " events"
                : "Choose a saved case to inspect its evidence and provenance"}
            </p>
          </FrameHeader>
          <FramePanel className="min-h-0 flex-1 overflow-y-auto p-3">
            {error && <p role="alert" className="mb-3 rounded-md border border-destructive/40 p-3 text-xs text-destructive">{error}</p>}
            {busy && <p role="status" className="mb-3 text-xs text-fg-muted">{busy}…</p>}
            {unregistered && <div className="mb-3 rounded-md border border-line p-3 text-xs">
              <strong>Unregistered case evidence folders ({unregistered.folders.length})</strong>
              <p className="mt-1 text-fg-muted">Read-only orphan review. No uncertain evidence is automatically adopted or deleted.</p>
              {unregistered.truncated && <Badge variant="warning">Directory scan truncated</Badge>}
              {unregistered.folders.map((folder) => (
                <div key={folder.case_id} className="mt-1 flex justify-between gap-2 border-t border-line py-2">
                  <span className="font-mono">{folder.case_id}</span>
                  <span>{folder.member_count} files{folder.member_scan_truncated ? " (incomplete)" : ""}</span>
                </div>
              ))}
              {!unregistered.folders.length && <p className="mt-2 text-fg-muted">No unregistered case evidence folders were found.</p>}
            </div>}
            {!ready ? (
              <div className="space-y-4 p-3">
                <h3 className="text-sm font-semibold">Temporary Quick Tools</h3>
                <p className="text-xs text-fg-muted">
                  Temporary outputs stay in backend memory for up to 15 minutes. There is no automatic
                  case persistence, and recovered passwords, keys, original inputs and confidential job
                  results are not eligible. Only explicitly staged SHA-256 digest outputs can be saved.
                </p>
                {temporary && <>
                  <label htmlFor="case-quick-input" className="block text-xs font-medium">Compute a SHA-256 digest</label>
                  <div className="flex gap-2">
                    <Input id="case-quick-input" size="sm" value={quickInput} maxLength={65536}
                      onChange={(e) => setQuickInput(e.target.value)}
                      placeholder="Input is hashed, never staged or persisted"
                      disabled={Boolean(busy)} />
                    <Button size="sm" disabled={!quickInput || Boolean(busy)}
                      onClick={() => void (async () => {
                        setBusy("Staging digest"); setError("");
                        try {
                          await stageTemporarySha256(quickInput);
                          setQuickInput("");
                          setTemp(await temporaryOverview());
                        } catch (cause) { setError(describeError(cause)); }
                        finally { setBusy(""); }
                      })()}>Stage digest</Button>
                  </div>
                  <div className="rounded-md border border-line p-3 text-xs">
                    <div className="flex items-center justify-between">
                      <strong>Volatile outputs ({temp?.outputs.length ?? 0}/{temp?.max_artifacts ?? 8})</strong>
                      <Button size="sm" variant="ghost" disabled={!temp?.outputs.length || Boolean(busy)}
                        onClick={() => void (async () => {
                          setBusy("Discarding temporary outputs"); setError("");
                          try { setTemp(await discardTemporary()); } catch (cause) { setError(describeError(cause)); }
                          finally { setBusy(""); }
                        })()}>Discard all</Button>
                    </div>
                    {(temp?.outputs ?? []).map((item) => (
                      <div key={item.id} className="flex justify-between gap-2 border-t border-line py-2">
                        <span>{item.name}</span><span className="text-fg-muted">{item.kind} · {item.bytes} B</span>
                      </div>
                    ))}
                    {!temp?.outputs.length && <p className="py-2 text-fg-muted">No saved or staged temporary output.</p>}
                  </div>
                  {Boolean(temp?.outputs.length) && <div className="space-y-2">
                    <h3 className="text-xs font-semibold">Save Current Work as Case</h3>
                    <p className="text-xs text-fg-muted">A separate native confirmation is required for every promotion. Original input is never saved.</p>
                    <Button size="sm" disabled={Boolean(busy) || !title.trim()}
                      onClick={() => void (async () => {
                        setBusy("Saving new investigation"); setError("");
                        try {
                          const saved = await promoteTemporary(title, undefined, description);
                          setTemp(null); setQuickInput(""); setTitle(""); setDescription("");
                          await refreshCases(); wb.setCaseId(saved.case.id);
                        } catch (cause) { setError(describeError(cause)); }
                        finally { setBusy(""); }
                      })()}>Save as New Case{title.trim() ? ": " + title : " (enter a case name on the left)"}</Button>
                    <div className="flex flex-wrap gap-2">
                      {cases.map((item) => (
                        <Button key={item.id} size="sm" variant="outline" disabled={Boolean(busy)}
                          onClick={() => void (async () => {
                            setBusy("Adding to saved investigation"); setError("");
                            try {
                              const saved = await promoteTemporary(undefined, item.id);
                              setTemp(null); setQuickInput("");
                              wb.setCaseId(saved.case.id);
                            } catch (cause) { setError(describeError(cause)); }
                            finally { setBusy(""); }
                          })()}>Add to {item.title}</Button>
                      ))}
                    </div>
                  </div>}
                </>}
                {!native && <p className="text-xs text-fg-muted">Use the installed CyberDeck desktop to stage and promote work.</p>}
              </div>
            ) : (
              <>
                <div className="mb-3 flex flex-wrap items-center gap-2">
                  <Button size="sm" variant="outline" onClick={() => void task("Reviewing evidence", async () => {
                    setReview(await reviewSelectedEvidence());
                  })} disabled={Boolean(busy)}>Review evidence files</Button>
                  <Button size="sm" variant="outline" onClick={() => void task("Checking integrity", async () => {
                    setIntegrity(await verifySelectedCase());
                  })} disabled={Boolean(busy)}>
                    <ShieldCheck className="size-3.5" /> Verify integrity
                  </Button>
                  <Button size="sm" variant="outline" disabled={Boolean(busy)}
                    onClick={() => router.push("/forensics")}>Open Forensics</Button>
                  {report?.truncated && <Badge variant="warning">Report truncated</Badge>}
                </div>
                {integrity && (
                  <p className="mb-3 rounded-md border border-line p-3 text-xs">
                    Verified {integrity.verified_artifacts} artifacts, {integrity.verified_bytes} bytes,
                    {integrity.provenance.verified_events} provenance events.
                  </p>
                )}
                {review && (
                  <div className="mb-3 rounded-md border border-line p-3 text-xs">
                    <div className="flex items-center justify-between">
                      <strong>Filesystem reconciliation</strong>
                      {review.truncated && <Badge variant="warning">Incomplete scan</Badge>}
                    </div>
                    <p className="mt-1 text-fg-muted">Read-only scan. Uncertain files are never silently adopted or deleted.</p>
                    <div className="mt-2 max-h-40 overflow-y-auto">
                      {review.entries.map((entry, i) => (
                        <div key={entry.name + (entry.artifact_id ?? String(i))}
                          className="flex justify-between gap-2 border-t border-line py-1.5">
                          <span className="truncate">{entry.name}</span>
                          <Badge size="sm" variant={entry.state === "indexed_verified" ? "success"
                            : entry.state === "indexed_tampered" || entry.state === "unsafe_entry" ? "error" : "warning"}>
                            {entry.state.replaceAll("_", " ")}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                <div className="mb-3 flex gap-2">
                  <Input size="sm" aria-label="Search case evidence and findings"
                    placeholder="Search case evidence or findings" value={query}
                    onChange={(e) => { setQuery(e.target.value); setSearchPage(null); setOffset(0); }}
                    onKeyDown={(e) => { if (e.key === "Enter" && query.trim()) void search(0); }} />
                  <Button size="sm" disabled={!query.trim() || Boolean(busy)}
                    onClick={() => void search(0)}><Search className="size-3.5" /> Search</Button>
                  {searchPage && <Button size="sm" variant="outline" onClick={() => setSearchPage(null)}>Clear</Button>}
                </div>
                <Tabs value={view} onValueChange={(value) => setView(value as View)}>
                  <TabsList size="sm" variant="underline">
                    <TabsTab value="evidence">Evidence</TabsTab>
                    <TabsTab value="findings">Findings</TabsTab>
                    <TabsTab value="timeline">Timeline</TabsTab>
                    <TabsTab value="lineage">Lineage</TabsTab>
                  </TabsList>
                  <TabsPanel value="evidence">
                    <Table><TableHeader><TableRow>
                      <TableHead>Artifact</TableHead><TableHead>Size</TableHead>
                      <TableHead>SHA-256</TableHead><TableHead>Reference</TableHead>
                    </TableRow></TableHeader><TableBody>
                      {artifacts.map((item) => (
                        <TableRow key={item.id}>
                          <TableCell className="max-w-44 truncate">{item.name}</TableCell>
                          <TableCell>{item.size.toLocaleString()} B</TableCell>
                          <TableCell className="font-mono text-xs">{item.sha256.slice(0, 16)}…</TableCell>
                          <TableCell>
                            <Button size="sm" variant="ghost" disabled={Boolean(busy)}
                              onClick={() => void task("Authorizing reference", async () => {
                                setReference(await scopedArtifactReference(item.id));
                              })}>Inspect ref</Button>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody></Table>
                    {artifacts.length === 0 && <p className="p-3 text-xs text-fg-muted">No indexed evidence.</p>}
                    {reference && <div className="mt-2 space-y-2 rounded-md border border-line p-3 text-xs">
                      <p>Backend-checked {reference.kind} ref: {reference.artifact_id} · revision {reference.session_revision}.
                        This reference alone does not authorize a cross-case read.</p>
                      <p className="font-medium">Add verified artifact to an existing investigation</p>
                      <p className="text-fg-muted">Choose the destination. The native OS will ask for confirmation and the source will remain unchanged.</p>
                      <div className="flex flex-wrap gap-2">
                        {cases.filter((item) => item.id !== reference.case_id).map((item) => (
                          <Button key={item.id} size="sm" variant="outline" disabled={Boolean(busy)}
                            onClick={() => void task("Copying verified evidence", async () => {
                              const receipt = await copySelectedArtifactToExisting(reference.artifact_id, item.id);
                              setCopyReceipt(receipt);
                            })}>Copy to {item.title}</Button>
                        ))}
                      </div>
                      {cases.filter((item) => item.id !== reference.case_id).length === 0 &&
                        <p className="text-fg-muted">Create a second saved case before copying evidence.</p>}
                      {copyReceipt && <p role="status" className="text-fg-muted">
                        Copied {copyReceipt.artifact_id} into saved case {copyReceipt.target_case_id}; original retained.
                      </p>}
                    </div>}
                  </TabsPanel>
                  <TabsPanel value="findings">
                    <Table><TableHeader><TableRow>
                      <TableHead>Severity</TableHead><TableHead>Finding</TableHead><TableHead>Source</TableHead>
                    </TableRow></TableHeader><TableBody>
                      {findings.map((item) => (
                        <TableRow key={item.id}><TableCell>{item.severity}</TableCell>
                          <TableCell>{item.title}</TableCell><TableCell>{item.source}</TableCell></TableRow>
                      ))}
                    </TableBody></Table>
                  </TabsPanel>
                  <TabsPanel value="timeline">
                    <div className="space-y-1 text-xs">
                      {report?.events.map((event) => (
                        <div key={event.id} className="grid grid-cols-[120px_1fr] gap-2 border-b border-line py-2">
                          <span className="text-fg-muted">{event.source} · {event.action}</span>
                          <span className="break-all">{event.source_description}</span>
                        </div>
                      ))}
                      {!report?.events.length && <p className="p-3 text-fg-muted">No provenance recorded.</p>}
                    </div>
                  </TabsPanel>
                  <TabsPanel value="lineage">
                    <div className="space-y-2 text-xs">
                      {lineage?.hops.map((hop, i) => (
                        <div key={i} className="rounded-md border border-line p-3">
                          <span className="font-mono">{hop.source_artifact_id}</span> → <span className="font-mono">{hop.derived_artifact_id}</span>
                          <span className="ml-2 text-fg-muted">{hop.format} · offset {hop.offset}</span>
                        </div>
                      ))}
                      {!lineage?.hops.length && <p className="p-3 text-fg-muted">No derived lineage links.</p>}
                      {lineage?.truncated && <Badge variant="warning">Lineage truncated</Badge>}
                    </div>
                  </TabsPanel>
                </Tabs>
                {searchPage && <div className="mt-3 flex items-center gap-2">
                  <Button size="sm" variant="outline" disabled={offset === 0 || Boolean(busy)}
                    onClick={() => void search(Math.max(0, offset - 30))}>Previous</Button>
                  <span className="text-xs text-fg-muted">Offset {offset}</span>
                  <Button size="sm" variant="outline"
                    disabled={Boolean(busy) || !(searchPage.truncated_artifacts || searchPage.truncated_findings)}
                    onClick={() => void search(offset + 30)}>Next</Button>
                </div>}
              </>
            )}
          </FramePanel>
        </Frame>
      </div>
    </div>
  );
}
