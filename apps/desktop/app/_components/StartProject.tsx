"use client";

import { useEffect, useMemo, useState } from "react";
import { ArrowRight, History } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Frame, FrameHeader, FramePanel } from "@/components/ui/frame";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Radio, RadioGroup } from "@/components/ui/radio-group";
import { caseCreate, caseList, isDesktop, type CaseRecordWire } from "@lib/ipc";
import { CATEGORIES, toolById, type ToolId } from "@state/tool-registry";
import { useWorkbench } from "@state/workbench";
import Image from "next/image";

type StartupChoice = "temporary" | "new" | "existing";

export function StartProject() {
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
    setNative(isDesktop());
    try {
      const raw = window.localStorage.getItem("cyberdeck.location");
      if (raw) {
        const value: unknown = JSON.parse(raw);
        if (value && typeof value === "object" && "tool" in value) {
          const id = (value as { tool?: ToolId }).tool;
          if (id && toolById(id) && !toolById(id)?.disabled) setLastTool(id);
        }
      }
    } catch {
      /* last tool is an optional preference, not restored evidence */
    }
    void caseList()
      .then((items) => {
        if (!active) return;
        const recent = items
          .filter((item) => item.id !== "scratchpad")
          .sort((a, b) => b.created_ms - a.created_ms);
        setCases(recent);
        setSelectedId((current) =>
          recent.some((item) => item.id === current)
            ? current
            : (recent[0]?.id ?? ""),
        );
        setLoading(false);
      })
      .catch((cause) => {
        if (!active) return;
        setError(String(cause));
        setLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  const recent = useMemo(() => cases.slice(0, 8), [cases]);
  const actionable =
    !submitting &&
    native &&
    (choice === "new"
      ? Boolean(title.trim())
      : choice === "existing" &&
        cases.some((record) => record.id === selectedId));

  function openTool(tool?: ToolId) {
    if (tool && toolById(tool) && !toolById(tool)?.disabled)
      wb.selectTool(tool);
    else wb.selectCategory("forensics");
  }

  async function begin() {
    if (!actionable) return;
    setError(null);
    setSubmitting(true);
    try {
      if (choice === "new") {
        const record = await caseCreate(title.trim(), description.trim());
        window.dispatchEvent(new Event("cyberdeck:cases-changed"));
        wb.setCaseId(record.id);
        openTool("forensics.files");
      } else if (choice === "existing") {
        if (!cases.some((record) => record.id === selectedId))
          throw new Error("Select an existing case");
        wb.setCaseId(selectedId);
        openTool(lastTool ?? "forensics.files");
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setSubmitting(false);
    }
  }

  const chooseTemporaryTool = (tool?: ToolId) => {
    wb.setCaseId("scratchpad");
    openTool(tool ?? "crypto.recipes");
  };

  return (
    <div className="h-full overflow-y-auto bg-app text-fg">
      <div className="flex min-h-full items-center justify-center px-4 py-6 sm:px-8">
        <Frame
          aria-label="Start CyberDeck"
          className="w-full max-w-[760px] shrink-0 p-1"
        >
          <FrameHeader className="flex-row items-center justify-between gap-5 px-2 py-3">
            <div className="flex min-w-0 items-center gap-3">
              <Image
                src="/logo.webp"
                alt=""
                width={50}
                height={50}
                className="size-8=10 shrink-0 object-contain grayscale"
              />
              <div className="min-w-0">
                <h1 className="text-sm font-semibold">Welcome to CyberDeck</h1>
                <p className="mt-1 text-xs text-fg-muted">
                  Choose how to start your investigation.
                </p>
              </div>
            </div>
            <div className="shrink-0 text-right">
              <div className="text-lg font-semibold tracking-tight">
                CyberDeck
              </div>
              <div className="text-[11px] text-fg-muted">
                Security Workbench
              </div>
            </div>
          </FrameHeader>
          <FramePanel className="overflow-hidden p-0">
            <RadioGroup
              aria-label="Investigation startup mode"
              value={choice}
              onValueChange={(value) => setChoice(value as StartupChoice)}
              className="gap-0 pt-3"
            >
              <div className="pb-4 px-5">
                <div className="flex items-center gap-3 py-2">
                  <Radio id="cyberdeck-start-temporary" value="temporary" />
                  <Label
                    htmlFor="cyberdeck-start-temporary"
                    className="cursor-pointer text-xs font-semibold"
                  >
                    Temporary workspace in memory
                  </Label>
                </div>
                <p className="ml-7 text-xs text-fg-muted">
                  Use tools without saving a case. Open a tool below to start.
                </p>
              </div>

              <div className="border-t border-line py-4 px-5">
                <div className="flex items-center gap-3">
                  <Radio
                    id="cyberdeck-start-new"
                    value="new"
                    disabled={!native}
                  />
                  <Label
                    htmlFor="cyberdeck-start-new"
                    className={`text-xs font-semibold ${native ? "cursor-pointer" : "opacity-50"}`}
                  >
                    New investigation case
                  </Label>
                </div>
                <div className="ml-7 mt-3 grid gap-2 sm:grid-cols-[105px_1fr] sm:items-center">
                  <Label
                    htmlFor="cyberdeck-new-case-name"
                    className="text-xs text-fg-muted"
                  >
                    Name
                  </Label>
                  <Input
                    id="cyberdeck-new-case-name"
                    value={title}
                    size="sm"
                    onChange={(e) => setTitle(e.target.value)}
                    disabled={!native || choice !== "new"}
                    maxLength={120}
                    placeholder="Investigation name"
                  />
                  <Label
                    htmlFor="cyberdeck-new-case-description"
                    className="text-xs text-fg-muted"
                  >
                    Description
                  </Label>
                  <Input
                    id="cyberdeck-new-case-description"
                    size="sm"
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    disabled={!native || choice !== "new"}
                    maxLength={500}
                    placeholder="Optional"
                  />
                </div>
              </div>

              <div className="border-t border-line py-4 px-5">
                <div className="flex items-center gap-3">
                  <Radio
                    id="cyberdeck-start-existing"
                    value="existing"
                    disabled={!native || cases.length === 0}
                  />
                  <Label
                    htmlFor="cyberdeck-start-existing"
                    className={`text-xs font-semibold ${native && cases.length > 0 ? "cursor-pointer" : "opacity-50"}`}
                  >
                    Open existing investigation
                  </Label>
                </div>
                <div className="ml-7 mt-3 overflow-hidden rounded-md border border-line">
                  <div className="grid grid-cols-[1fr_100px] gap-2 border-b border-line bg-raised px-3 py-2 text-xs text-fg-muted">
                    <span>Name</span>
                    <span>Created</span>
                  </div>
                  <div
                    className="max-h-40 min-h-28 overflow-y-auto"
                    aria-label="Saved cases"
                  >
                    {loading ? (
                      <p className="p-3 text-xs text-fg-muted">
                        Loading cases…
                      </p>
                    ) : recent.length === 0 ? (
                      <p className="p-3 text-xs text-fg-muted">
                        No saved cases found
                      </p>
                    ) : (
                      recent.map((record) => (
                        <Button
                          key={record.id}
                          variant="ghost"
                          size="sm"
                          disabled={!native}
                          onClick={() => {
                            setChoice("existing");
                            setSelectedId(record.id);
                          }}
                          aria-pressed={
                            choice === "existing" && selectedId === record.id
                          }
                          className={`flex h-auto w-full justify-between rounded-none px-3 py-2 text-left text-xs font-normal ${choice === "existing" && selectedId === record.id ? "bg-selected" : ""}`}
                        >
                          <span className="flex min-w-0 items-center gap-2">
                            <span
                              className={`size-2 shrink-0 rounded-full border border-fg-muted ${choice === "existing" && selectedId === record.id ? "bg-fg" : ""}`}
                            />
                            <span className="truncate">{record.title}</span>
                          </span>
                          <span className="shrink-0 text-fg-muted">
                            {record.created_ms
                              ? new Date(record.created_ms).toLocaleDateString()
                              : "—"}
                          </span>
                        </Button>
                      ))
                    )}
                  </div>
                </div>
              </div>
            </RadioGroup>

            <div className="px-5 border-t border-line py-4">
              <div className="flex items-center justify-between gap-2">
                <h2 className="text-[11px] font-semibold uppercase tracking-wide text-fg-muted">
                  Quick tools
                </h2>
                {lastTool && (
                  <Button
                    variant="ghost"
                    size="xs"
                    onClick={() => chooseTemporaryTool(lastTool)}
                    className="gap-1 text-fg-muted"
                  >
                    <History size={13} /> Last tool
                  </Button>
                )}
              </div>
              <div className="mt-2 flex flex-wrap gap-2">
                {CATEGORIES.filter((category) =>
                  category.tools.some((tool) => !tool.disabled),
                ).map((category) => (
                  <Button
                    key={category.id}
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      wb.setCaseId("scratchpad");
                      wb.selectCategory(category.id);
                    }}
                  >
                    <category.icon size={14} /> {category.label}
                  </Button>
                ))}
              </div>
            </div>

            <footer className="flex min-h-14 items-center justify-between gap-3 border-t border-line px-5 py-3">
              <div role="status" className="text-xs text-fg-muted">
                {error ? (
                  <span role="alert" className="text-err">
                    {error}
                  </span>
                ) : !native ? (
                  "Saved cases require the CyberDeck desktop runtime."
                ) : null}
              </div>
              {choice !== "temporary" && (
                <Button
                  size="sm"
                  onClick={() => void begin()}
                  loading={submitting}
                  disabled={!actionable}
                  className="min-w-20"
                >
                  {choice === "new" ? "Save" : "Load"} <ArrowRight size={14} />
                </Button>
              )}
            </footer>
          </FramePanel>
        </Frame>
      </div>
    </div>
  );
}
