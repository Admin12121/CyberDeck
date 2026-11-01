"use client";
/**
 * Workbench context: navigation, panel sizing, and the live job table.
 * Feature views read navigation state from here and dispatch intents
 * (select tool, run job) back through it. Panel sizes persist locally so
 * the layout survives restarts (Master Plan §3.5).
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { CATEGORIES, toolById, type CategoryId, type ToolId } from "@features/registry";
import type { RecipeStep } from "@features/crypto/model";
import { jobCancel, jobStart } from "@lib/ipc";
import { useNativeCaseSession, type CaseSessionState } from "@state/case-session";
import { usePanelPreferences } from "@state/panel-preferences";
import { applyJobEvent, type JobView } from "@state/jobs-model";

export interface RecipeHandoff {
  input: string;
  steps: RecipeStep[];
  source: string;
}

export type { CaseSessionState } from "@state/case-session";

interface WorkbenchApi {
  caseSession: CaseSessionState;
  caseId: string;
  setCaseId: (id: string) => void;
  recipeHandoff: RecipeHandoff | null;
  sendToRecipes: (input: string, source: string, steps?: RecipeStep[]) => void;
  consumeRecipeHandoff: () => void;
  dockTab: "jobs" | "console";
  setDockTab: (tab: "jobs" | "console") => void;
  consoleLines: string[];
  terminalLines: Record<string, string[]>;
  terminalInputs: Record<string, string>;
  terminalBusy: Record<string, boolean>;
  setTerminalBusy: (terminalId: string, busy: boolean) => void;
  logTerminal: (terminalId: string, line: string) => void;
  clearTerminal: (terminalId: string) => void;
  setTerminalInput: (terminalId: string, value: string) => void;
  logConsole: (line: string) => void;
  setConsoleLines: (lines: string[]) => void;
  category: CategoryId;
  tool: ToolId;
  jobs: Record<number, JobView>;
  paletteOpen: boolean;
  dockOpen: boolean;
  navigatorOpen: boolean;
  toggleNavigator: () => void;
  navigatorWidth: number;
  dockHeight: number;
  selectCategory: (id: CategoryId) => void;
  selectTool: (id: ToolId) => void;
  runDemoJob: () => void;
  trackOperation: <T>(kind: string, operation: () => Promise<T>) => Promise<T>;
  cancelJob: (id: number) => void;
  setPaletteOpen: (open: boolean) => void;
  setDockOpen: (open: boolean) => void;
  toggleDock: () => void;
  setNavigatorWidth: (px: number) => void;
  setDockHeight: (px: number) => void;
}

const WorkbenchContext = createContext<WorkbenchApi | null>(null);

export { PANEL_LIMITS } from "@state/panel-preferences";

function firstToolOf(category: CategoryId): ToolId {
  const cat = CATEGORIES.find((c) => c.id === category);
  return cat?.tools.find((t) => !t.disabled)?.id ?? (cat?.tools[0]?.id as ToolId);
}

export function WorkbenchProvider({ children }: { children: React.ReactNode }) {
  const [caseId, setCaseId] = useState("scratchpad");
  const [category, setCategory] = useState<CategoryId>("crypto");
  const [tool, setTool] = useState<ToolId>("crypto.recipes");
  const recentTools = useRef<Partial<Record<CategoryId, ToolId>>>({ crypto: "crypto.recipes" });
  const [jobs, setJobs] = useState<Record<number, JobView>>({});
  const localJobId = useRef(-1);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [dockOpen, setDockOpen] = useState(false);
  const [navigatorByCategory, setNavigatorByCategory] = useState<Record<CategoryId, boolean>>({ crypto: true, network: true, web: true, reverse: false, forensics: true });
  const [dockTab, setDockTab] = useState<"jobs" | "console">("jobs");
  const [consoleLines, setConsoleLines] = useState<string[]>([]);
  const [terminalLines, setTerminalLines] = useState<Record<string, string[]>>({});
  const [terminalInputs, setTerminalInputs] = useState<Record<string, string>>({});
  const [terminalBusy, setTerminalBusyState] = useState<Record<string, boolean>>({});
  const [recipeHandoff, setRecipeHandoff] = useState<RecipeHandoff | null>(null);
  // Default tool is in Crypto, which carries its own side panes; users toggle
  // the inspector from the title bar and it returns automatically elsewhere.
  // First paint uses the fallback sizes so SSR and hydration match; persisted
  // sizes apply right after mount, and persistence stays off until then.
  const [locationLoaded, setLocationLoaded] = useState(false);
  const { panels, setNavigatorWidth, setDockHeight } = usePanelPreferences();

  useEffect(() => {
    try {
      const value = window.localStorage.getItem("cyberdeck.navigator-open");
      if (value) {
        const saved = JSON.parse(value) as Partial<Record<CategoryId, boolean>>;
        setNavigatorByCategory((previous) => Object.fromEntries(Object.entries(previous).map(([key, open]) => [key, typeof saved[key as CategoryId] === "boolean" ? saved[key as CategoryId] : open])) as Record<CategoryId, boolean>);
      }
    } catch { /* optional navigator persistence */ }
    try {
      const savedCase = window.localStorage.getItem("cyberdeck.case-id");
      if (savedCase && /^[a-zA-Z0-9_-]{1,100}$/.test(savedCase)) setCaseId(savedCase);
    } catch { /* optional persistence */ }
    // restore last workspace location
    try {
      const raw = window.localStorage.getItem("cyberdeck.location") ?? window.localStorage.getItem("hacktool.location");
      if (raw) {
        const loc = JSON.parse(raw) as { category?: CategoryId; tool?: ToolId };
        const savedTool = loc.tool ? toolById(loc.tool) : undefined;
        if (savedTool && !savedTool.disabled) {
          setCategory(savedTool.category);
          setTool(savedTool.id);
          recentTools.current[savedTool.category] = savedTool.id;
        } else if (loc.category && CATEGORIES.some((cat) => cat.id === loc.category && cat.tools.some((item) => !item.disabled))) {
          setCategory(loc.category);
          setTool(firstToolOf(loc.category));
        }
      }
    } catch {
      // ignore malformed location
    }
    setLocationLoaded(true);
  }, []);

  useEffect(() => {
    if (!locationLoaded) return;
    try { window.localStorage.setItem("cyberdeck.case-id", caseId); } catch { /* optional */ }
  }, [caseId, locationLoaded]);

  useEffect(() => {
    if (!locationLoaded) return;
    try {
      window.localStorage.setItem("cyberdeck.location", JSON.stringify({ category, tool }));
    } catch {
      // ignore quota failures
    }
  }, [category, tool, locationLoaded]);

  const caseSession = useNativeCaseSession(caseId, locationLoaded);

  const changeCase = useCallback((id: string) => {
    setCaseId(id);
    setJobs({});
    setConsoleLines([]);
    setTerminalLines({});
    setTerminalInputs({});
    setTerminalBusyState({});
  }, []);

  const navigatorOpen = CATEGORIES.some((item) => item.id === category && item.tools.filter((tool) => !tool.disabled).length > 1) && navigatorByCategory[category];
  const toggleNavigator = useCallback(() => {
    if (!CATEGORIES.some((item) => item.id === category && item.tools.filter((tool) => !tool.disabled).length > 1)) return;
    setNavigatorByCategory((previous) => ({ ...previous, [category]: !previous[category] }));
  }, [category]);
  useEffect(() => {
    if (!locationLoaded) return;
    try { window.localStorage.setItem("cyberdeck.navigator-open", JSON.stringify(navigatorByCategory)); } catch { /* optional */ }
  }, [navigatorByCategory, locationLoaded]);

  const selectCategory = useCallback((id: CategoryId) => {
    const category = CATEGORIES.find((item) => item.id === id);
    if (!category?.tools.some((item) => !item.disabled)) return;
    setCategory(id);
    setTool(recentTools.current[id] ?? firstToolOf(id));
  }, []);

  const selectTool = useCallback((id: ToolId) => {
    const descriptor = toolById(id);
    if (!descriptor || descriptor.disabled) return;
    recentTools.current[descriptor.category] = id;
    setTool(id);
    setCategory(descriptor.category);
  }, []);

  const runDemoJob = useCallback(() => {
    void jobStart("demo", (event) => {
      setJobs((prev) => applyJobEvent(prev, event, "demo"));
      setDockOpen(true);
    }).catch((err) => console.error("job_start failed:", err));
  }, []);

  // Surface native operations without inventing backend cancellation or durable jobs.
  const trackOperation = useCallback(async <T,>(kind: string, operation: () => Promise<T>): Promise<T> => {
    const id = localJobId.current--;
    const startedAt = Date.now();
    setJobs((previous) => ({ ...previous, [id]: { id, kind, status: "running", percent: 0, message: "Working…", startedAt } }));
    setDockTab("jobs");
    setDockOpen(true);
    try {
      const result = await operation();
      setJobs((previous) => ({ ...previous, [id]: { ...previous[id], status: "completed", percent: 100, message: "Completed", finishedAt: Date.now() } }));
      return result;
    } catch (error) {
      setJobs((previous) => ({ ...previous, [id]: { ...previous[id], status: "failed", percent: 0, message: String(error), finishedAt: Date.now() } }));
      throw error;
    }
  }, []);

  const cancelJob = useCallback((id: number) => {
    void jobCancel(id).catch((err) => console.error("job_cancel failed:", err));
  }, []);

  const toggleDock = useCallback(() => setDockOpen((v) => !v), []);
  const logConsole = useCallback((line: string) => {
    setConsoleLines((prev) => [...prev.slice(-499), line]);
  }, []);
  const setTerminalBusy = useCallback((terminalId: string, busy: boolean) => {
    setTerminalBusyState((previous) => ({ ...previous, [terminalId]: busy }));
  }, []);
  const logTerminal = useCallback((terminalId: string, line: string) => {
    if (terminalId === "terminal-1") {
      setConsoleLines((prev) => [...prev.slice(-499), line]);
    } else {
      setTerminalLines((prev) => ({
        ...prev,
        [terminalId]: [...(prev[terminalId] ?? []).slice(-499), line],
      }));
    }
  }, []);
  const clearTerminal = useCallback((terminalId: string) => {
    if (terminalId === "terminal-1") setConsoleLines([]);
    else setTerminalLines((prev) => ({ ...prev, [terminalId]: [] }));
  }, []);
  const setTerminalInput = useCallback((terminalId: string, input: string) => {
    setTerminalInputs((prev) => ({ ...prev, [terminalId]: input.slice(0, 4096) }));
  }, []);

  // An explicit, bounded in-memory handoff: preserves source context without reimport.
  // Durable case links will replace this temporary channel in the case milestone.
  const sendToRecipes = useCallback((input: string, source: string, steps: RecipeStep[] = []) => {
    if (input.length > 1024 * 1024) {
      logConsole("recipe handoff refused: input exceeds 1 MiB limit");
      return;
    }
    setRecipeHandoff({ input, source, steps });
    selectTool("crypto.recipes");
    logConsole(`sent analysis data to Recipes from ${source}`);
  }, [selectTool, logConsole]);
  const consumeRecipeHandoff = useCallback(() => setRecipeHandoff(null), []);

  // Global shortcuts: Ctrl/Cmd+K palette, Ctrl+J jobs dock (Master Plan §3.5)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      if (mod && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((v) => !v);
      } else if (mod && e.key.toLowerCase() === "b") {
        if (e.target instanceof HTMLElement && (e.target.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName))) return;
        e.preventDefault();
        toggleNavigator();
      } else if (mod && e.key.toLowerCase() === "j") {
        e.preventDefault();
        setDockTab("jobs");
        setDockOpen(true);
      } else if (mod && e.key === "`") {
        e.preventDefault();
        setDockTab("console");
        setDockOpen(true);
      } else if (e.key === "Escape") {
        setPaletteOpen(false);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [toggleNavigator]);

  const value = useMemo<WorkbenchApi>(
    () => ({
      category,
      tool,
      caseId,
      caseSession,
      setCaseId: changeCase,
      jobs,
      paletteOpen,
      dockOpen,
      navigatorOpen,
      toggleNavigator,
      dockTab,
      consoleLines,
      terminalLines,
      terminalInputs,
      terminalBusy,
      setTerminalBusy,
      logTerminal,
      clearTerminal,
      setTerminalInput,
      recipeHandoff,
      sendToRecipes,
      consumeRecipeHandoff,
      navigatorWidth: panels.navigator,
      dockHeight: panels.dock,
      selectCategory,
      selectTool,
      runDemoJob,
      trackOperation,
      cancelJob,
      setPaletteOpen,
      setDockTab,
      setDockOpen,
      logConsole,
      setConsoleLines,
      toggleDock,
      setNavigatorWidth,
      setDockHeight,
    }),
    [
      category,
      tool,
      caseId,
      caseSession,
      jobs,
      paletteOpen,
      dockOpen,
      navigatorOpen,
      toggleNavigator,
      dockTab,
      consoleLines,
      terminalLines,
      terminalInputs,
      terminalBusy,
      setTerminalBusy,
      logTerminal,
      clearTerminal,
      setTerminalInput,
      recipeHandoff,
      sendToRecipes,
      consumeRecipeHandoff,
      panels.navigator,
      panels.dock,
      selectCategory,
      selectTool,
      changeCase,
      runDemoJob,
      trackOperation,
      cancelJob,
      toggleDock,
      setNavigatorWidth,
      setDockHeight,
    ],
  );

  return <WorkbenchContext.Provider value={value}>{children}</WorkbenchContext.Provider>;
}

export function useWorkbench(): WorkbenchApi {
  const ctx = useContext(WorkbenchContext);
  if (!ctx) throw new Error("useWorkbench must be used inside WorkbenchProvider");
  return ctx;
}
