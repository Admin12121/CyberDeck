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
  useState,
} from "react";
import { CATEGORIES, type CategoryId, type ToolId } from "@features/registry";
import { jobCancel, jobStart } from "@lib/ipc";
import { applyJobEvent, type JobView } from "@state/jobs-model";

interface WorkbenchApi {
  dockTab: "jobs" | "console";
  setDockTab: (tab: "jobs" | "console") => void;
  consoleLines: string[];
  logConsole: (line: string) => void;
  setConsoleLines: (lines: string[]) => void;
  category: CategoryId;
  tool: ToolId;
  jobs: Record<number, JobView>;
  paletteOpen: boolean;
  dockOpen: boolean;
  inspectorOpen: boolean;
  navigatorWidth: number;
  inspectorWidth: number;
  dockHeight: number;
  selectCategory: (id: CategoryId) => void;
  selectTool: (id: ToolId) => void;
  runDemoJob: () => void;
  cancelJob: (id: number) => void;
  setPaletteOpen: (open: boolean) => void;
  setDockOpen: (open: boolean) => void;
  toggleDock: () => void;
  toggleInspector: () => void;
  setNavigatorWidth: (px: number) => void;
  setInspectorWidth: (px: number) => void;
  setDockHeight: (px: number) => void;
}

const WorkbenchContext = createContext<WorkbenchApi | null>(null);

export const PANEL_LIMITS = {
  navigator: { min: 180, max: 340, fallback: 224 },
  inspector: { min: 240, max: 420, fallback: 288 },
  dock: { min: 140, max: 640, fallback: 280 },
} as const;

type PanelSizes = { navigator: number; inspector: number; dock: number };

const STORAGE_KEY = "hacktool.panel-sizes";

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function loadPanelSizes(): PanelSizes {
  const fallback: PanelSizes = {
    navigator: PANEL_LIMITS.navigator.fallback,
    inspector: PANEL_LIMITS.inspector.fallback,
    dock: PANEL_LIMITS.dock.fallback,
  };
  if (typeof window === "undefined") return fallback;
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return fallback;
    const parsed = JSON.parse(raw) as Partial<PanelSizes>;
    return {
      navigator: clamp(Number(parsed.navigator) || fallback.navigator, PANEL_LIMITS.navigator.min, PANEL_LIMITS.navigator.max),
      inspector: clamp(Number(parsed.inspector) || fallback.inspector, PANEL_LIMITS.inspector.min, PANEL_LIMITS.inspector.max),
      dock: clamp(Number(parsed.dock) || fallback.dock, PANEL_LIMITS.dock.min, PANEL_LIMITS.dock.max),
    };
  } catch {
    return fallback;
  }
}

function firstToolOf(category: CategoryId): ToolId {
  const cat = CATEGORIES.find((c) => c.id === category);
  return cat?.tools.find((t) => !t.disabled)?.id ?? (cat?.tools[0]?.id as ToolId);
}

export function WorkbenchProvider({ children }: { children: React.ReactNode }) {
  const [category, setCategory] = useState<CategoryId>("crypto");
  const [tool, setTool] = useState<ToolId>("crypto.recipes");
  const [jobs, setJobs] = useState<Record<number, JobView>>({});
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [dockOpen, setDockOpen] = useState(false);
  const [dockTab, setDockTab] = useState<"jobs" | "console">("jobs");
  const [consoleLines, setConsoleLines] = useState<string[]>([]);
  // Default tool is in Crypto, which carries its own side panes; users toggle
  // the inspector from the title bar and it returns automatically elsewhere.
  const [inspectorOpen, setInspectorOpen] = useState(false);
  // First paint uses the fallback sizes so SSR and hydration match; persisted
  // sizes apply right after mount, and persistence stays off until then.
  const [locationLoaded, setLocationLoaded] = useState(false);
  const [panels, setPanels] = useState<PanelSizes>(() => ({
    navigator: PANEL_LIMITS.navigator.fallback,
    inspector: PANEL_LIMITS.inspector.fallback,
    dock: PANEL_LIMITS.dock.fallback,
  }));
  const [panelsLoaded, setPanelsLoaded] = useState(false);

  useEffect(() => {
    setPanels(loadPanelSizes());
    setPanelsLoaded(true);
    // restore last workspace location
    try {
      const raw = window.localStorage.getItem("hacktool.location");
      if (raw) {
        const loc = JSON.parse(raw) as { category?: CategoryId; tool?: ToolId };
        if (loc.category) setCategory(loc.category);
        if (loc.tool) setTool(loc.tool);
      }
    } catch {
      // ignore malformed location
    }
    setLocationLoaded(true);
  }, []);

  useEffect(() => {
    if (!locationLoaded) return;
    try {
      window.localStorage.setItem("hacktool.location", JSON.stringify({ category, tool }));
    } catch {
      // ignore quota failures
    }
  }, [category, tool, locationLoaded]);

  // Persist panel sizes after every user-driven change.
  useEffect(() => {
    if (!panelsLoaded) return;
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(panels));
    } catch {
      // private-mode or quota failure: sizing still works in-memory
    }
  }, [panels, panelsLoaded]);

  const setNavigatorWidth = useCallback((px: number) => {
    setPanels((p) => ({ ...p, navigator: clamp(px, PANEL_LIMITS.navigator.min, PANEL_LIMITS.navigator.max) }));
  }, []);
  const setInspectorWidth = useCallback((px: number) => {
    setPanels((p) => ({ ...p, inspector: clamp(px, PANEL_LIMITS.inspector.min, PANEL_LIMITS.inspector.max) }));
  }, []);
  const setDockHeight = useCallback((px: number) => {
    setPanels((p) => ({ ...p, dock: clamp(px, PANEL_LIMITS.dock.min, PANEL_LIMITS.dock.max) }));
  }, []);

  const selectCategory = useCallback((id: CategoryId) => {
    setCategory(id);
    setTool(firstToolOf(id));
    // Crypto studios carry their own side panes; the global inspector only
    // gets in the way there. Users can still toggle it from the title bar.
    setInspectorOpen(id !== "crypto" && id !== "web");
  }, []);

  const selectTool = useCallback((id: ToolId) => {
    setTool(id);
    const cat = id.split(".")[0] as CategoryId;
    setCategory(cat);
    setInspectorOpen(cat !== "crypto" && cat !== "web");
  }, []);

  const runDemoJob = useCallback(() => {
    void jobStart("demo", (event) => {
      setJobs((prev) => applyJobEvent(prev, event, "demo"));
      setDockOpen(true);
    }).catch((err) => console.error("job_start failed:", err));
  }, []);

  const cancelJob = useCallback((id: number) => {
    void jobCancel(id).catch((err) => console.error("job_cancel failed:", err));
  }, []);

  const toggleDock = useCallback(() => setDockOpen((v) => !v), []);
  const logConsole = useCallback((line: string) => {
    setConsoleLines((prev) => [...prev.slice(-499), line]);
  }, []);
  const toggleInspector = useCallback(() => setInspectorOpen((v) => !v), []);

  // Global shortcuts: Ctrl/Cmd+K palette, Ctrl+J jobs dock (Master Plan §3.5)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      if (mod && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((v) => !v);
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
  }, []);

  const value = useMemo<WorkbenchApi>(
    () => ({
      category,
      tool,
      jobs,
      paletteOpen,
      dockOpen,
      dockTab,
      consoleLines,
      inspectorOpen,
      navigatorWidth: panels.navigator,
      inspectorWidth: panels.inspector,
      dockHeight: panels.dock,
      selectCategory,
      selectTool,
      runDemoJob,
      cancelJob,
      setPaletteOpen,
      setDockTab,
      setDockOpen,
      logConsole,
      setConsoleLines,
      toggleDock,
      toggleInspector,
      setNavigatorWidth,
      setInspectorWidth,
      setDockHeight,
    }),
    [
      category,
      tool,
      jobs,
      paletteOpen,
      dockOpen,
      dockTab,
      consoleLines,
      panels.navigator,
      panels.inspector,
      panels.dock,
      selectCategory,
      selectTool,
      runDemoJob,
      cancelJob,
      toggleDock,
      toggleInspector,
      setNavigatorWidth,
      setInspectorWidth,
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
