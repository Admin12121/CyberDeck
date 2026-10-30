"use client";
/**
 * Workbench context — navigation + live job table for the shell.
 * Feature views read navigation state from here and dispatch intents
 * (select tool, run job) back through it; persistence and per-tab state
 * arrive in later arcs.
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
  category: CategoryId;
  tool: ToolId;
  jobs: Record<number, JobView>;
  paletteOpen: boolean;
  dockOpen: boolean;
  inspectorOpen: boolean;
  selectCategory: (id: CategoryId) => void;
  selectTool: (id: ToolId) => void;
  runDemoJob: () => void;
  cancelJob: (id: number) => void;
  setPaletteOpen: (open: boolean) => void;
  toggleDock: () => void;
  toggleInspector: () => void;
}

const WorkbenchContext = createContext<WorkbenchApi | null>(null);

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
  const [inspectorOpen, setInspectorOpen] = useState(true);

  const selectCategory = useCallback((id: CategoryId) => {
    setCategory(id);
    setTool(firstToolOf(id));
  }, []);

  const selectTool = useCallback((id: ToolId) => {
    setTool(id);
    const cat = id.split(".")[0] as CategoryId;
    setCategory(cat);
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
        setDockOpen((v) => !v);
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
      inspectorOpen,
      selectCategory,
      selectTool,
      runDemoJob,
      cancelJob,
      setPaletteOpen,
      toggleDock,
      toggleInspector,
    }),
    [
      category,
      tool,
      jobs,
      paletteOpen,
      dockOpen,
      inspectorOpen,
      selectCategory,
      selectTool,
      runDemoJob,
      cancelJob,
      toggleDock,
      toggleInspector,
    ],
  );

  return <WorkbenchContext.Provider value={value}>{children}</WorkbenchContext.Provider>;
}

export function useWorkbench(): WorkbenchApi {
  const ctx = useContext(WorkbenchContext);
  if (!ctx) throw new Error("useWorkbench must be used inside WorkbenchProvider");
  return ctx;
}
