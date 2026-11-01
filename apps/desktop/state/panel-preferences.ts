"use client";

import { useCallback, useEffect, useState } from "react";

export const PANEL_LIMITS = {
  navigator: { min: 180, max: 340, fallback: 224 },
  dock: { min: 140, max: 640, fallback: 280 },
} as const;

export type PanelSizes = { navigator: number; dock: number };
const STORAGE_KEY = "cyberdeck.panel-sizes";

export const defaultPanelSizes: PanelSizes = {
  navigator: PANEL_LIMITS.navigator.fallback,
  dock: PANEL_LIMITS.dock.fallback,
};

export function clampPanel(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, Number.isFinite(value) ? value : min));
}

export function parsePanelSizes(value: string | null): PanelSizes {
  if (!value) return { ...defaultPanelSizes };
  try {
    const raw: unknown = JSON.parse(value);
    if (!raw || typeof raw !== "object") return { ...defaultPanelSizes };
    const p = raw as Partial<Record<keyof PanelSizes, unknown>>;
    return {
      navigator: clampPanel(typeof p.navigator === "number" ? p.navigator : PANEL_LIMITS.navigator.fallback,
        PANEL_LIMITS.navigator.min, PANEL_LIMITS.navigator.max),
      dock: clampPanel(typeof p.dock === "number" ? p.dock : PANEL_LIMITS.dock.fallback,
        PANEL_LIMITS.dock.min, PANEL_LIMITS.dock.max),
    };
  } catch { return { ...defaultPanelSizes }; }
}

export function usePanelPreferences() {
  // Hydrate after mount: no SSR/localStorage mismatches on the initial paint.
  const [panels, setPanels] = useState<PanelSizes>(defaultPanelSizes);
  const [loaded, setLoaded] = useState(false);
  useEffect(() => {
    try {
      const raw = window.localStorage.getItem(STORAGE_KEY)
        ?? window.localStorage.getItem("hacktool.panel-sizes");
      setPanels(parsePanelSizes(raw));
    } catch { setPanels({ ...defaultPanelSizes }); }
    setLoaded(true);
  }, []);
  useEffect(() => {
    if (!loaded) return;
    try { window.localStorage.setItem(STORAGE_KEY, JSON.stringify(panels)); }
    catch { /* optional user preference */ }
  }, [loaded, panels]);

  const setNavigatorWidth = useCallback((px: number) => {
    setPanels((prev) => ({ ...prev, navigator: clampPanel(px, PANEL_LIMITS.navigator.min, PANEL_LIMITS.navigator.max) }));
  }, []);
  const setDockHeight = useCallback((px: number) => {
    setPanels((prev) => ({ ...prev, dock: clampPanel(px, PANEL_LIMITS.dock.min, PANEL_LIMITS.dock.max) }));
  }, []);
  return { panels, setNavigatorWidth, setDockHeight };
}
