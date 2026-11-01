"use client";
import { createContext, useContext, useMemo, useRef, useState, type ReactNode } from "react";

export type WebTab = "proxy" | "history" | "repeater" | "scanner" | "spider";
interface RequestHandoff {
  id: number;
  request: string;
  reconstructed: boolean;
}
interface WebWorkflowState {
  tab: WebTab;
  setTab: (tab: WebTab) => void;
  target: string;
  setTarget: (target: string) => void;
  normalized: string;
  repeaterHandoff: RequestHandoff | null;
  draftInRepeater: (request: string, reconstructed?: boolean) => void;
  scanTarget: (url: string) => void;
}
const Context = createContext<WebWorkflowState | null>(null);

export function WebWorkflowProvider({ children }: { children: ReactNode }) {
  const [tab, setTab] = useState<WebTab>("proxy");
  const [target, setTarget] = useState("");
  const [repeaterHandoff, setRepeaterHandoff] = useState<RequestHandoff | null>(null);
  const sequence = useRef(0);
  const normalized = useMemo(() => {
    const value = target.trim();
    return value && !/^https?:\/\//i.test(value) ? `http://${value}` : value;
  }, [target]);
  const draftInRepeater = (request: string, reconstructed = false) => {
    sequence.current += 1;
    setRepeaterHandoff({ id: sequence.current, request, reconstructed });
    setTab("repeater");
  };
  const scanTarget = (url: string) => { setTarget(url); setTab("scanner"); };
  return (
    <Context.Provider value={{ tab, setTab, target, setTarget, normalized, repeaterHandoff, draftInRepeater, scanTarget }}>
      {children}
    </Context.Provider>
  );
}
export function useWebWorkflow(): WebWorkflowState {
  const context = useContext(Context);
  if (!context) throw new Error("WebWorkflowProvider is required for Web Studio");
  return context;
}

/** A draft only: proxy history currently stores request metadata, not its original headers/body. */
export function makeGetDraft(url: string): string {
  const parsed = new URL(url);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") throw new Error("Only HTTP(S) targets are supported");
  return `GET ${parsed.pathname || "/"}${parsed.search} HTTP/1.1\r\nHost: ${parsed.host}\r\nAccept: */*\r\n\r\n`;
}
