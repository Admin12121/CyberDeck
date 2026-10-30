"use client";
/** Web studio: ZAP-model workspace with top-bar tabs (Master Plan 5.2). */
import { useState } from "react";
import { HistoryView } from "./HistoryView";
import { ProxyView } from "./ProxyView";
import { RepeaterView } from "./RepeaterView";
import { ScannerView } from "./ScannerView";
import { SpiderView } from "./SpiderView";

export function WebWorkspace() {
  const [tab, setTab] = useState<"proxy" | "history" | "repeater" | "scanner" | "spider">("proxy");
  const show = (id: string) => (tab === id ? "h-full" : "hidden h-full");
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex h-8 shrink-0 items-center gap-1 border-b border-line bg-sidebar px-2">
        {(["proxy", "history", "repeater", "scanner", "spider"] as const).map((t) => (
          <button
            key={t}
            type="button"
            onClick={() => setTab(t)}
            className={`h-6 border px-3 font-mono text-[10px] uppercase tracking-wide ${
              tab === t ? "border-orange/50 text-orange" : "border-transparent text-fg-muted hover:text-fg"
            }`}
          >
            {t}
          </button>
        ))}
        <span className="ml-auto font-mono text-[10px] text-fg-muted">web studio · zap-model workflow</span>
      </div>
      <div className="min-h-0 flex-1">
        <div className={show("proxy")}><ProxyView /></div>
        <div className={show("history")}><HistoryView /></div>
        <div className={show("repeater")}><RepeaterView /></div>
        <div className={show("scanner")}><ScannerView /></div>
        <div className={show("spider")}><SpiderView /></div>
      </div>
    </div>
  );
}
