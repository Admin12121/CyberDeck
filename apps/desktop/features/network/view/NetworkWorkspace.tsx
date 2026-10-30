"use client";
/** Thin dispatcher: all network tools stay mounted; hidden views keep state. */
import { PacketStudioView } from "./PacketStudioView";
import { NetworkLabView } from "./NetworkLabView";
import { ScanView } from "./ScanView";
import type { ToolId } from "@features/registry";

export function NetworkWorkspace({ tool }: { tool: ToolId }) {
  const show = (id: ToolId) => (tool === id ? "h-full" : "hidden h-full");
  return (
    <>
      <div className={show("network.packet")}><PacketStudioView /></div>
      <div className={show("network.lab")}><NetworkLabView /></div>
      <div className={show("network.scan")}><ScanView /></div>
    </>
  );
}
