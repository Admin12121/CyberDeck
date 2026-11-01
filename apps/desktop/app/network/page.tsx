"use client";
import { NetworkWorkspace } from "./_components";
import { useWorkbenchLocation } from "@state/workbench";
export default function NetworkPage() {
  const { tool } = useWorkbenchLocation();
  return <NetworkWorkspace tool={tool} />;
}
