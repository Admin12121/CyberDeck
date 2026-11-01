"use client";

import { NetworkWorkspace } from "./NetworkWorkspace";
import { useWorkbenchLocation } from "@state/workbench";

export function NetworkRoute() {
  const { tool } = useWorkbenchLocation();
  return <div className="h-full min-h-0"><NetworkWorkspace tool={tool} /></div>;
}
