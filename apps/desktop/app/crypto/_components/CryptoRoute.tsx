"use client";

import { CryptoWorkspace } from "./CryptoWorkspace";
import { useWorkbenchLocation } from "@state/workbench";

export function CryptoRoute() {
  const { tool } = useWorkbenchLocation();
  return <div className="h-full min-h-0"><CryptoWorkspace tool={tool} /></div>;
}
