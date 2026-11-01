"use client";

import { ForensicsWorkspace } from "./ForensicsWorkspace";
import { useWorkbenchLocation } from "@state/workbench";

export function ForensicsRoute() {
  const { tool } = useWorkbenchLocation();
  return <div className="h-full min-h-0"><ForensicsWorkspace tool={tool} /></div>;
}
