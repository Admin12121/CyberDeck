"use client";
import { ForensicsWorkspace } from "./_components";
import { useWorkbenchLocation } from "@state/workbench";
export default function ForensicsPage() {
  const { tool } = useWorkbenchLocation();
  return <ForensicsWorkspace tool={tool} />;
}
