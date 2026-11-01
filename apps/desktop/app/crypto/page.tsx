"use client";
import { CryptoWorkspace } from "./_components";
import { useWorkbenchLocation } from "@state/workbench";
export default function CryptoPage() {
  const { tool } = useWorkbenchLocation();
  return <CryptoWorkspace tool={tool} />;
}
