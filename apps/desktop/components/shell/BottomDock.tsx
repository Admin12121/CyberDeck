"use client";
/** Bottom dock shell: tabs for the jobs table and the console. */
import { ConsoleDock } from "./ConsoleDock";
import { JobsDock } from "./JobsDock";
import { useWorkbench } from "@state/workbench";

export function BottomDock() {
  const wb = useWorkbench();
  const jobs = wb.dockTab === "jobs";
  return (
    <>
      {jobs ? <JobsDock /> : <ConsoleDock />}
    </>
  );
}
