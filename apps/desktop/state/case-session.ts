"use client";

import { useEffect, useRef, useState } from "react";
import { caseSessionClearV1, caseSessionSelectV1, isDesktop } from "@lib/ipc";
import {
  createCaseTransitionController, type CaseTransitionState,
} from "@state/case-transition";

export type CaseSessionState = CaseTransitionState;

/** Native backend is authoritative; transitions are serialized and generations cancel stale results. */
export function useNativeCaseSession(caseId: string, hydrated: boolean): CaseSessionState {
  const [session, setSession] = useState<CaseSessionState>({
    phase: "idle", caseId: null, revision: null, error: null,
  });
  const controller = useRef<ReturnType<typeof createCaseTransitionController> | null>(null);
  if (!controller.current) {
    controller.current = createCaseTransitionController(
      (id) => id === null ? caseSessionClearV1() : caseSessionSelectV1(id),
      setSession,
    );
  }

  useEffect(() => {
    if (!hydrated) return;
    const coordinator = controller.current!;
    coordinator.change(caseId, isDesktop());
    return () => coordinator.invalidate();
  }, [caseId, hydrated]);

  return session;
}
