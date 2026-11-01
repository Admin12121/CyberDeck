"use client";

import { useEffect, useRef, useState } from "react";
import { caseSessionClearV1, caseSessionSelectV1, isDesktop } from "@lib/ipc";

/** Only the native backend can authorize a case session. */
export interface CaseSessionState {
  phase: "unavailable" | "idle" | "selecting" | "ready" | "error";
  caseId: string | null;
  revision: number | null;
  error: string | null;
}

/** Serialize authoritative native case transitions; ignore late and unmounted generations. */
export function useNativeCaseSession(caseId: string, hydrated: boolean): CaseSessionState {
  const [session, setSession] = useState<CaseSessionState>({
    phase: "idle", caseId: null, revision: null, error: null,
  });
  const generation = useRef(0);
  const queue = useRef<Promise<void>>(Promise.resolve());

  useEffect(() => {
    if (!hydrated) return;
    const version = ++generation.current;
    if (!isDesktop()) {
      setSession({ phase: "unavailable", caseId: null, revision: null, error: null });
      return () => { generation.current++; };
    }
    const scratchpad = caseId === "scratchpad";
    setSession({
      phase: scratchpad ? "idle" : "selecting", caseId: null, revision: null, error: null,
    });
    const select = async () => {
      if (version !== generation.current) return;
      try {
        const result = scratchpad ? await caseSessionClearV1() : await caseSessionSelectV1(caseId);
        if (version !== generation.current) return;
        if (result.case_id !== (scratchpad ? null : caseId)) {
          throw new Error("Native case selection returned a different case");
        }
        setSession({
          phase: scratchpad ? "idle" : "ready",
          caseId: result.case_id, revision: result.revision, error: null,
        });
      } catch (cause) {
        if (version === generation.current) {
          setSession({ phase: "error", caseId: null, revision: null, error: String(cause) });
        }
      }
    };
    // An old in-flight A selection must never win a rapid A -> B -> A transition.
    queue.current = queue.current.then(select, select);
    return () => { generation.current++; };
  }, [caseId, hydrated]);

  return session;
}
