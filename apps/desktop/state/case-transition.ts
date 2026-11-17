/** Backend-authoritative, serialized case selection with cancellation and stale-result rejection. */
export interface SelectedNativeCase {
  case_id: string | null;
  revision: number | null;
}

export interface CaseTransitionState {
  phase: "unavailable" | "idle" | "selecting" | "ready" | "error";
  caseId: string | null;
  revision: number | null;
  error: string | null;
}

export function createCaseTransitionController(
  select: (id: string | null) => Promise<SelectedNativeCase>,
  publish: (value: CaseTransitionState) => void,
) {
  let generation = 0;
  let queue: Promise<void> = Promise.resolve();
  // The backend bumps its session revision on every select/clear — even
  // redundant ones. StrictMode/hot-reload effect re-runs must not re-select
  // the same case: a phantom revision bump re-labels the active scope and
  // orphans in-flight native work (stuck "cancelling", lost scope-bound
  // selections). Track the settled selection and skip no-op transitions.
  let applied: { caseId: string; native: boolean } | null = null;

  const change = (caseId: string, nativeAvailable: boolean) => {
    const version = ++generation;
    if (!nativeAvailable) {
      applied = null;
      publish({ phase: "unavailable", caseId: null, revision: null, error: null });
      return;
    }
    if (applied?.native && applied.caseId === caseId) return;

    const scratchpad = caseId === "scratchpad";
    applied = null;
    publish({ phase: scratchpad ? "idle" : "selecting", caseId: null, revision: null, error: null });
    const run = async () => {
      if (version !== generation) return;
      try {
        const response = await select(scratchpad ? null : caseId);
        if (version !== generation) return;
        if (response.case_id !== (scratchpad ? null : caseId)) {
          throw new Error("Native case selection returned a different case");
        }
        applied = { caseId, native: true };
        publish({
          phase: scratchpad ? "idle" : "ready",
          caseId: response.case_id, revision: response.revision, error: null,
        });
      } catch (error) {
        if (version === generation) {
          publish({ phase: "error", caseId: null, revision: null, error: String(error) });
        }
      }
    };
    // Run transitions sequentially so A cannot finish after B and restore A.
    queue = queue.then(run, run);
  };
  const invalidate = () => { generation++; };
  const settled = () => queue;
  return { change, invalidate, settled };
}
