"use client";

import { createContext, useCallback, useContext, useRef, useState, type ReactNode, type Dispatch, type SetStateAction } from "react";

/**
 * Small volatile per-case draft store. Neither evidence nor secrets are written
 * to localStorage. Feature owners opt in for eligible drafts/offsets/filters.
 */
type SessionStore = {
  read: <T>(key: string, initial: T) => T;
  write: <T>(key: string, value: T) => void;
  dropCase: (caseId: string) => void;
};
const Context = createContext<SessionStore | null>(null);

export function WorkspaceSessionProvider({ children }: { children: ReactNode }) {
  const cache = useRef(new Map<string, unknown>());
  const read = useCallback(<T,>(key: string, initial: T): T =>
    (cache.current.has(key) ? cache.current.get(key) as T : initial), []);
  const write = useCallback(<T,>(key: string, value: T) => {
    if (cache.current.size >= 120 && !cache.current.has(key)) {
      const first = cache.current.keys().next().value;
      if (first) cache.current.delete(first);
    }
    cache.current.set(key, value);
  }, []);
  const dropCase = useCallback((caseId: string) => {
    for (const key of cache.current.keys()) if (key.startsWith(caseId + ":")) cache.current.delete(key);
  }, []);
  return <Context.Provider value={{ read, write, dropCase }}>{children}</Context.Provider>;
}

/** State is restored on remount, and a case switch changes the cache namespace. */
export function useWorkspaceDraft<T>(
  caseId: string, feature: string, name: string, initial: T,
): [T, Dispatch<SetStateAction<T>>] {
  const store = useContext(Context);
  if (!store) throw new Error("WorkspaceSessionProvider is required");
  const key = caseId + ":" + feature + ":" + name;
  const [entry, setEntry] = useState(() => ({ key, value: store.read(key, initial) }));
  const value = entry.key === key ? entry.value : store.read(key, initial);
  const update = useCallback<Dispatch<SetStateAction<T>>>((action) => {
    setEntry((previous) => {
      const current = previous.key === key ? previous.value : store.read(key, initial);
      const next = typeof action === "function"
        ? (action as (state: T) => T)(current) : action;
      store.write(key, next);
      return { key, value: next };
    });
  }, [key, store, initial]);
  return [value, update];
}
