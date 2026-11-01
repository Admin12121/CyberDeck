"use client";

import { useCallback, useState } from "react";

const MAX_LINES = 500;
const MAX_INPUT_CHARS = 4096;

/** Volatile per-session console buffers; deliberately never persisted to disk. */
export function useTerminalSessions() {
  const [consoleLines, setConsoleLines] = useState<string[]>([]);
  const [terminalLines, setTerminalLines] = useState<Record<string, string[]>>({});
  const [terminalInputs, setTerminalInputs] = useState<Record<string, string>>({});
  const [terminalBusy, setTerminalBusyState] = useState<Record<string, boolean>>({});

  const logConsole = useCallback((line: string) => {
    setConsoleLines((prev) => [...prev.slice(-(MAX_LINES - 1)), line]);
  }, []);

  const logTerminal = useCallback((id: string, line: string) => {
    if (id === "terminal-1") {
      setConsoleLines((prev) => [...prev.slice(-(MAX_LINES - 1)), line]);
    } else {
      setTerminalLines((prev) => ({
        ...prev,
        [id]: [...(prev[id] ?? []).slice(-(MAX_LINES - 1)), line],
      }));
    }
  }, []);

  const clearTerminal = useCallback((id: string) => {
    if (id === "terminal-1") setConsoleLines([]);
    else setTerminalLines((prev) => ({ ...prev, [id]: [] }));
  }, []);
  const setTerminalInput = useCallback((id: string, text: string) => {
    setTerminalInputs((prev) => ({ ...prev, [id]: text.slice(0, MAX_INPUT_CHARS) }));
  }, []);
  const setTerminalBusy = useCallback((id: string, busy: boolean) => {
    setTerminalBusyState((prev) => ({ ...prev, [id]: busy }));
  }, []);
  const resetTerminals = useCallback(() => {
    setConsoleLines([]);
    setTerminalLines({});
    setTerminalInputs({});
    setTerminalBusyState({});
  }, []);

  return {
    consoleLines, setConsoleLines, terminalLines, terminalInputs, terminalBusy,
    logConsole, logTerminal, clearTerminal, setTerminalInput, setTerminalBusy, resetTerminals,
  };
}
