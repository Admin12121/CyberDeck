"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useWorkbenchCase, useWorkbenchJobs } from "@state/workbench";
import type { CategoryId } from "@state/tool-registry";

export type NotificationStatus = "completed" | "failed";
export interface JobNotification {
  id: string;
  caseId: string;
  jobId: number;
  feature: CategoryId | null;
  status: NotificationStatus;
  createdAt: number;
  read: boolean;
}

/** Conservative ownership inference. Do not label unknown jobs as a specific feature. */
export function featureForJob(kind: string): CategoryId | null {
  const name = kind.toLowerCase();
  if (/^recovery:|^crypto[: ]|^hash[: ]/.test(name)) return "crypto";
  if (/^web[: ]|^engine:|^proxy[: ]/.test(name)) return "web";
  if (/^network[: ]|^scan[: ]|^packet[: ]/.test(name)) return "network";
  if (/^forensics[: ]|^carve[: ]/.test(name)) return "forensics";
  return null;
}

interface NotificationContextValue {
  notifications: readonly JobNotification[];
  unreadFor: (feature: CategoryId) => number;
  markRead: (feature: CategoryId) => void;
}
const Context = createContext<NotificationContextValue | null>(null);

export function JobNotificationProvider({ children }: { children: ReactNode }) {
  const { caseId } = useWorkbenchCase();
  const { jobs } = useWorkbenchJobs();
  const [notifications, setNotifications] = useState<JobNotification[]>([]);
  const seen = useRef(new Set<string>());
  const previousCase = useRef(caseId);

  useEffect(() => {
    if (previousCase.current !== caseId) {
      previousCase.current = caseId;
      seen.current.clear();
      setNotifications([]);
    }
    const added: JobNotification[] = [];
    for (const job of Object.values(jobs)) {
      if (job.status !== "completed" && job.status !== "failed") continue;
      const eventId = caseId + ":" + job.id + ":" + (job.finishedAt ?? job.startedAt);
      if (seen.current.has(eventId)) continue;
      seen.current.add(eventId);
      added.push({
        id: eventId, caseId, jobId: job.id,
        feature: featureForJob(job.kind),
        status: job.status, createdAt: job.finishedAt ?? Date.now(),
        read: false,
      });
    }
    if (added.length) setNotifications((previous) => [...added, ...previous].slice(0, 100));
  }, [caseId, jobs]);

  const unreadFor = useCallback((feature: CategoryId) =>
    notifications.filter((event) => event.feature === feature && !event.read).length, [notifications]);
  const markRead = useCallback((feature: CategoryId) => {
    setNotifications((current) => current.map((event) =>
      event.feature === feature && !event.read ? { ...event, read: true } : event));
  }, []);
  const value = useMemo(() => ({ notifications, unreadFor, markRead }),
    [notifications, unreadFor, markRead]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
}
export function useJobNotifications() {
  const value = useContext(Context);
  if (!value) throw new Error("JobNotificationProvider is required");
  return value;
}
