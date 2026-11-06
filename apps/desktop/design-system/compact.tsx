"use client";
/**
 * Compact UI primitives (UX revision): icon-led navigation and single-focus
 * sections modeled on the reference tools — an icon rail with count badges
 * (Bettercap), one-line section headers with a single state chip, and
 * info-tooltips that replace explanatory text walls. Long explanations move
 * into `InfoTip` tooltips; the screen shows controls and results, not prose.
 */
import type { LucideIcon } from "lucide-react";
import { Info } from "lucide-react";
import type { ReactNode } from "react";

import { Chip } from "./panes";

/**
 * Compact icon-only mode rail (Bettercap style): left-aligned square pills,
 * icon per mode, tooltip = label, active = orange pill background. Deliberately
 * NOT a tab bar: no full-width stretch, no underline, no labels underneath.
 */
export function IconRail({
  items,
  active,
  onChange,
  ariaLabel,
}: {
  items: readonly { id: string; label: string; icon: LucideIcon; badge?: number | string }[];
  active: string;
  onChange: (id: string) => void;
  ariaLabel: string;
}) {
  return (
    <div role="toolbar" aria-label={ariaLabel} className="flex shrink-0 items-center gap-1 px-2 py-1.5">
      {items.map((item) => {
        const activeItem = item.id === active;
        return (
          <button
            key={item.id}
            type="button"
            onClick={() => onChange(item.id)}
            aria-pressed={activeItem}
            aria-label={item.label}
            title={item.label}
            className={`relative inline-flex h-8 w-8 items-center justify-center rounded-md transition-colors focus-visible:outline focus-visible:outline-1 focus-visible:outline-ring ${
              activeItem
                ? "bg-orange/15 text-orange"
                : "text-fg-muted hover:bg-raised hover:text-fg-dim"
            }`}
          >
            <item.icon size={15} strokeWidth={activeItem ? 2 : 1.5} />
            {item.badge !== undefined && item.badge !== 0 && item.badge !== "" ? (
              <span className="absolute -right-1 -top-1 min-w-3.5 rounded-full bg-err px-1 text-center font-mono text-[9px] leading-3.5 text-white">
                {item.badge}
              </span>
            ) : null}
          </button>
        );
      })}
    </div>
  );
}

/**
 * One-line section header replacing the full-width ALL-CAPS bars: a small
 * icon, a normal-case title, and at most ONE state chip on the right.
 * Everything else (long explanations) belongs in an `InfoTip`.
 */
export function SectionHeader({
  icon: Icon,
  title,
  state,
  stateTone = "muted",
  info,
  actions,
}: {
  icon: LucideIcon;
  title: string;
  /** The single state word for this section, e.g. "ready" | "no capture". */
  state?: string;
  stateTone?: "muted" | "orange" | "ok" | "err";
  /** Long explanation — rendered as an info tooltip, never as body text. */
  info?: string;
  actions?: ReactNode;
}) {
  return (
    <div className="flex shrink-0 items-center gap-2 px-3 py-1.5">
      <Icon size={13} strokeWidth={1.5} className="shrink-0 text-fg-muted" />
      <span className="truncate text-xs font-semibold text-fg">{title}</span>
      {info ? <InfoTip text={info} /> : null}
      <span className="flex-1" />
      {actions}
      {state ? <Chip tone={stateTone}>{state}</Chip> : null}
    </div>
  );
}

/** Info tooltip: keeps long explanations one hover away instead of on screen. */
export function InfoTip({ text }: { text: string }) {
  return (
    <span
      tabIndex={0}
      role="note"
      aria-label={text}
      title={text}
      className="inline-flex cursor-help items-center text-fg-muted hover:text-fg-dim focus-visible:outline focus-visible:outline-1 focus-visible:outline-ring"
    >
      <Info size={12} strokeWidth={1.5} />
    </span>
  );
}

/** Icon-only toolbar button with a required tooltip (Bettercap toolbar style). */
export function IconButton({
  icon: Icon,
  onClick,
  disabled,
  title,
  tone = "default",
  badge,
}: {
  icon: LucideIcon;
  onClick?: () => void;
  disabled?: boolean;
  title: string;
  tone?: "default" | "primary" | "danger";
  badge?: number | string;
}) {
  const tones: Record<string, string> = {
    default: "border-line text-fg-dim hover:text-fg",
    primary: "border-orange/50 text-orange hover:text-orange",
    danger: "border-err/50 text-err hover:text-err",
  };
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={title}
      aria-label={title}
      className={`relative inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-sm border bg-transparent transition-colors focus-visible:outline focus-visible:outline-1 focus-visible:outline-ring disabled:cursor-not-allowed disabled:opacity-40 ${tones[tone]}`}
    >
      <Icon size={14} strokeWidth={1.5} />
      {badge !== undefined && badge !== 0 && badge !== "" ? (
        <span className="absolute -right-1.5 -top-1.5 min-w-3.5 rounded-full bg-err px-1 text-center font-mono text-[9px] leading-3.5 text-white">
          {badge}
        </span>
      ) : null}
    </button>
  );
}

/**
 * A single row of muted status chips. Used INSTEAD of stacking prominent
 * chips everywhere: only state that demands action (blocked, error, counts)
 * belongs here; everything else stays in section headers.
 */
export function StatusStrip({ items }: { items: readonly ({ label: string; tone?: "muted" | "orange" | "ok" | "err" } | null)[] }) {
  const visible = items.filter(Boolean) as { label: string; tone?: "muted" | "orange" | "ok" | "err" }[];
  if (visible.length === 0) return null;
  return (
    <div className="flex flex-wrap items-center gap-1 px-3 py-1">
      {visible.map((item) => (
        <Chip key={item.label} tone={item.tone ?? "muted"}>
          {item.label}
        </Chip>
      ))}
    </div>
  );
}

/**
 * Toolbar row: dense one-line composite of labeled controls (Wireshark
 * toolbar style). Labels are short; long descriptions go in control
 * tooltips. Not a component — the documented layout for workspace toolbars:
 * one flex-wrap row, h-7/h-8 controls, gap-2, px-2, no section bars inside.
 */
