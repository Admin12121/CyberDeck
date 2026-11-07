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
import { Tooltip, TooltipPopup, TooltipTrigger } from "@/components/ui/tooltip";
import { Frame, FrameHeader, FramePanel, FrameTitle, FrameDescription, FrameFooter } from "@/components/ui/frame";
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

/** Info tooltip (coss): keeps long explanations one hover away, not on screen. */
export function InfoTip({ text }: { text: string }) {
  return (
    <Tooltip>
      <TooltipTrigger
        render={(props) => (
          <span
            {...props}
            tabIndex={0}
            role="note"
            aria-label={text}
            className="inline-flex cursor-help items-center text-fg-muted hover:text-fg-dim focus-visible:outline focus-visible:outline-1 focus-visible:outline-ring"
          >
            <Info size={12} strokeWidth={1.5} />
          </span>
        )}
      />
      <TooltipPopup className="max-w-sm text-xs leading-relaxed">{text}</TooltipPopup>
    </Tooltip>
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
 * Centered full-height empty-state card (coss Frame): frame → frame header →
 * frame panel, exactly the structure the user asked for. The surrounding
 * viewport is the card's canvas — controls stay at top, the card centers in
 * the remaining space.
 */
export function EmptyCard({
  icon: Icon,
  title,
  children,
  footer,
}: {
  icon: LucideIcon;
  title: string;
  children?: ReactNode;
  footer?: ReactNode;
}) {
  return (
    <div className="flex min-h-0 flex-1 items-center justify-center p-6">
      <Frame className="w-full max-w-md">
        <FrameHeader>
          <span className="inline-flex items-center gap-2">
            <Icon size={16} strokeWidth={1.5} className="text-fg-muted" />
            <FrameTitle>{title}</FrameTitle>
          </span>
        </FrameHeader>
        <FramePanel>
          {children ? <div className="text-xs leading-relaxed text-fg-muted">{children}</div> : null}
        </FramePanel>
        {footer ? <FrameFooter>{footer}</FrameFooter> : null}
      </Frame>
    </div>
  );
}

/**
 * Toolbar row: dense one-line composite of labeled controls (Wireshark
 * toolbar style). Labels are short; long descriptions go in control
 * tooltips. Not a component — the documented layout for workspace toolbars:
 * one flex-wrap row, h-7/h-8 controls, gap-2, px-2, no section bars inside.
 */


/**
 * WorkspaceShell: the ONE shared top row for every network tool — mode rail
 * (optional), toolbar content, and the content area below. Fixes the page-
 * to-page inconsistency: identical bg-panel surface, identical height, one
 * border-b under the row, content fills the rest. Every workspace renders
 * through this; bespoke top rows are a defect.
 */
export function WorkspaceShell({
  rail,
  toolbar,
  status,
  children,
  contentClassName = "",
}: {
  rail?: ReactNode;
  toolbar?: ReactNode;
  /** Muted status chips under the toolbar row; hidden when empty. */
  status?: ReactNode;
  children: ReactNode;
  contentClassName?: string;
}) {
  return (
    <div className="flex h-full min-h-0 flex-col bg-app">
      <div className="cd-workspace-toolbar flex items-center gap-1">
        {rail}
        {rail && toolbar ? <span className="h-5 w-px shrink-0 bg-line" aria-hidden="true" /> : null}
        <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2 px-2 py-1.5">{toolbar}</div>
      </div>
      {status}
      <div className={`min-h-0 flex-1 ${contentClassName}`}>{children}</div>
    </div>
  );
}


/**
 * The ONE category dispatcher: every tool view of a category stays mounted
 * and only the active one is visible, so per-case drafts and native job
 * state survive tab switches. Provider wrappers (EvidenceProvider,
 * WebWorkflowProvider) compose around it; views needing an active flag
 * receive it through `render(active)`.
 */
export function CategoryWorkspace({
  activeId,
  views,
}: {
  activeId: string;
  views: readonly { id: string; render: (active: boolean) => ReactNode }[];
}) {
  return (
    <div className="min-h-0 flex-1">
      {views.map((view) => (
        <div key={view.id} className={view.id === activeId ? "h-full" : "hidden h-full"}>
          {view.render(view.id === activeId)}
        </div>
      ))}
    </div>
  );
}


/** The one error treatment: a full-width strip with the shared err tokens.
 * Replaces the banner/boxed/paragraph/inline error variants. */
export function ErrorStrip({ children }: { children: ReactNode }) {
  return (
    <div role="alert" className="shrink-0 border-b border-err/50 bg-err/10 px-3 py-1 font-mono text-3xs text-err">
      {children}
    </div>
  );
}

/** The one progress treatment: bounded 0..100 bar on the shared track.
 * Callers provide their own label row; the bar itself stays plain. */
export function ProgressBar({ percent, className = "" }: { percent: number; className?: string }) {
  const clamped = Math.max(0, Math.min(100, percent));
  return (
    <div className={`h-1.5 border border-line bg-app ${className}`}>
      <div className="h-full bg-orange" style={{ width: `${clamped}%` }} />
    </div>
  );
}

/** One monospace block in a findings/results stack: bold header (with the
 * honesty note one hover away) over bounded mono rows. Blocks separate by
 * border, never by nested cards. */
export function ResultStack({ title, info, children }: { title: ReactNode; info?: string; children?: ReactNode }) {
  return (
    <div className="border-t border-line p-2 text-3xs text-fg-muted">
      <div className="mb-1 flex items-center gap-1 font-semibold text-fg">
        <span>{title}</span>
        {info ? <InfoTip text={info} /> : null}
      </div>
      {children}
    </div>
  );
}

/** The one hex-dump row renderer (offset / hex / ascii columns). Consumers
 * pass hexDump() rows; truncation and paging stay the caller's concern. */
export function HexRows({ rows }: { rows: readonly { offset: number; hex: string; ascii: string }[] }) {
  return (
    <>
      {rows.map((row) => (
        <div key={row.offset}>
          <span className="text-fg-muted">{row.offset.toString(16).padStart(8, "0")}</span>
          {"  "}
          {row.hex}
          {"  "}
          <span className="text-orange">{row.ascii}</span>
        </div>
      ))}
    </>
  );
}


/**
 * ModeCard — the idle/control surface for a tool mode, copying the Web
 * proxy card exactly (the user-designated reference): centered Frame with
 * rounded-xl border, header (icon + title + status chip), panel holding the
 * CONTROLS (inputs and buttons live inside the card, not in a toolbar row).
 * Results tables render below the card in full width once data exists.
 */
export function ModeCard({
  icon: Icon,
  title,
  state,
  stateTone = "muted",
  info,
  children,
  below,
}: {
  icon: LucideIcon;
  title: string;
  state?: string;
  stateTone?: "muted" | "orange" | "ok" | "err";
  info?: string;
  children: ReactNode;
  /** Full-width content under the card (results tables, findings). */
  below?: ReactNode;
}) {
  return (
    <div className="min-h-0 flex-1 overflow-y-auto bg-app p-4 sm:p-6">
      <div className="flex min-h-full w-full flex-col items-center justify-center gap-4">
        <Frame className="mx-auto w-full max-w-2xl rounded-xl bg-muted/72 p-1">
          <FrameHeader className="flex-row items-center justify-between gap-3 px-4 py-3">
            <span className="inline-flex items-center gap-2">
              <Icon size={15} strokeWidth={1.5} className="text-fg-muted" />
              <FrameTitle>{title}</FrameTitle>
            </span>
            {state ? <Chip tone={stateTone}>{state}</Chip> : null}
            {info ? <InfoTip text={info} /> : null}
          </FrameHeader>
          <FramePanel className="space-y-4 rounded-lg bg-background px-4 pb-5 pt-4">
            {children}
          </FramePanel>
        </Frame>
        {below}
      </div>
    </div>
  );
}
