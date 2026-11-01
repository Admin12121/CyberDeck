"use client";
/**
 * Dark Matter pane primitives shared by every studio: bordered panels with
 * compact headers, empty states, inspector fields, status chips, and the
 * drag resizer. Density is Zed-style compact; no decorative color (§3).
 */
import type { LucideIcon } from "lucide-react";
import type { CSSProperties, ReactNode } from "react";

export { Resizer } from "./Resizer";

export function Pane({
  title,
  actions,
  children,
  className = "",
  bodyClassName = "",
  style,
}: {
  title: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
  style?: CSSProperties;
}) {
  return (
    <section style={style} className={`flex min-h-0 min-w-0 flex-col bg-panel ${className}`}>
      <header className="cd-workspace-toolbar justify-between gap-2 px-3">
        <span className="truncate text-xs font-semibold uppercase tracking-wider text-fg-muted">
          {title}
        </span>
        {actions ? <div className="flex shrink-0 items-center gap-1">{actions}</div> : null}
      </header>
      <div className={`min-h-0 flex-1 overflow-auto ${bodyClassName}`}>{children}</div>
    </section>
  );
}

/** Shared local-workspace tabs. Primary category navigation stays in the sidebar. */
export function WorkspaceTabs<T extends string>({
  items, active, onChange, ariaLabel, placement = "top",
}: {
  items: readonly T[];
  active: T;
  onChange: (tab: T) => void;
  ariaLabel: string;
  placement?: "top" | "bottom";
}) {
  return (
    <div role="tablist" aria-label={ariaLabel}
      className="cd-workspace-toolbar min-w-0 gap-1 overflow-x-auto px-2"
      data-placement={placement}>
      {items.map((tab) => (
        <button key={tab} type="button" role="tab" aria-selected={tab === active}
          onClick={() => onChange(tab)}
          onKeyDown={(event) => {
            const index = items.indexOf(tab);
            const next = event.key === "ArrowRight" ? (index + 1) % items.length
              : event.key === "ArrowLeft" ? (index - 1 + items.length) % items.length
              : event.key === "Home" ? 0 : event.key === "End" ? items.length - 1 : -1;
            if (next < 0) return;
            event.preventDefault();
            onChange(items[next]);
            event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>('[role="tab"]')[next]?.focus();
          }}
          tabIndex={tab === active ? 0 : -1}
          className={`h-6 shrink-0 rounded-sm border border-line px-2 font-mono text-[10px] uppercase tracking-wide transition-colors focus-visible:outline-2 focus-visible:outline-offset-0 focus-visible:outline-ring ${tab === active ? "bg-selected font-semibold text-fg" : "text-fg-muted hover:bg-raised hover:text-fg"}`}>
          {tab}
        </button>
      ))}
    </div>
  );
}

export function EmptyState({
  icon: Icon,
  title,
  detail,
  badge,
}: {
  icon?: LucideIcon;
  title: string;
  detail?: string;
  badge?: string;
}) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-2 p-6 text-center">
      {Icon ? <Icon size={22} strokeWidth={1.5} className="text-fg-muted" /> : null}
      <div className="text-sm font-medium text-fg">{title}</div>
      {detail ? <div className="max-w-md text-xs leading-relaxed text-fg-muted">{detail}</div> : null}
      {badge ? (
        <span className="border border-line px-1.5 py-0.5 font-mono text-[11px] uppercase tracking-wide text-fg-muted">
          {badge}
        </span>
      ) : null}
    </div>
  );
}

export function Chip({
  children,
  tone = "muted",
}: {
  children: ReactNode;
  tone?: "muted" | "orange" | "ok" | "err";
}) {
  const tones: Record<string, string> = {
    muted: "border-line text-fg-muted",
    orange: "border-orange/40 text-orange",
    ok: "border-ok/40 text-ok",
    err: "border-err/40 text-err",
  };
  return (
    <span
      className={`inline-flex items-center border px-1.5 py-px font-mono text-[10px] uppercase tracking-wide ${tones[tone]}`}
    >
      {children}
    </span>
  );
}

export function Field({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="border-b border-line/50 px-3 py-1.5">
      <div className="text-[10px] uppercase tracking-wider text-fg-muted">{label}</div>
      <div className="truncate font-mono text-[13px] text-fg-dim">{value}</div>
    </div>
  );
}

export function ToolButton({
  children,
  onClick,
  disabled,
  title,
  tone = "default",
}: {
  children: ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  title?: string;
  tone?: "default" | "primary" | "danger";
}) {
  const tones: Record<string, string> = {
    default: "border-line text-fg-dim hover:text-fg",
    primary: "border-orange/50 text-orange hover:bg-orange-dim",
    danger: "border-err/40 text-err hover:bg-err/10",
  };
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={`inline-flex h-8 items-center gap-1 border px-3 font-mono text-xs transition-colors disabled:cursor-not-allowed disabled:opacity-40 ${tones[tone]}`}
    >
      {children}
    </button>
  );
}

export function TextInput({
  value,
  onChange,
  placeholder,
  className = "",
  mono = true,
  onKeyDown,
  ariaLabel,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  className?: string;
  mono?: boolean;
  onKeyDown?: (e: React.KeyboardEvent<HTMLInputElement>) => void;
  ariaLabel?: string;
}) {
  return (
    <input
      value={value}
      onChange={(e) => onChange(e.target.value)}
      onKeyDown={onKeyDown}
      placeholder={placeholder}
      aria-label={ariaLabel}
      className={`h-8 border border-line bg-app px-2 text-[13px] text-fg placeholder:text-fg-muted ${mono ? "font-mono" : ""} ${className}`}
    />
  );
}

export function Select({
  value,
  onChange,
  options,
  ariaLabel,
  className = "",
}: {
  value: string;
  onChange: (value: string) => void;
  options: { value: string; label: string }[];
  ariaLabel?: string;
  className?: string;
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      aria-label={ariaLabel}
      className={`h-8 border border-line bg-app px-2 font-mono text-xs text-fg-dim ${className}`}
    >
      {options.map((opt) => (
        <option key={opt.value} value={opt.value}>
          {opt.label}
        </option>
      ))}
    </select>
  );
}
