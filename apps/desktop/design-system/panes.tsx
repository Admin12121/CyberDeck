"use client";
/**
 * Dark Matter pane primitives shared by every studio: bordered panels with
 * compact headers, empty states, inspector fields and status chips.
 * Density is Zed-style compact; no decorative color (Master Plan §3).
 */
import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

export function Pane({
  title,
  actions,
  children,
  className = "",
  bodyClassName = "",
}: {
  title: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={`flex min-h-0 min-w-0 flex-col border border-line bg-panel ${className}`}>
      <header className="flex h-7 shrink-0 items-center justify-between gap-2 border-b border-line bg-sidebar px-2">
        <span className="truncate text-[10px] font-medium uppercase tracking-wider text-fg-muted">
          {title}
        </span>
        {actions ? <div className="flex shrink-0 items-center gap-1">{actions}</div> : null}
      </header>
      <div className={`min-h-0 flex-1 overflow-auto ${bodyClassName}`}>{children}</div>
    </section>
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
      <div className="text-xs text-fg-dim">{title}</div>
      {detail ? <div className="max-w-md font-mono text-[11px] leading-relaxed text-fg-muted">{detail}</div> : null}
      {badge ? (
        <span className="border border-line px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wide text-fg-muted">
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
  tone?: "muted" | "blue" | "orange" | "ok" | "err";
}) {
  const tones: Record<string, string> = {
    muted: "border-line text-fg-muted",
    blue: "border-blue/40 text-blue",
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
      <div className="truncate font-mono text-xs text-fg-dim">{value}</div>
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
    default: "border-line text-fg-dim hover:border-line-strong hover:text-fg",
    primary: "border-blue/50 text-blue hover:bg-blue-dim",
    danger: "border-err/40 text-err hover:bg-err/10",
  };
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={title}
      className={`inline-flex h-6 items-center gap-1 border px-2 font-mono text-[11px] transition-colors disabled:cursor-not-allowed disabled:opacity-40 ${tones[tone]}`}
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
      className={`h-6 border border-line bg-app px-2 text-xs text-fg placeholder:text-fg-muted focus:border-blue focus:outline-none ${mono ? "font-mono" : ""} ${className}`}
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
      className={`h-6 border border-line bg-app px-1 font-mono text-[11px] text-fg-dim focus:border-blue focus:outline-none ${className}`}
    >
      {options.map((opt) => (
        <option key={opt.value} value={opt.value}>
          {opt.label}
        </option>
      ))}
    </select>
  );
}
