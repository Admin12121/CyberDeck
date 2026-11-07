"use client";
/**
 * Dark Matter pane primitives shared by every studio: bordered panels with
 * compact headers, empty states, inspector fields, status chips, and the
 * drag resizer. Density is Zed-style compact; no decorative color (§3).
 */
import type { LucideIcon } from "lucide-react";
import type { CSSProperties, ReactNode } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select as CossSelect, SelectItem, SelectPopup, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsList, TabsPanel, TabsTab } from "@/components/ui/tabs";

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
/** Shared coss tabs. A panel map is optional for feature views with in-place tab content. */
export function WorkspaceTabs<T extends string>({
  items, active, onChange, ariaLabel, placement = "top", panels,
}: {
  items: readonly T[];
  active: T;
  onChange: (tab: T) => void;
  ariaLabel: string;
  placement?: "top" | "bottom";
  panels?: Partial<Record<T, ReactNode>>;
}) {
  return (
    <Tabs value={active} onValueChange={(value) => onChange(value as T)}
      className={panels ? "flex min-h-0 flex-1 flex-col gap-0" : "shrink-0 gap-0"}>
      <TabsList aria-label={ariaLabel} size="sm"
        className="w-full min-w-0 justify-start gap-1 overflow-x-auto rounded-none border-b border-line bg-panel px-2 py-1"
        data-placement={placement}>
        {items.map((tab) => (
          <TabsTab key={tab} value={tab}
            className="h-7 shrink-0 grow-0 rounded-md px-3 font-mono text-[10px] uppercase tracking-wide">
            {tab}
          </TabsTab>
        ))}
      </TabsList>
      {panels && (
        <div className="min-h-0 flex-1">
          {items.map((tab) => (
            <TabsPanel key={tab} value={tab} keepMounted className="h-full min-h-0 data-[hidden]:hidden">
              {panels[tab]}
            </TabsPanel>
          ))}
        </div>
      )}
    </Tabs>
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
  return (
    <Button variant={tone === "danger" ? "destructive-outline" : tone === "primary" ? "secondary" : "outline"}
      size="sm" onClick={onClick} disabled={disabled} title={title}
      className="h-8 gap-1 rounded-sm px-3 font-mono text-xs">
      {children}
    </Button>
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
  disabled,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  className?: string;
  mono?: boolean;
  onKeyDown?: (e: React.KeyboardEvent<HTMLInputElement>) => void;
  ariaLabel?: string;
  disabled?: boolean;
}) {
  return (
    <Input size="sm" value={value} onChange={(e) => onChange(e.target.value)}
      onKeyDown={onKeyDown} placeholder={placeholder} aria-label={ariaLabel} disabled={disabled}
      className={`min-w-0 rounded-sm ${mono ? "font-mono" : ""} ${className}`} />
  );
}

export function Select({
  value,
  onChange,
  options,
  ariaLabel,
  className = "",
  disabled,
}: {
  value: string;
  onChange: (value: string) => void;
  options: { value: string; label: string }[];
  ariaLabel?: string;
  className?: string;
  disabled?: boolean;
}) {
  return (
    <CossSelect items={options} value={value} disabled={disabled}
      onValueChange={(next) => { if (typeof next === "string") onChange(next); }}>
      <SelectTrigger size="sm" aria-label={ariaLabel} disabled={disabled}
        className={`h-8 min-w-0 rounded-sm font-mono text-xs ${className}`}>
        <SelectValue />
      </SelectTrigger>
      <SelectPopup alignItemWithTrigger={false} className="max-h-72">
        {options.map((option) => (
          <SelectItem key={option.value} value={option.value}>
            {option.label}
          </SelectItem>
        ))}
      </SelectPopup>
    </CossSelect>
  );
}

/** The one multi-line input: mono by default, bounded, shared chrome.
 * Replaces the bespoke per-view textarea class strings. */
export function TextArea({
  value,
  onChange,
  placeholder,
  ariaLabel,
  rows = 2,
  maxLength,
  disabled,
  mono = true,
  className = "",
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  ariaLabel?: string;
  rows?: number;
  maxLength?: number;
  disabled?: boolean;
  mono?: boolean;
  className?: string;
}) {
  return (
    <textarea
      value={value}
      disabled={disabled}
      rows={rows}
      maxLength={maxLength}
      placeholder={placeholder}
      aria-label={ariaLabel}
      spellCheck={false}
      onChange={(e) => onChange(e.target.value)}
      className={`w-full resize-y rounded-sm border border-line bg-panel px-2 py-1 text-xs leading-relaxed text-fg focus-visible:outline focus-visible:outline-1 focus-visible:outline-ring disabled:opacity-40 ${mono ? "font-mono" : ""} ${className}`}
    />
  );
}

/** The one numeric input: shared chrome, number semantics, bounded. */
export function NumberInput({
  value,
  onChange,
  ariaLabel,
  min,
  max,
  step = 1,
  className = "",
  disabled,
}: {
  value: number;
  onChange: (value: number) => void;
  ariaLabel?: string;
  min?: number;
  max?: number;
  step?: number;
  className?: string;
  disabled?: boolean;
}) {
  return (
    <Input type="number" size="sm" value={Number.isFinite(value) ? String(value) : ""} min={min}
      max={max} step={step} aria-label={ariaLabel} disabled={disabled}
      onChange={(e) => {
        const next = Number(e.target.value);
        if (Number.isFinite(next)) onChange(next);
      }}
      className={`min-w-0 rounded-sm font-mono ${className}`} />
  );
}

/** The one labeled checkbox: native input with the accent token, one
 * label treatment. Replaces the accent-/bare-checkbox drift. */
export function CheckBox({
  checked,
  onChange,
  disabled,
  children,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
  children: ReactNode;
}) {
  return (
    <label className={`flex items-center gap-2 text-xs text-fg-dim ${disabled ? "opacity-40" : ""}`}>
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
        className="accent-[var(--color-orange)]"
      />
      {children}
    </label>
  );
}
