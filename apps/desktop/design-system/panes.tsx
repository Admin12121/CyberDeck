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
import { Tabs, TabsList, TabsTab } from "@/components/ui/tabs";

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
    <Tabs value={active} onValueChange={(value) => onChange(value as T)}
      className="w-full gap-0">
      <TabsList aria-label={ariaLabel} size="sm" variant="underline"
        className="cd-workspace-toolbar w-full min-w-0 justify-start gap-1 overflow-x-auto px-2"
        data-placement={placement}>
        {items.map((tab) => (
          <TabsTab key={tab} value={tab} className="h-7 shrink-0 rounded-sm px-2 font-mono text-[10px] uppercase tracking-wide">
            {tab}
          </TabsTab>
        ))}
      </TabsList>
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
    <Input size="sm" value={value} onChange={(e) => onChange(e.target.value)}
      onKeyDown={onKeyDown} placeholder={placeholder} aria-label={ariaLabel}
      className={`min-w-0 rounded-sm ${mono ? "font-mono" : ""} ${className}`} />
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
    <CossSelect items={options} value={value}
      onValueChange={(next) => { if (typeof next === "string") onChange(next); }}>
      <SelectTrigger size="sm" aria-label={ariaLabel}
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
