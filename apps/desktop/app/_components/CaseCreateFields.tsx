"use client";
/**
 * The one case create-form pattern (name + optional description), extracted
 * from the start page. Case creation is centralized: only the start page,
 * the Cases page, and the status-bar quick-create render this.
 */
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export function CaseCreateFields({
  title,
  description,
  onTitleChange,
  onDescriptionChange,
  disabled,
  idPrefix = "cyberdeck-case",
}: {
  title: string;
  description: string;
  onTitleChange: (value: string) => void;
  onDescriptionChange: (value: string) => void;
  disabled?: boolean;
  idPrefix?: string;
}) {
  return (
    <div className="grid gap-2 sm:grid-cols-[105px_1fr] sm:items-center">
      <Label htmlFor={`${idPrefix}-name`} className="text-xs text-fg-muted">
        Name
      </Label>
      <Input
        id={`${idPrefix}-name`}
        value={title}
        size="sm"
        onChange={(e) => onTitleChange(e.target.value)}
        disabled={disabled}
        maxLength={120}
        placeholder="Investigation name"
      />
      <Label htmlFor={`${idPrefix}-description`} className="text-xs text-fg-muted">
        Description
      </Label>
      <Input
        id={`${idPrefix}-description`}
        size="sm"
        value={description}
        onChange={(e) => onDescriptionChange(e.target.value)}
        disabled={disabled}
        maxLength={500}
        placeholder="Optional"
      />
    </div>
  );
}
