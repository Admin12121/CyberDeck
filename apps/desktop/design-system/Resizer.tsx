"use client";
/**
 * Drag handle for resizable shell sections (Master Plan §3.5: all essential
 * panes resizable/collapsible). Pointer-event based, clamps between min/max,
 * and doubles as a visible separator.
 */
import { useCallback, useEffect, useRef, useState } from "react";

export type ResizeDirection = "horizontal" | "vertical";

interface ResizerProps {
  direction: ResizeDirection;
  /** Current size in px being controlled. */
  value: number;
  onChange: (value: number) => void;
  min: number;
  max: number;
  /** Which side the panel sits on relative to the drag direction. */
  flip?: boolean;
  ariaLabel: string;
  /**
   * Called on drag start; may return the synced starting size. Use when the
   * panel is in a flexible (unset) state and must be measured before the
   * first move applies a pixel delta.
   */
  onDragStart?: () => number | void;
}

export function Resizer({ direction, value, onChange, min, max, flip = false, ariaLabel, onDragStart }: ResizerProps) {
  const [dragging, setDragging] = useState(false);
  const startRef = useRef<{ pointer: number; value: number } | null>(null);

  const onPointerDown = useCallback(
    (e: React.PointerEvent<HTMLDivElement>) => {
      e.preventDefault();
      const synced = onDragStart ? onDragStart() : undefined;
      startRef.current = {
        pointer: direction === "horizontal" ? e.clientX : e.clientY,
        value: typeof synced === "number" ? synced : value,
      };
      setDragging(true);
    },
    [direction, value, onDragStart],
  );

  useEffect(() => {
    if (!dragging) return;
    const onMove = (e: PointerEvent) => {
      if (!startRef.current) return;
      const current = direction === "horizontal" ? e.clientX : e.clientY;
      const delta = current - startRef.current.pointer;
      const next = startRef.current.value + (flip ? -delta : delta);
      onChange(Math.min(max, Math.max(min, next)));
    };
    const onUp = () => {
      startRef.current = null;
      setDragging(false);
    };
    window.addEventListener("pointermove", onMove);
    window.addEventListener("pointerup", onUp);
    return () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
    };
  }, [dragging, direction, flip, min, max, onChange]);

  return (
    <div
      role="separator"
      aria-label={ariaLabel}
      aria-orientation={direction === "horizontal" ? "vertical" : "horizontal"}
      aria-valuenow={Math.round(value)}
      aria-valuemin={min}
      aria-valuemax={max}
      tabIndex={0}
      onPointerDown={onPointerDown}
      onKeyDown={(e) => {
        const step = e.shiftKey ? 32 : 8;
        if (direction === "horizontal" && (e.key === "ArrowLeft" || e.key === "ArrowRight")) {
          e.preventDefault();
          const dir = (e.key === "ArrowLeft" ? -1 : 1) * (flip ? -1 : 1);
          onChange(Math.min(max, Math.max(min, value + dir * step)));
        }
        if (direction === "vertical" && (e.key === "ArrowUp" || e.key === "ArrowDown")) {
          e.preventDefault();
          const dir = (e.key === "ArrowUp" ? -1 : 1) * (flip ? -1 : 1);
          onChange(Math.min(max, Math.max(min, value + dir * step)));
        }
      }}
      className={`group relative z-10 shrink-0 transition-colors ${
        direction === "horizontal" ? "w-px cursor-col-resize" : "h-px cursor-row-resize"
      } ${dragging ? "bg-orange" : "bg-line hover:bg-line-strong"}`}
      style={{ touchAction: "none" }}
      data-dragging={dragging || undefined}
    >
      {/* wider invisible hit area around the 1px visual line */}
      <div
        className={
          direction === "horizontal"
            ? "absolute inset-y-0 -left-2 -right-2"
            : "absolute inset-x-0 -top-2 -bottom-2"
        }
      />
    </div>
  );
}
