"use client";

/** Display real bounded packet-count observations from native capture status polling.
 * No synthetic traffic and no claims about pre-capture interface activity. */
export type CaptureActivityPoint = { at: number; packets: number };

export function CaptureActivity({ samples }: { samples: readonly CaptureActivityPoint[] }) {
  if (samples.length < 2) return null;
  const rates = samples.slice(1).map((item, index) => {
    const previous = samples[index];
    return Math.max(0, (item.packets - previous.packets) * 1000 / Math.max(1, item.at - previous.at));
  });
  const peak = Math.max(1, ...rates);
  const points = rates.map((value, index) =>
    `${(index / Math.max(1, rates.length - 1) * 96 + 2).toFixed(1)},${(24 - value / peak * 20).toFixed(1)}`
  ).join(" ");
  return (
    <svg viewBox="0 0 100 28" role="img" aria-label="Recent captured packet activity"
      className="h-7 w-32 shrink-0 text-fg-dim" preserveAspectRatio="none">
      <title>Captured packets per second from native status samples</title>
      <polyline points={points} fill="none" stroke="currentColor" strokeWidth="1.5"
        strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}
