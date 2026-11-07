"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";
import { PanelBottomClose, PanelBottomOpen, PanelLeftClose, PanelLeftOpen, PanelRightClose, PanelRightOpen } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Pane, Resizer } from "@ds/panes";

/** Shared three-pane Packet Analysis geometry. Resizes to the *actual* available
 * workspace, not a fixed 720px cap; hiding a pane never discards its data. */
export function PacketPaneSplit({
  list, details, bytes, detailTitle, bytesTitle, bytesActions,
}: {
  list: ReactNode;
  details: ReactNode;
  bytes: ReactNode;
  detailTitle: ReactNode;
  bytesTitle: ReactNode;
  bytesActions?: ReactNode;
}) {
  const rootRef = useRef<HTMLDivElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const detailRef = useRef<HTMLDivElement>(null);
  const [bounds, setBounds] = useState({ width: 1000, height: 680 });
  const [listHeight, setListHeight] = useState<number | null>(null);
  const [detailsWidth, setDetailsWidth] = useState<number | null>(null);
  const [inspectorOpen, setInspectorOpen] = useState(true);
  const [detailsOpen, setDetailsOpen] = useState(true);
  const [bytesOpen, setBytesOpen] = useState(true);

  useEffect(() => {
    const node = rootRef.current;
    if (!node) return;
    const observe = () => setBounds({
      width: node.getBoundingClientRect().width,
      height: node.getBoundingClientRect().height,
    });
    observe();
    const observer = new ResizeObserver(observe);
    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  const maxList = Math.max(108, bounds.height - 132);
  const minList = Math.min(108, maxList);
  const maxDetail = Math.max(180, bounds.width - 180);
  const minDetail = Math.min(180, maxDetail);
  const measuredList = listHeight === null ? bounds.height * 0.6 : listHeight;
  const shownList = Math.min(maxList, Math.max(minList, measuredList));
  const measuredDetail = detailsWidth === null ? bounds.width * 0.5 : detailsWidth;
  const shownDetail = Math.min(maxDetail, Math.max(minDetail, measuredDetail));

  const closeDetails = () => {
    if (!bytesOpen) setInspectorOpen(false);
    else setDetailsOpen(false);
  };
  const closeBytes = () => {
    if (!detailsOpen) setInspectorOpen(false);
    else setBytesOpen(false);
  };
  return (
    <div ref={rootRef} className="flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden">
      <div ref={listRef}
        className={`min-h-0 overflow-auto bg-panel ${inspectorOpen ? "shrink-0" : "flex-1"}`}
        style={inspectorOpen ? { height: shownList } : undefined}>
        {list}
      </div>
      {inspectorOpen ? (
        <>
          <Resizer direction="vertical" ariaLabel="Resize packet list and inspectors"
            value={shownList} min={minList} max={maxList} onChange={setListHeight}
            onDragStart={() => {
              const measured = Math.round(listRef.current?.getBoundingClientRect().height ?? shownList);
              setListHeight(measured);
              return measured;
            }} />
          <div className="flex min-h-0 min-w-0 flex-1">
            {detailsOpen && (
              <div ref={detailRef} className={bytesOpen ? "flex min-h-0 shrink-0 flex-col overflow-hidden" : "flex min-h-0 min-w-0 flex-1 flex-col overflow-hidden"}
                style={bytesOpen ? { width: shownDetail } : undefined}>
                <Pane className="min-h-0 flex-1" title={detailTitle} actions={
                  <>
                    {!bytesOpen && (
                      <Button variant="ghost" size="icon-xs" title="Show packet bytes" aria-label="Show packet bytes"
                        onClick={() => setBytesOpen(true)}><PanelRightOpen size={14}/></Button>
                    )}
                    <Button variant="ghost" size="icon-xs" title="Hide packet details" aria-label="Hide packet details"
                      onClick={closeDetails}><PanelLeftClose size={14}/></Button>
                    <Button variant="ghost" size="icon-xs" title="Hide packet inspectors" aria-label="Hide packet inspectors"
                      onClick={() => setInspectorOpen(false)}><PanelBottomClose size={14}/></Button>
                  </>
                }>
                  {details}
                </Pane>
              </div>
            )}
            {detailsOpen && bytesOpen && (
              <Resizer direction="horizontal" ariaLabel="Resize packet details and bytes"
                value={shownDetail} min={minDetail} max={maxDetail} onChange={setDetailsWidth}
                onDragStart={() => {
                  const measured = Math.round(detailRef.current?.getBoundingClientRect().width ?? shownDetail);
                  setDetailsWidth(measured);
                  return measured;
                }} />
            )}
            {bytesOpen && (
              <Pane
                className="flex-1 overflow-hidden"
                title={bytesTitle}
                actions={
                  <>
                    {bytesActions}
                    {!detailsOpen && (
                      <Button variant="ghost" size="icon-xs" title="Show packet details" aria-label="Show packet details"
                        onClick={() => setDetailsOpen(true)}><PanelLeftOpen size={14}/></Button>
                    )}
                    <Button variant="ghost" size="icon-xs" title="Hide packet bytes" aria-label="Hide packet bytes"
                      onClick={closeBytes}><PanelRightClose size={14}/></Button>
                    <Button variant="ghost" size="icon-xs" title="Hide packet inspectors" aria-label="Hide packet inspectors"
                      onClick={() => setInspectorOpen(false)}><PanelBottomClose size={14}/></Button>
                  </>
                }
              >
                {bytes}
              </Pane>
            )}
          </div>
        </>
      ) : (
        <div className="flex shrink-0 justify-end border-t border-line bg-panel px-2 py-1">
          <Button size="xs" variant="ghost" title="Restore packet detail and bytes panes"
            onClick={() => {
              setInspectorOpen(true);
              if (!detailsOpen && !bytesOpen) { setDetailsOpen(true); setBytesOpen(true); }
            }}><PanelBottomOpen size={14}/> Show Inspectors</Button>
        </div>
      )}
    </div>
  );
}
