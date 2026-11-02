"use client";

import { Fragment, useMemo } from "react";
import { ArrowDownIcon, ArrowUpIcon, CornerDownLeftIcon, XIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Command,
  CommandCollection,
  CommandDialog,
  CommandDialogPopup,
  CommandDialogPrimitive,
  CommandEmpty,
  CommandFooter,
  CommandGroup,
  CommandGroupLabel,
  CommandInput,
  CommandItem,
  CommandList,
  CommandPanel,
  CommandSeparator,
  CommandShortcut,
} from "@/components/ui/command";
import { Kbd, KbdGroup } from "@/components/ui/kbd";
import { CATEGORIES } from "@state/tool-registry";
import { useWorkbench } from "@state/workbench";

interface PaletteAction {
  id: string;
  value: string;
  label: string;
  hint: string;
  shortcut?: string;
  run: () => void;
}

interface PaletteGroup {
  value: string;
  items: PaletteAction[];
}

/** Uses the shared coss Command / Kbd primitives; the workbench owns shortcuts and actions. */
export function CommandPalette() {
  const wb = useWorkbench();

  const groups = useMemo<PaletteGroup[]>(() => [
    ...CATEGORIES.map((category) => ({
      value: category.label,
      items: category.tools.filter((tool) => !tool.disabled).map((tool) => ({
        id: tool.id,
        value: `${category.label} ${tool.label} ${tool.hint}`,
        label: tool.label,
        hint: tool.hint,
        run: () => wb.selectTool(tool.id),
      })),
    })).filter((group) => group.items.length > 0),
    {
      value: "Actions",
      items: [
        {
          id: "jobs",
          value: "Open jobs dock active completed jobs",
          label: "Open Jobs",
          hint: "View active and completed jobs",
          shortcut: "Ctrl+J",
          run: () => { wb.setDockTab("jobs"); wb.setDockOpen(true); },
        },
        {
          id: "console",
          value: "Open console operation messages",
          label: "Open Console",
          hint: "Inspect local operation messages",
          shortcut: "Ctrl+`",
          run: () => { wb.setDockTab("console"); wb.setDockOpen(true); },
        },
        {
          id: "navigator",
          value: "Toggle navigator contextual sidebar",
          label: "Toggle Navigator",
          hint: "Expand or collapse contextual navigation",
          shortcut: "Ctrl+B",
          run: wb.toggleNavigator,
        },
      ],
    },
  ], [wb]);

  const run = (item: PaletteAction) => {
    wb.setPaletteOpen(false);
    item.run();
  };

  return (
    <CommandDialog open={wb.paletteOpen} onOpenChange={wb.setPaletteOpen}>
      <CommandDialogPopup aria-label="CyberDeck command palette">
        <Command items={groups}>
          <div className="relative">
            <CommandInput placeholder="Search tools and commands…" className="pr-10" />
            <CommandDialogPrimitive.Close
              render={
                <Button variant="ghost" size="icon-xs" aria-label="Close command palette"
                  className="absolute right-3 top-1/2 z-10 -translate-y-1/2" />
              }
            >
              <XIcon aria-hidden="true" />
            </CommandDialogPrimitive.Close>
          </div>
          <CommandPanel>
            <CommandEmpty>No matching CyberDeck commands.</CommandEmpty>
            <CommandList>
              {(group: PaletteGroup, index: number) => (
                <Fragment key={group.value}>
                  {index > 0 && <CommandSeparator />}
                  <CommandGroup items={group.items}>
                    <CommandGroupLabel>{group.value}</CommandGroupLabel>
                    <CommandCollection>
                      {(item: PaletteAction) => (
                        <CommandItem key={item.id} value={item.value} onClick={() => run(item)}
                          title={item.hint} className="min-h-9 px-3">
                          <span className="min-w-0 flex-1 truncate">{item.label}</span>
                          {item.shortcut && <CommandShortcut>{item.shortcut}</CommandShortcut>}
                        </CommandItem>
                      )}
                    </CommandCollection>
                  </CommandGroup>
                </Fragment>
              )}
            </CommandList>
          </CommandPanel>
          <CommandFooter>
            <div className="flex items-center gap-4">
              <span className="flex items-center gap-2">
                <KbdGroup><Kbd><ArrowUpIcon /></Kbd><Kbd><ArrowDownIcon /></Kbd></KbdGroup>
                Navigate
              </span>
              <span className="flex items-center gap-2"><Kbd><CornerDownLeftIcon /></Kbd> Open</span>
            </div>
            <span className="flex items-center gap-2"><Kbd>Esc</Kbd> Close</span>
          </CommandFooter>
        </Command>
      </CommandDialogPopup>
    </CommandDialog>
  );
}
