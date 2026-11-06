---
name: cyberdeck-ui
description: CyberDeck UI/UX design language for every frontend change — use whenever creating or editing any .tsx view, design-system primitive, workspace layout, toolbar, empty state, dialog, or status display in apps/desktop; also whenever the user complains about text density, borders, alignment, "AI slop", or clutter in the UI.
---

# CyberDeck UI/UX design language

You are editing a security workbench whose users are pentesters staring at it
for hours. Every screen must answer one question at a glance: **what is the
state, and what is the one action available now?** Everything else is a hover
away. The references are Bettercap (icon rail, dense tables, colored type
chips), Wireshark (one toolbar row, one big results pane) and Zenmap (simple
tabs, one focused view).

## The five laws

1. **One screen, one question.** If two sections are visible at once, both
   lose. Use an `IconRail` mode switcher and render exactly one mode.
2. **Text budget per screen: ~30 words.** Explanations, honesty contracts,
   rationale and platform caveats go into `InfoTip` tooltips — verbatim, they
   must survive there (contract tests assert tooltip text, not body copy).
   The footer status bar already explains global state; never re-explain it.
3. **Border budget: ONE per region.** Borders group real content only. A
   toolbar row has no border-b; sections are separated by spacing. If you
   count 3+ nested bordered rectangles in one region, you have failed.
4. **Case management lives ONLY in the Case section.** No Create/Choose-case
   buttons, no case pointer sentences in tool views. The footer already shows
   the case state — silence about it is correct.
5. **Authorization is a dialog, not chrome.** Active operations confirm via
   the native Yes/No dialog with full wording (existing pattern). On-screen
   auth checkboxes exist only where the backend takes a literal parameter —
   then ONE compact checkbox in the toolbar row, never a section.

## Primitives (use these, do not hand-roll)

All in `apps/desktop/design-system/compact.tsx` (plus the older
`design-system/panes.tsx`):

- `IconRail` — icon-only pill buttons (34px, orange active pill, badge counts,
  tooltip = label). NEVER render it full-width with labels underneath — that
  reads as tabs, which users explicitly rejected.
- `SectionHeader` — small icon + normal-case title + ONE state chip + optional
  InfoTip. No ALL-CAPS mono bars.
- `InfoTip` — carries long text; pair it with any header.
- `IconButton` — icon-only toolbar control, tooltip REQUIRED.
- `StatusStrip` — one row of muted chips for state that demands action
  (counts, blockers). Not for "everything is fine".

## Layout contracts

- **Toolbar row**: one `flex flex-wrap items-center gap-2 py-1.5 pr-2` row;
  every control `h-7`/`h-8`; mixed heights in one row are a defect. Icon
  buttons may carry text labels only if the icon is ambiguous.
- **Empty state = centered card** using the full remaining height, modeled on
  the welcome screen: rounded card → card header (icon + short title) → card
  panel (one short line). No badge rows, no stacked explanations, no buttons
  beyond the single primary action.
- **Data state**: the table/SVG fills the remaining height edge to edge.
- **Dialogs**: standard frame → frame header → frame panel; actions
  Continue/Cancel right-aligned. This is also the authorization pattern.
- **Max two borders per screen**: around the content pane and (optionally)
  around one focused card. Everything else separates by spacing.

## Language rules

- Titles: normal case, ≤4 words ("Lab scope", "ARP analysis").
- Buttons: verbs ≤2 words ("Sweep", "Analyze"). Verbose gating wording goes in
  the tooltip.
- Status chips: single words ("ready", "no capture", "running").
- Never put Master Plan references, §-numbers, or honesty-contract text on
  screen — InfoTip only. Honesty is non-negotiable; on-screen verbosity is.

## Verification contract

- `cd apps/desktop && bun run typecheck` clean.
- Colocated `*.test.mjs` source-contract files updated: assertions target the
  NEW markup, and honesty-wording assertions point at tooltip text.
- Before committing, re-read your own diff and delete every explanation that
  duplicates a tooltip, every border that separates nothing, and every control
  whose state the footer already shows.
