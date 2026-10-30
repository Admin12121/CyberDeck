# HackTool — Cybersecurity Workbench

Integrated desktop security workbench: **Tauri 2 + Rust** native core, **Next.js (static export) + TypeScript** interface, **Dark Matter** theme (Zed-style near-black, blue = selection/analysis, orange = active operations).

Full product and engineering specification: [Master Plan.md](./Master Plan.md).
Upstream sources for study and future engine packaging live in `reference/` (never committed, never shipped as-is).

## Status — Arc 1 (workbench shell)

- Monorepo: bun workspace (frontend) + Cargo workspace (native).
- Desktop shell: title bar, category rail (Crypto / Network / Web / Reverse / Forensics), navigator, workspace host, inspector, jobs dock (Ctrl+J), status bar, command palette (Ctrl+K).
- Feature-MVC structure under `apps/desktop/features/<feature>/{model,controller,view}`.
- Shared job pipeline: typed Tauri IPC (`Channel<JobEvent>`), tokio workers, safe cancellation; browser fallback for UI development without the desktop shell.
- Working capability slices: Recipes (four-column pipeline, real operations), hash format identification (conservative heuristics), digests (WebCrypto), strings extraction + Shannon entropy, sample packet three-pane studio, Burp-style web layout with editors.
- Engines (john/hashcat, nmap-family, ZAP, Wireshark dissectors, Ettercap) are **not** integrated yet — planned per the Master Plan phase gates with license review first.

## Commands

```bash
bun install                 # frontend deps
bun run dev                 # Next dev server (browser mode, IPC falls back to simulation)
bun run tauri dev           # full desktop shell (Tauri + Next dev)
bun run build               # static export -> apps/desktop/out
bun run icons               # regenerate placeholder icons
cargo check --workspace     # native side
cargo test --workspace      # core + job wire-type tests
bun run tauri build         # packaged installer (per-platform)
```

## Layout

```
apps/desktop/            # Next.js app + src-tauri (Tauri 2 shell)
  app/                   # routes (static export)
  components/shell/      # workbench shell (rail, navigator, dock, palette…)
  design-system/         # Dark Matter pane primitives
  features/              # feature-MVC modules
    crypto/  network/  web/  reverse/  forensics/
      model/             # pure domain types + engines (deterministic, testable)
      controller/        # state transitions (pure)
      view/              # React views (client components)
  lib/                   # typed IPC client, byte utils
  state/                 # workbench context, job model
  src-tauri/             # commands, job manager, capabilities (least privilege)
crates/core/             # shared Rust domain types (artifacts, jobs)
scripts/                 # icon generation etc.
reference/               # upstream study sources (git-ignored)
```

## Rules baked into this scaffold

- The frontend never spawns processes or touches the filesystem — every native action is a typed command in `src-tauri` (Master Plan §9.2).
- Tools are named by user-facing operation, never by upstream engine; engine identity appears in results provenance (§5.5, §6).
- Production builds must work offline with no server; no Next.js server features (§2.2).
- Capabilities are gated by status (`planned` → `integrated` → `verified` → `shipping`); UI never claims more (§6).
- `reference/` is study material only; redistribution/licensing review precedes any bundling (§7.2).
