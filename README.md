# HackTool: Cybersecurity Workbench

Integrated desktop security workbench: **Tauri 2 + Rust** native core, **Next.js (static export) + TypeScript** interface, **Dark Matter** theme (Zed-style near-black, blue = selection/analysis, orange = active operations).

Full product and engineering specification: [Master Plan.md](./Master Plan.md).
Upstream sources for study and future engine packaging live in `reference/` (never committed, never shipped as-is).

## Status: Arc 3 (recipes suite + packet engine)

- Monorepo: bun workspace (frontend) + Cargo workspace (native).
- Desktop shell: title bar (logo), category rail (Crypto / Network / Web / Reverse / Forensics), navigator, workspace host, inspector, jobs dock (Ctrl+J), status bar, command palette (Ctrl+K). All sections resizable with clamped drag handles; sizes persist.
- Warm Dark Matter: orange is the primary accent (selection, active state, focus); blue reserved for data semantics.
- Feature-MVC structure under `apps/desktop/features/<feature>/{model,controller,view}`.
- Shared job pipeline: typed Tauri IPC (`Channel<JobEvent>`), tokio workers, safe cancellation; browser fallback for UI development without the desktop shell.
- **Native crypto engine (`crates/crypto`)**: MD5, SHA-1/224/256/384/512, HMAC-SHA256, CRC32, Base64/hex, URL encode/decode, XOR, ROT13, gzip, entropy, magic-byte signatures; reference test vectors in tests.
- **Artifact store (`crates/storage`)**: SQLite (bundled) index of imported evidence; immutable copies under the OS app-data directory, content-addressed by SHA-256.
- **Packet engine (`crates/packet`)**: classic PCAP parsing (both endiannesses, micro/nanosecond) with Ethernet/ARP/IPv4/IPv6/TCP/UDP/ICMP dissection and port-based service naming; guard rails on malformed records; 8 tests.
- **Recipes**: 24 operations (Base32/64, hex, binary, URL, ROT-N, XOR, case ops, JSON, JWT decode, URL/email extraction, hex dumps), inline step parameters, drag-and-drop, image preview from Base64 output, input over output with resizable split.
- **Hash Analysis**: format identification plus real candidate verification through the native engine.
- **Real evidence pipeline**: import via native file dialog, real digests + signature + entropy computed at import, hex view and strings extraction served from Rust; provenance travels with results.
- Engines (john/hashcat, nmap-family, ZAP, Wireshark dissectors, Ettercap) are **not** bundled yet; planned per the Master Plan phase gates with license review first.

## Commands

```bash
bun install                 # frontend deps
bun run dev                 # Next dev server (browser mode, IPC falls back to simulation)
bun run tauri dev           # full desktop shell (Tauri + Next dev)
bun run build               # static export -> apps/desktop/out
bun run icons               # regenerate the icon set from logo.webp
cargo test --workspace      # native tests: crypto vectors, evidence pipeline, storage
bun run tauri build         # packaged installer (per-platform)
```

## Layout

```
apps/desktop/            # Next.js app + src-tauri (Tauri 2 shell)
  app/                   # routes (static export)
  components/shell/      # workbench shell (rail, navigator, dock, palette…)
  design-system/         # Dark Matter pane primitives + resizer
  features/              # feature-MVC modules
    crypto/  network/  web/  reverse/  forensics/
      model/             # pure domain types + engines (deterministic, testable)
      controller/        # state transitions (pure)
      view/              # React views (client components)
  lib/                   # typed IPC client, byte utils
  state/                 # workbench context, job model
  src-tauri/             # commands, job manager, evidence store, capabilities
crates/core/             # shared Rust domain types (artifacts, jobs)
crates/crypto/           # native operations: digests, HMAC, encodings, gzip
crates/storage/          # SQLite artifact index
scripts/                 # icon generation etc.
reference/               # upstream study sources (git-ignored)
```

## Rules baked into this scaffold

- The frontend never spawns processes or touches the filesystem; every native action is a typed command in `src-tauri`, and file paths only ever come from the native dialog or our own index (Master Plan §9.2).
- Tools are named by user-facing operation, never by upstream engine; engine identity appears in results provenance (§5.5, §6).
- Production builds must work offline with no server; no Next.js server features (§2.2).
- Capabilities are gated by status (`planned` → `integrated` → `verified` → `shipping`); UI never claims more (§6).
- `reference/` is study material only; redistribution/licensing review precedes any bundling (§7.2).
