# Master Plan

**Cybersecurity Workbench**  
Product and Engineering Specification  
**Platforms:** Linux, Windows, macOS  
**Technology:** Rust, Tauri 2, Next.js, TypeScript  
**Interface:** Dark Matter theme informed by Delta and Zed

The project is a self-contained cybersecurity desktop application that consolidates capabilities from established open-source tools. It provides one installation, specialized security workspaces, a common execution model, and locally managed investigation data. Integrated functionality is organized by task rather than by third-party product name.

---

## 1. Product scope and positioning

### 1.1 Core requirements

1. The application shall be distributed as installable desktop software for Linux, Windows, and macOS. A hosted website or browser dashboard is not part of the product.
2. Each official release shall include the security engines and private runtimes required by its advertised capabilities. Users shall not be required to install individual upstream tools.
3. Features shall perform genuine operations and expose relevant advanced settings, raw results, and diagnostics.
4. Workspaces shall follow established domain-specific interaction patterns for packet analysis, web security, scanning, cryptographic transformations, and forensics.
5. Shared navigation, search, project storage, keyboard shortcuts, and typed data exchange shall connect the specialized workspaces.
6. All supported capabilities shall be validated on each advertised operating system. Platform limitations shall be stated explicitly.
7. Third-party redistribution, license compatibility, signing, and dependency requirements shall be resolved before any engine is included in a public installer.
8. Reverse engineering and AI integration shall follow the initial desktop release as dedicated development phases.

### 1.2 Target users

- Cybersecurity students studying networking, cryptography, web security, digital forensics and offensive security.
- CTF participants who need rapid decoding, analysis, discovery and evidence organization.
- Authorized penetration testers and security auditors.
- Malware and reverse-engineering researchers (extended capability in a later phase).
- Instructors who need reproducible labs and inspectable results.

### 1.3 Product positioning

The product is an integrated desktop application, not a directory of links, a collection of embedded websites, a generic terminal launcher, or an operating system distribution. Each security discipline retains a dedicated interface within the common application shell.

The application shall demonstrate measurable advantages in the following areas:

- Less setup: integrated engines and private runtimes.
- Less context switching: cross-tool data handoff.
- Better usability: consistent shortcuts, workspaces, accessibility and inspectable configuration.
- Better investigation continuity: saved captures, requests, runs, evidence and notes.
- Better engine choice: use the most appropriate compatible implementation or hardware, measured rather than assumed.
- Better reproducibility: record inputs, settings, engine versions and source hashes.

### 1.4 Exclusions from the initial stable release

- Shipping a browser-accessible remote execution service.
- Rebuilding the entire Ghidra, Wireshark, ZAP or Hashcat source code from scratch.
- Guaranteed unrestricted functionality without operating-system privileges, GPU drivers or required network capture facilities.
- A complete native reverse-engineering suite in the first release.
- Autonomous AI-driven active security testing.
- Exact copying of protected logos, paid/proprietary assets or distinct branded artwork.

**Interface reference policy:** Preserve useful layout patterns, information hierarchy, workflows, keyboard interactions, and relevant feature coverage from reference applications. Use independently developed styling, icons, and branding. Do not incorporate proprietary application code or protected artwork without appropriate rights.

---

## 2. Technology and desktop architecture

### 2.1 Technology stack

| Layer | Technology | Responsibility |
|---|---|---|
| App shell / packaging | **Tauri 2** | Desktop windows, installers, operating-system integration, signed updates. |
| Frontend framework | **Next.js (App Router, static export)** | All desktop interface views and client-side interaction. |
| Frontend language | **TypeScript** | Type-safe interaction and view models. |
| Native core | **Rust** | Modules, jobs, hardware detection, controlled engine execution, file analysis. |
| Async runtime | Tokio | Background tasks, streams, cancellation, bounded concurrency. |
| IPC | Tauri commands + events/channels | Typed frontend/native communication without an app web server. |
| Local persistence | SQLite | Cases, settings, scan history, references, tool/session records. |
| Artifact storage | Versioned local directories | Captures, exports, attachments, binary samples, engine outputs. |
| UI primitives | Tailwind CSS + Radix/shadcn patterns | Custom, accessible, density-aware components. |
| Editors | Monaco or CodeMirror 6, selected after benchmarking | Request/response, recipes, hex and rule editing. |
| Large tables | Virtualized grid components | Packet lists, scan results, request history, finding lists. |
| Graphs | Dedicated canvas/WebGL-backed graph views where justified | Topology, flows, later control-flow graphs. |
| Engine inclusion | Rust libraries, bundled binaries, private runtimes | Features available immediately after installation. |

### 2.2 Next.js desktop configuration

Next.js is used for the application interface. Tauri loads the exported static assets rather than a production Next.js server. The initial configuration is:

```ts
// apps/desktop/next.config.ts
import type { NextConfig } from "next";

const config: NextConfig = {
  output: "export",
  images: { unoptimized: true },
};

export default config;
```

```jsonc
// apps/desktop/src-tauri/tauri.conf.json (illustrative relevant fields)
{
  "build": {
    "beforeDevCommand": "pnpm dev",
    "beforeBuildCommand": "pnpm build",
    "devUrl": "http://localhost:3000",
    "frontendDist": "../out"
  }
}
```

- The localhost development URL exists only while developing; shipped desktop builds load bundled assets.
- **Do not use** Next.js server-side rendering, runtime server actions, production API routes, server-hosted middleware or Node-only server dependencies.
- UI components that invoke Rust or access browser-only objects must be client components.
- Dynamic application data comes through Tauri IPC, not Next.js server endpoints.
- Every production build must work disconnected from the network.

Reference: [Tauri: Next.js integration](https://tauri.app/start/frontend/nextjs/) and [Tauri frontend configuration](https://v2.tauri.app/start/frontend/).

### 2.3 Execution layers

```text
┌───────────────────────────────────────────────────────────────────────┐
│ Tauri Desktop Window · Next.js Interface                              │
│ App Shell · Packet Studio · Web Studio · Scan Studio · Recipes        │
│ Hash/Crypto · Case Explorer · Jobs · Settings                         │
└───────────────────────────────┬───────────────────────────────────────┘
                                │ typed Tauri IPC / events
┌───────────────────────────────▼───────────────────────────────────────┐
│ Rust Application Core                                                  │
│ Capability Registry · Session Manager · Artifact Store · Job Manager  │
│ Permission Broker · Engine Planner · Results Normalizer               │
└─────────────┬─────────────────┬──────────────────┬───────────────────┘
              │                 │                  │
        Built-in Rust      Embedded libraries  Bundled engine workers
        crypto/parsers      / WASM modules       private Java/Python,
                                               GPU/CPU and CLI engines
              │                 │                  │
              └─────────────────┴──────────────────┘
                                │
                    Normalized outputs + raw evidence
                                │
                      Workspace / SQLite / exports
```

### 2.4 Engine runtime rules

- Production builds include **all engines advertised for that build**, using compliant bundling methods.
- A capability can be built into Rust, linked to a library, or run as a private packaged worker; the interface shall not require users to manage the implementation directly.
- Sidecar executables and bundled resources are stored in the application's protected installation directory.
- No arbitrary shell execution through the frontend; the Rust core owns argument validation, process creation and sandbox policy.
- Private Python or Java runtimes must be bundled when an engine actually requires them.
- Every engine has an ABI/CLI/API compatibility manifest and a supported-platform matrix.
- Never label an engine "integrated" if it only opens a separate installed application.
- Changes in upstream tools must not silently break the shared data model.

---

## 3. Visual design: Dark Matter, Delta, and Zed

### 3.1 Visual references

The reference Delta screenshot establishes the reference for a dark, information-dense desktop layout. Relevant characteristics include a narrow navigation rail, structured tables and graphs, a contextual inspector, subtle panel separators, and selective use of blue and orange. The application shall use these interface characteristics with independent visual assets and security-specific workflows.

**Delta reference:** Compact title bars, dense tables, searchable lists, multi-pane context, and precise separators.  
**Zed reference:** Editor typography, keyboard navigation, split panes, persistent tabs, and restrained window chrome.  
**Dark Matter theme:** Near-black neutral surfaces, blue for selection and analysis, orange for active operations, readable gray text, and distinct error and success states.

### 3.2 Proposed design tokens (original palette, not extracted official Delta values)

```css
:root[data-theme="darkmatter"] {
  --app-bg:           #0b0c10;
  --sidebar-bg:       #0e1014;
  --panel-bg:         #11141a;
  --panel-raised:     #171b22;
  --input-bg:         #0d1015;
  --border-subtle:    #222934;
  --border-strong:    #354050;
  --text-primary:     #dce2ea;
  --text-secondary:   #929eae;
  --text-muted:       #667181;
  --accent-blue:      #4d9fff;
  --accent-blue-dim:  #18344e;
  --accent-orange:    #ff904d;
  --accent-orange-dim:#432a1f;
  --success:          #5dc8a0;
  --warning:          #e7b66c;
  --error:            #e87578;
  --selection-bg:     #142738;
}
```

**Color behavior**

- **Blue:** selected row, active navigation, filter application, graph edge, read/analyze status.
- **Orange:** active operation, running job, secondary focus, meaningful highlights and security-sensitive controls.
- **Green:** successful completion or verified status only.
- **Red:** actual errors, blocked actions and significant alerts only.
- **Gray:** nearly everything else; do not turn every category into a decorative color.
- Decorative glow, neon borders, blurred gradients, particle animation, and ornamental terminal graphics are excluded.

### 3.3 Typography and density

- UI: crisp modern sans serif, compact label and control sizing, restrained line-height.
- Data: configurable monospaced font with stable column alignment.
- Default UI density: **compact**, with a comfortable option for accessibility.
- Small panels and command controls are acceptable; tiny unreadable text is not.
- Prioritize contrast, focus visibility, information hierarchy and truncation/tooltip behavior.

### 3.4 Desktop shell layout

```text
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ App | Case: Sample Investigation | Packet Studio  •  Scan Studio  •  Recipe |  ⌘K  │
├──────┬─────────────────────┬───────────────────────────────────────┬─────────────────┤
│ rail │ section navigator   │ active specialist workspace          │ contextual       │
│      │                     │                                       │ inspector        │
│ home │ project tree        │ [toolbar + filters]                   │                 │
│ pkt  │ captures / sessions │                                       │ selected object  │
│ web  │ targets / requests  │  full working tool-specific UI        │ fields / meta    │
│ scan │ operations / jobs   │                                       │ actions / notes  │
│ cook │                     │                                       │                 │
│ hash │                     │                                       │                 │
├──────┴─────────────────────┴───────────────────────────────────────┴─────────────────┤
│ Jobs • Console • Evidence • Problems | live execution / progress / logs             │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

**Panel sizing targets (adjustable, not rigid):** title bar ~36-42 px; global rail ~44-52 px; navigation sidebar ~220-280 px; inspector ~280-360 px; bottom dock initially collapsed, expandable to ~160-280 px. All essential panes must be resizable/collapsible. Support layouts for 1366×768 and higher, including high-DPI scaling.

### 3.5 Common application behaviors

- Tabs for multiple active tool workspaces, like an editor; pinned and recently used tabs.
- Independent state per tab; no data loss when switching.
- Command palette (Ctrl/Cmd+K), global searchable actions and context-sensitive menus.
- Split views, drag-resize separators, keyboard-first table and editor navigation.
- Ctrl/Cmd+P for tool search; shortcuts configurable and OS-aware.
- Status bar showing active workspace, resource use, job state, capture state and engine version.
- Optional right-side inspector; dashboard widgets shall not reduce the space available to active analysis views.
- Explicit unsaved-state indicators and crash recovery.
- Integrated light theme may be added later; the initial design is dark-first.

---

## 4. Specialist interface design

The application shall share navigation and workspace conventions while retaining domain-specific layouts for packet analysis, web security, scanning, and data transformations. A single generic form layout is not appropriate for these disciplines.

| Workspace | Primary reference | Must preserve |
|---|---|---|
| **Packet & Network Analysis** | Wireshark | Three linked packet panes, display filter, capture interfaces, stream following, statistics. |
| **Web Security** | Burp Suite workflow + ZAP | Site tree, proxy history/intercept, request/response editors, repeater, scanning and findings tabs. |
| **Network & Vulnerability Scanning** | Zenmap / Nmap | Target+profile, scan operations, host/port tables, topology, raw output, comparison. |
| **Data / Cryptography Recipes** | CyberChef | Operation browser, recipe steps, input, output, auto-bake behavior, data handoff. |
| **Hash & Password Analysis** | Strongest compatible parts of John + Hashcat | Unified algorithm and operation model, engine choice, device selection, sessions. |
| **Digital Forensics** | Evidence-centric analysis tools | File tree, hex/preview, metadata, signatures, extraction, timelines, structured findings. |
| **Reverse Engineering (later)** | Ghidra/Rizin concepts | Full decompiler-centric multi-pane interface, xrefs, graphs, symbols, annotations. |

Interaction patterns may follow established security applications. Visual identity, icons, brand assets, and implementation shall remain independently developed.

---

## 5. Detailed workspace requirements

### 5.1 Packet & Network Analysis Studio: Wireshark layout + Ettercap mode

**Purpose:** Unified offline packet inspection, live packet capture where supported, protocol/session analysis, and a clearly separated network-interaction mode within the same workspace.

**Screen structure:**

```text
┌─ Packet Studio ─────────────────────────────────────────────────────────────────┐
│ Capture  Open  Save   Interface [eth0 ▾]  ▶ Start  ■ Stop  Display Filter [  ]   │
├───────────────┬────────────────────────────────────────────────────────────────┤
│ Sessions      │ PACKET LIST                                                    │
│ ▾ local.pcap  │ No.   Time     Source        Destination   Protocol  Length Info│
│   TCP         │ 1     ...      ...           ...           TCP       ...    ... │
│   HTTP        │ 2     ...      ...           ...           HTTP      ...    ... │
│   DNS         ├────────────────────────────────────────────────────────────────┤
│   Extracted   │ PACKET DETAILS  (expandable protocol/field tree)               │
│   Flows       │ ▾ Frame  ▾ Ethernet  ▾ IPv4  ▾ TCP  ▾ Payload                 │
│               ├────────────────────────────────────────────────────────────────┤
│               │ PACKET BYTES: OFFSET | HEX | ASCII                            │
├───────────────┴────────────────────────────────────────────────────────────────┤
│ Tabs: Packets | Conversations | Endpoints | Statistics | Streams | Network Lab │
└────────────────────────────────────────────────────────────────────────────────┘
```

**Required features:**

- Open PCAP and PCAPNG; packet count, loading progress, indexing and large-capture handling.
- Packet list with configurable columns, sorting, coloring rules, search, bookmarks and annotation.
- Wireshark-compatible display filters where supported by the underlying dissector engine; validate syntax visibly.
- Selected packet synchronizes packet details and exact highlighted bytes.
- Reassembly and Follow TCP/UDP/HTTP Stream where supported; extract reassembled objects with provenance.
- Capture-interface selector, capture start/stop, capture filters, capture metadata and clear privilege diagnostics.
- Conversations, endpoints, protocol hierarchy, I/O graphs, expert annotations and export formats.
- Packet analysis operates independently from active network operations.

**Ettercap-inspired integrated mode: `Network Lab`**

- Accessible as a tab/mode **inside Packet Studio**, within the existing application rather than as a separately installed program.
- Separate target/scope selector, interface picker, supported host-discovery controls and inspection/analysis panels.
- Distinguish passive observations from operations that actively alter network traffic.
- Any active traffic manipulation requires a user-configured authorized lab scope, explicit confirmation, compatible privileges and a visible stop/emergency-disengage control.
- Show operating-system limitations and privilege requirements before enabling controls; privileged operations shall not run silently.
- Network Lab events can be correlated with the packet timeline, but must not overwrite evidence or pollute passive views without labeling.

**Implementation candidates:** Wireshark/TShark-compatible packet dissection; native Rust file/index model; capture components subject to OS-specific driver/permission and licensing checks; vetted Ettercap capabilities where legally and technically supportable.

**Acceptance tests:** Real captures with DNS, TCP, TLS and HTTP samples load; filter + selection + hex highlighting match expected packet references; stream reconstruction matches known fixtures; live capture works only on explicitly supported OS+privilege combinations; Network Lab displays appropriate isolation/scope gates.

References: [Wireshark UI](https://www.wireshark.org/docs/wsug_html/), [Ettercap](https://github.com/Ettercap/ettercap).

### 5.2 Web Security Studio: familiar Burp/ZAP workflow

**Purpose:** HTTP/S inspection, interception, request replay, scope management, crawler/active scanning, API testing and consolidated findings.

**Layout:**

```text
┌─ Web Security ──────────────────────────────────────────────────────────────────┐
│ Target [Authorized scope ▾] | Proxy [ON/OFF] | Scan | Import API | Export       │
├────────────────────┬───────────────────────────────────────────────────────────┤
│ SITES / SCOPE TREE │ HTTP HISTORY / INTERCEPT / FINDINGS TABLE                │
│ ▾ example.test     │ Method | Host | Path | Status | Length | Notes | Time    │
│  ▾ /api            ├─────────────────────────┬─────────────────────────────────┤
│    /products       │ REQUEST EDITOR          │ RESPONSE VIEWER                 │
│    /auth           │ raw / parsed / headers   │ raw / rendered / headers        │
│                    │                         │                                 │
├────────────────────┴─────────────────────────┴─────────────────────────────────┤
│ Tabs: Proxy | History | Repeater | Site Map | Spider | Scanner | Alerts | API   │
└────────────────────────────────────────────────────────────────────────────────┘
```

**Functional requirements:**

- HTTP and HTTPS interception and proxy history; user-controlled local listener, interception toggle, request/response editing and forwarding.
- Proxy certificate management with explicit install/trust/removal instructions; private key never exported silently.
- Sites tree, contexts/scope rules, exclusions, authentication/session configuration and filtering.
- Request/response viewers with syntax highlighting, raw/pretty/hex views, cookies, headers, parameters, timing and comparison.
- Multiple Repeater tabs, saved requests, configurable redirects and response comparison.
- Crawling/spidering and supported ZAP active scanner policies; queue, cancellation, result validation and findings provenance.
- OpenAPI/GraphQL import and API request grouping where engine support permits.
- Evidence-backed findings: endpoint, evidence/request IDs, confidence, severity, validator, engine version and scan policy.
- Preserve manual-testing usability; request editors shall remain accessible independently of scan results.

**Engine strategy:** Integrate a packaged ZAP engine using its supported APIs/automation interfaces and a private Java runtime where needed. Implement any UI-only features in the Rust/Next layer; **feature parity must be checked against ZAP API coverage**, since not all desktop operations are exposed. Burp Suite is a workflow reference, **not** bundled/copied proprietary code.

**Acceptance tests:** Local controlled demo application can be proxied; edited requests travel through the correct session; history and Replay are consistent; scanner evidence links to real traffic; certificates are scoped and removable; no unintended proxy listener exposure.

References: [ZAP desktop UI](https://www.zaproxy.org/docs/desktop/ui/), [ZAP API](https://www.zaproxy.org/docs/api/), [Burp HTTP history](https://portswigger.net/burp/documentation/desktop/tools/proxy/http-history).

### 5.3 Discovery & Assessment Studio: Zenmap-style interface

**Purpose:** One coherent scanning environment covering network discovery, web-server review, template checks and injection assessment, without four disconnected tool pages.

**Layout:**

```text
┌─ Discovery & Assessment ────────────────────────────────────────────────────────┐
│ Target [scope]  Profile [Profile ▾]  Engine [Auto / Network / Web / Templates] │
│ ▶ Run  ■ Stop   ▸ Advanced Options    Authorization Scope [Edit]             │
├─────────────────┬──────────────────────────────────────────────────────────────┤
│ Scan sessions   │ HOSTS / SERVICES / FINDINGS TABLE                           │
│ + New scan      │ Host | Port | Service | Version | Source | Status           │
│ ▾ Last scan     ├──────────────────────────────────────────────────────────────┤
│   Host A        │ Overview | Ports | Hosts | Topology | Findings | Raw Output  │
│   Host B        │                                                              │
│                 │ Selected host / request / test evidence and configuration     │
├─────────────────┴──────────────────────────────────────────────────────────────┤
│ Jobs | Run History | Diff Scans | Reports | Templates | Policies               │
└────────────────────────────────────────────────────────────────────────────────┘
```

**Shared features:** target editor; CIDR and target-set handling; authorized-scope check; reusable scan profiles; live state; structured result tables; saved runs; scan diff; engine/provenance labels; raw output; structured export; relevant advanced controls.

**Capability-specific controls:**

| Capability | Source technology | Dedicated features within the common studio |
|---|---|---|
| Host/port discovery | Nmap / alternatives | Scan types, host discovery, service/OS detection, NSE support when available, ports/hosts, topology and raw output. |
| Web-server review | Nikto | Web-server checks, check families, target paths, evidence and raw output. |
| Template checks | Nuclei | Template selection, tags/severity, template metadata, match evidence and template update policy. |
| SQL injection assessment | SQLmap | Request import, parameter selection, detection settings, DBMS fingerprint, evidence and controlled advanced options. |
| Content discovery (later) | ffuf / equivalent | Wordlists, response filters, status/size comparison and result triage. |

- Treat **Zenmap** as the host-scanning interface reference: target + profile + command preview + hosts/services + topology + scan comparison.
- SQLmap and Nuclei share the same job/history/result system but retain domain-specific tabs so advanced controls are not lost.
- Preserve engine source/identity in result provenance, while maintaining capability-based navigation.
- A "full feature" claim is valid only after an auditable matrix of upstream options and supported UI/API coverage is completed.

**Acceptance tests:** Compare output against upstream golden fixtures; confirm scan profiles produce expected engine configuration; verify imported request targets match scope; test stop/cancel, retry, export, result deduplication and scan-to-scan diff.

Reference: [Zenmap guide](https://nmap.org/book/zenmap.html).

### 5.4 Transformation & Cryptography Recipes: CyberChef-style

**Purpose:** A powerful visual processing pipeline that preserves the highly effective CyberChef interaction model.

**Required four-column composition:**

```text
┌─────────────────┬──────────────────┬──────────────────┬──────────────────┐
│ OPERATIONS      │ RECIPE           │ INPUT            │ OUTPUT           │
│ Search          │ Step 1           │ Raw / Hex / File │ Live result      │
│ Encoding        │ Step 2           │ Paste / Drop     │ Text / Hex       │
│ Cryptography    │ Step 3           │                  │ Copy / Export    │
│ Compression     │ [+ Add]          │                  │                  │
│ Parsing         │ Auto-Bake [✓]    │                  │                  │
└─────────────────┴──────────────────┴──────────────────┴──────────────────┘
```

**Required features:**

- Searchable operation catalog and categories; draggable recipe steps; enable/disable/reorder; per-step parameter editing.
- Input and output as text, bytes, hexadecimal or files; configurable encoding, size display and validation.
- Auto-Bake toggle, manual run, error location per operation, performance/timeouts for large inputs.
- Save, load, import/export recipes in a versioned local format; operation provenance and deterministic reproduction.
- Core families: Base32/64, hex, URL, Unicode, number bases, hashes, HMAC, XOR, classical ciphers, compression, parsing and data extraction.
- Support data transfer from packet streams, web requests, forensic files and other module outputs.
- Advanced operations may run in native Rust/WASM workers instead of blocking the UI thread.
- Study CyberChef operation parity and licenses before importing code. Preserve the excellent four-panel pattern while making styling original.

**Acceptance tests:** Known input/recipe/output fixtures, file round-trip, operation ordering, errors, encoding correctness, large input responsiveness and saved recipe replay.

Reference: [CyberChef](https://github.com/gchq/CyberChef).

### 5.5 Hash, Password & Authentication Analysis: unified John + Hashcat capabilities

The navigation shall identify user-facing operations rather than individual upstream engines. Hashcat and John the Ripper implementations are managed behind the unified password-analysis interface.

**Primary operations:** identify/inspect hash format; generate hash; verify a candidate password; audit password strength; run authorized offline hash-recovery sessions; inspect algorithm parameters; benchmark available compute implementations.

**Interface:** input panel → hash/format selection → operation mode → strategy/settings → compute device → job monitor → structured results and audit report.

**Engine planner:**

1. Normalize format and parameters without guessing ambiguous algorithms as fact.
2. Check which bundled implementations support that exact format/parameters.
3. Detect CPU instructions, compatible GPU compute backends, available memory and driver status.
4. Compare validated cached benchmarks for the same format and workload type.
5. Choose an implementation or explain a fallback; do not assume "yescrypt = CPU" or "GPU always wins".
6. Persist session progress, engine version, work units and recovery evidence.

The integrated UI must support the specialized strengths of CPU and GPU implementations and provide advanced controls where meaningful, rather than mechanically exposing duplicate tool menus. Clearly distinguish hashing algorithms from encryption schemes; passwords are generally verified against password-hashing/KDF formats, not reversible "encrypted hashes".

**Acceptance tests:** Correct verification on supplied test vectors; parity between supported engines; deterministic device selection and fallback; safe cancellation; accurate performance reporting; audit logs do not expose password material by default.

### 5.6 Digital Forensics & File Analysis

**Purpose:** Evidence-first inspection, not scattered utilities requiring repeated uploads.

**Layout:** evidence/file tree at left; artifact preview/hex/strings/metadata in center; properties, signatures, timeline and extraction details in the inspector.

**Capabilities:** file signatures, hashes, entropy, metadata (ExifTool-compatible), archives/firmware inspection (Binwalk-compatible), extraction with path safety, strings, timestamps, YARA-X scanning, artifact relationships, exports and reproducible notes.

**Operational requirements:** preserve imported originals; record SHA-256 and source metadata; extraction into isolated paths; defend against decompression bombs and path traversal; report parser errors without corrupting evidence; allow adding extracted content to a case.

### 5.7 Reverse Engineering: **next phase, advanced UI only**

Reverse engineering is excluded from the initial release and shall be developed as a dedicated advanced workspace in a subsequent phase.

**Future dedicated layout:**

```text
┌─ Reverse Engineering Studio (future) ─────────────────────────────────────────┐
│ Modules/Symbols │ Decompiler / Assembly / Hex     │ Xrefs / Types / Functions  │
│ Functions tree  │ tabs + synchronized addresses   │ Callers / callees / notes  │
├─────────────────┴──────────────────────────────────┴───────────────────────────┤
│ Control-flow graph / call graph | strings | imports | segments | analysis log │
└───────────────────────────────────────────────────────────────────────────────┘
```

**Future requirements:** PE/ELF/Mach-O support, functions and symbols, cross references, disassembly, decompilation when a compatible engine is available, control-flow graph, call graph, signatures, string references, data types, annotations, patch previews, scripting and analysis-history preservation. Compare Ghidra/Rizin/LIEF/Capstone integration options in a separate RFC. Implement after the core workbench, rendering model and analysis storage are proven.

---

## 6. Capability ownership and third-party source plan

A single user-facing module may use several implementation engines. Selection shall consider data format, algorithm, operating system, required permissions, measured performance, and licensing constraints. Engine identity shall remain available in results and diagnostic records.

| End-user module | Existing upstream references | Packaging/integration direction |
|---|---|---|
| Hash & password analysis | John the Ripper, Hashcat | Bundled compatible engines or vetted libraries; unified CPU/GPU planner. |
| Packet & network analysis | Wireshark, TShark, Ettercap | Packet dissection + controlled interaction mode; driver/permission gates. |
| Web security | OWASP ZAP; Burp UI as interaction reference | Bundled ZAP worker/private runtime plus owned UI and missing integration logic. |
| Discovery & assessment | Nmap/Zenmap, Nikto, Nuclei, SQLmap | One scan workspace with engine-specific configuration and normalized findings. |
| Data/crypto recipes | CyberChef, Rust crypto libraries | Preserve full recipe interface and expand with native processing where useful. |
| Digital forensics | ExifTool, Binwalk, YARA-X | Bundled or linked compatible parsers; one evidence model. |
| CTF helpers | HackTools, custom Rust utilities | Reimplement general-purpose operations where practical; integrate into existing categories. |
| Reverse (future) | Ghidra, Rizin, LIEF, Capstone | Separate deep UI and analysis data model; defer integration. |

### Integration statuses

Every engine receives one explicit status per platform:

- `planned`: architecture and license under assessment.
- `integrated`: execution and output parser implemented in development.
- `verified`: platform acceptance and regression tests pass.
- `shipping`: included in official installer, signed/hashed and functional without external installation.
- `restricted`: blocked by licensing, dependencies or incompatible platform capabilities.

No screenshots, marketing text or default UI controls may imply `shipping` when the status is lower.

### Integration and reuse policy

Using a packaged upstream engine is compatible with a unified product when its execution, data, controls, and results are integrated into the common workspace. Established cryptographic primitives, packet dissectors, and scanners should not be rewritten without a validated technical reason. Improvements shall be assessed through workflow efficiency, correctness, result correlation, scheduling, reliability, and reproducible benchmarks.

---

## 7. Packaging: one installer, no separate installations

### 7.1 Distribution promise

An official supported build ships the required private components for **every capability it advertises**. Engine-specific runtime dependencies (for example Python or Java) are managed internally, hidden from normal users and versioned with the application. Users must not be directed to `pip install`, `brew install`, `apt install`, Java installers or upstream tool installers as part of the normal onboarding flow.

Use Tauri **sidecars** for compatible packaged executables and **resources** for scripts, rules, templates, models and other bundled data. For language runtimes, use platform-appropriate private packaged distributions. Apply integrity checks and avoid writable engine directories during ordinary execution.

### 7.2 Platform and redistribution constraints

- **Windows packet capture:** Npcap has distinct licensing and may require an OS driver installation with privileges. This does not fit the same ordinary embedded-binary model. The build cannot promise live capture unless its redistribution/installation path is solved.
- **Nmap redistribution:** the NPSL has important embedding and redistribution terms. Obtain explicit clearance/permission or choose another compatible implementation; do not assume that because the repository is public it may be bundled freely.
- **GPU acceleration:** drivers, hardware and supported compute backends are system components. Include engines but report when a compatible runtime/device is unavailable. CPU fallback must be genuinely supported for the selected operation.
- **Privilege-sensitive network features:** root/admin or restricted OS entitlements may be needed. Do not quietly elevate or obscure these restrictions.
- **macOS signing/notarization:** the shipped native executable and bundled workers need platform-compliant signing and packaging.
- **Engine size:** large Java and rule/template bundles can increase installer size; measure and optimize without turning necessary dependencies into separate manual downloads.
- **Cross-platform support:** some upstream projects have weaker Windows or macOS support; prove support with real builds and integration tests.

**Release policy:** A capability shall not be advertised for a platform until the required engine can be distributed and operated lawfully and reliably within the application installer. External installation procedures do not satisfy the product requirements.

References: [Tauri sidecars](https://v2.tauri.app/develop/sidecar/), [Nmap license](https://nmap.org/npsl/), [Npcap license](https://github.com/nmap/npcap/blob/master/LICENSE).

### 7.3 Clean-machine acceptance test

For each release target:

1. Start with a clean VM/system image with no security tools preinstalled.
2. Install the single signed application package.
3. Launch without a cloud account or backend server.
4. Confirm every advertised built-in module loads and works offline.
5. Verify all bundled workers execute using the packaged private runtimes and resources.
6. Verify updates, rollback safety, repair, uninstall and data-preservation policy.
7. Verify unsupported hardware/privileges produce actionable, accurate diagnostics.

---

## 8. Unified application data and execution model

### 8.1 Capability model

```text
Capability
  ├─ id / category / name / input schema / output schema
  ├─ supported operations and expert settings
  ├─ supported engine implementations
  ├─ resource + permission requirements
  ├─ workspace presenter
  └─ tests and provenance requirements

Engine implementation
  ├─ engine id / version / license / platform / build hash
  ├─ supported formats, features and options
  ├─ detection + capability probing
  ├─ execution adapter / parsing adapter
  ├─ cancellation / timeout / resource budgets
  └─ output + diagnostic normalization
```

### 8.2 Canonical artifact types

`BinaryArtifact`, `TextArtifact`, `CaptureArtifact`, `NetworkHost`, `NetworkService`, `HTTPRequest`, `HTTPResponse`, `ScanFinding`, `CryptoResult`, `Recipe`, `ToolExecution`, `EvidenceNote`, `ProjectCase`.

Each produced artifact stores source reference, content hash, create time, producing capability/engine, tool version, parameters, warnings, errors and optional evidence relationships. Store raw engine outputs alongside normalized structures when legally and operationally appropriate.

### 8.3 Jobs, progress and cancellation

- Job queue with identifiers, state transitions, progress where supported, timestamps and resource consumption.
- Separate CPU/GPU/network/IO job classes and concurrency budgets.
- Structured events streamed to the UI without serializing entire giant datasets every frame.
- Cancel means terminate the job/worker safely, clean temporary data, mark partial results and preserve evidence where appropriate.
- Retry creates a new execution record linked to the previous attempt.
- No global shell command textbox as a shortcut around permissions.
- Never infer scan success from a `0` process exit alone; validate output integrity and engine-specific status.

### 8.4 Project/case persistence

Store lightweight metadata in SQLite. Save large PCAP, hex, HTTP, log and binary artifacts as files in a versioned project directory. Keep indexes for search, row virtualization and linked views. Support import/export in a portable case format with a manifest, checksums, linked artifacts and schema version.

---

## 9. Security, privacy and authorization model

### 9.1 Threat model

Threat sources include malicious imported files, malformed captures, crafted web responses, untrusted third-party rules/templates, compromised engine bundles, unsafe UI-to-native commands and unintended active network operations.

### 9.2 Native trust boundaries

- Frontend cannot invoke arbitrary paths or shell commands.
- Tauri capabilities are least-privilege, window-scoped and action-scoped.
- Rust validates structured inputs before invoking a worker.
- Bundled workers run with minimal OS privileges and constrained filesystem/network access wherever practical.
- Plugins/rules/templates must be versioned, checked and treated as untrusted when applicable.
- Securely isolate the app's proxy and any local APIs; loopback binding and API secrets are mandatory when needed.
- Never let a renderer-supplied path escape approved workspaces.
- Maintain engine SBOM, hashes, provenance and update verification.

### 9.3 Active network testing

- Require explicit scope selection and a statement of authorized use before running active scans or network interaction.
- Validate run configuration against the selected scope.
- Make risky modes visibly distinguishable from passive analysis.
- Provide immediate stop controls, timeouts, concurrency limits and activity logs.
- Do not silently turn on network manipulation after opening a capture file.

### 9.4 Evidence and secrets

- Original evidence remains immutable in the case store by default.
- Sensitive logs, credentials, proxy keys and tokens must not be exported or sent to AI by default.
- Use OS secret stores for protected credentials where feasible.
- No telemetry by default; local/offline remains the baseline.
- Optional AI integrations require opt-in and a clear disclosure of what data leaves the device.

---

## 10. Project organization and repository

```text
cybersecurity-workbench/
├── apps/
│   └── desktop/
│       ├── app/                      # Next.js static routes/layouts
│       ├── features/                 # packet, web, scan, recipes, hash, forensics
│       ├── components/               # shared desktop shell, grids, editors
│       ├── design-system/            # darkmatter tokens, components, icons
│       ├── state/                    # client-side state + IPC consumers
│       ├── src-tauri/                # Tauri entry, permissions, packaging
│       ├── next.config.ts
│       └── package.json
├── crates/
│   ├── core/                         # capability and artifact types
│   ├── capabilities/                 # supported operations
│   ├── runtime/                      # jobs, workers, resource policies
│   ├── registry/                     # features, versions, supported engines
│   ├── packet/                       # file indexing, capture integration
│   ├── web-security/                 # proxy/session models
│   ├── scanning/                     # target/scope/results models
│   ├── crypto/                       # crypto primitives and format models
│   ├── forensics/                    # evidence inspection and extraction
│   ├── storage/                      # SQLite + artifact store
│   └── platform/                     # OS-specific privilege and device logic
├── engines/
│   ├── manifests/                    # engine license/version/features/targets
│   ├── adapters/                     # Rust integration bridges
│   ├── patches/                      # reviewed vendor patches, if needed
│   └── packaging/                    # build recipes for bundled engines
├── fixtures/                         # pcap, HTTP, file, hash test data
├── tests/                            # integration and clean-machine smoke tests
├── docs/
│   ├── design-system.md
│   ├── workspace-packet.md
│   ├── workspace-web.md
│   ├── workspace-scanning.md
│   ├── workspace-recipes.md
│   ├── security-model.md
│   ├── engine-licensing.md
│   └── release-matrix.md
├── scripts/
├── .github/workflows/
├── Cargo.toml
├── pnpm-workspace.yaml
└── README.md
```

**Organizational rules:** UI components cannot directly own native engine processes; Rust models cannot depend on Next.js; engine integration code should not be spread through presentation components; every module needs a stable contract and test fixtures.

---

## 11. Implementation roadmap

### Phase 0: Architecture, licensing, UI prototypes

**Deliver:** Next/Tauri/Rust shell; Dark Matter design tokens; native IPC prototype; tool registry; artifact schema; safe job runner; build matrix; initial license register.

**Prototype each specialist screen** with representative real datasets before investing in full engines. Create and usability-test packet panes, Burp/ZAP proxy panes, Zenmap scanning panes and the CyberChef recipe builder. Confirm the shell has sufficient flexibility for these very different layouts.

**Gate:** Linux, Windows and macOS demo builds launch; no application server required; users can switch between faithful screen prototypes; native processing works via IPC.

### Phase 1: Transformation, cryptography and file analysis

**Deliver:** functioning recipe engine with four-column UI; hashing/format inspection; core encoding/compression; metadata, signatures, entropy, hex/strings and evidence storage; cross-tool data handoff.

**Gate:** No simulated outputs; reference test vectors pass; large artifacts do not freeze UI; install is self-contained on all advertised platforms.

### Phase 2: Packet & Network Analysis

**Deliver:** full packet-list/details/bytes layout; capture open/filter/reassembly; conversations and statistics; supported live capture; Network Lab/Ettercap-inspired controlled mode where technically and legally available.

**Gate:** verified PCAP fixtures; correct linked panes; stable multi-gigabyte indexing strategy; OS capture limitations explicitly tested; no unsafe automatic elevation.

### Phase 3: Discovery & Assessment

**Deliver:** Zenmap-style scan manager; host/port/results/topology; saved profiles; Nikto/Nuclei/SQLmap capability panels, consistent normalized findings, engine-specific advanced options and export.

**Gate:** every advertised engine bundled with no manual setup; scan results match golden fixtures; scope guardrails and job cancellation pass integration tests.

### Phase 4: Web Security

**Deliver:** proxy interception/history, sites tree, request/response editors, repeater, ZAP crawler/scanner, findings and session controls; private runtime packaging.

**Gate:** end-to-end tests against controlled lab service; TLS/proxy setup and cleanup tested; UI feature matrix against ZAP's exposed capabilities; no unprotected proxy API.

### Phase 5: Integration polish and first stable desktop release

**Deliver:** complete project/case workflow, consistent shortcuts, multiple-tabs/splits, report exports, responsive large-data views, platform-specific installer and update testing, dependency/legal documentation.

**Gate:** automated acceptance run on clean Linux, Windows and macOS machines; every shipping feature works with no external tool install; signed release assets and release rollback policy.

### Phase 6: Advanced Reverse Engineering (subsequent release)

**Deliver:** separate RFC; decompiler/disassembly/hex synchronization, symbols/xrefs, CFG/call graph, analysis database and native backend integrations. This is a major research-grade UI phase, not part of the initial release scope.

### Phase 7: Optional AI (subsequent release)

**Deliver:** evidence-aware explanations, natural-language query of selected artifacts, report assistance and user-approved suggestion flows; optional local/remote model configuration. Keep AI out of the critical engine path.

**Sequencing note:** Some workstreams can proceed in parallel; phase gates are based on demonstrable functioning capability, not calendar promises or an arbitrary count of tools.

---

## 12. Detailed definition of done

A feature is **complete** only when:

- [ ] Its specialist UI is implemented with the expected source-tool workflow and keyboard behavior.
- [ ] Its underlying engine is genuine and included in the installer on supported platforms.
- [ ] Advanced settings expose the relevant upstream capability rather than silently discarding controls.
- [ ] Its input/output is typed, validated, reproducible and linked to stored artifacts.
- [ ] All relevant OS-specific limitations and permissions are correctly disclosed.
- [ ] Cancellation, errors, timeouts and partial outputs behave predictably.
- [ ] No manual installation of executables, private runtimes, or plugins is required.
- [ ] It has a completed license/redistribution review and dependency manifest.
- [ ] It passes integration fixtures and clean-machine packaging tests.
- [ ] Its UI remains readable under common DPI and window-size configurations.
- [ ] Documentation, shortcuts and test coverage are in place.
- [ ] Benchmarks or parity claims are backed by recorded measurements.

### Performance and accessibility expectations

- Use windowed/virtualized lists for packet, request and scan tables.
- Heavy parsing runs outside the UI rendering thread.
- Navigation remains responsive while background work runs.
- Defer slow initialization until a workspace opens, without hiding the first-use cost.
- Measure startup, memory footprint, frame responsiveness, packet indexing and job overhead on each OS.
- Support keyboard navigation, screen-reader labels, visible focus and configurable font sizes.
- Do not claim an arbitrary speed-up over upstream tools without a reproducible benchmark.

---

## 13. Risk register and release blockers

| Risk | Impact | Required mitigation |
|---|---|---|
| Licenses forbid or complicate bundling (Nmap, capture driver, GPL components) | **Critical** | Obtain redistribution approval; isolate components as required; use vetted compatible alternatives; block release of affected features. |
| Very large binaries/private runtimes | High | Per-platform size budgets, shared runtimes, compression and component audits; retain one-install rule. |
| Live capture privilege and OS dependencies | **Critical** for capture claim | Platform validation, compliant driver strategy, explicit privileges, verified fallback to offline PCAP. |
| ZAP API does not expose every GUI operation | High | Feature/API gap analysis; build owned supported adapters where feasible; never claim unsupported parity. |
| Hash engine and GPU compatibility differences | High | Capability matrix, device probing and benchmark-based selection with known-good fallbacks. |
| Reimplementing complex layouts takes longer than engine integration | High | Prototype complex panes early; maintain UI parity checklists and regression screenshots. |
| Data corruption on cancellation/crash | High | Transactional records, immutable evidence, durable job states and recovery tests. |
| Malformed files compromise native parsers | **Critical** | Fuzzing, guarded workers, limits and security audits. |
| Proprietary design or branding copied too literally | Medium/High | Preserve workflows but use original visual tokens, icons and brand; separate interface reference from protected assets. |
| Next.js server-only features accidentally introduced | Medium | Static export check and offline smoke test in CI; ban runtime server dependencies. |
| Excessive scope prevents a functional release | High | Ship complete capability slices with clear gates; defer Reverse/AI until core workflows are proven. |

---

## 14. Immediate implementation backlog

**P0: Initial development iteration**

1. Initialize monorepo, Cargo workspace, Next.js static export and Tauri 2 shell.
2. Set up typed Rust IPC and cancellable example jobs.
3. Implement Dark Matter tokens and the configurable desktop layout.
4. Build realistic **Packet Studio** mock from sample PCAP-derived data: packet list/details/bytes and filter UI.
5. Build realistic **Web Security** mock: site tree, request history, editor, response viewer and tab system.
6. Build realistic **Scan Studio** mock: profiles, host list, ports, raw results and findings tabs.
7. Build the CyberChef-style four-column Recipes UI with real encode/decode operations.
8. Define capability/engine manifests, normalized artifacts and shared job states.
9. Start a verified upstream license + redistribution checklist for every proposed bundled engine.
10. Produce a runnable packaged build for each OS and record gaps immediately.

**P1: First complete functional capability**

- The first complete functional capability shall combine **Recipes and Hash/File Inspection**. This scope can be validated with reference test vectors and sample files, requires no privileged network access, and exercises the shared runtime, storage, and desktop interface.
- Packet Studio interface and indexing development may proceed in parallel using representative PCAP fixtures.

**P2: Engineering design documents**

- `RFC-001`: Bundled Engine Runtime, Signing & License Gate.
- `RFC-002`: Packet Parsing and Live Capture Across OSes.
- `RFC-003`: ZAP Engine and HTTP Proxy IPC / Certificate Management.
- `RFC-004`: Unified Scan Result Schema and Engine Option Coverage.
- `RFC-005`: Next.js/Tauri UI Performance on Large Data Tables.
- `RFC-006`: Advanced Reverse Engineering UI (future phase).

---

## 15. Sources and design references

**Visual references**

- [Delta](https://delta.dev/): desktop workspace, compact panes, high-density styling.
- [Delta appearance settings](https://delta.dev/docs/configuration/settings): theme and font choices.
- [Zed](https://zed.dev/); [Zed appearance](https://zed.dev/docs/appearance): editor interaction patterns, appearance and keyboard-driven workflow.
- Reference screenshot: Delta desktop workspace, used for visual direction only. The screenshot is not included in application assets.

**Core engineering**

- [Tauri 2](https://tauri.app/); [Tauri Next.js guide](https://tauri.app/start/frontend/nextjs/).
- [Tauri sidecars](https://v2.tauri.app/develop/sidecar/).
- [Next.js static export](https://nextjs.org/docs/app/guides/static-exports).

**Security application references**

- [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html/); [Ettercap](https://github.com/Ettercap/ettercap).
- [OWASP ZAP desktop guide](https://www.zaproxy.org/docs/desktop/); [ZAP API](https://www.zaproxy.org/docs/api/).
- [Burp Suite HTTP history documentation](https://portswigger.net/burp/documentation/desktop/tools/proxy/http-history): workflow reference only.
- [Zenmap GUI User's Guide](https://nmap.org/book/zenmap.html).
- [CyberChef source](https://github.com/gchq/CyberChef).
- [Hashcat](https://github.com/hashcat/hashcat); [John the Ripper](https://github.com/openwall/john).
- [ExifTool](https://github.com/exiftool/exiftool); [Binwalk](https://github.com/ReFirmLabs/binwalk); [YARA-X](https://github.com/VirusTotal/yara-x).
- [Nuclei](https://github.com/projectdiscovery/nuclei); [SQLmap](https://github.com/sqlmapproject/sqlmap); [Nikto](https://github.com/sullo/nikto).

**Licensing and release constraints**

- [Nmap Public Source License](https://nmap.org/npsl/); [Nmap embedding guidance](https://nmap.org/book/man-legal.html).
- [Npcap license](https://github.com/nmap/npcap/blob/master/LICENSE).
- License checks must be repeated against the **exact version and artifacts actually packaged**, including transitive dependencies.

---
