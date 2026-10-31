/**
 * Typed IPC client. The frontend never invokes raw paths or shell commands;
 * every native action goes through a named wrapper here (Master Plan §9.2).
 *
 * When running in a plain browser (next dev without Tauri) the wrappers fall
 * back to a local simulation so UI development does not require the desktop
 * shell. The status bar always shows which transport is live.
 */
import { invoke, Channel } from "@tauri-apps/api/core";
import type { JobEvent } from "@state/jobs-model";

const inTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

export type JobKindWire = "demo";

export function isDesktop(): boolean {
  return inTauri;
}

export async function jobStart(
  kind: JobKindWire,
  onEvent: (event: JobEvent) => void,
): Promise<number> {
  if (!inTauri) return simulateJob(kind, onEvent);
  const channel = new Channel<JobEvent>();
  channel.onmessage = onEvent;
  return invoke<number>("job_start", { kind, onEvent: channel });
}

export async function jobCancel(id: number): Promise<boolean> {
  if (!inTauri) return cancelSimulated(id);
  return invoke<boolean>("job_cancel", { id });
}

// --- base64 helpers ----------------------------------------------------------

export const b64 = {
  encode(bytes: Uint8Array): string {
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin);
  },
  decode(text: string): Uint8Array {
    const bin = atob(text);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  },
};

// --- native crypto -----------------------------------------------------------

export interface OpResult {
  output_b64: string;
  output_hex: string;
  engine: string;
  engine_version: string;
}

/** The SHA family also runs in the browser via WebCrypto; all else is native. */
const WEB_CRYPTO_ALGOS = new Set(["sha1", "sha256", "sha384", "sha512"]);

export async function cryptoOp(op: string, data: Uint8Array, key?: Uint8Array): Promise<OpResult> {
  if (!inTauri) {
    if (!WEB_CRYPTO_ALGOS.has(op)) {
      throw new Error(`${op} runs in the native engine; it requires the desktop runtime`);
    }
    const digest = await crypto.subtle.digest(op.replace("sha", "SHA-").toUpperCase(), data as Uint8Array<ArrayBuffer>);
    const hexOut = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
    return {
      output_b64: b64.encode(b64.decode(hexToB64(hexOut))),
      output_hex: hexOut,
      engine: "webcrypto (platform)",
      engine_version: "browser fallback",
    };
  }
  return invoke<OpResult>("crypto_op", {
    op,
    dataB64: b64.encode(data),
    keyB64: key ? b64.encode(key) : null,
  });
}

function hexToB64(hexText: string): string {
  const bytes = new Uint8Array(hexText.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(hexText.slice(i * 2, i * 2 + 2), 16);
  return b64.encode(bytes);
}

// --- native recipe execution ----------------------------------------------------

export interface RecipeStepWire {
  opId: string;
  enabled: boolean;
  param?: string;
}

export interface RecipeRunWire {
  outputB64: string;
  byteLength: number;
  elapsedMs: number;
  error: { stepIndex: number; opId: string; message: string } | null;
}

/** Execute supported recipe pipelines inside the native Rust crate. */
export async function recipeRun(input: string, steps: RecipeStepWire[]): Promise<RecipeRunWire> {
  if (!inTauri) throw new Error("native recipe execution requires the desktop runtime");
  return invoke<RecipeRunWire>("recipe_run", { input, steps });
}

// --- unified cases and findings ------------------------------------------------

export interface CaseRecordWire {
  id: string;
  title: string;
  description: string;
  created_ms: number;
}

export interface FindingRecordWire {
  id: number;
  case_id: string;
  source: string;
  title: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  details: string;
  artifact_id: string | null;
  created_ms: number;
}

export type NewFindingWire = Pick<FindingRecordWire, "title" | "severity" | "details">;

export async function caseList(): Promise<CaseRecordWire[]> {
  if (!inTauri) return [{ id: "scratchpad", title: "Scratchpad", description: "Default working case", created_ms: 0 }];
  return invoke<CaseRecordWire[]>("case_list");
}

export async function caseCreate(title: string, description = ""): Promise<CaseRecordWire> {
  if (!inTauri) throw new Error("Creating cases requires the desktop runtime");
  return invoke<CaseRecordWire>("case_create", { title, description });
}

export async function caseFindingsList(caseId: string): Promise<FindingRecordWire[]> {
  if (!inTauri) return [];
  return invoke<FindingRecordWire[]>("case_findings_list", { caseId });
}

export async function caseFindingsAdd(
  caseId: string,
  source: string,
  findings: NewFindingWire[],
  artifactId: string | null = null,
): Promise<number> {
  if (!inTauri) throw new Error("Saving findings requires the desktop runtime");
  return invoke<number>("case_findings_add", { caseId, source, artifactId, findings });
}

export interface CaseEventWire {
  id: number;
  case_id: string;
  source: string;
  action: string;
  artifact_id: string | null;
  source_description: string;
  created_ms: number;
}

export interface CaseReportWire {
  schema_version: number;
  generated_ms: number;
  case: CaseRecordWire;
  artifacts: Pick<ArtifactRecord, "id" | "name" | "size" | "sha256" | "signature" | "imported_at">[];
  findings: FindingRecordWire[];
  events: CaseEventWire[];
  truncated: boolean;
}

export async function caseEventsList(caseId: string): Promise<CaseEventWire[]> {
  if (!inTauri) return [];
  return invoke<CaseEventWire[]>("case_events_list", { caseId });
}

export async function caseReport(caseId: string): Promise<CaseReportWire> {
  if (!inTauri) throw new Error("Case export requires the desktop runtime");
  return invoke<CaseReportWire>("case_report", { caseId });
}

// --- evidence ----------------------------------------------------------------

export interface ArtifactRecord {
  id: string;
  case_id: string;
  name: string;
  stored_path: string;
  original_path: string | null;
  size: number;
  sha256: string;
  md5: string;
  sha1: string;
  crc32: string;
  signature: string | null;
  entropy: number;
  /** Epoch milliseconds as a string; format on display. */
  imported_at: string;
}

export interface HexRowWire {
  offset: number;
  hex: string;
  ascii: string;
}

export interface HexResponseWire {
  rows: HexRowWire[];
  offset: number;
  total_size: number;
  complete: boolean;
}

export interface StringHitWire {
  offset: number;
  text: string;
}

export async function fileList(caseId = "scratchpad"): Promise<ArtifactRecord[]> {
  if (!inTauri) return [];
  return invoke<ArtifactRecord[]>("file_list", { case: caseId });
}

export async function fileImportDialog(caseId = "scratchpad"): Promise<ArtifactRecord> {
  if (!inTauri) throw new Error("evidence import requires the desktop runtime");
  return invoke<ArtifactRecord>("file_import_dialog", { caseId });
}

/** Save a derived byte buffer to the selected case, with recorded provenance. */
export async function fileImportDerived(caseId: string, name: string, bytes: Uint8Array, sourceDescription?: string): Promise<ArtifactRecord> {
  if (!inTauri) throw new Error("Derived evidence import requires the desktop runtime");
  if (bytes.length > 8 * 1024 * 1024) throw new Error("Derived evidence must not exceed 8 MiB");
  return invoke<ArtifactRecord>("file_import_derived", { caseId, name, dataB64: b64.encode(bytes), sourceDescription: sourceDescription ?? null });
}

export interface SignatureScanWire {
  hits: { offset: number; format: string; description: string }[];
  scanned_bytes: number;
  file_bytes: number;
  truncated: boolean;
  integrity_checked: boolean;
}

/** Extract a bounded embedded Gzip member to the currently selected case. */
export async function fileExtractGzip(caseId: string, id: string, offset: number): Promise<ArtifactRecord> {
  if (!inTauri) throw new Error("Gzip extraction requires the desktop runtime");
  return invoke<ArtifactRecord>("file_extract_gzip", { caseId, id, offset });
}

export async function fileSignatureScan(caseId: string, id: string): Promise<SignatureScanWire> {
  if (!inTauri) throw new Error("Binary scanning requires the native desktop runtime");
  return invoke<SignatureScanWire>("file_signature_scan", { caseId, id });
}

export async function fileHex(caseId: string, id: string, offset: number, len: number): Promise<HexResponseWire> {
  if (!inTauri) throw new Error("evidence inspection requires the desktop runtime");
  return invoke<HexResponseWire>("file_hex", { caseId, id, offset, len });
}

export async function fileStrings(caseId: string, id: string, minLen: number, maxHits: number): Promise<StringHitWire[]> {
  if (!inTauri) throw new Error("evidence inspection requires the desktop runtime");
  return invoke<StringHitWire[]>("file_strings", { caseId, id, minLen, maxHits });
}

// --- captures ----------------------------------------------------------------

export interface PcapLayerWire {
  label: string;
  value: string;
}

export interface PcapPacketWire {
  index: number;
  time_ms: number;
  source: string;
  destination: string;
  protocol: string;
  length: number;
  info: string;
  color_hint: string;
  stream_id: string | null;
  layers: PcapLayerWire[];
}

export interface PcapOpenWire {
  format: "pcap" | "pcapng";
  linktype: number;
  packet_count: number;
  shown: number;
  malformed_tail: boolean;
  file_name: string;
  packets: PcapPacketWire[];
}

export async function pcapOpenDialog(): Promise<PcapOpenWire> {
  if (!inTauri) throw new Error("capture opening requires the desktop runtime");
  return invoke<PcapOpenWire>("pcap_open_dialog", {});
}

export interface StreamChunkWire {
  dir: string;
  text: string;
  kind: "data" | "gap" | "notice" | "datagram";
  hex_data: string | null;
}

export interface StreamTranscriptWire {
  protocol: "TCP" | "UDP";
  chunks: StreamChunkWire[];
  gaps: number;
  retransmissions: number;
  truncated: boolean;
}

export async function pcapFollowStream(streamId: string): Promise<StreamTranscriptWire> {
  if (!inTauri) throw new Error("stream following requires the desktop runtime");
  return invoke<StreamTranscriptWire>("pcap_follow_stream", { streamId });
}

export async function pcapPacketBytes(index: number, offset: number, len: number): Promise<HexResponseWire> {
  if (!inTauri) throw new Error("capture inspection requires the desktop runtime");
  return invoke<HexResponseWire>("pcap_packet_bytes", { index, offset, len });
}

// --- recovery + file digests --------------------------------------------------

export interface CrackMatchWire {
  line_no: number;
  password: string;
}

export interface CrackResultWire {
  algo: string;
  target_hash: string;
  wordlist: string;
  tried: number;
  matches: CrackMatchWire[];
  duration_ms: number;
  threads: number;
  engine: string;
  engine_version: string;
}

export interface WordlistInfoWire {
  name: string;
  path: string;
  size: number;
}

export async function pickWordlist(): Promise<WordlistInfoWire> {
  if (!inTauri) throw new Error("wordlist picking requires the desktop runtime");
  return invoke<WordlistInfoWire>("pick_wordlist", {});
}

export interface CrackProgressWire {
  tried: number;
  total: number;
  percent: number;
}

export async function crackWordlistDialog(
  algo: string,
  targetHash: string,
  wordlistPath?: string,
  onProgress?: (progress: CrackProgressWire) => void,
): Promise<CrackResultWire> {
  if (!inTauri) throw new Error("recovery sessions require the desktop runtime");
  const channel = new Channel<CrackProgressWire>();
  if (onProgress) channel.onmessage = onProgress;
  return invoke<CrackResultWire>("crack_wordlist_dialog", {
    algo,
    targetHash,
    wordlistPath: wordlistPath ?? null,
    onProgress: channel,
  });
}

export interface FileDigestsWire {
  name: string;
  size: number;
  sha256: string;
  sha1: string;
  md5: string;
  crc32: string;
}

export async function digestFileDialog(): Promise<FileDigestsWire> {
  if (!inTauri) throw new Error("file hashing requires the desktop runtime");
  return invoke<FileDigestsWire>("digest_file_dialog", {});
}

export interface AttackMatchWire {
  line_no: number;
  password: string;
}

export interface AttackResultWire {
  mode: string;
  algo: string;
  target_hash: string;
  source: string;
  tried: number;
  generated: number;
  cap_reached: boolean;
  matches: AttackMatchWire[];
  duration_ms: number;
  threads: number;
  engine: string;
  engine_version: string;
}

export async function crackRulesDialog(algo: string, targetHash: string): Promise<AttackResultWire> {
  if (!inTauri) throw new Error("rule-based attacks require the desktop runtime");
  return invoke<AttackResultWire>("crack_rules_dialog", { algo, targetHash });
}

export async function crackMask(algo: string, targetHash: string, mask: string): Promise<AttackResultWire> {
  if (!inTauri) throw new Error("mask attacks require the desktop runtime");
  return invoke<AttackResultWire>("crack_mask", { algo, targetHash, mask });
}

/** Wordlist words with a mask suffix; reuses the picked wordlist when given. */
export async function crackHybridDialog(
  algo: string,
  targetHash: string,
  mask: string,
  wordlistPath?: string,
): Promise<AttackResultWire> {
  if (!inTauri) throw new Error("hybrid attacks require the desktop runtime");
  return invoke<AttackResultWire>("crack_hybrid_dialog", {
    algo,
    targetHash,
    mask,
    wordlistPath: wordlistPath ?? null,
  });
}

/** Mask prefix + wordlist words; reuses the picked wordlist when given. */
export async function crackHybridReverseDialog(
  algo: string,
  targetHash: string,
  mask: string,
  wordlistPath?: string,
): Promise<AttackResultWire> {
  if (!inTauri) throw new Error("hybrid attacks require the desktop runtime");
  return invoke<AttackResultWire>("crack_hybrid_reverse_dialog", {
    algo,
    targetHash,
    mask,
    wordlistPath: wordlistPath ?? null,
  });
}

/** Full combinator: first wordlist word + second wordlist word. */
export async function crackCombinatorDialog(
  algo: string,
  targetHash: string,
  firstWordlistPath?: string,
  secondWordlistPath?: string,
): Promise<AttackResultWire> {
  if (!inTauri) throw new Error("combinator attacks require the desktop runtime");
  return invoke<AttackResultWire>("crack_combinator_dialog", {
    algo,
    targetHash,
    wordlistPath: firstWordlistPath ?? null,
    secondWordlistPath: secondWordlistPath ?? null,
  });
}

export interface BenchmarkWire {
  algo: string;
  hashes_per_second: number;
  duration_ms: number;
  threads: number;
}

/** Measure the native digest rate for an algorithm (KDFs are rejected). */
export async function benchmarkDigest(algo: string, durationMs?: number): Promise<BenchmarkWire> {
  if (!inTauri) throw new Error("benchmarking requires the desktop runtime");
  return invoke<BenchmarkWire>("benchmark", { algo, durationMs: durationMs ?? null });
}

export interface GpuDeviceWire {
  name: string;
  driver_version: string;
  memory_total: string;
  compute_cap: string;
  backend: string;
  usable: boolean;
}

export interface DeviceInfoWire {
  cpu_arch: string;
  cpu_cores: number;
  cpu_engine: string;
  gpu_devices: GpuDeviceWire[];
  planner_note: string;
}

export async function deviceInfo(): Promise<DeviceInfoWire> {
  if (!inTauri) throw new Error("device probing requires the desktop runtime");
  return invoke<DeviceInfoWire>("device_info", {});
}

// --- external engines (hashcat MIT, john GPLv2 sidecar) -----------------------

export interface EngineStatusWire {
  id: string;
  label: string;
  license: string;
  available: boolean;
  version: string;
  source: string;
  note: string;
}

export interface EngineAttackResultWire {
  engine: string;
  engine_version: string;
  algo: string;
  mode: string;
  tried_note: string;
  matches: AttackMatchWire[];
  duration_ms: number;
  raw_tail: string;
}

export async function enginesDetect(): Promise<EngineStatusWire[]> {
  if (!inTauri) throw new Error("engine detection requires the desktop runtime");
  return invoke<EngineStatusWire[]>("engines_detect", {});
}

export async function engineAttack(
  engine: string,
  algo: string,
  targetHash: string,
  mode: string,
  mask?: string,
): Promise<EngineAttackResultWire> {
  if (!inTauri) throw new Error("external engines require the desktop runtime");
  return invoke<EngineAttackResultWire>("engine_attack", { engine, algo, targetHash, mode, mask: mask ?? null });
}

/** Verify a candidate against a bcrypt/argon2 PHC string (native engine). */
export async function kdfVerify(hash: string, candidate: string): Promise<boolean> {
  if (!inTauri) throw new Error("KDF verification requires the desktop runtime");
  return invoke<boolean>("kdf_verify", { hash, candidate });
}

// --- crack history -------------------------------------------------------------

export interface CrackEntryWire {
  id: number;
  algo: string;
  hash: string;
  password: string;
  engine: string;
  wordlist: string | null;
  recovered_at: string;
}

export async function crackHistoryList(): Promise<CrackEntryWire[]> {
  if (!inTauri) return [];
  return invoke<CrackEntryWire[]>("crack_history_list", {});
}

export async function crackHistoryDelete(id: number): Promise<void> {
  if (!inTauri) throw new Error("history requires the desktop runtime");
  return invoke<void>("crack_history_delete", { id });
}

export async function crackHistoryClear(): Promise<void> {
  if (!inTauri) throw new Error("history requires the desktop runtime");
  return invoke<void>("crack_history_clear", {});
}

// --- web studio ---------------------------------------------------------------

export interface HttpResponseWire {
  status: number;
  headers: [string, string][];
  body: string;
  body_truncated: boolean;
  size: number;
  duration_ms: number;
  url: string;
}

export async function httpSend(requestRaw: string): Promise<HttpResponseWire> {
  if (!inTauri) throw new Error("sending requests requires the desktop runtime");
  return invoke<HttpResponseWire>("http_send", { requestRaw });
}

export interface WebFindingWire {
  severity: string;
  title: string;
  detail: string;
  evidence: string;
}

export async function webScan(targetUrl: string, authorized: boolean): Promise<WebFindingWire[]> {
  if (!inTauri) throw new Error("scanning requires the desktop runtime");
  return invoke<WebFindingWire[]>("web_scan", { targetUrl, authorized });
}

export async function spiderScan(targetUrl: string, maxDepth: number, authorized: boolean): Promise<string[]> {
  if (!inTauri) throw new Error("spidering requires the desktop runtime");
  return invoke<string[]>("spider_scan", { targetUrl, maxDepth, authorized });
}

export interface CapturedRequestWire {
  id: number;
  method: string;
  host: string;
  path: string;
  status: number;
  size: number;
  at_ms: number;
}

export interface ProxyStatusWire {
  running: boolean;
  port: number;
  captured: number;
}

export async function proxyStart(port: number): Promise<ProxyStatusWire> {
  if (!inTauri) throw new Error("the proxy requires the desktop runtime");
  return invoke<ProxyStatusWire>("proxy_start", { port });
}

export async function proxyStop(): Promise<ProxyStatusWire> {
  if (!inTauri) throw new Error("the proxy requires the desktop runtime");
  return invoke<ProxyStatusWire>("proxy_stop", {});
}

export async function proxyStatus(): Promise<ProxyStatusWire> {
  if (!inTauri) return { running: false, port: 8080, captured: 0 };
  return invoke<ProxyStatusWire>("proxy_status", {});
}

export async function proxyHistory(): Promise<CapturedRequestWire[]> {
  if (!inTauri) return [];
  return invoke<CapturedRequestWire[]>("proxy_history", {});
}

export interface MatchReplaceRuleWire {
  find: string;
  replace: string;
}

export async function proxyIntercept(on: boolean): Promise<boolean> {
  if (!inTauri) return on;
  return invoke<boolean>("proxy_intercept", { on });
}

export interface PendingRequestWire {
  id: number;
  method: string;
  url: string;
  host: string;
  path: string;
  body_preview: string;
}

export async function proxyPending(): Promise<PendingRequestWire[]> {
  if (!inTauri) return [];
  return invoke<PendingRequestWire[]>("proxy_pending", {});
}

export async function proxyForward(id: number): Promise<number> {
  if (!inTauri) throw new Error("the proxy requires the desktop runtime");
  return invoke<number>("proxy_forward", { id });
}

export async function proxyDrop(id: number): Promise<void> {
  if (!inTauri) throw new Error("the proxy requires the desktop runtime");
  return invoke<void>("proxy_drop", { id });
}

export async function proxySetRules(rules: MatchReplaceRuleWire[]): Promise<number> {
  if (!inTauri) return 0;
  return invoke<number>("proxy_set_rules", { rules });
}

export async function proxyCaPem(): Promise<string> {
  if (!inTauri) throw new Error("CA export requires the desktop runtime");
  return invoke<string>("proxy_ca_pem", {});
}

export interface WsConnectionWire {
  host: string;
  at_ms: number;
}

export async function wsList(): Promise<WsConnectionWire[]> {
  if (!inTauri) return [];
  return invoke<WsConnectionWire[]>("ws_list", {});
}

export interface WebEngineStatusWire {
  id: string;
  label: string;
  license: string;
  available: boolean;
  version: string;
}

export async function webEnginesDetect(): Promise<WebEngineStatusWire[]> {
  if (!inTauri) return [];
  return invoke<WebEngineStatusWire[]>("web_engines_detect", {});
}

export interface EngineScanResultWire {
  tool: string;
  raw: string;
  duration_ms: number;
}

export async function engineScan(tool: string, target: string, authorized: boolean): Promise<EngineScanResultWire> {
  if (!inTauri) throw new Error("external engines require the desktop runtime");
  return invoke<EngineScanResultWire>("engine_scan", { tool, target, authorized });
}

// --- network scanner -----------------------------------------------------------

export interface ScanProgressWire {
  tried: number;
  total: number;
  percent: number;
}

export interface ScanEntryWire {
  host: string;
  port: number;
  state: string;
  service: string;
  banner: string;
}

export interface ScanSummaryWire {
  id: number;
  targets: string;
  ports: string;
  hosts_scanned: number;
  open_ports: number;
  duration_ms: number;
  at_ms: number;
}

export interface NetscanStatusWire {
  running: boolean;
  results: number;
  saved_findings: number;
  save_error: string | null;
}

export async function netscanStart(
  targets: string,
  ports: string,
  caseId: string,
  authorized: boolean,
  onProgress?: (p: ScanProgressWire) => void,
): Promise<ScanSummaryWire> {
  if (!inTauri) throw new Error("network scanning requires the desktop runtime");
  const channel = new Channel<ScanProgressWire>();
  if (onProgress) channel.onmessage = onProgress;
  return invoke<ScanSummaryWire>("netscan_start", { targets, ports, caseId, authorized, onProgress: channel });
}

export async function netscanResults(): Promise<ScanEntryWire[]> {
  if (!inTauri) return [];
  return invoke<ScanEntryWire[]>("netscan_results", {});
}

export async function netscanStop(): Promise<void> {
  if (!inTauri) throw new Error("network scanning requires the desktop runtime");
  return invoke<void>("netscan_stop", {});
}

export async function netscanStatus(): Promise<NetscanStatusWire> {
  if (!inTauri) return { running: false, results: 0, saved_findings: 0, save_error: null };
  return invoke<NetscanStatusWire>("netscan_status", {});
}

export interface ScanHistoryItemWire {
  id: number;
  targets: string;
  ports: string;
  hosts_scanned: number;
  open_ports: number;
  duration_ms: number;
  at_ms: number;
}

export async function netscanHistory(): Promise<ScanHistoryItemWire[]> {
  if (!inTauri) return [];
  return invoke<ScanHistoryItemWire[]>("netscan_history", {});
}

export async function netscanExport(format: "json" | "csv"): Promise<string> {
  if (!inTauri) throw new Error("export requires the desktop runtime");
  return invoke<string>("netscan_export", { format });
}

export async function netscanDiscoverHosts(targets: string, authorized: boolean): Promise<string[]> {
  if (!inTauri) throw new Error("host discovery requires the desktop runtime");
  return invoke<string[]>("netscan_discover_hosts", { targets, authorized });
}

// --- browser fallback (demo jobs) --------------------------------------------

interface Simulation {
  timer: ReturnType<typeof setInterval>;
  onEvent: (event: JobEvent) => void;
}

const simJobs = new Map<number, Simulation>();

function simulateJob(kind: JobKindWire, onEvent: (event: JobEvent) => void): Promise<number> {
  const id = Math.floor(Math.random() * 1_000_000) + 1;
  const total = 50;
  let step = 0;
  onEvent({ type: "started", job_id: id, total_steps: total });
  const timer = setInterval(() => {
    if (!simJobs.has(id)) return;
    step += 1;
    onEvent({
      type: "progress",
      job_id: id,
      step,
      percent: Math.round((step / total) * 100),
      message: `processing unit ${step}/${total}`,
    });
    if (step >= total) {
      clearInterval(timer);
      simJobs.delete(id);
      onEvent({ type: "completed", job_id: id, message: `demo job finished (${total} units)` });
    }
  }, 100);
  simJobs.set(id, { timer, onEvent });
  return Promise.resolve(id);
}

function cancelSimulated(id: number): Promise<boolean> {
  const sim = simJobs.get(id);
  if (!sim) return Promise.resolve(false);
  clearInterval(sim.timer);
  simJobs.delete(id);
  sim.onEvent({ type: "cancelled", job_id: id });
  return Promise.resolve(true);
}
