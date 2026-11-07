"use client";
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { Play, Square, Trash2, Eye, EyeOff, FileUp, SlidersHorizontal, FileText, Library, Download, Hash } from "lucide-react";
import { Phosphor } from "@lucasmarkes/hairline/react";
import { Accordion, AccordionItem, AccordionTrigger, AccordionPanel } from "@/components/ui/accordion";
import { ErrorStrip, ProgressBar } from "@ds/compact";
import { Chip, NumberInput, Select, TextArea, TextInput } from "@ds/panes";
import { hasCurrentRecoveryScope, recoveryDisplay } from "./recovery-presentation";
import { chooseRecoveryBackend, DEFAULT_CANDIDATES, DEFAULT_MATCHES, DEFAULT_OPENCL_BATCH } from "./recovery-auto";
import { Button } from "@/components/ui/button";
import { useCaseReady, useWorkbenchCase } from "@state/workbench";
import {
  isDesktop, recoveryCancelV1, recoveryDevicesV1, recoveryDiscardV1,
  recoverySelectWordlistV1, recoveryWordlistStatusV1, type RecoveryWordlistV1,
  recoveryRevealV1, recoveryStartV1, recoveryStatusV1, recoveryAutopilotV1,
  recoveryMaskV1, recoverySelectHashFileV1, recoveryHashStatusV1,
  recoveryUseHashTextV1, unshadowV1, type RecoveryHashInputStatusV1,
  recoveryHashcatCapabilitiesV1, recoveryStartHashcatV1,
  wordlistLibraryListV1, wordlistLibraryFetchV1, wordlistLibraryDeleteV1, wordlistLibraryUseV1,
  rulesLibraryListV1, rulesLibraryInspectV1,
  type WordlistLibraryEntryV1, type WordlistFetchProgressV1, type RuleSetEntryV1,
  type EmbeddedHashcatCapabilityV1,
  type RecoveryBackendV1, type RecoveryDeviceInventoryV1,
  type RecoveryJobStatusV1, type RecoveryRequestV1, type HashcatRawAlgorithmV1, type RecoveryRawAlgorithmV1, type HashcatWordlistPresetV1,
} from "@lib/ipc";

/** `pwMax` marks modes whose upstream optimized kernels reject longer
 * candidates; absent means no advertised kernel cap. Rendered only here for
 * the embedded-Hashcat selector, never as a claim about the Rust CPU engine.
 */
const EMBEDDED_MODES: readonly { value: HashcatRawAlgorithmV1; label: string; digits: number; pwMax?: number | null }[] = [
  { value: "md5", label: "MD5 · mode 0", digits: 32, pwMax: 32 },
  { value: "sha1", label: "SHA-1 · mode 100", digits: 40, pwMax: 32 },
  { value: "md5crypt", label: "md5crypt $1$/$apr1$ · mode 500", digits: 0 },
  { value: "ntlm", label: "NTLM · mode 1000", digits: 32, pwMax: 32 },
  { value: "sha256", label: "SHA-256 · mode 1400", digits: 64, pwMax: 32 },
  { value: "sha512", label: "SHA-512 · mode 1700", digits: 128, pwMax: 32 },
  { value: "sha512crypt", label: "sha512crypt $6$ · mode 1800", digits: 0 },
  { value: "bcrypt", label: "bcrypt $2*$ · mode 3200", digits: 0 },
  { value: "sha256crypt", label: "sha256crypt $5$ · mode 7400", digits: 0 },
  { value: "descrypt", label: "descrypt (classic crypt(3)) · mode 1500", digits: 0 },
  { value: "mssql-2005", label: "MSSQL 2005 · mode 132", digits: 0 },
  { value: "mssql-2012", label: "MSSQL 2012/2014 · mode 1731", digits: 0 },
  { value: "phpass", label: "phpass (WordPress/phpBB) · mode 400", digits: 0 },
  { value: "md5-pass-salt", label: "md5($pass.$salt) · mode 10", digits: 0 },
  { value: "md5-salt-pass", label: "md5($salt.$pass) · mode 20", digits: 0 },
  { value: "sha1-pass-salt", label: "sha1($pass.$salt) · mode 110", digits: 0 },
  { value: "sha1-salt-pass", label: "sha1($salt.$pass) · mode 120", digits: 0 },
  { value: "hmac-md5", label: "HMAC-MD5 (key = pass) · mode 50", digits: 0 },
  { value: "hmac-sha1", label: "HMAC-SHA1 (key = pass) · mode 60", digits: 0 },
  { value: "mscash", label: "mscash / DCC1 · mode 1100", digits: 0 },
  { value: "mscash2", label: "mscash2 / DCC2 · mode 2100", digits: 0 },
  { value: "netntlm-v1", label: "NetNTLMv1 · mode 5500", digits: 0 },
  { value: "netntlm-v2", label: "NetNTLMv2 · mode 5600", digits: 0 },
  { value: "kerberos-tgs-rep", label: "Kerberos TGS-REP etype 23 ($krb5tgs$) · mode 13100", digits: 0, pwMax: 32 },
  { value: "kerberos-as-rep", label: "Kerberos AS-REP etype 23 ($krb5asrep$) · mode 18200", digits: 0, pwMax: 32 },
  { value: "bitlocker", label: "BitLocker ($bitlocker$) · mode 22100", digits: 0 },
  { value: "bitcoin", label: "Bitcoin wallet.dat · mode 11300", digits: 0 },
  { value: "keepass", label: "KeePass (KDBX v2/v3) · mode 13400", digits: 0 },
  { value: "ethereum-pbkdf2", label: "Ethereum wallet (PBKDF2) · mode 15600", digits: 0 },
  { value: "ethereum-scrypt", label: "Ethereum wallet (scrypt) · mode 15700", digits: 0 },
  { value: "office-97-2003", label: "MS Office 97/2003 ($oldoffice$) · mode 9700", digits: 0, pwMax: 32 },
  { value: "office-2007", label: "MS Office 2007 ($office$) · mode 9400", digits: 0 },
  { value: "office-2013", label: "MS Office 2013 ($office$) · mode 9600", digits: 0 },
  { value: "pdf-1.1-1.3", label: "PDF 1.1-1.3 ($pdf$ R2) · mode 10400", digits: 0, pwMax: 32 },
  { value: "pdf-1.4-1.6", label: "PDF 1.4-1.6 ($pdf$ R3/R4) · mode 10500", digits: 0 },
  { value: "winzip-aes", label: "WinZip AES ($zip2$) · mode 13600", digits: 0 },
  { value: "7zip", label: "7-Zip ($7z$) · mode 11600", digits: 0 },
  { value: "zip-legacy", label: "ZIP legacy (ZipCrypto) · modes 17200/17210", digits: 0 },
];
const RUST_MODES: readonly { value: RecoveryRawAlgorithmV1; label: string; digits: number; pwMax?: number | null }[] = [
  ...EMBEDDED_MODES,
  { value: "sha3_256", label: "SHA3-256 · CPU", digits: 64 },
  { value: "sha3_512", label: "SHA3-512 · CPU", digits: 128 },
  { value: "ripemd160", label: "RIPEMD-160 · CPU", digits: 40 },
  { value: "whirlpool", label: "Whirlpool · CPU", digits: 128 },
  { value: "blake2b512", label: "BLAKE2b-512 · CPU", digits: 128 },
  { value: "mysql5", label: "MySQL 4.1+ (*sha1(sha1)) · CPU", digits: 40 },
  { value: "lm", label: "LAN Manager · CPU", digits: 32 },
];
// A digest algorithm is an explicit operator choice: length alone is insufficient.
let lastHashcatMode: RecoveryRawAlgorithmV1 = "sha256";
let lastHashcatPreset: HashcatWordlistPresetV1 = "plain";

// Store only a backend-owned opaque job reference across route remounts.
let currentJob: { scope: string; id: number } | null = null;

function useRecoveryController(targetHash: string, onCaseCreated?: (caseId: string) => void) {
  const { caseId, caseSession } = useWorkbenchCase();
  const { caseReady, caseRevision } = useCaseReady();
  const [desktop, setDesktop] = useState(false);
  useEffect(() => setDesktop(isDesktop()), []);
  const scope = caseReady ? caseId + ":" + String(caseRevision) : null;
  const scopeRef = useRef(scope);
  scopeRef.current = scope;
  const [backend, setBackend] = useState("auto");
  const [attackMode, setAttackMode] = useState<"wordlist" | "mask">("wordlist");
  const [maskText, setMaskText] = useState("");
  const [customCharsets, setCustomCharsets] = useState("");
  const [hashInput, setHashInput] = useState<RecoveryHashInputStatusV1 | null>(null);
  const [hashInputBusy, setHashInputBusy] = useState(false);
  const [engineChoice, setEngineChoice] = useState<"rust" | "hashcat">("rust");
  const [hashcatAlgorithm, setHashcatAlgorithm] = useState<RecoveryRawAlgorithmV1>(lastHashcatMode);
  const [hashcatPreset, setHashcatPreset] = useState<HashcatWordlistPresetV1>(lastHashcatPreset);
  const [hashcatCapability, setHashcatCapability] = useState<EmbeddedHashcatCapabilityV1 | null>(null);
  const [inventory, setInventory] = useState<RecoveryDeviceInventoryV1 | null>(null);
  const [deviceError, setDeviceError] = useState<string | null>(null);
  const [batchSize, setBatchSize] = useState(DEFAULT_OPENCL_BATCH);
  const [ruleText, setRuleText] = useState("");
  const [maxCandidates, setMaxCandidates] = useState(DEFAULT_CANDIDATES);
  const [maxMatches, setMaxMatches] = useState(DEFAULT_MATCHES);
  const [jobId, setJobId] = useState<number | null>(null);
  const [status, setStatus] = useState<RecoveryJobStatusV1 | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [secretHex, setSecretHex] = useState<string | null>(null);
  const [revealing, setRevealing] = useState(false);
  const [pendingCancel, setPendingCancel] = useState(false);
  const [wordlist, setWordlist] = useState<{ scope: string; info: RecoveryWordlistV1 } | null>(null);
  const [choosingWordlist, setChoosingWordlist] = useState(false);
  const [wordlistError, setWordlistError] = useState<string | null>(null);
  const [discarded, setDiscarded] = useState(false);
  // Auto-resume: after a cancelled/capped CPU run, Start continues from the
  // remembered ordinal instead of replaying the wordlist from zero.
  const lastResume = useRef(0);
  const clearReveal = useCallback(() => setSecretHex(null), []);
  const hash = targetHash.trim();
  const hashcatMode = RUST_MODES.find((item) => item.value === hashcatAlgorithm)!;
  // Modular KDF strings run on the native CPU engine by default; the embedded
  // core covers several of them when explicitly selected. Detection is strict:
  // only known modular prefixes count, so unknown $-formats (pkzip2, ...)
  // correctly land in the unsupported state instead of a wall of controls.
  const KDF_PREFIXES = [
    "$2a$", "$2b$", "$2y$", "$2x$", "$argon2", "$y$", "$7$", "$gy$", "$G$",
    "$scrypt$", "$pbkdf2", "$6$", "$5$", "$1$", "$apr1$", "$sha1$", "$P$",
    "$H$", "$NT$", "$DCC2$", "DCC2#", "M$", "$NETNTLM", "WPA*01*", "0x0100",
    "0x0200", "$zip2$", "$7z$", "$pkzip2$", "$pkzip$",
    "$oldoffice$", "$office$", "$pdf$", "$bitcoin$", "$keepass$", "$ethwallet$",
    "$krb5tgs$", "$krb5asrep$", "$bitlocker$",
  ];
  const isKdfHash =
    (hash.startsWith("$") && KDF_PREFIXES.some((prefix) => hash.startsWith(prefix))) ||
    hash.startsWith("WPA*01*") ||
    hash.startsWith("0x0100") ||
    hash.startsWith("0x0200") ||
    hash.startsWith("DCC2#") ||
    hash.startsWith("M$");
  const hexBody = hash.startsWith("*") ? hash.slice(1) : hash;
  const modularModeSelected = hashcatMode.digits === 0;
  const validHash = isKdfHash || modularModeSelected
    ? (isKdfHash || (hash.startsWith("*") && hexBody.length === 40 && /^[a-fA-F0-9]+$/.test(hexBody)))
    : hexBody.length === hashcatMode.digits && /^[a-fA-F0-9]+$/.test(hexBody);
  useEffect(() => {
    // Length is a suggestion, never an identity claim: preserve an operator's
    // explicit MD5/NTLM choice when both share 32-digit digest shapes.
    if (engineChoice === "hashcat") {
      const kdfSuggestion: Partial<Record<string, HashcatRawAlgorithmV1>> = {
        "$6$": "sha512crypt", "$1$": "md5crypt", "$apr1$": "md5crypt",
        "$2a$": "bcrypt", "$2b$": "bcrypt", "$2y$": "bcrypt",
        "$P$": "phpass", "$H$": "phpass",
        "$zip2$": "winzip-aes", "$7z$": "7zip", "$pkzip2$": "zip-legacy", "$pkzip$": "zip-legacy",
        "$oldoffice$": "office-97-2003", "$office$": "office-2007", "$pdf$": "pdf-1.1-1.3",
        "$bitcoin$": "bitcoin", "$keepass$": "keepass",
        "$krb5tgs$": "kerberos-tgs-rep", "$krb5asrep$": "kerberos-as-rep", "$bitlocker$": "bitlocker",
      };
      const match = Object.entries(kdfSuggestion).find(([prefix]) => hash.startsWith(prefix));
      if (match && match[1]) {
        setHashcatAlgorithm(match[1]);
        lastHashcatMode = match[1];
        return;
      }
    }
    if (!/^[a-fA-F0-9]+$/.test(hash) || hash.length === hashcatMode.digits) return;
    const suggestions: Partial<Record<number, RecoveryRawAlgorithmV1>> = {
      32: "md5", 40: "sha1", 64: "sha256", 128: "sha512",
    };
    const suggestion = suggestions[hash.length];
    if (suggestion) setHashcatAlgorithm(suggestion);
  }, [hash, hashcatMode.digits, engineChoice]);
  const running = status?.phase === "running" || status?.phase === "cancelling";
  // GPU route is currently SHA-256-only. In Auto, other raw modes must run
  // on the available Rust CPU, even if a GPU later passes independent KAT.
  const selection: RecoveryBackendV1 = isKdfHash
    ? { backend: "cpu" }
    : chooseRecoveryBackend(backend, inventory, batchSize, hashcatAlgorithm);
  const selectedDevice = selection.backend === "open_cl" ? selection.device_index : null;
  const deviceAvailable = selectedDevice === null ||
    !!inventory?.devices.some((item) => item.device_index === selectedDevice);

  useEffect(() => {
    clearReveal();
    setStatus(null);
    setError(null);
    setBusy(false);
    setPendingCancel(false);
    setDiscarded(false);
    setWordlistError(null);
    setChoosingWordlist(false);
    if (scope && currentJob?.scope === scope) {
      setJobId(currentJob.id);
    } else {
      // A route remount may briefly have no selected native case while the
      // backend session is being restored. Do not forget a still-running job.
      if (scope || caseId === "scratchpad") currentJob = null;
      setJobId(null);
    }
  }, [scope, caseId, clearReveal]);

  useEffect(() => {
    if (!desktop) { setInventory(null); return; }
    let active = true;
    void recoveryDevicesV1().then((data) => {
      if (active) { setInventory(data); setDeviceError(null); }
    }).catch((reason: unknown) => {
      if (active) setDeviceError(String(reason));
    });
    return () => { active = false; };
  }, [desktop]);

  useEffect(() => {
    if (!desktop) { setHashcatCapability(null); return; }
    let active = true;
    void recoveryHashcatCapabilitiesV1().then((capability) => {
      if (active) setHashcatCapability(capability);
    }).catch(() => {
      if (active) setHashcatCapability({
        available: false, mode: 1400, modes: [], hardware_verified: false,
        detail: "Bundled native Hashcat is unavailable",
      });
    });
    return () => { active = false; };
  }, [desktop]);

  useEffect(() => {
    if (!scope || !desktop) { setWordlist(null); return; }
    let active = true;
    setWordlist(null);
    void recoveryWordlistStatusV1().then((info) => {
      if (active && scopeRef.current === scope)
        setWordlist(info ? { scope, info } : null);
    }).catch((reason: unknown) => {
      if (active && scopeRef.current === scope) setWordlistError(String(reason));
    });
    void recoveryHashStatusV1().then((status) => {
      if (active && scopeRef.current === scope) setHashInput(status);
    }).catch(() => {});
    return () => { active = false; };
  }, [scope, desktop]);

  useEffect(() => {
    if (!scope || jobId === null) return;
    let active = true;
    const refresh = async () => {
      try {
        const next = await recoveryStatusV1(jobId);
        if (!active || scopeRef.current !== scope || currentJob?.id !== jobId) return;
        setStatus(next);
        if (next.summary?.resume_index && (next.phase === "cancelled" || next.phase === "failed")) {
          lastResume.current = next.summary.resume_index;
        }
        if (next.phase === "completed") lastResume.current = 0;
        if (next.error) setError(next.error);
      } catch (reason) {
        if (!active || scopeRef.current !== scope) return;
        setError(String(reason));
        setStatus(null);
        setJobId(null);
        if (currentJob?.id === jobId) currentJob = null;
      }
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), 900);
    return () => { active = false; window.clearInterval(timer); };
  }, [scope, jobId]);

  useEffect(() => {
    if (secretHex === null) return;
    const timer = window.setTimeout(clearReveal, 30000);
    return () => window.clearTimeout(timer);
  }, [secretHex, clearReveal]);

  const selectedWordlist = wordlist?.scope === scope ? wordlist.info : null;

  const chooseWordlist = async () => {
    if (!desktop || !scope || choosingWordlist || busy || jobId !== null) return;
    const requestedScope = scope;
    setChoosingWordlist(true);
    setWordlistError(null);
    try {
      const info = await recoverySelectWordlistV1();
      if (scopeRef.current === requestedScope) setWordlist({ scope: requestedScope, info });
    } catch (reason) {
      if (scopeRef.current === requestedScope && !/cancelled/i.test(String(reason)))
        setWordlistError(String(reason));
    } finally {
      if (scopeRef.current === requestedScope) setChoosingWordlist(false);
    }
  };

  // --- library (wordlists + rule sets) -------------------------------------
  const [libraryOpen, setLibraryOpen] = useState(false);
  const [libraryEntries, setLibraryEntries] = useState<WordlistLibraryEntryV1[] | null>(null);
  const [libraryBusy, setLibraryBusy] = useState<string | null>(null);
  const [libraryProgress, setLibraryProgress] = useState<WordlistFetchProgressV1 | null>(null);
  const [ruleSets, setRuleSets] = useState<RuleSetEntryV1[] | null>(null);
  const [ruleSetId, setRuleSetId] = useState<string | null>(null);
  const [ruleSetNote, setRuleSetNote] = useState<string | null>(null);
  const refreshLibrary = useCallback(async () => {
    try {
      const entries = await wordlistLibraryListV1();
      setLibraryEntries(entries);
      setRuleSets(await rulesLibraryListV1());
    } catch {
      setLibraryEntries([]);
    }
  }, []);
  useEffect(() => {
    if (!desktop) return;
    void refreshLibrary();
  }, [desktop, refreshLibrary]);
  const useLibraryWordlist = async (id: string) => {
    if (!scope || libraryBusy || jobId !== null) return;
    const requestedScope = scope;
    setLibraryBusy(id);
    setWordlistError(null);
    try {
      const info = await wordlistLibraryUseV1(id);
      if (scopeRef.current === requestedScope) setWordlist({ scope: requestedScope, info });
      void refreshLibrary();
    } catch (reason) {
      if (scopeRef.current === requestedScope) setWordlistError(String(reason));
    } finally {
      if (scopeRef.current === requestedScope) setLibraryBusy(null);
    }
  };
  const downloadLibraryWordlist = async (id: string) => {
    if (libraryBusy) return;
    setLibraryBusy(id);
    setLibraryProgress(null);
    try {
      await wordlistLibraryFetchV1(id, setLibraryProgress);
      void refreshLibrary();
    } catch (reason) {
      setWordlistError(String(reason));
    } finally {
      setLibraryProgress(null);
      setLibraryBusy(null);
    }
  };
  const deleteLibraryWordlist = async (id: string) => {
    if (libraryBusy) return;
    setLibraryBusy(id);
    try {
      await wordlistLibraryDeleteV1(id);
      void refreshLibrary();
    } catch (reason) {
      setWordlistError(String(reason));
    } finally {
      setLibraryBusy(null);
    }
  };
  const pickRuleSet = async (id: string | null) => {
    if (jobId !== null || busy) return;
    setRuleSetId(id);
    setRuleSetNote(null);
    if (id) {
      setRuleText("");
      try {
        const summary = await rulesLibraryInspectV1(id);
        setRuleSetNote(summary.skipped > 0
          ? `${summary.rule_count.toLocaleString()} rules active, ${summary.skipped.toLocaleString()} skipped by the bounded engine`
          : `${summary.rule_count.toLocaleString()} rules active`);
      } catch (reason) {
        setRuleSetNote(String(reason));
      }
    }
    clearReveal();
  };

  const start = async () => {
    if (attackMode === "mask") {
      if (!scope || !validHash || !maskText.trim() || busy || jobId !== null) return;
      clearReveal(); setError(null); setBusy(true); setStatus(null); setJobId(null);
      setDiscarded(false);
      const requestScope = scope;
      const request: RecoveryRequestV1 = {
        algorithm: isKdfHash ? "kdf" : hashcatAlgorithm,
        target_hash: hash.toLowerCase(),
        backend: { backend: "cpu" },
        max_candidates: maxCandidates, max_matches: maxMatches,
      };
      try {
        const id = await recoveryMaskV1(request, maskText.trim(), () => {}, customCharsets.trim() || undefined);
        if (scopeRef.current !== requestScope) return;
        currentJob = { scope: requestScope, id };
        setJobId(id);
      } catch (reason) {
        if (scopeRef.current === requestScope && !/cancelled/i.test(String(reason)))
          setError(String(reason));
      } finally { if (scopeRef.current === requestScope) setBusy(false); }
      return;
    }
    if (!scope || !validHash || !selectedWordlist || busy ||
      (engineChoice === "hashcat" ? !hashcatCapability?.available : !deviceAvailable) ||
      jobId !== null) return;
    if (!isKdfHash && ruleText.trim() && (engineChoice !== "rust" || selection.backend !== "cpu")) {
      setError("Wordlist rules require the native Rust CPU backend. Select CPU first.");
      return;
    }
    if (isKdfHash && engineChoice === "rust" && selection.backend !== "cpu") {
      setError("KDF hashes run on the native Rust CPU backend only.");
      return;
    }
    clearReveal(); setError(null); setBusy(true); setStatus(null); setJobId(null);
    setDiscarded(false);
    const requestScope = scope;
    const selected: RecoveryBackendV1 = engineChoice === "hashcat"
      ? { backend: "hashcat_managed" }
      : selection;
    const request: RecoveryRequestV1 = {
      algorithm: isKdfHash && engineChoice === "rust" ? "kdf" : hashcatAlgorithm,
      target_hash: hash.toLowerCase(), backend: selected,
      max_candidates: maxCandidates, max_matches: maxMatches,
    };
    try {
      // Both paths share the same backend-authorized job, cancellation and
      // confidential Reveal lifecycle; never silently substitute engines.
      const onEvent = () => {
        // Poll authoritative Rust state; events never contain recovered plaintext.
      };
      const id = engineChoice === "hashcat"
        ? await recoveryStartHashcatV1(request, onEvent, hashcatPreset)
        : await recoveryStartV1(request, onEvent, isKdfHash ? undefined : ruleText, ruleSetId,
            lastResume.current || undefined);
      if (scopeRef.current !== requestScope) return;
      currentJob = { scope: requestScope, id };
      setJobId(id);
    } catch (reason) {
      if (scopeRef.current === requestScope && !/cancelled/i.test(String(reason)))
        setError(String(reason));
    } finally { if (scopeRef.current === requestScope) setBusy(false); }
  };

  const importHashFile = async () => {
    if (!scope || hashInputBusy || jobId !== null) return;
    const requestedScope = scope;
    setHashInputBusy(true);
    setError(null);
    try {
      const status = await recoverySelectHashFileV1();
      if (scopeRef.current === requestedScope) setHashInput(status);
    } catch (reason) {
      if (scopeRef.current === requestedScope && !/cancelled/i.test(String(reason)))
        setError(String(reason));
    } finally { if (scopeRef.current === requestedScope) setHashInputBusy(false); }
  };
  const importUnshadow = async () => {
    if (!scope || hashInputBusy || jobId !== null) return;
    const requestedScope = scope;
    setHashInputBusy(true);
    setError(null);
    try {
      const merged = await unshadowV1();
      if (!merged.trim()) return;
      const status = await recoveryUseHashTextV1(merged);
      if (scopeRef.current === requestedScope) setHashInput(status);
    } catch (reason) {
      if (scopeRef.current === requestedScope && !/cancelled/i.test(String(reason)))
        setError(String(reason));
    } finally { if (scopeRef.current === requestedScope) setHashInputBusy(false); }
  };

  const autoStart = async () => {
    if (!scope || !validHash || busy || jobId !== null) return;
    clearReveal(); setError(null); setBusy(true); setStatus(null); setJobId(null);
    setDiscarded(false);
    const requestScope = scope;
    try {
      const onEvent = () => {};
      const id = await recoveryAutopilotV1(hash, maxCandidates, maxMatches, onEvent);
      if (scopeRef.current !== requestScope) return;
      currentJob = { scope: requestScope, id };
      setJobId(id);
    } catch (reason) {
      if (scopeRef.current === requestScope && !/cancelled/i.test(String(reason)))
        setError(String(reason));
    } finally { if (scopeRef.current === requestScope) setBusy(false); }
  };

  const cancel = async () => {
    if (jobId === null || !scope || !running) return;
    setPendingCancel(true);
    try {
      if (!await recoveryCancelV1(jobId) && scopeRef.current === scope)
        setError("Native recovery already finished or revoked.");
    } catch (reason) {
      if (scopeRef.current === scope) setError(String(reason));
    } finally { if (scopeRef.current === scope) setPendingCancel(false); }
  };

  const discard = async () => {
    if (jobId === null || !scope || running) return;
    clearReveal();
    try {
      const discarded = await recoveryDiscardV1(jobId);
      if (!discarded) { setError("Result already revoked; check active case."); return; }
    } catch (reason) { setError(String(reason)); return; }
    if (scopeRef.current === scope) {
      if (currentJob?.id === jobId) currentJob = null;
      setJobId(null); setStatus(null); setError(null); setDiscarded(true);
    }
  };

  const reveal = async (ordinal: number) => {
    if (jobId === null || !scope || !status?.reveal_available) return;
    setRevealing(true); clearReveal(); setError(null);
    try {
      // A separate native OS confirmation is required for EACH reveal.
      const hex = await recoveryRevealV1(jobId, ordinal);
      if (scopeRef.current === scope && currentJob?.id === jobId) setSecretHex(hex);
    } catch (reason) {
      if (scopeRef.current === scope) setError(String(reason));
    } finally { if (scopeRef.current === scope) setRevealing(false); }
  };

  const disabledReason = !desktop ? "Requires the native desktop runtime"
    : !scope ? (caseId === "scratchpad" ? "Select a saved case to authorize recovery"
      : caseSession.error ?? "Waiting for native case selection")
    : !validHash ? (isKdfHash ? "This modular hash is not a supported KDF format"
      : "Enter a " + hashcatMode.label + " digest (" + hashcatMode.digits + " hexadecimal characters)")
    : attackMode === "mask" ? (maskText.trim() ? null : "Enter a mask pattern first")
    : !selectedWordlist ? "Choose a wordlist from the library or file picker before starting"
    : ruleText.trim().length > 4096 ? "Rule text exceeds the 4 KiB limit"
    : ruleText.trim() && (engineChoice !== "rust" || selection.backend !== "cpu")
      ? "Wordlist rules require native Rust CPU mode"
    : engineChoice === "hashcat" && !hashcatCapability?.available
      ? hashcatCapability?.detail ?? "Embedded Hashcat capability unavailable"
    : engineChoice === "hashcat" && !hashcatCapability?.modes.some((mode) => mode.algorithm === hashcatAlgorithm)
      ? "Selected Hashcat mode has not passed its native known-answer recovery test"
    : engineChoice === "rust" && !deviceAvailable ? "Selected OpenCL device unavailable" : null;
  const autoDisabledReason = !desktop ? "Requires the native desktop runtime"
    : !scope ? (caseId === "scratchpad" ? "Select a saved case to authorize recovery"
      : caseSession.error ?? "Waiting for native case selection")
    : !validHash ? "Enter a supported digest or modular KDF hash first"
    : libraryEntries !== null && !libraryEntries.some((entry) => entry.present)
      ? "Download a wordlist in the library first" : null;
  const progress = status?.progress;
  const percent = progress && progress.budget > 0
    ? Math.min(100, Math.round(progress.tried / progress.budget * 100)) : 0;
  // Mask even the next paint after a case switch; effects run after rendering.
  const scopedJob = hasCurrentRecoveryScope(currentJob, scope, jobId);

  return {
    desktop, scope, onCaseCreated, backend, setBackend, inventory, deviceError, batchSize, setBatchSize,
    ruleText, setRuleText, ruleSetId, pickRuleSet, ruleSets, ruleSetNote,
    libraryOpen, setLibraryOpen, libraryEntries, libraryBusy, libraryProgress,
    useLibraryWordlist, downloadLibraryWordlist, deleteLibraryWordlist, refreshLibrary,
    engineChoice, setEngineChoice, hashcatCapability,
    hashcatAlgorithm, setHashcatAlgorithm, hashcatMode, isKdfHash,
    hashcatPreset, setHashcatPreset,
    maxCandidates, setMaxCandidates, maxMatches, setMaxMatches,
    jobId: scopedJob ? jobId : null,
    status: scopedJob ? status : null,
    busy, error: scopedJob || jobId === null ? error : null,
    secretHex: scopedJob ? secretHex : null,
    discarded, revealing, pendingCancel, clearReveal, validHash,
    selectedWordlist, choosingWordlist, wordlistError, chooseWordlist,
    running: scopedJob && running, selectedDevice, deviceAvailable,
    attackMode, setAttackMode, maskText, setMaskText, customCharsets, setCustomCharsets,
    hashInput, hashInputBusy, importHashFile, importUnshadow,
    start, autoStart, autoDisabledReason, cancel, discard, reveal,
    disabledReason, progress: scopedJob ? progress : null, percent, hash, caseId, selection,
  };
}

type RecoveryController = ReturnType<typeof useRecoveryController>;
const RecoveryContext = createContext<RecoveryController | null>(null);
function useRecovery() {
  const state = useContext(RecoveryContext);
  if (!state) throw new Error("Recovery V1 requires its provider");
  return state;
}

export function NativeRecoveryV1({
  targetHash, children, onCaseCreated,
}: { targetHash: string; children: ReactNode; onCaseCreated?: (caseId: string) => void }) {
  const state = useRecoveryController(targetHash, onCaseCreated);
  return <RecoveryContext.Provider value={state}>{children}</RecoveryContext.Provider>;
}

export function NativeRecoveryControls() {
  const r = useRecovery();
  const jobInProgress = r.busy || r.running || (r.jobId !== null && r.status === null);
  const fileLabel = r.selectedWordlist?.name ?? "No wordlist selected";

  // Progressive disclosure: before there is something to act on, the panel is
  // a single quiet line — no chips, no state telemetry, no empty controls.
  if (!r.desktop) {
    return (
      <section aria-label="Recovery controls" className="border-b border-line px-3 pb-3 pt-3">
        <h3 className="text-xs font-semibold text-fg">Recovery</h3>
        <p className="pt-1 text-2xs text-fg-muted">Runs in the CyberDeck desktop app.</p>
      </section>
    );
  }
  if (!r.validHash && r.jobId === null) {
    return (
      <section aria-label="Recovery controls" className="border-b border-line px-3 pb-3 pt-3">
        <h3 className="text-xs font-semibold text-fg">Recovery</h3>
        <p className="pt-1 text-2xs text-fg-muted">
          {r.hash.length > 0 ? "Unsupported hash format." : "Paste a hash to start recovery."}
        </p>
      </section>
    );
  }
  const statusText = !r.scope
    ? "Choose a saved case to authorize recovery — status-bar switcher or start page."
    : r.wordlistError
      ? r.wordlistError
      : null;

  return (
    <section aria-label="Recovery controls" className="border-b border-line px-3 pb-3 pt-3">
      <h3 className="text-xs font-semibold text-fg">Recovery</h3>
      <div className="mt-4 space-y-1.5">
        <div className="flex items-center gap-2">
          <label className="min-w-0 flex-1 space-y-1">
            <span className="text-2xs text-fg-dim">Attack mode</span>
            <Select ariaLabel="Recovery attack mode" value={r.attackMode}
              onChange={(value) => {
                if (r.jobId === null && !r.busy && (value === "wordlist" || value === "mask")) {
                  r.setAttackMode(value); r.clearReveal();
                }
              }}
              options={[
                { value: "wordlist", label: "Wordlist · library or file" },
                { value: "mask", label: "Mask · CPU bounded keyspace" },
              ]} className="w-full" />
          </label>
          <label className="min-w-0 flex-1 space-y-1">
            <span className="text-2xs text-fg-dim">Hash file · optional</span>
            <Button size="sm" variant="outline"
              className="h-8 w-full justify-start gap-1.5 rounded-md px-2 text-2xs"
              title={r.hashInput ? r.hashInput.count + " hashes bound (" + r.hashInput.source + ")" : "Crack a whole hash file in one pass"}
              disabled={!r.desktop || !r.scope || r.hashInputBusy || r.jobId !== null || r.busy}
              onClick={() => void r.importHashFile()}>
              <Hash size={13} aria-hidden="true" />
              <span className="min-w-0 flex-1 truncate text-left">
                {r.hashInputBusy ? "Selecting…" : r.hashInput ? r.hashInput.count + " hashes · " + r.hashInput.source : "Import hash file"}
              </span>
            </Button>
          </label>
        </div>
        {r.attackMode === "mask" ? (
          <div className="space-y-1.5">
            <label className="block space-y-1">
              <span className="text-2xs text-fg-dim">Custom charsets · optional</span>
              <TextInput ariaLabel="Custom mask charsets"
                value={r.customCharsets}
                onChange={(value) => {
                  if (r.jobId !== null || r.busy) return;
                  r.setCustomCharsets(value.slice(0, 1200)); r.clearReveal();
                }}
                placeholder="1=0123456789abcdef;2=ABC"
                className={r.jobId !== null || r.busy ? "w-full opacity-40" : "w-full"} />
            </label>
            <label className="block space-y-1">
              <span className="text-2xs text-fg-dim">Mask pattern</span>
              <TextInput ariaLabel="Recovery mask pattern"
                value={r.maskText}
                onChange={(value) => {
                  if (r.jobId !== null || r.busy) return;
                  r.setMaskText(value.slice(0, 256)); r.clearReveal();
                }}
                placeholder="?u?l?l?o?d?d?d?d"
                className={r.jobId !== null || r.busy ? "w-full opacity-40" : "w-full"} />
            </label>
          </div>
        ) : null}
        <div className="flex items-center justify-between gap-2">
          <span className="text-2xs font-medium text-fg-dim">{r.attackMode === "mask" ? "Mask target" : "Wordlist"}</span>
          <span className="text-3xs text-fg-muted">{r.selectedWordlist
            ? r.selectedWordlist.size_bytes.toLocaleString() + " bytes"
            : "Required"}</span>
        </div>
        <div className="flex min-w-0 items-stretch gap-2" role="group" aria-label="Wordlist and recovery actions">
          {r.attackMode === "wordlist" ? (
            <>
          <Button size="sm" variant="outline"
            className="h-10 min-w-0 flex-1 justify-start gap-2 rounded-md px-2.5 text-left shadow-none"
            aria-label={r.choosingWordlist ? "Selecting wordlist" : "Choose wordlist"}
            title={r.selectedWordlist ? "Replace wordlist: " + fileLabel : "Choose a local wordlist in the native file picker"}
            disabled={!r.desktop || !r.scope || r.choosingWordlist || jobInProgress || r.jobId !== null}
            onClick={() => void r.chooseWordlist()}>
            {r.selectedWordlist ? <FileText size={15} className="shrink-0" aria-hidden="true" />
              : <FileUp size={15} className="shrink-0" aria-hidden="true" />}
            <span className="min-w-0 flex-1 truncate font-mono text-2xs text-fg-dim"
              title={fileLabel}>{r.choosingWordlist ? "Selecting…" : fileLabel}</span>
          </Button>
          <Button size="icon" variant="outline" className="h-10 w-10 shrink-0 rounded-md"
            aria-label={r.libraryOpen ? "Close wordlist library" : "Open wordlist library"}
            title="Wordlist library: built-in and downloadable password lists"
            disabled={!r.desktop || jobInProgress || r.jobId !== null}
            aria-expanded={r.libraryOpen}
            onClick={() => r.setLibraryOpen(!r.libraryOpen)}>
            <Library size={15} aria-hidden="true" />
          </Button>
            </>
          ) : null}
          {r.busy || r.jobId === null ? (
            <Button size="icon" className="h-10 w-10 shrink-0 rounded-md"
              aria-label={r.busy ? "Starting recovery" : "Start"}
              title={r.disabledReason ?? (r.selectedWordlist ? "Start recovery" : "Auto crack: detect and run the full attack ladder")}
              disabled={!!(r.selectedWordlist ? r.disabledReason : r.autoDisabledReason) || r.busy || r.choosingWordlist}
              onClick={() => void (r.selectedWordlist || r.attackMode === "mask" ? r.start() : r.autoStart())}>
              <Play size={16} aria-hidden="true" />
            </Button>
          ) : r.status === null ? (
            <Button size="icon" className="h-10 w-10 shrink-0 rounded-md"
              aria-label="Loading recovery job" title="Loading job" disabled>
              <Play size={16} aria-hidden="true" />
            </Button>
          ) : r.running ? (
            <Button size="icon" variant="outline" className="h-10 w-10 shrink-0 rounded-md"
              aria-label={r.pendingCancel || r.status.phase === "cancelling" ? "Stopping recovery" : "Stop recovery"}
              title="Stop recovery (cooperative cancellation)"
              disabled={r.pendingCancel || r.status.phase === "cancelling"}
              onClick={() => void r.cancel()}>
              <Square size={15} aria-hidden="true" />
            </Button>
          ) : (
            <Button size="icon" variant="outline" className="h-10 w-10 shrink-0 rounded-md"
              aria-label="Discard recovery result"
              title="Discard finished or failed results"
              disabled={r.revealing}
              onClick={() => void r.discard()}>
              <Trash2 size={15} aria-hidden="true" />
            </Button>
          )}
        </div>
        {r.libraryOpen && r.attackMode === "wordlist" ? (
          <div role="region" aria-label="Wordlist library" className="space-y-1.5 rounded-md border border-line bg-app p-2">
            <div className="flex items-center justify-between gap-2">
              <span className="text-3xs font-semibold uppercase tracking-wider text-fg-muted">Library</span>
              <Button size="sm" variant="ghost" className="h-6 px-2 text-3xs text-fg-muted"
                onClick={() => void r.refreshLibrary()} disabled={!!r.libraryBusy}>
                Refresh
              </Button>
            </div>
            {r.libraryEntries === null ? (
              <p className="text-2xs text-fg-muted">Loading library…</p>
            ) : r.libraryEntries.map((entry) => (
              <div key={entry.id} className="flex items-center justify-between gap-2 border-t border-line/60 pt-1.5 first:border-0 first:pt-0">
                <div className="min-w-0">
                  <p className="truncate text-2xs text-fg" title={entry.name}>{entry.name}</p>
                  <p className="text-3xs text-fg-muted">
                    {entry.present
                      ? entry.size_bytes.toLocaleString() + " bytes · " + entry.license_note
                      : "Not downloaded · " + entry.license_note}
                  </p>
                </div>
                {entry.present ? (
                  <div className="flex shrink-0 items-center gap-1">
                    <Button size="sm" variant="outline" className="h-7 px-2 text-3xs"
                      disabled={!!r.libraryBusy || r.jobId !== null}
                      onClick={() => void r.useLibraryWordlist(entry.id)}>
                      Use
                    </Button>
                    {entry.origin === "downloaded" ? (
                      <Button size="icon" variant="ghost" className="h-7 w-7"
                        aria-label={"Delete " + entry.name}
                        disabled={!!r.libraryBusy}
                        onClick={() => void r.deleteLibraryWordlist(entry.id)}>
                        <Trash2 size={12} aria-hidden="true" />
                      </Button>
                    ) : null}
                  </div>
                ) : (
                  <Button size="sm" variant="outline" className="h-7 shrink-0 gap-1 px-2 text-3xs"
                    disabled={!!r.libraryBusy}
                    onClick={() => void r.downloadLibraryWordlist(entry.id)}>
                    <Download size={12} aria-hidden="true" />
                    {r.libraryBusy === entry.id && r.libraryProgress
                      ? Math.round(r.libraryProgress.downloaded_bytes / 1048576) + " MB"
                      : "Download"}
                  </Button>
                )}
              </div>
            ))}
          </div>
        ) : null}
        {r.wordlistError ? <ErrorStrip>{r.wordlistError}</ErrorStrip> : null}
        {statusText
          ? <p role="status" className="pt-1 text-2xs text-fg-muted">{statusText}</p>
          : null}
      </div>

      <Accordion defaultValue={[]} className="mt-3 border-t border-line/70">
        <AccordionItem value="advanced" className="border-0">
          <AccordionTrigger className="group w-full rounded-none px-0 py-2.5 text-2xs font-medium text-fg-dim hover:text-fg focus-visible:ring-2 focus-visible:ring-orange">
            <span className="flex min-w-0 items-center gap-2">
              <SlidersHorizontal size={14} aria-hidden="true" className="text-fg-muted" />
              Advanced settings
            </span>
          </AccordionTrigger>
          <AccordionPanel className="space-y-3 border-t border-line/50 pt-3 pb-1">
            <div className="space-y-1.5">
              <span className="text-3xs font-semibold uppercase tracking-wider text-fg-muted">Engine</span>
              <Select ariaLabel="Recovery execution engine" value={r.engineChoice}
                onChange={(value) => {
                  if (r.jobId === null && !r.busy && (value === "rust" || value === "hashcat")) {
                    if (value === "hashcat") {
                      // Only modes with a successful fixed native KAT are
                      // advertised; never leave a stale, unverified selection.
                      const validated = r.hashcatCapability?.modes ?? [];
                      if (!validated.some((mode) => mode.algorithm === r.hashcatAlgorithm) && validated.length > 0) {
                        r.setHashcatAlgorithm(validated[0].algorithm);
                        lastHashcatMode = validated[0].algorithm;
                      }
                    }
                    r.setEngineChoice(value);
                    r.clearReveal();
                  }
                }}
                options={[
                  { value: "rust", label: "CyberDeck native Rust" },
                  ...(r.hashcatCapability?.available && !r.ruleText.trim() ? [
                    { value: "hashcat", label: "Hashcat embedded · 5 raw modes (experimental)" },
                  ] : []),
                ]} className="w-full" />
              {r.isKdfHash ? (
                <div className="space-y-1">
                  <span className="text-2xs text-fg-dim">Hash family</span>
                  <p className="rounded-md border border-line bg-app px-2 py-1.5 text-2xs text-fg">
                    Modular KDF · CPU
                  </p>
                </div>
              ) : (
                <label className="block space-y-1">
                  <span className="text-2xs text-fg-dim">Hash algorithm</span>
                  <Select ariaLabel="Recovery wordlist hash algorithm"
                    value={r.hashcatAlgorithm}
                    onChange={(value) => {
                      if (r.jobId !== null || r.busy) return;
                      const match = (r.engineChoice === "hashcat" ? EMBEDDED_MODES : RUST_MODES).find((mode) => mode.value === value);
                      if (!match) return;
                      r.setHashcatAlgorithm(match.value);
                      if (match.value !== "sha256" && r.backend.startsWith("open_cl:")) r.setBackend("cpu");
                      lastHashcatMode = match.value;
                      r.clearReveal();
                    }}
                    options={(r.engineChoice === "hashcat" ? EMBEDDED_MODES : RUST_MODES).filter((entry) =>
                      r.engineChoice !== "hashcat" || !r.hashcatCapability?.modes.length ||
                      r.hashcatCapability.modes.some((mode) => mode.algorithm === entry.value)
                    ).map(({value, label}) => ({value, label}))}
                    className="w-full" />
                  <span className="text-3xs text-fg-muted">MD5, NTLM and MD4 share 32 hex digits.</span>
                  {r.engineChoice === "hashcat" && r.hashcatMode.pwMax ? (
                    <span className="block text-3xs text-fg-muted"
                      title={"This mode's upstream optimized kernel skips candidates longer than " +
                        r.hashcatMode.pwMax + " characters; longer wordlist entries are not tested."}>
                      Optimized kernel tests candidates up to {r.hashcatMode.pwMax} characters (upstream kernel limit).
                    </span>
                  ) : null}
                </label>
              )}
              {r.engineChoice === "hashcat" && (
                <label className="block space-y-1">
                  <span className="text-2xs text-fg-dim">Wordlist transformation</span>
                  <Select ariaLabel="Embedded Hashcat candidate preset"
                    value={r.hashcatPreset}
                    onChange={(value) => {
                      if (r.jobId !== null || r.busy) return;
                      if (value !== "plain" && value !== "uppercase" && value !== "append_one") return;
                      r.setHashcatPreset(value);
                      lastHashcatPreset = value;
                      r.clearReveal();
                    }}
                    options={[
                      { value: "plain", label: "Original wordlist" },
                      { value: "uppercase", label: "Uppercase candidates" },
                      { value: "append_one", label: "Append 1 to candidates" },
                    ]} className="w-full" />
                  <span className="text-3xs text-fg-muted">
                    Prepared privately and bounded before native Hashcat; not arbitrary Hashcat rule scripts.
                  </span>
                </label>
              )}
              {r.hashcatCapability && !r.hashcatCapability.available ? (
                <p className="text-3xs text-fg-muted">
                  GPU engine not built (dev). See docs/crypto-review.md.
                </p>
              ) : null}
            </div>
            <div className="space-y-1.5">
              <span className="text-3xs font-semibold uppercase tracking-wider text-fg-muted">Compute</span>
              {r.engineChoice === "hashcat" ? (
                <p className="text-3xs text-fg-muted">Device selection is handled by Hashcat.</p>
              ) : <Select ariaLabel="Recovery V1 backend" value={r.backend}
                onChange={(value) => {
                  if (r.jobId === null && !r.busy) { r.setBackend(value); r.clearReveal(); }
                }}
                options={[
                  { value: "auto", label: "Auto · verified GPU or CPU" },
                  { value: "cpu", label: "CPU · Native Rust" },
                  ...(r.hashcatAlgorithm === "sha256" ? r.inventory?.devices ?? [] : []).map((device) => ({
                    value: "open_cl:" + device.device_index,
                    label: "OpenCL " + device.device_index + " · " + device.name
                      + (device.hardware_verified ? "" : " (unverified)"),
                  })),
                ]} className="w-full" />}
            </div>
            {r.engineChoice === "rust" && !r.isKdfHash && (
              <div className="space-y-1.5">
                <span className="block text-3xs font-semibold uppercase tracking-wider text-fg-muted">CPU wordlist rules · optional</span>
                <TextArea ariaLabel="Native CPU wordlist transformation rules"
                  value={r.ruleText} maxLength={4096} rows={3}
                  disabled={r.jobId !== null || r.busy}
                  onChange={(value) => {
                    const text = value.slice(0, 4096);
                    r.setRuleText(text);
                    if (text.trim()) r.setBackend("cpu");
                    r.clearReveal();
                  }}
                  placeholder={":\n$1\nu"} />
                <label className="block space-y-1">
                  <span className="text-2xs text-fg-dim">Bundled rule sets</span>
                  <Select ariaLabel="Bundled rule set library"
                    value={r.ruleSetId ?? "none"}
                    onChange={(value) => {
                      if (r.jobId !== null || r.busy) return;
                      void r.pickRuleSet(value === "none" ? null : value);
                      if (value !== "none") r.setBackend("cpu");
                    }}
                    options={[
                      { value: "none", label: "No bundled rule set" },
                      ...(r.ruleSets ?? []).map((set) => ({
                        value: set.id,
                        label: set.id + " · " + set.rule_count.toLocaleString() + " rules",
                      })),
                    ]} className="w-full" />
                  {r.ruleSetNote ? (
                    <span className="block text-3xs text-fg-muted">{r.ruleSetNote}</span>
                  ) : null}
                </label>
              </div>
            )}
            <div className="space-y-1.5">
              <span className="text-3xs font-semibold uppercase tracking-wider text-fg-muted">Processing limits</span>
              <div className="grid grid-cols-2 gap-2">
                <label className="min-w-0 space-y-1">
                  <span className="text-2xs text-fg-muted">Passwords to try</span>
                  <NumberInput ariaLabel="Recovery candidate budget" min={1} max={1000000}
                    value={r.maxCandidates} onChange={(value) => {
                      if (r.jobId !== null || r.busy || !Number.isSafeInteger(value)) return;
                      r.setMaxCandidates(Math.max(1, Math.min(1000000, value)));
                    }} className={r.jobId !== null || r.busy ? "w-full opacity-40" : "w-full"} />
                </label>
                <label className="min-w-0 space-y-1">
                  <span className="text-2xs text-fg-muted">Masked results</span>
                  <NumberInput ariaLabel="Maximum matches" min={1} max={4}
                    value={r.maxMatches} onChange={(value) => {
                      if (r.jobId !== null || r.busy || !Number.isSafeInteger(value)) return;
                      r.setMaxMatches(Math.max(1, Math.min(4, value)));
                    }} className={r.jobId !== null || r.busy ? "w-full opacity-40" : "w-full"} />
                </label>
              </div>
            </div>
            {r.selectedDevice !== null ? (
              <label className="block space-y-1">
                <span className="text-2xs text-fg-muted">OpenCL batch size</span>
                <NumberInput ariaLabel="OpenCL batch size" min={1} max={65536}
                  value={r.batchSize} onChange={(value) => {
                    if (r.jobId !== null || r.busy || !Number.isSafeInteger(value)) return;
                    r.setBatchSize(Math.max(1, Math.min(65536, value)));
                  }} className={r.jobId !== null || r.busy ? "w-full opacity-40" : "w-full"} />
              </label>
            ) : null}
          </AccordionPanel>
        </AccordionItem>
      </Accordion>
    </section>
  );
}

export function NativeRecoveryDevices() {
  const { inventory, deviceError, desktop } = useRecovery();
  return (
    <section aria-label="Recovery devices" className="space-y-2 px-3 py-3 text-2xs">
      <div className="text-xs font-semibold text-fg">Devices</div>
      <div className="flex items-center justify-between gap-2">
        <div><span>CPU · Native Rust</span>
          <p className="text-fg-muted">{inventory?.cpu
            ? inventory.cpu.model + " · " + inventory.cpu.logical_processors + " logical processors (" + inventory.cpu.architecture + ")"
            : desktop ? "Detecting CPU resources…" : "Desktop only"}</p>
        </div><Chip tone={desktop ? "ok" : "muted"}>{desktop ? "Available" : "Desktop only"}</Chip>
      </div>
      {(inventory?.devices ?? []).map((device) => (
        <div key={device.device_index} className="flex flex-wrap items-start justify-between gap-2 border-t border-line pt-2">
          <span className="min-w-0 flex-1 break-words">
            {device.name}<span className="block text-fg-muted">{device.vendor} · {device.driver}</span>
          </span>
          <Chip tone="muted">Unverified</Chip>
        </div>
      ))}
      {desktop && inventory?.devices.length === 0 ? (
        <p className="text-fg-muted">No OpenCL devices detected. CPU remains available.</p>
      ) : null}
      {deviceError ? <ErrorStrip>{deviceError}</ErrorStrip> : null}
      {inventory && !inventory.opencl_detected ? (
        <details className="text-fg-muted">
          <summary className="cursor-pointer">OpenCL details</summary>
          <p className="mt-1 break-words">{inventory.detail}</p>
        </details>
      ) : null}
    </section>
  );
}

/** Only called for a backend-authorized, native-OS-confirmed transient reveal.
 * Binary/non-UTF8 candidates retain unambiguous hex rather than mojibake.
 * Never log or persist the result; clear underlying candidate byte array.
 */
function printableRevealedCandidate(hex: string): string | null {
  if (hex.length === 0 || hex.length > 8192 ||
    hex.length % 2 !== 0 || !/^[a-fA-F0-9]+$/.test(hex)) return null;
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return /[\x00-\x1f\x7f-\x9f]/u.test(text) ? null : text;
  } catch {
    return null;
  } finally {
    bytes.fill(0);
  }
}

export function NativeRecoveryResults() {
  const r = useRecovery();
  // Before a hash or a job exists there is nothing to show.
  if (!r.hash && r.jobId === null) return null;
  const view = recoveryDisplay(r.scope, r.jobId, r.status, r.error, r.discarded);
  const matches = r.status?.summary?.matches ?? [];
  const revealedText = r.secretHex === null ? null : printableRevealedCandidate(r.secretHex);
  const [visibleMatches, setVisibleMatches] = useState(16);
  useEffect(() => { setVisibleMatches(16); }, [r.scope, r.jobId]);
  const isActive = view.kind === "running";
  return (
    <div className="h-full min-h-0 space-y-3 overflow-y-auto p-3"
      aria-live="polite" aria-relevant="text" aria-label="Scroll recovery results"
      onScroll={(event) => {
        const node = event.currentTarget;
        if (node.scrollTop + node.clientHeight >= node.scrollHeight - 72) {
          setVisibleMatches((count) => Math.min(count + 16, matches.length));
        }
      }}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-xs font-medium text-fg">{view.title}</span>
          {isActive ? <Chip tone="orange">Active</Chip> : null}
          {view.kind === "completed" ? <Chip tone="ok">Masked</Chip> : null}
          {view.kind === "failed" ? <Chip tone="err">Failed</Chip> : null}
        </div>
        {r.jobId !== null ? <span className="font-mono text-2xs text-fg-muted">Job #{r.jobId}</span> : null}
      </div>
      {isActive ? (
        <div className="flex items-center gap-3 rounded-md border border-line/70 bg-app/50 px-2.5 py-2">
          <Phosphor intensity={1} play theme="dark" label="Recovery activity"
            className="h-20 w-20 shrink-0" />
          <div className="min-w-0 space-y-1">
            <div className="text-2xs font-semibold text-fg">Processing wordlist</div>
            <p className="text-2xs leading-relaxed text-fg-muted">{view.detail}</p>
          </div>
        </div>
      ) : <p className="text-2xs leading-relaxed text-fg-muted">{view.detail}</p>}
      {r.status?.progress && (
        <div className="space-y-1.5">
          {r.status.progress.stage ? (
            <p className="text-2xs text-fg-muted">Stage · {r.status.progress.stage}</p>
          ) : null}
          <div className="flex justify-between gap-2 font-mono text-3xs text-fg-dim">
            <span>{r.status.progress.tried.toLocaleString()} / {r.status.progress.budget.toLocaleString()} candidates</span>
            <span>{r.percent}%</span>
          </div>
          <ProgressBar percent={r.percent} className="w-full" />
        </div>
      )}
      {r.status?.summary && (
        <div className="flex flex-wrap gap-3 text-2xs text-fg-muted">
          {r.status.summary.engine.startsWith("embedded_hashcat")
              ? <span>Hashcat processed · count unavailable in ABI v1</span>
              : <span>{r.status.summary.tried.toLocaleString()} checked</span>}
          <span>{r.status.summary.duration_ms.toLocaleString()} ms</span>
          {r.status.summary.duration_ms > 0 && !r.status.summary.engine.startsWith("embedded_hashcat") ? (
            <span>{Math.round(r.status.summary.tried / (r.status.summary.duration_ms / 1000)).toLocaleString()} H/s</span>
          ) : null}
          {r.status.summary.limit_reached ? <span>Candidate limit reached</span> : null}
        </div>
      )}
      {(r.status?.summary?.stages?.length ?? 0) > 0 ? (
        <div role="list" aria-label="Autopilot stage results" className="space-y-1">
          {r.status!.summary!.stages!.map((stage, index) => (
            <div key={index} role="listitem" className="flex items-center justify-between gap-2 rounded-sm border border-line/70 bg-app/40 px-2.5 py-1.5 text-2xs">
              <span className="min-w-0 truncate text-fg-dim" title={stage.label}>{stage.label}</span>
              <span className="flex shrink-0 items-center gap-2 text-fg-muted">
                <span className="font-mono">{stage.tried.toLocaleString()} tried</span>
                {stage.matched ? <Chip tone="ok">Match</Chip> : <Chip tone="muted">No match</Chip>}
              </span>
            </div>
          ))}
        </div>
      ) : null}
      {matches.length > 0 && (
        <div className="space-y-2" aria-label="Masked recovered candidates">
          {matches.slice(0, visibleMatches).map((match, ordinal) => (
            <div key={ordinal} className="flex items-center justify-between gap-2 rounded-sm border border-line bg-app px-3 py-2">
              <div className="min-w-0">
                <p className="font-mono text-xs text-fg">••••••••</p>
                <p className="mt-1 text-2xs text-fg-muted">Candidate #{match.candidate_index}</p>
              </div>
              <Button size="sm" variant="outline" className="h-8 gap-1.5"
                title="Native OS confirmation required before revealing sensitive candidate bytes"
                disabled={r.status?.phase !== "completed" || !r.status.reveal_available || r.revealing}
                onClick={() => void r.reveal(ordinal)}>
                <Eye size={13} aria-hidden="true" /> Reveal
              </Button>
            </div>
          ))}
        </div>
      )}
      {visibleMatches < matches.length ? <p className="text-2xs text-fg-muted">Scroll to view more masked matches</p> : null}
      {r.secretHex !== null && (
        <div role="region" aria-label="Transient recovered candidate" className="rounded-sm border border-line bg-app p-3">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <span className="text-2xs text-warn">{revealedText === null ? "Sensitive binary candidate · hex" : "Recovered candidate · UTF-8"} · auto-hide in 30 seconds</span>
            <Button size="sm" variant="outline" className="h-8 gap-1"
              onClick={r.clearReveal}><EyeOff size={13} aria-hidden="true" /> Hide</Button>
          </div>
          <code className="block whitespace-pre-wrap break-all font-mono text-xs text-fg">
            {revealedText ?? r.secretHex}
          </code>
          {revealedText !== null ? (
            <details className="mt-2 text-3xs text-fg-muted">
              <summary className="cursor-pointer">Show exact candidate bytes (hex)</summary>
              <code className="mt-1 block break-all font-mono text-2xs">{r.secretHex}</code>
            </details>
          ) : null}
        </div>
      )}
      {r.error && <ErrorStrip>{r.error}</ErrorStrip>}
    </div>
  );
}
