"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { Accordion, AccordionItem, AccordionTrigger, AccordionPanel } from "@/components/ui/accordion";
import { VerifyAlgorithmCombobox, VERIFY_ALGORITHMS, type VerifyAlgorithmId } from "./VerifyAlgorithmCombobox";
import { verifyDigestOutput } from "./verify-output";
import { FileUp, Info, Link2, Play } from "lucide-react";
import { ErrorStrip } from "@ds/compact";
import { Chip, Pane, Resizer, TextArea, TextInput, ToolButton } from "@ds/panes";
import { useWorkbench, useWorkbenchCase } from "@state/workbench";
import { cryptoOp, kdfVerify } from "@lib/ipc";
import { detectHashFormats } from "./model/hash";
import {
  NativeRecoveryV1, NativeRecoveryControls, NativeRecoveryResults, NativeRecoveryDevices,
} from "./NativeRecoveryV1";

const MAX_HASH_INPUT_CHARS = 2048;
const CANDIDATE_PAGE_SIZE = 12;

// Hash drafts are transient, case-isolated and never written to disk.
// Cache only operator-pasted digests, NEVER verification candidates or passwords.
const hashDrafts = new Map<string, string>();
function rememberedHash(caseId: string): string {
  return typeof window === "undefined" ? "" : hashDrafts.get(caseId) ?? "";
}
function keepHash(caseId: string, value: string) {
  if (typeof window === "undefined") return;
  if (!hashDrafts.has(caseId) && hashDrafts.size >= 12) hashDrafts.delete(hashDrafts.keys().next().value!);
  hashDrafts.set(caseId, value);
}

export function HashAnalysisView() {
  const { caseId } = useWorkbenchCase();
  const { sendToRecipes } = useWorkbench();
  const [operationsWidth, setOperationsWidth] = useState(408);
  const [input, setInput] = useState("");
  const hashFileRef = useRef<HTMLInputElement>(null);
  const [hashImportError, setHashImportError] = useState<string | null>(null);
  const [visibleCandidates, setVisibleCandidates] = useState(CANDIDATE_PAGE_SIZE);
  const [candidate, setCandidate] = useState("");
  const [algorithm, setAlgorithm] = useState<VerifyAlgorithmId>("sha256");
  const [verdict, setVerdict] = useState<"match" | "mismatch" | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const candidates = useMemo(() => detectHashFormats(input), [input]);
  useEffect(() => { setVisibleCandidates(CANDIDATE_PAGE_SIZE); }, [input]);
  const showNextCandidates = (node: HTMLDivElement) => {
    if (node.scrollTop + node.clientHeight >= node.scrollHeight - 72) {
      setVisibleCandidates((n) => Math.min(n + CANDIDATE_PAGE_SIZE, candidates.length));
    }
  };
  const hash = input.trim();
  const cpuRecoveryEligible = /^[a-fA-F0-9]+$/.test(hash) && [32, 40, 64, 128].includes(hash.length);
  // Digest length is a hint, not a guarantee of the hash algorithm.
  useEffect(() => {
    if (!/^[a-fA-F0-9]+$/.test(hash)) return;
    if (hash.length === 32) setAlgorithm("md5");
    else if (hash.length === 40) setAlgorithm("sha1");
    else if (hash.length === 64) setAlgorithm("sha256");
    else if (hash.length === 128) setAlgorithm("sha512");
  }, [hash]);

  const kdfFormat = /^\$(?:2[abxy]\$|argon2(?:id|i|d)\$|y\$|7\$|scrypt\$|pbkdf2(?:-sha256|-sha512)?\$)/.test(hash);

  useEffect(() => {
    setInput(rememberedHash(caseId));
    setCandidate("");
    setHashImportError(null);
    setVerdict(null);
    setVerifyError(null);
  }, [caseId]);

  const importHashFile = async (file: File | undefined) => {
    if (!file) return;
    setHashImportError(null);
    try {
      if (file.size > 8192) throw new Error("Choose a small text file (8 KiB maximum).");
      const text = (await file.text()).replace(/^\uFEFF/, "").trim();
      const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
      if (lines.length !== 1) throw new Error("The file must contain exactly one hash.");
      const line = lines[0];
      const shaSum = /^([0-9a-fA-F]{32,40}|[0-9a-fA-F]{56,64}|[0-9a-fA-F]{96,128})\s+\*?\S.+$/.exec(line);
      const value = shaSum ? shaSum[1] : line;
      if (value.length > MAX_HASH_INPUT_CHARS) throw new Error("Hash exceeds the 2,048-character input limit.");
      setInput(value);
      keepHash(caseId, value);
      setVerdict(null);
      setVerifyError(null);
    } catch (reason) {
      setHashImportError(reason instanceof Error ? reason.message : String(reason));
    }
  };

  const verify = async () => {
    if (verifying) return;
    setVerifying(true);
    setVerifyError(null);
    setVerdict(null);
    try {
      if (!hash || !candidate.length) throw new Error("Enter a hash and candidate.");
      if (kdfFormat) {
        const matched = await kdfVerify(hash, candidate);
        setVerdict(matched ? "match" : "mismatch");
      } else {
        if (!/^[0-9a-f]+$/i.test(hash)) throw new Error("Expected a hexadecimal digest.");
        if (hash.length !== VERIFY_ALGORITHMS.find((op) => op.id === algorithm)!.hexLength) {
          throw new Error("Digest length does not match the selected algorithm.");
        }
        const output = await cryptoOp(algorithm, new TextEncoder().encode(candidate));
        setVerdict(verifyDigestOutput(algorithm, hash, output) ? "match" : "mismatch");
      }
    } catch (reason) {
      setVerifyError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setVerifying(false);
    }
  };

  return (
    <NativeRecoveryV1 targetHash={input} onCaseCreated={(newCaseId) => keepHash(newCaseId, input)}>
      <div className="flex h-full min-h-0 min-w-0 gap-px bg-line">
        <div className="flex min-w-0 flex-1 flex-col gap-px">
          <Pane title="Hash Input" className="shrink-0" bodyClassName="p-3">
            <TextArea
              value={input}
              onChange={(value) => {
                const next = value.slice(0, MAX_HASH_INPUT_CHARS);
                setInput(next);
                keepHash(caseId, next);
                setHashImportError(null);
                setVerdict(null);
                setVerifyError(null);
              }}
              maxLength={MAX_HASH_INPUT_CHARS}
              ariaLabel="Hash input"
              placeholder="Paste a digest or password hash…"
              rows={4}
              className="h-28 min-h-28 max-h-28 overflow-y-auto"
            />
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <input ref={hashFileRef} type="file" accept=".txt,.hash,.md5,.sha1,.sha256,.sha512,text/plain"
                aria-label="Choose a hash text file" className="sr-only"
                onChange={(event) => {
                  const file = event.currentTarget.files?.[0];
                  if (file) void importHashFile(file);
                  event.currentTarget.value = "";
                }} />
              <ToolButton title="Import a single hash from a local text file (8 KiB maximum)"
                onClick={() => hashFileRef.current?.click()}>
                <FileUp size={13} aria-hidden="true" /> Import
              </ToolButton>
              <ToolButton disabled={!hash.length} title="Send the entered hash to Recipes for further analysis without exposing verification candidates"
                onClick={() => sendToRecipes(hash, "Hash Analysis target")}>
                <Link2 size={13} aria-hidden="true" /> To Recipes
              </ToolButton>
              <span className="ml-auto font-mono text-2xs text-fg-muted">{hash.length}/{MAX_HASH_INPUT_CHARS} characters</span>
            </div>
            {hashImportError ? <ErrorStrip>{hashImportError}</ErrorStrip> : null}
          </Pane>
          <Pane title="Detected Candidates" className={hash ? "h-[40%] min-h-44 max-h-[50%] shrink-0" : "h-44 shrink-0"} bodyClassName="overflow-hidden"
            actions={
              <details className="relative text-2xs text-fg-muted">
                <summary className="inline-flex cursor-pointer items-center gap-1 rounded px-1 focus-visible:outline focus-visible:outline-2"
                  aria-label="About heuristic hash identification">
                  <Info size={13} aria-hidden="true" /> About
                </summary>
                <p className="mt-1 max-w-sm rounded-sm border border-line bg-app p-2 leading-relaxed">
                  Formats are heuristic candidates based on string shape, not confirmed identities.
                  Identical lengths can represent different algorithms. CPU wordlist recovery accepts
                  MD5, SHA-1, NTLM, SHA-256, SHA-512 and SHA3-256 when explicitly selected;
                  a matching digest length alone never proves the algorithm.
                </p>
              </details>
            }>
            {hash.length === 0 ? (
              <div className="px-3 py-6 text-center">
                <p className="text-xs font-medium text-fg">No hash to identify</p>
                <p className="mt-1 text-2xs text-fg-muted">Paste a hash to view possible formats.</p>
              </div>
            ) : (
              <div className="h-full min-h-0 overflow-auto" onScroll={(event) => showNextCandidates(event.currentTarget)}
                aria-label="Scroll detected candidates">
                <table className="data-table" aria-label="Heuristic hash format candidates">
                  <thead>
                    <tr>
                      <th scope="col">Possible format</th>
                      <th scope="col">Confidence</th>
                      <th scope="col">Recovery V1</th>
                    </tr>
                  </thead>
                  <tbody>
                    {candidates.slice(0, visibleCandidates).map((item, index) => (
                      <tr key={item.format + index} className="align-top">
                        <td>
                          <p className="font-medium text-fg">{item.format}</p>
                          <p className="mt-1 text-2xs leading-relaxed text-fg-muted">{item.note}</p>
                        </td>
                        <td>
                          <Chip tone={item.confidence === "high" ? "ok" : "muted"}>
                            {item.confidence}
                          </Chip>
                        </td>
                        <td className="text-2xs">
                          {cpuRecoveryEligible ? (
                            <span className="text-warn">CPU eligible · confirm algorithm</span>
                          ) : (
                            <span className="text-fg-muted">Raw CPU mode not recognized</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {visibleCandidates < candidates.length ? <p className="px-3 py-2 text-2xs text-fg-muted">Scroll to load more candidates</p> : null}
              </div>
            )}
          </Pane>
          <Pane title="Recovery Results" className="min-h-40 flex-1" bodyClassName="overflow-hidden">
            <NativeRecoveryResults />
          </Pane>
        </div>
        <Resizer
          direction="horizontal" flip ariaLabel="Resize hash analysis operations"
          value={operationsWidth} onChange={setOperationsWidth} min={320} max={580}
        />
        <Pane title="Operations" className="shrink-0" style={{ width: operationsWidth }}
          bodyClassName="overflow-y-auto">
          <Accordion defaultValue={["verify"]} className="border-b border-line">
            <AccordionItem value="verify" className="border-none">
              <AccordionTrigger className="w-full rounded-none px-3 py-2.5 text-xs font-semibold text-fg hover:bg-app/40">
                Verify
              </AccordionTrigger>
              <AccordionPanel className="space-y-3 px-3 pb-3">
                <label className="block space-y-1">
                  <span className="text-2xs text-fg-muted">Hash algorithm (length is only a suggestion)</span>
                  <VerifyAlgorithmCombobox value={algorithm}
                    onChange={(value) => { setAlgorithm(value); setVerdict(null); }} />
                </label>
                <label className="block space-y-1">
                  <span className="text-2xs text-fg-muted">Candidate</span>
                  <TextInput value={candidate} ariaLabel="Candidate password" placeholder="Enter candidate"
                    onChange={(value) => { setCandidate(value); setVerdict(null); }} className="w-full" />
                </label>
                <ToolButton tone="primary" onClick={() => void verify()}
                  disabled={verifying || !hash || !candidate.length}
                  title="Verify one candidate against the selected digest or recognized native KDF">
                  <Play size={13} aria-hidden="true" /> {verifying ? "Checking…" : "Verify"}
                </ToolButton>
                {verdict === "match" ? <Chip tone="ok">Match</Chip> : null}
                {verdict === "mismatch" ? <Chip tone="err">No match</Chip> : null}
                {verifyError ? <ErrorStrip>{verifyError}</ErrorStrip> : null}
              </AccordionPanel>
            </AccordionItem>
          </Accordion>
          <NativeRecoveryControls />
        </Pane>
      </div>
    </NativeRecoveryV1>
  );
}
