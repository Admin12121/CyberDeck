"use client";

import { useEffect, useMemo, useState } from "react";
import { FileUp, Info, Link2, Play } from "lucide-react";
import { Chip, Pane, Resizer, Select, TextInput, ToolButton } from "@ds/panes";
import { useWorkbenchCase } from "@state/workbench";
import { cryptoOp, kdfVerify } from "@lib/ipc";
import { detectHashFormats } from "./model/hash";
import { isSha256WordlistTarget } from "./recovery-presentation";
import {
  NativeRecoveryV1, NativeRecoveryControls, NativeRecoveryResults, NativeRecoveryDevices,
} from "./NativeRecoveryV1";

const MAX_HASH_INPUT_CHARS = 2048;
const CANDIDATE_PAGE_SIZE = 12;

const VERIFY_OPTIONS = [
  { value: "md5", label: "MD5" },
  { value: "sha1", label: "SHA-1" },
  { value: "sha256", label: "SHA-256" },
  { value: "sha512", label: "SHA-512" },
  { value: "ntlm", label: "NTLM" },
  { value: "sha3_256", label: "SHA3-256" },
];
const VERIFY_HEX_LENGTH: Record<string, number> = {
  md5: 32, sha1: 40, sha256: 64, sha512: 128, ntlm: 32, sha3_256: 64,
};

export function HashAnalysisView() {
  const { caseId } = useWorkbenchCase();
  const [operationsWidth, setOperationsWidth] = useState(408);
  const [input, setInput] = useState("");
  const [visibleCandidates, setVisibleCandidates] = useState(CANDIDATE_PAGE_SIZE);
  const [candidate, setCandidate] = useState("");
  const [algorithm, setAlgorithm] = useState("sha256");
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
  const compatibleShape = isSha256WordlistTarget(hash);
  const kdfFormat = /^\$(?:2[abxy]\$|argon2(?:id|i|d)\$|y\$|7\$)/.test(hash);

  useEffect(() => {
    setCandidate("");
    setVerdict(null);
    setVerifyError(null);
  }, [caseId]);

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
        if (hash.length !== VERIFY_HEX_LENGTH[algorithm]) {
          throw new Error("Digest length does not match the selected algorithm.");
        }
        const output = await cryptoOp(algorithm, new TextEncoder().encode(candidate));
        setVerdict(output.output_hex.toLowerCase() === hash.toLowerCase() ? "match" : "mismatch");
      }
    } catch (reason) {
      setVerifyError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setVerifying(false);
    }
  };

  return (
    <NativeRecoveryV1 targetHash={input}>
      <div className="flex h-full min-h-0 min-w-0 gap-px bg-line">
        <div className="flex min-w-0 flex-1 flex-col gap-px">
          <Pane title="Hash Input" className="shrink-0" bodyClassName="p-3">
            <textarea
              value={input}
              onChange={(event) => {
                setInput(event.target.value.slice(0, MAX_HASH_INPUT_CHARS));
                setVerdict(null);
                setVerifyError(null);
              }}
              spellCheck={false}
              maxLength={MAX_HASH_INPUT_CHARS}
              aria-label="Hash input"
              placeholder="Paste a digest or password hash…"
              className="h-28 max-h-28 min-h-28 w-full resize-none overflow-y-auto rounded-sm border border-line bg-app p-3 font-mono text-xs leading-relaxed text-fg outline-none ring-0 focus:border-line focus:outline-none focus:ring-0 focus-visible:border-line focus-visible:outline-none focus-visible:ring-0"
            />
            <div className="mt-2 flex flex-wrap items-center gap-2">
              <ToolButton disabled title="Hash file import is not available in this screen">
                <FileUp size={13} aria-hidden="true" /> Import
              </ToolButton>
              <ToolButton disabled title="Forensic handoff will be enabled after case integration">
                <Link2 size={13} aria-hidden="true" /> Handoff
              </ToolButton>
              <span className="ml-auto font-mono text-[11px] text-fg-muted">{hash.length}/{MAX_HASH_INPUT_CHARS} characters</span>
            </div>
          </Pane>
          <Pane title="Detected Candidates" className={hash ? "h-[40%] min-h-44 max-h-[50%] shrink-0" : "h-44 shrink-0"} bodyClassName="overflow-hidden"
            actions={
              <details className="relative text-[11px] text-fg-muted">
                <summary className="inline-flex cursor-pointer items-center gap-1 rounded px-1 focus-visible:outline focus-visible:outline-2"
                  aria-label="About heuristic hash identification">
                  <Info size={13} aria-hidden="true" /> About
                </summary>
                <p className="mt-1 max-w-sm rounded-sm border border-line bg-app p-2 leading-relaxed">
                  Formats are heuristic candidates based on string shape, not confirmed identities.
                  Identical lengths can represent different algorithms. Recovery V1 only accepts
                  64-character hexadecimal targets for SHA-256; shape alone does not establish SHA-256.
                </p>
              </details>
            }>
            {hash.length === 0 ? (
              <div className="px-3 py-6 text-center">
                <p className="text-xs font-medium text-fg">No hash to identify</p>
                <p className="mt-1 text-[11px] text-fg-muted">Paste a hash to view possible formats.</p>
              </div>
            ) : (
              <div className="h-full min-h-0 overflow-auto" onScroll={(event) => showNextCandidates(event.currentTarget)}
                aria-label="Scroll detected candidates">
                <table className="w-full text-left text-xs" aria-label="Heuristic hash format candidates">
                  <thead className="sticky top-0 z-10 border-b border-line bg-app text-[11px] text-fg-muted">
                    <tr>
                      <th scope="col" className="min-w-40 px-3 py-2 font-medium">Possible format</th>
                      <th scope="col" className="px-3 py-2 font-medium">Confidence</th>
                      <th scope="col" className="min-w-32 px-3 py-2 font-medium">Recovery V1</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line/60">
                    {candidates.slice(0, visibleCandidates).map((item, index) => (
                      <tr key={item.format + index} className="align-top">
                        <td className="px-3 py-2">
                          <p className="font-medium text-fg">{item.format}</p>
                          <p className="mt-1 text-[11px] leading-relaxed text-fg-muted">{item.note}</p>
                        </td>
                        <td className="px-3 py-2">
                          <Chip tone={item.confidence === "high" ? "ok" : "muted"}>
                            {item.confidence}
                          </Chip>
                        </td>
                        <td className="px-3 py-2 text-[11px]">
                          {compatibleShape ? (
                            <span className="text-warn">Shape eligible · SHA-256 only</span>
                          ) : (
                            <span className="text-fg-muted">Not supported in V1</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {visibleCandidates < candidates.length ? <p className="px-3 py-2 text-[11px] text-fg-muted">Scroll to load more candidates</p> : null}
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
          <section aria-label="Verify candidate" className="space-y-3 border-b border-line px-3 py-3">
            <div className="text-xs font-semibold text-fg">Verify</div>
            <div className="space-y-2">
              <label className="block space-y-1">
                <span className="text-[11px] text-fg-muted">Algorithm</span>
                <Select value={algorithm} ariaLabel="Verification algorithm"
                  onChange={(value) => {
                    setAlgorithm(value);
                    setVerdict(null);
                  }} options={VERIFY_OPTIONS} className="w-full" />
              </label>
              <label className="block space-y-1">
                <span className="text-[11px] text-fg-muted">Candidate</span>
                <TextInput value={candidate} ariaLabel="Candidate password" placeholder="Enter candidate"
                  onChange={(value) => { setCandidate(value); setVerdict(null); }}
                  className="w-full" />
              </label>
              <ToolButton tone="primary" onClick={() => void verify()}
                disabled={verifying || !hash || !candidate.length}
                title="Verify the entered candidate against the selected digest or native KDF format">
                <Play size={13} aria-hidden="true" /> {verifying ? "Checking…" : "Verify"}
              </ToolButton>
              {verdict === "match" ? <Chip tone="ok">Match</Chip> : null}
              {verdict === "mismatch" ? <Chip tone="err">No match</Chip> : null}
              {verifyError ? <p role="alert" className="text-[11px] text-err">{verifyError}</p> : null}
            </div>
          </section>
          <NativeRecoveryControls />
          <NativeRecoveryDevices />
        </Pane>
      </div>
    </NativeRecoveryV1>
  );
}
