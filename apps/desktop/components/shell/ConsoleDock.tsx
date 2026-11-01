"use client";
/**
 * Console dock: operation log plus a small command router
 * (help, clear, scan, spider, get, crack, status).
 */
import { useRef } from "react";
import { b64,crackWordlistDialog,cryptoOp,httpSend,isDesktop,kdfVerify,spiderScan,webScan } from "@lib/ipc";import { useWorkbenchCase, useWorkbenchTerminals } from "@state/workbench";

export function ConsoleDock({ terminalId }: { terminalId: string }) {
  const wb = useWorkbenchTerminals();
  const { caseId } = useWorkbenchCase();
  const currentCase = useRef(caseId);
  currentCase.current = caseId;
  const input = wb.terminalInputs[terminalId] ?? "";
  const setInput = (value: string) => wb.setTerminalInput(terminalId, value);
  const lines = terminalId === "terminal-1" ? wb.consoleLines : wb.terminalLines[terminalId] ?? [];
  const busy = wb.terminalBusy[terminalId] ?? false;
  const setBusy = (next: boolean) => wb.setTerminalBusy(terminalId, next);

  const log = (line: string) => {
    if (currentCase.current === caseId) wb.logTerminal(terminalId, line);
  };

  const runCommand = async (raw: string) => {
    const caseAtInvocation = caseId;
    const line = raw.trim();
    if (!line) return;
    const [cmd, ...args] = line.split(/\s+/);
    // Console history is retained in memory; do not echo secrets or target credentials.
    const sensitive = new Set(["verify", "hash", "b64", "unb64", "crack", "get", "scan", "spider"]);
    log(sensitive.has(cmd.toLowerCase()) ? `> ${cmd.toLowerCase()} [arguments hidden]` : `> ${line}`);
    switch (cmd.toLowerCase()) {
      case "clear":
        wb.clearTerminal(terminalId);
        return;
      case "help":
        log("commands: hash <algo> <text> · verify <kdf-hash> <password> · b64 <text> · unb64 <b64> · scan --authorized <url> · spider --authorized <url> [depth] · get <url> · crack <algo> <hash> <wordlist> · status · clear");
        return;
      case "status":
        log(`ipc: ${isDesktop() ? "tauri" : "browser fallback"} · tools stay mounted · console keeps last 500 lines`);
        return;
      case "hash": {
        if (args.length < 2) return log("usage: hash <algo> <text>  (algos: md5, sha1, sha224, sha256, sha384, sha512, crc32, ntlm, sha3_256, sha3_512)");
        const result = await cryptoOp(args[0], new TextEncoder().encode(args.slice(1).join(" ")));
        log(`hash: ${result.output_hex}  · engine ${result.engine} ${result.engine_version}`);
        return;
      }
      case "verify": {
        if (args.length < 2) return log("usage: verify <bcrypt-or-argon2-hash> <password>");
        const matched = await kdfVerify(args[0], args.slice(1).join(" "));
        log(matched ? "verify: MATCH" : "verify: no match");
        return;
      }
      case "b64": {
        if (!args[0]) return log("usage: b64 <text>");
        const encoded = b64.encode(new TextEncoder().encode(args.join(" ")));
        log(`b64: ${encoded}`);
        return;
      }
      case "unb64": {
        if (!args[0]) return log("usage: unb64 <base64>");
        const decoded = b64.decode(args.join(""));
        const text = new TextDecoder().decode(decoded);
        log(`unb64: ${text}`);
        return;
      }
      case "scan": {
        if (args[0] !== "--authorized" || !args[1]) return log("usage: scan --authorized <url>  (only targets you own or are authorized to test)");
        log(`scan ${args[1]}: running native review…`);
        try {
          const findings = await webScan(args[1], true);
          log(`scan: ${findings.length} findings`);
          for (const f of findings.slice(0, 20)) log(`  [${f.severity}] ${f.title}`);
        } catch (err) {
          log(`scan failed: ${err instanceof Error ? err.message : String(err)}`);
        }
        return;
      }
      case "spider": {
        if (args[0] !== "--authorized" || !args[1]) return log("usage: spider --authorized <url> [depth]");
        const depth = Math.max(1, Math.min(4, Number.parseInt(args[2] ?? "2", 10) || 2));
        log(`spider ${args[1]} depth ${depth}: crawling…`);
        try {
          const links = await spiderScan(args[1], depth, true);
          log(`spider: ${links.length} urls`);
          for (const url of links.slice(0, 10)) log(`  ${url}`);
        } catch (err) {
          log(`spider failed: ${err instanceof Error ? err.message : String(err)}`);
        }
        return;
      }
      case "get": {
        if (!args[0]) return log("usage: get <url>");
        try {
          const resp = await httpSend(`GET ${args[0]} HTTP/1.1\nHost: ${args[0].replace(/^https?:\/\//, "").split("/")[0]}\n\n`);
          log(`get: ${resp.status} · ${resp.size} bytes · ${resp.duration_ms} ms`);
        } catch (err) {
          log(`get failed: ${err instanceof Error ? err.message : String(err)}`);
        }
        return;
      }
      case "crack": {
        if (args.length < 3) return log("usage: crack <algo> <hash> <wordlist-path>");
        setBusy(true);
        log(`crack ${args[0]}: running authorized recovery…`);
        try {
          const result = await crackWordlistDialog(args[0], args[1], args[2]);
          log(`crack: ${result.tried} tried in ${result.duration_ms} ms · ${result.matches.length} match(es) · ${result.threads} threads`);
          if (result.matches.length > 0) log("  matches recovered; plaintext is withheld from the operation log");
        } catch (err) {
          log(`crack failed: ${err instanceof Error ? err.message : String(err)}`);
        } finally {
          if (currentCase.current === caseAtInvocation) setBusy(false);
        }
        return;
      }
      default:
        log(`unknown command: ${cmd} (try help)`);
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col bg-panel" role="region" aria-label={`CyberDeck command console ${terminalId.slice(9)}`}>
      <div className="min-h-0 flex-1 overflow-auto p-2 font-mono text-[11px] leading-relaxed">
        {lines.length === 0 ? (
          <div className="text-fg-muted">
            Type help for commands.
          </div>
        ) : (
          lines.map((line, i) => (
            <div key={i} className={line.startsWith(">") ? "text-fg" : "text-fg-dim"} style={{ whiteSpace: "pre-wrap" }}>
              {line}
            </div>
          ))
        )}
      </div>
      <div className="flex h-7 shrink-0 items-center gap-1 border-t border-line px-2">
        <span className="font-mono text-[11px] text-orange">$</span>
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !busy) {
              const value = input;
              setInput("");
              void runCommand(value).catch((error: unknown) => log(`Command failed: ${error instanceof Error ? error.message : String(error)}`));
            }
          }}
          aria-label={`Console ${terminalId.slice(9)} command input`}
          spellCheck={false}
          className="h-full flex-1 bg-transparent font-mono text-[11px] text-fg focus:outline-none"
          placeholder={busy ? "running…" : "type a command (help)"}
        />
      </div>
    </div>
  );
}
