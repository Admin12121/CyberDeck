"use client";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Chip, Field, Pane, TextInput, ToolButton } from "@ds/panes";
import { hexDump } from "@lib/hex";
import {
  fileHex,
  fileImportDialog,
  fileList,
  fileStrings,
  isDesktop,
  type ArtifactRecord,
  type HexResponseWire,
  type StringHitWire,
} from "@lib/ipc";
import type { ToolId } from "@features/registry";
import { extractStrings, formatEntropy, shannonEntropy } from "../controller";
import { SAMPLE_EVIDENCE, sampleContent, sampleMetadata } from "../model";

import { EvidenceTree, useEvidence } from "./shared";

export function MetadataView() {
  const ctx = useEvidence();
  return (
    <div className="flex h-full min-h-0 gap-px bg-line">
      <EvidenceTree ctx={ctx} />
      <Pane title={`Metadata: ${ctx.selectedArtifact?.name ?? ctx.selectedSample?.name ?? "no selection"}`} className="min-w-0 flex-1">
        {ctx.selectedArtifact ? (
          <table className="data-table">
            <thead>
              <tr>
                <th className="w-32">Key</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              <tr><td className="text-fg">sha256</td><td className="text-fg-dim">{ctx.selectedArtifact.sha256}</td></tr>
              <tr><td className="text-fg">md5</td><td className="text-fg-dim">{ctx.selectedArtifact.md5}</td></tr>
              <tr><td className="text-fg">sha1</td><td className="text-fg-dim">{ctx.selectedArtifact.sha1}</td></tr>
              <tr><td className="text-fg">crc32</td><td className="text-fg-dim">{ctx.selectedArtifact.crc32}</td></tr>
              <tr><td className="text-fg">signature</td><td className="text-fg-dim">{ctx.selectedArtifact.signature ?? "unrecognized"}</td></tr>
              <tr><td className="text-fg">size</td><td className="text-fg-dim">{ctx.selectedArtifact.size} bytes</td></tr>
              <tr><td className="text-fg">entropy</td><td className="text-fg-dim">{formatEntropy(ctx.selectedArtifact.entropy)}</td></tr>
              <tr><td className="text-fg">imported</td><td className="text-fg-dim">{new Date(Number(ctx.selectedArtifact.imported_at)).toLocaleString()}</td></tr>
            </tbody>
          </table>
        ) : ctx.selectedSample ? (
          <table className="data-table">
            <thead>
              <tr>
                <th className="w-32">Key</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              {sampleMetadata(ctx.selectedSample).map((row) => (
                <tr key={row.key}>
                  <td className="text-fg">{row.key}</td>
                  <td className="text-fg-dim">{row.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <div className="p-3 font-mono text-[11px] text-fg-muted">select evidence to inspect</div>
        )}
      </Pane>
    </div>
  );
}

