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

import { EvidenceTree, HexBody, useArtifactBytes, useEvidence } from "./shared";

export function FileAnalysisView() {
  const ctx = useEvidence();
  const highEntropy =
    ctx.selectedArtifact
      ? ctx.selectedArtifact.entropy > 7.5
      : ctx.selectedSample
        ? shannonEntropy(sampleContent(ctx.selectedSample.id)) > 7.5
        : false;

  return (
    <div className="flex h-full min-h-0 gap-px bg-line">
      <EvidenceTree ctx={ctx} />
      <Pane title={`Hex: ${ctx.selectedArtifact?.name ?? ctx.selectedSample?.name ?? "no selection"}`} className="min-w-0 flex-1" bodyClassName="relative">
        <HexBody ctx={ctx} />
      </Pane>
      <Pane title="Inspector" className="w-80 shrink-0">
        {ctx.selectedArtifact ? (
          <>
            <Field label="sha256" value={<span className="break-all">{ctx.selectedArtifact.sha256}</span>} />
            <Field label="md5" value={ctx.selectedArtifact.md5} />
            <Field label="sha1" value={ctx.selectedArtifact.sha1} />
            <Field label="crc32" value={ctx.selectedArtifact.crc32} />
            <Field label="signature" value={ctx.selectedArtifact.signature ?? "unrecognized"} />
            <Field label="size" value={`${ctx.selectedArtifact.size} bytes`} />
            <Field label="entropy" value={formatEntropy(ctx.selectedArtifact.entropy)} />
            <Field label="imported" value={new Date(Number(ctx.selectedArtifact.imported_at)).toLocaleString()} />
            <Field label="original path" value={ctx.selectedArtifact.original_path ?? "n/a"} />
            <Field label="case" value={ctx.selectedArtifact.case_id} />
          </>
        ) : ctx.selectedSample ? (
          sampleMetadata(ctx.selectedSample).map((row) => <Field key={row.key} label={row.key} value={row.value} />)
        ) : (
          <div className="p-3 font-mono text-[11px] text-fg-muted">select evidence to inspect</div>
        )}
        {highEntropy ? (
          <div className="px-3 py-1.5">
            <Chip tone="orange">high entropy; compressed or encrypted?</Chip>
          </div>
        ) : null}
        <div className="border-t border-line p-2">
          <ToolButton disabled title="Extraction with path safety and decompression-bomb guards, arc 3">Extract…</ToolButton>
          <div className="mt-1" />
          <ToolButton disabled title="YARA-X rules, arc 3">YARA scan</ToolButton>
        </div>
      </Pane>
    </div>
  );
}

