"""MVC split: carve the four workspace view files into per-view modules."""
import io
import os

base = "apps/desktop/features"

CLIENT = '"use client";'
REACT_IMPORTS = 'import { useCallback, useEffect, useMemo, useRef, useState } from "react";'

def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    io.open(path, "w", encoding="utf-8", newline="\n").write(content)
    print("wrote", path)

# ---------------- crypto ----------------
p = f"{base}/crypto/view/CryptoWorkspace.tsx"
s = io.open(p, encoding="utf-8").read()

i_hash = s.index("// ---------------------------------------------------------- hash analysis ---")
i_ops = s.index("// -------------------------------------------------------------- crypto ops ---")

header = s[:i_hash]
hash_part = s[i_hash:i_ops]
ops_part = s[i_ops:]

# constants live in the header between dispatcher and recipes view
consts = "\nconst OP_MIME" 
ci = header.index("/** MIME type used by drag-and-drop between the catalog and the recipe. */")
consts_block = header[ci:header.index("export function CryptoWorkspace")]
header_no_consts = header[:ci] + header[header.index("export function CryptoWorkspace"):]

crypto_imports = f'''{CLIENT}
import {REACT_IMPORTS[7:]}
import {{ ArrowDown, ArrowUp, Copy, Play, Wand2, X }} from "lucide-react";
import {{ Chip, EmptyState, Field, Pane, Resizer, Select, TextInput, ToolButton }} from "@ds/panes";
import {{
  OPERATIONS,
  detectImageMime,
  magicRecipe,
  operationById,
  runRecipe,
  type OperationCategory,
  type RecipeState,
}} from "../model";
import {{
  addStep,
  clearRecipe,
  initialRecipeState,
  moveStep,
  moveStepTo,
  removeStep,
  setAutoBake,
  setInput,
  setStepParam,
  toggleStep,
}} from "../controller";
import {{ detectHashFormats }} from "../model/hash";
import {{
  b64,
  crackHistoryClear,
  crackHistoryDelete,
  crackHistoryList,
  crackMask,
  crackRulesDialog,
  crackWordlistDialog,
  cryptoOp,
  deviceInfo,
  enginesDetect,
  engineAttack,
  digestFileDialog,
  isDesktop,
  kdfVerify,
  pickWordlist,
  type AttackResultWire,
  type CrackEntryWire,
  type CrackProgressWire,
  type CrackResultWire,
  type DeviceInfoWire,
  type EngineAttackResultWire,
  type EngineStatusWire,
  type FileDigestsWire,
  type OpResult,
  type WordlistInfoWire,
}} from "@lib/ipc";
import type {{ ToolId }} from "@features/registry";
'''

write(f"{base}/crypto/view/RecipesView.tsx",
      crypto_imports + "\n" + consts_block.replace("/** MIME type used by drag-and-drop between the catalog and the recipe. */",
      "/** MIME types used by drag-and-drop between the catalog and the recipe. */") + "\n" + hash_part[:0] + header_no_consts.split("export function CryptoWorkspace")[0].split("/** MIME type used by drag-and-drop")[0].split("const CATEGORY_ORDER")[1] and "" or "")

# simpler: assemble explicitly
recipes_body = s[s.index("const CATEGORY_ORDER: OperationCategory[]"):i_hash]
write(f"{base}/crypto/view/RecipesView.tsx",
      crypto_imports + "\n// ---------------------------------------------------------------- recipes ---\n\n" + recipes_body)

hash_body = hash_part
write(f"{base}/crypto/view/HashAnalysisView.tsx",
      crypto_imports + "\n" + hash_body)

ops_body = ops_part
write(f"{base}/crypto/view/CryptoOpsView.tsx",
      crypto_imports + "\n" + ops_body)

dispatcher = f'''{CLIENT}
/** Thin dispatcher: all crypto tools stay mounted; hidden views keep state. */
import {{ HashAnalysisView }} from "./HashAnalysisView";
import {{ RecipesView }} from "./RecipesView";
import {{ CryptoOpsView }} from "./CryptoOpsView";
import type {{ ToolId }} from "@features/registry";

export function CryptoWorkspace({{ tool }}: {{ tool: ToolId }}) {{
  const show = (id: ToolId) => (tool === id ? "h-full" : "hidden h-full");
  return (
    <>
      <div className={{show("crypto.recipes")}}><RecipesView /></div>
      <div className={{show("crypto.hash")}}><HashAnalysisView /></div>
      <div className={{show("crypto.ops")}}><CryptoOpsView /></div>
    </>
  );
}}
'''
write(f"{base}/crypto/view/CryptoWorkspace.tsx", dispatcher)

# ---------------- network ----------------
p = f"{base}/network/view/NetworkWorkspace.tsx"
s = io.open(p, encoding="utf-8").read()
i_lab = s.index("// ------------------------------------------------------------ network lab ---")
i_scan = s.index("// ---------------------------------------------------------------- scanning ---")

network_imports = f'''{CLIENT}
import {{ useEffect, useMemo, useState }} from "react";
import {{ ChevronRight, FolderOpen, Play, ShieldAlert, Square }} from "lucide-react";
import {{ Chip, EmptyState, Pane, Select, TextInput, ToolButton }} from "@ds/panes";
import {{ hexDump }} from "@lib/hex";
import {{ isDesktop, pcapOpenDialog, pcapPacketBytes, type HexResponseWire, type PcapOpenWire, type PcapPacketWire }} from "@lib/ipc";
import {{ useWorkbench }} from "@state/workbench";
import type {{ ToolId }} from "@features/registry";
import {{
  PROTOCOL_COLORS,
  SAMPLE_HOSTS,
  SAMPLE_PACKETS,
  detailTree,
  sampleFrameBytes,
  type DetailNode,
}} from "../model";
'''

packet_body = s[s.index("type DisplayPacket"):i_lab]
lab_body = s[i_lab:i_scan]
scan_body = s[i_scan:]

write(f"{base}/network/view/PacketStudioView.tsx", network_imports + "\n" + packet_body)
write(f"{base}/network/view/NetworkLabView.tsx", network_imports + "\n" + lab_body)
write(f"{base}/network/view/ScanView.tsx", network_imports + "\n" + scan_body)

write(f"{base}/network/view/NetworkWorkspace.tsx", f'''{CLIENT}
/** Thin dispatcher: all network tools stay mounted; hidden views keep state. */
import {{ PacketStudioView }} from "./PacketStudioView";
import {{ NetworkLabView }} from "./NetworkLabView";
import {{ ScanView }} from "./ScanView";
import type {{ ToolId }} from "@features/registry";

export function NetworkWorkspace({{ tool }}: {{ tool: ToolId }}) {{
  const show = (id: ToolId) => (tool === id ? "h-full" : "hidden h-full");
  return (
    <>
      <div className={{show("network.packet")}}><PacketStudioView /></div>
      <div className={{show("network.lab")}}><NetworkLabView /></div>
      <div className={{show("network.scan")}}><ScanView /></div>
    </>
  );
}}
''')

# ---------------- forensics ----------------
p = f"{base}/forensics/view/ForensicsWorkspace.tsx"
s = io.open(p, encoding="utf-8").read()
i_files = s.index("function FileAnalysisView()")
i_meta = s.index("function MetadataView()")
i_strings = s.index("function StringsView()")
i_extract = s.index("function extractFromSample(")

forensics_imports = f'''{CLIENT}
import {{ useCallback, useEffect, useMemo, useState }} from "react";
import {{ Chip, Field, Pane, TextInput, ToolButton }} from "@ds/panes";
import {{ hexDump }} from "@lib/hex";
import {{
  fileHex,
  fileImportDialog,
  fileList,
  fileStrings,
  isDesktop,
  type ArtifactRecord,
  type HexResponseWire,
  type StringHitWire,
}} from "@lib/ipc";
import type {{ ToolId }} from "@features/registry";
import {{ extractStrings, formatEntropy, shannonEntropy }} from "../controller";
import {{ SAMPLE_EVIDENCE, sampleContent, sampleMetadata }} from "../model";
'''

shared_body = s[s.index("interface Selected {"):i_files]
files_body = s[i_files:i_meta]
meta_body = s[i_meta:i_strings]
strings_body = s[i_strings:]

write(f"{base}/forensics/view/shared.tsx", forensics_imports + "\n" + shared_body)
write(f"{base}/forensics/view/FileAnalysisView.tsx", forensics_imports + '\nimport { EvidenceTree, HexBody, useArtifactBytes, useEvidence } from "./shared";\n\n' + files_body)
write(f"{base}/forensics/view/MetadataView.tsx", forensics_imports + '\nimport { EvidenceTree, useEvidence } from "./shared";\n\n' + meta_body)
write(f"{base}/forensics/view/StringsView.tsx", forensics_imports + '\nimport { EvidenceTree, useEvidence } from "./shared";\n\n' + strings_body)

write(f"{base}/forensics/view/ForensicsWorkspace.tsx", f'''{CLIENT}
/** Thin dispatcher: all forensics tools stay mounted; hidden views keep state. */
import {{ FileAnalysisView }} from "./FileAnalysisView";
import {{ MetadataView }} from "./MetadataView";
import {{ StringsView }} from "./StringsView";
import type {{ ToolId }} from "@features/registry";

export function ForensicsWorkspace({{ tool }}: {{ tool: ToolId }}) {{
  const show = (id: ToolId) => (tool === id ? "h-full" : "hidden h-full");
  return (
    <>
      <div className={{show("forensics.files")}}><FileAnalysisView /></div>
      <div className={{show("forensics.metadata")}}><MetadataView /></div>
      <div className={{show("forensics.strings")}}><StringsView /></div>
    </>
  );
}}
''')

print("split done")
