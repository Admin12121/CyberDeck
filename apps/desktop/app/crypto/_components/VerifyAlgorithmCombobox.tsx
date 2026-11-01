"use client";

import {
  Combobox, ComboboxInput, ComboboxPopup, ComboboxList,
  ComboboxItem, ComboboxEmpty, ComboboxCollection,
} from "@/components/ui/combobox";

export const VERIFY_ALGORITHMS = [
  { id: "md4", label: "MD4", hexLength: 32 },
  { id: "md5", label: "MD5", hexLength: 32 },
  { id: "ntlm", label: "NTLM", hexLength: 32 },
  { id: "sha1", label: "SHA-1", hexLength: 40 },
  { id: "sha224", label: "SHA-224", hexLength: 56 },
  { id: "sha256", label: "SHA-256", hexLength: 64 },
  { id: "sha384", label: "SHA-384", hexLength: 96 },
  { id: "sha512", label: "SHA-512", hexLength: 128 },
  { id: "sha3_256", label: "SHA3-256", hexLength: 64 },
  { id: "sha3_512", label: "SHA3-512", hexLength: 128 },
  { id: "crc32", label: "CRC32", hexLength: 8 },
] as const;

export type VerifyAlgorithmId = (typeof VERIFY_ALGORITHMS)[number]["id"];

export function VerifyAlgorithmCombobox({
  value, onChange,
}: {
  value: VerifyAlgorithmId;
  onChange: (value: VerifyAlgorithmId) => void;
}) {
  const labels = VERIFY_ALGORITHMS.map((entry) => entry.label);
  const selected = VERIFY_ALGORITHMS.find((entry) => entry.id === value)?.label ?? "SHA-256";

  return (
    <Combobox items={labels} value={selected}
      onValueChange={(label) => {
        const match = VERIFY_ALGORITHMS.find((entry) => entry.label === label);
        if (match) onChange(match.id);
      }}>
      <ComboboxInput size="sm" aria-label="Search verification algorithms"
        placeholder="Search algorithms" className="w-full" />
      <ComboboxPopup align="start" className="min-w-56">
        <ComboboxEmpty>No matching algorithm</ComboboxEmpty>
        <ComboboxList>
          <ComboboxCollection>
            {(label) => <ComboboxItem key={label} value={label}>{label}</ComboboxItem>}
          </ComboboxCollection>
        </ComboboxList>
      </ComboboxPopup>
    </Combobox>
  );
}
