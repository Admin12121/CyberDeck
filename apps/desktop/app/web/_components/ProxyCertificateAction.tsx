"use client";

import { useState } from "react";
import { Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { downloadContent } from "@lib/download";
import { isDesktop, proxyCaPem } from "@lib/ipc";

/** A single CA export action owned by the Web workspace toolbar, never by a tool card. */
export function ProxyCertificateAction() {
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const desktop = isDesktop();

  const downloadCa = async () => {
    if (!desktop || exporting) return;
    setExporting(true);
    setError(null);
    try {
      const pem = await proxyCaPem();
      downloadContent(pem, "cyberdeck-root-ca.crt", "application/x-x509-ca-cert");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="flex items-center gap-2">
      {error && (
        <span role="alert" className="max-w-48 truncate text-xs text-err" title={error}>
          CA export failed
        </span>
      )}
      <Button type="button" size="icon-sm" variant="ghost"
        aria-label="Download proxy CA certificate"
        title={desktop ? "Download CyberDeck proxy CA certificate" : "Requires the desktop application"}
        disabled={!desktop || exporting} onClick={() => void downloadCa()}>
        <Download size={16} />
      </Button>
    </div>
  );
}
