import type { Metadata } from "next";
import "./globals.css";
import { AppShell } from "@shell/AppShell";

export const metadata: Metadata = {
  title: "CyberDeck: Cybersecurity Workbench",
  description:
    "Integrated desktop workbench: packet analysis, web security, scanning, crypto recipes, hash analysis, forensics.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark" suppressHydrationWarning>
      <body><AppShell>{children}</AppShell></body>
    </html>
  );
}
