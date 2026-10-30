import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "HackTool — Cybersecurity Workbench",
  description:
    "Integrated desktop workbench: packet analysis, web security, scanning, crypto recipes, hash analysis, forensics.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" data-theme="darkmatter">
      <body>{children}</body>
    </html>
  );
}
