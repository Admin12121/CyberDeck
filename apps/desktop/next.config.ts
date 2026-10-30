import type { NextConfig } from "next";

// Desktop static-export configuration (Master Plan §2.2):
// Tauri loads ./out; no server rendering, no API routes, no Node server deps.
const nextConfig: NextConfig = {
  output: "export",
  images: { unoptimized: true },
};

export default nextConfig;
