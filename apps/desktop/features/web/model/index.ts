/**
 * Web feature — model layer.
 * Sample site tree + proxy history for the Burp/ZAP-style workspace (§5.2).
 * The live proxy listener, interception queue and ZAP engine arrive arc 4.
 */

export interface HistoryRow {
  id: number;
  method: "GET" | "POST" | "PUT" | "DELETE";
  host: string;
  path: string;
  status: number;
  length: number;
  timeMs: number;
  note?: string;
}

export interface SiteNode {
  name: string;
  children?: SiteNode[];
}

export const SAMPLE_SITES: SiteNode = {
  name: "lab.example.test",
  children: [
    {
      name: "/api",
      children: [
        { name: "/products", children: [{ name: "GET 200" }, { name: "POST 201" }] },
        { name: "/auth", children: [{ name: "POST 200" }, { name: "POST 401" }] },
      ],
    },
    { name: "/assets", children: [{ name: "GET 200" }, { name: "GET 304" }] },
    { name: "/", children: [{ name: "GET 200" }] },
  ],
};

export const SAMPLE_HISTORY: HistoryRow[] = [
  { id: 1, method: "GET", host: "lab.example.test", path: "/", status: 200, length: 2140, timeMs: 41 },
  { id: 2, method: "GET", host: "lab.example.test", path: "/assets/app.js", status: 200, length: 88012, timeMs: 12 },
  { id: 3, method: "GET", host: "lab.example.test", path: "/api/products", status: 200, length: 4096, timeMs: 18, note: "session cookie echoed" },
  { id: 4, method: "POST", host: "lab.example.test", path: "/api/auth", status: 200, length: 132, timeMs: 64 },
  { id: 5, method: "POST", host: "lab.example.test", path: "/api/auth", status: 401, length: 89, timeMs: 58, note: "invalid credentials — lab fixture" },
  { id: 6, method: "GET", host: "lab.example.test", path: "/api/products?page=2", status: 200, length: 4018, timeMs: 16 },
];

export function statusTone(status: number): string {
  if (status >= 500) return "text-err";
  if (status >= 400) return "text-orange";
  if (status >= 300) return "text-warn";
  if (status >= 200) return "text-ok";
  return "text-fg-muted";
}

export function methodTone(method: string): string {
  switch (method) {
    case "GET":
      return "text-blue";
    case "POST":
      return "text-orange";
    case "PUT":
      return "text-warn";
    default:
      return "text-err";
  }
}

export const SAMPLE_REQUEST = `GET /api/products HTTP/1.1\r\nHost: lab.example.test\r\nUser-Agent: HackTool-Workbench/0.1\r\nAccept: application/json\r\nCookie: session=lab-fixture\r\n\r\n`;

export const SAMPLE_RESPONSE = `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4096\r\nX-Lab-Note: controlled demo service\r\n\r\n{"products":[{"id":1,"name":"widget"}]}`;
