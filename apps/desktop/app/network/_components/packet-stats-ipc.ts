/**
 * Typed IPC client for Wireshark-parity capture-wide statistics: the IO graph
 * (bounded ≤120 time buckets over the FULL native capture cache, not the 20k
 * shown-packet window) and the endpoint top-talkers table (IPv4/IPv6/MAC,
 * ≤64 rows by bytes, with Wireshark talker-convention in/out columns).
 *
 * Component-local client following the pcap-export-ipc.ts convention; these
 * wrappers mirror the Rust serde structs IoGraphWire / EndpointsWire in
 * src-tauri/src/features/network/ipc/pcap_wire.rs exactly. Defensive
 * projection only: counts, lengths and addresses — never packet bytes.
 */
import { invoke } from "@tauri-apps/api/core";
import { isDesktop } from "@lib/ipc";

/** One bounded time bucket (≤ 120 per graph) of the capture-wide IO graph. */
export interface IoBucketWire {
  /** Bucket start in ms relative to the first packet. */
  from_ms: number;
  packets: number;
  bytes: number;
  tcp_packets: number;
  udp_packets: number;
  other_packets: number;
}

export interface IoGraphWire {
  packet_count: number;
  bucket_count: number;
  bucket_width_ms: number;
  total_bytes: number;
  buckets: IoBucketWire[];
}

export interface EndpointRowWire {
  address: string;
  family: "ip4" | "ip6" | "mac";
  packets: number;
  bytes: number;
  /** Frames where the address is the source (Wireshark talker convention). */
  packets_out: number;
  bytes_out: number;
  packets_in: number;
  bytes_in: number;
}

export interface EndpointsWire {
  packet_count: number;
  endpoint_count: number;
  truncated: boolean;
  rows: EndpointRowWire[];
}

/** Capture-wide IO graph over the full open capture cache. */
export async function networkCaptureIoGraphV1(): Promise<IoGraphWire> {
  if (!isDesktop()) throw new Error("capture statistics require the desktop runtime");
  return invoke<IoGraphWire>("network_capture_io_graph_v1", {});
}

/** Capture-wide endpoint statistics over the full open capture cache. */
export async function networkCaptureEndpointsV1(): Promise<EndpointsWire> {
  if (!isDesktop()) throw new Error("capture statistics require the desktop runtime");
  return invoke<EndpointsWire>("network_capture_endpoints_v1", {});
}

/** Case-authorized verified IO graph over a saved original capture. */
export async function pcapCaseIoGraphV1(artifactId: string): Promise<IoGraphWire> {
  if (!isDesktop()) throw new Error("Saved capture statistics require desktop");
  return invoke<IoGraphWire>("pcap_case_io_graph_v1", { artifactId });
}

/** Case-authorized verified endpoint statistics over a saved original capture. */
export async function pcapCaseEndpointsV1(artifactId: string): Promise<EndpointsWire> {
  if (!isDesktop()) throw new Error("Saved capture statistics require desktop");
  return invoke<EndpointsWire>("pcap_case_endpoints_v1", { artifactId });
}
