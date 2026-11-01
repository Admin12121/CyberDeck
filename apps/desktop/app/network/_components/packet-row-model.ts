import type { CaptureFrameProvenanceV1 } from "@lib/ipc";
import type { PacketTableRow } from "./PacketTable";

/** Native Capture V1 exposes original-frame provenance, not decoded protocols or timestamps. */
export function nativeCapturePacketRow(frame: CaptureFrameProvenanceV1): PacketTableRow {
  return {
    index: frame.packet_index,
    source: frame.source,
    destination: frame.destination,
    length: frame.captured_length,
    info: frame.stream_id
      ? "Flow: " + frame.stream_id
      : "Original frame · PCAP offset " + frame.pcap_frame_offset,
    // Do not synthesize time or a protocol from the presence of source/destination.
    protocol: null,
  };
}
