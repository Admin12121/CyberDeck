import assert from "node:assert/strict";
import { test } from "node:test";
import fs from "node:fs";
import path from "node:path";

const root = import.meta.dirname;
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");
const repoRead = (file) => fs.readFileSync(path.join(root, "../../../../../", file), "utf8");

test("macOS routes into the normal native capture setup flow, not the unsupported path", () => {
  const live = read("LiveCaptureView.tsx");
  // macOS is a first-class native platform state in this view.
  assert.match(live, /nativePlatform === "macos"/);
  assert.match(live, /const macosHost = nativePlatform === "macos";/);
  // Interface listing, eligibility and Start use the shared native flow.
  assert.match(live, /captureInterfacesV1\(/);
  assert.match(live, /captureStartV1\(/);
  // The Windows-only "not operational" notice must stay Windows-scoped.
  assert.match(live, /windowsHost && eligible\.length === 0/);
  assert.doesNotMatch(live, /macosHost && eligible\.length === 0/);
});

test("macOS setup shows a privileges notice chip with honest BPF wording", () => {
  const live = read("LiveCaptureView.tsx");
  assert.match(live, /macosHost && \(/);
  assert.match(live, /<Chip tone="orange">BPF privileges required<\/Chip>/);
  // The chip explains that /dev/bpf* access is gated at Start, without
  // promising privileges the process may not have.
  assert.match(
    live,
    /Start requires root privileges or read\/write access to \/dev\/bpf\*/i,
  );
  // The permissions info affordance covers macOS BPF as well.
  assert.match(live, /macOS native capture requires BPF \(\/dev\/bpf\*\) access/);
  assert.match(live, /macOS requires BPF device privileges/);
});

test("macOS capability reporting is supported-with-privileges, not unsupported", () => {
  const captureIpc = repoRead("apps/desktop/src-tauri/src/features/network/ipc/capture.rs");
  // Capabilities: backend present, privileges message, still no raw probes.
  assert.match(captureIpc, /#\[cfg\(target_os = "macos"\)\]/);
  assert.match(captureIpc, /capture_backend_present: true/);
  assert.match(
    captureIpc,
    /requires BPF access — run with appropriate privileges/,
  );
  // Interface discovery must not fail-closed on macOS anymore.
  const macosBlock = captureIpc.split("#[cfg(target_os = \"macos\")]")[1] ?? "";
  assert.ok(macosBlock.length > 0, "macOS cfg blocks exist in the capture IPC");
  // The unsupported fallback excludes macOS now.
  assert.match(
    captureIpc,
    /#\[cfg\(not\(any\(target_os = "windows", target_os = "linux", target_os = "macos"\)\)\)\]/,
  );
});

test("macOS BPF backend owns device acquisition, ioctl sequence and honest privilege errors", () => {
  const backend = repoRead("crates/packet/src/infrastructure/bpf_capture.rs");
  // Zero-dependency FFI surface (std links libc on macOS).
  assert.match(backend, /unsafe extern "C"/);
  assert.match(backend, /fn getifaddrs/);
  assert.match(backend, /fn ioctl/);
  assert.match(backend, /fn poll/);
  // Full libpcap-equivalent configuration sequence.
  for (const ioctl of ["BIOCSBLEN", "BIOCSETIF", "BIOCGDLT", "BIOCIMMEDIATE", "FIONREAD"]) {
    assert.match(backend, new RegExp(ioctl));
  }
  // Ethernet-only enforcement and bounded probing.
  assert.match(backend, /DLT_EN10MB/);
  assert.match(backend, /BPF_DEVICE_PROBE_LIMIT/);
  // Privilege failures keep a structured, macOS-honest error code.
  assert.match(backend, /CaptureErrorCode::PermissionDenied/);
  assert.match(backend, /access_bpf/);
  // The kernel record parser is defensive and unit-tested in-module.
  assert.match(backend, /fn step_kernel_record/);
  assert.match(backend, /zero_hdrlen_and_short_hdrlen_records_are_rejected/);
  assert.match(backend, /mod tests/);
});

test("live.rs routes macOS discovery and capture through the BPF backend", () => {
  const live = repoRead("crates/packet/src/live.rs");
  assert.match(
    live,
    /crate::infrastructure::bpf_capture::discover_interfaces\(\)/,
  );
  assert.match(
    live,
    /capture_macos_with_progress_filtered\(|crate::infrastructure::bpf_capture::capture_with_progress_filtered\(/,
  );
  // The platform catch-all no longer claims macOS is unsupported.
  assert.match(live, /not\(any\(target_os = "linux", target_os = "macos"\)\)/);
  assert.doesNotMatch(live, /macOS BPF not implemented/);
});
