import type { RecoveryBackendV1, RecoveryDeviceInventoryV1 } from "@lib/ipc";

export const DEFAULT_CANDIDATES = 100_000;
export const DEFAULT_MATCHES = 1;
export const DEFAULT_OPENCL_BATCH = 4096;

/**
 * Auto never assumes that device enumeration proves working kernels.
 * Only independently verified, enumerated OpenCL devices qualify;
 * otherwise run CPU. An explicit OpenCL override is not silently
 * downgraded to CPU; the native backend validates its availability.
 */
export function chooseRecoveryBackend(
  choice: string,
  inventory: RecoveryDeviceInventoryV1 | null,
  batchSize = DEFAULT_OPENCL_BATCH,
  algorithm = "sha256",
): RecoveryBackendV1 {
  if (choice === "auto") {
    // Native OpenCL recovery only implements SHA-256 today. Preserve CPU for
    // all other digests even when an independently verified GPU is present.
    if (algorithm !== "sha256") return { backend: "cpu" };
    const verified = inventory?.devices.find((device) => device.hardware_verified);
    return verified && inventory?.opencl_detected
      ? { backend: "open_cl", device_index: verified.device_index, batch_size: batchSize }
      : { backend: "cpu" };
  }
  if (choice === "cpu") return { backend: "cpu" };
  if (/^open_cl:\d+$/.test(choice)) {
    return { backend: "open_cl", device_index: Number(choice.slice(8)), batch_size: batchSize };
  }
  throw new Error("Invalid recovery backend selection");
}
