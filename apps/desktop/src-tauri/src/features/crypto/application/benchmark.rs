//! CPU digest benchmark and conservative desktop device capability reporting.
use std::time::{Duration, Instant};

use super::attack_domain::{BenchmarkWire, DeviceInfoWire};

pub fn benchmark(algo: String, duration_ms: Option<u64>) -> Result<BenchmarkWire, String> {
    if cyberdeck_crypto::kdf_format(&algo).is_some() {
        return Err("KDF formats are deliberately slow; benchmark a digest instead".into());
    }
    cyberdeck_crypto::apply_op(&algo, b"bench", None)?;
    let budget = Duration::from_millis(duration_ms.unwrap_or(2000).clamp(200, 10_000));
    let started = Instant::now();
    let mut count = 0u64;
    let mut input = *b"benchmark-input-0000";
    while started.elapsed() < budget {
        for i in 0..1000u32 {
            input[16..20].copy_from_slice(&i.to_be_bytes());
            cyberdeck_crypto::apply_op(&algo, &input, None)?;
            count += 1;
        }
    }
    let elapsed = started.elapsed();
    Ok(BenchmarkWire {
        algo,
        hashes_per_second: count as f64 / elapsed.as_secs_f64(),
        duration_ms: elapsed.as_millis() as u64,
        threads: 1,
    })
}

pub fn device_info() -> DeviceInfoWire {
    let cpu_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let gpu_devices = super::gpu_discovery::detect_gpus();
    let planner_note = if gpu_devices.is_empty() {
        "No NVIDIA GPU detected by the legacy command. Native OpenCL device selection is available in the crypto crate, but not yet wired into this desktop command."
    } else {
        "GPU hardware detected. Native OpenCL recovery exists in the crypto crate but is not yet connected to desktop attacks; hashcat remains a separate adapter."
    };
    DeviceInfoWire {
        cpu_arch: std::env::consts::ARCH.to_owned(),
        cpu_cores,
        cpu_engine: "cyberdeck-crypto (rust)".into(),
        gpu_devices,
        planner_note: planner_note.into(),
    }
}
