//! Read-only device inventory adapter for the legacy desktop GPU indicator.
//! Does not claim this Tauri attack path has been wired to the native OpenCL core.
use super::attack_domain::GpuDevice;

pub fn detect_gpus() -> Vec<GpuDevice> {
    let mut command = std::process::Command::new("nvidia-smi");
    command.args([
        "--query-gpu=name,driver_version,memory.total,compute_cap",
        "--format=csv,noheader",
    ]);
    // Use the same bounded, concurrently drained process runner as engine
    // adapters so a broken driver command cannot hang the desktop indefinitely.
    let output = crate::engines::process::run_with_timeout(
        command,
        std::time::Duration::from_secs(3),
    );
    match output {
        Ok((status, stdout, _)) if status.success() =>
            String::from_utf8_lossy(&stdout)
                .lines()
                .filter(|line| !line.trim().is_empty())
                .map(|line| {
                    let fields: Vec<_> = line.split(',').map(str::trim).collect();
                    GpuDevice {
                        name: fields.first().copied().unwrap_or_default().to_owned(),
                        driver_version: fields.get(1).copied().unwrap_or("n/a").to_owned(),
                        memory_total: fields.get(2).copied().unwrap_or("n/a").to_owned(),
                        compute_cap: fields.get(3).copied().unwrap_or("n/a").to_owned(),
                        backend: "NVIDIA hardware detected; native OpenCL recovery is not connected to this desktop command".into(),
                        usable: false,
                    }
                })
                .collect(),
        _ => Vec::new(),
    }
}
