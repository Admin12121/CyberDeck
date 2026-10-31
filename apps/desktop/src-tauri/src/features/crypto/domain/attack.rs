//! Stable serialized attack result types, independent of Tauri.
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct AttackMatch {
    pub line_no: u64,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct AttackResultWire {
    pub mode: String,
    pub algo: String,
    pub target_hash: String,
    pub source: String,
    pub tried: u64,
    pub generated: u64,
    pub cap_reached: bool,
    pub matches: Vec<AttackMatch>,
    pub duration_ms: u64,
    pub threads: usize,
    pub engine: String,
    pub engine_version: String,
}

#[derive(Debug, Serialize)]
pub struct BenchmarkWire {
    pub algo: String,
    pub hashes_per_second: f64,
    pub duration_ms: u64,
    pub threads: usize,
}

#[derive(Debug, Serialize)]
pub struct GpuDevice {
    pub name: String,
    pub driver_version: String,
    pub memory_total: String,
    pub compute_cap: String,
    pub backend: String,
    pub usable: bool,
}

#[derive(Debug, Serialize)]
pub struct DeviceInfoWire {
    pub cpu_arch: String,
    pub cpu_cores: usize,
    pub cpu_engine: String,
    pub gpu_devices: Vec<GpuDevice>,
    pub planner_note: String,
}
