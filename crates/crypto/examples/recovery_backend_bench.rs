//! Reproducible end-to-end CPU / selected-OpenCL recovery benchmark.
//! Exercises the native service intended for future Tauri IPC, without
//! passwords, persistence, real files or loading a synthetic wordlist.
//! cargo run --release -p cyberdeck-crypto --example recovery_backend_bench --
//!   --backend cpu|opencl --attempts 100000 --repeats 3 --device 0
use cyberdeck_crypto::recovery::{
    recover_sha256_wordlist_on_backend, RecoveryBackend, RecoveryLimits,
};
use std::io::{self, BufReader, Read};
use std::time::Instant;

fn item(index: u64) -> String {
    format!("cyberdeck-{index:012x}")
}

/// Generates a deterministic newline-delimited wordlist as the reader asks
/// for bytes. No allocation proportional to the selected keyspace.
struct SyntheticWordlist {
    produced: u64,
    total: u64,
    current: Vec<u8>,
    offset: usize,
}

impl SyntheticWordlist {
    fn new(total: u64) -> Self {
        Self {
            produced: 0,
            total,
            current: Vec::new(),
            offset: 0,
        }
    }
}
impl Read for SyntheticWordlist {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let mut written = 0;
        while written < buffer.len() {
            if self.offset == self.current.len() {
                if self.produced >= self.total {
                    break;
                }
                self.current = format!("{}\n", item(self.produced)).into_bytes();
                self.produced += 1;
                self.offset = 0;
            }
            let count = (buffer.len() - written).min(self.current.len() - self.offset);
            buffer[written..written + count]
                .copy_from_slice(&self.current[self.offset..self.offset + count]);
            written += count;
            self.offset += count;
        }
        Ok(written)
    }
}

fn run() -> Result<(), String> {
    let mut backend = String::from("cpu");
    let mut attempts = 100_000u64;
    let mut repeats = 3usize;
    let mut device = 0usize;
    let mut batch_size = 4096usize;
    let mut probe_only = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--backend" => backend = args.next().ok_or("missing backend")?,
            "--attempts" => {
                attempts = args
                    .next()
                    .ok_or("missing attempts")?
                    .parse()
                    .map_err(|_| "invalid attempts")?
            }
            "--repeats" => {
                repeats = args
                    .next()
                    .ok_or("missing repeats")?
                    .parse()
                    .map_err(|_| "invalid repeats")?
            }
            "--device" => {
                device = args
                    .next()
                    .ok_or("missing device")?
                    .parse()
                    .map_err(|_| "invalid device")?
            }
            "--batch-size" => {
                batch_size = args
                    .next()
                    .ok_or("missing batch size")?
                    .parse()
                    .map_err(|_| "invalid batch size")?
            }
            "--probe" => probe_only = true,
            "--help" | "-h" => {
                println!("--probe | --backend cpu|opencl --attempts N --repeats N --device INDEX --batch-size N");
                return Ok(());
            }
            _ => return Err(format!("unknown argument: {arg}")),
        }
    }
    if attempts == 0 || attempts > 1_000_000 || !(1..=5).contains(&repeats) {
        return Err("attempts must be 1..=1000000; repeats 1..=5".into());
    }
    let selected = match backend.as_str() {
        "cpu" => RecoveryBackend::Cpu,
        "opencl" => RecoveryBackend::OpenCl {
            device_index: device,
            batch_size,
        },
        _ => return Err("backend must be cpu or opencl".into()),
    };
    if probe_only || backend == "opencl" {
        let probe = cyberdeck_crypto::gpu::probe();
        eprintln!("OpenCL available={} | {}", probe.available, probe.detail);
        for (i, device) in probe.devices.iter().enumerate() {
            eprintln!(
                "GPU [{i}]: {} / {} / {}",
                device.name, device.vendor, device.driver
            );
        }
        if probe_only {
            return Ok(());
        }
        if !probe.available {
            return Err("no physical OpenCL GPU is available; no hardware benchmark ran".into());
        }
        if device >= probe.devices.len() {
            return Err("selected GPU device index is unavailable".into());
        }
    }
    let known = item(attempts - 1);
    let digest = hex::encode(cyberdeck_crypto::apply_op(
        "sha256",
        known.as_bytes(),
        None,
    )?);
    println!("backend,device_index,batch_size,trial,attempts,wall_ms,verified_per_second");
    for trial in 1..=repeats {
        let source = BufReader::with_capacity(8192, SyntheticWordlist::new(attempts));
        let started = Instant::now();
        let mut last_progress = 0u64;
        let result = recover_sha256_wordlist_on_backend(
            selected,
            &digest,
            source,
            RecoveryLimits {
                max_candidates: attempts,
                max_matches: 1,
            },
            || false,
            |progress| {
                assert!(progress.tried >= last_progress);
                last_progress = progress.tried;
            },
        )?;
        let seconds = started.elapsed().as_secs_f64();
        if result.tried != attempts
            || result.hits.len() != 1
            || result.hits[0].index != attempts - 1
            || result.hits[0].candidate != known.as_bytes()
            || result.cancelled
            || last_progress != attempts
        {
            return Err(format!(
                "{backend} trial {trial} failed known-answer verification"
            ));
        }
        println!(
            "{backend},{device},{batch_size},{trial},{attempts},{:.3},{:.0}",
            seconds * 1000.0,
            attempts as f64 / seconds
        );
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("recovery_backend_bench: {error}");
        std::process::exit(1);
    }
}
