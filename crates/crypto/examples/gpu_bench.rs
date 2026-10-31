//! End-to-end verified native OpenCL GPU benchmark with synthetic known answers.
//! cargo run --release -p cyberdeck-crypto --example gpu_bench -- --attempts 100000 --repeats 3
use cyberdeck_crypto::gpu::{
    self, GpuHash, GpuStreamResult, GPU_STREAM_BATCH, MAX_GPU_BATCH, MAX_GPU_STREAM_CANDIDATES,
};
use md4::{Digest as _, Md4};
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::time::Instant;
fn item(i: u64) -> Vec<u8> {
    format!("cyberdeck-{i:012x}").into_bytes()
}
fn stream(n: u64) -> impl Iterator<Item = Vec<u8>> {
    (0..n).map(item)
}
fn run_algo(
    kind: &str,
    n: u64,
    repeats: usize,
    device_index: usize,
    batch_size: usize,
) -> Result<(), String> {
    let expected = item(n - 1);
    let hash = |bytes: &[u8]| -> Vec<u8> {
        match kind {
            "md5" => Md5::digest(bytes).to_vec(),
            "sha1" => Sha1::digest(bytes).to_vec(),
            "ntlm" => {
                let mut utf16le = Vec::with_capacity(bytes.len() * 2);
                for byte in bytes {
                    utf16le.extend_from_slice(&[*byte, 0]);
                }
                Md4::digest(&utf16le).to_vec()
            }
            _ => Sha256::digest(bytes).to_vec(),
        }
    };
    let algorithm = match kind {
        "md5" => GpuHash::Md5,
        "sha1" => GpuHash::Sha1,
        "ntlm" => GpuHash::Ntlm,
        _ => GpuHash::Sha256,
    };
    let recover = |target: &str, len: u64| -> Result<GpuStreamResult, String> {
        gpu::recover_stream_on_device_with_batch(
            algorithm,
            device_index,
            batch_size,
            target,
            stream(len),
            len,
            1,
            || false,
        )
    };
    let warm = n.min(4096);
    let warm_digest = hex::encode(hash(&item(warm - 1)));
    let warm_result = recover(&warm_digest, warm)?;
    if warm_result.hits.len() != 1 || warm_result.hits[0].index != warm - 1 {
        return Err(format!("{kind}: warmup verification failed"));
    }
    let target = hex::encode(hash(&expected));
    for trial in 1..=repeats {
        let start = Instant::now();
        let result = recover(&target, n)?;
        let elapsed = start.elapsed().as_secs_f64();
        if result.tried != n
            || result.hits.len() != 1
            || result.hits[0].index != n - 1
            || result.hits[0].candidate != expected
            || result.cancelled
        {
            return Err(format!("{kind}: invalid GPU result in trial {trial}"));
        }
        println!(
            "{device_index},{batch_size},{kind},{trial},{n},{},{:.3},{:.0}",
            result.batches,
            elapsed * 1000.0,
            n as f64 / elapsed
        );
    }
    Ok(())
}
fn execute() -> Result<(), String> {
    let mut attempts = 100_000u64;
    let mut repeats = 3usize;
    let mut algorithm = String::from("all");
    let mut probe_only = false;
    // None selects every physical OpenCL GPU discovered by probe().
    let mut device_index: Option<usize> = Some(0);
    let mut batch_size = GPU_STREAM_BATCH;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--attempts" => {
                attempts = args
                    .next()
                    .ok_or("missing --attempts")?
                    .parse()
                    .map_err(|_| "invalid --attempts")?
            }
            "--repeats" => {
                repeats = args
                    .next()
                    .ok_or("missing --repeats")?
                    .parse()
                    .map_err(|_| "invalid --repeats")?
            }
            "--algorithm" => algorithm = args.next().ok_or("missing --algorithm")?,
            "--device" => {
                let value = args.next().ok_or("missing --device")?;
                device_index = if value == "all" {
                    None
                } else {
                    Some(value.parse().map_err(|_| "invalid --device index")?)
                };
            }
            "--batch-size" => {
                batch_size = args
                    .next()
                    .ok_or("missing --batch-size")?
                    .parse()
                    .map_err(|_| "invalid --batch-size")?
            }
            "--probe" => probe_only = true,
            "--help" | "-h" => {
                println!("--probe | --device INDEX|all --batch-size N --algorithm sha256|md5|sha1|ntlm|all --attempts N --repeats N");
                return Ok(());
            }
            _ => return Err(format!("unknown option {arg}")),
        }
    }
    if attempts == 0 || attempts > MAX_GPU_STREAM_CANDIDATES || repeats == 0 || repeats > 10 {
        return Err("attempts must be 1..=10000000 and repeats 1..=10".into());
    }
    let devices = gpu::probe();
    eprintln!(
        "OpenCL available={} | {}",
        devices.available, devices.detail
    );
    for (index, d) in devices.devices.iter().enumerate() {
        eprintln!("GPU [{index}]: {} / {} / {}", d.name, d.vendor, d.driver);
    }
    if probe_only {
        return Ok(());
    }
    if !devices.available {
        return Err(
            "No physical OpenCL GPU detected. Install vendor drivers and run on host".into(),
        );
    }
    if batch_size == 0 || batch_size > MAX_GPU_BATCH {
        return Err(format!("--batch-size must be in 1..={MAX_GPU_BATCH}"));
    }
    if let Some(index) = device_index {
        if index >= devices.devices.len() {
            return Err(format!(
                "GPU device index {index} out of range; {} OpenCL GPU(s) detected",
                devices.devices.len()
            ));
        }
    }
    let algos: &[&str] = match algorithm.as_str() {
        "all" => &["sha256", "md5", "sha1", "ntlm"],
        "sha256" => &["sha256"],
        "md5" => &["md5"],
        "sha1" => &["sha1"],
        "ntlm" => &["ntlm"],
        _ => return Err("unknown algorithm".into()),
    };
    println!("device_index,batch_size,algorithm,trial,attempts,batches,wall_ms,attempts_per_sec");
    let selected: Vec<usize> = match device_index {
        Some(index) => vec![index],
        None => (0..devices.devices.len()).collect(),
    };
    for index in selected {
        for algo in algos {
            run_algo(algo, attempts, repeats, index, batch_size)?;
        }
    }
    Ok(())
}
fn main() {
    if let Err(e) = execute() {
        eprintln!("gpu_bench: {e}");
        std::process::exit(1)
    }
}
