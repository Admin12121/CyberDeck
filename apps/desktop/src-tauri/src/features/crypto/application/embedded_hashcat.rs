//! Supervised, opt-in Hashcat source-compiled worker. Case and job identity
//! remain owned by RecoveryCtx. No external installed hashcat process.
//! All confidential outputs reside in a restrictive, temporary directory.
use super::recovery_backend::{
    self, RecoveryCancel, RecoveryProgressWire, RecoveryRequest, RecoveryRun,
};
use cyberdeck_crypto::recovery::{RecoveryTarget, MAX_FAST_CANDIDATES};
#[path = "embedded_hashcat_preset.rs"]
mod preset;
pub use preset::WordlistPreset;

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

#[cfg(test)]
const MAGIC: &[u8; 8] = b"CDHC0001";
const MAX_PRIVATE_OUTPUT: u64 = 1 << 20;
const HARD_DEADLINE: Duration = Duration::from_secs(315);
/// Per-session candidate cap, mirroring the worker protocol's own bound.
/// Chunked sessions never exceed this; only the session COUNT grows.
const WORKER_SESSION_CANDIDATES: u64 = 1_000_000;

/// Safe, stable diagnostics for a sealed child process. Never include the
/// worker's stdout/stderr because upstream libraries may print target data.
fn worker_failure(code: Option<i32>) -> &'static str {
    match code {
        Some(10) => "embedded worker protocol rejected request",
        Some(11) => "embedded worker input files unavailable or unsafe",
        Some(21) => "embedded Hashcat C ABI version mismatch",
        Some(22) => "embedded Hashcat could not allocate native context",
        Some(23 | 24) => "embedded Hashcat rejected bounds or file path",
        Some(31) => "Hashcat SHA-256 mode options initialization failed",
        Some(32) => "Hashcat native option parsing failed",
        Some(33) => "Hashcat native option validation failed",
        Some(34) => "Hashcat native session setup failed before compute initialization",
        Some(36) => "Hashcat native bridge initialization failed",
        Some(37) => "Hashcat native compute runtime loader failed",
        Some(38) => "Hashcat native device initialization failed; check compatible OpenCL drivers",
        Some(39) => "Hashcat native post-device setup failed",
        Some(35) => "Hashcat native session preparation failed",
        Some(40) => "Hashcat native kernel execution failed",
        _ => "embedded Hashcat worker crashed or exited unexpectedly",
    }
}

/// Best-effort clearing of confidential worker output on all return paths.
struct SensitiveBytes(Vec<u8>);
impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.0.fill(0);
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Worker exit cleanup must happen even if the supervising native thread
/// panics or the active case is revoked while the GPU runtime is busy.
struct PrivateChild(Child);
impl Drop for PrivateChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn worker_name() -> &'static str {
    if cfg!(windows) {
        "cyberdeck-recovery-worker.exe"
    } else {
        "cyberdeck-recovery-worker"
    }
}

fn shim_name() -> &'static str {
    if cfg!(windows) {
        "cyberdeck_hashcat_shim.dll"
    } else if cfg!(target_os = "macos") {
        "libcyberdeck_hashcat_shim.dylib"
    } else {
        "libcyberdeck_hashcat_shim.so"
    }
}

fn hashcat_library_name() -> &'static str {
    if cfg!(windows) {
        "hashcat.dll"
    } else if cfg!(target_os = "macos") {
        "libhashcat.8.dylib"
    } else {
        "libhashcat.so.8"
    }
}

pub fn runtime_available(root: &Path) -> Result<(), String> {
    // A native library without its exact SHA-256 mode, kernels and notices
    // cannot be advertised as a complete bundled recovery capability.
    let required_files = [
        worker_name(),
        shim_name(),
        hashcat_library_name(),
        if cfg!(windows) {
            "modules/module_00000.dll"
        } else {
            "modules/module_00000.so"
        },
        if cfg!(windows) {
            "modules/module_01400.dll"
        } else {
            "modules/module_01400.so"
        },
        // Upstream loads the generic recipe preflight kernel during startup.
        "OpenCL/m04000-pure.cl",
        "OpenCL/m01400_a0-optimized.cl",
        "OpenCL/m01400_a1-optimized.cl",
        "OpenCL/m01400_a3-optimized.cl",
        "OpenCL/amp_a0.cl",
        "source-manifest.json",
        "licenses/HASHCAT_MIT.txt",
        "licenses/OPENCL_HEADERS.txt",
    ];
    for relative in required_files {
        let path = root.join(relative);
        if !path.is_file() || path.metadata().map(|meta| meta.len() == 0).unwrap_or(true) {
            return Err("source-built Hashcat runtime is incomplete".into());
        }
    }
    // A bundled mode needs its actual module plus the optimized kernel family.
    for mode in [0u32, 100, 1000, 1400, 1700] {
        let module = if cfg!(windows) {
            format!("modules/module_{mode:05}.dll")
        } else {
            format!("modules/module_{mode:05}.so")
        };
        let path = root.join(module);
        if !path.is_file() || path.metadata().map(|m| m.len() == 0).unwrap_or(true) {
            return Err("source-built Hashcat runtime is incomplete".into());
        }
        for attack in [0, 1, 3] {
            let kernel = root.join(format!("OpenCL/m{mode:05}_a{attack}-optimized.cl"));
            if !kernel.is_file() || kernel.metadata().map(|m| m.len() == 0).unwrap_or(true) {
                return Err("source-built Hashcat runtime is incomplete".into());
            }
        }
    }
    // Archive batch (B1): these upstream modes ship pure-only kernels (7-Zip
    // also has a suffix-less optimized kernel), so the kernel set is explicit
    // per mode instead of the a0/a1/a3 triplet.
    // Document batch (B2): Office 2007/2013 and PDF 1.4-1.6 are pure-only;
    // oldoffice and PDF 1.1-1.3 ship optimized-only kernel families.
    // Wallet batch (B3): all four wallet modes are pure-only.
    for (mode, kernels) in [
        (
            13100u32,
            &[
                "m13100_a0-optimized.cl",
                "m13100_a1-optimized.cl",
                "m13100_a3-optimized.cl",
                "m13100_a0-pure.cl",
                "m13100_a1-pure.cl",
                "m13100_a3-pure.cl",
                "m13100_a4-pure.cl",
            ] as &[&str],
        ),
        (
            18200,
            &[
                "m18200_a0-optimized.cl",
                "m18200_a1-optimized.cl",
                "m18200_a3-optimized.cl",
                "m18200_a0-pure.cl",
                "m18200_a1-pure.cl",
                "m18200_a3-pure.cl",
                "m18200_a4-pure.cl",
            ] as &[&str],
        ),
        (22100u32, &["m22100-pure.cl"] as &[&str]),
        (11300u32, &["m11300-pure.cl"] as &[&str]),
        (13400, &["m13400-pure.cl"] as &[&str]),
        (15600, &["m15600-pure.cl"] as &[&str]),
        (15700, &["m15700-pure.cl"] as &[&str]),
        (9400u32, &["m09400-pure.cl"] as &[&str]),
        (9600, &["m09600-pure.cl"] as &[&str]),
        (
            9700,
            &[
                "m09700_a0-optimized.cl",
                "m09700_a1-optimized.cl",
                "m09700_a3-optimized.cl",
                "m09700_a4-optimized.cl",
            ] as &[&str],
        ),
        (
            10400,
            &[
                "m10400_a0-optimized.cl",
                "m10400_a1-optimized.cl",
                "m10400_a3-optimized.cl",
                "m10400_a4-optimized.cl",
            ] as &[&str],
        ),
        (10500, &["m10500-pure.cl"] as &[&str]),
        (
            11600u32,
            &["m11600-pure.cl", "m11600-optimized.cl"] as &[&str],
        ),
        (13600, &["m13600-pure.cl"] as &[&str]),
        (
            17200,
            &[
                "m17200_a0-pure.cl",
                "m17200_a1-pure.cl",
                "m17200_a3-pure.cl",
                "m17200_a4-pure.cl",
            ] as &[&str],
        ),
        (
            17210,
            &[
                "m17210_a0-pure.cl",
                "m17210_a1-pure.cl",
                "m17210_a3-pure.cl",
                "m17210_a4-pure.cl",
            ] as &[&str],
        ),
    ] {
        let module = if cfg!(windows) {
            format!("modules/module_{mode:05}.dll")
        } else {
            format!("modules/module_{mode:05}.so")
        };
        let path = root.join(module);
        if !path.is_file() || path.metadata().map(|m| m.len() == 0).unwrap_or(true) {
            return Err("source-built Hashcat runtime is incomplete".into());
        }
        for kernel in kernels {
            let path = root.join("OpenCL").join(kernel);
            if !path.is_file() || path.metadata().map(|m| m.len() == 0).unwrap_or(true) {
                return Err("source-built Hashcat runtime is incomplete".into());
            }
        }
    }
    if !root.join("capability-manifest.json").is_file() {
        return Err("source-built Hashcat runtime is incomplete".into());
    }
    if !root.join("tunings").is_dir() {
        return Err("source-built Hashcat runtime is incomplete".into());
    }
    Ok(())
}

/// Execute a fixed no-evidence loader probe using the exact bundled private
/// worker. This is not device enumeration or a kernel known-answer test.
/// The worker emits no text; all diagnostics are static and redacted.
pub fn probe_opencl_loader(root: &Path) -> Result<bool, String> {
    runtime_available(root)?;
    let child = Command::new(root.join(worker_name()))
        .arg("--probe-opencl-loader")
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "bundled Hashcat worker loader probe could not start")?;
    let mut child = PrivateChild(child);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = child
            .0
            .try_wait()
            .map_err(|_| "bundled Hashcat loader probe failed")?
        {
            return match status.code() {
                Some(0) => Ok(true),
                Some(37) => Ok(false),
                _ => Err("bundled Hashcat loader probe returned an unexpected result".into()),
            };
        }
        if Instant::now() >= deadline {
            return Err("bundled Hashcat loader probe timed out".into());
        }
        thread::sleep(Duration::from_millis(25));
    }
}

/// Trusted built-in KATs use only public fixtures: zero user hashes, wordlists,
/// case context or secret output ever passes into this capability probe.
const PUBLIC_KATS: &[(u32, &str, &str)] = &[
    (1400, "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (0, "abc", "900150983cd24fb0d6963f7d28e17f72"),
    (100, "abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
    (1000, "password", "8846f7eaee8fb117ad06bdd830b7586c"),
    (1700, "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"),
    // Batch-1 KDF modes: vectors verified independently by our native Rust
    // engines (pwhash / john / Openwall published bcrypt vectors).
    (500, "password", "$1$5pZSV9va$azfrPr6af3Fc7dLblQXVa0"),
    (1800, "test", "$6$G/gkPn17kHYo0gTF$xhDFU0QYExdMH2ghOWKrrVtu1BuTpNMSJURCXk43.EYekmK8iwV6RNqftUUC8mqDel1J7m3JEbUkbu4YyqSyv/"),
    (3200, "U*U", "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"),
    // Batch-2: salted digests + HMAC (independent Node-crypto vectors),
    // Windows auth (john the Ripper vectors) and sha256crypt (pwhash).
    (400, "openwall", "$P$900000000m6YEJzWtTmNBBL4jypbHv1"),
    (10, "cyberdeck", "c51d5447beddf60e68604ca2dbf4e6ad:4242"),
    (20, "cyberdeck", "a944dd5c9a02c5bed3a4b175ac565d7c:4242"),
    (50, "cyberdeck", "dc5b5ad28f4dd280463a5319b976bd50:4242"),
    (60, "cyberdeck", "3de2a5579621deb8357374953c6a520d4779fc8a:4242"),
    (110, "cyberdeck", "047564e24f0e65d25618c3369b98d9602219c03d:4242"),
    (120, "cyberdeck", "0c0ae97e6246815bb0426ba6cff3093561f069b3:4242"),
    (1100, "test1", "64cd29e36a8431a2b111378564a10631:test1"),
    (2100, "test1", "$DCC2$10240#test1#607bbe89611e37446e736f7856515bf8"),
    (5500, "g3rg3g3rg3g3rg3", "a::b:1122334455667788:000000000000000000000000000000000000000000000000:BFCCAF26128EC95F9999C9792F49434267A1D9B0EF89BFFB"),
    (5600, "password", "NTLMV2TEST::WORKGROUP:1122334455667788:07659A550D5E9D02996DFD95C87EC1D5:0101000000000000006CF6385B74CA01B3610B02D99732DD000000000200120057004F0052004B00470052004F00550050000100200044004100540041002E00420049004E0043002D0053004500430055005200490000000000"),
    (7400, "cyberdeck-kat-2026", "$5$CyberDeckKAT$kGyqS./awuvI5h4KB95ES/o9w3pxHqKFF8aBBpvSGvD"),
    (1500, "cyberdeck-descrypt-kat", "KySCHrKHoR6zc"),
    (132, "cyberdeck", "0x01004b617431118f284707047f3aca6a8aa6efc55a14ebf4bda1"),
    (1731, "cyberdeck", "0x02004b617432e84f1ad231ba962162606f404c602512e47115fe3318ce08ee7cb1bcb1a87794e8c7c903d8aef844b99c020ec88a21bc36f6c2d4f931e92491ddc919d49e70d5"),
    // Batch-3 archive containers: upstream hashcat example hashes
    // (module ST_HASH/ST_PASS, pass "hashcat"), independently verified by
    // the native CPU verifiers in cyberdeck-crypto/src/archives.rs.
    (13600, "hashcat", "$zip2$*0*1*0*0675369741458183*5dc5*0**36b85538918416712640*$/zip2$"),
    (11600, "hashcat", "$7z$0$14$0$$11$33363437353138333138300000000000$2365089182$16$12$d00321533b483f54a523f624a5f63269"),
    (17200, "hashcat", "$pkzip2$1*1*2*0*e3*1c5*eda7a8de*0*28*8*e3*eda7*5096*a9fc1f4e951c8fb3031a6f903e5f4e3211c8fdc4671547bf77f6f682afbfcc7475d83898985621a7af9bccd1349d1976500a68c48f630b7f22d7a0955524d768e34868880461335417ddd149c65a917c0eb0a4bf7224e24a1e04cf4ace5eef52205f4452e66ded937db9545f843a68b1e84a2e933cc05fb36d3db90e6c5faf1bee2249fdd06a7307849902a8bb24ec7e8a0886a4544ca47979a9dfeefe034bdfc5bd593904cfe9a5309dd199d337d3183f307c2cb39622549a5b9b8b485b7949a4803f63f67ca427a0640ad3793a519b2476c52198488e3e2e04cac202d624fb7d13c2*$/pkzip2$"),
    (17210, "hashcat", "$pkzip2$1*1*2*0*1d1*1c5*eda7a8de*0*28*0*1d1*eda7*5096*1dea673da43d9fc7e2be1a1f4f664269fceb6cb88723a97408ae1fe07f774d31d1442ea8485081e63f919851ca0b7588d5e3442317fff19fe547a4ef97492ed75417c427eea3c4e146e16c100a2f8b6abd7e5988dc967e5a0e51f641401605d673630ea52ebb04da4b388489901656532c9aa474ca090dbac7cf8a21428d57b42a71da5f3d83fed927361e5d385ca8e480a6d42dea5b4bf497d3a24e79fc7be37c8d1721238cbe9e1ea3ae1eb91fc02aabdf33070d718d5105b70b3d7f3d2c28b3edd822e89a5abc0c8fee117c7fbfbfd4b4c8e130977b75cb0b1da080bfe1c0859e6483c42f459c8069d45a76220e046e6c2a2417392fd87e4aa4a2559eaab3baf78a77a1b94d8c8af16a977b4bb45e3da211838ad044f209428dba82666bf3d54d4eed82c64a9b3444a44746b9e398d0516a2596d84243b4a1d7e87d9843f38e45b6be67fd980107f3ad7b8453d87300e6c51ac9f5e3f6c3b702654440c543b1d808b62f7a313a83b31a6faaeedc2620de7057cd0df80f70346fe2d4dccc318f0b5ed128bcf0643e63d754bb05f53afb2b0fa90b34b538b2ad3648209dff587df4fa18698e4fa6d858ad44aa55d2bba3b08dfdedd3e28b8b7caf394d5d9d95e452c2ab1c836b9d74538c2f0d24b9b577*$/pkzip2$"),
    // Batch-4 documents: upstream hashcat example hashes
    // (module ST_HASH/ST_PASS, pass "hashcat"), independently verified by
    // the native CPU verifiers in cyberdeck-crypto/src/documents.rs.
    (9700, "hashcat", "$oldoffice$0*55045061647456688860411218030058*e7e24d163fbd743992d4b8892bf3f2f7*493410dbc832557d3fe1870ace8397e2"),
    (9400, "hashcat", "$office$*2007*20*128*16*18410007331073848057180885845227*944c70a5ee6e5ab2a6a86ff54b5f621a*e6650f1f2630c27fd8fc0f5e56e2e01f99784b9f"),
    (9600, "hashcat", "$office$*2013*100000*256*16*67805436882475302087847656644837*0c392d3b9ca889656d1e615c54f9f3c9*612b79e33b96322c3253fc8a0f314463cd76bc4efe1352f7efffca0f374f7e4b"),
    (10400, "hashcat", "$pdf$1*2*40*-1*0*16*01221086741440841668371056103222*32*27c3fecef6d46a78eb61b8b4dbc690f5f8a2912bbb9afc842c12d79481568b74*32*0000000000000000000000000000000000000000000000000000000000000000"),
    (10500, "hashcat", "$pdf$2*3*128*-4*1*16*62888255846156252261477183186121*32*6879919b1afd520bd3b7dbcc0868a0a500000000000000000000000000000000*32*0000000000000000000000000000000000000000000000000000000000000000"),
    // Batch-5 wallets: upstream hashcat example hashes
    // (module ST_HASH/ST_PASS, pass "hashcat"), independently verified by
    // the native CPU verifiers in cyberdeck-crypto/src/wallets.rs.
    (11300, "hashcat", "$bitcoin$96$c265931309b4a59307921cf054b4ec6b6e4554369be79802e94e16477645777d948ae1d375191831efc78e5acd1f0443$16$8017214013543185$200460$96$480008005625057442352316337722323437108374245623701184230273883222762730232857701607167815448714$66$014754433300175043011633205413774877455616682000536368706315333388"),
    (13400, "hashcat", "$keepass$*2*24569*0*c40432355cce7348c48053ceea0a28e7d18859c4ea47e3a799c6300861f64b95*265dafcc42e1537ff42e97e1e283c70014133be0fe2d420b4d24c6d57c9d2207*a00e20a852694c15aabb074d61b902fa*48dd553fb96f7996635f2414bfe6a1a8429ef0ffb71a1752abbef31853172c35*a44ae659958ad7fae8c8952cb83f3cf03fec2371ce22a8bf7fac1e687af2f249*1*64*5a26ea376cc5afc955104c334571d30486acbac512a94b75ca82a9e31dd97bf7"),
    (15600, "hashcat", "$ethereum$p*1024*38353131353831333338313138363430*a8b4dfe92687dbc0afeb5dae7863f18964241e96b264f09959903c8c924583fc*0a9252861d1e235994ce33dbca91c98231764d8ecb4950015a8ae20d6415b986"),
    (15700, "hashcat", "$ethereum$s*262144*8*1*3134313837333434333838303231333633373433323633373534333136363537*73da7f80ec3bd4f2a128c3a815cfb4d576ecb1a9b47024c902e62ea926f7795b*910e0f8dc1f7ba41959e1089bb769f3e919109591913cc33ba03953d7a905efd"),
    // Batch-6: upstream hashcat example hash (module ST_HASH/ST_PASS,
    // pass "hashcat"), independently verified by the native CPU verifier
    // in cyberdeck-crypto/src/bitlocker.rs.
    (22100, "hashcat", "$bitlocker$1$16$6f972989ddc209f1eccf07313a7266a2$1048576$12$3a33a8eaff5e6f81d907b591$60$316b0f6d4cb445fb056f0e3e0633c413526ff4481bbf588917b70a4e8f8075f5ceb45958a800b42cb7ff9b7f5e17c6145bf8561ea86f52d3592059fb"),
    // Batch-6: upstream hashcat example hashes (module ST_HASH/ST_PASS,
    // pass "hashcat"), independently verified by the native CPU verifier
    // in cyberdeck-crypto/src/kerberos.rs.
    (13100, "hashcat", "$krb5tgs$23$*user$realm$test/spn*$b548e10f5694ae018d7ad63c257af7dc$35e8e45658860bc31a859b41a08989265f4ef8afd75652ab4d7a30ef151bf6350d879ae189a8cb769e01fa573c6315232b37e4bcad9105520640a781e5fd85c09615e78267e494f433f067cc6958200a82f70627ce0eebc2ac445729c2a8a0255dc3ede2c4973d2d93ac8c1a56b26444df300cb93045d05ff2326affaa3ae97f5cd866c14b78a459f0933a550e0b6507bf8af27c2391ef69fbdd649dd059a4b9ae2440edd96c82479645ccdb06bae0eead3b7f639178a90cf24d9a"),
    (18200, "hashcat", "$krb5asrep$23$user@domain.com:3e156ada591263b8aab0965f5aebd837$007497cb51b6c8116d6407a782ea0e1c5402b17db7afa6b05a6d30ed164a9933c754d720e279c6c573679bd27128fe77e5fea1f72334c1193c8ff0b370fadc6368bf2d49bbfdba4c5dccab95e8c8ebfdc75f438a0797dbfb2f8a1a5f4c423f9bfc1fea483342a11bd56a216f4d5158ccc4b224b52894fadfba3957dfe4b6b8f5f9f9fe422811a314768673e0c924340b8ccb84775ce9defaa3baa0910b676ad0036d13032b0dd94e3b13903cc738a7b6d00b0b3c210d1f972a6c7cae9bd3c959acf7565be528fc179118f28c679f6deeee1456f0781eb8154e18e49cb27b64bf74cd7112a0ebae2102ac"),
];
type Readiness = Result<Vec<u32>, String>;
static READINESS_CACHE: OnceLock<Mutex<HashMap<PathBuf, Readiness>>> = OnceLock::new();

fn self_test_mode(root: &Path, mode: u32, word: &str, digest: &str) -> Result<(), String> {
    let scratch = tempfile::Builder::new()
        .prefix("cyberdeck-hc-selftest-")
        .tempdir()
        .map_err(|_| "could not create private Hashcat self-test workspace")?;
    let target_path = scratch.path().join("public.hash");
    let wordlist_path = scratch.path().join("public.words");
    let result_path = scratch.path().join("public.out");
    fs::write(&target_path, format!("{digest}\n"))
        .map_err(|_| "could not create private Hashcat self-test hash")?;
    fs::write(&wordlist_path, format!("not-the-solution\n{word}\n"))
        .map_err(|_| "could not create private Hashcat self-test dictionary")?;
    let packet = frame_mode(
        root,
        &target_path,
        &wordlist_path,
        &result_path,
        2,
        30,
        0,
        mode,
    )?;
    let mut child = PrivateChild(
        Command::new(root.join(worker_name()))
            .current_dir(scratch.path())
            .env("HOME", scratch.path())
            .env("XDG_DATA_HOME", scratch.path())
            .env("XDG_CACHE_HOME", scratch.path())
            .env("XDG_CONFIG_HOME", scratch.path())
            .env("APPDATA", scratch.path())
            .env("LOCALAPPDATA", scratch.path())
            .env("TMP", scratch.path())
            .env("TEMP", scratch.path())
            .stdin(Stdio::piped())
            // Progress frames are tolerable garbage for KAT sessions: stdout
            // stays null and acceptance comes solely from the exit code plus
            // the independently verified outfile below.
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| "could not start bundled Hashcat self-test worker")?,
    );
    child
        .0
        .stdin
        .take()
        .ok_or("Hashcat self-test worker input unavailable")?
        .write_all(&packet)
        .map_err(|_| "could not send bounded Hashcat self-test")?;
    // Slow KDF modes (sha512crypt etc.) compile their kernels on first run;
    // the compiled kernel is cached afterward, so this cost is one-time.
    let deadline = Instant::now() + Duration::from_secs(180);
    loop {
        match child.0.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(status)) => return Err(worker_failure(status.code()).into()),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(30)),
            Ok(None) => return Err("native Hashcat self-test timed out".into()),
            Err(_) => return Err("native Hashcat self-test worker status unavailable".into()),
        }
    }
    drop(child);
    let metadata = fs::metadata(&result_path)
        .map_err(|_| "native Hashcat self-test failed to produce a match")?;
    if metadata.len() > 4096 {
        return Err("native Hashcat self-test result limit exceeded".into());
    }
    let mut result = SensitiveBytes(Vec::with_capacity(metadata.len() as usize));
    File::open(&result_path)
        .map_err(|_| "native Hashcat self-test result inaccessible")?
        .take(4097)
        .read_to_end(&mut result.0)
        .map_err(|_| "native Hashcat self-test result unreadable")?;
    let output = result.0.strip_suffix(b"\n").unwrap_or(&result.0);
    let output = output.strip_suffix(b"\r").unwrap_or(output);
    let expected = RecoveryTarget::parse(
        match mode {
            0 => "md5",
            100 => "sha1",
            1000 => "ntlm",
            1400 => "sha256",
            1700 => "sha512",
            // Salted/HMAC composed digests verify through their named format.
            10 => "md5-pass-salt",
            20 => "md5-salt-pass",
            50 => "hmac-md5",
            60 => "hmac-sha1",
            110 => "sha1-pass-salt",
            120 => "sha1-salt-pass",
            // KDF fixtures: the modular string carries its own family; the
            // verifier derives it (bcrypt/phpass/crypt family/Windows auth).
            400 | 500 | 1800 | 2100 | 3200 | 5500 | 5600 | 7400 | 132 | 1731 => "kdf",
            // Archive containers self-identify through their $-markers and
            // verify through the CPU verifiers in cyberdeck-crypto/archives.
            13600 | 11600 | 17200 | 17210 => "kdf",
            // Document containers verify through cyberdeck-crypto/documents.
            9700 | 9400 | 9600 | 10400 | 10500 => "kdf",
            // Wallet containers verify through cyberdeck-crypto/wallets.
            11300 | 13400 | 15600 | 15700 => "kdf",
            // Disk encryption verifies through cyberdeck-crypto/bitlocker.
            22100 => "kdf",
            // Kerberos verifies through cyberdeck-crypto/kerberos.
            13100 | 18200 => "kdf",
            1100 => "mscash",
            1500 => "descrypt",
            _ => return Err("Hashcat self-test mode unsupported".into()),
        },
        digest,
    )?;
    if output != word.as_bytes() || !expected.is_match(output)? {
        return Err(
            "native Hashcat self-test failed independent digest/candidate verification".into(),
        );
    }
    Ok(())
}

/// Only actually executed modes may be enabled in the desktop UI. A loader
/// check or enumerated GPU is insufficient. Cache exact runtime-path findings
/// for one process lifetime; after changing drivers, restart the application.
/// Real hardware/type mapping remains a separate acceptance requirement.
pub fn verified_modes(root: &Path) -> Readiness {
    let cache = READINESS_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = match cache.lock() {
        Ok(lock) => lock,
        Err(_) => return Err("Hashcat readiness cache unavailable".into()),
    };
    if let Some(stored) = guard.get(root) {
        return stored.clone();
    }
    let result = run_readiness_sweep(root);
    guard.insert(root.to_path_buf(), result.clone());
    result
}

/// The uncached readiness gate: a full sequential sweep of every public
/// known-answer test through the exact bundled private worker. This takes
/// roughly 452s on first execution because every KDF mode compiles and runs
/// its on-device KAT.
fn run_readiness_sweep(root: &Path) -> Readiness {
    runtime_available(root)?;
    if !probe_opencl_loader(root)? {
        return Err("Bundled Hashcat OpenCL loader unavailable".into());
    }
    let mut verified = Vec::new();
    let mut first_failure = None;
    for &(mode, word, digest) in PUBLIC_KATS {
        match self_test_mode(root, mode, word, digest) {
            Ok(()) => verified.push(mode),
            Err(error) if first_failure.is_none() => first_failure = Some(error),
            Err(_) => {}
        }
    }
    if verified.is_empty() {
        Err(first_failure.unwrap_or_else(|| {
            "No bundled Hashcat mode passed its private known-answer test".into()
        }))
    } else {
        Ok(verified)
    }
}

/// Disk-persisted readiness findings with a runtime-fingerprint trust model.
///
/// SECURITY INVARIANT: this cache may only claim modes that were actually
/// executed against this exact runtime. The fingerprint covers the runtime's
/// source-manifest.json bytes (which pin the built source tree) plus the
/// exact file sizes of the worker, shim and Hashcat library binaries (which
/// pin the produced artifacts); any change to the built runtime invalidates
/// every persisted finding. Modes absent from PUBLIC_KATS are always dropped
/// (clamped), an empty verified set never validates as a hit, and every
/// persistence error silently degrades to the synchronous sweep path — the
/// KAT gate never depends on the cache being readable or writable.
#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedReadiness {
    fingerprint: String,
    verified: Vec<u32>,
    verified_at_epoch_ms: u64,
}

const READINESS_CACHE_FILE_LIMIT: u64 = 64 * 1024;
static READINESS_REFRESH_IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// SHA-256 over the runtime's source-manifest.json bytes bound with the file
/// sizes of the three linked binaries. Binary names are hashed alongside the
/// sizes so a swapped runtime layout cannot alias two runtimes to one
/// fingerprint. Any unreadable component fails closed to None, which forces
/// the synchronous sweep path.
fn runtime_fingerprint(root: &Path) -> Option<String> {
    let manifest = fs::read(root.join("source-manifest.json")).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&manifest);
    for name in [worker_name(), shim_name(), hashcat_library_name()] {
        let size = fs::metadata(root.join(name)).ok()?.len();
        hasher.update([0u8]);
        hasher.update(name.as_bytes());
        hasher.update(size.to_le_bytes());
    }
    Some(
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    )
}

/// Validate and load a persisted readiness cache. Returns None — meaning the
/// caller must run the synchronous sweep — when the file is unreadable,
/// corrupt, oversized, written for a different runtime fingerprint, or its
/// mode list is not a non-empty subset of PUBLIC_KATS. An empty verified set
/// is written only after an observed failed sweep (see write_readiness_cache)
/// and therefore never validates.
fn read_readiness_cache(root: &Path, cache_path: &Path) -> Option<Vec<u32>> {
    if fs::metadata(cache_path).ok()?.len() > READINESS_CACHE_FILE_LIMIT {
        return None;
    }
    let bytes = fs::read(cache_path).ok()?;
    let persisted: PersistedReadiness = serde_json::from_slice(&bytes).ok()?;
    if persisted.fingerprint != runtime_fingerprint(root)? {
        return None;
    }
    let known: HashSet<u32> = PUBLIC_KATS.iter().map(|&(mode, _, _)| mode).collect();
    // Subset gate: only modes that are actually part of the public KAT set
    // were ever executed against this runtime. Any unknown mode means the
    // file was not produced by this build, so it never validates.
    if persisted.verified.is_empty() || !persisted.verified.iter().all(|mode| known.contains(mode))
    {
        return None;
    }
    // Clamp: modes not present in PUBLIC_KATS are dropped from the cached
    // list, enforcing the advertised-set invariant at the return boundary
    // even if a future edit loosens the subset gate above.
    let mut verified: Vec<u32> = persisted
        .verified
        .into_iter()
        .filter(|mode| known.contains(mode))
        .collect();
    verified.sort_unstable();
    verified.dedup();
    Some(verified)
}

/// Best-effort cache persistence; every error is silently ignored by design.
/// A plain (non-atomic) write is safe here because every read re-parses,
/// re-fingerprints and re-gates the content, so a torn write can only ever
/// degrade to the synchronous sweep path. A failed sweep is recorded as an
/// empty verified set: the file then never validates as a hit (forcing the
/// synchronous gate) and a previously good cache cannot outlive an observed
/// real failure on the same runtime.
fn write_readiness_cache(root: &Path, cache_path: &Path, readiness: &Readiness) {
    let verified = match readiness {
        Ok(modes) => modes.clone(),
        Err(_) => Vec::new(),
    };
    let Some(fingerprint) = runtime_fingerprint(root) else {
        return;
    };
    let persisted = PersistedReadiness {
        fingerprint,
        verified,
        verified_at_epoch_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis() as u64)
            .unwrap_or(0),
    };
    let payload = serde_json::to_vec(&persisted).unwrap_or_default();
    let _ = fs::write(cache_path, payload);
}

/// Re-run the full KAT sweep off the caller's critical path and rewrite the
/// persisted cache. The refresh is silent: it logs nothing, never panics
/// (catch_unwind) and touches no shared process state — its only effect is
/// the cache file. A single in-flight refresh prevents repeated capability
/// queries from stacking concurrent GPU sweeps.
fn spawn_readiness_refresh(root: PathBuf, cache_path: PathBuf) {
    if READINESS_REFRESH_IN_FLIGHT
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    thread::spawn(move || {
        let result = catch_unwind(AssertUnwindSafe(|| run_readiness_sweep(&root)));
        // A panicked refresh preserves the last-known-good cache file.
        if let Ok(readiness) = result {
            write_readiness_cache(&root, &cache_path, &readiness);
        }
        READINESS_REFRESH_IN_FLIGHT.store(false, Ordering::SeqCst);
    });
}

/// Readiness with a disk-persisted verified set: a cache hit for the current
/// runtime fingerprint returns immediately while a background thread re-runs
/// the full KAT sweep and rewrites the file (trust model: PersistedReadiness
/// above). Without a cache path — or on any cache miss/corruption — this is
/// exactly the synchronous in-process behavior of verified_modes.
pub fn verified_modes_cached(root: &Path, cache_path: Option<&Path>) -> Readiness {
    let Some(cache_path) = cache_path else {
        return verified_modes(root);
    };
    if let Some(verified) = read_readiness_cache(root, cache_path) {
        // Publish the persisted findings into the process-lifetime cache so
        // the other verified_modes gates (job start, autopilot) do not repeat
        // the multi-minute sweep after the capabilities query already ran.
        // try_lock keeps the hit path truly immediate: verified_modes holds
        // the cache mutex across its whole synchronous sweep, and a caller
        // stuck behind that lock would defeat the cached fast path. On
        // contention the insert is skipped; the sweep publishes its own
        // result when it completes.
        let cache = READINESS_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        if let Ok(mut guard) = cache.try_lock() {
            guard
                .entry(root.to_path_buf())
                .or_insert_with(|| Ok(verified.clone()));
        }
        spawn_readiness_refresh(root.to_path_buf(), cache_path.to_path_buf());
        return Ok(verified);
    }
    let result = verified_modes(root);
    write_readiness_cache(root, cache_path, &result);
    result
}

fn push_path(buffer: &mut Vec<u8>, path: &Path) -> Result<(), String> {
    let text = path.to_str().ok_or("native path is not UTF-8")?;
    if !path.is_absolute()
        || text.is_empty()
        || text.len() > 4096
        || text.bytes().any(|b| b < 32 || b == 127)
    {
        return Err("unsafe Hashcat worker input path".into());
    }
    let length = u16::try_from(text.len()).map_err(|_| "worker path too long")?;
    buffer.extend_from_slice(&length.to_le_bytes());
    buffer.extend_from_slice(text.as_bytes());
    Ok(())
}

pub(super) fn validate_embedded_request(request: &RecoveryRequest) -> Result<u32, String> {
    if !matches!(
        request.backend,
        recovery_backend::BackendSelection::HashcatManaged
    ) {
        return Err("embedded Hashcat requires Hashcat-managed device selection".into());
    }
    // max_candidates is the operator's TOTAL budget across chunked sessions;
    // each worker session stays bounded by the protocol's 1M-candidate cap.
    if request.max_candidates == 0
        || request.max_candidates > MAX_FAST_CANDIDATES
        || request.max_matches == 0
        || request.max_matches > 4
    {
        return Err("embedded Hashcat candidate or result limit exceeded".into());
    }
    let mode = match request.algorithm.as_str() {
        "md5" => 0,
        "sha1" => 100,
        "md5crypt" => 500,
        "ntlm" => 1000,
        "sha256" => 1400,
        "sha512" => 1700,
        "sha512crypt" => 1800,
        "bcrypt" => 3200,
        "phpass" => 400,
        "md5-pass-salt" => 10,
        "md5-salt-pass" => 20,
        "hmac-md5" => 50,
        "hmac-sha1" => 60,
        "sha1-pass-salt" => 110,
        "sha1-salt-pass" => 120,
        "mscash" => 1100,
        "mscash2" => 2100,
        "netntlm-v1" => 5500,
        "netntlm-v2" => 5600,
        "sha256crypt" => 7400,
        "descrypt" => 1500,
        "mssql-2005" => 132,
        "mssql-2012" => 1731,
        "office-97-2003" => 9700,
        "office-2007" => 9400,
        "office-2013" => 9600,
        "pdf-1.1-1.3" => 10400,
        "pdf-1.4-1.6" => 10500,
        "bitcoin" => 11300,
        "keepass" => 13400,
        "ethereum-pbkdf2" => 15600,
        "ethereum-scrypt" => 15700,
        "bitlocker" => 22100,
        "kerberos-tgs-rep" => 13100,
        "kerberos-as-rep" => 18200,
        "winzip-aes" => 13600,
        "7zip" => 11600,
        // Legacy ZipCrypto runs as 17200 (deflate) or 17210 (stored),
        // selected by the entry's own compression field.
        "zip-legacy" => cyberdeck_crypto::archives::PkZip::parse(&request.target_hash)
            .map_err(|error| format!("invalid zip-legacy target: {error}"))?
            .gpu_mode(),
        _ => return Err("hash mode not bundled for embedded Hashcat".into()),
    };
    match RecoveryTarget::parse(&request.algorithm, &request.target_hash)? {
        RecoveryTarget::Digest { .. } => Ok(mode),
        // KDF targets are self-describing modular strings; the parse above
        // already validated the family against the requested mode.
        RecoveryTarget::Kdf { .. } => {
            const KDF_MODES: &[&str] = &[
                "phpass", "md5crypt", "sha512crypt", "bcrypt", "sha256crypt", "mscash",
                "mscash2", "netntlm-v1", "netntlm-v2", "mssql-2005", "mssql-2012",
                "descrypt", "winzip-aes", "7zip", "zip-legacy",
                "office-97-2003", "office-2007", "office-2013", "pdf-1.1-1.3",
                "pdf-1.4-1.6", "bitcoin", "keepass", "ethereum-pbkdf2",
                "ethereum-scrypt", "bitlocker", "kerberos-tgs-rep",
                "kerberos-as-rep",
            ];
            if KDF_MODES.contains(&request.algorithm.as_str()) {
                Ok(mode)
            } else {
                Err("requested algorithm is not a bundled embedded KDF mode".into())
            }
        }
        RecoveryTarget::Multi(_) => {
            Err("embedded Hashcat requires a single target, not a hash list".into())
        }
    }
}

#[cfg(test)]
fn frame(
    root: &Path,
    target: &Path,
    wordlist: &Path,
    outfile: &Path,
    budget: u64,
    runtime: u32,
    device_id: u32,
) -> Result<Vec<u8>, String> {
    if budget == 0 || budget > 1_000_000 || runtime == 0 || runtime > 300 || device_id > 128 {
        return Err("embedded Hashcat work limits invalid".into());
    }
    let mut packet = MAGIC.to_vec();
    packet.extend_from_slice(&budget.to_le_bytes());
    packet.extend_from_slice(&runtime.to_le_bytes());
    packet.extend_from_slice(&device_id.to_le_bytes());
    for path in [root, target, wordlist, outfile] {
        push_path(&mut packet, path)?;
    }
    Ok(packet)
}

fn frame_mode(
    root: &Path,
    target: &Path,
    wordlist: &Path,
    outfile: &Path,
    budget: u64,
    runtime: u32,
    device_id: u32,
    hash_mode: u32,
) -> Result<Vec<u8>, String> {
    if budget == 0 || budget > 1_000_000 || runtime == 0 || runtime > 300 || device_id > 128 {
        return Err("embedded Hashcat work limits invalid".into());
    }
    if !matches!(
        hash_mode,
        0 | 10 | 20 | 50 | 60 | 100 | 110 | 120 | 132 | 400 | 500 | 1000 | 1100 | 1400 | 1500
        | 1700 | 1731 | 1800 | 2100 | 3200 | 5500 | 5600 | 7400
        | 11600 | 13600 | 17200 | 17210
        | 9400 | 9600 | 9700 | 10400 | 10500
        | 11300 | 13400 | 15600 | 15700
        | 22100
        | 13100 | 18200
    ) {
        return Err("embedded Hashcat mode unsupported".into());
    }
    let mut packet = b"CDHC0002".to_vec();
    packet.extend_from_slice(&budget.to_le_bytes());
    packet.extend_from_slice(&runtime.to_le_bytes());
    packet.extend_from_slice(&device_id.to_le_bytes());
    packet.extend_from_slice(&hash_mode.to_le_bytes());
    for path in [root, target, wordlist, outfile] {
        push_path(&mut packet, path)?;
    }
    Ok(packet)
}

/// GPU progress frame emitted by the worker on stdout during a session:
/// fixed layout "CDHC0003" (8 ASCII bytes) + u64 tried + u64 budget + u32
/// cracked, all little-endian, exactly PROGRESS_FRAME_SIZE bytes, roughly
/// every 500ms. Frames are aggregates for the progress UI only; matches
/// still come exclusively from the independently verified outfile, and the
/// session outcome remains the worker's exit code.
const PROGRESS_MAGIC: &[u8; 8] = b"CDHC0003";
const PROGRESS_FRAME_SIZE: usize = 8 + 8 + 8 + 4;
const PROGRESS_BUFFER_LIMIT: usize = 4096;

/// Incremental, strict parser for worker GPU progress frames. Complete
/// frames are extracted across arbitrary chunk boundaries with partial
/// reads buffered. Any unknown magic, malformed layout or unbounded
/// garbage poisons the parser permanently: no further frames are produced.
/// The supervisor keeps draining stdout to EOF afterwards so the worker
/// never observes a broken pipe mid-session; the session outcome is never
/// affected — it remains the worker's exit code plus the verified outfile.
struct ProgressFrames {
    buffer: Vec<u8>,
    healthy: bool,
}

impl ProgressFrames {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
            healthy: true,
        }
    }

    fn absorb(&mut self, chunk: &[u8]) -> Vec<(u64, u64, u32)> {
        let mut frames = Vec::new();
        if !self.healthy {
            return frames;
        }
        // A stalled or hostile writer must not grow this buffer unbounded.
        if self.buffer.len() + chunk.len() > PROGRESS_BUFFER_LIMIT {
            self.healthy = false;
            self.buffer.clear();
            return frames;
        }
        self.buffer.extend_from_slice(chunk);
        while self.buffer.len() >= PROGRESS_FRAME_SIZE {
            if &self.buffer[..8] != PROGRESS_MAGIC {
                self.healthy = false;
                self.buffer.clear();
                return frames;
            }
            let tried = u64::from_le_bytes(
                self.buffer[8..16]
                    .try_into()
                    .expect("fixed frame layout"),
            );
            let budget = u64::from_le_bytes(
                self.buffer[16..24]
                    .try_into()
                    .expect("fixed frame layout"),
            );
            let cracked = u32::from_le_bytes(
                self.buffer[24..28]
                    .try_into()
                    .expect("fixed frame layout"),
            );
            frames.push((tried, budget, cracked));
            self.buffer.drain(..PROGRESS_FRAME_SIZE);
        }
        frames
    }
}

/// Drain all GPU progress frames that arrived since the last poll and
/// forward them as aggregate progress wires. Frame counters are never
/// trusted for matches; the authoritative result remains the verified
/// outfile processed after the worker exits successfully. `offset` is the
/// candidates already submitted in earlier chunks and `total_budget` the
/// operator's whole-run budget, so the UI sees one continuous counter
/// instead of a per-chunk reset.
fn forward_progress_frames<P: FnMut(RecoveryProgressWire)>(
    frame_recv: &mpsc::Receiver<(u64, u64, u32)>,
    offset: u64,
    total_budget: u64,
    progress: &mut P,
) {
    while let Ok((tried, _chunk_budget, cracked)) = frame_recv.try_recv() {
        progress(RecoveryProgressWire {
            tried: offset + tried,
            budget: total_budget,
            matches: cracked as usize,
            stage: None,
        });
    }
}

/// Split the operator wordlist into private chunk files of at most
/// `MAX_CANDIDATES` candidates each, bounded by `total_budget` candidates
/// overall. The worker protocol keeps its per-session 1M/300s safety
/// bounds; big wordlists run as a sequence of bounded sessions instead of
/// being silently truncated at the first million candidates. Returns the
/// chunk files in order with their candidate counts.
fn write_wordlist_chunks(
    wordlist: &Path,
    scratch: &Path,
    total_budget: u64,
    cancel: &RecoveryCancel,
) -> Result<Vec<(PathBuf, u64)>, String> {
    let input = File::open(wordlist).map_err(|_| "wordlist became unavailable")?;
    let mut reader = BufReader::new(input);
    let mut chunks = Vec::new();
    let mut line = Vec::new();
    let mut total = 0u64;
    let mut index = 0u64;
    while total < total_budget {
        if cancel.is_cancelled() {
            return Err("recovery cancelled".into());
        }
        let path = scratch.join(format!("words.{index}.chunk"));
        let output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|_| "private chunk wordlist unavailable")?;
        let mut writer = BufWriter::new(output);
        let mut chunk_count = 0u64;
        while chunk_count < WORKER_SESSION_CANDIDATES && total < total_budget {
            if !preset::read_line_bounded(&mut reader, &mut line)? {
                break;
            }
            let data = line.strip_suffix(b"\n").unwrap_or(&line);
            let data = data.strip_suffix(b"\r").unwrap_or(data);
            if data.len() > 4096 {
                return Err("wordlist candidate exceeds recovery bound".into());
            }
            writer
                .write_all(data)
                .and_then(|_| writer.write_all(b"\n"))
                .map_err(|_| "cannot write private chunk wordlist")?;
            chunk_count += 1;
            total += 1;
        }
        writer.flush().map_err(|_| "cannot flush private chunk wordlist")?;
        if chunk_count == 0 {
            // Empty trailing chunk (budget not reached): drop and stop.
            let _ = fs::remove_file(&path);
            break;
        }
        chunks.push((path, chunk_count));
        index += 1;
    }
    Ok(chunks)
}

/// Executes selected bundled MD5/SHA-1/NTLM/SHA-256/SHA-512 wordlist mode. This function
/// does not assume Hashcat's device identifiers match CyberDeck's Rust OpenCL
/// inventory. Automatic GPU selection must not be certified without a KAT.
///
/// Wordlists larger than the worker protocol's per-session 1M-candidate bound
/// run as a sequence of bounded worker sessions over private chunk files; the
/// first independently verified match stops the sequence, cancellation is
/// honored between sessions, and progress frames are aggregated so the UI
/// sees one continuous tried/budget counter. A session that exhausts its
/// 300-second runtime leaves the tail of its chunk untried; the operator
/// budget governs the whole run.
pub fn execute_path<P: FnMut(RecoveryProgressWire)>(
    request: &RecoveryRequest,
    wordlist: &Path,
    runtime: &Path,
    cancel: &RecoveryCancel,
    preset: WordlistPreset,
    mut progress: P,
) -> Result<RecoveryRun, String> {
    let hash_mode = validate_embedded_request(request)?;
    runtime_available(runtime)?;
    if !wordlist.is_file() {
        return Err("wordlist must be an accessible regular file".into());
    }
    // No arbitrary Hashcat CLI or device flags. Only the known current mode.
    // Device choice 0 means Hashcat's own default, not verified GPU/CPU routing.
    let device_id = 0;
    let scratch = tempfile::Builder::new()
        .prefix("cyberdeck-hc-")
        .tempdir()
        .map_err(|_| "cannot create private Hashcat workspace")?;
    let hash = scratch.path().join("target.rawhash");
    // Bounded candidate transforms are prepared only in private job scratch.
    // The packaged Hashcat worker still executes the same native wordlist
    // attack, with no arbitrary rules/flags. Never mutate original evidence.
    let generated_path = scratch.path().join("transformed.words");
    let generated = match preset::generate(
        wordlist,
        &generated_path,
        request.max_candidates,
        preset,
        || cancel.is_cancelled(),
    ) {
        Ok(value) => value,
        Err(_error) if cancel.is_cancelled() => {
            return Ok(recovery_backend::embedded_result(
                request,
                Vec::new(),
                true,
                0,
            ));
        }
        Err(error) => return Err(error),
    };
    // A transformed empty wordlist is an exhausted operation, not a native
    // runtime/device failure. No worker or secret output is created.
    if generated == Some(0) {
        return Ok(recovery_backend::embedded_result(
            request,
            Vec::new(),
            false,
            0,
        ));
    }
    let mut file = File::create(&hash).map_err(|_| "cannot create private target file")?;
    file.write_all(request.target_hash.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .map_err(|_| "cannot write private target file")?;
    drop(file);

    // Bounded transformed lists stay a single session (they are capped at the
    // operator budget by construction). The original wordlist is split into
    // protocol-bounded chunk files, so lists far larger than the worker's
    // 1M-candidate session bound run as a sequence of sessions instead of
    // being silently truncated.
    let chunks: Vec<(PathBuf, u64)> = match generated {
        Some(count) => vec![(generated_path.clone(), count)],
        None => write_wordlist_chunks(wordlist, scratch.path(), request.max_candidates, cancel)?,
    };
    let total_budget: u64 = chunks.iter().map(|(_, count)| *count).sum();
    let run_started = Instant::now();
    let mut matches: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut submitted: u64 = 0;
    let mut cancelled = false;
    'chunks: for (index, (chunk_path, chunk_candidates)) in chunks.iter().enumerate() {
        if cancel.is_cancelled() {
            cancelled = true;
            break;
        }
        // The worker refuses an existing outfile: one private scratch output
        // per session, deleted with the workspace at the end.
        let output = scratch.path().join(format!("recovered.{index}.tmp"));
        let bytes = frame_mode(
            runtime,
            &hash,
            chunk_path,
            &output,
            *chunk_candidates,
            300,
            device_id,
            hash_mode,
        )?;
        let mut child = PrivateChild(
            Command::new(runtime.join(worker_name()))
                .current_dir(scratch.path())
                .env("HOME", scratch.path())
                // Hashcat may derive its profile from passwd(5), ignoring HOME.
                // Keep potfiles, session metadata and cache under private scratch.
                .env("XDG_DATA_HOME", scratch.path())
                .env("XDG_CACHE_HOME", scratch.path())
                .env("XDG_CONFIG_HOME", scratch.path())
                .env("APPDATA", scratch.path())
                .env("LOCALAPPDATA", scratch.path())
                .env("TMP", scratch.path())
                .env("TEMP", scratch.path())
                .stdin(Stdio::piped())
                // GPU progress frames are consumed from stdout; the worker's
                // diagnostics stay on the redacted stderr channel.
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|_| "could not start bundled Hashcat worker")?,
        );
        {
            let mut pipe = child
                .0
                .stdin
                .take()
                .ok_or("private worker stdin unavailable")?;
            pipe.write_all(&bytes)
                .map_err(|_| "private Hashcat worker protocol write failed")?;
        }
        // GPU progress: the worker emits fixed CDHC0003 counter frames on stdout
        // during the session. A dedicated reader thread turns the blocking pipe
        // into a channel so the poll loop below keeps its exact cancellation and
        // deadline cadence (incremental availability is drained via try_recv).
        // Frames are aggregates only; matches still come exclusively from the
        // verified outfile, and the final outcome is still the exit code. A
        // worker build without frame support simply writes nothing to stdout and
        // the reader thread sees EOF, so progress stays empty rather than
        // failing the session.
        let (frame_send, frame_recv) = mpsc::channel::<(u64, u64, u32)>();
        if let Some(mut pipe) = child.0.stdout.take() {
            thread::spawn(move || {
                let mut parser = ProgressFrames::new();
                let mut chunk = [0u8; 512];
                loop {
                    match pipe.read(&mut chunk) {
                        Ok(0) | Err(_) => break, // EOF: the session is ending.
                        Ok(read_len) => {
                            for (tried, budget, cracked) in parser.absorb(&chunk[..read_len]) {
                                if frame_send.send((tried, budget, cracked)).is_err() {
                                    // Supervisor gone; stop reading.
                                    return;
                                }
                            }
                            // After malformed frames the parser is poisoned and
                            // this loop keeps draining stdout to EOF so the
                            // worker never sees a broken pipe mid-session.
                        }
                    }
                }
            });
        }
        let started = Instant::now();
        let session_cancelled = loop {
            if cancel.is_cancelled() {
                break true;
            }
            if started.elapsed() > HARD_DEADLINE {
                return Err("Hashcat worker timed out and was terminated".into());
            }
            forward_progress_frames(&frame_recv, submitted, total_budget, &mut progress);
            match child.0.try_wait() {
                Ok(Some(status)) => {
                    if !status.success() {
                        return Err(worker_failure(status.code()).into());
                    }
                    break false;
                }
                Ok(None) => thread::sleep(Duration::from_millis(75)),
                Err(_) => return Err("Hashcat worker status unavailable".into()),
            }
        };
        // Drop terminates any remaining child and waits before TempDir deletes
        // sensitive inputs/output, including on timeout and case cancellation.
        drop(child);
        // Deliver final frames that completed before exit so the UI's last
        // counters approach the real totals before the summary lands.
        forward_progress_frames(&frame_recv, submitted, total_budget, &mut progress);
        if session_cancelled || cancel.is_cancelled() {
            cancelled = true;
            break 'chunks;
        }
        let mut chunk_matches: Vec<(u64, Vec<u8>)> = Vec::new();
        if output.exists() {
            if fs::metadata(&output)
                .map_err(|_| "recovery output metadata unavailable")?
                .len()
                > MAX_PRIVATE_OUTPUT
            {
                return Err("Hashcat result output exceeded strict limit".into());
            }
            let target = RecoveryTarget::parse(&request.algorithm, &request.target_hash)?;
            let content =
                SensitiveBytes(fs::read(&output).map_err(|_| "cannot read bounded private output")?);
            for candidate in content.0.split(|b| *b == b'\n') {
                let candidate = candidate.strip_suffix(b"\r").unwrap_or(candidate);
                if candidate.is_empty() {
                    continue;
                }
                if !target.is_match(candidate)? {
                    return Err("Hashcat candidate failed independent Rust digest verification".into());
                }
                // Find the real candidate ordinal inside this chunk (plus the
                // candidates already submitted in earlier chunks), rather than
                // fabricating work counters.
                let file = File::open(chunk_path).map_err(|_| "wordlist became unavailable")?;
                let mut reader = BufReader::new(file);
                let mut line = Vec::new();
                let mut index = 0u64;
                let found_index = loop {
                    line.clear();
                    if !preset::read_line_bounded(&mut reader, &mut line)? {
                        break None;
                    }
                    if line.len() > 4096 {
                        return Err("wordlist candidate exceeds recovery bound".into());
                    }
                    let data = line.strip_suffix(b"\n").unwrap_or(&line);
                    let data = data.strip_suffix(b"\r").unwrap_or(data);
                    if data == candidate {
                        break Some(index);
                    }
                    index += 1;
                    if index >= *chunk_candidates {
                        break None;
                    }
                };
                let Some(found_index) = found_index else {
                    return Err("Hashcat output is not a verified original wordlist candidate".into());
                };
                let global_index = submitted + found_index;
                if chunk_matches.iter().any(|(old, _)| *old == global_index) {
                    continue;
                }
                chunk_matches.push((global_index, candidate.to_vec()));
                if chunk_matches.len() >= request.max_matches {
                    break;
                }
            }
            matches.extend(chunk_matches);
            if !matches.is_empty() {
                // First match stops the sequence, matching the autopilot's
                // one-match-stops semantics across GPU stages.
                break 'chunks;
            }
        }
        submitted += chunk_candidates;
    }
    if cancelled {
        return Ok(recovery_backend::embedded_result(
            request,
            Vec::new(),
            true,
            run_started.elapsed().as_millis() as u64,
        ));
    }
    Ok(recovery_backend::embedded_result(
        request,
        matches,
        false,
        run_started.elapsed().as_millis() as u64,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_public_native_mode_fixture_is_independently_verifiable_without_gpu() {
        assert_eq!(PUBLIC_KATS.len(), 39);
        for &(mode, word, hash) in PUBLIC_KATS {
            let algorithm = match mode {
                0 => "md5",
                100 => "sha1",
                1000 => "ntlm",
                1400 => "sha256",
                1700 => "sha512",
                // KDF fixtures are verified through the KDF verifier, which
                // derives the family from the modular string itself.
                400 | 500 | 1800 | 2100 | 3200 | 5500 | 5600 | 7400 => "kdf",
                1500 => "descrypt",
                132 => "kdf",
                1731 => "kdf",
                // Archive containers self-identify via their $-markers.
                13600 | 11600 | 17200 | 17210 => "kdf",
                // Document containers likewise.
                9700 | 9400 | 9600 | 10400 | 10500 => "kdf",
                // Wallet containers likewise.
                11300 | 13400 | 15600 | 15700 => "kdf",
                // Disk encryption likewise.
                22100 => "kdf",
                // Kerberos likewise (verify through cyberdeck-crypto/kerberos).
                13100 | 18200 => "kdf",
                // Hint-driven composed targets: the wire shape is ambiguous.
                10 => "md5-pass-salt",
                20 => "md5-salt-pass",
                50 => "hmac-md5",
                60 => "hmac-sha1",
                110 => "sha1-pass-salt",
                120 => "sha1-salt-pass",
                1100 => "mscash",
                _ => panic!("invalid pinned Hashcat self-test mode"),
            };
            let target = if algorithm == "kdf" {
                RecoveryTarget::parse("", hash).unwrap()
            } else {
                RecoveryTarget::parse(algorithm, hash).unwrap()
            };
            assert!(
                target.is_match(word.as_bytes()).unwrap(),
                "{algorithm} fixture"
            );
            assert!(!target.is_match(b"not-the-solution").unwrap());
        }
    }

    #[test]
    fn hardware_verified_modes_include_the_core_raw_and_kdf_set() {
        // Hardware acceptance: whichever modes crack their fixtures through
        // the real private worker on the present devices are the advertised
        // set. The core raw digests and the crypt/KDF family must always be
        // among them; salted/HMAC/auth modes are hardware-dependent.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("resources/hashcat");
        let modes = verified_modes(&root).expect("worker readiness run failed");
        // Batch-3 archive containers passed their on-device KATs on the same
        // hardware (RTX 4060, 2026-11-05); they must keep passing.
        for required in [
            0u32, 100, 1000, 1400, 1700, 500, 1800, 3200, 400, 1100, 2100,
            13600, 11600, 17200, 17210, 9700, 9400, 9600, 10400, 10500,
            11300, 13400, 15600, 15700, 22100, 13100, 18200,
        ] {
            assert!(
                modes.contains(&required),
                "mode {required} must pass its on-device KAT"
            );
        }
    }

    #[test]
    fn an_unbundled_directory_never_reports_native_mode_ready() {
        let scratch = tempfile::tempdir().unwrap();
        assert!(verified_modes(scratch.path()).is_err());
    }

    #[test]
    fn digest_modes_and_worker_v2_packet_are_bounded() {
        // POSIX-style "/tmp/fixture" paths are not absolute on Windows; the
        // fixture root must be a real absolute temporary directory on every
        // platform because the worker protocol rejects relative inputs.
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path();
        for (algorithm, size, mode) in [
            ("md5", 32, 0),
            ("sha1", 40, 100),
            ("ntlm", 32, 1000),
            ("sha256", 64, 1400),
            ("sha512", 128, 1700),
        ] {
            let request = RecoveryRequest {
                algorithm: algorithm.into(),
                target_hash: "a".repeat(size),
                backend: recovery_backend::BackendSelection::HashcatManaged,
                max_candidates: 100,
                max_matches: 1,
                target_hashes: Vec::new(),
            };
            assert_eq!(validate_embedded_request(&request), Ok(mode));
            let packet = frame_mode(path, path, path, path, 100, 30, 0, mode).unwrap();
            assert_eq!(&packet[..8], b"CDHC0002");
            assert_eq!(u32::from_le_bytes(packet[24..28].try_into().unwrap()), mode);
            let mut bad = request.clone();
            bad.target_hash.pop();
            assert!(validate_embedded_request(&bad).is_err());
        }
        assert!(frame_mode(path, path, path, path, 1, 10, 0, 999).is_err());
    }

    #[test]
    fn ntlm_mode_1000_has_independent_utf16le_reference_verification() {
        // NTLM and MD5 are both 32 hexadecimal characters; identification
        // from digest shape alone must never silently choose the algorithm.
        let ntlm_hash = "8846f7eaee8fb117ad06bdd830b7586c";
        let target = RecoveryTarget::parse("ntlm", ntlm_hash).unwrap();
        assert!(target.is_match(b"password").unwrap());
        assert!(!target.is_match(b"Password").unwrap());
        assert!(RecoveryTarget::parse("ntlm", "a").is_err());
        let request = RecoveryRequest {
            algorithm: "ntlm".into(),
            target_hash: ntlm_hash.into(),
            backend: recovery_backend::BackendSelection::HashcatManaged,
            max_candidates: 100,
            max_matches: 1,
            target_hashes: Vec::new(),
        };
        assert_eq!(validate_embedded_request(&request), Ok(1000));
    }

    #[test]
    fn incomplete_bundle_must_not_claim_embedded_capability() {
        let scratch = tempfile::tempdir().unwrap();
        assert!(runtime_available(scratch.path()).is_err());
        // Merely creating a worker executable is insufficient; kernels,
        // SHA-256 mode, provenance and license notices are mandatory.
        std::fs::write(scratch.path().join(worker_name()), b"worker").unwrap();
        assert!(runtime_available(scratch.path()).is_err());
    }

    #[test]
    fn worker_failure_diagnostics_are_redacted_and_specific() {
        assert!(worker_failure(Some(34)).contains("before compute initialization"));
        assert!(worker_failure(Some(37)).contains("compute runtime loader"));
        assert!(worker_failure(Some(21)).contains("ABI"));
        assert!(worker_failure(None).contains("crashed"));
        for code in [
            10, 11, 21, 22, 23, 24, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        ] {
            assert!(!worker_failure(Some(code)).contains("/tmp/"));
        }
    }

    #[test]
    fn protocol_bounds_and_path_safety() {
        // Same Windows portability rule: the fixture root is a real absolute
        // temporary directory; the relative-path rejection case stays.
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path();
        assert!(frame(root, root, root, root, 1, 20, 0).is_ok());
        assert!(frame(root, root, root, root, 0, 20, 0).is_err());
        assert!(frame(root, root, root, root, 1, 301, 0).is_err());
        assert!(frame(Path::new("relative"), root, root, root, 1, 20, 0).is_err());
    }

    #[test]
    fn gpu_progress_frames_parse_across_chunks_and_poison_on_garbage() {
        let mut frame = Vec::new();
        frame.extend_from_slice(b"CDHC0003");
        frame.extend_from_slice(&1234u64.to_le_bytes());
        frame.extend_from_slice(&10_000u64.to_le_bytes());
        frame.extend_from_slice(&2u32.to_le_bytes());
        assert_eq!(frame.len(), PROGRESS_FRAME_SIZE);
        let mut parser = ProgressFrames::new();
        // A frame split across arbitrary reads is buffered until complete.
        assert!(parser.absorb(&frame[..11]).is_empty());
        assert_eq!(parser.absorb(&frame[11..]), vec![(1234, 10_000, 2)]);
        // Several complete frames in one chunk are all forwarded.
        let mut two = frame.clone();
        two.extend_from_slice(&frame);
        assert_eq!(
            parser.absorb(&two),
            vec![(1234, 10_000, 2), (1234, 10_000, 2)]
        );
        // A valid frame followed by unknown magic: the good frame is still
        // forwarded, then the parser poisons permanently and silently.
        let mut poisoned = frame.clone();
        poisoned.extend_from_slice(b"CDHC9999");
        poisoned.extend_from_slice(&[0u8; PROGRESS_FRAME_SIZE - 8]);
        assert_eq!(parser.absorb(&poisoned), vec![(1234, 10_000, 2)]);
        assert!(parser.absorb(&frame).is_empty());
        // A truncated magic prefix stays buffered without poisoning.
        let mut fresh = ProgressFrames::new();
        assert!(fresh.absorb(&frame[..7]).is_empty());
        assert_eq!(fresh.absorb(&frame[7..]), vec![(1234, 10_000, 2)]);
    }

    #[test]
    fn runtime_fingerprint_requires_the_pinned_runtime_files() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path();
        assert!(runtime_fingerprint(root).is_none());
        std::fs::write(root.join("source-manifest.json"), b"manifest-v1").unwrap();
        assert!(runtime_fingerprint(root).is_none());
        std::fs::write(root.join(worker_name()), b"worker-bytes").unwrap();
        std::fs::write(root.join(shim_name()), b"shim-bytes").unwrap();
        std::fs::write(root.join(hashcat_library_name()), b"hashcat-bytes").unwrap();
        let first = runtime_fingerprint(root).unwrap();
        // The produced-artifact sizes are part of the runtime identity, so a
        // different build must change the fingerprint.
        std::fs::write(root.join(shim_name()), b"shim-bytes-v2").unwrap();
        let second = runtime_fingerprint(root).unwrap();
        assert_ne!(first, second);
    }

    #[cfg(test)]
    fn persisted_cache(fingerprint: &str, verified: &[u32]) -> PersistedReadiness {
        PersistedReadiness {
            fingerprint: fingerprint.to_string(),
            verified: verified.to_vec(),
            verified_at_epoch_ms: 1,
        }
    }

    #[test]
    fn readiness_cache_roundtrip_validates_fingerprint_and_modes() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path();
        let cache = scratch.path().join("embedded-hashcat-verified.json");
        std::fs::write(root.join("source-manifest.json"), b"manifest-v1").unwrap();
        std::fs::write(root.join(worker_name()), b"worker-bytes").unwrap();
        std::fs::write(root.join(shim_name()), b"shim-bytes").unwrap();
        std::fs::write(root.join(hashcat_library_name()), b"hashcat-bytes").unwrap();
        let fingerprint = runtime_fingerprint(root).unwrap();
        // Without a cache the synchronous sweep runs; on this incomplete
        // bundle it fails, and the failure persists only as an empty set
        // that never validates as a hit.
        assert!(verified_modes_cached(root, Some(&cache)).is_err());
        let parsed: PersistedReadiness = serde_json::from_slice(&std::fs::read(&cache).unwrap())
            .unwrap();
        assert_eq!(parsed.fingerprint, fingerprint);
        assert!(parsed.verified.is_empty());
        assert!(read_readiness_cache(root, &cache).is_none());
        // Modes outside PUBLIC_KATS invalidate the cache entirely.
        let outside = persisted_cache(&fingerprint, &[9999]);
        std::fs::write(&cache, serde_json::to_vec(&outside).unwrap()).unwrap();
        assert!(read_readiness_cache(root, &cache).is_none());
        // A cache written for a different runtime (worker size changed) is
        // rejected by the fingerprint.
        let stale = persisted_cache(&fingerprint, &[0, 1000]);
        std::fs::write(&cache, serde_json::to_vec(&stale).unwrap()).unwrap();
        std::fs::write(root.join(worker_name()), b"worker-bytes-v2").unwrap();
        assert!(read_readiness_cache(root, &cache).is_none());
        // A valid cache for this exact runtime is accepted, sorted and
        // deduplicated.
        std::fs::write(root.join(worker_name()), b"worker-bytes").unwrap();
        let good = persisted_cache(&fingerprint, &[1000, 0, 1000]);
        std::fs::write(&cache, serde_json::to_vec(&good).unwrap()).unwrap();
        assert_eq!(read_readiness_cache(root, &cache).unwrap(), vec![0, 1000]);
        // Corrupt cache content is rejected.
        std::fs::write(&cache, b"not-json").unwrap();
        assert!(read_readiness_cache(root, &cache).is_none());
    }

    #[test]
    fn valid_cache_hit_returns_immediately_without_a_sweep() {
        let scratch = tempfile::tempdir().unwrap();
        let root = scratch.path();
        let cache = scratch.path().join("ready.json");
        std::fs::write(root.join("source-manifest.json"), b"manifest-v1").unwrap();
        std::fs::write(root.join(worker_name()), b"worker-bytes").unwrap();
        std::fs::write(root.join(shim_name()), b"shim-bytes").unwrap();
        std::fs::write(root.join(hashcat_library_name()), b"hashcat-bytes").unwrap();
        let fingerprint = runtime_fingerprint(root).unwrap();
        let good = persisted_cache(&fingerprint, &[0, 1400]);
        std::fs::write(&cache, serde_json::to_vec(&good).unwrap()).unwrap();
        // A cache hit must return without executing any KAT sweep; on this
        // incomplete bundle the synchronous sweep itself would fail.
        let verified = verified_modes_cached(root, Some(&cache)).unwrap();
        assert_eq!(verified, vec![0, 1400]);
    }
}
