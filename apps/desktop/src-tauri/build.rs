//! Build the pinned native Hashcat runtime for supported targets.
//! Windows development must remain usable even when the optional GNU/MSYS2
//! Hashcat toolchain is absent. Release builds are always strict: never ship
//! an unverified or partially built Hashcat runtime.
use std::{env, fs, path::PathBuf, process::Command};

#[path = "build_policy.rs"]
mod build_policy;

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo manifest directory"));
    let hashcat = root.join("src/third_party/hashcat");
    let script = hashcat.join("build-native.mjs");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo OUT_DIR"));
    let runtime = root.join("resources/hashcat");
    let dev_marker = runtime.join("DEVELOPMENT-HASHCAT-UNAVAILABLE.txt");

    println!("cargo:rustc-check-cfg=cfg(cyberdeck_hashcat_dev_disabled)");
    println!("cargo:rerun-if-changed=build_policy.rs");
    println!("cargo:rerun-if-env-changed=CYBERDECK_HASHCAT_BUILD");

    let target = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let profile = env::var("PROFILE").unwrap_or_default();
    let build_override = env::var("CYBERDECK_HASHCAT_BUILD").ok();
    let windows_dev =
        build_policy::defer_hashcat_on_windows_dev(&target, &profile, build_override.as_deref());
    // The optional pinned native source tree is irrelevant to Windows dev
    // builds. Watching it forces needless recompilation of the whole Tauri
    // app whenever any of those hundreds of source files change.
    if !windows_dev {
        for file in [
            "source-manifest.json",
            "capability-manifest.json",
            "native",
            "upstream",
            "build-native.mjs",
        ] {
            println!("cargo:rerun-if-changed={}", hashcat.join(file).display());
        }
        for key in ["CC", "MAKE", "RUSTC"] {
            println!("cargo:rerun-if-env-changed={key}");
        }
    }

    if windows_dev {
        // Tauri's resources/ directory must exist even without bundled
        // native DLLs. The marker is not a runnable engine or fake capability.
        fs::create_dir_all(&runtime).expect("create Hashcat development resource directory");
        build_policy::write_if_changed(&dev_marker, b"Hashcat native worker is unavailable in this Windows development build.\nSet CYBERDECK_HASHCAT_BUILD=1 to opt into native build after installing MSYS2 UCRT64 GCC/Make.\n")
            .expect("write Hashcat development-only resource marker");
        println!("cargo:rustc-cfg=cyberdeck_hashcat_dev_disabled");
        println!("cargo:warning=CyberDeck Hashcat native engine is disabled for Windows dev (other tools remain available). Set CYBERDECK_HASHCAT_BUILD=1 for a strict native build.");
    } else {
        let status = Command::new("node")
            .arg(&script)
            .arg("--out")
            .arg(out.join("embedded-hashcat"))
            .arg("--install")
            .arg(&runtime)
            .status()
            .expect("Node.js required to build the source-pinned Hashcat runtime");
        assert!(
            status.success(),
            "Hashcat source compilation failed. Native Hashcat is required for strict/release builds; Windows dev can omit it by leaving CYBERDECK_HASHCAT_BUILD unset"
        );
        // Remove only our own marker after a successful, strict native build.
        if dev_marker.exists() {
            fs::remove_file(dev_marker).expect("remove stale Hashcat development-only marker");
        }
    }
    tauri_build::build();
}
