//! Build pinned Hashcat native C core, SHA-256 module, CyberDeck narrow C
//! shim and a private Rust worker as part of the normal Tauri/Cargo build.
//! No reference/ checkout, installed Hashcat binary, or runtime downloads.
use std::{env, path::PathBuf, process::Command};

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo manifest directory"));
    let hashcat = root.join("src/third_party/hashcat");
    let script = hashcat.join("build-native.mjs");
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo OUT_DIR"));
    let runtime = root.join("resources/hashcat");

    println!(
        "cargo:rerun-if-changed={}",
        hashcat.join("source-manifest.json").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        hashcat.join("native").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        hashcat.join("upstream").display()
    );
    println!("cargo:rerun-if-changed={}", script.display());
    println!("cargo:rerun-if-env-changed=CC");
    println!("cargo:rerun-if-env-changed=MAKE");
    println!("cargo:rerun-if-env-changed=RUSTC");

    let status = Command::new("node")
        .arg(&script)
        .arg("--out")
        .arg(out.join("embedded-hashcat"))
        .arg("--install")
        .arg(&runtime)
        .status()
        .expect("Node.js required to build version-pinned embedded Hashcat");
    assert!(
        status.success(),
        "Hashcat source compilation failed; the desktop must not ship an unverified native engine"
    );
    // Tauri bundle.resources references these files; create them before
    // tauri-build validates desktop resource configuration.
    tauri_build::build();
}
