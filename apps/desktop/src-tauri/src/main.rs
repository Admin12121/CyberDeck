//! HackTool desktop entry point. The frontend never spawns processes or
//! touches the filesystem directly; every native action is a typed command
//! here (Master Plan §9.2).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod evidence;
mod jobs;
mod ops;
mod pcap;

use std::sync::Mutex;

use evidence::EvidenceCtx;
use hacktool_storage::ArtifactStore;
use tauri::Manager;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(jobs::JobManager::new())
        .manage(pcap::PcapCtx { current: std::sync::Mutex::new(None) })
        .setup(|app| {
            // Case store lives under the OS app-data directory; the SQLite
            // index and artifact copies are created on first launch (§8.4).
            let data_dir = app.path().app_data_dir()?.join("hacktool");
            let store = ArtifactStore::open(&data_dir.join("cases.db"))
                .map_err(std::io::Error::other)?;
            app.manage(EvidenceCtx {
                store: Mutex::new(store),
                artifacts_dir: data_dir.join("artifacts"),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            jobs::job_start,
            jobs::job_cancel,
            ops::crypto_op,
            ops::crypto_catalog,
            evidence::file_import_dialog,
            evidence::file_list,
            evidence::file_hex,
            evidence::file_strings,
            pcap::pcap_open_dialog,
            pcap::pcap_packet_bytes,
        ])
        .run(tauri::generate_context!())
        .expect("HackTool desktop runtime failed to start");
}
