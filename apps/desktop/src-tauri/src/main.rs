//! Desktop entry point. The frontend only ever talks to typed commands (§9.2).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod attack;
mod crack;
mod engines;
mod evidence;
mod history;
mod jobs;
mod ops;
mod pcap;
mod web;

use std::sync::Mutex;

use evidence::EvidenceCtx;
use hacktool_storage::ArtifactStore;
use tauri::Manager;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(jobs::JobManager::new())
        .manage(pcap::PcapCtx { current: std::sync::Mutex::new(None) })
        .manage(web::WebCtx {
            proxy_running: std::sync::atomic::AtomicBool::new(false),
            proxy_port: std::sync::atomic::AtomicU16::new(8080),
            proxy_handle: std::sync::Mutex::new(None),
            captured: std::sync::Mutex::new(Vec::new()),
        })
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
            ops::kdf_verify,
            evidence::file_import_dialog,
            evidence::file_list,
            evidence::file_hex,
            evidence::file_strings,
            evidence::digest_file_dialog,
            pcap::pcap_open_dialog,
            pcap::pcap_packet_bytes,
            crack::crack_wordlist_dialog,
            crack::pick_wordlist,
            history::crack_history_list,
            history::crack_history_delete,
            history::crack_history_clear,
            attack::crack_rules_dialog,
            attack::crack_mask,
            attack::device_info,
            engines::engines_detect,
            engines::engine_attack,
            web::http_send,
            web::web_scan,
            web::spider_scan,
            web::proxy_start,
            web::proxy_stop,
            web::proxy_status,
            web::proxy_history,
            web::web_engines_detect,
            web::engine_scan,
        ])
        .run(tauri::generate_context!())
        .expect("HackTool desktop runtime failed to start");
}
