//! Desktop entry point. The frontend only ever talks to typed commands (§9.2).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod attack;
mod cases;
mod crack;
mod engines;
mod evidence;
mod history;
mod jobs;
mod netscan;
mod ops;
mod pcap;
mod storage_paths;
mod web;
mod webtls;

use std::sync::Mutex;

use cyberdeck_storage::ArtifactStore;
use evidence::EvidenceCtx;
use tauri::Manager;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(jobs::JobManager::new())
        .manage(netscan::ScanCtx::default())
        .manage(pcap::PcapCtx {
            current: std::sync::Mutex::new(None),
        })
        .manage(web::WebCtx {
            proxy_running: std::sync::atomic::AtomicBool::new(false),
            proxy_port: std::sync::atomic::AtomicU16::new(8080),
            proxy_handle: std::sync::Mutex::new(None),
            ca: std::sync::Mutex::new(None),
            shared: std::sync::Arc::new(web::ProxyShared {
                running: std::sync::atomic::AtomicBool::new(false),
                intercept: std::sync::atomic::AtomicBool::new(false),
                port: std::sync::atomic::AtomicU16::new(8080),
                rules: std::sync::Mutex::new(Vec::new()),
                captured: std::sync::Mutex::new(Vec::new()),
                pending: std::sync::Mutex::new(std::collections::HashMap::new()),
                next_id: std::sync::atomic::AtomicU64::new(1),
                ca: std::sync::Mutex::new(None),
                ws: std::sync::Mutex::new(Vec::new()),
            }),
        })
        .setup(|app| {
            // Case store lives under the OS app-data directory; the SQLite
            // index and artifact copies are created on first launch (§8.4).
            let data_dir = storage_paths::data_dir(app.handle()).map_err(std::io::Error::other)?;
            let store =
                ArtifactStore::open(&data_dir.join("cases.db")).map_err(std::io::Error::other)?;
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
            ops::recipe_run,
            ops::kdf_verify,
            evidence::file_import_dialog,
            evidence::file_import_derived,
            cases::case_list,
            cases::case_create,
            cases::case_findings_list,
            cases::case_events_list,
            cases::case_report,
            cases::case_provenance_verify,
            cases::case_artifact_verify,
            cases::case_findings_add,
            evidence::file_list,
            evidence::file_hex,
            evidence::file_signature_scan,
            evidence::file_binary_inspect,
            evidence::file_extract_gzip,
            evidence::file_extract_archive,
            evidence::file_strings,
            evidence::digest_file_dialog,
            pcap::pcap_open_dialog,
            pcap::pcap_packet_bytes,
            pcap::pcap_follow_stream,
            crack::crack_wordlist_dialog,
            crack::pick_wordlist,
            history::crack_history_list,
            history::crack_history_delete,
            history::crack_history_clear,
            attack::crack_rules_dialog,
            attack::crack_mask,
            attack::crack_hybrid_dialog,
            attack::crack_hybrid_reverse_dialog,
            attack::crack_combinator_dialog,
            attack::benchmark,
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
            web::proxy_intercept,
            web::proxy_pending,
            web::proxy_forward,
            web::proxy_drop,
            web::proxy_set_rules,
            web::proxy_ca_pem,
            web::ws_list,
            web::web_engines_detect,
            web::engine_scan,
            netscan::netscan_start,
            netscan::netscan_stop,
            netscan::netscan_results,
            netscan::netscan_status,
            netscan::netscan_history,
            netscan::netscan_export,
            netscan::netscan_discover_hosts,
        ])
        .run(tauri::generate_context!())
        .expect("CyberDeck desktop runtime failed to start");
}
