//! Desktop entry point. The frontend only ever talks to typed commands (§9.2).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod features;

use std::sync::Mutex;

use cyberdeck_storage::ArtifactStore;
use features::forensics::ipc::evidence::EvidenceCtx;
use tauri::Manager;

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(features::shared::jobs::ipc::JobManager::new())
        .manage(features::shared::session::CaseSessionCtx::default())
        .manage(features::crypto::ipc::recovery::RecoveryCtx::default())
        .manage(features::network::ipc::capture::CaptureCtx::default())
        .manage(features::network::ipc::netscan::ScanCtx::default())
        .manage(features::network::ipc::pcap::PcapCtx {
            current: std::sync::Mutex::new(None),
        })
        .manage(features::web::ipc::web::WebCtx {
            proxy_running: std::sync::atomic::AtomicBool::new(false),
            proxy_port: std::sync::atomic::AtomicU16::new(8080),
            proxy_handle: std::sync::Mutex::new(None),
            ca: std::sync::Mutex::new(None),
            shared: std::sync::Arc::new(features::web::ipc::web::ProxyShared {
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
            app.state::<features::crypto::ipc::recovery::RecoveryCtx>()
                .start_expiry_cleanup();
            app.state::<features::shared::session::CaseSessionCtx>()
                .start_temporary_expiry_cleanup();
            // Case store lives under the OS app-data directory; the SQLite
            // index and artifact copies are created on first launch (§8.4).
            let data_dir = features::cases::infrastructure::storage_paths::data_dir(app.handle())
                .map_err(std::io::Error::other)?;
            let store =
                ArtifactStore::open(&data_dir.join("cases.db")).map_err(std::io::Error::other)?;
            app.manage(EvidenceCtx {
                store: Mutex::new(store),
                artifacts_dir: data_dir.join("artifacts"),
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            features::shared::jobs::ipc::job_start,
            features::shared::jobs::ipc::job_cancel,
            features::crypto::ipc::ops::crypto_op,
            features::crypto::ipc::ops::crypto_catalog,
            features::crypto::ipc::ops::recipe_run,
            features::crypto::ipc::ops::kdf_verify,
            features::forensics::ipc::evidence::file_import_dialog,
            features::forensics::ipc::evidence::file_import_derived,
            features::cases::case_list,
            features::cases::case_create,
            features::cases::case_findings_list,
            features::cases::case_events_list,
            features::cases::case_report,
            features::cases::case_provenance_verify,
            features::cases::case_artifact_verify,
            features::cases::case_integrity_verify,
            features::cases::case_provenance_verify_against,
            features::cases::case_findings_add,
            features::shared::session::case_session_select_v1,
            features::shared::session::case_session_clear_v1,
            features::shared::session::case_session_status_v1,
            features::shared::web_consent::web_capture_consent_start_v1,
            features::shared::web_consent::web_capture_consent_revoke_v1,
            features::shared::web_consent::web_capture_consent_status_v1,
            features::cases::scoped::case_search_scoped_v1,
            features::cases::scoped::case_lineage_scoped_v1,
            features::cases::scoped::case_resume_scoped_v1,
            features::cases::scoped::case_evidence_review_scoped_v1,
            features::cases::scoped::case_integrity_scoped_v1,
            features::cases::scoped::case_artifact_reference_scoped_v1,
            features::cases::scoped::case_copy_artifact_to_existing_v1,
            features::cases::temporary::case_temp_stage_sha256_v1,
            features::cases::temporary::case_temp_overview_v1,
            features::cases::temporary::case_temp_discard_v1,
            features::cases::temporary::case_temp_promote_v1,
            features::cases::temporary::case_unregistered_folders_review_v1,
            features::forensics::ipc::evidence::file_list,
            features::forensics::ipc::evidence::file_hex,
            features::forensics::ipc::evidence::file_signature_scan,
            features::forensics::ipc::evidence::file_carve_preview,
            features::forensics::ipc::evidence::file_binary_inspect,
            features::forensics::ipc::evidence::file_extract_gzip,
            features::forensics::ipc::evidence::file_extract_archive,
            features::forensics::ipc::evidence::file_extract_nested_archive,
            features::forensics::ipc::evidence::file_strings,
            features::forensics::ipc::evidence::file_strings_scan,
            features::forensics::ipc::evidence::file_entropy_regions,
            features::forensics::ipc::evidence::file_metadata_scan,
            features::forensics::ipc::evidence::file_yara_subset_scan,
            features::forensics::ipc::evidence::digest_file_dialog,
            features::network::ipc::pcap::pcap_open_dialog,
            features::network::ipc::pcap::pcap_packet_bytes,
            features::network::ipc::pcap::pcap_open_case_v1,
            features::network::ipc::pcap::pcap_case_packet_bytes_v1,
            features::network::ipc::pcap::pcap_case_follow_stream_v1,
            features::network::ipc::pcap::pcap_follow_stream,
            features::network::ipc::capture::capture_interfaces_v1,
            features::network::ipc::capture::capture_start_v1,
            features::network::ipc::capture::capture_stop_v1,
            features::network::ipc::capture::capture_status_v1,
            features::network::ipc::capture::capture_hosts_v1,
            features::network::ipc::capture::capture_flows_v1,
            features::network::ipc::capture::capture_provenance_v1,
            features::network::ipc::capture::capture_frame_page_v1,
            features::network::ipc::capture::capture_save_v1,
            features::network::ipc::capture::capture_packet_details_v1,
            features::network::ipc::capture::capture_follow_stream_v1,
            features::crypto::ipc::crack::crack_wordlist_dialog,
            features::crypto::ipc::crack::pick_wordlist,
            features::crypto::ipc::history::crack_history_list,
            features::crypto::ipc::history::crack_history_delete,
            features::crypto::ipc::history::crack_history_clear,
            features::crypto::ipc::attack::crack_rules_dialog,
            features::crypto::ipc::attack::crack_mask,
            features::crypto::ipc::attack::crack_hybrid_dialog,
            features::crypto::ipc::attack::crack_hybrid_reverse_dialog,
            features::crypto::ipc::attack::crack_combinator_dialog,
            features::crypto::ipc::attack::benchmark,
            features::crypto::ipc::attack::device_info,
            features::crypto::ipc::recovery::recovery_devices_v1,
            features::crypto::ipc::recovery::recovery_select_wordlist_v1,
            features::crypto::ipc::recovery::recovery_wordlist_status_v1,
            features::crypto::ipc::recovery::recovery_start_v1,
            features::crypto::ipc::recovery::recovery_hashcat_capabilities_v1,
            features::crypto::ipc::recovery::recovery_start_hashcat_v1,
            features::crypto::ipc::recovery::recovery_cancel_v1,
            features::crypto::ipc::recovery::recovery_status_v1,
            features::crypto::ipc::recovery::recovery_discard_v1,
            features::crypto::ipc::recovery::recovery_reveal_v1,
            features::crypto::ipc::engines::engines_detect,
            features::crypto::ipc::engines::engine_attack,
            features::shared::http_authority::http_send_scoped,
            features::web::ipc::web::web_scan,
            features::web::ipc::web::spider_scan,
            features::web::ipc::web::proxy_start,
            features::web::ipc::web::proxy_stop,
            features::web::ipc::web::proxy_status,
            features::web::ipc::web::proxy_history,
            // New backend-selected, OS-confirmed one-time History access.
            // Legacy proxy_history_detail/capture_configure remain unregistered.
            features::web::ipc::web::web_history_access_v1,
            features::web::ipc::web::assessment_jobs::web_assessment_start_v1,
            features::web::ipc::web::assessment_jobs::web_assessment_status_v1,
            features::web::ipc::web::assessment_jobs::web_assessment_cancel_v1,
            // Backend-selected case/revision and completed native job only.
            features::web::ipc::web::assessment_jobs::web_assessment_save_findings_v1,
            // Passive history rules: backend case/grant only, no active network request.
            features::web::ipc::web::assessment_jobs::web_passive_rules_v1,
            features::web::ipc::web::assessment_jobs::web_passive_start_v1,
            features::web::ipc::web::proxy_intercept,
            features::web::ipc::web::proxy_pending,
            features::web::ipc::web::proxy_forward,
            features::web::ipc::web::proxy_drop,
            features::web::ipc::web::proxy_set_rules,
            features::web::ipc::web::proxy_ca_pem,
            features::web::ipc::web::ws_list,
            features::web::ipc::web::web_engines_detect,
            features::web::ipc::web::engine_scan,
            features::network::ipc::netscan::netscan_start,
            features::network::ipc::netscan::netscan_udp_start_v1,
            features::network::ipc::netscan::netscan_stop,
            features::network::ipc::netscan::netscan_results,
            features::network::ipc::netscan::netscan_observations_v1,
            features::network::ipc::netscan::netscan_status,
            features::network::ipc::netscan::netscan_history,
            features::network::ipc::netscan::netscan_export,
            features::network::ipc::netscan::netscan_discover_hosts,
        ])
        .run(tauri::generate_context!())
        .expect("CyberDeck desktop runtime failed to start");
}
