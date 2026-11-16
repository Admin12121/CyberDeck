pub mod arp_discovery;
pub mod capture;
// coordinator-insert (DNS spoof slice): gated DNS responder IPC
pub mod dns_spoof;
pub mod icmp_echo;
pub mod netscan;
pub mod network_lab;
pub mod network_lab_live;
pub mod network_lab_report;
pub mod network_lab_spoof;
pub mod network_lab_targeting;
pub mod operation_gate;
pub mod os_hints_ipc;
pub mod pcap;
pub mod pcap_export;
pub mod scan_depth;
pub mod scan_insights;
pub mod scan_profiles;
pub mod syn_scan;
// coordinator-insert (Wifi monitor slice): monitor-mode capture IPC
pub mod wifi_monitor;
// coordinator-insert (HTTP proxy slice): gated plain-HTTP forward proxy IPC
pub mod http_proxy;
