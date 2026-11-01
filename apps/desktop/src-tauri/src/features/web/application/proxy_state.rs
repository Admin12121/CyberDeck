//! Proxy lifetime, pending decisions and volatile session state.
use super::proxy_stream_infrastructure::ProxyStream;
use super::{CapturedRequest, MatchReplaceRule};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64};
use std::sync::{Arc, Mutex};

/// A request held by the interceptor until forwarded or dropped.
pub struct PendingRequest {
    pub stream: ProxyStream,
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub info: CapturedRequest,
    /// Original HTTP request header (before user match/replace rules).
    pub original_head: String,
    pub history_stamp: Option<u64>,
}

pub struct ProxyShared {
    pub running: AtomicBool,
    pub intercept: AtomicBool,
    pub port: AtomicU16,
    pub rules: Mutex<Vec<MatchReplaceRule>>,
    pub captured: Mutex<Vec<CapturedRequest>>,
    pub pending: Mutex<HashMap<u64, PendingRequest>>,
    pub next_id: AtomicU64,
    /// CA state for TLS interception, set by proxy_start.
    pub ca: Mutex<Option<Arc<crate::features::web::webtls::CaState>>>,
    /// Relayed WebSocket connections, recorded during TLS interception.
    pub ws: Mutex<Vec<crate::features::web::webtls::WsConnection>>,
}

pub struct WebCtx {
    pub proxy_running: AtomicBool,
    pub proxy_port: AtomicU16,
    pub proxy_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    pub shared: Arc<ProxyShared>,
    pub ca: Mutex<Option<Arc<crate::features::web::webtls::CaState>>>,
}
