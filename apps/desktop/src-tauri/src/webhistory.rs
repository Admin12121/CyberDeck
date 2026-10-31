//! Bounded, case-isolated, volatile HTTP history. Disabled until explicit opt-in.
//! Snapshots preserve logical HTTP message bytes, not chunk framing/socket bytes.
use std::collections::VecDeque;
use base64::Engine as _;
use serde::Serialize;

const MAX_ENTRIES: usize = 64;
const MAX_RETAINED: usize = 2 * 1024 * 1024;
const MAX_BODY: usize = 64 * 1024;
const MAX_HEADER: usize = 32 * 1024;

struct Entry {
    id: u64, url: String, head: String, request: Vec<u8>,
    status: u16, headers: Vec<(String,String)>, response: Vec<u8>,
    request_truncated: bool, response_truncated: bool, charge: usize,
}
impl Entry {
    fn erase(&mut self) {
        self.request.fill(0); self.response.fill(0);
        self.head.clear(); self.url.clear(); self.headers.clear();
    }
}

#[derive(Default)]
pub struct HistoryStore {
    case_id: Option<String>,
    generation: u64,
    entries: VecDeque<Entry>,
    bytes: usize,
}

#[derive(Debug, Serialize)]
pub struct Detail {
    pub id: u64, pub url: String, pub request_head: String,
    pub request_body_base64: Option<String>, pub status: u16,
    pub response_headers: Vec<(String, String)>,
    pub response_body_base64: Option<String>,
    pub request_truncated: bool, pub response_truncated: bool,
    pub decoded_message: bool,
}

fn secret_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(n.as_str(), "authorization" | "proxy-authorization" | "cookie" |
        "set-cookie" | "x-api-key" | "x-auth-token" | "www-authenticate" |
        "proxy-authenticate" | "x-csrf-token" | "x-xsrf-token")
        || ["token","secret","password","credential"].iter().any(|v| n.contains(v))
}

/// Only narrow non-credential metadata is displayed without a reveal.
/// Values such as Referer, Location, WWW-Authenticate, or unknown headers
/// can carry bearer tokens, even when their names look innocuous.
fn safe_metadata(name: &str) -> bool {
    matches!(name.to_ascii_lowercase().as_str(),
        "content-type" | "content-length" | "accept" | "accept-encoding" |
        "cache-control" | "x-content-type-options")
}

fn redacted_head(head: &str) -> String {
    let mut result = String::new();
    let mut lines = head.split("\r\n");
    let method = lines.next().unwrap_or("HTTP").split_whitespace().next().unwrap_or("HTTP");
    result.push_str(method);
    result.push_str(" [target withheld] HTTP/1.1\r\n");
    for line in lines {
        if line.is_empty() { break; }
        if let Some((name,value)) = line.split_once(':') {
            result.push_str(name);
            result.push_str(": ");
            result.push_str(if secret_header(name) || !safe_metadata(name) { "[redacted]" } else { value.trim() });
            result.push_str("\r\n");
        }
    }
    result
}

impl HistoryStore {
    pub fn new() -> Self { Self::default() }
    pub fn enabled(&self) -> bool { self.case_id.is_some() }
    pub fn generation(&self) -> Option<u64> { self.enabled().then_some(self.generation) }
    pub fn configure(&mut self, case_id: Option<&str>) -> Result<(), String> {
        if let Some(id) = case_id {
            if id.is_empty() || id.len() > 128 || id.chars().any(char::is_control) {
                return Err("invalid case identifier".to_string());
            }
        }
        self.clear();
        self.case_id = case_id.map(str::to_string);
        Ok(())
    }
    pub fn clear(&mut self) {
        for entry in &mut self.entries { entry.erase(); }
        self.entries.clear(); self.bytes = 0; self.case_id = None;
        self.generation = self.generation.wrapping_add(1);
    }
    /// Never promote an old in-flight request to a newly selected case.
    pub fn record_at(&mut self, stamp: Option<u64>, id: u64, url: &str,
                     head: &str, request: &[u8], status: u16,
                     headers: &[(String,String)], response: &[u8]) {
        if stamp.is_none() || stamp != self.generation() { return; }
        self.record(id, url, head, request, status, headers, response);
    }
    pub fn record(&mut self, id: u64, url: &str, head: &str, request: &[u8],
                  status: u16, headers: &[(String,String)], response: &[u8]) {
        if !self.enabled() || url.len() > 4096 || head.len() > MAX_HEADER { return; }
        let req = request.len().min(MAX_BODY);
        let resp = response.len().min(MAX_BODY);
        let charge = url.len().saturating_add(head.len()).saturating_add(req)
            .saturating_add(resp).saturating_add(headers.iter().map(|(a,b)| a.len()+b.len()).sum::<usize>());
        if charge > MAX_RETAINED { return; }
        while self.entries.len() >= MAX_ENTRIES || self.bytes.saturating_add(charge) > MAX_RETAINED {
            let Some(mut evicted) = self.entries.pop_front() else { break };
            self.bytes = self.bytes.saturating_sub(evicted.charge);
            evicted.erase();
        }
        self.entries.push_back(Entry { id, url:url.into(), head:head.into(),
            request:request[..req].into(), status, headers:headers.to_vec(),
            response:response[..resp].into(), request_truncated:request.len()>MAX_BODY,
            response_truncated:response.len()>MAX_BODY, charge });
        self.bytes += charge;
    }
    pub fn detail(&self, case_id: &str, id: u64, reveal: bool) -> Option<Detail> {
        if self.case_id.as_deref() != Some(case_id) { return None; }
        let item = self.entries.iter().find(|x| x.id == id)?;
        let codec = base64::engine::general_purpose::STANDARD;
        Some(Detail {
            id, url: if reveal {item.url.clone()} else {"[target withheld]".into()},
            request_head: if reveal {item.head.clone()} else {redacted_head(&item.head)},
            request_body_base64: reveal.then(|| codec.encode(&item.request)),
            status:item.status,
            response_headers: item.headers.iter().map(|(name, value)|
                (name.clone(), if !reveal && (secret_header(name) || !safe_metadata(name)) {"[redacted]".into()} else {value.clone()})).collect(),
            response_body_base64:reveal.then(|| codec.encode(&item.response)),
            request_truncated:item.request_truncated, response_truncated:item.response_truncated,
            decoded_message:true,
        })
    }
    pub fn len(&self) -> usize { self.entries.len() }
}

/// A single desktop-process store, switched off by default. Configuration
/// and reading stay unregistered until the UI/case-retention contract is approved.
fn global() -> &'static std::sync::Mutex<HistoryStore> {
    static STORE: std::sync::OnceLock<std::sync::Mutex<HistoryStore>> = std::sync::OnceLock::new();
    STORE.get_or_init(|| std::sync::Mutex::new(HistoryStore::new()))
}
pub fn clear_session() { global().lock().expect("web history poisoned").clear(); }
pub fn configure_session(case_id: Option<&str>) -> Result<(), String> {
    global().lock().expect("web history poisoned").configure(case_id)
}
pub fn capture_generation() -> Option<u64> {
    global().lock().expect("web history poisoned").generation()
}
pub fn capture(stamp: Option<u64>, id: u64, url: &str, head: &str, req: &[u8],
               status: u16, headers: &[(String,String)], resp: &[u8]) {
    global().lock().expect("web history poisoned")
        .record_at(stamp, id, url, head, req, status, headers, resp);
}
pub fn read_detail(case_id: &str, id: u64, reveal: bool) -> Option<Detail> {
    global().lock().expect("web history poisoned").detail(case_id, id, reveal)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn off_by_default_and_isolated_by_case() {
        let mut store=HistoryStore::new();
        store.record(1,"http://x","GET / HTTP/1.1\r\n\r\n",b"a",200,&[],b"b");
        assert_eq!(store.len(),0);
        store.configure(Some("a")).unwrap();
        store.record(1,"http://x","GET / HTTP/1.1\r\n\r\n",b"a",200,&[],b"b");
        assert!(store.detail("b",1,true).is_none());
        store.configure(Some("b")).unwrap();
        assert!(store.detail("a",1,true).is_none());
        assert_eq!(store.len(),0);
    }
    #[test]
    fn safe_view_never_serializes_secrets_or_bodies() {
        let mut store=HistoryStore::new(); store.configure(Some("a")).unwrap();
        store.record(2,"http://x/?token=secret",
            "POST /?token=secret HTTP/1.1\r\nAuthorization: Bearer secret\r\nCookie: session=secret\r\nX-Api-Key: secret\r\nReferer: http://evil/?s=secret\r\n\r\n",
            b"password=secret",200,&[("Set-Cookie".into(),"session=secret".into()),("Location".into(),"https://x/?token=secret".into())],b"secret");
        let view=store.detail("a",2,false).unwrap();
        let json=serde_json::to_string(&view).unwrap();
        assert!(!json.contains("secret"),"{json}");
        assert!(view.request_body_base64.is_none());
        assert!(view.response_body_base64.is_none());
    }
    #[test]
    fn reveal_preserves_binary_and_flags_truncation() {
        let mut store=HistoryStore::new(); store.configure(Some("a")).unwrap();
        store.record(3,"http://x","POST / HTTP/1.1\r\n\r\n",&[0xff,0,0x7f],
            201,&[],&vec![0xab;MAX_BODY+1]);
        let view=store.detail("a",3,true).unwrap();
        assert_eq!(base64::engine::general_purpose::STANDARD.decode(view.request_body_base64.unwrap()).unwrap(),vec![0xff,0,0x7f]);
        assert!(view.response_truncated);
        assert_eq!(base64::engine::general_purpose::STANDARD.decode(view.response_body_base64.unwrap()).unwrap().len(),MAX_BODY);
    }
    #[test]
    fn inflight_completion_cannot_leak_to_new_case_or_new_session() {
        let mut store = HistoryStore::new();
        store.configure(Some("case-a")).unwrap();
        let old = store.generation();
        store.configure(Some("case-b")).unwrap();
        store.record_at(old, 10, "http://a", "POST / HTTP/1.1\r\n\r\n", b"secret", 200, &[], b"secret");
        assert_eq!(store.len(), 0);
        let active = store.generation();
        store.record_at(active, 11, "http://b", "GET / HTTP/1.1\r\n\r\n", b"", 200, &[], b"ok");
        assert_eq!(store.len(), 1);
        store.configure(None).unwrap();
        store.configure(Some("case-b")).unwrap();
        store.record_at(active, 12, "http://b", "GET / HTTP/1.1\r\n\r\n", b"", 200, &[], b"stale");
        assert_eq!(store.len(), 0);
        store.record_at(None, 13, "http://b", "GET / HTTP/1.1\r\n\r\n", b"", 200, &[], b"stale");
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn retention_cap_and_invalid_case_rejection() {
        let mut store=HistoryStore::new(); store.configure(Some("a")).unwrap();
        assert!(store.configure(Some("bad\ncase")).is_err());
        for i in 0..90 { store.record(i,"http://x","GET / HTTP/1.1\r\n\r\n",b"",200,&[],b""); }
        assert_eq!(store.len(),MAX_ENTRIES);
        assert!(store.detail("a",0,true).is_none());
        assert!(store.detail("a",89,true).is_some());
    }
}
