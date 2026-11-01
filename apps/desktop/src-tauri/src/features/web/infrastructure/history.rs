//! Bounded, case-isolated, volatile HTTP history. Disabled until explicit opt-in.
//! Snapshots preserve logical HTTP message bytes, not chunk framing/socket bytes.
use base64::Engine as _;
use cyberdeck_storage::{
    ActiveCaseHistoryPolicy, HistoryCaptureGrant, HistoryRetentionLimits, HistoryRevealPermit,
};
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

const MAX_ENTRIES: usize = 64;
const MAX_RETAINED: usize = 2 * 1024 * 1024;
const MAX_BODY: usize = 64 * 1024;
const MAX_HEADER: usize = 32 * 1024;

/// Best-effort overwrite of the owned live UTF-8 bytes before deallocation.
/// This does not guarantee erasure of earlier copies or physical memory.
fn clear_sensitive_text(text: &mut String) {
    let mut bytes = std::mem::take(text).into_bytes();
    bytes.fill(0);
}

fn clear_sensitive_headers(headers: &mut Vec<(String, String)>) {
    for (name, value) in headers.iter_mut() {
        clear_sensitive_text(name);
        clear_sensitive_text(value);
    }
    headers.clear();
}

struct Entry {
    id: u64,
    url: String,
    head: String,
    request: Vec<u8>,
    status: u16,
    headers: Vec<(String, String)>,
    response: Vec<u8>,
    request_truncated: bool,
    response_truncated: bool,
    charge: usize,
    forwarded: Option<ForwardedSnapshot>,
}
impl Entry {
    fn erase(&mut self) {
        self.request.fill(0);
        self.response.fill(0);
        clear_sensitive_text(&mut self.head);
        clear_sensitive_text(&mut self.url);
        clear_sensitive_headers(&mut self.headers);
        if let Some(forwarded) = self.forwarded.as_mut() {
            forwarded.erase();
        }
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.erase();
    }
}

#[derive(Default)]
pub struct HistoryStore {
    case_id: Option<String>,
    generation: u64,
    entries: VecDeque<Entry>,
    bytes: usize,
    limits: HistoryRetentionLimits,
}

/// The request as received from the browser before any match-and-replace
/// rules. Only a bounded body prefix is copied, and only with capture consent.
pub struct OriginalSnapshot {
    url: String,
    body_prefix: Vec<u8>,
    body_original_len: usize,
}
/// Logical HTTP request actually passed into the transport after edits.
/// NOT an exact HTTP/1.1 wire representation: reqwest normalizes framing.
#[derive(Debug)]
pub struct ForwardedSnapshot {
    method: String,
    url: String,
    headers: Vec<(String, String)>,
    body_prefix: Vec<u8>,
    body_original_len: usize,
}
impl ForwardedSnapshot {
    fn erase(&mut self) {
        self.body_prefix.fill(0);
        clear_sensitive_text(&mut self.method);
        clear_sensitive_text(&mut self.url);
        clear_sensitive_headers(&mut self.headers);
    }
}
impl Drop for ForwardedSnapshot {
    fn drop(&mut self) {
        self.erase();
    }
}

pub fn snapshot_forwarded(
    stamp: Option<u64>,
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Option<ForwardedSnapshot> {
    stamp?;
    if url.len() > 4096
        || method.len() > 32
        || headers
            .iter()
            .map(|(name, value)| name.len().saturating_add(value.len()))
            .sum::<usize>()
            > MAX_HEADER
    {
        return None;
    }
    Some(ForwardedSnapshot {
        method: method.to_owned(),
        url: url.to_owned(),
        headers: headers.to_vec(),
        body_prefix: body[..body.len().min(MAX_BODY)].to_vec(),
        body_original_len: body.len(),
    })
}

impl Drop for OriginalSnapshot {
    fn drop(&mut self) {
        self.body_prefix.fill(0);
        clear_sensitive_text(&mut self.url);
    }
}

pub fn snapshot_original(stamp: Option<u64>, url: &str, body: &[u8]) -> Option<OriginalSnapshot> {
    stamp?;
    Some(OriginalSnapshot {
        url: url.to_string(),
        body_prefix: body[..body.len().min(MAX_BODY)].to_vec(),
        body_original_len: body.len(),
    })
}

#[derive(Debug, Serialize)]
pub struct Detail {
    pub id: u64,
    pub url: String,
    pub request_head: String,
    pub request_body_base64: Option<String>,
    pub status: u16,
    pub response_headers: Vec<(String, String)>,
    pub response_body_base64: Option<String>,
    pub request_truncated: bool,
    pub response_truncated: bool,
    pub decoded_message: bool,
    /// Only populated after server-side case authorization and reveal.
    pub forwarded_method: Option<String>,
    pub forwarded_url: Option<String>,
    pub forwarded_headers: Option<Vec<(String, String)>>,
    pub forwarded_body_base64: Option<String>,
    pub forwarded_truncated: bool,
    /// Body bytes are exact, but HTTP headers/framing were normalized.
    pub forwarded_decoded_message: bool,
    pub original_wire_exact: bool,
}

fn secret_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    matches!(
        n.as_str(),
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "x-api-key"
            | "x-auth-token"
            | "www-authenticate"
            | "proxy-authenticate"
            | "x-csrf-token"
            | "x-xsrf-token"
    ) || ["token", "secret", "password", "credential"]
        .iter()
        .any(|v| n.contains(v))
}

/// Only narrow non-credential metadata is displayed without a reveal.
/// Values such as Referer, Location, WWW-Authenticate, or unknown headers
/// can carry bearer tokens, even when their names look innocuous.
fn safe_metadata(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "content-type"
            | "content-length"
            | "accept"
            | "accept-encoding"
            | "cache-control"
            | "x-content-type-options"
    )
}

fn redacted_head(head: &str) -> String {
    let mut result = String::new();
    let mut lines = head.split("\r\n");
    let method = lines
        .next()
        .unwrap_or("HTTP")
        .split_whitespace()
        .next()
        .unwrap_or("HTTP");
    result.push_str(method);
    result.push_str(" [target withheld] HTTP/1.1\r\n");
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            result.push_str(name);
            result.push_str(": ");
            result.push_str(if secret_header(name) || !safe_metadata(name) {
                "[redacted]"
            } else {
                value.trim()
            });
            result.push_str("\r\n");
        }
    }
    result
}

impl HistoryStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn enabled(&self) -> bool {
        self.case_id.is_some()
    }
    pub fn generation(&self) -> Option<u64> {
        self.enabled().then_some(self.generation)
    }
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
        for entry in &mut self.entries {
            entry.erase();
        }
        self.entries.clear();
        self.bytes = 0;
        self.limits = HistoryRetentionLimits::default();
        if let Some(mut case_id) = self.case_id.take() {
            clear_sensitive_text(&mut case_id);
        }
        self.generation = self.generation.wrapping_add(1);
    }
    /// Never promote an old in-flight request to a newly selected case.
    pub fn record_at(
        &mut self,
        stamp: Option<u64>,
        id: u64,
        url: &str,
        head: &str,
        request: &[u8],
        original_body_len: usize,
        status: u16,
        headers: &[(String, String)],
        response: &[u8],
    ) {
        if stamp.is_none() || stamp != self.generation() {
            return;
        }
        self.record_with_length(
            id,
            url,
            head,
            request,
            original_body_len,
            status,
            headers,
            response,
        );
    }
    pub fn record(
        &mut self,
        id: u64,
        url: &str,
        head: &str,
        request: &[u8],
        status: u16,
        headers: &[(String, String)],
        response: &[u8],
    ) {
        self.record_with_length(
            id,
            url,
            head,
            request,
            request.len(),
            status,
            headers,
            response,
        );
    }
    fn record_with_length(
        &mut self,
        id: u64,
        url: &str,
        head: &str,
        request: &[u8],
        original_body_len: usize,
        status: u16,
        headers: &[(String, String)],
        response: &[u8],
    ) {
        if !self.enabled() || url.len() > 4096 || head.len() > MAX_HEADER {
            return;
        }
        let max_body = MAX_BODY.min(self.limits.max_body_bytes);
        let req = request.len().min(max_body);
        let resp = response.len().min(max_body);
        let charge = url
            .len()
            .saturating_add(head.len())
            .saturating_add(req)
            .saturating_add(resp)
            .saturating_add(
                headers
                    .iter()
                    .map(|(a, b)| a.len() + b.len())
                    .sum::<usize>(),
            );
        if charge > MAX_RETAINED.min(self.limits.max_total_bytes) {
            return;
        }
        while self.entries.len() >= MAX_ENTRIES.min(self.limits.max_entries)
            || self.bytes.saturating_add(charge) > MAX_RETAINED.min(self.limits.max_total_bytes)
        {
            let Some(mut evicted) = self.entries.pop_front() else {
                break;
            };
            self.bytes = self.bytes.saturating_sub(evicted.charge);
            evicted.erase();
        }
        self.entries.push_back(Entry {
            id,
            url: url.into(),
            head: head.into(),
            request: request[..req].into(),
            status,
            headers: headers.to_vec(),
            response: response[..resp].into(),
            request_truncated: original_body_len > max_body,
            response_truncated: response.len() > max_body,
            charge,
            forwarded: None,
        });
        self.bytes += charge;
    }
    /// Attach provenance only when both original and forwarded data fit the
    /// current backend retention budget; never silently claim an absent draft.
    pub fn attach_forwarded(&mut self, stamp: Option<u64>, id: u64, mut draft: ForwardedSnapshot) {
        if stamp.is_none() || stamp != self.generation() {
            return;
        }
        let max_body = MAX_BODY.min(self.limits.max_body_bytes);
        draft.body_prefix.truncate(max_body);
        let extra = draft
            .method
            .len()
            .saturating_add(draft.url.len())
            .saturating_add(draft.body_prefix.len())
            .saturating_add(
                draft
                    .headers
                    .iter()
                    .map(|(a, b)| a.len().saturating_add(b.len()))
                    .sum::<usize>(),
            );
        let limit = MAX_RETAINED.min(self.limits.max_total_bytes);
        if extra > limit {
            return;
        }
        while self.bytes.saturating_add(extra) > limit && self.entries.len() > 1 {
            if let Some(mut old) = self.entries.pop_front() {
                self.bytes = self.bytes.saturating_sub(old.charge);
                old.erase();
            }
        }
        if self.bytes.saturating_add(extra) > limit {
            return;
        }
        if let Some(last) = self
            .entries
            .back_mut()
            .filter(|e| e.id == id && e.forwarded.is_none())
        {
            last.forwarded = Some(draft);
            last.charge = last.charge.saturating_add(extra);
            self.bytes = self.bytes.saturating_add(extra);
        }
    }

    /// Return a logical decoded request draft. Not socket framing. Truncated
    /// payloads cannot be replayed because that would change the request.
    pub fn replay_draft(
        &self,
        case_id: &str,
        id: u64,
        forwarded: bool,
    ) -> Result<super::repeater_application::BinaryReplayRequest, String> {
        if self.case_id.as_deref() != Some(case_id) {
            return Err("case mismatch".into());
        }
        let item = self
            .entries
            .iter()
            .find(|e| e.id == id)
            .ok_or("history entry missing")?;
        if forwarded {
            let draft = item
                .forwarded
                .as_ref()
                .ok_or("forwarded provenance missing")?;
            if draft.body_original_len != draft.body_prefix.len() {
                return Err("cannot replay truncated forwarded message".into());
            }
            return Ok(super::repeater_application::BinaryReplayRequest {
                method: draft.method.clone(),
                url: draft.url.clone(),
                headers: draft.headers.clone(),
                body: draft.body_prefix.clone(),
            });
        }
        if item.request_truncated {
            return Err("cannot replay truncated original message".into());
        }
        let mut lines = item.head.split("\r\n");
        let request_line = lines.next().ok_or("missing original request line")?;
        let method = request_line
            .split_ascii_whitespace()
            .next()
            .ok_or("missing original method")?;
        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            let (name, value) = line.split_once(':').ok_or("invalid original header")?;
            headers.push((name.to_string(), value.trim().to_string()));
        }
        Ok(super::repeater_application::BinaryReplayRequest {
            method: method.into(),
            url: item.url.clone(),
            headers,
            body: item.request.clone(),
        })
    }

    pub fn detail(&self, case_id: &str, id: u64, reveal: bool) -> Option<Detail> {
        if self.case_id.as_deref() != Some(case_id) {
            return None;
        }
        let item = self.entries.iter().find(|x| x.id == id)?;
        let codec = base64::engine::general_purpose::STANDARD;
        Some(Detail {
            id,
            url: if reveal {
                item.url.clone()
            } else {
                "[target withheld]".into()
            },
            request_head: if reveal {
                item.head.clone()
            } else {
                redacted_head(&item.head)
            },
            request_body_base64: reveal.then(|| codec.encode(&item.request)),
            status: item.status,
            response_headers: item
                .headers
                .iter()
                .map(|(name, value)| {
                    (
                        name.clone(),
                        if !reveal && (secret_header(name) || !safe_metadata(name)) {
                            "[redacted]".into()
                        } else {
                            value.clone()
                        },
                    )
                })
                .collect(),
            response_body_base64: reveal.then(|| codec.encode(&item.response)),
            request_truncated: item.request_truncated,
            response_truncated: item.response_truncated,
            decoded_message: true,
            forwarded_method: reveal
                .then(|| item.forwarded.as_ref().map(|f| f.method.clone()))
                .flatten(),
            forwarded_url: reveal
                .then(|| item.forwarded.as_ref().map(|f| f.url.clone()))
                .flatten(),
            forwarded_headers: reveal
                .then(|| item.forwarded.as_ref().map(|f| f.headers.clone()))
                .flatten(),
            forwarded_body_base64: reveal
                .then(|| {
                    item.forwarded
                        .as_ref()
                        .map(|f| codec.encode(&f.body_prefix))
                })
                .flatten(),
            forwarded_truncated: item
                .forwarded
                .as_ref()
                .is_some_and(|f| f.body_original_len > f.body_prefix.len()),
            forwarded_decoded_message: item.forwarded.is_some(),
            original_wire_exact: false,
        })
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// An active backend grant is authoritative, never a caller-supplied case
/// identifier. Lock order: this BoundHistory mutex, then backend policy mutex.
/// Integration must not call revoke/clear_session while retaining the policy lock.
struct BackendBinding {
    policy: Arc<Mutex<ActiveCaseHistoryPolicy>>,
    grant: HistoryCaptureGrant,
}

#[derive(Default)]
struct BoundHistory {
    store: HistoryStore,
    binding: Option<BackendBinding>,
}

impl BoundHistory {
    fn authorized_ids(&mut self) -> std::collections::HashSet<u64> {
        if self.authorized().is_none() {
            return std::collections::HashSet::new();
        }
        self.store.entries.iter().map(|entry| entry.id).collect()
    }

    fn wipe_local(&mut self) {
        self.binding.take();
        self.store.clear();
    }

    fn clear(&mut self) {
        if let Some(binding) = self.binding.take() {
            // Revoking a stale local grant must never revoke a NEW backend
            // case/consent generation created by Agent5 in the meantime.
            let mut policy = binding.policy.lock().expect("case policy poisoned");
            if policy
                .authorize_capture(&binding.grant.case_id, binding.grant.generation)
                .is_ok()
            {
                policy.revoke();
            }
        }
        self.store.clear();
    }

    fn arm(
        &mut self,
        policy: Arc<Mutex<ActiveCaseHistoryPolicy>>,
        grant: HistoryCaptureGrant,
    ) -> Result<u64, String> {
        grant.limits.validate()?;
        {
            let guard = policy.lock().map_err(|_| "case policy poisoned")?;
            let current = guard.authorize_capture(&grant.case_id, grant.generation)?;
            if current != grant {
                return Err("capture grant does not match backend authorization".into());
            }
        }
        if self
            .binding
            .as_ref()
            .is_some_and(|old| Arc::ptr_eq(&old.policy, &policy))
        {
            // Case switch or re-consent with the same authoritative policy.
            // Its new generation was already validated above.
            self.wipe_local();
        } else {
            self.clear();
        }
        {
            let guard = policy.lock().map_err(|_| "case policy poisoned")?;
            if guard.authorize_capture(&grant.case_id, grant.generation)? != grant {
                return Err("capture grant invalidated during handoff".into());
            }
        }
        self.store.configure(Some(&grant.case_id))?;
        self.store.limits = grant.limits;
        let generation = self.store.generation().ok_or("capture not enabled")?;
        self.binding = Some(BackendBinding { policy, grant });
        Ok(generation)
    }

    fn authorized(&mut self) -> Option<u64> {
        let binding = self.binding.as_ref()?;
        let valid = binding
            .policy
            .lock()
            .ok()
            .and_then(|p| {
                p.authorize_capture(&binding.grant.case_id, binding.grant.generation)
                    .ok()
            })
            .map(|g| g == binding.grant)
            .unwrap_or(false);
        if !valid {
            // Expiry/revocation may have already transitioned the policy to
            // a newer case. Only erase our obsolete local generation.
            self.wipe_local();
            return None;
        }
        self.store.generation()
    }

    fn capture(
        &mut self,
        stamp: Option<u64>,
        id: u64,
        original: OriginalSnapshot,
        head: &str,
        status: u16,
        headers: &[(String, String)],
        response: &[u8],
        forwarded: Option<ForwardedSnapshot>,
    ) {
        if stamp.is_none() || self.store.generation() != stamp {
            return;
        }
        let valid = if let Some(binding) = self.binding.as_ref() {
            if let Ok(policy) = binding.policy.lock() {
                let valid = policy
                    .authorize_capture(&binding.grant.case_id, binding.grant.generation)
                    .is_ok_and(|grant| grant == binding.grant);
                if valid {
                    // Policy lock is held until both bodies are written;
                    // case revoke cannot interleave with a stale capture.
                    self.store.record_at(
                        stamp,
                        id,
                        &original.url,
                        head,
                        &original.body_prefix,
                        original.body_original_len,
                        status,
                        headers,
                        response,
                    );
                    if let Some(forwarded) = forwarded {
                        self.store.attach_forwarded(stamp, id, forwarded);
                    }
                }
                valid
            } else {
                false
            }
        } else {
            false
        };
        if !valid {
            self.wipe_local();
        }
    }

    /// Redacted metadata is available with a valid grant. Sensitive reveal
    /// requires a separately verified backend-grant path, never a UI boolean.
    fn detail(&mut self, case_id: &str, id: u64) -> Option<Detail> {
        let binding = self.binding.as_ref()?;
        if binding.grant.case_id != case_id {
            return None;
        }
        let (valid, result) = {
            let policy = binding.policy.lock().ok()?;
            let valid = policy.authorize_grant(&binding.grant).is_ok();
            (
                valid,
                if valid {
                    self.store.detail(case_id, id, false)
                } else {
                    None
                },
            )
        };
        if !valid {
            self.wipe_local();
        }
        result
    }

    /// Reveal only after Agent5's backend has issued a short-lived, single-use
    /// permit. Consume atomically with reading the binary bytes.
    fn detail_with_permit(
        &mut self,
        grant: &HistoryCaptureGrant,
        permit: HistoryRevealPermit,
        id: u64,
    ) -> Result<Option<Detail>, String> {
        let binding = self
            .binding
            .as_ref()
            .ok_or("backend history consent unavailable")?;
        if binding.grant != *grant {
            return Err("backend history grant mismatch".into());
        }
        let mut policy = binding.policy.lock().map_err(|_| "case policy poisoned")?;
        policy.consume_reveal(grant, permit)?;
        Ok(self.store.detail(&grant.case_id, id, true))
    }

    fn replay_authorized(
        &mut self,
        grant: &HistoryCaptureGrant,
        permit: HistoryRevealPermit,
        id: u64,
        forwarded: bool,
    ) -> Result<super::repeater_application::BinaryReplayRequest, String> {
        let binding = self
            .binding
            .as_ref()
            .ok_or("backend history consent unavailable")?;
        if binding.grant != *grant {
            return Err("backend history grant mismatch".into());
        }
        let mut policy = binding.policy.lock().map_err(|_| "case policy poisoned")?;
        policy.consume_reveal(grant, permit)?;
        // The policy lock remains held while the request body is copied.
        self.store.replay_draft(&grant.case_id, id, forwarded)
    }
}

fn global() -> &'static Mutex<BoundHistory> {
    static STORE: std::sync::OnceLock<Mutex<BoundHistory>> = std::sync::OnceLock::new();
    STORE.get_or_init(|| Mutex::new(BoundHistory::default()))
}

pub fn clear_session() {
    global().lock().expect("web history poisoned").clear();
}

/// One lightweight process worker enforces retention expiry even while no
/// traffic or history lookup is occurring. This does not persist any bytes.
fn ensure_expiry_cleanup() -> Result<(), String> {
    static WORKER: std::sync::OnceLock<Result<(), String>> = std::sync::OnceLock::new();
    WORKER
        .get_or_init(|| {
            std::thread::Builder::new()
                .name("web-history-retention".into())
                .spawn(|| loop {
                    std::thread::sleep(std::time::Duration::from_millis(250));
                    if let Ok(mut bound) = global().lock() {
                        if bound.binding.is_some() {
                            let _ = bound.authorized();
                        }
                    }
                })
                .map(|_| ())
                .map_err(|e| format!("cannot start history retention worker: {e}"))
        })
        .clone()
}

/// Called only by integration AFTER backend case selection and explicit
/// consent. The trusted grant is verified against Agent5's live policy.
/// This does not register or authorize any frontend IPC by itself.
pub(crate) fn arm_backend_capture(
    policy: Arc<Mutex<ActiveCaseHistoryPolicy>>,
    grant: HistoryCaptureGrant,
) -> Result<u64, String> {
    let generation = global()
        .lock()
        .expect("web history poisoned")
        .arm(policy, grant)?;
    if let Err(error) = ensure_expiry_cleanup() {
        clear_session();
        return Err(error);
    }
    Ok(generation)
}

/// The legacy unregistered handler cannot enable capture via its own case_id
/// or boolean; it fails closed until Agent6 replaces its backend contract.
pub fn configure_session(case_id: Option<&str>) -> Result<(), String> {
    if case_id.is_none() {
        clear_session();
        Ok(())
    } else {
        Err("backend active-case authorization is required".into())
    }
}
pub fn capture_generation() -> Option<u64> {
    global().lock().expect("web history poisoned").authorized()
}

/// Redacted listener summaries are visible only for entries accepted into
/// the current backend-consented history generation, never a previous case.
pub(crate) fn authorized_entry_ids() -> std::collections::HashSet<u64> {
    global()
        .lock()
        .expect("web history poisoned")
        .authorized_ids()
}
pub fn capture(
    stamp: Option<u64>,
    id: u64,
    original: Option<OriginalSnapshot>,
    head: &str,
    status: u16,
    headers: &[(String, String)],
    resp: &[u8],
) {
    let Some(original) = original else { return };
    global()
        .lock()
        .expect("web history poisoned")
        .capture(stamp, id, original, head, status, headers, resp, None);
}
/// Capture the original logical browser message and the exact binary body
/// supplied to reqwest after rules. The transport's wire framing is NOT exact.
pub fn capture_forwarded(
    stamp: Option<u64>,
    id: u64,
    original: Option<OriginalSnapshot>,
    head: &str,
    status: u16,
    headers: &[(String, String)],
    resp: &[u8],
    forwarded: Option<ForwardedSnapshot>,
) {
    let Some(original) = original else { return };
    global()
        .lock()
        .expect("web history poisoned")
        .capture(stamp, id, original, head, status, headers, resp, forwarded);
}

/// Backend-only original/forwarded message draft. The grant is reverified
/// when requested; no truncated body is ever exposed for silent replay.
pub(crate) fn replay_draft_authorized(
    grant: &HistoryCaptureGrant,
    permit: HistoryRevealPermit,
    id: u64,
    forwarded: bool,
) -> Result<super::repeater_application::BinaryReplayRequest, String> {
    global()
        .lock()
        .expect("web history poisoned")
        .replay_authorized(grant, permit, id, forwarded)
}

/// Non-sensitive redacted reads only. A caller-provided `reveal=true` is NOT
/// backend authorization, even if an unregistered IPC is accidentally exposed.
pub fn read_detail(case_id: &str, id: u64, reveal: bool) -> Option<Detail> {
    if reveal {
        return None;
    }
    global()
        .lock()
        .expect("web history poisoned")
        .detail(case_id, id)
}
/// Integration-only reveal after a separate authenticated, user-confirmed
/// backend action; this grant must belong to the current case and generation.
pub(crate) fn read_detail_authorized(
    grant: &HistoryCaptureGrant,
    permit: HistoryRevealPermit,
    id: u64,
) -> Result<Option<Detail>, String> {
    global()
        .lock()
        .expect("web history poisoned")
        .detail_with_permit(grant, permit, id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn volatile_confidential_text_and_binary_are_cleared_on_invalidation() {
        let mut entry = Entry {
            id: 42,
            url: "https://host/?token=CONFIDENTIAL".into(),
            head: "Authorization: Bearer CONFIDENTIAL".into(),
            request: b"CONFIDENTIAL-request".to_vec(),
            status: 200,
            headers: vec![("Set-Cookie".into(), "CONFIDENTIAL-cookie".into())],
            response: b"CONFIDENTIAL-response".to_vec(),
            request_truncated: false,
            response_truncated: false,
            charge: 0,
            forwarded: Some(ForwardedSnapshot {
                method: "POST".into(),
                url: "https://host/?secret=CONFIDENTIAL".into(),
                headers: vec![("Authorization".into(), "CONFIDENTIAL".into())],
                body_prefix: b"CONFIDENTIAL-forwarded".to_vec(),
                body_original_len: 21,
            }),
        };
        entry.erase();
        assert!(entry.url.is_empty() && entry.head.is_empty() && entry.headers.is_empty());
        assert!(entry.request.iter().all(|b| *b == 0));
        assert!(entry.response.iter().all(|b| *b == 0));
        let forwarded = entry.forwarded.as_ref().unwrap();
        assert!(forwarded.url.is_empty() && forwarded.headers.is_empty());
        assert!(forwarded.body_prefix.iter().all(|b| *b == 0));

        let mut store = HistoryStore::new();
        store.configure(Some("scratchpad")).unwrap();
        store.record(
            12,
            "http://host/?token=CONFIDENTIAL",
            "GET /?token=CONFIDENTIAL HTTP/1.1\r\nAuthorization: Bearer CONFIDENTIAL\r\n\r\n",
            b"CONFIDENTIAL-request",
            200,
            &[("Set-Cookie".into(), "CONFIDENTIAL".into())],
            b"CONFIDENTIAL-response",
        );
        let view = serde_json::to_string(&store.detail("scratchpad", 12, false).unwrap()).unwrap();
        assert!(!view.contains("CONFIDENTIAL"));
        store.clear();
        assert_eq!(store.len(), 0);
        assert!(store.detail("scratchpad", 12, true).is_none());
    }
    #[test]
    fn off_by_default_and_isolated_by_case() {
        let mut store = HistoryStore::new();
        store.record(
            1,
            "http://x",
            "GET / HTTP/1.1\r\n\r\n",
            b"a",
            200,
            &[],
            b"b",
        );
        assert_eq!(store.len(), 0);
        store.configure(Some("a")).unwrap();
        store.record(
            1,
            "http://x",
            "GET / HTTP/1.1\r\n\r\n",
            b"a",
            200,
            &[],
            b"b",
        );
        assert!(store.detail("b", 1, true).is_none());
        store.configure(Some("b")).unwrap();
        assert!(store.detail("a", 1, true).is_none());
        assert_eq!(store.len(), 0);
    }
    #[test]
    fn safe_view_never_serializes_secrets_or_bodies() {
        let mut store = HistoryStore::new();
        store.configure(Some("a")).unwrap();
        store.record(2,"http://x/?token=secret",
            "POST /?token=secret HTTP/1.1\r\nAuthorization: Bearer secret\r\nCookie: session=secret\r\nX-Api-Key: secret\r\nReferer: http://evil/?s=secret\r\n\r\n",
            b"password=secret",200,&[("Set-Cookie".into(),"session=secret".into()),("Location".into(),"https://x/?token=secret".into())],b"secret");
        let view = store.detail("a", 2, false).unwrap();
        let json = serde_json::to_string(&view).unwrap();
        assert!(!json.contains("secret"), "{json}");
        assert!(view.request_body_base64.is_none());
        assert!(view.response_body_base64.is_none());
    }
    #[test]
    fn reveal_preserves_binary_and_flags_truncation() {
        let mut store = HistoryStore::new();
        store.configure(Some("a")).unwrap();
        store.record(
            3,
            "http://x",
            "POST / HTTP/1.1\r\n\r\n",
            &[0xff, 0, 0x7f],
            201,
            &[],
            &vec![0xab; MAX_BODY + 1],
        );
        let view = store.detail("a", 3, true).unwrap();
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(view.request_body_base64.unwrap())
                .unwrap(),
            vec![0xff, 0, 0x7f]
        );
        assert!(view.response_truncated);
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(view.response_body_base64.unwrap())
                .unwrap()
                .len(),
            MAX_BODY
        );
    }
    #[test]
    fn inflight_completion_cannot_leak_to_new_case_or_new_session() {
        let mut store = HistoryStore::new();
        store.configure(Some("case-a")).unwrap();
        let old = store.generation();
        store.configure(Some("case-b")).unwrap();
        store.record_at(
            old,
            10,
            "http://a",
            "POST / HTTP/1.1\r\n\r\n",
            b"secret",
            6,
            200,
            &[],
            b"secret",
        );
        assert_eq!(store.len(), 0);
        let active = store.generation();
        store.record_at(
            active,
            11,
            "http://b",
            "GET / HTTP/1.1\r\n\r\n",
            b"",
            0,
            200,
            &[],
            b"ok",
        );
        assert_eq!(store.len(), 1);
        store.configure(None).unwrap();
        store.configure(Some("case-b")).unwrap();
        store.record_at(
            active,
            12,
            "http://b",
            "GET / HTTP/1.1\r\n\r\n",
            b"",
            0,
            200,
            &[],
            b"stale",
        );
        assert_eq!(store.len(), 0);
        store.record_at(
            None,
            13,
            "http://b",
            "GET / HTTP/1.1\r\n\r\n",
            b"",
            0,
            200,
            &[],
            b"stale",
        );
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn original_snapshot_preserves_pre_edit_binary_and_actual_truncation() {
        let mut store = HistoryStore::new();
        store.configure(Some("case-a")).unwrap();
        let mut original = vec![b'A'; MAX_BODY + 9];
        original[..3].copy_from_slice(&[0xff, 0x00, 0x7f]);
        let snapshot =
            snapshot_original(store.generation(), "http://host/original?x=1", &original).unwrap();
        let mut forwarded = original.clone();
        forwarded[..3].copy_from_slice(b"NEW");
        store.record_at(
            store.generation(),
            55,
            &snapshot.url,
            "POST /original?x=1 HTTP/1.1\r\n\r\n",
            &snapshot.body_prefix,
            snapshot.body_original_len,
            201,
            &[],
            &forwarded,
        );
        let view = store.detail("case-a", 55, true).unwrap();
        assert_eq!(view.url, "http://host/original?x=1");
        assert!(view.request_truncated);
        let actual = base64::engine::general_purpose::STANDARD
            .decode(view.request_body_base64.unwrap())
            .unwrap();
        assert_eq!(&actual[..3], &[0xff, 0, 0x7f]);
        assert_eq!(actual.len(), MAX_BODY);
    }

    #[test]
    fn retention_cap_and_invalid_case_rejection() {
        let mut store = HistoryStore::new();
        store.configure(Some("a")).unwrap();
        assert!(store.configure(Some("bad\ncase")).is_err());
        for i in 0..90 {
            store.record(i, "http://x", "GET / HTTP/1.1\r\n\r\n", b"", 200, &[], b"");
        }
        assert_eq!(store.len(), MAX_ENTRIES);
        assert!(store.detail("a", 0, true).is_none());
        assert!(store.detail("a", 89, true).is_some());
    }

    #[test]
    fn backend_policy_binds_case_consent_redaction_and_strict_retention() {
        let temp = tempfile::tempdir().unwrap();
        let db = cyberdeck_storage::ArtifactStore::open(&temp.path().join("cases.db")).unwrap();
        let policy = Arc::new(Mutex::new(ActiveCaseHistoryPolicy::default()));
        let limits = HistoryRetentionLimits {
            max_entries: 1,
            max_total_bytes: 2048,
            max_body_bytes: 2,
            duration: std::time::Duration::from_secs(20),
        };
        let grant = {
            let mut gate = policy.lock().unwrap();
            gate.select_case(&db, "scratchpad").unwrap();
            gate.enable_volatile_capture("scratchpad", limits).unwrap()
        };
        let mut bound = BoundHistory::default();
        let stamp = bound.arm(Arc::clone(&policy), grant.clone()).unwrap();
        assert_eq!(bound.authorized(), Some(stamp));
        bound.capture(
            Some(stamp),
            5,
            OriginalSnapshot {
                url: "http://local/?token=private".into(),
                body_prefix: vec![0xff, 0, 0x7f],
                body_original_len: 3,
            },
            "POST /?token=private HTTP/1.1\r\nCookie: private\r\n\r\n",
            200,
            &[("Set-Cookie".into(), "secret=private".into())],
            &[0xfe, 0, 0x44],
            None,
        );
        assert!(bound.authorized_ids().contains(&5));
        let redacted = bound.detail("scratchpad", 5).unwrap();
        assert!(!serde_json::to_string(&redacted)
            .unwrap()
            .contains("private"));
        assert!(redacted.request_body_base64.is_none());
        let permit = { policy.lock().unwrap().approve_reveal(&grant).unwrap() };
        let revealed = bound
            .detail_with_permit(&grant, permit, 5)
            .unwrap()
            .unwrap();
        assert!(revealed.request_truncated && revealed.response_truncated);
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(revealed.request_body_base64.unwrap())
                .unwrap(),
            [0xff, 0]
        );
        assert!(bound.detail("other", 5).is_none());
        bound.capture(
            Some(stamp),
            6,
            OriginalSnapshot {
                url: "http://local/second".into(),
                body_prefix: vec![0x10],
                body_original_len: 1,
            },
            "GET /second HTTP/1.1\r\n\r\n",
            200,
            &[],
            b"ok",
            None,
        );
        assert_eq!(bound.store.len(), 1);
        assert!(bound.detail("scratchpad", 5).is_none());
        policy.lock().unwrap().revoke();
        assert_eq!(bound.authorized(), None);
        assert!(bound.authorized_ids().is_empty());
        assert_eq!(bound.store.len(), 0);
        assert!(bound.detail("scratchpad", 6).is_none());
        assert!(bound.arm(Arc::clone(&policy), grant).is_err());
    }

    #[test]
    fn caller_supplied_consent_cannot_enable_history() {
        // No runtime policy is injected here; the global legacy handler must
        // never accept a caller-owned case ID as sufficient authorization.
        assert!(configure_session(Some("scratchpad")).is_err());
    }

    #[test]
    fn provenance_retains_original_and_modified_binary_without_claiming_wire_exactness() {
        let mut store = HistoryStore::new();
        store.configure(Some("case-provenance")).unwrap();
        let stamp = store.generation();
        store.record_at(
            stamp,
            80,
            "http://127.0.0.1/original",
            "POST /original HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 3\r\n\r\n",
            &[0xff, 0x00, 0x7f],
            3,
            200,
            &[("Content-Type".into(), "application/octet-stream".into())],
            &[0xfe, 0x00, 0x55],
        );
        store.attach_forwarded(
            stamp,
            80,
            snapshot_forwarded(
                stamp,
                "PUT",
                "http://127.0.0.1/modified",
                &[("X-Trace".into(), "local".into())],
                &[0x41, 0x00, 0x42],
            )
            .unwrap(),
        );
        let redacted = store.detail("case-provenance", 80, false).unwrap();
        assert!(redacted.forwarded_url.is_none());
        assert!(redacted.forwarded_body_base64.is_none());
        assert!(!redacted.original_wire_exact);
        let revealed = store.detail("case-provenance", 80, true).unwrap();
        assert_eq!(revealed.forwarded_method.as_deref(), Some("PUT"));
        assert_eq!(
            revealed.forwarded_url.as_deref(),
            Some("http://127.0.0.1/modified")
        );
        assert!(revealed.forwarded_decoded_message && !revealed.original_wire_exact);
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(revealed.forwarded_body_base64.unwrap())
                .unwrap(),
            [0x41, 0x00, 0x42]
        );
        let original = store.replay_draft("case-provenance", 80, false).unwrap();
        assert_eq!(original.method, "POST");
        assert_eq!(original.body, [0xff, 0x00, 0x7f]);
        let modified = store.replay_draft("case-provenance", 80, true).unwrap();
        assert_eq!(modified.method, "PUT");
        assert_eq!(modified.body, [0x41, 0, 0x42]);
        assert!(store.replay_draft("wrong-case", 80, true).is_err());
    }

    #[test]
    fn truncated_capture_refuses_partial_replay() {
        let mut store = HistoryStore::new();
        store.configure(Some("c")).unwrap();
        let stamp = store.generation();
        store.record_at(
            stamp,
            9,
            "http://local/",
            "POST / HTTP/1.1\r\nHost: local\r\n\r\n",
            &[0xff; MAX_BODY],
            MAX_BODY + 1,
            200,
            &[],
            &[],
        );
        store.attach_forwarded(
            stamp,
            9,
            snapshot_forwarded(
                stamp,
                "POST",
                "http://local/",
                &[],
                &vec![0x41; MAX_BODY + 1],
            )
            .unwrap(),
        );
        assert!(store
            .replay_draft("c", 9, false)
            .unwrap_err()
            .contains("truncated"));
        assert!(store
            .replay_draft("c", 9, true)
            .unwrap_err()
            .contains("truncated"));
    }

    #[test]
    fn backend_capture_expires_and_erases_without_a_new_request() {
        let temp = tempfile::tempdir().unwrap();
        let db = cyberdeck_storage::ArtifactStore::open(&temp.path().join("cases.db")).unwrap();
        let policy = Arc::new(Mutex::new(ActiveCaseHistoryPolicy::default()));
        let grant = {
            let mut gate = policy.lock().unwrap();
            gate.select_case(&db, "scratchpad").unwrap();
            gate.enable_volatile_capture(
                "scratchpad",
                HistoryRetentionLimits {
                    duration: std::time::Duration::from_secs(2),
                    ..HistoryRetentionLimits::default()
                },
            )
            .unwrap()
        };
        let mut bound = BoundHistory::default();
        let stamp = bound.arm(Arc::clone(&policy), grant).unwrap();
        bound.capture(
            Some(stamp),
            1,
            OriginalSnapshot {
                url: "http://local/".into(),
                body_prefix: vec![0x42],
                body_original_len: 1,
            },
            "POST / HTTP/1.1\r\n\r\n",
            200,
            &[],
            b"hello",
            None,
        );
        assert_eq!(bound.store.len(), 1);
        std::thread::sleep(std::time::Duration::from_millis(2200));
        assert!(bound.authorized().is_none());
        assert_eq!(bound.store.len(), 0);
    }

    #[test]
    fn renewed_backend_grant_on_same_policy_replaces_old_case_without_revoking_new_consent() {
        let temp = tempfile::tempdir().unwrap();
        let db = cyberdeck_storage::ArtifactStore::open(&temp.path().join("cases.db")).unwrap();
        db.create_case("Second", "").unwrap();
        let other = db
            .list_cases()
            .unwrap()
            .into_iter()
            .find(|c| c.id != "scratchpad")
            .unwrap();
        let policy = Arc::new(Mutex::new(ActiveCaseHistoryPolicy::default()));
        let first = {
            let mut p = policy.lock().unwrap();
            p.select_case(&db, "scratchpad").unwrap();
            p.enable_volatile_capture("scratchpad", HistoryRetentionLimits::default())
                .unwrap()
        };
        let mut store = BoundHistory::default();
        let old = store.arm(Arc::clone(&policy), first.clone()).unwrap();
        store.capture(
            Some(old),
            1,
            OriginalSnapshot {
                url: "http://old/".into(),
                body_prefix: vec![0x41],
                body_original_len: 1,
            },
            "GET / HTTP/1.1\r\n\r\n",
            200,
            &[],
            b"ok",
            None,
        );
        let next = {
            let mut p = policy.lock().unwrap();
            p.select_case(&db, &other.id).unwrap();
            p.enable_volatile_capture(&other.id, HistoryRetentionLimits::default())
                .unwrap()
        };
        let new_stamp = store.arm(Arc::clone(&policy), next.clone()).unwrap();
        assert_ne!(old, new_stamp);
        assert_eq!(store.store.len(), 0);
        assert_eq!(store.authorized(), Some(new_stamp));
        store.capture(
            Some(old),
            2,
            OriginalSnapshot {
                url: "http://stale/".into(),
                body_prefix: vec![],
                body_original_len: 0,
            },
            "GET / HTTP/1.1\r\n\r\n",
            200,
            &[],
            b"stale",
            None,
        );
        assert_eq!(store.store.len(), 0);
        assert!(store.detail("scratchpad", 1).is_none());
        assert!(policy
            .lock()
            .unwrap()
            .authorize_capture(&other.id, next.generation)
            .is_ok());
    }

    #[tokio::test]
    async fn captured_binary_original_and_forwarded_replay_through_local_http_fixture() {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            use tokio::io::AsyncWriteExt;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                for (expected_method, expected_path, expected_body, status) in [
                    ("POST", "/original", vec![0xff, 0, 0x7f], 200),
                    ("PUT", "/edited", vec![0xfe, 0, 0x55], 201)
                ] {
                    let (mut client, _) = listener.accept().await.unwrap();
                    let (head, body) = crate::features::web::webtls::read_http_message(&mut client).await.unwrap();
                    assert!(head.starts_with(&format!("{expected_method} {expected_path} HTTP/1.1")), "{head}");
                    assert_eq!(body, expected_body);
                    let reply = format!("HTTP/1.1 {status} Test\r\nContent-Length: 3\r\nConnection: close\r\n\r\n");
                    client.write_all(reply.as_bytes()).await.unwrap();
                    client.write_all(&[0xf0,0,0x7f]).await.unwrap();
                }
            });
            let url = format!("http://127.0.0.1:{port}/original");
            let edited_url = format!("http://127.0.0.1:{port}/edited");
            let mut history = HistoryStore::new();
            history.configure(Some("case-fixture")).unwrap();
            let stamp = history.generation();
            history.record_at(stamp, 22, &url,
                &format!("POST /original HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Length: 3\r\n\r\n"),
                &[0xff,0,0x7f], 3, 200, &[], &[0xf0,0,0x7f]);
            history.attach_forwarded(stamp, 22, snapshot_forwarded(
                stamp, "PUT", &edited_url, &[], &[0xfe,0,0x55]).unwrap());
            let original = history.replay_draft("case-fixture", 22, false).unwrap();
            let forwarded = history.replay_draft("case-fixture", 22, true).unwrap();
            let original_reply = super::super::repeater_application::send_binary(original).await.unwrap();
            let edited_reply = super::super::repeater_application::send_binary(forwarded).await.unwrap();
            assert_eq!(original_reply.status, 200);
            assert_eq!(edited_reply.status, 201);
            assert_eq!(original_reply.body_base64, edited_reply.body_base64);
            server.await.unwrap();
        }).await.expect("history-to-repeater binary fixture timed out");
    }

    #[test]
    fn only_single_use_backend_reveal_permit_exposes_secret_and_replay_draft() {
        let temp = tempfile::tempdir().unwrap();
        let db = cyberdeck_storage::ArtifactStore::open(&temp.path().join("cases.db")).unwrap();
        let policy = Arc::new(Mutex::new(ActiveCaseHistoryPolicy::default()));
        let grant = {
            let mut backend = policy.lock().unwrap();
            backend.select_case(&db, "scratchpad").unwrap();
            backend
                .enable_volatile_capture("scratchpad", HistoryRetentionLimits::default())
                .unwrap()
        };
        let mut bound = BoundHistory::default();
        let stamp = bound.arm(Arc::clone(&policy), grant.clone()).unwrap();
        bound.capture(
            Some(stamp),
            1,
            OriginalSnapshot {
                url: "http://localhost/?key=hidden".into(),
                body_prefix: vec![0xff, 0, 0x7f],
                body_original_len: 3,
            },
            "POST /?key=hidden HTTP/1.1\r\nCookie: private\r\n\r\n",
            200,
            &[],
            &[0xfe, 0, 0x12],
            snapshot_forwarded(
                Some(stamp),
                "PUT",
                "http://localhost/forwarded",
                &[("Authorization".into(), "Bearer private".into())],
                &[0x41, 0, 0x42],
            ),
        );
        let safe = bound.detail("scratchpad", 1).unwrap();
        assert!(safe.request_body_base64.is_none());
        assert!(safe.forwarded_body_base64.is_none());
        let first = { policy.lock().unwrap().approve_reveal(&grant).unwrap() };
        let full = bound.detail_with_permit(&grant, first, 1).unwrap().unwrap();
        assert!(full.request_body_base64.is_some());
        let second = { policy.lock().unwrap().approve_reveal(&grant).unwrap() };
        let replay = bound.replay_authorized(&grant, second, 1, true).unwrap();
        assert_eq!(replay.method, "PUT");
        assert_eq!(replay.body, [0x41, 0, 0x42]);

        let stale = { policy.lock().unwrap().approve_reveal(&grant).unwrap() };
        policy.lock().unwrap().revoke();
        assert!(bound.detail_with_permit(&grant, stale, 1).is_err());
        assert!(bound.detail("scratchpad", 1).is_none());
    }
}
