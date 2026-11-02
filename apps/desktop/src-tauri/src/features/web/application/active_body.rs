//! SPDX-License-Identifier: MIT
//! Original bounded native POST form/JSON mutation rule, inspired by reviewed
//! ZAP variant concepts but not copied from Paros or ZAP Java implementations.
//! POST may change state: only an explicitly operator-authored template, exact
//! native permission dialog, and strictly pinned private origin can invoke it.
//! No captured sessions, cookies, arbitrary headers, or auth tokens attached.
use super::{active_query_application as query, scan_domain::Finding};
use reqwest::{header::CONTENT_TYPE, Client, Url};
use serde::de::{Error as _, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
#[cfg(test)]
use serde_json::Value;

const MAX_FIELDS: usize = 4;
const MAX_BODY_BYTES: usize = 2048;
const MAX_RESPONSE_BYTES: usize = 128 * 1024;
pub(super) const MAX_REQUESTS: usize = MAX_FIELDS + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BodyKind {
    Form,
    Json,
}

/// Reject duplicate keys and preserve source JSON member order so field
/// positions are exact even when the user wrote a non-alphabetical object.
struct OrderedObject(Vec<(String, String)>);
impl<'de> Deserialize<'de> for OrderedObject {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct OrderedVisitor;
        impl<'de> Visitor<'de> for OrderedVisitor {
            type Value = OrderedObject;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a flat JSON object with unique string fields")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut fields = Vec::new();
                while let Some((name, value)) = map.next_entry::<String, String>()? {
                    if fields
                        .iter()
                        .any(|(existing, _): &(String, String)| existing == &name)
                    {
                        return Err(A::Error::custom("duplicate JSON field"));
                    }
                    if fields.len() >= MAX_FIELDS {
                        return Err(A::Error::custom("too many JSON fields"));
                    }
                    fields.push((name, value));
                }
                Ok(OrderedObject(fields))
            }
        }
        deserializer.deserialize_map(OrderedVisitor)
    }
}

#[derive(Debug, Clone)]
pub(super) struct BodyPlan {
    pub kind: BodyKind,
    fields: Vec<(String, String)>,
}
impl BodyPlan {
    pub fn new(kind: BodyKind, supplied: &str) -> Result<Self, String> {
        if supplied.is_empty() || supplied.len() > MAX_BODY_BYTES {
            return Err("POST template must be 1–2048 bytes".into());
        }
        let fields: Vec<(String, String)> = match kind {
            BodyKind::Form => {
                // URL form encoding is parsed and serialized independently;
                // positions and repeated keys remain distinct.
                let mut parsed = Url::parse("http://cyberdeck.invalid/").unwrap();
                parsed.set_query(Some(supplied));
                parsed
                    .query_pairs()
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect()
            }
            BodyKind::Json => {
                let OrderedObject(fields) = serde_json::from_str(supplied)
                    .map_err(|_| "POST JSON requires a flat object with unique string fields")?;
                fields
            }
        };
        if fields.is_empty() || fields.len() > MAX_FIELDS {
            return Err("POST template needs one to four fields".into());
        }
        // Fail CLOSED instead of forwarding an unrelated protected field in
        // a baseline/other candidate's template body.
        for (name, value) in &fields {
            if name.is_empty()
                || name.len() > 128
                || value.len() > 512
                || query::sensitive_name(name)
                || name.bytes().any(|c| c.is_ascii_control())
            {
                return Err("POST template includes a protected or oversized field".into());
            }
        }
        Ok(Self { kind, fields })
    }
    pub fn count(&self) -> usize {
        self.fields.len()
    }
    fn encoded(&self, replace: Option<(usize, &str)>) -> Result<Vec<u8>, String> {
        let bytes = match self.kind {
            BodyKind::Form => {
                let mut parsed = Url::parse("http://cyberdeck.invalid/").unwrap();
                {
                    let mut encoder = parsed.query_pairs_mut();
                    for (i, (name, original)) in self.fields.iter().enumerate() {
                        encoder.append_pair(
                            name,
                            match replace {
                                Some((at, replacement)) if at == i => replacement,
                                _ => original.as_str(),
                            },
                        );
                    }
                }
                parsed.query().unwrap_or("").as_bytes().to_vec()
            }
            BodyKind::Json => {
                let mut encoded = Vec::from(b"{".as_slice());
                for (index, (name, original)) in self.fields.iter().enumerate() {
                    if index != 0 {
                        encoded.push(b',');
                    }
                    encoded.extend_from_slice(
                        serde_json::to_string(name)
                            .map_err(|_| "failed to serialize JSON name")?
                            .as_bytes(),
                    );
                    encoded.push(b':');
                    let value = match replace {
                        Some((position, substitute)) if position == index => substitute,
                        _ => original.as_str(),
                    };
                    encoded.extend_from_slice(
                        serde_json::to_string(value)
                            .map_err(|_| "failed to serialize JSON value")?
                            .as_bytes(),
                    );
                }
                encoded.push(b'}');
                encoded
            }
        };
        if bytes.len() > MAX_BODY_BYTES {
            return Err("mutated POST template exceeds 2048-byte bound".into());
        }
        Ok(bytes)
    }
    fn content_type(&self) -> &'static str {
        match self.kind {
            BodyKind::Form => "application/x-www-form-urlencoded",
            BodyKind::Json => "application/json",
        }
    }
}
async fn bounded_post_html(
    client: &Client,
    target: &Url,
    plan: &BodyPlan,
    body: Vec<u8>,
) -> Result<Option<Vec<u8>>, String> {
    let mut resp = client
        .post(target.clone())
        .header(CONTENT_TYPE, plan.content_type())
        .body(body)
        .send()
        .await
        .map_err(|_| "POST probe request failed")?;
    if resp.status() != reqwest::StatusCode::OK {
        return Ok(None);
    }
    let html = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(';').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("text/html"));
    if !html {
        return Ok(None);
    }
    if resp
        .content_length()
        .is_some_and(|n| n > MAX_RESPONSE_BYTES as u64)
    {
        return Err("POST probe response exceeds 128 KiB bound".into());
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|_| "POST probe response failed")?
    {
        if chunk.len() > MAX_RESPONSE_BYTES.saturating_sub(out.len()) {
            return Err("POST probe response exceeds 128 KiB bound".into());
        }
        out.extend_from_slice(&chunk);
    }
    Ok(Some(out))
}

/// A single baseline plus one mutation per original form/JSON position.
/// Caller supplies the exact pinned client, pre-authorized origin and backend
/// cancellation/60s job gate. Never auto-send form actions discovered by Spider.
pub(super) async fn run_with_progress(
    client: &Client,
    target: Url,
    job_id: u64,
    plan: BodyPlan,
    on_progress: &impl Fn(usize, usize),
) -> Result<Vec<Finding>, String> {
    run_with_budget(client, target, job_id, plan, MAX_FIELDS, on_progress).await
}

/// Execute at most an explicitly bounded number of POST mutations.
/// Baseline always runs once; the strict backend budget excludes the baseline.
pub(super) async fn run_with_budget(
    client: &Client,
    target: Url,
    job_id: u64,
    plan: BodyPlan,
    max_mutations: usize,
    on_progress: &impl Fn(usize, usize),
) -> Result<Vec<Finding>, String> {
    if max_mutations == 0 || max_mutations > MAX_FIELDS {
        return Err("POST mutation budget must be 1–4".into());
    }
    if target.as_str().len() > 4096
        || !matches!(target.scheme(), "http" | "https")
        || target.host_str().is_none()
        || !target.username().is_empty()
        || target.password().is_some()
        || target.fragment().is_some()
    {
        return Err("invalid scoped POST target".into());
    }
    let total = plan.count().min(max_mutations) + 1;
    debug_assert!(total <= MAX_REQUESTS);
    on_progress(0, 0);
    let baseline = bounded_post_html(client, &target, &plan, plan.encoded(None)?)
        .await?
        .ok_or("POST baseline must return HTTP 200 text/html")?;
    on_progress(1, 0);
    let mut findings = Vec::new();
    for position in 0..plan.count().min(max_mutations) {
        let marker = format!("<cyberdeck-post-probe-{job_id:x}-{position:x}>");
        let payload = plan.encoded(Some((position, &marker)))?;
        let candidate = bounded_post_html(client, &target, &plan, payload).await?;
        if candidate
            .as_ref()
            .is_some_and(|body| query::candidate_is_reflected(&baseline, body, marker.as_bytes()))
        {
            findings.push(Finding {
                severity:"low".into(),
                title:"potential unescaped POST parameter reflection".into(),
                detail:"An inert custom HTML marker was reflected from an explicitly approved POST template. This does not establish executable XSS. Review the output context and whether the endpoint changed state.".into(),
                evidence:format!(
                    "Rule cd.ascan.post-html-reflection.v1; approved origin {}; mode {}; field position {}; HTTP 200 text/html. Original template, names and values withheld.",
                    target.origin().ascii_serialization(),
                    if plan.kind==BodyKind::Form {"form"} else {"json"},
                    position+1,
                ),
            });
        }
        on_progress(position + 2, findings.len());
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn positional_form_and_json_mutations_do_not_copy_secrets() {
        let form = BodyPlan::new(BodyKind::Form, "q=first&q=second&term=a+b").unwrap();
        let mutated = String::from_utf8(form.encoded(Some((1, "<probe>"))).unwrap()).unwrap();
        let parsed = Url::parse(&format!("http://cyberdeck.invalid/?{mutated}")).unwrap();
        let pairs: Vec<_> = parsed.query_pairs().collect();
        assert_eq!(pairs[0].1, "first");
        assert_eq!(pairs[1].1, "<probe>");
        assert_eq!(pairs[2].1, "a b");
        let json = BodyPlan::new(BodyKind::Json, r#"{"alpha":"one","beta":"two"}"#).unwrap();
        let ordered = BodyPlan::new(BodyKind::Json, r#"{"z":"last","a":"first"}"#).unwrap();
        assert_eq!(ordered.fields[0].0, "z");
        assert_eq!(ordered.fields[1].0, "a");
        assert!(BodyPlan::new(BodyKind::Json, r#"{"dup":"one","dup":"two"}"#).is_err());
        let value: Value =
            serde_json::from_slice(&json.encoded(Some((1, "<probe>"))).unwrap()).unwrap();
        assert_eq!(value["alpha"], "one");
        assert_eq!(value["beta"], "<probe>");
        for body in ["session=SECRET&q=test", "csrf=SECRET", "password=hunter2"] {
            assert!(BodyPlan::new(BodyKind::Form, body).is_err());
        }
        for body in [
            r#"{"auth_token":"SECRET","q":"x"}"#,
            r#"{"a":{"nested":true}}"#,
        ] {
            assert!(BodyPlan::new(BodyKind::Json, body).is_err());
        }
        assert!(BodyPlan::new(BodyKind::Form, &"x=1&".repeat(5)).is_err());
        assert!(BodyPlan::new(BodyKind::Json, "[\"x\"]").is_err());
    }

    async fn fixture(kind: BodyKind, escape: bool, mutation_budget: usize) {
        tokio::time::timeout(Duration::from_secs(10),async {
            let server=TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr=server.local_addr().unwrap();
            let url=Url::parse(&format!("http://{addr}/submit")).unwrap();
            let handler=tokio::spawn(async move {
                for _ in 0..(mutation_budget.min(2) + 1) {
                    let (mut stream,_)=server.accept().await.unwrap();
                    let mut request=Vec::new();
                    let header_end=loop {
                        let mut buf=[0u8;1024];
                        let n=stream.read(&mut buf).await.unwrap();
                        assert!(n>0,"connection closed before complete request");
                        request.extend_from_slice(&buf[..n]);
                        assert!(request.len()<8192);
                        if let Some(start)=request.windows(4).position(|w|w==b"\r\n\r\n") {
                            break start+4;
                        }
                    };
                    let head=String::from_utf8_lossy(&request[..header_end]).to_ascii_lowercase();
                    assert!(head.starts_with("post /submit http/1.1"));
                    assert!(head.contains(match kind {BodyKind::Form=>"application/x-www-form-urlencoded",BodyKind::Json=>"application/json"}));
                    let content_length=head.lines().find_map(|line|line.strip_prefix("content-length: "))
                        .unwrap().trim().parse::<usize>().unwrap();
                    while request.len()-header_end<content_length {
                        let mut chunk=[0u8;1024];
                        let n=stream.read(&mut chunk).await.unwrap();
                        assert!(n>0);
                        request.extend_from_slice(&chunk[..n]);
                    }
                    let body=&request[header_end..header_end+content_length];
                    let reflected=match kind {
                        BodyKind::Form=>{
                            let parsed=Url::parse(&format!("http://cyberdeck.invalid/?{}",String::from_utf8_lossy(body))).unwrap();
                            let value=parsed.query_pairs().find(|(key,_)|key=="q").unwrap().1.into_owned();
                            value
                        },
                        BodyKind::Json=>serde_json::from_slice::<Value>(body).unwrap()["q"]
                            .as_str().unwrap().to_owned(),
                    };
                    let html=if escape {
                        reflected.replace('<',"&lt;").replace('>',"&gt;")
                    } else {reflected};
                    let reply=format!("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",html.len(),html);
                    stream.write_all(reply.as_bytes()).await.unwrap();
                }
            });
            let template=match kind {
                BodyKind::Form=>"q=baseline&label=hello",
                BodyKind::Json=>r#"{"q":"baseline","label":"hello"}"#,
            };
            let plan=BodyPlan::new(kind,template).unwrap();
            let client=Client::builder().timeout(Duration::from_secs(3))
                .redirect(reqwest::redirect::Policy::none()).no_proxy().build().unwrap();
            let progress=std::sync::atomic::AtomicUsize::new(0);
            let findings=run_with_budget(&client,url,12,plan,mutation_budget,&|p,_| {
                progress.store(p,std::sync::atomic::Ordering::Release);
            }).await.unwrap();
            handler.await.unwrap();
            assert_eq!(progress.load(std::sync::atomic::Ordering::Acquire),mutation_budget.min(2)+1);
            assert_eq!(findings.len(),if escape {0} else {1});
            if !escape {
                assert!(findings[0].evidence.contains(if kind == BodyKind::Form {
                    "field position 1"
                } else { "field position 1" }));
                assert!(!format!("{findings:?}").contains("baseline"));
                assert!(!format!("{findings:?}").contains("<cyberdeck"));
            }
        }).await.expect("bounded POST fixture timed out");
    }
    #[tokio::test]
    async fn localhost_form_post_reports_only_raw_reflection() {
        fixture(BodyKind::Form, false, 2).await;
        fixture(BodyKind::Form, true, 2).await;
        fixture(BodyKind::Form, false, 1).await;
    }
    #[tokio::test]
    async fn localhost_json_post_reports_only_raw_reflection() {
        fixture(BodyKind::Json, false, 2).await;
        fixture(BodyKind::Json, true, 2).await;
        fixture(BodyKind::Json, false, 1).await;
    }
}
