//! Serialized Web Studio command DTOs.
//! The public web::* re-exports preserve the existing Tauri/TypeScript contract.
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct CapturedRequest {
    pub id: u64,
    pub method: String,
    pub host: String,
    pub path: String,
    pub status: u16,
    pub size: usize,
    pub at_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct ProxyStatusWire {
    pub running: bool,
    pub port: u16,
    pub captured: usize,
}

#[derive(Debug, Serialize)]
pub struct HttpResponseWire {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    /// Exact bytes of the bounded response for hex/repeater tooling.
    pub body_base64: String,
    pub body_is_utf8: bool,
    pub body_truncated: bool,
    pub size: usize,
    pub duration_ms: u64,
    pub url: String,
}

#[derive(Debug, Serialize)]
pub struct PendingWire {
    pub id: u64,
    pub method: String,
    pub url: String,
    pub host: String,
    pub path: String,
    pub body_preview: String,
}

#[derive(Debug, Serialize)]
pub struct WsConnectionWire {
    pub host: String,
    pub bytes_client_to_server: u64,
    pub bytes_server_to_client: u64,
    pub at_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct WebEngineStatus {
    pub id: String,
    pub label: String,
    pub license: String,
    pub available: bool,
    pub version: String,
}

#[derive(Debug, Serialize)]
pub struct EngineScanResult {
    pub tool: String,
    pub raw: String,
    pub duration_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialized_http_response_fields_remain_compatible() {
        let dto = HttpResponseWire {
            status: 200,
            headers: vec![],
            body: "ok".into(),
            body_base64: "b2s=".into(),
            body_is_utf8: true,
            body_truncated: false,
            size: 2,
            duration_ms: 3,
            url: "http://localhost/".into(),
        };
        let serialized = serde_json::to_value(dto).unwrap();
        let mut keys: Vec<_> = serialized.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "body",
                "body_base64",
                "body_is_utf8",
                "body_truncated",
                "duration_ms",
                "headers",
                "size",
                "status",
                "url"
            ]
        );
    }

    #[test]
    fn proxy_status_wire_contract_is_unchanged() {
        let payload = serde_json::to_value(ProxyStatusWire {
            running: true,
            port: 8080,
            captured: 5,
        })
        .unwrap();
        assert_eq!(
            payload,
            serde_json::json!({
                "running": true,
                "port": 8080,
                "captured": 5,
            })
        );
    }
}
