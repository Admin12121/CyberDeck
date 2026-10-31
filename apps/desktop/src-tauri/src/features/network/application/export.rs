//! Scanner export rendering without filesystem or user-interface dependencies.
use super::ScanEntry;

/// Keep CSV headers, double-quote escaping and JSON structure identical.
pub(super) fn render_results(results: &[ScanEntry], format: &str) -> Result<String, String> {
    if format == "csv" {
        let mut csv = String::from("host,port,state,service,banner\n");
        for row in results {
            let banner = row.banner.replace('"', "\"\"");
            csv.push_str(&format!(
                "{},{},{},{},\"{}\"\n",
                row.host, row.port, row.state, row.service, banner
            ));
        }
        Ok(csv)
    } else {
        serde_json::to_string_pretty(results).map_err(|e| format!("serialize failed: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_csv_escaping_and_header() {
        let entries = vec![ScanEntry {
            host: "127.0.0.1".into(),
            port: 80,
            state: "open".into(),
            service: "http".into(),
            banner: "Server: \"example\"".into(),
        }];
        let text = render_results(&entries, "csv").unwrap();
        assert_eq!(
            text,
            "host,port,state,service,banner\n127.0.0.1,80,open,http,\"Server: \"\"example\"\"\"\n"
        );
    }
}
