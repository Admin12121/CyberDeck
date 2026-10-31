//! Reusable native HTTP transport with redirects and ambient proxy disabled.
use std::time::Duration;

/// Share connection pools across scans, Repeater and proxy forwarding.
pub(super) fn http_client() -> reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .redirect(reqwest::redirect::Policy::none())
                // Avoid looping when the host's proxy points back at CyberDeck.
                .no_proxy()
                .user_agent("CyberDeck-Workbench/0.1")
                .build()
                .expect("http client")
        })
        .clone()
}
