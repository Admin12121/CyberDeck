//! HTTPS MITM support (§5.2): a per-install CA is generated once and
//! persisted; per-host leaf certificates are minted on demand so the proxy
//! can terminate TLS when interception is on. Without interception, CONNECT
//! tunnels pass through untouched. WebSocket upgrades are relayed and listed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use rcgen::{Certificate, CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub struct CaState {
    pub cert_pem: String,
    /// Rebuilt each session from the persisted key; leaves chain to the
    /// installed CA cert because issuer DN + key match.
    pub ca_cert: Certificate,
    pub key_pair: KeyPair,
    pub leaf_cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

fn ca_params() -> Result<CertificateParams, String> {
    let mut params = CertificateParams::new(Vec::new()).map_err(|e| format!("CA params failed: {e}"))?;
    params.distinguished_name.push(rcgen::DnType::CommonName, "HackTool Root CA");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    Ok(params)
}

/// Load the persisted CA or generate one; PEMs live in the app-data dir so
/// the browser trust survives restarts.
pub fn init_ca(dir: &std::path::Path) -> Result<Arc<CaState>, String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create CA dir: {e}"))?;
    let cert_path = dir.join("ca.pem");
    let key_path = dir.join("ca.key");

    let (cert_pem, key_pem) = if cert_path.exists() && key_path.exists() {
        (
            std::fs::read_to_string(&cert_path).map_err(|e| format!("cannot read CA cert: {e}"))?,
            std::fs::read_to_string(&key_path).map_err(|e| format!("cannot read CA key: {e}"))?,
        )
    } else {
        let key = KeyPair::generate().map_err(|e| format!("CA key generation failed: {e}"))?;
        let mut params = ca_params()?;
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(3650);
        let cert = params.self_signed(&key).map_err(|e| format!("CA cert failed: {e}"))?;
        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();
        std::fs::write(&cert_path, &cert_pem).map_err(|e| format!("cannot write CA cert: {e}"))?;
        std::fs::write(&key_path, &key_pem).map_err(|e| format!("cannot write CA key: {e}"))?;
        (cert_pem, key_pem)
    };

    let key = KeyPair::from_pem(&key_pem).map_err(|e| format!("cannot load CA key: {e}"))?;
    let ca_cert = ca_params()?
        .self_signed(&key)
        .map_err(|e| format!("CA object failed: {e}"))?;

    Ok(Arc::new(CaState {
        cert_pem,
        ca_cert,
        key_pair: key,
        leaf_cache: Mutex::new(HashMap::new()),
    }))
}

/// Build (or reuse) a TLS server config presenting a host-signed leaf.
pub fn acceptor_for_host(ca: &Arc<CaState>, host: &str) -> Result<Arc<ServerConfig>, String> {
    {
        let cache = ca.leaf_cache.lock().expect("leaf cache poisoned");
        if let Some(config) = cache.get(host) {
            return Ok(Arc::clone(config));
        }
    }
    let leaf_key = KeyPair::generate().map_err(|e| format!("leaf key failed: {e}"))?;
    let mut params = CertificateParams::new(Vec::new()).map_err(|e| format!("leaf params failed: {e}"))?;
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        params.subject_alt_names = vec![rcgen::SanType::IpAddress(ip)];
    } else {
        params.subject_alt_names = vec![rcgen::SanType::DnsName(rcgen::Ia5String::try_from(host).map_err(|e| format!("bad san: {e}"))?)];
    }
    params.distinguished_name.push(rcgen::DnType::CommonName, host);
    let leaf = params
        .signed_by(&leaf_key, &ca.ca_cert, &ca.key_pair)
        .map_err(|e| format!("leaf signing failed: {e}"))?;
    let leaf_der = leaf.der().clone();
    let ca_der = pem_to_der(&ca.cert_pem);

    let cert_chain = vec![leaf_der, CertificateDer::from(ca_der)];
    let key_der = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, PrivateKeyDer::Pkcs8(key_der))
        .map_err(|e| format!("tls config failed: {e}"))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec(), b"h2".to_vec()];
    let config = Arc::new(config);
    {
        let mut cache = ca.leaf_cache.lock().expect("leaf cache poisoned");
        cache.insert(host.to_string(), Arc::clone(&config));
    }
    Ok(config)
}

pub fn tls_acceptor(ca: &Arc<CaState>, host: &str) -> Result<TlsAcceptor, String> {
    Ok(TlsAcceptor::from(acceptor_for_host(ca, host)?))
}

pub fn tls_client() -> Result<TlsConnector, String> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

/// Read one HTTP message (head + content-length body) from any async reader.
pub async fn read_http_message<R>(reader: &mut R) -> std::io::Result<(String, Vec<u8>)>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head_text = String::from_utf8_lossy(&head).to_string();
    let mut body = Vec::new();
    let content_length = head_text
        .lines()
        .find(|l| l.to_lowercase().starts_with("content-length:"))
        .and_then(|l| l.split(':').nth(1))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    if content_length > 0 {
        body = vec![0u8; content_length.min(4 * 1024 * 1024)];
        reader.read_exact(&mut body).await?;
    }
    Ok((head_text, body))
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct WsConnection {
    pub host: String,
    pub at_ms: u64,
}

pub fn pem_to_der(pem: &str) -> Vec<u8> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .unwrap_or_default()
}
