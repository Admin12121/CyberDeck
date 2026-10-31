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

#[path = "framing.rs"]
mod webframing;

const MAX_CA_LEAF_CACHE: usize = 128;

pub struct CaState {
    pub cert_pem: String,
    /// Rebuilt each session from the persisted key; leaves chain to the
    /// installed CA cert because issuer DN + key match.
    pub ca_cert: Certificate,
    pub key_pair: KeyPair,
    pub leaf_cache: Mutex<HashMap<String, Arc<ServerConfig>>>,
}

fn ca_params() -> Result<CertificateParams, String> {
    let mut params =
        CertificateParams::new(Vec::new()).map_err(|e| format!("CA params failed: {e}"))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "CyberDeck Root CA");
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

    // Never silently rotate an already-trusted MITM CA when only one file
    // survives a crash or an interrupted installation. The operator must
    // explicitly recover or reset the incomplete CA state.
    if cert_path.exists() != key_path.exists() {
        return Err(
            "incomplete interception CA: cert/key pair must both exist or both be absent"
                .to_string(),
        );
    }
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
        let cert = params
            .self_signed(&key)
            .map_err(|e| format!("CA cert failed: {e}"))?;
        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();
        std::fs::write(&cert_path, &cert_pem).map_err(|e| format!("cannot write CA cert: {e}"))?;
        // Restrict a locally trusted interception CA key to this OS user.
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&key_path)
                .map_err(|e| format!("cannot create CA key: {e}"))?;
            file.write_all(key_pem.as_bytes())
                .map_err(|e| format!("cannot write CA key: {e}"))?;
        }
        #[cfg(not(unix))]
        std::fs::write(&key_path, &key_pem).map_err(|e| format!("cannot write CA key: {e}"))?;
        (cert_pem, key_pem)
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot secure CA key: {e}"))?;
    }
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
    let mut params =
        CertificateParams::new(Vec::new()).map_err(|e| format!("leaf params failed: {e}"))?;
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        params.subject_alt_names = vec![rcgen::SanType::IpAddress(ip)];
    } else {
        params.subject_alt_names = vec![rcgen::SanType::DnsName(
            rcgen::Ia5String::try_from(host).map_err(|e| format!("bad san: {e}"))?,
        )];
    }
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, host);
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
    // Only HTTP/1.1 is supported by the bounded interception parser.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let config = Arc::new(config);
    {
        let mut cache = ca.leaf_cache.lock().expect("leaf cache poisoned");
        // A hostile browser can request arbitrarily many CONNECT authorities.
        // Bound leaf TLS configs rather than retaining one keypair per host forever.
        if cache.len() >= MAX_CA_LEAF_CACHE {
            if let Some(evicted) = cache.keys().next().cloned() {
                cache.remove(&evicted);
            }
        }
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

/// Read a bounded HTTP/1.1 request and decode chunked bodies before forwarding.
/// The upstream executor strips Transfer-Encoding and emits new framing.
pub async fn read_http_message<R>(reader: &mut R) -> std::io::Result<(String, Vec<u8>)>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use std::io::{Error, ErrorKind};
    use tokio::io::AsyncReadExt;

    const MAX_HEADERS: usize = 32 * 1024;
    const MAX_BODY: usize = 4 * 1024 * 1024;
    let mut head = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        if head.len() >= MAX_HEADERS {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "HTTP header limit exceeded",
            ));
        }
        if reader.read(&mut byte).await? == 0 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "incomplete HTTP headers",
            ));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head_text = String::from_utf8(head)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "non-UTF8 HTTP headers"))?;
    let body = match webframing::parse_framing(&head_text, MAX_BODY)? {
        webframing::BodyFraming::Fixed(content_length) => {
            let mut body = vec![0u8; content_length];
            reader.read_exact(&mut body).await?;
            body
        }
        webframing::BodyFraming::Chunked => webframing::read_chunked(reader, MAX_BODY).await?,
    };
    Ok((head_text, body))
}

#[cfg(test)]
mod framing_tests {
    use super::read_http_message;
    use tokio::io::{duplex, AsyncWriteExt};

    #[tokio::test]
    async fn bounded_request_body_roundtrip() {
        let (mut tx, mut rx) = duplex(256);
        tx.write_all(b"POST / HTTP/1.1\r\nHost: local\r\nContent-Length: 4\r\n\r\ntest")
            .await
            .unwrap();
        let (head, body) = read_http_message(&mut rx).await.unwrap();
        assert!(head.starts_with("POST / HTTP/1.1"));
        assert_eq!(body, b"test");
    }

    #[test]
    fn rejects_ambiguous_framing() {
        use super::webframing::{parse_framing, BodyFraming};
        for header in [
            "Content-Length: 4\r\nContent-Length: 4",
            "Transfer-Encoding: identity",
            "Transfer-Encoding: chunked\r\nContent-Length: 4",
            "Content-Length: +4",
            "Content-Length: 1, 1",
            "X-Header: ok\r\n continued",
            "BrokenHeader",
        ] {
            let head = format!("POST / HTTP/1.1\r\nHost: local\r\n{header}\r\n\r\n");
            assert!(parse_framing(&head, 1024).is_err(), "{header}");
        }
        assert_eq!(
            parse_framing(
                "POST / HTTP/1.1\r\nHost: local\r\nContent-Length: 4\r\n\r\n",
                1024
            )
            .unwrap(),
            BodyFraming::Fixed(4)
        );
    }

    #[tokio::test]
    async fn reads_chunked_binary_request() {
        let (mut tx, mut rx) = duplex(256);
        tx.write_all(b"POST /binary HTTP/1.1\r\nHost: local\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n\xff\x00\x7f\r\n0\r\n\r\n")
            .await
            .unwrap();
        let (head, body) = read_http_message(&mut rx).await.unwrap();
        assert!(head.contains("Transfer-Encoding: chunked"));
        assert_eq!(body, [0xff, 0x00, 0x7f]);
    }

    #[tokio::test]
    async fn rejects_oversized_or_invalid_requests() {
        for header in [
            "Content-Length: 5000000",
            "Transfer-Encoding: gzip",
            "Content-Length: nope",
        ] {
            let (mut tx, mut rx) = duplex(256);
            tx.write_all(format!("POST / HTTP/1.1\r\nHost: local\r\n{header}\r\n\r\n").as_bytes())
                .await
                .unwrap();
            assert!(read_http_message(&mut rx).await.is_err());
        }
    }
}

#[cfg(test)]
mod certificate_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn certificate_cache_is_bounded_across_distinct_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let ca = init_ca(dir.path()).unwrap();
        for host in 0..(MAX_CA_LEAF_CACHE + 3) {
            let hostname = format!("host-{host}.example.test");
            acceptor_for_host(&ca, &hostname).unwrap();
            assert!(ca.leaf_cache.lock().unwrap().len() <= MAX_CA_LEAF_CACHE);
        }
        assert_eq!(ca.leaf_cache.lock().unwrap().len(), MAX_CA_LEAF_CACHE);
    }

    #[test]
    fn incomplete_ca_never_replaces_trusted_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let first = init_ca(dir.path()).unwrap();
        let original_cert = first.cert_pem.clone();
        std::fs::remove_file(dir.path().join("ca.key")).unwrap();
        assert!(init_ca(dir.path())
            .err()
            .unwrap()
            .contains("incomplete interception CA"));
        assert_eq!(
            std::fs::read_to_string(dir.path().join("ca.pem")).unwrap(),
            original_cert
        );

        let second = tempfile::tempdir().unwrap();
        std::fs::write(second.path().join("ca.key"), "private-but-unpaired").unwrap();
        assert!(init_ca(second.path())
            .err()
            .unwrap()
            .contains("incomplete interception CA"));
        assert!(!second.path().join("ca.pem").exists());
    }

    #[tokio::test]
    async fn saved_ca_signs_trusted_leaves_after_restart() {
        let dir = tempfile::tempdir().unwrap();
        let first = init_ca(dir.path()).unwrap();
        let reloaded = init_ca(dir.path()).unwrap();
        assert_eq!(first.cert_pem, reloaded.cert_pem);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut connection = tls_acceptor(&reloaded, "localhost")
                .unwrap()
                .accept(socket)
                .await
                .unwrap();
            let mut message = [0u8; 4];
            connection.read_exact(&mut message).await.unwrap();
            assert_eq!(&message, b"PING");
            connection.write_all(b"PONG").await.unwrap();
            connection.flush().await.unwrap();
        });

        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from(pem_to_der(&first.cert_pem)))
            .unwrap();
        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));
        let socket = tokio::net::TcpStream::connect(address).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap();
        let mut connection = connector.connect(server_name, socket).await.unwrap();
        connection.write_all(b"PING").await.unwrap();
        let mut message = [0u8; 4];
        connection.read_exact(&mut message).await.unwrap();
        assert_eq!(&message, b"PONG");
        server.await.unwrap();
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct WsConnection {
    pub host: String,
    pub bytes_client_to_server: u64,
    pub bytes_server_to_client: u64,
    pub at_ms: u64,
}

pub fn pem_to_der(pem: &str) -> Vec<u8> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .unwrap_or_default()
}
