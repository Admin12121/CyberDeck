//! Deterministic local HTTP, HTTPS, CONNECT and WSS integration fixtures.

use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn shared(intercept: bool, ca: Option<Arc<crate::webtls::CaState>>) -> Arc<ProxyShared> {
    Arc::new(ProxyShared {
        running: AtomicBool::new(true),
        intercept: AtomicBool::new(intercept),
        port: AtomicU16::new(0),
        rules: Mutex::new(vec![]),
        captured: Mutex::new(vec![]),
        pending: Mutex::new(HashMap::new()),
        next_id: AtomicU64::new(1),
        ca: Mutex::new(ca),
        ws: Mutex::new(vec![]),
    })
}

fn trusted_connector(ca: &crate::webtls::CaState) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            crate::webtls::pem_to_der(&ca.cert_pem),
        ))
        .unwrap();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

#[tokio::test]
async fn verified_wss_mitm_relays_both_binary_directions() {
    tokio::time::timeout(Duration::from_secs(12), async {
            // The upstream and browser-facing MITM use different ephemeral
            // trusted CAs; neither TLS certificate verification is bypassed.
            let upstream_dir = tempfile::tempdir().unwrap();
            let upstream_ca = crate::webtls::init_ca(upstream_dir.path()).unwrap();
            let proxy_dir = tempfile::tempdir().unwrap();
            let proxy_ca = crate::webtls::init_ca(proxy_dir.path()).unwrap();

            let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let backend_port = backend_listener.local_addr().unwrap().port();
            let backend_ca = Arc::clone(&upstream_ca);
            let upstream = tokio::spawn(async move {
                let (socket, _) = backend_listener.accept().await.unwrap();
                let mut tls = crate::webtls::tls_acceptor(&backend_ca, "localhost")
                    .unwrap().accept(socket).await.unwrap();
                let (head, body) = crate::webtls::read_http_message(&mut tls).await.unwrap();
                assert!(head.starts_with("GET /ws HTTP/1.1"));
                assert!(head.contains("Upgrade: websocket"));
                assert!(body.is_empty());
                tls.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n").await.unwrap();
                // First application frame immediately follows the 101 header.
                tls.write_all(&[0x82, 3, 0xff, 0x00, 0x7f]).await.unwrap();
                tls.flush().await.unwrap();
                let mut masked_frame = [0u8; 9];
                tls.read_exact(&mut masked_frame).await.unwrap();
                assert_eq!(masked_frame, [0x82, 0x83, 1, 2, 3, 4, 0xfe, 2, 0x7c]);
                tls.write_all(&[0x82, 3, b'O', b'K', b'!']).await.unwrap();
                tls.flush().await.unwrap();
            });

            let state = shared(true, Some(Arc::clone(&proxy_ca)));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let worker_state = Arc::clone(&state);
            let backend_connector = trusted_connector(&upstream_ca);
            let worker = tokio::spawn(async move {
                let (mut connection, _) = listener.accept().await.unwrap();
                let (connect_head, _) = crate::webtls::read_http_message(&mut connection).await.unwrap();
                connect_tunnel_with_ws_connector(
                    connection, worker_state, &connect_head, None, Some(backend_connector)
                ).await.unwrap();
            });
            let mut browser = TcpStream::connect(address).await.unwrap();
            let connect = format!("CONNECT localhost:{backend_port} HTTP/1.1\r\nHost: localhost:{backend_port}\r\n\r\n");
            browser.write_all(connect.as_bytes()).await.unwrap();
            let tunnel_established = read_http_response_head(&mut browser).await.unwrap();
            assert!(tunnel_established.starts_with("HTTP/1.1 200"));
            let mut browser_tls = trusted_connector(&proxy_ca)
                .connect(
                    rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap(),
                    browser
                ).await.unwrap();
            let request = format!("GET /ws HTTP/1.1\r\nHost: localhost:{backend_port}\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n");
            browser_tls.write_all(request.as_bytes()).await.unwrap();
            let switching = read_http_response_head(&mut browser_tls).await.unwrap();
            assert!(is_websocket_switching_protocols(&switching));
            let mut first_frame = [0u8; 5];
            browser_tls.read_exact(&mut first_frame).await.unwrap();
            assert_eq!(first_frame, [0x82, 3, 0xff, 0x00, 0x7f]);

            browser_tls.write_all(&[0x82, 0x83, 1, 2, 3, 4, 0xfe, 2, 0x7c]).await.unwrap();
            browser_tls.flush().await.unwrap();
            let mut second_frame = [0u8; 5];
            browser_tls.read_exact(&mut second_frame).await.unwrap();
            assert_eq!(second_frame, [0x82, 3, b'O', b'K', b'!']);

            drop(browser_tls);
            upstream.await.unwrap();
            worker.await.unwrap();
            let ws = state.ws.lock().unwrap();
            assert_eq!(ws.len(), 1);
            assert_eq!(ws[0].host, "localhost");
            assert!(ws[0].bytes_client_to_server >= 9);
            assert!(ws[0].bytes_server_to_client >= 10);
        }).await.expect("verified WSS MITM echo timed out");
}

#[tokio::test]
async fn wss_non_switch_response_does_not_create_session() {
    tokio::time::timeout(Duration::from_secs(12), async {
            let upstream_dir = tempfile::tempdir().unwrap();
            let upstream_ca = crate::webtls::init_ca(upstream_dir.path()).unwrap();
            let proxy_dir = tempfile::tempdir().unwrap();
            let proxy_ca = crate::webtls::init_ca(proxy_dir.path()).unwrap();
            let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = backend_listener.local_addr().unwrap().port();
            let backend_ca = Arc::clone(&upstream_ca);
            let upstream = tokio::spawn(async move {
                let (socket, _) = backend_listener.accept().await.unwrap();
                let mut tls = crate::webtls::tls_acceptor(&backend_ca, "localhost")
                    .unwrap().accept(socket).await.unwrap();
                let (head, _) = crate::webtls::read_http_message(&mut tls).await.unwrap();
                assert!(head.starts_with("GET /ws HTTP/1.1"));
                tls.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\nConnection: close\r\n\r\nNO")
                    .await.unwrap();
                tls.flush().await.unwrap();
            });
            let state = shared(true, Some(Arc::clone(&proxy_ca)));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let worker_state = Arc::clone(&state);
            let backend_connector = trusted_connector(&upstream_ca);
            let worker = tokio::spawn(async move {
                let (mut connection, _) = listener.accept().await.unwrap();
                let (connect_head, _) = crate::webtls::read_http_message(&mut connection).await.unwrap();
                connect_tunnel_with_ws_connector(connection, worker_state, &connect_head, None, Some(backend_connector))
                    .await.unwrap();
            });
            let mut browser = TcpStream::connect(addr).await.unwrap();
            browser.write_all(format!("CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n").as_bytes()).await.unwrap();
            assert!(read_http_response_head(&mut browser).await.unwrap().starts_with("HTTP/1.1 200"));
            let mut browser_tls = trusted_connector(&proxy_ca).connect(
                rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap(), browser
            ).await.unwrap();
            browser_tls.write_all(format!(
                "GET /ws HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
            ).as_bytes()).await.unwrap();
            let resp = read_http_response_head(&mut browser_tls).await.unwrap();
            assert!(resp.starts_with("HTTP/1.1 403"), "{resp:?}");
            let mut body = [0u8; 2];
            browser_tls.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"NO");
            drop(browser_tls);
            upstream.await.unwrap();
            worker.await.unwrap();
            assert!(state.ws.lock().unwrap().is_empty());
        }).await.expect("WSS rejected-upgrade fixture timed out");
}

#[tokio::test]
async fn verified_https_upstream_preserves_response_bytes() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let directory = tempfile::tempdir().unwrap();
        let ca = crate::webtls::init_ca(directory.path()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_ca = Arc::clone(&ca);
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut tls = crate::webtls::tls_acceptor(&server_ca, "localhost")
                .unwrap()
                .accept(socket)
                .await
                .unwrap();
            let (head, _) = crate::webtls::read_http_message(&mut tls).await.unwrap();
            assert!(head.starts_with("GET /verified HTTP/1.1"));
            tls.write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\nconnection: close\r\n\r\n")
                .await
                .unwrap();
            tls.write_all(&[0xff, 0x00, 0x01]).await.unwrap();
            tls.flush().await.unwrap();
        });
        let client = reqwest::Client::builder()
            .add_root_certificate(reqwest::Certificate::from_pem(ca.cert_pem.as_bytes()).unwrap())
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .unwrap();
        let (status, _, body) = execute_request_with_client(
            &client,
            "GET",
            &format!("https://localhost:{port}/verified"),
            &[],
            &[],
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(body, vec![0xff, 0x00, 0x01]);
        server.await.unwrap();
    })
    .await
    .expect("verified upstream HTTPS request timed out");
}

#[tokio::test]
async fn chunked_binary_request_roundtrips_through_http_proxy() {
    tokio::time::timeout(Duration::from_secs(10), async {
            let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let backend_port = upstream_listener.local_addr().unwrap().port();
            let backend = tokio::spawn(async move {
                let (mut server, _) = upstream_listener.accept().await.unwrap();
                let (request_head, body) = crate::webtls::read_http_message(&mut server).await.unwrap();
                assert!(request_head.starts_with("POST /binary HTTP/1.1"));
                assert_eq!(body, [0xff, 0x00, 0x7f]);
                server.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nACK").await.unwrap();
            });
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let state = shared(false, None);
            let worker_state = Arc::clone(&state);
            let worker = tokio::spawn(async move {
                let (client, _) = listener.accept().await.unwrap();
                handle_conn(client, worker_state).await.unwrap();
            });
            let mut browser = TcpStream::connect(address).await.unwrap();
            let head = format!(
                "POST http://127.0.0.1:{backend_port}/binary HTTP/1.1\r\nHost: 127.0.0.1:{backend_port}\r\nTransfer-Encoding: chunked\r\n\r\n"
            );
            browser.write_all(head.as_bytes()).await.unwrap();
            browser.write_all(b"3\r\n\xff\x00\x7f\r\n0\r\n\r\n").await.unwrap();
            let mut response = Vec::new();
            browser.read_to_end(&mut response).await.unwrap();
            assert!(response.starts_with(b"HTTP/1.1 200"), "{response:?}");
            assert!(response.ends_with(b"ACK"), "{response:?}");
            worker.await.unwrap();
            backend.await.unwrap();
            assert_eq!(state.captured.lock().unwrap()[0].status, 200);
        }).await.expect("chunked proxy fixture timed out");
}

#[tokio::test]
async fn binary_http_roundtrip_through_proxy() {
    tokio::time::timeout(Duration::from_secs(10), async {
            let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let upstream_port = upstream_listener.local_addr().unwrap().port();
            let upstream = tokio::spawn(async move {
                let (mut conn, _) = upstream_listener.accept().await.unwrap();
                let (_, body) = crate::webtls::read_http_message(&mut conn).await.unwrap();
                assert_eq!(body, vec![0xff,0x00,0x7f]);
                conn.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 3\r\nConnection: close\r\n\r\n").await.unwrap();
                conn.write_all(&[0xff,0x00,0x01]).await.unwrap();
            });
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy_addr = listener.local_addr().unwrap();
            let state = shared(false, None);
            let serve_state = Arc::clone(&state);
            let worker = tokio::spawn(async move {
                let (conn, _) = listener.accept().await.unwrap();
                handle_conn(conn, serve_state).await.unwrap();
            });
            let mut browser = TcpStream::connect(proxy_addr).await.unwrap();
            let head = format!("POST http://127.0.0.1:{upstream_port}/binary HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\nContent-Length: 3\r\n\r\n");
            browser.write_all(head.as_bytes()).await.unwrap();
            browser.write_all(&[0xff,0x00,0x7f]).await.unwrap();
            let mut output = Vec::new();
            browser.read_to_end(&mut output).await.unwrap();
            assert!(output.starts_with(b"HTTP/1.1 200"), "{output:?}");
            assert!(output.ends_with(&[0xff,0x00,0x01]), "{output:?}");
            worker.await.unwrap();
            upstream.await.unwrap();
            let captured = state.captured.lock().unwrap();
            assert_eq!(captured.len(), 1);
            assert_eq!(captured[0].status, 200);
        }).await.expect("local HTTP proxy timed out");
}

#[tokio::test]
async fn connect_half_close_keeps_reverse_flow_alive() {
    tokio::time::timeout(Duration::from_secs(10), async {
            let backend_listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
            let backend_port=backend_listener.local_addr().unwrap().port();
            let backend=tokio::spawn(async move {
                let (mut conn,_)=backend_listener.accept().await.unwrap();
                let mut got=Vec::new();
                conn.read_to_end(&mut got).await.unwrap();
                assert_eq!(got,b"PING");
                conn.write_all(b"PONG").await.unwrap();
            });
            let proxy_listener=TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr=proxy_listener.local_addr().unwrap();
            let state=shared(false,None);
            let worker=tokio::spawn(async move {
                let (conn,_)=proxy_listener.accept().await.unwrap();
                handle_conn(conn,state).await.unwrap();
            });
            let mut browser=TcpStream::connect(addr).await.unwrap();
            browser.write_all(format!("CONNECT 127.0.0.1:{backend_port} HTTP/1.1\r\nHost: 127.0.0.1:{backend_port}\r\n\r\n").as_bytes()).await.unwrap();
            let (established,_)=crate::webtls::read_http_message(&mut browser).await.unwrap();
            assert!(established.starts_with("HTTP/1.1 200"), "{established}");
            browser.write_all(b"PING").await.unwrap();
            browser.shutdown().await.unwrap();
            let mut got=Vec::new();
            browser.read_to_end(&mut got).await.unwrap();
            assert_eq!(got,b"PONG");
            worker.await.unwrap(); backend.await.unwrap();
        }).await.expect("CONNECT passthrough timed out");
}

#[tokio::test]
async fn intercepted_tls_request_can_be_dropped() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let folder = tempfile::tempdir().unwrap();
        let ca = crate::webtls::init_ca(folder.path()).unwrap();
        let shared = shared(true, Some(Arc::clone(&ca)));
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = proxy_listener.local_addr().unwrap();
        let worker_state = Arc::clone(&shared);
        let worker = tokio::spawn(async move {
            let (conn, _) = proxy_listener.accept().await.unwrap();
            handle_conn(conn, worker_state).await.unwrap();
        });
        let mut browser = TcpStream::connect(addr).await.unwrap();
        browser
            .write_all(b"CONNECT localhost:8443 HTTP/1.1\r\nHost: localhost:8443\r\n\r\n")
            .await
            .unwrap();
        let (established, _) = crate::webtls::read_http_message(&mut browser)
            .await
            .unwrap();
        assert!(established.starts_with("HTTP/1.1 200"));
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(
                crate::webtls::pem_to_der(&ca.cert_pem),
            ))
            .unwrap();
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let mut tls = connector
            .connect(
                rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap(),
                browser,
            )
            .await
            .unwrap();
        tls.write_all(b"GET /health HTTP/1.1\r\nHost: localhost:8443\r\n\r\n")
            .await
            .unwrap();
        worker.await.unwrap();
        assert_eq!(shared.pending.lock().unwrap().len(), 1);
        let ctx = WebCtx {
            proxy_running: AtomicBool::new(true),
            proxy_port: AtomicU16::new(0),
            proxy_handle: Mutex::new(None),
            shared,
            ca: Mutex::new(Some(ca)),
        };
        proxy_application::drop_pending(1, &ctx).await.unwrap();
        let mut response = [0u8; 512];
        let size = tls.read(&mut response).await.unwrap();
        assert!(
            response[..size].starts_with(b"HTTP/1.1 502"),
            "{:?}",
            &response[..size]
        );
    })
    .await
    .expect("HTTPS intercepted request timed out");
}

#[tokio::test]
async fn stopped_proxy_rejects_late_intercept_request() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let shared = shared(true, None);
        let ctx = WebCtx {
            proxy_running: AtomicBool::new(true),
            proxy_port: AtomicU16::new(0),
            proxy_handle: Mutex::new(None),
            shared: Arc::clone(&shared),
            ca: Mutex::new(None),
        };
        proxy_application::stop_proxy(&ctx).await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let mut browser = TcpStream::connect(address).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        browser
            .write_all(b"GET http://example.invalid/path HTTP/1.1\r\nHost: example.invalid\r\n\r\n")
            .await
            .unwrap();
        handle_conn(server, Arc::clone(&shared)).await.unwrap();
        let mut response = [0_u8; 512];
        let n = browser.read(&mut response).await.unwrap();
        assert!(response[..n].starts_with(b"HTTP/1.1 503"));
        assert!(shared.pending.lock().unwrap().is_empty());
    })
    .await
    .expect("stopped-proxy regression timed out");
}
