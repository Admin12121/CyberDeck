//! Deterministic local HTTP, HTTPS, CONNECT and WSS integration fixtures.

use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn shared(
    intercept: bool,
    ca: Option<Arc<crate::features::web::webtls::CaState>>,
) -> Arc<ProxyShared> {
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

fn trusted_connector(ca: &crate::features::web::webtls::CaState) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            crate::features::web::webtls::pem_to_der(&ca.cert_pem),
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
            let upstream_ca = crate::features::web::webtls::init_ca(upstream_dir.path()).unwrap();
            let proxy_dir = tempfile::tempdir().unwrap();
            let proxy_ca = crate::features::web::webtls::init_ca(proxy_dir.path()).unwrap();

            let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let backend_port = backend_listener.local_addr().unwrap().port();
            let backend_ca = Arc::clone(&upstream_ca);
            let upstream = tokio::spawn(async move {
                let (socket, _) = backend_listener.accept().await.unwrap();
                let mut tls = crate::features::web::webtls::tls_acceptor(&backend_ca, "localhost")
                    .unwrap().accept(socket).await.unwrap();
                let (head, body) = crate::features::web::webtls::read_http_message(&mut tls).await.unwrap();
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
                let (connect_head, _) = crate::features::web::webtls::read_http_message(&mut connection).await.unwrap();
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
            let upstream_ca = crate::features::web::webtls::init_ca(upstream_dir.path()).unwrap();
            let proxy_dir = tempfile::tempdir().unwrap();
            let proxy_ca = crate::features::web::webtls::init_ca(proxy_dir.path()).unwrap();
            let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = backend_listener.local_addr().unwrap().port();
            let backend_ca = Arc::clone(&upstream_ca);
            let upstream = tokio::spawn(async move {
                let (socket, _) = backend_listener.accept().await.unwrap();
                let mut tls = crate::features::web::webtls::tls_acceptor(&backend_ca, "localhost")
                    .unwrap().accept(socket).await.unwrap();
                let (head, _) = crate::features::web::webtls::read_http_message(&mut tls).await.unwrap();
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
                let (connect_head, _) = crate::features::web::webtls::read_http_message(&mut connection).await.unwrap();
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
        let ca = crate::features::web::webtls::init_ca(directory.path()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server_ca = Arc::clone(&ca);
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut tls = crate::features::web::webtls::tls_acceptor(&server_ca, "localhost")
                .unwrap()
                .accept(socket)
                .await
                .unwrap();
            let (head, _) = crate::features::web::webtls::read_http_message(&mut tls)
                .await
                .unwrap();
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
                let (request_head, body) = crate::features::web::webtls::read_http_message(&mut server).await.unwrap();
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
                let (_, body) = crate::features::web::webtls::read_http_message(&mut conn).await.unwrap();
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
            let (established,_)=crate::features::web::webtls::read_http_message(&mut browser).await.unwrap();
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
        let ca = crate::features::web::webtls::init_ca(folder.path()).unwrap();
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
        let (established, _) = crate::features::web::webtls::read_http_message(&mut browser)
            .await
            .unwrap();
        assert!(established.starts_with("HTTP/1.1 200"));
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(
                crate::features::web::webtls::pem_to_der(&ca.cert_pem),
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

#[tokio::test]
async fn proxy_stop_cancels_active_connect_and_restart_rebinds_port() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let directory = tempfile::tempdir().unwrap();
        let shared = shared(false, None);
        shared.running.store(false, Ordering::Relaxed);
        let ctx = WebCtx {
            proxy_running: AtomicBool::new(false),
            proxy_port: AtomicU16::new(0),
            proxy_handle: Mutex::new(None),
            shared,
            ca: Mutex::new(None),
        };
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        for _ in 0..2 {
            let status = proxy_application::start_proxy(port, &ctx, directory.path())
                .await
                .unwrap();
            assert!(status.running);
            let mut browser = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            browser.write_all(format!(
                "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
            ).as_bytes()).await.unwrap();
            let (mut backend, _) = upstream.accept().await.unwrap();
            assert!(read_http_response_head(&mut browser).await.unwrap().starts_with("HTTP/1.1 200"));
            assert!(!proxy_application::stop_proxy(&ctx).await.unwrap().running);
            let mut buf = [0u8; 1];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), backend.read(&mut buf))
                    .await.unwrap().unwrap(), 0,
                "CONNECT upstream socket survived proxy_stop"
            );
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(2), browser.read(&mut buf))
                    .await.unwrap().unwrap(), 0,
                "browser CONNECT socket survived proxy_stop"
            );
            assert!(ctx.proxy_handle.lock().unwrap().is_none());
        }
    }).await.expect("CONNECT lifecycle test timed out");
}

#[tokio::test]
async fn proxy_stop_drains_intercept_and_restart_has_no_stale_pending_request() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let directory = tempfile::tempdir().unwrap();
        let shared = shared(true, None);
        shared.running.store(false, Ordering::Relaxed);
        let ctx = WebCtx {
            proxy_running: AtomicBool::new(false),
            proxy_port: AtomicU16::new(0),
            proxy_handle: Mutex::new(None),
            shared: Arc::clone(&shared),
            ca: Mutex::new(None),
        };
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = reserved.local_addr().unwrap().port();
        drop(reserved);
        proxy_application::start_proxy(port, &ctx, directory.path()).await.unwrap();
        let mut first = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        first.write_all(b"POST http://127.0.0.1:9/held HTTP/1.1\r\nHost: 127.0.0.1:9\r\nContent-Length: 3\r\n\r\n\xff\x00\x7f")
            .await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while shared.pending.lock().unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        let old_id = *shared.pending.lock().unwrap().keys().next().unwrap();
        proxy_application::stop_proxy(&ctx).await.unwrap();
        let mut response = [0u8; 512];
        let n = first.read(&mut response).await.unwrap();
        assert!(response[..n].starts_with(b"HTTP/1.1 503"));
        assert!(shared.pending.lock().unwrap().is_empty());
        proxy_application::start_proxy(port, &ctx, directory.path()).await.unwrap();
        assert!(shared.pending.lock().unwrap().is_empty());
        let mut next = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        next.write_all(b"GET http://127.0.0.1:9/next HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
            .await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while shared.pending.lock().unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        let new_id = *shared.pending.lock().unwrap().keys().next().unwrap();
        assert_ne!(old_id, new_id);
        proxy_application::drop_pending(new_id, &ctx).await.unwrap();
        let n = next.read(&mut response).await.unwrap();
        assert!(response[..n].starts_with(b"HTTP/1.1 502"));
        proxy_application::stop_proxy(&ctx).await.unwrap();
        assert!(shared.pending.lock().unwrap().is_empty());
    }).await.expect("held-request lifecycle test timed out");
}

#[tokio::test]
async fn wss_rejected_upgrade_relays_chunked_binary_without_waiting_for_eof() {
    tokio::time::timeout(Duration::from_secs(12), async {
        let server_dir = tempfile::tempdir().unwrap();
        let server_ca = crate::features::web::webtls::init_ca(server_dir.path()).unwrap();
        let proxy_dir = tempfile::tempdir().unwrap();
        let proxy_ca = crate::features::web::webtls::init_ca(proxy_dir.path()).unwrap();
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_port = upstream_listener.local_addr().unwrap().port();
        let server_ca_clone = Arc::clone(&server_ca);
        let backend = tokio::spawn(async move {
            let (socket, _) = upstream_listener.accept().await.unwrap();
            let mut tls = crate::features::web::webtls::tls_acceptor(&server_ca_clone, "localhost")
                .unwrap().accept(socket).await.unwrap();
            let (head, _) = crate::features::web::webtls::read_http_message(&mut tls).await.unwrap();
            assert!(head.starts_with("GET /ws HTTP/1.1"));
            tls.write_all(b"HTTP/1.1 403 Forbidden\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n")
                .await.unwrap();
            tls.write_all(b"3;id=1\r\n\xff\x00\x7f\r\n0\r\n\r\n").await.unwrap();
            tls.flush().await.unwrap();
            // Keep the upstream alive after the final chunk. The relay must
            // finish based on framing, not wait for connection shutdown.
            tokio::time::sleep(Duration::from_millis(500)).await;
        });
        let state = shared(true, Some(Arc::clone(&proxy_ca)));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let ws_connector = trusted_connector(&server_ca);
        let worker_state = Arc::clone(&state);
        let worker = tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.unwrap();
            let (connect_head, _) = crate::features::web::webtls::read_http_message(&mut client).await.unwrap();
            connect_tunnel_with_ws_connector(
                client, worker_state, &connect_head, None, Some(ws_connector)
            ).await.unwrap();
        });
        let mut browser = TcpStream::connect(proxy_addr).await.unwrap();
        browser.write_all(format!(
            "CONNECT localhost:{backend_port} HTTP/1.1\r\nHost: localhost:{backend_port}\r\n\r\n"
        ).as_bytes()).await.unwrap();
        assert!(read_http_response_head(&mut browser).await.unwrap().starts_with("HTTP/1.1 200"));
        let mut client_tls = trusted_connector(&proxy_ca).connect(
            rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap(), browser
        ).await.unwrap();
        client_tls.write_all(format!(
            "GET /ws HTTP/1.1\r\nHost: localhost:{backend_port}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
        ).as_bytes()).await.unwrap();
        assert!(read_http_response_head(&mut client_tls).await.unwrap().starts_with("HTTP/1.1 403"));
        let expected = b"3;id=1\r\n\xff\x00\x7f\r\n0\r\n\r\n";
        let mut actual = vec![0u8; expected.len()];
        client_tls.read_exact(&mut actual).await.unwrap();
        assert_eq!(&actual, expected);
        worker.await.unwrap();
        backend.await.unwrap();
        assert!(state.ws.lock().unwrap().is_empty());
    }).await.expect("WSS chunked rejection fixture timed out");
}

#[tokio::test]
async fn proxy_stop_cancels_inflight_forward_without_late_capture() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let directory = tempfile::tempdir().unwrap();
        let shared = shared(true, None);
        shared.running.store(false, Ordering::Relaxed);
        let ctx = Arc::new(WebCtx {
            proxy_running: AtomicBool::new(false),
            proxy_port: AtomicU16::new(0),
            proxy_handle: Mutex::new(None),
            shared: Arc::clone(&shared),
            ca: Mutex::new(None),
        });
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = reserved.local_addr().unwrap().port();
        drop(reserved);
        proxy_application::start_proxy(proxy_port, &ctx, directory.path()).await.unwrap();
        let mut browser = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
        browser.write_all(format!(
            "GET http://127.0.0.1:{upstream_port}/slow HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
        ).as_bytes()).await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while shared.pending.lock().unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }).await.unwrap();
        let id = *shared.pending.lock().unwrap().keys().next().unwrap();
        let forward_ctx = Arc::clone(&ctx);
        let forwarding = tokio::spawn(async move {
            proxy_application::forward(id, &forward_ctx).await
        });
        let (mut server_conn, _) = upstream.accept().await.unwrap();
        let (head, body) = crate::features::web::webtls::read_http_message(&mut server_conn).await.unwrap();
        assert!(head.starts_with("GET /slow HTTP/1.1"));
        assert!(body.is_empty());
        // Backend deliberately never sends a response. Stopping the proxy
        // must cancel this in-flight HTTP request and close both sockets.
        proxy_application::stop_proxy(&ctx).await.unwrap();
        let error = forwarding.await.unwrap().unwrap_err();
        assert!(error.contains("proxy stopped"), "{error}");
        let mut byte = [0u8; 1];
        assert_eq!(tokio::time::timeout(Duration::from_secs(2), browser.read(&mut byte))
            .await.unwrap().unwrap(), 0);
        assert_eq!(tokio::time::timeout(Duration::from_secs(2), server_conn.read(&mut byte))
            .await.unwrap().unwrap(), 0);
        assert!(shared.captured.lock().unwrap().is_empty());
        assert!(shared.pending.lock().unwrap().is_empty());
    }).await.expect("in-flight forward cancellation fixture timed out");
}

#[tokio::test]
async fn chunked_binary_upstream_response_is_normalized_without_corruption() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = backend.local_addr().unwrap().port();
        let backend_task = tokio::spawn(async move {
            let (mut server, _) = backend.accept().await.unwrap();
            let (head, body) = crate::features::web::webtls::read_http_message(&mut server).await.unwrap();
            assert!(head.starts_with("GET /chunked-response HTTP/1.1"));
            assert!(body.is_empty());
            server.write_all(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\n\xff\x00\x7f\r\n0\r\n\r\n"
            ).await.unwrap();
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let worker = tokio::spawn(async move {
            let (client, _) = listener.accept().await.unwrap();
            handle_conn(client, shared(false, None)).await.unwrap();
        });
        let mut browser = TcpStream::connect(proxy_addr).await.unwrap();
        browser.write_all(format!(
            "GET http://127.0.0.1:{port}/chunked-response HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
        ).as_bytes()).await.unwrap();
        let mut response = Vec::new();
        browser.read_to_end(&mut response).await.unwrap();
        let split = response.windows(4).position(|bytes| bytes == b"\r\n\r\n").unwrap();
        let headers = String::from_utf8_lossy(&response[..split]).to_ascii_lowercase();
        assert!(headers.starts_with("http/1.1 200"), "{headers}");
        assert!(headers.contains("content-length: 3"), "{headers}");
        assert!(!headers.contains("transfer-encoding:"), "{headers}");
        assert_eq!(&response[split + 4..], &[0xff, 0x00, 0x7f]);
        worker.await.unwrap();
        backend_task.await.unwrap();
    }).await.expect("chunked binary response proxy fixture timed out");
}
