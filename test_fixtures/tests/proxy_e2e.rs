use std::time::Duration;

use domain::ProxyConfig;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};

fn test_ca() -> (String, String) {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "Relay Test CA");
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let key = KeyPair::generate().expect("ca key");
    let cert = params.self_signed(&key).expect("self signed ca");
    (cert.pem(), key.serialize_pem())
}

#[tokio::test]
#[ignore = "requires network access"]
async fn https_mitm_capture_roundtrip() {
    let (cert_pem, key_pem) = test_ca();
    let (events, _) = tokio::sync::broadcast::channel(32);
    let handle = proxy::ProxyHandle::start(
        ProxyConfig {
            host: "127.0.0.1".into(),
            port: 0,
            ca_cert_pem: cert_pem.clone(),
            ca_key_pem: key_pem,
            upstream: None,
        },
        "test-session".into(),
        events.clone(),
    )
    .await
    .expect("proxy starts");
    let mut receiver = events.subscribe();
    let port = handle.status().port;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{port}")).expect("proxy url"))
        .add_root_certificate(
            reqwest::Certificate::from_pem(cert_pem.as_bytes()).expect("root cert"),
        )
        .timeout(Duration::from_secs(30))
        .build()
        .expect("client");
    let response = client
        .get("https://example.com/")
        .send()
        .await
        .expect("request through proxy");
    assert!(
        response.status().is_success(),
        "status {}",
        response.status()
    );
    let body = response.text().await.expect("body");
    assert!(body.contains("Example Domain"));

    let exchange = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
        .await
        .expect("capture event")
        .expect("exchange");
    assert_eq!(exchange.method, "GET");
    assert_eq!(exchange.host, "example.com");
    assert_eq!(exchange.status, 200);
    assert!(exchange.response_body.text.contains("Example Domain"));
    assert!(exchange.url.starts_with("https://example.com"));

    handle.shutdown().await;
}

#[tokio::test]
async fn replay_posts_to_local_endpoint() {
    use domain::{Body, Draft, Header, ReplayOptions};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind local server");
    let address = listener.local_addr().expect("addr");
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let mut buffer = vec![0u8; 8192];
        let read = stream.read(&mut buffer).await.expect("read");
        let request = String::from_utf8_lossy(&buffer[..read]).to_string();
        assert!(request.starts_with("POST /ping"), "{request}");
        assert!(request.contains("x-relay-test: yes"), "{request}");
        let payload = "{\"ok\":true}";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            payload.len(),
            payload
        );
        stream.write_all(response.as_bytes()).await.expect("write");
    });

    let draft = Draft {
        id: "draft-test".into(),
        session_id: "test-session".into(),
        source_exchange_id: "source".into(),
        method: "POST".into(),
        url: format!("http://{address}/ping"),
        headers: vec![
            Header::new("Content-Type", "application/json"),
            Header::new("X-Relay-Test", "yes"),
        ],
        cookies: vec![],
        body: Body::from_utf8_text("{\"hello\":\"relay\"}".into(), "application/json"),
        options: ReplayOptions::default(),
        created_at: chrono_now(),
        updated_at: chrono_now(),
    };

    let result = replay::replay(&draft).await.expect("replay succeeds");
    assert_eq!(result.status, 200);
    assert!(result.body.text.contains("\"ok\":true"));
    server.await.expect("server task");
}

fn chrono_now() -> String {
    "2026-01-01T00:00:00Z".into()
}

#[tokio::test]
#[ignore = "requires network access"]
async fn generated_ca_builds_install_page_and_works() {
    use std::time::Duration;

    let (cert_pem, key_pem) = proxy::generate_ca().expect("generated ca");
    let mobileconfig = proxy::ca_mobileconfig(&cert_pem, "Relay Local CA").expect("profile");
    assert!(mobileconfig.contains("com.apple.security.root"));
    assert!(mobileconfig.contains("Relay Local CA"));

    let (events, _) = tokio::sync::broadcast::channel(16);
    let handle = proxy::ProxyHandle::start(
        ProxyConfig {
            host: "127.0.0.1".into(),
            port: 0,
            ca_cert_pem: cert_pem.clone(),
            ca_key_pem: key_pem,
            upstream: None,
        },
        "generated-ca".into(),
        events.clone(),
    )
    .await
    .expect("proxy starts");
    let mut receiver = events.subscribe();
    let proxy_client = reqwest::Client::builder()
        .proxy(
            reqwest::Proxy::all(format!("http://127.0.0.1:{}", handle.status().port))
                .expect("proxy url"),
        )
        .add_root_certificate(reqwest::Certificate::from_pem(cert_pem.as_bytes()).expect("root"))
        .timeout(Duration::from_secs(30))
        .build()
        .expect("client");
    let install = proxy_client
        .get("http://mitm.it/")
        .send()
        .await
        .expect("mitm.it page");
    assert!(install.status().is_success());
    assert!(install
        .text()
        .await
        .expect("page")
        .contains("Relay certificate"));
    let cer = proxy_client
        .get("http://mitm.it/cert/cer")
        .send()
        .await
        .expect("mitm.it cert");
    assert_eq!(
        cer.bytes().await.expect("cert").first().copied(),
        Some(0x30)
    );
    let response = proxy_client
        .get("https://example.com/")
        .send()
        .await
        .expect("request through generated ca proxy");
    assert!(response.status().is_success());
    let exchange = tokio::time::timeout(Duration::from_secs(10), receiver.recv())
        .await
        .expect("event")
        .expect("exchange");
    assert_eq!(exchange.host, "example.com");
    handle.shutdown().await;
}

#[tokio::test]
#[ignore = "requires network access"]
async fn authenticated_upstream_proxy_is_used() {
    use domain::UpstreamProxy;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_port = listener.local_addr().expect("addr").port();
    let upstream = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.expect("upstream accept");
        let mut buffer = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read = client.read(&mut chunk).await.expect("read connect");
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&chunk[..read]);
            if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        let request = String::from_utf8_lossy(&buffer).to_string();
        assert!(request.starts_with("CONNECT example.com:443"), "{request}");
        assert!(
            request
                .to_ascii_lowercase()
                .contains("proxy-authorization: basic"),
            "missing proxy auth: {request}"
        );
        assert!(
            request.contains("Basic dXNlcjpzZWNyZXQ="),
            "wrong proxy auth: {request}"
        );
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .expect("connect response");
        let mut remote = tokio::net::TcpStream::connect("example.com:443")
            .await
            .expect("remote connect");
        let _ = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
    });

    let (cert_pem, key_pem) = proxy::generate_ca().expect("ca");
    let (events, _) = tokio::sync::broadcast::channel(16);
    let handle = proxy::ProxyHandle::start(
        ProxyConfig {
            host: "127.0.0.1".into(),
            port: 0,
            ca_cert_pem: cert_pem.clone(),
            ca_key_pem: key_pem,
            upstream: Some(UpstreamProxy {
                url: format!("http://127.0.0.1:{upstream_port}"),
                username: Some("user".into()),
                password: Some("secret".into()),
            }),
        },
        "upstream-test".into(),
        events,
    )
    .await
    .expect("relay starts");

    let client = reqwest::Client::builder()
        .proxy(
            reqwest::Proxy::all(format!("http://127.0.0.1:{}", handle.status().port))
                .expect("proxy"),
        )
        .add_root_certificate(reqwest::Certificate::from_pem(cert_pem.as_bytes()).expect("root"))
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("client");
    let response = client
        .get("https://example.com/")
        .send()
        .await
        .expect("through relay");
    assert!(response.status().is_success());
    assert!(response
        .text()
        .await
        .expect("body")
        .contains("Example Domain"));
    drop(client);
    upstream.abort();
    let _ = upstream.await;
    handle.shutdown().await;
}

#[tokio::test]
async fn local_targets_bypass_upstream_proxy() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let local = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("local bind");
    let local_port = local.local_addr().expect("local addr").port();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match local.accept().await {
                Ok(value) => value,
                Err(_) => break,
            };
            let mut buffer = [0u8; 2048];
            let _ = stream.read(&mut buffer).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 8\r\nConnection: close\r\n\r\nlocal-ok")
                .await;
        }
    });

    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("upstream bind");
    let upstream_port = upstream.local_addr().expect("upstream addr").port();
    let hits = Arc::new(AtomicUsize::new(0));
    let hits_task = hits.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = upstream.accept().await {
            hits_task.fetch_add(1, Ordering::Relaxed);
            let _ = stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
        }
    });

    let (cert_pem, key_pem) = proxy::generate_ca().expect("ca");
    let (events, _) = tokio::sync::broadcast::channel(16);
    let handle = proxy::ProxyHandle::start(
        ProxyConfig {
            host: "127.0.0.1".into(),
            port: 0,
            ca_cert_pem: cert_pem,
            ca_key_pem: key_pem,
            upstream: Some(domain::UpstreamProxy {
                url: format!("http://127.0.0.1:{upstream_port}"),
                username: None,
                password: None,
            }),
        },
        "local-bypass".into(),
        events,
    )
    .await
    .expect("relay starts");

    let client = reqwest::Client::builder()
        .proxy(
            reqwest::Proxy::all(format!("http://127.0.0.1:{}", handle.status().port))
                .expect("proxy"),
        )
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("client");
    let response = client
        .get(format!("http://127.0.0.1:{local_port}/"))
        .send()
        .await
        .expect("local request");
    assert!(response.status().is_success());
    assert!(response.text().await.expect("body").contains("local-ok"));
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(
        hits.load(Ordering::Relaxed),
        0,
        "upstream must not be used for local targets"
    );
    handle.shutdown().await;
}
