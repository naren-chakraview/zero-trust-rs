//! Integration test for the admin and proxy TLS postures (F10, N6).
//!
//! Runs the real `zt-gateway` binary with `client_auth: required` and an
//! ephemeral CA, then drives it over TLS with rustls. It checks that:
//!
//! - admin accepts a connection with no client certificate, so bootstrap can
//!   fetch a first X.509 SVID (F10);
//! - a client certificate presented on admin reaches the handler, so
//!   cert-bound issuance works (N6);
//! - the proxy refuses a connection with no client certificate.
//!
//! It is a regression guard. An earlier change stopped admin from requesting
//! client certs, which silently broke cert-bound issuance.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};

const ORDERS_ID: &str = "spiffe://chakra.internal/ns/orders/sa/orders-svc";
const INVENTORY_ID: &str = "spiffe://chakra.internal/ns/inventory/sa/inventory-svc";

struct Gateway {
    child: Child,
    dir: PathBuf,
    admin_port: u16,
    proxy_port: u16,
    server_root: CertificateDer<'static>,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Starts the gateway over TLS with `client_auth: required` and an ephemeral CA.
fn start_gateway(name: &str) -> Gateway {
    let dir = std::env::temp_dir().join(format!("zt-admin-tls-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // The server cert is generated here so the test can trust it as a root.
    let server = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    std::fs::write(dir.join("server-cert.pem"), server.cert.pem()).unwrap();
    std::fs::write(dir.join("server-key.pem"), server.key_pair.serialize_pem()).unwrap();
    let server_root = server.cert.der().clone();

    let admin_port = free_port();
    let proxy_port = free_port();
    let registry = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/registry.yaml");
    let config = format!(
        r#"proxy_addr: 127.0.0.1:{proxy_port}
admin_addr: 127.0.0.1:{admin_port}
upstream_addr: http://127.0.0.1:9
registry_path: {registry}
protected_workload: {INVENTORY_ID}
token_ttl_seconds: 300
tls:
  cert_path: {cert}
  key_path: {key}
  client_auth: required
"#,
        cert = dir.join("server-cert.pem").display(),
        key = dir.join("server-key.pem").display(),
    );
    let config_path = dir.join("gateway.config.yaml");
    std::fs::write(&config_path, config).unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_zt-gateway"))
        .arg(&config_path)
        .spawn()
        .expect("zt-gateway should start");
    let gateway = Gateway {
        child,
        dir,
        admin_port,
        proxy_port,
        server_root,
    };
    wait_for_port(admin_port);
    gateway
}

fn wait_for_port(port: u16) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(Instant::now() < deadline, "gateway never listened on {port}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// A TLS client identity: a certificate from the gateway's CA and its key.
struct ClientIdentity {
    cert_pem: String,
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

/// Has the gateway issue an X.509 SVID for `workload` over admin, with no
/// client certificate. This is the bootstrap path F10 keeps open.
fn issue_identity(gw: &Gateway, workload: &str, spiffe_id: &str, bootstrap_token: &str) -> ClientIdentity {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.subject_alt_names = vec![SanType::URI(spiffe_id.try_into().unwrap())];
    let csr_pem = params.serialize_request(&key).unwrap().pem().unwrap();

    let body = serde_json::json!({
        "workload_name": workload,
        "csr_pem": csr_pem,
        "bootstrap_token": bootstrap_token,
    })
    .to_string();
    let (status, response) = https_request(gw, None, gw.admin_port, "POST", "/v1/svid/x509", &body)
        .expect("admin must accept a connection without a client certificate");
    assert_eq!(status, 200, "x509 issuance over admin failed: {response}");

    let cert_pem = serde_json::from_str::<serde_json::Value>(&response).unwrap()["cert_pem"]
        .as_str()
        .unwrap()
        .to_string();
    let cert = rustls_pemfile::certs(&mut cert_pem.as_bytes()).next().unwrap().unwrap();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
    ClientIdentity { cert_pem, cert, key }
}

/// Sends one HTTP/1.1 request over TLS, optionally presenting a client
/// certificate. Returns the status and body, or an error if the TLS handshake
/// or the request failed.
fn https_request(
    gw: &Gateway,
    identity: Option<&ClientIdentity>,
    port: u16,
    method: &str,
    path: &str,
    body: &str,
) -> Result<(u16, String), String> {
    let mut roots = RootCertStore::empty();
    roots.add(gw.server_root.clone()).unwrap();
    let builder = ClientConfig::builder().with_root_certificates(roots);
    let config = match identity {
        Some(id) => builder
            .with_client_auth_cert(vec![id.cert.clone()], id.key.clone_key())
            .unwrap(),
        None => builder.with_no_client_auth(),
    };
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut tcp = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut tcp);

    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    tls.write_all(request.as_bytes()).map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    tls.read_to_end(&mut raw).map_err(|e| e.to_string())?;

    let text = String::from_utf8_lossy(&raw).to_string();
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| format!("no HTTP status in response: {text:?}"))?;
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b.to_string()).unwrap_or_default();
    Ok((status, body))
}

#[test]
#[ignore = "spawns zt-gateway and needs free loopback ports"]
fn admin_accepts_bootstrap_without_a_certificate_and_sees_one_when_presented() {
    let gw = start_gateway("admin");

    // Bootstrap: no client certificate, and admin still completes the TLS
    // handshake and issues the first SVID.
    let orders = issue_identity(&gw, "orders-svc", ORDERS_ID, "orders-dev-secret");

    // With a certificate presented on admin, the handler sees it. Issuance is
    // cert-bound because mTLS is on, so the token must carry a `cnf` claim.
    let token_body = serde_json::json!({
        "workload_name": "orders-svc",
        "audience": INVENTORY_ID,
        "bootstrap_token": "orders-dev-secret",
    })
    .to_string();
    let (status, body) = https_request(&gw, Some(&orders), gw.admin_port, "POST", "/v1/svid/jwt", &token_body)
        .expect("admin must accept the presented certificate");
    assert_eq!(status, 200, "cert-bound issuance failed: {body}");
    let token = serde_json::from_str::<serde_json::Value>(&body).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    let payload = token.split('.').nth(1).unwrap();
    let claims: serde_json::Value = serde_json::from_slice(
        &base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, payload).unwrap(),
    )
    .unwrap();
    assert!(
        claims["cnf"]["x5t#S256"].is_string(),
        "a presented certificate must bind the token (N6), got claims {claims}"
    );

    // Without a certificate, the same request is refused: the gateway requires
    // one to bind issuance.
    let (status, body) = https_request(&gw, None, gw.admin_port, "POST", "/v1/svid/jwt", &token_body)
        .expect("admin still accepts the connection");
    assert_ne!(status, 200, "unbound issuance must be refused when mTLS is on: {body}");
    assert!(body.contains("client certificate"), "unexpected refusal: {body}");

    let _ = orders.cert_pem;
}

#[test]
#[ignore = "spawns zt-gateway and needs free loopback ports"]
fn proxy_refuses_a_connection_without_a_client_certificate() {
    let gw = start_gateway("proxy");
    let result = https_request(&gw, None, gw.proxy_port, "GET", "/demo", "");
    assert!(result.is_err(), "the proxy must refuse a client with no certificate, got {result:?}");
}
