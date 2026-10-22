//! Integration test for the N5 edge-mint path against a real OIDC-style IdP.
//!
//! Starts `ghcr.io/navikt/mock-oauth2-server` in Docker, logs a user in
//! through its authorization-code flow to get a real RS256 `id_token`, then
//! runs the actual `zt-gateway` binary and calls `POST /v1/svid/jwt-with-user`
//! with that token. The gateway must mint a token carrying the user's email as
//! `user`. A tampered copy of the same token must be refused.
//!
//! Needs Docker, so it is ignored by default. Run with:
//!
//!     cargo test --test user_idp_integration -- --ignored

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use reqwest::header::{CONTENT_TYPE, LOCATION};
use reqwest::{redirect, Client, Url};
use zero_trust::{JsonWebKeySet, UserIdp};

const IMAGE: &str = "ghcr.io/navikt/mock-oauth2-server:2.1.10";
/// The OIDC `client_id` is also the `aud` of the id_token, so it must match
/// the `audience` configured for the gateway.
const AUDIENCE: &str = "zt-gateway";
const PRINCIPAL_EMAIL: &str = "alice@corp.internal";

/// Stops and removes the IdP container when the test ends, even on panic.
struct IdpContainer {
    name: String,
    base_url: String,
}

impl IdpContainer {
    fn start() -> Self {
        let name = format!("zt-it-idp-{}", std::process::id());
        let run = Command::new("docker")
            .args(["run", "-d", "--rm", "--name", &name, "-p", "127.0.0.1::8080", IMAGE])
            .output()
            .expect("docker must be installed to run this test");
        assert!(run.status.success(), "docker run failed: {}", String::from_utf8_lossy(&run.stderr));

        let port_out = Command::new("docker").args(["port", &name, "8080/tcp"]).output().unwrap();
        let mapping = String::from_utf8_lossy(&port_out.stdout);
        let port = mapping
            .lines()
            .next()
            .and_then(|line| line.rsplit(':').next())
            .expect("docker port should report a host port");

        Self {
            base_url: format!("http://localhost:{port}/default"),
            name,
        }
    }
}

impl Drop for IdpContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.name]).output();
    }
}

/// Kills the gateway process when the test ends.
struct GatewayProcess(Child);

impl Drop for GatewayProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Picks a free loopback port by binding to port 0 and releasing it.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Form-encodes `pairs` as an `application/x-www-form-urlencoded` body. It
/// reuses `Url`'s query encoder so the test needs no extra dependency.
fn form_body(pairs: &[(&str, &str)]) -> String {
    Url::parse_with_params("http://placeholder/", pairs).unwrap().query().unwrap().to_string()
}

async fn wait_until_ready(client: &Client, url: &str) {
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if let Ok(response) = client.get(url).send().await {
            if response.status().is_success() {
                return;
            }
        }
        assert!(Instant::now() < deadline, "IdP never became ready at {url}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// Logs in through the mock's authorization-code flow, with `email` as the
/// only extra claim, and returns the resulting `id_token`.
async fn fetch_id_token(client: &Client, issuer: &str) -> String {
    let authorize = Url::parse_with_params(
        &format!("{issuer}/authorize"),
        [
            ("response_type", "code"),
            ("client_id", AUDIENCE),
            ("redirect_uri", "http://localhost/cb"),
            ("scope", "openid"),
            ("state", "s"),
            ("nonce", "n"),
        ],
    )
    .unwrap();
    let claims = format!(r#"{{"email":"{PRINCIPAL_EMAIL}"}}"#);
    let login = client
        .post(authorize)
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(form_body(&[("username", "alice"), ("claims", &claims)]))
        .send()
        .await
        .unwrap();
    let location = login.headers()[LOCATION].to_str().unwrap().to_string();
    let code = Url::parse(&location)
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.into_owned())
        .expect("login should redirect with an authorization code");

    let token: serde_json::Value = client
        .post(format!("{issuer}/token"))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(form_body(&[
            ("grant_type", "authorization_code"),
            ("code", &code),
            ("redirect_uri", "http://localhost/cb"),
            ("client_id", AUDIENCE),
            ("client_secret", "unused"),
        ]))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    token["id_token"].as_str().expect("token response should include id_token").to_string()
}

/// Replaces an RS256 JWT's payload with `email` set to `forged_email`, keeping
/// the original signature. The result must fail verification.
fn tamper_email(token: &str, forged_email: &str) -> String {
    let mut parts = token.split('.');
    let header = parts.next().unwrap();
    let payload = parts.next().unwrap();
    let signature = parts.next().unwrap();
    let mut claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    claims["email"] = serde_json::Value::String(forged_email.to_string());
    format!("{header}.{}.{signature}", URL_SAFE_NO_PAD.encode(claims.to_string()))
}

/// Writes a gateway config that trusts `issuer`, with keys from `jwks_json`.
fn write_gateway_config(dir: &Path, issuer: &str, jwks_json: &str, admin_port: u16, proxy_port: u16) -> PathBuf {
    let jwks_path = dir.join("idp-jwks.json");
    std::fs::write(&jwks_path, jwks_json).unwrap();
    let registry = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/registry.yaml");
    let config = format!(
        r#"listen_addr: 127.0.0.1:{proxy_port}
upstream_addr: http://127.0.0.1:9
registry_path: {registry}
protected_workload: spiffe://chakra.internal/ns/inventory/sa/inventory-svc
admin_addr: 127.0.0.1:{admin_port}
proxy_addr: 127.0.0.1:{proxy_port}
user_issuers:
  - {issuer}
user_idps:
  - issuer: {issuer}
    jwks_path: {jwks}
    audience: {AUDIENCE}
    principal_claim: email
"#,
        jwks = jwks_path.display(),
    );
    let config_path = dir.join("gateway.config.yaml");
    std::fs::write(&config_path, config).unwrap();
    config_path
}

/// Decodes the payload of an issued JWT without verifying it. The gateway has
/// already verified its own signature, and this only inspects the claims.
fn payload_claims(token: &str) -> serde_json::Value {
    let payload = token.split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

#[tokio::test]
#[ignore = "needs Docker: cargo test --test user_idp_integration -- --ignored"]
async fn gateway_mints_a_user_token_from_a_real_idp_credential() {
    let idp = IdpContainer::start();
    let client = Client::builder().redirect(redirect::Policy::none()).build().unwrap();
    wait_until_ready(&client, &format!("{}/jwks", idp.base_url)).await;

    let id_token = fetch_id_token(&client, &idp.base_url).await;
    let jwks_json = client
        .get(format!("{}/jwks", idp.base_url))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    // The library-level check against the real IdP's keys and token shape.
    let jwks = JsonWebKeySet::from_json(&jwks_json).unwrap();
    let verifier = UserIdp::new(idp.base_url.clone(), jwks, AUDIENCE.to_string(), "email".to_string());
    assert_eq!(verifier.verify(&id_token).unwrap(), PRINCIPAL_EMAIL);

    // The same credential through the running gateway binary.
    let dir = std::env::temp_dir().join(format!("zt-it-gateway-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let admin_port = free_port();
    let proxy_port = free_port();
    let config_path = write_gateway_config(&dir, &idp.base_url, &jwks_json, admin_port, proxy_port);
    let _gateway = GatewayProcess(
        Command::new(env!("CARGO_BIN_EXE_zt-gateway"))
            .arg(&config_path)
            .spawn()
            .expect("zt-gateway should start"),
    );

    let mint_url = format!("http://127.0.0.1:{admin_port}/v1/svid/jwt-with-user");
    let mint = |credential: String| {
        let client = client.clone();
        let mint_url = mint_url.clone();
        let issuer = idp.base_url.clone();
        async move {
            let body = serde_json::json!({"user_credential": credential, "user_issuer": issuer});
            client.post(mint_url).json(&body).send().await.unwrap()
        }
    };

    // Wait for the admin listener to come up, using a request that will be
    // refused either way.
    wait_until_ready_for_post(&client, &mint_url).await;

    let accepted = mint(id_token.clone()).await;
    assert_eq!(accepted.status(), 200, "a genuine IdP credential must be accepted");
    let body: serde_json::Value = accepted.json().await.unwrap();
    let claims = payload_claims(body["token"].as_str().unwrap());
    assert_eq!(claims["user"], PRINCIPAL_EMAIL);

    let forged = mint(tamper_email(&id_token, "ceo@corp.internal")).await;
    assert_eq!(forged.status(), 401, "a tampered credential must be refused");

    let _ = std::fs::remove_dir_all(&dir);
}

/// Waits until the gateway's admin listener accepts a connection. Any HTTP
/// response counts, even an error, because only the transport matters here.
async fn wait_until_ready_for_post(client: &Client, url: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if client.post(url).body("{}").send().await.is_ok() {
            return;
        }
        assert!(Instant::now() < deadline, "gateway admin listener never came up at {url}");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
