//! Criterion benchmarks for the gateway's token-validation pipeline
//! (Task 4 / F17).
//!
//! These are informational baselines, not regression gates: there is no
//! pass/fail performance requirement here, just a measured cost for
//! `obo::validate` so the overhead of On-Behalf-Of delegation (a signed
//! `act` chain) can be compared against plain signature verification.
//!
//! Run with `cargo bench --bench gateway_benches`. HTML reports land in
//! `target/criterion/`.

use std::sync::Arc;

use criterion::{criterion_group, criterion_main, Criterion};

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::Router;
use jsonwebtoken::DecodingKey;
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;

use zero_trust::{
    exchange_token, now_unix_secs, validate, ActClaim, JwtSigner, JwtVerifier, LocalIssuer, OboClaims, Registry,
    SpiffeId, ValidationRequest, HEADER_OBO_TOKEN,
};

const INVENTORY: &str = "spiffe://chakra.internal/ns/inventory/sa/inventory-svc";
const ORDERS: &str = "spiffe://chakra.internal/ns/orders/sa/orders-svc";
const API_GATEWAY: &str = "spiffe://chakra.internal/ns/api-gateway/sa/api-gateway";
const GW1: &str = "spiffe://chakra.internal/ns/gw1/sa/gw1";
const GW2: &str = "spiffe://chakra.internal/ns/gw2/sa/gw2";

/// A test issuer: a real RS256 keypair, not a mock. Matches the keys used
/// by `src/obo.rs`'s own unit tests (`test_keys()`), kept separate here so
/// the benchmark binary doesn't depend on the library's `#[cfg(test)]` code.
fn test_issuer() -> (JwtSigner, JwtVerifier) {
    let mut rng = rand::rngs::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key = RsaPublicKey::from(&private_key);
    let private_pem = private_key.to_pkcs1_pem(LineEnding::LF).unwrap();
    let public_pem = public_key.to_pkcs1_pem(LineEnding::LF).unwrap();
    (
        JwtSigner::from_rsa_pem(private_pem.as_bytes()).unwrap(),
        JwtVerifier::from_rsa_pem(public_pem.as_bytes()).unwrap(),
    )
}

/// A real registry (via `Registry::from_yaml_str`), not a mock, with a
/// chain-depth ceiling generous enough that a three-hop delegation chain
/// still validates to `Decision::Allow`.
fn test_registry() -> Registry {
    let yaml = format!(
        r#"
trust_domain: chakra.internal
workloads:
  - name: inventory-svc
    spiffe_id: {INVENTORY}
    max_obo_chain_depth: 5
    allowed_callers:
      - {ORDERS}
      - {API_GATEWAY}
"#
    );
    Registry::from_yaml_str(&yaml).unwrap()
}

fn spiffe(s: &str) -> SpiffeId {
    s.parse().unwrap()
}

/// A plain (non-delegated) OBO token: `sub` + `aud`, no `act` chain.
fn single_hop_token(signer: &JwtSigner) -> String {
    let claims = OboClaims {
        user_iss: None,
        sub: ORDERS.to_string(),
        aud: vec![INVENTORY.to_string()],
        user: None,
        act: None,
        iat: 0,
        exp: 300,
        nbf: None,
        jti: None,
        cnf: None,
        iss: None,
    };
    signer.sign(&claims).unwrap()
}

/// A three-hop delegation chain: `sub` (the immediate caller) plus two
/// nested `act` hops, representing `api-gateway -> gw1 -> gw2 -> orders-svc`
/// acting on `inventory-svc`'s behalf. The whole chain is carried inside the
/// single signed token, so verifying it costs one signature check no matter
/// how many hops are nested — that's exactly what this benchmark is meant
/// to demonstrate against `validate_token_signature_and_checks`.
fn three_hop_delegation_token(signer: &JwtSigner) -> String {
    let claims = OboClaims {
        user_iss: None,
        sub: ORDERS.to_string(),
        aud: vec![INVENTORY.to_string()],
        user: None,
        act: Some(Box::new(ActClaim {
            sub: GW1.to_string(),
            act: Some(Box::new(ActClaim {
                sub: GW2.to_string(),
                act: Some(Box::new(ActClaim {
                    sub: API_GATEWAY.to_string(),
                    act: None,
                })),
            })),
        })),
        iat: 0,
        exp: 300,
        nbf: None,
        jti: None,
        cnf: None,
        iss: None,
    };
    signer.sign(&claims).unwrap()
}

/// Benchmark 1: `validate()` on a plain, single-hop OBO token — signature
/// verification plus every validation check `validate` performs (chain
/// depth/membership, user principal, issuer, `exp`/`nbf`, audience,
/// no-impersonation, allow-list lookup). Expected baseline: ~1-5ms.
fn bench_validate_token_signature_and_checks(c: &mut Criterion) {
    let registry = test_registry();
    let (signer, verifier) = test_issuer();
    let destination = spiffe(INVENTORY);
    let token = single_hop_token(&signer);

    let request = ValidationRequest {
        destination: &destination,
        source_principal: None,
        obo_token: Some(&token),
        caller_chain: None,
    };

    c.bench_function("validate_token_signature_and_checks", |b| {
        b.iter(|| validate(&registry, &verifier, &request, 0))
    });
}

/// Benchmark 2: `validate()` on a three-hop OBO delegation token. The
/// delegation chain is carried entirely inside the signed token (per the F1
/// fix in `src/obo.rs`), so this should cost about the same as the
/// single-hop case above — one signature verification either way, plus a
/// few extra in-memory SPIFFE-ID parses for the additional chain entries.
/// Expected baseline: ~1-5ms, comparable to the single-hop benchmark.
fn bench_validate_three_hop_delegation_chain(c: &mut Criterion) {
    let registry = test_registry();
    let (signer, verifier) = test_issuer();
    let destination = spiffe(INVENTORY);
    let token = three_hop_delegation_token(&signer);

    let request = ValidationRequest {
        destination: &destination,
        source_principal: None,
        obo_token: Some(&token),
        caller_chain: None,
    };

    c.bench_function("validate_three_hop_delegation_chain", |b| {
        b.iter(|| validate(&registry, &verifier, &request, 0))
    });
}

// ---------------------------------------------------------------------------
// Task 15 / N14: token exchange + proxy round-trip benchmarks.
//
// The two benchmarks above measure `obo::validate` in isolation -- the cost
// of checking a token that has *already arrived*. They say nothing about
// the cost of *producing* a re-minted token at each hop
// (`token_exchange::exchange_token`), or of a request's full network
// round-trip through a chain of gateways that each do so. The three
// benchmarks below close that gap:
//
//   - `exchange_token_rs256_signature`: the pure cost of one exchange (one
//     signature verification + one signature production), no network.
//   - `three_hop_proxy_round_trip_with_exchange`: an end-to-end HTTP
//     request through three real axum-based gateway processes (in-process,
//     but over real loopback TCP), each exchanging the token for the next
//     hop, terminating at a mock upstream backend.
//   - `proxy_round_trip_without_delegation`: the same shape of round trip,
//     but a single hop, no delegation chain, no exchange -- the baseline
//     "plain proxy" cost the delegated case's overhead is measured against.
// ---------------------------------------------------------------------------

/// A fresh 2048-bit RSA keypair, wrapped for this crate's JWT types: a
/// `kid`-tagged signer (for minting tokens as this identity), a throwaway
/// single-key verifier (only ever used to satisfy [`LocalIssuer::new`]'s
/// `verifier` field, which `exchange_token` itself never reads -- every
/// benchmark below passes its own *shared*, JWKS-style verifier explicitly
/// instead), and a [`DecodingKey`] for folding this identity's public key
/// into that shared verifier.
fn bench_keypair(kid: &str) -> (JwtSigner, JwtVerifier, DecodingKey) {
    let mut rng = rand::rngs::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public_key = RsaPublicKey::from(&private_key);
    let private_pem = private_key.to_pkcs1_pem(LineEnding::LF).unwrap();
    let public_pem = public_key.to_pkcs1_pem(LineEnding::LF).unwrap();

    let signer = JwtSigner::from_rsa_pem_with_kid(private_pem.as_bytes(), kid.to_string()).unwrap();
    let dummy_verifier = JwtVerifier::from_rsa_pem(public_pem.as_bytes()).unwrap();
    let decoding_key = DecodingKey::from_rsa_pem(public_pem.as_bytes()).unwrap();
    (signer, dummy_verifier, decoding_key)
}

/// A `Registry` with no registered workloads -- enough to satisfy
/// [`LocalIssuer::new`]'s constructor where the registry itself is never
/// consulted (every call site below reaches `exchange_token` directly via
/// [`IdentityProvider::sign_claims`], bypassing `issue_jwt_svid`'s
/// bootstrap-token/registry lookup entirely).
fn empty_registry() -> Registry {
    Registry::from_yaml_str("trust_domain: chakra.internal\nworkloads: []\n").unwrap()
}

/// Benchmark 3 (N14): the pure cost of [`exchange_token`] -- verifying the
/// inbound token's RS256 signature, then signing a freshly re-minted token
/// with the new hop prepended to the `act` chain. No network involved; this
/// isolates exchange cost from proxy/network overhead, which the next two
/// benchmarks add back in.
///
/// Setup mirrors the task brief: two real identities, an issuer (mints the
/// inbound token) and an exchanger (a real [`LocalIssuer`], the thing under
/// test), sharing one JWKS-style verifier the way two real gateways in the
/// same trust domain would.
fn bench_exchange_token_rs256_signature(c: &mut Criterion) {
    const NEXT_HOP_AUDIENCE: &str = "spiffe://chakra.internal/ns/bench-downstream/sa/bench-downstream";
    const EXCHANGER_ID: &str = "spiffe://chakra.internal/ns/bench-exchanger/sa/bench-exchanger";

    let (issuer_signer, _issuer_dummy_verifier, issuer_dk) = bench_keypair("bench-issuer");
    let (exchanger_signer, exchanger_dummy_verifier, exchanger_dk) = bench_keypair("bench-exchanger");

    let shared_verifier = JwtVerifier::from_jwks_entries(vec![
        ("bench-issuer".to_string(), issuer_dk),
        ("bench-exchanger".to_string(), exchanger_dk),
    ]);

    let exchanger_id: SpiffeId = EXCHANGER_ID.parse().unwrap();
    let exchanger_issuer = LocalIssuer::new(empty_registry(), exchanger_signer, exchanger_dummy_verifier, 300);

    // The inbound token the exchanger receives: signed by the issuer,
    // scoped to the exchanger as its audience.
    let inbound_claims = OboClaims {
        user_iss: None,
        sub: "spiffe://chakra.internal/ns/bench-caller/sa/bench-caller".to_string(),
        aud: vec![EXCHANGER_ID.to_string()],
        user: None,
        act: None,
        iat: 0,
        exp: 300,
        nbf: None,
        jti: None,
        cnf: None,
        iss: None,
    };
    let inbound_token = issuer_signer.sign(&inbound_claims).unwrap();

    c.bench_function("exchange_token_rs256_signature", |b| {
        b.iter(|| {
            exchange_token(
                &inbound_token,
                NEXT_HOP_AUDIENCE,
                &exchanger_id,
                5,
                &exchanger_issuer,
                &shared_verifier,
                &exchanger_id,
                300,
                0,
            )
            .unwrap()
        })
    });
}

/// Shared state for an axum handler that performs an RFC 8693 exchange and
/// forwards the re-minted token to the next hop over real loopback HTTP.
struct ExchangeHopState {
    issuer: LocalIssuer,
    verifier: Arc<JwtVerifier>,
    gateway_id: SpiffeId,
    max_chain_depth: u32,
    next_audience: String,
    next_hop_url: String,
    client: reqwest::Client,
}

/// Exchanges the inbound `X-SPIFFE-OBO-Token` for a token scoped to this
/// hop's configured next audience, then forwards the request on to the
/// next hop, relaying its response back unchanged. Mirrors (in miniature)
/// what `zt-gateway`'s own `handle_token_exchange` + `proxy_handler` do
/// together, minus routing/TLS/tracing -- the parts this benchmark isn't
/// measuring.
async fn exchange_hop_handler(State(state): State<Arc<ExchangeHopState>>, headers: HeaderMap) -> Response {
    let inbound = headers
        .get(HEADER_OBO_TOKEN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();

    let now = now_unix_secs();
    let (new_token, _ttl) = exchange_token(
        inbound,
        &state.next_audience,
        &state.gateway_id,
        state.max_chain_depth,
        &state.issuer,
        &state.verifier,
        &state.gateway_id,
        300,
        now,
    )
    .expect("exchange_token must succeed for a validly-signed inbound token in this benchmark");

    let upstream_response = state
        .client
        .get(&state.next_hop_url)
        .header(HEADER_OBO_TOKEN, new_token)
        .send()
        .await
        .expect("downstream hop must be reachable in this benchmark");

    let status = upstream_response.status();
    let body = upstream_response.bytes().await.unwrap_or_default();
    Response::builder().status(status).body(Body::from(body)).unwrap()
}

/// Shared state for an axum handler that validates the inbound token (no
/// exchange) and forwards the request on to a plain upstream -- the "last
/// hop" of a delegation chain, or a single non-delegated gateway.
struct ForwardHopState {
    registry: Registry,
    verifier: Arc<JwtVerifier>,
    destination: SpiffeId,
    backend_url: String,
    client: reqwest::Client,
}

/// Runs `obo::validate` against the inbound `X-SPIFFE-OBO-Token` and, if
/// allowed, forwards the request to `state.backend_url`, relaying its
/// response back unchanged. Denies (without ever reaching the backend) are
/// reported as `403`.
async fn forward_hop_handler(State(state): State<Arc<ForwardHopState>>, headers: HeaderMap) -> Response {
    let token = headers.get(HEADER_OBO_TOKEN).and_then(|v| v.to_str().ok());
    let now = now_unix_secs();
    let request = ValidationRequest {
        destination: &state.destination,
        source_principal: None,
        obo_token: token,
        caller_chain: None,
    };

    if !validate(&state.registry, &state.verifier, &request, now).is_allow() {
        return Response::builder().status(StatusCode::FORBIDDEN).body(Body::empty()).unwrap();
    }

    let upstream_response = state
        .client
        .get(&state.backend_url)
        .send()
        .await
        .expect("backend must be reachable in this benchmark");

    let status = upstream_response.status();
    let body = upstream_response.bytes().await.unwrap_or_default();
    Response::builder().status(status).body(Body::from(body)).unwrap()
}

/// Binds a mock upstream backend to a random loopback port and starts
/// serving it in the background. Always answers `200 ok` -- standing in
/// for whatever real application server sits behind the last gateway hop.
async fn spawn_mock_backend() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().fallback(|| async { (StatusCode::OK, "ok") });
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

/// Binds an exchange-hop gateway to a random loopback port and starts
/// serving it in the background.
async fn spawn_exchange_hop(state: Arc<ExchangeHopState>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().fallback(exchange_hop_handler).with_state(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

/// Binds a forward-hop gateway to a random loopback port and starts
/// serving it in the background.
async fn spawn_forward_hop(state: Arc<ForwardHopState>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().fallback(forward_hop_handler).with_state(state);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

/// Builds the full three-gateway chain the task brief calls for: `client ->
/// gw1 (exchange) -> gw2 (exchange) -> gw3 (forward) -> backend`. Every
/// hop is a real axum server bound to its own loopback port, wired
/// together with real `reqwest` HTTP calls -- not in-memory function
/// calls -- so the measured cost includes real (if local) network
/// round-trips, not just CPU-bound signing/verification.
///
/// All four identities (client, gw1, gw2, gw3) share one JWKS-style
/// verifier, the same trust model `LocalIssuer::with_jwks` documents for a
/// real multi-gateway deployment: each hop signs with its own key, but
/// every hop's verifier trusts every other hop's key, so a token re-minted
/// at gw1 verifies cleanly at gw2, and again at gw3.
///
/// Returns `(gw1_base_url, initial_client_token)` -- the entry point and
/// the token a benchmark iteration presents there.
async fn spawn_three_hop_chain() -> (String, String) {
    const GW1_ID: &str = "spiffe://chakra.internal/ns/bench-gw1/sa/bench-gw1";
    const GW2_ID: &str = "spiffe://chakra.internal/ns/bench-gw2/sa/bench-gw2";
    const GW3_ID: &str = "spiffe://chakra.internal/ns/bench-gw3/sa/bench-gw3";
    const CLIENT_ID: &str = "spiffe://chakra.internal/ns/bench-client/sa/bench-client";

    let (client_signer, _client_dv, client_dk) = bench_keypair("bench-client");
    let (gw1_signer, gw1_dummy_verifier, gw1_dk) = bench_keypair("bench-gw1");
    let (gw2_signer, gw2_dummy_verifier, gw2_dk) = bench_keypair("bench-gw2");
    let (_gw3_signer, _gw3_dv, gw3_dk) = bench_keypair("bench-gw3");

    let shared_verifier = Arc::new(JwtVerifier::from_jwks_entries(vec![
        ("bench-client".to_string(), client_dk),
        ("bench-gw1".to_string(), gw1_dk),
        ("bench-gw2".to_string(), gw2_dk),
        ("bench-gw3".to_string(), gw3_dk),
    ]));

    let gw1_id: SpiffeId = GW1_ID.parse().unwrap();
    let gw2_id: SpiffeId = GW2_ID.parse().unwrap();
    let gw3_id: SpiffeId = GW3_ID.parse().unwrap();

    let gw1_issuer = LocalIssuer::new(empty_registry(), gw1_signer, gw1_dummy_verifier, 300);
    let gw2_issuer = LocalIssuer::new(empty_registry(), gw2_signer, gw2_dummy_verifier, 300);

    let backend_url = spawn_mock_backend().await;

    // gw3: last hop, validates (current actor must be gw2) and forwards --
    // no exchange.
    let gw3_registry = Registry::from_yaml_str(&format!(
        r#"
trust_domain: chakra.internal
workloads:
  - name: bench-gw3
    spiffe_id: {GW3_ID}
    max_obo_chain_depth: 5
    allowed_callers:
      - {GW2_ID}
"#
    ))
    .unwrap();
    let gw3_state = Arc::new(ForwardHopState {
        registry: gw3_registry,
        verifier: Arc::clone(&shared_verifier),
        destination: gw3_id,
        backend_url,
        client: reqwest::Client::new(),
    });
    let gw3_url = spawn_forward_hop(gw3_state).await;

    // gw2: exchanges the token (scoping it to gw3) and forwards to gw3.
    let gw2_state = Arc::new(ExchangeHopState {
        issuer: gw2_issuer,
        verifier: Arc::clone(&shared_verifier),
        gateway_id: gw2_id,
        max_chain_depth: 5,
        next_audience: GW3_ID.to_string(),
        next_hop_url: gw3_url,
        client: reqwest::Client::new(),
    });
    let gw2_url = spawn_exchange_hop(gw2_state).await;

    // gw1: exchanges the token (scoping it to gw2) and forwards to gw2.
    let gw1_state = Arc::new(ExchangeHopState {
        issuer: gw1_issuer,
        verifier: Arc::clone(&shared_verifier),
        gateway_id: gw1_id,
        max_chain_depth: 5,
        next_audience: GW2_ID.to_string(),
        next_hop_url: gw2_url,
        client: reqwest::Client::new(),
    });
    let gw1_url = spawn_exchange_hop(gw1_state).await;

    // The initial client token: sub=client, aud=gw1, no `act` chain yet --
    // this is the token gw1 exchanges on the first hop.
    let now = now_unix_secs();
    let client_claims = OboClaims {
        user_iss: None,
        sub: CLIENT_ID.to_string(),
        aud: vec![GW1_ID.to_string()],
        user: None,
        act: None,
        iat: now,
        exp: now + 3600,
        nbf: Some(now),
        jti: None,
        cnf: None,
        iss: None,
    };
    let client_token = client_signer.sign(&client_claims).unwrap();

    (gw1_url, client_token)
}

/// Builds a single, non-delegated gateway (`client -> gw -> backend`): the
/// baseline this task's acceptance criteria call for, to compare the
/// three-hop delegated cost against. Same real-axum-server, real-HTTP
/// shape as [`spawn_three_hop_chain`] -- one hop, one `validate` call, no
/// exchange -- so the two benchmarks differ only in the delegation work
/// actually being measured, not in network/harness overhead.
///
/// Returns `(gw_base_url, client_token)`.
async fn spawn_baseline_gateway() -> (String, String) {
    const CLIENT_ID: &str = "spiffe://chakra.internal/ns/bench-baseline-client/sa/bench-baseline-client";
    const GW_ID: &str = "spiffe://chakra.internal/ns/bench-baseline-gw/sa/bench-baseline-gw";

    let (client_signer, _client_dv, client_dk) = bench_keypair("bench-baseline-client");
    let verifier = Arc::new(JwtVerifier::from_jwks_entries(vec![(
        "bench-baseline-client".to_string(),
        client_dk,
    )]));

    let backend_url = spawn_mock_backend().await;

    let gw_id: SpiffeId = GW_ID.parse().unwrap();
    let registry = Registry::from_yaml_str(&format!(
        r#"
trust_domain: chakra.internal
workloads:
  - name: bench-baseline-gw
    spiffe_id: {GW_ID}
    max_obo_chain_depth: 1
    allowed_callers:
      - {CLIENT_ID}
"#
    ))
    .unwrap();

    let state = Arc::new(ForwardHopState {
        registry,
        verifier,
        destination: gw_id,
        backend_url,
        client: reqwest::Client::new(),
    });
    let gw_url = spawn_forward_hop(state).await;

    let now = now_unix_secs();
    let claims = OboClaims {
        user_iss: None,
        sub: CLIENT_ID.to_string(),
        aud: vec![GW_ID.to_string()],
        user: None,
        act: None,
        iat: now,
        exp: now + 3600,
        nbf: Some(now),
        jti: None,
        cnf: None,
        iss: None,
    };
    let token = client_signer.sign(&claims).unwrap();

    (gw_url, token)
}

/// Benchmark 4 (N14): end-to-end request latency through the three-hop
/// chain (`client -> gw1 (exchange) -> gw2 (exchange) -> gw3 (forward) ->
/// backend`). The chain is built once, outside the measured loop; each
/// iteration is one real HTTP request from a fresh client call all the
/// way through to the backend and back, exercising two real
/// `exchange_token` calls, one `validate` call, and four real (loopback)
/// network hops.
fn bench_three_hop_proxy_round_trip_with_exchange(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let (gw1_url, client_token) = rt.block_on(spawn_three_hop_chain());
    let client = reqwest::Client::new();

    c.bench_function("three_hop_proxy_round_trip_with_exchange", |b| {
        b.iter(|| {
            rt.block_on(async {
                let response = client
                    .get(&gw1_url)
                    .header(HEADER_OBO_TOKEN, &client_token)
                    .send()
                    .await
                    .expect("request through the three-hop chain must succeed");
                assert_eq!(response.status(), StatusCode::OK);
            })
        })
    });
}

/// Benchmark 5 (N14): the baseline this task's acceptance criteria call
/// for -- a single, non-delegated gateway hop (`client -> gw -> backend`),
/// for comparison against benchmark 4's three-hop, double-exchange cost.
/// Same real-HTTP, real-axum-server shape; the only thing missing is the
/// exchange/delegation work.
fn bench_proxy_round_trip_without_delegation(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let (gw_url, client_token) = rt.block_on(spawn_baseline_gateway());
    let client = reqwest::Client::new();

    c.bench_function("proxy_round_trip_without_delegation", |b| {
        b.iter(|| {
            rt.block_on(async {
                let response = client
                    .get(&gw_url)
                    .header(HEADER_OBO_TOKEN, &client_token)
                    .send()
                    .await
                    .expect("request through the baseline gateway must succeed");
                assert_eq!(response.status(), StatusCode::OK);
            })
        })
    });
}

criterion_group!(
    benches,
    bench_validate_token_signature_and_checks,
    bench_validate_three_hop_delegation_chain,
    bench_exchange_token_rs256_signature,
    bench_three_hop_proxy_round_trip_with_exchange,
    bench_proxy_round_trip_without_delegation
);
criterion_main!(benches);
