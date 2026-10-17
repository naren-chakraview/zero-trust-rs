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

use criterion::{criterion_group, criterion_main, Criterion};

use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};

use zero_trust::{validate, ActClaim, JwtSigner, JwtVerifier, OboClaims, Registry, SpiffeId, ValidationRequest};

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

criterion_group!(
    benches,
    bench_validate_token_signature_and_checks,
    bench_validate_three_hop_delegation_chain
);
criterion_main!(benches);
