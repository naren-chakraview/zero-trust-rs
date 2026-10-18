//! Task 2 (F15): `iss` (issuer) claim validation.
//!
//! `obo::validate` now checks a token's signed `iss` claim, if present: it
//! must be a well-formed SPIFFE ID (start with `spiffe://`), or the token is
//! denied with `DenyReason::IssuerInvalid`. A *missing* `iss` is explicitly
//! not a deny — old tokens minted before this claim existed must keep
//! working unchanged. These integration tests exercise that behavior
//! through the crate's public API, the same way `tests/gap_probes.rs` does
//! for the F1/F2 fixes.

use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};
use zero_trust::*;

const INVENTORY: &str = "spiffe://chakra.internal/ns/inventory/sa/inventory-svc";
const ORDERS: &str = "spiffe://chakra.internal/ns/orders/sa/orders-svc";

fn registry() -> Registry {
    Registry::from_yaml_str(&format!(
        r#"
trust_domain: chakra.internal
workloads:
  - name: inventory-svc
    spiffe_id: {INVENTORY}
    max_obo_chain_depth: 3
    allowed_callers:
      - {ORDERS}
"#
    ))
    .unwrap()
}

/// TEST-ONLY RSA keypair, returned as (signer, verifier).
fn test_keys() -> (JwtSigner, JwtVerifier) {
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

fn claims_with_iss(iss: Option<String>) -> OboClaims {
    OboClaims {
        sub: ORDERS.to_string(),
        aud: vec![INVENTORY.to_string()],
        user: None,
        act: None,
        iat: 0,
        exp: 300,
        nbf: None,
        jti: None,
        cnf: None,
        iss,
    }
}

/// 1. Token with a valid `iss` (`spiffe://...`) is accepted.
#[test]
fn token_with_valid_spiffe_iss_is_accepted() {
    let reg = registry();
    let (signer, verifier) = test_keys();
    let destination: SpiffeId = INVENTORY.parse().unwrap();

    let claims = claims_with_iss(Some("spiffe://chakra.internal".to_string()));
    let token = signer.sign(&claims).unwrap();

    let request = ValidationRequest {
        destination: &destination,
        source_principal: None,
        obo_token: Some(&token),
        caller_chain: None,
    };

    assert_eq!(validate(&reg, &verifier, &request, 0), Decision::Allow);
}

/// 2. Token with an invalid `iss` format (not `spiffe://...`) is rejected
///    with `DenyReason::IssuerInvalid`.
#[test]
fn token_with_malformed_iss_is_rejected_with_issuer_invalid() {
    let reg = registry();
    let (signer, verifier) = test_keys();
    let destination: SpiffeId = INVENTORY.parse().unwrap();

    let claims = claims_with_iss(Some("https://not-a-spiffe-issuer.example".to_string()));
    let token = signer.sign(&claims).unwrap();

    let request = ValidationRequest {
        destination: &destination,
        source_principal: None,
        obo_token: Some(&token),
        caller_chain: None,
    };

    assert_eq!(
        validate(&reg, &verifier, &request, 0),
        Decision::Deny(DenyReason::IssuerInvalid)
    );
}

/// 2b. Same, but with an empty-string `iss` — also malformed.
#[test]
fn token_with_empty_iss_is_rejected_with_issuer_invalid() {
    let reg = registry();
    let (signer, verifier) = test_keys();
    let destination: SpiffeId = INVENTORY.parse().unwrap();

    let claims = claims_with_iss(Some(String::new()));
    let token = signer.sign(&claims).unwrap();

    let request = ValidationRequest {
        destination: &destination,
        source_principal: None,
        obo_token: Some(&token),
        caller_chain: None,
    };

    assert_eq!(
        validate(&reg, &verifier, &request, 0),
        Decision::Deny(DenyReason::IssuerInvalid)
    );
}

/// 3. Old tokens without an `iss` claim at all still work (backward
///    compat) — a missing `iss` is not treated as invalid.
#[test]
fn token_without_iss_claim_still_works() {
    let reg = registry();
    let (signer, verifier) = test_keys();
    let destination: SpiffeId = INVENTORY.parse().unwrap();

    let claims = claims_with_iss(None);
    let token = signer.sign(&claims).unwrap();

    let request = ValidationRequest {
        destination: &destination,
        source_principal: None,
        obo_token: Some(&token),
        caller_chain: None,
    };

    assert_eq!(validate(&reg, &verifier, &request, 0), Decision::Allow);
}

/// Same backward-compat case, but at the raw-JSON level: a token shaped
/// exactly like one minted before the `iss` claim existed (no `iss` key in
/// the JSON at all, not even `null`) must still deserialize and validate.
#[test]
fn pre_task_2_token_json_shape_still_deserializes_and_validates() {
    let reg = registry();
    let (signer, verifier) = test_keys();
    let destination: SpiffeId = INVENTORY.parse().unwrap();

    // Exactly the JSON shape issued before this task: no `iss` field.
    let old_json = format!(r#"{{"sub":"{ORDERS}","aud":["{INVENTORY}"],"exp":300,"iat":0}}"#);
    let claims: OboClaims = serde_json::from_str(&old_json).unwrap();
    assert_eq!(claims.iss, None);

    let token = signer.sign(&claims).unwrap();
    let request = ValidationRequest {
        destination: &destination,
        source_principal: None,
        obo_token: Some(&token),
        caller_chain: None,
    };

    assert_eq!(validate(&reg, &verifier, &request, 0), Decision::Allow);
}

/// `IssuerInvalid`'s deny reason string is populated (never the sentinel
/// "none" that `Decision::Allow` reports).
#[test]
fn issuer_invalid_deny_reason_has_a_populated_string() {
    assert_eq!(DenyReason::IssuerInvalid.as_str(), "issuer_invalid");
    assert_ne!(Decision::Deny(DenyReason::IssuerInvalid).deny_reason_str(), "none");
}

/// `IssuerNotTrusted` (reserved for a future trusted-issuer registry) also
/// has a populated string, even though nothing produces it yet.
#[test]
fn issuer_not_trusted_deny_reason_has_a_populated_string() {
    assert_eq!(DenyReason::IssuerNotTrusted.as_str(), "issuer_not_trusted");
    assert_ne!(Decision::Deny(DenyReason::IssuerNotTrusted).deny_reason_str(), "none");
}

/// `LocalIssuer::issue_jwt_svid` (the normal issuance path, Task 2's
/// `src/identity.rs` change) now stamps every token it mints with a
/// `spiffe://`-shaped `iss` claim, so tokens it issues pass the new check
/// above without any extra wiring.
#[test]
fn issued_tokens_carry_a_valid_spiffe_iss_claim() {
    let reg = Registry::from_yaml_str(&format!(
        r#"
trust_domain: chakra.internal
workloads:
  - name: orders-svc
    spiffe_id: {ORDERS}
    max_obo_chain_depth: 3
    allowed_callers: []
    bootstrap_token: orders-secret
"#
    ))
    .unwrap();
    let issuer = LocalIssuer::generate(reg, 300).unwrap();

    let issued = issuer.issue_jwt_svid("orders-svc", INVENTORY, "orders-secret").unwrap();
    let claims = issuer.verifier().verify_signature(&issued.token).unwrap();

    let iss = claims.iss.expect("issued token must carry an iss claim");
    assert!(iss.starts_with("spiffe://"));
}

// --- Task 3: `nbf` (not-before) and `jti` (JWT ID) validation ---
//
// `obo::validate`'s `nbf` check already existed (see `src/obo.rs`'s
// `obo_token_not_yet_valid_is_denied` / `obo_token_nbf_within_clock_skew_is_allowed`
// unit tests), but the clock-skew tolerance it used was a fixed constant.
// Task 3 makes that tolerance configurable (`GatewayConfig::clock_skew_tolerance_secs`,
// plumbed through `validate_with_clock_skew`) and has `LocalIssuer` stamp
// every issued token with `nbf`/`jti`. These integration tests exercise both
// through the crate's public API.

/// 1. A token whose `nbf` is in the future, beyond the configured clock-skew
///    tolerance, is rejected with `DenyReason::OboTokenNotYetValid` — even
///    with a custom (non-default) skew value, proving the configured
///    tolerance, not just the fixed default, is what's enforced.
#[test]
fn token_with_nbf_beyond_configured_clock_skew_is_rejected() {
    let reg = registry();
    let (signer, verifier) = test_keys();
    let destination: SpiffeId = INVENTORY.parse().unwrap();

    let mut claims = claims_with_iss(None);
    claims.nbf = Some(100); // valid starting at t=100
    claims.exp = 1_000;
    let token = signer.sign(&claims).unwrap();

    let request = ValidationRequest {
        destination: &destination,
        source_principal: None,
        obo_token: Some(&token),
        caller_chain: None,
    };

    // now=0, skew=10s: nbf (100) is far beyond now+skew (10) -> denied.
    assert_eq!(
        validate_with_clock_skew(&reg, &verifier, &request, 0, 10),
        Decision::Deny(DenyReason::OboTokenNotYetValid)
    );
}

/// 2. A token whose `nbf` is in the future, but within the configured
///    clock-skew tolerance, is accepted — including a tolerance wider than
///    the library's own default, proving the configured value (not the
///    default) is what's actually applied.
#[test]
fn token_with_nbf_within_configured_clock_skew_is_accepted() {
    let reg = registry();
    let (signer, verifier) = test_keys();
    let destination: SpiffeId = INVENTORY.parse().unwrap();

    let mut claims = claims_with_iss(None);
    claims.nbf = Some(100); // valid starting at t=100
    claims.exp = 1_000;
    let token = signer.sign(&claims).unwrap();

    let request = ValidationRequest {
        destination: &destination,
        source_principal: None,
        obo_token: Some(&token),
        caller_chain: None,
    };

    // now=0, skew=120s (wider than DEFAULT_CLOCK_SKEW_SECS): nbf (100) is
    // within now+skew (120) -> allowed.
    assert_eq!(
        validate_with_clock_skew(&reg, &verifier, &request, 0, 120),
        Decision::Allow
    );

    // The same request, at the plain (default-skew) `validate` entry point,
    // is denied -- nbf=100 exceeds `now + DEFAULT_CLOCK_SKEW_SECS` (0 + 60).
    // This pins down that the 120s tolerance used above is doing real work,
    // not just happening to agree with the default.
    assert_eq!(
        validate(&reg, &verifier, &request, 0),
        Decision::Deny(DenyReason::OboTokenNotYetValid)
    );
}

/// 3. `LocalIssuer::issue_jwt_svid` stamps every issued token with a
///    present `jti` claim (a non-empty string) — required for downstream
///    replay-cache tracking, even though `obo::validate` itself never
///    denies on a missing `jti` (old tokens must keep working).
#[test]
fn issued_tokens_carry_a_present_jti_claim() {
    let reg = Registry::from_yaml_str(&format!(
        r#"
trust_domain: chakra.internal
workloads:
  - name: orders-svc
    spiffe_id: {ORDERS}
    max_obo_chain_depth: 3
    allowed_callers: []
    bootstrap_token: orders-secret
"#
    ))
    .unwrap();
    let issuer = LocalIssuer::generate(reg, 300).unwrap();

    let issued = issuer.issue_jwt_svid("orders-svc", INVENTORY, "orders-secret").unwrap();
    let claims = issuer.verifier().verify_signature(&issued.token).unwrap();

    let jti = claims.jti.expect("issued token must carry a jti claim");
    assert!(!jti.is_empty());
}

/// 3b. Two separately issued tokens get distinct `jti` values -- a
///     constant/empty placeholder would defeat the whole point of a
///     replay-cache key.
#[test]
fn issued_tokens_have_distinct_jti_values() {
    let reg = Registry::from_yaml_str(&format!(
        r#"
trust_domain: chakra.internal
workloads:
  - name: orders-svc
    spiffe_id: {ORDERS}
    max_obo_chain_depth: 3
    allowed_callers: []
    bootstrap_token: orders-secret
"#
    ))
    .unwrap();
    let issuer = LocalIssuer::generate(reg, 300).unwrap();

    let issued_1 = issuer.issue_jwt_svid("orders-svc", INVENTORY, "orders-secret").unwrap();
    let issued_2 = issuer.issue_jwt_svid("orders-svc", INVENTORY, "orders-secret").unwrap();

    let jti_1 = issuer.verifier().verify_signature(&issued_1.token).unwrap().jti;
    let jti_2 = issuer.verifier().verify_signature(&issued_2.token).unwrap().jti;

    assert_ne!(jti_1, jti_2);
}

/// 4. `LocalIssuer::issue_jwt_svid` also stamps every issued token with
///    `nbf` set to the issuance time (`iat`), so a freshly issued token is
///    immediately valid under `obo::validate` at that same instant.
#[test]
fn issued_tokens_carry_an_nbf_equal_to_iat() {
    let reg = Registry::from_yaml_str(&format!(
        r#"
trust_domain: chakra.internal
workloads:
  - name: orders-svc
    spiffe_id: {ORDERS}
    max_obo_chain_depth: 3
    allowed_callers: []
    bootstrap_token: orders-secret
"#
    ))
    .unwrap();
    let issuer = LocalIssuer::generate(reg, 300).unwrap();

    let issued = issuer.issue_jwt_svid("orders-svc", INVENTORY, "orders-secret").unwrap();
    let claims = issuer.verifier().verify_signature(&issued.token).unwrap();

    assert_eq!(claims.nbf, Some(claims.iat));
}

// --- Task 1 (N4): RFC 8693 `act` nesting direction -------------------------
//
// RFC 8693 §4.1 defines the outermost `act` as the party *currently*
// exercising delegated authority, not the party that started the chain.
// Each `exchange_token` call must therefore *prepend* the exchanging hop as
// the new outermost `act`, nesting whatever was already there one level
// deeper as the prior actor — not bury the new hop at the bottom of the
// chain.

const GATEWAY: &str = "spiffe://chakra.internal/ns/api-gateway/sa/api-gateway";
const HOP_ORDERS: &str = "spiffe://chakra.internal/ns/orders-hop/sa/orders-hop";
const HOP_INVENTORY: &str = "spiffe://chakra.internal/ns/inventory-hop/sa/inventory-hop";

fn placeholder_registry() -> Registry {
    Registry::from_yaml_str(
        r#"
trust_domain: chakra.internal
workloads:
  - name: placeholder
    spiffe_id: spiffe://chakra.internal/ns/placeholder/sa/placeholder
    max_obo_chain_depth: 5
    allowed_callers: []
"#,
    )
    .unwrap()
}

/// Three successive exchanges (api-gateway, then an "orders" hop, then an
/// "inventory" hop) must leave the *most recently* exchanging hop
/// (inventory) as the outermost `act.sub` — the current actor, per RFC
/// 8693 §4.1 — with every older hop nested progressively deeper and
/// `sub` (the originator) never moving. Before the N4 fix, `append_hop`
/// buried each new hop at the bottom of the chain instead, so the
/// outermost `act.sub` after three hops was api-gateway (the *oldest*
/// hop) rather than inventory (the current one) — exactly the inversion
/// this test guards against.
#[test]
fn three_hop_chain_has_the_latest_hop_as_the_outermost_act() {
    let issuer = LocalIssuer::generate(placeholder_registry(), 300).unwrap();
    let now = 1_000i64;

    let originator_claims = OboClaims {
        sub: "spiffe://chakra.internal/ns/originator/sa/originator".to_string(),
        aud: vec![GATEWAY.to_string()],
        user: Some("spiffe://chakra.internal/ns/alice/sa/alice".to_string()),
        act: None,
        iat: now,
        exp: now + 300,
        nbf: None,
        jti: None,
        cnf: None,
        iss: None,
    };
    let token_0 = issuer.sign_claims(&originator_claims).unwrap();

    // Hop 1: api-gateway exchanges toward the orders hop.
    let (token_1, _) = exchange_token(
        &token_0,
        HOP_ORDERS,
        &GATEWAY.parse::<SpiffeId>().unwrap(),
        5,
        &issuer,
        issuer.verifier(),
        &GATEWAY.parse::<SpiffeId>().unwrap(),
        300,
        now,
    )
    .unwrap();

    // Hop 2: the orders hop exchanges toward the inventory hop.
    let (token_2, _) = exchange_token(
        &token_1,
        HOP_INVENTORY,
        &HOP_ORDERS.parse::<SpiffeId>().unwrap(),
        5,
        &issuer,
        issuer.verifier(),
        &HOP_ORDERS.parse::<SpiffeId>().unwrap(),
        300,
        now,
    )
    .unwrap();

    // Hop 3: the inventory hop exchanges toward a final backend — this is
    // the most recent hop, so it must land as the *outermost* `act` on the
    // resulting token.
    let (token_3, _) = exchange_token(
        &token_2,
        "spiffe://chakra.internal/ns/backend/sa/backend",
        &HOP_INVENTORY.parse::<SpiffeId>().unwrap(),
        5,
        &issuer,
        issuer.verifier(),
        &HOP_INVENTORY.parse::<SpiffeId>().unwrap(),
        300,
        now,
    )
    .unwrap();

    let final_claims = issuer.verifier().verify_signature(&token_3).unwrap();

    // The outermost `act.sub` is the LATEST hop (inventory), not the
    // oldest hop (api-gateway) — RFC 8693 §4.1's "current actor" position.
    let outermost = final_claims.act.as_deref().expect("act claim must be present");
    assert_eq!(outermost.sub, HOP_INVENTORY);
    assert_ne!(outermost.sub, GATEWAY);

    // Nested one level deeper is the prior (orders) hop...
    let middle = outermost.act.as_deref().expect("nested act must be present");
    assert_eq!(middle.sub, HOP_ORDERS);

    // ...and nested deepest is the oldest hop (api-gateway).
    let innermost = middle.act.as_deref().expect("innermost act must be present");
    assert_eq!(innermost.sub, GATEWAY);
    assert!(innermost.act.is_none());

    // `sub` (the end-to-end originator) never moves across any exchange.
    assert_eq!(final_claims.sub, "spiffe://chakra.internal/ns/originator/sa/originator");

    // `delegation_chain()`'s public API still reports chronological order
    // regardless of the underlying (newest-first) `act` nesting direction.
    assert_eq!(
        final_claims.delegation_chain(),
        vec![
            "spiffe://chakra.internal/ns/originator/sa/originator".to_string(),
            GATEWAY.to_string(),
            HOP_ORDERS.to_string(),
            HOP_INVENTORY.to_string(),
        ]
    );
}

// --- Task 2 (N1): authorize the current actor, not the originator ----------
//
// Review 0002 finding N1: `obo::validate` used to check the delegation
// chain's *originator* (`sub`) against a destination's allow-list and
// against the transport-verified mTLS peer. That's wrong once a token has
// been exchanged more than once — `sub` never moves, so the originator
// (e.g. api-gateway) would stay allow-listed at every hop even though the
// workload actually presenting the token (e.g. orders) is a different
// identity entirely. These tests build the same two-hop chain the N4 test
// above exercises (api-gateway -> orders), then prove `validate` now
// authorizes `orders` (the current actor, i.e. the outermost `act.sub`) —
// not `api-gateway` (`sub`, the originator) — both via the allow-list and
// via the mTLS peer check.

const N1_ORDERS: &str = "spiffe://chakra.internal/ns/orders/sa/orders-svc";
const N1_API_GATEWAY: &str = "spiffe://chakra.internal/ns/api-gateway/sa/api-gateway";
const N1_INVENTORY: &str = "spiffe://chakra.internal/ns/inventory/sa/inventory-svc";

/// Builds a registry for `inventory-svc` with exactly one SPIFFE ID in its
/// `allowed_callers`, so each test can independently check "orders allowed,
/// api-gateway allowed" by constructing a fresh registry per case.
fn n1_registry_allowing(allowed: &str) -> Registry {
    Registry::from_yaml_str(&format!(
        r#"
trust_domain: chakra.internal
workloads:
  - name: inventory-svc
    spiffe_id: {N1_INVENTORY}
    max_obo_chain_depth: 5
    allowed_callers:
      - {allowed}
"#
    ))
    .unwrap()
}

/// Mints a token with `sub = api-gateway` (the originator) and a single
/// `act` hop recording `orders` as the current actor — i.e. the token
/// api-gateway produced, then exchanged to orders, exactly as
/// `exchange_token` would leave it: `sub` stays at the originator, and
/// `act.sub` is the current (most recent) actor.
fn n1_two_hop_token(signer: &JwtSigner) -> String {
    let claims = OboClaims {
        sub: N1_API_GATEWAY.to_string(),
        aud: vec![N1_INVENTORY.to_string()],
        user: None,
        act: Some(Box::new(ActClaim {
            sub: N1_ORDERS.to_string(),
            act: None,
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

/// 1. Allow-list check: a two-hop chain (api-gateway -> orders) must be
///    authorized against `orders` (the current actor), not `api-gateway`
///    (the originator).
#[test]
fn two_hop_chain_allow_list_checks_current_actor() {
    let (signer, verifier) = test_keys();
    let destination: SpiffeId = N1_INVENTORY.parse().unwrap();
    let token = n1_two_hop_token(&signer);

    // Allow-listing the current actor (orders) -- PASS.
    let registry_orders = n1_registry_allowing(N1_ORDERS);
    let request = ValidationRequest {
        destination: &destination,
        source_principal: None,
        obo_token: Some(&token),
        caller_chain: None,
    };
    assert_eq!(
        validate(&registry_orders, &verifier, &request, 0),
        Decision::Allow,
        "current actor (orders) must be allow-listed, not the originator"
    );

    // Allow-listing only the originator (api-gateway), not the current
    // actor -- FAIL. Under the pre-N1 behavior this would have been
    // Decision::Allow (checking `sub`); after the fix it must deny.
    let registry_gateway = n1_registry_allowing(N1_API_GATEWAY);
    assert_eq!(
        validate(&registry_gateway, &verifier, &request, 0),
        Decision::Deny(DenyReason::CallerNotInAllowList),
        "originator (api-gateway) alone in the allow-list must no longer be sufficient"
    );
}

/// 2. mTLS peer check: the transport-verified peer must match the current
///    actor (orders), not the token's `sub` (api-gateway).
#[test]
fn mtls_cert_checked_against_current_actor() {
    let (signer, verifier) = test_keys();
    let destination: SpiffeId = N1_INVENTORY.parse().unwrap();
    let token = n1_two_hop_token(&signer);
    // Allow-list both, so the only thing distinguishing the two assertions
    // below is the no-impersonation (mTLS peer) check, not the allow-list.
    let registry = Registry::from_yaml_str(&format!(
        r#"
trust_domain: chakra.internal
workloads:
  - name: inventory-svc
    spiffe_id: {N1_INVENTORY}
    max_obo_chain_depth: 5
    allowed_callers:
      - {N1_ORDERS}
      - {N1_API_GATEWAY}
"#
    ))
    .unwrap();

    // Presented mTLS cert matches the current actor (orders) -- PASS.
    let orders_peer: SpiffeId = N1_ORDERS.parse().unwrap();
    let request_orders = ValidationRequest {
        destination: &destination,
        source_principal: Some(&orders_peer),
        obo_token: Some(&token),
        caller_chain: None,
    };
    assert_eq!(
        validate(&registry, &verifier, &request_orders, 0),
        Decision::Allow,
        "mTLS peer matching the current actor (orders) must be allowed"
    );

    // Presented mTLS cert matches `sub` (api-gateway, the originator), not
    // the current actor -- FAIL.
    let gateway_peer: SpiffeId = N1_API_GATEWAY.parse().unwrap();
    let request_gateway = ValidationRequest {
        destination: &destination,
        source_principal: Some(&gateway_peer),
        obo_token: Some(&token),
        caller_chain: None,
    };
    assert_eq!(
        validate(&registry, &verifier, &request_gateway, 0),
        Decision::Deny(DenyReason::OboTokenSubjectMismatch),
        "mTLS peer matching only the originator (sub), not the current actor, must be denied"
    );
}

/// 3. `current_actor` itself: single-hop (no delegation) returns `sub`
///    unchanged -- behavior for non-delegated tokens is untouched by N1.
#[test]
fn current_actor_defaults_to_sub_with_no_delegation() {
    let claims = OboClaims {
        sub: N1_ORDERS.to_string(),
        aud: vec![N1_INVENTORY.to_string()],
        user: None,
        act: None,
        iat: 0,
        exp: 300,
        nbf: None,
        jti: None,
        cnf: None,
        iss: None,
    };
    assert_eq!(current_actor(&claims).to_string(), N1_ORDERS);
}

/// 4. `current_actor` on a two-hop chain returns the outermost `act.sub`
///    (orders), never `sub` (api-gateway).
#[test]
fn current_actor_returns_outermost_act_sub_when_present() {
    let (signer, verifier) = test_keys();
    let token = n1_two_hop_token(&signer);
    let claims = verifier.verify_signature(&token).unwrap();

    assert_eq!(current_actor(&claims).to_string(), N1_ORDERS);
    assert_ne!(current_actor(&claims).to_string(), N1_API_GATEWAY);
    // `sub` itself is unchanged -- still the originator.
    assert_eq!(claims.sub, N1_API_GATEWAY);
}

// --- Task 13 (N12): issuer trust and JTI replay validation -----------------
//
// Review 0002 finding N12: tokens must be validated against a trusted
// issuer list, and an optional JTI (JWT ID) replay cache prevents a
// captured token from being reused indefinitely. Both checks are opt-in,
// reached through `validate_with_issuer_and_replay_policy` rather than
// `validate` itself, so every pre-existing `validate`/`validate_with_clock_skew`
// call site (and every test above) keeps behaving exactly as before.

const TRUSTED_ISSUER: &str = "spiffe://chakra.internal";
const UNTRUSTED_ISSUER: &str = "spiffe://attacker.example";

fn n12_claims(iss: Option<&str>, jti: Option<&str>) -> OboClaims {
    OboClaims {
        sub: ORDERS.to_string(),
        aud: vec![INVENTORY.to_string()],
        user: None,
        act: None,
        iat: 0,
        exp: 300,
        nbf: None,
        jti: jti.map(str::to_string),
        cnf: None,
        iss: iss.map(str::to_string),
    }
}

/// 1. A token whose `iss` is on the configured trusted-issuer list is
///    accepted.
#[test]
fn issuer_validation_trusted() {
    let reg = registry();
    let (signer, verifier) = test_keys();
    let destination: SpiffeId = INVENTORY.parse().unwrap();

    let token = signer.sign(&n12_claims(Some(TRUSTED_ISSUER), None)).unwrap();
    let request = ValidationRequest {
        destination: &destination,
        source_principal: None,
        obo_token: Some(&token),
        caller_chain: None,
    };

    let trusted_issuers = vec![TRUSTED_ISSUER.to_string()];
    assert_eq!(
        validate_with_issuer_and_replay_policy(&reg, &verifier, &request, 0, 60, &trusted_issuers, false, 3600),
        Decision::Allow
    );
}

/// 2. A token whose `iss` is *not* on the configured trusted-issuer list is
///    rejected with `DenyReason::IssuerNotTrusted` — a compromised (or
///    simply unrecognized) issuer's tokens are never accepted once a
///    trusted-issuer list is configured.
#[test]
fn issuer_validation_untrusted() {
    let reg = registry();
    let (signer, verifier) = test_keys();
    let destination: SpiffeId = INVENTORY.parse().unwrap();

    let token = signer.sign(&n12_claims(Some(UNTRUSTED_ISSUER), None)).unwrap();
    let request = ValidationRequest {
        destination: &destination,
        source_principal: None,
        obo_token: Some(&token),
        caller_chain: None,
    };

    let trusted_issuers = vec![TRUSTED_ISSUER.to_string()];
    assert_eq!(
        validate_with_issuer_and_replay_policy(&reg, &verifier, &request, 0, 60, &trusted_issuers, false, 3600),
        Decision::Deny(DenyReason::IssuerNotTrusted)
    );
}

/// 3. Two tokens minted with the same `jti` -- the second presentation is
///    rejected as a replay once JTI caching is enabled: the first request
///    is allowed and records the `jti`, the second (even though it is
///    otherwise a perfectly valid, independently-signed token) is denied
///    with `DenyReason::TokenReplayed`.
#[test]
fn jti_replay_detection() {
    let reg = registry();
    let (signer, verifier) = test_keys();
    let destination: SpiffeId = INVENTORY.parse().unwrap();

    let shared_jti = "jti-replay-test-1";
    let token_first = signer.sign(&n12_claims(Some(TRUSTED_ISSUER), Some(shared_jti))).unwrap();
    let token_second = signer.sign(&n12_claims(Some(TRUSTED_ISSUER), Some(shared_jti))).unwrap();

    let trusted_issuers = vec![TRUSTED_ISSUER.to_string()];

    let request_first = ValidationRequest {
        destination: &destination,
        source_principal: None,
        obo_token: Some(&token_first),
        caller_chain: None,
    };
    assert_eq!(
        validate_with_issuer_and_replay_policy(&reg, &verifier, &request_first, 0, 60, &trusted_issuers, true, 3600),
        Decision::Allow,
        "first presentation of a fresh jti must be allowed"
    );

    let request_second = ValidationRequest {
        destination: &destination,
        source_principal: None,
        obo_token: Some(&token_second),
        caller_chain: None,
    };
    assert_eq!(
        validate_with_issuer_and_replay_policy(&reg, &verifier, &request_second, 0, 60, &trusted_issuers, true, 3600),
        Decision::Deny(DenyReason::TokenReplayed),
        "replaying the same jti must be denied"
    );
}

/// 4. A replayed `jti` is accepted again once its cache entry's TTL has
///    elapsed -- the cache expires rather than remembering every jti
///    forever.
#[test]
fn jti_cache_respects_ttl() {
    let reg = registry();
    let (signer, verifier) = test_keys();
    let destination: SpiffeId = INVENTORY.parse().unwrap();

    let shared_jti = "jti-ttl-test-1";
    let token = signer.sign(&n12_claims(Some(TRUSTED_ISSUER), Some(shared_jti))).unwrap();
    let trusted_issuers = vec![TRUSTED_ISSUER.to_string()];

    let request = ValidationRequest {
        destination: &destination,
        source_principal: None,
        obo_token: Some(&token),
        caller_chain: None,
    };

    // A TTL of effectively zero (one nanosecond): the first call records
    // the jti, and by the time the second call's lazy-eviction sweep runs
    // (after a short real sleep), that record has already expired.
    assert_eq!(
        validate_with_issuer_and_replay_policy(&reg, &verifier, &request, 0, 60, &trusted_issuers, true, 0),
        Decision::Allow,
        "first presentation must be allowed"
    );
    std::thread::sleep(std::time::Duration::from_millis(5));
    assert_eq!(
        validate_with_issuer_and_replay_policy(&reg, &verifier, &request, 0, 60, &trusted_issuers, true, 0),
        Decision::Allow,
        "replay after the TTL has elapsed must be allowed again, not denied"
    );
}

// --- Task 6 (N3): validate inbound exchange requests (audience + depth) ---
//
// Review 0002 finding N3: `exchange_token` must refuse to re-mint a token
// that wasn't addressed to this gateway's own protected workload, and must
// refuse to extend a delegation chain that's already at (or past) the
// configured maximum depth. Before this fix, neither was checked at all --
// a token minted for one gateway could be exchanged through an unrelated
// one, and a chain could grow without bound regardless of any registry's
// `max_obo_chain_depth`.

const N3_PAYMENTS: &str = "spiffe://chakra.internal/ns/payments/sa/payments-svc";
const N3_ORDERS_GW: &str = "spiffe://chakra.internal/ns/orders-gw/sa/orders-gw";
const N3_DOWNSTREAM: &str = "spiffe://chakra.internal/ns/downstream/sa/downstream";

fn n3_issuer() -> LocalIssuer {
    LocalIssuer::generate(registry(), 300).unwrap()
}

/// A token whose `aud` names one workload (`payments`) must not be
/// exchangeable at a gateway protecting a different workload (`orders`) --
/// exactly the "token addressed to gateway A exchanged at gateway B" hole
/// N3 closes.
#[test]
fn exchange_rejects_wrong_audience() {
    let issuer = n3_issuer();
    let now = 1_000i64;

    let claims = OboClaims {
        sub: "spiffe://chakra.internal/ns/originator/sa/originator".to_string(),
        aud: vec![N3_PAYMENTS.to_string()],
        user: None,
        act: None,
        iat: now,
        exp: now + 300,
        nbf: None,
        jti: None,
        cnf: None,
        iss: None,
    };
    let token = issuer.sign_claims(&claims).unwrap();

    let destination_workload: SpiffeId = ORDERS.parse().unwrap();
    let result = exchange_token(
        &token,
        N3_DOWNSTREAM,
        &destination_workload,
        5,
        &issuer,
        issuer.verifier(),
        &N3_ORDERS_GW.parse::<SpiffeId>().unwrap(),
        300,
        now,
    );

    assert_eq!(result.unwrap_err(), TokenExchangeError::AudienceMismatch);
}

/// A token whose signed delegation chain is already 3 hops deep must be
/// rejected at a gateway configured with `max_chain_depth = 2` -- the
/// chain must not be allowed to grow past the configured limit.
#[test]
fn exchange_respects_max_depth() {
    let issuer = n3_issuer();
    let now = 1_000i64;

    // Chain so far: [originator, hop-a, hop-b] -- 3 entries, built directly
    // via nested `act` (outermost = most recent hop, per the N4 fix) rather
    // than performing three real exchanges, to isolate exactly the depth
    // check this test targets.
    let claims = OboClaims {
        sub: "spiffe://chakra.internal/ns/originator/sa/originator".to_string(),
        aud: vec![INVENTORY.to_string()],
        user: None,
        act: Some(Box::new(ActClaim {
            sub: "spiffe://chakra.internal/ns/hop-b/sa/hop-b".to_string(),
            act: Some(Box::new(ActClaim {
                sub: "spiffe://chakra.internal/ns/hop-a/sa/hop-a".to_string(),
                act: None,
            })),
        })),
        iat: now,
        exp: now + 300,
        nbf: None,
        jti: None,
        cnf: None,
        iss: None,
    };
    assert_eq!(claims.delegation_chain().len(), 3);
    let token = issuer.sign_claims(&claims).unwrap();

    let destination_workload: SpiffeId = INVENTORY.parse().unwrap();
    let result = exchange_token(
        &token,
        N3_DOWNSTREAM,
        &destination_workload,
        2, // max_chain_depth
        &issuer,
        issuer.verifier(),
        &N3_ORDERS_GW.parse::<SpiffeId>().unwrap(),
        300,
        now,
    );

    assert_eq!(result.unwrap_err(), TokenExchangeError::ChainDepthExceeded);
}

/// The happy path: a token addressed to this gateway's protected workload,
/// with a chain depth of 2 against a configured `max_chain_depth` of 3,
/// must be exchanged successfully -- proving the audience and depth
/// checks above don't also reject perfectly legitimate exchanges.
#[test]
fn exchange_allows_matching_audience_and_depth() {
    let issuer = n3_issuer();
    let now = 1_000i64;

    // Chain so far: [originator, hop-a] -- 2 entries, one hop already
    // recorded.
    let claims = OboClaims {
        sub: "spiffe://chakra.internal/ns/originator/sa/originator".to_string(),
        aud: vec![ORDERS.to_string()],
        user: None,
        act: Some(Box::new(ActClaim {
            sub: "spiffe://chakra.internal/ns/hop-a/sa/hop-a".to_string(),
            act: None,
        })),
        iat: now,
        exp: now + 300,
        nbf: None,
        jti: None,
        cnf: None,
        iss: None,
    };
    assert_eq!(claims.delegation_chain().len(), 2);
    let token = issuer.sign_claims(&claims).unwrap();

    let destination_workload: SpiffeId = ORDERS.parse().unwrap();
    let (new_token, ttl) = exchange_token(
        &token,
        N3_DOWNSTREAM,
        &destination_workload,
        3, // max_chain_depth
        &issuer,
        issuer.verifier(),
        &N3_ORDERS_GW.parse::<SpiffeId>().unwrap(),
        300,
        now,
    )
    .unwrap();

    assert_eq!(ttl, 300);
    let new_claims = issuer.verifier().verify_signature(&new_token).unwrap();
    assert_eq!(new_claims.aud, vec![N3_DOWNSTREAM.to_string()]);
    assert_eq!(new_claims.delegation_chain().len(), 3); // hop-a, then orders-gw appended
}

// --- Task 9 (N5): edge mint path for a human user principal -----------------
//
// Review 0002 finding N5: edge gateways (the mesh's entry points) need to
// mint tokens carrying a human user principal claim, not just a SPIFFE ID,
// so an action can be attributed end-to-end to the human who triggered it,
// not only to whichever service identity happened to make the call.
// `LocalIssuer::issue_jwt_svid_with_user` mints such a token (`sub` =
// gateway, `user` = human principal, `iss` = the trusted IdP that vouched
// for it), and `obo::validate_with_user_issuers` accepts that `user` claim
// as a human principal string -- not a SPIFFE ID -- when its `iss` is
// named in the configured trusted-issuer list.

const N5_EDGE_GATEWAY: &str = "spiffe://chakra.internal/ns/edge-gateway/sa/edge-gateway";
const N5_TRUSTED_ISSUER: &str = "auth.corp.internal";
const N5_HUMAN_PRINCIPAL: &str = "alice@corp.internal";

fn n5_registry() -> Registry {
    Registry::from_yaml_str(&format!(
        r#"
trust_domain: chakra.internal
workloads:
  - name: edge-gateway
    spiffe_id: {N5_EDGE_GATEWAY}
    max_obo_chain_depth: 3
    allowed_callers:
      - {N5_EDGE_GATEWAY}
"#
    ))
    .unwrap()
}

/// 1. `LocalIssuer::issue_jwt_svid_with_user` mints a token whose `sub` is
///    the gateway's own SPIFFE ID and whose `user` claim carries the human
///    principal verbatim (not a SPIFFE ID) -- the edge-mint path itself.
#[test]
fn user_principal_edge_mint() {
    let issuer = LocalIssuer::generate(n5_registry(), 300).unwrap();
    let gateway_id: SpiffeId = N5_EDGE_GATEWAY.parse().unwrap();
    let trusted_issuers = vec![N5_TRUSTED_ISSUER.to_string()];

    let issued = issuer
        .issue_jwt_svid_with_user(&gateway_id, N5_HUMAN_PRINCIPAL, N5_TRUSTED_ISSUER, &trusted_issuers)
        .unwrap();

    let claims = issuer.verifier().verify_signature(&issued.token).unwrap();
    assert_eq!(claims.sub, N5_EDGE_GATEWAY); // sub = gateway
    assert_eq!(claims.user, Some(N5_HUMAN_PRINCIPAL.to_string())); // user = human principal
    assert_eq!(claims.iss, Some(N5_TRUSTED_ISSUER.to_string()));
}

/// 2. `obo::validate_with_user_issuers` accepts a `user` claim from a
///    trusted issuer even though it isn't a well-formed SPIFFE ID -- and,
///    as a control, the exact same token is still rejected by the plain
///    `validate` entry point (which has no trusted-issuer list to consult),
///    proving the acceptance comes specifically from the N5 path, not from
///    some unrelated loosening of the user-principal check.
#[test]
fn user_principal_validation_accepts_user_claim() {
    let reg = n5_registry();
    let (signer, verifier) = test_keys();
    let destination: SpiffeId = N5_EDGE_GATEWAY.parse().unwrap();

    let claims = OboClaims {
        sub: N5_EDGE_GATEWAY.to_string(),
        aud: vec![N5_EDGE_GATEWAY.to_string()],
        user: Some(N5_HUMAN_PRINCIPAL.to_string()), // human principal, not a SPIFFE ID
        act: None,
        iat: 0,
        exp: 300,
        nbf: None,
        jti: None,
        cnf: None,
        iss: Some(N5_TRUSTED_ISSUER.to_string()),
    };
    let token = signer.sign(&claims).unwrap();

    let request = ValidationRequest {
        destination: &destination,
        source_principal: None,
        obo_token: Some(&token),
        caller_chain: None,
    };

    let trusted_issuers = vec![N5_TRUSTED_ISSUER.to_string()];
    assert_eq!(
        validate_with_user_issuers(&reg, &verifier, &request, 0, 60, &trusted_issuers),
        Decision::Allow,
        "a user claim from a trusted issuer must be accepted, not rejected as an invalid principal"
    );

    // Control: the plain `validate` entry point (no trusted-issuer list)
    // still denies the identical token -- the N5 acceptance is opt-in, not
    // a blanket loosening of `InvalidUserPrincipal`.
    assert_eq!(
        validate(&reg, &verifier, &request, 0),
        Decision::Deny(DenyReason::InvalidUserPrincipal)
    );
}

/// 3. A user credential whose claimed issuer is *not* in the configured
///    trusted-issuer list is rejected outright at mint time -- this
///    gateway never signs a `user` claim vouching for an IdP it hasn't
///    been told to trust.
#[test]
fn untrusted_user_issuer_rejected() {
    let issuer = LocalIssuer::generate(n5_registry(), 300).unwrap();
    let gateway_id: SpiffeId = N5_EDGE_GATEWAY.parse().unwrap();
    let trusted_issuers = vec![N5_TRUSTED_ISSUER.to_string()];

    let err = issuer
        .issue_jwt_svid_with_user(&gateway_id, N5_HUMAN_PRINCIPAL, "untrusted-idp.example", &trusted_issuers)
        .unwrap_err();

    assert!(matches!(err, IdentityError::UntrustedUserIssuer(iss) if iss == "untrusted-idp.example"));
}

// --- Task 3 (N2): bind certificates at exchange -----------------------------
//
// Review 0002 finding N2: `exchange_token` used to copy `cnf` verbatim from
// the inbound token, so a certificate-bound token died (or worse, stayed
// bound to a *stale* cert) after a single hop -- the exchanging gateway
// never got the chance to re-bind it to its own certificate. A gateway
// compromised after minting a token could have that token stolen and
// replayed elsewhere, since nothing re-anchored the binding to the actual
// party presenting it at each hop.
//
// `exchange_token_with_cert_binding` fixes this: it (1) validates that the
// inbound token's `cnf`, if present, matches the thumbprint of the cert the
// *exchanging* caller actually presented, then (2) re-mints the new token
// bound to *that* caller's cert -- never to whatever the inbound token
// happened to carry. These integration tests exercise that behavior through
// the crate's public API, the same way the N3/N4/N5 tests above do for their
// own findings.

const N2_ORDERS_GW: &str = "spiffe://chakra.internal/ns/orders-gw/sa/orders-gw";
const N2_INVENTORY_GW: &str = "spiffe://chakra.internal/ns/inventory-gw/sa/inventory-gw";
const N2_BACKEND: &str = "spiffe://chakra.internal/ns/backend/sa/backend";

fn n2_issuer() -> LocalIssuer {
    LocalIssuer::generate(placeholder_registry(), 300).unwrap()
}

/// 1. A token minted unbound at the originator (hop A), then exchanged at
///    hop B while hop B presents its own certificate, comes back bound to
///    **hop B's** thumbprint -- not left unbound, and not bound to anything
///    hop A had (hop A's token carried no `cnf` at all).
#[test]
fn cert_binding_at_exchange() {
    let issuer = n2_issuer();
    let now = 1_000i64;
    const HOP_B_THUMBPRINT: &str = "hop-b-cert-thumbprint";

    // Hop A's token: no `cnf` at all -- an ordinary unbound token, exactly
    // what a first-hop issuance looks like today.
    let claims = OboClaims {
        sub: "spiffe://chakra.internal/ns/originator/sa/originator".to_string(),
        aud: vec![N2_ORDERS_GW.to_string()],
        user: None,
        act: None,
        iat: now,
        exp: now + 300,
        nbf: None,
        jti: None,
        cnf: None,
        iss: None,
    };
    let token_at_a = issuer.sign_claims(&claims).unwrap();

    // Hop B exchanges it onward, presenting its own cert to the admin
    // listener -- the new token must come back bound to that cert.
    let destination_workload: SpiffeId = N2_ORDERS_GW.parse().unwrap();
    let (token_at_b, _ttl) = exchange_token_with_cert_binding(
        &token_at_a,
        N2_INVENTORY_GW,
        &destination_workload,
        5,
        &issuer,
        issuer.verifier(),
        &N2_ORDERS_GW.parse::<SpiffeId>().unwrap(),
        300,
        now,
        Some(HOP_B_THUMBPRINT),
    )
    .unwrap();

    let claims_at_b = issuer.verifier().verify_signature(&token_at_b).unwrap();
    assert_eq!(
        claims_at_b.cnf,
        Some(CertBinding {
            x5t_s256: HOP_B_THUMBPRINT.to_string()
        }),
        "the re-minted token must be bound to hop B's own cert, not left unbound"
    );
}

/// 2. A token already bound to hop A's cert, presented for exchange by a
///    caller whose presented cert thumbprint does *not* match, is rejected
///    with `CertificateBindingMismatch` -- a stolen bound token can't simply
///    be re-exchanged by whoever currently holds it.
#[test]
fn cert_binding_mismatch_at_exchange() {
    let issuer = n2_issuer();
    let now = 1_000i64;
    const HOP_A_THUMBPRINT: &str = "hop-a-cert-thumbprint";
    const ATTACKER_THUMBPRINT: &str = "attacker-cert-thumbprint";

    let claims = OboClaims {
        sub: "spiffe://chakra.internal/ns/originator/sa/originator".to_string(),
        aud: vec![N2_ORDERS_GW.to_string()],
        user: None,
        act: None,
        iat: now,
        exp: now + 300,
        nbf: None,
        jti: None,
        cnf: Some(CertBinding {
            x5t_s256: HOP_A_THUMBPRINT.to_string(),
        }),
        iss: None,
    };
    let bound_token = issuer.sign_claims(&claims).unwrap();

    let destination_workload: SpiffeId = N2_ORDERS_GW.parse().unwrap();

    // The legitimate holder (presenting hop A's own cert) can still
    // exchange it -- proves the mismatch below is really about the cert,
    // not some other failure mode.
    let legit_result = exchange_token_with_cert_binding(
        &bound_token,
        N2_INVENTORY_GW,
        &destination_workload,
        5,
        &issuer,
        issuer.verifier(),
        &N2_ORDERS_GW.parse::<SpiffeId>().unwrap(),
        300,
        now,
        Some(HOP_A_THUMBPRINT),
    );
    assert!(legit_result.is_ok(), "the legitimate cert holder must still be able to exchange");

    // An attacker presenting a *different* cert (or the token stolen and
    // replayed from a connection with no matching cert at all) must be
    // denied -- the whole point of the N2 fix.
    let mismatched_result = exchange_token_with_cert_binding(
        &bound_token,
        N2_INVENTORY_GW,
        &destination_workload,
        5,
        &issuer,
        issuer.verifier(),
        &N2_ORDERS_GW.parse::<SpiffeId>().unwrap(),
        300,
        now,
        Some(ATTACKER_THUMBPRINT),
    );
    assert_eq!(mismatched_result.unwrap_err(), TokenExchangeError::CertificateBindingMismatch);

    // No cert presented at all is just as much a mismatch -- fails closed,
    // never open.
    let no_cert_result = exchange_token_with_cert_binding(
        &bound_token,
        N2_INVENTORY_GW,
        &destination_workload,
        5,
        &issuer,
        issuer.verifier(),
        &N2_ORDERS_GW.parse::<SpiffeId>().unwrap(),
        300,
        now,
        None,
    );
    assert_eq!(no_cert_result.unwrap_err(), TokenExchangeError::CertificateBindingMismatch);
}

/// 3. A three-hop chain (gw-a -> gw-b -> gw-c -> backend), with each
///    exchanging hop presenting its *own* cert, ends up re-bound at every
///    hop: hop 1's output is bound to gw-a, hop 2's to gw-b, hop 3's to
///    gw-c -- never to some earlier hop's stale binding. Each hop's inbound
///    token (simulating what that hop received, already consumed by its own
///    transport-level cert-binding check at the proxy listener -- see the
///    pre-existing `obo::validate_with_cert_binding`/F5 tests -- and handed
///    to *this* exchange unbound) carries no `cnf` of its own; this isolates
///    exactly the re-binding mechanism this test targets (`cnf` always ends
///    up set to whatever the *current* exchanging hop presents) from the
///    separate "does the presented cert match an existing binding" check,
///    which `cert_binding_mismatch_at_exchange` above already covers.
///    `sub`/`act` (the signed delegation chain) are threaded through for
///    real at every hop, proving re-binding and chain-accumulation both
///    work correctly together across all three exchanges.
#[test]
fn cert_binding_propagates_through_chain() {
    let issuer = n2_issuer();
    let now = 1_000i64;
    const GW_A_THUMBPRINT: &str = "gw-a-cert-thumbprint";
    const GW_B_THUMBPRINT: &str = "gw-b-cert-thumbprint";
    const GW_C_THUMBPRINT: &str = "gw-c-cert-thumbprint";

    let gw_a: SpiffeId = "spiffe://chakra.internal/ns/gw-a/sa/gw-a".parse().unwrap();
    let gw_b: SpiffeId = "spiffe://chakra.internal/ns/gw-b/sa/gw-b".parse().unwrap();
    let gw_c: SpiffeId = "spiffe://chakra.internal/ns/gw-c/sa/gw-c".parse().unwrap();

    // Originator's token, addressed to gw-a, unbound.
    let originator_claims = OboClaims {
        sub: "spiffe://chakra.internal/ns/originator/sa/originator".to_string(),
        aud: vec![gw_a.to_string()],
        user: Some("spiffe://chakra.internal/ns/alice/sa/alice".to_string()),
        act: None,
        iat: now,
        exp: now + 300,
        nbf: None,
        jti: None,
        cnf: None,
        iss: None,
    };
    let token_0 = issuer.sign_claims(&originator_claims).unwrap();

    // Hop 1: gw-a exchanges toward gw-b, presenting its own cert -- the
    // inbound token had no `cnf`, so there's nothing to mismatch against;
    // the new token comes back bound to gw-a.
    let (token_1, _) = exchange_token_with_cert_binding(
        &token_0,
        "spiffe://chakra.internal/ns/gw-b/sa/gw-b",
        &gw_a,
        5,
        &issuer,
        issuer.verifier(),
        &gw_a,
        300,
        now,
        Some(GW_A_THUMBPRINT),
    )
    .unwrap();
    let claims_1 = issuer.verifier().verify_signature(&token_1).unwrap();
    assert_eq!(
        claims_1.cnf,
        Some(CertBinding {
            x5t_s256: GW_A_THUMBPRINT.to_string()
        }),
        "hop 1's output must be bound to gw-a's own cert"
    );

    // Hop 2: gw-b receives a token carrying the delegation chain built so
    // far (`sub` + `act` from hop 1's output) but, as it arrives for *this*
    // exchange, unbound -- re-signed as a fresh "inbound" claims set with
    // `cnf: None`, exactly like `token_0` was. gw-b then exchanges it
    // toward gw-c, presenting its own cert.
    let hop2_inbound_claims = OboClaims {
        sub: claims_1.sub.clone(),
        aud: vec![gw_b.to_string()],
        user: claims_1.user.clone(),
        act: claims_1.act.clone(),
        iat: now,
        exp: now + 300,
        nbf: None,
        jti: None,
        cnf: None,
        iss: None,
    };
    let token_1_unbound = issuer.sign_claims(&hop2_inbound_claims).unwrap();

    let (token_2, _) = exchange_token_with_cert_binding(
        &token_1_unbound,
        "spiffe://chakra.internal/ns/gw-c/sa/gw-c",
        &gw_b,
        5,
        &issuer,
        issuer.verifier(),
        &gw_b,
        300,
        now,
        Some(GW_B_THUMBPRINT),
    )
    .unwrap();
    let claims_2 = issuer.verifier().verify_signature(&token_2).unwrap();
    assert_eq!(
        claims_2.cnf,
        Some(CertBinding {
            x5t_s256: GW_B_THUMBPRINT.to_string()
        }),
        "hop 2's output must be bound to gw-b's own cert, not gw-a's stale binding"
    );
    assert_ne!(claims_2.cnf, claims_1.cnf, "the binding must change at every hop, never survive unchanged");
    // Chain so far: [originator, gw-a, gw-b].
    assert_eq!(claims_2.delegation_depth(), 2);

    // Hop 3: gw-c, same pattern -- receives the chain-so-far unbound, then
    // exchanges toward the final backend presenting its own cert.
    let hop3_inbound_claims = OboClaims {
        sub: claims_2.sub.clone(),
        aud: vec![gw_c.to_string()],
        user: claims_2.user.clone(),
        act: claims_2.act.clone(),
        iat: now,
        exp: now + 300,
        nbf: None,
        jti: None,
        cnf: None,
        iss: None,
    };
    let token_2_unbound = issuer.sign_claims(&hop3_inbound_claims).unwrap();

    let (token_3, _) = exchange_token_with_cert_binding(
        &token_2_unbound,
        N2_BACKEND,
        &gw_c,
        5,
        &issuer,
        issuer.verifier(),
        &gw_c,
        300,
        now,
        Some(GW_C_THUMBPRINT),
    )
    .unwrap();
    let final_claims = issuer.verifier().verify_signature(&token_3).unwrap();
    assert_eq!(
        final_claims.cnf,
        Some(CertBinding {
            x5t_s256: GW_C_THUMBPRINT.to_string()
        }),
        "the final token must be bound to the most recent hop's (gw-c's) cert"
    );
    assert_ne!(final_claims.cnf, claims_1.cnf);
    assert_ne!(final_claims.cnf, claims_2.cnf);

    // The delegation chain itself accumulates correctly across all three
    // real exchange calls, exactly as the N4 fix proves separately --
    // re-binding at every hop doesn't disturb it.
    assert_eq!(
        final_claims.delegation_chain(),
        vec![
            "spiffe://chakra.internal/ns/originator/sa/originator".to_string(),
            gw_a.to_string(),
            gw_b.to_string(),
            gw_c.to_string(),
        ]
    );
}

// --- Task 5 (N7, review 0002): split private signing keys from public JWKS ---
//
// Before this fix, `LocalIssuer::with_jwks`'s document embedded a
// `private_key_pem` for *every* `kid` in the trust domain, so any gateway
// that loaded the shared JWKS could mint tokens as any key, not just its
// own (review 0002 finding N7, carrying forward F4). These tests exercise
// the fix: a private signing key loaded from one file (issuer-only), a
// public JWKS loaded from a wholly separate file (every verifier), and
// proof that the public document itself never carries private material.

/// A fresh, TEST-ONLY 2048-bit RSA keypair's private half as PKCS#1 PEM
/// bytes -- the same shape `GatewayConfig::signing_key_path` loads in
/// production.
fn generate_private_key_pem() -> Vec<u8> {
    let mut rng = rand::rngs::OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    private_key.to_pkcs1_pem(LineEnding::LF).unwrap().as_bytes().to_vec()
}

/// A scratch directory for this test module's temp files, one per test
/// (unlike `src/ca.rs`/`src/tls.rs`'s single shared dir) since more than
/// one of these tests writes a `public-jwks.json` file and cargo test
/// runs every test in this binary concurrently in one process.
fn n7_scratch_dir(test_name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("zt-gateway-n7-test-{}-{test_name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Test 1/3: a `public_jwks` document -- the file every gateway's
/// `GatewayConfig::jwks_path` loads -- contains only standard public JWK
/// fields (`kid`, `kty`, `n`, `e`) and none of RSA's private-key fields
/// (`d`, `p`, `q`, `dp`, `dq`, `qi`). Written to and read back from an
/// actual file on disk, the same round trip `zt-gateway`'s `main` does for
/// `jwks_path`, not just an in-memory JSON string.
#[test]
fn public_jwks_contains_only_public_keys() {
    let private_pem = generate_private_key_pem();
    let public_jwks = JsonWebKeySet::from_rsa_private_pem("key-1".to_string(), &private_pem).unwrap();

    let dir = n7_scratch_dir("public_jwks_contains_only_public_keys");
    let jwks_path = dir.join("public-jwks.json");
    std::fs::write(&jwks_path, public_jwks.to_json().unwrap()).unwrap();

    let raw = std::fs::read_to_string(&jwks_path).unwrap();

    // None of RSA's private-key PKCS#1 fields ever appear as a JSON key in
    // the written document.
    for private_field in ["\"d\":", "\"p\":", "\"q\":", "\"dp\":", "\"dq\":", "\"qi\":"] {
        assert!(
            !raw.contains(private_field),
            "public_jwks file must never contain the private-key field {private_field}, but it did: {raw}"
        );
    }
    // Sanity check this isn't just an empty/degenerate document -- the
    // standard public fields are genuinely present.
    assert!(raw.contains("\"kid\""));
    assert!(raw.contains("\"kty\""));
    assert!(raw.contains("\"n\""));
    assert!(raw.contains("\"e\""));

    // And it round-trips back into a `JsonWebKeySet` with the same key.
    let loaded = JsonWebKeySet::from_json(&raw).unwrap();
    assert_eq!(loaded.keys.len(), 1);
    assert_eq!(loaded.keys[0].kid, "key-1");
    assert_eq!(loaded.keys[0].kty, "RSA");
}

/// Test 2/3: `LocalIssuer::with_separated_keys` signs with the loaded
/// private key (`signing_key_pem`), not with anything derived from the
/// public JWKS -- and the resulting token verifies correctly against that
/// same issuer's verifier (itself built from the public JWKS, never from
/// the private key directly).
#[test]
fn signing_uses_private_key_not_public() {
    let private_pem = generate_private_key_pem();
    let public_jwks = JsonWebKeySet::from_rsa_private_pem("key-1".to_string(), &private_pem).unwrap();

    let reg = Registry::from_yaml_str(&format!(
        r#"
trust_domain: chakra.internal
workloads:
  - name: orders-svc
    spiffe_id: {ORDERS}
    max_obo_chain_depth: 3
    allowed_callers: []
    bootstrap_token: orders-secret
"#
    ))
    .unwrap();

    let issuer =
        LocalIssuer::with_separated_keys(reg, &private_pem, Some("key-1".to_string()), &public_jwks, 300).unwrap();
    assert!(issuer.has_separated_signing_key(), "issuer must track its private key separately");

    let issued = issuer.issue_jwt_svid("orders-svc", INVENTORY, "orders-secret").unwrap();

    // The token is stamped with the kid this issuer signs with...
    let header = jsonwebtoken::decode_header(&issued.token).unwrap();
    assert_eq!(header.kid, Some("key-1".to_string()));

    // ...and actually verifies: the signature was produced by the private
    // key loaded from `signing_key_pem`, matching the public key published
    // in `public_jwks` under the same kid.
    let claims = issuer.verifier().verify_signature(&issued.token).unwrap();
    assert_eq!(claims.sub, ORDERS);

    // A token signed by some other, unrelated private key must NOT verify
    // against this issuer -- proving the issuer's verifier is actually
    // anchored to the public_jwks key material, not accepting anything.
    let rogue_pem = generate_private_key_pem();
    let rogue_signer = JwtSigner::from_rsa_pem_with_kid(&rogue_pem, "key-1".to_string()).unwrap();
    let rogue_token = rogue_signer
        .sign(&OboClaims {
            sub: ORDERS.to_string(),
            aud: vec![INVENTORY.to_string()],
            user: None,
            act: None,
            iat: 0,
            exp: 9_999_999_999,
            nbf: None,
            jti: None,
            cnf: None,
            iss: None,
        })
        .unwrap();
    assert!(issuer.verifier().verify_signature(&rogue_token).is_err());
}

/// Test 3/3: the issuer side (holds the private key, loaded from
/// `signing_key_pem`) and the verifier side (holds only `public_jwks`, and
/// nothing else -- no `LocalIssuer`, no private key ever in scope) are
/// genuinely separate objects built from separate inputs, and both work
/// correctly: the issuer signs, the standalone verifier verifies, with
/// zero private-key material anywhere in the verifier's construction
/// path.
#[test]
fn issuer_and_verifier_paths_separate() {
    let private_pem = generate_private_key_pem();
    let public_jwks = JsonWebKeySet::from_rsa_private_pem("key-1".to_string(), &private_pem).unwrap();

    // Round-trip public_jwks through a file, same as a verifier-only
    // gateway loading `GatewayConfig::jwks_path` would.
    let dir = n7_scratch_dir("issuer_and_verifier_paths_separate");
    let jwks_path = dir.join("public-jwks.json");
    std::fs::write(&jwks_path, public_jwks.to_json().unwrap()).unwrap();
    let loaded_public_jwks = JsonWebKeySet::from_json(&std::fs::read_to_string(&jwks_path).unwrap()).unwrap();

    // The issuer side: loads the private key (never written anywhere by
    // this test other than directly into `with_separated_keys`) plus the
    // public JWKS, and can sign.
    let reg = Registry::from_yaml_str(&format!(
        r#"
trust_domain: chakra.internal
workloads:
  - name: orders-svc
    spiffe_id: {ORDERS}
    max_obo_chain_depth: 3
    allowed_callers: []
    bootstrap_token: orders-secret
"#
    ))
    .unwrap();
    let issuer = LocalIssuer::with_separated_keys(
        reg,
        &private_pem,
        Some("key-1".to_string()),
        &loaded_public_jwks,
        300,
    )
    .unwrap();

    // The verifier side: built directly from the public JWKS alone --
    // `JsonWebKeySet::to_verifier` never sees `private_pem` at all. This
    // is what a verify-only consumer of `jwks_path` would hold.
    let standalone_verifier = loaded_public_jwks.to_verifier().unwrap();

    let issued = issuer.issue_jwt_svid("orders-svc", INVENTORY, "orders-secret").unwrap();

    // Both the issuer's own verifier and the wholly independent
    // standalone verifier (which never touched the private key) accept
    // the token the issuer signed.
    assert!(issuer.verifier().verify_signature(&issued.token).is_ok());
    let claims = standalone_verifier.verify_signature(&issued.token).unwrap();
    assert_eq!(claims.sub, ORDERS);
    assert_eq!(claims.aud, vec![INVENTORY.to_string()]);

    // And the public_jwks document this all ran through still carries no
    // private material (belt-and-suspenders with
    // `public_jwks_contains_only_public_keys` above, this time against the
    // exact file this test's issuer and verifier both actually loaded).
    let raw = std::fs::read_to_string(&jwks_path).unwrap();
    for private_field in ["\"d\":", "\"p\":", "\"q\":", "\"dp\":", "\"dq\":", "\"qi\":"] {
        assert!(!raw.contains(private_field));
    }
}
