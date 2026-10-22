//! Regression tests for the review 0002 findings (docs/reviews/0002-follow-up-review.md).
//!
//! These are the review's Appendix A probes inverted: each asserts the CORRECT
//! behavior, so a failing test means the finding is still open. Findings whose
//! coverage lives in the gateway binary's own tests (N9, N10) are not repeated
//! here.

use zero_trust::*;

const API: &str = "spiffe://chakra.internal/ns/api-gateway/sa/api-gateway";
const ORD: &str = "spiffe://chakra.internal/ns/orders/sa/orders-svc";
const INV: &str = "spiffe://chakra.internal/ns/inventory/sa/inventory-svc";
const OTHER: &str = "spiffe://chakra.internal/ns/payments/sa/payments-svc";

/// Inventory allows only orders-svc as a caller: the immediate hop.
fn reg_strict() -> Registry {
    Registry::from_yaml_str(&format!(
        r#"
trust_domain: chakra.internal
workloads:
  - name: api-gateway
    spiffe_id: {API}
    allowed_callers: []
    bootstrap_token: api-secret
  - name: orders-svc
    spiffe_id: {ORD}
    max_obo_chain_depth: 3
    allowed_callers: [{API}]
    bootstrap_token: orders-secret
  - name: inventory-svc
    spiffe_id: {INV}
    max_obo_chain_depth: 3
    allowed_callers: [{ORD}]
  - name: payments-svc
    spiffe_id: {OTHER}
    max_obo_chain_depth: 3
    allowed_callers: [{API}]
"#
    ))
    .unwrap()
}

fn id(s: &str) -> SpiffeId {
    s.parse().unwrap()
}

/// api-gateway -> orders (unbound token), then orders exchanges it for inventory.
fn two_hop_token(issuer: &LocalIssuer) -> String {
    let t1 = issuer.issue_jwt_svid("api-gateway", ORD, "api-secret").unwrap().token;
    exchange_token(&t1, INV, &id(ORD), 3, issuer, issuer.verifier(), &id(ORD), 300, now_unix_secs())
        .unwrap()
        .0
}

// --- N1: authorize the current actor, not the originator --------------------

#[test]
fn n1_legitimate_two_hop_chain_is_allowed_under_mtls() {
    // inventory allow-lists orders (its real caller), and orders is the mTLS peer.
    let issuer = LocalIssuer::generate(reg_strict(), 300).unwrap();
    let token = two_hop_token(&issuer);
    let dest = id(INV);
    let orders = id(ORD);
    let request = ValidationRequest {
        destination: &dest,
        source_principal: Some(&orders),
        obo_token: Some(&token),
        caller_chain: None,
    };
    let decision = validate(issuer.registry(), issuer.verifier(), &request, now_unix_secs());
    assert_eq!(decision, Decision::Allow);
}

#[test]
fn n1_mtls_peer_that_is_not_the_current_actor_is_denied() {
    // The token's current actor is orders, but payments presents the connection.
    let issuer = LocalIssuer::generate(reg_strict(), 300).unwrap();
    let token = two_hop_token(&issuer);
    let dest = id(INV);
    let payments = id(OTHER);
    let request = ValidationRequest {
        destination: &dest,
        source_principal: Some(&payments),
        obo_token: Some(&token),
        caller_chain: None,
    };
    let decision = validate(issuer.registry(), issuer.verifier(), &request, now_unix_secs());
    assert!(!decision.is_allow(), "a peer that is not the current actor must be denied");
}

// --- N2: re-bind at exchange to the exchanging hop's certificate ------------

#[test]
fn n2_exchange_binds_the_new_token_to_the_exchanging_hops_cert() {
    let issuer = LocalIssuer::generate(reg_strict(), 300).unwrap();
    let t1 = issuer.issue_jwt_svid("api-gateway", ORD, "api-secret").unwrap().token;
    let (t2, _) = exchange_token_with_cert_binding(
        &t1,
        INV,
        &id(ORD),
        3,
        &issuer,
        issuer.verifier(),
        &id(ORD),
        300,
        now_unix_secs(),
        Some("ORDERS-CERT-THUMB"),
    )
    .unwrap();
    let claims = issuer.verifier().verify_signature(&t2).unwrap();
    assert_eq!(
        claims.cnf.map(|c| c.x5t_s256),
        Some("ORDERS-CERT-THUMB".to_string()),
        "the re-minted token must be bound to the exchanging hop's certificate"
    );
}

// --- N3: exchange checks the inbound audience and depth ---------------------

#[test]
fn n3_exchange_refuses_a_token_addressed_to_another_gateway() {
    let issuer = LocalIssuer::generate(reg_strict(), 300).unwrap();
    let for_payments = issuer.issue_jwt_svid("api-gateway", OTHER, "api-secret").unwrap().token;
    let result = exchange_token(&for_payments, INV, &id(ORD), 3, &issuer, issuer.verifier(), &id(ORD), 300, now_unix_secs());
    assert!(result.is_err(), "a token addressed to payments must not be exchanged at orders");
}

#[test]
fn n3_exchange_enforces_max_chain_depth_at_mint_time() {
    let issuer = LocalIssuer::generate(reg_strict(), 300).unwrap();
    let token = two_hop_token(&issuer); // already one hop in its act chain
    // Limit of one hop in total. The inbound chain already holds one, so the
    // new hop would make two.
    let result = exchange_token(&token, OTHER, &id(INV), 1, &issuer, issuer.verifier(), &id(INV), 300, now_unix_secs());
    assert!(result.is_err(), "exchange must refuse to exceed max_obo_chain_depth");
}

// --- N4: act nesting follows RFC 8693 (outermost = current actor) -----------

#[test]
fn n4_outermost_act_is_the_current_actor() {
    let issuer = LocalIssuer::generate(reg_strict(), 300).unwrap();
    let t2 = two_hop_token(&issuer);
    // inventory exchanges it again for payments.
    let (t3, _) = exchange_token(&t2, OTHER, &id(INV), 3, &issuer, issuer.verifier(), &id(INV), 300, now_unix_secs()).unwrap();
    let claims = issuer.verifier().verify_signature(&t3).unwrap();
    assert_eq!(claims.act.as_ref().unwrap().sub, INV, "outermost act is the most recent hop");
}

// --- N5: an ingress path sets a human user principal, validated by issuer ---

#[test]
fn n5_user_mint_path_sets_the_user_claim() {
    let issuer = LocalIssuer::generate(reg_strict(), 300).unwrap();
    let gateway = id(API);
    let token = issuer
        .issue_jwt_svid_with_user(&gateway, "user@corp.internal", "auth.corp.internal", &["auth.corp.internal".to_string()])
        .unwrap()
        .token;
    let claims = issuer.verifier().verify_signature(&token).unwrap();
    assert_eq!(claims.user.as_deref(), Some("user@corp.internal"));
}

#[test]
fn n5_human_principal_from_a_trusted_issuer_is_not_rejected_as_non_spiffe() {
    let issuer = LocalIssuer::generate(reg_strict(), 300).unwrap();
    let gateway = id(INV);
    let trusted = vec!["auth.corp.internal".to_string()];
    let token = issuer
        .issue_jwt_svid_with_user(&gateway, "user@corp.internal", "auth.corp.internal", &trusted)
        .unwrap()
        .token;
    let dest = id(INV);
    let request = ValidationRequest {
        destination: &dest,
        source_principal: None,
        obo_token: Some(&token),
        caller_chain: None,
    };
    let decision = validate_with_user_issuers(issuer.registry(), issuer.verifier(), &request, now_unix_secs(), 60, &trusted);
    assert_ne!(decision, Decision::Deny(DenyReason::InvalidUserPrincipal));
}

// --- N6: an unbound token must not replay when the token is bound ----------

#[test]
fn n6_bound_token_is_refused_without_the_matching_cert() {
    let issuer = LocalIssuer::generate(reg_strict(), 300).unwrap();
    let token = issuer
        .issue_jwt_svid_with_cert_binding("orders-svc", INV, "CALLER-CERT", "orders-secret")
        .unwrap()
        .token;
    let dest = id(INV);
    let request = ValidationRequest {
        destination: &dest,
        source_principal: None,
        obo_token: Some(&token),
        caller_chain: None,
    };
    let decision = validate_with_cert_binding(issuer.registry(), issuer.verifier(), &request, None, now_unix_secs());
    assert_eq!(decision, Decision::Deny(DenyReason::CertificateBindingMismatch));
}

// --- N7: verifiers hold only public key material ---------------------------

#[test]
fn n7_public_jwks_document_carries_no_private_material() {
    use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
    let pem = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048)
        .unwrap()
        .to_pkcs1_pem(LineEnding::LF)
        .unwrap()
        .to_string();
    let public = JsonWebKeySet::from_rsa_private_pem("key-1".to_string(), pem.as_bytes()).unwrap();
    let json = public.to_json().unwrap();
    assert!(!json.contains("private_key_pem"));
    assert!(!json.contains("\"d\""));
    assert!(!json.contains("BEGIN"));
}

// --- N12: issuer and replay checks are enforced when configured -----------

#[test]
fn n12_token_from_an_untrusted_issuer_is_refused() {
    let issuer = LocalIssuer::generate(reg_strict(), 300).unwrap();
    let token = issuer.issue_jwt_svid("orders-svc", INV, "orders-secret").unwrap().token;
    let dest = id(INV);
    let request = ValidationRequest {
        destination: &dest,
        source_principal: None,
        obo_token: Some(&token),
        caller_chain: None,
    };
    let trusted = vec!["spiffe://chakra.internal/ns/other/sa/issuer".to_string()];
    let decision = validate_with_issuer_and_replay_policy(
        issuer.registry(),
        issuer.verifier(),
        &request,
        now_unix_secs(),
        60,
        &trusted,
        false,
        0,
    );
    assert_eq!(decision, Decision::Deny(DenyReason::IssuerNotTrusted));
}

#[test]
fn n12_a_replayed_jti_is_refused_when_replay_protection_is_on() {
    let issuer = LocalIssuer::generate(reg_strict(), 300).unwrap();
    let token = issuer.issue_jwt_svid("orders-svc", INV, "orders-secret").unwrap().token;
    let dest = id(INV);
    let request = ValidationRequest {
        destination: &dest,
        source_principal: None,
        obo_token: Some(&token),
        caller_chain: None,
    };
    let check = || {
        validate_with_issuer_and_replay_policy(
            issuer.registry(),
            issuer.verifier(),
            &request,
            now_unix_secs(),
            60,
            &[],
            true,
            300,
        )
    };
    assert!(check().is_allow(), "first use is allowed");
    assert_eq!(check(), Decision::Deny(DenyReason::TokenReplayed), "second use of the same jti is refused");
}
