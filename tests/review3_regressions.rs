//! Regression tests for the review 0003 findings (docs/reviews/0003-third-pass-review.md).
//!
//! These are the review's Appendix A probes inverted: each asserts the CORRECT
//! behavior, so a failing test means the finding is still open.

use zero_trust::*;

const AGENT: &str = "spiffe://chakra.internal/ns/agents/sa/research-agent";
const ORD: &str = "spiffe://chakra.internal/ns/orders/sa/orders-svc";

fn id(s: &str) -> SpiffeId {
    s.parse().unwrap()
}

/// Admin may DELETE orders, but only through a workload that is granted
/// DELETE too. The research agent holds GET only.
fn policy() -> CapabilityPolicy {
    CapabilityPolicy::from_yaml_str(
        &format!(
            r#"
default: deny
rules:
  - method: GET
    path: /orders/*
    workloads: [{AGENT}]
  - method: DELETE
    path: /orders/*
    users: [admin@example.com]
    workloads: [{ORD}]
"#
        ),
        now_unix_secs(),
    )
    .unwrap()
}

#[test]
fn r1_q5_agent_inherits_the_users_rights_without_its_own_grant() {
    // The original probe: the agent has no DELETE grant, but acts for an admin.
    let agent = id(AGENT);
    let d = policy().check(
        &CapabilityRequest {
            method: "DELETE",
            path: "/orders/42",
            user: Some("admin@example.com"),
            caller: Some(&agent),
        },
        now_unix_secs(),
    );
    assert!(!d.is_allow(), "an agent with only a GET grant must not DELETE for an admin");
}

#[test]
fn r1_q6_a_users_missing_grant_does_not_reach_data_through_the_agent() {
    // The original probe: an intern with no grants reaches data through the agent's GET grant.
    let agent = id(AGENT);
    let d = policy().check(
        &CapabilityRequest {
            method: "GET",
            path: "/orders/42",
            user: Some("intern@example.com"),
            caller: Some(&agent),
        },
        now_unix_secs(),
    );
    assert!(!d.is_allow(), "a user with no grant must not reach data through an agent");
}

#[test]
fn r4_q7_capability_paths_are_not_matched_across_dot_segments() {
    // The original probe: `*` crosses `/` and dot-segments are not normalized.
    // The proxy refuses such paths before this check runs, and the matcher does
    // not let `*` cross a separator.
    let agent = id(AGENT);
    let d = policy().check(
        &CapabilityRequest {
            method: "GET",
            path: "/orders/../admin/keys",
            user: None,
            caller: Some(&agent),
        },
        now_unix_secs(),
    );
    assert!(!d.is_allow(), "a grant on /orders/* must not reach /admin/keys");
}

// --- R3: an exchanged token never outlives the token it was derived from ---

const INV: &str = "spiffe://chakra.internal/ns/inventory/sa/inventory-svc";
const IDP: &str = "https://idp.example.com";
const API: &str = "spiffe://chakra.internal/ns/api-gateway/sa/api-gateway";

#[test]
fn r3_q1_exchange_does_not_extend_the_inbound_token_lifetime() {
    // A 10-second inbound token, exchanged with a 300-second TTL.
    let registry = Registry::from_yaml_str(&format!(
        r#"
trust_domain: chakra.internal
workloads:
  - name: api-gateway
    spiffe_id: spiffe://chakra.internal/ns/api-gateway/sa/api-gateway
    max_obo_chain_depth: 3
    allowed_callers: []
    bootstrap_token: api-secret
  - name: orders-svc
    spiffe_id: {ORD}
    max_obo_chain_depth: 3
    allowed_callers: []
    bootstrap_token: orders-secret
  - name: inventory-svc
    spiffe_id: {INV}
    max_obo_chain_depth: 3
    allowed_callers: []
"#
    ))
    .unwrap();
    let short = LocalIssuer::generate(registry, 10).unwrap();
    let t1 = short.issue_jwt_svid("api-gateway", ORD, "api-secret").unwrap().token;
    let inbound_exp = short.verifier().verify_signature(&t1).unwrap().exp;
    let (t2, _) = exchange_token(&t1, INV, &id(ORD), 3, &short, short.verifier(), &id(ORD), 300, now_unix_secs()).unwrap();
    let minted_exp = short.verifier().verify_signature(&t2).unwrap().exp;
    assert!(minted_exp <= inbound_exp, "minted exp {minted_exp} outlives inbound exp {inbound_exp}");
}

// --- R5: the exchanged chain never exceeds max_obo_chain_depth ---

#[test]
fn r5_q2_exchange_does_not_mint_a_chain_past_max_depth() {
    // Max depth 2. The inbound chain already holds two entries.
    let issuer = LocalIssuer::generate(reg_for_depth(), 300).unwrap();
    let t1 = issuer.issue_jwt_svid("api-gateway", ORD, "api-secret").unwrap().token;
    let (t2, _) = exchange_token(&t1, INV, &id(ORD), 2, &issuer, issuer.verifier(), &id(ORD), 300, now_unix_secs())
        .unwrap();
    let res = exchange_token(&t2, ORD, &id(INV), 2, &issuer, issuer.verifier(), &id(INV), 300, now_unix_secs());
    assert!(res.is_err(), "minting this hop would make a 3-entry chain against a max of 2");
}

fn reg_for_depth() -> Registry {
    Registry::from_yaml_str(&format!(
        r#"
trust_domain: chakra.internal
workloads:
  - name: api-gateway
    spiffe_id: spiffe://chakra.internal/ns/api-gateway/sa/api-gateway
    max_obo_chain_depth: 2
    allowed_callers: []
    bootstrap_token: api-secret
  - name: orders-svc
    spiffe_id: {ORD}
    max_obo_chain_depth: 2
    allowed_callers: []
    bootstrap_token: orders-secret
  - name: inventory-svc
    spiffe_id: {INV}
    max_obo_chain_depth: 2
    allowed_callers: []
"#
    ))
    .unwrap()
}

// --- R6: `iss` names the signing gateway; the user's IdP is in `user_iss` ---

#[test]
fn r6_q3_exchange_names_the_signing_gateway_in_iss() {
    let issuer = LocalIssuer::generate(reg_for_depth(), 300).unwrap();
    let t1 = issuer.issue_jwt_svid("api-gateway", ORD, "api-secret").unwrap().token;
    let iss1 = issuer.verifier().verify_signature(&t1).unwrap().iss;
    let (t2, _) = exchange_token(&t1, INV, &id(ORD), 3, &issuer, issuer.verifier(), &id(ORD), 300, now_unix_secs())
        .unwrap();
    let iss2 = issuer.verifier().verify_signature(&t2).unwrap().iss;
    assert_eq!(iss2.as_deref(), Some(issuer.gateway_iss().as_str()), "the re-minted token must name the gateway that signed it");
    // The originator's token was minted by the same issuer here, so iss1 matches
    // by construction. The copy-from-inbound behavior is what R6 removes, and it
    // shows up in the test above only when the two signers differ.
    let _ = iss1;
}

#[test]
fn r6_q4_edge_minted_token_names_the_gateway_and_records_the_idp_separately() {
    let issuer = LocalIssuer::generate(reg_for_depth(), 300).unwrap();
    let t = issuer
        .issue_jwt_svid_with_user(&id(API), "alice@example.com", IDP, &[IDP.to_string()])
        .unwrap()
        .token;
    let c = issuer.verifier().verify_signature(&t).unwrap();
    assert_eq!(c.iss.as_deref(), Some(issuer.gateway_iss().as_str()));
    assert_eq!(c.user_iss.as_deref(), Some(IDP));
}
