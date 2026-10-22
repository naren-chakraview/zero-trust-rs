//! Regression tests for review 0004 (docs/reviews/0004-fourth-pass-review.md).
//!
//! The S1 probes are inverted: they assert the path is refused, so they pass now.
//! The S2 and R1 probes stay as regressions for the per-hop design they document.

use zero_trust::*;

const AGENT: &str = "spiffe://chakra.internal/ns/agents/sa/research-agent";
const ORD: &str = "spiffe://chakra.internal/ns/orders/sa/orders-svc";

fn id(s: &str) -> SpiffeId {
    s.parse().unwrap()
}

fn policy(yaml: &str) -> CapabilityPolicy {
    CapabilityPolicy::from_yaml_str(yaml, now_unix_secs()).unwrap()
}

// --- S1: paths a backend could decode into another path are refused ---

#[test]
fn s1_matrix_parameter_dot_segment_is_refused() {
    assert_eq!(unsafe_path_reason("/orders/..;/admin"), Some("dot_segment"));
}

#[test]
fn s1_backslash_dot_segment_is_refused() {
    assert_eq!(unsafe_path_reason("/orders/..\\admin"), Some("backslash"));
}

#[test]
fn s1_encoded_backslash_is_refused() {
    assert_eq!(unsafe_path_reason("/orders/..%5cadmin"), Some("backslash"));
}

#[test]
fn s1_double_encoded_dots_are_refused() {
    assert_eq!(unsafe_path_reason("/orders/%252e%252e/admin"), Some("double_encoding"));
}

#[test]
fn s1_encoded_semicolon_dot_segment_is_refused() {
    assert_eq!(unsafe_path_reason("/orders/..%3b/admin"), Some("dot_segment"));
}

#[test]
fn s1_overlong_utf8_dot_is_refused() {
    assert_eq!(unsafe_path_reason("/orders/%c0%ae%c0%ae/admin"), Some("overlong_utf8"));
}

#[test]
fn s1_ordinary_matrix_parameters_on_real_segments_are_allowed() {
    // A parameter on a real segment is not a dot-segment, so it's still allowed.
    assert_eq!(unsafe_path_reason("/orders/42;jsessionid=abc"), None);
}

// --- R1 (kept): an agent acting for an admin needs its own grant in the same rule ---

#[test]
fn r1_verified_admin_rights_do_not_flow_to_the_agent() {
    let p = policy(&format!(
        "default: deny\nrules:\n  - method: DELETE\n    path: /orders/*\n    users: [admin@example.com]\n    workloads: [{ORD}]\n  - method: GET\n    path: /orders/*\n    workloads: [{AGENT}]\n"
    ));
    let agent = id(AGENT);
    let now = now_unix_secs();
    let delete = CapabilityRequest { method: "DELETE", path: "/orders/42", user: Some("admin@example.com"), caller: Some(&agent) };
    let get = CapabilityRequest { method: "GET", path: "/orders/42", user: Some("intern@example.com"), caller: Some(&agent) };
    assert!(!p.check(&delete, now).is_allow());
    assert!(!p.check(&get, now).is_allow());
}

// --- S2 (kept): the check is per hop, against the current actor ---

#[test]
fn s2_only_current_actor_is_checked() {
    // inventory grants orders-svc acting for alice. An agent earlier in the chain is not consulted.
    let p = policy(&format!(
        "default: deny\nrules:\n  - method: GET\n    path: /stock/*\n    users: [alice@example.com]\n    workloads: [{ORD}]\n"
    ));
    let orders = id(ORD);
    let req = CapabilityRequest { method: "GET", path: "/stock/7", user: Some("alice@example.com"), caller: Some(&orders) };
    assert!(p.check(&req, now_unix_secs()).is_allow());
}
