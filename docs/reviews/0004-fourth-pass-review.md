# Review 0004: Fourth-Pass Review

**Date:** 2026-10-22
**Reviewed at:** commit `a27371d` (HEAD of `master`)
**Inputs:** [Review 0003](0003-third-pass-review.md) and its resolution table, [Design 0002](../design/0002-delegation-with-bound-tokens.md)
**Baseline:** `cargo test` passes 334 tests (196 lib, 66 bin, 34 obo_tests, 12 review2_regressions, 7 review3_regressions, 8 gap_probes, 7 routing, 3 spire_provider, 1 registry_fixture). The 2 ignored `admin_tls` tests also pass with `--ignored`. The Docker-based IdP test was not run.

## Verdict

**Ready to feature.** Every finding from reviews 0001 to 0003 that bears on the article's claims is fixed and covered by a regression test, and Design 0002 (the proxy-side rebind) is implemented as accepted. What remains is hardening and documentation, listed below. None of it contradicts what the article says, provided the article describes the capability check the way this gateway implements it (S2).

## Resolution status (2026-10-22)

| ID | Status | Commit | How it's checked |
|---|---|---|---|
| S1 | Fixed | `5d7c40d` | `unsafe_path_reason` refuses backslashes, double encoding, overlong UTF-8, and dot-segments with matrix parameters. Probes inverted in `tests/review4_regressions.rs`. |
| S2 | Documented | `2edd6be` | The check is per hop, against the current actor. README, module doc, and demo doc say so. Probe kept as a regression. |
| S3 | Fixed | `2edd6be` | Review 0003 now says design 0002 is implemented. |
| S4 | Documented | `2edd6be` | The demo's agent is the orders-svc workload. README, demo doc, and policy file say so. |
| S5 | No change | | Already listed under known gaps in the README and the demo doc. |

The kind cluster was deleted, so the demos were not re-run after `5d7c40d`. The S1
change only refuses path forms the demos don't use.

## Review 0003 findings: verified

I checked each fix in the code and re-ran the review 0003 probes against `a27371d`. Every probe that still compiles now fails, which means the gap it demonstrated is gone. The capability probes (q5 to q7) no longer compile against the stricter policy format, so I replaced them with equivalent ones: an agent acting for an admin cannot `DELETE` without its own grant in the same rule, and an agent's grant does not apply for a user with no rights.

| ID | Verified | Notes |
|---|---|---|
| R1 Capability semantics | Yes | A rule matches only when the acting workload and the user are both listed; a workload-only rule applies only when there is no user; startup refuses a rule with no workloads. |
| R2 Verified headers | Yes | All `x-zt-verified-*` headers are stripped on the way in; caller, user and chain each have their own gateway-owned header. |
| R3 Lifetime cap | Yes | `exp = min(inbound.exp, now + ttl)` in exchange and in rebind. |
| R4 Paths | Yes, with S1 | Segment-aware `*` and `**`; dot-segments, empty segments and encoded dots or slashes return 400. |
| R5 Depth | Yes | Exchange checks `len() + 1`. |
| R6 `iss` | Yes | `iss` is the signing gateway; the IdP moved to `user_iss`. |
| R7 CA key | Yes | Only api-gateway mounts the CA key; the others are verify-only. |
| R8 Agent demo | Yes (by script) | `scripts/demo-agent-chain.sh` expects 200 for alice's GET and 403 `capability_denied` for the DELETE. I did not run the kind cluster. |
| R9 Decision log | Yes | No test covers the log line, as the resolution table says. |
| R10 `with_jwks` | Mitigated | Deprecated with a runtime warning; the binary does not use it. |
| R11 `jti` cache | Documented | |
| Design 0002 | Yes | `rebind_token` leaves `act` unchanged, binds to the workload's delegation cert, caps `exp`, and sets `iss` to the signer. Startup refuses a delegating route whose `workload_id` is not this gateway, whose upstream is not loopback, without mTLS, or without `delegation_cert_path`. Gateway tests cover the rebind and a replay from another certificate. |

## Remaining items

| ID | Sev | Title |
|---|---|---|
| S1 | P2 | Path filter misses `..;`, backslashes and double encoding |
| S2 | P2 (article wording) | Capability is checked against the current actor only |
| S3 | P2 | Review 0003's resolution table says Design 0002 is not implemented |
| S4 | P2 | The demo's "agent" is the orders-svc workload |
| S5 | Info | SPIRE and token exchange are still mutually exclusive |

### S1. Path filter misses `..;`, backslashes and double encoding
**Where:** `config::unsafe_path_reason`.
**Evidence:** probes `s1_*` in the appendix: `/orders/..;/admin`, `/orders/..\admin`, `/orders/..%5cadmin` and `/orders/%252e%252e/admin` are all accepted.
**Why it matters:** Tomcat and Spring treat `..;` as `..`; IIS and some Windows-hosted servers treat `\` as `/`; a backend or proxy that decodes twice turns `%252e` into `.`. Any of these lets a `/orders/*` grant reach a path the gateway never matched.
**Fix:** also refuse a segment that starts with `..;` or `.;` (or strip `;` parameters before matching and forward the stripped path), any `\` or `%5c`, and any `%25`. Add the four probes inverted.

### S2. Capability is checked against the current actor only
**Where:** `proxy_handler` passes `verified_caller` (the current actor) to `CapabilityPolicy::check`.
**Behavior:** at each hop the policy asks whether the workload calling *this* hop, acting for this user, holds the grant. An agent is bounded at every hop where it is the caller. Hops further down the chain trust the service that called them; for example, inventory does not check the agent that called orders (probe `s2_only_current_actor_is_checked`). This is a reasonable and common design, not a defect.
**Article impact:** say "the agent cannot exceed its own grant at any hop it calls," not "anywhere in the chain." If you want the stricter property, add an option to require every actor in the signed chain to hold the grant.

### S3. Stale line in review 0003's resolution table
The table ends with "The design item from Design 0002 ... is not implemented in this batch," but `98964f7` and `4dca2c1` implemented it. Update the sentence.

### S4. The demo's agent is orders-svc
`demo-agent-chain.sh` and `capability-policy.yaml` cast the orders-svc workload as "the research agent." That is fine for a demo, but the article and README should say the agent is played by a workload, not that an LLM agent runs in the demo.

### S5. SPIRE and token exchange
Unchanged from N8: `SpireProvider` cannot sign, so exchange and rebind are unavailable under SPIRE. This is documented. Worth one sentence in the article's honest-costs section if the article mentions SPIRE.

## Appendix: probes

Save as `tests/review4_probes.rs`. All pass at `a27371d`: the `s1_*` probes show the gap, and `s2_*` documents the current-actor behavior (keep it as a regression test if that is the intended design).

```rust
//! Probes from docs/reviews/0004-fourth-pass-review.md, at a27371d.
use zero_trust::*;

const AGENT: &str = "spiffe://chakra.internal/ns/agents/sa/research-agent";
const ORD: &str = "spiffe://chakra.internal/ns/orders/sa/orders-svc";

fn id(s: &str) -> SpiffeId {
    s.parse().unwrap()
}

fn policy(yaml: &str) -> CapabilityPolicy {
    CapabilityPolicy::from_yaml_str(yaml, now_unix_secs()).unwrap()
}

#[test]
fn s1_matrix_parameter_dot_segment_is_accepted() {
    assert!(unsafe_path_reason("/orders/..;/admin").is_none());
}

#[test]
fn s1_backslash_dot_segment_is_accepted() {
    assert!(unsafe_path_reason("/orders/..\\admin").is_none());
}

#[test]
fn s1_encoded_backslash_is_accepted() {
    assert!(unsafe_path_reason("/orders/..%5cadmin").is_none());
}

#[test]
fn s1_double_encoded_dots_are_accepted() {
    assert!(unsafe_path_reason("/orders/%252e%252e/admin").is_none());
}

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

#[test]
fn s2_only_current_actor_is_checked() {
    // inventory grants orders-svc acting for alice; an agent earlier in the chain is not consulted.
    let p = policy(&format!(
        "default: deny\nrules:\n  - method: GET\n    path: /stock/*\n    users: [alice@example.com]\n    workloads: [{ORD}]\n"
    ));
    let orders = id(ORD);
    let req = CapabilityRequest { method: "GET", path: "/stock/7", user: Some("alice@example.com"), caller: Some(&orders) };
    assert!(p.check(&req, now_unix_secs()).is_allow());
}
```
