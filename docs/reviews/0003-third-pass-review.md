# Review 0003: Third-Pass Review

**Date:** 2026-10-22
**Reviewed at:** commit `b3ba6b8` (HEAD of `master`; history rewritten since review 0002, so earlier hashes no longer resolve)
**Inputs:** [Review 0001](0001-security-gap-review.md), [Review 0002](0002-follow-up-review.md), [Design 0002](../design/0002-delegation-with-bound-tokens.md)
**Baseline:** `cargo test` passes 302 tests (183 lib, 55 bin, 34 obo_tests, 12 review2_regressions, 8 gap_probes, 6 routing, 3 spire_provider, 1 registry_fixture). The 2 ignored `admin_tls` tests also pass with `--ignored`; the Docker-based IdP test was not run.

## How to use this document

Part 1 is the status of each review 0002 finding. Part 2 lists new findings (R1 to R11). Appendix A has seven library probes (`tests/review3_probes.rs`) and Appendix B has two gateway-binary probes, to be added to the `tests` module in `src/bin/zt-gateway.rs`. Every probe asserts the **current** behavior at `b3ba6b8` and passes today; invert each one into a regression test once its finding is fixed.

## Summary

This pass closed the structural problem from review 0002. Validation now authorizes the current actor, `act` nests per RFC 8693, exchange checks audience and depth and re-binds the certificate, and each gateway signs with its own private key while verifiers load a public-only JWKS. The proxy enforces body limits while buffering, strips delegation headers, and checks trusted issuers and `jti` replay. User principals come only from a verified IdP credential, a capability policy with hot reload is in place, the k8s demo runs with mTLS required, and agent working files are gone from history. The benchmarks now measure the real cost of delegation.

The P0s from reviews 0001 and 0002 are closed. What remains is smaller, but four items touch the claims a reader would test first:

1. **Capability grants are a union of user and agent rights (R1).** An agent acting for an admin gets the admin's full rights, and an agent's own grant applies for any user it acts for. Bounded agent autonomy needs the intersection.
2. **A client can forge the gateway's `X-ZT-Verified-Chain` header** on a direct mTLS call, and `X-ZT-Verified-User` actually carries the calling workload, not the user (R2).
3. **Token exchange can extend a token's lifetime** past the token it was derived from (R3).
4. **Capability paths are matched raw.** `*` crosses `/` and dot-segments are not normalized (R4).

Fix those four and the repo backs the article's claims, with the hop-0 bearer token (Design 0002, option A) as an honest, documented limitation.

---

## Part 1: Status of review 0002 findings

| ID | Status | Notes |
|---|---|---|
| N1 Authorize current actor | **Fixed** | `obo::current_actor` drives the allow-list and the mTLS peer check. |
| N2 `cnf` copied at exchange | **Fixed** | The inbound `cnf` must match the exchanging caller's cert, and the new token is bound to that cert. |
| N3 Exchange checks | **Fixed** (one edge case) | Inbound audience and depth are checked. The depth check is off by one (R5). |
| N4 `act` nesting | **Fixed** | New hops are prepended, and `delegation_chain` is chronological. |
| N5 User principal | **Fixed** (semantics residual) | `/v1/svid/jwt-with-user` verifies an RS256 IdP credential with pinned algorithm, `iss`, `aud` and `exp`. Residual: the minted token's `iss` is the IdP URL although the gateway signed it (R6). |
| N6 Binding at issuance | **Fixed** | Issuance binds to the client cert when mTLS is on. The demo turns binding off for its hop-0 token; Design 0002 proposes the fix (still Proposed). |
| N7 Private keys in JWKS | **Fixed** | `with_separated_keys`, per-gateway `signing_key_path`, a public-only `jwks_path`, and `scripts/gen-gateway-keys.sh`. The legacy `with_jwks` private-key loader still exists (R10). |
| N8 SPIRE | **Partial** | ES256 is supported. Exchange is still unavailable under `SpireProvider` because it cannot sign; documented. |
| N9 Body limits | **Fixed** | `to_bytes(body, max_body_bytes)`, a limited upstream read, and a TLS handshake timeout. |
| N10 Header forwarding | **Partial** | Delegation headers and `Authorization` are stripped. But the gateway-owned `X-ZT-Verified-*` headers are not stripped on the way in, and the "user" header carries the workload (R2). |
| N11 `obo.chain` from header | **Mostly fixed** | Spans use the signed chain. The structured log line still writes the raw header as `obo_chain` (R9). |
| N12 Issuer and replay | **Fixed** (opt-in) | `trusted_issuers` and the `jti` cache work but are off by default and not enabled in the demo. With the cache on, every token is single-use (R11). |
| N13 Manifests | **Fixed** | `proxy_addr`/`admin_addr`, mTLS required, real-caller allow-lists. Residual: every gateway pod mounts the CA private key (R7). |
| N14 Benchmarks | **Fixed** | Exchange is ~0.4 to 1.4 ms; a 3-hop round trip with two exchanges is ~1.0 to 2.2 ms, against ~0.2 to 0.3 ms undelegated. |
| N15 Hygiene | **Fixed** | `.superpowers/` removed from history; `.gitattributes` added. |
| F11 Capability policy | **Implemented** (semantics issues) | Method + path rules with user and workload grants, `default: allow` with a mandatory expiry, hot reload. See R1 and R4. |

## Part 2: New findings

| ID | Sev | Title |
|---|---|---|
| R1 | P1 (blocks the agent claim) | Capability grants union user and agent rights |
| R2 | P1 | `X-ZT-Verified-*` can be forged; the "user" header carries the workload |
| R3 | P1 | Exchange can extend token lifetime |
| R4 | P1 | Capability paths matched raw; `*` crosses `/` |
| R5 | P2 | Exchange depth check is off by one |
| R6 | P2 | `iss` no longer names the signer |
| R7 | P2 | Every gateway pod holds the CA private key |
| R8 | P2 | The demo does not exercise the agent story |
| R9 | P2 | Structured log still records the raw chain header |
| R10 | P2 | Legacy private-key JWKS loader still present |
| R11 | Info | `jti` cache makes tokens single-use |

### R1. Capability grants union user and agent rights
**Where:** `src/capability.rs`, `CapabilityPolicy::check`: `if user_granted || workload_granted`.
**Problem:** a request is allowed when *either* the user or the calling workload holds a matching grant.
- An agent acting for an admin can do anything the admin can, even with no grant of its own (probe `q5`). A prompt-injected agent is bounded by its user's rights, not its own.
- An agent's own grant applies whoever it acts for, so a user with no rights reaches data through the agent (probe `q6`).

This is the confused-deputy pattern the article argues capability policy prevents.
**Fix:** when a request carries a verified user, require **both**: the user is granted the action **and** the current actor (or every actor in the chain, if you want the stricter form) is granted it. Workload-only grants should apply only to requests with no user. Express it as rule-level `users` AND `workloads` (empty meaning "no constraint on that side"), or as two separate rule sets that must both pass.
**Acceptance:** the agent with only a `GET /orders/*` grant cannot `DELETE` for an admin. An intern with no grants cannot `GET` through the agent. An admin acting through an agent that holds `DELETE` can.

### R2. `X-ZT-Verified-*` forgeable and mislabeled
**Where:** `src/bin/zt-gateway.rs`: `DELEGATION_HEADERS_TO_STRIP` does not include `x-zt-verified-user` or `x-zt-verified-chain`. `forward_to_upstream` only overwrites them when a verified value exists, and sets `x-zt-verified-user` from `verified_caller`.
**Problem:**
- On a direct mTLS call (no OBO token) there is no verified chain, so a client-sent `X-ZT-Verified-Chain` reaches the backend as if the gateway had vouched for it (probe `q8`).
- `X-ZT-Verified-User` carries the calling workload's SPIFFE ID, not the user (probe `q9`), and the verified user is never forwarded at all.
- The doc comment on `HEADER_VERIFIED_USER` says client copies are removed first; they are not.

**Fix:** strip every `x-zt-verified-*` header on the way in. Rename the caller header to `X-ZT-Verified-Caller`, and add `X-ZT-Verified-User` from the signed `user` claim (with its IdP).
**Acceptance:** a client-sent `X-ZT-Verified-*` never reaches the backend on any path; the backend sees caller, user and chain each under its own correct name.

### R3. Exchange can extend token lifetime
**Where:** `src/token_exchange.rs`: `exp: now_secs + ttl_secs`.
**Evidence:** probe `q1` (a 10 s inbound token yields a 300 s token). Repeated exchanges can keep a delegation alive indefinitely, including a user's authorization.
**Fix:** `exp = min(inbound.exp, now + ttl)`.

### R4. Capability paths matched raw
**Where:** `CapabilityPolicy::check` passes `parts.uri.path()` to `config::wildcard_matches`, whose `*` matches any bytes including `/`.
**Evidence:** probe `q7`: rule `GET /orders/*` allows `/orders/../admin/keys`. Many backends normalize dot-segments, so they would serve `/admin/keys`.
**Fix:** reject (400) paths containing dot-segments, encoded slashes (`%2F`) or encoded dots, or normalize before both route matching and capability checks, and forward the normalized path. Make `*` match within one segment and add `**` for multi-segment matches. Apply the same to the route table.

### R5. Exchange depth check is off by one
**Where:** `exchange_token_with_cert_binding`: `inbound_claims.delegation_chain().len() > max_chain_depth`.
**Evidence:** probe `q2`: with a max of 2, a 2-entry inbound chain is exchanged into a 3-entry token. The next hop rejects it, so this is not a bypass, just a token that should never have been minted.
**Fix:** compare `len() + 1`.

### R6. `iss` no longer names the signer
**Where:** exchange copies `iss` from the inbound token (probe `q3`). `issue_jwt_svid_with_user` sets `iss` to the IdP URL although the gateway signs the token (probe `q4`).
**Problem:** with per-gateway keys, `iss` should identify who signed the token. Today `trusted_issuers` checks the originator, and an operator reading a token cannot tell which gateway minted it except from `kid`.
**Fix:** set `iss` to the minting gateway (or its trust domain plus `kid`) on every mint. Record the IdP that vouched for the user in a separate claim (for example `user_iss`), and have `validate_with_user_issuers` check that claim.

### R7. Every gateway pod holds the CA private key
**Where:** `deploy/k8s/*-svc.yaml` and `api-gateway.yaml` all set `ca.key_path`.
**Problem:** one compromised gateway can mint an X.509 SVID for any identity offline. This is the X.509 version of the N7 problem.
**Fix:** run one issuing gateway (or SPIRE) with the CA key, and make the others verify-only (`ca.cert_path` alone).

### R8. The demo does not exercise the agent story
The verified kind demo proves a 3-hop chain with mTLS and per-hop exchange. But it does not enable `capability_policy_path`, `user_idps`, `trusted_issuers` or the `jti` cache, and its hop-0 token is unbound (`require_cert_binding: false`). For the article, add a demo variant: an IdP-backed user, an agent workload in the chain, a capability policy with `default: deny`, and one denied request that shows the agent cannot exceed its grant.

### R9. Structured log records the raw chain header
**Where:** `proxy_handler`'s `tracing::info!(..., obo_chain = caller_chain...)`.
**Fix:** log the verified chain; keep the raw header as `obo_chain_unverified`.

### R10. Legacy private-key JWKS loader
`LocalIssuer::with_jwks` still accepts a document of private keys. Deprecate it with a startup warning, or remove it, so nobody reintroduces the N7 setup.

### R11. `jti` cache semantics
With `jti_cache_enabled`, every token is accepted once per gateway, so clients must mint a token per request. That is a valid design (it pairs well with per-hop exchange), but document it next to the flag, along with the memory bound of the cache.

## What the repo now supports for the article

| Article claim | Backed by code? |
|---|---|
| Attested workload identity (SPIFFE IDs, mTLS) | Yes. The gateway CA or SPIRE (ES256) is used, with mTLS required in the demo. |
| On-behalf-of delegation, attested hop by hop | Yes. RFC 8693 `act` chains are re-minted and re-bound at each hop, and the current actor is checked against the mTLS peer. Caveat: the hop-0 token is a bearer token until Design 0002 lands. |
| Verified human principal in the chain | Yes, via the IdP-verified edge mint (R6 is cosmetic). |
| Capability policy an agent cannot exceed | **Not yet.** R1 (union semantics) and R4 (raw paths). |
| Auditable chain in traces | Yes, signed chain in spans; R2 and R9 to tidy up. |
| Cost of delegation | Yes: ~15 µs per verify, ~0.4 to 1.4 ms per exchange. |

## Suggested order of work

1. R1, then R4 (capability semantics and path handling).
2. R2 (verified headers), R3 (lifetime cap).
3. R8 (agent demo variant), which doubles as the article's walkthrough.
4. R5, R6, R7, R9, R10, R11.
5. Design 0002 option A (proxy-side re-mint) to remove the hop-0 bearer caveat.

## Appendix A: library probes

Save as `tests/review3_probes.rs`. Mapping: q1 to R3, q2 to R5, q3 and q4 to R6, q5 and q6 to R1, q7 to R4. All seven pass at `b3ba6b8`.

```rust
//! Probes from docs/reviews/0003-third-pass-review.md.
//! Each asserts CURRENT behavior at b3ba6b8; a passing test means the issue is real.
//! Invert each one into a regression test as its finding is fixed.
use zero_trust::*;

const API: &str = "spiffe://chakra.internal/ns/api-gateway/sa/api-gateway";
const ORD: &str = "spiffe://chakra.internal/ns/orders/sa/orders-svc";
const INV: &str = "spiffe://chakra.internal/ns/inventory/sa/inventory-svc";
const AGENT: &str = "spiffe://chakra.internal/ns/agents/sa/research-agent";
const IDP: &str = "https://idp.example.com";

fn reg() -> Registry {
    Registry::from_yaml_str(&format!(
        r#"
trust_domain: chakra.internal
workloads:
  - name: api-gateway
    spiffe_id: {API}
    max_obo_chain_depth: 3
    allowed_callers: []
    bootstrap_token: api-secret
  - name: orders-svc
    spiffe_id: {ORD}
    max_obo_chain_depth: 2
    allowed_callers: [{API}]
    bootstrap_token: orders-secret
  - name: inventory-svc
    spiffe_id: {INV}
    max_obo_chain_depth: 2
    allowed_callers: [{ORD}]
"#
    ))
    .unwrap()
}

fn id(s: &str) -> SpiffeId {
    s.parse().unwrap()
}

#[test]
fn q1_exchange_extends_token_lifetime_past_the_inbound_exp() {
    // Inbound token lives 10s; exchange with a 300s TTL outlives it.
    let short = LocalIssuer::generate(reg(), 10).unwrap();
    let t1 = short.issue_jwt_svid("api-gateway", ORD, "api-secret").unwrap().token;
    let inbound_exp = short.verifier().verify_signature(&t1).unwrap().exp;
    let (t2, _) =
        exchange_token(&t1, INV, &id(ORD), 3, &short, short.verifier(), &id(ORD), 300, now_unix_secs()).unwrap();
    let minted_exp = short.verifier().verify_signature(&t2).unwrap().exp;
    eprintln!("inbound exp {inbound_exp}, minted exp {minted_exp}");
    assert!(minted_exp > inbound_exp, "re-minted token outlives the token it was derived from");
}

#[test]
fn q2_exchange_mints_a_token_one_hop_past_max_depth() {
    // The depth check runs on the inbound chain, before this hop is appended.
    // orders allows depth 2; the inbound chain [api-gateway, orders] is already 2.
    let issuer = LocalIssuer::generate(reg(), 300).unwrap();
    let t1 = issuer.issue_jwt_svid("api-gateway", ORD, "api-secret").unwrap().token;
    let (t2, _) = exchange_token(&t1, ORD, &id(ORD), 2, &issuer, issuer.verifier(), &id(ORD), 300, now_unix_secs())
        .unwrap();
    let chain_len = issuer.verifier().verify_signature(&t2).unwrap().delegation_chain().len();
    let res = exchange_token(&t2, INV, &id(ORD), 2, &issuer, issuer.verifier(), &id(ORD), 300, now_unix_secs());
    eprintln!("inbound chain {chain_len} at max 2 -> exchange ok = {}", res.is_ok());
    assert!(res.is_ok(), "a token whose new chain is 3 hops was minted against a max of 2");
}

#[test]
fn q3_exchange_copies_iss_so_iss_no_longer_names_the_signer() {
    let issuer = LocalIssuer::generate(reg(), 300).unwrap();
    let t1 = issuer.issue_jwt_svid("api-gateway", ORD, "api-secret").unwrap().token;
    let iss1 = issuer.verifier().verify_signature(&t1).unwrap().iss;
    let (t2, _) = exchange_token(&t1, INV, &id(ORD), 3, &issuer, issuer.verifier(), &id(ORD), 300, now_unix_secs())
        .unwrap();
    let iss2 = issuer.verifier().verify_signature(&t2).unwrap().iss;
    assert_eq!(iss1, iss2, "re-minted token keeps the original iss even though a different hop signed it");
}

#[test]
fn q4_edge_minted_token_claims_the_idp_as_its_issuer() {
    // The gateway signs the token, but `iss` names the IdP.
    let issuer = LocalIssuer::generate(reg(), 300).unwrap();
    let t = issuer
        .issue_jwt_svid_with_user(&id(API), "alice@example.com", IDP, &[IDP.to_string()])
        .unwrap()
        .token;
    let c = issuer.verifier().verify_signature(&t).unwrap();
    assert_eq!(c.iss.as_deref(), Some(IDP));
    assert!(c.cnf.is_none(), "edge-minted hop-0 token is an unbound bearer token");
}

fn policy() -> CapabilityPolicy {
    CapabilityPolicy::from_yaml_str(
        &format!(
            r#"
default: deny
rules:
  - method: DELETE
    path: /orders/*
    users: [admin@example.com]
  - method: GET
    path: /orders/*
    workloads: [{AGENT}]
"#
        ),
        now_unix_secs(),
    )
    .unwrap()
}

#[test]
fn q5_user_grant_lets_any_workload_act_with_it() {
    // admin may DELETE; the research agent has no DELETE grant at all.
    let agent = id(AGENT);
    let d = policy().check(
        &CapabilityRequest { method: "DELETE", path: "/orders/42", user: Some("admin@example.com"), caller: Some(&agent) },
        now_unix_secs(),
    );
    assert!(d.is_allow(), "agent inherits the user's full rights: effective = user OR agent");
}

#[test]
fn q6_workload_grant_applies_for_any_user() {
    // The agent's GET grant applies whoever it acts for, including a user with no grants.
    let agent = id(AGENT);
    let d = policy().check(
        &CapabilityRequest { method: "GET", path: "/orders/42", user: Some("intern@example.com"), caller: Some(&agent) },
        now_unix_secs(),
    );
    assert!(d.is_allow(), "user with no rights reaches data through the agent's own grant");
}

#[test]
fn q7_capability_path_is_matched_raw_not_normalized() {
    let agent = id(AGENT);
    let d = policy().check(
        &CapabilityRequest { method: "GET", path: "/orders/../admin/keys", user: None, caller: Some(&agent) },
        now_unix_secs(),
    );
    assert!(d.is_allow(), "'*' crosses '/' and dot-segments are not normalized");
}
```

## Appendix B: gateway-binary probes

Add inside the `#[cfg(test)] mod tests` block at the end of `src/bin/zt-gateway.rs` (they use that module's `test_state`, `spawn_header_capturing_upstream` and `PeerIdentity`). Mapping: q8 and q9 to R2. Both pass at `b3ba6b8`.

```rust
    // --- Review 0003 probes (assert CURRENT behavior at b3ba6b8) ---

    /// q8: on a direct mTLS call (no OBO token) the gateway sets no verified
    /// chain, and a client-sent `X-ZT-Verified-Chain` is not stripped, so the
    /// backend receives a forged "verified" chain.
    #[tokio::test]
    async fn q8_client_can_forge_x_zt_verified_chain_on_direct_mtls_call() {
        let (upstream_addr, captured) = spawn_header_capturing_upstream().await;
        let router = build_router(test_state(upstream_addr));
        let mut request = Request::builder()
            .method("GET")
            .uri("/some/path")
            .header("x-zt-verified-chain", "spiffe://chakra.internal/ns/forged/sa/admin")
            .header("x-zt-verified-user", "spiffe://chakra.internal/ns/forged/sa/admin")
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(PeerIdentity {
            spiffe_id: Some(ORDERS.parse().unwrap()),
            cert_thumbprint: Some("orders-thumb".to_string()),
        });
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::OK);
        let received = captured.lock().unwrap().take().expect("upstream should have been hit");
        assert_eq!(
            received.get("x-zt-verified-chain").unwrap().to_str().unwrap(),
            "spiffe://chakra.internal/ns/forged/sa/admin",
            "forged verified-chain header reached the backend"
        );
    }

    /// q9: `X-ZT-Verified-User` carries the calling workload, not the user.
    #[tokio::test]
    async fn q9_x_zt_verified_user_carries_the_workload_not_the_user() {
        let (upstream_addr, captured) = spawn_header_capturing_upstream().await;
        let state = test_state(upstream_addr);
        let issued = state.identity.issue_jwt_svid("orders-svc", INVENTORY, "orders-secret").unwrap();
        let router = build_router(state);
        let request = Request::builder()
            .method("GET")
            .uri("/some/path")
            .header(HEADER_OBO_TOKEN, issued.token)
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), SC::OK);
        let received = captured.lock().unwrap().take().unwrap();
        assert_eq!(received.get("x-zt-verified-user").unwrap().to_str().unwrap(), ORDERS);
    }
```
