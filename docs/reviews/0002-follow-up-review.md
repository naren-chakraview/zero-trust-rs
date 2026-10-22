# Review 0002: Follow-up Review After the Security-Gap Pass

**Date:** 2026-10-17
**Reviewed at:** commit `5d1edff` (HEAD of `master`, 18 commits after review 0001's baseline `46cd5f5`)
**Inputs:** [Review 0001](0001-security-gap-review.md), `docs/superpowers/plans/2026-10-15-security-gaps-implementation.md`
**Baseline:** `cargo test` passes all 190 tests (124 lib, 34 bin, 8 gap_probes, 13 obo_tests, 6 routing, 3 spire_provider, 1 registry_fixture).

## Resolution status (as of 2026-10-21)

Each finding below was checked against the code and the tests on `master`.
Items marked **Partial** or **Open** are still not fully resolved. The
findings text below is the original review and is not edited.

| ID | Status | Commit(s) | Notes |
|---|---|---|---|
| F1 | Fixed | `1bbbd40`, `b64276f`, `77ac483` | N11 covers the span attribute. |
| F2 | Fixed | `deb46b8` | Human principals come from verified IdP credentials. |
| F3 | Fixed | `4fddfc2`, `1bbbd40`, `b64276f` | Exchange checks audience and depth, and the proxy strips delegation headers. |
| F4 | Fixed (static keys) | `63e9370`, JWKS commit | The gateway uses a public JWKS and a per-gateway signing key. The K8s manifests and `deploy-all.sh` now deploy them (option 1). Verified locally. Not yet confirmed on a cluster. |
| F5 | Fixed | `63e9370`, `d1f4103` | Issuance binds to the caller's cert by default. Exchange re-binds to the exchanging hop. |
| F6 | Fixed | `aa9f07c` | Request bodies are capped while buffering. Responses and the TLS handshake are bounded. |
| F7 | Fixed | (earlier) | Admin and proxy are separate. |
| F8 | Fixed | (earlier) | |
| F9 | Fixed | (earlier) | |
| F10 | Fixed | `eb0cd6a`, plus a follow-up commit | Admin uses a separate TLS acceptor. It requests client certs but doesn't require them, so bootstrap works and cert-bound issuance works. Startup refuses a non-loopback admin address. `tests/admin_tls.rs` covers it. The first version of this fix dropped the verifier and broke N6. |
| F11 | Fixed | `901db21`, `9f7c76f` | Capability policy with per-user and per-workload grants, a deadline on allow-by-default, and hot reload. There are no explicit deny rules yet. |
| F12 | Fixed | (earlier), `b64276f` | |
| F13 | Partial | `dbeac1d`, `98b56da` | ES256 verification is in. Under SPIRE, token exchange can't sign (N8). |
| F14 | Fixed | (earlier) | |
| F15 | Fixed | `77ac483` | `iss` is checked against `trusted_issuers` and `jti` against the replay cache, on the proxy path. |
| F16 | Partial | `5d1edff` | The demo script still assumes plain HTTP and isn't re-run. See `docs/demo-obo-chain.md`. |
| F17 | Fixed | `98b56da` | Exchange and proxy round-trip benchmarks are in. |
| F18 | Fixed | (earlier) | |
| N1 | Fixed | `1bbbd40` | |
| N2 | Fixed | `d1f4103` | |
| N3 | Fixed | `b64276f` | |
| N4 | Fixed | `4fddfc2` | |
| N5 | Fixed | `deb46b8`, `02085cd` | Verified credentials, plus an integration test against a real OIDC IdP. |
| N6 | Fixed | `63e9370` | |
| N7 | Fixed | `63e9370`, JWKS commit | The public-only set is deployed. The legacy `with_jwks` loader still exists in the library, but the binary doesn't use it. |
| N8 | Partial | `dbeac1d`, `98b56da` | ES256 is in. A separate token-signing key for SPIRE delegation isn't built. |
| N9 | Fixed | `aa9f07c` | |
| N10 | Fixed | `b64276f` | |
| N11 | Fixed | `b64276f` | |
| N12 | Fixed | `6a94e38`, `77ac483` | The library functions existed. The gateway now calls them. |
| N13 | Fixed | `50ae5b9`, JWKS commit | Manifests use `proxy_addr`/`admin_addr`, mTLS, and the JWKS settings. |
| N14 | Fixed | `98b56da` | |
| N15 | Fixed | `50ae5b9`, `0530875` | Agent files are untracked, but they remain in git history (13 commits). Rewriting history is a separate decision. |

Regression tests for the findings are in `tests/review2_regressions.rs` (commit
`52c8349`). All pass. The probes in Appendix A ran against the original
commit.

## How to use this document

Part 1 is the status of each review 0001 finding. Part 2 lists new findings (N1 to N15), most of them in code added during the fix pass. Appendix A has nine probe tests (`tests/review2_probes.rs`) that reproduce N1 to N7 against `5d1edff`. Each probe asserts the **current** behavior and passes today; invert it into a regression test once the finding is fixed.

## Summary

This pass did a lot of solid work. Signed claims replace the unsigned headers in every decision. There is a token-exchange endpoint, a separate loopback-only admin listener with rate limiting and constant-time secret comparison, and a route table. The pass also added W3C trace propagation, `nbf` checks with clock-skew tolerance, criterion benchmarks, a SPIRE Workload API client and a reworked demo. The test suite went from 68 to 190, all passing.

It is **not yet ready to feature**, for one structural reason: **the multi-hop delegation model authorizes the originator instead of the current caller.** Token exchange keeps the original `sub` and appends hops under `act`, but `validate` still checks the allow-list, the mTLS peer and the `cnf` binding against `sub`. The consequences, all reproduced in Appendix A:

- A legitimate two-hop chain (api-gateway to orders to inventory) is **denied** when inventory allow-lists only its real caller, orders-svc (N1).
- The same chain is **denied** whenever mTLS is on, because the peer (orders) never equals `sub` (api-gateway) (N1).
- A certificate-bound token cannot survive an exchange, because `cnf` is copied from the original caller (N2).

The demo passes only because mTLS is off and every hop's allow-list includes the originator, so allow-lists stop meaning "who may call me". Separately, the shared key file still holds every private key (F4), cert binding and the user principal have no production issuance path (N5, N6), and capability policy (F11) is not started.

---

## Part 1: Status of review 0001 findings

| ID | Status | Notes |
|---|---|---|
| F1 Unsigned chain header | **Fixed** (decision path) | Depth and entries now come from the signed `act` claim. Residual: the tracing span and log still record the unsigned header as `obo.chain` (N11). |
| F2 Unsigned user principal | **Partial** | Decisions use the signed `user` claim, and the raw header is recorded only as `obo.user_principal_unverified`. But no issuance path ever sets `user` (N5), and `validate` rejects any `user` that is not a SPIFFE ID, which excludes human principals. |
| F3 No re-minting on egress | **Partial** | `/v1/token-exchange` re-mints with an appended hop. But the authorization model is inconsistent with it (N1, N2), the exchange does not check the inbound audience (N3), and the proxy still forwards the inbound token and `X-SPIFFE-*` headers to the backend (N10). |
| F4 Shared trust anchor | **Open (regressed in blast radius)** | The `jwks_path` document still carries a private key for every `kid`. Every gateway that loads it can mint as any key (probe r9). Needs a public-key-only verification set and per-issuer private keys. |
| F5 Token-to-channel binding | **Partial (library only)** | `cnf.x5t#S256` is validated when present. But the only HTTP issuance route (`/v1/svid/jwt`) mints unbound tokens, so binding never applies in practice (N6). Exchange breaks binding (N2). |
| F6 Body limits and timeouts | **Partial** | Upstream connect/request timeouts, a concurrency limit and `TimeoutLayer` are in. But the proxy still buffers the request with `to_bytes(body, usize::MAX)` before checking size, and upstream responses are unbounded (N9). No TLS handshake timeout. |
| F7 Admin/proxy split, rate limit, constant-time | **Fixed** | Admin defaults to `127.0.0.1:6443`, `RateLimitLayer` behind a `Buffer`, `subtle::ConstantTimeEq` with a dummy compare for unknown workloads. |
| F8 CA SAN copying | **Fixed** | Since `8d5ce72`. |
| F9 Leaf constraints | **Fixed** | Since `8d5ce72`. |
| F10 `required` bootstrap deadlock | **Mostly mitigated** | The loopback admin listener avoids the external deadlock, but it reuses the proxy's TLS acceptor, so under `client_auth: required` the first X.509 SVID still cannot be fetched over the admin listener. |
| F11 Capability policy / agent model | **Open** | `TokenExchangeRequest.scope` is parsed and unused; there is no method/path/action or capability check. |
| F12 Tracing | **Mostly fixed** | W3C TraceContext extract/inject, a span per hop, deny events traced. Residual: N11. |
| F13 SPIRE | **Partial** | `SpireProvider` exists but is RS256-only (default SPIRE JWT keys are ES256, so the verifier ends up with zero keys), and it cannot sign, so token exchange is unavailable with SPIRE. SPIRE and delegation are currently mutually exclusive (N8). |
| F14 Topology | **Fixed** | Route table by method, path and host, validated against the registry. |
| F15 Claim checks | **Partial** | `nbf` with skew: done. `iss`: syntax only, optional, never checked against trusted issuers (`IssuerNotTrusted` is never produced). `jti`: issued but not enforced (no replay cache). `kid`: done. |
| F16 Demo fidelity | **Partial** | The demo now uses real exchange, but manifests are stale (N13) and the demo relies on originator allow-listing and plaintext transport, which hides N1. |
| F17 Benchmarks | **Partial** | Benchmarks measure verification only (~14.5 µs). The real per-hop OBO cost is the RS256 **signature** in token exchange plus the proxy round trip, and neither is benchmarked (N14). |
| F18 Stale metadata | **Fixed** | `repository` URL and the design-doc status are updated. |

## Part 2: New findings

| ID | Sev | Title |
|---|---|---|
| N1 | P0 | Authorization targets the originator (`sub`), not the current caller |
| N2 | P0 | Exchange copies `cnf`, so bound tokens fail at the next hop |
| N3 | P1 | Exchange does not check the inbound audience, authenticate the caller, or enforce depth |
| N4 | P1 | `act` nesting is reversed relative to RFC 8693 |
| N5 | P1 | No path sets the `user` claim; human principals are rejected |
| N6 | P1 | Cert binding has no production issuance path |
| N7 | P0 | Key file still distributes every private key (F4 carried forward) |
| N8 | P1 | SPIRE provider cannot verify default SPIRE tokens or sign exchanges |
| N9 | P1 | Proxy still buffers unbounded request bodies; responses unbounded |
| N10 | P1 | Inbound OBO token and unsigned headers still forwarded to the backend |
| N11 | P2 | `obo.chain` in spans and logs comes from the unsigned header |
| N12 | P2 | `iss` not checked against trusted issuers; `jti` replay not enforced |
| N13 | P2 | k8s manifests stale (ignored `listen_addr`, privileged default port) |
| N14 | P2 | Benchmarks omit the exchange signature and proxy round trip |
| N15 | P2 | Agent working files and local paths committed; CRLF churn |

### N1 (P0). Authorization targets the originator, not the current caller
**Where:** `src/obo.rs` `validate_with_clock_skew`: the allow-list check on `claims.sub` (end of function) and the no-impersonation check `claims.sub != source.to_string()`. `src/token_exchange.rs` `exchange_token`: `sub: inbound_claims.sub.clone()`.
**Problem:** after an exchange, `sub` is still the originator and the hop that is actually calling is buried in `act`. So each destination's allow-list is evaluated against whoever started the chain, and the mTLS peer is compared against the originator rather than the connection's real peer.
**Evidence:** probes `r1_allow_list_checks_originator_not_immediate_caller` (legitimate chain denied with `CallerNotInAllowList`) and `r2_exchanged_token_fails_impersonation_check_under_mtls` (denied with `OboTokenSubjectMismatch`).
**Fix:** define the **current actor** as the most recent hop (with RFC 8693 nesting, the outermost `act.sub`; `sub` when there is no `act`). Check `allowed_callers`, the mTLS peer match and `cnf` against the current actor. Keep `sub`/`user` as the subject the call is made on behalf of, and add an optional, separate policy for which originators may reach a destination through delegation.
**Acceptance:** with inventory allow-listing only orders-svc, the chain api-gateway → orders → inventory is allowed with mTLS on, and orders presenting a token whose current actor is someone else is denied.

### N2 (P0). Exchange copies `cnf`
**Where:** `src/token_exchange.rs`, `cnf: inbound_claims.cnf.clone()`.
**Evidence:** probe `r3_cert_binding_is_copied_so_bound_tokens_die_after_one_hop`.
**Fix:** at exchange, bind the new token to the **exchanging hop's** certificate (the thumbprint of the client cert presented to the admin listener, or a thumbprint supplied by the co-located workload). Require that the inbound token's `cnf`, if present, matches the exchanging caller's cert.

### N3 (P1). Exchange checks too little
**Where:** `src/token_exchange.rs` `exchange_token` (signature and `exp` only, by design per its module doc); `handle_token_exchange` in `src/bin/zt-gateway.rs`.
**Problem:** a token addressed to any audience can be exchanged at any gateway (probe `r4_exchange_does_not_check_inbound_audience`). The exchange caller is not authenticated beyond reaching the admin port, and depth is not enforced at mint time. The loopback default for the admin listener reduces exposure to the co-located workload, which is why this is P1 rather than P0.
**Fix:** require `inbound.aud` to contain this gateway's protected workload (or the routed workload), and enforce `max_obo_chain_depth` and `nbf` when minting. When the admin listener has TLS, authenticate the caller and record it.

### N4 (P1). `act` nesting reversed relative to RFC 8693
**Where:** `token_exchange.rs` `append_hop` appends the new hop at the innermost level; `OboClaims::delegation_chain` reads outermost-first as oldest.
**Evidence:** probe `r5_act_nesting_is_reversed_vs_rfc8693`.
**Problem:** RFC 8693 section 4.1 defines the outermost `act` as the current actor and nested `act` claims as prior actors. The current layout is internally consistent but not interoperable, and the docs call it RFC 8693.
**Fix:** prepend the new hop (`act = { sub: gateway, act: inbound.act }`), and flip `delegation_chain` to match. Fixing this makes N1's "current actor" the outermost `act`.

### N5 (P1). The user principal is unreachable
**Where:** `LocalIssuer::issue_jwt_svid` and `issue_jwt_svid_with_cert_binding` set `user: None`; exchange copies it. `validate` denies a `user` that does not parse as a SPIFFE ID.
**Evidence:** probes `r6_no_issuance_path_sets_a_user_principal`, `r7_human_user_principal_is_rejected_unless_spiffe_id`.
**Problem:** "user → agent → service, attested end to end" cannot be produced by the running system, and a human principal such as `user@corp.internal` is rejected.
**Fix:** add an ingress mint path (at the edge gateway) that sets `user` from a verified end-user credential (for example an OIDC ID token from a trusted IdP, with its issuer recorded). Validate `user` as a principal from a trusted user issuer, not as a SPIFFE ID.

### N6 (P1). Cert binding has no production entry point
**Where:** `/v1/svid/jwt` calls `issue_jwt_svid` (unbound); `issue_jwt_svid_with_cert_binding` is only called from tests.
**Evidence:** probe `r8_unbound_token_still_replays_without_any_cert`.
**Fix:** when the admin listener sees a verified client cert, issue bound tokens by default (a config flag to require it). Combine with N2.

### N7 (P0). Key file still distributes every private key
F4 is carried forward unchanged (probe `r9_jwks_file_still_holds_every_private_key`). Split it into (a) one private signing key per issuer, loaded only by that issuer, and (b) a public JWKS (`kty`, `n`, `e`, `kid`) loaded by verifiers. Reload the public set on change or on an interval so rotation needs no restart.

### N8 (P1). SPIRE provider limitations
**Where:** `src/spire_provider.rs`.
**Problem:** the verifier keeps only RSA authorities, and SPIRE's default JWT key type is EC, so against a default SPIRE deployment the verifier holds zero keys and every check fails closed. `sign_claims` always errors, so token exchange is unavailable under SPIRE. `issue_jwt_svid` ignores the requester and credential and returns the gateway's own SVID to any admin-listener caller. The module doc is candid about all three.
**Fix:** add ES256 to `JwtSigner`/`JwtVerifier`. For delegation under SPIRE, keep SPIRE for workload identity (mTLS and the gateway's own SVID) and run a separate token-exchange signing key whose public half is distributed as in N7. Document `/v1/svid/jwt` under SPIRE as "this gateway's identity" or disable it.

### N9 (P1). Proxy body handling
**Where:** `proxy_handler` in `src/bin/zt-gateway.rs`: `axum::body::to_bytes(body, usize::MAX)`, with the size check later in `forward_to_upstream`; the upstream response is read with `.bytes()` and no cap.
**Problem:** `DefaultBodyLimit` only applies to axum's body extractors, not to a raw `Request` read with `to_bytes`, so the proxy still buffers arbitrarily large bodies before rejecting them.
**Fix:** pass `max_body_bytes` to `to_bytes` (or wrap with `http_body_util::Limited` / `RequestBodyLimitLayer`), reject on `Content-Length` up front, cap the upstream response, and add a TLS handshake timeout in `serve()`. Add a test that streams a body larger than the limit and asserts 413 without a full buffer.

### N10 (P1). Delegation material forwarded to the backend
**Where:** `forward_to_upstream` clones all inbound headers except three hop-by-hop ones.
**Fix:** strip `X-SPIFFE-OBO-Token`, `X-SPIFFE-Caller-Chain` and `X-SPIFFE-User-Principal` before forwarding. If the backend needs identity, pass verified values in gateway-owned headers (for example `X-ZT-Verified-User`, `X-ZT-Verified-Chain`) that the gateway always overwrites. Also strip `Authorization` unless the route opts in.

### N11 (P2). `obo.chain` is still the unsigned header
**Where:** `proxy_handler`: `span.record("obo.chain", caller_chain...)` and the `obo_chain` field of the structured log.
**Fix:** record `claims.delegation_chain()` from the verified token; keep the raw header only as `obo.chain_unverified`.

### N12 (P2). Issuer and replay
Require `iss` and check it against a configured trusted-issuer list (producing `IssuerNotTrusted`). Optionally enforce `jti` uniqueness within the token TTL for high-value routes.

### N13 (P2). Stale k8s manifests
`deploy/k8s/*-svc.yaml` still set `listen_addr: 0.0.0.0:8443`, which the binary no longer reads. The proxy now defaults to `0.0.0.0:443` (a privileged port in a non-root container), while the Services target 8443. The demo script works around this with pod port-forwards. Also, `registry-configmap.yaml` allow-lists the originator (`client`, `api-gateway`) on every hop, which masks N1. Update the manifests to `proxy_addr`/`admin_addr`, enable mTLS, and allow-list only real immediate callers once N1 is fixed.

### N14 (P2). Benchmarks miss the real OBO cost
Add benchmarks for `exchange_token` (one RS256 sign per hop, typically far more expensive than verify) and a proxy round trip with and without an exchange, and update `docs/design/performance.md` accordingly.

### N15 (P2). Repository hygiene before going public
`.superpowers/` (34 tracked files of agent briefs, reports and review verdicts, including a local path under `/home/gundu/`) and `docs/superpowers/plans/` are committed. Remove them (or move them to a private branch) and add `.superpowers/` to `.gitignore`. The working copy also shows CRLF-only modifications again; add a `.gitattributes` (`* text=auto eol=lf`) to stop the churn.

## Suggested order of work

1. N4 + N1 together (RFC-correct nesting, then authorize the current actor). This is the change that makes multi-hop delegation and mTLS work together.
2. N2 + N6 (bind at issuance and re-bind at exchange).
3. N7 (split private signing keys from the public JWKS).
4. N3, N10, N9 (exchange checks, header stripping, body limits).
5. N5 (edge mint path with a verified user principal), then F11 (capability policy), which together are the agent story.
6. N8, N11 to N15.

## Appendix A: probe tests

Save as `tests/review2_probes.rs`. Mapping: r1 and r2 to N1, r3 to N2, r4 to N3, r5 to N4, r6 and r7 to N5, r8 to N6, r9 to N7. All nine pass at `5d1edff`. No new dependencies are needed (`rsa`, `rand` and `serde_json` are already in `Cargo.toml`).

```rust
//! Probes from docs/reviews/0002-follow-up-review.md.
//! Each asserts CURRENT behavior at 5d1edff; a passing test means the issue is real.
//! Invert each one into a regression test as its finding is fixed.
use zero_trust::*;

const API: &str = "spiffe://chakra.internal/ns/api-gateway/sa/api-gateway";
const ORD: &str = "spiffe://chakra.internal/ns/orders/sa/orders-svc";
const INV: &str = "spiffe://chakra.internal/ns/inventory/sa/inventory-svc";
const OTHER: &str = "spiffe://chakra.internal/ns/payments/sa/payments-svc";

/// inventory allows ONLY orders-svc as a caller (the immediate hop).
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

fn id(s: &str) -> SpiffeId { s.parse().unwrap() }

fn hop1_and_exchange(issuer: &LocalIssuer) -> String {
    // api-gateway -> orders: token aud=orders, sub=api-gateway
    let t1 = issuer.issue_jwt_svid("api-gateway", ORD, "api-secret").unwrap().token;
    // orders' gateway exchanges it for the next hop (inventory), appending itself
    let (t2, _) = exchange_token(&t1, INV, issuer, issuer.verifier(), &id(ORD), 300, now_unix_secs()).unwrap();
    t2
}

#[test]
fn r1_allow_list_checks_originator_not_immediate_caller() {
    // api-gateway -> orders -> inventory. Inventory allows orders (its real caller), not api-gateway.
    let issuer = LocalIssuer::generate(reg_strict(), 300).unwrap();
    let t2 = hop1_and_exchange(&issuer);
    let dest = id(INV);
    let r = ValidationRequest { destination: &dest, source_principal: None, obo_token: Some(&t2), caller_chain: None };
    let d = validate(issuer.registry(), issuer.verifier(), &r, now_unix_secs());
    eprintln!("legit 2-hop chain to inventory: {d:?}");
    assert_eq!(d, Decision::Deny(DenyReason::CallerNotInAllowList));
}

#[test]
fn r2_exchanged_token_fails_impersonation_check_under_mtls() {
    // Same chain, but now orders presents its own mTLS cert to inventory.
    let issuer = LocalIssuer::generate(reg_strict(), 300).unwrap();
    let t2 = hop1_and_exchange(&issuer);
    let dest = id(INV);
    let orders = id(ORD);
    let r = ValidationRequest { destination: &dest, source_principal: Some(&orders), obo_token: Some(&t2), caller_chain: None };
    let d = validate(issuer.registry(), issuer.verifier(), &r, now_unix_secs());
    eprintln!("2-hop chain with mTLS peer = orders: {d:?}");
    assert_eq!(d, Decision::Deny(DenyReason::OboTokenSubjectMismatch));
}

#[test]
fn r3_cert_binding_is_copied_so_bound_tokens_die_after_one_hop() {
    let issuer = LocalIssuer::generate(reg_strict(), 300).unwrap();
    let t1 = issuer.issue_jwt_svid_with_cert_binding("api-gateway", ORD, "API-CERT-THUMB", "api-secret").unwrap().token;
    let (t2, _) = exchange_token(&t1, INV, &issuer, issuer.verifier(), &id(ORD), 300, now_unix_secs()).unwrap();
    let claims = issuer.verifier().verify_signature(&t2).unwrap();
    assert_eq!(claims.cnf.unwrap().x5t_s256, "API-CERT-THUMB", "re-minted token still bound to the ORIGINAL caller's cert");
    let dest = id(INV);
    let r = ValidationRequest { destination: &dest, source_principal: None, obo_token: Some(&t2), caller_chain: None };
    // orders presents its own cert at the next hop -> mismatch
    let d = validate_with_cert_binding(issuer.registry(), issuer.verifier(), &r, Some("ORDERS-CERT-THUMB"), now_unix_secs());
    assert_eq!(d, Decision::Deny(DenyReason::CertificateBindingMismatch));
}

#[test]
fn r4_exchange_does_not_check_inbound_audience() {
    // A token addressed to payments can be exchanged at the ORDERS gateway for an inventory token.
    let issuer = LocalIssuer::generate(reg_strict(), 300).unwrap();
    let t_payments = issuer.issue_jwt_svid("api-gateway", OTHER, "api-secret").unwrap().token;
    let res = exchange_token(&t_payments, INV, &issuer, issuer.verifier(), &id(ORD), 300, now_unix_secs());
    assert!(res.is_ok(), "token not addressed to this gateway was exchanged anyway");
}

#[test]
fn r5_act_nesting_is_reversed_vs_rfc8693() {
    // RFC 8693 4.1: outermost `act` is the CURRENT actor; nested `act` = prior actors.
    let issuer = LocalIssuer::generate(reg_strict(), 300).unwrap();
    let t2 = hop1_and_exchange(&issuer);
    let (t3, _) = exchange_token(&t2, OTHER, &issuer, issuer.verifier(), &id(INV), 300, now_unix_secs()).unwrap();
    let c = issuer.verifier().verify_signature(&t3).unwrap();
    let outer = c.act.as_ref().unwrap();
    eprintln!("outermost act.sub = {} (most recent hop is inventory)", outer.sub);
    assert_eq!(outer.sub, ORD, "outermost act is the OLDEST hop, not the current actor");
}

#[test]
fn r6_no_issuance_path_sets_a_user_principal() {
    let issuer = LocalIssuer::generate(reg_strict(), 300).unwrap();
    let t2 = hop1_and_exchange(&issuer);
    assert!(issuer.verifier().verify_signature(&t2).unwrap().user.is_none());
}

#[test]
fn r7_human_user_principal_is_rejected_unless_spiffe_id() {
    let mut rng = rand::rngs::OsRng;
    use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
    let k = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let signer = JwtSigner::from_rsa_pem(k.to_pkcs1_pem(LineEnding::LF).unwrap().as_bytes()).unwrap();
    let verifier = JwtVerifier::from_rsa_pem(rsa::RsaPublicKey::from(&k).to_pkcs1_pem(LineEnding::LF).unwrap().as_bytes()).unwrap();
    let now = now_unix_secs();
    let claims = OboClaims { sub: ORD.into(), aud: vec![INV.into()], user: Some("user@corp.internal".into()), act: None,
        iat: now, exp: now + 300, nbf: None, jti: None, cnf: None, iss: None };
    let t = signer.sign(&claims).unwrap();
    let reg = reg_strict();
    let dest = id(INV);
    let r = ValidationRequest { destination: &dest, source_principal: None, obo_token: Some(&t), caller_chain: None };
    assert_eq!(validate(&reg, &verifier, &r, now), Decision::Deny(DenyReason::InvalidUserPrincipal));
}

#[test]
fn r8_unbound_token_still_replays_without_any_cert() {
    // The only HTTP issuance route mints tokens with no `cnf`, so binding never applies in practice.
    let issuer = LocalIssuer::generate(reg_strict(), 300).unwrap();
    let t = issuer.issue_jwt_svid("orders-svc", INV, "orders-secret").unwrap().token;
    let dest = id(INV);
    let r = ValidationRequest { destination: &dest, source_principal: None, obo_token: Some(&t), caller_chain: None };
    assert_eq!(validate_with_cert_binding(issuer.registry(), issuer.verifier(), &r, None, now_unix_secs()), Decision::Allow);
}

#[test]
fn r9_jwks_file_still_holds_every_private_key() {
    use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding};
    let mut rng = rand::rngs::OsRng;
    let k1 = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap().to_pkcs1_pem(LineEnding::LF).unwrap().to_string();
    let k2 = rsa::RsaPrivateKey::new(&mut rng, 2048).unwrap().to_pkcs1_pem(LineEnding::LF).unwrap().to_string();
    let jwks = serde_json::json!({"keys":[{"kid":"key-1","private_key_pem":k1},{"kid":"key-2","private_key_pem":k2}]}).to_string();
    let gw1 = LocalIssuer::with_jwks(reg_strict(), &jwks, "key-1".into(), 300).unwrap();
    let forged = LocalIssuer::with_jwks(reg_strict(), &jwks, "key-2".into(), 300).unwrap();
    let t = forged.issue_jwt_svid("orders-svc", INV, "orders-secret").unwrap().token;
    assert!(gw1.verifier().verify_signature(&t).is_ok());
}
```
