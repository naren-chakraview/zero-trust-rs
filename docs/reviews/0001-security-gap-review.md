# Review 0001: Security and Completeness Gap Review

**Date:** 2026-10-15
**Reviewed at:** commit `46cd5f5` ("Deploy the full ecosystem to a local kind cluster: OTEL traces + real SPIRE")
**Scope:** `src/**`, `deploy/k8s/**`, `scripts/demo-obo-chain.sh`, README, `docs/design/0001-tls-mtls-termination.md`
**Baseline:** `cargo test` passes all 68 existing tests (55 lib, 12 bin, 1 integration).
**Reference:** the claims made for this gateway in the companion article "Zero Trust for the Workloads You Don't Control" and the chakraview-zero-trust-blueprint.

## How to use this document

Each finding has an ID, a severity, the code location, evidence, a recommended fix and acceptance criteria. Appendix A has probe tests that reproduce findings F1 to F4, F8 and F9 against the current code. Each probe asserts the **current, vulnerable** behavior, so it passes today. When a finding is fixed, invert its probe into a regression test that asserts the safe behavior.

Severity:
- **P0:** undermines a core security property the project claims.
- **P1:** robustness, availability or fail-safe weakness on a security component.
- **P2:** hygiene, docs or completeness.

## Summary

The codebase is well structured. `obo::validate` is a total function with a named reason for every deny, RS256 is pinned, X.509 issuance uses CSRs so private keys never leave the workload, and issuance refuses any identity other than the one that authenticated. The trust root is decoupled from issuance, and there are real-socket mTLS tests that include the impersonation case. Keep all of that.

The main gap: today the gateway is an mTLS plus signed-caller allow-list gateway, not an On-Behalf-Of delegation gateway. Only the immediate caller (`sub`) is signed. The delegation chain and the user principal travel in unsigned headers, so depth limits, user attribution and "every hop attested" do not hold. There is also no shared trust anchor between gateways, and no capability/action policy layer.

| ID | Sev | Title |
|---|---|---|
| F1 | P0 | Caller chain is an unsigned header; depth limit bypassable |
| F2 | P0 | User principal is an unsigned, unvalidated header (also recorded as audit fact) |
| F3 | P0 | Gateway does not re-mint or extend delegation on egress |
| F4 | P0 | No shared trust anchor; each gateway signs with its own key |
| F5 | P0 | Bearer tokens not bound to the TLS channel; impersonation check only effective in `required` |
| F6 | P1 | Unbounded request body, full buffering, no timeouts or connection limits |
| F7 | P1 | Issuance and authorize endpoints share the proxy listener; no rate limiting; non-constant-time secret compare |
| F8 | P1 | CA copies all CSR SANs into the leaf (violates X.509-SVID "exactly one URI SAN") |
| F9 | P1 | Issued leaves lack basicConstraints, keyUsage and EKU |
| F10 | P1 | `client_auth: required` bootstrapping deadlock for first X.509 SVID |
| F11 | P1 | Authorization granularity is the whole workload (no method, path or action); no capability policy |
| F12 | P1 | No trace-context propagation; incomplete OBO span attributes |
| F13 | P2 | SPIRE deployed but not wired; bootstrap secrets in plaintext ConfigMap |
| F14 | P2 | Only the same-pod (sidecar) topology is supported |
| F15 | P2 | Missing JWT claim checks: `iss`, `nbf`, `jti`; no `kid` / key rotation |
| F16 | P2 | k8s deployment runs plain HTTP; demo chain is synthetic |
| F17 | P2 | No benchmarks for the OBO cost |
| F18 | P2 | Stale metadata and docs |

---

## P0 findings

### F1. Caller chain is an unsigned header; depth limit bypassable
**Where:** `src/obo.rs:108` (`CallerChain::parse(request.caller_chain.unwrap_or(""))`), `src/bin/zt-gateway.rs:512`.
**Problem:** `max_obo_chain_depth` is enforced against `X-SPIFFE-Caller-Chain`, which any caller controls. Omitting the header yields depth 0. Entries are also never validated as SPIFFE IDs.
**Evidence:** probes `f1_depth_limit_bypassed_by_omitting_chain_header` and `f1_chain_entries_not_validated`.
**Fix:** move the delegation chain into the signed token. Recommended shape: RFC 8693 token exchange semantics with nested `act` claims (`{"sub": <user or originator>, "act": {"sub": <hop n>, "act": {"sub": <hop n-1>}}}`). Compute depth from the signed `act` nesting. If the header is kept for observability, treat it as derived output, never as input to a decision, or require it to match the signed chain exactly.
**Acceptance:** a request whose signed chain exceeds `max_obo_chain_depth` is denied regardless of headers. A tampered or omitted header cannot change the decision. Chain entries that are not valid SPIFFE IDs are rejected.

### F2. User principal is an unsigned, unvalidated header
**Where:** `src/bin/zt-gateway.rs:513`, `:528` (`span.record("obo.user_principal", ...)`).
**Problem:** `X-SPIFFE-User-Principal` is never validated, yet it is written into traces and logs as the originating user. Any caller can attribute actions to any user, which defeats the audit-trail property.
**Fix:** carry the originating principal as a signed claim (the top-level `sub` in the RFC 8693 model, or a dedicated claim). Record only verified values in telemetry. If an unverified header is present, either reject it or record it under a clearly named attribute such as `obo.user_principal_unverified`.
**Acceptance:** a forged user header has no effect on decisions and never appears as `obo.user_principal`.

### F3. No re-minting or extension of delegation on egress
**Where:** `src/bin/zt-gateway.rs:576` (`forward_to_upstream`) forwards inbound headers unchanged; `headers::build_outbound_headers` exists but is not used by the gateway.
**Problem:** there is no hop-by-hop chain. The inbound token is passed to the backend as-is, and nothing appends the current hop or scopes a new token to the next audience.
**Fix:** provide a token-exchange endpoint (or a client library) that takes the inbound token plus the next audience and returns a new short-lived token with this hop appended to `act`. The inbound OBO token should not be forwarded to the backend unless the backend needs it; at minimum, strip or replace the delegation headers before forwarding.
**Acceptance:** a real three-hop test (gateway A → backend A calls out → gateway B → backend B → gateway C) yields a token at C whose signed chain is exactly [originator, A, B], with no hand-written headers.

### F4. No shared trust anchor between gateways
**Where:** `src/identity.rs` (`LocalIssuer` derives its verifier from its own private key); `deploy/k8s/*-svc.yaml` sets no `signing_key_path`, so each pod generates an ephemeral key; `scripts/demo-obo-chain.sh` fetches each token from the **destination's** gateway.
**Problem:** a token is only verifiable by the gateway that minted it, so the destination mints the caller's credential from a shared secret. That is not workload identity, and it breaks multi-hop delegation.
**Fix:** separate issuance from verification. Verification should load a trust bundle (JWKS with `kid`, or a SPIRE JWT bundle via the existing `IdentityProvider` seam) and support multiple active keys for rotation. Issuance should be a single authority, ideally SPIRE.
**Acceptance:** a token issued by authority X is accepted by every gateway trusting X's bundle; keys can rotate without downtime; no gateway needs another workload's secret.

### F5. Tokens not bound to the TLS channel
**Where:** `src/obo.rs:138` (subject-match check runs only when `source_principal` is `Some`).
**Problem:** with `client_auth: optional`, an attacker holding a stolen token presents no client cert, and the token is accepted. The impersonation check exists but only bites in `required`. Tokens are replayable for their full TTL.
**Evidence:** probe `f5_stolen_token_accepted_without_client_cert`.
**Fix:** certificate-bound tokens (RFC 8705 style `cnf: {"x5t#S256": <thumbprint>}`), checked against the presented client cert. Alternatively, require a client cert whenever an OBO token is presented, and document `optional` as a migration-only mode with this exact caveat. Consider a `jti` replay cache for high-value audiences.
**Acceptance:** a valid token presented without the bound cert, or with a different cert, is denied.

## P1 findings

### F6. Unbounded body, full buffering, no timeouts
**Where:** `src/bin/zt-gateway.rs:579` (`to_bytes(body, usize::MAX)`), `:170` (`reqwest::Client::new()` with no timeout), the accept loop in `serve()` (no handshake timeout, no connection cap), response fully buffered.
**Fix:** a configurable max body size (`DefaultBodyLimit` or explicit), stream request and response bodies, set connect, read and overall timeouts on the upstream client, a TLS handshake timeout, and a concurrency limit (`tower::limit`). Fail closed with 413/504.
**Acceptance:** tests for oversized body (413), slow upstream (504), and stalled handshake (connection dropped).

### F7. Issuance on the proxy listener; weak secret handling
**Where:** `src/bin/zt-gateway.rs:190-192`; `src/registry.rs:142` (`expected == credential`).
**Problem:** `/v1/svid/*` and `/v1/authorize` are reachable on the same port as protected traffic, with no rate limiting, and the bootstrap token comparison is not constant-time.
**Fix:** a separate admin listener (configurable, default loopback), rate limiting on issuance, constant-time comparison (`subtle::ConstantTimeEq`), and ideally hashed bootstrap secrets in the registry.

### F8. CA copies all CSR SANs
**Where:** `src/ca.rs:124` (checks only the first URI SAN), `:145` (`signed_by` signs the CSR params as-is).
**Evidence:** probe `f8_ca_signs_extra_sans`. A CSR with [URI orders-svc, DNS evil.example.com, URI inventory-svc] authenticated as orders-svc gets all three in the signed leaf.
**Fix:** build the leaf `CertificateParams` from scratch: exactly one URI SAN (the registry's SPIFFE ID), no DNS/IP SANs, and the subject taken from policy, not the CSR. Use the CSR only for its public key and proof of possession.
**Acceptance:** CSRs with more than one SAN, or any non-URI SAN, are rejected (or the extras are dropped); the issued leaf has exactly one URI SAN.
**Note:** a CSR requesting `basicConstraints CA:TRUE` is already rejected (`Unsupported extension requested in CSR`). Keep that as a regression test (probe `f8_ca_rejects_ca_true_csr`).

### F9. Leaves lack constraints
**Where:** `src/ca.rs` leaf issuance.
**Evidence:** probe `f9_leaf_has_no_constraints` shows basicConstraints, keyUsage and EKU all absent.
**Fix:** per the X.509-SVID spec, set basicConstraints `cA=false`, keyUsage `digitalSignature` (plus keyEncipherment / keyAgreement as appropriate), and EKU `clientAuth` (and `serverAuth` if leaves serve TLS).

### F10. `required` mode bootstrapping deadlock
**Problem:** with `client_auth: required`, a workload without a cert cannot complete the handshake to reach `/v1/svid/x509` and get its first cert.
**Fix:** follows from F7 (a separate issuance listener with its own TLS posture), or delegate X.509 issuance to SPIRE.

### F11. Authorization granularity and capability policy
**Problem:** the decision is caller SPIFFE ID → workload allow-list, with no method, path, action, tool or scope. This cannot express the capability policy (agent may call tool X with scope Y on behalf of user Z) that the companion article and blueprint ADR-0002 describe.
**Fix:** extend `ValidationRequest` with method, path and (optionally) an action/scope, and add a policy hook: either an OPA client (call OPA's REST API or embed via `regorus`) or a typed capability table in the registry. Model agents as workloads with a capability set, delegated on behalf of a user principal (depends on F1, F2).
**Acceptance:** a test where the same agent identity is allowed for one action and denied for another, for the same user.

### F12. Tracing gaps
**Where:** no `TextMapPropagator` is configured and none is injected on upstream calls; `obo.caller_principal` is set only on allow (`src/bin/zt-gateway.rs:533`).
**Fix:** set the W3C TraceContext propagator, extract on inbound and inject on outbound, and record verified caller attributes on deny as well (denies are the interesting audit events). Record only verified values (see F2).
**Acceptance:** the three-hop chain from F3 appears as a single trace in Jaeger, with signed-chain attributes on each span.

## P2 findings

- **F13. SPIRE not wired.** SPIRE is deployed in kind but the gateway uses `LocalIssuer`/`LocalCa` with plaintext bootstrap tokens in `deploy/k8s/registry-configmap.yaml`. Implement a SPIRE Workload API `IdentityProvider` (the `spiffe` crate) and fetch X.509/JWT SVIDs and bundles from the agent socket.
- **F14. Topology.** One `protected_workload` / `upstream_addr` per gateway, so the dedicated-gateway topology (one gateway fronting many backends) is unsupported. Add a route table (host or path → workload ID + upstream).
- **F15. JWT claims.** No `iss`, `nbf` or `jti` checks, and no `kid` in the header. `src/jwt.rs:62` disables the library's checks by design; keep that design but add explicit `iss`/`nbf` checks in `obo::validate` with their own `DenyReason`s, plus clock-skew leeway.
- **F16. Demo fidelity.** The k8s gateways run without `tls:`. `scripts/demo-obo-chain.sh` drives each hop from curl with a hand-written chain header (`orders-svc`, not even a SPIFFE ID), and the backends are `http-echo`, so no real service-to-service delegation occurs. Rework once F3 and F4 land.
- **F17. No benchmarks.** Add `criterion` benches for `validate()` (token verify + checks) and a proxy round-trip with and without OBO, so the latency cost of delegation can be stated with numbers.
- **F18. Stale metadata.** `Cargo.toml:7` still has `repository = "https://github.com/REPLACE_ME/zero-trust-rs"`. `docs/design/0001-tls-mtls-termination.md:3` still says implementation has not started.

## Suggested order of work

1. F4 (trust anchor / JWKS), because F1 to F3 need verifiable tokens across gateways.
2. F1 + F2 + F3 together (signed `act` chain, token exchange, header handling).
3. F5 (cert-bound tokens).
4. F6, F7, F10 (hardening and listener split).
5. F8, F9 (CA leaf hygiene).
6. F11 (capability policy and agent model), F12 (tracing).
7. F13 to F18.

## Appendix A: probe tests

Save as `tests/gap_probes.rs`. These assert **current** behavior and pass at `46cd5f5`; invert each one as its finding is fixed. `f8_ca_rejects_ca_true_csr` needs a fixture generated once:

```bash
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout /dev/null \
  -subj "/CN=x" \
  -addext "subjectAltName=URI:spiffe://chakra.internal/ns/orders/sa/orders-svc" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign" \
  -out tests/fixtures/ca_true.csr
```

```rust
//! Gap probes from docs/reviews/0001-security-gap-review.md.
//! Each test asserts CURRENT behavior at 46cd5f5; invert as findings are fixed.
use rcgen::{CertificateParams, KeyPair, SanType};
use zero_trust::*;

const INV: &str = "spiffe://chakra.internal/ns/inventory/sa/inventory-svc";
const ORD: &str = "spiffe://chakra.internal/ns/orders/sa/orders-svc";

fn reg() -> Registry {
    Registry::from_yaml_str(&format!(
        r#"
trust_domain: chakra.internal
workloads:
  - name: inventory-svc
    spiffe_id: {INV}
    max_obo_chain_depth: 3
    allowed_callers: [{ORD}]
  - name: orders-svc
    spiffe_id: {ORD}
    allowed_callers: []
    bootstrap_token: orders-secret
"#
    ))
    .unwrap()
}

fn token(issuer: &LocalIssuer) -> String {
    issuer.issue_jwt_svid("orders-svc", INV, "orders-secret").unwrap().token
}

fn req<'a>(dest: &'a SpiffeId, t: &'a str, chain: Option<&'a str>) -> ValidationRequest<'a> {
    ValidationRequest { destination: dest, source_principal: None, obo_token: Some(t), caller_chain: chain }
}

#[test]
fn f1_depth_limit_bypassed_by_omitting_chain_header() {
    let issuer = LocalIssuer::generate(reg(), 300).unwrap();
    let t = token(&issuer);
    let dest: SpiffeId = INV.parse().unwrap();
    let now = now_unix_secs();
    assert_eq!(
        validate(issuer.registry(), issuer.verifier(), &req(&dest, &t, Some("a,b,c,d")), now),
        Decision::Deny(DenyReason::OboChainDepthExceeded)
    );
    // Same token, header omitted: allowed.
    assert_eq!(validate(issuer.registry(), issuer.verifier(), &req(&dest, &t, None), now), Decision::Allow);
}

#[test]
fn f1_chain_entries_not_validated() {
    let issuer = LocalIssuer::generate(reg(), 300).unwrap();
    let t = token(&issuer);
    let dest: SpiffeId = INV.parse().unwrap();
    assert_eq!(
        validate(issuer.registry(), issuer.verifier(), &req(&dest, &t, Some("not-an-id,junk")), now_unix_secs()),
        Decision::Allow
    );
}

#[test]
fn f2_token_has_no_user_or_chain_claims() {
    let issuer = LocalIssuer::generate(reg(), 300).unwrap();
    let claims = issuer.verifier().verify_signature(&token(&issuer)).unwrap();
    let dbg = format!("{claims:?}");
    assert!(!dbg.contains("act") && !dbg.contains("user"), "only sub/aud/iat/exp are signed");
}

#[test]
fn f5_stolen_token_accepted_without_client_cert() {
    // client_auth: optional -> attacker presents no cert -> source_principal None.
    let issuer = LocalIssuer::generate(reg(), 300).unwrap();
    let t = token(&issuer);
    let dest: SpiffeId = INV.parse().unwrap();
    for _ in 0..3 {
        assert_eq!(validate(issuer.registry(), issuer.verifier(), &req(&dest, &t, None), now_unix_secs()), Decision::Allow);
    }
}

fn csr(params: CertificateParams) -> String {
    let kp = KeyPair::generate().unwrap();
    params.serialize_request(&kp).unwrap().pem().unwrap()
}

fn leaf(pem: &str) -> Vec<u8> {
    rustls_pemfile::certs(&mut pem.as_bytes()).next().unwrap().unwrap().to_vec()
}

#[test]
fn f8_ca_signs_extra_sans() {
    let ca = LocalCa::generate(reg(), 3600).unwrap();
    let mut p = CertificateParams::new(vec!["evil.example.com".to_string()]).unwrap();
    p.subject_alt_names.insert(0, SanType::URI(ORD.try_into().unwrap()));
    p.subject_alt_names.push(SanType::URI(INV.try_into().unwrap()));
    let signed = ca.sign_csr("orders-svc", &csr(p), "orders-secret").unwrap();
    let der = leaf(&signed.cert_pem);
    let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
    let san = cert.subject_alternative_name().unwrap().unwrap();
    // Current: [URI orders-svc, DNS evil.example.com, URI inventory-svc]
    assert_eq!(san.value.general_names.len(), 3);
}

#[test]
fn f8_ca_rejects_ca_true_csr() {
    // Existing GOOD behavior: keep as a regression test.
    let ca = LocalCa::generate(reg(), 3600).unwrap();
    let pem = std::fs::read_to_string("tests/fixtures/ca_true.csr").unwrap();
    assert!(ca.sign_csr("orders-svc", &pem, "orders-secret").is_err());
}

#[test]
fn f9_leaf_has_no_constraints() {
    let ca = LocalCa::generate(reg(), 3600).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.subject_alt_names = vec![SanType::URI(ORD.try_into().unwrap())];
    let signed = ca.sign_csr("orders-svc", &csr(p), "orders-secret").unwrap();
    let der = leaf(&signed.cert_pem);
    let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
    assert!(cert.basic_constraints().unwrap().is_none());
    assert!(cert.key_usage().unwrap().is_none());
    assert!(cert.extended_key_usage().unwrap().is_none());
}
```

`rustls-pemfile` and `x509-parser` are already regular dependencies, so no `Cargo.toml` change is needed.
