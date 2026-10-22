# 0002: Delegation with certificate-bound tokens

**Status:** Proposed
**Date:** 2026-10-22
**Relates to:** review 0002 findings N2 and N6; `docs/design/0001-tls-mtls-termination.md`;
`docs/demo-obo-chain.md` (known limitation 4)

## Problem

With mTLS on, token issuance binds each token to the caller's client certificate
(`cnf.x5t#S256`, N6). Token exchange then refuses any inbound token whose `cnf`
does not match the certificate the exchanging caller presented (N2). Together,
these rules break delegation at the first hop.

1. A client gets a token bound to its certificate.
2. The client calls api-gateway. The gateway's TLS peer is the client, which is
   correct.
3. api-gateway wants to exchange the token for orders-svc. It must present the
   client's certificate, and it doesn't hold the client's private key. The
   exchange fails with `CertificateBindingMismatch`.

The demo works around this by issuing its first token unbound
(`require_cert_binding: false` on api-gateway). That leaves a gap: the first
token is a bearer token. Every hop still checks the mTLS peer against the current
actor (N1), so the protection lost is the binding of the first token itself.

## Goal

A chain that starts with a bound token should delegate through several gateways.
At each hop:

- the token stays bound to a certificate that the caller in that hop can prove
  it holds;
- the originator stays in `sub`/`user`, so the chain's audit trail is kept;
- the audience and depth checks (N3) still apply.

No code path should exchange a token for a caller that can't show the key the
token is bound to.

## Options

### A. Proxy-side re-mint from the verified peer (recommended)

When a gateway's proxy receives a request whose token is bound to the TLS peer's
certificate, the gateway has already verified that peer (cert binding passed in
`validate`). It can therefore mint the next-hop token itself. The minted token is
addressed to the route's `workload_id` and bound to this gateway's own
certificate. The gateway appends itself to `act`, and the originator stays in
`sub`.

- The gateway holds its own key, so the binding is valid.
- The route table already names the next audience (`workload_id`).
- It needs no new admin call, and no client-held key.

Costs:
- Re-minting happens on the request path, so the signing cost of ~0.4–1.4 ms per
  hop (N14 benchmarks) is added there.
- A gateway may only re-mint for routes marked as delegating, so it's an explicit
  per-route opt-in (`delegate: true`).
- Minted tokens need a TTL limit, and the minting gateway needs audit logging.

### B. Holder-driven exchange

The client exchanges its own token for each next hop, presenting its own
certificate. The gateway then forwards the newly minted token.

This keeps the holder rule: only the cert the token is bound to can exchange it.
But the client has to know the whole chain in advance, and it has to be able to
reach every hop's audience. That's a change to every caller, and it pushes route
decisions onto clients. Rejected for now.

### C. Bind to the chain, not to the first hop

Keep the originator's `cnf` and add each hop's certificate thumbprint to its
`act` entry (`act.x5t#S256`). A verifier then checks the whole chain: each actor
in `act` presented its own certificate on the hop it made.

This is the strongest option, and the proof is end to end. But it changes the
token format and the validator, and it needs `act` thumbprints to be signed and
verified at every hop. Keep it as a later phase on top of A.

### D. Accept the unbound first token, and rely on N1 and short TTLs

This is the demo's current setting. The first token is a bearer token. A stolen
copy can be replayed only from a connection whose TLS peer is the current actor
(N1), and only until its short TTL expires.

It's simple, and it works now, but it's a weaker guarantee than the N6 design
intends. Accept it only for the demo, and mark it as such in the config.

## Recommendation

Build **A** now, and treat **C** as a follow-up.

A keeps the N2 rule intact: the token is bound to the key of the gateway that
holds it. It also fits the route table (`workload_id` is the next audience) and
doesn't need a new client protocol. D stays as the demo's explicit setting. It
should not be a silent default.

## Design for A

### Config

Add an opt-in flag to `Route`:

```yaml
routes:
  - path_pattern: /demo
    workload_id: spiffe://chakra.internal/ns/backend-a/sa/backend-a
    upstream_addr: http://backend-a.zero-trust-demo.svc.cluster.local:8080
    delegate: true               # re-mint the token for workload_id, bound to this gateway's cert
    delegated_ttl_seconds: 60    # TTL of the minted token; capped by token_ttl_seconds
```

`delegate` defaults to `false`, so existing routes behave as they do now.

### Request path

1. The proxy validates the inbound token as it does today (cert binding, N1
   peer check, audience, depth, issuer, JTI).
2. If the matched route has `delegate: true`, the gateway calls the same
   exchange logic as `POST /v1/token-exchange`. The inputs are:
   - `inbound_token`: the validated token;
   - `next_audience`: the route's `workload_id`;
   - `caller_cert_thumbprint`: this gateway's own certificate thumbprint.
     The gateway knows its own certificate, so it never needs the client's.
3. The minted token replaces `X-SPIFFE-OBO-Token` on the upstream request. The
   inbound token is removed, as N10 already requires.
4. Audit: the span records `obo.delegated_from` (the inbound `iss`/`jti`) and
   `obo.delegated_jti` (the minted `jti`).

### Binding rules

- The minted token's `cnf` is this gateway's certificate thumbprint.
- The inbound token's `cnf`, if present, must match the peer certificate that the
  proxy verified. A mismatch is refused before re-minting.
- The route's `delegate` flag is the only way a gateway re-mints. There's no
  implicit delegation.

### Failure handling

- Re-minting fails with a logged reason, and the request is refused with `403`
  and `deny_reason: delegation_failed`.
- A route with `delegate: true` and no mTLS on the proxy is a configuration error,
  so startup refuses it. Without mTLS there's no peer certificate to bind to.

### Scope

- `src/bin/zt-gateway.rs`: proxy path, after the decision and before forwarding.
- `src/config.rs`: `Route.delegate`, `Route.delegated_ttl_seconds`, and the
  startup check.
- `src/token_exchange.rs`: no change. The existing function already takes the
  caller's certificate thumbprint.
- Demo: `require_cert_binding` goes back to the default on api-gateway. Its
  `/demo` route sets `delegate: true`.

## Acceptance criteria

1. The demo chain passes with a bound first token: client token bound to the
   client's certificate, api-gateway re-mints with its own certificate, and each
   hop returns 200 from its backend.
2. Replaying the minted token from another certificate fails with
   `obo_token_subject_mismatch` or `certificate_binding_mismatch`.
3. Review 0002's N2 probe, `n2_exchange_binds_the_new_token_to_the_exchanging_hops_cert`,
   still passes. The re-minted token's `cnf` is the minting gateway's thumbprint.
4. A route without `delegate: true` behaves as before (no re-minting).
5. `tests/admin_tls.rs`-style integration test: a bound token presented over the
   proxy with the matching cert is re-minted, and the new token verifies at the
   next gateway.

## Open questions

- **Token size.** Each hop adds an `act` entry. The chain is bounded by
  `max_obo_chain_depth`, so the cost is small, but it should be measured.
- **Caching.** A gateway could cache minted tokens per (inbound `jti`,
  audience) to avoid re-signing on every request. Caching adds state to the
  request path, so it should wait for measurements.
- **Replay of the inbound token.** Once re-minted, the inbound token has no further
  use at that gateway. Whether the gateway should also record the inbound `jti`
  as consumed is open.

## Out of scope

- Option C (chain-level binding) is a later phase.
- Live JWKS distribution. The demo uses static keys, which are covered in the
  README's "Signing keys and JWKS" section.
