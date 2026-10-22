# 0002: Delegation with certificate-bound tokens

**Status:** Accepted with changes (review 0003, 2026-10-22). See "Changes from review 0003" below.
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
`validate`). It can therefore **rebind** the token: mint a copy addressed to
this workload (the route's `workload_id`) and bound to this gateway's own
certificate. The rebind changes who holds the token's key; it is not a
delegation, so `act` is left unchanged and the originator stays in `sub`.
Delegation to the next hop still happens through `POST /v1/token-exchange`,
exactly as today, now starting from a token this workload can prove it holds.

- The gateway holds its own key, so the binding is valid.
- The route table names the rebind audience (`workload_id`, this workload). It
  does **not** name the next hop; the backend chooses that when it calls
  exchange.
- It needs no new admin call for the rebind, and no client-held key.

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

## Changes from review 0003

Accepted, with four changes from review 0003. They are already folded into the
sections below; this list is the summary.

1. **Rebind, not next-hop delegation.** The route's `workload_id` is this
   workload's own identity (the destination being protected), not the next hop.
   The proxy rebinds the client-bound token to this workload's certificate,
   addressed to this workload. Delegation to the next hop stays in
   `POST /v1/token-exchange`, driven by the backend.
2. **No duplicate chain entry.** The rebind leaves `act` unchanged; only the
   exchange appends this workload. A chain never lists the same hop twice.
3. **Limits on the minted token.** `exp` is capped at the inbound token's `exp`
   (review 0003 R3), `iss` is the signing gateway (R6), and with the replay cache
   on the inbound `jti` is recorded as consumed.
4. **Exact acceptance tests.** Replay from another certificate fails with
   `certificate_binding_mismatch` specifically, and new criteria cover the chain
   length, the lifetime cap, replay, the demo with binding at its default, and the
   startup checks (including the loopback-upstream rule).

## Design for A

### Config

Add an opt-in flag to `Route`:

```yaml
routes:
  - path_pattern: /demo
    workload_id: spiffe://chakra.internal/ns/backend-a/sa/backend-a
    upstream_addr: http://backend-a.zero-trust-demo.svc.cluster.local:8080
    delegate: true               # rebind the token to this gateway's cert (aud = workload_id)
    delegated_ttl_seconds: 60    # TTL of the rebound token; capped by token_ttl_seconds and the inbound exp
```

`delegate` defaults to `false`, so existing routes behave as they do now.

### Request path

1. The proxy validates the inbound token as it does today (cert binding, N1
   peer check, audience, depth, issuer, JTI).
2. If the matched route has `delegate: true`, the gateway rebinds the token with
   a new `rebind_token` function (not `exchange_token`, which appends to `act`
   and copies `iss`). The rebound token has:
   - `sub`, `user` and `act`: copied unchanged (no new chain entry);
   - `aud`: the route's `workload_id`;
   - `cnf`: this gateway's own certificate thumbprint. The gateway knows its own
     certificate, so it never needs the client's;
   - `exp`: `min(inbound.exp, now + delegated_ttl_seconds)`, never later than the
     token it came from;
   - `iss`: this gateway (the signer), per review 0003 R6;
   - `jti`: new.
3. When the `jti` replay cache is on, the inbound `jti` is recorded as consumed
   at this gateway.
4. The rebound token replaces `X-SPIFFE-OBO-Token` on the upstream request. The
   inbound token is removed, as N10 already requires.
5. The backend delegates onward as today: it calls this gateway's
   `POST /v1/token-exchange` with the rebound token, presenting the workload
   certificate, and gets a token for the next audience with this workload
   appended to `act`.
6. Audit: the span records `obo.rebound_from` (the inbound `iss`/`jti`) and
   `obo.rebound_jti` (the minted `jti`).

Because the rebound token's current actor is still the previous hop while its
`cnf` names this workload, it cannot be used at a proxy: the peer that matches
the current actor never holds the bound certificate. Its only use is exchange
at this workload's admin listener, which is the intent.

### Binding rules

- The rebound token's `cnf` is this gateway's certificate thumbprint.
- `delegate: true` requires the route's `upstream_addr` to be loopback (the
  sidecar topology). The rebound token is only useful to a process holding this
  workload's certificate; a remote upstream with its own identity could not
  exchange it. Startup refuses a delegating route to a non-loopback upstream.
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
- `src/token_exchange.rs`: add `rebind_token` (shares the verification and
  binding checks with `exchange_token_with_cert_binding`, but leaves `act`
  unchanged and sets `iss` to the signer).
- Demo: `require_cert_binding` goes back to the default on api-gateway. Its
  `/demo` route sets `delegate: true`.

## Acceptance criteria

1. The demo chain passes with a bound first token: client token bound to the
   client's certificate, api-gateway re-mints with its own certificate, and each
   hop returns 200 from its backend.
2. Replaying the rebound token at a proxy from any other certificate fails with
   `certificate_binding_mismatch` (the binding check runs first).
3. Review 0002's N2 probe, `n2_exchange_binds_the_new_token_to_the_exchanging_hops_cert`,
   still passes. The rebound token's `cnf` is the minting gateway's thumbprint.
4. A route without `delegate: true` behaves as before (no re-minting).
5. `tests/admin_tls.rs`-style integration test: a bound token presented over the
   proxy with the matching cert is rebound, exchanged by the backend, and the
   exchanged token verifies at the next gateway.
6. The demo's three hops pass with `require_cert_binding` back at its default on
   api-gateway.
7. The rebind adds no chain entry: after rebind and one exchange, the chain is
   `[originator, this workload]`, not `[originator, this workload, this workload]`.
8. The rebound token's `exp` is never later than the inbound token's `exp`, and its
   `iss` names the minting gateway.
9. With the replay cache on, presenting the inbound token a second time at the same
   gateway after a rebind fails with `token_replayed`.
10. Startup refuses `delegate: true` on a route whose `upstream_addr` is not
    loopback, and on a proxy without mTLS.

## Open questions

- **Token size.** Each hop adds an `act` entry. The chain is bounded by
  `max_obo_chain_depth`, so the cost is small, but it should be measured.
- **Caching.** A gateway could cache minted tokens per (inbound `jti`,
  audience) to avoid re-signing on every request. Caching adds state to the
  request path, so it should wait for measurements.
- **Replay of the inbound token.** Resolved: when the replay cache is on, the
  inbound `jti` is recorded as consumed at rebind (request path step 3).
- **Marking rebound tokens.** Optionally add a type claim (for example
  `"zt_typ": "rebind"`) so `validate` can name the reason when one reaches a
  proxy, instead of relying on the binding mismatch.

## Out of scope

- Option C (chain-level binding) is a later phase.
- Live JWKS distribution. The demo uses static keys, which are covered in the
  README's "Signing keys and JWKS" section.
