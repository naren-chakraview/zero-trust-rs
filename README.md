# zero-trust / zt-gateway

A zero-trust identity and On-Behalf-Of (OBO) delegation gateway, based on the
[chakraview-zero-trust-blueprint](https://github.com/naren-chakraview/chakraview-zero-trust-blueprint)
reference architecture (SPIFFE/SPIRE identity, Istio mTLS, OPA/Gatekeeper
policy). This crate ports the blueprint's SPIFFE identity + OBO delegation
*logic* — the part expressed as Rego policies in the original — into a
standalone Rust service any application, in any language, can sit behind or
call. It does not attempt to reproduce the blueprint's Kubernetes/Istio/OPA
infrastructure.

It ships as two things:

- **A library** (`zero_trust`) — SPIFFE ID parsing, the workload registry,
  JWT SVID issuance/verification, OBO header construction, and the
  `validate()` decision engine. Usable on its own if you're embedding Rust.
- **A binary**, `zt-gateway` — an HTTP service built on the library that
  issues tokens, exposes a decision API, and reverse-proxies traffic to a
  backend application, denying anything that fails validation before the
  backend ever sees it.

## v0.1 limitation: no TLS yet

This version serves **plain HTTP, not mTLS**. Caller identity comes entirely
from a presented `X-SPIFFE-OBO-Token` (a signed, short-lived JWT) — there is
no independently-verified transport identity backing it. That means a leaked
token is usable by anyone until it expires (default 5 minutes), where the
blueprint's real mTLS layer would prevent that by binding identity to the
TLS channel itself. TLS/mTLS termination is planned as a v0.2 addition; the
validation engine (`obo::validate`) already has a `source_principal` slot
ready for a verified transport identity to plug into once that lands.

Workload identity issuance is also **local to this process** in v0.1 (see
`IdentityProvider`/`LocalIssuer` in `src/identity.rs`) rather than backed by
a real SPIRE server — but that's a trait boundary specifically so a
SPIRE-backed provider can be swapped in later without touching the
validation logic or the HTTP layer.

## Running it

```powershell
# From the repo root, using the fixture registry + example config:
cargo run --bin zt-gateway -- examples/gateway.config.yaml
```

By default this listens on `127.0.0.1:8443` and forwards allowed requests to
`http://127.0.0.1:8080` (see `examples/gateway.config.yaml` — point
`upstream_addr` at whatever backend app you're fronting).

### Try it with curl

```powershell
# 1. Ask for a token as orders-svc, scoped to call inventory-svc
#    (see tests/fixtures/registry.yaml for the bootstrap tokens / allow-lists)
curl -s -X POST http://127.0.0.1:8443/v1/svid/jwt `
  -H "content-type: application/json" `
  -d '{"workload_name":"orders-svc","audience":"spiffe://chakra.internal/ns/inventory/sa/inventory-svc","bootstrap_token":"orders-dev-secret"}'

# 2. Call the proxy without a token -> 403, upstream never sees it
curl -i http://127.0.0.1:8443/anything

# 3. Call the proxy with the issued token -> 200, forwarded to upstream_addr
curl -i http://127.0.0.1:8443/anything -H "X-SPIFFE-OBO-Token: <token from step 1>"

# Ask "would this be allowed?" directly, without going through the proxy path
curl -s -X POST http://127.0.0.1:8443/v1/authorize `
  -H "content-type: application/json" `
  -d '{"destination":"spiffe://chakra.internal/ns/inventory/sa/inventory-svc","obo_token":"<token>"}'
```

## HTTP surface

| Endpoint | Purpose |
|---|---|
| `POST /v1/svid/jwt` | Issue a JWT SVID: `{workload_name, audience, bootstrap_token}` -> `{token, expires_at}`. |
| `POST /v1/authorize` | Ask "is this allowed?" directly (ext_authz-style): `{destination, obo_token?, caller_chain?}` -> `{allow, deny_reason}`. |
| `ANY /*` | The reverse proxy. Requires `X-SPIFFE-OBO-Token`; forwards to `upstream_addr` on allow, `403` with `{deny_reason}` on deny. |

## Build & test

```powershell
cargo build
cargo test
```

## License

Licensed under either of

- Apache License, Version 2.0 (LICENSE-APACHE)
- MIT license (LICENSE-MIT)

at your option.
