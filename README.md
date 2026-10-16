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
  JWT SVID and X.509 SVID issuance/verification, OBO header construction,
  TLS/mTLS setup, and the `validate()` decision engine. Usable on its own if
  you're embedding Rust.
- **A binary**, `zt-gateway` — a TLS-capable HTTP service built on the
  library that issues tokens/certs, exposes a decision API, and
  reverse-proxies traffic to a backend application, denying anything that
  fails validation before the backend ever sees it.

## TLS and mTLS

TLS is opt-in via config (see `docs/design/0001-tls-mtls-termination.md` for
the full design). Three postures, in the order a deployment would typically
move through them:

- **No `tls:` block at all** — plain HTTP. Caller identity comes entirely
  from a presented `X-SPIFFE-OBO-Token`; a leaked token is usable by anyone
  until it expires (default 5 minutes).
- **`tls:` present, `client_auth: none`** (or omitted) — connections are
  encrypted, but caller identity is still bearer-token-only. Closes the
  "token travels in plaintext" gap without requiring any client to change.
- **`tls.client_auth: optional` or `required`** — the gateway also verifies
  a presented client certificate's SPIFFE ID (from its SAN URI) against a
  trusted CA, and feeds it into `obo::validate` as an independently-verified
  `source_principal`. This activates two checks that are otherwise dormant:
  a direct call with no OBO token but an allow-listed client cert, and
  rejecting an OBO token whose `sub` doesn't match the TLS-verified caller
  (impersonation). `optional` lets bearer-token-only and mTLS-capable
  callers coexist during migration; `required` fails the TLS handshake
  itself for anyone without a valid client cert — parity with the
  blueprint's `PeerAuthentication: STRICT`.

The CA a gateway **trusts** for verifying client certs is independent of
whether it can **issue** them itself — see `ca.cert_path`/`ca.key_path`
below. A gateway can verify against a CA it doesn't hold the key for.

Workload identity issuance (both JWT SVIDs and X.509 SVIDs) is **local to
this process** in v0.1 (see `IdentityProvider`/`LocalIssuer` in
`src/identity.rs` and `CertificateAuthority`/`LocalCa` in `src/ca.rs`)
rather than backed by a real SPIRE server — but both are trait boundaries
specifically so a SPIRE-backed provider can be swapped in later without
touching the validation logic or the HTTP layer.

### Config reference

```yaml
tls:
  cert_path: /path/to/server-cert.pem   # omit both to generate an ephemeral dev cert
  key_path: /path/to/server-key.pem
  client_auth: optional                 # none | optional | required

ca:
  cert_path: /path/to/ca-cert.pem       # trust root for verifying client certs
  key_path: /path/to/ca-key.pem         # optional — set only if THIS gateway issues X.509 SVIDs
  ttl_seconds: 3600                     # X.509 SVID TTL when this gateway is the issuer
```

Omit `ca.key_path` to run verify-only (trusting a CA this gateway doesn't
control) — `POST /v1/svid/x509` returns `501` in that mode. Omit `ca:`
entirely, with `client_auth` still enabled, to get an ephemeral dev CA
(same spirit as the ephemeral server cert / ephemeral JWT key fallbacks —
not for anything a real client should trust long-term).

Try `examples/gateway.mtls.config.yaml` to run with TLS + optional mTLS
enabled (ephemeral server + CA certs, generated fresh on every startup).
Because the ephemeral CA's key never touches disk, there's no cert on disk
for a `curl --cert`/`--cacert` walkthrough to point at — for a real,
runnable end-to-end mTLS flow (issuing a CSR-signed client cert, presenting
it over a real TLS handshake, and seeing the impersonation check fire),
see the `mtls_*` tests in `src/bin/zt-gateway.rs`, which exercise exactly
that path against a real socket.

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
| `POST /v1/svid/x509` | Issue an X.509 SVID from a CSR: `{workload_name, csr_pem, bootstrap_token}` -> `{cert_pem, expires_at}`. `501` if this gateway holds no CA signing key (verify-only mode). |
| `POST /v1/authorize` | Ask "is this allowed?" directly (ext_authz-style): `{destination, obo_token?, caller_chain?}` -> `{allow, deny_reason}`. |
| `ANY /*` | The reverse proxy. Requires `X-SPIFFE-OBO-Token` (or, with mTLS, an allow-listed client cert); forwards to `upstream_addr` on allow, `403` with `{deny_reason}` on deny. |

## Build & test

```powershell
cargo build
cargo test
```

## Running the full ecosystem in Kubernetes (local `kind` cluster)

`deploy/k8s/` deploys `zt-gateway` as a real multi-service ecosystem, next
to the identity and observability infrastructure it's meant to sit
alongside — `api-gateway` / `orders-svc` / `inventory-svc` (matching
`tests/fixtures/registry.yaml`), each fronted by its own `zt-gateway`
instance (blueprint Topology A: backend bound to `127.0.0.1` only inside
the pod), a real OTEL Collector + Jaeger receiving live traces, and a real
SPIRE server + agent issuing real SVIDs (infrastructure only — `zt-gateway`
still uses its own `LocalIssuer`/`LocalCa`, not SPIRE, in this version).

Requires `docker`, `kubectl`, and `kind` (see `scripts/install-k8s-tools.sh`
if you need them). From a shell with those on `PATH`:

```bash
scripts/create-kind-cluster.sh       # once, creates the "zero-trust" cluster
scripts/build-and-load-image.sh      # build the zt-gateway image, load into kind
scripts/deploy-all.sh                # api-gateway, orders-svc, inventory-svc
scripts/deploy-spire.sh              # SPIRE server + agent + a debug client pod
scripts/register-spire-entries.sh    # register the node + debug-client entries
kubectl apply -f deploy/k8s/jaeger.yaml -f deploy/k8s/otel-collector.yaml

scripts/port-forward-all.sh          # gateways on :18443-18445, Jaeger UI on :16686
scripts/verify-topology.sh           # allow-list / chain-depth checks against all 3
scripts/demo-obo-chain.sh            # a live 3-hop OBO chain, then check Jaeger
```

Jaeger's UI (after port-forwarding) is at `http://127.0.0.1:16686` —
spans from `zt-gateway` carry `obo.caller_principal`, `obo.chain`,
`obo.token_ttl_seconds`, `allow`, and `deny_reason`, matching the
blueprint's ADR-0008 field naming.

To prove SPIRE is really issuing identities: `kubectl logs -n
zero-trust-demo spire-debug-client` after `register-spire-entries.sh` shows
a real signed X.509 SVID for `spiffe://chakra.internal/ns/zero-trust-demo/sa/spire-debug-client`.

## Three-Hop Delegation Demo

With F3 (RFC 8693 token exchange, `POST /v1/token-exchange`) landed,
delegation across multiple gateways is backed by a signed `act` chain
rather than hand-written `X-SPIFFE-Caller-Chain` headers — each hop
exchanges the token it received for a new one scoped to the next hop,
with itself appended to the chain inside the signed JWT.

### Setup
1. Deploy three gateways (`gw-a`, `gw-b`, `gw-c`) sharing one JWKS trust
   anchor (see `docs/design/0001-tls-mtls-termination.md` and F4's
   JWKS support for cross-gateway verification).
2. Run the demo script:
   ```bash
   ./scripts/demo-three-hop-delegation.sh
   ```
   (Not yet checked in — build it on top of `scripts/demo-obo-chain.sh`,
   replacing the header-based hops with real `POST /v1/token-exchange`
   calls per the sequence below.)

### What happens
1. **Originator → Gateway A**: the originator calls `gw-a` with a signed
   OBO token asserting its own identity (chain depth 0).
2. **Gateway A → Gateway B**: `gw-a` calls `POST /v1/token-exchange` on
   itself with `subject_token` = the inbound token and `audience` =
   `gw-b`'s SPIFFE ID, getting back a new token with `gw-a` appended to
   the `act` chain, then forwards it to `gw-b`.
3. **Gateway B → Gateway C**: `gw-b` repeats the exchange, scoping a new
   token to `gw-c`'s audience; the chain is now `[originator, gw-a, gw-b]`.
4. **Gateway C → Backend**: `gw-c` forwards the final token (or exchanges
   again if the backend sits behind its own `zt-gateway`, extending the
   chain to include `gw-c`).

Each exchange is validated against `max_obo_chain_depth` and the
`allowed_callers` list in the workload registry (`registry.rs`), so a
chain that's too deep or an unauthorized hop is denied with a
`deny_reason` before it reaches the next gateway.

### Verify the trace
Open Jaeger at `http://localhost:16686` (see `scripts/port-forward-all.sh`)
and search for a trace containing the originator's ID. You should see:
- A single trace spanning all three gateways (W3C TraceContext
  propagation, F12).
- Each gateway's span carrying verified OBO attributes
  (`obo.caller_principal`, `obo.chain`, `allow`).
- No hand-written chain headers — delegation is entirely signed inside
  the exchanged JWTs.

### Troubleshooting
- Ensure all three gateways load the same JWKS (F4) so each can verify
  tokens minted by the others.
- Check that token TTLs (`token_ttl_seconds` / `token_exchange_ttl_secs`)
  are long enough to cover the full three-hop round trip.
- A `403` with `deny_reason` at any hop means the chain depth or
  caller allow-list was violated — check `tests/fixtures/registry.yaml`
  for the actual limits in the example config.

## License

Licensed under either of

- Apache License, Version 2.0 (LICENSE-APACHE)
- MIT license (LICENSE-MIT)

at your option.
