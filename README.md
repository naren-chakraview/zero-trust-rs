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

### Listeners: admin and proxy

The binary serves two listeners, each with its own routes and TLS posture:

- **Proxy** (`proxy_addr`, default `0.0.0.0:443`). Serves protected traffic
  only. It uses the configured `tls.client_auth`, so with `required` every
  caller must present a valid client certificate.
- **Admin** (`admin_addr`, default `127.0.0.1:6443`). Serves issuance and
  delegation: `/v1/svid/jwt`, `/v1/svid/x509`, `/v1/svid/jwt-with-user`,
  `/v1/authorize`, and `/v1/token-exchange`. Admin requests a client
  certificate but never requires one. A presented certificate is verified
  against the CA and reaches the handlers, so cert-bound issuance works. A
  request without one still completes the handshake, and that is what lets a
  workload fetch its first X.509 SVID under `client_auth: required`. The binary
  refuses to start unless `admin_addr` is a loopback address.

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

The main settings. Every key is optional unless marked required. The
defaults are in `src/config.rs`.

```yaml
# Listeners (both required in practice)
proxy_addr: 0.0.0.0:443                 # protected traffic; default 0.0.0.0:443
admin_addr: 127.0.0.1:6443              # issuance + delegation; must be loopback
upstream_addr: http://127.0.0.1:8080    # required: the backend app to forward to
registry_path: registry.yaml            # required: workload registry (see tests/fixtures/)
protected_workload: spiffe://chakra.internal/ns/inventory/sa/inventory-svc   # required

token_ttl_seconds: 300
max_body_mb: 100                        # request and upstream-response cap (N9)

tls:
  cert_path: /path/to/server-cert.pem   # omit both to generate an ephemeral dev cert
  key_path: /path/to/server-key.pem
  client_auth: optional                 # none | optional | required; applies to the proxy only

ca:
  cert_path: /path/to/ca-cert.pem       # trust root for verifying client certs
  key_path: /path/to/ca-key.pem         # optional; set only if THIS gateway issues X.509 SVIDs
  ttl_seconds: 3600                     # X.509 SVID TTL when this gateway is the issuer

# Token signing (see "Signing keys and JWKS" below)
signing_key_path: /path/to/private-key.pem   # this gateway's own private key (PKCS#1 PEM)
jwks_path: /path/to/public-jwks.json         # public verification set; holds no private keys
active_kid: key-1                            # which kid in jwks_path this gateway signs with

# Delegation and claim checks
require_cert_binding: true            # refuse unbound issuance when a cert is missing; defaults to true with mTLS
trusted_issuers: [spiffe://chakra.internal/ns/zt-gateway/sa/api-gateway]  # the signing gateways' iss values; empty disables the check (N12, R6)
jti_cache_enabled: true               # refuse a replayed jti (N12)
jti_ttl_secs: 300
clock_skew_tolerance_secs: 60

# Human (edge-minted) principals (N5)
user_issuers: [auth.corp.internal]    # every entry must also appear in user_idps
user_idps:
  - issuer: auth.corp.internal
    jwks_path: /path/to/idp-public-jwks.json   # the IdP's public RS256 keys
    audience: zt-gateway                       # required aud on the IdP credential
    principal_claim: email                     # claim that becomes the user principal

# Capability policy (F11)
capability_policy_path: /path/to/capability-policy.yaml
capability_policy_reload_secs: 5      # how often the file is checked for changes
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

With the example config, the proxy listens on `127.0.0.1:8443` and the admin
listener on `127.0.0.1:6443`. Allowed proxy requests are forwarded to
`http://127.0.0.1:8080` (see `examples/gateway.config.yaml` — point
`upstream_addr` at whatever backend app you're fronting).

### Try it with curl

```powershell
# 1. Ask for a token as orders-svc, scoped to call inventory-svc
#    (see tests/fixtures/registry.yaml for the bootstrap tokens / allow-lists)
curl -s -X POST http://127.0.0.1:6443/v1/svid/jwt `
  -H "content-type: application/json" `
  -d '{"workload_name":"orders-svc","audience":"spiffe://chakra.internal/ns/inventory/sa/inventory-svc","bootstrap_token":"orders-dev-secret"}'

# 2. Call the proxy without a token -> 403, upstream never sees it (the proxy is on 8443)
curl -i http://127.0.0.1:8443/anything

# 3. Call the proxy with the issued token -> 200, forwarded to upstream_addr
curl -i http://127.0.0.1:8443/anything -H "X-SPIFFE-OBO-Token: <token from step 1>"

# Ask "would this be allowed?" directly, without going through the proxy path
curl -s -X POST http://127.0.0.1:6443/v1/authorize `
  -H "content-type: application/json" `
  -d '{"destination":"spiffe://chakra.internal/ns/inventory/sa/inventory-svc","obo_token":"<token>"}'
```

## HTTP surface

| Endpoint | Purpose |
|---|---|
| Listener | Endpoint | Purpose |
|---|---|---|
| admin | `POST /v1/svid/jwt` | Issue a JWT SVID: `{workload_name, audience, bootstrap_token}` -> `{token, expires_at}`. The token carries the caller's cert thumbprint (`cnf`) when the caller presented one. |
| admin | `POST /v1/svid/x509` | Issue an X.509 SVID from a CSR: `{workload_name, csr_pem, bootstrap_token}` -> `{cert_pem, expires_at}`. `501` if this gateway holds no CA signing key (verify-only mode). |
| admin | `POST /v1/svid/jwt-with-user` | Edge mint: `{user_credential, user_issuer}` -> a token whose `user` claim is the principal from a verified IdP credential. `401` if the credential doesn't verify. |
| admin | `POST /v1/token-exchange` | RFC 8693 exchange: re-mints the inbound token for a new audience with this gateway appended to `act`. |
| admin | `POST /v1/authorize` | Ask "is this allowed?" directly (ext_authz-style): `{destination, obo_token?, caller_chain?}` -> `{allow, deny_reason}`. |
| proxy | `ANY /*` | The reverse proxy. Requires `X-SPIFFE-OBO-Token` (or, with mTLS, an allow-listed client cert). Forwards to `upstream_addr` on allow. Returns `403` with `{deny_reason}` on an OBO deny, and `403` with `deny_reason: capability_denied` when the capability policy refuses. Gateway-owned headers carry verified identity to the backend: `X-ZT-Verified-Caller` (the mTLS peer or current actor), `X-ZT-Verified-User` (the signed user claim, if any), and `X-ZT-Verified-Chain`. Any `X-ZT-Verified-*` or delegation header the client sent is removed first (review 0003 R2). |

## Signing keys and JWKS

Each gateway signs with its own private key, loaded from `signing_key_path`.
Verifiers load only a **public** JWKS (`jwks_path`: `kty`, `kid`, `n`, `e`).
A JWKS file that carries `private_key_pem` fields instead of `n`/`e` fails to
parse. The library's `with_jwks` loader still reads that legacy format, but the
binary never uses it. Set `active_kid` to the `kid` this gateway
signs with. Startup checks that the private key matches its published public key.

The Kubernetes deployment uses static keys. `scripts/gen-gateway-keys.sh`
generates one RSA key per gateway (kept in the git-ignored `deploy/k8s/keys/`)
and the public set `public-jwks.json`. `scripts/deploy-all.sh` creates a Secret
per gateway holding only that gateway's private key, plus a `zt-jwks` ConfigMap
with the public set, and each gateway's `active_kid` matches its key. Rotating a
key means adding the new public key to the set, restarting every gateway, and
then switching `active_kid`. Remove the old key from the set only after no
issued token still depends on it. A live JWKS endpoint would remove the restart
(see the review 0002 options).

To generate a public set from one private key, use
`JsonWebKeySet::from_rsa_private_pem` (see `src/identity.rs`).

## Capability policy (F11)

`capability_policy_path` points at a YAML file that says which verified users
and workloads may call which method and path on the protected upstream:

```yaml
default: allow                     # allow | deny
default_allow_until: 1798761600    # unix seconds; required when default is allow
rules:
  - method: POST                   # optional; omit to match any method
    path: /tools/search            # `*` matches one segment, `**` matches many
    users: [alice@corp.internal]   # the verified user claim
    workloads: [spiffe://chakra.internal/ns/agents/sa/research-agent]   # the verified caller
  - path: /inventory/*
    workloads: [spiffe://chakra.internal/ns/orders/sa/orders-svc]   # a machine-only grant
```

- Every rule names at least one workload, since every request is made by a
  workload. A rule that names users without workloads is refused at load.
- A request that acts for a user is allowed only when one rule lists both that
  user and the acting workload. The user's grant doesn't extend to an agent that
  wasn't granted it, and the agent's grant doesn't extend to a user who wasn't
  granted it (review 0003 R1). Only the current actor is checked, not the whole
  chain.
- A request with no user is allowed only by a rule with no `users`. Those rules
  match only verified machine callers, so an agent acting for someone can't use
  them.
- Requests whose path contains dot-segments (`.`, `..`), empty segments, or
  percent-encoded dots or slashes get `400` before routing or authorization.
- A request no rule covers gets the default. `default: allow` stops allowing
  at `default_allow_until`, and startup refuses an allow default whose deadline
  is missing or already past. Moving to `default: deny` is therefore required
  eventually.
- The file is reloaded every `capability_policy_reload_secs`. A file that fails
  to parse or validate is logged, and the previous policy stays in effect.
- Unknown keys are rejected, so a typo cannot silently open access.
- With no `capability_policy_path`, capability checks are off and a warning is logged.

There are no explicit deny rules yet. A broad grant cannot be narrowed by a
later exception.

## Edge user principals (N5)

`POST /v1/svid/jwt-with-user` takes a credential from an IdP. The credential must
be an RS256 JWT with the configured `iss` and `aud`, unexpired, and signed by a
key in that IdP's public JWKS (`user_idps`). The principal comes from the
configured claim. The algorithm is pinned to RS256, so `alg: none` and
key-confusion tokens are refused. The IdP keys come from a file, not a live
fetch. Rotating them means updating the file and restarting the gateway.

Credentials are not single-use. A stolen credential works until its `exp`.

## Known gaps

These are open. The review trackers in `docs/reviews/` have the detail.

- **SPIRE token exchange.** Under `spire_socket_path`, the SPIRE provider can
  verify ES256 tokens but cannot sign, so `/v1/token-exchange` is unavailable.
  Delegation under SPIRE needs a separate token-signing key. See N8 in review 0002.
- **Admin accepts connections without a client certificate.** Admin is
  loopback-only, so any local process can reach it. Issuance endpoints check
  bootstrap tokens, and token exchange checks only the signature of the token
  it's given, not the identity of the caller (N3, partly open).
- **Client-bound tokens can't be exchanged by the gateway that receives them.**
  A token bound to a client's certificate (N6) can only be exchanged by a caller
  presenting that certificate (N2). The gateway receiving it doesn't hold that
  key. The demo therefore issues its first token unbound (`require_cert_binding:
  false` on api-gateway). This is an explicit demo setting, not a default.
  `docs/design/0002-delegation-with-bound-tokens.md` proposes proxy-side
  re-minting to remove it.

## Build & test

```powershell
cargo build
cargo test
```

`cargo test` runs the unit and integration tests, and the review 0002
regression tests in `tests/review2_regressions.rs`. One integration test needs
Docker: `tests/user_idp_integration.rs` starts a mock OIDC provider, logs in
through it, and calls the edge-mint endpoint of the real binary. It is
`#[ignore]` by default, so run it with:

```powershell
cargo test --test user_idp_integration -- --ignored
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
- Each gateway needs the same public JWKS (`jwks_path`) and its own
  `signing_key_path` and `active_kid` (see "Signing keys and JWKS"). Without
  these, the gateways cannot verify each other's tokens. The Kubernetes
  manifests do not set them yet (see "Known gaps").
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
