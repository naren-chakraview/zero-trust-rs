# Design: TLS / mTLS Termination for zt-gateway

**Status**: Implementation complete as of 2026-10-15 (commits `4e6b5ad`
through `a26451f`). Both phases (server TLS and mTLS + X.509 issuance)
landed together, as planned below, plus the follow-on security-gap fixes
tracked alongside this work:
- JWKS-backed multi-gateway verification (F4, `4e6b5ad`)
- X.509 leaf hygiene per spec — exactly one URI SAN, basicConstraints/
  keyUsage/EKU (F8, F9, `8d5ce72`)
- RFC 8693 signed delegation chains and token exchange (F1, F2, F3,
  `1739383`, `2cc8adc`, `e91c5f7`)
- Separate admin/proxy listeners, rate limiting, constant-time token
  compare (F7, F10, `0b3a66d`)
- Request/response body limits, timeouts, concurrency limits (F6,
  `6eea37a`)
- RFC 8705 certificate-bound tokens, binding validated on use (F5,
  `910826b`)
- W3C TraceContext propagation, verified OBO claims recorded in spans
  (F12, `a26451f`)

See `docs/reviews/0001-security-gap-review.md` for the full security audit
and findings reference.

**Supersedes**: the "v0.1 limitation" section of `README.md`.

**Decisions locked in from the previous revision** (see "Decisions" at the
end for the full record):
- Phase 1 (server TLS) and Phase 2 (mTLS + X.509 issuance) ship together,
  in one implementation pass — not staged across separate sessions. The
  document keeps the two-phase *structure* below because it's still the
  clearest way to explain what each piece is for, but there is no gap
  between them operationally.
- X.509 SVID TTL defaults to 3600s (1h, matching ADR-0002) and is
  configurable (`ca.ttl_seconds`).
- The CA trust root is **decoupled from this gateway's own issuance
  capability** — a gateway can be configured to trust and verify client
  certs issued by a CA it does not itself hold the signing key for. See
  "Trust root vs. issuance capability" under Phase 2.

---

## Context

v0.1 of `zt-gateway` serves plain HTTP. Caller identity rests entirely on
whatever JWT SVID is presented in `X-SPIFFE-OBO-Token` — there's no
independent, transport-level proof of who's on the other end of the
connection. Two concrete consequences, both already called out in the
README and in `obo.rs`'s doc comments:

1. The bearer token itself travels in plaintext and can be intercepted.
2. `obo::validate`'s "no impersonation" check
   (`ValidationRequest::source_principal`, `DenyReason::OboTokenSubjectMismatch`)
   is *dormant* — it exists in the decision engine, ported faithfully from
   the blueprint's `validate-obo-chain.rego`, but nothing in `zt-gateway`
   ever populates `source_principal`, so that branch never runs in
   production. It's currently only exercised by a unit test
   (`obo::tests::obo_subject_mismatch_is_denied_when_source_principal_disagrees`)
   calling `validate()` directly.

This spec closes both gaps, in two phases.

## Goals

- Encrypt the connection between callers and `zt-gateway` (TLS termination).
- Let `zt-gateway` verify a caller's identity from its TLS client
  certificate, independent of whatever bearer token it also presents
  (mTLS), and feed that verified identity into the already-built
  `source_principal` slot in `obo::validate` — no changes to `obo.rs`
  itself required.
- Give workloads a way to obtain an X.509 SVID (a client certificate whose
  SAN contains their SPIFFE ID) from `zt-gateway`, mirroring how
  `LocalIssuer` already issues JWT SVIDs — via a CSR, so the private key
  never leaves the workload.
- Preserve backward compatibility: TLS is configuration-gated, and every
  existing `tower::oneshot` router test keeps working unchanged, because
  TLS wraps the *transport* the `Router` runs behind — it isn't part of the
  `Router`/handler logic at all.

## Non-goals (explicitly deferred)

- **Certificate rotation.** A real deployment needs workloads to
  automatically renew X.509 SVIDs before the (short, ~1h, per ADR-0002)
  TTL expires. That's client-side background-renewal logic, arguably its
  own crate — out of scope here, same reasoning as why the v0.1 spec
  deferred a SPIRE Workload API client.
- **Revocation / CRLs / OCSP.** v0.1's JWT SVIDs get their short-lived-token
  security property "for free" (a 5-minute TTL is its own revocation
  mechanism); X.509 SVIDs get the same treatment here (short TTL, no CRL
  infrastructure) rather than building revocation checking.
- **Federation** (trust between multiple `zt-gateway` instances / multiple
  trust domains) — single trust domain, single CA, matching the blueprint's
  own single-`chakra.internal` scope.
- **Real SPIRE integration.** Unrelated to this spec — still tracked
  separately behind the `IdentityProvider` trait boundary.

---

## Phase 1 — Server-side TLS termination

### What changes

`zt-gateway`'s listener stops being a bare `tokio::net::TcpListener` fed
straight into `axum::serve`. Instead:

1. Load (or generate) a server certificate + private key.
2. Build a `rustls::ServerConfig` from it.
3. Accept raw TCP connections, wrap each one in TLS via `tokio_rustls::TlsAcceptor`,
   then hand the resulting stream to the same `Router` as before (via
   hyper's connection-serving APIs, not `axum::serve` directly — see
   "Library choice" below).

Everything from `build_router()` inward — routing, handlers, `obo::validate`,
the proxy forwarding logic — is completely unaware TLS exists. That's a
deliberate seam: it's why none of the 6 existing router tests need to
change for Phase 1.

### Library choice

Direct `tokio-rustls` + a hand-rolled accept loop, rather than the
`axum-server` convenience crate. Reasoning: Phase 2 needs per-connection
access to the verified client certificate (to extract the caller's SPIFFE
ID), which means owning the accept loop rather than delegating it to a
wrapper crate whose client-cert-verifier hooks may or may not expose what's
needed. Building the plain-TLS accept loop by hand in Phase 1 means Phase 2
extends the same code rather than replacing it.

New dependency: `rustls` + `tokio-rustls` (same major versions already seen
transitively in this workspace when `reqwest`'s `rustls-tls` feature was
briefly enabled during v0.1 development — `rustls 0.23.x`, `tokio-rustls
0.26.x` — so this is proven to build cleanly in this environment already).

### Config additions

```yaml
tls:
  cert_path: /path/to/server-cert.pem   # optional
  key_path: /path/to/server-key.pem     # optional
```

- **`tls:` block absent** → v0.1 behavior: plain HTTP, unchanged. This is
  the default and keeps every existing test and the README's curl
  walkthrough working without modification.
- **`tls:` present, `cert_path`/`key_path` given** → load and use them.
- **`tls:` present, `cert_path`/`key_path` omitted** → generate an
  ephemeral, self-signed server certificate at startup via `rcgen`, log a
  warning (mirrors `LocalIssuer::generate`'s existing "no signing key
  configured" warning). Fine for local dev/testing; not for anything a real
  client needs to trust without `-k`/`--insecure`.

`GatewayConfig` gains an `Option<TlsConfig>` field; `ConfigError` gains
variants for cert/key load failures.

### Testing

- Unit tests for the cert-loading/ephemeral-generation logic in isolation.
- One integration test that binds the real TLS listener on `127.0.0.1:0`
  (this is the first test in the project that *can't* use
  `tower::oneshot`, because TLS is genuinely part of the transport being
  tested) and connects with a `rustls` client, confirming the handshake
  succeeds and a request round-trips correctly.
- All 6 existing `tower::oneshot`-based router tests: unchanged, still pass,
  proving the TLS layer is additive rather than a rewrite.

---

## Phase 2 — mTLS + X.509 SVID issuance

### New component: `LocalCa`

A second capability alongside `LocalIssuer`, not a replacement. Where
`LocalIssuer` holds one RSA keypair used to sign short-lived JWT SVIDs,
`LocalCa` holds a **separate** self-signed root keypair/certificate used to
sign X.509 SVIDs (client certs). Keeping these separate is deliberate —
JWT bearer-token signing and TLS PKI root-of-trust are different blast
radii, and compromising one shouldn't automatically compromise the other.

```rust
pub trait CertificateAuthority {
    /// The CA's own self-signed root certificate (DER), for building the
    /// rustls client-cert trust store.
    fn root_cert_der(&self) -> &[u8];

    /// Validates the CSR's embedded SPIFFE ID against the registry entry
    /// for `requester_workload_name` (rejecting a CSR that claims a
    /// different identity than the one the bootstrap token authenticated),
    /// then signs it. Returns the signed leaf certificate (DER).
    fn sign_csr(
        &self,
        requester_workload_name: &str,
        csr_der: &[u8],
        credential: &str,
    ) -> Result<SignedCert, CaError>;
}

pub struct LocalCa { /* registry handle, root keypair/cert, TTL */ }
impl CertificateAuthority for LocalCa { ... }
```

Same shape as `IdentityProvider`/`LocalIssuer`: a trait boundary now, one
local implementation, so a real CA/SPIRE-backed implementation can replace
it later without touching `obo.rs` or the HTTP layer. Kept as a *separate*
trait from `IdentityProvider` rather than folded into it, since a future
SPIRE-backed `IdentityProvider` for JWT SVIDs wouldn't necessarily also be
the thing issuing X.509 SVIDs — SPIRE's own server plays that role
directly, bypassing this trait entirely once that integration happens.

`LocalCa` is only ever *constructed* when this gateway actually holds CA
signing key material (`ca.key_path` configured, or the ephemeral-dev-CA
fallback) — see "Trust root vs. issuance capability" below. When this
gateway is only configured to *trust* an externally-issued CA, no `LocalCa`
exists; `AppState.ca` is `None`, and there's nothing for the
`CertificateAuthority` trait to do.

Certificate generation/signing: `rcgen` (pure Rust, well-established for
exactly this "small internal CA" use case, supports SAN URI entries —
which is precisely the `spiffe://...` SAN format ADR-0002 specifies). Exact
CSR-parsing/signing API surface (`rcgen`'s CSR-handling types have shifted
across versions) needs to be pinned against whatever's current on crates.io
at implementation time rather than assumed here.

### Issuance flow: `POST /v1/svid/x509`

Mirrors `POST /v1/svid/jwt`'s shape and auth model (same per-workload
`bootstrap_token` from the registry — no new credential type introduced),
but the request/response payload is different because of the CSR
requirement:

**Request**: `{ "workload_name": "orders-svc", "bootstrap_token": "...", "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\n..." }`

The workload:
1. Generates its own keypair locally (never sent to the gateway).
2. Builds a CSR embedding its SPIFFE ID as a SAN URI
   (`spiffe://chakra.internal/ns/orders/sa/orders-svc`).
3. POSTs the CSR (PEM) + its bootstrap token.

**Server-side validation** (`LocalCa::sign_csr`):
0. If `AppState.ca` is `None` (verify-only mode — this gateway trusts an
   external CA but doesn't hold its key), the handler short-circuits before
   ever calling `sign_csr`: `501 Not Implemented`, `"this gateway does not
   hold CA signing key material; obtain X.509 SVIDs from your
   organization's CA"`.
1. Look up `workload_name` in the registry (same as JWT issuance);
   `UnknownWorkload` if missing.
2. Check `bootstrap_token` against the registry entry; `InvalidBootstrapToken`
   if it doesn't match.
3. Parse the CSR; reject malformed input (`CaError::MalformedCsr`).
4. **Critically**: the CSR's SAN URI must exactly equal
   `requester.spiffe_id` — a workload authenticating as `orders-svc` cannot
   request a cert for any other SPIFFE ID, even a valid one elsewhere in
   the registry (`CaError::SanMismatch`). This is the X.509-issuance
   equivalent of the JWT flow's `sub` always being set from the looked-up
   registry entry rather than trusted from client input.
5. Sign the CSR with the CA key, TTL from `ca.ttl_seconds` (defaulting to
   3600s per ADR-0002's 1-hour X.509 SVID TTL — deliberately longer than
   the 5-minute JWT SVID TTL, matching the blueprint).

**Response**: `{ "cert_pem": "...", "expires_at": <unix> }` — just the
signed certificate. No private key in the response, by construction: the
gateway never had it.

**Explicit residual risk, flagged for visibility rather than silently
accepted**: the `bootstrap_token` shared-secret model (same one v0.1
already uses for JWT issuance) is weaker than real SPIRE node attestation
regardless of CSR-based key custody — a leaked bootstrap token still lets
an attacker request a cert for that workload's identity. CSR-based
issuance fixes *key custody* (the private key never transits the network
or touches the gateway), it does not fix *attestation strength*. Real
node/workload attestation remains explicitly out of scope until a SPIRE
integration replaces `LocalIssuer`/`LocalCa` entirely.

### Trust root vs. issuance capability

Two distinct questions, deliberately decoupled in the config:

1. **Which CA cert do we trust when verifying a presented client cert?**
   (needed whenever `client_auth != none`)
2. **Do we ourselves hold that CA's private key, i.e. can this gateway
   issue X.509 SVIDs via `POST /v1/svid/x509`?** (optional — a gateway can
   verify against a CA it doesn't control)

Both are governed by one `ca:` config block:

```yaml
ca:
  cert_path: /path/to/ca-cert.pem   # trust root; always used for client-cert verification
  key_path: /path/to/ca-key.pem     # optional — only set this if THIS gateway issues certs
  ttl_seconds: 3600                 # only meaningful when key_path is set
```

- **`cert_path` set, `key_path` set**: this gateway is a self-issuing CA.
  It trusts (and verifies client certs against) its own root, and
  `POST /v1/svid/x509` is live — `LocalCa` loads both and can sign CSRs.
  This is the common single-gateway case, and matches the previous
  revision's default assumption.
- **`cert_path` set, `key_path` absent**: **verify-only mode** — the
  scenario you asked to support explicitly. The gateway trusts client
  certs signed by a CA it does not control (an external/organizational CA,
  or a CA shared across multiple `zt-gateway` instances that only one of
  them — or some entirely separate service — actually issues from).
  `POST /v1/svid/x509` returns `501 Not Implemented` with a clear message
  (`"this gateway does not hold CA signing key material; obtain X.509
  SVIDs from your organization's CA"`) rather than silently failing or
  crashing at startup. No `LocalCa`/`CertificateAuthority` instance is
  constructed at all in this mode — `AppState.ca` is `None`.
- **`cert_path` absent entirely, but `client_auth != none`**: dev
  convenience fallback — generate an ephemeral CA keypair at startup (same
  spirit as the ephemeral server cert and ephemeral JWT signing key
  fallbacks already in this project), log a warning, and use it as both
  trust root and issuer. Not for anything a real client needs to trust
  long-term.

`AppState` gains `ca: Option<Arc<dyn CertificateAuthority + Send + Sync>>`
(only `Some` in the self-issuing and ephemeral-dev cases) plus a
`trust_root_der: Vec<u8>` used to build the rustls client verifier's root
store — resolved from `ca.cert_path` if set, or from the ephemeral CA's own
cert otherwise. The trust root is always available whenever `client_auth !=
none`; the issuer is only sometimes available. Handlers/verification code
only ever need `trust_root_der`; only the `/v1/svid/x509` handler touches
`ca`.

### Client certificate verification

`rustls::ServerConfig` gains a client-cert verifier
(`rustls::server::WebPkiClientVerifier`) built from a root store containing
`trust_root_der` (see above — resolved the same way regardless of whether
this gateway can also issue).

```yaml
tls:
  cert_path: /path/to/server-cert.pem
  key_path: /path/to/server-key.pem
  client_auth: optional        # none | optional | required
```

- **`none`** (default when `tls:` is present but `client_auth` is
  omitted): Phase 1 behavior — TLS encrypts the connection, no client cert
  requested. `source_principal` stays `None`, same as v0.1. The `ca:` block
  is irrelevant/unused in this mode.
- **`optional`**: client cert requested but not required; present callers
  get a verified `source_principal`, callers without one fall back to
  bearer-token-only (v0.1 behavior). This is the migration mode — existing
  bearer-token-only clients keep working while mTLS-capable ones get the
  stronger guarantee, side by side.
- **`required`**: TLS handshake itself fails for any connection without a
  valid client cert signed by the trusted CA — matches the blueprint's
  `PeerAuthentication: STRICT` posture. The natural end state once every
  caller has been migrated to X.509 SVIDs.

### Wiring the verified identity into `source_principal`

This is the one genuinely new piece of axum plumbing: getting data
extracted *during the TLS handshake* (the peer certificate) into a value a
request *handler* can read, since handlers only see the HTTP request, not
the raw connection.

The intended mechanism is axum's `Connected` trait +
`axum::extract::ConnectInfo<T>` extractor — the standard, documented axum
pattern for exposing per-connection metadata (this is the same mechanism
axum's own examples use for exposing a plain TCP peer address; extending
it to carry "verified SPIFFE ID from the client cert, if any" is a
natural fit, not a workaround). Concretely:

1. A small `PeerIdentity(Option<SpiffeId>)` type.
2. `impl Connected<&TlsStream<TcpStream>> for PeerIdentity` — pulled from
   the accepted connection's peer certificates (parse the leaf cert's SAN
   extension via `x509-parser`, look for a URI SAN starting with
   `spiffe://`, parse it with the existing `SpiffeId::from_str`; `None` if
   there's no client cert or its SAN isn't a SPIFFE URI).
3. Handlers (`proxy_handler`, `authorize`) extract
   `ConnectInfo(PeerIdentity(source_principal))` alongside the existing
   `State<AppState>` and pass `source_principal.as_ref()` into
   `ValidationRequest` — the *only* change inside `obo.rs`'s call sites;
   `obo::validate` itself is untouched, because it was already written to
   accept `Option<&SpiffeId>` in anticipation of exactly this.

Once this lands, two previously-dormant paths in `obo::validate` activate
in production for the first time:

- The **direct-call path** (no OBO token, `source_principal` in the
  allow-list) becomes reachable — a caller with only a valid client cert,
  no bearer token, can be allowed if it's directly allow-listed.
- The **impersonation check** (`DenyReason::OboTokenSubjectMismatch`)
  becomes reachable — an OBO token whose `sub` doesn't match the
  TLS-verified peer is now actually rejected, not just unit-tested.

Exact `Connected`/`ConnectInfo` trait shapes should be checked against the
axum 0.7 docs at implementation time (API surface for custom `Connected`
impls has evolved across axum versions) — the mechanism described above is
correct in spirit; treat method names as indicative, not final.

### New error types

- `TlsError` (Phase 1): cert/key load failures, rustls config build
  failures.
- `CaError` (Phase 2): `MalformedCsr`, `SanMismatch { requested, expected }`,
  `UnknownWorkload`, `InvalidBootstrapToken` (the latter two mirror
  `IdentityError`'s variants — worth a shared helper or a `From` bridge
  rather than duplicating the bootstrap-token-check logic between
  `LocalIssuer` and `LocalCa`; both end up doing the identical "look up by
  name, compare `bootstrap_token`" check against the same `Registry`).

### Testing

- Unit tests for `LocalCa::sign_csr`: valid CSR + correct token → signed
  cert whose SAN round-trips to the expected `SpiffeId`; SAN mismatch →
  `CaError::SanMismatch`; wrong bootstrap token → `InvalidBootstrapToken`;
  malformed CSR bytes → `MalformedCsr`.
- A real-listener integration test (extends Phase 1's) using a `rustls`
  client configured with a client certificate signed by the test `LocalCa`:
  - `client_auth: required`, no client cert presented → handshake itself
    fails (never reaches the HTTP layer).
  - `client_auth: optional`, valid client cert whose SPIFFE ID matches the
    OBO token's `sub` → allowed.
  - `client_auth: optional`, valid client cert whose SPIFFE ID does
    **not** match the OBO token's `sub` → `403` with
    `deny_reason: "obo_token_subject_mismatch"` — the test that finally
    proves the v0.1-built impersonation check works end-to-end, not just
    in a unit test calling `validate()` directly.

---

## Combined config schema (both phases)

Self-issuing gateway (this gateway both trusts and issues from its own CA):

```yaml
listen_addr: 127.0.0.1:8443
upstream_addr: http://127.0.0.1:8080
registry_path: registry.yaml
protected_workload: spiffe://chakra.internal/ns/inventory/sa/inventory-svc
signing_key_path: /path/to/jwt-signing-key.pem
token_ttl_seconds: 300

tls:
  cert_path: /path/to/server-cert.pem
  key_path: /path/to/server-key.pem
  client_auth: optional      # none | optional | required

ca:
  cert_path: /path/to/ca-cert.pem
  key_path: /path/to/ca-key.pem
  ttl_seconds: 3600
```

Verify-only gateway (trusts an externally-issued CA; `POST /v1/svid/x509`
disabled — just omit `ca.key_path`):

```yaml
tls:
  client_auth: required
ca:
  cert_path: /path/to/org-wide-ca-cert.pem
  # no key_path — this gateway never issues, only verifies
```

Omitting the entire `tls:` block preserves exact v0.1 behavior (`ca:` is
then irrelevant and can be omitted too).

## New dependencies

| Crate | Phase | Purpose |
|---|---|---|
| `rustls` | 1 | TLS protocol implementation |
| `tokio-rustls` | 1 | Async TLS accept/connect wrapping `tokio::net` streams |
| `rcgen` | 1 (ephemeral server cert), 2 (CA + CSR signing) | Certificate/CSR generation and signing |
| `x509-parser` | 2 | Parsing arbitrary presented client certs to extract the SAN URI |

## Operational rollout (once implemented)

Both phases land in the codebase together, but a deployment can still
adopt the *config* gradually:

1. Start with `tls:` present, `client_auth` omitted/`none` — connections
   are encrypted, nothing else changes. Immediately closes the "bearer
   token travels in plaintext" gap with zero coordination required across
   callers.
2. Move to `client_auth: optional` once a CA (self-issuing or externally
   trusted) is configured — lets bearer-token-only and mTLS-capable callers
   coexist while workloads migrate to requesting/obtaining X.509 SVIDs.
3. Move to `client_auth: required` once every expected caller has an X.509
   SVID — `zt-gateway` then reaches parity with the blueprint's
   `PeerAuthentication: STRICT` posture.

`tls:` omitted entirely at any point = exact v0.1 behavior, unchanged.

### Admin listener under `client_auth: required` (F10)

`client_auth` applies to the proxy listener only. The admin listener
(`admin_addr`, loopback-only) gets its own TLS acceptor, built from the same
server certificate with an *optional* client-certificate verifier. Admin
requests a client certificate but never requires one. A presented certificate
is verified against the CA and reaches the handlers, which need it for
cert-bound issuance (N6). Without a certificate the handshake still succeeds,
so a workload can fetch its first X.509 SVID over admin before it has one. The
binary refuses to start if `admin_addr` is not a loopback address.

An earlier version gave admin no verifier at all. That broke cert-bound
issuance, because the handlers never saw the certificate. The
`tests/admin_tls.rs` integration test covers both paths, and it fails if admin
stops seeing a presented certificate.

Bootstrap order for a strict deployment:

1. Workload calls `POST /v1/svid/x509` on admin with its bootstrap token and a
   CSR, over TLS but without a client certificate.
2. It then connects to the proxy with the issued X.509 SVID, which
   `client_auth: required` checks.

## Decisions

Resolved before implementation:

1. **Scope/sequencing**: Phase 1 and Phase 2 ship together in one
   implementation pass, not as separate sessions.
2. **X.509 SVID TTL**: defaults to 3600s (1h, matching ADR-0002),
   configurable via `ca.ttl_seconds`.
3. **CA trust model**: a gateway's client-cert trust root
   (`ca.cert_path`) is decoupled from its issuance capability
   (`ca.key_path`, optional) — see "Trust root vs. issuance capability."
   Supports both a single self-issuing gateway and a verify-only gateway
   trusting a CA it doesn't control (e.g. one shared across multiple
   `zt-gateway` instances, or an organizational CA external to this
   project entirely).
