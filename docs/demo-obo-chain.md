# Demo: a real three-hop OBO delegation chain (Task 7 / F16)

`scripts/demo-obo-chain.sh` drives the already-deployed `api-gateway` →
`orders-svc` → `inventory-svc` trio through a **real** three-hop RFC 8693
token-exchange chain — it calls `POST /v1/token-exchange` between every
hop, and never writes a chain header by hand. This replaces an earlier
version of the script that only ever simulated a chain (one independent
token minted per hop, and in one case a hand-forged
`X-SPIFFE-Caller-Chain` header), without ever exercising the real
`/v1/token-exchange` endpoint or a signed `act` chain.

## The flow

```
client --[token_0, aud=gw-a]--> Gateway A (api-gateway)
                                   |
                                   | POST /v1/token-exchange
                                   | subject_token=token_0, audience=gw-b
                                   v
                                token_1 (act: [gw-a])
                                   |
client --[token_1]-------------> Gateway B (orders-svc)
                                   |
                                   | POST /v1/token-exchange
                                   | subject_token=token_1, audience=gw-c
                                   v
                                token_2 (act: [gw-a, orders-svc])
                                   |
client --[token_2]-------------> Gateway C (inventory-svc)
```

Narratively, this is "client → Gateway A → Backend A → Gateway B → Backend
B → Gateway C → Backend C": each gateway's protected backend is the
`http-echo` sidecar already baked into its own pod
(`deploy/k8s/{api-gateway,orders-svc,inventory-svc}.yaml` — the "hello
from `<workload>`" container, reachable only via that gateway's own
`upstream_addr: http://127.0.0.1:8080`). `deploy/k8s/demo-backends.yaml`
additionally stands up three **new**, independently-named
`backend-a`/`backend-b`/`backend-c` Services, exactly as this task's brief
asked for — see "Known limitations" below for why the gateway trio
doesn't route to them yet, and how the demo script uses them in the
meantime.

Every hop's token keeps the same signed `sub` (the originating `client`'s
SPIFFE ID) end to end — `token_exchange::exchange_token` never changes
`sub`, only `aud` and the nested `act` chain — so each gateway's
`obo::validate` call is really authorizing *the original client*,
transitively, not "whoever called me directly." That's also why the
registry's `allowed_callers` lists needed an entry for `client` at
*every* hop (see the registry-configmap.yaml change this task made).

## Prerequisites

1. A `kind` cluster, with the gateway trio, registry, OTEL Collector, and
   Jaeger already deployed:
   ```bash
   scripts/create-kind-cluster.sh
   scripts/build-and-load-image.sh
   kubectl apply -f deploy/k8s/registry-configmap.yaml   # picks up the
                                                          # new `client`
                                                          # workload entry
   scripts/deploy-all.sh
   kubectl apply -f deploy/k8s/jaeger.yaml -f deploy/k8s/otel-collector.yaml
   ```
   If the gateway trio was already running from *before* this task's
   `registry-configmap.yaml` change, re-apply it and restart the
   Deployments so the new `client` entry and `allowed_callers` actually
   take effect — the registry is mounted via a `subPath` volume mount,
   which does **not** hot-reload on a ConfigMap change:
   ```bash
   kubectl apply -f deploy/k8s/registry-configmap.yaml
   kubectl -n zero-trust-demo rollout restart deployment/api-gateway deployment/orders-svc deployment/inventory-svc
   ```
2. SPIRE server + agent deployed (Task 6):
   ```bash
   scripts/setup-spire-kind.sh
   ```
   This demo script does **not** actually fetch the client's token from
   SPIRE's own Workload API — see "Known limitations" for exactly why,
   and what "SPIRE running" buys this demo today regardless.
3. Jaeger reachable — `deploy/k8s/jaeger.yaml` (applied above).
4. `kubectl`, `kind`, `curl`, and `python3` on `PATH` (the script uses
   `python3` purely for small JSON parsing steps, same as the rest of
   this project's demo/verification scripts).

## Running it

```bash
./scripts/demo-obo-chain.sh
```

It will:
1. Apply `deploy/k8s/demo-backends.yaml` (idempotent).
2. Port-forward to each gateway pod's admin port (6443) and proxy port
   (443), to Jaeger, and to the three demo backends.
3. Mint an initial token for `client`, run the two real
   `/v1/token-exchange` calls, call all three gateways, and curl the
   three demo backends directly.
4. Pull the resulting trace back out of Jaeger by ID and print each
   span's `allow` / `deny_reason` / `obo.delegation_depth` /
   `obo.delegation_chain` attributes.

All ports are overridable via environment variables (`GW_A_ADMIN_PORT`,
`GW_A_PROXY_PORT`, `JAEGER_PORT`, `BACKEND_A_PORT`, …) if any of the
defaults collide with something already running — see the top of the
script.

## Verifying in Jaeger

The script prints the shared trace ID it generated and used as the
`traceparent` header on all three gateway calls, then queries
`http://127.0.0.1:${JAEGER_PORT}/api/traces/<trace-id>` directly. You can
also open the UI (same port) and search for that trace ID, or for
service `zt-gateway`, directly:

- **Single trace, three spans**: all three `gateway_request` spans (one
  per hop) share the trace ID the script generated and passed as
  `traceparent`, per Task 9's W3C TraceContext propagation (F12) — the
  three separate `curl` calls land in Jaeger as one trace because they
  carry the same trace ID, not because the gateways talk to each other
  directly.
- **Delegation depth growing by one per hop**: `obo.delegation_depth` is
  `1` at Gateway A (chain `[client]`), `2` at Gateway B (chain `[client,
  api-gateway]`), `3` at Gateway C (chain `[client, api-gateway,
  orders-svc]`) — each number matches
  `OboClaims::delegation_chain().len()` read off the *signed* token,
  never an unsigned header.
- **Signed chain, not headers**: `obo.delegation_chain` prints the same
  chain as a `->`-joined string. There is no `X-SPIFFE-Caller-Chain`
  header anywhere in this script — compare with `git log -p --
  scripts/demo-obo-chain.sh` to see the old, header-forging version this
  one replaces.
- **`allow=true` / `deny_reason="none"`** on every span is the
  passing case. A `deny_reason` of `caller_not_in_allow_list` or
  `obo_token_signature_invalid` points straight at the two gaps called
  out below.

## Known limitations

This script exercises the real `/v1/token-exchange` endpoint and real signed
delegation chains. It has not been re-run against the current manifests, and
it is **expected to fail** until the gaps below are closed. Each one is
listed here rather than worked around silently.

1. **Cross-gateway JWKS sharing isn't wired up.** `exchange_token`'s output
   is only verifiable by a gateway that holds the matching public key. None
   of `deploy/k8s/{api-gateway,orders-svc,inventory-svc}.yaml` set
   `jwks_path`, `signing_key_path`, or `active_kid`, so each instance uses its
   own ephemeral keypair. **orders-svc cannot verify a token api-gateway
   exchanged**, and the demo fails at hop 2 with `obo_token_signature_invalid`.
   The fix is one public JWKS shared by all three gateways, each with its own
   `signing_key_path` and `active_kid` (see the README's "Signing keys and
   JWKS" section). This is a change to the three ConfigMaps.
2. **SPIRE identity issuance and `/v1/token-exchange` are mutually
   exclusive.** `SpireProvider::sign_claims` always returns `Err`, so a gateway
   with `spire_socket_path` set cannot serve `/v1/token-exchange`. None of the
   three ConfigMaps set `spire_socket_path` (the `ZT_SPIRE_SOCKET_PATH` env var
   they do set is inert, see the comment in `deploy/k8s/api-gateway.yaml`), so
   all three still run on `LocalIssuer`. "SPIRE running" in this demo's
   prerequisites means the SPIRE server and agent are up, for example for
   `spire-debug-client`'s SVID. It does not mean the gateways' identities are
   backed by SPIRE.
3. **`backend-a`/`backend-b`/`backend-c` aren't routed to.** They're deployed and
   the script curls them directly, in a clearly labeled step. None of the three
   gateway ConfigMaps has a `routes:` entry (F14) for them, so each gateway's
   proxy fallback still forwards to its own `upstream_addr`.
4. **The script assumes plain HTTP, but the gateways now serve TLS.** The
   manifests set `tls.client_auth: required` on each gateway. The proxy listener
   therefore requires a client certificate, and the admin listener serves HTTPS
   without requiring one. The script's `http://` calls to admin will fail, and
   its proxy calls will be refused without a client certificate. Switching the
   script to `https://` and presenting a client certificate for proxy calls is
   needed. See "Admin listener under `client_auth: required`" in
   `docs/design/0001-tls-mtls-termination.md` for the bootstrap order.

Until items 1 and 4 are fixed, the script will print a clear status per hop but
will not get to a fully passing, every-hop-`allow=true` run.
