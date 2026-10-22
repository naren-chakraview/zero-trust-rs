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

## Verified run

Run on the `zero-trust` kind cluster on 2026-10-22, after building the image
from the current `master`. All three hops returned 200, and each response came
from the expected backend (`response from backend-a`, `-b`, `-c`). Jaeger showed
one trace with three spans, at delegation depths 1, 2, and 3, and the chain
`client -> api-gateway -> orders-svc` in `obo.delegation_chain`. Cross-gateway
signature checks passed, so the static JWKS (`scripts/gen-gateway-keys.sh`,
`scripts/deploy-all.sh`) works on a cluster.

## Known limitations

These are real limits of the current design, not failures of this run.

1. **Delegation runs through a demo backend.** Each gateway's `/demo` route
   delegates to a loopback sidecar (`python3`, echoing the token it was handed).
   The gateway rebinds the token to its delegation cert (design 0002, option A).
   The demo script stands in for the backend when it exchanges the token onward,
   presenting the cert and key from the `zt-delegation-<gateway>` Secret. A real
   workload would hold its own key. The first token is bound to the client's cert
   from the start.
2. **SPIRE identity issuance and `/v1/token-exchange` are mutually exclusive.**
   `SpireProvider::sign_claims` always returns `Err`, so a gateway with
   `spire_socket_path` set can't serve `/v1/token-exchange`. The gateways run on
   `LocalIssuer`, and `ZT_SPIRE_SOCKET_PATH` in `deploy/k8s/api-gateway.yaml` is
   inert. The SPIRE server and agent are up for `spire-debug-client`'s SVID, but
   the gateways' identities aren't backed by SPIRE.
3. **Jaeger's `allow` and `deny_reason` fields print as `None`.** The spans carry
   the delegation chain and depth, but the demo script shows `None` for the
   decision fields. I haven't yet checked whether the gateway fails to record them
   on the span or the script reads them wrong. The decisions themselves were
   correct: every hop returned 200.

## Agent variant

`scripts/demo-agent-chain.sh` shows what a user-driven agent workload may and may
not do (review 0003, R8). It runs on the same cluster, and `scripts/deploy-all.sh`
deploys what it needs. The demo's "agent" is the orders-svc workload, playing that
role. No LLM runs in the demo. The policy checks the workload that calls each hop.
It doesn't check earlier actors in the chain.

- A mock OIDC IdP (`deploy/k8s/mock-idp.yaml`) stands in for a real provider. The
  demo reaches it through a port-forward pinned to `http://localhost:18500/default`,
  because the mock builds its issuer from the request host.
- api-gateway, orders-svc, and inventory-svc trust that IdP for user credentials
  (`user_idps`, with its public keys in the `zt-user-idp-jwks` ConfigMap).
- inventory-svc runs a capability policy (`deploy/k8s/policy/capability-policy.yaml`,
  `default: deny`). It lets alice act through the agent for `GET /demo`, in a rule
  that names both. It also lets the agent act alone for `GET /demo`. No rule grants
  `DELETE`.

The flow:

1. alice logs in through the IdP and gets an RS256 id_token.
2. api-gateway verifies it and mints an edge token with alice as `user`.
3. api-gateway exchanges that token for the agent, orders-svc.
4. The agent exchanges it for inventory-svc, so the chain is
   `[orders-svc, api-gateway]` with alice as `user`.
5. The agent GETs `/demo` for alice. Both hold the grant, so inventory answers
   200 from backend-c.
6. The agent DELETEs `/demo` for alice. No rule covers that, so inventory answers
   403 `capability_denied`.

The script exits non-zero unless step 5 is 200 and step 6 is 403
`capability_denied`. It passed on the kind cluster on 2026-10-22.

Two things it deliberately does not show. An intern with no grant, and an admin
with a grant on a workload that doesn't hold it, are covered by the unit tests in
`src/capability.rs`. The IdP's identity rides in the `user_iss` claim, and `iss`
names the gateway that signed each token (review 0003, R6).
