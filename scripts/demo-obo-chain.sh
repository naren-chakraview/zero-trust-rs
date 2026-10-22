#!/usr/bin/env bash
# demo-obo-chain.sh — real three-hop OBO delegation chain demo (Task 7 / F16).
#
# Replaces the old version of this script, which only ever simulated a
# multi-hop chain by hand-minting one independent token per hop (each via
# its own bootstrap-token-authenticated `POST /v1/svid/jwt` call) and, in
# one case, forging the unsigned `X-SPIFFE-Caller-Chain` header directly —
# never actually exercising `POST /v1/token-exchange` or a signed `act`
# chain at all.
#
# This version drives the *real* flow end to end:
#   1. Mint one initial token for the external `client` identity (hop 0).
#   2. Call api-gateway's proxy with it (hop 1).
#   3. Call api-gateway's own `POST /v1/token-exchange` to re-mint that
#      token for orders-svc's audience — api-gateway is appended to the
#      signed `act` chain server-side; nothing here forges a header.
#   4. Call orders-svc's proxy with the exchanged token (hop 2).
#   5. Exchange again at orders-svc, scoped to inventory-svc's audience.
#   6. Call inventory-svc's proxy with the final, twice-exchanged token
#      (hop 3).
#   7. Pull the resulting trace back out of Jaeger and print the signed
#      `obo.*` attributes recorded on each hop's span.
#
# See docs/demo-obo-chain.md for the full flow diagram, prerequisites, and
# — importantly — the "Known limitations" section: this script's calls at
# step 4/6 will be denied with a signature-verification error unless the
# three gateways share one JWKS trust anchor, which the currently-deployed
# ConfigMaps (deploy/k8s/{api-gateway,orders-svc,inventory-svc}.yaml)
# don't yet set up. That wiring is out of this task's scope (it would mean
# editing those three gateways' configs, and this task was explicitly
# scoped to the demo script + a new backends manifest + docs, not the
# already-deployed gateway trio) — it's called out here, and loudly in the
# docs, rather than silently papered over.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"

NAMESPACE="${NAMESPACE:-zero-trust-demo}"
TRUST_DOMAIN="chakra.internal"

CLIENT_ID="spiffe://${TRUST_DOMAIN}/ns/client/sa/client"
GW_A_ID="spiffe://${TRUST_DOMAIN}/ns/api-gateway/sa/api-gateway"   # api-gateway
GW_B_ID="spiffe://${TRUST_DOMAIN}/ns/orders/sa/orders-svc"          # orders-svc
GW_C_ID="spiffe://${TRUST_DOMAIN}/ns/inventory/sa/inventory-svc"    # inventory-svc

CLIENT_BOOTSTRAP_TOKEN="${CLIENT_BOOTSTRAP_TOKEN:-client-dev-secret}"

# Local ports this script forwards to. Deliberately forwarding straight to
# each gateway *pod* (not its Service): the Services in
# deploy/k8s/{api-gateway,orders-svc,inventory-svc}.yaml only declare port
# 8443, which predates the F7/F10 admin/proxy listener split — nothing
# inside the container listens on 8443 any more (the binary now binds
# `admin_addr` (default 127.0.0.1:6443) and `proxy_addr` (default
# 0.0.0.0:443) instead, per `GatewayConfig`). `kubectl port-forward` to a
# pod reaches whatever the process actually bound to inside that pod's
# network namespace regardless of declared `containerPort`/Service
# `targetPort`, so this works without touching those three files.
GW_A_ADMIN_PORT="${GW_A_ADMIN_PORT:-16001}"
GW_A_PROXY_PORT="${GW_A_PROXY_PORT:-16002}"
GW_B_ADMIN_PORT="${GW_B_ADMIN_PORT:-16003}"
GW_B_PROXY_PORT="${GW_B_PROXY_PORT:-16004}"
GW_C_ADMIN_PORT="${GW_C_ADMIN_PORT:-16005}"
GW_C_PROXY_PORT="${GW_C_PROXY_PORT:-16006}"
JAEGER_PORT="${JAEGER_PORT:-16686}"
BACKEND_A_PORT="${BACKEND_A_PORT:-16011}"
BACKEND_B_PORT="${BACKEND_B_PORT:-16012}"
BACKEND_C_PORT="${BACKEND_C_PORT:-16013}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
K8S_DIR="$(cd "$SCRIPT_DIR/../deploy/k8s" && pwd)"

PF_PIDS=()
# Holds the X.509 SVIDs and keys this run issues, one set per calling workload.
CERT_DIR="$(mktemp -d)"
cleanup() {
  for pid in "${PF_PIDS[@]:-}"; do
    kill "$pid" >/dev/null 2>&1 || true
  done
  rm -rf "$CERT_DIR"
}
trap cleanup EXIT

log() { echo "[demo-obo-chain] $*"; }

# Finds the (first) running pod for a `app=<label>` Deployment.
pod_for() {
  kubectl -n "$NAMESPACE" get pods -l "app=$1" \
    -o jsonpath='{.items[0].metadata.name}' 2>/dev/null
}

# Starts `kubectl port-forward` to a pod (so it reaches whatever address
# the container actually bound, not just declared containerPorts — see
# the comment above `GW_A_ADMIN_PORT`) and waits until the local port
# actually accepts connections before returning.
port_forward_pod() {
  local app="$1" local_port="$2" remote_port="$3"
  local pod
  pod="$(pod_for "$app")"
  if [ -z "$pod" ]; then
    echo "ERROR: no running pod found for app=$app in namespace $NAMESPACE" >&2
    exit 1
  fi
  nohup kubectl -n "$NAMESPACE" port-forward "pod/$pod" "${local_port}:${remote_port}" \
    >"/tmp/pf-${app}-${remote_port}.log" 2>&1 &
  PF_PIDS+=("$!")
  wait_for_local_port "$local_port" "$app:$remote_port"
}

port_forward_svc() {
  local svc="$1" ns="$2" local_port="$3" remote_port="$4"
  nohup kubectl -n "$ns" port-forward "svc/$svc" "${local_port}:${remote_port}" \
    >"/tmp/pf-svc-${svc}-${remote_port}.log" 2>&1 &
  PF_PIDS+=("$!")
  wait_for_local_port "$local_port" "$svc:$remote_port"
}

wait_for_local_port() {
  local port="$1" label="$2"
  local deadline=$((SECONDS + 30))
  # A TCP connect is enough to show the port-forward is up. An HTTP request is
  # not: the proxy listener requires a client certificate, so it refuses a
  # plain HTTPS request, and an HTTP check would never succeed on it.
  until (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      echo "ERROR: port-forward for $label never came up on 127.0.0.1:$port" >&2
      exit 1
    fi
    sleep 1
  done
}

# POST /v1/svid/jwt — mints an initial token for a registered workload,
# authenticated by its shared bootstrap token. This project's stand-in for
# a real SPIRE Workload API JWT-SVID fetch (see docs/demo-obo-chain.md's
# "Known limitations": SpireProvider, Task 5's SPIRE IdentityProvider,
# can't sign/re-mint tokens at all, and none of the three gateways are
# actually configured with `spire_socket_path` today, so this endpoint —
# backed by `LocalIssuer` — is the only thing that can hand back a token
# any of this script's later `/v1/token-exchange` calls can act on).
get_initial_token() {
  local admin_port="$1" workload_name="$2" audience="$3" bootstrap_token="$4"
  curl -sfk -X POST "https://127.0.0.1:${admin_port}/v1/svid/jwt" \
    -H "content-type: application/json" \
    -d "{\"workload_name\":\"${workload_name}\",\"audience\":\"${audience}\",\"bootstrap_token\":\"${bootstrap_token}\"}" \
    | python3 -c "import sys, json; print(json.load(sys.stdin)['token'])"
}

# POST /v1/svid/x509 — issues the calling workload's own X.509 SVID. Under
# `client_auth: required` the proxy listener only accepts a client cert from
# the shared CA, so each hop presents its caller's SVID. The CSR's single URI
# SAN must equal the workload's registered SPIFFE ID, or the CA refuses it.
# Writes $CERT_DIR/<name>.{key,crt}.
issue_svid_cert() {
  local name="$1" spiffe_id="$2" admin_port="$3" bootstrap_token="$4"
  local dir="$CERT_DIR"
  openssl req -new -newkey rsa:2048 -nodes -keyout "$dir/$name.key" -out "$dir/$name.csr" \
    -subj "/CN=$name" -addext "subjectAltName=URI:${spiffe_id}" 2>/dev/null
  local csr_json
  csr_json="$(python3 -c "import json,sys; print(json.dumps(open(sys.argv[1]).read()))" "$dir/$name.csr")"
  curl -sfk -X POST "https://127.0.0.1:${admin_port}/v1/svid/x509" \
    -H "content-type: application/json" \
    -d "{\"workload_name\":\"${name}\",\"csr_pem\":${csr_json},\"bootstrap_token\":\"${bootstrap_token}\"}" \
    | python3 -c "import sys, json; print(json.load(sys.stdin)['cert_pem'])" > "$dir/$name.crt"
}

# POST /v1/token-exchange — the real RFC 8693 exchange this task is about:
# re-mints `subject_token` for `audience`, with the gateway answering this
# call appended to the signed `act` chain server-side.
exchange_token() {
  local admin_port="$1" subject_token="$2" audience="$3"
  curl -sfk -X POST "https://127.0.0.1:${admin_port}/v1/token-exchange" \
    -H "content-type: application/json" \
    -d "{\"subject_token\":\"${subject_token}\",\"audience\":\"${audience}\"}" \
    | python3 -c "import sys, json; print(json.load(sys.stdin)['access_token'])"
}

# Calls a gateway's proxy listener with an OBO token and a shared W3C
# traceparent header (so all three hops land in one Jaeger trace — see
# "Verify the trace" in docs/demo-obo-chain.md). Prints the HTTP status
# and body; does not abort the script on a non-2xx response, so every hop
# still runs and the final diagnostics can point at exactly which hop
# failed and why.
call_proxy() {
  local label="$1" proxy_port="$2" token="$3" traceparent="$4" caller="$5"
  local status body
  # The TLS peer on each hop is the current actor, so present that caller's
  # SVID. -k: the server certificate is the gateway's ephemeral self-signed one.
  body="$(curl -sk -w '\n%{http_code}' "https://127.0.0.1:${proxy_port}/demo" \
    --cert "$CERT_DIR/$caller.crt" --key "$CERT_DIR/$caller.key" \
    -H "X-SPIFFE-OBO-Token: ${token}" \
    -H "traceparent: ${traceparent}")"
  status="${body##*$'\n'}"
  body="${body%$'\n'*}"
  echo "=== $label: status $status ==="
  echo "$body"
  if [ "$status" != "200" ]; then
    echo "  (non-200 response — see docs/demo-obo-chain.md's Known" \
         "limitations: the usual cause is the three gateways not sharing" \
         "a JWKS trust anchor yet, or the registry's allowed_callers not" \
         "including $CLIENT_ID.)"
  fi
}

random_hex() {
  local bytes="$1"
  python3 -c "import secrets; print(secrets.token_hex($bytes))"
}

log "Applying demo backends (deploy/k8s/demo-backends.yaml)..."
kubectl apply -f "$K8S_DIR/demo-backends.yaml"
kubectl -n "$NAMESPACE" rollout status deployment/backend-a --timeout=60s
kubectl -n "$NAMESPACE" rollout status deployment/backend-b --timeout=60s
kubectl -n "$NAMESPACE" rollout status deployment/backend-c --timeout=60s

log "Setting up port-forwards to the gateway trio, Jaeger, and the demo backends..."
port_forward_pod api-gateway "$GW_A_ADMIN_PORT" 6443
port_forward_pod api-gateway "$GW_A_PROXY_PORT" 443
port_forward_pod orders-svc "$GW_B_ADMIN_PORT" 6443
port_forward_pod orders-svc "$GW_B_PROXY_PORT" 443
port_forward_pod inventory-svc "$GW_C_ADMIN_PORT" 6443
port_forward_pod inventory-svc "$GW_C_PROXY_PORT" 443
port_forward_svc jaeger "$NAMESPACE" "$JAEGER_PORT" 16686
port_forward_svc backend-a "$NAMESPACE" "$BACKEND_A_PORT" 8080
port_forward_svc backend-b "$NAMESPACE" "$BACKEND_B_PORT" 8080
port_forward_svc backend-c "$NAMESPACE" "$BACKEND_C_PORT" 8080

TRACE_ID="$(random_hex 16)"
PARENT_SPAN_ID="$(random_hex 8)"
TRACEPARENT="00-${TRACE_ID}-${PARENT_SPAN_ID}-01"
log "Shared trace ID for this run's three gateway hops: $TRACE_ID"

echo
log "=== issuing X.509 SVIDs for the three calling workloads ==="
issue_svid_cert "client" "$CLIENT_ID" "$GW_A_ADMIN_PORT" "$CLIENT_BOOTSTRAP_TOKEN"
issue_svid_cert "api-gateway" "$GW_A_ID" "$GW_A_ADMIN_PORT" "${API_GATEWAY_BOOTSTRAP_TOKEN:-api-gateway-dev-secret}"
issue_svid_cert "orders-svc" "$GW_B_ID" "$GW_B_ADMIN_PORT" "${ORDERS_BOOTSTRAP_TOKEN:-orders-dev-secret}"

echo
log "=== hop 0: mint the initial token for '$CLIENT_ID' (audience: api-gateway) ==="
TOKEN_0=$(get_initial_token "$GW_A_ADMIN_PORT" "client" "$GW_A_ID" "$CLIENT_BOOTSTRAP_TOKEN")
echo "token_0 (for api-gateway): ${TOKEN_0:0:40}..."

echo
log "=== hop 1: client -> Gateway A (api-gateway) ==="
call_proxy "Gateway A (api-gateway)" "$GW_A_PROXY_PORT" "$TOKEN_0" "$TRACEPARENT" "client"

echo
log "=== exchange at Gateway A: re-mint for orders-svc, api-gateway appended to act chain ==="
TOKEN_1=$(exchange_token "$GW_A_ADMIN_PORT" "$TOKEN_0" "$GW_B_ID")
echo "token_1 (for orders-svc): ${TOKEN_1:0:40}..."

echo
log "=== hop 2: (on client's behalf) -> Gateway B (orders-svc) ==="
call_proxy "Gateway B (orders-svc)" "$GW_B_PROXY_PORT" "$TOKEN_1" "$TRACEPARENT" "api-gateway"

echo
log "=== exchange at Gateway B: re-mint for inventory-svc, orders-svc appended to act chain ==="
TOKEN_2=$(exchange_token "$GW_B_ADMIN_PORT" "$TOKEN_1" "$GW_C_ID")
echo "token_2 (for inventory-svc): ${TOKEN_2:0:40}..."

echo
log "=== hop 3: (on client's behalf) -> Gateway C (inventory-svc) ==="
call_proxy "Gateway C (inventory-svc)" "$GW_C_PROXY_PORT" "$TOKEN_2" "$TRACEPARENT" "orders-svc"

echo
log "=== demo backends (standalone; curled directly — see demo-backends.yaml's" \
    "header comment for why the gateway trio doesn't route to these yet) ==="
for b in a b c; do
  port_var="BACKEND_${b^^}_PORT"
  echo "-- backend-$b --"
  curl -s "http://127.0.0.1:${!port_var}/"
  echo
done

echo
log "Waiting for the OTEL batch exporter to flush..."
sleep 6

echo
log "=== Jaeger: spans for trace $TRACE_ID ==="
curl -s "http://127.0.0.1:${JAEGER_PORT}/api/traces/${TRACE_ID}" | python3 -c "
import sys, json
data = json.load(sys.stdin)
traces = data.get('data', [])
if not traces:
    print('No trace found yet for this ID -- the exporter may not have flushed;')
    print('re-run: curl http://127.0.0.1:${JAEGER_PORT}/api/traces/${TRACE_ID}')
    sys.exit(0)
spans = traces[0]['spans']
print(f'{len(spans)} span(s) in trace {\"${TRACE_ID}\"!r}:')
spans.sort(key=lambda s: s['startTime'])
for span in spans:
    tags = {t['key']: t['value'] for t in span['tags']}
    print(
        f\"  {span['operationName']:16} allow={tags.get('allow')!s:5} \"
        f\"deny_reason={tags.get('deny_reason')!r:28} \"
        f\"obo.delegation_depth={tags.get('obo.delegation_depth')} \"
        f\"obo.delegation_chain={tags.get('obo.delegation_chain')!r}\"
    )
"

echo
log "Done. See docs/demo-obo-chain.md for how to interpret the output above,"
log "and its 'Known limitations' section if any hop returned non-200."
