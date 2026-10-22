#!/usr/bin/env bash
# demo-agent-chain.sh — the agent variant of the three-hop demo (review 0003 R8).
#
# Shows what a user-driven agent may and may not do:
#   1. alice logs in through the mock IdP (an RS256 id_token);
#   2. api-gateway verifies it and mints an edge token with alice as `user`
#      (POST /v1/svid/jwt-with-user);
#   3. api-gateway exchanges that token for the agent workload (orders-svc);
#   4. the agent exchanges it for inventory-svc;
#   5. the agent GETs /demo on alice's behalf. inventory's capability policy
#      allows this, because alice and the agent hold the grant in one rule. Expect 200.
#   6. the agent DELETEs /demo on alice's behalf. The policy has no such grant,
#      so inventory refuses it with 403 `capability_denied`. Expect that.
#
# The script exits non-zero unless both expectations hold.
#
# Needs the demo deployed (scripts/deploy-all.sh, which also deploys the mock
# IdP). See docs/demo-obo-chain.md, "Agent variant".
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"

NAMESPACE="${NAMESPACE:-zero-trust-demo}"
TRUST_DOMAIN="chakra.internal"

# The mock IdP's issuer. The mock builds it from the request host, so the
# port-forward below is pinned to this exact address.
IDP="http://localhost:18500/default"
ALICE="alice@corp.internal"

GW_A_ID="spiffe://${TRUST_DOMAIN}/ns/api-gateway/sa/api-gateway"
GW_B_ID="spiffe://${TRUST_DOMAIN}/ns/orders/sa/orders-svc"          # the agent
GW_C_ID="spiffe://${TRUST_DOMAIN}/ns/inventory/sa/inventory-svc"

GW_A_ADMIN_PORT=16001     # api-gateway admin (6443 in the pod)
GW_B_ADMIN_PORT=16003     # orders-svc admin, where the agent exchanges
GW_C_PROXY_PORT=16006     # inventory-svc proxy (443 in the pod)
IDP_PORT=18500

CERT_DIR="$(mktemp -d)"
PF_PIDS=()
cleanup() {
  for pid in "${PF_PIDS[@]:-}"; do kill "$pid" >/dev/null 2>&1 || true; done
  rm -rf "$CERT_DIR"
}
trap cleanup EXIT

log() { echo "[demo-agent-chain] $*"; }
fail() { echo "[demo-agent-chain] FAIL: $*" >&2; exit 1; }

# Starts `kubectl port-forward` to a pod, then waits for it to accept connections.
port_forward_pod() {
  local app="$1" local_port="$2" remote_port="$3" pod
  pod="$(kubectl -n "$NAMESPACE" get pods -l "app=$app" -o jsonpath='{.items[0].metadata.name}')"
  kubectl -n "$NAMESPACE" port-forward "pod/$pod" "${local_port}:${remote_port}" >"/tmp/pf-agent-${app}-${remote_port}.log" 2>&1 &
  PF_PIDS+=("$!")
  wait_for_local_port "$local_port"
}

port_forward_svc() {
  local svc="$1" local_port="$2" remote_port="$3"
  kubectl -n "$NAMESPACE" port-forward "svc/$svc" "${local_port}:${remote_port}" >"/tmp/pf-agent-svc-${svc}.log" 2>&1 &
  PF_PIDS+=("$!")
  wait_for_local_port "$local_port"
}

wait_for_local_port() {
  local port="$1" deadline=$((SECONDS + 30))
  until (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; do
    [ "$SECONDS" -ge "$deadline" ] && fail "port-forward on 127.0.0.1:$port never came up"
    sleep 1
  done
}

# Logs `email` in through the mock IdP's authorization-code flow, with `email`
# as the only claim, and prints the id_token. The client_id is the audience
# the gateways require (user_idps `audience: zt-gateway`).
login() {
  local email="$1" location code
  local query="response_type=code&client_id=zt-gateway&redirect_uri=http://localhost/cb&scope=openid&state=s&nonce=n"
  location="$(curl -s -o /dev/null -D - -X POST "${IDP}/authorize?${query}" \
    --data-urlencode "username=${email%@*}" \
    --data-urlencode "claims={\"email\":\"${email}\"}" \
    | tr -d '\r' | awk -F': ' 'tolower($1)=="location"{print $2}')"
  code="$(python3 -c 'import sys,urllib.parse as u; print(u.parse_qs(u.urlparse(sys.argv[1]).query)["code"][0])' "$location")"
  curl -s -X POST "${IDP}/token" \
    -d grant_type=authorization_code -d "code=${code}" \
    -d redirect_uri=http://localhost/cb -d client_id=zt-gateway -d client_secret=unused \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["id_token"])'
}

# Mints an edge token for a verified IdP credential (admin, no client cert).
edge_mint() {
  local credential="$1" body
  body="$(curl -sk -X POST "https://127.0.0.1:${GW_A_ADMIN_PORT}/v1/svid/jwt-with-user" \
    -H "content-type: application/json" \
    -d "{\"user_credential\":\"${credential}\",\"user_issuer\":\"${IDP}\"}")"
  # Keep the gateway's own error text if the mint was refused.
  echo "$body" | python3 -c 'import sys,json
d=json.load(sys.stdin)
print(d["token"]) if "token" in d else (print("edge mint refused: "+json.dumps(d), file=sys.stderr))' 2>&1 || true
}

# Exchanges `subject` for `audience` at the given admin port (RFC 8693).
exchange() {
  local admin_port="$1" subject="$2" audience="$3"
  curl -sfk -X POST "https://127.0.0.1:${admin_port}/v1/token-exchange" \
    -H "content-type: application/json" \
    -d "{\"subject_token\":\"${subject}\",\"audience\":\"${audience}\"}" \
    | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])'
}

# Issues the calling workload's X.509 SVID over admin. The CSR's URI SAN must
# equal the workload's registered SPIFFE ID.
issue_svid_cert() {
  local name="$1" spiffe_id="$2" admin_port="$3" bootstrap_token="$4"
  openssl req -new -newkey rsa:2048 -nodes -keyout "$CERT_DIR/$name.key" -out "$CERT_DIR/$name.csr" \
    -subj "/CN=$name" -addext "subjectAltName=URI:${spiffe_id}" 2>/dev/null
  local csr_json
  csr_json="$(python3 -c "import json,sys; print(json.dumps(open(sys.argv[1]).read()))" "$CERT_DIR/$name.csr")"
  curl -sfk -X POST "https://127.0.0.1:${admin_port}/v1/svid/x509" \
    -H "content-type: application/json" \
    -d "{\"workload_name\":\"${name}\",\"csr_pem\":${csr_json},\"bootstrap_token\":\"${bootstrap_token}\"}" \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['cert_pem'])" > "$CERT_DIR/$name.crt"
}

# Calls inventory-svc's proxy as `caller` (the TLS peer must be the acting
# workload). Sets LAST_STATUS and LAST_BODY.
LAST_STATUS=""
LAST_BODY=""
call_proxy() {
  local label="$1" method="$2" token="$3" caller="$4" out
  out="$(curl -sk -w '\n%{http_code}' -X "$method" "https://127.0.0.1:${GW_C_PROXY_PORT}/demo" \
    --cert "$CERT_DIR/$caller.crt" --key "$CERT_DIR/$caller.key" \
    -H "X-SPIFFE-OBO-Token: ${token}")"
  LAST_STATUS="${out##*$'\n'}"
  LAST_BODY="${out%$'\n'*}"
  log "=== ${label}: ${method} /demo -> ${LAST_STATUS} ==="
  echo "${LAST_BODY}"
}

log "port-forwarding to the IdP, api-gateway admin, orders-svc admin, and inventory-svc proxy"
port_forward_svc mock-idp "$IDP_PORT" 8080
port_forward_pod api-gateway "$GW_A_ADMIN_PORT" 6443
port_forward_pod orders-svc "$GW_B_ADMIN_PORT" 6443
port_forward_pod inventory-svc "$GW_C_PROXY_PORT" 443

log "1. alice logs in through the IdP"
ID_TOKEN="$(login "$ALICE")"
[ -n "$ID_TOKEN" ] || fail "the IdP returned no id_token"

log "2. api-gateway verifies the id_token and mints an edge token with alice as user"
EDGE_TOKEN="$(edge_mint "$ID_TOKEN")"
[ -n "$EDGE_TOKEN" ] || fail "edge mint was refused (check user_idps on api-gateway)"

log "3. api-gateway exchanges it for the agent (orders-svc)"
AGENT_TOKEN="$(exchange "$GW_A_ADMIN_PORT" "$EDGE_TOKEN" "$GW_B_ID")"

log "4. the agent exchanges it for inventory-svc"
INVENTORY_TOKEN="$(exchange "$GW_B_ADMIN_PORT" "$AGENT_TOKEN" "$GW_C_ID")"

log "the agent's X.509 SVID (its TLS identity on the next hop)"
issue_svid_cert "orders-svc" "$GW_B_ID" "$GW_A_ADMIN_PORT" "orders-dev-secret"

echo
call_proxy "5. the agent reads /demo for alice" GET "$INVENTORY_TOKEN" orders-svc
[ "$LAST_STATUS" = "200" ] || fail "expected 200 for alice's GET through the agent, got $LAST_STATUS"
echo "$LAST_BODY" | grep -q "response from backend-c" || fail "the GET did not reach backend-c"

echo
call_proxy "6. the agent tries to DELETE /demo for alice" DELETE "$INVENTORY_TOKEN" orders-svc
[ "$LAST_STATUS" = "403" ] || fail "expected 403 for the DELETE, got $LAST_STATUS"
echo "$LAST_BODY" | grep -q "capability_denied" || fail "the 403 was not from the capability policy: $LAST_BODY"

echo
log "PASS: the agent read for alice, and was refused the DELETE. Its grant is bounded by the policy."
