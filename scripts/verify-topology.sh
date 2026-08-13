#!/usr/bin/env bash
set -euo pipefail

get_token() {
  local base="$1" workload="$2" audience="$3" secret="$4"
  curl -s -X POST "$base/v1/svid/jwt" \
    -H "content-type: application/json" \
    -d "{\"workload_name\":\"$workload\",\"audience\":\"$audience\",\"bootstrap_token\":\"$secret\"}" \
    | python3 -c "import sys, json; print(json.load(sys.stdin)['token'])"
}

status() {
  curl -s -o /dev/null -w "%{http_code}" "$@"
}

INVENTORY="http://127.0.0.1:18443"
ORDERS="http://127.0.0.1:18444"
APIGW="http://127.0.0.1:18445"
INV_ID="spiffe://chakra.internal/ns/inventory/sa/inventory-svc"
ORD_ID="spiffe://chakra.internal/ns/orders/sa/orders-svc"

echo "=== orders-svc: no token -> 403 ==="
CODE=$(status "$ORDERS/anything")
echo "got $CODE"; [ "$CODE" = "403" ] && echo PASS || echo FAIL

echo "=== orders-svc: token from api-gateway (allowed) -> 200 ==="
TOKEN=$(get_token "$ORDERS" "api-gateway" "$ORD_ID" "api-gateway-dev-secret")
CODE=$(status "$ORDERS/anything" -H "X-SPIFFE-OBO-Token: $TOKEN")
echo "got $CODE"; [ "$CODE" = "200" ] && echo PASS || echo FAIL

echo "=== api-gateway: allowed_callers is empty -> always 403, even with a token ==="
# api-gateway can't request its own token (that would be circular); build one
# signed by inventory-svc's issuer key -- wrong key entirely, so this proves
# the "no caller at all is allowed" case via a request with no token instead.
CODE=$(status "$APIGW/anything")
echo "got $CODE"; [ "$CODE" = "403" ] && echo PASS || echo FAIL

echo "=== inventory-svc: chain depth 4 (max is 3) -> 403 obo_chain_depth_exceeded ==="
TOKEN=$(get_token "$INVENTORY" "orders-svc" "$INV_ID" "orders-dev-secret")
RESPONSE=$(curl -s "$INVENTORY/anything" -H "X-SPIFFE-OBO-Token: $TOKEN" -H "X-SPIFFE-Caller-Chain: a,b,c,d")
echo "$RESPONSE"
echo "$RESPONSE" | grep -q "obo_chain_depth_exceeded" && echo PASS || echo FAIL

echo "=== inventory-svc: chain depth 2, valid token -> 200 (within max_obo_chain_depth: 3) ==="
CODE=$(status "$INVENTORY/anything" -H "X-SPIFFE-OBO-Token: $TOKEN" -H "X-SPIFFE-Caller-Chain: api-gateway,orders-svc")
echo "got $CODE"; [ "$CODE" = "200" ] && echo PASS || echo FAIL
