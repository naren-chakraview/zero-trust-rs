#!/usr/bin/env bash
set -euo pipefail

INVENTORY="http://127.0.0.1:18443"
ORDERS="http://127.0.0.1:18444"
ORD_ID="spiffe://chakra.internal/ns/orders/sa/orders-svc"
INV_ID="spiffe://chakra.internal/ns/inventory/sa/inventory-svc"

get_token() {
  local base="$1" workload="$2" audience="$3" secret="$4"
  curl -s -X POST "$base/v1/svid/jwt" \
    -H "content-type: application/json" \
    -d "{\"workload_name\":\"$workload\",\"audience\":\"$audience\",\"bootstrap_token\":\"$secret\"}" \
    | python3 -c "import sys, json; print(json.load(sys.stdin)['token'])"
}

echo "=== hop 1: api-gateway -> orders-svc (no prior chain, depth 0) ==="
TOKEN1=$(get_token "$ORDERS" "api-gateway" "$ORD_ID" "api-gateway-dev-secret")
curl -s -o /dev/null -w "status: %{http_code}\n" "$ORDERS/anything" -H "X-SPIFFE-OBO-Token: $TOKEN1"

echo
echo "=== hop 2: orders-svc -> inventory-svc, chain=[orders-svc] (depth 1, matches"
echo "    what build_outbound_headers would actually construct: the chain"
echo "    orders-svc received (empty) with itself appended) ==="
TOKEN2=$(get_token "$INVENTORY" "orders-svc" "$INV_ID" "orders-dev-secret")
curl -s -o /dev/null -w "status: %{http_code}\n" "$INVENTORY/anything" \
  -H "X-SPIFFE-OBO-Token: $TOKEN2" \
  -H "X-SPIFFE-Caller-Chain: orders-svc"

echo
echo "=== synthetic hop: someone forwards a chain already at depth 4 (max is 3) ==="
STATUS=$(curl -s -o /tmp/demo-resp.json -w "%{http_code}" "$INVENTORY/anything" \
  -H "X-SPIFFE-OBO-Token: $TOKEN2" \
  -H "X-SPIFFE-Caller-Chain: a,b,c,d")
echo "status: $STATUS"
cat /tmp/demo-resp.json
echo

echo
echo "=== waiting for the OTEL batch exporter to flush ==="
sleep 6

echo "=== recent zt-gateway trace spans (allow / deny_reason / obo.chain) ==="
curl -s "http://127.0.0.1:16686/api/traces?service=zt-gateway&limit=10" | python3 -c "
import sys, json
data = json.load(sys.stdin)
rows = []
for trace in data['data']:
    for span in trace['spans']:
        tags = {t['key']: t['value'] for t in span['tags']}
        if 'allow' in tags:
            rows.append((span['startTime'], tags.get('allow'), tags.get('deny_reason'), tags.get('obo.chain')))
rows.sort()
for start, allow, deny_reason, chain in rows[-6:]:
    print(f'allow={allow!s:5} deny_reason={deny_reason!r:30} obo.chain={chain!r}')
"
