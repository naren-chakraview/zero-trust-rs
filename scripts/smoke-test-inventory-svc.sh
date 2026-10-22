#!/usr/bin/env bash
set -euo pipefail

BASE="http://127.0.0.1:18443"

echo "=== 1. issue a token as orders-svc, scoped to inventory-svc ==="
TOKEN=$(curl -s -X POST "$BASE/v1/svid/jwt" \
  -H "content-type: application/json" \
  -d '{"workload_name":"orders-svc","audience":"spiffe://chakra.internal/ns/inventory/sa/inventory-svc","bootstrap_token":"orders-dev-secret"}' \
  | python3 -c "import sys, json; print(json.load(sys.stdin)['token'])")
echo "token acquired (${#TOKEN} chars)"

echo "=== 2. proxy without token -> expect 403 ==="
curl -s -o /dev/null -w "status: %{http_code}\n" "$BASE/anything"

echo "=== 3. proxy with token -> expect 200 + upstream body ==="
curl -s -i "$BASE/anything" -H "X-SPIFFE-OBO-Token: $TOKEN"
