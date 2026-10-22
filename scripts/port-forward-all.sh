#!/usr/bin/env bash
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"

pkill -f "kubectl port-forward -n zero-trust-demo" 2>/dev/null || true
sleep 1

nohup kubectl port-forward -n zero-trust-demo svc/inventory-svc 18443:8443 > /tmp/pf-inventory.log 2>&1 &
nohup kubectl port-forward -n zero-trust-demo svc/orders-svc 18444:8443 > /tmp/pf-orders.log 2>&1 &
nohup kubectl port-forward -n zero-trust-demo svc/api-gateway 18445:8443 > /tmp/pf-apigw.log 2>&1 &
nohup kubectl port-forward -n zero-trust-demo svc/jaeger 16686:16686 > /tmp/pf-jaeger.log 2>&1 &

sleep 2
echo "=== inventory (18443) ==="; cat /tmp/pf-inventory.log
echo "=== orders (18444) ==="; cat /tmp/pf-orders.log
echo "=== api-gateway (18445) ==="; cat /tmp/pf-apigw.log
echo "=== jaeger (16686) ==="; cat /tmp/pf-jaeger.log
