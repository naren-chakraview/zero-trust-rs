#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"
DIR="$(cd "$(dirname "$0")/../deploy/k8s" && pwd)"

kubectl apply -f "$DIR/namespace.yaml"
kubectl apply -f "$DIR/registry-configmap.yaml"
kubectl apply -f "$DIR/inventory-svc.yaml"
kubectl apply -f "$DIR/orders-svc.yaml"
kubectl apply -f "$DIR/api-gateway.yaml"

echo "=== waiting for rollouts ==="
kubectl rollout status -n zero-trust-demo deployment/inventory-svc --timeout=60s
kubectl rollout status -n zero-trust-demo deployment/orders-svc --timeout=60s
kubectl rollout status -n zero-trust-demo deployment/api-gateway --timeout=60s

kubectl get pods -n zero-trust-demo -o wide
