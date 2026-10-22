#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"
DIR="$(cd "$(dirname "$0")/../deploy/k8s" && pwd)"

kubectl apply -f "$DIR/namespace.yaml"
kubectl apply -f "$DIR/registry-configmap.yaml"
# Task 14 (N13): shared mTLS trust root (ca.cert_path/key_path, required by
# `tls.client_auth: required` in each *-svc.yaml's ConfigMap below). The file
# holds a private key, so it's git-ignored; generate it per zt-ca-secret.yaml's
# header comment before the first deploy.
if [[ ! -f "$DIR/zt-ca-secret.yaml" ]]; then
  echo "missing deploy/k8s/zt-ca-secret.yaml -- generate the local demo CA first (see its header comment)" >&2
  exit 1
fi
kubectl apply -f "$DIR/zt-ca-secret.yaml"
kubectl apply -f "$DIR/inventory-svc.yaml"
kubectl apply -f "$DIR/orders-svc.yaml"
kubectl apply -f "$DIR/api-gateway.yaml"

echo "=== waiting for rollouts ==="
kubectl rollout status -n zero-trust-demo deployment/inventory-svc --timeout=60s
kubectl rollout status -n zero-trust-demo deployment/orders-svc --timeout=60s
kubectl rollout status -n zero-trust-demo deployment/api-gateway --timeout=60s

kubectl get pods -n zero-trust-demo -o wide
