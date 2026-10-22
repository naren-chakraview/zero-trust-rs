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

# Option 1 JWKS (review 0002 F4/N7): one signing key per gateway, plus the
# public JWKS every gateway verifies against. Keys are generated on first run
# and kept after that. Each gateway's Secret is mounted only into its own pod.
KEYS_DIR="$DIR/keys"
"$(dirname "$0")/gen-gateway-keys.sh" "$KEYS_DIR"
for gw in api-gateway orders-svc inventory-svc; do
  kubectl -n zero-trust-demo create secret generic "zt-signing-key-$gw" \
    --from-file=signing-key.pem="$KEYS_DIR/$gw.pem" --dry-run=client -o yaml | kubectl apply -f -
done
kubectl -n zero-trust-demo create configmap zt-jwks \
  --from-file=public-jwks.json="$KEYS_DIR/public-jwks.json" --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f "$DIR/inventory-svc.yaml"
kubectl apply -f "$DIR/orders-svc.yaml"
kubectl apply -f "$DIR/api-gateway.yaml"

echo "=== waiting for rollouts ==="
kubectl rollout status -n zero-trust-demo deployment/inventory-svc --timeout=60s
kubectl rollout status -n zero-trust-demo deployment/orders-svc --timeout=60s
kubectl rollout status -n zero-trust-demo deployment/api-gateway --timeout=60s

kubectl get pods -n zero-trust-demo -o wide
