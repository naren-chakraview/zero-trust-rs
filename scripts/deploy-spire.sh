#!/usr/bin/env bash
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
DIR="$(cd "$(dirname "$0")/../deploy/k8s/spire" && pwd)"

kubectl apply -f "$DIR/server-account.yaml"
kubectl apply -f "$DIR/server-cluster-role.yaml"
kubectl apply -f "$DIR/server-configmap.yaml"
kubectl apply -f "$DIR/server-service.yaml"
kubectl apply -f "$DIR/bundle-configmap.yaml"
kubectl apply -f "$DIR/server-statefulset.yaml"

kubectl apply -f "$DIR/agent-account.yaml"
kubectl apply -f "$DIR/agent-cluster-role.yaml"
kubectl apply -f "$DIR/agent-configmap.yaml"
kubectl apply -f "$DIR/agent-daemonset.yaml"

kubectl apply -f "$DIR/debug-client.yaml"

echo "=== waiting for spire-server ==="
kubectl rollout status -n zero-trust-demo statefulset/spire-server --timeout=120s

echo "=== waiting for spire-agent ==="
kubectl rollout status -n zero-trust-demo daemonset/spire-agent --timeout=120s

echo "=== waiting for debug client pod ==="
kubectl wait -n zero-trust-demo --for=condition=Ready pod/spire-debug-client --timeout=60s

kubectl get pods -n zero-trust-demo -o wide
