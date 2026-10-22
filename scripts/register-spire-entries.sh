#!/usr/bin/env bash
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"

NODE_SPIFFE_ID="spiffe://chakra.internal/ns/zero-trust-demo/sa/spire-agent"
DEBUG_CLIENT_SPIFFE_ID="spiffe://chakra.internal/ns/zero-trust-demo/sa/spire-debug-client"

echo "=== registering the node (spire-agent) entry ==="
kubectl exec -n zero-trust-demo spire-server-0 -- \
  /opt/spire/bin/spire-server entry create \
  -node \
  -spiffeID "$NODE_SPIFFE_ID" \
  -selector k8s_psat:cluster:zero-trust \
  -selector k8s_psat:agent_ns:zero-trust-demo \
  -selector k8s_psat:agent_sa:spire-agent

echo "=== registering the spire-debug-client workload entry ==="
kubectl exec -n zero-trust-demo spire-server-0 -- \
  /opt/spire/bin/spire-server entry create \
  -spiffeID "$DEBUG_CLIENT_SPIFFE_ID" \
  -parentID "$NODE_SPIFFE_ID" \
  -selector k8s:ns:zero-trust-demo \
  -selector k8s:sa:spire-debug-client

echo "=== entries ==="
kubectl exec -n zero-trust-demo spire-server-0 -- \
  /opt/spire/bin/spire-server entry show
