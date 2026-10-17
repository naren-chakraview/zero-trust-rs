#!/usr/bin/env bash
# Deploys SPIRE server + agent (deploy/k8s/spire-server.yaml,
# deploy/k8s/spire-agent.yaml) into a Kind cluster, for testing Task 5's
# SpireProvider (src/spire_provider.rs) against real SPIRE.
#
# Usage: ./scripts/setup-spire-kind.sh [kind-cluster-name]
#   kind-cluster-name defaults to "chakra".
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"

KIND_CLUSTER="${1:-chakra}"
SPIRE_NAMESPACE="spire"
DIR="$(cd "$(dirname "$0")/../deploy/k8s" && pwd)"

echo "Setting up SPIRE on Kind cluster: $KIND_CLUSTER"

# Fail gracefully (clear message, no stack trace) when the required tools
# or cluster aren't available, rather than letting a later command fail
# with a confusing error.
for tool in kind kubectl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: '$tool' not found on PATH -- install it before running this script." >&2
        exit 1
    fi
done

if ! kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER"; then
    echo "ERROR: Kind cluster '$KIND_CLUSTER' not found." >&2
    echo "Create it first, e.g.: ./scripts/create-kind-cluster.sh" >&2
    exit 1
fi

# Load SPIRE images into Kind (pulls from the registry first if not
# already present locally; `|| true` so a cluster that already has the
# image cached, or a flaky pull, doesn't abort the whole script).
echo "Loading SPIRE images into Kind cluster..."
docker pull ghcr.io/spiffe/spire-server:1.8.0 || true
docker pull ghcr.io/spiffe/spire-agent:1.8.0 || true
kind load docker-image ghcr.io/spiffe/spire-server:1.8.0 --name "$KIND_CLUSTER" || true
kind load docker-image ghcr.io/spiffe/spire-agent:1.8.0 --name "$KIND_CLUSTER" || true

# `kubectl wait` errors immediately with "no matching resources found" if
# the label selector matches zero pods at the moment it's invoked -- it
# does not wait for pods to first come into existence, only for an
# already-existing object to reach the condition. Right after `apply`,
# the Deployment/DaemonSet controller may not have created its pod(s) yet,
# so wait_for_pod_then_ready polls for at least one matching pod to exist
# before handing off to the real `kubectl wait --for=condition=ready`.
wait_for_pod_then_ready() {
    local label="$1"
    local deadline=$((SECONDS + 300))
    until kubectl --context "kind-$KIND_CLUSTER" -n "$SPIRE_NAMESPACE" \
        get pods -l "$label" --no-headers 2>/dev/null | grep -q .; do
        if [ "$SECONDS" -ge "$deadline" ]; then
            echo "ERROR: no pods matching '$label' appeared within 300s" >&2
            exit 1
        fi
        sleep 2
    done
    kubectl --context "kind-$KIND_CLUSTER" -n "$SPIRE_NAMESPACE" wait \
        --for=condition=ready pod \
        -l "$label" \
        --timeout=300s
}

# Apply SPIRE manifests
echo "Deploying SPIRE server..."
kubectl --context "kind-$KIND_CLUSTER" apply -f "$DIR/spire-server.yaml"

echo "Waiting for SPIRE server to be ready..."
wait_for_pod_then_ready "app=spire-server"

echo "Deploying SPIRE agent..."
kubectl --context "kind-$KIND_CLUSTER" apply -f "$DIR/spire-agent.yaml"

echo "Waiting for SPIRE agent to be ready..."
wait_for_pod_then_ready "app=spire-agent"

echo "SPIRE setup complete!"
echo ""
kubectl --context "kind-$KIND_CLUSTER" -n "$SPIRE_NAMESPACE" get pods -o wide
echo ""
echo "Verify:"
echo "  kubectl -n $SPIRE_NAMESPACE get pods"
echo "  kubectl -n $SPIRE_NAMESPACE logs -l app=spire-server --tail=20"
echo "  kubectl -n $SPIRE_NAMESPACE logs -l app=spire-agent --tail=20"
