#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

IMAGE="zero-trust/zt-gateway:dev"
CLUSTER="zero-trust"

export PATH="$HOME/.local/bin:$PATH"

echo "=== docker build ==="
docker build -t "$IMAGE" .

echo "=== kind load docker-image ==="
kind load docker-image "$IMAGE" --name "$CLUSTER"

echo "done: $IMAGE loaded into kind cluster $CLUSTER"
