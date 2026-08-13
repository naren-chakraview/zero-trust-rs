#!/usr/bin/env bash
set -euo pipefail

DEST=/tmp/spire-quickstart
mkdir -p "$DEST"
BASE="https://raw.githubusercontent.com/spiffe/spire-tutorials/main/k8s/quickstart"

FILES=(
  spire-namespace.yaml
  server-account.yaml
  server-cluster-role.yaml
  server-configmap.yaml
  server-service.yaml
  server-statefulset.yaml
  agent-account.yaml
  agent-cluster-role.yaml
  agent-configmap.yaml
  agent-daemonset.yaml
  spire-bundle-configmap.yaml
  create-node-registration-entry.sh
)

for f in "${FILES[@]}"; do
  curl -4 -s -o "$DEST/$f" "$BASE/$f"
  echo "fetched $f ($(wc -l < "$DEST/$f") lines)"
done
