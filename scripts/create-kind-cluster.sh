#!/usr/bin/env bash
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"

kind create cluster --name zero-trust --wait 90s
kubectl cluster-info --context kind-zero-trust
kubectl get nodes -o wide
