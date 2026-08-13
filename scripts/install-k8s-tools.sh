#!/usr/bin/env bash
set -uo pipefail

mkdir -p ~/.local/bin

echo "=== fetching kubectl version ==="
KVER=""
for i in 1 2 3 4 5; do
  KVER=$(curl -4 -s -m 10 https://dl.k8s.io/release/stable.txt)
  if [ -n "$KVER" ]; then
    break
  fi
  echo "  attempt $i empty, retrying..."
  sleep 2
done
echo "kubectl version: [$KVER]"
if [ -z "$KVER" ]; then
  echo "FAILED to determine kubectl version" >&2
  exit 1
fi

echo "=== installing kubectl ==="
curl -4 --retry 5 --retry-delay 2 -fLo ~/.local/bin/kubectl "https://dl.k8s.io/release/${KVER}/bin/linux/amd64/kubectl"
chmod +x ~/.local/bin/kubectl
file ~/.local/bin/kubectl

echo "=== fetching kind version ==="
KIND_VER=""
for i in 1 2 3 4 5; do
  KIND_VER=$(curl -4 -s -m 10 https://api.github.com/repos/kubernetes-sigs/kind/releases/latest | grep -oP '"tag_name": "\K[^"]+')
  if [ -n "$KIND_VER" ]; then
    break
  fi
  echo "  attempt $i empty, retrying..."
  sleep 2
done
echo "kind version: [$KIND_VER]"
if [ -z "$KIND_VER" ]; then
  echo "FAILED to determine kind version" >&2
  exit 1
fi

echo "=== installing kind ==="
curl -4 --retry 5 --retry-delay 2 -fLo ~/.local/bin/kind "https://kind.sigs.k8s.io/dl/${KIND_VER}/kind-linux-amd64"
chmod +x ~/.local/bin/kind
file ~/.local/bin/kind

grep -q "HOME/.local/bin" ~/.bashrc || echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
export PATH="$HOME/.local/bin:$PATH"

echo "=== versions ==="
kubectl version --client
kind --version
