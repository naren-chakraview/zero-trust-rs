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

# Agent demo (review 0003 R8): the mock IdP, its public keys, and the capability
# policy for inventory-svc. The IdP's keys are fetched through a port-forward.
# The mock generates them at startup, so they can't be committed.
# Ops (review 0003). A gateway reads its config only at startup, and a ConfigMap
# change doesn't roll the pods that mount it. So each gateway's pod template carries
# a hash of everything that feeds it, and a change to any input rolls the pods.
roll_on_config_change() {
  local gw="$1"; shift
  local hash
  hash="$(cat "$@" | sha256sum | cut -d' ' -f1)"
  kubectl -n zero-trust-demo patch deployment "$gw" --type merge \
    -p "{\"spec\":{\"template\":{\"metadata\":{\"annotations\":{\"zt.chakra.dev/config-hash\":\"$hash\"}}}}}" >/dev/null
}

# After the rollout, checks that each running gateway loaded the registry and
# config its ConfigMaps hold. If the kubelet still had an older value when the pod
# started, the pod is replaced. A file mounted with subPath never picks up later
# changes, so a restart is the only fix.
verify_mounted_config() {
  local gw="$1" pod want have
  pod="$(kubectl -n zero-trust-demo get pods -l "app=$gw" -o json | python3 -c '
import json, sys
pods = [p for p in json.load(sys.stdin)["items"] if "deletionTimestamp" not in p["metadata"]]
print(pods[0]["metadata"]["name"] if pods else "")')"
  [ -n "$pod" ] || { echo "no running pod for $gw" >&2; return 1; }
  local stale=0
  want="$(kubectl -n zero-trust-demo get cm zt-registry -o jsonpath='{.data.registry\.yaml}' | sha256sum)"
  have="$(kubectl -n zero-trust-demo exec "$pod" -c zt-gateway -- sha256sum /etc/zt-gateway/registry.yaml 2>/dev/null || true)"
  [ -n "$have" ] && [ "${want%% *}" = "${have%% *}" ] || stale=1
  want="$(kubectl -n zero-trust-demo get cm "zt-gateway-config-$gw" -o jsonpath='{.data.gateway\.config\.yaml}' | sha256sum)"
  have="$(kubectl -n zero-trust-demo exec "$pod" -c zt-gateway -- sha256sum /etc/zt-gateway/gateway.config.yaml 2>/dev/null || true)"
  [ -n "$have" ] && [ "${want%% *}" = "${have%% *}" ] || stale=1
  if [ "$stale" = 1 ]; then
    echo "$gw loaded a stale config; replacing pod $pod"
    kubectl -n zero-trust-demo delete pod "$pod" >/dev/null
    kubectl -n zero-trust-demo rollout status "deployment/$gw" --timeout=120s
  fi
}

kubectl apply -f "$DIR/mock-idp.yaml"
kubectl -n zero-trust-demo rollout status deployment/mock-idp --timeout=120s
kubectl -n zero-trust-demo port-forward svc/mock-idp 18500:8080 >/tmp/zt-idp-pf.log 2>&1 &
IDP_PF=$!
for _ in $(seq 1 30); do
  curl -sf -o "$KEYS_DIR/idp-jwks.json" http://localhost:18500/default/jwks && break
  sleep 1
done
kill "$IDP_PF" 2>/dev/null || true
test -s "$KEYS_DIR/idp-jwks.json" || { echo "could not fetch the mock IdP's JWKS" >&2; exit 1; }
kubectl -n zero-trust-demo create configmap zt-user-idp-jwks \
  --from-file=idp-jwks.json="$KEYS_DIR/idp-jwks.json" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n zero-trust-demo create configmap zt-capability-policy \
  --from-file=capability-policy.yaml="$DIR/policy/capability-policy.yaml" --dry-run=client -o yaml | kubectl apply -f -
# Design 0002 (option A): each gateway's delegation certificate. The gateway holds
# the cert, which it binds rebound tokens to. Its co-located backend holds the key
# and presents the cert when it exchanges the token. The demo issues them from the
# demo CA in deploy/k8s/zt-ca-secret.yaml, so they're valid for the same trust root
# as the workload SVIDs. They're re-issued when less than an hour of validity is left.
DELEG_DIR="$KEYS_DIR/delegation"
mkdir -p "$DELEG_DIR"
python3 - "$DIR/zt-ca-secret.yaml" "$DELEG_DIR" <<'PY'
import os, sys, yaml
secret, out = sys.argv[1], sys.argv[2]
data = yaml.safe_load(open(secret))["stringData"]
for name, key in [("ca-cert.pem", "ca-cert.pem"), ("ca-key.pem", "ca-key.pem")]:
    path = os.path.join(out, key)
    with open(path, "w") as f:
        f.write(data[name])
    os.chmod(path, 0o600 if "key" in key else 0o644)
PY
for gw in api-gateway orders-svc inventory-svc; do
  case "$gw" in
    api-gateway) spiffe="spiffe://chakra.internal/ns/api-gateway/sa/api-gateway" ;;
    orders-svc) spiffe="spiffe://chakra.internal/ns/orders/sa/orders-svc" ;;
    inventory-svc) spiffe="spiffe://chakra.internal/ns/inventory/sa/inventory-svc" ;;
  esac
  if [ ! -f "$DELEG_DIR/$gw.crt" ] || ! openssl x509 -checkend 3600 -noout -in "$DELEG_DIR/$gw.crt" >/dev/null 2>&1; then
    openssl genrsa -traditional -out "$DELEG_DIR/$gw.key" 2048 2>/dev/null
    openssl req -new -key "$DELEG_DIR/$gw.key" -subj "/CN=$gw" -out "$DELEG_DIR/$gw.csr"
    printf 'subjectAltName=URI:%s\nextendedKeyUsage=clientAuth\nkeyUsage=digitalSignature\nbasicConstraints=CA:FALSE\n' "$spiffe" > "$DELEG_DIR/$gw.ext"
    openssl x509 -req -in "$DELEG_DIR/$gw.csr" -CA "$DELEG_DIR/ca-cert.pem" -CAkey "$DELEG_DIR/ca-key.pem" \
      -set_serial "0x$(openssl rand -hex 8)" -days 1 -extfile "$DELEG_DIR/$gw.ext" -out "$DELEG_DIR/$gw.crt" 2>/dev/null
    chmod 600 "$DELEG_DIR/$gw.key"
    echo "issued delegation certificate for $gw"
  fi
  kubectl -n zero-trust-demo create secret generic "zt-delegation-$gw" \
    --from-file=cert.pem="$DELEG_DIR/$gw.crt" --from-file=key.pem="$DELEG_DIR/$gw.key" \
    --dry-run=client -o yaml | kubectl apply -f -
done

kubectl apply -f "$DIR/inventory-svc.yaml"
kubectl apply -f "$DIR/orders-svc.yaml"
kubectl apply -f "$DIR/api-gateway.yaml"

# The config inputs of each gateway: its manifest, the registry, the keys, its
# delegation cert, the policy, and the CA. Any change rolls that gateway.
for gw in inventory-svc orders-svc api-gateway; do
  roll_on_config_change "$gw" "$DIR/$gw.yaml" "$DIR/registry-configmap.yaml" \
    "$DIR/policy/capability-policy.yaml" "$KEYS_DIR/public-jwks.json" \
    "$KEYS_DIR/idp-jwks.json" "$DELEG_DIR/$gw.crt" "$DIR/zt-ca-secret.yaml"
done

echo "=== waiting for rollouts ==="
kubectl rollout status -n zero-trust-demo deployment/inventory-svc --timeout=60s
kubectl rollout status -n zero-trust-demo deployment/orders-svc --timeout=60s
kubectl rollout status -n zero-trust-demo deployment/api-gateway --timeout=60s

echo "=== checking each gateway loaded its current config ==="
for gw in inventory-svc orders-svc api-gateway; do
  verify_mounted_config "$gw"
done

kubectl get pods -n zero-trust-demo -o wide
