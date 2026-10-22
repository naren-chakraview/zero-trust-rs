#!/usr/bin/env bash
# Generates one RSA signing key per gateway, and the public JWKS that every
# gateway verifies against (F4 / N7, review 0002). Static keys: a gateway
# signs with its own key, and the shared public set lists all three kids.
#
# Existing private keys are kept, so re-running is safe. The public JWKS is
# rebuilt from the keys on every run.
#
# Usage: scripts/gen-gateway-keys.sh [OUT_DIR]
#   OUT_DIR defaults to deploy/k8s/keys, which is git-ignored.
set -euo pipefail

GATEWAYS=(api-gateway orders-svc inventory-svc)
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${1:-$ROOT/deploy/k8s/keys}"
mkdir -p "$OUT_DIR"

for gw in "${GATEWAYS[@]}"; do
  if [ ! -f "$OUT_DIR/$gw.pem" ]; then
    # -traditional writes PKCS#1 PEM ("BEGIN RSA PRIVATE KEY"), the format
    # the gateway's signing_key_path loader reads.
    openssl genrsa -traditional -out "$OUT_DIR/$gw.pem" 2048 2>/dev/null
    chmod 600 "$OUT_DIR/$gw.pem"
    echo "generated signing key for $gw"
  fi
done

python3 - "$OUT_DIR" "${GATEWAYS[@]}" <<'PY'
import base64, json, os, subprocess, sys

out_dir, kids = sys.argv[1], sys.argv[2:]

def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

def openssl(*args: str) -> str:
    return subprocess.run(["openssl", *args], check=True, capture_output=True, text=True).stdout

keys = []
for kid in kids:
    pem = os.path.join(out_dir, kid + ".pem")
    # `-modulus` prints "Modulus=<hex>". Strip any leading zero byte, since
    # JWK `n` is the minimal big-endian encoding.
    modulus = bytes.fromhex(openssl("rsa", "-in", pem, "-noout", "-modulus").split("=", 1)[1].strip())
    modulus = modulus.lstrip(b"\x00")
    # `-text` prints "publicExponent: 65537 (0x10001)".
    text = openssl("rsa", "-in", pem, "-noout", "-text")
    exp_hex = next(l for l in text.splitlines() if "publicExponent:" in l).split("(0x", 1)[1].rstrip(")")
    exponent = bytes.fromhex(exp_hex if len(exp_hex) % 2 == 0 else "0" + exp_hex)
    keys.append({"kty": "RSA", "kid": kid, "n": b64url(modulus), "e": b64url(exponent)})

path = os.path.join(out_dir, "public-jwks.json")
with open(path, "w") as f:
    json.dump({"keys": keys}, f, indent=2)
    f.write("\n")
print("wrote", path)
PY
