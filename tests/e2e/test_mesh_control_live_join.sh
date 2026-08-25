#!/usr/bin/env bash
# Live fos-gz0.5 close gate: local Headscale + fractalos-mesh-control ts2021 join.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
role="$repo_root/guest/roles/mesh-controller"
manifest="$role/manifest.json"
version="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["headscale_version"])' "$manifest")"
work="$(mktemp -d /tmp/fractalos-mesh-control-live.XXXXXX)"
evidence_dir="$repo_root/build/evidence"
evidence="$evidence_dir/gz0.5-native-headscale-join.json"
server_pid=""

cleanup() {
    [ -z "${server_pid:-}" ] || kill "$server_pid" 2>/dev/null || true
    [ -z "${server_pid:-}" ] || wait "$server_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo "== build fractalos-mesh-control =="
cargo build -q -p fractalos-mesh-control
cargo test -q -p fractalos-mesh-control

echo "== fetch pinned Headscale ${version} =="
case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) asset="headscale_${version}_darwin_arm64" ;;
    Darwin-x86_64) asset="headscale_${version}_darwin_amd64" ;;
    Linux-x86_64) asset="headscale_${version}_linux_amd64" ;;
    Linux-aarch64|Linux-arm64) asset="headscale_${version}_linux_arm64" ;;
    *) echo "unsupported host" >&2; exit 2 ;;
esac
expected="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["validation_assets"][sys.argv[2]])' "$manifest" "$asset")"
binary="$work/headscale"
curl -fsSL --retry 3 -o "$binary" \
    "https://github.com/juanfont/headscale/releases/download/v${version}/${asset}"
actual="$(shasum -a 256 "$binary" | awk '{print $1}')"
[ "$actual" = "$expected" ] || { echo "checksum mismatch" >&2; exit 1; }
chmod 0755 "$binary"

ports="$(python3 - <<'PY'
import socket
socks=[]; ports=[]
for _ in range(3):
    s=socket.socket(); s.bind(('127.0.0.1',0)); socks.append(s); ports.append(str(s.getsockname()[1]))
print(' '.join(ports))
PY
)"
read -r http_port grpc_port metrics_port <<<"$ports"
mkdir -p "$work/secrets" "$work/state" "$work/run" "$work/out" "$evidence_dir"
cp "$role/files/config.yaml" "$work/config.yaml"
cp "$role/files/policy.hujson" "$work/policy.hujson"
python3 - "$work/config.yaml" "$work" "$http_port" "$grpc_port" "$metrics_port" <<'PY'
import pathlib, sys
path=pathlib.Path(sys.argv[1]); root=sys.argv[2]
text=path.read_text()
text=text.replace('https://mesh.fractalos.internal:8080', f'https://127.0.0.1:{sys.argv[3]}')
text=text.replace('0.0.0.0:8080', f'127.0.0.1:{sys.argv[3]}')
text=text.replace('127.0.0.1:50443', f'127.0.0.1:{sys.argv[4]}')
text=text.replace('127.0.0.1:9090', f'127.0.0.1:{sys.argv[5]}')
text=text.replace('/var/db/fractalos-secrets/headscale', f'{root}/secrets')
text=text.replace('/var/db/headscale', f'{root}/state')
text=text.replace('/var/run/headscale', f'{root}/run')
text=text.replace('/usr/local/etc/headscale/policy.hujson', f'{root}/policy.hujson')
path.write_text(text)
PY
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=127.0.0.1 \
    -addext 'subjectAltName = IP:127.0.0.1' \
    -keyout "$work/secrets/tls.key" -out "$work/secrets/tls.crt" >/dev/null 2>&1

echo "== start Headscale =="
"$binary" serve -c "$work/config.yaml" >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
    [ -S "$work/run/headscale.sock" ] && break
    kill -0 "$server_pid" 2>/dev/null || { cat "$work/server.log"; exit 1; }
    sleep 0.05
done
[ -S "$work/run/headscale.sock" ] || { cat "$work/server.log"; exit 1; }

"$binary" -c "$work/config.yaml" users create agents >/dev/null
"$binary" -c "$work/config.yaml" apikeys create --expiration 24h >"$work/api.token"
chmod 0600 "$work/api.token"
helper="$repo_root/tools/agentctl/agentctl-mesh"
base="https://127.0.0.1:${http_port}"
auth_key="$("$helper" --url "$base" --ca-file "$work/secrets/tls.crt" --token-file "$work/api.token" \
    enroll-key --user agents --ttl-seconds 3600 --reusable --tag tag:agent \
    | python3 -c 'import json,sys; p=json.load(sys.stdin); assert p["ok"], p; print(p["result"]["preAuthKey"]["key"])')"
netmap_out="$work/out/netmap.bin"
keys_out="$work/out/keys.json"

echo "== fractalos-mesh-control join (ts2021) =="
RUST_LOG="${RUST_LOG:-info}" cargo run -q -p fractalos-mesh-control -- join \
    --control-url "$base" \
    --auth-key "$auth_key" \
    --ca-file "$work/secrets/tls.crt" \
    --hostname "fractalos-gz05" \
    --key-file "$keys_out" \
    --netmap-out "$netmap_out" \
    --timeout-secs 90 \
    --derp-ping

test -s "$netmap_out"
bytes="$(wc -c <"$netmap_out" | tr -d ' ')"
peers="$("$binary" -c "$work/config.yaml" nodes list --output json | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"

# Regression: freestanding dataplane suites still green.
cargo run -q -p xtask -- test --suite test_wg_dataplane >/dev/null
cargo run -q -p xtask -- test --suite test_wg_derp >/dev/null
cargo run -q -p xtask -- test --suite test_wg_netmap >/dev/null

python3 - "$evidence" "$base" "$bytes" "$peers" "$version" <<'PY'
import json, sys, datetime
from pathlib import Path
Path(sys.argv[1]).write_text(json.dumps({
  "schema": "fractalos.gz0.5.native_headscale_join.v1",
  "task_id": "fos-gz0.5",
  "child_task_id": "fos-gz0.5.1",
  "generated_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
  "proof_class": "live_host",
  "claims_live_product": True,
  "headscale_version": sys.argv[5],
  "control_url": sys.argv[2],
  "netmap_bytes": int(sys.argv[3]),
  "nodes_listed": int(sys.argv[4]),
  "client": "fractalos-mesh-control",
  "protocol": "ts2021",
  "status": "PASSING",
  "notes": "Native Noise join without guest tailscaled; packed OP_WG_APPLY_NETMAP emitted",
}, indent=2) + "\n", encoding="utf-8")
print("wrote", sys.argv[1])
PY

echo "[PASS] fos-gz0.5 live native Headscale join"
echo "evidence: $evidence"
