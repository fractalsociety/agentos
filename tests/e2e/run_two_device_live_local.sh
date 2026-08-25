#!/usr/bin/env bash
# Boot an ephemeral Headscale (same pin as mesh-controller) and run the
# fos-gz0.14.19 vertical-slice gate with Docker Tailscale clients.
#
# Usage:
#   ./tests/e2e/run_two_device_live_local.sh
#
# Requires: docker, curl, openssl, python3, network access to fetch Headscale.

set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
role="$repo_root/guest/roles/mesh-controller"
manifest="$role/manifest.json"
version="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["headscale_version"])' "$manifest")"
work="$(mktemp -d /tmp/fractalos-two-device-live.XXXXXX)"
server_pid=""
cleanup() {
    [ -z "$server_pid" ] || kill "$server_pid" 2>/dev/null || true
    [ -z "$server_pid" ] || wait "$server_pid" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

echo "== ephemeral Headscale v${version} for fos-gz0.14.19 =="

if [ -n "${HEADSCALE_BIN:-}" ]; then
    binary="$HEADSCALE_BIN"
else
    case "$(uname -s)-$(uname -m)" in
        Darwin-x86_64) asset="headscale_${version}_darwin_amd64" ;;
        Darwin-arm64) asset="headscale_${version}_darwin_arm64" ;;
        Linux-x86_64) asset="headscale_${version}_linux_amd64" ;;
        Linux-aarch64|Linux-arm64) asset="headscale_${version}_linux_arm64" ;;
        *) echo "unsupported host: $(uname -s)-$(uname -m)" >&2; exit 2 ;;
    esac
    expected="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["validation_assets"][sys.argv[2]])' "$manifest" "$asset")"
    binary="$work/headscale"
    curl -fL --retry 3 -o "$binary" \
        "https://github.com/juanfont/headscale/releases/download/v${version}/${asset}"
    actual="$(shasum -a 256 "$binary" | awk '{print $1}')"
    [ "$actual" = "$expected" ] || {
        echo "Headscale checksum mismatch" >&2
        exit 1
    }
    chmod 0755 "$binary"
fi

ports="$(python3 - <<'PY'
import socket
sockets=[]
ports=[]
for _ in range(3):
    sock=socket.socket()
    sock.bind(('127.0.0.1', 0))
    sockets.append(sock)
    ports.append(str(sock.getsockname()[1]))
print(' '.join(ports))
PY
)"
read -r http_port grpc_port metrics_port <<<"$ports"
mkdir -p "$work/secrets" "$work/state" "$work/run"
cp "$role/files/config.yaml" "$work/config.yaml"
cp "$role/files/policy.hujson" "$work/policy.hujson"
advertised_host=host.docker.internal
listen_host=0.0.0.0
python3 - "$work/config.yaml" "$work" "$http_port" "$grpc_port" "$metrics_port" "$advertised_host" "$listen_host" <<'PY'
import pathlib, sys
path=pathlib.Path(sys.argv[1])
root=sys.argv[2]
text=path.read_text()
text=text.replace('https://mesh.fractalos.internal:8080', f'https://{sys.argv[6]}:{sys.argv[3]}')
text=text.replace('0.0.0.0:8080', f'{sys.argv[7]}:{sys.argv[3]}')
text=text.replace('127.0.0.1:50443', f'127.0.0.1:{sys.argv[4]}')
text=text.replace('127.0.0.1:9090', f'127.0.0.1:{sys.argv[5]}')
text=text.replace('/var/db/fractalos-secrets/headscale', f'{root}/secrets')
text=text.replace('/var/db/headscale', f'{root}/state')
text=text.replace('/var/run/headscale', f'{root}/run')
text=text.replace('/usr/local/etc/headscale/policy.hujson', f'{root}/policy.hujson')
path.write_text(text)
PY
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=127.0.0.1 \
    -addext 'subjectAltName = IP:127.0.0.1,DNS:host.docker.internal' \
    -keyout "$work/secrets/tls.key" -out "$work/secrets/tls.crt" >/dev/null 2>&1

"$binary" serve -c "$work/config.yaml" >"$work/server.log" 2>&1 &
server_pid=$!
for _ in $(seq 1 200); do
    [ -S "$work/run/headscale.sock" ] && break
    kill -0 "$server_pid" 2>/dev/null || { cat "$work/server.log"; exit 1; }
    sleep 0.05
done
[ -S "$work/run/headscale.sock" ] || { cat "$work/server.log"; exit 1; }

"$binary" -c "$work/config.yaml" users create agent-admin >/dev/null
"$binary" -c "$work/config.yaml" users create agents >/dev/null
"$binary" -c "$work/config.yaml" apikeys create --expiration 30m >"$work/api.token"
chmod 0600 "$work/api.token"

base="https://127.0.0.1:${http_port}"
login="https://host.docker.internal:${http_port}"

echo "Headscale URL=$base login=$login"
echo "Token file=$work/api.token"
echo "CA file=$work/secrets/tls.crt"

export FRACTALOS_TWO_DEVICE_LIVE=1
export FRACTALOS_HEADSCALE_URL="$base"
export FRACTALOS_HEADSCALE_LOGIN_URL="$login"
export FRACTALOS_HEADSCALE_TOKEN_FILE="$work/api.token"
export FRACTALOS_HEADSCALE_CA_FILE="$work/secrets/tls.crt"
export FRACTALOS_MESH_DOCKER=1

set +e
"$repo_root/tests/e2e/test_two_device_fractal.sh"
st=$?
set -e

# Persist a pointer to the last live run under build/evidence (token itself is not copied).
mkdir -p "$repo_root/build/evidence"
cat > "$repo_root/build/evidence/two-device-live-local-meta.json" <<EOF
{
  "schema": "fractalos.two_device_live_local.v1",
  "headscale_version": "$version",
  "headscale_url": "$base",
  "login_url": "$login",
  "gate_exit": $st,
  "evidence": "build/evidence/two-device-vertical-slice.json",
  "note": "ephemeral controller destroyed after run; re-run this script for a fresh live proof"
}
EOF

exit "$st"
