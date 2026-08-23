#!/usr/bin/env bash
# Validate the pinned controller release, configuration, policy, and REST API.
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
role="$repo_root/guest/roles/mesh-controller"
manifest="$role/manifest.json"
version="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["headscale_version"])' "$manifest")"
work="$(mktemp -d /tmp/agentos-headscale-validation.XXXXXX)"
server_pid=""
cleanup() {
    [ -z "$server_pid" ] || kill "$server_pid" 2>/dev/null || true
    [ -z "$server_pid" ] || wait "$server_pid" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

if [ -n "${HEADSCALE_BIN:-}" ]; then
    binary="$HEADSCALE_BIN"
else
    case "$(uname -s)-$(uname -m)" in
        Darwin-x86_64) asset="headscale_${version}_darwin_amd64" ;;
        Darwin-arm64) asset="headscale_${version}_darwin_arm64" ;;
        Linux-x86_64) asset="headscale_${version}_linux_amd64" ;;
        Linux-aarch64|Linux-arm64) asset="headscale_${version}_linux_arm64" ;;
        *) echo "unsupported validation host: $(uname -s)-$(uname -m)" >&2; exit 2 ;;
    esac
    expected="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["validation_assets"][sys.argv[2]])' "$manifest" "$asset")"
    binary="$work/headscale"
    curl -fL --retry 3 -o "$binary" \
        "https://github.com/juanfont/headscale/releases/download/v${version}/${asset}"
    actual="$(shasum -a 256 "$binary" | awk '{print $1}')"
    [ "$actual" = "$expected" ] || {
        echo "Headscale validation binary checksum mismatch" >&2
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
if [ "${AGENTOS_TAILSCALE_E2E:-0}" = "1" ]; then
    advertised_host=host.docker.internal
    listen_host=0.0.0.0
else
    advertised_host=127.0.0.1
    listen_host=127.0.0.1
fi
python3 - "$work/config.yaml" "$work" "$http_port" "$grpc_port" "$metrics_port" "$advertised_host" "$listen_host" <<'PY'
import pathlib, sys
path=pathlib.Path(sys.argv[1])
root=sys.argv[2]
text=path.read_text()
text=text.replace('https://mesh.agentos.internal:8080', f'https://{sys.argv[6]}:{sys.argv[3]}')
text=text.replace('0.0.0.0:8080', f'{sys.argv[7]}:{sys.argv[3]}')
text=text.replace('127.0.0.1:50443', f'127.0.0.1:{sys.argv[4]}')
text=text.replace('127.0.0.1:9090', f'127.0.0.1:{sys.argv[5]}')
text=text.replace('/var/db/agentos-secrets/headscale', f'{root}/secrets')
text=text.replace('/var/db/headscale', f'{root}/state')
text=text.replace('/var/run/headscale', f'{root}/run')
text=text.replace('/usr/local/etc/headscale/policy.hujson', f'{root}/policy.hujson')
path.write_text(text)
PY
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=127.0.0.1 \
    -addext 'subjectAltName = IP:127.0.0.1,DNS:host.docker.internal' \
    -keyout "$work/secrets/tls.key" -out "$work/secrets/tls.crt" >/dev/null 2>&1

"$binary" version | grep -q "v${version}"
"$binary" configtest -c "$work/config.yaml"
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
"$binary" -c "$work/config.yaml" policy check -f "$work/policy.hujson" | grep -q 'Policy is valid'
"$binary" -c "$work/config.yaml" apikeys create --expiration 5m >"$work/api.token"
chmod 0600 "$work/api.token"

helper="$repo_root/tools/agentctl/agentctl-mesh"
base="https://127.0.0.1:${http_port}"
"$helper" --url "$base" --ca-file "$work/secrets/tls.crt" --token-file "$work/api.token" status \
    | python3 -c 'import json,sys; assert json.load(sys.stdin)["ok"]'
"$helper" --url "$base" --ca-file "$work/secrets/tls.crt" --token-file "$work/api.token" nodes \
    | python3 -c 'import json,sys; assert json.load(sys.stdin)["ok"]'
"$helper" --url "$base" --ca-file "$work/secrets/tls.crt" --token-file "$work/api.token" \
    enroll-key --ttl-seconds 600 --ephemeral \
    | python3 -c 'import json,sys; p=json.load(sys.stdin); assert p["ok"] and p["result"]["preAuthKey"]["key"]'

if [ "${AGENTOS_TAILSCALE_E2E:-0}" = "1" ]; then
    AGENTOS_HEADSCALE_URL="$base" \
    AGENTOS_HEADSCALE_LOGIN_URL="https://host.docker.internal:${http_port}" \
    AGENTOS_HEADSCALE_TOKEN_FILE="$work/api.token" \
    AGENTOS_HEADSCALE_CA_FILE="$work/secrets/tls.crt" \
    AGENTOS_MESH_DOCKER=1 \
        bash "$repo_root/tests/e2e/test_headscale_mesh.sh"
    if [ "${AGENTOS_MESH_TRACE:-0}" = "1" ]; then
        "$binary" -c "$work/config.yaml" nodes list --output json >&2
    fi
    AGENTOS_HEADSCALE_BIN="$binary" \
    AGENTOS_HEADSCALE_CONFIG="$work/config.yaml" \
    AGENTOS_NETCAP_MAP="$role/files/netcap-map.json" \
    AGENTOS_NETCAP_STATE="$work/netcap-state.json" \
        "$role/files/policy-sync.py"
    python3 - "$work/netcap-state.json" <<'PY'
import json, sys
nodes=json.load(open(sys.argv[1]))["nodes"]
agents=[node for node in nodes if node["name"] in {"agent-a", "agent-b"}]
assert len(agents) == 2, nodes
assert all(node["netcap"] == "mesh-agent" for node in agents), nodes
assert all(node["agent_endpoint_ports"] == [8443] for node in agents), nodes
PY
fi

echo "[PASS] Headscale ${version} config, policy, REST management, and enrollment"
