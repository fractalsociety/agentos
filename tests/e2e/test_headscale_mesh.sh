#!/usr/bin/env bash
# Real E2E: enroll two standard Tailscale clients and call an agent endpoint.
set -euo pipefail
[ "${AGENTOS_MESH_TRACE:-0}" != "1" ] || set -x

skip() { echo "[SKIP] $*"; exit 2; }
fail() { echo "[FAIL] $*" >&2; exit 1; }

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
helper="${AGENTCTL_MESH_HELPER:-${repo_root}/tools/agentctl/agentctl-mesh}"
mesh_url="${AGENTOS_HEADSCALE_URL:-}"
login_url="${AGENTOS_HEADSCALE_LOGIN_URL:-$mesh_url}"
token_file="${AGENTOS_HEADSCALE_TOKEN_FILE:-}"
ca_file="${AGENTOS_HEADSCALE_CA_FILE:-}"
[ -n "$mesh_url" ] || skip "AGENTOS_HEADSCALE_URL is not set"
[ -s "$token_file" ] || skip "AGENTOS_HEADSCALE_TOKEN_FILE is not set/readable"
command -v python3 >/dev/null || skip "python3 is required"

work="$(mktemp -d)"
containers=""
docker_network=""
cleanup() {
    [ -f "$work/pids" ] && xargs kill < "$work/pids" 2>/dev/null || true
    for container in $containers; do docker rm -f "$container" >/dev/null 2>&1 || true; done
    [ -z "$docker_network" ] || docker network rm "$docker_network" >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

mesh_args=(--url "$mesh_url" --token-file "$token_file")
[ -z "$ca_file" ] || mesh_args+=(--ca-file "$ca_file")

enroll_key() {
    "$helper" "${mesh_args[@]}" \
        enroll-key --ttl-seconds 600 | \
        python3 -c 'import json,sys; p=json.load(sys.stdin)["result"]; print((p.get("preAuthKey") or p).get("key"))'
}

key_a="$(enroll_key)"
key_b="$(enroll_key)"
[ "$key_a" != "None" ] && [ "$key_b" != "None" ] || fail "enrollment API returned no key"

if [ "${AGENTOS_MESH_DOCKER:-0}" = "1" ] || ! command -v tailscaled >/dev/null; then
    command -v docker >/dev/null || skip "tailscaled or Docker is required"
    image="${AGENTOS_TAILSCALE_IMAGE:-tailscale/tailscale:v1.102.3}"
    endpoint_image="${AGENTOS_MESH_ENDPOINT_IMAGE:-nginx:1.29-alpine}"
    curl_image="${AGENTOS_MESH_CURL_IMAGE:-curlimages/curl:8.16.0}"
    suffix="$$"
    docker_network="agentos-mesh-${suffix}"
    node_a="agentos-mesh-a-${suffix}"
    node_b="agentos-mesh-b-${suffix}"
    endpoint="agentos-mesh-endpoint-${suffix}"
    containers="$endpoint $node_b $node_a"
    docker network create "$docker_network" >/dev/null
    mkdir -p "$work/site"
    echo '{"agent":"agent-a","ok":true}' > "$work/site/health"

    start_docker_client() {
        name=$1 key=$2 hostname=$3
        docker create --name "$name" --network "$docker_network" \
            --entrypoint sh "$image" -c \
            'update-ca-certificates >/dev/null; exec tailscaled --tun=userspace-networking --socks5-server=0.0.0.0:1055 --socket=/tmp/tailscaled.sock --state=/tmp/tailscaled.state' \
            >/dev/null
        if [ -n "$ca_file" ]; then
            docker cp "$ca_file" "$name:/usr/local/share/ca-certificates/agentos-headscale.crt"
        fi
        docker start "$name" >/dev/null
        for _ in $(seq 1 100); do
            docker exec "$name" test -S /tmp/tailscaled.sock >/dev/null 2>&1 && break
            sleep 0.1
        done
        if ! docker exec "$name" timeout 30 tailscale --socket=/tmp/tailscaled.sock up \
            --login-server="$login_url" --auth-key="$key" \
            --hostname="$hostname" --accept-dns=false >/dev/null; then
            docker logs "$name" >&2
            fail "$hostname could not enroll with Headscale"
        fi
    }

    start_docker_client "$node_a" "$key_a" agent-a
    start_docker_client "$node_b" "$key_b" agent-b
    docker create --name "$endpoint" --network "container:$node_a" \
        "$endpoint_image" >/dev/null
    docker cp "$work/site/health" "$endpoint:/usr/share/nginx/html/health"
    docker start "$endpoint" >/dev/null
    for _ in $(seq 1 50); do
        docker exec "$node_a" wget -qO- http://127.0.0.1:80/health 2>/dev/null \
            | grep -q '"ok":true' && break
        sleep 0.1
    done
    docker exec "$node_a" wget -qO- http://127.0.0.1:80/health \
        | grep -q '"ok":true' || fail "local agent endpoint did not start"
    docker exec "$node_a" tailscale --socket=/tmp/tailscaled.sock \
        serve --bg --tcp 8443 tcp://127.0.0.1:80 >/dev/null
    agent_a_ip="$(docker exec "$node_a" tailscale --socket=/tmp/tailscaled.sock ip -4 | head -1 | tr -d '\r')"
    response=""
    for _ in $(seq 1 30); do
        response="$(docker run --rm --network "container:$node_b" "$curl_image" \
            --fail --silent --show-error --max-time 5 \
            --socks5-hostname 127.0.0.1:1055 "http://${agent_a_ip}:8443/health" 2>/dev/null || true)"
        echo "$response" | grep -q '"ok":true' && break
        sleep 0.2
    done
    if ! echo "$response" | grep -q '"ok":true'; then
        docker exec "$node_a" tailscale --socket=/tmp/tailscaled.sock status >&2 || true
        docker exec "$node_b" tailscale --socket=/tmp/tailscaled.sock status >&2 || true
        docker exec "$node_a" tailscale --socket=/tmp/tailscaled.sock serve status >&2 || true
        fail "agent endpoint response mismatch: $response"
    fi
    echo "[PASS] two standard Tailscale containers enrolled and agent endpoint invoked"
    exit 0
fi

for binary in tailscale tailscaled curl; do
    command -v "$binary" >/dev/null || skip "$binary is required"
done

start_client() {
    name=$1 socket=$2 state=$3 socks=$4 key=$5
    tailscaled --tun=userspace-networking --socket="$socket" --state="$state" \
        --socks5-server="127.0.0.1:$socks" >"$work/$name.log" 2>&1 &
    echo $! >> "$work/pids"
    for _ in $(seq 1 50); do [ -S "$socket" ] && break; sleep 0.1; done
    tailscale --socket="$socket" up --login-server="$login_url" \
        --auth-key="$key" --hostname="$name" --accept-dns=false
}

start_client agent-a "$work/a.sock" "$work/a.state" 19055 "$key_a"
start_client agent-b "$work/b.sock" "$work/b.state" 29055 "$key_b"

python3 -m http.server 18443 --bind 127.0.0.1 --directory "$work" >"$work/http.log" 2>&1 &
echo $! >> "$work/pids"
echo '{"agent":"agent-a","ok":true}' > "$work/health"
tailscale --socket="$work/a.sock" serve --bg --tcp 8443 tcp://127.0.0.1:18443
agent_a_ip="$(tailscale --socket="$work/a.sock" ip -4 | head -1)"

response="$(curl --fail --silent --show-error --socks5-hostname 127.0.0.1:29055 \
    "http://${agent_a_ip}:8443/health")"
echo "$response" | grep -q '"ok":true' || fail "agent endpoint response mismatch: $response"
echo "[PASS] two standard Tailscale nodes enrolled and agent endpoint invoked"
