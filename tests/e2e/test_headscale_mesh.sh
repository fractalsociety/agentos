#!/usr/bin/env bash
# Real E2E: enroll two standard Tailscale clients and call an agent endpoint.
set -euo pipefail
[ "${FRACTALOS_MESH_TRACE:-0}" != "1" ] || set -x

skip() { echo "[SKIP] $*"; exit 2; }
fail() { echo "[FAIL] $*" >&2; exit 1; }

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
helper="${AGENTCTL_MESH_HELPER:-${repo_root}/tools/agentctl/agentctl-mesh}"
mesh_url="${FRACTALOS_HEADSCALE_URL:-}"
login_url="${FRACTALOS_HEADSCALE_LOGIN_URL:-$mesh_url}"
token_file="${FRACTALOS_HEADSCALE_TOKEN_FILE:-}"
ca_file="${FRACTALOS_HEADSCALE_CA_FILE:-}"
reconnect_cut="${FRACTALOS_MESH_RECONNECT_CUT:-0}"
reconnect_secs="${FRACTALOS_MESH_RECONNECT_SECONDS:-30}"
reconnect_evidence="${FRACTALOS_RECONNECT_EVIDENCE:-$repo_root/build/evidence/two-device-reconnect-cut.json}"
[ -n "$mesh_url" ] || skip "FRACTALOS_HEADSCALE_URL is not set"
[ -s "$token_file" ] || skip "FRACTALOS_HEADSCALE_TOKEN_FILE is not set/readable"
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

write_reconnect_evidence() {
    # args: method during_ok after_ok cut_start cut_end agent_ip pre_body post_body
    mkdir -p "$(dirname "$reconnect_evidence")"
    METHOD="$1" DURING_OK="$2" AFTER_OK="$3" CUT_START="$4" CUT_END="$5" \
    AGENT_IP="$6" PRE_BODY="$7" POST_BODY="$8" SECS="$reconnect_secs" \
    OUT="$reconnect_evidence" URL="$mesh_url" python3 - <<'PY'
import json, os
from pathlib import Path
Path(os.environ["OUT"]).write_text(json.dumps({
    "schema": "fractalos.two_device_reconnect_cut.v1",
    "task_id": "fos-gz0.14.19",
    "method": os.environ["METHOD"],
    "cut_seconds_requested": int(os.environ["SECS"]),
    "cut_start_utc": os.environ["CUT_START"],
    "cut_end_utc": os.environ["CUT_END"],
    "headscale_url": os.environ["URL"],
    "agent_a_ip": os.environ["AGENT_IP"],
    "during_cut_reachable": os.environ["DURING_OK"] == "1",
    "after_resume_ok": os.environ["AFTER_OK"] == "1",
    "pre_cut_body": os.environ["PRE_BODY"][:200],
    "post_resume_body": os.environ["POST_BODY"][:200],
    "status": "PASSING" if os.environ["DURING_OK"] == "0" and os.environ["AFTER_OK"] == "1" else "FAILING",
    "note": "AC-2 live route cut via tailscale down; session/CAS semantics covered by host worker reconnect suite",
}, indent=2) + "\n", encoding="utf-8")
print("wrote", os.environ["OUT"])
PY
}

# AC-2 live: cut Tailscale data plane ~30s, prove path fails, resume, prove same agent endpoint.
run_reconnect_cut_docker() {
    node_a=$1
    node_b=$2
    curl_image=$3
    agent_a_ip=$4
    pre_body=$5
    hostname_b=$6
    [ "$reconnect_cut" = "1" ] || return 0
    echo "== reconnect cut ${reconnect_secs}s (docker / tailscale down) =="
    cut_start="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    docker exec "$node_b" tailscale --socket=/tmp/tailscaled.sock down >/dev/null \
        || fail "tailscale down on agent-b failed"
    during_body="$(docker run --rm --network "container:$node_b" "$curl_image" \
        --silent --show-error --max-time 3 \
        --socks5-hostname 127.0.0.1:1055 "http://${agent_a_ip}:8443/health" 2>/dev/null || true)"
    during_ok=0
    echo "$during_body" | grep -q '"ok":true' && during_ok=1
    if [ "$during_ok" = "1" ]; then
        fail "agent endpoint still reachable during intended route cut"
    fi
    echo "during cut: unreachable (expected)"
    sleep "$reconnect_secs"
    cut_end="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    # Must restate all non-default prefs or `up` refuses to change settings.
    if ! docker exec "$node_b" timeout 45 tailscale --socket=/tmp/tailscaled.sock up \
        --login-server="$login_url" --hostname="$hostname_b" --accept-dns=false >/dev/null; then
        docker logs "$node_b" >&2 || true
        fail "tailscale up after cut failed on agent-b"
    fi
    post_body=""
    after_ok=0
    for _ in $(seq 1 60); do
        post_body="$(docker run --rm --network "container:$node_b" "$curl_image" \
            --fail --silent --show-error --max-time 5 \
            --socks5-hostname 127.0.0.1:1055 "http://${agent_a_ip}:8443/health" 2>/dev/null || true)"
        if echo "$post_body" | grep -q '"ok":true'; then
            after_ok=1
            break
        fi
        sleep 0.5
    done
    [ "$after_ok" = "1" ] || fail "agent endpoint did not recover after ${reconnect_secs}s cut: $post_body"
    # Same agent payload — no silent rewrite of the served object
    echo "$post_body" | grep -q '"agent":"agent-a"' \
        || fail "post-resume body lost agent identity: $post_body"
    write_reconnect_evidence "docker_tailscale_down" "0" "1" \
        "$cut_start" "$cut_end" "$agent_a_ip" "$pre_body" "$post_body"
    echo "[PASS] reconnect cut ${reconnect_secs}s: down→unreachable→up→8443 recovered"
}

run_reconnect_cut_host() {
    sock_a=$1
    sock_b=$2
    socks_b=$3
    agent_a_ip=$4
    pre_body=$5
    hostname_b=$6
    [ "$reconnect_cut" = "1" ] || return 0
    echo "== reconnect cut ${reconnect_secs}s (host / tailscale down) =="
    cut_start="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    tailscale --socket="$sock_b" down >/dev/null || fail "tailscale down on agent-b failed"
    during_body="$(curl --silent --show-error --max-time 3 \
        --socks5-hostname "127.0.0.1:$socks_b" \
        "http://${agent_a_ip}:8443/health" 2>/dev/null || true)"
    during_ok=0
    echo "$during_body" | grep -q '"ok":true' && during_ok=1
    [ "$during_ok" = "0" ] || fail "agent endpoint still reachable during intended route cut"
    echo "during cut: unreachable (expected)"
    sleep "$reconnect_secs"
    cut_end="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    tailscale --socket="$sock_b" up \
        --login-server="$login_url" --hostname="$hostname_b" --accept-dns=false \
        || fail "tailscale up after cut failed on agent-b"
    post_body=""
    after_ok=0
    for _ in $(seq 1 60); do
        post_body="$(curl --fail --silent --show-error --max-time 5 \
            --socks5-hostname "127.0.0.1:$socks_b" \
            "http://${agent_a_ip}:8443/health" 2>/dev/null || true)"
        if echo "$post_body" | grep -q '"ok":true'; then
            after_ok=1
            break
        fi
        sleep 0.5
    done
    [ "$after_ok" = "1" ] || fail "agent endpoint did not recover after ${reconnect_secs}s cut: $post_body"
    echo "$post_body" | grep -q '"agent":"agent-a"' \
        || fail "post-resume body lost agent identity: $post_body"
    write_reconnect_evidence "host_tailscale_down" "0" "1" \
        "$cut_start" "$cut_end" "$agent_a_ip" "$pre_body" "$post_body"
    echo "[PASS] reconnect cut ${reconnect_secs}s: down→unreachable→up→8443 recovered"
}

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

if [ "${FRACTALOS_MESH_DOCKER:-0}" = "1" ] || ! command -v tailscaled >/dev/null; then
    command -v docker >/dev/null || skip "tailscaled or Docker is required"
    image="${FRACTALOS_TAILSCALE_IMAGE:-tailscale/tailscale:v1.102.3}"
    endpoint_image="${FRACTALOS_MESH_ENDPOINT_IMAGE:-nginx:1.29-alpine}"
    curl_image="${FRACTALOS_MESH_CURL_IMAGE:-curlimages/curl:8.16.0}"
    suffix="$$"
    docker_network="fractalos-mesh-${suffix}"
    node_a="fractalos-mesh-a-${suffix}"
    node_b="fractalos-mesh-b-${suffix}"
    endpoint="fractalos-mesh-endpoint-${suffix}"
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
            docker cp "$ca_file" "$name:/usr/local/share/ca-certificates/fractalos-headscale.crt"
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
    run_reconnect_cut_docker "$node_a" "$node_b" "$curl_image" "$agent_a_ip" "$response" "agent-b"
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
run_reconnect_cut_host "$work/a.sock" "$work/b.sock" 29055 "$agent_a_ip" "$response" "agent-b"
echo "[PASS] two standard Tailscale nodes enrolled and agent endpoint invoked"
