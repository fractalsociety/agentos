#!/usr/bin/env bash
# Boot the baked FreeBSD image and prove the Headscale first-boot role.
set -euo pipefail

fail() { echo "[FAIL] $*" >&2; exit 1; }
repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
image="${FRACTALOS_FREEBSD_MESH_IMAGE:-$repo_root/build/guest-images/freebsd15-mesh-controller.img}"
key="${E2E_SSH_KEY:-$repo_root/tests/e2e/id_ed25519}"
[ -s "$image" ] || fail "FreeBSD mesh image not found: $image"
[ -s "$key" ] || fail "E2E SSH key not found: $key"
command -v qemu-system-x86_64 >/dev/null || fail "qemu-system-x86_64 is required"

firmware="${QEMU_X86_UEFI:-}"
if [ -z "$firmware" ]; then
    for candidate in \
        /opt/homebrew/share/qemu/edk2-x86_64-code.fd \
        /usr/local/share/qemu/edk2-x86_64-code.fd \
        /usr/share/qemu/edk2-x86_64-code.fd; do
        if [ -f "$candidate" ]; then firmware="$candidate"; break; fi
    done
fi
[ -s "$firmware" ] || fail "x86_64 EDK2 firmware is required"

read -r ssh_port http_port <<EOF
$(python3 - <<'PY'
import socket
s=[]; p=[]
for _ in range(2):
    sock=socket.socket(); sock.bind(('127.0.0.1', 0)); s.append(sock); p.append(sock.getsockname()[1])
print(*p)
PY
)
EOF
work="$(mktemp -d /tmp/fractalos-freebsd-mesh-e2e.XXXXXX)"
qemu_pid=""
cleanup() {
    [ -z "$qemu_pid" ] || kill "$qemu_pid" 2>/dev/null || true
    [ -z "$qemu_pid" ] || wait "$qemu_pid" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

qemu-system-x86_64 \
    -machine q35 -m 2048 \
    -snapshot \
    -drive "if=pflash,format=raw,unit=0,readonly=on,file=$firmware" \
    -drive "file=$image,if=virtio,format=raw" \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${ssh_port}-:22,hostfwd=tcp:127.0.0.1:${http_port}-:8080" \
    -device virtio-net-pci,netdev=net0 \
    -display none -monitor none -serial "file:$work/serial.log" &
qemu_pid=$!

ssh_args=(-i "$key" -p "$ssh_port" -o BatchMode=yes -o StrictHostKeyChecking=no \
          -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3)
scp_args=(-i "$key" -P "$ssh_port" -o BatchMode=yes -o StrictHostKeyChecking=no \
          -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3)
ready=0
for _ in $(seq 1 300); do
    kill -0 "$qemu_pid" 2>/dev/null || { tail -100 "$work/serial.log" >&2; fail "FreeBSD VM exited"; }
    if ssh "${ssh_args[@]}" root@127.0.0.1 true >/dev/null 2>&1; then ready=1; break; fi
    sleep 2
done
[ "$ready" = 1 ] || { tail -100 "$work/serial.log" >&2; fail "SSH did not become ready"; }

role_ready=0
for _ in $(seq 1 300); do
    kill -0 "$qemu_pid" 2>/dev/null || { tail -100 "$work/serial.log" >&2; fail "FreeBSD VM exited during role installation"; }
    if ssh "${ssh_args[@]}" root@127.0.0.1 \
        "test -f /var/db/fractalos-mesh-controller.installed" >/dev/null 2>&1; then
        role_ready=1
        break
    fi
    sleep 2
done
if [ "$role_ready" != 1 ]; then
    ssh "${ssh_args[@]}" root@127.0.0.1 \
        "set +e; tail -200 /var/log/fractalos-mesh-firstboot.log; \
         pgrep -laf 'pkg|fetch|headscale|fractalos'; tail -100 /var/log/messages" >&2 || true
    tail -100 "$work/serial.log" >&2
    fail "mesh-controller first boot did not complete"
fi

remote_check() {
    description=$1
    command=$2
    if ! ssh "${ssh_args[@]}" root@127.0.0.1 "$command"; then
        fail "$description"
    fi
}

remote_check "Headscale service is not running" \
    "service headscale onestatus"
remote_check "Headscale is not pinned to 0.29.3" \
    "/usr/local/sbin/headscale version | grep -q '0.29.3'"
remote_check "Headscale secret directory permissions are not 0700" \
    "test \"\$(stat -f %Lp /var/db/fractalos-secrets/headscale)\" = 700"
remote_check "Headscale API token permissions are not 0600" \
    "test \"\$(stat -f %Lp /var/db/fractalos-secrets/headscale/api.token)\" = 600"
if ! ssh "${ssh_args[@]}" root@127.0.0.1 \
    "test -s /var/db/headscale/netcap-state.json"; then
    ssh "${ssh_args[@]}" root@127.0.0.1 \
        "set +e; echo '--- /var/db/headscale'; ls -la /var/db/headscale; \
         echo '--- python'; command -v python3; python3 --version; \
         echo '--- reconciliation'; /usr/local/sbin/fractalos-headscale-policy-sync; echo status=\$?; \
         echo '--- state search'; find /var/db -name 'netcap-state*' -ls" >&2 || true
    fail "NetCap reconciliation state is missing"
fi

scp "${scp_args[@]}" root@127.0.0.1:/var/db/fractalos-secrets/headscale/tls.crt "$work/tls.crt" >/dev/null
curl --fail --silent --show-error --noproxy '*' --cacert "$work/tls.crt" \
    --resolve "mesh.fractalos.internal:${http_port}:127.0.0.1" \
    "https://mesh.fractalos.internal:${http_port}/health" \
    | grep -q '"status":"pass"' || fail "Headscale TLS health check failed"

echo "[PASS] FreeBSD first boot installed and started Headscale 0.29.3"
