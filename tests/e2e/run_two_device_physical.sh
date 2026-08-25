#!/bin/sh
# Physical / VM two-device expansion for fos-gz0.14.19.
#
# Same gate as Docker interim clients. On each machine:
#   1. Install Tailscale
#   2. Create a pre-auth key on the controller:
#        agentctl mesh --url "$FRACTALOS_HEADSCALE_URL" \
#          --token-file "$FRACTALOS_HEADSCALE_TOKEN_FILE" \
#          enroll-key --ttl-seconds 600
#   3. tailscale up --login-server="$FRACTALOS_HEADSCALE_URL" --auth-key='…'
#   4. Ensure tag:agent policy allows port 8443 between agents
#
# Then run this script from the controlplane checkout (controller host).

set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)

[ -n "${FRACTALOS_HEADSCALE_URL:-}" ] || {
    echo "Set FRACTALOS_HEADSCALE_URL" >&2
    exit 3
}
[ -s "${FRACTALOS_HEADSCALE_TOKEN_FILE:-}" ] || {
    echo "Set FRACTALOS_HEADSCALE_TOKEN_FILE to a non-empty token file" >&2
    exit 3
}

# Do NOT force Docker — use host tailscaled clients already enrolled.
export FRACTALOS_TWO_DEVICE_LIVE=1
unset FRACTALOS_MESH_DOCKER || true

echo "== physical/VM two-device vertical slice =="
echo "URL=$FRACTALOS_HEADSCALE_URL"
echo "Ensure two machines are already enrolled before continuing."
exec "$ROOT/tests/e2e/test_two_device_fractal.sh"
