#!/bin/sh
# fos-gz0.5.1 — native Headscale Noise join host gate.
#
# Without live credentials: compile/unit tests only, exit 3 blocked_external.
# Live: FRACTALOS_MESH_CONTROL_LIVE=1 plus Headscale URL + auth key.

set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }
blocked() { echo "BLOCKED_EXTERNAL: $*" >&2; }

echo "== fractalos-mesh-control unit/build =="
cargo test -p fractalos-mesh-control --quiet || fail "unit tests"
cargo build -p fractalos-mesh-control --quiet || fail "build"
pass "fractalos-mesh-control builds"

# Offline encode path (fixture peers → packed netmap).
FIX="$ROOT/tests/fixtures/mesh_control_peers.json"
cat >"$FIX" <<'JSON'
[
  {
    "name": "a",
    "node_key_hex": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
    "allowed_ip": 1681915905,
    "endpoint_ip": 167772161,
    "endpoint_port": 51820
  }
]
JSON
OUT="$ROOT/build/mesh-control/fixture-netmap.bin"
mkdir -p "$(dirname "$OUT")"
cargo run -q -p fractalos-mesh-control -- encode-netmap \
  --input-json "$FIX" --output "$OUT" || fail "encode-netmap"
test -s "$OUT" || fail "empty netmap"
pass "offline packed netmap encode"

if [ "${FRACTALOS_MESH_CONTROL_LIVE:-0}" != "1" ]; then
    blocked "FRACTALOS_MESH_CONTROL_LIVE unset — skip live Noise join / DERP"
    exit 3
fi

: "${FRACTALOS_HEADSCALE_URL:?}"
: "${FRACTALOS_HEADSCALE_AUTH_KEY:?}"

cargo run -q -p fractalos-mesh-control -- join \
  --control-url "$FRACTALOS_HEADSCALE_URL" \
  --auth-key "$FRACTALOS_HEADSCALE_AUTH_KEY" \
  ${FRACTALOS_HEADSCALE_CA_FILE:+--ca-file "$FRACTALOS_HEADSCALE_CA_FILE"} \
  --hostname "fractalos-join-gate" \
  --key-file "$ROOT/build/mesh-control/live-keys.json" \
  --netmap-out "$ROOT/build/mesh-control/live-netmap.bin" \
  --timeout-secs "${FRACTALOS_MESH_CONTROL_TIMEOUT:-90}" \
  --derp-ping || fail "live join"

test -s "$ROOT/build/mesh-control/live-netmap.bin" || fail "live netmap missing"
pass "live ts2021 join + packed netmap (+ DERP if map provided)"
exit 0
