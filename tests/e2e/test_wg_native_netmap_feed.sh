#!/bin/sh
# fos-gz0.5 native path — Headscale node list → packed OP_WG_APPLY_NETMAP feed.
#
# Proves the host converter + packed layout (L2). Does NOT claim live
# FractalOS-without-tailscaled join.

set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

EVIDENCE_DIR="$ROOT/build/evidence"
EVIDENCE="$EVIDENCE_DIR/wg-native-netmap-feed.json"
UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
REV=$(git rev-parse HEAD)
FIX="$ROOT/tests/fixtures/headscale_nodes_two.json"
OUT="$EVIDENCE_DIR/wg-netmap-from-fixture.bin"

mkdir -p "$EVIDENCE_DIR"

echo "== cargo test -p wg-headscale-netmap =="
cargo test -p wg-headscale-netmap -- --nocapture

echo "== encode fixture to packed netmap =="
cargo run -p wg-headscale-netmap --quiet -- encode --input "$FIX" --output "$OUT"
SIZE=$(wc -c < "$OUT" | tr -d ' ')
# header 8 + 2 peers * 48 = 104
[ "$SIZE" -eq 104 ] || {
    echo "FAIL: expected 104-byte netmap, got $SIZE" >&2
    exit 1
}

echo "== apply packed blob via host wg_net suite =="
cargo xtask test --suite test_wg_netmap

cat > "$EVIDENCE" <<EOF
{
  "schema": "fractalos.wg_native_netmap_feed.v1",
  "task_id": "fos-gz0.5",
  "generated_at": "$UTC",
  "controlplane_revision": "$REV",
  "proof_class": "host_feed",
  "claims_live_native_join": false,
  "tool": "tools/wg-headscale-netmap",
  "fixture": "tests/fixtures/headscale_nodes_two.json",
  "packed_bytes": $SIZE,
  "apply_suite": "test_wg_netmap",
  "status": "PASSING",
  "remaining": [
    "Noise/ts2021 login to Headscale control plane from FractalOS",
    "Live native join without guest tailscaled",
    "Interoperate with standard Tailscale clients from wg_net PD"
  ],
  "note": "Interim multi-machine (14.19) uses Tailscale clients; this feed is the native netmap bridge once login exists"
}
EOF

echo "PASS: Headscale→netmap feed host proof ($SIZE bytes)"
echo "wrote $EVIDENCE"
