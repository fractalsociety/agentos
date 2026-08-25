#!/bin/sh
# Two-device Fractal vertical-slice E2E gate (fos-gz0.14.19).
#
# Default: run L2 host supporting suites and record proof_class=host_support.
# Live L3 (interim data plane = Headscale + standard Tailscale clients):
#   FRACTALOS_TWO_DEVICE_LIVE=1 plus Headscale URL/token.
# Missing prerequisites → exit 3 blocked_external (never skip-success).
# Native wg_net Headscale join is fos-gz0.5 and is NOT claimed here.

set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

EVIDENCE_DIR="$ROOT/build/evidence"
EVIDENCE="$EVIDENCE_DIR/two-device-vertical-slice.json"
TOPOLOGY_JSON="$EVIDENCE_DIR/two-device-topology.json"
CHECKLIST_JSON="$EVIDENCE_DIR/two-device-checklist.json"
UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
REV=$(git rev-parse HEAD)
HELPER="${AGENTCTL_MESH_HELPER:-$ROOT/tools/agentctl/agentctl-mesh}"
MESH_URL="${FRACTALOS_HEADSCALE_URL:-}"
TOKEN_FILE="${FRACTALOS_HEADSCALE_TOKEN_FILE:-}"
CA_FILE="${FRACTALOS_HEADSCALE_CA_FILE:-}"
SIBLING_A="$ROOT/../fractalos-companion"
SIBLING_B="${HOME}/fractalos-companion"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }
blocked() { echo "BLOCKED_EXTERNAL: $*" >&2; }

mkdir -p "$EVIDENCE_DIR"

echo "== L2 host supporting suites =="
cargo xtask test --suite test_remote_grants || fail "remote grants"
cargo xtask test --suite test_shared_space_replication || fail "shared space"
cargo xtask test --suite test_local_gateway || fail "local gateway"
cargo xtask test --suite test_companion_gateway || fail "companion gateway"
cargo test -p fractal-worker-compat --test test_cursor_worker \
    --test test_remote_worker_sessions -- --nocapture \
    || fail "worker session / cursor contracts"
pass "host supporting suites"

# Companion sibling (fos-gz0.14.18) — pages gate must stay green for vertical slice.
COMPANION_STATUS="MISSING"
COMPANION_REV=""
SIB=""
if [ -d "$SIBLING_A" ]; then
    SIB=$SIBLING_A
elif [ -d "$SIBLING_B" ]; then
    SIB=$SIBLING_B
fi
if [ -n "$SIB" ] && [ -x "$SIB/scripts/test-companion-pages.sh" ]; then
    (cd "$SIB" && ./scripts/test-companion-pages.sh) || fail "companion sibling pages"
    COMPANION_STATUS="PASSING"
    if [ -d "$SIB/.git" ]; then
        COMPANION_REV=$(git -C "$SIB" rev-parse HEAD 2>/dev/null || echo "")
    fi
    pass "companion sibling pages"
else
    echo "NOTE: companion sibling missing or no page gate; live checklist will mark companion_pages PENDING"
fi

write_checklist() {
    mesh_smoke=$1
    topology=$2
    nodes_ok=$3
    reachability=$4
    grants=$5
    shared_space=$6
    companion=$7
    reconnect=$8
    cat > "$CHECKLIST_JSON" <<EOF
{
  "schema": "fractalos.two_device_checklist.v1",
  "generated_at": "$UTC",
  "data_plane": "interim_tailscale_clients",
  "items": [
    {"id": "host_support_suites", "status": "PASSING",
     "note": "grants/shared-space/gateways/workers host suites"},
    {"id": "mesh_two_client_smoke", "status": "$mesh_smoke",
     "note": "test_headscale_mesh.sh enroll + port 8443 reachability"},
    {"id": "topology_capture", "status": "$topology",
     "note": "NodeIDs/hostnames captured via agentctl mesh nodes"},
    {"id": "two_distinct_node_ids", "status": "$nodes_ok",
     "note": "at least two enrolled node identities"},
    {"id": "policy_port_8443_reachability", "status": "$reachability",
     "note": "bidirectional agent endpoint via WireGuard/Tailscale"},
    {"id": "grant_deny_host", "status": "$grants",
     "note": "test_remote_grants supporting evidence"},
    {"id": "shared_space_cas_host", "status": "$shared_space",
     "note": "test_shared_space_replication supporting evidence"},
    {"id": "companion_pages_sibling", "status": "$companion",
     "note": "fractalos-companion page gate; intents via companion_gateway host"},
    {"id": "reconnect_cut_30s_live", "status": "$reconnect",
     "note": "AC-2 live route cut ~30s (tailscale down) + host worker reconnect suite"}
  ]
}
EOF
}

write_evidence() {
    proof_class=$1
    live_requested=$2
    blocker=$3
    live_ok=$4
    mesh_status=$5
    PROOF_CLASS="$proof_class" LIVE_REQUESTED="$live_requested" \
    BLOCKER="$blocker" LIVE_OK="$live_ok" CONTROLPLANE_REV="$REV" \
    GENERATED_AT="$UTC" EVIDENCE_OUT="$EVIDENCE" \
    TOPOLOGY_PATH="$TOPOLOGY_JSON" CHECKLIST_PATH="$CHECKLIST_JSON" \
    MESH_STATUS="$mesh_status" COMPANION_STATUS="$COMPANION_STATUS" \
    COMPANION_REV="$COMPANION_REV" MESH_URL="$MESH_URL" \
    python3 - <<'PY'
import json, os
from pathlib import Path

blocker = os.environ["BLOCKER"] or None
topology = None
topo_path = Path(os.environ["TOPOLOGY_PATH"])
if topo_path.is_file() and topo_path.stat().st_size > 0:
    try:
        topology = json.loads(topo_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        topology = {"error": "invalid topology json"}

checklist = None
chk_path = Path(os.environ["CHECKLIST_PATH"])
if chk_path.is_file() and chk_path.stat().st_size > 0:
    try:
        checklist = json.loads(chk_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        checklist = {"error": "invalid checklist json"}

doc = {
  "schema": "fractalos.two_device_vertical_slice.v1",
  "task_id": "fos-gz0.14.19",
  "generated_at": os.environ["GENERATED_AT"],
  "controlplane_revision": os.environ["CONTROLPLANE_REV"],
  "linked_issue": {
    "id": "fos-gz0.14.19",
    "title": "Run the two-device Fractal vertical-slice E2E gate",
    "status": "open",
  },
  "proof_class": os.environ["PROOF_CLASS"],
  "live_requested": os.environ["LIVE_REQUESTED"] == "1",
  "claims_live_product": os.environ["LIVE_OK"] == "1",
  "data_plane": {
    "mode": "interim_tailscale_clients",
    "note": "Headscale coordination + standard Tailscale WG clients; native wg_net join is fos-gz0.5",
    "headscale_url": os.environ.get("MESH_URL") or None,
  },
  "host_support": {
    "suites": [
      "test_remote_grants",
      "test_shared_space_replication",
      "test_local_gateway",
      "test_companion_gateway",
      "test_cursor_worker",
      "test_remote_worker_sessions",
    ],
    "status": "PASSING",
  },
  "companion_sibling": {
    "status": os.environ["COMPANION_STATUS"],
    "revision": os.environ["COMPANION_REV"] or None,
  },
  "mesh_smoke": {
    "harness": "tests/e2e/test_headscale_mesh.sh",
    "status": os.environ["MESH_STATUS"],
  },
  "topology": topology,
  "checklist": checklist,
  "live_environment": {
    "flag": "FRACTALOS_TWO_DEVICE_LIVE",
    "requires": [
      "FRACTALOS_HEADSCALE_URL",
      "FRACTALOS_HEADSCALE_TOKEN_FILE",
      "two enrolled Tailscale/Headscale device NodeIDs",
    ],
    "blocker": blocker,
  },
  "acceptance_map": {
    "signed_discovery": "live: mesh enroll + topology NodeIDs when live_partial+",
    "worker_reconnect": "live: reconnect_cut_30s (tailscale down) + host reconnect_preserves_handles suite",
    "shared_space_cas": "host: test_shared_space_replication",
    "grant_deny": "host: test_remote_grants",
    "companion_intents": "host: test_companion_gateway; sibling pages when PASSING",
  },
  "proof_class_rules": {
    "host_support": "host suites only; FRACTALOS_TWO_DEVICE_LIVE unset",
    "live_partial": "mesh two-client smoke + topology (≥2 nodes) + host suites; reconnect_cut may still be PENDING",
    "live_vertical_slice": "all checklist items PASSING including reconnect_cut_30s_live",
    "blocked_external": "live requested but prerequisites missing",
  },
  "next_action": {
    "owner": "operator",
    "command": "FRACTALOS_TWO_DEVICE_LIVE=1 FRACTALOS_HEADSCALE_URL=... FRACTALOS_HEADSCALE_TOKEN_FILE=... FRACTALOS_MESH_DOCKER=1 ./tests/e2e/test_two_device_fractal.sh",
    "physical": "./tests/e2e/run_two_device_physical.sh  # same gate after tailscale up on two machines",
    "note": "Close fos-gz0.14.19 only with proof_class=live_vertical_slice",
  },
}
with open(os.environ["EVIDENCE_OUT"], "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
print("wrote", os.environ["EVIDENCE_OUT"])
PY
}

capture_topology() {
    # Best-effort NodeID capture via agentctl-mesh. Missing helper → empty topology.
    : > "$TOPOLOGY_JSON"
    if [ ! -x "$HELPER" ] && [ ! -f "$HELPER" ]; then
        # Try built agentctl binary path
        if [ -x "$ROOT/tools/agentctl/agentctl" ]; then
            HELPER="$ROOT/tools/agentctl/agentctl"
        else
            echo '{"captured":false,"reason":"agentctl mesh helper missing"}' > "$TOPOLOGY_JSON"
            return 1
        fi
    fi
    mesh_args="--url $MESH_URL --token-file $TOKEN_FILE"
    if [ -n "$CA_FILE" ]; then
        mesh_args="$mesh_args --ca-file $CA_FILE"
    fi
    # Prefer agentctl-mesh wrapper; fall back to `agentctl mesh`.
    nodes_out=""
    if [ -x "$ROOT/tools/agentctl/agentctl-mesh" ]; then
        nodes_out=$("$ROOT/tools/agentctl/agentctl-mesh" $mesh_args nodes 2>/dev/null || true)
    elif command -v agentctl >/dev/null 2>&1; then
        nodes_out=$(agentctl mesh $mesh_args nodes 2>/dev/null || true)
    elif [ -x "$ROOT/tools/agentctl/agentctl" ]; then
        nodes_out=$("$ROOT/tools/agentctl/agentctl" mesh $mesh_args nodes 2>/dev/null || true)
    fi
    if [ -z "$nodes_out" ]; then
        echo "{\"captured\":false,\"reason\":\"mesh nodes command produced no output\",\"url\":\"$MESH_URL\",\"at\":\"$UTC\"}" \
            > "$TOPOLOGY_JSON"
        return 1
    fi
    NODES_RAW="$nodes_out" GENERATED_AT="$UTC" MESH_URL="$MESH_URL" \
    TOPOLOGY_OUT="$TOPOLOGY_JSON" python3 - <<'PY'
import json, os, re
raw = os.environ["NODES_RAW"]
url = os.environ["MESH_URL"]
at = os.environ["GENERATED_AT"]
nodes = []
try:
    payload = json.loads(raw)
    # agentctl emits {"result": ...} or a bare list/dict
    result = payload.get("result", payload) if isinstance(payload, dict) else payload
    candidates = []
    if isinstance(result, list):
        candidates = result
    elif isinstance(result, dict):
        for key in ("nodes", "Nodes", "items"):
            if isinstance(result.get(key), list):
                candidates = result[key]
                break
        if not candidates:
            candidates = [result]
    for item in candidates:
        if not isinstance(item, dict):
            continue
        nid = item.get("id") or item.get("nodeId") or item.get("NodeID") or item.get("name")
        host = item.get("hostname") or item.get("name") or item.get("givenName")
        ip = item.get("ip") or item.get("ipv4") or item.get("address")
        nodes.append({"id": str(nid) if nid is not None else None,
                      "hostname": host, "ip": ip, "raw_keys": sorted(item.keys())})
except json.JSONDecodeError:
    # Fallback: scrape id-looking tokens
    for m in re.finditer(r'"id"\s*:\s*"([^"]+)"', raw):
        nodes.append({"id": m.group(1), "hostname": None, "ip": None})

doc = {
  "captured": True,
  "at": at,
  "headscale_url": url,
  "node_count": len(nodes),
  "nodes": nodes,
  "distinct_ids": sorted({n["id"] for n in nodes if n.get("id")}),
}
Path = __import__("pathlib").Path
Path(os.environ["TOPOLOGY_OUT"]).write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
print("topology nodes:", doc["node_count"], "distinct:", len(doc["distinct_ids"]))
PY
}

if [ "${FRACTALOS_TWO_DEVICE_LIVE:-0}" != "1" ]; then
    write_checklist "PENDING" "PENDING" "PENDING" "PENDING" \
        "PASSING" "PASSING" "$COMPANION_STATUS" "PENDING"
    blocked "FRACTALOS_TWO_DEVICE_LIVE unset — host support only; L3 not claimed"
    write_evidence "host_support" "0" \
        "FRACTALOS_TWO_DEVICE_LIVE unset at $UTC; host suites passed; L3 two-device proof not run" \
        "0" "NOT_RUN"
    exit 3
fi

# Live path prerequisites — fail closed
[ -n "$MESH_URL" ] || {
    write_checklist "BLOCKED" "BLOCKED" "BLOCKED" "BLOCKED" \
        "PASSING" "PASSING" "$COMPANION_STATUS" "PENDING"
    blocked "FRACTALOS_HEADSCALE_URL unset"
    write_evidence "blocked_external" "1" "FRACTALOS_HEADSCALE_URL unset at $UTC" "0" "NOT_RUN"
    exit 3
}
[ -s "$TOKEN_FILE" ] || {
    write_checklist "BLOCKED" "BLOCKED" "BLOCKED" "BLOCKED" \
        "PASSING" "PASSING" "$COMPANION_STATUS" "PENDING"
    blocked "FRACTALOS_HEADSCALE_TOKEN_FILE missing/empty"
    write_evidence "blocked_external" "1" "FRACTALOS_HEADSCALE_TOKEN_FILE missing at $UTC" "0" "NOT_RUN"
    exit 3
}

MESH_STATUS="FAILING"
if [ ! -x "$ROOT/tests/e2e/test_headscale_mesh.sh" ]; then
    write_checklist "BLOCKED" "BLOCKED" "BLOCKED" "BLOCKED" \
        "PASSING" "PASSING" "$COMPANION_STATUS" "PENDING"
    blocked "test_headscale_mesh.sh missing/not executable"
    write_evidence "blocked_external" "1" "mesh harness missing at $UTC" "0" "NOT_RUN"
    exit 3
fi

# Live vertical slice requires AC-2 reconnect cut inside the mesh harness.
export FRACTALOS_MESH_RECONNECT_CUT=1
export FRACTALOS_MESH_RECONNECT_SECONDS="${FRACTALOS_MESH_RECONNECT_SECONDS:-30}"
export FRACTALOS_RECONNECT_EVIDENCE="$EVIDENCE_DIR/two-device-reconnect-cut.json"
rm -f "$FRACTALOS_RECONNECT_EVIDENCE"

set +e
"$ROOT/tests/e2e/test_headscale_mesh.sh"
mesh_st=$?
set -e

if [ "$mesh_st" -eq 2 ]; then
    write_checklist "BLOCKED" "BLOCKED" "BLOCKED" "BLOCKED" \
        "PASSING" "PASSING" "$COMPANION_STATUS" "PENDING"
    blocked "test_headscale_mesh.sh skipped prerequisites (exit 2)"
    write_evidence "blocked_external" "1" \
        "test_headscale_mesh.sh exit 2 (skip) at $UTC" "0" "SKIPPED"
    exit 3
fi
if [ "$mesh_st" -ne 0 ]; then
    fail "test_headscale_mesh.sh failed (exit $mesh_st)"
fi
MESH_STATUS="PASSING"
pass "headscale mesh two-client smoke"

TOPO_STATUS="FAILING"
NODES_STATUS="FAILING"
if capture_topology; then
    TOPO_STATUS="PASSING"
    # Require ≥2 distinct ids when captured
    DISTINCT=$(python3 -c "import json; d=json.load(open('$TOPOLOGY_JSON')); print(len(d.get('distinct_ids') or []))")
    if [ "$DISTINCT" -ge 2 ]; then
        NODES_STATUS="PASSING"
        pass "topology: $DISTINCT distinct NodeIDs"
    else
        echo "NOTE: topology captured fewer than 2 distinct ids ($DISTINCT)"
    fi
else
    echo "NOTE: topology capture incomplete; checklist will not claim live_vertical_slice"
fi

REACH_STATUS="PASSING"  # mesh smoke already proved 8443 path
GRANTS_STATUS="PASSING"
SHARED_STATUS="PASSING"
RECONNECT_STATUS="PENDING"
RECONNECT_EVIDENCE="$EVIDENCE_DIR/two-device-reconnect-cut.json"
if [ -s "$RECONNECT_EVIDENCE" ]; then
    RECONNECT_STATUS=$(python3 -c "import json; print(json.load(open('$RECONNECT_EVIDENCE')).get('status','PENDING'))")
fi
if [ "$RECONNECT_STATUS" != "PASSING" ]; then
    fail "reconnect_cut_30s_live not PASSING (see $RECONNECT_EVIDENCE); refuse live_vertical_slice"
fi

# AC-2 session semantics (handles / no duplicate effects) — host supporting after live cut
echo "== AC-2 host worker reconnect suite (post live cut) =="
cargo test -p fractal-worker-compat --test test_remote_worker_sessions \
    reconnect_preserves_handles_and_avoids_duplicate_effects -- --nocapture \
    || fail "worker reconnect host suite after live cut"
pass "worker reconnect host suite after live cut"

write_checklist "$MESH_STATUS" "$TOPO_STATUS" "$NODES_STATUS" "$REACH_STATUS" \
    "$GRANTS_STATUS" "$SHARED_STATUS" "$COMPANION_STATUS" "$RECONNECT_STATUS"

# live_vertical_slice only when reconnect + companion + nodes all PASSING
PROOF="live_partial"
LIVE_OK="0"
if [ "$MESH_STATUS" = "PASSING" ] && [ "$NODES_STATUS" = "PASSING" ] \
    && [ "$COMPANION_STATUS" = "PASSING" ] && [ "$RECONNECT_STATUS" = "PASSING" ]; then
    PROOF="live_vertical_slice"
    LIVE_OK="1"
fi

write_evidence "$PROOF" "1" "" "$LIVE_OK" "$MESH_STATUS"

if [ "$PROOF" = "live_partial" ]; then
    echo "NOTE: proof_class=live_partial — reconnect_cut_30s_live still PENDING; fos-gz0.14.19 stays open"
    echo "NOTE: physical expansion: ./tests/e2e/run_two_device_physical.sh"
    exit 0
fi

pass "live_vertical_slice checklist complete"
exit 0
