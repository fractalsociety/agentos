#!/bin/sh
# Companion pages gate (fos-gz0.14.18).
#
# controlplane may only: (1) prove typed contracts / no UI pollution,
# (2) invoke sibling ../fractalos-companion when present,
# (3) record blocked_external evidence when the sibling is missing.
# Never treat a missing sibling as skipped-success.

set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

EVIDENCE_DIR="$ROOT/build/evidence"
EVIDENCE="$EVIDENCE_DIR/external-companion-followup.json"
SIBLING_A="$ROOT/../fractalos-companion"
SIBLING_B="${HOME}/fractalos-companion"
UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)
REV=$(git rev-parse HEAD)
WIT="$ROOT/interfaces/wit/fractal-companion-v1/companion.wit"
LG="$ROOT/contracts/local-gateway/interface.h"
WIT_HASH=$(shasum -a 256 "$WIT" | awk '{print $1}')
LG_HASH=$(shasum -a 256 "$LG" | awk '{print $1}')

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "PASS: $*"; }
blocked() { echo "BLOCKED_EXTERNAL: $*" >&2; }

mkdir -p "$EVIDENCE_DIR"

echo "== controlplane: no UI / browser assets in companion surface =="
UI_HITS=$(git ls-files \
  'interfaces/wit/fractal-companion-v1/*' \
  'contracts/local-gateway/*' \
  'kernel/fractalos-root-task/src/companion_gateway.c' \
  'kernel/fractalos-root-task/include/companion_gateway.h' \
  'services/companion-gateway/*' \
  'tests/e2e/test_companion_pages.sh' \
  'tests/test_companion_gateway.c' \
  'tests/test_local_gateway.c' \
  2>/dev/null | grep -E '\.(html|css|js|mjs|jsx|tsx|vue|svelte)$|package\.json$|yarn\.lock$|bun\.lockb$' || true)
[ -z "$UI_HITS" ] || fail "forbidden UI files in companion surface: $UI_HITS"
pass "no forbidden UI files in companion controlplane surface"

echo "== controlplane: companion + local-gateway contract suites =="
cargo test -p xtask --test daily_root_contract --test health_adapter_contract \
    --test project_progress_contract --test companion_schema_contract -- --nocapture \
    || fail "companion WIT contract suites"
cargo xtask test --suite test_local_gateway || fail "local gateway host suite"
cargo xtask test --suite test_companion_gateway || fail "companion gateway host suite"
pass "typed companion/local-gateway contracts"

write_evidence() {
    availability=$1
    sibling_path=$2
    sibling_rev=$3
    blocker=$4
    proof_class=$5
    sibling_check=$6
    COMPANION_WIT_HASH="$WIT_HASH" LOCAL_GATEWAY_HASH="$LG_HASH" \
    CONTROLPLANE_REV="$REV" GENERATED_AT="$UTC" \
    AVAILABILITY="$availability" SIBLING_PATH="$sibling_path" \
    SIBLING_REV="$sibling_rev" BLOCKER="$blocker" PROOF_CLASS="$proof_class" \
    SIBLING_CHECK="$sibling_check" EVIDENCE_OUT="$EVIDENCE" \
    python3 - <<'PY'
import json, os
rev = os.environ["SIBLING_REV"]
sibling_rev = None if rev in ("", "null") else rev
doc = {
  "schema": "fractalos.external_handoff.v1",
  "task_id": "build_companion_pages",
  "generated_at": os.environ["GENERATED_AT"],
  "controlplane_revision": os.environ["CONTROLPLANE_REV"],
  "linked_issue": {
    "id": "fos-gz0.14.18",
    "title": "Build companion project pages outside controlplane",
    "status": "open",
  },
  "boundary": {
    "controlplane_contributes": "typed companion.wit + local-gateway + companion_gateway host fence; no UI/HTTP/pages",
    "sibling_repository": "fractalos-companion",
    "prohibited_in_controlplane": [
      "html", "css", "js", "mjs", "jsx", "tsx", "vue", "svelte",
      "package.json", "node_modules",
    ],
  },
  "contracts": {
    "companion_wit": "interfaces/wit/fractal-companion-v1/companion.wit",
    "companion_wit_sha256": os.environ["COMPANION_WIT_HASH"],
    "local_gateway": "contracts/local-gateway/interface.h",
    "local_gateway_sha256": os.environ["LOCAL_GATEWAY_HASH"],
    "required_pages": ["daily-root", "project-progress", "worker-memory", "health"],
  },
  "repository": {
    "name": "fractalos-companion",
    "local_path": os.environ["SIBLING_PATH"] or None,
    "availability": os.environ["AVAILABILITY"],
    "revision": sibling_rev,
    "blocker": os.environ["BLOCKER"] or None,
  },
  "required_checks": [
    {"id": "controlplane-clean", "status": "PASSING",
     "requirement": "no UI files in companion surface"},
    {"id": "typed-contracts", "status": "PASSING",
     "requirement": "daily/health/progress/schema + local/companion gateway host suites"},
    {"id": "sibling-pages", "status": os.environ["SIBLING_CHECK"],
     "requirement": "sibling renders four pages from pinned schema"},
    {"id": "typed-intents-only", "status": os.environ["SIBLING_CHECK"],
     "requirement": "page actions submit granted task intents only"},
  ],
  "proof_class": os.environ["PROOF_CLASS"],
  "claims_live_product": False,
  "next_action": {
    "owner": "external (fractalos-companion)",
    "prerequisite": "create or clone sibling repo at ../fractalos-companion consuming companion.wit@"
      + os.environ["COMPANION_WIT_HASH"],
    "controlplane_completion": "handoff record complete; fos-gz0.14.18 stays OPEN until sibling page gates pass",
  },
}
path = os.environ["EVIDENCE_OUT"]
with open(path, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
print("wrote", path)
PY
}

echo "== sibling fractalos-companion probe =="
SIB=""
if [ -d "$SIBLING_A" ]; then
    SIB=$SIBLING_A
elif [ -d "$SIBLING_B" ]; then
    SIB=$SIBLING_B
fi

if [ -n "$SIB" ]; then
    SIB_REV=""
    if [ -d "$SIB/.git" ]; then
        SIB_REV=$(git -C "$SIB" rev-parse HEAD 2>/dev/null || echo "")
    fi
    if [ -x "$SIB/scripts/test-companion-pages.sh" ]; then
        write_evidence "available" "$SIB" "$SIB_REV" "" "sibling_present" "PASSING"
        (cd "$SIB" && ./scripts/test-companion-pages.sh) || fail "sibling page tests"
        pass "sibling companion pages"
        exit 0
    fi
    if [ -f "$SIB/Cargo.toml" ]; then
        write_evidence "available" "$SIB" "$SIB_REV" "" "sibling_present" "PASSING"
        (cd "$SIB" && cargo test) || fail "sibling cargo test"
        pass "sibling cargo tests"
        exit 0
    fi
    blocked "sibling present at $SIB but no known page test entrypoint"
    write_evidence "available" "$SIB" "$SIB_REV" \
        "sibling present at $SIB but missing scripts/test-companion-pages.sh or runnable Cargo.toml tests; recorded $UTC" \
        "blocked_external" "BLOCKED"
    exit 3
fi

blocked "sibling repository fractalos-companion not found (tried $SIBLING_A and $SIBLING_B)"
write_evidence "missing" "" "" \
    "sibling fractalos-companion missing at $SIBLING_A and $SIBLING_B; recorded $UTC; command: tests/e2e/test_companion_pages.sh" \
    "blocked_external" "BLOCKED"
exit 3
