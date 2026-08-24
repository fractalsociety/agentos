#!/bin/sh
# Fractal compatibility workers E2E harness.
# Default: offline fixture / cargo contract tests (no model spend).
# Live Cursor branch: set FRACTAL_CURSOR_LIVE=1 (requires `cursor` on PATH).
# Exit 2 = opted-in live prerequisites unavailable (skip).

set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

skip() {
    echo "SKIP: $*" >&2
    exit 2
}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

pass() {
    echo "PASS: $*"
}

echo "== fractal-worker contract: cursor =="
cargo test -p fractal-worker-compat --test test_cursor_worker -- --nocapture \
    || fail "cursor compat tests"

echo "== fractal-worker fixture replay via fractal-cursor-worker =="
cargo build -p fractal-worker-compat --bin fractal-cursor-worker \
    || fail "build fractal-cursor-worker"
BIN="$ROOT/target/debug/fractal-cursor-worker"
FIXTURE="$ROOT/tests/fixtures/cursor-worker"
OUT=$(mktemp "${TMPDIR:-/tmp}/fractal-cursor-replay.XXXXXX.json")
trap 'rm -f "$OUT"' EXIT HUP INT TERM

"$BIN" replay-session \
    --workspace-id e2e-replay \
    --root-object-id root \
    --allowed-file src/health.c \
    --jsonl-file "$FIXTURE/session.jsonl" \
    --peak-rss-bytes 1048576 \
    --secret-handle "handle:e2e-cursor" \
    >"$OUT" || fail "replay-session"

python3 - "$OUT" "$FIXTURE/canary_secrets.txt" <<'PY' || fail "replay validation"
import json, pathlib, sys
result = json.loads(pathlib.Path(sys.argv[1]).read_text())
canary = pathlib.Path(sys.argv[2]).read_text()
assert result.get("schema") == "fractal.worker.terminal-result.v1", result
assert result.get("provider") == "cursor", result
assert result.get("exit") == "success", result
assert result.get("usage", {}).get("peak_rss_bytes") == 1048576, result
assert result.get("changed_files") and all(
    f.get("path") == "src/health.c" and f.get("within_allowlist")
    for f in result["changed_files"]
), result
blob = json.dumps(result)
for line in canary.splitlines():
    token = line.split("=", 1)[-1].strip() if "=" in line else line.strip()
    if token.startswith("sk-") or token.startswith("/Users/"):
        assert token not in blob, f"canary leaked: {token}"
print("replay envelope ok")
PY
pass "cursor fixture replay"

# --- Live Cursor opt-in -------------------------------------------------------
run_cursor_live() {
    [ "${FRACTAL_CURSOR_LIVE:-0}" = "1" ] || {
        echo "SKIP: set FRACTAL_CURSOR_LIVE=1 to run live Cursor worker"
        return 0
    }
    command -v cursor >/dev/null 2>&1 || skip "cursor CLI not installed"
    [ -n "${FRACTAL_CURSOR_SECRET_HANDLE:-}" ] || skip "FRACTAL_CURSOR_SECRET_HANDLE unset"

    echo "== fractal-worker live: cursor =="
    "$BIN" discover-version >"$OUT" || fail "live discover-version"
    python3 - "$OUT" <<'PY' || fail "live version schema"
import json, pathlib, sys
v = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert v.get("provider") == "cursor"
assert v.get("protocol_version") == "fractal-worker/v1"
assert v.get("cli_version")
print("version", v["cli_version"])
PY

    SEED=$(mktemp -d "${TMPDIR:-/tmp}/fractal-cursor-seed.XXXXXX")
    mkdir -p "$SEED/src"
    printf '%s\n' 'int health(void) { return -1; }' >"$SEED/src/health.c"
    PROMPT='Edit only src/health.c so health() returns 0. Do not touch any other file.'

    "$BIN" open-session \
        --workspace-id e2e-live \
        --root-object-id root \
        --allowed-file src/health.c \
        --seed-dir "$SEED" \
        --secret-handle "$FRACTAL_CURSOR_SECRET_HANDLE" \
        --prompt "$PROMPT" \
        >"$OUT" || fail "live open-session"

    python3 - "$OUT" "$FIXTURE/canary_secrets.txt" <<'PY' || fail "live result validation"
import json, pathlib, sys
result = json.loads(pathlib.Path(sys.argv[1]).read_text())
canary = pathlib.Path(sys.argv[2]).read_text()
assert result.get("schema") == "fractal.worker.terminal-result.v1"
assert result.get("provider") == "cursor"
assert result.get("usage", {}).get("peak_rss_bytes", 0) >= 0
assert result.get("usage", {}).get("peak_rss_bytes", 0) <= 157286400
for f in result.get("changed_files") or []:
    assert f.get("within_allowlist"), f
    assert f.get("path") == "src/health.c", f
blob = json.dumps(result)
for needle in ["sk-CANARY", "/Users/someone"]:
    assert needle not in blob, needle
# Handle id may appear; raw canary secret values must not.
for line in canary.splitlines():
    if "sk-CANARY" in line:
        tok = line.split("=", 1)[-1].strip()
        assert tok not in blob, tok
print("live envelope ok exit=", result.get("exit"), "status=", result.get("exit_status"))
PY
    rm -rf "$SEED"
    pass "cursor live worker"
}

run_cursor_live

# Placeholders for sibling workers (implemented by parallel tasks).
for worker in claude hermes codex; do
    flag=$(echo "FRACTAL_${worker}_LIVE" | tr '[:lower:]' '[:upper:]')
    # shellcheck disable=SC2086
    eval "live=\${$flag:-0}"
    if [ "$live" = "1" ]; then
        echo "SKIP: $worker live branch not provided by this Cursor adapter task"
    else
        echo "SKIP: set $flag=1 when the $worker adapter is available"
    fi
done

pass "test_fractal_workers.sh"
