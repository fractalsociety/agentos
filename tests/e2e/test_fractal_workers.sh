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

echo "== fractal-worker provider readiness (live vs blocked) =="
cargo test -p fractal-worker-compat --test test_remote_worker_sessions \
    readiness_report_distinguishes_fixture_live_and_blocked -- --nocapture \
    || fail "provider readiness evidence"

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

# --- Live Claude opt-in -------------------------------------------------------
# Non-skipping live case: with FRACTAL_CLAUDE_LIVE=1 (and `claude` on PATH, or
# FRACTAL_CLAUDE_EXECUTABLE pointing at a real CLI), this branch performs the
# full live session — version preflight, isolated Git workspace spawn, stream
# translation, redaction, RSS and allowlist checks. Exit 2 only when opted-in
# prerequisites are genuinely unavailable.
run_claude_live() {
    [ "${FRACTAL_CLAUDE_LIVE:-0}" = "1" ] || {
        echo "SKIP: set FRACTAL_CLAUDE_LIVE=1 to run live Claude worker"
        return 0
    }
    if [ -n "${FRACTAL_CLAUDE_EXECUTABLE:-}" ]; then
        [ -x "${FRACTAL_CLAUDE_EXECUTABLE}" ] || skip "FRACTAL_CLAUDE_EXECUTABLE not executable"
    else
        command -v claude >/dev/null 2>&1 || skip "claude CLI not installed"
    fi
    [ -n "${FRACTAL_CLAUDE_SECRET_HANDLE:-}" ] || skip "FRACTAL_CLAUDE_SECRET_HANDLE unset"

    echo "== fractal-worker live: claude =="
    cargo build -p fractal-worker-compat --bin fractal-claude-worker \
        || fail "build fractal-claude-worker"
    CBIN="$ROOT/target/debug/fractal-claude-worker"

    "$CBIN" discover-version >"$OUT" || fail "live claude discover-version"
    python3 - "$OUT" <<'PY' || fail "live claude version schema"
import json, pathlib, sys
v = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert v.get("provider") == "claude", v
assert v.get("protocol_version") == "fractal-worker/v1", v
assert v.get("cli_version"), v
assert "stub" not in v["cli_version"].lower(), v
print("claude version", v["cli_version"])
PY

    SEED=$(mktemp -d "${TMPDIR:-/tmp}/fractal-claude-seed.XXXXXX")
    mkdir -p "$SEED/src"
    printf '%s\n' 'int health(void) { return -1; }' >"$SEED/src/health.c"
    PROMPT='Edit only src/health.c so health() returns 0. Do not touch any other file.'

    "$CBIN" open-session \
        --workspace-id e2e-claude-live \
        --root-object-id root \
        --allowed-file src/health.c \
        --seed-dir "$SEED" \
        --secret-handle "$FRACTAL_CLAUDE_SECRET_HANDLE" \
        --prompt "$PROMPT" \
        >"$OUT" || fail "live claude open-session"

    python3 - "$OUT" "$FIXTURE/canary_secrets.txt" <<'PY' || fail "live claude result validation"
import json, pathlib, sys
result = json.loads(pathlib.Path(sys.argv[1]).read_text())
canary = pathlib.Path(sys.argv[2]).read_text()
assert result.get("schema") == "fractal.worker.terminal-result.v1", result
assert result.get("provider") == "claude", result
peak = result.get("usage", {}).get("peak_rss_bytes", 0)
assert 0 <= peak <= 157286400, result
assert result.get("exit") in ("success", "failure", "cancelled"), result
for f in result.get("changed_files") or []:
    assert f.get("within_allowlist"), f
    assert f.get("path") == "src/health.c", f
blob = json.dumps(result)
for line in canary.splitlines():
    if "sk-CANARY" in line:
        tok = line.split("=", 1)[-1].strip()
        assert tok not in blob, f"canary leaked: {tok}"
for needle in ["sk-CANARY", "/Users/someone"]:
    assert needle not in blob, needle
# Handle id may appear; raw canary secret values must not.
assert result.get("secret_handle"), result
print("claude live envelope ok exit=", result.get("exit"), "status=", result.get("exit_status"))
PY
    rm -rf "$SEED"
    pass "claude live worker"
}

run_claude_live

# --- Live Hermes opt-in -------------------------------------------------------
# Non-skipping live case: with FRACTAL_HERMES_LIVE=1 (and `hermes` on PATH, or
# FRACTAL_HERMES_EXECUTABLE pointing at a real CLI), this branch performs the
# full live session without granting ambient shell/network/filesystem authority.
run_hermes_live() {
    [ "${FRACTAL_HERMES_LIVE:-0}" = "1" ] || {
        echo "SKIP: set FRACTAL_HERMES_LIVE=1 to run live Hermes worker"
        return 0
    }
    if [ -n "${FRACTAL_HERMES_EXECUTABLE:-}" ]; then
        [ -x "${FRACTAL_HERMES_EXECUTABLE}" ] || skip "FRACTAL_HERMES_EXECUTABLE not executable"
    else
        command -v hermes >/dev/null 2>&1 || skip "hermes CLI not installed"
    fi
    [ -n "${FRACTAL_HERMES_SECRET_HANDLE:-}" ] || skip "FRACTAL_HERMES_SECRET_HANDLE unset"

    echo "== fractal-worker live: hermes =="
    cargo build -p fractal-worker-compat --bin fractal-hermes-worker \
        || fail "build fractal-hermes-worker"
    HBIN="$ROOT/target/debug/fractal-hermes-worker"

    "$HBIN" discover-version >"$OUT" || fail "live hermes discover-version"
    python3 - "$OUT" <<'PY' || fail "live hermes version schema"
import json, pathlib, sys
v = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert v.get("provider") == "hermes", v
assert v.get("protocol_version") == "fractal-worker/v1", v
assert v.get("cli_version"), v
assert "stub" not in v["cli_version"].lower(), v
print("hermes version", v["cli_version"])
PY

    SEED=$(mktemp -d "${TMPDIR:-/tmp}/fractal-hermes-seed.XXXXXX")
    mkdir -p "$SEED/src"
    printf '%s\n' 'int health(void) { return -1; }' >"$SEED/src/health.c"
    PROMPT='Edit only src/health.c so health() returns 0. Do not touch any other file.'

    "$HBIN" open-session \
        --workspace-id e2e-hermes-live \
        --root-object-id root \
        --allowed-file src/health.c \
        --seed-dir "$SEED" \
        --secret-handle "$FRACTAL_HERMES_SECRET_HANDLE" \
        --prompt "$PROMPT" \
        >"$OUT" || fail "live hermes open-session"

    python3 - "$OUT" "$FIXTURE/canary_secrets.txt" <<'PY' || fail "live hermes result validation"
import json, pathlib, sys
result = json.loads(pathlib.Path(sys.argv[1]).read_text())
canary = pathlib.Path(sys.argv[2]).read_text()
assert result.get("schema") == "fractal.worker.terminal-result.v1", result
assert result.get("provider") == "hermes", result
peak = result.get("usage", {}).get("peak_rss_bytes", 0)
assert 0 <= peak <= 157286400, result
assert result.get("exit") in ("success", "failure", "cancelled"), result
for f in result.get("changed_files") or []:
    assert f.get("within_allowlist"), f
    assert f.get("path") == "src/health.c", f
blob = json.dumps(result)
for line in canary.splitlines():
    if "sk-CANARY" in line:
        tok = line.split("=", 1)[-1].strip()
        assert tok not in blob, f"canary leaked: {tok}"
for needle in ["sk-CANARY", "/Users/someone"]:
    assert needle not in blob, needle
assert result.get("secret_handle"), result
print("hermes live envelope ok exit=", result.get("exit"), "status=", result.get("exit_status"))
PY
    rm -rf "$SEED"
    pass "hermes live worker"
}

run_hermes_live

# --- Live Codex opt-in --------------------------------------------------------
run_codex_live() {
    [ "${FRACTAL_CODEX_LIVE:-0}" = "1" ] || {
        echo "SKIP: set FRACTAL_CODEX_LIVE=1 to run live Codex worker"
        return 0
    }
    if [ -n "${FRACTAL_CODEX_EXECUTABLE:-}" ]; then
        [ -x "${FRACTAL_CODEX_EXECUTABLE}" ] || skip "FRACTAL_CODEX_EXECUTABLE not executable"
    else
        command -v codex >/dev/null 2>&1 || skip "codex CLI not installed"
    fi
    [ -n "${FRACTAL_CODEX_SECRET_HANDLE:-}" ] || skip "FRACTAL_CODEX_SECRET_HANDLE unset"

    echo "== fractal-worker live: codex =="
    cargo build -p fractal-worker-compat --bin fractal-codex-worker \
        || fail "build fractal-codex-worker"
    CBIN="$ROOT/target/debug/fractal-codex-worker"
    FIXTURE="$ROOT/tests/fixtures/codex-worker"

    "$CBIN" discover-version >"$OUT" || fail "live codex discover-version"
    python3 - "$OUT" <<'PY' || fail "live codex version schema"
import json, pathlib, sys
v = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert v.get("provider") == "codex", v
assert v.get("protocol_version") == "fractal-worker/v1", v
assert v.get("cli_version"), v
assert "stub" not in v["cli_version"].lower(), v
print("codex version", v["cli_version"])
PY

    SEED=$(mktemp -d "${TMPDIR:-/tmp}/fractal-codex-seed.XXXXXX")
    mkdir -p "$SEED/src"
    printf '%s\n' 'int health(void) { return -1; }' >"$SEED/src/health.c"
    PROMPT='Edit only src/health.c so health() returns 0. Do not touch any other file.'

    "$CBIN" open-session \
        --workspace-id e2e-codex-live \
        --root-object-id root \
        --allowed-file src/health.c \
        --seed-dir "$SEED" \
        --secret-handle "$FRACTAL_CODEX_SECRET_HANDLE" \
        --prompt "$PROMPT" \
        >"$OUT" || fail "live codex open-session"

    python3 - "$OUT" "$FIXTURE/canary_secrets.txt" <<'PY' || fail "live codex result validation"
import json, pathlib, sys
result = json.loads(pathlib.Path(sys.argv[1]).read_text())
canary = pathlib.Path(sys.argv[2]).read_text()
assert result.get("schema") == "fractal.worker.terminal-result.v1", result
assert result.get("provider") == "codex", result
peak = result.get("usage", {}).get("peak_rss_bytes", 0)
assert 0 <= peak <= 157286400, result
assert result.get("exit") in ("success", "failure", "cancelled"), result
for f in result.get("changed_files") or []:
    assert f.get("within_allowlist"), f
    assert f.get("path") == "src/health.c", f
blob = json.dumps(result)
for line in canary.splitlines():
    if "sk-CANARY" in line:
        tok = line.split("=", 1)[-1].strip()
        assert tok not in blob, f"canary leaked: {tok}"
for needle in ["sk-CANARY", "/Users/someone"]:
    assert needle not in blob, needle
assert result.get("secret_handle"), result
print("codex live envelope ok exit=", result.get("exit"), "status=", result.get("exit_status"))
PY
    rm -rf "$SEED"
    pass "codex live worker"
}

run_codex_live

echo "== fractal-worker fixture replay via fractal-codex-worker =="
cargo build -p fractal-worker-compat --bin fractal-codex-worker \
    || fail "build fractal-codex-worker"
CBIN="$ROOT/target/debug/fractal-codex-worker"
CFIXTURE="$ROOT/tests/fixtures/codex-worker"
"$CBIN" replay-session \
    --workspace-id e2e-codex-replay \
    --root-object-id root \
    --allowed-file src/health.c \
    --jsonl-file "$CFIXTURE/session.jsonl" \
    --peak-rss-bytes 1048576 \
    --secret-handle "handle:e2e-codex" \
    >"$OUT" || fail "codex replay-session"
python3 - "$OUT" <<'PY' || fail "codex replay validation"
import json, pathlib, sys
result = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert result.get("schema") == "fractal.worker.terminal-result.v1", result
assert result.get("provider") == "codex", result
print("codex replay envelope ok")
PY
pass "codex fixture replay"

pass "test_fractal_workers.sh"
