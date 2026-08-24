#!/bin/sh
# Genuine official-Codex coding loop against a live AgentOS CC-PD.
# Exit 2 means the explicitly opted-in live prerequisites are unavailable.

set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
SOCKET=${CC_PD_SOCK:-"$ROOT/build/cc_pd.sock"}
AGENTCTL=${AGENTCTL:-"$ROOT/tools/agentctl/agentctl"}
LAUNCHER=${CODEX_RUN_AGENT:-${CODEX_AGENTOS:-"$ROOT/target/release/run-agent"}}
MANIFEST=${CODEX_WORKER_MANIFEST:-"$ROOT/manifests/workers/codex.toml"}
FIXTURE="$ROOT/tests/fixtures/codex-agent"

skip() {
    echo "SKIP: $*" >&2
    exit 2
}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

[ "${AGENTOS_CODEX_LIVE:-0}" = "1" ] || skip "set AGENTOS_CODEX_LIVE=1 to spend model tokens"
command -v codex >/dev/null 2>&1 || skip "official Codex CLI is not installed"
[ -n "${FRACTAL_CODEX_SECRET_HANDLE:-}${OPENAI_API_KEY:-}${CODEX_API_KEY:-}" ] || \
    skip "provide an opaque Codex secret handle or an inherited ephemeral API-key channel"
[ -S "$SOCKET" ] || skip "AgentOS CC-PD socket is not live: $SOCKET"
[ -x "$AGENTCTL" ] || skip "agentctl is not built: $AGENTCTL"
[ -x "$LAUNCHER" ] || skip "run-agent is not built: make build-tools"
[ -f "$MANIFEST" ] || skip "Codex worker manifest is missing: $MANIFEST"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/agentos-codex-e2e.XXXXXX")
ARTIFACTS=$(mktemp -d "${TMPDIR:-/tmp}/agentos-codex-result.XXXXXX")
trap 'rm -rf "$WORK" "$ARTIFACTS"' EXIT HUP INT TERM
cp "$FIXTURE"/* "$WORK"/
git -C "$WORK" init -q
git -C "$WORK" config user.name "AgentOS E2E"
git -C "$WORK" config user.email "agentos-e2e@invalid"
git -C "$WORK" add .
git -C "$WORK" commit -qm baseline

if make -s -C "$WORK" test >/dev/null 2>&1; then
    fail "broken fixture passed before Codex ran"
fi

EVENTS="$ARTIFACTS/codex-events.jsonl"
METRICS="$ARTIFACTS/codex-metrics.log"
RESULT="$ARTIFACTS/codex-result.json"
"$LAUNCHER" \
    --manifest "$MANIFEST" \
    --agentctl "$AGENTCTL" \
    --socket "$SOCKET" \
    --workspace "$WORK" \
    --allowed-file agent_health.c \
    --events "$EVENTS" \
    --result "$RESULT" \
    --metrics \
    --prompt \
    'Call agentos_pool_status exactly once and report its named live counts. Fix only agent_health.c so capacity requires valid accounting, at least one idle worker, and zero faulted workers. Run make test. Never use agentctl or the control socket through shell commands.' \
    >"$ARTIFACTS/codex-stdout.json" 2>"$METRICS"

make -s -C "$WORK" test >/dev/null || fail "fixture still fails after Codex"
[ "$(git -C "$WORK" diff --name-only)" = "agent_health.c" ] || \
    fail "Codex changed files outside agent_health.c"

python3 - "$EVENTS" "$METRICS" "$RESULT" <<'PY'
import json
import pathlib
import sys

events = [json.loads(line) for line in pathlib.Path(sys.argv[1]).read_text().splitlines()]
calls = [
    event["item"]
    for event in events
    if event.get("type") == "item.completed"
    and event.get("item", {}).get("type") == "mcp_tool_call"
    and event["item"].get("server") == "agentos"
    and event["item"].get("tool") == "agentos_pool_status"
]
if len(calls) != 1:
    raise SystemExit(f"FAIL: expected one completed pool call, got {len(calls)}")
pool = calls[0]["result"]["structured_content"]
if pool != {"ok": True, "total": 8, "busy": 0, "idle": 8, "faulted": 0}:
    raise SystemExit(f"FAIL: unexpected live pool result: {pool}")

result = json.loads(pathlib.Path(sys.argv[3]).read_text())
if result.get("schema") != "fractal.worker.terminal-result.v1":
    raise SystemExit(f"FAIL: wrong terminal-result schema: {result.get('schema')}")
if result.get("worker_id") != "codex" or result.get("provider") != "codex":
    raise SystemExit(f"FAIL: wrong worker identity: {result}")
if result.get("state") != "completed" or result.get("exit") != "success":
    raise SystemExit(f"FAIL: Codex did not complete successfully: {result}")
if result.get("version", {}).get("cli_version") in (None, "unknown"):
    raise SystemExit(f"FAIL: credential-free version preflight was not recorded: {result}")
usage = result.get("usage", {})
for field in ("input_tokens", "output_tokens", "cached_tokens", "peak_rss_bytes", "wall_time_ms"):
    if field not in usage:
        raise SystemExit(f"FAIL: common usage envelope is missing {field}")
if not usage["peak_rss_bytes"] or not usage["wall_time_ms"]:
    raise SystemExit(f"FAIL: missing structured process usage: {usage}")
metric_lines = [
    line.removeprefix("AGENTOS_CODEX_METRICS ")
    for line in pathlib.Path(sys.argv[2]).read_text().splitlines()
    if line.startswith("AGENTOS_CODEX_METRICS ")
]
if len(metric_lines) != 1:
    raise SystemExit("FAIL: launcher did not emit exactly one metrics record")
metrics = json.loads(metric_lines[0])
if metrics.get("exit_code") != 0 or not metrics.get("max_rss_bytes"):
    raise SystemExit(f"FAIL: invalid launcher metrics: {metrics}")

print(json.dumps({"ok": True, "pool": pool, "usage": usage, "process": metrics}, sort_keys=True))
PY

echo "PASS: official Codex queried live AgentOS, edited C, and passed tests"
