# Official Codex + FractalOS

`fractalos-mcp` is a narrow Model Context Protocol bridge from an orchestrator to
a live FractalOS CC-PD. `codex-fractalos` is the non-interactive compatibility
launcher that registers the read-only subset for one official Codex process
without modifying the operator's global Codex configuration.

The model receives three named tools:

- `fractalos_pool_status`
- `fractalos_list_guests`
- `fractalos_guest_status`

The server also advertises one explicitly mutating tool for trusted
orchestrators:

- `fractalos_run_native_task`

That operation accepts one bounded prompt and task policy, then invokes only
the named `agentctl agent-run` command. It cannot select raw opcodes, fabricate
capabilities, or open arbitrary sockets. The `codex-fractalos` compatibility
launcher deliberately does not allowlist this tool, preventing a recursive
Codex-to-native-Codex loop.

There is deliberately no raw-opcode, shell, or arbitrary-socket tool. The
Codex shell remains under its normal sandbox; only the separate MCP process
can open the configured CC-PD socket.

## Run it

Install and authenticate the official Codex CLI, then build the FractalOS host
tools:

```sh
make -C tools/agentctl
make build-tools
```

Boot FractalOS in one terminal so `build/cc_pd.sock` is live:

```sh
make run GUEST_OS=none
```

Run Codex from another terminal:

```sh
target/release/codex-fractalos \
  --metrics \
  --agentctl tools/agentctl/agentctl \
  --socket build/cc_pd.sock \
  -- exec --sandbox workspace-write --cd /path/to/worktree \
  'Inspect the live FractalOS pool, implement the requested change, and run tests.'
```

All arguments after `--` are passed to `codex`. The launcher injects the MCP
configuration with `-c`, marks the server required, and allowlists only the
three tools above. `--metrics` emits one `FRACTALOS_CODEX_METRICS` JSON record on
stderr with elapsed milliseconds, peak child RSS in bytes, and the exit code.
Codex `exec --json` independently emits token usage in its final JSONL event.

Run the live coding proof against an already booted FractalOS instance with:

```sh
FRACTALOS_CODEX_LIVE=1 make e2e-codex-agent
```

The test creates an isolated Git worktree, proves its C test fails, requires
official Codex to query the live pool exactly once through MCP, permits it to
edit only one C file, and requires the test to pass afterward.

## Current boundary

This is the production-capable path available now: official Codex runs on a
supported host and treats the seL4 system as a capability-limited external
control plane.

For the capability-native V2 path, use `tools/run_native_agent.py` as described
in `docs/native-agent-harness.md`. It boots FractalOS, keeps the authenticated
Codex model client in shared infrastructure, and submits the task through
CC-PD and Controller to the native harness.

The pinned official AArch64 CLI also boots inside an FractalOS-managed Linux
compatibility guest and passes its own version preflight via `cargo xtask
qemu-test --guest-os codex --timeout-secs 300`. That image is credential-free.
Authenticated work inside the guest still requires capability-gated guest
networking and a runtime secret broker, so the external MCP path remains the
only production-capable live-model path today.
