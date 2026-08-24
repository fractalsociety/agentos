# Official Codex + AgentOS

`agentos-mcp` is a read-only Model Context Protocol bridge from the official
Codex CLI to a live AgentOS CC-PD. `codex-agentos` is the non-interactive
launcher that registers that bridge for one Codex process without modifying
the operator's global Codex configuration.

The model receives three named tools:

- `agentos_pool_status`
- `agentos_list_guests`
- `agentos_guest_status`

There is deliberately no raw-opcode, shell, mutation, or arbitrary socket
tool. The Codex shell remains under its normal sandbox; only the separate MCP
process can open the configured CC-PD socket.

## Run it

Install and authenticate the official Codex CLI, then build the AgentOS host
tools:

```sh
make -C tools/agentctl
make build-tools
```

Boot AgentOS in one terminal so `build/cc_pd.sock` is live:

```sh
make run GUEST_OS=none
```

Run Codex from another terminal:

```sh
target/release/codex-agentos \
  --metrics \
  --agentctl tools/agentctl/agentctl \
  --socket build/cc_pd.sock \
  -- exec --sandbox workspace-write --cd /path/to/worktree \
  'Inspect the live AgentOS pool, implement the requested change, and run tests.'
```

All arguments after `--` are passed to `codex`. The launcher injects the MCP
configuration with `-c`, marks the server required, and allowlists only the
three tools above. `--metrics` emits one `AGENTOS_CODEX_METRICS` JSON record on
stderr with elapsed milliseconds, peak child RSS in bytes, and the exit code.
Codex `exec --json` independently emits token usage in its final JSONL event.

Run the live coding proof against an already booted AgentOS instance with:

```sh
AGENTOS_CODEX_LIVE=1 make e2e-codex-agent
```

The test creates an isolated Git worktree, proves its C test fails, requires
official Codex to query the live pool exactly once through MCP, permits it to
edit only one C file, and requires the test to pass afterward.

## Current boundary

This is the production-capable path available now: official Codex runs on a
supported host and treats the seL4 system as a capability-limited external
control plane. Codex does **not** yet run inside an AgentOS Linux guest. That
next stage requires a genuine Linux userspace/root filesystem, working guest
networking and certificates, the official Codex binary, and a secret broker;
the current deterministic guest fixture is only a small boot-test initramfs.
