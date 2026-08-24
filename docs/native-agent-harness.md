# Native agent harness architecture

AgentOS separates a model from the harness that turns model responses into
actions. The official Codex CLI Linux guest is a compatibility worker and
behavioral reference, not the operating system's authority boundary.

The production path is:

```text
task -> native harness -> model/tool/memory/exec capabilities -> services
```

Fractal may choose the task, harness, model, and requested capability set. The
AgentOS launcher decides which capabilities are actually minted and installed.
Task data, model output, mesh membership, and Headscale identity cannot create
authority.

## Authority rules

- Model inference requires a minted ModelSvc endpoint badge.
- Each visible/callable tool requires ToolSvc authority and a per-tool grant.
- Workspace and long-term memory require explicit frame/object capabilities.
- Verification and commands require ExecServer authority.
- Direct network access requires an independent NetCap. ModelCap does not imply
  NetCap because ModelSvc owns its restricted upstream transport.
- Joining the private Headscale mesh establishes connectivity and node identity,
  not ModelCap, ToolCap, MemoryCap, ExecCap, or NetCap.
- Capability masks in task descriptors are requirements for launch validation;
  only seL4 CSpace/VSpace objects enforce access.

## Migration

1. V0: AgentOS-managed Linux guest running the official Codex CLI as a reference.
2. V1: native coordinator assigning capability-scoped work to that guest.
3. V2: native Codex-style planner/tool/patch/verify harness using AgentOS services.
4. V3: Fractal scheduling multiple specialized harnesses and models over the
   AgentOS capability graph.

The V0 task stays valuable as an interoperability and performance test. V2 is
the default runtime target.

V0 is now boot-proven for the pinned official AArch64 `codex-cli 0.149.1`.
`cargo xtask qemu-test --guest-os codex --timeout-secs 300` builds AgentOS,
boots the CLI in a credential-free 768 MiB compatibility guest, runs the
binary's version preflight, and records boot time plus host QEMU RSS. The
larger allocation is isolated to this compatibility VM: it does not change the
native worker budget or duplicate shared ModelSvc/ToolSvc/AgentFS/ExecServer
state. Runtime credential delivery and authenticated in-guest inference remain
unimplemented.

The external official-Codex E2E was re-run against a live seL4 CC-PD on
2026-08-24. Codex queried the allowlisted pool-status MCP tool exactly once,
repaired only the permitted C source in an isolated repository, and passed the
previously failing test. The run took 31,180 ms and the Codex process peaked at
179,077,120 bytes RSS. This is genuine model-backed edit/test evidence for V0,
but it is not evidence that the native V2 worker has completed a live-model
task or met the 150 MiB ceiling.

## Implementation status

The native C bootstrap harness now builds as its own protection domain, boots
under seL4 on QEMU AArch64, and completes a Codex-style planner/final action,
a ModelSvc→ToolSvc→ModelSvc tool loop, and a verified
ModelSvc→AgentFS edit→ExecServer→ModelSvc loop. Root-task endpoint
distribution mints badged, call-only
client capabilities (`Write + GrantReply`) and distinct receive-only service
capabilities. The harness receives distinct ModelSvc, ToolSvc, AgentFS,
ExecServer, and LogDrain endpoints, but no direct NetServer endpoint.

ModelSvc's 4 MiB shared arena is physically divided into 64 badge-selected
48 KiB client partitions plus a 1 MiB service-only transport workspace.
Ordinary workers map only their own partition. ModelSvc checks every supplied
offset against the caller's partition and keys cached results by client, so a
worker cannot address or retrieve another worker's model data.

ToolSvc is also a singleton service with a separate 4 MiB arena and the same
badge-selected 48 KiB client partitions. Its first built-in MCP-compatible
tool is `agent.echo`; the on-target suite proves invocation through ToolCap and
rejection of a cross-worker output offset. Dynamic MCP provider registration
remains denied until CapBroker can mint and revoke provider endpoints.

AgentFS owns a separate 4 MiB transfer arena and a singleton in-memory
workspace overlay. A MemoryCap client maps only its badge-selected 48 KiB
partition. File contents remain private to AgentFS, are keyed by caller badge,
and are copied through checked offsets. The target suite proves create,
truncate, readback, path validation, and denial of cross-worker offsets. The
native harness now parses `memory_write` and `memory_read` actions, invokes the
AgentFS capability backend, and returns each observation to ModelSvc in a
bounded multi-step loop.

The ExecServer verification PD owns a fourth 4 MiB arena with 48 KiB
badge-selected client windows. It has no ModelCap, MemoryCap, ToolCap, or
NetCap. For a `verify` action the trusted harness reads the requested artifact
through MemoryCap, copies that snapshot and the expected result into its
ExecCap window, and requires a zero exit code before accepting a task marked
`HARNESS_TASK_REQUIRE_TEST`. Exact-byte verification is the first deployed
backend; compiling or executing repository tests remains the next backend.

This is a runnable native planner bootstrap, not yet a completed coding agent.
External MCP connections and repository tools are not implemented yet,
ExecServer does not yet compile or execute a command, and the monitor's dynamic
CapabilityBroker records policy metadata without
performing CNode mint/delete/revoke operations. Until those pieces and a real
live-model repository edit/test/result workflow is proven on target, the
project must not claim a completed native Codex agent. The built-in
`agentos-smoke-coder` is a deterministic target-test model, not a substitute
for live inference.

## Shared services and worker memory

A worker owns only its agent loop, bounded task/context state, a small writable
workspace overlay, and capability handles. The model client, MCP connections,
repository index, semantic cache, execution graph, and artifact store live in
shared service PDs and are charged once at system scope.

The harness resource contract reports private committed memory separately from
shared mapped arenas. The mature worker target is 20–150 MiB, with a 64 MiB
default private budget and a hard 150 MiB ceiling. A bootstrap worker may be
smaller than 20 MiB. Shared arenas do not become private merely because they
are mapped into several workers; access remains limited by endpoint badges,
offset validation, and per-worker object capabilities.

## Reproducible QEMU measurement

For a live OpenAI-compatible model, keep the API credential on the host and
run the bounded bridge. `AGENTOS_MODEL_NAME` is required because the native
registry's `fast` route is a logical route name, not an upstream model name.

```sh
export OPENAI_API_KEY='...'
export AGENTOS_MODEL_NAME='<upstream-model-id>'
python3 tools/model_bridge.py
```

If the official Codex CLI is already authenticated, it can instead act as the
single shared model client without an API key:

```sh
python3 tools/model_bridge.py --codex-cli
```

This backend launches Codex in a temporary read-only, tool-less workspace and
returns only its final message through the OpenAI-compatible response shape.
It permits one Codex process at a time by default, bounding the shared backend
memory independently of worker count. The native worker still has no NetCap or
credential; the heavier model client belongs to shared ModelSvc infrastructure
rather than being duplicated into each worker.

The CLI backend has been exercised locally against the authenticated official
Codex installation. The native live target gate is still open: its 2026-08-24
run correctly failed before contacting the bridge because the in-progress
exclusive-NIC split gives VirtIO ownership to `net_pd`, while the HTTP client
in `net_server` does not yet receive a working fastpath. The normal hermetic
target suite remains 34/34. Do not cite the local bridge check as native V2
live-model proof.

In another terminal, enable the opt-in live target assertion:

```sh
AGENTOS_LIVE_MODEL_TEST=1 cargo xtask run-tests \
  --board qemu_virt_aarch64 --timeout-secs 300
```

The bridge binds to loopback by default, accepts only the chat-completions
path, bounds request/response sizes, converts AgentOS's integer temperature
encoding, rewrites the logical model route, and injects the bearer credential.
The key never enters the guest or the worker CSpace. A non-HTTPS upstream is
rejected unless explicitly allowed for a trusted local model server.

Run:

```sh
cargo xtask run-tests --board qemu_virt_aarch64 --timeout-secs 180 \
  --perf-output build/agent-harness-qemu-perf.json --require-perf
```

The 2026-08-24 AArch64 QEMU run with ModelSvc, ToolSvc, AgentFS, and ExecServer
passed all 34 target assertions. Host monotonic timestamps measured 419.99 ms
from QEMU spawn to root-task readiness, a 3.54 ms cold native planner turn,
and 12 warm turns with 0.284 ms p50 and 0.538 ms p95. The bootstrap worker
reported 253,952 bytes of private committed memory and 196,608 bytes of shared
client mappings under its 64 MiB private limit. These are QEMU/host-arrival
measurements, not bare-metal cycle counts.

The same test originally exposed a roughly 992 ms tail caused by the generic
10 ms/one-second MCS scheduling class. Native agent and shared agent-service
PDs now use a 20 ms/100 ms interactive class; the repeated warm-turn p95 fell
to sub-millisecond latency in subsequent runs. The 253,952-byte bootstrap is intentionally
below the mature 20 MiB target floor; future context, overlay, and tool state
must remain below the 150 MiB ceiling rather than padding the worker.
