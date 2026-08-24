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

## Implementation status

The native C bootstrap harness now builds as its own protection domain, boots
under seL4 on QEMU AArch64, and completes both a Codex-style planner/final
action and a ModelSvc→ToolSvc→ModelSvc tool loop. Root-task endpoint
distribution mints badged, call-only
client capabilities (`Write + GrantReply`) and distinct receive-only service
capabilities. The harness receives distinct ModelSvc, ToolSvc, and LogDrain
endpoints, but no AgentFS, ExecServer, or direct NetServer endpoint.

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

This is a runnable native planner bootstrap, not yet a completed coding agent.
External MCP connections and repository tools are not implemented yet,
ExecServer does not yet execute a command, and the monitor's dynamic
CapabilityBroker records policy metadata without
performing CNode mint/delete/revoke operations. Until those pieces and a real
edit/test/result workflow are proven on target, the project must not claim a
completed native Codex agent.

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

Run:

```sh
cargo xtask run-tests --board qemu_virt_aarch64 --timeout-secs 180 \
  --perf-output build/agent-harness-qemu-perf.json --require-perf
```

The 2026-08-23 AArch64 QEMU run with ModelSvc and ToolSvc passed all 29 target
assertions. Host monotonic timestamps measured 460.11 ms from QEMU spawn to
root-task readiness, a 3.25 ms cold native planner turn, and 12 warm turns with
0.275 ms p50 and 0.561 ms p95. The bootstrap worker reported 245,760 bytes of
private committed memory and 98,304 bytes of shared ModelSvc+ToolSvc mappings
under its 64 MiB private limit. These are QEMU/host-arrival measurements, not
bare-metal cycle counts.

The same test originally exposed a roughly 992 ms tail caused by the generic
10 ms/one-second MCS scheduling class. Native agent and shared agent-service
PDs now use a 20 ms/100 ms interactive class; the repeated warm-turn p95 fell
to sub-millisecond latency in subsequent runs. The 245,760-byte bootstrap is intentionally
below the mature 20 MiB target floor; future context, overlay, and tool state
must remain below the 150 MiB ceiling rather than padding the worker.
