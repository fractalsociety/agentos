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

ExecSvc owns a fourth 4 MiB arena with 48 KiB badge-selected client windows.
It has no ModelCap, MemoryCap, ToolCap, or NetCap. For a `verify` action the
trusted harness reads the requested artifact through MemoryCap, copies that
snapshot and the expected result into its ExecCap window, and requires a zero
exit code before accepting a task marked `HARNESS_TASK_REQUIRE_TEST`.

ExecSvc also implements `RUN_PROFILE`, whose request contains an immutable
profile ID rather than a command string or argv. The deployed `C11_COMPILE`
profile sends at most 24 KiB of source to a shared `exec_transport` PD and
receives at most 16 KiB of diagnostics. That PD alone owns a dedicated VirtIO
console on bus.8; bus.8 occupies a separate 4 KiB physical MMIO page from the
model and network devices. The host proxy invokes `clang` with a fixed
compile-only argv, no shell, an empty temporary working directory, `-nostdinc`,
a conservative ban on preprocessor directives, a timeout, bounded output, and
Linux CPU/address-space/file-descriptor limits. An unknown profile, wrong
service badge, cross-worker offset, overlapping source/output range, missing
transport, or oversized payload is rejected.

The native harness exposes this as
`{"action":"test","path":"...","profile":"c11_compile"}`. A nonzero
compiler exit becomes a model observation so the agent can edit and retry;
`final` remains denied until a later profile run exits zero.

The second deployed profile, `AGENTOS_REPO_TEST`, is repository-scoped without
granting the worker a shell or host filesystem path. AgentFS exports up to 64
badge-owned overlay files within one 24 KiB bundle. ExecSvc requires the
profile-specific badge right, rejects cross-worker arena access, and forwards
the bundle through the isolated execution transport. The administrator—not the
worker—selects the repository root, prebuilt test runner, timeout, and fixed
`xtask test` argv. The host proxy exports a clean snapshot from `HEAD`, safely
extracts regular files, applies the overlay, and runs the suite in a temporary
workspace with networking denied. macOS uses `sandbox-exec`; Linux fails closed
unless bubblewrap is available. Absolute paths, traversal, `.git`, invalid
UTF-8, symlinks from the archive, arbitrary commands, and worker-selected
executables are rejected.

This is now a genuine, bounded native coding-agent loop rather than only a
deterministic planner demo. An authenticated official Codex process has driven
the on-target harness through `memory_write`, AgentFS mutation, a real C11
compiler profile through ExecCap, observation of compiler success, and
`final`. A second authenticated task repaired a tracked fixture through its
AgentFS overlay, invoked the capability-scoped managed repository suite, saw
`repository tests: ok`, and only then returned `final`. It is not yet a
general-purpose Codex replacement: repository change sets are capped at 24 KiB
and native networking is not yet available to transport services. The built-in
`agentos-smoke-coder` remains only the deterministic hermetic-test model.

Runtime authority is now enforced by actual CSpace operations rather than by a
capability bitmap alone. Root gives the controller a private authority CNode
and call-only source capabilities for the five harness capability classes; it
does not delegate the root CNode or accept caller-selected source/destination
slots. CapBroker performs `seL4_CNode_Mint` and `seL4_CNode_Delete`, then sends
the harness a controller-authenticated, strictly monotonic authority epoch.
The harness boots without ToolCap. The target suite mints ToolCap, completes a
ModelSvc→ToolSvc→ModelSvc turn, deletes ToolCap, proves that a tool-requiring
task is denied, re-mints ToolCap, and resumes the coding workflow. A failed
harness synchronization causes the broker to roll back the kernel operation.

## Shared external MCP providers

ToolSvc now routes external tools through a singleton `mcp_transport` PD. That
PD owns a dedicated bus.16 VirtIO console and maps only ToolSvc's private
staging pages. A worker has none of the MCP endpoint, MMIO page, provider
process, provider environment, credential, or socket. Its badged ToolCap must
contain `TOOLSVC_RIGHT_MCP_EXTERNAL`; without that bit, both discovery and
invocation fail before reaching the provider.

External names are collision-free under `mcp.*`. The model invokes
`mcp.tools.list` to receive the bounded, sanitized catalog, then invokes one of
the returned names. The host adapter speaks current MCP 2026-07-28 stdio with
`server/discover` and per-request metadata, and has a tested fallback to the
legacy initialize lifecycle. The administrator supplies an exact JSON argv
array and an explicit environment map, never a shell command. The default VM
gate starts a hermetic real MCP stdio server; a deployment can select another:

```sh
export AGENTOS_MCP_SERVER_COMMAND_JSON='["npx","-y","@example/mcp-server"]'
export AGENTOS_MCP_SERVER_ENV_JSON='{"SERVICE_TOKEN":"..."}'
cargo xtask run-tests --board qemu_virt_aarch64 --timeout-secs 180
```

The 2026-08-24 AArch64 target gate proves `tools/list`, `tools/call`, and a
complete native ModelSvc→ToolSvc→external MCP→ModelSvc harness loop. The
credential/environment remains shared service infrastructure and is not
charged to, mapped into, or copied for each worker.

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

The expanded native live target gate passed on 2026-08-24. The AArch64 seL4 worker sent
eight ModelCap requests through ModelSvc and NetServer to a dedicated
`model_transport` protection domain. That PD alone owns the model VirtIO
console and maps ModelSvc's service-private transport arena; the worker has no
transport cap, NetCap, credential, or host socket. The host proxy forwarded the
bounded JSON frames to one already-authenticated official Codex process. Codex
returned `memory_write(src/live.c, "int agentos_answer(void) { ... }")`, then
`test(src/live.c, c11_compile)`. ExecSvc validated the worker partition and
profile, the distinct execution transport invoked the real host compiler, and
Codex received `compile: ok` before returning `final`. Codex then independently
invoked capability-scoped `repo.search` to locate the tracked definition of
`agentos_repo_answer`, invoked separately authorized `repo.read` to inspect the
discovered file, wrote the repair through AgentFS, selected
`agentos_repo_tests`, received the successful managed-suite observation, and
returned a second gated final answer. The repository index is one bounded,
administrator-owned snapshot of Git `HEAD` in the persistent host execution
proxy; it is shared by every worker and excludes files larger than 1 MiB, with
8,192-file and 32 MiB aggregate ceilings. Workers receive only bounded
observations and never a repository root, argv, shell, or host filesystem
handle. ToolSvc checks distinct immutable badge rights for `agent.echo`,
`repo.search`, and `repo.read`; its own ExecCap contains only the fixed search
and read profiles. With on-target overlay-export isolation checks, the live VM
suite passed 41/41; the credential-free hermetic suite passed 39/39. The
subsequent runtime-authority suite passed 42/42 on real seL4, including kernel
ToolCap mint/delete/re-mint and epoch enforcement. The external MCP suite now
passes 45/45, adding real provider discovery, invocation, and a complete native
harness continuation through the provider.

These dedicated model, execution, and MCP consoles are honest intermediate
transports, not a claim of native TCP, a native compiler, arbitrary repository
commands, or native Headscale support. The current lwIP shim does not provide a real
packet path, so native Headscale-ready networking and device enrollment remain
open work. The transports prove the intended authority graph without placing
the model client, compiler process, credentials, or host sockets in every
worker.

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

The latest 2026-08-24 AArch64 QEMU performance run with ModelSvc, ToolSvc,
AgentFS, ExecSvc, and the model, execution, and MCP transport PDs passed all 45
target assertions. It measured 463.606 ms from QEMU spawn to root-task
readiness, a 3.799 ms cold native planner turn, and 12 warm turns with 0.190 ms
p50 and 0.536 ms p95. ModelSvc cached queries measured 0.043 ms p50 and
0.367 ms p95. The worker reported 274,432 bytes of
private committed memory
and 196,608 bytes of shared client mappings under its 64 MiB private limit;
its shared-component bitmap now includes the singleton repository index.
Host-side proxy memory is shared system infrastructure and is intentionally not
reported as worker-private memory. These are QEMU/host-arrival measurements,
not bare-metal cycle counts.

The clean-worktree authority run retained the same resource contract:
274,432 bytes private committed, 196,608 bytes shared mapped, a 64 MiB default
private limit, a 20 MiB mature-worker target floor, and a 150 MiB hard ceiling.
It reported 55 shared-component bits and completed all 12 warm turns without an
error. Dynamic authority therefore does not duplicate the model client,
repository index, MCP/tool connections, semantic cache, execution graph, or
artifact storage inside the worker.

The same test originally exposed a roughly 992 ms tail caused by the generic
10 ms/one-second MCS scheduling class. Native agent and shared agent-service
PDs now use a 20 ms/100 ms interactive class; the repeated warm-turn p95 fell
to sub-millisecond latency in subsequent runs. The 274,432-byte bootstrap is
intentionally below the mature 20 MiB target floor; future context, overlay,
and tool state must remain below the 150 MiB ceiling rather than padding the
worker. Multi-file export remains inside the existing MemoryCap and ExecCap
windows and does not add a per-worker repository copy; the repository snapshot,
test runner, model client, cache, and execution machinery remain shared rather
than duplicated per worker.
