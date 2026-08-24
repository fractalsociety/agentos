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

The planner loop and IPC contract exist. Root-task endpoint distribution now
mints badged client capabilities with send-only rights and installs a distinct
receive-only capability in each service PD. Static boot topology can therefore
enforce a least-privilege harness CSpace without trusting capability masks.

The native seL4 adapter is not runnable yet. ToolSvc is still a target stub,
ExecServer does not yet execute a command, and the monitor's dynamic
CapabilityBroker records policy metadata without performing CNode mint/delete
operations. Until those pieces are replaced and proven on target, the project
must not claim a completed native Codex agent.
