# FractalOS AgentLang and Programmable Agent Runtime PRD

Version: 3.2-draft
Date: 2026-08-24
Status: architecture revision; bootstrap Agent ISA v0 partially implemented

## 1. Product decision

FractalOS will not require a model to invoke one fixed semantic primitive per
turn or generate a full Rust/Python program for each action. The normative
model interface will be **AgentLang**, a small statically typed agent-native
DSL with a generated capability prelude. AgentLang lowers through Fractal Agent
IR into capability-scoped WASM. A trusted Rust host exposes the semantic
capability ABI and lowers it through the existing FractalOS contracts and seL4
IPC.

```text
LLM / agent
    |
objective + exact replayable context
    |
AgentLang
RUN_PROGRAM / bounded REPL + generated capability prelude
    |
Fractal Agent IR
    |
capability-scoped WASM
    |
trusted Rust host ABI
    |
Stable FractalOS Capability / Service ABI
    |
interface -> capability-authorized provider
    |
native or WASM-backed service PD
    |
seL4 IPC
    |
CPU

Across devices:

AgentLang runtime / MeshGateway
    |
Fractal Mesh Protocol (QUIC streams + typed frames)
    |
Headscale-managed Tailscale/WireGuard tailnet
    |
direct UDP -> peer relay -> DERP fallback
```

The existing contract system is the lower ABI and must not be replaced. The
new layer above it lets models express intent as small programs, compose safe
parallel operations locally, and return only curated results to model context.
Every nested operation is still independently authorized, budgeted, traced,
and replayable.

Python and TypeScript remain bootstrap and control-experiment languages. Rust
remains the implementation language for the trusted host, capability broker,
scheduler, module registry, verifier machinery, and most human-authored system
modules. Neither is the final internal model language.

The central hypothesis is now:

> The most effective AI-native interface is a dense agent-native language over
> a tiny typed semantic capability substrate, compiled into capability-scoped
> WASM rather than interpreted with ambient host authority.

This hypothesis must be selected by controlled benchmarks, not architectural
preference.

## 2. Goals

1. Reduce model turns, context growth, latency, and tool-presentation tokens by
   composing multiple capability calls inside one bounded program.
2. Preserve seL4 capability isolation at every dispatch boundary.
3. Make the exact model-visible session reconstructable from one canonical,
   append-only event stream.
4. Support asynchronous recursive agents whose inactive state can be
   passivated to immutable objects.
5. Allow safe capability-provider substitution without rewriting consumers.
6. Evolve behavior progressively, beginning with cheap harness refinements and
   requiring stronger evidence for deeper architectural changes.
7. Keep task feedback separate from hidden promotion authority.
8. Empirically compare direct tools, Python/TypeScript-style programmable
   environments, direct Agent IR, and AgentLang under identical conditions.
9. Let agents and immutable shared spaces move across a user's authorized
   devices while keeping memory proportional to active work and preserving
   local seL4 capability enforcement on every device.

## 3. Non-goals

- Replacing seL4, Microkit IPC, or existing per-PD contracts.
- Giving generated code a shell, filesystem path, socket, file descriptor, or
  ambient host authority.
- Treating the set of Agent ISA v0 operations as permanent architectural truth.
- Copying a host-permission Python or shell trust model into FractalOS.
- Requiring models to emit Rust crates, manifests, imports, and boilerplate for
  ordinary orchestration steps.
- Adding a UI, dashboard, interactive terminal, or browser bridge to this
  repository.
- Treating Headscale identity, a tailnet IP, MagicDNS name, WireGuard key, or
  remote badge as FractalOS application authority.
- Turning Headscale into the object store, event store, service registry, or
  distributed scheduler.
- Implementing a general distributed mutable filesystem, global consensus for
  every operation, or full-mesh gossip as the canonical event log.
- Allowing a candidate to observe, select, modify, or invoke its own hidden
  promotion verifier.

## 4. Non-negotiable safety and evolution core

The v2 safety architecture remains authoritative:

- seL4 capabilities and endpoint badges enforce isolation; declarations and
  tool presentation never create authority.
- All promoted programs, modules, capability graphs, ISA versions, verifier
  epochs, and activation records are immutable and content-addressed.
- Promotion uses held-out gates that the candidate cannot inspect.
- Verifier epochs are frozen during an evaluation and ratchet forward; a new
  candidate cannot weaken the verifier that judges it.
- Every external effect is recorded in an effect ledger and is attributable to
  a capability, principal, program, task, and event range.
- Null and unchanged baselines are first-class competitors, so mutation must
  beat doing nothing at equal budget.
- Evolvable modules are stateless functions over explicit immutable inputs.
  Durable state lives in versioned objects and scoped roots, not hidden module
  globals.
- Rollback is root restoration plus capability revocation, not best-effort
  reverse execution of unknown effects.

## 5. Architectural layers and change policy

| Layer | Role | Change policy |
|---|---|---|
| L0 | seL4 isolation, memory, capabilities, IPC, hardware safety | Immutable to agents |
| L1 | FractalOS messages, object transfer, cap transfer, events, timers | Stable machine ABI; rare reviewed changes |
| L2 | Trusted Rust host ABI, semantic capabilities, and service interfaces | Versioned; backward-compatible by default |
| L3 | Fractal Agent IR and capability-scoped WASM | Evolvable under benchmark and verifier gates |
| L4 | AgentLang and generated capability prelude | Model/runtime optimized; capability-derived |
| L5 | Learned representations and instruction vocabulary | Experimental and promotion-gated |

An evolved operation or program may only lower into authorized lower-layer
calls. No higher layer may weaken L0 or introduce an alternate hardware,
network, storage, or credential path.

## 6. AgentLang programming layer

### 6.1 Model-facing interface

The default model surface is intentionally tiny:

```text
RUN_PROGRAM(agentlang_source, inputs, constraints) -> ProgramHandle | result
REPL_CONTINUE(session, agentlang_fragment, constraints) -> result
```

`RUN_PROGRAM` compiles and executes bounded AgentLang source against a generated
prelude containing only capability interfaces installed for that agent and
scope. The runtime may return synchronously for bounded local computation or
immediately return a handle for long work. `REPL_CONTINUE` is optional
persistent AgentLang state, scoped and checkpointed like every other object.

The model may write a program conceptually like:

```text
let w = checkpoint(workspace)

parallel {
    a = delegate(coder, bug)
    b = delegate(coder, bug)
    c = delegate(coder, bug)
}

best = task_verify([a, b, c])

if best.pass {
    commit(best)
} else {
    restore(w)
}
```

AgentLang is intentionally denser than Rust and more constrained than Python.
It has static types with local inference, explicit `Result` propagation,
immutable values by default, typed handles and ObjectIDs, structured
`parallel`/`wait`/cancellation, and explicit capability effects. It has no
ambient filesystem, subprocess, network, environment, clock, reflection,
dynamic import, package installation, or unbounded runtime escape hatch.
Loops, recursion, allocation, children, result bytes, and effects are statically
bounded where possible and fuel-bounded otherwise.

The programming syntax is not the authority model. Generated prelude omission
reduces tokens but every compiled call is authorized again by the Rust host and
lower seL4 endpoint.

### 6.2 Deterministic compiler pipeline

The compilation record is content-addressed and includes AgentLang version,
source ObjectID, generated-prelude schema, interface versions, compiler hash,
constraints, Agent IR root, WASM root, and diagnostics root.

```text
AgentLang source
    -> parse
    -> type + effect + authority-shape check
    -> structured-concurrency lowering
    -> canonical Agent IR
    -> deterministic capability-scoped WASM
    -> validate imports, limits, and module manifest
    -> execute through trusted Rust host ABI
```

Compilation must be deterministic for pinned inputs. Content-addressed compiled
artifacts are cached, so recurring short programs do not pay repeat compile
cost. The production execution artifact is validated WASM. A direct Agent IR
interpreter may remain as a bootstrap, debugger, and benchmark arm, but it is
not the final general execution trust boundary.

### 6.3 Repository language constraint

Python, TypeScript, Rust-source generation, or shell-like programming layers
may exist only as external compatibility adapters, controlled guest workloads,
or host-side experiments. They do not execute with ambient host permissions
and are control arms for discovering what AgentLang should express; they are
not the final model-facing architecture and do not belong in FractalOS core
PDs.

The native production path uses an AgentLang parser/compiler, canonical Agent
IR, generated WIT bindings, capability-scoped WASM, and a trusted no-std Rust
host. C/Rust native PDs continue to implement stable system services. No
interpreted language is added to `kernel/`, `services/`, `libs/`, or
`userspace/servers/`.

### 6.4 Structured concurrency

Programs execute inside an explicit task scope:

- child tasks cannot outlive their scope unless deliberately detached by an
  authorized supervisor;
- child authority is a subset of the parent capability set;
- child budgets are carved from, not added to, the parent budget;
- cancellation and deadline expiry propagate to descendants;
- concurrency is bounded by scheduler quota and capability policy;
- parallel AgentLang calls are allowed only when the provider contract declares
  them concurrency-safe;
- a scope cannot commit while required children remain unresolved.

The programming layer returns compact selected outputs to the model while the
canonical event stream retains the complete nested trajectory.

### 6.5 Generated capability prelude and host SDK

AgentLang receives a compact typed prelude generated from the exact capability
interfaces and versions installed in the launch manifest. The compiler and
Rust/WASM boundary use generated host SDK bindings from the same definitions.
Together they provide:

- typed inputs, outputs, errors, handles, budgets, and constraints;
- no method for an uninstalled capability;
- structured concurrency primitives and cancellation;
- content-addressed object references rather than paths or descriptors;
- deterministic lowering into Agent IR and WASM imports;
- interface and provider version hashes in each program record.

Prelude omission is a usability and context-minimization feature. It is never
an authorization mechanism.

## 7. Fractal Agent IR and semantic capability ABI

The lower semantic vocabulary remains deliberately small:

```text
SPAWN       DELEGATE
CAP_GRANT   CAP_REVOKE
OBJECT_GET  OBJECT_PUT  OBJECT_QUERY
INFER       ACT
WAIT        EMIT
CHECKPOINT  RESTORE
TASK_VERIFY COMMIT
TRACE       BUDGET
TERMINATE
```

These operations are analogous to system calls. A model may invoke them
directly in the experimental direct-IR interface, but the production default
is AgentLang -> Agent IR -> WASM -> trusted Rust host ABI -> semantic ABI.

The v0 wire contract currently names `TASK_VERIFY` as `VERIFY`; this is a
bootstrap compatibility alias. The next interface version must use the
unambiguous `TASK_VERIFY` name. `PROMOTION_VERIFY` is not an Agent ISA opcode
and is never callable by an evolving candidate.

The submit representation contains only an operation, flags, semantic
capability class, abstract budget charge, and immutable ObjectIDs. It contains
no filesystem path, command, URL, TCP endpoint, file descriptor, JSON tool
name, or provider implementation locator.

| Semantic operation | Stable lower target | Execution form |
|---|---|---|
| `SPAWN`, `DELEGATE` | InitAgent / worker pool | Returns handle immediately |
| `CAP_GRANT`, `CAP_REVOKE` | CapBroker | Async; declaration never grants authority |
| `OBJECT_GET`, `OBJECT_PUT`, `OBJECT_QUERY` | AgentFS | Async or bounded local cache result |
| `INFER` | ModelSvc | Async |
| `ACT` | Capability-selected service interface | Async |
| `WAIT` | Task table plus EventBus completion | Bounded poll/subscription |
| `EMIT` | EventBus | Async |
| `CHECKPOINT` | Scoped immutable state root | Immediate |
| `RESTORE` | AgentFS-backed state root | Authorized state transition |
| `TASK_VERIFY` | Agent-visible verifier service | Async |
| `COMMIT` | State-root publication | Only after matching successful task evidence |
| `TRACE` | Event/DAG query service | Bounded query |
| `BUDGET` | QuotaPD / scheduler policy | Policy transition |
| `TERMINATE` | InitAgent / runner lifecycle | Immediate |

## 8. Capability seams and service graph

A capability is an interface seam, not a concrete plugin:

```text
service definition -> authorized provider -> consumer
```

Examples include `vcs`, `compiler`, `browser`, `workspace`, `model`, `memory`,
and `task-verifier`. A consumer binds to an interface version; launch policy
selects an installed provider:

```text
git-v7.wasm          implements vcs
jj-v3.wasm           implements vcs
cargo-v8.wasm        implements compiler
remote-rust-v2.wasm  implements compiler
```

Provider substitution must not change consumer Agent IR. A provider can be
local, remote, native, or WASM-backed, but it must satisfy the same typed
contract, effect policy, concurrency declaration, and capability envelope.

WASM Component Model/WIT is the preferred interface-definition and binding
mechanism unless measured constraints on the seL4 target require a smaller
generated representation. Any alternative must retain typed versioned
interfaces and generated bindings rather than an ad hoc byte ABI.

The service graph record is immutable and includes interface hashes, provider
hashes, dependency edges, capability requirements, budgets, and effect
classes. Rebinding a provider creates a new graph version and requires the
appropriate promotion tier.

## 9. Security invariant: presentation is never authorization

The execution boundary must authorize every nested capability call, even if
the method was hidden from the SDK or tool presentation. Dispatch independently
proves:

1. the caller holds the required seL4 endpoint capability and badge rights;
2. the capability belongs to the current authority epoch and scope;
3. the requested interface and provider versions match the launch graph;
4. input ObjectIDs and shared-memory ranges belong to the caller;
5. budget, deadline, effect, and concurrency constraints permit the call;
6. revocation has not invalidated the handle before dispatch.

Required adversarial tests fabricate hidden SDK calls, raw opcodes, stale
handles, provider IDs, capset ObjectIDs, completion events, cross-scope object
references, and direct lower-service messages. Presentation-only denial is a
security failure even when ordinary model traces never exhibit the bypass.

## 10. Canonical event stream

The append-only canonical event stream is the source of truth for execution.

> If the model saw it, the exact bytes or an immutable content reference to
> those bytes exist in the authorized session event stream.

Required event classes include:

```text
MODEL_REQUEST       MODEL_OUTPUT
PROGRAM_SUBMIT      PROGRAM_RESULT
CAPABILITY_CALL     CAPABILITY_RESULT
OBJECT_READ         OBJECT_WRITE
AGENT_SPAWN         TASK_STATE
MESSAGE             EVENT
TASK_VERIFICATION   PROMOTION_ATTESTATION
EFFECT              CHECKPOINT
COMMIT              RESTORE
BUDGET_CHANGE       CAPABILITY_CHANGE
```

Each event contains a schema version, monotonically ordered stream position,
causal parent(s), scope IDs, principal, authority epoch, program/module hashes,
input/result roots, budget delta, effect reference, environment root, verifier
epoch where applicable, and previous-event hash.

The following are projections of the same stream, not independent realities:

```text
Canonical Event Stream
    +-- model context reconstruction
    +-- causal execution DAG
    +-- replay and fork/resume
    +-- debugger/inspection API
    +-- training trajectories
    +-- metrics and accounting
    +-- effect ledger
```

The execution DAG is a causal index over stream events and immutable objects.
It may optimize graph traversal but cannot contain a transition absent from
the stream. Model context reconstruction must be deterministic for a pinned
context policy and event range.

## 11. Immutable objects, state, and effects

Everything durable and semantically important is content-addressed:

```text
workspace, agent state, task state, result, memory, trace,
capability set, service graph, program, module, verifier, environment
    -> ObjectID
```

Mutable runtime state is primarily a set of scoped current-root pointers.
Checkpoint saves a root; restore selects an earlier root; branch creates new
roots; compare diffs roots. Concurrent completion performs compare-and-swap on
the expected prior root and records a conflict rather than silently overwriting
another branch.

External effects cannot always be rolled back. Each effect therefore receives
an immutable ledger entry before or atomically with dispatch. Commit policy
must distinguish reversible state changes from irreversible external effects.
No state-root rollback may claim to undo an effect that remains externally
observable.

## 12. Lifecycle, scopes, and asynchronous actors

First-class runtime objects are:

```text
AgentHandle  TaskHandle  ProgramHandle  Message  Event  Scope
```

`SPAWN` and `DELEGATE` return handles immediately. Completion arrives through
messages/events; `WAIT` is a bounded poll or subscription primitive and never
holds a long `seL4_Call` open.

State and modules have explicit lifetimes:

| Scope | Lifetime | Examples |
|---|---|---|
| Task | One objective and its descendants | scratch roots, retries, local messages |
| Session | Resumable interaction | context policy, REPL state, session memory |
| Agent | Across sessions for one governed identity | continual harness, role, skill bindings |
| Global | Versioned deployment-wide state | interface registry, promoted providers, verifier epochs |

Idle agents are passivated: registers, active stack, and transient arenas are
released after state is checkpointed to immutable objects. An event or message
reactivates the agent subject to quota and authority revalidation. The memory
goal is proportional to the active frontier, not all historically spawned
agents. Dormant agents consume bounded metadata and object-store capacity, not
a resident harness or guest OS.

## 13. Verification split

### 13.1 TASK_VERIFY

`TASK_VERIFY` is visible to the agent and returns repair-relevant feedback such
as test counts, typed failures, or policy-safe diagnostics. Its verifier object,
inputs, result, and evidence root are recorded in the canonical event stream.
A matching successful task-verification result may authorize `COMMIT` under the
task policy.

### 13.2 PROMOTION_VERIFY

`PROMOTION_VERIFY` is a trusted promotion-system operation outside the
candidate's capability graph. It uses frozen judge code, hidden/held-out gate
corpora, anomaly monitors, challenger and null baselines, and a pinned verifier
epoch. Candidates receive only the promotion verdict and permitted coarse
reason codes after the evaluation is sealed; they do not receive hidden inputs,
per-case outputs, or an oracle they can adaptively query.

Task evidence can be an input to promotion, but passing task verification is
never sufficient to promote a harness, module, provider graph, IR version, or
ISA version.

## 14. Progressive evolution ladder

Self-improvement proceeds from cheap, narrow changes to expensive substrate
changes:

| Tier | Mutable artifact | Examples | Relative gate burden |
|---|---|---|---|
| E0 | Ephemeral reasoning | scratch, current plan | None beyond task policy |
| E1 | Continual harness | prompt notes, memory, skills, subagent roles, retry hints | Cheap evidence + rollback |
| E2 | Orchestration program | AgentLang source, Agent IR workflows, structured-concurrency patterns | Replay + held-out task gates |
| E3 | Executable module | capability-scoped WASM/provider implementation | Security, compatibility, resource gates |
| E4 | Capability graph | interfaces, providers, bindings, effect topology | Cross-service and adversarial gates |
| E5 | Agent ISA | new semantic operation or lowering | Multi-workload benchmark + ABI review |
| E6 | Substrate/hardware | stable ABI, seL4 integration, device path | Human-governed proof and release process |

As the tier deepens, mutation cost, blast radius, verification burden, minimum
sample size, and promotion threshold increase. Successful behavior should
begin at E1/E2 and crystallize downward only when repeated traces show that a
lower implementation is measurably cheaper, safer, or more reliable.

For example, a recurring successful sequence may propose `SPECULATE`, but the
proposal remains an orchestration macro until evidence justifies an E5 ISA
addition. Trace frequency alone is never sufficient.

AgentLang itself is evolvable. The initial syntax remains human-readable for
debugging and data collection. Trace mining may later propose denser typed
forms or learned tokens for recurring structures. A compressed representation
must preserve canonical lowering, auditability, capability effects, and
round-trip debugging. English, Python, TypeScript, and Rust source may
progressively disappear from internal trajectories; the typed IR, WASM module,
event lineage, and authorization checks may not.

## 15. Controlled interface benchmark

The evaluation compares six interfaces:

| Arm | Interface |
|---|---|
| A | Pi-style `read / write / edit / bash` |
| B | Prime-style persistent Python environment |
| C | Generated typed individual capability calls |
| D | General-purpose Code Mode: Python/TypeScript `RUN_PROGRAM` plus generated SDK |
| E | Direct Fractal semantic Agent IR |
| F | AgentLang: `RUN_PROGRAM -> Agent IR -> WASM -> Rust host ABI` |

Every arm uses the same model snapshot, tasks, task order, random seeds,
provider implementations, capability envelope, compute allocation, token and
wall-clock budgets, task verifier, promotion verifier epoch, retry policy, and
environment root. Interface adapters may differ only where the arm definition
requires it.

Required measurements:

- verified task success and confidence intervals;
- input/output tokens and model turns;
- wall time and time waiting on model, providers, and children;
- semantic operations, lower IPC operations, bytes moved, and context bytes;
- recovery/restore rate and unresolved side effects;
- cost and energy where measurable;
- achieved parallelism, active-frontier memory, and dormant-agent memory;
- authorization failures, fabricated-call containment, and effect violations.

The null baseline and incumbent remain in every promotion round. Arm F is not
the presumed winner. The benchmark decides whether direct semantics, a
general-purpose language, AgentLang, or a hybrid survives. Compiler latency,
compile-cache hit rate, generated-source tokens, type/effect failures, and WASM
size are additional required measurements for arms D-F.

## 16. Distributed Headscale agent mesh and shared spaces

### 16.1 Boundary and deployment decision

FractalOS uses Headscale for private device enrollment, WireGuard key and
network-map coordination, stable tailnet addressing, and coarse
deny-by-default connectivity policy. Headscale is not the FractalOS capability
authority and stores no canonical agent, task, object, verifier, or effect
state.

The first deployable controller remains the full Go Headscale service in the
FreeBSD `mesh-controller` guest described by `docs/mesh-network.md`. Supported
devices use standard `tailscaled` clients. An AgentOS node first reaches the
tailnet through the existing tailscaled shared-memory bridge; a native tailnet
PD is a later replacement after the `net_pd` and WireGuard paths are boot-proven
with standard-tailnet interoperability. FractalOS does not port the entire
Headscale server into a freestanding PD.

Headscale policy uses explicit deny-by-default Grants. A deployment with no
loaded policy is invalid because Headscale otherwise treats the tailnet as
allow-all. Device tags and Grants restrict which mesh gateways can establish
transport connections, but they remain defense in depth rather than Agent ISA
authorization.

The data path preference is:

```text
direct WireGuard UDP
    -> peer relay when configured and useful
    -> self-hosted DERP connectivity fallback
```

Direct connections are preferred for latency and throughput. Bulk replication
is rate-limited over DERP and selects a nearer replica/cache when available.
Headscale's embedded DERP may be used for bootstrap and recovery but is not the
high-throughput object path. At least one independently reachable self-hosted
DERP is recommended for devices behind difficult NATs.

### 16.2 Fractal Mesh Protocol

Above the tailnet, each device runs one shared `MeshGateway` service. Agents do
not instantiate a networking stack or Headscale client per harness. The
gateway maintains at most one long-lived QUIC connection per active peer pair,
using ALPN `fractalos-agent/1`, and passivates idle connections. It connects
only the active working set; it does not create an all-to-all connection graph.

QUIC is the v0 preferred transport because it supplies multiplexed,
flow-controlled streams, independent loss recovery, low-latency connection
establishment, and path migration. The semantic protocol remains
transport-neutral until the network benchmark freezes the choice.

| Channel | QUIC form | Permitted contents |
|---|---|---|
| Session control | Long-lived bidirectional stream | negotiation, keepalive, revocation epoch, service advertisements |
| Agent/task call | Bidirectional stream per active call | async submit, messages, task state, cancellation, bounded result |
| Event replication | Reliable unidirectional streams | canonical event ranges, acknowledgements on a control stream |
| Object transfer | Reliable unidirectional streams | verified chunks, range resume, `have/want`, multi-source fetch |
| Hints | QUIC DATAGRAM | presence, load, cache availability, non-authoritative health only |

Tasks, capability operations, messages, root changes, budget changes, effects,
and event records must never use datagrams. Every datagram is disposable and
reconstructible; loss or duplication cannot alter semantic state.

Native agent traffic uses raw QUIC rather than HTTP/3. HTTP/3 belongs at the
external local-page gateway. WebTransport may be an experimental browser
adapter but is not a normative dependency while its standard remains in flux.
Framed TCP and HTTP/3 remain control arms in the required network benchmark.

WIT defines the local WASM component interface, not the network encoding. The
network uses a generated, versioned, length-delimited Fractal Mesh frame
derived from the same interface schema. Hot-path headers and object chunks use
fixed-width or bounded-varint binary fields with no JSON. Extensible manifests
use deterministic CBOR. Postcard is a no-std Rust control-arm codec, not a
permanent cross-language ABI. Codec negotiation is versioned and cannot alter
the semantic interface or authorization rules.

### 16.3 Device, agent, and service identity

The distributed object model adds immutable `NodeID`, `SpaceID`, and
`ServiceID` values. A logical agent is location-independent:

```text
AgentHandle {
    agent_id
    state_root
    mailbox_head
    execution_lease
    permitted_placements
    authority_epoch
}
```

Only one device may hold a live execution lease for effectful execution. Other
devices address the durable mailbox, cache immutable state, or request
placement. A disconnected device may continue explicitly offline-safe work on
a branch, but it cannot acquire new global effects or claim the canonical root
after its lease expires. Ambiguous partitions do not trigger automatic lease
takeover; activation requires a newer fenced authority epoch.

This permits an agent to be reachable from all connected devices without
keeping a process, guest, model client, or complete harness resident on each
one. Schedulers place active work near needed objects, devices, models, or
capabilities. Lightweight devices can run observer, mailbox, cache, or local
gateway roles and delegate compute to stronger nodes.

MagicDNS locates devices. A signed Fractal service registry locates semantic
services:

```text
ServiceAdvertisement {
    service_id
    provider_node
    interface_hash
    endpoint
    required_capability
    health_epoch
    expiry
    signature
}
```

DNS records, tailnet IPs, and service advertisements provide discovery only.
They grant no right to call the advertised service.

### 16.4 Remote authorization

The hard invariant is:

> Tailnet membership authenticates an encrypted device transport. It never
> authorizes an Agent ISA operation.

Each remote operation carries a broker-verifiable, audience-bound grant:

```text
RemoteGrant {
    issuer
    subject_node
    subject_agent
    audience_node
    space_id
    interface_and_operations
    object_scope
    effect_class
    budget
    expiry
    nonce
    authority_epoch
    revocation_epoch
    signature
}
```

The receiving MeshGateway binds the QUIC peer to the authenticated tailnet
node, verifies the signed grant and current revocation state, and asks the
local CapBroker to derive a narrow local seL4 endpoint capability/badge. The
grant is rechecked at dispatch. A network grant never serializes, forwards, or
becomes a raw seL4 capability; a remote-provided badge is never trusted.
Authorization success, denial, expiry, revocation, and local-cap derivation are
canonical events.

### 16.5 Shared spaces and replication

A shared space is an immutable-object namespace plus ordered root transitions:

```text
SpaceRecord {
    space_id
    current_root       -> ObjectID
    shared_event_head  -> EventID
    membership_root    -> ObjectID
    service_root       -> ObjectID
    replica_set_root   -> ObjectID
    authority_epoch
}
```

One online authority orders each space's shared root/event transitions; two
warm replicas are the default availability target. Node/session execution
streams remain canonical for exact local model context and are content-linked
from the shared stream when they affect shared state. This avoids imposing a
single global log on unrelated work.

A mutation uploads missing immutable blocks first, then performs an authorized
compare-and-swap from the expected root to a proposed root with verification
evidence. Replicas exchange event heads, root digests, and `have/want` block or
range sets. Object transfers are chunked, hash-verified, resumable, and may
fetch from multiple authorized caches. The distributed wire identity is the
full 256-bit SHA-256 digest. The current shortened local v0 ObjectID may remain
an indexed alias only after collision checking; it is not a cross-device trust
boundary.

Offline devices create branch roots. Reconnection never silently applies
last-writer-wins. It either:

- merges a schema explicitly declared commutative;
- runs an authorized AgentLang merge task and `TASK_VERIFY`; or
- preserves both heads for user/agent resolution.

CRDTs are permitted only for naturally mergeable, low-risk user data such as
notes, collaborative drafts, presence, calendar annotations, and daily-page
preferences. Capabilities, authority epochs, budgets, effects, execution
leases, commits, task ownership, verifier results, and promotion state use
ordered compare-and-swap transitions and never CRDT conflict resolution.

Full-mesh gossip is not the source of truth. Optional gossip may later
advertise expendable cache, load, presence, or service-health hints if measured
fan-out justifies it. Canonical events and roots replicate reliably from the
space authority and warm replicas.

### 16.6 Local internet and daily-task pages

FractalOS core exposes shared-space, event-query, service-discovery, and
task-intent contracts. It contains no HTML, CSS, JavaScript, WebSocket server,
dashboard, or interactive browser code. Human-facing local pages live in an
external companion project or an explicitly managed Linux/FreeBSD guest:

```text
browser
    -> HTTPS / HTTP/3 (HTTP/2 fallback)
external Fractal Local Gateway
    -> generated typed client
MeshGateway
    -> read-only or task-scoped remote grant
shared-space/event/service APIs
```

The gateway can serve a per-user daily workspace from authorized calendar,
task, file, communication, and device providers. Page/read-model bundles are
immutable objects tied to an event range. Page actions submit narrow typed
task intents; they do not receive ambient `ACT`, `COMMIT`, credential,
promotion-verifier, or shell authority. Publishing a service requires an
explicit, expiring user-approved service capability and produces effect-ledger
events. Revocation stops both new HTTP access and downstream capability
derivation.

Each device may run a gateway for low-latency access, but all gateways consume
the same versioned APIs and shared roots. Page-generation code, browser assets,
TLS termination, CSP/sandbox policy, and human presentation remain outside
this repository.

### 16.7 Network acceptance benchmark

Before declaring QUIC and the mesh codec stable, run identical workloads over
raw QUIC, HTTP/3, and framed TCP on direct LAN, direct WAN, peer-relay, DERP,
hard-NAT, one-percent-loss, path-change, and thirty-second offline/reconnect
conditions. Include compact generated binary, Postcard, and deterministic-CBOR
control encodings where each is applicable.

Measure cold/warm connection time; p50/p95/p99 64-byte and 4-KiB task latency;
1-MiB and 1-GiB object throughput; concurrent-stream blocking; CPU, energy, and
peak/private memory; bytes after deduplication; cache hit rate; reconnect and
resync time; retransmitted bytes; event/root convergence; conflicts and
duplicates; direct/peer-relay/DERP path share; fabricated-call denial; and
end-to-end verified task completion.

The selected transport must improve representative task wall time or achieved
parallelism without exceeding the worker and active-peer memory envelopes.
Semantic service contracts, content identities, and grants remain independent
of the winning transport and codec.

### 16.8 Primary protocol references

- Headscale overview: <https://headscale.net/stable/>
- Headscale policy and Grants: <https://headscale.net/stable/ref/policy/>
- Headscale DERP behavior: <https://headscale.net/development/ref/derp/>
- Tailscale connection types: <https://tailscale.com/docs/reference/connection-types>
- QUIC transport (RFC 9000): <https://www.rfc-editor.org/rfc/rfc9000.html>
- QUIC DATAGRAM (RFC 9221): <https://www.rfc-editor.org/rfc/rfc9221.html>
- HTTP/3 (RFC 9114): <https://www.rfc-editor.org/rfc/rfc9114.html>
- Deterministic CBOR (RFC 8949): <https://www.rfc-editor.org/rfc/rfc8949.html>

## 17. Resource requirements

- A native worker retains the 64 MiB default private budget and 150 MiB hard
  ceiling. The current bootstrap is allowed to remain far smaller.
- Generated preludes/SDKs, compiler cache, provider clients, event indexing,
  model clients, repository indexes, and artifact storage should be shared
  singleton services where authority permits; workers must not instantiate an
  entire harness stack.
- A worker launches only the components named by its validated component graph.
- Passivation must release task stacks, transient program memory, and inactive
  provider mappings while retaining immutable roots and bounded mailbox data.
- Long model, browser, tool, and delegated operations use handles/events rather
  than blocked synchronous RPC.
- Program limits include instruction/fuel budget, memory pages, child count,
  concurrent calls, result bytes, event bytes, wall deadline, and effect class.
- One shared MeshGateway and object/event cache serve authorized local agents;
  agents do not spawn Headscale, tailscaled, DERP, QUIC, or gateway components.
- Mesh memory is bounded per active peer, connection, stream, and in-flight
  object range. Idle peers, agents, and spaces retain immutable roots and
  bounded mailbox/registry metadata only.

## 18. Functional acceptance criteria

### Programmable runtime

- A model can submit one bounded AgentLang program that performs at least two
  independent reads concurrently, computes a patch, invokes task verification,
  and returns one compact result.
- The same pinned AgentLang source, prelude, compiler, and constraints produce
  byte-identical Agent IR and WASM artifacts.
- The WASM validator rejects undeclared imports, malformed capability effects,
  excess memory/fuel/children, and interface-version mismatches.
- The complete nested call/result sequence is replayable although only the
  selected result enters the next model context.
- Cancellation, deadlines, child failure, and budget exhaustion deterministically
  close the structured-concurrency scope.

### Capability seams

- Two providers implementing one versioned interface can be swapped without
  changing the consumer program or IR.
- The launcher rejects incompatible interface/provider versions and undeclared
  effects before execution.
- Raw fabricated calls to hidden or uninstalled capabilities fail at dispatch
  and produce auditable denial events.

### Event sourcing and lifecycle

- A pinned event range deterministically reconstructs the exact model messages,
  DAG, task state, budget, and effect ledger.
- Fork, resume, checkpoint, restore, and passivation preserve causal lineage.
- A dormant agent can be reactivated by an authorized event without retaining
  a resident full harness or guest.

### Evolution and verification

- E1 continual-harness changes can be evaluated and rolled back without
  compiling a WASM module.
- Candidate code cannot invoke or infer held-out promotion cases through
  `TASK_VERIFY`, timing, event visibility, or provider errors.
- No artifact promotes without beating the incumbent and null baseline under a
  frozen verifier epoch and satisfying containment/resource gates.

### Benchmark

- Arms A-F run from one versioned workload manifest and emit one comparable
  schema.
- Results report verified success, tokens, turns, latency, operations, recovery,
  cost, parallelism, authority violations, and memory.
- Any proposed semantic instruction or crystallized provider cites the benchmark
  evidence and exact event ranges that justify promotion.

### Multi-device mesh

- Two standard tailnet devices and one AgentOS node exchange authenticated
  task messages, event ranges, and immutable objects through the MeshGateway.
- Direct connectivity is preferred and operation continues through relay/DERP
  fallback without changing AgentHandles, ObjectIDs, or service interfaces.
- A fabricated grant, stale authority epoch, wrong audience, expired lease,
  remote badge, or unauthorized object range fails before local service
  dispatch and emits a denial event.
- An offline branch reconnects through verified merge or retained conflict,
  never silent last-writer-wins.
- Passivating a remote agent releases its execution memory while its mailbox
  and state remain addressable from another authorized device.
- An external local gateway renders one daily workspace from a pinned shared
  root and can submit only its explicitly granted typed task intents; no UI
  implementation is added to this repository.

## 19. Delivery sequence

1. Preserve and finish the bootstrap Agent ISA v0 contract, futures, immutable
   roots, and target tests.
2. Make the append-only event stream canonical and derive the execution DAG and
   model-context reconstruction from it.
3. Define versioned WIT capability seams and generate the first no-std Rust
   host/WASM SDK bindings.
4. Specify AgentLang v0 grammar, type/effect system, capability prelude, and
   canonical source-to-IR mapping.
5. Implement deterministic `AgentLang -> Agent IR -> WASM` compilation and
   bounded `RUN_PROGRAM` with structured concurrency and independent dispatch
   authorization.
6. Add `AgentHandle`, `TaskHandle`, scoped mailboxes, completion events, and
   passivation/reactivation.
7. Split task-verifier contracts from the hidden promotion service and add
   leakage/adversarial tests.
8. Implement E1 continual-harness snapshots and evidence-backed rollback before
   enabling autonomous WASM/provider mutations.
9. Integrate the existing Headscale/tailscaled bridge with a capability-scoped
   MeshGateway, remote grants, and signed service advertisements.
10. Implement reliable QUIC task/event channels and resumable immutable-object
    replication, then add space authority, offline branches, and verified merge.
11. Define the external local-gateway API and prove one daily-workspace flow
    without adding presentation code to this repository.
12. Run benchmark arms A-F and the multi-device network matrix; use the results
    to select the default model surface, transport, and codec.
13. Permit E4/E5 evolution only after lower tiers produce reproducible gains.

## 20. Current implementation truth

The current branch implements only the bootstrap semantic substrate:

- a versioned 18-operation Agent ISA contract;
- a freestanding Agent IR compiler and semantic runtime;
- an executable AgentLang v0 front end with a capability-derived prelude,
  static handle/ObjectID/Result typing, explicit effects, bounded structured
  parallel groups, deterministic diagnostics, and canonical Agent IR output;
- immutable ObjectIDs, pending/terminal future nodes, budget accounting,
  checkpoint/restore, task verification evidence, verified-only commit, trace,
  and deterministic DAG hashing;
- immutable AgentFS object/root persistence with idempotent put/get,
  compare-and-swap publication, conflict preservation, and target coverage;
- an authenticated append-only 20-class event-stream core with deterministic
  hash chaining and replay projections;
- versioned WIT definitions for ten provider-neutral capability seams, explicit
  effect mappings, interchangeable-provider fixtures, and grammar/conformance
  validation;
- native harness authority mapping and AArch64 target assertions;
- host coverage for all operations, denial paths, concurrent completion
  conflicts, malformed inputs, deterministic hashing, and restore/commit rules.

The current wire name `VERIFY` means `TASK_VERIFY`. Long operations create
pending tickets, but lower-PD async adapters are not yet complete. AgentLang
execution, the deterministic IR-to-WASM compiler, generated host/WASM SDK,
`RUN_PROGRAM`, mandatory event emission and durable stream integration across
all runtime boundaries, scoped actor lifecycle, passivation,
continual-harness tier, hidden promotion service, and six-arm benchmark are
requirements in this PRD, not claims about the current implementation.

The repository has a documented Headscale architecture and ongoing `net_pd`
and WireGuard work, but it does not yet provide the Fractal Mesh QUIC protocol,
remote audience-bound grants, cross-device AgentHandles, shared-space
anti-entropy, authority leases, or the external local gateway. Native AgentOS
standard-tailnet interoperability is not boot-proven. The initial deployable
path therefore remains Headscale in the FreeBSD controller guest plus standard
tailscaled clients and the shared-memory bridge.

The AArch64 target currently proves protocol and authority behavior inside the
native coding harness. It does not yet prove that the complete programmable
runtime or every async lower-service adapter executes on seL4.
