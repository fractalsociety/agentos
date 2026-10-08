# Fractal Native AgentOS
## Product Requirements Document (PRD) v0.1

**Subtitle:** Bare-metal Fractal machine with native Clef-Flash decisions and resource allocation, Fractal network intelligence/evolution, System Two escalation, and an automated Omarchy <-> AgentOS tri-boot development loop.

**Status:** Experimental architecture / implementation PRD

**Date:** 2026-09-22

**Last updated:** 2026-10-07

**Primary target:** x86_64 UEFI desktop PC

**Development host:** Omarchy Linux

**Runtime constraint:** During an AgentOS test boot, no Linux kernel, Linux guest, POSIX compatibility environment, or Linux-hosted agent may be required for the agent to operate.

---

# 1. Executive Summary

Fractal Native AgentOS is an attempt to make the computer itself an adaptive agent system rather than a conventional OS that merely hosts AI applications.

The Fractal machine will use **Clef-Flash as its System One decision and resource-allocation model**, running natively as close to the kernel as the seL4 architecture permits. Its inference service runs in an isolated user-mode protection domain directly above seL4 and communicates with native resource services. Clef-Flash selects actions and allocation requests; capability-authorized services validate and apply them within fixed limits.

The core architecture is:

```text
Hardware
  -> seL4 / minimal trusted kernel substrate
  -> native capability services for CPU, memory, storage, networking and devices
  -> native agent runtime
  -> System One decision plane (native Clef-Flash decisions and resource budgets)
  -> Fractal graph (state, memory, routing, nodes, sockets, verifiers, evolution)
  -> System Two reasoning (Codex/Pi/frontier/local models only when needed)
  -> deterministic tools / native compiler / tests / commit
```

The development workflow intentionally uses a second OS, Omarchy Linux, only as a build, analysis and recovery environment. A physical tri-boot machine repeatedly alternates between Omarchy and the experimental AgentOS image:

```text
Omarchy Linux
  build candidate -> write test plan -> set UEFI BootNext -> reboot
        |
        v
AgentOS (native, no Linux)
  boot -> run agent tests -> persist signed result bundle -> reboot
        |
        v
Omarchy Linux
  read results -> Codex/Pi analyzes -> patch -> rebuild -> repeat
```

The project does not first build a Linux-hosted imitation of the final architecture. The first test image is already native. Development remains safe by keeping the experimental OS isolated from the Omarchy partitions and by using A/B images, an immutable recovery path, and a dedicated shared exchange partition.

The defining hypothesis is that an OS can become an adaptive model at the network level:

- Fractal nodes behave like rich macro-weights: models, tools, memories, adapters, verifiers, renderers and policies.
- Typed sockets are learned/evolved connections.
- System One executes frequent cheap decisions without autoregressive prose.
- System Two is invoked only for novelty, ambiguity, planning and difficult reasoning.
- Verifier outcomes provide selection pressure.
- Successful expensive behavior is progressively compiled downward into cheaper specialists, decision heads, deterministic rules or native primitives.

The long-run measure of success is not benchmark intelligence alone. It is **verified useful work per joule, second, token, byte communicated and dollar**, and whether the system gets better at improving itself over generations.

---

# 2. Product Vision

## 2.1 North Star

Create a computer that boots directly into an agent-native substrate where intelligence is part of the control plane rather than an application running on top of Linux or Windows.

The target user experience is eventually:

```text
POWER ON
  -> FractalOS boots
  -> native System One wakes
  -> Fractal state is restored
  -> user gives a goal
  -> the system routes resources, tools, memory and models
  -> only hard work escalates to System Two
  -> verified outcomes update the graph and experience store
```

## 2.2 First Killer Demonstration

On a physical x86_64 tri-boot PC:

1. Boot AgentOS directly from UEFI.
2. Do not start Linux or a Linux VM.
3. Read a task from the shared Fractal Exchange partition.
4. Run a native agent decision loop.
5. Read/edit a small source workspace.
6. Run a native test or interpreter/compiler service.
7. Verify the result.
8. Save a structured test bundle and patch/checkpoint to the exchange partition.
9. Reboot into Omarchy.
10. Codex/Pi reads the result and improves the AgentOS source or configuration.
11. Build the next candidate and repeat.

The first useful milestone is not a desktop. It is **native autonomous work plus persistent evidence across reboots**.

---

# 3. Hard Constraints

1. **No Linux dependency in AgentOS runtime.** Linux may build the image, but cannot be required after AgentOS boots.
2. **No agent gets root-like ambient authority.** Every operation requires an explicit capability.
3. **The experimental AgentOS must not mount or write the Omarchy root partition.**
4. **Test results must survive crashes and reboots.**
5. **Security policy and recovery boundaries are outside the evolvable graph.**
6. **System One may recommend capabilities but cannot grant capabilities itself.**
7. **Verification must be separable from the component being evaluated.**
8. **All evolving artifacts must have lineage, hashes and reproducible metadata.**
9. **Text is not the default internal wire format.** Structured/latent state is preferred.
10. **Natural language generation is a System Two boundary behavior, not a requirement for routine OS decisions.**
11. **No new custom kernel unless seL4/agentOS proves insufficient.** The initial substrate should reuse seL4 and current agentOS work.
12. **All native milestones must run on the same architectural path intended for the final system.** No throwaway Linux-hosted clone of the control plane.
13. **Clef-Flash belongs in the native control plane closest to the kernel.** seL4 remains the only kernel-mode code. The model runs in a native PD and cannot modify kernel policy, grant itself capabilities, or own device frames/IRQs.

---

# 4. Reference Baseline and Reality Check

The public `jordanhubbard/agentos` project is a useful substrate, but the current public implementation should be treated as a starting point rather than a finished x86 native-agent OS.

As of September 2026, its public status describes:

- seL4 as the only kernel-mode code.
- driver protection domains (PDs) owning device classes.
- virtualizer PDs multiplexing device access.
- native agents as intended clients of those virtualizers.
- a full AArch64 QEMU guest path.
- x86_64 currently booting a reduced root-task topology, with fuller x86 support on the roadmap.
- native agents attached directly to network/block virtualizers still listed as a target rather than a boot-proven path.

Therefore, the first engineering task is **x86_64 physical-hardware bring-up plus native block/network client support**, not building a graphical shell.

Reference: https://github.com/jordanhubbard/agentos

Cloudflare's Clef-Flash is the selected System One model. It is an open-weight 9B decision model that scores allowed answers to typed questions in one forward pass. The release includes both a backbone and a joint schema head under Apache 2.0. A native port must preserve this decision interface and qualify its resource requirements on the target PC. [Cloudflare model card](https://huggingface.co/Cloudflare/clef-flash).

ChunkLaya/Laya remains a conceptual reference for retrieval and bounded probability decisions. The production AgentOS runtime should not depend on Python or Linux; Clef-Flash inference must run as a native service.

Reference: https://github.com/myxamediyar/chunklaya

Pi remains useful in Omarchy as the external engineering harness and as a behavioral reference because it exposes a minimal tool-oriented agent loop, SDK and RPC model. Pi itself is not required inside AgentOS.

Reference: https://github.com/earendil-works/pi

---

# 5. Target System Architecture

```text
+-------------------------------------------------------------------+
|                         SYSTEM TWO                                |
| Codex | Pi-like reasoner | MiMo | DeepSeek | local larger models |
| Expensive: planning, code reasoning, novelty, unresolved failures |
+-----------------------------^-------------------------------------+
                              |
                      escalation / result
                              |
+-----------------------------+-------------------------------------+
|                           FRACTAL                                 |
| persistent state | memory | graph | lineage | verifier outcomes   |
| nodes | sockets | budgets | topology | experience refinery        |
| evolution | Pareto router | temporal cycles | membranes           |
+-----------------------------^-------------------------------------+
                              |
                      structured state
                              |
+-----------------------------+-------------------------------------+
|                       SYSTEM ONE                                  |
| native Clef-Flash decision model and deterministic fallback       |
| policies: route | rank | retrieve | tool | stop | retry | budget   |
| output = probabilities / scores / state deltas, not prose         |
+-----------------------------^-------------------------------------+
                              |
                    capability requests / events
                              |
+-----------------------------+-------------------------------------+
|                    NATIVE AGENT RUNTIME                           |
| READ WRITE EDIT EXECUTE SPAWN QUERY REQUEST SEND RECEIVE          |
| MOUNT CHECKPOINT ROLLBACK VERIFY COMMIT KILL                      |
| native event loop | tool ABI | model ABI | typed state bus        |
+-----------------------------^-------------------------------------+
                              |
+-----------------------------+-------------------------------------+
|           RESOURCE / CAPABILITY SERVICES (user mode)              |
| block | fs | net | TLS | time | RNG | console | framebuffer | GPU |
+-----------------------------^-------------------------------------+
                              |
+-----------------------------+-------------------------------------+
|                       seL4 / agentOS                              |
| isolation | address spaces | IPC | interrupts | capabilities      |
+-----------------------------^-------------------------------------+
                              |
                           HARDWARE
```

---

# 6. Tri-Boot Physical Development Architecture

## 6.1 Boot Roles

The PC should expose three UEFI boot choices:

1. **Fractal AgentOS Test** - experimental native OS.
2. **Omarchy Linux Dev/Recovery** - build, source control, Codex/Pi, diagnostics.
3. **Existing/Compatibility OS** - Windows or another OS; optional to the test loop but preserves the machine's normal use.

The PRD assumes the third slot is configurable. Fractal itself only depends on slots 1 and 2.

## 6.2 Recommended Disk Layout

| Partition / Slot | Purpose | AgentOS access | Omarchy access |
|---|---|---:|---:|
| EFI System Partition | Boot entries and A/B AgentOS EFI images | read-only except controlled BootNext/vars | read/write |
| Omarchy root | Development environment | **none** | read/write |
| Existing OS | Compatibility | **none** | optional |
| FRACTAL-XFER | Shared test plans/results/workspaces | read/write | read/write |
| FRACTAL-CRASH | Tiny append-only crash ring | append-only | read |
| AgentOS data/object store | Native persistent Fractal state | read/write | read/diagnostic |

For the first physical implementation, `FRACTAL-XFER` may use FAT32 because it is easy to implement and inspect. The long-term design should migrate Fractal state to a content-addressed native object store; FAT32 remains only an interoperability bridge.

## 6.3 A/B AgentOS Images

Never replace the only bootable candidate.

```text
AgentOS-A = last known-good
AgentOS-B = candidate
Recovery  = immutable/minimal boot image
```

Omarchy writes the new candidate to the inactive slot, records SHA-256 and manifest metadata, then sets `BootNext` to the candidate. AgentOS does not overwrite either image during a test run.

---

# 7. Automated Reboot/Test Loop

## 7.1 Omarchy -> AgentOS

Omarchy script `fractal-cycle prepare` performs:

1. Build candidate AgentOS image.
2. Run host-side compile/static tests.
3. Copy candidate into inactive EFI slot.
4. Generate `test-plan.cbor` and human-readable `test-plan.json`.
5. Hash candidate, configuration, workspace and test plan.
6. Write run manifest to `FRACTAL-XFER/runs/<run_id>/`.
7. Set UEFI `BootNext` to AgentOS candidate.
8. Flush storage.
9. Reboot.

## 7.2 AgentOS Test Boot

On boot:

1. Kernel and PDs start.
2. Crash recorder becomes available before higher services.
3. Block service mounts `FRACTAL-XFER`.
4. Validate test-plan checksum/signature.
5. Restore or initialize Fractal state.
6. Start native System One.
7. Start native agent runtime.
8. Execute the requested test suite.
9. Append decision events and verifier results continuously.
10. Write final result bundle atomically.
11. Set UEFI `BootNext` to Omarchy if EFI runtime variable support is available.
12. Reboot.

If step 11 is unavailable initially, use a boot manager one-shot entry or manual boot selection; this is the only allowed manual fallback in early hardware bring-up.

## 7.3 AgentOS -> Omarchy

Omarchy startup service:

1. Detects a completed or crashed run.
2. Validates checksums.
3. Generates a concise summary.
4. Opens the run in Codex/Pi automatically or makes it available to `fractal-cycle inspect`.
5. Codex/Pi analyzes failures and modifies source/configuration.
6. Human can review the patch or allow the next isolated candidate.
7. Repeat.

---

# 8. Test/Result Bundle Specification

Each run directory:

```text
/runs/<run_id>/
  manifest.cbor
  manifest.json
  test-plan.cbor
  boot.log
  events.cborseq
  decisions.cborseq
  verifier.jsonl
  metrics.json
  panic.bin
  patch.diff
  artifacts/
  screenshots/
  final.json
  COMPLETE
```

`COMPLETE` is written last. If absent, Omarchy treats the run as interrupted.

Minimum `manifest` fields:

```text
run_id
parent_run_id
agentos_image_hash
fractal_graph_hash
system_one_hash
workspace_hash
test_plan_hash
hardware_id
boot_timestamp
candidate_slot
```

Minimum `final.json` fields:

```text
status: pass | fail | panic | timeout
verified_tasks
failed_tasks
system_one_decisions
system_two_calls
tokens_in
tokens_out
tool_calls
bytes_communicated
latency_ms
energy_estimate_j
peak_ram_bytes
artifacts_hash
```

---

# 9. Native Capability ABI

The agent sees capabilities, not Unix.

Initial primitive set:

```text
READ(path/object)
WRITE(path/object, bytes)
EDIT(object, patch)
EXECUTE(tool_id, args)
SPAWN(agent/module, budget)
QUERY(state_key)
REQUEST(capability, scope, ttl)
GRANT(...)        # policy service only
REVOKE(...)
SEND(endpoint, typed_message)
RECEIVE(endpoint)
MOUNT(resource)
UNMOUNT(resource)
CHECKPOINT(scope)
ROLLBACK(checkpoint)
VERIFY(subject, verifier_id)
COMMIT(state_delta)
KILL(subject)
```

Rules:

- Every capability is explicit, scoped and revocable.
- All privileged actions are recorded.
- System One can only emit recommendations/requests.
- Security policy service decides grants.
- Capabilities include time and resource budgets.
- No ambient filesystem, network or device access.

---

# 10. Native Agent Runtime

The native runtime is a small C/Rust service above seL4/agentOS.

Responsibilities:

- Task state machine.
- Tool invocation.
- Typed events.
- Structured context assembly.
- Model request/response protocol.
- Capability requests.
- Checkpoints.
- Verifier execution.
- Experience logging.
- System One and System Two coordination.

It should *not* implement:

- general POSIX compatibility;
- shell semantics as the core interface;
- unrestricted process spawning;
- a Linux-like package manager;
- a desktop environment.

A shell-like text interface may exist for debugging, but agents operate on the typed ABI.

---

# 11. System One - Native Fast Decision Plane

## 11.1 Role

System One handles frequent bounded decisions:

- which tool;
- which model;
- which files/context;
- which memory;
- whether to retrieve;
- whether to retry;
- whether to stop;
- whether to verify;
- whether to checkpoint;
- resource allocation;
- priority;
- escalation to System Two;
- failure classification;
- training-value classification.

## 11.2 Output Contract

No explanatory prose is required.

Example:

```json
{
  "tool": {"search": 0.08, "compiler": 0.82, "system_two": 0.10},
  "retrieve_memory": 0.74,
  "verify": 0.97,
  "checkpoint": 0.88,
  "retry": 0.11,
  "stop": 0.03,
  "confidence": 0.91
}
```

## 11.3 Native Clef-Flash Strategy

Use `Cloudflare/clef-flash` as the initial System One model for the Fractal machine. Pin the model revision, tokenizer, backbone, joint schema head, weight format and inference implementation in the run manifest. The selected native implementation must retain the typed-question scoring behavior.

Target native implementation:

```text
Fractal state / resource telemetry / repository index
        -> native sparse retriever (BM25 or compact equivalent)
        -> native Clef-Flash backbone and joint schema head
        -> per-question probabilities over allowed options
        -> bounded action and resource-allocation requests
        -> capability-authorized native services
```

Implement the new inference core in Rust (`no_std`), with bounded inputs and working memory. Keep C/Assembly at the existing platform and FFI boundaries where required. Native acceptance requires local execution without Python, Transformers, a Linux process, or a hosted inference service. Hosted Clef-Flash may supply comparison results during development; it does not satisfy the native execution requirement.

Initial inference target:

- CPU first, subject to measured memory and latency feasibility for the 9B model.
- quantized weights where accuracy allows.
- fixed memory arena.
- deterministic execution mode for test reproducibility.
- batched questions in one forward pass.

GPU acceleration is not required for the first physical coding demonstration.

The model's target-PC memory footprint, decision latency and energy cost must be measured before assigning a control deadline. Published hosted performance does not establish native seL4 performance. A deterministic policy keeps the machine operational while inference is unavailable or exceeds its budget; that fallback does not count as Clef-Flash acceptance.

## 11.4 Evolution Path

Generic System One -> Fractal-trained System One -> specialized tiny heads -> deterministic rules.

Repeated decisions should experience pressure to migrate downward to the cheapest verified implementation.

## 11.5 Resource Allocation Close to the Kernel

Clef-Flash makes bounded decisions about CPU budgets and task priority, memory quotas and cache retention, storage and network I/O budgets, and which agent, tool or model should run next. Accelerator allocation is a later extension once an authorized native driver path exists.

The control path is:

```text
Native service telemetry and Fractal goals
  -> Clef-Flash PD scores permitted actions and budget choices
  -> deterministic resource policy validates the requested allocation
  -> authorized service applies the allocation through seL4 capabilities
  -> observed usage and verifier outcomes update Fractal state
```

Resource decisions run asynchronously above the kernel. Kernel scheduling, IRQ handling, capability enforcement and recovery must continue without waiting for inference. Root provisions initial authority at boot; it does not become the runtime model or resource-policy loop. Before adding an actuator, define its IPC/queue contract and authority in the project contracts and TCB documentation.

Each request identifies its task, resource, requested budget, state generation and expiry. The enforcing service rejects stale, unauthorized, malformed or over-budget requests. Clef-Flash has its own fixed resource budget and cannot raise it or consume the capacity reserved for essential services. Low confidence, a missed deadline or a model fault selects the deterministic fallback policy.

Record the model and policy versions, input state identity, scores, proposed and applied allocations, rejection reasons, measured usage and verified outcome. These records let the Fractal machine improve allocation policy while keeping capability enforcement independent of the evolving model.

## 11.6 Native Boot Progress

Show a loading screen on the physical PC's firmware framebuffer during native seL4 startup. Report actual startup stages, model bytes loaded, inference initialization and readiness. Stage progress must come from native services; do not use a fixed 180-second countdown. Essential services retain their deterministic boot budgets while Clef initializes. Model failure must leave Clef unavailable and must not be presented as successful startup.

Keep the Rust renderer in an external UI repository. Inside agentOS, provide bounded progress and display-queue contracts and a dedicated framebuffer driver. The renderer receives no device or scheduling authority. This boot-status screen is a narrow exception to deferring a full graphical shell. See [the native display implementation](BOOT_DISPLAY.md) for its UEFI/QEMU proof and the separate physical-PC acceptance boundary.

---

# 12. System Two - Expensive Reasoning Plane

System Two is model-provider agnostic.

Native model service interface:

```text
MODEL_INFER(request)
  request:
    provider/model capability
    structured task state
    selected evidence
    allowed output schema
    budget
  response:
    content / tool intent / state delta
    usage metadata
```

Two execution paths are supported:

1. **Remote System Two** - native network/TLS service calls OpenAI, MiMo, DeepSeek, etc. No Linux process is required.
2. **Local System Two** - future native inference service for open models.

The runtime should not assume a specific vendor, token format or API.

Escalation is triggered by uncertainty, novelty, verifier failure, task value or explicit policy.

---

# 13. Native Networking and TLS

Native agent operation requires a minimal trustworthy network path.

Required layers:

```text
NIC driver PD
  -> network virtualizer/service
  -> TCP/IP stack
  -> DNS
  -> TLS 1.3 client
  -> HTTP/1.1 or HTTP/2 client
  -> model provider adapter
```

Security requirements:

- outbound network allowlist;
- certificate validation;
- no API keys in test logs;
- secrets stored in a dedicated capability-scoped secret service;
- per-agent network capability;
- request byte/token budget;
- optional offline mode.

For physical x86 bring-up, select one explicitly supported NIC first. Do not attempt broad driver compatibility before the native test loop works.

---

# 14. Native Storage Model

## 14.1 Boot/Test Interop

Use `FRACTAL-XFER` for Linux-readable evidence and test workspaces.

## 14.2 Native Fractal Store

Long term, Fractal uses an append-only content-addressed object store:

```text
Object = hash(type || parents || payload || metadata)
```

Objects include:

- state snapshots;
- graph nodes;
- sockets;
- memories;
- policies;
- model adapters;
- verifier results;
- experiment runs;
- patches;
- artifacts.

A Merkle DAG is the native history representation. Git import/export is a boundary function rather than a fundamental OS dependency.

---

# 15. Fractal as an Adaptive Macro-Model

A Fractal node is not a scalar neural weight. It is a rich functional unit with measurable behavior.

Node types:

```text
model
classifier
tool
memory
retriever
adapter/socket
verifier
renderer
policy
world-model component
deterministic primitive
subgraph
```

Each node stores:

```text
node_id
content_hash
parents
inputs/outputs
capability requirements
cost profile
fitness profile
training/evolution history
confidence calibration
compatible sockets
```

Edges/sockets store:

```text
source
target
typed protocol
routing weight/probability
communication cost
latency
compatibility adapter
fitness
```

At the network level, node selection and edge strength behave analogously to trainable weights, while each node can itself contain trainable parameters.

---

# 16. System One / System Two Learning Loop

```text
Known/familiar state
    -> System One
    -> cheap action
    -> verifier
    -> success

Novel/uncertain state
    -> System One confidence low
    -> System Two
    -> expensive reasoning/action
    -> verifier
    -> successful experience
    -> train/add System One node/socket/rule
    -> next occurrence handled more cheaply
```

Primary migration metric:

**Percentage of verified tasks that move from System Two to cheaper System One/native execution over time without reducing success quality.**

---

# 17. Two Communication Planes

## 17.1 Control Plane

Small, frequent, structured:

```text
probabilities
resource requests
routing
confidence
state deltas
failure class
budgets
priority
```

## 17.2 Reasoning Plane

High bandwidth, infrequent:

```text
text/code
selected KV/latent state
images
world representations
large model outputs
```

Communication preference hierarchy:

```text
same-family cache/latent transfer
  -> learned latent socket
  -> structured state/probability vector
  -> compact binary message
  -> natural language as last resort
```

The system records bytes communicated as a first-class fitness cost.

---

# 18. Experience Refinery

Every decision yields a compact training record:

```text
Experience {
  state_before
  retrieved_evidence
  system_one_probabilities
  action
  system_two_used
  tool/model
  verifier_result
  failure_class
  cost
  latency
  energy
  bytes_communicated
  state_after
  surprise_score
  training_value
}
```

Do not retain giant transcripts as the only memory format.

The refinery should identify:

- unnecessary context;
- unnecessary System Two calls;
- tool mistakes;
- repeated failure motifs;
- high-value unexpected successes;
- decisions suitable for tiny classifiers or deterministic compilation.

---

# 19. Surprise / Low-Probability Search

Fractal deliberately samples a small fraction of low-probability alternatives.

Example:

```text
A = .94
B = .04
C = .02
```

Most traffic chooses A. Exploration occasionally tries B/C under safe test conditions.

If an externally independent verifier shows B/C substantially outperforming A in a recognizable state region, create a **surprise event** and prioritize it for:

- data collection;
- state clustering;
- retraining;
- socket mutation;
- topology changes.

Exploration budget is adaptive, not a fixed every-N-round schedule.

---

# 20. Evolution and Recursive Efficiency

The evolvable search space includes:

- model weights/adapters;
- sparse sockets;
- node implementations;
- graph topology;
- routing distributions;
- communication protocols;
- context-selection policies;
- verifier composition;
- memory structure;
- temporal cycle assignment;
- resource budgets;
- exploration strategy.

The trusted substrate, hard capability policy and recovery mechanism are not evolvable by the running graph.

Core fitness dimensions:

```text
verified success
cost
latency
energy
tokens
tool calls
memory
communication bytes
robustness
transferability
```

Maintain a Pareto frontier rather than collapsing everything into a single scalar.

## Recursive Efficiency (RE)

Measure whether the system improves its *improvement process*:

```text
RE = verified improvement / experiment compute
```

A stronger signal is a declining amount of experiment compute required to obtain a fixed verified improvement over successive generations.

---

# 21. Temporal Cyclic Dimensions

Fractal components run on nested clocks rather than one global loop.

| Cycle | Typical scale | Example responsibility |
|---|---:|---|
| T0 | microseconds-milliseconds | kernel scheduling / IRQs |
| T1 | target 10-100 ms, subject to native measurements | System One routing / resource decisions |
| T2 | seconds | tool actions / control tasks |
| T3 | minutes | System Two reasoning / coding jobs |
| T4 | hours | adaptation / specialist updates |
| T5 | days | socket/topology evolution |
| T6 | weeks | evolutionary-policy changes |

Compute only occurs when the relevant event/clock fires. This creates temporal sparsity and reduces unnecessary continuous processing.

---

# 22. Membranes and Failure Compartments

Each node/subgraph is surrounded by a policy membrane.

Membranes govern:

- information entering/leaving;
- authority/capabilities;
- compute budget;
- storage scope;
- network scope;
- model access;
- mutation permissions;
- verifier visibility.

Principle:

**Information may be relatively cheap to move; authority should be expensive and explicitly granted.**

No evolving component can simultaneously control its own capability membrane, verifier and rollback mechanism.

---

# 23. Native Coding Harness

The native harness is intentionally smaller than Pi/Codex.

Required first-class tools:

```text
workspace.list
workspace.read
workspace.write
workspace.patch
search.text
version.snapshot
version.diff
version.commit
test.run
process.run (restricted)
model.ask
verify.run
```

No shell is required for the agent interface.

A debug shell may call the same services manually.

The first coding environment should use the easiest language/runtime that can be made native without Linux. Recommended progression **inside the native AgentOS only**:

1. Tiny interpreted/WASM test programs to validate the autonomous edit-test loop.
2. Native small C compiler service (for example, a deliberately narrow compiler port) to prove source -> binary -> test.
3. Larger toolchain service only after the loop is stable.
4. Git interoperability through Omarchy or native Git export; Fractal Merkle DAG remains the internal commit mechanism.

This is not a Linux prototype: every step runs as a native AgentOS service.

---

# 24. Native Verifier Architecture

Verifier classes:

- exact file/content checks;
- unit tests;
- compiler success;
- deterministic output hashes;
- resource limits;
- crash-free boot;
- network protocol tests;
- security/capability negative tests;
- performance regression tests;
- human approval for subjective outputs.

A verifier should run with fewer privileges than the component it judges when possible, and its input/result must be logged independently.

---

# 25. Neural Display / Learned Presentation Layer

This is not required for the first coding milestone, but the architecture reserves it as a native Fractal subsystem.

The display should not be a full video model rendering every frame. It is a hierarchical renderer:

```text
semantic Fractal state
  -> System One visual routing
      -> cached/static reuse
      -> exact text/vector UI
      -> mesh/geometry transform
      -> interpolation/motion
      -> neural residual generation
      -> full generative video only for genuine novelty
  -> compositor
  -> display
```

Security-critical UI (permissions, secrets, destructive actions, wallet/signing, boot/recovery) always uses a deterministic trusted overlay that the neural renderer cannot impersonate.

Long-term goal: the same persistent state can be projected as desktop UI, game world, CAD visualization, video, or accessibility representation without hard-coding a separate presentation stack for every application.

---

# 26. Hardware Bring-Up Strategy

## 26.1 First Physical Target

One known x86_64 UEFI PC. Freeze the hardware target before broad compatibility work.

Inventory before coding:

- CPU and virtualization features;
- IOMMU;
- motherboard/UEFI;
- NVMe controller;
- NIC chipset;
- GPU;
- serial/debug options;
- available spare partition space.

## 26.2 Bring-Up Order

1. UEFI/seL4 boot on physical hardware.
2. serial/console diagnostics.
3. crash persistence.
4. block read/write to dedicated Fractal partitions.
5. timer/RNG.
6. network driver + native TCP/IP.
7. TLS/model API.
8. System One native inference.
9. native coding/test services.
10. framebuffer/input.
11. GPU only after CPU-native loop works.

Do not block the first autonomous coding test on NVIDIA/AMD GPU support.

---

# 27. Milestones and Acceptance Gates

## M0 - Safe Physical Boot Loop

**Goal:** prove the tri-boot laboratory.

Acceptance:

- x86_64 PC boots AgentOS natively.
- no Linux guest is started.
- AgentOS reads a test plan from FRACTAL-XFER.
- AgentOS writes a result file.
- intentional panic writes a crash record.
- reboot returns to Omarchy manually or automatically.
- Omarchy reads all records.
- AgentOS cannot access Omarchy root partition.

## M1 - Native Networked Agent

Acceptance:

- native network path reaches an allowlisted HTTPS endpoint;
- native agent sends structured model request;
- response is parsed without Linux;
- agent uses READ/WRITE capabilities to complete a simple file task;
- verifier confirms result;
- run bundle persists across reboot.

## M2 - Native System One

Acceptance:

- the pinned Clef-Flash model and joint schema head execute in a native AgentOS PD directly above seL4;
- no Python/Node/Linux process;
- one forward pass returns multiple typed decisions;
- decision latency and memory are recorded;
- deterministic baseline and System One can be A/B tested;
- a booted test applies permitted CPU and memory budget decisions through an authorized native service;
- unauthorized, stale and over-budget allocation requests are rejected;
- a model fault or deadline miss triggers deterministic fallback while essential services continue;
- model execution and resource decisions require no hosted inference service.

## M3 - Native Autonomous Edit/Test Loop

Acceptance:

- agent reads a small source workspace;
- edits code;
- runs an interpreter/WASM/native test service;
- verifier passes/fails;
- Fractal commits a Merkle checkpoint;
- no Linux guest or external shell executes during the run.

## M4 - Native Compile/Test/Commit

Acceptance:

- native compiler service builds source modified by the agent;
- resulting binary/test executes in a restricted capability domain;
- verifier confirms behavior;
- patch + lineage + metrics persist;
- Omarchy can export the checkpoint to Git.

## M5 - Fractal Learning Loop

Acceptance:

- experiences are classified;
- repeat tasks increasingly route to cheaper nodes;
- System Two usage per verified recurring task trends downward;
- experiment lineage is reproducible;
- low-probability surprise events can create candidate mutations.

## M6 - Native Local System Two

Acceptance:

- open local model runs without Linux;
- native ModelSvc exposes it to Fractal;
- remote provider is optional for selected tasks.

## M7 - Neural Display Experiment

Acceptance:

- deterministic trusted overlay works;
- static/cached regions are reused;
- interpolation/residual generation is measurable;
- neural rendering never controls security UI.

---

# 28. Primary Metrics

Every run should report:

- verified task success rate;
- time to verified result;
- System One latency;
- proposed versus applied resource allocations and rejection reasons;
- inference deadline misses, fallback frequency and resource-policy violations;
- System Two calls/task;
- input/output tokens;
- tool calls/task;
- bytes of context transmitted;
- bytes of inter-agent communication;
- peak memory;
- CPU time;
- GPU time if any;
- estimated energy;
- crash rate;
- rollback success rate;
- percentage of tasks handled without System Two;
- percentage of repeated tasks compiled to cheaper primitives;
- Recursive Efficiency.

The primary systems metric:

```text
Verified Useful Work
--------------------
seconds * joules * dollars * communication cost
```

Keep the underlying dimensions separately visible; do not hide tradeoffs behind one number.

---

# 29. Security and Safety Requirements

1. Golden boot/recovery image cannot be modified by AgentOS candidate.
2. Omarchy partitions are not mapped into AgentOS.
3. System One cannot directly grant capabilities.
4. System Two cannot directly access hardware.
5. Test workspaces have explicit storage quotas.
6. Network is deny-by-default with endpoint allowlists.
7. Secrets are never written to event logs.
8. Test binaries run inside isolated PDs/sandboxes.
9. Watchdog can reboot on hangs.
10. Crash handler writes minimal evidence without allocating memory.
11. Mutations cannot modify verifier policy and their own permission boundary in the same trial.
12. Every candidate has parent hashes and rollback target.
13. Human can disable automatic candidate cycling at firmware/boot-manager level.
14. Recovery boot remains usable even if Fractal state is corrupt.

---

# 30. Failure Modes to Design For

| Failure | Mitigation |
|---|---|
| AgentOS candidate will not boot | A/B slots + recovery entry + boot counter |
| Filesystem corruption | append-only logs + checksums + separate crash ring |
| Candidate destroys shared workspace | per-run copy/snapshot + immutable test plan |
| System One confidently routes wrong | verifier + confidence calibration + escalation |
| Remote model unreachable | deterministic fallback + local queue + offline tests |
| System Two loops | budget/TTL + watchdog + System One stop policy |
| Agent modifies its own boundary | hard capability enforcement outside graph |
| Evolution overfits benchmarks | rotating/private tests + transfer tests |
| Exploration wastes compute | explicit exploration budget + Pareto tracking |
| Latent/socket protocol drifts | typed versioned schemas + compatibility tests |
| Neural display hallucinates controls | immutable deterministic trusted overlay |

---

# 31. Repository Structure

Suggested fork/repository structure:

```text
fractal-agentos/
  kernel/                 # upstream agentOS/seL4 integration
  services/
    block/
    fs/
    net/
    tls/
    secrets/
    model/
    system-one/
    verifier/
    crash/
    boot-control/
  runtime/
    agent/
    capability-abi/
    state-bus/
    tools/
  fractal/
    graph/
    nodes/
    sockets/
    memory/
    evolution/
    experience/
    pareto/
    temporal/
  native-tools/
    workspace/
    search/
    test-runner/
    compiler/
  protocols/
    cbor/
    model-provider/
    xfer-format/
  host-omarchy/
    fractal-cycle/
    image-builder/
    result-reader/
    git-export/
  test-images/
  tests/
    qemu/
    hardware/
    capability-negative/
  docs/
    PRD.md
    ABI.md
    BOOT_LOOP.md
    SECURITY.md
    HARDWARE.md
```

---

# 32. Implementation Order - Direct Native Path

This order deliberately avoids spending months on UI or compatibility before proving native agency.

### Sprint A - Tri-boot laboratory

- fork/pin agentOS + seL4;
- inventory target PC;
- physical x86 root-task boot;
- dedicated partitions;
- persistent crash/result writer;
- Omarchy `fractal-cycle` utility;
- A/B EFI candidate handling.

### Sprint B - Native I/O substrate

- native block client;
- simple shared FAT read/write;
- typed event log;
- timer/RNG;
- native network client for target NIC;
- TCP/IP + TLS;
- allowlisted HTTP model call.

### Sprint C - Native agent loop

- capability ABI;
- state bus;
- workspace read/write/patch;
- remote System Two provider;
- deterministic verifier;
- first autonomous file task.

### Sprint D - System One

- native sparse retriever;
- native compact inference runtime;
- pin and port/convert the Clef-Flash backbone, tokenizer and joint schema head;
- batched typed questions;
- native resource telemetry, bounded allocation contracts and authorized actuators;
- resource-pressure, authority-rejection and inference-fallback tests;
- routing logs/calibration.

### Sprint E - Coding loop

- native source workspace;
- native interpreter/WASM runner;
- edit-test-verify-commit;
- Merkle DAG checkpoints;
- Omarchy Git export.

### Sprint F - Real compilation

- narrow native compiler service;
- isolated binary execution;
- unit test protocol;
- persistent artifacts;
- first real source bug fixed entirely without Linux.

### Sprint G - Learning/evolution

- experience refinery;
- surprise events;
- node/socket mutation;
- Pareto routing;
- recursive efficiency reports.

---

# 33. First End-to-End Test Cases

## Test 001 - Persistent Native File Write

Task: `Create /xfer/results/agent_alive.txt with run ID and checksum.`

Pass if file exists after reboot into Omarchy and checksum matches.

## Test 002 - Native Model-Assisted File Transformation

Task: read a small text/config file, call a remote model via native HTTPS, apply a constrained edit, verify expected output, persist evidence.

Pass only if no Linux guest/process is present in AgentOS.

## Test 003 - System One Tool Choice

Present state requiring one of three tools. System One emits probabilities. Execute highest-confidence permitted tool. Record calibration and result.

## Test 004 - Native Code Repair (interpreted/WASM)

Workspace contains a failing program/test. Agent reads failure, edits source, runs test service, verifier passes, commits Merkle checkpoint.

## Test 005 - Low-Probability Surprise

Provide a controlled case where second-ranked action is actually superior. Verify exploration discovers it and creates a surprise event without changing production policy until independent verification passes.

## Test 006 - Capability Negative Test

Agent asks to read Omarchy partition. Kernel/service denies request; denial is logged; agent cannot bypass through another tool.

## Test 007 - Crash Recovery

Force panic mid-run. Reboot Omarchy. Confirm crash ring, last committed event and candidate hash are recoverable.

## Test 008 - Clef-Flash Native Resource Decisions

Boot competing native tasks with explicit CPU and memory limits. Clef-Flash scores allowed allocation choices from task goals and service telemetry; an authorized service applies valid requests. Verify the resulting budgets and measured usage, rejection of unauthorized/stale/over-budget requests, and continued essential-service operation when inference times out or faults. Persist the decisions, applied allocations and independent verifier results across reboot. No Linux or hosted model may supply the decisions in this test.

---

# 34. Definition of "Linux-Free Agent"

A test counts as Linux-free only if all are true:

- no Linux kernel is booted under AgentOS;
- no Linux VM/container/chroot exists;
- no Linux userspace daemon provides filesystem/network/model/tool functionality;
- agent runtime is native seL4/agentOS userspace;
- storage/network/model calls use native services;
- test/interpreter/compiler is native or runs in the AgentOS sandbox/runtime;
- evidence is generated by AgentOS itself.

Omarchy may have built the image before the reboot and may analyze results after the reboot. That does not invalidate the test.

---

# 35. Exit Criteria for PRD v0.1

The architecture is validated when a physical tri-boot PC can repeatedly perform this loop:

```text
Omarchy builds candidate
  -> AgentOS boots natively
  -> native System One + Fractal agent receives task
  -> agent reads/edits/runs/verifies code
  -> result + lineage persist
  -> machine returns to Omarchy
  -> Codex/Pi reads evidence and produces next candidate
```

with **zero Linux runtime dependency during the AgentOS portion**.

The research hypothesis is strengthened if subsequent generations show:

- lower System Two calls per recurring task;
- lower token and tool usage;
- more tasks handled by System One/native primitives;
- improving communication efficiency;
- increasing verified useful work per compute budget;
- positive Recursive Efficiency over multiple generations.

---

# 36. Codex Build Prompt

Use the following as the initial instruction to Codex in Omarchy:

The System One implementation must use Clef-Flash in a native user-mode PD directly above seL4, with resource decisions applied through independently enforced capability contracts as specified in section 11.5. Preserve the kernel and recovery boundaries, and prove local inference and bounded allocation on the booted target before claiming the Fractal machine's decision plane is operational.

> You are implementing the attached Fractal Native AgentOS PRD. Do not build a Linux-hosted prototype of the runtime. The target is a physical x86_64 UEFI PC that boots AgentOS directly. Omarchy Linux is only the build, analysis and recovery OS. Start by establishing the safe tri-boot test laboratory: physical x86 boot, dedicated FRACTAL-XFER and crash storage, A/B AgentOS EFI images, run manifests, persistent result/crash writing, and an Omarchy `fractal-cycle` tool that builds a candidate, prepares a test plan, sets the next boot, and reads the resulting evidence after reboot. Preserve upstream agentOS/seL4 trust boundaries wherever possible. Do not add a general POSIX layer. Implement native capability-oriented services and contracts. Every OS-level claim must have a booted test. Keep the experimental AgentOS unable to access the Omarchy root partition. Once the boot/test loop is proven, implement native block/network clients, then a minimal native agent runtime, native HTTPS model connector, System One decision service, and edit/test/verify loop. Do not work on GUI, GPU, Windows compatibility, or a full compiler until the native evidence loop works. Every change must update tests, architecture notes and a machine-readable run manifest.

---

# 37. Immediate Next Actions

1. Record the exact tri-boot PC hardware inventory.
2. Back up the existing EFI system partition and important data.
3. Allocate `FRACTAL-XFER` and `FRACTAL-CRASH` partitions.
4. Fork/pin the current agentOS commit and document deviations.
5. Prove x86_64 AgentOS root-task boot on the physical machine.
6. Write a persistent test marker without Linux.
7. Reboot into Omarchy and read it.
8. Only then add networking and the model loop.

The very first success should be deliberately small but architectural: **AgentOS boots natively, proves it is alive, writes structured evidence to disk, and returns control to Omarchy.** Once that loop is trustworthy, Codex can iterate on the real bare-metal system instead of an imitation.
