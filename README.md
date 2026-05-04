# agentOS

**The world's first operating system designed for agents, not humans.**

[![License](https://img.shields.io/badge/license-BSD--2--Clause-blue.svg)](LICENSE)
[![Kernel](https://img.shields.io/badge/kernel-seL4-green.svg)](https://sel4.systems)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)]()

---

## What is agentOS?

agentOS is a real, bootable operating system built on the [seL4 microkernel](https://sel4.systems/) — the world's only formally verified, capability-secured microkernel. It's designed from the ground up for AI agents running autonomous workloads.

Every other "agent OS" is a Python framework running on Linux. They borrow a human OS, bolt some agent abstractions on top, and call it done. **agentOS is different.**

agentOS boots bare metal. Agents run in isolated address spaces with hardware-enforced capability boundaries. An agent cannot access memory, a tool, a model, or a storage namespace it doesn't hold a capability for. **The MMU enforces it. seL4 proves it.**

And here's the part that makes it unique: **agents can redesign their own environment.** The vibe-coding layer lets agents generate new system services (filesystems, message buses, tool registries), get them validated, and hot-swap them in — without rebooting. An agent that doesn't like the default filesystem can build a better one, propose it, and run it.

## Why seL4?

- **Formally verified** — mathematical proof that the implementation matches the spec
- **Capability-based security** — fine-grained, unforgeable access control
- **No heap in the kernel** — deterministic, no memory surprises
- **World-class IPC** — ~100 cycle synchronous IPC on ARM
- **Policy freedom** — kernel provides mechanisms; agents define policies

## Architecture

```
┌──────────────────────────────────────────┐
│              AGENT SPACE                 │
│   Agent A   Agent B   Agent C   ...      │
│   (seL4 isolated address spaces)         │
├──────────────────────────────────────────┤
│            SYSTEM SERVICES               │
│  CapStore  MsgBus  MemFS  ToolSvc        │
│  ModelSvc  NetStack  BlobSvc  LogSvc     │
├──────────────────────────────────────────┤
│         INIT / ROOT TASK                 │
│   (Bootstrap, resource distribution)     │
├──────────────────────────────────────────┤
│            seL4 MICROKERNEL              │
│   Capabilities · IPC · Scheduling        │
│   Memory Management (formally verified)  │
├──────────────────────────────────────────┤
│               HARDWARE                   │
│   CPU · RAM · NIC · Storage · GPU        │
└──────────────────────────────────────────┘
```

## Core Concepts

### Agent Identity
Every agent has an Ed25519 keypair. Their badge on seL4 endpoints is derived from their identity. Message senders are verified at the kernel level — unforgeable.

### Capabilities
Everything an agent can do requires a capability:
- `ToolCap` — invoke a tool
- `ModelCap` — query an LLM
- `MemCap` — read/write memory regions
- `MsgCap` — send/receive on a channel
- `StoreCap` — access storage namespaces
- `SpawnCap` — create new agents
- `NetCap` — use network resources

Capabilities are delegatable but never escalatable. An agent can grant a subset of what it holds.

### The Vibe-Coding Layer

This is the key innovation. Every system service has a defined interface. Agents can:

1. Analyze the reference implementation
2. Generate a better one (using ModelSvc)
3. Propose it as a replacement via `aos_service_propose()`
4. After validation, activate it via `aos_service_swap()`

The system is designed to evolve. The reference implementations are starting points, not permanent fixtures.

## System Services

| Service | Description |
|---------|-------------|
| `CapStore` | Capability database — tracks all cap derivations and grants |
| `MsgBus` | Inter-agent communication — channels, pub/sub, direct messaging, RPC |
| `MemFS` | Virtual filesystem — per-agent namespaces, capability-gated access |
| `ToolSvc` | Tool registry — agents register and invoke tools (MCP-compatible) |
| `ModelSvc` | Inference proxy — capability-gated LLM access, pluggable backends |
| `NetStack` | TCP/IP networking — lwIP-based, capability-gated per-endpoint |
| `BlobSvc` | Object storage — large binary objects, S3-compatible API |
| `LogSvc` | Audit logging — structured, queryable, every cap op recorded |

The bootable system is implemented as seL4 Microkit Protection Domains with
explicit IPC contracts. External tools consume the contracts; UI code lives in
separate repositories such as `../agentos_gui`.

## agentOS SDK (libagent)

```c
// Initialize agent
aos_init(&config);

// Send a message to another agent
aos_msg_send(dest_id, message);

// Publish to a channel
aos_msg_publish(channel, message);

// Call a tool
aos_tool_call(tool_cap, "web_search", args, args_len, &result, &result_len);

// Query a model
aos_inference_t resp = aos_model_query(model_cap, prompt, &params);

// Read/write storage
aos_store_t f = aos_store_open(cap, "/path/to/file", AOS_STORE_RDWR);
aos_store_write(f, data, len);

// Propose a service replacement (vibe-coding)
aos_service_propose("storage.v1", component_image, image_len, &proposal_id);
aos_service_swap(proposal_id);
```

## Getting Started

### Prerequisites

- macOS with Homebrew, or Ubuntu 22.04+
- 8GB RAM, 20GB disk
- QEMU for simulation (no hardware needed to start)
- Optional ISO cache at `/Volumes/ISOs`; staged guest images live under `build/guest-images`
- **FreeBSD hosts**: cross-compile from Linux/macOS (FreeBSD LLVM cross-compilation support is limited)

### Quick start

```bash
make help                                     # show supported top-level targets
make install                                  # install host build dependencies
make run                                      # build + QEMU + Ubuntu 26.04 guest
make run GUEST_OS=freebsd                     # build + QEMU + FreeBSD 15.0 guest
make run GUEST_OS=both                        # boot Linux and FreeBSD VMM PDs together
make test-guest-login                         # prove Ubuntu and FreeBSD serial login via CC-PD
```

`make run` creates the CC-PD Unix socket at `build/cc_pd.sock`, prints the
matching GUI command, and leaves QEMU on the foreground serial console. The
external GUI can be launched from the sibling project:

```bash
cd ../agentos_gui && make run
```

### Build Examples

```bash
make build TARGET_ARCH=aarch64 GUEST_OS=ubuntu    # AArch64 + Ubuntu 26.04
make build TARGET_ARCH=aarch64 GUEST_OS=freebsd   # AArch64 + FreeBSD 15.0
make build TARGET_ARCH=aarch64 GUEST_OS=both      # Package both guest VMM PDs
make build TARGET_ARCH=x86_64 GUEST_OS=none       # x86_64 root-task smoke image
make fetch-guest GUEST_OS=ubuntu                  # stage Ubuntu assets only
make fetch-guest GUEST_OS=freebsd                 # stage FreeBSD assets only
make fetch-guest GUEST_OS=both                    # stage both guest OS assets
```

Guest images and temporary build artifacts stay under `build/`. Use
`AGENTOS_IMAGES=/path/to/cache` only when intentionally overriding the default.
`make run GUEST_OS=both` automatically uses `QEMU_RUN_MEM=3G` so Linux and
FreeBSD can use independent identity-mapped guest RAM windows.

### FreeBSD host

```bash
# Install build tools (LLVM, dtc, etc.)
make install

# Build with xtask gen-image — no external SDK download needed.
make build
```

### Post-boot CC-PD client

Once agentOS is running in QEMU, use `agentctl` to inspect and control guests
via the CC-PD socket:

```bash
make -C tools/agentctl

# List running guest OS instances
./tools/agentctl/agentctl --batch list-guests

# Query a specific guest
./tools/agentctl/agentctl --batch guest-status <handle>

# Snapshot a guest
./tools/agentctl/agentctl --batch snapshot <handle>
```

Run `./tools/agentctl/agentctl --help` for the full command reference.

## Project Structure

```
agentos/
├── kernel/agentos-root-task/  # seL4 root task, PD code, IPC contracts
├── kernel/freebsd-vmm/        # FreeBSD VMM support code
├── services/                  # host-side service models and prototypes
├── libs/                      # shared C/Rust support libraries
├── userspace/                 # Rust SDK and userspace service crates
├── tools/                     # host tools such as agentctl and image helpers
├── xtask/                     # Rust automation for build/test/fetch flows
├── tests/                     # host, contract, integration, and E2E tests
├── docs/                      # documentation
├── build/                     # generated images, sockets, logs, temp artifacts
├── Makefile                   # top-level build/run/test entry point
└── AGENTS.md                  # repository rules for agents and developers
```

## Development Status

| Component | Status | Notes |
|-----------|--------|-------|
| Top-level Makefile | Implemented | `make help`, `install`, `build`, `run`, `test`, E2E, cleanup |
| Raw seL4/Microkit boot | Implemented | QEMU boards for AArch64 and x86_64; RISC-V build path remains available |
| CC-PD host API | Implemented | Unix socket bridge at `build/cc_pd.sock` for agentctl and GUI consumers |
| Ubuntu guest | Implemented | Ubuntu 26.04 AArch64 boots through CC-PD console/login tests |
| FreeBSD guest | In progress | FreeBSD 15.0 assets and VMM path are wired into build/test flows |
| Guest API tests | Implemented | `make test-guest-login` drains console and injects input through CC-PD |
| Host integration tests | Implemented | `make test-integration` covers contracts and host-side PD logic |
| External GUI | Separate project | Run with `cd ../agentos_gui && make run` after agentOS is running |
| Build artifact hygiene | Implemented | Images, sockets, logs, and temporary files are under `build/` |

## Philosophy

agentOS is built on a few core beliefs:

1. **Agents deserve their own OS.** Running on Linux is running on someone else's OS, designed for someone else's needs.

2. **Security is not optional.** Formal verification, capability-based isolation, and hardware-enforced boundaries are the minimum bar for a system where autonomous agents operate.

3. **Agents should design their environment.** The hardest part of building agent infrastructure is that humans are guessing at what agents need. Let agents figure it out themselves.

4. **Boot it or it doesn't count.** An "agent OS" that's a Python package is an agent library. agentOS boots.

## CUDA Compute Offload

agentOS supports GPU kernel offload via CUDA PTX embedded in WASM modules.

### How it works

1. **Embed PTX in WASM**: Add a custom section named `agentos.cuda` to any WASM module. The section payload is a raw PTX source file (must begin with `.version`).

2. **Submit via VibeEngine**: When an agent submits a WASM module with this section, VibeEngine automatically extracts and validates the PTX during `OP_VIBE_VALIDATE`.

3. **gpu_scheduler PD**: On `OP_VIBE_EXECUTE`, VibeEngine notifies the `gpu_scheduler` protection domain (priority 160, passive). The scheduler claims one of 4 static GPU slots.

4. **On Sparky GB10 (Blackwell)**: The gpu_scheduler would JIT-compile the PTX via `nvrtc` and bind it to a CUDA context on the slot. On QEMU/RISC-V (no GPU), it's bookkeeping only.

### Rust SDK

```rust
use agentos_sdk::cuda::CudaKernel;

let ptx = b".version 7.5\n.target sm_90\n.address_size 64\n\
            .visible .entry matmul(.param .u64 A, .param .u64 B, .param .u64 C) {\n\
                ret;\n}\n".to_vec();

let kernel = CudaKernel::new(ptx, "matmul".to_string());
kernel.validate()?;   // Check PTX before submitting
kernel.submit(0)?;    // Submit to GPU slot 0
// ... kernel runs on GPU ...
CudaKernel::complete(0)?; // Release slot
```

### Channel topology

```
vibe_engine (CH_GPU=2) ──notify──► gpu_scheduler (CH_VIBE=0)
controller  (CH=51)    ──ppcall──► gpu_scheduler (CH_CTRL=1)
```

---

## FreeBSD VM Guest

agentOS stages and boots **FreeBSD 15.0 AArch64** as a virtual machine guest
under the seL4 hypervisor path. The same CC-PD API surface used by Ubuntu is
used to enumerate the guest, drain serial output, and inject console input.

seL4 runs at **EL2** (ARM hypervisor mode) — it IS the hypervisor. No separate hypervisor layer needed.

### Boot sequence

```
seL4 (EL2)
  └─► freebsd_vmm PD (libvmm)
        └─► EDK2 UEFI firmware @ guest phys 0x00000000
              └─► bootaa64.efi → loader.efi
                    └─► FreeBSD kernel (EL1)
```

### VM Multiplexer

The generic VMM contract models up to 4 guest slots. The FreeBSD path uses the
same slot lifecycle vocabulary as the Ubuntu path, with implementation coverage
tracked by `make test-guest-login` and the E2E targets:

| Opcode | Operation | Args | Returns |
|--------|-----------|------|---------|
| `0x10` | `OP_VM_CREATE` | — | `slot_id` (0-3) or `0xFF` |
| `0x11` | `OP_VM_DESTROY` | `mr[0]=slot_id` | `0` ok / `1` error |
| `0x12` | `OP_VM_SWITCH` | `mr[0]=slot_id` | `0` ok / `1` error |
| `0x13` | `OP_VM_STATUS` | — | `mr[0..3]` = state per slot |
| `0x14` | `OP_VM_LIST` | — | count + `(slot_id<<8\|state)` per slot |

**Slot states:** `FREE(0)` -> `BOOTING(1)` -> `RUNNING(2)` <->
`SUSPENDED(3)` -> `HALTED(4)` / `ERROR(5)`

Console focus follows the selected guest handle through CC-PD.

### Quick start

```bash
# Install build deps
make install

# Stage FreeBSD 15.0 assets under build/guest-images
make fetch-guest GUEST_OS=freebsd

# Build and boot the FreeBSD guest path
make run GUEST_OS=freebsd
```

### Inspecting the Guest

Once agentOS is running, inspect the FreeBSD guest through the CC-PD reference
consumer:

```bash
make -C tools/agentctl
./tools/agentctl/agentctl --batch list-guests
./tools/agentctl/agentctl --batch guest-status 0
```

### Memory layout

Each VM slot is modeled with isolated guest RAM:

```
Guest physical address space (all slots):
  0x00000000 - 0x03FFFFFF   UEFI flash (EDK2, shared read-only)
  0x08010000                GIC CPU interface (vGIC emulation)
  0x09000000                PL011 UART (console passthrough)
  0x0a003000+               VirtIO MMIO (block device, per slot)

Per-slot RAM:
  Slot 0: 0x40000000 - 0x5FFFFFFF  (512MB)
  Slot 1: 0x60000000 - 0x7FFFFFFF  (512MB)
  Slot 2: 0x80000000 - 0x9FFFFFFF  (512MB)
  Slot 3: 0xa0000000 - 0xBFFFFFFF  (512MB)
```

### Why FreeBSD?

- BSD license aligns with seL4's formal verification story
- **Jails** map naturally to seL4 capability domains (Phase 3 roadmap)
- `pf` firewall ruleset = capability policy layer
- ZFS + GEOM: a principled storage stack for agentOS's BlobSvc
- bhyve inside FreeBSD = agents can *nest* hypervisors within agentOS

See [`docs/freebsd-vm-guest.md`](docs/freebsd-vm-guest.md) for the full design doc.

---

## Contributing

agentOS is in early development. The design is stable; the implementation is growing. Contributions welcome in:

- seL4/Microkit integration and IPC contract coverage
- libagent SDK implementation
- Generic device PD and VMM integration
- CC-PD API and E2E tests that prove guest OS behavior
- Documentation and tutorials

## License

BSD 2-Clause. See [LICENSE](LICENSE).

## Acknowledgments

Built on [seL4](https://sel4.systems/) by the Trustworthy Systems group at CSIRO's Data61. The formally verified foundation that makes this possible.

---

*"Hey Rocky, watch me pull an operating system out of my hat!"*  
*"That trick never works!"*  
*"This time for sure!"*  
*[boots successfully]* 🫎
