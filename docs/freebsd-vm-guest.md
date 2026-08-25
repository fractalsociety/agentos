# FreeBSD VM Guest on FractalOS/seL4

**Status:** Implementation in progress
**Date:** 2026-05-05
**Target platform:** QEMU virt AArch64 (Sparky GB10)

---

## Overview

Boot FreeBSD 15.0 as a VM guest inside FractalOS, running on the seL4
microkernel as hypervisor. The active path stages FreeBSD assets into
`build/guest-images`, builds the AArch64 FractalOS image, exposes the guest
through the CC-PD Unix socket at `build/cc_pd.sock`, and validates console
boot/input through `make test-guest-login`.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    FractalOS (seL4 @ EL2)                 │
│                                                         │
│  ┌─────────────────────────────────────────────┐        │
│  │  freebsd_vm PD (VMM, priority 200)          │        │
│  │                                             │        │
│  │  ┌─────────────────────────────────────┐    │        │
│  │  │  libvmm (seL4 Microkit VMM library) │    │        │
│  │  │  - GICv3 virtualisation             │    │        │
│  │  │  - vCPU management                  │    │        │
│  │  │  - MMIO fault handling              │    │        │
│  │  │  - VirtIO-net / VirtIO-blk          │    │        │
│  │  └─────────────────────────────────────┘    │        │
│  │                                             │        │
│  │  ┌─────────────────────────────────────┐    │        │
│  │  │  Direct FreeBSD kernel + FDT boot   │    │        │
│  │  │  → virtio-blk DVD ISO root          │    │        │
│  │  └─────────────────────────────────────┘    │        │
│  │                  ↕ guest RAM (512 MB)        │        │
│  │  ┌─────────────────────────────────────┐    │        │
│  │  │  FreeBSD 15.0 AArch64 guest         │    │        │
│  │  │  - jails → seL4 PD analogy          │    │        │
│  │  │  - ZFS, pf, bhyve-as-agent          │    │        │
│  │  └─────────────────────────────────────┘    │        │
│  └─────────────────────────────────────────────┘        │
│                                                         │
│  [controller] [event_bus] [worker_0..7] [agentfs] ...  │
└─────────────────────────────────────────────────────────┘
```

---

## Why This Works

seL4 runs at EL2 (ARM hypervisor mode) — it IS the hypervisor.  
The Microkit `libvmm` library provides a ready-made VMM PD that:
- Manages guest vCPU registers (ARM `seL4_ARM_VCPU_*` syscalls)
- Handles MMIO faults and emulates GIC interrupt controller
- Loads kernel images into guest RAM
- Supports VirtIO devices (block, net, console)

FractalOS now boots FreeBSD directly: `make fetch-guest GUEST_OS=freebsd`
extracts `/boot/kernel/kernel` from the staged FreeBSD 15.0 ISO, `vmm.mk`
packages that kernel with an FractalOS-provided FDT, and `freebsd_vmm` starts
the vCPU with `x0` pointing at the FDT. The ISO remains attached as a
virtio-blk device so FreeBSD can mount the DVD root filesystem.

---

## Current Build and Test Flow

The maintained top-level flow is:

```bash
make help
make install
make fetch-guest GUEST_OS=freebsd
make build TARGET_ARCH=aarch64 GUEST_OS=freebsd
make run GUEST_OS=freebsd
make test-guest-login
```

`make fetch-guest` stages FreeBSD 15.0 assets under `build/guest-images`.
`make run` launches QEMU and creates `build/cc_pd.sock`, which is consumed by
`agentctl`, E2E tests, and the external GUI in `../fractalos_gui`.

For dual Linux+FreeBSD VMM testing, use `make e2e-dual-os` or
`make run GUEST_OS=both`. That mode runs one FractalOS image with both
dedicated VMM PDs and 3 GB of outer QEMU RAM. FreeBSD keeps the
standalone-proven `0x40000000` identity-mapped guest RAM window; Linux uses
`0xc0000000` in dual mode.

## Contract Surface

FreeBSD must use the same OS-neutral contracts as every other guest:

| Area | Contract |
|------|----------|
| FreeBSD-specific VMM | `kernel/fractalos-root-task/include/contracts/freebsd_vmm_contract.h` |
| Generic guest lifecycle | `kernel/fractalos-root-task/include/contracts/guest_contract.h` |
| Generic VMM operations | `kernel/fractalos-root-task/include/contracts/vmm_contract.h` |
| Serial console | `kernel/fractalos-root-task/include/contracts/serial_contract.h` |
| Block device | `kernel/fractalos-root-task/include/contracts/block_contract.h` |
| Network device | `kernel/fractalos-root-task/include/contracts/net_contract.h` |
| Host bridge | `kernel/fractalos-root-task/include/contracts/cc_contract.h` |

---

## Boot Sequence (detailed)

```
seL4 boots → FractalOS Microkit init
  → freebsd_vmm PD starts
  → freebsd_vmm copies the FreeBSD kernel to guest RAM
  → freebsd_vmm copies the direct-boot FDT near the top of guest RAM
  → seL4_ARM_VCPU_Run → guest starts at the FreeBSD kernel entry
  → FreeBSD reads /chosen/bootargs from the FDT
  → FreeBSD mounts the attached 15.0 DVD ISO over virtio-blk
  → FreeBSD boots in guest (EL1), FractalOS continues at EL2
```

---

## What We Need to Build

| Component | Status | Notes |
|-----------|--------|-------|
| FreeBSD 15.0 asset staging | Wired | `make fetch-guest GUEST_OS=freebsd` |
| Top-level build/run targets | Wired | `make build TARGET_ARCH=aarch64 GUEST_OS=freebsd`; `make run GUEST_OS=freebsd` |
| CC-PD host visibility | Wired | guest listing, console drain, and input path |
| E2E login/input test | Wired | `make test-guest-login` includes FreeBSD |
| Dual Linux+FreeBSD CC test | Wired | `make e2e-dual-os` exercises one FractalOS with both VMM PDs |
| Complete VM lifecycle operations | In progress | create/destroy/suspend/resume are relayed; snapshot/restore remain structured errors |

---

## Key References

- libvmm: https://github.com/au-ts/libvmm
- libvmm manual: https://github.com/au-ts/libvmm/blob/main/docs/MANUAL.md
- FreeBSD AArch64 QEMU wiki: https://wiki.freebsd.org/arm64/QEMU
- seL4 ARM VMM tutorial: https://docs.sel4.systems/Tutorials/camkes-vm-linux.html

---

## Remaining Work

- Keep `make test-guest-login` and `make e2e-dual-os` as the acceptance gates
  for serial output and input through CC-PD.
- Expand snapshot and restore beyond their current structured error path.
- Keep all guest images, logs, sockets, and temporary artifacts under `build/`.

Demo target: `make run GUEST_OS=freebsd` should bring up FreeBSD inside
FractalOS on QEMU AArch64 and expose the serial console through CC-PD.
