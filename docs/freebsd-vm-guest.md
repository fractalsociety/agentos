# FreeBSD VM Guest on agentOS/seL4

**Status:** Implementation in progress
**Date:** 2026-05-02
**Target platform:** QEMU virt AArch64 (Sparky GB10)

---

## Overview

Boot FreeBSD 15.0 as a VM guest inside agentOS, running on the seL4
microkernel as hypervisor. The active path stages FreeBSD assets into
`build/guest-images`, builds the AArch64 agentOS image, exposes the guest
through the CC-PD Unix socket at `build/cc_pd.sock`, and validates console
boot/input through `make test-guest-login`.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    agentOS (seL4 @ EL2)                 │
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
│  │  │  UEFI firmware (EDK2 AArch64)       │    │        │
│  │  │  → loader.efi → FreeBSD kernel      │    │        │
│  │  └─────────────────────────────────────┘    │        │
│  │                  ↕ guest RAM (1–2GB)         │        │
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

FreeBSD AArch64 needs UEFI or U-Boot to hand it the UEFI system table pointer.
We use the pre-built `edk2-aarch64-code.fd` UEFI firmware — same as QEMU uses for FreeBSD guests — embedded as a binary in the VMM PD.

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
`agentctl`, E2E tests, and the external GUI in `../agentos_gui`.

For dual Linux+FreeBSD VMM testing, use `make run GUEST_OS=both`. That mode
automatically runs QEMU with 3 GB RAM so the FreeBSD VMM can use its
independent `0xc0000000` identity-mapped guest RAM window.

## Contract Surface

FreeBSD must use the same OS-neutral contracts as every other guest:

| Area | Contract |
|------|----------|
| FreeBSD-specific VMM | `kernel/agentos-root-task/include/contracts/freebsd_vmm_contract.h` |
| Generic guest lifecycle | `kernel/agentos-root-task/include/contracts/guest_contract.h` |
| Generic VMM operations | `kernel/agentos-root-task/include/contracts/vmm_contract.h` |
| Serial console | `kernel/agentos-root-task/include/contracts/serial_contract.h` |
| Block device | `kernel/agentos-root-task/include/contracts/block_contract.h` |
| Network device | `kernel/agentos-root-task/include/contracts/net_contract.h` |
| Host bridge | `kernel/agentos-root-task/include/contracts/cc_contract.h` |

---

## Boot Sequence (detailed)

```
seL4 boots → agentOS Microkit init
  → freebsd_vmm PD starts
  → libvmm: copy EDK2 firmware to guest flash region (0x0000_0000)
  → libvmm: configure vCPU entry at EDK2 reset vector
  → seL4_ARM_VCPU_Run → guest executes EDK2 UEFI firmware
  → EDK2 scans VirtIO block → finds FreeBSD EFI partition
  → EDK2 loads bootaa64.efi → loads loader.efi → loads /boot/kernel/kernel
  → loader.efi passes UEFI system table ptr → FreeBSD kernel takes over
  → FreeBSD boots in guest (EL1), agentOS continues at EL2
```

---

## What We Need to Build

| Component | Status | Notes |
|-----------|--------|-------|
| FreeBSD 15.0 asset staging | Wired | `make fetch-guest GUEST_OS=freebsd` |
| Top-level build/run targets | Wired | `make build TARGET_ARCH=aarch64 GUEST_OS=freebsd`; `make run GUEST_OS=freebsd` |
| CC-PD host visibility | Wired | guest listing, console drain, and input path |
| E2E login/input test | Wired | `make test-guest-login` includes FreeBSD |
| Full multi-user FreeBSD boot | In progress | Current test accepts login or maintenance prompt |
| Complete VM lifecycle operations | In progress | create/destroy/snapshot/restore are contract-backed |

---

## Key References

- libvmm: https://github.com/au-ts/libvmm
- libvmm manual: https://github.com/au-ts/libvmm/blob/main/docs/MANUAL.md
- FreeBSD AArch64 QEMU wiki: https://wiki.freebsd.org/arm64/QEMU
- seL4 ARM VMM tutorial: https://docs.sel4.systems/Tutorials/camkes-vm-linux.html
- EDK2 AArch64: pkg install edk2-bhyve OR build from tianocore/edk2

---

## Remaining Work

- Complete full FreeBSD 15.0 multi-user boot from the staged image.
- Keep `make test-guest-login` as the acceptance gate for serial output and
  input through CC-PD.
- Expand lifecycle coverage for create, destroy, snapshot, and restore.
- Keep all guest images, logs, sockets, and temporary artifacts under `build/`.

Demo target: `make run GUEST_OS=freebsd` should bring up FreeBSD inside
agentOS on QEMU AArch64 and expose the serial console through CC-PD.
