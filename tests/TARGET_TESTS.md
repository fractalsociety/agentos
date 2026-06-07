# agentOS Tests: Host Unit Tests vs Target Proof

agentOS has **two distinct layers** of automated test, and they prove different
things. Conflating them is a category error: a green host run does **not** mean
the IPC contract holds on real seL4.

| Layer            | What runs                                   | seL4 IPC?        | How to run                                  |
|------------------|---------------------------------------------|------------------|---------------------------------------------|
| Host unit/mock   | `tests/**/*_test.c` under `-DAGENTOS_TEST_HOST` | **No** — `tests/microkit.h` stub echoes MR0 | `make test-integration`, `xtask host-test`  |
| Simulator        | `userspace/sim/` in-memory seL4 model       | Modeled, in-process | `cargo test -p agentos-sim`                 |
| **Target proof** | seL4 root task + PDs in QEMU/hardware        | **Yes** — real `microkit_ppcall` | `make test-target`, `make run-tests`        |

> Rule of record (CLAUDE.md): never mock seL4 IPC for tests — the host stub is a
> *compile/logic* check only. The simulator and the target proof are the real
> coverage. This document exists so nobody mistakes the host mock for proof.

## Host unit / mock layer (NOT proof)

`tests/microkit.h` provides a stub `microkit_ppcall()` that simply returns its
argument and leaves the message registers untouched. So a contract test built
with `-DAGENTOS_TEST_HOST -I tests` exercises the *test body's* logic and the
struct/opcode definitions, but the PD under test is never invoked. Useful as a
fast compile gate and for pure-logic PDs (DVFS model, schedulers); useless as
proof that a live PD honours its contract.

Driven by:
- `make test-integration` — compiles + runs the host `tests/*.c` set.
- `make test-snapshot-sched`, `make test-power-mgr`, `make test-proc-server`,
  `make test-vibeos-contract` — individual host suites.

## Target proof layer (real seL4 IPC) — agentos-0h4

The target suite boots the actual seL4 root task and PDs in QEMU and issues
**real** `microkit_ppcall()`s across real channels, then reads the live replies.

- Runner: `tests/harness/target_contract_runner.c`
  → `target_contract_runner_main()` runs the SAME `run_*_tests(ch)` bodies that
  the host mock compiles, but against real channels:
  EventBus (`MONITOR_CH_EVENTBUS`), CC-PD (`CH_CC_PD`), serial_pd
  (`CH_SERIAL_PD`), log_drain (`CH_LOG_DRAIN`), guest lifecycle (`CH_GUEST_PD`).
- TAP: emitted to the serial console via `microkit_dbg_puts` (no libc), ending
  in the `TAP_DONE:<code>` sentinel that `xtask run-tests`
  (`xtask/src/cmd_run_tests.rs`) waits on.
- Image build: `make sel4-test-image BOARD=<board>` (sets `SEL4_TEST_IMAGE=1`,
  `GUEST_OS=none`).
- Gate: `make test-target` (per board) / `make test-target-all` (both arches),
  defined in `mk/target-tests.mk`.

```
make test-target TARGET_ARCH=aarch64 GUEST_OS=none
make test-target TARGET_ARCH=x86_64  GUEST_OS=none
```

## CC-PD VirtIO timeout proof — agentos-45b

CC-PD reaches its host controller over a VirtIO-MMIO serial console
(`build/cc_pd.sock`). `vio_serial_write()` / `vio_serial_read()` in
`kernel/agentos-root-task/src/cc_pd.c` spin on the VirtIO *used* ring with a
bounded wait (`CC_VIRTIO_WAIT_LIMIT`). If the ring never advances they log
`[cc_pd] TX timeout waiting for used ring` / `[cc_pd] RX timeout ...` and return
`false`, and the main loop `continue`s — the PD stays responsive.

`tests/harness/cc_virtio_timeout_test.sh` boots the test image with the CC-PD
console on a unix socket, sends one request frame, then **stops draining** the
socket so the TX used ring stalls. It asserts:
1. the bounded-wait timeout log line appears (error path is *observed*, not just
   compiled),
2. no kernel panic, and
3. QEMU/the root task is still alive afterwards (responsiveness).

Gate (in `mk/target-tests.mk`):

```
make test-cc-virtio-timeout BOARD=qemu_virt_aarch64
```

## Required wiring (owned by other files — see OUT-OF-SCOPE in the bead)

`mk/target-tests.mk` is self-contained except for one include line. The Makefile
owner must add to the root `Makefile`:

```make
include mk/target-tests.mk
```

For the target *contract* runner (agentos-0h4) to actually execute the five
suites instead of the current one-line stub TAP, the root-task build owner must
also:

1. **Compile** `tests/harness/target_contract_runner.c` and the five suites
   `tests/contracts/{eventbus,cc,serial_pd,log_drain,guest}_test.c` into the
   root task **when `SEL4_TEST_IMAGE=1`** (add them to the test-image object
   list in `kernel/agentos-root-task/Makefile`, with include paths
   `-I tests/harness -I tests -I kernel/agentos-root-task/include`).
2. **Call** `target_contract_runner_main()` from
   `kernel/agentos-root-task/src/main.c`, replacing the current stub under
   `#ifdef AGENTOS_SEL4_TEST_IMAGE` (lines ~1825-1830):

   ```c
   #ifdef AGENTOS_SEL4_TEST_IMAGE
       void target_contract_runner_main(void);
       target_contract_runner_main();   /* emits TAP + TAP_DONE */
   #endif
   ```

Until step 1+2 land, `make test-target` still builds and boots the image and
reports the stub TAP (`ok 1 - root task booted ...`); the five real-IPC suites
are present and compile but are not yet invoked on target. This is called out as
UNVERIFIED in the bead handoff.
