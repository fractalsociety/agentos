/*
 * target_contract_runner.c — on-target seL4 contract TAP runner (agentos-0h4)
 *
 * This is the Microkit protection domain that proves the *core* agentOS IPC
 * contracts against REAL seL4 IPC, on real (or QEMU-emulated) seL4 hardware.
 * It is the target-proof counterpart to the host-only mock suite that runs
 * under -DAGENTOS_TEST_HOST with the tests/microkit.h stub: where the host
 * suite issues PPCs into a stub that merely echoes MR0 back, this PD issues
 * genuine microkit_ppcall()s across real channels into the live PDs and
 * observes their real replies.
 *
 *   HOST  (mock):   make test-integration            (tests/microkit.h stub)
 *   TARGET (proof): make sel4-test-image + run-tests  (this PD, real IPC)
 *
 * Scope (the core IPC contracts named in agentos-0h4):
 *   - EventBus        (MONITOR_CH_EVENTBUS)
 *   - CC-PD           (CH_CC_PD)
 *   - serial_pd       (CH_SERIAL_PD)
 *   - log_drain       (CH_LOG_DRAIN)
 *   - guest lifecycle (CH_GUEST_PD)
 *
 * Each suite is the SAME run_*_tests(ch) function compiled into the host mock
 * suite — there is exactly one contract assertion body per PD, exercised in
 * two environments.  We do not fork a parallel set of assertions.
 *
 * Output: TAP version 14 on the serial console, terminated by the
 * "TAP_DONE:<code>" sentinel that xtask run-tests (cmd_run_tests.rs) waits on.
 * tf_tap_finish() emits the plan + pass/fail summary but NOT the sentinel, so
 * this runner emits it explicitly after the summary.
 *
 * Wiring (owned by the root-task build, see tests/TARGET_TESTS.md):
 *   Build this file plus the five tests/contracts/_test.c suites into the
 *   root task when SEL4_TEST_IMAGE=1, and call target_contract_runner_main()
 *   from main.c under #ifdef AGENTOS_SEL4_TEST_IMAGE in place of the current
 *   one-line stub TAP.
 *
 * Copyright (c) 2026 The agentOS Project
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "test_framework.h"
#include "../../kernel/agentos-root-task/include/agentos.h"

/* ── Contract suites under test (defined in tests/contracts/_test.c files) ── */

void run_eventbus_tests(microkit_channel ch);
void run_cc_tests(microkit_channel ch);
void run_serial_pd_tests(microkit_channel ch);
void run_log_drain_tests(microkit_channel ch);
void run_guest_tests(microkit_channel ch);

/* ── Emit the run-tests sentinel ──────────────────────────────────────────── */
/*
 * tf_tap_finish() prints "1..N", "# passed", "# failed" but intentionally does
 * NOT print the TAP_DONE sentinel (it is shared with the simulator harness,
 * which has its own completion path).  cmd_run_tests.rs::parse_tap_done() keys
 * off "TAP_DONE:<code>" with code 0 == pass, so derive the code from the
 * framework's running fail counter.
 */
static inline void target_tap_done(void)
{
    _tf_puts("TAP_DONE:");
    _tf_put_uint((uint64_t)(_tf_fail > 0 ? 1 : 0));
    _tf_puts("\n");
}

/* ── Entry point ──────────────────────────────────────────────────────────── */
/*
 * Run the core contract suites against real channels, then emit the summary
 * and the sentinel.  Channels come from agentos.h and match the controller's
 * view of each PD endpoint.
 */
void target_contract_runner_main(void)
{
    tf_tap_init("agentOS-target-contracts");

    run_eventbus_tests((microkit_channel)MONITOR_CH_EVENTBUS);
    run_cc_tests((microkit_channel)CH_CC_PD);
    run_serial_pd_tests((microkit_channel)CH_SERIAL_PD);
    run_log_drain_tests((microkit_channel)CH_LOG_DRAIN);
    run_guest_tests((microkit_channel)CH_GUEST_PD);

    tf_tap_finish();
    target_tap_done();
}
