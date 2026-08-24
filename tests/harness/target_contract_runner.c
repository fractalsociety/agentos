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
#include "../../kernel/agentos-root-task/include/sel4_ipc.h"
#include "../../contracts/modelsvc/interface.h"
#include "../../kernel/agentos-root-task/include/contracts/agent_harness_contract.h"

/* ── Contract suites under test ──────────────────────────────────────────────
 *
 * test_framework.h keeps its pass/fail counters in file-`static` storage, so
 * the suites MUST share a single translation unit with this runner for the
 * TAP plan/summary to aggregate.  We therefore #include the suite .c bodies
 * directly (a unity build) rather than link them as separate objects.  Each
 * suite's "" includes resolve relative to its own directory (tests/contracts),
 * and test_framework.h / agentos.h are #pragma once / guarded.
 *
 * Scope: only PDs that actually speak seL4 IPC on their listen endpoint and
 * are present in a GUEST_OS=none test image — EventBus, serial_pd, log_drain.
 * Excluded for now (tracked in agentos-8f5 / agentos-0h4):
 *   - cc_pd: its protocol runs over virtio-serial, not a seL4 endpoint, so a
 *     microkit_ppcall() to it would block; needs a virtio-serial test driver.
 *   - guest lifecycle: no guest VMM PD exists under GUEST_OS=none; needs a
 *     guest-enabled test image.
 */
#include "../contracts/eventbus_test.c"
#include "../contracts/serial_pd_test.c"
#include "../contracts/log_drain_test.c"

/* ── Target performance probe (agentos-gz0.1) ──────────────────────────────
 *
 * Keep the benchmark in the same PD as the real-IPC contract suite.  This
 * guarantees the sample measures a genuine seL4 call into the live EventBus,
 * not the AGENTOS_TEST_HOST transport shim.  The serial record is deliberately
 * machine-readable so xtask can apply regression thresholds and archive it.
 */
#define TARGET_PERF_BATCHES      12u
#define TARGET_PERF_BATCH_CALLS   1024u
#define TARGET_PERF_WARMUP          64u
#define TARGET_PERF_METRIC "sel4_ipc_eventbus_status"

/*
 * seL4 intentionally does not expose CNTVCT_EL0 to ordinary AArch64 PDs.
 * Reading it here faults instead of measuring anything.  Emit batch boundary
 * records and let xtask timestamp their arrival with the host monotonic clock.
 * Each batch contains enough real seL4 calls to amortize serial/scheduling
 * noise, while repeated batches still produce useful percentile gates.
 */
static void target_emit_batch_marker(const char *kind, const char *metric,
                                     uint32_t calls, uint32_t errors)
{
    _tf_puts("PERF_BATCH_");
    _tf_puts(kind);
    _tf_puts(":");
    _tf_puts(metric);
    _tf_puts(":");
    _tf_put_uint(calls);
    if (kind[0] == 'E') {
        _tf_puts(":");
        _tf_put_uint(errors);
    }
    _tf_puts("\n");
}

static void target_benchmark_eventbus_ipc(void)
{
    uint32_t errors = 0u;

    for (uint32_t i = 0u; i < TARGET_PERF_WARMUP; i++) {
        microkit_mr_set(0, (uint64_t)MSG_EVENTBUS_STATUS);
        (void)microkit_ppcall((microkit_channel)MONITOR_CH_EVENTBUS,
                             microkit_msginfo_new(MSG_EVENTBUS_STATUS, 1));
    }
    _tf_puts("# perf: EventBus warmup complete\n");

    for (uint32_t batch = 0u; batch < TARGET_PERF_BATCHES; batch++) {
        uint32_t batch_errors = 0u;
        target_emit_batch_marker("BEGIN", TARGET_PERF_METRIC,
                                 TARGET_PERF_BATCH_CALLS, 0u);
        for (uint32_t i = 0u; i < TARGET_PERF_BATCH_CALLS; i++) {
            microkit_mr_set(0, (uint64_t)MSG_EVENTBUS_STATUS);
            (void)microkit_ppcall((microkit_channel)MONITOR_CH_EVENTBUS,
                                 microkit_msginfo_new(MSG_EVENTBUS_STATUS, 1));
            if (microkit_mr_get(0) != AOS_OK) batch_errors++;
        }
        target_emit_batch_marker("END", TARGET_PERF_METRIC,
                                 TARGET_PERF_BATCH_CALLS, batch_errors);
        errors += batch_errors;
    }
    _tf_puts("# perf: EventBus sample window complete\n");

    if (errors == 0u) {
        _tf_ok("target perf: real EventBus IPC batches completed");
    } else {
        _tf_fail_point("target perf: real EventBus IPC batches completed",
                       "one or more calls returned an error");
    }
}

/* ── ModelSvc real-IPC + shared-arena proof (agentos-gz0.2) ──────── */
#define TARGET_MODELSVC_CAP 130u
#define TARGET_AGENT_HARNESS_CAP 131u
#define AGENT_HARNESS_COLD_TURN_METRIC "agent_harness_native_turn_cold"
#define AGENT_HARNESS_WARM_TURN_METRIC "agent_harness_native_turn_warm"

static uint32_t tr_rd32(const uint8_t *p, uint32_t off)
{
    return (uint32_t)p[off] | ((uint32_t)p[off + 1u] << 8u)
         | ((uint32_t)p[off + 2u] << 16u) | ((uint32_t)p[off + 3u] << 24u);
}

static void tr_copy(void *dst_ptr, const void *src_ptr, uint32_t len)
{
    uint8_t *dst = (uint8_t *)dst_ptr;
    const uint8_t *src = (const uint8_t *)src_ptr;
    for (uint32_t i = 0u; i < len; i++) dst[i] = src[i];
}

static void tr_zero(volatile void *ptr, uint32_t len)
{
    volatile uint8_t *dst = (volatile uint8_t *)ptr;
    for (uint32_t i = 0u; i < len; i++) dst[i] = 0u;
}

static bool tr_equal(const char *a, const char *b, uint32_t len)
{
    for (uint32_t i = 0u; i < len; i++) if (a[i] != b[i]) return false;
    return true;
}

static void target_modelsvc_contract(void)
{
    volatile uint8_t *arena = (volatile uint8_t *)(uintptr_t)MODELSVC_SHMEM_VADDR;
    static const char model[] = "agentos-echo";
    static const char prompt[] = "hello";
    static const char expected[] = "agentos:hello";
    const uint32_t client_base = MODELSVC_CLIENT_ARENA_OFFSET(21u);
    const uint32_t model_off = client_base + 0x100u;
    const uint32_t prompt_off = client_base + 0x200u;
    const uint32_t response_off = client_base + 0x400u;
    for (uint32_t i = 0u; i < sizeof(model); i++) arena[model_off + i] = model[i];
    for (uint32_t i = 0u; i < sizeof(prompt); i++) arena[prompt_off + i] = prompt[i];

    static sel4_msg_t req, rep;
    tr_zero(&req, sizeof(req));
    tr_zero(&rep, sizeof(rep));
    req.opcode = MODELSVC_OP_HEALTH;
    sel4_call((seL4_CPtr)TARGET_MODELSVC_CAP, &req, &rep);
    if (rep.opcode == MODELSVC_ERR_OK && tr_rd32(rep.data, 4u) == 4u)
        _tf_ok("ModelSvc target health over real seL4 IPC");
    else
        _tf_fail_point("ModelSvc target health over real seL4 IPC",
                       "unexpected status/model registry count");

    static modelsvc_query_wire_t wire;
    tr_zero(&wire, sizeof(wire));
    wire.max_tokens = 64u;
    wire.user_prompt_offset = prompt_off;
    wire.user_prompt_len = sizeof(prompt) - 1u;
    wire.response_offset = response_off;
    wire.response_buf_len = 128u;
    wire.model_id_offset = model_off;
    wire.model_id_len = sizeof(model) - 1u;
    tr_zero(&req, sizeof(req));
    req.opcode = MODELSVC_OP_QUERY;
    req.length = sizeof(wire);
    tr_copy(req.data, &wire, sizeof(wire));
    sel4_call((seL4_CPtr)TARGET_MODELSVC_CAP, &req, &rep);
    if (rep.opcode == MODELSVC_ERR_OK
        && tr_rd32(rep.data, 4u) == sizeof(expected) - 1u
        && tr_equal((const char *)(uintptr_t)(MODELSVC_SHMEM_VADDR + response_off),
                    expected, sizeof(expected) - 1u))
        _tf_ok("ModelSvc target native query uses shared arena");
    else
        _tf_fail_point("ModelSvc target native query uses shared arena",
                       "query failed or response mismatch");

    sel4_call((seL4_CPtr)TARGET_MODELSVC_CAP, &req, &rep);
    if (rep.opcode == MODELSVC_ERR_OK && tr_rd32(rep.data, 24u) == 1u)
        _tf_ok("ModelSvc target repeated query hits result cache");
    else
        _tf_fail_point("ModelSvc target repeated query hits result cache",
                       "second query did not report a cache hit");

    req.opcode = MODELSVC_OP_STREAM_BEGIN;
    sel4_call((seL4_CPtr)TARGET_MODELSVC_CAP, &req, &rep);
    uint32_t request_id = tr_rd32(rep.data, 4u);
    static char streamed[sizeof(expected)];
    tr_zero(streamed, sizeof(streamed));
    uint32_t cursor = 0u, state = 0u;
    for (uint32_t polls = 0u; polls < 8u && request_id != 0u; polls++) {
        modelsvc_stream_poll_wire_t poll;
        poll.request_id = request_id;
        poll.max_bytes = 4u;
        tr_zero(&req, sizeof(req));
        req.opcode = MODELSVC_OP_STREAM_POLL;
        req.length = sizeof(poll);
        tr_copy(req.data, &poll, sizeof(poll));
        sel4_call((seL4_CPtr)TARGET_MODELSVC_CAP, &req, &rep);
        uint32_t chunk = tr_rd32(rep.data, 8u);
        state = tr_rd32(rep.data, 4u);
        if (rep.opcode != MODELSVC_ERR_OK || cursor + chunk >= sizeof(streamed)) break;
        tr_copy(streamed + cursor,
                (const void *)(uintptr_t)(MODELSVC_SHMEM_VADDR + response_off),
                chunk);
        cursor += chunk;
        if (state == MODELSVC_STREAM_COMPLETE) break;
    }
    if (state == MODELSVC_STREAM_COMPLETE && cursor == sizeof(expected) - 1u
        && tr_equal(streamed, expected, sizeof(expected) - 1u))
        _tf_ok("ModelSvc target streams bounded response chunks");
    else
        _tf_fail_point("ModelSvc target streams bounded response chunks",
                       "stream did not complete with expected chunks");
}

static void target_agent_harness_contract(void)
{
    volatile uint8_t *arena = (volatile uint8_t *)(uintptr_t)HARNESS_SHMEM_VADDR;
    static const char model[] = "agentos-echo";
    static const char prompt[] =
        "{\"action\":\"final\",\"summary\":\"native-smoke\"}";
    static const char expected[] = "native-smoke";
    const uint32_t prompt_off = 0x1000u;
    const uint32_t model_off = 0x2000u;
    const uint32_t result_off = 0x4000u;
    for (uint32_t i = 0u; i < sizeof(prompt); i++) arena[prompt_off + i] = prompt[i];
    for (uint32_t i = 0u; i < sizeof(model); i++) arena[model_off + i] = model[i];
    for (uint32_t i = 0u; i < 256u; i++) arena[result_off + i] = 0u;

    sel4_msg_t req, rep;
    tr_zero(&req, sizeof(req));
    tr_zero(&rep, sizeof(rep));
    req.opcode = MSG_HARNESS_RESOURCES;
    sel4_call((seL4_CPtr)TARGET_AGENT_HARNESS_CAP, &req, &rep);
    _tf_puts("AGENT_RESOURCE_JSON:{\"schema\":1,\"worker\":\"codex_harness\","
             "\"private_committed_bytes\":");
    _tf_put_uint(tr_rd32(rep.data, 4u));
    _tf_puts(",\"private_limit_bytes\":");
    _tf_put_uint(tr_rd32(rep.data, 8u));
    _tf_puts(",\"shared_mapped_bytes\":");
    _tf_put_uint(tr_rd32(rep.data, 12u));
    _tf_puts(",\"target_low_bytes\":");
    _tf_put_uint(tr_rd32(rep.data, 16u));
    _tf_puts(",\"target_high_bytes\":");
    _tf_put_uint(tr_rd32(rep.data, 20u));
    _tf_puts(",\"shared_components\":");
    _tf_put_uint(tr_rd32(rep.data, 24u));
    _tf_puts("}\n");
    if (rep.opcode == HARNESS_OK
        && tr_rd32(rep.data, 4u) > 0u
        && tr_rd32(rep.data, 4u) <= HARNESS_WORKER_MAX_BYTES
        && tr_rd32(rep.data, 8u) == HARNESS_WORKER_DEFAULT_LIMIT_BYTES
        && tr_rd32(rep.data, 12u) == HARNESS_SHMEM_SIZE)
        _tf_ok("AgentHarness reports private and shared memory separately");
    else
        _tf_fail_point("AgentHarness reports private and shared memory separately",
                       "resource accounting was missing or exceeded budget");

    struct harness_req_submit submit;
    tr_zero(&submit, sizeof(submit));
    submit.task_id = 1u;
    submit.harness_kind = HARNESS_KIND_CODEX;
    submit.required_caps = HARNESS_CAP_MODEL;
    submit.max_steps = 4u;
    submit.authority_epoch = 1u;
    submit.prompt_offset = prompt_off;
    submit.prompt_len = sizeof(prompt) - 1u;
    submit.result_offset = result_off;
    submit.result_capacity = 256u;
    submit.model_id_offset = model_off;
    submit.model_id_len = sizeof(model) - 1u;
    tr_zero(&req, sizeof(req));
    req.opcode = MSG_HARNESS_SUBMIT;
    req.length = sizeof(submit);
    tr_copy(req.data, &submit, sizeof(submit));
    target_emit_batch_marker("BEGIN", AGENT_HARNESS_COLD_TURN_METRIC, 1u, 0u);
    sel4_call((seL4_CPtr)TARGET_AGENT_HARNESS_CAP, &req, &rep);
    bool submit_ok = rep.opcode == HARNESS_OK
        && tr_rd32(rep.data, 8u) == HARNESS_CAP_MODEL
        && tr_rd32(rep.data, 12u) == HARNESS_STATE_COMPLETE
        && tr_equal((const char *)(uintptr_t)(HARNESS_SHMEM_VADDR + result_off),
                    expected, sizeof(expected) - 1u);
    target_emit_batch_marker("END", AGENT_HARNESS_COLD_TURN_METRIC, 1u,
                             submit_ok ? 0u : 1u);
    if (submit_ok)
        _tf_ok("AgentHarness completes a native ModelSvc planner action");
    else
        _tf_fail_point("AgentHarness completes a native ModelSvc planner action",
                       "submit failed, authority broadened, or result mismatched");

    struct harness_req_task result_req = {.task_id = 1u};
    tr_zero(&req, sizeof(req));
    req.opcode = MSG_HARNESS_RESULT;
    req.length = sizeof(result_req);
    tr_copy(req.data, &result_req, sizeof(result_req));
    sel4_call((seL4_CPtr)TARGET_AGENT_HARNESS_CAP, &req, &rep);
    if (rep.opcode == HARNESS_OK
        && tr_rd32(rep.data, 8u) == HARNESS_STATE_COMPLETE
        && tr_rd32(rep.data, 16u) == 1u
        && tr_rd32(rep.data, 44u) == HARNESS_CAP_MODEL)
        _tf_ok("AgentHarness exports task and capability metrics");
    else
        _tf_fail_point("AgentHarness exports task and capability metrics",
                       "result metrics were incomplete");
}

static void target_benchmark_agent_harness(void)
{
    volatile uint8_t *arena = (volatile uint8_t *)(uintptr_t)HARNESS_SHMEM_VADDR;
    static const char model[] = "agentos-echo";
    static const char prompt[] =
        "{\"action\":\"final\",\"summary\":\"native-warm\"}";
    const uint32_t prompt_off = 0x1000u;
    const uint32_t model_off = 0x2000u;
    const uint32_t result_off = 0x4000u;
    for (uint32_t i = 0u; i < sizeof(prompt); i++) arena[prompt_off + i] = prompt[i];
    for (uint32_t i = 0u; i < sizeof(model); i++) arena[model_off + i] = model[i];

    uint32_t errors = 0u;
    for (uint32_t batch = 0u; batch < TARGET_PERF_BATCHES; batch++) {
        struct harness_req_submit submit;
        tr_zero(&submit, sizeof(submit));
        submit.task_id = 100u + batch;
        submit.harness_kind = HARNESS_KIND_CODEX;
        submit.required_caps = HARNESS_CAP_MODEL;
        submit.max_steps = 4u;
        submit.authority_epoch = 1u;
        submit.prompt_offset = prompt_off;
        submit.prompt_len = sizeof(prompt) - 1u;
        submit.result_offset = result_off;
        submit.result_capacity = 256u;
        submit.model_id_offset = model_off;
        submit.model_id_len = sizeof(model) - 1u;

        sel4_msg_t req, rep;
        tr_zero(&req, sizeof(req));
        tr_zero(&rep, sizeof(rep));
        req.opcode = MSG_HARNESS_SUBMIT;
        req.length = sizeof(submit);
        tr_copy(req.data, &submit, sizeof(submit));
        target_emit_batch_marker("BEGIN", AGENT_HARNESS_WARM_TURN_METRIC,
                                 1u, 0u);
        sel4_call((seL4_CPtr)TARGET_AGENT_HARNESS_CAP, &req, &rep);
        uint32_t batch_errors = rep.opcode == HARNESS_OK
            && tr_rd32(rep.data, 12u) == HARNESS_STATE_COMPLETE ? 0u : 1u;
        target_emit_batch_marker("END", AGENT_HARNESS_WARM_TURN_METRIC,
                                 1u, batch_errors);
        errors += batch_errors;
    }
    if (errors == 0u)
        _tf_ok("target perf: native AgentHarness warm turns completed");
    else
        _tf_fail_point("target perf: native AgentHarness warm turns completed",
                       "one or more harness turns failed");
}

#define MODELSVC_PERF_METRIC "modelsvc_cached_query"
#define MODELSVC_PERF_CALLS 256u

static void target_benchmark_modelsvc_cache(void)
{
    volatile uint8_t *arena = (volatile uint8_t *)(uintptr_t)MODELSVC_SHMEM_VADDR;
    static const char model[] = "agentos-echo";
    static const char prompt[] = "benchmark-cache";
    const uint32_t client_base = MODELSVC_CLIENT_ARENA_OFFSET(21u);
    const uint32_t model_off = client_base + 0x100u;
    const uint32_t prompt_off = client_base + 0x200u;
    const uint32_t response_off = client_base + 0x400u;
    for (uint32_t i = 0u; i < sizeof(model); i++) arena[model_off + i] = model[i];
    for (uint32_t i = 0u; i < sizeof(prompt); i++) arena[prompt_off + i] = prompt[i];

    modelsvc_query_wire_t wire;
    tr_zero(&wire, sizeof(wire));
    wire.max_tokens = 64u;
    wire.user_prompt_offset = prompt_off;
    wire.user_prompt_len = sizeof(prompt) - 1u;
    wire.response_offset = response_off;
    wire.response_buf_len = 128u;
    wire.model_id_offset = model_off;
    wire.model_id_len = sizeof(model) - 1u;
    sel4_msg_t req, rep;
    tr_zero(&req, sizeof(req));
    req.opcode = MODELSVC_OP_QUERY;
    req.length = sizeof(wire);
    tr_copy(req.data, &wire, sizeof(wire));
    /* Prime the exact-result cache outside the measured sample window. */
    sel4_call((seL4_CPtr)TARGET_MODELSVC_CAP, &req, &rep);

    uint32_t errors = 0u;
    for (uint32_t batch = 0u; batch < TARGET_PERF_BATCHES; batch++) {
        uint32_t batch_errors = 0u;
        target_emit_batch_marker("BEGIN", MODELSVC_PERF_METRIC,
                                 MODELSVC_PERF_CALLS, 0u);
        for (uint32_t i = 0u; i < MODELSVC_PERF_CALLS; i++) {
            sel4_call((seL4_CPtr)TARGET_MODELSVC_CAP, &req, &rep);
            if (rep.opcode != MODELSVC_ERR_OK || tr_rd32(rep.data, 24u) != 1u)
                batch_errors++;
        }
        target_emit_batch_marker("END", MODELSVC_PERF_METRIC,
                                 MODELSVC_PERF_CALLS, batch_errors);
        errors += batch_errors;
    }
    if (errors == 0u)
        _tf_ok("target perf: ModelSvc cached query batches completed");
    else
        _tf_fail_point("target perf: ModelSvc cached query batches completed",
                       "one or more cached queries failed");
}

/* ── libmicrokit symbol shim (agentos-8f5) ───────────────────────────────────
 *
 * agentOS PDs do not link libmicrokit, and the release kernel disables
 * CONFIG_PRINTING (seL4_DebugPutChar is a no-op).  Two consequences:
 *  1. microkit.h's inline helpers reference a handful of libmicrokit externs
 *     (microkit_dbg_puts/_put32, microkit_name, microkit_pps) — we define them.
 *  2. test_framework emits via microkit_dbg_puts; route it to the PL011 UART0
 *     that the root task maps into this PD at TEST_RUNNER_UART_VA (see main.c),
 *     mirroring cc_pd's direct-UART debug path.
 *
 * microkit_pps is the bitmask of valid protected-procedure channels; if a
 * channel's bit is clear, microkit_ppcall() takes its invalid-channel branch
 * and never issues the seL4_Call.  We set all bits so every ppcall goes out.
 */
#define TEST_RUNNER_UART_VA 0x10006000UL          /* MUST match main.c mapping */
#define TR_UART_DR (*(volatile uint32_t *)(TEST_RUNNER_UART_VA + 0x000u))

char      microkit_name[MICROKIT_PD_NAME_LENGTH] = "test_runner";
seL4_Word microkit_pps = ~(seL4_Word)0;           /* all channels valid */

void microkit_dbg_putc(int c) { TR_UART_DR = (uint32_t)(unsigned char)c; }
void microkit_dbg_puts(const char *s) { for (; *s; s++) microkit_dbg_putc(*s); }
void microkit_dbg_put32(seL4_Uint32 x)
{
    char buf[11];
    int  i = 10;
    buf[i] = '\0';
    if (x == 0u) { microkit_dbg_putc('0'); return; }
    while (x > 0u && i > 0) { buf[--i] = (char)('0' + (x % 10u)); x /= 10u; }
    microkit_dbg_puts(&buf[i]);
}

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

    /* Prove the native agent path first.  A failure in an unrelated legacy
     * contract must not hide whether the booted image can run an agent turn. */
    target_agent_harness_contract();
    target_benchmark_agent_harness();
    run_eventbus_tests((microkit_channel)MONITOR_CH_EVENTBUS);
    run_serial_pd_tests((microkit_channel)CH_SERIAL_PD);
    run_log_drain_tests((microkit_channel)CH_LOG_DRAIN);
    target_modelsvc_contract();
    _tf_puts("# skip: cc_pd (virtio-serial protocol) + guest (no VMM under GUEST_OS=none)\n");

    target_benchmark_eventbus_ipc();
    target_benchmark_modelsvc_cache();

    tf_tap_finish();
    target_tap_done();
}

/* ── PD entry point ──────────────────────────────────────────────────────────
 *
 * pd_entry.c calls pd_main(my_ep, ns_ep).  The runner is a pure client: it
 * issues PPCs to the service PDs and needs neither its own server endpoint nor
 * the nameserver.  After emitting TAP_DONE (which the run-tests harness waits
 * on, then tears down QEMU) it parks.
 */
void pd_main(seL4_CPtr my_ep, seL4_CPtr ns_ep)
{
    (void)my_ep;
    (void)ns_ep;
    target_contract_runner_main();
    for (;;) {
        seL4_Yield();
    }
}
