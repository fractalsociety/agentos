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
#include "../../contracts/execsvc/interface.h"
#include "../../contracts/toolsvc/interface.h"
#include "../../kernel/agentos-root-task/include/contracts/agent_harness_contract.h"
#include "../../kernel/agentos-root-task/include/contracts/agentfs_contract.h"
#include "../../kernel/agentos-root-task/include/contracts/cap_broker_contract.h"
#include "../../kernel/agentos-root-task/include/cap_authority.h"

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
#define TARGET_TOOLSVC_CAP 132u
#define TARGET_AGENTFS_CAP 133u
#define TARGET_CONTROLLER_CAP 134u
#define TARGET_EXECSVC_CAP 200u
#define TARGET_COMPILE_ONLY_EXECSVC_CAP 201u
#define TARGET_TEST_RUNNER_CLIENT_ID 23u
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

static bool tr_contains(const char *haystack, uint32_t haystack_len,
                        const char *needle, uint32_t needle_len)
{
    if (needle_len == 0u) return true;
    if (haystack_len < needle_len) return false;
    for (uint32_t i = 0u; i <= haystack_len - needle_len; i++)
        if (tr_equal(haystack + i, needle, needle_len)) return true;
    return false;
}

static void target_modelsvc_contract(void)
{
    volatile uint8_t *arena = (volatile uint8_t *)(uintptr_t)MODELSVC_SHMEM_VADDR;
    static const char model[] = "agentos-echo";
    static const char prompt[] = "hello";
    static const char expected[] = "agentos:hello";
    const uint32_t client_base = MODELSVC_CLIENT_ARENA_OFFSET(
        TARGET_TEST_RUNNER_CLIENT_ID);
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
    if (rep.opcode == MODELSVC_ERR_OK && tr_rd32(rep.data, 4u) == 6u)
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
        && tr_rd32(rep.data, 12u) == HARNESS_SHMEM_SIZE
            + TOOLSVC_CLIENT_ARENA_SIZE + AGENTFS_CLIENT_ARENA_SIZE
            + EXECSVC_CLIENT_ARENA_SIZE
        && tr_rd32(rep.data, 24u)
            == (HARNESS_SHARED_MODELSVC | HARNESS_SHARED_TOOL_MCP
                | HARNESS_SHARED_REPO_INDEX
                | HARNESS_SHARED_ARTIFACT_STORE
                | HARNESS_SHARED_EXEC_GRAPH))
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
        && tr_rd32(rep.data, 8u) == CAPBROKER_HARNESS_INITIAL_CAPS
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

static void target_toolsvc_contract(void)
{
    volatile uint8_t *arena = (volatile uint8_t *)(uintptr_t)TOOLSVC_SHMEM_VADDR;
    const uint32_t client_base = TOOLSVC_CLIENT_ARENA_OFFSET(
        TARGET_TEST_RUNNER_CLIENT_ID);
    const uint32_t name_off = client_base + 0x100u;
    const uint32_t input_off = client_base + 0x400u;
    const uint32_t output_off = client_base + 0x1000u;
    static const char name[] = "agent.echo";
    static const char input[] = "target-tool-ok";
    for (uint32_t i = 0u; i < sizeof(name); i++) arena[name_off + i] = name[i];
    for (uint32_t i = 0u; i < sizeof(input); i++) arena[input_off + i] = input[i];

    sel4_msg_t req, rep;
    tr_zero(&req, sizeof(req));
    req.opcode = TOOLSVC_OP_HEALTH;
    sel4_call((seL4_CPtr)TARGET_TOOLSVC_CAP, &req, &rep);
    if (rep.opcode == TOOLSVC_ERR_OK
        && tr_rd32(rep.data, 4u) == 4u
        && tr_rd32(rep.data, 8u) == TOOLSVC_INTERFACE_VERSION)
        _tf_ok("ToolSvc target health over distinct ToolCap");
    else
        _tf_fail_point("ToolSvc target health over distinct ToolCap",
                       "health reply was invalid");

    toolsvc_invoke_wire_t invoke;
    tr_zero(&invoke, sizeof(invoke));
    invoke.name_offset = name_off;
    invoke.name_len = sizeof(name) - 1u;
    invoke.input_offset = input_off;
    invoke.input_len = sizeof(input) - 1u;
    invoke.output_offset = output_off;
    invoke.output_buf_len = 128u;
    tr_zero(&req, sizeof(req));
    req.opcode = TOOLSVC_OP_INVOKE;
    req.length = sizeof(invoke);
    tr_copy(req.data, &invoke, sizeof(invoke));
    sel4_call((seL4_CPtr)TARGET_TOOLSVC_CAP, &req, &rep);
    if (rep.opcode == TOOLSVC_ERR_OK
        && tr_rd32(rep.data, 4u) == sizeof(input) - 1u
        && tr_equal((const char *)(uintptr_t)(TOOLSVC_SHMEM_VADDR + output_off),
                    input, sizeof(input) - 1u))
        _tf_ok("ToolSvc invokes shared singleton tool");
    else
        _tf_fail_point("ToolSvc invokes shared singleton tool",
                       "invoke failed or output mismatched");

    invoke.output_offset = TOOLSVC_CLIENT_ARENA_OFFSET(
        TARGET_TEST_RUNNER_CLIENT_ID - 1u);
    tr_copy(req.data, &invoke, sizeof(invoke));
    sel4_call((seL4_CPtr)TARGET_TOOLSVC_CAP, &req, &rep);
    if (rep.opcode == TOOLSVC_ERR_DENIED)
        _tf_ok("ToolSvc denies cross-worker arena offsets");
    else
        _tf_fail_point("ToolSvc denies cross-worker arena offsets",
                       "cross-partition output was accepted");

    static const char discover_name[] = TOOLSVC_MCP_DISCOVER_NAME;
    for (uint32_t i = 0u; i < sizeof(discover_name); i++)
        arena[name_off + i] = discover_name[i];
    invoke.name_len = sizeof(discover_name) - 1u;
    invoke.input_len = 0u;
    invoke.output_offset = output_off;
    invoke.output_buf_len = 4096u;
    tr_copy(req.data, &invoke, sizeof(invoke));
    sel4_call((seL4_CPtr)TARGET_TOOLSVC_CAP, &req, &rep);
    if (rep.opcode == TOOLSVC_ERR_OK
        && tr_contains((const char *)(uintptr_t)
                           (TOOLSVC_SHMEM_VADDR + output_off),
                       tr_rd32(rep.data, 4u), "mcp.fixture_echo", 16u))
        _tf_ok("ToolSvc discovers a real external MCP provider");
    else
        _tf_fail_point("ToolSvc discovers a real external MCP provider",
                       "MCP tools/list failed or omitted fixture tool");

    static const char external_name[] = "mcp.fixture_echo";
    static const char external_input[] = "{\"message\":\"target-mcp-ok\"}";
    for (uint32_t i = 0u; i < sizeof(external_name); i++)
        arena[name_off + i] = external_name[i];
    for (uint32_t i = 0u; i < sizeof(external_input); i++)
        arena[input_off + i] = external_input[i];
    invoke.name_len = sizeof(external_name) - 1u;
    invoke.input_len = sizeof(external_input) - 1u;
    tr_copy(req.data, &invoke, sizeof(invoke));
    sel4_call((seL4_CPtr)TARGET_TOOLSVC_CAP, &req, &rep);
    if (rep.opcode == TOOLSVC_ERR_OK
        && tr_contains((const char *)(uintptr_t)
                           (TOOLSVC_SHMEM_VADDR + output_off),
                       tr_rd32(rep.data, 4u), "target-mcp-ok", 13u))
        _tf_ok("ToolSvc invokes a real external MCP tool");
    else
        _tf_fail_point("ToolSvc invokes a real external MCP tool",
                       "MCP tools/call failed or result mismatched");
}

static void target_agent_harness_tool_loop(void)
{
    volatile uint8_t *arena = (volatile uint8_t *)(uintptr_t)HARNESS_SHMEM_VADDR;
    static const char model[] = "agentos-echo";
    static const char prompt[] =
        "{\"action\":\"tool\",\"tool\":\"agent.echo\","
        "\"input\":\"{\\\"action\\\":\\\"final\\\","
        "\\\"summary\\\":\\\"native-tool-loop\\\"}\"}";
    static const char expected[] = "native-tool-loop";
    const uint32_t prompt_off = 0x1000u;
    const uint32_t model_off = 0x2000u;
    const uint32_t result_off = 0x4000u;
    for (uint32_t i = 0u; i < sizeof(prompt); i++) arena[prompt_off + i] = prompt[i];
    for (uint32_t i = 0u; i < sizeof(model); i++) arena[model_off + i] = model[i];

    struct harness_req_submit submit;
    tr_zero(&submit, sizeof(submit));
    submit.task_id = 2u;
    submit.harness_kind = HARNESS_KIND_CODEX;
    submit.required_caps = HARNESS_CAP_MODEL | HARNESS_CAP_TOOL;
    submit.max_steps = 4u;
    submit.authority_epoch = 2u;
    submit.prompt_offset = prompt_off;
    submit.prompt_len = sizeof(prompt) - 1u;
    submit.result_offset = result_off;
    submit.result_capacity = 256u;
    submit.model_id_offset = model_off;
    submit.model_id_len = sizeof(model) - 1u;
    sel4_msg_t req, rep;
    tr_zero(&req, sizeof(req));
    req.opcode = MSG_HARNESS_SUBMIT;
    req.length = sizeof(submit);
    tr_copy(req.data, &submit, sizeof(submit));
    sel4_call((seL4_CPtr)TARGET_AGENT_HARNESS_CAP, &req, &rep);
    if (rep.opcode == HARNESS_OK
        && tr_rd32(rep.data, 12u) == HARNESS_STATE_COMPLETE
        && tr_equal((const char *)(uintptr_t)(HARNESS_SHMEM_VADDR + result_off),
                    expected, sizeof(expected) - 1u))
        _tf_ok("AgentHarness completes ModelSvc-ToolSvc-ModelSvc loop");
    else
        _tf_fail_point("AgentHarness completes ModelSvc-ToolSvc-ModelSvc loop",
                       "tool loop did not complete");

    struct harness_req_task result_req = {.task_id = 2u};
    tr_zero(&req, sizeof(req));
    req.opcode = MSG_HARNESS_RESULT;
    req.length = sizeof(result_req);
    tr_copy(req.data, &result_req, sizeof(result_req));
    sel4_call((seL4_CPtr)TARGET_AGENT_HARNESS_CAP, &req, &rep);
    if (rep.opcode == HARNESS_OK
        && tr_rd32(rep.data, 16u) == 2u
        && tr_rd32(rep.data, 20u) == 1u
        && tr_rd32(rep.data, 44u) == (HARNESS_CAP_MODEL | HARNESS_CAP_TOOL))
        _tf_ok("AgentHarness accounts distinct model and tool capabilities");
    else
        _tf_fail_point("AgentHarness accounts distinct model and tool capabilities",
                       "tool-loop metrics were incomplete");
}

static void target_cap_broker_tool_lifecycle(void)
{
    sel4_msg_t req, rep;
    struct cap_broker_req_grant grant = {
        .target_pd = CAPBROKER_HARNESS_PD_ID,
        .cap_class = HARNESS_CAP_TOOL,
        .rights = TOOLSVC_RIGHT_ALL,
        .ttl_ticks = 0u,
    };
    tr_zero(&req, sizeof(req));
    req.opcode = MSG_CAP_GRANT;
    req.length = sizeof(grant);
    tr_copy(req.data, &grant, sizeof(grant));
    sel4_call((seL4_CPtr)TARGET_CONTROLLER_CAP, &req, &rep);
    if (rep.opcode == CAP_BROKER_OK
        && tr_rd32(rep.data, 4u) == (CAPBROKER_HARNESS_INITIAL_CAPS
                                     | HARNESS_CAP_TOOL)
        && tr_rd32(rep.data, 8u) == 2u
        && tr_rd32(rep.data, 12u) == 1u)
        _tf_ok("CapBroker mints a real ToolCap and advances harness authority");
    else
        _tf_fail_point("CapBroker mints a real ToolCap and advances harness authority",
                       "kernel mint or harness epoch synchronization failed");
}

static void target_cap_broker_revoke_and_regrant_tool(void)
{
    sel4_msg_t req, rep;
    struct cap_broker_req_revoke revoke = {
        .target_pd = CAPBROKER_HARNESS_PD_ID,
        .cap_class = HARNESS_CAP_TOOL,
    };
    tr_zero(&req, sizeof(req));
    req.opcode = MSG_CAP_REVOKE_GRANT;
    req.length = sizeof(revoke);
    tr_copy(req.data, &revoke, sizeof(revoke));
    sel4_call((seL4_CPtr)TARGET_CONTROLLER_CAP, &req, &rep);
    bool revoked = rep.opcode == CAP_BROKER_OK
        && tr_rd32(rep.data, 4u) == CAPBROKER_HARNESS_INITIAL_CAPS
        && tr_rd32(rep.data, 8u) == 3u
        && tr_rd32(rep.data, 12u) == 1u;

    volatile uint8_t *arena = (volatile uint8_t *)(uintptr_t)HARNESS_SHMEM_VADDR;
    static const char model[] = "agentos-echo";
    static const char prompt[] = "{\"action\":\"final\",\"summary\":\"must-deny\"}";
    const uint32_t prompt_off = 0x1000u, model_off = 0x2000u;
    const uint32_t result_off = 0x4000u;
    for (uint32_t i = 0u; i < sizeof(prompt); i++) arena[prompt_off + i] = prompt[i];
    for (uint32_t i = 0u; i < sizeof(model); i++) arena[model_off + i] = model[i];
    struct harness_req_submit submit;
    tr_zero(&submit, sizeof(submit));
    submit.task_id = 90u;
    submit.harness_kind = HARNESS_KIND_CODEX;
    submit.required_caps = HARNESS_CAP_MODEL | HARNESS_CAP_TOOL;
    submit.max_steps = 2u;
    submit.authority_epoch = 3u;
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
    sel4_call((seL4_CPtr)TARGET_AGENT_HARNESS_CAP, &req, &rep);
    if (revoked && rep.opcode == HARNESS_ERR_CAP_DENIED
        && tr_rd32(rep.data, 8u) == CAPBROKER_HARNESS_INITIAL_CAPS)
        _tf_ok("CapBroker deletes ToolCap before the harness denies a new task");
    else
        _tf_fail_point("CapBroker deletes ToolCap before the harness denies a new task",
                       "delete, epoch sync, or capability preflight did not fail closed");

    struct cap_broker_req_grant grant = {
        .target_pd = CAPBROKER_HARNESS_PD_ID,
        .cap_class = HARNESS_CAP_TOOL,
        .rights = TOOLSVC_RIGHT_ALL,
        .ttl_ticks = 0u,
    };
    tr_zero(&req, sizeof(req));
    req.opcode = MSG_CAP_GRANT;
    req.length = sizeof(grant);
    tr_copy(req.data, &grant, sizeof(grant));
    sel4_call((seL4_CPtr)TARGET_CONTROLLER_CAP, &req, &rep);
    if (rep.opcode == CAP_BROKER_OK
        && tr_rd32(rep.data, 8u) == 4u
        && tr_rd32(rep.data, 12u) == 1u)
        _tf_ok("CapBroker re-mints ToolCap for the next harness epoch");
    else
        _tf_fail_point("CapBroker re-mints ToolCap for the next harness epoch",
                       "re-grant did not restore kernel authority");
}

static void target_agent_harness_external_mcp_loop(void)
{
    volatile uint8_t *arena = (volatile uint8_t *)(uintptr_t)HARNESS_SHMEM_VADDR;
    static const char model[] = "agentos-mcp-coder";
    static const char prompt[] = "external-mcp-smoke";
    static const char expected[] = "external-mcp-verified";
    const uint32_t prompt_off = 0x1000u;
    const uint32_t model_off = 0x2000u;
    const uint32_t result_off = 0x4000u;
    for (uint32_t i = 0u; i < sizeof(prompt); i++) arena[prompt_off + i] = prompt[i];
    for (uint32_t i = 0u; i < sizeof(model); i++) arena[model_off + i] = model[i];

    struct harness_req_submit submit;
    tr_zero(&submit, sizeof(submit));
    submit.task_id = 6u;
    submit.harness_kind = HARNESS_KIND_CODEX;
    submit.required_caps = HARNESS_CAP_MODEL | HARNESS_CAP_TOOL;
    submit.max_steps = 4u;
    submit.authority_epoch = 4u;
    submit.prompt_offset = prompt_off;
    submit.prompt_len = sizeof(prompt) - 1u;
    submit.result_offset = result_off;
    submit.result_capacity = 256u;
    submit.model_id_offset = model_off;
    submit.model_id_len = sizeof(model) - 1u;
    sel4_msg_t req, rep;
    tr_zero(&req, sizeof(req));
    req.opcode = MSG_HARNESS_SUBMIT;
    req.length = sizeof(submit);
    tr_copy(req.data, &submit, sizeof(submit));
    sel4_call((seL4_CPtr)TARGET_AGENT_HARNESS_CAP, &req, &rep);
    if (rep.opcode == HARNESS_OK
        && tr_rd32(rep.data, 12u) == HARNESS_STATE_COMPLETE
        && tr_equal((const char *)(uintptr_t)(HARNESS_SHMEM_VADDR + result_off),
                    expected, sizeof(expected) - 1u))
        _tf_ok("AgentHarness completes a real external MCP tool loop");
    else
        _tf_fail_point("AgentHarness completes a real external MCP tool loop",
                       "model, ToolCap, MCP transport, or continuation failed");
}

static void target_agent_harness_memory_loop(void)
{
    volatile uint8_t *arena = (volatile uint8_t *)(uintptr_t)HARNESS_SHMEM_VADDR;
    static const char model[] = "agentos-smoke-coder";
    static const char prompt[] = "edit-and-readback-smoke";
    static const char expected[] = "edit-readback-verified";
    const uint32_t prompt_off = 0x1000u;
    const uint32_t model_off = 0x2000u;
    const uint32_t result_off = 0x4000u;
    for (uint32_t i = 0u; i < sizeof(prompt); i++) arena[prompt_off + i] = prompt[i];
    for (uint32_t i = 0u; i < sizeof(model); i++) arena[model_off + i] = model[i];

    struct harness_req_submit submit;
    tr_zero(&submit, sizeof(submit));
    submit.task_id = 3u;
    submit.harness_kind = HARNESS_KIND_CODEX;
    submit.required_caps = HARNESS_CAP_MODEL | HARNESS_CAP_MEMORY
        | HARNESS_CAP_EXEC;
    submit.task_flags = HARNESS_TASK_REQUIRE_TEST;
    submit.max_steps = 5u;
    submit.authority_epoch = 4u;
    submit.prompt_offset = prompt_off;
    submit.prompt_len = sizeof(prompt) - 1u;
    submit.result_offset = result_off;
    submit.result_capacity = 256u;
    submit.model_id_offset = model_off;
    submit.model_id_len = sizeof(model) - 1u;
    sel4_msg_t req, rep;
    tr_zero(&req, sizeof(req));
    req.opcode = MSG_HARNESS_SUBMIT;
    req.length = sizeof(submit);
    tr_copy(req.data, &submit, sizeof(submit));
    sel4_call((seL4_CPtr)TARGET_AGENT_HARNESS_CAP, &req, &rep);
    if (rep.opcode == HARNESS_OK
        && tr_rd32(rep.data, 12u) == HARNESS_STATE_COMPLETE
        && tr_equal((const char *)(uintptr_t)(HARNESS_SHMEM_VADDR + result_off),
                    expected, sizeof(expected) - 1u))
        _tf_ok("AgentHarness edits AgentFS and verifies through ExecCap");
    else
        _tf_fail_point("AgentHarness edits AgentFS and verifies through ExecCap",
                       "model-memory-exec-model loop did not complete");

    struct harness_req_task result_req = {.task_id = 3u};
    tr_zero(&req, sizeof(req));
    req.opcode = MSG_HARNESS_RESULT;
    req.length = sizeof(result_req);
    tr_copy(req.data, &result_req, sizeof(result_req));
    sel4_call((seL4_CPtr)TARGET_AGENT_HARNESS_CAP, &req, &rep);
    if (rep.opcode == HARNESS_OK
        && tr_rd32(rep.data, 16u) == 3u
        && tr_rd32(rep.data, 24u) == 2u
        && tr_rd32(rep.data, 28u) == 1u
        && (int32_t)tr_rd32(rep.data, 40u) == 0
        && tr_rd32(rep.data, 44u) == (HARNESS_CAP_MODEL | HARNESS_CAP_MEMORY
                                     | HARNESS_CAP_EXEC))
        _tf_ok("AgentHarness accounts isolated model, memory, and exec caps");
    else
        _tf_fail_point("AgentHarness accounts isolated model, memory, and exec caps",
                       "verified edit-loop metrics were incomplete");
}

#ifdef AGENTOS_LIVE_MODEL_TEST
static void target_agent_harness_live_model(void)
{
    volatile uint8_t *arena = (volatile uint8_t *)(uintptr_t)HARNESS_SHMEM_VADDR;
    static const char model[] = "fast";
    static const char prompt[] =
        "Create src/live.c containing one valid C11 function named agentos_answer "
        "that takes no arguments and returns 42. Use memory_write, then test that "
        "path with the c11_compile profile, then return final only after the real "
        "compiler reports success.";
    const uint32_t prompt_off = 0x1000u;
    const uint32_t model_off = 0x2000u;
    const uint32_t result_off = 0x4000u;
    for (uint32_t i = 0u; i < sizeof(prompt); i++) arena[prompt_off + i] = prompt[i];
    for (uint32_t i = 0u; i < sizeof(model); i++) arena[model_off + i] = model[i];

    struct harness_req_submit submit;
    tr_zero(&submit, sizeof(submit));
    submit.task_id = 4u;
    submit.harness_kind = HARNESS_KIND_CODEX;
    submit.required_caps = HARNESS_CAP_MODEL | HARNESS_CAP_MEMORY
        | HARNESS_CAP_EXEC;
    submit.task_flags = HARNESS_TASK_REQUIRE_TEST;
    submit.max_steps = 8u;
    submit.authority_epoch = 4u;
    submit.prompt_offset = prompt_off;
    submit.prompt_len = sizeof(prompt) - 1u;
    submit.result_offset = result_off;
    submit.result_capacity = 2048u;
    submit.model_id_offset = model_off;
    submit.model_id_len = sizeof(model) - 1u;
    sel4_msg_t req, rep;
    tr_zero(&req, sizeof(req));
    req.opcode = MSG_HARNESS_SUBMIT;
    req.length = sizeof(submit);
    tr_copy(req.data, &submit, sizeof(submit));
    sel4_call((seL4_CPtr)TARGET_AGENT_HARNESS_CAP, &req, &rep);
    bool completed = rep.opcode == HARNESS_OK
        && tr_rd32(rep.data, 12u) == HARNESS_STATE_COMPLETE;

    struct harness_req_task result_req = {.task_id = 4u};
    tr_zero(&req, sizeof(req));
    req.opcode = MSG_HARNESS_RESULT;
    req.length = sizeof(result_req);
    tr_copy(req.data, &result_req, sizeof(result_req));
    sel4_call((seL4_CPtr)TARGET_AGENT_HARNESS_CAP, &req, &rep);
    if (completed && rep.opcode == HARNESS_OK
        && tr_rd32(rep.data, 12u) > 0u
        && tr_rd32(rep.data, 24u) >= 2u
        && tr_rd32(rep.data, 28u) >= 1u
        && (int32_t)tr_rd32(rep.data, 40u) == 0)
        _tf_ok("AgentHarness completes live-model edit and profiled C compilation");
    else
        _tf_fail_point("AgentHarness completes live-model edit and profiled C compilation",
                       "live model did not complete the capability-gated protocol");
}

static void target_agent_harness_live_repository(void)
{
    volatile uint8_t *arena = (volatile uint8_t *)(uintptr_t)HARNESS_SHMEM_VADDR;
    static const char model[] = "fast";
    static const char prompt[] =
        "Find the tracked file defining agentos_repo_answer with repo.search, "
        "then inspect it with repo.read. Repair that discovered file so the "
        "function takes no arguments and returns 42. Use memory_write, then test "
        "that path with the agentos_repo_tests profile, then return final only "
        "after the managed repository test suite reports success.";
    const uint32_t prompt_off = 0x1000u;
    const uint32_t model_off = 0x2000u;
    const uint32_t result_off = 0x4000u;
    for (uint32_t i = 0u; i < sizeof(prompt); i++) arena[prompt_off + i] = prompt[i];
    for (uint32_t i = 0u; i < sizeof(model); i++) arena[model_off + i] = model[i];

    struct harness_req_submit submit;
    tr_zero(&submit, sizeof(submit));
    submit.task_id = 5u;
    submit.harness_kind = HARNESS_KIND_CODEX;
    submit.required_caps = HARNESS_CAP_MODEL | HARNESS_CAP_TOOL
        | HARNESS_CAP_MEMORY | HARNESS_CAP_EXEC;
    submit.task_flags = HARNESS_TASK_REQUIRE_TEST;
    submit.max_steps = 8u;
    submit.authority_epoch = 4u;
    submit.prompt_offset = prompt_off;
    submit.prompt_len = sizeof(prompt) - 1u;
    submit.result_offset = result_off;
    submit.result_capacity = 2048u;
    submit.model_id_offset = model_off;
    submit.model_id_len = sizeof(model) - 1u;
    sel4_msg_t req, rep;
    tr_zero(&req, sizeof(req));
    req.opcode = MSG_HARNESS_SUBMIT;
    req.length = sizeof(submit);
    tr_copy(req.data, &submit, sizeof(submit));
    sel4_call((seL4_CPtr)TARGET_AGENT_HARNESS_CAP, &req, &rep);
    bool completed = rep.opcode == HARNESS_OK
        && tr_rd32(rep.data, 12u) == HARNESS_STATE_COMPLETE;

    struct harness_req_task result_req = {.task_id = 5u};
    tr_zero(&req, sizeof(req));
    req.opcode = MSG_HARNESS_RESULT;
    req.length = sizeof(result_req);
    tr_copy(req.data, &result_req, sizeof(result_req));
    sel4_call((seL4_CPtr)TARGET_AGENT_HARNESS_CAP, &req, &rep);
    if (completed && rep.opcode == HARNESS_OK
        && tr_rd32(rep.data, 12u) > 0u
        && tr_rd32(rep.data, 16u) >= 5u
        && tr_rd32(rep.data, 20u) >= 2u
        && tr_rd32(rep.data, 24u) >= 1u
        && tr_rd32(rep.data, 28u) >= 1u
        && (int32_t)tr_rd32(rep.data, 40u) == 0)
        _tf_ok("AgentHarness completes managed repository edit and tests");
    else
    {
        struct harness_req_task status_req = {.task_id = 5u};
        tr_zero(&req, sizeof(req));
        req.opcode = MSG_HARNESS_STATUS;
        req.length = sizeof(status_req);
        tr_copy(req.data, &status_req, sizeof(status_req));
        sel4_call((seL4_CPtr)TARGET_AGENT_HARNESS_CAP, &req, &rep);
        _tf_puts("# repository harness state=");
        _tf_put_hex(tr_rd32(rep.data, 8u));
        _tf_puts(" last_error=");
        _tf_put_hex(tr_rd32(rep.data, 16u));
        _tf_puts(" used_caps=");
        _tf_put_hex(tr_rd32(rep.data, 20u));
        _tf_puts("\n");
        _tf_fail_point("AgentHarness completes managed repository edit and tests",
                       "live model did not pass the managed repository profile");
    }
}
#endif

static void target_agentfs_workspace_contract(void)
{
    volatile uint8_t *arena = (volatile uint8_t *)(uintptr_t)AGENTFS_SHMEM_VADDR;
    const uint32_t client_base = AGENTFS_CLIENT_ARENA_OFFSET(
        TARGET_TEST_RUNNER_CLIENT_ID);
    const uint32_t path_off = client_base + 0x100u;
    const uint32_t data_off = client_base + 0x400u;
    const uint32_t output_off = client_base + 0x1000u;
    static const char path[] = "src/native.txt";
    static const char content[] = "agentfs-edit";
    for (uint32_t i = 0u; i < sizeof(path); i++) arena[path_off + i] = path[i];
    for (uint32_t i = 0u; i < sizeof(content); i++) arena[data_off + i] = content[i];

    struct agentfs_req_write write;
    tr_zero(&write, sizeof(write));
    write.path_offset = path_off;
    write.path_len = sizeof(path) - 1u;
    write.data_offset = data_off;
    write.data_len = sizeof(content) - 1u;
    write.flags = AGENTFS_WRITE_CREATE | AGENTFS_WRITE_TRUNCATE;
    sel4_msg_t req, rep;
    tr_zero(&req, sizeof(req));
    req.opcode = MSG_AGENTFS_WRITE;
    req.length = sizeof(write);
    tr_copy(req.data, &write, sizeof(write));
    sel4_call((seL4_CPtr)TARGET_AGENTFS_CAP, &req, &rep);
    if (rep.opcode == AGENTFS_OK
        && tr_rd32(rep.data, 8u) == sizeof(content) - 1u
        && tr_rd32(rep.data, 16u) == 1u)
        _tf_ok("AgentFS writes a badge-isolated workspace overlay");
    else
        _tf_fail_point("AgentFS writes a badge-isolated workspace overlay",
                       "write reply was invalid");

    struct agentfs_req_read read;
    tr_zero(&read, sizeof(read));
    read.path_offset = path_off;
    read.path_len = sizeof(path) - 1u;
    read.output_offset = output_off;
    read.output_capacity = 128u;
    tr_zero(&req, sizeof(req));
    req.opcode = MSG_AGENTFS_READ;
    req.length = sizeof(read);
    tr_copy(req.data, &read, sizeof(read));
    sel4_call((seL4_CPtr)TARGET_AGENTFS_CAP, &req, &rep);
    if (rep.opcode == AGENTFS_OK
        && tr_rd32(rep.data, 4u) == sizeof(content) - 1u
        && tr_equal((const char *)(uintptr_t)(AGENTFS_SHMEM_VADDR + output_off),
                    content, sizeof(content) - 1u))
        _tf_ok("AgentFS reads the updated workspace artifact");
    else
        _tf_fail_point("AgentFS reads the updated workspace artifact",
                       "read failed or content mismatched");

    read.output_offset = AGENTFS_CLIENT_ARENA_OFFSET(
        TARGET_TEST_RUNNER_CLIENT_ID - 1u);
    tr_copy(req.data, &read, sizeof(read));
    sel4_call((seL4_CPtr)TARGET_AGENTFS_CAP, &req, &rep);
    if (rep.opcode == AGENTFS_ERR_DENIED)
        _tf_ok("AgentFS denies cross-worker overlay offsets");
    else
        _tf_fail_point("AgentFS denies cross-worker overlay offsets",
                       "cross-partition read was accepted");

    struct agentfs_req_export_overlay export_req = {
        .output_offset = output_off,
        .output_capacity = 0x4000u,
    };
    tr_zero(&req, sizeof(req));
    req.opcode = MSG_AGENTFS_EXPORT_OVERLAY;
    req.length = sizeof(export_req);
    tr_copy(req.data, &export_req, sizeof(export_req));
    sel4_call((seL4_CPtr)TARGET_AGENTFS_CAP, &req, &rep);
    if (rep.opcode == AGENTFS_OK
        && tr_rd32(rep.data, 8u) == 1u
        && tr_rd32((const uint8_t *)(uintptr_t)
                       (AGENTFS_SHMEM_VADDR + output_off), 0u)
            == AGENTFS_OVERLAY_BUNDLE_MAGIC)
        _tf_ok("AgentFS exports the caller's bounded workspace overlay");
    else
        _tf_fail_point("AgentFS exports the caller's bounded workspace overlay",
                       "badge-owned overlay export failed");

    export_req.output_offset = AGENTFS_CLIENT_ARENA_OFFSET(
        TARGET_TEST_RUNNER_CLIENT_ID - 1u);
    tr_copy(req.data, &export_req, sizeof(export_req));
    sel4_call((seL4_CPtr)TARGET_AGENTFS_CAP, &req, &rep);
    if (rep.opcode == AGENTFS_ERR_DENIED)
        _tf_ok("AgentFS denies cross-worker overlay exports");
    else
        _tf_fail_point("AgentFS denies cross-worker overlay exports",
                       "overlay bundle escaped the caller partition");
}

static void target_execsvc_profile_contract(void)
{
    volatile uint8_t *arena = (volatile uint8_t *)(uintptr_t)EXECSVC_SHMEM_VADDR;
    const uint32_t client_base = EXECSVC_CLIENT_ARENA_OFFSET(
        TARGET_TEST_RUNNER_CLIENT_ID);
    const uint32_t source_off = client_base + 0x100u;
    const uint32_t output_off = client_base + 0x3000u;
    static const char source[] = "int target_contract(void) { return 0; }\n";
    for (uint32_t i = 0u; i < sizeof(source) - 1u; i++)
        arena[source_off + i] = source[i];

    execsvc_run_profile_wire_t wire = {
        .source_offset = source_off,
        .source_len = sizeof(source) - 1u,
        .output_offset = output_off,
        .output_capacity = 256u,
        .profile_id = 0xfeedu,
        .request_tag = 91u,
    };
    sel4_msg_t req, rep;
    tr_zero(&req, sizeof(req));
    req.opcode = EXECSVC_OP_RUN_PROFILE;
    req.length = sizeof(wire);
    tr_copy(req.data, &wire, sizeof(wire));
    sel4_call((seL4_CPtr)TARGET_EXECSVC_CAP, &req, &rep);
    if (rep.opcode == EXECSVC_ERR_UNSUPPORTED)
        _tf_ok("ExecSvc denies unknown execution profiles on target");
    else
        _tf_fail_point("ExecSvc denies unknown execution profiles on target",
                       "unknown profile reached the execution transport");

    wire.profile_id = EXECSVC_PROFILE_C11_COMPILE;
    wire.output_offset = EXECSVC_CLIENT_ARENA_OFFSET(
        TARGET_TEST_RUNNER_CLIENT_ID - 1u);
    tr_copy(req.data, &wire, sizeof(wire));
    sel4_call((seL4_CPtr)TARGET_EXECSVC_CAP, &req, &rep);
    if (rep.opcode == EXECSVC_ERR_DENIED)
        _tf_ok("ExecSvc denies cross-worker profile output offsets on target");
    else
        _tf_fail_point("ExecSvc denies cross-worker profile output offsets on target",
                       "profile output escaped the caller partition");

    wire.profile_id = EXECSVC_PROFILE_AGENTOS_REPO_TEST;
    wire.output_offset = output_off;
    tr_copy(req.data, &wire, sizeof(wire));
    sel4_call((seL4_CPtr)TARGET_COMPILE_ONLY_EXECSVC_CAP, &req, &rep);
    if (rep.opcode == EXECSVC_ERR_DENIED)
        _tf_ok("ExecSvc profile rights deny repository tests on target");
    else
        _tf_fail_point("ExecSvc profile rights deny repository tests on target",
                       "compile-only capability authorized repository execution");
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
        submit.authority_epoch = 4u;
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
    const uint32_t client_base = MODELSVC_CLIENT_ARENA_OFFSET(
        TARGET_TEST_RUNNER_CLIENT_ID);
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
    target_toolsvc_contract();
    target_agentfs_workspace_contract();
    target_execsvc_profile_contract();
    target_cap_broker_tool_lifecycle();
    target_agent_harness_tool_loop();
    target_cap_broker_revoke_and_regrant_tool();
    target_agent_harness_external_mcp_loop();
    target_agent_harness_memory_loop();
#ifdef AGENTOS_LIVE_MODEL_TEST
    target_agent_harness_live_model();
    target_agent_harness_live_repository();
#endif
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
