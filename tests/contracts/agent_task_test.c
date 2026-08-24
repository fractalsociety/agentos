/*
 * FractalOS capabilities v1 contract tests.
 *
 * The suite is intentionally contract-only: it proves the wire names,
 * version, typed identities, error taxonomy, and nonblocking invariants before
 * a runtime implementation is attached. The same assertions run in the host
 * test runner and in the target TAP runner.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "../../kernel/agentos-root-task/include/agentos.h"
#include "../../kernel/agentos-root-task/include/contracts/agent_task_contract.h"

_Static_assert(MSG_FRACTAL_PROGRAM_OPEN == 0x2E01,
               "program open opcode is versioned");
_Static_assert(MSG_FRACTAL_PROGRAM_POLL == 0x2E02,
               "program poll opcode is versioned");
_Static_assert(MSG_FRACTAL_TASK_SUBMIT == 0x2E03,
               "task submit opcode is versioned");
_Static_assert(MSG_FRACTAL_TASK_POLL == 0x2E04,
               "task poll opcode is versioned");
_Static_assert(MSG_FRACTAL_TASK_CANCEL == 0x2E05,
               "task cancel opcode is versioned");
_Static_assert(MSG_FRACTAL_TASK_BUDGET == 0x2E06,
               "task budget opcode is versioned");
_Static_assert(MSG_FRACTAL_TASK_VERIFY == 0x2E07,
               "TASK_VERIFY opcode is versioned");
_Static_assert(MSG_FRACTAL_TASK_RESULT == 0x2E08,
               "terminal result opcode is versioned");
_Static_assert(sizeof(struct agent_task_req_verify) == 128u,
               "TASK_VERIFY request remains bounded");
_Static_assert(offsetof(struct agent_task_req_poll, nonblocking) == 12u,
               "poll carries the nonblocking marker");
_Static_assert(offsetof(struct agent_task_req_cancel, authority_epoch) == 8u,
               "cancel carries the authority epoch");

static const uint32_t agent_task_opcodes[] = {
    MSG_FRACTAL_PROGRAM_OPEN,
    MSG_FRACTAL_PROGRAM_POLL,
    MSG_FRACTAL_TASK_SUBMIT,
    MSG_FRACTAL_TASK_POLL,
    MSG_FRACTAL_TASK_CANCEL,
    MSG_FRACTAL_TASK_BUDGET,
    MSG_FRACTAL_TASK_VERIFY,
    MSG_FRACTAL_TASK_RESULT,
};

static const uint32_t agent_task_errors[] = {
    AGENT_TASK_OK,
    AGENT_TASK_ERR_INVALID,
    AGENT_TASK_ERR_DENIED,
    AGENT_TASK_ERR_BUSY,
    AGENT_TASK_ERR_INCOMPLETE,
    AGENT_TASK_ERR_HARNESS,
    AGENT_TASK_ERR_NOT_FOUND,
    AGENT_TASK_ERR_VERSION,
    AGENT_TASK_ERR_STALE_HANDLE,
    AGENT_TASK_ERR_REVOKED,
    AGENT_TASK_ERR_CANCELLED,
    AGENT_TASK_ERR_BUDGET_EXHAUSTED,
    AGENT_TASK_ERR_NOT_READY,
    AGENT_TASK_ERR_WOULD_BLOCK,
    AGENT_TASK_ERR_TERMINAL,
    AGENT_TASK_ERR_AUTHORITY,
    AGENT_TASK_ERR_VERIFY_REQUIRED,
    AGENT_TASK_ERR_EVIDENCE_MISMATCH,
    AGENT_TASK_ERR_PROMOTION_FORBIDDEN,
};

static bool agent_task_unique(const uint32_t *values, size_t count)
{
    for (size_t i = 0u; i < count; i++)
        for (size_t j = i + 1u; j < count; j++)
            if (values[i] == values[j]) return false;
    return true;
}

#ifdef AGENTOS_TEST_HOST

#include <stdio.h>

static unsigned agent_task_tests;
static unsigned agent_task_failures;

static void agent_task_check(bool condition, const char *name)
{
    agent_task_tests++;
    if (condition) {
        printf("ok %u - %s\n", agent_task_tests, name);
    } else {
        printf("not ok %u - %s\n", agent_task_tests, name);
        agent_task_failures++;
    }
}

int main(void)
{
    puts("TAP version 14");
    agent_task_check(FRACTALOS_CAPABILITIES_INTERFACE_VERSION == 1u
                         && AGENT_TASK_FRACTAL_V1_VERSION == 1u,
                     "capabilities interface is explicitly version 1");
    agent_task_check(agent_task_unique(agent_task_opcodes,
                                       sizeof(agent_task_opcodes)
                                           / sizeof(agent_task_opcodes[0])),
                     "every asynchronous task opcode is collision-free");
    agent_task_check(MSG_AGENT_TASK_PROGRAM_OPEN == MSG_FRACTAL_PROGRAM_OPEN
                         && MSG_AGENT_TASK_PROGRAM_POLL == MSG_FRACTAL_PROGRAM_POLL
                         && MSG_AGENT_TASK_SUBMIT == MSG_FRACTAL_TASK_SUBMIT
                         && MSG_AGENT_TASK_POLL == MSG_FRACTAL_TASK_POLL
                         && MSG_AGENT_TASK_CANCEL == MSG_FRACTAL_TASK_CANCEL
                         && MSG_AGENT_TASK_BUDGET == MSG_FRACTAL_TASK_BUDGET
                         && MSG_AGENT_TASK_VERIFY == MSG_FRACTAL_TASK_VERIFY
                         && MSG_AGENT_TASK_TERMINAL_RESULT == MSG_FRACTAL_TASK_RESULT,
                     "all public task opcode aliases bind to v1 opcodes");
    agent_task_check(agent_task_unique(agent_task_errors,
                                       sizeof(agent_task_errors)
                                           / sizeof(agent_task_errors[0])),
                     "all task errors have distinct wire values");
    agent_task_check(AGENT_TASK_ERR_STALE_HANDLE != AGENT_TASK_ERR_REVOKED,
                     "stale handles and authority revocation are distinct errors");
    agent_task_check(AGENT_TASK_ERR_CANCELLED != AGENT_TASK_ERR_BUDGET_EXHAUSTED,
                     "cancellation and budget exhaustion are distinct errors");
    agent_task_check(AGENT_TASK_ERR_NOT_READY != AGENT_TASK_ERR_WOULD_BLOCK,
                     "not-ready is not a permission to block");
    agent_task_check(AGENT_TASK_NONBLOCKING == 1u
                         && sizeof(struct agent_task_req_poll) == 16u
                         && sizeof(struct agent_task_req_program_poll) == 16u,
                     "program and task polls are explicitly nonblocking");
    agent_task_check(sizeof(ProgramHandle) == 8u && sizeof(TaskHandle) == 8u,
                     "ProgramHandle and TaskHandle are typed opaque handles");
    agent_task_check(sizeof(WorkerIdentity) == 16u
                         && AGENT_TASK_WORKER_NATIVE != AGENT_TASK_WORKER_WASM,
                     "worker identity is typed and locator-free");
    agent_task_check(sizeof(struct agent_task_budget) == 24u
                         && offsetof(struct agent_task_req_submit, budget) == 8u,
                     "submission carries an explicit bounded budget");
    agent_task_check(offsetof(struct agent_task_req_program_open,
                              authority_epoch) == 40u
                         && offsetof(struct agent_task_req_verify,
                                     authority_epoch) == 8u,
                     "open and TASK_VERIFY bind to an authority epoch");
    agent_task_check(sizeof(struct agent_task_verify_evidence)
                         == 4u * 4u + 3u * AGENT_TASK_DIGEST_BYTES,
                     "TASK_VERIFY carries digest-only commit and test evidence");
    agent_task_check(offsetof(struct agent_task_reply_terminal_result,
                              result_digest)
                         + AGENT_TASK_DIGEST_BYTES
                         <= sizeof(struct agent_task_reply_terminal_result),
                     "terminal results carry typed state and an immutable digest");
    printf("1..%u\n", agent_task_tests);
    return agent_task_failures == 0u ? 0 : 1;
}

#else

#include "../harness/test_framework.h"

void run_agent_task_contract_tests(microkit_channel ch)
{
    (void)ch;
    TEST_SECTION("FractalOS capabilities v1 task boundary");
    if (FRACTALOS_CAPABILITIES_INTERFACE_VERSION == 1u
        && AGENT_TASK_FRACTAL_V1_VERSION == 1u)
        _tf_ok("target contract uses version 1");
    else
        _tf_fail_point("target contract uses version 1", "version drift");

    if (agent_task_unique(agent_task_opcodes,
                          sizeof(agent_task_opcodes)
                              / sizeof(agent_task_opcodes[0])))
        _tf_ok("target task opcodes are collision-free");
    else
        _tf_fail_point("target task opcodes are collision-free", "duplicate opcode");

    if (agent_task_unique(agent_task_errors,
                          sizeof(agent_task_errors)
                              / sizeof(agent_task_errors[0])))
        _tf_ok("target task errors are collision-free");
    else
        _tf_fail_point("target task errors are collision-free", "duplicate error");

    if (AGENT_TASK_ERR_STALE_HANDLE != AGENT_TASK_ERR_REVOKED
        && AGENT_TASK_ERR_REVOKED != AGENT_TASK_ERR_AUTHORITY)
        _tf_ok("target distinguishes stale handles from revocation");
    else
        _tf_fail_point("target distinguishes stale handles from revocation",
                       "authority error collision");

    if (AGENT_TASK_NONBLOCKING == 1u
        && offsetof(struct agent_task_req_poll, nonblocking) == 12u
        && offsetof(struct agent_task_req_terminal_result,
                    nonblocking) == 12u)
        _tf_ok("target poll and result requests are nonblocking");
    else
        _tf_fail_point("target poll and result requests are nonblocking",
                       "missing nonblocking marker");

    if (sizeof(ProgramHandle) == 8u && sizeof(TaskHandle) == 8u
        && sizeof(WorkerIdentity) == 16u)
        _tf_ok("target carries typed handles and worker identity");
    else
        _tf_fail_point("target carries typed handles and worker identity",
                       "wire layout drift");

    if (sizeof(struct agent_task_verify_evidence)
            == 4u * 4u + 3u * AGENT_TASK_DIGEST_BYTES
        && sizeof(struct agent_task_reply_terminal_result)
            >= AGENT_TASK_DIGEST_BYTES)
        _tf_ok("target TASK_VERIFY and terminal result records are present");
    else
        _tf_fail_point("target TASK_VERIFY and terminal result records are present",
                       "evidence/result layout drift");
}

#endif
