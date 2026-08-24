/* Contract-only tests for the native AgentHarness authority boundary. */

#include <stdint.h>
#include "../../kernel/agentos-root-task/include/contracts/agent_harness_contract.h"

#ifdef AGENTOS_TEST_HOST
#include <stdio.h>

static unsigned tests;
static unsigned failures;

static void check(int condition, const char *name)
{
    tests++;
    if (condition) printf("ok %u - %s\n", tests, name);
    else {
        printf("not ok %u - %s\n", tests, name);
        failures++;
    }
}

int main(void)
{
    puts("TAP version 14");
    check(!harness_authority_satisfies(HARNESS_CAP_MODEL, 0u),
          "model access is denied without ModelCap");
    check(!harness_authority_satisfies(HARNESS_CAP_NETWORK, HARNESS_CAP_MODEL),
          "ModelCap never implies NetCap");
    check(!harness_authority_satisfies(HARNESS_CAP_EXEC, HARNESS_CAP_TOOL),
          "ToolCap never implies ExecCap");
    check(!harness_authority_satisfies(HARNESS_CAP_MEMORY, HARNESS_CAP_EXEC),
          "ExecCap never implies MemoryCap");
    check(harness_authority_satisfies(
              HARNESS_CAP_MODEL | HARNESS_CAP_TOOL,
              HARNESS_CAP_MODEL | HARNESS_CAP_TOOL | HARNESS_CAP_MEMORY),
          "an explicit capability superset satisfies a task");
    check(!harness_authority_satisfies(1u << 31, HARNESS_CAP_KNOWN_MASK),
          "unknown requested capability bits are rejected");
    check(!harness_authority_satisfies(HARNESS_CAP_MODEL,
                                       HARNESS_CAP_MODEL | (1u << 31)),
          "unknown installed capability bits are rejected");
    check(MSG_HARNESS_SUBMIT != MSG_HARNESS_CANCEL &&
              MSG_HARNESS_CANCEL != MSG_HARNESS_STATUS &&
              MSG_HARNESS_STATUS != MSG_HARNESS_RESULT,
          "harness opcodes are unique");
    printf("1..%u\n", tests);
    return failures == 0u ? 0 : 1;
}
#endif
