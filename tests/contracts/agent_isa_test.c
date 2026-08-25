/* Contract tests for the Fractal Agent ISA v0 semantic surface. */

#include <stdint.h>
#include <stdio.h>

#include "../../kernel/fractalos-root-task/include/contracts/agent_isa_contract.h"

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
    check(AGENT_ISA_OP_LAST - AGENT_ISA_OP_FIRST + 1u == 18u,
          "v0 exposes exactly eighteen semantic instructions");
    check(AGENT_ISA_OP_SPAWN != AGENT_ISA_OP_DELEGATE
              && AGENT_ISA_OP_INFER != AGENT_ISA_OP_ACT
              && AGENT_ISA_OP_VERIFY != AGENT_ISA_OP_COMMIT,
          "semantic instruction numbers are distinct");
    check(MSG_AGENT_ISA_SUBMIT != MSG_AGENT_ISA_WAIT
              && MSG_AGENT_ISA_WAIT != MSG_AGENT_ISA_CANCEL
              && MSG_AGENT_ISA_CANCEL != MSG_AGENT_ISA_STATUS
              && MSG_AGENT_ISA_STATUS != MSG_AGENT_ISA_TRACE,
          "Agent ISA transport opcodes are distinct");
    check(sizeof(agent_object_id_t) == 16u,
          "v0 ObjectID is a compact opaque content identity");
    check(sizeof(struct agent_isa_req_submit) == 48u,
          "semantic submit fits one inline IPC payload");
    check(sizeof(struct agent_isa_reply_submit) == 48u,
          "semantic submit reply fits one inline IPC payload");
    check(sizeof(struct agent_isa_reply_wait) == 48u,
          "future polling reply fits one inline IPC payload");
    check(sizeof(struct agent_isa_reply_trace) == 48u,
          "execution graph edge fits one inline IPC payload");
    check((AGENT_ISA_CAP_KNOWN_MASK & (1u << 31)) == 0u,
          "unknown semantic authority cannot be declared");
    check((AGENT_ISA_FLAG_KNOWN_MASK & ~AGENT_ISA_FLAG_ASYNC) == 0u,
          "v0 submit has only one execution flag");

    agent_object_id_t zero = {{0u, 0u, 0u, 0u}};
    agent_object_id_t one = {{1u, 0u, 0u, 0u}};
    agent_object_id_t one_copy = one;
    check(agent_object_id_is_zero(&zero) && !agent_object_id_is_zero(&one),
          "zero ObjectID is reserved and detectable");
    check(agent_object_id_equal(&one, &one_copy)
              && !agent_object_id_equal(&one, &zero),
          "ObjectID equality is exact");

    printf("1..%u\n", tests);
    return failures == 0u ? 0 : 1;
}
