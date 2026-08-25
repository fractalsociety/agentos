#include <stdio.h>
#include <string.h>

#include "../../kernel/fractalos-root-task/include/contracts/agent_isa_dispatch_contract.h"

static unsigned tests;
static unsigned failures;

static void check(int condition, const char *name)
{
    tests++;
    if (condition) printf("ok %u - %s\n", tests, name);
    else { printf("not ok %u - %s\n", tests, name); failures++; }
}

int main(void)
{
    puts("TAP version 14");
    check(MSG_AGENT_ISA_DISPATCH_ENQUEUE == 0x3106,
          "dispatcher enqueue opcode is stable");
    check(MSG_AGENT_ISA_DISPATCH_COMPLETE == 0x3107,
          "trusted completion opcode is stable");
    check(MSG_AGENT_ISA_DISPATCH_CANCEL == 0x3108,
          "dispatcher cancel opcode is stable");
    check(MSG_AGENT_ISA_DISPATCH_STATUS == 0x3109,
          "dispatcher status opcode is stable");
    check(sizeof(struct agent_isa_dispatch_record) == 84u,
          "canonical dispatch record layout is stable");
    check(sizeof(struct agent_isa_dispatch_req_enqueue) <= 48u,
          "enqueue control fits inline seL4 payload");
    check(sizeof(struct agent_isa_dispatch_req_complete) <= 48u,
          "completion control fits inline seL4 payload");
    check(AGENT_ISA_DISPATCH_MAX_SLOTS == AGENT_ISA_MAX_TICKETS,
          "mailbox capacity matches future capacity");
    check(AGENT_ISA_DISPATCH_ERR_FORGED != AGENT_ISA_DISPATCH_OK,
          "forged completion has a fail-closed error");
    check(AGENT_ISA_DISPATCH_SLOT_CANCELLED
              != AGENT_ISA_DISPATCH_SLOT_COMPLETE,
          "cancelled and successful terminal states are distinct");
    printf("1..%u\n", tests);
    return failures == 0u ? 0 : 1;
}
