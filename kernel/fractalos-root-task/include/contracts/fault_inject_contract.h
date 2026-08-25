/*
 * FaultInject PD IPC Contract
 *
 * The FaultInject PD is a test-only endpoint used by CI to exercise the
 * fault-control path through real seL4 IPC. It is included only in images
 * built with FAULT_INJECT=1.
 */

#pragma once
#include "../fractalos.h"
#include "../system_desc.h"

#define FAULT_INJECT_CH_CC_PD  PD_CNODE_SLOT_FAULT_INJECT_EP

#define OP_FAULT_INJECT       0xF0u
#define OP_FAULT_STATUS       0xF1u
#define OP_FAULT_RESET        0xF2u

#define FAULT_NULL_DEREF      0x01u
#define FAULT_STACK_OVF       0x02u
#define FAULT_QUOTA_EXCEEDED  0x03u
#define FAULT_IPC_TIMEOUT     0x04u
#define FAULT_UNALIGNED_MEM   0x05u

#define FAULT_FLAG_VERIFY_RECOVERY  0x01u
#define FAULT_FLAG_EXPECT_NO_CRASH  0x02u

#define FAULT_RESULT_OK       0x00u
#define FAULT_RESULT_ERROR    0x01u
#define FAULT_RESULT_TIMEOUT  0x02u
#define FAULT_RESULT_NO_CRASH 0x03u

struct fault_inject_req_inject {
    uint32_t slot_id;
    uint32_t fault_kind;
    uint32_t flags;
};

struct fault_inject_reply_inject {
    uint32_t result;
    uint32_t ticks_to_recovery;
    uint32_t trace_event_id;
};

struct fault_inject_reply_status {
    uint32_t result;
    uint32_t ticks_to_recovery;
    uint32_t trace_event_id;
    uint32_t state;
};

enum fault_inject_error {
    FAULT_INJECT_OK = 0,
    FAULT_INJECT_ERR_BAD_SLOT = 1,
    FAULT_INJECT_ERR_BAD_KIND = 2,
    FAULT_INJECT_ERR_BUSY = 3,
};
