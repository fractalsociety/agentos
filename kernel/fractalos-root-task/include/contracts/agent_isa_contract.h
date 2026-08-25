/*
 * Fractal Agent ISA v0 IPC Contract
 *
 * This is the evolvable semantic layer above the stable FractalOS service
 * ABI. It does not replace or bypass any lower PD contract. An AgentHarness
 * runner translates accepted semantic operations into capability-addressed
 * service calls.
 *
 * The model-visible vocabulary is intentionally small. Inputs, constraints,
 * results, state, capability sets, environments, verifiers, and trace nodes
 * are opaque immutable ObjectIDs. Transport details remain below this layer.
 *
 * Authority invariants:
 *   - declared_caps describes intent and never grants authority;
 *   - installed seL4 endpoint caps remain the authority for every effect;
 *   - CAP_GRANT and CAP_REVOKE are broker requests, not CSpace operations;
 *   - capability_set_root is launcher-owned and included in every node;
 *   - unknown versions, operations, flags, caps, and ObjectID shapes fail
 *     closed before any lower service is invoked.
 *
 * Async invariants:
 *   - long operations require AGENT_ISA_FLAG_ASYNC and return a ticket;
 *   - WAIT is a bounded poll and never holds an seL4 call open;
 *   - completion notification is delivered separately through EventBus;
 *   - pending and terminal transitions are distinct immutable graph nodes.
 */

#pragma once

#include "../fractalos.h"
#include <stdbool.h>
#include <stdint.h>

#define AGENT_ISA_INTERFACE_VERSION 1u
#define AGENT_ISA_MAX_TICKETS       16u
#define AGENT_ISA_MAX_TRACE_NODES   32u
#define AGENT_ISA_MAX_BUDGET_UNITS  UINT32_C(0x7fffffff)

typedef struct {
    uint32_t word[4];
} agent_object_id_t;

enum agent_isa_operation {
    AGENT_ISA_OP_SPAWN = 1u,
    AGENT_ISA_OP_DELEGATE = 2u,
    AGENT_ISA_OP_CAP_GRANT = 3u,
    AGENT_ISA_OP_CAP_REVOKE = 4u,
    AGENT_ISA_OP_OBJECT_GET = 5u,
    AGENT_ISA_OP_OBJECT_PUT = 6u,
    AGENT_ISA_OP_OBJECT_QUERY = 7u,
    AGENT_ISA_OP_INFER = 8u,
    AGENT_ISA_OP_ACT = 9u,
    AGENT_ISA_OP_WAIT = 10u,
    AGENT_ISA_OP_EMIT = 11u,
    AGENT_ISA_OP_CHECKPOINT = 12u,
    AGENT_ISA_OP_RESTORE = 13u,
    AGENT_ISA_OP_VERIFY = 14u,
    AGENT_ISA_OP_COMMIT = 15u,
    AGENT_ISA_OP_TRACE = 16u,
    AGENT_ISA_OP_BUDGET = 17u,
    AGENT_ISA_OP_TERMINATE = 18u,
};

#define AGENT_ISA_OP_FIRST AGENT_ISA_OP_SPAWN
#define AGENT_ISA_OP_LAST  AGENT_ISA_OP_TERMINATE

/* Semantic authority classes. These map to installed lower-service endpoint
 * caps; they are deliberately not tool names or transport permissions. */
#define AGENT_ISA_CAP_CONTROL    (1u << 0)
#define AGENT_ISA_CAP_ADMIN      (1u << 1)
#define AGENT_ISA_CAP_OBJECT     (1u << 2)
#define AGENT_ISA_CAP_INFER      (1u << 3)
#define AGENT_ISA_CAP_ACT        (1u << 4)
#define AGENT_ISA_CAP_EVENT      (1u << 5)
#define AGENT_ISA_CAP_VERIFY     (1u << 6)
#define AGENT_ISA_CAP_COMMIT     (1u << 7)
#define AGENT_ISA_CAP_TRACE      (1u << 8)
#define AGENT_ISA_CAP_BUDGET     (1u << 9)
#define AGENT_ISA_CAP_KNOWN_MASK ((1u << 10) - 1u)

#define AGENT_ISA_FLAG_ASYNC       (1u << 0)
#define AGENT_ISA_FLAG_KNOWN_MASK  AGENT_ISA_FLAG_ASYNC

#define AGENT_ISA_WAIT_CONSUME     (1u << 0)
#define AGENT_ISA_WAIT_KNOWN_MASK  AGENT_ISA_WAIT_CONSUME

enum agent_isa_ticket_state {
    AGENT_ISA_TICKET_FREE = 0u,
    AGENT_ISA_TICKET_PENDING = 1u,
    AGENT_ISA_TICKET_COMPLETE = 2u,
    AGENT_ISA_TICKET_FAILED = 3u,
    AGENT_ISA_TICKET_CANCELLED = 4u,
    AGENT_ISA_TICKET_CONFLICT = 5u,
};

enum agent_isa_error {
    AGENT_ISA_OK = 0u,
    AGENT_ISA_ERR_INVALID = 1u,
    AGENT_ISA_ERR_VERSION = 2u,
    AGENT_ISA_ERR_OPERATION = 3u,
    AGENT_ISA_ERR_FLAGS = 4u,
    AGENT_ISA_ERR_OBJECT = 5u,
    AGENT_ISA_ERR_CAP_DENIED = 6u,
    AGENT_ISA_ERR_BUDGET = 7u,
    AGENT_ISA_ERR_TICKET_EXHAUSTED = 8u,
    AGENT_ISA_ERR_NOT_FOUND = 9u,
    AGENT_ISA_ERR_STATE = 10u,
    AGENT_ISA_ERR_CONFLICT = 11u,
    AGENT_ISA_ERR_TERMINATED = 12u,
    AGENT_ISA_ERR_BACKEND = 13u,
};

/* MSG_AGENT_ISA_SUBMIT. input_root and operand_root are operation-specific
 * immutable objects. No string, command, path, protocol, or handle appears in
 * the semantic wire format. */
struct agent_isa_req_submit {
    uint16_t interface_version;
    uint16_t operation;
    uint32_t flags;
    uint32_t declared_caps;
    uint32_t budget_units;
    agent_object_id_t input_root;
    agent_object_id_t operand_root;
};

struct agent_isa_reply_submit {
    uint32_t status;
    uint32_t ticket_id;
    uint32_t ticket_state;
    uint32_t authority_epoch;
    agent_object_id_t execution_node;
    agent_object_id_t state_root;
};

/* MSG_AGENT_ISA_WAIT. timeout_ticks is reserved at zero in v0: callers poll
 * or subscribe to EventBus rather than blocking a synchronous call. */
struct agent_isa_req_wait {
    uint16_t interface_version;
    uint16_t flags;
    uint32_t ticket_id;
    uint32_t timeout_ticks;
    uint32_t reserved;
};

struct agent_isa_reply_wait {
    uint32_t status;
    uint32_t ticket_id;
    uint32_t ticket_state;
    uint32_t operation;
    agent_object_id_t result_root;
    agent_object_id_t state_root;
};

struct agent_isa_req_cancel {
    uint16_t interface_version;
    uint16_t reserved16;
    uint32_t ticket_id;
    uint32_t reserved[2];
};

struct agent_isa_req_status {
    uint16_t interface_version;
    uint16_t reserved16;
    uint32_t reserved[3];
};

struct agent_isa_reply_status {
    uint32_t status;
    uint32_t terminated;
    uint32_t pending_tickets;
    uint32_t budget_used;
    uint32_t budget_limit;
    uint32_t authority_epoch;
    uint32_t trace_nodes;
    uint32_t reserved;
    agent_object_id_t state_root;
};

/* MSG_AGENT_ISA_TRACE returns one canonical graph edge by sequence. Sequence
 * zero selects the latest retained node. */
struct agent_isa_req_trace {
    uint16_t interface_version;
    uint16_t reserved16;
    uint32_t sequence;
    uint32_t reserved[2];
};

struct agent_isa_reply_trace {
    uint32_t status;
    uint32_t sequence;
    uint32_t operation;
    uint32_t ticket_state;
    agent_object_id_t node_root;
    agent_object_id_t parent_root;
};

_Static_assert(sizeof(agent_object_id_t) == 16u, "ObjectID v0 ABI drift");
_Static_assert(sizeof(struct agent_isa_req_submit) == 48u,
               "Agent ISA submit must fit one seL4 inline payload");
_Static_assert(sizeof(struct agent_isa_reply_submit) == 48u,
               "Agent ISA submit reply must fit one seL4 inline payload");
_Static_assert(sizeof(struct agent_isa_req_wait) == 16u,
               "Agent ISA wait request ABI drift");
_Static_assert(sizeof(struct agent_isa_reply_wait) == 48u,
               "Agent ISA wait reply must fit one seL4 inline payload");
_Static_assert(sizeof(struct agent_isa_reply_status) == 48u,
               "Agent ISA status reply must fit one seL4 inline payload");
_Static_assert(sizeof(struct agent_isa_reply_trace) == 48u,
               "Agent ISA trace reply must fit one seL4 inline payload");

static inline bool agent_object_id_is_zero(const agent_object_id_t *id)
{
    return id == (const agent_object_id_t *)0
        || (id->word[0] | id->word[1] | id->word[2] | id->word[3]) == 0u;
}

static inline bool agent_object_id_equal(const agent_object_id_t *a,
                                         const agent_object_id_t *b)
{
    return a != (const agent_object_id_t *)0
        && b != (const agent_object_id_t *)0
        && a->word[0] == b->word[0] && a->word[1] == b->word[1]
        && a->word[2] == b->word[2] && a->word[3] == b->word[3];
}
