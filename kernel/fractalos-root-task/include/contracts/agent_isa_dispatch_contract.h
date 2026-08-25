/*
 * Trusted asynchronous Agent ISA dispatcher contract.
 *
 * AgentHarness writes a canonical dispatch record into a badge-owned shared
 * mailbox, sends ENQUEUE, and replies to the model-facing caller immediately.
 * A distinct dispatcher PD performs lower-service calls and later invokes the
 * harness COMPLETE handler with a dispatcher-only badged capability.
 *
 * Presentation is never authorization.  The dispatcher and harness both
 * recheck the installed authority epoch, record digest, ticket ownership,
 * capability class, ObjectIDs, budget, and endpoint badge.  COMPLETE is an
 * internal trusted message and is not part of the model-visible Agent ISA.
 */

#pragma once

#include "agent_isa_contract.h"

#define AGENT_ISA_DISPATCH_INTERFACE_VERSION 1u
#define AGENT_ISA_DISPATCH_MAX_SLOTS         AGENT_ISA_MAX_TICKETS
#define AGENT_ISA_DISPATCH_BACKEND_OK        0u
#define AGENT_ISA_DISPATCH_BACKEND_FAILED    1u

enum agent_isa_dispatch_slot_state {
    AGENT_ISA_DISPATCH_SLOT_FREE = 0u,
    AGENT_ISA_DISPATCH_SLOT_QUEUED = 1u,
    AGENT_ISA_DISPATCH_SLOT_RUNNING = 2u,
    AGENT_ISA_DISPATCH_SLOT_COMPLETE = 3u,
    AGENT_ISA_DISPATCH_SLOT_FAILED = 4u,
    AGENT_ISA_DISPATCH_SLOT_CANCELLED = 5u,
};

enum agent_isa_dispatch_error {
    AGENT_ISA_DISPATCH_OK = 0u,
    AGENT_ISA_DISPATCH_ERR_INVALID = 1u,
    AGENT_ISA_DISPATCH_ERR_VERSION = 2u,
    AGENT_ISA_DISPATCH_ERR_SLOT = 3u,
    AGENT_ISA_DISPATCH_ERR_FULL = 4u,
    AGENT_ISA_DISPATCH_ERR_DIGEST = 5u,
    AGENT_ISA_DISPATCH_ERR_AUTHORITY = 6u,
    AGENT_ISA_DISPATCH_ERR_OWNER = 7u,
    AGENT_ISA_DISPATCH_ERR_STATE = 8u,
    AGENT_ISA_DISPATCH_ERR_NOT_FOUND = 9u,
    AGENT_ISA_DISPATCH_ERR_FORGED = 10u,
    AGENT_ISA_DISPATCH_ERR_BACKEND = 11u,
    AGENT_ISA_DISPATCH_ERR_EVENT = 12u, /* mandatory stream event missing/failed */
};

/* Canonical shared-mailbox record.  submission_digest is the first 128 bits
 * of SHA-256 over the explicit little-endian serialization of these fields. */
struct agent_isa_dispatch_record {
    uint16_t interface_version;
    uint16_t operation;
    uint32_t flags;
    uint32_t ticket_id;
    uint32_t authority_epoch;
    uint32_t declared_caps;
    uint32_t budget_units;
    uint32_t owner_badge_low;
    uint32_t owner_badge_high;
    uint32_t dispatch_nonce;
    agent_object_id_t input_root;
    agent_object_id_t operand_root;
    agent_object_id_t capability_set_root;
};

/* MSG_AGENT_ISA_DISPATCH_ENQUEUE.  The full record remains in shared memory;
 * the inline request binds its slot and digest without exceeding 48 bytes. */
struct agent_isa_dispatch_req_enqueue {
    uint16_t interface_version;
    uint16_t reserved16;
    uint32_t slot_index;
    uint32_t ticket_id;
    uint32_t authority_epoch;
    uint32_t dispatch_nonce;
    agent_object_id_t submission_digest;
    uint32_t reserved[3];
};

struct agent_isa_dispatch_reply_enqueue {
    uint32_t status;
    uint32_t slot_index;
    uint32_t queue_depth;
    uint32_t reserved;
};

/* MSG_AGENT_ISA_DISPATCH_COMPLETE.  Only a launcher-minted dispatcher badge
 * may invoke this handler; generated programs never receive that cap. */
struct agent_isa_dispatch_req_complete {
    uint16_t interface_version;
    uint16_t flags;
    uint32_t ticket_id;
    uint32_t authority_epoch;
    uint32_t dispatch_nonce;
    uint32_t backend_status;
    agent_object_id_t result_root;
    uint32_t reserved[3];
};

struct agent_isa_dispatch_req_cancel {
    uint16_t interface_version;
    uint16_t reserved16;
    uint32_t ticket_id;
    uint32_t authority_epoch;
    uint32_t dispatch_nonce;
    uint32_t reserved;
};

struct agent_isa_dispatch_req_status {
    uint16_t interface_version;
    uint16_t reserved16;
    uint32_t reserved[3];
};

struct agent_isa_dispatch_reply_status {
    uint32_t status;
    uint32_t queued;
    uint32_t running;
    uint32_t terminal;
    uint32_t cancelled;
    uint32_t capacity;
    uint32_t authority_epoch;
    uint32_t reserved;
};

_Static_assert(sizeof(struct agent_isa_dispatch_record) == 84u,
               "Agent ISA dispatch record ABI drift");
_Static_assert(sizeof(struct agent_isa_dispatch_req_enqueue) == 48u,
               "Agent ISA enqueue request must fit inline IPC");
_Static_assert(sizeof(struct agent_isa_dispatch_reply_enqueue) == 16u,
               "Agent ISA enqueue reply ABI drift");
_Static_assert(sizeof(struct agent_isa_dispatch_req_complete) == 48u,
               "Agent ISA completion request must fit inline IPC");
_Static_assert(sizeof(struct agent_isa_dispatch_req_cancel) == 20u,
               "Agent ISA cancel request ABI drift");
_Static_assert(sizeof(struct agent_isa_dispatch_req_status) == 16u,
               "Agent ISA dispatcher status request ABI drift");
_Static_assert(sizeof(struct agent_isa_dispatch_reply_status) == 32u,
               "Agent ISA dispatcher status reply ABI drift");
