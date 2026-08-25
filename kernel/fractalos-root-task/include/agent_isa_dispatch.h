/* Bounded freestanding mailbox state for the trusted Agent ISA dispatcher. */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "contracts/agent_isa_dispatch_contract.h"

struct agent_isa_dispatch_slot {
    uint32_t state;
    uint32_t backend_status;
    struct agent_isa_dispatch_record record;
    agent_object_id_t submission_digest;
    agent_object_id_t result_root;
};

typedef struct agent_isa_dispatch_mailbox {
    uint32_t authority_epoch;
    uint32_t queued;
    uint32_t running;
    uint32_t terminal;
    uint32_t cancelled;
    struct agent_isa_dispatch_slot slots[AGENT_ISA_DISPATCH_MAX_SLOTS];
} agent_isa_dispatch_mailbox_t;

void agent_isa_dispatch_record_digest(
    const struct agent_isa_dispatch_record *record,
    agent_object_id_t *out);

void agent_isa_dispatch_init(agent_isa_dispatch_mailbox_t *mailbox,
                             uint32_t authority_epoch);

uint32_t agent_isa_dispatch_enqueue(
    agent_isa_dispatch_mailbox_t *mailbox, uint64_t caller_badge,
    const struct agent_isa_dispatch_record *record,
    const struct agent_isa_dispatch_req_enqueue *req,
    struct agent_isa_dispatch_reply_enqueue *reply);

uint32_t agent_isa_dispatch_take(agent_isa_dispatch_mailbox_t *mailbox,
                                 uint32_t *slot_index,
                                 struct agent_isa_dispatch_record *record);

uint32_t agent_isa_dispatch_complete(
    agent_isa_dispatch_mailbox_t *mailbox, uint64_t caller_badge,
    uint64_t trusted_dispatcher_badge,
    const struct agent_isa_dispatch_req_complete *req);

uint32_t agent_isa_dispatch_cancel(
    agent_isa_dispatch_mailbox_t *mailbox, uint64_t caller_badge,
    const struct agent_isa_dispatch_req_cancel *req);

uint32_t agent_isa_dispatch_update_authority(
    agent_isa_dispatch_mailbox_t *mailbox, uint64_t owner_badge,
    uint32_t new_authority_epoch);

uint32_t agent_isa_dispatch_reap(agent_isa_dispatch_mailbox_t *mailbox,
                                 uint64_t owner_badge, uint32_t ticket_id,
                                 agent_object_id_t *result_root,
                                 bool *success);

uint32_t agent_isa_dispatch_status(
    const agent_isa_dispatch_mailbox_t *mailbox,
    struct agent_isa_dispatch_reply_status *reply);
