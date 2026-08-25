#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../kernel/fractalos-root-task/include/agent_isa.h"
#include "../kernel/fractalos-root-task/include/agent_isa_dispatch.h"

static unsigned tests;
static unsigned failures;

static void check(int condition, const char *name)
{
    tests++;
    if (condition) printf("ok %u - %s\n", tests, name);
    else { printf("not ok %u - %s\n", tests, name); failures++; }
}

static agent_object_id_t object(const char *text)
{
    agent_object_id_t id;
    agent_isa_object_id_from_bytes(text, (uint32_t)strlen(text), &id);
    return id;
}

static struct agent_isa_dispatch_record record_for(
    uint64_t owner, uint32_t ticket, uint32_t epoch, uint32_t nonce)
{
    struct agent_isa_dispatch_record record;
    memset(&record, 0, sizeof(record));
    record.interface_version = AGENT_ISA_DISPATCH_INTERFACE_VERSION;
    record.operation = AGENT_ISA_OP_DELEGATE;
    record.flags = AGENT_ISA_FLAG_ASYNC;
    record.ticket_id = ticket;
    record.authority_epoch = epoch;
    record.declared_caps = AGENT_ISA_CAP_CONTROL;
    record.budget_units = 3u;
    record.owner_badge_low = (uint32_t)owner;
    record.owner_badge_high = (uint32_t)(owner >> 32u);
    record.dispatch_nonce = nonce;
    record.input_root = object("objective");
    record.operand_root = object("workspace");
    record.capability_set_root = object("capset");
    return record;
}

static struct agent_isa_dispatch_req_enqueue enqueue_for(
    const struct agent_isa_dispatch_record *record, uint32_t slot)
{
    struct agent_isa_dispatch_req_enqueue req;
    memset(&req, 0, sizeof(req));
    req.interface_version = AGENT_ISA_DISPATCH_INTERFACE_VERSION;
    req.slot_index = slot;
    req.ticket_id = record->ticket_id;
    req.authority_epoch = record->authority_epoch;
    req.dispatch_nonce = record->dispatch_nonce;
    agent_isa_dispatch_record_digest(record, &req.submission_digest);
    return req;
}

static struct agent_isa_dispatch_req_complete completion_for(
    const struct agent_isa_dispatch_record *record, uint32_t backend_status)
{
    struct agent_isa_dispatch_req_complete req;
    memset(&req, 0, sizeof(req));
    req.interface_version = AGENT_ISA_DISPATCH_INTERFACE_VERSION;
    req.ticket_id = record->ticket_id;
    req.authority_epoch = record->authority_epoch;
    req.dispatch_nonce = record->dispatch_nonce;
    req.backend_status = backend_status;
    req.result_root = object("result");
    return req;
}

int main(void)
{
    puts("TAP version 14");
    const uint64_t owner = UINT64_C(0x0026000100000042);
    const uint64_t dispatcher = UINT64_C(0x0027000100000001);
    agent_isa_dispatch_mailbox_t mailbox;
    agent_isa_dispatch_init(&mailbox, 7u);

    struct agent_isa_dispatch_record record = record_for(owner, 9u, 7u, 1u);
    struct agent_isa_dispatch_req_enqueue enqueue = enqueue_for(&record, 0u);
    struct agent_isa_dispatch_reply_enqueue reply;
    check(agent_isa_dispatch_enqueue(&mailbox, owner, &record, &enqueue,
                                     &reply) == AGENT_ISA_DISPATCH_OK
              && reply.queue_depth == 1u,
          "owner enqueues a digest-bound semantic ticket");
    check(agent_isa_dispatch_enqueue(&mailbox, owner, &record, &enqueue,
                                     &reply) == AGENT_ISA_DISPATCH_ERR_FULL,
          "occupied mailbox slot provides bounded backpressure");

    struct agent_isa_dispatch_record tampered = record_for(owner, 10u, 7u, 2u);
    struct agent_isa_dispatch_req_enqueue bad = enqueue_for(&tampered, 1u);
    tampered.budget_units++;
    check(agent_isa_dispatch_enqueue(&mailbox, owner, &tampered, &bad, &reply)
              == AGENT_ISA_DISPATCH_ERR_DIGEST,
          "record tampering is rejected by canonical digest");
    bad = enqueue_for(&tampered, 1u);
    check(agent_isa_dispatch_enqueue(&mailbox, owner + 1u, &tampered, &bad,
                                     &reply) == AGENT_ISA_DISPATCH_ERR_OWNER,
          "badge mismatch cannot enqueue another owner's work");
    tampered.authority_epoch = 6u;
    bad = enqueue_for(&tampered, 1u);
    check(agent_isa_dispatch_enqueue(&mailbox, owner, &tampered, &bad, &reply)
              == AGENT_ISA_DISPATCH_ERR_AUTHORITY,
          "stale authority epoch is rejected before dispatch");

    uint32_t slot_index = UINT32_MAX;
    struct agent_isa_dispatch_record taken;
    check(agent_isa_dispatch_take(&mailbox, &slot_index, &taken)
              == AGENT_ISA_DISPATCH_OK
              && slot_index == 0u && taken.ticket_id == 9u,
          "dispatcher atomically claims queued work");
    struct agent_isa_dispatch_req_complete complete = completion_for(
        &record, AGENT_ISA_DISPATCH_BACKEND_OK);
    check(agent_isa_dispatch_complete(&mailbox, owner, dispatcher, &complete)
              == AGENT_ISA_DISPATCH_ERR_FORGED,
          "presentation or owner badge cannot forge completion");
    complete.authority_epoch++;
    check(agent_isa_dispatch_complete(&mailbox, dispatcher, dispatcher,
                                      &complete)
              == AGENT_ISA_DISPATCH_ERR_AUTHORITY,
          "trusted dispatcher cannot complete a stale epoch");
    complete.authority_epoch = record.authority_epoch;
    complete.dispatch_nonce++;
    check(agent_isa_dispatch_complete(&mailbox, dispatcher, dispatcher,
                                      &complete)
              == AGENT_ISA_DISPATCH_ERR_NOT_FOUND,
          "completion nonce binds the exact dispatch attempt");
    complete.dispatch_nonce = record.dispatch_nonce;
    check(agent_isa_dispatch_complete(&mailbox, dispatcher, dispatcher,
                                      &complete) == AGENT_ISA_DISPATCH_OK,
          "trusted dispatcher records one terminal completion");
    check(agent_isa_dispatch_complete(&mailbox, dispatcher, dispatcher,
                                      &complete)
              == AGENT_ISA_DISPATCH_ERR_STATE,
          "terminal completion is exactly once");

    agent_object_id_t result;
    bool success = false;
    check(agent_isa_dispatch_reap(&mailbox, owner + 1u, 9u, &result, &success)
              == AGENT_ISA_DISPATCH_ERR_OWNER,
          "cross-owner terminal result cannot be reaped");
    check(agent_isa_dispatch_reap(&mailbox, owner, 9u, &result, &success)
              == AGENT_ISA_DISPATCH_OK && success
              && agent_object_id_equal(&result, &complete.result_root),
          "owner reaps the immutable backend result");

    record = record_for(owner, 11u, 7u, 3u);
    enqueue = enqueue_for(&record, 0u);
    check(agent_isa_dispatch_enqueue(&mailbox, owner, &record, &enqueue,
                                     &reply) == AGENT_ISA_DISPATCH_OK,
          "freed slot can accept later work");
    struct agent_isa_dispatch_req_cancel cancel = {
        .interface_version = AGENT_ISA_DISPATCH_INTERFACE_VERSION,
        .ticket_id = record.ticket_id,
        .authority_epoch = record.authority_epoch,
        .dispatch_nonce = record.dispatch_nonce,
    };
    check(agent_isa_dispatch_cancel(&mailbox, owner, &cancel)
              == AGENT_ISA_DISPATCH_OK,
          "owner cancels queued work without dispatcher execution");
    check(agent_isa_dispatch_cancel(&mailbox, owner, &cancel)
              == AGENT_ISA_DISPATCH_OK,
          "cancellation is idempotent");
    check(agent_isa_dispatch_reap(&mailbox, owner, 11u, &result, &success)
              == AGENT_ISA_DISPATCH_OK && !success
              && agent_object_id_is_zero(&result),
          "cancelled work reaps without a fabricated result");

    record = record_for(owner, 12u, 7u, 4u);
    enqueue = enqueue_for(&record, 1u);
    check(agent_isa_dispatch_enqueue(&mailbox, owner, &record, &enqueue,
                                     &reply) == AGENT_ISA_DISPATCH_OK,
          "old-epoch work is queued before revocation");
    check(agent_isa_dispatch_update_authority(&mailbox, owner, 8u) == 1u,
          "authority epoch advance cancels outstanding old work");
    check(agent_isa_dispatch_take(&mailbox, &slot_index, &taken)
              == AGENT_ISA_DISPATCH_ERR_NOT_FOUND,
          "revoked work is never dispatched");

    struct agent_isa_dispatch_reply_status status;
    check(agent_isa_dispatch_status(&mailbox, &status)
              == AGENT_ISA_DISPATCH_OK && status.queued == 0u
              && status.running == 0u && status.cancelled == 1u
              && status.authority_epoch == 8u,
          "status exposes bounded queue and authority state");

    agent_isa_dispatch_record_digest(&record, &result);
    agent_object_id_t result2;
    agent_isa_dispatch_record_digest(&record, &result2);
    check(agent_object_id_equal(&result, &result2),
          "canonical record hashing is deterministic");

    printf("1..%u\n", tests);
    return failures == 0u ? 0 : 1;
}
