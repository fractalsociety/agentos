#include "agent_isa_dispatch.h"

#include <stddef.h>

#include "agent_event_emit.h"
#include "agent_isa.h"
#include "sha256_mini.h"

static void zero_bytes(void *dst, uint32_t len)
{
    uint8_t *p = (uint8_t *)dst;
    for (uint32_t i = 0u; i < len; i++) p[i] = 0u;
}

static void put16(uint8_t *dst, uint32_t *offset, uint16_t value)
{
    dst[(*offset)++] = (uint8_t)value;
    dst[(*offset)++] = (uint8_t)(value >> 8u);
}

static void put32(uint8_t *dst, uint32_t *offset, uint32_t value)
{
    dst[(*offset)++] = (uint8_t)value;
    dst[(*offset)++] = (uint8_t)(value >> 8u);
    dst[(*offset)++] = (uint8_t)(value >> 16u);
    dst[(*offset)++] = (uint8_t)(value >> 24u);
}

static void put_id(uint8_t *dst, uint32_t *offset,
                   const agent_object_id_t *id)
{
    for (uint32_t i = 0u; i < 4u; i++) put32(dst, offset, id->word[i]);
}

static uint64_t record_owner(const struct agent_isa_dispatch_record *record)
{
    return (uint64_t)record->owner_badge_low
        | ((uint64_t)record->owner_badge_high << 32u);
}

static bool reserved_zero(const uint32_t *words, uint32_t count)
{
    uint32_t combined = 0u;
    for (uint32_t i = 0u; i < count; i++) combined |= words[i];
    return combined == 0u;
}

static bool record_valid(const struct agent_isa_dispatch_record *record)
{
    if (record == NULL
        || record->interface_version != AGENT_ISA_DISPATCH_INTERFACE_VERSION
        || record->ticket_id == 0u || record->authority_epoch == 0u
        || record->dispatch_nonce == 0u || record->budget_units == 0u
        || record_owner(record) == 0u
        || agent_object_id_is_zero(&record->input_root)
        || agent_object_id_is_zero(&record->capability_set_root))
        return false;
    if (!agent_isa_operation_is_async(record->operation)
        || record->flags != AGENT_ISA_FLAG_ASYNC)
        return false;
    uint32_t required = agent_isa_operation_required_caps(record->operation);
    return required != UINT32_MAX && record->declared_caps == required;
}

void agent_isa_dispatch_record_digest(
    const struct agent_isa_dispatch_record *record,
    agent_object_id_t *out)
{
    if (out == NULL) return;
    if (record == NULL) {
        zero_bytes(out, sizeof(*out));
        return;
    }
    uint8_t canonical[84];
    uint32_t offset = 0u;
    put16(canonical, &offset, record->interface_version);
    put16(canonical, &offset, record->operation);
    put32(canonical, &offset, record->flags);
    put32(canonical, &offset, record->ticket_id);
    put32(canonical, &offset, record->authority_epoch);
    put32(canonical, &offset, record->declared_caps);
    put32(canonical, &offset, record->budget_units);
    put32(canonical, &offset, record->owner_badge_low);
    put32(canonical, &offset, record->owner_badge_high);
    put32(canonical, &offset, record->dispatch_nonce);
    put_id(canonical, &offset, &record->input_root);
    put_id(canonical, &offset, &record->operand_root);
    put_id(canonical, &offset, &record->capability_set_root);
    uint8_t digest[32];
    sha256_mini(canonical, offset, digest);
    for (uint32_t i = 0u; i < 4u; i++) {
        uint32_t base = i * 4u;
        out->word[i] = (uint32_t)digest[base]
            | ((uint32_t)digest[base + 1u] << 8u)
            | ((uint32_t)digest[base + 2u] << 16u)
            | ((uint32_t)digest[base + 3u] << 24u);
    }
}

void agent_isa_dispatch_init(agent_isa_dispatch_mailbox_t *mailbox,
                             uint32_t authority_epoch)
{
    if (mailbox == NULL) return;
    zero_bytes(mailbox, sizeof(*mailbox));
    mailbox->authority_epoch = authority_epoch;
}

uint32_t agent_isa_dispatch_enqueue(
    agent_isa_dispatch_mailbox_t *mailbox, uint64_t caller_badge,
    const struct agent_isa_dispatch_record *record,
    const struct agent_isa_dispatch_req_enqueue *req,
    struct agent_isa_dispatch_reply_enqueue *reply)
{
    if (reply != NULL) zero_bytes(reply, sizeof(*reply));
    if (mailbox == NULL || record == NULL || req == NULL || reply == NULL)
        return AGENT_ISA_DISPATCH_ERR_INVALID;
    if (req->interface_version != AGENT_ISA_DISPATCH_INTERFACE_VERSION)
        return reply->status = AGENT_ISA_DISPATCH_ERR_VERSION;
    if (req->reserved16 != 0u || !reserved_zero(req->reserved, 3u))
        return reply->status = AGENT_ISA_DISPATCH_ERR_INVALID;
    if (req->slot_index >= AGENT_ISA_DISPATCH_MAX_SLOTS)
        return reply->status = AGENT_ISA_DISPATCH_ERR_SLOT;
    if (!record_valid(record))
        return reply->status = AGENT_ISA_DISPATCH_ERR_INVALID;
    if (caller_badge == 0u || record_owner(record) != caller_badge)
        return reply->status = AGENT_ISA_DISPATCH_ERR_OWNER;
    if (record->authority_epoch != mailbox->authority_epoch
        || req->authority_epoch != record->authority_epoch)
        return reply->status = AGENT_ISA_DISPATCH_ERR_AUTHORITY;
    if (req->ticket_id != record->ticket_id
        || req->dispatch_nonce != record->dispatch_nonce)
        return reply->status = AGENT_ISA_DISPATCH_ERR_INVALID;
    agent_object_id_t digest;
    agent_isa_dispatch_record_digest(record, &digest);
    if (!agent_object_id_equal(&digest, &req->submission_digest))
        return reply->status = AGENT_ISA_DISPATCH_ERR_DIGEST;
    struct agent_isa_dispatch_slot *slot = &mailbox->slots[req->slot_index];
    if (slot->state != AGENT_ISA_DISPATCH_SLOT_FREE)
        return reply->status = AGENT_ISA_DISPATCH_ERR_FULL;
    for (uint32_t i = 0u; i < AGENT_ISA_DISPATCH_MAX_SLOTS; i++)
        if (mailbox->slots[i].state != AGENT_ISA_DISPATCH_SLOT_FREE
            && mailbox->slots[i].record.ticket_id == record->ticket_id
            && record_owner(&mailbox->slots[i].record) == caller_badge)
            return reply->status = AGENT_ISA_DISPATCH_ERR_STATE;

    slot->record = *record;
    slot->submission_digest = digest;
    slot->state = AGENT_ISA_DISPATCH_SLOT_QUEUED;
    mailbox->queued++;
    {
        eventbus_event_hash_t scope;
        eventbus_event_hash_t payload;
        uint32_t emit_status;
        agent_event_hash_object_id(record->input_root.word, &scope);
        agent_event_hash_object_id(digest.word, &payload);
        emit_status = agent_event_emit_nested_call(
            record->authority_epoch, -(int32_t)record->budget_units, &scope,
            (const eventbus_event_hash_t *)0, &payload,
            (const eventbus_event_hash_t *)0, (eventbus_event_hash_t *)0);
        if (emit_status != EVENTBUS_AGENT_EVENT_OK) {
            slot->state = AGENT_ISA_DISPATCH_SLOT_FREE;
            zero_bytes(slot, sizeof(*slot));
            mailbox->queued--;
            return reply->status = AGENT_ISA_DISPATCH_ERR_EVENT;
        }
    }
    reply->status = AGENT_ISA_DISPATCH_OK;
    reply->slot_index = req->slot_index;
    reply->queue_depth = mailbox->queued;
    return AGENT_ISA_DISPATCH_OK;
}

uint32_t agent_isa_dispatch_take(agent_isa_dispatch_mailbox_t *mailbox,
                                 uint32_t *slot_index,
                                 struct agent_isa_dispatch_record *record)
{
    if (mailbox == NULL || slot_index == NULL || record == NULL)
        return AGENT_ISA_DISPATCH_ERR_INVALID;
    for (uint32_t i = 0u; i < AGENT_ISA_DISPATCH_MAX_SLOTS; i++) {
        struct agent_isa_dispatch_slot *slot = &mailbox->slots[i];
        if (slot->state != AGENT_ISA_DISPATCH_SLOT_QUEUED) continue;
        slot->state = AGENT_ISA_DISPATCH_SLOT_RUNNING;
        mailbox->queued--;
        mailbox->running++;
        *slot_index = i;
        *record = slot->record;
        return AGENT_ISA_DISPATCH_OK;
    }
    return AGENT_ISA_DISPATCH_ERR_NOT_FOUND;
}

static struct agent_isa_dispatch_slot *find_ticket(
    agent_isa_dispatch_mailbox_t *mailbox, uint32_t ticket_id,
    uint32_t authority_epoch, uint32_t dispatch_nonce)
{
    for (uint32_t i = 0u; i < AGENT_ISA_DISPATCH_MAX_SLOTS; i++) {
        struct agent_isa_dispatch_slot *slot = &mailbox->slots[i];
        if (slot->state != AGENT_ISA_DISPATCH_SLOT_FREE
            && slot->record.ticket_id == ticket_id
            && slot->record.authority_epoch == authority_epoch
            && slot->record.dispatch_nonce == dispatch_nonce)
            return slot;
    }
    return NULL;
}

uint32_t agent_isa_dispatch_complete(
    agent_isa_dispatch_mailbox_t *mailbox, uint64_t caller_badge,
    uint64_t trusted_dispatcher_badge,
    const struct agent_isa_dispatch_req_complete *req)
{
    if (mailbox == NULL || req == NULL || trusted_dispatcher_badge == 0u)
        return AGENT_ISA_DISPATCH_ERR_INVALID;
    if (caller_badge != trusted_dispatcher_badge)
        return AGENT_ISA_DISPATCH_ERR_FORGED;
    if (req->interface_version != AGENT_ISA_DISPATCH_INTERFACE_VERSION)
        return AGENT_ISA_DISPATCH_ERR_VERSION;
    if (req->flags != 0u || !reserved_zero(req->reserved, 3u)
        || req->ticket_id == 0u || req->dispatch_nonce == 0u
        || agent_object_id_is_zero(&req->result_root))
        return AGENT_ISA_DISPATCH_ERR_INVALID;
    if (req->backend_status != AGENT_ISA_DISPATCH_BACKEND_OK
        && req->backend_status != AGENT_ISA_DISPATCH_BACKEND_FAILED)
        return AGENT_ISA_DISPATCH_ERR_BACKEND;
    if (req->authority_epoch != mailbox->authority_epoch)
        return AGENT_ISA_DISPATCH_ERR_AUTHORITY;
    struct agent_isa_dispatch_slot *slot = find_ticket(
        mailbox, req->ticket_id, req->authority_epoch, req->dispatch_nonce);
    if (slot == NULL) return AGENT_ISA_DISPATCH_ERR_NOT_FOUND;
    if (slot->state != AGENT_ISA_DISPATCH_SLOT_RUNNING)
        return AGENT_ISA_DISPATCH_ERR_STATE;
    slot->backend_status = req->backend_status;
    slot->result_root = req->result_root;
    slot->state = req->backend_status == AGENT_ISA_DISPATCH_BACKEND_OK
        ? AGENT_ISA_DISPATCH_SLOT_COMPLETE : AGENT_ISA_DISPATCH_SLOT_FAILED;
    mailbox->running--;
    mailbox->terminal++;
    {
        eventbus_event_hash_t scope;
        eventbus_event_hash_t payload;
        uint32_t emit_status;
        agent_event_hash_object_id(slot->record.input_root.word, &scope);
        agent_event_hash_object_id(req->result_root.word, &payload);
        emit_status = agent_event_emit_effect(
            req->authority_epoch, 0, &scope,
            (const eventbus_event_hash_t *)0, &payload,
            (eventbus_event_hash_t *)0);
        if (emit_status != EVENTBUS_AGENT_EVENT_OK) {
            slot->state = AGENT_ISA_DISPATCH_SLOT_RUNNING;
            mailbox->running++;
            mailbox->terminal--;
            return AGENT_ISA_DISPATCH_ERR_EVENT;
        }
    }
    return AGENT_ISA_DISPATCH_OK;
}

uint32_t agent_isa_dispatch_cancel(
    agent_isa_dispatch_mailbox_t *mailbox, uint64_t caller_badge,
    const struct agent_isa_dispatch_req_cancel *req)
{
    if (mailbox == NULL || req == NULL) return AGENT_ISA_DISPATCH_ERR_INVALID;
    if (req->interface_version != AGENT_ISA_DISPATCH_INTERFACE_VERSION)
        return AGENT_ISA_DISPATCH_ERR_VERSION;
    if (req->reserved16 != 0u || req->reserved != 0u)
        return AGENT_ISA_DISPATCH_ERR_INVALID;
    struct agent_isa_dispatch_slot *slot = find_ticket(
        mailbox, req->ticket_id, req->authority_epoch, req->dispatch_nonce);
    if (slot == NULL) return AGENT_ISA_DISPATCH_ERR_NOT_FOUND;
    if (caller_badge == 0u || record_owner(&slot->record) != caller_badge)
        return AGENT_ISA_DISPATCH_ERR_OWNER;
    if (slot->state == AGENT_ISA_DISPATCH_SLOT_CANCELLED)
        return AGENT_ISA_DISPATCH_OK;
    if (slot->state == AGENT_ISA_DISPATCH_SLOT_QUEUED) mailbox->queued--;
    else if (slot->state == AGENT_ISA_DISPATCH_SLOT_RUNNING) mailbox->running--;
    else return AGENT_ISA_DISPATCH_ERR_STATE;
    slot->state = AGENT_ISA_DISPATCH_SLOT_CANCELLED;
    mailbox->cancelled++;
    return AGENT_ISA_DISPATCH_OK;
}

uint32_t agent_isa_dispatch_update_authority(
    agent_isa_dispatch_mailbox_t *mailbox, uint64_t owner_badge,
    uint32_t new_authority_epoch)
{
    if (mailbox == NULL || owner_badge == 0u
        || new_authority_epoch <= mailbox->authority_epoch)
        return AGENT_ISA_DISPATCH_ERR_AUTHORITY;
    mailbox->authority_epoch = new_authority_epoch;
    uint32_t cancelled = 0u;
    for (uint32_t i = 0u; i < AGENT_ISA_DISPATCH_MAX_SLOTS; i++) {
        struct agent_isa_dispatch_slot *slot = &mailbox->slots[i];
        if (record_owner(&slot->record) != owner_badge
            || slot->record.authority_epoch >= new_authority_epoch)
            continue;
        if (slot->state == AGENT_ISA_DISPATCH_SLOT_QUEUED) mailbox->queued--;
        else if (slot->state == AGENT_ISA_DISPATCH_SLOT_RUNNING)
            mailbox->running--;
        else continue;
        slot->state = AGENT_ISA_DISPATCH_SLOT_CANCELLED;
        mailbox->cancelled++;
        cancelled++;
    }
    return cancelled;
}

uint32_t agent_isa_dispatch_reap(agent_isa_dispatch_mailbox_t *mailbox,
                                 uint64_t owner_badge, uint32_t ticket_id,
                                 agent_object_id_t *result_root,
                                 bool *success)
{
    if (mailbox == NULL || owner_badge == 0u || ticket_id == 0u
        || result_root == NULL || success == NULL)
        return AGENT_ISA_DISPATCH_ERR_INVALID;
    for (uint32_t i = 0u; i < AGENT_ISA_DISPATCH_MAX_SLOTS; i++) {
        struct agent_isa_dispatch_slot *slot = &mailbox->slots[i];
        if (slot->state == AGENT_ISA_DISPATCH_SLOT_FREE
            || slot->record.ticket_id != ticket_id) continue;
        if (record_owner(&slot->record) != owner_badge)
            return AGENT_ISA_DISPATCH_ERR_OWNER;
        if (slot->state == AGENT_ISA_DISPATCH_SLOT_COMPLETE
            || slot->state == AGENT_ISA_DISPATCH_SLOT_FAILED) {
            *result_root = slot->result_root;
            *success = slot->state == AGENT_ISA_DISPATCH_SLOT_COMPLETE;
            mailbox->terminal--;
        } else if (slot->state == AGENT_ISA_DISPATCH_SLOT_CANCELLED) {
            zero_bytes(result_root, sizeof(*result_root));
            *success = false;
            mailbox->cancelled--;
        } else return AGENT_ISA_DISPATCH_ERR_STATE;
        zero_bytes(slot, sizeof(*slot));
        return AGENT_ISA_DISPATCH_OK;
    }
    return AGENT_ISA_DISPATCH_ERR_NOT_FOUND;
}

uint32_t agent_isa_dispatch_status(
    const agent_isa_dispatch_mailbox_t *mailbox,
    struct agent_isa_dispatch_reply_status *reply)
{
    if (mailbox == NULL || reply == NULL) return AGENT_ISA_DISPATCH_ERR_INVALID;
    zero_bytes(reply, sizeof(*reply));
    reply->status = AGENT_ISA_DISPATCH_OK;
    reply->queued = mailbox->queued;
    reply->running = mailbox->running;
    reply->terminal = mailbox->terminal;
    reply->cancelled = mailbox->cancelled;
    reply->capacity = AGENT_ISA_DISPATCH_MAX_SLOTS;
    reply->authority_epoch = mailbox->authority_epoch;
    return AGENT_ISA_DISPATCH_OK;
}
