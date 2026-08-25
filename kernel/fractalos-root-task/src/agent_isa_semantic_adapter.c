/*
 * Semantic adapters: ISA ops → capability-selected PD endpoints (no names).
 * fos-gz0.14.1.2
 */

#include "agent_isa_semantic_adapter.h"

#include "agent_event_emit.h"
#include "agent_isa.h"

#include <stddef.h>
#include <stdint.h>

struct adapter_slot {
    int used;
    struct agent_isa_adapter_endpoint endpoint;
};

static struct {
    uint32_t authority_epoch;
    struct adapter_slot slots[AGENT_ISA_ADAPTER_MAX_ENDPOINTS];
} g_adapter;

static void bytes_zero(void *dst, size_t n)
{
    uint8_t *p = (uint8_t *)dst;
    while (n--) *p++ = 0;
}

static int id_zero(const agent_object_id_t *id)
{
    return id->word[0] == 0u && id->word[1] == 0u && id->word[2] == 0u
        && id->word[3] == 0u;
}

static int id_eq(const agent_object_id_t *a, const agent_object_id_t *b)
{
    return a->word[0] == b->word[0] && a->word[1] == b->word[1]
        && a->word[2] == b->word[2] && a->word[3] == b->word[3];
}

static int single_cap_bit(uint32_t mask)
{
    return mask != 0u && (mask & (mask - 1u)) == 0u
        && (mask & AGENT_ISA_CAP_KNOWN_MASK) == mask;
}

uint32_t agent_isa_adapter_service_class_for_op(uint16_t operation)
{
    switch (operation) {
    case AGENT_ISA_OP_SPAWN:
    case AGENT_ISA_OP_DELEGATE:
        return AGENT_ISA_CAP_CONTROL;
    case AGENT_ISA_OP_CAP_GRANT:
    case AGENT_ISA_OP_CAP_REVOKE:
        return AGENT_ISA_CAP_ADMIN;
    case AGENT_ISA_OP_OBJECT_GET:
    case AGENT_ISA_OP_OBJECT_PUT:
    case AGENT_ISA_OP_OBJECT_QUERY:
        return AGENT_ISA_CAP_OBJECT;
    case AGENT_ISA_OP_INFER:
        return AGENT_ISA_CAP_INFER;
    case AGENT_ISA_OP_ACT:
        return AGENT_ISA_CAP_ACT;
    case AGENT_ISA_OP_EMIT:
        return AGENT_ISA_CAP_EVENT;
    case AGENT_ISA_OP_VERIFY:
        return AGENT_ISA_CAP_VERIFY;
    default:
        return 0u;
    }
}

void agent_isa_adapter_reset(void)
{
    bytes_zero(&g_adapter, sizeof(g_adapter));
    g_adapter.authority_epoch = 1u;
}

uint32_t agent_isa_adapter_install(
    const struct agent_isa_adapter_req_install *req,
    struct agent_isa_adapter_reply_install *reply)
{
    uint32_t i;

    if (reply == NULL)
        return AGENT_ISA_ADAPTER_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL
        || req->interface_version != AGENT_ISA_ADAPTER_INTERFACE_VERSION) {
        reply->status = AGENT_ISA_ADAPTER_ERR_VERSION;
        return reply->status;
    }
    if (id_zero(&req->endpoint.interface_id)
        || !single_cap_bit(req->endpoint.service_class)
        || req->endpoint.authority_epoch == 0u
        || req->endpoint.budget_ceiling == 0u) {
        reply->status = AGENT_ISA_ADAPTER_ERR_INVALID;
        return reply->status;
    }

    for (i = 0u; i < AGENT_ISA_ADAPTER_MAX_ENDPOINTS; i++) {
        if (g_adapter.slots[i].used
            && g_adapter.slots[i].endpoint.service_class
                   == req->endpoint.service_class) {
            /* Replace endpoint for this class (versioned seam). */
            g_adapter.slots[i].endpoint = req->endpoint;
            g_adapter.authority_epoch = req->endpoint.authority_epoch;
            reply->status = AGENT_ISA_ADAPTER_OK;
            reply->endpoint_slot = i;
            return AGENT_ISA_ADAPTER_OK;
        }
    }
    for (i = 0u; i < AGENT_ISA_ADAPTER_MAX_ENDPOINTS; i++) {
        if (!g_adapter.slots[i].used) {
            g_adapter.slots[i].used = 1;
            g_adapter.slots[i].endpoint = req->endpoint;
            g_adapter.authority_epoch = req->endpoint.authority_epoch;
            reply->status = AGENT_ISA_ADAPTER_OK;
            reply->endpoint_slot = i;
            return AGENT_ISA_ADAPTER_OK;
        }
    }
    reply->status = AGENT_ISA_ADAPTER_ERR_FULL;
    return reply->status;
}

static struct adapter_slot *find_by_class(uint32_t service_class)
{
    for (uint32_t i = 0u; i < AGENT_ISA_ADAPTER_MAX_ENDPOINTS; i++)
        if (g_adapter.slots[i].used
            && g_adapter.slots[i].endpoint.service_class == service_class)
            return &g_adapter.slots[i];
    return NULL;
}

uint32_t agent_isa_adapter_invoke(
    const struct agent_isa_adapter_req_invoke *req,
    struct agent_isa_adapter_reply_invoke *reply)
{
    struct adapter_slot *slot;
    uint32_t want_class;
    agent_object_id_t completion;

    if (reply == NULL)
        return AGENT_ISA_ADAPTER_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL
        || req->interface_version != AGENT_ISA_ADAPTER_INTERFACE_VERSION) {
        reply->status = AGENT_ISA_ADAPTER_ERR_VERSION;
        return reply->status;
    }

    want_class = agent_isa_adapter_service_class_for_op(req->record.operation);
    if (want_class == 0u
        || !agent_isa_operation_is_async(req->record.operation)) {
        reply->status = AGENT_ISA_ADAPTER_ERR_INVALID;
        return reply->status;
    }
    if (req->record.declared_caps != want_class) {
        reply->status = AGENT_ISA_ADAPTER_ERR_WRONG_CLASS;
        return reply->status;
    }
    if (req->caller_authority_epoch == 0u
        || req->caller_authority_epoch != req->record.authority_epoch
        || req->record.authority_epoch != g_adapter.authority_epoch) {
        reply->status = AGENT_ISA_ADAPTER_ERR_AUTHORITY;
        return reply->status;
    }
    if (req->record.budget_units == 0u
        || req->caller_budget_remaining < req->record.budget_units) {
        reply->status = AGENT_ISA_ADAPTER_ERR_BUDGET;
        return reply->status;
    }
    if (id_zero(&req->record.input_root)
        || id_zero(&req->owned_object)
        || !id_eq(&req->record.input_root, &req->owned_object)) {
        reply->status = AGENT_ISA_ADAPTER_ERR_OWNERSHIP;
        return reply->status;
    }

    slot = find_by_class(want_class);
    if (slot == NULL) {
        reply->status = AGENT_ISA_ADAPTER_ERR_NO_ENDPOINT;
        return reply->status;
    }
    if (slot->endpoint.authority_epoch != req->record.authority_epoch) {
        reply->status = AGENT_ISA_ADAPTER_ERR_AUTHORITY;
        return reply->status;
    }
    if (req->record.budget_units > slot->endpoint.budget_ceiling) {
        reply->status = AGENT_ISA_ADAPTER_ERR_BUDGET;
        return reply->status;
    }

    /* Immutable completion: hash of interface + ticket + input (no names). */
    {
        uint32_t words[12];
        eventbus_event_hash_t scope;
        eventbus_event_hash_t payload;
        eventbus_event_hash_t evidence;
        uint32_t emit_status;

        words[0] = slot->endpoint.interface_id.word[0];
        words[1] = slot->endpoint.interface_id.word[1];
        words[2] = slot->endpoint.interface_id.word[2];
        words[3] = slot->endpoint.interface_id.word[3];
        words[4] = req->record.ticket_id;
        words[5] = req->record.operation;
        words[6] = req->record.input_root.word[0];
        words[7] = req->record.input_root.word[1];
        words[8] = req->record.input_root.word[2];
        words[9] = req->record.input_root.word[3];
        words[10] = req->record.dispatch_nonce;
        words[11] = want_class;
        agent_isa_object_id_from_bytes(words, (uint32_t)sizeof(words),
                                       &completion);

        /* No DAG transition without a stream event. */
        agent_event_hash_object_id(req->record.input_root.word, &scope);
        agent_event_hash_object_id(completion.word, &payload);
        agent_event_hash_object_id(slot->endpoint.interface_id.word, &evidence);
        emit_status = agent_event_emit_nested_call(
            req->record.authority_epoch,
            -(int32_t)req->record.budget_units, &scope,
            (const eventbus_event_hash_t *)0, &payload, &evidence,
            (eventbus_event_hash_t *)0);
        if (emit_status != EVENTBUS_AGENT_EVENT_OK) {
            bytes_zero(reply, sizeof(*reply));
            reply->status = AGENT_ISA_ADAPTER_ERR_EVENT;
            return reply->status;
        }
    }

    reply->status = AGENT_ISA_ADAPTER_OK;
    reply->service_class_selected = want_class;
    reply->interface_id_selected = slot->endpoint.interface_id;
    reply->completion_root = completion;
    reply->backend_status = AGENT_ISA_DISPATCH_BACKEND_OK;
    return AGENT_ISA_ADAPTER_OK;
}

uint32_t agent_isa_adapter_status(
    const struct agent_isa_adapter_req_status *req,
    struct agent_isa_adapter_reply_status *reply)
{
    uint32_t n = 0u;

    if (reply == NULL)
        return AGENT_ISA_ADAPTER_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL
        || req->interface_version != AGENT_ISA_ADAPTER_INTERFACE_VERSION) {
        reply->status = AGENT_ISA_ADAPTER_ERR_VERSION;
        return reply->status;
    }
    for (uint32_t i = 0u; i < AGENT_ISA_ADAPTER_MAX_ENDPOINTS; i++)
        if (g_adapter.slots[i].used)
            n++;
    reply->status = AGENT_ISA_ADAPTER_OK;
    reply->endpoint_count = n;
    reply->authority_epoch = g_adapter.authority_epoch;
    return AGENT_ISA_ADAPTER_OK;
}
