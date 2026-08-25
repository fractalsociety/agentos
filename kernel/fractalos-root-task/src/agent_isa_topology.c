/*
 * Dispatcher topology host glue (fos-gz0.14.1.3).
 */

#include "agent_isa_topology.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void bytes_zero(void *dst, size_t n)
{
    uint8_t *p = (uint8_t *)dst;
    while (n--) *p++ = 0;
}

void agent_isa_topology_init(agent_isa_topology_t *topo, uint64_t owner_badge,
                             uint64_t dispatcher_badge, uint32_t authority_epoch,
                             uint32_t installed_caps, uint32_t budget_limit,
                             const agent_object_id_t *capset,
                             const agent_object_id_t *environment,
                             const agent_object_id_t *initial_state)
{
    if (topo == NULL)
        return;
    bytes_zero(topo, sizeof(*topo));
    topo->owner_badge = owner_badge;
    topo->dispatcher_badge = dispatcher_badge;
    topo->authority_epoch = authority_epoch == 0u ? 1u : authority_epoch;
    topo->next_nonce = 1u;
    topo->budget_remaining = budget_limit;
    agent_isa_runtime_init(&topo->runtime, installed_caps, topo->authority_epoch,
                           capset, environment, initial_state, budget_limit);
    agent_isa_dispatch_init(&topo->mailbox, topo->authority_epoch);
    agent_isa_adapter_reset();
}

uint32_t agent_isa_topology_install_default_adapters(agent_isa_topology_t *topo)
{
    static const uint32_t classes[] = {
        AGENT_ISA_CAP_CONTROL, AGENT_ISA_CAP_ADMIN, AGENT_ISA_CAP_OBJECT,
        AGENT_ISA_CAP_INFER,   AGENT_ISA_CAP_ACT,   AGENT_ISA_CAP_EVENT,
        AGENT_ISA_CAP_VERIFY,
    };
    static const char *labels[] = {
        "pd-control", "pd-admin", "pd-object", "pd-infer",
        "pd-act", "pd-event", "pd-verify",
    };
    uint32_t i;

    if (topo == NULL)
        return AGENT_ISA_TOPOLOGY_ERR_INVALID;
    for (i = 0u; i < sizeof(classes) / sizeof(classes[0]); i++) {
        struct agent_isa_adapter_req_install req;
        struct agent_isa_adapter_reply_install reply;
        bytes_zero(&req, sizeof(req));
        req.interface_version = AGENT_ISA_ADAPTER_INTERFACE_VERSION;
        agent_isa_object_id_from_bytes(labels[i], (uint32_t)strlen(labels[i]),
                                       &req.endpoint.interface_id);
        req.endpoint.service_class = classes[i];
        req.endpoint.authority_epoch = topo->authority_epoch;
        req.endpoint.budget_ceiling = topo->budget_remaining == 0u
            ? 1u
            : topo->budget_remaining;
        if (agent_isa_adapter_install(&req, &reply) != AGENT_ISA_ADAPTER_OK)
            return AGENT_ISA_TOPOLOGY_ERR_ADAPTER;
    }
    return AGENT_ISA_TOPOLOGY_OK;
}

uint32_t agent_isa_topology_submit_async(
    agent_isa_topology_t *topo, uint16_t operation, uint32_t declared_caps,
    const agent_object_id_t *input_root, const agent_object_id_t *operand_root,
    struct agent_isa_reply_submit *reply)
{
    struct agent_isa_req_submit sreq;
    struct agent_isa_dispatch_record record;
    struct agent_isa_dispatch_req_enqueue ereq;
    struct agent_isa_dispatch_reply_enqueue ereply;
    uint32_t status;
    uint32_t slot;

    if (topo == NULL || reply == NULL || input_root == NULL)
        return AGENT_ISA_TOPOLOGY_ERR_INVALID;
    if (!agent_isa_operation_is_async(operation))
        return AGENT_ISA_TOPOLOGY_ERR_INVALID;
    if (topo->has_pending_dispatch)
        return AGENT_ISA_TOPOLOGY_ERR_STATE;

    bytes_zero(&sreq, sizeof(sreq));
    sreq.interface_version = AGENT_ISA_INTERFACE_VERSION;
    sreq.operation = operation;
    sreq.flags = AGENT_ISA_FLAG_ASYNC;
    sreq.declared_caps = declared_caps;
    sreq.budget_units = 1u;
    sreq.input_root = *input_root;
    if (operand_root != NULL)
        sreq.operand_root = *operand_root;

    status = agent_isa_runtime_submit(&topo->runtime, &sreq, reply);
    if (status != AGENT_ISA_OK)
        return AGENT_ISA_TOPOLOGY_ERR_RUNTIME;
    if (reply->ticket_state != AGENT_ISA_TICKET_PENDING)
        return AGENT_ISA_TOPOLOGY_ERR_STATE;

    bytes_zero(&record, sizeof(record));
    record.interface_version = AGENT_ISA_DISPATCH_INTERFACE_VERSION;
    record.operation = operation;
    record.flags = AGENT_ISA_FLAG_ASYNC;
    record.ticket_id = reply->ticket_id;
    record.authority_epoch = topo->authority_epoch;
    record.declared_caps = declared_caps;
    record.budget_units = 1u;
    record.owner_badge_low = (uint32_t)topo->owner_badge;
    record.owner_badge_high = (uint32_t)(topo->owner_badge >> 32u);
    record.dispatch_nonce = topo->next_nonce++;
    record.input_root = *input_root;
    if (operand_root != NULL)
        record.operand_root = *operand_root;
    record.capability_set_root = topo->runtime.capability_set_root;

    slot = topo->next_slot % AGENT_ISA_DISPATCH_MAX_SLOTS;
    topo->next_slot++;
    bytes_zero(&ereq, sizeof(ereq));
    ereq.interface_version = AGENT_ISA_DISPATCH_INTERFACE_VERSION;
    ereq.slot_index = slot;
    ereq.ticket_id = record.ticket_id;
    ereq.authority_epoch = record.authority_epoch;
    ereq.dispatch_nonce = record.dispatch_nonce;
    agent_isa_dispatch_record_digest(&record, &ereq.submission_digest);

    status = agent_isa_dispatch_enqueue(&topo->mailbox, topo->owner_badge,
                                       &record, &ereq, &ereply);
    if (status != AGENT_ISA_DISPATCH_OK)
        return AGENT_ISA_TOPOLOGY_ERR_DISPATCH;

    topo->pending_ticket = record.ticket_id;
    topo->pending_nonce = record.dispatch_nonce;
    topo->pending_slot = slot;
    topo->has_pending_dispatch = 1;
    /* Critically: return here — lower work not yet pumped. */
    return AGENT_ISA_TOPOLOGY_OK;
}

uint32_t agent_isa_topology_pump(agent_isa_topology_t *topo)
{
    uint32_t slot_index = 0u;
    struct agent_isa_dispatch_record record;
    struct agent_isa_adapter_req_invoke ireq;
    struct agent_isa_adapter_reply_invoke ireply;
    struct agent_isa_dispatch_req_complete creq;
    uint32_t status;

    if (topo == NULL)
        return AGENT_ISA_TOPOLOGY_ERR_INVALID;

    status = agent_isa_dispatch_take(&topo->mailbox, &slot_index, &record);
    if (status == AGENT_ISA_DISPATCH_ERR_NOT_FOUND)
        return AGENT_ISA_TOPOLOGY_ERR_EMPTY;
    if (status != AGENT_ISA_DISPATCH_OK)
        return AGENT_ISA_TOPOLOGY_ERR_DISPATCH;

    bytes_zero(&ireq, sizeof(ireq));
    ireq.interface_version = AGENT_ISA_ADAPTER_INTERFACE_VERSION;
    ireq.record = record;
    ireq.owned_object = record.input_root;
    ireq.caller_budget_remaining = topo->budget_remaining;
    ireq.caller_authority_epoch = topo->authority_epoch;
    status = agent_isa_adapter_invoke(&ireq, &ireply);
    if (status != AGENT_ISA_ADAPTER_OK)
        return AGENT_ISA_TOPOLOGY_ERR_ADAPTER;

    bytes_zero(&creq, sizeof(creq));
    creq.interface_version = AGENT_ISA_DISPATCH_INTERFACE_VERSION;
    creq.ticket_id = record.ticket_id;
    creq.authority_epoch = record.authority_epoch;
    creq.dispatch_nonce = record.dispatch_nonce;
    creq.backend_status = ireply.backend_status;
    creq.result_root = ireply.completion_root;

    /* Forged path is tested separately; pump uses trusted dispatcher badge. */
    status = agent_isa_dispatch_complete(&topo->mailbox, topo->dispatcher_badge,
                                         topo->dispatcher_badge, &creq);
    if (status != AGENT_ISA_DISPATCH_OK)
        return AGENT_ISA_TOPOLOGY_ERR_DISPATCH;

    status = agent_isa_runtime_complete(&topo->runtime, record.ticket_id,
                                        &ireply.completion_root,
                                        ireply.backend_status
                                            == AGENT_ISA_DISPATCH_BACKEND_OK);
    if (status != AGENT_ISA_OK)
        return AGENT_ISA_TOPOLOGY_ERR_RUNTIME;

    if (topo->has_pending_dispatch
        && topo->pending_ticket == record.ticket_id)
        topo->has_pending_dispatch = 0;
    return AGENT_ISA_TOPOLOGY_OK;
}

uint32_t agent_isa_topology_wait(agent_isa_topology_t *topo, uint32_t ticket_id,
                                 struct agent_isa_reply_wait *reply)
{
    struct agent_isa_req_wait wreq;

    if (topo == NULL || reply == NULL)
        return AGENT_ISA_TOPOLOGY_ERR_INVALID;
    bytes_zero(&wreq, sizeof(wreq));
    wreq.interface_version = AGENT_ISA_INTERFACE_VERSION;
    wreq.ticket_id = ticket_id;
    if (agent_isa_runtime_wait(&topo->runtime, &wreq, reply) != AGENT_ISA_OK)
        return AGENT_ISA_TOPOLOGY_ERR_RUNTIME;
    return AGENT_ISA_TOPOLOGY_OK;
}

uint32_t agent_isa_topology_revoke(agent_isa_topology_t *topo)
{
    uint32_t new_epoch;
    agent_object_id_t capset;

    if (topo == NULL)
        return AGENT_ISA_TOPOLOGY_ERR_INVALID;
    new_epoch = topo->authority_epoch + 1u;
    (void)agent_isa_dispatch_update_authority(&topo->mailbox, topo->owner_badge,
                                              new_epoch);
    capset = topo->runtime.capability_set_root;
    if (agent_isa_runtime_update_authority(&topo->runtime,
                                           topo->runtime.installed_caps,
                                           new_epoch, &capset)
        != AGENT_ISA_OK)
        return AGENT_ISA_TOPOLOGY_ERR_RUNTIME;
    topo->authority_epoch = new_epoch;
    if (topo->has_pending_dispatch) {
        struct agent_isa_req_cancel creq;
        bytes_zero(&creq, sizeof(creq));
        creq.interface_version = AGENT_ISA_INTERFACE_VERSION;
        creq.ticket_id = topo->pending_ticket;
        (void)agent_isa_runtime_cancel(&topo->runtime, &creq);
        topo->has_pending_dispatch = 0;
    }
    /* Re-install adapters at the new epoch so future work can proceed. */
    return agent_isa_topology_install_default_adapters(topo);
}
