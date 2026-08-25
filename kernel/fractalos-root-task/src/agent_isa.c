#include "agent_isa.h"
#include "sha256_mini.h"

#include <stddef.h>

#define AGENT_EXECUTION_NODE_CANONICAL_BYTES 160u
#define AGENT_STATE_TRANSITION_BYTES         128u

static void bytes_zero(void *dst_ptr, uint32_t len)
{
    uint8_t *dst = (uint8_t *)dst_ptr;
    for (uint32_t i = 0u; i < len; i++) dst[i] = 0u;
}

static void id_zero(agent_object_id_t *id)
{
    if (id != NULL) bytes_zero(id, sizeof(*id));
}

static void id_copy(agent_object_id_t *dst, const agent_object_id_t *src)
{
    if (dst == NULL) return;
    if (src == NULL) id_zero(dst);
    else for (uint32_t i = 0u; i < 4u; i++) dst->word[i] = src->word[i];
}

static void put16(uint8_t *out, uint32_t *offset, uint16_t value)
{
    out[(*offset)++] = (uint8_t)value;
    out[(*offset)++] = (uint8_t)(value >> 8u);
}

static void put32(uint8_t *out, uint32_t *offset, uint32_t value)
{
    for (uint32_t i = 0u; i < 4u; i++)
        out[(*offset)++] = (uint8_t)(value >> (i * 8u));
}

static void put_id(uint8_t *out, uint32_t *offset,
                   const agent_object_id_t *id)
{
    for (uint32_t i = 0u; i < 4u; i++) put32(out, offset, id->word[i]);
}

static void digest_to_id(const uint8_t digest[32], agent_object_id_t *out)
{
    for (uint32_t i = 0u; i < 4u; i++) {
        uint32_t base = i * 4u;
        out->word[i] = ((uint32_t)digest[base] << 24u)
            | ((uint32_t)digest[base + 1u] << 16u)
            | ((uint32_t)digest[base + 2u] << 8u)
            | (uint32_t)digest[base + 3u];
    }
}

void agent_isa_object_id_from_bytes(const void *data, uint32_t len,
                                    agent_object_id_t *out)
{
    if (out == NULL) return;
    if (data == NULL && len != 0u) {
        id_zero(out);
        return;
    }
    uint8_t digest[32];
    sha256_mini((const uint8_t *)data, len, digest);
    digest_to_id(digest, out);
}

bool agent_isa_operation_is_async(uint16_t operation)
{
    switch (operation) {
    case AGENT_ISA_OP_SPAWN:
    case AGENT_ISA_OP_DELEGATE:
    case AGENT_ISA_OP_CAP_GRANT:
    case AGENT_ISA_OP_CAP_REVOKE:
    case AGENT_ISA_OP_OBJECT_GET:
    case AGENT_ISA_OP_OBJECT_PUT:
    case AGENT_ISA_OP_OBJECT_QUERY:
    case AGENT_ISA_OP_INFER:
    case AGENT_ISA_OP_ACT:
    case AGENT_ISA_OP_EMIT:
    case AGENT_ISA_OP_VERIFY:
        return true;
    default:
        return false;
    }
}

uint32_t agent_isa_operation_required_caps(uint16_t operation)
{
    switch (operation) {
    case AGENT_ISA_OP_SPAWN:
    case AGENT_ISA_OP_DELEGATE:
    case AGENT_ISA_OP_TERMINATE:
        return AGENT_ISA_CAP_CONTROL;
    case AGENT_ISA_OP_CAP_GRANT:
    case AGENT_ISA_OP_CAP_REVOKE:
        return AGENT_ISA_CAP_ADMIN;
    case AGENT_ISA_OP_OBJECT_GET:
    case AGENT_ISA_OP_OBJECT_PUT:
    case AGENT_ISA_OP_OBJECT_QUERY:
    case AGENT_ISA_OP_CHECKPOINT:
    case AGENT_ISA_OP_RESTORE:
        return AGENT_ISA_CAP_OBJECT;
    case AGENT_ISA_OP_INFER:
        return AGENT_ISA_CAP_INFER;
    case AGENT_ISA_OP_ACT:
        return AGENT_ISA_CAP_ACT;
    case AGENT_ISA_OP_EMIT:
        return AGENT_ISA_CAP_EVENT;
    case AGENT_ISA_OP_VERIFY:
        return AGENT_ISA_CAP_VERIFY;
    case AGENT_ISA_OP_COMMIT:
        return AGENT_ISA_CAP_COMMIT;
    case AGENT_ISA_OP_TRACE:
        return AGENT_ISA_CAP_TRACE;
    case AGENT_ISA_OP_BUDGET:
        return AGENT_ISA_CAP_BUDGET;
    case AGENT_ISA_OP_WAIT:
        return 0u;
    default:
        return UINT32_MAX;
    }
}

void agent_isa_execution_node_hash(const struct agent_execution_node *node,
                                   agent_object_id_t *out)
{
    if (out == NULL) return;
    if (node == NULL) {
        id_zero(out);
        return;
    }
    uint8_t canonical[AGENT_EXECUTION_NODE_CANONICAL_BYTES];
    uint32_t offset = 0u;
    put16(canonical, &offset, node->interface_version);
    put16(canonical, &offset, node->operation);
    put32(canonical, &offset, node->ticket_state);
    put32(canonical, &offset, node->flags);
    put32(canonical, &offset, node->ticket_id);
    put32(canonical, &offset, node->sequence);
    put32(canonical, &offset, node->declared_caps);
    put32(canonical, &offset, node->budget_units);
    put32(canonical, &offset, node->authority_epoch);
    put_id(canonical, &offset, &node->parent_root);
    put_id(canonical, &offset, &node->previous_state_root);
    put_id(canonical, &offset, &node->input_root);
    put_id(canonical, &offset, &node->operand_root);
    put_id(canonical, &offset, &node->capability_set_root);
    put_id(canonical, &offset, &node->environment_root);
    put_id(canonical, &offset, &node->result_root);
    put_id(canonical, &offset, &node->result_state_root);
    if (offset != sizeof(canonical)) {
        id_zero(out);
        return;
    }
    agent_isa_object_id_from_bytes(canonical, sizeof(canonical), out);
}

static void derive_state(const struct agent_isa_runtime *runtime,
                         const struct agent_isa_ticket_record *ticket,
                         const agent_object_id_t *result_root,
                         agent_object_id_t *out)
{
    uint8_t canonical[AGENT_STATE_TRANSITION_BYTES];
    uint32_t offset = 0u;
    put16(canonical, &offset, AGENT_ISA_INTERFACE_VERSION);
    put16(canonical, &offset, ticket->operation);
    put32(canonical, &offset, ticket->flags);
    put32(canonical, &offset, ticket->declared_caps);
    put32(canonical, &offset, ticket->budget_units);
    put32(canonical, &offset, runtime->authority_epoch);
    put_id(canonical, &offset, &ticket->previous_state_root);
    put_id(canonical, &offset, &ticket->input_root);
    put_id(canonical, &offset, &ticket->operand_root);
    put_id(canonical, &offset, &runtime->capability_set_root);
    put_id(canonical, &offset, &runtime->environment_root);
    put_id(canonical, &offset, result_root);
    while (offset < sizeof(canonical)) canonical[offset++] = 0u;
    agent_isa_object_id_from_bytes(canonical, sizeof(canonical), out);
}

static void fill_submit_error(const struct agent_isa_runtime *runtime,
                              struct agent_isa_reply_submit *reply,
                              uint32_t status)
{
    bytes_zero(reply, sizeof(*reply));
    reply->status = status;
    if (runtime != NULL) {
        reply->authority_epoch = runtime->authority_epoch;
        id_copy(&reply->state_root, &runtime->state_root);
    }
}

static agent_object_id_t record_node(agent_isa_runtime_t *runtime,
                                     struct agent_execution_node *node)
{
    agent_object_id_t root;
    node->sequence = ++runtime->next_sequence;
    agent_isa_execution_node_hash(node, &root);
    runtime->trace[runtime->trace_head] = *node;
    runtime->trace_head = (runtime->trace_head + 1u)
        % AGENT_ISA_MAX_TRACE_NODES;
    if (runtime->trace_count < AGENT_ISA_MAX_TRACE_NODES)
        runtime->trace_count++;
    id_copy(&runtime->execution_head_root, &root);
    return root;
}

void agent_isa_runtime_init(agent_isa_runtime_t *runtime,
                            uint32_t installed_caps,
                            uint32_t authority_epoch,
                            const agent_object_id_t *capability_set_root,
                            const agent_object_id_t *environment_root,
                            const agent_object_id_t *initial_state_root,
                            uint32_t budget_limit)
{
    if (runtime == NULL) return;
    bytes_zero(runtime, sizeof(*runtime));
    runtime->installed_caps = installed_caps & AGENT_ISA_CAP_KNOWN_MASK;
    runtime->authority_epoch = authority_epoch;
    runtime->budget_limit = budget_limit <= AGENT_ISA_MAX_BUDGET_UNITS
        ? budget_limit : AGENT_ISA_MAX_BUDGET_UNITS;
    id_copy(&runtime->capability_set_root, capability_set_root);
    id_copy(&runtime->environment_root, environment_root);
    id_copy(&runtime->state_root, initial_state_root);
}

uint32_t agent_isa_runtime_update_authority(
    agent_isa_runtime_t *runtime, uint32_t installed_caps,
    uint32_t authority_epoch, const agent_object_id_t *capability_set_root)
{
    if (runtime == NULL || capability_set_root == NULL
        || agent_object_id_is_zero(capability_set_root)
        || (installed_caps & ~AGENT_ISA_CAP_KNOWN_MASK) != 0u
        || authority_epoch != runtime->authority_epoch + 1u)
        return AGENT_ISA_ERR_INVALID;
    runtime->installed_caps = installed_caps;
    runtime->authority_epoch = authority_epoch;
    id_copy(&runtime->capability_set_root, capability_set_root);
    return AGENT_ISA_OK;
}

static bool operation_objects_valid(const struct agent_isa_req_submit *req)
{
    bool input = !agent_object_id_is_zero(&req->input_root);
    bool operand = !agent_object_id_is_zero(&req->operand_root);
    switch (req->operation) {
    case AGENT_ISA_OP_SPAWN:
    case AGENT_ISA_OP_DELEGATE:
    case AGENT_ISA_OP_CAP_GRANT:
    case AGENT_ISA_OP_CAP_REVOKE:
    case AGENT_ISA_OP_ACT:
    case AGENT_ISA_OP_VERIFY:
        return input && operand;
    case AGENT_ISA_OP_OBJECT_GET:
    case AGENT_ISA_OP_OBJECT_PUT:
    case AGENT_ISA_OP_OBJECT_QUERY:
    case AGENT_ISA_OP_INFER:
    case AGENT_ISA_OP_EMIT:
    case AGENT_ISA_OP_RESTORE:
    case AGENT_ISA_OP_BUDGET:
        return input;
    case AGENT_ISA_OP_COMMIT:
        return input && operand;
    case AGENT_ISA_OP_CHECKPOINT:
    case AGENT_ISA_OP_TERMINATE:
        return !input && !operand;
    default:
        return false;
    }
}

static struct agent_isa_ticket_record *find_ticket(
    agent_isa_runtime_t *runtime, uint32_t ticket_id)
{
    for (uint32_t i = 0u; i < AGENT_ISA_MAX_TICKETS; i++)
        if (runtime->tickets[i].ticket_state != AGENT_ISA_TICKET_FREE
            && runtime->tickets[i].ticket_id == ticket_id)
            return &runtime->tickets[i];
    return NULL;
}

static struct agent_isa_ticket_record *allocate_ticket(
    agent_isa_runtime_t *runtime)
{
    for (uint32_t i = 0u; i < AGENT_ISA_MAX_TICKETS; i++)
        if (runtime->tickets[i].ticket_state == AGENT_ISA_TICKET_FREE)
            return &runtime->tickets[i];
    return NULL;
}

static uint32_t next_ticket_id(agent_isa_runtime_t *runtime)
{
    do {
        runtime->next_ticket_id++;
        if (runtime->next_ticket_id == 0u) runtime->next_ticket_id++;
    } while (find_ticket(runtime, runtime->next_ticket_id) != NULL);
    return runtime->next_ticket_id;
}

static void node_from_ticket(const agent_isa_runtime_t *runtime,
                             const struct agent_isa_ticket_record *ticket,
                             struct agent_execution_node *node)
{
    bytes_zero(node, sizeof(*node));
    node->interface_version = AGENT_ISA_INTERFACE_VERSION;
    node->operation = ticket->operation;
    node->ticket_state = ticket->ticket_state;
    node->flags = ticket->flags;
    node->ticket_id = ticket->ticket_id;
    node->declared_caps = ticket->declared_caps;
    node->budget_units = ticket->budget_units;
    node->authority_epoch = runtime->authority_epoch;
    id_copy(&node->previous_state_root, &ticket->previous_state_root);
    id_copy(&node->input_root, &ticket->input_root);
    id_copy(&node->operand_root, &ticket->operand_root);
    id_copy(&node->capability_set_root, &runtime->capability_set_root);
    id_copy(&node->environment_root, &runtime->environment_root);
}

static uint32_t immediate_submit(agent_isa_runtime_t *runtime,
                                 const struct agent_isa_req_submit *req,
                                 struct agent_isa_reply_submit *reply)
{
    struct agent_isa_ticket_record ticket;
    bytes_zero(&ticket, sizeof(ticket));
    ticket.ticket_state = AGENT_ISA_TICKET_COMPLETE;
    ticket.operation = req->operation;
    ticket.flags = req->flags;
    ticket.declared_caps = req->declared_caps;
    ticket.budget_units = req->budget_units;
    id_copy(&ticket.previous_state_root, &runtime->state_root);
    id_copy(&ticket.input_root, &req->input_root);
    id_copy(&ticket.operand_root, &req->operand_root);

    struct agent_execution_node node;
    node_from_ticket(runtime, &ticket, &node);
    id_copy(&node.parent_root, &runtime->execution_head_root);

    if (req->operation == AGENT_ISA_OP_CHECKPOINT) {
        id_copy(&node.result_root, &runtime->state_root);
        id_copy(&node.result_state_root, &runtime->state_root);
    } else if (req->operation == AGENT_ISA_OP_RESTORE
               || req->operation == AGENT_ISA_OP_COMMIT) {
        id_copy(&node.result_root, &req->input_root);
        id_copy(&runtime->state_root, &req->input_root);
        id_copy(&node.result_state_root, &runtime->state_root);
        runtime->verification_ready = false;
        id_zero(&runtime->verified_input_root);
        id_zero(&runtime->verification_evidence_root);
    } else if (req->operation == AGENT_ISA_OP_TERMINATE) {
        id_copy(&node.result_state_root, &runtime->state_root);
        runtime->terminated = true;
    } else {
        id_copy(&node.result_root, &req->input_root);
        derive_state(runtime, &ticket, &node.result_root,
                     &node.result_state_root);
        id_copy(&runtime->state_root, &node.result_state_root);
    }

    agent_object_id_t node_root = record_node(runtime, &node);
    bytes_zero(reply, sizeof(*reply));
    reply->status = AGENT_ISA_OK;
    reply->ticket_state = AGENT_ISA_TICKET_COMPLETE;
    reply->authority_epoch = runtime->authority_epoch;
    id_copy(&reply->execution_node, &node_root);
    id_copy(&reply->state_root, &runtime->state_root);
    return AGENT_ISA_OK;
}

uint32_t agent_isa_runtime_submit(
    agent_isa_runtime_t *runtime,
    const struct agent_isa_req_submit *req,
    struct agent_isa_reply_submit *reply)
{
    if (runtime == NULL || reply == NULL) return AGENT_ISA_ERR_INVALID;
    if (req == NULL) {
        fill_submit_error(runtime, reply, AGENT_ISA_ERR_INVALID);
        return AGENT_ISA_ERR_INVALID;
    }
    if (runtime->terminated) {
        fill_submit_error(runtime, reply, AGENT_ISA_ERR_TERMINATED);
        return AGENT_ISA_ERR_TERMINATED;
    }
    if (req->interface_version != AGENT_ISA_INTERFACE_VERSION) {
        fill_submit_error(runtime, reply, AGENT_ISA_ERR_VERSION);
        return AGENT_ISA_ERR_VERSION;
    }
    uint32_t required = agent_isa_operation_required_caps(req->operation);
    if (required == UINT32_MAX || req->operation == AGENT_ISA_OP_WAIT
        || req->operation == AGENT_ISA_OP_TRACE) {
        fill_submit_error(runtime, reply, AGENT_ISA_ERR_OPERATION);
        return AGENT_ISA_ERR_OPERATION;
    }
    bool async = agent_isa_operation_is_async(req->operation);
    if ((req->flags & ~AGENT_ISA_FLAG_KNOWN_MASK) != 0u
        || ((req->flags & AGENT_ISA_FLAG_ASYNC) != 0u) != async) {
        fill_submit_error(runtime, reply, AGENT_ISA_ERR_FLAGS);
        return AGENT_ISA_ERR_FLAGS;
    }
    if (!operation_objects_valid(req)) {
        fill_submit_error(runtime, reply, AGENT_ISA_ERR_OBJECT);
        return AGENT_ISA_ERR_OBJECT;
    }
    if ((req->declared_caps & ~AGENT_ISA_CAP_KNOWN_MASK) != 0u
        || req->declared_caps != required
        || (required & ~runtime->installed_caps) != 0u) {
        fill_submit_error(runtime, reply, AGENT_ISA_ERR_CAP_DENIED);
        return AGENT_ISA_ERR_CAP_DENIED;
    }
    if (req->budget_units == 0u
        || req->budget_units > AGENT_ISA_MAX_BUDGET_UNITS
        || runtime->budget_used > runtime->budget_limit
        || req->budget_units > runtime->budget_limit - runtime->budget_used) {
        fill_submit_error(runtime, reply, AGENT_ISA_ERR_BUDGET);
        return AGENT_ISA_ERR_BUDGET;
    }
    if (req->operation == AGENT_ISA_OP_COMMIT
        && (!runtime->verification_ready
            || !agent_object_id_equal(&req->input_root,
                                      &runtime->verified_input_root)
            || !agent_object_id_equal(&req->operand_root,
                                      &runtime->verification_evidence_root))) {
        fill_submit_error(runtime, reply, AGENT_ISA_ERR_STATE);
        return AGENT_ISA_ERR_STATE;
    }

    struct agent_isa_ticket_record *ticket = NULL;
    if (async) {
        ticket = allocate_ticket(runtime);
        if (ticket == NULL) {
            fill_submit_error(runtime, reply,
                              AGENT_ISA_ERR_TICKET_EXHAUSTED);
            return AGENT_ISA_ERR_TICKET_EXHAUSTED;
        }
    }
    runtime->budget_used += req->budget_units;
    if (!async) return immediate_submit(runtime, req, reply);

    bytes_zero(ticket, sizeof(*ticket));
    ticket->ticket_id = next_ticket_id(runtime);
    ticket->ticket_state = AGENT_ISA_TICKET_PENDING;
    ticket->operation = req->operation;
    ticket->flags = req->flags;
    ticket->declared_caps = req->declared_caps;
    ticket->budget_units = req->budget_units;
    id_copy(&ticket->previous_state_root, &runtime->state_root);
    id_copy(&ticket->input_root, &req->input_root);
    id_copy(&ticket->operand_root, &req->operand_root);

    struct agent_execution_node node;
    node_from_ticket(runtime, ticket, &node);
    id_copy(&node.parent_root, &runtime->execution_head_root);
    id_copy(&node.result_state_root, &runtime->state_root);
    agent_object_id_t node_root = record_node(runtime, &node);
    id_copy(&ticket->submit_node_root, &node_root);

    bytes_zero(reply, sizeof(*reply));
    reply->status = AGENT_ISA_OK;
    reply->ticket_id = ticket->ticket_id;
    reply->ticket_state = ticket->ticket_state;
    reply->authority_epoch = runtime->authority_epoch;
    id_copy(&reply->execution_node, &node_root);
    id_copy(&reply->state_root, &runtime->state_root);
    return AGENT_ISA_OK;
}

uint32_t agent_isa_runtime_complete(agent_isa_runtime_t *runtime,
                                    uint32_t ticket_id,
                                    const agent_object_id_t *result_root,
                                    bool success)
{
    if (runtime == NULL || ticket_id == 0u || result_root == NULL
        || agent_object_id_is_zero(result_root)) return AGENT_ISA_ERR_INVALID;
    struct agent_isa_ticket_record *ticket = find_ticket(runtime, ticket_id);
    if (ticket == NULL) return AGENT_ISA_ERR_NOT_FOUND;
    if (ticket->ticket_state != AGENT_ISA_TICKET_PENDING)
        return AGENT_ISA_ERR_STATE;

    bool conflict = success
        && !agent_object_id_equal(&runtime->state_root,
                                  &ticket->previous_state_root);
    ticket->ticket_state = conflict ? AGENT_ISA_TICKET_CONFLICT
        : success ? AGENT_ISA_TICKET_COMPLETE : AGENT_ISA_TICKET_FAILED;
    id_copy(&ticket->result_root, result_root);

    struct agent_execution_node node;
    node_from_ticket(runtime, ticket, &node);
    id_copy(&node.parent_root, &ticket->submit_node_root);
    id_copy(&node.result_root, result_root);
    if (ticket->ticket_state == AGENT_ISA_TICKET_COMPLETE) {
        derive_state(runtime, ticket, result_root, &node.result_state_root);
        id_copy(&runtime->state_root, &node.result_state_root);
        if (ticket->operation == AGENT_ISA_OP_VERIFY) {
            runtime->verification_ready = true;
            id_copy(&runtime->verified_input_root, &ticket->input_root);
            id_copy(&runtime->verification_evidence_root, result_root);
        }
    } else {
        id_copy(&node.result_state_root, &runtime->state_root);
        if (ticket->operation == AGENT_ISA_OP_VERIFY) {
            runtime->verification_ready = false;
            id_zero(&runtime->verified_input_root);
            id_zero(&runtime->verification_evidence_root);
        }
    }
    agent_object_id_t node_root = record_node(runtime, &node);
    id_copy(&ticket->terminal_node_root, &node_root);
    return conflict ? AGENT_ISA_ERR_CONFLICT : AGENT_ISA_OK;
}

uint32_t agent_isa_runtime_wait(agent_isa_runtime_t *runtime,
                                const struct agent_isa_req_wait *req,
                                struct agent_isa_reply_wait *reply)
{
    if (runtime == NULL || req == NULL || reply == NULL)
        return AGENT_ISA_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    reply->ticket_id = req->ticket_id;
    if (req->interface_version != AGENT_ISA_INTERFACE_VERSION)
        return reply->status = AGENT_ISA_ERR_VERSION;
    if ((req->flags & ~AGENT_ISA_WAIT_KNOWN_MASK) != 0u
        || req->timeout_ticks != 0u || req->reserved != 0u)
        return reply->status = AGENT_ISA_ERR_FLAGS;
    struct agent_isa_ticket_record *ticket = find_ticket(runtime,
                                                          req->ticket_id);
    if (ticket == NULL) return reply->status = AGENT_ISA_ERR_NOT_FOUND;
    reply->status = AGENT_ISA_OK;
    reply->ticket_state = ticket->ticket_state;
    reply->operation = ticket->operation;
    id_copy(&reply->result_root, &ticket->result_root);
    id_copy(&reply->state_root, &runtime->state_root);
    if ((req->flags & AGENT_ISA_WAIT_CONSUME) != 0u
        && ticket->ticket_state != AGENT_ISA_TICKET_PENDING)
        bytes_zero(ticket, sizeof(*ticket));
    return AGENT_ISA_OK;
}

uint32_t agent_isa_runtime_cancel(agent_isa_runtime_t *runtime,
                                  const struct agent_isa_req_cancel *req)
{
    if (runtime == NULL || req == NULL) return AGENT_ISA_ERR_INVALID;
    if (req->interface_version != AGENT_ISA_INTERFACE_VERSION)
        return AGENT_ISA_ERR_VERSION;
    if (req->reserved16 != 0u || req->reserved[0] != 0u
        || req->reserved[1] != 0u) return AGENT_ISA_ERR_INVALID;
    struct agent_isa_ticket_record *ticket = find_ticket(runtime,
                                                          req->ticket_id);
    if (ticket == NULL) return AGENT_ISA_ERR_NOT_FOUND;
    if (ticket->ticket_state == AGENT_ISA_TICKET_CANCELLED)
        return AGENT_ISA_OK;
    if (ticket->ticket_state != AGENT_ISA_TICKET_PENDING)
        return AGENT_ISA_ERR_STATE;
    ticket->ticket_state = AGENT_ISA_TICKET_CANCELLED;
    struct agent_execution_node node;
    node_from_ticket(runtime, ticket, &node);
    id_copy(&node.parent_root, &ticket->submit_node_root);
    id_copy(&node.result_state_root, &runtime->state_root);
    agent_object_id_t root = record_node(runtime, &node);
    id_copy(&ticket->terminal_node_root, &root);
    return AGENT_ISA_OK;
}

uint32_t agent_isa_runtime_status(agent_isa_runtime_t *runtime,
                                  const struct agent_isa_req_status *req,
                                  struct agent_isa_reply_status *reply)
{
    if (runtime == NULL || req == NULL || reply == NULL)
        return AGENT_ISA_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req->interface_version != AGENT_ISA_INTERFACE_VERSION)
        return reply->status = AGENT_ISA_ERR_VERSION;
    if (req->reserved16 != 0u || req->reserved[0] != 0u
        || req->reserved[1] != 0u || req->reserved[2] != 0u)
        return reply->status = AGENT_ISA_ERR_INVALID;
    uint32_t pending = 0u;
    for (uint32_t i = 0u; i < AGENT_ISA_MAX_TICKETS; i++)
        if (runtime->tickets[i].ticket_state == AGENT_ISA_TICKET_PENDING)
            pending++;
    reply->status = AGENT_ISA_OK;
    reply->terminated = runtime->terminated ? 1u : 0u;
    reply->pending_tickets = pending;
    reply->budget_used = runtime->budget_used;
    reply->budget_limit = runtime->budget_limit;
    reply->authority_epoch = runtime->authority_epoch;
    reply->trace_nodes = runtime->trace_count;
    id_copy(&reply->state_root, &runtime->state_root);
    return AGENT_ISA_OK;
}

uint32_t agent_isa_runtime_trace(agent_isa_runtime_t *runtime,
                                 const struct agent_isa_req_trace *req,
                                 struct agent_isa_reply_trace *reply)
{
    if (runtime == NULL || req == NULL || reply == NULL)
        return AGENT_ISA_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req->interface_version != AGENT_ISA_INTERFACE_VERSION)
        return reply->status = AGENT_ISA_ERR_VERSION;
    if (req->reserved16 != 0u || req->reserved[0] != 0u
        || req->reserved[1] != 0u)
        return reply->status = AGENT_ISA_ERR_INVALID;
    if ((runtime->installed_caps & AGENT_ISA_CAP_TRACE) == 0u)
        return reply->status = AGENT_ISA_ERR_CAP_DENIED;
    if (runtime->trace_count == 0u)
        return reply->status = AGENT_ISA_ERR_NOT_FOUND;

    struct agent_execution_node *node = NULL;
    if (req->sequence == 0u) {
        uint32_t index = (runtime->trace_head + AGENT_ISA_MAX_TRACE_NODES - 1u)
            % AGENT_ISA_MAX_TRACE_NODES;
        node = &runtime->trace[index];
    } else {
        for (uint32_t i = 0u; i < runtime->trace_count; i++) {
            uint32_t index = (runtime->trace_head
                              + AGENT_ISA_MAX_TRACE_NODES
                              - runtime->trace_count + i)
                % AGENT_ISA_MAX_TRACE_NODES;
            if (runtime->trace[index].sequence == req->sequence) {
                node = &runtime->trace[index];
                break;
            }
        }
    }
    if (node == NULL) return reply->status = AGENT_ISA_ERR_NOT_FOUND;
    reply->status = AGENT_ISA_OK;
    reply->sequence = node->sequence;
    reply->operation = node->operation;
    reply->ticket_state = node->ticket_state;
    agent_isa_execution_node_hash(node, &reply->node_root);
    id_copy(&reply->parent_root, &node->parent_root);
    return AGENT_ISA_OK;
}

_Static_assert(sizeof(struct agent_execution_node)
                   == AGENT_EXECUTION_NODE_CANONICAL_BYTES,
               "execution node struct/canonical encoding drift");
