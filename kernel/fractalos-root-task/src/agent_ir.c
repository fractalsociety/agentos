#include "agent_ir.h"

#include <stddef.h>

static void zero_bytes(void *dst_ptr, uint32_t len)
{
    uint8_t *dst = (uint8_t *)dst_ptr;
    for (uint32_t i = 0u; i < len; i++) dst[i] = 0u;
}

static void copy_id(agent_object_id_t *dst, const agent_object_id_t *src)
{
    for (uint32_t i = 0u; i < 4u; i++) dst->word[i] = src->word[i];
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

void agent_ir_node_hash_v0(const struct agent_ir_node_v0 *node,
                           agent_object_id_t *out)
{
    if (out == NULL) return;
    if (node == NULL) {
        zero_bytes(out, sizeof(*out));
        return;
    }
    uint8_t canonical[80];
    uint32_t offset = 0u;
    put16(canonical, &offset, node->interface_version);
    put16(canonical, &offset, node->operation);
    put32(canonical, &offset, node->execution_flags);
    put32(canonical, &offset, node->declared_caps);
    put32(canonical, &offset, node->budget_units);
    put_id(canonical, &offset, &node->subject_root);
    put_id(canonical, &offset, &node->context_root);
    put_id(canonical, &offset, &node->success_continuation_root);
    put_id(canonical, &offset, &node->failure_continuation_root);
    if (offset != sizeof(canonical)) {
        zero_bytes(out, sizeof(*out));
        return;
    }
    agent_isa_object_id_from_bytes(canonical, sizeof(canonical), out);
}

uint32_t agent_ir_validate_v0(const struct agent_ir_node_v0 *node)
{
    if (node == NULL) return AGENT_IR_ERR_INVALID;
    if (node->interface_version != AGENT_IR_INTERFACE_VERSION)
        return AGENT_IR_ERR_VERSION;
    uint32_t required = agent_isa_operation_required_caps(node->operation);
    if (required == UINT32_MAX) return AGENT_IR_ERR_OPERATION;
    if ((node->execution_flags & ~AGENT_ISA_FLAG_KNOWN_MASK) != 0u
        || ((node->execution_flags & AGENT_ISA_FLAG_ASYNC) != 0u)
            != agent_isa_operation_is_async(node->operation))
        return AGENT_IR_ERR_FLAGS;
    if ((node->declared_caps & ~AGENT_ISA_CAP_KNOWN_MASK) != 0u
        || node->declared_caps != required)
        return AGENT_IR_ERR_CAPABILITY;
    if (node->budget_units == 0u
        || node->budget_units > AGENT_ISA_MAX_BUDGET_UNITS)
        return AGENT_IR_ERR_BUDGET;

    struct agent_isa_req_submit instruction = {
        .interface_version = AGENT_ISA_INTERFACE_VERSION,
        .operation = node->operation,
        .flags = node->execution_flags,
        .declared_caps = node->declared_caps,
        .budget_units = node->budget_units,
        .input_root = node->subject_root,
        .operand_root = node->context_root,
    };
    /* Reuse the execution engine as the final object-shape authority during
     * compilation is intentionally avoided: it would charge budget or create
     * a ticket. Mirror only the stable v0 shape rules here. */
    bool subject = !agent_object_id_is_zero(&instruction.input_root);
    bool context = !agent_object_id_is_zero(&instruction.operand_root);
    switch (node->operation) {
    case AGENT_ISA_OP_SPAWN:
    case AGENT_ISA_OP_DELEGATE:
    case AGENT_ISA_OP_CAP_GRANT:
    case AGENT_ISA_OP_CAP_REVOKE:
    case AGENT_ISA_OP_ACT:
    case AGENT_ISA_OP_VERIFY:
    case AGENT_ISA_OP_COMMIT:
        if (!subject || !context) return AGENT_IR_ERR_OBJECT;
        break;
    case AGENT_ISA_OP_OBJECT_GET:
    case AGENT_ISA_OP_OBJECT_PUT:
    case AGENT_ISA_OP_OBJECT_QUERY:
    case AGENT_ISA_OP_INFER:
    case AGENT_ISA_OP_EMIT:
    case AGENT_ISA_OP_RESTORE:
    case AGENT_ISA_OP_BUDGET:
        if (!subject) return AGENT_IR_ERR_OBJECT;
        break;
    case AGENT_ISA_OP_CHECKPOINT:
    case AGENT_ISA_OP_TERMINATE:
        if (subject || context) return AGENT_IR_ERR_OBJECT;
        break;
    case AGENT_ISA_OP_WAIT:
    case AGENT_ISA_OP_TRACE:
        /* These compile to their dedicated bounded IPC forms in the runner. */
        break;
    default:
        return AGENT_IR_ERR_OPERATION;
    }

    bool success_edge = !agent_object_id_is_zero(
        &node->success_continuation_root);
    bool failure_edge = !agent_object_id_is_zero(
        &node->failure_continuation_root);
    if (agent_isa_operation_is_async(node->operation)
        && !success_edge && !failure_edge)
        return AGENT_IR_ERR_CONTINUATION;
    if (node->operation == AGENT_ISA_OP_TERMINATE
        && (success_edge || failure_edge))
        return AGENT_IR_ERR_CONTINUATION;
    return AGENT_IR_OK;
}

uint32_t agent_ir_compile_v0(const struct agent_ir_node_v0 *node,
                             struct agent_ir_compiled_v0 *compiled)
{
    if (compiled == NULL) return AGENT_IR_ERR_INVALID;
    zero_bytes(compiled, sizeof(*compiled));
    uint32_t status = agent_ir_validate_v0(node);
    if (status != AGENT_IR_OK) return status;
    compiled->instruction.interface_version = AGENT_ISA_INTERFACE_VERSION;
    compiled->instruction.operation = node->operation;
    compiled->instruction.flags = node->execution_flags;
    compiled->instruction.declared_caps = node->declared_caps;
    compiled->instruction.budget_units = node->budget_units;
    copy_id(&compiled->instruction.input_root, &node->subject_root);
    copy_id(&compiled->instruction.operand_root, &node->context_root);
    agent_ir_node_hash_v0(node, &compiled->ir_node_root);
    copy_id(&compiled->success_continuation_root,
            &node->success_continuation_root);
    copy_id(&compiled->failure_continuation_root,
            &node->failure_continuation_root);
    return AGENT_IR_OK;
}
