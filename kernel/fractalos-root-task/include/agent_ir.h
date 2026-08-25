/* Fractal Agent IR v0: immutable control-flow nodes above Agent ISA. */
#pragma once

#include <stdint.h>

#include "agent_isa.h"

#define AGENT_IR_INTERFACE_VERSION 1u

enum agent_ir_error {
    AGENT_IR_OK = 0u,
    AGENT_IR_ERR_INVALID = 1u,
    AGENT_IR_ERR_VERSION = 2u,
    AGENT_IR_ERR_OPERATION = 3u,
    AGENT_IR_ERR_FLAGS = 4u,
    AGENT_IR_ERR_CAPABILITY = 5u,
    AGENT_IR_ERR_BUDGET = 6u,
    AGENT_IR_ERR_OBJECT = 7u,
    AGENT_IR_ERR_CONTINUATION = 8u,
};

/* One immutable Agent IR node. subject/context lower to the two v0 ISA
 * operands. Success and failure roots name the next IR nodes; zero means the
 * graph terminates on that edge. Neither continuation is authority. */
struct agent_ir_node_v0 {
    uint16_t interface_version;
    uint16_t operation;
    uint32_t execution_flags;
    uint32_t declared_caps;
    uint32_t budget_units;
    agent_object_id_t subject_root;
    agent_object_id_t context_root;
    agent_object_id_t success_continuation_root;
    agent_object_id_t failure_continuation_root;
};

struct agent_ir_compiled_v0 {
    struct agent_isa_req_submit instruction;
    agent_object_id_t ir_node_root;
    agent_object_id_t success_continuation_root;
    agent_object_id_t failure_continuation_root;
};

uint32_t agent_ir_validate_v0(const struct agent_ir_node_v0 *node);

uint32_t agent_ir_compile_v0(const struct agent_ir_node_v0 *node,
                             struct agent_ir_compiled_v0 *compiled);

void agent_ir_node_hash_v0(const struct agent_ir_node_v0 *node,
                           agent_object_id_t *out);

_Static_assert(sizeof(struct agent_ir_node_v0) == 80u,
               "Agent IR v0 node ABI drift");
_Static_assert(sizeof(struct agent_ir_compiled_v0) == 96u,
               "Agent IR v0 compiled record ABI drift");
