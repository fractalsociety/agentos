/* Freestanding Fractal Agent ISA v0 execution-graph engine. */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "contracts/agent_isa_contract.h"

struct agent_execution_node {
    uint16_t interface_version;
    uint16_t operation;
    uint32_t ticket_state;
    uint32_t flags;
    uint32_t ticket_id;
    uint32_t sequence;
    uint32_t declared_caps;
    uint32_t budget_units;
    uint32_t authority_epoch;
    agent_object_id_t parent_root;
    agent_object_id_t previous_state_root;
    agent_object_id_t input_root;
    agent_object_id_t operand_root;
    agent_object_id_t capability_set_root;
    agent_object_id_t environment_root;
    agent_object_id_t result_root;
    agent_object_id_t result_state_root;
};

struct agent_isa_ticket_record {
    uint32_t ticket_id;
    uint32_t ticket_state;
    uint16_t operation;
    uint16_t reserved16;
    uint32_t flags;
    uint32_t declared_caps;
    uint32_t budget_units;
    agent_object_id_t previous_state_root;
    agent_object_id_t input_root;
    agent_object_id_t operand_root;
    agent_object_id_t submit_node_root;
    agent_object_id_t terminal_node_root;
    agent_object_id_t result_root;
};

typedef struct agent_isa_runtime {
    uint32_t installed_caps;
    uint32_t authority_epoch;
    uint32_t budget_limit;
    uint32_t budget_used;
    uint32_t next_ticket_id;
    uint32_t next_sequence;
    uint32_t trace_head;
    uint32_t trace_count;
    bool terminated;
    bool verification_ready;
    uint8_t reserved[2];
    agent_object_id_t capability_set_root;
    agent_object_id_t environment_root;
    agent_object_id_t state_root;
    agent_object_id_t execution_head_root;
    agent_object_id_t verified_input_root;
    agent_object_id_t verification_evidence_root;
    struct agent_isa_ticket_record tickets[AGENT_ISA_MAX_TICKETS];
    struct agent_execution_node trace[AGENT_ISA_MAX_TRACE_NODES];
} agent_isa_runtime_t;

void agent_isa_object_id_from_bytes(const void *data, uint32_t len,
                                    agent_object_id_t *out);

bool agent_isa_operation_is_async(uint16_t operation);
uint32_t agent_isa_operation_required_caps(uint16_t operation);

void agent_isa_execution_node_hash(const struct agent_execution_node *node,
                                   agent_object_id_t *out);

void agent_isa_runtime_init(agent_isa_runtime_t *runtime,
                            uint32_t installed_caps,
                            uint32_t authority_epoch,
                            const agent_object_id_t *capability_set_root,
                            const agent_object_id_t *environment_root,
                            const agent_object_id_t *initial_state_root,
                            uint32_t budget_limit);

uint32_t agent_isa_runtime_update_authority(
    agent_isa_runtime_t *runtime, uint32_t installed_caps,
    uint32_t authority_epoch, const agent_object_id_t *capability_set_root);

uint32_t agent_isa_runtime_submit(
    agent_isa_runtime_t *runtime,
    const struct agent_isa_req_submit *req,
    struct agent_isa_reply_submit *reply);

/* Trusted lower-ABI adapter entrypoint; this is intentionally not an IPC
 * opcode exposed to an agent. */
uint32_t agent_isa_runtime_complete(agent_isa_runtime_t *runtime,
                                    uint32_t ticket_id,
                                    const agent_object_id_t *result_root,
                                    bool success);

uint32_t agent_isa_runtime_wait(agent_isa_runtime_t *runtime,
                                const struct agent_isa_req_wait *req,
                                struct agent_isa_reply_wait *reply);

uint32_t agent_isa_runtime_cancel(agent_isa_runtime_t *runtime,
                                  const struct agent_isa_req_cancel *req);

uint32_t agent_isa_runtime_status(agent_isa_runtime_t *runtime,
                                  const struct agent_isa_req_status *req,
                                  struct agent_isa_reply_status *reply);

uint32_t agent_isa_runtime_trace(agent_isa_runtime_t *runtime,
                                 const struct agent_isa_req_trace *req,
                                 struct agent_isa_reply_trace *reply);
