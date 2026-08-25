/*
 * Agent ISA dispatcher topology (fos-gz0.14.1.3).
 *
 * Wires AgentHarness-facing submit → shared dispatch mailbox → capability-
 * selected semantic adapter → trusted completion. Submit returns before lower
 * work finishes. Completions require the dispatcher badge (no forged owner
 * completions). Authority revocation cancels outstanding queued/running work.
 */

#pragma once

#include "agent_isa.h"
#include "agent_isa_dispatch.h"
#include "agent_isa_semantic_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AGENT_ISA_TOPOLOGY_INTERFACE_VERSION 1u

enum agent_isa_topology_error {
    AGENT_ISA_TOPOLOGY_OK            = 0u,
    AGENT_ISA_TOPOLOGY_ERR_INVALID   = 1u,
    AGENT_ISA_TOPOLOGY_ERR_RUNTIME   = 2u,
    AGENT_ISA_TOPOLOGY_ERR_DISPATCH  = 3u,
    AGENT_ISA_TOPOLOGY_ERR_ADAPTER   = 4u,
    AGENT_ISA_TOPOLOGY_ERR_EMPTY     = 5u,
    AGENT_ISA_TOPOLOGY_ERR_STATE     = 6u,
};

typedef struct agent_isa_topology {
    agent_isa_runtime_t runtime;
    agent_isa_dispatch_mailbox_t mailbox;
    uint64_t owner_badge;
    uint64_t dispatcher_badge;
    uint32_t authority_epoch;
    uint32_t next_nonce;
    uint32_t next_slot;
    uint32_t budget_remaining;
    /* Pending dispatch metadata keyed by ticket_id (sparse). */
    uint32_t pending_ticket;
    uint32_t pending_nonce;
    uint32_t pending_slot;
    int has_pending_dispatch;
} agent_isa_topology_t;

void agent_isa_topology_init(agent_isa_topology_t *topo, uint64_t owner_badge,
                             uint64_t dispatcher_badge, uint32_t authority_epoch,
                             uint32_t installed_caps, uint32_t budget_limit,
                             const agent_object_id_t *capset,
                             const agent_object_id_t *environment,
                             const agent_object_id_t *initial_state);

/* Install default endpoints for all async-lowerable service classes. */
uint32_t agent_isa_topology_install_default_adapters(
    agent_isa_topology_t *topo);

/*
 * Submit an async semantic op: runtime ticket + mailbox enqueue.
 * Returns before adapter/lower completion (pending ticket).
 */
uint32_t agent_isa_topology_submit_async(
    agent_isa_topology_t *topo, uint16_t operation, uint32_t declared_caps,
    const agent_object_id_t *input_root, const agent_object_id_t *operand_root,
    struct agent_isa_reply_submit *reply);

/* One dispatcher step: take → adapter invoke → trusted complete → runtime complete. */
uint32_t agent_isa_topology_pump(agent_isa_topology_t *topo);

uint32_t agent_isa_topology_wait(agent_isa_topology_t *topo, uint32_t ticket_id,
                                 struct agent_isa_reply_wait *reply);

/* Bump authority epoch; cancels outstanding dispatch for this owner. */
uint32_t agent_isa_topology_revoke(agent_isa_topology_t *topo);

#ifdef __cplusplus
}
#endif
