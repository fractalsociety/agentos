#pragma once

#include <stdint.h>
#include "contracts/agent_task_contract.h"

struct harness_req_submit;
struct harness_reply_submit;
struct harness_reply_result;
struct mesh_remote_authority_state;
struct mesh_remote_grant;
struct mesh_execution_lease;
struct mesh_remote_authority_context;
struct mesh_completion_guard;
typedef struct mesh_remote_authority_state mesh_remote_authority_state_t;
typedef struct mesh_remote_grant mesh_remote_grant_t;
typedef struct mesh_execution_lease mesh_execution_lease_t;
typedef struct mesh_remote_authority_context mesh_remote_authority_context_t;
typedef struct mesh_completion_guard mesh_completion_guard_t;

typedef uint32_t (*agent_task_submit_fn)(
    const struct harness_req_submit *req,
    struct harness_reply_submit *reply, void *ctx);
typedef uint32_t (*agent_task_metrics_fn)(
    uint32_t task_id, struct harness_reply_result *reply, void *ctx);
typedef void (*agent_task_authority_fn)(
    uint32_t *installed_caps, uint32_t *authority_epoch, void *ctx);

void agent_task_gateway_init(uint8_t *arena, uint32_t arena_size,
                             agent_task_submit_fn submit,
                             agent_task_metrics_fn metrics,
                             agent_task_authority_fn authority, void *ctx);
uint32_t agent_task_gateway_begin(const struct agent_task_req_begin *req,
                                  struct agent_task_reply_begin *reply);
uint32_t agent_task_gateway_write(const struct agent_task_req_write *req);
uint32_t agent_task_gateway_run(const struct agent_task_req_run *req,
                                struct agent_task_reply_run *reply);
uint32_t agent_task_gateway_result(const struct agent_task_req_result *req,
                                   struct agent_task_reply_result *reply);
uint32_t agent_task_gateway_metrics(uint32_t task_id,
                                    struct harness_reply_result *reply);

uint32_t agent_task_gateway_remote_dispatch_recheck(
    const mesh_remote_authority_state_t *authority_state,
    const mesh_remote_grant_t *grant, const mesh_execution_lease_t *lease,
    const mesh_remote_authority_context_t *ctx, uint64_t admitted_local_badge,
    uint64_t *out_local_badge);
uint32_t agent_task_gateway_remote_completion_recheck(
    const mesh_remote_authority_state_t *authority_state,
    const mesh_remote_grant_t *grant, const mesh_execution_lease_t *lease,
    const mesh_remote_authority_context_t *ctx, uint64_t admitted_local_badge,
    mesh_completion_guard_t *completion, uint64_t completion_sequence);
