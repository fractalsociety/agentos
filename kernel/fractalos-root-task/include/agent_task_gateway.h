#pragma once

#include <stdint.h>
#include "contracts/agent_task_contract.h"

struct harness_req_submit;
struct harness_reply_submit;
struct harness_reply_result;
struct eventbus_agent_event;
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

/* The Fractal boundary is asynchronous.  The queue hook is deliberately
 * small: it admits a validated request to an existing worker/runner queue and
 * must return without executing the program. */
typedef uint32_t (*agent_task_enqueue_fn)(
    const struct agent_task_req_submit *req,
    const struct agent_task_handle *task, void *ctx);

#define AGENT_TASK_GATEWAY_RIGHT       (1ull << 1)
#define AGENT_TASK_MAX_PROGRAMS        8u
#define AGENT_TASK_MAX_FRACTAL_TASKS   8u
#define AGENT_TASK_MAX_CPU_QUANTA     UINT64_C(0xFFFFFFFF)
#define AGENT_TASK_MAX_MEMORY_BYTES   UINT64_C(0x40000000)
#define AGENT_TASK_MAX_STEPS          0x01000000u
#define AGENT_TASK_MAX_RESULT_BYTES   0x400000u

void agent_task_gateway_init(uint8_t *arena, uint32_t arena_size,
                             agent_task_submit_fn submit,
                             agent_task_metrics_fn metrics,
                             agent_task_authority_fn authority, void *ctx);
void agent_task_gateway_set_enqueue(agent_task_enqueue_fn enqueue);
uint32_t agent_task_gateway_begin(const struct agent_task_req_begin *req,
                                  struct agent_task_reply_begin *reply);
uint32_t agent_task_gateway_write(const struct agent_task_req_write *req);
uint32_t agent_task_gateway_run(const struct agent_task_req_run *req,
                                struct agent_task_reply_run *reply);
uint32_t agent_task_gateway_result(const struct agent_task_req_result *req,
                                   struct agent_task_reply_result *reply);
uint32_t agent_task_gateway_metrics(uint32_t task_id,
                                    struct harness_reply_result *reply);

/* Versioned asynchronous Fractal task-control-plane entry points. */
uint32_t agent_task_gateway_program_open(
    uint64_t badge, const struct agent_task_req_program_open *req,
    struct agent_task_reply_program_open *reply);
uint32_t agent_task_gateway_program_poll(
    uint64_t badge, const struct agent_task_req_program_poll *req,
    struct agent_task_reply_program_poll *reply);
uint32_t agent_task_gateway_submit(
    uint64_t badge, const struct agent_task_req_submit *req,
    struct agent_task_reply_submit *reply);
uint32_t agent_task_gateway_poll(
    uint64_t badge, const struct agent_task_req_poll *req,
    struct agent_task_reply_poll *reply);
uint32_t agent_task_gateway_cancel(
    uint64_t badge, const struct agent_task_req_cancel *req,
    struct agent_task_reply_cancel *reply);
uint32_t agent_task_gateway_budget(
    uint64_t badge, const struct agent_task_req_budget *req,
    struct agent_task_reply_budget *reply);
uint32_t agent_task_gateway_verify(
    uint64_t badge, const struct agent_task_req_verify *req,
    struct agent_task_reply_verify *reply);
uint32_t agent_task_gateway_commit(
    uint64_t badge, const struct agent_task_req_commit *req,
    struct agent_task_reply_commit *reply);
uint32_t agent_task_gateway_terminal_result(
    uint64_t badge, const struct agent_task_req_terminal_result *req,
    struct agent_task_reply_terminal_result *reply);

/* Called by the canonical EventBus writer after an authenticated append. */
void agent_task_gateway_authenticated_event(
    const struct eventbus_agent_event *event);

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
