#pragma once

#include <stdint.h>
#include "contracts/agent_task_contract.h"

struct harness_req_submit;
struct harness_reply_submit;
struct harness_reply_result;

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
