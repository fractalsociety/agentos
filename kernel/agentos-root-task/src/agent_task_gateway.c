#include "contracts/agent_harness_contract.h"
#include "agent_task_gateway.h"

#include <stdbool.h>
#include <stddef.h>

static struct {
    uint8_t *arena;
    uint32_t arena_size;
    agent_task_submit_fn submit;
    agent_task_metrics_fn metrics;
    agent_task_authority_fn authority;
    void *ctx;
    uint32_t next_task_id;
    uint32_t task_id;
    uint32_t required_caps;
    uint32_t task_flags;
    uint32_t max_steps;
    uint32_t prompt_len;
    uint32_t received_len;
    uint32_t result_capacity;
    uint32_t result_len;
    uint32_t available_caps;
    uint32_t authority_epoch;
    uint32_t harness_status;
    uint32_t state;
    bool active;
    bool ran;
    struct harness_reply_result last_metrics;
} g_task;

static void bytes_zero(void *dst, uint32_t len)
{
    uint8_t *p = (uint8_t *)dst;
    for (uint32_t i = 0u; i < len; i++) p[i] = 0u;
}

static void bytes_copy(void *dst, const void *src, uint32_t len)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (uint32_t i = 0u; i < len; i++) d[i] = s[i];
}

static bool gateway_ready(void)
{
    return g_task.arena != NULL && g_task.submit != NULL
        && g_task.metrics != NULL && g_task.authority != NULL
        && g_task.arena_size >= AGENT_TASK_RESULT_OFFSET
            + AGENT_TASK_RESULT_CAP;
}

void agent_task_gateway_init(uint8_t *arena, uint32_t arena_size,
                             agent_task_submit_fn submit,
                             agent_task_metrics_fn metrics,
                             agent_task_authority_fn authority, void *ctx)
{
    bytes_zero(&g_task, sizeof(g_task));
    g_task.arena = arena;
    g_task.arena_size = arena_size;
    g_task.submit = submit;
    g_task.metrics = metrics;
    g_task.authority = authority;
    g_task.ctx = ctx;
    g_task.next_task_id = 1u;
}

uint32_t agent_task_gateway_begin(const struct agent_task_req_begin *req,
                                  struct agent_task_reply_begin *reply)
{
    if (reply == NULL) return AGENT_TASK_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (!gateway_ready() || req == NULL
        || req->interface_version != AGENT_TASK_INTERFACE_VERSION
        || req->prompt_len == 0u || req->prompt_len > AGENT_TASK_PROMPT_CAP
        || req->result_capacity < 2u
        || req->result_capacity > AGENT_TASK_RESULT_CAP
        || req->max_steps == 0u
        || (req->required_caps & ~HARNESS_CAP_KNOWN_MASK) != 0u) {
        reply->status = AGENT_TASK_ERR_INVALID;
        return reply->status;
    }

    uint32_t available_caps = 0u, authority_epoch = 0u;
    g_task.authority(&available_caps, &authority_epoch, g_task.ctx);
    uint32_t task_id = g_task.next_task_id++;
    if (task_id == 0u) task_id = g_task.next_task_id++;

    g_task.task_id = task_id;
    g_task.required_caps = req->required_caps;
    g_task.task_flags = req->task_flags;
    g_task.max_steps = req->max_steps;
    g_task.prompt_len = req->prompt_len;
    g_task.received_len = 0u;
    g_task.result_capacity = req->result_capacity;
    g_task.result_len = 0u;
    g_task.available_caps = available_caps;
    g_task.authority_epoch = authority_epoch;
    g_task.harness_status = HARNESS_OK;
    g_task.state = HARNESS_STATE_IDLE;
    g_task.active = true;
    g_task.ran = false;
    bytes_zero(&g_task.last_metrics, sizeof(g_task.last_metrics));
    bytes_zero(g_task.arena + AGENT_TASK_PROMPT_OFFSET, req->prompt_len);
    bytes_zero(g_task.arena + AGENT_TASK_RESULT_OFFSET, req->result_capacity);

    reply->status = AGENT_TASK_OK;
    reply->task_id = task_id;
    reply->accepted_prompt_len = req->prompt_len;
    reply->result_capacity = req->result_capacity;
    reply->available_caps = available_caps;
    reply->authority_epoch = authority_epoch;
    return AGENT_TASK_OK;
}

uint32_t agent_task_gateway_write(const struct agent_task_req_write *req)
{
    if (!gateway_ready() || req == NULL || !g_task.active
        || req->task_id != g_task.task_id)
        return AGENT_TASK_ERR_NOT_FOUND;
    if (g_task.ran || req->len == 0u || req->len > AGENT_TASK_CHUNK_BYTES
        || req->offset != g_task.received_len
        || req->len > g_task.prompt_len - g_task.received_len)
        return AGENT_TASK_ERR_INVALID;
    bytes_copy(g_task.arena + AGENT_TASK_PROMPT_OFFSET + req->offset,
               req->data, req->len);
    g_task.received_len += req->len;
    return AGENT_TASK_OK;
}

uint32_t agent_task_gateway_run(const struct agent_task_req_run *req,
                                struct agent_task_reply_run *reply)
{
    if (reply == NULL) return AGENT_TASK_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (!gateway_ready() || req == NULL || !g_task.active
        || req->task_id != g_task.task_id) {
        reply->status = AGENT_TASK_ERR_NOT_FOUND;
        return reply->status;
    }
    reply->task_id = g_task.task_id;
    if (g_task.ran) {
        reply->status = AGENT_TASK_ERR_BUSY;
        return reply->status;
    }
    if (g_task.received_len != g_task.prompt_len) {
        reply->status = AGENT_TASK_ERR_INCOMPLETE;
        return reply->status;
    }

    /* Refresh kernel-owned authority at the effect boundary. The caller never
     * supplies an epoch and task text cannot manufacture a grant. */
    g_task.authority(&g_task.available_caps, &g_task.authority_epoch,
                     g_task.ctx);

    struct harness_req_submit submit;
    bytes_zero(&submit, sizeof(submit));
    submit.task_id = g_task.task_id;
    submit.harness_kind = HARNESS_KIND_CODEX;
    submit.required_caps = g_task.required_caps;
    submit.task_flags = g_task.task_flags;
    submit.max_steps = g_task.max_steps;
    submit.authority_epoch = g_task.authority_epoch;
    submit.prompt_offset = AGENT_TASK_PROMPT_OFFSET;
    submit.prompt_len = g_task.prompt_len;
    submit.result_offset = AGENT_TASK_RESULT_OFFSET;
    submit.result_capacity = g_task.result_capacity;

    struct harness_reply_submit harness_reply;
    bytes_zero(&harness_reply, sizeof(harness_reply));
    uint32_t harness_status = g_task.submit(&submit, &harness_reply,
                                             g_task.ctx);
    g_task.ran = true;
    g_task.harness_status = harness_status;
    g_task.state = harness_reply.state;
    g_task.last_metrics.status = harness_status;
    g_task.last_metrics.task_id = g_task.task_id;
    g_task.last_metrics.state = harness_reply.state;

    if (harness_status == HARNESS_OK) {
        struct harness_reply_result metrics;
        bytes_zero(&metrics, sizeof(metrics));
        uint32_t metrics_status = g_task.metrics(g_task.task_id, &metrics,
                                                  g_task.ctx);
        if (metrics_status != HARNESS_OK
            || metrics.result_len >= g_task.result_capacity) {
            reply->status = AGENT_TASK_ERR_HARNESS;
            reply->harness_status = metrics_status;
            reply->state = harness_reply.state;
            return reply->status;
        }
        g_task.last_metrics = metrics;
        g_task.result_len = metrics.result_len;
        g_task.state = metrics.state;
    }

    reply->status = AGENT_TASK_OK;
    reply->task_id = g_task.task_id;
    reply->harness_status = g_task.harness_status;
    reply->state = g_task.state;
    reply->result_len = g_task.result_len;
    reply->used_caps = g_task.last_metrics.used_caps;
    return AGENT_TASK_OK;
}

uint32_t agent_task_gateway_result(const struct agent_task_req_result *req,
                                   struct agent_task_reply_result *reply)
{
    if (reply == NULL) return AGENT_TASK_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (!gateway_ready() || req == NULL || !g_task.active
        || req->task_id != g_task.task_id) {
        reply->status = AGENT_TASK_ERR_NOT_FOUND;
        return reply->status;
    }
    reply->task_id = g_task.task_id;
    if (!g_task.ran) {
        reply->status = AGENT_TASK_ERR_INCOMPLETE;
        return reply->status;
    }
    if (req->offset > g_task.result_len
        || req->max_len > AGENT_TASK_RESULT_CHUNK_BYTES) {
        reply->status = AGENT_TASK_ERR_INVALID;
        return reply->status;
    }
    uint32_t len = g_task.result_len - req->offset;
    if (len > req->max_len) len = req->max_len;
    bytes_copy(reply->data,
               g_task.arena + AGENT_TASK_RESULT_OFFSET + req->offset, len);
    reply->status = AGENT_TASK_OK;
    reply->total_len = g_task.result_len;
    reply->chunk_offset = req->offset;
    reply->chunk_len = len;
    return AGENT_TASK_OK;
}

uint32_t agent_task_gateway_metrics(uint32_t task_id,
                                    struct harness_reply_result *reply)
{
    if (reply == NULL) return AGENT_TASK_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (!gateway_ready() || !g_task.active || !g_task.ran
        || task_id != g_task.task_id)
        return AGENT_TASK_ERR_NOT_FOUND;
    *reply = g_task.last_metrics;
    return AGENT_TASK_OK;
}
