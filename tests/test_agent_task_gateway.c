#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../kernel/agentos-root-task/include/contracts/agent_harness_contract.h"
#include "../kernel/agentos-root-task/include/agentos.h"
#include "../kernel/agentos-root-task/include/agent_task_gateway.h"

static uint8_t arena[HARNESS_SHMEM_SIZE];
static uint32_t installed_caps;
static uint32_t authority_epoch;
static uint32_t submit_calls;

static void authority(uint32_t *caps, uint32_t *epoch, void *ctx)
{
    (void)ctx;
    *caps = installed_caps;
    *epoch = authority_epoch;
}

static uint32_t submit(const struct harness_req_submit *req,
                       struct harness_reply_submit *reply, void *ctx)
{
    (void)ctx;
    submit_calls++;
    assert(req->authority_epoch == authority_epoch);
    assert(req->prompt_offset == AGENT_TASK_PROMPT_OFFSET);
    assert(req->result_offset == AGENT_TASK_RESULT_OFFSET);
    if (!harness_authority_satisfies(req->required_caps | HARNESS_CAP_MODEL,
                                     installed_caps)) {
        reply->status = HARNESS_ERR_CAP_DENIED;
        reply->task_id = req->task_id;
        reply->available_caps = installed_caps;
        reply->state = HARNESS_STATE_IDLE;
        return HARNESS_ERR_CAP_DENIED;
    }
    static const char expected_prompt[] = "repair the bounded fixture";
    static const char result[] = "fixture repaired and verified";
    assert(req->prompt_len == sizeof(expected_prompt) - 1u);
    assert(memcmp(arena + req->prompt_offset, expected_prompt,
                  sizeof(expected_prompt) - 1u) == 0);
    memcpy(arena + req->result_offset, result, sizeof(result));
    reply->status = HARNESS_OK;
    reply->task_id = req->task_id;
    reply->available_caps = installed_caps;
    reply->state = HARNESS_STATE_COMPLETE;
    return HARNESS_OK;
}

static uint32_t metrics(uint32_t task_id,
                        struct harness_reply_result *reply, void *ctx)
{
    (void)ctx;
    static const char result[] = "fixture repaired and verified";
    memset(reply, 0, sizeof(*reply));
    reply->status = HARNESS_OK;
    reply->task_id = task_id;
    reply->state = HARNESS_STATE_COMPLETE;
    reply->result_len = sizeof(result) - 1u;
    reply->model_calls = 3u;
    reply->tool_calls = 2u;
    reply->memory_ops = 1u;
    reply->exec_calls = 1u;
    reply->tokens_in = 400u;
    reply->tokens_out = 80u;
    reply->verification_exit_code = 0;
    reply->used_caps = HARNESS_CAP_MODEL | HARNESS_CAP_TOOL
        | HARNESS_CAP_MEMORY | HARNESS_CAP_EXEC;
    return HARNESS_OK;
}

static uint32_t begin_task(uint32_t required_caps, uint32_t prompt_len,
                           struct agent_task_reply_begin *reply)
{
    struct agent_task_req_begin begin = {
        .interface_version = AGENT_TASK_INTERFACE_VERSION,
        .required_caps = required_caps,
        .task_flags = HARNESS_TASK_ALLOW_PATCH | HARNESS_TASK_REQUIRE_TEST,
        .max_steps = 16u,
        .prompt_len = prompt_len,
        .result_capacity = 1024u,
    };
    return agent_task_gateway_begin(&begin, reply);
}

static void write_prompt(uint32_t task_id, const char *prompt, uint32_t len)
{
    uint32_t offset = 0u;
    while (offset < len) {
        struct agent_task_req_write write;
        memset(&write, 0, sizeof(write));
        write.task_id = task_id;
        write.offset = offset;
        write.len = len - offset;
        if (write.len > AGENT_TASK_CHUNK_BYTES)
            write.len = AGENT_TASK_CHUNK_BYTES;
        memcpy(write.data, prompt + offset, write.len);
        assert(agent_task_gateway_write(&write) == AGENT_TASK_OK);
        offset += write.len;
    }
}

int main(void)
{
    installed_caps = HARNESS_CAP_MODEL | HARNESS_CAP_TOOL
        | HARNESS_CAP_MEMORY | HARNESS_CAP_EXEC;
    authority_epoch = 7u;
    agent_task_gateway_init(arena, sizeof(arena), submit, metrics,
                            authority, NULL);

    static const char prompt[] = "repair the bounded fixture";
    struct agent_task_reply_begin begin_reply;
    assert(begin_task(installed_caps, sizeof(prompt) - 1u, &begin_reply)
           == AGENT_TASK_OK);
    assert(begin_reply.task_id != 0u);
    assert(begin_reply.available_caps == installed_caps);
    assert(begin_reply.authority_epoch == authority_epoch);

    struct agent_task_req_run run = {.task_id = begin_reply.task_id};
    struct agent_task_reply_run run_reply;
    assert(agent_task_gateway_run(&run, &run_reply)
           == AGENT_TASK_ERR_INCOMPLETE);

    struct agent_task_req_write bad_write = {
        .task_id = begin_reply.task_id,
        .offset = 1u,
        .len = 1u,
        .data = {'x'},
    };
    assert(agent_task_gateway_write(&bad_write) == AGENT_TASK_ERR_INVALID);
    write_prompt(begin_reply.task_id, prompt, sizeof(prompt) - 1u);

    authority_epoch = 8u;
    assert(agent_task_gateway_run(&run, &run_reply) == AGENT_TASK_OK);
    assert(run_reply.harness_status == HARNESS_OK);
    assert(run_reply.state == HARNESS_STATE_COMPLETE);
    assert(run_reply.used_caps == installed_caps);
    assert(submit_calls == 1u);

    char output[64] = {0};
    uint32_t copied = 0u;
    while (copied < run_reply.result_len) {
        struct agent_task_req_result result_req = {
            .task_id = begin_reply.task_id,
            .offset = copied,
            .max_len = AGENT_TASK_RESULT_CHUNK_BYTES,
        };
        struct agent_task_reply_result result_reply;
        assert(agent_task_gateway_result(&result_req, &result_reply)
               == AGENT_TASK_OK);
        assert(result_reply.chunk_offset == copied);
        memcpy(output + copied, result_reply.data, result_reply.chunk_len);
        copied += result_reply.chunk_len;
    }
    assert(strcmp(output, "fixture repaired and verified") == 0);

    struct harness_reply_result metric_reply;
    assert(agent_task_gateway_metrics(begin_reply.task_id, &metric_reply)
           == AGENT_TASK_OK);
    assert(metric_reply.model_calls == 3u);
    assert(metric_reply.verification_exit_code == 0);

    /* Declaring NetworkCap in task data does not install it. */
    struct agent_task_reply_begin denied_begin;
    assert(begin_task(HARNESS_CAP_MODEL | HARNESS_CAP_NETWORK,
                      sizeof(prompt) - 1u, &denied_begin) == AGENT_TASK_OK);
    write_prompt(denied_begin.task_id, prompt, sizeof(prompt) - 1u);
    run.task_id = denied_begin.task_id;
    assert(agent_task_gateway_run(&run, &run_reply) == AGENT_TASK_OK);
    assert(run_reply.harness_status == HARNESS_ERR_CAP_DENIED);
    assert(run_reply.used_caps == 0u);

    /* A fresh task receives a unique controller-owned identifier. */
    struct agent_task_reply_begin next_begin;
    assert(begin_task(HARNESS_CAP_MODEL, sizeof(prompt) - 1u, &next_begin)
           == AGENT_TASK_OK);
    assert(next_begin.task_id != denied_begin.task_id);

    /* The legacy adapter and Fractal v1 boundary have separate opcodes and
     * preserve the stale/revoked/nonblocking contract taxonomy. */
    assert(MSG_FRACTAL_PROGRAM_OPEN != MSG_FRACTAL_TASK_SUBMIT);
    assert(MSG_FRACTAL_TASK_POLL != MSG_FRACTAL_TASK_RESULT);
    assert(AGENT_TASK_ERR_STALE_HANDLE != AGENT_TASK_ERR_REVOKED);
    assert(AGENT_TASK_ERR_REVOKED != AGENT_TASK_ERR_AUTHORITY);
    assert(AGENT_TASK_NONBLOCKING == 1u);
    assert(sizeof(ProgramHandle) == sizeof(TaskHandle));

    puts("agent task gateway tests: ok");
    return 0;
}
