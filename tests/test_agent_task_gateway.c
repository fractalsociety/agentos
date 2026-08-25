#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../kernel/fractalos-root-task/include/contracts/agent_harness_contract.h"
#include "../kernel/fractalos-root-task/include/contracts/eventbus_contract.h"
#include "../kernel/fractalos-root-task/include/fractalos.h"
#include "../kernel/fractalos-root-task/include/agent_task_gateway.h"

static uint8_t arena[HARNESS_SHMEM_SIZE];
static uint32_t installed_caps;
static uint32_t authority_epoch;
static uint32_t submit_calls;
static struct eventbus_agent_event recorded_events[128];
static uint32_t recorded_event_count;

uint32_t fractalos_eventbus_record(struct eventbus_agent_event *event)
{
    if (event == NULL || recorded_event_count >= 128u)
        return EVENTBUS_AGENT_EVENT_ERR_INVALID;
    event->schema_version = EVENTBUS_AGENT_EVENT_SCHEMA_VERSION;
    event->position = recorded_event_count + 1u;
    if (recorded_event_count != 0u)
        event->previous_hash = recorded_events[recorded_event_count - 1u]
            .event_hash;
    eventbus_agent_event_hash(event, &event->event_hash);
    recorded_events[recorded_event_count++] = *event;
    return EVENTBUS_AGENT_EVENT_OK;
}

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

static uint32_t queue_calls;
static uint32_t queue_status;

static uint32_t enqueue(const struct agent_task_req_submit *req,
                        const struct agent_task_handle *task, void *ctx)
{
    (void)ctx;
    assert(req != NULL);
    assert(task != NULL && task->slot != 0u && task->generation != 0u);
    queue_calls++;
    return queue_status;
}

static struct agent_task_budget fractal_budget(void)
{
    return (struct agent_task_budget){
        .cpu_quanta = 100u,
        .memory_bytes = 4096u,
        .max_steps = 32u,
        .max_result_bytes = 128u,
    };
}

static uint32_t recorded_type_count(uint32_t event_type)
{
    uint32_t count = 0u;
    for (uint32_t i = 0u; i < recorded_event_count; i++)
        if (recorded_events[i].event_type == event_type) count++;
    return count;
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

    /* The asynchronous bridge binds every operation to the opening badge,
     * keeps ObjectIDs non-zero and scoped, and queues before any worker can
     * execute. */
    recorded_event_count = 0u;
    queue_calls = 0u;
    queue_status = AGENT_TASK_OK;
    authority_epoch = 11u;
    agent_task_gateway_init(arena, sizeof(arena), submit, metrics,
                            authority, NULL);
    agent_task_gateway_set_enqueue(enqueue);

    struct agent_task_req_program_open open = {0};
    open.program.program_version = 1u;
    open.program.interface_version = AGENT_TASK_FRACTAL_V1_VERSION;
    open.authority_epoch = authority_epoch;
    open.nonblocking = AGENT_TASK_NONBLOCKING;
    struct agent_task_reply_program_open open_reply;
    assert(agent_task_gateway_program_open(AGENT_TASK_GATEWAY_RIGHT, &open,
                                           &open_reply) == AGENT_TASK_ERR_INVALID);
    open.program.digest[0] = 0xA5u;
    open.authority_epoch--;
    assert(agent_task_gateway_program_open(AGENT_TASK_GATEWAY_RIGHT, &open,
                                           &open_reply) == AGENT_TASK_ERR_AUTHORITY);
    open.authority_epoch = authority_epoch;
    assert(agent_task_gateway_program_open(AGENT_TASK_GATEWAY_RIGHT,
                                           &open, &open_reply)
           == AGENT_TASK_OK);
    assert(open_reply.program.slot != 0u && open_reply.program.generation != 0u);

    struct agent_task_req_program_poll program_poll = {
        .program = open_reply.program,
        .authority_epoch = authority_epoch,
        .nonblocking = AGENT_TASK_NONBLOCKING,
    };
    struct agent_task_reply_program_poll program_poll_reply;
    assert(agent_task_gateway_program_poll(AGENT_TASK_GATEWAY_RIGHT | 4u,
                                           &program_poll, &program_poll_reply)
           == AGENT_TASK_ERR_DENIED);

    struct agent_task_req_submit fractal_submit = {
        .program = open_reply.program,
        .budget = fractal_budget(),
        .authority_epoch = authority_epoch,
        .nonblocking = AGENT_TASK_NONBLOCKING,
        .task_flags = HARNESS_TASK_ALLOW_PATCH | HARNESS_TASK_REQUIRE_TEST,
    };
    struct agent_task_reply_submit fractal_reply;
    fractal_submit.task_flags = 4u;
    assert(agent_task_gateway_submit(AGENT_TASK_GATEWAY_RIGHT,
                                     &fractal_submit, &fractal_reply)
           == AGENT_TASK_ERR_DENIED);
    fractal_submit.task_flags = HARNESS_TASK_ALLOW_PATCH
        | HARNESS_TASK_REQUIRE_TEST;
    assert(agent_task_gateway_submit(AGENT_TASK_GATEWAY_RIGHT,
                                     &fractal_submit, &fractal_reply)
           == AGENT_TASK_OK);
    assert(queue_calls == 1u);
    assert(fractal_reply.state == AGENT_TASK_STATE_ACCEPTED);
    assert(recorded_type_count(EVENTBUS_EVENT_NESTED_CALL) == 1u);
    assert(recorded_type_count(EVENTBUS_EVENT_BUDGET) == 1u);
    assert(!eventbus_event_hash_zero(&recorded_events[0].task_id));
    assert(!eventbus_event_hash_zero(&recorded_events[0].scope_id));

    struct agent_task_req_budget bad_budget = {
        .task = fractal_reply.task,
        .authority_epoch = authority_epoch,
        .nonblocking = AGENT_TASK_NONBLOCKING,
        .budget = fractal_budget(),
    };
    struct agent_task_reply_budget bad_budget_reply;
    bad_budget.budget.cpu_quanta = 0u;
    assert(agent_task_gateway_budget(AGENT_TASK_GATEWAY_RIGHT,
                                     &bad_budget, &bad_budget_reply)
           == AGENT_TASK_ERR_INVALID);

    struct agent_task_req_poll fractal_poll = {
        .task = fractal_reply.task,
        .authority_epoch = authority_epoch,
        .nonblocking = AGENT_TASK_NONBLOCKING,
    };
    struct agent_task_reply_poll fractal_poll_reply;
    assert(agent_task_gateway_poll(AGENT_TASK_GATEWAY_RIGHT | 4u,
                                   &fractal_poll, &fractal_poll_reply)
           == AGENT_TASK_ERR_DENIED);

    struct eventbus_agent_event completion = recorded_events[0];
    completion.event_type = EVENTBUS_EVENT_EFFECT;
    completion.flags = EVENTBUS_EVENT_FLAG_EXTERNAL_EFFECT
        | EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE;
    completion.payload_root.bytes[0] = 0x5Au;
    completion.scope_id.bytes[0] ^= 1u;
    eventbus_agent_event_hash(&completion, &completion.event_hash);
    agent_task_gateway_authenticated_event(&completion);
    assert(agent_task_gateway_poll(AGENT_TASK_GATEWAY_RIGHT, &fractal_poll,
                                   &fractal_poll_reply) == AGENT_TASK_OK);
    assert(fractal_poll_reply.state == AGENT_TASK_STATE_ACCEPTED);
    completion.scope_id = recorded_events[0].scope_id;
    eventbus_agent_event_hash(&completion, &completion.event_hash);
    agent_task_gateway_authenticated_event(&completion);
    assert(agent_task_gateway_poll(AGENT_TASK_GATEWAY_RIGHT, &fractal_poll,
                                   &fractal_poll_reply) == AGENT_TASK_OK);
    assert(fractal_poll_reply.state == AGENT_TASK_STATE_COMPLETE);

    struct agent_task_req_verify verify = {0};
    verify.task = fractal_reply.task;
    verify.authority_epoch = authority_epoch;
    verify.nonblocking = AGENT_TASK_NONBLOCKING;
    verify.evidence.evidence_version = AGENT_TASK_VERIFY_VERSION;
    verify.evidence.proof_level = AGENT_TASK_PROOF_HOST_CONTRACT;
    verify.evidence.test_count = 1u;
    verify.evidence.commit_digest[0] = 1u;
    verify.evidence.test_digest[0] = 2u;
    verify.evidence.evidence_digest[0] = 3u;
    struct agent_task_reply_verify verify_reply;
    assert(agent_task_gateway_verify(AGENT_TASK_GATEWAY_RIGHT, &verify,
                                     &verify_reply) == AGENT_TASK_OK);
    assert(verify_reply.verify_status == AGENT_TASK_VERIFY_ACCEPTED);
    assert(verify_reply.feedback_code == AGENT_TASK_FEEDBACK_NONE);
    assert(recorded_type_count(EVENTBUS_EVENT_TASK_VERIFY) == 1u);

    /* v1 VERIFY cannot mint commit/promotion authority. */
    struct agent_task_req_verify legacy = verify;
    legacy.evidence.evidence_version = AGENT_TASK_VERIFY_VERSION_V1;
    assert(agent_task_gateway_verify(AGENT_TASK_GATEWAY_RIGHT, &legacy,
                                     &verify_reply)
           == AGENT_TASK_ERR_PROMOTION_FORBIDDEN);
    assert(verify_reply.verify_status == AGENT_TASK_VERIFY_REJECTED);
    assert(verify_reply.feedback_code == AGENT_TASK_FEEDBACK_POLICY);

    /* Incomplete v2 evidence returns repair-safe rejection, not promotion data. */
    struct agent_task_req_verify incomplete = verify;
    incomplete.evidence.test_count = 0u;
    assert(agent_task_gateway_verify(AGENT_TASK_GATEWAY_RIGHT, &incomplete,
                                     &verify_reply) == AGENT_TASK_OK);
    assert(verify_reply.verify_status == AGENT_TASK_VERIFY_REJECTED);
    assert(verify_reply.feedback_code
           == AGENT_TASK_FEEDBACK_EVIDENCE_INCOMPLETE);

    /* Re-admit canonical evidence after the repair-safe reject. */
    assert(agent_task_gateway_verify(AGENT_TASK_GATEWAY_RIGHT, &verify,
                                     &verify_reply) == AGENT_TASK_OK);
    assert(verify_reply.verify_status == AGENT_TASK_VERIFY_ACCEPTED);

    struct agent_task_req_commit commit = {0};
    commit.task = fractal_reply.task;
    commit.authority_epoch = authority_epoch;
    commit.nonblocking = AGENT_TASK_NONBLOCKING;
    commit.candidate_root[0] = 1u;
    commit.evidence_sequence = verify_reply.evidence_sequence;
    struct agent_task_reply_commit commit_reply;
    assert(agent_task_gateway_commit(AGENT_TASK_GATEWAY_RIGHT, &commit,
                                     &commit_reply) == AGENT_TASK_OK);
    assert(commit_reply.consumed == 1u);

    /* Unconsumed evidence is single-use. */
    assert(agent_task_gateway_commit(AGENT_TASK_GATEWAY_RIGHT, &commit,
                                     &commit_reply)
           == AGENT_TASK_ERR_VERIFY_REQUIRED);

    struct agent_task_req_terminal_result terminal = {
        .task = fractal_reply.task,
        .authority_epoch = authority_epoch,
        .nonblocking = AGENT_TASK_NONBLOCKING,
    };
    struct agent_task_reply_terminal_result terminal_reply;
    assert(agent_task_gateway_terminal_result(AGENT_TASK_GATEWAY_RIGHT,
                                              &terminal, &terminal_reply)
           == AGENT_TASK_OK);
    assert(terminal_reply.result_kind == AGENT_TASK_RESULT_VALUE);
    assert(terminal_reply.verify_status == AGENT_TASK_VERIFY_ACCEPTED);

    /* A queue rejection is a terminal, authenticated failure rather than a
     * lost task. Cancellation likewise records a candidate-visible event. */
    recorded_event_count = 0u;
    queue_calls = 0u;
    queue_status = AGENT_TASK_ERR_HARNESS;
    agent_task_gateway_init(arena, sizeof(arena), submit, metrics,
                            authority, NULL);
    agent_task_gateway_set_enqueue(enqueue);
    assert(agent_task_gateway_program_open(AGENT_TASK_GATEWAY_RIGHT, &open,
                                           &open_reply) == AGENT_TASK_OK);
    fractal_submit.program = open_reply.program;
    fractal_submit.authority_epoch = authority_epoch;
    assert(agent_task_gateway_submit(AGENT_TASK_GATEWAY_RIGHT, &fractal_submit,
                                     &fractal_reply) == AGENT_TASK_ERR_HARNESS);
    assert(fractal_reply.state == AGENT_TASK_STATE_FAILED);
    assert(recorded_type_count(EVENTBUS_EVENT_TASK) == 1u);

    recorded_event_count = 0u;
    queue_status = AGENT_TASK_OK;
    agent_task_gateway_init(arena, sizeof(arena), submit, metrics,
                            authority, NULL);
    agent_task_gateway_set_enqueue(enqueue);
    assert(agent_task_gateway_program_open(AGENT_TASK_GATEWAY_RIGHT, &open,
                                           &open_reply) == AGENT_TASK_OK);
    fractal_submit.program = open_reply.program;
    assert(agent_task_gateway_submit(AGENT_TASK_GATEWAY_RIGHT, &fractal_submit,
                                     &fractal_reply) == AGENT_TASK_OK);
    struct agent_task_req_cancel cancel = {
        .task = fractal_reply.task,
        .authority_epoch = authority_epoch,
        .nonblocking = AGENT_TASK_NONBLOCKING,
    };
    struct agent_task_reply_cancel cancel_reply;
    assert(agent_task_gateway_cancel(AGENT_TASK_GATEWAY_RIGHT, &cancel,
                                     &cancel_reply) == AGENT_TASK_OK);
    assert(cancel_reply.state == AGENT_TASK_STATE_CANCELLED);
    assert(recorded_type_count(EVENTBUS_EVENT_TASK) == 1u);

    puts("agent task gateway tests: ok");
    return 0;
}
