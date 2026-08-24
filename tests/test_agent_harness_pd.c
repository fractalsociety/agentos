/* Host tests for the production native AgentHarness PD core. */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define AGENTOS_TEST_HOST 1
#include "../userspace/agents/codex-harness/codex_harness_pd.c"

static uint8_t arena[HARNESS_SHMEM_SIZE];
static uint32_t model_calls;
static const char *model_reply;
static uint32_t model_status;
static bool model_echo_after_first;
static uint32_t memory_calls;
static const char *memory_next;
static char memory_path[AGENTFS_PATH_MAX];
static char memory_content[HARNESS_TOOL_SCRATCH_CAP];
static uint32_t exec_calls;
static uint32_t test_calls;
static bool test_fail_first;

static const char *latest_observation(const char *prompt, uint32_t prompt_len,
                                      uint32_t *observation_len)
{
    static const char marker[] = "\nObservation:\n";
    static const char end[] = "\nContinue the original task";
    const char *latest = NULL;
    for (uint32_t i = 0u; i + sizeof(marker) - 1u <= prompt_len; i++)
        if (memcmp(prompt + i, marker, sizeof(marker) - 1u) == 0)
            latest = prompt + i + sizeof(marker) - 1u;
    assert(latest != NULL);
    uint32_t remaining = prompt_len - (uint32_t)(latest - prompt);
    for (uint32_t i = 0u; i + sizeof(end) - 1u <= remaining; i++) {
        if (memcmp(latest + i, end, sizeof(end) - 1u) == 0) {
            *observation_len = i;
            return latest;
        }
    }
    assert(false);
    return NULL;
}

static uint32_t fake_model(const char *system_prompt,
                           uint32_t system_prompt_len,
                           const char *user_prompt,
                           uint32_t user_prompt_len,
                           const char *model_id,
                           uint32_t model_id_len,
                           char *response,
                           uint32_t response_capacity,
                           uint32_t *response_len,
                           uint32_t *tokens_in,
                           uint32_t *tokens_out,
                           void *ctx)
{
    (void)system_prompt;
    (void)system_prompt_len;
    (void)user_prompt;
    (void)user_prompt_len;
    (void)model_id;
    (void)model_id_len;
    (void)ctx;
    model_calls++;
    if (model_status != HARNESS_OK) return model_status;
    uint32_t len = 0u;
    const char *selected;
    if (model_echo_after_first && model_calls > 1u)
        selected = latest_observation(user_prompt, user_prompt_len, &len);
    else {
        selected = model_reply;
        len = (uint32_t)strlen(selected);
    }
    assert(len + 1u <= response_capacity);
    memcpy(response, selected, len);
    response[len] = '\0';
    *response_len = len;
    *tokens_in = 11u;
    *tokens_out = 7u;
    return HARNESS_OK;
}

static uint32_t fake_tool(const char *name, uint32_t name_len,
                          const char *input, uint32_t input_len,
                          char *output, uint32_t output_capacity,
                          uint32_t *output_len, void *ctx)
{
    (void)ctx;
    assert(name_len == strlen("agent.echo"));
    assert(memcmp(name, "agent.echo", name_len) == 0);
    assert(input_len + 1u <= output_capacity);
    memcpy(output, input, input_len);
    output[input_len] = '\0';
    *output_len = input_len;
    return HARNESS_OK;
}

static uint32_t fake_memory(bool write, const char *path, uint32_t path_len,
                            const char *content, uint32_t content_len,
                            char *output, uint32_t output_capacity,
                            uint32_t *output_len, void *ctx)
{
    (void)ctx;
    assert(path_len + 1u <= sizeof(memory_path));
    memcpy(memory_path, path, path_len);
    memory_path[path_len] = '\0';
    memory_calls++;
    if (!write) {
        uint32_t len = (uint32_t)strlen(memory_content);
        assert(len + 1u <= output_capacity);
        memcpy(output, memory_content, len + 1u);
        *output_len = len;
        return HARNESS_OK;
    }
    assert(content_len + 1u <= sizeof(memory_content));
    memcpy(memory_content, content, content_len);
    memory_content[content_len] = '\0';
    const char *next = memory_next != NULL ? memory_next
        : "{\"action\":\"final\",\"summary\":\"edit-written\"}";
    uint32_t next_len = (uint32_t)strlen(next);
    assert(next_len + 1u <= output_capacity);
    memcpy(output, next, next_len + 1u);
    *output_len = next_len;
    return HARNESS_OK;
}

static uint32_t fake_exec(const char *actual, uint32_t actual_len,
                          const char *expected, uint32_t expected_len,
                          int32_t *exit_code,
                          char *output, uint32_t output_capacity,
                          uint32_t *output_len, void *ctx)
{
    (void)ctx;
    exec_calls++;
    *exit_code = actual_len == expected_len
        && memcmp(actual, expected, actual_len) == 0 ? 0 : 1;
    static const char next[] =
        "{\"action\":\"final\",\"summary\":\"edit-verified\"}";
    assert(sizeof(next) <= output_capacity);
    memcpy(output, next, sizeof(next));
    *output_len = sizeof(next) - 1u;
    return HARNESS_OK;
}

static uint32_t fake_test(uint32_t profile_id,
                          const char *source, uint32_t source_len,
                          int32_t *exit_code,
                          char *output, uint32_t output_capacity,
                          uint32_t *output_len, void *ctx)
{
    (void)ctx;
    assert(profile_id == EXECSVC_PROFILE_C11_COMPILE);
    static const char expected[] = "int answer(void) { return 42; }\n";
    test_calls++;
    if (test_fail_first && test_calls == 1u) {
        *exit_code = 1;
        static const char repair[] =
            "{\"action\":\"memory_write\",\"path\":\"src/answer.c\","
            "\"content\":\"int answer(void) { return 42; }\\n\"}";
        assert(sizeof(repair) <= output_capacity);
        memcpy(output, repair, sizeof(repair));
        *output_len = sizeof(repair) - 1u;
        return HARNESS_OK;
    }
    assert(source_len == sizeof(expected) - 1u);
    assert(memcmp(source, expected, source_len) == 0);
    *exit_code = 0;
    static const char next[] =
        "{\"action\":\"final\",\"summary\":\"compile-verified\"}";
    assert(sizeof(next) <= output_capacity);
    memcpy(output, next, sizeof(next));
    *output_len = sizeof(next) - 1u;
    return HARNESS_OK;
}

static struct harness_req_submit request(uint32_t required_caps)
{
    static const char prompt[] = "repair the workspace";
    static const char model[] = "agentos-echo";
    memcpy(arena + 0x1000u, prompt, sizeof(prompt));
    memcpy(arena + 0x2000u, model, sizeof(model));
    return (struct harness_req_submit){
        .task_id = 42u,
        .harness_kind = HARNESS_KIND_CODEX,
        .required_caps = required_caps,
        .max_steps = 8u,
        .authority_epoch = 7u,
        .prompt_offset = 0x1000u,
        .prompt_len = sizeof(prompt) - 1u,
        .result_offset = 0x3000u,
        .result_capacity = 512u,
        .model_id_offset = 0x2000u,
        .model_id_len = sizeof(model) - 1u,
    };
}

static void reset(uint32_t installed_caps)
{
    memset(arena, 0, sizeof(arena));
    model_calls = 0u;
    model_reply = "{\"action\":\"final\",\"summary\":\"done\"}";
    model_status = HARNESS_OK;
    model_echo_after_first = false;
    memory_calls = 0u;
    memory_next = NULL;
    exec_calls = 0u;
    test_calls = 0u;
    test_fail_first = false;
    memory_path[0] = '\0';
    memory_content[0] = '\0';
    harness_runtime_init(arena, sizeof(arena), installed_caps, 7u,
                         fake_model, NULL);
}

static void test_compile_action_reads_agentfs_and_uses_profiled_exec(void)
{
    struct harness_reply_submit submit;
    struct harness_reply_result result;
    reset(HARNESS_CAP_MODEL | HARNESS_CAP_MEMORY | HARNESS_CAP_EXEC);
    static const char source[] = "int answer(void) { return 42; }\n";
    memcpy(memory_content, source, sizeof(source));
    model_reply = "{\"action\":\"test\",\"path\":\"src/answer.c\","
                  "\"profile\":\"c11_compile\"}";
    model_echo_after_first = true;
    harness_runtime_set_memory_backend(fake_memory, NULL);
    harness_runtime_set_test_backend(fake_test, NULL);
    struct harness_req_submit req = request(
        HARNESS_CAP_MODEL | HARNESS_CAP_MEMORY | HARNESS_CAP_EXEC);
    req.task_flags = HARNESS_TASK_REQUIRE_TEST;
    assert(harness_runtime_submit(&req, &submit) == HARNESS_OK);
    assert(strcmp((char *)arena + req.result_offset, "compile-verified") == 0);
    assert(strcmp(memory_path, "src/answer.c") == 0);
    assert(test_calls == 1u);
    assert(harness_runtime_result(req.task_id, &result) == HARNESS_OK);
    assert(result.memory_ops == 1u);
    assert(result.exec_calls == 1u);
    assert(result.verification_exit_code == 0);

    reset(HARNESS_CAP_MODEL | HARNESS_CAP_MEMORY);
    model_reply = "{\"action\":\"test\",\"path\":\"src/answer.c\","
                  "\"profile\":\"c11_compile\"}";
    harness_runtime_set_memory_backend(fake_memory, NULL);
    req = request(HARNESS_CAP_MODEL | HARNESS_CAP_MEMORY);
    assert(harness_runtime_submit(&req, &submit) == HARNESS_ERR_CAP_DENIED);
    assert(test_calls == 0u);
}

static void test_failed_compile_is_observed_and_can_be_repaired(void)
{
    struct harness_reply_submit submit;
    struct harness_reply_result result;
    reset(HARNESS_CAP_MODEL | HARNESS_CAP_MEMORY | HARNESS_CAP_EXEC);
    memcpy(memory_content, "int answer(void) { return ; }\n",
           sizeof("int answer(void) { return ; }\n"));
    model_reply = "{\"action\":\"test\",\"path\":\"src/answer.c\","
                  "\"profile\":\"c11_compile\"}";
    model_echo_after_first = true;
    test_fail_first = true;
    memory_next = "{\"action\":\"test\",\"path\":\"src/answer.c\","
                  "\"profile\":\"c11_compile\"}";
    harness_runtime_set_memory_backend(fake_memory, NULL);
    harness_runtime_set_test_backend(fake_test, NULL);
    struct harness_req_submit req = request(
        HARNESS_CAP_MODEL | HARNESS_CAP_MEMORY | HARNESS_CAP_EXEC);
    req.task_flags = HARNESS_TASK_REQUIRE_TEST;
    assert(harness_runtime_submit(&req, &submit) == HARNESS_OK);
    assert(strcmp((char *)arena + req.result_offset, "compile-verified") == 0);
    assert(test_calls == 2u);
    assert(harness_runtime_result(req.task_id, &result) == HARNESS_OK);
    assert(result.model_calls == 4u);
    assert(result.memory_ops == 3u);
    assert(result.exec_calls == 2u);
    assert(result.verification_exit_code == 0);
}

static void test_verify_reads_memory_and_requires_exec_success(void)
{
    struct harness_reply_submit submit;
    struct harness_reply_result result;
    reset(HARNESS_CAP_MODEL | HARNESS_CAP_MEMORY | HARNESS_CAP_EXEC);
    memcpy(memory_content, "after\n", 7u);
    model_reply = "{\"action\":\"verify\",\"path\":\"src/answer.txt\","
                  "\"expected\":\"after\\n\"}";
    model_echo_after_first = true;
    harness_runtime_set_memory_backend(fake_memory, NULL);
    harness_runtime_set_exec_backend(fake_exec, NULL);
    struct harness_req_submit req = request(
        HARNESS_CAP_MODEL | HARNESS_CAP_MEMORY | HARNESS_CAP_EXEC);
    req.task_flags = HARNESS_TASK_REQUIRE_TEST;
    assert(harness_runtime_submit(&req, &submit) == HARNESS_OK);
    assert(strcmp((char *)arena + req.result_offset, "edit-verified") == 0);
    assert(harness_runtime_result(req.task_id, &result) == HARNESS_OK);
    assert(result.model_calls == 2u);
    assert(result.memory_ops == 1u);
    assert(result.exec_calls == 1u);
    assert(result.verification_exit_code == 0);
    assert(result.used_caps == (HARNESS_CAP_MODEL | HARNESS_CAP_MEMORY
                                | HARNESS_CAP_EXEC));
}

static void test_memory_write_uses_memory_cap_and_returns_to_model(void)
{
    struct harness_reply_submit submit;
    struct harness_reply_result result;
    reset(HARNESS_CAP_MODEL | HARNESS_CAP_MEMORY);
    model_reply = "{\"action\":\"memory_write\","
                  "\"path\":\"src/answer.txt\",\"content\":\"after\\n\"}";
    model_echo_after_first = true;
    harness_runtime_set_memory_backend(fake_memory, NULL);
    struct harness_req_submit req = request(HARNESS_CAP_MODEL
                                             | HARNESS_CAP_MEMORY);
    assert(harness_runtime_submit(&req, &submit) == HARNESS_OK);
    assert(strcmp((char *)arena + req.result_offset, "edit-written") == 0);
    assert(strcmp(memory_path, "src/answer.txt") == 0);
    assert(strcmp(memory_content, "after\n") == 0);
    assert(harness_runtime_result(req.task_id, &result) == HARNESS_OK);
    assert(result.model_calls == 2u);
    assert(result.memory_ops == 1u);
    assert(result.used_caps == (HARNESS_CAP_MODEL | HARNESS_CAP_MEMORY));

    reset(HARNESS_CAP_MODEL);
    model_reply = "{\"action\":\"memory_write\","
                  "\"path\":\"src/answer.txt\",\"content\":\"after\"}";
    req = request(HARNESS_CAP_MODEL);
    assert(harness_runtime_submit(&req, &submit) == HARNESS_ERR_CAP_DENIED);
    assert(memory_calls == 0u);
}

static void test_tool_action_uses_distinct_capability_and_returns_to_model(void)
{
    struct harness_reply_submit submit;
    struct harness_reply_result result;
    reset(HARNESS_CAP_MODEL | HARNESS_CAP_TOOL);
    model_reply = "{\"action\":\"tool\",\"tool\":\"agent.echo\","
                  "\"input\":\"{\\\"action\\\":\\\"final\\\","
                  "\\\"summary\\\":\\\"tool-ok\\\"}\"}";
    model_echo_after_first = true;
    harness_runtime_set_tool_backend(fake_tool, NULL);
    struct harness_req_submit req = request(HARNESS_CAP_MODEL | HARNESS_CAP_TOOL);
    assert(harness_runtime_submit(&req, &submit) == HARNESS_OK);
    assert(strcmp((char *)arena + req.result_offset, "tool-ok") == 0);
    assert(harness_runtime_result(req.task_id, &result) == HARNESS_OK);
    assert(result.model_calls == 2u);
    assert(result.tool_calls == 1u);
    assert(result.used_caps == (HARNESS_CAP_MODEL | HARNESS_CAP_TOOL));

    reset(HARNESS_CAP_MODEL);
    model_reply = "{\"action\":\"tool\",\"tool\":\"agent.echo\","
                  "\"input\":\"{}\"}";
    req = request(HARNESS_CAP_MODEL);
    assert(harness_runtime_submit(&req, &submit) == HARNESS_ERR_CAP_DENIED);
}

static void test_missing_authority_denies_before_model(void)
{
    struct harness_reply_submit rep;
    reset(0u);
    struct harness_req_submit req = request(HARNESS_CAP_MODEL);
    assert(harness_runtime_submit(&req, &rep) == HARNESS_ERR_CAP_DENIED);
    assert(rep.available_caps == 0u);
    assert(model_calls == 0u);

    reset(HARNESS_CAP_MODEL);
    req = request(HARNESS_CAP_MODEL | HARNESS_CAP_NETWORK);
    assert(harness_runtime_submit(&req, &rep) == HARNESS_ERR_CAP_DENIED);
    assert(model_calls == 0u);
}

static void test_bounds_and_epoch_are_checked(void)
{
    struct harness_reply_submit rep;
    reset(HARNESS_CAP_MODEL);
    struct harness_req_submit req = request(HARNESS_CAP_MODEL);
    req.prompt_offset = HARNESS_SHMEM_SIZE - 2u;
    req.prompt_len = 16u;
    assert(harness_runtime_submit(&req, &rep) == HARNESS_ERR_INVALID);
    assert(model_calls == 0u);

    req = request(HARNESS_CAP_MODEL);
    req.authority_epoch++;
    assert(harness_runtime_submit(&req, &rep) == HARNESS_ERR_CAP_DENIED);
    assert(model_calls == 0u);
}

static void test_final_action_completes_and_exports_metrics(void)
{
    struct harness_reply_submit submit;
    struct harness_reply_result result;
    reset(HARNESS_CAP_MODEL);
    struct harness_req_submit req = request(HARNESS_CAP_MODEL);
    assert(harness_runtime_submit(&req, &submit) == HARNESS_OK);
    assert(submit.state == HARNESS_STATE_COMPLETE);
    assert(strcmp((char *)arena + req.result_offset, "done") == 0);
    assert(harness_runtime_result(req.task_id, &result) == HARNESS_OK);
    assert(result.model_calls == 1u);
    assert(result.tokens_in == 11u);
    assert(result.tokens_out == 7u);
    assert(result.used_caps == HARNESS_CAP_MODEL);
}

static void test_protocol_and_backend_failures_are_reported(void)
{
    struct harness_reply_submit submit;
    struct harness_reply_status status;
    reset(HARNESS_CAP_MODEL);
    model_reply = "not json";
    struct harness_req_submit req = request(HARNESS_CAP_MODEL);
    assert(harness_runtime_submit(&req, &submit) == HARNESS_ERR_PROTOCOL);
    assert(harness_runtime_status(req.task_id, &status) == HARNESS_OK);
    assert(status.state == HARNESS_STATE_FAILED);
    assert(status.last_error == HARNESS_ERR_PROTOCOL);

    reset(HARNESS_CAP_MODEL);
    model_status = HARNESS_ERR_MODEL;
    req = request(HARNESS_CAP_MODEL);
    assert(harness_runtime_submit(&req, &submit) == HARNESS_ERR_MODEL);
    assert(model_calls == 1u);
}

static void test_verification_requires_exec_cap(void)
{
    struct harness_reply_submit rep;
    reset(HARNESS_CAP_MODEL);
    struct harness_req_submit req = request(HARNESS_CAP_MODEL);
    req.task_flags = HARNESS_TASK_REQUIRE_TEST;
    assert(harness_runtime_submit(&req, &rep) == HARNESS_ERR_CAP_DENIED);
    assert(model_calls == 0u);
}

static void test_shared_memory_is_not_charged_per_worker(void)
{
    struct harness_reply_resources resources;
    reset(HARNESS_CAP_MODEL);
    harness_runtime_set_resources(12u * 1024u * 1024u,
                                  64u * 1024u * 1024u,
                                  HARNESS_SHMEM_SIZE,
                                  HARNESS_SHARED_MODELSVC |
                                      HARNESS_SHARED_REPO_INDEX);
    assert(harness_runtime_resources(&resources) == HARNESS_OK);
    assert(resources.private_committed_bytes == 12u * 1024u * 1024u);
    assert(resources.shared_mapped_bytes == HARNESS_SHMEM_SIZE);
    assert(resources.private_limit_bytes == 64u * 1024u * 1024u);
    assert(resources.target_low_bytes == 20u * 1024u * 1024u);
    assert(resources.target_high_bytes == 150u * 1024u * 1024u);

    harness_runtime_set_resources(151u * 1024u * 1024u,
                                  200u * 1024u * 1024u,
                                  HARNESS_SHMEM_SIZE,
                                  HARNESS_SHARED_MODELSVC);
    assert(harness_runtime_resources(&resources) == HARNESS_ERR_MEMORY);
    assert(resources.private_limit_bytes == HARNESS_WORKER_MAX_BYTES);
}

int main(void)
{
    test_missing_authority_denies_before_model();
    test_bounds_and_epoch_are_checked();
    test_final_action_completes_and_exports_metrics();
    test_tool_action_uses_distinct_capability_and_returns_to_model();
    test_memory_write_uses_memory_cap_and_returns_to_model();
    test_verify_reads_memory_and_requires_exec_success();
    test_compile_action_reads_agentfs_and_uses_profiled_exec();
    test_failed_compile_is_observed_and_can_be_repaired();
    test_protocol_and_backend_failures_are_reported();
    test_verification_requires_exec_cap();
    test_shared_memory_is_not_charged_per_worker();
    puts("agent harness PD tests: ok");
    return 0;
}
