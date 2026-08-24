/*
 * Native AgentHarness protection-domain adapter.
 *
 * This bootstrap adapter implements the capability-checking control plane and
 * real ModelSvc planner turns plus capability-bound ToolSvc dispatch. It has
 * no network client and no ambient service lookup. Additional action backends
 * must be added as distinct capability-bound calls.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../../../kernel/agentos-root-task/include/contracts/agent_harness_contract.h"
#include "../../../contracts/toolsvc/interface.h"
#include "../../../contracts/execsvc/interface.h"
#include "../../../kernel/agentos-root-task/include/contracts/agentfs_contract.h"

#define HARNESS_SYSTEM_PROMPT_OFFSET 0x8000u
#define HARNESS_SYSTEM_PROMPT_CAP    4096u
#define HARNESS_MODEL_CONTEXT_OFFSET 0x9000u
#define HARNESS_MODEL_CONTEXT_CAP    0x3000u
#define HARNESS_TOOL_INPUT_OFFSET    0x8000u
#define HARNESS_TOOL_OUTPUT_OFFSET   0x9000u
#define HARNESS_TOOL_SCRATCH_CAP     4096u
#define HARNESS_EXEC_OUTPUT_OFFSET   0xb000u
#define HARNESS_INTERNAL_OFFSET      HARNESS_TOOL_INPUT_OFFSET
#define HARNESS_INTERNAL_CAP         0x4000u
#define HARNESS_CONTEXT_CAP          HARNESS_MODEL_CONTEXT_CAP

static const char harness_system_prompt[] =
    "You are an AgentOS coding agent. Return exactly one JSON object and no "
    "markdown. Actions: {\"action\":\"memory_write\",\"path\":\"relative/path\","
    "\"content\":\"text\"}; {\"action\":\"memory_read\",\"path\":\"relative/path\"}; "
    "{\"action\":\"verify\",\"path\":\"relative/path\",\"expected\":\"text\"}; "
    "{\"action\":\"tool\",\"tool\":\"name\",\"input\":\"text\"}; or "
    "{\"action\":\"final\",\"summary\":\"result\"}. Never return final before "
    "required verification succeeds.";

typedef uint32_t (*harness_model_backend_fn)(
    const char *system_prompt, uint32_t system_prompt_len,
    const char *user_prompt, uint32_t user_prompt_len,
    const char *model_id, uint32_t model_id_len,
    char *response, uint32_t response_capacity, uint32_t *response_len,
    uint32_t *tokens_in, uint32_t *tokens_out, void *ctx);

typedef uint32_t (*harness_tool_backend_fn)(
    const char *name, uint32_t name_len,
    const char *input, uint32_t input_len,
    char *output, uint32_t output_capacity, uint32_t *output_len,
    void *ctx);

typedef uint32_t (*harness_memory_backend_fn)(
    bool write, const char *path, uint32_t path_len,
    const char *content, uint32_t content_len,
    char *output, uint32_t output_capacity, uint32_t *output_len,
    void *ctx);

typedef uint32_t (*harness_exec_backend_fn)(
    const char *actual, uint32_t actual_len,
    const char *expected, uint32_t expected_len,
    int32_t *exit_code,
    char *output, uint32_t output_capacity, uint32_t *output_len,
    void *ctx);

typedef struct {
    uint32_t task_id;
    uint32_t state;
    uint32_t step;
    uint32_t last_error;
    uint32_t result_len;
    uint32_t model_calls;
    uint32_t tool_calls;
    uint32_t memory_ops;
    uint32_t exec_calls;
    uint32_t tokens_in;
    uint32_t tokens_out;
    uint32_t used_caps;
    uint32_t denied_attempts;
    int32_t verification_exit_code;
    bool occupied;
} harness_task_state_t;

static uint8_t *runtime_arena;
static uint32_t runtime_arena_size;
static uint32_t runtime_installed_caps;
static uint32_t runtime_authority_epoch;
static harness_model_backend_fn runtime_model_backend;
static void *runtime_model_ctx;
static harness_tool_backend_fn runtime_tool_backend;
static void *runtime_tool_ctx;
static harness_memory_backend_fn runtime_memory_backend;
static void *runtime_memory_ctx;
static harness_exec_backend_fn runtime_exec_backend;
static void *runtime_exec_ctx;
static harness_task_state_t current_task;
static uint32_t runtime_private_committed_bytes;
static uint32_t runtime_private_limit_bytes;
static uint32_t runtime_shared_mapped_bytes;
static uint32_t runtime_shared_components;
static char runtime_context[HARNESS_CONTEXT_CAP];

static void bytes_zero(void *ptr, uint32_t len)
{
    uint8_t *p = (uint8_t *)ptr;
    for (uint32_t i = 0u; i < len; i++) p[i] = 0u;
}

static void bytes_copy(void *dst_ptr, const void *src_ptr, uint32_t len)
{
    uint8_t *dst = (uint8_t *)dst_ptr;
    const uint8_t *src = (const uint8_t *)src_ptr;
    for (uint32_t i = 0u; i < len; i++) dst[i] = src[i];
}

static bool bytes_equal(const char *a, uint32_t a_len,
                        const char *b, uint32_t b_len)
{
    if (a_len != b_len) return false;
    for (uint32_t i = 0u; i < a_len; i++)
        if (a[i] != b[i]) return false;
    return true;
}

static bool context_append(uint32_t *length, const char *text,
                           uint32_t text_len)
{
    if (length == NULL || text == NULL || *length > HARNESS_CONTEXT_CAP
        || text_len > HARNESS_CONTEXT_CAP - *length) return false;
    bytes_copy(runtime_context + *length, text, text_len);
    *length += text_len;
    return true;
}

static bool context_append_turn(uint32_t *length,
                                const char *action, uint32_t action_len,
                                const char *observation,
                                uint32_t observation_len)
{
    static const char action_label[] = "\nPrevious action:\n";
    static const char observation_label[] = "\nObservation:\n";
    static const char continuation[] =
        "\nContinue the original task with exactly one next JSON action.\n";
    return context_append(length, action_label, sizeof(action_label) - 1u)
        && context_append(length, action, action_len)
        && context_append(length, observation_label,
                          sizeof(observation_label) - 1u)
        && context_append(length, observation, observation_len)
        && context_append(length, continuation, sizeof(continuation) - 1u);
}

static bool arena_range(uint32_t offset, uint32_t len)
{
    return runtime_arena != NULL
        && offset <= runtime_arena_size
        && len <= runtime_arena_size - offset;
}

static bool ranges_overlap(uint32_t a_offset, uint32_t a_len,
                           uint32_t b_offset, uint32_t b_len)
{
    if (a_len == 0u || b_len == 0u) return false;
    return a_offset < b_offset + b_len && b_offset < a_offset + a_len;
}

static bool overlaps_internal(uint32_t offset, uint32_t len)
{
    return ranges_overlap(offset, len, HARNESS_INTERNAL_OFFSET,
                          HARNESS_INTERNAL_CAP);
}

static void fill_submit_reply(struct harness_reply_submit *rep,
                              uint32_t status, uint32_t task_id,
                              uint32_t state)
{
    if (rep == NULL) return;
    rep->status = status;
    rep->task_id = task_id;
    rep->available_caps = runtime_installed_caps;
    rep->state = state;
}

static uint32_t fail_task(uint32_t error,
                          struct harness_reply_submit *rep)
{
    current_task.state = HARNESS_STATE_FAILED;
    current_task.last_error = error;
    fill_submit_reply(rep, error, current_task.task_id, current_task.state);
    return error;
}

/* Locate a JSON string value for an exact quoted key. This intentionally
 * supports only the planner protocol's string fields and fails closed on
 * malformed or non-string values. */
static bool json_string(const char *json, uint32_t json_len,
                        const char *key, uint32_t key_len,
                        const char **value, uint32_t *value_len)
{
    for (uint32_t i = 0u; i + key_len + 2u <= json_len; i++) {
        if (json[i] != '"') continue;
        bool match = true;
        for (uint32_t j = 0u; j < key_len; j++) {
            if (json[i + 1u + j] != key[j]) { match = false; break; }
        }
        if (!match || json[i + 1u + key_len] != '"') continue;
        uint32_t p = i + key_len + 2u;
        while (p < json_len && (json[p] == ' ' || json[p] == '\t'
                               || json[p] == '\r' || json[p] == '\n')) p++;
        /* A matching quoted token may be a value rather than this key (for
         * example action="tool" followed by the key "tool"). Keep scanning
         * unless the token is followed by a JSON key separator. */
        if (p >= json_len || json[p] != ':') continue;
        p++;
        while (p < json_len && (json[p] == ' ' || json[p] == '\t'
                               || json[p] == '\r' || json[p] == '\n')) p++;
        if (p >= json_len || json[p++] != '"') return false;
        uint32_t start = p;
        bool escaped = false;
        while (p < json_len) {
            if (!escaped && json[p] == '"') {
                *value = json + start;
                *value_len = p - start;
                return true;
            }
            if (!escaped && json[p] == '\\') escaped = true;
            else escaped = false;
            p++;
        }
        return false;
    }
    return false;
}

static bool decode_json_string(char *dst, uint32_t dst_cap,
                               const char *src, uint32_t src_len,
                               uint32_t *written)
{
    uint32_t out = 0u;
    for (uint32_t i = 0u; i < src_len; i++) {
        char c = src[i];
        if (c == '\\') {
            if (++i >= src_len) return false;
            switch (src[i]) {
            case '"': c = '"'; break;
            case '\\': c = '\\'; break;
            case '/': c = '/'; break;
            case 'b': c = '\b'; break;
            case 'f': c = '\f'; break;
            case 'n': c = '\n'; break;
            case 'r': c = '\r'; break;
            case 't': c = '\t'; break;
            default: return false; /* unicode escapes are not accepted yet */
            }
        }
        if (out + 1u >= dst_cap) return false;
        dst[out++] = c;
    }
    if (dst_cap == 0u) return false;
    dst[out] = '\0';
    *written = out;
    return true;
}

void harness_runtime_init(void *arena, uint32_t arena_size,
                          uint32_t installed_caps, uint32_t authority_epoch,
                          harness_model_backend_fn model_backend,
                          void *model_ctx)
{
    runtime_arena = (uint8_t *)arena;
    runtime_arena_size = arena_size;
    runtime_installed_caps = installed_caps & HARNESS_CAP_KNOWN_MASK;
    runtime_authority_epoch = authority_epoch;
    runtime_model_backend = model_backend;
    runtime_model_ctx = model_ctx;
    runtime_tool_backend = NULL;
    runtime_tool_ctx = NULL;
    runtime_memory_backend = NULL;
    runtime_memory_ctx = NULL;
    runtime_exec_backend = NULL;
    runtime_exec_ctx = NULL;
    runtime_private_committed_bytes = 0u;
    runtime_private_limit_bytes = HARNESS_WORKER_DEFAULT_LIMIT_BYTES;
    runtime_shared_mapped_bytes = arena_size;
    runtime_shared_components = (installed_caps & HARNESS_CAP_MODEL) != 0u
        ? HARNESS_SHARED_MODELSVC : 0u;
    bytes_zero(&current_task, sizeof(current_task));
    current_task.state = HARNESS_STATE_IDLE;
    current_task.verification_exit_code = -1;
}

void harness_runtime_set_tool_backend(harness_tool_backend_fn tool_backend,
                                      void *tool_ctx)
{
    runtime_tool_backend = tool_backend;
    runtime_tool_ctx = tool_ctx;
}

void harness_runtime_set_memory_backend(harness_memory_backend_fn memory_backend,
                                        void *memory_ctx)
{
    runtime_memory_backend = memory_backend;
    runtime_memory_ctx = memory_ctx;
}

void harness_runtime_set_exec_backend(harness_exec_backend_fn exec_backend,
                                      void *exec_ctx)
{
    runtime_exec_backend = exec_backend;
    runtime_exec_ctx = exec_ctx;
}

void harness_runtime_set_resources(uint32_t private_committed_bytes,
                                   uint32_t private_limit_bytes,
                                   uint32_t shared_mapped_bytes,
                                   uint32_t shared_components)
{
    runtime_private_committed_bytes = private_committed_bytes;
    runtime_private_limit_bytes = private_limit_bytes <= HARNESS_WORKER_MAX_BYTES
        ? private_limit_bytes : HARNESS_WORKER_MAX_BYTES;
    runtime_shared_mapped_bytes = shared_mapped_bytes;
    runtime_shared_components = shared_components & HARNESS_SHARED_COMPONENT_MASK;
}

uint32_t harness_runtime_resources(struct harness_reply_resources *rep)
{
    if (rep == NULL) return HARNESS_ERR_INVALID;
    rep->status = runtime_private_committed_bytes <= runtime_private_limit_bytes
        ? HARNESS_OK : HARNESS_ERR_MEMORY;
    rep->private_committed_bytes = runtime_private_committed_bytes;
    rep->private_limit_bytes = runtime_private_limit_bytes;
    rep->shared_mapped_bytes = runtime_shared_mapped_bytes;
    rep->target_low_bytes = HARNESS_WORKER_TARGET_LOW_BYTES;
    rep->target_high_bytes = HARNESS_WORKER_MAX_BYTES;
    rep->shared_components = runtime_shared_components;
    rep->authority_epoch = runtime_authority_epoch;
    return rep->status;
}

uint32_t harness_runtime_submit(const struct harness_req_submit *req,
                                struct harness_reply_submit *rep)
{
    uint32_t task_id = req == NULL ? 0u : req->task_id;
    if (req == NULL || rep == NULL || req->task_id == 0u
        || req->harness_kind != HARNESS_KIND_CODEX || req->max_steps == 0u
        || req->prompt_len == 0u || req->result_capacity < 2u
        || !arena_range(req->prompt_offset, req->prompt_len)
        || !arena_range(req->result_offset, req->result_capacity)
        || !arena_range(req->model_id_offset, req->model_id_len)
        || ranges_overlap(req->prompt_offset, req->prompt_len,
                          req->result_offset, req->result_capacity)
        || ranges_overlap(req->model_id_offset, req->model_id_len,
                          req->result_offset, req->result_capacity)
        || overlaps_internal(req->prompt_offset, req->prompt_len)
        || overlaps_internal(req->result_offset, req->result_capacity)
        || overlaps_internal(req->model_id_offset, req->model_id_len)) {
        fill_submit_reply(rep, HARNESS_ERR_INVALID, task_id,
                          HARNESS_STATE_IDLE);
        return HARNESS_ERR_INVALID;
    }

    uint32_t needed = req->required_caps | HARNESS_CAP_MODEL;
    if ((req->task_flags & HARNESS_TASK_REQUIRE_TEST) != 0u)
        needed |= HARNESS_CAP_EXEC;
    if (req->authority_epoch != runtime_authority_epoch
        || !harness_authority_satisfies(needed, runtime_installed_caps)) {
        fill_submit_reply(rep, HARNESS_ERR_CAP_DENIED, req->task_id,
                          HARNESS_STATE_IDLE);
        return HARNESS_ERR_CAP_DENIED;
    }

    if (runtime_model_backend == NULL) {
        fill_submit_reply(rep, HARNESS_ERR_MODEL, req->task_id,
                          HARNESS_STATE_FAILED);
        return HARNESS_ERR_MODEL;
    }

    bytes_zero(&current_task, sizeof(current_task));
    current_task.occupied = true;
    current_task.task_id = req->task_id;
    current_task.state = HARNESS_STATE_PLANNING;
    current_task.verification_exit_code = -1;
    current_task.used_caps = HARNESS_CAP_MODEL;

    static const char task_label[] = "Original task:\n";
    uint32_t context_len = 0u;
    if (!context_append(&context_len, task_label, sizeof(task_label) - 1u)
        || !context_append(&context_len,
                           (const char *)(runtime_arena + req->prompt_offset),
                           req->prompt_len))
        return fail_task(HARNESS_ERR_PROTOCOL, rep);
    const char *next_prompt = runtime_context;
    uint32_t next_prompt_len = context_len;
    char *response = (char *)(runtime_arena + req->result_offset);
    char *action_input = (char *)(runtime_arena + HARNESS_TOOL_INPUT_OFFSET);
    char *observation = (char *)(runtime_arena + HARNESS_TOOL_OUTPUT_OFFSET);
    char *exec_observation = (char *)(runtime_arena
                                      + HARNESS_EXEC_OUTPUT_OFFSET);
    static const char echo_prefix[] = "agentos:";

    for (uint32_t step = 1u; step <= req->max_steps; step++) {
        current_task.state = HARNESS_STATE_PLANNING;
        current_task.step = step;
        uint32_t response_len = 0u, tokens_in = 0u, tokens_out = 0u;
        uint32_t status = runtime_model_backend(
            harness_system_prompt,
            (uint32_t)(sizeof(harness_system_prompt) - 1u),
            next_prompt, next_prompt_len,
            req->model_id_len == 0u ? NULL
                : (const char *)(runtime_arena + req->model_id_offset),
            req->model_id_len, response, req->result_capacity, &response_len,
            &tokens_in, &tokens_out, runtime_model_ctx);
        current_task.model_calls++;
        current_task.tokens_in += tokens_in;
        current_task.tokens_out += tokens_out;
        if (status != HARNESS_OK || response_len >= req->result_capacity)
            return fail_task(status == HARNESS_OK
                                 ? HARNESS_ERR_MODEL : status, rep);
        response[response_len] = '\0';

        const char *json = response;
        uint32_t json_len = response_len;
        if (json_len >= sizeof(echo_prefix) - 1u
            && bytes_equal(json, sizeof(echo_prefix) - 1u,
                           echo_prefix, sizeof(echo_prefix) - 1u)) {
            json += sizeof(echo_prefix) - 1u;
            json_len -= sizeof(echo_prefix) - 1u;
        }

        const char *action = NULL;
        uint32_t action_len = 0u;
        if (!json_string(json, json_len, "action", 6u,
                         &action, &action_len))
            return fail_task(HARNESS_ERR_PROTOCOL, rep);

        if (bytes_equal(action, action_len, "final", 5u)) {
            const char *summary = NULL;
            uint32_t summary_len = 0u, final_len = 0u;
            if (!json_string(json, json_len, "summary", 7u,
                             &summary, &summary_len))
                return fail_task(HARNESS_ERR_PROTOCOL, rep);
            /* A final action cannot bypass a requested verification gate. */
            if ((req->task_flags & HARNESS_TASK_REQUIRE_TEST) != 0u
                && current_task.verification_exit_code != 0)
                return fail_task(HARNESS_ERR_EXEC, rep);
            if (!decode_json_string(action_input, HARNESS_TOOL_SCRATCH_CAP,
                                    summary, summary_len, &final_len)
                || final_len >= req->result_capacity)
                return fail_task(HARNESS_ERR_PROTOCOL, rep);
            bytes_copy(response, action_input, final_len + 1u);
            current_task.result_len = final_len;
            current_task.state = HARNESS_STATE_COMPLETE;
            current_task.last_error = HARNESS_OK;
            fill_submit_reply(rep, HARNESS_OK, req->task_id,
                              current_task.state);
            return HARNESS_OK;
        }

        if (bytes_equal(action, action_len, "tool", 4u)) {
            if ((runtime_installed_caps & HARNESS_CAP_TOOL) == 0u
                || runtime_tool_backend == NULL) {
                current_task.denied_attempts++;
                return fail_task(HARNESS_ERR_CAP_DENIED, rep);
            }
            const char *tool = NULL, *input = NULL;
            uint32_t tool_len = 0u, input_len = 0u;
            if (!json_string(json, json_len, "tool", 4u, &tool, &tool_len)
                || !json_string(json, json_len, "input", 5u,
                                &input, &input_len))
                return fail_task(HARNESS_ERR_PROTOCOL, rep);
            char tool_name[TOOLSVC_TOOL_NAME_MAX];
            uint32_t name_len = 0u, decoded_input_len = 0u;
            if (!decode_json_string(tool_name, sizeof(tool_name),
                                    tool, tool_len, &name_len)
                || !decode_json_string(action_input, HARNESS_TOOL_SCRATCH_CAP,
                                       input, input_len, &decoded_input_len))
                return fail_task(HARNESS_ERR_PROTOCOL, rep);
            uint32_t observation_len = 0u;
            current_task.state = HARNESS_STATE_TOOL;
            status = runtime_tool_backend(
                tool_name, name_len, action_input, decoded_input_len,
                observation, HARNESS_TOOL_SCRATCH_CAP, &observation_len,
                runtime_tool_ctx);
            current_task.tool_calls++;
            current_task.used_caps |= HARNESS_CAP_TOOL;
            if (status != HARNESS_OK
                || observation_len >= HARNESS_TOOL_SCRATCH_CAP)
                return fail_task(status == HARNESS_OK
                                     ? HARNESS_ERR_TOOL : status, rep);
            if (!context_append_turn(&context_len, json, json_len,
                                     observation, observation_len))
                return fail_task(HARNESS_ERR_PROTOCOL, rep);
            next_prompt_len = context_len;
            continue;
        }

        bool memory_write = bytes_equal(action, action_len,
                                        "memory_write", 12u);
        bool memory_read = bytes_equal(action, action_len,
                                       "memory_read", 11u);
        if (memory_write || memory_read) {
            if ((runtime_installed_caps & HARNESS_CAP_MEMORY) == 0u
                || runtime_memory_backend == NULL) {
                current_task.denied_attempts++;
                return fail_task(HARNESS_ERR_CAP_DENIED, rep);
            }
            const char *path = NULL, *content = NULL;
            uint32_t path_len = 0u, content_len = 0u;
            if (!json_string(json, json_len, "path", 4u,
                             &path, &path_len)
                && !json_string(json, json_len, "object", 6u,
                                &path, &path_len))
                return fail_task(HARNESS_ERR_PROTOCOL, rep);
            if (memory_write
                && !json_string(json, json_len, "content", 7u,
                                &content, &content_len))
                return fail_task(HARNESS_ERR_PROTOCOL, rep);
            char decoded_path[AGENTFS_PATH_MAX];
            uint32_t decoded_path_len = 0u, decoded_content_len = 0u;
            if (!decode_json_string(decoded_path, sizeof(decoded_path),
                                    path, path_len, &decoded_path_len)
                || (memory_write
                    && !decode_json_string(action_input,
                                           HARNESS_TOOL_SCRATCH_CAP,
                                           content, content_len,
                                           &decoded_content_len)))
                return fail_task(HARNESS_ERR_PROTOCOL, rep);
            uint32_t observation_len = 0u;
            current_task.state = HARNESS_STATE_MEMORY;
            status = runtime_memory_backend(
                memory_write, decoded_path, decoded_path_len,
                memory_write ? action_input : NULL, decoded_content_len,
                observation, HARNESS_TOOL_SCRATCH_CAP, &observation_len,
                runtime_memory_ctx);
            current_task.memory_ops++;
            current_task.used_caps |= HARNESS_CAP_MEMORY;
            if (status != HARNESS_OK
                || observation_len >= HARNESS_TOOL_SCRATCH_CAP)
                return fail_task(status == HARNESS_OK
                                     ? HARNESS_ERR_MEMORY : status, rep);
            if (!context_append_turn(&context_len, json, json_len,
                                     observation, observation_len))
                return fail_task(HARNESS_ERR_PROTOCOL, rep);
            next_prompt_len = context_len;
            continue;
        }

        if (bytes_equal(action, action_len, "verify", 6u)) {
            if ((runtime_installed_caps & HARNESS_CAP_MEMORY) == 0u
                || (runtime_installed_caps & HARNESS_CAP_EXEC) == 0u
                || runtime_memory_backend == NULL
                || runtime_exec_backend == NULL) {
                current_task.denied_attempts++;
                return fail_task(HARNESS_ERR_CAP_DENIED, rep);
            }
            const char *path = NULL, *expected = NULL;
            uint32_t path_len = 0u, expected_len = 0u;
            if (!json_string(json, json_len, "path", 4u,
                             &path, &path_len)
                || !json_string(json, json_len, "expected", 8u,
                                &expected, &expected_len))
                return fail_task(HARNESS_ERR_PROTOCOL, rep);
            char decoded_path[AGENTFS_PATH_MAX];
            uint32_t decoded_path_len = 0u, decoded_expected_len = 0u;
            if (!decode_json_string(decoded_path, sizeof(decoded_path),
                                    path, path_len, &decoded_path_len)
                || !decode_json_string(action_input,
                                       HARNESS_TOOL_SCRATCH_CAP,
                                       expected, expected_len,
                                       &decoded_expected_len))
                return fail_task(HARNESS_ERR_PROTOCOL, rep);

            uint32_t actual_len = 0u;
            status = runtime_memory_backend(
                false, decoded_path, decoded_path_len, NULL, 0u,
                observation, HARNESS_TOOL_SCRATCH_CAP, &actual_len,
                runtime_memory_ctx);
            current_task.memory_ops++;
            current_task.used_caps |= HARNESS_CAP_MEMORY;
            if (status != HARNESS_OK || actual_len >= HARNESS_TOOL_SCRATCH_CAP)
                return fail_task(status == HARNESS_OK
                                     ? HARNESS_ERR_MEMORY : status, rep);

            uint32_t exec_observation_len = 0u;
            int32_t exit_code = -1;
            current_task.state = HARNESS_STATE_VERIFYING;
            status = runtime_exec_backend(
                observation, actual_len,
                action_input, decoded_expected_len, &exit_code,
                exec_observation, HARNESS_TOOL_SCRATCH_CAP,
                &exec_observation_len, runtime_exec_ctx);
            current_task.exec_calls++;
            current_task.used_caps |= HARNESS_CAP_EXEC;
            current_task.verification_exit_code = exit_code;
            if (status != HARNESS_OK || exit_code != 0
                || exec_observation_len >= HARNESS_TOOL_SCRATCH_CAP)
                return fail_task(status == HARNESS_OK
                                     ? HARNESS_ERR_EXEC : status, rep);
            if (!context_append_turn(&context_len, json, json_len,
                                     exec_observation,
                                     exec_observation_len))
                return fail_task(HARNESS_ERR_PROTOCOL, rep);
            next_prompt_len = context_len;
            continue;
        }

        return fail_task(HARNESS_ERR_PROTOCOL, rep);
    }

    return fail_task(HARNESS_ERR_STEP_LIMIT, rep);
}

uint32_t harness_runtime_status(uint32_t task_id,
                                struct harness_reply_status *rep)
{
    if (rep == NULL) return HARNESS_ERR_INVALID;
    if (!current_task.occupied || current_task.task_id != task_id) {
        bytes_zero(rep, sizeof(*rep));
        rep->status = HARNESS_ERR_NOT_FOUND;
        rep->task_id = task_id;
        return HARNESS_ERR_NOT_FOUND;
    }
    rep->status = HARNESS_OK;
    rep->task_id = task_id;
    rep->state = current_task.state;
    rep->step = current_task.step;
    rep->last_error = current_task.last_error;
    rep->used_caps = current_task.used_caps;
    rep->denied_attempts = current_task.denied_attempts;
    rep->authority_epoch = runtime_authority_epoch;
    return HARNESS_OK;
}

uint32_t harness_runtime_result(uint32_t task_id,
                                struct harness_reply_result *rep)
{
    if (rep == NULL) return HARNESS_ERR_INVALID;
    if (!current_task.occupied || current_task.task_id != task_id) {
        bytes_zero(rep, sizeof(*rep));
        rep->status = HARNESS_ERR_NOT_FOUND;
        rep->task_id = task_id;
        return HARNESS_ERR_NOT_FOUND;
    }
    if (current_task.state != HARNESS_STATE_COMPLETE
        && current_task.state != HARNESS_STATE_FAILED
        && current_task.state != HARNESS_STATE_CANCELLED)
        return HARNESS_ERR_BUSY;
    rep->status = HARNESS_OK;
    rep->task_id = task_id;
    rep->state = current_task.state;
    rep->result_len = current_task.result_len;
    rep->model_calls = current_task.model_calls;
    rep->tool_calls = current_task.tool_calls;
    rep->memory_ops = current_task.memory_ops;
    rep->exec_calls = current_task.exec_calls;
    rep->tokens_in = current_task.tokens_in;
    rep->tokens_out = current_task.tokens_out;
    rep->verification_exit_code = current_task.verification_exit_code;
    rep->used_caps = current_task.used_caps;
    return HARNESS_OK;
}

uint32_t harness_runtime_cancel(uint32_t task_id)
{
    if (!current_task.occupied || current_task.task_id != task_id)
        return HARNESS_ERR_NOT_FOUND;
    current_task.state = HARNESS_STATE_CANCELLED;
    current_task.last_error = HARNESS_OK;
    return HARNESS_OK;
}

#ifndef AGENTOS_TEST_HOST

#include "../../../contracts/modelsvc/interface.h"
#include "../../../kernel/agentos-root-task/include/sel4_client.h"
#include "../../../kernel/agentos-root-task/include/sel4_server.h"
#include "../../../kernel/agentos-root-task/include/system_desc.h"

static sel4_server_t harness_server;

static uint32_t rd32(const uint8_t *p, uint32_t off)
{
    return (uint32_t)p[off] | ((uint32_t)p[off + 1u] << 8u)
         | ((uint32_t)p[off + 2u] << 16u) | ((uint32_t)p[off + 3u] << 24u);
}

static uint32_t target_model_backend(
    const char *system_prompt, uint32_t system_prompt_len,
    const char *user_prompt, uint32_t user_prompt_len,
    const char *model_id, uint32_t model_id_len,
    char *response, uint32_t response_capacity, uint32_t *response_len,
    uint32_t *tokens_in, uint32_t *tokens_out, void *ctx)
{
    (void)ctx;
    if (system_prompt_len >= HARNESS_SYSTEM_PROMPT_CAP
        || user_prompt_len > HARNESS_MODEL_CONTEXT_CAP)
        return HARNESS_ERR_MODEL;
    bytes_copy(runtime_arena + HARNESS_SYSTEM_PROMPT_OFFSET,
               system_prompt, system_prompt_len);
    runtime_arena[HARNESS_SYSTEM_PROMPT_OFFSET + system_prompt_len] = '\0';
    bytes_copy(runtime_arena + HARNESS_MODEL_CONTEXT_OFFSET,
               user_prompt, user_prompt_len);

    modelsvc_query_wire_t wire;
    bytes_zero(&wire, sizeof(wire));
    wire.max_tokens = 2048u;
    wire.temperature_milli = 200u;
    const uint32_t partition = MODELSVC_CLIENT_ARENA_OFFSET(
        AGENT_HARNESS_BOOTSTRAP_CLIENT_ID);
    wire.system_prompt_offset = partition + HARNESS_SYSTEM_PROMPT_OFFSET;
    wire.system_prompt_len = system_prompt_len;
    wire.user_prompt_offset = partition + HARNESS_MODEL_CONTEXT_OFFSET;
    wire.user_prompt_len = user_prompt_len;
    wire.response_offset = partition
        + (uint32_t)((uint8_t *)response - runtime_arena);
    wire.response_buf_len = response_capacity;
    if (model_id != NULL) {
        wire.model_id_offset = partition
            + (uint32_t)((const uint8_t *)model_id - runtime_arena);
        wire.model_id_len = model_id_len;
    }

    sel4_msg_t rep;
    uint32_t status = sel4_client_call(PD_CNODE_SLOT_MODELSVC_EP,
                                       MODELSVC_OP_QUERY,
                                       &wire, sizeof(wire), &rep);
    if (status != MODELSVC_ERR_OK || rep.length < 16u)
        return HARNESS_ERR_MODEL;
    *response_len = rd32(rep.data, 4u);
    *tokens_in = rd32(rep.data, 8u);
    *tokens_out = rd32(rep.data, 12u);
    return HARNESS_OK;
}

static uint32_t target_tool_backend(
    const char *name, uint32_t name_len,
    const char *input, uint32_t input_len,
    char *output, uint32_t output_capacity, uint32_t *output_len,
    void *ctx)
{
    (void)ctx;
    const uint32_t name_rel = 0x100u;
    const uint32_t input_rel = 0x400u;
    const uint32_t output_rel = 0x2000u;
    if (name_len >= 256u || input_len >= 0x1800u
        || output_capacity > TOOLSVC_CLIENT_ARENA_SIZE - output_rel)
        return HARNESS_ERR_TOOL;

    uint8_t *tool_arena = (uint8_t *)(uintptr_t)
        TOOLSVC_CLIENT_ARENA_VADDR(AGENT_HARNESS_BOOTSTRAP_CLIENT_ID);
    bytes_copy(tool_arena + name_rel, name, name_len);
    bytes_copy(tool_arena + input_rel, input, input_len);

    const uint32_t partition = TOOLSVC_CLIENT_ARENA_OFFSET(
        AGENT_HARNESS_BOOTSTRAP_CLIENT_ID);
    toolsvc_invoke_wire_t wire;
    bytes_zero(&wire, sizeof(wire));
    wire.name_offset = partition + name_rel;
    wire.name_len = name_len;
    wire.input_offset = partition + input_rel;
    wire.input_len = input_len;
    wire.output_offset = partition + output_rel;
    wire.output_buf_len = output_capacity;

    sel4_msg_t rep;
    uint32_t status = sel4_client_call(PD_CNODE_SLOT_TOOLSVC_EP,
                                       TOOLSVC_OP_INVOKE,
                                       &wire, sizeof(wire), &rep);
    if (status != TOOLSVC_ERR_OK || rep.length < 8u)
        return status == TOOLSVC_ERR_DENIED
            ? HARNESS_ERR_CAP_DENIED : HARNESS_ERR_TOOL;
    uint32_t len = rd32(rep.data, 4u);
    if (len >= output_capacity) return HARNESS_ERR_TOOL;
    bytes_copy(output, tool_arena + output_rel, len);
    output[len] = '\0';
    *output_len = len;
    return HARNESS_OK;
}

static uint32_t target_memory_backend(
    bool write, const char *path, uint32_t path_len,
    const char *content, uint32_t content_len,
    char *output, uint32_t output_capacity, uint32_t *output_len,
    void *ctx)
{
    (void)ctx;
    const uint32_t path_rel = 0x100u;
    const uint32_t data_rel = 0x400u;
    const uint32_t output_rel = 0x2000u;
    if (path_len == 0u || path_len >= AGENTFS_PATH_MAX
        || content_len > AGENTFS_WORKSPACE_FILE_MAX
        || output_capacity > AGENTFS_CLIENT_ARENA_SIZE - output_rel)
        return HARNESS_ERR_MEMORY;

    uint8_t *memory_arena = (uint8_t *)(uintptr_t)
        AGENTFS_CLIENT_ARENA_VADDR(AGENT_HARNESS_BOOTSTRAP_CLIENT_ID);
    const uint32_t partition = AGENTFS_CLIENT_ARENA_OFFSET(
        AGENT_HARNESS_BOOTSTRAP_CLIENT_ID);
    bytes_copy(memory_arena + path_rel, path, path_len);

    sel4_msg_t rep;
    uint32_t status;
    if (write) {
        bytes_copy(memory_arena + data_rel, content, content_len);
        struct agentfs_req_write wire;
        bytes_zero(&wire, sizeof(wire));
        wire.path_offset = partition + path_rel;
        wire.path_len = path_len;
        wire.data_offset = partition + data_rel;
        wire.data_len = content_len;
        wire.flags = AGENTFS_WRITE_CREATE | AGENTFS_WRITE_TRUNCATE;
        status = sel4_client_call(PD_CNODE_SLOT_AGENTFS_EP,
                                  MSG_AGENTFS_WRITE,
                                  &wire, sizeof(wire), &rep);
        if (status != AGENTFS_OK) {
            return status == AGENTFS_ERR_DENIED
                ? HARNESS_ERR_CAP_DENIED : HARNESS_ERR_MEMORY;
        }
        static const char updated[] =
            "{\"observation\":\"memory_write\",\"status\":\"ok\"}";
        if (sizeof(updated) > output_capacity) return HARNESS_ERR_MEMORY;
        bytes_copy(output, updated, sizeof(updated));
        *output_len = (uint32_t)sizeof(updated) - 1u;
        return HARNESS_OK;
    }

    struct agentfs_req_read wire;
    bytes_zero(&wire, sizeof(wire));
    wire.path_offset = partition + path_rel;
    wire.path_len = path_len;
    wire.output_offset = partition + output_rel;
    wire.output_capacity = output_capacity - 1u;
    status = sel4_client_call(PD_CNODE_SLOT_AGENTFS_EP,
                              MSG_AGENTFS_READ,
                              &wire, sizeof(wire), &rep);
    if (status != AGENTFS_OK || rep.length < 8u) {
        return status == AGENTFS_ERR_DENIED
            ? HARNESS_ERR_CAP_DENIED : HARNESS_ERR_MEMORY;
    }
    uint32_t len = rd32(rep.data, 4u);
    if (len >= output_capacity) return HARNESS_ERR_MEMORY;
    bytes_copy(output, memory_arena + output_rel, len);
    output[len] = '\0';
    *output_len = len;
    return HARNESS_OK;
}

static uint32_t target_exec_backend(
    const char *actual, uint32_t actual_len,
    const char *expected, uint32_t expected_len,
    int32_t *exit_code,
    char *output, uint32_t output_capacity, uint32_t *output_len,
    void *ctx)
{
    (void)ctx;
    const uint32_t actual_rel = 0x100u;
    const uint32_t expected_rel = 0x2000u;
    if (actual_len > 0x1800u || expected_len > 0x1800u
        || exit_code == NULL || output_len == NULL)
        return HARNESS_ERR_EXEC;
    uint8_t *exec_arena = (uint8_t *)(uintptr_t)
        EXECSVC_CLIENT_ARENA_VADDR(AGENT_HARNESS_BOOTSTRAP_CLIENT_ID);
    bytes_copy(exec_arena + actual_rel, actual, actual_len);
    bytes_copy(exec_arena + expected_rel, expected, expected_len);
    uint32_t partition = EXECSVC_CLIENT_ARENA_OFFSET(
        AGENT_HARNESS_BOOTSTRAP_CLIENT_ID);
    execsvc_verify_exact_wire_t wire = {
        .actual_offset = partition + actual_rel,
        .actual_len = actual_len,
        .expected_offset = partition + expected_rel,
        .expected_len = expected_len,
        .request_tag = current_task.task_id,
    };
    sel4_msg_t rep;
    uint32_t status = sel4_client_call(PD_CNODE_SLOT_EXEC_SERVER_EP,
                                       EXECSVC_OP_VERIFY_EXACT,
                                       &wire, sizeof(wire), &rep);
    if (status != EXECSVC_OK || rep.length < sizeof(execsvc_verify_reply_t))
        return status == EXECSVC_ERR_DENIED
            ? HARNESS_ERR_CAP_DENIED : HARNESS_ERR_EXEC;
    *exit_code = (int32_t)rd32(rep.data, 4u);
    static const char verified[] =
        "{\"observation\":\"verify\",\"exit_code\":0}";
    if (sizeof(verified) > output_capacity) return HARNESS_ERR_EXEC;
    bytes_copy(output, verified, sizeof(verified));
    *output_len = sizeof(verified) - 1u;
    return HARNESS_OK;
}

static uint32_t h_submit(sel4_badge_t badge, const sel4_msg_t *req,
                         sel4_msg_t *rep, void *ctx)
{
    (void)badge; (void)ctx;
    if (req->length != sizeof(struct harness_req_submit))
        return HARNESS_ERR_INVALID;
    struct harness_req_submit submit;
    struct harness_reply_submit reply;
    bytes_copy(&submit, req->data, sizeof(submit));
    uint32_t status = harness_runtime_submit(&submit, &reply);
    bytes_copy(rep->data, &reply, sizeof(reply));
    rep->length = sizeof(reply);
    return status;
}

static uint32_t request_task_id(const sel4_msg_t *req, uint32_t *task_id)
{
    if (req->length != sizeof(struct harness_req_task))
        return HARNESS_ERR_INVALID;
    *task_id = rd32(req->data, 0u);
    return HARNESS_OK;
}

static uint32_t h_status(sel4_badge_t badge, const sel4_msg_t *req,
                         sel4_msg_t *rep, void *ctx)
{
    (void)badge; (void)ctx;
    uint32_t task_id;
    uint32_t status = request_task_id(req, &task_id);
    if (status != HARNESS_OK) return status;
    struct harness_reply_status reply;
    status = harness_runtime_status(task_id, &reply);
    bytes_copy(rep->data, &reply, sizeof(reply));
    rep->length = sizeof(reply);
    return status;
}

static uint32_t h_result(sel4_badge_t badge, const sel4_msg_t *req,
                         sel4_msg_t *rep, void *ctx)
{
    (void)badge; (void)ctx;
    uint32_t task_id;
    uint32_t status = request_task_id(req, &task_id);
    if (status != HARNESS_OK) return status;
    struct harness_reply_result reply;
    status = harness_runtime_result(task_id, &reply);
    bytes_copy(rep->data, &reply, sizeof(reply));
    rep->length = sizeof(reply);
    return status;
}

static uint32_t h_cancel(sel4_badge_t badge, const sel4_msg_t *req,
                         sel4_msg_t *rep, void *ctx)
{
    (void)badge; (void)ctx;
    uint32_t task_id;
    uint32_t status = request_task_id(req, &task_id);
    if (status != HARNESS_OK) return status;
    status = harness_runtime_cancel(task_id);
    rep->data[0] = (uint8_t)status;
    rep->data[1] = rep->data[2] = rep->data[3] = 0u;
    rep->length = 4u;
    return status;
}

static uint32_t h_resources(sel4_badge_t badge, const sel4_msg_t *req,
                            sel4_msg_t *rep, void *ctx)
{
    (void)badge; (void)ctx;
    if (req->length != 0u) return HARNESS_ERR_INVALID;
    struct harness_reply_resources reply;
    uint32_t status = harness_runtime_resources(&reply);
    bytes_copy(rep->data, &reply, sizeof(reply));
    rep->length = sizeof(reply);
    return status;
}

__attribute__((noreturn))
void pd_main(seL4_CPtr my_ep, seL4_CPtr ns_ep)
{
    (void)ns_ep;
    extern uint8_t _end[];
    const uint32_t image_base = 0x400000u;
    uint32_t image_bytes = (uint32_t)((uintptr_t)_end - image_base);
    image_bytes = (image_bytes + 4095u) & ~4095u;
    harness_runtime_init((void *)(uintptr_t)HARNESS_SHMEM_VADDR,
                         HARNESS_SHMEM_SIZE,
                         HARNESS_CAP_MODEL | HARNESS_CAP_TOOL
                             | HARNESS_CAP_MEMORY | HARNESS_CAP_EXEC, 1u,
                         target_model_backend, NULL);
    harness_runtime_set_tool_backend(target_tool_backend, NULL);
    harness_runtime_set_memory_backend(target_memory_backend, NULL);
    harness_runtime_set_exec_backend(target_exec_backend, NULL);
    /* Private charge: mapped image + 64 KiB stack + 4 KiB IPC page + a fixed
     * 128 KiB allowance for CNode/TCB/SC/page-table kernel objects. */
    harness_runtime_set_resources(image_bytes + 0x10000u + 0x1000u + 0x20000u,
                                  HARNESS_WORKER_DEFAULT_LIMIT_BYTES,
                                  HARNESS_SHMEM_SIZE + TOOLSVC_CLIENT_ARENA_SIZE
                                      + AGENTFS_CLIENT_ARENA_SIZE
                                      + EXECSVC_CLIENT_ARENA_SIZE,
                                  HARNESS_SHARED_MODELSVC
                                      | HARNESS_SHARED_TOOL_MCP
                                      | HARNESS_SHARED_ARTIFACT_STORE
                                      | HARNESS_SHARED_EXEC_GRAPH);
    sel4_server_init(&harness_server, my_ep);
    (void)sel4_server_register(&harness_server, MSG_HARNESS_SUBMIT,
                               h_submit, NULL);
    (void)sel4_server_register(&harness_server, MSG_HARNESS_CANCEL,
                               h_cancel, NULL);
    (void)sel4_server_register(&harness_server, MSG_HARNESS_STATUS,
                               h_status, NULL);
    (void)sel4_server_register(&harness_server, MSG_HARNESS_RESULT,
                               h_result, NULL);
    (void)sel4_server_register(&harness_server, MSG_HARNESS_RESOURCES,
                               h_resources, NULL);
    sel4_server_run(&harness_server);
    for (;;) { __asm__ volatile("" ::: "memory"); }
}

#endif
