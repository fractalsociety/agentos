/*
 * ModelSvc production contract tests.
 *
 * These tests compile the real service implementation in host mode. They
 * exercise the compact seL4 wire format, badge-based authorization, bounded
 * shared-memory access, routing, result caching, statistics, streaming polls,
 * and cancellation without replacing handlers with a parallel mock.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define AGENTOS_TEST_HOST 1
#include "../services/modelsvc/model_svc.c"

static uint8_t shmem[MODELSVC_SHMEM_SIZE];
static uint32_t transport_calls;

static uint64_t badge(uint16_t service, uint16_t client)
{
    return ((uint64_t)service << 48u) | ((uint64_t)client << 32u);
}

static uint32_t fake_transport(const modelsvc_model_info_t *model,
                               const char *system_prompt,
                               uint32_t system_prompt_len,
                               const char *user_prompt,
                               uint32_t user_prompt_len,
                               uint32_t max_tokens,
                               uint32_t temperature_milli,
                               char *response,
                               uint32_t response_cap,
                               uint32_t *response_len,
                               uint32_t *tokens_in,
                               uint32_t *tokens_out,
                               uint64_t *latency_us,
                               void *ctx)
{
    (void)system_prompt;
    (void)system_prompt_len;
    (void)max_tokens;
    (void)temperature_milli;
    (void)ctx;
    assert(strcmp(model->model_id, "default") == 0);
    transport_calls++;

    static const char prefix[] = "answer:";
    uint32_t need = (uint32_t)(sizeof(prefix) - 1u) + user_prompt_len;
    if (need + 1u > response_cap) return MODELSVC_ERR_NOMEM;
    memcpy(response, prefix, sizeof(prefix) - 1u);
    memcpy(response + sizeof(prefix) - 1u, user_prompt, user_prompt_len);
    response[need] = '\0';
    *response_len = need;
    *tokens_in = (user_prompt_len + 3u) / 4u;
    *tokens_out = (need + 3u) / 4u;
    *latency_us = 125u;
    return MODELSVC_ERR_OK;
}

static sel4_msg_t dispatch(uint64_t raw_badge, uint32_t opcode,
                           const void *payload, uint32_t payload_len)
{
    sel4_msg_t req = {0};
    sel4_msg_t rep = {0};
    req.opcode = opcode;
    req.length = payload_len;
    assert(payload_len <= sizeof(req.data));
    if (payload_len != 0u) memcpy(req.data, payload, payload_len);
    (void)modelsvc_dispatch_one(raw_badge, &req, &rep);
    return rep;
}

static uint32_t client_offset(uint16_t client, uint32_t relative)
{
    return MODELSVC_CLIENT_ARENA_OFFSET(client) + relative;
}

static modelsvc_query_wire_t make_query(uint16_t client, const char *prompt,
                                        uint32_t response_offset,
                                        uint32_t response_cap)
{
    const uint32_t prompt_offset = client_offset(client, 0x1000u);
    uint32_t prompt_len = (uint32_t)strlen(prompt);
    memcpy(&shmem[prompt_offset], prompt, prompt_len + 1u);
    return (modelsvc_query_wire_t){
        .max_tokens = 128u,
        .temperature_milli = 200u,
        .user_prompt_offset = prompt_offset,
        .user_prompt_len = prompt_len,
        .response_offset = response_offset,
        .response_buf_len = response_cap,
        .request_tag = 42u,
    };
}

static void test_health_and_admin_registry(void)
{
    sel4_msg_t rep = dispatch(badge(SVC_ID_MODELSVC, 9u),
                              MODELSVC_OP_HEALTH, NULL, 0u);
    assert(rep.opcode == MODELSVC_ERR_OK);
    assert(rd32(rep.data, 0u) == MODELSVC_ERR_OK);
    assert(rd32(rep.data, 4u) == 6u); /* HTTP routes + native diagnostics */
    assert(rd32(rep.data, 8u) == MODELSVC_INTERFACE_VERSION);

    modelsvc_register_req_t *registration =
        (modelsvc_register_req_t *)&shmem[client_offset(
            MODELSVC_ADMIN_CONTROLLER_PD, 0x2000u)];
    memset(registration, 0, sizeof(*registration));
    registration->opcode = MODELSVC_OP_REGISTER;
    registration->context_window = 32768u;
    registration->max_tokens = 2048u;
    strcpy(registration->model_id, "private");
    strcpy(registration->endpoint_url, "http://127.0.0.1/v1/chat/completions");
    modelsvc_shmem_object_wire_t object = {
        .offset = client_offset(MODELSVC_ADMIN_CONTROLLER_PD, 0x2000u),
        .length = sizeof(*registration),
    };

    rep = dispatch(badge(SVC_ID_MODELSVC, 9u), MODELSVC_OP_REGISTER,
                   &object, sizeof(object));
    assert(rep.opcode == MODELSVC_ERR_DENIED);

    rep = dispatch(badge(SVC_ID_MODELSVC, MODELSVC_ADMIN_CONTROLLER_PD),
                   MODELSVC_OP_REGISTER, &object, sizeof(object));
    assert(rep.opcode == MODELSVC_ERR_OK);

    modelsvc_list_wire_t list = {
        .buf_offset = client_offset(9u, 0x4000u), .max_count = 8u};
    rep = dispatch(badge(SVC_ID_MODELSVC, 9u), MODELSVC_OP_LIST,
                   &list, sizeof(list));
    assert(rep.opcode == MODELSVC_ERR_OK);
    assert(rd32(rep.data, 4u) == 7u);
    assert(rd32(rep.data, 8u) == 7u * sizeof(modelsvc_model_info_t));
}

static void test_bounds_and_capability_isolation(void)
{
    modelsvc_query_wire_t query = make_query(
        9u, "hello", client_offset(9u, 0x8000u), 256u);
    query.user_prompt_offset = MODELSVC_SHMEM_SIZE - 2u;
    query.user_prompt_len = 16u;
    sel4_msg_t rep = dispatch(badge(SVC_ID_MODELSVC, 9u), MODELSVC_OP_QUERY,
                              &query, sizeof(query));
    assert(rep.opcode == MODELSVC_ERR_INVALID_ARG);

    /* A globally valid offset in a different caller's partition is still
     * invalid for this badge. */
    query = make_query(9u, "hello", client_offset(9u, 0x8000u), 256u);
    memcpy(&shmem[client_offset(10u, 0x1000u)], "hello", 6u);
    query.user_prompt_offset = client_offset(10u, 0x1000u);
    rep = dispatch(badge(SVC_ID_MODELSVC, 9u), MODELSVC_OP_QUERY,
                   &query, sizeof(query));
    assert(rep.opcode == MODELSVC_ERR_INVALID_ARG);

    query = make_query(9u, "hello", client_offset(10u, 0x8000u), 256u);
    rep = dispatch(badge(SVC_ID_MODELSVC, 9u), MODELSVC_OP_QUERY,
                   &query, sizeof(query));
    assert(rep.opcode == MODELSVC_ERR_INVALID_ARG);

    query = make_query(9u, "hello", client_offset(9u, 0x8000u), 256u);
    rep = dispatch(badge(0xFFFFu, 9u), MODELSVC_OP_QUERY,
                   &query, sizeof(query));
    assert(rep.opcode == MODELSVC_ERR_DENIED);
}

static void test_query_cache_and_stats(void)
{
    const uint32_t response_offset = client_offset(9u, 0x8000u);
    modelsvc_query_wire_t query = make_query(9u, "hello", response_offset, 256u);
    sel4_msg_t rep = dispatch(badge(SVC_ID_MODELSVC, 9u), MODELSVC_OP_QUERY,
                              &query, sizeof(query));
    assert(rep.opcode == MODELSVC_ERR_OK);
    assert(rd32(rep.data, 4u) == strlen("answer:hello"));
    assert(strcmp((char *)&shmem[response_offset], "answer:hello") == 0);
    assert(transport_calls == 1u);

    memset(&shmem[response_offset], 0, 256u);
    rep = dispatch(badge(SVC_ID_MODELSVC, 9u), MODELSVC_OP_QUERY,
                   &query, sizeof(query));
    assert(rep.opcode == MODELSVC_ERR_OK);
    assert(strcmp((char *)&shmem[response_offset], "answer:hello") == 0);
    assert(transport_calls == 1u); /* exact result cache hit */

    uint32_t name_offset = client_offset(9u, 0x3000u);
    memcpy(&shmem[name_offset], "default", 8u);
    modelsvc_shmem_object_wire_t name = {.offset = name_offset, .length = 7u};
    rep = dispatch(badge(SVC_ID_MODELSVC, 9u), MODELSVC_OP_STATS,
                   &name, sizeof(name));
    assert(rep.opcode == MODELSVC_ERR_OK);
    assert(rd32(rep.data, 8u) == 2u); /* low 32 bits total_requests */
}

static void test_stream_poll_and_cancel(void)
{
    const uint32_t response_offset = client_offset(10u, 0x9000u);
    modelsvc_query_wire_t query = make_query(
        10u, "stream-me", response_offset, 256u);
    query.flags = MODELSVC_FLAG_STREAMING;
    sel4_msg_t rep = dispatch(badge(SVC_ID_MODELSVC, 10u),
                              MODELSVC_OP_STREAM_BEGIN,
                              &query, sizeof(query));
    assert(rep.opcode == MODELSVC_ERR_OK);
    uint32_t request_id = rd32(rep.data, 4u);
    assert(request_id != 0u);

    modelsvc_stream_poll_wire_t poll = {.request_id = request_id, .max_bytes = 4u};
    uint32_t collected = 0u;
    do {
        rep = dispatch(badge(SVC_ID_MODELSVC, 10u), MODELSVC_OP_STREAM_POLL,
                       &poll, sizeof(poll));
        assert(rep.opcode == MODELSVC_ERR_OK);
        uint32_t chunk = rd32(rep.data, 8u);
        assert(chunk <= 4u);
        collected += chunk;
    } while (rd32(rep.data, 4u) != MODELSVC_STREAM_COMPLETE);
    assert(collected == strlen("answer:stream-me"));

    query = make_query(10u, "cancel-me", response_offset, 256u);
    rep = dispatch(badge(SVC_ID_MODELSVC, 10u), MODELSVC_OP_STREAM_BEGIN,
                   &query, sizeof(query));
    request_id = rd32(rep.data, 4u);
    modelsvc_cancel_wire_t cancel = {.request_id = request_id};
    rep = dispatch(badge(SVC_ID_MODELSVC, 11u), MODELSVC_OP_CANCEL,
                   &cancel, sizeof(cancel));
    assert(rep.opcode == MODELSVC_ERR_DENIED); /* request ownership */
    rep = dispatch(badge(SVC_ID_MODELSVC, 10u), MODELSVC_OP_CANCEL,
                   &cancel, sizeof(cancel));
    assert(rep.opcode == MODELSVC_ERR_OK);
}

int main(void)
{
    memset(shmem, 0, sizeof(shmem));
    modelsvc_test_init(shmem, sizeof(shmem));
    modelsvc_set_transport(fake_transport, NULL);

    test_health_and_admin_registry();
    test_bounds_and_capability_isolation();
    test_query_cache_and_stats();
    test_stream_poll_and_cancel();
    puts("[PASS] ModelSvc production contract tests");
    return 0;
}
