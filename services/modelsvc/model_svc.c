/*
 * agentOS ModelSvc — capability-gated model inference protection domain.
 *
 * The service keeps all state in fixed-size tables: there is no allocator,
 * libc, Linux, or ambient network access. Large prompts and responses use a
 * shared-memory arena; the 48-byte seL4 payload carries only checked offsets.
 * A caller's minted endpoint badge is its ModelCap and request identity.
 *
 * Backends are injected through modelsvc_transport_fn. The production backend
 * serializes an OpenAI-compatible request and delegates HTTP to NetServer, the
 * only PD with a network capability. Host contract tests inject a deterministic
 * transport while exercising this exact implementation.
 *
 * Copyright (c) 2026 The agentOS Project
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../../contracts/modelsvc/interface.h"

#ifdef AGENTOS_TEST_HOST
#include <string.h>

typedef unsigned long seL4_CPtr;
typedef uint64_t sel4_badge_t;
typedef struct {
    uint32_t opcode;
    uint32_t length;
    uint8_t data[48];
} sel4_msg_t;

#define SEL4_ERR_OK          0u
#define SEL4_ERR_INVALID_OP  1u
#define SEL4_SERVER_MAX_HANDLERS 32u

typedef uint32_t (*sel4_handler_fn)(sel4_badge_t, const sel4_msg_t *,
                                    sel4_msg_t *, void *);
typedef struct {
    struct { uint32_t opcode; sel4_handler_fn fn; void *ctx; }
        handlers[SEL4_SERVER_MAX_HANDLERS];
    uint32_t handler_count;
    seL4_CPtr ep;
} sel4_server_t;

static inline void sel4_server_init(sel4_server_t *srv, seL4_CPtr ep)
{
    memset(srv, 0, sizeof(*srv));
    srv->ep = ep;
}
static inline int sel4_server_register(sel4_server_t *srv, uint32_t opcode,
                                       sel4_handler_fn fn, void *ctx)
{
    if (srv->handler_count >= SEL4_SERVER_MAX_HANDLERS) return -1;
    uint32_t index = srv->handler_count++;
    srv->handlers[index].opcode = opcode;
    srv->handlers[index].fn = fn;
    srv->handlers[index].ctx = ctx;
    return 0;
}
static inline uint32_t sel4_server_dispatch(sel4_server_t *srv,
                                            sel4_badge_t badge,
                                            const sel4_msg_t *req,
                                            sel4_msg_t *rep)
{
    for (uint32_t i = 0u; i < srv->handler_count; i++) {
        if (srv->handlers[i].opcode == req->opcode) {
            uint32_t rc = srv->handlers[i].fn(badge, req, rep,
                                               srv->handlers[i].ctx);
            rep->opcode = rc;
            return rc;
        }
    }
    rep->opcode = SEL4_ERR_INVALID_OP;
    rep->length = 0u;
    return rep->opcode;
}

#else
#define AGENTOS_DEBUG 1
#include "agentos.h"
#include "net_server.h"
#include "sel4_client.h"
#include "sel4_server.h"
#include "system_desc.h"
#endif

#ifndef SVC_ID_MODELSVC
#define SVC_ID_MODELSVC 25u
#endif
#ifndef MODELSVC_ADMIN_CONTROLLER_PD
#define MODELSVC_ADMIN_CONTROLLER_PD 4u
#define MODELSVC_ADMIN_INIT_PD       5u
#endif
#ifndef PD_CNODE_SLOT_NET_SERVER_EP
#define PD_CNODE_SLOT_NET_SERVER_EP 14u
#endif
#ifndef OP_NET_HTTP_POST
#define OP_NET_HTTP_POST 0x500u
#endif

#define MODELSVC_CACHE_RESPONSE_MAX (8u * 1024u)
#define MODELSVC_STREAM_RESPONSE_MAX MODELSVC_STREAM_CHUNK_MAX
#define MODELSVC_HTTP_URL_OFFSET    MODELSVC_INTERNAL_ARENA_OFFSET
#define MODELSVC_HTTP_BODY_OFFSET   (MODELSVC_INTERNAL_ARENA_OFFSET + 0x1000u)
#define MODELSVC_HTTP_BODY_CAP      (MODELSVC_SHMEM_SIZE - MODELSVC_HTTP_BODY_OFFSET)

typedef uint32_t (*modelsvc_transport_fn)(
    const modelsvc_model_info_t *model,
    const char *system_prompt, uint32_t system_prompt_len,
    const char *user_prompt, uint32_t user_prompt_len,
    uint32_t max_tokens, uint32_t temperature_milli,
    char *response, uint32_t response_cap, uint32_t *response_len,
    uint32_t *tokens_in, uint32_t *tokens_out, uint64_t *latency_us,
    void *ctx);

typedef struct {
    bool active;
    modelsvc_model_info_t info;
    char api_key_env[64];
} model_slot_t;

typedef struct {
    bool valid;
    uint64_t key;
    uint32_t response_len;
    uint64_t age;
    char response[MODELSVC_CACHE_RESPONSE_MAX];
} cache_slot_t;

typedef struct {
    bool active;
    uint32_t id;
    uint16_t owner;
    uint32_t state;
    uint32_t response_offset;
    uint32_t response_cap;
    uint32_t response_len;
    uint32_t cursor;
    uint32_t tokens_in;
    uint32_t tokens_out;
    char response[MODELSVC_STREAM_RESPONSE_MAX];
} stream_slot_t;

static model_slot_t models[MODELSVC_MAX_MODELS];
static cache_slot_t cache_entries[MODELSVC_CACHE_ENTRIES];
static stream_slot_t streams[MODELSVC_MAX_INFLIGHT];
static uint32_t model_count;
static uint32_t next_request_id = 1u;
static uint64_t cache_clock;
static uint8_t *modelsvc_shmem;
static uint32_t modelsvc_shmem_size;
static modelsvc_transport_fn transport_fn;
static void *transport_ctx;
static sel4_server_t server;

static uint32_t rd32(const uint8_t *data, uint32_t offset)
{
    return (uint32_t)data[offset]
         | ((uint32_t)data[offset + 1u] << 8u)
         | ((uint32_t)data[offset + 2u] << 16u)
         | ((uint32_t)data[offset + 3u] << 24u);
}

static void wr32(uint8_t *data, uint32_t offset, uint32_t value)
{
    data[offset] = (uint8_t)value;
    data[offset + 1u] = (uint8_t)(value >> 8u);
    data[offset + 2u] = (uint8_t)(value >> 16u);
    data[offset + 3u] = (uint8_t)(value >> 24u);
}

static void wr64(uint8_t *data, uint32_t offset, uint64_t value)
{
    wr32(data, offset, (uint32_t)value);
    wr32(data, offset + 4u, (uint32_t)(value >> 32u));
}

static void bytes_zero(void *ptr, uint32_t len)
{
    uint8_t *p = (uint8_t *)ptr;
    for (uint32_t i = 0u; i < len; i++) p[i] = 0u;
}

static void bytes_copy(void *dst, const void *src, uint32_t len)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (uint32_t i = 0u; i < len; i++) d[i] = s[i];
}

static bool bytes_equal(const char *a, uint32_t a_len,
                        const char *b, uint32_t b_len)
{
    if (a_len != b_len) return false;
    for (uint32_t i = 0u; i < a_len; i++)
        if (a[i] != b[i]) return false;
    return true;
}

static bool bytes_contains(const char *haystack, uint32_t haystack_len,
                           const char *needle, uint32_t needle_len)
{
    if (needle_len == 0u || needle_len > haystack_len) return false;
    for (uint32_t i = 0u; i <= haystack_len - needle_len; i++)
        if (bytes_equal(haystack + i, needle_len, needle, needle_len))
            return true;
    return false;
}

static uint32_t bounded_strlen(const char *value, uint32_t cap)
{
    uint32_t len = 0u;
    while (len < cap && value[len] != '\0') len++;
    return len;
}

static void copy_string(char *dst, uint32_t cap, const char *src, uint32_t len)
{
    if (cap == 0u) return;
    if (len >= cap) len = cap - 1u;
    bytes_copy(dst, src, len);
    dst[len] = '\0';
}

static bool __attribute__((unused)) shmem_range(uint32_t offset, uint32_t len)
{
    return modelsvc_shmem != NULL
        && offset <= modelsvc_shmem_size
        && len <= modelsvc_shmem_size - offset;
}

static bool client_shmem_range(uint16_t client, uint32_t offset, uint32_t len)
{
    if (client >= MODELSVC_CLIENT_SLOT_COUNT) return false;
    uint32_t base = MODELSVC_CLIENT_ARENA_OFFSET(client);
    return modelsvc_shmem != NULL
        && offset >= base
        && offset <= base + MODELSVC_CLIENT_ARENA_SIZE
        && len <= base + MODELSVC_CLIENT_ARENA_SIZE - offset;
}

static uint16_t badge_service(sel4_badge_t badge)
{
    return (uint16_t)(badge >> 48u);
}

static uint16_t badge_client(sel4_badge_t badge)
{
    return (uint16_t)(badge >> 32u);
}

static bool badge_has_model_cap(sel4_badge_t badge)
{
    return badge_service(badge) == SVC_ID_MODELSVC;
}

static bool badge_is_admin(sel4_badge_t badge)
{
    uint16_t client = badge_client(badge);
    return badge_has_model_cap(badge)
        && (client == MODELSVC_ADMIN_CONTROLLER_PD
            || client == MODELSVC_ADMIN_INIT_PD);
}

static uint64_t hash_bytes(uint64_t hash, const void *data, uint32_t len)
{
    const uint8_t *bytes = (const uint8_t *)data;
    for (uint32_t i = 0u; i < len; i++) {
        hash ^= bytes[i];
        hash *= UINT64_C(1099511628211);
    }
    return hash;
}

static uint64_t query_cache_key(const modelsvc_query_wire_t *wire,
                                const model_slot_t *model,
                                uint16_t client)
{
    uint64_t hash = UINT64_C(1469598103934665603);
    /* Cache storage is shared once, but entries remain caller-scoped so a
     * guessed prompt cannot retrieve another worker's cached response. */
    hash = hash_bytes(hash, &client, sizeof(client));
    hash = hash_bytes(hash, model->info.model_id,
                      bounded_strlen(model->info.model_id, MODELSVC_MODEL_ID_MAX));
    hash = hash_bytes(hash, &wire->max_tokens, sizeof(wire->max_tokens));
    hash = hash_bytes(hash, &wire->temperature_milli,
                      sizeof(wire->temperature_milli));
    if (wire->system_prompt_len != 0u)
        hash = hash_bytes(hash, modelsvc_shmem + wire->system_prompt_offset,
                          wire->system_prompt_len);
    return hash_bytes(hash, modelsvc_shmem + wire->user_prompt_offset,
                      wire->user_prompt_len);
}

static model_slot_t *find_model(const char *id, uint32_t len)
{
    for (uint32_t i = 0u; i < MODELSVC_MAX_MODELS; i++) {
        if (!models[i].active) continue;
        uint32_t current_len = bounded_strlen(models[i].info.model_id,
                                              MODELSVC_MODEL_ID_MAX);
        if (current_len != len) continue;
        bool match = true;
        for (uint32_t j = 0u; j < len; j++) {
            if (models[i].info.model_id[j] != id[j]) { match = false; break; }
        }
        if (match) return &models[i];
    }
    return NULL;
}

static model_slot_t *default_model(void)
{
    for (uint32_t i = 0u; i < MODELSVC_MAX_MODELS; i++)
        if (models[i].active && (models[i].info.flags & MODELSVC_FLAG_DEFAULT))
            return &models[i];
    return NULL;
}

static uint32_t register_model(const modelsvc_register_req_t *request)
{
    uint32_t id_len = bounded_strlen(request->model_id, MODELSVC_MODEL_ID_MAX);
    uint32_t endpoint_len = bounded_strlen(request->endpoint_url,
                                           MODELSVC_ENDPOINT_MAX);
    if (id_len == 0u || id_len == MODELSVC_MODEL_ID_MAX
        || endpoint_len == 0u || endpoint_len == MODELSVC_ENDPOINT_MAX
        || request->context_window == 0u || request->max_tokens == 0u)
        return MODELSVC_ERR_INVALID_ARG;

    model_slot_t *slot = find_model(request->model_id, id_len);
    if (slot == NULL) {
        for (uint32_t i = 0u; i < MODELSVC_MAX_MODELS; i++) {
            if (!models[i].active) { slot = &models[i]; break; }
        }
        if (slot == NULL) return MODELSVC_ERR_NOMEM;
        bytes_zero(slot, sizeof(*slot));
        slot->active = true;
        model_count++;
    }

    copy_string(slot->info.model_id, MODELSVC_MODEL_ID_MAX,
                request->model_id, id_len);
    copy_string(slot->info.endpoint_url, MODELSVC_ENDPOINT_MAX,
                request->endpoint_url, endpoint_len);
    copy_string(slot->api_key_env, sizeof(slot->api_key_env),
                request->api_key_env,
                bounded_strlen(request->api_key_env, sizeof(request->api_key_env)));
    slot->info.context_window = request->context_window;
    slot->info.max_tokens = request->max_tokens;
    slot->info.flags = request->flags;
    return MODELSVC_ERR_OK;
}

static void register_default(const char *id, const char *url, const char *key,
                             uint32_t context, uint32_t max_tokens,
                             uint32_t flags)
{
    modelsvc_register_req_t request;
    bytes_zero(&request, sizeof(request));
    copy_string(request.model_id, sizeof(request.model_id), id,
                bounded_strlen(id, MODELSVC_MODEL_ID_MAX));
    copy_string(request.endpoint_url, sizeof(request.endpoint_url), url,
                bounded_strlen(url, MODELSVC_ENDPOINT_MAX));
    copy_string(request.api_key_env, sizeof(request.api_key_env), key,
                bounded_strlen(key, 64u));
    request.context_window = context;
    request.max_tokens = max_tokens;
    request.flags = flags;
    (void)register_model(&request);
}

static cache_slot_t *cache_lookup(uint64_t key)
{
    for (uint32_t i = 0u; i < MODELSVC_CACHE_ENTRIES; i++) {
        if (cache_entries[i].valid && cache_entries[i].key == key) {
            cache_entries[i].age = ++cache_clock;
            return &cache_entries[i];
        }
    }
    return NULL;
}

static void cache_store(uint64_t key, const char *response, uint32_t len)
{
    if (len > MODELSVC_CACHE_RESPONSE_MAX) return;
    cache_slot_t *slot = NULL;
    for (uint32_t i = 0u; i < MODELSVC_CACHE_ENTRIES; i++) {
        if (!cache_entries[i].valid) { slot = &cache_entries[i]; break; }
        if (slot == NULL || cache_entries[i].age < slot->age)
            slot = &cache_entries[i];
    }
    slot->valid = true;
    slot->key = key;
    slot->response_len = len;
    slot->age = ++cache_clock;
    bytes_copy(slot->response, response, len);
}

static uint32_t validate_query(const modelsvc_query_wire_t *wire,
                               uint16_t client,
                               model_slot_t **model_out)
{
    if (wire->temperature_milli > 2000u || wire->user_prompt_len == 0u
        || wire->response_buf_len < 2u
        || wire->model_id_len >= MODELSVC_MODEL_ID_MAX
        || !client_shmem_range(client, wire->user_prompt_offset,
                               wire->user_prompt_len)
        || !client_shmem_range(client, wire->response_offset,
                               wire->response_buf_len)
        || (wire->system_prompt_len != 0u
            && !client_shmem_range(client, wire->system_prompt_offset,
                                   wire->system_prompt_len))
        || (wire->model_id_len != 0u
            && !client_shmem_range(client, wire->model_id_offset,
                                   wire->model_id_len)))
        return MODELSVC_ERR_INVALID_ARG;

    model_slot_t *model = wire->model_id_len == 0u
        ? default_model()
        : find_model((const char *)modelsvc_shmem + wire->model_id_offset,
                     wire->model_id_len);
    if (model == NULL) return MODELSVC_ERR_NOT_FOUND;

    uint32_t max_tokens = wire->max_tokens == 0u
        ? model->info.max_tokens : wire->max_tokens;
    if (max_tokens > model->info.max_tokens) return MODELSVC_ERR_INVALID_ARG;
    uint64_t estimated_input = ((uint64_t)wire->system_prompt_len
                              + (uint64_t)wire->user_prompt_len + 3u) / 4u;
    if (estimated_input + max_tokens > model->info.context_window)
        return MODELSVC_ERR_CONTEXT_FULL;
    *model_out = model;
    return MODELSVC_ERR_OK;
}

static uint32_t execute_query(const modelsvc_query_wire_t *wire,
                              uint16_t client,
                              char *output, uint32_t output_cap,
                              uint32_t *response_len,
                              uint32_t *tokens_in, uint32_t *tokens_out,
                              uint64_t *latency_us, bool *cache_hit)
{
    model_slot_t *model = NULL;
    uint32_t status = validate_query(wire, client, &model);
    if (status != MODELSVC_ERR_OK) return status;
    if (output_cap < 2u) return MODELSVC_ERR_INVALID_ARG;

    uint64_t key = query_cache_key(wire, model, client);
    cache_slot_t *cached = cache_lookup(key);
    model->info.total_requests++;
    if (cached != NULL && cached->response_len + 1u <= output_cap) {
        bytes_copy(output, cached->response, cached->response_len);
        output[cached->response_len] = '\0';
        *response_len = cached->response_len;
        *tokens_in = 0u;
        *tokens_out = (cached->response_len + 3u) / 4u;
        *latency_us = 0u;
        *cache_hit = true;
        model->info.total_tokens_out += *tokens_out;
        return MODELSVC_ERR_OK;
    }
    uint32_t max_tokens = wire->max_tokens == 0u
        ? model->info.max_tokens : wire->max_tokens;
    if ((model->info.flags & MODELSVC_FLAG_LOCAL) != 0u) {
        /* Dependency-free native fast path used for diagnostics and target
         * contract proof. Production model backends still route via transport. */
        static const char prefix[] = "agentos:";
        static const char smoke_model[] = "agentos-smoke-coder";
        static const char smoke_task[] = "edit-and-readback-smoke";
        static const char write_observation[] =
            "{\"observation\":\"memory_write\",\"status\":\"ok\"}";
        static const char verify_observation[] =
            "{\"observation\":\"verify\",\"exit_code\":0}";
        static const char write_action[] =
            "{\"action\":\"memory_write\",\"path\":\"src/answer.txt\","
            "\"content\":\"after\\n\"}";
        static const char verify_action[] =
            "{\"action\":\"verify\",\"path\":\"src/answer.txt\","
            "\"expected\":\"after\\n\"}";
        static const char final_action[] =
            "{\"action\":\"final\",\"summary\":\"edit-readback-verified\"}";
        const char *user = (const char *)modelsvc_shmem
            + wire->user_prompt_offset;
        uint32_t id_len = bounded_strlen(model->info.model_id,
                                         MODELSVC_MODEL_ID_MAX);
        const char *local_response = NULL;
        uint32_t local_response_len = 0u;
        if (bytes_equal(model->info.model_id, id_len,
                        smoke_model, sizeof(smoke_model) - 1u)) {
            if (bytes_contains(user, wire->user_prompt_len,
                               verify_observation,
                               sizeof(verify_observation) - 1u)) {
                local_response = final_action;
                local_response_len = sizeof(final_action) - 1u;
            } else if (bytes_contains(user, wire->user_prompt_len,
                                      write_observation,
                                      sizeof(write_observation) - 1u)) {
                local_response = verify_action;
                local_response_len = sizeof(verify_action) - 1u;
            } else if (bytes_contains(user, wire->user_prompt_len,
                                      smoke_task, sizeof(smoke_task) - 1u)) {
                local_response = write_action;
                local_response_len = sizeof(write_action) - 1u;
            } else {
                return MODELSVC_ERR_INVALID_ARG;
            }
        }
        if (local_response != NULL) {
            if (local_response_len + 1u > output_cap)
                return MODELSVC_ERR_NOMEM;
            bytes_copy(output, local_response, local_response_len);
            *response_len = local_response_len;
        } else {
            static const char original_marker[] = "Original task:\n";
            static const char observation_marker[] = "\nObservation:\n";
            static const char continuation_marker[] =
                "\nContinue the original task";
            const char *selected = user;
            uint32_t selected_len = wire->user_prompt_len;
            const char *latest_observation = NULL;
            for (uint32_t i = 0u;
                 i + sizeof(observation_marker) - 1u <= wire->user_prompt_len;
                 i++) {
                if (bytes_equal(user + i, sizeof(observation_marker) - 1u,
                                observation_marker,
                                sizeof(observation_marker) - 1u))
                    latest_observation = user + i
                        + sizeof(observation_marker) - 1u;
            }
            if (latest_observation != NULL) {
                selected = latest_observation;
                selected_len = wire->user_prompt_len
                    - (uint32_t)(selected - user);
                for (uint32_t i = 0u;
                     i + sizeof(continuation_marker) - 1u <= selected_len;
                     i++) {
                    if (bytes_equal(selected + i,
                                    sizeof(continuation_marker) - 1u,
                                    continuation_marker,
                                    sizeof(continuation_marker) - 1u)) {
                        selected_len = i;
                        break;
                    }
                }
            } else if (wire->user_prompt_len
                           >= sizeof(original_marker) - 1u
                       && bytes_equal(user, sizeof(original_marker) - 1u,
                                      original_marker,
                                      sizeof(original_marker) - 1u)) {
                selected += sizeof(original_marker) - 1u;
                selected_len -= sizeof(original_marker) - 1u;
            }
            if (sizeof(prefix) - 1u + selected_len + 1u > output_cap)
                return MODELSVC_ERR_NOMEM;
            bytes_copy(output, prefix, sizeof(prefix) - 1u);
            bytes_copy(output + sizeof(prefix) - 1u, selected, selected_len);
            *response_len = (uint32_t)(sizeof(prefix) - 1u)
                + selected_len;
        }
        *tokens_in = (wire->system_prompt_len + wire->user_prompt_len + 3u) / 4u;
        *tokens_out = (*response_len + 3u) / 4u;
        *latency_us = 0u;
        status = MODELSVC_ERR_OK;
    } else {
        if (transport_fn == NULL) return MODELSVC_ERR_NET;
        status = transport_fn(
            &model->info,
            wire->system_prompt_len == 0u ? NULL
                : (const char *)modelsvc_shmem + wire->system_prompt_offset,
            wire->system_prompt_len,
            (const char *)modelsvc_shmem + wire->user_prompt_offset,
            wire->user_prompt_len,
            max_tokens, wire->temperature_milli,
            output, output_cap, response_len, tokens_in, tokens_out, latency_us,
            transport_ctx);
    }
    if (status != MODELSVC_ERR_OK) return status;
    if (*response_len >= output_cap) return MODELSVC_ERR_INTERNAL;
    output[*response_len] = '\0';
    model->info.total_tokens_in += *tokens_in;
    model->info.total_tokens_out += *tokens_out;
    model->info.total_latency_us += *latency_us;
    cache_store(key, output, *response_len);
    *cache_hit = false;
    return MODELSVC_ERR_OK;
}

static uint32_t h_health(sel4_badge_t badge, const sel4_msg_t *req,
                         sel4_msg_t *rep, void *ctx)
{
    (void)req; (void)ctx;
    if (!badge_has_model_cap(badge)) return MODELSVC_ERR_DENIED;
    wr32(rep->data, 0u, MODELSVC_ERR_OK);
    wr32(rep->data, 4u, model_count);
    wr32(rep->data, 8u, MODELSVC_INTERFACE_VERSION);
    rep->length = 12u;
    return MODELSVC_ERR_OK;
}

static uint32_t h_register(sel4_badge_t badge, const sel4_msg_t *req,
                           sel4_msg_t *rep, void *ctx)
{
    (void)ctx;
    if (!badge_is_admin(badge)) return MODELSVC_ERR_DENIED;
    if (req->length < sizeof(modelsvc_shmem_object_wire_t))
        return MODELSVC_ERR_INVALID_ARG;
    uint32_t offset = rd32(req->data, 0u);
    uint32_t length = rd32(req->data, 4u);
    if (length != sizeof(modelsvc_register_req_t)
        || !client_shmem_range(badge_client(badge), offset, length))
        return MODELSVC_ERR_INVALID_ARG;
    uint32_t status = register_model(
        (const modelsvc_register_req_t *)(modelsvc_shmem + offset));
    wr32(rep->data, 0u, status);
    rep->length = 4u;
    return status;
}

static uint32_t h_unregister(sel4_badge_t badge, const sel4_msg_t *req,
                             sel4_msg_t *rep, void *ctx)
{
    (void)ctx;
    if (!badge_is_admin(badge)) return MODELSVC_ERR_DENIED;
    if (req->length < sizeof(modelsvc_shmem_object_wire_t))
        return MODELSVC_ERR_INVALID_ARG;
    uint32_t offset = rd32(req->data, 0u), length = rd32(req->data, 4u);
    if (length == 0u || length >= MODELSVC_MODEL_ID_MAX
        || !client_shmem_range(badge_client(badge), offset, length))
        return MODELSVC_ERR_INVALID_ARG;
    model_slot_t *model = find_model((const char *)modelsvc_shmem + offset, length);
    if (model == NULL) return MODELSVC_ERR_NOT_FOUND;
    model->active = false;
    model_count--;
    wr32(rep->data, 0u, MODELSVC_ERR_OK);
    rep->length = 4u;
    return MODELSVC_ERR_OK;
}

static uint32_t h_list(sel4_badge_t badge, const sel4_msg_t *req,
                       sel4_msg_t *rep, void *ctx)
{
    (void)ctx;
    if (!badge_has_model_cap(badge)) return MODELSVC_ERR_DENIED;
    if (req->length < sizeof(modelsvc_list_wire_t))
        return MODELSVC_ERR_INVALID_ARG;
    uint32_t offset = rd32(req->data, 0u), max_count = rd32(req->data, 4u);
    if (max_count > MODELSVC_MAX_MODELS) max_count = MODELSVC_MAX_MODELS;
    uint64_t bytes64 = (uint64_t)max_count * sizeof(modelsvc_model_info_t);
    if (bytes64 > UINT32_MAX
        || !client_shmem_range(badge_client(badge), offset, (uint32_t)bytes64))
        return MODELSVC_ERR_INVALID_ARG;
    uint32_t written = 0u;
    for (uint32_t i = 0u; i < MODELSVC_MAX_MODELS && written < max_count; i++) {
        if (!models[i].active) continue;
        bytes_copy(modelsvc_shmem + offset
                       + written * sizeof(modelsvc_model_info_t),
                   &models[i].info, sizeof(modelsvc_model_info_t));
        written++;
    }
    wr32(rep->data, 0u, MODELSVC_ERR_OK);
    wr32(rep->data, 4u, written);
    wr32(rep->data, 8u, written * sizeof(modelsvc_model_info_t));
    rep->length = 12u;
    return MODELSVC_ERR_OK;
}

static uint32_t h_stats(sel4_badge_t badge, const sel4_msg_t *req,
                        sel4_msg_t *rep, void *ctx)
{
    (void)ctx;
    if (!badge_has_model_cap(badge)) return MODELSVC_ERR_DENIED;
    if (req->length < sizeof(modelsvc_shmem_object_wire_t))
        return MODELSVC_ERR_INVALID_ARG;
    uint32_t offset = rd32(req->data, 0u), length = rd32(req->data, 4u);
    if (length == 0u || length >= MODELSVC_MODEL_ID_MAX
        || !client_shmem_range(badge_client(badge), offset, length))
        return MODELSVC_ERR_INVALID_ARG;
    model_slot_t *model = find_model((const char *)modelsvc_shmem + offset, length);
    if (model == NULL) return MODELSVC_ERR_NOT_FOUND;
    wr32(rep->data, 0u, MODELSVC_ERR_OK);
    wr32(rep->data, 4u, 0u);
    wr64(rep->data, 8u, model->info.total_requests);
    wr64(rep->data, 16u, model->info.total_tokens_in);
    wr64(rep->data, 24u, model->info.total_tokens_out);
    wr64(rep->data, 32u, model->info.total_requests == 0u ? 0u
        : model->info.total_latency_us / model->info.total_requests);
    rep->length = 40u;
    return MODELSVC_ERR_OK;
}

static uint32_t h_query(sel4_badge_t badge, const sel4_msg_t *req,
                        sel4_msg_t *rep, void *ctx)
{
    (void)ctx;
    if (!badge_has_model_cap(badge)) return MODELSVC_ERR_DENIED;
    if (req->length != sizeof(modelsvc_query_wire_t))
        return MODELSVC_ERR_INVALID_ARG;
    modelsvc_query_wire_t wire;
    bytes_copy(&wire, req->data, sizeof(wire));
    uint16_t client = badge_client(badge);
    if (!client_shmem_range(client, wire.response_offset, wire.response_buf_len))
        return MODELSVC_ERR_INVALID_ARG;
    uint32_t response_len = 0u, tokens_in = 0u, tokens_out = 0u;
    uint64_t latency_us = 0u;
    bool cache_hit = false;
    uint32_t status = execute_query(&wire, client,
        (char *)modelsvc_shmem + wire.response_offset, wire.response_buf_len,
        &response_len, &tokens_in, &tokens_out, &latency_us, &cache_hit);
    wr32(rep->data, 0u, status);
    wr32(rep->data, 4u, response_len);
    wr32(rep->data, 8u, tokens_in);
    wr32(rep->data, 12u, tokens_out);
    wr64(rep->data, 16u, latency_us);
    wr32(rep->data, 24u, cache_hit ? 1u : 0u);
    rep->length = 28u;
    return status;
}

static stream_slot_t *find_stream(uint32_t id)
{
    for (uint32_t i = 0u; i < MODELSVC_MAX_INFLIGHT; i++)
        if (streams[i].active && streams[i].id == id) return &streams[i];
    return NULL;
}

static uint32_t h_stream_begin(sel4_badge_t badge, const sel4_msg_t *req,
                               sel4_msg_t *rep, void *ctx)
{
    (void)ctx;
    if (!badge_has_model_cap(badge)) return MODELSVC_ERR_DENIED;
    if (req->length != sizeof(modelsvc_query_wire_t))
        return MODELSVC_ERR_INVALID_ARG;
    stream_slot_t *slot = NULL;
    for (uint32_t i = 0u; i < MODELSVC_MAX_INFLIGHT; i++) {
        if (!streams[i].active) { slot = &streams[i]; break; }
    }
    if (slot == NULL) return MODELSVC_ERR_RATE_LIMIT;
    modelsvc_query_wire_t wire;
    bytes_copy(&wire, req->data, sizeof(wire));
    model_slot_t *model = NULL;
    uint16_t client = badge_client(badge);
    uint32_t status = validate_query(&wire, client, &model);
    (void)model;
    if (status != MODELSVC_ERR_OK) return status;

    bytes_zero(slot, sizeof(*slot));
    slot->active = true;
    slot->id = next_request_id++;
    if (next_request_id == 0u) next_request_id = 1u;
    slot->owner = badge_client(badge);
    slot->state = MODELSVC_STREAM_RUNNING;
    slot->response_offset = wire.response_offset;
    slot->response_cap = wire.response_buf_len;
    bool cache_hit = false;
    uint64_t latency = 0u;
    status = execute_query(&wire, client,
                           slot->response, sizeof(slot->response),
                           &slot->response_len, &slot->tokens_in,
                           &slot->tokens_out, &latency, &cache_hit);
    if (status != MODELSVC_ERR_OK) {
        slot->active = false;
        return status;
    }
    slot->state = MODELSVC_STREAM_READY;
    wr32(rep->data, 0u, MODELSVC_ERR_OK);
    wr32(rep->data, 4u, slot->id);
    wr32(rep->data, 8u, slot->state);
    wr32(rep->data, 12u, cache_hit ? 1u : 0u);
    rep->length = 16u;
    return MODELSVC_ERR_OK;
}

static uint32_t h_stream_poll(sel4_badge_t badge, const sel4_msg_t *req,
                              sel4_msg_t *rep, void *ctx)
{
    (void)ctx;
    if (!badge_has_model_cap(badge)) return MODELSVC_ERR_DENIED;
    if (req->length < sizeof(modelsvc_stream_poll_wire_t))
        return MODELSVC_ERR_INVALID_ARG;
    uint32_t id = rd32(req->data, 0u), max_bytes = rd32(req->data, 4u);
    stream_slot_t *slot = find_stream(id);
    if (slot == NULL) return MODELSVC_ERR_NOT_FOUND;
    if (slot->owner != badge_client(badge)) return MODELSVC_ERR_DENIED;
    if (slot->state == MODELSVC_STREAM_CANCELLED) {
        slot->active = false;
        return MODELSVC_ERR_NOT_FOUND;
    }
    if (max_bytes == 0u || max_bytes > slot->response_cap)
        max_bytes = slot->response_cap;
    if (max_bytes > MODELSVC_STREAM_CHUNK_MAX)
        max_bytes = MODELSVC_STREAM_CHUNK_MAX;
    uint32_t remaining = slot->response_len - slot->cursor;
    uint32_t chunk = remaining < max_bytes ? remaining : max_bytes;
    bytes_copy(modelsvc_shmem + slot->response_offset,
               slot->response + slot->cursor, chunk);
    if (chunk < slot->response_cap)
        modelsvc_shmem[slot->response_offset + chunk] = '\0';
    slot->cursor += chunk;
    slot->state = slot->cursor == slot->response_len
        ? MODELSVC_STREAM_COMPLETE : MODELSVC_STREAM_READY;
    wr32(rep->data, 0u, MODELSVC_ERR_OK);
    wr32(rep->data, 4u, slot->state);
    wr32(rep->data, 8u, chunk);
    wr32(rep->data, 12u, slot->response_len);
    wr32(rep->data, 16u, slot->tokens_in);
    wr32(rep->data, 20u, slot->tokens_out);
    rep->length = 24u;
    if (slot->state == MODELSVC_STREAM_COMPLETE) slot->active = false;
    return MODELSVC_ERR_OK;
}

static uint32_t h_cancel(sel4_badge_t badge, const sel4_msg_t *req,
                         sel4_msg_t *rep, void *ctx)
{
    (void)ctx;
    if (!badge_has_model_cap(badge)) return MODELSVC_ERR_DENIED;
    if (req->length < sizeof(modelsvc_cancel_wire_t))
        return MODELSVC_ERR_INVALID_ARG;
    stream_slot_t *slot = find_stream(rd32(req->data, 0u));
    if (slot == NULL) return MODELSVC_ERR_NOT_FOUND;
    if (slot->owner != badge_client(badge)) return MODELSVC_ERR_DENIED;
    slot->state = MODELSVC_STREAM_CANCELLED;
    slot->active = false;
    wr32(rep->data, 0u, MODELSVC_ERR_OK);
    rep->length = 4u;
    return MODELSVC_ERR_OK;
}

void modelsvc_set_transport(modelsvc_transport_fn fn, void *ctx)
{
    transport_fn = fn;
    transport_ctx = ctx;
}

static void modelsvc_init_state(uint8_t *shmem, uint32_t shmem_size)
{
    bytes_zero(models, sizeof(models));
    bytes_zero(cache_entries, sizeof(cache_entries));
    bytes_zero(streams, sizeof(streams));
    model_count = 0u;
    next_request_id = 1u;
    cache_clock = 0u;
    modelsvc_shmem = shmem;
    modelsvc_shmem_size = shmem_size;
    transport_fn = NULL;
    transport_ctx = NULL;

    register_default("default",
        "http://10.0.2.2:8790/v1/chat/completions", "NVIDIA_API_KEY",
        128000u, 4096u, MODELSVC_FLAG_DEFAULT | MODELSVC_FLAG_STREAMING);
    register_default("code-gen",
        "http://10.0.2.2:8790/v1/chat/completions", "NVIDIA_API_KEY",
        128000u, 32768u, MODELSVC_FLAG_STREAMING);
    register_default("fast",
        "http://10.0.2.2:8790/v1/chat/completions", "OPENAI_API_KEY",
        16000u, 4096u, MODELSVC_FLAG_STREAMING);
    register_default("agentos-echo", "builtin://echo", "",
        16000u, 4096u, MODELSVC_FLAG_LOCAL | MODELSVC_FLAG_STREAMING);
    register_default("agentos-smoke-coder", "builtin://smoke-coder", "",
        16000u, 4096u, MODELSVC_FLAG_LOCAL);

    sel4_server_init(&server, 0u);
    (void)sel4_server_register(&server, MODELSVC_OP_QUERY, h_query, NULL);
    (void)sel4_server_register(&server, MODELSVC_OP_REGISTER, h_register, NULL);
    (void)sel4_server_register(&server, MODELSVC_OP_UNREGISTER, h_unregister, NULL);
    (void)sel4_server_register(&server, MODELSVC_OP_LIST, h_list, NULL);
    (void)sel4_server_register(&server, MODELSVC_OP_STATS, h_stats, NULL);
    (void)sel4_server_register(&server, MODELSVC_OP_HEALTH, h_health, NULL);
    (void)sel4_server_register(&server, MODELSVC_OP_STREAM_BEGIN,
                               h_stream_begin, NULL);
    (void)sel4_server_register(&server, MODELSVC_OP_STREAM_POLL,
                               h_stream_poll, NULL);
    (void)sel4_server_register(&server, MODELSVC_OP_CANCEL, h_cancel, NULL);
}

#ifdef AGENTOS_TEST_HOST
void modelsvc_test_init(void *shmem, uint32_t shmem_size)
{
    modelsvc_init_state((uint8_t *)shmem, shmem_size);
}

static uint32_t modelsvc_dispatch_one(sel4_badge_t badge,
                                      const sel4_msg_t *req,
                                      sel4_msg_t *rep)
{
    return sel4_server_dispatch(&server, badge, req, rep);
}

#else

static seL4_CPtr net_server_ep = PD_CNODE_SLOT_NET_SERVER_EP;

static uint32_t append_bytes(char *dst, uint32_t pos, uint32_t cap,
                             const char *src, uint32_t len)
{
    if (len > cap - pos) return UINT32_MAX;
    bytes_copy(dst + pos, src, len);
    return pos + len;
}

static uint32_t append_json_string(char *dst, uint32_t pos, uint32_t cap,
                                   const char *src, uint32_t len)
{
    pos = append_bytes(dst, pos, cap, "\"", 1u);
    if (pos == UINT32_MAX) return pos;
    for (uint32_t i = 0u; i < len; i++) {
        const char *escape = NULL;
        uint32_t escape_len = 0u;
        switch (src[i]) {
        case '\"': escape = "\\\""; escape_len = 2u; break;
        case '\\': escape = "\\\\"; escape_len = 2u; break;
        case '\n': escape = "\\n"; escape_len = 2u; break;
        case '\r': escape = "\\r"; escape_len = 2u; break;
        case '\t': escape = "\\t"; escape_len = 2u; break;
        default: break;
        }
        pos = escape != NULL ? append_bytes(dst, pos, cap, escape, escape_len)
                             : append_bytes(dst, pos, cap, &src[i], 1u);
        if (pos == UINT32_MAX) return pos;
    }
    return append_bytes(dst, pos, cap, "\"", 1u);
}

static uint32_t append_u32(char *dst, uint32_t pos, uint32_t cap, uint32_t value)
{
    char reverse[10];
    uint32_t count = 0u;
    do { reverse[count++] = (char)('0' + value % 10u); value /= 10u; }
    while (value != 0u && count < sizeof(reverse));
    if (count > cap - pos) return UINT32_MAX;
    while (count != 0u) dst[pos++] = reverse[--count];
    return pos;
}

static const char *find_json_key(const char *json, uint32_t len, const char *key)
{
    uint32_t key_len = bounded_strlen(key, 64u);
    for (uint32_t i = 0u; i + key_len <= len; i++) {
        bool match = true;
        for (uint32_t j = 0u; j < key_len; j++)
            if (json[i + j] != key[j]) { match = false; break; }
        if (match) return json + i + key_len;
    }
    return NULL;
}

static uint32_t parse_json_u32(const char *json, uint32_t len, const char *key)
{
    const char *p = find_json_key(json, len, key);
    if (p == NULL) return 0u;
    const char *end = json + len;
    while (p < end && (*p < '0' || *p > '9')) p++;
    uint32_t value = 0u;
    while (p < end && *p >= '0' && *p <= '9') {
        value = value * 10u + (uint32_t)(*p - '0'); p++;
    }
    return value;
}

static uint32_t parse_content(const char *json, uint32_t len,
                              char *output, uint32_t cap, uint32_t *out_len)
{
    const char *p = find_json_key(json, len, "\"content\"");
    const char *end = json + len;
    if (p == NULL) return MODELSVC_ERR_INTERNAL;
    while (p < end && *p != ':') p++;
    while (p < end && *p != '\"') p++;
    if (p == end) return MODELSVC_ERR_INTERNAL;
    p++;
    uint32_t written = 0u;
    while (p < end) {
        char c = *p++;
        if (c == '\"') break;
        if (c == '\\' && p < end) {
            c = *p++;
            if (c == 'n') c = '\n';
            else if (c == 'r') c = '\r';
            else if (c == 't') c = '\t';
        }
        if (written + 1u >= cap) return MODELSVC_ERR_NOMEM;
        output[written++] = c;
    }
    output[written] = '\0';
    *out_len = written;
    return MODELSVC_ERR_OK;
}

static uint32_t net_transport(const modelsvc_model_info_t *model,
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
    (void)ctx;
    char *url = (char *)modelsvc_shmem + MODELSVC_HTTP_URL_OFFSET;
    char *body = (char *)modelsvc_shmem + MODELSVC_HTTP_BODY_OFFSET;
    uint32_t url_len = bounded_strlen(model->endpoint_url, MODELSVC_ENDPOINT_MAX);
    if (!shmem_range(MODELSVC_HTTP_URL_OFFSET, url_len + 1u))
        return MODELSVC_ERR_INTERNAL;
    bytes_copy(url, model->endpoint_url, url_len + 1u);

    uint32_t pos = 0u;
#define APPEND_LITERAL(value) do { \
    pos = append_bytes(body, pos, MODELSVC_HTTP_BODY_CAP, value, \
                       (uint32_t)(sizeof(value) - 1u)); \
    if (pos == UINT32_MAX) return MODELSVC_ERR_NOMEM; \
} while (0)
    APPEND_LITERAL("{\"model\":");
    pos = append_json_string(body, pos, MODELSVC_HTTP_BODY_CAP,
                             model->model_id,
                             bounded_strlen(model->model_id, MODELSVC_MODEL_ID_MAX));
    if (pos == UINT32_MAX) return MODELSVC_ERR_NOMEM;
    APPEND_LITERAL(",\"messages\":[");
    if (system_prompt_len != 0u) {
        APPEND_LITERAL("{\"role\":\"system\",\"content\":");
        pos = append_json_string(body, pos, MODELSVC_HTTP_BODY_CAP,
                                 system_prompt, system_prompt_len);
        if (pos == UINT32_MAX) return MODELSVC_ERR_NOMEM;
        APPEND_LITERAL("},");
    }
    APPEND_LITERAL("{\"role\":\"user\",\"content\":");
    pos = append_json_string(body, pos, MODELSVC_HTTP_BODY_CAP,
                             user_prompt, user_prompt_len);
    if (pos == UINT32_MAX) return MODELSVC_ERR_NOMEM;
    APPEND_LITERAL("}],\"max_tokens\":");
    pos = append_u32(body, pos, MODELSVC_HTTP_BODY_CAP, max_tokens);
    if (pos == UINT32_MAX) return MODELSVC_ERR_NOMEM;
    APPEND_LITERAL(",\"temperature\":");
    pos = append_u32(body, pos, MODELSVC_HTTP_BODY_CAP, temperature_milli);
    if (pos == UINT32_MAX) return MODELSVC_ERR_NOMEM;
    APPEND_LITERAL(",\"temperature_scale\":1000,\"stream\":false}");
#undef APPEND_LITERAL

    uint8_t request[16];
    wr32(request, 0u, MODELSVC_HTTP_URL_OFFSET);
    wr32(request, 4u, url_len);
    wr32(request, 8u, MODELSVC_HTTP_BODY_OFFSET);
    wr32(request, 12u, pos);
    sel4_msg_t reply;
    uint32_t call_status = sel4_client_call(net_server_ep, OP_NET_HTTP_POST,
                                            request, sizeof(request), &reply);
    if (call_status != SEL4_ERR_OK) return MODELSVC_ERR_NET;
    uint32_t http_status = rd32(reply.data, 0u);
    uint32_t body_offset = rd32(reply.data, 4u);
    uint32_t body_len = rd32(reply.data, 8u);
    if (http_status == 429u) return MODELSVC_ERR_RATE_LIMIT;
    if (http_status < 200u || http_status >= 300u
        || !shmem_range(body_offset, body_len)) return MODELSVC_ERR_NET;
    const char *json = (const char *)modelsvc_shmem + body_offset;
    uint32_t parse_status = parse_content(json, body_len, response,
                                          response_cap, response_len);
    if (parse_status != MODELSVC_ERR_OK) return parse_status;
    *tokens_in = parse_json_u32(json, body_len, "\"prompt_tokens\"");
    *tokens_out = parse_json_u32(json, body_len, "\"completion_tokens\"");
    if (*tokens_in == 0u) *tokens_in = (user_prompt_len + 3u) / 4u;
    if (*tokens_out == 0u) *tokens_out = (*response_len + 3u) / 4u;
    *latency_us = 0u;
    return MODELSVC_ERR_OK;
}

void pd_main(seL4_CPtr my_ep, seL4_CPtr ns_ep)
{
    (void)ns_ep;
    modelsvc_init_state((uint8_t *)(uintptr_t)MODELSVC_SHMEM_VADDR,
                        MODELSVC_SHMEM_SIZE);
    modelsvc_set_transport(net_transport, NULL);
    server.ep = my_ep;
    sel4_server_run(&server);
}
#endif
