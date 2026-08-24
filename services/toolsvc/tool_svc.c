/*
 * ToolSvc — singleton capability-gated tool registry and dispatcher.
 *
 * The bootstrap service exposes one built-in MCP-compatible tool,
 * `agent.echo`. It is intentionally small: dynamic providers and external MCP
 * transports will extend this service without being copied into each worker.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../../contracts/toolsvc/interface.h"
#include "../../kernel/agentos-root-task/include/system_desc.h"

typedef uint64_t toolsvc_badge_t;

static uint8_t *toolsvc_arena;
static uint32_t toolsvc_arena_size;
static uint64_t echo_call_count;

static const char echo_name[] = "agent.echo";
static const char tool_list_json[] =
    "{\"tools\":[{\"name\":\"agent.echo\",\"description\":"
    "\"Return the supplied JSON unchanged\",\"inputSchema\":{},\"calls\":0}]}";
static const char tool_info_json[] =
    "{\"name\":\"agent.echo\",\"description\":"
    "\"Return the supplied JSON unchanged\",\"system\":true}";

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

static bool bytes_equal(const uint8_t *a, uint32_t a_len,
                        const char *b, uint32_t b_len)
{
    if (a_len != b_len) return false;
    for (uint32_t i = 0u; i < a_len; i++)
        if (a[i] != (uint8_t)b[i]) return false;
    return true;
}

static void wr32(uint8_t *p, uint32_t off, uint32_t value)
{
    p[off] = (uint8_t)value;
    p[off + 1u] = (uint8_t)(value >> 8u);
    p[off + 2u] = (uint8_t)(value >> 16u);
    p[off + 3u] = (uint8_t)(value >> 24u);
}

static void wr64(uint8_t *p, uint32_t off, uint64_t value)
{
    wr32(p, off, (uint32_t)value);
    wr32(p, off + 4u, (uint32_t)(value >> 32u));
}

static uint16_t badge_service(toolsvc_badge_t badge)
{
    return (uint16_t)(badge >> 48u);
}

static uint16_t badge_client(toolsvc_badge_t badge)
{
    return (uint16_t)(badge >> 32u);
}

static bool caller_range(uint16_t client, uint32_t offset, uint32_t len)
{
    if (toolsvc_arena == NULL || client >= TOOLSVC_CLIENT_SLOT_COUNT)
        return false;
    uint32_t base = TOOLSVC_CLIENT_ARENA_OFFSET(client);
    return offset >= base
        && offset <= base + TOOLSVC_CLIENT_ARENA_SIZE
        && len <= base + TOOLSVC_CLIENT_ARENA_SIZE - offset
        && offset <= toolsvc_arena_size
        && len <= toolsvc_arena_size - offset;
}

static bool ranges_overlap(uint32_t a, uint32_t a_len,
                           uint32_t b, uint32_t b_len)
{
    if (a_len == 0u || b_len == 0u) return false;
    return a < b + b_len && b < a + a_len;
}

void toolsvc_runtime_init(void *arena, uint32_t arena_size)
{
    toolsvc_arena = (uint8_t *)arena;
    toolsvc_arena_size = arena_size;
    echo_call_count = 0u;
}

static uint32_t write_json(uint16_t client, uint32_t offset, uint32_t cap,
                           const char *json, uint32_t len,
                           uint8_t *reply, uint32_t *reply_len)
{
    if (!caller_range(client, offset, cap)) return TOOLSVC_ERR_DENIED;
    if (cap <= len) return TOOLSVC_ERR_TOO_LARGE;
    bytes_copy(toolsvc_arena + offset, json, len);
    toolsvc_arena[offset + len] = '\0';
    wr32(reply, 4u, 1u);
    wr32(reply, 8u, len);
    *reply_len = 12u;
    return TOOLSVC_ERR_OK;
}

uint32_t toolsvc_runtime_dispatch(toolsvc_badge_t badge, uint32_t opcode,
                                  const void *payload, uint32_t payload_len,
                                  uint8_t *reply, uint32_t *reply_len)
{
    if (reply == NULL || reply_len == NULL) return TOOLSVC_ERR_INVALID_ARG;
    bytes_zero(reply, 56u);
    *reply_len = 4u;
    if (badge_service(badge) != SVC_ID_TOOLSVC) {
        wr32(reply, 0u, TOOLSVC_ERR_DENIED);
        return TOOLSVC_ERR_DENIED;
    }
    uint16_t client = badge_client(badge);
    uint32_t status = TOOLSVC_ERR_INVALID_ARG;

    if (opcode == TOOLSVC_OP_HEALTH && payload_len == 0u) {
        status = TOOLSVC_ERR_OK;
        wr32(reply, 4u, 1u);
        wr32(reply, 8u, TOOLSVC_INTERFACE_VERSION);
        *reply_len = 12u;
    } else if (opcode == TOOLSVC_OP_INVOKE
               && payload != NULL
               && payload_len == sizeof(toolsvc_invoke_wire_t)) {
        toolsvc_invoke_wire_t req;
        bytes_copy(&req, payload, sizeof(req));
        if (!caller_range(client, req.name_offset, req.name_len)
            || !caller_range(client, req.input_offset, req.input_len)
            || !caller_range(client, req.output_offset, req.output_buf_len)
            || ranges_overlap(req.output_offset, req.output_buf_len,
                              req.name_offset, req.name_len)
            || ranges_overlap(req.output_offset, req.output_buf_len,
                              req.input_offset, req.input_len)) {
            status = TOOLSVC_ERR_DENIED;
        } else if (!bytes_equal(toolsvc_arena + req.name_offset, req.name_len,
                                echo_name, sizeof(echo_name) - 1u)) {
            status = TOOLSVC_ERR_NOT_FOUND;
        } else if (req.output_buf_len <= req.input_len) {
            status = TOOLSVC_ERR_TOO_LARGE;
        } else {
            bytes_copy(toolsvc_arena + req.output_offset,
                       toolsvc_arena + req.input_offset, req.input_len);
            toolsvc_arena[req.output_offset + req.input_len] = '\0';
            echo_call_count++;
            status = TOOLSVC_ERR_OK;
            wr32(reply, 4u, req.input_len);
            wr64(reply, 8u, 0u);
            *reply_len = 16u;
        }
    } else if (opcode == TOOLSVC_OP_LIST
               && payload != NULL
               && payload_len == sizeof(toolsvc_list_wire_t)) {
        toolsvc_list_wire_t req;
        bytes_copy(&req, payload, sizeof(req));
        status = write_json(client, req.output_offset, req.output_buf_len,
                            tool_list_json,
                            (uint32_t)(sizeof(tool_list_json) - 1u),
                            reply, reply_len);
    } else if (opcode == TOOLSVC_OP_INFO
               && payload != NULL
               && payload_len == sizeof(toolsvc_info_wire_t)) {
        toolsvc_info_wire_t req;
        bytes_copy(&req, payload, sizeof(req));
        if (!caller_range(client, req.name_offset, req.name_len)) {
            status = TOOLSVC_ERR_DENIED;
        } else if (!bytes_equal(toolsvc_arena + req.name_offset, req.name_len,
                                echo_name, sizeof(echo_name) - 1u)) {
            status = TOOLSVC_ERR_NOT_FOUND;
        } else {
            status = write_json(client, req.output_offset, req.output_buf_len,
                                tool_info_json,
                                (uint32_t)(sizeof(tool_info_json) - 1u),
                                reply, reply_len);
        }
    } else if (opcode == TOOLSVC_OP_STATS && payload_len == 0u) {
        status = TOOLSVC_ERR_OK;
        wr64(reply, 8u, echo_call_count);
        wr64(reply, 16u, 0u);
        wr64(reply, 24u, 0u);
        *reply_len = 32u;
    } else if (opcode == TOOLSVC_OP_REGISTER
               || opcode == TOOLSVC_OP_UNREGISTER) {
        /* Dynamic provider authority is not available until CapBroker can mint
         * and revoke provider endpoints. Fail closed instead of trusting a
         * provider badge supplied in shared memory. */
        status = TOOLSVC_ERR_DENIED;
    }

    wr32(reply, 0u, status);
    return status;
}

#ifndef AGENTOS_TEST_HOST

#include "../../kernel/agentos-root-task/include/sel4_server.h"

static uint32_t toolsvc_handler(sel4_badge_t badge, const sel4_msg_t *req,
                                sel4_msg_t *rep, void *ctx)
{
    (void)ctx;
    return toolsvc_runtime_dispatch((toolsvc_badge_t)badge, req->opcode,
                                    req->data, req->length,
                                    rep->data, &rep->length);
}

__attribute__((noreturn))
void pd_main(seL4_CPtr my_ep, seL4_CPtr ns_ep)
{
    (void)ns_ep;
    toolsvc_runtime_init((void *)(uintptr_t)TOOLSVC_SHMEM_VADDR,
                         TOOLSVC_SHMEM_SIZE);
    static sel4_server_t server;
    sel4_server_init(&server, my_ep);
    (void)sel4_server_register(&server, SEL4_SERVER_OPCODE_ANY,
                               toolsvc_handler, NULL);
    sel4_server_run(&server);
    for (;;) { __asm__ volatile("" ::: "memory"); }
}

#endif
