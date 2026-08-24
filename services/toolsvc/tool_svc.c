/*
 * ToolSvc — singleton capability-gated tool registry and dispatcher.
 *
 * The singleton exposes capability-scoped built-ins. Repository discovery is
 * delegated to a shared administrator-owned index rather than copied into
 * every worker. External MCP providers live behind one administrator-owned
 * transport capability; workers never receive provider process, credential,
 * network, or transport handles.
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

typedef uint32_t (*toolsvc_repo_backend_fn)(
    bool read, const uint8_t *input, uint32_t input_len,
    uint8_t *output, uint32_t output_capacity, uint32_t *output_len,
    void *ctx);
static toolsvc_repo_backend_fn repo_backend;
static void *repo_backend_ctx;

typedef uint32_t (*toolsvc_mcp_backend_fn)(
    bool list, const uint8_t *name, uint32_t name_len,
    const uint8_t *input, uint32_t input_len,
    uint8_t *output, uint32_t output_capacity, uint32_t *output_len,
    void *ctx);
static toolsvc_mcp_backend_fn mcp_backend;
static void *mcp_backend_ctx;

static const char echo_name[] = "agent.echo";
static const char repo_search_name[] = "repo.search";
static const char repo_read_name[] = "repo.read";
static const char mcp_discover_name[] = TOOLSVC_MCP_DISCOVER_NAME;
static const char tool_list_prefix[] = "{\"tools\":[";
static const char tool_list_suffix[] = "]}";
static const char tool_list_echo_entry[] =
    "{\"name\":\"agent.echo\",\"description\":"
    "\"Return the supplied JSON unchanged\",\"inputSchema\":{}}";
static const char tool_list_search_entry[] =
    "{\"name\":\"repo.search\",\"description\":"
    "\"Search the shared tracked-code index for a literal string\","
    "\"inputSchema\":{\"type\":\"string\"}}";
static const char tool_list_read_entry[] =
    "{\"name\":\"repo.read\",\"description\":"
    "\"Read one tracked file from the shared repository snapshot\","
    "\"inputSchema\":{\"type\":\"string\"}}";
static const char tool_list_mcp_entry[] =
    "{\"name\":\"mcp.tools.list\",\"description\":"
    "\"Discover tools registered by the shared external MCP provider\","
    "\"inputSchema\":{\"type\":\"object\"}}";
static const char echo_info_json[] =
    "{\"name\":\"agent.echo\",\"description\":"
    "\"Return the supplied JSON unchanged\",\"system\":true}";
static const char repo_search_info_json[] =
    "{\"name\":\"repo.search\",\"description\":"
    "\"Search tracked files for a bounded literal query\",\"system\":true}";
static const char repo_read_info_json[] =
    "{\"name\":\"repo.read\",\"description\":"
    "\"Read one bounded tracked file by relative path\",\"system\":true}";

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

static bool bytes_prefix(const uint8_t *value, uint32_t value_len,
                         const char *prefix, uint32_t prefix_len)
{
    if (value_len < prefix_len) return false;
    for (uint32_t i = 0u; i < prefix_len; i++)
        if (value[i] != (uint8_t)prefix[i]) return false;
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

static uint32_t badge_rights(toolsvc_badge_t badge)
{
    return (uint32_t)badge;
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
    repo_backend = NULL;
    repo_backend_ctx = NULL;
    mcp_backend = NULL;
    mcp_backend_ctx = NULL;
}

void toolsvc_runtime_set_mcp_backend(toolsvc_mcp_backend_fn backend,
                                     void *ctx)
{
    mcp_backend = backend;
    mcp_backend_ctx = ctx;
}

static bool append_json(uint8_t *dst, uint32_t cap, uint32_t *used,
                        const char *src, uint32_t len)
{
    if (*used > cap || len > cap - *used) return false;
    bytes_copy(dst + *used, src, len);
    *used += len;
    return true;
}

static uint32_t write_tool_list(uint16_t client, uint32_t rights,
                                uint32_t offset, uint32_t cap,
                                uint8_t *reply, uint32_t *reply_len)
{
    if (!caller_range(client, offset, cap)) return TOOLSVC_ERR_DENIED;
    uint8_t *out = toolsvc_arena + offset;
    uint32_t used = 0u, count = 0u;
    if (!append_json(out, cap, &used, tool_list_prefix,
                     sizeof(tool_list_prefix) - 1u))
        return TOOLSVC_ERR_TOO_LARGE;
    const struct { uint32_t right; const char *json; uint32_t len; } entries[] = {
        { TOOLSVC_RIGHT_AGENT_ECHO, tool_list_echo_entry,
          sizeof(tool_list_echo_entry) - 1u },
        { TOOLSVC_RIGHT_REPO_SEARCH, tool_list_search_entry,
          sizeof(tool_list_search_entry) - 1u },
        { TOOLSVC_RIGHT_REPO_READ, tool_list_read_entry,
          sizeof(tool_list_read_entry) - 1u },
        { TOOLSVC_RIGHT_MCP_EXTERNAL, tool_list_mcp_entry,
          sizeof(tool_list_mcp_entry) - 1u },
    };
    for (uint32_t i = 0u; i < sizeof(entries) / sizeof(entries[0]); i++) {
        if ((rights & entries[i].right) == 0u) continue;
        if (count != 0u && !append_json(out, cap, &used, ",", 1u))
            return TOOLSVC_ERR_TOO_LARGE;
        if (!append_json(out, cap, &used, entries[i].json, entries[i].len))
            return TOOLSVC_ERR_TOO_LARGE;
        count++;
    }
    if (!append_json(out, cap, &used, tool_list_suffix,
                     sizeof(tool_list_suffix) - 1u)
        || used >= cap)
        return TOOLSVC_ERR_TOO_LARGE;
    out[used] = '\0';
    wr32(reply, 4u, count);
    wr32(reply, 8u, used);
    *reply_len = 12u;
    return TOOLSVC_ERR_OK;
}

void toolsvc_runtime_set_repo_backend(toolsvc_repo_backend_fn backend,
                                      void *ctx)
{
    repo_backend = backend;
    repo_backend_ctx = ctx;
}

static uint32_t write_json(uint16_t client, uint32_t offset, uint32_t cap,
                           const char *json, uint32_t len,
                           uint32_t count,
                           uint8_t *reply, uint32_t *reply_len)
{
    if (!caller_range(client, offset, cap)) return TOOLSVC_ERR_DENIED;
    if (cap <= len) return TOOLSVC_ERR_TOO_LARGE;
    bytes_copy(toolsvc_arena + offset, json, len);
    toolsvc_arena[offset + len] = '\0';
    wr32(reply, 4u, count);
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
    uint32_t rights = badge_rights(badge);
    uint32_t status = TOOLSVC_ERR_INVALID_ARG;

    if (opcode == TOOLSVC_OP_HEALTH && payload_len == 0u) {
        status = TOOLSVC_ERR_OK;
        uint32_t count = ((rights & TOOLSVC_RIGHT_AGENT_ECHO) != 0u ? 1u : 0u)
            + ((rights & TOOLSVC_RIGHT_REPO_SEARCH) != 0u ? 1u : 0u)
            + ((rights & TOOLSVC_RIGHT_REPO_READ) != 0u ? 1u : 0u)
            + ((rights & TOOLSVC_RIGHT_MCP_EXTERNAL) != 0u ? 1u : 0u);
        wr32(reply, 4u, count);
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
        } else if (bytes_equal(toolsvc_arena + req.name_offset, req.name_len,
                               echo_name, sizeof(echo_name) - 1u)) {
            if ((rights & TOOLSVC_RIGHT_AGENT_ECHO) == 0u) {
                status = TOOLSVC_ERR_DENIED;
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
        } else {
            bool search = bytes_equal(toolsvc_arena + req.name_offset,
                                      req.name_len, repo_search_name,
                                      sizeof(repo_search_name) - 1u);
            bool read = bytes_equal(toolsvc_arena + req.name_offset,
                                    req.name_len, repo_read_name,
                                    sizeof(repo_read_name) - 1u);
            bool discover = bytes_equal(toolsvc_arena + req.name_offset,
                                        req.name_len, mcp_discover_name,
                                        sizeof(mcp_discover_name) - 1u);
            bool external = bytes_prefix(toolsvc_arena + req.name_offset,
                                         req.name_len, TOOLSVC_MCP_PREFIX,
                                         TOOLSVC_MCP_PREFIX_LEN);
            uint32_t required = search ? TOOLSVC_RIGHT_REPO_SEARCH
                : (read ? TOOLSVC_RIGHT_REPO_READ
                   : (external ? TOOLSVC_RIGHT_MCP_EXTERNAL : 0u));
            uint32_t input_max = read ? TOOLSVC_REPO_PATH_MAX
                : (external ? TOOLSVC_MCP_INPUT_MAX : TOOLSVC_REPO_QUERY_MAX);
            if (required == 0u) {
                status = TOOLSVC_ERR_NOT_FOUND;
            } else if ((rights & required) == 0u) {
                status = TOOLSVC_ERR_DENIED;
            } else if ((!discover && req.input_len == 0u)
                       || req.input_len > input_max
                       || req.output_buf_len > (external
                            ? TOOLSVC_MCP_OUTPUT_MAX
                            : TOOLSVC_REPO_OUTPUT_MAX)) {
                status = TOOLSVC_ERR_TOO_LARGE;
            } else if (external) {
                if (mcp_backend == NULL) {
                    status = TOOLSVC_ERR_PROVIDER_DOWN;
                } else {
                    uint32_t output_len = 0u;
                    status = mcp_backend(
                        discover,
                        toolsvc_arena + req.name_offset, req.name_len,
                        toolsvc_arena + req.input_offset, req.input_len,
                        toolsvc_arena + req.output_offset,
                        req.output_buf_len, &output_len, mcp_backend_ctx);
                    if (status == TOOLSVC_ERR_OK
                        && output_len < req.output_buf_len) {
                        toolsvc_arena[req.output_offset + output_len] = '\0';
                        wr32(reply, 4u, output_len);
                        wr64(reply, 8u, 0u);
                        *reply_len = 16u;
                    } else if (status == TOOLSVC_ERR_OK) {
                        status = TOOLSVC_ERR_TOO_LARGE;
                    }
                }
            } else if (repo_backend == NULL) {
                status = TOOLSVC_ERR_PROVIDER_DOWN;
            } else {
                uint32_t output_len = 0u;
                status = repo_backend(
                    read, toolsvc_arena + req.input_offset, req.input_len,
                    toolsvc_arena + req.output_offset, req.output_buf_len,
                    &output_len, repo_backend_ctx);
                if (status == TOOLSVC_ERR_OK
                    && output_len < req.output_buf_len) {
                    toolsvc_arena[req.output_offset + output_len] = '\0';
                    wr32(reply, 4u, output_len);
                    wr64(reply, 8u, 0u);
                    *reply_len = 16u;
                } else if (status == TOOLSVC_ERR_OK) {
                    status = TOOLSVC_ERR_TOO_LARGE;
                }
            }
        }
    } else if (opcode == TOOLSVC_OP_LIST
               && payload != NULL
               && payload_len == sizeof(toolsvc_list_wire_t)) {
        toolsvc_list_wire_t req;
        bytes_copy(&req, payload, sizeof(req));
        status = write_tool_list(client, rights, req.output_offset,
                                 req.output_buf_len, reply, reply_len);
    } else if (opcode == TOOLSVC_OP_INFO
               && payload != NULL
               && payload_len == sizeof(toolsvc_info_wire_t)) {
        toolsvc_info_wire_t req;
        bytes_copy(&req, payload, sizeof(req));
        if (!caller_range(client, req.name_offset, req.name_len)) {
            status = TOOLSVC_ERR_DENIED;
        } else {
            const uint8_t *name = toolsvc_arena + req.name_offset;
            const char *json = NULL;
            uint32_t len = 0u, required = 0u;
            if (bytes_equal(name, req.name_len, echo_name,
                            sizeof(echo_name) - 1u)) {
                json = echo_info_json;
                len = (uint32_t)(sizeof(echo_info_json) - 1u);
                required = TOOLSVC_RIGHT_AGENT_ECHO;
            } else if (bytes_equal(name, req.name_len, repo_search_name,
                                   sizeof(repo_search_name) - 1u)) {
                json = repo_search_info_json;
                len = (uint32_t)(sizeof(repo_search_info_json) - 1u);
                required = TOOLSVC_RIGHT_REPO_SEARCH;
            } else if (bytes_equal(name, req.name_len, repo_read_name,
                                   sizeof(repo_read_name) - 1u)) {
                json = repo_read_info_json;
                len = (uint32_t)(sizeof(repo_read_info_json) - 1u);
                required = TOOLSVC_RIGHT_REPO_READ;
            }
            if (json == NULL) status = TOOLSVC_ERR_NOT_FOUND;
            else if ((rights & required) == 0u) status = TOOLSVC_ERR_DENIED;
            else status = write_json(client, req.output_offset,
                                     req.output_buf_len, json, len, 1u,
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

#include "../../contracts/execsvc/interface.h"
#include "../../kernel/agentos-root-task/include/mcp_transport.h"
#include "../../kernel/agentos-root-task/include/sel4_client.h"
#include "../../kernel/agentos-root-task/include/sel4_server.h"

static uint32_t target_repo_backend(
    bool read, const uint8_t *input, uint32_t input_len,
    uint8_t *output, uint32_t output_capacity, uint32_t *output_len,
    void *ctx)
{
    (void)ctx;
    const uint32_t source_rel = 0x100u;
    const uint32_t output_rel = 0x2000u;
    if (output_len == NULL || input_len == 0u
        || input_len > EXECSVC_SOURCE_MAX || output_capacity == 0u
        || output_capacity > EXECSVC_OUTPUT_MAX)
        return TOOLSVC_ERR_INVALID_ARG;
    uint8_t *arena = (uint8_t *)(uintptr_t)
        EXECSVC_CLIENT_ARENA_VADDR(TOOLSVC_BOOTSTRAP_CLIENT_ID);
    bytes_copy(arena + source_rel, input, input_len);
    uint32_t partition = EXECSVC_CLIENT_ARENA_OFFSET(
        TOOLSVC_BOOTSTRAP_CLIENT_ID);
    execsvc_run_profile_wire_t wire = {
        .source_offset = partition + source_rel,
        .source_len = input_len,
        .output_offset = partition + output_rel,
        .output_capacity = output_capacity,
        .profile_id = read ? EXECSVC_PROFILE_AGENTOS_REPO_READ
                           : EXECSVC_PROFILE_AGENTOS_REPO_SEARCH,
        .request_tag = read ? 0x72656164u : 0x66696e64u,
    };
    sel4_msg_t rep;
    uint32_t status = sel4_client_call(PD_CNODE_SLOT_EXEC_SERVER_EP,
                                       EXECSVC_OP_RUN_PROFILE,
                                       &wire, sizeof(wire), &rep);
    if (status != EXECSVC_OK || rep.length < sizeof(execsvc_run_profile_reply_t))
        return status == EXECSVC_ERR_DENIED
            ? TOOLSVC_ERR_DENIED : TOOLSVC_ERR_PROVIDER_DOWN;
    execsvc_run_profile_reply_t result;
    bytes_copy(&result, rep.data, sizeof(result));
    if (result.status != EXECSVC_OK || result.request_tag != wire.request_tag
        || result.output_len >= output_capacity)
        return result.status == EXECSVC_ERR_DENIED
            ? TOOLSVC_ERR_DENIED : TOOLSVC_ERR_PROVIDER_DOWN;
    bytes_copy(output, arena + output_rel, result.output_len);
    *output_len = result.output_len;
    return TOOLSVC_ERR_OK;
}

static uint32_t target_mcp_backend(
    bool list, const uint8_t *name, uint32_t name_len,
    const uint8_t *input, uint32_t input_len,
    uint8_t *output, uint32_t output_capacity, uint32_t *output_len,
    void *ctx)
{
    (void)ctx;
    const uint32_t name_offset = TOOLSVC_INTERNAL_ARENA_OFFSET + 0x100u;
    const uint32_t input_offset = TOOLSVC_INTERNAL_ARENA_OFFSET + 0x1000u;
    const uint32_t output_offset = TOOLSVC_INTERNAL_ARENA_OFFSET + 0x6000u;
    if (output_len == NULL || name_len < TOOLSVC_MCP_PREFIX_LEN
        || name_len >= TOOLSVC_TOOL_NAME_MAX
        || input_len > TOOLSVC_MCP_INPUT_MAX
        || output_capacity == 0u
        || output_capacity > TOOLSVC_MCP_OUTPUT_MAX)
        return TOOLSVC_ERR_INVALID_ARG;
    bytes_copy(toolsvc_arena + name_offset, name, name_len);
    if (input_len != 0u)
        bytes_copy(toolsvc_arena + input_offset, input, input_len);
    mcp_transport_wire_t wire = {
        .operation = list ? MCP_TRANSPORT_REQUEST_LIST
                          : MCP_TRANSPORT_REQUEST_INVOKE,
        .name_offset = name_offset,
        .name_len = name_len,
        .input_offset = input_offset,
        .input_len = input_len,
        .output_offset = output_offset,
        .output_capacity = output_capacity,
        .request_tag = list ? 0x6c697374u : 0x63616c6cu,
    };
    sel4_msg_t rep;
    uint32_t call_status = sel4_client_call(PD_CNODE_SLOT_MCP_TRANSPORT_EP,
                                             MCP_TRANSPORT_OP_REQUEST,
                                             &wire, sizeof(wire), &rep);
    if (call_status != SEL4_ERR_OK || rep.length < sizeof(mcp_transport_reply_t))
        return TOOLSVC_ERR_PROVIDER_DOWN;
    mcp_transport_reply_t result;
    bytes_copy(&result, rep.data, sizeof(result));
    if (result.request_tag != wire.request_tag
        || result.output_len >= output_capacity
        || result.output_len > TOOLSVC_MCP_OUTPUT_MAX)
        return TOOLSVC_ERR_PROVIDER_DOWN;
    if (result.status != TOOLSVC_ERR_OK) return result.status;
    bytes_copy(output, toolsvc_arena + output_offset, result.output_len);
    *output_len = result.output_len;
    return TOOLSVC_ERR_OK;
}

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
    toolsvc_runtime_set_repo_backend(target_repo_backend, NULL);
    toolsvc_runtime_set_mcp_backend(target_mcp_backend, NULL);
    static sel4_server_t server;
    sel4_server_init(&server, my_ep);
    (void)sel4_server_register(&server, SEL4_SERVER_OPCODE_ANY,
                               toolsvc_handler, NULL);
    sel4_server_run(&server);
    for (;;) { __asm__ volatile("" ::: "memory"); }
}

#endif
