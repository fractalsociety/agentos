/* Isolated ExecServer verification PD. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../../contracts/execsvc/interface.h"
#include "../../kernel/agentos-root-task/include/system_desc.h"
#ifndef AGENTOS_TEST_HOST
#include "../../kernel/agentos-root-task/include/sel4_server.h"
#include "../../kernel/agentos-root-task/include/sel4_client.h"
#include "../../kernel/agentos-root-task/include/exec_transport.h"
#endif

static uint8_t *exec_arena;
static uint32_t exec_arena_size;
typedef uint32_t (*execsvc_transport_fn)(
    uint32_t profile_id, const uint8_t *source, uint32_t source_len,
    uint8_t *output, uint32_t output_capacity, uint32_t request_tag,
    int32_t *exit_code, uint32_t *output_len, void *ctx);
static execsvc_transport_fn exec_transport;
static void *exec_transport_ctx;
#ifndef AGENTOS_TEST_HOST
static sel4_server_t exec_server;
#endif

static uint16_t badge_service(uint64_t badge)
{
    return (uint16_t)(badge >> 48u);
}

static uint16_t badge_client(uint64_t badge)
{
    return (uint16_t)(badge >> 32u);
}

static uint32_t badge_rights(uint64_t badge)
{
    return (uint32_t)badge;
}

static bool client_range(uint16_t client, uint32_t offset, uint32_t len)
{
    if (exec_arena == NULL || client >= EXECSVC_CLIENT_SLOT_COUNT)
        return false;
    uint32_t base = EXECSVC_CLIENT_ARENA_OFFSET(client);
    return offset >= base
        && offset <= base + EXECSVC_CLIENT_ARENA_SIZE
        && len <= base + EXECSVC_CLIENT_ARENA_SIZE - offset
        && offset <= exec_arena_size
        && len <= exec_arena_size - offset;
}

static void bytes_copy(void *dst_ptr, const void *src_ptr, uint32_t len)
{
    uint8_t *dst = (uint8_t *)dst_ptr;
    const uint8_t *src = (const uint8_t *)src_ptr;
    for (uint32_t i = 0u; i < len; i++) dst[i] = src[i];
}

void execsvc_verify_init(void *arena, uint32_t arena_size)
{
    exec_arena = (uint8_t *)arena;
    exec_arena_size = arena_size;
}

void execsvc_verify_set_transport(execsvc_transport_fn transport, void *ctx)
{
    exec_transport = transport;
    exec_transport_ctx = ctx;
}

uint32_t execsvc_verify_dispatch(uint64_t badge,
                                 const execsvc_verify_exact_wire_t *wire,
                                 execsvc_verify_reply_t *reply)
{
    if (reply == NULL) return EXECSVC_ERR_INVALID;
    *reply = (execsvc_verify_reply_t){
        .status = EXECSVC_ERR_INVALID,
        .exit_code = -1,
        .checked_bytes = 0u,
        .mismatch_offset = UINT32_MAX,
    };
    if (badge_service(badge) != SVC_ID_EXEC_SERVER
        || (badge_rights(badge) & EXECSVC_RIGHT_VERIFY_EXACT) == 0u) {
        reply->status = EXECSVC_ERR_DENIED;
    } else if (wire != NULL) {
        uint16_t client = badge_client(badge);
        if (!client_range(client, wire->actual_offset, wire->actual_len)
            || !client_range(client, wire->expected_offset,
                             wire->expected_len)) {
            reply->status = EXECSVC_ERR_DENIED;
        } else {
            reply->status = EXECSVC_OK;
            reply->checked_bytes = wire->actual_len < wire->expected_len
                ? wire->actual_len : wire->expected_len;
            reply->exit_code = wire->actual_len == wire->expected_len ? 0 : 1;
            const uint8_t *actual = exec_arena + wire->actual_offset;
            const uint8_t *expected = exec_arena + wire->expected_offset;
            for (uint32_t i = 0u; i < reply->checked_bytes; i++) {
                if (actual[i] == expected[i]) continue;
                reply->exit_code = 1;
                reply->mismatch_offset = i;
                break;
            }
            if (reply->exit_code != 0
                && reply->mismatch_offset == UINT32_MAX)
                reply->mismatch_offset = reply->checked_bytes;
        }
    }
    return reply->status;
}

uint32_t execsvc_run_profile_dispatch(
    uint64_t badge, const execsvc_run_profile_wire_t *wire,
    execsvc_run_profile_reply_t *reply)
{
    if (reply == NULL) return EXECSVC_ERR_INVALID;
    *reply = (execsvc_run_profile_reply_t){
        .status = EXECSVC_ERR_INVALID,
        .exit_code = -1,
        .output_len = 0u,
        .request_tag = wire != NULL ? wire->request_tag : 0u,
    };
    if (badge_service(badge) != SVC_ID_EXEC_SERVER) {
        reply->status = EXECSVC_ERR_DENIED;
        return reply->status;
    }
    if (wire == NULL || wire->source_len == 0u
        || wire->source_len > EXECSVC_SOURCE_MAX
        || wire->output_capacity == 0u
        || wire->output_capacity > EXECSVC_OUTPUT_MAX) {
        return reply->status;
    }
    uint32_t required_right = EXECSVC_PROFILE_RIGHT(wire->profile_id);
    if (required_right == 0u) {
        reply->status = EXECSVC_ERR_UNSUPPORTED;
        return reply->status;
    }
    if ((badge_rights(badge) & required_right) == 0u) {
        reply->status = EXECSVC_ERR_DENIED;
        return reply->status;
    }
    uint16_t client = badge_client(badge);
    if (!client_range(client, wire->source_offset, wire->source_len)
        || !client_range(client, wire->output_offset, wire->output_capacity)) {
        reply->status = EXECSVC_ERR_DENIED;
        return reply->status;
    }
    uint32_t source_end = wire->source_offset + wire->source_len;
    uint32_t output_end = wire->output_offset + wire->output_capacity;
    if (wire->source_offset < output_end && wire->output_offset < source_end) {
        reply->status = EXECSVC_ERR_INVALID;
        return reply->status;
    }
    if (exec_transport == NULL) {
        reply->status = EXECSVC_ERR_TRANSPORT;
        return reply->status;
    }
    uint32_t output_len = 0u;
    int32_t exit_code = -1;
    uint32_t status = exec_transport(
        wire->profile_id, exec_arena + wire->source_offset, wire->source_len,
        exec_arena + wire->output_offset, wire->output_capacity,
        wire->request_tag, &exit_code, &output_len, exec_transport_ctx);
    if (status != EXECSVC_OK || output_len > wire->output_capacity) {
        reply->status = status == EXECSVC_OK
            ? EXECSVC_ERR_TRANSPORT : status;
        return reply->status;
    }
    reply->status = EXECSVC_OK;
    reply->exit_code = exit_code;
    reply->output_len = output_len;
    return reply->status;
}

#ifndef AGENTOS_TEST_HOST
static uint32_t target_transport(
    uint32_t profile_id, const uint8_t *source, uint32_t source_len,
    uint8_t *output, uint32_t output_capacity, uint32_t request_tag,
    int32_t *exit_code, uint32_t *output_len, void *ctx)
{
    (void)ctx;
    uintptr_t arena_base = (uintptr_t)exec_arena;
    uintptr_t source_addr = (uintptr_t)source;
    uintptr_t output_addr = (uintptr_t)output;
    if (source_addr < arena_base || source_addr > arena_base + exec_arena_size
        || output_addr < arena_base || output_addr > arena_base + exec_arena_size
        || source_len > exec_arena_size - (uint32_t)(source_addr - arena_base)
        || output_capacity > exec_arena_size
            - (uint32_t)(output_addr - arena_base))
        return EXECSVC_ERR_INVALID;
    execsvc_run_profile_wire_t wire = {
        .source_offset = (uint32_t)(source_addr - arena_base),
        .source_len = source_len,
        .output_offset = (uint32_t)(output_addr - arena_base),
        .output_capacity = output_capacity,
        .profile_id = profile_id,
        .request_tag = request_tag,
    };
    sel4_msg_t rep;
    uint32_t status = sel4_client_call(PD_CNODE_SLOT_EXEC_TRANSPORT_EP,
                                       EXEC_TRANSPORT_OP_RUN,
                                       &wire, sizeof(wire), &rep);
    if (status != SEL4_ERR_OK || rep.length < sizeof(execsvc_run_profile_reply_t))
        return EXECSVC_ERR_TRANSPORT;
    execsvc_run_profile_reply_t transport_reply;
    bytes_copy(&transport_reply, rep.data, sizeof(transport_reply));
    if (transport_reply.request_tag != request_tag
        || transport_reply.output_len > output_capacity)
        return EXECSVC_ERR_TRANSPORT;
    *exit_code = transport_reply.exit_code;
    *output_len = transport_reply.output_len;
    return transport_reply.status;
}

static uint32_t h_verify_exact(sel4_badge_t badge, const sel4_msg_t *req,
                               sel4_msg_t *rep, void *ctx)
{
    (void)ctx;
    execsvc_verify_exact_wire_t wire;
    execsvc_verify_reply_t reply;
    const execsvc_verify_exact_wire_t *wire_ptr = NULL;
    if (req->length == sizeof(wire)) {
        bytes_copy(&wire, req->data, sizeof(wire));
        wire_ptr = &wire;
    }
    uint32_t status = execsvc_verify_dispatch(badge, wire_ptr, &reply);
    bytes_copy(rep->data, &reply, sizeof(reply));
    rep->length = sizeof(reply);
    return status;
}

static uint32_t h_run_profile(sel4_badge_t badge, const sel4_msg_t *req,
                              sel4_msg_t *rep, void *ctx)
{
    (void)ctx;
    execsvc_run_profile_wire_t wire;
    execsvc_run_profile_reply_t reply;
    const execsvc_run_profile_wire_t *wire_ptr = NULL;
    if (req->length == sizeof(wire)) {
        bytes_copy(&wire, req->data, sizeof(wire));
        wire_ptr = &wire;
    }
    uint32_t status = execsvc_run_profile_dispatch(badge, wire_ptr, &reply);
    bytes_copy(rep->data, &reply, sizeof(reply));
    rep->length = sizeof(reply);
    return status;
}

__attribute__((noreturn))
void pd_main(seL4_CPtr my_ep, seL4_CPtr ns_ep)
{
    (void)ns_ep;
    execsvc_verify_init((void *)(uintptr_t)EXECSVC_SHMEM_VADDR,
                        EXECSVC_SHMEM_SIZE);
    execsvc_verify_set_transport(target_transport, NULL);
    sel4_server_init(&exec_server, my_ep);
    (void)sel4_server_register(&exec_server, EXECSVC_OP_VERIFY_EXACT,
                               h_verify_exact, NULL);
    (void)sel4_server_register(&exec_server, EXECSVC_OP_RUN_PROFILE,
                               h_run_profile, NULL);
    sel4_server_run(&exec_server);
    for (;;) { __asm__ volatile("" ::: "memory"); }
}
#endif
