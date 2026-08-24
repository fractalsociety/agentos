/* Isolated ExecServer verification PD. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../../contracts/execsvc/interface.h"
#include "../../kernel/agentos-root-task/include/system_desc.h"
#ifndef AGENTOS_TEST_HOST
#include "../../kernel/agentos-root-task/include/sel4_server.h"
#endif

static uint8_t *exec_arena;
static uint32_t exec_arena_size;
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
    if (badge_service(badge) != SVC_ID_EXEC_SERVER) {
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

#ifndef AGENTOS_TEST_HOST
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

__attribute__((noreturn))
void pd_main(seL4_CPtr my_ep, seL4_CPtr ns_ep)
{
    (void)ns_ep;
    execsvc_verify_init((void *)(uintptr_t)EXECSVC_SHMEM_VADDR,
                        EXECSVC_SHMEM_SIZE);
    sel4_server_init(&exec_server, my_ep);
    (void)sel4_server_register(&exec_server, EXECSVC_OP_VERIFY_EXACT,
                               h_verify_exact, NULL);
    sel4_server_run(&exec_server);
    for (;;) { __asm__ volatile("" ::: "memory"); }
}
#endif
