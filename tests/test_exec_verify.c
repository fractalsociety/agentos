#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define AGENTOS_TEST_HOST 1
#include "../services/exec-server/exec_verify.c"

static uint8_t arena[EXECSVC_SHMEM_SIZE];

static uint64_t badge(uint16_t service, uint16_t client)
{
    return ((uint64_t)service << 48u) | ((uint64_t)client << 32u);
}

int main(void)
{
    const uint16_t client = 11u;
    const uint32_t base = EXECSVC_CLIENT_ARENA_OFFSET(client);
    execsvc_verify_init(arena, sizeof(arena));
    memcpy(arena + base + 0x100u, "after\n", 6u);
    memcpy(arena + base + 0x200u, "after\n", 6u);

    execsvc_verify_exact_wire_t wire = {
        .actual_offset = base + 0x100u,
        .actual_len = 6u,
        .expected_offset = base + 0x200u,
        .expected_len = 6u,
        .request_tag = 42u,
    };
    execsvc_verify_reply_t reply;
    assert(execsvc_verify_dispatch(badge(SVC_ID_EXEC_SERVER, client),
                                   &wire, &reply) == EXECSVC_OK);
    assert(reply.exit_code == 0);
    assert(reply.checked_bytes == 6u);

    arena[base + 0x202u] = 'X';
    assert(execsvc_verify_dispatch(badge(SVC_ID_EXEC_SERVER, client),
                                   &wire, &reply) == EXECSVC_OK);
    assert(reply.exit_code == 1);
    assert(reply.mismatch_offset == 2u);

    wire.expected_offset = EXECSVC_CLIENT_ARENA_OFFSET(client + 1u);
    assert(execsvc_verify_dispatch(badge(SVC_ID_EXEC_SERVER, client),
                                   &wire, &reply) == EXECSVC_ERR_DENIED);
    assert(execsvc_verify_dispatch(badge(SVC_ID_TOOLSVC, client),
                                   &wire, &reply) == EXECSVC_ERR_DENIED);
    puts("exec verify tests: ok");
    return 0;
}
