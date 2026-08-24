#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define AGENTOS_TEST_HOST 1
#include "../services/exec-server/exec_verify.c"

static uint8_t arena[EXECSVC_SHMEM_SIZE];
static uint32_t transport_calls;

static uint32_t fake_transport(uint32_t profile_id,
                               const uint8_t *source, uint32_t source_len,
                               uint8_t *output, uint32_t output_capacity,
                               uint32_t request_tag, int32_t *exit_code,
                               uint32_t *output_len, void *ctx)
{
    (void)ctx;
    assert(profile_id == EXECSVC_PROFILE_C11_COMPILE);
    static const char expected_source[] = "int answer(void){return 42;}";
    assert(source_len == sizeof(expected_source) - 1u);
    assert(memcmp(source, expected_source, source_len) == 0);
    assert(request_tag == 77u);
    static const char compiled[] = "compile: ok";
    assert(output_capacity >= sizeof(compiled) - 1u);
    memcpy(output, compiled, sizeof(compiled) - 1u);
    *output_len = sizeof(compiled) - 1u;
    *exit_code = 0;
    transport_calls++;
    return EXECSVC_OK;
}

static uint64_t badge_with_rights(uint16_t service, uint16_t client,
                                  uint32_t rights)
{
    return ((uint64_t)service << 48u) | ((uint64_t)client << 32u) | rights;
}

static uint64_t badge(uint16_t service, uint16_t client)
{
    return badge_with_rights(service, client, EXECSVC_RIGHT_ALL);
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
    assert(execsvc_verify_dispatch(
               badge_with_rights(SVC_ID_EXEC_SERVER, client,
                                 EXECSVC_RIGHT_C11_COMPILE),
               &wire, &reply) == EXECSVC_ERR_DENIED);

    static const char source[] = "int answer(void){return 42;}";
    memcpy(arena + base + 0x400u, source, sizeof(source) - 1u);
    execsvc_run_profile_wire_t run = {
        .source_offset = base + 0x400u,
        .source_len = sizeof(source) - 1u,
        .output_offset = base + 0x3000u,
        .output_capacity = 1024u,
        .profile_id = EXECSVC_PROFILE_C11_COMPILE,
        .request_tag = 77u,
    };
    execsvc_run_profile_reply_t run_reply;
    execsvc_verify_set_transport(fake_transport, NULL);
    assert(execsvc_run_profile_dispatch(badge(SVC_ID_EXEC_SERVER, client),
                                        &run, &run_reply) == EXECSVC_OK);
    assert(run_reply.exit_code == 0);
    assert(run_reply.output_len == strlen("compile: ok"));
    assert(run_reply.request_tag == 77u);
    assert(memcmp(arena + run.output_offset, "compile: ok",
                  run_reply.output_len) == 0);
    assert(transport_calls == 1u);

    assert(execsvc_run_profile_dispatch(
               badge_with_rights(SVC_ID_EXEC_SERVER, client,
                                 EXECSVC_RIGHT_VERIFY_EXACT),
               &run, &run_reply) == EXECSVC_ERR_DENIED);
    assert(transport_calls == 1u);
    run.profile_id = EXECSVC_PROFILE_AGENTOS_REPO_TEST;
    assert(execsvc_run_profile_dispatch(
               badge_with_rights(SVC_ID_EXEC_SERVER, client,
                                 EXECSVC_RIGHT_C11_COMPILE),
               &run, &run_reply) == EXECSVC_ERR_DENIED);
    assert(transport_calls == 1u);

    run.profile_id = 0xfeedu;
    assert(execsvc_run_profile_dispatch(badge(SVC_ID_EXEC_SERVER, client),
                                        &run, &run_reply)
           == EXECSVC_ERR_UNSUPPORTED);
    assert(transport_calls == 1u);
    run.profile_id = EXECSVC_PROFILE_C11_COMPILE;
    run.output_offset = EXECSVC_CLIENT_ARENA_OFFSET(client + 1u);
    assert(execsvc_run_profile_dispatch(badge(SVC_ID_EXEC_SERVER, client),
                                        &run, &run_reply)
           == EXECSVC_ERR_DENIED);
    run.output_offset = base + 0x3000u;
    assert(execsvc_run_profile_dispatch(badge(SVC_ID_TOOLSVC, client),
                                        &run, &run_reply)
           == EXECSVC_ERR_DENIED);
    execsvc_verify_set_transport(NULL, NULL);
    assert(execsvc_run_profile_dispatch(badge(SVC_ID_EXEC_SERVER, client),
                                        &run, &run_reply)
           == EXECSVC_ERR_TRANSPORT);
    puts("exec verify tests: ok");
    return 0;
}
