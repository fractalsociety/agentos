#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define AGENTOS_TEST_HOST 1
#include "../services/toolsvc/tool_svc.c"

#define BADGE(service, client) \
    (((uint64_t)(service) << 48u) | ((uint64_t)(client) << 32u))

static uint32_t rd32_test(const uint8_t *p, uint32_t off)
{
    return (uint32_t)p[off] | ((uint32_t)p[off + 1u] << 8u)
         | ((uint32_t)p[off + 2u] << 16u) | ((uint32_t)p[off + 3u] << 24u);
}

int main(void)
{
    static uint8_t arena[TOOLSVC_SHMEM_SIZE];
    uint8_t reply[56] = {0};
    uint32_t reply_len = 0u;
    const uint32_t client = 11u;
    const uint32_t base = TOOLSVC_CLIENT_ARENA_OFFSET(client);
    const uint64_t badge = BADGE(SVC_ID_TOOLSVC, client);

    toolsvc_runtime_init(arena, sizeof(arena));
    assert(toolsvc_runtime_dispatch(badge, TOOLSVC_OP_HEALTH,
                                    NULL, 0u, reply, &reply_len)
           == TOOLSVC_ERR_OK);
    assert(reply_len == 12u);
    assert(rd32_test(reply, 4u) == 1u);
    assert(rd32_test(reply, 8u) == TOOLSVC_INTERFACE_VERSION);
    assert(toolsvc_runtime_dispatch(BADGE(SVC_ID_MODELSVC, client),
                                    TOOLSVC_OP_HEALTH, NULL, 0u,
                                    reply, &reply_len) == TOOLSVC_ERR_DENIED);

    static const char tool[] = "agent.echo";
    static const char input[] = "{\"action\":\"final\",\"summary\":\"tool-ok\"}";
    const uint32_t name_off = base + 0x100u;
    const uint32_t input_off = base + 0x400u;
    const uint32_t output_off = base + 0x1000u;
    memcpy(arena + name_off, tool, sizeof(tool) - 1u);
    memcpy(arena + input_off, input, sizeof(input) - 1u);

    toolsvc_invoke_wire_t invoke = {
        .name_offset = name_off,
        .name_len = sizeof(tool) - 1u,
        .input_offset = input_off,
        .input_len = sizeof(input) - 1u,
        .output_offset = output_off,
        .output_buf_len = 256u,
    };
    assert(toolsvc_runtime_dispatch(badge, TOOLSVC_OP_INVOKE,
                                    &invoke, sizeof(invoke), reply, &reply_len)
           == TOOLSVC_ERR_OK);
    assert(rd32_test(reply, 4u) == sizeof(input) - 1u);
    assert(memcmp(arena + output_off, input, sizeof(input) - 1u) == 0);

    invoke.output_offset = TOOLSVC_CLIENT_ARENA_OFFSET(client + 1u);
    assert(toolsvc_runtime_dispatch(badge, TOOLSVC_OP_INVOKE,
                                    &invoke, sizeof(invoke), reply, &reply_len)
           == TOOLSVC_ERR_DENIED);

    toolsvc_list_wire_t list = {
        .output_offset = base + 0x2000u,
        .output_buf_len = 512u,
    };
    assert(toolsvc_runtime_dispatch(badge, TOOLSVC_OP_LIST,
                                    &list, sizeof(list), reply, &reply_len)
           == TOOLSVC_ERR_OK);
    assert(strstr((char *)(arena + list.output_offset), "agent.echo") != NULL);

    printf("tool service tests: ok\n");
    return 0;
}
