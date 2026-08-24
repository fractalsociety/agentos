#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define AGENTOS_TEST_HOST 1
#include "../services/toolsvc/tool_svc.c"

#define BADGE(service, client, rights) \
    (((uint64_t)(service) << 48u) | ((uint64_t)(client) << 32u) \
     | (uint64_t)(rights))

static uint32_t fake_repo(bool read, const uint8_t *input, uint32_t input_len,
                          uint8_t *output, uint32_t output_capacity,
                          uint32_t *output_len, void *ctx)
{
    (void)ctx;
    const char *result = read ? "int answer(void) { return 0; }\n"
                              : "src/answer.c:1:int answer(void)\n";
    uint32_t len = (uint32_t)strlen(result);
    assert(input_len > 0u);
    assert(output_capacity > len);
    memcpy(output, result, len);
    *output_len = len;
    return TOOLSVC_ERR_OK;
}

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
    const uint64_t badge = BADGE(SVC_ID_TOOLSVC, client, TOOLSVC_RIGHT_ALL);
    const uint64_t echo_badge = BADGE(SVC_ID_TOOLSVC, client,
                                      TOOLSVC_RIGHT_AGENT_ECHO);

    toolsvc_runtime_init(arena, sizeof(arena));
    toolsvc_runtime_set_repo_backend(fake_repo, NULL);
    assert(toolsvc_runtime_dispatch(badge, TOOLSVC_OP_HEALTH,
                                    NULL, 0u, reply, &reply_len)
           == TOOLSVC_ERR_OK);
    assert(reply_len == 12u);
    assert(rd32_test(reply, 4u) == 3u);
    assert(rd32_test(reply, 8u) == TOOLSVC_INTERFACE_VERSION);
    assert(toolsvc_runtime_dispatch(BADGE(SVC_ID_MODELSVC, client, 0u),
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

    static const char search_tool[] = "repo.search";
    static const char query[] = "answer";
    memcpy(arena + name_off, search_tool, sizeof(search_tool) - 1u);
    memcpy(arena + input_off, query, sizeof(query) - 1u);
    invoke.name_len = sizeof(search_tool) - 1u;
    invoke.input_len = sizeof(query) - 1u;
    assert(toolsvc_runtime_dispatch(echo_badge, TOOLSVC_OP_INVOKE,
                                    &invoke, sizeof(invoke), reply, &reply_len)
           == TOOLSVC_ERR_DENIED);
    assert(toolsvc_runtime_dispatch(badge, TOOLSVC_OP_INVOKE,
                                    &invoke, sizeof(invoke), reply, &reply_len)
           == TOOLSVC_ERR_OK);
    assert(strstr((char *)(arena + output_off), "src/answer.c") != NULL);

    static const char read_tool[] = "repo.read";
    static const char path[] = "src/answer.c";
    memcpy(arena + name_off, read_tool, sizeof(read_tool) - 1u);
    memcpy(arena + input_off, path, sizeof(path) - 1u);
    invoke.name_len = sizeof(read_tool) - 1u;
    invoke.input_len = sizeof(path) - 1u;
    assert(toolsvc_runtime_dispatch(echo_badge, TOOLSVC_OP_INVOKE,
                                    &invoke, sizeof(invoke), reply, &reply_len)
           == TOOLSVC_ERR_DENIED);
    assert(toolsvc_runtime_dispatch(badge, TOOLSVC_OP_INVOKE,
                                    &invoke, sizeof(invoke), reply, &reply_len)
           == TOOLSVC_ERR_OK);
    assert(strstr((char *)(arena + output_off), "return 0") != NULL);

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
    assert(strstr((char *)(arena + list.output_offset), "repo.search") != NULL);
    assert(strstr((char *)(arena + list.output_offset), "repo.read") != NULL);
    assert(rd32_test(reply, 4u) == 3u);

    assert(toolsvc_runtime_dispatch(echo_badge, TOOLSVC_OP_LIST,
                                    &list, sizeof(list), reply, &reply_len)
           == TOOLSVC_ERR_OK);
    assert(strstr((char *)(arena + list.output_offset), "repo.search") == NULL);
    assert(rd32_test(reply, 4u) == 1u);

    printf("tool service tests: ok\n");
    return 0;
}
