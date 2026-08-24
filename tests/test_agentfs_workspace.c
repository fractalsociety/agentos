#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define AGENTOS_TEST_HOST 1
#include "../services/agentfs/workspace_overlay.c"

#define BADGE(service, client) \
    (((uint64_t)(service) << 48u) | ((uint64_t)(client) << 32u))

static uint32_t rd32_test(const uint8_t *p, uint32_t off)
{
    return (uint32_t)p[off] | ((uint32_t)p[off + 1u] << 8u)
         | ((uint32_t)p[off + 2u] << 16u) | ((uint32_t)p[off + 3u] << 24u);
}

int main(void)
{
    static uint8_t arena[AGENTFS_SHMEM_SIZE];
    uint8_t reply[56] = {0};
    uint32_t reply_len = 0u;
    const uint32_t client = 11u;
    const uint32_t base = AGENTFS_CLIENT_ARENA_OFFSET(client);
    const uint64_t badge = BADGE(SVC_ID_AGENTFS, client);
    const char path[] = "src/answer.txt";
    const char first[] = "before";
    const char second[] = "after";
    memcpy(arena + base + 0x100u, path, sizeof(path) - 1u);
    memcpy(arena + base + 0x400u, first, sizeof(first) - 1u);

    agentfs_workspace_init(arena, sizeof(arena));
    struct agentfs_req_write write = {
        .path_offset = base + 0x100u,
        .path_len = sizeof(path) - 1u,
        .data_offset = base + 0x400u,
        .data_len = sizeof(first) - 1u,
        .flags = AGENTFS_WRITE_CREATE | AGENTFS_WRITE_TRUNCATE,
    };
    assert(agentfs_workspace_dispatch(badge, MSG_AGENTFS_WRITE,
                                      &write, sizeof(write), reply, &reply_len)
           == AGENTFS_OK);
    assert(rd32_test(reply, 8u) == sizeof(first) - 1u);
    assert(rd32_test(reply, 12u) == sizeof(first) - 1u);
    assert(rd32_test(reply, 16u) == 1u);

    struct agentfs_req_stat stat = {
        .path_offset = base + 0x100u,
        .path_len = sizeof(path) - 1u,
    };
    assert(agentfs_workspace_dispatch(badge, MSG_AGENTFS_STAT,
                                      &stat, sizeof(stat), reply, &reply_len)
           == AGENTFS_OK);
    assert(rd32_test(reply, 8u) == sizeof(first) - 1u);

    struct agentfs_req_read read = {
        .path_offset = base + 0x100u,
        .path_len = sizeof(path) - 1u,
        .output_offset = base + 0x1000u,
        .output_capacity = 128u,
    };
    assert(agentfs_workspace_dispatch(badge, MSG_AGENTFS_READ,
                                      &read, sizeof(read), reply, &reply_len)
           == AGENTFS_OK);
    assert(memcmp(arena + read.output_offset, first, sizeof(first) - 1u) == 0);

    read.output_offset = AGENTFS_CLIENT_ARENA_OFFSET(client + 1u);
    assert(agentfs_workspace_dispatch(badge, MSG_AGENTFS_READ,
                                      &read, sizeof(read), reply, &reply_len)
           == AGENTFS_ERR_DENIED);
    assert(agentfs_workspace_dispatch(BADGE(SVC_ID_MODELSVC, client),
                                      MSG_AGENTFS_STAT, &stat, sizeof(stat),
                                      reply, &reply_len) == AGENTFS_ERR_DENIED);

    assert(agentfs_workspace_dispatch(BADGE(SVC_ID_AGENTFS, client + 1u),
                                      MSG_AGENTFS_STAT, &stat, sizeof(stat),
                                      reply, &reply_len) == AGENTFS_ERR_DENIED);

    memcpy(arena + base + 0x400u, second, sizeof(second) - 1u);
    write.data_len = sizeof(second) - 1u;
    assert(agentfs_workspace_dispatch(badge, MSG_AGENTFS_WRITE,
                                      &write, sizeof(write), reply, &reply_len)
           == AGENTFS_OK);
    assert(rd32_test(reply, 16u) == 2u);

    const char path2[] = "tests/answer.txt";
    const char data2[] = "42\n";
    memcpy(arena + base + 0x500u, path2, sizeof(path2) - 1u);
    memcpy(arena + base + 0x700u, data2, sizeof(data2) - 1u);
    write.path_offset = base + 0x500u;
    write.path_len = sizeof(path2) - 1u;
    write.data_offset = base + 0x700u;
    write.data_len = sizeof(data2) - 1u;
    assert(agentfs_workspace_dispatch(badge, MSG_AGENTFS_WRITE,
                                      &write, sizeof(write), reply, &reply_len)
           == AGENTFS_OK);

    struct agentfs_req_export_overlay export_req = {
        .output_offset = base + 0x1000u,
        .output_capacity = 0x5000u,
    };
    assert(agentfs_workspace_dispatch(badge, MSG_AGENTFS_EXPORT_OVERLAY,
                                      &export_req, sizeof(export_req),
                                      reply, &reply_len) == AGENTFS_OK);
    const uint8_t *bundle = arena + export_req.output_offset;
    assert(rd32_test(bundle, 0u) == AGENTFS_OVERLAY_BUNDLE_MAGIC);
    assert(rd32_test(bundle, 4u) == AGENTFS_OVERLAY_BUNDLE_VERSION);
    assert(rd32_test(bundle, 8u) == 2u);
    assert(rd32_test(bundle, 12u) == rd32_test(reply, 4u));
    export_req.output_offset = AGENTFS_CLIENT_ARENA_OFFSET(client + 1u);
    assert(agentfs_workspace_dispatch(badge, MSG_AGENTFS_EXPORT_OVERLAY,
                                      &export_req, sizeof(export_req),
                                      reply, &reply_len) == AGENTFS_ERR_DENIED);

    struct agentfs_req_delete del = {
        .path_offset = base + 0x100u,
        .path_len = sizeof(path) - 1u,
    };
    assert(agentfs_workspace_dispatch(badge, MSG_AGENTFS_DELETE,
                                      &del, sizeof(del), reply, &reply_len)
           == AGENTFS_OK);
    assert(agentfs_workspace_dispatch(badge, MSG_AGENTFS_STAT,
                                      &stat, sizeof(stat), reply, &reply_len)
           == AGENTFS_ERR_NOT_FOUND);

    puts("agentfs workspace tests: ok");
    return 0;
}
