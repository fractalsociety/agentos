/* Badge-isolated mutable workspace overlay owned by the singleton AgentFS PD. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "workspace_overlay.h"
#include "../../kernel/fractalos-root-task/include/contracts/agentfs_contract.h"
#include "../../kernel/fractalos-root-task/include/system_desc.h"

typedef struct workspace_file {
    bool active;
    uint16_t owner;
    uint16_t path_len;
    uint32_t inode;
    uint32_t version;
    uint32_t size;
    char path[AGENTFS_PATH_MAX];
    uint8_t data[AGENTFS_WORKSPACE_FILE_MAX];
} workspace_file_t;

static uint8_t *workspace_arena;
static uint32_t workspace_arena_size;
static workspace_file_t workspace_files[AGENTFS_WORKSPACE_MAX_FILES];
static uint32_t next_inode;

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

static void wr32(uint8_t *p, uint32_t off, uint32_t value)
{
    p[off] = (uint8_t)value;
    p[off + 1u] = (uint8_t)(value >> 8u);
    p[off + 2u] = (uint8_t)(value >> 16u);
    p[off + 3u] = (uint8_t)(value >> 24u);
}

static uint16_t badge_service(uint64_t badge)
{
    return (uint16_t)(badge >> 48u);
}

static uint16_t badge_client(uint64_t badge)
{
    return (uint16_t)(badge >> 32u);
}

static bool caller_range(uint16_t client, uint32_t offset, uint32_t len)
{
    if (workspace_arena == NULL || client >= AGENTFS_CLIENT_SLOT_COUNT)
        return false;
    uint32_t base = AGENTFS_CLIENT_ARENA_OFFSET(client);
    return offset >= base
        && offset <= base + AGENTFS_CLIENT_ARENA_SIZE
        && len <= base + AGENTFS_CLIENT_ARENA_SIZE - offset
        && offset <= workspace_arena_size
        && len <= workspace_arena_size - offset;
}

static bool path_valid(uint16_t client, uint32_t offset, uint32_t len)
{
    if (len == 0u || len >= AGENTFS_PATH_MAX
        || !caller_range(client, offset, len)) return false;
    const uint8_t *path = workspace_arena + offset;
    if (path[0] == '/' || path[len - 1u] == '/') return false;
    for (uint32_t i = 0u; i < len; i++) {
        if (path[i] == '\0' || path[i] == '\\') return false;
        if (path[i] == '.' && i + 1u < len && path[i + 1u] == '.')
            return false;
    }
    return true;
}

static bool path_equal(const workspace_file_t *file,
                       const uint8_t *path, uint32_t path_len)
{
    if (!file->active || file->path_len != path_len) return false;
    for (uint32_t i = 0u; i < path_len; i++)
        if ((uint8_t)file->path[i] != path[i]) return false;
    return true;
}

static workspace_file_t *find_file(uint16_t owner,
                                   const uint8_t *path, uint32_t path_len)
{
    for (uint32_t i = 0u; i < AGENTFS_WORKSPACE_MAX_FILES; i++)
        if (workspace_files[i].owner == owner
            && path_equal(&workspace_files[i], path, path_len))
            return &workspace_files[i];
    return NULL;
}

static workspace_file_t *new_file(uint16_t owner,
                                  const uint8_t *path, uint32_t path_len)
{
    for (uint32_t i = 0u; i < AGENTFS_WORKSPACE_MAX_FILES; i++) {
        workspace_file_t *file = &workspace_files[i];
        if (file->active) continue;
        bytes_zero(file, sizeof(*file));
        file->active = true;
        file->owner = owner;
        file->path_len = (uint16_t)path_len;
        file->inode = next_inode++;
        file->version = 1u;
        bytes_copy(file->path, path, path_len);
        return file;
    }
    return NULL;
}

void agentfs_workspace_init(void *arena, uint32_t arena_size)
{
    workspace_arena = (uint8_t *)arena;
    workspace_arena_size = arena_size;
    bytes_zero(workspace_files, sizeof(workspace_files));
    next_inode = 1u;
}

static uint32_t finish(uint8_t *reply, uint32_t *reply_len, uint32_t status)
{
    wr32(reply, 0u, status);
    if (*reply_len < 4u) *reply_len = 4u;
    return status;
}

uint32_t agentfs_workspace_dispatch(uint64_t badge, uint32_t opcode,
                                    const void *payload, uint32_t payload_len,
                                    uint8_t *reply, uint32_t *reply_len)
{
    if (reply == NULL || reply_len == NULL) return AGENTFS_ERR_BAD_PATH;
    bytes_zero(reply, 56u);
    *reply_len = 4u;
    if (badge_service(badge) != SVC_ID_AGENTFS)
        return finish(reply, reply_len, AGENTFS_ERR_DENIED);
    uint16_t client = badge_client(badge);

    if (opcode == MSG_AGENTFS_WRITE && payload != NULL
        && payload_len == sizeof(struct agentfs_req_write)) {
        struct agentfs_req_write req;
        bytes_copy(&req, payload, sizeof(req));
        if (!path_valid(client, req.path_offset, req.path_len)
            || !caller_range(client, req.data_offset, req.data_len))
            return finish(reply, reply_len, AGENTFS_ERR_DENIED);
        if (req.file_offset > AGENTFS_WORKSPACE_FILE_MAX
            || req.data_len > AGENTFS_WORKSPACE_FILE_MAX - req.file_offset)
            return finish(reply, reply_len, AGENTFS_ERR_TOO_LARGE);
        const uint8_t *path = workspace_arena + req.path_offset;
        workspace_file_t *file = find_file(client, path, req.path_len);
        bool created = false;
        if (file == NULL) {
            if ((req.flags & AGENTFS_WRITE_CREATE) == 0u)
                return finish(reply, reply_len, AGENTFS_ERR_NOT_FOUND);
            file = new_file(client, path, req.path_len);
            if (file == NULL)
                return finish(reply, reply_len, AGENTFS_ERR_NO_SPACE);
            created = true;
        }
        if ((req.flags & AGENTFS_WRITE_TRUNCATE) != 0u) file->size = 0u;
        bytes_copy(file->data + req.file_offset,
                   workspace_arena + req.data_offset, req.data_len);
        uint32_t end = req.file_offset + req.data_len;
        if (end > file->size) file->size = end;
        if (!created) file->version++;
        wr32(reply, 4u, file->inode);
        wr32(reply, 8u, req.data_len);
        wr32(reply, 12u, file->size);
        wr32(reply, 16u, file->version);
        *reply_len = 20u;
        return finish(reply, reply_len, AGENTFS_OK);
    }

    if (opcode == MSG_AGENTFS_READ && payload != NULL
        && payload_len == sizeof(struct agentfs_req_read)) {
        struct agentfs_req_read req;
        bytes_copy(&req, payload, sizeof(req));
        if (!path_valid(client, req.path_offset, req.path_len)
            || !caller_range(client, req.output_offset, req.output_capacity))
            return finish(reply, reply_len, AGENTFS_ERR_DENIED);
        workspace_file_t *file = find_file(
            client, workspace_arena + req.path_offset, req.path_len);
        if (file == NULL)
            return finish(reply, reply_len, AGENTFS_ERR_NOT_FOUND);
        uint32_t actual = 0u;
        if (req.file_offset < file->size) {
            actual = file->size - req.file_offset;
            if (actual > req.output_capacity) actual = req.output_capacity;
            bytes_copy(workspace_arena + req.output_offset,
                       file->data + req.file_offset, actual);
        }
        wr32(reply, 4u, actual);
        wr32(reply, 8u, file->size);
        wr32(reply, 12u, file->version);
        *reply_len = 16u;
        return finish(reply, reply_len, AGENTFS_OK);
    }

    if (opcode == MSG_AGENTFS_STAT && payload != NULL
        && payload_len == sizeof(struct agentfs_req_stat)) {
        struct agentfs_req_stat req;
        bytes_copy(&req, payload, sizeof(req));
        if (!path_valid(client, req.path_offset, req.path_len))
            return finish(reply, reply_len, AGENTFS_ERR_DENIED);
        workspace_file_t *file = find_file(
            client, workspace_arena + req.path_offset, req.path_len);
        if (file == NULL)
            return finish(reply, reply_len, AGENTFS_ERR_NOT_FOUND);
        wr32(reply, 4u, file->inode);
        wr32(reply, 8u, file->size);
        wr32(reply, 12u, 0u);
        wr32(reply, 16u, 0u);
        wr32(reply, 20u, file->version);
        *reply_len = 24u;
        return finish(reply, reply_len, AGENTFS_OK);
    }

    if (opcode == MSG_AGENTFS_DELETE && payload != NULL
        && payload_len == sizeof(struct agentfs_req_delete)) {
        struct agentfs_req_delete req;
        bytes_copy(&req, payload, sizeof(req));
        if (!path_valid(client, req.path_offset, req.path_len))
            return finish(reply, reply_len, AGENTFS_ERR_DENIED);
        workspace_file_t *file = find_file(
            client, workspace_arena + req.path_offset, req.path_len);
        if (file == NULL)
            return finish(reply, reply_len, AGENTFS_ERR_NOT_FOUND);
        file->active = false;
        return finish(reply, reply_len, AGENTFS_OK);
    }

    if (opcode == MSG_AGENTFS_EXPORT_OVERLAY && payload != NULL
        && payload_len == sizeof(struct agentfs_req_export_overlay)) {
        struct agentfs_req_export_overlay req;
        bytes_copy(&req, payload, sizeof(req));
        if (req.output_capacity < sizeof(agentfs_overlay_bundle_header_t)
            || !caller_range(client, req.output_offset, req.output_capacity))
            return finish(reply, reply_len, AGENTFS_ERR_DENIED);

        uint32_t total = sizeof(agentfs_overlay_bundle_header_t);
        uint32_t count = 0u;
        for (uint32_t i = 0u; i < AGENTFS_WORKSPACE_MAX_FILES; i++) {
            const workspace_file_t *file = &workspace_files[i];
            if (!file->active || file->owner != client) continue;
            uint32_t entry_len = sizeof(agentfs_overlay_entry_header_t)
                               + file->path_len + file->size;
            if (entry_len > req.output_capacity - total)
                return finish(reply, reply_len, AGENTFS_ERR_TOO_LARGE);
            total += entry_len;
            count++;
        }
        if (count == 0u)
            return finish(reply, reply_len, AGENTFS_ERR_NOT_FOUND);

        uint8_t *out = workspace_arena + req.output_offset;
        wr32(out, 0u, AGENTFS_OVERLAY_BUNDLE_MAGIC);
        wr32(out, 4u, AGENTFS_OVERLAY_BUNDLE_VERSION);
        wr32(out, 8u, count);
        wr32(out, 12u, total);
        uint32_t cursor = sizeof(agentfs_overlay_bundle_header_t);
        for (uint32_t i = 0u; i < AGENTFS_WORKSPACE_MAX_FILES; i++) {
            const workspace_file_t *file = &workspace_files[i];
            if (!file->active || file->owner != client) continue;
            wr32(out, cursor, file->path_len);
            wr32(out, cursor + 4u, file->size);
            cursor += sizeof(agentfs_overlay_entry_header_t);
            bytes_copy(out + cursor, file->path, file->path_len);
            cursor += file->path_len;
            bytes_copy(out + cursor, file->data, file->size);
            cursor += file->size;
        }
        wr32(reply, 4u, total);
        wr32(reply, 8u, count);
        *reply_len = 12u;
        return finish(reply, reply_len, AGENTFS_OK);
    }

    return finish(reply, reply_len, AGENTFS_ERR_BAD_PATH);
}
