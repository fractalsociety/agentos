/*
 * AgentFS IPC Contract
 *
 * AgentFS is the distributed object store and service registry for agentOS.
 * It stores WASM modules, configuration blobs, and ephemeral agent state.
 * It also serves as the /devices namespace for guest OS device discovery.
 *
 * Channel: CH_VFS_SERVER (reused for AgentFS in current build)
 * Opcodes: MSG_AGENTFS_* (see agentos.h)
 *
 * Invariants:
 *   - All path arguments are NUL-terminated strings placed in the shared
 *     agentfs_shmem region before the IPC call.
 *   - READ/WRITE data is also transferred via agentfs_shmem.
 *   - SEARCH queries use a prefix-match on the path component.
 *   - A successful WRITE publishes EVT_OBJECT_CREATED to the EventBus.
 *   - DELETE tombstones the object; EVT_OBJECT_DELETED is published.
 *   - STAT on a non-existent path returns AGENTFS_ERR_NOT_FOUND.
 */

#pragma once
#include "../agentos.h"

#define AGENTFS_INTERFACE_VERSION 2u

/* Singleton transfer arena. AgentFS owns all 4 MiB; an ordinary MemoryCap
 * client maps only the badge-selected 48 KiB partition. File contents remain
 * in AgentFS private storage and are copied through this bounded window. */
#define AGENTFS_SHMEM_VADDR              0x62000000u
#define AGENTFS_SHMEM_SIZE               (4u * 1024u * 1024u)
#define AGENTFS_CLIENT_SLOT_COUNT        64u
#define AGENTFS_CLIENT_ARENA_SIZE        (48u * 1024u)
#define AGENTFS_CLIENT_REGION_SIZE       \
    (AGENTFS_CLIENT_SLOT_COUNT * AGENTFS_CLIENT_ARENA_SIZE)
#define AGENTFS_INTERNAL_ARENA_OFFSET    AGENTFS_CLIENT_REGION_SIZE
#define AGENTFS_CLIENT_ARENA_OFFSET(client_id) \
    ((uint32_t)(client_id) * AGENTFS_CLIENT_ARENA_SIZE)
#define AGENTFS_CLIENT_ARENA_VADDR(client_id) \
    (AGENTFS_SHMEM_VADDR + AGENTFS_CLIENT_ARENA_OFFSET(client_id))

#define AGENTFS_PATH_MAX                 128u
#define AGENTFS_WORKSPACE_MAX_FILES       64u
#define AGENTFS_WORKSPACE_FILE_MAX      8192u
#define AGENTFS_WRITE_CREATE        (1u << 0)
#define AGENTFS_WRITE_TRUNCATE      (1u << 1)

/* ─── Channel IDs ────────────────────────────────────────────────────────── */
#define AGENTFS_CH_CONTROLLER   CH_VFS_SERVER   /* controller → agentfs */

/* ─── Request structs ────────────────────────────────────────────────────── */

struct agentfs_req_read {
    uint32_t path_offset;
    uint32_t path_len;
    uint32_t output_offset;
    uint32_t output_capacity;
    uint32_t file_offset;
};

struct agentfs_req_write {
    uint32_t path_offset;
    uint32_t path_len;
    uint32_t data_offset;
    uint32_t data_len;
    uint32_t file_offset;
    uint32_t flags;
};

struct agentfs_req_stat {
    uint32_t path_offset;
    uint32_t path_len;
};

struct agentfs_req_list {
    uint32_t path_len;          /* directory path in shmem */
    uint32_t max_entries;       /* max entries to return */
};

struct agentfs_req_delete {
    uint32_t path_offset;
    uint32_t path_len;
};

struct agentfs_req_search {
    uint32_t query_len;         /* prefix query string in shmem */
    uint32_t max_results;
};

/* ─── Reply structs ──────────────────────────────────────────────────────── */

struct agentfs_reply_read {
    uint32_t ok;
    uint32_t actual;            /* bytes actually read */
    uint32_t file_size;
    uint32_t version;
};

struct agentfs_reply_write {
    uint32_t ok;
    uint32_t inode;             /* inode of written object */
    uint32_t written;           /* bytes written */
    uint32_t file_size;
    uint32_t version;
};

struct agentfs_reply_stat {
    uint32_t ok;
    uint32_t inode;
    uint32_t size_lo;           /* object size (low 32 bits) */
    uint32_t size_hi;
    uint32_t flags;             /* AGENTFS_FLAG_* */
};

#define AGENTFS_FLAG_DIR      (1u << 0)
#define AGENTFS_FLAG_WASM     (1u << 1)
#define AGENTFS_FLAG_READONLY (1u << 2)
#define AGENTFS_FLAG_EVICTED  (1u << 3)  /* in cold tier */

struct agentfs_reply_list {
    uint32_t ok;
    uint32_t count;             /* entries written to shmem */
};

struct agentfs_reply_delete {
    uint32_t ok;
};

struct agentfs_reply_search {
    uint32_t ok;
    uint32_t count;             /* results written to shmem */
};

/* ─── Shmem layout: directory listing entry ──────────────────────────────── */

typedef struct __attribute__((packed)) {
    uint32_t inode;
    uint32_t size_lo;
    uint32_t flags;
    uint8_t  name[64];          /* NUL-terminated object name */
} agentfs_dirent_t;

/* ─── Error codes ────────────────────────────────────────────────────────── */

enum agentfs_error {
    AGENTFS_OK              = 0,
    AGENTFS_ERR_NOT_FOUND   = 1,
    AGENTFS_ERR_NO_SPACE    = 2,
    AGENTFS_ERR_BAD_PATH    = 3,
    AGENTFS_ERR_READONLY    = 4,
    AGENTFS_ERR_TOO_LARGE   = 5,
    AGENTFS_ERR_BAD_INODE   = 6,
    AGENTFS_ERR_DENIED      = 7,
};

_Static_assert(sizeof(struct agentfs_req_write) == 24u,
               "AgentFS write wire must fit one seL4 payload");
_Static_assert(sizeof(struct agentfs_req_read) == 20u,
               "AgentFS read wire must fit one seL4 payload");
