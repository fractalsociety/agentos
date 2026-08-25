/*
 * fos-gz0.14.5.3 — AgentFS descriptor persist/resolve keyed by payload_root.
 */

#include "descriptor_store.h"

#define AGENTFS_DESC_OK        0u
#define AGENTFS_DESC_ERR       1u
#define AGENTFS_DESC_NOT_FOUND 2u
#define AGENTFS_DESC_FULL      3u

static struct agentfs_desc_entry g_descs[AGENTFS_DESC_MAX_ENTRIES];
static uint32_t g_desc_count;

static void zero_bytes(void *dst, uint32_t n)
{
    uint8_t *p = (uint8_t *)dst;
    while (n--) *p++ = 0u;
}

static void copy_bytes(void *dst, const void *src, uint32_t n)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    while (n--) *d++ = *s++;
}

static int hash_eq(const eventbus_event_hash_t *a,
                   const eventbus_event_hash_t *b)
{
    return eventbus_event_hash_equal(a, b);
}

void agentfs_desc_store_init(void)
{
    zero_bytes(g_descs, (uint32_t)sizeof(g_descs));
    g_desc_count = 0u;
}

uint32_t agentfs_desc_persist(const eventbus_event_hash_t *payload_root,
                              const uint8_t *bytes, uint32_t length)
{
    uint32_t i;
    struct agentfs_desc_entry *slot = (struct agentfs_desc_entry *)0;

    if (payload_root == (const eventbus_event_hash_t *)0
            || bytes == (const uint8_t *)0 || length == 0u
            || length > AGENTFS_DESC_MAX_BYTES
            || eventbus_event_hash_zero(payload_root))
        return AGENTFS_DESC_ERR;

    for (i = 0u; i < AGENTFS_DESC_MAX_ENTRIES; i++) {
        if (g_descs[i].used && hash_eq(&g_descs[i].payload_root, payload_root)) {
            slot = &g_descs[i];
            break;
        }
        if (!g_descs[i].used && slot == (struct agentfs_desc_entry *)0)
            slot = &g_descs[i];
    }
    if (slot == (struct agentfs_desc_entry *)0)
        return AGENTFS_DESC_FULL;

    if (!slot->used)
        g_desc_count++;
    slot->used = 1;
    slot->payload_root = *payload_root;
    slot->length = length;
    copy_bytes(slot->bytes, bytes, length);
    return AGENTFS_DESC_OK;
}

uint32_t agentfs_desc_resolve(const eventbus_event_hash_t *payload_root,
                              uint8_t *out, uint32_t capacity,
                              uint32_t *out_length)
{
    uint32_t i;
    if (payload_root == (const eventbus_event_hash_t *)0
            || out_length == (uint32_t *)0)
        return AGENTFS_DESC_ERR;
    for (i = 0u; i < AGENTFS_DESC_MAX_ENTRIES; i++) {
        if (!g_descs[i].used
                || !hash_eq(&g_descs[i].payload_root, payload_root))
            continue;
        *out_length = g_descs[i].length;
        if (out != (uint8_t *)0) {
            uint32_t n = g_descs[i].length;
            if (n > capacity) n = capacity;
            copy_bytes(out, g_descs[i].bytes, n);
        }
        return AGENTFS_DESC_OK;
    }
    return AGENTFS_DESC_NOT_FOUND;
}

uint32_t agentfs_desc_count(void)
{
    return g_desc_count;
}
