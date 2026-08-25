/*
 * Immutable shared-space replication host runtime (fos-gz0.14.10.3).
 */

#include "shared_space.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct chunk_slot {
    int present;
    uint32_t bytes;
    struct shared_space_digest hash;
    uint8_t data[SHARED_SPACE_MAX_CHUNK_BYTES];
};

struct object_slot {
    int used;
    shared_object_id_t object_id;
    uint32_t total_chunks;
    struct chunk_slot chunks[SHARED_SPACE_MAX_CHUNKS];
};

struct device_slot {
    int used;
    shared_device_id_t device_id;
    /* Bit i set => device knows global objects[i]. */
    uint8_t knows[SHARED_SPACE_MAX_OBJECTS];
};

struct space_slot {
    int used;
    struct shared_space_record record;
};

static struct {
    struct object_slot objects[SHARED_SPACE_MAX_OBJECTS];
    struct device_slot devices[SHARED_SPACE_MAX_DEVICES];
    struct space_slot spaces[SHARED_SPACE_MAX_SPACES];
} g_ss;

static void bytes_zero(void *dst, size_t n)
{
    uint8_t *p = (uint8_t *)dst;
    while (n--)
        *p++ = 0;
}

static int digest_is_zero(const struct shared_space_digest *d)
{
    uint8_t c = 0u;
    uint32_t i;
    for (i = 0u; i < SHARED_SPACE_DIGEST_BYTES; i++)
        c |= d->bytes[i];
    return c == 0u;
}

static int digest_eq(const struct shared_space_digest *a,
                     const struct shared_space_digest *b)
{
    uint8_t d = 0u;
    uint32_t i;
    for (i = 0u; i < SHARED_SPACE_DIGEST_BYTES; i++)
        d |= (uint8_t)(a->bytes[i] ^ b->bytes[i]);
    return d == 0u;
}

static void digest_copy(struct shared_space_digest *dst,
                        const struct shared_space_digest *src)
{
    uint32_t i;
    for (i = 0u; i < SHARED_SPACE_DIGEST_BYTES; i++)
        dst->bytes[i] = src->bytes[i];
}

static void hash_payload(const uint8_t *payload, uint32_t len,
                         struct shared_space_digest *out)
{
    uint64_t hash = UINT64_C(0xcbf29ce484222325);
    uint32_t i;
    bytes_zero(out, sizeof(*out));
    for (i = 0u; i < len; i++) {
        hash ^= payload[i];
        hash *= UINT64_C(0x100000001b3);
    }
    hash ^= len;
    for (i = 0u; i < 8u; i++)
        out->bytes[i] = (uint8_t)(hash >> (i * 8u));
    for (i = 8u; i < SHARED_SPACE_DIGEST_BYTES; i++)
        out->bytes[i] = (uint8_t)(0x5Au ^ out->bytes[i - 8u]);
}

static struct space_slot *find_space(const shared_space_id_t *id)
{
    uint32_t i;
    if (digest_is_zero(id))
        return NULL;
    for (i = 0u; i < SHARED_SPACE_MAX_SPACES; i++) {
        if (g_ss.spaces[i].used &&
            digest_eq(&g_ss.spaces[i].record.space_id, id))
            return &g_ss.spaces[i];
    }
    return NULL;
}

static struct object_slot *find_object(const shared_object_id_t *id)
{
    uint32_t i;
    if (digest_is_zero(id))
        return NULL;
    for (i = 0u; i < SHARED_SPACE_MAX_OBJECTS; i++) {
        if (g_ss.objects[i].used &&
            digest_eq(&g_ss.objects[i].object_id, id))
            return &g_ss.objects[i];
    }
    return NULL;
}

static int object_index(const shared_object_id_t *id)
{
    uint32_t i;
    for (i = 0u; i < SHARED_SPACE_MAX_OBJECTS; i++) {
        if (g_ss.objects[i].used &&
            digest_eq(&g_ss.objects[i].object_id, id))
            return (int)i;
    }
    return -1;
}

static struct object_slot *alloc_object(void)
{
    uint32_t i;
    for (i = 0u; i < SHARED_SPACE_MAX_OBJECTS; i++) {
        if (!g_ss.objects[i].used) {
            bytes_zero(&g_ss.objects[i], sizeof(g_ss.objects[i]));
            g_ss.objects[i].used = 1;
            return &g_ss.objects[i];
        }
    }
    return NULL;
}

static struct device_slot *find_or_alloc_device(const shared_device_id_t *id)
{
    uint32_t i;
    struct device_slot *free_slot = NULL;
    if (digest_is_zero(id))
        return NULL;
    for (i = 0u; i < SHARED_SPACE_MAX_DEVICES; i++) {
        if (g_ss.devices[i].used &&
            digest_eq(&g_ss.devices[i].device_id, id))
            return &g_ss.devices[i];
        if (!g_ss.devices[i].used && free_slot == NULL)
            free_slot = &g_ss.devices[i];
    }
    if (free_slot == NULL)
        return NULL;
    bytes_zero(free_slot, sizeof(*free_slot));
    free_slot->used = 1;
    digest_copy(&free_slot->device_id, id);
    return free_slot;
}

static int device_knows(const struct device_slot *dev, int obj_idx)
{
    if (dev == NULL || obj_idx < 0 ||
        (uint32_t)obj_idx >= SHARED_SPACE_MAX_OBJECTS)
        return 0;
    return dev->knows[obj_idx] != 0u;
}

static void device_mark(struct device_slot *dev, int obj_idx)
{
    if (dev != NULL && obj_idx >= 0 &&
        (uint32_t)obj_idx < SHARED_SPACE_MAX_OBJECTS)
        dev->knows[obj_idx] = 1u;
}

static int object_complete(const struct object_slot *obj)
{
    uint32_t i;
    if (obj == NULL || obj->total_chunks == 0u)
        return 0;
    for (i = 0u; i < obj->total_chunks; i++) {
        if (!obj->chunks[i].present)
            return 0;
    }
    return 1;
}

static int head_contains(const struct shared_space_record *rec,
                         const shared_object_id_t *root)
{
    uint32_t i;
    for (i = 0u; i < rec->head_count && i < SHARED_SPACE_MAX_HEADS; i++) {
        if (digest_eq(&rec->heads[i], root))
            return 1;
    }
    return 0;
}

static uint32_t add_head(struct shared_space_record *rec,
                         const shared_object_id_t *root)
{
    if (head_contains(rec, root))
        return SHARED_SPACE_OK;
    if (rec->head_count >= SHARED_SPACE_MAX_HEADS)
        return SHARED_SPACE_ERR_FULL;
    digest_copy(&rec->heads[rec->head_count++], root);
    if (rec->head_count == 1u)
        digest_copy(&rec->current_root, root);
    return SHARED_SPACE_OK;
}

static void set_single_head(struct shared_space_record *rec,
                            const shared_object_id_t *root)
{
    uint32_t i;
    for (i = 0u; i < SHARED_SPACE_MAX_HEADS; i++)
        bytes_zero(&rec->heads[i], sizeof(rec->heads[i]));
    rec->head_count = 1u;
    digest_copy(&rec->heads[0], root);
    digest_copy(&rec->current_root, root);
}

void shared_space_reset(void)
{
    bytes_zero(&g_ss, sizeof(g_ss));
}

uint32_t shared_space_create(const struct shared_space_req_create *req,
                             struct shared_space_reply_create *reply)
{
    struct space_slot *slot;
    uint32_t i;

    if (reply == NULL)
        return SHARED_SPACE_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL ||
        req->interface_version != SHARED_SPACE_INTERFACE_VERSION ||
        digest_is_zero(&req->space_id) ||
        digest_is_zero(&req->authority_device) ||
        req->authority_epoch == 0u) {
        reply->status = SHARED_SPACE_ERR_INVALID;
        return reply->status;
    }
    if (find_space(&req->space_id) != NULL) {
        reply->status = SHARED_SPACE_ERR_DUPLICATE;
        return reply->status;
    }
    if (find_or_alloc_device(&req->authority_device) == NULL) {
        reply->status = SHARED_SPACE_ERR_FULL;
        return reply->status;
    }

    slot = NULL;
    for (i = 0u; i < SHARED_SPACE_MAX_SPACES; i++) {
        if (!g_ss.spaces[i].used) {
            slot = &g_ss.spaces[i];
            break;
        }
    }
    if (slot == NULL) {
        reply->status = SHARED_SPACE_ERR_FULL;
        return reply->status;
    }
    bytes_zero(slot, sizeof(*slot));
    slot->used = 1;
    digest_copy(&slot->record.space_id, &req->space_id);
    slot->record.authority_epoch = req->authority_epoch;
    slot->record.head_count = 0u;
    reply->record = slot->record;
    reply->status = SHARED_SPACE_OK;
    return SHARED_SPACE_OK;
}

uint32_t shared_space_put_object(const struct shared_space_req_put_object *req,
                                 const uint8_t *payload,
                                 struct shared_space_reply_put_object *reply)
{
    struct space_slot *space;
    struct object_slot *obj;
    struct shared_space_digest computed;
    uint32_t stored = 0u;
    uint32_t i;

    if (reply == NULL)
        return SHARED_SPACE_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL || payload == NULL ||
        req->interface_version != SHARED_SPACE_INTERFACE_VERSION ||
        digest_is_zero(&req->space_id) || digest_is_zero(&req->object_id) ||
        req->total_chunks == 0u ||
        req->total_chunks > SHARED_SPACE_MAX_CHUNKS ||
        req->chunk_index >= req->total_chunks ||
        req->chunk_bytes == 0u ||
        req->chunk_bytes > SHARED_SPACE_MAX_CHUNK_BYTES ||
        digest_is_zero(&req->chunk_hash)) {
        reply->status = SHARED_SPACE_ERR_INVALID;
        return reply->status;
    }

    space = find_space(&req->space_id);
    if (space == NULL) {
        reply->status = SHARED_SPACE_ERR_NOT_FOUND;
        return reply->status;
    }

    hash_payload(payload, req->chunk_bytes, &computed);
    if (!digest_eq(&computed, &req->chunk_hash)) {
        reply->status = SHARED_SPACE_ERR_HASH_MISMATCH;
        return reply->status;
    }

    obj = find_object(&req->object_id);
    if (obj == NULL) {
        obj = alloc_object();
        if (obj == NULL) {
            reply->status = SHARED_SPACE_ERR_FULL;
            return reply->status;
        }
        digest_copy(&obj->object_id, &req->object_id);
        obj->total_chunks = req->total_chunks;
    } else if (obj->total_chunks != req->total_chunks) {
        reply->status = SHARED_SPACE_ERR_CORRUPT;
        return reply->status;
    }

    if (obj->chunks[req->chunk_index].present) {
        if (!digest_eq(&obj->chunks[req->chunk_index].hash, &req->chunk_hash) ||
            obj->chunks[req->chunk_index].bytes != req->chunk_bytes) {
            reply->status = SHARED_SPACE_ERR_CORRUPT;
            return reply->status;
        }
        /* Idempotent resume — already stored. */
    } else {
        obj->chunks[req->chunk_index].present = 1;
        obj->chunks[req->chunk_index].bytes = req->chunk_bytes;
        digest_copy(&obj->chunks[req->chunk_index].hash, &req->chunk_hash);
        memcpy(obj->chunks[req->chunk_index].data, payload, req->chunk_bytes);
    }

    for (i = 0u; i < obj->total_chunks; i++) {
        if (obj->chunks[i].present)
            stored++;
    }
    reply->accepted_chunk_index = req->chunk_index;
    reply->chunks_stored = stored;
    reply->status = SHARED_SPACE_OK;
    return SHARED_SPACE_OK;
}

uint32_t shared_space_get_object(const struct shared_space_req_get_object *req,
                                 uint8_t *out_payload, uint32_t out_cap,
                                 struct shared_space_reply_get_object *reply)
{
    struct object_slot *obj;

    if (reply == NULL)
        return SHARED_SPACE_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL || out_payload == NULL ||
        req->interface_version != SHARED_SPACE_INTERFACE_VERSION ||
        digest_is_zero(&req->object_id)) {
        reply->status = SHARED_SPACE_ERR_INVALID;
        return reply->status;
    }
    if (find_space(&req->space_id) == NULL) {
        reply->status = SHARED_SPACE_ERR_NOT_FOUND;
        return reply->status;
    }
    obj = find_object(&req->object_id);
    if (obj == NULL) {
        reply->status = SHARED_SPACE_ERR_MISSING_BLOCK;
        return reply->status;
    }
    if (req->chunk_index >= obj->total_chunks ||
        !obj->chunks[req->chunk_index].present) {
        reply->status = SHARED_SPACE_ERR_MISSING_BLOCK;
        return reply->status;
    }
    if (out_cap < obj->chunks[req->chunk_index].bytes) {
        reply->status = SHARED_SPACE_ERR_INVALID;
        return reply->status;
    }
    memcpy(out_payload, obj->chunks[req->chunk_index].data,
           obj->chunks[req->chunk_index].bytes);
    reply->chunk_index = req->chunk_index;
    digest_copy(&reply->chunk_hash, &obj->chunks[req->chunk_index].hash);
    reply->total_chunks = obj->total_chunks;
    reply->chunk_bytes = obj->chunks[req->chunk_index].bytes;
    reply->status = SHARED_SPACE_OK;
    return SHARED_SPACE_OK;
}

uint32_t shared_space_have_want(const struct shared_space_req_have_want *req,
                                const shared_object_id_t *have,
                                const shared_object_id_t *want,
                                struct shared_space_reply_have_want *reply)
{
    struct device_slot *dev;
    uint32_t i;
    uint32_t missing = 0u;
    uint32_t duplicates = 0u;

    if (reply == NULL)
        return SHARED_SPACE_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL ||
        req->interface_version != SHARED_SPACE_INTERFACE_VERSION ||
        req->have_count > SHARED_SPACE_MAX_HAVE_WANT ||
        req->want_count > SHARED_SPACE_MAX_HAVE_WANT ||
        (req->have_count > 0u && have == NULL) ||
        (req->want_count > 0u && want == NULL) ||
        find_space(&req->space_id) == NULL) {
        reply->status = SHARED_SPACE_ERR_INVALID;
        return reply->status;
    }

    dev = find_or_alloc_device(&req->from_device);
    if (dev == NULL) {
        reply->status = SHARED_SPACE_ERR_FULL;
        return reply->status;
    }

    for (i = 0u; i < req->have_count; i++) {
        int idx = object_index(&have[i]);
        if (idx >= 0 && object_complete(&g_ss.objects[idx])) {
            if (device_knows(dev, idx))
                duplicates++;
            else
                device_mark(dev, idx);
        }
    }
    for (i = 0u; i < req->want_count; i++) {
        int idx = object_index(&want[i]);
        if (idx < 0 || !object_complete(&g_ss.objects[idx]) ||
            !device_knows(dev, idx))
            missing++;
    }

    reply->missing_count = missing;
    reply->duplicate_count = duplicates;
    reply->status = SHARED_SPACE_OK;
    return SHARED_SPACE_OK;
}

uint32_t shared_space_device_ingest(const shared_device_id_t *device,
                                    const shared_object_id_t *object_id)
{
    struct device_slot *dev;
    int idx;

    if (device == NULL || object_id == NULL)
        return SHARED_SPACE_ERR_INVALID;
    idx = object_index(object_id);
    if (idx < 0 || !object_complete(&g_ss.objects[idx]))
        return SHARED_SPACE_ERR_MISSING_BLOCK;
    dev = find_or_alloc_device(device);
    if (dev == NULL)
        return SHARED_SPACE_ERR_FULL;
    device_mark(dev, idx);
    return SHARED_SPACE_OK;
}

uint32_t shared_space_cas_root(const struct shared_space_req_cas_root *req,
                               struct shared_space_reply_cas_root *reply)
{
    struct space_slot *space;
    int obj_idx;

    if (reply == NULL)
        return SHARED_SPACE_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL ||
        req->interface_version != SHARED_SPACE_INTERFACE_VERSION ||
        digest_is_zero(&req->proposed_root)) {
        reply->status = SHARED_SPACE_ERR_INVALID;
        return reply->status;
    }
    if (digest_is_zero(&req->verify_evidence)) {
        reply->status = SHARED_SPACE_ERR_NO_EVIDENCE;
        return reply->status;
    }

    space = find_space(&req->space_id);
    if (space == NULL) {
        reply->status = SHARED_SPACE_ERR_NOT_FOUND;
        return reply->status;
    }
    if (req->authority_epoch != space->record.authority_epoch) {
        reply->status = SHARED_SPACE_ERR_STALE_EPOCH;
        return reply->status;
    }

    obj_idx = object_index(&req->proposed_root);
    if (obj_idx < 0 || !object_complete(&g_ss.objects[obj_idx])) {
        reply->status = SHARED_SPACE_ERR_MISSING_BLOCK;
        return reply->status;
    }

    /* First root: expected must be zero. */
    if (space->record.head_count == 0u) {
        if (!digest_is_zero(&req->expected_root)) {
            reply->status = SHARED_SPACE_ERR_STALE_ROOT;
            return reply->status;
        }
        set_single_head(&space->record, &req->proposed_root);
        digest_copy(&space->record.shared_event_head, &req->shared_event_head);
        reply->record = space->record;
        reply->head_count = space->record.head_count;
        reply->status = SHARED_SPACE_OK;
        return SHARED_SPACE_OK;
    }

    if (space->record.head_count != 1u ||
        !digest_eq(&space->record.current_root, &req->expected_root)) {
        /* Conflict: do not LWW; retain both expected tip and proposal as heads. */
        (void)add_head(&space->record, &req->proposed_root);
        reply->record = space->record;
        reply->head_count = space->record.head_count;
        reply->status = SHARED_SPACE_ERR_CAS_CONFLICT;
        return reply->status;
    }

    set_single_head(&space->record, &req->proposed_root);
    digest_copy(&space->record.shared_event_head, &req->shared_event_head);
    reply->record = space->record;
    reply->head_count = 1u;
    reply->status = SHARED_SPACE_OK;
    return SHARED_SPACE_OK;
}

uint32_t shared_space_branch(const struct shared_space_req_branch *req,
                             struct shared_space_reply_branch *reply)
{
    struct space_slot *space;
    int obj_idx;
    uint32_t status;

    if (reply == NULL)
        return SHARED_SPACE_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL ||
        req->interface_version != SHARED_SPACE_INTERFACE_VERSION ||
        digest_is_zero(&req->branch_root)) {
        reply->status = SHARED_SPACE_ERR_INVALID;
        return reply->status;
    }

    space = find_space(&req->space_id);
    if (space == NULL) {
        reply->status = SHARED_SPACE_ERR_NOT_FOUND;
        return reply->status;
    }
    /* Offline branch may use a lagging epoch; online must match. */
    if (req->authority_epoch > space->record.authority_epoch) {
        reply->status = SHARED_SPACE_ERR_STALE_EPOCH;
        return reply->status;
    }

    obj_idx = object_index(&req->branch_root);
    if (obj_idx < 0 || !object_complete(&g_ss.objects[obj_idx])) {
        reply->status = SHARED_SPACE_ERR_MISSING_BLOCK;
        return reply->status;
    }
    if (!digest_is_zero(&req->base_root) &&
        space->record.head_count > 0u &&
        !head_contains(&space->record, &req->base_root) &&
        !digest_eq(&space->record.current_root, &req->base_root)) {
        reply->status = SHARED_SPACE_ERR_STALE_ROOT;
        return reply->status;
    }

    if (find_or_alloc_device(&req->device_id) == NULL) {
        reply->status = SHARED_SPACE_ERR_FULL;
        return reply->status;
    }

    status = add_head(&space->record, &req->branch_root);
    if (status != SHARED_SPACE_OK) {
        reply->status = status;
        return status;
    }
    /* Offline reconnect with divergent tip: ensure base remains as a head. */
    if (!digest_is_zero(&req->base_root) &&
        !digest_eq(&req->base_root, &req->branch_root))
        (void)add_head(&space->record, &req->base_root);

    reply->record = space->record;
    reply->status = SHARED_SPACE_OK;
    return SHARED_SPACE_OK;
}

uint32_t shared_space_merge(const struct shared_space_req_merge *req,
                            struct shared_space_reply_merge *reply)
{
    struct space_slot *space;
    int obj_idx;

    if (reply == NULL)
        return SHARED_SPACE_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL ||
        req->interface_version != SHARED_SPACE_INTERFACE_VERSION) {
        reply->status = SHARED_SPACE_ERR_INVALID;
        return reply->status;
    }
    if (req->policy == SHARED_SPACE_MERGE_CRDT) {
        reply->status = SHARED_SPACE_ERR_CRDT_FORBIDDEN;
        return reply->status;
    }

    space = find_space(&req->space_id);
    if (space == NULL) {
        reply->status = SHARED_SPACE_ERR_NOT_FOUND;
        return reply->status;
    }
    if (req->authority_epoch != space->record.authority_epoch) {
        reply->status = SHARED_SPACE_ERR_STALE_EPOCH;
        return reply->status;
    }
    if (!head_contains(&space->record, &req->head_a) ||
        !head_contains(&space->record, &req->head_b)) {
        reply->status = SHARED_SPACE_ERR_NOT_FOUND;
        return reply->status;
    }

    if (req->policy == SHARED_SPACE_MERGE_RETAIN_BOTH) {
        reply->record = space->record;
        reply->head_count = space->record.head_count;
        reply->status = SHARED_SPACE_OK;
        return SHARED_SPACE_OK;
    }

    if (req->policy != SHARED_SPACE_MERGE_VERIFIED) {
        reply->status = SHARED_SPACE_ERR_INVALID;
        return reply->status;
    }
    if (digest_is_zero(&req->verify_evidence)) {
        reply->status = SHARED_SPACE_ERR_NO_EVIDENCE;
        return reply->status;
    }
    if (digest_is_zero(&req->merged_root)) {
        reply->status = SHARED_SPACE_ERR_INVALID;
        return reply->status;
    }
    obj_idx = object_index(&req->merged_root);
    if (obj_idx < 0 || !object_complete(&g_ss.objects[obj_idx])) {
        reply->status = SHARED_SPACE_ERR_MISSING_BLOCK;
        return reply->status;
    }

    set_single_head(&space->record, &req->merged_root);
    reply->record = space->record;
    reply->head_count = 1u;
    reply->status = SHARED_SPACE_OK;
    return SHARED_SPACE_OK;
}

uint32_t shared_space_status(const struct shared_space_req_status *req,
                             struct shared_space_reply_status *reply)
{
    struct space_slot *space;

    if (reply == NULL)
        return SHARED_SPACE_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL ||
        req->interface_version != SHARED_SPACE_INTERFACE_VERSION) {
        reply->status = SHARED_SPACE_ERR_INVALID;
        return reply->status;
    }
    space = find_space(&req->space_id);
    if (space == NULL) {
        reply->status = SHARED_SPACE_ERR_NOT_FOUND;
        return reply->status;
    }
    reply->record = space->record;
    reply->status = SHARED_SPACE_OK;
    return SHARED_SPACE_OK;
}

uint32_t shared_space_object_count(void)
{
    uint32_t i, n = 0u;
    for (i = 0u; i < SHARED_SPACE_MAX_OBJECTS; i++) {
        if (g_ss.objects[i].used)
            n++;
    }
    return n;
}

uint32_t shared_space_space_count(void)
{
    uint32_t i, n = 0u;
    for (i = 0u; i < SHARED_SPACE_MAX_SPACES; i++) {
        if (g_ss.spaces[i].used)
            n++;
    }
    return n;
}
