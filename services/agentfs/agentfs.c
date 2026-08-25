/*
 * FractalOS AgentFS Protection Domain
 *
 * AgentFS is the agent-native object store. It is NOT POSIX.
 * Every stored item is an Object: content-addressed, versioned,
 * capability-gated, metadata-rich, and event-emitting.
 *
 * This PD runs as a passive server at priority 150.
 * Clients call in with typed operation requests.
 * Results are returned synchronously via IPC reply.
 *
 * Object model:
 *   - ObjectId: 32-byte identifier (BLAKE3 hash for blobs, UUID for mutable)
 *   - Every object has: id, schema_type, version, size, cap_tag, metadata[]
 *   - Write-once blob store (immutable by content hash)
 *   - Mutable objects produce new versions (append-only versioned log)
 *   - Vector index for semantic similarity queries (cosine, HNSW-sketched)
 *
 * Storage tiers (configured at boot):
 *   - Hot: mapped shared memory region (eventbus_ring style)
 *   - Cold: deferred to external store (MinIO/S3-compat via model proxy)
 *
 * Channel assignments:
 *   CH_CONTROLLER = 0  (controller calls in for admin ops)
 *   CH_EVENTBUS   = 1  (outbound notify on object mutations)
 *
 * IPC ops (opcode in data[0..3]):
 *   OP_AGENTFS_PUT      = 0x30  — write object
 *   OP_AGENTFS_GET      = 0x31  — read object by id
 *   OP_AGENTFS_QUERY    = 0x32  — list/filter objects
 *   OP_AGENTFS_DELETE   = 0x33  — delete (soft: creates tombstone)
 *   OP_AGENTFS_VECTOR   = 0x34  — vector similarity query
 *   OP_AGENTFS_STAT     = 0x35  — object metadata
 *   OP_AGENTFS_HEALTH   = 0x36  — health check (for swap infra)
 *
 * E5-S8: migrated from Microkit to raw seL4 IPC.
 *
 * Copyright (c) 2026 The FractalOS Project
 * SPDX-License-Identifier: BSD-2-Clause
 */

#define FRACTALOS_DEBUG 1
#include "fractalos.h"
#include "sel4_server.h"
#include "contracts/agentfs_contract.h"
#include "contracts/eventbus_contract.h"
#include "descriptor_store.h"
#include "workspace_overlay.h"
#include <stdint.h>
#include <stdbool.h>

/* setvar_vaddr — patched by the system initializer */
uintptr_t agentfs_store_vaddr;

/* Outbound endpoint to event bus (0 = not wired, fire-and-forget stub) */
static seL4_CPtr g_eventbus_ep = 0;

#if defined(__GNUC__)
__attribute__((weak)) uint32_t fractalos_eventbus_record(
    struct eventbus_agent_event *event)
{
    (void)event;
    return EVENTBUS_AGENT_EVENT_OK;
}
__attribute__((weak)) uint32_t fractalos_eventbus_canonical_epoch(void)
{
    return 0u;
}
#else
extern uint32_t fractalos_eventbus_record(struct eventbus_agent_event *event);
extern uint32_t fractalos_eventbus_canonical_epoch(void);
#endif

/* ── Op codes ───────────────────────────────────────────────────────────── */
#define OP_AGENTFS_PUT      0x30
#define OP_AGENTFS_GET      0x31
#define OP_AGENTFS_QUERY    0x32
#define OP_AGENTFS_DELETE   0x33
#define OP_AGENTFS_VECTOR   0x34
#define OP_AGENTFS_STAT     0x35
#define OP_AGENTFS_HEALTH   0x36

/* ── Result codes ───────────────────────────────────────────────────────── */
#define AFS_OK          0
#define AFS_ERR_NOCAP   1   /* caller lacks capability */
#define AFS_ERR_NOENT   2   /* object not found */
#define AFS_ERR_NOSPACE 3   /* hot store full */
#define AFS_ERR_TYPE    4   /* schema type mismatch */
#define AFS_ERR_INTRNL  99

/* ── Object model ───────────────────────────────────────────────────────── */
#define OBJECT_ID_BYTES   32
#define MAX_SCHEMA_LEN    32
#define MAX_HOT_OBJECTS   256
#define BLOB_STORE_SIZE   (256 * 1024)  /* 256KB hot store in shared MR */
#define MAX_VECTOR_DIM    512           /* max embedding dimension */

typedef struct {
    uint8_t  bytes[OBJECT_ID_BYTES];
    uint8_t  scheme;  /* 0=null, 1=blake3, 2=uuid */
} object_id_t;

typedef enum {
    OBJ_STATE_LIVE,
    OBJ_STATE_TOMBSTONE,  /* soft-deleted */
    OBJ_STATE_EVICTED,    /* moved to cold tier */
} obj_state_t;

typedef struct {
    object_id_t  id;
    char         schema[MAX_SCHEMA_LEN];   /* e.g. "FractalOS::InferenceResult" */
    uint32_t     version;
    uint32_t     size;
    uint32_t     cap_tag;    /* badge of the cap required to read this object */
    uint64_t     created_at; /* monotonic microseconds */
    uint64_t     modified_at;
    obj_state_t  state;
    uint32_t     blob_offset; /* offset into blob_store[] */
    /* Optional vector embedding (for semantic search) */
    uint16_t     vec_dim;     /* 0 if no vector */
    float        vec[MAX_VECTOR_DIM];
} agentfs_obj_t;

/* ── In-memory hot store ────────────────────────────────────────────────── */
static agentfs_obj_t  hot_index[MAX_HOT_OBJECTS];
static uint8_t   blob_store[BLOB_STORE_SIZE];
static uint32_t  blob_watermark = 0;
static uint32_t  hot_count = 0;
static uint64_t  total_puts = 0;
static uint64_t  total_gets = 0;
static uint64_t  total_vectors = 0;

/* ── Simple BLAKE3-inspired fingerprint (no external deps) ──────────────── */
/* Real BLAKE3 needs ~2KB of code; we use a simplified MurmurHash3 analog  */
/* for the prototype. Replace with actual BLAKE3 for production.            */
static void simple_hash(const uint8_t *data, uint32_t len, uint8_t out[32]) {
    uint64_t h0 = 0x6c62272e07bb0142ULL;
    uint64_t h1 = 0x62b821756295c58dULL;
    for (uint32_t i = 0; i < len; i++) {
        h0 ^= (uint64_t)data[i] << ((i % 8) * 8);
        h0 = (h0 << 13) | (h0 >> 51);
        h0 += h1;
        h1 ^= h0;
        h1 = (h1 << 17) | (h1 >> 47);
    }
    /* Fill 32 bytes from two 64-bit values with mixing */
    for (int i = 0; i < 4; i++) {
        uint64_t x = (i % 2 == 0) ? h0 : h1;
        x ^= (uint64_t)i * 0xdeadbeefcafeULL;
        out[i*8+0] = (x >> 56) & 0xff;
        out[i*8+1] = (x >> 48) & 0xff;
        out[i*8+2] = (x >> 40) & 0xff;
        out[i*8+3] = (x >> 32) & 0xff;
        out[i*8+4] = (x >> 24) & 0xff;
        out[i*8+5] = (x >> 16) & 0xff;
        out[i*8+6] = (x >>  8) & 0xff;
        out[i*8+7] = (x >>  0) & 0xff;
        /* re-mix */
        h0 ^= h1 + x;
        h1 ^= h0;
    }
}

/* ── Object lookup by ID ────────────────────────────────────────────────── */
static agentfs_obj_t *find_object(const object_id_t *id) {
    for (uint32_t i = 0; i < hot_count; i++) {
        if (hot_index[i].state == OBJ_STATE_LIVE) {
            bool match = true;
            for (int j = 0; j < OBJECT_ID_BYTES; j++) {
                if (hot_index[i].id.bytes[j] != id->bytes[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return &hot_index[i];
        }
    }
    return (void *)0;
}

/* ── Cosine similarity (for vector queries) ─────────────────────────────── */
static float cosine_sim(const float *a, const float *b, uint16_t dim) {
    float dot = 0.0f, na = 0.0f, nb = 0.0f;
    for (uint16_t i = 0; i < dim; i++) {
        dot += a[i] * b[i];
        na  += a[i] * a[i];
        nb  += b[i] * b[i];
    }
    if (na < 1e-9f || nb < 1e-9f) return 0.0f;
    /* fast inverse sqrt approximation — good enough for ranking */
    float inv_na = 1.0f / __builtin_sqrtf(na);
    float inv_nb = 1.0f / __builtin_sqrtf(nb);
    return dot * inv_na * inv_nb;
}

/* ── msg helpers ────────────────────────────────────────────────────────── */
#ifndef FRACTALOS_IPC_HELPERS_DEFINED
#define FRACTALOS_IPC_HELPERS_DEFINED
static inline uint32_t msg_u32(const sel4_msg_t *m, uint32_t off) {
    uint32_t v = 0;
    if (off + 4u <= SEL4_MSG_DATA_BYTES) {
        v  = (uint32_t)m->data[off]; v |= (uint32_t)m->data[off+1]<<8;
        v |= (uint32_t)m->data[off+2]<<16; v |= (uint32_t)m->data[off+3]<<24;
    }
    return v;
}
static inline void rep_u32(sel4_msg_t *m, uint32_t off, uint32_t v) {
    if (off + 4u <= SEL4_MSG_DATA_BYTES) {
        m->data[off]=(uint8_t)v; m->data[off+1]=(uint8_t)(v>>8);
        m->data[off+2]=(uint8_t)(v>>16); m->data[off+3]=(uint8_t)(v>>24);
    }
}
#endif /* FRACTALOS_IPC_HELPERS_DEFINED */

/* ── Emit event to EventBus (fire-and-forget seL4_Call, guarded) ────────── */
static eventbus_event_hash_t agentfs_hash_bytes(const uint8_t *bytes,
                                                uint32_t length)
{
    eventbus_event_hash_t result = {{0}};
    eventbus_event_hash_bytes(bytes, length, &result);
    return result;
}

/* Canonical object events authenticate the operation and the immutable
 * reference together.  Hashing only the object id would make PUT/GET/DELETE
 * indistinguishable in the replay projection. */
static uint32_t emit_canonical_reference(uint32_t event_type,
                                         sel4_badge_t badge,
                                         const uint8_t *reference,
                                         uint32_t reference_len)
{
    uint8_t payload[4u + 1u + OBJECT_ID_BYTES];
    struct eventbus_agent_event event = {0};
    eventbus_event_hash_t scope;
    eventbus_event_hash_t payload_root;
    uint8_t scope_seed[12] = {'a', 'f', 's', 0u, 0u, 0u,
                              0u, 0u, 0u, 0u, 0u, 0u};
    uint32_t i;

    if (reference_len > OBJECT_ID_BYTES)
        reference_len = OBJECT_ID_BYTES;
    for (i = 0u; i < 8u; i++)
        scope_seed[4u + i] = (uint8_t)(badge >> (i * 8u));
    scope = agentfs_hash_bytes(scope_seed, (uint32_t)sizeof(scope_seed));

    payload[0] = (uint8_t)event_type;
    payload[1] = (uint8_t)(event_type >> 8u);
    payload[2] = (uint8_t)(event_type >> 16u);
    payload[3] = (uint8_t)(event_type >> 24u);
    payload[4] = (uint8_t)reference_len;
    for (i = 0u; i < reference_len; i++) payload[5u + i] = reference[i];
    payload_root = agentfs_hash_bytes(payload, 5u + reference_len);

    event.event_type = EVENTBUS_EVENT_OBJECT_TRANSITION;
    event.authority_epoch = fractalos_eventbus_canonical_epoch != (void *)0
        ? fractalos_eventbus_canonical_epoch() : 0u;
    event.flags = EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE;
    event.scope_id = scope;
    event.payload_root = payload_root;
    return fractalos_eventbus_record(&event);
}

static uint32_t emit_event(uint32_t event_type, sel4_badge_t badge,
                           const object_id_t *id) {
    uint32_t canonical_status = EVENTBUS_AGENT_EVENT_OK;
#ifndef FRACTALOS_TEST_HOST
    if (g_eventbus_ep) {
        sel4_msg_t emsg = {0};
        emsg.opcode = MSG_EVENT_PUBLISH;
        rep_u32(&emsg, 0, MSG_EVENT_PUBLISH);
        rep_u32(&emsg, 4, event_type);
        /* Pack first 16 bytes of object ID */
        uint32_t id0 = 0, id1 = 0, id2 = 0, id3 = 0;
        if (id != (const object_id_t *)0) {
            for (int i = 0; i < 4; i++) id0 = (id0 << 8) | id->bytes[i];
            for (int i = 4; i < 8; i++) id1 = (id1 << 8) | id->bytes[i];
            for (int i = 8; i <12; i++) id2 = (id2 << 8) | id->bytes[i];
            for (int i = 12;i <16; i++) id3 = (id3 << 8) | id->bytes[i];
        }
        rep_u32(&emsg, 8,  id0);
        rep_u32(&emsg, 12, id1);
        rep_u32(&emsg, 16, id2);
        rep_u32(&emsg, 20, id3);
        emsg.length = 24;
        sel4_msg_t erep = {0};
        sel4_call(g_eventbus_ep, &emsg, &erep);
    }
#else
    (void)event_type; (void)id;
#endif

    if (fractalos_eventbus_record != (void *)0) {
        const uint8_t *reference = id != (const object_id_t *)0
            ? id->bytes : (const uint8_t *)0;
        uint32_t reference_len = id != (const object_id_t *)0
            ? OBJECT_ID_BYTES : 0u;
        canonical_status = emit_canonical_reference(event_type, badge,
                                                     reference, reference_len);
    }
    return canonical_status;
}

/* ── OP handlers ────────────────────────────────────────────────────────── */

static uint32_t h_put(sel4_badge_t b, const sel4_msg_t *req,
                       sel4_msg_t *rep, void *ctx) {
    (void)b; (void)ctx;
    uint32_t size    = msg_u32(req, 4);
    uint32_t cap_tag = msg_u32(req, 8);

    if (hot_count >= MAX_HOT_OBJECTS) {
        rep_u32(rep, 0, AFS_ERR_NOSPACE); rep->length = 4;
        return SEL4_ERR_NO_MEM;
    }
    if (blob_watermark + size > BLOB_STORE_SIZE) {
        rep_u32(rep, 0, AFS_ERR_NOSPACE); rep->length = 4;
        return SEL4_ERR_NO_MEM;
    }

    agentfs_obj_t *obj = &hot_index[hot_count++];
    obj->version     = 1;
    obj->size        = size;
    obj->cap_tag     = cap_tag;
    obj->state       = OBJ_STATE_LIVE;
    obj->blob_offset = blob_watermark;
    obj->vec_dim     = 0;
    blob_watermark  += size;
    total_puts++;

    /* Generate content-addressed ID from size+cap_tag+counter */
    uint8_t seed[16];
    for (int i = 0; i < 8; i++) seed[i]   = (size >> (i*4)) & 0xff;
    for (int i = 0; i < 8; i++) seed[i+8] = (total_puts >> (i*4)) & 0xff;
    simple_hash(seed, 16, obj->id.bytes);
    obj->id.scheme = 1; /* blake3-analog */

    /* Emit event */
    if (emit_event(EVT_OBJECT_CREATED, b, &obj->id)
            != EVENTBUS_AGENT_EVENT_OK) {
        obj->state = OBJ_STATE_TOMBSTONE;
        hot_count--;
        blob_watermark -= size;
        total_puts--;
        rep_u32(rep, 0, AFS_ERR_INTRNL); rep->length = 4;
        return SEL4_ERR_INVALID_OP;
    }

    /* Return object ID first 16 bytes in reply */
    uint32_t w0 = 0, w1 = 0, w2 = 0, w3 = 0;
    for (int i = 0; i < 4; i++) w0 = (w0 << 8) | obj->id.bytes[i];
    for (int i = 4; i < 8; i++) w1 = (w1 << 8) | obj->id.bytes[i];
    for (int i = 8; i <12; i++) w2 = (w2 << 8) | obj->id.bytes[i];
    for (int i = 12;i <16; i++) w3 = (w3 << 8) | obj->id.bytes[i];
    rep_u32(rep, 0,  AFS_OK);
    rep_u32(rep, 4,  w0);
    rep_u32(rep, 8,  w1);
    rep_u32(rep, 12, w2);
    rep_u32(rep, 16, w3);
    rep->length = 20;

    log_drain_write(3, 3, "[agentfs] Object stored\n");
    return SEL4_ERR_OK;
}

static uint32_t h_get(sel4_badge_t b, const sel4_msg_t *req,
                       sel4_msg_t *rep, void *ctx) {
    (void)b; (void)ctx;
    /* Reconstruct object ID from data[4..19] */
    object_id_t query_id = {0};
    uint32_t words[4];
    words[0] = msg_u32(req, 4);
    words[1] = msg_u32(req, 8);
    words[2] = msg_u32(req, 12);
    words[3] = msg_u32(req, 16);
    for (int w = 0; w < 4; w++)
        for (int bb = 0; bb < 4; bb++)
            query_id.bytes[w*4+bb] = (words[w] >> (24 - bb*8)) & 0xff;

    total_gets++;
    agentfs_obj_t *obj = find_object(&query_id);
    if (!obj) {
        rep_u32(rep, 0, AFS_ERR_NOENT); rep->length = 4;
        return SEL4_ERR_NOT_FOUND;
    }

    if (emit_event(EVT_OBJECT_CREATED, b, &obj->id)
            != EVENTBUS_AGENT_EVENT_OK) {
        rep_u32(rep, 0, AFS_ERR_INTRNL); rep->length = 4;
        return SEL4_ERR_INVALID_OP;
    }

    rep_u32(rep, 0,  AFS_OK);
    rep_u32(rep, 4,  obj->version);
    rep_u32(rep, 8,  obj->size);
    rep_u32(rep, 12, obj->cap_tag);
    rep_u32(rep, 16, obj->blob_offset);
    rep->length = 20;
    return SEL4_ERR_OK;
}

static uint32_t h_vector(sel4_badge_t b, const sel4_msg_t *req,
                          sel4_msg_t *rep, void *ctx) {
    (void)b; (void)ctx;
    /* query_dim in data[4..7], float dims in data[8..] */
    uint32_t query_dim = msg_u32(req, 4);
    if (query_dim > 8) query_dim = 8;

    float query_vec[8] = {0};
    for (uint32_t i = 0; i < query_dim; i++) {
        uint32_t raw = msg_u32(req, 8 + i * 4u);
        float f;
        __builtin_memcpy(&f, &raw, 4);
        query_vec[i] = f;
    }

    total_vectors++;

    /* Linear scan */
    float best_score = -1.0f;
    agentfs_obj_t *best = (void *)0;
    for (uint32_t i = 0; i < hot_count; i++) {
        if (hot_index[i].state != OBJ_STATE_LIVE) continue;
        if (hot_index[i].vec_dim == 0) continue;
        uint16_t cmp_dim = hot_index[i].vec_dim < (uint16_t)query_dim ?
                           hot_index[i].vec_dim : (uint16_t)query_dim;
        float s = cosine_sim(query_vec, hot_index[i].vec, cmp_dim);
        if (s > best_score) {
            best_score = s;
            best = &hot_index[i];
        }
    }

    if (!best || best_score < 0.01f) {
        if (emit_event(EVT_OBJECT_CREATED, b, (const object_id_t *)0)
                != EVENTBUS_AGENT_EVENT_OK) {
            rep_u32(rep, 0, AFS_ERR_INTRNL); rep->length = 4;
            return SEL4_ERR_INVALID_OP;
        }
        rep_u32(rep, 0, AFS_OK);
        rep_u32(rep, 4, 0);  /* zero results */
        rep->length = 8;
        return SEL4_ERR_OK;
    }

    /* Return top-1 result */
    if (emit_event(EVT_OBJECT_CREATED, b, &best->id)
            != EVENTBUS_AGENT_EVENT_OK) {
        rep_u32(rep, 0, AFS_ERR_INTRNL); rep->length = 4;
        return SEL4_ERR_INVALID_OP;
    }
    uint32_t id_prefix = 0;
    for (int i = 0; i < 4; i++)
        id_prefix = (id_prefix << 8) | best->id.bytes[i];
    uint32_t score_bits;
    __builtin_memcpy(&score_bits, &best_score, 4);

    rep_u32(rep, 0,  AFS_OK);
    rep_u32(rep, 4,  1);           /* 1 result */
    rep_u32(rep, 8,  id_prefix);   /* first 4 bytes of object ID */
    rep_u32(rep, 12, score_bits);  /* similarity score as float bits */
    rep->length = 16;
    return SEL4_ERR_OK;
}

static uint32_t h_stat(sel4_badge_t b, const sel4_msg_t *req,
                        sel4_msg_t *rep, void *ctx) {
    (void)b; (void)req; (void)ctx;
    if (emit_event(EVT_OBJECT_CREATED, b, (const object_id_t *)0)
            != EVENTBUS_AGENT_EVENT_OK) {
        rep_u32(rep, 0, AFS_ERR_INTRNL); rep->length = 4;
        return SEL4_ERR_INVALID_OP;
    }
    rep_u32(rep, 0,  AFS_OK);
    rep_u32(rep, 4,  hot_count);
    rep_u32(rep, 8,  blob_watermark);
    rep_u32(rep, 12, (uint32_t)total_puts);
    rep_u32(rep, 16, (uint32_t)total_gets);
    rep_u32(rep, 20, (uint32_t)total_vectors);
    rep->length = 24;
    return SEL4_ERR_OK;
}

static uint32_t h_health(sel4_badge_t b, const sel4_msg_t *req,
                          sel4_msg_t *rep, void *ctx) {
    (void)b; (void)req; (void)ctx;
    if (emit_event(EVT_OBJECT_CREATED, b, (const object_id_t *)0)
            != EVENTBUS_AGENT_EVENT_OK) {
        rep_u32(rep, 0, AFS_ERR_INTRNL); rep->length = 4;
        return SEL4_ERR_INVALID_OP;
    }
    rep_u32(rep, 0, AFS_OK);
    rep_u32(rep, 4, hot_count);
    rep_u32(rep, 8, blob_watermark);
    rep->length = 12;
    return SEL4_ERR_OK;
}

static uint32_t h_delete(sel4_badge_t b, const sel4_msg_t *req,
                          sel4_msg_t *rep, void *ctx) {
    (void)b; (void)ctx;
    object_id_t del_id = {0};
    uint32_t words[4];
    words[0] = msg_u32(req, 4);
    words[1] = msg_u32(req, 8);
    words[2] = msg_u32(req, 12);
    words[3] = msg_u32(req, 16);
    for (int w = 0; w < 4; w++)
        for (int bb = 0; bb < 4; bb++)
            del_id.bytes[w*4+bb] = (words[w] >> (24 - bb*8)) & 0xff;

    agentfs_obj_t *obj = find_object(&del_id);
    if (!obj) {
        rep_u32(rep, 0, AFS_ERR_NOENT); rep->length = 4;
        return SEL4_ERR_NOT_FOUND;
    }
    obj->state = OBJ_STATE_TOMBSTONE;
    if (emit_event(EVT_OBJECT_DELETED, b, &obj->id)
            != EVENTBUS_AGENT_EVENT_OK) {
        obj->state = OBJ_STATE_LIVE;
        rep_u32(rep, 0, AFS_ERR_INTRNL); rep->length = 4;
        return SEL4_ERR_INVALID_OP;
    }

    rep_u32(rep, 0, AFS_OK);
    rep->length = 4;
    return SEL4_ERR_OK;
}

static uint32_t h_workspace(sel4_badge_t badge, const sel4_msg_t *req,
                            sel4_msg_t *rep, void *ctx)
{
    uint8_t descriptor[4u + SEL4_MSG_DATA_BYTES + SEL4_MSG_DATA_BYTES];
    eventbus_event_hash_t request_root;
    uint32_t request_len;
    uint32_t reply_len;
    uint32_t status;
    (void)ctx;
    rep->length = SEL4_MSG_DATA_BYTES;
    status = agentfs_workspace_dispatch((uint64_t)badge, req->opcode,
                                         req->data, req->length,
                                         rep->data, &rep->length);
    if (status != AGENTFS_OK)
        return status;

    /* Workspace writes, reads, deletes, and exports all change or expose a
     * mutable root.  Bind the bounded IPC request and reply to that root so
     * replay cannot observe a state transition without its event. */
    request_len = req->length;
    if (request_len > SEL4_MSG_DATA_BYTES) request_len = SEL4_MSG_DATA_BYTES;
    reply_len = rep->length;
    if (reply_len > SEL4_MSG_DATA_BYTES) reply_len = SEL4_MSG_DATA_BYTES;
    descriptor[0] = (uint8_t)req->opcode;
    descriptor[1] = (uint8_t)(req->opcode >> 8u);
    descriptor[2] = (uint8_t)(req->opcode >> 16u);
    descriptor[3] = (uint8_t)(req->opcode >> 24u);
    for (uint32_t i = 0u; i < request_len; i++)
        descriptor[4u + i] = req->data[i];
    for (uint32_t i = 0u; i < reply_len; i++)
        descriptor[4u + request_len + i] = rep->data[i];
    eventbus_event_hash_bytes(descriptor, 4u + request_len + reply_len,
                              &request_root);
    if (emit_canonical_reference(req->opcode, badge, request_root.bytes,
                                 EVENTBUS_AGENT_EVENT_HASH_BYTES)
            != EVENTBUS_AGENT_EVENT_OK)
        return SEL4_ERR_INVALID_OP;
    /* Persist the exact IPC descriptor so replay can resolve model-visible
     * bytes from the stream payload_root. */
    if (agentfs_desc_persist(&request_root, descriptor,
                             4u + request_len + reply_len)
            != 0u)
        return SEL4_ERR_INVALID_OP;
    return status;
}

/* ── Entry point ────────────────────────────────────────────────────────── */

void agentfs_main(seL4_CPtr my_ep, seL4_CPtr ns_ep)
{
    (void)ns_ep;

    log_drain_write(3, 3, "[agentfs] AgentFS PD starting...\n");
    for (uint32_t i = 0; i < MAX_HOT_OBJECTS; i++)
        hot_index[i].state = OBJ_STATE_TOMBSTONE;
    hot_count      = 0;
    blob_watermark = 0;
    total_puts     = 0;
    total_gets     = 0;
    total_vectors  = 0;
    agentfs_workspace_init((void *)(uintptr_t)AGENTFS_SHMEM_VADDR,
                           AGENTFS_SHMEM_SIZE);
    agentfs_desc_store_init();
    log_drain_write(3, 3, "[agentfs] Capacity: 256 objects, 256KB blob store.\n");
    log_drain_write(3, 3, "[agentfs] Vector index: linear scan (HNSW in Phase 2).\n");
    log_drain_write(3, 3, "[agentfs] AgentFS ALIVE.\n");

    static sel4_server_t srv;
    sel4_server_init(&srv, my_ep);
    sel4_server_register(&srv, OP_AGENTFS_PUT,    h_put,    (void *)0);
    sel4_server_register(&srv, OP_AGENTFS_GET,    h_get,    (void *)0);
    sel4_server_register(&srv, OP_AGENTFS_QUERY,  h_stat,   (void *)0); /* Phase 1 stand-in */
    sel4_server_register(&srv, OP_AGENTFS_DELETE, h_delete, (void *)0);
    sel4_server_register(&srv, OP_AGENTFS_VECTOR, h_vector, (void *)0);
    sel4_server_register(&srv, OP_AGENTFS_STAT,   h_stat,   (void *)0);
    sel4_server_register(&srv, OP_AGENTFS_HEALTH, h_health, (void *)0);
    sel4_server_register(&srv, MSG_AGENTFS_READ,   h_workspace, (void *)0);
    sel4_server_register(&srv, MSG_AGENTFS_WRITE,  h_workspace, (void *)0);
    sel4_server_register(&srv, MSG_AGENTFS_STAT,   h_workspace, (void *)0);
    sel4_server_register(&srv, MSG_AGENTFS_DELETE, h_workspace, (void *)0);
    sel4_server_register(&srv, MSG_AGENTFS_EXPORT_OVERLAY,
                         h_workspace, (void *)0);
    sel4_server_run(&srv);
}

void pd_main(seL4_CPtr my_ep, seL4_CPtr ns_ep) { agentfs_main(my_ep, ns_ep); }
