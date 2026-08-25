/*
 * Continual harness E1: snapshot / evaluate / promote / rollback (no WASM).
 * fos-gz0.14.8
 */

#include "continual_harness.h"

#include <stddef.h>
#include <stdint.h>

struct continual_snapshot {
    int used;
    uint32_t id;
    uint32_t kind;
    uint32_t tier;
    uint32_t version;
    uint32_t evaluated;
    uint32_t beats_incumbent;
    uint32_t beats_null;
    uint32_t candidate_score;
    struct continual_digest content_root;
    struct continual_digest evidence_root;
    struct continual_digest snapshot_root;
};

struct continual_slot {
    int has_active;
    uint32_t active_version;
    uint32_t previous_version;
    struct continual_digest active_root;
    struct continual_digest previous_root;
    uint32_t incumbent_score;
};

static struct {
    uint32_t next_id;
    uint32_t wasm_compiled;
    struct continual_snapshot snaps[CONTINUAL_HARNESS_MAX_SNAPSHOTS];
    struct continual_slot slots[5]; /* index by kind 1..4 */
} g_ch;

static void bytes_zero(void *dst, size_t n)
{
    uint8_t *p = (uint8_t *)dst;
    while (n--) *p++ = 0;
}

static int digest_zero(const struct continual_digest *d)
{
    for (uint32_t i = 0u; i < CONTINUAL_HARNESS_DIGEST_BYTES; i++)
        if (d->bytes[i] != 0u)
            return 0;
    return 1;
}

static int digest_eq(const struct continual_digest *a,
                     const struct continual_digest *b)
{
    for (uint32_t i = 0u; i < CONTINUAL_HARNESS_DIGEST_BYTES; i++)
        if (a->bytes[i] != b->bytes[i])
            return 0;
    return 1;
}

static void digest_mix(struct continual_digest *out,
                       const struct continual_digest *a,
                       const struct continual_digest *b, uint32_t kind,
                       uint32_t version)
{
    for (uint32_t i = 0u; i < CONTINUAL_HARNESS_DIGEST_BYTES; i++)
        out->bytes[i] = (uint8_t)(a->bytes[i] ^ b->bytes[i] ^ (uint8_t)(kind + i)
                                  ^ (uint8_t)(version * 17u + i));
}

static uint32_t score_from_digest(const struct continual_digest *d)
{
    uint32_t s = 0u;
    for (uint32_t i = 0u; i < CONTINUAL_HARNESS_DIGEST_BYTES; i++)
        s = (s * 131u) + d->bytes[i];
    return s;
}

static int kind_ok(uint32_t kind)
{
    return kind >= CONTINUAL_KIND_NOTE && kind <= CONTINUAL_KIND_RETRY_HINT;
}

static struct continual_slot *slot_for(uint32_t kind)
{
    if (!kind_ok(kind))
        return NULL;
    return &g_ch.slots[kind];
}

static struct continual_snapshot *find_snap(uint32_t id)
{
    for (uint32_t i = 0u; i < CONTINUAL_HARNESS_MAX_SNAPSHOTS; i++)
        if (g_ch.snaps[i].used && g_ch.snaps[i].id == id)
            return &g_ch.snaps[i];
    return NULL;
}

static struct continual_snapshot *alloc_snap(void)
{
    for (uint32_t i = 0u; i < CONTINUAL_HARNESS_MAX_SNAPSHOTS; i++) {
        if (!g_ch.snaps[i].used) {
            bytes_zero(&g_ch.snaps[i], sizeof(g_ch.snaps[i]));
            g_ch.snaps[i].used = 1;
            return &g_ch.snaps[i];
        }
    }
    return NULL;
}

void continual_harness_reset(void)
{
    bytes_zero(&g_ch, sizeof(g_ch));
    g_ch.next_id = 1u;
    /* Null baseline score is fixed; incumbents start equal to null. */
    for (uint32_t k = CONTINUAL_KIND_NOTE; k <= CONTINUAL_KIND_RETRY_HINT; k++)
        g_ch.slots[k].incumbent_score = 1000u;
}

uint32_t continual_harness_snapshot(const struct continual_req_snapshot *req,
                                    struct continual_reply_snapshot *reply)
{
    struct continual_snapshot *snap;
    struct continual_slot *slot;

    if (reply == NULL)
        return CONTINUAL_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL || req->interface_version != CONTINUAL_HARNESS_INTERFACE_VERSION
        || !kind_ok(req->kind) || digest_zero(&req->content_root)
        || digest_zero(&req->evidence_root)) {
        reply->status = CONTINUAL_ERR_INVALID;
        return reply->status;
    }
    if (req->tier != CONTINUAL_TIER_E1_HARNESS) {
        reply->status = CONTINUAL_ERR_GATE;
        return reply->status;
    }
    if (g_ch.wasm_compiled != 0u) {
        reply->status = CONTINUAL_ERR_WASM_FORBIDDEN;
        return reply->status;
    }

    snap = alloc_snap();
    if (snap == NULL) {
        reply->status = CONTINUAL_ERR_FULL;
        return reply->status;
    }
    slot = slot_for(req->kind);
    snap->id = g_ch.next_id++;
    snap->kind = req->kind;
    snap->tier = req->tier;
    snap->version = slot->has_active ? slot->active_version + 1u : 1u;
    snap->content_root = req->content_root;
    snap->evidence_root = req->evidence_root;
    digest_mix(&snap->snapshot_root, &req->content_root, &req->evidence_root,
               req->kind, snap->version);

    reply->status = CONTINUAL_OK;
    reply->snapshot_id = snap->id;
    reply->version = snap->version;
    reply->snapshot_root = snap->snapshot_root;
    return CONTINUAL_OK;
}

uint32_t continual_harness_evaluate(const struct continual_req_evaluate *req,
                                    struct continual_reply_evaluate *reply)
{
    struct continual_snapshot *snap;
    struct continual_slot *slot;
    uint32_t cand;
    uint32_t null_score = 1000u;

    if (reply == NULL)
        return CONTINUAL_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL || req->interface_version != CONTINUAL_HARNESS_INTERFACE_VERSION) {
        reply->status = CONTINUAL_ERR_INVALID;
        return reply->status;
    }
    snap = find_snap(req->snapshot_id);
    if (snap == NULL) {
        reply->status = CONTINUAL_ERR_NOT_FOUND;
        return reply->status;
    }
    if (snap->tier != CONTINUAL_TIER_E1_HARNESS) {
        reply->status = CONTINUAL_ERR_GATE;
        return reply->status;
    }
    slot = slot_for(snap->kind);
    cand = score_from_digest(&snap->content_root);
    /* Require evidence linkage to contribute; zero-evidence already rejected. */
    cand ^= (score_from_digest(&snap->evidence_root) & 0xFFFFu);

    snap->candidate_score = cand;
    snap->beats_incumbent = cand > slot->incumbent_score ? 1u : 0u;
    snap->beats_null = cand > null_score ? 1u : 0u;
    snap->evaluated = 1u;

    reply->status = CONTINUAL_OK;
    reply->snapshot_id = snap->id;
    reply->beats_incumbent = snap->beats_incumbent;
    reply->beats_null = snap->beats_null;
    reply->candidate_score = cand;
    reply->incumbent_score = slot->incumbent_score;
    reply->null_score = null_score;
    return CONTINUAL_OK;
}

uint32_t continual_harness_promote(const struct continual_req_promote *req,
                                   struct continual_reply_promote *reply)
{
    struct continual_snapshot *snap;
    struct continual_slot *slot;

    if (reply == NULL)
        return CONTINUAL_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL || req->interface_version != CONTINUAL_HARNESS_INTERFACE_VERSION
        || req->require_beat_both != 1u) {
        reply->status = CONTINUAL_ERR_INVALID;
        return reply->status;
    }
    if (g_ch.wasm_compiled != 0u) {
        reply->status = CONTINUAL_ERR_WASM_FORBIDDEN;
        return reply->status;
    }
    snap = find_snap(req->snapshot_id);
    if (snap == NULL) {
        reply->status = CONTINUAL_ERR_NOT_FOUND;
        return reply->status;
    }
    if (!snap->evaluated) {
        reply->status = CONTINUAL_ERR_EVIDENCE;
        return reply->status;
    }
    if (!snap->beats_incumbent || !snap->beats_null) {
        reply->status = CONTINUAL_ERR_BASELINE;
        return reply->status;
    }

    slot = slot_for(snap->kind);
    reply->previous_version = slot->has_active ? slot->active_version : 0u;
    if (slot->has_active) {
        slot->previous_version = slot->active_version;
        slot->previous_root = slot->active_root;
    }
    slot->has_active = 1;
    slot->active_version = snap->version;
    slot->active_root = snap->snapshot_root;
    slot->incumbent_score = snap->candidate_score;

    reply->status = CONTINUAL_OK;
    reply->snapshot_id = snap->id;
    reply->promoted_version = snap->version;
    reply->promoted_root = snap->snapshot_root;
    return CONTINUAL_OK;
}

uint32_t continual_harness_rollback(const struct continual_req_rollback *req,
                                    struct continual_reply_rollback *reply)
{
    struct continual_slot *slot;

    if (reply == NULL)
        return CONTINUAL_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL || req->interface_version != CONTINUAL_HARNESS_INTERFACE_VERSION
        || !kind_ok(req->kind)) {
        reply->status = CONTINUAL_ERR_INVALID;
        return reply->status;
    }
    slot = slot_for(req->kind);
    if (!slot->has_active || slot->previous_version == 0u) {
        reply->status = CONTINUAL_ERR_STALE;
        return reply->status;
    }
    slot->active_version = slot->previous_version;
    slot->active_root = slot->previous_root;
    slot->previous_version = 0u;
    bytes_zero(&slot->previous_root, sizeof(slot->previous_root));
    /* Incumbent score rolls back to null baseline floor. */
    slot->incumbent_score = 1000u;

    reply->status = CONTINUAL_OK;
    reply->kind = req->kind;
    reply->restored_version = slot->active_version;
    reply->restored_root = slot->active_root;
    return CONTINUAL_OK;
}

uint32_t continual_harness_status(const struct continual_req_status *req,
                                  struct continual_reply_status *reply)
{
    struct continual_slot *slot;
    uint32_t count = 0u;

    if (reply == NULL)
        return CONTINUAL_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL || req->interface_version != CONTINUAL_HARNESS_INTERFACE_VERSION
        || !kind_ok(req->kind)) {
        reply->status = CONTINUAL_ERR_INVALID;
        return reply->status;
    }
    slot = slot_for(req->kind);
    for (uint32_t i = 0u; i < CONTINUAL_HARNESS_MAX_SNAPSHOTS; i++)
        if (g_ch.snaps[i].used && g_ch.snaps[i].kind == req->kind)
            count++;

    reply->status = CONTINUAL_OK;
    reply->kind = req->kind;
    reply->active_version = slot->has_active ? slot->active_version : 0u;
    reply->snapshot_count = count;
    if (slot->has_active)
        reply->active_root = slot->active_root;
    reply->wasm_compiled = g_ch.wasm_compiled;
    return CONTINUAL_OK;
}

uint32_t continual_harness_query_held_out(
    const struct continual_req_query_held_out *req,
    struct continual_reply_query_held_out *reply)
{
    if (reply == NULL)
        return CONTINUAL_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    (void)req;
    /* Candidate-facing path: never disclose held-out promotion cases. */
    reply->status = CONTINUAL_ERR_LEAKAGE;
    return CONTINUAL_ERR_LEAKAGE;
}
