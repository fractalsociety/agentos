/*
 * Fractal Local Gateway host runtime (fos-gz0.14.10.5).
 */

#include "local_gateway.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct service_slot {
    int used;
    int revoked;
    local_gateway_service_id_t service_id;
    local_gateway_audience_t audience;
    local_gateway_service_id_t parent_service;
    uint32_t grant_mask;
    uint64_t authority_epoch;
    uint64_t expires_unix_ms;
    local_gateway_event_id_t effect_ledger_event;
};

struct session_slot {
    int used;
    int invalid; /* set on revoke of backing service */
    local_gateway_session_id_t session_id;
    local_gateway_service_id_t service_id;
    local_gateway_root_id_t pinned_root;
    struct local_gateway_event_range event_range;
    uint32_t grant_mask;
    uint64_t authority_epoch;
};

struct daily_slot {
    int used;
    local_gateway_root_id_t pinned_root;
    uint8_t date_key[LOCAL_GATEWAY_MAX_DATE_BYTES];
    uint8_t date_len;
    uint8_t tz_key[LOCAL_GATEWAY_MAX_TZ_BYTES];
    uint8_t tz_len;
    local_gateway_object_id_t bundle_id;
    struct local_gateway_event_range event_range;
    uint64_t authority_epoch;
    uint32_t item_count;
    struct local_gateway_daily_item items[LOCAL_GATEWAY_MAX_DAILY_ITEMS];
};

static struct {
    struct service_slot services[LOCAL_GATEWAY_MAX_SERVICES];
    struct session_slot sessions[LOCAL_GATEWAY_MAX_SESSIONS];
    struct daily_slot dailies[LOCAL_GATEWAY_MAX_SERVICES];
} g_lg;

static void bytes_zero(void *dst, size_t n)
{
    uint8_t *p = (uint8_t *)dst;
    while (n--)
        *p++ = 0;
}

static int digest_is_zero(const struct local_gateway_digest *d)
{
    uint8_t c = 0u;
    uint32_t i;
    for (i = 0u; i < LOCAL_GATEWAY_DIGEST_BYTES; i++)
        c |= d->bytes[i];
    return c == 0u;
}

static int digest_eq(const struct local_gateway_digest *a,
                     const struct local_gateway_digest *b)
{
    uint8_t d = 0u;
    uint32_t i;
    for (i = 0u; i < LOCAL_GATEWAY_DIGEST_BYTES; i++)
        d |= (uint8_t)(a->bytes[i] ^ b->bytes[i]);
    return d == 0u;
}

static void digest_copy(struct local_gateway_digest *dst,
                        const struct local_gateway_digest *src)
{
    memcpy(dst->bytes, src->bytes, LOCAL_GATEWAY_DIGEST_BYTES);
}

static void hash_mix(struct local_gateway_digest *out, const uint8_t *data,
                     uint32_t len, uint8_t tag)
{
    uint64_t hash = UINT64_C(0xcbf29ce484222325);
    uint32_t i;
    bytes_zero(out, sizeof(*out));
    hash ^= tag;
    hash *= UINT64_C(0x100000001b3);
    for (i = 0u; i < len; i++) {
        hash ^= data[i];
        hash *= UINT64_C(0x100000001b3);
    }
    hash ^= len;
    for (i = 0u; i < 8u; i++)
        out->bytes[i] = (uint8_t)(hash >> (i * 8u));
    for (i = 8u; i < LOCAL_GATEWAY_DIGEST_BYTES; i++)
        out->bytes[i] = (uint8_t)(0x5Au ^ out->bytes[i - 8u] ^ tag);
}

static int grant_mask_ok(uint32_t mask)
{
    if ((mask & LOCAL_GATEWAY_AMBIENT_MASK) != 0u)
        return 0;
    if ((mask & ~LOCAL_GATEWAY_GRANT_MASK_ALLOWED) != 0u)
        return 0;
    return 1;
}

static struct service_slot *find_service(const local_gateway_service_id_t *id)
{
    uint32_t i;
    if (digest_is_zero(id))
        return NULL;
    for (i = 0u; i < LOCAL_GATEWAY_MAX_SERVICES; i++) {
        if (g_lg.services[i].used &&
            digest_eq(&g_lg.services[i].service_id, id))
            return &g_lg.services[i];
    }
    return NULL;
}

static struct session_slot *find_session(const local_gateway_session_id_t *id)
{
    uint32_t i;
    if (digest_is_zero(id))
        return NULL;
    for (i = 0u; i < LOCAL_GATEWAY_MAX_SESSIONS; i++) {
        if (g_lg.sessions[i].used &&
            digest_eq(&g_lg.sessions[i].session_id, id))
            return &g_lg.sessions[i];
    }
    return NULL;
}

static uint32_t service_live_check(const struct service_slot *svc,
                                   uint64_t epoch, uint64_t now_unix_ms)
{
    if (svc == NULL)
        return LOCAL_GATEWAY_ERR_NOT_FOUND;
    if (svc->revoked)
        return LOCAL_GATEWAY_ERR_REVOKED;
    if (epoch != svc->authority_epoch)
        return LOCAL_GATEWAY_ERR_STALE_EPOCH;
    if (now_unix_ms > svc->expires_unix_ms)
        return LOCAL_GATEWAY_ERR_EXPIRED;
    return LOCAL_GATEWAY_OK;
}

static uint32_t cascade_revoke(const local_gateway_service_id_t *parent,
                               uint32_t *sessions_invalidated,
                               uint32_t *derived_blocked)
{
    uint32_t i;
    uint32_t n_sess = 0u;
    uint32_t n_derived = 0u;

    for (i = 0u; i < LOCAL_GATEWAY_MAX_SESSIONS; i++) {
        if (g_lg.sessions[i].used && !g_lg.sessions[i].invalid &&
            digest_eq(&g_lg.sessions[i].service_id, parent)) {
            g_lg.sessions[i].invalid = 1;
            n_sess++;
        }
    }

    for (i = 0u; i < LOCAL_GATEWAY_MAX_SERVICES; i++) {
        struct service_slot *child = &g_lg.services[i];
        if (!child->used || child->revoked)
            continue;
        if (digest_is_zero(&child->parent_service))
            continue;
        if (!digest_eq(&child->parent_service, parent))
            continue;
        child->revoked = 1;
        n_derived++;
        {
            uint32_t child_sess = 0u;
            uint32_t child_der = 0u;
            (void)cascade_revoke(&child->service_id, &child_sess, &child_der);
            n_sess += child_sess;
            n_derived += child_der;
        }
    }

    if (sessions_invalidated != NULL)
        *sessions_invalidated = n_sess;
    if (derived_blocked != NULL)
        *derived_blocked = n_derived;
    return LOCAL_GATEWAY_OK;
}

void local_gateway_reset(void)
{
    bytes_zero(&g_lg, sizeof(g_lg));
}

uint32_t local_gateway_publish_service(
    const struct local_gateway_req_publish_service *req,
    struct local_gateway_reply_publish_service *reply)
{
    struct service_slot *slot;
    struct service_slot *parent;
    uint32_t i;

    if (reply == NULL)
        return LOCAL_GATEWAY_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL ||
        req->interface_version != LOCAL_GATEWAY_INTERFACE_VERSION ||
        digest_is_zero(&req->service_id) ||
        digest_is_zero(&req->audience) ||
        digest_is_zero(&req->effect_ledger_event) ||
        req->authority_epoch == 0u ||
        req->expires_unix_ms == 0u) {
        reply->status = LOCAL_GATEWAY_ERR_INVALID;
        return reply->status;
    }
    if ((req->grant_mask & LOCAL_GATEWAY_AMBIENT_MASK) != 0u) {
        reply->status = LOCAL_GATEWAY_ERR_AMBIENT_DENIED;
        return reply->status;
    }
    if (!grant_mask_ok(req->grant_mask) || req->grant_mask == 0u) {
        reply->status = LOCAL_GATEWAY_ERR_INVALID;
        return reply->status;
    }
    if (find_service(&req->service_id) != NULL) {
        reply->status = LOCAL_GATEWAY_ERR_DUPLICATE;
        return reply->status;
    }

    if (!digest_is_zero(&req->parent_service)) {
        parent = find_service(&req->parent_service);
        if (parent == NULL) {
            reply->status = LOCAL_GATEWAY_ERR_NOT_FOUND;
            return reply->status;
        }
        if (parent->revoked) {
            reply->status = LOCAL_GATEWAY_ERR_DERIVE_DENIED;
            return reply->status;
        }
        if (req->authority_epoch != parent->authority_epoch) {
            reply->status = LOCAL_GATEWAY_ERR_STALE_EPOCH;
            return reply->status;
        }
        /* Child grants must be a subset of parent. */
        if ((req->grant_mask & ~parent->grant_mask) != 0u) {
            reply->status = LOCAL_GATEWAY_ERR_DENIED;
            return reply->status;
        }
    }

    slot = NULL;
    for (i = 0u; i < LOCAL_GATEWAY_MAX_SERVICES; i++) {
        if (!g_lg.services[i].used) {
            slot = &g_lg.services[i];
            break;
        }
    }
    if (slot == NULL) {
        reply->status = LOCAL_GATEWAY_ERR_FULL;
        return reply->status;
    }

    bytes_zero(slot, sizeof(*slot));
    slot->used = 1;
    digest_copy(&slot->service_id, &req->service_id);
    digest_copy(&slot->audience, &req->audience);
    digest_copy(&slot->parent_service, &req->parent_service);
    slot->grant_mask = req->grant_mask;
    slot->authority_epoch = req->authority_epoch;
    slot->expires_unix_ms = req->expires_unix_ms;
    digest_copy(&slot->effect_ledger_event, &req->effect_ledger_event);

    digest_copy(&reply->service_id, &slot->service_id);
    reply->expires_unix_ms = slot->expires_unix_ms;
    reply->status = LOCAL_GATEWAY_OK;
    return LOCAL_GATEWAY_OK;
}

uint32_t local_gateway_revoke_service(
    const struct local_gateway_req_revoke_service *req,
    struct local_gateway_reply_revoke_service *reply)
{
    struct service_slot *svc;
    uint32_t n_sess = 0u;
    uint32_t n_der = 0u;

    if (reply == NULL)
        return LOCAL_GATEWAY_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL ||
        req->interface_version != LOCAL_GATEWAY_INTERFACE_VERSION ||
        digest_is_zero(&req->service_id) ||
        digest_is_zero(&req->effect_ledger_event)) {
        reply->status = LOCAL_GATEWAY_ERR_INVALID;
        return reply->status;
    }

    svc = find_service(&req->service_id);
    if (svc == NULL) {
        reply->status = LOCAL_GATEWAY_ERR_NOT_FOUND;
        return reply->status;
    }
    if (req->authority_epoch != svc->authority_epoch) {
        reply->status = LOCAL_GATEWAY_ERR_STALE_EPOCH;
        return reply->status;
    }
    if (svc->revoked) {
        reply->status = LOCAL_GATEWAY_ERR_REVOKED;
        return reply->status;
    }

    svc->revoked = 1;
    digest_copy(&svc->effect_ledger_event, &req->effect_ledger_event);
    (void)cascade_revoke(&svc->service_id, &n_sess, &n_der);
    reply->sessions_invalidated = n_sess;
    reply->derived_blocked = n_der;
    reply->status = LOCAL_GATEWAY_OK;
    return LOCAL_GATEWAY_OK;
}

uint32_t local_gateway_open_session(
    const struct local_gateway_req_open_session *req,
    struct local_gateway_reply_open_session *reply)
{
    struct service_slot *svc;
    struct session_slot *slot;
    uint32_t live;
    uint32_t i;

    if (reply == NULL)
        return LOCAL_GATEWAY_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL ||
        req->interface_version != LOCAL_GATEWAY_INTERFACE_VERSION ||
        digest_is_zero(&req->service_id) ||
        digest_is_zero(&req->session_id) ||
        digest_is_zero(&req->pinned_root) ||
        req->event_range.first_seq == 0u ||
        req->event_range.last_seq < req->event_range.first_seq ||
        digest_is_zero(&req->event_range.head)) {
        reply->status = LOCAL_GATEWAY_ERR_INVALID;
        return reply->status;
    }
    if ((req->grant_mask & LOCAL_GATEWAY_AMBIENT_MASK) != 0u) {
        reply->status = LOCAL_GATEWAY_ERR_AMBIENT_DENIED;
        return reply->status;
    }
    if (!grant_mask_ok(req->grant_mask) || req->grant_mask == 0u) {
        reply->status = LOCAL_GATEWAY_ERR_INVALID;
        return reply->status;
    }

    svc = find_service(&req->service_id);
    live = service_live_check(svc, req->authority_epoch, req->now_unix_ms);
    if (live != LOCAL_GATEWAY_OK) {
        reply->status = live;
        return reply->status;
    }
    if ((req->grant_mask & ~svc->grant_mask) != 0u) {
        reply->status = LOCAL_GATEWAY_ERR_DENIED;
        return reply->status;
    }
    if (find_session(&req->session_id) != NULL) {
        reply->status = LOCAL_GATEWAY_ERR_DUPLICATE;
        return reply->status;
    }

    slot = NULL;
    for (i = 0u; i < LOCAL_GATEWAY_MAX_SESSIONS; i++) {
        if (!g_lg.sessions[i].used) {
            slot = &g_lg.sessions[i];
            break;
        }
    }
    if (slot == NULL) {
        reply->status = LOCAL_GATEWAY_ERR_FULL;
        return reply->status;
    }

    bytes_zero(slot, sizeof(*slot));
    slot->used = 1;
    digest_copy(&slot->session_id, &req->session_id);
    digest_copy(&slot->service_id, &req->service_id);
    digest_copy(&slot->pinned_root, &req->pinned_root);
    slot->event_range = req->event_range;
    slot->grant_mask = req->grant_mask;
    slot->authority_epoch = req->authority_epoch;

    digest_copy(&reply->session_id, &slot->session_id);
    digest_copy(&reply->pinned_root, &slot->pinned_root);
    reply->grant_mask = slot->grant_mask;
    reply->status = LOCAL_GATEWAY_OK;
    return LOCAL_GATEWAY_OK;
}

static struct daily_slot *find_or_build_daily(
    const struct session_slot *sess, const uint8_t *date_key, uint8_t date_len,
    const uint8_t *tz_key, uint8_t tz_len)
{
    uint32_t i;
    struct daily_slot *free_slot = NULL;
    struct local_gateway_digest mix;

    for (i = 0u; i < LOCAL_GATEWAY_MAX_SERVICES; i++) {
        struct daily_slot *d = &g_lg.dailies[i];
        if (!d->used) {
            if (free_slot == NULL)
                free_slot = d;
            continue;
        }
        if (digest_eq(&d->pinned_root, &sess->pinned_root) &&
            d->date_len == date_len && d->tz_len == tz_len &&
            memcmp(d->date_key, date_key, date_len) == 0 &&
            memcmp(d->tz_key, tz_key, tz_len) == 0)
            return d;
    }
    if (free_slot == NULL)
        return NULL;

    bytes_zero(free_slot, sizeof(*free_slot));
    free_slot->used = 1;
    digest_copy(&free_slot->pinned_root, &sess->pinned_root);
    free_slot->date_len = date_len;
    free_slot->tz_len = tz_len;
    memcpy(free_slot->date_key, date_key, date_len);
    memcpy(free_slot->tz_key, tz_key, tz_len);
    free_slot->event_range = sess->event_range;
    free_slot->authority_epoch = sess->authority_epoch;

    hash_mix(&mix, sess->pinned_root.bytes, LOCAL_GATEWAY_DIGEST_BYTES, 0xD1u);
    hash_mix(&free_slot->bundle_id, date_key, date_len, 0xD2u);
    for (i = 0u; i < LOCAL_GATEWAY_DIGEST_BYTES; i++)
        free_slot->bundle_id.bytes[i] ^= mix.bytes[i] ^ tz_key[i % tz_len];

    free_slot->item_count = 1u;
    hash_mix(&free_slot->items[0].item_id, free_slot->bundle_id.bytes,
             LOCAL_GATEWAY_DIGEST_BYTES, 0xD3u);
    free_slot->items[0].kind = 1u;
    free_slot->items[0].label_len = date_len;
    memcpy(free_slot->items[0].label, date_key, date_len);
    return free_slot;
}

uint32_t local_gateway_get_daily(
    const struct local_gateway_req_get_daily *req,
    struct local_gateway_daily_item *out_items, uint32_t out_cap,
    struct local_gateway_reply_get_daily *reply)
{
    struct session_slot *sess;
    struct service_slot *svc;
    struct daily_slot *daily;
    uint32_t live;
    uint32_t n;
    uint32_t i;

    if (reply == NULL)
        return LOCAL_GATEWAY_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL ||
        req->interface_version != LOCAL_GATEWAY_INTERFACE_VERSION ||
        digest_is_zero(&req->session_id) ||
        req->date_len != LOCAL_GATEWAY_MAX_DATE_BYTES ||
        req->tz_len == 0u || req->tz_len > LOCAL_GATEWAY_MAX_TZ_BYTES) {
        reply->status = LOCAL_GATEWAY_ERR_INVALID;
        return reply->status;
    }

    sess = find_session(&req->session_id);
    if (sess == NULL || sess->invalid) {
        reply->status = sess != NULL ? LOCAL_GATEWAY_ERR_REVOKED
                                     : LOCAL_GATEWAY_ERR_NOT_FOUND;
        return reply->status;
    }
    if (req->authority_epoch != sess->authority_epoch) {
        reply->status = LOCAL_GATEWAY_ERR_STALE_EPOCH;
        return reply->status;
    }
    if ((sess->grant_mask & LOCAL_GATEWAY_GRANT_DAILY_ROOT) == 0u) {
        reply->status = LOCAL_GATEWAY_ERR_NO_GRANT;
        return reply->status;
    }

    svc = find_service(&sess->service_id);
    live = service_live_check(svc, req->authority_epoch, req->now_unix_ms);
    if (live != LOCAL_GATEWAY_OK) {
        reply->status = live;
        return reply->status;
    }

    daily = find_or_build_daily(sess, req->date_key, req->date_len, req->tz_key,
                                req->tz_len);
    if (daily == NULL) {
        reply->status = LOCAL_GATEWAY_ERR_FULL;
        return reply->status;
    }

    n = daily->item_count;
    if (out_items != NULL && out_cap < n) {
        reply->status = LOCAL_GATEWAY_ERR_INVALID;
        return reply->status;
    }
    if (out_items != NULL) {
        for (i = 0u; i < n; i++)
            out_items[i] = daily->items[i];
    }

    digest_copy(&reply->bundle_id, &daily->bundle_id);
    digest_copy(&reply->pinned_root, &daily->pinned_root);
    reply->event_range = daily->event_range;
    reply->authority_epoch = daily->authority_epoch;
    reply->item_count = n;
    reply->status = LOCAL_GATEWAY_OK;
    return LOCAL_GATEWAY_OK;
}

uint32_t local_gateway_submit_intent(
    const struct local_gateway_req_submit_intent *req,
    struct local_gateway_reply_submit_intent *reply)
{
    struct session_slot *sess;
    struct service_slot *svc;
    uint32_t live;
    uint8_t mix_buf[64];

    if (reply == NULL)
        return LOCAL_GATEWAY_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL ||
        req->interface_version != LOCAL_GATEWAY_INTERFACE_VERSION ||
        digest_is_zero(&req->session_id) ||
        digest_is_zero(&req->subject) ||
        digest_is_zero(&req->expect_root) ||
        req->note_len > LOCAL_GATEWAY_MAX_NOTE_BYTES ||
        req->intent_kind < LOCAL_GATEWAY_INTENT_ACKNOWLEDGE ||
        req->intent_kind > LOCAL_GATEWAY_INTENT_CANCEL) {
        reply->status = LOCAL_GATEWAY_ERR_INVALID;
        return reply->status;
    }

    sess = find_session(&req->session_id);
    if (sess == NULL || sess->invalid) {
        reply->status = sess != NULL ? LOCAL_GATEWAY_ERR_REVOKED
                                     : LOCAL_GATEWAY_ERR_NOT_FOUND;
        return reply->status;
    }
    if (req->authority_epoch != sess->authority_epoch) {
        reply->status = LOCAL_GATEWAY_ERR_STALE_EPOCH;
        return reply->status;
    }
    if ((sess->grant_mask & LOCAL_GATEWAY_GRANT_TASK_INTENT) == 0u) {
        reply->status = LOCAL_GATEWAY_ERR_NO_GRANT;
        return reply->status;
    }
    if (!digest_eq(&req->expect_root, &sess->pinned_root)) {
        reply->status = LOCAL_GATEWAY_ERR_STALE_ROOT;
        return reply->status;
    }

    svc = find_service(&sess->service_id);
    live = service_live_check(svc, req->authority_epoch, req->now_unix_ms);
    if (live != LOCAL_GATEWAY_OK) {
        reply->status = live;
        return reply->status;
    }

    memcpy(mix_buf, req->session_id.bytes, 32u);
    memcpy(mix_buf + 32u, req->subject.bytes, 32u);
    hash_mix(&reply->intent_id, mix_buf, 64u, (uint8_t)req->intent_kind);
    digest_copy(&reply->committed_root, &sess->pinned_root);
    reply->status = LOCAL_GATEWAY_OK;
    return LOCAL_GATEWAY_OK;
}

uint32_t local_gateway_status(const struct local_gateway_req_status *req,
                              struct local_gateway_reply_status *reply)
{
    struct service_slot *svc;
    struct session_slot *sess;

    if (reply == NULL)
        return LOCAL_GATEWAY_ERR_INVALID;
    bytes_zero(reply, sizeof(*reply));
    if (req == NULL ||
        req->interface_version != LOCAL_GATEWAY_INTERFACE_VERSION) {
        reply->status = LOCAL_GATEWAY_ERR_INVALID;
        return reply->status;
    }

    if (!digest_is_zero(&req->service_id)) {
        svc = find_service(&req->service_id);
        if (svc == NULL) {
            reply->status = LOCAL_GATEWAY_ERR_NOT_FOUND;
            return reply->status;
        }
        reply->revoked = svc->revoked ? 1u : 0u;
        reply->grant_mask = svc->grant_mask;
        reply->expires_unix_ms = svc->expires_unix_ms;
        reply->status = LOCAL_GATEWAY_OK;
        return LOCAL_GATEWAY_OK;
    }

    sess = find_session(&req->session_id);
    if (sess == NULL) {
        reply->status = LOCAL_GATEWAY_ERR_NOT_FOUND;
        return reply->status;
    }
    svc = find_service(&sess->service_id);
    reply->revoked = (sess->invalid || (svc != NULL && svc->revoked)) ? 1u : 0u;
    reply->grant_mask = sess->grant_mask;
    reply->expires_unix_ms = svc != NULL ? svc->expires_unix_ms : 0u;
    digest_copy(&reply->pinned_root, &sess->pinned_root);
    reply->status = LOCAL_GATEWAY_OK;
    return LOCAL_GATEWAY_OK;
}

uint32_t local_gateway_service_count(void)
{
    uint32_t i, n = 0u;
    for (i = 0u; i < LOCAL_GATEWAY_MAX_SERVICES; i++) {
        if (g_lg.services[i].used)
            n++;
    }
    return n;
}

uint32_t local_gateway_session_count(void)
{
    uint32_t i, n = 0u;
    for (i = 0u; i < LOCAL_GATEWAY_MAX_SESSIONS; i++) {
        if (g_lg.sessions[i].used && !g_lg.sessions[i].invalid)
            n++;
    }
    return n;
}
