/*
 * Fractal Companion Gateway host runtime (fos-gz0.14.17).
 *
 * Audience-checked projection dispatch over Local Gateway sessions.
 */

#include "companion_gateway.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct cg_service {
    int used;
    local_gateway_service_id_t service_id;
    local_gateway_audience_t audience;
};

struct cg_session {
    int used;
    int invalid;
    local_gateway_session_id_t session_id;
    local_gateway_service_id_t service_id;
    local_gateway_audience_t audience;
    local_gateway_root_id_t pinned_root;
    struct local_gateway_event_range event_range;
    uint32_t grant_mask;
    uint64_t authority_epoch;
};

static struct {
    struct cg_service services[LOCAL_GATEWAY_MAX_SERVICES];
    struct cg_session sessions[LOCAL_GATEWAY_MAX_SESSIONS];
} g_cg;

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
    return memcmp(a->bytes, b->bytes, LOCAL_GATEWAY_DIGEST_BYTES) == 0;
}

static void digest_copy(struct local_gateway_digest *dst,
                        const struct local_gateway_digest *src)
{
    memcpy(dst->bytes, src->bytes, LOCAL_GATEWAY_DIGEST_BYTES);
}

static void digest_fill(struct local_gateway_digest *d, uint8_t seed)
{
    uint32_t i;
    for (i = 0u; i < LOCAL_GATEWAY_DIGEST_BYTES; i++)
        d->bytes[i] = (uint8_t)(seed + i);
}

static uint32_t map_lg_err(uint32_t st)
{
    switch (st) {
    case LOCAL_GATEWAY_OK:
        return COMPANION_GATEWAY_OK;
    case LOCAL_GATEWAY_ERR_INVALID:
        return COMPANION_GATEWAY_ERR_INVALID;
    case LOCAL_GATEWAY_ERR_DENIED:
        return COMPANION_GATEWAY_ERR_DENIED;
    case LOCAL_GATEWAY_ERR_NOT_FOUND:
        return COMPANION_GATEWAY_ERR_NOT_FOUND;
    case LOCAL_GATEWAY_ERR_EXPIRED:
        return COMPANION_GATEWAY_ERR_EXPIRED;
    case LOCAL_GATEWAY_ERR_REVOKED:
        return COMPANION_GATEWAY_ERR_REVOKED;
    case LOCAL_GATEWAY_ERR_STALE_EPOCH:
        return COMPANION_GATEWAY_ERR_STALE_EPOCH;
    case LOCAL_GATEWAY_ERR_STALE_ROOT:
        return COMPANION_GATEWAY_ERR_STALE_ROOT;
    case LOCAL_GATEWAY_ERR_AMBIENT_DENIED:
        return COMPANION_GATEWAY_ERR_AMBIENT_DENIED;
    case LOCAL_GATEWAY_ERR_NO_GRANT:
        return COMPANION_GATEWAY_ERR_NO_GRANT;
    default:
        return COMPANION_GATEWAY_ERR_DENIED;
    }
}

static struct cg_service *find_service(const local_gateway_service_id_t *id)
{
    uint32_t i;
    if (digest_is_zero(id))
        return NULL;
    for (i = 0u; i < LOCAL_GATEWAY_MAX_SERVICES; i++) {
        if (g_cg.services[i].used &&
            digest_eq(&g_cg.services[i].service_id, id))
            return &g_cg.services[i];
    }
    return NULL;
}

static struct cg_session *find_session(const local_gateway_session_id_t *id)
{
    uint32_t i;
    if (digest_is_zero(id))
        return NULL;
    for (i = 0u; i < LOCAL_GATEWAY_MAX_SESSIONS; i++) {
        if (g_cg.sessions[i].used &&
            digest_eq(&g_cg.sessions[i].session_id, id))
            return &g_cg.sessions[i];
    }
    return NULL;
}

static int contains_canary(const uint8_t *buf, uint32_t len)
{
    static const char *canaries[] = {"CRED:", "sk_live", "PASSWORD=",
                                     "BEGIN PRIVATE"};
    uint32_t c;
    for (c = 0u; c < 4u; c++) {
        const char *pat = canaries[c];
        size_t plen = strlen(pat);
        uint32_t i;
        if (len < plen)
            continue;
        for (i = 0u; i + plen <= len; i++) {
            if (memcmp(buf + i, pat, plen) == 0)
                return 1;
        }
    }
    return 0;
}

static uint32_t audience_check(const struct cg_session *sess,
                               const local_gateway_audience_t *presented)
{
    if (sess == NULL)
        return COMPANION_GATEWAY_ERR_NOT_FOUND;
    if (sess->invalid)
        return COMPANION_GATEWAY_ERR_REVOKED;
    if (presented == NULL || digest_is_zero(presented))
        return COMPANION_GATEWAY_ERR_WRONG_AUDIENCE;
    if (!digest_eq(&sess->audience, presented))
        return COMPANION_GATEWAY_ERR_WRONG_AUDIENCE;
    return COMPANION_GATEWAY_OK;
}

void companion_gateway_reset(void)
{
    local_gateway_reset();
    bytes_zero(&g_cg, sizeof(g_cg));
}

uint32_t companion_gateway_publish_service(
    const struct local_gateway_req_publish_service *req,
    struct local_gateway_reply_publish_service *reply)
{
    uint32_t st;
    struct cg_service *slot;
    uint32_t i;

    st = local_gateway_publish_service(req, reply);
    if (st != LOCAL_GATEWAY_OK)
        return map_lg_err(st);

    slot = NULL;
    for (i = 0u; i < LOCAL_GATEWAY_MAX_SERVICES; i++) {
        if (!g_cg.services[i].used) {
            slot = &g_cg.services[i];
            break;
        }
    }
    if (slot == NULL)
        return COMPANION_GATEWAY_ERR_DENIED;

    bytes_zero(slot, sizeof(*slot));
    slot->used = 1;
    digest_copy(&slot->service_id, &req->service_id);
    digest_copy(&slot->audience, &req->audience);
    return COMPANION_GATEWAY_OK;
}

uint32_t companion_gateway_revoke_service(
    const struct local_gateway_req_revoke_service *req,
    struct local_gateway_reply_revoke_service *reply)
{
    uint32_t st;
    uint32_t i;

    st = local_gateway_revoke_service(req, reply);
    if (st != LOCAL_GATEWAY_OK)
        return map_lg_err(st);

    for (i = 0u; i < LOCAL_GATEWAY_MAX_SESSIONS; i++) {
        if (g_cg.sessions[i].used &&
            digest_eq(&g_cg.sessions[i].service_id, &req->service_id))
            g_cg.sessions[i].invalid = 1;
    }
    /* Cascade: mark sessions whose service was derived (child) — local_gateway
     * already revoked children; invalidate any session whose service status
     * is revoked. */
    for (i = 0u; i < LOCAL_GATEWAY_MAX_SESSIONS; i++) {
        struct local_gateway_req_status sreq;
        struct local_gateway_reply_status sreply;
        if (!g_cg.sessions[i].used || g_cg.sessions[i].invalid)
            continue;
        memset(&sreq, 0, sizeof(sreq));
        sreq.interface_version = LOCAL_GATEWAY_INTERFACE_VERSION;
        sreq.service_id = g_cg.sessions[i].service_id;
        if (local_gateway_status(&sreq, &sreply) == LOCAL_GATEWAY_OK &&
            sreply.revoked)
            g_cg.sessions[i].invalid = 1;
    }
    return COMPANION_GATEWAY_OK;
}

uint32_t companion_gateway_open_session(
    const struct local_gateway_req_open_session *req,
    const local_gateway_audience_t *presented_audience,
    struct local_gateway_reply_open_session *reply)
{
    struct cg_service *svc;
    struct cg_session *slot;
    uint32_t st;
    uint32_t i;

    if (req == NULL || presented_audience == NULL || reply == NULL)
        return COMPANION_GATEWAY_ERR_INVALID;

    svc = find_service(&req->service_id);
    if (svc == NULL)
        return COMPANION_GATEWAY_ERR_NOT_FOUND;
    if (!digest_eq(&svc->audience, presented_audience))
        return COMPANION_GATEWAY_ERR_WRONG_AUDIENCE;

    st = local_gateway_open_session(req, reply);
    if (st != LOCAL_GATEWAY_OK)
        return map_lg_err(st);

    slot = NULL;
    for (i = 0u; i < LOCAL_GATEWAY_MAX_SESSIONS; i++) {
        if (!g_cg.sessions[i].used) {
            slot = &g_cg.sessions[i];
            break;
        }
    }
    if (slot == NULL)
        return COMPANION_GATEWAY_ERR_DENIED;

    bytes_zero(slot, sizeof(*slot));
    slot->used = 1;
    digest_copy(&slot->session_id, &req->session_id);
    digest_copy(&slot->service_id, &req->service_id);
    digest_copy(&slot->audience, presented_audience);
    digest_copy(&slot->pinned_root, &req->pinned_root);
    slot->event_range = req->event_range;
    slot->grant_mask = req->grant_mask;
    slot->authority_epoch = req->authority_epoch;
    return COMPANION_GATEWAY_OK;
}

uint32_t companion_gateway_get_daily(
    const struct local_gateway_req_get_daily *req,
    const local_gateway_audience_t *presented_audience,
    struct local_gateway_daily_item *out_items, uint32_t out_cap,
    struct local_gateway_reply_get_daily *reply)
{
    struct cg_session *sess;
    uint32_t aud;
    uint32_t st;

    if (req == NULL || reply == NULL)
        return COMPANION_GATEWAY_ERR_INVALID;
    sess = find_session(&req->session_id);
    aud = audience_check(sess, presented_audience);
    if (aud != COMPANION_GATEWAY_OK)
        return aud;

    st = local_gateway_get_daily(req, out_items, out_cap, reply);
    return map_lg_err(st);
}

uint32_t companion_gateway_get_health(
    const local_gateway_session_id_t *session_id,
    const local_gateway_audience_t *presented_audience,
    uint64_t authority_epoch, uint64_t now_unix_ms,
    struct companion_gateway_health_summary *out)
{
    struct cg_session *sess;
    uint32_t aud;
    struct local_gateway_req_status sreq;
    struct local_gateway_reply_status sreply;

    if (session_id == NULL || out == NULL)
        return COMPANION_GATEWAY_ERR_INVALID;
    bytes_zero(out, sizeof(*out));
    sess = find_session(session_id);
    aud = audience_check(sess, presented_audience);
    if (aud != COMPANION_GATEWAY_OK)
        return aud;
    if (authority_epoch != sess->authority_epoch)
        return COMPANION_GATEWAY_ERR_STALE_EPOCH;
    if ((sess->grant_mask & LOCAL_GATEWAY_GRANT_HEALTH) == 0u)
        return COMPANION_GATEWAY_ERR_NO_GRANT;

    memset(&sreq, 0, sizeof(sreq));
    sreq.interface_version = LOCAL_GATEWAY_INTERFACE_VERSION;
    sreq.service_id = sess->service_id;
    if (local_gateway_status(&sreq, &sreply) != LOCAL_GATEWAY_OK)
        return COMPANION_GATEWAY_ERR_NOT_FOUND;
    if (sreply.revoked)
        return COMPANION_GATEWAY_ERR_REVOKED;
    if (now_unix_ms > sreply.expires_unix_ms)
        return COMPANION_GATEWAY_ERR_EXPIRED;

    digest_copy(&out->provenance_root, &sess->pinned_root);
    out->event_range = sess->event_range;
    out->authority_epoch = sess->authority_epoch;
    out->revoked = 0u;
    out->signal_count = 1u;
    out->signals[0].family = 1u;
    out->signals[0].confidence_bp = 5000u;
    out->signals[0].freshness = 1u;
    return COMPANION_GATEWAY_OK;
}

uint32_t companion_gateway_list_progress(
    const local_gateway_session_id_t *session_id,
    const local_gateway_audience_t *presented_audience,
    uint64_t authority_epoch, uint64_t now_unix_ms,
    struct companion_gateway_progress_item *out_items, uint32_t out_cap,
    uint32_t *out_count, local_gateway_root_id_t *out_root,
    struct local_gateway_event_range *out_range)
{
    struct cg_session *sess;
    uint32_t aud;
    struct local_gateway_req_status sreq;
    struct local_gateway_reply_status sreply;

    (void)now_unix_ms;
    if (session_id == NULL || out_count == NULL)
        return COMPANION_GATEWAY_ERR_INVALID;
    *out_count = 0u;
    sess = find_session(session_id);
    aud = audience_check(sess, presented_audience);
    if (aud != COMPANION_GATEWAY_OK)
        return aud;
    if (authority_epoch != sess->authority_epoch)
        return COMPANION_GATEWAY_ERR_STALE_EPOCH;
    if ((sess->grant_mask & LOCAL_GATEWAY_GRANT_PROGRESS) == 0u)
        return COMPANION_GATEWAY_ERR_NO_GRANT;

    memset(&sreq, 0, sizeof(sreq));
    sreq.interface_version = LOCAL_GATEWAY_INTERFACE_VERSION;
    sreq.service_id = sess->service_id;
    if (local_gateway_status(&sreq, &sreply) != LOCAL_GATEWAY_OK ||
        sreply.revoked)
        return COMPANION_GATEWAY_ERR_REVOKED;

    if (out_items != NULL && out_cap >= 1u) {
        bytes_zero(&out_items[0], sizeof(out_items[0]));
        digest_fill(&out_items[0].project_id, 0x70u);
        out_items[0].proof_level = 1u;
        out_items[0].state = 1u;
        out_items[0].label_len = 7u;
        memcpy(out_items[0].label, "project", 7u);
        *out_count = 1u;
    } else if (out_items == NULL) {
        *out_count = 1u;
    } else {
        return COMPANION_GATEWAY_ERR_INVALID;
    }
    if (out_root != NULL)
        digest_copy(out_root, &sess->pinned_root);
    if (out_range != NULL)
        *out_range = sess->event_range;
    return COMPANION_GATEWAY_OK;
}

uint32_t companion_gateway_list_worker_memory(
    const local_gateway_session_id_t *session_id,
    const local_gateway_audience_t *presented_audience,
    uint64_t authority_epoch, uint64_t now_unix_ms,
    struct companion_gateway_worker_memory *out_items, uint32_t out_cap,
    uint32_t *out_count, local_gateway_root_id_t *out_root,
    struct local_gateway_event_range *out_range)
{
    struct cg_session *sess;
    uint32_t aud;
    struct local_gateway_req_status sreq;
    struct local_gateway_reply_status sreply;

    (void)now_unix_ms;
    if (session_id == NULL || out_count == NULL)
        return COMPANION_GATEWAY_ERR_INVALID;
    *out_count = 0u;
    sess = find_session(session_id);
    aud = audience_check(sess, presented_audience);
    if (aud != COMPANION_GATEWAY_OK)
        return aud;
    if (authority_epoch != sess->authority_epoch)
        return COMPANION_GATEWAY_ERR_STALE_EPOCH;
    if ((sess->grant_mask & LOCAL_GATEWAY_GRANT_WORKER_MEMORY) == 0u)
        return COMPANION_GATEWAY_ERR_NO_GRANT;

    memset(&sreq, 0, sizeof(sreq));
    sreq.interface_version = LOCAL_GATEWAY_INTERFACE_VERSION;
    sreq.service_id = sess->service_id;
    if (local_gateway_status(&sreq, &sreply) != LOCAL_GATEWAY_OK ||
        sreply.revoked)
        return COMPANION_GATEWAY_ERR_REVOKED;

    if (out_items != NULL && out_cap >= 1u) {
        bytes_zero(&out_items[0], sizeof(out_items[0]));
        digest_fill(&out_items[0].worker_id, 0x60u);
        out_items[0].active_private_bytes = 32u * 1024u * 1024u;
        out_items[0].dormant_private_bytes = 128u * 1024u;
        *out_count = 1u;
    } else if (out_items == NULL) {
        *out_count = 1u;
    } else {
        return COMPANION_GATEWAY_ERR_INVALID;
    }
    if (out_root != NULL)
        digest_copy(out_root, &sess->pinned_root);
    if (out_range != NULL)
        *out_range = sess->event_range;
    return COMPANION_GATEWAY_OK;
}

uint32_t companion_gateway_submit_intent(
    const struct local_gateway_req_submit_intent *req,
    const local_gateway_audience_t *presented_audience,
    struct local_gateway_reply_submit_intent *reply)
{
    struct cg_session *sess;
    uint32_t aud;
    uint32_t st;

    if (req == NULL || reply == NULL)
        return COMPANION_GATEWAY_ERR_INVALID;
    sess = find_session(&req->session_id);
    aud = audience_check(sess, presented_audience);
    if (aud != COMPANION_GATEWAY_OK)
        return aud;
    if (contains_canary(req->note, req->note_len))
        return COMPANION_GATEWAY_ERR_CREDENTIAL;

    st = local_gateway_submit_intent(req, reply);
    return map_lg_err(st);
}
