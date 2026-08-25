/*
 * fos-gz0.14.10.5 — Fractal Local Gateway contracts (L2 host).
 *
 * Proves: pinned daily workspace under session grants; task-intent only when
 * granted; ambient ACT/COMMIT/credential/shell/promotion denied; revoke
 * invalidates sessions and blocks downstream derivation; expiry/stale epoch
 * fail closed. No HTML/CSS/JS in this change set.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../kernel/fractalos-root-task/include/fractalos.h"
#include "../kernel/fractalos-root-task/include/local_gateway.h"

static int g_failures;

static void expect_eq_u32(const char *name, uint32_t got, uint32_t want)
{
    if (got != want) {
        fprintf(stderr, "FAIL %s: got %u want %u\n", name, got, want);
        g_failures++;
    } else {
        printf("ok - %s\n", name);
    }
}

static void expect_true(const char *name, int cond)
{
    if (!cond) {
        fprintf(stderr, "FAIL %s\n", name);
        g_failures++;
    } else {
        printf("ok - %s\n", name);
    }
}

static void digest_fill(struct local_gateway_digest *d, uint8_t seed)
{
    uint32_t i;
    for (i = 0u; i < LOCAL_GATEWAY_DIGEST_BYTES; i++)
        d->bytes[i] = (uint8_t)(seed + i);
}

static void digest_zero(struct local_gateway_digest *d)
{
    memset(d, 0, sizeof(*d));
}

static int digest_eq(const struct local_gateway_digest *a,
                     const struct local_gateway_digest *b)
{
    return memcmp(a->bytes, b->bytes, LOCAL_GATEWAY_DIGEST_BYTES) == 0;
}

static void test_opcodes(void)
{
    expect_eq_u32("MSG_LOCAL_GATEWAY_PUBLISH_SERVICE",
                  MSG_LOCAL_GATEWAY_PUBLISH_SERVICE, 0x3401u);
    expect_eq_u32("MSG_LOCAL_GATEWAY_REVOKE_SERVICE",
                  MSG_LOCAL_GATEWAY_REVOKE_SERVICE, 0x3402u);
    expect_eq_u32("MSG_LOCAL_GATEWAY_OPEN_SESSION",
                  MSG_LOCAL_GATEWAY_OPEN_SESSION, 0x3403u);
    expect_eq_u32("MSG_LOCAL_GATEWAY_GET_DAILY", MSG_LOCAL_GATEWAY_GET_DAILY,
                  0x3404u);
    expect_eq_u32("MSG_LOCAL_GATEWAY_SUBMIT_INTENT",
                  MSG_LOCAL_GATEWAY_SUBMIT_INTENT, 0x3405u);
    expect_eq_u32("MSG_LOCAL_GATEWAY_STATUS", MSG_LOCAL_GATEWAY_STATUS,
                  0x3406u);
    expect_eq_u32("interface version", LOCAL_GATEWAY_INTERFACE_VERSION, 1u);
}

static uint32_t publish(const local_gateway_service_id_t *svc,
                        const local_gateway_audience_t *aud,
                        const local_gateway_service_id_t *parent,
                        uint32_t grants, uint64_t epoch, uint64_t expires,
                        const char *label)
{
    struct local_gateway_req_publish_service req;
    struct local_gateway_reply_publish_service reply;

    memset(&req, 0, sizeof(req));
    req.interface_version = LOCAL_GATEWAY_INTERFACE_VERSION;
    req.grant_mask = grants;
    req.service_id = *svc;
    req.audience = *aud;
    if (parent != NULL)
        req.parent_service = *parent;
    req.authority_epoch = epoch;
    req.expires_unix_ms = expires;
    digest_fill(&req.effect_ledger_event, 0xE1u);
    expect_eq_u32(label, local_gateway_publish_service(&req, &reply),
                  LOCAL_GATEWAY_OK);
    return reply.status;
}

static uint32_t open_session(const local_gateway_service_id_t *svc,
                             const local_gateway_session_id_t *sess,
                             const local_gateway_root_id_t *root,
                             uint32_t grants, uint64_t epoch, uint64_t now,
                             const char *label, uint32_t want_status)
{
    struct local_gateway_req_open_session req;
    struct local_gateway_reply_open_session reply;

    memset(&req, 0, sizeof(req));
    req.interface_version = LOCAL_GATEWAY_INTERFACE_VERSION;
    req.grant_mask = grants;
    req.service_id = *svc;
    req.session_id = *sess;
    req.pinned_root = *root;
    req.event_range.stream_id = 1u;
    req.event_range.first_seq = 1u;
    req.event_range.last_seq = 10u;
    digest_fill(&req.event_range.head, 0xDDu);
    req.authority_epoch = epoch;
    req.now_unix_ms = now;
    expect_eq_u32(label, local_gateway_open_session(&req, &reply), want_status);
    return reply.status;
}

static void test_ambient_denied(void)
{
    local_gateway_service_id_t svc;
    local_gateway_audience_t aud;
    struct local_gateway_req_publish_service req;
    struct local_gateway_reply_publish_service reply;

    local_gateway_reset();
    digest_fill(&svc, 0x10u);
    digest_fill(&aud, 0xA0u);

    memset(&req, 0, sizeof(req));
    req.interface_version = LOCAL_GATEWAY_INTERFACE_VERSION;
    req.grant_mask =
        LOCAL_GATEWAY_GRANT_DAILY_ROOT | LOCAL_GATEWAY_AMBIENT_ACT;
    req.service_id = svc;
    req.audience = aud;
    req.authority_epoch = 1u;
    req.expires_unix_ms = 10000u;
    digest_fill(&req.effect_ledger_event, 0xE1u);
    expect_eq_u32("publish ambient ACT denied",
                  local_gateway_publish_service(&req, &reply),
                  LOCAL_GATEWAY_ERR_AMBIENT_DENIED);

    req.grant_mask =
        LOCAL_GATEWAY_GRANT_TASK_INTENT | LOCAL_GATEWAY_AMBIENT_SHELL |
        LOCAL_GATEWAY_AMBIENT_COMMIT | LOCAL_GATEWAY_AMBIENT_CREDENTIAL |
        LOCAL_GATEWAY_AMBIENT_PROMOTION;
    expect_eq_u32("publish ambient bundle denied",
                  local_gateway_publish_service(&req, &reply),
                  LOCAL_GATEWAY_ERR_AMBIENT_DENIED);
}

static void test_daily_workspace_and_intent(void)
{
    local_gateway_service_id_t svc;
    local_gateway_audience_t aud;
    local_gateway_session_id_t sess;
    local_gateway_session_id_t sess_ro;
    local_gateway_root_id_t root;
    local_gateway_object_id_t subject;
    struct local_gateway_req_get_daily dreq;
    struct local_gateway_reply_get_daily dreply;
    struct local_gateway_daily_item items[4];
    struct local_gateway_req_submit_intent ireq;
    struct local_gateway_reply_submit_intent ireply;
    struct local_gateway_req_status sreq;
    struct local_gateway_reply_status sreply;

    local_gateway_reset();
    digest_fill(&svc, 0x11u);
    digest_fill(&aud, 0xA1u);
    digest_fill(&sess, 0x51u);
    digest_fill(&sess_ro, 0x52u);
    digest_fill(&root, 0x91u);
    digest_fill(&subject, 0xB1u);

    publish(&svc, &aud, NULL,
            LOCAL_GATEWAY_GRANT_DAILY_ROOT | LOCAL_GATEWAY_GRANT_TASK_INTENT,
            2u, 50000u, "publish daily+intent service");

    open_session(&svc, &sess, &root,
                 LOCAL_GATEWAY_GRANT_DAILY_ROOT | LOCAL_GATEWAY_GRANT_TASK_INTENT,
                 2u, 1000u, "open full session", LOCAL_GATEWAY_OK);

    /* Read-only session without task-intent grant. */
    open_session(&svc, &sess_ro, &root, LOCAL_GATEWAY_GRANT_DAILY_ROOT, 2u,
                 1000u, "open daily-only session", LOCAL_GATEWAY_OK);

    memset(&dreq, 0, sizeof(dreq));
    dreq.interface_version = LOCAL_GATEWAY_INTERFACE_VERSION;
    dreq.session_id = sess;
    dreq.authority_epoch = 2u;
    dreq.now_unix_ms = 1000u;
    dreq.date_len = 10u;
    dreq.tz_len = 3u;
    memcpy(dreq.date_key, "2026-08-24", 10u);
    memcpy(dreq.tz_key, "UTC", 3u);
    expect_eq_u32("get daily workspace",
                  local_gateway_get_daily(&dreq, items, 4u, &dreply),
                  LOCAL_GATEWAY_OK);
    expect_eq_u32("daily item_count", dreply.item_count, 1u);
    expect_true("daily pinned to root",
                digest_eq(&dreply.pinned_root, &root));
    {
        local_gateway_object_id_t zero;
        digest_zero(&zero);
        expect_true("daily bundle non-zero",
                    !digest_eq(&dreply.bundle_id, &zero));
    }

    /* Intent without grant denied. */
    memset(&ireq, 0, sizeof(ireq));
    ireq.interface_version = LOCAL_GATEWAY_INTERFACE_VERSION;
    ireq.intent_kind = LOCAL_GATEWAY_INTENT_ACKNOWLEDGE;
    ireq.session_id = sess_ro;
    ireq.subject = subject;
    ireq.expect_root = root;
    ireq.authority_epoch = 2u;
    ireq.now_unix_ms = 1000u;
    expect_eq_u32("intent without grant",
                  local_gateway_submit_intent(&ireq, &ireply),
                  LOCAL_GATEWAY_ERR_NO_GRANT);

    /* Wrong expect_root denied. */
    ireq.session_id = sess;
    digest_fill(&ireq.expect_root, 0xFFu);
    expect_eq_u32("intent stale root",
                  local_gateway_submit_intent(&ireq, &ireply),
                  LOCAL_GATEWAY_ERR_STALE_ROOT);

    ireq.expect_root = root;
    expect_eq_u32("intent granted",
                  local_gateway_submit_intent(&ireq, &ireply),
                  LOCAL_GATEWAY_OK);
    {
        local_gateway_object_id_t zero;
        digest_zero(&zero);
        expect_true("intent id minted",
                    !digest_eq(&ireply.intent_id, &zero));
    }
    expect_true("intent committed root",
                digest_eq(&ireply.committed_root, &root));

    memset(&sreq, 0, sizeof(sreq));
    sreq.interface_version = LOCAL_GATEWAY_INTERFACE_VERSION;
    sreq.session_id = sess;
    expect_eq_u32("session status", local_gateway_status(&sreq, &sreply),
                  LOCAL_GATEWAY_OK);
    expect_eq_u32("session not revoked", sreply.revoked, 0u);
    expect_true("status pinned root",
                digest_eq(&sreply.pinned_root, &root));
}

static void test_revoke_blocks_access_and_derivation(void)
{
    local_gateway_service_id_t parent, child;
    local_gateway_audience_t aud;
    local_gateway_session_id_t sess;
    local_gateway_root_id_t root;
    struct local_gateway_req_revoke_service rreq;
    struct local_gateway_reply_revoke_service rreply;
    struct local_gateway_req_publish_service preq;
    struct local_gateway_reply_publish_service preply;
    struct local_gateway_req_get_daily dreq;
    struct local_gateway_reply_get_daily dreply;
    struct local_gateway_req_status sreq;
    struct local_gateway_reply_status sreply;
    local_gateway_service_id_t orphan;

    local_gateway_reset();
    digest_fill(&parent, 0x20u);
    digest_fill(&child, 0x21u);
    digest_fill(&aud, 0xA2u);
    digest_fill(&sess, 0x53u);
    digest_fill(&root, 0x92u);
    digest_fill(&orphan, 0x22u);

    publish(&parent, &aud, NULL,
            LOCAL_GATEWAY_GRANT_DAILY_ROOT | LOCAL_GATEWAY_GRANT_TASK_INTENT |
                LOCAL_GATEWAY_GRANT_PROGRESS,
            3u, 90000u, "publish parent");
    publish(&child, &aud, &parent, LOCAL_GATEWAY_GRANT_DAILY_ROOT, 3u, 90000u,
            "publish child derived");

    open_session(&parent, &sess, &root, LOCAL_GATEWAY_GRANT_DAILY_ROOT, 3u,
                 2000u, "open parent session", LOCAL_GATEWAY_OK);
    expect_eq_u32("active sessions before revoke",
                  local_gateway_session_count(), 1u);

    memset(&rreq, 0, sizeof(rreq));
    rreq.interface_version = LOCAL_GATEWAY_INTERFACE_VERSION;
    rreq.service_id = parent;
    rreq.authority_epoch = 3u;
    digest_fill(&rreq.effect_ledger_event, 0xE2u);
    expect_eq_u32("revoke parent",
                  local_gateway_revoke_service(&rreq, &rreply),
                  LOCAL_GATEWAY_OK);
    expect_true("sessions invalidated", rreply.sessions_invalidated >= 1u);
    expect_true("derived blocked", rreply.derived_blocked >= 1u);
    expect_eq_u32("no live sessions", local_gateway_session_count(), 0u);

    memset(&dreq, 0, sizeof(dreq));
    dreq.interface_version = LOCAL_GATEWAY_INTERFACE_VERSION;
    dreq.session_id = sess;
    dreq.authority_epoch = 3u;
    dreq.now_unix_ms = 2000u;
    dreq.date_len = 10u;
    dreq.tz_len = 3u;
    memcpy(dreq.date_key, "2026-08-24", 10u);
    memcpy(dreq.tz_key, "UTC", 3u);
    expect_eq_u32("daily after revoke",
                  local_gateway_get_daily(&dreq, NULL, 0u, &dreply),
                  LOCAL_GATEWAY_ERR_REVOKED);

    memset(&sreq, 0, sizeof(sreq));
    sreq.interface_version = LOCAL_GATEWAY_INTERFACE_VERSION;
    sreq.service_id = child;
    expect_eq_u32("child status", local_gateway_status(&sreq, &sreply),
                  LOCAL_GATEWAY_OK);
    expect_eq_u32("child revoked via cascade", sreply.revoked, 1u);

    /* New derivation from revoked parent denied. */
    memset(&preq, 0, sizeof(preq));
    preq.interface_version = LOCAL_GATEWAY_INTERFACE_VERSION;
    preq.grant_mask = LOCAL_GATEWAY_GRANT_DAILY_ROOT;
    preq.service_id = orphan;
    preq.audience = aud;
    preq.parent_service = parent;
    preq.authority_epoch = 3u;
    preq.expires_unix_ms = 90000u;
    digest_fill(&preq.effect_ledger_event, 0xE3u);
    expect_eq_u32("derive after revoke",
                  local_gateway_publish_service(&preq, &preply),
                  LOCAL_GATEWAY_ERR_DERIVE_DENIED);
}

static void test_expiry_and_stale_epoch(void)
{
    local_gateway_service_id_t svc;
    local_gateway_audience_t aud;
    local_gateway_session_id_t sess;
    local_gateway_root_id_t root;
    struct local_gateway_req_open_session oreq;
    struct local_gateway_reply_open_session oreply;

    local_gateway_reset();
    digest_fill(&svc, 0x30u);
    digest_fill(&aud, 0xA3u);
    digest_fill(&sess, 0x54u);
    digest_fill(&root, 0x93u);

    publish(&svc, &aud, NULL, LOCAL_GATEWAY_GRANT_DAILY_ROOT, 5u, 1000u,
            "publish short-lived");

    memset(&oreq, 0, sizeof(oreq));
    oreq.interface_version = LOCAL_GATEWAY_INTERFACE_VERSION;
    oreq.grant_mask = LOCAL_GATEWAY_GRANT_DAILY_ROOT;
    oreq.service_id = svc;
    oreq.session_id = sess;
    oreq.pinned_root = root;
    oreq.event_range.stream_id = 1u;
    oreq.event_range.first_seq = 1u;
    oreq.event_range.last_seq = 2u;
    digest_fill(&oreq.event_range.head, 0xDEu);
    oreq.authority_epoch = 4u; /* stale */
    oreq.now_unix_ms = 500u;
    expect_eq_u32("open stale epoch",
                  local_gateway_open_session(&oreq, &oreply),
                  LOCAL_GATEWAY_ERR_STALE_EPOCH);

    oreq.authority_epoch = 5u;
    oreq.now_unix_ms = 1001u; /* past expiry */
    expect_eq_u32("open expired", local_gateway_open_session(&oreq, &oreply),
                  LOCAL_GATEWAY_ERR_EXPIRED);

    oreq.now_unix_ms = 999u;
    expect_eq_u32("open before expiry",
                  local_gateway_open_session(&oreq, &oreply), LOCAL_GATEWAY_OK);
}

static void test_no_daily_grant(void)
{
    local_gateway_service_id_t svc;
    local_gateway_audience_t aud;
    local_gateway_session_id_t sess;
    local_gateway_root_id_t root;
    struct local_gateway_req_get_daily dreq;
    struct local_gateway_reply_get_daily dreply;

    local_gateway_reset();
    digest_fill(&svc, 0x40u);
    digest_fill(&aud, 0xA4u);
    digest_fill(&sess, 0x55u);
    digest_fill(&root, 0x94u);

    publish(&svc, &aud, NULL, LOCAL_GATEWAY_GRANT_PROGRESS, 1u, 80000u,
            "publish progress-only");
    open_session(&svc, &sess, &root, LOCAL_GATEWAY_GRANT_PROGRESS, 1u, 100u,
                 "open progress session", LOCAL_GATEWAY_OK);

    memset(&dreq, 0, sizeof(dreq));
    dreq.interface_version = LOCAL_GATEWAY_INTERFACE_VERSION;
    dreq.session_id = sess;
    dreq.authority_epoch = 1u;
    dreq.now_unix_ms = 100u;
    dreq.date_len = 10u;
    dreq.tz_len = 3u;
    memcpy(dreq.date_key, "2026-08-24", 10u);
    memcpy(dreq.tz_key, "UTC", 3u);
    expect_eq_u32("daily without grant",
                  local_gateway_get_daily(&dreq, NULL, 0u, &dreply),
                  LOCAL_GATEWAY_ERR_NO_GRANT);
}

int main(void)
{
    printf("1..?\n");
    test_opcodes();
    test_ambient_denied();
    test_daily_workspace_and_intent();
    test_revoke_blocks_access_and_derivation();
    test_expiry_and_stale_epoch();
    test_no_daily_grant();

    if (g_failures != 0) {
        fprintf(stderr, "%d failures\n", g_failures);
        return 1;
    }
    printf("All local-gateway contract tests passed\n");
    return 0;
}
