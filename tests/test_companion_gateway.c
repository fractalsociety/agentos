/*
 * fos-gz0.14.17 — Fractal companion gateway boundary (L2 host).
 *
 * Proves: pinned daily/health/progress/worker-memory projections; audience
 * fence; ungranted mutation / credential canary / stale root / revoke fail
 * closed before dispatch. No HTML/CSS/JS/HTTP server.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../kernel/fractalos-root-task/include/companion_gateway.h"

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

static int digest_eq(const struct local_gateway_digest *a,
                     const struct local_gateway_digest *b)
{
    return memcmp(a->bytes, b->bytes, LOCAL_GATEWAY_DIGEST_BYTES) == 0;
}

static const uint32_t ALL_PROJ_GRANTS =
    LOCAL_GATEWAY_GRANT_DAILY_ROOT | LOCAL_GATEWAY_GRANT_HEALTH |
    LOCAL_GATEWAY_GRANT_PROGRESS | LOCAL_GATEWAY_GRANT_WORKER_MEMORY |
    LOCAL_GATEWAY_GRANT_TASK_INTENT;

static void publish_ok(const local_gateway_service_id_t *svc,
                       const local_gateway_audience_t *aud, uint32_t grants)
{
    struct local_gateway_req_publish_service req;
    struct local_gateway_reply_publish_service reply;

    memset(&req, 0, sizeof(req));
    req.interface_version = LOCAL_GATEWAY_INTERFACE_VERSION;
    req.grant_mask = grants;
    req.service_id = *svc;
    req.audience = *aud;
    req.authority_epoch = 1u;
    req.expires_unix_ms = 100000u;
    digest_fill(&req.effect_ledger_event, 0xE1u);
    expect_eq_u32("publish", companion_gateway_publish_service(&req, &reply),
                  COMPANION_GATEWAY_OK);
}

static void open_ok(const local_gateway_service_id_t *svc,
                    const local_gateway_session_id_t *sess,
                    const local_gateway_root_id_t *root,
                    const local_gateway_audience_t *aud, uint32_t grants)
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
    req.event_range.last_seq = 5u;
    digest_fill(&req.event_range.head, 0xDDu);
    req.authority_epoch = 1u;
    req.now_unix_ms = 1000u;
    expect_eq_u32("open",
                  companion_gateway_open_session(&req, aud, &reply),
                  COMPANION_GATEWAY_OK);
}

static void test_projections_pinned(void)
{
    local_gateway_service_id_t svc;
    local_gateway_audience_t aud;
    local_gateway_session_id_t sess;
    local_gateway_root_id_t root;
    struct local_gateway_req_get_daily dreq;
    struct local_gateway_reply_get_daily dreply;
    struct local_gateway_daily_item items[4];
    struct companion_gateway_health_summary health;
    struct companion_gateway_progress_item progress[4];
    struct companion_gateway_worker_memory mem[4];
    local_gateway_root_id_t out_root;
    struct local_gateway_event_range out_range;
    uint32_t count = 0u;

    companion_gateway_reset();
    digest_fill(&svc, 0x10u);
    digest_fill(&aud, 0xA0u);
    digest_fill(&sess, 0x51u);
    digest_fill(&root, 0x91u);

    publish_ok(&svc, &aud, ALL_PROJ_GRANTS);
    open_ok(&svc, &sess, &root, &aud, ALL_PROJ_GRANTS);

    memset(&dreq, 0, sizeof(dreq));
    dreq.interface_version = LOCAL_GATEWAY_INTERFACE_VERSION;
    dreq.session_id = sess;
    dreq.authority_epoch = 1u;
    dreq.now_unix_ms = 1000u;
    dreq.date_len = 10u;
    dreq.tz_len = 3u;
    memcpy(dreq.date_key, "2026-08-24", 10u);
    memcpy(dreq.tz_key, "UTC", 3u);
    expect_eq_u32("daily",
                  companion_gateway_get_daily(&dreq, &aud, items, 4u, &dreply),
                  COMPANION_GATEWAY_OK);
    expect_true("daily root pin", digest_eq(&dreply.pinned_root, &root));
    expect_eq_u32("daily items", dreply.item_count, 1u);

    expect_eq_u32("health",
                  companion_gateway_get_health(&sess, &aud, 1u, 1000u, &health),
                  COMPANION_GATEWAY_OK);
    expect_true("health root pin",
                digest_eq(&health.provenance_root, &root));
    expect_eq_u32("health signals", health.signal_count, 1u);

    expect_eq_u32("progress",
                  companion_gateway_list_progress(&sess, &aud, 1u, 1000u,
                                                  progress, 4u, &count,
                                                  &out_root, &out_range),
                  COMPANION_GATEWAY_OK);
    expect_eq_u32("progress count", count, 1u);
    expect_true("progress root pin", digest_eq(&out_root, &root));
    expect_eq_u32("progress proof L1", progress[0].proof_level, 1u);

    expect_eq_u32("worker memory",
                  companion_gateway_list_worker_memory(
                      &sess, &aud, 1u, 1000u, mem, 4u, &count, &out_root,
                      &out_range),
                  COMPANION_GATEWAY_OK);
    expect_eq_u32("worker mem count", count, 1u);
    expect_true("dormant << active",
                mem[0].dormant_private_bytes < mem[0].active_private_bytes);
}

static void test_fail_closed(void)
{
    local_gateway_service_id_t svc;
    local_gateway_audience_t aud, wrong;
    local_gateway_session_id_t sess;
    local_gateway_root_id_t root;
    local_gateway_object_id_t subject;
    struct local_gateway_req_open_session oreq;
    struct local_gateway_reply_open_session oreply;
    struct local_gateway_req_submit_intent ireq;
    struct local_gateway_reply_submit_intent ireply;
    struct companion_gateway_health_summary health;
    struct local_gateway_req_revoke_service rreq;
    struct local_gateway_reply_revoke_service rreply;
    const char *cred = "CRED:sk_live_canary";

    companion_gateway_reset();
    digest_fill(&svc, 0x11u);
    digest_fill(&aud, 0xA1u);
    digest_fill(&wrong, 0xA2u);
    digest_fill(&sess, 0x52u);
    digest_fill(&root, 0x92u);
    digest_fill(&subject, 0xB2u);

    publish_ok(&svc, &aud, ALL_PROJ_GRANTS);

    memset(&oreq, 0, sizeof(oreq));
    oreq.interface_version = LOCAL_GATEWAY_INTERFACE_VERSION;
    oreq.grant_mask = ALL_PROJ_GRANTS;
    oreq.service_id = svc;
    oreq.session_id = sess;
    oreq.pinned_root = root;
    oreq.event_range.stream_id = 1u;
    oreq.event_range.first_seq = 1u;
    oreq.event_range.last_seq = 2u;
    digest_fill(&oreq.event_range.head, 0xDEu);
    oreq.authority_epoch = 1u;
    oreq.now_unix_ms = 1000u;
    expect_eq_u32("wrong audience open",
                  companion_gateway_open_session(&oreq, &wrong, &oreply),
                  COMPANION_GATEWAY_ERR_WRONG_AUDIENCE);

    open_ok(&svc, &sess, &root, &aud, ALL_PROJ_GRANTS);

    expect_eq_u32("wrong audience health",
                  companion_gateway_get_health(&sess, &wrong, 1u, 1000u,
                                               &health),
                  COMPANION_GATEWAY_ERR_WRONG_AUDIENCE);

    memset(&ireq, 0, sizeof(ireq));
    ireq.interface_version = LOCAL_GATEWAY_INTERFACE_VERSION;
    ireq.intent_kind = LOCAL_GATEWAY_INTENT_ACKNOWLEDGE;
    ireq.session_id = sess;
    ireq.subject = subject;
    digest_fill(&ireq.expect_root, 0xFFu);
    ireq.authority_epoch = 1u;
    ireq.now_unix_ms = 1000u;
    expect_eq_u32("stale root intent",
                  companion_gateway_submit_intent(&ireq, &aud, &ireply),
                  COMPANION_GATEWAY_ERR_STALE_ROOT);

    ireq.expect_root = root;
    ireq.note_len = (uint32_t)strlen(cred);
    memcpy(ireq.note, cred, ireq.note_len);
    expect_eq_u32("credential canary",
                  companion_gateway_submit_intent(&ireq, &aud, &ireply),
                  COMPANION_GATEWAY_ERR_CREDENTIAL);

    ireq.note_len = 0u;
    expect_eq_u32("clean intent",
                  companion_gateway_submit_intent(&ireq, &aud, &ireply),
                  COMPANION_GATEWAY_OK);

    memset(&rreq, 0, sizeof(rreq));
    rreq.interface_version = LOCAL_GATEWAY_INTERFACE_VERSION;
    rreq.service_id = svc;
    rreq.authority_epoch = 1u;
    digest_fill(&rreq.effect_ledger_event, 0xE2u);
    expect_eq_u32("revoke",
                  companion_gateway_revoke_service(&rreq, &rreply),
                  COMPANION_GATEWAY_OK);
    expect_eq_u32("health after revoke",
                  companion_gateway_get_health(&sess, &aud, 1u, 1000u, &health),
                  COMPANION_GATEWAY_ERR_REVOKED);
}

static void test_ungranted_mutation(void)
{
    local_gateway_service_id_t svc;
    local_gateway_audience_t aud;
    local_gateway_session_id_t sess;
    local_gateway_root_id_t root;
    local_gateway_object_id_t subject;
    struct local_gateway_req_submit_intent ireq;
    struct local_gateway_reply_submit_intent ireply;

    companion_gateway_reset();
    digest_fill(&svc, 0x12u);
    digest_fill(&aud, 0xA3u);
    digest_fill(&sess, 0x53u);
    digest_fill(&root, 0x93u);
    digest_fill(&subject, 0xB3u);

    publish_ok(&svc, &aud, LOCAL_GATEWAY_GRANT_DAILY_ROOT);
    open_ok(&svc, &sess, &root, &aud, LOCAL_GATEWAY_GRANT_DAILY_ROOT);

    memset(&ireq, 0, sizeof(ireq));
    ireq.interface_version = LOCAL_GATEWAY_INTERFACE_VERSION;
    ireq.intent_kind = LOCAL_GATEWAY_INTENT_DEFER;
    ireq.session_id = sess;
    ireq.subject = subject;
    ireq.expect_root = root;
    ireq.authority_epoch = 1u;
    ireq.now_unix_ms = 1000u;
    expect_eq_u32("ungranted intent",
                  companion_gateway_submit_intent(&ireq, &aud, &ireply),
                  COMPANION_GATEWAY_ERR_NO_GRANT);
}

int main(void)
{
    printf("1..?\n");
    test_projections_pinned();
    test_fail_closed();
    test_ungranted_mutation();
    if (g_failures != 0) {
        fprintf(stderr, "%d failures\n", g_failures);
        return 1;
    }
    printf("All companion-gateway boundary tests passed\n");
    return 0;
}
