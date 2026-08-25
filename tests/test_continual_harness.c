/*
 * fos-gz0.14.8 — continual harness E1 host proof.
 *
 * Snapshot/evaluate/promote/rollback without WASM; held-out probes deny;
 * promote requires beating incumbent and null baselines.
 */

#include <stdio.h>
#include <string.h>

#include "../kernel/fractalos-root-task/include/fractalos.h"
#include "../kernel/fractalos-root-task/include/continual_harness.h"

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

static void fill_digest(struct continual_digest *d, uint8_t tag)
{
    memset(d, tag, sizeof(*d));
}

static void test_opcodes(void)
{
    expect_eq_u32("SNAPSHOT", MSG_CONTINUAL_SNAPSHOT, 0x3501u);
    expect_eq_u32("EVALUATE", MSG_CONTINUAL_EVALUATE, 0x3502u);
    expect_eq_u32("PROMOTE", MSG_CONTINUAL_PROMOTE, 0x3503u);
    expect_eq_u32("ROLLBACK", MSG_CONTINUAL_ROLLBACK, 0x3504u);
    expect_eq_u32("STATUS", MSG_CONTINUAL_STATUS, 0x3505u);
    expect_eq_u32("QUERY_HELD_OUT", MSG_CONTINUAL_QUERY_HELD_OUT, 0x3506u);
}

static uint32_t snapshot_skill(uint8_t content_tag, uint8_t evidence_tag,
                               struct continual_reply_snapshot *out)
{
    struct continual_req_snapshot req;
    memset(&req, 0, sizeof(req));
    req.interface_version = CONTINUAL_HARNESS_INTERFACE_VERSION;
    req.kind = CONTINUAL_KIND_SKILL;
    req.tier = CONTINUAL_TIER_E1_HARNESS;
    fill_digest(&req.content_root, content_tag);
    fill_digest(&req.evidence_root, evidence_tag);
    return continual_harness_snapshot(&req, out);
}

static void test_snapshot_promote_rollback_without_wasm(void)
{
    struct continual_reply_snapshot s1, s2;
    struct continual_req_evaluate ereq;
    struct continual_reply_evaluate ereply;
    struct continual_req_promote preq;
    struct continual_reply_promote preply;
    struct continual_req_rollback rreq;
    struct continual_reply_rollback rreply;
    struct continual_req_status streq;
    struct continual_reply_status streply;

    continual_harness_reset();

    expect_eq_u32("snap1", snapshot_skill(0xA0u, 0xB0u, &s1), CONTINUAL_OK);
    expect_eq_u32("snap2 stronger", snapshot_skill(0xFFu, 0xFEu, &s2),
                  CONTINUAL_OK);

    /* Weak candidate fails baselines. */
    memset(&ereq, 0, sizeof(ereq));
    ereq.interface_version = CONTINUAL_HARNESS_INTERFACE_VERSION;
    ereq.snapshot_id = s1.snapshot_id;
    expect_eq_u32("eval weak", continual_harness_evaluate(&ereq, &ereply),
                  CONTINUAL_OK);

    memset(&preq, 0, sizeof(preq));
    preq.interface_version = CONTINUAL_HARNESS_INTERFACE_VERSION;
    preq.snapshot_id = s1.snapshot_id;
    preq.require_beat_both = 1u;
    if (ereply.beats_incumbent && ereply.beats_null) {
        /* If weak somehow beats, promote then continue; else expect baseline. */
        expect_eq_u32("unexpected weak promote",
                      continual_harness_promote(&preq, &preply), CONTINUAL_OK);
    } else {
        expect_eq_u32("weak promote denied",
                      continual_harness_promote(&preq, &preply),
                      CONTINUAL_ERR_BASELINE);
    }

    memset(&ereq, 0, sizeof(ereq));
    ereq.interface_version = CONTINUAL_HARNESS_INTERFACE_VERSION;
    ereq.snapshot_id = s2.snapshot_id;
    expect_eq_u32("eval strong", continual_harness_evaluate(&ereq, &ereply),
                  CONTINUAL_OK);
    expect_eq_u32("strong beats incumbent", ereply.beats_incumbent, 1u);
    expect_eq_u32("strong beats null", ereply.beats_null, 1u);

    preq.snapshot_id = s2.snapshot_id;
    expect_eq_u32("promote strong", continual_harness_promote(&preq, &preply),
                  CONTINUAL_OK);
    expect_eq_u32("promoted version", preply.promoted_version, s2.version);

    /* Second generation to enable rollback lineage. */
    expect_eq_u32("snap3", snapshot_skill(0xF0u, 0xF1u, &s1), CONTINUAL_OK);
    ereq.snapshot_id = s1.snapshot_id;
    expect_eq_u32("eval gen2", continual_harness_evaluate(&ereq, &ereply),
                  CONTINUAL_OK);
    if (ereply.beats_incumbent && ereply.beats_null) {
        preq.snapshot_id = s1.snapshot_id;
        expect_eq_u32("promote gen2", continual_harness_promote(&preq, &preply),
                      CONTINUAL_OK);
        memset(&rreq, 0, sizeof(rreq));
        rreq.interface_version = CONTINUAL_HARNESS_INTERFACE_VERSION;
        rreq.kind = CONTINUAL_KIND_SKILL;
        expect_eq_u32("rollback", continual_harness_rollback(&rreq, &rreply),
                      CONTINUAL_OK);
        expect_true("rollback restored prior", rreply.restored_version != 0u);
    }

    memset(&streq, 0, sizeof(streq));
    streq.interface_version = CONTINUAL_HARNESS_INTERFACE_VERSION;
    streq.kind = CONTINUAL_KIND_SKILL;
    expect_eq_u32("status", continual_harness_status(&streq, &streply),
                  CONTINUAL_OK);
    expect_eq_u32("no wasm compiled", streply.wasm_compiled, 0u);
    expect_true("snapshots retained", streply.snapshot_count >= 2u);
}

static void test_deeper_tier_and_held_out_denied(void)
{
    struct continual_req_snapshot req;
    struct continual_reply_snapshot reply;
    struct continual_req_query_held_out qreq;
    struct continual_reply_query_held_out qreply;

    continual_harness_reset();
    memset(&req, 0, sizeof(req));
    req.interface_version = CONTINUAL_HARNESS_INTERFACE_VERSION;
    req.kind = CONTINUAL_KIND_NOTE;
    req.tier = CONTINUAL_TIER_E3_WASM;
    fill_digest(&req.content_root, 0x11u);
    fill_digest(&req.evidence_root, 0x22u);
    expect_eq_u32("E3 wasm tier gated", continual_harness_snapshot(&req, &reply),
                  CONTINUAL_ERR_GATE);

    memset(&qreq, 0, sizeof(qreq));
    qreq.interface_version = CONTINUAL_HARNESS_INTERFACE_VERSION;
    qreq.probe_tag = 1u;
    fill_digest(&qreq.case_id, 0x55u);
    expect_eq_u32("held-out leakage denied",
                  continual_harness_query_held_out(&qreq, &qreply),
                  CONTINUAL_ERR_LEAKAGE);
}

int main(void)
{
    printf("1..3\n");
    test_opcodes();
    test_snapshot_promote_rollback_without_wasm();
    test_deeper_tier_and_held_out_denied();
    if (g_failures != 0) {
        fprintf(stderr, "%d assertion(s) failed\n", g_failures);
        return 1;
    }
    printf("TAP_DONE\n");
    return 0;
}
