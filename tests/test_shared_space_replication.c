/*
 * fos-gz0.14.10.3 — immutable shared-space replication + verified merge (L2).
 *
 * Proves: three logical devices converge after online/offline edits; have/want
 * anti-entropy + ingest; hash corruption / stale epoch / missing blocks fail
 * closed; CAS conflict retains both heads (no LWW); verified merge publishes a
 * single root; CRDT merge is forbidden.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../kernel/fractalos-root-task/include/fractalos.h"
#include "../kernel/fractalos-root-task/include/shared_space.h"

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

static void digest_fill(struct shared_space_digest *d, uint8_t seed)
{
    uint32_t i;
    for (i = 0u; i < SHARED_SPACE_DIGEST_BYTES; i++)
        d->bytes[i] = (uint8_t)(seed + i);
}

static void digest_zero(struct shared_space_digest *d)
{
    memset(d, 0, sizeof(*d));
}

static void hash_payload(const uint8_t *payload, uint32_t len,
                         struct shared_space_digest *out)
{
    uint64_t hash = UINT64_C(0xcbf29ce484222325);
    uint32_t i;
    memset(out, 0, sizeof(*out));
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

static int digest_eq(const struct shared_space_digest *a,
                     const struct shared_space_digest *b)
{
    return memcmp(a->bytes, b->bytes, SHARED_SPACE_DIGEST_BYTES) == 0;
}

static uint32_t put_one_chunk(const shared_space_id_t *space,
                              const shared_object_id_t *object_id,
                              const uint8_t *payload, uint32_t len,
                              const char *label)
{
    struct shared_space_req_put_object req;
    struct shared_space_reply_put_object reply;
    struct shared_space_digest hash;

    memset(&req, 0, sizeof(req));
    req.interface_version = SHARED_SPACE_INTERFACE_VERSION;
    req.chunk_index = 0u;
    req.space_id = *space;
    req.object_id = *object_id;
    req.total_chunks = 1u;
    req.chunk_bytes = len;
    hash_payload(payload, len, &hash);
    req.chunk_hash = hash;
    expect_eq_u32(label, shared_space_put_object(&req, payload, &reply),
                  SHARED_SPACE_OK);
    return reply.status;
}

static void create_space(const shared_space_id_t *space,
                         const shared_device_id_t *auth, uint64_t epoch,
                         const char *label)
{
    struct shared_space_req_create req;
    struct shared_space_reply_create reply;

    memset(&req, 0, sizeof(req));
    req.interface_version = SHARED_SPACE_INTERFACE_VERSION;
    req.space_id = *space;
    req.authority_device = *auth;
    req.authority_epoch = epoch;
    expect_eq_u32(label, shared_space_create(&req, &reply), SHARED_SPACE_OK);
}

static void cas_ok(const shared_space_id_t *space,
                   const shared_object_id_t *expected,
                   const shared_object_id_t *proposed, uint64_t epoch,
                   const char *label)
{
    struct shared_space_req_cas_root req;
    struct shared_space_reply_cas_root reply;

    memset(&req, 0, sizeof(req));
    req.interface_version = SHARED_SPACE_INTERFACE_VERSION;
    req.space_id = *space;
    if (expected != NULL)
        req.expected_root = *expected;
    req.proposed_root = *proposed;
    digest_fill(&req.shared_event_head, 0xE0u);
    req.authority_epoch = epoch;
    digest_fill(&req.verify_evidence, 0xBEu);
    expect_eq_u32(label, shared_space_cas_root(&req, &reply), SHARED_SPACE_OK);
    expect_eq_u32("cas head_count=1", reply.head_count, 1u);
}

static void test_opcodes(void)
{
    expect_eq_u32("MSG_SHARED_SPACE_CREATE", MSG_SHARED_SPACE_CREATE, 0x3301u);
    expect_eq_u32("MSG_SHARED_SPACE_PUT_OBJECT", MSG_SHARED_SPACE_PUT_OBJECT,
                  0x3302u);
    expect_eq_u32("MSG_SHARED_SPACE_GET_OBJECT", MSG_SHARED_SPACE_GET_OBJECT,
                  0x3303u);
    expect_eq_u32("MSG_SHARED_SPACE_HAVE_WANT", MSG_SHARED_SPACE_HAVE_WANT,
                  0x3304u);
    expect_eq_u32("MSG_SHARED_SPACE_CAS_ROOT", MSG_SHARED_SPACE_CAS_ROOT,
                  0x3305u);
    expect_eq_u32("MSG_SHARED_SPACE_BRANCH", MSG_SHARED_SPACE_BRANCH, 0x3306u);
    expect_eq_u32("MSG_SHARED_SPACE_MERGE", MSG_SHARED_SPACE_MERGE, 0x3307u);
    expect_eq_u32("MSG_SHARED_SPACE_STATUS", MSG_SHARED_SPACE_STATUS, 0x3308u);
    expect_eq_u32("interface version", SHARED_SPACE_INTERFACE_VERSION, 1u);
}

static void test_hash_corruption_and_resume(void)
{
    shared_space_id_t space;
    shared_device_id_t auth;
    shared_object_id_t obj;
    uint8_t payload[16];
    struct shared_space_req_put_object req;
    struct shared_space_reply_put_object reply;
    struct shared_space_digest good_hash;

    shared_space_reset();
    digest_fill(&space, 0x10u);
    digest_fill(&auth, 0xA1u);
    digest_fill(&obj, 0x20u);
    memset(payload, 0x42, sizeof(payload));
    create_space(&space, &auth, 1u, "create for hash tests");

    memset(&req, 0, sizeof(req));
    req.interface_version = SHARED_SPACE_INTERFACE_VERSION;
    req.chunk_index = 0u;
    req.space_id = space;
    req.object_id = obj;
    req.total_chunks = 1u;
    req.chunk_bytes = (uint32_t)sizeof(payload);
    hash_payload(payload, (uint32_t)sizeof(payload), &good_hash);
    digest_fill(&req.chunk_hash, 0xFFu); /* wrong hash */
    expect_eq_u32("hash corruption rejected",
                  shared_space_put_object(&req, payload, &reply),
                  SHARED_SPACE_ERR_HASH_MISMATCH);

    req.chunk_hash = good_hash;
    expect_eq_u32("put after fix",
                  shared_space_put_object(&req, payload, &reply),
                  SHARED_SPACE_OK);
    expect_eq_u32("chunks_stored=1", reply.chunks_stored, 1u);

    /* Idempotent resume of same chunk. */
    expect_eq_u32("resume put ok",
                  shared_space_put_object(&req, payload, &reply),
                  SHARED_SPACE_OK);
    expect_eq_u32("resume still 1 chunk", reply.chunks_stored, 1u);
}

static void test_stale_epoch_and_no_evidence(void)
{
    shared_space_id_t space;
    shared_device_id_t auth;
    shared_object_id_t root;
    uint8_t payload[8];
    struct shared_space_req_cas_root req;
    struct shared_space_reply_cas_root reply;

    shared_space_reset();
    digest_fill(&space, 0x11u);
    digest_fill(&auth, 0xA2u);
    digest_fill(&root, 0x21u);
    memset(payload, 0x11, sizeof(payload));
    create_space(&space, &auth, 5u, "create epoch 5");
    put_one_chunk(&space, &root, payload, (uint32_t)sizeof(payload),
                  "put root obj");

    memset(&req, 0, sizeof(req));
    req.interface_version = SHARED_SPACE_INTERFACE_VERSION;
    req.space_id = space;
    digest_zero(&req.expected_root);
    req.proposed_root = root;
    digest_fill(&req.shared_event_head, 0xE1u);
    req.authority_epoch = 5u;
    digest_zero(&req.verify_evidence);
    expect_eq_u32("CAS no evidence", shared_space_cas_root(&req, &reply),
                  SHARED_SPACE_ERR_NO_EVIDENCE);

    digest_fill(&req.verify_evidence, 0xBEu);
    req.authority_epoch = 4u;
    expect_eq_u32("CAS stale epoch", shared_space_cas_root(&req, &reply),
                  SHARED_SPACE_ERR_STALE_EPOCH);

    req.authority_epoch = 5u;
    expect_eq_u32("CAS fresh epoch", shared_space_cas_root(&req, &reply),
                  SHARED_SPACE_OK);
}

static void test_have_want_three_devices(void)
{
    shared_space_id_t space;
    shared_device_id_t dev_a, dev_b, dev_c;
    shared_object_id_t obj_a, obj_b, obj_c;
    uint8_t pa[4], pb[4], pc[4];
    shared_object_id_t have[2];
    shared_object_id_t want[2];
    struct shared_space_req_have_want hw;
    struct shared_space_reply_have_want hwr;
    struct shared_space_req_get_object greq;
    struct shared_space_reply_get_object greply;
    uint8_t out[8];

    shared_space_reset();
    digest_fill(&space, 0x12u);
    digest_fill(&dev_a, 0xD1u);
    digest_fill(&dev_b, 0xD2u);
    digest_fill(&dev_c, 0xD3u);
    digest_fill(&obj_a, 0x31u);
    digest_fill(&obj_b, 0x32u);
    digest_fill(&obj_c, 0x33u);
    memset(pa, 0xAAu, sizeof(pa));
    memset(pb, 0xBBu, sizeof(pb));
    memset(pc, 0xCCu, sizeof(pc));

    create_space(&space, &dev_a, 1u, "create three-device space");
    put_one_chunk(&space, &obj_a, pa, (uint32_t)sizeof(pa), "put obj_a");
    put_one_chunk(&space, &obj_b, pb, (uint32_t)sizeof(pb), "put obj_b");
    put_one_chunk(&space, &obj_c, pc, (uint32_t)sizeof(pc), "put obj_c");

    /* Device A already has obj_a; wants obj_b. */
    expect_eq_u32("A ingest a", shared_space_device_ingest(&dev_a, &obj_a),
                  SHARED_SPACE_OK);

    memset(&hw, 0, sizeof(hw));
    hw.interface_version = SHARED_SPACE_INTERFACE_VERSION;
    hw.have_count = 1u;
    hw.want_count = 1u;
    hw.space_id = space;
    hw.from_device = dev_a;
    have[0] = obj_a;
    want[0] = obj_b;
    expect_eq_u32("A have/want",
                  shared_space_have_want(&hw, have, want, &hwr),
                  SHARED_SPACE_OK);
    expect_eq_u32("A missing obj_b", hwr.missing_count, 1u);
    expect_eq_u32("A duplicate obj_a", hwr.duplicate_count, 1u);

    expect_eq_u32("A ingest b", shared_space_device_ingest(&dev_a, &obj_b),
                  SHARED_SPACE_OK);
    expect_eq_u32("A have/want after ingest",
                  shared_space_have_want(&hw, have, want, &hwr),
                  SHARED_SPACE_OK);
    expect_eq_u32("A no longer missing b", hwr.missing_count, 0u);

    /* Device B learns via have announcement of obj_b then wants obj_c. */
    memset(&hw, 0, sizeof(hw));
    hw.interface_version = SHARED_SPACE_INTERFACE_VERSION;
    hw.have_count = 1u;
    hw.want_count = 1u;
    hw.space_id = space;
    hw.from_device = dev_b;
    have[0] = obj_b;
    want[0] = obj_c;
    expect_eq_u32("B have/want",
                  shared_space_have_want(&hw, have, want, &hwr),
                  SHARED_SPACE_OK);
    expect_eq_u32("B missing c", hwr.missing_count, 1u);
    expect_eq_u32("B ingest c", shared_space_device_ingest(&dev_b, &obj_c),
                  SHARED_SPACE_OK);

    /* Device C wants both a and b; ingest closes missing. */
    memset(&hw, 0, sizeof(hw));
    hw.interface_version = SHARED_SPACE_INTERFACE_VERSION;
    hw.have_count = 0u;
    hw.want_count = 2u;
    hw.space_id = space;
    hw.from_device = dev_c;
    want[0] = obj_a;
    want[1] = obj_b;
    expect_eq_u32("C have/want before",
                  shared_space_have_want(&hw, NULL, want, &hwr),
                  SHARED_SPACE_OK);
    expect_eq_u32("C missing 2", hwr.missing_count, 2u);
    expect_eq_u32("C ingest a", shared_space_device_ingest(&dev_c, &obj_a),
                  SHARED_SPACE_OK);
    expect_eq_u32("C ingest b", shared_space_device_ingest(&dev_c, &obj_b),
                  SHARED_SPACE_OK);
    expect_eq_u32("C have/want after",
                  shared_space_have_want(&hw, NULL, want, &hwr),
                  SHARED_SPACE_OK);
    expect_eq_u32("C converged", hwr.missing_count, 0u);

    /* Global store still serves get for all three objects (dedupe). */
    memset(&greq, 0, sizeof(greq));
    greq.interface_version = SHARED_SPACE_INTERFACE_VERSION;
    greq.chunk_index = 0u;
    greq.space_id = space;
    greq.object_id = obj_a;
    expect_eq_u32("get obj_a",
                  shared_space_get_object(&greq, out, (uint32_t)sizeof(out),
                                         &greply),
                  SHARED_SPACE_OK);
    expect_true("payload a", memcmp(out, pa, sizeof(pa)) == 0);
    expect_eq_u32("object count 3", shared_space_object_count(), 3u);
}

static void test_cas_conflict_retain_both(void)
{
    shared_space_id_t space;
    shared_device_id_t auth;
    shared_object_id_t root1, root2, root3;
    uint8_t p1[4], p2[4], p3[4];
    struct shared_space_req_cas_root req;
    struct shared_space_reply_cas_root reply;
    struct shared_space_req_status sreq;
    struct shared_space_reply_status sreply;

    shared_space_reset();
    digest_fill(&space, 0x13u);
    digest_fill(&auth, 0xA3u);
    digest_fill(&root1, 0x41u);
    digest_fill(&root2, 0x42u);
    digest_fill(&root3, 0x43u);
    memset(p1, 1, sizeof(p1));
    memset(p2, 2, sizeof(p2));
    memset(p3, 3, sizeof(p3));

    create_space(&space, &auth, 1u, "create cas space");
    put_one_chunk(&space, &root1, p1, (uint32_t)sizeof(p1), "put root1");
    put_one_chunk(&space, &root2, p2, (uint32_t)sizeof(p2), "put root2");
    put_one_chunk(&space, &root3, p3, (uint32_t)sizeof(p3), "put root3");

    cas_ok(&space, NULL, &root1, 1u, "CAS first root");

    /* Successful advance root1 -> root2. */
    cas_ok(&space, &root1, &root2, 1u, "CAS advance to root2");

    /* Stale expected (root1) proposing root3 → conflict, retain both heads. */
    memset(&req, 0, sizeof(req));
    req.interface_version = SHARED_SPACE_INTERFACE_VERSION;
    req.space_id = space;
    req.expected_root = root1;
    req.proposed_root = root3;
    digest_fill(&req.shared_event_head, 0xE2u);
    req.authority_epoch = 1u;
    digest_fill(&req.verify_evidence, 0xBEu);
    expect_eq_u32("CAS conflict", shared_space_cas_root(&req, &reply),
                  SHARED_SPACE_ERR_CAS_CONFLICT);
    expect_true("conflict head_count>=2", reply.head_count >= 2u);
    expect_true("current still root2 (no LWW)",
                digest_eq(&reply.record.current_root, &root2));

    memset(&sreq, 0, sizeof(sreq));
    sreq.interface_version = SHARED_SPACE_INTERFACE_VERSION;
    sreq.space_id = space;
    expect_eq_u32("status after conflict",
                  shared_space_status(&sreq, &sreply), SHARED_SPACE_OK);
    expect_true("status dual heads", sreply.record.head_count >= 2u);
    expect_true("heads include root2",
                digest_eq(&sreply.record.heads[0], &root2) ||
                    digest_eq(&sreply.record.heads[1], &root2));
    expect_true("heads include root3",
                digest_eq(&sreply.record.heads[0], &root3) ||
                    digest_eq(&sreply.record.heads[1], &root3));
}

static void test_offline_branch_and_verified_merge(void)
{
    shared_space_id_t space;
    shared_device_id_t online, offline;
    shared_object_id_t base, branch, merged;
    uint8_t pb[4], pbr[4], pm[4];
    struct shared_space_req_branch breq;
    struct shared_space_reply_branch breply;
    struct shared_space_req_merge mreq;
    struct shared_space_reply_merge mreply;

    shared_space_reset();
    digest_fill(&space, 0x14u);
    digest_fill(&online, 0xDAu);
    digest_fill(&offline, 0xDBu);
    digest_fill(&base, 0x51u);
    digest_fill(&branch, 0x52u);
    digest_fill(&merged, 0x53u);
    memset(pb, 0x10, sizeof(pb));
    memset(pbr, 0x20, sizeof(pbr));
    memset(pm, 0x30, sizeof(pm));

    create_space(&space, &online, 2u, "create merge space");
    put_one_chunk(&space, &base, pb, (uint32_t)sizeof(pb), "put base");
    put_one_chunk(&space, &branch, pbr, (uint32_t)sizeof(pbr), "put branch");
    put_one_chunk(&space, &merged, pm, (uint32_t)sizeof(pm), "put merged");

    cas_ok(&space, NULL, &base, 2u, "CAS base root");

    /* Offline device publishes divergent tip from base (lagging epoch ok). */
    memset(&breq, 0, sizeof(breq));
    breq.interface_version = SHARED_SPACE_INTERFACE_VERSION;
    breq.space_id = space;
    breq.device_id = offline;
    breq.base_root = base;
    breq.branch_root = branch;
    breq.authority_epoch = 1u; /* lagging offline epoch */
    expect_eq_u32("offline branch", shared_space_branch(&breq, &breply),
                  SHARED_SPACE_OK);
    expect_true("branch dual heads", breply.record.head_count >= 2u);

    /* CRDT policy forbidden. */
    memset(&mreq, 0, sizeof(mreq));
    mreq.interface_version = SHARED_SPACE_INTERFACE_VERSION;
    mreq.policy = SHARED_SPACE_MERGE_CRDT;
    mreq.space_id = space;
    mreq.head_a = base;
    mreq.head_b = branch;
    mreq.merged_root = merged;
    mreq.authority_epoch = 2u;
    digest_fill(&mreq.verify_evidence, 0xBEu);
    expect_eq_u32("CRDT forbidden", shared_space_merge(&mreq, &mreply),
                  SHARED_SPACE_ERR_CRDT_FORBIDDEN);

    /* Verified merge without evidence fails. */
    mreq.policy = SHARED_SPACE_MERGE_VERIFIED;
    digest_zero(&mreq.verify_evidence);
    expect_eq_u32("merge no evidence", shared_space_merge(&mreq, &mreply),
                  SHARED_SPACE_ERR_NO_EVIDENCE);

    /* Verified merge with evidence publishes single root. */
    digest_fill(&mreq.verify_evidence, 0xBEu);
    expect_eq_u32("verified merge", shared_space_merge(&mreq, &mreply),
                  SHARED_SPACE_OK);
    expect_eq_u32("merged head_count", mreply.head_count, 1u);
    expect_true("merged current root",
                digest_eq(&mreply.record.current_root, &merged));

    /* RETAIN_BOTH leaves heads when called on a fresh conflict. */
    {
        shared_object_id_t other;
        uint8_t po[4];
        digest_fill(&other, 0x54u);
        memset(po, 0x40, sizeof(po));
        put_one_chunk(&space, &other, po, (uint32_t)sizeof(po), "put other");

        memset(&breq, 0, sizeof(breq));
        breq.interface_version = SHARED_SPACE_INTERFACE_VERSION;
        breq.space_id = space;
        breq.device_id = offline;
        breq.base_root = merged;
        breq.branch_root = other;
        breq.authority_epoch = 2u;
        expect_eq_u32("second branch", shared_space_branch(&breq, &breply),
                      SHARED_SPACE_OK);

        memset(&mreq, 0, sizeof(mreq));
        mreq.interface_version = SHARED_SPACE_INTERFACE_VERSION;
        mreq.policy = SHARED_SPACE_MERGE_RETAIN_BOTH;
        mreq.space_id = space;
        mreq.head_a = merged;
        mreq.head_b = other;
        mreq.authority_epoch = 2u;
        expect_eq_u32("retain both", shared_space_merge(&mreq, &mreply),
                      SHARED_SPACE_OK);
        expect_true("retain head_count>=2", mreply.head_count >= 2u);
    }
}

static void test_missing_block(void)
{
    shared_space_id_t space;
    shared_device_id_t auth;
    shared_object_id_t missing;
    struct shared_space_req_get_object greq;
    struct shared_space_reply_get_object greply;
    struct shared_space_req_cas_root creq;
    struct shared_space_reply_cas_root creply;
    uint8_t out[8];

    shared_space_reset();
    digest_fill(&space, 0x15u);
    digest_fill(&auth, 0xA5u);
    digest_fill(&missing, 0x99u);
    create_space(&space, &auth, 1u, "create missing-block space");

    memset(&greq, 0, sizeof(greq));
    greq.interface_version = SHARED_SPACE_INTERFACE_VERSION;
    greq.space_id = space;
    greq.object_id = missing;
    expect_eq_u32("get missing",
                  shared_space_get_object(&greq, out, (uint32_t)sizeof(out),
                                         &greply),
                  SHARED_SPACE_ERR_MISSING_BLOCK);

    memset(&creq, 0, sizeof(creq));
    creq.interface_version = SHARED_SPACE_INTERFACE_VERSION;
    creq.space_id = space;
    creq.proposed_root = missing;
    creq.authority_epoch = 1u;
    digest_fill(&creq.verify_evidence, 0xBEu);
    expect_eq_u32("CAS missing block", shared_space_cas_root(&creq, &creply),
                  SHARED_SPACE_ERR_MISSING_BLOCK);
}

int main(void)
{
    printf("1..?\n");
    test_opcodes();
    test_hash_corruption_and_resume();
    test_stale_epoch_and_no_evidence();
    test_have_want_three_devices();
    test_cas_conflict_retain_both();
    test_offline_branch_and_verified_merge();
    test_missing_block();

    if (g_failures != 0) {
        fprintf(stderr, "%d failures\n", g_failures);
        return 1;
    }
    printf("All shared-space replication tests passed\n");
    return 0;
}
