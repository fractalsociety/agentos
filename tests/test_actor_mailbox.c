/*
 * fos-gz0.14.7.1 — scoped actor handles and persistent mailboxes (L2 host).
 *
 * Proves: SPAWN/DELEGATE return immediately; child caps/budgets are subsets;
 * causal mailbox delivery; stale and cross-scope handles fail.
 */

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../kernel/fractalos-root-task/include/fractalos.h"
#include "../kernel/fractalos-root-task/include/actor_mailbox.h"

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

static struct actor_agent_handle spawn_root(uint32_t scope, uint64_t caps,
                                            uint64_t budget)
{
    struct actor_req_spawn req;
    struct actor_reply_spawn reply;
    memset(&req, 0, sizeof(req));
    req.interface_version = ACTOR_MAILBOX_INTERFACE_VERSION;
    req.scope = scope;
    req.cap_mask = caps;
    req.budget_units = budget;
    expect_eq_u32("spawn root status", actor_mailbox_spawn(&req, &reply),
                  ACTOR_MAILBOX_OK);
    return reply.agent;
}

static void test_opcodes_versioned(void)
{
    expect_eq_u32("MSG_ACTOR_SPAWN", MSG_ACTOR_SPAWN, 0x3001u);
    expect_eq_u32("MSG_ACTOR_DELEGATE", MSG_ACTOR_DELEGATE, 0x3002u);
    expect_eq_u32("MSG_ACTOR_MAILBOX_DELIVER", MSG_ACTOR_MAILBOX_DELIVER,
                  0x3003u);
    expect_eq_u32("MSG_ACTOR_MAILBOX_POLL", MSG_ACTOR_MAILBOX_POLL, 0x3004u);
    expect_eq_u32("MSG_ACTOR_HANDLE_RESOLVE", MSG_ACTOR_HANDLE_RESOLVE,
                  0x3005u);
    expect_eq_u32("MSG_ACTOR_PASSIVATE", MSG_ACTOR_PASSIVATE, 0x3006u);
    expect_eq_u32("MSG_ACTOR_REACTIVATE", MSG_ACTOR_REACTIVATE, 0x3007u);
    expect_eq_u32("MSG_ACTOR_MEMORY_STATS", MSG_ACTOR_MEMORY_STATS, 0x3008u);
    expect_eq_u32("interface version", ACTOR_MAILBOX_INTERFACE_VERSION, 1u);
}

static void fill_root(uint8_t root[32], uint8_t tag)
{
    memset(root, tag, 32);
}

static void test_passivate_reactivate_preserves_lineage(void)
{
    struct actor_agent_handle agent;
    struct actor_req_mailbox_deliver dreq;
    struct actor_reply_mailbox_deliver dreply;
    struct actor_req_passivate preq;
    struct actor_reply_passivate preply;
    struct actor_req_reactivate rreq;
    struct actor_reply_reactivate rreply;
    struct actor_req_handle_resolve sreq;
    struct actor_reply_handle_resolve sreply;
    uint8_t root[32];
    uint64_t gen_before;
    uint64_t head_before;

    actor_mailbox_reset();
    agent = spawn_root(ACTOR_SCOPE_AGENT, 0xFFu, 50u);

    memset(&dreq, 0, sizeof(dreq));
    dreq.interface_version = ACTOR_MAILBOX_INTERFACE_VERSION;
    dreq.agent = agent;
    dreq.message.sequence = 1u;
    dreq.message.causal_parent = 0u;
    dreq.message.scope = ACTOR_SCOPE_AGENT;
    dreq.message.payload[0] = 0xABCDu;
    expect_eq_u32("seed deliver", actor_mailbox_deliver(&dreq, &dreply),
                  ACTOR_MAILBOX_OK);
    head_before = dreply.accepted_sequence;
    gen_before = agent.generation;

    fill_root(root, 0x42u);
    memset(&preq, 0, sizeof(preq));
    preq.interface_version = ACTOR_MAILBOX_INTERFACE_VERSION;
    preq.agent = agent;
    memcpy(preq.checkpoint_root, root, 32u);
    expect_eq_u32("passivate ok", actor_mailbox_passivate(&preq, &preply),
                  ACTOR_MAILBOX_OK);
    expect_eq_u32("passivate dormant", preply.lifecycle, ACTOR_STATE_DORMANT);
    expect_eq_u32("passivate preserves head", (uint32_t)preply.mailbox_head,
                  (uint32_t)head_before);
    expect_true("released harness bytes",
                preply.resident_bytes_released >= ACTOR_DORMANT_METADATA_BYTES);

    /* Poll while dormant is denied. */
    {
        struct actor_req_mailbox_poll poll_req;
        struct actor_reply_mailbox_poll poll_reply;
        memset(&poll_req, 0, sizeof(poll_req));
        poll_req.interface_version = ACTOR_MAILBOX_INTERFACE_VERSION;
        poll_req.agent = agent;
        expect_eq_u32("poll dormant denied",
                      actor_mailbox_poll(&poll_req, &poll_reply),
                      ACTOR_MAILBOX_ERR_NOT_ACTIVE);
    }

    /* Wrong checkpoint denied. */
    memset(&rreq, 0, sizeof(rreq));
    rreq.interface_version = ACTOR_MAILBOX_INTERFACE_VERSION;
    rreq.agent = agent;
    fill_root(rreq.checkpoint_root, 0x99u);
    rreq.event_token = 7u;
    rreq.quota_units = 1u;
    expect_eq_u32("wrong checkpoint denied",
                  actor_mailbox_reactivate(&rreq, &rreply),
                  ACTOR_MAILBOX_ERR_CHECKPOINT);

    memcpy(rreq.checkpoint_root, root, 32u);
    rreq.quota_units = 0u;
    expect_eq_u32("zero quota denied",
                  actor_mailbox_reactivate(&rreq, &rreply),
                  ACTOR_MAILBOX_ERR_QUOTA);

    rreq.quota_units = 1u;
    rreq.event_token = 0u;
    expect_eq_u32("zero event token denied",
                  actor_mailbox_reactivate(&rreq, &rreply),
                  ACTOR_MAILBOX_ERR_DENIED);

    rreq.event_token = 7u;
    expect_eq_u32("reactivate ok", actor_mailbox_reactivate(&rreq, &rreply),
                  ACTOR_MAILBOX_OK);
    expect_eq_u32("reactivate active", rreply.lifecycle, ACTOR_STATE_ACTIVE);
    expect_eq_u32("lineage head preserved", (uint32_t)rreply.mailbox_head,
                  (uint32_t)head_before);
    expect_eq_u32("lineage generation preserved", (uint32_t)rreply.generation,
                  (uint32_t)gen_before);
    expect_eq_u32("harness restored", (uint32_t)rreply.resident_bytes,
                  ACTOR_ACTIVE_HARNESS_BYTES);

    memset(&sreq, 0, sizeof(sreq));
    sreq.interface_version = ACTOR_MAILBOX_INTERFACE_VERSION;
    sreq.kind = 0u;
    sreq.agent = agent;
    sreq.expected_scope = ACTOR_SCOPE_AGENT;
    expect_eq_u32("resolve after reactivate",
                  actor_mailbox_resolve(&sreq, &sreply), ACTOR_MAILBOX_OK);
    expect_eq_u32("resolve head matches lineage", (uint32_t)sreply.mailbox_head,
                  (uint32_t)head_before);

    /* Next causal deliver continues from preserved head. */
    dreq.message.sequence = head_before + 1u;
    dreq.message.causal_parent = head_before;
    expect_eq_u32("post-reactivate causal deliver",
                  actor_mailbox_deliver(&dreq, &dreply), ACTOR_MAILBOX_OK);
}

static void test_active_frontier_memory_proof(void)
{
    struct actor_agent_handle keep;
    struct actor_agent_handle dormant[8];
    struct actor_req_passivate preq;
    struct actor_reply_passivate preply;
    struct actor_req_memory_stats mreq;
    struct actor_reply_memory_stats mreply;
    uint8_t root[32];
    uint64_t all_active_bytes;
    uint32_t i;

    actor_mailbox_reset();
    keep = spawn_root(ACTOR_SCOPE_AGENT, 0xFFu, 100u);
    for (i = 0u; i < 8u; i++)
        dormant[i] = spawn_root(ACTOR_SCOPE_AGENT, 0x0Fu, 10u);

    memset(&mreq, 0, sizeof(mreq));
    mreq.interface_version = ACTOR_MAILBOX_INTERFACE_VERSION;
    expect_eq_u32("stats all active",
                  actor_mailbox_memory_stats(&mreq, &mreply), ACTOR_MAILBOX_OK);
    expect_eq_u32("9 active", mreply.active_count, 9u);
    expect_eq_u32("0 dormant", mreply.dormant_count, 0u);
    all_active_bytes = mreply.active_resident_bytes;
    expect_true("all-active bytes scale with harness",
                all_active_bytes == 9u * (uint64_t)ACTOR_ACTIVE_HARNESS_BYTES);

    fill_root(root, 0x77u);
    for (i = 0u; i < 8u; i++) {
        memset(&preq, 0, sizeof(preq));
        preq.interface_version = ACTOR_MAILBOX_INTERFACE_VERSION;
        preq.agent = dormant[i];
        root[31] = (uint8_t)(0x10u + i);
        memcpy(preq.checkpoint_root, root, 32u);
        expect_eq_u32("passivate frontier agent",
                      actor_mailbox_passivate(&preq, &preply),
                      ACTOR_MAILBOX_OK);
    }
    (void)keep;

    expect_eq_u32("stats after passivate",
                  actor_mailbox_memory_stats(&mreq, &mreply), ACTOR_MAILBOX_OK);
    expect_eq_u32("1 active remains", mreply.active_count, 1u);
    expect_eq_u32("8 dormant", mreply.dormant_count, 8u);
    expect_eq_u32("active harness only",
                  (uint32_t)mreply.active_resident_bytes,
                  ACTOR_ACTIVE_HARNESS_BYTES);
    expect_eq_u32("dormant metadata only",
                  (uint32_t)mreply.dormant_metadata_bytes,
                  8u * ACTOR_DORMANT_METADATA_BYTES);
    expect_true(
        "frontier much smaller than all-active",
        mreply.frontier_bytes < all_active_bytes
            && mreply.frontier_bytes
                   == (uint64_t)ACTOR_ACTIVE_HARNESS_BYTES
                          + 8u * (uint64_t)ACTOR_DORMANT_METADATA_BYTES);

    /* Zero checkpoint rejected. */
    memset(&preq, 0, sizeof(preq));
    preq.interface_version = ACTOR_MAILBOX_INTERFACE_VERSION;
    preq.agent = keep;
    expect_eq_u32("zero checkpoint denied",
                  actor_mailbox_passivate(&preq, &preply),
                  ACTOR_MAILBOX_ERR_CHECKPOINT);
}

static void test_spawn_delegate_return_immediately(void)
{
    struct actor_agent_handle agent;
    struct actor_req_delegate dreq;
    struct actor_reply_delegate dreply;
    uint32_t agents_before;
    uint32_t tasks_before;

    actor_mailbox_reset();
    agents_before = actor_mailbox_agent_count();
    tasks_before = actor_mailbox_task_count();

    agent = spawn_root(ACTOR_SCOPE_AGENT, 0xFFu, 100u);
    expect_true("spawn allocated agent", actor_mailbox_agent_count()
                                             == agents_before + 1u);
    expect_true("spawn returned non-zero id", agent.id != 0u);

    memset(&dreq, 0, sizeof(dreq));
    dreq.interface_version = ACTOR_MAILBOX_INTERFACE_VERSION;
    dreq.scope = ACTOR_SCOPE_TASK;
    dreq.cap_mask = 0x0Fu;
    dreq.budget_units = 10u;
    dreq.agent = agent;
    expect_eq_u32("delegate status", actor_mailbox_delegate(&dreq, &dreply),
                  ACTOR_MAILBOX_OK);
    expect_true("delegate returned task id", dreply.task.id != 0u);
    expect_true("delegate allocated task",
                actor_mailbox_task_count() == tasks_before + 1u);
    expect_eq_u32("delegate task scope", dreply.task.scope, ACTOR_SCOPE_TASK);
    expect_eq_u32("delegate agent id", (uint32_t)dreply.task.agent_id,
                  (uint32_t)agent.id);
}

static void test_subset_caps_and_budgets(void)
{
    struct actor_agent_handle parent;
    struct actor_req_spawn sreq;
    struct actor_reply_spawn sreply;
    struct actor_req_delegate dreq;
    struct actor_reply_delegate dreply;

    actor_mailbox_reset();
    parent = spawn_root(ACTOR_SCOPE_AGENT, 0x0Fu, 50u);

    memset(&sreq, 0, sizeof(sreq));
    sreq.interface_version = ACTOR_MAILBOX_INTERFACE_VERSION;
    sreq.scope = ACTOR_SCOPE_SESSION;
    sreq.cap_mask = 0xF0u; /* not a subset */
    sreq.budget_units = 10u;
    sreq.parent = parent;
    expect_eq_u32("spawn excess caps denied",
                  actor_mailbox_spawn(&sreq, &sreply), ACTOR_MAILBOX_ERR_CAPS);

    sreq.cap_mask = 0x03u;
    sreq.budget_units = 100u; /* over parent budget */
    expect_eq_u32("spawn excess budget denied",
                  actor_mailbox_spawn(&sreq, &sreply),
                  ACTOR_MAILBOX_ERR_BUDGET);

    sreq.budget_units = 20u;
    expect_eq_u32("spawn subset ok", actor_mailbox_spawn(&sreq, &sreply),
                  ACTOR_MAILBOX_OK);

    memset(&dreq, 0, sizeof(dreq));
    dreq.interface_version = ACTOR_MAILBOX_INTERFACE_VERSION;
    dreq.scope = ACTOR_SCOPE_TASK;
    dreq.cap_mask = 0x10u; /* bit not in parent 0x0F */
    dreq.budget_units = 5u;
    dreq.agent = parent;
    expect_eq_u32("delegate excess caps denied",
                  actor_mailbox_delegate(&dreq, &dreply),
                  ACTOR_MAILBOX_ERR_CAPS);

    dreq.cap_mask = 0x01u;
    dreq.budget_units = 40u; /* parent has 30 remaining after child took 20 */
    expect_eq_u32("delegate excess budget denied",
                  actor_mailbox_delegate(&dreq, &dreply),
                  ACTOR_MAILBOX_ERR_BUDGET);

    dreq.budget_units = 5u;
    expect_eq_u32("delegate subset ok",
                  actor_mailbox_delegate(&dreq, &dreply), ACTOR_MAILBOX_OK);
}

static void test_causal_mailbox_delivery(void)
{
    struct actor_agent_handle agent;
    struct actor_req_mailbox_deliver dreq;
    struct actor_reply_mailbox_deliver dreply;
    struct actor_req_mailbox_poll preq;
    struct actor_reply_mailbox_poll preply;

    actor_mailbox_reset();
    agent = spawn_root(ACTOR_SCOPE_AGENT, 0xFFu, 10u);

    memset(&dreq, 0, sizeof(dreq));
    dreq.interface_version = ACTOR_MAILBOX_INTERFACE_VERSION;
    dreq.agent = agent;
    dreq.message.sequence = 1u;
    dreq.message.causal_parent = 0u;
    dreq.message.scope = ACTOR_SCOPE_AGENT;
    dreq.message.payload[0] = 0xABu;
    expect_eq_u32("deliver seq1", actor_mailbox_deliver(&dreq, &dreply),
                  ACTOR_MAILBOX_OK);
    expect_eq_u32("accepted seq1", (uint32_t)dreply.accepted_sequence, 1u);

    /* Out-of-order / wrong causal parent rejected. */
    dreq.message.sequence = 3u;
    dreq.message.causal_parent = 1u;
    expect_eq_u32("deliver skip denied",
                  actor_mailbox_deliver(&dreq, &dreply),
                  ACTOR_MAILBOX_ERR_CAUSAL);

    dreq.message.sequence = 2u;
    dreq.message.causal_parent = 0u; /* should be 1 */
    expect_eq_u32("deliver bad parent denied",
                  actor_mailbox_deliver(&dreq, &dreply),
                  ACTOR_MAILBOX_ERR_CAUSAL);

    dreq.message.sequence = 2u;
    dreq.message.causal_parent = 1u;
    dreq.message.payload[0] = 0xCDu;
    expect_eq_u32("deliver seq2", actor_mailbox_deliver(&dreq, &dreply),
                  ACTOR_MAILBOX_OK);

    memset(&preq, 0, sizeof(preq));
    preq.interface_version = ACTOR_MAILBOX_INTERFACE_VERSION;
    preq.agent = agent;
    expect_eq_u32("poll first", actor_mailbox_poll(&preq, &preply),
                  ACTOR_MAILBOX_OK);
    expect_eq_u32("poll seq1", (uint32_t)preply.message.sequence, 1u);
    expect_eq_u32("poll payload1", (uint32_t)preply.message.payload[0], 0xABu);

    expect_eq_u32("poll second", actor_mailbox_poll(&preq, &preply),
                  ACTOR_MAILBOX_OK);
    expect_eq_u32("poll seq2", (uint32_t)preply.message.sequence, 2u);

    expect_eq_u32("poll empty", actor_mailbox_poll(&preq, &preply),
                  ACTOR_MAILBOX_ERR_EMPTY);
}

static void test_stale_and_cross_scope_handles(void)
{
    struct actor_agent_handle agent;
    struct actor_agent_handle stale;
    struct actor_req_mailbox_deliver dreq;
    struct actor_reply_mailbox_deliver dreply;
    struct actor_req_spawn sreq;
    struct actor_reply_spawn sreply;
    struct actor_req_handle_resolve rreq;
    struct actor_reply_handle_resolve rreply;
    struct actor_req_delegate treq;
    struct actor_reply_delegate treply;

    actor_mailbox_reset();
    agent = spawn_root(ACTOR_SCOPE_SESSION, 0xFFu, 40u);
    stale = agent;

    expect_eq_u32("bump epoch", actor_mailbox_bump_epoch(agent.id),
                  ACTOR_MAILBOX_OK);

    memset(&dreq, 0, sizeof(dreq));
    dreq.interface_version = ACTOR_MAILBOX_INTERFACE_VERSION;
    dreq.agent = stale;
    dreq.message.sequence = 1u;
    dreq.message.causal_parent = 0u;
    dreq.message.scope = ACTOR_SCOPE_SESSION;
    expect_eq_u32("stale deliver denied",
                  actor_mailbox_deliver(&dreq, &dreply),
                  ACTOR_MAILBOX_ERR_STALE_HANDLE);

    /* Refresh handle via resolve after re-fetching by bump... use spawn child
     * path: re-read by constructing current handle from bump side effects.
     * bump increments generation+epoch; build a fresh handle. */
    agent.generation = stale.generation + 1u;
    agent.authority_epoch = stale.authority_epoch + 1u;

    memset(&sreq, 0, sizeof(sreq));
    sreq.interface_version = ACTOR_MAILBOX_INTERFACE_VERSION;
    sreq.scope = ACTOR_SCOPE_GLOBAL; /* wider than parent session — denied */
    sreq.cap_mask = 0x01u;
    sreq.budget_units = 1u;
    sreq.parent = agent;
    expect_eq_u32("cross-scope wider spawn denied",
                  actor_mailbox_spawn(&sreq, &sreply),
                  ACTOR_MAILBOX_ERR_CROSS_SCOPE);

    memset(&treq, 0, sizeof(treq));
    treq.interface_version = ACTOR_MAILBOX_INTERFACE_VERSION;
    treq.scope = ACTOR_SCOPE_TASK;
    treq.cap_mask = 0x01u;
    treq.budget_units = 1u;
    treq.agent = agent;
    expect_eq_u32("narrow delegate ok",
                  actor_mailbox_delegate(&treq, &treply), ACTOR_MAILBOX_OK);

    memset(&rreq, 0, sizeof(rreq));
    rreq.interface_version = ACTOR_MAILBOX_INTERFACE_VERSION;
    rreq.kind = 1u;
    rreq.task = treply.task;
    rreq.expected_scope = ACTOR_SCOPE_SESSION; /* wrong */
    expect_eq_u32("cross-scope resolve denied",
                  actor_mailbox_resolve(&rreq, &rreply),
                  ACTOR_MAILBOX_ERR_CROSS_SCOPE);

    rreq.expected_scope = ACTOR_SCOPE_TASK;
    expect_eq_u32("resolve task ok", actor_mailbox_resolve(&rreq, &rreply),
                  ACTOR_MAILBOX_OK);

    /* Message scope mismatch against agent scope. */
    dreq.agent = agent;
    dreq.message.sequence = 1u;
    dreq.message.causal_parent = 0u;
    dreq.message.scope = ACTOR_SCOPE_GLOBAL;
    expect_eq_u32("message cross-scope denied",
                  actor_mailbox_deliver(&dreq, &dreply),
                  ACTOR_MAILBOX_ERR_CROSS_SCOPE);
}

int main(void)
{
    printf("1..7\n");
    test_opcodes_versioned();
    test_spawn_delegate_return_immediately();
    test_subset_caps_and_budgets();
    test_causal_mailbox_delivery();
    test_stale_and_cross_scope_handles();
    test_passivate_reactivate_preserves_lineage();
    test_active_frontier_memory_proof();
    if (g_failures != 0) {
        fprintf(stderr, "%d assertion(s) failed\n", g_failures);
        return 1;
    }
    printf("TAP_DONE\n");
    return 0;
}
