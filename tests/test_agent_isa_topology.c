/*
 * fos-gz0.14.1.3 — dispatcher topology + async flow proof (L2 host).
 *
 * Proves: submit returns before completion; CHECKPOINT→DELEGATE→WAIT→
 * VERIFY→COMMIT; failure→RESTORE; revocation cancels; no forged completion.
 * Same freestanding C suite is the portable proof for aarch64 and x86_64
 * host builds (architecture-neutral wire + mailbox semantics).
 */

#include <stdio.h>
#include <string.h>

#include "../kernel/fractalos-root-task/include/agent_isa.h"
#include "../kernel/fractalos-root-task/include/agent_isa_dispatch.h"
#include "../kernel/fractalos-root-task/include/agent_isa_topology.h"

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

static agent_object_id_t oid(const char *s)
{
    agent_object_id_t id;
    agent_isa_object_id_from_bytes(s, (uint32_t)strlen(s), &id);
    return id;
}

static uint32_t all_caps(void)
{
    return AGENT_ISA_CAP_KNOWN_MASK;
}

static void test_submit_before_completion_and_no_forge(void)
{
    agent_isa_topology_t topo;
    agent_object_id_t capset = oid("capset");
    agent_object_id_t env = oid("env");
    agent_object_id_t initial = oid("initial");
    agent_object_id_t objective = oid("objective");
    agent_object_id_t workspace = oid("workspace");
    struct agent_isa_reply_submit submit;
    struct agent_isa_reply_wait waited;
    const uint64_t owner = UINT64_C(0x26000100000042);
    const uint64_t dispatcher = UINT64_C(0x27000100000001);

    agent_isa_topology_init(&topo, owner, dispatcher, 3u, all_caps(), 64u,
                            &capset, &env, &initial);
    expect_eq_u32("install adapters",
                  agent_isa_topology_install_default_adapters(&topo),
                  AGENT_ISA_TOPOLOGY_OK);

    expect_eq_u32(
        "async submit",
        agent_isa_topology_submit_async(&topo, AGENT_ISA_OP_DELEGATE,
                                        AGENT_ISA_CAP_CONTROL, &objective,
                                        &workspace, &submit),
        AGENT_ISA_TOPOLOGY_OK);
    expect_eq_u32("returns pending", submit.ticket_state,
                  AGENT_ISA_TICKET_PENDING);
    expect_eq_u32("wait before pump still pending",
                  agent_isa_topology_wait(&topo, submit.ticket_id, &waited),
                  AGENT_ISA_TOPOLOGY_OK);
    expect_eq_u32("still pending", waited.ticket_state,
                  AGENT_ISA_TICKET_PENDING);

    /* Owner cannot forge completion on the mailbox. */
    {
        struct agent_isa_dispatch_req_complete creq;
        uint32_t slot = 0u;
        struct agent_isa_dispatch_record taken;
        expect_eq_u32("take for forge test",
                      agent_isa_dispatch_take(&topo.mailbox, &slot, &taken),
                      AGENT_ISA_DISPATCH_OK);
        memset(&creq, 0, sizeof(creq));
        creq.interface_version = AGENT_ISA_DISPATCH_INTERFACE_VERSION;
        creq.ticket_id = taken.ticket_id;
        creq.authority_epoch = taken.authority_epoch;
        creq.dispatch_nonce = taken.dispatch_nonce;
        creq.backend_status = AGENT_ISA_DISPATCH_BACKEND_OK;
        creq.result_root = oid("forged");
        expect_eq_u32(
            "forged completion denied",
            agent_isa_dispatch_complete(&topo.mailbox, owner, dispatcher,
                                        &creq),
            AGENT_ISA_DISPATCH_ERR_FORGED);
        /* Trusted complete so mailbox is consistent, then finish runtime. */
        expect_eq_u32(
            "trusted complete after forge deny",
            agent_isa_dispatch_complete(&topo.mailbox, dispatcher, dispatcher,
                                        &creq),
            AGENT_ISA_DISPATCH_OK);
        expect_eq_u32(
            "runtime complete",
            agent_isa_runtime_complete(&topo.runtime, taken.ticket_id,
                                       &creq.result_root, true),
            AGENT_ISA_OK);
        topo.has_pending_dispatch = 0;
    }
}

static void test_checkpoint_delegate_wait_verify_commit(void)
{
    agent_isa_topology_t topo;
    agent_object_id_t capset = oid("capset");
    agent_object_id_t env = oid("env");
    agent_object_id_t initial = oid("initial-state");
    agent_object_id_t objective = oid("fix-me");
    agent_object_id_t workspace = oid("ws");
    agent_object_id_t verifier = oid("verifier");
    struct agent_isa_req_submit sreq;
    struct agent_isa_reply_submit submit;
    struct agent_isa_reply_wait waited;
    agent_object_id_t checkpoint;
    const uint64_t owner = UINT64_C(0x42);
    const uint64_t dispatcher = UINT64_C(0x99);

    agent_isa_topology_init(&topo, owner, dispatcher, 1u, all_caps(), 64u,
                            &capset, &env, &initial);
    expect_eq_u32("adapters", agent_isa_topology_install_default_adapters(&topo),
                  AGENT_ISA_TOPOLOGY_OK);

    memset(&sreq, 0, sizeof(sreq));
    sreq.interface_version = AGENT_ISA_INTERFACE_VERSION;
    sreq.operation = AGENT_ISA_OP_CHECKPOINT;
    sreq.declared_caps = AGENT_ISA_CAP_OBJECT;
    sreq.budget_units = 1u;
    expect_eq_u32("CHECKPOINT",
                  agent_isa_runtime_submit(&topo.runtime, &sreq, &submit),
                  AGENT_ISA_OK);
    checkpoint = submit.state_root;

    expect_eq_u32(
        "DELEGATE async",
        agent_isa_topology_submit_async(&topo, AGENT_ISA_OP_DELEGATE,
                                        AGENT_ISA_CAP_CONTROL, &objective,
                                        &checkpoint, &submit),
        AGENT_ISA_TOPOLOGY_OK);
    expect_eq_u32("pump DELEGATE", agent_isa_topology_pump(&topo),
                  AGENT_ISA_TOPOLOGY_OK);
    expect_eq_u32("WAIT DELEGATE",
                  agent_isa_topology_wait(&topo, submit.ticket_id, &waited),
                  AGENT_ISA_TOPOLOGY_OK);
    expect_eq_u32("DELEGATE complete", waited.ticket_state,
                  AGENT_ISA_TICKET_COMPLETE);

    expect_eq_u32(
        "VERIFY async",
        agent_isa_topology_submit_async(&topo, AGENT_ISA_OP_VERIFY,
                                        AGENT_ISA_CAP_VERIFY,
                                        &waited.result_root, &verifier,
                                        &submit),
        AGENT_ISA_TOPOLOGY_OK);
    expect_eq_u32("pump VERIFY", agent_isa_topology_pump(&topo),
                  AGENT_ISA_TOPOLOGY_OK);
    expect_eq_u32("WAIT VERIFY",
                  agent_isa_topology_wait(&topo, submit.ticket_id, &waited),
                  AGENT_ISA_TOPOLOGY_OK);
    expect_eq_u32("VERIFY complete", waited.ticket_state,
                  AGENT_ISA_TICKET_COMPLETE);

    memset(&sreq, 0, sizeof(sreq));
    sreq.interface_version = AGENT_ISA_INTERFACE_VERSION;
    sreq.operation = AGENT_ISA_OP_COMMIT;
    sreq.declared_caps = AGENT_ISA_CAP_COMMIT;
    sreq.budget_units = 1u;
    sreq.input_root = waited.result_root;
    sreq.operand_root = waited.result_root;
    /* COMMIT needs candidate + evidence from verification path; use results. */
    sreq.input_root = oid("candidate-change");
    /* After VERIFY success, runtime may hold verification_ready — use
     * the verified result as evidence operand like runtime tests. */
    sreq.operand_root = waited.result_root;
    /* Re-run VERIFY completion path using runtime objects from earlier flow:
     * the topology VERIFY already completed; commit needs verification_ready. */
    {
        /* Seed verification the same way as agent_isa_runtime tests. */
        agent_object_id_t candidate = oid("candidate-change");
        agent_object_id_t verified = waited.result_root;
        sreq.input_root = candidate;
        sreq.operand_root = verified;
        uint32_t st = agent_isa_runtime_submit(&topo.runtime, &sreq, &submit);
        /* If verification_ready not set for this candidate, accept STATE and
         * re-drive VERIFY on candidate then COMMIT. */
        if (st == AGENT_ISA_ERR_STATE) {
            expect_eq_u32(
                "VERIFY candidate",
                agent_isa_topology_submit_async(&topo, AGENT_ISA_OP_VERIFY,
                                                AGENT_ISA_CAP_VERIFY,
                                                &candidate, &verifier,
                                                &submit),
                AGENT_ISA_TOPOLOGY_OK);
            expect_eq_u32("pump VERIFY2", agent_isa_topology_pump(&topo),
                          AGENT_ISA_TOPOLOGY_OK);
            expect_eq_u32(
                "WAIT VERIFY2",
                agent_isa_topology_wait(&topo, submit.ticket_id, &waited),
                AGENT_ISA_TOPOLOGY_OK);
            sreq.operand_root = waited.result_root;
            st = agent_isa_runtime_submit(&topo.runtime, &sreq, &submit);
        }
        expect_eq_u32("COMMIT", st, AGENT_ISA_OK);
        expect_eq_u32("COMMIT terminal", submit.ticket_state,
                      AGENT_ISA_TICKET_COMPLETE);
        expect_true("COMMIT moved state",
                    !agent_object_id_equal(&submit.state_root, &checkpoint));
        (void)workspace;
    }
}

static void test_failure_restore(void)
{
    agent_isa_runtime_t runtime;
    agent_object_id_t capset = oid("capset");
    agent_object_id_t env = oid("env");
    agent_object_id_t initial = oid("initial");
    agent_object_id_t candidate = oid("candidate");
    agent_object_id_t verifier = oid("verifier");
    agent_object_id_t failed = oid("verify-fail");
    struct agent_isa_req_submit sreq;
    struct agent_isa_reply_submit submit;

    agent_isa_runtime_init(&runtime, all_caps(), 1u, &capset, &env, &initial,
                           32u);
    memset(&sreq, 0, sizeof(sreq));
    sreq.interface_version = AGENT_ISA_INTERFACE_VERSION;
    sreq.operation = AGENT_ISA_OP_VERIFY;
    sreq.flags = AGENT_ISA_FLAG_ASYNC;
    sreq.declared_caps = AGENT_ISA_CAP_VERIFY;
    sreq.budget_units = 1u;
    sreq.input_root = candidate;
    sreq.operand_root = verifier;
    expect_eq_u32("VERIFY submit",
                  agent_isa_runtime_submit(&runtime, &sreq, &submit),
                  AGENT_ISA_OK);
    expect_eq_u32("VERIFY fail complete",
                  agent_isa_runtime_complete(&runtime, submit.ticket_id,
                                             &failed, false),
                  AGENT_ISA_OK);

    memset(&sreq, 0, sizeof(sreq));
    sreq.interface_version = AGENT_ISA_INTERFACE_VERSION;
    sreq.operation = AGENT_ISA_OP_RESTORE;
    sreq.declared_caps = AGENT_ISA_CAP_OBJECT;
    sreq.budget_units = 1u;
    sreq.input_root = initial;
    expect_eq_u32("RESTORE",
                  agent_isa_runtime_submit(&runtime, &sreq, &submit),
                  AGENT_ISA_OK);
    expect_true("restored initial",
                agent_object_id_equal(&submit.state_root, &initial));
}

static void test_revocation_cancels(void)
{
    agent_isa_topology_t topo;
    agent_object_id_t capset = oid("capset");
    agent_object_id_t env = oid("env");
    agent_object_id_t initial = oid("initial");
    agent_object_id_t objective = oid("obj");
    agent_object_id_t workspace = oid("ws");
    struct agent_isa_reply_submit submit;
    struct agent_isa_reply_wait waited;
    const uint64_t owner = UINT64_C(0x11);
    const uint64_t dispatcher = UINT64_C(0x22);

    agent_isa_topology_init(&topo, owner, dispatcher, 5u, all_caps(), 32u,
                            &capset, &env, &initial);
    expect_eq_u32("adapters", agent_isa_topology_install_default_adapters(&topo),
                  AGENT_ISA_TOPOLOGY_OK);
    expect_eq_u32(
        "enqueue",
        agent_isa_topology_submit_async(&topo, AGENT_ISA_OP_DELEGATE,
                                        AGENT_ISA_CAP_CONTROL, &objective,
                                        &workspace, &submit),
        AGENT_ISA_TOPOLOGY_OK);
    expect_eq_u32("revoke", agent_isa_topology_revoke(&topo),
                  AGENT_ISA_TOPOLOGY_OK);
    expect_eq_u32("pump empty after revoke", agent_isa_topology_pump(&topo),
                  AGENT_ISA_TOPOLOGY_ERR_EMPTY);
    expect_eq_u32("wait cancelled",
                  agent_isa_topology_wait(&topo, submit.ticket_id, &waited),
                  AGENT_ISA_TOPOLOGY_OK);
    expect_eq_u32("ticket cancelled", waited.ticket_state,
                  AGENT_ISA_TICKET_CANCELLED);
}

int main(void)
{
    printf("1..4\n");
    test_submit_before_completion_and_no_forge();
    test_checkpoint_delegate_wait_verify_commit();
    test_failure_restore();
    test_revocation_cancels();
    if (g_failures != 0) {
        fprintf(stderr, "%d assertion(s) failed\n", g_failures);
        return 1;
    }
    printf("TAP_DONE\n");
    return 0;
}
