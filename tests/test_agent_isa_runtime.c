/* Runtime tests for Fractal Agent ISA v0. Implementation is linked separately. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../kernel/fractalos-root-task/include/agent_isa.h"

static unsigned tests;
static unsigned failures;

static void check(int condition, const char *name)
{
    tests++;
    if (condition) printf("ok %u - %s\n", tests, name);
    else {
        printf("not ok %u - %s\n", tests, name);
        failures++;
    }
}

static agent_object_id_t object(const char *text)
{
    agent_object_id_t id;
    agent_isa_object_id_from_bytes(text, (uint32_t)strlen(text), &id);
    return id;
}

static struct agent_isa_req_submit request(uint16_t operation,
                                            uint32_t caps,
                                            agent_object_id_t input,
                                            agent_object_id_t operand)
{
    struct agent_isa_req_submit req = {
        .interface_version = AGENT_ISA_INTERFACE_VERSION,
        .operation = operation,
        .flags = agent_isa_operation_is_async(operation)
            ? AGENT_ISA_FLAG_ASYNC : 0u,
        .declared_caps = caps,
        .budget_units = 1u,
        .input_root = input,
        .operand_root = operand,
    };
    return req;
}

static bool exercise_operation(uint16_t operation,
                               const agent_object_id_t *capset,
                               const agent_object_id_t *environment,
                               const agent_object_id_t *initial)
{
    agent_isa_runtime_t runtime;
    agent_isa_runtime_init(&runtime, AGENT_ISA_CAP_KNOWN_MASK, 3u,
                           capset, environment, initial, 32u);
    agent_object_id_t input = object("matrix-input");
    agent_object_id_t operand = object("matrix-operand");
    agent_object_id_t result = object("matrix-result");
    agent_object_id_t zero = {{0u, 0u, 0u, 0u}};
    struct agent_isa_reply_submit reply;

    if (operation == AGENT_ISA_OP_WAIT) {
        struct agent_isa_req_submit infer = request(
            AGENT_ISA_OP_INFER, AGENT_ISA_CAP_INFER, input, zero);
        if (agent_isa_runtime_submit(&runtime, &infer, &reply)
                != AGENT_ISA_OK) return false;
        struct agent_isa_req_wait wait = {
            .interface_version = AGENT_ISA_INTERFACE_VERSION,
            .ticket_id = reply.ticket_id,
        };
        struct agent_isa_reply_wait waited;
        return agent_isa_runtime_wait(&runtime, &wait, &waited)
                == AGENT_ISA_OK
            && waited.ticket_state == AGENT_ISA_TICKET_PENDING;
    }
    if (operation == AGENT_ISA_OP_TRACE) {
        struct agent_isa_req_submit checkpoint = request(
            AGENT_ISA_OP_CHECKPOINT, AGENT_ISA_CAP_OBJECT, zero, zero);
        if (agent_isa_runtime_submit(&runtime, &checkpoint, &reply)
                != AGENT_ISA_OK) return false;
        struct agent_isa_req_trace trace = {
            .interface_version = AGENT_ISA_INTERFACE_VERSION,
        };
        struct agent_isa_reply_trace traced;
        return agent_isa_runtime_trace(&runtime, &trace, &traced)
            == AGENT_ISA_OK;
    }
    if (operation == AGENT_ISA_OP_COMMIT) {
        struct agent_isa_req_submit verify = request(
            AGENT_ISA_OP_VERIFY, AGENT_ISA_CAP_VERIFY, input, operand);
        if (agent_isa_runtime_submit(&runtime, &verify, &reply)
                != AGENT_ISA_OK
            || agent_isa_runtime_complete(&runtime, reply.ticket_id,
                                          &result, true) != AGENT_ISA_OK)
            return false;
        struct agent_isa_req_submit commit = request(
            AGENT_ISA_OP_COMMIT, AGENT_ISA_CAP_COMMIT, input, result);
        return agent_isa_runtime_submit(&runtime, &commit, &reply)
            == AGENT_ISA_OK;
    }

    if (operation == AGENT_ISA_OP_CHECKPOINT
        || operation == AGENT_ISA_OP_TERMINATE) {
        input = zero;
        operand = zero;
    } else if (operation == AGENT_ISA_OP_OBJECT_GET
               || operation == AGENT_ISA_OP_OBJECT_PUT
               || operation == AGENT_ISA_OP_OBJECT_QUERY
               || operation == AGENT_ISA_OP_INFER
               || operation == AGENT_ISA_OP_EMIT
               || operation == AGENT_ISA_OP_RESTORE
               || operation == AGENT_ISA_OP_BUDGET) {
        operand = zero;
    }
    uint32_t caps = agent_isa_operation_required_caps(operation);
    struct agent_isa_req_submit req = request(operation, caps, input, operand);
    if (agent_isa_runtime_submit(&runtime, &req, &reply) != AGENT_ISA_OK)
        return false;
    if (agent_isa_operation_is_async(operation))
        return agent_isa_runtime_complete(&runtime, reply.ticket_id,
                                          &result, true) == AGENT_ISA_OK;
    return reply.ticket_state == AGENT_ISA_TICKET_COMPLETE;
}

int main(void)
{
    puts("TAP version 14");

    agent_isa_runtime_t runtime;
    agent_object_id_t capset = object("capset");
    agent_object_id_t environment = object("environment");
    agent_object_id_t initial = object("workspace-v1");
    uint32_t all_caps = AGENT_ISA_CAP_KNOWN_MASK;
    agent_isa_runtime_init(&runtime, all_caps, 7u, &capset, &environment,
                           &initial, 128u);

    bool all_operations_covered = true;
    for (uint16_t operation = AGENT_ISA_OP_FIRST;
         operation <= AGENT_ISA_OP_LAST; operation++)
        if (!exercise_operation(operation, &capset, &environment, &initial))
            all_operations_covered = false;
    check(all_operations_covered,
          "all eighteen Agent ISA instructions have executable contract coverage");

    agent_object_id_t objective = object("fix(issue)");
    agent_object_id_t workspace = object("workspace");
    struct agent_isa_reply_submit submit;
    struct agent_isa_req_submit req = request(
        AGENT_ISA_OP_DELEGATE, AGENT_ISA_CAP_CONTROL,
        objective, workspace);
    check(agent_isa_runtime_submit(&runtime, &req, &submit) == AGENT_ISA_OK
              && submit.ticket_id != 0u
              && submit.ticket_state == AGENT_ISA_TICKET_PENDING
              && !agent_object_id_is_zero(&submit.execution_node),
          "DELEGATE returns a future and immutable pending node");

    struct agent_isa_req_wait wait = {
        .interface_version = AGENT_ISA_INTERFACE_VERSION,
        .ticket_id = submit.ticket_id,
    };
    struct agent_isa_reply_wait waited;
    check(agent_isa_runtime_wait(&runtime, &wait, &waited) == AGENT_ISA_OK
              && waited.ticket_state == AGENT_ISA_TICKET_PENDING,
          "WAIT polls without holding synchronous IPC open");

    agent_object_id_t delegated = object("delegated-result");
    check(agent_isa_runtime_complete(&runtime, submit.ticket_id,
                                     &delegated, true) == AGENT_ISA_OK,
          "trusted lower adapter completes a delegated ticket");
    check(agent_isa_runtime_wait(&runtime, &wait, &waited) == AGENT_ISA_OK
              && waited.ticket_state == AGENT_ISA_TICKET_COMPLETE
              && agent_object_id_equal(&waited.result_root, &delegated),
          "WAIT returns the immutable delegated result");

    agent_object_id_t zero = {{0u, 0u, 0u, 0u}};
    req = request(0xffffu, 0u, objective, zero);
    check(agent_isa_runtime_submit(&runtime, &req, &submit)
              == AGENT_ISA_ERR_OPERATION,
          "unknown semantic operation fails closed");
    req = request(AGENT_ISA_OP_INFER, AGENT_ISA_CAP_INFER, objective, zero);
    req.interface_version++;
    check(agent_isa_runtime_submit(&runtime, &req, &submit)
              == AGENT_ISA_ERR_VERSION,
          "unknown Agent ISA version fails closed");
    req.interface_version = AGENT_ISA_INTERFACE_VERSION;
    req.flags |= 1u << 31;
    check(agent_isa_runtime_submit(&runtime, &req, &submit)
              == AGENT_ISA_ERR_FLAGS,
          "unknown execution flags fail closed");
    req = request(AGENT_ISA_OP_DELEGATE, AGENT_ISA_CAP_CONTROL,
                  zero, workspace);
    check(agent_isa_runtime_submit(&runtime, &req, &submit)
              == AGENT_ISA_ERR_OBJECT,
          "DELEGATE rejects a missing objective ObjectID");
    req = request(AGENT_ISA_OP_VERIFY, AGENT_ISA_CAP_VERIFY,
                  delegated, zero);
    check(agent_isa_runtime_submit(&runtime, &req, &submit)
              == AGENT_ISA_ERR_OBJECT,
          "VERIFY rejects a missing verifier ObjectID");

    agent_isa_runtime_t restricted;
    agent_isa_runtime_init(&restricted, AGENT_ISA_CAP_INFER, 1u,
                           &capset, &environment, &initial, 8u);
    req = request(AGENT_ISA_OP_CAP_GRANT, AGENT_ISA_CAP_ADMIN,
                  capset, workspace);
    check(agent_isa_runtime_submit(&restricted, &req, &submit)
              == AGENT_ISA_ERR_CAP_DENIED,
          "CAP_GRANT declaration cannot create broker authority");
    req = request(AGENT_ISA_OP_INFER, AGENT_ISA_CAP_INFER,
                  objective, zero);
    req.declared_caps |= AGENT_ISA_CAP_ACT;
    check(agent_isa_runtime_submit(&restricted, &req, &submit)
              == AGENT_ISA_ERR_CAP_DENIED,
          "extra undeclared semantic authority fails closed");

    agent_isa_runtime_t bounded;
    agent_isa_runtime_init(&bounded, all_caps, 1u, &capset, &environment,
                           &initial, 1u);
    req = request(AGENT_ISA_OP_INFER, AGENT_ISA_CAP_INFER,
                  objective, zero);
    req.budget_units = 2u;
    check(agent_isa_runtime_submit(&bounded, &req, &submit)
              == AGENT_ISA_ERR_BUDGET,
          "operation budget cannot exceed the runtime limit");
    req.budget_units = AGENT_ISA_MAX_BUDGET_UNITS + 1u;
    check(agent_isa_runtime_submit(&bounded, &req, &submit)
              == AGENT_ISA_ERR_BUDGET,
          "non-canonical oversized budget fails closed");

    agent_isa_runtime_t exhausted;
    agent_isa_runtime_init(&exhausted, all_caps, 1u, &capset, &environment,
                           &initial, 64u);
    uint32_t tickets[AGENT_ISA_MAX_TICKETS];
    for (uint32_t i = 0u; i < AGENT_ISA_MAX_TICKETS; i++) {
        req = request(AGENT_ISA_OP_INFER, AGENT_ISA_CAP_INFER,
                      objective, zero);
        uint32_t status = agent_isa_runtime_submit(&exhausted, &req, &submit);
        tickets[i] = submit.ticket_id;
        if (status != AGENT_ISA_OK) tickets[i] = 0u;
    }
    req = request(AGENT_ISA_OP_INFER, AGENT_ISA_CAP_INFER, objective, zero);
    check(tickets[0] != 0u
              && agent_isa_runtime_submit(&exhausted, &req, &submit)
                  == AGENT_ISA_ERR_TICKET_EXHAUSTED,
          "bounded future table rejects ticket exhaustion");

    agent_isa_runtime_t concurrent;
    agent_isa_runtime_init(&concurrent, all_caps, 1u, &capset, &environment,
                           &initial, 8u);
    req = request(AGENT_ISA_OP_INFER, AGENT_ISA_CAP_INFER,
                  objective, zero);
    (void)agent_isa_runtime_submit(&concurrent, &req, &submit);
    uint32_t first_ticket = submit.ticket_id;
    req = request(AGENT_ISA_OP_ACT, AGENT_ISA_CAP_ACT,
                  objective, workspace);
    (void)agent_isa_runtime_submit(&concurrent, &req, &submit);
    uint32_t second_ticket = submit.ticket_id;
    agent_object_id_t first_result = object("first-branch");
    agent_object_id_t second_result = object("second-branch");
    uint32_t first_status = agent_isa_runtime_complete(
        &concurrent, first_ticket, &first_result, true);
    uint32_t second_status = agent_isa_runtime_complete(
        &concurrent, second_ticket, &second_result, true);
    wait.interface_version = AGENT_ISA_INTERFACE_VERSION;
    wait.flags = 0u;
    wait.ticket_id = second_ticket;
    wait.timeout_ticks = 0u;
    wait.reserved = 0u;
    (void)agent_isa_runtime_wait(&concurrent, &wait, &waited);
    check(first_status == AGENT_ISA_OK
              && second_status == AGENT_ISA_ERR_CONFLICT
              && waited.ticket_state == AGENT_ISA_TICKET_CONFLICT,
          "concurrent future completion records a branch conflict");

    agent_isa_runtime_t flow;
    agent_isa_runtime_init(&flow, all_caps, 9u, &capset, &environment,
                           &initial, 64u);
    req = request(AGENT_ISA_OP_CHECKPOINT, AGENT_ISA_CAP_OBJECT, zero, zero);
    check(agent_isa_runtime_submit(&flow, &req, &submit) == AGENT_ISA_OK
              && submit.ticket_state == AGENT_ISA_TICKET_COMPLETE
              && agent_object_id_equal(&submit.state_root, &initial),
          "CHECKPOINT saves the current immutable root");
    agent_object_id_t checkpoint = submit.state_root;

    req = request(AGENT_ISA_OP_COMMIT, AGENT_ISA_CAP_COMMIT,
                  workspace, delegated);
    check(agent_isa_runtime_submit(&flow, &req, &submit)
              == AGENT_ISA_ERR_STATE,
          "COMMIT cannot bypass trusted verification evidence");

    req = request(AGENT_ISA_OP_DELEGATE, AGENT_ISA_CAP_CONTROL,
                  objective, checkpoint);
    check(agent_isa_runtime_submit(&flow, &req, &submit) == AGENT_ISA_OK,
          "checkpoint root can be delegated without exposing storage details");
    agent_object_id_t candidate = object("candidate-change");
    (void)agent_isa_runtime_complete(&flow, submit.ticket_id, &candidate, true);

    agent_object_id_t verifier = object("rust.tests");
    req = request(AGENT_ISA_OP_VERIFY, AGENT_ISA_CAP_VERIFY,
                  candidate, verifier);
    check(agent_isa_runtime_submit(&flow, &req, &submit) == AGENT_ISA_OK,
          "VERIFY names an immutable verifier capability object");
    agent_object_id_t verified = object("verification-pass");
    (void)agent_isa_runtime_complete(&flow, submit.ticket_id, &verified, true);
    req = request(AGENT_ISA_OP_COMMIT, AGENT_ISA_CAP_COMMIT,
                  candidate, verified);
    check(agent_isa_runtime_submit(&flow, &req, &submit) == AGENT_ISA_OK
              && submit.ticket_state == AGENT_ISA_TICKET_COMPLETE
              && !agent_object_id_equal(&submit.state_root, &checkpoint),
          "successful verification permits a semantic COMMIT transition");

    agent_isa_runtime_t rollback;
    agent_isa_runtime_init(&rollback, all_caps, 9u, &capset, &environment,
                           &initial, 64u);
    req = request(AGENT_ISA_OP_VERIFY, AGENT_ISA_CAP_VERIFY,
                  candidate, verifier);
    (void)agent_isa_runtime_submit(&rollback, &req, &submit);
    (void)agent_isa_runtime_complete(&rollback, submit.ticket_id,
                                     &verified, false);
    req = request(AGENT_ISA_OP_RESTORE, AGENT_ISA_CAP_OBJECT,
                  initial, zero);
    check(agent_isa_runtime_submit(&rollback, &req, &submit) == AGENT_ISA_OK
              && agent_object_id_equal(&submit.state_root, &initial),
          "failed verification can RESTORE the saved root");

    struct agent_isa_req_trace trace = {
        .interface_version = AGENT_ISA_INTERFACE_VERSION,
    };
    struct agent_isa_reply_trace trace_reply;
    check(agent_isa_runtime_trace(&flow, &trace, &trace_reply) == AGENT_ISA_OK
              && !agent_object_id_is_zero(&trace_reply.node_root)
              && !agent_object_id_equal(&trace_reply.node_root,
                                        &trace_reply.parent_root),
          "execution DAG cannot create a self-parent cycle");

    struct agent_execution_node node = flow.trace[
        (flow.trace_head + AGENT_ISA_MAX_TRACE_NODES - 1u)
        % AGENT_ISA_MAX_TRACE_NODES];
    agent_object_id_t hash_a, hash_b;
    agent_isa_execution_node_hash(&node, &hash_a);
    agent_isa_execution_node_hash(&node, &hash_b);
    check(agent_object_id_equal(&hash_a, &hash_b)
              && agent_object_id_equal(&hash_a, &trace_reply.node_root),
          "canonical execution-node hashing is deterministic");

    printf("1..%u\n", tests);
    return failures == 0u ? 0 : 1;
}
