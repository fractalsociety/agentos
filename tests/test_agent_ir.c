/* Fractal Agent IR v0 validation and lowering tests. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../kernel/fractalos-root-task/include/agent_ir.h"

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

int main(void)
{
    puts("TAP version 14");
    agent_object_id_t objective = object("fix(issue)");
    agent_object_id_t workspace = object("workspace");
    agent_object_id_t success = object("verify-next");
    agent_object_id_t failure = object("restore-next");
    struct agent_ir_node_v0 node = {
        .interface_version = AGENT_IR_INTERFACE_VERSION,
        .operation = AGENT_ISA_OP_DELEGATE,
        .execution_flags = AGENT_ISA_FLAG_ASYNC,
        .declared_caps = AGENT_ISA_CAP_CONTROL,
        .budget_units = 8u,
        .subject_root = objective,
        .context_root = workspace,
        .success_continuation_root = success,
        .failure_continuation_root = failure,
    };
    check(sizeof(node) == 80u,
          "Agent IR node is a bounded immutable control-flow record");
    check(agent_ir_validate_v0(&node) == AGENT_IR_OK,
          "valid DELEGATE node has explicit success and failure edges");

    struct agent_ir_compiled_v0 compiled;
    check(agent_ir_compile_v0(&node, &compiled) == AGENT_IR_OK
              && compiled.instruction.operation == AGENT_ISA_OP_DELEGATE
              && compiled.instruction.flags == AGENT_ISA_FLAG_ASYNC
              && agent_object_id_equal(&compiled.instruction.input_root,
                                       &objective)
              && agent_object_id_equal(
                  &compiled.success_continuation_root, &success),
          "Agent IR lowers deterministically to one semantic instruction");
    agent_object_id_t first_root = compiled.ir_node_root;
    (void)agent_ir_compile_v0(&node, &compiled);
    check(agent_object_id_equal(&first_root, &compiled.ir_node_root),
          "canonical Agent IR node identity is deterministic");

    node.interface_version++;
    check(agent_ir_validate_v0(&node) == AGENT_IR_ERR_VERSION,
          "unknown Agent IR version fails closed");
    node.interface_version = AGENT_IR_INTERFACE_VERSION;
    node.operation = 0xffffu;
    check(agent_ir_validate_v0(&node) == AGENT_IR_ERR_OPERATION,
          "unknown semantic operation fails IR validation");
    node.operation = AGENT_ISA_OP_DELEGATE;
    node.execution_flags = 0u;
    check(agent_ir_validate_v0(&node) == AGENT_IR_ERR_FLAGS,
          "async IR node cannot lower as a synchronous call");
    node.execution_flags = AGENT_ISA_FLAG_ASYNC;
    node.declared_caps = AGENT_ISA_CAP_ADMIN;
    check(agent_ir_validate_v0(&node) == AGENT_IR_ERR_CAPABILITY,
          "IR capability declarations must exactly match semantic intent");
    node.declared_caps = AGENT_ISA_CAP_CONTROL;
    node.subject_root = (agent_object_id_t){{0u, 0u, 0u, 0u}};
    check(agent_ir_validate_v0(&node) == AGENT_IR_ERR_OBJECT,
          "IR rejects a missing objective ObjectID");
    node.subject_root = objective;
    node.success_continuation_root = (agent_object_id_t){{0u, 0u, 0u, 0u}};
    node.failure_continuation_root = node.success_continuation_root;
    check(agent_ir_validate_v0(&node) == AGENT_IR_ERR_CONTINUATION,
          "long operation requires a continuation edge");

    memset(&node, 0, sizeof(node));
    node.interface_version = AGENT_IR_INTERFACE_VERSION;
    node.operation = AGENT_ISA_OP_TERMINATE;
    node.declared_caps = AGENT_ISA_CAP_CONTROL;
    node.budget_units = 1u;
    node.success_continuation_root = success;
    check(agent_ir_validate_v0(&node) == AGENT_IR_ERR_CONTINUATION,
          "TERMINATE cannot point to another IR node");

    printf("1..%u\n", tests);
    return failures == 0u ? 0 : 1;
}
