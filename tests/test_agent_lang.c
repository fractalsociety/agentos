/* AgentLang v0 parser, type/effect checker, and canonical IR tests. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../kernel/fractalos-root-task/include/agent_lang.h"

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

static void add_value(struct agent_lang_prelude_v0 *prelude,
                      const char *name, uint16_t type)
{
    struct agent_lang_prelude_value_v0 *value =
        &prelude->values[prelude->value_count++];
    size_t length = strlen(name);
    memcpy(value->name, name, length + 1u);
    value->type = type;
    value->root = object(name);
}

static struct agent_lang_prelude_v0 full_prelude(void)
{
    struct agent_lang_prelude_v0 prelude;
    memset(&prelude, 0, sizeof(prelude));
    prelude.interface_version = AGENT_LANG_INTERFACE_VERSION;
    prelude.installed_caps = AGENT_ISA_CAP_OBJECT | AGENT_ISA_CAP_CONTROL
        | AGENT_ISA_CAP_VERIFY | AGENT_ISA_CAP_COMMIT;
    prelude.declared_effects = prelude.installed_caps;
    prelude.max_nodes = AGENT_LANG_MAX_NODES;
    prelude.max_parallelism = 4u;
    add_value(&prelude, "workspace", AGENT_LANG_TYPE_OBJECT_ID);
    add_value(&prelude, "role", AGENT_LANG_TYPE_OBJECT_ID);
    add_value(&prelude, "objective", AGENT_LANG_TYPE_OBJECT_ID);
    add_value(&prelude, "coder", AGENT_LANG_TYPE_AGENT_HANDLE);
    add_value(&prelude, "task_verifier", AGENT_LANG_TYPE_OBJECT_ID);
    return prelude;
}

static uint32_t compile(const char *source,
                        const struct agent_lang_prelude_v0 *prelude,
                        struct agent_lang_program_v0 *program,
                        struct agent_lang_diagnostic_v0 *diagnostic)
{
    return agent_lang_compile_v0(source, (uint32_t)strlen(source), prelude,
                                 program, diagnostic);
}

int main(void)
{
    puts("TAP version 14");
    struct agent_lang_prelude_v0 prelude = full_prelude();
    struct agent_lang_program_v0 program;
    struct agent_lang_diagnostic_v0 diagnostic;
    const char *valid =
        "let w = checkpoint(workspace)?\n"
        "let worker = spawn(role, workspace)?\n"
        "parallel {\n"
        "  let a = delegate(worker, objective)?\n"
        "  let b = delegate(coder, objective)?\n"
        "}\n"
        "let best = task_verify([a, b])?\n"
        "commit(best)?\n";

    check(compile(valid, &prelude, &program, &diagnostic)
              == AGENT_LANG_OK
              && program.node_count == 6u,
          "valid checkpoint/parallel/spawn/delegate/verify/commit compiles");
    check(program.steps[0].node.operation == AGENT_ISA_OP_CHECKPOINT
              && program.steps[1].node.operation == AGENT_ISA_OP_SPAWN
              && program.steps[2].node.operation == AGENT_ISA_OP_DELEGATE
              && program.steps[3].node.operation == AGENT_ISA_OP_DELEGATE
              && program.steps[4].node.operation == AGENT_ISA_OP_VERIFY
              && program.steps[5].node.operation == AGENT_ISA_OP_COMMIT,
          "AgentLang operations lower to the existing semantic ISA");
    check(program.steps[2].parallel_group != 0u
              && program.steps[2].parallel_group
                    == program.steps[3].parallel_group
              && program.steps[1].parallel_group == 0u
              && program.steps[4].parallel_group == 0u,
          "parallel block lowers to one bounded structured-concurrency group");
    check(agent_object_id_equal(
              &program.steps[2].node.success_continuation_root,
              &program.steps[4].ir_node_root)
              && agent_object_id_equal(
                  &program.steps[3].node.success_continuation_root,
                  &program.steps[4].ir_node_root),
          "parallel branches join at the same canonical continuation");

    struct agent_lang_program_v0 repeated;
    struct agent_lang_diagnostic_v0 repeated_diagnostic;
    check(compile(valid, &prelude, &repeated, &repeated_diagnostic)
              == AGENT_LANG_OK
              && memcmp(&program, &repeated, sizeof(program)) == 0
              && agent_object_id_equal(&program.program_root,
                                       &repeated.program_root),
          "same source and prelude produce byte-identical canonical IR");

    const char *wait_restore =
        "let t = delegate(coder, objective)?\n"
        "let result = wait(t)?\n"
        "restore(result)?\n";
    check(compile(wait_restore, &prelude, &program, &diagnostic)
              == AGENT_LANG_OK
              && program.steps[0].result_type == AGENT_LANG_TYPE_TASK_HANDLE
              && program.steps[1].result_type == AGENT_LANG_TYPE_OBJECT_ID
              && program.steps[1].node.operation == AGENT_ISA_OP_WAIT
              && program.steps[2].node.operation == AGENT_ISA_OP_RESTORE,
          "TaskHandle and ObjectID types infer through wait and restore");

    struct agent_lang_prelude_v0 denied = prelude;
    denied.installed_caps &= ~AGENT_ISA_CAP_CONTROL;
    check(compile("let a = delegate(coder, objective)?", &denied,
                  &program, &diagnostic) == AGENT_LANG_ERR_CAPABILITY
              && diagnostic.required_effect == AGENT_ISA_CAP_CONTROL,
          "generated prelude cannot compile a missing capability");

    denied = prelude;
    denied.declared_effects &= ~AGENT_ISA_CAP_CONTROL;
    check(compile("let a = delegate(coder, objective)?", &denied,
                  &program, &diagnostic) == AGENT_LANG_ERR_EFFECT
              && diagnostic.required_effect == AGENT_ISA_CAP_CONTROL,
          "installed authority does not excuse an undeclared program effect");

    check(compile("let a = delegate(workspace, objective)?", &prelude,
                  &program, &diagnostic) == AGENT_LANG_ERR_TYPE
              && diagnostic.expected_type == AGENT_LANG_TYPE_AGENT_HANDLE
              && diagnostic.actual_type == AGENT_LANG_TYPE_OBJECT_ID,
          "static checking rejects an ObjectID where AgentHandle is required");
    check(compile("let a = delegate(coder, missing)?", &prelude,
                  &program, &diagnostic) == AGENT_LANG_ERR_UNDECLARED,
          "unknown values cannot become ambient inputs");
    check(compile("let a = delegate(coder, objective)", &prelude,
                  &program, &diagnostic) == AGENT_LANG_ERR_RESULT_REQUIRED,
          "capability results require explicit question-mark propagation");

    const char *malformed = "parallel { let a = spawn(role workspace)? }";
    check(compile(malformed, &prelude, &program, &diagnostic)
              == AGENT_LANG_ERR_SYNTAX
              && diagnostic.line == 1u && diagnostic.column != 0u,
          "malformed syntax reports a stable source position");
    struct agent_lang_diagnostic_v0 first_diagnostic = diagnostic;
    (void)compile(malformed, &prelude, &program, &diagnostic);
    check(memcmp(&first_diagnostic, &diagnostic, sizeof(diagnostic)) == 0,
          "diagnostics are deterministic for pinned invalid source");

    check(compile("import filesystem", &prelude, &program, &diagnostic)
              == AGENT_LANG_ERR_FORBIDDEN,
          "dynamic imports and ambient filesystem access are forbidden");
    check(compile("shell(workspace)?", &prelude, &program, &diagnostic)
              == AGENT_LANG_ERR_FORBIDDEN,
          "shell execution has no AgentLang escape hatch");
    check(compile("network(workspace)?", &prelude, &program, &diagnostic)
              == AGENT_LANG_ERR_FORBIDDEN,
          "ambient network access is forbidden");
    check(compile("reflect(workspace)?", &prelude, &program, &diagnostic)
              == AGENT_LANG_ERR_FORBIDDEN,
          "reflection is forbidden");
    check(compile("while objective { commit(objective)? }", &prelude,
                  &program, &diagnostic) == AGENT_LANG_ERR_FORBIDDEN,
          "unbounded loops are rejected before lowering");
    check(compile("fn recurse() { recurse() }", &prelude,
                  &program, &diagnostic) == AGENT_LANG_ERR_FORBIDDEN,
          "functions and recursion are outside bounded AgentLang v0");
    check(compile("new workspace", &prelude, &program, &diagnostic)
              == AGENT_LANG_ERR_FORBIDDEN,
          "unbounded dynamic allocation is forbidden");

    prelude.max_parallelism = 1u;
    check(compile(valid, &prelude, &program, &diagnostic)
              == AGENT_LANG_ERR_BOUNDS,
          "parallel width is checked against the capability prelude limit");
    prelude = full_prelude();
    prelude.max_nodes = 2u;
    check(compile(valid, &prelude, &program, &diagnostic)
              == AGENT_LANG_ERR_BOUNDS,
          "program node count is statically bounded");

    printf("1..%u\n", tests);
    return failures == 0u ? 0 : 1;
}
