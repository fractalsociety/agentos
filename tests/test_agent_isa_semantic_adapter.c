/*
 * fos-gz0.14.1.2 — semantic adapters for existing FractalOS services (L2).
 *
 * Every async semantic op reaches only its capability-selected endpoint;
 * epoch/budget/ownership are rechecked; completions are immutable digests
 * without provider/implementation names.
 */

#include <stdio.h>
#include <string.h>

#include "../kernel/fractalos-root-task/include/fractalos.h"
#include "../kernel/fractalos-root-task/include/agent_isa.h"
#include "../kernel/fractalos-root-task/include/agent_isa_semantic_adapter.h"

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

static void install_class(uint32_t service_class, const char *iface_label)
{
    struct agent_isa_adapter_req_install req;
    struct agent_isa_adapter_reply_install reply;
    memset(&req, 0, sizeof(req));
    req.interface_version = AGENT_ISA_ADAPTER_INTERFACE_VERSION;
    req.endpoint.interface_id = oid(iface_label);
    req.endpoint.service_class = service_class;
    req.endpoint.authority_epoch = 1u;
    req.endpoint.budget_ceiling = 100u;
    expect_eq_u32("install", agent_isa_adapter_install(&req, &reply),
                  AGENT_ISA_ADAPTER_OK);
}

static struct agent_isa_dispatch_record make_record(uint16_t op, uint32_t caps,
                                                    agent_object_id_t input)
{
    struct agent_isa_dispatch_record r;
    memset(&r, 0, sizeof(r));
    r.interface_version = AGENT_ISA_DISPATCH_INTERFACE_VERSION;
    r.operation = op;
    r.flags = AGENT_ISA_FLAG_ASYNC;
    r.ticket_id = 7u;
    r.authority_epoch = 1u;
    r.declared_caps = caps;
    r.budget_units = 3u;
    r.owner_badge_low = 0x42u;
    r.owner_badge_high = 0u;
    r.dispatch_nonce = 9u;
    r.input_root = input;
    r.operand_root = oid("operand");
    r.capability_set_root = oid("capset");
    return r;
}

static void test_opcodes(void)
{
    expect_eq_u32("INSTALL", MSG_AGENT_ISA_ADAPTER_INSTALL, 0x310Au);
    expect_eq_u32("INVOKE", MSG_AGENT_ISA_ADAPTER_INVOKE, 0x310Bu);
    expect_eq_u32("STATUS", MSG_AGENT_ISA_ADAPTER_STATUS, 0x310Cu);
}

static void test_all_async_ops_reach_selected_service(void)
{
    static const struct {
        uint16_t op;
        uint32_t caps;
        const char *iface;
    } cases[] = {
        { AGENT_ISA_OP_SPAWN, AGENT_ISA_CAP_CONTROL, "iface-control" },
        { AGENT_ISA_OP_DELEGATE, AGENT_ISA_CAP_CONTROL, "iface-control" },
        { AGENT_ISA_OP_CAP_GRANT, AGENT_ISA_CAP_ADMIN, "iface-admin" },
        { AGENT_ISA_OP_CAP_REVOKE, AGENT_ISA_CAP_ADMIN, "iface-admin" },
        { AGENT_ISA_OP_OBJECT_GET, AGENT_ISA_CAP_OBJECT, "iface-object" },
        { AGENT_ISA_OP_OBJECT_PUT, AGENT_ISA_CAP_OBJECT, "iface-object" },
        { AGENT_ISA_OP_OBJECT_QUERY, AGENT_ISA_CAP_OBJECT, "iface-object" },
        { AGENT_ISA_OP_INFER, AGENT_ISA_CAP_INFER, "iface-infer" },
        { AGENT_ISA_OP_ACT, AGENT_ISA_CAP_ACT, "iface-act" },
        { AGENT_ISA_OP_EMIT, AGENT_ISA_CAP_EVENT, "iface-event" },
        { AGENT_ISA_OP_VERIFY, AGENT_ISA_CAP_VERIFY, "iface-verify" },
    };
    uint32_t i;

    agent_isa_adapter_reset();
    install_class(AGENT_ISA_CAP_CONTROL, "iface-control");
    install_class(AGENT_ISA_CAP_ADMIN, "iface-admin");
    install_class(AGENT_ISA_CAP_OBJECT, "iface-object");
    install_class(AGENT_ISA_CAP_INFER, "iface-infer");
    install_class(AGENT_ISA_CAP_ACT, "iface-act");
    install_class(AGENT_ISA_CAP_EVENT, "iface-event");
    install_class(AGENT_ISA_CAP_VERIFY, "iface-verify");

    for (i = 0u; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct agent_isa_adapter_req_invoke req;
        struct agent_isa_adapter_reply_invoke reply;
        agent_object_id_t want_iface = oid(cases[i].iface);
        agent_object_id_t input = oid("owned-input");

        memset(&req, 0, sizeof(req));
        req.interface_version = AGENT_ISA_ADAPTER_INTERFACE_VERSION;
        req.record = make_record(cases[i].op, cases[i].caps, input);
        req.owned_object = input;
        req.caller_budget_remaining = 10u;
        req.caller_authority_epoch = 1u;

        expect_eq_u32("invoke ok", agent_isa_adapter_invoke(&req, &reply),
                      AGENT_ISA_ADAPTER_OK);
        expect_eq_u32("class selected", reply.service_class_selected,
                      cases[i].caps);
        expect_true("interface selected by class not name",
                    reply.interface_id_selected.word[0] == want_iface.word[0]
                        && reply.interface_id_selected.word[1]
                               == want_iface.word[1]);
        expect_true("immutable completion",
                    reply.completion_root.word[0] != 0u
                        || reply.completion_root.word[1] != 0u);
        expect_eq_u32("backend ok", reply.backend_status,
                      AGENT_ISA_DISPATCH_BACKEND_OK);
        /* Reply struct has no char name[] — size locked by contract. */
        expect_eq_u32("reply wire size",
                      (uint32_t)sizeof(reply), 48u);
    }
}

static void test_rechecks_and_denials(void)
{
    struct agent_isa_adapter_req_invoke req;
    struct agent_isa_adapter_reply_invoke reply;
    agent_object_id_t input = oid("owned-input");

    agent_isa_adapter_reset();
    install_class(AGENT_ISA_CAP_INFER, "iface-infer");

    memset(&req, 0, sizeof(req));
    req.interface_version = AGENT_ISA_ADAPTER_INTERFACE_VERSION;
    req.record = make_record(AGENT_ISA_OP_INFER, AGENT_ISA_CAP_INFER, input);
    req.owned_object = input;
    req.caller_budget_remaining = 10u;
    req.caller_authority_epoch = 1u;

    /* Wrong declared class for op. */
    req.record.declared_caps = AGENT_ISA_CAP_ACT;
    expect_eq_u32("wrong class", agent_isa_adapter_invoke(&req, &reply),
                  AGENT_ISA_ADAPTER_ERR_WRONG_CLASS);
    req.record.declared_caps = AGENT_ISA_CAP_INFER;

    /* Stale epoch. */
    req.caller_authority_epoch = 99u;
    expect_eq_u32("stale epoch", agent_isa_adapter_invoke(&req, &reply),
                  AGENT_ISA_ADAPTER_ERR_AUTHORITY);
    req.caller_authority_epoch = 1u;

    /* Budget. */
    req.caller_budget_remaining = 1u;
    expect_eq_u32("budget", agent_isa_adapter_invoke(&req, &reply),
                  AGENT_ISA_ADAPTER_ERR_BUDGET);
    req.caller_budget_remaining = 10u;

    /* Ownership mismatch. */
    req.owned_object = oid("other");
    expect_eq_u32("ownership", agent_isa_adapter_invoke(&req, &reply),
                  AGENT_ISA_ADAPTER_ERR_OWNERSHIP);
    req.owned_object = input;

    /* Missing endpoint for class. */
    agent_isa_adapter_reset();
    expect_eq_u32("no endpoint", agent_isa_adapter_invoke(&req, &reply),
                  AGENT_ISA_ADAPTER_ERR_NO_ENDPOINT);
}

static void test_infer_cannot_use_act_endpoint(void)
{
    struct agent_isa_adapter_req_invoke req;
    struct agent_isa_adapter_reply_invoke reply;
    agent_object_id_t input = oid("owned-input");

    agent_isa_adapter_reset();
    install_class(AGENT_ISA_CAP_ACT, "iface-act-only");

    memset(&req, 0, sizeof(req));
    req.interface_version = AGENT_ISA_ADAPTER_INTERFACE_VERSION;
    req.record = make_record(AGENT_ISA_OP_INFER, AGENT_ISA_CAP_INFER, input);
    req.owned_object = input;
    req.caller_budget_remaining = 10u;
    req.caller_authority_epoch = 1u;
    expect_eq_u32("infer without infer endpoint",
                  agent_isa_adapter_invoke(&req, &reply),
                  AGENT_ISA_ADAPTER_ERR_NO_ENDPOINT);
}

int main(void)
{
    printf("1..4\n");
    test_opcodes();
    test_all_async_ops_reach_selected_service();
    test_rechecks_and_denials();
    test_infer_cannot_use_act_endpoint();
    if (g_failures != 0) {
        fprintf(stderr, "%d assertion(s) failed\n", g_failures);
        return 1;
    }
    printf("TAP_DONE\n");
    return 0;
}
