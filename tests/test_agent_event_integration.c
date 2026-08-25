/*
 * fos-gz0.14.5.3 — AgentFS descriptors + ISA emission + IPC RECORD/SEAL/REPLAY.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../kernel/fractalos-root-task/include/fractalos.h"
#include "../kernel/fractalos-root-task/include/agent_event_emit.h"
#include "../kernel/fractalos-root-task/include/agent_isa.h"
#include "../kernel/fractalos-root-task/include/agent_isa_semantic_adapter.h"
#include "../kernel/fractalos-root-task/include/contracts/eventbus_contract.h"
#include "../services/agentfs/descriptor_store.h"

/* Canonical EventBus adapter (provides fractalos_eventbus_*). */
#include "../kernel/fractalos-root-task/src/event_bus.c"

extern uint32_t fractalos_eventbus_agent_ipc(uint32_t opcode,
                                             const void *req, uint32_t req_len,
                                             void *rep, uint32_t *rep_len);

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

static eventbus_event_hash_t hash_label(const char *label)
{
    eventbus_event_hash_t h;
    eventbus_event_hash_bytes((const uint8_t *)label,
                              (uint32_t)strlen(label), &h);
    return h;
}

static agent_object_id_t oid(const char *s)
{
    agent_object_id_t id;
    agent_isa_object_id_from_bytes(s, (uint32_t)strlen(s), &id);
    return id;
}

static void test_descriptor_persist_resolve(void)
{
    eventbus_event_hash_t root = hash_label("desc-root-1");
    uint8_t desc[] = {0x02, 0x10, 0x00, 0x00, 'p', 'a', 't', 'h'};
    uint8_t out[64];
    uint32_t out_len = 0u;

    agentfs_desc_store_init();
    expect_eq_u32("desc persist",
                  agentfs_desc_persist(&root, desc, (uint32_t)sizeof(desc)),
                  0u);
    expect_eq_u32("desc count", agentfs_desc_count(), 1u);
    expect_eq_u32("desc resolve",
                  agentfs_desc_resolve(&root, out, (uint32_t)sizeof(out),
                                       &out_len),
                  0u);
    expect_eq_u32("desc length", out_len, (uint32_t)sizeof(desc));
    expect_true("desc bytes", memcmp(out, desc, sizeof(desc)) == 0);

    {
        eventbus_event_hash_t missing = hash_label("missing");
        expect_eq_u32("desc missing",
                      agentfs_desc_resolve(&missing, out, sizeof(out),
                                           &out_len),
                      2u);
    }
}

static void test_ipc_record_seal_replay(void)
{
    struct eventbus_req_agent_record req;
    struct eventbus_reply_agent_record rep;
    struct eventbus_reply_agent_seal seal_rep;
    struct eventbus_req_agent_replay replay_req;
    struct eventbus_reply_agent_replay replay_rep;
    uint32_t rep_len;
    uint32_t status;

    fractalos_eventbus_canonical_init(1u);
    memset(&req, 0, sizeof(req));
    req.event_type = EVENTBUS_EVENT_TASK;
    req.authority_epoch = 1u;
    req.flags = EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE;
    req.scope_id = hash_label("scope-ipc");
    req.payload_root = hash_label("payload-ipc");

    rep_len = (uint32_t)sizeof(rep);
    status = fractalos_eventbus_agent_ipc(MSG_EVENTBUS_AGENT_RECORD, &req,
                                          (uint32_t)sizeof(req), &rep,
                                          &rep_len);
    expect_eq_u32("ipc record", status, EVENTBUS_AGENT_EVENT_OK);
    expect_eq_u32("ipc record status field", rep.status,
                  EVENTBUS_AGENT_EVENT_OK);

    rep_len = (uint32_t)sizeof(seal_rep);
    status = fractalos_eventbus_agent_ipc(MSG_EVENTBUS_AGENT_SEAL, NULL, 0u,
                                          &seal_rep, &rep_len);
    expect_eq_u32("ipc seal", status, EVENTBUS_AGENT_EVENT_OK);
    expect_true("ipc seal count", seal_rep.seal.event_count >= 1u);

    memset(&replay_req, 0, sizeof(replay_req));
    replay_req.seal = seal_rep.seal;
    rep_len = (uint32_t)sizeof(replay_rep);
    status = fractalos_eventbus_agent_ipc(MSG_EVENTBUS_AGENT_REPLAY,
                                          &replay_req,
                                          (uint32_t)sizeof(replay_req),
                                          &replay_rep, &rep_len);
    expect_eq_u32("ipc replay", status, EVENTBUS_AGENT_EVENT_OK);
    expect_true("ipc replay tasks",
                replay_rep.replay.task_events >= 1u);

    replay_req.seal.head.bytes[0] ^= 0xffu;
    rep_len = (uint32_t)sizeof(replay_rep);
    status = fractalos_eventbus_agent_ipc(MSG_EVENTBUS_AGENT_REPLAY,
                                          &replay_req,
                                          (uint32_t)sizeof(replay_req),
                                          &replay_rep, &rep_len);
    expect_true("ipc replay rejects tamper",
                status != EVENTBUS_AGENT_EVENT_OK);
}

static void test_adapter_emits_nested_call(void)
{
    struct agent_isa_adapter_req_install ireq;
    struct agent_isa_adapter_reply_install irep;
    struct agent_isa_adapter_req_invoke vreq;
    struct agent_isa_adapter_reply_invoke vrep;
    const struct eventbus_agent_event_stream *stream;
    uint32_t before;
    agent_object_id_t input = oid("owned-obj");

    fractalos_eventbus_canonical_init(1u);
    agent_isa_adapter_reset();

    memset(&ireq, 0, sizeof(ireq));
    ireq.interface_version = AGENT_ISA_ADAPTER_INTERFACE_VERSION;
    ireq.endpoint.interface_id = oid("iface-net");
    ireq.endpoint.service_class = AGENT_ISA_CAP_OBJECT;
    ireq.endpoint.authority_epoch = 1u;
    ireq.endpoint.budget_ceiling = 100u;
    expect_eq_u32("install for emit",
                  agent_isa_adapter_install(&ireq, &irep),
                  AGENT_ISA_ADAPTER_OK);

    stream = fractalos_eventbus_canonical_stream();
    before = stream ? (uint32_t)stream->event_count : 0u;

    memset(&vreq, 0, sizeof(vreq));
    vreq.interface_version = AGENT_ISA_ADAPTER_INTERFACE_VERSION;
    vreq.caller_authority_epoch = 1u;
    vreq.caller_budget_remaining = 50u;
    vreq.owned_object = input;
    vreq.record.interface_version = AGENT_ISA_DISPATCH_INTERFACE_VERSION;
    vreq.record.operation = AGENT_ISA_OP_OBJECT_PUT;
    vreq.record.flags = AGENT_ISA_FLAG_ASYNC;
    vreq.record.ticket_id = 3u;
    vreq.record.authority_epoch = 1u;
    vreq.record.declared_caps = AGENT_ISA_CAP_OBJECT;
    vreq.record.budget_units = 2u;
    vreq.record.owner_badge_low = 1u;
    vreq.record.dispatch_nonce = 11u;
    vreq.record.input_root = input;
    vreq.record.operand_root = oid("op");
    vreq.record.capability_set_root = oid("caps");

    expect_eq_u32("invoke emits", agent_isa_adapter_invoke(&vreq, &vrep),
                  AGENT_ISA_ADAPTER_OK);
    stream = fractalos_eventbus_canonical_stream();
    expect_true("stream grew",
                stream != NULL && (uint32_t)stream->event_count > before);
    expect_eq_u32("last is nested_call",
                  stream->events[stream->event_count - 1u].event_type,
                  EVENTBUS_EVENT_NESTED_CALL);
}

static void test_emit_helper_fail_closed_without_payload(void)
{
    eventbus_event_hash_t scope = hash_label("scope-only");
    expect_eq_u32("emit requires payload",
                  agent_event_emit_nested_call(1u, 0, &scope, NULL, NULL,
                                               NULL, NULL),
                  EVENTBUS_AGENT_EVENT_ERR_INVALID);
}

int main(void)
{
    test_descriptor_persist_resolve();
    test_ipc_record_seal_replay();
    test_adapter_emits_nested_call();
    test_emit_helper_fail_closed_without_payload();
    if (g_failures) {
        fprintf(stderr, "%d failures\n", g_failures);
        return 1;
    }
    printf("All agent event integration tests passed\n");
    return 0;
}
