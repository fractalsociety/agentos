/*
 * eventbus_test.c — contract tests for the EventBus PD
 *
 * Covered opcodes:
 *   MSG_EVENTBUS_INIT        (0x0001) — initialise the event bus
 *   MSG_EVENTBUS_SUBSCRIBE   (0x0002) — subscribe a channel to events
 *   MSG_EVENTBUS_UNSUBSCRIBE (0x0003) — unsubscribe a channel
 *   MSG_EVENTBUS_STATUS      (0x0004) — query ring buffer status
 *
 * Channel: MONITOR_CH_EVENTBUS (1) from the controller's perspective.
 *
 * Copyright (c) 2026 The FractalOS Project
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "../harness/test_framework.h"
#include "../../kernel/fractalos-root-task/include/fractalos.h"
#include "../../kernel/fractalos-root-task/include/contracts/agent_task_contract.h"
#include "../../kernel/fractalos-root-task/include/contracts/eventbus_contract.h"

#define ASSERT_EVENT_CONTRACT(condition, name)                         \
    do {                                                               \
        if (condition) _tf_ok(name);                                   \
        else _tf_fail_point(name, "canonical event contract assertion"); \
    } while (0)

static eventbus_event_hash_t eventbus_test_id(uint8_t value)
{
    eventbus_event_hash_t result = {{0}};
    result.bytes[0] = value;
    result.bytes[31] = (uint8_t)(value ^ 0xa5u);
    return result;
}

static struct eventbus_agent_event eventbus_test_event(
    uint32_t type, eventbus_event_hash_t scope,
    eventbus_event_hash_t task, uint32_t epoch)
{
    struct eventbus_agent_event event = {0};
    event.event_type = type;
    event.authority_epoch = epoch;
    event.scope_id = scope;
    event.task_id = task;
    event.payload_root = eventbus_test_id((uint8_t)(type + 30u));
    return event;
}

static void eventbus_test_append_chain(
    struct eventbus_agent_event_stream *stream, uint32_t type,
    eventbus_event_hash_t scope, eventbus_event_hash_t task,
    eventbus_event_hash_t evidence)
{
    struct eventbus_agent_event event = eventbus_test_event(
        type, scope, task,
        type == EVENTBUS_EVENT_AUTHORITY_CHANGE
            ? (stream->initial_authority_epoch + 1u)
            : (stream->event_count >= 6u
                   ? stream->initial_authority_epoch + 1u
                   : stream->initial_authority_epoch));
    if (stream->event_count != 0u)
        event.causal_parent = stream->events[stream->event_count - 1u].event_hash;
    if (type == EVENTBUS_EVENT_TASK_VERIFY) {
        event.flags = EVENTBUS_EVENT_FLAG_TASK_VERIFY_SUCCESS
            | EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE;
        event.payload_root = eventbus_test_id(44u);
        event.evidence_root = evidence;
    } else if (type == EVENTBUS_EVENT_COMMIT) {
        event.payload_root = eventbus_test_id(44u);
        event.evidence_root = evidence;
    }
    (void)eventbus_agent_event_stream_append(stream, &event);
}

void run_eventbus_tests(microkit_channel ch)
{
    TEST_SECTION("eventbus");

    /* STATUS — must succeed; the root task maps the ring on target (fos-gom)
     * and event_bus_main initialises it before entering its server loop. */
    ASSERT_IPC_OK(ch, MSG_EVENTBUS_STATUS, "eventbus: STATUS returns ok");

    /* SUBSCRIBE — subscribe the monitor channel (badge 0 = self). */
    microkit_mr_set(0, (uint64_t)MSG_EVENTBUS_SUBSCRIBE);
    microkit_mr_set(1, 0);  /* subscriber channel id */
    (void)microkit_ppcall(ch, microkit_msginfo_new(MSG_EVENTBUS_SUBSCRIBE, 2));
    {
        uint64_t rc = microkit_mr_get(0);
        if (rc == AOS_OK || rc == AOS_ERR_EXISTS) {
            _tf_ok("eventbus: SUBSCRIBE returns ok or already-subscribed");
        } else {
            _tf_fail_point("eventbus: SUBSCRIBE returns ok or already-subscribed",
                           "unexpected error code");
        }
    }

    /* UNSUBSCRIBE — should succeed (or return not-found if not subscribed). */
    microkit_mr_set(0, (uint64_t)MSG_EVENTBUS_UNSUBSCRIBE);
    microkit_mr_set(1, 0);
    (void)microkit_ppcall(ch, microkit_msginfo_new(MSG_EVENTBUS_UNSUBSCRIBE, 2));
    {
        uint64_t rc = microkit_mr_get(0);
        if (rc == AOS_OK || rc == AOS_ERR_NOT_FOUND) {
            _tf_ok("eventbus: UNSUBSCRIBE returns ok or not-found");
        } else {
            _tf_fail_point("eventbus: UNSUBSCRIBE returns ok or not-found",
                           "unexpected error code");
        }
    }

    /* INIT — reinitialise (idempotent on a running system). */
    ASSERT_IPC_OK_OR_ERR(ch, MSG_EVENTBUS_INIT, AOS_ERR_BUSY,
                         "eventbus: INIT returns ok or busy");

    /* STATUS again — confirm bus is still responsive after subscribe/unsubscribe. */
    ASSERT_IPC_OK(ch, MSG_EVENTBUS_STATUS, "eventbus: STATUS still ok after ops");

    /* Canonical Agent event schema checks.  EventBus transports these records;
     * the durable stream contract authenticates and replays them above it. */
    ASSERT_EVENT_CONTRACT(EVENTBUS_AGENT_EVENT_SCHEMA_VERSION == 2u,
                          "eventbus: canonical event schema is version 2");
    ASSERT_EVENT_CONTRACT(EVENTBUS_EVENT_TASK < EVENTBUS_EVENT_RECONNECT
                              && EVENTBUS_EVENT_TASK_VERIFY
                                  != EVENTBUS_EVENT_COMMIT,
                          "eventbus: lifecycle and TASK_VERIFY event types are distinct");
    ASSERT_EVENT_CONTRACT(EVENTBUS_EVENT_FLAG_KNOWN_MASK
                    == (EVENTBUS_EVENT_FLAG_TASK_VERIFY_SUCCESS
                        | EVENTBUS_EVENT_FLAG_EXTERNAL_EFFECT
                        | EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE
                        | EVENTBUS_EVENT_FLAG_PROMOTION_INTERNAL),
                          "eventbus: event flags fail closed");
    ASSERT_EVENT_CONTRACT(EVENTBUS_AGENT_EVENT_ERR_TAMPER
                    != EVENTBUS_AGENT_EVENT_ERR_TRUNCATED
                    && EVENTBUS_AGENT_EVENT_ERR_REORDERED
                        != EVENTBUS_AGENT_EVENT_ERR_SCOPE
                    && EVENTBUS_AGENT_EVENT_ERR_COMMIT_EVIDENCE
                        != EVENTBUS_AGENT_EVENT_ERR_PROMOTION_FORBIDDEN,
                          "eventbus: replay failures are distinguishable");

    ASSERT_EVENT_CONTRACT(AGENT_TASK_VERIFY_VERSION_V1 == 1u
                              && AGENT_TASK_VERIFY_VERSION_V2 == 2u
                              && AGENT_TASK_VERIFY_VERSION
                                  == AGENT_TASK_VERIFY_VERSION_V2,
                          "eventbus: TASK_VERIFY transition is explicit v1 to v2");
    ASSERT_EVENT_CONTRACT(AGENT_TASK_VERIFY_V1_DECODE_ONLY
                              && AGENT_TASK_VERIFY_V2_CANONICAL,
                          "eventbus: legacy VERIFY cannot grant promotion");

    /* Exercise the canonical stream through the EventBus contract's public
     * helpers as well as the IPC endpoint above.  The list is deliberately
     * explicit: adding an event class requires updating this contract test. */
    {
        static struct eventbus_agent_event_stream stream;
        static struct eventbus_agent_event_stream tampered;
        static struct eventbus_agent_event_seal seal;
        static struct eventbus_agent_replay first, second;
        const eventbus_event_hash_t scope = eventbus_test_id(1u);
        const eventbus_event_hash_t task = eventbus_test_id(2u);
        const eventbus_event_hash_t evidence = eventbus_test_id(90u);
        const uint32_t types[] = {
            EVENTBUS_EVENT_TASK, EVENTBUS_EVENT_NESTED_CALL,
            EVENTBUS_EVENT_OBJECT_TRANSITION, EVENTBUS_EVENT_MAILBOX,
            EVENTBUS_EVENT_BUDGET, EVENTBUS_EVENT_AUTHORITY_CHANGE,
            EVENTBUS_EVENT_TASK_VERIFY, EVENTBUS_EVENT_EFFECT,
            EVENTBUS_EVENT_CHECKPOINT, EVENTBUS_EVENT_COMMIT,
            EVENTBUS_EVENT_DISCONNECT, EVENTBUS_EVENT_RECONNECT,
        };
        eventbus_agent_event_stream_init(&stream, 1u);
        for (uint32_t i = 0u; i < sizeof(types) / sizeof(types[0]); i++)
            eventbus_test_append_chain(&stream, types[i], scope, task, evidence);
        eventbus_agent_event_stream_seal(&stream, &seal);
        ASSERT_EVENT_CONTRACT(stream.event_count == 12u
                                  && eventbus_agent_event_replay(
                                      stream.events, stream.event_count, &seal,
                                      1u, &first) == EVENTBUS_AGENT_EVENT_OK
                                  && first.task_events == 1u
                                  && first.nested_call_events == 1u
                                  && first.object_events == 1u
                                  && first.mailbox_events == 1u
                                  && first.budget_events == 1u
                                  && first.authority_events == 1u
                                  && first.verification_events == 1u
                                  && first.effect_events == 1u
                                  && first.checkpoint_events == 1u
                                  && first.commit_events == 1u
                                  && first.disconnect_events == 1u
                                  && first.reconnect_events == 1u,
                              "eventbus: every Agent transition is chained");
        ASSERT_EVENT_CONTRACT(eventbus_agent_event_replay(
                                  stream.events, stream.event_count, &seal,
                                  1u, &second) == EVENTBUS_AGENT_EVENT_OK
                                  && eventbus_event_hash_equal(
                                      &first.projection_hash,
                                      &second.projection_hash),
                              "eventbus: sealed replay is exact");

        tampered = stream;
        tampered.events[2].payload_root = eventbus_test_id(201u);
        ASSERT_EVENT_CONTRACT(eventbus_agent_event_replay(
                                  tampered.events, tampered.event_count, &seal,
                                  1u, &second) == EVENTBUS_AGENT_EVENT_ERR_TAMPER,
                              "eventbus: tamper is rejected");

        struct eventbus_agent_event swap = stream.events[1];
        tampered = stream;
        tampered.events[1] = tampered.events[2];
        tampered.events[2] = swap;
        ASSERT_EVENT_CONTRACT(eventbus_agent_event_replay(
                                  tampered.events, tampered.event_count, &seal,
                                  1u, &second) == EVENTBUS_AGENT_EVENT_ERR_REORDERED,
                              "eventbus: reorder is rejected");
        ASSERT_EVENT_CONTRACT(eventbus_agent_event_replay(
                                  stream.events, stream.event_count - 1u, &seal,
                                  1u, &second) == EVENTBUS_AGENT_EVENT_ERR_TRUNCATED,
                              "eventbus: truncation is rejected");

        tampered = stream;
        tampered.events[11].scope_id = eventbus_test_id(77u);
        tampered.events[11].parent_scope_id = (eventbus_event_hash_t){{0}};
        eventbus_agent_event_hash(&tampered.events[11],
                                  &tampered.events[11].event_hash);
        ASSERT_EVENT_CONTRACT(eventbus_agent_event_replay(
                                  tampered.events, tampered.event_count, &seal,
                                  1u, &second) == EVENTBUS_AGENT_EVENT_ERR_SCOPE,
                              "eventbus: cross-scope references are rejected");
    }

    {
        static struct eventbus_agent_event_stream stream;
        static struct eventbus_agent_event_seal seal;
        static struct eventbus_agent_replay replay;
        const eventbus_event_hash_t scope = eventbus_test_id(3u);
        const eventbus_event_hash_t task = eventbus_test_id(4u);
        const eventbus_event_hash_t evidence = eventbus_test_id(90u);
        eventbus_agent_event_stream_init(&stream, 1u);
        eventbus_test_append_chain(&stream, EVENTBUS_EVENT_TASK,
                                   scope, task, evidence);
        eventbus_test_append_chain(&stream, EVENTBUS_EVENT_COMMIT,
                                   scope, task, evidence);
        eventbus_agent_event_stream_seal(&stream, &seal);
        ASSERT_EVENT_CONTRACT(eventbus_agent_event_replay(
                                  stream.events, stream.event_count, &seal,
                                  1u, &replay)
                                  == EVENTBUS_AGENT_EVENT_ERR_COMMIT_EVIDENCE,
                              "eventbus: commit requires TASK_VERIFY evidence");

        struct eventbus_agent_event promotion = eventbus_test_event(
            EVENTBUS_EVENT_PROMOTION_VERIFY, scope, task, 1u);
        promotion.schema_version = EVENTBUS_AGENT_EVENT_SCHEMA_VERSION;
        promotion.position = 1u;
        promotion.flags = EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE;
        eventbus_agent_event_hash(&promotion, &promotion.event_hash);
        stream = (struct eventbus_agent_event_stream){0};
        stream.initial_authority_epoch = 1u;
        stream.events[0] = promotion;
        stream.event_count = 1u;
        seal.event_count = 1u;
        seal.head = promotion.event_hash;
        ASSERT_EVENT_CONTRACT(eventbus_agent_event_replay(
                                  stream.events, stream.event_count, &seal,
                                  1u, &replay)
                                  == EVENTBUS_AGENT_EVENT_ERR_PROMOTION_FORBIDDEN,
                              "eventbus: candidate-visible PROMOTION_VERIFY is forbidden");
    }
}
