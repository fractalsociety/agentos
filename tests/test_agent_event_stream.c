/* Host contract tests for the append-only Agent event stream. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../kernel/agentos-root-task/include/contracts/eventbus_contract.h"

static unsigned tests;
static unsigned failures;

static void check(int condition, const char *name)
{
    tests++;
    if (condition)
        printf("ok %u - %s\n", tests, name);
    else {
        printf("not ok %u - %s\n", tests, name);
        failures++;
    }
}

static eventbus_event_hash_t id(uint8_t value)
{
    eventbus_event_hash_t result = {{0}};
    result.bytes[0] = value;
    result.bytes[31] = (uint8_t)(value ^ 0xa5u);
    return result;
}

static struct eventbus_agent_event make_event(uint32_t type,
                                               eventbus_event_hash_t scope,
                                               eventbus_event_hash_t task,
                                               uint32_t epoch)
{
    struct eventbus_agent_event event = {0};
    event.event_type = type;
    event.authority_epoch = epoch;
    event.scope_id = scope;
    event.task_id = task;
    event.payload_root = id((uint8_t)(type + 30u));
    return event;
}

static void seal_stream(const struct eventbus_agent_event_stream *stream,
                        struct eventbus_agent_event_seal *seal)
{
    *seal = (struct eventbus_agent_event_seal){0};
    seal->event_count = stream->event_count;
    if (stream->event_count != 0u)
        seal->head = stream->events[stream->event_count - 1u].event_hash;
}

int main(void)
{
    struct eventbus_agent_event_stream stream;
    struct eventbus_agent_event_seal seal;
    struct eventbus_agent_replay first, second;
    const eventbus_event_hash_t scope = id(1u);
    const eventbus_event_hash_t task = id(2u);
    eventbus_event_hash_t evidence = id(90u);
    uint32_t status;

    puts("TAP version 14");
    eventbus_agent_event_stream_init(&stream, 7u);

    /* Every lifecycle and semantic transition is a chained event. */
    struct eventbus_agent_event event = make_event(
        EVENTBUS_EVENT_TASK, scope, task, 7u);
    status = eventbus_agent_event_stream_append(&stream, &event);
    check(status == EVENTBUS_AGENT_EVENT_OK, "task event is appended");

    event = make_event(EVENTBUS_EVENT_NESTED_CALL, scope, task, 7u);
    event.causal_parent = stream.events[stream.event_count - 1u].event_hash;
    event.payload_root = id(31u);
    check(eventbus_agent_event_stream_append(&stream, &event)
              == EVENTBUS_AGENT_EVENT_OK,
          "nested call event is hash chained");

    event = make_event(EVENTBUS_EVENT_OBJECT_TRANSITION, scope, task, 7u);
    event.causal_parent = stream.events[stream.event_count - 1u].event_hash;
    check(eventbus_agent_event_stream_append(&stream, &event)
              == EVENTBUS_AGENT_EVENT_OK,
          "object transition event is hash chained");

    event = make_event(EVENTBUS_EVENT_MAILBOX, scope, task, 7u);
    event.causal_parent = stream.events[stream.event_count - 1u].event_hash;
    check(eventbus_agent_event_stream_append(&stream, &event)
              == EVENTBUS_AGENT_EVENT_OK,
          "mailbox event is hash chained");

    event = make_event(EVENTBUS_EVENT_BUDGET, scope, task, 7u);
    event.budget_delta = 12;
    event.causal_parent = stream.events[stream.event_count - 1u].event_hash;
    check(eventbus_agent_event_stream_append(&stream, &event)
              == EVENTBUS_AGENT_EVENT_OK,
          "budget event is hash chained");

    event = make_event(EVENTBUS_EVENT_AUTHORITY_CHANGE, scope, task, 8u);
    event.causal_parent = stream.events[stream.event_count - 1u].event_hash;
    check(eventbus_agent_event_stream_append(&stream, &event)
              == EVENTBUS_AGENT_EVENT_OK,
          "authority change advances the event epoch");

    event = make_event(EVENTBUS_EVENT_TASK_VERIFY, scope, task, 8u);
    event.flags = EVENTBUS_EVENT_FLAG_TASK_VERIFY_SUCCESS
        | EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE;
    event.causal_parent = stream.events[stream.event_count - 1u].event_hash;
    event.payload_root = id(44u);
    event.evidence_root = evidence;
    check(eventbus_agent_event_stream_append(&stream, &event)
              == EVENTBUS_AGENT_EVENT_OK,
          "TASK_VERIFY records candidate-safe evidence");

    event = make_event(EVENTBUS_EVENT_EFFECT, scope, task, 8u);
    event.flags = EVENTBUS_EVENT_FLAG_EXTERNAL_EFFECT;
    event.causal_parent = stream.events[stream.event_count - 1u].event_hash;
    check(eventbus_agent_event_stream_append(&stream, &event)
              == EVENTBUS_AGENT_EVENT_OK,
          "effect event is hash chained");

    event = make_event(EVENTBUS_EVENT_CHECKPOINT, scope, task, 8u);
    event.causal_parent = stream.events[stream.event_count - 1u].event_hash;
    check(eventbus_agent_event_stream_append(&stream, &event)
              == EVENTBUS_AGENT_EVENT_OK,
          "checkpoint event is hash chained");

    event = make_event(EVENTBUS_EVENT_COMMIT, scope, task, 8u);
    event.causal_parent = stream.events[stream.event_count - 1u].event_hash;
    event.payload_root = id(44u);
    event.evidence_root = evidence;
    check(eventbus_agent_event_stream_append(&stream, &event)
              == EVENTBUS_AGENT_EVENT_OK,
          "commit event carries matching TASK_VERIFY evidence");

    event = make_event(EVENTBUS_EVENT_DISCONNECT, scope, task, 8u);
    event.causal_parent = stream.events[stream.event_count - 1u].event_hash;
    check(eventbus_agent_event_stream_append(&stream, &event)
              == EVENTBUS_AGENT_EVENT_OK,
          "disconnect event is hash chained");

    event = make_event(EVENTBUS_EVENT_RECONNECT, scope, task, 8u);
    event.causal_parent = stream.events[stream.event_count - 1u].event_hash;
    check(eventbus_agent_event_stream_append(&stream, &event)
              == EVENTBUS_AGENT_EVENT_OK,
          "reconnect event is hash chained");

    seal_stream(&stream, &seal);
    status = eventbus_agent_event_replay(stream.events, stream.event_count,
                                         &seal, 7u, &first);
    check(status == EVENTBUS_AGENT_EVENT_OK
              && first.event_count == 12u
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
          "replay accounts for every required event class");
    status = eventbus_agent_event_replay(stream.events, stream.event_count,
                                         &seal, 7u, &second);
    check(status == EVENTBUS_AGENT_EVENT_OK
              && memcmp(&first, &second, sizeof(first)) == 0,
          "replay is exact and deterministic");

    struct eventbus_agent_event copied[EVENTBUS_AGENT_EVENT_MAX_EVENTS];
    memcpy(copied, stream.events, sizeof(copied));
    copied[2].payload_root = id(201u);
    check(eventbus_agent_event_replay(copied, stream.event_count, &seal, 7u,
                                      &second) == EVENTBUS_AGENT_EVENT_ERR_TAMPER,
          "tampered event content is rejected");

    memcpy(copied, stream.events, sizeof(copied));
    {
        struct eventbus_agent_event swap = copied[1];
        copied[1] = copied[2];
        copied[2] = swap;
    }
    check(eventbus_agent_event_replay(copied, stream.event_count, &seal, 7u,
                                      &second) == EVENTBUS_AGENT_EVENT_ERR_REORDERED,
          "reordered events are rejected");
    check(eventbus_agent_event_replay(stream.events, stream.event_count - 1u,
                                      &seal, 7u, &second)
              == EVENTBUS_AGENT_EVENT_ERR_TRUNCATED,
          "truncated streams are rejected");

    memcpy(copied, stream.events, sizeof(copied));
    copied[11].scope_id = id(77u);
    copied[11].parent_scope_id = (eventbus_event_hash_t){{0}};
    eventbus_agent_event_hash(&copied[11], &copied[11].event_hash);
    check(eventbus_agent_event_replay(copied, stream.event_count, &seal, 7u,
                                      &second) == EVENTBUS_AGENT_EVENT_ERR_SCOPE,
          "cross-scope causal references are rejected");

    struct eventbus_agent_event_stream unverified;
    eventbus_agent_event_stream_init(&unverified, 7u);
    event = make_event(EVENTBUS_EVENT_TASK, scope, task, 7u);
    (void)eventbus_agent_event_stream_append(&unverified, &event);
    event = make_event(EVENTBUS_EVENT_COMMIT, scope, task, 7u);
    event.causal_parent = unverified.events[0].event_hash;
    event.payload_root = id(44u);
    event.evidence_root = evidence;
    (void)eventbus_agent_event_stream_append(&unverified, &event);
    seal_stream(&unverified, &seal);
    check(eventbus_agent_event_replay(unverified.events,
                                      unverified.event_count, &seal, 7u,
                                      &second)
              == EVENTBUS_AGENT_EVENT_ERR_COMMIT_EVIDENCE,
          "commit without matching TASK_VERIFY evidence is rejected");

    memcpy(copied, stream.events, sizeof(copied));
    seal_stream(&stream, &seal);
    copied[0].event_type = EVENTBUS_EVENT_PROMOTION_VERIFY;
    copied[0].flags = EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE;
    eventbus_agent_event_hash(&copied[0], &copied[0].event_hash);
    check(eventbus_agent_event_replay(copied, stream.event_count, &seal, 7u,
                                      &second)
              == EVENTBUS_AGENT_EVENT_ERR_PROMOTION_FORBIDDEN,
          "candidate-visible promotion verification is rejected");

    printf("1..%u\n", tests);
    return failures == 0u ? 0 : 1;
}
