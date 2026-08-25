/*
 * fos-gz0.14.5.3 — mandatory Agent ISA / model-path event emission.
 */

#include "agent_event_emit.h"

#include <stddef.h>

#if defined(__GNUC__)
__attribute__((weak)) uint32_t fractalos_eventbus_record(
    struct eventbus_agent_event *event)
{
    (void)event;
    /* Suites that omit the EventBus adapter keep a no-op default. Integration
     * tests link event_bus.c (strong) or supply a failing stub for fail-closed. */
    return EVENTBUS_AGENT_EVENT_OK;
}
#else
extern uint32_t fractalos_eventbus_record(struct eventbus_agent_event *event);
#endif

void agent_event_hash_object_id(const uint32_t words[4],
                                eventbus_event_hash_t *out)
{
    uint8_t bytes[16];
    uint32_t i;
    if (out == (eventbus_event_hash_t *)0)
        return;
    for (i = 0u; i < 4u; i++) {
        bytes[i * 4u] = (uint8_t)words[i];
        bytes[i * 4u + 1u] = (uint8_t)(words[i] >> 8u);
        bytes[i * 4u + 2u] = (uint8_t)(words[i] >> 16u);
        bytes[i * 4u + 3u] = (uint8_t)(words[i] >> 24u);
    }
    eventbus_event_hash_bytes(bytes, (uint32_t)sizeof(bytes), out);
}

static uint32_t emit_typed(
    uint32_t event_type,
    uint32_t authority_epoch,
    int32_t budget_delta,
    const eventbus_event_hash_t *scope_id,
    const eventbus_event_hash_t *task_id,
    const eventbus_event_hash_t *payload_root,
    const eventbus_event_hash_t *evidence_root,
    eventbus_event_hash_t *out_event_hash)
{
    struct eventbus_agent_event event;
    uint32_t status;

    event = (struct eventbus_agent_event){0};
    event.event_type = event_type;
    event.authority_epoch = authority_epoch;
    event.budget_delta = budget_delta;
    event.flags = EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE;
    if (scope_id != (const eventbus_event_hash_t *)0)
        event.scope_id = *scope_id;
    if (task_id != (const eventbus_event_hash_t *)0)
        event.task_id = *task_id;
    if (payload_root != (const eventbus_event_hash_t *)0)
        event.payload_root = *payload_root;
    if (evidence_root != (const eventbus_event_hash_t *)0)
        event.evidence_root = *evidence_root;

    status = fractalos_eventbus_record(&event);
    if (status == EVENTBUS_AGENT_EVENT_OK
            && out_event_hash != (eventbus_event_hash_t *)0)
        *out_event_hash = event.event_hash;
    return status;
}

uint32_t agent_event_emit_nested_call(
    uint32_t authority_epoch,
    int32_t budget_delta,
    const eventbus_event_hash_t *scope_id,
    const eventbus_event_hash_t *task_id,
    const eventbus_event_hash_t *payload_root,
    const eventbus_event_hash_t *evidence_root,
    eventbus_event_hash_t *out_event_hash)
{
    if (scope_id == (const eventbus_event_hash_t *)0
            || payload_root == (const eventbus_event_hash_t *)0)
        return EVENTBUS_AGENT_EVENT_ERR_INVALID;
    return emit_typed(EVENTBUS_EVENT_NESTED_CALL, authority_epoch, budget_delta,
                      scope_id, task_id, payload_root, evidence_root,
                      out_event_hash);
}

uint32_t agent_event_emit_effect(
    uint32_t authority_epoch,
    int32_t budget_delta,
    const eventbus_event_hash_t *scope_id,
    const eventbus_event_hash_t *task_id,
    const eventbus_event_hash_t *payload_root,
    eventbus_event_hash_t *out_event_hash)
{
    if (scope_id == (const eventbus_event_hash_t *)0
            || payload_root == (const eventbus_event_hash_t *)0)
        return EVENTBUS_AGENT_EVENT_ERR_INVALID;
    return emit_typed(EVENTBUS_EVENT_EFFECT, authority_epoch, budget_delta,
                      scope_id, task_id, payload_root,
                      (const eventbus_event_hash_t *)0, out_event_hash);
}
