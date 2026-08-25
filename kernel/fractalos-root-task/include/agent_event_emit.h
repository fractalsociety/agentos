/* Mandatory Agent ISA → canonical event stream emission helpers. */
#pragma once

#include <stdint.h>

#include "contracts/eventbus_contract.h"

/* Emit a candidate-visible NESTED_CALL (or EFFECT) event. Returns
 * EVENTBUS_AGENT_EVENT_* status. On success, *out_event_hash is set when
 * non-NULL. */
uint32_t agent_event_emit_nested_call(
    uint32_t authority_epoch,
    int32_t budget_delta,
    const eventbus_event_hash_t *scope_id,
    const eventbus_event_hash_t *task_id,
    const eventbus_event_hash_t *payload_root,
    const eventbus_event_hash_t *evidence_root,
    eventbus_event_hash_t *out_event_hash);

uint32_t agent_event_emit_effect(
    uint32_t authority_epoch,
    int32_t budget_delta,
    const eventbus_event_hash_t *scope_id,
    const eventbus_event_hash_t *task_id,
    const eventbus_event_hash_t *payload_root,
    eventbus_event_hash_t *out_event_hash);

/* Hash 16 bytes of ObjectID words into an eventbus hash. */
void agent_event_hash_object_id(const uint32_t words[4],
                                eventbus_event_hash_t *out);
