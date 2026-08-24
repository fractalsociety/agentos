/*
 * Canonical EventBus adapter.
 *
 * The transport implementation was moved to services/event-bus during the
 * E9 migration.  Keep this source path as the kernel-owned adapter: it
 * preserves the old transport entry points and owns the bounded, authenticated
 * Agent execution stream used by the task and AgentFS paths below.
 */

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
#include "../../../services/event-bus/event_bus.c"
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

/* The extracted transport predates agentos.h and locally defines a handful
 * of compatibility macros.  Its definitions have already been consumed;
 * clear them before loading the canonical contract so enum names remain
 * usable by the adapter below. */
#undef MSG_EVENTBUS_INIT
#undef MSG_EVENTBUS_SUBSCRIBE
#undef MSG_EVENTBUS_UNSUBSCRIBE
#undef MSG_EVENTBUS_STATUS
#undef MSG_EVENTBUS_READY
#undef OP_PUBLISH_BATCH
#undef EVENTBUS_ERR_OVERFLOW
#undef AGENTOS_RING_MAGIC
#undef MSG_EVENT_SYSTEM_READY

#include "contracts/eventbus_contract.h"

#include <stdbool.h>
#include <stdint.h>

static struct eventbus_agent_event_stream g_agent_stream;
static bool g_agent_stream_ready;

static void eventbus_zero(void *dst, uint32_t length)
{
    uint8_t *bytes = (uint8_t *)dst;
    uint32_t i;
    for (i = 0u; i < length; i++) bytes[i] = 0u;
}

/*
 * Initialise the candidate-visible stream.  This is deliberately explicit:
 * an authority epoch and scope are pinned before the first model-visible
 * record, so a later replay cannot silently reinterpret a prefix.
 */
uint32_t agentos_eventbus_canonical_init(uint32_t authority_epoch)
{
    eventbus_agent_event_stream_init(&g_agent_stream, authority_epoch);
    g_agent_stream_ready = true;
    return EVENTBUS_AGENT_EVENT_OK;
}

const struct eventbus_agent_event_stream *
agentos_eventbus_canonical_stream(void)
{
    return g_agent_stream_ready ? &g_agent_stream : (const struct eventbus_agent_event_stream *)0;
}

uint32_t agentos_eventbus_canonical_epoch(void)
{
    if (!g_agent_stream_ready) return 0u;
    if (g_agent_stream.event_count == 0u)
        return g_agent_stream.initial_authority_epoch;
    return g_agent_stream.events[g_agent_stream.event_count - 1u]
        .authority_epoch;
}

uint32_t agentos_eventbus_canonical_seal(struct eventbus_agent_event_seal *seal)
{
    if (!g_agent_stream_ready || seal == (struct eventbus_agent_event_seal *)0)
        return EVENTBUS_AGENT_EVENT_ERR_INVALID;
    eventbus_agent_event_stream_seal(&g_agent_stream, seal);
    return EVENTBUS_AGENT_EVENT_OK;
}

uint32_t agentos_eventbus_canonical_replay(
    const struct eventbus_agent_event_seal *seal,
    struct eventbus_agent_replay *replay)
{
    if (!g_agent_stream_ready || seal == (const struct eventbus_agent_event_seal *)0
            || replay == (struct eventbus_agent_replay *)0)
        return EVENTBUS_AGENT_EVENT_ERR_INVALID;
    return eventbus_agent_event_replay(g_agent_stream.events,
                                       g_agent_stream.event_count, seal,
                                       g_agent_stream.initial_authority_epoch,
                                       replay);
}

/*
 * Single writer entry point used by PD adapters.  The caller supplies the
 * semantic fields but never supplies the chain fields: schema, position,
 * previous_hash and event_hash are always written here.  A failed append is
 * transactional; no invalid commit or cross-scope record remains observable.
 */
uint32_t agentos_eventbus_record(struct eventbus_agent_event *event)
{
    struct eventbus_agent_event saved_event;
    uint64_t saved_count;
    struct eventbus_agent_event_seal seal;
    struct eventbus_agent_replay replay;
    uint32_t status;

    if (event == (struct eventbus_agent_event *)0)
        return EVENTBUS_AGENT_EVENT_ERR_INVALID;
    if (!g_agent_stream_ready)
        agentos_eventbus_canonical_init(event->authority_epoch);
    if (g_agent_stream.event_count >= EVENTBUS_AGENT_EVENT_MAX_EVENTS)
        return EVENTBUS_AGENT_EVENT_ERR_INVALID;

    /* Candidate-visible records may never smuggle the hidden promotion bit. */
    if ((event->flags & EVENTBUS_EVENT_FLAG_PROMOTION_INTERNAL) != 0u
            || event->event_type == EVENTBUS_EVENT_PROMOTION_VERIFY)
        return EVENTBUS_AGENT_EVENT_ERR_PROMOTION_FORBIDDEN;

    saved_event = *event;
    saved_count = g_agent_stream.event_count;
    status = eventbus_agent_event_stream_append(&g_agent_stream, event);
    if (status != EVENTBUS_AGENT_EVENT_OK)
        return status;

    eventbus_agent_event_stream_seal(&g_agent_stream, &seal);
    status = eventbus_agent_event_replay(g_agent_stream.events,
                                         g_agent_stream.event_count, &seal,
                                         g_agent_stream.initial_authority_epoch,
                                         &replay);
    if (status != EVENTBUS_AGENT_EVENT_OK) {
        g_agent_stream.event_count = saved_count;
        *event = saved_event;
        eventbus_zero(&g_agent_stream.events[saved_count],
                      (uint32_t)sizeof(g_agent_stream.events[saved_count]));
        return status;
    }
    return EVENTBUS_AGENT_EVENT_OK;
}

/* Stable alias for adapters that use the shorter stream vocabulary. */
uint32_t agent_event_record(struct eventbus_agent_event *event)
{
    return agentos_eventbus_record(event);
}
