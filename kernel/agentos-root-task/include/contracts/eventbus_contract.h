/*
 * EventBus IPC Contract
 *
 * The EventBus is the publish-subscribe backbone of agentOS.
 * All PDs that need to exchange asynchronous events go through EventBus.
 *
 * Channel: EVENTBUS_CH_* (see agentos.h)
 * Opcodes: MSG_EVENTBUS_* (see agentos.h)
 *
 * Invariants:
 *   - Subscribers read the ring directly (zero-copy); EventBus only writes.
 *   - PUBLISH_BATCH is atomic: all events in a batch are written before any
 *     subscriber is notified.
 *   - A subscriber that falls behind loses events (overflow_count incremented).
 *   - MSG_EVENTBUS_QUERY_SUBSCRIBERS is read-only; it does not modify state.
 *   - Ordering: INIT must be the first message sent to EventBus at boot.
 */

#pragma once
#include "../agentos.h"

/*
 * Canonical Agent event stream
 *
 * EventBus is the transport/notification layer.  The records below are the
 * durable execution schema carried by that layer: an event is accepted only
 * once, has a monotonically increasing position, and commits to the complete
 * preceding record through previous_hash.  Object and scope identifiers are
 * opaque content-addressed values; no path, provider locator, or transient
 * pointer is part of the event contract.
 *
 * The small freestanding hash below is deliberately an ABI-level test hash,
 * not a replacement for the production SHA-256 object store.  A production
 * EventBus implementation must calculate the same 32-byte field with its
 * configured cryptographic digest and must never accept a caller-supplied
 * event_hash without recomputing it.
 */

#define EVENTBUS_AGENT_EVENT_SCHEMA_VERSION 2u
#define EVENTBUS_AGENT_EVENT_MAX_SCOPES     32u
#define EVENTBUS_AGENT_EVENT_MAX_EVENTS     64u
#define EVENTBUS_AGENT_EVENT_HASH_BYTES     32u
#define EVENTBUS_AGENT_EVENT_CANONICAL_BYTES 252u

/* TASK_VERIFY is the v2 spelling of the candidate-facing verification
 * record.  v1 VERIFY may be decoded by a compatibility adapter only; it is
 * never an event type and can never authorize promotion. */
#define EVENTBUS_TASK_VERIFY_VERSION_V1 1u
#define EVENTBUS_TASK_VERIFY_VERSION_V2 2u
#define EVENTBUS_TASK_VERIFY_VERSION EVENTBUS_TASK_VERIFY_VERSION_V2

typedef struct eventbus_event_hash {
    uint8_t bytes[EVENTBUS_AGENT_EVENT_HASH_BYTES];
} eventbus_event_hash_t;

enum eventbus_agent_event_type {
    EVENTBUS_EVENT_TASK = 1u,
    EVENTBUS_EVENT_NESTED_CALL = 2u,
    EVENTBUS_EVENT_OBJECT_TRANSITION = 3u,
    EVENTBUS_EVENT_MAILBOX = 4u,
    EVENTBUS_EVENT_BUDGET = 5u,
    EVENTBUS_EVENT_AUTHORITY_CHANGE = 6u,
    EVENTBUS_EVENT_TASK_VERIFY = 7u,
    EVENTBUS_EVENT_EFFECT = 8u,
    EVENTBUS_EVENT_CHECKPOINT = 9u,
    EVENTBUS_EVENT_COMMIT = 10u,
    EVENTBUS_EVENT_DISCONNECT = 11u,
    EVENTBUS_EVENT_RECONNECT = 12u,
};

/* Reserved outside the candidate-visible event vocabulary. */
#define EVENTBUS_EVENT_PROMOTION_VERIFY 0x100u
#define EVENTBUS_AGENT_EVENT_CLASS_FIRST EVENTBUS_EVENT_TASK
#define EVENTBUS_AGENT_EVENT_CLASS_LAST  EVENTBUS_EVENT_RECONNECT

/* Names used by the Agent IR and by the v1 canonical-event design. */
#define EVENTBUS_EVENT_TASK_STATE       EVENTBUS_EVENT_TASK
#define EVENTBUS_EVENT_CAPABILITY_CALL  EVENTBUS_EVENT_NESTED_CALL
#define EVENTBUS_EVENT_OBJECT_WRITE     EVENTBUS_EVENT_OBJECT_TRANSITION
#define EVENTBUS_EVENT_MESSAGE          EVENTBUS_EVENT_MAILBOX
#define EVENTBUS_EVENT_BUDGET_CHANGE    EVENTBUS_EVENT_BUDGET
#define EVENTBUS_EVENT_CAPABILITY_CHANGE EVENTBUS_EVENT_AUTHORITY_CHANGE
#define EVENTBUS_EVENT_TASK_VERIFICATION EVENTBUS_EVENT_TASK_VERIFY

/* Short aliases keep the schema usable by Agent IR contract tests without
 * making the transport opcode namespace part of the Agent ISA. */
#define AGENT_EVENT_TASK              EVENTBUS_EVENT_TASK
#define AGENT_EVENT_NESTED_CALL       EVENTBUS_EVENT_NESTED_CALL
#define AGENT_EVENT_OBJECT_TRANSITION EVENTBUS_EVENT_OBJECT_TRANSITION
#define AGENT_EVENT_MAILBOX           EVENTBUS_EVENT_MAILBOX
#define AGENT_EVENT_BUDGET            EVENTBUS_EVENT_BUDGET
#define AGENT_EVENT_AUTHORITY_CHANGE  EVENTBUS_EVENT_AUTHORITY_CHANGE
#define AGENT_EVENT_TASK_VERIFY       EVENTBUS_EVENT_TASK_VERIFY
#define AGENT_EVENT_EFFECT            EVENTBUS_EVENT_EFFECT
#define AGENT_EVENT_CHECKPOINT        EVENTBUS_EVENT_CHECKPOINT
#define AGENT_EVENT_COMMIT            EVENTBUS_EVENT_COMMIT
#define AGENT_EVENT_DISCONNECT        EVENTBUS_EVENT_DISCONNECT
#define AGENT_EVENT_RECONNECT         EVENTBUS_EVENT_RECONNECT

#define EVENTBUS_EVENT_FLAG_TASK_VERIFY_SUCCESS (1u << 0)
#define EVENTBUS_EVENT_FLAG_EXTERNAL_EFFECT    (1u << 1)
#define EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE  (1u << 2)
#define EVENTBUS_EVENT_FLAG_PROMOTION_INTERNAL (1u << 3)
#define EVENTBUS_EVENT_FLAG_KNOWN_MASK          ((1u << 4) - 1u)

enum eventbus_agent_event_error {
    EVENTBUS_AGENT_EVENT_OK = 0u,
    EVENTBUS_AGENT_EVENT_ERR_INVALID = 1u,
    EVENTBUS_AGENT_EVENT_ERR_VERSION = 2u,
    EVENTBUS_AGENT_EVENT_ERR_TAMPER = 3u,
    EVENTBUS_AGENT_EVENT_ERR_TRUNCATED = 4u,
    EVENTBUS_AGENT_EVENT_ERR_REORDERED = 5u,
    EVENTBUS_AGENT_EVENT_ERR_SCOPE = 6u,
    EVENTBUS_AGENT_EVENT_ERR_COMMIT_EVIDENCE = 7u,
    EVENTBUS_AGENT_EVENT_ERR_PROMOTION_FORBIDDEN = 8u,
    EVENTBUS_AGENT_EVENT_ERR_AUTHORITY = 9u,
};

struct eventbus_agent_event {
    uint32_t schema_version;
    uint32_t event_type;
    uint64_t position;
    uint32_t authority_epoch;
    int32_t budget_delta;
    uint32_t flags;
    eventbus_event_hash_t scope_id;
    eventbus_event_hash_t parent_scope_id;
    eventbus_event_hash_t task_id;
    eventbus_event_hash_t causal_parent;
    eventbus_event_hash_t payload_root;
    eventbus_event_hash_t evidence_root;
    eventbus_event_hash_t previous_hash;
    eventbus_event_hash_t event_hash;
};

struct eventbus_agent_event_seal {
    uint64_t event_count;
    eventbus_event_hash_t head;
};

struct eventbus_agent_event_stream {
    uint32_t initial_authority_epoch;
    uint64_t event_count;
    struct eventbus_agent_event events[EVENTBUS_AGENT_EVENT_MAX_EVENTS];
};

struct eventbus_agent_replay {
    uint64_t event_count;
    uint32_t task_events;
    uint32_t nested_call_events;
    uint32_t object_events;
    uint32_t mailbox_events;
    uint32_t budget_events;
    uint32_t authority_events;
    uint32_t verification_events;
    uint32_t effect_events;
    uint32_t checkpoint_events;
    uint32_t commit_events;
    uint32_t disconnect_events;
    uint32_t reconnect_events;
    uint32_t authority_epoch;
    eventbus_event_hash_t head;
    eventbus_event_hash_t projection_hash;
};

static inline int eventbus_event_hash_equal(const eventbus_event_hash_t *a,
                                            const eventbus_event_hash_t *b)
{
    uint8_t different = 0u;
    uint32_t i;
    if (a == (const eventbus_event_hash_t *)0
            || b == (const eventbus_event_hash_t *)0)
        return 0;
    for (i = 0u; i < EVENTBUS_AGENT_EVENT_HASH_BYTES; i++)
        different |= (uint8_t)(a->bytes[i] ^ b->bytes[i]);
    return different == 0u;
}

static inline int eventbus_event_hash_zero(const eventbus_event_hash_t *a)
{
    static const eventbus_event_hash_t zero = {{0}};
    return eventbus_event_hash_equal(a, &zero);
}

static inline void eventbus_event_hash_bytes(const uint8_t *bytes,
                                             uint32_t length,
                                             eventbus_event_hash_t *out)
{
    /* Four independent FNV-1a lanes give a stable 256-bit test digest. */
    uint64_t lanes[4] = {
        UINT64_C(0xcbf29ce484222325), UINT64_C(0x84222325cbf29ce4),
        UINT64_C(0x9e3779b185ebca87), UINT64_C(0x517cc1b727220a95),
    };
    uint32_t i;
    if (out == (eventbus_event_hash_t *)0)
        return;
    for (i = 0u; i < length; i++) {
        uint32_t lane = i & 3u;
        lanes[lane] ^= bytes[i];
        lanes[lane] *= UINT64_C(0x100000001b3);
        lanes[(lane + 1u) & 3u] ^= lanes[lane] >> 29u;
    }
    for (i = 0u; i < 4u; i++) {
        uint64_t value = lanes[i];
        uint32_t j;
        for (j = 0u; j < 8u; j++)
            out->bytes[i * 8u + j] = (uint8_t)(value >> (j * 8u));
    }
}

static inline void eventbus_event_hash_put_u32(uint8_t *bytes,
                                               uint32_t *offset,
                                               uint32_t value)
{
    bytes[(*offset)++] = (uint8_t)value;
    bytes[(*offset)++] = (uint8_t)(value >> 8u);
    bytes[(*offset)++] = (uint8_t)(value >> 16u);
    bytes[(*offset)++] = (uint8_t)(value >> 24u);
}

static inline void eventbus_event_hash_put_u64(uint8_t *bytes,
                                               uint32_t *offset,
                                               uint64_t value)
{
    uint32_t i;
    for (i = 0u; i < 8u; i++)
        bytes[(*offset)++] = (uint8_t)(value >> (i * 8u));
}

static inline void eventbus_event_hash_put_hash(
    uint8_t *bytes, uint32_t *offset, const eventbus_event_hash_t *value)
{
    uint32_t i;
    for (i = 0u; i < EVENTBUS_AGENT_EVENT_HASH_BYTES; i++)
        bytes[(*offset)++] = value->bytes[i];
}

static inline void eventbus_agent_event_hash(
    const struct eventbus_agent_event *event, eventbus_event_hash_t *out)
{
    uint8_t canonical[EVENTBUS_AGENT_EVENT_CANONICAL_BYTES];
    uint32_t offset = 0u;
    if (event == (const struct eventbus_agent_event *)0
            || out == (eventbus_event_hash_t *)0)
        return;
    /* Never hash C padding: this is the wire/canonical representation and is
     * therefore identical on x86_64, AArch64, and freestanding compilers. */
    eventbus_event_hash_put_u32(canonical, &offset, event->schema_version);
    eventbus_event_hash_put_u32(canonical, &offset, event->event_type);
    eventbus_event_hash_put_u64(canonical, &offset, event->position);
    eventbus_event_hash_put_u32(canonical, &offset, event->authority_epoch);
    eventbus_event_hash_put_u32(canonical, &offset, (uint32_t)event->budget_delta);
    eventbus_event_hash_put_u32(canonical, &offset, event->flags);
    eventbus_event_hash_put_hash(canonical, &offset, &event->scope_id);
    eventbus_event_hash_put_hash(canonical, &offset, &event->parent_scope_id);
    eventbus_event_hash_put_hash(canonical, &offset, &event->task_id);
    eventbus_event_hash_put_hash(canonical, &offset, &event->causal_parent);
    eventbus_event_hash_put_hash(canonical, &offset, &event->payload_root);
    eventbus_event_hash_put_hash(canonical, &offset, &event->evidence_root);
    eventbus_event_hash_put_hash(canonical, &offset, &event->previous_hash);
    eventbus_event_hash_bytes(canonical, offset, out);
}

static inline void eventbus_agent_event_stream_init(
    struct eventbus_agent_event_stream *stream, uint32_t authority_epoch)
{
    if (stream == (struct eventbus_agent_event_stream *)0)
        return;
    *stream = (struct eventbus_agent_event_stream){0};
    stream->initial_authority_epoch = authority_epoch;
}

static inline uint32_t eventbus_agent_event_stream_append(
    struct eventbus_agent_event_stream *stream,
    struct eventbus_agent_event *event)
{
    eventbus_event_hash_t head = {{0}};
    if (stream == (struct eventbus_agent_event_stream *)0
            || event == (struct eventbus_agent_event *)0)
        return EVENTBUS_AGENT_EVENT_ERR_INVALID;
    if (stream->event_count >= EVENTBUS_AGENT_EVENT_MAX_EVENTS)
        return EVENTBUS_AGENT_EVENT_ERR_INVALID;
    if (event->event_type < EVENTBUS_EVENT_TASK
            || event->event_type > EVENTBUS_EVENT_RECONNECT)
        return event->event_type == EVENTBUS_EVENT_PROMOTION_VERIFY
            ? EVENTBUS_AGENT_EVENT_ERR_PROMOTION_FORBIDDEN
            : EVENTBUS_AGENT_EVENT_ERR_INVALID;
    if ((event->flags & ~EVENTBUS_EVENT_FLAG_KNOWN_MASK) != 0u)
        return EVENTBUS_AGENT_EVENT_ERR_INVALID;
    if ((event->flags & EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE)
            && (event->flags & EVENTBUS_EVENT_FLAG_PROMOTION_INTERNAL))
        return EVENTBUS_AGENT_EVENT_ERR_PROMOTION_FORBIDDEN;
    if (eventbus_event_hash_zero(&event->scope_id))
        return EVENTBUS_AGENT_EVENT_ERR_SCOPE;
    if (stream->event_count != 0u)
        head = stream->events[stream->event_count - 1u].event_hash;
    event->schema_version = EVENTBUS_AGENT_EVENT_SCHEMA_VERSION;
    event->position = stream->event_count + 1u;
    event->previous_hash = head;
    eventbus_agent_event_hash(event, &event->event_hash);
    stream->events[stream->event_count++] = *event;
    return EVENTBUS_AGENT_EVENT_OK;
}

static inline void eventbus_agent_event_stream_seal(
    const struct eventbus_agent_event_stream *stream,
    struct eventbus_agent_event_seal *seal)
{
    if (stream == (const struct eventbus_agent_event_stream *)0
            || seal == (struct eventbus_agent_event_seal *)0)
        return;
    *seal = (struct eventbus_agent_event_seal){0};
    seal->event_count = stream->event_count;
    if (stream->event_count != 0u)
        seal->head = stream->events[stream->event_count - 1u].event_hash;
}

static inline int eventbus_event_type_known(uint32_t type)
{
    return type >= EVENTBUS_EVENT_TASK && type <= EVENTBUS_EVENT_RECONNECT;
}

static inline uint32_t eventbus_event_count_one(
    struct eventbus_agent_replay *replay,
    const struct eventbus_agent_event *event)
{
    switch (event->event_type) {
    case EVENTBUS_EVENT_TASK: replay->task_events++; break;
    case EVENTBUS_EVENT_NESTED_CALL: replay->nested_call_events++; break;
    case EVENTBUS_EVENT_OBJECT_TRANSITION: replay->object_events++; break;
    case EVENTBUS_EVENT_MAILBOX: replay->mailbox_events++; break;
    case EVENTBUS_EVENT_BUDGET: replay->budget_events++; break;
    case EVENTBUS_EVENT_AUTHORITY_CHANGE: replay->authority_events++; break;
    case EVENTBUS_EVENT_TASK_VERIFY: replay->verification_events++; break;
    case EVENTBUS_EVENT_EFFECT: replay->effect_events++; break;
    case EVENTBUS_EVENT_CHECKPOINT: replay->checkpoint_events++; break;
    case EVENTBUS_EVENT_COMMIT: replay->commit_events++; break;
    case EVENTBUS_EVENT_DISCONNECT: replay->disconnect_events++; break;
    case EVENTBUS_EVENT_RECONNECT: replay->reconnect_events++; break;
    default: return EVENTBUS_AGENT_EVENT_ERR_INVALID;
    }
    return EVENTBUS_AGENT_EVENT_OK;
}

/*
 * Verify and replay a sealed range.  A caller cannot turn a prefix into a
 * complete history, reorder records, reference a sibling scope, or publish a
 * commit without the successful TASK_VERIFY evidence for the same task and
 * candidate root.  PROMOTION_VERIFY is intentionally not an event type in
 * this candidate-visible contract; the reserved internal flag is rejected
 * when exposed to the candidate.
 */
static inline uint32_t eventbus_agent_event_replay(
    const struct eventbus_agent_event *events, uint64_t count,
    const struct eventbus_agent_event_seal *seal, uint32_t initial_epoch,
    struct eventbus_agent_replay *replay)
{
    eventbus_event_hash_t previous = {{0}};
    eventbus_event_hash_t verified_task = {{0}};
    eventbus_event_hash_t verified_candidate = {{0}};
    eventbus_event_hash_t verified_evidence = {{0}};
    eventbus_event_hash_t verified_scope = {{0}};
    eventbus_event_hash_t scopes[EVENTBUS_AGENT_EVENT_MAX_SCOPES];
    eventbus_event_hash_t parents[EVENTBUS_AGENT_EVENT_MAX_SCOPES];
    eventbus_event_hash_t event_hashes[EVENTBUS_AGENT_EVENT_MAX_EVENTS];
    eventbus_event_hash_t event_scopes[EVENTBUS_AGENT_EVENT_MAX_EVENTS];
    uint32_t scope_count = 0u;
    uint32_t verified = 0u;
    uint32_t i;

    if (events == (const struct eventbus_agent_event *)0
            || seal == (const struct eventbus_agent_event_seal *)0
            || replay == (struct eventbus_agent_replay *)0)
        return EVENTBUS_AGENT_EVENT_ERR_INVALID;
    if (count != seal->event_count)
        return count < seal->event_count
            ? EVENTBUS_AGENT_EVENT_ERR_TRUNCATED
            : EVENTBUS_AGENT_EVENT_ERR_INVALID;
    *replay = (struct eventbus_agent_replay){0};
    replay->authority_epoch = initial_epoch;

    for (i = 0u; i < count; i++) {
        const struct eventbus_agent_event *event = &events[i];
        eventbus_event_hash_t computed;
        if (event->schema_version != EVENTBUS_AGENT_EVENT_SCHEMA_VERSION)
            return EVENTBUS_AGENT_EVENT_ERR_VERSION;
        if (event->position != (uint64_t)i + 1u)
            return EVENTBUS_AGENT_EVENT_ERR_REORDERED;
        if (!eventbus_event_hash_equal(&event->previous_hash, &previous))
            return EVENTBUS_AGENT_EVENT_ERR_REORDERED;
        eventbus_agent_event_hash(event, &computed);
        if (!eventbus_event_hash_equal(&computed, &event->event_hash))
            return EVENTBUS_AGENT_EVENT_ERR_TAMPER;
        if (event->event_type == EVENTBUS_EVENT_PROMOTION_VERIFY
                && (event->flags & EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE))
            return EVENTBUS_AGENT_EVENT_ERR_PROMOTION_FORBIDDEN;
        if (!eventbus_event_type_known(event->event_type))
            return EVENTBUS_AGENT_EVENT_ERR_INVALID;
        if ((event->flags & ~EVENTBUS_EVENT_FLAG_KNOWN_MASK) != 0u)
            return EVENTBUS_AGENT_EVENT_ERR_INVALID;
        if ((event->flags & EVENTBUS_EVENT_FLAG_CANDIDATE_VISIBLE)
                && (event->flags & EVENTBUS_EVENT_FLAG_PROMOTION_INTERNAL))
            return EVENTBUS_AGENT_EVENT_ERR_PROMOTION_FORBIDDEN;
        if (eventbus_event_hash_zero(&event->scope_id))
            return EVENTBUS_AGENT_EVENT_ERR_SCOPE;
        {
            uint32_t scope_index = scope_count;
            uint32_t j;
            for (j = 0u; j < scope_count; j++) {
                if (eventbus_event_hash_equal(&scopes[j], &event->scope_id)) {
                    scope_index = j;
                    break;
                }
            }
            if (scope_index == scope_count) {
                if (scope_count >= EVENTBUS_AGENT_EVENT_MAX_SCOPES)
                    return EVENTBUS_AGENT_EVENT_ERR_SCOPE;
                if (!eventbus_event_hash_zero(&event->parent_scope_id)) {
                    uint32_t parent_found = 0u;
                    for (j = 0u; j < scope_count; j++)
                        if (eventbus_event_hash_equal(&scopes[j],
                                                      &event->parent_scope_id))
                            parent_found = 1u;
                    if (!parent_found)
                        return EVENTBUS_AGENT_EVENT_ERR_SCOPE;
                }
                scopes[scope_count] = event->scope_id;
                parents[scope_count] = event->parent_scope_id;
                scope_count++;
            } else if (!eventbus_event_hash_equal(&parents[scope_index],
                                                   &event->parent_scope_id)) {
                return EVENTBUS_AGENT_EVENT_ERR_SCOPE;
            }
        }
        if (!eventbus_event_hash_zero(&event->causal_parent)) {
            uint32_t parent_event = i;
            uint32_t found = 0u;
            uint32_t j;
            for (j = 0u; j < i; j++) {
                if (eventbus_event_hash_equal(&event_hashes[j],
                                              &event->causal_parent)) {
                    parent_event = j;
                    found = 1u;
                    break;
                }
            }
            if (!found)
                return EVENTBUS_AGENT_EVENT_ERR_SCOPE;
            {
                eventbus_event_hash_t cursor = event->scope_id;
                uint32_t contained = 0u;
                for (j = 0u; j <= EVENTBUS_AGENT_EVENT_MAX_SCOPES; j++) {
                    if (eventbus_event_hash_equal(&cursor,
                                                  &event_scopes[parent_event])) {
                        contained = 1u;
                        break;
                    }
                    for (uint32_t k = 0u; k < scope_count; k++)
                        if (eventbus_event_hash_equal(&scopes[k], &cursor)) {
                            cursor = parents[k];
                            break;
                        }
                }
                if (!contained)
                    return EVENTBUS_AGENT_EVENT_ERR_SCOPE;
            }
        }
        if (event->event_type == EVENTBUS_EVENT_AUTHORITY_CHANGE) {
            if (event->authority_epoch != replay->authority_epoch + 1u)
                return EVENTBUS_AGENT_EVENT_ERR_AUTHORITY;
            replay->authority_epoch = event->authority_epoch;
        } else if (event->authority_epoch != replay->authority_epoch) {
            return EVENTBUS_AGENT_EVENT_ERR_AUTHORITY;
        }
        if (event->event_type == EVENTBUS_EVENT_TASK_VERIFY) {
            if (!(event->flags & EVENTBUS_EVENT_FLAG_TASK_VERIFY_SUCCESS)
                    || eventbus_event_hash_zero(&event->task_id)
                    || eventbus_event_hash_zero(&event->payload_root)
                    || eventbus_event_hash_zero(&event->evidence_root))
                return EVENTBUS_AGENT_EVENT_ERR_COMMIT_EVIDENCE;
            verified = 1u;
            verified_task = event->task_id;
            verified_candidate = event->payload_root;
            verified_evidence = event->evidence_root;
            verified_scope = event->scope_id;
        }
        if (event->event_type == EVENTBUS_EVENT_COMMIT) {
            if (!verified || !eventbus_event_hash_equal(&event->task_id,
                                                         &verified_task)
                    || !eventbus_event_hash_equal(&event->scope_id,
                                                  &verified_scope)
                    || !eventbus_event_hash_equal(&event->payload_root,
                                                  &verified_candidate)
                    || !eventbus_event_hash_equal(&event->evidence_root,
                                                  &verified_evidence))
                return EVENTBUS_AGENT_EVENT_ERR_COMMIT_EVIDENCE;
            verified = 0u; /* evidence is single-use */
        }
        if (eventbus_event_count_one(replay, event) != EVENTBUS_AGENT_EVENT_OK)
            return EVENTBUS_AGENT_EVENT_ERR_INVALID;
        replay->event_count++;
        replay->head = event->event_hash;
        event_hashes[i] = event->event_hash;
        event_scopes[i] = event->scope_id;
        previous = event->event_hash;
    }
    if (!eventbus_event_hash_equal(&replay->head, &seal->head))
        return EVENTBUS_AGENT_EVENT_ERR_TRUNCATED;
    eventbus_event_hash_bytes((const uint8_t *)replay,
                              (uint32_t)(sizeof(*replay)
                                         - sizeof(replay->projection_hash)),
                              &replay->projection_hash);
    return EVENTBUS_AGENT_EVENT_OK;
}

/* ─── Channel IDs (EventBus perspective) ─────────────────────────────────── */
#define EVENTBUS_CH_MONITOR    1  /* monitor → eventbus */
#define EVENTBUS_CH_INITAGENT  2  /* init_agent → eventbus */

/* ─── Request structs ────────────────────────────────────────────────────── */

struct eventbus_req_init {
    uint32_t version;           /* caller's agentos version */
};

struct eventbus_req_subscribe {
    uint32_t notify_ch;         /* channel to signal on new events */
    uint32_t topic_mask;        /* event kind bitmask; 0 = all events */
};

struct eventbus_req_unsubscribe {
    uint32_t notify_ch;         /* channel to remove */
};

struct eventbus_req_publish_batch {
    uint32_t count;             /* number of batch_event_t entries */
    uint32_t offset;            /* byte offset into shared eventbus ring region */
};

struct eventbus_req_status {
    /* no fields — query-only */
};

struct eventbus_req_query_subscribers {
    /* no fields — returns count + subscriber list in shmem */
};

/* ─── Reply structs ──────────────────────────────────────────────────────── */

struct eventbus_reply_init {
    uint32_t ok;                /* 0 = success */
    uint32_t capacity;          /* ring capacity in event slots */
};

struct eventbus_reply_subscribe {
    uint32_t ok;                /* 0 = success */
    uint32_t subscriber_id;     /* assigned subscriber index */
};

struct eventbus_reply_unsubscribe {
    uint32_t ok;
};

struct eventbus_reply_publish_batch {
    uint32_t dispatched;        /* events written to ring */
    uint32_t dropped;           /* events dropped (ring full) */
};

struct eventbus_reply_status {
    uint32_t head;              /* ring write index */
    uint32_t tail;              /* ring read index (min across subscribers) */
    uint32_t overflow_count;    /* total events dropped since boot */
    uint32_t subscriber_count;  /* active subscriber count */
};

struct eventbus_reply_query_subscribers {
    uint32_t count;             /* subscriber entries written to shmem */
};

/* ─── Error codes ────────────────────────────────────────────────────────── */

enum eventbus_error {
    EVENTBUS_OK               = 0,
    EVENTBUS_ERR_NOT_INIT     = 1,  /* INIT not yet received */
    EVENTBUS_ERR_FULL         = 2,  /* subscriber table full (MAX_SUBSCRIBERS) */
    EVENTBUS_ERR_NOT_FOUND    = 3,  /* unsubscribe: channel not registered */
    EVENTBUS_ERR_BAD_OFFSET   = 4,  /* batch offset outside staging region */
    EVENTBUS_ERR_BAD_COUNT    = 5,  /* batch count > PUBLISH_BATCH_MAX */
};
