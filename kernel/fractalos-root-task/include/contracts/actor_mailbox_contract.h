/*
 * Scoped Actor + Persistent Mailbox Contract (fos-gz0.14.7.1 / .7.2)
 *
 * First-class AgentHandle / TaskHandle / ProgramHandle identities with
 * task|session|agent|global scope. SPAWN and DELEGATE return immediately;
 * completion is mailbox/event driven. Child caps and budgets must be subsets
 * of the parent. Causal mailbox delivery is strictly sequenced. Stale
 * generation/epoch and cross-scope handles fail before dispatch.
 *
 * fos-gz0.14.7.2: PASSIVATE checkpoints idle actors to an immutable root and
 * releases resident harness/mailbox buffers; REACTIVATE restores lineage after
 * quota/authority checks; MEMORY_STATS proves active vs dormant frontier.
 *
 * Channels: MSG_ACTOR_* (see fractalos.h)
 * Version: 1
 */

#pragma once

#include <stdint.h>

#define ACTOR_MAILBOX_INTERFACE_VERSION 1u

#define ACTOR_MAILBOX_MAX_AGENTS   64u
#define ACTOR_MAILBOX_MAX_TASKS    128u
#define ACTOR_MAILBOX_DEPTH        32u
#define ACTOR_MAILBOX_PAYLOAD_WORDS 4u

/* Host accounting for active-frontier memory proof (bytes). */
#define ACTOR_ACTIVE_HARNESS_BYTES   4096u
#define ACTOR_DORMANT_METADATA_BYTES 128u

/* Scope lifetimes — narrower scopes may nest under wider ones. */
enum actor_scope_class {
    ACTOR_SCOPE_TASK    = 0u,
    ACTOR_SCOPE_SESSION = 1u,
    ACTOR_SCOPE_AGENT   = 2u,
    ACTOR_SCOPE_GLOBAL  = 3u,
};

enum actor_lifecycle_state {
    ACTOR_STATE_ACTIVE  = 0u,
    ACTOR_STATE_DORMANT = 1u,
};

enum actor_mailbox_error {
    ACTOR_MAILBOX_OK                 = 0u,
    ACTOR_MAILBOX_ERR_INVALID        = 1u,
    ACTOR_MAILBOX_ERR_DENIED         = 2u,
    ACTOR_MAILBOX_ERR_NOT_FOUND      = 3u,
    ACTOR_MAILBOX_ERR_STALE_HANDLE   = 4u,
    ACTOR_MAILBOX_ERR_CROSS_SCOPE    = 5u,
    ACTOR_MAILBOX_ERR_BUDGET         = 6u,
    ACTOR_MAILBOX_ERR_CAPS           = 7u,
    ACTOR_MAILBOX_ERR_CAUSAL         = 8u,
    ACTOR_MAILBOX_ERR_FULL           = 9u,
    ACTOR_MAILBOX_ERR_EMPTY          = 10u,
    ACTOR_MAILBOX_ERR_EXHAUSTED      = 11u,
    ACTOR_MAILBOX_ERR_NOT_ACTIVE     = 12u,
    ACTOR_MAILBOX_ERR_NOT_DORMANT    = 13u,
    ACTOR_MAILBOX_ERR_CHECKPOINT     = 14u,
    ACTOR_MAILBOX_ERR_QUOTA          = 15u,
};

/* Opaque wire handles — generation + authority_epoch detect staleness. */
struct actor_agent_handle {
    uint64_t id;
    uint32_t generation;
    uint32_t authority_epoch;
    uint32_t scope; /* actor_scope_class */
} __attribute__((packed));

struct actor_task_handle {
    uint64_t id;
    uint32_t generation;
    uint32_t authority_epoch;
    uint32_t scope;
    uint64_t agent_id;
} __attribute__((packed));

struct actor_program_handle {
    uint64_t id;
    uint32_t generation;
    uint32_t authority_epoch;
    uint32_t scope;
} __attribute__((packed));

struct actor_mailbox_message {
    uint64_t sequence;
    uint64_t causal_parent;
    uint32_t scope;
    uint32_t reserved;
    uint64_t payload[ACTOR_MAILBOX_PAYLOAD_WORDS];
} __attribute__((packed));

/* ─── Requests / replies ─────────────────────────────────────────────────── */

struct actor_req_spawn {
    uint32_t interface_version;
    uint32_t scope;
    uint64_t cap_mask;
    uint64_t budget_units;
    /* Parent agent; id==0 means root (global) spawn. */
    struct actor_agent_handle parent;
} __attribute__((packed));

struct actor_reply_spawn {
    uint32_t status;
    uint32_t reserved;
    struct actor_agent_handle agent;
} __attribute__((packed));

struct actor_req_delegate {
    uint32_t interface_version;
    uint32_t scope;
    uint64_t cap_mask;
    uint64_t budget_units;
    struct actor_agent_handle agent;
} __attribute__((packed));

struct actor_reply_delegate {
    uint32_t status;
    uint32_t reserved;
    struct actor_task_handle task;
} __attribute__((packed));

struct actor_req_mailbox_deliver {
    uint32_t interface_version;
    uint32_t reserved;
    struct actor_agent_handle agent;
    struct actor_mailbox_message message;
} __attribute__((packed));

struct actor_reply_mailbox_deliver {
    uint32_t status;
    uint32_t reserved;
    uint64_t accepted_sequence;
} __attribute__((packed));

struct actor_req_mailbox_poll {
    uint32_t interface_version;
    uint32_t reserved;
    struct actor_agent_handle agent;
} __attribute__((packed));

struct actor_reply_mailbox_poll {
    uint32_t status;
    uint32_t reserved;
    struct actor_mailbox_message message;
} __attribute__((packed));

struct actor_req_handle_resolve {
    uint32_t interface_version;
    uint32_t kind; /* 0=agent, 1=task, 2=program */
    struct actor_agent_handle agent;
    struct actor_task_handle task;
    struct actor_program_handle program;
    uint32_t expected_scope;
} __attribute__((packed));

struct actor_reply_handle_resolve {
    uint32_t status;
    uint32_t scope;
    uint64_t cap_mask;
    uint64_t budget_remaining;
    uint64_t mailbox_head;
} __attribute__((packed));

/* fos-gz0.14.7.2 — passivation / reactivation / frontier stats */

struct actor_req_passivate {
    uint32_t interface_version;
    uint32_t reserved;
    struct actor_agent_handle agent;
    /* Immutable checkpoint root (ObjectID bytes); all-zero rejected. */
    uint8_t checkpoint_root[32];
} __attribute__((packed));

struct actor_reply_passivate {
    uint32_t status;
    uint32_t lifecycle; /* actor_lifecycle_state */
    uint64_t mailbox_head;
    uint64_t resident_bytes_released;
    uint8_t checkpoint_root[32];
} __attribute__((packed));

struct actor_req_reactivate {
    uint32_t interface_version;
    uint32_t reserved;
    struct actor_agent_handle agent;
    /* Must match the root recorded at passivation. */
    uint8_t checkpoint_root[32];
    /* Authorized wake event token (non-zero). */
    uint64_t event_token;
    uint64_t quota_units;
} __attribute__((packed));

struct actor_reply_reactivate {
    uint32_t status;
    uint32_t lifecycle;
    uint64_t mailbox_head;
    uint64_t generation;
    uint64_t resident_bytes;
} __attribute__((packed));

struct actor_req_memory_stats {
    uint32_t interface_version;
    uint32_t reserved;
} __attribute__((packed));

struct actor_reply_memory_stats {
    uint32_t status;
    uint32_t active_count;
    uint32_t dormant_count;
    uint32_t reserved;
    uint64_t active_resident_bytes;
    uint64_t dormant_metadata_bytes;
    uint64_t frontier_bytes; /* active + dormant */
} __attribute__((packed));

_Static_assert(sizeof(struct actor_agent_handle) == 20u,
               "AgentHandle wire size");
_Static_assert(sizeof(struct actor_task_handle) == 28u,
               "TaskHandle wire size");
_Static_assert(sizeof(struct actor_program_handle) == 20u,
               "ProgramHandle wire size");
_Static_assert(sizeof(struct actor_mailbox_message) == 56u,
               "mailbox message wire size");
_Static_assert(sizeof(struct actor_req_passivate) == 60u,
               "passivate request wire size");
_Static_assert(sizeof(struct actor_reply_passivate) == 56u,
               "passivate reply wire size");
_Static_assert(sizeof(struct actor_req_reactivate) == 76u,
               "reactivate request wire size");
_Static_assert(sizeof(struct actor_reply_memory_stats) == 40u,
               "memory stats reply wire size");
