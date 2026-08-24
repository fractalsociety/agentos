/*
 * InitAgent IPC Contract
 *
 * The InitAgent PD orchestrates the agentOS boot sequence and manages
 * the top-level agent lifecycle.
 *
 * Channel: INITAGENT_CH_* (see agentos.h)
 * Opcodes: MSG_INITAGENT_* (see agentos.h)
 *
 * Invariants:
 *   - MSG_INITAGENT_START is sent exactly once by monitor at boot.
 *   - MSG_INITAGENT_READY is sent exactly once by init_agent to monitor.
 *   - MSG_INITAGENT_AGENT_LIST returns data in the shared shmem region;
 *     the caller must hold a mapping to that region.
 *   - SHUTDOWN triggers graceful teardown; all agents are notified before
 *     the reply is sent.
 */

#pragma once
#include "../agentos.h"
#include "agent_harness_contract.h"

/* ─── Channel IDs (InitAgent perspective) ────────────────────────────────── */
#define INITAGENT_CH_MONITOR   1  /* monitor → init_agent */
#define INITAGENT_CH_EVENTBUS  2  /* init_agent → eventbus */

/* ─── Request structs ────────────────────────────────────────────────────── */

struct initagent_req_start {
    uint32_t boot_flags;        /* BOOT_FLAG_* bitmask */
};

#define BOOT_FLAG_RECOVERY  (1u << 0)  /* boot into recovery mode */
#define BOOT_FLAG_VERBOSE   (1u << 1)  /* enable verbose boot logging */

struct initagent_req_shutdown {
    uint32_t reason;            /* SHUTDOWN_REASON_* */
    uint32_t timeout_ms;        /* max ms to wait for agent teardown */
};

#define SHUTDOWN_REASON_HALT    0
#define SHUTDOWN_REASON_REBOOT  1
#define SHUTDOWN_REASON_PANIC   2

struct initagent_req_status {
    /* no fields */
};

struct initagent_req_agent_list {
    /* no fields — results in shmem */
};

/* ─── Composable AgentHarness subprotocol ───
 *
 * A composition manifest is a launch declaration, never authority. InitAgent
 * validates it and derives the endpoint/mapping plan; the launcher and
 * CapBroker must still create the actual CSpace/VSpace objects.
 */

#define HARNESS_COMPOSE_INTERFACE_VERSION 1u
#define HARNESS_COMPOSE_MAX_COMPONENTS    7u
#define HARNESS_COMPOSE_DEFAULT_LIMIT_BYTES HARNESS_WORKER_DEFAULT_LIMIT_BYTES
#define HARNESS_COMPOSE_MAX_PRIVATE_BYTES HARNESS_WORKER_MAX_BYTES

enum harness_component_id {
    HARNESS_COMPONENT_RUNNER_CORE = 1u,
    HARNESS_COMPONENT_CODEX_PLANNER = 2u,
    HARNESS_COMPONENT_CONTEXT = 3u,
    HARNESS_COMPONENT_MODEL_CLIENT = 4u,
    HARNESS_COMPONENT_TOOL_CLIENT = 5u,
    HARNESS_COMPONENT_MEMORY_CLIENT = 6u,
    HARNESS_COMPONENT_EXEC_CLIENT = 7u,
    HARNESS_COMPONENT_NETWORK_CLIENT = 8u,
    HARNESS_COMPONENT_CODEX_GUEST = 9u,
};

#define HARNESS_COMPONENT_VERSION_1 1u
#define HARNESS_COMPONENT_BIT(id) (1u << ((uint32_t)(id) - 1u))
#define HARNESS_COMPONENT_REF(id, version) \
    (((uint32_t)(version) << 16) | ((uint32_t)(id) & 0xffffu))
#define HARNESS_COMPONENT_REF_ID(ref) ((uint16_t)((ref) & 0xffffu))
#define HARNESS_COMPONENT_REF_VERSION(ref) ((uint16_t)((ref) >> 16))

enum harness_profile_id {
    HARNESS_PROFILE_CUSTOM = 0u,
    HARNESS_PROFILE_READ_ONLY = 1u,
    HARNESS_PROFILE_CODING = 2u,
    HARNESS_PROFILE_CODEX_COMPAT = 3u,
};

enum harness_component_flags {
    HARNESS_COMPONENT_PRIVATE = (1u << 0),
    HARNESS_COMPONENT_SHARED_SERVICE = (1u << 1),
    HARNESS_COMPONENT_SINGLETON = (1u << 2),
    HARNESS_COMPONENT_COMPATIBILITY = (1u << 3),
};

enum harness_compose_error {
    HARNESS_COMPOSE_OK = 0u,
    HARNESS_COMPOSE_ERR_INVALID = 1u,
    HARNESS_COMPOSE_ERR_UNKNOWN_COMPONENT = 2u,
    HARNESS_COMPOSE_ERR_VERSION = 3u,
    HARNESS_COMPOSE_ERR_DUPLICATE = 4u,
    HARNESS_COMPOSE_ERR_DEPENDENCY = 5u,
    HARNESS_COMPOSE_ERR_CYCLE = 6u,
    HARNESS_COMPOSE_ERR_CONFLICT = 7u,
    HARNESS_COMPOSE_ERR_CAPABILITY = 8u,
    HARNESS_COMPOSE_ERR_RESOURCE_LIMIT = 9u,
    HARNESS_COMPOSE_ERR_UNKNOWN_PROFILE = 10u,
    HARNESS_COMPOSE_ERR_CATALOG = 11u,
};

/* MSG_INITAGENT_COMPOSE_VALIDATE. Exactly one seL4 inline payload. The
 * declared_caps field must exactly match the capabilities derived from the
 * selected catalog entries. Extra authority is rejected as well as missing
 * authority so profile intent stays canonical and auditable. */
struct initagent_req_compose_validate {
    uint32_t interface_version;
    uint32_t profile_id;
    uint32_t component_count;
    uint32_t declared_caps;
    uint32_t private_limit_bytes;
    uint32_t component_refs[HARNESS_COMPOSE_MAX_COMPONENTS];
};

/* MSG_INITAGENT_COMPOSE_PROFILE expands and validates one built-in profile. */
struct initagent_req_compose_profile {
    uint32_t interface_version;
    uint32_t profile_id;
    uint32_t private_limit_bytes;
    uint32_t reserved;
};

/* Reply shared by both composition opcodes. Endpoint and mapping masks use
 * HARNESS_CAP_* bits but remain a plan only. rejected_index is UINT32_MAX when
 * no individual manifest entry caused the failure. */
struct initagent_reply_compose {
    uint32_t status;
    uint32_t profile_id;
    uint32_t fingerprint_lo;
    uint32_t fingerprint_hi;
    uint32_t component_mask;
    uint32_t required_caps;
    uint32_t private_committed_bytes;
    uint32_t shared_mapped_bytes;
    uint32_t endpoint_mask;
    uint32_t mapping_mask;
    uint32_t shared_components;
    uint32_t rejected_index;
};

_Static_assert(sizeof(struct initagent_req_compose_validate) == 48u,
               "composition manifest must fit one seL4 payload");
_Static_assert(sizeof(struct initagent_req_compose_profile) == 16u,
               "profile request wire size");
_Static_assert(sizeof(struct initagent_reply_compose) == 48u,
               "composition reply must fit one seL4 payload");

/* ─── Reply structs ──────────────────────────────────────────────────────── */

struct initagent_reply_start {
    uint32_t ok;
};

struct initagent_reply_shutdown {
    uint32_t ok;
    uint32_t agents_stopped;
};

struct initagent_reply_status {
    uint32_t state;             /* INITAGENT_STATE_* */
    uint32_t agent_count;       /* active agents */
    uint32_t uptime_ticks;
};

#define INITAGENT_STATE_BOOTING   0
#define INITAGENT_STATE_RUNNING   1
#define INITAGENT_STATE_STOPPING  2

struct initagent_reply_agent_list {
    uint32_t count;             /* entries written to shmem */
};

/* ─── Shmem layout: agent_list entry ────────────────────────────────────── */

typedef struct __attribute__((packed)) {
    uint32_t agent_id;
    uint32_t pd_id;
    uint32_t state;             /* 0=idle 1=running 2=faulted */
    uint32_t cap_mask;
} agent_list_entry_t;

/* ─── Error codes ────────────────────────────────────────────────────────── */

enum initagent_error {
    INITAGENT_OK              = 0,
    INITAGENT_ERR_ALREADY_STARTED = 1,
    INITAGENT_ERR_NOT_STARTED = 2,
    INITAGENT_ERR_SHUTDOWN_TIMEOUT = 3,
};
