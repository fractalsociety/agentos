/*
 * CapBroker IPC Contract
 *
 * The CapBroker PD manages runtime capability grants between PDs.
 * It enforces the current cap_policy and maintains a grant ledger used by
 * cap_audit_log for attestation.
 *
 * Channel: (controller → cap_broker; mapped via monitor dispatch)
 * Opcodes: MSG_CAP_GRANT, MSG_CAP_REVOKE_GRANT, MSG_CAP_GRANT_STATUS, MSG_CAP_LIST,
 *          MSG_CAP_REMOTE_DERIVE, MSG_CAP_REMOTE_REVOKE_EPOCH
 *          OP_CAP_BROKER_RELOAD, OP_CAP_STATUS (see agentos.h)
 *
 * Invariants:
 *   - CAP_GRANT requires the granting PD to hold the capability class itself.
 *   - A grant persists until CAP_REVOKE_GRANT or until the target PD exits.
 *   - CAP_LIST enumerates all active grants (not just for a single PD).
 *   - OP_CAP_BROKER_RELOAD atomically updates policy and revokes violating grants.
 *   - CAP_GRANT_STATUS for a PD that has never been granted returns 0 cap_mask.
 *   - All grants are logged to cap_audit_log automatically.
 */

#pragma once
#include "../agentos.h"
#include "mesh_agent_contract.h"

/* ─── Request structs ────────────────────────────────────────────────────── */

struct cap_broker_req_grant {
    uint32_t target_pd;         /* PD receiving the capability */
    uint32_t cap_class;         /* AGENTOS_CAP_* constant */
    uint32_t rights;            /* CAP_RIGHT_* bitmask */
    uint32_t ttl_ticks;         /* 0 = permanent until revoke */
};

#define CAP_RIGHT_READ    (1u << 0)
#define CAP_RIGHT_WRITE   (1u << 1)
#define CAP_RIGHT_EXECUTE (1u << 2)

struct cap_broker_req_revoke {
    uint32_t target_pd;
    uint32_t cap_class;
};

struct cap_broker_req_status {
    uint32_t target_pd;
};

struct cap_broker_req_list {
    uint32_t max_entries;       /* max cap_grant_entry_t entries in shmem */
};

struct cap_broker_req_remote_derive {
    uint32_t target_pd;
    uint32_t requested_effect_class;
    uint64_t requested_operations;
    uint64_t requested_budget_units;
    uint32_t grant_offset;      /* RemoteGrant in CapBroker/MeshAgent shmem */
    uint32_t grant_length;
};

struct cap_broker_req_remote_revoke_epoch {
    mesh_revocation_epoch_t epoch;
};

/* ─── Reply structs ──────────────────────────────────────────────────────── */

struct cap_broker_reply_grant {
    uint32_t ok;
    uint32_t grant_id;          /* opaque ID for this grant */
};

struct cap_broker_reply_revoke {
    uint32_t ok;
};

struct cap_broker_reply_status {
    uint32_t ok;
    uint32_t cap_mask;          /* AGENTOS_CAP_* bitmask of active grants */
    uint32_t policy_version;    /* current policy version */
    uint32_t active_grants;     /* number of individual grants for this PD */
};

struct cap_broker_reply_list {
    uint32_t ok;
    uint32_t count;             /* entries written to shmem */
};

struct cap_broker_reply_remote_derive {
    uint32_t ok;
    uint32_t reserved;
    uint64_t local_badge;       /* receiving-node CSpace only; never serialized */
};

struct cap_broker_reply_remote_revoke_epoch {
    uint32_t ok;
    uint32_t revoked_entries;
};

#define CAP_BROKER_REMOTE_MAX_BADGES 64u
#define CAP_BROKER_REMOTE_BADGE_PREFIX UINT64_C(0xCB00000000000000)

struct cap_broker_remote_badge_entry {
    uint64_t badge;
    mesh_node_id_t issuer;
    mesh_agent_id_t subject_agent;
    mesh_space_id_t space_id;
    uint8_t nonce[MESH_NONCE_BYTES];
    uint64_t operations;
    uint64_t budget_units;
    uint64_t expiry_unix_ms;
    uint64_t authority_epoch;
    uint64_t revocation_epoch;
    uint32_t effect_class;
    uint32_t generation;
    uint8_t active;
};

struct cap_broker_remote_state {
    struct cap_broker_remote_badge_entry entries[CAP_BROKER_REMOTE_MAX_BADGES];
    uint64_t mesh_agent_caller_badge;
    uint32_t next_slot;
    uint32_t generation;
    mesh_revocation_epoch_t current_epoch;
};
typedef struct cap_broker_remote_state cap_broker_remote_state_t;

void cap_broker_remote_init(cap_broker_remote_state_t *state,
                            uint64_t mesh_agent_caller_badge);
uint32_t cap_broker_derive_remote_endpoint_badge(
    cap_broker_remote_state_t *state, uint64_t caller_badge,
    const mesh_remote_grant_t *grant, uint64_t requested_operations,
    uint32_t requested_effect_class, uint64_t requested_budget_units,
    uint64_t *out_local_badge);
uint32_t cap_broker_remote_badge_recheck(
    const cap_broker_remote_state_t *state, uint64_t local_badge,
    const mesh_remote_grant_t *grant, uint64_t requested_operations,
    uint32_t requested_effect_class, uint64_t requested_budget_units,
    uint64_t now_unix_ms, uint64_t authority_epoch,
    uint64_t revocation_epoch);
uint32_t cap_broker_remote_revoke_epoch(
    cap_broker_remote_state_t *state, uint64_t authority_epoch,
    uint64_t revocation_epoch);

/* ─── Shmem layout: grant entry ─────────────────────────────────────────── */

typedef struct __attribute__((packed)) {
    uint32_t grant_id;
    uint32_t target_pd;
    uint32_t cap_class;
    uint32_t rights;
    uint32_t ttl_ticks;         /* 0 = permanent */
    uint32_t age_ticks;         /* ticks since grant */
} cap_grant_entry_t;

/* ─── Error codes ────────────────────────────────────────────────────────── */

enum cap_broker_error {
    CAP_BROKER_OK              = 0,
    CAP_BROKER_ERR_NOT_HELD    = 1,  /* granting PD doesn't hold the cap */
    CAP_BROKER_ERR_POLICY_DENY = 2,  /* policy rejects this grant */
    CAP_BROKER_ERR_NOT_FOUND   = 3,  /* grant_id or target_pd not found */
    CAP_BROKER_ERR_TABLE_FULL  = 4,
    CAP_BROKER_ERR_KERNEL      = 5,  /* seL4 mint/delete failed */
    CAP_BROKER_ERR_SYNC        = 6,  /* harness epoch update failed */
    CAP_BROKER_ERR_FORBIDDEN   = 7,  /* caller lacks CapAdmin badge right */
    CAP_BROKER_ERR_BAD_ARG     = 8,
    CAP_BROKER_ERR_REMOTE_CALLER = 9,
    CAP_BROKER_ERR_REMOTE_SCOPE = 10,
    CAP_BROKER_ERR_REMOTE_STALE = 11,
    CAP_BROKER_ERR_REMOTE_REPLAY = 12,
    CAP_BROKER_ERR_REMOTE_AUDIENCE = 13,
    CAP_BROKER_ERR_REMOTE_MALFORMED = 14,
};
