/*
 * Continual Harness Refinement Contract (fos-gz0.14.8 / E1)
 *
 * Cheap versioned evolution of notes, memory, skills, roles, and retry hints
 * before WASM or capability-graph mutation. Snapshots are immutable and
 * evidence-linked. Promote only when the candidate beats incumbent and null
 * baselines under a ratcheted gate. Rollback restores the prior promoted root
 * without compiling WASM.
 *
 * Held-out promotion corpora are never readable through this candidate-facing
 * API (QUERY_HELD_OUT always fails closed).
 *
 * Channels: MSG_CONTINUAL_* (see fractalos.h)
 * Version: 1
 */

#pragma once

#include <stdint.h>

#define CONTINUAL_HARNESS_INTERFACE_VERSION 1u
#define CONTINUAL_HARNESS_DIGEST_BYTES      32u
#define CONTINUAL_HARNESS_MAX_SNAPSHOTS     32u
#define CONTINUAL_HARNESS_MAX_KIND_SLOTS    8u

enum continual_artifact_kind {
    CONTINUAL_KIND_NOTE       = 1u,
    CONTINUAL_KIND_SKILL      = 2u,
    CONTINUAL_KIND_ROLE       = 3u,
    CONTINUAL_KIND_RETRY_HINT = 4u,
};

enum continual_tier {
    CONTINUAL_TIER_E1_HARNESS = 1u, /* notes/skills/roles — no WASM */
    CONTINUAL_TIER_E2_ORCH    = 2u, /* orchestration programs — ratcheted */
    CONTINUAL_TIER_E3_WASM    = 3u, /* WASM providers — ratcheted */
};

enum continual_harness_error {
    CONTINUAL_OK                    = 0u,
    CONTINUAL_ERR_INVALID           = 1u,
    CONTINUAL_ERR_DENIED            = 2u,
    CONTINUAL_ERR_NOT_FOUND         = 3u,
    CONTINUAL_ERR_FULL              = 4u,
    CONTINUAL_ERR_GATE              = 5u, /* deeper tier / failed ratchet */
    CONTINUAL_ERR_BASELINE          = 6u, /* did not beat incumbent+null */
    CONTINUAL_ERR_EVIDENCE          = 7u,
    CONTINUAL_ERR_STALE             = 8u,
    CONTINUAL_ERR_WASM_FORBIDDEN    = 9u, /* E1 path must not compile WASM */
    CONTINUAL_ERR_LEAKAGE           = 10u, /* held-out / promotion corpus probe */
};

struct continual_digest {
    uint8_t bytes[CONTINUAL_HARNESS_DIGEST_BYTES];
} __attribute__((packed));

struct continual_req_snapshot {
    uint32_t interface_version;
    uint32_t kind; /* continual_artifact_kind */
    uint32_t tier; /* must be E1 for this host path */
    uint32_t reserved;
    struct continual_digest content_root;
    struct continual_digest evidence_root; /* TASK_VERIFY-linked evidence */
} __attribute__((packed));

struct continual_reply_snapshot {
    uint32_t status;
    uint32_t snapshot_id;
    uint32_t version;
    uint32_t reserved;
    struct continual_digest snapshot_root;
} __attribute__((packed));

struct continual_req_evaluate {
    uint32_t interface_version;
    uint32_t snapshot_id;
    uint32_t authority_epoch;
    uint32_t reserved;
} __attribute__((packed));

struct continual_reply_evaluate {
    uint32_t status;
    uint32_t snapshot_id;
    uint32_t beats_incumbent; /* 1/0 */
    uint32_t beats_null;      /* 1/0 */
    uint32_t candidate_score; /* coarse host metric — not held-out labels */
    uint32_t incumbent_score;
    uint32_t null_score;
    uint32_t reserved;
} __attribute__((packed));

struct continual_req_promote {
    uint32_t interface_version;
    uint32_t snapshot_id;
    uint32_t authority_epoch;
    uint32_t require_beat_both; /* must be 1 for E1 promote */
} __attribute__((packed));

struct continual_reply_promote {
    uint32_t status;
    uint32_t snapshot_id;
    uint32_t promoted_version;
    uint32_t previous_version;
    struct continual_digest promoted_root;
} __attribute__((packed));

struct continual_req_rollback {
    uint32_t interface_version;
    uint32_t kind;
    uint32_t authority_epoch;
    uint32_t reserved;
} __attribute__((packed));

struct continual_reply_rollback {
    uint32_t status;
    uint32_t kind;
    uint32_t restored_version;
    uint32_t reserved;
    struct continual_digest restored_root;
} __attribute__((packed));

struct continual_req_status {
    uint32_t interface_version;
    uint32_t kind;
} __attribute__((packed));

struct continual_reply_status {
    uint32_t status;
    uint32_t kind;
    uint32_t active_version;
    uint32_t snapshot_count;
    struct continual_digest active_root;
    uint32_t wasm_compiled; /* must remain 0 on E1 path */
    uint32_t reserved;
} __attribute__((packed));

/* Candidate probe for held-out promotion corpora — always fails closed. */
struct continual_req_query_held_out {
    uint32_t interface_version;
    uint32_t probe_tag;
    struct continual_digest case_id;
} __attribute__((packed));

struct continual_reply_query_held_out {
    uint32_t status; /* always CONTINUAL_ERR_LEAKAGE for candidates */
    uint32_t reserved;
} __attribute__((packed));

_Static_assert(sizeof(struct continual_digest) == 32u, "continual digest");
_Static_assert(sizeof(struct continual_req_snapshot) == 80u, "snapshot req");
_Static_assert(sizeof(struct continual_reply_snapshot) == 48u, "snapshot reply");
_Static_assert(sizeof(struct continual_req_evaluate) == 16u, "evaluate req");
_Static_assert(sizeof(struct continual_reply_evaluate) == 32u, "evaluate reply");
_Static_assert(sizeof(struct continual_req_promote) == 16u, "promote req");
_Static_assert(sizeof(struct continual_reply_promote) == 48u, "promote reply");
_Static_assert(sizeof(struct continual_req_query_held_out) == 40u,
               "held-out probe req");
