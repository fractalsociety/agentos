/*
 * Immutable Shared-Space Replication Contract (fos-gz0.14.10.3)
 *
 * SpaceID namespaces with ordered root CAS (not last-writer-wins), have/want
 * anti-entropy, hash-verified resumable object transfer, offline branches,
 * dual-head conflict retention, and verified-merge publication.
 *
 * Capability, budget, effect, lease, commit, and verifier state MUST NOT be
 * CRDT-merged. Those classes use CAS + verified evidence only.
 *
 * Channels: MSG_SHARED_SPACE_* (see fractalos.h)
 * Version: 1
 */

#pragma once

#include <stdint.h>

#define SHARED_SPACE_INTERFACE_VERSION 1u

#define SHARED_SPACE_DIGEST_BYTES   32u
#define SHARED_SPACE_MAX_SPACES     8u
#define SHARED_SPACE_MAX_OBJECTS    64u
#define SHARED_SPACE_MAX_CHUNKS     64u
#define SHARED_SPACE_MAX_CHUNK_BYTES 512u
#define SHARED_SPACE_MAX_HAVE_WANT  32u
#define SHARED_SPACE_MAX_HEADS      4u
#define SHARED_SPACE_MAX_DEVICES    8u

enum shared_space_error {
    SHARED_SPACE_OK                    = 0u,
    SHARED_SPACE_ERR_INVALID           = 1u,
    SHARED_SPACE_ERR_DENIED            = 2u,
    SHARED_SPACE_ERR_NOT_FOUND         = 3u,
    SHARED_SPACE_ERR_HASH_MISMATCH     = 4u,
    SHARED_SPACE_ERR_STALE_EPOCH       = 5u,
    SHARED_SPACE_ERR_CAS_CONFLICT      = 6u,
    SHARED_SPACE_ERR_MISSING_BLOCK     = 7u,
    SHARED_SPACE_ERR_DUPLICATE         = 8u,
    SHARED_SPACE_ERR_FULL              = 9u,
    SHARED_SPACE_ERR_NO_EVIDENCE       = 10u,
    SHARED_SPACE_ERR_CRDT_FORBIDDEN    = 11u,
    SHARED_SPACE_ERR_CORRUPT           = 12u,
    SHARED_SPACE_ERR_STALE_ROOT        = 13u,
};

/* Full 256-bit content identity (host may use FNV until SHA-256 wired). */
struct shared_space_digest {
    uint8_t bytes[SHARED_SPACE_DIGEST_BYTES];
} __attribute__((packed));

typedef struct shared_space_digest shared_space_id_t;
typedef struct shared_space_digest shared_object_id_t;
typedef struct shared_space_digest shared_event_id_t;
typedef struct shared_space_digest shared_device_id_t;

/* Space record — mirrors fractal-agent-ir §16.5 SpaceRecord. */
struct shared_space_record {
    shared_space_id_t space_id;
    shared_object_id_t current_root;
    shared_event_id_t shared_event_head;
    shared_object_id_t membership_root;
    shared_object_id_t service_root;
    shared_object_id_t replica_set_root;
    uint64_t authority_epoch;
    uint32_t head_count; /* >1 means unresolved conflict */
    uint32_t reserved;
    shared_object_id_t heads[SHARED_SPACE_MAX_HEADS];
} __attribute__((packed));

struct shared_space_chunk_ref {
    shared_object_id_t object_id;
    uint32_t chunk_index;
    uint32_t chunk_bytes;
    struct shared_space_digest chunk_hash;
} __attribute__((packed));

/* ─── CREATE ─────────────────────────────────────────────────────────────── */

struct shared_space_req_create {
    uint32_t interface_version;
    uint32_t reserved;
    shared_space_id_t space_id;
    shared_device_id_t authority_device;
    uint64_t authority_epoch;
} __attribute__((packed));

struct shared_space_reply_create {
    uint32_t status;
    uint32_t reserved;
    struct shared_space_record record;
} __attribute__((packed));

/* ─── PUT_OBJECT (hash-verified; resumable by chunk_index) ───────────────── */

struct shared_space_req_put_object {
    uint32_t interface_version;
    uint32_t chunk_index;
    shared_space_id_t space_id;
    shared_object_id_t object_id;
    struct shared_space_digest chunk_hash;
    uint32_t total_chunks;
    uint32_t chunk_bytes;
    /* chunk payload follows in host arena (max SHARED_SPACE_MAX_CHUNK_BYTES) */
} __attribute__((packed));

struct shared_space_reply_put_object {
    uint32_t status;
    uint32_t accepted_chunk_index;
    uint32_t chunks_stored;
    uint32_t reserved;
} __attribute__((packed));

/* ─── GET_OBJECT ─────────────────────────────────────────────────────────── */

struct shared_space_req_get_object {
    uint32_t interface_version;
    uint32_t chunk_index;
    shared_space_id_t space_id;
    shared_object_id_t object_id;
} __attribute__((packed));

struct shared_space_reply_get_object {
    uint32_t status;
    uint32_t chunk_index;
    struct shared_space_digest chunk_hash;
    uint32_t total_chunks;
    uint32_t chunk_bytes;
    /* chunk payload copied to caller buffer by host API */
} __attribute__((packed));

/* ─── HAVE / WANT anti-entropy ───────────────────────────────────────────── */

struct shared_space_req_have_want {
    uint32_t interface_version;
    uint32_t have_count;
    uint32_t want_count;
    uint32_t reserved;
    shared_space_id_t space_id;
    shared_device_id_t from_device;
    /* followed by have[have_count] then want[want_count] object ids in arena */
} __attribute__((packed));

struct shared_space_reply_have_want {
    uint32_t status;
    uint32_t missing_count; /* objects in want[] not present locally */
    uint32_t duplicate_count; /* objects in have[] already present */
    uint32_t reserved;
} __attribute__((packed));

/* ─── CAS_ROOT (expected → proposed; evidence required) ──────────────────── */

struct shared_space_req_cas_root {
    uint32_t interface_version;
    uint32_t reserved;
    shared_space_id_t space_id;
    shared_object_id_t expected_root;
    shared_object_id_t proposed_root;
    shared_event_id_t shared_event_head;
    uint64_t authority_epoch;
    struct shared_space_digest verify_evidence; /* non-zero required */
} __attribute__((packed));

struct shared_space_reply_cas_root {
    uint32_t status;
    uint32_t head_count;
    struct shared_space_record record;
} __attribute__((packed));

/* ─── BRANCH (offline) ───────────────────────────────────────────────────── */

struct shared_space_req_branch {
    uint32_t interface_version;
    uint32_t reserved;
    shared_space_id_t space_id;
    shared_device_id_t device_id;
    shared_object_id_t base_root;
    shared_object_id_t branch_root;
    uint64_t authority_epoch; /* must match current for online; offline may lag */
} __attribute__((packed));

struct shared_space_reply_branch {
    uint32_t status;
    uint32_t reserved;
    struct shared_space_record record;
} __attribute__((packed));

/* ─── MERGE_VERIFIED (AgentLang/TASK_VERIFY evidence; never CRDT) ─────────── */

enum shared_space_merge_policy {
    SHARED_SPACE_MERGE_VERIFIED = 1u, /* requires verify_evidence */
    SHARED_SPACE_MERGE_RETAIN_BOTH = 2u,
    /* CRDT intentionally omitted from wire — returns CRDT_FORBIDDEN */
    SHARED_SPACE_MERGE_CRDT = 3u,
};

struct shared_space_req_merge {
    uint32_t interface_version;
    uint32_t policy; /* shared_space_merge_policy */
    shared_space_id_t space_id;
    shared_object_id_t head_a;
    shared_object_id_t head_b;
    shared_object_id_t merged_root; /* used when policy=VERIFIED */
    uint64_t authority_epoch;
    struct shared_space_digest verify_evidence;
} __attribute__((packed));

struct shared_space_reply_merge {
    uint32_t status;
    uint32_t head_count;
    struct shared_space_record record;
} __attribute__((packed));

/* ─── STATUS / RESOLVE ───────────────────────────────────────────────────── */

struct shared_space_req_status {
    uint32_t interface_version;
    uint32_t reserved;
    shared_space_id_t space_id;
} __attribute__((packed));

struct shared_space_reply_status {
    uint32_t status;
    uint32_t reserved;
    struct shared_space_record record;
} __attribute__((packed));

_Static_assert(sizeof(struct shared_space_digest) == 32u,
               "shared space digest wire size");
_Static_assert(sizeof(struct shared_space_record) == 336u,
               "shared space record wire size");
_Static_assert(sizeof(struct shared_space_req_create) == 80u,
               "shared space create request wire size");
_Static_assert(sizeof(struct shared_space_req_cas_root) == 176u,
               "shared space cas request wire size");
_Static_assert(sizeof(struct shared_space_req_merge) == 176u,
               "shared space merge request wire size");
