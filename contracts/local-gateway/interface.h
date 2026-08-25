/*
 * Fractal Local Gateway Contract (fos-gz0.14.10.5)
 *
 * External/guest companion gateways consume FractalOS through this versioned
 * API. It fences session authority in front of companion-export projections
 * (see companion_export_contract.h / fractal-companion WIT).
 *
 * Normative rules (IR §16.6):
 *   1. Reads are pinned to an immutable shared-space root + event range.
 *   2. The only mutation is a narrowly granted task-intent.
 *   3. Publishing a gateway service requires an explicit, expiring,
 *      user-approved service capability and emits an effect-ledger event id.
 *   4. Revocation denies new sessions and blocks downstream capability
 *      derivation from the revoked parent.
 *   5. Sessions NEVER receive ambient ACT, COMMIT, credential, shell, or
 *      promotion authority (bits rejected at publish/open).
 *   6. No HTML/CSS/JS/WebSocket/dashboard belongs in this repository; TLS and
 *      page rendering stay in the sibling companion project.
 *
 * Channels: MSG_LOCAL_GATEWAY_* (see fractalos.h)
 * Version: 1
 */

#pragma once

#include <stdint.h>

#define LOCAL_GATEWAY_INTERFACE_VERSION 1u

#define LOCAL_GATEWAY_DIGEST_BYTES     32u
#define LOCAL_GATEWAY_MAX_SERVICES     8u
#define LOCAL_GATEWAY_MAX_SESSIONS     16u
#define LOCAL_GATEWAY_MAX_DATE_BYTES   10u
#define LOCAL_GATEWAY_MAX_TZ_BYTES     64u
#define LOCAL_GATEWAY_MAX_NOTE_BYTES   512u
#define LOCAL_GATEWAY_MAX_DAILY_ITEMS  32u
#define LOCAL_GATEWAY_MAX_LABEL_BYTES  128u

enum local_gateway_error {
    LOCAL_GATEWAY_OK                 = 0u,
    LOCAL_GATEWAY_ERR_INVALID        = 1u,
    LOCAL_GATEWAY_ERR_DENIED         = 2u,
    LOCAL_GATEWAY_ERR_NOT_FOUND      = 3u,
    LOCAL_GATEWAY_ERR_EXPIRED        = 4u,
    LOCAL_GATEWAY_ERR_REVOKED        = 5u,
    LOCAL_GATEWAY_ERR_STALE_EPOCH    = 6u,
    LOCAL_GATEWAY_ERR_STALE_ROOT     = 7u,
    LOCAL_GATEWAY_ERR_AMBIENT_DENIED = 8u,
    LOCAL_GATEWAY_ERR_NO_GRANT       = 9u,
    LOCAL_GATEWAY_ERR_FULL           = 10u,
    LOCAL_GATEWAY_ERR_DUPLICATE      = 11u,
    LOCAL_GATEWAY_ERR_DERIVE_DENIED  = 12u,
};

/* Forbidden ambient authorities — must never appear in grant_mask. */
#define LOCAL_GATEWAY_AMBIENT_ACT        (1u << 16)
#define LOCAL_GATEWAY_AMBIENT_COMMIT     (1u << 17)
#define LOCAL_GATEWAY_AMBIENT_CREDENTIAL (1u << 18)
#define LOCAL_GATEWAY_AMBIENT_SHELL      (1u << 19)
#define LOCAL_GATEWAY_AMBIENT_PROMOTION  (1u << 20)
#define LOCAL_GATEWAY_AMBIENT_MASK       (LOCAL_GATEWAY_AMBIENT_ACT |        \
                                          LOCAL_GATEWAY_AMBIENT_COMMIT |     \
                                          LOCAL_GATEWAY_AMBIENT_CREDENTIAL | \
                                          LOCAL_GATEWAY_AMBIENT_SHELL |      \
                                          LOCAL_GATEWAY_AMBIENT_PROMOTION)

/* Allowed narrow grants (align with companion grant bits). */
#define LOCAL_GATEWAY_GRANT_PROJECT       (1u << 0)
#define LOCAL_GATEWAY_GRANT_PROGRESS      (1u << 1)
#define LOCAL_GATEWAY_GRANT_DAILY_ROOT    (1u << 2)
#define LOCAL_GATEWAY_GRANT_HEALTH        (1u << 3)
#define LOCAL_GATEWAY_GRANT_WORKER_MEMORY (1u << 4)
#define LOCAL_GATEWAY_GRANT_TASK_INTENT   (1u << 5)
#define LOCAL_GATEWAY_GRANT_MASK_ALLOWED  (LOCAL_GATEWAY_GRANT_PROJECT |       \
                                          LOCAL_GATEWAY_GRANT_PROGRESS |      \
                                          LOCAL_GATEWAY_GRANT_DAILY_ROOT |    \
                                          LOCAL_GATEWAY_GRANT_HEALTH |        \
                                          LOCAL_GATEWAY_GRANT_WORKER_MEMORY | \
                                          LOCAL_GATEWAY_GRANT_TASK_INTENT)

struct local_gateway_digest {
    uint8_t bytes[LOCAL_GATEWAY_DIGEST_BYTES];
} __attribute__((packed));

typedef struct local_gateway_digest local_gateway_service_id_t;
typedef struct local_gateway_digest local_gateway_session_id_t;
typedef struct local_gateway_digest local_gateway_audience_t;
typedef struct local_gateway_digest local_gateway_root_id_t;
typedef struct local_gateway_digest local_gateway_object_id_t;
typedef struct local_gateway_digest local_gateway_event_id_t;

struct local_gateway_event_range {
    uint32_t stream_id;
    uint32_t reserved;
    uint64_t first_seq;
    uint64_t last_seq;
    local_gateway_object_id_t head;
} __attribute__((packed));

enum local_gateway_intent_kind {
    LOCAL_GATEWAY_INTENT_ACKNOWLEDGE   = 1u,
    LOCAL_GATEWAY_INTENT_DEFER         = 2u,
    LOCAL_GATEWAY_INTENT_PRIORITIZE    = 3u,
    LOCAL_GATEWAY_INTENT_REQUEST_PROOF = 4u,
    LOCAL_GATEWAY_INTENT_CANCEL        = 5u,
};

/* ─── PUBLISH_SERVICE (expiring user-approved service capability) ───────── */

struct local_gateway_req_publish_service {
    uint32_t interface_version;
    uint32_t grant_mask; /* narrow grants only; ambient bits → AMBIENT_DENIED */
    local_gateway_service_id_t service_id;
    local_gateway_audience_t audience;
    local_gateway_service_id_t parent_service; /* zero = root publication */
    uint64_t authority_epoch;
    uint64_t expires_unix_ms;
    local_gateway_event_id_t effect_ledger_event; /* non-zero required */
} __attribute__((packed));

struct local_gateway_reply_publish_service {
    uint32_t status;
    uint32_t reserved;
    local_gateway_service_id_t service_id;
    uint64_t expires_unix_ms;
} __attribute__((packed));

/* ─── REVOKE_SERVICE (stops access + downstream derivation) ─────────────── */

struct local_gateway_req_revoke_service {
    uint32_t interface_version;
    uint32_t reserved;
    local_gateway_service_id_t service_id;
    uint64_t authority_epoch;
    local_gateway_event_id_t effect_ledger_event; /* non-zero required */
} __attribute__((packed));

struct local_gateway_reply_revoke_service {
    uint32_t status;
    uint32_t sessions_invalidated;
    uint32_t derived_blocked;
    uint32_t reserved;
} __attribute__((packed));

/* ─── OPEN_SESSION (pinned shared root + grant subset of service) ───────── */

struct local_gateway_req_open_session {
    uint32_t interface_version;
    uint32_t grant_mask; /* must be ⊆ service grant_mask; no ambient */
    local_gateway_service_id_t service_id;
    local_gateway_session_id_t session_id;
    local_gateway_root_id_t pinned_root; /* shared-space root ObjectID */
    struct local_gateway_event_range event_range;
    uint64_t authority_epoch;
    uint64_t now_unix_ms;
} __attribute__((packed));

struct local_gateway_reply_open_session {
    uint32_t status;
    uint32_t grant_mask;
    local_gateway_session_id_t session_id;
    local_gateway_root_id_t pinned_root;
} __attribute__((packed));

/* ─── GET_DAILY_WORKSPACE (pinned daily bundle under session) ───────────── */

struct local_gateway_req_get_daily {
    uint32_t interface_version;
    uint32_t reserved;
    local_gateway_session_id_t session_id;
    uint64_t authority_epoch;
    uint64_t now_unix_ms;
    uint8_t date_key[LOCAL_GATEWAY_MAX_DATE_BYTES]; /* YYYY-MM-DD */
    uint8_t date_len;
    uint8_t tz_len;
    uint8_t reserved2[2];
    uint8_t tz_key[LOCAL_GATEWAY_MAX_TZ_BYTES];
} __attribute__((packed));

struct local_gateway_daily_item {
    local_gateway_object_id_t item_id;
    uint32_t kind;
    uint32_t label_len;
    uint8_t label[LOCAL_GATEWAY_MAX_LABEL_BYTES];
} __attribute__((packed));

struct local_gateway_reply_get_daily {
    uint32_t status;
    uint32_t item_count;
    local_gateway_object_id_t bundle_id;
    local_gateway_root_id_t pinned_root;
    struct local_gateway_event_range event_range;
    uint64_t authority_epoch;
    /* Host API copies items into caller array (max LOCAL_GATEWAY_MAX_DAILY_ITEMS). */
} __attribute__((packed));

/* ─── SUBMIT_TASK_INTENT (only mutation; requires TASK_INTENT grant) ─────── */

struct local_gateway_req_submit_intent {
    uint32_t interface_version;
    uint32_t intent_kind; /* local_gateway_intent_kind */
    local_gateway_session_id_t session_id;
    local_gateway_object_id_t subject;
    local_gateway_root_id_t expect_root; /* CAS against session pinned root */
    uint64_t authority_epoch;
    uint64_t now_unix_ms;
    uint32_t note_len;
    uint32_t reserved;
    uint8_t note[LOCAL_GATEWAY_MAX_NOTE_BYTES];
} __attribute__((packed));

struct local_gateway_reply_submit_intent {
    uint32_t status;
    uint32_t reserved;
    local_gateway_object_id_t intent_id;
    local_gateway_root_id_t committed_root;
} __attribute__((packed));

/* ─── STATUS ────────────────────────────────────────────────────────────── */

struct local_gateway_req_status {
    uint32_t interface_version;
    uint32_t reserved;
    local_gateway_service_id_t service_id; /* zero → session lookup */
    local_gateway_session_id_t session_id;
} __attribute__((packed));

struct local_gateway_reply_status {
    uint32_t status;
    uint32_t revoked; /* 1 if service revoked */
    uint32_t grant_mask;
    uint32_t reserved;
    uint64_t expires_unix_ms;
    local_gateway_root_id_t pinned_root;
} __attribute__((packed));

_Static_assert(sizeof(struct local_gateway_digest) == 32u,
               "local gateway digest wire size");
_Static_assert(sizeof(struct local_gateway_event_range) == 56u,
               "local gateway event range wire size");
_Static_assert(sizeof(struct local_gateway_req_publish_service) == 152u,
               "local gateway publish request wire size");
_Static_assert(sizeof(struct local_gateway_req_open_session) == 176u,
               "local gateway open request wire size");
_Static_assert(sizeof(struct local_gateway_req_get_daily) == 134u,
               "local gateway get-daily request wire size");
_Static_assert(sizeof(struct local_gateway_req_submit_intent) == 640u,
               "local gateway intent request wire size");
