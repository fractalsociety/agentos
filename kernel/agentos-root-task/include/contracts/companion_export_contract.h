/*
 * Fractal Companion Export Contract v1
 *
 * This header is the controller-facing ABI for the read-mostly companion
 * projection.  It defines bounded, fixed-layout request and reply records;
 * variable data is returned through the caller's checked result arena.  The
 * only mutating operation is MSG_COMPANION_SUBMIT_TASK_INTENT.
 *
 * No record in this ABI contains secret material, personal-record bodies,
 * command text, host paths, or ranking/promotion state.  External sources
 * are represented only by opaque handles and provenance ObjectIDs.
 */

#pragma once

#include "../agentos.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Dedicated controller channel; 60 is reserved for board-specific log drain. */
#define CH_COMPANION_EXPORT                 61u

/* Version and wire bounds.  These are protocol limits, not allocation hints. */
#define COMPANION_SCHEMA_MAJOR              1u
#define COMPANION_SCHEMA_MINOR              0u
#define COMPANION_OBJECT_ID_BYTES           32u
#define COMPANION_MAX_PAGE_ITEMS            64u
#define COMPANION_MAX_RESULT_BYTES          16384u
#define COMPANION_MAX_LABEL_BYTES           128u
#define COMPANION_MAX_REF_BYTES             96u
#define COMPANION_MAX_NOTE_BYTES            512u
#define COMPANION_MAX_DATE_BYTES            10u
#define COMPANION_MAX_TZ_BYTES              64u
#define COMPANION_MAX_WORKER_KIND_BYTES     16u
#define COMPANION_MAX_DAILY_ITEMS           64u
#define COMPANION_MAX_CONFLICT_HEADS        8u
#define COMPANION_MAX_HEALTH_SIGNALS        16u

/* Request opcodes are also declared in agentos.h; these aliases make the
 * contract header self-documenting and keep tests independent of literals. */
#define COMPANION_OP_DESCRIBE               MSG_COMPANION_DESCRIBE
#define COMPANION_OP_LIST_PROJECTS          MSG_COMPANION_LIST_PROJECTS
#define COMPANION_OP_LIST_PROGRESS          MSG_COMPANION_LIST_PROGRESS
#define COMPANION_OP_GET_DAILY_ROOT         MSG_COMPANION_GET_DAILY_ROOT
#define COMPANION_OP_GET_HEALTH_ADAPTER     MSG_COMPANION_GET_HEALTH_ADAPTER
#define COMPANION_OP_LIST_WORKER_MEMORY     MSG_COMPANION_LIST_WORKER_MEMORY
#define COMPANION_OP_SUBMIT_TASK_INTENT     MSG_COMPANION_SUBMIT_TASK_INTENT

typedef struct __attribute__((packed)) {
    uint8_t bytes[COMPANION_OBJECT_ID_BYTES];
} companion_object_id_t;

typedef companion_object_id_t companion_source_handle_t;

typedef struct __attribute__((packed)) {
    uint32_t major;
    uint32_t minor;
} companion_schema_version_t;

/* `first_seq == last_seq == 0` is the sole empty-range representation. */
typedef struct __attribute__((packed)) {
    uint32_t stream_id;
    uint64_t first_seq;
    uint64_t last_seq;
    companion_object_id_t head;
} companion_event_range_t;

typedef struct __attribute__((packed)) {
    uint64_t event_seq;
    uint64_t authority_epoch;
    uint32_t stream_id;
    uint32_t schema_major;
    companion_object_id_t root;
} companion_event_cursor_t;

enum companion_grant {
    COMPANION_GRANT_PROJECT       = 1u << 0,
    COMPANION_GRANT_PROGRESS      = 1u << 1,
    COMPANION_GRANT_DAILY_ROOT    = 1u << 2,
    COMPANION_GRANT_HEALTH        = 1u << 3,
    COMPANION_GRANT_WORKER_MEMORY = 1u << 4,
    COMPANION_GRANT_TASK_INTENT   = 1u << 5,
};

enum companion_source_class {
    COMPANION_SOURCE_PROJECTION = 0u,
    COMPANION_SOURCE_CREDENTIAL = 1u,
    COMPANION_SOURCE_PERSONAL_RECORD = 2u,
    COMPANION_SOURCE_SHELL_COMMAND = 3u,
    COMPANION_SOURCE_FILESYSTEM_PATH = 4u,
    COMPANION_SOURCE_PROMOTION = 5u,
};

enum companion_redaction_class {
    COMPANION_REDACTION_PUBLIC = 0u,
    COMPANION_REDACTION_SUMMARY = 1u,
    COMPANION_REDACTION_HASHED = 2u,
    COMPANION_REDACTION_WITHHELD = 3u,
};

enum companion_proof_level {
    COMPANION_PROOF_NONE = 0u,
    COMPANION_PROOF_HOST = 1u,
    COMPANION_PROOF_TARGET = 2u,
    COMPANION_PROOF_QEMU = 3u,
    COMPANION_PROOF_LIVE = 4u,
    COMPANION_PROOF_EXTERNAL = 5u,
};

enum companion_intent_kind {
    COMPANION_INTENT_ACKNOWLEDGE = 0u,
    COMPANION_INTENT_DEFER = 1u,
    COMPANION_INTENT_PRIORITIZE = 2u,
    COMPANION_INTENT_REQUEST_PROOF = 3u,
    COMPANION_INTENT_CANCEL = 4u,
};

/* Typed result status. Zero is success; no untyped status is permitted. */
enum companion_export_error {
    COMPANION_EXPORT_OK = 0u,
    COMPANION_EXPORT_ERR_INVALID = 1u,
    COMPANION_EXPORT_ERR_UNSUPPORTED_SCHEMA = 2u,
    COMPANION_EXPORT_ERR_DENIED = 3u,
    COMPANION_EXPORT_ERR_STALE_AUTHORITY = 4u,
    COMPANION_EXPORT_ERR_STALE_CURSOR = 5u,
    COMPANION_EXPORT_ERR_RESULT_TOO_LARGE = 6u,
    COMPANION_EXPORT_ERR_NOT_FOUND = 7u,
    COMPANION_EXPORT_ERR_UNAVAILABLE = 8u,
    COMPANION_EXPORT_ERR_CONFLICT = 9u,
    COMPANION_EXPORT_ERR_REDACTED = 10u,
    COMPANION_EXPORT_ERR_STALE_SOURCE = 11u,
    COMPANION_EXPORT_ERR_RATE_LIMITED = 12u,
    COMPANION_EXPORT_ERR_EXPIRED = 13u,
};

typedef struct __attribute__((packed)) {
    uint32_t max_items; /* 1..COMPANION_MAX_PAGE_ITEMS */
    uint32_t max_bytes; /* 1..COMPANION_MAX_RESULT_BYTES */
    uint8_t has_cursor;
    uint8_t reserved[3];
    companion_event_cursor_t cursor;
} companion_page_request_t;

typedef struct __attribute__((packed)) {
    uint32_t max_page_items;
    uint32_t max_result_bytes;
    uint32_t max_label_bytes;
    uint32_t max_ref_bytes;
    uint32_t max_note_bytes;
    uint32_t max_daily_items;
    uint32_t max_conflict_heads;
    uint32_t max_health_signals;
} companion_limits_t;

/* Fixed fields use length-prefixed bounded byte strings.  The NUL byte is
 * not part of the length and is reserved only for host-side inspection. */
typedef struct __attribute__((packed)) {
    companion_schema_version_t schema;
    uint64_t authority_epoch;
    companion_object_id_t project_id;
    companion_object_id_t snapshot_root;
    companion_event_range_t range;
    uint32_t reference_len;
    char reference[COMPANION_MAX_REF_BYTES];
    uint32_t title_len;
    char title[COMPANION_MAX_LABEL_BYTES];
    uint32_t node_count;
    uint32_t blocked_count;
    uint32_t proof;
    uint64_t updated_event_seq;
    uint32_t redaction;
} companion_project_t;

typedef struct __attribute__((packed)) {
    companion_schema_version_t schema;
    uint64_t authority_epoch;
    companion_object_id_t node_id;
    companion_object_id_t project_id;
    companion_object_id_t snapshot_root;
    companion_event_range_t range;
    uint32_t reference_len;
    char reference[COMPANION_MAX_REF_BYTES];
    uint32_t title_len;
    char title[COMPANION_MAX_LABEL_BYTES];
    uint32_t state;
    uint32_t proof;
    uint32_t depth;
    uint32_t depends_on_count;
    uint32_t percent_x100; /* 0..10000 */
    uint64_t event_seq;
    companion_object_id_t blocker_evidence_id;
    uint32_t blocker_event_seq;
    uint32_t blocker_proof;
    uint32_t blocker_redaction;
    companion_source_handle_t worker;
    uint8_t has_assignment;
    uint8_t reserved[3];
    uint32_t assignment_kind_len;
    char assignment_kind[COMPANION_MAX_WORKER_KIND_BYTES];
    uint64_t assigned_event_seq;
    uint32_t assignment_redaction;
    uint32_t redaction;
} companion_progress_t;

typedef struct __attribute__((packed)) {
    companion_object_id_t item_id;
    companion_object_id_t subject;
    uint32_t ordinal;
    uint64_t event_seq;
    uint32_t origin;
    uint32_t redaction;
} companion_daily_item_t;

typedef struct __attribute__((packed)) {
    companion_schema_version_t schema;
    uint64_t authority_epoch;
    companion_object_id_t bundle_id;
    companion_object_id_t project_root;
    companion_object_id_t event_root;
    companion_event_range_t range;
    uint32_t date_len; /* exactly 10 bytes: YYYY-MM-DD */
    char date_key[COMPANION_MAX_DATE_BYTES];
    uint32_t tz_len;
    char tz_key[COMPANION_MAX_TZ_BYTES];
    int32_t utc_offset_minutes; /* -1440..1440 */
    uint64_t built_at_unix;
    uint32_t freshness_seconds;
    uint32_t item_count;
    uint32_t conflict_head_count;
    companion_object_id_t conflict_heads[COMPANION_MAX_CONFLICT_HEADS];
    companion_daily_item_t items[COMPANION_MAX_DAILY_ITEMS];
    uint32_t redaction;
} companion_daily_root_t;

typedef struct __attribute__((packed)) {
    uint32_t source;
    uint32_t status;
    companion_object_id_t provenance;
    uint64_t observed_unix;
    uint32_t redaction;
} companion_health_signal_t;

typedef struct __attribute__((packed)) {
    companion_schema_version_t schema;
    uint64_t authority_epoch;
    companion_source_handle_t source;
    companion_object_id_t snapshot_root;
    uint32_t consent_scope;
    uint64_t consent_expires_unix;
    uint8_t revoked;
    uint8_t reserved[3];
    uint32_t status;
    uint32_t freshness_seconds;
    uint32_t signal_count;
    companion_health_signal_t signals[COMPANION_MAX_HEALTH_SIGNALS];
    companion_object_id_t provenance;
    companion_event_range_t range;
    uint32_t redaction;
} companion_health_adapter_t;

typedef struct __attribute__((packed)) {
    companion_schema_version_t schema;
    uint64_t authority_epoch;
    companion_source_handle_t worker;
    companion_object_id_t snapshot_root;
    uint32_t kind_len;
    char kind[COMPANION_MAX_WORKER_KIND_BYTES];
    uint32_t state;
    uint64_t active_bytes;
    uint64_t dormant_bytes;
    uint64_t target_low_bytes;
    uint64_t target_high_bytes;
    companion_source_handle_t assignment_worker;
    uint8_t has_assignment;
    uint8_t reserved[3];
    uint32_t assignment_kind_len;
    char assignment_kind[COMPANION_MAX_WORKER_KIND_BYTES];
    uint64_t assigned_event_seq;
    uint32_t assignment_redaction;
    uint32_t peer_count;
    uint32_t reconnect_count;
    uint64_t last_event_seq;
    companion_event_range_t range;
    uint32_t redaction;
} companion_worker_memory_t;

typedef struct __attribute__((packed)) {
    companion_schema_version_t schema;
    uint32_t min_schema_minor;
    uint64_t authority_epoch;
    uint32_t grants;
    companion_limits_t limits;
    uint64_t oldest_retained_seq;
    uint64_t newest_seq;
} companion_session_t;

typedef struct __attribute__((packed)) {
    companion_schema_version_t schema;
    uint32_t kind;
    companion_object_id_t subject;
    companion_object_id_t expect_root;
    companion_event_cursor_t cursor;
    uint64_t authority_epoch;
    uint32_t requested_proof;
    uint32_t note_len;
    char note[COMPANION_MAX_NOTE_BYTES];
    uint32_t note_redaction;
} companion_task_intent_t;

typedef struct __attribute__((packed)) {
    companion_object_id_t intent_id;
    uint8_t accepted;
    uint8_t reserved[3];
    uint64_t event_seq;
    uint64_t authority_epoch;
} companion_task_intent_receipt_t;

/* Requests.  Result records are returned in the checked result arena. */
struct companion_req_describe {
    companion_schema_version_t requested;
};

struct companion_req_list_projects {
    uint64_t authority_epoch;
    companion_page_request_t page;
};

struct companion_req_list_progress {
    uint64_t authority_epoch;
    companion_object_id_t project_id;
    companion_page_request_t page;
};

struct companion_req_get_daily_root {
    uint64_t authority_epoch;
    uint32_t date_len;
    char date_key[COMPANION_MAX_DATE_BYTES];
    uint32_t tz_len;
    char tz_key[COMPANION_MAX_TZ_BYTES];
};

struct companion_req_get_health_adapter {
    uint64_t authority_epoch;
};

struct companion_req_list_worker_memory {
    uint64_t authority_epoch;
    companion_page_request_t page;
};

struct companion_req_submit_task_intent {
    companion_task_intent_t intent;
};

typedef struct __attribute__((packed)) {
    uint32_t status; /* enum companion_export_error */
    uint32_t result_bytes;
    uint32_t item_count;
    uint8_t more;
    uint8_t reserved[3];
    companion_event_cursor_t next_cursor;
    companion_event_range_t range;
    uint64_t authority_epoch;
} companion_page_reply_t;

typedef struct __attribute__((packed)) {
    uint32_t status; /* enum companion_export_error */
    uint32_t reserved;
    uint64_t authority_epoch;
} companion_status_reply_t;

/* Validation helpers are normative and side-effect free. */
static inline bool companion_schema_compatible(companion_schema_version_t client,
                                               companion_schema_version_t server)
{
    return client.major == server.major && client.minor <= server.minor;
}

static inline bool companion_page_valid(const companion_page_request_t *page,
                                       const companion_limits_t *limits)
{
    if (page == NULL || limits == NULL || page->max_items == 0u ||
        page->max_bytes == 0u || page->max_items > limits->max_page_items ||
        page->max_bytes > limits->max_result_bytes ||
        page->max_items > COMPANION_MAX_PAGE_ITEMS ||
        page->max_bytes > COMPANION_MAX_RESULT_BYTES)
        return false;
    return true;
}

static inline bool companion_cursor_stale(const companion_event_cursor_t *cursor,
                                          uint64_t authority_epoch,
                                          uint64_t oldest_retained_seq,
                                          uint64_t newest_seq)
{
    return cursor == NULL || cursor->authority_epoch != authority_epoch ||
           cursor->event_seq < oldest_retained_seq ||
           cursor->event_seq > newest_seq;
}

_Static_assert(sizeof(companion_object_id_t) == COMPANION_OBJECT_ID_BYTES,
               "companion ObjectID must be exactly 32 bytes");
_Static_assert(sizeof(companion_event_cursor_t) == 56u,
               "companion EventCursor wire size");
_Static_assert(sizeof(struct companion_req_describe) == 8u,
               "companion describe request wire size");
_Static_assert(offsetof(companion_project_t, reference) >
               offsetof(companion_project_t, reference_len),
               "companion Project reference is length-prefixed");
_Static_assert(offsetof(companion_task_intent_t, note) >
               offsetof(companion_task_intent_t, note_len),
               "companion TaskIntent note is length-prefixed");
