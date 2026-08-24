/*
 * Fractal Companion Export Contract v1.1
 *
 * The WIT file is the authoritative logical schema.  This header defines the
 * seL4 transport for those values: requests are fixed, naturally aligned
 * records and every successful result is encoded into a caller-owned shared
 * result arena.  No variable-sized response is returned in message registers.
 *
 * v1.0 compatibility: opcodes are unchanged.  A server distinguishes the
 * legacy v1.0 request records below from v1.1 by the received request size.
 * v1.0 clients remain supported while schema major == 1 and the server reports
 * min_schema_minor == 0.  New fields are therefore a negotiated minor change.
 */

#pragma once

#include "../agentos.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Generated from tools/abi_spec.toml; never allocate this with a local literal. */
#define COMPANION_CH_CONTROLLER ABI_COMPANION_EXPORT_CH_CONTROLLER
_Static_assert(CH_COMPANION_EXPORT == COMPANION_CH_CONTROLLER,
               "companion channel drifted from generated registry");

#define COMPANION_SCHEMA_MAJOR              1u
#define COMPANION_SCHEMA_MINOR              1u
#define COMPANION_SCHEMA_MIN_MINOR          0u
#define COMPANION_ABI_ALIGNMENT             8u
#define COMPANION_OBJECT_ID_BYTES           32u
#define COMPANION_RESULT_ARENA_BYTES        65536u
#define COMPANION_MAX_REQUEST_BYTES         2048u
#define COMPANION_MAX_PAGE_ITEMS            64u
#define COMPANION_MAX_RESULT_BYTES          16384u
#define COMPANION_MAX_LABEL_BYTES           128u
#define COMPANION_MAX_REF_BYTES             96u
#define COMPANION_MAX_NOTE_BYTES            512u
#define COMPANION_MAX_DATE_BYTES            10u
#define COMPANION_MAX_TIMEZONE_BYTES        64u
#define COMPANION_MAX_WORKER_KIND_BYTES     16u
#define COMPANION_MAX_ORDERING_KEY_BYTES    96u
#define COMPANION_MAX_DAILY_ITEMS           64u
#define COMPANION_MAX_CONFLICT_HEADS        8u
#define COMPANION_MAX_HEALTH_SIGNALS        16u
#define COMPANION_MAX_PROGRESS_DEPENDENCIES 64u
#define COMPANION_MAX_CONSENT_SCOPES         8u

#define COMPANION_REPLY_FLAG_MORE            (1u << 0)
#define COMPANION_REPLY_FLAG_HAS_NEXT_CURSOR (1u << 1)

#define COMPANION_OP_DESCRIBE ABI_COMPANION_EXPORT_OP_DESCRIBE
#define COMPANION_OP_LIST_PROJECTS ABI_COMPANION_EXPORT_OP_LIST_PROJECTS
#define COMPANION_OP_LIST_PROGRESS ABI_COMPANION_EXPORT_OP_LIST_PROGRESS
#define COMPANION_OP_GET_DAILY_ROOT ABI_COMPANION_EXPORT_OP_GET_DAILY_ROOT
#define COMPANION_OP_GET_HEALTH_ADAPTER ABI_COMPANION_EXPORT_OP_GET_HEALTH_ADAPTER
#define COMPANION_OP_LIST_WORKER_MEMORY ABI_COMPANION_EXPORT_OP_LIST_WORKER_MEMORY
#define COMPANION_OP_SUBMIT_TASK_INTENT ABI_COMPANION_EXPORT_OP_SUBMIT_TASK_INTENT

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    uint8_t bytes[COMPANION_OBJECT_ID_BYTES];
} companion_object_id_t;

typedef companion_object_id_t companion_source_handle_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    uint32_t major;
    uint32_t minor;
} companion_schema_version_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    uint32_t stream_id;
    uint32_t reserved;
    uint64_t first_seq;
    uint64_t last_seq;
    companion_object_id_t head;
} companion_event_range_t;

enum companion_projection_kind {
    COMPANION_PROJECTION_PROJECT = 1u,
    COMPANION_PROJECTION_PROGRESS = 2u,
    COMPANION_PROJECTION_DAILY_ROOT = 3u,
    COMPANION_PROJECTION_HEALTH = 4u,
    COMPANION_PROJECTION_WORKER_MEMORY = 5u,
    COMPANION_PROJECTION_TASK_INTENT = 6u,
};

/* v1.1 cursors bind every resumption dimension, including the deterministic
 * zero-based position in the projection's canonical ordering. */
typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    uint64_t event_seq;
    uint64_t authority_epoch;
    uint32_t stream_id;
    uint32_t schema_major;
    uint32_t schema_minor;
    uint32_t projection;
    uint64_t position;
    companion_object_id_t root;
} companion_event_cursor_t;

/* Retained solely to decode requests produced from the published v1.0 header. */
typedef struct __attribute__((packed)) {
    uint64_t event_seq;
    uint64_t authority_epoch;
    uint32_t stream_id;
    uint32_t schema_major;
    companion_object_id_t root;
} companion_event_cursor_v1_0_t;

enum companion_grant {
    COMPANION_GRANT_PROJECT       = 1u << 0,
    COMPANION_GRANT_PROGRESS      = 1u << 1,
    COMPANION_GRANT_DAILY_ROOT    = 1u << 2,
    COMPANION_GRANT_HEALTH        = 1u << 3,
    COMPANION_GRANT_WORKER_MEMORY = 1u << 4,
    COMPANION_GRANT_TASK_INTENT   = 1u << 5,
};

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

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    uint32_t offset;
    uint32_t capacity;
} companion_result_arena_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    uint32_t abi_major;
    uint32_t abi_minor;
    uint32_t request_bytes;
    uint32_t reserved;
    companion_result_arena_t result;
} companion_request_header_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    uint32_t max_items;
    uint32_t max_bytes;
    uint8_t has_cursor;
    uint8_t reserved[7];
    companion_event_cursor_t cursor;
} companion_page_request_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    uint32_t max_page_items;
    uint32_t max_result_bytes;
    uint32_t max_label_bytes;
    uint32_t max_ref_bytes;
    uint32_t max_note_bytes;
    uint32_t max_date_bytes;
    uint32_t max_timezone_bytes;
    uint32_t max_worker_kind_bytes;
    uint32_t max_ordering_key_bytes;
    uint32_t max_daily_items;
    uint32_t max_conflict_heads;
    uint32_t max_health_signals;
    uint32_t max_progress_dependencies;
    uint32_t max_consent_scopes;
} companion_limits_t;

/* The common reply is always returned inline.  On success result_bytes is
 * non-zero and identifies an 8-byte-aligned slice wholly inside the arena
 * supplied by the request.  Errors return result_bytes == item_count == 0. */
typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    uint32_t status;
    uint32_t abi_major;
    uint32_t abi_minor;
    uint32_t flags;
    uint32_t result_offset;
    uint32_t result_bytes;
    uint32_t item_count;
    uint32_t reserved;
    uint64_t authority_epoch;
    companion_event_cursor_t next_cursor;
} companion_reply_t;

/* Result-arena encoding of WIT values. Every result starts with this record
 * header followed by the named companion_wire_* payload. Records and list
 * elements begin at an 8-byte boundary. Scalars are little-endian. Strings and lists are encoded
 * as {offset,length} slices relative to the start of this result.  Slices are
 * bounds checked, non-overlapping, and zero padded to the next 8-byte boundary.
 * Object IDs and source handles are inline exactly 32 bytes. */
typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    uint32_t record_type;
    uint32_t record_bytes;
    uint32_t field_count;
    uint32_t reserved;
} companion_wire_record_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    uint32_t offset;
    uint32_t length;
} companion_wire_bytes_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    uint32_t offset;
    uint32_t count;
    uint32_t stride;
    uint32_t reserved;
} companion_wire_list_t;

enum companion_wire_record_type {
    COMPANION_WIRE_SESSION = 1u,
    COMPANION_WIRE_PROJECT_PAGE = 2u,
    COMPANION_WIRE_PROGRESS_PAGE = 3u,
    COMPANION_WIRE_DAILY_ROOT = 4u,
    COMPANION_WIRE_HEALTH_ADAPTER_SUMMARY = 5u,
    COMPANION_WIRE_WORKER_MEMORY_PAGE = 6u,
    COMPANION_WIRE_TASK_INTENT_RECEIPT = 7u,
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

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    companion_source_handle_t worker;
    companion_wire_bytes_t kind;
    uint64_t assigned_event_seq;
    uint32_t redaction;
    uint32_t reserved;
} companion_wire_worker_assignment_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    companion_object_id_t evidence_id;
    uint64_t event_seq;
    uint32_t observed_proof;
    uint32_t redaction;
} companion_wire_blocker_evidence_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    uint8_t has_value;
    uint8_t reserved[7];
    companion_wire_worker_assignment_t value;
} companion_wire_optional_assignment_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    uint64_t authority_epoch;
    uint32_t item_count;
    uint32_t item_bytes;
    uint32_t flags;
    uint32_t reserved;
    companion_event_cursor_t next_cursor;
    companion_event_range_t range;
} companion_wire_page_info_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    companion_schema_version_t schema;
    uint64_t authority_epoch;
    companion_object_id_t project_id;
    companion_object_id_t snapshot_root;
    companion_event_range_t range;
    companion_wire_bytes_t reference;
    companion_wire_bytes_t title;
    uint32_t node_count;
    uint32_t blocked_count;
    uint32_t proof;
    uint32_t reserved;
    uint64_t updated_event_seq;
    uint32_t redaction;
    uint32_t reserved2;
} companion_wire_project_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    companion_schema_version_t schema;
    uint64_t authority_epoch;
    companion_object_id_t node_id;
    companion_object_id_t project_id;
    companion_object_id_t snapshot_root;
    companion_event_range_t range;
    companion_wire_bytes_t reference;
    companion_wire_bytes_t title;
    uint32_t state;
    uint32_t proof;
    uint32_t depth;
    uint32_t depends_on_count;
    uint32_t percent_x100;
    uint32_t reserved;
    uint64_t event_seq;
    companion_wire_blocker_evidence_t blocker;
    companion_wire_optional_assignment_t assignment;
    uint32_t redaction;
    uint32_t reserved2;
} companion_wire_progress_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    companion_object_id_t intent_id;
    uint32_t kind;
    uint32_t reserved;
    companion_object_id_t subject;
    companion_object_id_t expect_root;
} companion_wire_task_intent_reference_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    uint8_t has_value;
    uint8_t reserved[7];
    companion_wire_task_intent_reference_t value;
} companion_wire_optional_intent_reference_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    companion_object_id_t item_id;
    companion_object_id_t subject;
    companion_wire_bytes_t ordering_key;
    uint32_t ordinal;
    uint32_t reserved;
    uint64_t event_seq;
    uint32_t origin;
    uint32_t reserved2;
    companion_object_id_t provenance;
    uint32_t freshness_seconds;
    uint32_t source_freshness;
    companion_wire_optional_intent_reference_t intent;
    uint32_t redaction;
    uint32_t reserved3;
} companion_wire_daily_item_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    companion_schema_version_t schema;
    uint64_t authority_epoch;
    companion_object_id_t bundle_id;
    companion_object_id_t project_root;
    companion_object_id_t event_root;
    companion_event_range_t range;
    companion_wire_bytes_t date_key;
    companion_wire_bytes_t timezone_key;
    int32_t utc_offset_minutes;
    uint32_t reserved;
    uint64_t built_at_unix;
    uint32_t freshness_seconds;
    uint32_t source_freshness;
    uint32_t item_count;
    companion_wire_list_t items;
    companion_object_id_t provenance;
    companion_wire_list_t conflict_heads;
    uint32_t merge_policy;
    uint8_t has_merge_schema;
    uint8_t merge_reserved[3];
    companion_object_id_t merge_schema;
    uint32_t redaction;
    uint32_t reserved2;
} companion_wire_daily_root_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    uint32_t source;
    uint32_t status;
    companion_object_id_t provenance;
    uint64_t observed_unix;
    uint32_t freshness_seconds;
    uint32_t source_freshness;
    uint32_t redaction;
    uint32_t reserved;
} companion_wire_health_signal_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    companion_schema_version_t schema;
    uint64_t authority_epoch;
    companion_source_handle_t source;
    uint32_t origin;
    uint32_t reserved2;
    companion_wire_list_t consent_scope;
    uint64_t consent_expires_unix;
    uint8_t revoked;
    uint8_t reserved[3];
    uint32_t status;
    uint32_t freshness_seconds;
    uint32_t reserved3;
    companion_wire_list_t signals;
    companion_object_id_t provenance;
    companion_event_range_t range;
    uint32_t redaction;
    uint32_t reserved4;
} companion_wire_health_adapter_summary_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    companion_schema_version_t schema;
    uint64_t authority_epoch;
    companion_source_handle_t worker;
    companion_wire_bytes_t kind;
    uint32_t state;
    uint32_t reserved;
    uint64_t active_bytes;
    uint64_t dormant_bytes;
    uint64_t target_low_bytes;
    uint64_t target_high_bytes;
    companion_wire_optional_assignment_t assignment;
    uint32_t peer_count;
    uint32_t reconnect_count;
    uint64_t last_event_seq;
    companion_event_range_t range;
    uint32_t redaction;
    uint32_t reserved2;
} companion_wire_worker_memory_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    companion_schema_version_t schema;
    uint32_t min_schema_minor;
    uint32_t reserved;
    uint64_t authority_epoch;
    uint32_t grants;
    uint32_t reserved2;
    companion_limits_t limits;
    uint64_t oldest_retained_seq;
    uint64_t newest_seq;
} companion_wire_session_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    companion_object_id_t intent_id;
    uint8_t accepted;
    uint8_t reserved[7];
    uint64_t event_seq;
    uint64_t authority_epoch;
} companion_wire_task_intent_receipt_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    companion_schema_version_t schema;
    uint32_t kind;
    uint32_t reserved;
    companion_object_id_t subject;
    companion_object_id_t expect_root;
    companion_event_cursor_t cursor;
    uint64_t authority_epoch;
    uint32_t requested_proof;
    uint32_t note_len;
    char note[COMPANION_MAX_NOTE_BYTES];
    uint32_t note_redaction;
    uint32_t reserved2;
} companion_wire_task_intent_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    companion_wire_page_info_t page;
    companion_wire_list_t items;
} companion_wire_project_page_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    companion_wire_page_info_t page;
    companion_wire_list_t items;
} companion_wire_progress_page_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    companion_wire_page_info_t page;
    companion_wire_list_t items;
} companion_wire_worker_memory_page_t;

/* Transport call: MR0=opcode, MR1=request_offset, MR2=request_bytes. The
 * request record is copied by the caller into its capability-scoped 64 KiB
 * companion arena. `header.request_bytes` must equal both MR2 and sizeof(the
 * received record). The request and result slices must be aligned, bounded,
 * and non-overlapping. This also distinguishes v1.1 from legacy v1.0. */
struct companion_req_describe {
    companion_request_header_t header;
    companion_schema_version_t requested;
};

struct companion_req_list_projects {
    companion_request_header_t header;
    uint64_t authority_epoch;
    companion_page_request_t page;
};

struct companion_req_list_progress {
    companion_request_header_t header;
    uint64_t authority_epoch;
    companion_object_id_t project_id;
    companion_page_request_t page;
};

struct companion_req_get_daily_root {
    companion_request_header_t header;
    uint64_t authority_epoch;
    uint32_t date_len;
    char date_key[COMPANION_MAX_DATE_BYTES];
    uint8_t date_padding[2];
    uint32_t timezone_len;
    char timezone_key[COMPANION_MAX_TIMEZONE_BYTES];
};

struct companion_req_get_health_adapter {
    companion_request_header_t header;
    uint64_t authority_epoch;
};

struct companion_req_list_worker_memory {
    companion_request_header_t header;
    uint64_t authority_epoch;
    companion_page_request_t page;
};

struct companion_req_submit_task_intent {
    companion_request_header_t header;
    companion_wire_task_intent_t intent;
};

/* Published v1.0 request layouts.  A v1.1 server accepts these while its
 * min_schema_minor is zero and returns the v1.0 result encoding. */
struct companion_req_describe_v1_0 {
    companion_schema_version_t requested;
};

typedef struct __attribute__((packed)) {
    uint32_t max_items;
    uint32_t max_bytes;
    uint8_t has_cursor;
    uint8_t reserved[3];
    companion_event_cursor_v1_0_t cursor;
} companion_page_request_v1_0_t;

struct companion_req_list_projects_v1_0 {
    uint64_t authority_epoch;
    companion_page_request_v1_0_t page;
};

struct companion_req_list_progress_v1_0 {
    uint64_t authority_epoch;
    companion_object_id_t project_id;
    companion_page_request_v1_0_t page;
};

struct companion_req_get_daily_root_v1_0 {
    uint64_t authority_epoch;
    uint32_t date_len;
    char date_key[COMPANION_MAX_DATE_BYTES];
    uint32_t timezone_len;
    char timezone_key[COMPANION_MAX_TIMEZONE_BYTES];
};

struct companion_req_get_health_adapter_v1_0 {
    uint64_t authority_epoch;
};

struct companion_req_list_worker_memory_v1_0 {
    uint64_t authority_epoch;
    companion_page_request_v1_0_t page;
};

typedef companion_wire_session_t companion_session_t;

typedef struct __attribute__((aligned(COMPANION_ABI_ALIGNMENT))) {
    companion_schema_version_t schema;
    uint32_t projection;
    uint32_t stream_id;
    companion_object_id_t root;
    uint64_t authority_epoch;
    uint64_t oldest_retained_seq;
    uint64_t newest_seq;
    uint64_t max_position;
} companion_cursor_binding_t;

static inline bool companion_object_id_equal(const companion_object_id_t *a,
                                             const companion_object_id_t *b)
{
    if (a == NULL || b == NULL) return false;
    for (uint32_t i = 0u; i < COMPANION_OBJECT_ID_BYTES; i++)
        if (a->bytes[i] != b->bytes[i]) return false;
    return true;
}

static inline bool companion_schema_supported(companion_schema_version_t client,
                                              companion_schema_version_t server,
                                              uint32_t min_minor)
{
    return client.major == server.major && client.minor >= min_minor
        && client.minor <= server.minor;
}

static inline bool companion_schema_compatible(companion_schema_version_t client,
                                               companion_schema_version_t server)
{
    return companion_schema_supported(client, server,
                                      COMPANION_SCHEMA_MIN_MINOR);
}

static inline bool companion_arena_valid(const companion_result_arena_t *arena,
                                         uint32_t required_bytes)
{
    if (arena == NULL || arena->capacity == 0u
        || arena->capacity > COMPANION_MAX_RESULT_BYTES
        || required_bytes > arena->capacity
        || (arena->offset & (COMPANION_ABI_ALIGNMENT - 1u)) != 0u)
        return false;
    return arena->offset <= COMPANION_RESULT_ARENA_BYTES - arena->capacity;
}

static inline bool companion_request_transport_valid(
    uint32_t request_offset, uint32_t request_bytes,
    const companion_result_arena_t *result)
{
    if (result == NULL || request_bytes == 0u
        || request_bytes > COMPANION_MAX_REQUEST_BYTES
        || (request_offset & (COMPANION_ABI_ALIGNMENT - 1u)) != 0u
        || request_offset > COMPANION_RESULT_ARENA_BYTES - request_bytes
        || !companion_arena_valid(result, sizeof(companion_wire_record_t)))
        return false;
    uint32_t request_end = request_offset + request_bytes;
    uint32_t result_end = result->offset + result->capacity;
    return request_end <= result->offset || result_end <= request_offset;
}

static inline bool companion_page_valid(const companion_page_request_t *page,
                                        const companion_limits_t *limits)
{
    return page != NULL && limits != NULL && page->max_items != 0u
        && page->max_bytes != 0u
        && page->max_items <= limits->max_page_items
        && page->max_bytes <= limits->max_result_bytes
        && page->max_items <= COMPANION_MAX_PAGE_ITEMS
        && page->max_bytes <= COMPANION_MAX_RESULT_BYTES;
}

static inline uint32_t companion_cursor_validate(
    const companion_event_cursor_t *cursor,
    const companion_cursor_binding_t *binding)
{
    if (cursor == NULL || binding == NULL) return COMPANION_EXPORT_ERR_INVALID;
    if (cursor->schema_major != binding->schema.major
        || cursor->schema_minor != binding->schema.minor
        || cursor->projection != binding->projection
        || cursor->stream_id != binding->stream_id
        || cursor->authority_epoch != binding->authority_epoch
        || !companion_object_id_equal(&cursor->root, &binding->root)
        || cursor->event_seq < binding->oldest_retained_seq
        || cursor->event_seq > binding->newest_seq
        || cursor->position > binding->max_position)
        return COMPANION_EXPORT_ERR_STALE_CURSOR;
    return COMPANION_EXPORT_OK;
}

/* Compatibility helper retained for callers that only need epoch/window
 * screening.  New code must use companion_cursor_validate(). */
static inline bool companion_cursor_stale(const companion_event_cursor_t *cursor,
                                          uint64_t authority_epoch,
                                          uint64_t oldest_retained_seq,
                                          uint64_t newest_seq)
{
    return cursor == NULL || cursor->authority_epoch != authority_epoch
        || cursor->event_seq < oldest_retained_seq
        || cursor->event_seq > newest_seq;
}

_Static_assert((COMPANION_ABI_ALIGNMENT & (COMPANION_ABI_ALIGNMENT - 1u)) == 0u,
               "companion ABI alignment must be a power of two");
_Static_assert(sizeof(companion_object_id_t) == 32u,
               "ObjectID wire size");
_Static_assert(sizeof(companion_event_cursor_v1_0_t) == 56u,
               "v1.0 cursor remains decodable");
_Static_assert(sizeof(companion_event_cursor_t) == 72u,
               "v1.1 cursor wire size");
_Static_assert(offsetof(companion_event_cursor_t, position) == 32u,
               "cursor position is deterministic and aligned");
_Static_assert(sizeof(companion_request_header_t) == 24u,
               "request header wire size");
_Static_assert(sizeof(companion_reply_t) == 112u,
               "bounded common reply wire size");
_Static_assert(sizeof(struct companion_req_describe_v1_0) == 8u,
               "v1.0 describe request remains distinguishable");
_Static_assert(sizeof(struct companion_req_describe) == 32u,
               "v1.1 describe request wire size");
_Static_assert(sizeof(struct companion_req_list_projects) <= COMPANION_MAX_REQUEST_BYTES,
               "project request exceeds bounded transport");
_Static_assert(sizeof(struct companion_req_list_progress) <= COMPANION_MAX_REQUEST_BYTES,
               "progress request exceeds bounded transport");
_Static_assert(sizeof(struct companion_req_get_daily_root) <= COMPANION_MAX_REQUEST_BYTES,
               "daily-root request exceeds bounded transport");
_Static_assert(sizeof(struct companion_req_get_health_adapter) <= COMPANION_MAX_REQUEST_BYTES,
               "health request exceeds bounded transport");
_Static_assert(sizeof(struct companion_req_list_worker_memory) <= COMPANION_MAX_REQUEST_BYTES,
               "worker-memory request exceeds bounded transport");
_Static_assert(sizeof(struct companion_req_submit_task_intent) <= COMPANION_MAX_REQUEST_BYTES,
               "task-intent request exceeds bounded transport");
_Static_assert(sizeof(companion_wire_record_t) + sizeof(companion_wire_session_t)
                   <= COMPANION_MAX_RESULT_BYTES,
               "session response exceeds bounded transport");
_Static_assert(sizeof(companion_wire_record_t) + sizeof(companion_wire_daily_root_t)
                   <= COMPANION_MAX_RESULT_BYTES,
               "daily-root response header exceeds bounded transport");
_Static_assert(sizeof(companion_wire_record_t) + sizeof(companion_wire_health_adapter_summary_t)
                   <= COMPANION_MAX_RESULT_BYTES,
               "health response header exceeds bounded transport");
_Static_assert(COMPANION_MAX_DATE_BYTES % 2u == 0u,
               "date field padding assumes an even bound");
