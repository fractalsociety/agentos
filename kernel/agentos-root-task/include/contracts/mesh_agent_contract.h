/*
 * MeshAgent / Fractal Mesh Contract
 *
 * This header is the C contract boundary for the distributed Fractal object
 * and task mesh.  It describes generated wire records; it is not a network
 * codec and it deliberately contains no socket, QUIC, datagram, or seL4 badge
 * representation.  A generated encoder/decoder owns byte serialization and
 * must preserve the field order, widths, and little-endian encoding declared
 * by the schema constants below.
 *
 * Reliable streams carry semantic frames.  A datagram may carry only a
 * disposable hint (presence, load, or cache availability).  A lost,
 * duplicated, or reordered hint must not change authorization, task state,
 * event state, object state, lease state, or completion state.
 *
 * Channel: controller ↔ mesh_agent (assigned in agentos.system)
 * Opcodes: MSG_MESH_* / MSG_REMOTE_SPAWN_* (see agentos.h)
 */

#pragma once
#include "../agentos.h"
#include "eventbus_contract.h"

/* ─── Generated wire schema constants ───────────────────────────────────── */

#define MESH_CONTRACT_VERSION          1u
#define MESH_WIRE_SCHEMA_VERSION       1u
#define MESH_WIRE_ENCODING_GENERATED   1u
#define MESH_WIRE_LITTLE_ENDIAN        1u
#define MESH_WIRE_LENGTH_DELIMITED     1u

#define MESH_ID_BYTES                  32u
#define MESH_SIGNATURE_BYTES           64u
#define MESH_RESUME_TOKEN_BYTES        32u
#define MESH_NONCE_BYTES               32u
#define MESH_ENDPOINT_BYTES            64u
#define MESH_FRAME_HEADER_BYTES        64u
#define MESH_MAX_FRAME_PAYLOAD         (64u * 1024u)
#define MESH_MAX_FRAME_BYTES           (MESH_FRAME_HEADER_BYTES + MESH_MAX_FRAME_PAYLOAD)
#define MESH_MAX_INFLIGHT_FRAMES       64u
#define MESH_MAX_INFLIGHT_BYTES        (1024u * 1024u)

/* ─── Immutable distributed identities ──────────────────────────────────── */

struct mesh_node_id {
    uint8_t bytes[MESH_ID_BYTES];
};
typedef struct mesh_node_id mesh_node_id_t;

struct mesh_service_id {
    uint8_t bytes[MESH_ID_BYTES];
};
typedef struct mesh_service_id mesh_service_id_t;

struct mesh_space_id {
    uint8_t bytes[MESH_ID_BYTES];
};
typedef struct mesh_space_id mesh_space_id_t;

struct mesh_object_id {
    uint8_t bytes[MESH_ID_BYTES];
};
typedef struct mesh_object_id mesh_object_id_t;

struct mesh_agent_id {
    uint8_t bytes[MESH_ID_BYTES];
};
typedef struct mesh_agent_id mesh_agent_id_t;

struct mesh_interface_hash {
    uint8_t bytes[MESH_ID_BYTES];
};
typedef struct mesh_interface_hash mesh_interface_hash_t;

struct mesh_remote_session_handle {
    uint64_t session_id;
    uint64_t generation;
};
typedef struct mesh_remote_session_handle mesh_remote_session_handle_t;

struct mesh_resume_token {
    uint8_t bytes[MESH_RESUME_TOKEN_BYTES];
};
typedef struct mesh_resume_token mesh_resume_token_t;

/* A network message never contains a local endpoint badge.  A badge is
 * derived by the receiving CapBroker after grant validation and remains a
 * local capability in the receiving address space. */
#define MESH_REMOTE_GRANT_HAS_LOCAL_BADGE 0u
#define MESH_REMOTE_WIRE_HAS_BADGE        0u

/* ─── Signed discovery and authority records ────────────────────────────── */

#define MESH_ADVERTISEMENT_SIGNATURE_DOMAIN "agentos/fractal-service-ad/1"

struct mesh_service_advertisement {
    mesh_service_id_t service_id;
    mesh_node_id_t provider_node;
    mesh_interface_hash_t interface_hash;
    uint8_t endpoint[MESH_ENDPOINT_BYTES];
    uint64_t required_capability;
    uint64_t health_epoch;
    uint64_t expiry_unix_ms;
    uint8_t signature[MESH_SIGNATURE_BYTES];
};
typedef struct mesh_service_advertisement mesh_service_advertisement_t;

enum mesh_effect_class {
    MESH_EFFECT_READ_ONLY = 0u,
    MESH_EFFECT_LOCAL      = 1u,
    MESH_EFFECT_SHARED     = 2u,
    MESH_EFFECT_EXTERNAL   = 3u,
};

#define MESH_GRANT_SCOPE_OBJECTS      (1u << 0)
#define MESH_GRANT_SCOPE_SPACE_ROOT  (1u << 1)
#define MESH_GRANT_SCOPE_MAILBOX     (1u << 2)

struct mesh_remote_grant {
    mesh_node_id_t issuer;
    mesh_node_id_t subject_node;
    mesh_agent_id_t subject_agent;
    mesh_node_id_t audience_node;
    mesh_space_id_t space_id;
    mesh_interface_hash_t interface_hash;
    mesh_object_id_t object_scope;
    uint64_t operation_mask;
    uint32_t scope_flags;
    uint32_t effect_class;
    uint64_t budget_units;
    uint64_t expiry_unix_ms;
    uint64_t authority_epoch;
    uint64_t revocation_epoch;
    uint8_t nonce[MESH_NONCE_BYTES];
    uint8_t signature[MESH_SIGNATURE_BYTES];
};
typedef struct mesh_remote_grant mesh_remote_grant_t;

struct mesh_revocation_epoch {
    uint64_t authority_epoch;
    uint64_t revocation_epoch;
};
typedef struct mesh_revocation_epoch mesh_revocation_epoch_t;

struct mesh_execution_lease {
    uint64_t lease_id;
    uint64_t fence_epoch;
    uint64_t expires_unix_ms;
    uint64_t authority_epoch;
    uint64_t revocation_epoch;
    mesh_node_id_t holder_node;
    mesh_agent_id_t subject_agent;
    mesh_space_id_t space_id;
    uint8_t nonce[MESH_NONCE_BYTES];
    uint8_t signature[MESH_SIGNATURE_BYTES];
};
typedef struct mesh_execution_lease mesh_execution_lease_t;

/* Schema-facing names used by the language-neutral contract documentation. */
typedef mesh_node_id_t NodeID;
typedef mesh_service_id_t ServiceID;
typedef mesh_space_id_t SpaceID;
typedef mesh_remote_session_handle_t RemoteSessionHandle;
typedef mesh_service_advertisement_t ServiceAdvertisement;
typedef mesh_remote_grant_t RemoteGrant;
typedef mesh_execution_lease_t ExecutionLease;

/* ─── Typed, length-delimited semantic frames ───────────────────────────── */

#define MESH_FRAME_MAGIC 0x314D5346u /* ASCII "FSM1", generated schema v1 */

enum mesh_frame_type {
    MESH_FRAME_TASK    = 1u,
    MESH_FRAME_EVENT   = 2u,
    MESH_FRAME_OBJECT  = 3u,
    MESH_FRAME_CONTROL = 4u,
    MESH_FRAME_HINT    = 5u, /* disposable datagram contents only */
};

enum mesh_frame_flags {
    MESH_FRAME_FLAG_FIRST       = 1u << 0,
    MESH_FRAME_FLAG_LAST        = 1u << 1,
    MESH_FRAME_FLAG_ACK         = 1u << 2,
    MESH_FRAME_FLAG_CANCEL      = 1u << 3,
    MESH_FRAME_FLAG_RESUMED     = 1u << 4,
};

/* Fixed-width generated header.  `header_bytes + payload_bytes` is the
 * complete semantic frame length; the carrier's packet/stream framing is not
 * part of this ABI. */
struct mesh_frame_header {
    uint32_t magic;
    uint16_t schema_version;
    uint8_t frame_type;
    uint8_t flags;
    uint32_t header_bytes;
    uint32_t payload_bytes;
    uint64_t session_id;
    uint64_t session_generation;
    uint64_t sequence;
    uint64_t ack_sequence;
    uint64_t authority_epoch;
    uint64_t revocation_epoch;
};
typedef struct mesh_frame_header mesh_frame_header_t;

struct mesh_task_frame {
    mesh_agent_id_t task_id;
    uint32_t task_kind;
    uint32_t task_flags;
    uint64_t task_bytes;
};
typedef struct mesh_task_frame mesh_task_frame_t;

struct mesh_event_frame {
    mesh_object_id_t event_id;
    mesh_object_id_t parent_event_id;
    uint64_t event_sequence;
    uint32_t event_kind;
    uint32_t event_bytes;
};
typedef struct mesh_event_frame mesh_event_frame_t;

struct mesh_object_frame {
    mesh_object_id_t object_id;
    uint64_t chunk_offset;
    uint64_t object_bytes;
    uint32_t chunk_bytes;
    uint32_t object_flags;
    uint8_t chunk_digest[MESH_ID_BYTES];
};
typedef struct mesh_object_frame mesh_object_frame_t;

struct mesh_control_frame {
    uint32_t control_kind;
    uint32_t credit_frames;
    uint64_t credit_bytes;
    uint64_t next_sequence;
    uint64_t completion_sequence;
    uint64_t cancellation_id;
    uint64_t resume_sequence;
};
typedef struct mesh_control_frame mesh_control_frame_t;

struct mesh_hint_frame {
    uint32_t hint_kind;
    uint32_t load_units;
    uint64_t hint_expiry_unix_ms;
};
typedef struct mesh_hint_frame mesh_hint_frame_t;

enum mesh_control_kind {
    MESH_CONTROL_KEEPALIVE       = 1u,
    MESH_CONTROL_CREDIT          = 2u,
    MESH_CONTROL_ACK             = 3u,
    MESH_CONTROL_CANCEL          = 4u,
    MESH_CONTROL_COMPLETE        = 5u,
    MESH_CONTROL_RESUME          = 6u,
};

enum mesh_task_kind {
    MESH_TASK_SUBMIT             = 1u,
    MESH_TASK_MESSAGE            = 2u,
    MESH_TASK_RESULT             = 3u,
};

enum mesh_event_kind {
    MESH_EVENT_CANONICAL         = 1u,
    MESH_EVENT_SESSION            = 2u,
    MESH_EVENT_AUTHORIZATION      = 3u,
};

/* ─── Asynchronous session and lease IPC records ────────────────────────── */

struct mesh_agent_req_session_open {
    mesh_node_id_t target_node;
    mesh_service_id_t service_id;
    mesh_space_id_t space_id;
    mesh_remote_grant_t grant;
    uint64_t requested_sequence;
};

struct mesh_agent_reply_session_open {
    uint32_t status;
    uint32_t reserved;
    mesh_remote_session_handle_t handle;
    mesh_resume_token_t resume_token;
    uint64_t accepted_sequence;
};

struct mesh_agent_req_session_resume {
    mesh_remote_session_handle_t handle;
    mesh_resume_token_t resume_token;
    uint64_t last_received_sequence;
    uint64_t last_completed_sequence;
};

struct mesh_agent_reply_session_resume {
    uint32_t status;
    uint32_t replay_from_available;
    mesh_resume_token_t next_resume_token;
    uint64_t next_sequence;
    uint64_t next_completed_sequence;
};

struct mesh_agent_req_session_cancel {
    mesh_remote_session_handle_t handle;
    uint64_t cancellation_id;
    uint32_t reason;
    uint32_t reserved;
};

struct mesh_agent_reply_session_cancel {
    uint32_t status;
    uint32_t was_pending;
    uint64_t cancellation_id;
};

struct mesh_agent_req_service_advertise {
    mesh_service_advertisement_t advertisement;
};

struct mesh_agent_reply_service_advertise {
    uint32_t status;
    uint32_t reserved;
    uint64_t health_epoch;
};

struct mesh_agent_req_service_withdraw {
    mesh_service_id_t service_id;
    uint64_t health_epoch;
};

struct mesh_agent_req_lease {
    mesh_execution_lease_t lease;
};

struct mesh_agent_reply_lease {
    uint32_t status;
    uint32_t reserved;
    mesh_execution_lease_t lease;
};

struct mesh_agent_req_revocation_epoch {
    mesh_revocation_epoch_t epoch;
};

struct mesh_agent_req_frame_ack {
    mesh_remote_session_handle_t handle;
    uint64_t sequence;
    uint64_t credit_bytes;
    uint32_t credit_frames;
    uint32_t reserved;
};

enum mesh_session_state {
    MESH_SESSION_OPEN = 1u,
    MESH_SESSION_ACTIVE = 2u,
    MESH_SESSION_CANCELLING = 3u,
    MESH_SESSION_COMPLETE = 4u,
    MESH_SESSION_RESUMABLE = 5u,
    MESH_SESSION_CLOSED = 6u,
};

enum mesh_cancel_reason {
    MESH_CANCEL_REQUESTED = 1u,
    MESH_CANCEL_DEADLINE = 2u,
    MESH_CANCEL_REVOKED = 3u,
    MESH_CANCEL_BUDGET = 4u,
    MESH_CANCEL_DISCONNECT = 5u,
};

enum mesh_completion_status {
    MESH_COMPLETION_OK = 0u,
    MESH_COMPLETION_FAILED = 1u,
    MESH_COMPLETION_CANCELLED = 2u,
};

/* ─── Contract-only guards ───────────────────────────────────────────────── */

struct mesh_replay_cursor {
    uint64_t highest_sequence;
};
typedef struct mesh_replay_cursor mesh_replay_cursor_t;

struct mesh_completion_guard {
    uint64_t completion_sequence;
    uint8_t completed;
};
typedef struct mesh_completion_guard mesh_completion_guard_t;

struct mesh_flow_window {
    uint32_t frames_in_flight;
    uint32_t reserved;
    uint64_t bytes_in_flight;
};
typedef struct mesh_flow_window mesh_flow_window_t;

/* ─── Remote authority validation contract ──────────────────────────────── */

#define MESH_REMOTE_GRANT_SIGNATURE_DOMAIN \
    "agentos/fractal-remote-grant/1"
#define MESH_EXECUTION_LEASE_SIGNATURE_DOMAIN \
    "agentos/fractal-execution-lease/1"
#define MESH_REMOTE_GRANT_SIGNING_BYTES 304u
#define MESH_EXECUTION_LEASE_SIGNING_BYTES 168u
#define MESH_REMOTE_NONCE_CACHE_CAP 64u

enum mesh_authorization_decision {
    MESH_AUTHZ_DECISION_DENY = 0u,
    MESH_AUTHZ_DECISION_ALLOW = 1u,
};

enum mesh_remote_authn_status {
    MESH_REMOTE_AUTHN_OK = 0u,
    MESH_REMOTE_AUTHN_UNTRUSTED_ISSUER = 1u,
    MESH_REMOTE_AUTHN_BAD_SIGNATURE = 2u,
    MESH_REMOTE_AUTHN_REVOKED_ISSUER = 3u,
};

enum mesh_authorization_status {
    MESH_AUTHZ_OK = 0u,
    MESH_AUTHZ_ERR_BAD_ARG = 1u,
    MESH_AUTHZ_ERR_PEER_SUBJECT = 2u,
    MESH_AUTHZ_ERR_ISSUER = 3u,
    MESH_AUTHZ_ERR_SIGNATURE = 4u,
    MESH_AUTHZ_ERR_AUDIENCE = 5u,
    MESH_AUTHZ_ERR_AGENT = 6u,
    MESH_AUTHZ_ERR_SPACE = 7u,
    MESH_AUTHZ_ERR_INTERFACE = 8u,
    MESH_AUTHZ_ERR_OPERATION = 9u,
    MESH_AUTHZ_ERR_OBJECT_SCOPE = 10u,
    MESH_AUTHZ_ERR_EFFECT = 11u,
    MESH_AUTHZ_ERR_BUDGET = 12u,
    MESH_AUTHZ_ERR_EXPIRED = 13u,
    MESH_AUTHZ_ERR_NONCE = 14u,
    MESH_AUTHZ_ERR_REPLAY = 15u,
    MESH_AUTHZ_ERR_STALE_AUTHORITY = 16u,
    MESH_AUTHZ_ERR_REVOKED = 17u,
    MESH_AUTHZ_ERR_REMOTE_BADGE = 18u,
    MESH_AUTHZ_ERR_CAPBROKER = 19u,
    MESH_AUTHZ_ERR_LEASE_PARTITIONED = 20u,
    MESH_AUTHZ_ERR_LEASE_SUBJECT = 21u,
    MESH_AUTHZ_ERR_LEASE_SIGNATURE = 22u,
    MESH_AUTHZ_ERR_NOT_ADMITTED = 23u,
    MESH_AUTHZ_ERR_DUPLICATE_COMPLETION = 24u,
    MESH_AUTHZ_ERR_EVENT = 25u,
};

typedef uint32_t (*mesh_remote_grant_verify_fn)(
    const mesh_remote_grant_t *grant, void *ctx);
typedef uint32_t (*mesh_execution_lease_verify_fn)(
    const mesh_execution_lease_t *lease,
    const mesh_remote_grant_t *grant, void *ctx);
typedef uint64_t (*mesh_capbroker_derive_fn)(
    const mesh_remote_grant_t *grant, uint64_t requested_operations,
    uint32_t requested_effect_class, uint64_t requested_budget_units,
    void *ctx);
typedef uint32_t (*mesh_authz_event_fn)(
    uint32_t canonical_event_type, uint32_t decision, uint32_t status,
    const mesh_remote_grant_t *grant,
    const mesh_execution_lease_t *lease, uint64_t local_badge, void *ctx);

struct mesh_remote_nonce_entry {
    mesh_node_id_t issuer;
    uint8_t nonce[MESH_NONCE_BYTES];
    uint64_t expiry_unix_ms;
    uint64_t authority_epoch;
    uint64_t revocation_epoch;
    uint8_t active;
};

struct mesh_remote_authority_state {
    struct mesh_remote_nonce_entry nonces[MESH_REMOTE_NONCE_CACHE_CAP];
    uint32_t next_nonce;
};
typedef struct mesh_remote_authority_state mesh_remote_authority_state_t;

struct mesh_remote_authority_context {
    /* Transport identity is authentication input only.  In particular, a
     * Headscale/tailnet identity is never an Agent ISA authority grant. */
    mesh_node_id_t authenticated_tailnet_peer;
    mesh_node_id_t local_node;
    mesh_agent_id_t expected_agent;
    mesh_space_id_t expected_space;
    mesh_interface_hash_t expected_interface;
    mesh_object_id_t expected_object_scope;
    uint64_t requested_operations;
    uint32_t required_scope_flags;
    uint32_t requested_effect_class;
    uint32_t max_effect_class;
    uint64_t requested_budget_units;
    uint64_t now_unix_ms;
    uint64_t authority_epoch;
    uint64_t revocation_epoch;
    uint64_t expected_lease_fence_epoch;
    mesh_remote_grant_verify_fn verify_grant;
    mesh_execution_lease_verify_fn verify_lease;
    mesh_capbroker_derive_fn derive_local_badge;
    mesh_authz_event_fn emit_event;
    void *callback_ctx;
};
typedef struct mesh_remote_authority_context mesh_remote_authority_context_t;

void mesh_agent_remote_authority_init(mesh_remote_authority_state_t *state);
uint32_t mesh_agent_admit_remote_grant(
    mesh_remote_authority_state_t *state,
    const mesh_remote_grant_t *grant,
    const mesh_remote_authority_context_t *ctx,
    uint64_t serialized_badge, uint64_t *out_local_badge);
uint32_t mesh_agent_recheck_remote_grant(
    const mesh_remote_authority_state_t *state,
    const mesh_remote_grant_t *grant,
    const mesh_remote_authority_context_t *ctx,
    uint64_t *out_local_badge);
uint32_t mesh_agent_validate_execution_lease(
    const mesh_execution_lease_t *lease,
    const mesh_remote_grant_t *grant,
    const mesh_remote_authority_context_t *ctx);

static inline bool mesh_frame_type_is_datagram_safe(uint8_t frame_type)
{
    return frame_type == MESH_FRAME_HINT;
}

static inline bool mesh_frame_header_valid(const mesh_frame_header_t *header,
                                           uint32_t available_bytes)
{
    if (header == NULL || header->magic != MESH_FRAME_MAGIC ||
        header->schema_version != MESH_WIRE_SCHEMA_VERSION ||
        header->header_bytes != MESH_FRAME_HEADER_BYTES ||
        header->frame_type < MESH_FRAME_TASK ||
        header->frame_type > MESH_FRAME_HINT ||
        header->payload_bytes > MESH_MAX_FRAME_PAYLOAD ||
        header->header_bytes > available_bytes) {
        return false;
    }
    return header->payload_bytes <= available_bytes - header->header_bytes;
}

static inline bool mesh_sequence_is_replay(const mesh_replay_cursor_t *cursor,
                                            uint64_t sequence)
{
    return cursor == NULL || sequence <= cursor->highest_sequence;
}

static inline bool mesh_sequence_accept(mesh_replay_cursor_t *cursor,
                                        uint64_t sequence)
{
    if (cursor == NULL || mesh_sequence_is_replay(cursor, sequence)) {
        return false;
    }
    cursor->highest_sequence = sequence;
    return true;
}

bool mesh_grant_audience_matches(const mesh_remote_grant_t *grant,
                                 const mesh_node_id_t *local_node);
bool mesh_epochs_current(const mesh_remote_grant_t *grant,
                         mesh_revocation_epoch_t current);
bool mesh_remote_badge_accepted(uint64_t remote_badge);

static inline bool mesh_completion_accept(mesh_completion_guard_t *guard,
                                          uint64_t completion_sequence)
{
    if (guard == NULL || guard->completed != 0u) return false;
    guard->completed = 1u;
    guard->completion_sequence = completion_sequence;
    return true;
}

static inline bool mesh_flow_allows(const mesh_flow_window_t *window,
                                    uint32_t frame_bytes)
{
    return window != NULL && frame_bytes <= MESH_MAX_FRAME_PAYLOAD &&
           window->frames_in_flight < MESH_MAX_INFLIGHT_FRAMES &&
           window->bytes_in_flight <= MESH_MAX_INFLIGHT_BYTES &&
           (uint64_t)frame_bytes <=
               (MESH_MAX_INFLIGHT_BYTES - window->bytes_in_flight);
}

_Static_assert(sizeof(mesh_node_id_t) == MESH_ID_BYTES, "NodeID wire size");
_Static_assert(sizeof(mesh_service_id_t) == MESH_ID_BYTES, "ServiceID wire size");
_Static_assert(sizeof(mesh_space_id_t) == MESH_ID_BYTES, "SpaceID wire size");
_Static_assert(sizeof(mesh_remote_session_handle_t) == 16u,
               "remote session handle wire size");
_Static_assert(sizeof(mesh_frame_header_t) == MESH_FRAME_HEADER_BYTES,
               "generated frame header wire size");
_Static_assert(MESH_REMOTE_GRANT_SIGNING_BYTES ==
                   (7u * MESH_ID_BYTES + 5u * 8u + 2u * 4u +
                    MESH_NONCE_BYTES),
               "RemoteGrant canonical signing size");
_Static_assert(MESH_EXECUTION_LEASE_SIGNING_BYTES ==
                   (5u * 8u + 3u * MESH_ID_BYTES + MESH_NONCE_BYTES),
               "ExecutionLease canonical signing size");
_Static_assert(MESH_REMOTE_GRANT_HAS_LOCAL_BADGE == 0u,
               "remote grants never carry local badges");
_Static_assert(MESH_REMOTE_WIRE_HAS_BADGE == 0u,
               "wire records never carry remote badges");

/* ─── Legacy MeshAgent request/reply records ────────────────────────────── */

/* ─── Request structs ────────────────────────────────────────────────────── */

struct mesh_agent_req_announce {
    uint32_t node_id;           /* this node's mesh ID */
    uint32_t slot_count;        /* available WASM worker slots */
    uint32_t gpu_slots;         /* available GPU slots */
    uint32_t flags;             /* MESH_NODE_FLAG_* */
};

#define MESH_NODE_FLAG_GPU    (1u << 0)  /* node has GPU capability */
#define MESH_NODE_FLAG_RELAY  (1u << 1)  /* node acts as mesh relay */

struct mesh_agent_req_status {
    /* no fields */
};

struct mesh_agent_req_remote_spawn {
    uint64_t wasm_hash_lo;
    uint64_t wasm_hash_hi;
    uint32_t cap_mask;
    uint32_t preferred_node;    /* 0 = best-available selection */
};

struct mesh_agent_req_heartbeat {
    uint32_t node_id;
    uint32_t tick;
};

/* ─── Reply structs ──────────────────────────────────────────────────────── */

struct mesh_agent_reply_announce {
    uint32_t ok;
    uint32_t peer_count;        /* known peers at time of reply */
};

struct mesh_agent_reply_status {
    uint32_t peer_count;
    uint32_t total_slots;
    uint32_t available_slots;
};

struct mesh_agent_reply_remote_spawn {
    uint32_t ok;
    uint32_t node_id;           /* node that accepted the task */
    uint32_t ticket_id;         /* completion ticket */
};

struct mesh_agent_reply_heartbeat {
    uint32_t ok;
};

/* ─── Configuration ──────────────────────────────────────────────────────── */

#define MESH_HEARTBEAT_INTERVAL_MS  1000u
#define MESH_PEER_TIMEOUT_MS        5000u  /* peer declared down after this silence */

/* ─── Error codes ────────────────────────────────────────────────────────── */

enum mesh_agent_error {
    MESH_OK                  = 0,
    MESH_ERR_ALREADY_ANNOUNCED = 1,
    MESH_ERR_NO_PEERS        = 2,
    MESH_ERR_NO_SLOTS        = 3,
    MESH_ERR_BAD_NODE        = 4,
    MESH_ERR_MALFORMED_FRAME = 5,
    MESH_ERR_REPLAY          = 6,
    MESH_ERR_WRONG_AUDIENCE  = 7,
    MESH_ERR_STALE_EPOCH     = 8,
    MESH_ERR_REMOTE_BADGE    = 9,
    MESH_ERR_DUPLICATE_COMPLETION = 10,
    MESH_ERR_FLOW_CONTROL    = 11,
    MESH_ERR_RESUME_REJECTED = 12,
};
