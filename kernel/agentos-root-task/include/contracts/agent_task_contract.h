/*
 * Native Agent Task Gateway Contract
 *
 * This is the controller-facing transport for externally supplied tasks.  It
 * deliberately transports data only: required_caps is a declaration and the
 * authority epoch is supplied by the controller from CapBroker state.
 */
#pragma once

#include <stdint.h>

/* v1 called the model-visible verifier "VERIFY".  v2 names the same
 * candidate-facing operation TASK_VERIFY; v1 remains a decode-only alias and
 * never grants promotion authority. */
#define AGENT_TASK_INTERFACE_VERSION_V1 1u
#define AGENT_TASK_INTERFACE_VERSION_V2 2u
#define AGENT_TASK_INTERFACE_VERSION AGENT_TASK_INTERFACE_VERSION_V2
/* The wire operation was VERIFY in v1 and is TASK_VERIFY in v2.  Keep the
 * legacy value decode-only: accepting a v1 record must not create a
 * candidate-visible promotion or commit authority. */
#define AGENT_TASK_VERIFY_VERSION_V1 AGENT_TASK_INTERFACE_VERSION_V1
#define AGENT_TASK_VERIFY_VERSION_V2 AGENT_TASK_INTERFACE_VERSION_V2
#define AGENT_TASK_VERIFY_VERSION AGENT_TASK_VERIFY_VERSION_V2
#define AGENT_TASK_VERIFY_V1_DECODE_ONLY 1u
#define AGENT_TASK_VERIFY_V2_CANONICAL 1u

#define AGENT_TASK_PROMPT_OFFSET 0x0000u
#define AGENT_TASK_PROMPT_CAP    0x4000u
#define AGENT_TASK_RESULT_OFFSET 0x4000u
#define AGENT_TASK_RESULT_CAP    0x4000u
#define AGENT_TASK_CHUNK_BYTES   36u
#define AGENT_TASK_RESULT_CHUNK_BYTES 28u

enum agent_task_error {
    AGENT_TASK_OK = 0u,
    AGENT_TASK_ERR_INVALID = 1u,
    AGENT_TASK_ERR_DENIED = 2u,
    AGENT_TASK_ERR_BUSY = 3u,
    AGENT_TASK_ERR_INCOMPLETE = 4u,
    AGENT_TASK_ERR_HARNESS = 5u,
    AGENT_TASK_ERR_NOT_FOUND = 6u,
    AGENT_TASK_ERR_VERSION = 7u,
    AGENT_TASK_ERR_STALE_HANDLE = 8u,
    AGENT_TASK_ERR_REVOKED = 9u,
    AGENT_TASK_ERR_CANCELLED = 10u,
    AGENT_TASK_ERR_BUDGET_EXHAUSTED = 11u,
    AGENT_TASK_ERR_NOT_READY = 12u,
    AGENT_TASK_ERR_WOULD_BLOCK = 13u,
    AGENT_TASK_ERR_TERMINAL = 14u,
    AGENT_TASK_ERR_AUTHORITY = 15u,
    AGENT_TASK_ERR_VERIFY_REQUIRED = 16u,
    AGENT_TASK_ERR_EVIDENCE_MISMATCH = 17u,
    AGENT_TASK_ERR_PROMOTION_FORBIDDEN = 18u,
};

struct agent_task_req_begin {
    uint32_t interface_version;
    uint32_t required_caps;
    uint32_t task_flags;
    uint32_t max_steps;
    uint32_t prompt_len;
    uint32_t result_capacity;
};

struct agent_task_reply_begin {
    uint32_t status;
    uint32_t task_id;
    uint32_t accepted_prompt_len;
    uint32_t result_capacity;
    uint32_t available_caps;
    uint32_t authority_epoch;
};

/* Exactly one seL4 inline payload. Writes must be contiguous. */
struct agent_task_req_write {
    uint32_t task_id;
    uint32_t offset;
    uint32_t len;
    uint8_t data[AGENT_TASK_CHUNK_BYTES];
};

struct agent_task_req_run {
    uint32_t task_id;
};

struct agent_task_reply_run {
    uint32_t status;
    uint32_t task_id;
    uint32_t harness_status;
    uint32_t state;
    uint32_t result_len;
    uint32_t used_caps;
};

struct agent_task_req_result {
    uint32_t task_id;
    uint32_t offset;
    uint32_t max_len;
};

/* Exactly one seL4 inline payload. */
struct agent_task_reply_result {
    uint32_t status;
    uint32_t task_id;
    uint32_t total_len;
    uint32_t chunk_offset;
    uint32_t chunk_len;
    uint8_t data[AGENT_TASK_RESULT_CHUNK_BYTES];
};

_Static_assert(sizeof(struct agent_task_req_begin) == 24u,
               "agent task begin wire size");
_Static_assert(sizeof(struct agent_task_reply_begin) == 24u,
               "agent task begin reply wire size");
_Static_assert(sizeof(struct agent_task_req_write) == 48u,
               "agent task write must fit one seL4 payload");
_Static_assert(sizeof(struct agent_task_reply_run) == 24u,
               "agent task run reply wire size");
_Static_assert(sizeof(struct agent_task_reply_result) == 48u,
               "agent task result must fit one seL4 payload");

/*
 * Fractal control-plane contract (fractalos:capabilities@1.0.0).
 *
 * This is deliberately additive to the original native gateway records above.
 * The old records are still consumed by the existing AgentHarness adapter;
 * the records below define the versioned asynchronous boundary that new
 * adapters must implement.  A program is identified by an opaque digest, and
 * all effect-bearing requests carry the authority epoch observed by the
 * controller.  There are no textual paths, commands, URLs, credentials, or
 * provider locators in this ABI.
 */
#define FRACTALOS_CAPABILITIES_INTERFACE_VERSION 1u
#define AGENT_TASK_FRACTAL_V1_VERSION 1u
#define AGENT_TASK_CONTRACT_VERSION_V1 1u
#define AGENT_TASK_CONTRACT_VERSION_V2 2u
#define AGENT_TASK_CONTRACT_VERSION AGENT_TASK_CONTRACT_VERSION_V2
#define AGENT_TASK_NONBLOCKING 1u
#define AGENT_TASK_DIGEST_BYTES 32u

enum agent_task_state {
    AGENT_TASK_STATE_ACCEPTED = 1u,
    AGENT_TASK_STATE_RUNNING = 2u,
    AGENT_TASK_STATE_COMPLETE = 3u,
    AGENT_TASK_STATE_FAILED = 4u,
    AGENT_TASK_STATE_CANCELLED = 5u,
    AGENT_TASK_STATE_REVOKED = 6u,
    AGENT_TASK_STATE_BUDGET_EXHAUSTED = 7u,
};

enum agent_task_program_state {
    AGENT_TASK_PROGRAM_LOADING = 1u,
    AGENT_TASK_PROGRAM_READY = 2u,
    AGENT_TASK_PROGRAM_REJECTED = 3u,
};

enum agent_task_worker_kind {
    AGENT_TASK_WORKER_NATIVE = 1u,
    AGENT_TASK_WORKER_AGENTLANG = 2u,
    AGENT_TASK_WORKER_WASM = 3u,
    AGENT_TASK_WORKER_GUEST = 4u,
};

enum agent_task_result_kind {
    AGENT_TASK_RESULT_NONE = 0u,
    AGENT_TASK_RESULT_VALUE = 1u,
    AGENT_TASK_RESULT_FAILURE = 2u,
};

enum agent_task_verify_status {
    AGENT_TASK_VERIFY_UNVERIFIED = 0u,
    AGENT_TASK_VERIFY_ACCEPTED = 1u,
    AGENT_TASK_VERIFY_REJECTED = 2u,
};

enum agent_task_proof_level {
    AGENT_TASK_PROOF_NONE = 0u,
    AGENT_TASK_PROOF_HOST_CONTRACT = 1u,
    AGENT_TASK_PROOF_TARGET_CONTRACT = 2u,
};

/* These are typed opaque identities, not names or capability locators. */
struct agent_task_program_handle {
    uint32_t slot;
    uint32_t generation;
};
typedef struct agent_task_program_handle ProgramHandle;

struct agent_task_handle {
    uint32_t slot;
    uint32_t generation;
};
typedef struct agent_task_handle TaskHandle;

struct agent_task_worker_identity {
    uint32_t kind;
    uint32_t slot;
    uint32_t generation;
    uint32_t reserved;
};
typedef struct agent_task_worker_identity WorkerIdentity;

struct agent_task_program_ref {
    uint8_t digest[AGENT_TASK_DIGEST_BYTES];
    uint32_t program_version;
    uint32_t interface_version;
};

struct agent_task_budget {
    uint64_t cpu_quanta;
    uint64_t memory_bytes;
    uint32_t max_steps;
    uint32_t max_result_bytes;
};

/* TASK_VERIFY evidence is digest-only: commit/test evidence is represented by
 * immutable digests and a proof level, never by executable command text. */
struct agent_task_verify_evidence {
    /* Must be AGENT_TASK_VERIFY_VERSION for a canonical TASK_VERIFY.  A v1
     * evidence record may be decoded by compatibility code but cannot be
     * used as commit evidence. */
    uint32_t evidence_version;
    uint32_t proof_level;
    uint32_t test_count;
    uint32_t reserved;
    uint8_t commit_digest[AGENT_TASK_DIGEST_BYTES];
    uint8_t test_digest[AGENT_TASK_DIGEST_BYTES];
    uint8_t evidence_digest[AGENT_TASK_DIGEST_BYTES];
};

struct agent_task_req_program_open {
    struct agent_task_program_ref program;
    uint32_t authority_epoch;
    uint32_t nonblocking;
};

struct agent_task_reply_program_open {
    uint32_t status;
    struct agent_task_program_handle program;
    uint32_t state;
    uint32_t authority_epoch;
    struct agent_task_worker_identity worker;
};

struct agent_task_req_program_poll {
    struct agent_task_program_handle program;
    uint32_t authority_epoch;
    uint32_t nonblocking;
};

struct agent_task_reply_program_poll {
    uint32_t status;
    struct agent_task_program_handle program;
    uint32_t state;
    uint32_t authority_epoch;
    struct agent_task_worker_identity worker;
};

struct agent_task_req_submit {
    struct agent_task_program_handle program;
    struct agent_task_budget budget;
    uint32_t authority_epoch;
    uint32_t nonblocking;
    uint32_t task_flags;
    uint32_t reserved;
};

struct agent_task_reply_submit {
    uint32_t status;
    struct agent_task_program_handle program;
    struct agent_task_handle task;
    uint32_t state;
    uint32_t authority_epoch;
    struct agent_task_worker_identity worker;
};

struct agent_task_req_poll {
    struct agent_task_handle task;
    uint32_t authority_epoch;
    uint32_t nonblocking;
};

struct agent_task_reply_poll {
    uint32_t status;
    struct agent_task_handle task;
    uint32_t state;
    uint32_t terminal_code;
    uint32_t authority_epoch;
    struct agent_task_worker_identity worker;
};

struct agent_task_req_cancel {
    struct agent_task_handle task;
    uint32_t authority_epoch;
    uint32_t nonblocking;
};

struct agent_task_reply_cancel {
    uint32_t status;
    struct agent_task_handle task;
    uint32_t state;
    uint32_t authority_epoch;
};

struct agent_task_req_budget {
    struct agent_task_handle task;
    uint32_t authority_epoch;
    uint32_t nonblocking;
    struct agent_task_budget budget;
};

struct agent_task_reply_budget {
    uint32_t status;
    struct agent_task_handle task;
    struct agent_task_budget remaining;
    uint32_t authority_epoch;
};

struct agent_task_req_verify {
    struct agent_task_handle task;
    uint32_t authority_epoch;
    uint32_t nonblocking;
    struct agent_task_verify_evidence evidence;
};

struct agent_task_reply_verify {
    uint32_t status;
    struct agent_task_handle task;
    uint32_t state;
    uint32_t verify_status;
    uint32_t authority_epoch;
    uint32_t evidence_sequence;
};

struct agent_task_req_terminal_result {
    struct agent_task_handle task;
    uint32_t authority_epoch;
    uint32_t nonblocking;
};

struct agent_task_reply_terminal_result {
    uint32_t status;
    struct agent_task_handle task;
    uint32_t state;
    uint32_t result_kind;
    uint32_t terminal_code;
    uint32_t result_bytes;
    uint32_t verify_status;
    struct agent_task_worker_identity worker;
    uint8_t result_digest[AGENT_TASK_DIGEST_BYTES];
};

_Static_assert(sizeof(struct agent_task_program_handle) == 8u,
               "ProgramHandle wire size");
_Static_assert(sizeof(struct agent_task_handle) == 8u,
               "TaskHandle wire size");
_Static_assert(sizeof(struct agent_task_worker_identity) == 16u,
               "WorkerIdentity wire size");
_Static_assert(sizeof(struct agent_task_budget) == 24u,
               "task budget wire size");
_Static_assert(sizeof(struct agent_task_program_ref) == 40u,
               "program reference wire size");
_Static_assert(sizeof(struct agent_task_verify_evidence) == 112u,
               "TASK_VERIFY evidence wire size");
