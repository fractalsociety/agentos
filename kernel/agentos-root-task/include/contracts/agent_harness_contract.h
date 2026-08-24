/*
 * AgentHarness IPC Contract
 *
 * A native AgentHarness PD implements a Codex-style plan/tool/patch/verify
 * loop.  It is orchestration, not authority: task data can state which
 * capability classes it requires, but cannot grant any capability.
 *
 * Authority comes only from seL4 capabilities installed by the launcher:
 *   - a minted ModelSvc endpoint badge (ModelCap),
 *   - a ToolSvc endpoint badge plus its per-tool allowlist (ToolCap),
 *   - explicitly mapped AgentFS objects/frames (MemoryCap),
 *   - an ExecServer endpoint badge (ExecCap), and
 *   - when unavoidable, a separately minted NetServer endpoint (NetCap).
 *
 * ModelCap does not imply NetCap: ModelSvc owns its own restricted network
 * transport. Mesh membership also confers no AgentHarness capability.
 *
 * Invariants:
 *   - SUBMIT rejects required_caps not present in launcher-derived authority.
 *   - available_caps is derived from installed CSpace slots, never from shmem.
 *   - unknown capability bits are rejected.
 *   - task_id is unique while a task is queued or running.
 *   - CANCEL is idempotent and revokes outstanding sub-operations.
 *   - RESULT is available only after COMPLETE, FAILED, or CANCELLED.
 */

#pragma once

#include "../agentos.h"
#include <stdbool.h>
#include <stdint.h>

#define HARNESS_INTERFACE_VERSION 1u
#define HARNESS_CH_CONTROL         1u
#define HARNESS_CH_MODELSVC        2u
#define HARNESS_CH_TOOLSVC         3u
#define HARNESS_CH_AGENTFS         4u
#define HARNESS_CH_EXECSERVER      5u
#define HARNESS_CH_NETSERVER       6u /* absent from ordinary coding harnesses */

#define HARNESS_CAP_MODEL          (1u << 0)
#define HARNESS_CAP_TOOL           (1u << 1)
#define HARNESS_CAP_MEMORY         (1u << 2)
#define HARNESS_CAP_EXEC           (1u << 3)
#define HARNESS_CAP_NETWORK        (1u << 4)
#define HARNESS_CAP_KNOWN_MASK     (HARNESS_CAP_MODEL | HARNESS_CAP_TOOL | \
                                    HARNESS_CAP_MEMORY | HARNESS_CAP_EXEC | \
                                    HARNESS_CAP_NETWORK)

#define HARNESS_TASK_ALLOW_PATCH   (1u << 0)
#define HARNESS_TASK_REQUIRE_TEST  (1u << 1)

enum harness_kind {
    HARNESS_KIND_CODEX = 1u,
};

enum harness_state {
    HARNESS_STATE_IDLE = 0u,
    HARNESS_STATE_PLANNING = 1u,
    HARNESS_STATE_TOOL = 2u,
    HARNESS_STATE_VERIFYING = 3u,
    HARNESS_STATE_COMPLETE = 4u,
    HARNESS_STATE_FAILED = 5u,
    HARNESS_STATE_CANCELLED = 6u,
};

enum harness_error {
    HARNESS_OK = 0u,
    HARNESS_ERR_INVALID = 1u,
    HARNESS_ERR_BUSY = 2u,
    HARNESS_ERR_NOT_FOUND = 3u,
    HARNESS_ERR_CAP_DENIED = 4u,
    HARNESS_ERR_MODEL = 5u,
    HARNESS_ERR_TOOL = 6u,
    HARNESS_ERR_MEMORY = 7u,
    HARNESS_ERR_EXEC = 8u,
    HARNESS_ERR_STEP_LIMIT = 9u,
    HARNESS_ERR_PROTOCOL = 10u,
};

/* Stored in harness shmem before MSG_HARNESS_SUBMIT. */
struct harness_req_submit {
    uint32_t task_id;
    uint32_t harness_kind;
    uint32_t required_caps;   /* declaration only; never a grant */
    uint32_t task_flags;
    uint32_t max_steps;
    uint32_t authority_epoch; /* must match launcher-owned grant epoch */
    uint32_t prompt_offset;
    uint32_t prompt_len;
    uint32_t result_offset;
    uint32_t result_capacity;
};

struct harness_reply_submit {
    uint32_t status;
    uint32_t task_id;
    uint32_t available_caps;  /* observed installed authority */
    uint32_t state;
};

struct harness_req_task {
    uint32_t task_id;
};

struct harness_reply_status {
    uint32_t status;
    uint32_t task_id;
    uint32_t state;
    uint32_t step;
    uint32_t last_error;
    uint32_t used_caps;
    uint32_t denied_attempts;
    uint32_t authority_epoch;
};

struct harness_reply_result {
    uint32_t status;
    uint32_t task_id;
    uint32_t state;
    uint32_t result_len;
    uint32_t model_calls;
    uint32_t tool_calls;
    uint32_t memory_ops;
    uint32_t exec_calls;
    uint32_t tokens_in;
    uint32_t tokens_out;
    int32_t verification_exit_code;
    uint32_t used_caps;
};

/* Policy preflight only. Real enforcement remains the CSpace/VSpace layout. */
static inline bool harness_authority_satisfies(uint32_t required,
                                                uint32_t installed)
{
    if ((required & ~HARNESS_CAP_KNOWN_MASK) != 0u) return false;
    if ((installed & ~HARNESS_CAP_KNOWN_MASK) != 0u) return false;
    return (required & ~installed) == 0u;
}
