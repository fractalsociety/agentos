/*
 * Native Agent Task Gateway Contract
 *
 * This is the controller-facing transport for externally supplied tasks.  It
 * deliberately transports data only: required_caps is a declaration and the
 * authority epoch is supplied by the controller from CapBroker state.
 */
#pragma once

#include <stdint.h>

#define AGENT_TASK_INTERFACE_VERSION 1u

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
