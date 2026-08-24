/* Capability-gated ExecServer verification contract. */

#pragma once

#include <stdint.h>

#define EXECSVC_INTERFACE_VERSION          1u
#define EXECSVC_OP_VERIFY_EXACT            0xe4u

#define EXECSVC_SHMEM_VADDR                0x63000000u
#define EXECSVC_SHMEM_SIZE                 (4u * 1024u * 1024u)
#define EXECSVC_CLIENT_SLOT_COUNT          64u
#define EXECSVC_CLIENT_ARENA_SIZE          (48u * 1024u)
#define EXECSVC_CLIENT_ARENA_OFFSET(client_id) \
    ((uint32_t)(client_id) * EXECSVC_CLIENT_ARENA_SIZE)
#define EXECSVC_CLIENT_ARENA_VADDR(client_id) \
    (EXECSVC_SHMEM_VADDR + EXECSVC_CLIENT_ARENA_OFFSET(client_id))

typedef struct {
    uint32_t actual_offset;
    uint32_t actual_len;
    uint32_t expected_offset;
    uint32_t expected_len;
    uint32_t request_tag;
} execsvc_verify_exact_wire_t;

typedef struct {
    uint32_t status;
    int32_t exit_code;
    uint32_t checked_bytes;
    uint32_t mismatch_offset;
} execsvc_verify_reply_t;

enum execsvc_error {
    EXECSVC_OK = 0u,
    EXECSVC_ERR_INVALID = 1u,
    EXECSVC_ERR_DENIED = 2u,
};

_Static_assert(sizeof(execsvc_verify_exact_wire_t) == 20u,
               "ExecSvc verify request must fit one seL4 payload");
_Static_assert(sizeof(execsvc_verify_reply_t) == 16u,
               "ExecSvc verify reply must fit one seL4 payload");
