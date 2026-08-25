/* Capability-gated ExecServer verification contract. */

#pragma once

#include <stdint.h>

#define EXECSVC_INTERFACE_VERSION          4u
#define EXECSVC_OP_VERIFY_EXACT            0xe4u
#define EXECSVC_OP_RUN_PROFILE             0xe5u

#define EXECSVC_SHMEM_VADDR                0x63000000u
#define EXECSVC_SHMEM_SIZE                 (4u * 1024u * 1024u)
#define EXECSVC_CLIENT_SLOT_COUNT          64u
#define EXECSVC_CLIENT_ARENA_SIZE          (48u * 1024u)
#define EXECSVC_CLIENT_ARENA_OFFSET(client_id) \
    ((uint32_t)(client_id) * EXECSVC_CLIENT_ARENA_SIZE)
#define EXECSVC_CLIENT_ARENA_VADDR(client_id) \
    (EXECSVC_SHMEM_VADDR + EXECSVC_CLIENT_ARENA_OFFSET(client_id))

/* Execution authority is an immutable profile identifier, never a caller-
 * supplied argv or shell command.  The first profile performs a real C11
 * compile-only validation with fixed warning/error flags. */
#define EXECSVC_PROFILE_C11_COMPILE         1u
#define EXECSVC_PROFILE_FRACTALOS_REPO_TEST   2u
#define EXECSVC_PROFILE_FRACTALOS_REPO_SEARCH 3u
#define EXECSVC_PROFILE_FRACTALOS_REPO_READ   4u
#define EXECSVC_RIGHT_VERIFY_EXACT          (1u << 0)
#define EXECSVC_RIGHT_C11_COMPILE           (1u << 1)
#define EXECSVC_RIGHT_FRACTALOS_REPO_TEST     (1u << 2)
#define EXECSVC_RIGHT_FRACTALOS_REPO_SEARCH   (1u << 3)
#define EXECSVC_RIGHT_FRACTALOS_REPO_READ     (1u << 4)
#define EXECSVC_RIGHT_FRACTALOS_REPOSITORY    \
    (EXECSVC_RIGHT_FRACTALOS_REPO_SEARCH | EXECSVC_RIGHT_FRACTALOS_REPO_READ)
#define EXECSVC_RIGHT_ALL                   \
    (EXECSVC_RIGHT_VERIFY_EXACT | EXECSVC_RIGHT_C11_COMPILE \
     | EXECSVC_RIGHT_FRACTALOS_REPO_TEST | EXECSVC_RIGHT_FRACTALOS_REPOSITORY)
#define EXECSVC_PROFILE_RIGHT(profile_id)                         \
    ((profile_id) == EXECSVC_PROFILE_C11_COMPILE                  \
         ? EXECSVC_RIGHT_C11_COMPILE                              \
         : ((profile_id) == EXECSVC_PROFILE_FRACTALOS_REPO_TEST     \
                ? EXECSVC_RIGHT_FRACTALOS_REPO_TEST                  \
                : ((profile_id) == EXECSVC_PROFILE_FRACTALOS_REPO_SEARCH \
                       ? EXECSVC_RIGHT_FRACTALOS_REPO_SEARCH         \
                       : ((profile_id) == EXECSVC_PROFILE_FRACTALOS_REPO_READ \
                              ? EXECSVC_RIGHT_FRACTALOS_REPO_READ : 0u))))
#define EXECSVC_SOURCE_MAX                  (24u * 1024u)
#define EXECSVC_OUTPUT_MAX                  (16u * 1024u)
#define EXECSVC_REPO_PATH_MAX               256u
#define EXECSVC_REPO_BUNDLE_MAGIC           0x50524741u /* "AGRP" */
#define EXECSVC_REPO_BUNDLE_VERSION         1u

/* Input for the managed repository profile. The path and file bytes follow
 * this header. Repository root and test command are administrator-owned
 * transport configuration and never enter worker-controlled input. */
typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t path_len;
    uint32_t content_len;
} execsvc_repo_bundle_header_t;

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

typedef struct {
    uint32_t source_offset;
    uint32_t source_len;
    uint32_t output_offset;
    uint32_t output_capacity;
    uint32_t profile_id;
    uint32_t request_tag;
} execsvc_run_profile_wire_t;

typedef struct {
    uint32_t status;
    int32_t exit_code;
    uint32_t output_len;
    uint32_t request_tag;
} execsvc_run_profile_reply_t;

enum execsvc_error {
    EXECSVC_OK = 0u,
    EXECSVC_ERR_INVALID = 1u,
    EXECSVC_ERR_DENIED = 2u,
    EXECSVC_ERR_UNSUPPORTED = 3u,
    EXECSVC_ERR_TRANSPORT = 4u,
};

_Static_assert(sizeof(execsvc_verify_exact_wire_t) == 20u,
               "ExecSvc verify request must fit one seL4 payload");
_Static_assert(sizeof(execsvc_verify_reply_t) == 16u,
               "ExecSvc verify reply must fit one seL4 payload");
_Static_assert(sizeof(execsvc_run_profile_wire_t) == 24u,
               "ExecSvc profile request must fit one seL4 payload");
_Static_assert(sizeof(execsvc_run_profile_reply_t) == 16u,
               "ExecSvc profile reply must fit one seL4 payload");
_Static_assert(sizeof(execsvc_repo_bundle_header_t) == 16u,
               "ExecSvc repository bundle header ABI drift");
_Static_assert(EXECSVC_PROFILE_RIGHT(EXECSVC_PROFILE_C11_COMPILE)
                   == EXECSVC_RIGHT_C11_COMPILE,
               "C11 profile must map to its immutable capability right");
_Static_assert(EXECSVC_PROFILE_RIGHT(EXECSVC_PROFILE_FRACTALOS_REPO_TEST)
                   == EXECSVC_RIGHT_FRACTALOS_REPO_TEST,
               "repository profile must map to its immutable capability right");
_Static_assert(EXECSVC_PROFILE_RIGHT(EXECSVC_PROFILE_FRACTALOS_REPO_SEARCH)
                   == EXECSVC_RIGHT_FRACTALOS_REPO_SEARCH,
               "repository search must map to its immutable capability right");
_Static_assert(EXECSVC_PROFILE_RIGHT(EXECSVC_PROFILE_FRACTALOS_REPO_READ)
                   == EXECSVC_RIGHT_FRACTALOS_REPO_READ,
               "repository read must map to its immutable capability right");
