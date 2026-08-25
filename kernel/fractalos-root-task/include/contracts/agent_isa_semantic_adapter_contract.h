/*
 * Semantic adapters for Agent ISA → existing FractalOS PD contracts
 * (fos-gz0.14.1.2).
 *
 * Each async semantic operation reaches only its capability-selected service
 * endpoint. Endpoints are installed by opaque interface ObjectID + service
 * class — never by implementation/provider name. Invocation rechecks
 * authority epoch, budget, and object ownership, then yields an authenticated
 * immutable completion ObjectID.
 *
 * Channels: MSG_AGENT_ISA_ADAPTER_* (see fractalos.h)
 * Version: 1
 */

#pragma once

#include "agent_isa_contract.h"
#include "agent_isa_dispatch_contract.h"

#define AGENT_ISA_ADAPTER_INTERFACE_VERSION 1u
#define AGENT_ISA_ADAPTER_MAX_ENDPOINTS     16u

enum agent_isa_adapter_error {
    AGENT_ISA_ADAPTER_OK                 = 0u,
    AGENT_ISA_ADAPTER_ERR_INVALID        = 1u,
    AGENT_ISA_ADAPTER_ERR_VERSION        = 2u,
    AGENT_ISA_ADAPTER_ERR_DENIED         = 3u,
    AGENT_ISA_ADAPTER_ERR_NOT_FOUND      = 4u,
    AGENT_ISA_ADAPTER_ERR_FULL           = 5u,
    AGENT_ISA_ADAPTER_ERR_AUTHORITY      = 6u,
    AGENT_ISA_ADAPTER_ERR_BUDGET         = 7u,
    AGENT_ISA_ADAPTER_ERR_OWNERSHIP      = 8u,
    AGENT_ISA_ADAPTER_ERR_NO_ENDPOINT    = 9u,
    AGENT_ISA_ADAPTER_ERR_WRONG_CLASS    = 10u,
    AGENT_ISA_ADAPTER_ERR_NAME_FORBIDDEN = 11u, /* provider/impl names rejected */
    AGENT_ISA_ADAPTER_ERR_EVENT          = 12u, /* canonical stream append failed */
};

/* Stable service class = Agent ISA cap bit used for endpoint selection. */
struct agent_isa_adapter_endpoint {
    agent_object_id_t interface_id; /* opaque installed PD contract identity */
    uint32_t service_class;         /* AGENT_ISA_CAP_* bit */
    uint32_t authority_epoch;
    uint32_t budget_ceiling;
    uint32_t reserved;
} __attribute__((packed));

struct agent_isa_adapter_req_install {
    uint32_t interface_version;
    uint32_t reserved;
    struct agent_isa_adapter_endpoint endpoint;
} __attribute__((packed));

struct agent_isa_adapter_reply_install {
    uint32_t status;
    uint32_t endpoint_slot;
} __attribute__((packed));

struct agent_isa_adapter_req_invoke {
    uint32_t interface_version;
    uint32_t reserved;
    struct agent_isa_dispatch_record record;
    /* Owner-presented object ownership proof for input_root (must match). */
    agent_object_id_t owned_object;
    uint32_t caller_budget_remaining;
    uint32_t caller_authority_epoch;
} __attribute__((packed));

/* Completion is digest-only; no provider/implementation name fields. */
struct agent_isa_adapter_reply_invoke {
    uint32_t status;
    uint32_t service_class_selected;
    agent_object_id_t interface_id_selected;
    agent_object_id_t completion_root;
    uint32_t backend_status; /* AGENT_ISA_DISPATCH_BACKEND_* */
    uint32_t reserved;
} __attribute__((packed));

struct agent_isa_adapter_req_status {
    uint32_t interface_version;
    uint32_t reserved;
} __attribute__((packed));

struct agent_isa_adapter_reply_status {
    uint32_t status;
    uint32_t endpoint_count;
    uint32_t authority_epoch;
    uint32_t reserved;
} __attribute__((packed));

_Static_assert(sizeof(struct agent_isa_adapter_endpoint) == 32u,
               "adapter endpoint wire size");
_Static_assert(sizeof(struct agent_isa_adapter_req_install) == 40u,
               "adapter install request");
_Static_assert(sizeof(struct agent_isa_adapter_reply_invoke) == 48u,
               "adapter invoke reply has no name fields");

#ifdef __cplusplus
extern "C" {
#endif

/* Map async ISA op → required service class (0 if not async-lowerable). */
uint32_t agent_isa_adapter_service_class_for_op(uint16_t operation);

#ifdef __cplusplus
}
#endif
